# -*- coding: utf-8 -*-
"""套餐/Plus 资格查询后台队列。"""
from __future__ import annotations

import logging
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from config import proxy as proxy_cfg
from core import db
from core.account_proxy import resolve_registration_proxy
from core.chatgpt_plan import (
    check_account_plan,
    resolve_current_plan_check_proxy,
    resolve_plan_check_browser_family,
)

logger = logging.getLogger(__name__)


def _int_setting(name: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(getattr(proxy_cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


def _float_setting(name: str, default: float, lower: float, upper: float) -> float:
    try:
        value = float(getattr(proxy_cfg, name, default) or 0.0)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


_WORKERS = _int_setting("PLAN_CHECK_WORKERS", 3, 1, 16)
_QUEUE_LIMIT = _int_setting("PLAN_CHECK_QUEUE_LIMIT", 500, _WORKERS, 5000)
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="plan-check")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_RATE_LOCK = threading.Lock()
_NEXT_REQUEST_AT = 0.0


def _wait_for_rate_slot() -> None:
    """为所有查询线程分配错开的请求启动时间。"""
    global _NEXT_REQUEST_AT
    min_interval = _float_setting("PLAN_CHECK_MIN_INTERVAL", 0.4, 0.0, 30.0)
    jitter = _float_setting("PLAN_CHECK_JITTER", 0.3, 0.0, 30.0)
    with _RATE_LOCK:
        now = time.monotonic()
        scheduled = max(now, _NEXT_REQUEST_AT) + (random.uniform(0.0, jitter) if jitter else 0.0)
        _NEXT_REQUEST_AT = scheduled + min_interval
    wait_seconds = scheduled - now
    if wait_seconds > 0:
        time.sleep(wait_seconds)


def wait_for_rate_slot() -> None:
    """供同一认证接口的其他后台任务复用全局请求节流。"""
    _wait_for_rate_slot()


def _registration_recheck_delay() -> float:
    return _float_setting("PLAN_CHECK_REGISTRATION_RECHECK_DELAY", 2.0, 0.0, 30.0)


def _token_rejected(result: dict) -> bool:
    if result.get("token_expired") is True:
        return True
    if result.get("http_status") != 401:
        return False
    preview = str(result.get("response_preview") or "").lower()
    return not any(marker in preview for marker in (
        "<!doctype", "<html", "cloudflare", "cf-chl-", "turnstile", "captcha",
    ))


def _persist_refreshed_cookies(account_id: int, email: str, cookies: list[dict]) -> None:
    from core.account_cookie_store import persist_cookie_credential

    metadata = persist_cookie_credential(
        email,
        cookies,
        source="plan_check_refresh",
        account_id=account_id,
    )
    if not db.update_account_web_cookie_credential(
        account_id,
        credential_path=metadata["credential_path"],
        saved_at=metadata["saved_at"],
        cookie_count=metadata["count"],
        has_session_cookie=metadata["has_session_cookie"],
        status="saved",
        error=None,
    ):
        raise RuntimeError("账号已删除，未写入刷新后的 Cookie 元数据")


def _check_plan_current_token(
    *,
    account_id: int,
    email: str,
    access_token: str,
    proxy: str | None,
    timezone_offset_min: str,
    device_id: str | None,
    cookies: list[dict] | None,
    browser_family: str,
) -> tuple[str, dict, list[dict] | None]:
    context_kwargs = {
        "browser_family": browser_family,
    }
    if str(device_id or "").strip():
        context_kwargs["device_id"] = str(device_id).strip()
    if cookies is not None:
        context_kwargs["cookies"] = cookies

    result = check_account_plan(
        access_token,
        proxy=proxy,
        timezone_offset_min=timezone_offset_min,
        **context_kwargs,
    )
    if not _token_rejected(result):
        return access_token, result, cookies

    from core.account_token_refresh import refresh_account_web_access_token

    refreshed = refresh_account_web_access_token(
        account_id,
        access_token,
        proxy=proxy,
        max_attempts=1,
        browser_family=browser_family,
    )
    if not refreshed.get("ok"):
        failed = dict(result)
        failed["token_refresh_error"] = str(
            refreshed.get("error") or "Cookie AT 刷新失败"
        )[:500]
        return access_token, failed, cookies

    replacement = str(refreshed.get("access_token") or "").strip()
    refreshed_cookies = list(refreshed.get("cookies") or [])
    verified_context = dict(context_kwargs)
    if refreshed_cookies:
        verified_context["cookies"] = refreshed_cookies
    verified = check_account_plan(
        replacement,
        proxy=refreshed.get("proxy") if "proxy" in refreshed else proxy,
        timezone_offset_min=timezone_offset_min,
        max_attempts=1,
        **verified_context,
    )
    if not verified.get("ok"):
        failed = dict(verified)
        failed["token_refresh_error"] = str(
            verified.get("error") or "新 AT 未通过套餐核验"
        )[:500]
        return access_token, failed, cookies

    if not db.replace_account_access_token(
        account_id,
        expected_access_token=access_token,
        access_token=replacement,
        source="plan_check_cookie_refresh",
    ):
        return access_token, {
            "ok": False,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": "套餐查询期间 Web AT 已被其他任务更新",
            "retryable": True,
        }, cookies

    verified["token_refreshed"] = True
    if refreshed_cookies:
        try:
            _persist_refreshed_cookies(account_id, email, refreshed_cookies)
        except Exception as exc:
            verified["token_refresh_error"] = (
                f"新 AT 已保存，但 Cookie 更新失败: {type(exc).__name__}: {str(exc)[:180]}"
            )
            logger.warning("[Plan] 刷新后 Cookie 保存失败: %s", email, exc_info=True)
    logger.info("[Plan] Web AT 已通过 Cookie session 自动刷新: %s", email)
    return replacement, verified, refreshed_cookies or cookies


def restore_account_request_context(
    *,
    account_id: int,
    proxy: str | None,
    device_id: str | None,
    cookies: list[dict] | None,
    force_configured_proxy: bool = False,
) -> tuple[str | None, str | None, list[dict] | None]:
    """Fill request context while keeping qualification routing explicit.

    Health/browser flows may still restore the account's registration proxy.
    Qualification checks pass ``force_configured_proxy=True`` so a historical
    ``proxy_used`` value can never override the currently configured country
    selected pool (PH in the current deployment).
    """
    try:
        account = db.get_account(int(account_id)) or {}
    except Exception:
        account = {}

    if force_configured_proxy:
        try:
            proxy = resolve_current_plan_check_proxy()
        except Exception:
            # Let check_account_plan turn a broken proxy configuration into a
            # structured task result instead of failing while queueing it.
            logger.warning(
                "[Plan] 当前套餐检测代理解析失败，将由请求阶段返回配置错误: account_id=%s",
                account_id,
                exc_info=True,
            )
            proxy = None
    elif proxy is None:
        stored_proxy = resolve_registration_proxy(account)
        if stored_proxy:
            proxy = stored_proxy
    device_id = str(device_id or account.get("device_id") or "").strip() or None

    if cookies is None:
        try:
            credential = db.load_account_web_cookie_credential(int(account_id)) or {}
            stored_cookies = credential.get("cookies")
            if isinstance(stored_cookies, list):
                cookies = stored_cookies
        except Exception:
            logger.debug(
                "[Plan] 读取账号 Cookie 上下文失败: account_id=%s",
                account_id,
                exc_info=True,
            )
    if not device_id:
        for cookie in cookies or []:
            if str(cookie.get("name") or "").strip().lower() != "oai-did":
                continue
            value = str(cookie.get("value") or "").strip()
            if value and len(value) <= 256 and "\r" not in value and "\n" not in value:
                device_id = value
            break
    return proxy, device_id, cookies


def _run_plan_check(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str,
    proxy: str | None,
    timezone_offset_min: str,
    device_id: str | None = None,
    cookies: list[dict] | None = None,
) -> dict:
    try:
        if not db.mark_account_plan_check_running(account_id):
            return {"ok": False, "error": "账号已删除或套餐查询状态已被重置"}

        _wait_for_rate_slot()
        browser_family = resolve_plan_check_browser_family()
        context_kwargs = {"browser_family": browser_family}
        if str(device_id or "").strip():
            context_kwargs["device_id"] = str(device_id).strip()
        if cookies is not None:
            context_kwargs["cookies"] = cookies
        if trigger == "registration_auto":
            logger.info(
                "[Plan] 注册后使用当前检测代理并复用设备/Cookie: email=%s proxy=%s device=%s cookies=%s",
                email,
                bool(str(proxy or "").strip()),
                bool(str(device_id or "").strip()),
                len(cookies or []),
            )
        current_token, result, cookies = _check_plan_current_token(
            account_id=account_id,
            email=email,
            access_token=access_token,
            proxy=proxy,
            timezone_offset_min=timezone_offset_min,
            device_id=device_id,
            cookies=cookies,
            browser_family=browser_family,
        )
        if cookies is not None:
            context_kwargs["cookies"] = cookies

        recheck_delay = _registration_recheck_delay()
        plan_type = str(result.get("current_plan_type") or "").strip().lower()
        promo_status = str(result.get("plus_trial_status") or "").strip().lower()
        invalid_plan_context = plan_type in {"", "guest", "unknown"}
        coupon_conclusive = (
            result.get("promo_check_ok") is True
            and promo_status in {"available", "redeemed", "unavailable"}
        )
        offer_unsettled = (
            not bool(result.get("plus_trial_eligible"))
            or not coupon_conclusive
        )
        should_recheck = (
            trigger == "registration_auto"
            and recheck_delay > 0
            and bool(result.get("ok"))
            and (
                invalid_plan_context
                or (plan_type == "free" and offer_unsettled)
            )
        )
        if should_recheck:
            logger.info(
                "[Plan] 新账号 0 元试用优惠状态尚未明确，%.1fs 后复查一次: %s",
                recheck_delay,
                email,
            )
            time.sleep(recheck_delay)
            _wait_for_rate_slot()
            recheck_result = check_account_plan(
                current_token,
                proxy=proxy,
                timezone_offset_min=timezone_offset_min,
                max_attempts=1,
                **context_kwargs,
            )
            recheck_plan_type = str(
                recheck_result.get("current_plan_type") or ""
            ).strip().lower()
            recheck_usable = (
                bool(recheck_result.get("ok"))
                and recheck_plan_type not in {"", "guest", "unknown"}
            )
            if recheck_usable:
                result = recheck_result
            else:
                logger.warning(
                    "[Plan] 新账号资格复查未得到有效账号上下文，保留首次有效结果: %s, %s",
                    email,
                    recheck_result.get("error")
                    or f"plan={recheck_plan_type or 'unknown'}",
                )

        final_plan_type = str(
            result.get("current_plan_type") or ""
        ).strip().lower()
        if bool(result.get("ok")) and final_plan_type in {"", "guest", "unknown"}:
            result = {
                **result,
                "ok": False,
                "retryable": True,
                "error": "套餐接口返回 guest/unknown，未建立有效账号认证上下文",
            }

        db.update_account_plan_check(acc_id=account_id, result=result)
        if trigger == "registration_auto":
            try:
                from core.registration_service import continue_registration_paypal_after_plan

                continue_registration_paypal_after_plan(account_id)
            except Exception:
                logger.exception(
                    "[Plan] 资格查询完成后续接注册 PP 流程失败: account_id=%s",
                    account_id,
                )
        if result.get("ok"):
            logger.info(
                "[Plan] 后台查询成功: %s, plan=%s, plus_trial=%s, trigger=%s",
                email,
                result.get("current_plan_type") or "unknown",
                bool(result.get("plus_trial_eligible")),
                trigger,
            )
        else:
            logger.warning(
                "[Plan] 后台查询失败: %s, trigger=%s, error=%s",
                email,
                trigger,
                result.get("error") or "未知错误",
            )
        return result
    except Exception as exc:
        result = {
            "ok": False,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"{type(exc).__name__}: {str(exc)[:180]}",
        }
        try:
            db.update_account_plan_check(acc_id=account_id, result=result)
        except Exception:
            logger.exception("[Plan] 写入后台查询异常状态失败: account_id=%s", account_id)
        logger.exception("[Plan] 后台查询异常: %s", email)
        return result
    finally:
        _QUEUE_SLOTS.release()


def enqueue_account_plan_check(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str,
    proxy: str | None = None,
    timezone_offset_min: str = "-",
    device_id: str | None = None,
    cookies: list[dict] | None = None,
) -> dict:
    """把查询放入统一线程池；重复查询或队列满时不提交。

    ``proxy`` remains a compatibility argument for older callers, but is
    deliberately discarded in favor of the current plan-check configuration.
    """
    account_id = int(account_id)
    email = str(email or "").strip()
    access_token = str(access_token or "").strip()
    if not access_token:
        return {"accepted": False, "busy": False, "error": "账号缺少 access_token"}
    proxy, device_id, cookies = restore_account_request_context(
        account_id=account_id,
        proxy=proxy,
        device_id=device_id,
        cookies=cookies,
        force_configured_proxy=True,
    )
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "queue_full": True, "error": "套餐查询队列已满，请稍后重试"}

    if not db.claim_account_plan_check(acc_id=account_id, trigger=trigger):
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "该账号正在查询套餐"}

    try:
        _EXECUTOR.submit(
            _run_plan_check,
            account_id=account_id,
            email=email,
            access_token=access_token,
            trigger=str(trigger or "manual"),
            proxy=proxy,
            timezone_offset_min=str(timezone_offset_min or "-"),
            device_id=str(device_id or "").strip() or None,
            cookies=cookies,
        )
    except Exception as exc:
        _QUEUE_SLOTS.release()
        result = {
            "ok": False,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "error": f"套餐查询入队失败: {type(exc).__name__}: {str(exc)[:160]}",
        }
        db.update_account_plan_check(acc_id=account_id, result=result)
        return {"accepted": False, "busy": False, "error": result["error"]}

    return {
        "accepted": True,
        "busy": False,
        "account_id": account_id,
        "email": email,
        "status": "queued",
        "trigger": str(trigger or "manual"),
    }


def queue_settings() -> dict:
    return {
        "workers": _WORKERS,
        "queue_limit": _QUEUE_LIMIT,
        "min_interval": _float_setting("PLAN_CHECK_MIN_INTERVAL", 0.4, 0.0, 30.0),
        "jitter": _float_setting("PLAN_CHECK_JITTER", 0.3, 0.0, 30.0),
    }
