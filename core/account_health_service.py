# -*- coding: utf-8 -*-
"""Web AT 账号验活后台队列。"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from config import proxy as proxy_cfg
from core import db
from core.account_proxy import resolve_registration_proxy
from core.chatgpt_plan import check_account_alive, resolve_plan_check_route
from core.plan_check_service import restore_account_request_context, wait_for_rate_slot

logger = logging.getLogger(__name__)


def _int_setting(name: str, fallback_name: str, default: int, lower: int, upper: int) -> int:
    raw = getattr(proxy_cfg, name, getattr(proxy_cfg, fallback_name, default))
    try:
        value = int(raw or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


_WORKERS = _int_setting("ACCOUNT_HEALTH_WORKERS", "PLAN_CHECK_WORKERS", 3, 1, 16)
_QUEUE_LIMIT = _int_setting(
    "ACCOUNT_HEALTH_QUEUE_LIMIT", "PLAN_CHECK_QUEUE_LIMIT", 500, _WORKERS, 5000,
)
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="account-health")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)


def _primary_health_proxy(
    account_id: int, requested_proxy: str | None, *, account: dict | None = None,
) -> str | None:
    if requested_proxy is not None:
        return str(requested_proxy or "")
    if account is None:
        account = db.get_account(account_id) or {}
    registered = resolve_registration_proxy(account)
    if registered:
        return registered
    try:
        return str(resolve_plan_check_route(None).get("proxy") or "")
    except Exception:
        return None


def _fresh_pool_proxy(*excluded: str | None) -> str:
    blocked = {str(value or "") for value in excluded}
    for _ in range(5):
        candidate = str(proxy_cfg.pick_proxy() or "")
        if candidate and candidate not in blocked:
            return candidate
    return ""


def _retryable_health_network_result(result: dict) -> bool:
    if str(result.get("status") or "") != "error":
        return False
    http_status = result.get("http_status")
    return http_status is None or http_status in {403, 408, 425, 429} or (
        isinstance(http_status, int) and http_status >= 500
    )


def _health_browser_family() -> str:
    family = str(
        getattr(proxy_cfg, "ACCOUNT_HEALTH_BROWSER_FAMILY", "firefox") or "firefox"
    ).strip().lower()
    return family if family in {"chrome", "firefox"} else "firefox"


def _persist_refreshed_cookies(account_id: int, email: str, cookies: list[dict]) -> None:
    from core.account_cookie_store import persist_cookie_credential

    metadata = persist_cookie_credential(
        email,
        cookies,
        source="health_refresh",
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


def _run_health_check(
    *,
    account_id: int,
    check_id: str,
    email: str,
    access_token: str,
    trigger: str,
    proxy: str | None,
    timezone_offset_min: str,
) -> dict:
    try:
        if not db.mark_account_health_check_running(account_id, check_id=check_id):
            return {"ok": False, "status": "error", "error": "账号已删除或验活任务已被重置"}

        # Long queues must use the token that is current when a worker starts,
        # not a credential captured before other supplementation refreshed it.
        account = db.get_account(account_id)
        if account is None:
            return {"ok": False, "status": "error", "error": "账号已删除"}
        access_token = str(account.get("access_token") or "").strip()
        if not access_token:
            result = check_account_alive("")  # Pure local no_token classification.
            db.update_account_health_check(account_id, result=result, check_id=check_id)
            return result
        effective_proxy = _primary_health_proxy(account_id, proxy, account=account)
        effective_proxy, device_id, cookies = restore_account_request_context(
            account_id=account_id,
            proxy=effective_proxy,
            device_id=None,
            cookies=None,
        )
        request_context = {
            "device_id": device_id,
            "cookies": cookies,
            "browser_family": _health_browser_family(),
        }
        wait_for_rate_slot()
        result = check_account_alive(
            access_token,
            proxy=effective_proxy,
            timezone_offset_min=timezone_offset_min,
            max_attempts=1,
            **request_context,
        )
        fallback_proxy = ""
        if proxy is None and _retryable_health_network_result(result):
            fallback_proxy = _fresh_pool_proxy(effective_proxy)
            if fallback_proxy:
                first_error = str(result.get("error") or result.get("message") or "网络失败")[:180]
                result = check_account_alive(
                    access_token,
                    proxy=fallback_proxy,
                    timezone_offset_min=timezone_offset_min,
                    max_attempts=1,
                    **request_context,
                )
                result["proxy_fallback_reason"] = f"注册代理验活失败后轮换：{first_error}"
                effective_proxy = fallback_proxy
        # token_invalid 已排除了挑战页和明确停用；401、JWT 到期以及
        # 403/invalid_token 都应尝试用保存的 Cookie session 自愈。
        should_refresh = result.get("status") == "token_invalid"
        if should_refresh:
            from core.account_token_refresh import refresh_account_web_access_token

            refreshed = refresh_account_web_access_token(
                account_id,
                access_token,
                proxy=effective_proxy,
                max_attempts=1,
                browser_family=_health_browser_family(),
            )
            if (
                not refreshed.get("ok")
                and refreshed.get("retryable_network") is True
                and proxy is None
            ):
                refresh_fallback_proxy = _fresh_pool_proxy(effective_proxy, fallback_proxy)
                if refresh_fallback_proxy:
                    fallback = refresh_account_web_access_token(
                        account_id,
                        access_token,
                        proxy=refresh_fallback_proxy,
                        max_attempts=1,
                        browser_family=_health_browser_family(),
                    )
                    fallback["proxy_fallback_used"] = True
                    refreshed = fallback
            if refreshed.get("ok"):
                replacement = str(refreshed.get("access_token") or "")
                verified = check_account_alive(
                    replacement,
                    proxy=refreshed.get("proxy"),
                    timezone_offset_min=timezone_offset_min,
                    max_attempts=1,
                    device_id=device_id,
                    cookies=(
                        refreshed.get("cookies")
                        if isinstance(refreshed.get("cookies"), list)
                        else cookies
                    ),
                    browser_family=_health_browser_family(),
                )
                if verified.get("status") == "alive":
                    replaced = db.replace_account_access_token(
                        account_id,
                        expected_access_token=access_token,
                        access_token=replacement,
                        source="health_cookie_refresh",
                    )
                    if replaced:
                        result = verified
                        result["token_refreshed"] = True
                        result["message"] = "Cookie session 已刷新 Web AT，账号认证成功"
                        refreshed_cookies = list(refreshed.get("cookies") or [])
                        if refreshed_cookies:
                            try:
                                _persist_refreshed_cookies(
                                    account_id,
                                    email,
                                    refreshed_cookies,
                                )
                            except Exception as exc:
                                result["token_refresh_error"] = (
                                    f"新 AT 已保存，但 Cookie 更新失败: {type(exc).__name__}: {str(exc)[:180]}"
                                )
                                logger.warning("[Health] 刷新后 Cookie 保存失败: %s", email, exc_info=True)
                        logger.info(
                            "[Health] Web AT 已通过 Cookie session 自动刷新: %s, attempts=%s",
                            email,
                            refreshed.get("attempt_count") or 1,
                        )
                    else:
                        result = {
                            "ok": False,
                            "status": "error",
                            "alive": None,
                            "reason": "credential_changed",
                            "message": "验活期间账号凭证已被其他流程更新，请重新验活",
                            "error": "账号 Web AT 已变化，已放弃旧 Cookie 刷新结果",
                            "http_status": None,
                        }
                else:
                    # 二次验证才是刷新后的最终证据。不能继续落第一次的 401，
                    # 否则代理挑战或网络失败会被误显示成 AT 失效。
                    result = dict(verified)
                    verified_status = str(result.get("status") or "error")
                    if verified_status == "token_invalid":
                        result["message"] = "Cookie 已签发新 Web AT，但新 AT 仍未通过认证"
                    elif verified_status == "error":
                        result["message"] = "Cookie 已签发新 Web AT，但二次验活异常"
                    result["token_refresh_error"] = str(
                        verified.get("error")
                        or verified.get("message")
                        or "刷新后的 Token 验证失败"
                    )[:300]
            else:
                result["message"] = "Web AT 已失效；Cookie session 暂未能自动刷新"
                result["token_refresh_error"] = str(refreshed.get("error") or "刷新失败")[:300]
        db.update_account_health_check(account_id, result=result, check_id=check_id)
        status = str(result.get("status") or "error")
        if status == "alive":
            logger.info("[Health] 账号存活: %s, trigger=%s", email, trigger)
        elif status == "token_invalid":
            logger.warning(
                "[Health] Web AT 失效，账号状态未知: %s, reason=%s, trigger=%s, refresh=%s",
                email,
                result.get("reason") or "token_rejected",
                trigger,
                result.get("token_refresh_error") or "未刷新",
            )
        elif status == "dead":
            logger.warning(
                "[Health] 账号失活: %s, reason=%s, trigger=%s",
                email,
                result.get("reason") or "unknown",
                trigger,
            )
        else:
            logger.warning(
                "[Health] 验活异常: %s, trigger=%s, error=%s",
                email,
                trigger,
                result.get("error") or result.get("message") or "未知错误",
            )
        return result
    except Exception as exc:
        result = {
            "ok": False,
            "status": "error",
            "alive": None,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "reason": "internal_error",
            "message": "验活任务内部异常",
            "error": f"{type(exc).__name__}: {str(exc)[:400]}",
        }
        try:
            db.update_account_health_check(account_id, result=result, check_id=check_id)
        except Exception:
            logger.exception("[Health] 写入验活异常状态失败: account_id=%s", account_id)
        logger.exception("[Health] 验活任务异常: %s", email)
        return result
    finally:
        _QUEUE_SLOTS.release()


def enqueue_account_health_check(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str,
    proxy: str | None = None,
    timezone_offset_min: str = "-",
) -> dict:
    """加入独立验活队列；无 Web AT 时直接持久化 no_token。"""
    account_id = int(account_id)
    email = str(email or "").strip()
    access_token = str(access_token or "").strip()

    if not access_token:
        check_id = db.claim_account_health_check(acc_id=account_id, trigger=trigger)
        if not check_id:
            return {"accepted": False, "busy": True, "error": "该账号正在验活"}
        result = check_account_alive("")
        db.update_account_health_check(account_id, result=result, check_id=check_id)
        return {
            "accepted": False,
            "recorded": True,
            "busy": False,
            "account_id": account_id,
            "email": email,
            "status": "no_token",
            "error": None,
        }

    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "queue_full": True, "error": "验活队列已满，请稍后重试"}

    try:
        check_id = db.claim_account_health_check(acc_id=account_id, trigger=trigger)
    except BaseException:
        _QUEUE_SLOTS.release()
        raise
    if not check_id:
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "该账号正在验活"}

    try:
        _EXECUTOR.submit(
            _run_health_check,
            account_id=account_id,
            check_id=check_id,
            email=email,
            access_token=access_token,
            trigger=str(trigger or "manual"),
            proxy=proxy,
            timezone_offset_min=str(timezone_offset_min or "-"),
        )
    except Exception as exc:
        _QUEUE_SLOTS.release()
        result = {
            "ok": False,
            "status": "error",
            "alive": None,
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "reason": "enqueue_failed",
            "message": "验活任务入队失败",
            "error": f"验活任务入队失败: {type(exc).__name__}: {str(exc)[:300]}",
        }
        db.update_account_health_check(account_id, result=result, check_id=check_id)
        return {"accepted": False, "busy": False, "error": result["error"]}

    return {
        "accepted": True,
        "busy": False,
        "account_id": account_id,
        "email": email,
        "status": "queued",
        "trigger": str(trigger or "manual"),
    }


def enqueue_accounts_health_check(
    account_ids: list, *, proxy: str | None = None, timezone_offset_min: str = "-",
) -> dict:
    from core.supplement_queue import enqueue_supplement_batch

    def submit(*, account_id: int, email: str, claim_id: str, trigger: str):
        return _EXECUTOR.submit(
            _run_health_check, account_id=account_id, email=email, check_id=claim_id,
            access_token="", trigger=trigger, proxy=proxy,
            timezone_offset_min=str(timezone_offset_min or "-"),
        )

    return enqueue_supplement_batch(
        account_ids, kind="health", trigger="manual_bulk", slots=_QUEUE_SLOTS, submit=submit,
    )


def queue_settings() -> dict:
    return {
        "workers": _WORKERS,
        "queue_limit": _QUEUE_LIMIT,
        "shared_rate_limit": True,
    }
