# -*- coding: utf-8 -*-
"""账号管理 MoMo 本地协议任务队列。"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

try:
    from curl_cffi import requests as curl_requests
except ImportError:  # pragma: no cover - requirements.txt installs curl_cffi
    curl_requests = None

from config import extract_link as cfg
from config.env_loader import env_value, load_env
from core import db
from core.momo_extract import (
    MomoExtractionError,
    MomoUnavailableError,
    derive_vn_proxy,
    extract_momo_link,
    is_momo_gateway_url,
    proxy_chain_id,
)

logger = logging.getLogger(__name__)


def _reload_env() -> None:
    try:
        load_env(override=True)
    except Exception:
        pass


def _setting(name: str, default=None):
    _reload_env()
    raw = os.getenv(name)
    if raw is not None and str(raw).strip() != "":
        return str(raw).strip()
    return getattr(cfg, name, default)


def _int_setting(name: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(_setting(name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


def _float_setting(name: str, default: float, lower: float, upper: float) -> float:
    try:
        value = float(_setting(name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


def _proxy_pool() -> list[str]:
    _reload_env()
    value = env_value(
        "MOMO_PROXY_POOL",
        getattr(cfg, "MOMO_PROXY_POOL", []),
        "list_str_multiline",
    )
    if isinstance(value, str):
        value = value.splitlines()
    return [str(item).strip() for item in (value or []) if str(item).strip()]


def _proxy_api_url() -> str:
    return str(_setting("MOMO_PROXY_API_URL", "") or "").strip()


_WORKERS = _int_setting("MOMO_WORKERS", 2, 1, 16)
_QUEUE_LIMIT = _int_setting("MOMO_QUEUE_LIMIT", 500, _WORKERS, 5000)
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="momo-extract")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)

_PROXY_SELECT_LOCK = threading.Lock()
_PROXY_INDEX = 0
_CHAIN_LOCKS: dict[str, threading.Lock] = {}


def _fetch_dynamic_proxy(api_url: str, *, timeout: float) -> str:
    """Directly fetch one unauthenticated VN SOCKS5 endpoint from the provider."""
    parsed_api = urlsplit(str(api_url or "").strip())
    if parsed_api.scheme not in {"http", "https"} or not parsed_api.hostname:
        raise MomoExtractionError("动态代理 API URL 无效", stage="proxy_api")
    try:
        if curl_requests is not None:
            session = curl_requests.Session(impersonate="chrome136")
            session.trust_env = False
            try:
                response = session.get(
                    api_url,
                    headers={"Accept": "text/plain"},
                    timeout=max(1.0, float(timeout)),
                    proxies={},
                )
                if int(response.status_code) < 200 or int(response.status_code) >= 300:
                    raise RuntimeError(f"HTTP {int(response.status_code)}")
                body = bytes(response.content or b"")
            finally:
                session.close()
        else:
            opener = build_opener(ProxyHandler({}))
            request = Request(
                api_url,
                headers={"Accept": "text/plain", "User-Agent": "TurbGPT-MoMo/1.0"},
            )
            with opener.open(request, timeout=max(1.0, float(timeout))) as response:
                body = response.read(4097)
    except Exception as exc:
        raise MomoExtractionError(
            f"动态代理 API 请求失败: {type(exc).__name__}",
            stage="proxy_api",
            retryable=True,
        ) from exc
    if len(body) > 4096:
        raise MomoExtractionError(
            "动态代理 API 响应过长", stage="proxy_api", retryable=True
        )
    value = body.decode("utf-8", "replace").strip()
    if "\n" in value or "\r" in value:
        raise MomoExtractionError(
            "动态代理 API 未返回单行 host:port", stage="proxy_api", retryable=True
        )
    match = re.fullmatch(r"([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?):([0-9]{1,5})", value)
    if not match or ".." in match.group(1):
        raise MomoExtractionError(
            "动态代理 API 未返回有效 host:port", stage="proxy_api", retryable=True
        )
    host, raw_port = match.groups()
    if len(host) > 253 or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in host.split(".")
    ):
        raise MomoExtractionError(
            "动态代理 API 返回的主机名无效", stage="proxy_api", retryable=True
        )
    port = int(raw_port)
    if not 1 <= port <= 65535:
        raise MomoExtractionError(
            "动态代理 API 返回的端口无效", stage="proxy_api", retryable=True
        )
    return f"socks5h://{host}:{port}"


def _select_proxy(
    *,
    api_url: str,
    api_timeout: float,
    pool: list[str],
) -> tuple[str, str, threading.Lock, bool]:
    """Select one attempt-scoped proxy and its per-chain serialization lock."""
    global _PROXY_INDEX
    if api_url:
        seed = _fetch_dynamic_proxy(api_url, timeout=api_timeout)
        vn_proxy = seed
        proxy_is_vn = True
    else:
        if not pool:
            raise MomoExtractionError(
                "MOMO_PROXY_POOL 为空，请在配置 -> 提链中填写 Sticky 代理",
                stage="proxy",
            )
        with _PROXY_SELECT_LOCK:
            seed = pool[_PROXY_INDEX % len(pool)]
            _PROXY_INDEX = (_PROXY_INDEX + 1) % max(1, len(pool))
        vn_proxy = derive_vn_proxy(seed)
        proxy_is_vn = False
    chain_id = proxy_chain_id(vn_proxy)
    with _PROXY_SELECT_LOCK:
        chain_lock = _CHAIN_LOCKS.setdefault(chain_id, threading.Lock())
    return seed, chain_id, chain_lock, proxy_is_vn


def validate_configuration() -> dict:
    """校验所有 MoMo seed，避免批量任务执行到一半才发现配置错误。"""
    api_url = _proxy_api_url()
    if api_url:
        parsed = urlsplit(api_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("MOMO_PROXY_API_URL 必须是有效的 HTTP(S) URL")
        return {
            "dynamic_proxy_api": True,
            "configured_proxies": 0,
            "unique_sticky_sessions": 0,
        }
    pool = _proxy_pool()
    if not pool:
        raise ValueError("MOMO_PROXY_POOL 为空，请在配置 -> 提链中填写 Sticky 代理")
    chain_ids = []
    for index, seed in enumerate(pool, start=1):
        try:
            chain_ids.append(proxy_chain_id(derive_vn_proxy(seed)))
        except Exception as exc:
            raise ValueError(f"MOMO_PROXY_POOL 第 {index} 条无效: {exc}") from exc
    if len(set(chain_ids)) != len(chain_ids):
        raise ValueError("MOMO_PROXY_POOL 包含重复 sticky session，请删除重复项")
    return {"configured_proxies": len(pool), "unique_sticky_sessions": len(chain_ids)}


def _sanitize_text(value: object, *, secrets: tuple[str, ...] = ()) -> str:
    text = str(value or "")
    for secret in sorted((str(item) for item in secrets if str(item)), key=len, reverse=True):
        text = text.replace(secret, "***")
    text = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9._=-]+", r"\1***", text)
    text = re.sub(
        r"(?i)(https?://|socks4a?://|socks5h?://)[^/@\s]+@",
        r"\1***@",
        text,
    )
    text = re.sub(
        r"(?i)(\b(?:access_token|refresh_token|session_token|client_secret|token)\b"
        r"[\"']?\s*[:=]\s*[\"']?)([^\"'&,\s}\]]+)",
        r"\1***",
        text,
    )
    text = re.sub(
        r"(?i)(__Secure-next-auth\.session-token=)[^;\s]+",
        r"\1***",
        text,
    )
    text = re.sub(r"(?i)\b(?:pi|seti|cs)_[A-Za-z0-9_]+_secret_[A-Za-z0-9_]+", "***", text)
    return text


def _safe_error(exc: Exception, *, secrets: tuple[str, ...] = ()) -> str:
    text = _sanitize_text(f"{type(exc).__name__}: {exc}", secrets=secrets)
    return text[:500]


def _run_momo(
    *,
    account_id: int,
    email: str,
    access_token: str,
    settings: dict,
) -> dict:
    try:
        if not db.mark_account_momo_running(account_id):
            return {"ok": False, "status": "failed", "error": "账号已删除或 MoMo 状态已被重置"}
        max_attempts = int(settings.get("max_attempts") or 0)
        attempt = 0
        while True:
            attempt += 1
            proxy_seed = ""
            proxy_key = ""
            try:
                proxy_seed, proxy_key, chain_lock, proxy_is_vn = _select_proxy(
                    api_url=settings["proxy_api_url"],
                    api_timeout=settings["proxy_api_timeout"],
                    pool=settings["proxy_pool"],
                )
                db.mark_account_momo_running(
                    account_id,
                    message=f"正在使用第 {attempt} 条 VN 代理执行完整 MoMo 链",
                )
                logger.info(
                    "[MoMo] 尝试开始: %s attempt=%s proxy_chain=%s",
                    email,
                    attempt,
                    proxy_key,
                )
                # One chain lock covers checkout, Stripe, approve, poll and redirect.
                with chain_lock:
                    result = extract_momo_link(
                        access_token=access_token,
                        email=email,
                        proxy=proxy_seed,
                        proxy_is_vn=proxy_is_vn,
                        pre_proxy="" if proxy_is_vn else settings["pre_proxy"],
                        promo_id=settings["promo_id"],
                        request_timeout=settings["request_timeout"],
                        poll_timeout=settings["poll_timeout"],
                        poll_interval=settings["poll_interval"],
                    )
                final_url = str(result.get("long_url") or "")
                if not is_momo_gateway_url(final_url):
                    raise MomoExtractionError(
                        "协议执行器未返回有效 payment.momo.vn 网关 URL",
                        stage="result_validation",
                    )
                stored = {
                    "ok": True,
                    "status": "success",
                    "checked_at": datetime.now().isoformat(timespec="seconds"),
                    "message": "MoMo 链提取成功",
                    "url": final_url,
                    "currency": result.get("currency"),
                    "amount": result.get("amount"),
                    "payment_method_types": result.get("methods") or [],
                    "proxy_key": proxy_key,
                }
                db.update_account_momo(account_id, stored)
                logger.info("[MoMo] 成功: %s proxy_chain=%s", email, proxy_key)
                return {**stored, "result": result}
            except MomoUnavailableError as exc:
                stored = {
                    "ok": False,
                    "status": "no_momo",
                    "checked_at": datetime.now().isoformat(timespec="seconds"),
                    "message": "当前账号的 VN/VND Checkout 不提供 MoMo",
                    "currency": exc.currency,
                    "amount": exc.amount,
                    "payment_method_types": exc.methods or [],
                    "proxy_key": proxy_key,
                }
                db.update_account_momo(account_id, stored)
                logger.info(
                    "[MoMo] 明确无 MoMo: %s methods=%s proxy_chain=%s",
                    email,
                    exc.methods,
                    proxy_key,
                )
                return stored
            except MomoExtractionError as exc:
                safe_error = _safe_error(
                    exc,
                    secrets=(
                        access_token,
                        proxy_seed,
                        str(settings.get("pre_proxy") or ""),
                        str(settings.get("proxy_api_url") or ""),
                    ),
                )
                can_retry = exc.retryable and (max_attempts == 0 or attempt < max_attempts)
                if can_retry:
                    logger.warning(
                        "[MoMo] 临时失败，废弃代理后重跑: %s attempt=%s stage=%s proxy_chain=%s error=%s",
                        email,
                        attempt,
                        exc.stage,
                        proxy_key or "unavailable",
                        safe_error,
                    )
                    interval = float(settings.get("retry_interval") or 0)
                    if interval > 0:
                        time.sleep(interval)
                    continue
                stored = {
                    "ok": False,
                    "status": "failed",
                    "checked_at": datetime.now().isoformat(timespec="seconds"),
                    "message": "MoMo 提链失败",
                    "error": safe_error,
                    "stage": getattr(exc, "stage", "unknown"),
                    "proxy_key": proxy_key,
                }
                db.update_account_momo(account_id, stored)
                logger.error(
                    "[MoMo] 失败: %s proxy_chain=%s error=%s",
                    email,
                    proxy_key,
                    safe_error,
                )
                return stored
            except Exception as exc:
                safe_error = _safe_error(
                    exc,
                    secrets=(
                        access_token,
                        proxy_seed,
                        str(settings.get("pre_proxy") or ""),
                        str(settings.get("proxy_api_url") or ""),
                    ),
                )
                stored = {
                    "ok": False,
                    "status": "failed",
                    "checked_at": datetime.now().isoformat(timespec="seconds"),
                    "message": "MoMo 提链失败",
                    "error": safe_error,
                    "stage": getattr(exc, "stage", "unknown"),
                    "proxy_key": proxy_key,
                }
                db.update_account_momo(account_id, stored)
                logger.error("[MoMo] 失败: %s error=%s", email, safe_error)
                return stored
    finally:
        _QUEUE_SLOTS.release()


def enqueue_account_momo(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str = "manual",
    force: bool = False,
) -> dict:
    account_id = int(account_id)
    email = str(email or "").strip()
    access_token = str(access_token or "").strip()
    if not access_token:
        return {"accepted": False, "busy": False, "error": "账号缺少 access_token"}

    settings = {
        "proxy_api_url": _proxy_api_url(),
        "proxy_api_timeout": _float_setting("MOMO_PROXY_API_TIMEOUT", 15.0, 1.0, 120.0),
        "proxy_pool": _proxy_pool(),
        "pre_proxy": str(_setting("MOMO_PRE_PROXY", "") or "").strip(),
        "promo_id": str(_setting("MOMO_PROMO_ID", "plus-1-month-free") or "plus-1-month-free").strip(),
        "request_timeout": _float_setting("MOMO_REQUEST_TIMEOUT", 30.0, 5.0, 180.0),
        "poll_timeout": _float_setting("MOMO_POLL_TIMEOUT", 45.0, 1.0, 300.0),
        "poll_interval": _float_setting("MOMO_POLL_INTERVAL", 1.0, 0.1, 10.0),
        "max_attempts": _int_setting("MOMO_PROXY_MAX_ATTEMPTS", 0, 0, 10000),
        "retry_interval": _float_setting("MOMO_PROXY_RETRY_INTERVAL", 1.0, 0.0, 60.0),
    }
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "busy": False, "queue_full": True, "error": "MoMo 提链队列已满"}

    try:
        claim = db.claim_account_momo(
            account_id,
            trigger=str(trigger or "manual"),
            force=bool(force),
        )
    except Exception as exc:
        _QUEUE_SLOTS.release()
        return {
            "accepted": False,
            "busy": False,
            "error": f"MoMo 状态占用失败: {_safe_error(exc)}",
        }
    if claim != "claimed":
        _QUEUE_SLOTS.release()
        messages = {
            "missing": "账号不存在",
            "busy": "该账号正在执行 MoMo 提链",
            "no_momo": "该账号已记录为无 MoMo，普通任务不会重复检测",
            "success": "该账号已有 MoMo 链，普通任务不会重复提取",
        }
        return {
            "accepted": False,
            "busy": claim == "busy",
            "skipped": claim in {"no_momo", "success"},
            "terminal_status": claim if claim in {"no_momo", "success"} else None,
            "error": messages.get(claim, "MoMo 任务无法入队"),
        }

    try:
        future = _EXECUTOR.submit(
            _run_momo,
            account_id=account_id,
            email=email,
            access_token=access_token,
            settings=settings,
        )
    except Exception as exc:
        _QUEUE_SLOTS.release()
        error = f"MoMo 任务入队失败: {_safe_error(exc)}"
        db.update_account_momo(account_id, {"status": "failed", "error": error, "stage": "queue"})
        return {"accepted": False, "busy": False, "error": error}

    return {
        "accepted": True,
        "busy": False,
        "account_id": account_id,
        "email": email,
        "status": "queued",
        "trigger": str(trigger or "manual"),
        "force": bool(force),
        "proxy_key": None,
        "future": future,
    }


def queue_settings() -> dict:
    dynamic_proxy_api = bool(_proxy_api_url())
    return {
        "workers": _WORKERS,
        "queue_limit": _QUEUE_LIMIT,
        "dynamic_proxy_api": dynamic_proxy_api,
        "configured_proxies": 0 if dynamic_proxy_api else len(_proxy_pool()),
    }


__all__ = ["enqueue_account_momo", "queue_settings", "validate_configuration"]
