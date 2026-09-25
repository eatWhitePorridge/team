# -*- coding: utf-8 -*-
"""Account-scoped PayPal extraction, OTP continuation, and Plus verification."""
from __future__ import annotations

import logging
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

from config import paypal as cfg
from core import db, paypal_proxy_pool
from core.chatgpt_plan import check_account_plan, resolve_plan_check_browser_family


logger = logging.getLogger(__name__)

_BA_TOKEN_RE = re.compile(r"BA-[A-Z0-9-]+\Z")
_BEARER_RE = re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._=-]+")
_PROXY_AUTH_RE = re.compile(r"(?i)(https?://|socks4://|socks5h?://)[^/@\s]+@")
_SECRET_FIELD_RE = re.compile(
    r"(?i)(\b(?:access_token|refresh_token|client_secret|ba_token|otp|phone|token)\b"
    r"[\"']?\s*[:=]\s*[\"']?)([^\"'&,\s}\]]+)"
)


def _int_setting(name: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(getattr(cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


def _float_setting(name: str, default: float, lower: float, upper: float) -> float:
    try:
        value = float(getattr(cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


def _int_value(value: object, default: int, lower: int, upper: int) -> int:
    try:
        parsed = int(value if value not in {None, ""} else default)
    except (TypeError, ValueError):
        parsed = default
    return max(lower, min(upper, parsed))


def _float_value(value: object, default: float, lower: float, upper: float) -> float:
    try:
        parsed = float(value if value not in {None, ""} else default)
    except (TypeError, ValueError):
        parsed = default
    return max(lower, min(upper, parsed))


class _DynamicQueueSlots:
    """A resizable in-flight limit that keeps existing task releases valid."""

    def __init__(self, limit: int) -> None:
        self._limit = max(1, int(limit))
        self._active = 0
        self._condition = threading.Condition()

    def acquire(self, blocking: bool = True, timeout: float | None = None) -> bool:
        with self._condition:
            if not blocking:
                if self._active >= self._limit:
                    return False
                self._active += 1
                return True

            deadline = None if timeout is None else time.monotonic() + max(0.0, float(timeout))
            while self._active >= self._limit:
                if deadline is None:
                    self._condition.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            self._active += 1
            return True

    def release(self) -> None:
        with self._condition:
            if self._active <= 0:
                raise ValueError("PayPal queue slot released too many times")
            self._active -= 1
            self._condition.notify_all()

    def resize(self, limit: int) -> None:
        with self._condition:
            self._limit = max(1, int(limit))
            self._condition.notify_all()

    @property
    def limit(self) -> int:
        with self._condition:
            return self._limit

    @property
    def active(self) -> int:
        with self._condition:
            return self._active


_RUNTIME_LOCK = threading.RLock()
_WORKERS = _int_setting("PAYPAL_WORKERS", 20, 1, 64)
_QUEUE_LIMIT = _int_setting("PAYPAL_QUEUE_LIMIT", 500, _WORKERS, 5000)
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="paypal")
_QUEUE_SLOTS = _DynamicQueueSlots(_QUEUE_LIMIT)


class _PayPalTraceSink:
    """Buffer adapter traces so detailed logging does not rewrite JSON per request."""

    def __init__(
        self,
        *,
        account_id: int,
        phase: str,
        attempt: int | None = None,
        batch_size: int = 5,
        mode: str | None = None,
        suppress_protocol_failure_summary: bool = False,
    ) -> None:
        self.account_id = int(account_id)
        self.phase = str(phase or "system")
        self.attempt = attempt
        self.batch_size = max(1, int(batch_size))
        self.mode = str(mode or "").strip().lower() or None
        self.suppress_protocol_failure_summary = bool(
            suppress_protocol_failure_summary
        )
        self._buffer: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def __call__(self, event: dict | None = None, **kwargs: Any) -> None:
        raw = dict(event or {})
        raw.update(kwargs)
        message = str(raw.get("message") or "")
        if (
            self.suppress_protocol_failure_summary
            and str(raw.get("status") or "").strip().lower() == "failed"
            and message.startswith(("提链协议失败：", "提链协议异常："))
        ):
            return
        stage = str(raw.get("stage") or "").strip().lower()
        phase = str(raw.get("phase") or self.phase)
        if self.phase == "payment" and stage.startswith("otp"):
            phase = "sms"
        raw["phase"] = phase
        raw["attempt"] = raw.get("attempt", self.attempt)
        raw["mode"] = raw.get("mode") or self.mode
        with self._lock:
            self._buffer.append(raw)
            should_flush = len(self._buffer) >= self.batch_size
        if should_flush:
            self.flush()

    def emit(self, *, status: str, message: str, stage: str = "", **details: Any) -> None:
        self({"status": status, "message": message, "stage": stage, **details})

    def flush(self) -> None:
        with self._lock:
            if not self._buffer:
                return
            pending = self._buffer
            self._buffer = []
        try:
            db.append_account_paypal_events(self.account_id, pending)
        except Exception as exc:
            logger.warning(
                "[PayPal] 写入详细流程日志失败: account=%s error=%s",
                self.account_id, type(exc).__name__,
            )


def reload_runtime_settings() -> dict[str, int]:
    """Apply hot-loaded worker and queue settings without interrupting active tasks."""
    global _WORKERS, _QUEUE_LIMIT, _EXECUTOR, _QUEUE_SLOTS

    workers = _int_setting("PAYPAL_WORKERS", 20, 1, 64)
    queue_limit = _int_setting("PAYPAL_QUEUE_LIMIT", 500, workers, 5000)
    retired_executor = None
    with _RUNTIME_LOCK:
        if workers != _WORKERS:
            replacement = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="paypal")
            retired_executor = _EXECUTOR
            _EXECUTOR = replacement
            _WORKERS = workers
        if queue_limit != _QUEUE_LIMIT:
            if isinstance(_QUEUE_SLOTS, _DynamicQueueSlots):
                _QUEUE_SLOTS.resize(queue_limit)
            else:
                # Compatibility for tests or extensions that replace the limiter.
                _QUEUE_SLOTS = _DynamicQueueSlots(queue_limit)
            _QUEUE_LIMIT = queue_limit

    if retired_executor is not None:
        retired_executor.shutdown(wait=False, cancel_futures=False)
    return {"workers": _WORKERS, "queue_limit": _QUEUE_LIMIT}


def _submit_runtime(worker, **kwargs):
    """Submit against the current executor while excluding a concurrent swap."""
    with _RUNTIME_LOCK:
        return _EXECUTOR.submit(worker, **kwargs)


class PayPalWorkflowError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        stage: str,
        code: str = "workflow",
        retryable: bool = False,
        ambiguous: bool = False,
        replay_safe: bool = False,
        http_status: int | None = None,
        amount: Any = None,
        currency: str = "",
    ) -> None:
        self.stage = str(stage or "unknown")
        self.code = str(code or "workflow")
        self.retryable = bool(retryable)
        self.ambiguous = bool(ambiguous)
        self.replay_safe = bool(replay_safe)
        self.http_status = int(http_status) if http_status is not None else None
        self.amount = amount
        self.currency = str(currency or "")
        super().__init__(str(message or "PayPal workflow failed"))


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _safe_text(value: object, *, secrets: tuple[str, ...] = ()) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    for secret in sorted((str(item) for item in secrets if str(item)), key=len, reverse=True):
        text = text.replace(secret, "***")
    text = _BEARER_RE.sub(r"\1***", text)
    text = _PROXY_AUTH_RE.sub(r"\1***@", text)
    text = _SECRET_FIELD_RE.sub(r"\1***", text)
    text = re.sub(r"(?i)(ba_token=)BA-[A-Z0-9-]+", r"\1BA-***", text)
    return text[:500]


def _error_info(exc: Exception, *, secrets: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "error": _safe_text(f"{type(exc).__name__}: {exc}", secrets=secrets),
        "stage": str(getattr(exc, "stage", "unknown") or "unknown")[:80],
        "code": str(getattr(exc, "code", "unknown") or "unknown")[:80],
        "retryable": bool(getattr(exc, "retryable", False)),
        "ambiguous": bool(getattr(exc, "ambiguous", False)),
        "replay_safe": bool(getattr(exc, "replay_safe", False)),
        "amount": getattr(exc, "amount", None),
        "currency": str(getattr(exc, "currency", "") or ""),
    }


def _parse_verify_delays(value: object) -> list[float]:
    if isinstance(value, (list, tuple)):
        raw = value
    else:
        raw = str(value or "").replace(";", ",").split(",")
    out: list[float] = []
    for item in raw:
        if str(item).strip() == "":
            continue
        try:
            delay = max(0.0, min(3600.0, float(item)))
        except (TypeError, ValueError) as exc:
            raise ValueError("PAYPAL_PLUS_VERIFY_DELAYS 必须是逗号分隔的非负秒数") from exc
        out.append(delay)
    return out


def _normalize_country(value: object, fallback: str) -> str:
    country = str(value or fallback).strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", country):
        raise ValueError("国家必须是两位代码")
    return country


def _csv_values(value: object) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        raw = value
    else:
        raw = re.split(r"[,;\n]", str(value or ""))
    result: list[str] = []
    seen: set[str] = set()
    for item in raw:
        text = str(item or "").strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            result.append(text)
    return result


def _sms_settings(snapshot: dict, opts: dict) -> dict[str, Any]:
    frozen = snapshot.get("sms") if isinstance(snapshot.get("sms"), dict) else {}
    override = opts.get("sms") if isinstance(opts.get("sms"), dict) else {}
    luban_frozen = frozen.get("luban") if isinstance(frozen.get("luban"), dict) else {}
    luban_override = override.get("luban") if isinstance(override.get("luban"), dict) else {}
    smsbower_frozen = (
        frozen.get("smsbower") if isinstance(frozen.get("smsbower"), dict) else {}
    )
    smsbower_override = (
        override.get("smsbower") if isinstance(override.get("smsbower"), dict) else {}
    )
    herosms_frozen = (
        frozen.get("herosms") if isinstance(frozen.get("herosms"), dict) else {}
    )
    herosms_override = (
        override.get("herosms") if isinstance(override.get("herosms"), dict) else {}
    )

    def value(key: str, config_name: str, default: object) -> object:
        if key in luban_override and luban_override.get(key) is not None:
            return luban_override.get(key)
        if key in luban_frozen and luban_frozen.get(key) is not None:
            return luban_frozen.get(key)
        return getattr(cfg, config_name, default)

    def smsbower_value(key: str, config_name: str, default: object) -> object:
        if key in smsbower_override and smsbower_override.get(key) is not None:
            return smsbower_override.get(key)
        if key in smsbower_frozen and smsbower_frozen.get(key) is not None:
            return smsbower_frozen.get(key)
        return getattr(cfg, config_name, default)

    def herosms_value(key: str, config_name: str, default: object) -> object:
        if key in herosms_override and herosms_override.get(key) is not None:
            return herosms_override.get(key)
        if key in herosms_frozen and herosms_frozen.get(key) is not None:
            return herosms_frozen.get(key)
        return getattr(cfg, config_name, default)

    mode = str(
        override.get("mode")
        or frozen.get("mode")
        or getattr(cfg, "PAYPAL_SMS_MODE", "manual")
        or "manual"
    ).strip().lower()
    if mode not in {"manual", "auto"}:
        raise ValueError("PAYPAL_SMS_MODE 仅支持 manual / auto")
    channels = _csv_values(
        override.get("channels")
        or frozen.get("channels")
        or getattr(cfg, "PAYPAL_SMS_CHANNELS", "herosms")
    )
    if mode == "auto" and not channels:
        raise ValueError("自动接码时 PAYPAL_SMS_CHANNELS 不能为空")
    return {
        "mode": mode,
        "channels": channels,
        "max_retries": _int_value(
            override.get("max_retries", frozen.get("max_retries")),
            _int_setting("PAYPAL_SMS_MAX_RETRIES", 3, 1, 20),
            1,
            20,
        ),
        "herosms": {
            "handler_url": str(herosms_value(
                "handler_url", "PAYPAL_HEROSMS_HANDLER_URL",
                "https://hero-sms.com/stubs/handler_api.php",
            ) or ""),
            "api_key": str(herosms_value(
                "api_key", "PAYPAL_HEROSMS_API_KEY", "",
            ) or ""),
            "country_id": str(herosms_value(
                "country_id", "PAYPAL_HEROSMS_COUNTRY_ID", "16",
            ) or "16"),
            "service": str(herosms_value(
                "service", "PAYPAL_HEROSMS_SERVICE", "ts",
            ) or "ts"),
            "max_price": herosms_value(
                "max_price", "PAYPAL_HEROSMS_MAX_PRICE", 0.2,
            ),
            "operator": str(herosms_value(
                "operator", "PAYPAL_HEROSMS_OPERATOR", "",
            ) or ""),
            "fixed_price": str(herosms_value(
                "fixed_price", "PAYPAL_HEROSMS_FIXED_PRICE", "",
            ) or ""),
            "phone_exception": str(herosms_value(
                "phone_exception", "PAYPAL_HEROSMS_PHONE_EXCEPTION", "",
            ) or ""),
            "code_wait": _float_value(herosms_value(
                "code_wait", "PAYPAL_HEROSMS_CODE_WAIT", 120,
            ), 120, 1, 1800),
            "poll_interval": _float_value(herosms_value(
                "poll_interval", "PAYPAL_HEROSMS_POLL_INTERVAL", 5,
            ), 5, 0.1, 60),
            "request_timeout": _float_value(herosms_value(
                "request_timeout", "PAYPAL_HEROSMS_REQUEST_TIMEOUT", 20,
            ), 20, 1, 120),
            "proxy": str(herosms_value(
                "proxy", "PAYPAL_HEROSMS_PROXY", "",
            ) or ""),
        },
        "smsbower": {
            "handler_url": str(smsbower_value(
                "handler_url", "PAYPAL_SMSBOWER_HANDLER_URL",
                "https://smsbower.page/stubs/handler_api.php",
            ) or ""),
            "api_key": str(smsbower_value(
                "api_key", "PAYPAL_SMSBOWER_API_KEY", "",
            ) or ""),
            "country_id": str(smsbower_value(
                "country_id", "PAYPAL_SMSBOWER_COUNTRY_ID", "16",
            ) or "16"),
            "service": str(smsbower_value(
                "service", "PAYPAL_SMSBOWER_SERVICE", "ts",
            ) or "ts"),
            "min_price": smsbower_value(
                "min_price", "PAYPAL_SMSBOWER_MIN_PRICE", 0.07,
            ),
            "max_price": smsbower_value(
                "max_price", "PAYPAL_SMSBOWER_MAX_PRICE", 0.2,
            ),
            "code_wait": _float_value(smsbower_value(
                "code_wait", "PAYPAL_SMSBOWER_CODE_WAIT", 120,
            ), 120, 1, 1800),
            "poll_interval": _float_value(smsbower_value(
                "poll_interval", "PAYPAL_SMSBOWER_POLL_INTERVAL", 5,
            ), 5, 0.1, 60),
            "request_timeout": _float_value(smsbower_value(
                "request_timeout", "PAYPAL_SMSBOWER_REQUEST_TIMEOUT", 20,
            ), 20, 1, 120),
            "proxy": str(smsbower_value(
                "proxy", "PAYPAL_SMSBOWER_PROXY", "",
            ) or ""),
        },
        "luban": {
            "api_base": str(value("api_base", "PAYPAL_LUBAN_API_BASE", "https://lubansms.com/v2/api") or ""),
            "api_key": str(value("api_key", "PAYPAL_LUBAN_API_KEY", "") or ""),
            "country": str(value("country", "PAYPAL_LUBAN_COUNTRY", "Brazil") or "Brazil"),
            "service": str(value("service", "PAYPAL_LUBAN_SERVICE", "PayPal") or "PayPal"),
            "providers": _csv_values(value("providers", "PAYPAL_LUBAN_PROVIDERS", "")),
            "service_ids": _csv_values(value("service_ids", "PAYPAL_LUBAN_SERVICE_IDS", "")),
            "max_price": value("max_price", "PAYPAL_LUBAN_MAX_PRICE", ""),
            "max_attempts": _int_value(
                value("max_attempts", "PAYPAL_LUBAN_MAX_ATTEMPTS", 3), 3, 1, 50,
            ),
            "list_max_pages": _int_value(
                value("list_max_pages", "PAYPAL_LUBAN_LIST_MAX_PAGES", 5), 5, 1, 100,
            ),
            "code_wait": _float_value(
                value("code_wait", "PAYPAL_LUBAN_CODE_WAIT", 120), 120, 1, 1800,
            ),
            "poll_interval": _float_value(
                value("poll_interval", "PAYPAL_LUBAN_POLL_INTERVAL", 5), 5, 0.1, 60,
            ),
            "request_timeout": _float_value(
                value("request_timeout", "PAYPAL_LUBAN_REQUEST_TIMEOUT", 20), 20, 1, 120,
            ),
            "proxy": str(value("proxy", "PAYPAL_LUBAN_PROXY", "") or ""),
        },
    }


def _task_settings(flow_snapshot: dict | None, options: dict | None) -> dict[str, Any]:
    snapshot = dict(flow_snapshot or {})
    opts = dict(options or {})
    promo_strategy = str(
        opts.get("promo_strategy")
        or snapshot.get("promo_strategy")
        or getattr(cfg, "PAYPAL_STRIPE_PROMO_STRATEGY", "post_update")
        or "post_update"
    ).strip().lower()
    if promo_strategy not in {"upfront", "post_update"}:
        raise ValueError("promo_strategy 仅支持 upfront / post_update")
    # Upgrade legacy OAICS snapshots in place.  Extraction is Stripe-only.
    requested_mode = "stripe"
    buyer_mode = str(
        opts.get("buyer_mode")
        or snapshot.get("buyer_mode")
        or getattr(cfg, "PAYPAL_BUYER_MODE", "identity_elevation")
        or "identity_elevation"
    ).strip().lower()
    if buyer_mode not in {"original", "identity_elevation"}:
        raise ValueError("buyer_mode 仅支持 original / identity_elevation")
    payment_executor = str(
        opts.get("payment_executor")
        or snapshot.get("payment_executor")
        or getattr(cfg, "PAYPAL_PAYMENT_EXECUTOR", "local")
        or "local"
    ).strip().lower()
    if payment_executor not in {"local", "remote"}:
        raise ValueError("payment_executor 仅支持 local / remote")

    current_extract_pool = paypal_proxy_pool.pool_snapshot("extract")
    current_payment_pool = paypal_proxy_pool.pool_snapshot("payment")
    extract_pool = dict(snapshot.get("extract_pool") or current_extract_pool)
    payment_pool = dict(snapshot.get("payment_pool") or current_payment_pool)

    def task_value(key: str, config_name: str, default: object) -> object:
        if key in opts and opts.get(key) is not None:
            return opts.get(key)
        if key in snapshot and snapshot.get(key) is not None:
            return snapshot.get(key)
        return getattr(cfg, config_name, default)

    phone = str(opts.get("phone") or snapshot.get("phone") or getattr(cfg, "PAYPAL_PAYMENT_PHONE", "") or "").strip()
    sms_settings = _sms_settings(snapshot, opts)
    payment_country = _normalize_country(
        opts.get("country") or snapshot.get("payment_country"),
        str(getattr(cfg, "PAYPAL_PAYMENT_COUNTRY", "US") or "US"),
    )
    if not phone and sms_settings["mode"] == "auto":
        from core.paypal_sms import resolve_channel_country

        _, payment_country, _ = resolve_channel_country(sms_settings)
    return {
        "requested_mode": requested_mode,
        "promo_strategy": promo_strategy,
        "promo_id": str(snapshot.get("promo_id") or getattr(cfg, "PAYPAL_PROMO_ID", "plus-1-month-free") or "plus-1-month-free"),
        "extract_country": _normalize_country(
            opts.get("extract_country") or snapshot.get("extract_country"),
            str(getattr(cfg, "PAYPAL_EXTRACT_COUNTRY", "BR") or "BR"),
        ),
        "billing_country": _normalize_country(
            opts.get("billing_country") or snapshot.get("billing_country"),
            str(getattr(cfg, "PAYPAL_BILLING_COUNTRY", "DE") or "DE"),
        ),
        "payment_country": payment_country,
        "buyer_mode": buyer_mode,
        "payment_executor": payment_executor,
        "remote_api_base": str(task_value(
            "remote_api_base", "PAYPAL_REMOTE_API_BASE",
            "https://paypal.173.249.205.56.sslip.io/paypal-pay/api",
        ) or "").strip(),
        "remote_poll_interval": _float_value(
            task_value("remote_poll_interval", "PAYPAL_REMOTE_POLL_INTERVAL", 1.0),
            1.0, 0.1, 30.0,
        ),
        "remote_job_timeout": _float_value(
            task_value("remote_job_timeout", "PAYPAL_REMOTE_JOB_TIMEOUT", 600),
            600.0, 10.0, 3600.0,
        ),
        "phone": phone,
        "sms": sms_settings,
        "request_timeout": _float_value(
            task_value("request_timeout", "PAYPAL_REQUEST_TIMEOUT", 30.0), 30.0, 3.0, 120.0,
        ),
        "checkout_attempts": _int_value(
            task_value("checkout_attempts", "PAYPAL_CHECKOUT_MAX_ATTEMPTS", 5), 5, 1, 5,
        ),
        "extract_attempts": _int_value(
            task_value("extract_attempts", "PAYPAL_EXTRACT_MAX_ATTEMPTS", 3), 3, 1, 20,
        ),
        "payment_attempts": _int_value(
            task_value("payment_attempts", "PAYPAL_PAYMENT_MAX_ATTEMPTS", 2), 2, 1, 10,
        ),
        "retry_interval": _float_value(
            task_value("retry_interval", "PAYPAL_RETRY_INTERVAL", 1.0), 1.0, 0.0, 60.0,
        ),
        "verify_delays": _parse_verify_delays(
            task_value("verify_delays", "PAYPAL_PLUS_VERIFY_DELAYS", "5,30,120")
        ),
        "extract_pool": extract_pool,
        "payment_pool": payment_pool,
    }


def _assert_lease_snapshot(lease: paypal_proxy_pool.ProxyLease, expected: dict) -> None:
    pool_id = str(expected.get("pool_id") or "")
    version = str(expected.get("pool_version") or "")
    if pool_id and lease.pool_id != pool_id:
        raise PayPalWorkflowError(
            "任务引用的代理池 ID 已变化", stage="proxy_pool", code="pool_changed",
            replay_safe=True,
        )
    if version and lease.pool_version != version:
        raise PayPalWorkflowError(
            "任务提交后代理池版本已变化，无法使用不可变流程快照继续执行",
            stage="proxy_pool", code="pool_changed", replay_safe=True,
        )


def _validate_ba(url: object, token: object = "") -> tuple[str, str]:
    value = str(url or "").strip()
    try:
        parsed = urlsplit(value)
    except Exception as exc:
        raise PayPalWorkflowError("PayPal BA URL 无效", stage="result_validation", code="capability") from exc
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in {"paypal.com", "www.paypal.com"}:
        raise PayPalWorkflowError("PayPal BA URL 主机无效", stage="result_validation", code="capability")
    if parsed.path.rstrip("/") != "/agreements/approve":
        raise PayPalWorkflowError("PayPal BA URL 路径无效", stage="result_validation", code="capability")
    query_token = str((parse_qs(parsed.query).get("ba_token") or [""])[0]).strip()
    supplied = str(token or query_token).strip()
    if not _BA_TOKEN_RE.fullmatch(query_token) or supplied != query_token:
        raise PayPalWorkflowError("PayPal BA token 无效或与 URL 不一致", stage="result_validation", code="capability")
    return value, query_token


def _token_rejected(result: dict) -> bool:
    if result.get("token_expired") is True:
        return True
    if result.get("http_status") != 401:
        return False
    preview = str(result.get("response_preview") or "").lower()
    return not any(marker in preview for marker in (
        "<!doctype", "<html", "cloudflare", "cf-chl-", "turnstile", "captcha",
    ))


def _parse_local_timestamp(value: object) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is not None:
        return parsed.astimezone().replace(tzinfo=None)
    return parsed


def _conclusive_plan_result(result: dict) -> bool:
    if not bool(result.get("ok")):
        return False
    plan = str(
        result.get("current_plan_type") or result.get("plan_type") or ""
    ).strip().lower()
    if plan in {"", "guest", "unknown"}:
        return False
    if plan != "free":
        return True
    promo_status = str(result.get("plus_trial_status") or "").strip().lower()
    return result.get("promo_check_ok") is True and promo_status in {
        "available", "redeemed", "not_eligible", "unavailable",
    }


def _recent_plan_result(account_id: int) -> tuple[dict | None, float | None]:
    account = db.get_account(account_id) or {}
    raw = account.get("plan_last_success_result_json")
    try:
        result = json.loads(raw) if isinstance(raw, str) else dict(raw or {})
    except (TypeError, ValueError, json.JSONDecodeError):
        return None, None
    if not isinstance(result, dict) or not _conclusive_plan_result(result):
        return None, None
    checked_at = _parse_local_timestamp(
        account.get("plan_last_success_at") or result.get("checked_at")
    )
    if checked_at is None:
        return None, None
    age = max(0.0, (datetime.now() - checked_at).total_seconds())
    confirmed_zero_offer = (
        str(result.get("current_plan_type") or result.get("plan_type") or "")
        .strip()
        .lower()
        == "free"
        and result.get("plus_trial_eligible") is True
        and result.get("promo_check_ok") is True
        and str(result.get("plus_trial_status") or "").strip().lower() == "available"
    )
    if confirmed_zero_offer:
        # Eligibility was already proved in the registration context. Reusing
        # it avoids a later request-only CF probe invalidating that evidence;
        # Stripe still enforces the final amount == 0 invariant before payment.
        ttl = _float_setting(
            "PAYPAL_ELIGIBLE_PLAN_RESULT_TTL",
            86400.0,
            0.0,
            604800.0,
        )
    else:
        ttl = _float_setting("PAYPAL_PLAN_RESULT_TTL", 300.0, 0.0, 3600.0)
    if ttl <= 0 or age > ttl:
        return None, age
    return result, age


def _wait_for_active_plan_check(account_id: int, timeout: float) -> dict:
    deadline = time.monotonic() + max(1.0, min(90.0, float(timeout or 0.0)))
    while True:
        account = db.get_account(account_id) or {}
        status = str(account.get("plan_check_status") or "").strip().lower()
        if status not in {"queued", "running"}:
            return account
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return account
        time.sleep(min(0.25, remaining))


def _persist_refreshed_cookies(account_id: int, email: str, cookies: list[dict]) -> None:
    from core.account_cookie_store import persist_cookie_credential

    metadata = persist_cookie_credential(
        email, cookies, source="paypal_plus_verify_refresh", account_id=account_id,
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
    *, account_id: int, email: str, access_token: str, proxy: str | None,
    timeout: float, device_id: str | None = None, cookies: list[dict] | None = None,
    force_configured_proxy: bool = True,
) -> tuple[str, dict]:
    """Check current AT first; refresh only on explicit 401/token_expired.

    The zero-offer stage resolves the configured proxy once so the initial
    check and any token refresh stay on the same sticky session. Other callers
    leave the default enabled to prevent a PayPal/extraction proxy from being
    reused for qualification.
    """
    from core.plan_check_service import restore_account_request_context

    proxy, device_id, cookies = restore_account_request_context(
        account_id=account_id,
        proxy=proxy,
        device_id=device_id,
        cookies=cookies,
        force_configured_proxy=force_configured_proxy,
    )
    browser_family = resolve_plan_check_browser_family()
    context_kwargs: dict[str, Any] = {}
    if str(device_id or "").strip():
        context_kwargs["device_id"] = str(device_id).strip()
    if cookies is not None:
        context_kwargs["cookies"] = cookies
    result = check_account_plan(
        access_token, proxy=proxy, timeout=timeout, max_attempts=2,
        browser_family=browser_family,
        **context_kwargs,
    )
    if not _token_rejected(result):
        db.update_account_plan_check(acc_id=account_id, result=result)
        return access_token, result

    from core.account_token_refresh import refresh_account_web_access_token

    refreshed = refresh_account_web_access_token(
        account_id, access_token, proxy=proxy, max_attempts=1,
        browser_family=browser_family,
    )
    if not refreshed.get("ok"):
        result = dict(result)
        result["token_refresh_error"] = _safe_text(refreshed.get("error") or "Cookie AT 刷新失败")
        db.update_account_plan_check(acc_id=account_id, result=result)
        return access_token, result

    replacement = str(refreshed.get("access_token") or "")
    refreshed_cookies = list(refreshed.get("cookies") or [])
    verified_context = dict(context_kwargs)
    if refreshed_cookies:
        verified_context["cookies"] = refreshed_cookies
    verified = check_account_plan(
        replacement, proxy=proxy, timeout=timeout, max_attempts=2,
        browser_family=browser_family,
        **verified_context,
    )
    if verified.get("ok"):
        replaced = db.replace_account_access_token(
            account_id,
            expected_access_token=access_token,
            access_token=replacement,
            source="paypal_plus_verify_refresh",
        )
        if not replaced:
            return access_token, {
                "ok": False, "error": "套餐核验期间 Web AT 已被其他任务更新",
                "retryable": True, "checked_at": _now(),
            }
        if refreshed_cookies:
            try:
                _persist_refreshed_cookies(account_id, email, refreshed_cookies)
            except Exception as exc:
                logger.warning("[PayPal] 刷新 AT 后更新 Cookie 失败: account=%s error=%s", account_id, type(exc).__name__)
        verified["token_refreshed"] = True
        db.update_account_plan_check(acc_id=account_id, result=verified)
        return replacement, verified

    verified = dict(verified)
    verified["token_refresh_error"] = _safe_text(verified.get("error") or "新 AT 未通过套餐核验")
    db.update_account_plan_check(acc_id=account_id, result=verified)
    return access_token, verified


def _check_zero_offer(
    *, account_id: int, email: str, access_token: str,
    lease: paypal_proxy_pool.ProxyLease | None,
    settings: dict,
) -> tuple[str, dict]:
    running_kwargs: dict[str, Any] = {}
    if lease is not None:
        running_kwargs.update({
            "proxy_pool_ref": lease.entry_id,
            "proxy_pool_version": lease.pool_version,
        })
    db.mark_account_paypal_running(
        account_id,
        stage="zero_offer",
        message="正在检查当前套餐与 0 元优惠",
        **running_kwargs,
    )
    trace = _PayPalTraceSink(
        account_id=account_id, phase="zero_offer", batch_size=1,
    )
    token = access_token
    result, cache_age = _recent_plan_result(account_id)
    if result is not None:
        trace.emit(
            status="reused",
            stage="account_plan",
            message=f"复用注册阶段套餐与优惠结果：age={cache_age:.1f}s",
        )
    else:
        account = db.get_account(account_id) or {}
        plan_status = str(account.get("plan_check_status") or "").strip().lower()
        if plan_status in {"queued", "running"}:
            trace.emit(
                status="waiting",
                stage="account_plan",
                message="注册阶段套餐与优惠查询仍在运行，等待其结果",
            )
            wait_timeout = max(
                5.0,
                min(90.0, float(settings["request_timeout"]) * 2.0 + 5.0),
            )
            account = _wait_for_active_plan_check(account_id, wait_timeout)
            result, cache_age = _recent_plan_result(account_id)
            if result is not None:
                trace.emit(
                    status="reused",
                    stage="account_plan",
                    message=f"注册阶段套餐与优惠查询完成，复用结果：age={cache_age:.1f}s",
                )
            elif str(account.get("plan_check_status") or "").strip().lower() in {"queued", "running"}:
                error = "注册阶段套餐与优惠查询仍在运行，请稍后重试 PayPal 流程"
                db.update_account_paypal(
                    account_id,
                    stage="zero_offer",
                    result={"status": "retryable_error", "error": error},
                )
                raise PayPalWorkflowError(
                    error,
                    stage="zero_offer",
                    code="plan_check_busy",
                    retryable=False,
                )

        if result is None:
            if not db.claim_account_plan_check(
                acc_id=account_id,
                trigger="paypal_zero_offer",
            ):
                error = "套餐与优惠查询正被其他任务占用，请稍后重试 PayPal 流程"
                db.update_account_paypal(
                    account_id,
                    stage="zero_offer",
                    result={"status": "retryable_error", "error": error},
                )
                raise PayPalWorkflowError(
                    error,
                    stage="zero_offer",
                    code="plan_check_busy",
                    retryable=False,
                )
            if not db.mark_account_plan_check_running(account_id):
                raise PayPalWorkflowError(
                    "账号已删除或套餐查询状态被重置",
                    stage="zero_offer",
                    code="state",
                )

            try:
                from core.plan_check_service import restore_account_request_context

                plan_proxy, device_id, cookies = restore_account_request_context(
                    account_id=account_id,
                    proxy=None,
                    device_id=None,
                    cookies=None,
                    force_configured_proxy=True,
                )
                trace.emit(
                    status="context",
                    stage="account_plan",
                    message=(
                        "使用当前配置代理查询套餐与优惠："
                        f"proxy={'configured' if plan_proxy else 'direct'} "
                        f"device={bool(device_id)} cookies={len(cookies or [])}"
                    ),
                )
                token, result = _check_plan_current_token(
                    account_id=account_id,
                    email=email,
                    access_token=access_token,
                    proxy=plan_proxy,
                    timeout=settings["request_timeout"],
                    device_id=device_id,
                    cookies=cookies,
                    force_configured_proxy=False,
                )
            except Exception as exc:
                error = _safe_text(
                    f"{type(exc).__name__}: {exc}",
                    secrets=(access_token,),
                )
                failed_result = {
                    "ok": False,
                    "checked_at": _now(),
                    "error": error,
                    "retryable": True,
                }
                try:
                    db.update_account_plan_check(
                        acc_id=account_id,
                        result=failed_result,
                    )
                except Exception:
                    logger.exception(
                        "[PayPal] 套餐查询异常后写入失败状态失败: account=%s",
                        account_id,
                    )
                raise PayPalWorkflowError(
                    error,
                    stage="zero_offer",
                    code="plan_check",
                    retryable=True,
                ) from exc
    if result.get("ok"):
        trace.emit(
            status="response",
            stage="account_plan",
            message=(
                "套餐与优惠查询完成："
                f"plan={str(result.get('current_plan_type') or result.get('plan_type') or 'unknown').lower()} "
                f"promo={str(result.get('plus_trial_status') or 'unknown').lower()}"
            ),
            http_status=result.get("http_status"),
        )
    else:
        trace.emit(
            status="failed",
            stage="account_plan",
            message="套餐与优惠查询失败",
            http_status=result.get("http_status"),
        )
    campaign = str(result.get("plus_trial_campaign_id") or settings["promo_id"])
    if not result.get("ok"):
        code = "invalid_token" if _token_rejected(result) else "plan_check"
        retryable = code != "invalid_token" and bool(result.get("retryable", True))
        db.update_account_paypal(
            account_id, stage="zero_offer", result={
                "status": "retryable_error" if retryable else "failed",
                "campaign": campaign,
                "error": _safe_text(result.get("error") or "套餐查询失败"),
            },
        )
        raise PayPalWorkflowError(
            result.get("error") or "套餐查询失败",
            stage="zero_offer", code=code, retryable=retryable,
        )

    plan = str(result.get("current_plan_type") or result.get("plan_type") or "").lower()
    promo_status = str(result.get("plus_trial_status") or "").lower()
    # A failed coupon probe is never evidence that the account lacks an offer.
    if plan == "free" and result.get("promo_check_ok") is False:
        db.update_account_paypal(
            account_id, stage="zero_offer", result={
                "status": "retryable_error", "campaign": campaign,
                "error": _safe_text(result.get("promo_check_error") or "优惠接口临时失败"),
            },
        )
        raise PayPalWorkflowError(
            result.get("promo_check_error") or "优惠接口临时失败",
            stage="zero_offer", code="promo_check", retryable=True,
        )

    eligible = (
        plan == "free"
        and bool(result.get("plus_trial_eligible"))
        and promo_status == "available"
    )
    if not eligible:
        db.update_account_paypal(
            account_id, stage="zero_offer", result={
                "status": "not_eligible", "campaign": campaign,
                "amount": None, "currency": None,
            },
        )
        raise PayPalWorkflowError(
            "当前账号没有明确可用的 0 元 Plus 优惠",
            stage="zero_offer", code="not_eligible", retryable=False,
        )

    db.update_account_paypal(
        account_id, stage="zero_offer", result={
            "status": "eligible", "campaign": campaign,
        },
    )
    return token, result


def _run_extract_legacy_oaics(
    *, account_id: int, email: str, access_token: str, settings: dict,
) -> tuple[bool, str]:
    attempted: set[str] = set()
    last_error = "PayPal 提链失败"
    token = access_token
    total_attempt = 0
    use_stripe_mode = False
    oaics_fallback_reason = ""
    stripe_attempts = 0
    network_failures = 0
    checkout_limit = int(settings["checkout_attempts"])
    network_limit = int(settings["extract_attempts"])
    while True:
        requested_mode = "stripe" if use_stripe_mode else "oaics"
        adapter_invoked = False
        attempt_label = (
            f"cs_live {stripe_attempts + 1}/{checkout_limit}"
            if requested_mode == "stripe"
            else "OAICS 1/1"
        )
        lease = None
        trace: _PayPalTraceSink | None = None
        try:
            lease = paypal_proxy_pool.acquire("extract", exclude_entry_ids=attempted)
            attempted.add(lease.entry_id)
            _assert_lease_snapshot(lease, settings["extract_pool"])
            token, account_result = _check_zero_offer(
                account_id=account_id, email=email, access_token=token,
                lease=lease, settings=settings,
            )
            total_attempt += 1
            if requested_mode == "stripe":
                stripe_attempts += 1
            adapter_invoked = True
            attempt_label = (
                f"cs_live {stripe_attempts}/{checkout_limit}"
                if requested_mode == "stripe"
                else "OAICS 1/1"
            )
            trace = _PayPalTraceSink(
                account_id=account_id, phase="extract", attempt=total_attempt,
                mode=requested_mode,
                suppress_protocol_failure_summary=True,
            )
            trace.emit(
                status="step", stage="proxy", mode=requested_mode,
                message=(
                    f"开始 {attempt_label}，提链代理 entry={lease.entry_id[:8]}"
                ),
            )
            if not db.mark_account_paypal_running(
                account_id, stage="extract",
                message=f"正在创建并执行 {attempt_label}",
                mode=requested_mode,
            ):
                raise PayPalWorkflowError("账号已删除或 PP 状态被重置", stage="extract", code="state")

            from core.paypal_extract import extract_paypal_link

            try:
                result = extract_paypal_link(
                    access_token=token,
                    email=email,
                    proxy=lease.proxy,
                    requested_mode=requested_mode,
                    promo_strategy=settings["promo_strategy"],
                    promo_id=settings["promo_id"],
                    country=settings["extract_country"],
                    billing_country=settings["billing_country"],
                    request_timeout=settings["request_timeout"],
                    account_result=account_result,
                    trace=trace,
                    allow_stripe_fallback=False,
                )
            finally:
                trace.flush()
            amount = result.get("amount")
            try:
                amount_number = int(amount)
            except (TypeError, ValueError) as exc:
                raise PayPalWorkflowError(
                    "Checkout 未返回可解析的实付金额", stage="amount_check", code="not_zero",
                    amount=amount, currency=str(result.get("currency") or ""),
                ) from exc
            if amount_number != 0:
                raise PayPalWorkflowError(
                    "Checkout 实付金额不是 0", stage="amount_check", code="not_zero",
                    amount=amount_number, currency=str(result.get("currency") or ""),
                )
            ba_url, ba_token = _validate_ba(
                result.get("paypal_approve_url"), result.get("ba_token"),
            )
            db.update_account_paypal(
                account_id, stage="zero_offer", result={
                    "status": "eligible", "campaign": settings["promo_id"],
                    "amount": amount_number,
                    "currency": str(result.get("currency") or "").upper(),
                },
            )
            db.update_account_paypal(
                account_id, stage="extract", result={
                    "status": "success", "message": "PayPal BA 链提取成功",
                    "requested_mode": "oaics",
                    "actual_mode": result.get("actual_mode") or requested_mode,
                    "fallback_reason": (
                        result.get("fallback_reason") or oaics_fallback_reason or None
                    ),
                    "ba_url": ba_url, "ba_token": ba_token,
                    "proxy_pool_ref": lease.entry_id,
                    "proxy_pool_version": lease.pool_version,
                },
            )
            paypal_proxy_pool.release(
                lease, success=True, country=settings["extract_country"],
                uploaded_bytes=int(result.get("uploaded_bytes") or 0),
                downloaded_bytes=int(result.get("downloaded_bytes") or 0),
            )
            logger.info(
                "[PayPal] 提链成功: account=%s mode=%s fallback=%s",
                account_id, result.get("actual_mode") or requested_mode,
                bool(result.get("fallback_reason") or oaics_fallback_reason),
            )
            return True, token
        except Exception as exc:
            info = _error_info(exc, secrets=(access_token, token, lease.proxy if lease else ""))
            last_error = info["error"]
            if lease is not None:
                paypal_proxy_pool.release(
                    lease, success=False, failure_stage=info["stage"],
                    country=settings["extract_country"],
                )

            if info["code"] in {"not_eligible", "not_zero"}:
                if info["code"] == "not_zero":
                    db.update_account_paypal(
                        account_id, stage="zero_offer", result={
                            "status": "not_eligible", "campaign": settings["promo_id"],
                            "amount": info.get("amount"), "currency": info.get("currency"),
                        },
                    )
                db.update_account_paypal(
                    account_id, stage="extract", result={
                        "status": "unavailable", "message": last_error,
                        "requested_mode": "oaics", "actual_mode": requested_mode,
                        "stage": info["stage"],
                    },
                )
                return False, token

            stage = str(info["stage"] or "")
            oaics_route_switch = (
                requested_mode == "oaics"
                and adapter_invoked
                and info["code"] == "fallback"
                and stage == "checkout_create"
            )
            oaics_network_retry = (
                requested_mode == "oaics" and adapter_invoked and info["retryable"]
            )
            if oaics_network_retry:
                network_failures += 1
            if oaics_route_switch:
                use_stripe_mode = True
                oaics_fallback_reason = f"oaics_{info['code']}_{stage or 'unknown'}"[:160]
                if trace is not None:
                    trace.emit(
                        status="fallback", stage=stage, mode="oaics",
                        message=(
                            f"OAICS Checkout 返回 Hosted 类型：{last_error}；"
                            f"准备 cs_live 1/{checkout_limit}"
                        ),
                    )
                    trace.flush()
                logger.warning(
                    "[PayPal] OAICS Checkout 返回 Hosted 类型，切换 hosted Stripe: "
                    "account=%s next=cs_live 1/%s stage=%s code=%s",
                    account_id, checkout_limit, stage, info["code"],
                )
                db.mark_account_paypal_running(
                    account_id, stage="extract",
                    message=f"OAICS 返回 Hosted 类型，准备 cs_live 1/{checkout_limit}",
                    mode="stripe",
                )
                if settings["retry_interval"]:
                    time.sleep(settings["retry_interval"])
                continue

            if oaics_network_retry and network_failures < network_limit:
                if trace is not None:
                    trace.emit(
                        status="fallback", stage=stage, mode="oaics",
                        message=(
                            f"OAICS 网络临时失败：{last_error}；"
                            f"轮换代理后重试 OAICS（{network_failures + 1}/{network_limit}）"
                        ),
                    )
                    trace.flush()
                logger.warning(
                    "[PayPal] OAICS 网络临时失败，保持 OAICS 模式并轮换代理: "
                    "account=%s attempt=%s/%s stage=%s",
                    account_id, network_failures, network_limit, stage,
                )
                db.mark_account_paypal_running(
                    account_id, stage="extract",
                    message="OAICS 网络临时失败，轮换代理后重试 OAICS",
                    mode="oaics",
                )
                if settings["retry_interval"]:
                    time.sleep(settings["retry_interval"])
                continue

            checkout_miss = requested_mode == "stripe" and info["code"] == "unavailable" and (
                stage == "checkout_create"
                or stage == "redirect"
                or stage.startswith("stripe_")
            )
            if checkout_miss:
                if stripe_attempts < checkout_limit:
                    if trace is not None:
                        trace.emit(
                            status="fallback", stage=stage, mode="stripe",
                            message=(
                                f"cs_live {stripe_attempts}/{checkout_limit} 未命中："
                                f"{last_error}；准备 cs_live "
                                f"{stripe_attempts + 1}/{checkout_limit}"
                            ),
                        )
                        trace.flush()
                    logger.warning(
                        "[PayPal] cs_live 未命中，重新创建并轮换代理: "
                        "account=%s attempt=%s/%s total_attempt=%s stage=%s",
                        account_id, stripe_attempts, checkout_limit, total_attempt, stage,
                    )
                    db.mark_account_paypal_running(
                        account_id, stage="extract",
                        message=(
                            f"cs_live {stripe_attempts}/{checkout_limit} 未命中，"
                            f"准备 cs_live {stripe_attempts + 1}/{checkout_limit}"
                        ),
                        mode="stripe",
                    )
                    if settings["retry_interval"]:
                        time.sleep(settings["retry_interval"])
                    continue
                db.update_account_paypal(
                    account_id, stage="extract", result={
                        "status": "unavailable", "message": last_error,
                        "requested_mode": "oaics", "actual_mode": "stripe",
                        "fallback_reason": oaics_fallback_reason or None, "stage": stage,
                    },
                )
                logger.warning(
                    "[PayPal] cs_live 撞链次数已用尽: account=%s attempts=%s stage=%s",
                    account_id, stripe_attempts, stage,
                )
                return False, token

            if info["code"] == "unavailable":
                db.update_account_paypal(
                    account_id, stage="extract", result={
                        "status": "unavailable", "message": last_error,
                        "requested_mode": "oaics", "actual_mode": requested_mode,
                        "fallback_reason": oaics_fallback_reason or None, "stage": stage,
                    },
                )
                return False, token

            if info["retryable"] and not oaics_network_retry:
                network_failures += 1
            if (
                info["retryable"]
                and network_failures < network_limit
                and (requested_mode != "stripe" or stripe_attempts < checkout_limit)
            ):
                if trace is not None:
                    trace.emit(
                        status="fallback", stage=stage, mode=requested_mode,
                        message=(
                            f"{attempt_label} 网络临时失败：{last_error}；"
                            "轮换代理后重试"
                        ),
                    )
                    trace.flush()
                logger.warning(
                    "[PayPal] 提链网络临时失败，轮换代理: "
                    "account=%s mode=%s network_attempt=%s/%s total_attempt=%s stage=%s",
                    account_id, requested_mode, network_failures, network_limit,
                    total_attempt, stage,
                )
                if settings["retry_interval"]:
                    time.sleep(settings["retry_interval"])
                continue

            db.update_account_paypal(
                account_id, stage="extract", result={
                    "status": "failed", "error": last_error,
                    "stage": info["stage"], "requested_mode": "oaics",
                    "actual_mode": requested_mode,
                    "fallback_reason": oaics_fallback_reason or None,
                },
            )
            return False, token


def _run_extract(
    *, account_id: int, email: str, access_token: str, settings: dict,
) -> tuple[bool, str]:
    """Extract a zero-value PayPal BA using Stripe only, at most five times."""
    attempted: set[str] = set()
    token = access_token
    checkout_limit = max(1, min(5, int(settings.get("checkout_attempts") or 5)))

    # Eligibility belongs to the account's registration context, not to a
    # Stripe checkout attempt. Run it once before leasing any extraction proxy.
    try:
        token, account_result = _check_zero_offer(
            account_id=account_id,
            email=email,
            access_token=token,
            lease=None,
            settings=settings,
        )
    except Exception as exc:
        info = _error_info(exc, secrets=(access_token, token))
        unavailable = info["code"] == "not_eligible"
        result = {
            "status": "unavailable" if unavailable else "failed",
            "stage": info["stage"],
            "requested_mode": "stripe",
            "actual_mode": "stripe",
            "fallback_reason": None,
        }
        if unavailable:
            result["message"] = info["error"]
        else:
            result["error"] = info["error"]
        db.update_account_paypal(account_id, stage="extract", result=result)
        return False, token

    for attempt in range(1, checkout_limit + 1):
        lease = None
        trace: _PayPalTraceSink | None = None
        attempt_label = f"Stripe {attempt}/{checkout_limit}"
        try:
            lease = paypal_proxy_pool.acquire("extract", exclude_entry_ids=attempted)
            attempted.add(lease.entry_id)
            _assert_lease_snapshot(lease, settings["extract_pool"])

            trace = _PayPalTraceSink(
                account_id=account_id,
                phase="extract",
                attempt=attempt,
                mode="stripe",
                suppress_protocol_failure_summary=True,
            )
            trace.emit(
                status="step",
                stage="proxy",
                mode="stripe",
                message=f"开始 {attempt_label}，提链代理 entry={lease.entry_id[:8]}",
            )
            if not db.mark_account_paypal_running(
                account_id,
                stage="extract",
                message=f"正在创建并执行 {attempt_label}",
                mode="stripe",
            ):
                raise PayPalWorkflowError(
                    "账号已删除或 PP 状态被重置",
                    stage="extract",
                    code="state",
                )

            from core.paypal_extract import extract_paypal_link

            try:
                result = extract_paypal_link(
                    access_token=token,
                    email=email,
                    proxy=lease.proxy,
                    requested_mode="stripe",
                    promo_strategy=settings["promo_strategy"],
                    promo_id=settings["promo_id"],
                    country=settings["extract_country"],
                    billing_country=settings["billing_country"],
                    request_timeout=settings["request_timeout"],
                    account_result=account_result,
                    trace=trace,
                    allow_stripe_fallback=False,
                )
            finally:
                trace.flush()

            actual_mode = str(result.get("actual_mode") or "stripe").strip().lower()
            if actual_mode != "stripe":
                raise PayPalWorkflowError(
                    "Stripe Checkout 返回了非 Stripe 会话",
                    stage="checkout_create",
                    code="unavailable",
                    retryable=True,
                )

            amount = result.get("amount")
            try:
                amount_number = int(amount)
            except (TypeError, ValueError) as exc:
                raise PayPalWorkflowError(
                    "Checkout 未返回可解析的实付金额",
                    stage="amount_check",
                    code="not_zero",
                    amount=amount,
                    currency=str(result.get("currency") or ""),
                ) from exc
            if amount_number != 0:
                raise PayPalWorkflowError(
                    "Checkout 实付金额不是 0",
                    stage="amount_check",
                    code="not_zero",
                    amount=amount_number,
                    currency=str(result.get("currency") or ""),
                )

            ba_url, ba_token = _validate_ba(
                result.get("paypal_approve_url"), result.get("ba_token"),
            )
            db.update_account_paypal(
                account_id,
                stage="zero_offer",
                result={
                    "status": "eligible",
                    "campaign": settings["promo_id"],
                    "amount": amount_number,
                    "currency": str(result.get("currency") or "").upper(),
                },
            )
            db.update_account_paypal(
                account_id,
                stage="extract",
                result={
                    "status": "success",
                    "message": "PayPal BA 链提取成功",
                    "requested_mode": "stripe",
                    "actual_mode": "stripe",
                    "fallback_reason": None,
                    "ba_url": ba_url,
                    "ba_token": ba_token,
                    "proxy_pool_ref": lease.entry_id,
                    "proxy_pool_version": lease.pool_version,
                },
            )
            paypal_proxy_pool.release(
                lease,
                success=True,
                country=settings["extract_country"],
                uploaded_bytes=int(result.get("uploaded_bytes") or 0),
                downloaded_bytes=int(result.get("downloaded_bytes") or 0),
            )
            logger.info(
                "[PayPal] Stripe 提链成功: account=%s attempt=%s/%s",
                account_id,
                attempt,
                checkout_limit,
            )
            return True, token
        except Exception as exc:
            info = _error_info(
                exc,
                secrets=(access_token, token, lease.proxy if lease else ""),
            )
            if lease is not None:
                paypal_proxy_pool.release(
                    lease,
                    success=False,
                    failure_stage=info["stage"],
                    country=settings["extract_country"],
                )

            if info["code"] in {"not_eligible", "not_zero"}:
                if info["code"] == "not_zero":
                    db.update_account_paypal(
                        account_id,
                        stage="zero_offer",
                        result={
                            "status": "not_eligible",
                            "campaign": settings["promo_id"],
                            "amount": info.get("amount"),
                            "currency": info.get("currency"),
                        },
                    )
                db.update_account_paypal(
                    account_id,
                    stage="extract",
                    result={
                        "status": "unavailable",
                        "message": info["error"],
                        "requested_mode": "stripe",
                        "actual_mode": "stripe",
                        "fallback_reason": None,
                        "stage": info["stage"],
                    },
                )
                return False, token

            stage = str(info["stage"] or "")
            checkout_miss = info["code"] in {"unavailable", "fallback"} and (
                stage == "checkout_create"
                or stage == "redirect"
                or stage.startswith("stripe_")
            )
            can_retry = attempt < checkout_limit and (checkout_miss or info["retryable"])
            if can_retry:
                if trace is not None:
                    trace.emit(
                        status="retrying",
                        stage=stage,
                        mode="stripe",
                        message=(
                            f"{attempt_label} 失败：{info['error']}；轮换代理后准备 "
                            f"Stripe {attempt + 1}/{checkout_limit}"
                        ),
                    )
                    trace.flush()
                db.mark_account_paypal_running(
                    account_id,
                    stage="extract",
                    message=(
                        f"Stripe {attempt}/{checkout_limit} 失败，准备 "
                        f"Stripe {attempt + 1}/{checkout_limit}"
                    ),
                    mode="stripe",
                )
                logger.warning(
                    "[PayPal] Stripe 提链失败，轮换代理重试: "
                    "account=%s attempt=%s/%s stage=%s code=%s",
                    account_id,
                    attempt,
                    checkout_limit,
                    stage,
                    info["code"],
                )
                if settings["retry_interval"]:
                    time.sleep(settings["retry_interval"])
                continue

            final_status = "unavailable" if info["code"] in {"unavailable", "fallback"} else "failed"
            result = {
                "status": final_status,
                "stage": info["stage"],
                "requested_mode": "stripe",
                "actual_mode": "stripe",
                "fallback_reason": None,
            }
            if final_status == "unavailable":
                result["message"] = info["error"]
            else:
                result["error"] = info["error"]
            db.update_account_paypal(account_id, stage="extract", result=result)
            if checkout_miss and attempt >= checkout_limit:
                logger.warning(
                    "[PayPal] Stripe 提链次数已用尽: account=%s attempts=%s stage=%s",
                    account_id,
                    checkout_limit,
                    stage,
                )
            return False, token

    return False, token


_PAYMENT_PRE_MUTATION_STAGES = frozenset({
    "input", "phone_required", "proxy", "proxy_pool", "proxy_country", "session",
    "remote_input", "remote_session", "remote_device", "remote_create",
    "agreement_load", "agreement_init", "agreement_challenge",
    "agreement_redirect", "datadome", "datadome_fallback", "preflight",
    "risk_bootstrap", "risk_p1", "risk_p2", "risk_w", "tealeaf",
    "guest_onboarding", "guest_onboarding_redirect",
    "observability", "signup_context", "checkout_context", "locale_metadata",
    "address_normalization",
})

_PAYMENT_NEW_NUMBER_FAILURES = frozenset({
    ("otp_initiate", "SMS_LIMIT_EXCEEDED"),
    ("sms_poll", "TIMEOUT"),
    ("signup", "OAS_ERROR"),
})


def _payment_failure_is_pre_mutation(info: dict) -> bool:
    """Return true only when the adapter proves a whole-flow replay is safe."""
    return bool(info.get("replay_safe")) and str(info.get("stage") or "") in _PAYMENT_PRE_MUTATION_STAGES


def _payment_retry_from_start(info: dict) -> bool:
    """Rotate only for retryable failures before the first PayPal mutation."""
    return bool(info.get("retryable")) and _payment_failure_is_pre_mutation(info)


def _payment_can_restart_with_new_number(info: dict) -> bool:
    """Restart only after an explicit rejection or a pre-submit SMS timeout."""
    return (
        bool(info.get("replay_safe"))
        and not bool(info.get("ambiguous"))
        and (
            str(info.get("stage") or "").strip().lower(),
            str(info.get("code") or "").strip().upper(),
        ) in _PAYMENT_NEW_NUMBER_FAILURES
    )


def _payment_result_error_info(result: dict) -> dict[str, Any]:
    """Normalize the payment adapter's structured failure without exposing bodies."""
    payload = result.get("error")
    details = dict(payload) if isinstance(payload, dict) else {}
    stage = str(details.get("stage") or result.get("stage") or "payment_result")[:80]
    code = str(details.get("code") or result.get("error_code") or "PAYMENT_FAILED")[:80]
    retryable_value = result.get("retryable") if "retryable" in result else details.get("retryable", False)
    replay_value = result.get("replay_safe") if "replay_safe" in result else details.get("replay_safe", False)
    ambiguous_value = result.get("ambiguous") if "ambiguous" in result else details.get("ambiguous", False)
    http_status = details.get("http_status", result.get("http_status"))
    if isinstance(payload, dict):
        message = f"PayPal 支付失败: [{stage}] {code}"
    else:
        message = str(payload or result.get("message") or f"PayPal 支付失败: [{stage}] {code}")
    return {
        "error": _safe_text(message),
        "stage": stage,
        "code": code,
        "retryable": bool(retryable_value),
        "replay_safe": bool(replay_value),
        "ambiguous": bool(ambiguous_value),
        "http_status": http_status,
    }


def _service_context(settings: dict, lease: paypal_proxy_pool.ProxyLease) -> dict:
    return {
        "proxy_entry_id": lease.entry_id,
        "proxy_pool_id": lease.pool_id,
        "proxy_pool_version": lease.pool_version,
        "payment_country": settings["payment_country"],
        "buyer_mode": settings["buyer_mode"],
        "payment_executor": settings.get("payment_executor", "local"),
        "remote_api_base": settings.get("remote_api_base", ""),
        "remote_poll_interval": settings.get("remote_poll_interval", 1.0),
        "remote_job_timeout": settings.get("remote_job_timeout", 600.0),
        "request_timeout": settings["request_timeout"],
        "verify_delays": list(settings["verify_delays"]),
        # This object lives only inside the dedicated private persisted context.
        # It freezes the SMS API route for OTP continuation and is stripped from
        # every account/job list response.
        "sms": json.loads(json.dumps(settings.get("sms") or {}, ensure_ascii=False)),
    }


def _remote_checkpoint_callback(
    *,
    account_id: int,
    settings: dict,
    lease: paypal_proxy_pool.ProxyLease,
):
    """Build a durable checkpoint callback for the remote executor."""
    service_meta = _service_context(settings, lease)

    def checkpoint(remote_context: dict, _job: dict) -> None:
        private_context = dict(remote_context or {})
        private_context["_paypal_service"] = service_meta
        if not db.checkpoint_account_paypal_payment_context(
            account_id, private_context,
        ):
            raise PayPalWorkflowError(
                "账号状态已变化，无法保存远程 PayPal 任务上下文",
                stage="remote_checkpoint",
                code="REMOTE_CHECKPOINT_REJECTED",
                retryable=False,
                ambiguous=True,
                replay_safe=False,
            )

    return checkpoint


def _is_remote_context(value: object) -> bool:
    return (
        isinstance(value, dict)
        and str(value.get("executor") or "").strip().lower() == "remote"
        and bool(str(value.get("job_id") or "").strip())
        and bool(str(value.get("device_cookie") or "").strip())
    )


def _remote_context_needs_resume(account_context: dict) -> bool:
    remote_context = next((
        value for value in (
            account_context.get("paypal_otp_context"),
            account_context.get("paypal_payment_context"),
        )
        if _is_remote_context(value)
    ), None)
    if not isinstance(remote_context, dict):
        return False
    return str(remote_context.get("last_status") or "").strip().lower() not in {
        "completed", "failed", "cancelled",
    }


def _sms_db_result(
    activation: dict,
    *,
    status: str,
    error: object = None,
) -> dict[str, Any]:
    value = dict(activation or {})
    result: dict[str, Any] = {
        "status": status,
        "channel": value.get("channel"),
        "provider": value.get("provider"),
        "service_id": value.get("service_id"),
        "request_id": value.get("request_id"),
        "country": value.get("country"),
        "cost": value.get("cost"),
        "phone_masked": value.get("phone_masked"),
        "context": value,
    }
    if status in {"acquired", "polling", "waiting", "code_received", "submitted"}:
        result["acquired_at"] = _now()
    if status in {"consumed", "rejected"}:
        result["completed_at"] = _now()
    if error is not None:
        result["error"] = _safe_text(error)
    return result


def _reject_sms_before_payment(
    *, account_id: int, settings: dict, activation: dict, reason: object,
) -> None:
    """Reject only when the payment adapter proved no mutation occurred."""
    from core import paypal_sms

    try:
        paypal_sms.reject_number(settings["sms"], activation)
    except Exception as exc:
        db.update_account_paypal_sms(
            account_id,
            _sms_db_result(
                activation,
                status="failed",
                error=f"支付前失败且接码渠道拒号失败: {type(exc).__name__}: {exc}",
            ),
        )
        logger.warning(
            "[PayPal][SMS] 支付前拒号失败: account=%s channel=%s error=%s",
            account_id, activation.get("channel"), type(exc).__name__,
        )
        return
    db.update_account_paypal_sms(
        account_id,
        _sms_db_result(activation, status="rejected", error=reason),
    )


def _verify_plus(
    *, account_id: int, email: str, access_token: str,
    lease: paypal_proxy_pool.ProxyLease, settings: dict,
    start_message: str = "",
    authorization_confirmed: bool = True,
) -> dict:
    if not db.update_account_paypal(
        account_id, stage="payment", result={
            "status": "verifying",
            "message": start_message or (
                "PayPal 已授权，正在用当前 Web AT 确认 Plus"
                if authorization_confirmed
                else "尚未取得 PayPal Billing Agreement，正在只读核验套餐"
            ),
            "proxy_pool_ref": lease.entry_id, "proxy_pool_version": lease.pool_version,
        },
    ):
        return {"status": "verification_blocked", "error": "账号已删除"}

    token = access_token
    delays = [0.0, *list(settings.get("verify_delays") or [])]
    last_result: dict = {}
    trace = _PayPalTraceSink(
        account_id=account_id,
        phase="verify",
        attempt=(db.get_account(account_id) or {}).get("paypal_payment_attempt_count"),
        batch_size=1,
    )
    for index, delay in enumerate(delays):
        if delay > 0:
            trace.emit(
                status="waiting",
                stage="plan_verify",
                message=f"等待 {delay:g}s 后执行第 {index + 1}/{len(delays)} 次套餐核验",
            )
            time.sleep(delay)
        token, result = _check_plan_current_token(
            account_id=account_id, email=email, access_token=token,
            proxy=lease.proxy, timeout=settings["request_timeout"],
        )
        last_result = result
        plan_value = str(
            result.get("current_plan_type") or result.get("plan_type") or "unknown"
        ).lower()
        trace.emit(
            status="response" if result.get("ok") else "failed",
            stage="plan_verify",
            message=(
                f"套餐核验第 {index + 1}/{len(delays)} 次完成：plan={plan_value}"
                if result.get("ok")
                else f"套餐核验第 {index + 1}/{len(delays)} 次失败"
            ),
            http_status=result.get("http_status"),
        )
        if result.get("ok"):
            plan = str(result.get("current_plan_type") or result.get("plan_type") or "").lower()
            if plan == "plus":
                stored = {
                    "status": "confirmed", "message": "套餐接口已确认 plan=plus",
                    "verified_at": _now(), "confirmed_at": _now(),
                    "payment_context": None, "otp_context": None,
                }
                db.update_account_paypal(account_id, stage="payment", result=stored)
                try:
                    from core.registration_service import continue_registration_codex_after_plus

                    continuation = continue_registration_codex_after_plus(account_id)
                    if continuation.get("accepted"):
                        logger.info(
                            "[PayPal] plan=plus 已确认，Codex 自动接码已入队: account=%s job=%s",
                            account_id, (continuation.get("job") or {}).get("id"),
                        )
                except Exception as exc:
                    # Plus 已确认是支付链路的最终事实；Codex 入队失败不能回滚它。
                    logger.exception(
                        "[PayPal] plan=plus 已确认，但 Codex 自动接码续跑异常: account=%s error=%s",
                        account_id, type(exc).__name__,
                    )
                return stored
            # A valid free response is eventual consistency, not a token problem.
            if plan == "free" and index < len(delays) - 1:
                continue
            if plan == "free":
                if authorization_confirmed:
                    stored = {
                        "status": "pending",
                        "message": "PayPal 已授权，但套餐仍为 free，等待后续复查",
                        "verified_at": _now(),
                    }
                else:
                    stored = {
                        "status": "verification_blocked",
                        "message": "未取得 PayPal Billing Agreement，套餐仍为 free",
                        "error": "PayPal Billing Agreement 未授权",
                        "stage": "authorization_missing",
                        "verified_at": _now(),
                    }
                db.update_account_paypal(account_id, stage="payment", result=stored)
                return stored
            stored = {
                "status": "verification_blocked",
                "message": f"套餐返回 {plan or 'unknown'}，尚不能确认 Plus",
                "error": f"套餐返回 {plan or 'unknown'}",
                "stage": "plan_unexpected", "verified_at": _now(),
            }
            db.update_account_paypal(account_id, stage="payment", result=stored)
            return stored

        # 403/429/timeout/guest/malformed are retryable verification evidence,
        # never a reason to refresh a token or repeat PayPal authorization.
        if index < len(delays) - 1 and bool(result.get("retryable", True)):
            continue
        stored = {
            "status": "verification_blocked",
            "message": (
                "PayPal 已授权，套餐核验暂时失败，可单独重试核验"
                if authorization_confirmed
                else "未取得 PayPal Billing Agreement，套餐核验暂时失败"
            ),
            "error": _safe_text(result.get("error") or "套餐核验失败"),
            "stage": "plan_verify", "verified_at": _now(),
        }
        db.update_account_paypal(account_id, stage="payment", result=stored)
        return stored

    stored = {
        "status": "verification_blocked", "message": "套餐核验未返回结果",
        "error": _safe_text(last_result.get("error") or "套餐核验未返回结果"),
        "stage": "plan_verify",
    }
    db.update_account_paypal(account_id, stage="payment", result=stored)
    return stored


def _handle_payment_result(
    *, account_id: int, email: str, access_token: str, result: dict,
    lease: paypal_proxy_pool.ProxyLease, settings: dict,
) -> dict:
    status = str(result.get("status") or "").strip().lower()
    if status == "waiting_otp":
        otp_context = dict(result.get("otp_context") or result.get("context") or {})
        otp_context["_paypal_service"] = _service_context(settings, lease)
        payment_context = dict(result.get("payment_context") or {})
        payment_context["_paypal_service"] = _service_context(settings, lease)
        stored = {
            "status": "waiting_otp", "message": "等待 PayPal 短信验证码",
            "otp_context": otp_context, "payment_context": payment_context,
            "proxy_pool_ref": lease.entry_id, "proxy_pool_version": lease.pool_version,
        }
        db.update_account_paypal(account_id, stage="payment", result=stored)
        paypal_proxy_pool.suspend(lease)
        return stored
    if status in {"authorized", "success"}:
        payment_context = result.get("payment_context") or result.get("context")
        if isinstance(payment_context, dict):
            payment_context = dict(payment_context)
            payment_context["_paypal_service"] = _service_context(settings, lease)
        stored = {
            "status": "authorized", "message": "PayPal Agreement 已授权，尚未确认 Plus",
            "reference": result.get("reference"),
            "agreement_id": result.get("agreement_id"),
            "payment_context": payment_context,
            "otp_context": None,
            "proxy_pool_ref": lease.entry_id, "proxy_pool_version": lease.pool_version,
        }
        db.update_account_paypal(account_id, stage="payment", result=stored)
        verified = _verify_plus(
            account_id=account_id, email=email, access_token=access_token,
            lease=lease, settings=settings,
        )
        paypal_proxy_pool.release(
            lease, success=verified.get("status") in {"confirmed", "pending"},
            failure_stage="plan_verify" if verified.get("status") == "verification_blocked" else "",
            country=settings["payment_country"],
        )
        return verified
    if status in {"pending", "pending_verification", "verification_blocked"}:
        info = _payment_result_error_info(result)
        payment_context = result.get("payment_context") or result.get("context")
        if isinstance(payment_context, dict):
            payment_context = dict(payment_context)
            payment_context["_paypal_service"] = _service_context(settings, lease)
        otp_context = result.get("otp_context")
        if isinstance(otp_context, dict):
            otp_context = dict(otp_context)
            otp_context["_paypal_service"] = _service_context(settings, lease)
        stored = {
            "status": "verification_blocked",
            "message": str(result.get("message") or (
                "PayPal 结果不确定，禁止自动重付"
                if info["ambiguous"]
                else "PayPal 会员已创建，但 Billing Agreement 未授权；禁止自动重放注册"
            ))[:500],
            "error": info["error"],
            "stage": info["stage"],
            "payment_context": payment_context,
            "otp_context": otp_context,
            "proxy_pool_ref": lease.entry_id, "proxy_pool_version": lease.pool_version,
        }
        db.update_account_paypal(account_id, stage="payment", result=stored)
        paypal_proxy_pool.suspend(lease)
        return stored
    if status == "failed":
        info = _payment_result_error_info(result)
        raise PayPalWorkflowError(
            info["error"], stage=info["stage"], code=info["code"],
            retryable=info["retryable"], ambiguous=not info["replay_safe"],
            replay_safe=info["replay_safe"], http_status=info["http_status"],
        )
    raise PayPalWorkflowError(
        result.get("error") or "PayPal 协议未返回有效状态",
        stage=str(result.get("stage") or "payment_result"),
        code="payment_result", retryable=False, ambiguous=True,
    )


def _run_remote_existing_job_with_number(
    *,
    account_id: int,
    email: str,
    access_token: str,
    settings: dict,
    payment_phone: str,
    activation: dict | None,
    remote_context: dict,
) -> dict:
    """Send a replacement phone to the same remote job after local SMS timeout."""
    remote_context = dict(remote_context or {})
    remote_context.pop("_phone_rotation_pending", None)
    lease = None
    trace: _PayPalTraceSink | None = None
    meta = remote_context.get("_paypal_service")
    meta = meta if isinstance(meta, dict) else {}
    try:
        lease = paypal_proxy_pool.resume(
            "payment",
            str(meta.get("proxy_entry_id") or ""),
            expected_pool_version=str(meta.get("proxy_pool_version") or ""),
        )
        if not db.mark_account_paypal_running(
            account_id,
            stage="payment",
            message="正在向原远程 PayPal 任务提交新号码",
            proxy_pool_ref=lease.entry_id,
            proxy_pool_version=lease.pool_version,
        ):
            raise PayPalWorkflowError(
                "账号状态已变化，不能向远程任务提交新号码",
                stage="remote_phone",
                code="state",
                ambiguous=True,
            )
        trace = _PayPalTraceSink(
            account_id=account_id,
            phase="payment",
            attempt=(db.get_account(account_id) or {}).get("paypal_payment_attempt_count"),
        )
        trace.emit(
            status="step",
            stage="remote_phone",
            message="复用原远程任务并提交新号码，不重复创建 PayPal Agreement 任务",
        )
        from core.paypal_remote import resume_remote_paypal_payment

        try:
            result = resume_remote_paypal_payment(
                context=remote_context,
                value=payment_phone,
                timeout=settings["request_timeout"],
                poll_interval=settings["remote_poll_interval"],
                job_timeout=settings["remote_job_timeout"],
                trace=trace,
                checkpoint=_remote_checkpoint_callback(
                    account_id=account_id, settings=settings, lease=lease,
                ),
            )
        finally:
            trace.flush()
        handled = _handle_payment_result(
            account_id=account_id,
            email=email,
            access_token=access_token,
            result=dict(result or {}),
            lease=lease,
            settings=settings,
        )
        if activation is not None and handled.get("status") == "waiting_otp":
            db.update_account_paypal_sms(
                account_id, _sms_db_result(activation, status="waiting"),
            )
            if not db.claim_account_paypal_sms(account_id):
                return handled
            return _continue_auto_sms_core(
                account_id=account_id,
                settings=settings,
                activation=activation,
                rotate_on_timeout=True,
            )
        if activation is not None:
            sms_status = (
                "consumed" if handled.get("status") in {"authorized", "confirmed", "pending"}
                else "ambiguous"
            )
            db.update_account_paypal_sms(
                account_id,
                _sms_db_result(
                    activation,
                    status=sms_status,
                    error=handled.get("error") if sms_status == "ambiguous" else None,
                ),
            )
        return handled
    except Exception as exc:
        info = _error_info(
            exc,
            secrets=(access_token, payment_phone, lease.proxy if lease else ""),
        )
        if trace is not None:
            trace.emit(
                status="failed",
                stage=info["stage"],
                message=f"远程任务换号失败：{info['error']}",
            )
            trace.flush()
        if lease is not None:
            paypal_proxy_pool.suspend(lease)
        if activation is not None:
            db.update_account_paypal_sms(
                account_id,
                _sms_db_result(activation, status="ambiguous", error=info["error"]),
            )
        stored = {
            "status": "verification_blocked",
            "message": "远程 PayPal 任务换号结果不确定，已保留原任务",
            "error": info["error"],
            "stage": info["stage"],
            "code": info["code"],
            "replay_safe": False,
            "payment_context": remote_context,
            "otp_context": remote_context,
        }
        db.update_account_paypal(account_id, stage="payment", result=stored)
        return stored


def _run_payment_with_number(
    *, account_id: int, email: str, access_token: str, settings: dict,
) -> dict:
    context = db.get_account_paypal_context(account_id) or {}
    try:
        ba_url, ba_token = _validate_ba(
            context.get("paypal_ba_url"), context.get("paypal_ba_token"),
        )
    except Exception as exc:
        info = _error_info(exc, secrets=(access_token,))
        stored = {
            "status": "failed", "message": "保存的 PP 链无效，请重新提取",
            "error": info["error"], "stage": info["stage"],
        }
        db.update_account_paypal(account_id, stage="payment", result=stored)
        return stored
    payment_phone = str(settings.get("phone") or "").strip()
    activation: dict[str, Any] | None = None
    auto_sms = not payment_phone and str((settings.get("sms") or {}).get("mode") or "manual") == "auto"
    if auto_sms:
        from core import paypal_sms

        db.update_account_paypal_sms(account_id, {"status": "acquiring", "context": None})
        try:
            activation = dict(paypal_sms.acquire_number(settings["sms"]) or {})
            payment_phone = str(activation.get("phone") or "").strip()
            if not payment_phone:
                raise paypal_sms.PayPalSmsError(
                    "自动接码返回空手机号", stage="sms_acquire", code="phone_missing",
                )
            db.update_account_paypal_sms(
                account_id, _sms_db_result(activation, status="acquired"),
            )
            logger.info(
                "[PayPal][SMS] 已取得号码: account=%s channel=%s provider=%s phone=%s cost=%s",
                account_id, activation.get("channel"), activation.get("provider"),
                activation.get("phone_masked"), activation.get("cost"),
            )
        except Exception as exc:
            info = _error_info(exc)
            db.update_account_paypal_sms(account_id, {
                "status": "failed", "error": info["error"], "context": None,
            })
            stored = {
                "status": "verification_blocked",
                "message": "已保存 PP 链，但自动取号失败，可直接重试支付",
                "error": info["error"],
                "stage": "sms_acquire",
            }
            db.update_account_paypal(account_id, stage="payment", result=stored)
            return stored
    if not payment_phone:
        stored = {
            "status": "verification_blocked",
            "message": "已保存 PP 链，但未配置 PayPal 手机号或自动接码",
            "error": "未配置 PayPal 手机号",
            "stage": "phone_required",
        }
        db.update_account_paypal(account_id, stage="payment", result=stored)
        return stored

    remote_context = next((
        value for value in (
            context.get("paypal_otp_context"), context.get("paypal_payment_context"),
        )
        if _is_remote_context(value)
    ), None)
    if (
        activation is not None
        and isinstance(remote_context, dict)
        and bool(remote_context.get("_phone_rotation_pending"))
    ):
        return _run_remote_existing_job_with_number(
            account_id=account_id,
            email=email,
            access_token=access_token,
            settings=settings,
            payment_phone=payment_phone,
            activation=activation,
            remote_context=remote_context,
        )

    attempted: set[str] = set()
    for attempt in range(1, int(settings["payment_attempts"]) + 1):
        lease = None
        trace: _PayPalTraceSink | None = None
        payment_invoked = False
        try:
            lease = paypal_proxy_pool.acquire("payment", exclude_entry_ids=attempted)
            attempted.add(lease.entry_id)
            _assert_lease_snapshot(lease, settings["payment_pool"])
            if not db.mark_account_paypal_running(
                account_id, stage="payment",
                message=f"正在初始化 PayPal 支付（第 {attempt} 次代理尝试）",
                proxy_pool_ref=lease.entry_id,
                proxy_pool_version=lease.pool_version,
            ):
                raise PayPalWorkflowError("账号已删除或支付状态被重置", stage="payment", code="state")
            trace = _PayPalTraceSink(
                account_id=account_id, phase="payment", attempt=attempt,
            )
            trace.emit(
                status="step", stage="proxy",
                message=f"已取得授权代理租约：entry={lease.entry_id[:8]}",
            )
            payment_invoked = True
            try:
                if str(settings.get("payment_executor") or "local") == "remote":
                    from core.paypal_remote import start_remote_paypal_payment

                    result = start_remote_paypal_payment(
                        api_base=settings["remote_api_base"],
                        ba_url=ba_url,
                        phone=payment_phone,
                        country=settings["payment_country"],
                        buyer_mode=settings["buyer_mode"],
                        proxy=lease.proxy,
                        timeout=settings["request_timeout"],
                        poll_interval=settings["remote_poll_interval"],
                        job_timeout=settings["remote_job_timeout"],
                        trace=trace,
                        checkpoint=_remote_checkpoint_callback(
                            account_id=account_id, settings=settings, lease=lease,
                        ),
                    )
                else:
                    from core.paypal_payment import start_paypal_payment

                    result = start_paypal_payment(
                        ba_url=ba_url,
                        phone=payment_phone, country=settings["payment_country"],
                        buyer_mode=settings["buyer_mode"], proxy=lease.proxy,
                        timeout=settings["request_timeout"], trace=trace,
                    )
            finally:
                trace.flush()
            handled = _handle_payment_result(
                account_id=account_id, email=email, access_token=access_token,
                result=dict(result or {}), lease=lease, settings=settings,
            )
            if activation is not None and handled.get("status") == "waiting_otp":
                db.update_account_paypal_sms(
                    account_id, _sms_db_result(activation, status="waiting"),
                )
                if not db.claim_account_paypal_sms(account_id):
                    return handled
                return _continue_auto_sms_core(
                    account_id=account_id, settings=settings, activation=activation,
                    rotate_on_timeout=True,
                )
            if activation is not None:
                sms_status = (
                    "consumed" if handled.get("status") in {"authorized", "confirmed", "pending"}
                    else "ambiguous"
                )
                db.update_account_paypal_sms(
                    account_id,
                    _sms_db_result(
                        activation, status=sms_status,
                        error=handled.get("error") if sms_status == "ambiguous" else None,
                    ),
                )
            return handled
        except Exception as exc:
            info = _error_info(
                exc,
                secrets=(access_token, ba_url, ba_token, payment_phone, lease.proxy if lease else ""),
            )
            if trace is not None:
                trace.emit(
                    status="failed", stage=info["stage"],
                    message=f"授权尝试失败：{info['error']}",
                )
                trace.flush()
            new_number_failure = _payment_can_restart_with_new_number(info)
            safe_before_payment = (
                not payment_invoked or _payment_failure_is_pre_mutation(info)
                or new_number_failure
            )
            if lease is not None:
                if info["ambiguous"] or not safe_before_payment:
                    paypal_proxy_pool.suspend(lease)
                else:
                    paypal_proxy_pool.release(
                        lease, success=False, failure_stage=info["stage"],
                        country=settings["payment_country"],
                    )
            if _payment_retry_from_start(info) and attempt < int(settings["payment_attempts"]):
                if settings["retry_interval"]:
                    time.sleep(settings["retry_interval"])
                continue
            ambiguous = info["ambiguous"] or not safe_before_payment
            if activation is not None:
                if new_number_failure or not ambiguous:
                    _reject_sms_before_payment(
                        account_id=account_id, settings=settings,
                        activation=activation, reason=info["error"],
                    )
                else:
                    db.update_account_paypal_sms(
                        account_id,
                        _sms_db_result(activation, status="ambiguous", error=info["error"]),
                    )
            stored = {
                "status": "verification_blocked" if ambiguous else "failed",
                "message": (
                    "支付结果不确定，禁止自动重付"
                    if ambiguous
                    else (
                        "PayPal 当前号码达到短信发送限制，准备换号"
                        if str(info.get("code") or "").upper() == "SMS_LIMIT_EXCEEDED"
                        else "PayPal 支付失败"
                    )
                ),
                "error": info["error"], "stage": info["stage"],
                "code": info["code"],
                "replay_safe": bool(info["replay_safe"]),
            }
            if lease is not None:
                stored.update({
                    "proxy_pool_ref": lease.entry_id,
                    "proxy_pool_version": lease.pool_version,
                })
            db.update_account_paypal(account_id, stage="payment", result=stored)
            return stored
    return {"status": "failed", "error": "PayPal 支付尝试已耗尽"}


def _payment_result_allows_new_number(result: dict) -> bool:
    """Retry only an explicit phone/session rejection."""
    error = (result or {}).get("error")
    details = error if isinstance(error, dict) else {}
    return (
        str((result or {}).get("status") or "").strip().lower() == "failed"
        and _payment_can_restart_with_new_number({
            "stage": details.get("stage") or (result or {}).get("stage"),
            "code": details.get("code") or (result or {}).get("code")
                    or (result or {}).get("error_code"),
            "replay_safe": (
                (result or {}).get("replay_safe")
                if "replay_safe" in (result or {})
                else details.get("replay_safe")
            ),
            "ambiguous": bool(
                (result or {}).get("ambiguous", details.get("ambiguous", False))
            ),
        })
    )


def _run_payment_start(
    *, account_id: int, email: str, access_token: str, settings: dict,
) -> dict:
    """Run payment and rotate phone activations after safe number failures."""
    payment_phone = str(settings.get("phone") or "").strip()
    sms_settings = settings.get("sms") if isinstance(settings.get("sms"), dict) else {}
    auto_sms = not payment_phone and str(sms_settings.get("mode") or "manual") == "auto"
    number_attempts = int(sms_settings.get("max_retries") or 1) if auto_sms else 1
    number_attempts = max(1, min(20, number_attempts))

    last_result: dict = {}
    for number_attempt in range(1, number_attempts + 1):
        if number_attempt > 1:
            previous_code = str(
                last_result.get("code")
                or last_result.get("error_code")
                or (
                    (last_result.get("error") or {}).get("code")
                    if isinstance(last_result.get("error"), dict) else ""
                )
            ).strip().upper()
            if previous_code == "SMS_LIMIT_EXCEEDED":
                reason = "PayPal 返回 SMS_LIMIT_EXCEEDED，当前号码/会话达到短信发送限制"
            elif previous_code == "TIMEOUT":
                reason = "当前号码等待短信验证码超时"
            elif previous_code == "OAS_ERROR":
                reason = "PayPal 返回 OAS_ERROR，同号码资料重试已耗尽"
            else:
                reason = "上一个号码被 PayPal 明确拒绝"
            retry_state = db.get_account_paypal_context(account_id) or {}
            retry_remote_context = next((
                value for value in (
                    retry_state.get("paypal_otp_context"),
                    retry_state.get("paypal_payment_context"),
                )
                if _is_remote_context(value) and bool(value.get("_phone_rotation_pending"))
            ), None)
            context_reset = (
                {}
                if isinstance(retry_remote_context, dict)
                else {"payment_context": None, "otp_context": None}
            )
            db.update_account_paypal(
                account_id,
                stage="payment",
                result={
                    "status": "running",
                    "message": (
                        f"{reason}；复用现有 PP 链，仅重新执行支付授权，正在申请新号码 "
                        f"（{number_attempt}/{number_attempts}）"
                    ),
                    **context_reset,
                },
            )
            if settings.get("retry_interval"):
                time.sleep(float(settings["retry_interval"]))

        last_result = _run_payment_with_number(
            account_id=account_id,
            email=email,
            access_token=access_token,
            settings=settings,
        )
        if not auto_sms or not _payment_result_allows_new_number(last_result):
            return last_result
        if number_attempt >= number_attempts:
            exhausted = {
                **last_result,
                "message": (
                    f"已尝试 {number_attempts} 个号码，均被 PayPal 拒绝、达到短信限制或接码超时；"
                    "已保留 PP 链，可再次执行支付"
                ),
            }
            db.update_account_paypal(account_id, stage="payment", result=exhausted)
            return exhausted
        logger.warning(
            "[PayPal][SMS] 当前号码不可继续，自动换号: account=%s attempt=%s/%s code=%s",
            account_id,
            number_attempt,
            number_attempts,
            str(last_result.get("code") or ""),
        )

    return last_result


def _settings_from_otp_context(context: dict) -> tuple[dict, dict]:
    otp_context = dict(context.get("paypal_otp_context") or {})
    payment_context = dict(context.get("paypal_payment_context") or {})
    meta = otp_context.get("_paypal_service") or payment_context.get("_paypal_service") or {}
    if not isinstance(meta, dict):
        meta = {}
    settings = _task_settings(None, {
        "country": meta.get("payment_country"),
        "buyer_mode": meta.get("buyer_mode"),
        "payment_executor": meta.get("payment_executor"),
        "remote_api_base": meta.get("remote_api_base"),
        "remote_poll_interval": meta.get("remote_poll_interval"),
        "remote_job_timeout": meta.get("remote_job_timeout"),
        "verify_delays": meta.get("verify_delays"),
        "sms": meta.get("sms") if isinstance(meta.get("sms"), dict) else None,
    })
    if meta.get("request_timeout") is not None:
        settings["request_timeout"] = max(3.0, min(120.0, float(meta["request_timeout"])))
    return settings, otp_context


def _run_otp_core(*, account_id: int, otp: str) -> dict:
    lease = None
    trace: _PayPalTraceSink | None = None
    context: dict = {}
    email = ""
    access_token = ""
    otp_context: dict = {}
    try:
        context = db.get_account_paypal_context(account_id) or {}
        email = str(context.get("email") or "")
        access_token = str(context.get("access_token") or "")
        settings, otp_context = _settings_from_otp_context(context)
        meta = otp_context.get("_paypal_service") if isinstance(otp_context.get("_paypal_service"), dict) else {}
        try:
            lease = paypal_proxy_pool.resume(
                "payment", str(meta.get("proxy_entry_id") or context.get("paypal_payment_proxy_pool_ref") or ""),
                expected_pool_version=str(meta.get("proxy_pool_version") or context.get("paypal_payment_proxy_pool_version") or ""),
            )
        except paypal_proxy_pool.PayPalProxyPoolError as exc:
            raise PayPalWorkflowError(
                f"PayPal OTP 必须复用原代理，无法继续：{exc}",
                stage="proxy", code="otp_proxy_unavailable",
                retryable=False, ambiguous=True,
            ) from exc
        trace = _PayPalTraceSink(
            account_id=account_id,
            phase="payment",
            attempt=context.get("paypal_payment_attempt_count"),
        )
        trace.emit(
            status="step", stage="otp_resume",
            message=f"已恢复 OTP 原代理租约：entry={lease.entry_id[:8]}",
        )
        try:
            if (
                str(settings.get("payment_executor") or "local") == "remote"
                or _is_remote_context(otp_context)
            ):
                from core.paypal_remote import resume_remote_paypal_payment

                result = resume_remote_paypal_payment(
                    context=otp_context,
                    value=otp,
                    timeout=settings["request_timeout"],
                    poll_interval=settings["remote_poll_interval"],
                    job_timeout=settings["remote_job_timeout"],
                    trace=trace,
                    checkpoint=_remote_checkpoint_callback(
                        account_id=account_id, settings=settings, lease=lease,
                    ),
                )
            else:
                from core.paypal_payment import submit_paypal_otp

                result = submit_paypal_otp(
                    context=otp_context, otp=otp, proxy=lease.proxy,
                    timeout=settings["request_timeout"], trace=trace,
                )
        finally:
            trace.flush()
        handled = _handle_payment_result(
            account_id=account_id, email=email, access_token=access_token,
            result=dict(result or {}), lease=lease, settings=settings,
        )
        activation = context.get("paypal_sms_context")
        if isinstance(activation, dict) and activation:
            handled_status = str(handled.get("status") or "").strip().lower()
            sms_status = "submitted" if handled_status == "waiting_otp" else "consumed"
            db.update_account_paypal_sms(
                account_id,
                _sms_db_result(activation, status=sms_status),
            )
        return handled
    except Exception as exc:
        info = _error_info(exc, secrets=(otp, access_token, lease.proxy if lease else ""))
        if trace is not None:
            trace.emit(
                status="failed", stage=info["stage"],
                message=f"OTP/授权继续流程失败：{info['error']}",
            )
            trace.flush()
        new_number_failure = _payment_can_restart_with_new_number(info)
        if lease is not None:
            if new_number_failure:
                paypal_proxy_pool.release(
                    lease,
                    success=False,
                    failure_stage=info["stage"],
                    country=settings["payment_country"],
                )
            else:
                paypal_proxy_pool.suspend(lease)
        # Invalid/expired OTP remains resumable if the protocol returned a fresh
        # context.  A structured signup rejection happened before agreement
        # authorization and can start a new payment with a new number.  Lost or
        # malformed mutation responses remain ambiguous and must not restart.
        if str(info["code"] or "").lower() in {"invalid_otp", "otp_expired"}:
            stored = {
                "status": "waiting_otp", "message": "PayPal 验证码无效或已过期，请重新获取后提交",
                "error": info["error"], "stage": info["stage"],
                "otp_context": getattr(exc, "context", otp_context),
            }
        elif new_number_failure:
            code = str(info.get("code") or "").upper()
            stored = {
                "status": "failed",
                "message": (
                    (
                        "PayPal 返回 SMS_LIMIT_EXCEEDED：当前号码/会话达到短信发送限制；"
                        if code == "SMS_LIMIT_EXCEEDED"
                        else "PayPal 返回 OAS_ERROR：同号码资料重试已耗尽；"
                    )
                    + "将复用现有 PP 链并换号重新授权"
                ),
                "error": info["error"],
                "stage": info["stage"],
                "code": info["code"],
                "replay_safe": True,
                "payment_context": None,
                "otp_context": None,
            }
        else:
            stored = {
                "status": "verification_blocked",
                "message": "验证码提交后结果不确定，禁止自动重付",
                "error": info["error"], "stage": info["stage"],
                "code": info["code"],
                "replay_safe": False,
            }
        db.update_account_paypal(account_id, stage="payment", result=stored)
        activation = context.get("paypal_sms_context")
        if isinstance(activation, dict) and activation:
            db.update_account_paypal_sms(
                account_id, _sms_db_result(activation, status="consumed"),
            )
        return stored


def _run_otp(*, account_id: int, otp: str) -> dict:
    try:
        return _run_otp_core(account_id=account_id, otp=otp)
    finally:
        _QUEUE_SLOTS.release()


def _continue_auto_sms_core(
    *, account_id: int, settings: dict, activation: dict,
    rotate_on_timeout: bool = False,
) -> dict:
    """Poll one existing activation and resume the same PayPal proxy context."""
    from core import paypal_sms

    try:
        code = paypal_sms.wait_for_sms_code(settings["sms"], activation)
    except Exception as exc:
        info = _error_info(exc)
        status = "timeout" if str(info.get("code") or "").lower() == "timeout" else "failed"
        if status == "timeout" and rotate_on_timeout:
            _reject_sms_before_payment(
                account_id=account_id,
                settings=settings,
                activation=activation,
                reason=info["error"],
            )
            stored = {
                "status": "failed",
                "message": "等待短信验证码超时，准备取消当前号码并换号",
                "error": info["error"],
                "stage": "sms_poll",
                "code": "timeout",
                "replay_safe": True,
                "ambiguous": False,
            }
            current = db.get_account_paypal_context(account_id) or {}
            remote_context = next((
                value for value in (
                    current.get("paypal_otp_context"),
                    current.get("paypal_payment_context"),
                )
                if _is_remote_context(value)
            ), None)
            if isinstance(remote_context, dict):
                remote_context = dict(remote_context)
                remote_context["_phone_rotation_pending"] = True
                stored["payment_context"] = remote_context
                stored["otp_context"] = remote_context
            else:
                stored["payment_context"] = None
                stored["otp_context"] = None
            db.update_account_paypal(account_id, stage="payment", result=stored)
            return stored
        db.update_account_paypal_sms(
            account_id, _sms_db_result(activation, status=status, error=info["error"]),
        )
        stored = {
            "status": "waiting_otp",
            "message": "PayPal 仍在等待验证码；自动接码暂未取得短信，可继续自动接码或手动提交",
        }
        db.update_account_paypal(account_id, stage="payment", result=stored)
        return {**stored, "sms_status": status, "sms_error": info["error"]}

    db.update_account_paypal_sms(
        account_id, _sms_db_result(activation, status="code_received"),
    )
    if not db.claim_account_paypal_otp(account_id):
        stored = {
            "status": "waiting_otp",
            "message": "已取得短信，但 PayPal OTP 状态已变化；未自动重复提交",
        }
        db.update_account_paypal_sms(
            account_id,
            _sms_db_result(activation, status="ambiguous", error=stored["message"]),
        )
        return stored
    return _run_otp_core(account_id=account_id, otp=code)


def _run_sms_continue(*, account_id: int) -> dict:
    try:
        context = db.get_account_paypal_context(account_id) or {}
        settings, _ = _settings_from_otp_context(context)
        activation = context.get("paypal_sms_context")
        if not isinstance(activation, dict) or not activation:
            stored = {
                "status": "waiting_otp",
                "message": "缺少可继续的自动接码 activation，请手动提交验证码",
            }
            db.update_account_paypal(account_id, stage="payment", result=stored)
            return stored
        return _continue_auto_sms_core(
            account_id=account_id, settings=settings, activation=activation,
        )
    finally:
        _QUEUE_SLOTS.release()


def _run_remote_resume_core(*, account_id: int) -> dict:
    """Resume a persisted remote job without creating or replaying payment."""
    context = db.get_account_paypal_context(account_id) or {}
    email = str(context.get("email") or "")
    access_token = str(context.get("access_token") or "")
    remote_context = next((
        value for value in (
            context.get("paypal_otp_context"), context.get("paypal_payment_context"),
        )
        if _is_remote_context(value)
    ), None)
    if not isinstance(remote_context, dict):
        return {"status": "failed", "error": "缺少可恢复的远程 PayPal 上下文"}
    settings, _ = _settings_from_otp_context(context)
    meta = remote_context.get("_paypal_service")
    meta = meta if isinstance(meta, dict) else {}
    lease = None
    trace: _PayPalTraceSink | None = None
    try:
        lease = paypal_proxy_pool.resume(
            "payment",
            str(meta.get("proxy_entry_id") or context.get("paypal_payment_proxy_pool_ref") or ""),
            expected_pool_version=str(
                meta.get("proxy_pool_version")
                or context.get("paypal_payment_proxy_pool_version")
                or ""
            ),
        )
        current_status = str(context.get("paypal_payment_status") or "").strip().lower()
        if current_status in {"queued", "running"}:
            if not db.mark_account_paypal_running(
                account_id,
                stage="payment",
                message="正在续查服务重启前的远程 PayPal 任务",
                proxy_pool_ref=lease.entry_id,
                proxy_pool_version=lease.pool_version,
            ):
                raise PayPalWorkflowError(
                    "账号状态已变化，远程任务恢复已停止",
                    stage="remote_resume",
                    code="state",
                    ambiguous=True,
                )
        elif current_status == "verifying":
            db.update_account_paypal(
                account_id,
                stage="payment",
                result={
                    "status": "running",
                    "message": "正在续查此前未完成的远程 PayPal 任务",
                },
            )
        trace = _PayPalTraceSink(
            account_id=account_id,
            phase="payment",
            attempt=context.get("paypal_payment_attempt_count"),
        )
        trace.emit(
            status="step",
            stage="remote_resume",
            message="使用原设备 Cookie 续查远程 PayPal 任务",
        )
        from core.paypal_remote import resume_remote_paypal_payment

        try:
            result = resume_remote_paypal_payment(
                context=remote_context,
                timeout=settings["request_timeout"],
                poll_interval=settings["remote_poll_interval"],
                job_timeout=settings["remote_job_timeout"],
                trace=trace,
                checkpoint=_remote_checkpoint_callback(
                    account_id=account_id, settings=settings, lease=lease,
                ),
            )
        finally:
            trace.flush()
        handled = _handle_payment_result(
            account_id=account_id,
            email=email,
            access_token=access_token,
            result=dict(result or {}),
            lease=lease,
            settings=settings,
        )
        activation = context.get("paypal_sms_context")
        if (
            isinstance(activation, dict)
            and activation
            and handled.get("status") == "waiting_otp"
        ):
            db.update_account_paypal_sms(
                account_id, _sms_db_result(activation, status="waiting"),
            )
            sms_mode = str((settings.get("sms") or {}).get("mode") or "manual")
            if sms_mode == "auto" and db.claim_account_paypal_sms(account_id):
                return _continue_auto_sms_core(
                    account_id=account_id,
                    settings=settings,
                    activation=activation,
                    rotate_on_timeout=True,
                )
        elif isinstance(activation, dict) and activation and handled.get("status") in {
            "authorized", "confirmed", "pending",
        }:
            db.update_account_paypal_sms(
                account_id, _sms_db_result(activation, status="consumed"),
            )
        return handled
    except Exception as exc:
        info = _error_info(
            exc,
            secrets=(access_token, lease.proxy if lease else ""),
        )
        if trace is not None:
            trace.emit(
                status="failed",
                stage=info["stage"],
                message=f"远程任务恢复失败：{info['error']}",
            )
            trace.flush()
        if lease is not None:
            paypal_proxy_pool.suspend(lease)
        stored = {
            "status": "verification_blocked",
            "message": "远程 PayPal 任务续查失败，已保留任务上下文",
            "error": info["error"],
            "stage": info["stage"],
            "code": info["code"],
            "replay_safe": False,
            "payment_context": remote_context,
            "otp_context": remote_context if context.get("paypal_otp_context") else None,
        }
        db.update_account_paypal(account_id, stage="payment", result=stored)
        return stored


def _run_remote_resume(*, account_id: int) -> dict:
    try:
        return _run_remote_resume_core(account_id=account_id)
    finally:
        _QUEUE_SLOTS.release()


def resume_remote_paypal_tasks(
    account_ids: list[int] | tuple[int, ...] | None = None,
) -> dict[str, int]:
    """Queue durable remote jobs found after a local service restart."""
    ids = list(account_ids) if account_ids is not None else db.list_resumable_remote_paypal_account_ids()
    queued = 0
    skipped = 0
    for raw_id in ids:
        try:
            account_id = int(raw_id)
        except (TypeError, ValueError):
            skipped += 1
            continue
        if not _QUEUE_SLOTS.acquire(blocking=False):
            skipped += 1
            continue
        try:
            _submit_runtime(_run_remote_resume, account_id=account_id)
        except Exception:
            _QUEUE_SLOTS.release()
            skipped += 1
            continue
        queued += 1
    return {"queued": queued, "skipped": skipped}


def _run_verification(*, account_id: int, settings: dict) -> dict:
    lease = None
    outcome: dict = {}
    try:
        context = db.get_account_paypal_context(account_id) or {}
        authorization_confirmed = bool(str(context.get("paypal_agreement_id") or "").strip())
        meta = {}
        payment_context = context.get("paypal_payment_context")
        if isinstance(payment_context, dict):
            meta = payment_context.get("_paypal_service") or {}
        entry_id = str(
            (meta.get("proxy_entry_id") if isinstance(meta, dict) else "")
            or context.get("paypal_payment_proxy_pool_ref") or ""
        )
        version = str(
            (meta.get("proxy_pool_version") if isinstance(meta, dict) else "")
            or context.get("paypal_payment_proxy_pool_version") or ""
        )
        start_message = ""
        try:
            lease = paypal_proxy_pool.resume(
                "payment", entry_id, expected_pool_version=version,
            )
        except paypal_proxy_pool.PayPalProxyPoolError as exc:
            logger.warning(
                "[PayPal] 原代理引用不可恢复，只读 Plus 核验改用当前代理池: "
                "account=%s reason=%s",
                account_id, _safe_text(exc),
            )
            lease = paypal_proxy_pool.acquire("payment")
            start_message = "原代理引用不可用，Plus 只读核验改用新代理"
        if not authorization_confirmed:
            start_message = (
                "尚未取得 PayPal Billing Agreement，正在只读核验套餐"
                + ("；原代理引用不可用，Plus 只读核验改用新代理" if start_message else "")
            )
        outcome = _verify_plus(
            account_id=account_id, email=str(context.get("email") or ""),
            access_token=str(context.get("access_token") or ""),
            lease=lease, settings=settings, start_message=start_message,
            authorization_confirmed=authorization_confirmed,
        )
        return outcome
    except Exception as exc:
        info = _error_info(exc)
        stored = {
            "status": "verification_blocked", "message": "Plus 核验暂时失败，可稍后重试",
            "error": info["error"], "stage": info["stage"],
        }
        db.update_account_paypal(account_id, stage="payment", result=stored)
        outcome = stored
        return stored
    finally:
        if lease is not None:
            paypal_proxy_pool.release(
                lease,
                success=outcome.get("status") in {"confirmed", "pending"},
                failure_stage=(
                    "" if outcome.get("status") in {"confirmed", "pending"}
                    else "plan_verify"
                ),
                country=settings["payment_country"],
            )
        _QUEUE_SLOTS.release()


def _run_account(*, account_id: int, action: str, settings: dict) -> dict:
    try:
        context = db.get_account_paypal_context(account_id)
        if not context:
            return {"ok": False, "status": "failed", "error": "账号不存在"}
        email = str(context.get("email") or "")
        token = str(context.get("access_token") or "")
        has_saved_link = (
            str(context.get("paypal_extract_status") or "").strip().lower() == "success"
            and bool(
                str(context.get("paypal_ba_url") or "").strip()
                or str(context.get("paypal_ba_token") or "").strip()
            )
        )
        if action in {"extract", "extract_and_pay"} and not has_saved_link:
            ok, token = _run_extract(
                account_id=account_id, email=email, access_token=token, settings=settings,
            )
            if not ok or action == "extract":
                return {"ok": ok, "status": (db.get_account(account_id) or {}).get("paypal_extract_status")}
            claim = db.claim_account_paypal(
                account_id, action="pay", trigger="registration_auto_continue",
                mode="extract_and_pay",
                payment_proxy_pool_ref="",
                payment_proxy_pool_version=settings["payment_pool"].get("pool_version"),
            )
            if claim != "claimed":
                return {"ok": False, "status": claim, "error": "提链成功，但支付阶段未能占用"}
        elif action == "extract":
            return {"ok": True, "status": "success"}
        return _run_payment_start(
            account_id=account_id, email=email, access_token=token, settings=settings,
        )
    finally:
        _QUEUE_SLOTS.release()


def enqueue_account_paypal(
    *,
    account_id: int,
    action: str,
    trigger: str = "manual",
    force: bool = False,
    flow_snapshot: dict | None = None,
    options: dict | None = None,
) -> dict[str, Any]:
    selected_action = str(action or "").strip().lower()
    if selected_action not in {"extract", "pay", "extract_and_pay", "reauthorize"}:
        raise ValueError("action 仅支持 extract / pay / extract_and_pay / reauthorize")
    account_id = int(account_id)
    account = db.get_account_paypal_context(account_id)
    if account is None:
        return {"accepted": False, "status": "missing", "error": "账号不存在"}
    if selected_action in {"extract", "extract_and_pay"} and not str(account.get("access_token") or "").strip():
        return {"accepted": False, "status": "no_token", "error": "账号缺少 Web AT"}
    settings = _task_settings(flow_snapshot, options)
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "queue_full": True, "error": "PayPal 队列已满，请稍后重试"}

    extract_pool = settings["extract_pool"]
    payment_pool = settings["payment_pool"]
    claim = db.claim_account_paypal(
        account_id,
        action=selected_action,
        trigger=trigger,
        mode=str((flow_snapshot or {}).get("mode") or selected_action),
        requested_mode="stripe",
        force=bool(force),
        extract_proxy_pool_ref="",
        extract_proxy_pool_version=extract_pool.get("pool_version"),
        payment_proxy_pool_ref="",
        payment_proxy_pool_version=payment_pool.get("pool_version"),
    )
    original_claim = claim
    if claim in {"authorized", "pending", "verification_blocked"}:
        claim = db.claim_account_paypal_verification(account_id, trigger=trigger)
        if original_claim == "verification_blocked" and _remote_context_needs_resume(account):
            worker = _run_remote_resume
            kwargs = {"account_id": account_id}
        else:
            worker = _run_verification
            kwargs = {"account_id": account_id, "settings": settings}
    else:
        worker = _run_account
        kwargs = {"account_id": account_id, "action": selected_action, "settings": settings}
    if claim != "claimed":
        _QUEUE_SLOTS.release()
        messages = {
            "busy": "该账号已有 PP 任务运行中",
            "success": "该账号已保存 PP 链",
            "unavailable": "该账号已明确没有可用 PP 链",
            "waiting_otp": "该账号正在等待 PayPal 验证码",
            "confirmed": "该账号已经确认 Plus",
            "link_required": "支付前需要先提取 PP 链",
            "missing": "账号不存在",
        }
        return {
            "accepted": False,
            "busy": claim == "busy",
            "status": claim,
            "error": messages.get(claim, f"PP 任务未占用: {claim}"),
        }
    try:
        _submit_runtime(worker, **kwargs)
    except Exception as exc:
        _QUEUE_SLOTS.release()
        stage = "extract" if selected_action in {"extract", "extract_and_pay"} else "payment"
        db.update_account_paypal(
            account_id, stage=stage,
            result={"status": "failed", "error": f"PP 队列提交失败: {type(exc).__name__}", "stage": "queue"},
        )
        return {"accepted": False, "status": "failed", "error": "PP 队列提交失败"}
    return {
        "accepted": True, "busy": False, "status": "queued",
        "account_id": account_id, "action": selected_action, "trigger": trigger,
    }


def submit_account_paypal_otp(*, account_id: int, otp: str) -> dict[str, Any]:
    account_id = int(account_id)
    code = str(otp or "").strip()
    if not re.fullmatch(r"\d{6}", code):
        raise ValueError("otp 必须是 6 位数字")
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "queue_full": True, "error": "PayPal 队列已满，请稍后重试"}
    if not db.claim_account_paypal_otp(account_id):
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "账号不在等待 PayPal 验证码状态"}
    try:
        _submit_runtime(_run_otp, account_id=account_id, otp=code)
    except Exception:
        _QUEUE_SLOTS.release()
        db.update_account_paypal(
            account_id, stage="payment", result={
                "status": "waiting_otp", "message": "验证码入队失败，请重新提交",
            },
        )
        return {"accepted": False, "error": "PayPal 验证码入队失败"}
    return {"accepted": True, "status": "running", "account_id": account_id}


def continue_account_paypal_sms(*, account_id: int) -> dict[str, Any]:
    """Continue polling one persisted activation without starting payment again."""
    account_id = int(account_id)
    context = db.get_account_paypal_context(account_id)
    if context is None:
        return {"accepted": False, "status": "missing", "error": "账号不存在"}
    if str(context.get("paypal_payment_status") or "") != "waiting_otp":
        return {
            "accepted": False,
            "status": str(context.get("paypal_payment_status") or "not_started"),
            "error": "账号不在等待 PayPal 验证码状态",
        }
    if not isinstance(context.get("paypal_sms_context"), dict):
        return {
            "accepted": False, "status": "manual_only",
            "error": "该账号没有可继续的自动接码 activation",
        }
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {"accepted": False, "queue_full": True, "error": "PayPal 队列已满，请稍后重试"}
    if not db.claim_account_paypal_sms(account_id):
        _QUEUE_SLOTS.release()
        return {
            "accepted": False, "busy": True,
            "error": "自动接码正在运行、已消费，或当前状态不可继续",
        }
    try:
        _submit_runtime(_run_sms_continue, account_id=account_id)
    except Exception:
        _QUEUE_SLOTS.release()
        db.update_account_paypal_sms(account_id, {
            "status": "timeout", "error": "自动接码入队失败，可重新继续",
        })
        db.update_account_paypal(
            account_id, stage="payment", result={
                "status": "waiting_otp", "message": "自动接码入队失败，可重新继续或手动提交",
            },
        )
        return {"accepted": False, "error": "自动接码入队失败"}
    return {"accepted": True, "status": "polling", "account_id": account_id}


def queue_settings() -> dict[str, Any]:
    pools = {}
    for kind in ("extract", "payment"):
        try:
            pools[kind] = paypal_proxy_pool.list_pool(kind)
        except Exception as exc:
            pools[kind] = {
                "kind": kind, "items": [], "total": 0, "enabled": 0,
                "error": _safe_text(f"{type(exc).__name__}: {exc}"),
            }
    return {
        "workers": _WORKERS,
        "queue_limit": _QUEUE_LIMIT,
        "extract_pool": pools["extract"],
        "payment_pool": pools["payment"],
    }


__all__ = [
    "PayPalWorkflowError", "enqueue_account_paypal",
    "submit_account_paypal_otp", "continue_account_paypal_sms",
    "queue_settings", "reload_runtime_settings", "resume_remote_paypal_tasks",
]
