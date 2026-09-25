# -*- coding: utf-8 -*-
"""HTTP adapter for the standalone PayPal agreement worker service."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

import requests


DEVICE_COOKIE_NAME = "paypal_web_device_id"
DEFAULT_API_BASE = "https://paypal.173.249.205.56.sslip.io/paypal-pay/api"
_ACTIVE_STATUSES = frozenset({"queued", "running", "cancelling"})
_OTP_CODE_RE = re.compile(r"^\d{4,8}$")
_OTP_SETTLE_TIMEOUT = 60.0
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,160}$")
_COOKIE_RE = re.compile(r"^[A-Za-z0-9._~-]{16,256}$")
_SECRET_RE = re.compile(
    r"(?i)(Bearer\s+)[A-Za-z0-9._=-]+|"
    r"\b(?:BA-|EC-|tok_|cs_(?:live|test)_)[A-Za-z0-9._-]{6,}\b"
)
_PROXY_AUTH_RE = re.compile(r"(?i)(https?://|socks4://|socks5h?://)[^/@\s]+@")
_PHONE_RE = re.compile(r"(?<!\d)\+?\d[\d ()-]{7,}\d(?!\d)")


class RemotePayPalError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        stage: str,
        message: str = "",
        retryable: bool = False,
        replay_safe: bool = False,
        ambiguous: bool | None = None,
        http_status: int | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        self.code = str(code or "REMOTE_PAYPAL_ERROR").upper()[:80]
        self.stage = _stage_slug(stage)
        self.retryable = bool(retryable)
        self.replay_safe = bool(replay_safe)
        self.ambiguous = bool(not replay_safe if ambiguous is None else ambiguous)
        self.http_status = int(http_status) if http_status is not None else None
        self.context = _json_copy(context) if isinstance(context, Mapping) else None
        super().__init__(str(message or self.code)[:500])


def _json_copy(value: Mapping[str, Any] | None) -> dict[str, Any]:
    return json.loads(json.dumps(dict(value or {}), ensure_ascii=False))


def _bounded_float(
    value: object,
    *,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    try:
        parsed = float(value if value not in {None, ""} else default)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _api_base(value: object) -> str:
    raw = str(value or DEFAULT_API_BASE).strip().rstrip("/")
    parsed = urlsplit(raw)
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme not in {"http", "https"}
        or not host
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise RemotePayPalError(
            "REMOTE_API_BASE_INVALID", stage="remote_input", replay_safe=True,
        )
    if parsed.scheme != "https" and host not in {"127.0.0.1", "localhost", "::1"}:
        raise RemotePayPalError(
            "REMOTE_API_HTTPS_REQUIRED", stage="remote_input", replay_safe=True,
        )
    return raw


def _stage_slug(value: object) -> str:
    text = re.sub(r"[^a-z0-9_-]+", "_", str(value or "remote_job").strip().lower())
    return (text.strip("_") or "remote_job")[:80]


def _safe_message(value: object, *, secrets: tuple[str, ...] = ()) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    for secret in sorted((str(item) for item in secrets if str(item)), key=len, reverse=True):
        text = text.replace(secret, "***")
    text = _SECRET_RE.sub(lambda match: f"{match.group(1)}***" if match.group(1) else "***", text)
    text = _PROXY_AUTH_RE.sub(r"\1***@", text)

    def mask_phone(match: re.Match) -> str:
        digits = "".join(ch for ch in match.group(0) if ch.isdigit())
        return f"+**{digits[-4:]}" if digits else "+**"

    return _PHONE_RE.sub(mask_phone, text)[:500]


def _response_json(
    response: Any,
    *,
    stage: str,
    context: Mapping[str, Any] | None = None,
    request_mutating: bool = False,
) -> dict:
    status = int(getattr(response, "status_code", 0) or 0)
    deterministic_rejection = status in {400, 401, 403, 404, 405, 413, 415, 422}
    replay_safe = context is None and (
        not request_mutating or deterministic_rejection
    )
    try:
        payload = response.json()
    except Exception as exc:
        raise RemotePayPalError(
            "REMOTE_RESPONSE_INVALID",
            stage=stage,
            message="远程 PayPal API 未返回 JSON",
            retryable=status >= 500 or status == 0,
            replay_safe=replay_safe,
            ambiguous=not replay_safe,
            http_status=status or None,
            context=context,
        ) from exc
    if not isinstance(payload, dict):
        raise RemotePayPalError(
            "REMOTE_RESPONSE_INVALID",
            stage=stage,
            message="远程 PayPal API 响应结构无效",
            replay_safe=replay_safe,
            ambiguous=not replay_safe,
            http_status=status or None,
            context=context,
        )
    if not 200 <= status < 300:
        error = _safe_message(payload.get("error") or payload.get("detail") or f"HTTP {status}")
        missing = status == 404 and context is not None
        raise RemotePayPalError(
            "REMOTE_JOB_NOT_FOUND" if missing else "REMOTE_HTTP_ERROR",
            stage=stage,
            message=error,
            retryable=status in {408, 425, 429} or status >= 500,
            replay_safe=replay_safe,
            ambiguous=not replay_safe,
            http_status=status,
            context=context,
        )
    return payload


def _cookie_value(session: Any, response: Any | None = None) -> str:
    jars = [getattr(response, "cookies", None), getattr(session, "cookies", None)]
    for jar in jars:
        if jar is None:
            continue
        try:
            value = jar.get(DEVICE_COOKIE_NAME)
        except Exception:
            value = None
            try:
                for cookie in jar:
                    if getattr(cookie, "name", "") == DEVICE_COOKIE_NAME:
                        value = getattr(cookie, "value", "")
                        break
            except Exception:
                value = None
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _set_cookie(session: Any, value: str) -> None:
    if not _COOKIE_RE.fullmatch(str(value or "")):
        raise RemotePayPalError(
            "REMOTE_DEVICE_COOKIE_INVALID", stage="remote_resume", replay_safe=False,
        )
    jar = getattr(session, "cookies", None)
    if jar is None or not hasattr(jar, "set"):
        raise RemotePayPalError(
            "REMOTE_SESSION_INVALID", stage="remote_resume", replay_safe=False,
        )
    jar.set(DEVICE_COOKIE_NAME, value, path="/")


def _new_session(session_factory: Callable[[], Any] | None = None) -> Any:
    session = session_factory() if session_factory is not None else requests.Session()
    if not hasattr(session, "request"):
        raise RemotePayPalError(
            "REMOTE_SESSION_INVALID", stage="remote_session", replay_safe=True,
        )
    headers = getattr(session, "headers", None)
    if hasattr(headers, "update"):
        headers.update({
            "Accept": "application/json",
            "User-Agent": "gpt-register-paypal-remote/1.0",
        })
    return session


def _close_session(session: Any) -> None:
    close = getattr(session, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


def _request(
    session: Any,
    method: str,
    url: str,
    *,
    timeout: float,
    stage: str,
    context: Mapping[str, Any] | None = None,
    json_body: dict | None = None,
) -> tuple[dict, Any]:
    try:
        response = session.request(
            method,
            url,
            json=json_body,
            timeout=timeout,
        )
    except Exception as exc:
        mutating = str(method or "GET").upper() not in {"GET", "HEAD", "OPTIONS"}
        raise RemotePayPalError(
            "REMOTE_TRANSPORT_ERROR",
            stage=stage,
            message=f"远程 PayPal API 请求失败: {type(exc).__name__}",
            retryable=True,
            replay_safe=context is None and not mutating,
            ambiguous=context is not None or mutating,
            context=context,
        ) from exc
    return _response_json(
        response,
        stage=stage,
        context=context,
        request_mutating=str(method or "GET").upper() not in {"GET", "HEAD", "OPTIONS"},
    ), response


def _validate_context(context: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(context, Mapping):
        raise RemotePayPalError(
            "REMOTE_CONTEXT_INVALID", stage="remote_resume", replay_safe=False,
        )
    saved = _json_copy(context)
    if str(saved.get("executor") or "").lower() != "remote":
        raise RemotePayPalError(
            "REMOTE_CONTEXT_INVALID", stage="remote_resume", replay_safe=False,
        )
    saved["api_base"] = _api_base(saved.get("api_base"))
    job_id = str(saved.get("job_id") or "").strip()
    device_cookie = str(saved.get("device_cookie") or "").strip()
    if not _JOB_ID_RE.fullmatch(job_id) or not _COOKIE_RE.fullmatch(device_cookie):
        raise RemotePayPalError(
            "REMOTE_CONTEXT_INVALID", stage="remote_resume", replay_safe=False,
        )
    saved["job_id"] = job_id
    saved["device_cookie"] = device_cookie
    try:
        saved["log_cursor"] = max(0, int(saved.get("log_cursor") or 0))
    except (TypeError, ValueError):
        saved["log_cursor"] = 0
    return saved


def _job_from_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    job = payload.get("job") if isinstance(payload.get("job"), dict) else payload
    if not isinstance(job, Mapping):
        raise RemotePayPalError(
            "REMOTE_JOB_RESPONSE_INVALID", stage="remote_job", replay_safe=False,
        )
    result = _json_copy(job)
    job_id = str(result.get("id") or "").strip()
    if not _JOB_ID_RE.fullmatch(job_id):
        raise RemotePayPalError(
            "REMOTE_JOB_RESPONSE_INVALID", stage="remote_job", replay_safe=False,
        )
    result["id"] = job_id
    result["status"] = str(result.get("status") or "").strip().lower()
    return result


def _remote_time(value: object) -> str | None:
    try:
        timestamp = float(value)
    except (TypeError, ValueError):
        text = str(value or "").strip()
        if not text:
            return None
        try:
            datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        return text
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _emit_remote_logs(
    context: dict[str, Any],
    job: Mapping[str, Any],
    *,
    trace: Callable[[dict[str, Any]], None] | None,
    secrets: tuple[str, ...],
) -> bool:
    logs = job.get("logs") if isinstance(job.get("logs"), list) else []
    cursor = max(0, min(int(context.get("log_cursor") or 0), len(logs)))
    if trace is not None:
        for item in logs[cursor:]:
            if not isinstance(item, Mapping):
                continue
            level = str(item.get("level") or "info").strip().lower()
            status = (
                "failed" if level == "error" else
                "warning" if level in {"warning", "warn"} else
                "success" if level == "success" else
                "step"
            )
            event = {
                "status": status,
                "stage": _stage_slug(job.get("stage") or "remote_job"),
                "message": _safe_message(item.get("message"), secrets=secrets),
            }
            timestamp = _remote_time(item.get("time"))
            if timestamp:
                event["time"] = timestamp
            trace(event)
    changed = len(logs) != int(context.get("log_cursor") or 0)
    context["log_cursor"] = len(logs)
    return changed


def _checkpoint(
    callback: Callable[[dict[str, Any], dict[str, Any]], None] | None,
    context: dict[str, Any],
    job: dict[str, Any],
) -> None:
    if callback is not None:
        callback(_json_copy(context), _json_copy(job))


def _job_error(job: Mapping[str, Any]) -> tuple[str, str, bool, bool, int | None]:
    result = job.get("result") if isinstance(job.get("result"), Mapping) else {}
    raw_error = job.get("error") or result.get("error") or "远程 PayPal 任务失败"
    code = str(
        job.get("error_code") or result.get("error_code") or result.get("code")
        or "REMOTE_JOB_FAILED"
    ).upper()[:80]
    retryable = bool(job.get("retryable", result.get("retryable", False)))
    replay_safe = bool(job.get("replay_safe", result.get("replay_safe", False)))
    try:
        http_status = int(job.get("http_status") or result.get("http_status"))
    except (TypeError, ValueError):
        http_status = None
    return _safe_message(raw_error), code, retryable, replay_safe, http_status


def _safe_reference(value: object) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    parsed = urlsplit(text)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        try:
            port = f":{parsed.port}" if parsed.port else ""
        except ValueError:
            port = ""
        text = f"{parsed.scheme}://{parsed.hostname}{port}"
    return _safe_message(text)[:300] or None


def _result_from_job(context: dict[str, Any], job: dict[str, Any]) -> dict[str, Any] | None:
    status = str(job.get("status") or "").strip().lower()
    result = job.get("result") if isinstance(job.get("result"), Mapping) else {}
    stage = _stage_slug(
        result.get("failure_stage") or result.get("stage")
        or job.get("failure_stage") or job.get("stage") or "remote_job"
    )
    if status == "awaiting_otp" or bool(job.get("awaiting_otp")):
        return {
            "status": "waiting_otp",
            "message": _safe_message(
                job.get("awaiting_prompt") or "等待 PayPal 短信验证码"
            ),
            "context": _json_copy(context),
            "payment_context": _json_copy(context),
            "otp_context": _json_copy(context),
        }
    if status == "awaiting_captcha" or bool(job.get("awaiting_captcha")):
        return {
            "status": "pending_verification",
            "message": _safe_message(
                job.get("awaiting_prompt") or "远程 PayPal 任务需要人工挑战"
            ),
            "stage": "remote_captcha",
            "error": {
                "code": "REMOTE_CAPTCHA_REQUIRED",
                "stage": "remote_captcha",
                "retryable": False,
                "replay_safe": False,
            },
            "context": _json_copy(context),
            "payment_context": _json_copy(context),
            "replay_safe": False,
        }
    if status == "completed":
        reference = _safe_reference(
            result.get("reference") or result.get("final_merchant_url")
            or result.get("return_url") or result.get("pending_url")
        )
        agreement_id = (
            result.get("agreement_id") or result.get("billing_agreement_id")
        )
        return {
            "status": "authorized",
            "message": "远程 PayPal Agreement 已授权",
            "reference": reference,
            "agreement_id": agreement_id,
            "context": _json_copy(context),
            "payment_context": _json_copy(context),
        }
    if status in {"failed", "cancelled"}:
        message, code, retryable, replay_safe, http_status = _job_error(job)
        if status == "cancelled" and code == "REMOTE_JOB_FAILED":
            code = "REMOTE_JOB_CANCELLED"
        return {
            "status": "failed",
            "message": message,
            "stage": stage,
            "error_code": code,
            "error": {
                "code": code,
                "stage": stage,
                "retryable": retryable,
                "replay_safe": replay_safe,
                "http_status": http_status,
            },
            "retryable": retryable,
            "replay_safe": replay_safe,
            "ambiguous": not replay_safe,
            "payment_context": _json_copy(context),
        }
    return None


def create_remote_paypal_job(
    *,
    api_base: str,
    ba_url: str,
    phone: str,
    country: str,
    buyer_mode: str,
    proxy: str,
    timeout: float = 30.0,
    session_factory: Callable[[], Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Create a remote job and return its private resumable context."""
    base = _api_base(api_base)
    request_timeout = _bounded_float(timeout, default=30.0, minimum=1.0, maximum=120.0)
    session = _new_session(session_factory)
    try:
        _, preflight = _request(
            session, "GET", f"{base}/jobs", timeout=request_timeout,
            stage="remote_device", context=None,
        )
        device_cookie = _cookie_value(session, preflight)
        if not _COOKIE_RE.fullmatch(device_cookie):
            raise RemotePayPalError(
                "REMOTE_DEVICE_COOKIE_MISSING",
                stage="remote_device",
                message="远程 PayPal API 未下发设备 Cookie",
                retryable=True,
                replay_safe=True,
            )
        payload, response = _request(
            session,
            "POST",
            f"{base}/jobs",
            timeout=request_timeout,
            stage="remote_create",
            context=None,
            json_body={
                "paypal_url": str(ba_url or "").strip(),
                "phone": str(phone or "").strip(),
                "country": str(country or "").strip().upper(),
                "buyer_mode": str(buyer_mode or "").strip().lower(),
                "agreement_only": True,
                "proxies": [str(proxy or "").strip()],
            },
        )
        device_cookie = _cookie_value(session, response) or device_cookie
        job = _job_from_payload(payload)
        context = {
            "schema_version": 1,
            "executor": "remote",
            "api_base": base,
            "job_id": job["id"],
            "device_cookie": device_cookie,
            "log_cursor": 0,
            "last_status": str(job.get("status") or "queued"),
            "last_stage": str(job.get("stage") or ""),
            "created_at": datetime.now(tz=timezone.utc).isoformat(),
        }
        return context, job
    finally:
        _close_session(session)


def get_remote_paypal_job(
    *,
    context: Mapping[str, Any],
    timeout: float = 30.0,
    session_factory: Callable[[], Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    saved = _validate_context(context)
    session = _new_session(session_factory)
    try:
        _set_cookie(session, saved["device_cookie"])
        payload, response = _request(
            session,
            "GET",
            f"{saved['api_base']}/jobs/{saved['job_id']}?log_offset=0",
            timeout=_bounded_float(timeout, default=30.0, minimum=1.0, maximum=120.0),
            stage="remote_poll",
            context=saved,
        )
        cookie = _cookie_value(session, response)
        if cookie:
            saved["device_cookie"] = cookie
        return saved, _job_from_payload(payload)
    finally:
        _close_session(session)


def submit_remote_paypal_value(
    *,
    context: Mapping[str, Any],
    value: str,
    timeout: float = 30.0,
    session_factory: Callable[[], Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    saved = _validate_context(context)
    text = str(value or "").strip()
    if not text or len(text) > 80:
        raise RemotePayPalError(
            "REMOTE_OTP_VALUE_INVALID", stage="remote_otp", replay_safe=False,
            context=saved,
        )
    session = _new_session(session_factory)
    try:
        _set_cookie(session, saved["device_cookie"])
        payload, response = _request(
            session,
            "POST",
            f"{saved['api_base']}/jobs/{saved['job_id']}/otp",
            timeout=_bounded_float(timeout, default=30.0, minimum=1.0, maximum=120.0),
            stage="remote_otp",
            context=saved,
            json_body={"value": text},
        )
        cookie = _cookie_value(session, response)
        if cookie:
            saved["device_cookie"] = cookie
        return saved, _job_from_payload(payload)
    finally:
        _close_session(session)


def cancel_remote_paypal_job(
    *,
    context: Mapping[str, Any],
    timeout: float = 30.0,
    session_factory: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    saved = _validate_context(context)
    session = _new_session(session_factory)
    try:
        _set_cookie(session, saved["device_cookie"])
        payload, _ = _request(
            session,
            "POST",
            f"{saved['api_base']}/jobs/{saved['job_id']}/cancel",
            timeout=_bounded_float(timeout, default=30.0, minimum=1.0, maximum=120.0),
            stage="remote_cancel",
            context=saved,
            json_body={},
        )
        return _job_from_payload(payload)
    finally:
        _close_session(session)


def wait_remote_paypal_job(
    *,
    context: Mapping[str, Any],
    initial_job: Mapping[str, Any] | None = None,
    timeout: float = 30.0,
    poll_interval: float = 1.0,
    job_timeout: float = 600.0,
    session_factory: Callable[[], Any] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    trace: Callable[[dict[str, Any]], None] | None = None,
    checkpoint: Callable[[dict[str, Any], dict[str, Any]], None] | None = None,
    secrets: tuple[str, ...] = (),
    settle_submitted_otp: bool = False,
) -> dict[str, Any]:
    saved = _validate_context(context)
    interval = _bounded_float(poll_interval, default=1.0, minimum=0.1, maximum=30.0)
    started_at = monotonic()
    deadline = started_at + _bounded_float(
        job_timeout, default=600.0, minimum=10.0, maximum=3600.0,
    )
    otp_settle_deadline = min(deadline, started_at + _OTP_SETTLE_TIMEOUT)
    job = _json_copy(initial_job) if isinstance(initial_job, Mapping) else None
    while True:
        if job is None:
            try:
                saved, job = get_remote_paypal_job(
                    context=saved, timeout=timeout, session_factory=session_factory,
                )
            except RemotePayPalError as exc:
                if monotonic() >= deadline or not exc.retryable:
                    return {
                        "status": "pending_verification",
                        "message": "远程 PayPal 任务暂时无法查询，已保留任务上下文",
                        "stage": exc.stage,
                        "error": {
                            "code": exc.code,
                            "stage": exc.stage,
                            "retryable": exc.retryable,
                            "replay_safe": False,
                            "http_status": exc.http_status,
                        },
                        "context": _json_copy(saved),
                        "payment_context": _json_copy(saved),
                        "replay_safe": False,
                    }
                sleep(interval)
                continue

        changed_logs = _emit_remote_logs(
            saved, job, trace=trace, secrets=secrets,
        )
        status = str(job.get("status") or "").strip().lower()
        changed_state = (
            status != str(saved.get("last_status") or "")
            or str(job.get("stage") or "") != str(saved.get("last_stage") or "")
        )
        saved["last_status"] = status
        saved["last_stage"] = str(job.get("stage") or "")[:160]
        if changed_logs or changed_state:
            _checkpoint(checkpoint, saved, job)
        result = _result_from_job(saved, job)
        if result is not None:
            if (
                settle_submitted_otp
                and result.get("status") == "waiting_otp"
                and monotonic() < otp_settle_deadline
            ):
                # POST /otp acknowledges input before the worker consumes it.
                # During that short window the job still reports awaiting_otp.
                sleep(interval)
                job = None
                continue
            return result
        if status not in _ACTIVE_STATUSES:
            return {
                "status": "pending_verification",
                "message": _safe_message(
                    f"远程 PayPal 任务返回未知状态: {status or 'empty'}"
                ),
                "stage": "remote_status",
                "error": {
                    "code": "REMOTE_STATUS_UNKNOWN",
                    "stage": "remote_status",
                    "retryable": False,
                    "replay_safe": False,
                },
                "context": _json_copy(saved),
                "payment_context": _json_copy(saved),
                "replay_safe": False,
            }
        if monotonic() >= deadline:
            return {
                "status": "pending_verification",
                "message": "远程 PayPal 任务仍在运行，已保留任务上下文供续查",
                "stage": "remote_poll",
                "error": {
                    "code": "REMOTE_JOB_TIMEOUT",
                    "stage": "remote_poll",
                    "retryable": True,
                    "replay_safe": False,
                },
                "context": _json_copy(saved),
                "payment_context": _json_copy(saved),
                "replay_safe": False,
            }
        sleep(interval)
        job = None


def start_remote_paypal_payment(
    *,
    api_base: str,
    ba_url: str,
    phone: str,
    country: str,
    buyer_mode: str,
    proxy: str,
    timeout: float = 30.0,
    poll_interval: float = 1.0,
    job_timeout: float = 600.0,
    session_factory: Callable[[], Any] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    trace: Callable[[dict[str, Any]], None] | None = None,
    checkpoint: Callable[[dict[str, Any], dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    context, job = create_remote_paypal_job(
        api_base=api_base,
        ba_url=ba_url,
        phone=phone,
        country=country,
        buyer_mode=buyer_mode,
        proxy=proxy,
        timeout=timeout,
        session_factory=session_factory,
    )
    _checkpoint(checkpoint, context, job)
    return wait_remote_paypal_job(
        context=context,
        initial_job=job,
        timeout=timeout,
        poll_interval=poll_interval,
        job_timeout=job_timeout,
        session_factory=session_factory,
        sleep=sleep,
        monotonic=monotonic,
        trace=trace,
        checkpoint=checkpoint,
        secrets=(ba_url, phone, proxy, context["device_cookie"]),
    )


def resume_remote_paypal_payment(
    *,
    context: Mapping[str, Any],
    value: str = "",
    timeout: float = 30.0,
    poll_interval: float = 1.0,
    job_timeout: float = 600.0,
    session_factory: Callable[[], Any] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    trace: Callable[[dict[str, Any]], None] | None = None,
    checkpoint: Callable[[dict[str, Any], dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    saved = _validate_context(context)
    initial_job = None
    submitted_value = str(value or "").strip()
    if submitted_value:
        saved, initial_job = submit_remote_paypal_value(
            context=saved,
            value=submitted_value,
            timeout=timeout,
            session_factory=session_factory,
        )
        _checkpoint(checkpoint, saved, initial_job)
    return wait_remote_paypal_job(
        context=saved,
        initial_job=initial_job,
        timeout=timeout,
        poll_interval=poll_interval,
        job_timeout=job_timeout,
        session_factory=session_factory,
        sleep=sleep,
        monotonic=monotonic,
        trace=trace,
        checkpoint=checkpoint,
        secrets=(saved["device_cookie"], submitted_value),
        settle_submitted_otp=bool(_OTP_CODE_RE.fullmatch(submitted_value)),
    )


__all__ = [
    "DEFAULT_API_BASE",
    "DEVICE_COOKIE_NAME",
    "RemotePayPalError",
    "cancel_remote_paypal_job",
    "create_remote_paypal_job",
    "get_remote_paypal_job",
    "resume_remote_paypal_payment",
    "start_remote_paypal_payment",
    "submit_remote_paypal_value",
    "wait_remote_paypal_job",
]
