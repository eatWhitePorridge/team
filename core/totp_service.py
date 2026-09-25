# -*- coding: utf-8 -*-
"""Account-level ChatGPT TOTP enrollment and background queue."""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Callable

import pyotp

from config import twofa as twofa_cfg
from core import db
from core.account_cookie_store import normalize_cookies, persist_cookie_credential
from core.network_errors import is_retryable_network_error as _is_retryable_reauth_error
from core.plan_check_service import restore_account_request_context
from core.nextauth_cookies import session_cookie_scope
from core.session import BrowserSession

logger = logging.getLogger(__name__)

_MFA_INFO_URL = "https://chatgpt.com/backend-api/accounts/mfa_info"
_MFA_ENROLL_URL = "https://chatgpt.com/backend-api/accounts/mfa/enroll"
_MFA_ACTIVATE_URL = (
    "https://chatgpt.com/backend-api/accounts/mfa/user/activate_enrollment"
)


def _int_setting(name: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(getattr(twofa_cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


def _float_setting(name: str, default: float, lower: float, upper: float) -> float:
    try:
        value = float(getattr(twofa_cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


_WORKERS = _int_setting("TOTP_WORKERS", 4, 1, 32)
_QUEUE_LIMIT = _int_setting("TOTP_QUEUE_LIMIT", 500, _WORKERS, 5000)
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="totp-enroll")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)


class MfaRequestError(RuntimeError):
    """Sanitized MFA transport/protocol error safe to persist in account state."""

    def __init__(
        self,
        message: str,
        *,
        stage: str | None = None,
        http_status: int | None = None,
        retryable: bool = False,
        auth_required: bool = False,
        error_code: str = "mfa_request_failed",
    ) -> None:
        super().__init__(message)
        self.stage = str(stage or "").strip() or None
        self.http_status = http_status
        self.retryable = bool(retryable)
        self.auth_required = bool(auth_required)
        self.error_code = str(error_code or "mfa_request_failed")


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _mfa_headers(session: BrowserSession, access_token: str) -> dict[str, str]:
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/")
    headers.update({
        "accept": "application/json",
        "authorization": f"Bearer {str(access_token or '').strip()}",
        "content-type": "application/json",
        "origin": "https://chatgpt.com",
        "oai-device-id": session.device_id,
        "oai-language": session.navigator_language(),
    })
    return headers


def _looks_like_edge_challenge(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(marker in lowered for marker in (
        "<!doctype", "<html", "cloudflare", "cf-chl-", "turnstile", "captcha",
    ))


def _request_json(
    session: BrowserSession,
    method: str,
    url: str,
    access_token: str,
    *,
    payload: dict[str, Any] | None = None,
    stage: str,
) -> dict[str, Any]:
    timeout = _int_setting("TOTP_REQUEST_TIMEOUT", 20, 5, 120)
    request_fn = session.get if method == "GET" else session.post
    kwargs: dict[str, Any] = {
        "headers": _mfa_headers(session, access_token),
        "allow_redirects": False,
        "timeout": timeout,
    }
    if payload is not None:
        kwargs["data"] = json.dumps(payload, separators=(",", ":"))
    try:
        response = request_fn(url, **kwargs)
    except Exception as exc:
        raise MfaRequestError(
            f"{method} MFA 接口网络失败: {type(exc).__name__}",
            stage=stage,
            retryable=True,
            error_code="network_error",
        ) from exc

    status = int(getattr(response, "status_code", 0) or 0)
    response_text = str(getattr(response, "text", "") or "")
    if not 200 <= status < 300:
        challenge = _looks_like_edge_challenge(response_text)
        raise MfaRequestError(
            f"{method} MFA 接口返回 HTTP {status}",
            stage=stage,
            http_status=status,
            retryable=challenge or status in {408, 425, 429} or status >= 500,
            auth_required=status in {401, 403} and not challenge,
            error_code="authentication_required" if status in {401, 403} and not challenge else "http_error",
        )
    if not response_text.strip():
        return {}
    try:
        data = response.json()
    except Exception as exc:
        raise MfaRequestError(
            f"{method} MFA 接口响应不是有效 JSON",
            stage=stage,
            http_status=status,
            retryable=True,
            error_code="invalid_json",
        ) from exc
    if not isinstance(data, dict):
        raise MfaRequestError(
            f"{method} MFA 接口响应不是 JSON 对象",
            stage=stage,
            http_status=status,
            retryable=True,
            error_code="invalid_response",
        )
    return data


def parse_totp_factor_ids(payload: dict[str, Any] | None) -> list[str]:
    """Return non-empty active TOTP factor IDs from an mfa_info response."""
    factors = (payload or {}).get("factors")
    entries = factors.get("totp") if isinstance(factors, dict) else None
    if not isinstance(entries, list):
        return []
    factor_ids: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        factor_id = str(entry.get("id") or "").strip()
        if factor_id and factor_id not in factor_ids:
            factor_ids.append(factor_id)
    return factor_ids


def get_mfa_info(
    session: BrowserSession,
    access_token: str,
    *,
    stage: str = "mfa_info",
) -> dict[str, Any]:
    # mfa_info is read-only and can be retried safely. Keep enrollment and
    # activation POSTs single-shot because a lost response can still mean the
    # server accepted the mutation.
    attempts = _int_setting("TOTP_MFA_INFO_ATTEMPTS", 3, 1, 6)
    retry_delay = _float_setting("TOTP_MFA_INFO_RETRY_DELAY", 0.75, 0.0, 5.0)
    for attempt in range(1, attempts + 1):
        try:
            return _request_json(
                session,
                "GET",
                _MFA_INFO_URL,
                access_token,
                stage=stage,
            )
        except MfaRequestError as exc:
            if not exc.retryable or attempt >= attempts:
                raise
            logger.warning(
                "[TOTP] mfa_info 临时失败，任务内重试: stage=%s attempt=%s/%s code=%s",
                stage,
                attempt,
                attempts,
                exc.error_code,
            )
            if retry_delay > 0:
                time.sleep(min(5.0, retry_delay * attempt))
    raise RuntimeError("TOTP mfa_info 重试循环异常结束")  # pragma: no cover


def _enroll_totp(session: BrowserSession, access_token: str) -> tuple[str, str]:
    data = _request_json(
        session,
        "POST",
        _MFA_ENROLL_URL,
        access_token,
        payload={"factor_type": "totp"},
        stage="enroll",
    )
    secret = str(data.get("secret") or "").strip().replace(" ", "")
    enrollment_session_id = str(data.get("session_id") or "").strip()
    if not secret or not enrollment_session_id:
        raise MfaRequestError(
            "enroll 响应缺少 secret 或 session_id",
            stage="enroll",
            error_code="enroll_response_incomplete",
        )
    try:
        pyotp.TOTP(secret).at(0)
    except Exception as exc:
        raise MfaRequestError(
            "enroll 返回的 TOTP secret 不是有效 Base32",
            stage="enroll",
            error_code="invalid_totp_secret",
        ) from exc
    return secret, enrollment_session_id


def generate_totp_code(
    secret: str,
    *,
    time_fn: Callable[[], float] = time.time,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> str:
    """Generate a six-digit SHA-1 TOTP without using an expiring time window."""
    interval = 30
    minimum_remaining = _float_setting("TOTP_MIN_WINDOW_SECONDS", 5.0, 1.0, 15.0)
    current = float(time_fn())
    remaining = interval - (current % interval)
    if remaining < minimum_remaining:
        sleep_fn(remaining + 0.2)
        current = float(time_fn())
    generator = pyotp.TOTP(
        secret,
        digits=6,
        interval=interval,
        digest=hashlib.sha1,
    )
    return generator.at(current)


def _activate_totp(
    session: BrowserSession,
    access_token: str,
    secret: str,
    enrollment_session_id: str,
    *,
    time_fn: Callable[[], float],
    sleep_fn: Callable[[float], None],
) -> dict[str, Any]:
    code = generate_totp_code(secret, time_fn=time_fn, sleep_fn=sleep_fn)
    return _request_json(
        session,
        "POST",
        _MFA_ACTIVATE_URL,
        access_token,
        payload={
            "code": code,
            "factor_type": "totp",
            "session_id": enrollment_session_id,
        },
        stage="activate",
    )


def _failed_result(exc: Exception, *, access_token: str, reauthenticated: bool) -> dict[str, Any]:
    if isinstance(exc, MfaRequestError):
        error_code = exc.error_code
        http_status = exc.http_status
        retryable = exc.retryable
    else:
        error_code = "internal_error"
        http_status = None
        retryable = False
    return {
        "ok": False,
        "status": "failed",
        "message": "TOTP 补接失败",
        "error": f"{type(exc).__name__}: {str(exc)[:300]}",
        "error_code": error_code,
        "failure_stage": exc.stage if isinstance(exc, MfaRequestError) else None,
        "http_status": http_status,
        "retryable": retryable,
        "checked_at": _now_iso(),
        "access_token": access_token,
        "access_token_refreshed": reauthenticated,
    }


def _reauth_request_error(exc: Exception) -> MfaRequestError:
    """Translate reauth/mail failures without persisting sensitive exception text."""
    safe_to_persist = bool(getattr(exc, "safe_to_persist", False))
    supplied_code = str(getattr(exc, "error_code", "") or "").strip()
    supplied_retryable = getattr(exc, "retryable", None)
    retryable = _is_retryable_reauth_error(exc)
    supplied_status = getattr(exc, "http_status", getattr(exc, "status", None))
    try:
        http_status = int(supplied_status) if supplied_status is not None else None
    except (TypeError, ValueError):
        http_status = None
    if http_status is not None and not 100 <= http_status <= 599:
        http_status = None

    if safe_to_persist:
        message = str(exc).strip()[:240] or "邮箱重认证失败"
        error_code = supplied_code or "reauth_failed"
    elif supplied_retryable is not None:
        message = f"邮箱重认证取码失败: {type(exc).__name__}"
        error_code = supplied_code or "reauth_mail_error"
    elif retryable:
        message = f"邮箱重认证网络失败: {type(exc).__name__}"
        error_code = supplied_code or "reauth_network_error"
    else:
        message = f"邮箱重认证失败: {type(exc).__name__}"
        error_code = supplied_code or "reauth_failed"

    return MfaRequestError(
        message,
        stage="reauth",
        http_status=http_status,
        retryable=retryable,
        error_code=error_code,
    )


def enroll_totp_with_session(
    session: BrowserSession,
    access_token: str,
    email: str,
    *,
    reauth_callback: Callable[[BrowserSession, str, str], str] | None = None,
    time_fn: Callable[[], float] = time.time,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Enroll TOTP using the authoritative mfa_info state sequence.

    The temporary enrollment session ID never leaves this function. A returned
    ``factor_id`` can only originate from ``mfa_info.factors.totp[].id``.
    """
    token = str(access_token or "").strip()
    if not token:
        return _failed_result(
            ValueError("账号缺少 access_token"),
            access_token="",
            reauthenticated=False,
        )

    reauthenticated = False
    secret = ""
    enrollment_session_id = ""

    # A newly registered AT normally succeeds directly. Only an explicit auth
    # rejection restarts the baseline/enroll pair after protocol reauth.
    for auth_attempt in range(2):
        try:
            before = get_mfa_info(session, token, stage="mfa_info_before")
            before_ids = parse_totp_factor_ids(before)
            if before_ids:
                return {
                    "ok": True,
                    "status": "already_active",
                    "message": "远端账号已经启用 TOTP",
                    "factor_id": before_ids[0],
                    "factor_count": len(before_ids),
                    "checked_at": _now_iso(),
                    "access_token": token,
                    "access_token_refreshed": reauthenticated,
                }
            secret, enrollment_session_id = _enroll_totp(session, token)
            break
        except MfaRequestError as exc:
            can_reauth = (
                exc.auth_required
                and auth_attempt == 0
                and reauth_callback is not None
            )
            if not can_reauth:
                return _failed_result(
                    exc,
                    access_token=token,
                    reauthenticated=reauthenticated,
                )
            try:
                replacement = str(reauth_callback(session, email, token) or "").strip()
            except Exception as reauth_exc:
                return _failed_result(
                    _reauth_request_error(reauth_exc),
                    access_token=token,
                    reauthenticated=reauthenticated,
                )
            if not replacement:
                return _failed_result(
                    MfaRequestError(
                        "重认证未返回新的 access_token",
                        stage="reauth",
                        error_code="reauth_token_missing",
                    ),
                    access_token=token,
                    reauthenticated=reauthenticated,
                )
            token = replacement
            reauthenticated = True
    else:  # pragma: no cover - loop exits through return or break
        return _failed_result(
            RuntimeError("TOTP enrollment 未开始"),
            access_token=token,
            reauthenticated=reauthenticated,
        )

    # Required observation point. A transient failure here does not discard a
    # valid in-memory enrollment; the final mfa_info remains authoritative.
    try:
        middle = get_mfa_info(session, token, stage="mfa_info_middle")
        middle_ids = parse_totp_factor_ids(middle)
        if middle_ids:
            return {
                "ok": True,
                "status": "already_active",
                "message": "enroll 后检测到远端已有 active TOTP",
                "factor_id": middle_ids[0],
                "factor_count": len(middle_ids),
                "checked_at": _now_iso(),
                "access_token": token,
                "access_token_refreshed": reauthenticated,
            }
    except MfaRequestError:
        logger.warning("[TOTP] enroll 后的中间状态查询失败，将以激活后的最终查询为准")

    activation_error: MfaRequestError | None = None
    activation_response: dict[str, Any] = {}
    try:
        activation_response = _activate_totp(
            session,
            token,
            secret,
            enrollment_session_id,
            time_fn=time_fn,
            sleep_fn=sleep_fn,
        )
    except MfaRequestError as exc:
        activation_error = exc

    attempts = _int_setting("TOTP_FINAL_CHECK_ATTEMPTS", 3, 1, 8)
    final_error: MfaRequestError | None = None
    final_query_succeeded = False
    for attempt in range(1, attempts + 1):
        try:
            final_info = get_mfa_info(session, token, stage="mfa_info_final")
            final_query_succeeded = True
            final_ids = parse_totp_factor_ids(final_info)
            if final_ids:
                return {
                    "ok": True,
                    "status": "active",
                    "message": "TOTP 已确认启用",
                    "secret": secret,
                    "factor_id": final_ids[0],
                    "factor_count": len(final_ids),
                    "checked_at": _now_iso(),
                    "access_token": token,
                    "access_token_refreshed": reauthenticated,
                }
            final_error = None
        except MfaRequestError as exc:
            final_error = exc
        if attempt < attempts:
            sleep_fn(min(2.0, 0.5 * attempt))

    activation_rejected = activation_response.get("success") is False
    deterministic_failure = (
        activation_rejected
        or (
            activation_error is not None
            and activation_error.http_status is not None
            and not activation_error.retryable
        )
    )
    if deterministic_failure and final_query_succeeded:
        reason: Exception = activation_error or MfaRequestError(
            "activate_enrollment 返回 success=false",
            stage="activate",
            error_code="activation_rejected",
        )
        return {
            **_failed_result(
                reason,
                access_token=token,
                reauthenticated=reauthenticated,
            ),
            "message": "TOTP 激活被拒绝",
        }

    # The POST may have reached the server even when its response or the final
    # GET was lost. Keep the secret for recovery, but never report active.
    uncertainty = activation_error or final_error
    return {
        "ok": False,
        "status": "activation_uncertain",
        "message": "激活请求已提交，但尚未确认 active factor",
        "error": str(uncertainty or "最终 mfa_info 暂未返回 active TOTP")[:300],
        "error_code": (
            uncertainty.error_code
            if isinstance(uncertainty, MfaRequestError)
            else "activation_not_confirmed"
        ),
        "failure_stage": (
            uncertainty.stage
            if isinstance(uncertainty, MfaRequestError)
            else "mfa_info_final"
        ),
        "http_status": (
            uncertainty.http_status
            if isinstance(uncertainty, MfaRequestError)
            else None
        ),
        "retryable": True,
        "secret": secret,
        "checked_at": _now_iso(),
        "access_token": token,
        "access_token_refreshed": reauthenticated,
    }


def _apply_account_cookies(session: BrowserSession, cookies: list[dict[str, Any]] | None) -> None:
    now = time.time()
    for cookie in normalize_cookies(cookies or [], source="totp_enroll"):
        expires = cookie.get("expires")
        if isinstance(expires, (int, float)) and expires > 0 and expires <= now:
            continue
        name = str(cookie.get("name") or "")
        value = str(cookie.get("value") or "")
        if name.lower() == "oai-did" and value and value != session.device_id:
            continue
        session.session.cookies.set(
            name,
            value,
            domain=str(cookie.get("domain") or "chatgpt.com"),
            path=str(cookie.get("path") or "/"),
        )


def _cookie_key(cookie: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(cookie.get("domain") or "").lower(),
        str(cookie.get("path") or "/"),
        str(cookie.get("name") or ""),
    )


def _merged_runtime_cookies(
    original: list[dict[str, Any]] | None,
    runtime_cookies: Any,
) -> list[dict[str, Any]]:
    original_by_key = {
        _cookie_key(cookie): dict(cookie)
        for cookie in normalize_cookies(original or [], source="totp_original")
    }
    # Runtime is authoritative for session cookies, including deletions and
    # rotation between whole/chunked forms. Keep original metadata only for
    # cookies that still exist, rather than resurrecting expired sessions.
    merged = {
        key: cookie for key, cookie in original_by_key.items()
        if session_cookie_scope(cookie["name"], cookie["domain"], cookie["path"]) is None
    }
    for runtime in normalize_cookies(runtime_cookies, source="totp_runtime"):
        key = _cookie_key(runtime)
        previous = original_by_key.get(key)
        if previous is None:
            merged[key] = dict(runtime)
            continue
        updated = dict(previous)
        updated["value"] = str(runtime.get("value") or "")
        if runtime.get("expires") not in (None, 0, -1):
            updated["expires"] = runtime.get("expires")
        updated["secure"] = bool(runtime.get("secure", previous.get("secure")))
        merged[key] = updated
    return list(merged.values())


def _persist_runtime_cookies(
    account_id: int,
    email: str,
    session: BrowserSession,
    original: list[dict[str, Any]] | None,
) -> None:
    cookies = _merged_runtime_cookies(original, session.session.cookies.jar)
    if not cookies:
        return
    metadata = persist_cookie_credential(
        email,
        cookies,
        source="totp_enroll",
        account_id=account_id,
    )
    db.update_account_web_cookie_credential(
        account_id,
        credential_path=metadata["credential_path"],
        saved_at=metadata["saved_at"],
        cookie_count=metadata["count"],
        has_session_cookie=metadata["has_session_cookie"],
        status="saved",
        error=None,
    )


def _protocol_reauth(
    session: BrowserSession,
    email: str,
    previous_access_token: str,
) -> str:
    # Lazy import keeps account export/storage independent from this queue at
    # module import time while reusing its proven pure-HTTP reauth sequence.
    from core.account_export import reauthenticate_for_2fa

    attempts = _int_setting("TOTP_REAUTH_ATTEMPTS", 3, 1, 5)
    for attempt in range(1, attempts + 1):
        try:
            return reauthenticate_for_2fa(
                session,
                email,
                otp_code=None,
                allow_manual_input=False,
                previous_access_token=previous_access_token,
            )
        except Exception as exc:
            retryable = _is_retryable_reauth_error(exc)
            if (
                not retryable or attempt >= attempts
                or getattr(exc, "reauth_restart_recommended", True) is False
            ):
                raise
            logger.warning(
                "[TOTP] 重认证临时失败，任务内重试: attempt=%s/%s error=%s",
                attempt,
                attempts,
                type(exc).__name__,
            )
            time.sleep(min(2.0, 0.75 * attempt))
    raise RuntimeError("TOTP 重认证重试循环异常结束")  # pragma: no cover


def _run_account_totp(
    *,
    account_id: int,
    claim_id: str,
    email: str,
    access_token: str,
    trigger: str,
    proxy: str | None,
    device_id: str | None,
    cookies: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    session: BrowserSession | None = None
    try:
        if not db.mark_account_totp_running(account_id, claim_id=claim_id):
            return {"ok": False, "status": "failed", "error": "账号已删除或任务已被重置"}

        latest_account = db.get_account(account_id) or {}
        latest_token = str(latest_account.get("access_token") or "").strip()
        if latest_token:
            access_token = latest_token

        proxy, device_id, cookies = restore_account_request_context(
            account_id=account_id,
            proxy=proxy,
            device_id=device_id,
            cookies=cookies,
        )
        session = BrowserSession(
            proxy=proxy if proxy is not None else "",
            detect_exit_geo=False,
            device_id=device_id,
        )
        _apply_account_cookies(session, cookies)
        result = enroll_totp_with_session(
            session,
            access_token,
            email,
            reauth_callback=_protocol_reauth,
        )

        effective_token = str(result.pop("access_token", "") or "").strip()
        if effective_token and effective_token != access_token:
            replaced = db.replace_account_access_token(
                account_id,
                expected_access_token=access_token,
                access_token=effective_token,
                source="totp_reauth",
            )
            if not replaced:
                result["token_update_error"] = "任务期间账号 Web AT 已被其他流程更新"
        if result.get("access_token_refreshed"):
            try:
                _persist_runtime_cookies(account_id, email, session, cookies)
            except Exception as exc:
                result["cookie_update_error"] = f"{type(exc).__name__}: {str(exc)[:180]}"
                logger.warning("[TOTP] 刷新后的 Cookie 保存失败: account_id=%s", account_id)

        db.update_account_totp(account_id, result=result, claim_id=claim_id)
        if result.get("status") == "active":
            logger.info("[TOTP] 补接成功: account_id=%s trigger=%s", account_id, trigger)
        elif result.get("status") == "already_active":
            logger.info("[TOTP] 远端已启用，无需重复补接: account_id=%s", account_id)
        else:
            logger.warning(
                "[TOTP] 补接未确认: account_id=%s status=%s stage=%s code=%s error=%s",
                account_id,
                result.get("status") or "failed",
                result.get("failure_stage") or "unknown",
                result.get("error_code") or "unknown",
                result.get("error") or result.get("message") or "未知错误",
            )
        return result
    except Exception as exc:
        result = {
            "ok": False,
            "status": "failed",
            "message": "TOTP 补接任务异常",
            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
            "error_code": "internal_error",
            "checked_at": _now_iso(),
        }
        try:
            db.update_account_totp(account_id, result=result, claim_id=claim_id)
        except Exception:
            logger.exception("[TOTP] 写入异常状态失败: account_id=%s", account_id)
        logger.exception("[TOTP] 补接任务异常: account_id=%s", account_id)
        return result
    finally:
        if session is not None:
            try:
                session.session.close()
            except Exception:
                pass
        _QUEUE_SLOTS.release()


def enqueue_account_totp(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str = "manual",
    proxy: str | None = None,
    device_id: str | None = None,
    cookies: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Atomically enqueue one account for TOTP reconciliation/enrollment."""
    account_id = int(account_id)
    email = str(email or "").strip()
    access_token = str(access_token or "").strip()
    if not access_token:
        return {"accepted": False, "busy": False, "error": "账号缺少 access_token"}
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {
            "accepted": False,
            "busy": False,
            "queue_full": True,
            "error": "TOTP 补接队列已满，请稍后重试",
        }

    try:
        claim_id = db.claim_account_totp(account_id, trigger=str(trigger or "manual"))
    except BaseException:
        _QUEUE_SLOTS.release()
        raise
    if not claim_id:
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "该账号正在补接 TOTP"}
    try:
        _EXECUTOR.submit(
            _run_account_totp,
            account_id=account_id,
            claim_id=claim_id,
            email=email,
            access_token=access_token,
            trigger=str(trigger or "manual"),
            proxy=proxy,
            device_id=device_id,
            cookies=cookies,
        )
    except Exception as exc:
        _QUEUE_SLOTS.release()
        result = {
            "ok": False,
            "status": "failed",
            "message": "TOTP 补接任务入队失败",
            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
            "error_code": "enqueue_failed",
            "checked_at": _now_iso(),
        }
        db.update_account_totp(account_id, result=result, claim_id=claim_id)
        return {"accepted": False, "busy": False, "error": result["error"]}
    return {
        "accepted": True,
        "busy": False,
        "account_id": account_id,
        "email": email,
        "status": "queued",
        "trigger": str(trigger or "manual"),
    }


def enqueue_accounts_totp(account_ids: list) -> dict:
    from core.supplement_queue import enqueue_supplement_batch

    # Workers read the current access token from storage when they start, so
    # queued requests do not retain hundreds of credential copies in memory.
    return enqueue_supplement_batch(
        account_ids, kind="totp", trigger="manual_bulk", slots=_QUEUE_SLOTS,
        submit=lambda **kwargs: _EXECUTOR.submit(
            _run_account_totp, **kwargs, access_token="", proxy=None, device_id=None, cookies=None,
        ),
    )


def queue_settings() -> dict[str, Any]:
    return {"workers": _WORKERS, "queue_limit": _QUEUE_LIMIT}


__all__ = [
    "MfaRequestError",
    "enroll_totp_with_session",
    "enqueue_account_totp",
    "enqueue_accounts_totp",
    "get_mfa_info",
    "parse_totp_factor_ids",
    "queue_settings",
]
