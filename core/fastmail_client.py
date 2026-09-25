# -*- coding: utf-8 -*-
"""Fastmail JMAP 邮箱客户端（仅 Token，不导入邮箱素材）。

任务开始时通过 Fastmail 的 ``UserAlias/set`` 或 customer ``Alias/set`` 创建普通邮箱 Alias，
再使用 JMAP ``Email/query``/``Email/queryChanges`` 增量读取其目标收件箱。
这里不会创建 Masked Email；默认 JMAP 请求只使用 Bearer Token，只有旧版
customer Alias 或 Bearer 失败后的兼容 fallback 才会使用配置的 Web Cookie。
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import re
import string
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Iterable
from urllib.parse import urlparse

import requests

from config import email as _email_cfg
from core.otp_poll_control import check_stop_requested, sleep_with_stop
from core.otp_utils import extract_otp, looks_like_openai_email

logger = logging.getLogger(__name__)

DEFAULT_API_BASE = "https://api.fastmail.com"
DEFAULT_SESSION_PATH = "/jmap/session"
CORE_CAPABILITY = "urn:ietf:params:jmap:core"
MAIL_CAPABILITY = "urn:ietf:params:jmap:mail"
SUBMISSION_CAPABILITY = "urn:ietf:params:jmap:submission"
CUSTOMER_CAPABILITY = "https://www.fastmail.com/dev/customer"
USER_CAPABILITY = "https://www.fastmail.com/dev/user"
FASTMAIL_KIND_NOT_CONFIGURED = "not_configured"
FASTMAIL_KIND_SESSION_EXPIRED = "session_expired"
FASTMAIL_KIND_BAD_CREDENTIALS = "bad_credentials"
FASTMAIL_KIND_PERMISSION_DENIED = "permission_denied"
FASTMAIL_KIND_NETWORK = "network"
FASTMAIL_KIND_RATE_LIMITED = "rate_limited"
FASTMAIL_KIND_UPSTREAM_ERROR = "upstream_error"
FASTMAIL_KIND_PROTOCOL_ERROR = "protocol_error"
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_CACHE_TTL_SECONDS = 300
_DEFAULT_MESSAGE_LIMIT = 10
# JMAP Email/get expects bodyProperties to be a list of property names, not
# JSON objects. Keep this explicit so an upstream schema change is visible.
_BODY_PROPERTIES = [
    "partId",
    "blobId",
    "type",
    "size",
    "charset",
    "name",
    "disposition",
]


class FastmailMailError(RuntimeError):
    """Fastmail 授权、JMAP 或验证码读取失败。"""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        retryable: bool = True,
        kind: str = FASTMAIL_KIND_UPSTREAM_ERROR,
        code: str | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.retryable = retryable
        # ``kind`` matches the other mailbox clients; ``code`` is retained as
        # an explicit API-facing alias for callers that use error_code fields.
        self.kind = str(kind or FASTMAIL_KIND_UPSTREAM_ERROR)
        self.code = str(code or self.kind)
        self.error_code = self.code
        self.session_expired = self.kind == FASTMAIL_KIND_SESSION_EXPIRED


@dataclass
class FastmailSession:
    api_url: str
    accounts: dict[str, dict[str, Any]]
    primary_accounts: dict[str, str]
    capabilities: dict[str, Any]
    token_fingerprint: str
    username: str = ""
    cookie_fingerprint: str = ""


@dataclass
class FastmailAccount:
    email: str
    # JMAP mail account used by Email/query and Email/get.
    account_id: str
    api_url: str
    # UserAlias uses the mail account; legacy customer Alias uses the
    # customer account. Keep the selected method with the lease so release
    # works even if account capabilities change after creation.
    alias_account_id: str | None = None
    alias_id: str | None = None
    alias_method: str = "Alias"
    created_at: float = field(default_factory=time.time)
    query_state: str | None = None
    known_message_ids: set[str] = field(default_factory=set, repr=False)


_LOCK = threading.RLock()
_CONTEXT_CACHE: dict[str, FastmailAccount] = {}
_LEASED_EMAILS: set[str] = set()
_SESSION_CACHE: FastmailSession | None = None
_SESSION_CACHE_EXPIRES = 0.0
_RUNTIME_COOKIE = ""
_SUDO_EXPIRES = 0.0
_CONFIGURED_COOKIE_FINGERPRINT = ""


def _cache_key(email: str) -> str:
    return str(email or "").strip().lower()


def _token() -> str:
    token = str(getattr(_email_cfg, "FASTMAIL_API_TOKEN", "") or "").strip()
    if not token:
        raise FastmailMailError(
            "Fastmail API Token 未配置，请在配置 → 邮箱 / OTP 填写 FASTMAIL_API_TOKEN。",
            retryable=False,
            kind=FASTMAIL_KIND_NOT_CONFIGURED,
        )
    return token


def _fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8", errors="replace")).hexdigest()[:16]


def _api_base() -> str:
    raw = str(getattr(_email_cfg, "FASTMAIL_API_BASE", DEFAULT_API_BASE) or DEFAULT_API_BASE).strip().rstrip("/")
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    return raw


def _session_url() -> str:
    raw = str(getattr(_email_cfg, "FASTMAIL_SESSION_URL", "") or "").strip()
    if raw:
        if re.match(r"^https?://", raw, re.IGNORECASE):
            return raw
        return _api_base() + (raw if raw.startswith("/") else "/" + raw)
    path = str(getattr(_email_cfg, "FASTMAIL_SESSION_PATH", DEFAULT_SESSION_PATH) or DEFAULT_SESSION_PATH).strip()
    if not path.startswith("/"):
        path = "/" + path
    return _api_base() + path


def _timeout() -> float:
    try:
        return max(3.0, float(getattr(_email_cfg, "FASTMAIL_REQUEST_TIMEOUT", 20) or 20))
    except (TypeError, ValueError):
        return 20.0


def _poll_interval(default: int | None = None) -> float:
    raw = default if default is not None else getattr(_email_cfg, "FASTMAIL_POLL_INTERVAL", None)
    if raw in (None, ""):
        raw = getattr(_email_cfg, "OTP_POLL_INTERVAL", 3)
    try:
        return max(1.0, float(raw or 3))
    except (TypeError, ValueError):
        return 3.0


def _headers(*, include_cookie: bool = True) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {_token()}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if include_cookie:
        cookie = _cookie_header()
        if cookie:
            headers["Cookie"] = cookie
    return headers


def _configured_cookie() -> str:
    return str(getattr(_email_cfg, "FASTMAIL_SESSION_COOKIE", "") or "").strip()


def _cookie_fingerprint(cookie: str | None = None) -> str:
    value = _configured_cookie() if cookie is None else str(cookie or "")
    return _fingerprint(value) if value else ""


def _sync_cookie_runtime_state() -> None:
    """Drop process-local sudo cookies when the configured Web cookie changes."""
    global _CONFIGURED_COOKIE_FINGERPRINT, _RUNTIME_COOKIE, _SUDO_EXPIRES
    fingerprint = _cookie_fingerprint()
    with _LOCK:
        if fingerprint == _CONFIGURED_COOKIE_FINGERPRINT:
            return
        _CONFIGURED_COOKIE_FINGERPRINT = fingerprint
        _RUNTIME_COOKIE = ""
        _SUDO_EXPIRES = 0.0


def _merge_cookie_headers(*values: str) -> str:
    """Merge Cookie header fragments by cookie name, keeping newest values."""
    merged: dict[str, str] = {}
    for raw in values:
        for part in str(raw or "").split(";"):
            if "=" not in part:
                continue
            name, value = part.strip().split("=", 1)
            if name.strip():
                merged[name.strip()] = value.strip()
    return "; ".join(f"{name}={value}" for name, value in merged.items())


def _cookie_header() -> str:
    _sync_cookie_runtime_state()
    return _merge_cookie_headers(_configured_cookie(), _RUNTIME_COOKIE)


def _sudo_password() -> str:
    return str(getattr(_email_cfg, "FASTMAIL_SUDO_PASSWORD", "") or "").strip()


def _sudo_url(api_url: str | None = None) -> str:
    raw = str(api_url or "").strip()
    if raw:
        parsed = urlparse(raw)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}/auth/sudo"
    return _api_base() + "/auth/sudo"


def _ensure_sudo() -> None:
    """Establish Fastmail's short-lived sudo session when configured.

    The fma Bearer token is cookie-bound. The password is sent only to
    Fastmail's documented two-step ``/auth/sudo`` flow and never logged or
    persisted. The returned sudo cookie remains process-local.
    """
    global _RUNTIME_COOKIE, _SUDO_EXPIRES
    password = _sudo_password()
    if not password:
        return
    cookie = _cookie_header()
    if not cookie:
        raise FastmailMailError(
            "Fastmail sudo 已配置密码，但缺少 FASTMAIL_SESSION_COOKIE",
            retryable=False,
            kind=FASTMAIL_KIND_NOT_CONFIGURED,
        )
    with _LOCK:
        if _SUDO_EXPIRES and time.monotonic() < _SUDO_EXPIRES - 5:
            return

    client = requests.Session()
    base_headers = {
        "Authorization": f"Bearer {_token()}",
        "Cookie": cookie,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Origin": "https://app.fastmail.com",
        "User-Agent": "Mozilla/5.0",
    }
    try:
        start = client.post(
            _api_base() + "/auth/sudo",
            headers=base_headers,
            json={"type": "start"},
            timeout=_timeout(),
        )
    except requests.RequestException as exc:
        raise FastmailMailError(
            f"Fastmail sudo 初始化失败: {exc}",
            kind=FASTMAIL_KIND_NETWORK,
        ) from exc
    if start.status_code >= 400:
        detail = _response_detail(start)
        kind = _auth_error_kind(int(start.status_code), detail, url=_api_base() + "/auth/sudo") if start.status_code in (401, 403) else (
            FASTMAIL_KIND_RATE_LIMITED
            if start.status_code == 429
            else FASTMAIL_KIND_UPSTREAM_ERROR
            if start.status_code >= 500
            else FASTMAIL_KIND_PROTOCOL_ERROR
        )
        if kind == FASTMAIL_KIND_SESSION_EXPIRED:
            _invalidate_auth_state()
        raise FastmailMailError(
            f"Fastmail sudo 初始化失败: HTTP {start.status_code}; {detail}",
            status=start.status_code,
            retryable=start.status_code >= 500,
            kind=kind,
        )
    start_payload = start.json() if start.content else {}
    login_id = str(start_payload.get("loginId") or "").strip()
    if not login_id:
        raise FastmailMailError(
            "Fastmail sudo 响应缺少 loginId",
            retryable=False,
            kind=FASTMAIL_KIND_PROTOCOL_ERROR,
        )
    next_url = str(start_payload.get("nextUrl") or "").strip() or _sudo_url()
    try:
        verified = client.post(
            next_url,
            headers={**base_headers, "Cookie": _merge_cookie_headers(cookie, _cookie_jar_header(client))},
            json={
                "type": "password",
                "value": password,
                "remember": False,
                "loginId": login_id,
            },
            timeout=_timeout(),
        )
    except requests.RequestException as exc:
        raise FastmailMailError(
            f"Fastmail sudo 验证失败: {exc}",
            kind=FASTMAIL_KIND_NETWORK,
        ) from exc
    if verified.status_code >= 400:
        detail = _response_detail(verified)
        kind = _auth_error_kind(int(verified.status_code), detail, url=next_url) if verified.status_code in (401, 403) else (
            FASTMAIL_KIND_RATE_LIMITED
            if verified.status_code == 429
            else FASTMAIL_KIND_UPSTREAM_ERROR
            if verified.status_code >= 500
            else FASTMAIL_KIND_PROTOCOL_ERROR
        )
        if kind == FASTMAIL_KIND_SESSION_EXPIRED:
            _invalidate_auth_state()
        raise FastmailMailError(
            f"Fastmail sudo 验证失败: HTTP {verified.status_code}; {detail}",
            status=verified.status_code,
            retryable=verified.status_code >= 500,
            kind=kind,
        )
    payload = verified.json() if verified.content else {}
    try:
        max_age = max(30, int(start_payload.get("maxAge") or 900))
    except (TypeError, ValueError):
        max_age = 900
    with _LOCK:
        _RUNTIME_COOKIE = _cookie_jar_header(client)
        _SUDO_EXPIRES = time.monotonic() + max_age
    logger.info("[Fastmail] sudo 会话已建立，有效期约 %ss", max_age)


def _cookie_jar_header(client: requests.Session) -> str:
    return "; ".join(f"{item.name}={item.value}" for item in client.cookies)


def _response_detail(response: requests.Response) -> str:
    try:
        payload = response.json()
        if isinstance(payload, dict):
            for key in ("description", "detail", "error", "message"):
                if payload.get(key):
                    return str(payload[key])[:240]
        return str(payload)[:240]
    except (ValueError, TypeError):
        return str(getattr(response, "text", "") or "")[:240]


def _invalidate_auth_state() -> None:
    """Forget cached authorization state after an upstream auth rejection."""
    global _SESSION_CACHE, _SESSION_CACHE_EXPIRES, _RUNTIME_COOKIE, _SUDO_EXPIRES
    with _LOCK:
        _SESSION_CACHE = None
        _SESSION_CACHE_EXPIRES = 0.0
        _RUNTIME_COOKIE = ""
        _SUDO_EXPIRES = 0.0


def _auth_error_kind(status: int, detail: str, *, url: str = "") -> str:
    """Classify an HTTP authorization response without exposing credentials."""
    text = f"{url} {detail}".lower()
    if status == 401:
        # Fastmail uses this wording when a previously valid bearer session was
        # revoked or expired. A password rejection is handled by the sudo flow.
        if any(marker in text for marker in ("password", "incorrect", "wrong password")):
            return FASTMAIL_KIND_BAD_CREDENTIALS
        return FASTMAIL_KIND_SESSION_EXPIRED
    if any(marker in text for marker in ("session", "cookie", "bearer", "login", "csrf")):
        return FASTMAIL_KIND_SESSION_EXPIRED
    return FASTMAIL_KIND_PERMISSION_DENIED


def _auth_error_message(kind: str, status: int, detail: str) -> str:
    if kind == FASTMAIL_KIND_SESSION_EXPIRED:
        hint = (
            "请在 Fastmail → Privacy & Security → Manage API tokens 重新生成 API Token；"
            "如果使用旧版 customer Alias，再同步更新 FASTMAIL_SESSION_COOKIE。"
        )
        return f"Fastmail API Token/会话已失效: HTTP {status}; {detail or '未返回详细原因'}。{hint}"
    if kind == FASTMAIL_KIND_BAD_CREDENTIALS:
        return f"Fastmail 凭证无效: HTTP {status}; {detail or '未返回详细原因'}"
    if kind == FASTMAIL_KIND_PERMISSION_DENIED:
        return f"Fastmail Token 权限不足: HTTP {status}; {detail or '未返回详细原因'}"
    return f"Fastmail 请求失败: HTTP {status}; {detail or '未返回详细原因'}"


def _http_json(
    method: str,
    url: str,
    payload: Any = None,
    *,
    include_cookie: bool = True,
) -> Any:
    response = None
    try:
        if method.upper() == "GET":
            response = requests.get(
                url,
                headers=_headers(include_cookie=include_cookie),
                timeout=_timeout(),
            )
        else:
            response = requests.post(
                url,
                json=payload,
                headers=_headers(include_cookie=include_cookie),
                timeout=_timeout(),
            )
    except requests.RequestException as exc:
        raise FastmailMailError(
            f"Fastmail 请求失败 ({method} {url}): {type(exc).__name__}: {exc}",
            kind=FASTMAIL_KIND_NETWORK,
        ) from exc
    try:
        status = int(response.status_code)
        if status in (401, 403):
            detail = _response_detail(response)
            kind = _auth_error_kind(status, detail, url=url)
            _invalidate_auth_state()
            raise FastmailMailError(
                _auth_error_message(kind, status, detail),
                status=status,
                retryable=False,
                kind=kind,
            )
        if status == 429 or status >= 500:
            kind = FASTMAIL_KIND_RATE_LIMITED if status == 429 else FASTMAIL_KIND_UPSTREAM_ERROR
            raise FastmailMailError(
                f"Fastmail 临时请求失败: HTTP {status}; {_response_detail(response)}",
                status=status,
                retryable=True,
                kind=kind,
            )
        if status >= 400:
            raise FastmailMailError(
                f"Fastmail 请求失败: HTTP {status}; {_response_detail(response)}",
                status=status,
                retryable=False,
                kind=FASTMAIL_KIND_PROTOCOL_ERROR,
            )
        try:
            return response.json()
        except (ValueError, TypeError) as exc:
            raise FastmailMailError(
                f"Fastmail 响应不是 JSON: HTTP {status}",
                retryable=False,
                kind=FASTMAIL_KIND_PROTOCOL_ERROR,
            ) from exc
    finally:
        try:
            response.close()
        except Exception:
            pass


def _session_from_payload(
    payload: Any,
    token: str,
    *,
    cookie_fingerprint: str | None = None,
) -> FastmailSession:
    if not isinstance(payload, dict):
        raise FastmailMailError(
            "Fastmail session 响应不是对象",
            retryable=False,
            kind=FASTMAIL_KIND_PROTOCOL_ERROR,
        )
    api_url = str(payload.get("apiUrl") or "").strip()
    if not api_url:
        raise FastmailMailError(
            "Fastmail session 缺少 apiUrl",
            retryable=False,
            kind=FASTMAIL_KIND_PROTOCOL_ERROR,
        )
    accounts = payload.get("accounts") if isinstance(payload.get("accounts"), dict) else {}
    primary = payload.get("primaryAccounts") if isinstance(payload.get("primaryAccounts"), dict) else {}
    capabilities = payload.get("capabilities") if isinstance(payload.get("capabilities"), dict) else {}
    username = str(payload.get("username") or "").strip()
    return FastmailSession(
        api_url=api_url,
        accounts={str(k): v for k, v in accounts.items() if isinstance(v, dict)},
        primary_accounts={str(k): str(v) for k, v in primary.items() if v},
        capabilities=capabilities,
        token_fingerprint=_fingerprint(token),
        username=username,
        cookie_fingerprint=(
            _cookie_fingerprint() if cookie_fingerprint is None else cookie_fingerprint
        ),
    )


def _get_session(*, force: bool = False) -> FastmailSession:
    global _SESSION_CACHE, _SESSION_CACHE_EXPIRES
    token = _token()
    fingerprint = _fingerprint(token)
    cookie_fingerprint = _cookie_fingerprint()
    with _LOCK:
        if (
            not force
            and _SESSION_CACHE is not None
            and _SESSION_CACHE.token_fingerprint == fingerprint
            and (
                not _SESSION_CACHE.cookie_fingerprint
                or _SESSION_CACHE.cookie_fingerprint == cookie_fingerprint
            )
            and time.monotonic() < _SESSION_CACHE_EXPIRES
        ):
            return _SESSION_CACHE
    used_cookie = False
    try:
        # The documented JMAP Session resource is bearer-token authenticated;
        # an old Web Cookie must not make a valid API token look expired.
        payload = _http_json("GET", _session_url(), include_cookie=False)
    except FastmailMailError as first_error:
        if not cookie_fingerprint or first_error.kind not in {
            FASTMAIL_KIND_SESSION_EXPIRED,
            FASTMAIL_KIND_BAD_CREDENTIALS,
        }:
            raise
        try:
            payload = _http_json("GET", _session_url(), include_cookie=True)
            used_cookie = True
        except FastmailMailError:
            # Preserve the first error because it describes the bearer token
            # that failed, while avoiding a second credential detail in logs.
            raise first_error
    session = _session_from_payload(
        payload,
        token,
        cookie_fingerprint=cookie_fingerprint if used_cookie else "",
    )
    with _LOCK:
        _SESSION_CACHE = session
        _SESSION_CACHE_EXPIRES = time.monotonic() + _CACHE_TTL_SECONDS
    logger.info(
        "[Fastmail] JMAP Session 已发现: api=%s accounts=%s customer=%s",
        session.api_url,
        len(session.accounts),
        CUSTOMER_CAPABILITY in session.primary_accounts,
    )
    return session


def check_session(*, force: bool = True, require_alias: bool = True) -> dict[str, Any]:
    """Validate the configured Fastmail credentials without creating an Alias.

    The result is deliberately limited to booleans and capability metadata so
    it can be returned by a local diagnostics endpoint without echoing a token
    or Cookie. ``force=True`` is the default for an explicit health check; the
    normal registration path can continue to use the short session cache.
    """
    try:
        session = _get_session(force=force)
        _account_for(session, MAIL_CAPABILITY)
        alias_method = ""
        has_customer_alias = False
        has_user_alias = False
        if require_alias:
            alias_account_id = _alias_account_for(session)
            has_user_alias = _user_alias_supported(session, alias_account_id)
            # Alias/getAvailability remains a customer capability even when
            # creation uses the newer UserAlias method.
            _customer_alias_account_for(session)
            has_customer_alias = True
            alias_method = "UserAlias" if has_user_alias else "Alias"
        return {
            "ok": True,
            "status": "ok",
            "kind": "ok",
            "code": "ok",
            "error_code": "ok",
            "mail_capability": True,
            "customer_alias_capability": has_customer_alias,
            "user_alias_capability": has_user_alias,
            "alias_method": alias_method,
            "cookie_configured": bool(_configured_cookie()),
        }
    except FastmailMailError as exc:
        return {
            "ok": False,
            "status": "error",
            "kind": exc.kind,
            "code": exc.code,
            "error_code": exc.error_code,
            "error": str(exc),
            "message": str(exc),
            "http_status": exc.status,
            "retryable": exc.retryable,
            "cookie_configured": bool(_configured_cookie()),
        }


def _session_uses_cookie(session: FastmailSession) -> bool:
    """Return whether this Session was obtained through the Cookie fallback."""
    return bool(session.cookie_fingerprint)


def _account_for(
    session: FastmailSession,
    capability: str,
    *,
    config_key: str = "FASTMAIL_ACCOUNT_ID",
) -> str:
    configured = str(getattr(_email_cfg, config_key, "") or "").strip()
    if configured:
        if configured not in session.accounts:
            raise FastmailMailError(
                f"Fastmail Session 未找到配置的账号 {configured}",
                retryable=False,
                kind=FASTMAIL_KIND_PERMISSION_DENIED,
            )
        account = session.accounts.get(configured) or {}
        account_caps = account.get("accountCapabilities") or {}
        primary_id = session.primary_accounts.get(capability)
        if capability not in account_caps and primary_id != configured:
            raise FastmailMailError(
                f"Fastmail 账号 {configured} 未授予 {capability}",
                retryable=False,
                kind=FASTMAIL_KIND_PERMISSION_DENIED,
            )
        return configured
    primary = session.primary_accounts.get(capability)
    if primary:
        return primary
    for account_id, account in session.accounts.items():
        caps = account.get("accountCapabilities") or {}
        if capability in caps:
            return account_id
    if capability == CUSTOMER_CAPABILITY:
        raise FastmailMailError(
            "当前 Fastmail API Token 不具备普通 Alias 管理权限："
            "JMAP Session 未提供 https://www.fastmail.com/dev/customer capability/accountId。",
            retryable=False,
            kind=FASTMAIL_KIND_PERMISSION_DENIED,
        )
    raise FastmailMailError(
        f"Fastmail Token/Session 未授予 {capability}，请重新生成包含所需权限的 API Token。",
        retryable=False,
        kind=FASTMAIL_KIND_PERMISSION_DENIED,
    )


def _user_alias_supported(session: FastmailSession, account_id: str) -> bool:
    account = session.accounts.get(account_id) or {}
    capabilities = account.get("accountCapabilities") or {}
    return USER_CAPABILITY in capabilities


def _user_alias_account_for(session: FastmailSession) -> str:
    configured = str(getattr(_email_cfg, "FASTMAIL_ACCOUNT_ID", "") or "").strip()
    if configured and configured in session.accounts and _user_alias_supported(session, configured):
        return configured
    primary = session.primary_accounts.get(MAIL_CAPABILITY)
    if primary and _user_alias_supported(session, primary):
        return primary
    for account_id in session.accounts:
        if _user_alias_supported(session, account_id):
            return account_id
    return ""


def _alias_account_for(session: FastmailSession) -> str:
    """Return the account used by Alias/UserAlias set/get operations."""
    configured = str(getattr(_email_cfg, "FASTMAIL_ALIAS_ACCOUNT_ID", "") or "").strip()
    if configured:
        if configured not in session.accounts:
            raise FastmailMailError(
                f"Fastmail Session 未找到配置的账号 {configured}",
                retryable=False,
                kind=FASTMAIL_KIND_PERMISSION_DENIED,
            )
        if _user_alias_supported(session, configured):
            return configured
        account = session.accounts.get(configured) or {}
        capabilities = account.get("accountCapabilities") or {}
        primary_customer = session.primary_accounts.get(CUSTOMER_CAPABILITY)
        if CUSTOMER_CAPABILITY in capabilities or primary_customer == configured:
            return configured
        raise FastmailMailError(
            f"Fastmail 账号 {configured} 未授予普通 Alias/UserAlias 权限",
            retryable=False,
            kind=FASTMAIL_KIND_PERMISSION_DENIED,
        )
    user_account = _user_alias_account_for(session)
    if user_account:
        return user_account
    return _account_for(
        session,
        CUSTOMER_CAPABILITY,
        config_key="FASTMAIL_ALIAS_ACCOUNT_ID",
    )


def _customer_alias_account_for(session: FastmailSession) -> str:
    """Return the customer account used by Alias availability/domain methods."""
    return _account_for(
        session,
        CUSTOMER_CAPABILITY,
        config_key="FASTMAIL_ALIAS_ACCOUNT_ID",
    )


def _jmap_call(
    session: FastmailSession,
    using: Iterable[str],
    method_calls: list[list[Any]],
    *,
    include_cookie: bool = True,
) -> dict[str, list[Any]]:
    payload = _http_json(
        "POST",
        session.api_url,
        {"using": list(using), "methodCalls": method_calls},
        include_cookie=include_cookie,
    )
    responses = payload.get("methodResponses") if isinstance(payload, dict) else None
    if not isinstance(responses, list):
        raise FastmailMailError(
            "Fastmail 响应缺少 methodResponses",
            retryable=False,
            kind=FASTMAIL_KIND_PROTOCOL_ERROR,
        )
    result: dict[str, list[Any]] = {}
    for item in responses:
        if not isinstance(item, list) or len(item) != 3:
            raise FastmailMailError(
                "Fastmail method response 格式无效",
                retryable=False,
                kind=FASTMAIL_KIND_PROTOCOL_ERROR,
            )
        name, arguments, tag = item
        if name == "error":
            args = arguments if isinstance(arguments, dict) else {"description": arguments}
            error_type = str(args.get("type") or "error")
            description = str(args.get("description") or args.get("detail") or "")
            lower_type = error_type.lower()
            lower_text = f"{error_type} {description}".lower()
            if lower_type in {"unauthorized", "notauthenticated", "authenticationfailed"}:
                error_kind = FASTMAIL_KIND_SESSION_EXPIRED
            elif lower_type in {"forbidden", "accountnotfound", "accountnotsupported"}:
                error_kind = FASTMAIL_KIND_PERMISSION_DENIED
            elif any(marker in lower_text for marker in ("session", "cookie", "bearer", "login")):
                error_kind = FASTMAIL_KIND_SESSION_EXPIRED
            elif lower_type == "ratelimit":
                error_kind = FASTMAIL_KIND_RATE_LIMITED
            elif lower_type in {"serverfail", "temporarilyunavailable"}:
                error_kind = FASTMAIL_KIND_UPSTREAM_ERROR
            else:
                error_kind = FASTMAIL_KIND_PROTOCOL_ERROR
            if error_kind == FASTMAIL_KIND_SESSION_EXPIRED:
                _invalidate_auth_state()
            raise FastmailMailError(
                f"Fastmail JMAP {error_type}: {description or args}",
                status=429 if error_type == "rateLimit" else None,
                retryable=error_type in {"rateLimit", "serverFail", "temporarilyUnavailable"},
                kind=error_kind,
            )
        if not isinstance(tag, str):
            raise FastmailMailError(
                "Fastmail method response 缺少 tag",
                retryable=False,
                kind=FASTMAIL_KIND_PROTOCOL_ERROR,
            )
        # Fastmail Alias/set with onSuccessUpdateIdentities appends an
        # Identity/set response using the same invocation tag. The primary
        # Alias/set result is first and must not be overwritten by that side
        # effect response.
        result.setdefault(tag, item)
    return result


def _method_args(result: dict[str, list[Any]], tag: str) -> dict[str, Any]:
    item = result.get(tag)
    if not item or len(item) != 3 or not isinstance(item[1], dict):
        raise FastmailMailError(
            f"Fastmail 缺少 {tag} 方法响应",
            retryable=False,
            kind=FASTMAIL_KIND_PROTOCOL_ERROR,
        )
    return item[1]


def _bool_config(name: str, default: bool) -> bool:
    raw = getattr(_email_cfg, name, default)
    return raw is True or str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _int_config(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(getattr(_email_cfg, name, default) or default)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _alias_domains() -> list[str]:
    raw = getattr(_email_cfg, "FASTMAIL_ALIAS_DOMAINS", None)
    if isinstance(raw, str):
        values = re.split(r"[,\s]+", raw)
    elif isinstance(raw, (list, tuple, set)):
        values = [str(item or "") for item in raw]
    else:
        values = []
    domains: list[str] = []
    for value in values:
        domain = str(value or "").strip().lower().lstrip("@")
        if not domain:
            continue
        if not _DOMAIN_RE.fullmatch(domain):
            raise FastmailMailError(
                f"FASTMAIL_ALIAS_DOMAINS 包含无效域名: {domain}",
                retryable=False,
                kind=FASTMAIL_KIND_NOT_CONFIGURED,
            )
        if domain not in domains:
            domains.append(domain)
    if not domains:
        raise FastmailMailError(
            "FASTMAIL_ALIAS_DOMAINS 未配置；请填写当前 Fastmail 账号可创建 Alias 的域名。",
            retryable=False,
            kind=FASTMAIL_KIND_NOT_CONFIGURED,
        )
    return domains


def _random_local_part() -> str:
    length = _int_config("FASTMAIL_ALIAS_LOCAL_LENGTH", 12, minimum=6, maximum=32)
    alphabet = string.ascii_lowercase + string.digits
    return secrets.choice(string.ascii_lowercase) + "".join(
        secrets.choice(alphabet) for _ in range(length - 1)
    )


def list_aliases(session: FastmailSession | None = None) -> list[dict[str, Any]]:
    """读取普通 Alias；主要用于发现目标邮箱和诊断 Token 权限。"""
    current = session or _get_session()
    alias_account_id = _alias_account_for(current)
    user_alias = _user_alias_supported(current, alias_account_id)
    result = _jmap_call(
        current,
        [CORE_CAPABILITY, USER_CAPABILITY if user_alias else CUSTOMER_CAPABILITY],
        [[
            "UserAlias/get" if user_alias else "Alias/get",
            {"accountId": alias_account_id, "ids": None},
            "aliases",
        ]],
        include_cookie=not user_alias or _session_uses_cookie(current),
    )
    values = _method_args(result, "aliases").get("list") or []
    return [item for item in values if isinstance(item, dict)]


def _alias_target_email(session: FastmailSession, mail_account_id: str) -> str:
    configured = str(getattr(_email_cfg, "FASTMAIL_ALIAS_TARGET_EMAIL", "") or "").strip()
    candidates = [configured, session.username]
    mail_account = session.accounts.get(mail_account_id) or {}
    candidates.append(str(mail_account.get("name") or "").strip())
    for candidate in candidates:
        if candidate and _EMAIL_RE.fullmatch(candidate):
            return candidate

    # Some OAuth sessions omit username/account name. Existing Alias targets
    # still reveal the mailbox that receives forwarded mail.
    for item in list_aliases(session):
        for candidate in item.get("targetEmails") or []:
            target = str(candidate or "").strip()
            if _EMAIL_RE.fullmatch(target):
                return target
    raise FastmailMailError(
        "Fastmail Session 未发现 Alias 目标邮箱；请配置 FASTMAIL_ALIAS_TARGET_EMAIL。",
        retryable=False,
        kind=FASTMAIL_KIND_NOT_CONFIGURED,
    )


def _alias_is_available(
    session: FastmailSession,
    alias_account_id: str,
    email: str,
) -> bool:
    availability_account_id = _customer_alias_account_for(session)
    user_alias = _user_alias_supported(session, alias_account_id)
    result = _jmap_call(
        session,
        [CORE_CAPABILITY, CUSTOMER_CAPABILITY],
        [[
            "Alias/getAvailability",
            {"accountId": availability_account_id, "email": email},
            "availability",
        ]],
        include_cookie=not user_alias or _session_uses_cookie(session),
    )
    args = _method_args(result, "availability")
    return args.get("isAvailable") is True


def _create_alias(session: FastmailSession) -> FastmailAccount:
    mail_account_id = _account_for(session, MAIL_CAPABILITY)
    alias_account_id = _alias_account_for(session)
    user_alias = _user_alias_supported(session, alias_account_id)
    target_email = _alias_target_email(session, mail_account_id) if not user_alias else ""
    domains = _alias_domains()
    attempts = _int_config("FASTMAIL_ALIAS_CREATE_ATTEMPTS", 10, minimum=1, maximum=50)
    description = str(
        getattr(_email_cfg, "FASTMAIL_ALIAS_DESCRIPTION", "ChatGPT registration") or ""
    ).strip()
    update_identities = _bool_config("FASTMAIL_ALIAS_UPDATE_IDENTITIES", True)

    for attempt in range(1, attempts + 1):
        domain = domains[(attempt - 1) % len(domains)]
        email = f"{_random_local_part()}@{domain}"
        if not _alias_is_available(session, alias_account_id, email):
            continue
        create_id = "newAlias"
        create_values: dict[str, Any] = {"email": email}
        if user_alias:
            create_values.update({
                "restrictSendingTo": "everybody",
                "isShared": False,
                "description": description,
            })
        else:
            create_values.update({
                "targetEmails": [target_email],
                "targetGroupRef": None,
                "restrictSendingTo": "everybody",
                "description": description,
            })
        result = _jmap_call(
            session,
            [
                CORE_CAPABILITY,
                USER_CAPABILITY if user_alias else CUSTOMER_CAPABILITY,
                *([SUBMISSION_CAPABILITY] if update_identities else []),
            ],
            [[
                "UserAlias/set" if user_alias else "Alias/set",
                {
                    "accountId": alias_account_id,
                    "create": {
                        create_id: create_values,
                    },
                    "onSuccessUpdateIdentities": update_identities,
                },
                "create",
            ]],
            include_cookie=not user_alias or _session_uses_cookie(session),
        )
        args = _method_args(result, "create")
        created = args.get("created") if isinstance(args.get("created"), dict) else {}
        item = created.get(create_id) if isinstance(created, dict) else None
        if isinstance(item, dict) and str(item.get("id") or "").strip():
            return FastmailAccount(
                email=email,
                account_id=mail_account_id,
                api_url=session.api_url,
                alias_account_id=alias_account_id,
                alias_id=str(item["id"]).strip(),
                alias_method="UserAlias" if user_alias else "Alias",
            )
        not_created = args.get("notCreated") if isinstance(args.get("notCreated"), dict) else {}
        detail = not_created.get(create_id) if isinstance(not_created, dict) else None
        error_type = str(detail.get("type") or "") if isinstance(detail, dict) else ""
        if error_type in {"alreadyExists", "invalidProperties"}:
            continue
        raise FastmailMailError(
            f"Fastmail 普通 Alias 创建失败: {detail or args}",
            retryable=error_type in {"rateLimit", "serverFail", "temporarilyUnavailable"},
            kind=(
                FASTMAIL_KIND_RATE_LIMITED
                if error_type == "rateLimit"
                else FASTMAIL_KIND_UPSTREAM_ERROR
                if error_type in {"serverFail", "temporarilyUnavailable"}
                else FASTMAIL_KIND_PROTOCOL_ERROR
            ),
        )
    raise FastmailMailError(
        f"Fastmail 普通 Alias 连续 {attempts} 次未找到可用地址",
        retryable=True,
        kind=FASTMAIL_KIND_RATE_LIMITED,
    )


def pick_account() -> FastmailAccount:
    """仅使用 Token 创建一个 Fastmail 普通 Alias，不读取本地邮箱池。"""
    session = _get_session()
    account = _create_alias(session)
    key = _cache_key(account.email)
    with _LOCK:
        if key in _LEASED_EMAILS:
            raise FastmailMailError(
                f"Fastmail 地址已被当前进程租用: {account.email}",
                retryable=False,
                kind=FASTMAIL_KIND_PROTOCOL_ERROR,
            )
        _CONTEXT_CACHE[key] = account
        _LEASED_EMAILS.add(key)
    logger.info(
        "[Fastmail] 已创建普通 Alias: %s alias_id=%s",
        account.email,
        account.alias_id or "-",
    )
    return account


def get_account_context(email: str) -> FastmailAccount | None:
    return _CONTEXT_CACHE.get(_cache_key(email))


def _delete_alias(account: FastmailAccount) -> None:
    if not account.alias_id or not account.alias_account_id:
        return
    try:
        _ensure_sudo()
        session = _get_session()
        user_alias = account.alias_method == "UserAlias"
        alias_capability = USER_CAPABILITY if user_alias else CUSTOMER_CAPABILITY
        if user_alias:
            # UserAlias is owned by the user's mail account. The Web flow
            # removes it with a hard destroy; unlike customer Alias/set,
            # clearing targetEmails is not a valid UserAlias update.
            method_name = "UserAlias/set"
            method_args: dict[str, Any] = {
                "accountId": account.alias_account_id,
                "destroy": [account.alias_id],
                "onSuccessUpdateIdentities": _bool_config(
                    "FASTMAIL_ALIAS_UPDATE_IDENTITIES", True
                ),
            }
        else:
            method_name = "Alias/set"
            method_args = {
                "accountId": account.alias_account_id,
                # Fastmail Web's "remove address" flow disables the
                # Alias by clearing targetEmails. A hard JMAP destroy
                # returns forbidden/needsSudo even after the web flow
                # has established sudo, and does not clean its Identity.
                "update": {account.alias_id: {"targetEmails": None}},
                "onSuccessUpdateIdentities": _bool_config(
                    "FASTMAIL_ALIAS_UPDATE_IDENTITIES", True
                ),
            }
        result = _jmap_call(
            session,
            [
                CORE_CAPABILITY,
                alias_capability,
                *(
                    [SUBMISSION_CAPABILITY]
                    if _bool_config("FASTMAIL_ALIAS_UPDATE_IDENTITIES", True)
                    else []
                ),
            ],
            [[
                method_name,
                method_args,
                "delete",
            ]],
            include_cookie=not user_alias or _session_uses_cookie(session),
        )
        args = _method_args(result, "delete")
        completed = (
            account.alias_id in (args.get("destroyed") or {})
            if user_alias
            else account.alias_id in (args.get("updated") or {})
        )
        if not completed:
            error_key = "notDestroyed" if user_alias else "notUpdated"
            errors = args.get(error_key) or {}
            detail = errors.get(account.alias_id) if isinstance(errors, dict) else None
            raise FastmailMailError(
                f"Fastmail 普通 Alias 回收未完成: {account.email}; "
                f"{detail or args}",
                retryable=False,
            )
        logger.info(
            "[Fastmail] 已%s未使用普通 Alias%s: %s",
            "删除" if user_alias else "停用",
            "并清理 Identity" if _bool_config("FASTMAIL_ALIAS_UPDATE_IDENTITIES", True) else "",
            account.email,
        )
    except Exception as exc:
        logger.warning("[Fastmail] 删除未使用普通 Alias 失败: %s (%s)", account.email, exc)


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    """失败/未消耗任务删除 alias；成功地址保留给后续 Codex 邮件。"""
    key = _cache_key(email)
    with _LOCK:
        account = _CONTEXT_CACHE.pop(key, None)
        _LEASED_EMAILS.discard(key)
    normalized = str(status or "").strip().lower()
    if account and normalized not in {"registered", "used", "success", "completed"}:
        _delete_alias(account)
    logger.info("[Fastmail] 已释放任务上下文: %s status=%s note=%s", email, status, note or "")


def _timestamp(value: Any) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    raw = str(value).strip()
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        pass
    try:
        parsed = parsedate_to_datetime(raw)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _address_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, dict):
            address = str(item.get("email") or item.get("address") or "").strip()
            name = str(item.get("name") or "").strip()
            out.append(f"{name} <{address}>" if name and address else address)
        elif str(item or "").strip():
            out.append(str(item).strip())
    return out


def _body_values(message: dict[str, Any]) -> tuple[str, str]:
    values = message.get("bodyValues") if isinstance(message.get("bodyValues"), dict) else {}
    text_ids = [
        str(item.get("partId") or "")
        for item in (message.get("textBody") or [])
        if isinstance(item, dict) and item.get("partId")
    ]
    html_ids = [
        str(item.get("partId") or "")
        for item in (message.get("htmlBody") or [])
        if isinstance(item, dict) and item.get("partId")
    ]

    def collect(ids: list[str]) -> str:
        chunks: list[str] = []
        for part_id in ids:
            item = values.get(part_id)
            if isinstance(item, dict) and item.get("value") is not None:
                chunks.append(str(item.get("value") or ""))
        return "\n".join(chunks)

    text = collect(text_ids)
    html = collect(html_ids)
    if not text and not html:
        preview = str(message.get("preview") or "")
        text = preview
    return text, html


def _message_item(message: dict[str, Any]) -> dict[str, Any]:
    text, html = _body_values(message)
    sender = _address_values(message.get("from"))
    to = _address_values(message.get("to"))
    cc = _address_values(message.get("cc"))
    return {
        "id": message.get("id"),
        "receivedAt": message.get("receivedAt"),
        "from": ", ".join(sender),
        "to": ", ".join(to),
        "cc": ", ".join(cc),
        "deliveredTo": " ".join(
            str(message.get(key) or "").strip()
            for key in (
                "deliveredTo",
                "header:Fastmail-MaskedEmail:asText",
                "header:x-original-delivered-to:asText",
            )
            if str(message.get(key) or "").strip()
        ),
        "subject": str(message.get("subject") or ""),
        "preview": str(message.get("preview") or ""),
        "text": text,
        "html": html,
    }


def _message_properties() -> list[str]:
    return [
        "id", "receivedAt", "from", "to", "cc", "bcc", "subject", "preview",
        "textBody", "htmlBody", "bodyValues", "mailboxIds",
        # Some forwarding paths do not preserve the parsed To field.
        "header:Fastmail-MaskedEmail:asText",
        "header:x-original-delivered-to:asText",
    ]


def _initial_messages(session: FastmailSession, account: FastmailAccount) -> list[dict[str, Any]]:
    account_id = account.account_id or _account_for(session, MAIL_CAPABILITY)
    calls = [
        [
            "Email/query",
            {
                "accountId": account_id,
                "filter": {"to": account.email},
                "sort": [{"property": "receivedAt", "isAscending": False}],
                "limit": max(1, int(getattr(_email_cfg, "FASTMAIL_MESSAGE_LIMIT", _DEFAULT_MESSAGE_LIMIT) or _DEFAULT_MESSAGE_LIMIT)),
            },
            "query",
        ],
        [
            "Email/get",
            {
                "accountId": account_id,
                "properties": _message_properties(),
                "bodyProperties": _BODY_PROPERTIES,
                "fetchTextBodyValues": True,
                "fetchHTMLBodyValues": True,
                "#ids": {"resultOf": "query", "name": "Email/query", "path": "/ids/*"},
            },
            "get",
        ],
    ]
    result = _jmap_call(
        session,
        [CORE_CAPABILITY, MAIL_CAPABILITY],
        calls,
        include_cookie=_session_uses_cookie(session),
    )
    query_args = _method_args(result, "query")
    account.query_state = str(query_args.get("queryState") or "") or None
    messages = _method_args(result, "get").get("list") or []
    account.known_message_ids.update(
        str(item.get("id")) for item in messages if isinstance(item, dict) and item.get("id")
    )
    return [item for item in messages if isinstance(item, dict)]


def _changed_messages(session: FastmailSession, account: FastmailAccount) -> list[dict[str, Any]]:
    if not account.query_state:
        return _initial_messages(session, account)
    account_id = account.account_id or _account_for(session, MAIL_CAPABILITY)
    calls = [
        [
            "Email/queryChanges",
            {
                "accountId": account_id,
                "filter": {"to": account.email},
                "sort": [{"property": "receivedAt", "isAscending": False}],
                "sinceQueryState": account.query_state,
                "maxChanges": max(20, int(getattr(_email_cfg, "FASTMAIL_MESSAGE_LIMIT", _DEFAULT_MESSAGE_LIMIT) or _DEFAULT_MESSAGE_LIMIT) * 3),
            },
            "changes",
        ],
        [
            "Email/get",
            {
                "accountId": account_id,
                "properties": _message_properties(),
                "bodyProperties": _BODY_PROPERTIES,
                "fetchTextBodyValues": True,
                "fetchHTMLBodyValues": True,
                # Email/queryChanges returns [{"id": ..., "index": ...}], so
                # the back-reference must select each object's id member.
                "#ids": {"resultOf": "changes", "name": "Email/queryChanges", "path": "/added/*/id"},
            },
            "get",
        ],
    ]
    try:
        result = _jmap_call(
            session,
            [CORE_CAPABILITY, MAIL_CAPABILITY],
            calls,
            include_cookie=_session_uses_cookie(session),
        )
    except FastmailMailError as exc:
        # queryState 过期/服务器重启时，完整查询一次即可恢复增量同步。
        if any(marker in str(exc).lower() for marker in ("cannotcalculatechanges", "query state", "invalidarguments")):
            account.query_state = None
            account.known_message_ids.clear()
            return _initial_messages(session, account)
        raise
    changes = _method_args(result, "changes")
    account.query_state = str(changes.get("newQueryState") or account.query_state) or None
    messages = _method_args(result, "get").get("list") or []
    out = []
    for item in messages:
        if not isinstance(item, dict):
            continue
        message_id = str(item.get("id") or "")
        if message_id and message_id not in account.known_message_ids:
            account.known_message_ids.add(message_id)
            out.append(item)
    return out


def _recipient_matches(item: dict[str, Any], target: str) -> bool:
    target = target.casefold()
    recipients = " ".join(
        str(item.get(key) or "") for key in ("to", "cc", "bcc", "deliveredTo")
    ).casefold()
    if not recipients:
        return True
    return target in recipients


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
    exclude_codes: set[str] | None = None,
) -> str:
    """通过 Email/queryChanges 增量轮询 Fastmail，返回最新 OpenAI 六位验证码。"""
    target = str(email or "").strip()
    if not target:
        raise FastmailMailError(
            "Fastmail 取码缺少邮箱地址",
            retryable=False,
            kind=FASTMAIL_KIND_NOT_CONFIGURED,
        )
    wait_seconds = int(max_wait if max_wait is not None else getattr(_email_cfg, "OTP_MAX_WAIT", 90) or 90)
    interval = _poll_interval(poll_interval)
    settle = max(0, int(settle_seconds if settle_seconds is not None else getattr(_email_cfg, "OTP_SETTLE_SECONDS", 5) or 5))
    deadline = time.monotonic() + max(0, wait_seconds)
    excluded = {str(code or "").strip() for code in (exclude_codes or set()) if str(code or "").strip()}
    session = _get_session()
    with _LOCK:
        account = _CONTEXT_CACHE.get(_cache_key(target))
    if account is None:
        account = FastmailAccount(
            email=target,
            account_id=_account_for(session, MAIL_CAPABILITY),
            api_url=session.api_url,
        )
    best_otp: str | None = None
    best_timestamp = float("-inf")
    settle_until: float | None = None
    last_error = "收件箱为空或尚未出现新的 OpenAI 验证码"
    logger.info("[Fastmail] 开始增量轮询: email=%s 最长=%ss", target, wait_seconds)

    while time.monotonic() <= deadline:
        check_stop_requested(target)
        try:
            messages = _changed_messages(session, account)
            for raw in sorted(messages, key=lambda row: _timestamp(row.get("receivedAt")) or float("-inf"), reverse=True):
                item = _message_item(raw)
                message_time = _timestamp(item.get("receivedAt"))
                if after_ts is not None and message_time is not None and message_time < float(after_ts) - 30:
                    continue
                if not _recipient_matches(item, target):
                    continue
                if not looks_like_openai_email(item):
                    continue
                otp = extract_otp(item)
                if not otp:
                    continue
                if otp in excluded and (not after_ts or message_time is None or message_time < float(after_ts)):
                    last_error = "最新邮件仍是已提交过的旧验证码"
                    break
                candidate_time = float("-inf") if message_time is None else message_time
                if best_otp is None or candidate_time > best_timestamp or (candidate_time == best_timestamp and otp != best_otp):
                    best_otp = otp
                    best_timestamp = candidate_time
                    settle_until = time.monotonic() + settle
                    logger.info("[Fastmail] 锁定 OTP 候选，等待 %ss 确认", settle)
        except FastmailMailError as exc:
            if not exc.retryable:
                raise
            last_error = str(exc)
        check_stop_requested(target)
        if best_otp and settle_until is not None and time.monotonic() >= settle_until:
            return best_otp
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sleep_with_stop(target, min(interval, remaining))

    if best_otp:
        check_stop_requested(target)
        return best_otp
    raise FastmailMailError(
        f"等待 Fastmail 验证码超时: {target}; {last_error}",
        kind=FASTMAIL_KIND_UPSTREAM_ERROR,
    )


def reset_runtime_state() -> None:
    """测试/热更新使用：清除 Token 相关内存状态，不触碰邮箱池。"""
    global _SESSION_CACHE, _SESSION_CACHE_EXPIRES, _RUNTIME_COOKIE
    global _SUDO_EXPIRES, _CONFIGURED_COOKIE_FINGERPRINT
    with _LOCK:
        _CONTEXT_CACHE.clear()
        _LEASED_EMAILS.clear()
        _SESSION_CACHE = None
        _SESSION_CACHE_EXPIRES = 0.0
        _RUNTIME_COOKIE = ""
        _SUDO_EXPIRES = 0.0
        _CONFIGURED_COOKIE_FINGERPRINT = ""
