# -*- coding: utf-8 -*-
"""
注册成功后的 Codex OAuth 授权模块（2026-06-15 改造：全新 session + 接码）。

旧方案"复用注册的已登录 session"会撞 /choose-an-account 卡死（React SPA 解析不出
可提交字段）。新方案改为用**全新干净 session**从头登录，走 OpenAI 标准风控路径，
手机号验证靠接码平台自动收码，当前通过 core.sms_provider 支持 GrizzlySMS 和 L_API.md
定义的本地 L 取号服务。

完整接口链（2026-06-15 浏览器抓包确认，均 POST auth.openai.com，json）：
    1. 提交邮箱   /api/accounts/authorize/continue  {"username":{"kind":"email","value":邮箱}}  带 sentinel(authorize_continue)
    2. 验邮箱码   /api/accounts/email-otp/validate   {"code":"xxx"}                            带 sentinel(email_otp_validate)
    3. 如遇 TOTP   /api/accounts/mfa/verify           {"id":"<factor>","type":"totp","code":"xxx"}
    4. 提交手机号 /api/accounts/add-phone/send       {"phone_number":"+1xxx"}                    无需 sentinel
    5. 验手机码   /api/accounts/phone-otp/validate   {"code":"xxx"}                            无需 sentinel
    6. 选 workspace /api/accounts/workspace/select   {"workspace_id":"<uuid>"}                  无需 sentinel
       workspace_id 从 oai-client-auth-session cookie（base64 解码）的 workspaces[0].id 取
    7. → 重定向 localhost:1455/auth/callback?code=ac_...，从 Location 抠 code

拿到 code 后换 token / 落盘的逻辑（exchange_codex_token / build_codex_storage /
save_codex_credential）沿用旧实现，未改动。
"""
import base64
import hashlib
import inspect
import json
import logging
import random
import re
import secrets
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs, quote, unquote, urljoin

# 用模块属性方式访问 config，支持 WebUI 热加载（config.reload_all()）。
# 协议级常量（CLIENT_ID/URL/SCOPE/OUTPUT_DIRNAME）虽然不会改，统一从 _cfg 读，
# 这样 reload 后立即生效，不用再分两套导入。
from config import codex as _cfg
from config import openai_protocol as _protocol_cfg
from core.session import BrowserSession
from core.humanize import delay as human_delay
from core.openai_auth import (
    _is_transient_network_error,
    _is_broken_proxy_session_error,
    _extract_error_code,
    detect_account_unusable_response_body,
    AccountUnusableError,
    request_sentinel_token,
    build_sentinel_header,
    network_preflight,
    send_email_otp,
)
from core.protocol_rate_limit import rotate_sticky_proxy_session
from core import sms_provider, totp_service
from curl_cffi import requests as curl_requests

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 跟重定向链时的最大跳数，防死循环
_MAX_REDIRECTS = 15

# Auth Web 在不同版本/域策略下使用的会话 Cookie 名称。
_AUTH_SESSION_COOKIE_NAMES = (
    "oai-client-auth-session",
    "__Secure-oai-client-auth-session",
    "oai-client-auth-session-token",
    "__Secure-oai-client-auth-session-token",
)

# 网络层临时性错误（代理抖动 / TLS 握手失败 / 重置）重试参数，对齐 openai_auth.follow_authorize
_NET_MAX_ATTEMPTS = 3
_NET_BACKOFF_BASE = 2.0


class CodexAuthResponseError(RuntimeError):
    """Preserve HTTP evidence without requiring callers to parse error text."""
    def __init__(self, message: str, *, http_status: int, error_code: str = ""):
        super().__init__(message)
        self.http_status = http_status
        self.error_code = error_code


def _with_net_retry(label: str, fn):
    """
    对临时性网络错误（TLS/代理/超时/重置）做重试包装。
    非临时错误（业务 4xx 等）直接抛。最多 _NET_MAX_ATTEMPTS 次。
    """
    last_exc = None
    for attempt in range(1, _NET_MAX_ATTEMPTS + 1):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if _is_broken_proxy_session_error(exc) or not _is_transient_network_error(exc):
                raise
            if attempt >= _NET_MAX_ATTEMPTS:
                break
            backoff = _NET_BACKOFF_BASE ** (attempt - 1)
            logger.warning(
                f"[Codex] {label} 临时性网络错误 ({type(exc).__name__}: {str(exc)[:120]})，"
                f"{backoff:.1f}s 后重试 (尝试 {attempt}/{_NET_MAX_ATTEMPTS})..."
            )
            time.sleep(backoff)
    raise last_exc if last_exc else RuntimeError(f"[Codex] {label} 重试耗尽但无异常记录")


def _check_codex_flow_stop(email: str) -> None:
    """同时响应注册任务和账号页 Codex 补跑的停止信号。"""
    try:
        from core.registration_service import check_stop_requested
        check_stop_requested()
    except ImportError:
        pass
    try:
        from core.codex_retry_service import check_stop_requested
        check_stop_requested(email)
    except ImportError:
        pass


def _sleep_codex_retry(seconds: float, email: str) -> None:
    """可中断的整轮重试退避。"""
    deadline = time.monotonic() + max(0.0, float(seconds or 0.0))
    while True:
        _check_codex_flow_stop(email)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.5, remaining))


def _mask_proxy(proxy: str | None) -> str:
    text = str(proxy or "").strip()
    if not text:
        return "direct"
    entry_id = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:8]
    try:
        parsed = urlparse(text)
        host = parsed.hostname or "unknown"
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme or 'proxy'}://***:***@{host}{port} entry={entry_id}"
    except (TypeError, ValueError):
        return f"proxy://configured entry={entry_id}"


def _configured_codex_proxies() -> list[str]:
    """热读取并规范化代理池，去重但保留配置顺序。"""
    try:
        from config import proxy as proxy_cfg
        candidates = [
            proxy_cfg.normalize_proxy_url(item)
            for item in list(getattr(proxy_cfg, "PROXY_POOL", []) or [])
        ]
    except Exception:
        return []
    return list(dict.fromkeys(item for item in candidates if item))


def _initial_codex_proxy(proxy: str | None) -> str:
    """把 None（自动代理池）解析成当前整轮可追踪的明确代理值。"""
    if proxy is not None:
        return str(proxy or "").strip()
    candidates = _configured_codex_proxies()
    return random.choice(candidates) if candidates else ""


def _next_codex_proxy(
    *,
    requested_proxy: str | None,
    current_proxy: str,
    attempted_proxies: set[str],
) -> str:
    """选择下一轮出口；直连不切代理，显式代理只轮换其 sticky session。"""
    if not bool(getattr(_cfg, "CODEX_ROTATE_PROXY_ON_RETRY", True)):
        return current_proxy
    if requested_proxy == "":
        return ""

    if requested_proxy is None:
        available = [item for item in _configured_codex_proxies() if item not in attempted_proxies]
        if available:
            return random.choice(available)

    rotated = rotate_sticky_proxy_session(current_proxy)
    if rotated and rotated != current_proxy:
        return rotated
    return current_proxy


def _oauth_failure_retry_reason(result: dict) -> str:
    """只对会话/出口故障整轮重跑，邮箱和接码平台错误留在各自重试层。"""
    if not isinstance(result, dict) or result.get("ok") or result.get("status") != "failed":
        return ""
    stage = str(result.get("failure_stage") or "").strip().lower()
    text = str(result.get("message") or "").strip().lower()
    if stage in {"email_otp_wait", "sms_budget"}:
        return ""
    if any(marker in text for marker in ("用户手动停止", "stopped", "cancelled")):
        return ""
    if _is_cpa_callback_reauth_error(text):
        return "cpa_callback_session"
    if (
        stage in {"bootstrap", "email_submit", "email_otp_submit", "mfa", "phone", "workspace"}
        and _is_oauth_session_invalid_response(text)
    ):
        return "oauth_session_invalid"
    if "status=409" in text or "http 409" in text:
        if any(marker in text for marker in ("session", "no longer valid", "expired")) or stage in {
            "bootstrap", "email_submit", "email_otp_submit", "mfa", "phone", "workspace",
        }:
            return "oauth_session_invalid"
    if ("status=403" in text or "http 403" in text) and stage in {
        "network_preflight", "bootstrap", "email_submit", "email_otp_submit", "mfa", "phone", "workspace",
    }:
        return "edge_rejected"
    if re.search(r"(?:status[=:]|http)\s*(?:429|5\d\d)\b", text):
        return "upstream_http"
    if _is_transient_network_error(RuntimeError(text)):
        return "network"
    return ""


def _email_otp_error_allows_resend(exc: Exception) -> bool:
    """邮箱接口自身故障时不重复触发 OTP；无邮件/超时才允许重发。"""
    if getattr(exc, "resend_recommended", True) is False:
        return False
    text = f"{type(exc).__name__}: {exc}".lower()
    if re.search(r"http\s*(?:401|403|429|5\d\d)\b", text):
        return False
    if any(marker in text for marker in (
        "bad gateway",
        "cloudflare 5xx",
        "invalid pickup credentials",
        "unauthorized",
        "forbidden",
    )):
        return False
    if _is_transient_network_error(RuntimeError(text)):
        return False
    return True


def _read_email_otp(otp_provider, email: str, *, after_ts: float, rejected_codes: set[str]) -> str:
    kwargs = {"after_ts": after_ts}
    if rejected_codes:
        # Custom integrations may still implement only the documented two-argument callback.
        exclusions = set(rejected_codes)
        try:
            inspect.signature(otp_provider).bind(email, **kwargs, exclude_codes=exclusions)
        except (TypeError, ValueError):
            pass
        else:
            kwargs["exclude_codes"] = exclusions
    return str(otp_provider(email, **kwargs) or "").strip()


def _codex_result(
    *,
    status: str,
    ok: bool = False,
    http_status: int | None = None,
    email: str | None = None,
    file_path: str | None = None,
    callback_url: str | None = None,
    message: str = "",
    **extra,
) -> dict:
    """构造与 flow_trigger._flow_result 同形态的结构化结果。"""
    result = {
        "status": status,
        "ok": ok,
        "http_status": http_status,
        "email": email,
        "file_path": file_path,
        "callback_url": callback_url,
        "message": message,
    }
    result.update(extra)
    return result


# ============================================================
# PKCE / state（对照 CLIProxyAPI pkce.go）
# ============================================================

def _generate_pkce() -> tuple[str, str]:
    """生成 PKCE 代码对：verifier=base64url(96字节)，challenge=base64url(sha256(verifier))。"""
    verifier_bytes = secrets.token_bytes(96)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _generate_state() -> str:
    """生成 OAuth state 随机串，防 CSRF。"""
    return secrets.token_urlsafe(32)


def _build_authorize_url(state: str, code_challenge: str, prompt: str = "login") -> str:
    """按 CLIProxyAPI openai_auth.go 的参数集拼 Codex 授权 URL。"""
    params = {
        "client_id": _cfg.CODEX_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": _cfg.CODEX_REDIRECT_URI,
        "scope": _cfg.CODEX_SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": prompt,
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    return f"{_cfg.CODEX_AUTH_URL}?{urlencode(params)}"


def _ensure_oai_context_url(auth_url: str, session: BrowserSession) -> str:
    """在 Codex OAuth 授权 URL 上补齐前端同源上下文参数，保持 oai-did 连续。"""
    try:
        parsed = urlparse(auth_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        changed = False
        additions = {
            "ext-oai-did": session.device_id,
            "auth_session_logging_id": session.auth_session_logging_id,
            "screen_hint": "login_or_signup",
        }
        for key, value in additions.items():
            if not params.get(key):
                params[key] = [value]
                changed = True
        if not changed:
            return auth_url
        query = urlencode(params, doseq=True)
        return parsed._replace(query=query).geturl()
    except Exception:
        return auth_url


# ============================================================
# CPA 管理接口：授权地址由 CPA 生成，成功回调提交给 CPA
# ============================================================

def _codex_auth_url_source() -> str:
    return str(getattr(_cfg, "CODEX_AUTH_URL_SOURCE", "cpa") or "cpa").strip().lower()


def _cpa_management_origin() -> str:
    raw = str(getattr(_cfg, "CPA_MANAGEMENT_URL", "") or "").strip()
    if not raw:
        raise RuntimeError("[Codex][CPA] 尚未配置 CPA_MANAGEMENT_URL")
    try:
        parsed = urlparse(raw)
    except Exception as exc:
        raise RuntimeError(f"[Codex][CPA] CPA_MANAGEMENT_URL 格式无效: {raw}") from exc
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RuntimeError(f"[Codex][CPA] CPA_MANAGEMENT_URL 格式无效: {raw}")
    return f"{parsed.scheme}://{parsed.netloc}"


def _cpa_management_key() -> str:
    key = str(getattr(_cfg, "CPA_MANAGEMENT_KEY", "") or "").strip()
    if not key:
        raise RuntimeError("[Codex][CPA] 尚未配置 CPA_MANAGEMENT_KEY")
    return key


def _cpa_request_json(method: str, path: str, body: dict | None = None) -> dict:
    """调用 CPA 管理接口，兼容 FlowPilot 的 /v0/management/* 协议。"""
    origin = _cpa_management_origin()
    key = _cpa_management_key()
    timeout = int(getattr(_cfg, "CPA_REQUEST_TIMEOUT", 30) or 30)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
        "X-Management-Key": key,
    }
    url = f"{origin}{path}"
    session = curl_requests.Session()
    try:
        resp = session.request(
            method.upper(),
            url,
            headers=headers,
            data=None if body is None else json.dumps(body),
            timeout=timeout,
        )
        try:
            payload = resp.json()
        except Exception:
            payload = {}
        if resp.status_code < 200 or resp.status_code >= 300:
            msg = ""
            if isinstance(payload, dict):
                msg = payload.get("error") or payload.get("message") or payload.get("detail") or payload.get("reason") or ""
            raise RuntimeError(
                f"[Codex][CPA] 管理接口失败 {method.upper()} {path} status={resp.status_code}: "
                f"{msg or (resp.text or '')[:300]}"
            )
        return payload if isinstance(payload, dict) else {}
    finally:
        try:
            session.close()
        except Exception:
            pass


def _sub2_codex_base() -> str:
    from config import sub2api as _sub2_cfg
    raw = str(
        getattr(_sub2_cfg, "SUB2API_API_BASE", "")
        or getattr(_sub2_cfg, "SUB2_CODEX_API_BASE", "")
        or ""
    ).strip().rstrip("/")
    if not raw:
        raise RuntimeError("[Codex][sub2] 尚未配置 SUB2API_API_BASE")
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RuntimeError(f"[Codex][sub2] SUB2API_API_BASE 格式无效: {raw}")
    return raw


def _sub2_codex_headers() -> dict:
    from config import sub2api as _sub2_cfg
    token = str(getattr(_sub2_cfg, "SUB2_CODEX_API_TOKEN", "") or getattr(_sub2_cfg, "SUB2API_API_KEY", "") or getattr(_sub2_cfg, "SUB2API_API_TOKEN", "") or "").strip()
    auth_header = str(getattr(_sub2_cfg, "SUB2_CODEX_AUTH_HEADER", "") or getattr(_sub2_cfg, "SUB2API_API_AUTH_HEADER", "x-api-key") or "x-api-key").strip()
    auth_prefix = str(getattr(_sub2_cfg, "SUB2_CODEX_AUTH_PREFIX", "") or getattr(_sub2_cfg, "SUB2API_API_AUTH_PREFIX", "") or "").strip()
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "turb-gpt-free-register/codex-sub2",
    }
    if token:
        headers[auth_header] = f"{auth_prefix} {token}".strip() if auth_prefix else token
    return headers


def _sub2_codex_request_json(method: str, path: str, body: dict | None = None) -> dict:
    from config import sub2api as _sub2_cfg
    base = _sub2_codex_base()
    timeout = int(getattr(_sub2_cfg, "SUB2API_API_TIMEOUT", 20) or 20)
    normalized_path = "/" + str(path or "").lstrip("/")
    url = f"{base}{normalized_path}"
    session = curl_requests.Session()
    try:
        resp = session.request(
            method.upper(),
            url,
            headers=_sub2_codex_headers(),
            data=None if body is None else json.dumps(body),
            timeout=timeout,
        )
        try:
            payload = resp.json()
        except Exception:
            payload = {}
        if resp.status_code < 200 or resp.status_code >= 300:
            msg = ""
            if isinstance(payload, dict):
                msg = payload.get("error") or payload.get("message") or payload.get("detail") or payload.get("reason") or ""
            raise RuntimeError(
                f"[Codex][sub2] 接口失败 {method.upper()} {normalized_path} status={resp.status_code}: "
                f"{msg or (resp.text or '')[:300]}"
            )
        return payload if isinstance(payload, dict) else {}
    finally:
        try:
            session.close()
        except Exception:
            pass


def _request_sub2_authorize_url() -> dict:
    """从 sub2 生成 Codex OAuth 授权地址；本地不生成 PKCE。"""
    from config import sub2api as _sub2_cfg
    path = str(getattr(_sub2_cfg, "SUB2_CODEX_AUTH_URL_PATH", "/api/v1/admin/openai/generate-auth-url") or "/api/v1/admin/openai/generate-auth-url")
    logger.info("[Codex][sub2] 正在通过 sub2 接口生成授权地址...")
    payload = _sub2_codex_request_json("POST", path, {})
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    auth_url = _first_non_empty(
        payload.get("url"), payload.get("auth_url"), payload.get("authUrl"),
        data.get("url"), data.get("auth_url"), data.get("authUrl"),
    )
    session_id = _first_non_empty(
        payload.get("session_id"), payload.get("sessionId"),
        data.get("session_id"), data.get("sessionId"),
    )
    state = _first_non_empty(
        payload.get("state"), payload.get("auth_state"), payload.get("authState"),
        data.get("state"), data.get("auth_state"), data.get("authState"),
        _extract_state_from_auth_url(auth_url),
    )
    if not auth_url.startswith("http"):
        raise RuntimeError(f"[Codex][sub2] sub2 未返回有效 auth_url: {payload}")
    if not state:
        raise RuntimeError("[Codex][sub2] 授权地址缺少 state")
    logger.info("[Codex][sub2] 已获取授权地址，state=%s...", state[:12])
    logger.info("[Codex][sub2] 完整授权地址: %s", auth_url)
    if not session_id:
        logger.warning("[Codex][sub2] 授权地址响应缺少 session_id，后续 exchange-code 可能失败")
    return {"auth_url": auth_url, "state": state, "session_id": session_id, "origin": _sub2_codex_base(), "raw": payload}


def _summarize_sub2_response(payload: dict) -> str:
    """压缩 sub2api 响应日志，避免整包刷屏，同时保留账号创建关键信息。"""
    try:
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        parts = []
        if isinstance(data, dict):
            for key in ("id", "account_id", "name", "email", "platform", "type"):
                val = data.get(key)
                if val not in (None, ""):
                    parts.append(f"{key}={val}")
        if parts:
            return " ".join(parts)
        if isinstance(payload, dict):
            compact = {k: payload.get(k) for k in ("code", "message", "success") if k in payload}
            return str(compact or payload)[:300]
    except Exception:
        pass
    return str(payload)[:300]


def _submit_sub2_callback(callback_url: str, *, session_id: str = "", redirect_uri: str = "") -> dict:
    """提交 OAuth callback 给 sub2。"""
    from config import sub2api as _sub2_cfg
    path = str(getattr(_sub2_cfg, "SUB2_CODEX_CALLBACK_PATH", "/api/v1/admin/openai/create-from-oauth") or "/api/v1/admin/openai/create-from-oauth")
    mode = str(getattr(_sub2_cfg, "SUB2_CODEX_CALLBACK_PAYLOAD_MODE", "create_from_oauth") or "create_from_oauth").strip().lower()
    if mode == "callback_url":
        body = {"callback_url": str(callback_url or "").strip()}
    elif mode == "redirect_url":
        body = {"redirect_url": str(callback_url or "").strip()}
    else:
        parsed = urlparse(str(callback_url or ""))
        qs = parse_qs(parsed.query)
        code = (qs.get("code") or [""])[0]
        state = (qs.get("state") or [""])[0]
        if not session_id:
            raise RuntimeError("[Codex][sub2] exchange-code 缺少 session_id")
        if not code:
            raise RuntimeError(f"[Codex][sub2] callback_url 缺少 code: {callback_url}")
        if not state:
            raise RuntimeError(f"[Codex][sub2] callback_url 缺少 state: {callback_url}")
        body = {"session_id": session_id, "code": code, "state": state}
        if redirect_uri:
            body["redirect_uri"] = redirect_uri
        if mode in {"create_from_oauth", "create-from-oauth", "create_oauth_account"}:
            body.setdefault("concurrency", 3)
            body.setdefault("priority", 50)

    max_attempts = max(1, int(getattr(_cfg, "CPA_CALLBACK_SUBMIT_RETRIES", 5) or 5))
    base_delay = max(1.0, float(getattr(_cfg, "CPA_CALLBACK_SUBMIT_RETRY_DELAY", 6) or 6))
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info("[Codex][sub2] 正在上传 OAuth callback（第 %s/%s 次）... callback=%s", attempt, max_attempts, callback_url)
            payload = _sub2_codex_request_json("POST", path, body)
            logger.info("[Codex][sub2] callback 已上传并处理完成（第 %s 次成功）响应=%s", attempt, _summarize_sub2_response(payload))
            return payload
        except Exception as exc:
            last_exc = exc
            retryable = _is_cpa_callback_retryable(exc)
            if attempt >= max_attempts or not retryable:
                logger.warning("[Codex][sub2] callback 上传失败且不再重试：attempt=%s/%s retryable=%s error=%s", attempt, max_attempts, retryable, exc)
                raise
            delay = base_delay * attempt
            logger.warning("[Codex][sub2] callback 上传失败，将在 %.1fs 后重试：attempt=%s/%s error=%s", delay, attempt, max_attempts, exc)
            time.sleep(delay)
    raise RuntimeError(f"[Codex][sub2] callback 上传失败：{last_exc}")



def _cpa_request_raw(method: str, path: str, body: dict | None = None, *, response_type: str = "text"):
    """调用 CPA 管理接口并返回原始响应；用于下载 auth-files 这类非 JSON 响应。"""
    origin = _cpa_management_origin()
    key = _cpa_management_key()
    timeout = int(getattr(_cfg, "CPA_REQUEST_TIMEOUT", 30) or 30)
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}",
        "X-Management-Key": key,
    }
    url = f"{origin}{path}"
    session = curl_requests.Session()
    try:
        resp = session.request(
            method.upper(),
            url,
            headers=headers,
            data=None if body is None else json.dumps(body),
            timeout=timeout,
        )
        if resp.status_code < 200 or resp.status_code >= 300:
            msg = ""
            try:
                payload = resp.json()
                if isinstance(payload, dict):
                    msg = payload.get("error") or payload.get("message") or payload.get("detail") or payload.get("reason") or ""
            except Exception:
                pass
            raise RuntimeError(
                f"[Codex][CPA] 管理接口失败 {method.upper()} {path} status={resp.status_code}: "
                f"{msg or (resp.text or '')[:300]}"
            )
        if response_type == "bytes":
            return resp.content
        return resp.text
    finally:
        try:
            session.close()
        except Exception:
            pass


def list_cpa_codex_auth_files() -> list[dict]:
    """读取 CPA auth-files 列表，仅返回 type/name/email 可识别为 codex 的凭证。"""
    payload = _cpa_request_json("GET", "/v0/management/auth-files")
    files = payload.get("files") if isinstance(payload.get("files"), list) else []
    out = []
    for item in files:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        ftype = str(item.get("type") or "").strip().lower()
        email = str(item.get("email") or "").strip().lower()
        if ftype == "codex" or name.lower().startswith("codex-") or "codex" in name.lower():
            copied = dict(item)
            copied["name"] = name
            copied["email"] = email or str(item.get("email") or "")
            out.append(copied)
    return out


def find_cpa_codex_auth_file(*, email: str = "", local_filename: str = "") -> dict | None:
    """按本地回执/凭证文件名或邮箱匹配 CPA 侧 codex auth 文件。"""
    email_l = str(email or "").strip().lower()
    local_name_l = str(local_filename or "").strip().lower()
    local_stem_l = local_name_l[:-5] if local_name_l.endswith(".json") else local_name_l
    files = list_cpa_codex_auth_files()
    if not files:
        return None

    def score(item: dict) -> int:
        name_l = str(item.get("name") or "").lower()
        item_email_l = str(item.get("email") or "").lower()
        s = 0
        if local_name_l and name_l == local_name_l:
            s = max(s, 100)
        if local_stem_l and name_l.startswith(local_stem_l):
            s = max(s, 80)
        if email_l and item_email_l == email_l:
            s = max(s, 70)
        if email_l and email_l in name_l:
            s = max(s, 60)
        # 本地 CPA 回执名一般是 codex-邮箱-cpa-callback.json，CPA 实际文件是 codex-邮箱-free.json。
        if local_stem_l.endswith("-cpa-callback"):
            base = local_stem_l[:-len("-cpa-callback")]
            if base and name_l.startswith(base + "-"):
                s = max(s, 75)
        return s

    ranked = sorted(((score(item), item) for item in files), key=lambda x: x[0], reverse=True)
    return ranked[0][1] if ranked and ranked[0][0] > 0 else None


def download_cpa_codex_auth_text(*, cpa_name: str | None = None, email: str = "", local_filename: str = "") -> tuple[str, str, dict]:
    """
    从 CPA auth-files 下载一个 Codex JSON 文本。
    Returns: (content_text, download_filename, matched_file_meta)
    """
    meta = None
    name = str(cpa_name or "").strip()
    if name:
        # 已经拿到 CPA 文件名时直接下载，不再额外拉取一次 auth-files 列表。
        # 账号列表批量下载会先统一列一次列表；这里重复列会导致选中多账号时浏览器长时间等待下载确认。
        meta = {"name": name}
    else:
        meta = find_cpa_codex_auth_file(email=email, local_filename=local_filename)
        name = str((meta or {}).get("name") or "").strip()
    if not name:
        target = email or local_filename or cpa_name or "未知"
        raise RuntimeError(f"[Codex][CPA] 未在 CPA auth-files 中找到匹配的 Codex 凭证: {target}")
    text = _cpa_request_raw("GET", f"/v0/management/auth-files/download?name={quote(name, safe='')}", response_type="text")
    # 下载接口正常应返回 JSON 文本，这里做一次轻校验，避免把 HTML/错误文本当凭证导出。
    try:
        parsed = json.loads(text)
    except Exception as exc:
        raise RuntimeError(f"[Codex][CPA] CPA 下载内容不是有效 JSON: {name}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"[Codex][CPA] CPA 下载内容不是 JSON 对象: {name}")
    return json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", name, (meta or {"name": name})

def _first_non_empty(*values) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _extract_state_from_auth_url(auth_url: str) -> str:
    try:
        return parse_qs(urlparse(auth_url).query).get("state", [""])[0]
    except Exception:
        return ""


def _request_cpa_authorize_url() -> dict:
    """从 CPA 生成 Codex OAuth 授权地址；本地不生成 PKCE。"""
    logger.info("[Codex][CPA] 正在通过 CPA 管理接口生成授权地址...")
    payload = _cpa_request_json("GET", "/v0/management/codex-auth-url")
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    auth_url = _first_non_empty(
        payload.get("url"),
        payload.get("auth_url"),
        payload.get("authUrl"),
        data.get("url"),
        data.get("auth_url"),
        data.get("authUrl"),
    )
    state = _first_non_empty(
        payload.get("state"),
        payload.get("auth_state"),
        payload.get("authState"),
        data.get("state"),
        data.get("auth_state"),
        data.get("authState"),
        _extract_state_from_auth_url(auth_url),
    )
    if not auth_url.startswith("http"):
        raise RuntimeError(f"[Codex][CPA] CPA 未返回有效 auth_url: {payload}")
    if not state:
        raise RuntimeError("[Codex][CPA] CPA 授权地址缺少 state")
    logger.info(f"[Codex][CPA] 已获取授权地址，state={state[:12]}...")
    logger.info(f"[Codex][CPA] 完整授权地址: {auth_url}")
    return {
        "auth_url": auth_url,
        "state": state,
        "origin": _cpa_management_origin(),
        "raw": payload,
    }


def _is_cpa_callback_retryable(exc: Exception) -> bool:
    text = str(exc or "").lower()
    return (
        "status=409" in text
        or "timeout waiting for oauth callback" in text
        or "timeout" in text
        or "timed out" in text
        or "connection" in text
        or "status=429" in text
        or "status=500" in text
        or "status=502" in text
        or "status=503" in text
        or "status=504" in text
    )


def _is_cpa_callback_reauth_error(exc_or_text) -> bool:
    """CPA 收到 callback 后仍 409 timeout，通常需要重新生成授权地址重新跑一轮 OAuth。"""
    text = str(exc_or_text or "").lower()
    return (
        "oauth-callback" in text
        and "status=409" in text
        and "timeout waiting for oauth callback" in text
    ) or (
        "timeout waiting for oauth callback" in text
    )


def _submit_cpa_callback(callback_url: str) -> dict:
    """提交 OAuth callback 给 CPA。

    CPA 偶发会在浏览器已拿到 localhost callback 后仍返回
    “409 Timeout waiting for OAuth callback”，通常是管理端等待/入库的竞态；
    这里按同一个 callback URL 做多次重试，不重新生成授权地址。
    """
    body = {
        "provider": "codex",
        "redirect_url": str(callback_url or "").strip(),
    }
    max_attempts = max(1, int(getattr(_cfg, "CPA_CALLBACK_SUBMIT_RETRIES", 5) or 5))
    base_delay = max(1.0, float(getattr(_cfg, "CPA_CALLBACK_SUBMIT_RETRY_DELAY", 6) or 6))
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(
                "[Codex][CPA] 正在提交 OAuth callback 给 CPA（第 %s/%s 次）... callback=%s",
                attempt, max_attempts, str(callback_url or "")
            )
            payload = _cpa_request_json("POST", "/v0/management/oauth-callback", body)
            logger.info("[Codex][CPA] callback 已提交（第 %s 次成功）", attempt)
            return payload
        except Exception as exc:
            last_exc = exc
            retryable = _is_cpa_callback_retryable(exc)
            if attempt >= max_attempts or not retryable:
                logger.warning(
                    "[Codex][CPA] callback 提交失败且不再重试：attempt=%s/%s retryable=%s error=%s",
                    attempt, max_attempts, retryable, exc
                )
                raise
            delay = base_delay * attempt
            logger.warning(
                "[Codex][CPA] callback 提交失败，将在 %.1fs 后重试：attempt=%s/%s error=%s",
                delay, attempt, max_attempts, exc
            )
            time.sleep(delay)
    raise RuntimeError(f"[Codex][CPA] callback 提交失败：{last_exc}")


# ============================================================
# 小工具：判定/解析
# ============================================================

def _is_redirect_uri(location: str) -> bool:
    """判断 Location 是否指向注册的 redirect_uri（localhost:1455/auth/callback）。"""
    try:
        parsed = urlparse(location)
    except Exception:
        return False
    return parsed.scheme in ("http", "https") and \
        parsed.hostname in ("localhost", "127.0.0.1") and \
        parsed.port == 1455 and \
        parsed.path == "/auth/callback"


def _extract_code(location: str, state: str) -> str:
    """从 redirect_uri 的 Location 里提取并校验 code。"""
    parsed = urlparse(location)
    qs = parse_qs(parsed.query)
    err = (qs.get("error") or [""])[0]
    if err:
        err_desc = (qs.get("error_description") or [""])[0]
        raise RuntimeError(f"[Codex] 授权服务器返回错误: error={err}, desc={err_desc}")
    code = (qs.get("code") or [""])[0]
    if not code:
        raise RuntimeError(f"[Codex] redirect_uri 缺少 code 参数: {location}")
    returned_state = (qs.get("state") or [""])[0]
    if returned_state and returned_state != state:
        raise RuntimeError(
            f"[Codex] state 不匹配（疑似 CSRF）: expected={state[:8]}..., got={returned_state[:8]}..."
        )
    return code


def _decode_jwt_segment(seg: str) -> dict:
    """base64url 解码一个 JWT/cookie 段为 JSON dict（失败返回 {}）。"""
    try:
        padding = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + padding))
    except Exception:
        return {}


def _post_json(session: BrowserSession, url: str, payload: dict, referer: str,
               sentinel_header: str | None = None, so_header: str | None = None):
    """统一发 /api/accounts/* 的 JSON POST。"""
    headers = session.get_auth_headers(referer=referer)
    if sentinel_header:
        headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
    return session.post(url, headers=headers, data=json.dumps(payload), allow_redirects=False)


def _resp_json(resp) -> dict:
    try:
        return resp.json()
    except Exception:
        return {}


def _response_text(resp) -> str:
    try:
        data = resp.json()
        if isinstance(data, dict):
            parts = []
            def walk(x):
                if isinstance(x, dict):
                    for v in x.values(): walk(v)
                elif isinstance(x, list):
                    for v in x: walk(v)
                elif x is not None:
                    parts.append(str(x))
            walk(data)
            return " ".join(parts)
    except Exception:
        pass
    return str(getattr(resp, 'text', '') or '')


def _safe_url_summary(url: str | None) -> str:
    """只保留 URL 的 origin/path，避免把 OAuth 参数写入日志。"""
    text = str(url or "").strip()
    if not text:
        return "-"
    try:
        parsed = urlparse(urljoin("https://auth.openai.com/", text))
    except Exception:
        return "invalid"
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"


class _BootstrapScriptParser(HTMLParser):
    """提取 Auth Web SSR 页里的 bootstrap-inert-script JSON。"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._capturing = False
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "script":
            return
        values = {str(key).lower(): str(value or "") for key, value in attrs}
        if values.get("id") == "bootstrap-inert-script":
            self._capturing = True

    def handle_data(self, data: str) -> None:
        if self._capturing:
            self._parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._capturing:
            self._capturing = False

    @property
    def content(self) -> str:
        return "".join(self._parts).strip()


class _AuthJsonScriptParser(HTMLParser):
    """Extract inert script text; never execute page JavaScript."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self._parts = None
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() == "script":
            self._parts = []

    def handle_data(self, data: str) -> None:
        if self._parts is not None:
            self._parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._parts is not None:
            self.scripts.append("".join(self._parts))
            self._parts = None


def _workspace_records(value) -> list[dict]:
    """Read an explicit workspace list, preserving server order."""
    rows = value.get("workspaces") if isinstance(value, dict) else None
    if not isinstance(rows, list):
        return []
    records = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        wid = row.get("id") or row.get("account_id")
        if not isinstance(wid, str) or not wid.strip() or wid.strip() in seen:
            continue
        seen.add(wid.strip())
        records.append({**row, "id": wid.strip()})
    return records


def _remember_auth_session(session: BrowserSession, auth_session, *, source: str = "json") -> int:
    """Keep the latest server list within this OAuth transaction only."""
    if not isinstance(auth_session, dict) or not auth_session:
        return 0
    previous = getattr(session, "_codex_auth_session_payload", None)
    previous = previous if isinstance(previous, dict) else {}
    sid = auth_session.get("session_id")
    if sid and previous.get("session_id") and sid != previous["session_id"]:
        previous = {}
    payload = {**previous, **auth_session}
    # A missing field preserves this transaction's list; an explicit [] clears
    # it. Never union old and new choices or reorder the latest server list.
    session._codex_auth_session_payload = payload
    # Keep the old narrow attribute as a compatibility view for callers and
    # adapters that recorded the response before the richer payload cache was
    # introduced.  It is always replaced from the current transaction state.
    session._codex_auth_session_workspaces = list(payload.get("workspaces") or []) \
        if isinstance(payload.get("workspaces"), list) else []
    session._codex_auth_session_source = source
    count = len(_workspace_records(payload))
    if "workspaces" in auth_session:
        logger.info("[Codex] 已缓存授权工作区：source=%s count=%s", source, count)
    return count


def _unflatten_auth_router_data(flat):
    """Decode JSON reference tables in React Router streamController.enqueue."""
    if not isinstance(flat, list) or not flat or len(flat) > 10000:
        return {}
    cache = {}
    active = set()

    def resolve(index, depth=0):
        if type(index) is not int or index < 0 or index >= len(flat) or depth > 32:
            return None
        if index in active:
            return None
        if index in cache:
            return cache[index]
        active.add(index)
        value = flat[index]
        if isinstance(value, dict):
            result = {}
            for key, ref in value.items():
                match = re.fullmatch(r"_(\d+)", key)
                decoded_key = resolve(int(match[1]), depth + 1) if match else key
                if isinstance(decoded_key, str):
                    result[decoded_key] = resolve(ref, depth + 1)
        elif isinstance(value, list):
            result = [resolve(ref, depth + 1) for ref in value]
        else:
            result = value
        active.remove(index)
        cache[index] = result
        return result

    return resolve(0)


def _auth_session_from_ssr(html: str) -> dict:
    """Read only the client-auth-session loader, including HAR stream format."""
    if not html or len(html) > 8_000_000:
        return {}
    parser = _AuthJsonScriptParser()
    parser.feed(html)
    decoder = json.JSONDecoder()
    for script in parser.scripts:
        candidates = []
        try:
            candidates.append(json.loads(script))
        except (ValueError, TypeError):
            pass
        for match in re.finditer(
            r"(?:window\.)?__(?:reactRouterContext|staticRouterHydrationData)"
            r"(?:\.streamController\.enqueue\(\s*|\s*=\s*)", script,
        ):
            try:
                raw = script[match.end():].lstrip()
                if raw.startswith("JSON.parse("):
                    raw = raw[len("JSON.parse("):].lstrip()
                value, _ = decoder.raw_decode(raw)
                if isinstance(value, str):
                    value = json.loads(value)
                candidates.append(_unflatten_auth_router_data(value) if isinstance(value, list) else value)
            except (ValueError, TypeError, RecursionError):
                continue
        for payload in candidates:
            if not isinstance(payload, dict):
                continue
            state = payload.get("state", payload)
            loaders = state.get("loaderData") if isinstance(state, dict) else None
            if not isinstance(loaders, dict):
                continue
            loader = loaders.get("routes/layouts/client-auth-session-layout/layout")
            auth_session = loader.get("session") if isinstance(loader, dict) else None
            if isinstance(auth_session, dict):
                return auth_session
    return {}


def _sync_auth_document_context(
    session: BrowserSession,
    resp,
    *,
    stage: str,
) -> bool:
    """使用 Auth Web SSR bootstrap 下发的文档身份更新后续 JSON 请求头。"""
    body = str(getattr(resp, "text", "") or "")
    if "bootstrap-inert-script" not in body:
        return False

    parser = _BootstrapScriptParser()
    try:
        parser.feed(body)
        payload = json.loads(parser.content)
    except Exception:
        logger.debug("[Codex] 解析 Auth 文档 bootstrap 失败：stage=%s", stage, exc_info=True)
        return False
    if not isinstance(payload, dict):
        return False

    document_id = str(payload.get("documentNavigationId") or "").strip().lower()
    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        document_id,
    ):
        logger.warning("[Codex] Auth 文档缺少有效 documentNavigationId：stage=%s", stage)
        return False

    old_document_id = str(getattr(session, "document_navigation_id", "") or "")
    session.document_navigation_id = document_id

    immutable = payload.get("immutableClientSessionMetadata")
    immutable = immutable if isinstance(immutable, dict) else {}
    server_logging_id = str(immutable.get("auth_session_logging_id") or "").strip()
    if server_logging_id:
        session.auth_session_logging_id = server_logging_id

    statsig = payload.get("statsigClientInitData")
    statsig = statsig if isinstance(statsig, dict) else {}
    identity = statsig.get("identity")
    identity = identity if isinstance(identity, dict) else {}
    oaicom_stable_id = str(identity.get("oaicomStableId") or "").strip()
    if oaicom_stable_id:
        session.oaicom_stable_id = oaicom_stable_id

    server_device_id = str(identity.get("deviceId") or "").strip()
    local_device_id = str(getattr(session, "device_id", "") or "").strip()
    device_match = not server_device_id or server_device_id == local_device_id
    if not device_match:
        logger.warning(
            "[Codex] Auth 文档设备 ID 与当前会话不一致：stage=%s server=%s local=%s",
            stage,
            hashlib.sha256(server_device_id.encode()).hexdigest()[:8],
            hashlib.sha256(local_device_id.encode()).hexdigest()[:8],
        )

    logger.info(
        "[Codex] Auth 文档上下文已同步：stage=%s document=%s -> %s device_match=%s",
        stage,
        old_document_id[:8] or "-",
        document_id[:8],
        device_match,
    )
    return True


def _auth_session_cookie_fingerprint(session: BrowserSession) -> str:
    """返回 auth session Cookie 的脱敏摘要，用于比较请求前后的状态。"""
    candidates = _auth_session_cookie_candidates(session)
    if not candidates:
        return "missing"
    domain, name, value = candidates[0]
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:10]
    decoded = _decode_auth_session_cookie(value)
    session_id = str(decoded.get("session_id") or "") if isinstance(decoded, dict) else ""
    session_hash = (
        hashlib.sha256(session_id.encode("utf-8", errors="ignore")).hexdigest()[:8]
        if session_id else "-"
    )
    workspaces = decoded.get("workspaces") if isinstance(decoded, dict) else None
    workspace_count = len(workspaces) if isinstance(workspaces, list) else 0
    verified = decoded.get("email_verified") if isinstance(decoded, dict) else None
    return (
        f"present name={name} domain={domain or '-'} len={len(value)} sha={digest} "
        f"sid={session_hash} verified={verified!r} workspaces={workspace_count}"
    )


def _set_cookie_names(resp) -> list[str]:
    """提取响应 Set-Cookie 名称，不记录 Cookie 值。"""
    headers = getattr(resp, "headers", {}) or {}
    values = []
    for method_name in ("get_list", "get_all"):
        method = getattr(headers, method_name, None)
        if not callable(method):
            continue
        try:
            values = list(method("set-cookie") or method("Set-Cookie") or [])
        except Exception:
            values = []
        if values:
            break
    if not values:
        try:
            value = headers.get("set-cookie") or headers.get("Set-Cookie") or ""
        except Exception:
            value = ""
        if value:
            values = [str(value)]

    names = []
    cookie_name_pattern = re.compile(r"(?:^|,\s*)([!#$%&'*+.^_`|~0-9A-Za-z-]+)=")
    for value in values:
        names.extend(cookie_name_pattern.findall(str(value)))
    return list(dict.fromkeys(names))


def _extract_auth_step(payload: dict) -> tuple[str, str, dict]:
    """从 Auth Web JSON 中严格提取 page.type、下一跳和 auth session。"""
    if not isinstance(payload, dict):
        return "", "", {}
    containers = [payload]
    for key in ("data", "result"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            containers.append(nested)

    page = {}
    auth_session = {}
    continue_url = ""
    for container in containers:
        if not page and isinstance(container.get("page"), dict):
            page = container["page"]
        if not auth_session:
            for key in ("oai-client-auth-session", "auth_session"):
                value = container.get(key)
                if isinstance(value, dict):
                    auth_session = value
                    break
                if isinstance(value, str):
                    decoded = _decode_auth_session_cookie(value)
                    if decoded:
                        auth_session = decoded
                        break
        if not continue_url:
            for key in ("continue_url", "external_url", "redirect_url", "url", "location"):
                value = container.get(key)
                if isinstance(value, str) and value.strip():
                    continue_url = value.strip()
                    break

    if not auth_session:
        pending = [payload]
        for _ in range(32):
            if not pending:
                break
            container = pending.pop(0)
            for key in ("oai-client-auth-session", "auth_session", "client_auth_session"):
                value = container.get(key)
                if isinstance(value, str):
                    value = _decode_auth_session_cookie(value)
                if isinstance(value, dict) and value:
                    auth_session = value
                    break
            if auth_session:
                break
            pending.extend(container[key] for key in ("data", "result", "page", "payload")
                           if isinstance(container.get(key), dict))

    if not continue_url and page:
        page_payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
        for source in (page_payload, page):
            for key in (
                "continue_url",
                "continueUrl",
                "external_url",
                "redirect_url",
                "next_url",
                "nextUrl",
                "url",
                "location",
            ):
                value = source.get(key)
                if isinstance(value, str) and value.strip():
                    continue_url = value.strip()
                    break
            if continue_url:
                break
    page_type = str(page.get("type") or "").strip().lower().replace("-", "_")
    return page_type, continue_url, auth_session


def _auth_step_requires_phone(page_type: str, continue_url: str) -> bool:
    normalized = str(page_type or "").strip().lower().replace("-", "_")
    if normalized in {
        "add_phone",
        "phone_verification",
        "phone_number",
        "phone_number_verification",
    }:
        return True
    try:
        path = urlparse(urljoin("https://auth.openai.com/", str(continue_url or ""))).path.lower()
    except Exception:
        path = ""
    return path.startswith("/add-phone") or path.startswith("/phone-verification")


def _auth_step_requires_mfa(page_type: str, continue_url: str) -> bool:
    normalized = str(page_type or "").strip().lower().replace("-", "_")
    if normalized in {"mfa_challenge", "totp_challenge"}:
        return True
    try:
        path = urlparse(urljoin("https://auth.openai.com/", str(continue_url or ""))).path.lower()
    except Exception:
        path = ""
    return path.startswith("/mfa-challenge")


def _prepare_phone_step(session: BrowserSession, continue_url: str = "") -> str:
    """在购买号码前消费手机号下一跳，并确认同一 OAuth Session 仍有效。"""
    target = urljoin(
        "https://auth.openai.com/",
        str(continue_url or "https://auth.openai.com/add-phone").strip(),
    )
    parsed = urlparse(target)
    if parsed.scheme != "https" or parsed.hostname != "auth.openai.com":
        raise RuntimeError(
            f"[Codex] 邮箱 OTP 返回了不可信的手机号下一跳: {_safe_url_summary(target)}"
        )

    cookie_before = _auth_session_cookie_fingerprint(session)
    headers = session.get_auth_navigate_headers(
        referer="https://auth.openai.com/email-verification",
        user_initiated=False,
        target_origin="https://auth.openai.com",
    )
    headers["sec-fetch-site"] = "same-origin"
    resp = _with_net_retry(
        "进入手机号阶段",
        lambda: session.get(target, headers=headers, allow_redirects=True),
    )
    status = int(getattr(resp, "status_code", 0) or 0)
    final_url = str(getattr(resp, "url", "") or target)
    final_path = (urlparse(final_url).path or "/").lower()
    _sync_auth_document_context(session, resp, stage="add_phone")
    cookie_after = _auth_session_cookie_fingerprint(session)
    logger.info(
        "[Codex] 手机号阶段预检：status=%s target=%s final=%s auth_cookie=%s -> %s",
        status,
        _safe_url_summary(target),
        _safe_url_summary(final_url),
        cookie_before,
        cookie_after,
    )

    body = _response_text(resp)[:2000]
    if (
        _is_oauth_session_invalid_response(body, status)
        or final_path in {"/log-in", "/login"}
        or final_path.startswith("/log-in/")
        or final_path.startswith("/login/")
    ):
        raise RuntimeError(
            f"[Codex] 手机号阶段预检授权会话失效 status={status}, "
            f"final={_safe_url_summary(final_url)}"
        )
    if status >= 400:
        raise RuntimeError(
            f"[Codex] 手机号阶段预检失败 status={status}, "
            f"final={_safe_url_summary(final_url)}: {body[:240]}"
        )
    if not (
        final_path.startswith("/add-phone")
        or final_path.startswith("/phone-verification")
    ):
        raise RuntimeError(
            f"[Codex] 手机号阶段未进入号码验证页面，拒绝购买号码: "
            f"final={_safe_url_summary(final_url)}"
        )

    session.codex_phone_referer = final_url
    return final_url


def _is_oauth_session_invalid_response(text: str, status_code: int | None = None) -> bool:
    """识别必须从登录入口重新开始的 OAuth 会话失效响应。"""
    low = str(text or '').lower()
    exact_markers = (
        'sign-in session is no longer valid',
        'signin session is no longer valid',
        'session is no longer valid',
        'login session is no longer valid',
        'invalid authorization step',
        'invalid_auth_step',
    )
    if any(marker in low for marker in exact_markers):
        return True
    if status_code == 409 and any(marker in low for marker in (
        'invalid_state',
        'invalid state',
        'start over to continue',
        'session expired',
        'session has expired',
    )):
        return True
    return False


def _phone_failure_reason(text: str, status_code: int | None = None) -> str:
    low = str(text or '').lower()
    if _is_oauth_session_invalid_response(low, status_code):
        return 'oauth_session_invalid'
    if 'whatsapp' in low or 'whats app' in low:
        return 'whatsapp_channel'
    if any(k in low for k in (
        'phone number is not valid', 'invalid phone number', 'invalid phone', 'not a valid phone',
        '号码无效', '手机号无效', '电话号码无效', 'invalid_number', 'invalid_phone',
    )):
        return 'invalid_phone'
    if any(k in low for k in (
        'cannot send', "can't send", 'could not send', "couldn't send", 'unable to send',
        'cannot deliver', 'unable to deliver', 'failed to send', 'send failed',
        '无法发送', '不能发送', '无法向', '发送验证码', '发送短信',
    )):
        return 'delivery_refused'
    if any(k in low for k in ('too many', 'rate limit', 'throttle', 'limited', '频繁', '限流')):
        return 'send_limited'
    if any(k in low for k in ('already used', 'used too many', 'maximum', '上限', '已被使用')):
        return 'phone_used_or_max'
    if status_code and status_code >= 500:
        return 'server_error'
    if status_code and status_code >= 400:
        return 'send_rejected'
    return ''


def _phone_send_advanced_to_otp(resp) -> bool:
    """Prefer the structured next auth step over fuzzy response text markers."""
    status = int(getattr(resp, "status_code", 0) or 0)
    if status == 204:
        return True
    if status != 200:
        return False
    if _extract_error_code(resp):
        return False
    payload = _resp_json(resp)
    page_type, continue_url, _ = _extract_auth_step(payload)
    normalized = str(page_type or "").strip().lower().replace("-", "_")
    if "phone" in normalized and "otp" in normalized:
        return True
    try:
        path = urlparse(
            urljoin("https://auth.openai.com/", str(continue_url or ""))
        ).path.lower()
    except Exception:
        path = ""
    return path.startswith("/phone-verification")


# ============================================================
# 步骤 0：用全新 session 跟随 Codex authorize URL，建立 auth.openai.com 会话
# ============================================================

def _bootstrap_authorize(
    session: BrowserSession,
    state: str,
    code_challenge: str | None = None,
    auth_url: str | None = None,
) -> None:
    """
    GET Codex authorize URL 并跟随重定向，落到登录页，建立 auth.openai.com cookies
    （含 oai-client-auth-session：内含 Codex 目标 + 后续要用的 workspace 列表）。
    """
    session._codex_auth_session_payload = {}
    session._codex_auth_session_workspaces = []
    session._codex_auth_session_source = ""
    session._codex_consent_url = ""
    session._codex_selected_workspace_id = ""
    # 默认使用调用方传入的 CPA 授权地址；未传时才走保留的本地 PKCE 生成逻辑。
    if not auth_url:
        if not code_challenge:
            raise RuntimeError("[Codex] 本地生成授权地址需要 code_challenge")
        auth_url = _build_authorize_url(state, code_challenge, prompt="login")
    auth_url = _ensure_oai_context_url(auth_url, session)
    headers = session.get_auth_navigate_headers(referer="https://chatgpt.com/")
    logger.info("[Codex] 跟随 Codex authorize URL 建立会话...")
    logger.info(f"[Codex] 完整授权地址: {auth_url}")
    resp = _with_net_retry(
        "bootstrap authorize",
        lambda: session.get(auth_url, headers=headers, allow_redirects=True),
    )
    if getattr(resp, "status_code", 0) >= 400:
        raise RuntimeError(
            f"[Codex] bootstrap authorize 失败 status={resp.status_code}: "
            f"{(getattr(resp, 'text', '') or '')[:300]}"
        )
    _sync_auth_document_context(session, resp, stage="oauth_authorize")
    logger.debug(f"[Codex] authorize 落点: {getattr(resp, 'url', '')}, status={getattr(resp, 'status_code', '')}")


# ============================================================
# 步骤 1：提交邮箱（触发邮箱 OTP 发送）
# ============================================================

def _post_email_otp_control(
    session: BrowserSession,
    url: str,
    *,
    referer: str,
    sentinel_header: str | None = None,
    so_header: str | None = None,
):
    """发送邮箱 OTP 控制请求（passwordless/send-otp 或 email-otp/resend）。"""
    headers = session.get_auth_headers(referer=referer)
    if sentinel_header:
        headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
    return session.post(url, headers=headers, allow_redirects=False)


def _trigger_email_otp(session: BrowserSession) -> str:
    """按 Auth Web 当前顺序触发邮箱 OTP，返回实际采用的发送路径。"""
    sentinel_header = None
    so_header = None
    try:
        sentinel_resp = request_sentinel_token(session, "authorize_continue")
        sentinel_header, so_header = build_sentinel_header(
            session, sentinel_resp, "authorize_continue"
        )
    except Exception as exc:
        # 发送接口本身仍可返回明确结果；sentinel 失败时继续尝试无 token 的
        # resend/send 兜底，而不是把“未发码”伪装成邮箱轮询超时。
        logger.warning("[Codex][OTP] 发码前刷新 sentinel 失败，继续兜底：%s", str(exc)[:180])

    control_requests = (
        (
            "passwordless/send-otp",
            "https://auth.openai.com/api/accounts/passwordless/send-otp",
            "https://auth.openai.com/email-verification",
        ),
        (
            "email-otp/resend",
            "https://auth.openai.com/api/accounts/email-otp/resend",
            "https://auth.openai.com/email-verification",
        ),
    )
    for label, url, referer in control_requests:
        try:
            resp = _post_email_otp_control(
                session,
                url,
                referer=referer,
                sentinel_header=sentinel_header,
                so_header=so_header,
            )
            status = int(getattr(resp, "status_code", 0) or 0)
            logger.info("[Codex][OTP] %s 响应 status=%s", label, status)
            if status in (200, 201, 204):
                return label
        except Exception as exc:
            logger.warning("[Codex][OTP] %s 请求失败，继续兜底：%s", label, str(exc)[:180])

    # 最后使用网页验证码页的 GET 发送接口。该接口返回成功只代表请求被
    # 接受，真正的“新邮件”仍由后续 after_ts/旧码过滤来确认。
    send_email_otp(session, referer="https://auth.openai.com/email-verification")
    return "email-otp/send"


def _capture_otp_baseline(email: str) -> None:
    """在 Codex 补跑发码前记录邮箱当前水位（iCloud 等无可靠时间戳来源）。"""
    try:
        from core.email_provider import resolve_email_source

        if resolve_email_source(email) != "icloud":
            return
        from core.icloud_mail_client import capture_otp_baseline

        captured = capture_otp_baseline(email)
        logger.info("[Codex][OTP] 发码前邮箱水位快照：captured=%s", bool(captured))
    except Exception as exc:
        logger.debug("[Codex][OTP] 发码前邮箱水位快照失败（不阻断）: %s", str(exc)[:160])


def _submit_email(session: BrowserSession, email: str) -> None:
    """提交邮箱并显式触发邮箱 OTP。

    ``authorize/continue`` 在不同 Auth Web 版本上的语义不一致：有的版本
    会在该 POST 后自动发码，有的版本只把会话切到 ``email-verification``，
    需要前端随后 GET ``/api/accounts/email-otp/send``。只检查 POST=200 会把
    后一种情况误判成“已发码”，导致后台一直等不到邮件；因此这里始终消费
    成功的授权步骤后再走一次与网页发送按钮相同的显式发码请求。
    """
    sentinel_resp = request_sentinel_token(session, "authorize_continue")
    sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "authorize_continue")
    payload = {"username": {"kind": "email", "value": email}}
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/authorize/continue",
        payload,
        referer="https://auth.openai.com/log-in",
        sentinel_header=sentinel_header,
        so_header=so_header,
    )
    if resp.status_code not in (200, 204):
        raise RuntimeError(
            f"[Codex] 提交邮箱失败 status={resp.status_code}: {(resp.text or '')[:300]}"
        )
    # 不同 Auth Web 版本的真实发码按钮分别走 passwordless/send-otp、
    # email-otp/resend 或 email-otp/send；按网页当前顺序尝试，避免只拿到
    # 一个 HTTP 200 却没有任何新邮件。
    send_path = _trigger_email_otp(session)
    logger.info(f"[Codex] 已提交邮箱并触发邮箱 OTP：{email} path={send_path}")


def _submit_email_identifier(session: BrowserSession, email: str) -> dict:
    """提交邮箱但不主动触发邮箱 OTP；供密码/TOTP 登录路径使用。"""
    sentinel_resp = request_sentinel_token(session, "authorize_continue")
    sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "authorize_continue")
    payload = {"username": {"kind": "email", "value": email}}
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/authorize/continue",
        payload,
        referer="https://auth.openai.com/log-in",
        sentinel_header=sentinel_header,
        so_header=so_header,
    )
    if resp.status_code not in (200, 204):
        raise CodexAuthResponseError(
            f"[Codex] 提交邮箱失败 status={resp.status_code}: {(resp.text or '')[:300]}",
            http_status=resp.status_code, error_code=_extract_error_code(resp),
        )
    payload = _resp_json(resp)
    page_type, continue_url, auth_session = _extract_auth_step(payload)
    _remember_auth_session(session, auth_session, source="email_identifier")
    logger.info(
        "[Codex] 已提交邮箱，准备密码登录：%s next=%s",
        email,
        page_type or _safe_url_summary(continue_url),
    )
    return {
        "page_type": page_type,
        "continue_url": continue_url,
        "auth_session": auth_session,
        "mfa_required": _auth_step_requires_mfa(page_type, continue_url),
        "email_otp_required": _auth_step_requires_email_otp(page_type, continue_url),
        "phone_required": _auth_step_requires_phone(page_type, continue_url),
    }


# ============================================================
# 步骤 2：提交邮箱 OTP
# ============================================================

def _submit_email_otp_step(session: BrowserSession, code: str) -> dict:
    """提交邮箱验证码，返回服务端明确给出的下一授权步骤。"""
    sentinel_header = None
    so_header = None
    if bool(getattr(_protocol_cfg, "SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE", True)):
        sentinel_flow = "email_otp_validate"
        sentinel_resp = request_sentinel_token(session, sentinel_flow)
        sentinel_header, so_header = build_sentinel_header(
            session,
            sentinel_resp,
            sentinel_flow,
        )
    cookie_before = _auth_session_cookie_fingerprint(session)
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/email-otp/validate",
        {"code": code},
        referer="https://auth.openai.com/email-verification",
        sentinel_header=sentinel_header,
        so_header=so_header,
    )
    if resp.status_code != 200:
        error_code = _extract_error_code(resp)
        if error_code in ("account_deactivated", "account_deleted", "account_banned"):
            raise AccountUnusableError(
                f"[Codex] 账号已废（{error_code}）status={resp.status_code}: {(resp.text or '')[:200]}",
                error_code=error_code,
            )
        body_error_code = detect_account_unusable_response_body(resp.text or "")
        if body_error_code:
            raise AccountUnusableError(
                f"[Codex] 账号已废（{body_error_code}）status={resp.status_code}: {(resp.text or '')[:200]}",
                error_code=body_error_code,
            )
        raise CodexAuthResponseError(
            f"[Codex] 邮箱 OTP 验证失败 status={resp.status_code}: {(resp.text or '')[:300]}",
            http_status=resp.status_code,
            error_code=error_code,
        )

    payload = _resp_json(resp)
    page_type, continue_url, auth_session = _extract_auth_step(payload)
    location = ""
    try:
        location = resp.headers.get("location") or resp.headers.get("Location") or ""
    except Exception:
        pass
    if not continue_url and location:
        continue_url = str(location)
    cookie_after = _auth_session_cookie_fingerprint(session)
    response_session_id = str(auth_session.get("session_id") or "")
    response_session_hash = (
        hashlib.sha256(response_session_id.encode("utf-8", errors="ignore")).hexdigest()[:8]
        if response_session_id else "-"
    )
    logger.info(
        "[Codex] 邮箱 OTP 响应诊断：status=%s page_type=%s continue=%s "
        "json_keys=%s response_sid=%s email_verified=%r set_cookie=%s auth_cookie=%s -> %s",
        resp.status_code,
        page_type or "空",
        _safe_url_summary(continue_url),
        sorted(payload.keys()) if isinstance(payload, dict) else [],
        response_session_hash,
        auth_session.get("email_verified") if auth_session else None,
        _set_cookie_names(resp) or [],
        cookie_before,
        cookie_after,
    )

    response_text = _response_text(resp)
    if _is_oauth_session_invalid_response(response_text, resp.status_code):
        raise RuntimeError(
            f"[Codex] 邮箱 OTP 响应显示授权会话失效 status={resp.status_code}: "
            f"{response_text[:240]}"
        )
    if not isinstance(payload, dict) or not payload:
        raise RuntimeError("[Codex] 邮箱 OTP 返回 HTTP 200，但缺少可判定下一步的 JSON 状态")

    _remember_auth_session(session, auth_session, source="email_otp")
    mfa_required = _auth_step_requires_mfa(page_type, continue_url)
    phone_required = not mfa_required and _auth_step_requires_phone(page_type, continue_url)
    logger.info(
        "[Codex] 邮箱 OTP 验证通过，下一步=%s",
        "add-phone" if phone_required else (page_type or _safe_url_summary(continue_url)),
    )
    if phone_required:
        _prepare_phone_step(session, continue_url)
    return {
        "page_type": page_type,
        "continue_url": continue_url,
        "auth_session": auth_session,
        "mfa_required": mfa_required,
        "phone_required": phone_required,
    }


def _submit_email_otp(session: BrowserSession, code: str) -> bool:
    """Backward-compatible boolean wrapper used by existing protocol tests."""
    return bool(_submit_email_otp_step(session, code).get("phone_required"))


def _auth_step_requires_email_otp(page_type: str, continue_url: str) -> bool:
    normalized = str(page_type or "").strip().lower().replace("-", "_")
    if normalized in {
        "email_otp_verification",
        "otp_verification",
        "email_verification",
        "passwordless_otp",
    }:
        return True
    try:
        path = urlparse(urljoin("https://auth.openai.com/", str(continue_url or ""))).path.lower()
    except Exception:
        path = ""
    return path.startswith("/email-verification") or path.startswith("/email-otp")


def _submit_password_step(session: BrowserSession, password: str) -> dict:
    """提交已保存的 ChatGPT 登录密码，返回下一授权步骤。"""
    sentinel_resp = request_sentinel_token(session, "password_verify")
    sentinel_header, so_header = build_sentinel_header(session, sentinel_resp, "password_verify")
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/password/verify",
        {"password": password},
        referer="https://auth.openai.com/log-in/password",
        sentinel_header=sentinel_header,
        so_header=so_header,
    )
    if resp.status_code not in (200, 201):
        error_code = _extract_error_code(resp)
        if error_code in ("account_deactivated", "account_deleted", "account_banned"):
            raise AccountUnusableError(
                f"[Codex] 账号已废（{error_code}）status={resp.status_code}: {(resp.text or '')[:200]}",
                error_code=error_code,
            )
        raise CodexAuthResponseError(
            f"[Codex] 密码验证失败 status={resp.status_code}"
            f"{f' code={error_code}' if error_code else ''}: {(resp.text or '')[:300]}",
            http_status=resp.status_code, error_code=error_code,
        )

    payload = _resp_json(resp)
    page_type, continue_url, auth_session = _extract_auth_step(payload)
    response_text = _response_text(resp)
    if _is_oauth_session_invalid_response(response_text, resp.status_code):
        raise RuntimeError(
            f"[Codex] 密码验证响应显示授权会话失效 status={resp.status_code}: "
            f"{response_text[:240]}"
        )

    _remember_auth_session(session, auth_session, source="password")
    mfa_required = _auth_step_requires_mfa(page_type, continue_url)
    email_otp_required = _auth_step_requires_email_otp(page_type, continue_url)
    phone_required = not mfa_required and not email_otp_required and _auth_step_requires_phone(page_type, continue_url)
    logger.info(
        "[Codex] 密码验证通过，下一步=%s",
        (
            "mfa"
            if mfa_required
            else ("email-otp" if email_otp_required else ("add-phone" if phone_required else (page_type or _safe_url_summary(continue_url))))
        ),
    )
    if phone_required:
        _prepare_phone_step(session, continue_url)
    return {
        "page_type": page_type,
        "continue_url": continue_url,
        "auth_session": auth_session,
        "mfa_required": mfa_required,
        "email_otp_required": email_otp_required,
        "phone_required": phone_required,
    }


def _load_password_totp_login_password(email: str) -> str:
    """Return the saved ChatGPT password when this account can use TOTP login."""
    if not bool(getattr(_cfg, "CODEX_PREFER_PASSWORD_TOTP_LOGIN", True)):
        return ""
    try:
        from core import db

        account = db.get_account_by_email(email) or {}
    except Exception:
        return ""
    if not str(account.get("totp_secret") or "").strip():
        return ""
    raw_extra = account.get("extra_json")
    extra = {}
    if isinstance(raw_extra, dict):
        extra = raw_extra
    elif isinstance(raw_extra, str) and raw_extra.strip():
        try:
            parsed = json.loads(raw_extra)
            if isinstance(parsed, dict):
                extra = parsed
        except Exception:
            extra = {}
    password = str(
        extra.get("registration_password")
        or account.get("registration_password")
        or ""
    ).strip()
    if not password:
        return ""
    if len(password) > 256 or "\r" in password or "\n" in password:
        return ""
    return password


# ============================================================
# 步骤 3：已有账号的 TOTP MFA challenge
# ============================================================

def _mfa_factor_id_from_url(url: str | None) -> str:
    try:
        path = urlparse(urljoin("https://auth.openai.com/", str(url or ""))).path
    except Exception:
        return ""
    parts = [unquote(part).strip() for part in path.split("/") if part.strip()]
    for index, part in enumerate(parts[:-1]):
        if part.lower() != "mfa-challenge":
            continue
        candidate = parts[index + 1]
        if re.fullmatch(r"[A-Za-z0-9_-]{8,256}", candidate):
            return candidate
    return ""


def _load_codex_totp_credential(email: str, challenge_factor_id: str = "") -> tuple[str, str]:
    from core import db

    account = db.get_account_by_email(email) or {}
    secret = str(account.get("totp_secret") or "").strip().replace(" ", "").upper()
    stored_factor_id = str(account.get("totp_factor_id") or "").strip()
    challenge_factor_id = str(challenge_factor_id or "").strip()
    if not secret:
        raise RuntimeError(
            "[Codex] 当前授权要求 TOTP 2FA，但本地没有可用的 TOTP secret"
        )
    if (
        stored_factor_id
        and challenge_factor_id
        and not secrets.compare_digest(stored_factor_id, challenge_factor_id)
    ):
        raise RuntimeError(
            "[Codex] 本地 TOTP factor 与当前 MFA challenge 不一致，请重新同步 2FA"
        )
    factor_id = challenge_factor_id or stored_factor_id
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,256}", factor_id):
        raise RuntimeError(
            "[Codex] 当前授权要求 TOTP 2FA，但本地没有有效的 active factor ID"
        )
    return secret, factor_id


def _prepare_mfa_step(
    session: BrowserSession, continue_url: str, *,
    referer: str = "https://auth.openai.com/email-verification",
) -> tuple[str, str]:
    """Navigate to the exact challenge page before posting the TOTP code."""
    target = urljoin("https://auth.openai.com/", str(continue_url or "").strip())
    parsed = urlparse(target)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "auth.openai.com"
        or not parsed.path.lower().startswith("/mfa-challenge")
    ):
        raise RuntimeError(
            f"[Codex] 邮箱 OTP 返回了不可信的 MFA 下一跳: {_safe_url_summary(target)}"
        )

    cookie_before = _auth_session_cookie_fingerprint(session)
    headers = session.get_auth_navigate_headers(
        referer=referer,
        user_initiated=False,
        target_origin="https://auth.openai.com",
    )
    headers["sec-fetch-site"] = "same-origin"
    resp = _with_net_retry(
        "进入 TOTP MFA 阶段",
        lambda: session.get(target, headers=headers, allow_redirects=True),
    )
    status = int(getattr(resp, "status_code", 0) or 0)
    final_url = str(getattr(resp, "url", "") or target)
    final_path = (urlparse(final_url).path or "/").lower()
    _sync_auth_document_context(session, resp, stage="mfa_challenge")
    cookie_after = _auth_session_cookie_fingerprint(session)
    logger.info(
        "[Codex] TOTP MFA 阶段预检：status=%s target=%s final=%s auth_cookie=%s -> %s",
        status,
        _safe_url_summary(target),
        _safe_url_summary(final_url),
        cookie_before,
        cookie_after,
    )

    body = _response_text(resp)[:2000]
    if (
        _is_oauth_session_invalid_response(body, status)
        or final_path in {"/log-in", "/login"}
        or final_path.startswith("/log-in/")
        or final_path.startswith("/login/")
    ):
        raise RuntimeError(
            f"[Codex] TOTP MFA 阶段授权会话失效 status={status}, "
            f"final={_safe_url_summary(final_url)}"
        )
    if status >= 400:
        raise RuntimeError(
            f"[Codex] TOTP MFA 阶段预检失败 status={status}, "
            f"final={_safe_url_summary(final_url)}: {body[:240]}"
        )
    if not final_path.startswith("/mfa-challenge"):
        raise RuntimeError(
            "[Codex] TOTP MFA 阶段未进入 challenge 页面: "
            f"final={_safe_url_summary(final_url)}"
        )

    session.codex_mfa_referer = final_url
    return final_url, _mfa_factor_id_from_url(final_url)


def _verify_totp_challenge(
    session: BrowserSession,
    *,
    secret: str,
    factor_id: str,
    referer: str,
) -> dict:
    try:
        code = totp_service.generate_totp_code(secret)
    except Exception as exc:
        raise RuntimeError("[Codex] 本地 TOTP secret 无法生成有效验证码") from exc

    cookie_before = _auth_session_cookie_fingerprint(session)
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/mfa/verify",
        {"id": factor_id, "type": "totp", "code": code},
        referer=referer,
    )
    status = int(getattr(resp, "status_code", 0) or 0)
    response_text = _response_text(resp)
    error_code = _extract_error_code(resp)
    if _is_oauth_session_invalid_response(response_text, status):
        raise RuntimeError(
            f"[Codex] TOTP MFA 验证时授权会话失效 status={status}: "
            f"{response_text[:240]}"
        )
    if status not in (200, 204) or error_code:
        raise CodexAuthResponseError(
            f"[Codex] TOTP MFA 验证失败 status={status}"
            f"{f' code={error_code}' if error_code else ''}: {response_text[:240]}",
            http_status=status, error_code=error_code,
        )

    payload = _resp_json(resp)
    page_type, continue_url, auth_session = _extract_auth_step(payload)
    try:
        location = resp.headers.get("location") or resp.headers.get("Location") or ""
    except Exception:
        location = ""
    if not continue_url and location:
        continue_url = str(location)
    if _auth_step_requires_mfa(page_type, continue_url):
        raise RuntimeError("[Codex] TOTP MFA 验证后仍停留在 challenge，验证码未被接受")

    _remember_auth_session(session, auth_session, source="totp")
    phone_required = _auth_step_requires_phone(page_type, continue_url)
    cookie_after = _auth_session_cookie_fingerprint(session)
    logger.info(
        "[Codex] TOTP MFA 验证通过，下一步=%s auth_cookie=%s -> %s",
        "add-phone" if phone_required else (page_type or _safe_url_summary(continue_url)),
        cookie_before,
        cookie_after,
    )
    if phone_required:
        _prepare_phone_step(session, continue_url)
    return {
        "page_type": page_type,
        "continue_url": continue_url,
        "auth_session": auth_session,
        "mfa_required": False,
        "phone_required": phone_required,
    }


def _complete_totp_mfa_challenge(session: BrowserSession, email: str, step: dict) -> dict:
    continue_url = str((step or {}).get("continue_url") or "").strip()
    challenge_factor_id = _mfa_factor_id_from_url(continue_url)
    secret, factor_id = _load_codex_totp_credential(email, challenge_factor_id)
    target = continue_url or (
        "https://auth.openai.com/mfa-challenge/" + quote(factor_id, safe="")
    )
    referer, navigated_factor_id = _prepare_mfa_step(session, target)
    if navigated_factor_id and not secrets.compare_digest(navigated_factor_id, factor_id):
        raise RuntimeError(
            "[Codex] MFA 页面 factor 与本地 active factor ID 不一致，请重新同步 2FA"
        )
    return _verify_totp_challenge(
        session,
        secret=secret,
        factor_id=factor_id,
        referer=referer,
    )


# ============================================================
# 步骤 4-5：手机号验证（接码，失败换号重试）
# ============================================================

def _sms_provider_name() -> str:
    """当前接码通道名，仅用于 Codex 流程日志。"""
    return str(sms_provider.runtime_setting("provider", getattr(_cfg, "SMS_PROVIDER", "smsbower")) or "smsbower").strip().lower()


def _sleep_before_phone_retry(attempt: int, max_retries: int, *, prefix: str = "[Codex]") -> None:
    """换号前随机等待，至少 3 秒，避免连续提交号码过快。"""
    if attempt >= max_retries:
        return
    seconds = random.uniform(3.0, 8.0)
    logger.info(f"{prefix} 换号前随机等待 {seconds:.1f} 秒")
    time.sleep(seconds)


def _do_phone_verification(session: BrowserSession) -> dict:
    """
    用接码平台拿号 → add-phone/send 发短信 → 收码 → phone-otp/validate。
    一个号收不到码或被 OpenAI 拒就取消换号，最多 SMS_MAX_RETRIES 次（热加载）。

    实际平台适配在 core.sms_provider：
        - SMS_PROVIDER="smsbower"：SMSBower handler_api.php（默认）
        - SMS_PROVIDER="luban"：复用 PayPal Luban 配置，服务使用 OpenAI
        - SMS_PROVIDER="grizzly"：GrizzlySMS handler_api.php
        - SMS_PROVIDER="l"：L_API.md 的 /take-phone 和 /fetch-code JSON 接口
        - SMS_PROVIDER="h"：H_API.md 的本地号码生命周期接口
    """
    http = sms_provider._http()
    max_retries = max(1, int(sms_provider.runtime_setting("max_retries", _cfg.SMS_MAX_RETRIES)))
    provider = _sms_provider_name()
    try:
        last_err = None
        for attempt in range(1, max_retries + 1):
            activation_id = None
            try:
                activation_id, phone = sms_provider.acquire_number(http)
                logger.info(
                    f"[Codex] 手机验证尝试 {attempt}/{max_retries}，"
                    f"provider={provider}, activation_id={activation_id}, 号码=+{phone}"
                )

                # 发短信
                send_resp = _post_json(
                    session,
                    "https://auth.openai.com/api/accounts/add-phone/send",
                    {"phone_number": f"+{phone}"},
                    referer=str(
                        getattr(session, "codex_phone_referer", "")
                        or "https://auth.openai.com/add-phone"
                    ),
                )
                send_text = _response_text(send_resp)
                send_advanced = _phone_send_advanced_to_otp(send_resp)
                send_reason = "" if send_advanced else _phone_failure_reason(
                    send_text, send_resp.status_code
                )
                if send_reason == 'oauth_session_invalid':
                    logger.warning(
                        f"[Codex] add-phone/send 检测到授权会话失效，status={send_resp.status_code}: "
                        f"{send_text[:240]}；停止换号并重建完整授权会话"
                    )
                    raise RuntimeError(
                        f"[Codex] add-phone/send 授权会话失效 status={send_resp.status_code}: "
                        f"{send_text[:240]}"
                    )
                if send_resp.status_code not in (200, 204) or send_reason:
                    # 号码无效 / 无法发送 / WhatsApp 通道 / 限流等 → 释放当前号并换号。
                    logger.warning(
                        f"[Codex] add-phone/send 未成功 reason={send_reason or 'unknown'}, "
                        f"status={send_resp.status_code}: {send_text[:240]}，换号重试"
                    )
                    sms_provider.cancel(activation_id, http, rejected=True)
                    _sleep_before_phone_retry(attempt, max_retries)
                    continue

                # 通知平台短信已发出（status=1）
                sms_provider.set_status(activation_id, 1, http=http)

                # 定时轮询接码平台获取短信。wait_for_sms_code 内部按 SMS_POLL_INTERVAL 轮询，
                # 最长等待 SMS_CODE_WAIT；超时立即取消当前号并换号。
                try:
                    logger.info(
                        f"[Codex] 短信已发送，开始轮询验证码 activation_id={activation_id}, "
                        f"wait={_cfg.SMS_CODE_WAIT}s, interval={_cfg.SMS_POLL_INTERVAL}s"
                    )
                    sms_code = sms_provider.wait_for_sms_code(activation_id, http)
                except sms_provider.SmsCodeTimeout:
                    logger.warning(f"[Codex] 号码 +{phone} 在 {_cfg.SMS_CODE_WAIT}s 内未收到短信，取消换号")
                    sms_provider.cancel(activation_id, http)
                    _sleep_before_phone_retry(attempt, max_retries)
                    continue

                # 验手机码
                val_resp = _post_json(
                    session,
                    "https://auth.openai.com/api/accounts/phone-otp/validate",
                    {"code": sms_code},
                    referer="https://auth.openai.com/phone-verification",
                )
                if val_resp.status_code != 200:
                    val_text = _response_text(val_resp)
                    val_reason = _phone_failure_reason(val_text, val_resp.status_code) or 'code_rejected'
                    if val_reason == 'oauth_session_invalid':
                        logger.warning(
                            f"[Codex] phone-otp/validate 检测到授权会话失效，status={val_resp.status_code}: "
                            f"{val_text[:240]}；停止换号并重建完整授权会话"
                        )
                        raise RuntimeError(
                            f"[Codex] phone-otp/validate 授权会话失效 status={val_resp.status_code}: "
                            f"{val_text[:240]}"
                        )
                    logger.warning(
                        f"[Codex] phone-otp/validate 失败 reason={val_reason}, status={val_resp.status_code}: "
                        f"{val_text[:240]}，换号重试"
                    )
                    sms_provider.cancel(activation_id, http, rejected=True)
                    _sleep_before_phone_retry(attempt, max_retries)
                    continue

                _page, _url, phone_auth_session = _extract_auth_step(_resp_json(val_resp))
                _remember_auth_session(session, phone_auth_session, source="phone_otp")
                # 成功
                metadata = sms_provider.activation_metadata(activation_id)
                sms_provider.complete(activation_id, http)
                logger.info("[Codex] 手机号验证通过")
                return {**metadata, "codex_phone_status": "verified"}

            except (sms_provider.SmsNoBalanceError, sms_provider.SmsBudgetExceededError):
                # 余额不足，重试无意义，直接抛
                if activation_id:
                    sms_provider.cancel(activation_id, http)
                raise
            except sms_provider.SmsProviderError as exc:
                last_err = exc
                logger.warning(f"[Codex] 接码尝试 {attempt} 失败：{exc}")
                if activation_id:
                    sms_provider.cancel(activation_id, http)
                _sleep_before_phone_retry(attempt, max_retries)
                continue
            except Exception:
                # OpenAI 请求若在号码领取后遇到代理/TLS/停止信号，也必须释放号码。
                # 异常继续上抛，由外层决定是否重建 OAuth 会话和更换代理。
                if activation_id:
                    sms_provider.cancel(activation_id, http)
                raise

        raise RuntimeError(
            f"[Codex] 手机号验证重试 {max_retries} 次仍失败（provider={provider}）"
            + (f"，最后错误：{last_err}" if last_err else "")
        )
    finally:
        http.close()


# ============================================================
# 步骤 5：选 workspace → 拿 callback code
# ============================================================

class CodexWorkspaceDataError(RuntimeError):
    """No usable workspace in the current OAuth transaction's local evidence."""

    error_code = "oauth_workspace_unavailable"


def _decode_auth_session_cookie(raw: str) -> dict:
    value = unquote(str(raw or "")).strip().strip('"')
    decoded = _decode_jwt_segment(value.split(".", 1)[0])
    return decoded if isinstance(decoded, dict) else {}


def _auth_session_cookie_candidates(session: BrowserSession) -> list[tuple[str, str, str]]:
    """Only consider unexpired cookies applicable to workspace/select."""
    cookies = getattr(getattr(session, "session", None), "cookies", None)
    jar = getattr(cookies, "jar", None)
    candidates = []
    seen_names = set()
    if jar is not None:
        for cookie in jar:
            name = str(getattr(cookie, "name", "") or "")
            if name not in _AUTH_SESSION_COOKIE_NAMES:
                continue
            seen_names.add(name)
            domain = str(getattr(cookie, "domain", "") or "").lower().lstrip(".")
            path = str(getattr(cookie, "path", "") or "/")
            endpoint = "/api/accounts/workspace/select"
            expired = getattr(cookie, "is_expired", None)
            if (
                domain not in {"auth.openai.com", "openai.com"}
                or not (path == endpoint or endpoint.startswith(path.rstrip("/") + "/"))
                or (callable(expired) and expired())
            ):
                continue
            raw = getattr(cookie, "value", None)
            if isinstance(raw, str) and raw:
                candidates.append((domain, name, raw))
    # Dictionary-only adapters have no domain metadata. Never reintroduce a
    # cookie rejected above through an unscoped Cookies.get call.
    if cookies is not None:
        for name in _AUTH_SESSION_COOKIE_NAMES:
            if name in seen_names:
                continue
            try:
                raw = cookies.get(name)
            except Exception:
                continue
            if isinstance(raw, str) and raw:
                candidates.append(("", name, raw))
    return sorted(candidates, key=lambda item: (
        0 if item[0] == "auth.openai.com" else 1,
        _AUTH_SESSION_COOKIE_NAMES.index(item[1]),
    ))


def _workspace_selection_data(session: BrowserSession) -> tuple[list[dict], str]:
    cached = getattr(session, "_codex_auth_session_payload", None)
    cached = cached if isinstance(cached, dict) else {}
    cached_records = None
    if isinstance(cached.get("workspaces"), list):
        cached_records = _workspace_records(cached)
        if cached_records:
            return cached_records, str(getattr(session, "_codex_auth_session_source", "json"))
    # Compatibility with sessions created by older code and test/adaptor
    # objects that expose only the response's workspace list.
    legacy = getattr(session, "_codex_auth_session_workspaces", None)
    if isinstance(legacy, list):
        records = _workspace_records({"workspaces": legacy})
        if records:
            return records, "auth_response"
    for _domain, _name, raw in _auth_session_cookie_candidates(session):
        payload = _decode_auth_session_cookie(raw)
        # A password/TOTP response can omit ``workspaces`` while the Set-Cookie
        # value is rotated to a newer session.  In that case the cookie is the
        # only current server evidence and must not be discarded merely
        # because the last JSON response carried an older session_id.  The
        # transaction is reset at bootstrap, so a decoded current cookie is
        # safe to use as the fallback source here.
        records = _workspace_records(payload)
        if records:
            return records, "auth_cookie"
    if cached_records is not None:
        # Preserve an explicit empty response only after checking whether the
        # current cookie carries a usable list (some responses set [] before
        # the rotated cookie is available to the client).
        return cached_records, str(getattr(session, "_codex_auth_session_source", "json"))
    return [], "missing"


def _get_workspace_id(session: BrowserSession, expected_workspace_id: str = "") -> str:
    """Choose only from server-provided records; never guess an account ID."""
    records, source = _workspace_selection_data(session)
    if not records:
        raise CodexWorkspaceDataError(
            "[Codex] 找不到 oai-client-auth-session cookie 中的可用工作区，认证响应亦无 workspaces"
        )
    if expected_workspace_id and not any(row["id"] == expected_workspace_id for row in records):
        raise CodexWorkspaceDataError("[Codex] 目标母号工作区不在授权列表中，已停止授权")
    wid = expected_workspace_id or records[0]["id"]
    logger.info("[Codex] 工作区选择：source=%s count=%s workspace_id=%s", source, len(records), wid)
    return wid


def _load_consent_workspaces(session: BrowserSession, state: str) -> str:
    """One bounded consent navigation in the same session; return a callback if supplied."""
    target = urljoin("https://auth.openai.com/", str(
        getattr(session, "_codex_consent_url", "") or "/sign-in-with-chatgpt/codex/consent"
    ))
    referer = str(getattr(session, "codex_mfa_referer", "") or "https://auth.openai.com/")
    for _ in range(_MAX_REDIRECTS):
        if _is_redirect_uri(target):
            _extract_code(target, state)
            return target
        parsed = urlparse(target)
        if (parsed.scheme != "https" or parsed.hostname != "auth.openai.com"
                or parsed.username or parsed.password or parsed.port not in (None, 443)):
            raise RuntimeError("[Codex] consent 跳转到非预期的授权地址")
        response = _with_net_retry(
            "读取 Codex consent 页面",
            lambda: session.get(target, headers=session.get_auth_navigate_headers(
                referer=referer, user_initiated=False,
            ), allow_redirects=False),
        )
        status = int(getattr(response, "status_code", 0) or 0)
        headers = getattr(response, "headers", {}) or {}
        location = headers.get("location") or headers.get("Location")
        if status in (301, 302, 303, 307, 308) and location:
            referer, target = target, urljoin(target, str(location))
            continue
        if not 200 <= status < 300:
            raise CodexAuthResponseError(
                f"[Codex] consent 页面请求失败 status={status}",
                http_status=status, error_code=_extract_error_code(response),
            )
        path = parsed.path.rstrip("/")
        if path in {"/log-in", "/login"} or path.startswith(("/log-in/", "/login/")):
            raise CodexAuthResponseError(
                "[Codex] consent 返回登录页，授权会话已失效", http_status=401, error_code="session_expired",
            )
        if path not in {"/workspace", "/sign-in-with-chatgpt/codex/consent"}:
            raise CodexWorkspaceDataError("[Codex] consent 尚未进入工作区选择页面")
        session._codex_consent_url = target
        _sync_auth_document_context(session, response, stage="consent_workspace")
        payload = _auth_session_from_ssr(str(getattr(response, "text", "") or ""))
        count = _remember_auth_session(session, payload, source="consent_ssr")
        logger.info("[Codex] consent 工作区恢复：ssr_count=%s auth_cookie=%s", count,
                    _auth_session_cookie_fingerprint(session))
        return ""
    raise RuntimeError("[Codex] consent 跳转次数超限")


def _select_workspace_and_get_callback(session: BrowserSession, state: str, expected_workspace_id: str = "") -> str:
    """
    POST workspace/select，然后跟随后续重定向/响应里的 URL 直到命中 localhost:1455 callback。
    返回完整 callback URL（含 code）。
    """
    try:
        wid = _get_workspace_id(session, expected_workspace_id)
    except CodexWorkspaceDataError:
        logger.info("[Codex] 本地工作区信息不足，读取当前 consent 页面恢复")
        callback = _load_consent_workspaces(session, state)
        if callback:
            return callback
        # The GET may set the cookie without embedding SSR data. Re-read both.
        wid = _get_workspace_id(session, expected_workspace_id)
    session._codex_selected_workspace_id = wid
    resp = _post_json(
        session,
        "https://auth.openai.com/api/accounts/workspace/select",
        {"workspace_id": wid},
        referer=str(getattr(session, "_codex_consent_url", "") or
                    "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"),
    )
    status = int(getattr(resp, "status_code", 0) or 0)
    if not 200 <= status < 400 or _extract_error_code(resp):
        raise CodexAuthResponseError(
            f"[Codex] 工作区选择被拒绝 status={status}",
            http_status=status, error_code=_extract_error_code(resp),
        )

    # 1) 直接带 Location 头命中 callback
    loc = resp.headers.get("location") or resp.headers.get("Location")
    if loc and _is_redirect_uri(loc):
        return loc

    # 2) 响应 JSON 里给了下一步 URL（continue_url / redirect_url / url / next）
    data = _resp_json(resp)
    next_url = None
    for key in ("redirect_url", "continue_url", "url", "next", "location"):
        v = data.get(key)
        if isinstance(v, str) and v:
            next_url = v
            break

    # 3) 没给 URL 但有 Location（非 callback）→ 从 Location 起跟
    if not next_url and loc:
        next_url = loc

    if not next_url:
        raise RuntimeError(
            f"[Codex] workspace/select 后找不到下一跳 URL: status={resp.status_code}, "
            f"body={(resp.text or '')[:300]}"
        )

    # 跟随重定向链直到命中 callback
    return _follow_until_callback(session, next_url, state)


def _follow_until_callback(session: BrowserSession, url: str, state: str) -> str:
    """从给定 URL 起逐跳跟随，命中 localhost:1455 callback 时返回其 Location。"""
    if url.startswith("/"):
        url = "https://auth.openai.com" + url
    for hop in range(_MAX_REDIRECTS):
        if _is_redirect_uri(url):
            return url
        headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/")
        resp = session.get(url, headers=headers, allow_redirects=False)
        loc = resp.headers.get("location") or resp.headers.get("Location")
        logger.debug(f"[Codex] callback 跟随 hop {hop}: status={getattr(resp,'status_code','')}, location={loc}")
        if loc is None:
            raise RuntimeError(
                f"[Codex] 跟随中断，未命中 callback: url={url}, "
                f"status={getattr(resp,'status_code','')}, body={(resp.text or '')[:200]}"
            )
        if _is_redirect_uri(loc):
            return loc
        url = loc if loc.startswith("http") else ("https://auth.openai.com" + loc)
    raise RuntimeError(f"[Codex] 跟随 callback 超过 {_MAX_REDIRECTS} 跳")


# ============================================================
# 换 token（对照 CLIProxyAPI ExchangeCodeForTokensWithRedirect）—— 未改动
# ============================================================

def exchange_codex_token(session: BrowserSession, code: str, code_verifier: str) -> dict:
    """用 authorization code 换 token。"""
    data = {
        "grant_type": "authorization_code",
        "client_id": _cfg.CODEX_CLIENT_ID,
        "code": code,
        "redirect_uri": _cfg.CODEX_REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    base = session._get_common_headers()
    base.update(headers)
    headers = base

    logger.info("[Codex] 用 authorization code 换 token...")
    resp = session.post(_cfg.CODEX_TOKEN_URL, headers=headers, data=urlencode(data))
    http_status = resp.status_code
    if http_status != 200:
        raise RuntimeError(
            f"[Codex] 换 token 失败 status={http_status}: {(resp.text or '')[:300]}"
        )
    token_resp = resp.json()
    if not token_resp.get("access_token"):
        raise RuntimeError(f"[Codex] token 响应缺少 access_token: {token_resp}")
    logger.info(
        f"[Codex] 换 token 成功，expires_in={token_resp.get('expires_in')}, "
        f"access_token={token_resp['access_token'][:16]}..."
    )
    return token_resp


# ============================================================
# 解析 id_token / 落盘 —— 未改动
# ============================================================

def _parse_id_token(id_token: str) -> dict:
    """base64 解码 JWT payload（不验签），抽 email / account_id / plan_type。"""
    if not id_token:
        return {}
    try:
        parts = id_token.split(".")
        if len(parts) < 2:
            return {}
        claims = _decode_jwt_segment(parts[1])
    except Exception as exc:
        logger.warning(f"[Codex] id_token 解析失败: {exc}")
        return {}

    auth_claim = claims.get("https://api.openai.com/auth", {}) or {}
    profile_claim = claims.get("https://api.openai.com/profile", {}) or {}
    # OpenAI 新版 id_token 的 email 在顶层 claim；旧版/CLIProxyAPI 实现里在 profile_claim。
    # 顶层优先，否则回退 profile_claim，避免落盘的 codex-邮箱.json 里 email 字段为空。
    email_value = claims.get("email") or profile_claim.get("email", "")
    return {
        "email": email_value,
        "account_id": auth_claim.get("chatgpt_account_id", ""),
        "plan_type": auth_claim.get("chatgpt_plan_type", ""),
    }


def build_codex_storage(token_resp: dict, id_claims: dict) -> dict:
    """组装 CLIProxyAPI CodexTokenStorage JSON 结构。"""
    expires_in = token_resp.get("expires_in", 0) or 0
    expired_dt = datetime.now(timezone.utc) + _timedelta_seconds(expires_in)
    last_refresh_dt = datetime.now(timezone.utc)
    return {
        "id_token": token_resp.get("id_token", ""),
        "access_token": token_resp.get("access_token", ""),
        "refresh_token": token_resp.get("refresh_token", ""),
        "account_id": id_claims.get("account_id", ""),
        "last_refresh": last_refresh_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "email": id_claims.get("email", ""),
        "type": "codex",
        "expired": expired_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _timedelta_seconds(seconds: int):
    from datetime import timedelta
    return timedelta(seconds=int(seconds))


def _credential_file_name(email: str, plan_type: str) -> str:
    """对照 CLIProxyAPI filename.go：无 plan→codex-{email}.json，否则带 plan 后缀。"""
    def safe_part(value: str, fallback: str) -> str:
        text = re.sub(r"[^A-Za-z0-9@._+-]+", "_", str(value or "").strip())
        text = text.strip(".")
        return text[:180] or fallback

    email = safe_part(email, "unknown")
    plan = safe_part((plan_type or "").strip().lower(), "")
    if plan == "":
        return f"codex-{email}.json"
    return f"codex-{email}-{plan}.json"


def save_codex_credential(storage: dict, email: str, plan_type: str) -> Path:
    """落盘到 {PROJECT_ROOT}/{CODEX_OUTPUT_DIRNAME}/codex-{email}.json。"""
    out_dir = _PROJECT_ROOT / _cfg.CODEX_OUTPUT_DIRNAME
    out_dir.mkdir(parents=True, exist_ok=True)
    fname = _credential_file_name(email, plan_type)
    path = out_dir / fname
    if not path.resolve().is_relative_to(out_dir.resolve()):
        raise ValueError("Codex 凭证路径越出输出目录")
    path.write_text(
        json.dumps(storage, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def _extract_cpa_auth_json(payload: dict) -> dict | None:
    """
    尝试从 CPA oauth-callback 响应里提取完整授权文件。
    不同 CPA 版本字段名可能不同；只要看起来是 codex auth json 就落本地。
    """
    if not isinstance(payload, dict):
        return None
    candidates = [
        payload.get("auth_json"),
        payload.get("authJson"),
        payload.get("auth"),
        payload.get("auth_file"),
        payload.get("authFile"),
        payload.get("file"),
        payload.get("data"),
    ]
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    candidates.extend([
        data.get("auth_json"),
        data.get("authJson"),
        data.get("auth"),
        data.get("auth_file"),
        data.get("authFile"),
        data.get("file"),
    ])
    for item in candidates:
        if isinstance(item, dict) and (
            item.get("type") == "codex"
            or item.get("access_token")
            or item.get("refresh_token")
            or item.get("id_token")
        ):
            return item
    return None


def _save_cpa_local_record(
    *,
    email: str,
    callback_url: str,
    auth_url: str,
    state: str,
    submit_payload: dict,
) -> Path | None:
    """
    本地记录 CPA 授权结果：
      1) 如果 CPA 返回完整 auth json，保存为可用 codex-邮箱[-plan].json；
      2) 否则按配置保存 callback 提交回执，便于追踪 CPA 侧授权文件。
    """
    auth_json = _extract_cpa_auth_json(submit_payload)
    if auth_json:
        effective_email = auth_json.get("email") or email
        plan = auth_json.get("plan_type") or auth_json.get("chatgpt_plan_type") or ""
        return save_codex_credential(auth_json, effective_email, plan)

    if not bool(getattr(_cfg, "CPA_SAVE_CALLBACK_RECEIPT", True)):
        return None

    out_dir = _PROJECT_ROOT / _cfg.CODEX_OUTPUT_DIRNAME
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_email = (email or "unknown").strip().replace("/", "_").replace("\\", "_")
    path = out_dir / f"codex-{safe_email}-cpa-callback.json"
    record = {
        "type": "codex_cpa_callback",
        "email": email,
        "state": state,
        "auth_url": auth_url,
        "callback_url": callback_url,
        "cpa_management_origin": _cpa_management_origin(),
        "cpa_submit_response": submit_payload,
        "submitted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "授权地址由 CPA 生成；callback 已提交给 CPA。若 CPA 响应未包含 token，本文件为本地回执记录。",
    }
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _save_sub2_local_record(
    *,
    email: str,
    callback_url: str,
    auth_url: str,
    state: str,
    submit_payload: dict,
) -> Path | None:
    """本地记录 sub2 授权结果；若 sub2 返回完整 auth json，则保存为可用 codex 凭证。"""
    auth_json = _extract_cpa_auth_json(submit_payload)
    if auth_json:
        effective_email = auth_json.get("email") or email
        plan = auth_json.get("plan_type") or auth_json.get("chatgpt_plan_type") or ""
        return save_codex_credential(auth_json, effective_email, plan)

    if not bool(getattr(_cfg, "CPA_SAVE_CALLBACK_RECEIPT", True)):
        return None

    out_dir = _PROJECT_ROOT / _cfg.CODEX_OUTPUT_DIRNAME
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_email = (email or "unknown").strip().replace("/", "_").replace("\\", "_")
    path = out_dir / f"codex-{safe_email}-sub2-callback.json"
    try:
        sub2_origin = _sub2_codex_base()
    except Exception:
        sub2_origin = ""
    record = {
        "type": "codex_sub2_callback",
        "email": email,
        "state": state,
        "auth_url": auth_url,
        "callback_url": callback_url,
        "sub2_origin": sub2_origin,
        "sub2_submit_response": submit_payload,
        "submitted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "授权地址由 sub2 生成；callback 已上传给 sub2。若 sub2 响应未包含 token，本文件为本地回执记录。",
    }
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


# ============================================================
# 入口
# ============================================================

def _run_codex_oauth_once(
    email: str,
    otp_provider=None,
    proxy: str | None = None,
    force: bool = False,
    _cpa_reauth_round: int = 1,
    auth_source: str | None = None,
    expected_workspace_id: str = "",
) -> dict:
    """
    注册成功后的 Codex OAuth 授权入口（全新 session + 接码方案）。

    不复用注册的 session：内部新建干净 BrowserSession，从头登录该邮箱，
    走 邮箱 OTP → 手机短信验证 → 选 workspace → 拿 code → 换 token → 落盘。

    Args:
        email: 已注册成功的账号邮箱
        otp_provider: 邮箱 OTP 获取回调 fn(email, after_ts)->code，默认用 wait_for_otp
        proxy: 代理（不传从 PROXY_POOL 抽）
        force: True 时跳过 ENABLE_CODEX_AUTO 开关限制，供手动补跑使用
        auth_source: 覆盖 CODEX_AUTH_URL_SOURCE，取 cpa / sub2 / local。
            WebUI 的注册和补跑都传 "local"（本地 PKCE），CLI 不传则读配置。

    Returns:
        结构化结果 dict。任何异常都被吞掉转 status=failed，不向上抛，不影响注册主流程。
    """
    if not force and not _cfg.ENABLE_CODEX_AUTO:
        return _codex_result(status="skipped", message="ENABLE_CODEX_AUTO=False")
    if not email:
        return _codex_result(status="skipped", message="email 为空")

    # 这里固定走协议（curl_cffi）。roxy/cloak 注册时是在自己已经打开的浏览器里
    # 就地调 run_roxy_codex_oauth，压根不经过这个函数，所以不需要再分发一次。
    if otp_provider is None:
        from core.email_provider import wait_for_otp as otp_provider

    session = None
    stage = "session_init"
    try:
        browser_family = str(
            getattr(_cfg, "CODEX_BROWSER_FAMILY", "firefox") or "firefox"
        ).strip().lower()
        session = BrowserSession(proxy=proxy, browser_family=browser_family)
        profile = getattr(session, "browser_profile", {}) or {}
        logger.info(
            "[Codex] HTTP 指纹：family=%s impersonate=%s ua=%s",
            profile.get("browser_family") or browser_family,
            profile.get("impersonate") or getattr(session, "impersonate", "unknown"),
            profile.get("user_agent") or "unknown",
        )
        logger.info(f"[Codex] 开始授权（全新 session）：{email}")

        def check_flow_stop() -> None:
            _check_codex_flow_stop(email)

        # 1. 授权地址
        #    默认由 CPA 生成（本地不生成 PKCE/state）；local 模式保留旧代码用于兼容。
        stage = "authorization_url"
        selected_auth_source = str(auth_source or _codex_auth_url_source()).strip().lower()
        cpa_auth = None
        code_verifier = None
        code_challenge = None
        auth_url = None
        if selected_auth_source == "cpa":
            cpa_auth = _request_cpa_authorize_url()
            state = cpa_auth["state"]
            auth_url = cpa_auth["auth_url"]
            logger.info(f"[Codex] 当前使用 CPA 授权地址: {auth_url}")
        elif selected_auth_source == "sub2":
            sub2_auth = _request_sub2_authorize_url()
            state = sub2_auth["state"]
            auth_url = sub2_auth["auth_url"]
            logger.info(f"[Codex] 当前使用 sub2 授权地址: {auth_url}")
        elif selected_auth_source == "local":
            code_verifier, code_challenge = _generate_pkce()
            state = _generate_state()
            logger.info("[Codex] 当前使用本地 PKCE 生成授权地址，完整 URL 将在 bootstrap 阶段输出")
        else:
            raise RuntimeError(f"[Codex] 不支持的 CODEX_AUTH_URL_SOURCE={selected_auth_source!r}")

        # 2. 网络预检 + 建立会话。预检不携带邮箱，不触发 OTP；
        #    真正烧邮箱的 authorize/continue 只在预检成功后执行。
        stage = "network_preflight"
        check_flow_stop()
        network_preflight(session)
        human_delay("navigate")

        stage = "bootstrap"
        check_flow_stop()
        _bootstrap_authorize(session, state, code_challenge, auth_url=auth_url)
        human_delay("navigate")

        # 3. 提交邮箱（触发邮箱 OTP）
        _capture_otp_baseline(email)
        otp_after_ts = time.time()
        stage = "email_submit"
        check_flow_stop()
        _submit_email(session, email)
        human_delay("form")

        # 4. A rejected OTP may be a delayed delivery from an earlier request.
        # Keep this challenge alive while waiting for a different message.
        rejected_email_codes: set[str] = set()
        max_email_otp_attempts = 3
        for email_otp_attempt in range(1, max_email_otp_attempts + 1):
            stage = "email_otp_wait"
            logger.info(f"[Codex] 等待邮箱 OTP：{email}（第 {email_otp_attempt}/{max_email_otp_attempts} 次）")
            try:
                check_flow_stop()
                email_otp = _read_email_otp(
                    otp_provider, email, after_ts=otp_after_ts, rejected_codes=rejected_email_codes,
                )
                check_flow_stop()
            except Exception as exc:
                check_flow_stop()
                if email_otp_attempt >= max_email_otp_attempts:
                    raise
                if not _email_otp_error_allows_resend(exc):
                    logger.warning(
                        "[Codex] 邮箱取码接口持续故障，不重复触发 OTP，也不切换 OpenAI 代理：%s: %s",
                        type(exc).__name__,
                        str(exc)[:240],
                    )
                    raise
                if rejected_email_codes:
                    logger.warning(
                        "[Codex][OTP] 错码后尚未收到其他验证码，保留当前会话继续等待，不再次发码（下一轮 %s/%s）",
                        email_otp_attempt + 1, max_email_otp_attempts,
                    )
                    continue
                logger.warning(
                    "[Codex] 一直未收到邮箱 OTP，重新提交邮箱触发重发后继续等待（下一轮 %s/%s）：%s: %s",
                    email_otp_attempt + 1,
                    max_email_otp_attempts,
                    type(exc).__name__,
                    str(exc)[:180],
                )
                _capture_otp_baseline(email)
                otp_after_ts = time.time()
                stage = "email_submit"
                _submit_email(session, email)
                human_delay("api")
                continue
            if email_otp in rejected_email_codes:
                # Some providers allow a previously seen numeric code if its timestamp changes.
                # An explicit rejection in this challenge must never be submitted again.
                if email_otp_attempt >= max_email_otp_attempts:
                    raise RuntimeError("[Codex] 邮箱持续返回已被拒绝的验证码，未重复提交")
                logger.warning("[Codex][OTP] 忽略已被拒绝的验证码，继续等待其他邮件（%s/%s）", email_otp_attempt, max_email_otp_attempts)
                human_delay("api")
                continue
            logger.info("[Codex] 邮箱 OTP 已收到，准备验证（%s/%s）", email_otp_attempt, max_email_otp_attempts)
            human_delay("otp_input")
            stage = "email_otp_submit"
            check_flow_stop()
            try:
                auth_step = _submit_email_otp_step(session, email_otp)
            except CodexAuthResponseError as exc:
                if exc.error_code != "wrong_email_otp_code" or exc.http_status not in (400, 401):
                    raise
                rejected_email_codes.add(email_otp)
                if email_otp_attempt >= max_email_otp_attempts:
                    raise
                logger.warning(
                    "[Codex][OTP] 服务端拒绝当前验证码，已排除；保留当前会话等待其他邮件，不重新发码（下一轮 %s/%s）",
                    email_otp_attempt + 1, max_email_otp_attempts,
                )
                continue
            break
        human_delay("api")

        mfa_verified = False
        if auth_step.get("mfa_required"):
            stage = "mfa"
            check_flow_stop()
            auth_step = _complete_totp_mfa_challenge(session, email, auth_step)
            mfa_verified = True
            human_delay("api")

        # 5. 仅在 authorize 状态明确进入 add-phone 时接码。
        phone_required = bool(auth_step.get("phone_required"))
        sms_metadata = {"codex_phone_status": "not_required"}
        if phone_required:
            stage = "phone"
            check_flow_stop()
            sms_metadata = _do_phone_verification(session)
            human_delay("post_auth")
        else:
            logger.info("[Codex] 当前授权未要求手机验证，跳过接码")

        # 6. 选 workspace → 拿 callback code。部分响应虽然没有显式返回
        # add-phone marker，但在手机验证前不会下发 workspace cookie；仅对这个
        # 明确状态做一次回退，其他 workspace 错误继续原样抛出。
        stage = "workspace"
        consent_candidate = str((auth_step or {}).get("continue_url") or "").strip()
        consent_path = urlparse(urljoin("https://auth.openai.com/", consent_candidate)).path.rstrip("/")
        if consent_path in {"/workspace", "/sign-in-with-chatgpt/codex/consent"}:
            session._codex_consent_url = urljoin("https://auth.openai.com/", consent_candidate)
        try:
            check_flow_stop()
            callback_url = _select_workspace_and_get_callback(session, state, **({"expected_workspace_id": expected_workspace_id} if expected_workspace_id else {}))
        except RuntimeError as exc:
            missing_workspace = any(marker in str(exc) for marker in (
                "找不到 oai-client-auth-session cookie",
                "cookie 里无 workspaces 字段",
            ))
            if phone_required or mfa_verified or not missing_workspace:
                raise
            logger.info("[Codex] 邮箱 OTP 响应未标记 add-phone，但 workspace 尚未建立，进入按需手机验证")
            stage = "phone"
            check_flow_stop()
            _prepare_phone_step(session)
            sms_metadata = _do_phone_verification(session)
            phone_required = True
            human_delay("post_auth")
            stage = "workspace"
            callback_url = _select_workspace_and_get_callback(session, state, **({"expected_workspace_id": expected_workspace_id} if expected_workspace_id else {}))
        code = _extract_code(callback_url, state)
        logger.info(f"[Codex] 已拿到 authorization code：{code[:24]}...")

        # 7A. CPA 模式：把 callback URL 交给 CPA，由 CPA 持有 verifier 并完成换 token / 写 auth。
        #     本地不再用 code 换 token；仅保存 CPA 返回的授权文件或回调回执。
        if selected_auth_source == "cpa":
            stage = "callback_submit"
            check_flow_stop()
            submit_payload = _submit_cpa_callback(callback_url)
            path = _save_cpa_local_record(
                email=email,
                callback_url=callback_url,
                auth_url=auth_url or "",
                state=state,
                submit_payload=submit_payload,
            )
            msg = submit_payload.get("message") or submit_payload.get("status_message") or "CPA callback submitted"
            logger.info(f"[Codex][CPA] 成功：{email}，{msg}，本地记录={path or 'disabled'}")
            return _codex_result(
                status="success",
                ok=True,
                email=email,
                file_path=str(path) if path else None,
                callback_url=callback_url,
                message=str(msg),
            )

        # 7A-sub2. sub2 模式：把 callback URL 上传给 sub2。
        if selected_auth_source == "sub2":
            stage = "callback_submit"
            check_flow_stop()
            submit_payload = _submit_sub2_callback(
                callback_url,
                session_id=(sub2_auth or {}).get("session_id", ""),
                redirect_uri=(parse_qs(urlparse(auth_url or "").query).get("redirect_uri") or [""])[0],
            )
            path = _save_sub2_local_record(
                email=email,
                callback_url=callback_url,
                auth_url=auth_url or "",
                state=state,
                submit_payload=submit_payload,
            )
            msg = submit_payload.get("message") or submit_payload.get("status_message") or "sub2 callback uploaded"
            logger.info(f"[Codex][sub2] 成功：{email}，{msg}，本地记录={path or 'disabled'}")
            return _codex_result(
                status="success",
                ok=True,
                email=email,
                file_path=str(path) if path else None,
                callback_url=callback_url,
                message=str(msg),
            )

        # 7B. local 模式：保留旧实现，用本地 verifier 换 token 并保存 CPA 兼容授权文件。
        if not code_verifier:
            raise RuntimeError("[Codex] local 模式缺少 code_verifier")
        stage = "token_exchange"
        check_flow_stop()
        token_resp = exchange_codex_token(session, code, code_verifier)
        refresh_token = str(token_resp.get("refresh_token") or "").strip()
        if not refresh_token:
            raise RuntimeError("[Codex] token 响应缺少 refresh_token")

        # 8. 解析 id_token + 落盘
        id_claims = _parse_id_token(token_resp.get("id_token", ""))
        if expected_workspace_id and id_claims.get("account_id") != expected_workspace_id:
            raise RuntimeError("[Codex] OAuth 返回的工作区与目标母号不一致，未保存凭证")
        effective_email = id_claims.get("email") or email
        if expected_workspace_id and effective_email.casefold() != email.casefold():
            raise RuntimeError("[Codex] OAuth 邮箱不一致，未保存凭证")
        storage = build_codex_storage(token_resp, id_claims)
        check_flow_stop()
        path = save_codex_credential(storage, effective_email, id_claims.get("plan_type", ""))

        logger.info(
            f"[Codex] 成功：{effective_email}，plan={id_claims.get('plan_type') or 'unknown'}, "
            f"account_id={id_claims.get('account_id') or 'unknown'}, 已保存到 {path}"
        )
        return _codex_result(
            status="success",
            ok=True,
            email=effective_email,
            file_path=str(path),
            callback_url=callback_url,
            message=f"plan={id_claims.get('plan_type') or 'unknown'}",
            refresh_token=refresh_token,
            credential=storage,
            **sms_metadata,
        )
    except AccountUnusableError as exc:
        logger.warning(f"[Codex] 账号已废（{exc.error_code}）：{email}")
        return _codex_result(
            status="deactivated",
            email=email,
            message=f"账号已废（{exc.error_code}）",
        )
    except sms_provider.SmsBudgetExceededError as exc:
        logger.warning("[Codex] 批次短信预算已耗尽：%s", exc)
        return _codex_result(
            status="failed",
            email=email,
            message=str(exc)[:500],
            failure_stage="sms_budget",
        )
    except Exception as exc:
        logger.warning(f"[Codex] 失败：{email}，{type(exc).__name__}: {str(exc)[:200]}")
        logger.debug("[Codex] 失败详情:", exc_info=True)
        return _codex_result(
            status="failed",
            email=email,
            message=f"{type(exc).__name__}: {str(exc)[:200]}",
            failure_stage=stage,
        )
    finally:
        if session is not None:
            try:
                session.session.close()
            except Exception:
                logger.debug("[Codex] 关闭协议会话失败", exc_info=True)


def run_codex_oauth(
    email: str,
    otp_provider=None,
    proxy: str | None = None,
    force: bool = False,
    _cpa_reauth_round: int = 1,
    auth_source: str | None = None,
    login_mode: str = "email_otp",
    expected_workspace_id: str = "",
    auto_retry: bool = True,
) -> dict:
    """执行 Codex OAuth，并在出口/会话故障时用全新 Session 整轮恢复。"""
    if login_mode not in {"email_otp", "password_totp"}:
        raise ValueError("不支持的 Codex 登录模式")
    password_login = None
    if login_mode == "password_totp":
        from core import codex_password_totp as password_login
    flow_max_attempts = max(1, int(getattr(_cfg, "CODEX_FLOW_MAX_ATTEMPTS", 3) or 3))
    preflight_max_attempts = max(
        1,
        int(getattr(_cfg, "CODEX_PROXY_PREFLIGHT_MAX_ATTEMPTS", 10) or 10),
    )
    base_delay = max(0.0, float(getattr(_cfg, "CODEX_FLOW_RETRY_DELAY", 2.0) or 0.0))
    preflight_delay = max(
        0.0,
        float(getattr(_cfg, "CODEX_PROXY_PREFLIGHT_RETRY_DELAY", 0.5) or 0.0),
    )
    current_proxy = _initial_codex_proxy(proxy)
    attempted_proxies: set[str] = set()
    last_result = _codex_result(status="failed", email=email, message="Codex OAuth 未执行")
    attempt = 0
    preflight_failures = 0
    flow_failures = 0

    while True:
        attempt += 1
        _check_codex_flow_stop(email)
        attempted_proxies.add(current_proxy)
        logger.info(
            "[Codex][恢复] 完整授权会话 %s，出口=%s（代理预检失败=%s/%s，业务恢复失败=%s/%s）",
            attempt,
            _mask_proxy(current_proxy),
            preflight_failures,
            preflight_max_attempts,
            flow_failures,
            flow_max_attempts,
        )
        try:
            run_once = password_login.run_once if password_login else _run_codex_oauth_once
            result = run_once(
                email,
                otp_provider=otp_provider,
                proxy=current_proxy,
                force=force,
                _cpa_reauth_round=_cpa_reauth_round,
                auth_source=auth_source,
                **({"expected_workspace_id": expected_workspace_id} if expected_workspace_id else {}),
            )
        except Exception as exc:
            result = _codex_result(
                status="failed",
                email=email,
                message=f"{type(exc).__name__}: {str(exc)[:200]}",
                failure_stage="session_init",
            )
        if not isinstance(result, dict):
            result = _codex_result(
                status="failed",
                email=email,
                message="Codex OAuth 未返回结构化结果",
                failure_stage="unknown",
            )
        result = dict(result)
        result["oauth_attempts"] = attempt
        last_result = result

        if not auto_retry:
            # Team-only authorization retries are bounded by the persistent
            # coordinator; do not multiply them by this recovery loop.
            return result
        reason = password_login.retry_reason(result) if password_login else _oauth_failure_retry_reason(result)
        if not reason:
            return result

        next_proxy = _next_codex_proxy(
            requested_proxy=proxy,
            current_proxy=current_proxy,
            attempted_proxies=attempted_proxies,
        )
        changed = next_proxy != current_proxy
        stage = str(result.get("failure_stage") or "unknown").strip().lower()
        is_preflight_proxy_failure = (
            changed
            and stage in {"session_init", "network_preflight", "bootstrap"}
            and reason in {"network", "edge_rejected", "upstream_http"}
        )
        if is_preflight_proxy_failure:
            preflight_failures += 1
            exhausted = preflight_failures >= preflight_max_attempts
            delay = preflight_delay
            retry_scope = "proxy_preflight"
            retry_progress = f"代理候选 {preflight_failures + 1}/{preflight_max_attempts}"
        else:
            flow_failures += 1
            exhausted = flow_failures >= flow_max_attempts
            delay = base_delay * flow_failures
            retry_scope = "oauth_flow"
            retry_progress = f"业务恢复 {flow_failures + 1}/{flow_max_attempts}"

        if exhausted:
            result["retry_exhausted"] = True
            result["retry_reason"] = reason
            result["retry_scope"] = retry_scope
            logger.warning(
                "[Codex][恢复] 重试已耗尽：attempt=%s scope=%s stage=%s reason=%s "
                "proxy_failures=%s/%s flow_failures=%s/%s",
                attempt,
                retry_scope,
                stage,
                reason,
                preflight_failures,
                preflight_max_attempts,
                flow_failures,
                flow_max_attempts,
            )
            return result

        logger.warning(
            "[Codex][恢复] 当前完整会话不可继续：stage=%s reason=%s scope=%s；%s，"
            "%.1fs 后重建会话（%s）",
            stage,
            reason,
            retry_scope,
            (
                f"切换出口 {_mask_proxy(current_proxy)} -> {_mask_proxy(next_proxy)}"
                if changed
                else f"复用端点 {_mask_proxy(current_proxy)}"
            ),
            delay,
            retry_progress,
        )
        _sleep_codex_retry(delay, email)
        current_proxy = next_proxy

    return last_result
