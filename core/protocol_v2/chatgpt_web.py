"""ChatGPT Web / NextAuth 纯协议登录。

目标：拿到 `chatgpt.com/backend-api` 可用的 Web accessToken。

这条链路不是 Codex/CLI OAuth，也不是 platform OAuth：

  1. chatgpt.com `/api/auth/session` + `/api/auth/csrf` 初始化 NextAuth cookie/state
  2. POST `/api/auth/signin/openai` 拿 auth.openai.com authorize URL
  3. auth.openai.com 走邮箱 + 密码（必要时 email OTP）
  4. GET `https://chatgpt.com/api/auth/callback/openai?...`
  5. 从 `https://chatgpt.com/api/auth/session` 读取 Web `accessToken`

加入 workspace 后，调用：

  GET /api/auth/session?exchange_workspace_token=true&workspace_id=...&reason=...

重新换 workspace-scoped accessToken。
"""

from __future__ import annotations

import base64
import asyncio
import json
import secrets
import string
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

import httpx

from .core.http_client import (
    AUTH_BASE,
    build_client,
    json_headers,
    nav_headers,
    request_with_retry,
    set_oai_did_cookie,
    chatgpt_frontend_headers,
)
from core.ces_telemetry import (
    emit_async_anonymous,
    emit_async_authenticated,
    emit_async_login_web_stage,
    emit_async_signup,
)
from .core.pkce import new_device_id
from .core.profile import Profile, random_profile
from .core.sentinel import SentinelGenerator
from .flow import (
    EmailOtpInvalidError,
    _create_account,
    _gen_birthday,
    _gen_password,
    _kickoff_email_otp,
    _maybe_begin_otp_generation,
    _maybe_mark_bad_otp,
    _maybe_mark_otp_send_started,
    _maybe_prime_otp_fetcher,
    _maybe_wait_current_otp_generation,
    _password_verify,
    _send_email_otp,
    _send_passwordless_otp,
    _user_register,
    _validate_email_otp,
)

CHATGPT_BASE = "https://chatgpt.com"
WEB_PROVIDER_ID = "openai"
WEB_CALLBACK_URL = f"{CHATGPT_BASE}/api/auth/callback/{WEB_PROVIDER_ID}"

OtpFetcher = Callable[[str], Awaitable[str]]


@dataclass(slots=True)
class ChatGPTWebLoginResult:
    email: str
    access_token: str
    session_token: str
    expires_in: int
    chatgpt_account_id: str
    chatgpt_user_id: str
    plan_type: str
    sub: str
    auth_provider: str = "openai"
    id_token: str = ""
    refresh_token: str = ""
    device_id: str = ""
    duration_seconds: float = 0.0
    proxy_used: Optional[str] = None
    user: dict[str, Any] = field(default_factory=dict)
    account: dict[str, Any] = field(default_factory=dict)
    password_set: bool = True
    signup_mode: str = ""


def _snippet(text: str, limit: int = 300) -> str:
    text = str(text or "").replace("\n", " ").strip()
    return text[:limit]


async def _emit_login_web_stage_safely(
    client: Any,
    profile: Profile,
    device_id: str,
    stage: str,
    *,
    log: Callable[[str], None],
    scope: str,
) -> None:
    """上报真实到达的 Login Web 阶段；失败不改变注册/登录主流程。"""
    try:
        await emit_async_login_web_stage(client, profile, device_id, stage)
    except Exception as exc:  # noqa: BLE001
        log(
            f"📡 [{scope}] Login Web {stage} 遥测跳过："
            f"{type(exc).__name__}: {str(exc)[:120]}"
        )


def _jwt_claims(token: str) -> dict[str, Any]:
    if not token:
        return {}
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    pad = "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + pad).decode("utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def _pick_code_from_url(raw_url: str) -> str:
    if not raw_url:
        return ""
    try:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(raw_url).query)
        return (qs.get("code") or [""])[0]
    except Exception:  # noqa: BLE001
        return ""


def _is_web_callback(raw_url: str) -> bool:
    if not raw_url:
        return False
    try:
        parsed = urllib.parse.urlparse(raw_url)
    except Exception:  # noqa: BLE001
        return False
    return (
        parsed.scheme == "https"
        and parsed.netloc == "chatgpt.com"
        and parsed.path == "/api/auth/callback/openai"
        and bool(_pick_code_from_url(raw_url))
    )


def _parse_device_id(raw_url: str) -> str:
    try:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(raw_url).query)
        return (qs.get("device_id") or [""])[0]
    except Exception:  # noqa: BLE001
        return ""


def _workspace_ids_from_cookie(client: httpx.AsyncClient) -> list[str]:
    out: list[str] = []
    for cookie in client.cookies.jar:
        if cookie.name != "oai-client-auth-session":
            continue
        raw = cookie.value or ""
        head = raw.split(".", 1)[0]
        head += "=" * (-len(head) % 4)
        try:
            payload = json.loads(base64.urlsafe_b64decode(head).decode("utf-8"))
        except Exception:  # noqa: BLE001
            continue
        candidates = [payload]
        if isinstance(payload, dict):
            for key in ("client_auth_session", "data"):
                val = payload.get(key)
                if isinstance(val, dict):
                    candidates.append(val)
        for src in candidates:
            if not isinstance(src, dict):
                continue
            workspaces = src.get("workspaces") or []
            if not isinstance(workspaces, list):
                continue
            for item in workspaces:
                if not isinstance(item, dict):
                    continue
                ws_id = str(item.get("id") or item.get("account_id") or "")
                if ws_id and ws_id not in out:
                    out.append(ws_id)
    return out


def set_chatgpt_did_cookie(client: httpx.AsyncClient, device_id: str) -> None:
    if not device_id:
        return
    client.cookies.set("oai-did", device_id, domain="chatgpt.com", path="/")
    client.cookies.set("oai-did", device_id, domain=".chatgpt.com", path="/")


def _nextauth_session_cookie(client: httpx.AsyncClient) -> str:
    """拼回 NextAuth 分片 session cookie（session JSON 没给 sessionToken 时兜底）。"""
    chunks: dict[int, str] = {}
    single = ""
    for cookie in client.cookies.jar:
        name = cookie.name or ""
        if name == "__Secure-next-auth.session-token":
            single = cookie.value or ""
        elif name.startswith("__Secure-next-auth.session-token."):
            suffix = name.rsplit(".", 1)[-1]
            if suffix.isdigit():
                chunks[int(suffix)] = cookie.value or ""
    if chunks:
        return "".join(v for _, v in sorted(chunks.items()))
    return single


def _chatgpt_api_headers(
    profile: Profile,
    device_id: str,
    *,
    oai_session_id: str = "",
    target_path: str = "/api/auth/session",
    target_route: str = "/api/auth/session",
) -> dict[str, str]:
    """NextAuth `/api/auth/*` headers.

    The captured browser requests do not carry `oai-client-*` or
    `x-openai-target-*`; those belong to ChatGPT backend/CES calls.
    `device_id` and the remaining keyword arguments stay in the signature for
    compatibility with older callers.
    """
    headers = {
        "accept": "*/*",
        "content-type": "application/json",
        "accept-language": profile.locale,
        "referer": f"{CHATGPT_BASE}/",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": profile.user_agent,
    }
    return headers


async def _get_chatgpt_session(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    params: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    headers = _chatgpt_api_headers(
        profile,
        device_id,
        oai_session_id=str(getattr(client, "oai_session_id", "") or ""),
    )
    resp = await request_with_retry(
        client,
        "GET",
        f"{CHATGPT_BASE}/api/auth/session",
        params=params,
        headers=headers,
        follow_redirects=False,
        retries=2,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"ChatGPT session HTTP {resp.status_code}: {_snippet(resp.text)}")
    try:
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"ChatGPT session 非 JSON: {_snippet(resp.text)}") from exc
    return data if isinstance(data, dict) else {}


async def _get_nextauth_csrf(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
) -> str:
    headers = _chatgpt_api_headers(
        profile,
        device_id,
        oai_session_id=str(getattr(client, "oai_session_id", "") or ""),
        target_path="/api/auth/csrf",
        target_route="/api/auth/csrf",
    )
    resp = await request_with_retry(
        client,
        "GET",
        f"{CHATGPT_BASE}/api/auth/csrf",
        headers=headers,
        follow_redirects=False,
        retries=2,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"NextAuth csrf HTTP {resp.status_code}: {_snippet(resp.text)}")
    try:
        token = str((resp.json() or {}).get("csrfToken") or "")
    except Exception:  # noqa: BLE001
        token = ""
    if not token:
        raise RuntimeError(f"NextAuth csrf 响应缺 csrfToken: {_snippet(resp.text)}")
    return token


async def _start_nextauth_openai_signin(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    email: str,
) -> str:
    """初始化 NextAuth state，返回 auth.openai.com authorize URL。"""
    set_chatgpt_did_cookie(client, device_id)

    # 关键：先 GET /session 让 NextAuth 写 csrf cookie；只 GET /csrf 会导致 csrf=true。
    await _get_chatgpt_session(client, profile=profile, device_id=device_id)
    csrf = await _get_nextauth_csrf(client, profile=profile, device_id=device_id)

    auth_session_logging_id = str(
        getattr(client, "auth_session_logging_id", "") or uuid.uuid4()
    )
    setattr(client, "auth_session_logging_id", auth_session_logging_id)
    query = {
        "prompt": "login",
        "ext-oai-did": device_id,
        "auth_session_logging_id": auth_session_logging_id,
        "screen_hint": "login_or_signup",
        "login_hint": email,
    }
    signin_url = (
        f"{CHATGPT_BASE}/api/auth/signin/{WEB_PROVIDER_ID}?"
        + urllib.parse.urlencode(query)
    )
    headers = {
        "content-type": "application/x-www-form-urlencoded",
        "accept": "application/json",
        "origin": CHATGPT_BASE,
        "referer": f"{CHATGPT_BASE}/auth/login",
        "user-agent": profile.user_agent,
        "accept-language": profile.locale,
    }
    data = {
        "csrfToken": csrf,
        "callbackUrl": f"{CHATGPT_BASE}/",
        "json": "true",
    }
    resp = await request_with_retry(
        client,
        "POST",
        signin_url,
        data=data,
        headers=headers,
        follow_redirects=False,
        retries=2,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"NextAuth signin HTTP {resp.status_code}: {_snippet(resp.text)}")
    try:
        body = resp.json()
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"NextAuth signin 非 JSON: {_snippet(resp.text)}") from exc

    url = str(body.get("url") or "")
    if "csrf=true" in url:
        # 极少数情况下 csrf cookie 刚写入又轮换，重取一次。
        csrf = await _get_nextauth_csrf(client, profile=profile, device_id=device_id)
        data["csrfToken"] = csrf
        resp = await request_with_retry(
            client,
            "POST",
            signin_url,
            data=data,
            headers=headers,
            follow_redirects=False,
            retries=2,
        )
        body = resp.json() if resp.text else {}
        url = str(body.get("url") or "")

    if not url:
        raise RuntimeError(f"NextAuth signin 没返回 url: {_snippet(resp.text)}")
    return _with_authorize_email_hint(
        urllib.parse.urljoin(CHATGPT_BASE, url),
        email,
        device_id=device_id,
        auth_session_logging_id=auth_session_logging_id,
    )


def _with_authorize_email_hint(
    auth_url: str,
    email: str,
    *,
    device_id: str = "",
    auth_session_logging_id: str = "",
) -> str:
    """Keep the returned authorize URL on the same NextAuth session identity."""
    parsed = urllib.parse.urlparse(auth_url)
    params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    params.pop("ext-passkey-client-capabilities", None)
    params["login_hint"] = email
    params["screen_hint"] = "login_or_signup"
    params.setdefault("ccaps", "login_methods")
    if device_id:
        params.setdefault("ext-oai-did", device_id)
        params.setdefault("device_id", device_id)
    if auth_session_logging_id:
        params.setdefault("auth_session_logging_id", auth_session_logging_id)
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(params)))


async def _follow_authorize_to_callback_or_login(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    start_url: str,
    max_hops: int = 12,
) -> tuple[str, str]:
    """跟 auth.openai.com authorize 链。

    Returns:
        (callback_url, last_url)。callback_url 非空表示已拿到 ChatGPT callback。
    """
    cur = start_url
    last = cur
    for hop in range(max_hops):
        if _is_web_callback(cur):
            return cur, cur
        headers = nav_headers(profile, device_id, site="cross-site" if hop == 0 else "same-origin")
        headers["referer"] = CHATGPT_BASE + "/" if hop == 0 else AUTH_BASE + "/"
        resp = await request_with_retry(
            client, "GET", cur, headers=headers, follow_redirects=False, retries=2
        )
        loc = (resp.headers.get("location") or "").strip()
        if loc:
            full = urllib.parse.urljoin(str(resp.url), loc)
            if _is_web_callback(full):
                return full, full
            cur = full
            last = full
            continue
        last = str(resp.url)
        if _is_web_callback(last):
            return last, last
        return "", last
    return "", last


async def _submit_username_step(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    email: str,
) -> tuple[str, str, str]:
    headers = json_headers(
        profile,
        device_id,
        f"{AUTH_BASE}/log-in",
        document_navigation_id=str(
            getattr(client, "document_navigation_id", "") or ""
        ),
    )
    headers.update(
        await sentinel.sentinel_headers(
            client,
            "authorize_continue",
            observer_timeout_ms=5000,
        )
    )
    resp = await request_with_retry(
        client,
        "POST",
        f"{AUTH_BASE}/api/accounts/authorize/continue",
        json={
            "username": {"kind": "email", "value": email},
            "screen_hint": "login_or_signup",
        },
        headers=headers,
        follow_redirects=False,
        retries=2,
    )
    if resp.status_code not in (200, 201, 204, 302, 303, 307, 308):
        raise RuntimeError(f"authorize/continue(username) HTTP {resp.status_code}: {_snippet(resp.text)}")
    loc = (resp.headers.get("location") or "").strip()
    if loc:
        return urllib.parse.urljoin(str(resp.url), loc), "", ""
    try:
        body = resp.json() if resp.text else {}
    except Exception:  # noqa: BLE001
        body = {}
    if isinstance(body, dict):
        page = body.get("page") if isinstance(body.get("page"), dict) else {}
        payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
        return (
            str(body.get("continue_url") or body.get("url") or ""),
            str(page.get("type") or "").strip().lower(),
            str(payload.get("email_verification_mode") or "").strip().lower(),
        )
    return "", "", ""


async def _submit_username(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    email: str,
) -> str:
    next_url, _, _ = await _submit_username_step(
        client,
        sentinel,
        profile=profile,
        device_id=device_id,
        email=email,
    )
    return next_url


async def _chase_to_web_callback(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    start_url: str,
    max_hops: int = 12,
) -> str:
    cur = start_url
    for _ in range(max_hops):
        if _is_web_callback(cur):
            return cur
        headers = nav_headers(profile, device_id, site="same-origin")
        headers["referer"] = AUTH_BASE + "/"
        resp = await request_with_retry(
            client, "GET", cur, headers=headers, follow_redirects=False, retries=2
        )
        loc = (resp.headers.get("location") or "").strip()
        if loc:
            full = urllib.parse.urljoin(str(resp.url), loc)
            if _is_web_callback(full):
                return full
            cur = full
            continue
        if _is_web_callback(str(resp.url)):
            return str(resp.url)
        return ""
    return ""


async def _select_workspace_to_web_callback(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    referer_url: str,
) -> str:
    """Web OAuth 登录撞 /workspace 时，提交 workspace/select 后追 ChatGPT callback。"""
    for workspace_id in _workspace_ids_from_cookie(client):
        headers = json_headers(
            profile,
            device_id,
            referer_url or f"{AUTH_BASE}/workspace",
            document_navigation_id=str(
                getattr(client, "document_navigation_id", "") or ""
            ),
        )
        resp = await request_with_retry(
            client,
            "POST",
            f"{AUTH_BASE}/api/accounts/workspace/select",
            json={"workspace_id": workspace_id},
            headers=headers,
            follow_redirects=False,
            retries=2,
        )
        loc = (resp.headers.get("location") or "").strip()
        if loc:
            full = urllib.parse.urljoin(str(resp.url), loc)
            if _is_web_callback(full):
                return full
            code_url = await _chase_to_web_callback(
                client, profile=profile, device_id=device_id, start_url=full
            )
            if code_url:
                return code_url
        try:
            body = resp.json() if resp.text else {}
        except Exception:  # noqa: BLE001
            body = {}
        if isinstance(body, dict):
            for key in ("continue_url", "redirect_url", "url"):
                val = str(body.get(key) or "")
                if not val:
                    continue
                if _is_web_callback(val):
                    return val
                code_url = await _chase_to_web_callback(
                    client, profile=profile, device_id=device_id, start_url=val
                )
                if code_url:
                    return code_url
    return ""


async def _validate_login_email_otp(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    email: str,
    otp_fetcher: OtpFetcher,
    log: Callable[[str], None],
    max_attempts: int = 3,
) -> str:
    pending_otp = ""
    for attempt in range(1, max_attempts + 1):
        if pending_otp:
            otp = pending_otp
            pending_otp = ""
        else:
            log(f"📬 [Web] 等登录二次邮箱验证码（{attempt}/{max_attempts}）...")
            otp = (await otp_fetcher(email)).strip()
        if not otp:
            raise RuntimeError("otp_fetcher 返回空 OTP")
        log(f"📨 [Web] 收到验证码 {otp[:2]}**{otp[-2:]}")
        try:
            return await _validate_email_otp(
                client, sentinel, profile=profile, device_id=device_id, otp=otp,
            )
        except EmailOtpInvalidError as exc:
            await _maybe_mark_bad_otp(otp_fetcher, email, otp)
            if attempt >= max_attempts:
                raise
            log(f"🔁 [Web] OTP 被拒：{exc}")
            replacement = await _maybe_wait_current_otp_generation(
                otp_fetcher,
                email,
                log,
            )
            if replacement:
                # Keep the current OpenAI send/session alive. The next loop will
                # submit this different settled candidate without a resend.
                pending_otp = replacement
            else:
                await _maybe_begin_otp_generation(otp_fetcher, email, log)
                log("📮 [Web] 当前代次无其他候选码，重新触发邮件验证码 ...")
                await _maybe_mark_otp_send_started(otp_fetcher, email)
                await _send_email_otp(client, profile=profile, device_id=device_id)
    return ""


async def _complete_callback_and_fetch_session(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    callback_url: str,
) -> dict[str, Any]:
    if callback_url:
        resp = await request_with_retry(
            client,
            "GET",
            callback_url,
            headers={
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "accept-language": profile.locale,
                "referer": AUTH_BASE + "/",
                "user-agent": profile.user_agent,
            },
            follow_redirects=False,
            retries=2,
        )
        # NextAuth 有时 302 到 /api/auth/error?error=OAuthCallback，但 cookie/session 已写好。
        if resp.status_code >= 500:
            raise RuntimeError(f"ChatGPT callback HTTP {resp.status_code}: {_snippet(resp.text)}")

    session = await _get_chatgpt_session(client, profile=profile, device_id=device_id)
    if not session.get("accessToken"):
        # 兜底触发 NextAuth 刷新一次。
        session = await _get_chatgpt_session(
            client, profile=profile, device_id=device_id, params={"refresh": "true"}
        )
    return session


def _result_from_session(
    session: dict[str, Any],
    *,
    email: str,
    device_id: str,
    started: float,
    proxy: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
) -> ChatGPTWebLoginResult:
    at = str(session.get("accessToken") or "")
    if not at:
        err = session.get("error") or session.get("workspaceTokenExchangeError") or ""
        raise RuntimeError(f"ChatGPT session 未返回 accessToken: {_snippet(err or session)}")

    claims = _jwt_claims(at)
    auth_info = claims.get("https://api.openai.com/auth") or {}
    profile_info = claims.get("https://api.openai.com/profile") or {}
    account = session.get("account") if isinstance(session.get("account"), dict) else {}
    user = session.get("user") if isinstance(session.get("user"), dict) else {}

    exp = int(claims.get("exp") or 0)
    expires_in = max(0, exp - int(time.time())) if exp else 0
    account_id = (
        str(auth_info.get("chatgpt_account_id") or "")
        or str(account.get("id") or "")
        or str(profile_info.get("account_id") or "")
    )
    chatgpt_user_id = (
        str(auth_info.get("chatgpt_user_id") or "")
        or str(auth_info.get("chatgpt_account_user_id") or "")
        or str(auth_info.get("user_id") or "")
        or str(user.get("id") or "")
    )
    plan_type = str(auth_info.get("chatgpt_plan_type") or account.get("planType") or "")
    if not plan_type:
        plan_type = "free"
    session_token = str(session.get("sessionToken") or "")
    if not session_token and client is not None:
        session_token = _nextauth_session_cookie(client)

    return ChatGPTWebLoginResult(
        email=email,
        access_token=at,
        session_token=session_token,
        expires_in=expires_in,
        chatgpt_account_id=account_id,
        chatgpt_user_id=chatgpt_user_id,
        plan_type=plan_type,
        sub=str(claims.get("sub") or ""),
        auth_provider=str(session.get("authProvider") or "openai"),
        device_id=device_id,
        duration_seconds=time.monotonic() - started,
        proxy_used=proxy,
        user=user,
        account=account,
    )


def _expose_chatgpt_sentinel_context(client: Any, sentinel: SentinelGenerator) -> None:
    """Expose the Web Sentinel instance context for the post-login bridge.

    The authenticated bootstrap can run after this async client has finished
    the Web flow. Keeping the actual Web generator's sid/React property keys
    lets the VM use the same browser lifecycle instead of silently creating a
    second set of runtime identifiers.
    """
    for target, source in (
        ("chatgpt_sentinel_sid", "sid"),
        ("react_listening_key", "react_listening_key"),
        ("react_container_key", "react_container_key"),
        ("react_resources_key", "react_resources_key"),
    ):
        value = str(getattr(sentinel, source, "") or "").strip()
        if value:
            setattr(client, target, value)


async def _create_signup_callback(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    full_name: str,
    birthday: str,
) -> str:
    continue_url = await _create_account(
        client,
        sentinel,
        profile=profile,
        device_id=device_id,
        full_name=full_name,
        birthday=birthday,
    )
    if _is_web_callback(continue_url):
        return continue_url
    if not continue_url:
        return ""
    return await _chase_to_web_callback(
        client,
        profile=profile,
        device_id=device_id,
        start_url=continue_url,
    )


async def chatgpt_web_register_with_client(
    client: httpx.AsyncClient,
    *,
    email: str,
    password: Optional[str],
    profile: Profile,
    device_id: str,
    otp_fetcher: OtpFetcher,
    proxy: Optional[str] = None,
    log: Optional[Callable[[str], None]] = None,
    full_name: str = "",
    birthday: str = "",
) -> ChatGPTWebLoginResult:
    """Create an account through ChatGPT Web NextAuth and return its Web session.

    The current Web flow can branch directly from authorize to email verification
    (passwordless signup), while older sessions still use create-account/password.
    Both branches finish at the same ChatGPT callback and /api/auth/session.
    """
    started = time.monotonic()
    info = log or (lambda s: None)
    if not email or "@" not in email:
        raise RuntimeError("email 非法")
    if not device_id:
        device_id = new_device_id()

    generated_password = password or _gen_password(16)
    if not full_name:
        first = "".join(secrets.choice(string.ascii_lowercase) for _ in range(7)).capitalize()
        last = "".join(secrets.choice(string.ascii_lowercase) for _ in range(8)).capitalize()
        full_name = f"{first} {last}"
    birthday = birthday or _gen_birthday()

    set_chatgpt_did_cookie(client, device_id)
    set_oai_did_cookie(client, device_id)
    sentinel = SentinelGenerator.from_profile(device_id, profile)
    _expose_chatgpt_sentinel_context(client, sentinel)

    try:
        await emit_async_anonymous(client, profile, device_id)
        await emit_async_signup(client, profile, device_id)
    except Exception as exc:  # noqa: BLE001
        info(f"📡 [Web注册] CES 匿名生命周期跳过：{type(exc).__name__}: {str(exc)[:120]}")

    await _maybe_prime_otp_fetcher(otp_fetcher, email, info)
    await _maybe_mark_otp_send_started(otp_fetcher, email)
    info("🌐 [Web注册 1/6] 初始化 NextAuth ...")
    auth_url = await _start_nextauth_openai_signin(
        client, profile=profile, device_id=device_id, email=email
    )
    auth_device = _parse_device_id(auth_url)
    if auth_device and auth_device != device_id:
        device_id = auth_device
        set_chatgpt_did_cookie(client, device_id)
        set_oai_did_cookie(client, device_id)
        sentinel = SentinelGenerator.from_profile(device_id, profile)
        _expose_chatgpt_sentinel_context(client, sentinel)

    info("🌐 [Web注册 2/6] authorize(login_hint) ...")
    callback_url, last_url = await _follow_authorize_to_callback_or_login(
        client, profile=profile, device_id=device_id, start_url=auth_url
    )
    page_type = ""
    email_mode = ""
    next_url = last_url

    if callback_url:
        info("🌐 [Web注册] 邮箱已存在且会话有效，直接消费 callback")
    elif "/email-verification" not in next_url and "/create-account/password" not in next_url:
        info("🌐 [Web注册 3/6] 提交邮箱 ...")
        await _maybe_mark_otp_send_started(otp_fetcher, email)
        next_url, page_type, email_mode = await _submit_username_step(
            client,
            sentinel,
            profile=profile,
            device_id=device_id,
            email=email,
        )
        info(
            "🧭 [Web注册] "
            f"page={page_type or '-'} mode={email_mode or '-'} "
            f"next={next_url[:100] or '-'}"
        )

    direct_otp = (
        page_type == "email_otp_verification"
        or "/email-verification" in next_url
        or "/email-otp" in next_url
    )
    password_signup = (
        page_type == "create_account_password"
        or "/create-account/password" in next_url
    )
    password_set = False
    profile_created = False
    signup_mode = email_mode or ("passwordless_signup" if direct_otp else "")

    if direct_otp:
        await _emit_login_web_stage_safely(
            client, profile, device_id, "email_verification", log=info, scope="Web注册"
        )

    if not callback_url and direct_otp:
        info("📬 [Web注册 4/6] 已直接发码，等待 passwordless signup OTP ...")
        otp_continue = await _validate_login_email_otp(
            client,
            sentinel,
            profile=profile,
            device_id=device_id,
            email=email,
            otp_fetcher=otp_fetcher,
            log=info,
        )
        if _is_web_callback(otp_continue):
            await _emit_login_web_stage_safely(
                client, profile, device_id, "otp_validated", log=info, scope="Web注册"
            )
            callback_url = otp_continue
        else:
            info(f"🎂 [Web注册 5/6] OTP 已验证，创建资料 · 生日 {birthday} ...")
            await _emit_login_web_stage_safely(
                client,
                profile,
                device_id,
                "otp_validated_about_you",
                log=info,
                scope="Web注册",
            )
            callback_url = await _create_signup_callback(
                client,
                sentinel,
                profile=profile,
                device_id=device_id,
                full_name=full_name,
                birthday=birthday,
            )
            profile_created = True

    elif not callback_url and password_signup:
        info("🔐 [Web注册 4/6] 旧密码注册分支，提交账号密码 ...")
        if next_url:
            await request_with_retry(
                client,
                "GET",
                next_url,
                headers=nav_headers(profile, device_id, site="same-origin"),
                retries=1,
            )
        fresh_register = await _user_register(
            client,
            sentinel,
            profile=profile,
            device_id=device_id,
            email=email,
            password=generated_password,
        )
        password_set = bool(fresh_register)
        signup_mode = "password_signup"
        await _maybe_mark_otp_send_started(otp_fetcher, email)
        await _kickoff_email_otp(
            client,
            sentinel=sentinel,
            profile=profile,
            device_id=device_id,
            existing_or_resumed=not fresh_register,
            log=info,
        )
        await _emit_login_web_stage_safely(
            client, profile, device_id, "email_verification", log=info, scope="Web注册"
        )
        await _validate_login_email_otp(
            client,
            sentinel,
            profile=profile,
            device_id=device_id,
            email=email,
            otp_fetcher=otp_fetcher,
            log=info,
        )
        info(f"🎂 [Web注册 5/6] 创建资料 · 生日 {birthday} ...")
        await _emit_login_web_stage_safely(
            client,
            profile,
            device_id,
            "otp_validated_about_you",
            log=info,
            scope="Web注册",
        )
        callback_url = await _create_signup_callback(
            client,
            sentinel,
            profile=profile,
            device_id=device_id,
            full_name=full_name,
            birthday=birthday,
        )
        profile_created = True

    elif not callback_url:
        raise RuntimeError(
            "ChatGPT Web 注册未进入可识别状态: "
            f"page={page_type or '-'} mode={email_mode or '-'} last={next_url[:180]}"
        )

    if not callback_url:
        raise RuntimeError(
            f"ChatGPT Web 注册完成资料后未拿到 callback，最后落点: {next_url[:180]}"
        )

    info("✅ [Web注册 6/6] 消费 callback，读取 Web session ...")
    session = await _complete_callback_and_fetch_session(
        client,
        profile=profile,
        device_id=device_id,
        callback_url=callback_url,
    )
    result = _result_from_session(
        session,
        email=email,
        device_id=device_id,
        started=started,
        proxy=proxy,
        client=client,
    )
    result.password_set = password_set
    result.signup_mode = signup_mode
    if profile_created:
        await _emit_login_web_stage_safely(
            client,
            profile,
            device_id,
            "profile_submitted",
            log=info,
            scope="Web注册",
        )
    try:
        await emit_async_authenticated(
            client,
            profile,
            device_id,
            result,
            access_token=result.access_token,
        )
    except Exception as exc:  # noqa: BLE001
        info(f"📡 [Web注册] CES 登录生命周期跳过：{type(exc).__name__}: {str(exc)[:120]}")
    info(
        "🪙 [Web注册] Web AT OK · "
        f"account={result.chatgpt_account_id or '(空)'} plan={result.plan_type} "
        f"mode={result.signup_mode or '-'}"
    )
    return result


async def chatgpt_web_login_with_client(
    client: httpx.AsyncClient,
    *,
    email: str,
    password: str,
    profile: Profile,
    device_id: str,
    otp_fetcher: Optional[OtpFetcher] = None,
    proxy: Optional[str] = None,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGPTWebLoginResult:
    """复用给定 httpx client/cookies，拿 ChatGPT Web accessToken。"""
    started = time.monotonic()
    info = log or (lambda s: None)

    if not email or "@" not in email:
        raise RuntimeError("email 非法")
    if not device_id:
        device_id = new_device_id()

    set_chatgpt_did_cookie(client, device_id)
    set_oai_did_cookie(client, device_id)
    sentinel = SentinelGenerator.from_profile(device_id, profile)
    _expose_chatgpt_sentinel_context(client, sentinel)

    try:
        await emit_async_anonymous(client, profile, device_id)
        await emit_async_signup(client, profile, device_id)
    except Exception as exc:  # noqa: BLE001
        info(f"📡 [Web] CES 匿名生命周期跳过：{type(exc).__name__}: {str(exc)[:120]}")

    if not password and otp_fetcher is not None:
        await _maybe_prime_otp_fetcher(otp_fetcher, email, info)
        await _maybe_mark_otp_send_started(otp_fetcher, email)

    info("🌐 [Web] 初始化 NextAuth / OpenAI signin ...")
    auth_url = await _start_nextauth_openai_signin(
        client, profile=profile, device_id=device_id, email=email
    )
    auth_device = _parse_device_id(auth_url)
    if auth_device and auth_device != device_id:
        device_id = auth_device
        set_chatgpt_did_cookie(client, device_id)
        set_oai_did_cookie(client, device_id)
        sentinel = SentinelGenerator.from_profile(device_id, profile)
        _expose_chatgpt_sentinel_context(client, sentinel)

    info("🌐 [Web] 跟 authorize 链 ...")
    callback_url, last_url = await _follow_authorize_to_callback_or_login(
        client, profile=profile, device_id=device_id, start_url=auth_url
    )

    if not callback_url:
        info("👤 [Web] 提交邮箱 username ...")
        if otp_fetcher is not None:
            await _maybe_mark_otp_send_started(otp_fetcher, email)
        next_url = await _submit_username(
            client, sentinel, profile=profile, device_id=device_id, email=email
        )
        if _is_web_callback(next_url):
            callback_url = next_url
        else:
            if not password:
                direct_otp = (
                    "/email-verification" in (next_url or "")
                    or "/email-otp" in (next_url or "")
                )
                if not direct_otp:
                    await _maybe_mark_otp_send_started(otp_fetcher, email)
                    direct_otp = await _send_passwordless_otp(
                        client,
                        profile=profile,
                        device_id=device_id,
                        referer=f"{AUTH_BASE}/log-in/password",
                    )
                if not callback_url and not direct_otp:
                    callback_url, last_after_auth = await _follow_authorize_to_callback_or_login(
                        client,
                        profile=profile,
                        device_id=device_id,
                        start_url=auth_url,
                    )
                    if last_after_auth:
                        last_url = last_after_auth
                    if not callback_url:
                        raise RuntimeError(
                            "passwordless 账号未进入 Web callback 或邮箱 OTP 状态，"
                            f"最后落点: {(next_url or last_url)[:160]}"
                        )
                if not callback_url:
                    if otp_fetcher is None:
                        raise RuntimeError("ChatGPT Web passwordless 登录需要 otp_fetcher")
                    await _emit_login_web_stage_safely(
                        client,
                        profile,
                        device_id,
                        "email_verification",
                        log=info,
                        scope="Web",
                    )
                    info("📬 [Web] passwordless 账号等待邮箱 OTP ...")
                    otp_continue = await _validate_login_email_otp(
                        client,
                        sentinel,
                        profile=profile,
                        device_id=device_id,
                        email=email,
                        otp_fetcher=otp_fetcher,
                        log=info,
                    )
                    await _emit_login_web_stage_safely(
                        client,
                        profile,
                        device_id,
                        "otp_validated",
                        log=info,
                        scope="Web",
                    )
                    if _is_web_callback(otp_continue):
                        callback_url = otp_continue
                    elif otp_continue:
                        callback_url = await _chase_to_web_callback(
                            client,
                            profile=profile,
                            device_id=device_id,
                            start_url=otp_continue,
                        )
                        if not callback_url and "/workspace" in otp_continue:
                            callback_url = await _select_workspace_to_web_callback(
                                client,
                                profile=profile,
                                device_id=device_id,
                                referer_url=otp_continue,
                            )
                    if not callback_url:
                        callback_url, last_after_otp = await _follow_authorize_to_callback_or_login(
                            client,
                            profile=profile,
                            device_id=device_id,
                            start_url=auth_url,
                        )
                        if last_after_otp:
                            last_url = last_after_otp
                if not callback_url:
                    raise RuntimeError(
                        "ChatGPT Web passwordless 登录未拿到 callback code，"
                        f"最后落点: {last_url[:160]}"
                    )
                info("✅ [Web] 完成 passwordless callback，读取 /api/auth/session ...")
                session = await _complete_callback_and_fetch_session(
                    client,
                    profile=profile,
                    device_id=device_id,
                    callback_url=callback_url,
                )
                result = _result_from_session(
                    session,
                    email=email,
                    device_id=device_id,
                    started=started,
                    proxy=proxy,
                    client=client,
                )
                try:
                    await emit_async_authenticated(
                        client,
                        profile,
                        device_id,
                        result,
                        access_token=result.access_token,
                    )
                except Exception as exc:  # noqa: BLE001
                    info(f"📡 [Web] CES 登录生命周期跳过：{type(exc).__name__}: {str(exc)[:120]}")
                info(
                    "🪙 [Web] accessToken OK(passwordless) · "
                    f"account={result.chatgpt_account_id or '(空)'} plan={result.plan_type}"
                )
                return result
            # 有些响应给 /email-verification（passwordless），但 password/verify 仍可直接走。
            if next_url and next_url.startswith("http"):
                last_url = next_url
            info("🔐 [Web] 提交密码 ...")
            needs_otp, continue_url = await _password_verify(
                client, sentinel, profile=profile, device_id=device_id, password=password
            )
            if needs_otp:
                if otp_fetcher is None:
                    raise RuntimeError("ChatGPT Web 登录需要 email OTP，但未提供 otp_fetcher")
                await _emit_login_web_stage_safely(
                    client,
                    profile,
                    device_id,
                    "email_verification",
                    log=info,
                    scope="Web",
                )
                otp_continue = await _validate_login_email_otp(
                    client,
                    sentinel,
                    profile=profile,
                    device_id=device_id,
                    email=email,
                    otp_fetcher=otp_fetcher,
                    log=info,
                )
                await _emit_login_web_stage_safely(
                    client,
                    profile,
                    device_id,
                    "otp_validated",
                    log=info,
                    scope="Web",
                )
                if _is_web_callback(otp_continue):
                    callback_url = otp_continue
                elif otp_continue:
                    info(f"🧭 [Web] OTP validate continue={otp_continue[:120]}")
                    callback_url = await _chase_to_web_callback(
                        client,
                        profile=profile,
                        device_id=device_id,
                        start_url=otp_continue,
                    )
                    if not callback_url and "/workspace" in otp_continue:
                        info("🏢 [Web] 选择 workspace 继续 OAuth ...")
                        callback_url = await _select_workspace_to_web_callback(
                            client,
                            profile=profile,
                            device_id=device_id,
                            referer_url=otp_continue,
                        )
            if not callback_url and _is_web_callback(continue_url):
                callback_url = continue_url
            elif not callback_url and continue_url:
                info("🧭 [Web] 追登录 continue_url ...")
                callback_url = await _chase_to_web_callback(
                    client,
                    profile=profile,
                    device_id=device_id,
                    start_url=continue_url,
                )
                if not callback_url and "/workspace" in continue_url:
                    info("🏢 [Web] 选择 workspace 继续 OAuth ...")
                    callback_url = await _select_workspace_to_web_callback(
                        client,
                        profile=profile,
                        device_id=device_id,
                        referer_url=continue_url,
                    )
            if needs_otp and not callback_url:
                # email OTP 验证后有时 continue_url 仍停在 /email-verification 静态页；
                # 复用同一个 NextAuth state / OpenAI 登录态重新追 authorize，通常会
                # 直接回 chatgpt.com/api/auth/callback/openai?code=...
                info("🔁 [Web] OTP 已验证，重新追 authorize callback ...")
                callback_url, last_after_otp = await _follow_authorize_to_callback_or_login(
                    client,
                    profile=profile,
                    device_id=device_id,
                    start_url=auth_url,
                )
                if last_after_otp:
                    last_url = last_after_otp
                if not callback_url and "choose-an-account" in (last_url or ""):
                    info("👤 [Web] choose-an-account 后重新提交邮箱 ...")
                    next_url2 = await _submit_username(
                        client, sentinel, profile=profile, device_id=device_id, email=email
                    )
                    if next_url2:
                        info(f"🧭 [Web] choose-an-account continue={next_url2[:120]}")
                    if _is_web_callback(next_url2):
                        callback_url = next_url2
                    elif next_url2:
                        last_url = next_url2
                        if "/email-verification" in next_url2 or "/email-otp" in next_url2:
                            if otp_fetcher is None:
                                raise RuntimeError("ChatGPT Web 登录需要 email OTP，但未提供 otp_fetcher")
                            await _emit_login_web_stage_safely(
                                client,
                                profile,
                                device_id,
                                "email_verification",
                                log=info,
                                scope="Web",
                            )
                            info("📬 [Web] choose-an-account 后走 passwordless OTP ...")
                            otp_continue2 = await _validate_login_email_otp(
                                client,
                                sentinel,
                                profile=profile,
                                device_id=device_id,
                                email=email,
                                otp_fetcher=otp_fetcher,
                                log=info,
                                max_attempts=2,
                            )
                            await _emit_login_web_stage_safely(
                                client,
                                profile,
                                device_id,
                                "otp_validated",
                                log=info,
                                scope="Web",
                            )
                            if _is_web_callback(otp_continue2):
                                callback_url = otp_continue2
                            elif otp_continue2:
                                info(f"🧭 [Web] passwordless OTP continue={otp_continue2[:120]}")
                                callback_url = await _chase_to_web_callback(
                                    client,
                                    profile=profile,
                                    device_id=device_id,
                                    start_url=otp_continue2,
                                )
                                if not callback_url and "/workspace" in otp_continue2:
                                    info("🏢 [Web] 选择 workspace 继续 OAuth ...")
                                    callback_url = await _select_workspace_to_web_callback(
                                        client,
                                        profile=profile,
                                        device_id=device_id,
                                        referer_url=otp_continue2,
                                    )
                        else:
                            callback_url = await _chase_to_web_callback(
                                client,
                                profile=profile,
                                device_id=device_id,
                                start_url=next_url2,
                            )
                        if not callback_url:
                            callback_url, last_after_choose = await _follow_authorize_to_callback_or_login(
                                client,
                                profile=profile,
                                device_id=device_id,
                                start_url=auth_url,
                            )
                            if last_after_choose:
                                last_url = last_after_choose
                        if not callback_url:
                            info("🔐 [Web] choose-an-account 后再次提交密码 ...")
                            needs_otp2, continue_url2 = await _password_verify(
                                client,
                                sentinel,
                                profile=profile,
                                device_id=device_id,
                                password=password,
                            )
                            if needs_otp2:
                                if otp_fetcher is None:
                                    raise RuntimeError("ChatGPT Web 登录需要 email OTP，但未提供 otp_fetcher")
                                await _emit_login_web_stage_safely(
                                    client,
                                    profile,
                                    device_id,
                                    "email_verification",
                                    log=info,
                                    scope="Web",
                                )
                                otp_continue3 = await _validate_login_email_otp(
                                    client,
                                    sentinel,
                                    profile=profile,
                                    device_id=device_id,
                                    email=email,
                                    otp_fetcher=otp_fetcher,
                                    log=info,
                                )
                                await _emit_login_web_stage_safely(
                                    client,
                                    profile,
                                    device_id,
                                    "otp_validated",
                                    log=info,
                                    scope="Web",
                                )
                                if _is_web_callback(otp_continue3):
                                    callback_url = otp_continue3
                                elif otp_continue3:
                                    info(f"🧭 [Web] 第二次 OTP continue={otp_continue3[:120]}")
                                    callback_url = await _chase_to_web_callback(
                                        client,
                                        profile=profile,
                                        device_id=device_id,
                                        start_url=otp_continue3,
                                    )
                                    if not callback_url and "/workspace" in otp_continue3:
                                        info("🏢 [Web] 选择 workspace 继续 OAuth ...")
                                        callback_url = await _select_workspace_to_web_callback(
                                            client,
                                            profile=profile,
                                            device_id=device_id,
                                            referer_url=otp_continue3,
                                        )
                            if not callback_url and _is_web_callback(continue_url2):
                                callback_url = continue_url2
                            elif not callback_url and continue_url2:
                                last_url = continue_url2
                                callback_url = await _chase_to_web_callback(
                                    client,
                                    profile=profile,
                                    device_id=device_id,
                                    start_url=continue_url2,
                                )
                                if not callback_url and "/workspace" in continue_url2:
                                    info("🏢 [Web] 选择 workspace 继续 OAuth ...")
                                    callback_url = await _select_workspace_to_web_callback(
                                        client,
                                        profile=profile,
                                        device_id=device_id,
                                        referer_url=continue_url2,
                                    )
                            if needs_otp2 and not callback_url:
                                info("🔁 [Web] 第二次 OTP 已验证，重新追 authorize callback ...")
                                callback_url, last_after_otp2 = await _follow_authorize_to_callback_or_login(
                                    client,
                                    profile=profile,
                                    device_id=device_id,
                                    start_url=auth_url,
                                )
                                if last_after_otp2:
                                    last_url = last_after_otp2

    if not callback_url:
        info("🔎 [Web] 未拿到 callback，尝试直接读取 NextAuth session ...")
        try:
            session = await _get_chatgpt_session(client, profile=profile, device_id=device_id)
            if not session.get("accessToken"):
                session = await _get_chatgpt_session(
                    client, profile=profile, device_id=device_id, params={"refresh": "true"}
                )
            if session.get("accessToken"):
                result = _result_from_session(
                    session,
                    email=email,
                    device_id=device_id,
                    started=started,
                    proxy=proxy,
                    client=client,
                )
                try:
                    await emit_async_authenticated(
                        client,
                        profile,
                        device_id,
                        result,
                        access_token=result.access_token,
                    )
                except Exception as exc:  # noqa: BLE001
                    info(f"📡 [Web] CES 登录生命周期跳过：{type(exc).__name__}: {str(exc)[:120]}")
                info(
                    "🪙 [Web] accessToken OK(session fallback) · "
                    f"account={result.chatgpt_account_id or '(空)'} plan={result.plan_type}"
                )
                return result
        except Exception as exc:  # noqa: BLE001
            info(f"🔎 [Web] session fallback 失败：{exc}")
        raise RuntimeError(f"ChatGPT Web 登录未拿到 callback code，最后落点: {last_url[:160]}")

    info("✅ [Web] 完成 ChatGPT callback，读取 /api/auth/session ...")
    session = await _complete_callback_and_fetch_session(
        client, profile=profile, device_id=device_id, callback_url=callback_url
    )
    result = _result_from_session(
        session, email=email, device_id=device_id, started=started, proxy=proxy, client=client
    )
    try:
        await emit_async_authenticated(
            client,
            profile,
            device_id,
            result,
            access_token=result.access_token,
        )
    except Exception as exc:  # noqa: BLE001
        info(f"📡 [Web] CES 登录生命周期跳过：{type(exc).__name__}: {str(exc)[:120]}")
    info(
        "🪙 [Web] accessToken OK · "
        f"account={result.chatgpt_account_id or '(空)'} plan={result.plan_type}"
    )
    return result


async def chatgpt_web_login_get_tokens(
    *,
    email: str,
    password: str,
    proxy: Optional[str] = None,
    profile: Optional[Profile] = None,
    device_id: Optional[str] = None,
    otp_fetcher: Optional[OtpFetcher] = None,
    attempts: int = 3,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGPTWebLoginResult:
    """独立创建 client，完成纯 ChatGPT Web 登录并返回 Web accessToken。"""
    p = profile or random_profile(proxy=proxy)
    did = device_id or new_device_id()
    info = log or (lambda s: None)
    last_exc: Exception | None = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            async with build_client(profile=p, proxy=proxy) as client:
                return await chatgpt_web_login_with_client(
                    client,
                    email=email,
                    password=password,
                    profile=p,
                    device_id=did,
                    otp_fetcher=otp_fetcher,
                    proxy=proxy,
                    log=log,
                )
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if getattr(exc, "mailbox_unavailable", False):
                break
            if attempt >= max(1, attempts):
                break
            info(f"🔁 [Web] 登录失败，重试 {attempt + 1}/{max(1, attempts)}：{exc}")
            await asyncio.sleep(min(2 * attempt, 6))
    assert last_exc is not None
    raise last_exc


async def exchange_workspace_access_token(
    client: httpx.AsyncClient,
    *,
    workspace_id: str,
    email: str,
    profile: Profile,
    device_id: str,
    reason: str = "join_workspace",
    proxy: Optional[str] = None,
    log: Optional[Callable[[str], None]] = None,
) -> ChatGPTWebLoginResult:
    """加入 workspace 后，用 NextAuth session 重新换 workspace-scoped AT。"""
    started = time.monotonic()
    info = log or (lambda s: None)
    workspace_id = (workspace_id or "").strip()
    if not workspace_id:
        raise RuntimeError("workspace_id 为空")

    info(f"🔄 [Web] exchange workspace token · workspace={workspace_id}")
    session = await _get_chatgpt_session(
        client,
        profile=profile,
        device_id=device_id,
        params={
            "exchange_workspace_token": "true",
            "workspace_id": workspace_id,
            "reason": reason,
        },
    )
    if session.get("workspaceTokenExchangeError"):
        raise RuntimeError(f"workspace token exchange 失败: {_snippet(session['workspaceTokenExchangeError'])}")
    if not session.get("accessToken"):
        # 兜底：先把前端当前 workspace cookie 写上，再让 session 做 workspace_update。
        client.cookies.set("_account", workspace_id, domain="chatgpt.com", path="/")
        client.cookies.set("_account", workspace_id, domain=".chatgpt.com", path="/")
        session = await _get_chatgpt_session(
            client,
            profile=profile,
            device_id=device_id,
            params={"workspace_update": "true", "reason": reason},
        )

    result = _result_from_session(
        session, email=email, device_id=device_id, started=started, proxy=proxy, client=client
    )
    # 对齐 ChatGPT 前端：token 换好后把当前 account cookie 指向 workspace。
    client.cookies.set("_account", workspace_id, domain="chatgpt.com", path="/")
    client.cookies.set("_account", workspace_id, domain=".chatgpt.com", path="/")
    info(
        "✅ [Web] workspace AT OK · "
        f"account={result.chatgpt_account_id or '(空)'} plan={result.plan_type}"
    )
    return result


__all__ = [
    "CHATGPT_BASE",
    "WEB_CALLBACK_URL",
    "ChatGPTWebLoginResult",
    "chatgpt_web_login_get_tokens",
    "chatgpt_web_login_with_client",
    "chatgpt_web_register_with_client",
    "exchange_workspace_access_token",
    "set_chatgpt_did_cookie",
]
