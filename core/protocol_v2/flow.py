"""Platform OAuth protocol registration.

The primary flow is passwordless and follows the current OpenAI Web state
machine: authorize -> email OTP -> create_account -> PKCE token exchange.
The former password-first implementation remains available as
``register_via_protocol`` for explicit legacy use.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
import logging
import random
import secrets
import string
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

from .core.http_client import (
    AUTH_BASE,
    DEFAULT_SCOPE,
    PLATFORM_AUDIENCE,
    PLATFORM_AUTH0_CLIENT,
    PLATFORM_CLIENT_ID,
    PLATFORM_REDIRECT_URI,
    build_client,
    clear_oauth_session_cookies,
    json_headers,
    nav_headers,
    request_with_retry,
    set_oai_did_cookie,
)
from .core.pkce import new_device_id, new_pkce, random_state_nonce
from .core.profile import Profile, random_profile
from .core.sentinel import SentinelGenerator

logger = logging.getLogger(__name__)

# 异步 OTP 拉取器，签名 (email) -> str
OtpFetcher = Callable[[str], Awaitable[str]]


@dataclass(slots=True)
class RegisterResult:
    email: str
    password: str
    access_token: str
    refresh_token: str
    id_token: str
    device_id: str
    session_token: str = ""
    proxy_used: Optional[str] = None
    duration_seconds: float = 0.0
    # 从 token JWT claims 解出（供 sub2api 导出用）
    expires_in: int = 0
    chatgpt_account_id: str = ""
    chatgpt_user_id: str = ""
    plan_type: str = "plus"
    sub: str = ""
    auth_provider: str = ""
    token_source: str = "platform"
    workspace_id: str = ""
    workspace_joined: bool = False
    workspace_join_result: Optional[dict[str, Any]] = None
    platform_access_token: str = ""
    platform_refresh_token: str = ""
    platform_id_token: str = ""
    platform_expires_in: int = 0


class EmailOtpInvalidError(RuntimeError):
    """OpenAI 明确返回邮箱 OTP 错误/过期，可触发重新收码重试。"""


class EmailAuthStepError(RuntimeError):
    """OpenAI 返回 invalid_auth_step，说明当前 auth session 已不在邮箱 OTP 阶段。"""


class AccountCreationFailedError(RuntimeError):
    """OpenAI 在 create_account_password 阶段明确拒绝创建账号；通常不会发邮箱 OTP。"""


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------


def _gen_password(length: int = 16) -> str:
    """随机强密码：>=8 位，至少 1 个大写/小写/数字。"""
    alphabet = string.ascii_letters + string.digits
    while True:
        p = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in p) and any(c.isupper() for c in p) and any(c.isdigit() for c in p):
            return p


def _gen_birthday() -> str:
    """随机生日 yyyy-mm-dd（年龄 25-45）。"""
    year = datetime.utcnow().year - random.randint(25, 45)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{year:04d}-{month:02d}-{day:02d}"


def _pick_code_from_url(raw_url: str) -> str:
    if not raw_url:
        return ""
    qs = parse_qs(urlparse(raw_url).query)
    arr = qs.get("code") or []
    return arr[0] if arr else ""


def _snippet(s: str, max_len: int = 240) -> str:
    return s if len(s) <= max_len else s[:max_len] + "…"


def _jwt_claims(token: str) -> dict[str, Any]:
    """解码 JWT payload（不验签，只取 claims）。"""
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


# ---------------------------------------------------------------------------
# 各 endpoint 调用
# ---------------------------------------------------------------------------


async def _platform_authorize(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    pkce_challenge: str,
    state_val: str,
    nonce_val: str,
    email: str,
) -> str:
    """Step 1: 起 OAuth flow，种 login_session。

    2026-07 后 OpenAI 可能不再先落到 /create-account/password，
    而是在 authorize 302 后直接进入 /email-verification 并发码。
    返回最终 URL，供上层判断是否要跳过 user/register。
    """
    params = {
        "issuer": AUTH_BASE,
        "client_id": PLATFORM_CLIENT_ID,
        "audience": PLATFORM_AUDIENCE,
        "redirect_uri": PLATFORM_REDIRECT_URI,
        "device_id": device_id,
        "screen_hint": "login_or_signup",
        "max_age": "0",
        "login_hint": email,
        "scope": DEFAULT_SCOPE,
        "response_type": "code",
        "response_mode": "query",
        "state": state_val,
        "nonce": nonce_val,
        "code_challenge": pkce_challenge,
        "code_challenge_method": "S256",
        "auth0Client": PLATFORM_AUTH0_CLIENT,
    }
    headers = nav_headers(profile, device_id, site="same-origin")
    headers["Referer"] = "https://platform.openai.com/"
    resp = await request_with_retry(
        client, "GET", f"{AUTH_BASE}/api/accounts/authorize",
        params=params, headers=headers,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"authorize HTTP {resp.status_code}: {_snippet(resp.text)}")
    return str(resp.url or "")


def _auth_step_info(data: dict[str, Any]) -> tuple[str, str, str]:
    """Extract (page_type, email_verification_mode, continue_url) from auth step JSON."""
    if not isinstance(data, dict):
        return "", "", ""
    page = data.get("page") if isinstance(data.get("page"), dict) else {}
    payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
    page_type = str(page.get("type") or "").strip().lower()
    mode = str(payload.get("email_verification_mode") or "").strip().lower()
    continue_url = str(data.get("continue_url") or "").strip()
    return page_type, mode, continue_url


def _extract_continue_url(data: dict[str, Any] | None) -> str:
    """Read continuation URLs from both current and older auth responses."""
    if not isinstance(data, dict):
        return ""
    direct = str(data.get("continue_url") or data.get("continueUrl") or "").strip()
    if direct:
        return direct
    page = data.get("page")
    if isinstance(page, dict):
        payload = page.get("payload")
        if isinstance(payload, dict):
            nested = str(
                payload.get("continue_url")
                or payload.get("continueUrl")
                or payload.get("next_url")
                or payload.get("nextUrl")
                or ""
            ).strip()
            if nested:
                return nested
    session_info = data.get("oai-client-auth-session")
    if isinstance(session_info, dict):
        return str(
            session_info.get("continue_url")
            or session_info.get("continueUrl")
            or ""
        ).strip()
    return ""


async def _authorize_continue_signup(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    email: str,
) -> dict[str, Any]:
    """Drive the current authorize state with screen_hint=signup.

    Recent auth.openai flows use /authorize/continue to decide whether the
    account should go to create_account_password or email_otp_verification.
    Skipping this step can leave us guessing and using the wrong OTP endpoint.
    """
    body = json.dumps({
        "username": {"value": email, "kind": "email"},
        "screen_hint": "signup",
    })
    headers = json_headers(
        profile,
        device_id,
        f"{AUTH_BASE}/create-account",
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
        content=body,
        headers=headers,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"authorize/continue HTTP {resp.status_code}: {_snippet(resp.text)}")
    try:
        out = resp.json() if resp.text else {}
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"authorize/continue 非 JSON: {_snippet(resp.text)}") from exc
    return out if isinstance(out, dict) else {}


def _is_email_otp_step(page_type: str, email_mode: str, continue_url: str) -> bool:
    page = str(page_type or "").strip().lower().replace("-", "_")
    mode = str(email_mode or "").strip().lower().replace("-", "_")
    target = str(continue_url or "").strip().lower()
    return (
        "email_otp" in page
        or "email_verification" in page
        or mode in {"otp", "email_otp", "passwordless"}
        or "/email-verification" in target
        or "/email-otp" in target
    )


async def _user_register(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    email: str,
    password: str,
) -> bool:
    """Step 2: 提交 email + password（sentinel flow=username_password_create）。"""
    body = json.dumps({"username": email, "password": password})
    headers = json_headers(
        profile,
        device_id,
        f"{AUTH_BASE}/create-account/password",
        document_navigation_id=str(
            getattr(client, "document_navigation_id", "") or ""
        ),
    )
    headers.update(
        await sentinel.sentinel_headers(
            client,
            "username_password_create",
            observer_timeout_ms=5000,
        )
    )
    resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/api/accounts/user/register",
        content=body, headers=headers,
    )
    if resp.status_code in (200, 201):
        return True
    raw = resp.text or ""
    if '"invalid_auth_step"' in raw:
        # 上次注册流程已走到 email_otp 阶段；续跑 send/validate，不要直接失败。
        return False
    if "Failed to create account" in raw or "account_creation_failed" in raw:
        # 如果 authorize/continue 明确给的是 create_account_password，
        # account_creation_failed 表示账号创建被拒，通常不会进入 email OTP，
        # 继续轮询只会空等。只有 invalid_auth_step 才按已进入 OTP 处理。
        raise AccountCreationFailedError(
            f"HTTP {resp.status_code} account_creation_failed（OpenAI 未创建账号，通常不会发验证码）: "
            f"{_snippet(raw)}"
        )
    raise RuntimeError(f"user/register HTTP {resp.status_code}: {_snippet(raw)}")


async def _send_email_otp(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    referer: str = f"{AUTH_BASE}/create-account/password",
) -> None:
    """Step 3: 触发邮件（GET + navigate 头，cors 会被 sentinel 砍）。"""
    headers = nav_headers(profile, device_id, site="same-origin")
    headers["Referer"] = referer
    resp = await request_with_retry(
        client, "GET", f"{AUTH_BASE}/api/accounts/email-otp/send", headers=headers,
    )
    if resp.status_code not in (200, 302):
        raise RuntimeError(f"email-otp/send HTTP {resp.status_code}: {_snippet(resp.text)}")


async def _send_passwordless_otp(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    referer: str = f"{AUTH_BASE}/create-account/password",
    sentinel_token: str = "",
) -> bool:
    headers = json_headers(
        profile,
        device_id,
        referer,
        document_navigation_id=str(
            getattr(client, "document_navigation_id", "") or ""
        ),
    )
    if sentinel_token:
        headers["openai-sentinel-token"] = sentinel_token
    resp = await request_with_retry(
        client,
        "POST",
        f"{AUTH_BASE}/api/accounts/passwordless/send-otp",
        headers=headers,
    )
    return resp.status_code in (200, 201, 204)


async def _resend_email_otp(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    referer: str = f"{AUTH_BASE}/email-verification",
    sentinel_token: str = "",
) -> bool:
    headers = json_headers(
        profile,
        device_id,
        referer,
        document_navigation_id=str(
            getattr(client, "document_navigation_id", "") or ""
        ),
    )
    if sentinel_token:
        headers["openai-sentinel-token"] = sentinel_token
    resp = await request_with_retry(
        client,
        "POST",
        f"{AUTH_BASE}/api/accounts/email-otp/resend",
        headers=headers,
    )
    return resp.status_code == 200


async def _kickoff_email_otp(
    client: httpx.AsyncClient,
    *,
    sentinel: SentinelGenerator,
    profile: Profile,
    device_id: str,
    existing_or_resumed: bool,
    log: Callable[[str], None],
) -> None:
    """Send/resend OTP using the endpoint that matches the current auth state."""
    sentinel_token = ""
    try:
        sentinel_token = await sentinel.sentinel_token(client, "authorize_continue")
    except Exception as exc:  # noqa: BLE001
        log(f"⚠️ [4/8] 发码前刷新 sentinel 失败，继续尝试：{exc}")
    if existing_or_resumed:
        log("📮 [4/8] 续跑/已有状态优先 resend 邮箱验证码 ...")
        if await _resend_email_otp(
            client,
            profile=profile,
            device_id=device_id,
            sentinel_token=sentinel_token,
        ):
            return
        log("⚠️ [4/8] resend 失败，兜底 email-otp/send(email-verification) ...")
        await _send_email_otp(
            client,
            profile=profile,
            device_id=device_id,
            referer=f"{AUTH_BASE}/email-verification",
        )
        return

    log("📮 [4/8] 新注册状态触发邮箱验证码 ...")
    if await _send_passwordless_otp(
        client,
        profile=profile,
        device_id=device_id,
        sentinel_token=sentinel_token,
    ):
        log("📮 [4/8] passwordless/send-otp OK")
        return
    if await _resend_email_otp(
        client,
        profile=profile,
        device_id=device_id,
        sentinel_token=sentinel_token,
    ):
        log("📮 [4/8] email-otp/resend OK")
        return
    await _send_email_otp(client, profile=profile, device_id=device_id)


def _mask_otp(code: str) -> str:
    code = str(code or "")
    if len(code) < 4:
        return "**"
    return f"{code[:2]}**{code[-2:]}"


def _is_mailbox_unavailable_error(exc: BaseException) -> bool:
    return bool(getattr(exc, "mailbox_unavailable", False))


async def _maybe_prime_otp_fetcher(
    otp_fetcher: OtpFetcher,
    email: str,
    log: Callable[[str], None],
) -> None:
    """If the mailbox backend supports it, snapshot the current/latest code.

    Direct-code Email API providers often return the latest cached code even
    before OpenAI sends the new one.  Priming marks that cached value as stale
    so the first poll waits for a different code instead of immediately using
    an old OTP.
    """
    prime = getattr(otp_fetcher, "prime", None)
    if not callable(prime):
        return
    try:
        old = prime(email)
        if inspect.isawaitable(old):
            old = await old
        if old:
            log(f"📭 [4/8] 预读到旧验证码 {_mask_otp(str(old))}，后续会排除")
    except Exception as exc:  # noqa: BLE001
        if _is_mailbox_unavailable_error(exc):
            raise
        log(f"⚠️ [4/8] 预读旧验证码失败，继续发码：{exc}")


async def _maybe_mark_bad_otp(
    otp_fetcher: OtpFetcher,
    email: str,
    code: str,
) -> None:
    marker = getattr(otp_fetcher, "mark_bad", None)
    if not callable(marker):
        return
    out = marker(email, code)
    if inspect.isawaitable(out):
        await out


def _otp_fetcher_is_generation_aware(otp_fetcher: OtpFetcher) -> bool:
    return bool(getattr(otp_fetcher, "generation_aware", False))


async def _maybe_begin_otp_generation(
    otp_fetcher: OtpFetcher,
    email: str,
    log: Callable[[str], None],
) -> bool:
    begin = getattr(otp_fetcher, "begin_generation", None)
    if not callable(begin):
        return False
    old = begin(email)
    if inspect.isawaitable(old):
        old = await old
    if old:
        log(f"📭 发码前基线验证码 {_mask_otp(str(old))}")
    return True


async def _maybe_mark_otp_send_started(
    otp_fetcher: OtpFetcher,
    email: str,
) -> bool:
    """Record the wall-clock boundary immediately before an OTP send request."""
    marker = getattr(otp_fetcher, "mark_send_started", None)
    if not callable(marker):
        return False
    out = marker(email)
    if inspect.isawaitable(out):
        await out
    return True


async def _maybe_wait_current_otp_generation(
    otp_fetcher: OtpFetcher,
    email: str,
    log: Callable[[str], None],
) -> str:
    """Wait for another candidate before invalidating the current send.

    Direct-code APIs can surface an older email first. A resend would invalidate
    the correct OTP that may still be in flight, so generation-aware providers
    get one polling window before a new send is triggered.
    """
    if not _otp_fetcher_is_generation_aware(otp_fetcher):
        return ""
    log("⏳ OTP 被拒，先等待当前发码代次的其他候选码 ...")
    try:
        code = str(await otp_fetcher(email) or "").strip()
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        if _is_mailbox_unavailable_error(exc):
            raise
        log(f"📭 当前发码代次未出现其他候选码，准备 resend：{exc}")
        return ""
    if code:
        log(f"📨 当前发码代次出现候选验证码 {_mask_otp(code)}")
    return code


async def _maybe_set_strict_stale_otp(
    otp_fetcher: OtpFetcher,
    email: str,
    *,
    enabled: bool,
    max_retries: int = 8,
) -> bool:
    setter = getattr(otp_fetcher, "set_strict_stale", None)
    if not callable(setter):
        return False
    out = setter(email, enabled, max_retries)
    if inspect.isawaitable(out):
        await out
    return True


async def _validate_email_otp(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    otp: str,
) -> str:
    """Validate a passwordless OTP with the current Auth Web Sentinel context."""
    body = json.dumps({"code": otp})
    headers = json_headers(
        profile,
        device_id,
        f"{AUTH_BASE}/email-verification",
        document_navigation_id=str(
            getattr(client, "document_navigation_id", "") or ""
        ),
    )
    headers.update(
        await sentinel.sentinel_headers(
            client,
            "email_otp_validate",
            observer_timeout_ms=5000,
        )
    )
    resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/api/accounts/email-otp/validate",
        content=body, headers=headers,
    )

    def _raise_known_otp_error(response: Any) -> None:
        raw = response.text or ""
        low = raw.lower()
        if "invalid_auth_step" in low:
            raise EmailAuthStepError(
                f"email-otp/validate HTTP {response.status_code}: {_snippet(raw)}"
            )
        if (
            "wrong_email_otp_code" in low
            or "wrong code" in low
            or "incorrect" in low
            or "expired" in low
        ):
            raise EmailOtpInvalidError(
                f"email-otp/validate HTTP {response.status_code}: {_snippet(raw)}"
            )

    def _continue_url(response: Any) -> str:
        try:
            out = response.json() if response.text else {}
        except Exception:  # noqa: BLE001
            out = {}
        if isinstance(out, dict):
            return _extract_continue_url(out) or str(
                out.get("redirect_uri")
                or out.get("redirect_url")
                or out.get("url")
                or ""
            )
        return ""

    if resp.status_code == 200:
        return _continue_url(resp)

    _raise_known_otp_error(resp)
    raise RuntimeError(
        f"email-otp/validate HTTP {resp.status_code}: {_snippet(resp.text)}"
    )


async def _fetch_and_validate_email_otp_with_continue(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    email: str,
    otp_fetcher: OtpFetcher,
    log: Callable[[str], None],
    max_attempts: int = 3,
    last_code: str = "",
) -> tuple[str, str]:
    """Fetch and validate an OTP, preserving the auth continuation URL."""
    otp = last_code
    for attempt in range(1, max_attempts + 1):
        if not otp:
            log(f"📬 [5/8] 等邮箱收码（尝试 {attempt}/{max_attempts}）...")
            otp = await otp_fetcher(email)
            log(f"📨 [5/8] 收到验证码 {otp[:2]}**{otp[-2:]}")
        log(f"🔑 [6/8] 回填验证码（尝试 {attempt}/{max_attempts}）...")
        try:
            continue_url = await _validate_email_otp(
                client, sentinel, profile=profile, device_id=device_id, otp=otp,
            )
            return otp, continue_url
        except EmailAuthStepError as exc:
            raise RuntimeError(
                f"OTP 验证 invalid_auth_step（auth flow 已失效，不重试）: {exc}"
            ) from exc
        except EmailOtpInvalidError as exc:
            await _maybe_mark_bad_otp(otp_fetcher, email, otp)
            if attempt >= max_attempts:
                raise
            log(f"🔁 [6/8] OTP 被拒：{exc}")
            otp = await _maybe_wait_current_otp_generation(
                otp_fetcher,
                email,
                log,
            )
            if otp:
                continue
            await _maybe_begin_otp_generation(otp_fetcher, email, log)
            log("📮 [6/8] 当前代次无其他候选码，resend 后重试 ...")
            retry_sentinel = ""
            try:
                retry_sentinel = await sentinel.sentinel_token(client, "authorize_continue")
            except Exception:  # noqa: BLE001
                retry_sentinel = ""
            await _maybe_mark_otp_send_started(otp_fetcher, email)
            if not await _resend_email_otp(
                client,
                profile=profile,
                device_id=device_id,
                sentinel_token=retry_sentinel,
            ):
                await _send_email_otp(
                    client,
                    profile=profile,
                    device_id=device_id,
                    referer=f"{AUTH_BASE}/email-verification",
                )
            otp = ""
    raise RuntimeError("email OTP 重试耗尽")


async def _fetch_and_validate_email_otp(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    email: str,
    otp_fetcher: OtpFetcher,
    log: Callable[[str], None],
    max_attempts: int = 3,
    last_code: str = "",
) -> str:
    """Backward-compatible wrapper used by the legacy password flow."""
    otp, _ = await _fetch_and_validate_email_otp_with_continue(
        client,
        sentinel,
        profile=profile,
        device_id=device_id,
        email=email,
        otp_fetcher=otp_fetcher,
        log=log,
        max_attempts=max_attempts,
        last_code=last_code,
    )
    return otp


async def _continue_authorization(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    continue_url: str,
) -> str:
    """Navigate the post-OTP continuation so auth cookies reach about-you."""
    target = str(continue_url or "").strip()
    if not target:
        return ""
    target = urljoin(f"{AUTH_BASE}/", target)
    headers = nav_headers(profile, device_id, site="same-origin")
    headers["Referer"] = f"{AUTH_BASE}/email-verification"
    resp = await request_with_retry(
        client,
        "GET",
        target,
        headers=headers,
        follow_redirects=True,
    )
    if resp.status_code >= 400:
        raise RuntimeError(
            f"authorize continuation HTTP {resp.status_code}: {_snippet(resp.text)}"
        )
    return str(resp.url or "")


async def _create_account(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    full_name: str,
    birthday: str,
) -> str:
    """Step 6: 提交 name + birthdate（sentinel flow=oauth_create_account）。

    成功时新版接口会直接返回 continue_url，其中可能已经带 OAuth code。
    返回该 URL 让上层优先用原始 PKCE verifier 换 token，避免 passwordless
    账号后续再走密码登录路径。
    """
    body = json.dumps({"name": full_name, "birthdate": birthday})
    headers = json_headers(
        profile,
        device_id,
        f"{AUTH_BASE}/about-you",
        document_navigation_id=str(
            getattr(client, "document_navigation_id", "") or ""
        ),
    )
    headers.update(
        await sentinel.sentinel_headers(
            client,
            "oauth_create_account",
            observer_timeout_ms=5000,
        )
    )
    resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/api/accounts/create_account",
        content=body, headers=headers,
    )
    if resp.status_code in (200, 302):
        loc = resp.headers.get("Location", "")
        try:
            out = resp.json() if resp.text else {}
        except Exception:  # noqa: BLE001
            out = {}
        if isinstance(out, dict):
            page = out.get("page") if isinstance(out.get("page"), dict) else {}
            payload = page.get("payload") if isinstance(page.get("payload"), dict) else {}
            return str(
                out.get("continue_url")
                or out.get("redirect_uri")
                or out.get("redirect_url")
                or out.get("url")
                or payload.get("url")
                or loc
                or ""
            )
        return loc or ""
    raw = resp.text or ""
    if resp.status_code == 400 and "user_already_exists" in raw:
        # 2026-07 实测部分邮箱在 email-otp/validate 后账号已落库，
        # create_account 再提交会返回 user_already_exists；后续重新 authorize 仍可拿 code。
        return ""
    raise RuntimeError(f"create_account HTTP {resp.status_code}: {_snippet(raw)}")


# ---------------------------------------------------------------------------
# Phase 2: 重新走一遍 OAuth login 拿 ?code=
# ---------------------------------------------------------------------------


async def _prime_authorize(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    pkce_challenge: str,
    state_val: str,
    nonce_val: str,
    email: str,
) -> str:
    """重新 GET /api/accounts/authorize 并手动 chase（最多 10 跳）找 ?code=。

    注册阶段种下"已登录"cookie 后，OpenAI 看到时会直接 307 到 redirect_uri?code=，
    半路截获；没拿到返回空串，调用方走 password/verify。
    """
    params = {
        "issuer": AUTH_BASE,
        "client_id": PLATFORM_CLIENT_ID,
        "audience": PLATFORM_AUDIENCE,
        "redirect_uri": PLATFORM_REDIRECT_URI,
        "device_id": device_id,
        "screen_hint": "login_or_signup",
        "max_age": "0",
        "login_hint": email,
        "scope": DEFAULT_SCOPE,
        "response_type": "code",
        "response_mode": "query",
        "state": state_val,
        "nonce": nonce_val,
        "code_challenge": pkce_challenge,
        "code_challenge_method": "S256",
        "auth0Client": PLATFORM_AUTH0_CLIENT,
    }
    headers = nav_headers(profile, device_id, site="same-origin")
    headers["Referer"] = "https://platform.openai.com/"

    cur_url = f"{AUTH_BASE}/api/accounts/authorize"
    cur_params: Optional[dict[str, str]] = params
    for hop in range(10):
        resp = await request_with_retry(
            client, "GET", cur_url, params=cur_params, headers=headers,
            follow_redirects=False,
        )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"prime authorize HTTP {resp.status_code} (hop {hop}): {_snippet(resp.text)}"
            )
        loc = resp.headers.get("Location", "")
        if loc:
            full = loc if loc.startswith("http") else urljoin(str(resp.url), loc)
            code = _pick_code_from_url(full)
            if code:
                return code
            cur_url = full
            cur_params = None
            continue
        return ""
    return ""


async def _password_verify(
    client: httpx.AsyncClient,
    sentinel: SentinelGenerator,
    *,
    profile: Profile,
    device_id: str,
    password: str,
) -> tuple[bool, str]:
    """POST /api/accounts/password/verify。

    Returns:
        (needs_email_otp, continue_url)。撞 add_phone / phone_otp 墙时直接抛错
        （精简版不接 SMS）。
    """
    tok = await sentinel.sentinel_token(client, "password_verify")
    body = json.dumps({"password": password})
    headers = json_headers(
        profile,
        device_id,
        f"{AUTH_BASE}/log-in/password",
        document_navigation_id=str(
            getattr(client, "document_navigation_id", "") or ""
        ),
    )
    headers["openai-sentinel-token"] = tok
    resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/api/accounts/password/verify",
        content=body, headers=headers,
    )
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"password/verify HTTP {resp.status_code}: {_snippet(resp.text)}")
    try:
        out = resp.json()
    except Exception:  # noqa: BLE001
        out = {}
    page_type = ((out.get("page") or {}).get("type") or "").strip()
    cont = (out.get("continue_url") or "").strip()
    if page_type == "add_phone":
        raise RuntimeError("password/verify 撞 add_phone 墙（精简版未实现添加手机号）")
    if page_type in ("phone_verification", "phone_otp"):
        raise RuntimeError("password/verify 撞短信验证（精简版不接 SMS）")
    if page_type in ("email_otp_verification", "otp_verification"):
        return True, cont
    if not cont:
        raise RuntimeError(
            f"password/verify 没 continue_url，page.type={page_type}, body={_snippet(resp.text)}"
        )
    return False, cont


# ---------------------------------------------------------------------------
# Consent / code 抓取
# ---------------------------------------------------------------------------


async def _chase_to_code(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    start_url: str,
    max_hops: int = 10,
) -> str:
    """GET start_url，最多 hop max_hops 次找 ?code=。"""
    cur = start_url
    for _ in range(max_hops):
        headers = nav_headers(profile, device_id, site="same-origin")
        headers["Referer"] = AUTH_BASE + "/"
        resp = await request_with_retry(
            client, "GET", cur, headers=headers, follow_redirects=False
        )
        loc = resp.headers.get("Location", "")
        if loc:
            full = loc if loc.startswith("http") else urljoin(cur, loc)
            code = _pick_code_from_url(full)
            if code:
                return code
            cur = full
            continue
        code = _pick_code_from_url(str(resp.url))
        if code:
            return code
        return ""
    return ""


def _pick_workspace_id_from_cookie(client: httpx.AsyncClient) -> str:
    """从 oai-client-auth-session cookie 解码取 workspaces[0].id。"""
    for cookie in client.cookies.jar:
        if cookie.name != "oai-client-auth-session":
            continue
        raw = cookie.value or ""
        parts = raw.split(".")
        if not parts:
            continue
        head = parts[0]
        pad = "=" * (-len(head) % 4)
        try:
            payload = json.loads(base64.urlsafe_b64decode(head + pad).decode("utf-8"))
        except Exception:  # noqa: BLE001
            continue
        ws = payload.get("workspaces") or []
        if ws and isinstance(ws[0], dict) and ws[0].get("id"):
            return str(ws[0]["id"])
    return ""


async def _extract_code(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    device_id: str,
    continue_url: str,
) -> str:
    """Step 7: 完整 consent 链路找 ?code=（chase → workspace/select → organization/select）。"""
    code = await _chase_to_code(
        client, profile=profile, device_id=device_id, start_url=continue_url
    )
    if code:
        return code

    ws_id = _pick_workspace_id_from_cookie(client)
    if not ws_id:
        raise RuntimeError(
            "consent chase 没拿到 ?code= 且 cookie 里没 workspaces[]，注册可能没成功"
        )
    ws_body = json.dumps({"workspace_id": ws_id})
    ws_headers = json_headers(
        profile,
        device_id,
        continue_url,
        document_navigation_id=str(
            getattr(client, "document_navigation_id", "") or ""
        ),
    )
    ws_resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/api/accounts/workspace/select",
        content=ws_body, headers=ws_headers, follow_redirects=False,
    )
    code = _pick_code_from_url((ws_resp.headers.get("Location") or "").strip())
    if code:
        return code
    try:
        ws_out = ws_resp.json()
    except Exception:  # noqa: BLE001
        ws_out = {}
    ws_continue = (ws_out.get("continue_url") or "").strip()
    if ws_continue:
        code = await _chase_to_code(
            client, profile=profile, device_id=device_id, start_url=ws_continue
        )
        if code:
            return code

    orgs = (ws_out.get("data") or {}).get("orgs") or []
    if not orgs:
        raise RuntimeError(f"workspace/select 后没 ?code= 也没 orgs[]，body={_snippet(ws_resp.text)}")
    org_id = (orgs[0].get("id") or "").strip()
    if not org_id:
        raise RuntimeError("workspace/select 返回的 orgs[0].id 为空")
    projects = orgs[0].get("projects") or []
    proj_id = (projects[0].get("id") or "").strip() if projects else ""

    org_body_dict: dict[str, Any] = {"org_id": org_id}
    if proj_id:
        org_body_dict["project_id"] = proj_id
    org_headers = json_headers(
        profile,
        device_id,
        continue_url,
        document_navigation_id=str(
            getattr(client, "document_navigation_id", "") or ""
        ),
    )
    if ws_continue:
        org_headers["referer"] = ws_continue
    org_resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/api/accounts/organization/select",
        content=json.dumps(org_body_dict), headers=org_headers, follow_redirects=False,
    )
    code = _pick_code_from_url((org_resp.headers.get("Location") or "").strip())
    if code:
        return code
    try:
        org_out = org_resp.json()
    except Exception:  # noqa: BLE001
        org_out = {}
    org_continue = (org_out.get("continue_url") or "").strip()
    if org_continue:
        code = await _chase_to_code(
            client, profile=profile, device_id=device_id, start_url=org_continue
        )
        if code:
            return code
    raise RuntimeError(
        f"organization/select 也没 ?code=, status={org_resp.status_code}, body={_snippet(org_resp.text)}"
    )


# ---------------------------------------------------------------------------
# Token exchange
# ---------------------------------------------------------------------------


async def _token_exchange(
    client: httpx.AsyncClient, *, code: str, pkce_verifier: str,
) -> tuple[str, str, str, int]:
    """Step 8: 用 code + verifier 换 (access_token, refresh_token, id_token, expires_in)。"""
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": PLATFORM_REDIRECT_URI,
        "client_id": PLATFORM_CLIENT_ID,
        "code_verifier": pkce_verifier,
    }
    resp = await request_with_retry(
        client, "POST", f"{AUTH_BASE}/oauth/token",
        content=urlencode(form),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    if resp.status_code != 200:
        raise RuntimeError(f"/oauth/token HTTP {resp.status_code}: {_snippet(resp.text)}")
    data = resp.json()
    access = data.get("access_token") or ""
    refresh = data.get("refresh_token") or ""
    id_token = data.get("id_token") or ""
    expires_in = int(data.get("expires_in") or 0)
    if not access:
        raise RuntimeError(f"/oauth/token 缺 access_token: {_snippet(resp.text)}")
    return access, refresh, id_token, expires_in


async def _platform_passwordless_token_exchange(
    client: httpx.AsyncClient,
    *,
    profile: Profile,
    code: str,
    pkce_verifier: str,
) -> tuple[str, str, str, int]:
    """Exchange the first authorize code through the current Platform SPA API."""
    headers = {
        "accept": "*/*",
        "accept-language": profile.locale,
        "auth0-client": PLATFORM_AUTH0_CLIENT,
        "cache-control": "no-cache",
        "content-type": "application/json",
        "origin": "https://platform.openai.com",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": "https://platform.openai.com/",
        "sec-ch-ua": profile.sec_ch_ua,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": profile.sec_ch_ua_platform,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": profile.user_agent,
    }
    resp = await request_with_retry(
        client,
        "POST",
        f"{AUTH_BASE}/api/accounts/oauth/token",
        headers=headers,
        json={
            "client_id": PLATFORM_CLIENT_ID,
            "code_verifier": pkce_verifier,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": PLATFORM_REDIRECT_URI,
        },
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"api/accounts/oauth/token HTTP {resp.status_code}: {_snippet(resp.text)}"
        )
    data = resp.json()
    access = str(data.get("access_token") or "")
    refresh = str(data.get("refresh_token") or "")
    id_token = str(data.get("id_token") or "")
    expires_in = int(data.get("expires_in") or 0)
    missing = [
        name
        for name, value in (("access_token", access), ("refresh_token", refresh))
        if not value
    ]
    if missing:
        raise RuntimeError(
            "api/accounts/oauth/token 缺字段: " + ", ".join(missing)
        )
    return access, refresh, id_token, expires_in


# ---------------------------------------------------------------------------
# 顶层 API
# ---------------------------------------------------------------------------


async def register_via_platform_passwordless(
    *,
    email: str,
    proxy: Optional[str],
    otp_fetcher: OtpFetcher,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    birthday: Optional[str] = None,
    log: Optional[Callable[[str], None]] = None,
    profile: Optional[Profile] = None,
    post_token_hook: Optional[
        Callable[[httpx.AsyncClient, Profile, str, RegisterResult], Awaitable[None]]
    ] = None,
    on_platform_result: Optional[Callable[[RegisterResult], Awaitable[None] | None]] = None,
) -> RegisterResult:
    """Register through Platform OAuth using the current passwordless flow.

    This deliberately never calls ``user/register`` or creates a local password.
    The OAuth code returned by the initial PKCE transaction is exchanged directly,
    matching the current yukkcat/chatgpt2api registration path.
    """
    import time as _t

    started = _t.monotonic()
    p = profile or random_profile(proxy=proxy)
    info = log or (lambda s: logger.info(s))
    if not email or "@" not in email:
        raise ValueError("email 非法")

    fn = first_name or "".join(
        secrets.choice(string.ascii_lowercase) for _ in range(7)
    ).capitalize()
    ln = last_name or "".join(
        secrets.choice(string.ascii_lowercase) for _ in range(8)
    ).capitalize()
    full_name = f"{fn} {ln}".strip()
    bd = birthday or _gen_birthday()

    device_id = new_device_id()
    pkce = new_pkce()
    state_val, nonce_val = random_state_nonce()

    info(
        f"🎒 [1/7] Platform passwordless · transport=curl_cffi/{p.impersonate} "
        f"UA={p.user_agent[:32]}... locale={p.locale}"
    )
    async with build_client(profile=p, proxy=proxy) as client:
        set_oai_did_cookie(client, device_id)
        sentinel = SentinelGenerator.from_profile(device_id, p)

        # authorize may send the OTP before the redirect chain finishes.
        await _maybe_prime_otp_fetcher(otp_fetcher, email, info)
        await _maybe_mark_otp_send_started(otp_fetcher, email)
        info("👋 [2/7] Platform authorize(login_hint) ...")
        authorize_final_url = await _platform_authorize(
            client,
            profile=p,
            device_id=device_id,
            pkce_challenge=pkce.challenge,
            state_val=state_val,
            nonce_val=nonce_val,
            email=email,
        )
        direct_otp = "/email-verification" in authorize_final_url.lower()
        if direct_otp:
            info("📮 [3/7] authorize 已直接发送 passwordless OTP")
        else:
            info("📧 [3/7] authorize/continue 提交注册邮箱 ...")
            await _maybe_mark_otp_send_started(otp_fetcher, email)
            step = await _authorize_continue_signup(
                client,
                sentinel,
                profile=p,
                device_id=device_id,
                email=email,
            )
            page_type, email_mode, continue_url = _auth_step_info(step)
            direct_otp = _is_email_otp_step(page_type, email_mode, continue_url)
            info(
                "🧭 [3/7] authorize/continue "
                f"page={page_type or '-'} mode={email_mode or '-'} "
                f"otp={'yes' if direct_otp else 'no'}"
            )
            if not direct_otp:
                info("📮 [3/7] 切换 passwordless signup 并发送 OTP ...")
                await _maybe_mark_otp_send_started(otp_fetcher, email)
                sent = await _send_passwordless_otp(
                    client,
                    profile=p,
                    device_id=device_id,
                )
                if not sent:
                    raise RuntimeError("authorize/continue 后仍未进入 OTP，passwordless/send-otp 也失败")

        info("📬 [4/7] 等待并验证注册 OTP ...")
        _otp, otp_continue_url = await _fetch_and_validate_email_otp_with_continue(
            client,
            sentinel,
            profile=p,
            device_id=device_id,
            email=email,
            otp_fetcher=otp_fetcher,
            log=info,
        )
        # Existing accounts can return an OAuth callback directly after OTP.
        code = _pick_code_from_url(otp_continue_url)
        if not code and otp_continue_url:
            continued_url = await _continue_authorization(
                client,
                profile=p,
                device_id=device_id,
                continue_url=otp_continue_url,
            )
            code = _pick_code_from_url(continued_url)

        if not code:
            info(f"🎂 [5/7] 创建账号资料 · 生日 {bd} ...")
            create_continue_url = await _create_account(
                client,
                sentinel,
                profile=p,
                device_id=device_id,
                full_name=full_name,
                birthday=bd,
            )
            if not create_continue_url:
                raise RuntimeError("create_account 成功响应缺少 OAuth continuation")
            code = _pick_code_from_url(create_continue_url)
            if not code:
                code = await _extract_code(
                    client,
                    profile=p,
                    device_id=device_id,
                    continue_url=create_continue_url,
                )
        else:
            info("👤 [5/7] 邮箱已存在，OTP 后直接返回 OAuth callback")

        if not code:
            raise RuntimeError("Platform passwordless 注册未拿到 OAuth callback code")

        info("🎁 [6/7] 兑换 Platform access / refresh / id_token ...")
        access, refresh, id_tok, expires_in = await _platform_passwordless_token_exchange(
            client,
            profile=p,
            code=code,
            pkce_verifier=pkce.verifier,
        )

        access_claims = _jwt_claims(access)
        id_claims = _jwt_claims(id_tok)
        auth_info = access_claims.get("https://api.openai.com/auth") or {}
        result_obj = RegisterResult(
            email=email,
            password="",
            access_token=access,
            refresh_token=refresh,
            id_token=id_tok,
            device_id=device_id,
            proxy_used=proxy,
            duration_seconds=_t.monotonic() - started,
            expires_in=expires_in,
            chatgpt_account_id=str(auth_info.get("chatgpt_account_id") or ""),
            chatgpt_user_id=str(auth_info.get("chatgpt_user_id") or ""),
            plan_type=str(auth_info.get("chatgpt_plan_type") or "plus"),
            sub=str(id_claims.get("sub") or access_claims.get("sub") or ""),
            auth_provider="openai",
            token_source="platform_passwordless",
        )
        info(
            "🪙 [7/7] Platform token OK · "
            f"access(len={len(access)}) refresh(len={len(refresh)})"
        )
        if on_platform_result is not None:
            hook_out = on_platform_result(result_obj)
            if inspect.isawaitable(hook_out):
                await hook_out
        if post_token_hook is not None:
            await post_token_hook(client, p, device_id, result_obj)
        return result_obj


async def register_via_protocol(
    *,
    email: str,
    proxy: Optional[str],
    otp_fetcher: OtpFetcher,
    password: Optional[str] = None,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    birthday: Optional[str] = None,
    fetch_account_id: bool = True,
    resume_otp_strict_retries: int = 4,
    log: Optional[Callable[[str], None]] = None,
    profile: Optional[Profile] = None,
    post_token_hook: Optional[
        Callable[[httpx.AsyncClient, Profile, str, RegisterResult], Awaitable[None]]
    ] = None,
    on_platform_result: Optional[Callable[[RegisterResult], Awaitable[None] | None]] = None,
) -> RegisterResult:
    """精简版协议注册（创建账号 + 拿 token，无支付）。

    Args:
        email: 已能收信的邮箱（Cloud Mail 子邮箱）
        proxy: 代理 URL（http://user:pass@host:port），None=直连
        otp_fetcher: 异步函数 `async def(email) -> str`，返回 6 位 OTP
        password: 留空 → 自动生成 16 位强密码
        first_name / last_name / birthday: 留空 → 随机
        resume_otp_strict_retries: 续跑路径短窗口轮询次数；只用于 send 后等“新码”
        log: 进度日志回调；默认 logger.info
        profile: 浏览器指纹；留空 → 随机
    """
    import time as _t

    started = _t.monotonic()
    p = profile or random_profile(proxy=proxy)
    info = log or (lambda s: logger.info(s))

    if not password:
        password = _gen_password(16)
    fn = first_name or "".join(secrets.choice(string.ascii_lowercase) for _ in range(7)).capitalize()
    ln = last_name or "".join(secrets.choice(string.ascii_lowercase) for _ in range(8)).capitalize()
    full_name = f"{fn} {ln}".strip()
    bd = birthday or _gen_birthday()

    device_id = new_device_id()
    pkce = new_pkce()
    state_val, nonce_val = random_state_nonce()
    result_obj: Optional[RegisterResult] = None

    info(
        f"🎒 [1/8] 准备身份卡 · transport=curl_cffi/{p.impersonate} "
        f"UA={p.user_agent[:32]}... locale={p.locale}"
    )

    async with build_client(profile=p, proxy=proxy) as client:
        set_oai_did_cookie(client, device_id)
        sentinel = SentinelGenerator.from_profile(device_id, p)

        info("👋 [2/8] 敲门 authorize ...")
        authorize_final_url = await _platform_authorize(
            client, profile=p, device_id=device_id,
            pkce_challenge=pkce.challenge, state_val=state_val,
            nonce_val=nonce_val, email=email,
        )
        if "/email-verification" in authorize_final_url:
            info("🧭 [2/8] authorize 已直接进入 email-verification")

        page_type = ""
        email_mode = ""
        continue_url = ""
        if "/email-verification" not in authorize_final_url:
            try:
                step = await _authorize_continue_signup(
                    client, sentinel, profile=p, device_id=device_id, email=email
                )
                page_type, email_mode, continue_url = _auth_step_info(step)
                if page_type or email_mode:
                    info(
                        f"🧭 [2/8] authorize/continue page={page_type or '-'} "
                        f"mode={email_mode or '-'}"
                    )
            except Exception as exc:  # noqa: BLE001
                # Older platform authorize flows can still work without this probe;
                # keep the old path as fallback instead of failing the mailbox here.
                info(f"⚠️ [2/8] authorize/continue 探测失败，回退旧注册路径：{exc}")

        direct_otp_state = (
            "/email-verification" in authorize_final_url
            or _is_email_otp_step(page_type, email_mode, continue_url)
        )
        if direct_otp_state:
            fresh_register = False
            info("🔁 [3/8] authorize/continue 已进入 email_otp，跳过 user/register ...")
        else:
            info("📝 [3/8] 提交账号密码 ...")
            try:
                fresh_register = await _user_register(
                    client, sentinel, profile=p, device_id=device_id,
                    email=email, password=password,
                )
            except AccountCreationFailedError as exc:
                info("⛔ [3/8] user/register 被拒，当前不是 email_otp 状态，不再空等验证码")
                raise RuntimeError(
                    "账号创建被 OpenAI 拒绝，且 authorize/continue 返回 create_account_password；"
                    "本次不会发邮箱验证码。建议换邮箱/代理/稍后重试，或抓到直接 "
                    "email-verification 的 HAR 后再适配。"
                ) from exc
            if not fresh_register:
                info("🔁 [3/8] 检测到 invalid_auth_step，按已进入 email_otp 路径继续 ...")

        await _maybe_prime_otp_fetcher(otp_fetcher, email, info)
        strict_stale_enabled = False
        if not fresh_register:
            if await _maybe_set_strict_stale_otp(
                otp_fetcher,
                email,
                enabled=True,
                max_retries=max(1, int(resume_otp_strict_retries or 1)),
            ):
                strict_stale_enabled = True
                info("🔒 [4/8] 续跑路径启用同码兜底：先等新验证码，窗口结束仍相同则提交一次")
        await _maybe_mark_otp_send_started(otp_fetcher, email)
        await _kickoff_email_otp(
            client,
            sentinel=sentinel,
            profile=p,
            device_id=device_id,
            existing_or_resumed=not fresh_register,
            log=info,
        )

        try:
            otp = await _fetch_and_validate_email_otp(
                client, sentinel, profile=p, device_id=device_id,
                email=email, otp_fetcher=otp_fetcher, log=info,
            )
        finally:
            if strict_stale_enabled:
                await _maybe_set_strict_stale_otp(otp_fetcher, email, enabled=False)

        info(f"🎂 [7/8] 录入资料 · 生日 {bd}，建账号 ...")
        create_continue_url = await _create_account(
            client, sentinel, profile=p, device_id=device_id,
            full_name=full_name, birthday=bd,
        )

        # 新 passwordless/signup 流在 create_account 响应里直接给 callback code。
        # 这个 code 绑定的是第一次 authorize 的 PKCE，所以优先用 pkce.verifier。
        code = _pick_code_from_url(create_continue_url)
        token_pkce_verifier = pkce.verifier
        if code:
            info("🎯 [8/8] create_account 直接返回 code")
        else:
            # Phase 2：清旧 session，用新 PKCE 重新 authorize 拿 ?code=
            info("🧹 [8/8] 清理旧会话，重新 PKCE ...")
            clear_oauth_session_cookies(client)
            pkce2 = new_pkce()
            token_pkce_verifier = pkce2.verifier
            state2, nonce2 = random_state_nonce()

            info("🔁 [8/8] 追跳转链找授权 code ...")
            code = await _prime_authorize(
                client, profile=p, device_id=device_id,
                pkce_challenge=pkce2.challenge, state_val=state2,
                nonce_val=nonce2, email=email,
            )
            if code:
                info("🎯 [8/8] 直接拿到 code")
            else:
                info("🔐 [8/8] 走密码登录路径 ...")
                needs_otp, continue_url = await _password_verify(
                    client, sentinel, profile=p, device_id=device_id, password=password,
                )
                if needs_otp:
                    info(f"📨 [8/8] 撞二次验证，复用 OTP {otp[:2]}**{otp[-2:]} ...")
                    try:
                        await _validate_email_otp(
                            client, sentinel, profile=p, device_id=device_id, otp=otp,
                        )
                    except RuntimeError as exc:
                        msg = str(exc).lower()
                        if (
                            isinstance(exc, EmailOtpInvalidError)
                            or "incorrect" in msg
                            or "expired" in msg
                            or "wrong_email_otp_code" in msg
                            or "wrong code" in msg
                        ):
                            info("🔁 [8/8] OTP 被拒，再拉一条新的 ...")
                            otp2 = await otp_fetcher(email)
                            await _validate_email_otp(
                                client, sentinel, profile=p, device_id=device_id, otp=otp2,
                            )
                        else:
                            raise
                if not continue_url:
                    continue_url = f"{AUTH_BASE}/sign-in-with-chatgpt/codex/consent"
                info("✅ [8/8] 追 consent 拿 code ...")
                code = await _extract_code(
                    client, profile=p, device_id=device_id, continue_url=continue_url
                )
                info("🎯 [8/8] 拿到 code")

        info("🎁 [8/8] 兑换 access / refresh / id_token ...")
        access, refresh, id_tok, expires_in = await _token_exchange(
            client, code=code, pkce_verifier=token_pkce_verifier,
        )
        info(
            f"🪙 [8/8] token 拿齐：access(len={len(access)}) "
            f"refresh(len={len(refresh)}) id_token(len={len(id_tok)})"
        )

        # 解 platform token claims（默认值）
        access_claims = _jwt_claims(access)
        id_claims = _jwt_claims(id_tok)
        auth_info = access_claims.get("https://api.openai.com/auth") or {}
        chatgpt_account_id = str(auth_info.get("chatgpt_account_id") or "")
        chatgpt_user_id = str(auth_info.get("chatgpt_user_id") or "")
        plan_type = str(auth_info.get("chatgpt_plan_type") or "plus")
        sub = str(id_claims.get("sub") or access_claims.get("sub") or "")

        # 复用「仍登录着」的同一 session，用 Codex client 再 authorize 拿 chatgpt_account_id。
        # 不走密码登录（密码登录会撞 add_phone）；team 账号此时自动进 team，授权链路走通。
        if fetch_account_id and not chatgpt_account_id:
            info("🪪 [+] 复用登录态，走 Codex client 拿 chatgpt_account_id ...")
            try:
                from .chatgpt_login import fetch_account_id_via_session

                acc = await fetch_account_id_via_session(
                    client, profile=p, device_id=device_id, email=email,
                )
                # 用 Codex token 覆盖（带 account_id）
                access = acc.access_token or access
                refresh = acc.refresh_token or refresh
                id_tok = acc.id_token or id_tok
                expires_in = acc.expires_in or expires_in
                chatgpt_account_id = acc.chatgpt_account_id or chatgpt_account_id
                chatgpt_user_id = acc.chatgpt_user_id or chatgpt_user_id
                plan_type = acc.plan_type or plan_type
                sub = acc.sub or sub
                info(f"🪪 [+] 拿到 chatgpt_account_id = {chatgpt_account_id or '(仍为空)'}")
            except Exception as exc:  # noqa: BLE001
                info(f"⚠️ [+] Codex 授权失败，保留 platform token（account_id 留空）：{exc}")

        elapsed = _t.monotonic() - started
        result_obj = RegisterResult(
            email=email,
            password=password,
            access_token=access,
            refresh_token=refresh,
            id_token=id_tok,
            device_id=device_id,
            proxy_used=proxy,
            duration_seconds=elapsed,
            expires_in=expires_in,
            chatgpt_account_id=chatgpt_account_id,
            chatgpt_user_id=chatgpt_user_id,
            plan_type=plan_type,
            sub=sub,
        )
        if on_platform_result is not None:
            hook_out = on_platform_result(result_obj)
            if inspect.isawaitable(hook_out):
                await hook_out
        if post_token_hook is not None:
            await post_token_hook(client, p, device_id, result_obj)

    if result_obj is None:
        raise RuntimeError("register_via_protocol 内部状态异常：缺少结果对象")
    return result_obj


__all__ = [
    "RegisterResult",
    "OtpFetcher",
    "EmailAuthStepError",
    "EmailOtpInvalidError",
    "AccountCreationFailedError",
    "register_via_platform_passwordless",
    "register_via_protocol",
]
