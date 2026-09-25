# -*- coding: utf-8 -*-
"""
OpenAI Auth 模块
处理 auth.openai.com 域名下的注册请求（步骤4-5、7-8、10、12）
以及 sentinel.openai.com 的 sentinel token 请求（步骤6、9、11）
"""
import json
import logging
import secrets
import time
from dataclasses import dataclass, replace

from config import SENTINEL_SV
from core.session import BrowserSession
from core.sentinel_runner import (
    generate_sentinel_artifacts,
    generate_sentinel_prepare_token,
    load_sentinel_sdk_assets,
)

logger = logging.getLogger(__name__)
_SENTINEL_FRAME_URL = (
    "https://sentinel.openai.com/backend-api/sentinel/frame.html"
    f"?sv={SENTINEL_SV}"
)


class EmailOtpInvalidError(RuntimeError):
    """邮箱验证码无效/过期，可重新发送后重试。"""


class AccountCreationFailedError(RuntimeError):
    """密码注册接口明确拒绝创建账号，不能按已进入 OTP 处理。"""


@dataclass(frozen=True, slots=True)
class PasswordRegistrationResult:
    """旧密码注册分支的状态；accepted 与 resumed_otp 始终互斥。"""

    accepted: bool
    resumed_otp: bool
    registration_password: str | None
    response: dict
    otp_requested_at: float | None = None


class AccountUnusableError(Exception):
    """
    邮箱对应的 OpenAI 账号已废（删除/停用/封禁），再试也是同样结果。

    与普通网络/风控错误区分：这类错误意味着这个邮箱素材本身不可用，
    上层应把邮箱标成 failed 直接剔除，而不是放回 available 反复重试。

    携带 error_code 便于日志与排查（如 account_deactivated）。
    """

    def __init__(self, message: str, error_code: str = ""):
        super().__init__(message)
        self.error_code = error_code


# 远端返回这些 error code 时，判定邮箱素材已废，不再重试。
_ACCOUNT_DEAD_CODES = frozenset({
    "account_deactivated",   # 账号已删除/停用
    "account_deleted",
    "account_banned",
})

_ACCOUNT_DEAD_TEXT_MARKERS = (
    "account_deactivated",
    "account_deleted",
    "account_banned",
    "account deactivated",
    "account deleted",
    "account banned",
    "account has been deactivated",
    "account has been deleted",
    "account was deactivated",
    "account was deleted",
    "your account has been deactivated",
    "your account has been deleted",
    "your account was deactivated",
    "your account was deleted",
    "账号已停用",
    "账号已禁用",
    "账号已删除",
    "账户已停用",
    "账户已禁用",
    "账户已删除",
)


def detect_account_unusable_text(text: str) -> str:
    """从浏览器页面/异常文本里识别账号已废，返回规范 error_code；未命中返回空串。"""
    low = str(text or "").lower()
    for code in _ACCOUNT_DEAD_CODES:
        if code in low:
            return code
    if any(marker in low for marker in _ACCOUNT_DEAD_TEXT_MARKERS):
        if "delete" in low or "删除" in low:
            return "account_deleted"
        if "ban" in low or "封" in low:
            return "account_banned"
        return "account_deactivated"
    return ""


def detect_account_unusable_response_body(body: str) -> str:
    """
    按纯协议模式同源逻辑，从接口响应 JSON 的 error.code 识别账号已废。

    这不是页面文字识别；用于浏览器/指纹浏览器拦截
    /api/accounts/email-otp/validate 响应后，读取响应体里的结构化错误码。
    """
    try:
        payload = json.loads(body or "")
    except Exception:
        return ""
    err = payload.get("error") if isinstance(payload, dict) else None
    code = ""
    if isinstance(err, dict):
        code = str(err.get("code") or "")
    elif isinstance(payload, dict):
        code = str(payload.get("code") or payload.get("error_code") or "")
    return code if code in _ACCOUNT_DEAD_CODES else ""


def _extract_error_code(resp) -> str:
    """从响应体 JSON 里抽 error.code（拿不到返回空串）。"""
    try:
        payload = resp.json()
    except Exception:
        return ""
    err = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(err, dict):
        return str(err.get("code") or "")
    if isinstance(payload, dict):
        return str(payload.get("code") or payload.get("error_code") or "")
    return ""


# 步骤4 网络层临时性错误（代理抽风 / TLS 握手失败 / 重置等）的重试参数
_FOLLOW_AUTH_MAX_ATTEMPTS = 3
_FOLLOW_AUTH_BACKOFF_BASE = 2.0  # 第 N 次重试前等 2^(N-1) 秒


def _is_transient_network_error(exc: Exception) -> bool:
    """识别可重试的临时性网络错误（TLS / 连接超时 / 连接重置 / 代理拒绝）。"""
    name = type(exc).__name__
    msg = str(exc).lower()
    transient_classes = ("SSLError", "ConnectionError", "Timeout", "CurlError", "ProxyError")
    if any(t.lower() in name.lower() for t in transient_classes):
        return True
    transient_keywords = (
        "wrong_version_number",      # 代理给了非 TLS 响应
        "tls connect",
        "ssl",
        "unexpected eof",
        "connection reset",
        "connection refused",
        "connection closed",
        "failed to connect",
        "couldn't connect",
        "timed out",
        "timeout was reached",
        "empty reply",
        "could not resolve host",
        "could not resolve proxy",
        "socks5 connection",
        "proxy",
        "curl: (6)",                 # DNS resolution failure
        "curl: (7)",                 # failed to connect
        "curl: (28)",                # operation timeout
        "curl: (35)",
        "curl: (52)",                # empty reply from server
        "curl: (55)",                # send failure
        "curl: (56)",                # network recv failure
        "curl: (92)",                # HTTP/2 stream error
        "curl: (97)",                # proxy handshake failure
    )
    return any(k in msg for k in transient_keywords)


def _is_broken_proxy_session_error(exc: Exception) -> bool:
    """识别继续重试同一 sticky 会话没有意义的 SOCKS/代理握手错误。"""
    msg = str(exc or "").lower()
    return any(marker in msg for marker in (
        "curl: (97)",
        "cannot complete socks5 connection",
        "socks5 authentication failed",
        "proxy authentication required",
        "proxy connect aborted",
    ))


def network_preflight(session: BrowserSession) -> None:
    """
    注册前网络预检：打开 ChatGPT 根页面，建立边缘节点/cookie/基础连通性。

    完整浏览器 HAR 在点击注册前不会预访 auth.openai.com/log-in 或 Sentinel frame；
    提前访问这两个域会制造额外 Cookie/页面轨迹，因此只验证真实首屏入口。
    """
    checks = [
        ("chatgpt-root", lambda: session.get(
            "https://chatgpt.com/",
            headers=session.get_chatgpt_navigate_headers(referer="https://chatgpt.com/"),
            allow_redirects=True,
        )),
    ]
    for label, fn in checks:
        last_exc = None
        for attempt in range(1, _FOLLOW_AUTH_MAX_ATTEMPTS + 1):
            try:
                logger.info(f"[预检] {label} ({attempt}/{_FOLLOW_AUTH_MAX_ATTEMPTS})")
                resp = fn()
                if getattr(resp, "status_code", 0) >= 400:
                    raise RuntimeError(f"{label} status={resp.status_code}, body={(getattr(resp, 'text', '') or '')[:180]}")
                break
            except Exception as exc:
                last_exc = exc
                if (
                    _is_broken_proxy_session_error(exc)
                    or not _is_transient_network_error(exc)
                    or attempt >= _FOLLOW_AUTH_MAX_ATTEMPTS
                ):
                    raise
                backoff = _FOLLOW_AUTH_BACKOFF_BASE ** (attempt - 1)
                logger.warning(f"[预检] {label} 临时失败：{type(exc).__name__}: {str(exc)[:120]}，{backoff:.1f}s 后重试")
                time.sleep(backoff)
        else:
            raise last_exc if last_exc else RuntimeError(f"[预检] {label} 未完成")


def follow_authorize(session: BrowserSession, authorize_url: str) -> str:
    """
    步骤4: 跟随 authorize URL 重定向。
    GET auth.openai.com/api/accounts/authorize?...

    这个请求会产生一系列重定向，建立 auth.openai.com 的 session cookies。
    遇到临时性网络错误（代理抽风 / TLS 握手失败 等）会自动重试。

    Args:
        session: 浏览器会话
        authorize_url: 从步骤3获取的 authorize URL
    """
    headers = session.get_auth_navigate_headers(referer="https://chatgpt.com/")

    last_exc: Exception | None = None
    for attempt in range(1, _FOLLOW_AUTH_MAX_ATTEMPTS + 1):
        try:
            logger.info(f"[步骤4] 跟随 authorize URL 重定向 (尝试 {attempt}/{_FOLLOW_AUTH_MAX_ATTEMPTS})...")
            resp = session.get(authorize_url, headers=headers, allow_redirects=True)
            resp.raise_for_status()
            final_url = str(getattr(resp, "url", "") or "")
            if "/api/accounts/user/register" in final_url or "/create-account/password" in final_url:
                logger.info("[步骤4] 检测到旧密码注册路径: %s", final_url)
            logger.info(f"[步骤4] 重定向完成, 最终URL: {final_url}")
            return final_url
        except Exception as exc:
            last_exc = exc
            if not _is_transient_network_error(exc):
                # 非临时性错误（比如 4xx 业务错误）直接抛出，不重试
                raise
            if attempt >= _FOLLOW_AUTH_MAX_ATTEMPTS:
                break
            backoff = _FOLLOW_AUTH_BACKOFF_BASE ** (attempt - 1)
            logger.warning(
                f"[步骤4] 临时性网络错误 ({type(exc).__name__}: {str(exc)[:120]})，"
                f"{backoff:.1f}s 后重试..."
            )
            time.sleep(backoff)

    # 三次都失败：抛出最后一次异常
    raise last_exc if last_exc else RuntimeError("步骤4 重试耗尽但无异常记录")


def request_sentinel_token(session: BrowserSession, flow: str) -> dict:
    """
    步骤6/9/11: 请求 Sentinel Token。
    POST https://sentinel.openai.com/backend-api/sentinel/req

    Args:
        session: 浏览器会话
        flow: 流程类型
            - "username_password_create": 步骤6
            - "email_otp_validate": 邮箱验证码校验
            - "authorize_continue": 提交邮箱/旧兼容分支
            - "oauth_create_account": 步骤11

    Returns:
        sentinel 响应 JSON，包含 token、turnstile、proofofwork 等
    """
    url = "https://sentinel.openai.com/backend-api/sentinel/req"

    sdk_url, sdk_source, sdk_hash = load_sentinel_sdk_assets(session)
    profile = getattr(session, "browser_profile", {}) or {}
    runner_context = {
        "user_agent": profile.get("user_agent"),
        "browser_profile": profile,
        "sentinel_sid": getattr(session, "sentinel_sid", None),
        "react_listening_key": getattr(session, "react_listening_key", None),
        "react_container_key": getattr(session, "react_container_key", None),
        "react_resources_key": getattr(session, "react_resources_key", None),
        "cookie": session.sentinel_cookie_header()
        if hasattr(session, "sentinel_cookie_header")
        else f"oai-did={session.device_id}",
    }
    prepare_token = generate_sentinel_prepare_token(
        sdk_source=sdk_source,
        sdk_url=sdk_url,
        flow=flow,
        device_id=session.device_id,
        **runner_context,
    )
    body = json.dumps(
        {"p": prepare_token, "id": session.device_id, "flow": flow},
        separators=(",", ":"),
    )

    headers = session.get_sentinel_headers()
    frame_url = str(
        getattr(session, "_auth_sentinel_frame_url", "")
        or headers.get("referer")
        or _SENTINEL_FRAME_URL
    ).strip()
    headers["referer"] = frame_url

    logger.info(f"[Sentinel] 请求 sentinel token, flow={flow}")
    resp = session.post(url, headers=headers, data=body)
    resp.raise_for_status()

    data = resp.json()
    if not isinstance(data, dict):
        raise RuntimeError("Sentinel 响应结构不是对象")
    challenge_token = str(data.get("token") or "").strip()
    if not challenge_token:
        raise RuntimeError("Sentinel 响应缺少 challenge token")

    # challenge 与 prepare token 必须作为一个不可拆分的上下文传给第二阶段。
    data["_sentinel_context"] = {
        "prepare_token": prepare_token,
        "sdk_url": sdk_url,
        "sdk_hash": sdk_hash,
        "flow": flow,
        "device_id": session.device_id,
    }
    sdk_sources = getattr(session, "_sentinel_sdk_sources", None)
    if not isinstance(sdk_sources, dict):
        sdk_sources = {}
        setattr(session, "_sentinel_sdk_sources", sdk_sources)
    sdk_sources[sdk_hash] = sdk_source
    logger.info(f"[Sentinel] 获取 sentinel token 成功, persona={data.get('persona')}")

    if data.get("proofofwork", {}).get("required"):
        seed = data["proofofwork"].get("seed", "")
        difficulty = data["proofofwork"].get("difficulty", "")
        logger.info(f"[Sentinel] 需要 PoW: seed={seed}, difficulty={difficulty}")

    # 增强诊断：哪些反爬机制被要求
    requires = []
    if data.get("turnstile", {}).get("required"):
        requires.append("turnstile")
    if data.get("so", {}).get("required"):
        requires.append("so")
    if data.get("proofofwork", {}).get("required"):
        requires.append("pow")
    logger.info(f"[Sentinel] 服务端要求项: {requires or '无'}")

    return data


def prime_sentinel_session(session: BrowserSession) -> tuple[str, str, str]:
    """进入 Auth Web 验证页后加载一次 Sentinel iframe/SDK。"""
    asset = load_sentinel_sdk_assets(session)
    logger.info(
        "[Sentinel] iframe/SDK 会话已初始化 sdk=%s...",
        str(asset[2] or "")[:12] or "?",
    )
    return asset


def build_sentinel_header(session: BrowserSession, sentinel_resp: dict, flow: str) -> tuple:
    """
    根据 sentinel 响应构建 openai-sentinel-token 和 openai-sentinel-so-token 请求头值。

    实现策略：把 challenge 喂给 sentinel-runner.js（Node + sdk.js 在 vm 沙箱中执行），
    让真实 SDK 自己产出包含 turnstile / so / pow 的最终 token，避免硬塞 dx 被风控拒绝。

    Args:
        session: 浏览器会话（提供 device_id 与 user_agent，必须与后续 HTTP 请求保持一致）
        sentinel_resp: sentinel/req 的响应 JSON
        flow: 流程类型，必须与请求 challenge 时传入的 flow 完全一致

    Returns:
        (sentinel_header, so_header) 元组
        sentinel_header: openai-sentinel-token 请求头的值（runner 直接产出的 JSON 字符串）
        so_header: 独立 openai-sentinel-so-token 复合 token；未要求 SO 时可为 None
    """
    if not isinstance(sentinel_resp, dict):
        raise ValueError("sentinel_resp 必须是对象")
    context = sentinel_resp.get("_sentinel_context")
    if not isinstance(context, dict):
        raise RuntimeError("Sentinel challenge 缺少两阶段上下文，请重新请求 challenge")

    prepare_token = str(context.get("prepare_token") or "").strip()
    sdk_url = str(context.get("sdk_url") or "").strip()
    sdk_hash = str(context.get("sdk_hash") or "").strip()
    if not prepare_token or not sdk_url or not sdk_hash:
        raise RuntimeError("Sentinel challenge 的两阶段上下文不完整")
    if str(context.get("flow") or "") != flow:
        raise RuntimeError("Sentinel challenge 与当前 flow 不一致")
    if str(context.get("device_id") or "") != str(session.device_id):
        raise RuntimeError("Sentinel challenge 与当前设备 ID 不一致")
    sdk_sources = getattr(session, "_sentinel_sdk_sources", {})
    sdk_source = str(sdk_sources.get(sdk_hash) or "") if isinstance(sdk_sources, dict) else ""
    if not sdk_source:
        current_url, current_source, current_hash = load_sentinel_sdk_assets(session)
        if current_url != sdk_url or current_hash != sdk_hash:
            raise RuntimeError("Sentinel SDK 在 challenge 期间发生变化，请重新开始该阶段")
        sdk_source = current_source

    challenge = {
        key: value
        for key, value in sentinel_resp.items()
        if key != "_sentinel_context"
    }
    profile = getattr(session, "browser_profile", {}) or {}
    artifacts = generate_sentinel_artifacts(
        challenge,
        prepare_token=prepare_token,
        sdk_source=sdk_source,
        sdk_url=sdk_url,
        sdk_hash=sdk_hash,
        flow=flow,
        device_id=session.device_id,
        observer_timeout_ms=5000,
        user_agent=profile.get("user_agent"),
        browser_profile=profile,
        sentinel_sid=getattr(session, "sentinel_sid", None),
        react_listening_key=getattr(session, "react_listening_key", None),
        react_container_key=getattr(session, "react_container_key", None),
        react_resources_key=getattr(session, "react_resources_key", None),
        cookie=session.sentinel_cookie_header()
        if hasattr(session, "sentinel_cookie_header")
        else f"oai-did={session.device_id}",
    )

    # oai-sc 只能在所有必需产物通过一致性校验后写入当前 HTTP 会话。
    if artifacts.oai_sc_value:
        for domain in (".openai.com", "openai.com", ".auth.openai.com", "auth.openai.com"):
            try:
                session.session.cookies.set(
                    "oai-sc", artifacts.oai_sc_value, domain=domain, path="/"
                )
            except Exception:
                logger.debug("[Sentinel] oai-sc 写入失败 domain=%s", domain, exc_info=True)

    logger.info(
        "[Sentinel] SDK 产物校验成功 flow=%s sdk=%s p=%s t=%s so=%s",
        flow,
        sdk_hash[:12] or "?",
        len(artifacts.proof_token),
        len(artifacts.turnstile_token),
        bool(artifacts.so_token),
    )
    return artifacts.token, artifacts.so_token or None


# ============================================================
# 旧密码注册分支
# ============================================================

_PASSWORD_PAGE_URL = "https://auth.openai.com/create-account/password"


def is_password_registration_url(url: str) -> bool:
    """判断 authorize 最终落点是否要求先设置账号密码。"""
    target = str(url or "").lower()
    return (
        "/create-account/password" in target
        or "/api/accounts/user/register" in target
    )


def generate_openai_registration_password(length: int = 14) -> str:
    """生成独立的 OpenAI 登录密码；不会读取 Outlook 邮箱素材密码。"""
    try:
        from config import register as register_config

        configured = str(getattr(register_config, "REGISTER_PASSWORD", "") or "").strip()
        if configured:
            return configured
    except Exception:
        logger.debug("读取 REGISTER_PASSWORD 失败，改用随机密码", exc_info=True)

    if length < 8 or length > 64:
        raise ValueError("OpenAI 注册密码长度必须在 8 到 64 之间")
    # '-' is reserved by the account export delimiter (``----``), so keep it
    # out of generated passwords to avoid ambiguous copy/paste boundaries.
    groups = (
        "ABCDEFGHJKLMNPQRSTUVWXYZ",
        "abcdefghjkmnpqrstuvwxyz",
        "23456789",
        "!@#$%^&*?_+=",
    )
    chars = [secrets.choice(group) for group in groups]
    pool = "".join(groups)
    chars.extend(secrets.choice(pool) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def _response_json_object(resp) -> dict:
    try:
        payload = resp.json()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def register_user(
    session: BrowserSession,
    email: str,
    password: str,
    sentinel_header: str,
    so_header: str | None = None,
) -> PasswordRegistrationResult:
    """提交旧版邮箱密码注册，并区分新建成功与已进入 OTP 的恢复状态。"""
    if not str(sentinel_header or "").strip():
        raise ValueError("user/register 缺少 openai-sentinel-token")

    url = "https://auth.openai.com/api/accounts/user/register"
    headers = session.get_auth_headers(referer=_PASSWORD_PAGE_URL)
    headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header

    body = json.dumps(
        {"password": password, "username": email},
        separators=(",", ":"),
    )
    logger.info("[步骤7] 提交旧密码注册请求, 邮箱: %s", email)
    resp = session.post(url, headers=headers, data=body)
    payload = _response_json_object(resp)
    error_code = _extract_error_code(resp)
    raw = str(getattr(resp, "text", "") or "")
    low = raw.lower()

    if error_code == "invalid_auth_step" or "invalid_auth_step" in low:
        logger.info("[步骤7] auth session 已进入邮箱 OTP，按恢复路径继续")
        return PasswordRegistrationResult(
            accepted=False,
            resumed_otp=True,
            registration_password=None,
            response=payload,
        )

    if resp.status_code in (200, 201):
        logger.info(
            "[步骤7] 密码注册请求已接受: %s",
            (payload.get("page") or {}).get("type")
            if isinstance(payload.get("page"), dict)
            else "unknown",
        )
        return PasswordRegistrationResult(
            accepted=True,
            resumed_otp=False,
            registration_password=password,
            response=payload,
        )

    if error_code in _ACCOUNT_DEAD_CODES:
        raise AccountUnusableError(
            f"账号已废弃（{error_code}），邮箱不可再用",
            error_code=error_code,
        )
    if error_code == "account_creation_failed" or any(
        marker in low
        for marker in ("account_creation_failed", "failed to create account")
    ):
        raise AccountCreationFailedError(
            f"user/register HTTP {resp.status_code}: {(raw or json.dumps(payload))[:240]}"
        )

    logger.error("[步骤7] 请求失败, 状态码: %s", resp.status_code)
    logger.error("[步骤7] 响应内容: %s", raw[:500])
    resp.raise_for_status()
    raise RuntimeError(f"user/register HTTP {resp.status_code} 返回未知错误")


def start_password_registration(
    session: BrowserSession,
    email: str,
    password: str | None = None,
) -> PasswordRegistrationResult:
    """完成密码页 Sentinel、user/register 和发码，然后交回既有 OTP 流程。"""
    candidate_password = password or generate_openai_registration_password()
    sentinel_response = request_sentinel_token(session, "username_password_create")
    sentinel_header, so_header = build_sentinel_header(
        session,
        sentinel_response,
        "username_password_create",
    )
    result = register_user(
        session,
        email,
        candidate_password,
        sentinel_header,
        so_header,
    )
    referer = (
        "https://auth.openai.com/email-verification"
        if result.resumed_otp
        else _PASSWORD_PAGE_URL
    )
    otp_requested_at = time.time()
    send_email_otp(session, referer=referer)
    return replace(result, otp_requested_at=otp_requested_at)


def navigate_about_you(session: BrowserSession, about_url: str | None = None) -> str:
    """进入 about-you 页面状态；服务端未返回 continue_url 时使用默认页面 URL 兜底。"""
    url = str(about_url or "https://auth.openai.com/about-you")
    if url.startswith("/"):
        url = "https://auth.openai.com" + url
    headers = session.get_auth_navigate_headers(referer="https://auth.openai.com/email-verification")
    headers["sec-fetch-site"] = "same-origin"
    logger.info("[步骤10.5] 导航到 about-you 页面，建立资料页状态")
    resp = session.get(url, headers=headers, allow_redirects=True)
    if resp.status_code >= 400:
        raise RuntimeError(f"about-you 导航失败 status={resp.status_code}: {(resp.text or '')[:240]}")
    final_url = str(getattr(resp, "url", "") or url)
    if "/api/accounts/user/register" in final_url or "/create-account/password" in final_url:
        raise RuntimeError(f"about-you 导航落入旧密码注册路径: {final_url}")
    logger.info(f"[步骤10.5] about-you 导航完成，落点: {final_url}")
    return final_url


def send_email_otp(session: BrowserSession, referer: str = "https://auth.openai.com/email-verification") -> None:
    """重新发送邮箱验证码。用于验证码错误/过期后重新取码。"""
    url = "https://auth.openai.com/api/accounts/email-otp/send"
    headers = session.get_auth_navigate_headers(referer=referer)
    headers["sec-fetch-site"] = "same-origin"
    headers["sec-fetch-user"] = "?1"
    logger.info("[OTP] 请求发送/重新发送邮箱验证码...")
    resp = session.get(url, headers=headers, allow_redirects=True)
    if resp.status_code >= 400:
        logger.warning("[OTP] 重新发送验证码失败 status=%s: %s", resp.status_code, (resp.text or '')[:300])
        resp.raise_for_status()
    logger.info("[OTP] 发送/重新发送验证码请求完成，status=%s", resp.status_code)


def validate_email_otp(session: BrowserSession, code: str, sentinel_header: str | None = None, so_header: str | None = None) -> dict:
    """
    步骤10: 提交邮箱验证码验证。
    POST https://auth.openai.com/api/accounts/email-otp/validate

    Args:
        session: 浏览器会话
        code: 6位数字验证码
        sentinel_header: openai-sentinel-token 头的值（email_otp_validate flow）

    Returns:
        验证响应 JSON，例如:
        {
            "continue_url": "https://auth.openai.com/about-you",
            "method": "GET",
            "page": {"type": "about_you", "backstack_behavior": "default"}
        }
    """
    url = "https://auth.openai.com/api/accounts/email-otp/validate"

    headers = session.get_auth_headers(referer="https://auth.openai.com/email-verification")
    if sentinel_header:
        headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
        logger.info("[步骤10] 已添加 openai-sentinel-so-token 头")

    body = json.dumps({"code": code})

    logger.info(f"[步骤10] 提交邮箱验证码: {code}")
    resp = session.post(url, headers=headers, data=body)

    if resp.status_code != 200:
        logger.error(f"[步骤10] 请求失败, 状态码: {resp.status_code}")
        logger.error(f"[步骤10] 响应内容: {resp.text}")
        # 先看是不是"账号已废"——这类邮箱再试也没用，单独抛出让上层标 failed
        err_code = _extract_error_code(resp)
        if err_code in _ACCOUNT_DEAD_CODES:
            raise AccountUnusableError(
                f"账号已废弃（{err_code}），邮箱不可再用", error_code=err_code,
            )
        low = (resp.text or '').lower()
        if resp.status_code in (400, 401, 422) and any(k in low for k in (
            'invalid', 'incorrect', 'expired', 'code', 'otp', 'verification',
            '验证码', '認証コード', '確認コード', 'コード'
        )):
            raise EmailOtpInvalidError(f"邮箱验证码无效或已过期: status={resp.status_code}, body={(resp.text or '')[:240]}")
        resp.raise_for_status()

    data = resp.json()
    page_type = data.get('page', {}).get('type')
    logger.info(f"[步骤10] 验证码验证成功: {page_type}")
    logger.info(f"[步骤10] 验证响应摘要: {json.dumps(data, ensure_ascii=False)[:1000]}")
    return data


def create_account(session: BrowserSession, name: str, birthday: str, sentinel_header: str, so_header: str = None) -> dict:
    """
    步骤12: 提交用户信息，完成注册。
    POST https://auth.openai.com/api/accounts/create_account

    Args:
        session: 浏览器会话
        name: 用户显示名称
        birthday: 生日，格式 "YYYY-MM-DD"
        sentinel_header: openai-sentinel-token 头的值
        so_header: openai-sentinel-so-token 头的值

    Returns:
        创建账号响应 JSON
    """
    url = "https://auth.openai.com/api/accounts/create_account"

    headers = session.get_auth_headers(referer="https://auth.openai.com/about-you")
    headers["openai-sentinel-token"] = sentinel_header
    if so_header:
        headers["openai-sentinel-so-token"] = so_header
        logger.info(f"[步骤12] 已添加 openai-sentinel-so-token 头")

    body = json.dumps({
        "name": name,
        "birthdate": birthday,
    })

    logger.info(f"[步骤12] 提交用户信息, 名称: {name}, 生日: {birthday}")
    resp = session.post(url, headers=headers, data=body)

    if resp.status_code != 200:
        logger.error(f"[步骤12] 请求失败, 状态码: {resp.status_code}")
        logger.error(f"[步骤12] 响应内容: {resp.text}")
        resp.raise_for_status()

    data = resp.json()
    logger.info("[步骤12] 创建接口返回成功，等待 OAuth 回调建立登录态")
    return data
