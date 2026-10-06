"""Opt-in Codex OAuth login with an existing password and TOTP credential."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import secrets
from urllib.parse import parse_qs, urljoin, urlparse

logger = logging.getLogger(__name__)


class PasswordTotpLoginError(RuntimeError):
    def __init__(self, message: str, *, code: str, retryable: bool = False):
        super().__init__(message)
        self.error_code = code
        self.retryable = retryable


def login_material(account: dict) -> tuple[str, str]:
    """Read only login credentials, never a previous access/refresh token."""
    extra = account.get("extra_json") or {}
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except (TypeError, ValueError):
            extra = {}
    if not isinstance(extra, dict):
        extra = {}
    password = str(extra.get("registration_password") or account.get("registration_password") or "")
    if not password or len(password) > 256 or "\r" in password or "\n" in password:
        raise PasswordTotpLoginError("缺少有效的 ChatGPT 账号密码", code="password_missing")
    secret = str(account.get("totp_secret") or "").replace(" ", "").strip().upper()
    if not secret:
        raise PasswordTotpLoginError("缺少已绑定的 TOTP 密钥", code="totp_secret_missing")
    try:
        decoded = base64.b32decode(secret + "=" * (-len(secret) % 8))
        if not decoded:
            raise ValueError("empty secret")
    except (ValueError, TypeError):
        raise PasswordTotpLoginError("TOTP 密钥不是有效 Base32", code="totp_secret_invalid") from None
    if str(account.get("totp_status") or "").lower() in {"queued", "running"}:
        raise PasswordTotpLoginError("账号正在补接 2FA，请完成后再授权", code="totp_busy")
    return password, secret


def login_material_fingerprint(account: dict) -> str:
    """Bind a successful MFA verification to the exact stored login material."""
    password, secret = login_material(account)
    material = [str(account.get("email") or "").strip().casefold(), password, secret]
    return hashlib.sha256(json.dumps(material, ensure_ascii=False).encode()).hexdigest()


def _auth_url(value: str) -> str:
    target = urljoin("https://auth.openai.com/", value)
    parsed = urlparse(target)
    if (
        parsed.scheme != "https" or parsed.hostname != "auth.openai.com"
        or parsed.username or parsed.password or parsed.port not in (None, 443)
    ):
        raise PasswordTotpLoginError("授权返回了非预期的下一步地址", code="unexpected_auth_target")
    return target


def _navigate_password(session, step: dict) -> str:
    from core import codex_oauth as oauth

    url = _auth_url(str(step.get("continue_url") or "/log-in/password"))
    if urlparse(url).path.rstrip("/") != "/log-in/password":
        raise PasswordTotpLoginError("服务端未进入密码登录步骤", code="password_step_missing")
    response = oauth._with_net_retry(
        "进入密码登录阶段",
        lambda: session.get(url, headers=session.get_auth_navigate_headers(
            referer="https://auth.openai.com/log-in",
        ), allow_redirects=False),
    )
    status = int(getattr(response, "status_code", 0) or 0)
    if not 200 <= status < 300:
        raise RuntimeError(f"password page status={status}: {oauth._response_text(response)[:240]}")
    oauth._sync_auth_document_context(session, response, stage="password_login")
    return url


def _reject_additional_verification(step: dict) -> None:
    from core import codex_oauth as oauth

    page_type, url = str(step.get("page_type") or ""), str(step.get("continue_url") or "")
    if step.get("email_otp_required") or oauth._auth_step_requires_email_otp(page_type, url):
        raise PasswordTotpLoginError(
            "服务端要求额外的邮箱验证；密码 + 2FA 模式不会自动发送或读取邮件",
            code="email_verification_required",
        )
    if step.get("phone_required") or oauth._auth_step_requires_phone(page_type, url):
        raise PasswordTotpLoginError(
            "服务端要求额外的手机验证；密码 + 2FA 模式不会自动购买号码",
            code="phone_verification_required",
        )


def _callback(session, step: dict, state: str, email: str, expected_workspace_id: str = "") -> str:
    from core import codex_oauth as oauth

    current = str(step.get("continue_url") or "")
    for _ in range(oauth._MAX_REDIRECTS):
        oauth._check_codex_flow_stop(email)
        if current and oauth._is_redirect_uri(current):
            return current
        if not current:
            return oauth._select_workspace_and_get_callback(session, state, **({"expected_workspace_id": expected_workspace_id} if expected_workspace_id else {}))
        target = _auth_url(current)
        path = urlparse(target).path.rstrip("/")
        if path in {"/workspace", "/sign-in-with-chatgpt/codex/consent"}:
            # 供协议层在 auth Cookie 缺失时读取同一 consent 文档的 SSR loaderData。
            session._codex_consent_url = target
            return oauth._select_workspace_and_get_callback(session, state, **({"expected_workspace_id": expected_workspace_id} if expected_workspace_id else {}))
        response = session.get(target, headers=session.get_auth_navigate_headers(
            referer="https://auth.openai.com/",
        ), allow_redirects=False)
        status = int(getattr(response, "status_code", 0) or 0)
        if status not in (301, 302, 303, 307, 308):
            raise RuntimeError(f"OAuth callback status={status}: {oauth._response_text(response)[:240]}")
        location = response.headers.get("location") or response.headers.get("Location")
        if not location:
            raise PasswordTotpLoginError("授权跳转缺少下一步地址", code="callback_missing")
        current = urljoin(target, str(location))
    raise PasswordTotpLoginError("OAuth 回调跳转次数超限", code="callback_redirect_limit")


def _failure(exc: Exception, *, stage: str, email: str, password: str, secret: str) -> dict:
    from core import codex_oauth as oauth

    text = str(exc)
    status_match = re.search(r"(?:status[=:]|http)\s*(\d{3})\b", text, re.I)
    status = getattr(exc, "http_status", None) or (int(status_match.group(1)) if status_match else None)
    code_match = re.search(r"\bcode=([a-zA-Z0-9_]+)", text)
    code = str(getattr(exc, "error_code", "") or (code_match.group(1) if code_match else ""))
    expired = code in {
        "session_expired", "invalid_session", "invalid_auth_step", "invalid_state",
    } or oauth._is_oauth_session_invalid_response(text, status)
    retryable = bool(getattr(exc, "retryable", False)) or expired
    if isinstance(exc, PasswordTotpLoginError):
        message = text
    elif expired:
        message = "OAuth 登录会话已失效，需要重新建立授权事务"
    elif status == 401:
        message = {
            "password": "密码验证被拒绝（HTTP 401），未自动切换邮箱验证码",
            "mfa": "TOTP 验证被拒绝（HTTP 401），请检查密钥、因子和系统时间",
        }.get(stage, "OAuth 请求被拒绝（HTTP 401）")
    else:
        message = f"密码 + 2FA 授权失败：stage={stage} error={type(exc).__name__}"
        if status is not None:
            message += f" HTTP {status}"
    if expired:
        code = "oauth_session_invalid"
    if not isinstance(exc, PasswordTotpLoginError) and (
        status in {403, 408, 425, 429} or (status is not None and status >= 500)
        or oauth._is_transient_network_error(exc) or oauth._is_broken_proxy_session_error(exc)
    ):
        retryable = True
    # The upstream MFA endpoint can report an account ban as HTTP 403. Keep
    # this terminal account state out of the generic edge-rejection retry path.
    # Password verification already maps these codes to AccountUnusableError;
    # this also covers the same response arriving during TOTP verification.
    account_unusable = code in {"account_deactivated", "account_deleted", "account_banned"}
    if account_unusable:
        retryable = False
        if not isinstance(exc, PasswordTotpLoginError):
            message = f"账号已封禁/停用（{code}）"
    for value in (password, secret):
        if value:
            message = message.replace(value, "***")
    return oauth._codex_result(
        status="deactivated" if account_unusable else "failed", email=email, message=message, failure_stage=stage,
        http_status=status, error_code=code or "password_totp_failed", retryable=retryable,
        login_mode="password_totp", error_type=type(exc).__name__,
    )


def retry_reason(result: dict) -> str:
    from core.account_state import unusable_account_code
    if unusable_account_code(result):
        return ""
    if result.get("ok") or not result.get("retryable"):
        return ""
    if result.get("error_code") == "oauth_session_invalid":
        return "oauth_session_invalid"
    if result.get("http_status") == 403:
        return "edge_rejected"
    return "network" if result.get("http_status") is None else "upstream_http"


def run_once(
    email: str, otp_provider=None, proxy=None, force=False,
    _cpa_reauth_round=1, auth_source=None, expected_workspace_id: str = "",
) -> dict:
    from core import codex_oauth as oauth, db, progress_events

    session = None
    password = secret = ""
    verified_factor_id = ""
    stage = "credentials"
    try:
        progress_events.phase(stage)
        if auth_source != "local":
            raise PasswordTotpLoginError("密码 + 2FA 授权只支持本地 PKCE", code="unsupported_auth_source")
        account = db.get_account_by_email(email) or {}
        password, secret = login_material(account)
        from core.account_state import unusable_account_code
        if code := unusable_account_code(account):
            raise PasswordTotpLoginError("账号已封禁/停用，不再授权", code=code)
        oauth._check_codex_flow_stop(email)
        stage = "session_init"
        progress_events.phase(stage)
        session = oauth.BrowserSession(proxy=proxy, browser_family=oauth._codex_browser_profile_key())
        profile = getattr(session, "browser_profile", {}) or {}
        logger.info("[Codex][密码+2FA] HTTP 指纹：profile=%s impersonate=%s",
                    oauth._codex_browser_profile_key(), profile.get("impersonate") or "unknown")
        session._codex_selected_workspace_id = ""
        verifier, challenge = oauth._generate_pkce()
        state = oauth._generate_state()
        stage = "network_preflight"
        progress_events.phase(stage)
        oauth.network_preflight(session)
        stage = "bootstrap"
        progress_events.phase(stage)
        oauth._bootstrap_authorize(session, state, challenge)
        stage = "email_submit"
        progress_events.phase(stage)
        oauth._check_codex_flow_stop(email)
        step = oauth._submit_email_identifier(session, email)
        _reject_additional_verification(step)
        page_type = str(step.get("page_type") or "")
        path = urlparse(urljoin("https://auth.openai.com/", str(step.get("continue_url") or ""))).path.rstrip("/")
        if page_type not in {"login_password", "password"} and path != "/log-in/password":
            raise PasswordTotpLoginError("服务端未返回密码登录步骤", code="password_step_missing")
        stage = "password"
        progress_events.phase(stage)
        password_url = _navigate_password(session, step)
        oauth._check_codex_flow_stop(email)
        step = oauth._submit_password_step(session, password)
        logger.info("[Codex][密码+2FA] 密码已验证")
        _reject_additional_verification(step)
        if step.get("mfa_required"):
            stage = "mfa"
            progress_events.phase(stage)
            oauth._check_codex_flow_stop(email)
            target = str(step.get("continue_url") or "")
            stored_factor = str(account.get("totp_factor_id") or "")
            factor = oauth._mfa_factor_id_from_url(target) or stored_factor
            if not re.fullmatch(r"[A-Za-z0-9_-]{8,256}", factor):
                raise PasswordTotpLoginError("缺少当前 MFA factor ID", code="mfa_factor_missing")
            if stored_factor and not secrets.compare_digest(stored_factor, factor):
                raise PasswordTotpLoginError("当前 MFA factor 与保存的 2FA 不一致", code="mfa_factor_mismatch")
            referer, actual_factor = oauth._prepare_mfa_step(
                session, target or f"/mfa-challenge/{factor}", referer=password_url,
            )
            if actual_factor and not secrets.compare_digest(actual_factor, factor):
                raise PasswordTotpLoginError("MFA 跳转后 factor 不一致", code="mfa_factor_mismatch")
            step = oauth._verify_totp_challenge(session, secret=secret, factor_id=factor, referer=referer)
            _reject_additional_verification(step)
            verified_factor_id = factor
            logger.info("[Codex][密码+2FA] TOTP 已验证")
        elif step.get("page_type") not in {"consent", "workspace", "workspace_selection", "external_url"} and not step.get("continue_url"):
            raise PasswordTotpLoginError("密码验证后缺少授权下一步", code="authorization_step_missing")
        stage = "workspace"
        progress_events.phase(stage)
        oauth._check_codex_flow_stop(email)
        callback = _callback(session, step, state, email, **({"expected_workspace_id": expected_workspace_id} if expected_workspace_id else {}))
        returned_state = parse_qs(urlparse(callback).query).get("state", [""])[0]
        if not returned_state or not secrets.compare_digest(returned_state, state):
            raise PasswordTotpLoginError("OAuth 回调 state 不匹配或缺失", code="oauth_state_mismatch")
        code = oauth._extract_code(callback, state)
        stage = "token_exchange"
        progress_events.phase(stage)
        oauth._check_codex_flow_stop(email)
        token = oauth.exchange_codex_token(session, code, verifier)
        if not token.get("access_token") or not token.get("refresh_token"):
            raise PasswordTotpLoginError("OAuth 未返回完整的 AT/RT", code="token_response_incomplete")
        claims = oauth._parse_id_token(token.get("id_token", ""))
        if claims.get("email") and str(claims["email"]).casefold() != email.casefold():
            raise PasswordTotpLoginError("OAuth 返回的账号与目标邮箱不一致", code="oauth_account_mismatch")
        selected_workspace_id = expected_workspace_id or getattr(session, "_codex_selected_workspace_id", "")
        if not claims.get("account_id"):
            raise PasswordTotpLoginError("OAuth Token 未返回工作区 ID，未保存凭证", code="oauth_workspace_missing")
        if selected_workspace_id and claims.get("account_id") != selected_workspace_id:
            raise PasswordTotpLoginError("OAuth Token 工作区与本次选择不一致，未保存凭证", code="oauth_workspace_mismatch")
        logger.info("[Codex][密码+2FA] 授权工作区已确认: workspace_id=%s plan=%s",
                    claims["account_id"], claims.get("plan_type") or "unknown")
        stage = "save_credential"
        progress_events.phase(stage)
        storage = oauth.build_codex_storage(token, claims)
        oauth._check_codex_flow_stop(email)
        path = oauth.save_codex_credential(storage, email, claims.get("plan_type", ""))
        return oauth._codex_result(
            status="success", ok=True, email=email, file_path=str(path), callback_url=callback,
            message="密码 + 2FA OAuth 授权完成", refresh_token=token["refresh_token"],
            credential=storage, codex_phone_status="not_required", login_mode="password_totp",
            **({"totp_login_verification": {"factor_id": verified_factor_id,
                  "material_fingerprint": login_material_fingerprint(account)}} if verified_factor_id else {}),
        )
    except oauth.AccountUnusableError as exc:
        return oauth._codex_result(status="deactivated", email=email,
                                   message=f"账号已封禁/停用（{exc.error_code}）",
                                   error_code=exc.error_code, retryable=False,
                                   failure_stage=stage, login_mode="password_totp")
    except Exception as exc:
        result = _failure(exc, stage=stage, email=email, password=password, secret=secret)
        logger.warning("[Codex][密码+2FA] %s code=%s", result["message"], result["error_code"])
        return result
    finally:
        if session is not None:
            try:
                session.session.close()
            except Exception:
                logger.debug("[Codex][密码+2FA] 关闭协议会话失败")
