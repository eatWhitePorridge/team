"""Opt-in password/TOTP Web login on one HTTP session, before Team acceptance."""
from __future__ import annotations

import logging
import re
import secrets
from urllib.parse import parse_qs, urljoin, urlsplit

from core import account_export, chatgpt_auth, codex_oauth as oauth
from core import codex_password_totp as password_login
from core.account_cookie_store import has_session_cookie, normalize_cookies
from core.session import BrowserSession

logger = logging.getLogger(__name__)
WebLoginError = password_login.PasswordTotpLoginError


def _open_authorize(session, authorize_url: str) -> None:
    """Consume only Auth redirects; never rewrite the NextAuth transaction."""
    current = authorize_url
    for _ in range(10):
        current = password_login._auth_url(current)
        response = session.get(current, headers=session.get_auth_navigate_headers(
            referer="https://chatgpt.com/",
        ), allow_redirects=False)
        status = int(response.status_code)
        if status in {301, 302, 303, 307, 308}:
            location = response.headers.get("location")
            if not location:
                raise WebLoginError("Web 登录跳转缺少地址", code="web_authorize_redirect_missing")
            current = urljoin(current, location)
            continue
        if status != 200:
            raise oauth.CodexAuthResponseError("Web 登录入口请求失败", http_status=status,
                                              error_code="web_authorize_failed")
        oauth._sync_auth_document_context(session, response, stage="web_password_login")
        return
    raise WebLoginError("Web 登录跳转次数超限", code="web_authorize_redirect_limit")


def login(session, account: dict) -> dict:
    """Return verified Web session/cookies; caller owns and closes the HTTP session.

    This consumes existing credentials only. It never enrolls a factor, reads
    email, imports old cookies, or exchanges a Codex token for a Web cookie.
    """
    password = secret = ""
    session.redact_request_urls = True
    stage = "credentials"
    email = str(account.get("email") or "").strip()
    try:
        password, secret = password_login.login_material(account)
        if str(account.get("codex_status") or "").lower() == "deactivated":
            raise WebLoginError("账号已废号", code="account_deactivated")
        stage = "web_signin"
        csrf = chatgpt_auth.get_csrf_token(session)
        if not csrf:
            raise WebLoginError("Web 登录缺少 CSRF", code="web_csrf_missing")
        authorize_url = chatgpt_auth.signin_openai(session, csrf, email)
        states = parse_qs(urlsplit(password_login._auth_url(authorize_url)).query).get("state", [])
        if len(states) != 1 or not states[0]:
            raise WebLoginError("Web 登录缺少授权 state", code="web_state_missing")
        state = states[0]
        session._password_totp_callback_validated = False
        session._chatgpt_bootstrap_session = None
        _open_authorize(session, authorize_url)

        stage = "email_submit"
        step = oauth._submit_email_identifier(session, email)
        password_login._reject_additional_verification(step)
        path = urlsplit(urljoin("https://auth.openai.com/", step.get("continue_url") or "")).path.rstrip("/")
        if step.get("page_type") not in {"login_password", "password"} and path != "/log-in/password":
            raise WebLoginError("服务端未进入密码登录步骤", code="password_step_missing")
        stage = "password"
        password_url = password_login._navigate_password(session, step)
        step = oauth._submit_password_step(session, password)
        password_login._reject_additional_verification(step)
        logger.info("[Team][密码+2FA] Web 登录密码已验证: account_id=%s", account.get("id"))

        factor = ""
        if step.get("mfa_required"):
            stage = "mfa"
            target = str(step.get("continue_url") or "")
            stored = str(account.get("totp_factor_id") or "")
            factor = oauth._mfa_factor_id_from_url(target) or stored
            if not re.fullmatch(r"[A-Za-z0-9_-]{8,256}", factor):
                raise WebLoginError("缺少当前 MFA factor ID", code="mfa_factor_missing")
            if stored and not secrets.compare_digest(stored, factor):
                raise WebLoginError("当前 MFA factor 与已保存的 2FA 不一致", code="mfa_factor_mismatch")
            target = password_login._auth_url(target or f"/mfa-challenge/{factor}")
            referer, actual = oauth._prepare_mfa_step(session, target, referer=password_url)
            if actual and not secrets.compare_digest(actual, factor):
                raise WebLoginError("MFA 跳转后 factor 不一致", code="mfa_factor_mismatch")
            step = oauth._verify_totp_challenge(session, secret=secret, factor_id=factor, referer=referer)
            password_login._reject_additional_verification(step)
            logger.info("[Team][密码+2FA] Web 登录 TOTP 已验证: account_id=%s", account.get("id"))

        stage = "web_callback"
        session._reauth_otp_payload = step.get("auth_session") or {}
        target = str(step.get("continue_url") or "")
        if not target and step.get("page_type") in {"workspace", "workspace_selection"}:
            target = "https://auth.openai.com/workspace"
        if not target:
            raise WebLoginError("密码验证后缺少 Web 回调地址", code="web_callback_missing")
        final_url = account_export.follow_oauth_callback(
            session, urljoin("https://auth.openai.com/", target),
            referer="https://auth.openai.com/", expected_state=state,
        )
        final = urlsplit(final_url)
        if final.hostname == "auth.openai.com" and final.path.rstrip("/") == "/workspace":
            final_url = account_export._select_reauth_workspace(session, expected_state=state)
            final = urlsplit(final_url)
        if (final.hostname != "chatgpt.com" or final.path.rstrip("/") == "/auth/error"
                or parse_qs(final.query).get("error") or not session._password_totp_callback_validated):
            raise WebLoginError("未完成本次 ChatGPT Web 登录回调", code="web_callback_incomplete")

        stage = "web_session"
        payload = account_export.fetch_session(session, force_network=True)
        if str((payload.get("user") or {}).get("email") or "").strip().casefold() != email.casefold():
            raise WebLoginError("新 Web 登录态与目标账号不一致", code="web_session_account_mismatch")
        cookies = normalize_cookies(session.session.cookies.jar, source="password_totp_web")
        if not payload.get("accessToken") or not has_session_cookie(cookies):
            raise WebLoginError("未取得有效 Web 登录 Cookie", code="web_session_cookie_missing")
        return {"session": payload, "cookies": cookies, "verified_factor_id": factor}
    except WebLoginError:
        raise
    except Exception as exc:
        failure = password_login._failure(exc, stage=stage, email=email, password=password, secret=secret)
        message = str(failure["message"]).replace("密码 + 2FA 授权失败", "密码 + 2FA Web 登录失败")
        raise WebLoginError(message, code=str(failure["error_code"]), retryable=bool(failure["retryable"])) from None


def accept_team(account: dict, invite: dict, *, claim_id: str, expected_workspace_id: str = "") -> dict:
    """Use a fresh Web transaction and keep its jar/route through Team verification."""
    from config import proxy as proxy_cfg
    from core import db, team_invite_service as team
    from core.chatgpt_plan import token_claims

    for attempt in range(2):
        env = None
        login_complete = False
        try:
            env = BrowserSession(proxy=proxy_cfg.pick_proxy(), detect_exit_geo=False)
            env.redact_request_urls = True
            authenticated = login(env, account)
            login_complete = True
            result = team._accept_invite_protocol(
                account, invite, account["email"], authenticated["cookies"],
                expected_workspace_id=expected_workspace_id, http_session=env,
            )
            result.pop("cookies", None)
            if result.get("status") not in {"joined", "already_member"}:
                return result
            workspace_id = str(result.get("workspace_id") or "")
            if not workspace_id or (expected_workspace_id and workspace_id != expected_workspace_id):
                raise team.TeamInviteError("未确认邀请的目标工作区", code="workspace_mismatch", status=409)
            state = team._protocol_session_state(env, workspace_id=workspace_id)
            payload = state.get("data") or {}
            cookies = normalize_cookies(env.session.cookies.jar, source="password_totp_web")
            claims = token_claims(str(payload.get("accessToken") or ""))
            # Claims come from the session endpoint on this authenticated HTTPS
            # connection. Never use an old token or a workspace-list entry here.
            if (state.get("status") != 200 or claims.get("account_id") != workspace_id
                    or claims.get("token_expired") is True):
                raise team.TeamInviteError("邀请已处理，但目标 Team 登录态尚未确认", code="workspace_session_unconfirmed", status=409)
            if team._state_email(state) != account["email"].strip().casefold():
                raise team.TeamInviteError("邀请后的登录账号不一致", code="session_account_mismatch", status=409)
            db.save_password_totp_web_session(
                account, payload, cookies, claim_id=claim_id, factor_id=authenticated["verified_factor_id"],
            )
            return {**result, "workspace_id": workspace_id, "session_refreshed": True,
                    "cookie_count": len(cookies), "recipient_verified": True,
                    "message": "已通过密码 + 2FA 登录并确认目标 Team，已保存新登录态"}
        except team.TeamInviteError:
            raise
        except Exception as exc:
            password, secret = password_login.login_material(account)
            failure = password_login._failure(exc, stage="web_login" if not login_complete else "team_session",
                                              email=account["email"], password=password, secret=secret)
            if not login_complete and attempt == 0 and failure.get("retryable"):
                logger.warning("[Team][密码+2FA] Web 登录临时失败，换新代理会话重试: account_id=%s code=%s",
                               account.get("id"), failure.get("error_code"))
                continue
            raise team.TeamInviteError(str(failure["message"]), code=str(failure["error_code"]),
                                       status=502, retryable=bool(failure["retryable"])) from None
        finally:
            if env is not None:
                try:
                    env.session.close()
                except Exception:
                    logger.warning("[Team][密码+2FA] HTTP 会话关闭失败: account_id=%s", account.get("id"))
