# -*- coding: utf-8 -*-
"""
注册后处理模块：
    1. 拉取 /api/auth/session，从中抽取 accessToken / user 信息
    2. 设置 2FA（TOTP），返回 secret
    3. 把账号信息（邮箱 + accessToken + TOTP secret）落盘成 JSON

整体复用注册阶段的 BrowserSession（同一 cookie jar / 同一 IP / 同一 UA），
避免再起新会话被风控关联或缺失登录态。
"""
import base64
import json
import logging
import math
import secrets
import time
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
import threading
from urllib.parse import parse_qs, unquote, urlencode, urljoin, urlsplit

from core.session import BrowserSession
from core.humanize import delay as human_delay
from core.nextauth_cookies import reconcile_session_cookies

logger = logging.getLogger(__name__)

# 输出目录（与项目根 .claude/ 工作区分离，单独放在 accounts/）
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ACCOUNTS_DIR = _PROJECT_ROOT / "accounts"
_BATCH_ARCHIVE_LOCK = threading.RLock()

_REAUTH_TRANSIENT_COOKIE_NAMES = frozenset({
    "__host-authjs.csrf-token",
    "__host-next-auth.csrf-token",
    "__secure-authjs.callback-url",
    "__secure-authjs.nonce",
    "__secure-authjs.pkce.code_verifier",
    "__secure-authjs.state",
    "__secure-next-auth.callback-url",
    "__secure-next-auth.nonce",
    "__secure-next-auth.pkce.code_verifier",
    "__secure-next-auth.state",
    "authjs.callback-url",
    "authjs.csrf-token",
    "authjs.nonce",
    "authjs.pkce.code_verifier",
    "authjs.state",
    "next-auth.callback-url",
    "next-auth.csrf-token",
    "next-auth.nonce",
    "next-auth.pkce.code_verifier",
    "next-auth.state",
    "oai-csrf-cookie",
    "oai-login-csrf",
})
_REAUTH_EDGE_COOKIE_NAMES = frozenset({
    "__cf_bm",
    "__cflb",
    "__cfseq",
    "_cfuvid",
    "cf_clearance",
})


class ReauthenticationError(RuntimeError):
    """Sanitized account reauthentication error safe for task state/logging."""

    safe_to_persist = True

    def __init__(
        self,
        message: str,
        *,
        error_code: str,
        http_status: int | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.error_code = str(error_code or "reauth_failed")
        self.http_status = http_status
        self.retryable = bool(retryable)


def _is_reauth_transient_cookie_name(name: str) -> bool:
    normalized = str(name or "").strip().lower()
    return normalized in _REAUTH_TRANSIENT_COOKIE_NAMES or normalized.startswith(
        "oai-login-csrf_"
    )


def _clear_reauth_oauth_cookies(session: BrowserSession) -> int:
    """Remove per-transaction OAuth cookies without touching login/device state."""
    cookies = getattr(getattr(session, "session", None), "cookies", None)
    jar = getattr(cookies, "jar", None)
    if jar is None or not callable(getattr(cookies, "delete", None)):
        return 0

    to_remove: list[tuple[str, str, str]] = []
    for cookie in jar:
        name = str(getattr(cookie, "name", "") or "")
        if _is_reauth_transient_cookie_name(name):
            to_remove.append((
                name,
                str(getattr(cookie, "domain", "") or ""),
                str(getattr(cookie, "path", "") or "/"),
            ))

    removed = 0
    for name, domain, path in to_remove:
        try:
            cookies.delete(name, domain=domain, path=path)
            removed += 1
        except Exception:
            logger.debug(
                "[2FA] 清理 OAuth 瞬态 Cookie 失败: name=%s domain=%s",
                name,
                domain,
                exc_info=True,
            )
    if removed:
        logger.info("[2FA] 已清理 OAuth 瞬态 Cookie: count=%s", removed)
    return removed


def _clear_reauth_edge_cookies(session: BrowserSession) -> int:
    """Drop edge cookies visible to auth.openai.com after a challenge response."""
    cookies = getattr(getattr(session, "session", None), "cookies", None)
    jar = getattr(cookies, "jar", None)
    if jar is None or not callable(getattr(cookies, "delete", None)):
        return 0

    auth_host = "auth.openai.com"
    to_remove: list[tuple[str, str, str]] = []
    for cookie in jar:
        name = str(getattr(cookie, "name", "") or "")
        normalized_name = name.lower()
        domain = str(getattr(cookie, "domain", "") or "")
        normalized_domain = domain.lower().lstrip(".")
        visible_to_auth = bool(normalized_domain) and (
            auth_host == normalized_domain
            or auth_host.endswith("." + normalized_domain)
        )
        is_edge_cookie = (
            normalized_name in _REAUTH_EDGE_COOKIE_NAMES
            or normalized_name.startswith("cf_chl_")
        )
        if visible_to_auth and is_edge_cookie:
            to_remove.append((
                name,
                domain,
                str(getattr(cookie, "path", "") or "/"),
            ))

    removed = 0
    for name, domain, path in to_remove:
        try:
            cookies.delete(name, domain=domain, path=path)
            removed += 1
        except Exception:
            logger.debug(
                "[2FA] 清理 Auth 边缘 Cookie 失败: name=%s domain=%s",
                name,
                domain,
                exc_info=True,
            )
    return removed


def _looks_like_reauth_edge_challenge(response: object) -> bool:
    headers = getattr(response, "headers", {}) or {}
    try:
        mitigated = str(headers.get("cf-mitigated") or "").lower()
        server = str(headers.get("server") or "").lower()
    except Exception:
        mitigated = ""
        server = ""
    body = str(getattr(response, "text", "") or "").lower()
    return (
        mitigated == "challenge"
        or "cloudflare" in server
        or any(marker in body for marker in (
            "<!doctype",
            "<html",
            "cloudflare",
            "cf-chl-",
            "just a moment",
            "turnstile",
        ))
    )


class _ClientBootstrapParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self._capturing = False
        self._chunks: list[str] = []
        self.payload = ""

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "script" or self.payload:
            return
        values = {str(key).lower(): str(value or "") for key, value in attrs}
        if (
            values.get("id") == "client-bootstrap"
            and values.get("type", "").lower() == "application/json"
        ):
            self._capturing = True
            self._chunks = []

    def handle_data(self, data: str) -> None:
        if self._capturing:
            self._chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._capturing:
            self.payload = "".join(self._chunks)
            self._capturing = False


def _session_from_client_bootstrap(html: str) -> dict:
    if not html or len(html) > 4_000_000:
        return {}
    parser = _ClientBootstrapParser()
    try:
        parser.feed(html)
        bootstrap = json.loads(parser.payload) if parser.payload else {}
    except (ValueError, TypeError):
        return {}
    if not isinstance(bootstrap, dict):
        return {}
    if str(bootstrap.get("authStatus") or "").lower() != "logged_in":
        return {}
    session_info = bootstrap.get("session")
    if not isinstance(session_info, dict) or not str(
        session_info.get("accessToken") or ""
    ).strip():
        return {}
    return dict(session_info)


def _account_material_line(email: str, row: dict | None = None) -> str:
    """优先输出 Outlook 原始素材；没有素材时退回邮箱地址。"""
    if row:
        return row.get("original_email_line") or row.get("email") or email
    return email


def _account_copy_line(material_line: str, access_token: str, totp_secret: str | None = None) -> str:
    """生成包含 token 的整行归档，方便从批次汇总文件里复制。"""
    return f"{material_line}----{access_token}----{totp_secret}" if totp_secret else f"{material_line}----{access_token}"


def create_batch_archive_dir(count: int, workers: int = 1) -> Path:
    """为一次运行创建批次归档目录，例如 accounts/20260509-10个-3线程。"""
    day = datetime.now().strftime("%Y%m%d")
    base_name = f"{day}-{count}个" if workers <= 1 else f"{day}-{count}个-{workers}线程"
    folder = _ACCOUNTS_DIR / base_name
    suffix = 2
    while folder.exists():
        folder = _ACCOUNTS_DIR / f"{base_name}-{suffix}"
        suffix += 1
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "注册成功的邮箱.txt").write_text("", encoding="utf-8")
    (folder / "注册成功的token.txt").write_text("", encoding="utf-8")
    (folder / "注册成功整行.txt").write_text("", encoding="utf-8")
    (folder / "注册成功账号.json").write_text("[]\n", encoding="utf-8")
    return folder


def _append_line(path: Path, line: str) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(line + "\n")


def _append_batch_archive(
    *,
    row_id: int,
    email: str,
    access_token: str,
    totp_secret: str | None,
    email_source: str | None,
    proxy_used: str | None,
    extra: dict,
    batch_dir: Path | None,
) -> Path:
    """把注册成功账号追加到本次批次目录的 TXT/JSON 文件中。"""
    from core import db

    folder = batch_dir or create_batch_archive_dir(count=1)
    row = db.get_account(row_id) or {}
    folder.mkdir(parents=True, exist_ok=True)
    material_line = _account_material_line(email, row)
    copy_line = _account_copy_line(material_line, access_token, totp_secret)
    archive = {
        "id": row_id,
        "email": email,
        "email_source": email_source,
        "proxy_used": proxy_used,
        "access_token": access_token,
        "totp_secret": totp_secret,
        "material_line": material_line,
        "copy_line": copy_line,
        "saved_at": datetime.now().isoformat(timespec="seconds"),
        "row": row,
        "extra": extra,
    }

    with _BATCH_ARCHIVE_LOCK:
        _append_line(folder / "注册成功的邮箱.txt", material_line)
        _append_line(folder / "注册成功的token.txt", access_token)
        _append_line(folder / "注册成功整行.txt", copy_line)

        json_path = folder / "注册成功账号.json"
        try:
            rows = json.loads(json_path.read_text(encoding="utf-8")) if json_path.exists() else []
        except Exception:
            rows = []
        if not isinstance(rows, list):
            rows = []
        rows.append(archive)
        json_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return folder


def follow_oauth_callback(session: BrowserSession, continue_url: str, referer: str = "https://auth.openai.com/about-you", *, expected_state: str = "") -> str:
    """
    步骤12.5: 跟随 create_account 返回的 continue_url，完成 OAuth 回调。

    create_account 成功后返回的 continue_url 一般指向
        https://auth.openai.com/authorize/continue?...
    它会再 302 到
        https://chatgpt.com/api/auth/callback/openai?code=...&state=...
    回调请求会让 chatgpt.com 设置 `__Secure-next-auth.session-token` cookie，
    之后 /api/auth/session 才能返回 accessToken。

    Returns:
        重定向链最终落点 URL（一般是 chatgpt.com 站内地址）
    """
    if not continue_url:
        raise ValueError("continue_url 为空，无法完成 OAuth 回调")

    def navigation_headers(target_url: str) -> dict:
        target = urlsplit(target_url)
        host = (target.hostname or "").lower()
        source = urlsplit(str(referer or ""))
        target_origin = (
            f"{target.scheme}://{target.netloc}"
            if target.scheme and target.netloc
            else ""
        )
        source_origin = (
            f"{source.scheme}://{source.netloc}"
            if source.scheme and source.netloc
            else ""
        )
        # 浏览器的 strict-origin-when-cross-origin 会在跨站导航时只发送来源
        # origin；同一个重定向链后续仍沿用最初文档的 referrer。
        effective_referer = str(referer or "")
        if source_origin and source_origin != target_origin:
            effective_referer = source_origin + "/"
        if host == "chatgpt.com" or host.endswith(".chatgpt.com"):
            return session.get_chatgpt_navigate_headers(referer=effective_referer)
        if host == "auth.openai.com" or host.endswith(".auth.openai.com"):
            return session.get_auth_navigate_headers(referer=effective_referer)
        raise RuntimeError(f"OAuth 回调跳转到非预期域名: {host or 'unknown'}")

    # curl 在自动跟随跨域 302 时会复用调用方传入的整组自定义头，导致
    # auth.openai.com 的 same-origin 导航头被带到 chatgpt.com。浏览器会按每个
    # 目标域重新计算 Sec-Fetch-*；这里逐跳跟随，保持同一 Cookie Jar 和代理。
    current_url = str(continue_url)
    logger.info("[OAuth回调] 逐跳跟随 continue_url，按目标域重建导航头")
    for hop in range(1, 9):
        if expected_state:
            target = urlsplit(current_url)
            if (target.scheme != "https" or target.hostname not in {"chatgpt.com", "auth.openai.com"}
                    or target.username or target.password or target.port not in (None, 443)):
                raise RuntimeError("Web 登录回调地址无效")
            if target.hostname == "chatgpt.com" and target.path.rstrip("/") == "/api/auth/callback/openai":
                returned = parse_qs(target.query).get("state", [])
                if len(returned) != 1 or not secrets.compare_digest(returned[0], expected_state):
                    raise RuntimeError("Web 登录回调 state 不匹配")
                session._password_totp_callback_validated = True
        resp = session.get(
            current_url,
            headers=navigation_headers(current_url),
            allow_redirects=False,
        )
        removed = reconcile_session_cookies(
            getattr(getattr(session, "session", None), "cookies", None), resp, current_url,
        )
        if removed:
            logger.info("[Session] OAuth 回调已清理过时会话 Cookie: count=%s", removed)
        status = int(getattr(resp, "status_code", 0) or 0)
        location = str((getattr(resp, "headers", {}) or {}).get("location") or "")
        parsed = urlsplit(current_url)
        logger.info(
            "[OAuth回调] hop=%s status=%s target=%s%s",
            hop,
            status,
            parsed.netloc,
            parsed.path or "/",
        )
        if status not in {301, 302, 303, 307, 308} or not location:
            if status >= 400:
                resp.raise_for_status()
            final_url = str(getattr(resp, "url", "") or current_url)
            bootstrap_session = _session_from_client_bootstrap(
                str(getattr(resp, "text", "") or "")
            )
            if bootstrap_session:
                session._chatgpt_bootstrap_session = bootstrap_session
                logger.info(
                    "[OAuth回调] 已从首页 client-bootstrap 获取登录态，"
                    "后续不再额外请求 /api/auth/session"
                )
            logger.info("[OAuth回调] 完成, 最终落点: %s", final_url.split("?", 1)[0] if expected_state else final_url)
            return final_url
        current_url = urljoin(current_url, location)

    raise RuntimeError("OAuth 回调重定向超过 8 跳")


def _pick_reauth_workspace_id(payload: dict, preferred_workspace_id: str = "") -> str:
    """Prefer the previous workspace among server-provided Auth choices."""
    candidates: list[dict] = []
    if isinstance(payload, dict):
        candidates.append(payload)
    pending = [(payload, 0)] if isinstance(payload, dict) else []
    for _ in range(24):
        if not pending:
            break
        candidate, depth = pending.pop(0)
        if depth >= 3:
            continue
        for key in ("client_auth_session", "auth_session", "oai-client-auth-session", "data", "result", "page", "payload"):
            nested = candidate.get(key)
            if isinstance(nested, dict):
                candidates.append(nested)
                pending.append((nested, depth + 1))

    records: list[dict] = []
    for candidate in candidates:
        workspaces = candidate.get("workspaces")
        if not isinstance(workspaces, list):
            continue
        records.extend(item for item in workspaces if isinstance(item, dict))

    preferred = str(preferred_workspace_id or "").strip()
    if preferred:
        for item in records:
            identifiers = {
                str(item.get("id") or "").strip(),
                str(item.get("account_id") or "").strip(),
            }
            if preferred in identifiers:
                return str(item.get("id") or item.get("account_id") or "").strip()
    for item in records:
        workspace_id = str(item.get("id") or item.get("account_id") or "").strip()
        if workspace_id:
            return workspace_id
    return ""


def _select_reauth_workspace(
    session: BrowserSession,
    *,
    preferred_workspace_id: str = "",
    expected_state: str = "",
) -> str:
    """处理重认证回调落到 ``/workspace`` 的新 Auth Web 分支。

    多工作区账号在邮箱 OTP 后不会直接跳 ChatGPT，而是先要求选择工作区。
    优先使用本次 OTP 响应或 Auth Cookie 的工作区，再继续同一重定向链。
    """
    workspace_id = _pick_reauth_workspace_id(
        getattr(session, "_reauth_otp_payload", None), preferred_workspace_id,
    )
    source = "otp_response"
    cookie_names = {
        "oai-client-auth-session", "__Secure-oai-client-auth-session",
        "oai-client-auth-session-token", "__Secure-oai-client-auth-session-token",
    }
    cookies = getattr(getattr(session, "session", None), "cookies", None)
    jar = getattr(cookies, "jar", None)
    raw_candidates: list[tuple[int, str]] = []
    if jar is not None:
        for cookie in jar:
            domain = str(cookie.domain or "").lower().lstrip(".")
            path = str(cookie.path or "/").rstrip("/") or "/"
            if (
                cookie.name in cookie_names and cookie.value
                and domain in {"auth.openai.com", "openai.com"}
                and (path == "/" or "/api/accounts/workspace/select" == path
                     or "/api/accounts/workspace/select".startswith(path + "/"))
                and not cookie.is_expired()
            ):
                raw_candidates.append((0 if domain == "auth.openai.com" else 1, str(cookie.value)))
    elif cookies is not None:
        for name in sorted(cookie_names):
            try:
                raw = cookies.get(name)
            except Exception:
                continue
            if raw:
                raw_candidates.append((0, str(raw)))

    decoded_count = 0
    for _priority, raw in sorted(raw_candidates, key=lambda item: item[0]):
        if workspace_id:
            break
        try:
            segment = unquote(raw).strip('"').split(".", 1)[0]
            segment += "=" * (-len(segment) % 4)
            payload = json.loads(base64.urlsafe_b64decode(segment).decode("utf-8"))
        except (ValueError, UnicodeError):
            continue
        if not isinstance(payload, dict):
            continue
        decoded_count += 1
        workspace_id = _pick_reauth_workspace_id(payload, preferred_workspace_id)
        source = "auth_cookie"
    if not workspace_id:
        # Some successful OTP responses omit workspaces entirely. Reuse only
        # the previous AT's account ID; workspace/select still validates it,
        # and _exchange_new_token still requires fresh authentication time.
        workspace_id = str(preferred_workspace_id or "").strip()
        source = "previous_access_token"
    if not workspace_id:
        if not raw_candidates:
            message, code = "重认证落入 workspace，但缺少授权工作区 Cookie", "reauth_workspace_cookie_missing"
        elif not decoded_count:
            message, code = "重认证 workspace Cookie 无法解析", "reauth_workspace_cookie_invalid"
        else:
            message, code = "重认证 workspace 没有可选择的工作区", "reauth_workspace_missing"
        raise ReauthenticationError(
            message, error_code=code, retryable=True,
        )
    logger.info(
        "[2FA] 重认证工作区选择: source=%s cookie_candidates=%s decoded=%s",
        source, len(raw_candidates), decoded_count,
    )

    headers = session.get_auth_headers(referer="https://auth.openai.com/workspace")
    headers["sec-fetch-site"] = "same-origin"
    try:
        resp = session.post(
            "https://auth.openai.com/api/accounts/workspace/select",
            headers=headers,
            data=json.dumps({"workspace_id": workspace_id}, separators=(",", ":")),
            allow_redirects=False,
        )
    except Exception as exc:
        raise ReauthenticationError(
            "重认证工作区选择请求失败",
            error_code="reauth_workspace_network",
            retryable=True,
        ) from exc
    status = int(getattr(resp, "status_code", 0) or 0)
    if not 200 <= status < 400:
        raise ReauthenticationError(
            f"重认证工作区选择被拒绝（HTTP {status}）",
            error_code="reauth_workspace_rejected",
            http_status=status,
            retryable=status in {408, 425, 429} or status >= 500,
        )
    location = str((getattr(resp, "headers", {}) or {}).get("location") or "").strip()
    if not location:
        try:
            data = resp.json()
        except Exception:
            data = {}
        if isinstance(data, dict):
            location = str(
                data.get("continue_url") or data.get("redirect_url")
                or data.get("url") or data.get("location") or ""
            ).strip()
    if not location:
        raise ReauthenticationError(
            "重认证工作区选择响应缺少下一跳",
            error_code="reauth_workspace_no_redirect",
            retryable=True,
        )
    return follow_oauth_callback(
        session,
        urljoin("https://auth.openai.com/", location),
        referer="https://auth.openai.com/workspace",
        **({"expected_state": expected_state} if expected_state else {}),
    )


def fetch_session(
    session: BrowserSession,
    *,
    force_network: bool = False,
    cache_buster: bool = False,
) -> dict:
    """
    GET https://chatgpt.com/api/auth/session
    注册成功后立刻调用，拿到 accessToken / user / account / expires。

    Returns:
        完整 session JSON，包含字段:
            - accessToken: str (Bearer token, 用于 backend-api 调用)
            - user: {id, name, email, idp, iat, mfa}
            - account: {id, planType, structure, ...}
            - expires: ISO 时间字符串
    """
    if force_network:
        session._chatgpt_bootstrap_session = None
    cached = getattr(session, "_chatgpt_bootstrap_session", None)
    if isinstance(cached, dict) and cached.get("accessToken"):
        data = dict(cached)
        # 一次性消费，避免后续 2FA 重认证误用注册阶段旧 AT。
        session._chatgpt_bootstrap_session = None
        logger.info("[Session] 使用首页 client-bootstrap 登录态")
    else:
        def request_session(*, refresh: bool) -> dict:
            params: list[tuple[str, str]] = []
            if refresh:
                params.append(("refresh", "true"))
            if cache_buster:
                params.append(("_", str(time.time_ns())))
            url = "https://chatgpt.com/api/auth/session"
            if params:
                url = f"{url}?{urlencode(params)}"
            headers = session.get_nextauth_headers(referer="https://chatgpt.com/")
            if cache_buster or refresh:
                headers.update({"cache-control": "no-cache", "pragma": "no-cache"})
            resp = session.get(url, headers=headers)
            removed = reconcile_session_cookies(
                getattr(getattr(session, "session", None), "cookies", None), resp, url,
            )
            if removed:
                logger.info("[Session] 会话刷新已清理过时 Cookie: count=%s", removed)
            resp.raise_for_status()
            payload = resp.json()
            return payload if isinstance(payload, dict) else {}

        logger.info("[Session] 首页未提供登录态，回退拉取 /api/auth/session")
        data = request_session(refresh=False)
        if not data.get("accessToken"):
            # 与协议 V2 登录保持一致。NextAuth 回调后的普通 session 请求
            # 偶尔只返回 WARNING_BANNER；refresh=true 会触发一次服务端
            # session-token 交换，而不是继续轮询同一份匿名响应。
            logger.info("[Session] 普通 session 无 accessToken，尝试 refresh=true")
            data = request_session(refresh=True)

    if not data.get("accessToken"):
        logger.error(
            "[Session] 响应中没有 accessToken: keys=%s warning_only=%s",
            sorted(str(key) for key in data.keys()),
            set(data.keys()) == {"WARNING_BANNER"},
        )
        raise RuntimeError("未拿到 accessToken，登录态可能未建立")

    user = data.get("user") or {}
    account = data.get("account") or {}
    logger.info(
        f"[Session] 成功，user_id={user.get('id')}, email={user.get('email')}, "
        f"plan={account.get('planType')}, mfa={user.get('mfa')}"
    )
    return data


def _jwt_numeric_date(access_token: str, claim: str) -> float | None:
    """Read a JWT NumericDate claim for freshness checks, without logging it."""
    try:
        encoded = str(access_token or "").split(".")[1]
        encoded += "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded).decode("utf-8"))
        value = float(payload.get(claim))
    except (AttributeError, IndexError, KeyError, TypeError, UnicodeDecodeError, ValueError):
        return None
    if not math.isfinite(value) or value <= 0:
        return None
    # Current Web ATs encode pwd_auth_time in milliseconds while standard JWT
    # NumericDate fields such as iat/exp use seconds.
    return value / 1000.0 if value > 100_000_000_000 else value


def _jwt_chatgpt_account_id(access_token: str) -> str:
    """Read the personal ChatGPT account id without logging token contents."""
    try:
        encoded = str(access_token or "").split(".")[1]
        encoded += "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded).decode("utf-8"))
        auth = payload.get("https://api.openai.com/auth")
        if not isinstance(auth, dict):
            return ""
        return str(auth.get("chatgpt_account_id") or "").strip()
    except (AttributeError, IndexError, TypeError, UnicodeDecodeError, ValueError):
        return ""


def _is_fresh_reauth_token(
    access_token: str,
    *,
    previous_access_token: str,
    reauth_started_at: float,
) -> bool:
    token = str(access_token or "").strip()
    if not token or token == str(previous_access_token or "").strip():
        return False
    pwd_auth_time = _jwt_numeric_date(token, "pwd_auth_time")
    if pwd_auth_time is None:
        return False
    return pwd_auth_time >= float(reauth_started_at) - 10.0


def _trigger_reauth(session: BrowserSession, email: str) -> str:
    """
    步骤2-3: 发起密码重认证，返回 OpenAI authorize URL。
    重定向链会自动触发邮箱发送一份新的 OTP（用于 2FA 重认证）。
    """
    # Restored browser credentials can contain host-only and domain variants of
    # the same stale OAuth state. Clear every transient variant before NextAuth
    # creates a fresh CSRF/state/PKCE transaction. Session, device and edge
    # cookies are deliberately outside this allowlist.
    _clear_reauth_oauth_cookies(session)

    # 重新拿一次 csrf（旧的可能已过期）
    csrf_url = "https://chatgpt.com/api/auth/csrf"
    try:
        csrf_resp = session.get(
            csrf_url,
            headers=session.get_nextauth_headers(referer="https://chatgpt.com/"),
        )
    except Exception as exc:
        raise ReauthenticationError(
            "获取重认证 CSRF 时网络失败",
            error_code="reauth_csrf_network",
            retryable=True,
        ) from exc
    csrf_status = int(getattr(csrf_resp, "status_code", 0) or 0)
    if not 200 <= csrf_status < 300:
        raise ReauthenticationError(
            f"获取重认证 CSRF 返回 HTTP {csrf_status}",
            error_code="reauth_csrf_http_error",
            http_status=csrf_status,
            retryable=csrf_status in {403, 408, 425, 429} or csrf_status >= 500,
        )
    try:
        csrf_token = str(csrf_resp.json().get("csrfToken") or "").strip()
    except Exception as exc:
        raise ReauthenticationError(
            "重认证 CSRF 响应不是有效 JSON",
            error_code="reauth_csrf_invalid_response",
            retryable=True,
        ) from exc
    if not csrf_token:
        raise ReauthenticationError(
            "重认证 CSRF 响应缺少 csrfToken",
            error_code="reauth_csrf_invalid_response",
            retryable=True,
        )
    logger.info("[2FA] 已获取重认证 CSRF")

    # POST /api/auth/signin/openai 带 reauth 参数
    query = {
        "connection": "password",
        "login_hint": email,
        "reauth": "password",
        "max_age": "0",
        "ext-oai-did": session.device_id,
    }
    signin_url = "https://chatgpt.com/api/auth/signin/openai?" + urlencode(query)

    headers = session.get_nextauth_headers(referer="https://chatgpt.com/")
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = "https://chatgpt.com"

    body = urlencode({
        "callbackUrl": "https://chatgpt.com/?action=enable&factor=totp",
        "csrfToken": csrf_token,
        "json": "true",
    })

    logger.info("[2FA] 发起重认证 signin/openai...")
    try:
        resp = session.post(signin_url, headers=headers, data=body)
    except Exception as exc:
        raise ReauthenticationError(
            "发起重认证时网络失败",
            error_code="reauth_signin_network",
            retryable=True,
        ) from exc
    status = int(getattr(resp, "status_code", 0) or 0)
    if not 200 <= status < 300:
        raise ReauthenticationError(
            f"发起重认证返回 HTTP {status}",
            error_code="reauth_signin_http_error",
            http_status=status,
            retryable=status in {403, 408, 425, 429} or status >= 500,
        )
    try:
        auth_url = str(resp.json().get("url") or "").strip()
    except Exception as exc:
        raise ReauthenticationError(
            "重认证响应不是有效 JSON",
            error_code="reauth_signin_invalid_response",
            retryable=True,
        ) from exc
    if not auth_url:
        raise ReauthenticationError(
            "重认证响应缺少 authorize URL",
            error_code="reauth_signin_invalid_response",
            retryable=True,
        )
    parsed_auth_url = urlsplit(auth_url)
    if (
        parsed_auth_url.scheme.lower() != "https"
        or (parsed_auth_url.hostname or "").lower() != "auth.openai.com"
    ):
        raise ReauthenticationError(
            "重认证响应返回了非预期 authorize 地址",
            error_code="reauth_signin_invalid_url",
        )
    return auth_url


def _follow_reauth(session: BrowserSession, auth_url: str) -> None:
    """
    步骤3: 跟随 authorize URL 触发邮箱 OTP 发送。
    auth.openai.com 会重定向到 /email-verification 页面，期间发送 OTP 邮件。
    """
    headers = session.get_auth_navigate_headers(referer="https://chatgpt.com/")
    logger.info("[2FA] 跟随 authorize URL，触发 OTP 发送...")
    try:
        response = session.get(auth_url, headers=headers, allow_redirects=True)
    except Exception as exc:
        raise ReauthenticationError(
            "重认证 authorize 导航网络失败",
            error_code="reauth_authorize_network",
            retryable=True,
        ) from exc

    status = int(getattr(response, "status_code", 0) or 0)
    if status == 403 and _looks_like_reauth_edge_challenge(response):
        removed = _clear_reauth_edge_cookies(session)
        logger.warning(
            "[2FA] authorize 命中边缘挑战，清理 Auth 边缘 Cookie 后同路由重试: "
            "removed=%s",
            removed,
        )
        try:
            response = session.get(auth_url, headers=headers, allow_redirects=True)
        except Exception as exc:
            raise ReauthenticationError(
                "重认证 authorize 边缘恢复请求网络失败",
                error_code="reauth_authorize_edge_retry_network",
                retryable=True,
            ) from exc
        status = int(getattr(response, "status_code", 0) or 0)

    if status == 403:
        if _looks_like_reauth_edge_challenge(response):
            raise ReauthenticationError(
                "重认证 authorize 持续命中边缘挑战（HTTP 403）",
                error_code="reauth_authorize_edge_challenge",
                http_status=status,
                retryable=True,
            )
        raise ReauthenticationError(
            "重认证 authorize 被拒绝（HTTP 403）",
            error_code="reauth_authorize_forbidden",
            http_status=status,
            retryable=True,
        )
    if not 200 <= status < 300:
        raise ReauthenticationError(
            f"重认证 authorize 返回 HTTP {status}",
            error_code="reauth_authorize_http_error",
            http_status=status,
            retryable=status in {408, 425, 429} or status >= 500,
        )

    final_url = str(getattr(response, "url", "") or auth_url)
    parsed = urlsplit(final_url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.rstrip("/") or "/"
    if host != "auth.openai.com" or not (
        path == "/email-verification" or path.startswith("/email-verification/")
    ):
        known_landings = {
            "/log-in", "/log-in/password", "/login", "/workspace", "/mfa",
            "/phone-verification", "/about-you", "/create-account/password", "/auth/error",
        }
        landing = path if host == "auth.openai.com" and path in known_landings else (
            "other_auth_page" if host == "auth.openai.com" else "other_host"
        )
        raise ReauthenticationError(
            f"重认证 authorize 未进入邮箱验证流程: landing={landing}",
            error_code="reauth_authorize_unexpected_landing",
            retryable=True,
        )
    logger.info("[2FA] 重认证已进入邮箱验证流程")


def _validate_reauth_otp(session: BrowserSession, code: str) -> str:
    """
    步骤4: 提交邮箱 OTP 验证。
    返回 continue_url（带 code 参数的 callback URL，用于跳回 chatgpt.com）。
    """
    url = "https://auth.openai.com/api/accounts/email-otp/validate"
    headers = session.get_auth_headers(referer="https://auth.openai.com/email-verification")
    body = json.dumps({"code": code})

    logger.info("[2FA] 提交重认证 OTP")
    try:
        resp = session.post(url, headers=headers, data=body)
    except Exception as exc:
        raise ReauthenticationError(
            "提交邮箱重认证 OTP 时网络失败",
            error_code="reauth_otp_network",
            retryable=True,
        ) from exc
    status = int(getattr(resp, "status_code", 0) or 0)
    if not 200 <= status < 300:
        raise ReauthenticationError(
            f"邮箱重认证 OTP 被拒绝（HTTP {status}）",
            error_code="reauth_otp_rejected",
            http_status=status,
            # A 401 normally means the mailbox returned the preceding code
            # during a short provider delay. A fresh reauth transaction can
            # safely request and validate a new OTP.
            retryable=status in {401, 403, 408, 425, 429} or status >= 500,
        )
    try:
        data = resp.json()
        continue_url = str(data.get("continue_url") or "").strip()
    except Exception as exc:
        raise ReauthenticationError(
            "邮箱重认证 OTP 响应不是有效 JSON",
            error_code="reauth_otp_invalid_response",
            retryable=True,
        ) from exc
    if not continue_url:
        raise ReauthenticationError(
            "OTP 验证响应缺少 continue_url",
            error_code="reauth_otp_invalid_response",
            retryable=True,
        )
    session._reauth_otp_payload = data
    return continue_url


def _exchange_new_token(
    session: BrowserSession,
    continue_url: str,
    *,
    previous_access_token: str,
    reauth_started_at: float,
) -> str:
    """
    步骤5: 跟随 continue_url 完成回调，再次拉 /api/auth/session 拿到新 accessToken
    （此时 token 内嵌的 pwd_auth_time 是新鲜的，2FA enroll 才会接受）。
    """
    logger.info("[2FA] 跟随 continue_url，刷新 session-token cookie...")
    session._chatgpt_bootstrap_session = None
    try:
        final_url = follow_oauth_callback(
            session,
            continue_url,
            referer="https://auth.openai.com/email-verification",
        )
    except ReauthenticationError:
        raise
    except Exception as exc:
        raise ReauthenticationError(
            "重认证 OAuth 回调请求失败",
            error_code="reauth_oauth_callback_failed",
            retryable=True,
        ) from exc

    parsed_final = urlsplit(final_url)
    final_host = (parsed_final.hostname or "").lower()
    callback_errors = parse_qs(parsed_final.query).get("error") or []
    if parsed_final.path.rstrip("/") == "/auth/error" or callback_errors:
        callback_error = str(callback_errors[0] if callback_errors else "callback_error")
        safe_error = (
            callback_error
            if callback_error.replace("_", "").isalnum()
            else "callback_error"
        )
        raise ReauthenticationError(
            f"重认证 OAuth 回调失败: {safe_error}",
            error_code="reauth_oauth_callback_error",
            retryable=True,
        )
    if final_host == "auth.openai.com" and parsed_final.path.rstrip("/") == "/workspace":
        # Team/多工作区账号在 OTP 后会先落到 workspace 选择页；选择后才会
        # 继续跳到 ChatGPT 的 NextAuth callback。
        logger.info("[2FA] OAuth 回调落到 workspace，继续选择工作区")
        final_url = _select_reauth_workspace(
            session,
            preferred_workspace_id=_jwt_chatgpt_account_id(previous_access_token),
        )
        parsed_final = urlsplit(final_url)
        final_host = (parsed_final.hostname or "").lower()
    if final_host != "chatgpt.com":
        raise ReauthenticationError(
            "重认证 OAuth 回调未返回 ChatGPT",
            error_code="reauth_oauth_callback_unexpected_landing",
            retryable=True,
        )

    from config import twofa as _twofa_cfg

    try:
        attempts = int(getattr(_twofa_cfg, "TOTP_REAUTH_SESSION_ATTEMPTS", 10) or 10)
    except (TypeError, ValueError):
        attempts = 10
    attempts = max(1, min(30, attempts))
    try:
        interval = float(getattr(_twofa_cfg, "TOTP_REAUTH_SESSION_INTERVAL", 1.0) or 1.0)
    except (TypeError, ValueError):
        interval = 1.0
    interval = max(0.1, min(5.0, interval))

    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            session_info = fetch_session(
                session,
                force_network=attempt > 1,
                cache_buster=True,
            )
            last_error = None
            candidate = str(session_info.get("accessToken") or "").strip()
            if _is_fresh_reauth_token(
                candidate,
                previous_access_token=previous_access_token,
                reauth_started_at=reauth_started_at,
            ):
                logger.info(
                    "[2FA] 已获取包含新鲜认证时间的 accessToken: attempt=%s",
                    attempt,
                )
                return candidate
            logger.warning(
                "[2FA] session 尚未返回重认证后的新 accessToken: attempt=%s/%s",
                attempt,
                attempts,
            )
        except Exception as exc:
            last_error = exc
            logger.warning(
                "[2FA] 重认证后读取 session 失败: attempt=%s/%s error=%s",
                attempt,
                attempts,
                type(exc).__name__,
            )
        if attempt < attempts:
            time.sleep(interval)

    if last_error is not None:
        raise ReauthenticationError(
            f"重认证回调后未能读取有效登录态: {type(last_error).__name__}",
            error_code="reauth_session_unavailable",
            retryable=True,
        ) from last_error
    raise ReauthenticationError(
        "重认证已完成，但 session 持续返回旧 access_token，pwd_auth_time 未刷新",
        error_code="reauth_session_stale",
        retryable=True,
    )


def _wait_reauth_email_otp(session: BrowserSession, email: str, *, after_ts: float) -> str:
    """正常等待优先；确认邮箱可读但无新码时，在原认证会话内补发一次。"""
    from core.email_provider import wait_for_otp
    from core.icloud_mail_client import ICloudOtpTimeoutError, capture_otp_baseline
    from core.openai_auth import send_email_otp

    try:
        return wait_for_otp(email, after_ts=after_ts)
    except ICloudOtpTimeoutError as exc:
        if not exc.resend_recommended:
            raise
        logger.warning(
            "[2FA] 邮箱可读取但未收到本次新码，保留重认证会话补发一次: reason=%s",
            exc.reason,
        )

    # 重发前更新水位及时间边界，避免把迟到的上一封验证码当作重发结果。
    captured = capture_otp_baseline(email)
    resend_after_ts = time.time()
    logger.info("[2FA] 补发前旧码水位快照: captured=%s", captured)
    try:
        send_email_otp(session, referer="https://auth.openai.com/email-verification")
    except Exception as exc:
        # 发码请求抛错也可能已送达，不由外层重新发起整轮 OAuth 再次发码。
        raise ReauthenticationError(
            "重认证补发验证码请求未确认，请稍后重试",
            error_code="reauth_otp_resend_unconfirmed",
        ) from exc
    return wait_for_otp(email, after_ts=resend_after_ts)


def reauthenticate_for_2fa(
    session: BrowserSession,
    email: str,
    otp_code: str | None = None,
    *,
    allow_manual_input: bool = False,
    previous_access_token: str = "",
) -> str:
    """Refresh authentication time through the existing pure-HTTP email OTP flow."""
    from config import email as _email_cfg

    session._reauth_otp_payload = None
    # Some iCloud pickup APIs do not expose a reliable timestamp. Record the
    # current message before asking OpenAI to send a new OTP, otherwise a retry
    # can immediately reuse the previous reauth code and receive HTTP 401.
    try:
        from core.email_provider import resolve_email_source

        if resolve_email_source(email) == "icloud":
            from core.icloud_mail_client import capture_otp_baseline

            captured = capture_otp_baseline(email)
            logger.info("[2FA] iCloud 发码前旧码水位快照: captured=%s", captured)
    except Exception:
        logger.warning("[2FA] iCloud 发码前旧码水位快照失败，将继续使用时间过滤")

    reauth_otp_after_ts = time.time()
    auth_url = _trigger_reauth(session, email)
    human_delay("api")
    _follow_reauth(session, auth_url)
    human_delay("navigate")

    if otp_code is None:
        if _email_cfg.USE_EMAIL_SERVICE:
            logger.info("[2FA] 自动等待邮箱重认证 OTP...")
            otp_code = _wait_reauth_email_otp(session, email, after_ts=reauth_otp_after_ts)
        elif allow_manual_input:
            logger.info("")
            logger.info("[2FA] 请检查邮箱，输入新收到的 6 位验证码")
            otp_code = input(">>> 2FA 验证码: ").strip()
        else:
            raise ReauthenticationError(
                "TOTP 补接需要重认证，但当前未启用自动邮箱取码",
                error_code="reauth_mail_unavailable",
            )

    otp_code = str(otp_code or "").strip()
    if not otp_code:
        raise ReauthenticationError(
            "邮箱重认证 OTP 为空",
            error_code="reauth_otp_empty",
            retryable=True,
        )

    human_delay("otp_input")
    continue_url = _validate_reauth_otp(session, otp_code)
    human_delay("api")
    return _exchange_new_token(
        session,
        continue_url,
        previous_access_token=previous_access_token,
        reauth_started_at=reauth_otp_after_ts,
    )


def setup_2fa(
    session: BrowserSession,
    email: str,
    otp_code: str | None = None,
    *,
    access_token: str | None = None,
) -> str:
    """Backward-compatible synchronous wrapper over the account TOTP service."""
    from core.totp_service import enroll_totp_with_session

    token = str(access_token or "").strip()
    if not token:
        token = str(fetch_session(session).get("accessToken") or "").strip()
    result = enroll_totp_with_session(
        session,
        token,
        email,
        reauth_callback=lambda current, current_email, current_token: reauthenticate_for_2fa(
            current,
            current_email,
            otp_code=otp_code,
            allow_manual_input=True,
            previous_access_token=current_token,
        ),
    )
    if not result.get("ok"):
        raise RuntimeError(str(result.get("error") or result.get("message") or "TOTP 设置失败"))
    secret = str(result.get("secret") or "").strip()
    if not secret:
        raise RuntimeError("远端 TOTP 已启用，但本地没有可恢复的 secret")
    logger.info("[2FA] TOTP 已通过 mfa_info 确认启用")
    return secret


def save_account_data(
    email: str,
    access_token: str,
    totp_secret: str | None = None,
    extra: dict | None = None,
    output_path: Path | None = None,  # 兼容老接口，已废弃
    email_source: str | None = None,
    proxy_used: str | None = None,
    batch_dir: Path | None = None,
    web_cookies=None,
    web_cookie_source: str | None = None,
    initial_plan_result: dict | None = None,
) -> int:
    """
    将账号信息保存到本地 JSON/TXT 文件存储。
    返回新插入/更新的 row id。
    """
    from core.db import insert_account
    extra = dict(extra or {})
    normalized_web_cookies = None
    web_cookie_normalize_error: Exception | None = None
    if web_cookies is not None:
        try:
            from core.account_cookie_store import normalize_cookies

            normalized_web_cookies = normalize_cookies(
                web_cookies,
                source=str(web_cookie_source or "registration"),
            )
            if not str(extra.get("device_id") or "").strip():
                for cookie in normalized_web_cookies:
                    if str(cookie.get("name") or "").strip().lower() != "oai-did":
                        continue
                    value = str(cookie.get("value") or "").strip()
                    if value and len(value) <= 256 and "\r" not in value and "\n" not in value:
                        extra["device_id"] = value
                    break
        except Exception as exc:
            web_cookie_normalize_error = exc
    user = extra.get("user") or {}
    account = extra.get("account") or {}
    # 从 extra.codex 抽出顶层 codex 状态/错误，方便 WebUI 直接读账号字段
    codex = extra.get("codex") or {}
    codex_status = codex.get("status")  # success / failed / skipped
    codex_error = None
    if codex_status == "failed":
        codex_error = codex.get("message")

    row_id = insert_account(
        email=email,
        access_token=access_token,
        totp_secret=totp_secret,
        user_id=user.get("id"),
        user_name=user.get("name"),
        plan_type=account.get("planType"),
        expires_at=extra.get("expires"),
        device_id=extra.get("device_id"),
        proxy_used=proxy_used,
        email_source=email_source,
        extra=extra,
        codex_status=codex_status,
        codex_error=codex_error,
    )
    if web_cookies is not None:
        from core import db
        from core.account_cookie_store import persist_cookie_credential

        try:
            if web_cookie_normalize_error is not None:
                raise web_cookie_normalize_error
            normalized_cookies = normalized_web_cookies or []
            if normalized_cookies:
                metadata = persist_cookie_credential(
                    email,
                    normalized_cookies,
                    source=str(web_cookie_source or "registration"),
                    account_id=row_id,
                )
                db.update_account_web_cookie_credential(
                    row_id,
                    credential_path=metadata["credential_path"],
                    saved_at=metadata["saved_at"],
                    cookie_count=metadata["count"],
                    has_session_cookie=metadata["has_session_cookie"],
                    status="saved",
                    error=None,
                )
                logger.info(
                    "[Cookie] Web Cookie 已保存：id=%s email=%s count=%s has_session=%s",
                    row_id,
                    email,
                    metadata["count"],
                    metadata["has_session_cookie"],
                )
            else:
                db.update_account_web_cookie_credential(
                    row_id,
                    status="empty",
                    error="注册会话未捕获到可保存的 ChatGPT/OpenAI Cookie",
                )
                logger.warning("[Cookie] 未捕获到可保存的 Web Cookie：id=%s email=%s", row_id, email)
        except Exception as exc:
            try:
                db.update_account_web_cookie_credential(
                    row_id,
                    status="failed",
                    error=f"{type(exc).__name__}: {str(exc)[:500]}",
                )
            except Exception:
                logger.debug("[Cookie] 保存失败状态回写异常", exc_info=True)
            logger.warning(
                "[Cookie] Web Cookie 保存失败（不影响账号与 Web AT）：id=%s email=%s error=%s: %s",
                row_id,
                email,
                type(exc).__name__,
                str(exc)[:180],
            )
    if codex_status and codex_status != "skipped":
        # CLI/单驱动入口会在保存基础账号前完成 Codex；同步到独立字段，
        # 与 WebUI 的“基础注册后独立 OAuth”路径保持同一数据模型。
        from core.db import update_account_codex_result

        update_account_codex_result(email, codex)
    batch_folder = _append_batch_archive(
        row_id=row_id,
        email=email,
        access_token=access_token,
        totp_secret=totp_secret,
        email_source=email_source,
        proxy_used=proxy_used,
        extra=extra,
        batch_dir=batch_dir,
    )
    logger.info(f"[Save] 账号已写入 DB, id={row_id}, email={email}")
    logger.info(f"[Save] 批次归档目录: {batch_folder}")

    # TOTP is an account post-processing task. The base account and managed
    # cookies must exist before registration optionally invokes the same queue
    # used by manual and bulk supplementation.
    try:
        from config import twofa as _twofa_cfg

        if _twofa_cfg.auto_setup_after_registration_enabled():
            from core.totp_service import enqueue_account_totp

            totp_kwargs = {
                "account_id": row_id,
                "email": email,
                "access_token": access_token,
                "trigger": "registration_auto",
            }
            device_id = str(extra.get("device_id") or "").strip()
            if device_id:
                totp_kwargs["device_id"] = device_id
            if normalized_web_cookies:
                totp_kwargs["cookies"] = normalized_web_cookies
            queued_totp = enqueue_account_totp(**totp_kwargs)
            if queued_totp.get("accepted"):
                logger.info("[TOTP] 注册后自动补接已入队: id=%s email=%s", row_id, email)
            elif queued_totp.get("busy"):
                logger.info("[TOTP] 账号已有补接任务，不重复入队: id=%s email=%s", row_id, email)
            else:
                logger.warning(
                    "[TOTP] 注册后自动补接入队失败（不影响注册结果）: %s",
                    queued_totp.get("error") or "未知错误",
                )
    except Exception as exc:
        logger.warning(
            "[TOTP] 注册后自动补接入队异常（不影响注册结果）: %s: %s",
            type(exc).__name__,
            str(exc)[:180],
        )

    # 优先保存注册原始会话的最终 accounts/check。它比换代理后的后台查询更接近
    # 开户事实，并且可省掉一次重复请求；其他注册驱动仍走原后台查询路径。
    initial_plan_saved = False
    initial_plan_conclusive = False
    initial_plan_type = ""
    if isinstance(initial_plan_result, dict):
        initial_plan_type = str(
            initial_plan_result.get("current_plan_type")
            or initial_plan_result.get("plan_type")
            or ""
        ).strip().lower()
    initial_plan_usable = initial_plan_type not in {"", "guest", "unknown"}
    if (
        isinstance(initial_plan_result, dict)
        and initial_plan_result.get("ok")
        and initial_plan_usable
    ):
        try:
            from core import db

            initial_plan_saved = bool(db.update_account_plan_check(
                acc_id=row_id,
                result=initial_plan_result,
            ))
            if initial_plan_saved:
                trial_eligible = bool(initial_plan_result.get("plus_trial_eligible"))
                promo_check_ok = initial_plan_result.get("promo_check_ok") is True
                promo_status = str(
                    initial_plan_result.get("plus_trial_status") or ""
                ).strip().lower()
                has_active_subscription = (
                    initial_plan_result.get("has_active_subscription") is True
                )
                # 新账号的优惠资格可能在开户后短暂延迟出现。明确的非 Free
                # 套餐无需再查；guest/unknown 不是有效账号结论，不能短路。
                # Free 套餐只有在资格与 coupon 状态都已明确时才可短路。
                initial_plan_conclusive = bool(
                    (
                        initial_plan_type != "free"
                        and has_active_subscription
                    )
                    or (
                        initial_plan_type == "free"
                        and trial_eligible
                        and promo_check_ok
                        and promo_status in {"available", "redeemed", "unavailable"}
                    )
                )
                logger.info(
                    "[Plan] 已保存注册会话最终资格: id=%s plan=%s plus_trial=%s campaign=%s",
                    row_id,
                    initial_plan_result.get("current_plan_type") or "unknown",
                    bool(initial_plan_result.get("plus_trial_eligible")),
                    initial_plan_result.get("plus_trial_campaign_id") or "无",
                )
                if not initial_plan_conclusive:
                    logger.info(
                        "[Plan] 注册会话首次资格尚未明确或暂未命中 0 元优惠，"
                        "将进入注册后后台复查: id=%s email=%s",
                        row_id,
                        email,
                    )
            else:
                logger.warning(
                    "[Plan] 注册会话资格未能关联账号，将回退后台查询: id=%s email=%s",
                    row_id,
                    email,
                )
        except Exception as exc:
            logger.warning(
                "[Plan] 保存注册会话资格失败，将回退后台查询: %s: %s",
                type(exc).__name__,
                str(exc)[:180],
            )
        if initial_plan_saved and initial_plan_conclusive:
            return row_id
    elif isinstance(initial_plan_result, dict) and initial_plan_result.get("ok"):
        logger.warning(
            "[Plan] 注册会话返回无效账号上下文，不作为成功套餐落库，将改由后台复查: "
            "id=%s email=%s plan=%s",
            row_id,
            email,
            initial_plan_type or "unknown",
        )

    # session 中的 account.planType 不能说明 Plus 试用资格。未提供首次响应时账号
    # 落库后只负责入队，由专用线程池异步查询并回写。
    try:
        from core.plan_check_service import enqueue_account_plan_check

        plan_check_kwargs = {
            "account_id": row_id,
            "email": email,
            "access_token": access_token,
            "trigger": "registration_auto",
        }
        device_id = str(extra.get("device_id") or "").strip()
        if device_id:
            plan_check_kwargs["device_id"] = device_id
        if normalized_web_cookies:
            plan_check_kwargs["cookies"] = normalized_web_cookies
        queued = enqueue_account_plan_check(
            **plan_check_kwargs,
        )
        if queued.get("accepted"):
            logger.info(f"[Plan] 注册后自动查询已入队: id={row_id}, email={email}")
        elif queued.get("busy"):
            logger.info(f"[Plan] 账号已有套餐查询，注册流程不重复入队: id={row_id}, email={email}")
        else:
            logger.warning(f"[Plan] 注册后自动查询入队失败（不影响注册结果）: {email}, {queued.get('error')}")
    except Exception as exc:
        logger.warning(
            f"[Plan] 注册后自动查询入队异常（不影响注册结果）: "
            f"{email}, {type(exc).__name__}: {str(exc)[:180]}"
        )
    return row_id
