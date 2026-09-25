# -*- coding: utf-8 -*-
"""Mail.com Web session client used to create real account aliases."""
from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, quote, urljoin, urlparse, urlunparse

from curl_cffi import requests

from config import email as _email_cfg


LOGIN_PAGE_URL = "https://www.mail.com/"
LOGIN_URL = "https://login.mail.com/login"
OAUTH_URL = "https://oauthbridge.navigator-lxa.mail.com/navigator/oauth2/token"
MAIL_LIST_URL = "https://maillist.mail.com/Mailbox/Mail"
MAIL_BODY_URL = "https://webmail-cats-live.mail.com/mailbox/primary/mailbody/{mail_id}/Body"
SETTINGS_ADDRESSES_URL = "https://settings-cats.mail.com/mailaccount/primary/emailAddresses"
SETTINGS_VALIDATE_URL = "https://settings-cats.mail.com/mailaccount/emailAddressValidations"
SETTINGS_REMOVE_URL = (
    "https://settings-cats.mail.com/mailaccount/primary/"
    "emailAddressesRemovals/{address}/removals"
)

MAIL_SCOPE = "mail_mailbox_r"
MAIL_CLIENT_ID = "mailcom_webmailermaillist_passport_live"
SETTINGS_SCOPE = "mail_mailbox_w webmailer_setting_r webmailer_setting_w mail_confix_w"
SETTINGS_CLIENT_ID = "mailcom_mailset_root_live"
DEFAULT_OAUTH_PUBLIC_SECRET = "*******"
IMPERSONATE = "firefox147"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) "
    "Gecko/20100101 Firefox/147.0"
)
STATISTICS_RE = re.compile(r'name=["\']statistics["\'][^>]*value=["\']([^"\']*)', re.I)


class MailcomWebError(RuntimeError):
    def __init__(self, message: str, *, kind: str = "upstream_error", status: int = 502):
        super().__init__(message)
        self.kind = kind
        self.status = status


@dataclass(frozen=True, slots=True)
class MailcomWebMessage:
    mail_id: str
    subject: str
    sender: str
    recipients: tuple[str, ...]
    timestamp: float


class MailcomWebClient:
    def __init__(
        self,
        username: str,
        password: str,
        *,
        timeout: float | None = None,
        proxy_url: str = "",
        state: dict[str, Any] | None = None,
    ) -> None:
        self.username = str(username or "").strip().lower()
        self.password = str(password or "")
        configured_timeout = getattr(_email_cfg, "MAILCOM_WEB_TIMEOUT", 25)
        self.timeout = max(1.0, float(timeout if timeout is not None else configured_timeout))
        self.impersonate = IMPERSONATE
        self.proxy_url = str(proxy_url or "").strip()
        self._closed = False
        self.session = self._new_session(self.proxy_url)
        restored = dict(state) if isinstance(state, dict) else {}
        self.sid = str(restored.get("sid") or "")
        self.auth_id = str(restored.get("auth_id") or "")
        restored_tokens = restored.get("tokens")
        if not isinstance(restored_tokens, dict):
            restored_tokens = {}
        self.tokens: dict[str, str] = {
            str(key): str(value)
            for key, value in restored_tokens.items()
            if str(key) and str(value)
        }
        cookies = restored.get("cookies")
        if isinstance(cookies, dict):
            self.session.cookies.update({
                str(key): str(value)
                for key, value in cookies.items()
                if str(key)
            })

    @staticmethod
    def _new_session(proxy_url: str = "") -> requests.Session:
        # This client is cached by base mailbox and reused by worker threads.
        # curl_cffi's default mode creates one Curl handle per thread, while
        # Session.close() only closes the caller's handle. Mailbox requests are
        # already serialized by mailcom_client._web_lock, so one handle is safe.
        session = requests.Session(
            impersonate=IMPERSONATE,
            use_thread_local_curl=False,
        )
        session.headers.update({"User-Agent": USER_AGENT})
        if proxy_url:
            session.trust_env = False
            session.proxies.update({"http": proxy_url, "https": proxy_url})
        return session

    def _reset_session(self) -> None:
        self._close_current_session()
        self.session = self._new_session(self.proxy_url)
        self._closed = False
        self.sid = ""
        self.auth_id = ""
        self.tokens.clear()

    def _close_current_session(self) -> None:
        close = getattr(getattr(self, "session", None), "close", None)
        if callable(close):
            close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._close_current_session()

    def export_state(self) -> dict[str, Any]:
        cookies: dict[str, str] = {}
        cookie_jar = getattr(self.session, "cookies", None)
        get_dict = getattr(cookie_jar, "get_dict", None)
        if callable(get_dict):
            try:
                cookies = {
                    str(key): str(value) for key, value in dict(get_dict()).items()
                }
            except (TypeError, ValueError):
                cookies = {}
        if not cookies:
            try:
                cookies = {
                    str(cookie.name): str(cookie.value)
                    for cookie in cookie_jar.jar
                    if str(getattr(cookie, "name", ""))
                }
            except (AttributeError, TypeError):
                cookies = {}
        return {
            "sid": self.sid,
            "auth_id": self.auth_id,
            "tokens": dict(self.tokens),
            "cookies": cookies,
            "saved_at": int(time.time()),
        }

    def __enter__(self) -> "MailcomWebClient":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @staticmethod
    def _redirect_summary(location: str) -> str:
        parsed = urlparse(str(location or ""))
        host = (parsed.hostname or "relative").lower()
        path = parsed.path or "/"
        keys = sorted(parse_qs(parsed.query, keep_blank_values=True))
        return f"{host}{path}; keys={','.join(keys) or '-'}"

    @staticmethod
    def _mailcom_redirect(location: str, *, base_url: str) -> str:
        target = urljoin(base_url, str(location or ""))
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
        if (
            parsed.scheme != "https"
            or not host
            or (host != "mail.com" and not host.endswith(".mail.com"))
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise MailcomWebError(
                "Mail.com 登录返回了不可信的中间跳转",
                kind="login_redirect",
                status=401,
            )
        return target

    def _resolve_login_redirect(self, response: Any) -> tuple[Any, str]:
        location = str(response.headers.get("Location", "") or "")
        for _ in range(3):
            if self._is_assistance_redirect(response, location):
                raise MailcomWebError(
                    "Mail.com Web 登录被当前出口拒绝 (redirect=assistance)",
                    kind="blocked",
                    status=403,
                )
            self._raise_for_interception(location)
            query = parse_qs(urlparse(location).query, keep_blank_values=True)
            if query.get("ott"):
                break
            if response.status_code not in {302, 303} or not location:
                break
            if "logout?ls=wd" in location:
                break
            target = self._mailcom_redirect(location, base_url=LOGIN_URL)
            try:
                response = self.session.get(
                    target,
                    allow_redirects=False,
                    timeout=self.timeout,
                    headers={"Referer": LOGIN_PAGE_URL},
                )
            except requests.RequestsError as exc:
                raise MailcomWebError(
                    "无法跟随 Mail.com 登录中间跳转", kind="network",
                ) from exc
            location = str(response.headers.get("Location", "") or "")
        self._raise_for_interception(location)
        return response, location

    @staticmethod
    def _is_assistance_redirect(response: Any, location: str) -> bool:
        parsed = urlparse(str(location or ""))
        if (
            (parsed.hostname or "").lower() == "support.mail.com"
            and parsed.path.rstrip("/").lower().endswith("/account/login/index.html")
        ):
            return True
        body = str(getattr(response, "text", "") or "").lower()
        return '"redirect"' in body and '"assistance"' in body

    @staticmethod
    def _raise_for_interception(location: str) -> None:
        parsed = urlparse(str(location or ""))
        host = (parsed.hostname or "").lower()
        if host != "mail.com" and not host.endswith(".mail.com"):
            return
        interception = str(
            (parse_qs(parsed.query, keep_blank_values=True).get("interceptiontype") or [""])[0]
        ).strip()
        if not interception:
            return
        normalized = re.sub(r"[^A-Za-z0-9_-]", "", interception)[:64]
        if normalized.casefold() == "mtanobligation":
            raise MailcomWebError(
                "Mail.com Web 登录需要手机验证",
                kind="verification_required",
                status=403,
            )
        raise MailcomWebError(
            f"Mail.com Web 登录需要完成安全检查 ({normalized or 'unknown'})",
            kind="interception_required",
            status=403,
        )

    @staticmethod
    def _decode_token(token: str) -> dict[str, Any]:
        try:
            payload = token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            return json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
        except (IndexError, ValueError, json.JSONDecodeError) as exc:
            raise MailcomWebError("Mail.com 返回了无法解析的 Access Token") from exc

    @classmethod
    def _token_expiry(cls, token: str) -> float:
        value = float(cls._decode_token(token).get("exp") or 0)
        return value / 1000.0 if value > 10_000_000_000 else value

    @staticmethod
    def _timezone_hours() -> int:
        local = time.localtime()
        offset = -time.timezone if not local.tm_isdst else -time.altzone
        return int(offset // 3600)

    def login(self, retries: int = 3) -> None:
        last_error: MailcomWebError | None = None
        for attempt in range(max(1, int(retries))):
            if attempt:
                self._reset_session()
            try:
                self._login_once()
                self.tokens.clear()
                return
            except MailcomWebError as exc:
                last_error = exc
                if exc.kind in {
                    "bad_credentials", "blocked", "verification_required",
                    "interception_required",
                }:
                    break
                if attempt + 1 < retries:
                    time.sleep(2 * (attempt + 1))
        raise last_error or MailcomWebError("Mail.com Web 登录失败", kind="login_failed")

    def _login_once(self) -> None:
        statistics = ""
        try:
            page = self.session.get(LOGIN_PAGE_URL, timeout=self.timeout)
            if page.ok:
                match = STATISTICS_RE.search(page.text)
                statistics = match.group(1) if match else ""
        except requests.RequestsError:
            pass

        form = {
            "username": self.username,
            "password": self.password,
            "service": "mailint",
            "uasServiceID": "mc_starter_mailcom",
            "successURL": "https://$(clientName)-$(dataCenter).mail.com/login",
            "loginFailedURL": "https://www.mail.com/logout?ls=wd",
            "loginErrorURL": "https://www.mail.com/logout?ls=te",
            "edition": "US",
            "lang": "en",
            "usertype": "standard",
            "ibaInfo": "abd=false",
            "statistics": statistics,
        }
        try:
            response = self.session.post(
                LOGIN_URL,
                data=form,
                allow_redirects=False,
                timeout=self.timeout,
                headers={"Origin": LOGIN_PAGE_URL.rstrip("/"), "Referer": LOGIN_PAGE_URL},
            )
        except requests.RequestsError as exc:
            raise MailcomWebError("无法连接 Mail.com 登录服务", kind="network") from exc

        response, location = self._resolve_login_redirect(response)
        if response.status_code == 429:
            raise MailcomWebError("Mail.com 登录频率受限", kind="rate_limited", status=429)
        if response.status_code == 403:
            raise MailcomWebError("Mail.com 拒绝了当前网络的登录请求", kind="blocked", status=403)
        if response.status_code in {302, 303} and "ott=" not in location:
            kind = "bad_credentials" if "logout?ls=wd" in location else "login_redirect"
            raise MailcomWebError(
                "Mail.com 登录未返回一次性令牌 "
                f"({self._redirect_summary(location)})",
                kind=kind,
                status=401,
            )
        if response.status_code not in {302, 303} or "ott=" not in location:
            raise MailcomWebError(
                f"Mail.com 登录响应异常 (HTTP {response.status_code})",
                kind="login_failed",
            )

        callback = urljoin(LOGIN_URL, location)
        parsed = urlparse(callback)
        query = parsed.query + ("&" if parsed.query else "") + f"tz={self._timezone_hours()}"
        halogin = urlunparse((parsed.scheme, parsed.netloc, "/halogin", "", query, ""))
        try:
            exchanged = self.session.get(halogin, allow_redirects=False, timeout=self.timeout)
        except requests.RequestsError as exc:
            raise MailcomWebError("无法完成 Mail.com 会话交换", kind="network") from exc
        exchange_location = exchanged.headers.get("Location", "")
        sid = (parse_qs(urlparse(exchange_location).query).get("sid") or [""])[0]
        if exchanged.status_code not in {302, 303} or not sid:
            raise MailcomWebError(
                "Mail.com 会话交换未返回 SID",
                kind="session_rejected",
                status=401,
            )
        self.sid = sid

    @staticmethod
    def _settings_headers(token: str, content_type: str, *, accept: str | None = None) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": accept or content_type,
            "Content-Type": content_type,
            "Origin": "https://mailset-root.mail.com",
            "Referer": "https://mailset-root.mail.com/",
            "x-ui-app": "mailcom.mailset-compose/1.0.5-build.335",
        }

    @staticmethod
    def _oauth_headers(client_id: str = SETTINGS_CLIENT_ID) -> dict[str, str]:
        public_secret = str(
            getattr(_email_cfg, "MAILCOM_OAUTH_PUBLIC_SECRET", DEFAULT_OAUTH_PUBLIC_SECRET)
            or DEFAULT_OAUTH_PUBLIC_SECRET
        )
        encoded = base64.b64encode(f"{client_id}:{public_secret}".encode()).decode()
        if client_id == SETTINGS_CLIENT_ID:
            context = {
                "Origin": "https://mailset-root.mail.com",
                "Referer": "https://mailset-root.mail.com/",
            }
        else:
            context = {
                "Origin": "https://webmailer.mail.com",
                "Referer": "https://webmailer.mail.com/",
                "x-ui-app": "mailcom.webmailer.mail-list/6.6.3",
            }
        context["Authorization"] = f"Basic {encoded}"
        return context

    def _token(self, scope: str, client_id: str, *, force: bool = False) -> str:
        cache_key = f"{client_id}|{scope}"
        token = self.tokens.get(cache_key, "")
        if token and not force:
            try:
                if self._token_expiry(token) > time.time() + 60:
                    return token
            except MailcomWebError:
                pass
        if not self.sid:
            self.login()
        try:
            response = self.session.post(
                OAUTH_URL,
                params={"sid": self.sid},
                data={"grant_type": "urn:mam:oauth:grant-type:spa", "scope": scope},
                timeout=self.timeout,
                headers=self._oauth_headers(client_id),
            )
        except requests.RequestsError as exc:
            raise MailcomWebError("无法连接 Mail.com OAuth 服务", kind="network") from exc
        if response.status_code in {401, 403}:
            raise MailcomWebError("Mail.com Web 会话已失效", kind="session_expired", status=401)
        if response.status_code == 429:
            raise MailcomWebError("Mail.com OAuth 请求频率受限", kind="rate_limited", status=429)
        if response.status_code != 200:
            raise MailcomWebError(
                f"Mail.com Settings Token 请求失败 (HTTP {response.status_code})",
                kind="oauth_failed",
            )
        try:
            token = str(response.json()["access_token"])
        except (ValueError, KeyError) as exc:
            raise MailcomWebError("Mail.com Token 响应缺少 Access Token", kind="oauth_failed") from exc
        self.auth_id = str(self._decode_token(token).get("auth_id") or self.auth_id)
        self.tokens[cache_key] = token
        return token

    def _settings_token(self, *, force: bool = False) -> str:
        return self._token(SETTINGS_SCOPE, SETTINGS_CLIENT_ID, force=force)

    def _mail_token(self, *, force: bool = False) -> str:
        return self._token(MAIL_SCOPE, MAIL_CLIENT_ID, force=force)

    def ensure_settings_token(self) -> str:
        try:
            return self._settings_token()
        except MailcomWebError as exc:
            if exc.kind != "session_expired":
                raise
            self.sid = ""
            self.tokens.clear()
            self.login()
            return self._settings_token(force=True)

    def ensure_mail_token(self) -> str:
        try:
            return self._mail_token()
        except MailcomWebError as exc:
            if exc.kind != "session_expired":
                raise
            self.sid = ""
            self.tokens.clear()
            self.login()
            return self._mail_token(force=True)

    @staticmethod
    def _mail_headers(token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.1and1.mms.unified-maillist-v1+json; charset=utf-8",
            "Content-Type": "application/vnd.1and1.mms.inboxadrequest-v1+json; charset=utf-8",
            "Origin": "https://webmailer.mail.com",
            "Referer": "https://webmailer.mail.com/",
            "x-ui-app": "mailcom.webmailer.mail-list/6.6.3",
        }

    def query_messages(self, recipient: str, *, amount: int = 20) -> list[MailcomWebMessage]:
        token = self.ensure_mail_token()
        params = {
            "folderTypeOrId": "INBOX",
            "offset": "0",
            "amount": str(max(1, min(int(amount or 20), 50))),
            "orderBy": "INTERNALDATE DESC",
            "no_cache": self.auth_id,
            "condition": f"mail.header:subject,to,from,cc:{recipient}",
        }

        def request(current_token: str):
            return self.session.post(
                MAIL_LIST_URL,
                params=params,
                data=b"",
                headers=self._mail_headers(current_token),
                timeout=self.timeout,
            )

        try:
            response = request(token)
            if response.status_code == 401:
                self.tokens.pop(f"{MAIL_CLIENT_ID}|{MAIL_SCOPE}", None)
                response = request(self.ensure_mail_token())
        except requests.RequestsError as exc:
            raise MailcomWebError("无法连接 Mail.com 邮件列表服务", kind="network") from exc
        if response.status_code != 200:
            raise MailcomWebError(
                f"查询 Mail.com 收件箱失败 (HTTP {response.status_code})",
                kind="mail_query_failed",
            )
        try:
            elements = response.json().get("mailListElements") or []
        except (ValueError, AttributeError) as exc:
            raise MailcomWebError("Mail.com 邮件列表响应不是 JSON", kind="mail_query_failed") from exc

        messages: list[MailcomWebMessage] = []
        for element in elements:
            raw = element.get("rawData") or {}
            attributes = raw.get("attribute") or {}
            header = raw.get("mailHeader") or {}
            mail_id = str(attributes.get("mailIdentifier") or "").strip()
            if not mail_id:
                continue
            recipients = header.get("to") or []
            if isinstance(recipients, str):
                recipients = [recipients]
            try:
                timestamp = float(header.get("date") or attributes.get("internalDate") or 0)
            except (TypeError, ValueError):
                timestamp = 0.0
            if timestamp > 10_000_000_000:
                timestamp /= 1000.0
            messages.append(MailcomWebMessage(
                mail_id=mail_id,
                subject=str(header.get("subject") or ""),
                sender=str(header.get("from") or ""),
                recipients=tuple(str(value) for value in recipients),
                timestamp=timestamp,
            ))
        return messages

    def get_message_body(self, mail_id: str) -> str:
        token = self.ensure_mail_token()

        def request(current_token: str):
            return self.session.get(
                MAIL_BODY_URL.format(mail_id=str(mail_id)),
                params={"absoluteURI": "false", "no_cache": self.auth_id},
                headers={**self._mail_headers(current_token), "Accept": "text/plain"},
                timeout=self.timeout,
            )

        try:
            response = request(token)
            if response.status_code == 401:
                self.tokens.pop(f"{MAIL_CLIENT_ID}|{MAIL_SCOPE}", None)
                response = request(self.ensure_mail_token())
        except requests.RequestsError as exc:
            raise MailcomWebError("无法连接 Mail.com 邮件正文服务", kind="network") from exc
        if response.status_code != 200:
            raise MailcomWebError(
                f"获取 Mail.com 邮件正文失败 (HTTP {response.status_code})",
                kind="mail_body_failed",
            )
        return str(response.text or "")

    def list_aliases(self) -> list[str]:
        token = self.ensure_settings_token()
        try:
            response = self.session.get(
                SETTINGS_ADDRESSES_URL,
                params={
                    "absoluteURI": "false",
                    "q.state.in": "ACTIVE",
                    "q.type.in": "MANAGED,DOMAIN_HOSTING",
                },
                headers=self._settings_headers(
                    token,
                    "application/vnd.ui.trinity.mailaddress.list-v5+json",
                ),
                timeout=self.timeout,
            )
        except requests.RequestsError as exc:
            raise MailcomWebError("无法读取 Mail.com 地址列表", kind="network") from exc
        if response.status_code != 200:
            raise MailcomWebError(
                f"读取 Mail.com 地址列表失败 (HTTP {response.status_code})",
                kind="settings_failed",
            )
        try:
            rows = response.json().get("mailaddresslist") or []
        except ValueError as exc:
            raise MailcomWebError("Mail.com 地址列表响应不是 JSON", kind="settings_failed") from exc
        return [
            str(row.get("address") or "").strip().lower()
            for row in rows
            if str(row.get("address") or "").strip()
        ]

    def add_alias(self, address: str) -> None:
        normalized = str(address or "").strip().lower()
        token = self.ensure_settings_token()
        try:
            validation = self.session.post(
                SETTINGS_VALIDATE_URL,
                params={"absoluteURI": "false"},
                json=[normalized],
                headers=self._settings_headers(
                    token,
                    "application/vnd.ui.trinity.email-address-validation-request+json",
                    accept="application/vnd.ui.trinity.email-address-validation-response+json",
                ),
                timeout=self.timeout,
            )
        except requests.RequestsError as exc:
            raise MailcomWebError("无法校验 Mail.com Alias", kind="network") from exc
        if validation.status_code != 200:
            raise MailcomWebError(
                f"Mail.com Alias 校验失败 (HTTP {validation.status_code})",
                kind="alias_invalid",
                status=400,
            )
        try:
            response = self.session.post(
                SETTINGS_ADDRESSES_URL,
                params={"absoluteURI": "false"},
                json={
                    "address": normalized,
                    "deletable": True,
                    "pgpEnabled": False,
                    "defaultSenderAddress": False,
                    "defaultReceiverAddress": False,
                    "state": "ACTIVE",
                },
                headers=self._settings_headers(
                    token,
                    "application/vnd.ui.trinity.minimalmailaddress-v3+json",
                ),
                timeout=self.timeout,
            )
        except requests.RequestsError as exc:
            raise MailcomWebError("无法创建 Mail.com Alias", kind="network") from exc
        if response.status_code != 201:
            kind = "alias_limit" if response.status_code in {403, 409, 422, 429} else "settings_failed"
            raise MailcomWebError(
                f"创建 Mail.com Alias 失败 (HTTP {response.status_code})",
                kind=kind,
                status=400,
            )

    def delete_alias(self, address: str) -> bool:
        """Delete one managed address through Mail.com's current removal API.

        ``False`` means the address was already absent. Every other non-2xx
        response is surfaced so callers can rebuild the authenticated session.
        """
        normalized = str(address or "").strip().lower()
        if not normalized or "@" not in normalized:
            raise MailcomWebError(
                "Mail.com Alias 地址格式无效",
                kind="alias_invalid",
                status=400,
            )
        url = SETTINGS_REMOVE_URL.format(
            address=quote(normalized, safe="@._-+"),
        )

        def request(current_token: str):
            return self.session.post(
                url,
                params={"absoluteURI": "false"},
                data=b"",
                headers=self._settings_headers(
                    current_token,
                    "text/plain;charset=UTF-8",
                ),
                timeout=self.timeout,
            )

        token = self.ensure_settings_token()
        try:
            response = request(token)
            if response.status_code == 401:
                self.tokens.pop(f"{SETTINGS_CLIENT_ID}|{SETTINGS_SCOPE}", None)
                response = request(self.ensure_settings_token())
        except requests.RequestsError as exc:
            raise MailcomWebError("无法删除 Mail.com Alias", kind="network") from exc
        if response.status_code == 404:
            return False
        if response.status_code in {401, 403}:
            raise MailcomWebError(
                "Mail.com Web 会话已失效",
                kind="session_expired",
                status=401,
            )
        if response.status_code == 429:
            raise MailcomWebError(
                "Mail.com Alias 删除请求频率受限",
                kind="rate_limited",
                status=429,
            )
        if response.status_code == 409:
            raise MailcomWebError(
                "Mail.com 不允许删除该 Alias",
                kind="alias_not_deletable",
                status=409,
            )
        if not 200 <= response.status_code < 300:
            raise MailcomWebError(
                f"删除 Mail.com Alias 失败 (HTTP {response.status_code})",
                kind="alias_delete_failed",
            )
        return True
