# -*- coding: utf-8 -*-
"""Read and accept ChatGPT Team invitations in isolated account Roxy sessions.

Each worker handles one explicitly selected account at a time.
Mailbox credentials are used only to locate the invitation URL; the URL is
kept in memory for the duration of the task and is never written to account
state, logs, or API responses.  The browser operation reuses the active Roxy
profile created by :mod:`core.account_browser_session`, then persists the
resulting managed ChatGPT/OpenAI cookies.
"""
from __future__ import annotations

import base64
import hashlib
import html as html_lib
import json
import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlparse

import requests

from config import roxybrowser as _roxy_cfg
from core import db
from core.account_cookie_store import (
    capture_selenium_cookies,
    has_session_cookie,
    normalize_cookies,
    persist_cookie_credential,
)
from core.account_token_refresh import (
    _merged_cookie_snapshot,
    _seed_cookie_jar,
    _session_headers,
)
from core.network_errors import is_retryable_network_error
from core.session import BrowserSession


logger = logging.getLogger(__name__)

_ALLOWED_INVITE_HOSTS = frozenset({
    "chatgpt.com", "www.chatgpt.com", "auth.openai.com",
})
_TRACKING_HOST_MARKERS = ("mandrillapp.com", "mailchimp.com", "mailchi.mp")
_URL_RE = re.compile(r"https?://[^\s<>'\"()]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_INVITE_PATH_RE = re.compile(
    r"(?:^|/)(?:accept[-_]?invite|invite(?:/accept)?|join(?:/invite)?|"
    r"team/invite|workspace/invite|organization/invite|business/invite)(?:/|$)",
    re.IGNORECASE,
)
_INVITE_QUERY_KEYS = frozenset({
    "invite", "invite_id", "inviteid", "invite_token", "invitetoken",
    "invitation", "invitation_id", "invitation_token", "workspace_invite",
    "invite_code", "invitation_code",
})
_TRACKING_QUERY_KEYS = frozenset({
    "u", "url", "redirect", "redirect_url", "redirect_uri", "target", "link",
    "href", "destination", "next", "continue", "return", "return_to", "returnto",
})
_INVITE_SUCCESS_HINTS = (
    "you've joined", "you have joined", "joined the workspace", "joined the team",
    "you are now a member", "welcome to the team", "welcome to your workspace",
    "workspace joined", "invitation accepted", "invite accepted",
    "已加入", "加入了工作区", "加入了团队", "已成功加入", "邀请已接受", "接受邀请成功",
)
_INVITE_ALREADY_HINTS = (
    "already a member", "already joined", "already accepted", "is already in",
    "已经是成员", "已是成员", "已经加入", "已加入该工作区", "已接受邀请",
)
_INVITE_EXPIRED_HINTS = (
    "invite has expired", "invitation expired", "expired invitation", "invalid invite",
    "invite is no longer valid", "invitation revoked", "seat is full", "no seats",
    "邀请已过期", "邀请无效", "邀请已撤销", "席位已满", "没有可用席位",
)
_INVITE_PENDING_HINTS = (
    "administrator approval", "admin approval", "pending approval", "等待管理员",
    "管理员批准", "需要管理员", "contact your administrator",
)
_ACCEPT_WORDS = (
    "accept", "join", "continue", "get started", "加入", "接受", "同意",
    "开始使用", "继续",
)
_NEGATIVE_ACTION_WORDS = (
    "decline", "reject", "cancel", "leave", "退出", "拒绝", "取消", "logout",
    # Never treat an identity-provider CTA such as "Continue with Google" as
    # the Team invitation action when an invite page falls back to login UI.
    "google", "apple", "microsoft", "github", "facebook", "sso", "oauth",
    "saml", "oidc", "passkey", "social",
)


class TeamInviteError(RuntimeError):
    """Sanitized Team invite error safe to persist in account state."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "team_invite_failed",
        status: int = 500,
        retryable: bool = False,
    ) -> None:
        super().__init__(str(message)[:500])
        self.code = str(code or "team_invite_failed")
        self.status = int(status or 500)
        self.retryable = bool(retryable)


def _int_setting(name: str, default: int, lower: int, upper: int) -> int:
    raw = os.getenv(name, "")
    try:
        value = int(raw) if str(raw).strip() else default
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


def _float_setting(name: str, default: float, lower: float, upper: float) -> float:
    raw = os.getenv(name, "")
    try:
        value = float(raw) if str(raw).strip() else default
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


# TEAM_INVITE_WORKERS 是旧版未进配置页时的兼容环境变量；新配置统一使用
# ROXY_ 前缀，以便归入本地指纹浏览器配置分组。
_WORKERS = _int_setting(
    "TEAM_INVITE_WORKERS",
    int(getattr(_roxy_cfg, "ROXY_TEAM_INVITE_WORKERS", 10) or 10),
    1,
    20,
)
_QUEUE_LIMIT = _int_setting("TEAM_INVITE_QUEUE_LIMIT", 100, _WORKERS, 500)
_MESSAGE_SCAN_LIMIT = _int_setting("TEAM_INVITE_MESSAGE_LIMIT", 100, 1, 100)
_INVITE_TIMEOUT = _float_setting("TEAM_INVITE_TIMEOUT_SECONDS", 60.0, 10.0, 180.0)
_INVITE_POLL_INTERVAL = _float_setting("TEAM_INVITE_POLL_INTERVAL_SECONDS", 1.0, 0.25, 5.0)
_MAIL_WAIT_TIMEOUT = _float_setting("TEAM_INVITE_MAIL_WAIT_SECONDS", 30.0, 0.0, 120.0)
_MAIL_POLL_INTERVAL = _float_setting(
    "TEAM_INVITE_MAIL_POLL_INTERVAL_SECONDS", 2.0, 0.5, 10.0,
)
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="team-invite")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_PROTOCOL_WORKERS = _int_setting("TEAM_INVITE_PROTOCOL_WORKERS", 10, 1, 50)
_PROTOCOL_QUEUE_LIMIT = _int_setting(
    "TEAM_INVITE_PROTOCOL_QUEUE_LIMIT", 100, _PROTOCOL_WORKERS, 500,
)
_PROTOCOL_EXECUTOR = ThreadPoolExecutor(
    max_workers=_PROTOCOL_WORKERS,
    thread_name_prefix="team-invite-protocol",
)
_PROTOCOL_QUEUE_SLOTS = threading.BoundedSemaphore(_PROTOCOL_QUEUE_LIMIT)
_PROTOCOL_ACCEPT_ATTEMPTS = _int_setting(
    "TEAM_INVITE_PROTOCOL_ACCEPT_ATTEMPTS", 6, 1, 10,
)
_PROTOCOL_READ_ATTEMPTS = _int_setting("TEAM_INVITE_PROTOCOL_READ_ATTEMPTS", 3, 1, 5)
_PROTOCOL_ACCEPT_BACKOFF = _float_setting(
    "TEAM_INVITE_PROTOCOL_ACCEPT_BACKOFF_SECONDS", 0.75, 0.1, 5.0,
)
_PROTOCOL_ACCEPT_COOLDOWN = _float_setting(
    "TEAM_INVITE_PROTOCOL_ACCEPT_COOLDOWN_SECONDS", 1.0, 0.0, 5.0,
)
_PROTOCOL_ACCEPT_LOCKS_GUARD = threading.Lock()
_PROTOCOL_ACCEPT_LOCKS: dict[str, threading.Lock] = {}
_SESSION_URL = "https://chatgpt.com/api/auth/session"
_PROTOCOL_REDIRECT_LIMIT = 8


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _protocol_accept_lock(workspace_id: str) -> threading.Lock:
    """Serialize membership writes for the same target Team workspace."""
    key = str(workspace_id or "").strip() or "unknown-workspace"
    with _PROTOCOL_ACCEPT_LOCKS_GUARD:
        lock = _PROTOCOL_ACCEPT_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PROTOCOL_ACCEPT_LOCKS[key] = lock
        return lock


def _email_key(value: Any) -> str:
    return str(value or "").strip().lower()


def _message_timestamp(message: dict[str, Any]) -> float | None:
    for key in (
        "receivedAt", "received_at", "receivedDateTime", "sentAt", "createdAt",
        "created_at", "ingestedAt", "date", "timestamp", "time",
    ):
        raw = message.get(key)
        if raw in (None, ""):
            continue
        if isinstance(raw, (int, float)):
            value = float(raw)
            return value / 1000.0 if value > 1e12 else value
        text = str(raw).strip()
        try:
            value = float(text)
            return value / 1000.0 if value > 1e12 else value
        except (TypeError, ValueError):
            pass
        try:
            parsed = parsedate_to_datetime(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except (TypeError, ValueError, OverflowError):
            pass
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except (TypeError, ValueError, OverflowError):
            continue
    return None


def _flatten_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, dict):
        return " ".join(_flatten_text(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_text(item) for item in value)
    return ""


def _extract_addresses(value: Any) -> set[str]:
    """Extract RFC-style addresses from provider-specific recipient fields."""
    found: set[str] = set()
    if isinstance(value, dict):
        # Address objects should be consumed before walking all values so a
        # display name containing an @ does not become a false recipient.
        for key in ("email", "address", "mail", "value"):
            candidate = value.get(key)
            if isinstance(candidate, str) and _EMAIL_RE.fullmatch(candidate.strip()):
                found.add(candidate.strip().lower())
        for child in value.values():
            found.update(_extract_addresses(child))
        return found
    if isinstance(value, (list, tuple, set)):
        for child in value:
            found.update(_extract_addresses(child))
        return found
    if isinstance(value, str):
        for _name, address in getaddresses([value]):
            address = str(address or "").strip().lower()
            if address and _EMAIL_RE.fullmatch(address):
                found.add(address)
        # Some JSON APIs return a bare address without RFC display syntax.
        for match in re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", value, re.I):
            if _EMAIL_RE.fullmatch(match):
                found.add(match.lower())
    return found


def _message_recipients(message: dict[str, Any]) -> set[str]:
    addresses: set[str] = set()
    for key in (
        "to", "To", "toRecipients", "ToRecipients", "recipient", "recipients",
        "deliveredTo", "delivered_to", "xOriginalTo", "X-Original-To", "envelopeTo",
        "cc", "ccRecipients", "bcc", "bccRecipients",
    ):
        if key in message:
            addresses.update(_extract_addresses(message.get(key)))
    return addresses


def _message_bodies(message: dict[str, Any]) -> tuple[str, str]:
    text_fields = (
        "text", "bodyText", "bodyPreview", "preview", "content", "body", "snippet",
    )
    html_fields = ("html", "html_content", "bodyHtml", "htmlBody", "contentHtml")
    # Providers do not agree on whether ``body``/``content`` is a string or a
    # nested object.  Flatten both forms so an invitation URL is not lost just
    # because the mailbox API returned a MIME-like structure.
    text = "\n".join(
        _flatten_text(message.get(key)) for key in text_fields
        if message.get(key) not in (None, "")
    )
    html = "\n".join(
        _flatten_text(message.get(key)) for key in html_fields
        if message.get(key) not in (None, "")
    )
    # JMAP bodyValues or provider-specific nested content.
    body_values = message.get("bodyValues")
    if isinstance(body_values, dict):
        values = "\n".join(
            _flatten_text(item.get("value"))
            for item in body_values.values()
            if isinstance(item, dict) and item.get("value") not in (None, "")
        )
        if values:
            text = f"{text}\n{values}" if text else values
    return text, html


def _message_haystack(message: dict[str, Any]) -> str:
    text, html = _message_bodies(message)
    return "\n".join((
        str(message.get("subject") or ""),
        str(message.get("from") or ""),
        str(message.get("sender") or ""),
        text,
        html,
    ))


def _targeted_message(message: Any, email: str, *, source: str) -> dict[str, Any] | None:
    if not isinstance(message, dict):
        return None
    item = dict(message)
    item["_team_target_email"] = str(email).strip()
    item["_team_source"] = str(source or "")[:40]
    return item


def _normalise_message_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ("messages", "mails", "emails", "results", "list", "value", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict) and key == "data":
                nested = _normalise_message_list(value)
                if nested:
                    return nested
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _mime_message_to_dict(message: Any) -> dict[str, Any]:
    """Convert an email.message object while retaining HTML href links."""
    try:
        from email.header import decode_header

        def decode(value: Any) -> str:
            chunks: list[str] = []
            for raw, charset in decode_header(value or ""):
                if isinstance(raw, bytes):
                    try:
                        chunks.append(raw.decode(charset or "utf-8", errors="replace"))
                    except LookupError:
                        chunks.append(raw.decode("utf-8", errors="replace"))
                else:
                    chunks.append(str(raw))
            return "".join(chunks)
    except Exception:
        decode = lambda value: str(value or "")

    plain: list[str] = []
    html_parts: list[str] = []
    parts = message.walk() if getattr(message, "is_multipart", lambda: False)() else [message]
    for part in parts:
        if getattr(part, "get_content_maintype", lambda: "")() == "multipart":
            continue
        content_type = str(getattr(part, "get_content_type", lambda: "")() or "")
        try:
            raw = part.get_payload(decode=True)
            charset = part.get_content_charset() or "utf-8"
            body = raw.decode(charset, errors="replace") if isinstance(raw, bytes) else str(raw or "")
        except Exception:
            body = ""
        if content_type == "text/plain" and body:
            plain.append(body)
        elif content_type == "text/html" and body:
            html_parts.append(body)
    date_header = str(message.get("Date") or "")
    return {
        "id": str(message.get("Message-ID") or "")[:200],
        "subject": decode(message.get("Subject")),
        "from": decode(message.get("From")),
        "to": decode(message.get("To")),
        "deliveredTo": " ".join(
            decode(message.get(name)) for name in (
                "Delivered-To", "X-Original-To", "Envelope-To", "X-Envelope-To",
            ) if message.get(name)
        ),
        "date": date_header,
        "text": "\n".join(plain),
        "html": "\n".join(html_parts),
    }


def _provider_messages(email: str, source: str) -> list[dict[str, Any]]:
    """Read a bounded set of messages from one configured mailbox provider."""
    target = str(email or "").strip()
    source = str(source or "").strip().lower()
    if not target or not _EMAIL_RE.fullmatch(target):
        raise TeamInviteError("账号邮箱格式无效", code="invalid_email", status=400)

    if source == "icloud":
        from core import icloud_mail_client as client

        account = client.get_account_context(target)
        if account is None:
            raise TeamInviteError("iCloud 邮箱上下文不存在", code="mailbox_unavailable", status=404)
        try:
            rows = client.list_messages(target, limit=min(20, _MESSAGE_SCAN_LIMIT))
        except client.ICloudMailError as exc:
            raise TeamInviteError(
                f"iCloud 邮箱暂时不可用: {type(exc).__name__}",
                code="mailbox_request_failed", status=502, retryable=True,
            ) from exc
        return [
            item for item in (
                _targeted_message(message, target, source=source)
                for message in rows
            ) if item
        ]

    if source == "lof":
        from core import lof_mail_client as client

        payload = client.list_messages(target, limit=100, body=True)
        return [
            item for item in (
                _targeted_message(message, target, source=source)
                for message in _normalise_message_list(payload)
            ) if item
        ]

    if source == "fastmail":
        from core import fastmail_client as client

        session = client._get_session()  # type: ignore[attr-defined]
        account = client.get_account_context(target)
        if account is None:
            account = client.FastmailAccount(
                email=target,
                account_id=client._account_for(session, client.MAIL_CAPABILITY),  # type: ignore[attr-defined]
                api_url=session.api_url,
            )
        rows = client._initial_messages(session, account)  # type: ignore[attr-defined]
        return [
            item for item in (
                _targeted_message(client._message_item(row), target, source=source)  # type: ignore[attr-defined]
                for row in rows
            ) if item
        ]

    if source == "outlook":
        from core import outlook_client as client

        account = client.get_account_context(target)
        if account is None:
            raise TeamInviteError("Outlook 邮箱上下文不存在", code="mailbox_unavailable", status=404)
        http = client._http_session()  # type: ignore[attr-defined]
        rows: list[dict[str, Any]] = []
        try:
            for protocol in ("graph", "imap"):
                try:
                    rows.extend(client._fetch_via(http, protocol, account))  # type: ignore[attr-defined]
                except Exception:
                    # One transport failing should not hide a message returned
                    # by the other transport.
                    continue
        finally:
            try:
                http.close()
            except Exception:
                pass
        return [
            item for item in (
                _targeted_message(row, target, source=source) for row in rows
            ) if item
        ]

    if source == "mailcom":
        from core import mailcom_client as client

        account = client.get_account_context(target)
        if account is None:
            raise TeamInviteError("Mail.com 邮箱上下文不存在", code="mailbox_unavailable", status=404)
        connection = client._connect(account)  # type: ignore[attr-defined]
        rows: list[dict[str, Any]] = []
        try:
            ids = client._search_message_ids(connection, after_ts=None)  # type: ignore[attr-defined]
            for message_id in reversed(ids):
                message = client._fetch_message(connection, message_id)  # type: ignore[attr-defined]
                if message is not None:
                    rows.append(_mime_message_to_dict(message))
                if len(rows) >= 50:
                    break
        finally:
            client._close(connection)  # type: ignore[attr-defined]
        return [
            item for item in (
                _targeted_message(row, target, source=source) for row in rows
            ) if item
        ]

    if source == "cloudflare":
        from core import cf_temp_mail_client as client

        account = client.get_account_context(target)
        if account is None or not account.jwt:
            raise TeamInviteError("Cloudflare 临时邮箱上下文不存在", code="mailbox_unavailable", status=404)
        rows = client.list_messages(account.jwt, limit=100)
        expanded: list[dict[str, Any]] = []
        for row in rows:
            detail = row
            message_id = client._message_id(row)  # type: ignore[attr-defined]
            if message_id and not client._otp_item(row).get("text") and not client._otp_item(row).get("html"):  # type: ignore[attr-defined]
                detail = {**row, **(client.get_message_detail(account.jwt, message_id) or {})}
            expanded.append(detail)
        return [
            item for item in (
                _targeted_message(row, target, source=source) for row in expanded
            ) if item
        ]

    if source == "cloudflare_domain":
        from core import qqmail_client as client

        connection = client._connect_imap()  # type: ignore[attr-defined]
        try:
            rows = client._search_messages(connection)  # type: ignore[attr-defined]
        finally:
            try:
                connection.logout()
            except Exception:
                pass
        return [
            item for item in (
                _targeted_message(row, target, source=source) for row in rows
            ) if item
        ]

    if source == "generic_api":
        from core import generic_api_mail_client as client

        account = client.get_account_context(target)
        if account is None:
            raise TeamInviteError("通用 API 邮箱上下文不存在", code="mailbox_unavailable", status=404)
        try:
            response = requests.get(
                account.code_url,
                headers={"Accept": "application/json,text/plain,*/*", "User-Agent": "gpt-register/1.0"},
                timeout=20,
                verify=False,
            )
            try:
                payload = response.json()
            except Exception:
                payload = {}
            if response.status_code >= 400:
                raise TeamInviteError("通用邮箱 API 请求失败", code="mailbox_request_failed", status=502, retryable=True)
            row = payload.get("message") if isinstance(payload, dict) else None
            if not isinstance(row, dict):
                row = payload.get("mail") if isinstance(payload, dict) else None
            if not isinstance(row, dict):
                row = {
                    "subject": "",
                    "from": "",
                    "to": target,
                    "text": response.text or "",
                    "html": response.text or "",
                }
            return [item for item in (_targeted_message(row, target, source=source),) if item]
        except TeamInviteError:
            raise
        except Exception as exc:
            raise TeamInviteError(
                f"通用邮箱 API 暂时不可用: {type(exc).__name__}",
                code="mailbox_request_failed", status=502, retryable=True,
            ) from exc

    if source == "gptmail":
        from core import gptmail_client as client

        data = client._get("/api/emails", params={"email": target})  # type: ignore[attr-defined]
        rows: list[dict[str, Any]] = []
        for summary in _normalise_message_list(data):
            message_id = str(summary.get("id") or "").strip()
            detail = client._get(f"/api/email/{message_id}") if message_id else summary  # type: ignore[attr-defined]
            rows.append({**summary, **(detail if isinstance(detail, dict) else {})})
        return [item for item in (_targeted_message(row, target, source=source) for row in rows) if item]

    if source == "mailnest":
        from core import mailnest_client as client

        rows = client._get_mails(target)  # type: ignore[attr-defined]
        return [item for item in (_targeted_message(row, target, source=source) for row in _normalise_message_list(rows)) if item]

    if source == "cloudmail":
        from core import cloudmail_client as client

        rows = client._request(
            "/api/public/emailList",
            {"toEmail": target, "timeSort": "desc", "type": 0, "isDel": 0, "num": 1, "size": 100},
        )
        return [item for item in (_targeted_message(row, target, source=source) for row in _normalise_message_list(rows)) if item]

    raise TeamInviteError(
        f"邮箱来源 {source or 'unknown'} 暂不支持读取 Team 邀请",
        code="unsupported_mail_source", status=400,
    )


def fetch_latest_mail_message(email: str, source: str | None = None) -> dict[str, Any] | None:
    """Fetch the newest message for an account's exact recipient address."""
    target = str(email or "").strip()
    if not target:
        raise TeamInviteError("账号邮箱为空", code="invalid_email", status=400)
    if source is None:
        from core.email_provider import resolve_email_source

        source = resolve_email_source(target)
    rows = _provider_messages(target, str(source or ""))
    if not rows:
        return None
    rows.sort(key=lambda item: _message_timestamp(item) or float("-inf"), reverse=True)
    return rows[0]


def _decode_url_candidate(raw: Any) -> str:
    value = html_lib.unescape(str(raw or "")).strip()
    for _ in range(3):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def _tracking_unwrap(raw_url: str, *, depth: int = 0, seen: set[str] | None = None) -> tuple[str, str] | None:
    if depth > 3:
        return None
    seen = seen or set()
    candidate = _decode_url_candidate(raw_url).rstrip(".,;:!?)]}>\"'")
    if not candidate or candidate in seen:
        return None
    seen.add(candidate)
    try:
        parsed = urlparse(candidate)
        # Accessing ``port`` can itself raise ValueError for malformed URLs.
        port = parsed.port
        host = str(parsed.hostname or "").lower().rstrip(".")
        username = parsed.username
        password = parsed.password
    except ValueError:
        return None
    path = unquote(str(parsed.path or "")).lower().rstrip("/") or "/"
    if parsed.scheme.lower() != "https" or not host or username or password or port:
        return None
    query_keys = {str(key).strip().lower() for key, _value in parse_qsl(parsed.query, keep_blank_values=True)}
    is_direct_invite = host in _ALLOWED_INVITE_HOSTS and (
        bool(_INVITE_PATH_RE.search(path))
        or bool(query_keys & _INVITE_QUERY_KEYS)
    )
    if is_direct_invite:
        return candidate, "direct"
    # Mandrill/similar redirect links, and auth URLs that carry an invite in a
    # ``next``/``return_to`` parameter, are accepted only when their decoded
    # destination is itself a valid ChatGPT invite URL.  Relative destinations
    # are resolved against the current official host; no external destination
    # is ever navigated directly.
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if str(key).strip().lower() not in _TRACKING_QUERY_KEYS:
            continue
        nested_value = _decode_url_candidate(value)
        if nested_value.startswith("/") and not nested_value.startswith("//"):
            nested_value = f"https://{host}{nested_value}"
        elif nested_value.startswith("//"):
            nested_value = f"https:{nested_value}"
        nested = _tracking_unwrap(nested_value, depth=depth + 1, seen=seen)
        if nested:
            return nested[0], "tracking"

    # Some mail systems put the destination in a JSON-like tracking payload
    # instead of a named query parameter.  Recurse only over URL-shaped values
    # and run the same strict official-host/path validation on each one.  We do
    # not attempt opaque base64 decoding because it cannot be safely validated
    # without trusting an unbounded payload format.
    if any(marker in host for marker in _TRACKING_HOST_MARKERS):
        for _key, value in parse_qsl(parsed.query, keep_blank_values=True):
            for nested_raw in _URL_RE.findall(_decode_url_candidate(value).replace("\\/", "/")):
                nested = _tracking_unwrap(nested_raw, depth=depth + 1, seen=seen)
                if nested:
                    return nested[0], "tracking"
    return None


def _iter_url_candidates(message: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in (
        "subject", "text", "body", "bodyText", "bodyPreview", "content", "html",
        "html_content", "bodyHtml", "preview", "snippet", "links", "link", "url", "href",
        "invite_url", "inviteUrl", "action_url", "actionUrl", "cta_url", "ctaUrl",
        "web_url", "webUrl", "redirect_url", "redirectUrl", "next", "return_to", "returnTo",
    ):
        value = message.get(key)
        if value not in (None, ""):
            flattened = _flatten_text(value)
            if flattened:
                values.append(flattened)
    # Keep the raw HTML and decoded text; href attributes are included by the
    # generic URL regex after entity decoding.
    # JSON/MIME encoders often escape slashes as ``https:\/\/...``.
    joined = html_lib.unescape("\n".join(values)).replace("\\/", "/")
    return _URL_RE.findall(joined)


def _invite_candidates(message: dict[str, Any]) -> list[tuple[int, str, str]]:
    """Return validated invite URLs in *message*, ordered by trust.

    URL extraction is intentionally independent from recipient validation.  It
    lets the multi-message scanner distinguish an ordinary non-invite mail
    from a real invite delivered to the wrong address, which must be rejected
    rather than silently accepted.
    """
    candidates: list[tuple[int, str, str]] = []
    seen: set[tuple[int, str]] = set()
    for raw in _iter_url_candidates(message):
        unwrapped = _tracking_unwrap(raw)
        if not unwrapped:
            continue
        url, kind = unwrapped
        score = 0 if kind == "direct" else 1
        key = (score, url)
        if key in seen:
            continue
        seen.add(key)
        candidates.append((score, url, kind))
    candidates.sort(key=lambda item: (item[0], item[1]))
    return candidates


def manual_invite(value: str) -> dict[str, Any]:
    """Validate a supplied link; recipient identity must still come from its loader."""
    if not isinstance(value, str) or len(value) > 8192 or any(c in value for c in "\r\n\x00"):
        raise ValueError("邀请链接格式无效")
    found = _tracking_unwrap(value.strip())
    if not found or not _trusted_protocol_url(found[0]):
        raise ValueError("需要有效的 ChatGPT Team 邀请链接")
    url, kind = found
    return {"url": url, "kind": kind, "fingerprint": hashlib.sha256(url.encode()).hexdigest(),
            "recipient_verified": False}


def extract_invite_link(message: dict[str, Any], expected_email: str) -> dict[str, Any]:
    """Return an in-memory invite link after recipient/host validation."""
    if not isinstance(message, dict):
        raise TeamInviteError("邀请邮件格式无效", code="invite_message_invalid", status=502)
    target = _email_key(expected_email)
    if not _EMAIL_RE.fullmatch(target):
        raise TeamInviteError("账号邮箱格式无效", code="invalid_email", status=400)

    recipients = _message_recipients(message)
    targeted = _email_key(message.get("_team_target_email"))
    recipient_verified = target in recipients if recipients else targeted == target
    if recipients and target not in recipients:
        raise TeamInviteError(
            "邀请邮件收件人不是当前账号，已拒绝处理",
            code="wrong_recipient", status=409,
        )
    if not recipient_verified:
        raise TeamInviteError(
            "邀请邮件缺少可验证的收件人地址，已拒绝自动接受",
            code="recipient_unverified", status=409,
        )

    candidates = _invite_candidates(message)
    if not candidates:
        raise TeamInviteError(
            "邮件中没有找到有效的 ChatGPT Team 邀请链接",
            code="invite_not_found", status=404, retryable=True,
        )
    _score, url, kind = candidates[0]
    return {
        "url": url,
        "kind": kind,
        "fingerprint": hashlib.sha256(url.encode("utf-8")).hexdigest(),
        "recipient_verified": True,
    }


def find_invite_message(
    email: str,
    source: str | None = None,
    *,
    diagnostics: dict[str, int] | None = None,
    excluded_fingerprints: set[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Find the newest valid invitation among a bounded recent-mail window.

    A mailbox can receive a later login/marketing message after the Team
    invitation.  Looking at only the newest message made the button report
    ``未找到邀请`` even though the invitation was still present.  We scan the
    provider's bounded result set newest-first and retain the strict recipient
    checks performed by :func:`extract_invite_link`.
    """
    target = str(email or "").strip()
    if not target:
        raise TeamInviteError("账号邮箱为空", code="invalid_email", status=400)
    if source is None:
        from core.email_provider import resolve_email_source

        source = resolve_email_source(target)
    rows = _provider_messages(target, str(source or ""))
    if diagnostics is not None:
        diagnostics.update(message_count=len(rows), scanned_count=0)
    indexed = list(enumerate(rows))
    indexed.sort(
        key=lambda pair: (_message_timestamp(pair[1]) is not None,
                          _message_timestamp(pair[1]) or float("-inf"),
                          -pair[0]),
        reverse=True,
    )
    for _index, message in indexed[:_MESSAGE_SCAN_LIMIT]:
        if diagnostics is not None:
            diagnostics["scanned_count"] += 1
        # Avoid raising recipient errors for ordinary unrelated messages.  If
        # this message does contain a valid invite, extract_invite_link will
        # raise the explicit wrong-recipient/unverified error instead.
        if not _invite_candidates(message):
            continue
        invite = extract_invite_link(message, target)
        if excluded_fingerprints and invite["fingerprint"] in excluded_fingerprints:
            # A single mail may contain more than one valid invitation link.
            for _score, url, kind in _invite_candidates(message):
                fingerprint = hashlib.sha256(url.encode("utf-8")).hexdigest()
                if fingerprint not in excluded_fingerprints:
                    return message, {**invite, "url": url, "kind": kind, "fingerprint": fingerprint}
            continue
        return message, invite
    return None


def wait_for_invite_message(
    email: str,
    source: str | None = None,
    *,
    timeout: float | None = None,
    poll_interval: float | None = None,
    diagnostics: dict[str, int] | None = None,
    excluded_fingerprints: set[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Poll briefly so mailbox ingestion lag does not become a false miss."""
    wait_seconds = _MAIL_WAIT_TIMEOUT if timeout is None else max(0.0, float(timeout))
    interval = (
        _MAIL_POLL_INTERVAL
        if poll_interval is None
        else max(0.1, float(poll_interval))
    )
    deadline = time.monotonic() + wait_seconds
    attempts = 0
    last_retryable_error: TeamInviteError | None = None
    while True:
        attempts += 1
        try:
            scan: dict[str, int] = {}
            found = find_invite_message(email, source=source, diagnostics=scan,
                                        **({"excluded_fingerprints": excluded_fingerprints} if excluded_fingerprints else {}))
            if diagnostics is not None and scan:
                diagnostics.update(scan)
                diagnostics["poll_attempts"] = attempts
                diagnostics["max_message_count"] = max(
                    diagnostics.get("max_message_count", 0), scan["message_count"],
                )
                diagnostics["max_scanned_count"] = max(
                    diagnostics.get("max_scanned_count", 0), scan["scanned_count"],
                )
            last_retryable_error = None
        except TeamInviteError as exc:
            if not exc.retryable:
                raise
            found = None
            last_retryable_error = exc
            logger.warning(
                "[Team] 邮箱临时失败，继续等待: email=%s attempt=%s code=%s",
                email,
                attempts,
                exc.code,
            )
        if found is not None:
            if attempts > 1:
                logger.info(
                    "[Team] 等待邮件后找到邀请: email=%s attempts=%s",
                    email, attempts,
                )
            return found
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if last_retryable_error is not None:
                raise last_retryable_error
            return None
        time.sleep(min(interval, remaining))


def _no_invite_result(diagnostics: dict[str, int]) -> dict[str, Any]:
    count = diagnostics.get("max_message_count")
    if count is None:
        message = "未找到 Team 邀请邮件"
    elif count == 0:
        message = "邮箱接口未返回邮件，未找到 Team 邀请"
    else:
        scanned = diagnostics.get("max_scanned_count", count)
        message = f"本次轮询最多取回 {count} 封邮件、扫描 {scanned} 封，未识别到 Team 邀请链接"
    if diagnostics.get("poll_attempts"):
        message += f"（查询 {diagnostics['poll_attempts']} 次）"
    return {
        "status": "no_invite", "message": message, "error": message,
        "error_code": "invite_not_found", "retryable": True,
        "checked_at": _now_iso(), "recipient_verified": False,
    }


def _browser_auth_state(driver, *, refresh: bool = False) -> dict[str, Any]:
    path = "/api/auth/session?refresh=true" if refresh else "/api/auth/session"
    script = r"""
    const done = arguments[0];
    const path = arguments[1];
    const host = String(location.hostname || '').toLowerCase();
    const sameChatGPT = host === 'chatgpt.com' || host.endsWith('.chatgpt.com');
    const endpoint = sameChatGPT ? path : `https://chatgpt.com${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    fetch(endpoint, {method:'GET', credentials:'include', cache:'no-store',
      headers:{'Accept':'application/json'}, signal:controller.signal})
      .then(async response => {
        let data = null;
        try { data = await response.json(); } catch (_) {}
        done({status: response.status, data});
      })
      .catch(error => done({status: 0, error: String(error)}))
      .finally(() => clearTimeout(timer));
    """
    try:
        result = driver.execute_async_script(script, path)
    except Exception as exc:
        return {"status": 0, "error": type(exc).__name__}
    return result if isinstance(result, dict) else {"status": 0}


def _page_snapshot(driver) -> dict[str, Any]:
    try:
        from core.roxy_registration import _page_snapshot as snapshot

        value = snapshot(driver)
        return value if isinstance(value, dict) else {}
    except Exception:
        try:
            value = driver.execute_script(
                "return {url: location.href, title: document.title || '', text: (document.body && document.body.innerText) || ''};"
            )
            return value if isinstance(value, dict) else {}
        except Exception:
            return {"url": str(getattr(driver, "current_url", "") or "")}


def _navigate(driver, url: str) -> dict[str, Any]:
    from core.roxy_registration import _navigate_page

    value = _navigate_page(driver, url, timeout=max(10, int(_INVITE_TIMEOUT)))
    return value if isinstance(value, dict) else {}


def _find_invite_action(driver) -> Any | None:
    script = r"""
    const visible = el => !!el && !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true'
      && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
    const positive = ['accept','join','continue','get started','加入','接受','同意','开始使用','继续'];
    const negative = ['decline','reject','cancel','leave','退出','拒绝','取消','logout',
      'google','apple','microsoft','github','facebook','sso','oauth','saml','oidc','passkey','social'];
    const textOf = el => String(el.innerText || el.value || el.getAttribute('aria-label') || '').trim().toLowerCase();
    const nodes = [...document.querySelectorAll('button,a,[role="button"],input[type="submit"],input[type="button"]')];
    let best = null; let bestScore = -1;
    for (const el of nodes) {
      if (!visible(el)) continue;
      const text = textOf(el);
      if (!text || negative.some(word => text.includes(word))) continue;
      const score = positive.reduce((n, word) => n + (text.includes(word) ? 2 : 0), 0)
        + (String(el.getAttribute('type') || '').toLowerCase() === 'submit' ? 1 : 0);
      if (score > bestScore) { best = el; bestScore = score; }
    }
    return bestScore > 0 ? best : null;
    """
    try:
        return driver.execute_script(script)
    except Exception:
        return None


def _click_element(driver, element) -> bool:
    if element is None:
        return False
    try:
        from core.roxy_registration import _human_click

        _human_click(driver, element, label="team_invite_accept")
        return True
    except Exception:
        try:
            element.click()
            return True
        except Exception:
            return False


def _page_text(snapshot: dict[str, Any]) -> str:
    return str(snapshot.get("text") or "").replace("\u00a0", " ").strip().lower()


def _is_login_page(snapshot: dict[str, Any]) -> bool:
    url = str(snapshot.get("url") or "").lower()
    return "/auth/login" in url or (
        "/login" in url and ("chatgpt.com" in url or "auth.openai.com" in url)
    )


def _classify_page_error(text: str) -> tuple[str, str] | None:
    if any(marker in text for marker in _INVITE_EXPIRED_HINTS):
        return "expired", "邀请已过期、撤销或当前工作区没有可用席位"
    if any(marker in text for marker in _INVITE_PENDING_HINTS):
        return "needs_acceptance", "邀请需要管理员批准，当前尚未进入 Team"
    return None


def _cookie_value(cookies: list[dict[str, Any]], name: str) -> str:
    wanted = str(name or "").lower()
    for cookie in cookies:
        if str(cookie.get("name") or "").lower() == wanted:
            return str(cookie.get("value") or "")
    return ""


def _decode_workspace_cookie(value: str) -> dict[str, Any]:
    raw = unquote(str(value or "")).split(".", 1)[0]
    if not raw:
        return {}
    try:
        raw += "=" * (-len(raw) % 4)
        payload = json.loads(base64.urlsafe_b64decode(raw.encode("ascii")))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


_TEAM_STRUCTURE_VALUES = frozenset({
    "team", "business", "enterprise", "organization", "org", "team_workspace",
})
_WORKSPACE_ID_KEYS = (
    "workspace_id", "workspaceId", "team_id", "teamId", "organization_id",
    "organizationId", "org_id", "orgId",
)
_ACCOUNT_ID_KEYS = ("account_id", "accountId", "id")
_WORKSPACE_CONTEXT_SEGMENTS = frozenset({
    "workspace", "workspaces", "team", "teams", "organization", "organizations",
    "org", "orgs", "business", "businesses",
})
_TEAM_CONTEXT_SEGMENTS = frozenset({
    "team", "teams", "organization", "organizations", "org", "orgs",
    "business", "businesses",
})


def _context_has_segment(context: str, segments: frozenset[str]) -> bool:
    """Match path keys by segment, not substring (``workspace`` != ``workspaces``)."""
    tokens = set(re.findall(r"[a-z0-9]+", str(context or "").lower()))
    return bool(tokens & segments)


def _state_email(state: dict[str, Any]) -> str:
    """Return an auth-session email, if the endpoint exposes one."""
    data = state.get("data") if isinstance(state.get("data"), dict) else {}
    candidates: list[Any] = [data]
    for key in ("user", "account", "profile"):
        value = data.get(key)
        if isinstance(value, dict):
            candidates.append(value)
    for item in candidates:
        for key in ("email", "emailAddress", "username"):
            value = _email_key(item.get(key)) if isinstance(item, dict) else ""
            if _EMAIL_RE.fullmatch(value):
                return value
    return ""


def _structure_value(item: dict[str, Any]) -> str:
    for key in ("structure", "workspace_structure", "workspaceStructure", "type", "kind", "planType", "plan_type"):
        value = str(item.get(key) or "").strip().lower()
        if value:
            return value
    return ""


def _record_team_like(item: dict[str, Any], context: str) -> bool:
    structure = _structure_value(item)
    if structure in _TEAM_STRUCTURE_VALUES or any(
        marker in structure for marker in ("team", "business", "enterprise", "organization", "org")
    ):
        return True
    for key in ("is_team", "isTeam", "team", "is_business", "isBusiness", "business"):
        value = item.get(key)
        if isinstance(value, bool) and value:
            return True
        if str(value or "").strip().lower() in {"team", "business", "true", "1"}:
            return True
    # A generic ``workspaces[]`` container can contain the personal workspace
    # as well as Team workspaces.  Only explicitly Team-shaped path segments
    # count here; a newly-added generic workspace is promoted by
    # ``_workspace_evidence`` after an accept/join click.
    return _context_has_segment(context, _TEAM_CONTEXT_SEGMENTS)


def _workspace_records(value: Any) -> list[dict[str, Any]]:
    """Collect workspace/team records without treating personal account IDs as workspaces."""
    records: list[dict[str, Any]] = []

    def visit(node: Any, context: str = "") -> None:
        if isinstance(node, dict):
            context_text = str(context or "").lower()
            explicit_id = ""
            for key in _WORKSPACE_ID_KEYS:
                candidate = str(node.get(key) or "").strip()
                if candidate:
                    explicit_id = candidate
                    break
            generic_id = str(node.get("id") or "").strip()
            id_value = explicit_id or (
                generic_id
                if context_text and _context_has_segment(context_text, _WORKSPACE_CONTEXT_SEGMENTS)
                else ""
            )
            structure = _structure_value(node)
            team_like = _record_team_like(node, context_text)
            if id_value and (
                explicit_id
                or team_like
                or _context_has_segment(context_text, _WORKSPACE_CONTEXT_SEGMENTS)
            ):
                name = ""
                for key in ("workspace_name", "workspaceName", "team_name", "teamName", "display_name", "displayName", "name"):
                    candidate = str(node.get(key) or "").strip()
                    if candidate:
                        name = candidate[:200]
                        break
                records.append({
                    "id": id_value[:200],
                    "name": name,
                    "structure": structure[:80],
                    "team_like": bool(team_like),
                })
            for key, child in node.items():
                child_context = f"{context}/{str(key).strip().lower()}"
                if isinstance(child, (dict, list)):
                    visit(child, child_context)
            return
        if isinstance(node, list):
            for index, child in enumerate(node):
                visit(child, f"{context}/{index}")

    visit(value)
    merged: dict[str, dict[str, Any]] = {}
    for record in records:
        key = str(record.get("id") or "")
        if not key:
            continue
        current = merged.get(key)
        if current is None:
            merged[key] = record
        else:
            if not current.get("name") and record.get("name"):
                current["name"] = record["name"]
            current["team_like"] = bool(current.get("team_like") or record.get("team_like"))
            if not current.get("structure") and record.get("structure"):
                current["structure"] = record["structure"]
    return list(merged.values())


def _item_id(item: dict[str, Any], keys: tuple[str, ...] = _ACCOUNT_ID_KEYS) -> str:
    for key in keys:
        value = str(item.get(key) or "").strip()
        if value:
            return value[:200]
    return ""


def _workspace_evidence(
    state: dict[str, Any],
    cookies: list[dict[str, Any]],
    before: dict[str, Any],
    before_cookies: list[dict[str, Any]],
    page_text: str,
    clicked: int,
) -> dict[str, Any]:
    """Extract structural workspace evidence; never return token values.

    ChatGPT's auth session commonly keeps the personal account in
    ``data.account.id`` even after a Team invitation adds a separate entry to
    ``workspaces[]``.  Only explicit workspace/team records (or a changed
    ``_account`` cookie that is not a known personal ID) are eligible as the
    Team workspace ID.
    """
    after_data = state.get("data") if isinstance(state.get("data"), dict) else {}
    before_data = before.get("data") if isinstance(before.get("data"), dict) else {}
    account = after_data.get("account") if isinstance(after_data.get("account"), dict) else {}
    before_account = before_data.get("account") if isinstance(before_data.get("account"), dict) else {}
    structure = _structure_value(account) or _structure_value(after_data)
    before_structure = _structure_value(before_account) or _structure_value(before_data)

    account_id = _item_id(account)
    before_account_id = _item_id(before_account)
    account_cookie = _cookie_value(cookies, "_account")
    before_account_cookie = _cookie_value(before_cookies, "_account")
    cookie_payload = _decode_workspace_cookie(_cookie_value(cookies, "oai-client-auth-session"))
    before_cookie_payload = _decode_workspace_cookie(_cookie_value(before_cookies, "oai-client-auth-session"))

    def merge_records(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        for group in groups:
            for item in group:
                key = str(item.get("id") or "").strip()
                if not key:
                    continue
                current = merged.get(key)
                if current is None:
                    merged[key] = dict(item)
                    continue
                current["team_like"] = bool(current.get("team_like") or item.get("team_like"))
                if not current.get("name") and item.get("name"):
                    current["name"] = item["name"]
                if not current.get("structure") and item.get("structure"):
                    current["structure"] = item["structure"]
        return list(merged.values())

    after_records = merge_records(_workspace_records(after_data), _workspace_records(cookie_payload))
    before_records = merge_records(_workspace_records(before_data), _workspace_records(before_cookie_payload))
    after_by_id = {str(item["id"]): item for item in after_records if item.get("id")}
    before_by_id = {str(item["id"]): item for item in before_records if item.get("id")}
    before_known_ids = set(before_by_id) | {value for value in (before_account_id, before_account_cookie) if value}

    cookie_record = after_by_id.get(account_cookie) if account_cookie else None
    # ``_account`` normally identifies the personal account.  Use it as the
    # active workspace only when the record is explicitly Team-shaped or the
    # cookie changed to a newly-added ID; otherwise prefer a Team/new record.
    active_record = (
        cookie_record
        if cookie_record and (
            cookie_record.get("team_like") or account_cookie not in before_known_ids
        )
        else None
    )
    team_records = [item for item in after_records if item.get("team_like")]
    new_records = [item for item in after_records if str(item.get("id") or "") not in before_known_ids]
    if active_record is None:
        active_record = next((item for item in new_records if item.get("team_like")), None)
    # A successful invite can add a workspace record whose API payload only
    # contains ``id``/``name`` (no ``structure`` or ``type`` marker).  Once an
    # accept/join action was actually clicked, a *new* record is still strong
    # structural evidence and should be selected as the workspace.  Without
    # this fallback we could report ``workspace_changed`` while returning an
    # empty workspace ID, which in turn prevents the session-token exchange.
    if active_record is None and clicked > 0 and new_records:
        active_record = new_records[0]
    if active_record is None and team_records:
        active_record = team_records[0]

    workspace_id = str(active_record.get("id") or "").strip() if active_record else ""
    if not workspace_id:
        for item in (account, after_data):
            explicit = _item_id(item, _WORKSPACE_ID_KEYS)
            if explicit:
                workspace_id = explicit
                break
    if not workspace_id and structure in _TEAM_STRUCTURE_VALUES and (
        not before_account_id or account_id != before_account_id
    ):
        # Some session payloads expose the current Team account as ``id``. Do
        # not reuse an unchanged personal account ID as a workspace ID.
        workspace_id = account_id or _item_id(after_data)
    if not workspace_id and account_cookie and account_cookie not in before_known_ids and clicked > 0:
        workspace_id = account_cookie

    workspace_name = str((active_record or {}).get("name") or "").strip()[:200]
    if not workspace_name:
        for item in (account, after_data):
            for key in ("workspace_name", "workspaceName", "team_name", "teamName", "display_name", "displayName"):
                candidate = str(item.get(key) or "").strip()
                if candidate:
                    workspace_name = candidate[:200]
                    break
            if workspace_name:
                break

    workspace_changed = bool(
        (workspace_id and workspace_id not in before_known_ids)
        or (account_cookie and before_account_cookie and account_cookie != before_account_cookie and account_cookie != before_account_id)
        or (set(after_by_id) != set(before_by_id) and bool(new_records))
        or (structure in _TEAM_STRUCTURE_VALUES and before_structure != structure)
    )
    page_lower = str(page_text or "").lower()
    team_like = bool(
        (active_record and active_record.get("team_like"))
        or structure in _TEAM_STRUCTURE_VALUES
        or any(marker in page_lower for marker in ("team workspace", "business workspace", "team plan", "团队工作区", "团队空间", "团队成员"))
        or (clicked > 0 and bool(new_records) and bool(workspace_id))
    )
    explicit_success = any(marker in page_lower for marker in _INVITE_SUCCESS_HINTS)
    explicit_already = any(marker in page_lower for marker in _INVITE_ALREADY_HINTS)
    strong = bool(
        (explicit_already and (team_like or clicked > 0))
        or (explicit_success and team_like)
        or (clicked > 0 and workspace_changed and bool(workspace_id))
        # Some invitation links accept immediately on navigation and do not
        # render an actionable button.  A fresh, explicitly Team-shaped
        # workspace in /api/auth/session (for example account.organizationId
        # plus a Team planType) is sufficient confirmation in that case.
        or (team_like and workspace_changed and bool(workspace_id))
    )
    session_account_id = _item_id(account, ("account_id", "accountId")) or account_id or workspace_id
    return {
        "workspace_id": workspace_id[:200],
        "workspace_name": workspace_name,
        "session_account_id": session_account_id[:200],
        "workspace_changed": workspace_changed,
        "team_like": team_like,
        "explicit_success": explicit_success,
        "explicit_already": explicit_already,
        "strong": strong,
    }


def _exchange_workspace_token(driver, workspace_id: str) -> bool:
    if not workspace_id:
        return False
    script = r"""
    const done = arguments[0];
    const workspace = encodeURIComponent(String(arguments[1] || ''));
    const url = `/api/auth/session?exchange_workspace_token=true&workspace_id=${workspace}&reason=join_team_invite`;
    fetch(url, {method:'GET', credentials:'include', cache:'no-store', headers:{'Accept':'application/json'}})
      .then(async r => { let data = null; try { data = await r.json(); } catch (_) {} done({status:r.status, data}); })
      .catch(() => done({status:0}));
    """
    try:
        result = driver.execute_async_script(script, workspace_id)
        return isinstance(result, dict) and int(result.get("status") or 0) == 200 and bool(
            isinstance(result.get("data"), dict) and result["data"].get("accessToken")
        )
    except Exception:
        return False


def _protocol_get(
    env: BrowserSession, url: str, *, stage: str, attempts: int | None = None, **kwargs,
):
    label, code = {
        "session": ("协议会话校验", "protocol_session_failed"),
        "invite": ("协议访问邀请", "protocol_request_failed"),
    }[stage]
    total_attempts = _PROTOCOL_READ_ATTEMPTS if attempts is None else max(1, min(5, attempts))
    for attempt in range(1, total_attempts + 1):
        try:
            return env.session.get(url, **kwargs)
        except Exception as exc:
            retryable = is_retryable_network_error(exc)
            if not retryable or attempt >= total_attempts:
                raise TeamInviteError(
                    f"{label}失败: {type(exc).__name__}（尝试 {attempt} 次）",
                    code=code, status=502, retryable=retryable,
                ) from exc
            logger.warning(
                "[Team][协议] 网络读取重试: stage=%s attempt=%s/%s error=%s",
                stage, attempt, total_attempts, type(exc).__name__,
            )
            time.sleep(_PROTOCOL_ACCEPT_BACKOFF * attempt)


def _protocol_session_state(
    env: BrowserSession,
    *,
    refresh: bool = False,
    workspace_id: str = "",
    attempts: int | None = None,
) -> dict[str, Any]:
    """Read a ChatGPT session without returning or logging token values."""
    params: dict[str, str] = {}
    if workspace_id:
        params = {
            "exchange_workspace_token": "true",
            "workspace_id": str(workspace_id),
            "reason": "join_team_invite",
        }
    elif refresh:
        params = {"refresh": "true"}
    response = _protocol_get(
        env,
        _SESSION_URL,
        stage="session",
        attempts=attempts,
        params=params or None,
        headers=_session_headers(env),
        allow_redirects=False,
        timeout=20,
    )
    payload: Any = None
    if int(response.status_code) == 200:
        try:
            payload = response.json()
        except Exception:
            payload = None
    return {
        "status": int(response.status_code),
        "data": payload if isinstance(payload, dict) else {},
    }


def _trusted_protocol_url(value: Any) -> str | None:
    """Validate every redirect hop without exposing the invite URL."""
    candidate = str(value or "").strip()
    try:
        parsed = urlparse(candidate)
        port = parsed.port
    except ValueError:
        return None
    host = str(parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme.lower() != "https"
        or host not in _ALLOWED_INVITE_HOSTS
        or parsed.username
        or parsed.password
        or port
    ):
        return None
    return candidate


def _protocol_navigation_headers(
    env: BrowserSession, referer: str, target_url: str,
) -> dict[str, str]:
    headers = env.get_nextauth_headers(referer or "https://chatgpt.com/")
    headers.pop("content-type", None)
    try:
        source_host = str(urlparse(referer).hostname or "").lower()
        target_host = str(urlparse(target_url).hostname or "").lower()
    except ValueError:
        source_host = target_host = ""
    headers.update({
        "accept": env._navigation_accept(),  # BrowserSession profile-consistent Accept.
        "cache-control": "no-cache",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin" if source_host == target_host else "cross-site",
        "upgrade-insecure-requests": "1",
    })
    return headers


def _protocol_navigate_invite(env: BrowserSession, invite_url: str) -> dict[str, Any]:
    """GET an invite through a bounded, official-host-only redirect chain."""
    current = _trusted_protocol_url(invite_url)
    if not current:
        raise TeamInviteError("邀请链接安全校验失败", code="invite_url_rejected", status=400)
    referer = "https://chatgpt.com/"
    response = None
    redirects = 0
    for _hop in range(_PROTOCOL_REDIRECT_LIMIT + 1):
        response = _protocol_get(
            env, current, stage="invite",
            headers=_protocol_navigation_headers(env, referer, current),
            allow_redirects=False, timeout=25,
        )
        status = int(response.status_code)
        if status not in {301, 302, 303, 307, 308}:
            break
        location = str(response.headers.get("location") or "").strip()
        next_url = _trusted_protocol_url(urljoin(current, location))
        if not next_url:
            raise TeamInviteError(
                "邀请跳转到了非可信地址，已停止协议处理",
                code="invite_redirect_rejected",
                status=409,
            )
        referer, current = current, next_url
        redirects += 1
    else:  # pragma: no cover - loop is explicitly bounded
        response = None
    if response is None or int(response.status_code) in {301, 302, 303, 307, 308}:
        raise TeamInviteError(
            "邀请跳转次数过多",
            code="invite_redirect_limit",
            status=502,
            retryable=True,
        )
    try:
        body = str(response.text or "")[:2_000_000]
    except Exception:
        body = ""
    return {
        "status": int(response.status_code),
        "url": current,
        "text": body.replace("\u00a0", " "),
        "redirects": redirects,
    }


def _protocol_cookie_snapshot(
    original: list[dict[str, Any]], env: BrowserSession,
) -> list[dict[str, Any]]:
    return _merged_cookie_snapshot(original, env.session.cookies.jar)


def _unflatten_router_payload(flat: Any) -> Any:
    """Decode React Router's flattened hydration payload enough for loaders."""
    if not isinstance(flat, list):
        return None
    cache: dict[int, Any] = {}
    resolving: set[int] = set()

    def resolve_ref(value: Any) -> Any:
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, int):
            if value < 0 or value >= len(flat):
                return None
            return resolve_index(value)
        if isinstance(value, dict):
            decoded: dict[str, Any] = {}
            for raw_key, raw_value in value.items():
                key_match = re.fullmatch(r"_(\d+)", str(raw_key))
                key = resolve_index(int(key_match.group(1))) if key_match else raw_key
                if isinstance(key, str):
                    decoded[key] = resolve_ref(raw_value)
            return decoded
        if isinstance(value, list):
            return [resolve_ref(item) for item in value]
        return value

    def resolve_index(index: int) -> Any:
        if index in cache:
            return cache[index]
        if index in resolving:
            return None
        resolving.add(index)
        cache[index] = None
        decoded = resolve_ref(flat[index])
        cache[index] = decoded
        resolving.discard(index)
        return decoded

    return resolve_index(0) if flat else None


def _extract_protocol_invite_context(page_html: str, expected_email: str) -> dict[str, Any] | None:
    """Read the server-validated invite IDs from React Router loader data."""
    candidates: list[Any] = []
    source = str(page_html or "")
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\.enqueue\(", source):
        try:
            serialized, _end = decoder.raw_decode(source[match.end():].lstrip())
            if not isinstance(serialized, str):
                continue
            candidates.append(_unflatten_router_payload(json.loads(serialized.strip())))
        except (TypeError, ValueError, json.JSONDecodeError):
            continue

    matches: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            context = value.get("inviteAuthContext")
            if isinstance(context, dict):
                matches.append({**value, "inviteAuthContext": context})
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    for candidate in candidates:
        visit(candidate)
    expected_key = _email_key(expected_email)
    for loader in matches:
        context = loader["inviteAuthContext"]
        invite_email = _email_key(context.get("email"))
        current_email = _email_key(loader.get("currentUserEmail"))
        accept_workspace_id = str(context.get("acceptWorkspaceId") or "").strip()
        workspace_id = str(context.get("workspaceId") or "").strip()
        if (
            loader.get("isMatchingLoggedInUser") is not True
            or invite_email != expected_key
            or (current_email and current_email != expected_key)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", accept_workspace_id)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", workspace_id)
        ):
            continue
        return {
            "accept_workspace_id": accept_workspace_id,
            "workspace_id": workspace_id,
            "workspace_name": str(context.get("workspaceName") or "").strip()[:200],
            "email_verified": True,
        }
    return None


def _redact_protocol_detail(value: str, secrets: tuple[str, ...]) -> str:
    text = html_lib.unescape(unquote(value)).replace("\\/", "/")
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    text = re.sub(r"(?i)\b(?:cookie|set-cookie|authorization)\s*:[^\r\n]*", "[redacted header]", text)
    text = re.sub(r"(?i)\bBearer\s+[^\s,;]+", "Bearer [redacted]", text)
    text = re.sub(r"(?i)(?:https?|socks5h?)://[^\s<>\"']+", "[redacted URL]", text)
    text = re.sub(r"[^\s<>\"']+@[^\s<>\"']+", "[redacted email]", text)
    text = re.sub(
        r"(?i)\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|password|secret|"
        r"api[_-]?key|invite[_-]?(?:token|id))\b[\"']?\s*[:=]\s*"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)",
        "[redacted credential]", text,
    )
    text = re.sub(r"[A-Za-z0-9_+/=-]{24,}(?:\.[A-Za-z0-9_+/=-]+)*", "[redacted value]", text)
    return " ".join(text.split())[:240]


def _protocol_error_details(payload: Any, *, secrets: tuple[str, ...]) -> tuple[str, str]:
    """Keep bounded error fields only, never raw bodies, headers, or input data."""
    if not isinstance(payload, dict):
        return "", "接口未返回 JSON 错误说明"
    pending = [(payload, 0)]
    code = ""
    messages: list[str] = []
    for _ in range(16):
        if not pending:
            break
        node, depth = pending.pop(0)
        if isinstance(node, str):
            messages.append(node)
        elif isinstance(node, dict):
            for key in ("code", "type", "error_code"):
                raw = node.get(key)
                if (
                    not code and isinstance(raw, str)
                    and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", raw)
                    and not any(secret and secret in raw for secret in secrets)
                ):
                    code = raw
            for key in ("message", "msg", "description", "title"):
                if isinstance(node.get(key), str):
                    messages.append(node[key])
            if depth < 2:
                pending.extend((node[key], depth + 1) for key in ("error", "detail", "errors") if key in node)
        elif isinstance(node, list) and depth < 3:
            pending.extend((item, depth + 1) for item in node[:4])
    details = list(dict.fromkeys(
        _redact_protocol_detail(message, secrets) for message in messages[:8] if message
    ))
    return code, "; ".join(details)[:240] or "接口未返回可识别的错误说明"


def _protocol_submit_accept(
    env: BrowserSession,
    *,
    accept_workspace_id: str,
    access_token: str,
) -> dict[str, Any]:
    route = "/accounts/{account_id}/invites/accept"
    path = f"/accounts/{quote(accept_workspace_id, safe='')}/invites/accept"
    headers = env.get_chatgpt_headers("https://chatgpt.com/accept-invite")
    headers.update({
        "accept": "application/json",
        "authorization": f"Bearer {access_token}",
        "oai-device-id": env.device_id,
        "oai-language": env.navigator_language(),
        "x-openai-target-path": path,
        "x-openai-target-route": route,
    })
    last_status = 0
    last_error_code = ""
    last_detail = ""
    secrets = (access_token, accept_workspace_id)
    try:
        secrets += tuple(cookie.value for cookie in env.session.cookies.jar if cookie.value)
    except (AttributeError, TypeError):
        pass
    for attempt in range(1, _PROTOCOL_ACCEPT_ATTEMPTS + 1):
        try:
            response = env.session.post(
                f"https://chatgpt.com/backend-api{path}",
                headers=headers,
                json={},
                allow_redirects=False,
                timeout=25,
            )
        except Exception as exc:
            retryable = is_retryable_network_error(exc)
            if not retryable or attempt >= _PROTOCOL_ACCEPT_ATTEMPTS:
                raise TeamInviteError(
                    f"协议提交邀请失败: {type(exc).__name__}（尝试 {attempt} 次）",
                    code="protocol_accept_failed", status=502, retryable=retryable,
                ) from exc
            logger.warning(
                "[Team][协议] 接受邀请网络重试: attempt=%s/%s error=%s",
                attempt, _PROTOCOL_ACCEPT_ATTEMPTS, type(exc).__name__,
            )
            time.sleep(_PROTOCOL_ACCEPT_BACKOFF * attempt)
            continue
        last_status = int(response.status_code)
        if last_status in {200, 201, 202, 204}:
            last_error_code, last_detail = "", ""
            break
        payload: Any = None
        try:
            payload = response.json()
        except Exception:
            payload = None
        last_error_code, last_detail = _protocol_error_details(payload, secrets=secrets)
        logger.warning(
            "[Team][协议] 接受邀请响应: attempt=%s/%s status=%s code=%s detail=%s",
            attempt, _PROTOCOL_ACCEPT_ATTEMPTS, last_status,
            last_error_code or "-", last_detail,
        )
        terminal_conflict = any(marker in last_error_code.lower() for marker in (
            "workspace_join_request_pending",
            "workspace_paid_seat_capacity_exhausted",
            "already",
            "member",
        ))
        retryable_conflict = last_status in {408, 409, 425, 429, 500, 502, 503, 504}
        if (
            attempt >= _PROTOCOL_ACCEPT_ATTEMPTS
            or terminal_conflict
            or not retryable_conflict
        ):
            break
        time.sleep(_PROTOCOL_ACCEPT_BACKOFF * attempt)
    return {
        "status": last_status,
        "error_code": last_error_code,
        "error_detail": last_detail,
        "attempt_count": attempt,
    }


def _accept_invite_protocol(
    account: dict[str, Any],
    invite: dict[str, Any],
    expected_email: str,
    cookies: list[dict[str, Any]],
    *, expected_workspace_id: str = "", http_session: BrowserSession | None = None,
) -> dict[str, Any]:
    """Attempt invite acceptance using only HTTP and verify the resulting session."""
    # Team invitations are often processed long after registration.  The
    # account's saved ``proxy_used`` can therefore contain an expired sticky
    # session.  Pure-protocol Team recovery does not need registration-exit
    # affinity, so draw a fresh entry from the current proxy pool per task.
    from config import proxy as proxy_cfg

    selected_proxy = str(proxy_cfg.pick_proxy() or "").strip() if http_session is None else ""
    env: BrowserSession | None = None
    original = normalize_cookies(cookies, source="team_invite_protocol")
    if not original or not has_session_cookie(original):
        raise TeamInviteError(
            "该账号没有有效的 ChatGPT session Cookie",
            code="web_cookies_missing",
            status=400,
        )
    try:
        env = http_session if http_session is not None else BrowserSession(proxy=selected_proxy, detect_exit_geo=False)
        if http_session is None:
            _seed_cookie_jar(env, original)
        before_state = _protocol_session_state(env)
        if int(before_state.get("status") or 0) != 200:
            return {
                "status": "session_required",
                "message": "保存的 Cookie 登录态已失效或被当前出口拒绝",
                "error": "保存的 Cookie 登录态已失效或被当前出口拒绝",
                "error_code": "cookie_session_invalid",
                "retryable": int(before_state.get("status") or 0) in {403, 408, 425, 429},
                "cookies": _protocol_cookie_snapshot(original, env),
            }
        expected_key = _email_key(expected_email)
        session_email = _state_email(before_state)
        if not session_email:
            return {
                "status": "wrong_account",
                "message": "协议登录态未返回可验证邮箱，已停止接受邀请",
                "error": "协议登录态未返回可验证邮箱，已停止接受邀请",
                "error_code": "session_identity_unverified",
                "retryable": False,
                "cookies": _protocol_cookie_snapshot(original, env),
            }
        if expected_key and session_email != expected_key:
            return {
                "status": "wrong_account",
                "message": "保存的 Cookie 登录态与所选账号不一致，已停止接受邀请",
                "error": "保存的 Cookie 登录态与所选账号不一致，已停止接受邀请",
                "error_code": "session_account_mismatch",
                "retryable": False,
                "cookies": _protocol_cookie_snapshot(original, env),
            }
        before_cookies = _protocol_cookie_snapshot(original, env)
        page = _protocol_navigate_invite(env, str(invite.get("url") or ""))
        page_text = str(page.get("text") or "")
        page_url = str(page.get("url") or "").lower()
        page_status = int(page.get("status") or 0)
        if "/auth/login" in page_url or (
            "/login" in page_url and urlparse(page_url).hostname in _ALLOWED_INVITE_HOSTS
        ):
            return {
                "status": "session_required",
                "message": "邀请链接要求重新登录，当前 Cookie 登录态不足",
                "error": "邀请链接要求重新登录，当前 Cookie 登录态不足",
                "error_code": "session_required",
                "retryable": False,
                "cookies": _protocol_cookie_snapshot(original, env),
            }
        page_error = _classify_page_error(page_text.lower())
        if page_error:
            status, message = page_error
            return {
                "status": status,
                "message": message,
                "error": message,
                "error_code": "invite_expired" if status == "expired" else "admin_approval_pending",
                "retryable": status != "expired",
                "cookies": _protocol_cookie_snapshot(original, env),
            }
        if page_status in {401, 403}:
            return {
                "status": "session_required",
                "message": "协议邀请请求被登录态或风控拒绝",
                "error": "协议邀请请求被登录态或风控拒绝",
                "error_code": "protocol_request_blocked",
                "retryable": page_status == 403,
                "cookies": _protocol_cookie_snapshot(original, env),
            }
        if page_status in {408, 425, 429} or page_status >= 500:
            raise TeamInviteError(
                f"协议邀请请求 HTTP {page_status}",
                code="protocol_request_failed",
                status=502,
                retryable=True,
            )

        invite_context = _extract_protocol_invite_context(page_text, expected_email)
        if invite_context is None:
            return {
                "status": "needs_acceptance",
                "message": "邀请页没有返回可验证的协议接受参数；请改用 Roxy 补 Team",
                "error": "协议未能读取邀请接受参数，需要使用 Roxy 补 Team",
                "error_code": "protocol_context_missing",
                "retryable": True,
                "cookies": _protocol_cookie_snapshot(original, env),
            }
        if expected_workspace_id and invite_context["workspace_id"] != expected_workspace_id:
            raise TeamInviteError("邀请属于其他工作区，未接受该邀请", code="invite_workspace_mismatch", status=409)
        before_data = before_state.get("data") if isinstance(before_state.get("data"), dict) else {}
        access_token = str(before_data.get("accessToken") or "").strip()
        if not access_token:
            return {
                "status": "session_required",
                "message": "当前 Cookie Session 没有可用于接受邀请的访问令牌",
                "error": "当前 Cookie Session 没有可用于接受邀请的访问令牌",
                "error_code": "session_access_token_missing",
                "retryable": True,
                "cookies": _protocol_cookie_snapshot(original, env),
            }
        try:
            # The service frequently returns HTTP 409 when several members of
            # one Team accept concurrently. Mail/session preparation remains
            # parallel, but membership writes for the same workspace are
            # serialized and briefly cooled down before the next member.
            with _protocol_accept_lock(str(invite_context.get("workspace_id") or "")):
                accept_response = _protocol_submit_accept(
                    env,
                    accept_workspace_id=str(invite_context["accept_workspace_id"]),
                    access_token=access_token,
                )
                if (
                    int(accept_response.get("status") or 0)
                    in {200, 201, 202, 204}
                    and _PROTOCOL_ACCEPT_COOLDOWN > 0
                ):
                    time.sleep(_PROTOCOL_ACCEPT_COOLDOWN)
        except TeamInviteError:
            raise
        except Exception as exc:
            raise TeamInviteError(
                f"协议提交邀请失败: {type(exc).__name__}",
                code="protocol_accept_failed",
                status=502,
                retryable=is_retryable_network_error(exc),
            ) from exc
        accept_status = int(accept_response.get("status") or 0)
        accept_error = str(accept_response.get("error_code") or "").lower()
        accept_detail = str(accept_response.get("error_detail") or "")
        detail_suffix = f"；接口说明：{accept_detail}" if accept_detail else ""
        if accept_status not in {200, 201, 202, 204}:
            if "workspace_join_request_pending" in accept_error:
                return {
                    "status": "needs_acceptance",
                    "message": "Team 加入请求正在等待管理员批准",
                    "error": "Team 加入请求正在等待管理员批准",
                    "error_code": "workspace_join_request_pending",
                    "retryable": True,
                    "cookies": _protocol_cookie_snapshot(original, env),
                }
            if "workspace_paid_seat_capacity_exhausted" in accept_error:
                return {
                    "status": "needs_acceptance",
                    "message": "Team 付费席位已满，无法直接接受邀请",
                    "error": "Team 付费席位已满，无法直接接受邀请",
                    "error_code": "workspace_paid_seat_capacity_exhausted",
                    "retryable": True,
                    "cookies": _protocol_cookie_snapshot(original, env),
                }
            if "already" in accept_error or "member" in accept_error:
                return {
                    "status": "already_member",
                    "message": "账号已经是该 Team 成员",
                    "workspace_id": invite_context.get("workspace_id"),
                    "workspace_name": invite_context.get("workspace_name"),
                    "session_refreshed": False,
                    "cookies": _protocol_cookie_snapshot(original, env),
                }
            if accept_status in {401, 403}:
                return {
                    "status": "session_required",
                    "message": "协议接受邀请被登录态或风控拒绝",
                    "error": "协议接受邀请被登录态或风控拒绝" + detail_suffix,
                    "error_code": accept_error or "protocol_accept_blocked",
                    "retryable": accept_status == 403,
                    "cookies": _protocol_cookie_snapshot(original, env),
                }
            if accept_status in {404, 410}:
                return {
                    "status": "expired",
                    "message": "邀请已经失效或被撤销",
                    "error": "邀请已经失效或被撤销" + detail_suffix,
                    "error_code": accept_error or "invite_expired",
                    "retryable": False,
                    "cookies": _protocol_cookie_snapshot(original, env),
                }
            return {
                "status": "failed",
                "message": f"协议接受邀请失败: HTTP {accept_status}" + detail_suffix,
                "error": f"协议接受邀请失败: HTTP {accept_status}" + detail_suffix,
                "error_code": accept_error or "protocol_accept_failed",
                "retryable": accept_status in {408, 409, 425, 429} or accept_status >= 500,
                "cookies": _protocol_cookie_snapshot(original, env),
            }

        workspace_id = str(invite_context.get("workspace_id") or "")
        refreshed = False
        after_state: dict[str, Any] = {}
        after_cookies = _protocol_cookie_snapshot(original, env)
        evidence: dict[str, Any] = {}
        for verify_attempt in range(1, 5):
            try:
                # This phase already polls four times; do not multiply that
                # budget by the initial-session transport retry count.
                exchanged = _protocol_session_state(env, workspace_id=workspace_id, attempts=1)
                refreshed = refreshed or (
                    int(exchanged.get("status") or 0) == 200
                    and bool(str((exchanged.get("data") or {}).get("accessToken") or ""))
                )
                after_state = _protocol_session_state(env, refresh=True, attempts=1)
            except Exception:
                after_state = {}
            after_cookies = _protocol_cookie_snapshot(original, env)
            if int(after_state.get("status") or 0) == 200:
                after_email = _state_email(after_state)
                if not after_email or (expected_key and after_email != expected_key):
                    return {
                        "status": "wrong_account",
                        "message": "邀请访问后的登录态与所选账号不一致",
                        "error": "邀请访问后的登录态与所选账号不一致",
                        "error_code": "session_account_mismatch",
                        "retryable": False,
                        "cookies": after_cookies,
                    }
                evidence = _workspace_evidence(
                    after_state,
                    after_cookies,
                    before_state,
                    before_cookies,
                    page_text,
                    clicked=1,
                )
                if evidence.get("explicit_already"):
                    return {
                        "status": "already_member",
                        "message": "账号已经是该 Team 成员",
                        "workspace_id": workspace_id if http_session is not None else (evidence.get("workspace_id") or workspace_id),
                        "workspace_name": evidence.get("workspace_name") or invite_context.get("workspace_name"),
                        "session_account_id": evidence.get("session_account_id"),
                        "session_refreshed": refreshed,
                        "cookies": after_cookies,
                    }
                if evidence.get("strong") or refreshed:
                    return {
                        "status": "joined",
                        "message": (
                            "协议已接受 Team 邀请并成功切换 Team Session"
                            if refreshed
                            else "协议已接受 Team 邀请并确认登录态已更新"
                        ),
                        "workspace_id": workspace_id if http_session is not None else (evidence.get("workspace_id") or workspace_id),
                        "workspace_name": evidence.get("workspace_name") or invite_context.get("workspace_name"),
                        "session_account_id": evidence.get("session_account_id"),
                        "session_refreshed": refreshed,
                        "cookies": after_cookies,
                    }
            if verify_attempt < 4:
                time.sleep(0.75 * verify_attempt)
        if int(after_state.get("status") or 0) != 200:
            return {
                "status": "session_required",
                "message": "邀请接受后登录态无法复查",
                "error": "邀请接受后登录态无法复查",
                "error_code": "protocol_session_failed",
                "retryable": True,
                "cookies": after_cookies,
            }
        return {
            "status": "not_confirmed",
            "message": "邀请接受接口已返回成功，但 Team Session 尚未确认更新",
            "error": "邀请已提交，暂未确认 Team Session",
            "error_code": "protocol_join_not_confirmed",
            "retryable": True,
            "cookies": after_cookies,
        }
    finally:
        if env is not None and http_session is None:
            try:
                env.session.close()
            except Exception:
                pass


def _accept_invite_in_driver(driver, invite: dict[str, Any], expected_email: str) -> dict[str, Any]:
    """Navigate and accept an invite, returning only sanitized structural data."""
    try:
        before_cookies = capture_selenium_cookies(driver)
    except Exception:
        before_cookies = []
    before_state = _browser_auth_state(driver)
    expected_key = _email_key(expected_email)

    def session_mismatch_result(cookies: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "status": "wrong_account",
            "message": "Roxy 当前登录态与所选账号不一致，已停止接受邀请",
            "error": "Roxy 当前登录态与所选账号不一致，已停止接受邀请",
            "error_code": "session_account_mismatch",
            "retryable": False,
            "cookie_count": len(cookies),
            "cookies": cookies,
            "recipient_verified": bool(invite.get("recipient_verified")),
        }

    before_email = _state_email(before_state)
    if before_email and expected_key and before_email != expected_key:
        return session_mismatch_result(before_cookies)
    try:
        _navigate(driver, str(invite["url"]))
    except Exception as exc:
        raise TeamInviteError(
            f"打开邀请页面失败: {type(exc).__name__}",
            code="invite_navigation_failed", status=502, retryable=True,
        ) from exc

    deadline = time.monotonic() + _INVITE_TIMEOUT
    clicked = 0
    no_action_since: float | None = None
    last_state: dict[str, Any] = before_state
    last_cookies = before_cookies
    while time.monotonic() < deadline:
        snapshot = _page_snapshot(driver)
        text = _page_text(snapshot)
        if _is_login_page(snapshot):
            return {
                "status": "session_required",
                "message": "邀请页面要求重新登录，当前 Cookie 登录态不足",
                "error": "邀请页面要求重新登录，当前 Cookie 登录态不足",
                "error_code": "session_required",
                "retryable": False,
                "cookie_count": len(last_cookies),
                "cookies": last_cookies,
                "recipient_verified": bool(invite.get("recipient_verified")),
            }
        page_error = _classify_page_error(text)
        if page_error:
            status, message = page_error
            return {
                "status": status,
                "message": message,
                "error": message,
                "error_code": "invite_expired" if status == "expired" else "admin_approval_pending",
                "retryable": status != "expired",
                "cookie_count": len(last_cookies),
                "cookies": last_cookies,
                "recipient_verified": bool(invite.get("recipient_verified")),
            }

        action = _find_invite_action(driver) if clicked < 2 else None
        if action is not None:
            if _click_element(driver, action):
                clicked += 1
                no_action_since = None
                time.sleep(0.8)
                continue
        elif no_action_since is None:
            no_action_since = time.monotonic()

        refresh = (clicked > 0 and int((deadline - time.monotonic()) / max(_INVITE_POLL_INTERVAL, 0.25)) % 3 == 0)
        current_state = _browser_auth_state(driver, refresh=refresh)
        if current_state.get("status") == 200:
            last_state = current_state
            current_email = _state_email(current_state)
            if current_email and expected_key and current_email != expected_key:
                return session_mismatch_result(last_cookies)
        try:
            last_cookies = capture_selenium_cookies(driver)
        except Exception:
            pass
        evidence = _workspace_evidence(
            last_state, last_cookies, before_state, before_cookies, text, clicked,
        )
        # The server's explicit "already a member" response is conclusive on
        # its own.  It is common for that page not to expose a workspace list
        # or an active ``_account`` cookie, so requiring structural evidence
        # here would incorrectly downgrade an idempotent retry to
        # ``needs_acceptance``.
        if evidence.get("explicit_already"):
            return {
                "status": "already_member",
                "message": "账号已经是该 Team 成员",
                "workspace_id": evidence.get("workspace_id"),
                "workspace_name": evidence.get("workspace_name"),
                "session_account_id": evidence.get("session_account_id"),
                "session_refreshed": False,
                "cookie_count": len(last_cookies),
                "cookies": last_cookies,
                "recipient_verified": bool(invite.get("recipient_verified")),
            }
        if evidence.get("strong"):
            refreshed = False
            if evidence.get("workspace_changed") and evidence.get("workspace_id"):
                refreshed = _exchange_workspace_token(driver, str(evidence["workspace_id"]))
                if refreshed:
                    last_state = _browser_auth_state(driver, refresh=True)
                    try:
                        last_cookies = capture_selenium_cookies(driver)
                    except Exception:
                        pass
            return {
                "status": "joined",
                "message": "已接受 Team 邀请并确认登录态已更新",
                "workspace_id": evidence.get("workspace_id"),
                "workspace_name": evidence.get("workspace_name"),
                "session_account_id": evidence.get("session_account_id"),
                "session_refreshed": refreshed,
                "cookie_count": len(last_cookies),
                "cookies": last_cookies,
                "recipient_verified": bool(invite.get("recipient_verified")),
            }
        if no_action_since is not None and time.monotonic() - no_action_since >= 8 and clicked == 0:
            return {
                "status": "needs_acceptance",
                "message": "已打开邀请页面，但没有找到可自动确认的接受按钮；请在 Roxy 中确认后重试",
                "error": "已打开邀请页面，但没有找到可自动确认的接受按钮；请在 Roxy 中确认后重试",
                "error_code": "accept_button_not_found",
                "retryable": True,
                "cookie_count": len(last_cookies),
                "cookies": last_cookies,
                "recipient_verified": bool(invite.get("recipient_verified")),
            }
        time.sleep(_INVITE_POLL_INTERVAL)

    return {
        "status": "not_confirmed",
        "message": "邀请页面已处理，但尚未确认账号进入 Team；请检查 Roxy 页面后重试",
        "error": "邀请页面已处理，但尚未确认账号进入 Team；请检查 Roxy 页面后重试",
        "error_code": "join_not_confirmed",
        "retryable": True,
        "cookie_count": len(last_cookies),
        "cookies": last_cookies,
        "recipient_verified": bool(invite.get("recipient_verified")),
    }


def _persist_team_cookies(account_id: int, email: str, cookies: list[dict[str, Any]]) -> dict[str, Any] | None:
    normalized = normalize_cookies(cookies, source="team_invite")
    if not normalized:
        return None
    # A CDP read can briefly return only newly-mutated cookies.  Merge that
    # snapshot with the previous managed jar before deciding whether it is
    # safe to replace the credential file; otherwise a transient partial read
    # could destroy a still-valid login session.
    if not has_session_cookie(normalized):
        try:
            previous = db.load_account_web_cookie_credential(account_id) or {}
            previous_cookies = previous.get("cookies") if isinstance(previous, dict) else []
            if isinstance(previous_cookies, list):
                normalized = normalize_cookies([*previous_cookies, *normalized], source="team_invite_merge")
        except Exception:
            # The caller will receive a clear session-cookie error below; do
            # not include provider/file details in the persisted message.
            pass
    if not has_session_cookie(normalized):
        raise TeamInviteError(
            "浏览器 Cookie 快照缺少有效登录会话，未覆盖原有 Cookie",
            code="cookie_session_missing",
            status=409,
            retryable=True,
        )
    metadata = persist_cookie_credential(
        email,
        normalized,
        source="team_invite",
        account_id=account_id,
    )
    if not db.update_account_web_cookie_credential(
        account_id,
        credential_path=metadata["credential_path"],
        saved_at=metadata["saved_at"],
        cookie_count=metadata["count"],
        has_session_cookie=metadata["has_session_cookie"],
        status="saved",
        error=None,
    ):
        raise TeamInviteError("账号已删除，未写入更新后的 Cookie", code="account_deleted", status=404)
    return metadata


def _safe_failure(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, TeamInviteError):
        if exc.code == "invite_not_found":
            status = "no_invite"
        elif exc.code in {"wrong_recipient", "recipient_unverified", "session_account_mismatch"}:
            status = "wrong_account"
        elif exc.code == "unsupported_mail_source":
            status = "unsupported"
        else:
            status = "failed"
        return {
            "status": status,
            "message": str(exc),
            "error": str(exc),
            "error_code": exc.code,
            "retryable": exc.retryable,
            "checked_at": _now_iso(),
        }
    # Keep the account-session error code actionable without persisting the
    # original exception text (Roxy/provider errors may contain implementation
    # details or sensitive request data).
    try:
        from core.account_browser_session import AccountBrowserSessionError
    except Exception:  # pragma: no cover - import is stable in production
        AccountBrowserSessionError = ()  # type: ignore[assignment,misc]
    if isinstance(exc, AccountBrowserSessionError):
        code = str(getattr(exc, "code", "browser_session_failed") or "browser_session_failed")
        safe_messages = {
            "account_not_found": "账号不存在",
            "web_cookies_missing": "该账号没有可用的 Web Cookie，请先保存登录态",
            "web_cookies_expired": "保存的 Web Cookie 已过期，请重新登录后保存",
            "cookie_session_invalid": "保存的 Web Cookie 已失效，请重新登录后保存",
            "session_verification_blocked": "当前代理出口被 ChatGPT 风控拦截，请复用注册代理后重试",
            "session_verification_failed": "暂时无法验证 ChatGPT 登录态，请稍后重试",
            "browser_session_opening": "该账号的 Roxy 登录态正在打开，请稍后重试",
            "browser_session_missing": "该账号没有可用的 Roxy 登录态，请重新打开",
            "browser_session_stale": "Roxy 登录态已失效，请重新打开",
            "browser_session_failed": "打开 Roxy 登录态失败，请稍后重试",
        }
        message = safe_messages.get(code, "Roxy 登录态不可用，请稍后重试")
        retryable = code in {
            "session_verification_blocked", "session_verification_failed",
            "browser_session_opening", "browser_session_missing", "browser_session_stale",
            "browser_session_failed",
        }
        status = "session_required" if code in {
            "web_cookies_missing", "web_cookies_expired", "cookie_session_invalid",
            "browser_session_missing", "browser_session_stale",
        } else "failed"
        return {
            "status": status,
            "message": message,
            "error": message,
            "error_code": code[:120],
            "retryable": retryable,
            "checked_at": _now_iso(),
        }
    return {
        "status": "failed",
        "message": "补 Team 任务异常",
        # Provider exceptions may contain mailbox pickup URLs or credentials;
        # persist only the exception type in the account-facing state.
        "error": f"{type(exc).__name__}",
        "error_code": "internal_error",
        "retryable": False,
        "checked_at": _now_iso(),
    }


def _run_team_invite(*, account_id: int, claim_id: str, email: str, trigger: str) -> dict[str, Any]:
    browser_used = False
    try:
        if not db.mark_account_team_invite_running(account_id, claim_id=claim_id):
            return {"ok": False, "status": "failed", "error": "账号已删除或任务已被重置"}
        account = db.get_account(account_id)
        if not account:
            raise TeamInviteError("账号不存在", code="account_not_found", status=404)
        target_email = str(account.get("email") or email).strip()
        from core.email_provider import resolve_email_source

        source = resolve_email_source(target_email)
        mail_scan: dict[str, int] = {}
        found = wait_for_invite_message(target_email, source=source, diagnostics=mail_scan)
        if found is None:
            result = _no_invite_result(mail_scan)
            logger.info("[Team] 未找到邀请: account_id=%s detail=%s", account_id, result["message"])
            db.update_account_team_invite(account_id, result=result, claim_id=claim_id)
            return result
        _message, invite = found
        result: dict[str, Any] = {}

        def operation(driver, _session):
            return _accept_invite_in_driver(driver, invite, target_email)

        from core.account_browser_session import run_account_browser_session

        browser_used = True
        result = run_account_browser_session(account_id, operation, open_if_missing=True)
        if not isinstance(result, dict):
            result = {"status": "not_confirmed", "message": "浏览器未返回邀请处理结果"}
        result["invite_link_fingerprint"] = invite["fingerprint"]
        result["recipient_verified"] = bool(invite.get("recipient_verified"))
        # The callback's final cookie snapshot is the authoritative browser
        # state. Persist it for both success and a manual-confirmation outcome.
        cookies = result.pop("cookies", None)
        if isinstance(cookies, list):
            result["cookie_count"] = len(cookies)
            try:
                _persist_team_cookies(account_id, target_email, cookies)
            except TeamInviteError:
                raise
            except Exception as exc:
                result["cookie_update_error"] = f"Cookie 保存失败: {type(exc).__name__}"
                logger.warning("[Team] 更新 Cookie 保存失败: account_id=%s", account_id)
        result.setdefault("checked_at", _now_iso())
        result.setdefault("message", "补 Team 任务完成")
        db.update_account_team_invite(account_id, result=result, claim_id=claim_id)
        logger.info(
            "[Team] 补 Team 完成: account_id=%s status=%s source=%s cookies=%s",
            account_id,
            result.get("status") or "unknown",
            source,
            result.get("cookie_count") or 0,
        )
        return result
    except Exception as exc:
        result = _safe_failure(exc)
        try:
            db.update_account_team_invite(account_id, result=result, claim_id=claim_id)
        except Exception:
            logger.exception("[Team] 写入异常状态失败: account_id=%s", account_id)
        logger.warning("[Team] 补 Team 失败: account_id=%s code=%s", account_id, result.get("error_code"))
        return result
    finally:
        try:
            if browser_used:
                from core.account_browser_session import close_account_browser_session

                closed = close_account_browser_session(
                    account_id=account_id,
                    force_delete_created_profile=True,
                )
                logger.info(
                    "[Team] 补 Team 浏览器清理: account_id=%s closed=%s profile=%s",
                    account_id,
                    bool(closed.get("closed")) if isinstance(closed, dict) else False,
                    str(closed.get("profile_id") or "-") if isinstance(closed, dict) else "-",
                )
        except Exception:
            # 清理失败不能覆盖已经持久化的 Team 处理结果；保留异常日志，
            # 进程退出时的全局清理仍会再尝试一次。
            logger.exception("[Team] 补 Team 浏览器清理失败: account_id=%s", account_id)
        finally:
            _QUEUE_SLOTS.release()


def enqueue_account_team_invite(
    *, account_id: int, email: str, trigger: str = "manual",
) -> dict[str, Any]:
    """Queue one explicitly selected account for Team invitation handling."""
    account_id = int(account_id)
    email = str(email or "").strip()
    if not email:
        return {"accepted": False, "busy": False, "error": "账号邮箱为空"}
    if not _EMAIL_RE.fullmatch(email):
        return {
            "accepted": False,
            "busy": False,
            "error": "账号邮箱格式无效",
            "error_code": "invalid_email",
        }
    account = db.get_account(account_id)
    if not account:
        return {"accepted": False, "busy": False, "error": "账号不存在"}
    if not bool(account.get("has_web_cookies")):
        return {
            "accepted": False,
            "busy": False,
            "error": "该账号没有可注入的 Web Cookie，请先保存登录态",
            "error_code": "web_cookies_missing",
        }
    if not _QUEUE_SLOTS.acquire(blocking=False):
        return {
            "accepted": False,
            "busy": False,
            "queue_full": True,
            "error": "补 Team 队列已满，请稍后重试",
        }
    try:
        claim_id = db.claim_account_team_invite(account_id, trigger=trigger)
    except Exception:
        _QUEUE_SLOTS.release()
        raise
    if not claim_id:
        _QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "该账号正在补 Team"}
    try:
        _EXECUTOR.submit(
            _run_team_invite,
            account_id=account_id,
            claim_id=claim_id,
            email=email,
            trigger=str(trigger or "manual"),
        )
    except Exception as exc:
        _QUEUE_SLOTS.release()
        result = {
            "status": "failed",
            "message": "补 Team 任务入队失败",
            # Executor/provider exceptions can contain request details; keep
            # them out of account state and the API response.
            "error": "补 Team 任务入队失败，请稍后重试",
            "error_code": "enqueue_failed",
            "retryable": True,
            "checked_at": _now_iso(),
        }
        db.update_account_team_invite(account_id, result=result, claim_id=claim_id)
        logger.warning("[Team] 任务入队失败: account_id=%s error=%s", account_id, type(exc).__name__)
        return {
            "accepted": False,
            "busy": False,
            "error": result["error"],
            "error_code": result["error_code"],
        }
    return {
        "accepted": True,
        "busy": False,
        "account_id": account_id,
        "email": email,
        "status": "queued",
        "trigger": str(trigger or "manual"),
    }


def _run_team_invite_protocol(
    *, account_id: int, claim_id: str, email: str, trigger: str, expected_workspace_id: str = "",
    login_mode: str = "cookie", invite_url: str = "",
) -> dict[str, Any]:
    try:
        if not db.mark_account_team_invite_running(account_id, claim_id=claim_id):
            return {"ok": False, "status": "failed", "error": "账号已删除或任务已被重置"}
        account = db.get_account(account_id)
        if not account:
            raise TeamInviteError("账号不存在", code="account_not_found", status=404)
        target_email = str(account.get("email") or email).strip()
        from core.email_provider import resolve_email_source

        source = "manual" if invite_url else resolve_email_source(target_email)
        mail_scan: dict[str, int] = {}
        found = ({}, manual_invite(invite_url)) if invite_url else wait_for_invite_message(target_email, source=source, diagnostics=mail_scan)
        if found is None:
            result = _no_invite_result(mail_scan)
            logger.info("[Team][协议] 未找到邀请: account_id=%s detail=%s", account_id, result["message"])
            db.update_account_team_invite(account_id, result=result, claim_id=claim_id)
            return result
        _message, invite = found
        try:
            credential = (db.load_account_web_cookie_credential(account_id) or {}) if login_mode == "cookie" else {}
        except Exception as exc:
            raise TeamInviteError(
                "保存的 Web Cookie 无法读取",
                code="web_cookies_invalid",
                status=400,
            ) from exc
        cookies = normalize_cookies(credential.get("cookies") or [])
        excluded: set[str] = set()
        while True:
            try:
                if login_mode == "password_totp":
                    from core.web_password_totp import accept_team
                    result = accept_team(account, invite, claim_id=claim_id, expected_workspace_id=expected_workspace_id)
                else:
                    result = _accept_invite_protocol(account, invite, target_email, cookies,
                        **({"expected_workspace_id": expected_workspace_id} if expected_workspace_id else {}))
                break
            except TeamInviteError as exc:
                if exc.code != "invite_workspace_mismatch" or not expected_workspace_id or invite_url:
                    raise
                excluded.add(invite["fingerprint"])
                found = wait_for_invite_message(target_email, source=source, diagnostics=mail_scan,
                                                excluded_fingerprints=excluded)
                if found is None or len(excluded) >= _MESSAGE_SCAN_LIMIT:
                    raise TeamInviteError("未找到目标母号的有效邀请，未接受其他工作区邀请",
                                          code="target_invite_not_found", status=404) from None
                _message, invite = found
        if (expected_workspace_id and result.get("status") in {"joined", "already_member"}
                and result.get("workspace_id") != expected_workspace_id):
            raise TeamInviteError("加入结果未确认目标母号工作区", code="workspace_mismatch", status=409)
        result["invite_link_fingerprint"] = invite["fingerprint"]
        result["recipient_verified"] = bool(invite.get("recipient_verified")) or (
            login_mode == "password_totp" and result.get("status") in {"joined", "already_member"}
        )
        runtime_cookies = result.pop("cookies", None)
        persistable_status = str(result.get("status") or "").lower() not in {
            "wrong_account", "session_required", "failed",
        }
        if isinstance(runtime_cookies, list) and persistable_status and login_mode == "cookie":
            result["cookie_count"] = len(runtime_cookies)
            _persist_team_cookies(account_id, target_email, runtime_cookies)
        result.setdefault("checked_at", _now_iso())
        result.setdefault("message", "协议补 Team 任务完成")
        db.update_account_team_invite(account_id, result=result, claim_id=claim_id)
        logger.info(
            "[Team][协议] 补 Team 完成: account_id=%s status=%s source=%s cookies=%s",
            account_id,
            result.get("status") or "unknown",
            source,
            result.get("cookie_count") or 0,
        )
        return result
    except Exception as exc:
        result = _safe_failure(exc)
        try:
            db.update_account_team_invite(account_id, result=result, claim_id=claim_id)
        except Exception:
            logger.exception("[Team][协议] 写入异常状态失败: account_id=%s", account_id)
        logger.warning(
            "[Team][协议] 补 Team 失败: account_id=%s code=%s",
            account_id,
            result.get("error_code"),
        )
        return result
    finally:
        _PROTOCOL_QUEUE_SLOTS.release()


def enqueue_account_team_invite_protocol(
    *, account_id: int, email: str, trigger: str = "manual_protocol", expected_workspace_id: str = "",
    login_mode: str = "cookie", invite_url: str = "",
) -> dict[str, Any]:
    """Queue a pure-HTTP Team invite attempt; never opens or falls back to Roxy."""
    account_id = int(account_id)
    if login_mode not in {"cookie", "password_totp"}:
        raise ValueError("不支持的 Team 登录模式")
    if invite_url:
        if login_mode != "password_totp":
            raise ValueError("手动邀请链接仅用于密码 + 2FA 模式")
        manual_invite(invite_url)
    email = str(email or "").strip()
    if not email or not _EMAIL_RE.fullmatch(email):
        return {
            "accepted": False,
            "busy": False,
            "error": "账号邮箱格式无效" if email else "账号邮箱为空",
            "error_code": "invalid_email",
        }
    account = db.get_account(account_id)
    if not account:
        return {"accepted": False, "busy": False, "error": "账号不存在"}
    if login_mode == "password_totp":
        from core.codex_password_totp import login_material, PasswordTotpLoginError
        try:
            login_material(account)
        except PasswordTotpLoginError as exc:
            return {"accepted": False, "busy": False, "error": str(exc), "error_code": exc.error_code}
    elif not bool(account.get("has_web_cookies")):
        return {
            "accepted": False,
            "busy": False,
            "error": "该账号没有可用的 Web Cookie，请先保存登录态",
            "error_code": "web_cookies_missing",
        }
    if not _PROTOCOL_QUEUE_SLOTS.acquire(blocking=False):
        return {
            "accepted": False,
            "busy": False,
            "queue_full": True,
            "error": "协议补 Team 队列已满，请稍后重试",
        }
    try:
        claim_id = db.claim_account_team_invite(account_id, trigger=trigger)
    except Exception:
        _PROTOCOL_QUEUE_SLOTS.release()
        raise
    if not claim_id:
        _PROTOCOL_QUEUE_SLOTS.release()
        return {"accepted": False, "busy": True, "error": "该账号正在补 Team"}
    try:
        attempt_count = int((db.get_account(account_id) or {}).get("team_invite_attempt_count") or 0) if login_mode == "password_totp" else 0
        _PROTOCOL_EXECUTOR.submit(
            _run_team_invite_protocol,
            account_id=account_id,
            claim_id=claim_id,
            email=email,
            trigger=str(trigger or "manual_protocol"),
            **({"login_mode": login_mode, "invite_url": invite_url} if login_mode != "cookie" else {}),
            **({"expected_workspace_id": expected_workspace_id} if expected_workspace_id else {}),
        )
    except Exception as exc:
        _PROTOCOL_QUEUE_SLOTS.release()
        result = {
            "status": "failed",
            "message": "协议补 Team 任务入队失败",
            "error": "协议补 Team 任务入队失败，请稍后重试",
            "error_code": "enqueue_failed",
            "retryable": True,
            "checked_at": _now_iso(),
        }
        db.update_account_team_invite(account_id, result=result, claim_id=claim_id)
        logger.warning(
            "[Team][协议] 任务入队失败: account_id=%s error=%s",
            account_id,
            type(exc).__name__,
        )
        return {
            "accepted": False,
            "busy": False,
            "error": result["error"],
            "error_code": result["error_code"],
        }
    return {
        "accepted": True,
        "busy": False,
        "account_id": account_id,
        "email": email,
        "status": "queued",
        "trigger": str(trigger or "manual_protocol"),
        "mode": "protocol",
        **({"attempt_count": attempt_count} if login_mode == "password_totp" else {}),
    }


def enqueue_accounts_team_invite_protocol(account_ids: list) -> dict:
    from core.supplement_queue import enqueue_supplement_batch

    return enqueue_supplement_batch(
        account_ids, kind="team", trigger="manual_protocol_bulk", slots=_PROTOCOL_QUEUE_SLOTS,
        valid_email=lambda email: bool(_EMAIL_RE.fullmatch(email)),
        submit=lambda **kwargs: _PROTOCOL_EXECUTOR.submit(_run_team_invite_protocol, **kwargs),
    )


def queue_settings() -> dict[str, Any]:
    return {
        "workers": _WORKERS,
        "queue_limit": _QUEUE_LIMIT,
        "timeout_seconds": _INVITE_TIMEOUT,
        "protocol_workers": _PROTOCOL_WORKERS,
        "protocol_queue_limit": _PROTOCOL_QUEUE_LIMIT,
    }


__all__ = [
    "TeamInviteError",
    "enqueue_account_team_invite",
    "enqueue_account_team_invite_protocol",
    "enqueue_accounts_team_invite_protocol",
    "extract_invite_link",
    "find_invite_message",
    "fetch_latest_mail_message",
    "queue_settings",
]
