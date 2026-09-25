# -*- coding: utf-8 -*-
"""iCloud 邮箱池与 OTP 客户端。"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, unquote, urlencode, urljoin, urlparse, urlunparse
from zoneinfo import ZoneInfo

import requests

from config import email as _email_cfg
from core.otp_utils import extract_otp, looks_like_openai_email

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CONTEXT_CACHE: dict[str, "ICloudEmailAccount"] = {}
_BASELINES: dict[str, tuple[str, str]] = {}
_SHARE_CURSORS: dict[str, str] = {}
_SHARE_INITIALIZED: set[str] = set()
_QUERY_API_TIMEZONE = ZoneInfo("Asia/Shanghai")
_QUERY_WEB_HOSTS = frozenset({"icloud.thefindnet.xyz"})
_SHARE_MAIL_HOSTS = frozenset({"mail.mczero.top"})
_SQ_API_HOSTS = frozenset({"icloud-api.top"})
_IMPORT_RE = re.compile(
    r"^(?P<email>[^\s]+@[^\s]+?)---(?P<token>[^\s]+)---(?P<pickup_url>https?://\S+)$",
    re.IGNORECASE,
)


class ICloudMailError(RuntimeError):
    """FlySMS iCloud 邮箱错误。"""


class ICloudOtpTimeoutError(ICloudMailError):
    """可记录的取码超时原因；接口故障不能触发重复发码。"""

    safe_to_persist = True
    retryable = True
    reauth_restart_recommended = False
    _REASONS = {
        "no_messages": "取码接口尚无邮件",
        "no_openai_mail": "尚未收到 OpenAI 验证邮件",
        "old_message": "验证码邮件早于本次请求",
        "baseline_message": "仍是发码前的旧邮件",
        "baseline_code": "仍是发码前的旧验证码",
        "excluded_code": "返回的验证码已被排除",
        "no_code": "最新 OpenAI 邮件不含验证码",
        "mail_api_error": "取码接口持续异常",
        "mail_credentials_invalid": "取码凭证被接口拒绝",
    }

    def __init__(self, reason: str, *, http_status: int | None = None) -> None:
        self.reason = reason if reason in self._REASONS else "mail_api_error"
        self.http_status = http_status
        self.resend_recommended = self.reason not in {"mail_api_error", "mail_credentials_invalid"}
        self.error_code = "icloud_otp_timeout" if self.resend_recommended else "icloud_mail_api_error"
        detail = self._REASONS[self.reason]
        if http_status is not None:
            detail += f"（HTTP {http_status}）"
        super().__init__(f"等待 iCloud 验证码超时：{detail}")


@dataclass
class ICloudEmailAccount:
    email: str
    token: str
    pickup_url: str
    allocation_id: int | None = None
    protocol: str = ""


def parse_import_line(line: str) -> dict | None:
    """解析 FlySMS、query.php、分享链接或通用 GET API 素材。"""
    raw = str(line or "").strip()
    match = _IMPORT_RE.match(raw)
    if match:
        record = {key: value.strip() for key, value in match.groupdict().items()}
        parsed = urlparse(record["pickup_url"])
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        query_record = _query_url_record(record["pickup_url"], expected_email=record["email"])
        if query_record:
            record["token"] = query_record["token"]
        share_record = _share_url_record(record["pickup_url"], expected_email=record["email"])
        if share_record:
            record["token"] = share_record["token"]
        sq_record = _sq_url_record(record["pickup_url"], expected_email=record["email"])
        if sq_record:
            record["token"] = sq_record["token"]
        return record

    expected_email = ""
    url = raw
    for separator in ("----", "===="):
        if separator in raw:
            expected_email, url = (part.strip() for part in raw.split(separator, 1))
            break
    return (
        _query_url_record(url, expected_email=expected_email)
        or _share_url_record(url, expected_email=expected_email)
        or _sq_url_record(url, expected_email=expected_email)
        or _generic_api_url_record(raw, expected_email=expected_email)
    )


def _query_url_record(url: str, *, expected_email: str = "") -> dict | None:
    parsed = urlparse(str(url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    query = parse_qs(parsed.query, keep_blank_values=True)
    email = str((query.get("mail") or [""])[0]).strip()
    password = str((query.get("pwd") or [""])[0]).strip()
    if not email or not password or not parsed.path.lower().endswith("query.php"):
        return None
    if expected_email and expected_email.lower() != email.lower():
        return None
    return {"email": email, "token": password, "pickup_url": str(url).strip()}


def _share_url_record(url: str, *, expected_email: str = "") -> dict | None:
    """解析 mail.mczero.top 的 `/s/<token>/<email>` 分享链接。"""
    parsed = urlparse(str(url or "").strip())
    if (
        parsed.scheme not in {"http", "https"}
        or str(parsed.hostname or "").lower() not in _SHARE_MAIL_HOSTS
    ):
        return None
    parts = [unquote(part).strip() for part in parsed.path.split("/") if part]
    if len(parts) != 3 or parts[0].lower() != "s":
        return None
    token, email = parts[1], parts[2]
    if not token or "@" not in email:
        return None
    if expected_email and expected_email.lower() != email.lower():
        return None
    pickup_url = urlunparse(parsed._replace(query="", fragment=""))
    return {"email": email, "token": token, "pickup_url": pickup_url}


def _sq_url_record(url: str, *, expected_email: str = "") -> dict | None:
    """解析 icloud-api.top 的 `/s/<token>/<email>` 分享链接。"""
    parsed = urlparse(str(url or "").strip())
    if (
        parsed.scheme not in {"http", "https"}
        or str(parsed.hostname or "").lower() not in _SQ_API_HOSTS
    ):
        return None
    parts = [unquote(part).strip() for part in parsed.path.split("/") if part]
    if len(parts) != 3 or parts[0].lower() not in {"s", "sq"}:
        return None
    token, email = parts[1], parts[2]
    if not token or "@" not in email:
        return None
    if expected_email and expected_email.lower() != email.lower():
        return None
    pickup_url = urlunparse(parsed._replace(query="", fragment=""))
    return {"email": email, "token": token, "pickup_url": pickup_url}


def _is_native_icloud_url(url: str) -> bool:
    parsed = urlparse(str(url or "").strip())
    host = str(parsed.hostname or "").lower()
    path = parsed.path.lower()
    return (
        host in _SHARE_MAIL_HOSTS
        or host in _SQ_API_HOSTS
        or path.endswith("query.php")
        or (host == "flysms.xyz" and path.startswith("/icloud/"))
    )


def _generic_api_url_record(raw: str, *, expected_email: str = "") -> dict | None:
    candidate_url = str(raw or "").strip()
    for separator in ("----", "===="):
        if separator in candidate_url:
            _, candidate_url = candidate_url.split(separator, 1)
            candidate_url = candidate_url.strip()
            break
    if _is_native_icloud_url(candidate_url):
        return None
    try:
        from core.generic_api_mail_client import GenericApiMailError, parse_import_line as parse_generic

        record = parse_generic(raw)
    except GenericApiMailError:
        return None
    email = str(record.get("email") or "").strip()
    if not email.lower().endswith("@icloud.com"):
        return None
    if expected_email and expected_email.lower() != email.lower():
        return None
    return {
        "email": email,
        "token": "",
        "pickup_url": str(record.get("code_url") or "").strip(),
        "protocol": "generic_api",
    }


def _accounts_file() -> Path:
    value = str(getattr(_email_cfg, "ICLOUD_ACCOUNTS_FILE", "用于注册的iCloud邮箱.txt") or "").strip()
    path = Path(value or "用于注册的iCloud邮箱.txt")
    return path if path.is_absolute() else _PROJECT_ROOT / path


def _api_url() -> str:
    base = str(getattr(_email_cfg, "ICLOUD_API_BASE", "https://flysms.xyz/icloud") or "").strip()
    path = str(getattr(_email_cfg, "ICLOUD_LATEST_MESSAGES_PATH", "/api/pickup/messages/latest") or "").strip()
    if not base:
        raise ICloudMailError("ICLOUD_API_BASE 为空")
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _message_timestamp(message: dict) -> float | None:
    for key in ("sentAt", "date", "mailboxReceivedAt", "ingestedAt"):
        raw = str(message.get(key) or "").strip()
        if not raw:
            continue
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                # thefindnet query.php returns `saved_at` without an offset, but
                # the served clock is Asia/Shanghai. Treating it as UTC moves an
                # old OTP eight hours into the future and defeats `after_ts`.
                parsed = parsed.replace(tzinfo=(
                    _QUERY_API_TIMEZONE
                    if key == "date" and (message.get("saved_at") or message.get("sqApi"))
                    else timezone.utc
                ))
            return parsed.timestamp()
        except ValueError:
            continue
    return None


def _message_identity(message: dict) -> str:
    explicit = f"{message.get('mailbox') or ''}:{message.get('uid') or ''}:{message.get('ingestedAt') or ''}"
    if explicit != "::":
        return explicit
    return "query:" + ":".join(str(message.get(key) or "") for key in ("saved_at", "from", "subject", "body"))


def _query_account_url(account: ICloudEmailAccount) -> str | None:
    record = _query_url_record(account.pickup_url, expected_email=account.email)
    if record is None:
        return None
    parsed = urlparse(account.pickup_url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    params = [(key, value) for key, value in params if key != "_t"]
    params.append(("_t", str(int(time.time() * 1000))))
    return urlunparse(parsed._replace(query=urlencode(params), fragment=""))


def _share_account_record(account: ICloudEmailAccount) -> dict | None:
    return _share_url_record(account.pickup_url, expected_email=account.email)


def _sq_account_record(account: ICloudEmailAccount) -> dict | None:
    return _sq_url_record(account.pickup_url, expected_email=account.email)


def _share_request_url(account: ICloudEmailAccount, share_record: dict) -> str:
    key = account.email.lower()
    params = [("format", "json")]
    cursor = _SHARE_CURSORS.get(key, "")
    if cursor:
        params.append(("after", cursor))
    elif key not in _SHARE_INITIALIZED:
        params.append(("refresh", "1"))
    parsed = urlparse(str(share_record["pickup_url"]))
    return urlunparse(parsed._replace(query=urlencode(params), fragment=""))


def _fetch_share_latest(
    account: ICloudEmailAccount, share_record: dict,
) -> tuple[dict | None, str]:
    request_url = _share_request_url(account, share_record)
    timeout = max(5, int(getattr(_email_cfg, "ICLOUD_REQUEST_TIMEOUT", 20) or 20))
    try:
        response = requests.get(
            request_url,
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-cache",
                "User-Agent": "gpt-register/1.0",
            },
            timeout=timeout,
        )
    except requests.RequestException as exc:
        host = str(urlparse(request_url).hostname or "share endpoint")
        raise ICloudMailError(
            f"iCloud Share API 请求失败: {type(exc).__name__}: {host}"
        ) from exc

    if response.status_code in {401, 403, 404}:
        raise ICloudMailError("iCloud Share URL 凭证无效")
    try:
        payload = response.json()
    except ValueError as exc:
        raise ICloudMailError(
            f"iCloud Share API 返回非 JSON 响应: HTTP {response.status_code}"
        ) from exc
    if not isinstance(payload, dict):
        raise ICloudMailError(
            f"iCloud Share API 返回格式错误: HTTP {response.status_code}"
        )
    if response.status_code != 200:
        notice = str(payload.get("notice") or payload.get("error") or "").strip()
        suffix = f": {notice[:160]}" if notice else ""
        raise ICloudMailError(
            f"iCloud Share API 请求失败: HTTP {response.status_code}{suffix}"
        )

    key = account.email.lower()
    _SHARE_INITIALIZED.add(key)
    state = str(payload.get("state") or "").strip().lower()
    raw_message = payload.get("message")
    message_id = str(payload.get("message_id") or "").strip()
    if not isinstance(raw_message, dict):
        if message_id and not _SHARE_CURSORS.get(key):
            _SHARE_CURSORS[key] = message_id
        if state in {"empty", "ready"}:
            return None, "NO_MESSAGES_FOUND"
        notice = str(payload.get("notice") or "").strip()
        return None, notice[:200] or f"iCloud Share API state={state or 'unknown'}"

    message = dict(raw_message)
    message_id = str(message.get("id") or message_id).strip()
    if message_id:
        _SHARE_CURSORS[key] = message_id
    codes = message.get("codes")
    code = next((
        str(value) for value in codes
        if re.fullmatch(r"\d{6}", str(value or ""))
    ), "") if isinstance(codes, list) else ""
    preview = str(message.get("preview") or "")
    date = str(message.get("date") or "")
    if not date and isinstance(message.get("received_at"), (int, float)):
        date = datetime.fromtimestamp(
            float(message["received_at"]), tz=timezone.utc,
        ).isoformat()
    message.update({
        "mailbox": "share",
        "uid": message_id,
        "to": account.email,
        "date": date,
        "ingestedAt": date,
        "text": f"verification code: {code}\n{preview}" if code else preview,
        "html": preview,
    })
    return message, ""


def _sq_request_url(record: dict) -> str:
    parsed = urlparse(str(record["pickup_url"]))
    parts = parsed.path.split("/")
    for index, part in enumerate(parts):
        if part.lower() in {"s", "sq"}:
            parts[index] = "sq"
            break
    return urlunparse(parsed._replace(path="/".join(parts), query="", fragment=""))


def _sq_text(mapping: dict, *keys: str) -> str:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, dict):
            nested = value.get("content") or value.get("text") or value.get("html")
            if isinstance(nested, str) and nested.strip():
                return nested
    return ""


def _normalize_sq_message(
    account: ICloudEmailAccount, payload: dict, raw_message: object,
) -> dict | None:
    message = dict(raw_message) if isinstance(raw_message, dict) else {}
    raw_text = raw_message if isinstance(raw_message, str) else ""
    text = raw_text or _sq_text(
        message, "text", "body", "content", "html", "msg", "bodyText", "bodyPreview",
    )
    subject = _sq_text(message, "subject") or _sq_text(payload, "subject")
    sender = (
        _sq_text(message, "from", "sender", "fromEmail")
        or _sq_text(payload, "from", "sender", "fromEmail")
    )
    date = (
        _sq_text(message, "date", "time", "sentAt", "receivedAt")
        or _sq_text(payload, "time", "date")
    )
    if not text and not subject and not sender:
        return None
    uid = str(
        message.get("uid") or message.get("id") or message.get("message_id") or ""
    ).strip()
    if not uid:
        identity = "\0".join((date, sender, subject, text))
        uid = hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()[:24]
    message.update({
        "mailbox": str(message.get("mailbox") or payload.get("mailbox") or "INBOX"),
        "uid": uid,
        "from": str(message.get("from") or sender),
        "subject": str(message.get("subject") or subject),
        "to": str(message.get("to") or account.email),
        "date": str(message.get("date") or date),
        "ingestedAt": str(message.get("ingestedAt") or date),
        "text": str(message.get("text") or text),
        "html": str(message.get("html") or (text if "<" in text and ">" in text else "")),
        "sqApi": True,
    })
    return message


def _fetch_sq_latest(
    account: ICloudEmailAccount, sq_record: dict,
) -> tuple[dict | None, str]:
    request_url = _sq_request_url(sq_record)
    timeout = max(5, int(getattr(_email_cfg, "ICLOUD_REQUEST_TIMEOUT", 20) or 20))
    try:
        response = requests.get(
            request_url,
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-cache",
                "User-Agent": "gpt-register/1.0",
            },
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise ICloudMailError(
            f"iCloud SQ API 请求失败: {type(exc).__name__}: {urlparse(request_url).hostname or 'endpoint'}"
        ) from exc

    if response.status_code in {401, 403, 404}:
        raise ICloudMailError("iCloud SQ API 凭证无效")
    try:
        payload = response.json()
    except ValueError as exc:
        raise ICloudMailError(
            f"iCloud SQ API 返回非 JSON 响应: HTTP {response.status_code}"
        ) from exc
    if not isinstance(payload, dict):
        raise ICloudMailError(
            f"iCloud SQ API 返回格式错误: HTTP {response.status_code}"
        )
    if response.status_code != 200:
        detail = str(payload.get("msg") or payload.get("error") or "").strip()
        suffix = f": {detail[:160]}" if detail else ""
        raise ICloudMailError(
            f"iCloud SQ API 请求失败: HTTP {response.status_code}{suffix}"
        )

    status = payload.get("status")
    success = status is True or status == 1 or (
        isinstance(status, str) and status.strip().lower() in {"true", "1", "success"}
    )
    raw_message = payload.get("msg")
    detail = str(raw_message or "").strip()
    compact_detail = re.sub(r"\s+", "", detail).lower()
    if not success:
        if not detail or any(marker in compact_detail for marker in (
            "暂无邮件", "暂时无邮件", "没有邮件", "nomessages", "nomail", "empty",
        )):
            return None, "NO_MESSAGES_FOUND"
        if any(marker in compact_detail for marker in (
            "invalidbase64", "invalidtoken", "invalidcredential", "凭证无效", "链接无效",
        )):
            raise ICloudMailError("iCloud SQ API 凭证无效")
        raise ICloudMailError(f"iCloud SQ API 请求失败: {detail[:200]}")

    raw_messages = raw_message if isinstance(raw_message, list) else [raw_message]
    messages = [
        message for message in (
            _normalize_sq_message(account, payload, item) for item in raw_messages
        ) if message is not None
    ]
    if not messages:
        return None, "NO_MESSAGES_FOUND"
    messages.sort(key=lambda item: _message_timestamp(item) or 0.0, reverse=True)
    return next((item for item in messages if looks_like_openai_email(item)), messages[0]), ""


def _fetch_query_latest(account: ICloudEmailAccount, request_url: str) -> tuple[dict | None, str]:
    timeout = max(5, int(getattr(_email_cfg, "ICLOUD_REQUEST_TIMEOUT", 20) or 20))
    try:
        response = requests.get(
            request_url,
            headers={"Accept": "application/json", "User-Agent": "gpt-register/1.0"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        parsed = urlparse(request_url)
        raise ICloudMailError(
            f"iCloud Query API 请求失败: {type(exc).__name__}: {parsed.scheme}://{parsed.netloc}{parsed.path}"
        ) from exc
    try:
        payload = response.json()
    except ValueError as exc:
        raise ICloudMailError(f"iCloud Query API 返回非 JSON 响应: HTTP {response.status_code}") from exc
    if not isinstance(payload, dict):
        raise ICloudMailError(f"iCloud Query API 返回格式错误: HTTP {response.status_code}")
    if response.status_code == 401:
        raise ICloudMailError("iCloud Query API 凭证无效")
    if response.status_code != 200 or str(payload.get("status") or "").lower() != "success":
        message = str(payload.get("message") or payload.get("error") or f"HTTP {response.status_code}")
        raise ICloudMailError(f"iCloud Query API 请求失败: {message[:200]}")
    data = payload.get("data")
    if not isinstance(data, list):
        raise ICloudMailError("iCloud Query API 响应中 data 不是数组")
    if not data:
        return None, "NO_MESSAGES_FOUND"
    messages = []
    for item in data:
        if not isinstance(item, dict):
            continue
        message = dict(item)
        message["text"] = str(item.get("body") or "")
        message["date"] = str(item.get("saved_at") or item.get("date") or "")
        messages.append(message)
    if not messages:
        return None, "NO_MESSAGES_FOUND"
    messages.sort(key=lambda item: _message_timestamp(item) or 0.0, reverse=True)
    # 重认证的通知邮件可能比验证码晚到。取码时从返回列表里选最新含 OTP
    # 的 OpenAI 邮件，后续仍用发码时间和旧码水位过滤，不能拿旧码充数。
    for message in messages:
        if looks_like_openai_email(message) and extract_otp(message):
            return message, ""
    return next((item for item in messages if looks_like_openai_email(item)), messages[0]), ""


def _query_web_origin(account: ICloudEmailAccount) -> str | None:
    """Return the allow-listed origin that serves full query.php message HTML.

    ``query.php`` intentionally returns only a plain-text body.  The provider's
    web viewer uses a credential-bound HTTP session and a separate detail
    endpoint to retrieve the original HTML.  Never post mailbox credentials to
    an arbitrary imported query.php host: this richer adapter is enabled only
    for the known HTTPS service origin.
    """
    if _query_url_record(account.pickup_url, expected_email=account.email) is None:
        return None
    parsed = urlparse(str(account.pickup_url or "").strip())
    try:
        host = str(parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() != "https" or host not in _QUERY_WEB_HOSTS:
        return None
    if parsed.username or parsed.password or port not in (None, 443):
        return None
    return f"https://{host}"


def _fetch_query_web_messages(
    account: ICloudEmailAccount, *, limit: int = 20,
) -> list[dict]:
    """Fetch query-provider summaries and enrich them with original HTML."""
    origin = _query_web_origin(account)
    if origin is None:
        return []
    timeout = max(5, int(getattr(_email_cfg, "ICLOUD_REQUEST_TIMEOUT", 20) or 20))
    bounded_limit = max(1, min(20, int(limit or 20)))
    headers = {
        "Accept": "application/json",
        "Cache-Control": "no-cache",
        "User-Agent": "gpt-register/1.0",
    }
    try:
        with requests.Session() as session:
            response = session.post(
                f"{origin}/public/search-emails.php",
                json={"credentials": f"{account.email}----{account.token}"},
                headers=headers,
                timeout=timeout,
            )
            try:
                payload = response.json()
            except ValueError as exc:
                raise ICloudMailError(
                    f"iCloud Query Web 返回非 JSON 响应: HTTP {response.status_code}"
                ) from exc
            if not isinstance(payload, dict):
                raise ICloudMailError(
                    f"iCloud Query Web 返回格式错误: HTTP {response.status_code}"
                )
            if response.status_code in {400, 401, 403}:
                raise ICloudMailError("iCloud Query Web 凭证无效")
            raw_status = payload.get("status")
            success = raw_status is True or raw_status == 1 or (
                isinstance(raw_status, str)
                and raw_status.strip().lower() in {"true", "1", "success", "ok"}
            )
            if response.status_code != 200 or not success:
                detail = str(payload.get("message") or payload.get("error") or "").strip()
                suffix = f": {detail[:160]}" if detail else ""
                raise ICloudMailError(
                    f"iCloud Query Web 请求失败: HTTP {response.status_code}{suffix}"
                )

            summaries = payload.get("emails")
            if not isinstance(summaries, list):
                raise ICloudMailError("iCloud Query Web 响应中 emails 不是数组")
            messages: list[dict] = []
            for raw_summary in summaries[:bounded_limit]:
                if not isinstance(raw_summary, dict):
                    continue
                message = dict(raw_summary)
                message_id = str(message.get("id") or "").strip()
                message["date"] = str(
                    message.get("date") or message.get("created_at") or ""
                )
                message["text"] = str(
                    message.get("text") or message.get("snippet")
                    or message.get("body_excerpt") or ""
                )
                if message_id and len(message_id) <= 256:
                    detail_response = session.get(
                        f"{origin}/public/get-email-body.php",
                        params={"id": message_id},
                        headers=headers,
                        timeout=timeout,
                    )
                    if detail_response.status_code == 200:
                        try:
                            detail_payload = detail_response.json()
                        except ValueError:
                            detail_payload = None
                        if isinstance(detail_payload, dict):
                            detail_id = str(detail_payload.get("id") or message_id).strip()
                            if not detail_id or detail_id == message_id:
                                message.update({
                                    key: value for key, value in detail_payload.items()
                                    if key not in {"html", "htmlBody", "html_body"}
                                })
                                message["html"] = str(
                                    detail_payload.get("htmlBody")
                                    or detail_payload.get("html_body") or ""
                                )
                messages.append(message)
    except ICloudMailError:
        raise
    except requests.RequestException as exc:
        raise ICloudMailError(
            f"iCloud Query Web 请求失败: {type(exc).__name__}: {urlparse(origin).hostname or 'query endpoint'}"
        ) from exc
    messages.sort(key=lambda item: _message_timestamp(item) or 0.0, reverse=True)
    return messages


def list_messages(email: str, *, limit: int = 20) -> list[dict]:
    """Return recent iCloud messages, retaining HTML when the provider allows it."""
    account = get_account_context(email)
    if account is None or (not account.token and not _uses_generic_api(account)):
        raise ICloudMailError(f"iCloud 邮箱不存在或取件凭证为空: {email}")
    if _query_web_origin(account):
        return _fetch_query_web_messages(account, limit=limit)
    if _uses_generic_api(account):
        message = _fetch_generic_api_message(account)
        return [message] if isinstance(message, dict) else []
    message, _reason = _fetch_latest(account)
    return [message] if isinstance(message, dict) else []


def _uses_generic_api(account: ICloudEmailAccount) -> bool:
    return str(account.protocol or "").strip().lower() == "generic_api"


def _fetch_generic_api_message(account: ICloudEmailAccount) -> dict | None:
    """Fetch the full generic-API mail, even when it contains no OTP.

    Some iCloud pickup endpoints return Team invitations under ``data.body``
    with ``code: null``.  OTP-only normalization previously discarded that
    mail before the Team invitation scanner could inspect its HTML.
    """
    from core.generic_api_mail_client import _json_response_email, mask_code_url

    request_url = str(account.pickup_url or "").strip()
    timeout = max(5, int(getattr(_email_cfg, "ICLOUD_REQUEST_TIMEOUT", 20) or 20))
    try:
        response = requests.get(
            request_url,
            headers={
                "Accept": "application/json,text/plain,*/*",
                "Cache-Control": "no-cache",
                "User-Agent": "gpt-register/1.0",
            },
            timeout=timeout,
            verify=False,
        )
    except requests.RequestException as exc:
        raise ICloudMailError(
            f"iCloud 通用 API 请求失败: {type(exc).__name__}: {urlparse(request_url).hostname or 'endpoint'}"
        ) from exc
    if response.status_code != 200:
        raise ICloudMailError(
            f"iCloud 通用 API 请求失败: HTTP {response.status_code}: {mask_code_url(request_url)}"
        )

    text = response.text or ""
    response_email = _json_response_email(text)
    if response_email and response_email.lower() != account.email.lower():
        raise ICloudMailError(
            f"iCloud 通用 API 返回了其他邮箱的数据: expected={account.email}, actual={response_email}"
        )
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    raw_mail = next((
        value for value in (
            payload.get("mail"), payload.get("message"), payload.get("data"),
        ) if isinstance(value, dict)
    ), None)
    message = dict(raw_mail) if isinstance(raw_mail, dict) else {}
    body = str(
        message.get("body") or message.get("htmlBody") or message.get("html")
        or message.get("content") or message.get("text") or ""
    )
    code = str(message.get("code") or payload.get("code") or "").strip()
    if not message and not body and not code and not text.strip():
        return None
    date = str(
        message.get("date") or message.get("sentAt") or message.get("ingestedAt") or ""
    ).strip()
    uid = str(message.get("uid") or message.get("id") or "").strip()
    if not uid:
        uid = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:24]
    message.update({
        "mailbox": str(message.get("mailbox") or "generic_api"),
        "uid": uid,
        "from": str(
            message.get("from") or message.get("sender")
            or "ChatGPT <noreply@tm.openai.com>"
        ),
        "subject": str(message.get("subject") or "Your temporary ChatGPT login code"),
        "to": str(message.get("to") or response_email or account.email),
        "date": date,
        "ingestedAt": str(message.get("ingestedAt") or date),
        "text": str(message.get("text") or body or (f"verification code: {code}" if code else text)),
        "html": str(message.get("html") or message.get("htmlBody") or body),
        "genericApi": True,
    })
    if code:
        message["code"] = code
    return message


def _fetch_generic_api_latest(account: ICloudEmailAccount) -> tuple[dict | None, str]:
    from core.generic_api_mail_client import _extract_code

    message = _fetch_generic_api_message(account)
    if not isinstance(message, dict):
        return None, "NO_MESSAGES_FOUND"
    code = _extract_code(json.dumps(message, ensure_ascii=False))
    if not code:
        return None, "NO_MESSAGES_FOUND"
    message["code"] = code
    return message, ""


def _fetch_latest(account: ICloudEmailAccount) -> tuple[dict | None, str]:
    if _uses_generic_api(account):
        return _fetch_generic_api_latest(account)
    query_url = _query_account_url(account)
    if query_url:
        return _fetch_query_latest(account, query_url)
    share_record = _share_account_record(account)
    if share_record:
        return _fetch_share_latest(account, share_record)
    sq_record = _sq_account_record(account)
    if sq_record:
        return _fetch_sq_latest(account, sq_record)
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {account.token}",
        "X-Mailbox-Email": account.email,
        "User-Agent": "gpt-register/1.0",
    }
    timeout = max(5, int(getattr(_email_cfg, "ICLOUD_REQUEST_TIMEOUT", 20) or 20))
    try:
        response = requests.get(_api_url(), headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        raise ICloudMailError(f"FlySMS 请求失败: {type(exc).__name__}: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise ICloudMailError(f"FlySMS 返回非 JSON 响应: HTTP {response.status_code}") from exc
    if not isinstance(payload, dict):
        raise ICloudMailError(f"FlySMS 返回格式错误: HTTP {response.status_code}")

    code = str(payload.get("code") or "").strip().upper()
    if code == "NO_MESSAGES_FOUND" or str(payload.get("error") or "").strip() == "No messages found":
        return None, "NO_MESSAGES_FOUND"
    if response.status_code != 200:
        message = str(payload.get("error") or payload.get("message") or f"HTTP {response.status_code}")
        raise ICloudMailError(f"FlySMS 请求失败: {message[:200]}")

    response_email = str(payload.get("email") or "").strip()
    if response_email and response_email.lower() != account.email.lower():
        raise ICloudMailError("FlySMS token 返回了其他邮箱的数据")
    message = payload.get("message")
    if not isinstance(message, dict):
        return None, "响应中没有 message"
    return message, ""


def _check_stop_requested(email: str) -> None:
    from core.registration_service import check_stop_requested as check_registration_stop
    from core.codex_retry_service import check_stop_requested as check_codex_stop

    check_registration_stop()
    check_codex_stop(email)


def _sleep_with_stop(email: str, seconds: float) -> None:
    remaining = max(0.0, float(seconds or 0.0))
    while remaining > 0:
        _check_stop_requested(email)
        step = min(0.5, remaining)
        time.sleep(step)
        remaining -= step
    _check_stop_requested(email)


def import_from_file(path: str | Path | None = None) -> tuple[int, int]:
    from core.db import import_icloud_emails

    source = Path(path) if path else _accounts_file()
    if not source.is_absolute():
        source = _PROJECT_ROOT / source
    if not source.exists():
        return 0, 0
    records = []
    invalid = 0
    for raw in source.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        record = parse_import_line(line)
        if record is None:
            invalid += 1
        else:
            record["original_email_line"] = line
            records.append(record)
    inserted, skipped = import_icloud_emails(records)
    return inserted, skipped + invalid


def pick_account(
    *, mode: str = "single", alias_limit: int | None = None,
    job_id: int | None = None, batch_id: str | None = None,
) -> ICloudEmailAccount:
    if str(mode or "single").strip().lower() != "single":
        raise ICloudMailError("iCloud 邮箱池仅支持 single 模式")
    from core.db import claim_icloud_email, icloud_email_pool_summary

    prepare_started = time.perf_counter()
    inserted, skipped = import_from_file()
    import_finished = time.perf_counter()
    if inserted:
        logger.info("[iCloud] 已自动导入 %s 个邮箱（跳过 %s 个）", inserted, skipped)
    row = claim_icloud_email(job_id=job_id, batch_id=batch_id)
    claim_finished = time.perf_counter()
    if row is None:
        raise ICloudMailError(f"iCloud 邮箱池没有可用账号: {icloud_email_pool_summary()}")
    account = ICloudEmailAccount(
        email=row["email"], token=row["token"], pickup_url=row["pickup_url"],
        allocation_id=row.get("allocation_id"), protocol=str(row.get("protocol") or ""),
    )
    _CONTEXT_CACHE[account.email.lower()] = account
    # 记录领取邮箱时已经存在的最新邮件。部分 iCloud 接口不提供可靠的
    # 时间戳，单靠 after_ts 会把旧验证码误判为新码；用消息 identity 做
    # 水位可以在“发码接口返回 200 但实际未发新邮件”时安全等待，而不是
    # 立即提交上一轮验证码。
    try:
        message, _ = _fetch_latest(account)
        code = extract_otp(message or {}) or ""
        if message and code:
            _BASELINES[account.email.lower()] = (_message_identity(message), code)
            logger.info("[iCloud] 已记录领取前旧码: %s", account.email)
    except Exception as exc:
        logger.debug("[iCloud] 领取前旧码探测失败（不阻断）: %s", exc)
    logger.info("[iCloud] 选中邮箱: %s（allocation=%s）", account.email, account.allocation_id or "-")
    logger.info(
        "[iCloud] 分配阶段耗时：导入=%.3fs 领取=%.3fs 旧码基线=%.3fs",
        import_finished - prepare_started, claim_finished - import_finished,
        time.perf_counter() - claim_finished,
    )
    return account


def get_account_context(email: str) -> ICloudEmailAccount | None:
    key = str(email or "").strip().lower()
    if key in _CONTEXT_CACHE:
        return _CONTEXT_CACHE[key]
    from core.db import get_icloud_email_by_email

    row = get_icloud_email_by_email(email)
    if row is None:
        return None
    account = ICloudEmailAccount(
        email=str(row.get("email") or email), token=str(row.get("token") or ""),
        pickup_url=str(row.get("pickup_url") or ""), allocation_id=row.get("allocation_id"),
        protocol=str(row.get("protocol") or ""),
    )
    _CONTEXT_CACHE[key] = account
    return account


def capture_otp_baseline(email: str) -> bool:
    """在触发新验证码前记录当前最新邮件的 identity/code 水位。

    iCloud 的部分取件接口缺少可靠的邮件时间戳，因此 Codex 补跑不能只
    依赖 ``after_ts``；发送前快照可以排除同一封旧邮件，即使它的时间字段为空。
    """
    account = get_account_context(email)
    if account is None or (not account.token and not _uses_generic_api(account)):
        return False
    try:
        message, _ = _fetch_latest(account)
        code = extract_otp(message or {}) or ""
        if not message or not code:
            return False
        _BASELINES[str(email or "").strip().lower()] = (
            _message_identity(message),
            code,
        )
        return True
    except Exception as exc:
        logger.debug("[iCloud] 发码前旧码快照失败（不阻断）: %s", exc)
        return False


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    from core.db import release_icloud_email

    release_icloud_email(email, status=status, note=note)
    key = str(email or "").strip().lower()
    _CONTEXT_CACHE.pop(key, None)
    _BASELINES.pop(key, None)
    _SHARE_CURSORS.pop(key, None)
    _SHARE_INITIALIZED.discard(key)


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
    exclude_codes: set[str] | None = None,
) -> str:
    account = get_account_context(email)
    if account is None or (not account.token and not _uses_generic_api(account)):
        raise ICloudMailError(f"iCloud 邮箱不存在或取码凭证为空: {email}")

    deadline = time.time() + int(max_wait or _email_cfg.OTP_MAX_WAIT)
    interval = max(1, int(poll_interval or _email_cfg.OTP_POLL_INTERVAL))
    # FlySMS 暴露最新邮件；Query API 返回最近若干封。首个符合条件的 OTP 立即返回。
    settle = max(0, int(settle_seconds if settle_seconds is not None else 0))
    excluded = {str(code) for code in (exclude_codes or set()) if code}
    baseline_identity, baseline_code = _BASELINES.get(email.lower(), ("", ""))
    best_code = ""
    best_identity = ""
    settle_until: float | None = None
    last_reason = "no_messages"
    last_http_status: int | None = None
    last_exception: Exception | None = None
    credential_verified = False
    consecutive_invalid_credentials = 0
    logger.info("[iCloud] 开始轮询: email=%s 最长=%ss settle=%ss", email, int(deadline - time.time()), settle)

    while time.time() < deadline:
        _check_stop_requested(email)
        try:
            from core.db import renew_email_allocation_lease
            renew_email_allocation_lease(email)
        except Exception:
            logger.debug("[iCloud] 邮箱租约续期失败", exc_info=True)
        try:
            message, no_message_reason = _fetch_latest(account)
            last_http_status = None
            last_exception = None
            if message is None:
                last_reason = "no_messages"
                if no_message_reason == "NO_MESSAGES_FOUND":
                    credential_verified = True
                    consecutive_invalid_credentials = 0
            elif not looks_like_openai_email(message):
                credential_verified = True
                consecutive_invalid_credentials = 0
                last_reason = "no_openai_mail"
            else:
                credential_verified = True
                consecutive_invalid_credentials = 0
                identity = _message_identity(message)
                timestamp = _message_timestamp(message)
                code = extract_otp(message) or ""
                fresh_after_request = bool(
                    identity
                    and after_ts is not None
                    and timestamp is not None
                    and timestamp >= float(after_ts) - 5
                )
                # 对已经提交过的数字验证码使用严格时间边界。普通新码保留 5 秒
                # 时钟宽限，但旧码不能借此宽限再次命中同一封旧邮件。
                excluded_code_is_fresh = bool(
                    identity
                    and after_ts
                    and timestamp is not None
                    and timestamp >= float(after_ts)
                )
                if after_ts is not None and timestamp is not None and timestamp < float(after_ts) - 30:
                    last_reason = "old_message"
                elif identity and baseline_identity and identity == baseline_identity:
                    last_reason = "baseline_message"
                elif code and baseline_code and code == baseline_code and not fresh_after_request:
                    last_reason = "baseline_code"
                elif code in excluded and not excluded_code_is_fresh:
                    last_reason = "excluded_code"
                elif code:
                    now = time.time()
                    if code != best_code or identity != best_identity:
                        best_code = code
                        best_identity = identity
                        settle_until = now + settle
                        logger.info(
                            "[iCloud] 锁定候选 OTP=%s uid=%s mail_time=%s time_basis=%s after_ts=%s，等待 settle",
                            code[:2] + "****", message.get("uid") or "-",
                            timestamp, "saved_at" if message.get("saved_at") else "message_date", after_ts,
                        )
                else:
                    last_reason = "no_code"
        except ICloudMailError as exc:
            last_exception = exc
            status_match = re.search(r"\bHTTP\s+([1-5]\d{2})\b", str(exc), re.IGNORECASE)
            last_http_status = int(status_match.group(1)) if status_match else None
            if any(marker in str(exc) for marker in (
                "Invalid pickup credentials", "INVALID_PICKUP_CREDENTIALS", "Query API 凭证无效",
                "Share URL 凭证无效", "SQ API 凭证无效",
            )):
                consecutive_invalid_credentials += 1
                last_reason = "mail_credentials_invalid"
                if not credential_verified and consecutive_invalid_credentials >= 3:
                    raise
                logger.warning(
                    "[iCloud] pickup 凭证暂时被拒绝，继续轮询: email=%s verified=%s attempt=%s",
                    email, credential_verified, consecutive_invalid_credentials,
                )
            else:
                last_reason = "mail_api_error"
        except Exception as exc:
            last_exception = exc
            last_http_status = None
            last_reason = "mail_api_error"

        # pickup 请求返回时任务可能已停止；必须在返回候选 OTP 前复查。
        _check_stop_requested(email)
        now = time.time()
        if best_code and settle_until is not None and now >= settle_until:
            _BASELINES[email.lower()] = (best_identity, best_code)
            logger.info("[iCloud] settle 完成，返回 OTP=%s", best_code[:2] + "****")
            return best_code
        _sleep_with_stop(email, min(interval, max(0.0, deadline - now)))

    if best_code:
        _check_stop_requested(email)
        _BASELINES[email.lower()] = (best_identity, best_code)
        return best_code
    raise ICloudOtpTimeoutError(last_reason, http_status=last_http_status) from last_exception
