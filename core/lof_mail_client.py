# -*- coding: utf-8 -*-
"""LOF 临时邮箱 API 客户端。

LOF 的公开接口没有创建邮箱动作，而是对四个域名提供收件地址查询。
因此注册任务在本地生成随机地址，收码时按原始收件地址查询 API。
"""
from __future__ import annotations

import logging
import random
import re
import secrets
import string
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

import requests

from config import email as _email_cfg
from core.otp_utils import extract_otp, looks_like_openai_email
from core.otp_poll_control import check_stop_requested, sleep_with_stop

logger = logging.getLogger(__name__)

BASE_URL = "https://mail.lof.pub/mail-api"
DEFAULT_DOMAINS = ("lof.pub", "zeanl.com", "ssmmail.com", "sinas3.net")
REQUEST_TIMEOUT = 20
MAX_BATCH_RECIPIENTS = 100
MESSAGE_LIMIT = 100
_EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+)$")
_CODE_RE = re.compile(r"^\d{6}$")
_VERIFICATION_HINTS = (
    "verification code",
    "temporary chatgpt",
    "verify your email",
    "one-time code",
    "otp",
    "验证码",
    "确认码",
    "認証コード",
    "検証コード",
    "인증 코드",
    "kode verifikasi",
    "kode sementara",
    "kode sekali pakai",
)
_PLAN_HINTS = (
    "your new plan",
    "successfully subscribed",
    "subscription",
    "manage your subscription",
    "billing",
    "invoice",
    "receipt",
    "payment",
    "套餐",
    "订阅",
    "账单",
    "发票",
)


class LofMailError(RuntimeError):
    """LOF 服务请求、配置或取码失败。"""

    def __init__(self, message: str, *, status: int | None = None, payload: Any = None):
        super().__init__(message)
        self.status = status
        self.payload = payload


class LofMailHTTPError(LofMailError):
    """LOF 返回非成功 HTTP 状态。"""


@dataclass(frozen=True)
class LofMailAccount:
    email: str
    domain: str


_CONTEXT_CACHE: dict[str, LofMailAccount] = {}


def _cache_key(email: str) -> str:
    return str(email or "").strip().lower()


def _base_url(base_url: str | None = None) -> str:
    value = base_url if base_url is not None else getattr(_email_cfg, "LOF_MAIL_API_BASE", BASE_URL)
    value = str(value or BASE_URL).strip().rstrip("/")
    if not value:
        raise LofMailError("LOF Mail API 地址未配置")
    return value


def _token(token: str | None = None) -> str:
    value = token if token is not None else getattr(_email_cfg, "LOF_MAIL_API_TOKEN", "")
    value = str(value or "").strip()
    if not value:
        raise LofMailError(
            "LOF Mail API Token 未配置，请填写 LOF_MAIL_API_TOKEN（配置 → 邮箱 / OTP）。"
        )
    return value


def _timeout() -> float:
    try:
        return max(1.0, float(getattr(_email_cfg, "LOF_MAIL_REQUEST_TIMEOUT", REQUEST_TIMEOUT) or REQUEST_TIMEOUT))
    except (TypeError, ValueError):
        return float(REQUEST_TIMEOUT)


def _normalize_domains(raw: Any) -> list[str]:
    if raw is None:
        parts: list[Any] = []
    elif isinstance(raw, str):
        parts = raw.replace(";", "\n").replace(",", "\n").splitlines()
    else:
        try:
            parts = list(raw)
        except TypeError:
            parts = [raw]

    allowed = set(DEFAULT_DOMAINS)
    result: list[str] = []
    for item in parts:
        domain = str(item or "").strip().lower().lstrip("@")
        if domain in allowed and domain not in result:
            result.append(domain)
    return result


def configured_domains() -> list[str]:
    """返回配置中的 LOF 域名，并限制在平台公布的四个域名内."""
    configured = _normalize_domains(getattr(_email_cfg, "LOF_MAIL_DOMAINS", DEFAULT_DOMAINS))
    if configured:
        return configured
    # 空列表表示使用平台的固定域名默认值，而不是生成不可收信的地址。
    return list(DEFAULT_DOMAINS)


def _random_local_part(length: int | None = None) -> str:
    try:
        requested = int(length if length is not None else getattr(_email_cfg, "LOF_MAIL_RANDOM_LOCAL_LENGTH", 12))
    except (TypeError, ValueError):
        requested = 12
    length = max(6, min(32, requested))
    alphabet = string.ascii_lowercase + string.digits
    return random.choice(string.ascii_lowercase) + "".join(
        secrets.choice(alphabet) for _ in range(length - 1)
    )


def _validate_recipient(email: str) -> str:
    target = str(email or "").strip()
    match = _EMAIL_RE.fullmatch(target)
    if not match:
        raise LofMailError(f"LOF Mail 收件地址格式无效: {target!r}")
    return target


def _parse_message_time(raw: Any) -> float | None:
    """Parse LOF's ISO-8601 ``receivedAt`` value into a Unix timestamp."""
    if raw is None or raw == "":
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        pass
    text = str(raw).strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _flatten_address(value: Any) -> str:
    """Turn LOF's list-of-address objects into the shape used by otp_utils."""
    if isinstance(value, (list, tuple)):
        return ", ".join(part for part in (_flatten_address(item) for item in value) if part)
    if isinstance(value, dict):
        return " ".join(
            str(value.get(key) or "").strip()
            for key in ("name", "email", "address")
            if str(value.get(key) or "").strip()
        )
    return str(value or "").strip()


def _otp_message_item(message: Any) -> tuple[dict[str, Any], float | None] | None:
    if not isinstance(message, dict):
        return None
    item = {
        "id": message.get("id"),
        "from": _flatten_address(message.get("from")),
        "subject": str(message.get("subject") or ""),
        "text": str(message.get("text") or message.get("preview") or ""),
        "html": str(message.get("html") or message.get("body") or ""),
    }
    return item, _parse_message_time(
        message.get("receivedAt")
        or message.get("received_at")
        or message.get("createdAt")
        or message.get("created_at")
        or message.get("timestamp")
        or message.get("date")
    )


def _is_verification_message(item: dict[str, Any]) -> bool:
    """Exclude billing/plan emails that also contain unrelated numbers."""
    if not looks_like_openai_email(item):
        return False
    haystack = " ".join(
        str(item.get(key) or "").lower() for key in ("subject", "text", "html")
    )
    if any(hint in haystack for hint in _PLAN_HINTS):
        return False
    if any(hint in haystack for hint in _VERIFICATION_HINTS):
        return True

    # OpenAI localizes verification subjects. Keep a sender-based fallback so
    # an unlisted locale does not silently discard a real six-digit OTP.
    sender = str(item.get("from") or "").lower()
    trusted_sender = re.search(
        r"@(?:[a-z0-9-]+\.)*(?:openai\.com|chatgpt\.com)\b",
        sender,
    )
    code = str(extract_otp(item) or "").strip()
    return bool(trusted_sender and _CODE_RE.fullmatch(code))


def _message_haystack(item: dict[str, Any]) -> str:
    return " ".join(
        str(item.get(key) or "").lower() for key in ("from", "subject", "text", "html")
    )


def _is_plan_message(item: dict[str, Any]) -> bool:
    """识别会在正文中带出无关数字的套餐/账单邮件。"""
    return any(hint in _message_haystack(item) for hint in _PLAN_HINTS)


def _code_payload_is_relevant(payload: Any) -> bool:
    """判断 ``/v1/code`` 的快捷结果是否确实是验证邮件。"""
    normalized = _otp_message_item(payload)
    if normalized is None:
        return True
    item, _ = normalized
    # 有些部署只返回 recipient/code，没有邮件元数据；这时保留旧的快捷路径。
    if not _message_haystack(item).strip():
        return True
    if _is_plan_message(item):
        return False
    return _is_verification_message(item)


def _extract_message_code(message: Any) -> tuple[str | None, float | None]:
    normalized = _otp_message_item(message)
    if normalized is None:
        return None, None
    item, received_at = normalized
    if not _is_verification_message(item):
        return None, received_at
    code = str(extract_otp(item) or "").strip()
    return (code if _CODE_RE.fullmatch(code) else None), received_at


def _message_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        messages = payload.get("messages")
    else:
        messages = payload
    if not isinstance(messages, list):
        raise LofMailError("LOF Mail /v1/messages 响应缺少 messages 数组")
    return [message for message in messages if isinstance(message, dict)]


def _fetch_message_code(
    email: str,
    *,
    after_ts: float | None = None,
    exclude_codes: set[str] | None = None,
) -> tuple[str | None, bool]:
    """Return the newest relevant six-digit code and whether timestamps exist."""
    payload = list_messages(email, limit=MESSAGE_LIMIT, body=True)
    messages = _message_list(payload)
    excluded = {str(code or "").strip() for code in (exclude_codes or set()) if str(code or "").strip()}
    parsed: list[tuple[float, int, dict[str, Any]]] = []
    has_timestamp = False
    for index, message in enumerate(messages):
        received_at = _parse_message_time(
            message.get("receivedAt")
            or message.get("received_at")
            or message.get("createdAt")
            or message.get("created_at")
            or message.get("timestamp")
            or message.get("date")
        )
        if received_at is not None:
            has_timestamp = True
        if after_ts is not None:
            # 没有时间戳的邮件无法证明是在本轮重认证之后到达的；让调用方
            # 在这种情况下回退到兼容的 /v1/code 接口，而不是误提交旧码。
            if received_at is None or received_at < float(after_ts) - 30:
                continue
        parsed.append((received_at if received_at is not None else float("-inf"), index, message))

    for _, _, message in sorted(parsed, key=lambda row: (row[0], -row[1]), reverse=True):
        code, received_at = _extract_message_code(message)
        if not code:
            continue
        if code in excluded and (
            after_ts is None
            or received_at is None
            or received_at < float(after_ts)
        ):
            # 列表按时间倒序；最新相关邮件已经是本轮用过的旧码时，
            # 不能回退到更旧的另一封验证码。
            break
        return code, has_timestamp
    return None, has_timestamp


def _response_payload(response: Any, path: str) -> Any:
    try:
        return response.json()
    except (TypeError, ValueError) as exc:
        body = str(getattr(response, "text", "") or "")[:200]
        raise LofMailError(
            f"LOF Mail 响应不是 JSON ({path}): HTTP {getattr(response, 'status_code', '?')}; {body}"
        ) from exc


def _request_json(
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    auth: bool = True,
) -> Any:
    headers = {"Accept": "application/json"}
    if auth:
        headers["Authorization"] = f"Bearer {_token()}"
    if json_body is not None:
        headers["Content-Type"] = "application/json"

    url = _base_url() + "/" + str(path or "").lstrip("/")
    try:
        request_kwargs: dict[str, Any] = {
            "headers": headers,
            "timeout": _timeout(),
        }
        if params is not None:
            request_kwargs["params"] = params
        if str(method).upper() == "GET":
            response = requests.get(url, **request_kwargs)
        elif str(method).upper() == "POST":
            request_kwargs["json"] = json_body
            response = requests.post(url, **request_kwargs)
        else:
            raise LofMailError(f"LOF Mail 不支持 HTTP 方法: {method}")
    except requests.RequestException as exc:
        raise LofMailError(f"LOF Mail 请求失败 ({path}): {type(exc).__name__}: {exc}") from exc

    payload = _response_payload(response, path)
    status = int(getattr(response, "status_code", 0) or 0)
    if status < 200 or status >= 300:
        message = ""
        if isinstance(payload, dict):
            message = str(payload.get("error") or payload.get("message") or "").strip()
        if not message:
            message = str(getattr(response, "text", "") or payload)[:200]
        raise LofMailHTTPError(
            f"LOF Mail 请求失败 ({path}): HTTP {status}; {message}",
            status=status,
            payload=payload,
        )
    return payload


def pick_account() -> LofMailAccount:
    """在 LOF 支持域名中生成并缓存一个随机收件地址。"""
    _token()  # 在领取阶段尽早暴露配置错误，而不是等到 OTP 阶段才失败。
    domain = random.choice(configured_domains())
    email = f"{_random_local_part()}@{domain}"
    account = LofMailAccount(email=email, domain=domain)
    _CONTEXT_CACHE[_cache_key(email)] = account
    logger.info("[LOF Mail] 已生成临时邮箱: %s", email)
    return account


def get_account_context(email: str) -> LofMailAccount | None:
    """返回当前进程已生成的 LOF 邮箱上下文。"""
    return _CONTEXT_CACHE.get(_cache_key(email))


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    """LOF 地址无需远端释放；任务结束时清理本进程上下文。"""
    _CONTEXT_CACHE.pop(_cache_key(email), None)
    logger.info("[LOF Mail] 已释放临时邮箱: %s（status=%s, note=%s）", email, status, note or "")


def _fetch_code_endpoint(target: str) -> tuple[str | None, Any, str | None, bool]:
    """读取快捷接口，返回 ``(可用验证码, 原始响应, 原始 code, 格式有效)``。"""
    try:
        payload = _request_json("GET", "/v1/code", params={"to": target})
    except LofMailHTTPError as exc:
        if exc.status == 404 and isinstance(exc.payload, dict) and exc.payload.get("error") == "code_not_found":
            return None, exc.payload, None, True
        raise

    if not isinstance(payload, dict):
        raise LofMailError("LOF Mail /v1/code 响应不是对象")
    if payload.get("error") == "code_not_found":
        return None, payload, None, True
    raw_code = payload.get("code")
    if raw_code is None or str(raw_code).strip() == "":
        return None, payload, None, True
    code = str(raw_code).strip()
    format_ok = bool(_CODE_RE.fullmatch(code))
    if format_ok and _code_payload_is_relevant(payload):
        return code, payload, code, True
    return None, payload, code, format_ok


def _invalid_code_error(raw_code: str, payload: Any) -> LofMailError:
    return LofMailError(f"LOF Mail 返回非法验证码: {raw_code!r}", payload=payload)


def fetch_code(email: str) -> str | None:
    """查询一个收件地址当前最新验证码；必要时回退到完整邮件列表。"""
    target = _validate_recipient(email)
    code, payload, raw_code, format_ok = _fetch_code_endpoint(target)
    if code:
        return code

    # /v1/code 只返回最新邮件里的数字。套餐通知常常排在验证邮件之后，
    # 因此无论是 4 位数字、无关的 6 位数字还是空结果，都尝试从正文找真正的 OTP。
    fallback_error: LofMailError | None = None
    try:
        message_code, _ = _fetch_message_code(target)
    except LofMailError as exc:
        fallback_error = exc
        message_code = None
    if message_code:
        return message_code

    # 已知是套餐/营销邮件时返回空，让轮询继续等待新验证邮件；对未知格式仍保留
    # 原来的异常语义，便于调用方区分服务响应异常。
    endpoint_item = _otp_message_item(payload)
    is_irrelevant = endpoint_item is not None and _is_plan_message(endpoint_item[0])
    if raw_code is not None and not format_ok and not is_irrelevant:
        error = _invalid_code_error(raw_code, payload)
        if fallback_error is not None:
            error.__cause__ = fallback_error
        raise error
    if fallback_error is not None and raw_code is None:
        # /v1/code 没有验证码时，兼容旧行为：一次邮件列表格式异常不应让
        # 轮询直接失败，下一轮仍会重试。
        return None
    return None


def list_messages(email: str, *, limit: int = 10, body: bool = True) -> Any:
    """查询收件地址的邮件列表，``limit`` 最大为 100。"""
    target = _validate_recipient(email)
    try:
        requested_limit = int(limit)
    except (TypeError, ValueError) as exc:
        raise LofMailError("LOF Mail messages 的 limit 必须是整数") from exc
    if requested_limit < 1 or requested_limit > MAX_BATCH_RECIPIENTS:
        raise LofMailError(f"LOF Mail messages 的 limit 必须在 1~{MAX_BATCH_RECIPIENTS} 之间")
    return _request_json(
        "GET",
        "/v1/messages",
        params={"to": target, "limit": requested_limit, "body": 1 if body else 0},
    )


def fetch_codes(recipients: Iterable[str]) -> Any:
    """批量查询验证码，最多接收 100 个原始收件地址。"""
    if isinstance(recipients, (str, bytes)):
        raise LofMailError("LOF Mail codes 的 recipients 必须是地址列表")
    try:
        targets = [_validate_recipient(item) for item in recipients]
    except TypeError as exc:
        raise LofMailError("LOF Mail codes 的 recipients 必须是地址列表") from exc
    if not targets:
        raise LofMailError("LOF Mail codes 至少需要一个收件地址")
    if len(targets) > MAX_BATCH_RECIPIENTS:
        raise LofMailError(f"LOF Mail codes 最多支持 {MAX_BATCH_RECIPIENTS} 个收件地址")
    return _request_json("POST", "/v1/codes", json_body={"recipients": targets})


def health_check() -> Any:
    """检查 LOF 服务健康状态；该请求不携带 Authorization。"""
    return _request_json("GET", "/health", auth=False)


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
    exclude_codes: set[str] | None = None,
) -> str:
    """轮询 LOF，返回最新的六位验证码。

    有 ``after_ts`` 时优先读取带 ``receivedAt`` 的邮件列表，以排除重认证
    开始前的旧验证码。列表接口不可用或没有时间戳时，才回退到快捷接口。
    """
    target = _validate_recipient(email)
    _token()  # 已持久化的 LOF 地址在服务重启后也应立即报告缺少 Token。
    try:
        wait_seconds = int(max_wait if max_wait is not None else getattr(_email_cfg, "OTP_MAX_WAIT", 90))
    except (TypeError, ValueError):
        wait_seconds = 90
    try:
        interval = int(poll_interval if poll_interval is not None else getattr(_email_cfg, "OTP_POLL_INTERVAL", 3))
    except (TypeError, ValueError):
        interval = 3
    try:
        settle = int(settle_seconds if settle_seconds is not None else getattr(_email_cfg, "OTP_SETTLE_SECONDS", 5))
    except (TypeError, ValueError):
        settle = 5
    wait_seconds = max(0, wait_seconds)
    interval = max(1, interval)
    settle = max(0, settle)
    deadline = time.monotonic() + wait_seconds
    excluded = {
        str(code or "").strip()
        for code in (exclude_codes or set())
        if str(code or "").strip()
    }
    candidate: str | None = None
    candidate_seen_at: float | None = None
    last_error = "尚未收到验证码"

    logger.info("[LOF Mail] 开始轮询邮箱 %s，最长 %ss", target, wait_seconds)
    while time.monotonic() <= deadline:
        check_stop_requested(target)
        # A transient API failure must not leave ``code`` undefined below.
        code: str | None = None
        code_from_fresh_messages = False
        fetch_failed = False
        try:
            if after_ts is None:
                code = fetch_code(target)
            else:
                # The code endpoint exposes only the number from the newest mail;
                # it can therefore mistake a plan notice for an OTP.  The message
                # list has timestamps and full bodies, so use it as the authoritative
                # source whenever it is available.
                try:
                    code, has_timestamp = _fetch_message_code(
                        target,
                        after_ts=after_ts,
                        exclude_codes=excluded,
                    )
                    code_from_fresh_messages = bool(code)
                except LofMailError as message_exc:
                    # Keep the fast endpoint as a compatibility fallback for older
                    # LOF deployments that do not expose /v1/messages reliably.
                    last_error = str(message_exc)
                    code = _fetch_code_endpoint(target)[0]
                    has_timestamp = False
                if not code and not has_timestamp:
                    code = _fetch_code_endpoint(target)[0]
        except LofMailHTTPError as exc:
            # 鉴权/参数错误不会因等待而恢复；429 和 5xx 仍按轮询策略重试。
            if exc.status not in {404, 429} and exc.status is not None and 400 <= exc.status < 500:
                raise
            fetch_failed = True
            last_error = str(exc)
        except LofMailError as exc:
            fetch_failed = True
            last_error = str(exc)
        except Exception as exc:  # 防止单次异常中断整个轮询窗口
            fetch_failed = True
            last_error = f"{type(exc).__name__}: {exc}"
        check_stop_requested(target)
        if not fetch_failed:
            if not code:
                last_error = "尚未收到验证码"
            elif code in excluded and not code_from_fresh_messages:
                last_error = "最新验证码仍是本轮已提交过的旧验证码"
            else:
                now = time.monotonic()
                if candidate != code:
                    candidate = code
                    candidate_seen_at = now
                    logger.info("[LOF Mail] 锁定 OTP 候选，等待 %ss 确认", settle)
                if settle == 0 or (candidate_seen_at is not None and now - candidate_seen_at >= settle):
                    return code

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sleep_with_stop(target, min(interval, remaining))

    if candidate:
        check_stop_requested(target)
        return candidate
    raise LofMailError(f"等待 LOF Mail 验证码超时: {target}; {last_error}")


__all__ = [
    "BASE_URL",
    "DEFAULT_DOMAINS",
    "LofMailAccount",
    "LofMailError",
    "LofMailHTTPError",
    "configured_domains",
    "fetch_code",
    "fetch_codes",
    "fetch_latest_otp",
    "get_account_context",
    "health_check",
    "list_messages",
    "pick_account",
    "release_account",
]
