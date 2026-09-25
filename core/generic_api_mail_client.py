# -*- coding: utf-8 -*-
"""
通用 API 取码邮箱客户端。

邮箱池导入格式：
    email----code_url
    code_url

仅提供 code_url 时，导入阶段会先请求一次接口，从 JSON 响应的 email 字段解析邮箱。
注册时领取 email；取码时直接 GET code_url，并从响应中提取 6 位验证码。
响应可以是纯文本、HTML 或 JSON，只要其中包含 6 位验证码即可。
"""
import json
import logging
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from config import email as _email_cfg
from core.otp_utils import extract_otp

logger = logging.getLogger(__name__)

_CODE_REGEX = re.compile(r"\b(\d{6})\b")
_EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_CONTEXT_WORDS = ("code", "verify", "verification", "验证码", "代码", "确认码", "認証", "コード")
_OTP_FIELD_KEYS = frozenset({
    "code", "otp", "verificationcode", "verifycode", "verification_code", "verify_code",
})
_JSON_IDENTITY_KEYS = frozenset({
    "email", "address", "to", "from", "sender", "recipient",
    "id", "uid", "scope", "date", "sentat", "mailboxreceivedat", "ingestedat",
    "time", "timestamp",
})
_CONTEXT_CACHE: dict[str, "GenericApiEmailAccount"] = {}
_OTP_BASELINES: dict[str, str] = {}
_HOST_LOCKS: dict[str, threading.Lock] = {}
_HOST_NEXT_AT: dict[str, float] = {}
_HOST_STATE_LOCK = threading.Lock()
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ACCOUNTS_FILE = _PROJECT_ROOT / "用于注册的API邮箱.txt"


class GenericApiMailError(RuntimeError):
    """通用 API 取码邮箱错误。"""


@dataclass
class GenericApiEmailAccount:
    email: str
    code_url: str
    base_email: str = ""
    allocation_id: int | None = None


def _normalized_json_key(value: object) -> str:
    return re.sub(r"[^a-z0-9_]", "", str(value or "").strip().lower())


def _flatten_json(obj, *, parent_key: str = "") -> str:
    """提取可能包含 OTP 的 JSON 文本，同时跳过邮箱、ID 和时间等身份字段。"""
    parts: list[str] = []
    def walk(x, key: str = ""):
        if isinstance(x, dict):
            for child_key, value in x.items():
                normalized = _normalized_json_key(child_key)
                if normalized in _JSON_IDENTITY_KEYS:
                    continue
                walk(value, normalized)
        elif isinstance(x, list):
            for v in x:
                walk(v, key)
        elif x is not None:
            parts.append(str(x))
    walk(obj, parent_key)
    return "\n".join(parts)


def _exact_otp(value: object) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int) and 100000 <= value <= 999999:
        return str(value)
    candidate = str(value).strip()
    return candidate if re.fullmatch(r"\d{6}", candidate) else None


def _find_structured_otp(obj) -> str | None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if _normalized_json_key(key) in _OTP_FIELD_KEYS:
                code = _exact_otp(value)
                if code:
                    return code
        for value in obj.values():
            code = _find_structured_otp(value)
            if code:
                return code
    elif isinstance(obj, list):
        for value in obj:
            code = _find_structured_otp(value)
            if code:
                return code
    return None


def _extract_code(text: str) -> str | None:
    """从纯文本/HTML/JSON 文本中提取 6 位 OTP。"""
    if not text:
        return None

    candidates_text: list[str] = []
    try:
        parsed = json.loads(text)
        # 新接口的顶层 code 是权威字段，必须先于邮箱名、邮件 ID 等数字处理。
        if isinstance(parsed, dict) and "code" in parsed:
            code = _exact_otp(parsed.get("code"))
            if code:
                return code
        code = _find_structured_otp(parsed)
        if code:
            return code
        candidates_text.append(_flatten_json(parsed))
    except Exception:
        candidates_text.append(text)

    for body in candidates_text:
        # 复用邮件 OTP 抽取逻辑。
        code = extract_otp({"text": body, "content": body, "subject": body[:200]})
        if code:
            return code

        codes = _CODE_REGEX.findall(body)
        if not codes:
            continue
        lower = body.lower()
        for code in codes:
            idx = lower.find(code)
            window = lower[max(0, idx - 80): idx + 86]
            if any(w.lower() in window for w in _CONTEXT_WORDS):
                return code
        return codes[-1]
    return None


def mask_code_url(raw_url: str) -> str:
    try:
        parsed = urlparse(str(raw_url or ""))
        path_parts = parsed.path.split("/")
        for index, part in enumerate(path_parts[:-1]):
            if part.lower() in {"code", "mail"} and path_parts[index + 1]:
                path_parts[index + 1] = "***"
                break
        netloc = parsed.netloc
        if "@" in netloc:
            netloc = "***:***@" + netloc.rsplit("@", 1)[1]
        query = [
            (key, "***" if value else "")
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunparse(parsed._replace(
            netloc=netloc,
            path="/".join(path_parts),
            query=urlencode(query),
            fragment="***" if parsed.fragment else "",
        ))
    except Exception:
        return "<invalid-url>"


def _validate_email(value: object, *, from_response: bool = False) -> str:
    email = str(value or "").strip()
    if not _EMAIL_REGEX.fullmatch(email):
        message = "接口响应缺少有效 email 字段" if from_response else "邮箱格式无效"
        raise GenericApiMailError(message)
    return email


def _validate_code_url(raw_url: object) -> str:
    code_url = str(raw_url or "").strip()
    parsed = urlparse(code_url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise GenericApiMailError("取码地址必须是有效的 HTTP(S) URL")
    return code_url


def _json_response_email(text: str) -> str | None:
    try:
        payload = json.loads(text or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    value = payload.get("email")
    if value is None and isinstance(payload.get("data"), dict):
        value = payload["data"].get("email")
    candidate = str(value or "").strip()
    return candidate or None


def _discover_email(code_url: str, *, timeout: float = 20.0) -> str:
    preview = mask_code_url(code_url)
    headers = {
        "Accept": "application/json,text/plain,*/*",
        "User-Agent": "Mozilla/5.0 (compatible; gpt-register/1.0)",
    }
    try:
        response = requests.get(code_url, headers=headers, timeout=timeout, verify=False)
    except Exception as exc:
        raise GenericApiMailError(
            f"访问取码地址失败: {preview} ({type(exc).__name__})"
        ) from exc
    if response.status_code != 200:
        retry_after = str(response.headers.get("Retry-After") or "").strip()
        suffix = f"，Retry-After={retry_after}s" if retry_after else ""
        raise GenericApiMailError(
            f"取码地址返回 HTTP {response.status_code}{suffix}: {preview}"
        )
    try:
        payload = json.loads(response.text or "")
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise GenericApiMailError(f"取码地址未返回有效 JSON: {preview}") from exc
    if not isinstance(payload, dict):
        raise GenericApiMailError(f"取码地址 JSON 顶层必须是对象: {preview}")
    return _validate_email(payload.get("email"), from_response=True)


def parse_import_line(line: str, *, timeout: float = 20.0) -> dict:
    """解析 `email----URL` 或 URL-only 通用 API 邮箱素材。"""
    raw = str(line or "").strip()
    if not raw:
        raise GenericApiMailError("邮箱素材为空")

    parsed_raw = urlparse(raw)
    if parsed_raw.scheme.lower() in {"http", "https"} and parsed_raw.hostname:
        code_url = _validate_code_url(raw)
        email = _discover_email(code_url, timeout=timeout)
        return {
            "email": email,
            "code_url": code_url,
            "original_email_line": raw,
        }

    separator = "----" if "----" in raw else "====" if "====" in raw else ""
    if not separator:
        raise GenericApiMailError("格式应为单独取码 URL，或 邮箱----取码 URL")
    parts = [part.strip() for part in raw.split(separator, 3)]
    if len(parts) < 2:
        raise GenericApiMailError("格式应为 邮箱----取码 URL")
    email = _validate_email(parts[0])
    code_url = _validate_code_url(parts[1])
    return {
        "email": email,
        "code_url": code_url,
        "original_email_line": raw,
        "access_token": parts[2] if len(parts) > 2 else "",
        "totp_secret": parts[3] if len(parts) > 3 else "",
    }


def _validate_response_email(text: str, account: GenericApiEmailAccount) -> None:
    response_email = _json_response_email(text)
    if not response_email:
        return
    expected = {
        str(account.email or "").strip().lower(),
        str(account.base_email or "").strip().lower(),
    }
    expected.discard("")
    if response_email.lower() not in expected:
        raise GenericApiMailError(
            f"取码接口邮箱不匹配: expected={account.email}, actual={response_email}"
        )


def _host_min_interval(raw_url: str) -> float:
    host = (urlparse(raw_url).hostname or "").lower()
    return 1.0 if host == "cdkk.985008.xyz" or host.endswith(".985008.xyz") else 0.0


def _wait_host_slot(raw_url: str) -> None:
    interval = _host_min_interval(raw_url)
    if interval <= 0:
        return
    host = (urlparse(raw_url).hostname or "").lower()
    with _HOST_STATE_LOCK:
        lock = _HOST_LOCKS.setdefault(host, threading.Lock())
    with lock:
        delay = _HOST_NEXT_AT.get(host, 0.0) - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        _HOST_NEXT_AT[host] = time.monotonic() + interval


def _request_code(account: GenericApiEmailAccount, headers: dict) -> requests.Response:
    _wait_host_slot(account.code_url)
    return requests.get(account.code_url, headers=headers, timeout=20, verify=False)


def _check_stop_requested(email: str) -> None:
    """同时响应注册任务与已有账号 Codex 补跑的停止信号。"""
    from core.registration_service import check_stop_requested as check_registration_stop
    from core.codex_retry_service import check_stop_requested as check_codex_stop

    check_registration_stop()
    check_codex_stop(email)


def _sleep_with_stop(email: str, seconds: float) -> None:
    remaining = max(0.0, float(seconds or 0.0))
    if remaining == 0:
        time.sleep(0.0)
        _check_stop_requested(email)
        return
    while remaining > 0:
        _check_stop_requested(email)
        step = min(0.5, remaining)
        time.sleep(step)
        remaining -= step
    _check_stop_requested(email)


def _prime_account(account: GenericApiEmailAccount) -> None:
    headers = {"Accept": "application/json,text/plain,*/*", "User-Agent": "gpt-register/1.0"}
    try:
        resp = _request_code(account, headers)
        if resp.status_code == 200:
            _validate_response_email(resp.text or "", account)
            code = _extract_code(resp.text or "")
            if code:
                _OTP_BASELINES[account.email.lower()] = code
                logger.info("[GenericAPI] 已记录领取前旧码: %s", account.email)
    except GenericApiMailError as exc:
        logger.warning("[GenericAPI] 领取前响应校验失败（不阻断）: %s", exc)
    except Exception as exc:
        logger.debug("[GenericAPI] 领取前旧码探测失败（不阻断）: %s", exc)


def pick_account(
    *, mode: str = "single", alias_limit: int | None = None,
    job_id: int | None = None, batch_id: str | None = None,
) -> GenericApiEmailAccount:
    """领取一个可用通用 API 邮箱。"""
    from core.db import claim_generic_api_email, generic_api_email_pool_summary

    inserted, skipped = import_from_file()
    if inserted:
        logger.info(f"[GenericAPI] 已自动从 {_ACCOUNTS_FILE.name} 导入 {inserted} 个邮箱（跳过 {skipped} 个）")

    row = claim_generic_api_email(
        mode=mode,
        alias_limit=alias_limit,
        job_id=job_id,
        batch_id=batch_id,
    )
    if row is None:
        summary = generic_api_email_pool_summary()
        raise GenericApiMailError(
            f"通用 API 邮箱池没有可用账号: {summary}. 请在 WebUI 邮箱池导入：取码 URL 或 邮箱----取码地址"
        )
    account = GenericApiEmailAccount(
        email=row["email"],
        code_url=row["code_url"],
        base_email=row.get("base_email") or row["email"],
        allocation_id=row.get("allocation_id"),
    )
    _CONTEXT_CACHE[account.email] = account
    _prime_account(account)
    logger.info(
        "[GenericAPI] 选中邮箱: %s（base=%s allocation=%s）",
        account.email, account.base_email, account.allocation_id or "-",
    )
    return account


def import_from_file(path: str | Path | None = None) -> tuple[int, int]:
    """从文本文件导入通用 API 邮箱，支持 URL-only 与 email----URL。"""
    from core.db import import_generic_api_emails
    p = Path(path) if path else _ACCOUNTS_FILE
    if not p.is_absolute():
        p = _PROJECT_ROOT / p
    if not p.exists():
        return 0, 0
    records = []
    invalid = 0
    for line_number, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            records.append(parse_import_line(line))
        except GenericApiMailError as exc:
            invalid += 1
            logger.warning("[GenericAPI] 自动导入第 %s 行失败: %s", line_number, exc)
    inserted, skipped = import_generic_api_emails(records)
    return inserted, skipped + invalid


def get_account_context(email: str) -> GenericApiEmailAccount | None:
    if email in _CONTEXT_CACHE:
        return _CONTEXT_CACHE[email]
    from core.db import get_generic_api_email_by_email
    row = get_generic_api_email_by_email(email)
    if row is None:
        return None
    account = GenericApiEmailAccount(
        email=row["email"], code_url=row["code_url"],
        base_email=row.get("base_email") or row["email"],
        allocation_id=row.get("allocation_id"),
    )
    _CONTEXT_CACHE[email] = account
    return account


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    from core.db import release_generic_api_email
    release_generic_api_email(email, status=status, note=note)
    _CONTEXT_CACHE.pop(email, None)
    _OTP_BASELINES.pop(email.lower(), None)


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
    exclude_codes: set[str] | None = None,
) -> str:
    """
    轮询该邮箱配置的 code_url，直到提取到 6 位验证码或超时。

    settle 机制：首次拿到验证码后不立刻返回，而是继续等 OTP_SETTLE_SECONDS 秒。
    如果期间取码地址返回了不同验证码，则替换候选并重置 settle 倒计时；
    连续 settle 秒没有变化后才返回，避免取到接口缓存中的旧码。
    """
    account = get_account_context(email)
    if account is None:
        raise GenericApiMailError(f"通用 API 邮箱不存在或未导入: {email}")
    _check_stop_requested(email)
    try:
        from core.db import renew_email_allocation_lease
        renew_email_allocation_lease(email)
    except Exception:
        logger.debug("[GenericAPI] 邮箱租约续期失败", exc_info=True)

    deadline = time.time() + (max_wait or _email_cfg.OTP_MAX_WAIT)
    interval = poll_interval or _email_cfg.OTP_POLL_INTERVAL
    settle = settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS
    headers = {
        "Accept": "application/json,text/plain,*/*",
        "User-Agent": "Mozilla/5.0 (compatible; gpt-register/1.0)",
    }
    last_error = ""
    best_otp: str | None = None
    best_seen_at: float = 0.0
    settle_until: float | None = None
    logger.info(
        "[GenericAPI] 开始轮询: email=%s url=%s 最长=%ss settle=%ss",
        email, mask_code_url(account.code_url), max_wait or _email_cfg.OTP_MAX_WAIT, settle,
    )
    baseline = _OTP_BASELINES.get(email.lower(), "")
    excluded = {str(code) for code in (exclude_codes or set()) if code}
    same_code_allowed_at = time.time() + 25
    rate_limit_retries = 0

    while time.time() < deadline:
        _check_stop_requested(email)
        try:
            try:
                from core.db import renew_email_allocation_lease
                renew_email_allocation_lease(email)
            except Exception:
                logger.debug("[GenericAPI] 邮箱租约续期失败", exc_info=True)
            resp = _request_code(account, headers)
            _check_stop_requested(email)
            text = resp.text or ""
            if resp.status_code == 200:
                rate_limit_retries = 0
                _validate_response_email(text, account)
                code = _extract_code(text)
                if code and code in excluded:
                    code = None
                    last_error = "取码接口仍返回已提交过的旧码"
                elif code and baseline and code == baseline and time.time() < same_code_allowed_at:
                    code = None
                    last_error = "取码接口仍返回领取前旧码"
                if code:
                    now_seen = time.time()
                    if not best_otp:
                        best_otp = code
                        best_seen_at = now_seen
                        settle_until = now_seen + settle
                        logger.info(
                            f"[GenericAPI] 首次锁定 OTP={code}, "
                            f"等 {settle}s 看取码接口是否出现更新验证码..."
                        )
                    elif code != best_otp:
                        logger.info(
                            f"[GenericAPI] 发现更新 OTP={code}，"
                            f"替换之前的 {best_otp}, 重置 settle 计时"
                        )
                        best_otp = code
                        best_seen_at = now_seen
                        settle_until = now_seen + settle
                    else:
                        logger.debug(f"[GenericAPI] 取码接口仍返回候选 OTP={best_otp}")
                else:
                    last_error = f"HTTP 200 但未提取到 6 位验证码，响应预览: {text[:160]}"
            elif resp.status_code == 429:
                rate_limit_retries += 1
                retry_after = resp.headers.get("Retry-After", "")
                try:
                    backoff = max(float(retry_after), 0.0)
                except (TypeError, ValueError):
                    backoff = min(30.0, 2.0 * (2 ** min(rate_limit_retries - 1, 4)))
                last_error = f"HTTP 429，退避 {backoff:.1f}s"
                _sleep_with_stop(email, backoff)
            else:
                last_error = f"HTTP {resp.status_code}: {text[:160]}"
        except GenericApiMailError:
            raise
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        # _request_code 可能阻塞到任务已停止；放在宽泛异常处理之外，避免
        # StopRequested 被当成普通取码错误吞掉后仍返回候选 OTP。
        _check_stop_requested(email)
        now = time.time()
        if best_otp and settle_until is not None and now >= settle_until:
            logger.info(
                f"[GenericAPI] settle 完成，返回 OTP={best_otp}, "
                f"候选锁定时间={time.strftime('%H:%M:%S', time.localtime(best_seen_at))}"
            )
            return best_otp

        remaining = int(deadline - now)
        if best_otp and settle_until is not None:
            logger.info(
                f"[GenericAPI] 已锁定候选 OTP={best_otp}，等 settle 中"
                f"（剩余 settle ~{max(0, int(settle_until - now))}s, 总剩余 {remaining}s）..."
            )
        else:
            logger.info(
                f"[GenericAPI] 暂未从取码接口拿到验证码，"
                f"{interval}s 后重试（剩余 {remaining}s）..."
            )
        _sleep_with_stop(email, interval)

    if best_otp:
        _check_stop_requested(email)
        logger.warning(f"[GenericAPI] 总超时但已有候选，返回 OTP={best_otp}")
        return best_otp

    raise GenericApiMailError(f"等待通用 API 验证码超时: {email}; {last_error}")
