# -*- coding: utf-8 -*-
"""Mail.com account-pool integration backed by read-only IMAP polling."""
from __future__ import annotations

import atexit
import email
import hashlib
import html
import imaplib
import json
import logging
import re
import ssl
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.header import decode_header
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlparse

from config import email as _email_cfg

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CODE_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")
_CONTEXT_CODE_RES = (
    re.compile(
        r"(?:temporary|verification|login|security|one[ -]?time|otp)"
        r"(?:\s+[\w'-]+|\s*[/,:：-]\s*){0,8}?"
        r"(?<!\d)(\d{6})(?!\d)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:验证码|驗證碼|认证码|認證碼|确认码|確認碼|認証コード|確認コード|検証コード|コード)"
        r"[^\d]{0,80}(?<!\d)(\d{6})(?!\d)",
        re.IGNORECASE,
    ),
)
_CONTEXT_CACHE: dict[str, "MailcomAccount"] = {}
_WEB_CLIENTS: OrderedDict[str, object] = OrderedDict()
_WEB_CLIENT_LOCKS: dict[str, threading.RLock] = {}
_WEB_CACHE_LOCK = threading.RLock()
_WEB_LOGIN_BLOCKING_KINDS = frozenset({
    "verification_required", "interception_required",
})


class MailcomMailError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        kind: str = "mailcom_error",
        resend_recommended: bool = True,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.resend_recommended = bool(resend_recommended)


@dataclass(slots=True)
class MailcomAccount:
    email: str
    base_email: str
    password: str
    allocation_id: int | None = None


def parse_import_line(line: str) -> dict | None:
    """Parse ``email----password`` without exposing the password in errors."""
    raw = str(line or "").strip()
    if not raw or raw.startswith("#") or "----" not in raw:
        return None
    mailbox, password = (part.strip() for part in raw.split("----", 1))
    local, separator, domain = mailbox.partition("@")
    if not separator or not local or not domain or any(ch.isspace() for ch in mailbox):
        return None
    if not password:
        return None
    return {
        "email": mailbox,
        "password": password,
        "original_email_line": raw,
    }


def _accounts_file() -> Path:
    configured = str(
        getattr(_email_cfg, "MAILCOM_ACCOUNTS_FILE", "用于注册的Mailcom邮箱.txt")
        or "用于注册的Mailcom邮箱.txt"
    ).strip()
    path = Path(configured)
    return path if path.is_absolute() else _PROJECT_ROOT / path


def import_from_file(path: str | Path | None = None) -> tuple[int, int]:
    from core.db import import_mailcom_accounts

    source = Path(path) if path else _accounts_file()
    if not source.is_absolute():
        source = _PROJECT_ROOT / source
    if not source.exists():
        return 0, 0
    records: list[dict] = []
    invalid = 0
    for raw in source.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        record = parse_import_line(line)
        if record is None:
            invalid += 1
        else:
            records.append(record)
    inserted, skipped = import_mailcom_accounts(records)
    return inserted, skipped + invalid


def pick_account(
    *,
    mode: str = "single",
    alias_limit: int | None = None,
    job_id: int | None = None,
    batch_id: str | None = None,
) -> MailcomAccount:
    from core.db import claim_mailcom_email, mailcom_pool_summary

    inserted, skipped = import_from_file()
    if inserted:
        logger.info("[Mail.com] 已自动导入 %s 个邮箱（跳过 %s 个）", inserted, skipped)
    row = claim_mailcom_email(
        mode=mode,
        alias_limit=alias_limit,
        job_id=job_id,
        batch_id=batch_id,
    )
    if row is None:
        raise MailcomMailError(f"Mail.com 邮箱池没有可用账号: {mailcom_pool_summary()}")
    account = MailcomAccount(
        email=str(row.get("email") or ""),
        base_email=str(row.get("base_email") or row.get("email") or ""),
        password=str(row.get("password") or ""),
        allocation_id=row.get("allocation_id"),
    )
    _CONTEXT_CACHE[account.email.lower()] = account
    if str(mode or "single").strip().lower() == "plus_alias":
        try:
            _ensure_managed_alias(account)
        except Exception as exc:
            from core.db import complete_email_allocation

            complete_email_allocation(
                account.email,
                status="failed",
                error=f"Mail.com Alias 创建失败: {type(exc).__name__}: {exc}",
            )
            _CONTEXT_CACHE.pop(account.email.lower(), None)
            if isinstance(exc, MailcomMailError):
                raise
            raise MailcomMailError(
                f"Mail.com Alias 创建失败: {type(exc).__name__}: {exc}"
            ) from exc
    logger.info(
        "[Mail.com] 选中邮箱: %s（base=%s, allocation=%s）",
        account.email,
        account.base_email,
        account.allocation_id or "-",
    )
    return account


def _web_lock(base_email: str) -> threading.RLock:
    key = str(base_email or "").strip().lower()
    with _WEB_CACHE_LOCK:
        return _WEB_CLIENT_LOCKS.setdefault(key, threading.RLock())


def _web_cache_limit() -> int:
    try:
        configured = int(getattr(_email_cfg, "MAILCOM_WEB_CACHE_SIZE", 4) or 4)
    except (TypeError, ValueError):
        configured = 4
    return max(1, min(configured, 32))


def _proxy_route_family(proxy_url: object) -> str:
    value = str(proxy_url or "").strip()
    if not value:
        return "direct"
    try:
        parsed = urlparse(value)
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        username = re.sub(
            r"(?i)((?:session|sid)[_-])[a-z0-9]+",
            r"\1*",
            username,
            count=1,
        )
        material = "|".join([
            parsed.scheme.lower(), (parsed.hostname or "").lower(),
            str(parsed.port or ""), username, password,
        ])
    except (TypeError, ValueError):
        material = value
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _web_state_digest(state: object) -> str:
    if not isinstance(state, dict):
        return ""
    comparable = dict(state)
    comparable.pop("saved_at", None)
    try:
        rendered = json.dumps(
            comparable, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
        )
    except (TypeError, ValueError):
        return ""
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _persist_web_client_state(client: object | None) -> bool:
    export_state = getattr(client, "export_state", None)
    if not callable(export_state):
        return False
    try:
        state = export_state()
    except Exception:
        logger.debug("[Mail.com] 导出 Web 会话失败", exc_info=True)
        return False
    if not isinstance(state, dict) or not str(state.get("sid") or "").strip():
        return False
    digest = _web_state_digest(state)
    if digest and digest == str(getattr(client, "_mailcom_state_digest", "") or ""):
        return True
    try:
        from core.mailcom_session_store import save_session

        saved = save_session(
            str(getattr(client, "username", "") or ""),
            str(getattr(client, "password", "") or ""),
            str(getattr(client, "proxy_url", "") or ""),
            state,
        )
    except Exception:
        logger.warning("[Mail.com] 持久化 Web 会话失败", exc_info=True)
        return False
    if saved and digest:
        setattr(client, "_mailcom_state_digest", digest)
    return bool(saved)


def _delete_persisted_web_session(base_email: object) -> None:
    try:
        from core.mailcom_session_store import delete_session

        delete_session(str(base_email or ""))
    except Exception:
        logger.debug("[Mail.com] 删除持久化 Web 会话失败", exc_info=True)


def _mark_web_login_state(
    account: MailcomAccount,
    status: str,
    error: object = None,
) -> None:
    try:
        from core.db import mark_mailcom_web_login_state

        mark_mailcom_web_login_state(
            account.base_email,
            status,
            str(error or "")[:300] or None,
        )
    except Exception:
        logger.debug("[Mail.com] 更新母号 Web 登录状态失败", exc_info=True)


def _web_operation_succeeded(account: MailcomAccount, client: object) -> None:
    _persist_web_client_state(client)
    _mark_web_login_state(account, "ready")


def _close_web_client(client: object | None, *, persist: bool = True) -> None:
    if client is None:
        return
    if persist:
        _persist_web_client_state(client)
    close = getattr(type(client), "close", None)
    if callable(close):
        close = getattr(client, "close", None)
    if not callable(close):
        close = getattr(getattr(client, "session", None), "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            logger.debug("[Mail.com] 关闭 Web 会话失败", exc_info=True)


def _trim_web_client_cache(*, exclude: set[str] | None = None) -> int:
    """Evict idle LRU clients without closing a mailbox in active use."""
    excluded = {str(value or "").strip().lower() for value in (exclude or set())}
    closed = 0
    while True:
        with _WEB_CACHE_LOCK:
            if len(_WEB_CLIENTS) <= _web_cache_limit():
                return closed
            candidates = [key for key in _WEB_CLIENTS if key not in excluded]
            locks = {
                key: _WEB_CLIENT_LOCKS.setdefault(key, threading.RLock())
                for key in candidates
            }
        removed = False
        for key in candidates:
            lock = locks[key]
            if not lock.acquire(blocking=False):
                continue
            try:
                with _WEB_CACHE_LOCK:
                    if len(_WEB_CLIENTS) <= _web_cache_limit():
                        return closed
                    client = _WEB_CLIENTS.pop(key, None)
                if client is not None:
                    _close_web_client(client)
                    closed += 1
                    removed = True
                    logger.debug("[Mail.com] 已回收 LRU Web 会话: base=%s", key)
                    break
            finally:
                lock.release()
        if not removed:
            # All overflow entries are currently in use. A later cache access
            # or polling completion will retry; never close an active request.
            return closed


def close_cached_web_clients() -> int:
    """Close every cached Mail.com transport during shutdown or maintenance."""
    with _WEB_CACHE_LOCK:
        clients = list(_WEB_CLIENTS.values())
        _WEB_CLIENTS.clear()
    for client in clients:
        _close_web_client(client)
    return len(clients)


def _web_client(account: MailcomAccount):
    key = account.base_email.strip().lower()
    stale = None
    stale_is_invalid = False
    with _WEB_CACHE_LOCK:
        client = _WEB_CLIENTS.get(key)
        if (
            client is None
            or getattr(client, "username", "") != key
            or getattr(client, "password", "") != account.password
        ):
            stale = _WEB_CLIENTS.pop(key, None)
            stale_is_invalid = stale is not None
            candidate_proxy = _mailcom_web_proxy(key)
            restored_state: dict | None = None
            restored_proxy = ""
            try:
                from core.mailcom_session_store import load_session

                persisted = load_session(key, account.password)
            except Exception:
                logger.warning("[Mail.com] 读取持久化 Web 会话失败", exc_info=True)
                persisted = None
            if isinstance(persisted, dict):
                stored_proxy = str(persisted.get("proxy_url") or "").strip()
                if _proxy_route_family(stored_proxy) == _proxy_route_family(candidate_proxy):
                    restored_proxy = stored_proxy
                    restored_state = (
                        dict(persisted.get("state") or {})
                        if isinstance(persisted.get("state"), dict)
                        else None
                    )
                else:
                    _delete_persisted_web_session(key)
            client = _new_web_client(
                account,
                proxy_url=restored_proxy or candidate_proxy,
                state=restored_state,
            )
            _WEB_CLIENTS[key] = client
        else:
            _WEB_CLIENTS.move_to_end(key)
    if stale_is_invalid:
        _close_web_client(stale, persist=False)
    else:
        _close_web_client(stale)
    _trim_web_client_cache(exclude={key})
    return client


def _new_web_client(
    account: MailcomAccount,
    *,
    proxy_url: str,
    direct_fallback: bool = False,
    state: dict | None = None,
):
    from core.mailcom_web_client import MailcomWebClient

    kwargs = {"proxy_url": proxy_url}
    if state:
        kwargs["state"] = state
    client = MailcomWebClient(
        account.base_email.strip().lower(), account.password, **kwargs,
    )
    setattr(client, "_mailcom_direct_fallback", bool(direct_fallback))
    if state:
        setattr(client, "_mailcom_state_digest", _web_state_digest(state))
    logger.info(
        "[Mail.com] Web 会话已创建：transport=curl_cffi/%s route=%s base=%s",
        getattr(client, "impersonate", "unknown"),
        "direct_fallback" if direct_fallback else "proxy" if proxy_url else "direct",
        account.base_email,
    )
    if state:
        logger.info("[Mail.com] 已恢复加密持久化 Web 会话: base=%s", account.base_email)
    return client


def _is_direct_web_fallback(client) -> bool:
    return getattr(client, "_mailcom_direct_fallback", False) is True


def _direct_web_fallback_enabled() -> bool:
    return bool(getattr(_email_cfg, "MAILCOM_WEB_DIRECT_FALLBACK", True))


def _replace_with_direct_web_client(account: MailcomAccount, *, expected=None):
    """Replace a rejected proxy session with one explicit direct session."""
    if not _direct_web_fallback_enabled():
        return None
    if expected is not None and not str(getattr(expected, "proxy_url", "") or "").strip():
        return None
    if not _discard_web_client(account, expected=expected):
        return None

    replacement = _new_web_client(account, proxy_url="", direct_fallback=True)
    key = account.base_email.strip().lower()
    with _WEB_CACHE_LOCK:
        _WEB_CLIENTS[key] = replacement
        _WEB_CLIENTS.move_to_end(key)
    _trim_web_client_cache(exclude={key})
    return replacement


def _discard_web_client(account: MailcomAccount, *, expected=None) -> bool:
    """Drop one cached Web session without closing a newer replacement."""
    key = account.base_email.strip().lower()
    with _WEB_CACHE_LOCK:
        cached = _WEB_CLIENTS.get(key)
        if expected is not None and cached is not expected:
            return False
        cached = _WEB_CLIENTS.pop(key, None)
    if cached is None:
        return False
    _close_web_client(cached, persist=False)
    _delete_persisted_web_session(key)
    return True


def _web_proxy_attempt_limit() -> int:
    try:
        configured = int(getattr(_email_cfg, "MAILCOM_WEB_PROXY_ATTEMPTS", 3) or 3)
    except (TypeError, ValueError):
        configured = 3
    return max(1, min(configured, 10))


def _mailcom_web_proxy(base_email: str) -> str:
    """Choose one stable proxy route for a base mailbox's cached Web session."""
    if not bool(getattr(_email_cfg, "MAILCOM_WEB_USE_PROXY", True)):
        return ""

    from config import proxy as proxy_cfg
    from core.protocol_rate_limit import rotate_sticky_proxy_session

    explicit = str(getattr(_email_cfg, "MAILCOM_WEB_PROXY", "") or "").strip()
    if explicit:
        candidate = proxy_cfg.normalize_proxy_url(explicit)
    else:
        pool = [
            proxy_cfg.normalize_proxy_url(value)
            for value in list(getattr(proxy_cfg, "PROXY_POOL", []) or [])
            if str(value or "").strip()
        ]
        if not pool:
            return ""
        digest = hashlib.sha256(str(base_email or "").strip().lower().encode()).digest()
        candidate = pool[int.from_bytes(digest[:8], "big") % len(pool)]
    return rotate_sticky_proxy_session(candidate)


def _ensure_managed_alias(account: MailcomAccount) -> None:
    """Create and verify the reserved address in Mail.com's managed Alias list."""
    target = account.email.strip().lower()
    if target == account.base_email.strip().lower():
        return
    if "+" in target.partition("@")[0] or "-split-" not in target.partition("@")[0]:
        raise MailcomMailError("Mail.com Alias 地址格式无效")

    from core.db import mark_mailcom_alias_created
    from core.mailcom_web_client import MailcomWebError

    attempts = _web_proxy_attempt_limit()
    non_recoverable_kinds = {
        "bad_credentials", "alias_invalid", "alias_limit",
        *_WEB_LOGIN_BLOCKING_KINDS,
    }
    with _web_lock(account.base_email):
        session_attempt = 1
        while True:
            client = _web_client(account)
            try:
                aliases = set(client.list_aliases())
                if target not in aliases:
                    try:
                        client.add_alias(target)
                    except MailcomWebError:
                        # The create response can be lost after the provider commits.
                        aliases = set(client.list_aliases())
                        if target not in aliases:
                            raise
                    if target not in aliases:
                        for confirm_attempt in range(3):
                            aliases = set(client.list_aliases())
                            if target in aliases:
                                break
                            if confirm_attempt < 2:
                                time.sleep(1)
                if target not in aliases:
                    raise MailcomMailError("Mail.com 返回成功，但 Alias 列表未出现新地址")
                if not mark_mailcom_alias_created(target):
                    raise MailcomMailError("Mail.com Alias 已创建，但本地分配记录不存在")
                logger.info(
                    "[Mail.com] 真实 Alias 已确认: %s（base=%s）",
                    target,
                    account.base_email,
                )
                _web_operation_succeeded(account, client)
                return
            except MailcomWebError as exc:
                direct_fallback = _is_direct_web_fallback(client)
                if exc.kind in non_recoverable_kinds:
                    if exc.kind in _WEB_LOGIN_BLOCKING_KINDS:
                        _mark_web_login_state(account, exc.kind, exc)
                    if exc.kind in {
                        "bad_credentials", "blocked", "network",
                        *_WEB_LOGIN_BLOCKING_KINDS,
                    }:
                        _discard_web_client(account, expected=client)
                    raise MailcomMailError(
                        f"Mail.com Web Alias 失败 [{exc.kind}]: {exc}",
                        kind=exc.kind,
                        resend_recommended=False,
                    ) from exc
                if not direct_fallback and session_attempt < attempts:
                    _discard_web_client(account, expected=client)
                    _web_client(account)
                    session_attempt += 1
                    logger.warning(
                        "[Mail.com] Web Alias 会话失败，已重建代理会话："
                        "kind=%s session=%s/%s email=%s",
                        exc.kind,
                        session_attempt,
                        attempts,
                        target,
                    )
                    continue
                replacement = _replace_with_direct_web_client(account, expected=client)
                if replacement is not None:
                    logger.warning(
                        "[Mail.com] Web Alias 代理会话均被拒绝，改用本机直连："
                        "kind=%s proxy_sessions=%s email=%s",
                        exc.kind,
                        attempts,
                        target,
                    )
                    continue
                if exc.kind in {"bad_credentials", "blocked", "network"}:
                    _discard_web_client(account, expected=client)
                raise MailcomMailError(
                    f"Mail.com Web Alias 失败 [{exc.kind}]: {exc}",
                    kind=exc.kind,
                    resend_recommended=False,
                ) from exc


def delete_managed_alias(base_email: str, alias_email: str) -> str:
    """Delete one managed Alias and verify it disappeared remotely.

    Returns ``deleted`` when this call removed it and ``missing`` when the
    provider had already removed it. Both outcomes release local capacity.
    """
    base = str(base_email or "").strip().lower()
    target = str(alias_email or "").strip().lower()
    base_local, separator, base_domain = base.partition("@")
    target_local, target_separator, target_domain = target.partition("@")
    if (
        not separator
        or not target_separator
        or not base_local
        or not target_local
        or base_domain != target_domain
        or target == base
        or "-split-" not in target_local
    ):
        raise MailcomMailError(
            "Mail.com Alias 地址与母号不匹配",
            kind="alias_invalid",
            resend_recommended=False,
        )

    account = get_account_context(base)
    if account is None or not account.password:
        raise MailcomMailError(
            "Mail.com 母号不存在或密码为空",
            kind="bad_credentials",
            resend_recommended=False,
        )

    from core.mailcom_web_client import MailcomWebError

    attempts = _web_proxy_attempt_limit()
    non_recoverable_kinds = {
        "bad_credentials", "alias_invalid", "alias_not_deletable",
        *_WEB_LOGIN_BLOCKING_KINDS,
    }
    with _web_lock(base):
        session_attempt = 1
        while True:
            client = _web_client(account)
            try:
                aliases = set(client.list_aliases())
                if target not in aliases:
                    logger.info(
                        "[Mail.com] Alias 已不在远端列表: %s（base=%s）",
                        target,
                        base,
                    )
                    _web_operation_succeeded(account, client)
                    return "missing"
                try:
                    deleted = client.delete_alias(target)
                except MailcomWebError:
                    # The response may be lost after the provider commits.
                    if target not in set(client.list_aliases()):
                        logger.info(
                            "[Mail.com] Alias 删除响应丢失但远端已生效: %s（base=%s）",
                            target,
                            base,
                        )
                        _web_operation_succeeded(account, client)
                        return "deleted"
                    raise
                if not deleted:
                    _web_operation_succeeded(account, client)
                    return "missing"
                for confirm_attempt in range(4):
                    if target not in set(client.list_aliases()):
                        logger.info(
                            "[Mail.com] Alias 已删除: %s（base=%s）",
                            target,
                            base,
                        )
                        _web_operation_succeeded(account, client)
                        return "deleted"
                    if confirm_attempt < 3:
                        time.sleep(1)
                raise MailcomWebError(
                    "Mail.com 返回删除成功，但 Alias 仍在远端列表",
                    kind="alias_delete_unconfirmed",
                )
            except MailcomWebError as exc:
                direct_fallback = _is_direct_web_fallback(client)
                if exc.kind in non_recoverable_kinds:
                    if exc.kind in _WEB_LOGIN_BLOCKING_KINDS:
                        _mark_web_login_state(account, exc.kind, exc)
                    if exc.kind == "bad_credentials":
                        _discard_web_client(account, expected=client)
                    elif exc.kind in _WEB_LOGIN_BLOCKING_KINDS:
                        _discard_web_client(account, expected=client)
                    raise MailcomMailError(
                        f"Mail.com Alias 删除失败 [{exc.kind}]: {exc}",
                        kind=exc.kind,
                        resend_recommended=False,
                    ) from exc
                if not direct_fallback and session_attempt < attempts:
                    _discard_web_client(account, expected=client)
                    _web_client(account)
                    session_attempt += 1
                    logger.warning(
                        "[Mail.com] Alias 删除会话失败，已重建代理会话："
                        "kind=%s session=%s/%s email=%s",
                        exc.kind,
                        session_attempt,
                        attempts,
                        target,
                    )
                    continue
                replacement = _replace_with_direct_web_client(account, expected=client)
                if replacement is not None:
                    logger.warning(
                        "[Mail.com] Alias 删除代理会话均失败，改用本机直连："
                        "kind=%s proxy_sessions=%s email=%s",
                        exc.kind,
                        attempts,
                        target,
                    )
                    continue
                if exc.kind in {"bad_credentials", "blocked", "network", "session_expired"}:
                    _discard_web_client(account, expected=client)
                raise MailcomMailError(
                    f"Mail.com Alias 删除失败 [{exc.kind}]: {exc}",
                    kind=exc.kind,
                    resend_recommended=False,
                ) from exc


def get_account_context(mailbox: str) -> MailcomAccount | None:
    key = str(mailbox or "").strip().lower()
    if key in _CONTEXT_CACHE:
        return _CONTEXT_CACHE[key]
    from core.db import get_mailcom_by_email

    row = get_mailcom_by_email(mailbox)
    if row is None:
        return None
    account = MailcomAccount(
        email=str(row.get("email") or mailbox),
        base_email=str(row.get("base_email") or row.get("email") or mailbox),
        password=str(row.get("password") or ""),
        allocation_id=row.get("allocation_id"),
    )
    _CONTEXT_CACHE[key] = account
    return account


def release_account(mailbox: str, status: str = "available", note: str | None = None) -> None:
    from core.db import release_mailcom_email

    release_mailcom_email(mailbox, status=status, note=note)
    _CONTEXT_CACHE.pop(str(mailbox or "").strip().lower(), None)


def _decode_header(value: str | None) -> str:
    chunks: list[str] = []
    for payload, charset in decode_header(value or ""):
        if isinstance(payload, bytes):
            try:
                chunks.append(payload.decode(charset or "utf-8", errors="replace"))
            except LookupError:
                chunks.append(payload.decode("utf-8", errors="replace"))
        else:
            chunks.append(payload)
    return "".join(chunks)


class _VisibleHTMLParser(HTMLParser):
    _HIDDEN_TAGS = frozenset({"head", "script", "style", "template", "svg", "noscript"})
    _BREAK_TAGS = frozenset({"br", "div", "li", "p", "table", "td", "th", "tr"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._hidden_depth = 0
        self._chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        lowered = tag.lower()
        if lowered in self._HIDDEN_TAGS:
            self._hidden_depth += 1
        elif self._hidden_depth == 0 and lowered in self._BREAK_TAGS:
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in self._HIDDEN_TAGS:
            self._hidden_depth = max(0, self._hidden_depth - 1)
        elif self._hidden_depth == 0 and lowered in self._BREAK_TAGS:
            self._chunks.append("\n")

    def handle_data(self, data: str) -> None:
        if self._hidden_depth == 0 and data:
            self._chunks.append(data)

    def text(self) -> str:
        return re.sub(r"[ \t\r\f\v]+", " ", "".join(self._chunks))


def _decode_part(part: email.message.Message) -> str:
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _visible_html_text(raw_html: str) -> str:
    parser = _VisibleHTMLParser()
    try:
        parser.feed(raw_html)
        parser.close()
    except Exception:
        logger.debug("[Mail.com] HTML 邮件正文解析不完整", exc_info=True)
    return html.unescape(parser.text())


def _message_text(message: email.message.Message) -> str:
    subject = _decode_header(message.get("Subject"))
    plain_chunks: list[str] = []
    html_chunks: list[str] = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        content_type = part.get_content_type()
        if content_type == "text/plain":
            decoded = _decode_part(part)
            if decoded:
                plain_chunks.append(decoded)
        elif content_type == "text/html":
            decoded = _decode_part(part)
            if decoded:
                html_chunks.append(decoded)

    # Multipart alternatives contain the same message twice. Prefer plain text;
    # raw HTML must never reach the generic numeric fallback because CSS colors
    # such as #202123 look exactly like a six-digit OTP.
    if plain_chunks:
        body = "\n".join(plain_chunks)
    else:
        body = "\n".join(_visible_html_text(chunk) for chunk in html_chunks)
    return html.unescape("\n".join(part for part in (subject, body) if part))


def _extract_otp(message: email.message.Message) -> str:
    return _extract_otp_text(_message_text(message))


def _extract_otp_text(visible_text: str) -> str:
    for pattern in _CONTEXT_CODE_RES:
        match = pattern.search(visible_text)
        if match:
            return match.group(1)
    match = _CODE_RE.search(visible_text)
    return match.group(1) if match else ""


def _latest_web_candidate(
    client,
    account: MailcomAccount,
    *,
    after_ts: float | None,
    exclude_codes: set[str],
) -> dict | None:
    accepted_recipients = {account.email.lower(), account.base_email.lower()}
    candidates: list[dict] = []
    for message in client.query_messages(account.email, amount=20)[:10]:
        sender = str(message.sender or "").lower()
        subject = str(message.subject or "")
        if not (
            "openai.com" in sender
            or "chatgpt" in sender
            or "chatgpt" in subject.lower()
            or "openai" in subject.lower()
        ):
            continue
        recipients = {
            address.strip().lower()
            for address in message.recipients
            if str(address or "").strip()
        }
        if recipients and recipients.isdisjoint(accepted_recipients):
            continue
        timestamp = float(message.timestamp or 0.0)
        if after_ts is not None and timestamp < float(after_ts) - 5:
            continue
        body = client.get_message_body(message.mail_id)
        visible_body = _visible_html_text(body) if "<" in body and ">" in body else body
        code = _extract_otp_text(html.unescape("\n".join((subject, visible_body))))
        if not code:
            continue
        if code in exclude_codes and (after_ts is None or timestamp < float(after_ts)):
            continue
        try:
            sequence = int(message.mail_id)
        except (TypeError, ValueError):
            sequence = 0
        candidates.append({
            "code": code,
            "timestamp": timestamp,
            "sequence": sequence,
            "subject": subject,
        })
    return max(candidates, key=lambda item: (item["timestamp"], item["sequence"])) if candidates else None


def _message_timestamp(message: email.message.Message) -> float | None:
    try:
        value = parsedate_to_datetime(message.get("Date"))
    except (TypeError, ValueError, OverflowError):
        return None
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()


def _recipient_addresses(message: email.message.Message) -> set[str]:
    headers: list[str] = []
    for name in ("To", "Delivered-To", "X-Original-To", "Envelope-To", "X-Envelope-To"):
        headers.extend(message.get_all(name, []))
    return {
        address.strip().lower()
        for _, address in getaddresses(headers)
        if address and "@" in address
    }


def _is_openai_message(message: email.message.Message) -> bool:
    sender = " ".join(message.get_all("From", [])).lower()
    subject = _decode_header(message.get("Subject")).lower()
    return (
        "openai.com" in sender
        or "chatgpt" in sender
        or "chatgpt" in subject
        or "openai" in subject
    )


def _create_ssl_context() -> ssl.SSLContext:
    """Use Certifi on Python builds whose bundled OpenSSL CA file is incomplete."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except (ImportError, OSError):
        return ssl.create_default_context()


def _connect(account: MailcomAccount) -> imaplib.IMAP4_SSL:
    host = str(getattr(_email_cfg, "MAILCOM_IMAP_HOST", "imap.mail.com") or "imap.mail.com")
    try:
        port = int(getattr(_email_cfg, "MAILCOM_IMAP_PORT", 993) or 993)
        timeout = max(1, int(getattr(_email_cfg, "MAILCOM_IMAP_TIMEOUT", 20) or 20))
    except (TypeError, ValueError) as exc:
        raise MailcomMailError("Mail.com IMAP 配置非法") from exc
    client: imaplib.IMAP4_SSL | None = None
    try:
        client = imaplib.IMAP4_SSL(
            host,
            port,
            ssl_context=_create_ssl_context(),
            timeout=timeout,
        )
        client.login(account.base_email, account.password)
        status, _ = client.select("INBOX", readonly=True)
        if str(status or "").upper() != "OK":
            raise MailcomMailError("Mail.com INBOX 打开失败")
        return client
    except imaplib.IMAP4.error as exc:
        if client is not None:
            try:
                client.logout()
            except Exception:
                pass
        raise MailcomMailError("Mail.com IMAP 登录失败，请检查邮箱或密码") from exc
    except MailcomMailError:
        if client is not None:
            try:
                client.logout()
            except Exception:
                pass
        raise
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        if client is not None:
            try:
                client.logout()
            except Exception:
                pass
        raise MailcomMailError(f"Mail.com IMAP 连接失败: {type(exc).__name__}") from exc


def _close(client: imaplib.IMAP4_SSL | None) -> None:
    if client is None:
        return
    try:
        client.logout()
    except Exception:
        pass


def _search_message_ids(
    client: imaplib.IMAP4_SSL,
    *,
    after_ts: float | None,
) -> list[bytes]:
    if after_ts is None:
        status, data = client.search(None, "ALL")
    else:
        since = datetime.fromtimestamp(float(after_ts), tz=timezone.utc) - timedelta(days=1)
        status, data = client.search(None, "SINCE", since.strftime("%d-%b-%Y"))
    if str(status or "").upper() != "OK":
        raise MailcomMailError("Mail.com IMAP 搜索邮件失败")
    raw_ids = data[0].split() if data and isinstance(data[0], bytes) else []
    return raw_ids[-50:]


def _fetch_message(client: imaplib.IMAP4_SSL, message_id: bytes) -> email.message.Message | None:
    status, result = client.fetch(message_id, "(BODY.PEEK[])")
    if str(status or "").upper() != "OK":
        return None
    raw = next(
        (item[1] for item in result or [] if isinstance(item, tuple) and len(item) > 1 and isinstance(item[1], bytes)),
        None,
    )
    return email.message_from_bytes(raw) if raw else None


def _latest_candidate(
    client: imaplib.IMAP4_SSL,
    account: MailcomAccount,
    *,
    after_ts: float | None,
    exclude_codes: set[str],
) -> dict | None:
    accepted_recipients = {account.email.lower(), account.base_email.lower()}
    candidates: list[dict] = []
    for message_id in reversed(_search_message_ids(client, after_ts=after_ts)):
        message = _fetch_message(client, message_id)
        if message is None or not _is_openai_message(message):
            continue
        recipients = _recipient_addresses(message)
        if recipients and recipients.isdisjoint(accepted_recipients):
            continue
        timestamp = _message_timestamp(message)
        if after_ts is not None and (timestamp is None or timestamp < float(after_ts) - 5):
            continue
        code = _extract_otp(message)
        if not code:
            continue
        if code in exclude_codes and (
            after_ts is None or timestamp is None or timestamp < float(after_ts)
        ):
            continue
        try:
            sequence = int(message_id)
        except (TypeError, ValueError):
            sequence = 0
        candidates.append({
            "code": code,
            "timestamp": timestamp or 0.0,
            "sequence": sequence,
            "subject": _decode_header(message.get("Subject")),
        })
    return max(candidates, key=lambda item: (item["timestamp"], item["sequence"])) if candidates else None


def _check_stop_requested(mailbox: str) -> None:
    from core.registration_service import check_stop_requested as check_registration_stop
    from core.codex_retry_service import check_stop_requested as check_codex_stop

    check_registration_stop()
    check_codex_stop(mailbox)


def _sleep_with_stop(mailbox: str, seconds: float) -> None:
    remaining = max(0.0, float(seconds or 0.0))
    while remaining > 0:
        _check_stop_requested(mailbox)
        step = min(0.5, remaining)
        time.sleep(step)
        remaining -= step
    _check_stop_requested(mailbox)


def fetch_latest_otp(
    mailbox: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
    exclude_codes: set[str] | None = None,
) -> str:
    account = get_account_context(mailbox)
    if account is None or not account.password:
        raise MailcomMailError(f"Mail.com 邮箱不存在或密码为空: {mailbox}")

    wait_seconds = int(max_wait if max_wait is not None else _email_cfg.OTP_MAX_WAIT)
    interval = max(1, int(poll_interval if poll_interval is not None else _email_cfg.OTP_POLL_INTERVAL))
    settle = max(0, int(settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS))
    excluded = {str(code) for code in (exclude_codes or set()) if code}
    deadline = time.monotonic() + max(1, wait_seconds)
    best: dict | None = None
    settle_until: float | None = None
    last_error = ""
    client: imaplib.IMAP4_SSL | None = None
    web_client = None
    web_proxy_attempt = 1
    web_proxy_attempt_limit = _web_proxy_attempt_limit()
    use_web_proxy = bool(getattr(_email_cfg, "MAILCOM_WEB_USE_PROXY", True))
    if use_web_proxy:
        with _web_lock(account.base_email):
            web_client = _web_client(account)
        if not str(getattr(web_client, "proxy_url", "") or "").strip():
            if _is_direct_web_fallback(web_client):
                logger.info(
                    "[Mail.com] 复用代理失败后的本机直连 Web 会话: base=%s",
                    account.base_email,
                )
            else:
                raise MailcomMailError(
                    "Mail.com Web 取码已启用代理，但独立代理和全局代理池均为空",
                    kind="proxy_not_configured",
                    resend_recommended=False,
                )
    logger.info(
        "[Mail.com] 开始轮询: email=%s base=%s channel=%s 最长=%ss settle=%ss",
        account.email,
        account.base_email,
        (
            "web_direct_fallback"
            if web_client is not None and _is_direct_web_fallback(web_client)
            else "web_proxy"
            if web_client is not None
            else "imap_direct"
        ),
        wait_seconds,
        settle,
    )

    try:
        while time.monotonic() < deadline:
            _check_stop_requested(mailbox)
            try:
                from core.db import renew_email_allocation_lease

                renew_email_allocation_lease(mailbox)
            except Exception:
                logger.debug("[Mail.com] 邮箱租约续期失败", exc_info=True)
            try:
                if web_client is not None:
                    with _web_lock(account.base_email):
                        # Alias/Codex 并发取同一个基础邮箱时，始终采用缓存中最新的
                        # 会话，避免另一个线程已经换出口后仍继续使用旧 session。
                        web_client = _web_client(account)
                        candidate = _latest_web_candidate(
                            web_client,
                            account,
                            after_ts=after_ts,
                            exclude_codes=excluded,
                        )
                        _web_operation_succeeded(account, web_client)
                else:
                    if client is None:
                        client = _connect(account)
                    candidate = _latest_candidate(
                        client,
                        account,
                        after_ts=after_ts,
                        exclude_codes=excluded,
                    )
                last_error = ""
            except Exception as exc:
                from core.mailcom_web_client import MailcomWebError

                if isinstance(exc, MailcomWebError):
                    if exc.kind in _WEB_LOGIN_BLOCKING_KINDS:
                        _mark_web_login_state(account, exc.kind, exc)
                        with _web_lock(account.base_email):
                            _discard_web_client(account, expected=web_client)
                        raise MailcomMailError(
                            f"Mail.com Web 取码失败 [{exc.kind}]: {exc}",
                            kind=exc.kind,
                            resend_recommended=False,
                        ) from exc
                    if exc.kind == "bad_credentials":
                        raise MailcomMailError(
                            f"Mail.com Web 取码失败 [{exc.kind}]: {exc}",
                            kind="bad_credentials",
                            resend_recommended=False,
                        ) from exc
                    last_error = f"Mail.com Web 取码失败 [{exc.kind}]: {exc}"
                    if _is_direct_web_fallback(web_client):
                        with _web_lock(account.base_email):
                            _discard_web_client(account, expected=web_client)
                        raise MailcomMailError(
                            f"Mail.com Web 本机直连取码失败 [{exc.kind}]: {exc}",
                            kind="web_direct_unavailable",
                            resend_recommended=False,
                        ) from exc
                    if web_proxy_attempt >= web_proxy_attempt_limit:
                        with _web_lock(account.base_email):
                            replacement = _replace_with_direct_web_client(
                                account,
                                expected=web_client,
                            )
                        if replacement is not None:
                            web_client = replacement
                            logger.warning(
                                "[Mail.com] Web 取码代理会话均失败，改用本机直连："
                                "kind=%s proxy_sessions=%s email=%s",
                                exc.kind,
                                web_proxy_attempt_limit,
                                account.email,
                            )
                            continue
                        raise MailcomMailError(
                            "Mail.com Web 取码代理恢复失败 "
                            f"[{exc.kind}]（已尝试 {web_proxy_attempt_limit} 个 session）: {exc}",
                            kind="web_proxy_unavailable",
                            resend_recommended=False,
                        ) from exc

                    previous_client = web_client
                    with _web_lock(account.base_email):
                        _discard_web_client(account, expected=previous_client)
                        web_client = _web_client(account)
                    if not str(getattr(web_client, "proxy_url", "") or "").strip():
                        raise MailcomMailError(
                            "Mail.com Web 换代理后没有可用代理地址",
                            kind="proxy_not_configured",
                            resend_recommended=False,
                        ) from exc
                    web_proxy_attempt += 1
                    logger.warning(
                        "[Mail.com] Web 取码出口失败，已重建代理会话："
                        "kind=%s session=%s/%s email=%s",
                        exc.kind,
                        web_proxy_attempt,
                        web_proxy_attempt_limit,
                        account.email,
                    )
                    # 代理恢复属于同一次取码，不返回浏览器层触发 OTP 重发。
                    continue
                elif isinstance(exc, MailcomMailError):
                    if "登录失败" in str(exc) or "配置非法" in str(exc):
                        raise
                    last_error = str(exc)
                    _close(client)
                    client = None
                    candidate = None
                elif isinstance(exc, (imaplib.IMAP4.abort, imaplib.IMAP4.error, OSError, TimeoutError, ssl.SSLError)):
                    last_error = f"{type(exc).__name__}: {exc}"
                    _close(client)
                    client = None
                    candidate = None
                else:
                    raise

            if candidate and (
                best is None
                or (candidate["timestamp"], candidate["sequence"])
                > (best["timestamp"], best["sequence"])
            ):
                best = candidate
                settle_until = time.monotonic() + settle
                logger.info(
                    "[Mail.com] 锁定 OTP 候选，subject=%r，等待 %ss 确认是否有更新邮件",
                    candidate.get("subject") or "",
                    settle,
                )
            if best is not None and (settle == 0 or time.monotonic() >= float(settle_until or 0)):
                logger.info("[Mail.com] OTP 获取成功: email=%s", account.email)
                return str(best["code"])

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sleep_for = min(float(interval), remaining)
            if settle_until is not None:
                sleep_for = min(sleep_for, max(0.05, settle_until - time.monotonic()))
            _sleep_with_stop(mailbox, sleep_for)
    finally:
        _close(client)
        _trim_web_client_cache()

    detail = f"，最后错误: {last_error}" if last_error else ""
    raise MailcomMailError(f"等待 Mail.com 验证码超时（{wait_seconds}s）{detail}")


atexit.register(close_cached_web_clients)
