# -*- coding: utf-8 -*-
"""Restore a registered account into a visible Roxy browser session."""
from __future__ import annotations

import atexit
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from config import roxybrowser as _roxy_cfg
from core import db
from core.account_cookie_store import inject_selenium_cookies
from core.account_proxy import resolve_registration_proxy
from core.roxybrowser_client import (
    RoxyBrowserClient,
    RoxyOpenResult,
)


logger = logging.getLogger(__name__)
_CHATGPT_HOME = "https://chatgpt.com/"


class AccountBrowserSessionError(RuntimeError):
    def __init__(self, message: str, *, code: str = "browser_session_failed", status: int = 500):
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass
class _ActiveSession:
    session_id: str
    account_id: int
    email: str
    client: RoxyBrowserClient
    opened: RoxyOpenResult
    driver: Any
    opened_at: str
    cookie_count: int
    # A browser session can be shared by the explicit "打开 Roxy" action and
    # account-level workflows (for example accepting a Team invitation).  Keep
    # page operations serialized so a concurrent close/open cannot invalidate
    # a driver halfway through an operation.
    operation_lock: threading.RLock = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.operation_lock is None:
            self.operation_lock = threading.RLock()

    def public(self, *, already_open: bool = False) -> dict:
        return {
            "ok": True,
            "session_id": self.session_id,
            "account_id": self.account_id,
            "email": self.email,
            "profile_id": self.opened.profile_id,
            "opened_at": self.opened_at,
            "cookie_count": self.cookie_count,
            "already_open": bool(already_open),
            "verified": True,
        }


_LOCK = threading.RLock()
_SESSIONS: dict[str, _ActiveSession] = {}
_SESSION_BY_ACCOUNT: dict[int, str] = {}
_OPENING: set[int] = set()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _usable_proxy(account: dict) -> str | None:
    return resolve_registration_proxy(account) or None


def _build_account_driver(opened: RoxyOpenResult):
    # 延迟导入避免账号管理初始化时引入注册服务循环依赖；所有 Roxy 会话
    # 必须复用同一套 automation mask 与低流量初始化。
    from core.roxy_registration import _build_driver

    return _build_driver(opened)


def _driver_alive(session: _ActiveSession) -> bool:
    try:
        session.driver.execute_script("return document.readyState")
        return True
    except Exception:
        return False


def _delete_created_profile(
    session: _ActiveSession,
    *,
    force: bool = False,
) -> None:
    if not session.opened.created_by_run:
        return
    if force:
        session.client.delete_profile(session.opened.profile_id)
        return
    if not bool(getattr(_roxy_cfg, "ROXY_ONE_PROFILE_PER_ACCOUNT", True)):
        return
    if not bool(getattr(_roxy_cfg, "ROXY_DELETE_PROFILE_AFTER_RUN", True)):
        return
    session.client.delete_profile(session.opened.profile_id)


def _cleanup(
    session: _ActiveSession,
    *,
    force_delete_created_profile: bool = False,
) -> None:
    try:
        session.driver.quit()
    except Exception:
        logger.debug("[账号免登录] Selenium 连接关闭失败", exc_info=True)
    try:
        session.client.close_profile(session.opened.profile_id)
        _delete_created_profile(session, force=force_delete_created_profile)
    except Exception:
        logger.debug("[账号免登录] Roxy 环境关闭失败", exc_info=True)
    try:
        session.client.stop_traffic_bridge()
    except Exception:
        logger.debug("[账号免登录] Roxy 流量桥关闭失败", exc_info=True)
    try:
        session.client.close()
    except Exception:
        logger.debug("[账号免登录] Roxy 客户端关闭失败", exc_info=True)


def _cleanup_partial(
    client: RoxyBrowserClient | None,
    opened: RoxyOpenResult | None,
    driver: Any,
    *,
    account_id: int,
) -> None:
    if client is None:
        return
    if opened is None:
        try:
            client.stop_traffic_bridge()
        except Exception:
            logger.debug("[账号免登录] Roxy 流量桥关闭失败", exc_info=True)
        try:
            client.close()
        except Exception:
            logger.debug("[账号免登录] Roxy 客户端关闭失败", exc_info=True)
        return
    placeholder = _ActiveSession(
        session_id="",
        account_id=account_id,
        email="",
        client=client,
        opened=opened,
        driver=driver,
        opened_at=_now(),
        cookie_count=0,
    )
    if driver is not None:
        _cleanup(placeholder)
        return
    try:
        client.close_profile(opened.profile_id)
        _delete_created_profile(placeholder)
    except Exception:
        logger.debug("[账号免登录] 失败环境清理异常", exc_info=True)
    try:
        client.stop_traffic_bridge()
    except Exception:
        logger.debug("[账号免登录] Roxy 流量桥关闭失败", exc_info=True)
    try:
        client.close()
    except Exception:
        logger.debug("[账号免登录] Roxy 客户端关闭失败", exc_info=True)


def _verify_chatgpt_session(
    driver: Any,
    *,
    attempts: int = 3,
    retry_delay: float = 1.5,
) -> None:
    set_timeout = getattr(driver, "set_script_timeout", None)
    if callable(set_timeout):
        set_timeout(20)
    last_status = 0
    max_attempts = max(1, int(attempts or 1))
    delay = max(0.0, float(retry_delay or 0.0))
    for attempt in range(1, max_attempts + 1):
        result = driver.execute_async_script(
            """
            const done = arguments[arguments.length - 1];
            fetch('/api/auth/session', {
              method: 'GET', credentials: 'include', cache: 'no-store',
              headers: {'Accept': 'application/json'}
            }).then(async (response) => {
              done({status: response.status, body: await response.text()});
            }).catch((error) => done({status: 0, error: String(error)}));
            """
        )
        if not isinstance(result, dict):
            last_status = 0
        else:
            last_status = int(result.get("status") or 0)
            try:
                payload = json.loads(str(result.get("body") or "{}"))
            except json.JSONDecodeError:
                payload = {}
            if (
                last_status == 200
                and isinstance(payload, dict)
                and str(payload.get("accessToken") or "")
            ):
                return
            if last_status == 200:
                raise AccountBrowserSessionError(
                    "保存的 Cookie 已过期、被撤销或未形成有效登录态，需要重新登录后再保存",
                    code="cookie_session_invalid",
                    status=409,
                )
        if attempt < max_attempts and delay:
            time.sleep(delay)

    if last_status in {403, 429}:
        raise AccountBrowserSessionError(
            "Cookie 已注入，但当前代理出口被 ChatGPT 风控拦截，请复用注册代理后重试",
            code="session_verification_blocked",
            status=502,
        )
    raise AccountBrowserSessionError(
        "Cookie 已注入，但暂时无法验证 ChatGPT 登录态",
        code="session_verification_failed",
        status=502,
    )


def _pop_session(*, account_id: int | None = None, session_id: str | None = None) -> _ActiveSession | None:
    with _LOCK:
        resolved_id = str(session_id or "")
        if not resolved_id and account_id is not None:
            resolved_id = _SESSION_BY_ACCOUNT.get(int(account_id), "")
        session = _SESSIONS.pop(resolved_id, None) if resolved_id else None
        if session is not None:
            _SESSION_BY_ACCOUNT.pop(session.account_id, None)
        return session


def open_account_browser_session(account_id: int) -> dict:
    account_id = int(account_id)
    stale: _ActiveSession | None = None
    with _LOCK:
        existing_id = _SESSION_BY_ACCOUNT.get(account_id)
        existing = _SESSIONS.get(existing_id or "")
        if existing is not None and _driver_alive(existing):
            return existing.public(already_open=True)
        if existing is not None:
            stale = _pop_session(session_id=existing.session_id)
        if account_id in _OPENING:
            raise AccountBrowserSessionError(
                "该账号的免登录浏览器正在打开，请稍后",
                code="browser_session_opening",
                status=409,
            )
        _OPENING.add(account_id)

    if stale is not None:
        _cleanup(stale)

    client: RoxyBrowserClient | None = None
    opened: RoxyOpenResult | None = None
    driver = None
    active: _ActiveSession | None = None
    try:
        account = db.get_account(account_id)
        if account is None:
            raise AccountBrowserSessionError("账号不存在", code="account_not_found", status=404)
        try:
            credential = db.load_account_web_cookie_credential(account_id)
        except ValueError as exc:
            raise AccountBrowserSessionError(str(exc), code="web_cookies_missing", status=400) from exc
        if not credential or not credential.get("cookies"):
            raise AccountBrowserSessionError(
                "该账号没有可注入的 Web Cookie",
                code="web_cookies_missing",
                status=400,
            )

        client = RoxyBrowserClient()
        opened = client.open_profile(
            proxy_url=_usable_proxy(account),
            headless_override=False,
            retain_profile=True,
        )
        driver = _build_account_driver(opened)
        driver.set_page_load_timeout(int(getattr(_roxy_cfg, "ROXY_PAGE_LOAD_TIMEOUT", 35) or 35))
        cookie_count = inject_selenium_cookies(driver, credential["cookies"])
        if cookie_count <= 0:
            raise AccountBrowserSessionError(
                "Cookie 文件中没有未过期、可注入的 Cookie",
                code="web_cookies_expired",
                status=409,
            )

        driver.get(_CHATGPT_HOME)
        _verify_chatgpt_session(driver)
        active = _ActiveSession(
            session_id=uuid.uuid4().hex,
            account_id=account_id,
            email=str(account.get("email") or ""),
            client=client,
            opened=opened,
            driver=driver,
            opened_at=_now(),
            cookie_count=cookie_count,
        )
        with _LOCK:
            _SESSIONS[active.session_id] = active
            _SESSION_BY_ACCOUNT[account_id] = active.session_id
        logger.info(
            "[账号免登录] 已打开并验证：account_id=%s email=%s profile=%s cookies=%s",
            account_id,
            active.email,
            opened.profile_id,
            cookie_count,
        )
        return active.public()
    except AccountBrowserSessionError:
        if active is None:
            _cleanup_partial(client, opened, driver, account_id=account_id)
        raise
    except Exception as exc:
        if active is None:
            _cleanup_partial(client, opened, driver, account_id=account_id)
        raise AccountBrowserSessionError(
            f"打开免登录浏览器失败: {type(exc).__name__}: {str(exc)[:300]}",
            code="browser_session_failed",
            status=502,
        ) from exc
    finally:
        with _LOCK:
            _OPENING.discard(account_id)


def close_account_browser_session(
    account_id: int | None = None,
    *,
    session_id: str | None = None,
    force_delete_created_profile: bool = False,
) -> dict:
    session = _pop_session(account_id=account_id, session_id=session_id)
    if session is None:
        return {"ok": True, "closed": False, "message": "该账号没有运行中的免登录浏览器"}
    # Wait for an in-flight account workflow (such as Team invitation
    # acceptance) before tearing down the shared driver/profile.
    with session.operation_lock:
        _cleanup(
            session,
            force_delete_created_profile=force_delete_created_profile,
        )
    logger.info(
        "[账号免登录] 已关闭：account_id=%s email=%s profile=%s",
        session.account_id,
        session.email,
        session.opened.profile_id,
    )
    return {
        "ok": True,
        "closed": True,
        "session_id": session.session_id,
        "account_id": session.account_id,
        "profile_id": session.opened.profile_id,
    }


def get_active_account_browser_session(account_id: int) -> _ActiveSession | None:
    """Return the live in-process session for one account, if any.

    The object is intentionally an internal session handle; callers should
    use :func:`run_account_browser_session` so its operation lock is held while
    touching the Selenium driver.  No cookie or token values are exposed.
    """
    normalized = int(account_id)
    with _LOCK:
        session_id = _SESSION_BY_ACCOUNT.get(normalized)
        session = _SESSIONS.get(session_id or "")
        if session is None:
            return None
        if not _driver_alive(session):
            return None
        return session


def run_account_browser_session(
    account_id: int,
    operation: Callable[[Any, _ActiveSession], Any],
    *,
    open_if_missing: bool = True,
) -> Any:
    """Run one operation on the account's shared Roxy Selenium session.

    Existing sessions are reused.  When ``open_if_missing`` is true (the
    default), the saved Web Cookie credential is restored through the normal
    Roxy opener first.  The callback runs while the session operation lock is
    held, preventing the UI's close action from racing with it.
    """
    normalized = int(account_id)
    session = get_active_account_browser_session(normalized)
    if session is None and open_if_missing:
        open_account_browser_session(normalized)
        session = get_active_account_browser_session(normalized)
    if session is None:
        raise AccountBrowserSessionError(
            "该账号没有可用的 Roxy 登录态",
            code="browser_session_missing",
            status=409,
        )
    with session.operation_lock:
        if not _driver_alive(session):
            raise AccountBrowserSessionError(
                "Roxy 登录态已失效，请重新打开",
                code="browser_session_stale",
                status=409,
            )
        result = operation(session.driver, session)
        # Account workflows may refresh/rotate the browser cookie jar. Keep
        # the in-process session summary in sync for the UI without exposing
        # cookie values through the session handle.
        if isinstance(result, dict) and result.get("cookie_count") is not None:
            try:
                session.cookie_count = max(0, int(result.get("cookie_count") or 0))
            except (TypeError, ValueError):
                pass
        return result


def close_all_account_browser_sessions() -> None:
    with _LOCK:
        session_ids = list(_SESSIONS)
    for session_id in session_ids:
        try:
            close_account_browser_session(session_id=session_id)
        except Exception:
            logger.debug("[账号免登录] 进程退出清理失败：session=%s", session_id, exc_info=True)


atexit.register(close_all_account_browser_sessions)


__all__ = [
    "AccountBrowserSessionError",
    "close_account_browser_session",
    "close_all_account_browser_sessions",
    "get_active_account_browser_session",
    "open_account_browser_session",
    "run_account_browser_session",
]
