# -*- coding: utf-8 -*-
"""按实际出口限制纯协议注册的并发和启动频率。"""

from __future__ import annotations

import logging
import random
import re
import threading
import time
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlparse, urlunparse

logger = logging.getLogger(__name__)


@dataclass
class _ExitState:
    active: int = 0
    last_started: float = 0.0


_CONDITION = threading.Condition()
_STATES: dict[str, _ExitState] = {}


def rotate_sticky_proxy_session(proxy_url: str) -> str:
    """为常见动态代理用户名换一个 session/sid，其他字段保持不变。"""
    text = str(proxy_url or "").strip()
    if not text:
        return text
    try:
        parsed = urlparse(text)
        username = unquote(parsed.username or "")
    except ValueError:
        return text
    if not username or not parsed.hostname:
        return text
    rotated, count = re.subn(
        r"(?i)(?P<prefix>(?:session|sid)[_-])(?P<value>[a-z0-9]+)",
        lambda match: f"{match.group('prefix')}{random.randint(10_000_000, 99_999_999)}",
        username,
        count=1,
    )
    if count == 0 or rotated == username:
        return text
    userinfo = quote(rotated, safe="-._~")
    if parsed.password is not None:
        userinfo += ":" + quote(unquote(parsed.password or ""), safe="-._~")
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port else ""
    return urlunparse(parsed._replace(netloc=f"{userinfo}@{host}{port}"))


def sleep_with_stop(seconds: float) -> None:
    """短周期等待，让 WebUI 的停止任务在驻留/退避期间及时生效。"""
    deadline = time.monotonic() + max(0.0, float(seconds or 0.0))
    while True:
        _check_stop_requested()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.5, remaining))


def exit_key(session) -> str:
    """优先使用探测到的出口 IP；不可得时只保留代理端点，不暴露凭证。"""
    geo = getattr(session, "exit_geo", None) or {}
    ip = str(geo.get("ip") or "").strip()
    if ip:
        return f"ip:{ip}"

    proxy = str(getattr(session, "proxy", None) or "").strip()
    if proxy:
        try:
            parsed = urlparse(proxy)
            host = parsed.hostname or "unknown"
            port = parsed.port or 0
            return f"proxy:{host}:{port}"
        except ValueError:
            return "proxy:configured"
    return "direct"


def _limits() -> tuple[int, float]:
    from config import openai_protocol as cfg

    try:
        concurrency = max(0, int(getattr(cfg, "PROTOCOL_EXIT_MAX_CONCURRENCY", 100) or 0))
    except (TypeError, ValueError):
        concurrency = 100
    try:
        interval = max(0.0, float(getattr(cfg, "PROTOCOL_EXIT_MIN_START_INTERVAL", 8.0) or 0.0))
    except (TypeError, ValueError):
        interval = 8.0
    return concurrency, interval


def _check_stop_requested() -> None:
    try:
        from core.registration_service import check_stop_requested

        check_stop_requested()
    except ImportError:
        return


@dataclass
class ProtocolExitLease:
    key: str
    _released: bool = False

    def release(self) -> None:
        if self._released:
            return
        with _CONDITION:
            state = _STATES.get(self.key)
            if state is not None:
                state.active = max(0, state.active - 1)
            self._released = True
            _CONDITION.notify_all()

    def __enter__(self) -> "ProtocolExitLease":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.release()


def acquire_protocol_exit_lease(session) -> ProtocolExitLease:
    """等待当前出口可用；等待以短周期进行，因此任务停止可以及时生效。"""
    key = exit_key(session)
    max_concurrency, min_interval = _limits()

    while True:
        _check_stop_requested()
        with _CONDITION:
            now = time.monotonic()
            state = _STATES.setdefault(key, _ExitState())
            concurrency_ready = max_concurrency == 0 or state.active < max_concurrency
            interval_remaining = max(0.0, min_interval - (now - state.last_started))
            if concurrency_ready and interval_remaining <= 0:
                state.active += 1
                state.last_started = now
                logger.info(
                    "[协议节流] 已取得出口槽位 key=%s active=%s limit=%s",
                    key,
                    state.active,
                    max_concurrency or "不限",
                )
                return ProtocolExitLease(key=key)

            wait_seconds = min(0.5, interval_remaining) if interval_remaining > 0 else 0.5
            _CONDITION.wait(timeout=max(0.05, wait_seconds))


def _reset_for_tests() -> None:
    with _CONDITION:
        _STATES.clear()
        _CONDITION.notify_all()
