# -*- coding: utf-8 -*-
"""Managed proxy leases for PayPal extraction and payment tasks.

Proxy credentials stay in configuration.  Persisted state and registration
snapshots only contain stable hashes, counters, and masked endpoints.
"""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable
from urllib.parse import urlsplit

from config import paypal as cfg
from config import proxy as proxy_cfg
from core import db


_KINDS = {"extract", "payment"}
_LOCK = threading.RLock()
_ACTIVE: dict[tuple[str, str], int] = {}
_CURSOR = {"extract": 0, "payment": 0}


class PayPalProxyPoolError(RuntimeError):
    stage = "proxy"
    code = "proxy_pool"
    retryable = False
    replay_safe = True
    ambiguous = False


@dataclass(frozen=True)
class ProxyLease:
    kind: str
    pool_id: str
    pool_version: str
    entry_id: str
    proxy: str

    def public(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "pool_id": self.pool_id,
            "pool_version": self.pool_version,
            "entry_id": self.entry_id,
        }


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _state_path():
    return db._DATA_DIR / "PayPal代理池状态.json"


def _pool_id(kind: str) -> str:
    if kind == "extract":
        return str(getattr(cfg, "PAYPAL_EXTRACT_POOL_ID", "paypal_extract_pool") or "paypal_extract_pool")
    if kind == "payment":
        return str(getattr(cfg, "PAYPAL_PAYMENT_POOL_ID", "paypal_payment_pool") or "paypal_payment_pool")
    raise ValueError("kind 仅支持 extract / payment")


def _raw_pool(kind: str) -> list[str]:
    if kind == "extract":
        values = getattr(cfg, "PAYPAL_EXTRACT_PROXY_POOL", [])
    elif kind == "payment":
        values = getattr(cfg, "PAYPAL_PAYMENT_PROXY_POOL", [])
    else:
        raise ValueError("kind 仅支持 extract / payment")
    if isinstance(values, str):
        values = values.splitlines()
    return [str(item).strip() for item in (values or []) if str(item).strip()]


def _normalize_proxy(raw: str) -> str:
    value = proxy_cfg.normalize_proxy_url(raw)
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https", "socks5", "socks5h"}:
            raise ValueError("不支持的代理协议")
        if not parsed.hostname or parsed.port is None:
            raise ValueError("代理缺少 host/port")
    except (TypeError, ValueError) as exc:
        raise PayPalProxyPoolError(f"代理格式无效: {type(exc).__name__}") from exc
    return value


def _entry_id(pool_id: str, proxy: str) -> str:
    return hashlib.sha256(f"{pool_id}\0{proxy}".encode("utf-8")).hexdigest()[:16]


def _version(pool_id: str, proxies: Iterable[str]) -> str:
    joined = "\0".join([pool_id, *proxies])
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def _mask_proxy(proxy: str) -> str:
    try:
        parsed = urlsplit(proxy)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        auth = "***:***@" if parsed.username is not None else ""
        return f"{scheme}://{auth}{host}{port}"
    except Exception:
        return "***"


def _configured(kind: str) -> tuple[str, str, list[dict[str, str]]]:
    pool_id = _pool_id(kind)
    proxies: list[str] = []
    seen: set[str] = set()
    for raw in _raw_pool(kind):
        normalized = _normalize_proxy(raw)
        if normalized in seen:
            continue
        seen.add(normalized)
        proxies.append(normalized)
    version = _version(pool_id, proxies)
    return pool_id, version, [
        {
            "entry_id": _entry_id(pool_id, proxy),
            "proxy": proxy,
            "masked_proxy": _mask_proxy(proxy),
        }
        for proxy in proxies
    ]


def _read_state() -> dict:
    value = db._read_json(_state_path(), {"schema_version": 1, "entries": {}})
    if not isinstance(value, dict):
        value = {}
    entries = value.get("entries")
    if not isinstance(entries, dict):
        entries = {}
    return {"schema_version": 1, "entries": entries}


def _write_state(state: dict) -> None:
    db._write_json(_state_path(), state)


def pool_snapshot(kind: str) -> dict[str, Any]:
    pool_id, version, entries = _configured(kind)
    return {
        "pool_id": pool_id,
        "pool_version": version,
        "configured_count": len(entries),
    }


def list_pool(kind: str) -> dict[str, Any]:
    pool_id, version, configured = _configured(kind)
    with _LOCK, db._LOCK:
        state = _read_state()
        rows = []
        for item in configured:
            saved = state["entries"].get(item["entry_id"])
            if not isinstance(saved, dict):
                saved = {}
            rows.append({
                "entry_id": item["entry_id"],
                "masked_proxy": item["masked_proxy"],
                "enabled": saved.get("enabled") is not False,
                "lease_count": max(0, int(saved.get("lease_count") or 0)),
                "success_count": max(0, int(saved.get("success_count") or 0)),
                "failure_count": max(0, int(saved.get("failure_count") or 0)),
                "active_count": _ACTIVE.get((kind, item["entry_id"]), 0),
                "last_selected_at": saved.get("last_selected_at"),
                "last_success_at": saved.get("last_success_at"),
                "last_failure_at": saved.get("last_failure_at"),
                "last_failure_stage": saved.get("last_failure_stage"),
                "last_country": saved.get("last_country"),
                "uploaded_bytes": max(0, int(saved.get("uploaded_bytes") or 0)),
                "downloaded_bytes": max(0, int(saved.get("downloaded_bytes") or 0)),
            })
    return {
        "kind": kind,
        "pool_id": pool_id,
        "pool_version": version,
        "items": rows,
        "total": len(rows),
        "enabled": sum(1 for row in rows if row["enabled"]),
    }


def set_enabled(kind: str, entry_id: str, enabled: bool) -> bool:
    _, _, configured = _configured(kind)
    if entry_id not in {item["entry_id"] for item in configured}:
        return False
    with _LOCK, db._LOCK:
        state = _read_state()
        row = state["entries"].setdefault(entry_id, {})
        row["enabled"] = bool(enabled)
        row["updated_at"] = _now()
        _write_state(state)
    return True


def acquire(kind: str, *, exclude_entry_ids: Iterable[str] = ()) -> ProxyLease:
    global _CURSOR
    pool_id, version, configured = _configured(kind)
    if not configured:
        name = "PAYPAL_EXTRACT_PROXY_POOL" if kind == "extract" else "PAYPAL_PAYMENT_PROXY_POOL"
        raise PayPalProxyPoolError(f"{name} 为空")
    excluded = {str(item) for item in exclude_entry_ids}
    with _LOCK, db._LOCK:
        state = _read_state()
        candidates = []
        for item in configured:
            saved = state["entries"].get(item["entry_id"])
            if isinstance(saved, dict) and saved.get("enabled") is False:
                continue
            if item["entry_id"] in excluded:
                continue
            candidates.append(item)
        if not candidates:
            raise PayPalProxyPoolError("代理池没有可用且未尝试的条目")

        # Prefer the least occupied entry, while rotating ties deterministically.
        start = _CURSOR[kind] % len(candidates)
        rotated = candidates[start:] + candidates[:start]
        selected = min(
            enumerate(rotated),
            key=lambda pair: (_ACTIVE.get((kind, pair[1]["entry_id"]), 0), pair[0]),
        )[1]
        selected_index = candidates.index(selected)
        _CURSOR[kind] = (selected_index + 1) % len(candidates)
        key = (kind, selected["entry_id"])
        _ACTIVE[key] = _ACTIVE.get(key, 0) + 1
        saved = state["entries"].setdefault(selected["entry_id"], {})
        saved["lease_count"] = max(0, int(saved.get("lease_count") or 0)) + 1
        saved["last_selected_at"] = _now()
        saved["updated_at"] = _now()
        _write_state(state)
    return ProxyLease(kind, pool_id, version, selected["entry_id"], selected["proxy"])


def resume(kind: str, entry_id: str, *, expected_pool_version: str = "") -> ProxyLease:
    """Lease the exact configured entry used by an earlier workflow step."""
    pool_id, version, configured = _configured(kind)
    if expected_pool_version and version != str(expected_pool_version):
        raise PayPalProxyPoolError("代理池版本已变化，无法保证任务继续使用同一 Sticky 代理")
    selected = next((item for item in configured if item["entry_id"] == str(entry_id)), None)
    if selected is None:
        raise PayPalProxyPoolError("任务原代理已从代理池移除")
    with _LOCK, db._LOCK:
        state = _read_state()
        saved = state["entries"].get(selected["entry_id"])
        if isinstance(saved, dict) and saved.get("enabled") is False:
            raise PayPalProxyPoolError("任务原代理已被停用")
        key = (kind, selected["entry_id"])
        _ACTIVE[key] = _ACTIVE.get(key, 0) + 1
        saved = state["entries"].setdefault(selected["entry_id"], {})
        saved["lease_count"] = max(0, int(saved.get("lease_count") or 0)) + 1
        saved["last_selected_at"] = _now()
        saved["updated_at"] = _now()
        _write_state(state)
    return ProxyLease(kind, pool_id, version, selected["entry_id"], selected["proxy"])


def suspend(lease: ProxyLease) -> None:
    """Release in-process occupancy without recording success/failure counters."""
    with _LOCK:
        key = (lease.kind, lease.entry_id)
        current = _ACTIVE.get(key, 0)
        if current <= 1:
            _ACTIVE.pop(key, None)
        else:
            _ACTIVE[key] = current - 1


def release(
    lease: ProxyLease,
    *,
    success: bool,
    failure_stage: str = "",
    country: str = "",
    uploaded_bytes: int = 0,
    downloaded_bytes: int = 0,
) -> None:
    with _LOCK, db._LOCK:
        key = (lease.kind, lease.entry_id)
        current = _ACTIVE.get(key, 0)
        if current <= 1:
            _ACTIVE.pop(key, None)
        else:
            _ACTIVE[key] = current - 1
        state = _read_state()
        saved = state["entries"].setdefault(lease.entry_id, {})
        counter = "success_count" if success else "failure_count"
        saved[counter] = max(0, int(saved.get(counter) or 0)) + 1
        stamp = _now()
        saved["last_success_at" if success else "last_failure_at"] = stamp
        if not success:
            saved["last_failure_stage"] = str(failure_stage or "")[:120]
        if country:
            saved["last_country"] = str(country).upper()[:2]
        saved["uploaded_bytes"] = max(0, int(saved.get("uploaded_bytes") or 0)) + max(0, int(uploaded_bytes or 0))
        saved["downloaded_bytes"] = max(0, int(saved.get("downloaded_bytes") or 0)) + max(0, int(downloaded_bytes or 0))
        saved["updated_at"] = stamp
        _write_state(state)


__all__ = [
    "PayPalProxyPoolError", "ProxyLease", "acquire", "resume", "suspend", "release",
    "list_pool", "pool_snapshot", "set_enabled",
]
