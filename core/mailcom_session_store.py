# -*- coding: utf-8 -*-
"""Encrypted persistence for reusable Mail.com Web sessions."""
from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_STATE_PATH = _PROJECT_ROOT / "data" / "mailcom-web-sessions.json"
_KEY_PATH = _PROJECT_ROOT / "data" / "mailcom-web-session.key"
_LOCK = threading.RLock()
_FERNET: Fernet | None = None
_VERSION = 1
_MAX_ENTRIES = 512
_MAX_AGE_SECONDS = 14 * 24 * 60 * 60


def _base(value: object) -> str:
    return str(value or "").strip().lower()


def _entry_key(base_email: str) -> str:
    return hashlib.sha256(_base(base_email).encode("utf-8")).hexdigest()


def _credential_hash(base_email: str, password: str) -> str:
    material = f"{_base(base_email)}\0{str(password or '')}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _safe_timestamp(value: object) -> float:
    try:
        timestamp = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return timestamp if math.isfinite(timestamp) and timestamp > 0 else 0.0


def _cipher() -> Fernet:
    global _FERNET
    if _FERNET is not None:
        return _FERNET
    _KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        key = _KEY_PATH.read_bytes().strip()
    except FileNotFoundError:
        key = Fernet.generate_key()
        try:
            descriptor = os.open(
                _KEY_PATH,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            key = _KEY_PATH.read_bytes().strip()
        else:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(key + b"\n")
    _FERNET = Fernet(key)
    return _FERNET


def _read_document() -> dict[str, Any]:
    try:
        document = json.loads(_STATE_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError, TypeError):
        return {"version": _VERSION, "items": {}}
    if not isinstance(document, dict) or not isinstance(document.get("items"), dict):
        return {"version": _VERSION, "items": {}}
    return document


def _write_document(document: dict[str, Any]) -> None:
    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = _STATE_PATH.with_name(
        f".{_STATE_PATH.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    temporary.write_text(
        json.dumps(document, ensure_ascii=True, separators=(",", ":")),
        encoding="utf-8",
    )
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    os.replace(temporary, _STATE_PATH)


def _prune(items: dict[str, Any], now: float) -> None:
    expired = [
        key
        for key, value in items.items()
        if not isinstance(value, dict)
        or now - _safe_timestamp(value.get("saved_at")) > _MAX_AGE_SECONDS
    ]
    for key in expired:
        items.pop(key, None)
    overflow = len(items) - _MAX_ENTRIES
    if overflow > 0:
        oldest = sorted(
            items,
            key=lambda key: _safe_timestamp((items.get(key) or {}).get("saved_at")),
        )
        for key in oldest[:overflow]:
            items.pop(key, None)


def save_session(
    base_email: str,
    password: str,
    proxy_url: str,
    state: dict[str, Any],
) -> bool:
    normalized = _base(base_email)
    payload_state = dict(state or {})
    if not normalized or not password or not str(payload_state.get("sid") or "").strip():
        return False
    now = time.time()
    payload = {
        "version": _VERSION,
        "base_email": normalized,
        "credential_hash": _credential_hash(normalized, password),
        "proxy_url": str(proxy_url or "").strip(),
        "state": payload_state,
        "saved_at": now,
    }
    encrypted = _cipher().encrypt(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    with _LOCK:
        document = _read_document()
        items = document.setdefault("items", {})
        _prune(items, now)
        items[_entry_key(normalized)] = {"saved_at": now, "ciphertext": encrypted}
        document["version"] = _VERSION
        _write_document(document)
    return True


def load_session(base_email: str, password: str) -> dict[str, Any] | None:
    normalized = _base(base_email)
    if not normalized or not password:
        return None
    key = _entry_key(normalized)
    with _LOCK:
        document = _read_document()
        item = document.get("items", {}).get(key)
    if not isinstance(item, dict):
        return None
    saved_at = _safe_timestamp(item.get("saved_at"))
    if time.time() - saved_at > _MAX_AGE_SECONDS:
        delete_session(normalized)
        return None
    try:
        plaintext = _cipher().decrypt(
            str(item.get("ciphertext") or "").encode("ascii")
        )
        payload = json.loads(plaintext.decode("utf-8"))
    except (InvalidToken, ValueError, TypeError, UnicodeError):
        delete_session(normalized)
        return None
    if (
        not isinstance(payload, dict)
        or _base(payload.get("base_email")) != normalized
        or payload.get("credential_hash") != _credential_hash(normalized, password)
        or not isinstance(payload.get("state"), dict)
        or not str(payload["state"].get("sid") or "").strip()
    ):
        delete_session(normalized)
        return None
    return {
        "proxy_url": str(payload.get("proxy_url") or "").strip(),
        "state": dict(payload["state"]),
        "saved_at": _safe_timestamp(payload.get("saved_at")) or saved_at,
    }


def delete_session(base_email: str) -> bool:
    normalized = _base(base_email)
    if not normalized:
        return False
    with _LOCK:
        document = _read_document()
        items = document.get("items", {})
        if not isinstance(items, dict) or items.pop(_entry_key(normalized), None) is None:
            return False
        _write_document(document)
    return True
