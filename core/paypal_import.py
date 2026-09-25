# -*- coding: utf-8 -*-
"""Parse manually supplied PayPal Billing Agreement credentials.

The import format is ``email--BA approval URL``.  A bare ``BA-...`` token is
accepted as a convenience and is converted to the canonical PayPal approval
URL before storage.  This module deliberately returns validation errors
without echoing the supplied credential.
"""
from __future__ import annotations

import re
from urllib.parse import quote

from core.paypal_extract import validate_paypal_approval_url


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+$")
_BA_TOKEN_RE = re.compile(r"^BA-[A-Z0-9-]+$")
_BA_PREFIX = "https://www.paypal.com/agreements/approve?ba_token="


def normalize_ba_value(value: str) -> tuple[str, str]:
    """Return a validated ``(approval_url, ba_token)`` pair."""
    candidate = str(value or "").strip()
    if not candidate:
        raise ValueError("BA 链为空")
    if _BA_TOKEN_RE.fullmatch(candidate):
        approval_url = f"{_BA_PREFIX}{quote(candidate, safe='-')}"
    else:
        approval_url = candidate
    try:
        canonical_url, ba_token = validate_paypal_approval_url(approval_url)
    except Exception as exc:  # validator exposes several stable error classes
        raise ValueError("BA 链必须是 PayPal agreements/approve 链或 BA-... Token") from exc
    return canonical_url, ba_token


def _split_line(line: str) -> tuple[str, str] | None:
    # Prefer the delimiter whose right-hand side starts with a supported
    # credential.  This keeps local-parts containing ``--`` unambiguous and
    # handles both ``--`` and the existing project's ``----`` convention.
    four_dash = re.match(r"^(.+?)----(https?://|BA-)(.+)$", line)
    if four_dash:
        return four_dash.group(1).strip(), (four_dash.group(2) + four_dash.group(3)).strip()
    for match in re.finditer(r"--", line):
        email = line[: match.start()].strip()
        value = line[match.end() :].strip()
        if value.startswith(("http://", "https://", "BA-")):
            return email, value
    return None


def parse_manual_ba_text(text: str, *, max_lines: int = 5000) -> tuple[list[dict], list[dict]]:
    """Parse a pasted/uploaded text document without returning raw BA values in errors."""
    if not isinstance(text, str):
        raise ValueError("text 必须是字符串")
    records: list[dict] = []
    errors: list[dict] = []
    lines = text.splitlines()
    if len(lines) > max_lines:
        raise ValueError(f"单次最多导入 {max_lines} 行")
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = _split_line(line)
        if parts is None:
            errors.append({"line": line_number, "error": "格式应为 email--BA 链"})
            continue
        email, value = parts
        if not _EMAIL_RE.fullmatch(email):
            errors.append({"line": line_number, "error": "邮箱格式无效"})
            continue
        try:
            ba_url, ba_token = normalize_ba_value(value)
        except ValueError as exc:
            errors.append({"line": line_number, "email": email, "error": str(exc)})
            continue
        records.append({"email": email, "ba_url": ba_url, "ba_token": ba_token})
    return records, errors
