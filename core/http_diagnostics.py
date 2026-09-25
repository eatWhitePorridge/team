"""Bounded, credential-free evidence for HTTP 403 responses; never retries requests."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)
_LOG_PATH = Path(__file__).resolve().parent.parent / "注册日志" / "http-diagnostics" / "403.jsonl"
_LOCK = threading.Lock()
_HANDLER = None
_WRITE_WARNING = False
_BODY_LIMIT = 32768
_HOSTS = {"chatgpt.com", "auth.openai.com", "sentinel.openai.com", "api.openai.com"}
_SEGMENTS = set("api backend-api backend-anon auth accounts account oauth authorize continue token session csrf signin "
                "callback openai password verify mfa mfa-challenge log-in create-account email-verification "
                "email-otp send validate consent workspace select organization organizations users invites "
                "me check seat seats billing subscription subscriptions mfa_info user enroll activate_enrollment".split())
_ERROR_CODES = {"account_deactivated", "access_denied", "permission_denied", "invalid_token", "token_expired",
                "unauthorized", "forbidden", "authentication_error", "unsupported_country", "region_not_supported",
                "rate_limit_exceeded", "insufficient_permissions", "oauth_session_invalid"}


def safe_target(url: str) -> str:
    """Keep the endpoint shape, removing queries, userinfo and dynamic path identifiers."""
    try:
        parsed = urlsplit(str(url))
        host = parsed.hostname if parsed.hostname in _HOSTS else "[other-host]"
        parts = [part if part in _SEGMENTS or re.fullmatch(r"v\d+(?:-\d{4}-\d{2}-\d{2})?", part)
                 else ":redacted" for part in parsed.path.split("/") if part][:12]
        return host + "/" + "/".join(parts)
    except Exception:
        return "[invalid-target]"


def _tag(value) -> str:
    return hashlib.sha256(str(value).encode()).hexdigest()[:12] if value else "none"


def response_evidence(session, response, url: str, method: str) -> dict:
    headers = {str(k).lower(): str(v) for k, v in (getattr(response, "headers", {}) or {}).items()}
    selected = {}
    rules = {
        "cf-ray": r"[0-9a-fA-F]{8,32}-[A-Z]{3}",
        "cf-mitigated": r"challenge",
        "x-request-id": r"[0-9a-fA-F-]{8,64}",
        "x-openai-request-id": r"[0-9a-fA-F-]{8,64}",
        "retry-after": r"\d{1,8}",
        "server": r"cloudflare|nginx|envoy|openresty",
    }
    for key, pattern in rules.items():
        value = headers.get(key, "").strip()
        if value:
            selected[key] = value if re.fullmatch(pattern, value) else "[other]"
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type:
        selected["content-type"] = content_type if content_type in {
            "text/html", "application/json", "application/problem+json", "text/plain",
        } else "[other]"

    content = getattr(response, "content", None)
    if not isinstance(content, bytes):
        content = str(getattr(response, "text", "") or "").encode("utf-8", errors="replace")
    sample = content[:_BODY_LIMIT]
    text = sample.decode("utf-8", errors="replace").lower()
    markers = [name for name, needle in (
        ("cf_challenge_platform", "/cdn-cgi/challenge-platform/"), ("cf_chl", "cf-chl-"),
        ("cf_challenge_options", "_cf_chl_opt"), ("just_a_moment", "just a moment"),
        ("cf_attention_required", "attention required! | cloudflare"),
        ("cf_error_1020", "error 1020"), ("access_denied", "access denied"),
    ) if needle in text]
    error_code = ""
    if content_type in {"application/json", "application/problem+json"} and len(content) <= _BODY_LIMIT:
        try:
            body = json.loads(sample)
            error = body.get("error") if isinstance(body, dict) else None
            code = error.get("code") if isinstance(error, dict) else None
            if code:
                error_code = code if isinstance(code, str) and code in _ERROR_CODES else "[other]"
        except (ValueError, UnicodeDecodeError):
            pass
    # A CF server header or cookie alone does not establish that CF denied the request.
    classification = "unknown_403"
    if selected.get("cf-mitigated") == "challenge":
        classification = "cf_challenge_confirmed"
    elif any(marker.startswith("cf_") for marker in markers):
        classification = "cf_page_markers"
    elif content_type in {"application/json", "application/problem+json"}:
        classification = "json_error"
    target = safe_target(url)
    stage = {
        "chatgpt.com/": "network_preflight",
        "auth.openai.com/oauth/authorize": "bootstrap",
        "auth.openai.com/api/accounts/authorize/continue": "email_submit",
        "auth.openai.com/api/accounts/password/verify": "password",
        "auth.openai.com/api/accounts/mfa/verify": "mfa",
        "auth.openai.com/api/accounts/workspace/select": "workspace",
        "auth.openai.com/oauth/token": "token_exchange",
    }.get(target, "other")
    record = {
        "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "status": 403, "method": method if method in {"GET", "POST", "DELETE", "PUT", "PATCH", "HEAD"} else "UNKNOWN",
        "target": target, "response_target": safe_target(getattr(response, "url", None) or url),
        "stage_hint": stage, "classification": classification, "headers": selected,
        "session_tag": _tag(getattr(session, "device_id", "")), "proxy_tag": _tag(getattr(session, "proxy", "")),
        "body_bytes": len(content), "scanned_bytes": len(sample), "sample_sha256": hashlib.sha256(sample).hexdigest(),
        "body_markers": markers, "error_code": error_code,
    }
    return record


class _PrivateRotatingHandler(RotatingFileHandler):
    def _open(self):
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, "a", encoding="utf-8")

    def handleError(self, record):
        raise  # Let the observer report a write failure without affecting HTTP handling.


def record_forbidden(session, response, url: str, method: str) -> None:
    """Best-effort observation; failures must not change the returned response or retries."""
    global _HANDLER, _WRITE_WARNING
    try:
        payload = json.dumps(response_evidence(session, response, url, method), ensure_ascii=False, separators=(",", ":"))
        logger.warning("[HTTP403诊断] %s", payload)
        with _LOCK:
            if _HANDLER is None:
                _LOG_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                _HANDLER = _PrivateRotatingHandler(_LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
                _HANDLER.setFormatter(logging.Formatter("%(message)s"))
            _HANDLER.emit(logging.LogRecord(__name__, logging.WARNING, __file__, 0, payload, (), None))
    except Exception as exc:
        if not _WRITE_WARNING:
            _WRITE_WARNING = True
            logger.warning("[HTTP403诊断] 独立日志未能保存：error=%s；原请求处理继续", type(exc).__name__)
