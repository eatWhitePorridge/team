# -*- coding: utf-8 -*-
"""Direct ChatGPT/Stripe PayPal Billing Agreement extraction.

The module owns one deterministic task flow.  It never rotates the supplied
proxy and never delegates extraction to another HTTP service.  Account and
promotion eligibility are checked before a Checkout is created.  OAICS is the
preferred mode; a hosted Stripe Checkout is an explicit, observable fallback.

Only a strictly validated PayPal Billing Agreement approval URL is returned.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

try:
    from curl_cffi import requests as curl_requests
except ImportError:  # pragma: no cover - requirements.txt installs curl_cffi
    curl_requests = None


CHATGPT_BASE = "https://chatgpt.com"
STRIPE_BASE = "https://api.stripe.com"
CHECKOUT_PATH = "/backend-api/payments/checkout"
CHECKOUT_URL = CHATGPT_BASE + CHECKOUT_PATH
CHECKOUT_TAXES_URL = CHECKOUT_URL + "/taxes"
CHECKOUT_CONFIRM_URL = CHECKOUT_URL + "/confirm"
CHECKOUT_CUSTOM_START_URL = CHECKOUT_URL + "/custom_payment_method/start"
CHECKOUT_UPDATE_URL = CHECKOUT_URL + "/update"
CHECKOUT_SNAPSHOT_URL = CHECKOUT_URL + "/snapshot"
CHECKOUT_APPROVE_URL = CHECKOUT_URL + "/approve"

PROMO_ID = "plus-1-month-free"
PLAN_NAME = "chatgptplusplan"
STRIPE_VERSION_BASE = "2025-03-31.basil"
STRIPE_VERSION_FULL = (
    "2025-03-31.basil; checkout_server_update_beta=v1; "
    "checkout_manual_approval_preview=v1"
)
PAYPAL_STRIPE_VERSION = (
    "2020-08-27;custom_checkout_beta=v1; "
    "checkout_server_update_beta=v1; checkout_manual_approval_preview=v1"
)
STRIPE_RUNTIME_VERSION = "6f8494a281"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) "
    "Gecko/20100101 Firefox/147.0"
)
CHATGPT_CLIENT_VERSION = "prod-db390ebea64862bf1899c420a4c736e0cf639747"
CHATGPT_CLIENT_BUILD_NUMBER = "7904904"

KNOWN_PUBLISHABLE_KEYS = (
    "pk_live_51Pj377KslHRdbaPgTJYjThzH3f5dt1N1vK7LUp0qh0yNSarhfZ6nfbG7FFlh8KLxVkvdMWN5o6Mc4Vda6NHaSnaV00C2Sbl8Zs",
    "pk_live_51HOrSwC6h1nxGoI3lTAgRjYVrz4dU3fVOabyCcKR3pbEJguCVAlqCxdxCUvoRh1XWwRacViovU3kLKvpkjh7IqkW00iXQsjo3n",
)

_BA_TOKEN_RE = re.compile(r"BA-[A-Z0-9-]+\Z")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+\S+")
_PROXY_AUTH_RE = re.compile(r"(?i)(\b(?:socks5h?|https?)://)[^\s/@]+(?::[^\s/@]*)?@")
_BA_QUERY_RE = re.compile(r"(?i)(ba_token=)BA-[A-Z0-9-]+")
_PAYPAL_URL_CANDIDATE_RE = re.compile(
    r"https://(?:www\.)?paypal\.com/agreements/approve\?[^\s<>\"']+"
)
_TRACE_ID_RE = re.compile(
    r"(?i)(?:BA|EC)-[A-Za-z0-9_-]+|"
    r"(?:oaics|cs_(?:live|test)|seti|pi|pm|cpmt|ctoken|cus)_[A-Za-z0-9_-]+"
)


@dataclass(frozen=True, slots=True)
class _CountryProfile:
    code: str
    currency: str
    locale: str
    timezone: str
    line1: str
    city: str
    postal_code: str
    state: str = ""


_COUNTRIES: dict[str, _CountryProfile] = {
    "BR": _CountryProfile("BR", "USD", "pt-BR", "America/Sao_Paulo", "Avenida Paulista 1000", "Sao Paulo", "01310-100", "SP"),
    "DE": _CountryProfile("DE", "EUR", "de-DE", "Europe/Berlin", "1 Friedrichstrasse", "Berlin", "10117"),
    "US": _CountryProfile("US", "USD", "en-US", "America/New_York", "1 Market St", "San Francisco", "94105", "CA"),
    "GB": _CountryProfile("GB", "GBP", "en-GB", "Europe/London", "1 Canada Square", "London", "E14 5AB"),
    "FR": _CountryProfile("FR", "EUR", "fr-FR", "Europe/Paris", "10 Rue de la Paix", "Paris", "75002"),
    "JP": _CountryProfile("JP", "JPY", "ja-JP", "Asia/Tokyo", "1-1 Marunouchi", "Chiyoda-ku", "100-0005", "Tokyo"),
    "CA": _CountryProfile("CA", "CAD", "en-CA", "America/Toronto", "100 King St W", "Toronto", "M5X 1A9", "ON"),
    "AU": _CountryProfile("AU", "AUD", "en-AU", "Australia/Sydney", "1 Martin Place", "Sydney", "2000", "NSW"),
    "SG": _CountryProfile("SG", "SGD", "en-SG", "Asia/Singapore", "1 Raffles Place", "Singapore", "048616"),
}

_OPENAI_IE_COUNTRIES = {
    "AT", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI",
    "FR", "GB", "GR", "HR", "HU", "IE", "IS", "IT", "LI", "LT", "LU",
    "LV", "MT", "NL", "NO", "PL", "PT", "RO", "SE", "SI", "SK",
}

_OAICS_WRAPPER_KEYS = (
    "checkout_session", "checkoutSession", "session", "checkout", "data",
    "result", "payload", "response", "checkout_state", "checkoutState",
    "checkout_snapshot", "checkoutSnapshot",
)
_OAICS_AMOUNT_PATHS = (
    ("checkout_amount_minor",),
    ("total_summary", "due"),
    ("totalSummary", "due"),
    ("invoice", "amount_due"),
    ("invoice", "amountDue"),
    ("amount_due",),
    ("amountDue",),
    ("amount_total",),
    ("amountTotal",),
    ("total", "total"),
    ("total", "due"),
    ("total", "taxInclusive"),
    ("total", "taxInclusiveAmount"),
)
_STRIPE_AMOUNT_PATHS = (
    ("total_summary", "due"),
    ("total_summary", "total"),
    ("invoice", "amount_due"),
    ("invoice", "total"),
    ("elements_options", "amount"),
    ("payment_intent", "amount"),
)


def _redact(value: object) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    text = _BEARER_RE.sub("Bearer [AT]", text)
    text = _JWT_RE.sub("[AT]", text)
    text = _PROXY_AUTH_RE.sub(r"\1***@", text)
    text = _BA_QUERY_RE.sub(r"\1BA-***", text)
    return text[:500]


def _safe_trace_target(url: object) -> str:
    """Keep only a redacted host/path; queries can contain reusable credentials."""
    try:
        parsed = urlsplit(str(url or ""))
        host = str(parsed.hostname or "").lower()
        path = _TRACE_ID_RE.sub("***", str(parsed.path or "/"))
        return f"{host}{path}"[:240]
    except Exception:
        return "unknown"


class PaypalExtractionError(RuntimeError):
    """Base error with a stable service-facing classification."""

    code = "capability"

    def __init__(
        self,
        message: str,
        *,
        stage: str,
        retryable: bool = False,
        http_status: int | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self.stage = str(stage or "unknown")
        self.detail = _redact(message or "PayPal extraction failed")
        self.retryable = bool(retryable)
        self.http_status = int(http_status) if http_status is not None else None
        self.details = dict(details or {})
        super().__init__(f"[{self.stage}] {self.detail}")

    def as_dict(self) -> dict[str, Any]:
        result = {
            "ok": False,
            "code": self.code,
            "stage": self.stage,
            "error": self.detail,
            "retryable": self.retryable,
            "http_status": self.http_status,
        }
        if self.details:
            result["details"] = self.details
        return result


class PaypalInvalidTokenError(PaypalExtractionError):
    code = "invalid_token"


class PaypalTransportError(PaypalExtractionError):
    code = "transport"


class PaypalCapabilityError(PaypalExtractionError):
    code = "capability"


class PaypalFallbackError(PaypalCapabilityError):
    code = "fallback"


class PaypalNotZeroError(PaypalExtractionError):
    code = "not_zero"

    def __init__(
        self,
        message: str,
        *,
        stage: str,
        amount: int | str | None,
        currency: str,
        observations: list[tuple[str, int]] | None = None,
    ) -> None:
        self.amount = amount
        self.currency = str(currency or "").upper()
        self.observations = list(observations or [])
        super().__init__(
            message,
            stage=stage,
            details={
                "amount": amount,
                "currency": self.currency,
                "observations": [f"{key}={value}" for key, value in self.observations],
            },
        )


class PaypalUnavailableError(PaypalExtractionError):
    code = "unavailable"


# Short aliases are convenient for callers while preserving explicit names.
InvalidTokenError = PaypalInvalidTokenError
TransportError = PaypalTransportError
CapabilityError = PaypalCapabilityError
FallbackError = PaypalFallbackError
NotZeroError = PaypalNotZeroError
UnavailableError = PaypalUnavailableError


class _ConfirmBlocked(Exception):
    pass


def _normalize_access_token(raw: str) -> str:
    token = str(raw or "").strip().strip('"').strip("'")
    if token.lower().startswith("authorization:"):
        token = token.split(":", 1)[1].strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if not token or len(token.split(".")) != 3:
        raise PaypalInvalidTokenError("access token format is invalid", stage="input")
    return token


def _token_profile(access_token: str) -> dict[str, Any]:
    payload_part = access_token.split(".", 2)[1]
    padded = payload_part + "=" * (-len(payload_part) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except Exception as exc:
        raise PaypalInvalidTokenError("access token payload is invalid", stage="input") from exc
    if not isinstance(payload, dict):
        raise PaypalInvalidTokenError("access token payload is invalid", stage="input")
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and time.time() >= float(exp):
        raise PaypalInvalidTokenError("access token is expired", stage="account_check")
    auth = payload.get("https://api.openai.com/auth") or {}
    profile = payload.get("https://api.openai.com/profile") or {}
    return {
        "email": str(profile.get("email") or payload.get("email") or "").strip(),
        "name": str(profile.get("name") or payload.get("name") or "").strip(),
        "account_id": str(auth.get("chatgpt_account_id") or "").strip(),
    }


def _normalize_proxy(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        raise PaypalTransportError(
            "a task-stable proxy is required; direct mode is disabled",
            stage="proxy",
        )
    if "://" not in value:
        if "@" in value:
            value = "socks5h://" + value
        else:
            parts = value.split(":")
            if len(parts) == 2:
                value = f"socks5h://{parts[0]}:{parts[1]}"
            elif len(parts) >= 4:
                host, port, username = parts[:3]
                password = ":".join(parts[3:])
                value = (
                    f"socks5h://{quote(username, safe='')}:{quote(password, safe='')}"
                    f"@{host}:{port}"
                )
            else:
                raise PaypalTransportError("proxy URL is invalid", stage="proxy")
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme == "socks5":
            scheme = "socks5h"
        if scheme not in {"socks5h", "http", "https"}:
            raise ValueError("unsupported scheme")
        port = parsed.port
        if not parsed.hostname or port is None or not 1 <= port <= 65535:
            raise ValueError("missing host or port")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("path/query/fragment is not allowed")
        if (parsed.username is None) != (parsed.password is None):
            raise ValueError("username and password must be paired")
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        auth = ""
        if parsed.username is not None:
            auth = (
                f"{quote(unquote(parsed.username), safe='')}:"
                f"{quote(unquote(parsed.password or ''), safe='')}@"
            )
        return urlunsplit((scheme, f"{auth}{host}:{port}", "", "", ""))
    except PaypalExtractionError:
        raise
    except Exception as exc:
        raise PaypalTransportError("proxy URL is invalid", stage="proxy") from exc


def _nested_present(payload: Any, path: tuple[str, ...]) -> tuple[bool, Any]:
    """Distinguish a missing amount path from an explicitly null value."""

    current = payload
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            return False, None
        current = current[key]
    return True, current


def _minor_amount(value: Any) -> int | None:
    if isinstance(value, Mapping):
        for key in ("minorUnitsAmount", "minor_units_amount", "amount"):
            if value.get(key) is not None:
                return _minor_amount(value.get(key))
        return None
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    text = str(value).strip()
    if not re.fullmatch(r"[+-]?\d+(?:\.0+)?", text):
        return None
    return int(text.split(".", 1)[0])


def amount_observations(payload: Any, *, mode: str) -> list[tuple[str, int]]:
    """Collect payable fields only; product unit prices are intentionally ignored."""

    paths = _OAICS_AMOUNT_PATHS if mode == "oaics" else _STRIPE_AMOUNT_PATHS
    wrappers = _OAICS_WRAPPER_KEYS if mode == "oaics" else ()
    observations: list[tuple[str, int]] = []
    invalid: list[str] = []
    visited: set[int] = set()

    def visit(value: Any, prefix: str = "") -> None:
        if not isinstance(value, Mapping) or id(value) in visited:
            return
        visited.add(id(value))
        for path in paths:
            present, raw = _nested_present(value, path)
            if not present:
                continue
            label = prefix + ".".join(path)
            amount = _minor_amount(raw)
            if amount is None:
                invalid.append(label)
            else:
                observations.append((label, amount))
        for key in wrappers:
            nested = value.get(key)
            if isinstance(nested, Mapping):
                visit(nested, prefix + key + ".")

    visit(payload)
    if invalid:
        # An invalid exposed amount must not be silently ignored.  A sentinel
        # value makes require_zero_amount reject it without exposing raw data.
        observations.extend((f"invalid:{label}", 1) for label in invalid)
    return list(dict.fromkeys(observations))


def checkout_currency(payload: Any) -> str:
    visited: set[int] = set()

    def find(value: Any) -> str:
        if not isinstance(value, Mapping) or id(value) in visited:
            return ""
        visited.add(id(value))
        for key in ("currency", "currency_code", "currencyCode"):
            candidate = str(value.get(key) or "").strip().upper()
            if re.fullmatch(r"[A-Z]{3}", candidate):
                return candidate
        for nested in value.values():
            if isinstance(nested, Mapping):
                candidate = find(nested)
                if candidate:
                    return candidate
        return ""

    return find(payload)


def require_zero_amount(
    payload: Any,
    *,
    mode: str,
    stage: str,
    currency: str = "",
) -> int:
    observations = amount_observations(payload, mode=mode)
    detected_currency = checkout_currency(payload) or str(currency or "").upper()
    if not observations:
        raise PaypalNotZeroError(
            "Checkout did not expose a verifiable payable amount",
            stage=stage,
            amount="unknown",
            currency=detected_currency,
        )
    invalid = [(label, amount) for label, amount in observations if label.startswith("invalid:")]
    if invalid:
        raise PaypalNotZeroError(
            "Checkout exposed an invalid payable amount",
            stage=stage,
            amount="invalid",
            currency=detected_currency,
            observations=invalid,
        )
    nonzero = [(label, amount) for label, amount in observations if amount != 0]
    if nonzero:
        raise PaypalNotZeroError(
            "Checkout payable amount is not zero",
            stage=stage,
            amount=nonzero[0][1],
            currency=detected_currency,
            observations=nonzero,
        )
    return 0


def validate_paypal_approval_url(url: str) -> tuple[str, str]:
    """Return ``(url, ba_token)`` only for the exact PayPal BA endpoint."""

    raw = html.unescape(str(url or "").strip())
    if not raw or any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise PaypalUnavailableError("PayPal approval URL is malformed", stage="redirect")
    try:
        parsed = urlsplit(raw)
        host = (parsed.hostname or "").lower()
        if parsed.scheme.lower() != "https":
            raise ValueError("scheme")
        if host not in {"paypal.com", "www.paypal.com"}:
            raise ValueError("hostname")
        if parsed.port not in (None, 443) or parsed.username or parsed.password:
            raise ValueError("authority")
        if parsed.path != "/agreements/approve" or "#" in raw:
            raise ValueError("path")
        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        tokens = query.get("ba_token") or []
        if len(tokens) != 1 or not _BA_TOKEN_RE.fullmatch(tokens[0]):
            raise ValueError("ba_token")
    except PaypalExtractionError:
        raise
    except Exception as exc:
        raise PaypalUnavailableError(
            "PayPal approval URL failed hostname/path/ba_token validation",
            stage="redirect",
        ) from exc
    return raw, tokens[0]


def _walk_dicts(value: Any):
    if isinstance(value, Mapping):
        yield value
        for nested in value.values():
            yield from _walk_dicts(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            yield from _walk_dicts(nested)


def _find_string(
    payload: Any,
    names: tuple[str, ...],
    *,
    prefixes: tuple[str, ...] = (),
) -> str:
    for item in _walk_dicts(payload):
        for name in names:
            value = item.get(name)
            if not isinstance(value, str):
                continue
            value = value.strip()
            if value and (not prefixes or value.startswith(prefixes)):
                return value
    return ""


def _payment_method_types(payload: Any) -> list[str]:
    methods: list[str] = []
    for item in _walk_dicts(payload):
        for key in ("payment_method_types", "paymentMethodTypes"):
            values = item.get(key)
            if not isinstance(values, list):
                continue
            for value in values:
                if isinstance(value, Mapping):
                    value = value.get("type")
                normalized = str(value or "").strip().lower()
                if normalized and normalized not in methods:
                    methods.append(normalized)
        specs = item.get("payment_method_specs")
        if isinstance(specs, list):
            for value in specs:
                normalized = str(value.get("type") if isinstance(value, Mapping) else "").strip().lower()
                if normalized and normalized not in methods:
                    methods.append(normalized)
    return methods


def _custom_payment_methods(payload: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in _walk_dicts(payload):
        values = item.get("custom_payment_methods")
        if values is None:
            values = item.get("customPaymentMethods")
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, Mapping):
                continue
            method_id = str(value.get("id") or "").strip()
            if method_id.startswith("cpmt_") and method_id not in seen:
                seen.add(method_id)
                result.append(dict(value))
    result.sort(key=lambda item: 0 if "paypal" in json.dumps(item).lower() else 1)
    return result


def _extract_redirect(payload: Any) -> str:
    if isinstance(payload, Mapping):
        action = payload.get("next_action")
        if isinstance(action, Mapping):
            redirect = action.get("redirect_to_url")
            if isinstance(redirect, Mapping):
                value = str(redirect.get("url") or "").strip()
                if value.startswith("https://"):
                    return value
            value = str(action.get("url") or "").strip()
            if value.startswith("https://"):
                return value
        for nested in payload.values():
            value = _extract_redirect(nested)
            if value:
                return value
    elif isinstance(payload, (list, tuple)):
        for nested in payload:
            value = _extract_redirect(nested)
            if value:
                return value
    return ""


def _submission_state(payload: Any) -> str:
    for item in _walk_dicts(payload):
        submission = item.get("submission_attempt")
        if isinstance(submission, Mapping):
            return str(submission.get("state") or submission.get("status") or "").lower()
    return ""


def _has_current_paypal_decline(payload: Any, payment_method_id: str) -> bool:
    """Return true only for a generic decline attributable to this submission."""

    if isinstance(payload, Mapping):
        decline_code = str(payload.get("decline_code") or "").strip().lower()
        if decline_code == "generic_decline":
            payment_method = payload.get("payment_method")
            if isinstance(payment_method, Mapping):
                declined_id = str(payment_method.get("id") or "").strip()
            elif isinstance(payment_method, str):
                declined_id = payment_method.strip()
            else:
                declined_id = ""
            if not payment_method_id or not declined_id or declined_id == payment_method_id:
                return True
        return any(
            _has_current_paypal_decline(value, payment_method_id)
            for value in payload.values()
        )
    if isinstance(payload, (list, tuple)):
        return any(
            _has_current_paypal_decline(value, payment_method_id)
            for value in payload
        )
    return False


def _is_zero_amount(value: Any) -> bool:
    if value is None or str(value).strip() == "":
        return False
    try:
        from decimal import Decimal, InvalidOperation
        return Decimal(str(value).strip()) == 0
    except (InvalidOperation, TypeError, ValueError):
        return False


def _is_positive_amount(value: Any) -> bool:
    if value is None or str(value).strip() == "":
        return False
    try:
        from decimal import Decimal, InvalidOperation
        return Decimal(str(value).strip()) > 0
    except (InvalidOperation, TypeError, ValueError):
        return False


def _clean_redirect_candidate(value: Any) -> str:
    candidate = html.unescape(str(value or "")).strip().strip("\"'")
    candidate = candidate.replace("\\u0026", "&").replace("\\/", "/")
    if "%3A%2F%2F" in candidate.upper():
        candidate = unquote(candidate)
    return candidate


def _is_paypal_approval_url(value: Any) -> bool:
    try:
        parsed = urlsplit(_clean_redirect_candidate(value))
    except Exception:
        return False
    host = str(parsed.hostname or "").lower().rstrip(".")
    return (
        host in {"paypal.com", "www.paypal.com"}
        and parsed.path.lower().rstrip("/") == "/agreements/approve"
        and any(key.lower() == "ba_token" and token for key, token in parse_qsl(parsed.query))
    )


def _is_paypal_pm_redirect_url(value: Any) -> bool:
    try:
        parsed = urlsplit(_clean_redirect_candidate(value))
    except Exception:
        return False
    return (
        str(parsed.hostname or "").lower().rstrip(".") == "pm-redirects.stripe.com"
        and parsed.path.lower().startswith("/authorize/")
    )


def _paypal_handoff_key(value: Any) -> str:
    candidate = _clean_redirect_candidate(value)
    try:
        parsed = urlsplit(candidate)
    except Exception:
        return ""
    host = str(parsed.hostname or "").lower().rstrip(".")
    if host == "pm-redirects.stripe.com" and parsed.path.lower().startswith("/authorize/"):
        return "pm:" + hashlib.sha256(parsed.path.rstrip("/").encode()).hexdigest()
    if host in {"paypal.com", "www.paypal.com"} and parsed.path.lower().rstrip("/") == "/agreements/approve":
        for key, token in parse_qsl(parsed.query):
            if key.lower() == "ba_token" and token:
                return "ba:" + hashlib.sha256(token.encode()).hexdigest()
    return ""


def _submission_attempt_id(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    submission = payload.get("submission_attempt") or {}
    if not isinstance(submission, dict):
        return ""
    for key in ("id", "submission_id", "attempt_id"):
        value = submission.get(key)
        if isinstance(value, dict):
            value = value.get("id")
        if str(value or "").strip():
            return str(value).strip()
    return ""


def _find_payment_method_id(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    candidates = [
        payload.get("payment_method"),
        (payload.get("submission_attempt") or {}).get("payment_method"),
        (payload.get("setup_intent") or {}).get("payment_method"),
        (payload.get("payment_intent") or {}).get("payment_method"),
    ]
    for value in candidates:
        if isinstance(value, dict):
            value = value.get("id")
        value = str(value or "")
        if value.startswith("pm_"):
            return value
    return ""


def _explicit_checkout_due(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return None
    summary = payload.get("total_summary")
    invoice = payload.get("invoice")
    submission = payload.get("submission_attempt")
    candidates = (
        summary.get("due") if isinstance(summary, dict) else None,
        invoice.get("amount_due") if isinstance(invoice, dict) else None,
        submission.get("expected_amount") if isinstance(submission, dict) else None,
        submission.get("amount_due") if isinstance(submission, dict) else None,
    )
    return next((value for value in candidates if value is not None), None)


def _extract_paypal_redirect(payload: Any) -> str:
    candidate = _clean_redirect_candidate(_extract_redirect(payload))
    if _is_paypal_approval_url(candidate) or _is_paypal_pm_redirect_url(candidate):
        return candidate
    raw = json.dumps(payload, ensure_ascii=False) if isinstance(payload, (dict, list)) else ""
    for pattern in (
        r"https?://pm-redirects\.stripe\.com/authorize/[^\s\"'<>\\]+",
        r"https?://(?:www\.)?paypal\.com/agreements/approve\?[^\s\"'<>\\]+",
    ):
        for match in re.finditer(pattern, raw, re.I):
            candidate = _clean_redirect_candidate(match.group(0))
            if _is_paypal_approval_url(candidate) or _is_paypal_pm_redirect_url(candidate):
                return candidate
    return ""


def _poll_rejection_reason(
    payload: Any,
    redirect: str,
    *,
    expected_submission_id: str = "",
    rejected_submission_id: str = "",
    rejected_handoff_keys: set[str] | None = None,
    require_zero_due: bool = False,
) -> str:
    observed = _submission_attempt_id(payload)
    if expected_submission_id and observed and observed != expected_submission_id:
        return "submission-id-mismatch"
    if rejected_submission_id and observed == rejected_submission_id:
        return "stale-risk-submission"
    if require_zero_due:
        due = _explicit_checkout_due(payload)
        if due is not None and not _is_zero_amount(due):
            return "non-zero-due"
    key = _paypal_handoff_key(redirect)
    if key and key in (rejected_handoff_keys or set()):
        return "stale-risk-handoff"
    return ""


def _validate_promo_update_context(payload: Any, session_id: str) -> str:
    if not isinstance(payload, dict):
        return ""
    candidates = [payload]
    for value in (payload.get("checkout_session"), payload.get("data")):
        if isinstance(value, dict):
            candidates.append(value)
            if isinstance(value.get("checkout_session"), dict):
                candidates.append(value["checkout_session"])
    returned_ids: set[str] = set()
    for index, item in enumerate(candidates):
        value = item.get("checkout_session_id")
        if value is None and index > 0:
            value = item.get("id")
        if str(value or "").strip():
            returned_ids.add(str(value).strip())
    mismatched = sorted(value for value in returned_ids if value != str(session_id))
    if mismatched:
        raise PaypalCapabilityError(
            "优惠更新返回了不同的 Checkout Session",
            stage="stripe_promo_update",
        )
    for item in candidates:
        key = str(item.get("publishable_key") or "").strip()
        if key.startswith("pk_"):
            return key
    return ""


def _record_submission_context(ctx: dict[str, Any], payload: dict[str, Any], *, amount: Any, source: str) -> None:
    submission = payload.get("submission_attempt") or {}
    if not isinstance(submission, dict):
        submission = {}
    ctx["submission_attempt"] = dict(submission)
    ctx["submission_source"] = source
    ctx["submission_expected_amount"] = amount
    ctx["submission_state"] = str(submission.get("state") or "")
    ctx["submission_id"] = _submission_attempt_id(payload)
    ctx["submission_observed_amount"] = _explicit_checkout_due(payload)
    method = submission.get("payment_method")
    if isinstance(method, dict):
        method = method.get("id")
    if str(method or "").startswith("pm_"):
        ctx["submission_payment_method_id"] = str(method)


def _inherit_submission_context(previous: Mapping[str, Any], refreshed: dict[str, Any], *, original_amount: Any) -> None:
    for key in ("guid", "muid", "sid", "client_session_id"):
        if previous.get(key) and not refreshed.get(key):
            refreshed[key] = previous[key]
    refreshed["original_checkout_amount"] = original_amount


def _validate_zero_due_submission(payload: Any, *, risk_submission_id: str, expected_payment_method_id: str) -> tuple[dict[str, Any], str]:
    if not isinstance(payload, dict):
        raise PaypalCapabilityError("优惠后 0 元 PayPal confirm 返回了非对象响应", stage="stripe_confirm")
    submission = payload.get("submission_attempt") or {}
    if not isinstance(submission, dict) or not submission:
        raise PaypalCapabilityError("优惠后 0 元 PayPal confirm 未返回新的 submission_attempt", stage="stripe_confirm")
    submission_id = _submission_attempt_id(payload)
    if risk_submission_id and submission_id and submission_id == risk_submission_id:
        raise PaypalCapabilityError("优惠后 confirm 仍指向全价 submission", stage="stripe_confirm")
    response_pm = _find_payment_method_id(payload)
    if expected_payment_method_id and response_pm and response_pm != expected_payment_method_id:
        raise PaypalCapabilityError("优惠后 submission 切换了 PayPal PaymentMethod", stage="stripe_confirm")
    due = _explicit_checkout_due(payload)
    if due is not None and not _is_zero_amount(due):
        raise PaypalNotZeroError(
            "优惠后 submission 仍为非 0 元账单",
            stage="stripe_confirm",
            amount=due,
            currency="",
        )
    return submission, submission_id


def _processor_entity(country: str) -> str:
    return "openai_ie" if country.upper() in _OPENAI_IE_COUNTRIES else "openai_llc"


class PaypalExtractor:
    """Execute one direct, non-rotating PayPal extraction task."""

    def __init__(
        self,
        *,
        access_token: str,
        proxy: str,
        email: str = "",
        requested_mode: str = "oaics",
        promo_strategy: str = "post_update",
        promo_id: str = PROMO_ID,
        country: str = "BR",
        billing_country: str = "DE",
        request_timeout: float = 30,
        account_result: Mapping[str, Any] | None = None,
        account_checker: Callable[..., Mapping[str, Any]] | None = None,
        session_factory: Callable[[str, str], Any] | None = None,
        sentinel_provider: Callable[..., Mapping[str, str] | str] | None = None,
        trace: Callable[[dict[str, Any]], None] | None = None,
        allow_stripe_fallback: bool = True,
        sleep: Callable[[float], None] = time.sleep,
        zero_sync_attempts: int = 6,
        max_redirect_hops: int = 6,
    ) -> None:
        self.access_token = _normalize_access_token(access_token)
        self.token_profile = _token_profile(self.access_token)
        self.proxy = _normalize_proxy(proxy)
        self.requested_mode = str(requested_mode or "oaics").strip().lower()
        self.promo_strategy = str(promo_strategy or "post_update").strip().lower()
        self.promo_id = str(promo_id or PROMO_ID).strip() or PROMO_ID
        self.country = str(country or "BR").strip().upper()
        self.billing_country = str(billing_country or "DE").strip().upper()
        if self.requested_mode not in {"oaics", "stripe"}:
            raise PaypalCapabilityError(
                "requested_mode must be oaics or stripe", stage="input"
            )
        if self.promo_strategy not in {"upfront", "post_update"}:
            raise PaypalCapabilityError(
                "promo_strategy must be upfront or post_update", stage="input"
            )
        if self.country not in _COUNTRIES:
            raise PaypalCapabilityError("proxy country is unsupported", stage="input")
        if self.billing_country not in _COUNTRIES:
            raise PaypalCapabilityError("billing country is unsupported", stage="input")
        self.profile = _COUNTRIES[self.billing_country]
        resolved_email = str(email or self.token_profile.get("email") or "").strip()
        if not resolved_email or "@" not in resolved_email:
            raise PaypalInvalidTokenError(
                "account email is unavailable", stage="input"
            )
        name = str(self.token_profile.get("name") or "").strip()
        self.billing = {
            "email": resolved_email,
            "name": name[:128] or resolved_email.split("@", 1)[0][:64],
            "address": {
                "country": self.profile.code,
                "line1": self.profile.line1,
                "city": self.profile.city,
                "postal_code": self.profile.postal_code,
                "state": self.profile.state,
            },
        }
        self.request_timeout = max(1.0, float(request_timeout))
        self.account_result = dict(account_result) if account_result is not None else None
        self.account_checker = account_checker
        self.session_factory = session_factory
        self.sentinel_provider = sentinel_provider
        if trace is not None and not callable(trace):
            raise PaypalCapabilityError("trace callback is invalid", stage="input")
        self.trace = trace
        self.allow_stripe_fallback = bool(allow_stripe_fallback)
        self.sleep = sleep
        self.zero_sync_attempts = max(1, int(zero_sync_attempts))
        self.max_redirect_hops = max(1, int(max_redirect_hops))
        self.device_id = str(uuid.uuid4())
        self.oai_session_id = str(uuid.uuid4())
        self.session: Any = None
        self.stage = "init"
        self._sdk_source = ""
        self._sdk_url = ""

    def _emit_trace(
        self,
        *,
        status: str,
        message: str,
        stage: str | None = None,
        **details: Any,
    ) -> None:
        if self.trace is None:
            return
        try:
            self.trace({
                "status": status,
                "message": _redact(message),
                "stage": str(stage or self.stage or "unknown"),
                **details,
            })
        except Exception:
            return

    def _account_check(self) -> dict[str, Any]:
        self.stage = "account_check"
        if self.account_result is not None:
            raw = dict(self.account_result)
        else:
            checker = self.account_checker
            if checker is None:
                from core.chatgpt_plan import check_account_plan

                checker = check_account_plan
            try:
                raw = dict(
                    checker(
                        self.access_token,
                        proxy=self.proxy,
                        timeout=self.request_timeout,
                        max_attempts=1,
                        retry_delay=0,
                    )
                    or {}
                )
            except PaypalExtractionError:
                raise
            except Exception as exc:
                raise PaypalTransportError(
                    f"account eligibility check failed: {type(exc).__name__}: {_redact(exc)}",
                    stage=self.stage,
                    retryable=True,
                ) from exc

        status = int(raw.get("http_status") or 0)
        error_detail = _redact(raw.get("error") or "").strip()
        error = error_detail.lower()
        if not raw.get("ok"):
            if status == 401 or "token" in error and any(
                marker in error for marker in ("expired", "invalid", "unauthorized")
            ):
                raise PaypalInvalidTokenError(
                    "account check rejected the access token",
                    stage=self.stage,
                    http_status=status or None,
                )
            if raw.get("retryable") or status in {403, 408, 409, 425, 429} or status >= 500:
                detail = "account eligibility could not be verified"
                if error_detail:
                    detail = f"{detail}: {error_detail}"
                raise PaypalTransportError(
                    detail,
                    stage=self.stage,
                    retryable=True,
                    http_status=status or None,
                )
            raise PaypalUnavailableError(
                "account is unavailable for Checkout",
                stage=self.stage,
                http_status=status or None,
            )

        plan = str(raw.get("current_plan_type") or "").strip().lower()
        if plan and plan != "free":
            raise PaypalUnavailableError(
                "account is not on the free plan", stage=self.stage
            )
        if "plus_trial_eligible" in raw and not bool(raw.get("plus_trial_eligible")):
            raise PaypalUnavailableError(
                "account is not eligible for the Plus promotion", stage=self.stage
            )
        promo_status = str(raw.get("plus_trial_status") or "").strip().lower()
        if promo_status in {"not_eligible", "redeemed", "unavailable"}:
            raise PaypalUnavailableError(
                f"Plus promotion is {promo_status}", stage=self.stage
            )
        if promo_status == "unknown" or (
            raw.get("plus_trial_eligible") is True
            and "promo_check_ok" in raw
            and not raw.get("promo_check_ok")
        ):
            raise PaypalTransportError(
                "Plus promotion eligibility is temporarily unknown",
                stage=self.stage,
                retryable=True,
                http_status=int(raw.get("promo_check_http_status") or 0) or None,
            )
        return {
            "ok": True,
            "account_id": str(raw.get("account_id") or self.token_profile.get("account_id") or ""),
            "current_plan_type": plan or None,
            "plus_trial_eligible": raw.get("plus_trial_eligible"),
            "plus_trial_status": promo_status or None,
            "promo_campaign_id": str(raw.get("plus_trial_campaign_id") or self.promo_id),
        }

    def _new_session(self) -> Any:
        if self.session_factory is not None:
            session = self.session_factory("paypal", self.proxy)
        else:
            if curl_requests is None:
                raise PaypalTransportError(
                    "curl_cffi is required for PayPal extraction", stage="session"
                )
            session = curl_requests.Session(impersonate="firefox147")
        if not hasattr(session, "headers"):
            session.headers = {}
        if hasattr(session, "trust_env"):
            session.trust_env = False
        self._pin_proxy(session)
        return session

    def _pin_proxy(self, session: Any) -> None:
        session.proxies = {"http": self.proxy, "https": self.proxy}

    def _configure_session(self) -> None:
        self.session = self._new_session()
        language = self.profile.locale.split("-", 1)[0]
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept-Language": f"{self.profile.locale},{language};q=0.9,en;q=0.8",
            }
        )
        jar = getattr(self.session, "cookies", None)
        if jar is not None and hasattr(jar, "set"):
            try:
                jar.set("oai-did", self.device_id, domain="chatgpt.com", path="/")
            except Exception:
                pass

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        if self.session is None:
            raise PaypalTransportError("HTTP session is not initialized", stage=self.stage)
        self._pin_proxy(self.session)
        verb = str(method or "GET").upper()
        target = _safe_trace_target(url)
        started = time.monotonic()
        try:
            response = getattr(self.session, method.lower())(url, **kwargs)
        except PaypalExtractionError:
            raise
        except Exception as exc:
            self._emit_trace(
                status="failed",
                stage=self.stage,
                message=f"{verb} {target} 请求失败：{type(exc).__name__}",
                method=verb,
                target=target,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            raise PaypalTransportError(
                f"network request failed: {type(exc).__name__}: {_redact(exc)}",
                stage=self.stage,
                retryable=True,
            ) from exc
        http_status = int(getattr(response, "status_code", 0) or 0)
        self._emit_trace(
            status="response" if 200 <= http_status < 400 else "http_error",
            stage=self.stage,
            message=f"{verb} {target} -> HTTP {http_status or 'unknown'}",
            method=verb,
            target=target,
            http_status=http_status or None,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return response

    @staticmethod
    def _response_json(response: Any, *, stage: str) -> dict[str, Any]:
        try:
            payload = response.json()
        except Exception:
            try:
                payload = json.loads(str(getattr(response, "text", "") or "{}"))
            except Exception as exc:
                raise PaypalCapabilityError(
                    "upstream response is not JSON", stage=stage
                ) from exc
        if not isinstance(payload, dict):
            raise PaypalCapabilityError("upstream JSON is not an object", stage=stage)
        return payload

    def _raise_http(
        self,
        response: Any,
        *,
        label: str,
        capability: bool = False,
    ) -> None:
        status = int(getattr(response, "status_code", 0) or 0)
        if status == 401:
            raise PaypalInvalidTokenError(
                f"{label} rejected the access token",
                stage=self.stage,
                http_status=status,
            )
        if status in {403, 408, 409, 425, 429} or status >= 500:
            raise PaypalTransportError(
                f"{label} temporarily failed",
                stage=self.stage,
                retryable=True,
                http_status=status,
            )
        error_type = PaypalCapabilityError if capability else PaypalUnavailableError
        raise error_type(
            f"{label} failed",
            stage=self.stage,
            http_status=status or None,
        )

    def _context_headers(self, *, referer: str, route: str = "") -> dict[str, str]:
        language = self.profile.locale.split("-", 1)[0]
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Origin": CHATGPT_BASE,
            "Referer": referer,
            "User-Agent": USER_AGENT,
            "Accept-Language": f"{self.profile.locale},{language};q=0.9,en;q=0.8",
            "OAI-Language": self.profile.locale,
            "oai-device-id": self.device_id,
            "oai-session-id": self.oai_session_id,
            "oai-client-version": CHATGPT_CLIENT_VERSION,
            "oai-client-build-number": CHATGPT_CLIENT_BUILD_NUMBER,
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }
        if route:
            headers["x-openai-target-path"] = route
            headers["x-openai-target-route"] = route
        return headers

    @staticmethod
    def _stripe_headers() -> dict[str, str]:
        return {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Origin": "https://js.stripe.com",
            "Referer": "https://js.stripe.com/",
            "Content-Type": "application/x-www-form-urlencoded",
        }

    def _warmup(self, page_url: str) -> None:
        self.stage = "warmup"
        response = self._request(
            "get",
            page_url,
            headers={
                **self._context_headers(referer=CHATGPT_BASE + "/"),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "upgrade-insecure-requests": "1",
                "sec-fetch-dest": "document",
                "sec-fetch-mode": "navigate",
            },
            timeout=self.request_timeout,
        )
        if int(getattr(response, "status_code", 0) or 0) >= 400:
            self._raise_http(response, label="ChatGPT page warmup")

    def _cookie_header(self) -> str:
        jar = getattr(self.session, "cookies", None)
        values: dict[str, str] = {"oai-did": self.device_id}
        if jar is not None:
            try:
                for cookie in jar:
                    name = str(getattr(cookie, "name", "") or "")
                    value = str(getattr(cookie, "value", "") or "")
                    domain = str(getattr(cookie, "domain", "") or "").lower()
                    if name and value and (not domain or "chatgpt.com" in domain or "openai.com" in domain):
                        values[name] = value
            except Exception:
                try:
                    values.update({str(k): str(v) for k, v in jar.get_dict().items()})
                except Exception:
                    pass
        return "; ".join(f"{key}={value}" for key, value in values.items())

    def _default_sentinel_provider(
        self,
        *,
        flow: str,
        page_url: str,
    ) -> dict[str, str]:
        """Mint Sentinel with the repository's Node SDK runner and this task session."""

        from core.sentinel_runner import (
            generate_sentinel_artifacts,
            generate_sentinel_prepare_token,
        )

        if not self._sdk_source:
            frame_url = CHATGPT_BASE + "/backend-api/sentinel/frame.html"
            frame = self._request(
                "get",
                frame_url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": page_url,
                },
                timeout=self.request_timeout,
            )
            if int(getattr(frame, "status_code", 0) or 0) != 200:
                self._raise_http(frame, label="Sentinel frame")
            match = re.search(
                r'''src=["']([^"']*/sentinel/[^"']+/sdk\.js[^"']*)["']''',
                str(getattr(frame, "text", "") or ""),
            )
            if not match:
                raise PaypalCapabilityError(
                    "Sentinel frame did not expose sdk.js", stage="sentinel"
                )
            sdk_url = urljoin(frame_url, html.unescape(match.group(1)))
            parsed = urlsplit(sdk_url)
            if parsed.scheme != "https" or (parsed.hostname or "").lower() not in {
                "chatgpt.com", "sentinel.openai.com"
            }:
                raise PaypalCapabilityError("Sentinel sdk URL is invalid", stage="sentinel")
            sdk = self._request(
                "get",
                sdk_url,
                headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Referer": frame_url},
                timeout=self.request_timeout,
            )
            source = str(getattr(sdk, "text", "") or "")
            if int(getattr(sdk, "status_code", 0) or 0) != 200 or "SentinelSDK" not in source:
                self._raise_http(sdk, label="Sentinel sdk")
            if len(source.encode("utf-8", errors="replace")) > 2 * 1024 * 1024:
                raise PaypalCapabilityError("Sentinel sdk is too large", stage="sentinel")
            self._sdk_url, self._sdk_source = sdk_url, source

        cookie_header = self._cookie_header()
        runner_context = {
            "user_agent": USER_AGENT,
            "page_url": page_url,
            "browser_profile": {
                "user_agent": USER_AGENT,
                "navigator_language": self.profile.locale,
                "navigator_languages": [self.profile.locale, "en-US", "en"],
                "timezone_iana": self.profile.timezone,
                "browser_family": "firefox",
            },
            "cookie": cookie_header,
        }
        try:
            prepare = generate_sentinel_prepare_token(
                sdk_source=self._sdk_source,
                sdk_url=self._sdk_url,
                flow=flow,
                device_id=self.device_id,
                **runner_context,
            )
        except Exception as exc:
            raise PaypalTransportError(
                f"Sentinel prepare failed: {type(exc).__name__}",
                stage="sentinel",
                retryable=True,
            ) from exc
        body = {"p": prepare, "id": self.device_id, "flow": flow}
        challenge_response = self._request(
            "post",
            CHATGPT_BASE + "/backend-api/sentinel/req",
            data=json.dumps(body, separators=(",", ":")),
            headers={
                "Content-Type": "text/plain;charset=UTF-8",
                "Origin": CHATGPT_BASE,
                "Referer": CHATGPT_BASE + "/backend-api/sentinel/frame.html",
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Cookie": cookie_header,
            },
            timeout=max(self.request_timeout, 60.0),
        )
        if int(getattr(challenge_response, "status_code", 0) or 0) != 200:
            self._raise_http(challenge_response, label="Sentinel challenge")
        challenge = self._response_json(challenge_response, stage="sentinel")
        try:
            artifacts = generate_sentinel_artifacts(
                challenge,
                prepare_token=prepare,
                sdk_source=self._sdk_source,
                sdk_url=self._sdk_url,
                flow=flow,
                device_id=self.device_id,
                **runner_context,
            )
        except Exception as exc:
            raise PaypalTransportError(
                f"Sentinel artifacts failed: {type(exc).__name__}",
                stage="sentinel",
                retryable=True,
            ) from exc
        headers = {"OpenAI-Sentinel-Token": str(artifacts.token or "")}
        if artifacts.so_token:
            headers["OpenAI-Sentinel-SO-Token"] = str(artifacts.so_token)
        return headers

    def _sentinel_headers(self, *, flow: str, page_url: str) -> dict[str, str]:
        self.stage = "sentinel"
        try:
            if self.sentinel_provider is None:
                raw: Mapping[str, str] | str = self._default_sentinel_provider(
                    flow=flow, page_url=page_url
                )
            else:
                raw = self.sentinel_provider(
                    session=self.session,
                    flow=flow,
                    device_id=self.device_id,
                    page_url=page_url,
                    proxy=self.proxy,
                    user_agent=USER_AGENT,
                    cookie_header=self._cookie_header(),
                    timeout=self.request_timeout,
                )
        except PaypalExtractionError:
            raise
        except Exception as exc:
            raise PaypalTransportError(
                f"Sentinel provider failed: {type(exc).__name__}",
                stage=self.stage,
                retryable=True,
            ) from exc
        if isinstance(raw, str):
            headers = {"OpenAI-Sentinel-Token": raw}
        else:
            headers = {str(key): str(value) for key, value in dict(raw or {}).items() if value}
        main = next(
            (value for key, value in headers.items() if key.lower() == "openai-sentinel-token"),
            "",
        )
        if not main:
            raise PaypalCapabilityError(
                "Sentinel provider returned no main token", stage=self.stage
            )
        return headers

    def _create_checkout(self, mode: str, promo_strategy: str) -> dict[str, Any]:
        mode = str(mode or "").strip().lower()
        if mode not in {"oaics", "stripe"}:
            raise PaypalCapabilityError(
                "Checkout mode must be oaics or stripe", stage="checkout_create"
            )
        upfront = mode == "oaics" or promo_strategy == "upfront"
        sentinel_headers = self._sentinel_headers(
            flow="chatgpt_checkout", page_url=CHATGPT_BASE + "/"
        )
        # Sentinel generation temporarily owns the stage. Restore the actual
        # request stage so HTTP traces and failures identify Checkout correctly.
        self.stage = "checkout_create"
        headers = {
            **self._context_headers(referer=CHATGPT_BASE + "/", route=CHECKOUT_PATH),
            "Content-Type": "application/json",
            "Accept": "*/*",
            **sentinel_headers,
        }
        body: dict[str, Any] = {
            "entry_point": "all_plans_pricing_modal",
            "plan_name": PLAN_NAME,
            "billing_details": {
                "country": self.profile.code,
                "currency": self.profile.currency,
            },
            "check_card_proxy": True,
        }
        if mode == "oaics":
            body["checkout_ui_mode"] = "custom"
        if upfront:
            body["promo_campaign"] = {
                "promo_campaign_id": self.promo_id,
                "is_coupon_from_query_param": False,
            }
        self._emit_trace(
            status="step",
            stage=self.stage,
            message=(
                "Checkout 请求契约："
                f"requested={mode} "
                f"ui={'custom' if mode == 'oaics' else 'hosted(omitted)'} "
                f"promo={'upfront' if upfront else 'post_update'}"
            ),
            requested_mode=mode,
            checkout_ui_mode="custom" if mode == "oaics" else "omitted",
            promo_on_create=upfront,
        )
        response = self._request(
            "post",
            CHECKOUT_URL,
            json=body,
            headers=headers,
            timeout=max(self.request_timeout, 30.0),
        )
        if int(getattr(response, "status_code", 0) or 0) != 200:
            self._raise_http(
                response,
                label=f"{mode} Checkout create",
                capability=mode == "oaics",
            )
        payload = self._response_json(response, stage=self.stage)
        raw_session = str(payload.get("checkout_session_id") or "").strip()
        if re.fullmatch(r"oaics_[A-Za-z0-9_-]+", raw_session):
            actual_mode = "oaics"
        elif re.fullmatch(r"cs_(?:live|test)_[A-Za-z0-9_-]+", raw_session):
            actual_mode = "stripe"
        else:
            searchable = "\n".join(
                str(payload.get(key) or "")
                for key in ("checkout_url", "url", "openai_checkout_url")
            )
            match = re.search(r"oaics_[A-Za-z0-9_-]+", searchable)
            if match:
                raw_session, actual_mode = match.group(0), "oaics"
            else:
                match = re.search(r"cs_(?:live|test)_[A-Za-z0-9_-]+", searchable)
                if not match:
                    raise PaypalCapabilityError(
                        "Checkout response did not contain a supported session",
                        stage=self.stage,
                    )
                raw_session, actual_mode = match.group(0), "stripe"
        processor = str(payload.get("processor_entity") or "").strip() or _processor_entity(
            self.profile.code
        )
        checkout_url = str(
            payload.get("checkout_url")
            or payload.get("url")
            or payload.get("openai_checkout_url")
            or ""
        ).strip()
        if raw_session not in checkout_url:
            checkout_url = f"{CHATGPT_BASE}/checkout/{processor}/{raw_session}"
        raw_key = str(
            payload.get("stripe_publishable_key")
            or payload.get("publishable_key")
            or payload.get("publishableKey")
            or payload.get("stripePublishableKey")
            or payload.get("key")
            or ""
        )
        key_match = re.search(r"pk_(?:live|test)_[A-Za-z0-9]+", raw_key)
        return {
            "session_id": raw_session,
            "actual_mode": actual_mode,
            "processor_entity": processor,
            "checkout_url": checkout_url,
            "publishable_key": key_match.group(0) if key_match else "",
            "promo_applied": "upfront" if upfront else "post_update",
        }

    def _checkout_with_fallback(self) -> tuple[dict[str, Any], str]:
        fallback_reason = ""
        if self.requested_mode == "stripe":
            checkout = self._create_checkout("stripe", self.promo_strategy)
            if checkout["actual_mode"] != "stripe":
                raise PaypalUnavailableError(
                    "hosted Stripe request returned an OAICS session; "
                    "retry with a fresh Checkout route",
                    stage="checkout_create",
                )
            return checkout, fallback_reason

        try:
            checkout = self._create_checkout("oaics", "upfront")
        except PaypalCapabilityError as exc:
            if not self.allow_stripe_fallback:
                raise
            fallback_reason = "oaics_capability_error"
            checkout = self._create_checkout("stripe", self.promo_strategy)
            if checkout["actual_mode"] != "stripe":
                raise PaypalFallbackError(
                    "Stripe fallback did not return a hosted session",
                    stage="checkout_create",
                ) from exc
            return checkout, fallback_reason

        if checkout["actual_mode"] == "oaics":
            return checkout, fallback_reason
        if not self.allow_stripe_fallback:
            raise PaypalFallbackError(
                "OAICS returned a hosted Stripe session; explicit Stripe retry is required",
                stage="checkout_create",
            )
        fallback_reason = "oaics_returned_hosted_stripe"
        if self.promo_strategy == "post_update":
            # The OAICS attempt necessarily carried the promotion upfront.  A
            # fresh hosted Checkout is required to preserve post_update semantics.
            checkout = self._create_checkout("stripe", "post_update")
            if checkout["actual_mode"] != "stripe":
                raise PaypalFallbackError(
                    "Stripe fallback did not return a hosted session",
                    stage="checkout_create",
                )
        return checkout, fallback_reason

    def _oaics_headers(self, checkout: Mapping[str, Any], route: str) -> dict[str, str]:
        return {
            **self._context_headers(referer=str(checkout["checkout_url"]), route=route),
            "Content-Type": "application/json",
        }

    def _fetch_oaics_state(self, checkout: Mapping[str, Any]) -> dict[str, Any]:
        self.stage = "oaics_state"
        route = "/backend-api/payments/checkout/{processor_entity}/{checkout_session_id}"
        response = self._request(
            "get",
            f"{CHECKOUT_URL}/{checkout['processor_entity']}/{checkout['session_id']}",
            headers=self._oaics_headers(checkout, route),
            timeout=max(self.request_timeout, 45.0),
        )
        if int(getattr(response, "status_code", 0) or 0) != 200:
            self._raise_http(response, label="OAICS state")
        return self._response_json(response, stage=self.stage)

    def _submit_oaics_taxes(self, checkout: Mapping[str, Any]) -> dict[str, Any]:
        self.stage = "oaics_taxes"
        address = dict(self.billing["address"])
        body = {
            "checkout_session_id": checkout["session_id"],
            "checkout_email": self.billing["email"],
            "billing_country": self.profile.code,
            "billing_name": self.billing["name"],
            "currency": self.profile.currency,
            "tax_id": None,
            "processor_entity": checkout["processor_entity"],
            "billing_address": {
                "country": self.profile.code,
                "line1": address.get("line1", ""),
                "line2": "",
                "city": address.get("city", ""),
                "state": address.get("state", ""),
                "postal_code": address.get("postal_code", ""),
            },
        }
        route = CHECKOUT_PATH + "/taxes"
        response = self._request(
            "post",
            CHECKOUT_TAXES_URL,
            json=body,
            headers=self._oaics_headers(checkout, route),
            timeout=max(self.request_timeout, 50.0),
        )
        if int(getattr(response, "status_code", 0) or 0) != 200:
            self._raise_http(response, label="OAICS taxes")
        return self._response_json(response, stage=self.stage)

    def _wait_oaics_zero(
        self,
        checkout: Mapping[str, Any],
        initial: Mapping[str, Any],
    ) -> dict[str, Any]:
        payload = dict(initial)
        last: PaypalNotZeroError | None = None
        for attempt in range(4):
            if attempt:
                self.sleep(0.8)
                payload = self._fetch_oaics_state(checkout)
            try:
                require_zero_amount(
                    payload,
                    mode="oaics",
                    stage="oaics_zero",
                    currency=self.profile.currency,
                )
                detected = checkout_currency(payload)
                if detected and detected != self.profile.currency:
                    raise PaypalUnavailableError(
                        "OAICS currency does not match billing country",
                        stage="oaics_zero",
                        details={"expected": self.profile.currency, "actual": detected},
                    )
                return payload
            except PaypalNotZeroError as exc:
                if exc.amount == "invalid":
                    raise
                last = exc
        assert last is not None
        raise last

    def _oaics_elements(self, state: Mapping[str, Any]) -> dict[str, Any]:
        self.stage = "oaics_elements"
        publishable_key = _find_string(
            state,
            ("publishable_key", "stripe_publishable_key", "publishableKey"),
            prefixes=("pk_live_", "pk_test_"),
        )
        customer_secret = _find_string(
            state,
            ("customer_session_client_secret", "customerSessionClientSecret"),
        )
        if not publishable_key or not customer_secret:
            raise PaypalCapabilityError(
                "OAICS state lacks Stripe publishable key or customer secret",
                stage=self.stage,
            )
        stripe_js_id = str(uuid.uuid4())
        methods = _payment_method_types(state)
        params: dict[str, Any] = {
            "customer_session_client_secret": customer_secret,
            "client_betas[0]": "custom_checkout_server_updates_1",
            "client_betas[1]": "custom_checkout_manual_approval_1",
            "deferred_intent[mode]": "subscription",
            "deferred_intent[amount]": "0",
            "deferred_intent[currency]": self.profile.currency.lower(),
            "deferred_intent[setup_future_usage]": "off_session",
            "currency": self.profile.currency.lower(),
            "key": publishable_key,
            "_stripe_version": STRIPE_VERSION_FULL,
            "elements_init_source": "stripe.elements",
            "referrer_host": "chatgpt.com",
            "stripe_js_id": stripe_js_id,
            "locale": self.profile.locale,
            "type": "deferred_intent",
        }
        for index, method in enumerate(methods):
            params[f"deferred_intent[payment_method_types][{index}]"] = method
        response = self._request(
            "get",
            STRIPE_BASE + "/v1/elements/sessions",
            params=params,
            headers=self._stripe_headers(),
            timeout=max(self.request_timeout, 40.0),
        )
        if int(getattr(response, "status_code", 0) or 0) != 200:
            self._raise_http(response, label="Stripe OAICS elements")
        payload = self._response_json(response, stage=self.stage)
        payload["_publishable_key"] = publishable_key
        payload["_stripe_js_id"] = stripe_js_id
        payload["_payment_method_types"] = methods
        return payload

    def _oaics_confirmation_token(
        self,
        state: Mapping[str, Any],
        elements: Mapping[str, Any],
    ) -> str:
        self.stage = "oaics_confirmation_token"
        key = str(elements.get("_publishable_key") or "")
        stripe_js_id = str(elements.get("_stripe_js_id") or uuid.uuid4())
        element_id = _find_string(
            elements, ("session_id", "sessionId", "id"), prefixes=("elements_session_",)
        )
        config_id = _find_string(
            elements, ("config_id", "elements_session_config_id", "elementsSessionConfigId")
        )
        customer = _find_string(
            elements,
            ("customer", "customer_id", "customerId"),
            prefixes=("cus_",),
        )
        address = self.billing["address"]
        guid, muid, sid = (uuid.uuid4().hex + uuid.uuid4().hex[:6] for _ in range(3))
        body: dict[str, Any] = {
            "payment_method_data[type]": "paypal",
            "payment_method_data[billing_details][name]": self.billing["name"],
            "payment_method_data[billing_details][email]": self.billing["email"],
            "payment_method_data[guid]": guid,
            "payment_method_data[muid]": muid,
            "payment_method_data[sid]": sid,
            "payment_method_data[payment_user_agent]": (
                f"stripe.js/{STRIPE_RUNTIME_VERSION}; stripe-js-v3/{STRIPE_RUNTIME_VERSION}; "
                "payment-element; deferred-intent"
            ),
            "payment_method_data[referrer]": CHATGPT_BASE,
            "payment_method_data[time_on_page]": "30000",
            "setup_future_usage": "off_session",
            "set_as_default_payment_method": "false",
            "mandate_data[customer_acceptance][type]": "online",
            "mandate_data[customer_acceptance][online][infer_from_client]": "true",
            "client_context[currency]": self.profile.currency.lower(),
            "client_context[mode]": "subscription",
            "client_attribution_metadata[client_session_id]": stripe_js_id,
            "client_attribution_metadata[merchant_integration_source]": "elements",
            "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
            "client_attribution_metadata[merchant_integration_version]": "2021",
            "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
            "client_attribution_metadata[payment_method_selection_flow]": "automatic",
            "client_attribution_metadata[merchant_integration_additional_elements][0]": "expressCheckout",
            "client_attribution_metadata[merchant_integration_additional_elements][1]": "payment",
            "client_attribution_metadata[merchant_integration_additional_elements][2]": "address",
            "key": key,
        }
        for field in ("line1", "city", "state", "postal_code", "country"):
            if address.get(field):
                body[f"payment_method_data[billing_details][address][{field}]"] = address[field]
        for index, method in enumerate(elements.get("_payment_method_types") or []):
            body[f"client_context[payment_method_types][{index}]"] = method
        if customer:
            body["client_context[customer]"] = customer
        for prefix in ("client_attribution_metadata", "payment_method_data[client_attribution_metadata]"):
            if element_id:
                body[f"{prefix}[elements_session_id]"] = element_id
            if config_id:
                body[f"{prefix}[elements_session_config_id]"] = config_id
        response = self._request(
            "post",
            STRIPE_BASE + "/v1/confirmation_tokens",
            data=body,
            headers={
                **self._stripe_headers(),
                "Authorization": f"Bearer {key}",
                "Stripe-Version": STRIPE_VERSION_FULL,
            },
            timeout=max(self.request_timeout, 40.0),
        )
        if int(getattr(response, "status_code", 0) or 0) != 200:
            self._raise_http(response, label="Stripe ConfirmationToken")
        payload = self._response_json(response, stage=self.stage)
        token = _find_string(
            payload, ("id", "confirmation_token", "confirmationToken"), prefixes=("ctoken_", "ct_")
        )
        if not token:
            raise PaypalCapabilityError(
                "Stripe ConfirmationToken response lacks a token", stage=self.stage
            )
        return token

    def _oaics_confirm(
        self,
        checkout: Mapping[str, Any],
        selected_type: str,
        *,
        confirmation_token: str = "",
    ) -> dict[str, Any]:
        self.stage = "oaics_confirm"
        route = CHECKOUT_PATH + "/confirm"
        headers = {
            **self._oaics_headers(checkout, route),
            **self._sentinel_headers(
                flow="checkout_session_approval", page_url=str(checkout["checkout_url"])
            ),
        }
        body: dict[str, Any] = {
            "checkout_session_id": checkout["session_id"],
            "selected_payment_method_type": selected_type,
        }
        if confirmation_token:
            body["confirm_token"] = confirmation_token
        else:
            body["processor_entity"] = checkout["processor_entity"]
        response = self._request(
            "post",
            CHECKOUT_CONFIRM_URL,
            json=body,
            headers=headers,
            timeout=max(self.request_timeout, 50.0),
        )
        if int(getattr(response, "status_code", 0) or 0) != 200:
            self._raise_http(response, label="OAICS confirm")
        payload = self._response_json(response, stage=self.stage)
        status = str(payload.get("status") or "").strip().lower()
        if status == "blocked":
            raise _ConfirmBlocked
        if not status:
            raise PaypalCapabilityError(
                "OAICS confirm response lacks status", stage=self.stage
            )
        if confirmation_token and status in {
            "declined", "failed", "error", "requires_action"
        }:
            raise PaypalUnavailableError(
                f"OAICS confirm returned {status}", stage=self.stage
            )
        if not confirmation_token and status != "success":
            raise PaypalUnavailableError(
                f"OAICS custom confirm returned {status}", stage=self.stage
            )
        return payload

    def _oaics_intent_confirm(
        self,
        confirmation_token: str,
        app_confirm: Mapping[str, Any],
        elements: Mapping[str, Any],
    ) -> dict[str, Any]:
        self.stage = "oaics_intent_confirm"
        client_secret = _find_string(app_confirm, ("client_secret",))
        if "_secret_" not in client_secret:
            raise PaypalCapabilityError(
                "OAICS confirm lacks an Intent client secret", stage=self.stage
            )
        intent_id = client_secret.split("_secret_", 1)[0]
        if intent_id.startswith("pi_"):
            expected_type, collection = "payment_intent", "payment_intents"
        elif intent_id.startswith("seti_"):
            expected_type, collection = "setup_intent", "setup_intents"
        else:
            raise PaypalCapabilityError("OAICS Intent type is unsupported", stage=self.stage)
        intent_type = str(app_confirm.get("type") or "").strip().lower()
        if intent_type and intent_type != expected_type:
            raise PaypalCapabilityError(
                "OAICS Intent type does not match its client secret", stage=self.stage
            )
        key = str(elements.get("_publishable_key") or "")
        body = {
            "confirmation_token": confirmation_token,
            "client_secret": client_secret,
            "use_stripe_sdk": "true",
            "key": key,
        }
        return_url = _find_string(app_confirm, ("confirm_return_url", "return_url"))
        if return_url:
            body["return_url"] = return_url
        response = self._request(
            "post",
            f"{STRIPE_BASE}/v1/{collection}/{intent_id}/confirm",
            data=body,
            headers={
                **self._stripe_headers(),
                "Authorization": f"Bearer {key}",
                "Stripe-Version": STRIPE_VERSION_FULL,
            },
            timeout=max(self.request_timeout, 50.0),
        )
        if int(getattr(response, "status_code", 0) or 0) != 200:
            self._raise_http(response, label="Stripe OAICS Intent confirm")
        return self._response_json(response, stage=self.stage)

    def _oaics_standard_paypal(
        self,
        checkout: Mapping[str, Any],
        state: Mapping[str, Any],
    ) -> str:
        elements = self._oaics_elements(state)
        token = self._oaics_confirmation_token(state, elements)
        try:
            app_confirm = self._oaics_confirm(
                checkout, "paypal", confirmation_token=token
            )
        except _ConfirmBlocked:
            try:
                app_confirm = self._oaics_confirm(
                    checkout, "paypal", confirmation_token=token
                )
            except _ConfirmBlocked as exc:
                raise PaypalUnavailableError(
                    "OAICS PayPal confirm remained blocked", stage="oaics_confirm"
                ) from exc
        redirect = _extract_redirect(app_confirm)
        if redirect:
            return redirect
        intent = self._oaics_intent_confirm(token, app_confirm, elements)
        redirect = _extract_redirect(intent)
        if not redirect:
            raise PaypalUnavailableError(
                "OAICS PayPal Intent returned no redirect", stage="oaics_intent_confirm"
            )
        return redirect

    def _oaics_custom_paypal(
        self,
        checkout: Mapping[str, Any],
        methods: list[dict[str, Any]],
    ) -> str:
        for method in methods:
            method_id = str(method.get("id") or "")
            try:
                self._oaics_confirm(checkout, method_id)
            except _ConfirmBlocked:
                try:
                    self._oaics_confirm(checkout, method_id)
                except _ConfirmBlocked as exc:
                    raise PaypalUnavailableError(
                        "OAICS custom confirm remained blocked", stage="oaics_confirm"
                    ) from exc
            self.stage = "oaics_custom_start"
            route = CHECKOUT_PATH + "/custom_payment_method/start"
            body = {
                "checkout_session_id": checkout["session_id"],
                "processor_entity": checkout["processor_entity"],
                "custom_payment_method_type_id": method_id,
            }
            response = self._request(
                "post",
                CHECKOUT_CUSTOM_START_URL,
                json=body,
                headers=self._oaics_headers(checkout, route),
                timeout=max(self.request_timeout, 60.0),
            )
            if int(getattr(response, "status_code", 0) or 0) != 200:
                self._raise_http(response, label="OAICS custom payment start")
            payload = self._response_json(response, stage=self.stage)
            if str(payload.get("status") or "").strip().lower() != "requires_action":
                raise PaypalUnavailableError(
                    "OAICS custom payment start did not require action",
                    stage=self.stage,
                )
            redirect = _extract_redirect(payload)
            action = payload.get("next_action") if isinstance(payload, Mapping) else {}
            payment_type = str(
                (action or {}).get("paymentMethodType")
                or (action or {}).get("payment_method_type")
                or ""
            ).lower()
            if redirect and ("paypal" in payment_type or "paypal" in redirect.lower()):
                return redirect
        raise PaypalUnavailableError(
            "OAICS custom methods did not expose PayPal", stage="oaics_custom_start"
        )

    def _run_oaics(self, checkout: Mapping[str, Any]) -> tuple[str, int, str]:
        state = self._fetch_oaics_state(checkout)
        taxes = self._submit_oaics_taxes(checkout)
        self._wait_oaics_zero(checkout, taxes or state)
        for attempt in range(3):
            if attempt:
                self.sleep(0.8 * attempt)
            # The taxes response can contain amount/payment method summaries but
            # omit the Stripe keys required by the provider flow. Fetch the
            # canonical Checkout state again, matching link-pp's provider stage.
            state = self._fetch_oaics_state(checkout)
            require_zero_amount(
                state,
                mode="oaics",
                stage="oaics_provider_zero",
                currency=self.profile.currency,
            )
            methods = _payment_method_types(state)
            if "paypal" in methods:
                return self._oaics_standard_paypal(checkout, state), 0, (
                    checkout_currency(state) or self.profile.currency
                )
            custom = _custom_payment_methods(state)
            if custom:
                return self._oaics_custom_paypal(checkout, custom), 0, (
                    checkout_currency(state) or self.profile.currency
                )
            if methods:
                raise PaypalUnavailableError(
                    "OAICS payment_method_types does not contain paypal",
                    stage="oaics_methods",
                    details={"methods": methods},
                )
        raise PaypalUnavailableError(
            "OAICS did not expose a determinable PayPal method", stage="oaics_methods"
        )

    def _stripe_publishable_key(self, checkout: Mapping[str, Any]) -> str:
        key = str(checkout.get("publishable_key") or "")
        if key.startswith(("pk_live_", "pk_test_")):
            return key
        self.stage = "stripe_key_probe"
        for candidate in KNOWN_PUBLISHABLE_KEYS:
            response = self._request(
                "post",
                f"{STRIPE_BASE}/v1/payment_pages/{checkout['session_id']}/init",
                data={
                    "key": candidate,
                    "_stripe_version": STRIPE_VERSION_BASE,
                    "browser_locale": self.profile.locale,
                },
                headers=self._stripe_headers(),
                timeout=min(self.request_timeout, 15.0),
            )
            if int(getattr(response, "status_code", 0) or 0) == 200:
                return candidate
        raise PaypalCapabilityError(
            "Stripe publishable key could not be determined", stage=self.stage
        )

    def _stripe_init(
        self,
        checkout: Mapping[str, Any],
        key: str,
    ) -> tuple[dict[str, Any], str, dict[str, Any]]:
        self.stage = "stripe_init"
        stripe_js_id = str(uuid.uuid4())
        url = f"{STRIPE_BASE}/v1/payment_pages/{checkout['session_id']}/init"
        last_response: Any = None
        for version in (STRIPE_VERSION_FULL, STRIPE_VERSION_BASE):
            body: dict[str, Any] = {
                "browser_locale": self.profile.locale,
                "browser_timezone": self.profile.timezone,
                "elements_session_client[elements_init_source]": "custom_checkout",
                "elements_session_client[referrer_host]": "chatgpt.com",
                "elements_session_client[stripe_js_id]": stripe_js_id,
                "elements_session_client[locale]": self.profile.locale,
                "elements_session_client[is_aggregation_expected]": "false",
                "elements_options_client[saved_payment_method][enable_save]": "never",
                "elements_options_client[saved_payment_method][enable_redisplay]": "never",
                "key": key,
                "_stripe_version": version,
            }
            if version == STRIPE_VERSION_FULL:
                body["elements_session_client[client_betas][0]"] = "custom_checkout_server_updates_1"
                body["elements_session_client[client_betas][1]"] = "custom_checkout_manual_approval_1"
            response = self._request(
                "post", url, data=body, headers=self._stripe_headers(), timeout=self.request_timeout
            )
            last_response = response
            if int(getattr(response, "status_code", 0) or 0) == 200:
                payload = self._response_json(response, stage=self.stage)
                methods = _payment_method_types(payload)
                observations = amount_observations(payload, mode="stripe")
                observed_amount = observations[0][1] if observations else None
                context = {
                    "stripe_js_id": stripe_js_id,
                    "elements_session_id": f"elements_session_{uuid.uuid4().hex[:11]}",
                    "elements_session_config_id": "",
                    "client_session_id": str(uuid.uuid4()),
                    "guid": uuid.uuid4().hex + uuid.uuid4().hex[:6],
                    "muid": uuid.uuid4().hex + uuid.uuid4().hex[:6],
                    "sid": uuid.uuid4().hex + uuid.uuid4().hex[:6],
                    "config_id": str(payload.get("config_id") or ""),
                    "init_checksum": str(payload.get("init_checksum") or ""),
                    "currency": checkout_currency(payload).lower(),
                    "amount": observed_amount,
                    "checkout_amount": observed_amount,
                    "runtime_version": STRIPE_RUNTIME_VERSION,
                    "payment_method_types": methods,
                    "stripe_hosted_url": str(payload.get("stripe_hosted_url") or ""),
                }
                return payload, version, context
            if int(getattr(response, "status_code", 0) or 0) != 400:
                break
        assert last_response is not None
        self._raise_http(last_response, label="Stripe init")
        raise AssertionError("unreachable")

    def _stripe_update_promo(self, checkout: Mapping[str, Any]) -> dict[str, Any]:
        self.stage = "stripe_promo_update"
        route = CHECKOUT_PATH + "/update"
        body = {
            "checkout_session_id": checkout["session_id"],
            "processor_entity": checkout["processor_entity"],
            "plan_name": PLAN_NAME,
            "price_interval": "month",
            "seat_quantity": 1,
            "discount_code": None,
            "promo_campaign": {
                "promo_campaign_id": self.promo_id,
                "is_coupon_from_query_param": False,
            },
        }
        response = self._request(
            "post",
            CHECKOUT_UPDATE_URL,
            json=body,
            headers={
                **self._context_headers(referer=str(checkout["checkout_url"]), route=route),
                "Content-Type": "application/json",
            },
            timeout=max(self.request_timeout, 45.0),
        )
        if int(getattr(response, "status_code", 0) or 0) != 200:
            self._raise_http(response, label="Stripe promotion update")
        return self._response_json(response, stage=self.stage)

    def _prepare_stripe_zero(
        self,
        checkout: Mapping[str, Any],
        key: str,
    ) -> tuple[dict[str, Any], str, dict[str, Any]]:
        init_payload, version, context = self._stripe_init(checkout, key)
        self._require_stripe_paypal(init_payload, stage="stripe_init")
        self._stripe_elements(checkout, key, version, context)
        try:
            require_zero_amount(
                init_payload,
                mode="stripe",
                stage="stripe_zero",
                currency=self.profile.currency,
            )
            return init_payload, version, context
        except PaypalNotZeroError as initial_error:
            if self.promo_strategy != "post_update" or initial_error.amount in {
                "unknown", "invalid"
            }:
                raise
            self._stripe_update_promo(checkout)
            last = initial_error
            for attempt in range(self.zero_sync_attempts):
                self.sleep(0.8 if attempt == 0 else 1.5)
                init_payload, version, context = self._stripe_init(checkout, key)
                self._require_stripe_paypal(init_payload, stage="stripe_init_after_update")
                try:
                    require_zero_amount(
                        init_payload,
                        mode="stripe",
                        stage="stripe_zero_after_update",
                        currency=self.profile.currency,
                    )
                    self._stripe_elements(checkout, key, version, context)
                    return init_payload, version, context
                except PaypalNotZeroError as exc:
                    if exc.amount in {"unknown", "invalid"}:
                        raise
                    last = exc
            raise last

    def _refresh_stripe_zero_context(
        self,
        checkout: Mapping[str, Any],
        key: str,
        previous: Mapping[str, Any],
        original_amount: Any,
        *,
        max_attempts: int = 6,
    ) -> tuple[dict[str, Any], str, dict[str, Any], int]:
        """Rebuild the same Checkout after promo/update until its due is zero."""
        last_amount: Any = None
        for attempt in range(max(1, int(max_attempts))):
            self.sleep(0.8 if attempt == 0 else 1.5)
            init_payload, version, context = self._stripe_init(checkout, key)
            self._require_stripe_paypal(init_payload, stage="stripe_init_after_update")
            previous_currency = str(previous.get("currency") or "").lower()
            current_currency = str(context.get("currency") or "").lower()
            if previous_currency and current_currency and previous_currency != current_currency:
                raise PaypalCapabilityError(
                    "优惠后 Checkout context 切换了币种",
                    stage="stripe_init_after_update",
                )
            self._stripe_elements(checkout, key, version, context)
            tax_payload = self._stripe_tax(checkout, key, version, context)
            # Tax refresh can rotate the Elements identifiers; fetch once more
            # before creating the new PM, matching the reference flow.
            self._stripe_elements(checkout, key, version, context)
            last_amount = context.get("amount")
            self._emit_trace(
                status="step",
                stage="stripe_zero_sync",
                message=f"优惠后 0 元 Checkout context 同步检查 {attempt + 1}/{max_attempts}: amount={last_amount}",
            )
            if _is_zero_amount(last_amount):
                _inherit_submission_context(previous, context, original_amount=original_amount)
                context["promo_checkout_amount"] = last_amount
                context["promo_sync_attempts"] = attempt + 1
                context["tax_payload"] = tax_payload
                return init_payload, version, context, attempt + 1
        raise PaypalNotZeroError(
            "Plus 首月免费优惠未生效：0 元 Checkout context 未同步",
            stage="stripe_zero_sync",
            amount=last_amount,
            currency=str(previous.get("currency") or self.profile.currency),
        )

    def _require_stripe_paypal(self, payload: Mapping[str, Any], *, stage: str) -> list[str]:
        methods = _payment_method_types(payload)
        explicit = isinstance(payload.get("payment_method_types"), list) or isinstance(
            payload.get("payment_method_specs"), list
        )
        if not explicit or not methods:
            raise PaypalUnavailableError(
                "Stripe did not explicitly expose payment methods", stage=stage
            )
        if "paypal" not in methods:
            raise PaypalUnavailableError(
                "Stripe Checkout does not support PayPal",
                stage=stage,
                details={"methods": methods},
            )
        return methods

    def _stripe_elements(
        self,
        checkout: Mapping[str, Any],
        key: str,
        version: str,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        self.stage = "stripe_elements"
        params: dict[str, Any] = {
            "client_betas[0]": "custom_checkout_server_updates_1",
            "client_betas[1]": "custom_checkout_manual_approval_1",
            "deferred_intent[mode]": "subscription",
            "deferred_intent[amount]": str(
                context.get("amount") if context.get("amount") is not None else 0
            ),
            "deferred_intent[currency]": str(context.get("currency") or self.profile.currency).lower(),
            "deferred_intent[setup_future_usage]": "off_session",
            "currency": str(context.get("currency") or self.profile.currency).lower(),
            "key": key,
            "_stripe_version": version,
            "elements_init_source": "custom_checkout",
            "referrer_host": "chatgpt.com",
            "stripe_js_id": context["stripe_js_id"],
            "locale": self.profile.locale.split("-", 1)[0],
            "type": "deferred_intent",
            "checkout_session_id": checkout["session_id"],
        }
        for index, method in enumerate(context.get("payment_method_types") or []):
            params[f"deferred_intent[payment_method_types][{index}]"] = method
        response = self._request(
            "get",
            STRIPE_BASE + "/v1/elements/sessions",
            params=params,
            headers=self._stripe_headers(),
            timeout=self.request_timeout,
        )
        if int(getattr(response, "status_code", 0) or 0) != 200:
            self._raise_http(response, label="Stripe elements")
        payload = self._response_json(response, stage=self.stage)
        if payload.get("session_id"):
            context["elements_session_id"] = str(payload["session_id"])
        if payload.get("config_id"):
            context["elements_session_config_id"] = str(payload["config_id"])
        element_methods = _payment_method_types(payload)
        if element_methods:
            context["payment_method_types"] = element_methods
        self._require_stripe_paypal(payload, stage=self.stage)
        return payload

    def _stripe_tax(
        self,
        checkout: Mapping[str, Any],
        key: str,
        version: str,
        context: Mapping[str, Any],
    ) -> dict[str, Any]:
        self.stage = "stripe_tax"
        address = self.billing["address"]
        body: dict[str, Any] = {
            "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
            "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
            "elements_session_client[elements_init_source]": "custom_checkout",
            "elements_session_client[referrer_host]": "chatgpt.com",
            "elements_session_client[stripe_js_id]": context["stripe_js_id"],
            "elements_session_client[session_id]": context["elements_session_id"],
            "elements_session_client[locale]": self.profile.locale.split("-", 1)[0],
            "elements_session_client[is_aggregation_expected]": "false",
            "elements_options_client[saved_payment_method][enable_save]": "never",
            "elements_options_client[saved_payment_method][enable_redisplay]": "never",
            "key": key,
            "_stripe_version": version,
        }
        for field in ("country", "line1", "city", "postal_code", "state"):
            if address.get(field):
                body[f"tax_region[{field}]"] = address[field]
        response = self._request(
            "post",
            f"{STRIPE_BASE}/v1/payment_pages/{checkout['session_id']}",
            data=body,
            headers=self._stripe_headers(),
            timeout=self.request_timeout,
        )
        if int(getattr(response, "status_code", 0) or 0) != 200:
            self._raise_http(response, label="Stripe tax region")
        payload = self._response_json(response, stage=self.stage)
        summary = payload.get("total_summary") if isinstance(payload, dict) else None
        due = summary.get("due") if isinstance(summary, dict) else None
        if due is None:
            invoice = payload.get("invoice") if isinstance(payload, dict) else None
            due = invoice.get("amount_due") if isinstance(invoice, dict) else None
        if due is not None and isinstance(context, dict):
            context["amount"] = due
        if isinstance(context, dict):
            context["tax_payload"] = payload
        return payload

    def _snapshot_billing(self, checkout: Mapping[str, Any]) -> None:
        self.stage = "stripe_snapshot"
        address = self.billing["address"]
        snapshot_address = {
            key: address.get(key, "")
            for key in ("line1", "city", "country", "postal_code", "state")
            if address.get(key)
        }
        body = {
            "snapshot": {
                "billing_address": {
                    "name": self.billing["name"],
                    "address": snapshot_address,
                }
            }
        }
        response = self._request(
            "post",
            CHECKOUT_SNAPSHOT_URL,
            json=body,
            headers={
                **self._context_headers(referer=str(checkout["checkout_url"])),
                "Content-Type": "application/json",
            },
            timeout=min(self.request_timeout, 20.0),
        )
        status = int(getattr(response, "status_code", 0) or 0)
        if status < 200 or status >= 300:
            self._raise_http(response, label="ChatGPT billing snapshot")

    def _stripe_payment_method(
        self,
        checkout: Mapping[str, Any],
        key: str,
        context: Mapping[str, Any],
    ) -> str:
        self.stage = "stripe_payment_method"
        address = self.billing["address"]
        body: dict[str, Any] = {
            "type": "paypal",
            "billing_details[name]": self.billing["name"],
            "billing_details[email]": self.billing["email"],
            "payment_user_agent": (
                f"stripe.js/{STRIPE_RUNTIME_VERSION}; stripe-js-v3/{STRIPE_RUNTIME_VERSION}; "
                "payment-element; deferred-intent"
            ),
            "referrer": CHATGPT_BASE,
            "time_on_page": "30000",
            "client_attribution_metadata[client_session_id]": context["stripe_js_id"],
            "client_attribution_metadata[checkout_session_id]": checkout["session_id"],
            "client_attribution_metadata[checkout_config_id]": context.get("config_id", ""),
            "client_attribution_metadata[elements_session_id]": context["elements_session_id"],
            "client_attribution_metadata[elements_session_config_id]": context.get("elements_session_config_id", ""),
            "client_attribution_metadata[merchant_integration_source]": "elements",
            "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
            "client_attribution_metadata[merchant_integration_version]": "2021",
            "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
            "client_attribution_metadata[payment_method_selection_flow]": "automatic",
            "guid": context["guid"],
            "muid": context["muid"],
            "sid": context["sid"],
            "key": key,
            "_stripe_version": STRIPE_VERSION_BASE,
        }
        for field in ("country", "line1", "city", "postal_code", "state"):
            if address.get(field):
                body[f"billing_details[address][{field}]"] = address[field]
        response = self._request(
            "post",
            STRIPE_BASE + "/v1/payment_methods",
            data=body,
            headers=self._stripe_headers(),
            timeout=self.request_timeout,
        )
        if int(getattr(response, "status_code", 0) or 0) != 200:
            self._raise_http(response, label="Stripe PayPal payment method")
        payment_method = str(self._response_json(response, stage=self.stage).get("id") or "")
        if not payment_method.startswith("pm_"):
            raise PaypalCapabilityError(
                "Stripe did not return a PayPal pm_*", stage=self.stage
            )
        return payment_method

    @staticmethod
    def _paypal_return_url(
        checkout: Mapping[str, Any], init_payload: Mapping[str, Any]
    ) -> str:
        hosted = str(init_payload.get("stripe_hosted_url") or "").strip()
        if hosted.startswith("https://pay.openai.com/"):
            hosted = "https://checkout.stripe.com/" + hosted.split("/", 3)[3]
        if not hosted:
            hosted = f"https://checkout.stripe.com/c/pay/{checkout['session_id']}"
        parsed = urlsplit(hosted)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query.update(
            {
                "redirect_pm_type": "paypal",
                "lid": str(uuid.uuid4()),
                "ui_mode": "custom",
            }
        )
        return urlunsplit(
            (
                parsed.scheme or "https",
                parsed.netloc or "checkout.stripe.com",
                parsed.path,
                urlencode(query),
                "",
            )
        )

    def _stripe_confirm(
        self,
        checkout: Mapping[str, Any],
        key: str,
        init_payload: Mapping[str, Any],
        context: Mapping[str, Any],
        payment_method: str,
    ) -> dict[str, Any]:
        self.stage = "stripe_confirm"
        body = {
            "eid": "NA",
            "payment_method": payment_method,
            "guid": context["guid"],
            "muid": context["muid"],
            "sid": context["sid"],
            "expected_amount": str(
                context.get("amount") if context.get("amount") is not None else 0
            ),
            "expected_payment_method_type": "paypal",
            "key": key,
            "_stripe_version": PAYPAL_STRIPE_VERSION,
            "init_checksum": str(init_payload.get("init_checksum") or context.get("init_checksum") or ""),
            "version": STRIPE_RUNTIME_VERSION,
            "return_url": self._paypal_return_url(checkout, init_payload),
            "client_attribution_metadata[client_session_id]": context["client_session_id"],
            "client_attribution_metadata[checkout_session_id]": checkout["session_id"],
            "client_attribution_metadata[checkout_config_id]": context.get("config_id", ""),
            "client_attribution_metadata[merchant_integration_source]": "checkout",
            "client_attribution_metadata[merchant_integration_version]": "custom_checkout",
            "client_attribution_metadata[payment_method_selection_flow]": "automatic",
            "link_brand": "link",
        }
        response = self._request(
            "post",
            f"{STRIPE_BASE}/v1/payment_pages/{checkout['session_id']}/confirm",
            data=body,
            headers=self._stripe_headers(),
            timeout=self.request_timeout,
        )
        if int(getattr(response, "status_code", 0) or 0) == 400 and "terms of service" in str(
            getattr(response, "text", "") or ""
        ).lower():
            body["consent[terms_of_service]"] = "accepted"
            response = self._request(
                "post",
                f"{STRIPE_BASE}/v1/payment_pages/{checkout['session_id']}/confirm",
                data=body,
                headers=self._stripe_headers(),
                timeout=self.request_timeout,
            )
        if int(getattr(response, "status_code", 0) or 0) != 200:
            text = str(getattr(response, "text", "") or "").lower()
            if "payment_method_types_mismatch" in text:
                raise PaypalUnavailableError(
                    "Stripe confirm rejected PayPal", stage=self.stage
                )
            self._raise_http(response, label="Stripe PayPal confirm")
        payload = self._response_json(response, stage=self.stage)
        if _has_current_paypal_decline(payload, payment_method):
            raise PaypalUnavailableError(
                "Stripe declined the PayPal setup", stage=self.stage
            )
        return payload

    def _approve(
        self,
        checkout: Mapping[str, Any],
        sentinel_headers: Mapping[str, str],
    ) -> None:
        self.stage = "stripe_approve"
        route = CHECKOUT_PATH + "/approve"
        headers = {
            **self._context_headers(referer=str(checkout["checkout_url"]), route=route),
            "Content-Type": "application/json",
            "OAI-Telemetry": "[1,null]",
            **dict(sentinel_headers),
        }
        response = self._request(
            "post",
            CHECKOUT_APPROVE_URL,
            json={
                "checkout_session_id": checkout["session_id"],
                "processor_entity": checkout["processor_entity"],
            },
            headers=headers,
            timeout=min(self.request_timeout, 20.0),
        )
        if int(getattr(response, "status_code", 0) or 0) != 200:
            self._raise_http(response, label="ChatGPT Checkout approve")
        result = str(self._response_json(response, stage=self.stage).get("result") or "").lower()
        if result != "approved":
            raise PaypalUnavailableError(
                "ChatGPT Checkout approval was not approved", stage=self.stage
            )

    def _stripe_poll(
        self,
        checkout: Mapping[str, Any],
        key: str,
        payment_method: str,
        *,
        expected_submission_id: str = "",
        rejected_submission_id: str = "",
        rejected_handoff_keys: set[str] | None = None,
        require_zero_due: bool = False,
        context: Mapping[str, Any] | None = None,
        max_attempts: int = 5,
    ) -> str:
        self.stage = "stripe_poll"
        params = {
            "key": key,
            "_stripe_version": STRIPE_VERSION_FULL,
            "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
            "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
            "elements_session_client[elements_init_source]": "custom_checkout",
            "elements_session_client[referrer_host]": "chatgpt.com",
        }
        if context:
            # The full payment-page read must use the active Elements session.
            # Without these identifiers Stripe can return a stale risk-stage
            # redirect after checkout/update rebuilt the invoice.
            for source, target in (
                ("stripe_js_id", "elements_session_client[stripe_js_id]"),
                ("elements_session_id", "elements_session_client[session_id]"),
                ("client_session_id", "elements_session_client[client_session_id]"),
                ("config_id", "elements_session_client[config_id]"),
            ):
                value = str(context.get(source) or "")
                if value:
                    params[target] = value
            locale = str(context.get("locale") or self.profile.locale.split("-", 1)[0])
            params["elements_session_client[locale]"] = locale
        for attempt in range(max(1, int(max_attempts))):
            payload: dict[str, Any] = {}
            try:
                response = self._request(
                    "get",
                    f"{STRIPE_BASE}/v1/payment_pages/{checkout['session_id']}/poll",
                    params={"key": key, "_stripe_version": STRIPE_VERSION_BASE},
                    headers=self._stripe_headers(),
                    timeout=min(self.request_timeout, 20.0),
                )
                if int(getattr(response, "status_code", 0) or 0) == 200:
                    payload = self._response_json(response, stage=self.stage)
            except PaypalExtractionError:
                payload = {}
            redirect = _extract_paypal_redirect(payload)
            if redirect:
                rejection = _poll_rejection_reason(
                    payload,
                    redirect,
                    expected_submission_id=expected_submission_id,
                    rejected_submission_id=rejected_submission_id,
                    rejected_handoff_keys=rejected_handoff_keys,
                    require_zero_due=require_zero_due,
                )
                if not rejection:
                    return redirect
                self._emit_trace(
                    status="response",
                    stage=self.stage,
                    message=f"忽略旧 PayPal submission 结果：{rejection}",
                )
            if _has_current_paypal_decline(payload, payment_method):
                raise PaypalUnavailableError("Stripe declined the PayPal setup", stage=self.stage)

            # The compact poll endpoint can lag. Read the full payment page
            # using the refreshed Elements context before trying again.
            try:
                page = self._request(
                    "get",
                    f"{STRIPE_BASE}/v1/payment_pages/{checkout['session_id']}",
                    params=params,
                    headers=self._stripe_headers(),
                    timeout=min(self.request_timeout, 20.0),
                )
                if int(getattr(page, "status_code", 0) or 0) == 200:
                    page_payload = self._response_json(page, stage=self.stage)
                    redirect = _extract_paypal_redirect(page_payload)
                    if redirect:
                        rejection = _poll_rejection_reason(
                            page_payload,
                            redirect,
                            expected_submission_id=expected_submission_id,
                            rejected_submission_id=rejected_submission_id,
                            rejected_handoff_keys=rejected_handoff_keys,
                            require_zero_due=require_zero_due,
                        )
                        if not rejection:
                            return redirect
                        self._emit_trace(
                            status="response",
                            stage=self.stage,
                            message=f"忽略旧 PayPal submission 结果：{rejection}",
                        )
                    if _has_current_paypal_decline(page_payload, payment_method):
                        raise PaypalUnavailableError("Stripe declined the PayPal setup", stage=self.stage)
            except PaypalExtractionError:
                raise
            if attempt + 1 < max(1, int(max_attempts)):
                self.sleep(0.8)
        raise PaypalUnavailableError(
            "Stripe did not produce a PayPal redirect", stage=self.stage
        )

    def _run_stripe(self, checkout: Mapping[str, Any]) -> tuple[str, int, str]:
        """Run the hosted Stripe flow using two distinct PayPal submissions.

        For ``post_update`` promotions the first, full-price submission is only
        a risk/merchant gate. Its buyer handoff is resolved and discarded. The
        promotion is then applied to the same Checkout session and a fresh
        Stripe context plus fresh PayPal PaymentMethod is used for the only BA
        that may leave this method.
        """
        key = self._stripe_publishable_key(checkout)
        init_payload, version, context = self._stripe_init(checkout, key)
        self._require_stripe_paypal(init_payload, stage="stripe_init")
        self._stripe_elements(checkout, key, version, context)
        tax_payload = self._stripe_tax(checkout, key, version, context)
        amount = context.get("amount")
        currency = (
            str(context.get("currency") or checkout_currency(tax_payload) or self.profile.currency)
            .strip()
            .lower()
        )
        promo_requested = self.promo_strategy == "post_update"
        if promo_requested and not _is_positive_amount(amount):
            raise PaypalNotZeroError(
                "全价风控阶段必须使用未优惠的非 0 元账单",
                stage="stripe_risk_gate",
                amount=amount if amount is not None else "unknown",
                currency=currency,
            )
        if not promo_requested and not _is_zero_amount(amount):
            raise PaypalNotZeroError(
                "Stripe Checkout 未达到 0 元账单",
                stage="stripe_zero_before_paypal",
                amount=amount if amount is not None else "unknown",
                currency=currency,
            )

        self._snapshot_billing(checkout)
        self._warmup(str(checkout["checkout_url"]))

        # First submission: full-price risk gate for post-update promotions.
        risk_headers = self._sentinel_headers(
            flow="checkout_session_approval", page_url=str(checkout["checkout_url"])
        )
        risk_pm = self._stripe_payment_method(checkout, key, context)
        risk_confirm = self._stripe_confirm(
            checkout, key, init_payload, context, risk_pm
        )
        if not isinstance(risk_confirm, dict):
            raise PaypalCapabilityError(
                "Stripe PayPal confirm returned a non-object response",
                stage="stripe_confirm",
            )
        risk_submission = risk_confirm.get("submission_attempt") or {}
        if not isinstance(risk_submission, dict):
            risk_submission = {}
        risk_id = _submission_attempt_id(risk_confirm)
        risk_state = str(risk_submission.get("state") or "").lower()
        if promo_requested and not risk_submission:
            raise PaypalCapabilityError(
                "全价 PayPal confirm 未返回 submission_attempt",
                stage="stripe_confirm",
            )
        if risk_state in {"failed", "expired", "canceled", "cancelled"}:
            raise PaypalUnavailableError(
                f"全价 PayPal submission 状态不可继续：{risk_state}",
                stage="stripe_confirm",
            )
        _record_submission_context(
            context,
            risk_confirm,
            amount=amount,
            source="pre_promo_risk_gate",
        )
        context.update(
            {
                "risk_submission_id": risk_id,
                "risk_payment_method_id": risk_pm,
                "payment_method_id": risk_pm,
                "checkout_context_source": "pre_promo_risk_gate",
                "original_checkout_amount": amount,
            }
        )

        risk_redirect = _extract_paypal_redirect(risk_confirm)
        if risk_state == "requires_approval":
            self._approve(checkout, risk_headers)
        if not risk_redirect or risk_state == "requires_approval":
            risk_redirect = self._stripe_poll(
                checkout,
                key,
                risk_pm,
                expected_submission_id=risk_id,
                context=context,
                max_attempts=5,
            )
        if not (_is_paypal_approval_url(risk_redirect) or _is_paypal_pm_redirect_url(risk_redirect)):
            raise PaypalUnavailableError(
                "全价 PayPal submission 未生成 buyer handoff",
                stage="stripe_poll",
            )

        if not promo_requested:
            # No post-update promotion requested: this is already the only
            # submission and can be returned to the common redirect resolver.
            return risk_redirect, 0, currency

        # Resolve the full-price handoff as a risk gate only. Never return its
        # BA and remember its identity so a lagging poll cannot be accepted.
        rejected_handoff_keys = {_paypal_handoff_key(risk_redirect)} - {""}
        try:
            discarded = self._resolve_paypal(risk_redirect)[0]
        except PaypalExtractionError:
            raise
        rejected_handoff_keys.add(_paypal_handoff_key(discarded))
        self._emit_trace(
            status="step",
            stage="stripe_risk_gate",
            message="全价 PayPal handoff 已完成，仅作为风控闸门；开始同步优惠后的 Checkout",
        )

        promo_response = self._stripe_update_promo(checkout)
        refreshed_key = _validate_promo_update_context(promo_response, str(checkout["session_id"]))
        if refreshed_key and refreshed_key != key:
            key = refreshed_key
        zero_init, zero_version, zero_context, sync_attempts = self._refresh_stripe_zero_context(
            checkout,
            key,
            context,
            amount,
            max_attempts=self.zero_sync_attempts,
        )
        self._snapshot_billing(checkout)
        zero_pm = self._stripe_payment_method(checkout, key, zero_context)
        if zero_pm == risk_pm:
            raise PaypalCapabilityError(
                "优惠后 PayPal PaymentMethod 未刷新，拒绝复用全价 submission",
                stage="stripe_payment_method",
            )
        zero_context.update(
            {
                "risk_submission_id": risk_id,
                "risk_payment_method_id": risk_pm,
                "zero_due_payment_method_id": zero_pm,
                "payment_method_id": zero_pm,
                "submission_rebound": True,
                "promo_sync_attempts": sync_attempts,
                "checkout_context_source": "post_promo_zero_due",
            }
        )
        zero_confirm = self._stripe_confirm(
            checkout, key, zero_init, zero_context, zero_pm
        )
        zero_submission, zero_id = _validate_zero_due_submission(
            zero_confirm,
            risk_submission_id=risk_id,
            expected_payment_method_id=zero_pm,
        )
        zero_state = str(zero_submission.get("state") or "").lower()
        if zero_state in {"failed", "expired", "canceled", "cancelled"}:
            raise PaypalUnavailableError(
                f"优惠后 0 元 submission 状态不可继续：{zero_state}",
                stage="stripe_confirm",
            )
        _record_submission_context(
            zero_context,
            zero_confirm,
            amount=zero_context.get("amount"),
            source="post_promo_zero_due",
        )
        zero_redirect = _extract_paypal_redirect(zero_confirm)
        zero_headers = self._sentinel_headers(
            flow="checkout_session_approval", page_url=str(checkout["checkout_url"])
        )
        if zero_state == "requires_approval":
            self._approve(checkout, zero_headers)
        if not zero_redirect or zero_state == "requires_approval":
            zero_redirect = self._stripe_poll(
                checkout,
                key,
                zero_pm,
                expected_submission_id=zero_id,
                rejected_submission_id=risk_id,
                rejected_handoff_keys=rejected_handoff_keys,
                require_zero_due=True,
                context=zero_context,
                max_attempts=5,
            )
        if not (_is_paypal_approval_url(zero_redirect) or _is_paypal_pm_redirect_url(zero_redirect)):
            raise PaypalUnavailableError(
                "优惠后 0 元 submission 未生成 buyer handoff",
                stage="stripe_poll",
            )
        if _paypal_handoff_key(zero_redirect) in rejected_handoff_keys:
            raise PaypalUnavailableError(
                "优惠后轮询返回了全价 submission 的旧 buyer handoff",
                stage="stripe_poll",
            )
        return zero_redirect, 0, currency

    def _resolve_paypal(self, start_url: str) -> tuple[str, str]:
        current = html.unescape(str(start_url or "").strip())
        if not current:
            raise PaypalUnavailableError("provider returned no redirect", stage="redirect")
        for hop in range(self.max_redirect_hops + 1):
            try:
                return validate_paypal_approval_url(current)
            except PaypalUnavailableError:
                pass
            try:
                parsed = urlsplit(current)
            except ValueError as exc:
                raise PaypalUnavailableError("provider redirect is malformed", stage="redirect") from exc
            host = (parsed.hostname or "").lower()
            if parsed.scheme != "https" or not host or not (
                host == "stripe.com"
                or host.endswith(".stripe.com")
                or host in {"paypal.com", "www.paypal.com"}
            ):
                raise PaypalUnavailableError(
                    "provider redirect host is not allowed", stage="redirect"
                )
            if hop >= self.max_redirect_hops:
                break
            self.stage = "redirect"
            response = self._request(
                "get",
                current,
                allow_redirects=False,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
                timeout=self.request_timeout,
            )
            status = int(getattr(response, "status_code", 0) or 0)
            if status in {408, 425, 429} or status >= 500:
                self._raise_http(response, label="PayPal redirect")
            location = str(
                (getattr(response, "headers", {}) or {}).get("location")
                or (getattr(response, "headers", {}) or {}).get("Location")
                or ""
            ).strip()
            if location:
                current = urljoin(current, html.unescape(location))
                continue
            body = html.unescape(str(getattr(response, "text", "") or ""))
            for match in _PAYPAL_URL_CANDIDATE_RE.finditer(body):
                candidate = match.group(0).replace("\\u0026", "&").replace("\\/", "/")
                try:
                    return validate_paypal_approval_url(candidate)
                except PaypalUnavailableError:
                    continue
            break
        raise PaypalUnavailableError(
            "provider redirect did not resolve to a valid PayPal BA URL",
            stage="redirect",
        )

    def run(self) -> dict[str, Any]:
        try:
            self._emit_trace(
                status="step", stage="account_check",
                message="开始检查账号套餐与 PayPal 提链资格",
            )
            account = self._account_check()
            self._emit_trace(
                status="response", stage="account_check",
                message=(
                    f"账号资格通过：plan={account.get('current_plan_type') or 'unknown'} "
                    f"promo={account.get('plus_trial_status') or 'unknown'}"
                ),
            )
            self._configure_session()
            self._warmup(CHATGPT_BASE + "/")
            checkout, fallback_reason = self._checkout_with_fallback()
            actual_mode = str(checkout["actual_mode"])
            self._emit_trace(
                status="fallback" if fallback_reason else "step",
                stage="checkout_create",
                message=(
                    f"Checkout 已创建：requested={self.requested_mode} actual={actual_mode}"
                    + (f" fallback={fallback_reason}" if fallback_reason else "")
                ),
            )
            if actual_mode == "oaics":
                try:
                    provider_redirect, amount, currency = self._run_oaics(checkout)
                except PaypalCapabilityError as exc:
                    if not self.allow_stripe_fallback:
                        raise
                    fallback_reason = "oaics_capability_error"
                    self._emit_trace(
                        status="fallback", stage=exc.stage,
                        message="OAICS 能力不匹配，创建全新 Stripe Checkout 回退",
                    )
                    checkout = self._create_checkout("stripe", self.promo_strategy)
                    if checkout["actual_mode"] != "stripe":
                        raise PaypalFallbackError(
                            "Runtime Stripe fallback did not return a hosted session",
                            stage="checkout_create",
                        ) from exc
                    actual_mode = "stripe"
                    provider_redirect, amount, currency = self._run_stripe(checkout)
            elif actual_mode == "stripe":
                provider_redirect, amount, currency = self._run_stripe(checkout)
            else:  # pragma: no cover - guarded by checkout parser
                raise PaypalCapabilityError("unsupported actual mode", stage="checkout_create")
            approval_url, ba_token = self._resolve_paypal(provider_redirect)
            result = {
                "ok": True,
                "paypal_approve_url": approval_url,
                "ba_token": ba_token,
                "requested_mode": self.requested_mode,
                "actual_mode": actual_mode,
                "fallback_reason": fallback_reason,
                "promo_strategy": self.promo_strategy,
                "promo_id": self.promo_id,
                "applied_promo_strategy": checkout.get("promo_applied"),
                "amount": amount,
                "currency": str(currency or self.profile.currency).upper(),
                "session_id": checkout["session_id"],
                "checkout_url": checkout["checkout_url"],
                "provider_redirect_url": provider_redirect,
                "account": account,
            }
            self._emit_trace(
                status="success", stage="redirect",
                message=(
                    f"PP 链提取完成：mode={actual_mode} amount={amount} "
                    f"currency={str(currency or self.profile.currency).upper()}"
                ),
            )
            return result
        except PaypalExtractionError as exc:
            self._emit_trace(
                status="failed", stage=exc.stage,
                message=f"提链协议失败：{exc.detail}",
                http_status=exc.http_status,
            )
            raise
        except Exception as exc:
            self._emit_trace(
                status="failed", stage=self.stage,
                message=f"提链协议异常：{type(exc).__name__}",
            )
            raise
        finally:
            if self.session is not None:
                try:
                    self.session.close()
                except Exception:
                    pass


def extract_paypal_link(
    *,
    access_token: str,
    email: str = "",
    proxy: str,
    requested_mode: str = "oaics",
    promo_strategy: str = "post_update",
    promo_id: str = PROMO_ID,
    country: str = "BR",
    billing_country: str = "DE",
    request_timeout: float = 30,
    account_result: Mapping[str, Any] | None = None,
    trace: Callable[[dict[str, Any]], None] | None = None,
    allow_stripe_fallback: bool = True,
) -> dict[str, Any]:
    """Stable service entry point for one direct PayPal extraction task."""

    return PaypalExtractor(
        access_token=access_token,
        email=email,
        proxy=proxy,
        requested_mode=requested_mode,
        promo_strategy=promo_strategy,
        promo_id=promo_id,
        country=country,
        billing_country=billing_country,
        request_timeout=request_timeout,
        account_result=account_result,
        trace=trace,
        allow_stripe_fallback=allow_stripe_fallback,
    ).run()


__all__ = [
    "PaypalExtractor",
    "PaypalExtractionError",
    "PaypalInvalidTokenError",
    "PaypalTransportError",
    "PaypalCapabilityError",
    "PaypalFallbackError",
    "PaypalNotZeroError",
    "PaypalUnavailableError",
    "InvalidTokenError",
    "TransportError",
    "CapabilityError",
    "FallbackError",
    "NotZeroError",
    "UnavailableError",
    "amount_observations",
    "require_zero_amount",
    "validate_paypal_approval_url",
    "extract_paypal_link",
]
