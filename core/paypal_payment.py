# -*- coding: utf-8 -*-
"""Resumable, pure-HTTP PayPal billing-agreement adapter.

The public API deliberately stops after sending the SMS challenge.  The caller
persists the returned JSON context and later resumes the exact same PayPal
checkout, cookie jar, generated profile, and proxy by calling
``submit_paypal_otp``.  No browser or UI fallback exists in this module.

``status == "authorized"`` means only that PayPal returned a billing authorize
object.  It must never be interpreted as proof that ChatGPT Plus is active;
``plus_confirmation`` reports that separate outcome.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import math
import os
import random
import re
import secrets
import string
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

try:
    from curl_cffi import requests as curl_requests
except ImportError:  # pragma: no cover - requirements.txt installs curl_cffi
    curl_requests = None


PAYPAL_ORIGIN = "https://www.paypal.com"
GRAPHQL_URL = f"{PAYPAL_ORIGIN}/graphql"
CONTEXT_VERSION = 1
DEFAULT_TIMEOUT = 30.0
DEFAULT_CONTEXT_TTL = 30 * 60
DEFAULT_MAX_CARD_ATTEMPTS = 3
EUAT_COOKIE_NAME = "AV894Kt2TSumQQrJwe-8mzmyREO"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
)

_BA_TOKEN_RE = re.compile(r"^BA-[A-Za-z0-9]{8,80}$")
_OTP_RE = re.compile(r"^\d{6}$")
_SAFE_ERROR_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,79}$")
_SAFE_REMOTE_ERROR_CODES = frozenset(
    {
        "ACCOUNT_ALREADY_EXISTS",
        "ACCOUNT_LOCKED",
        "ACCOUNT_RESTRICTED",
        "BUYER_NOT_SET",
        "CARD_GENERIC_ERROR",
        "CC_LINKED_TO_FULL_ACCOUNT",
        "CHALLENGE_EXPIRED",
        "CREATE_CARD_ACCOUNT_CANDIDATE_VALIDATION_ERROR",
        "FI_CONFIRMATION_CONTINGENCY",
        "INSTRUMENT_SHARING_LIMIT_EXCEEDED",
        "INVALID_OTP",
        "NEED_CREDIT_CARD",
        "OAS_ERROR",
        "OTP_EXPIRED",
        "OTP_INVALID",
        "PAYER_ACCOUNT_RESTRICTED",
        "PAYER_INVALID_FOR_PAYMENT",
        "PHONE_CONFIRMATION_FAILED",
        "RESIDENTIAL_ADDRESS_NOT_FOUND",
        "SMS_LIMIT_EXCEEDED",
        "TOO_MANY_ATTEMPTS",
        "TRANSACTION_REFUSED",
    }
)
_SAFE_OTP_STATES = frozenset({
    "DENIED", "EXPIRED", "FAILED", "INVALID", "PENDING", "REJECTED",
    "SMS_LIMIT_EXCEEDED",
})
_PROXY_REGION_RE = re.compile(
    r"(?i)(?:^|[-_=;,&:@])(?:country|region|zone)[-_=](?P<country>[a-z]{2})(?=$|[-_=;,&:@])"
)
_PAYPAL_HOSTS = {"paypal.com", "www.paypal.com"}
_MERCHANT_CONFIRMATION_HOSTS = {
    "chatgpt.com",
    "chat.openai.com",
    "checkout.stripe.com",
    "pay.openai.com",
    "pm-redirects.stripe.com",
}
_TRACE_ID_RE = re.compile(
    r"(?i)(?:BA|EC)-[A-Za-z0-9_-]+|"
    r"(?:oaics|cs_(?:live|test)|seti|pi|pm|cpmt|ctoken|cus)_[A-Za-z0-9_-]+"
)


class PayPalPaymentError(RuntimeError):
    """Structured protocol failure whose text never contains response bodies."""

    def __init__(
        self,
        code: str,
        *,
        stage: str,
        retryable: bool = False,
        replay_safe: bool = True,
        http_status: int | None = None,
    ) -> None:
        safe_code = str(code or "PAYPAL_PROTOCOL_ERROR").upper()
        if not _SAFE_ERROR_CODE_RE.fullmatch(safe_code):
            safe_code = "PAYPAL_PROTOCOL_ERROR"
        self.code = safe_code
        self.stage = _safe_stage(stage)
        self.retryable = bool(retryable)
        self.replay_safe = bool(replay_safe)
        self.ambiguous = False
        self.http_status = int(http_status) if http_status is not None else None
        super().__init__(f"[{self.stage}] {self.code}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "stage": self.stage,
            "retryable": self.retryable,
            "replay_safe": self.replay_safe,
            "ambiguous": self.ambiguous,
            "http_status": self.http_status,
        }


class PayPalPaymentInputError(PayPalPaymentError):
    """Caller supplied an invalid or inconsistent input."""


class PayPalPaymentUncertainError(PayPalPaymentError):
    """A mutating request may have committed although its response was lost."""

    def __init__(self, code: str, *, stage: str) -> None:
        super().__init__(
            code,
            stage=stage,
            retryable=False,
            replay_safe=False,
        )
        self.ambiguous = True


def _safe_stage(value: object) -> str:
    stage = re.sub(r"[^a-z0-9_]+", "_", str(value or "unknown").lower()).strip("_")
    return stage[:64] or "unknown"


def _safe_trace_target(url: object) -> str:
    """Return a credential-free request target for persisted flow logs."""
    try:
        parsed = urlsplit(str(url or ""))
        host = str(parsed.hostname or "").lower()
        path = _TRACE_ID_RE.sub("***", str(parsed.path or "/"))
        return f"{host}{path}"[:240]
    except Exception:
        return "unknown"


def _emit_trace_callback(
    trace: Callable[[dict[str, Any]], None] | None,
    payload: dict[str, Any],
) -> None:
    if trace is None:
        return
    try:
        trace(payload)
    except Exception:
        return


def _safe_graphql_code(errors: object, fallback: str) -> str:
    if isinstance(errors, list):
        for error in errors:
            if not isinstance(error, Mapping):
                continue
            for key in ("message", "name", "_name"):
                value = str(error.get(key) or "").upper()
                if value in _SAFE_REMOTE_ERROR_CODES:
                    return value
            data = error.get("data")
            if isinstance(data, Mapping):
                value = str(data.get("contingency") or "").upper()
                if value in _SAFE_REMOTE_ERROR_CODES:
                    return value
    return fallback


def _is_timeout_error(exc: BaseException) -> bool:
    name = type(exc).__name__.lower()
    text = str(exc).lower()
    return "timeout" in name or "timed out" in text or "operation timed" in text


def _normalize_proxy(proxy: str) -> str:
    value = str(proxy or "").strip()
    if not value:
        raise PayPalPaymentInputError("PROXY_REQUIRED", stage="input")
    if any(ord(char) < 0x20 or char.isspace() for char in value):
        raise PayPalPaymentInputError("PROXY_INVALID", stage="input")

    if "://" not in value:
        parts = value.split(":", 3)
        if len(parts) != 4:
            raise PayPalPaymentInputError("PROXY_INVALID", stage="input")
        host, port, username, password = parts
        value = (
            f"http://{quote(username, safe='-._~')}:{quote(password, safe='-._~')}"
            f"@{host}:{port}"
        )

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise PayPalPaymentInputError("PROXY_INVALID", stage="input") from None
    if parsed.scheme.lower() not in {"http", "https", "socks5", "socks5h"}:
        raise PayPalPaymentInputError("PROXY_SCHEME_UNSUPPORTED", stage="input")
    if not parsed.hostname or not port or not (1 <= int(port) <= 65535):
        raise PayPalPaymentInputError("PROXY_INVALID", stage="input")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise PayPalPaymentInputError("PROXY_INVALID", stage="input")

    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    auth = ""
    if parsed.username is not None:
        auth = quote(unquote(parsed.username), safe="-._~")
        if parsed.password is not None:
            auth += ":" + quote(unquote(parsed.password), safe="-._~")
        auth += "@"
    return urlunsplit((parsed.scheme.lower(), f"{auth}{host}:{port}", "", "", ""))


def _proxy_fingerprint(proxy: str) -> str:
    return hashlib.sha256(proxy.encode("utf-8")).hexdigest()[:24]


def _declared_proxy_country(proxy: str) -> str:
    decoded = unquote(proxy)
    countries = {
        match.group("country").upper()
        for match in _PROXY_REGION_RE.finditer(decoded)
    }
    if not countries:
        return ""
    if len(countries) != 1:
        return "MULTIPLE"
    return next(iter(countries))


def _extract_ba_token(*, ba_url: str, ba_token: str) -> str:
    raw_url = str(ba_url or "").strip()
    raw_token = str(ba_token or "").strip()
    if bool(raw_url) == bool(raw_token):
        raise PayPalPaymentInputError("BA_INPUT_AMBIGUOUS", stage="input")
    if raw_token:
        if not _BA_TOKEN_RE.fullmatch(raw_token):
            raise PayPalPaymentInputError("BA_TOKEN_INVALID", stage="input")
        return raw_token

    try:
        parsed = urlsplit(raw_url)
        port = parsed.port
    except ValueError:
        raise PayPalPaymentInputError("BA_URL_INVALID", stage="input") from None
    if (
        parsed.scheme.lower() != "https"
        or (parsed.hostname or "").lower() not in _PAYPAL_HOSTS
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.path.rstrip("/") != "/agreements/approve"
    ):
        raise PayPalPaymentInputError("BA_URL_INVALID", stage="input")
    try:
        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise PayPalPaymentInputError("BA_URL_INVALID", stage="input") from None
    if set(query) != {"ba_token"}:
        raise PayPalPaymentInputError("BA_URL_INVALID", stage="input")
    values = query.get("ba_token") or []
    if len(values) != 1 or not _BA_TOKEN_RE.fullmatch(str(values[0])):
        raise PayPalPaymentInputError("BA_URL_INVALID", stage="input")
    return str(values[0])


_COUNTRIES: dict[str, dict[str, Any]] = {
    "BR": {"locale": "pt_BR", "lang": "pt", "code": "55", "phone": r"\d{10,11}", "tz": "America/Sao_Paulo", "offset": 180, "address": ("Avenida Paulista", "1000", "Bela Vista", "Sao Paulo", "SP", "01310-100")},
    "GB": {"locale": "en_GB", "lang": "en", "code": "44", "phone": r"7\d{9}", "tz": "Europe/London", "offset": 0, "address": ("Arundel Gardens", "12", "Notting Hill", "London", "Greater London", "W11 2LW")},
    "US": {"locale": "en_US", "lang": "en", "code": "1", "phone": r"[2-9]\d{9}", "tz": "America/New_York", "offset": 300, "address": ("Fifth Avenue", "350", "", "New York", "NY", "10118")},
    "JP": {"locale": "ja_JP", "lang": "ja", "code": "81", "phone": r"[789]0\d{8}", "tz": "Asia/Tokyo", "offset": -540, "address": ("Marunouchi", "1-1-1", "Chiyoda-ku", "Chiyoda", "Tokyo", "100-0005")},
    "TH": {"locale": "th_TH", "lang": "th", "code": "66", "phone": r"[689]\d{8}", "tz": "Asia/Bangkok", "offset": -420, "address": ("Rama I Road", "991", "Pathum Wan", "Bangkok", "Bangkok", "10330")},
    "ID": {"locale": "id_ID", "lang": "id", "code": "62", "phone": r"8\d{8,11}", "tz": "Asia/Jakarta", "offset": -420, "address": ("Jalan M.H. Thamrin", "1", "Menteng", "Jakarta Pusat", "DKI Jakarta", "10310")},
    "PH": {"locale": "en_PH", "lang": "en", "code": "63", "phone": r"9\d{9}", "tz": "Asia/Manila", "offset": -480, "address": ("Ayala Avenue", "6750", "San Lorenzo", "Makati", "Metro Manila", "1226")},
    "TW": {"locale": "zh_TW", "lang": "zh", "code": "886", "phone": r"9\d{8}", "tz": "Asia/Taipei", "offset": -480, "address": ("Xinyi Road", "7", "Xinyi District", "Taipei", "Taipei", "110")},
    "MX": {"locale": "es_MX", "lang": "es", "code": "52", "phone": r"\d{10}", "tz": "America/Mexico_City", "offset": 360, "address": ("Avenida Paseo de la Reforma", "222", "Juarez", "Ciudad de Mexico", "CMX", "06600")},
    "AE": {"locale": "en_AE", "lang": "en", "code": "971", "phone": r"5[024568]\d{7}", "tz": "Asia/Dubai", "offset": -240, "address": ("Sheikh Zayed Road", "1", "Trade Centre", "Dubai", "Dubai", "")},
    "AU": {"locale": "en_AU", "lang": "en", "code": "61", "phone": r"4\d{8}", "tz": "Australia/Sydney", "offset": -600, "address": ("George Street", "1", "", "Sydney", "NSW", "2000")},
    "CA": {"locale": "en_CA", "lang": "en", "code": "1", "phone": r"[2-9]\d{9}", "tz": "America/Toronto", "offset": 300, "address": ("Queen Street West", "100", "", "Toronto", "ON", "M5H 2N2")},
}

_FIRST_NAMES = ("Alex", "Daniel", "Lucas", "Oliver", "Emma", "Sofia", "Mia", "Julia")
_LAST_NAMES = ("Smith", "Silva", "Lee", "Garcia", "Martin", "Santos", "Brown", "Chen")
_COUNTRY_NAME_POOLS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "GB": (
        (
            "Oliver", "George", "Harry", "Jack", "Noah", "Charlie", "Thomas",
            "James", "William", "Henry", "Amelia", "Olivia", "Isla", "Emily",
            "Sophie", "Grace", "Charlotte", "Ella", "Lucy", "Alice",
        ),
        (
            "Smith", "Jones", "Taylor", "Brown", "Williams", "Wilson", "Johnson",
            "Davies", "Patel", "Robinson", "Wright", "Thompson", "Evans",
            "Walker", "White", "Edwards", "Green", "Hall", "Thomas", "Clarke",
        ),
    ),
}
_COUNTRY_ADDRESS_POOLS: dict[str, tuple[tuple[str, str, str, str, str, str], ...]] = {
    "GB": (
        ("Arundel Gardens", "12", "Notting Hill", "London", "Greater London", "W11 2LW"),
        ("Noel Road", "25", "Islington", "London", "Greater London", "N1 8HQ"),
        ("Derngate", "78", "Semilong", "Northampton", "Northamptonshire", "NN1 1UH"),
        ("Forthlin Road", "20", "Allerton", "Liverpool", "Merseyside", "L18 9TL"),
        ("Menlove Avenue", "251", "Woolton", "Liverpool", "Merseyside", "L25 7SA"),
        ("Plymouth Grove", "84", "Chorlton-on-Medlock", "Manchester", "Greater Manchester", "M13 9LW"),
    ),
}


def _normalize_phone(phone: str, country: str) -> dict[str, str]:
    raw = str(phone or "").strip()
    if not raw.startswith("+") or not re.fullmatch(r"\+[0-9]{8,15}", raw):
        raise PayPalPaymentInputError("PHONE_INVALID", stage="input")
    profile = _COUNTRIES[country]
    digits = raw[1:]
    code = str(profile["code"])
    if not digits.startswith(code):
        raise PayPalPaymentInputError("PHONE_COUNTRY_MISMATCH", stage="input")
    local = digits[len(code):]
    if not re.fullmatch(str(profile["phone"]), local):
        raise PayPalPaymentInputError("PHONE_INVALID", stage="input")
    return {"full": raw, "local": local, "country_code": code}


def _random_password() -> str:
    chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^"),
    ]
    chars.extend(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    random.SystemRandom().shuffle(chars)
    return "".join(chars)


def _luhn_digit(body: str) -> str:
    digits = [int(value) for value in body]
    for index in range(len(digits) - 1, -1, -2):
        digits[index] *= 2
        if digits[index] > 9:
            digits[index] -= 9
    return str((10 - sum(digits) % 10) % 10)


def _generate_card() -> dict[str, str]:
    prefix = secrets.choice(("4", "51", "52", "53", "54", "55"))
    body = prefix + "".join(secrets.choice(string.digits) for _ in range(15 - len(prefix)))
    return {
        "number": body + _luhn_digit(body),
        "expiry": f"{secrets.randbelow(12) + 1:02d}/{2028 + secrets.randbelow(4)}",
        "cvv": f"{secrets.randbelow(1000):03d}",
    }


def _generate_cpf() -> str:
    digits = [secrets.randbelow(10) for _ in range(9)]
    remainder = sum(value * weight for value, weight in zip(digits, range(10, 1, -1))) % 11
    digits.append(0 if remainder < 2 else 11 - remainder)
    remainder = sum(value * weight for value, weight in zip(digits, range(11, 1, -1))) % 11
    digits.append(0 if remainder < 2 else 11 - remainder)
    return "".join(str(value) for value in digits)


def _generate_identity(country: str, dob: dict[str, str]) -> dict[str, str]:
    if country == "BR":
        return {"type": "CPF", "value": _generate_cpf()}
    if country == "TH":
        body = [secrets.randbelow(8) + 1] + [secrets.randbelow(10) for _ in range(11)]
        check = (11 - sum(value * weight for value, weight in zip(body, range(13, 1, -1))) % 11) % 10
        return {"type": "NATIONAL_ID", "value": "".join(map(str, body)) + str(check)}
    if country == "ID":
        value = f"317301{int(dob['day']):02d}{int(dob['month']):02d}{int(dob['year']) % 100:02d}{secrets.randbelow(9999) + 1:04d}"
        return {"type": "NATIONAL_ID", "value": value}
    if country == "PH":
        return {"type": "NATIONAL_ID", "value": "".join(secrets.choice(string.digits) for _ in range(16))}
    if country == "TW":
        return {"type": "NATIONAL_ID", "value": "A1" + "".join(secrets.choice(string.digits) for _ in range(8))}
    if country == "AE":
        return {"type": "NATIONAL_ID", "value": "784" + dob["year"] + "".join(secrets.choice(string.digits) for _ in range(8))}
    return {}


def _generate_profile(country: str, phone: dict[str, str]) -> dict[str, Any]:
    first_names, last_names = _COUNTRY_NAME_POOLS.get(
        country, (_FIRST_NAMES, _LAST_NAMES),
    )
    first_name = secrets.choice(first_names)
    last_name = secrets.choice(last_names)
    year = 1980 + secrets.randbelow(21)
    month = 1 + secrets.randbelow(12)
    day = 1 + secrets.randbelow(28)
    dob = {"day": f"{day:02d}", "month": f"{month:02d}", "year": str(year)}
    address_pool = _COUNTRY_ADDRESS_POOLS.get(country)
    street, house, district, city, state, postal = (
        secrets.choice(address_pool)
        if address_pool
        else _COUNTRIES[country]["address"]
    )
    return {
        "user": {
            "first_name": first_name,
            "last_name": last_name,
            "email": "".join(
                secrets.choice(string.ascii_lowercase + string.digits)
                for _ in range(12)
            ) + "@gmail.com",
            "password": _random_password(),
            "phone": dict(phone),
            "dob": dob,
            "identity": _generate_identity(country, dob),
        },
        "card": _generate_card(),
        "address": {
            "street": street,
            "house_number": house,
            "line2": district,
            "city": city,
            "state": state,
            "postal_code": postal,
            "country": country,
        },
    }


def _new_context(
    *,
    ba_token: str,
    phone: dict[str, str],
    country: str,
    buyer_mode: str,
    proxy_fingerprint: str,
    now: float,
    ttl: float,
) -> dict[str, Any]:
    context_id = uuid.uuid4().hex
    return {
        "version": CONTEXT_VERSION,
        "context_id": context_id,
        "phase": "starting",
        "created_at": now,
        "expires_at": now + ttl,
        "proxy_fingerprint": proxy_fingerprint,
        "country": country,
        "buyer_mode": buyer_mode,
        "otp_attempts": 0,
        "state": {
            "ba_token": ba_token,
            "ec_token": "",
            "ssrt": "",
            "ctx_id": "",
            "signup_url": "",
            "content_identifier": "",
            "paypal_client_metadata_id": str(uuid.uuid4()),
            "euat_token": "",
            "user_id": "",
            "auth_id": "",
            "challenge_id": "",
        },
        "profile": _generate_profile(country, phone),
        "cookies": [],
    }


def _validate_context(context: Mapping[str, Any], *, proxy: str, now: float) -> dict[str, Any]:
    try:
        data = json.loads(json.dumps(dict(context), allow_nan=False))
    except Exception:
        raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input") from None
    if data.get("version") != CONTEXT_VERSION:
        raise PayPalPaymentInputError("CONTEXT_VERSION_UNSUPPORTED", stage="input")
    if not re.fullmatch(r"[a-f0-9]{32}", str(data.get("context_id") or "")):
        raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input")
    if data.get("phase") != "waiting_otp":
        raise PayPalPaymentInputError("CONTEXT_NOT_WAITING_OTP", stage="input")
    if data.get("proxy_fingerprint") != _proxy_fingerprint(proxy):
        raise PayPalPaymentInputError("PROXY_CONTEXT_MISMATCH", stage="input")
    try:
        created_at = float(data.get("created_at"))
        expires_at = float(data.get("expires_at"))
        otp_attempts = int(data.get("otp_attempts", 0))
    except (TypeError, ValueError):
        raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input") from None
    if (
        not math.isfinite(created_at)
        or not math.isfinite(expires_at)
        or created_at >= expires_at
        or expires_at - created_at > 86400.0
        or otp_attempts < 0
        or otp_attempts > 100
    ):
        raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input")
    if expires_at <= now:
        raise PayPalPaymentInputError("OTP_CONTEXT_EXPIRED", stage="input")
    country = str(data.get("country") or "")
    buyer_mode = str(data.get("buyer_mode") or "")
    state = data.get("state")
    profile = data.get("profile")
    if country not in _COUNTRIES or buyer_mode not in {"original", "identity_elevation"}:
        raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input")
    declared_country = _declared_proxy_country(proxy)
    if declared_country and declared_country != country:
        raise PayPalPaymentInputError("PROXY_COUNTRY_MISMATCH", stage="input")
    if not isinstance(state, dict) or not isinstance(profile, dict):
        raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input")
    required = ("ba_token", "ec_token", "auth_id", "challenge_id", "signup_url")
    if any(not str(state.get(key) or "") for key in required):
        raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input")
    ec_token = str(state["ec_token"])
    if (
        not _BA_TOKEN_RE.fullmatch(str(state["ba_token"]))
        or not re.fullmatch(r"EC-[A-Za-z0-9_-]{3,100}", ec_token)
        or not re.fullmatch(r"[0-9a-f-]{36}", str(state.get("paypal_client_metadata_id") or ""))
    ):
        raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input")
    try:
        metadata_id = uuid.UUID(str(state["paypal_client_metadata_id"]))
        signup = urlsplit(str(state["signup_url"]))
        signup_port = signup.port
        signup_query = parse_qs(signup.query, keep_blank_values=True, strict_parsing=True)
    except (KeyError, ValueError):
        raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input") from None
    if (
        str(metadata_id) != str(state["paypal_client_metadata_id"])
        or signup.scheme != "https"
        or (signup.hostname or "").lower() not in _PAYPAL_HOSTS
        or signup_port not in {None, 443}
        or signup.username is not None
        or signup.password is not None
        or signup.fragment
        or signup.path != "/checkoutweb/signup"
        or signup_query.get("token") != [ec_token]
        or signup_query.get("ba_token") != [str(state["ba_token"])]
        or signup_query.get("country.x") != [country]
    ):
        raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input")
    for key in ("auth_id", "challenge_id", "content_identifier"):
        value = str(state.get(key) or "")
        if not value or len(value) > 1024 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
            raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input")
    try:
        normalized_phone = _normalize_phone(str(profile["user"]["phone"]["full"]), country)
        stored_phone = profile["user"]["phone"]
        card = profile["card"]
        address = profile["address"]
    except (KeyError, TypeError, PayPalPaymentInputError):
        raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input") from None
    cookies = data.get("cookies")
    if (
        not isinstance(stored_phone, dict)
        or stored_phone != normalized_phone
        or not isinstance(card, dict)
        or not re.fullmatch(r"\d{13,19}", str(card.get("number") or ""))
        or _luhn_digit(str(card.get("number") or "")[:-1]) != str(card.get("number") or "")[-1:]
        or not re.fullmatch(r"(?:0[1-9]|1[0-2])/20\d{2}", str(card.get("expiry") or ""))
        or not re.fullmatch(r"\d{3,4}", str(card.get("cvv") or ""))
        or not isinstance(address, dict)
        or str(address.get("country") or "") != country
        or not isinstance(cookies, list)
        or len(cookies) > 200
    ):
        raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input")
    for cookie in cookies:
        if not isinstance(cookie, dict):
            raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input")
        name = str(cookie.get("name") or "")
        value = str(cookie.get("value") or "")
        domain = str(cookie.get("domain") or "").lower().lstrip(".")
        path = str(cookie.get("path") or "")
        expires = cookie.get("expires")
        if (
            not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}", name)
            or len(value) > 4096
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
            or not (domain == "paypal.com" or domain.endswith(".paypal.com"))
            or not path.startswith("/")
            or len(path) > 1024
            or not isinstance(cookie.get("secure"), bool)
            or (expires is not None and not isinstance(expires, (int, float)))
        ):
            raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input")
    return data


def _phone_hint(context: Mapping[str, Any]) -> str:
    try:
        full = str(context["profile"]["user"]["phone"]["full"])
    except Exception:
        return "***"
    digits = "".join(char for char in full if char.isdigit())
    return f"***{digits[-4:]}" if len(digits) >= 4 else "***"


CHECKOUT_SESSION_QUERY = """
query CheckoutSessionDataQuery($token: String!) {
  checkoutSession(token: $token) {
    checkoutSessionType
    cart { amounts { total { currencyCode currencyValue } } }
    merchant { country merchantId name }
  }
}
"""

DEFERRED_FEATURE_QUERY = """
query DeferredFeature($channel: String!, $countryCodeAsString: String!, $isBaslAsString: String!, $isForcedGuest: String!, $token: String!, $integrationType: String!) {
  otpLoginContext(token: $token, integrationType: $integrationType) { context }
  elmoExperiment(
    app: "checkoutuinodeweb"
    filters: [{key: "Country", value: $countryCodeAsString}, {key: "Channel", value: $channel}, {key: "IsBasl", value: $isBaslAsString}, {key: "IsGuestOnly", value: $isForcedGuest}]
    res: "weasley:deferredFeature:memberAsDefault"
  ) { treatments { experimentId experimentName factors { key value } treatmentId treatmentName } }
}
"""

SUPPORTED_FUNDING_SOURCES_QUERY = """
query SupportedFundingSourcesQuery($token: String!, $userCountry: CountryCodes) {
  checkoutSession(token: $token) {
    supportedFundingSources(userCountry: $userCountry) {
      issuers { name usage issuerLogoUrl { href } rank }
    }
  }
}
"""

GRIFFIN_METADATA_QUERY = """
query GriffinMetadataQuery($countryCode: CountryCodes!, $languageCode: CheckoutContentLanguageCode!, $shippingCountryCode: CountryCodes!) {
  localeMetadata {
    address(countryCode: $countryCode, languageCode: $languageCode) { layout { name isRequired maxLength minLength regex } }
    currencyCode(countryCode: $countryCode)
    phone(countryCode: $countryCode) { masks { mobile } patterns { default } }
  }
}
"""

ADDRESS_NORMALIZATION_QUERY = """
query AddressAutocompleteFromPostalCodeQuery($postalCode: String!, $token: String!, $country: CountryCodes) {
  addressNormalization(postalCode: $postalCode, token: $token, processMode: FASTCOMPLETION, scope: STREET_LEVEL, country: $country) {
    line1 line2 city state postalCode
  }
}
"""

INSTALLMENT_OPTIONS_QUERY = """
query InstallmentOptionsQuery($buyerCountry: CountryCodes!, $cardNumber: String!, $cardType: CardIssuerType, $token: String!) {
  getInstallmentsForOnboardingFlows(
    buyerCountry: $buyerCountry cardNumber: $cardNumber cardType: $cardType token: $token
  ) { term feeReferenceId }
}
"""

INITIATE_OTP_MUTATION = """
mutation InitiateRiskBasedTwoFactorPhoneConfirmationMutation($phoneNumber: String!, $locale: LocaleInput!, $phoneCountry: CountryCodes!, $token: String!) {
  initiateRiskBasedTwoFactorPhoneConfirmation(locale: $locale, phoneCountry: $phoneCountry, phoneNumber: $phoneNumber, token: $token) {
    authId challengeId state
  }
}
"""

CONFIRM_OTP_MUTATION = """
mutation ConfirmRiskBasedTwoFactorPhoneConfirmationMutation($pin: String!, $authId: String!, $challengeId: String!, $token: String!) {
  confirmRiskBasedTwoFactorPhoneConfirmation(pin: $pin, authId: $authId, challengeId: $challengeId, token: $token) {
    authId challengeId state
  }
}
"""

SIGNUP_MUTATION = """
mutation SignUpNewMemberMutation($bank: BankAccountInput, $billingAddress: AddressInput, $card: CardInput, $contentIdentifier: String, $country: CountryCodes, $countrySpecificFirstName: String, $countrySpecificLastName: String, $crsData: CommonReportingStandardsInput, $currencyConversionType: CheckoutCurrencyConversionType, $dateOfBirth: DateOfBirth, $email: String!, $firstName: String!, $gender: Gender, $identityDocument: IdentityDocumentInput, $lastName: String!, $middleName: String, $marketingOptOut: Boolean, $nationality: CountryCodes, $occupation: Occupation, $password: String, $phone: PhoneInput!, $placeOfBirth: CountryCodes, $secondaryIdentityDocument: IdentityDocumentInput, $selectedInstallmentOption: InstallmentsInput, $shareAddressWithDonatee: Boolean, $shippingAddress: AddressInput, $supportedThreeDsExperiences: [ThreeDSPaymentExperience], $token: String!, $residentialAddress: AddressInput, $isSignupIncentiveOptIn: Boolean, $isSignupIncentiveOptInStretch: Boolean, $legalAgreements: LegalAgreementsInput, $collectedConsents: [CollectedConsent]) {
  onboardAccount: signUpNewMember(
    bank: $bank
    billingAddress: $billingAddress
    card: $card
    contentIdentifier: $contentIdentifier
    countrySpecificFirstName: $countrySpecificFirstName
    countrySpecificLastName: $countrySpecificLastName
    country: $country
    crsData: $crsData
    currencyConversionType: $currencyConversionType
    dateOfBirth: $dateOfBirth
    email: $email
    firstName: $firstName
    gender: $gender
    identityDocument: $identityDocument
    lastName: $lastName
    middleName: $middleName
    marketingOptOut: $marketingOptOut
    nationality: $nationality
    occupation: $occupation
    password: $password
    phone: $phone
    placeOfBirth: $placeOfBirth
    secondaryIdentityDocument: $secondaryIdentityDocument
    selectedInstallmentOption: $selectedInstallmentOption
    shareAddressWithDonatee: $shareAddressWithDonatee
    shippingAddress: $shippingAddress
    token: $token
    residentialAddress: $residentialAddress
    isSignupIncentiveOptIn: $isSignupIncentiveOptIn
    isSignupIncentiveOptInStretch: $isSignupIncentiveOptInStretch
    legalAgreements: $legalAgreements
    collectedConsents: $collectedConsents
  ) {
    ...buyer
    flags {
      is3DSecureRequired
      __typename
    }
    ...fundingOptions
    paymentContingencies {
      ...threeDomainSecure
      ...threeDSContingencyData
      __typename
    }
    __typename
  }
}

fragment buyer on CheckoutSession {
  buyer {
    auth {
      accessToken
      __typename
    }
    userId
    __typename
  }
  __typename
}

fragment fundingOptions on CheckoutSession {
  fundingOptions {
    allPlans {
      fundingSources {
        fundingInstrument {
          id
          __typename
        }
        amount {
          currencyCode
          currencyValue
          __typename
        }
        __typename
      }
      fundingContingencies {
        ... on OpenBankingContingency {
          encryptedId
          contingencyReasons
          contingencyType
          __typename
        }
        __typename
      }
      __typename
    }
    fundingInstrument {
      id
      lastDigits
      name
      nameDescription
      type
      __typename
    }
    __typename
  }
  __typename
}

fragment threeDomainSecure on PaymentContingencies {
  threeDomainSecure(experiences: $supportedThreeDsExperiences) {
    status
    redirectUrl {
      href
      __typename
    }
    method
    parameter
    experience
    requestParams {
      key
      value
      __typename
    }
    __typename
  }
  __typename
}

fragment threeDSContingencyData on PaymentContingencies {
  threeDSContingencyData {
    name
    causeName
    resolution {
      type
      resolutionName
      paymentCard {
        billingAddress {
          line1
          line2
          city
          state
          country
          postalCode
          __typename
        }
        expireYear
        expireMonth
        currencyCode
        cardProductClass
        id
        encryptedNumber
        type
        number
        bankIdentificationNumber
        __typename
      }
      contingencyContext {
        deviceDataCollectionUrl {
          href
          __typename
        }
        jwtSpecification {
          jwtDuration
          jwtIssuer
          jwtOrgUnitId
          type
          __typename
        }
        authenticationProvider
        cardBrandProcessed
        reason
        referenceId
        source
        __typename
      }
      __typename
    }
    __typename
  }
  __typename
}
"""

BUYER_FUNDING_QUERY = """
query BuyerFundingContextQuery($token: String!) {
  checkoutSession(token: $token) {
    buyer { userId auth { accessToken } }
    fundingOptions { fundingInstrument { id lastDigits type } allPlans { fundingSources { fundingInstrument { id type } } } }
  }
}
"""

BUYER_CONTEXT_QUERY = """
query BuyerContextQuery($token: String!) {
  checkoutSession(token: $token) { buyer { userId auth { accessToken } } }
}
"""

AUTHORIZE_MUTATION = """
mutation authorize($billingAgreementId: String!, $addressId: String, $fundingPreference: billingFundingPreferenceInput, $legalAgreements: billingLegalAgreementsInput) {
  billing {
    authorize(billingAgreementId: $billingAgreementId, addressId: $addressId, fundingPreference: $fundingPreference, legalAgreements: $legalAgreements) {
      billingAgreementToken paymentAction returnURL { href } buyer { userId }
    }
  }
}
"""


class _LivePayPalProtocol:
    """One PayPal protocol session bound to one immutable proxy."""

    def __init__(
        self,
        *,
        proxy: str,
        timeout: float,
        context: dict[str, Any],
        max_card_attempts: int = DEFAULT_MAX_CARD_ATTEMPTS,
        session_factory: Callable[..., Any] | None = None,
        trace: Callable[[dict[str, Any]], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.proxy = proxy
        self.timeout = max(1.0, float(timeout))
        self.context = context
        self.state = context["state"]
        self.profile = context["profile"]
        self.country = str(context["country"])
        self.country_profile = _COUNTRIES[self.country]
        self.max_card_attempts = max(1, int(max_card_attempts))
        self.sleep = sleep
        self.trace = trace
        self.last_graphql_meta: dict[str, Any] = {}
        common_headers = {
            "Accept-Language": self._accept_language(),
        }
        if session_factory is not None:
            self.transport_engine = "custom"
            self.session = session_factory(
                proxy=proxy,
                timeout=self.timeout,
                headers=dict(common_headers),
            )
        else:
            if curl_requests is None:
                raise PayPalPaymentError("CURL_CFFI_REQUIRED", stage="session")
            impersonate = (os.getenv("PAYPAL_CURL_IMPERSONATE") or "chrome").strip()
            self.transport_engine = f"curl_cffi/{impersonate}"
            # curl_cffi must generate UA/client hints together with its TLS and
            # HTTP/2 fingerprint. Only the locale is application-specific.
            self.session = curl_requests.Session(
                impersonate=impersonate,
                headers=common_headers,
            )
            self.session.proxies = {"http": proxy, "https": proxy}
            self.session.timeout = self.timeout
            try:
                self.session.trust_env = False
            except Exception:
                pass
        self._import_cookies(context.get("cookies"))

    def _emit_trace(
        self,
        *,
        status: str,
        message: str,
        stage: str,
        **details: Any,
    ) -> None:
        _emit_trace_callback(self.trace, {
            "status": status,
            "message": str(message or "")[:500],
            "stage": _safe_stage(stage),
            **details,
        })

    def _accept_language(self) -> str:
        locale = str(self.country_profile["locale"]).replace("_", "-")
        return f"{locale},{str(self.country_profile['lang'])};q=0.9,en-US;q=0.7,en;q=0.5"

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass

    def _import_cookies(self, rows: object) -> None:
        if not isinstance(rows, list):
            return
        cookies = getattr(self.session, "cookies", None)
        setter = getattr(cookies, "set", None)
        if not callable(setter):
            return
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            name = str(row.get("name") or "")
            value = str(row.get("value") or "")
            domain = str(row.get("domain") or ".paypal.com")
            path = str(row.get("path") or "/")
            if not name or not value or not domain:
                continue
            try:
                setter(name, value, domain=domain, path=path)
            except Exception:
                try:
                    setter(name, value)
                except Exception:
                    continue

    def export_cookies(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        jar = getattr(getattr(self.session, "cookies", None), "jar", None)
        if jar is None:
            return result
        try:
            for cookie in jar:
                name = str(getattr(cookie, "name", "") or "")
                value = str(getattr(cookie, "value", "") or "")
                domain = str(getattr(cookie, "domain", "") or ".paypal.com")
                if not name or not value:
                    continue
                result.append(
                    {
                        "name": name,
                        "value": value,
                        "domain": domain,
                        "path": str(getattr(cookie, "path", "") or "/"),
                        "secure": bool(getattr(cookie, "secure", True)),
                        "expires": getattr(cookie, "expires", None),
                    }
                )
        except Exception:
            return []
        return result

    def _cookie_value(self, name: str) -> str:
        wanted = str(name or "")
        if not wanted:
            return ""
        jar = getattr(getattr(self.session, "cookies", None), "jar", None)
        if jar is None:
            return ""
        found = ""
        try:
            for cookie in jar:
                if str(getattr(cookie, "name", "") or "") == wanted:
                    found = str(getattr(cookie, "value", "") or "")
        except Exception:
            return ""
        return found

    def checkpoint(self, phase: str) -> None:
        self.context["phase"] = str(phase)
        self.context["cookies"] = self.export_cookies()
        self._emit_trace(
            status="checkpoint",
            stage=str(phase),
            message=f"PayPal 流程检查点：{_safe_stage(phase)}",
        )

    def _request(
        self,
        method: str,
        url: str,
        *,
        stage: str,
        mutation: bool = False,
        accepted_statuses: set[int] | None = None,
        **kwargs: Any,
    ) -> Any:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)
        verb = str(method or "GET").upper()
        target = _safe_trace_target(url)
        started = time.monotonic()
        try:
            response = self.session.request(method, url, **kwargs)
        except Exception as exc:
            self._emit_trace(
                status="failed",
                stage=stage,
                message=f"{verb} {target} 请求失败：{type(exc).__name__}",
                method=verb,
                target=target,
                duration_ms=int((time.monotonic() - started) * 1000),
                mutation=mutation,
            )
            if mutation:
                raise PayPalPaymentUncertainError(
                    "MUTATION_RESPONSE_TIMEOUT" if _is_timeout_error(exc) else "MUTATION_TRANSPORT_UNCERTAIN",
                    stage=stage,
                ) from exc
            raise PayPalPaymentError(
                "NETWORK_TIMEOUT" if _is_timeout_error(exc) else "NETWORK_ERROR",
                stage=stage,
                retryable=not mutation,
                replay_safe=not mutation,
            ) from exc

        status = int(getattr(response, "status_code", 0) or 0)
        self._emit_trace(
            status="response" if 200 <= status < 400 else "http_error",
            stage=stage,
            message=f"{verb} {target} -> HTTP {status or 'unknown'}",
            method=verb,
            target=target,
            http_status=status or None,
            duration_ms=int((time.monotonic() - started) * 1000),
            mutation=mutation,
        )
        accepted = accepted_statuses or set(range(200, 300))
        if status in accepted:
            return response
        if mutation and (status in {408, 425, 429} or status >= 500):
            raise PayPalPaymentUncertainError("MUTATION_STATUS_UNCERTAIN", stage=stage)
        if status == 407:
            code = "PROXY_AUTHENTICATION_REQUIRED"
        elif status == 403:
            code = "PAYPAL_CHALLENGE_REQUIRED"
        else:
            code = "PAYPAL_HTTP_ERROR"
        raise PayPalPaymentError(
            code,
            stage=stage,
            retryable=(status in {408, 425, 429} or status >= 500),
            http_status=status,
        )

    @staticmethod
    def _paypal_redirect_url(current: str, location: str) -> str:
        target = urljoin(current, str(location or ""))
        parsed = urlsplit(target)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not (host == "paypal.com" or host.endswith(".paypal.com")):
            raise PayPalPaymentError("PAYPAL_REDIRECT_INVALID", stage="redirect")
        return target

    def _follow_paypal_response(
        self,
        response: Any,
        *,
        stage: str,
        referer: str = "",
        max_hops: int = 8,
        terminal_statuses: set[int] | None = None,
    ) -> Any:
        current_response = response
        current_url = str(getattr(response, "url", "") or "")
        current_referer = referer
        allowed_terminal_statuses = set(terminal_statuses or ())
        for _ in range(max_hops):
            status = int(getattr(current_response, "status_code", 0) or 0)
            if status not in {301, 302, 303, 307, 308}:
                return current_response
            location = str(getattr(current_response, "headers", {}).get("Location") or "")
            if not location:
                raise PayPalPaymentError("PAYPAL_REDIRECT_MISSING", stage=stage)
            target = self._paypal_redirect_url(current_url, location)
            headers = self._navigation_headers(referer=current_url or current_referer)
            current_referer, current_url = current_url, target
            current_response = self._request(
                "GET",
                target,
                stage=stage,
                accepted_statuses=(
                    set(range(200, 300))
                    | {301, 302, 303, 307, 308}
                    | allowed_terminal_statuses
                ),
                headers=headers,
            )
        raise PayPalPaymentError("PAYPAL_REDIRECT_LIMIT", stage=stage)

    def _navigation_headers(self, *, referer: str = "") -> dict[str, str]:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": self._accept_language(),
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
        }
        if referer:
            headers["Referer"] = referer
            headers["Sec-Fetch-Site"] = "same-origin"
        else:
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-User"] = "?1"
        return headers

    def _graphql(
        self,
        operation: str,
        query: str,
        variables: dict[str, Any],
        *,
        stage: str,
        mutation: bool = False,
        endpoint: str | None = None,
        referer: str = "",
        app_name: str = "checkoutuinodeweb_weasley",
        batched: bool = False,
        extra_body: dict[str, Any] | None = None,
        omit_context_headers: bool = False,
        client_metadata_id: str | None = None,
    ) -> Any:
        token = str(
            variables.get("token")
            or variables.get("billingAgreementId")
            or self.state.get("ec_token")
            or self.state.get("ba_token")
        )
        target = endpoint or f"{GRAPHQL_URL}?{operation}"
        headers = {
            "Content-Type": "application/json",
            "X-App-Name": app_name,
            "X-Requested-With": "fetch",
            "Origin": PAYPAL_ORIGIN,
            "Referer": referer or str(self.state.get("signup_url") or PAYPAL_ORIGIN),
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            # The checkoutweb request binds this header to the active BA/EC
            # context. A task UUID here disagrees with the FraudNet correlation
            # id used by the page and is rejected by some onboarding buckets.
            "PayPal-Client-Metadata-Id": str(client_metadata_id or token),
        }
        if not omit_context_headers:
            headers.update(
                {
                    "PayPal-Client-Context": token,
                    "X-Country": self.country,
                    "X-Locale": str(self.country_profile["locale"]),
                }
            )
        euat = str(self.state.get("euat_token") or "")
        if euat:
            headers["X-PayPal-Internal-EUAT"] = euat
        item = {"operationName": operation, "variables": variables, "query": query}
        if extra_body:
            item.update(extra_body)
        payload: Any = [item] if batched else item
        def send() -> Any:
            return self._request(
                "POST",
                target,
                stage=stage,
                mutation=mutation,
                # PayPal returns deterministic GraphQL validation/card errors as
                # HTTP 400 JSON. Parse those before deciding whether retrying is
                # safe; non-JSON mutation responses remain ambiguous below.
                accepted_statuses=set(range(200, 300)) | {400},
                headers=headers,
                json=payload,
            )

        def capture_meta(response: Any) -> None:
            response_headers = getattr(response, "headers", {}) or {}
            debug_id = ""
            for name in ("paypal-debug-id", "Paypal-Debug-Id", "PayPal-Debug-Id"):
                try:
                    debug_id = str(response_headers.get(name) or "")
                except Exception:
                    debug_id = ""
                if debug_id:
                    break
            self.last_graphql_meta = {
                "operation": operation,
                "status": int(getattr(response, "status_code", 0) or 0),
                "paypal_debug_id": debug_id,
                "response_bytes": len(getattr(response, "content", b"") or b""),
            }

        response = send()
        capture_meta(response)
        try:
            return response.json()
        except Exception as exc:
            body = str(getattr(response, "text", "") or "")
            lower = body.casefold()
            challenge_html = any(marker in lower for marker in (
                "authchallengenodeweb", "captcha", "<!doctype html", "<html",
            ))
            self._emit_trace(
                status="warning",
                stage=stage,
                message=(
                    "PayPal GraphQL 返回 challenge HTML，使用同会话预热后重试一次"
                    if challenge_html else
                    "PayPal GraphQL 返回非 JSON，禁止自动重放变更请求"
                ),
                response_kind="challenge_html" if challenge_html else "non_json",
                response_bytes=len(getattr(response, "content", b"") or b""),
            )
            if challenge_html:
                self._soft_request(
                    "GET",
                    str(headers.get("Referer") or self.state.get("signup_url") or PAYPAL_ORIGIN),
                    stage=f"{stage}_challenge_warmup",
                    headers=self._navigation_headers(referer=PAYPAL_ORIGIN),
                )
                response = send()
                capture_meta(response)
                try:
                    return response.json()
                except Exception as retry_exc:
                    if mutation:
                        raise PayPalPaymentUncertainError(
                            "MUTATION_RESPONSE_INVALID", stage=stage,
                        ) from retry_exc
                    raise PayPalPaymentError(
                        "PAYPAL_RESPONSE_INVALID", stage=stage,
                    ) from retry_exc
            if mutation:
                raise PayPalPaymentUncertainError("MUTATION_RESPONSE_INVALID", stage=stage) from exc
            raise PayPalPaymentError("PAYPAL_RESPONSE_INVALID", stage=stage) from exc

    @staticmethod
    def _result_item(result: Any) -> dict[str, Any]:
        item = result[0] if isinstance(result, list) and result else result
        return item if isinstance(item, dict) else {}

    @staticmethod
    def _find_value(value: Any, key: str) -> str:
        if isinstance(value, Mapping):
            found = value.get(key)
            if isinstance(found, str) and found:
                return found
            for item in value.values():
                nested = _LivePayPalProtocol._find_value(item, key)
                if nested:
                    return nested
        elif isinstance(value, list):
            for item in value:
                nested = _LivePayPalProtocol._find_value(item, key)
                if nested:
                    return nested
        return ""

    @staticmethod
    def _build_fn_sync_data(token: str, *, signup: bool = False) -> str:
        now_ms = int(time.time() * 1000)
        payload: dict[str, Any] = {
            "SC_VERSION": "2.0.4",
            "syncStatus": "data",
            "f": token,
            "s": "IWC_LOGIN_APP" if signup else "IWC_NEXT_CHECKOUT",
            "chk": {
                "ts": now_ms,
                "eteid": [random.randint(-10_000_000_000, 20_000_000_000) for _ in range(6)] + [None, None],
                "tts": random.randint(20, 80),
            },
            "dc": json.dumps(
                {
                    "screen": {
                        "colorDepth": 24,
                        "pixelDepth": 24,
                        "height": 900,
                        "width": 1440,
                        "availHeight": 860,
                        "availWidth": 1440,
                    },
                    "ua": USER_AGENT,
                },
                separators=(",", ":"),
            ),
            "wv": False,
            "web_integration_type": "WEB_REDIRECT",
            "cookie_enabled": True,
        }
        if signup:
            timing_parts = (
                ("Di0", random.randint(12_000, 24_000)),
                ("Di1", random.randint(5, 18)),
                ("Di2", random.randint(80, 180)),
                ("Ui0", 24),
                ("Ui1", random.randint(40, 80)),
                ("Ui2", random.randint(45, 95)),
                ("Di3", random.randint(2_000, 5_000)),
                ("Di4", 24),
                ("Di5", random.randint(60, 140)),
                ("Uh", random.randint(2_500, 5_500)),
            )
            base = random.randint(18_000, 56_000)
            chunks = []
            for _ in range(20):
                first = max(1_000, base + random.randint(-28_000, 28_000))
                second = first + random.randint(-250, 250)
                third = max(1_000, first - random.randint(250, 700))
                chunks.append(f"{first},{second},{third}")
            chunks.append(f"{random.randint(8_000, 28_000)},{random.randint(20, 80)}")
            payload["d"] = {
                "ts2": "".join(f"{key}:{value}" for key, value in timing_parts),
                "rDT": ":".join(chunks),
            }
        return quote(json.dumps(payload, separators=(",", ":")), safe="")

    def _fingerprint_browser(self) -> dict[str, Any]:
        return {
            "ua": USER_AGENT,
            "lang": str(self.country_profile["locale"]).replace("_", "-"),
            "colorDepth": 24,
            "deviceMemory": 8,
            "hardwareConcurrency": 8,
            "screenResolution": [900, 1440],
            "availableScreenResolution": [860, 1440],
            "timezoneOffset": int(self.country_profile["offset"]),
            "timezone": str(self.country_profile["tz"]),
            "sessionStorage": True,
            "localStorage": True,
            "indexedDb": True,
            "openDatabase": True,
            "cpuClass": "not available",
            "platform": "Win32",
            "doNotTrack": "not available",
            "plugins": [],
            "webgl": (
                "Google Inc. (NVIDIA)|ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Ti "
                "Direct3D11 vs_5_0 ps_5_0, D3D11)"
            ),
            "webglVendorAndRenderer": (
                "Google Inc. (NVIDIA)~ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Ti "
                "Direct3D11 vs_5_0 ps_5_0, D3D11)"
            ),
            "hasLiedLanguages": False,
            "hasLiedResolution": False,
            "hasLiedOs": False,
            "hasLiedBrowser": False,
            "touchSupport": [0, False, False],
            "fonts": (
                "Arial", "Courier New", "Georgia", "Times New Roman",
                "Trebuchet MS", "Verdana",
            ),
            "audio": "124.04347527516074",
        }

    def _send_tealeaf(self, page_url: str, *, stage: str) -> None:
        now_ms = int(time.time() * 1000)
        start_x, start_y = random.randint(100, 500), random.randint(100, 400)
        end_x, end_y = random.randint(300, 800), random.randint(200, 600)
        dx: list[int] = []
        dy: list[int] = []
        timestamps: list[int] = []
        for index in range(10):
            progress = index / 9
            dx.append(int(start_x + (end_x - start_x) * progress + random.randint(-3, 3)))
            dy.append(int(start_y + (end_y - start_y) * progress + random.randint(-3, 3)))
            timestamps.append(index * 200 + random.randint(0, 50))
        payload = {
            "type": 2,
            "offset": 0,
            "screenviewOffset": 0,
            "count": 3,
            "fromWeb": True,
            "messages": [
                {
                    "type": 6,
                    "offset": 0,
                    "screenviewOffset": 0,
                    "performance": {
                        "timing": {
                            "navigationStart": now_ms - 5_000,
                            "domContentLoadedEventEnd": now_ms - 3_000,
                            "loadEventEnd": now_ms - 2_000,
                        }
                    },
                },
                {
                    "type": 2,
                    "offset": 0,
                    "screenviewOffset": 0,
                    "screenview": {
                        "type": "LOAD",
                        "name": page_url,
                        "url": page_url,
                        "host": "www.paypal.com",
                        "referrer": "",
                    },
                },
                {
                    "type": 11,
                    "offset": 1_000,
                    "screenviewOffset": 0,
                    "mouseMove": {"dx": dx, "dy": dy, "ts": timestamps},
                },
            ],
        }
        headers = {
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "X-Tealeaf-SaaS-AppKey": "76938917d7504ff7a962174c021690bd",
            "Origin": PAYPAL_ORIGIN,
        }
        tltsid = self._cookie_value("TLTSID")
        tltdid = self._cookie_value("TLTDID")
        if tltsid:
            headers["X-Tealeaf-SaaS-TLTSID"] = tltsid
        if tltdid:
            headers["X-Tealeaf-TLTDID"] = tltdid
        self._soft_request(
            "POST",
            f"{PAYPAL_ORIGIN}/platform/tealeaftarget",
            stage=stage,
            data=gzip.compress(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
            headers=headers,
        )

    def _send_analytics(
        self,
        page_name: str,
        *,
        stage: str,
        event: str = "im",
    ) -> None:
        now_ms = int(time.time() * 1000)
        params = {
            "v": "1.15.0",
            "t": str(now_ms),
            "g": str(-int(self.country_profile["offset"])),
            "pgrp": "main:billing:hagrid",
            "page": page_name,
            "pgtf": "Nodejs",
            "s": "ci",
            "env": "live",
            "comp": "checkoutuinodeweb",
            "tsrce": "checkoutuinodeweb",
            "cu": "1",
            "ef_policy": "ccpa",
            "c_prefs": "T=1,P=1,F=1,type=explicit_banner",
            "pxpguid": uuid.uuid4().hex,
            "pgst": str(now_ms - random.randint(2_000, 5_000)),
            "calc": uuid.uuid4().hex[:13],
            "rsta": str(self.country_profile["locale"]),
            "ccpg": self.country,
            "cnac": self.country,
            "flnm": "Hagrid",
            "e": event,
            "fpti_sdk_name": "pa-js",
            "cd": "24",
            "sw": "1440",
            "sh": "900",
            "bw": "1280",
            "bh": "720",
            "ce": "1",
        }
        ec_token = str(self.state.get("ec_token") or "")
        user_id = str(self.state.get("user_id") or "")
        if ec_token:
            params["fltk"] = ec_token
        if user_id:
            params.update({
                "cust": user_id,
                "party_id": user_id,
                "acnt": "personal",
                "aver": "unverified",
                "rstr": "unrestricted",
            })
        self._soft_request("GET", "https://t.paypal.com/ts", stage=stage, params=params)

    def _soft_request(self, method: str, url: str, *, stage: str, **kwargs: Any) -> None:
        try:
            self._request(method, url, stage=stage, **kwargs)
        except PayPalPaymentError:
            return

    def _send_risk_signals(self) -> None:
        token = str(self.state["ba_token"])
        now_ms = int(time.time() * 1000)
        headers = {
            "Content-Type": "application/json",
            "Origin": PAYPAL_ORIGIN,
            "Referer": PAYPAL_ORIGIN,
            "X-Requested-With": "XMLHttpRequest",
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
        }
        common = {"f": token, "s": "IWC_NEXT_CHECKOUT", "t": now_ms}
        p1 = {
            **common,
            "cb1": "close498",
            "cb2": f"fingerprintSetup{now_ms}",
            "v": "5.8.2",
            "fp2": {"browser": self._fingerprint_browser()},
        }
        self._soft_request("POST", "https://c.paypal.com/v1/r/d/b/p1", stage="risk_p1", json=p1, headers=headers)
        self._soft_request("POST", "https://c.paypal.com/v1/r/d/b/p2", stage="risk_p2", json={**common, "v": "5.8.2"}, headers=headers)
        self._soft_request("POST", "https://c.paypal.com/v1/r/d/b/w", stage="risk_w", json=common, headers=headers)

        page_params: list[tuple[str, str]] = []
        if self.state.get("ssrt"):
            page_params.append(("ssrt", str(self.state["ssrt"])))
        page_params.extend((("token", token), ("ul", "1")))
        page_url = f"{PAYPAL_ORIGIN}/pay?{urlencode(page_params)}"
        self._send_tealeaf(page_url, stage="tealeaf")
        self._send_analytics("main:xo:modxo:login", stage="analytics_login")
        self._soft_request(
            "POST",
            f"{PAYPAL_ORIGIN}/pay/api/trpc/observability.handleClientEmit?token={quote(token)}",
            stage="observability",
            data=b"",
            headers={"Content-Type": "application/json", "Origin": PAYPAL_ORIGIN},
        )

    def _send_weasley_events(self, event_names: tuple[str, ...], *, stage: str) -> None:
        token = str(self.state["ec_token"])
        signup_url = str(self.state.get("signup_url") or PAYPAL_ORIGIN)
        if not token or not event_names:
            return
        now_ms = int(time.time() * 1000)
        locale = f"{self.country_profile['lang']}_{self.country}"
        events = [
            {
                "level": "info",
                "event": name,
                "payload": {
                    "clientCountry": self.country,
                    "clientLocale": locale,
                    "clientTimestamp": now_ms + index,
                    "timestamp": str(now_ms + index),
                    "token": token,
                },
            }
            for index, name in enumerate(event_names)
        ]
        self._soft_request(
            "POST",
            f"{PAYPAL_ORIGIN}/xoplatform/logger/api/logger/",
            stage=stage,
            json={
                "events": events,
                "meta": {
                    "integrationData": {
                        "contextId": token,
                        "contextType": token,
                        "integrationMethod": "FULLPAGE",
                        "integrationType": "EC",
                    }
                },
                "tracking": [],
                "metrics": [],
            },
            headers={
                "Content-Type": "application/json",
                "Origin": PAYPAL_ORIGIN,
                "Referer": signup_url,
                "X-Requested-With": "fetch",
                "X-App-Name": "checkoutuinodeweb_weasley",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
            },
        )

    def _send_signup_page_signals(self) -> None:
        signup_url = str(self.state.get("signup_url") or PAYPAL_ORIGIN)
        self._send_tealeaf(signup_url, stage="signup_page_tealeaf")
        self._send_weasley_events(
            (
                "weasley_client_eligibility_check_success",
                "WEASLEY_PAGE_INTERACTIVE_FPTI",
                "WEASLEY_PREPARE_BILLING_PAGE_FPTI",
                "weasley_payment_request_api_available",
            ),
            stage="signup_page_observability",
        )
        self._send_onboarding_retry_signals()
        self._soft_request(
            "POST",
            f"{PAYPAL_ORIGIN}/pay/api/trpc/observability.handleClientEmit?token={quote(str(self.state['ba_token']))}",
            stage="signup_page_emit",
            data=b"",
            headers={"Content-Type": "application/json", "Origin": PAYPAL_ORIGIN},
        )

    def _send_signup_signals(self) -> None:
        token = str(self.state["ec_token"])
        signup_url = str(self.state.get("signup_url") or PAYPAL_ORIGIN)
        app_id = "CHECKOUTUINODEWEB_ONBOARDING_LITE"
        headers = {
            "Origin": PAYPAL_ORIGIN,
            "Referer": signup_url,
            "X-Requested-With": "XMLHttpRequest",
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
        }
        elapsed = random.randint(700, 1400)
        fields = (
            "email", "phone", "cardNumber", "cardExpiry", "cardCvv", "password",
            "firstName", "lastName", "billingLine1", "billingCity",
            "billingPostalCode", "billingState", "dateOfBirth",
        )
        for field in fields:
            if field in {"password", "cardCvv"}:
                timing = (
                    f"Di0:{elapsed}Di1:{random.randint(7, 45)}Di2:{random.randint(80, 420)}"
                    f"Ui0:{random.randint(20, 45)}Ui1:{random.randint(45, 120)}"
                    f"Uh:{random.randint(1200, 6500)}"
                )
            elif field == "cardNumber":
                timing = (
                    f"Dk91:{elapsed}Di0:{random.randint(120, 320)}"
                    f"Uk91:{random.randint(80, 180)}Uh:{random.randint(1200, 2200)}"
                )
            else:
                timing = (
                    f"Dk000:{elapsed}Uk000:{random.randint(4, 13)}"
                    f"Uh:{random.randint(850, 1300)}"
                )
            payload = {
                "tsobj": {
                    "elid": field,
                    "sid": app_id,
                    "tst": app_id,
                    "wsps": False,
                    "ts": timing,
                    "pf": {"psu": False, "val": False},
                }
            }
            self._soft_request(
                "GET",
                "https://c.paypal.com/v1/r/d/b/w",
                stage="signup_field_signal",
                params={
                    "f": token,
                    "s": app_id,
                    "d": quote(json.dumps(payload, separators=(",", ":")), safe=""),
                },
                headers=headers,
            )
        self._send_weasley_events(
            (
                "weasley_create_account_and_pay_submit",
                "weasley_api_request_sign_up_new_member_mutation",
            ),
            stage="signup_observability",
        )

    def _send_onboarding_retry_signals(
        self,
        *,
        stage_prefix: str = "signup_page_risk",
    ) -> None:
        token = str(self.state["ec_token"])
        signup_url = str(self.state.get("signup_url") or PAYPAL_ORIGIN)
        app_id = "CHECKOUTUINODEWEB_ONBOARDING_LITE"
        now_ms = int(time.time() * 1000)
        common = {"f": token, "s": app_id, "t": now_ms}
        p1 = {
            **common,
            "cb1": "close498",
            "cb2": f"fingerprintSetup{now_ms}",
            "v": "5.8.2",
            "fp2": {"browser": self._fingerprint_browser()},
        }
        headers = {
            "Content-Type": "application/json",
            "Origin": PAYPAL_ORIGIN,
            "Referer": signup_url,
            "X-Requested-With": "XMLHttpRequest",
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
        }
        for path, payload in (
            ("p1", p1),
            ("p2", {**common, "v": "5.8.2"}),
            ("w", common),
        ):
            self._soft_request(
                "POST",
                f"https://c.paypal.com/v1/r/d/b/{path}",
                stage=f"{stage_prefix}_{path}",
                json={"appId": app_id, "correlationId": token, "payload": payload},
                headers=headers,
            )

    @staticmethod
    def _extract_ec(value: str) -> str:
        decoded = unquote(str(value or ""))
        match = re.search(r"EC-[A-Za-z0-9_-]+", decoded)
        return match.group(0) if match else ""

    @staticmethod
    def _extract_onboarding_redirect(value: str) -> str:
        match = re.search(
            r'"onboardingRedirectUrl"\s*:\s*"([^"]+)"',
            str(value or ""),
        )
        return match.group(1).replace("\\/", "/") if match else ""

    def _discover_modxo_action_ids(self, html: str, base_url: str) -> tuple[str, str]:
        discovered = {"show": "", "create": ""}
        aliases = {
            "show": (
                "showCreateAccountAction", "showCreateAccount", "createAccountAction",
            ),
            "create": (
                "createUserAction", "createUser", "continueToPaymentAction",
            ),
        }

        def scan(source: str) -> None:
            for key, names in aliases.items():
                if discovered[key]:
                    continue
                candidates: list[tuple[int, str]] = []
                for alias in names:
                    for alias_match in re.finditer(re.escape(alias), source or "", re.I):
                        left = max(0, alias_match.start() - 3500)
                        right = min(len(source), alias_match.end() + 3500)
                        window = source[left:right]
                        for id_match in re.finditer(r'["\']([0-9a-f]{32,64})["\']', window, re.I):
                            absolute = left + id_match.start()
                            candidates.append((abs(absolute - alias_match.start()), id_match.group(1)))
                if candidates:
                    discovered[key] = min(candidates, key=lambda item: item[0])[1]

        scan(str(html or ""))
        if all(discovered.values()):
            return discovered["show"], discovered["create"]

        script_urls: list[str] = []
        for source in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', str(html or ""), re.I):
            if "_next/static/" not in source:
                continue
            script_url = urljoin(base_url, source.replace("\\/", "/"))
            parsed = urlsplit(script_url)
            if (
                parsed.scheme == "https"
                and (parsed.hostname or "").lower() in _PAYPAL_HOSTS
                and script_url not in script_urls
            ):
                script_urls.append(script_url)

        for script_url in script_urls[:120]:
            try:
                response = self._request(
                    "GET",
                    script_url,
                    stage="modxo_action_chunk",
                    headers={
                        "Accept": "*/*",
                        "Referer": base_url,
                        "Sec-Fetch-Dest": "script",
                        "Sec-Fetch-Mode": "no-cors",
                        "Sec-Fetch-Site": "same-origin",
                    },
                )
            except PayPalPaymentError:
                continue
            scan(str(getattr(response, "text", "") or ""))
            if all(discovered.values()):
                break
        return discovered["show"], discovered["create"]

    def _follow_modxo_action_redirect(self, response: Any, referer: str) -> Any:
        headers = getattr(response, "headers", {}) or {}
        location = str(headers.get("Location") or headers.get("x-action-redirect") or "")
        if not location:
            return response
        location = location.split(";", 1)[0]
        if location.startswith("/?"):
            target = f"{PAYPAL_ORIGIN}/pay{location}"
        else:
            target = self._paypal_redirect_url(
                str(getattr(response, "url", "") or referer),
                location,
            )
        next_response = self._request(
            "GET",
            target,
            stage="modxo_action_redirect",
            accepted_statuses=set(range(200, 300)) | {301, 302, 303, 307, 308},
            headers=self._navigation_headers(referer=referer),
        )
        return self._follow_paypal_response(
            next_response,
            stage="modxo_action_redirect",
            referer=referer,
        )

    def _try_modxo_server_actions(self, initial_response: Any) -> Any | None:
        initial_url = str(getattr(initial_response, "url", "") or PAYPAL_ORIGIN)
        initial_html = str(getattr(initial_response, "text", "") or "")
        show_action, create_action = self._discover_modxo_action_ids(initial_html, initial_url)
        if not show_action or not create_action:
            return None

        token = str(self.state["ba_token"])
        pay_query = urlencode({
            'ssrt': str(self.state.get('ssrt') or ''),
            'token': token,
            'ul': '1',
            'ctxId': str(self.state.get('ctx_id') or ''),
            'country.x': self.country,
        })
        pay_url = f"{PAYPAL_ORIGIN}/pay/?{pay_query}"
        try:
            pay_with_card_url = (
                pay_url + "&paypal_client_cfci=modxo_vaulted_not_recurring-Pay_With_Card"
            )
            first = self._request(
                "POST",
                pay_with_card_url,
                stage="modxo_pay_with_card",
                accepted_statuses=set(range(200, 300)) | {301, 302, 303, 307, 308},
                files=[
                    ("_1_ctxId", (None, str(self.state.get("ctx_id") or ""))),
                    ("_1_formName", (None, "createAccountAction")),
                    ("0", (None, '["$K1"]')),
                ],
                headers={
                    "Accept": "text/x-component",
                    "Origin": PAYPAL_ORIGIN,
                    "Referer": pay_url,
                    "Next-Action": show_action,
                },
            )
            self._follow_modxo_action_redirect(first, pay_url)

            continue_url = (
                pay_url + "&paypal_client_cfci=modxo_vaulted_not_recurring-Continue_To_Payment"
            )
            result = self._request(
                "POST",
                continue_url,
                stage="modxo_continue_to_payment",
                accepted_statuses=set(range(200, 300)) | {301, 302, 303, 307, 308},
                files=[
                    ("_1_ctxId", (None, str(self.state.get("ctx_id") or ""))),
                    ("_1_token", (None, token)),
                    ("_1_login_email", (None, str(self.profile["user"]["email"]))),
                    ("_1_formName", (None, "createAccount")),
                    ("0", (None, f'["$K1",{{"emailSubmitTime":{int(time.time() * 1000)}}}]')),
                ],
                headers={
                    "Accept": "text/x-component",
                    "Origin": PAYPAL_ORIGIN,
                    "Referer": pay_with_card_url,
                    "Next-Action": create_action,
                },
            )
            direct_ec = self._extract_ec(str(getattr(result, "url", "") or "")) or self._extract_ec(
                str(getattr(result, "text", "") or "")
            )
            if direct_ec:
                self.state["ec_token"] = direct_ec
                return result
            onboarding_url = self._extract_onboarding_redirect(
                str(getattr(result, "text", "") or "")
            )
            if not onboarding_url:
                return None
            target = self._paypal_redirect_url(str(getattr(result, "url", "") or pay_url), onboarding_url)
            response = self._request(
                "GET",
                target,
                stage="modxo_onboarding",
                accepted_statuses=set(range(200, 300)) | {301, 302, 303, 307, 308},
                headers=self._navigation_headers(referer=pay_url),
            )
            return self._follow_paypal_response(
                response,
                stage="modxo_onboarding_redirect",
                referer=pay_url,
            )
        except PayPalPaymentError as exc:
            self._emit_trace(
                status="fallback",
                stage="modxo_server_action",
                message=f"PayPal Next Action 回退失败，继续 compact route：{exc.code}",
            )
            return None

    def _extract_signup_content_identifier(self, html: str) -> tuple[str, str]:
        source = str(html or "")
        decoded = unquote(source)
        for candidate in (source, decoded):
            for pattern in (
                r'"contentIdentifier"\s*:\s*"([^"]*signupTerms[^"]*)"',
                r'\\"contentIdentifier\\"\s*:\s*\\"([^"\\]*signupTerms[^"\\]*)\\"',
                r'([A-Z]{2}:[a-z]{2}:[0-9a-f]{16,64}:compliance\.signupTerms)',
            ):
                match = re.search(pattern, candidate, re.I)
                if match:
                    return match.group(1).replace("\\/", "/"), "page"
        for candidate in (source, decoded):
            for pattern in (
                r'"contentHash"\s*:\s*"([^"]+)"',
                r'\\"contentHash\\"\s*:\s*\\"([^"\\]+)\\"',
            ):
                match = re.search(pattern, candidate, re.I)
                if match:
                    return (
                        f"{self.country}:{self.country_profile['lang']}:"
                        f"{match.group(1)}:compliance.signupTerms",
                        "content_hash",
                    )
        return (
            f"{self.country}:{self.country_profile['lang']}:compliance.signupTerms",
            "fallback",
        )

    def _initial_load(self) -> tuple[Any, str]:
        token = str(self.state["ba_token"])
        approve_url = f"{PAYPAL_ORIGIN}/agreements/approve?{urlencode({'ba_token': token})}"
        response = self._request(
            "GET",
            approve_url,
            stage="agreement_load",
            accepted_statuses=set(range(200, 300)) | {301, 302, 303, 307, 308, 403},
            headers=self._navigation_headers(),
        )
        if int(getattr(response, "status_code", 0) or 0) == 403:
            fallback_url = approve_url + "&YWRzZGRjYXB0Y2hh=1"
            response = self._request(
                "POST",
                fallback_url,
                stage="datadome_fallback",
                accepted_statuses=set(range(200, 300)) | {301, 302, 303, 307, 308, 403},
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": PAYPAL_ORIGIN,
                },
                data={"adsddtoken": ""},
            )
            if int(getattr(response, "status_code", 0) or 0) == 403:
                raise PayPalPaymentError(
                    "PAYPAL_CHALLENGE_REQUIRED",
                    stage="agreement_challenge",
                    retryable=True,
                )
        # The reference flow keeps a 403 returned by the fallback redirect and
        # lets guest onboarding fall through to the compact create-account
        # route. Treating this response as a terminal redirect error prevents
        # that protocol fallback from ever running.
        response = self._follow_paypal_response(
            response,
            stage="agreement_redirect",
            terminal_statuses={403},
        )
        html = str(getattr(response, "text", "") or "")
        response_url = str(getattr(response, "url", "") or approve_url)
        ssrt = re.search(r"[?&]ssrt=(\d+)", response_url) or re.search(r"ssrt=(\d+)", html)
        ctx_id = re.search(r'"ctxId"[^\"]*"([^\"]+)"', html)
        self.state["ssrt"] = ssrt.group(1) if ssrt else ""
        self.state["ctx_id"] = ctx_id.group(1) if ctx_id else ""
        self.state["ec_token"] = self._extract_ec(response_url) or self._extract_ec(html)
        onboard_match = re.search(
            r'onboardingLink"\s*:\s*"([^\"]*?/agreements/approve\?[^\"]+)',
            html,
            re.I,
        ) or re.search(r'href=["\']([^"\']*?ulOnboardRedirect=true[^"\']*)["\']', html, re.I)
        if onboard_match:
            onboarding_url = onboard_match.group(1).replace("\\u0026", "&").replace("&amp;", "&").replace("\\/", "/")
            onboarding_url = self._paypal_redirect_url(response_url, onboarding_url)
        else:
            params = {
                "ul": "1",
                "modxo_redirect_reason": "guest_user",
                "ulOnboardRedirect": "true",
                "ba_token": token,
                "locale.x": str(self.country_profile["locale"]),
                "country.x": self.country,
            }
            if self.state["ssrt"]:
                params["ssrt"] = str(self.state["ssrt"])
            onboarding_url = f"{PAYPAL_ORIGIN}/agreements/approve?{urlencode(params)}"
        return response, onboarding_url

    def _load_checkout(self, initial_response: Any, onboarding_url: str) -> None:
        response = initial_response
        if not self.state.get("ec_token"):
            response = self._request(
                "GET",
                onboarding_url,
                stage="guest_onboarding",
                accepted_statuses=set(range(200, 300)) | {301, 302, 303, 307, 308, 403},
                headers=self._navigation_headers(referer=str(getattr(initial_response, "url", "") or PAYPAL_ORIGIN)),
            )
            response = self._follow_paypal_response(
                response,
                stage="guest_onboarding_redirect",
                terminal_statuses={403},
            )
            if int(getattr(response, "status_code", 0) or 0) == 403:
                self._emit_trace(
                    status="fallback",
                    stage="guest_onboarding",
                    message=(
                        "PayPal guest onboarding 仍返回 challenge；"
                        "按参考流程切换 compact create-account route"
                    ),
                    http_status=403,
                )
            else:
                self.state["ec_token"] = (
                    self._extract_ec(str(getattr(response, "url", "") or ""))
                    or self._extract_ec(str(getattr(response, "text", "") or ""))
                )

        if not self.state.get("ec_token"):
            action_response = self._try_modxo_server_actions(initial_response)
            if action_response is not None:
                response = action_response
                self.state["ec_token"] = (
                    str(self.state.get("ec_token") or "")
                    or self._extract_ec(str(getattr(response, "url", "") or ""))
                    or self._extract_ec(str(getattr(response, "text", "") or ""))
                )

        if not self.state.get("ec_token"):
            token = str(self.state["ba_token"])
            compact_url = (
                f"{PAYPAL_ORIGIN}/pay?ssrt={quote(str(self.state.get('ssrt') or ''))}"
                f"&token={quote(token)}&ul=1"
                "&paypal_client_cfci=modxo_vaulted_not_recurring-Pay_With_Card"
            )
            response = self._request(
                "POST",
                compact_url,
                stage="create_checkout",
                mutation=True,
                accepted_statuses=set(range(200, 300)) | {301, 302, 303, 307, 308},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": PAYPAL_ORIGIN,
                    "Referer": f"{PAYPAL_ORIGIN}/pay?token={quote(token)}&ul=1",
                },
                data={
                    "ctxId": str(self.state.get("ctx_id") or ""),
                    "formName": "createAccountAction",
                    "fn_sync_data": self._build_fn_sync_data(token),
                },
            )
            response = self._follow_paypal_response(response, stage="create_checkout_redirect")
            self.state["ec_token"] = self._extract_ec(str(getattr(response, "url", "") or "")) or self._extract_ec(str(getattr(response, "text", "") or ""))

        ec_token = str(self.state.get("ec_token") or "")
        if not ec_token.startswith("EC-"):
            raise PayPalPaymentError("EC_TOKEN_MISSING", stage="create_checkout")
        params = {
            "ul": "1",
            "modxo_redirect_reason": "guest_user",
            "locale.x": str(self.country_profile["locale"]),
            "country.x": self.country,
            "ba_token": str(self.state["ba_token"]),
            "token": ec_token,
            "rcache": "1",
            "cookieBannerVariant": "hidden",
        }
        if self.state.get("ssrt"):
            params["ssrt"] = str(self.state["ssrt"])
        signup_url = f"{PAYPAL_ORIGIN}/checkoutweb/signup?{urlencode(params)}"
        signup_response = self._request(
            "GET",
            signup_url,
            stage="signup_context",
            headers=self._navigation_headers(referer=str(getattr(response, "url", "") or PAYPAL_ORIGIN)),
        )
        signup_html = str(getattr(signup_response, "text", "") or "")
        self.state["signup_url"] = signup_url
        content_identifier, content_source = self._extract_signup_content_identifier(signup_html)
        self.state["content_identifier"] = content_identifier
        self.state["content_identifier_source"] = content_source
        self._emit_trace(
            status="diagnostic",
            stage="signup_context",
            message=(
                "PayPal signup 上下文："
                f"ec={'yes' if self.state.get('ec_token') else 'no'} "
                f"ctx={'yes' if self.state.get('ctx_id') else 'no'} "
                f"ssrt={'yes' if self.state.get('ssrt') else 'no'} "
                f"content={content_source}"
            ),
        )

    def _warm_checkout_context(self) -> None:
        token = str(self.state["ec_token"])
        try:
            self._graphql(
                "DeferredFeature",
                DEFERRED_FEATURE_QUERY,
                {
                    "channel": "WEB",
                    "countryCodeAsString": self.country,
                    "integrationType": "XoSignupAuth",
                    "isBaslAsString": "false",
                    "isForcedGuest": "false",
                    "token": token,
                },
                stage="deferred_feature",
            )
        except PayPalPaymentError:
            pass
        checkout_result = self._graphql(
            "CheckoutSessionDataQuery",
            CHECKOUT_SESSION_QUERY,
            {"token": token},
            stage="checkout_context",
        )
        item = self._result_item(checkout_result)
        errors = item.get("errors") or []
        if errors:
            raise PayPalPaymentError(
                _safe_graphql_code(errors, "CHECKOUT_CONTEXT_REJECTED"),
                stage="checkout_context",
            )
        checkout = (item.get("data") or {}).get("checkoutSession") or {}
        if not isinstance(checkout, Mapping):
            raise PayPalPaymentError("CHECKOUT_CONTEXT_MISSING", stage="checkout_context")
        if self.context["buyer_mode"] == "identity_elevation" and checkout.get("checkoutSessionType") != "BILLING_WITHOUT_PURCHASE":
            raise PayPalPaymentError("CHECKOUT_TYPE_MISMATCH", stage="checkout_context")
        total = (((checkout.get("cart") or {}).get("amounts") or {}).get("total") or {})
        self.state["checkout_currency"] = str(total.get("currencyCode") or "")
        self.state["checkout_amount"] = str(total.get("currencyValue") or "")

        # Griffin metadata is a read-only page warm-up. PayPal does not expose
        # this query for every locale/checkout bucket, so a 4xx here must not
        # prevent the later OTP and signup operations from using their own
        # server-side validation.
        try:
            self._graphql(
                "GriffinMetadataQuery",
                GRIFFIN_METADATA_QUERY,
                {
                    "countryCode": self.country,
                    "languageCode": str(self.country_profile["lang"]),
                    "shippingCountryCode": self.country,
                },
                stage="locale_metadata",
            )
        except PayPalPaymentError as exc:
            self._emit_trace(
                status="warning",
                stage="locale_metadata",
                message=f"PayPal locale metadata 预热失败，继续支付流程：{exc.code}",
                http_status=exc.http_status,
            )
        try:
            self._graphql(
                "SupportedFundingSourcesQuery",
                SUPPORTED_FUNDING_SOURCES_QUERY,
                {"token": token, "userCountry": self.country},
                stage="supported_funding_sources",
            )
        except PayPalPaymentError:
            pass
        self._normalize_profile_address()
        if self.context["buyer_mode"] == "identity_elevation":
            identity_result = self._graphql(
                "CheckoutSessionDataQuery",
                CHECKOUT_SESSION_QUERY,
                {"token": token},
                stage="identity_checkout_context",
            )
            identity_item = self._result_item(identity_result)
            identity_errors = identity_item.get("errors") or []
            if identity_errors:
                raise PayPalPaymentError(
                    _safe_graphql_code(identity_errors, "IDENTITY_ELEVATION_CONTEXT_REJECTED"),
                    stage="identity_checkout_context",
                )
            identity_checkout = (identity_item.get("data") or {}).get("checkoutSession") or {}
            if not isinstance(identity_checkout, Mapping):
                raise PayPalPaymentError(
                    "IDENTITY_ELEVATION_CONTEXT_MISSING",
                    stage="identity_checkout_context",
                )
            if identity_checkout.get("checkoutSessionType") != "BILLING_WITHOUT_PURCHASE":
                raise PayPalPaymentError(
                    "IDENTITY_ELEVATION_CONTEXT_TYPE_MISMATCH",
                    stage="identity_checkout_context",
                )
            self.state["signup_context_ready"] = True

    def _normalize_profile_address(
        self,
        *,
        stage: str = "address_normalization",
    ) -> None:
        token = str(self.state["ec_token"])
        address = self.profile["address"]
        if str(address.get("postal_code") or ""):
            try:
                normalized_result = self._graphql(
                    "AddressAutocompleteFromPostalCodeQuery",
                    ADDRESS_NORMALIZATION_QUERY,
                    {
                        "country": self.country,
                        "postalCode": str(address["postal_code"]),
                        "token": token,
                    },
                    stage=stage,
                )
                normalized = (self._result_item(normalized_result).get("data") or {}).get("addressNormalization") or {}
                if isinstance(normalized, Mapping) and normalized:
                    address["normalized"] = {
                        "line1": str(normalized.get("line1") or ""),
                        "line2": str(normalized.get("line2") or ""),
                        "city": str(normalized.get("city") or address["city"]),
                        "state": str(normalized.get("state") or address["state"]),
                        "postal_code": str(normalized.get("postalCode") or address["postal_code"]),
                    }
            except PayPalPaymentError:
                pass

    def _rotate_gb_signup_profile(self, *, next_attempt: int) -> None:
        verified_phone = dict(self.profile["user"]["phone"])
        self.profile = _generate_profile(self.country, verified_phone)
        self.context["profile"] = self.profile
        self._emit_trace(
            status="retry",
            stage="signup",
            message=(
                "PayPal createMemberAccount 返回 OAS_ERROR；保留已验证手机号和当前 Session，"
                f"轮换姓名、邮箱、地址与卡片，准备 profile {next_attempt}/{self.max_card_attempts}"
            ),
            failure_code="OAS_ERROR",
            checkpoint="createMemberAccount",
            profile_attempt=next_attempt,
        )
        signup_url = str(self.state.get("signup_url") or PAYPAL_ORIGIN)
        self._send_tealeaf(signup_url, stage="signup_retry_tealeaf")
        self._send_onboarding_retry_signals(stage_prefix="signup_retry_risk")
        self._normalize_profile_address(stage="signup_retry_address")

    def _initiate_otp(self) -> None:
        phone = self.profile["user"]["phone"]
        self._send_weasley_events(
            (
                "weasley_risk_based_phone_confirmation_modal_component_mounted",
                "weasley_initiate_phone_confirmation_start",
                "weasley_api_request_initiate_risk_based_two_factor_phone_confirmation_mutation",
            ),
            stage="otp_initiate_observability",
        )
        result = self._graphql(
            "InitiateRiskBasedTwoFactorPhoneConfirmationMutation",
            INITIATE_OTP_MUTATION,
            {
                "phoneNumber": str(phone["local"]),
                "locale": {"country": self.country, "lang": str(self.country_profile["lang"])},
                "phoneCountry": self.country,
                "token": str(self.state["ec_token"]),
            },
            stage="otp_initiate",
            mutation=True,
        )
        item = self._result_item(result)
        errors = item.get("errors") or []
        data_root = item.get("data")
        data_root = data_root if isinstance(data_root, Mapping) else {}
        data = data_root.get("initiateRiskBasedTwoFactorPhoneConfirmation") or {}
        data = data if isinstance(data, Mapping) else {}
        state = str(data.get("state") or "").strip().upper()
        auth_id = str(data.get("authId") or "")
        challenge_id = str(data.get("challengeId") or "")
        if errors:
            code = _safe_graphql_code(
                errors,
                state if state in _SAFE_OTP_STATES else "OTP_INITIATE_REJECTED",
            )
            self._emit_trace(
                status="warning",
                stage="otp_initiate",
                message=(
                    "PayPal OTP 初始化被拒绝："
                    f"state={state or 'EMPTY'} code={code} "
                    f"authId={'yes' if auth_id else 'no'} "
                    f"challengeId={'yes' if challenge_id else 'no'}"
                ),
            )
            raise PayPalPaymentError(code, stage="otp_initiate")
        if state not in {"PENDING", "INITIATED"}:
            self._emit_trace(
                status="warning",
                stage="otp_initiate",
                message=(
                    "PayPal OTP 初始化响应异常："
                    f"state={state or 'EMPTY'} "
                    f"authId={'yes' if auth_id else 'no'} "
                    f"challengeId={'yes' if challenge_id else 'no'} "
                    f"rootKeys={','.join(sorted(map(str, item.keys()))) or '-'} "
                    f"dataKeys={','.join(sorted(map(str, data.keys()))) or '-'}"
                ),
            )
            if state in _SAFE_OTP_STATES:
                raise PayPalPaymentError(state, stage="otp_initiate")
            raise PayPalPaymentUncertainError(
                "OTP_INITIATE_RESPONSE_UNCERTAIN",
                stage="otp_initiate",
            )
        if not auth_id or not challenge_id:
            self._emit_trace(
                status="warning",
                stage="otp_initiate",
                message=(
                    "PayPal OTP 初始化缺少挑战标识："
                    f"state={state} authId={'yes' if auth_id else 'no'} "
                    f"challengeId={'yes' if challenge_id else 'no'}"
                ),
            )
            raise PayPalPaymentUncertainError(
                "OTP_CHALLENGE_MISSING",
                stage="otp_initiate",
            )
        self.state["auth_id"] = auth_id
        self.state["challenge_id"] = challenge_id

    def start(self) -> None:
        self._emit_trace(
            status="step", stage="agreement_load",
            message="开始加载 PayPal Billing Agreement",
        )
        initial_response, onboarding_url = self._initial_load()
        self._send_risk_signals()
        self._load_checkout(initial_response, onboarding_url)
        self._send_signup_page_signals()
        self._warm_checkout_context()
        self._send_tealeaf(
            str(self.state.get("signup_url") or PAYPAL_ORIGIN),
            stage="signup_form_tealeaf",
        )
        self._initiate_otp()
        self.checkpoint("waiting_otp")

    def _set_euat_token(self, token: str) -> None:
        value = str(token or "")
        self.state["euat_token"] = value
        cookies = getattr(self.session, "cookies", None)
        jar = getattr(cookies, "jar", None)
        clearer = getattr(jar, "clear", None)
        if callable(clearer) and jar is not None:
            stale: list[tuple[str, str, str]] = []
            try:
                for cookie in jar:
                    if str(getattr(cookie, "name", "") or "") == EUAT_COOKIE_NAME:
                        stale.append((
                            str(getattr(cookie, "domain", "") or ".paypal.com"),
                            str(getattr(cookie, "path", "") or "/"),
                            EUAT_COOKIE_NAME,
                        ))
                for domain, path, name in stale:
                    clearer(domain, path, name)
            except Exception:
                pass
        if not value:
            return
        setter = getattr(cookies, "set", None)
        if not callable(setter):
            return
        try:
            setter(EUAT_COOKIE_NAME, value, domain=".paypal.com", path="/")
        except Exception:
            try:
                setter(EUAT_COOKIE_NAME, value)
            except Exception:
                return

    def _sync_euat_after_navigation(self, fallback: str) -> None:
        refreshed = self._cookie_value(EUAT_COOKIE_NAME)
        self._set_euat_token(refreshed or fallback)

    @staticmethod
    def _error_items(item: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        errors = item.get("errors") or []
        if not isinstance(errors, list):
            return []
        return [error for error in errors if isinstance(error, Mapping)]

    @staticmethod
    def _has_buyer_not_set(result: Any) -> bool:
        item = _LivePayPalProtocol._result_item(result)
        for error in _LivePayPalProtocol._error_items(item):
            if str(error.get("message") or "") == "BUYER_NOT_SET":
                return True
            data = error.get("data")
            if isinstance(data, Mapping) and str(data.get("contingency") or "") == "BUYER_NOT_SET":
                return True
        return False

    def _confirm_otp(self, otp: str) -> bool:
        self.context["otp_attempts"] = int(self.context.get("otp_attempts") or 0) + 1
        self._send_weasley_events(
            (
                "weasley_confirm_phone_confirmation_start",
                "weasley_api_request_confirm_risk_based_two_factor_phone_confirmation_mutation",
            ),
            stage="otp_confirm_observability",
        )
        result = self._graphql(
            "ConfirmRiskBasedTwoFactorPhoneConfirmationMutation",
            CONFIRM_OTP_MUTATION,
            {
                "pin": otp,
                "authId": str(self.state["auth_id"]),
                "challengeId": str(self.state["challenge_id"]),
                "token": str(self.state["ec_token"]),
            },
            stage="otp_confirm",
            mutation=True,
        )
        item = self._result_item(result)
        errors = self._error_items(item)
        data_root = item.get("data")
        data_root = data_root if isinstance(data_root, Mapping) else {}
        data = data_root.get("confirmRiskBasedTwoFactorPhoneConfirmation") or {}
        if not isinstance(data, Mapping):
            data = {}
        state = str(data.get("state") or "")
        if data.get("authId"):
            self.state["auth_id"] = str(data["authId"])
        if data.get("challengeId"):
            self.state["challenge_id"] = str(data["challengeId"])
        if state == "CONFIRMED":
            self.state.pop("last_otp_error", None)
            return True
        if errors or state:
            fallback = state if state in _SAFE_OTP_STATES else "OTP_INVALID"
            self.state["last_otp_error"] = _safe_graphql_code(errors, fallback)
            self.checkpoint("waiting_otp")
            return False
        raise PayPalPaymentUncertainError("OTP_CONFIRM_RESPONSE_UNCERTAIN", stage="otp_confirm")

    @staticmethod
    def _card_issuer_type(number: str) -> str:
        prefix2 = int(number[:2]) if number[:2].isdigit() else 0
        if 51 <= prefix2 <= 55:
            return "MASTER_CARD"
        return "VISA"

    def _signup_variables(self) -> dict[str, Any]:
        user = self.profile["user"]
        card = self.profile["card"]
        address = self.profile["address"]
        normalized = address.get("normalized")
        normalized = normalized if isinstance(normalized, Mapping) else {}
        line1 = str(normalized.get("line1") or "")
        if not line1:
            if self.country == "AE":
                line1 = f"PO Box {address['house_number']}"
            elif self.country in {"GB", "US", "TH", "ID", "PH", "TW", "AU", "CA"}:
                line1 = f"{address['house_number']} {address['street']}"
            elif self.country == "JP":
                line1 = f"{address['street']} {address['house_number']}"
            else:
                line1 = f"{address['street']}, {address['house_number']}"
        quality = {
            "autoCompleteType": "ANS" if normalized else "MANUAL",
            "isUserModified": not bool(normalized),
        }
        billing_address = {
            "postalCode": str(normalized.get("postal_code") or address["postal_code"]),
            "line1": line1,
            "line2": str(normalized.get("line2") or ("" if self.country in {"GB", "US", "JP", "AU", "CA"} else address["line2"])),
            "city": str(normalized.get("city") or address["city"]),
            "state": str(normalized.get("state") or address["state"]),
            "accountQuality": quality,
            "country": self.country,
            "familyName": str(user["last_name"]),
            "givenName": str(user["first_name"]),
        }
        variables: dict[str, Any] = {
            "billingAddress": billing_address,
            "card": {
                "cardNumber": str(card["number"]),
                "expirationDate": str(card["expiry"]),
                "securityCode": str(card["cvv"]),
                "type": self._card_issuer_type(str(card["number"])),
                "productClass": "CREDIT",
            },
            "contentIdentifier": str(self.state.get("content_identifier") or f"{self.country}:{self.country_profile['lang']}:compliance.signupTerms"),
            "country": self.country,
            "crsData": None,
            "dateOfBirth": dict(user["dob"]),
            "email": str(user["email"]),
            "firstName": str(user["first_name"]),
            "identityDocument": dict(user["identity"]) if user.get("identity") else None,
            "lastName": str(user["last_name"]),
            "legalAgreements": {},
            "marketingOptOut": False,
            "password": str(user["password"]),
            "phone": {
                "countryCode": str(user["phone"]["country_code"]),
                "number": str(user["phone"]["local"]),
                "type": "MOBILE",
            },
            "supportedThreeDsExperiences": ["IFRAME"],
            "token": str(self.state["ec_token"]),
            "shippingAddress": {
                "postalCode": "",
                "line1": "",
                "city": "",
                "state": "",
                "accountQuality": {
                    "autoCompleteType": "MANUAL",
                    "isUserModified": False,
                },
                "country": self.country,
                "familyName": str(user["last_name"]),
                "givenName": str(user["first_name"]),
            },
        }
        if self.country in {"ID", "PH", "TW", "AE", "TH"}:
            variables["nationality"] = self.country
        if self.country == "CA":
            variables["occupation"] = "BUSINESS"
        if self.country in {"GB", "US", "JP", "TH", "ID", "PH", "TW", "AE", "AU", "CA"}:
            variables["residentialAddress"] = {
                **billing_address,
                "accountQuality": dict(quality),
            }
        return variables

    @staticmethod
    def _is_pre_account_card_error(errors: list[Mapping[str, Any]]) -> bool:
        allowed = {
            "CARD_GENERIC_ERROR",
            "CC_LINKED_TO_FULL_ACCOUNT",
            "CREATE_CARD_ACCOUNT_CANDIDATE_VALIDATION_ERROR",
        }
        for error in errors:
            checkpoints = {str(value) for value in (error.get("checkpoints") or [])}
            message = str(error.get("message") or error.get("_name") or "")
            if "validate.fi" in checkpoints and message in allowed:
                return True
        return False

    @staticmethod
    def _has_post_account_card_error(errors: list[Mapping[str, Any]]) -> bool:
        for error in errors:
            checkpoints = {str(value) for value in (error.get("checkpoints") or [])}
            if checkpoints.intersection({"addCard", "card", "fi"}):
                return True
        return False

    @staticmethod
    def _is_create_member_oas_error(errors: list[Mapping[str, Any]]) -> bool:
        return any(
            str(error.get("message") or error.get("_name") or "").upper() == "OAS_ERROR"
            and "createMemberAccount" in {
                str(checkpoint) for checkpoint in (error.get("checkpoints") or [])
            }
            for error in errors
            if isinstance(error, Mapping)
        )

    def _emit_oas_diagnostic(self, *, attempt: int) -> None:
        cookie_names: list[str] = []
        try:
            jar = getattr(getattr(self.session, "cookies", None), "jar", None)
            cookie_names = sorted({
                str(getattr(cookie, "name", "") or "")
                for cookie in (jar or [])
                if getattr(cookie, "name", "")
            })
        except Exception:
            cookie_names = []
        address = self.profile.get("address") or {}
        debug_id = str(self.last_graphql_meta.get("paypal_debug_id") or "missing")
        response_bytes = int(self.last_graphql_meta.get("response_bytes") or 0)
        visible_cookie_names = ",".join(cookie_names[:12]) or "none"
        if len(cookie_names) > 12:
            visible_cookie_names += f",+{len(cookie_names) - 12}"
        self._emit_trace(
            status="diagnostic",
            stage="signup",
            message=(
                f"OAS 诊断：profile={attempt}/{self.max_card_attempts} "
                f"transport={self.transport_engine} metadata=ec "
                f"ctx={'yes' if self.state.get('ctx_id') else 'no'} "
                f"ssrt={'yes' if self.state.get('ssrt') else 'no'} "
                f"content={self.state.get('content_identifier_source') or 'unknown'} "
                f"address={'normalized' if address.get('normalized') else 'manual'} "
                f"cookies={len(cookie_names)}[{visible_cookie_names}] "
                f"debug_id={debug_id} bytes={response_bytes}"
            ),
        )

    def _signup_member(self) -> dict[str, Any]:
        for attempt in range(1, self.max_card_attempts + 1):
            card = self.profile["card"]
            try:
                self._graphql(
                    "InstallmentOptionsQuery",
                    INSTALLMENT_OPTIONS_QUERY,
                    {
                        "buyerCountry": self.country,
                        "cardNumber": str(card["number"]),
                        "cardType": self._card_issuer_type(str(card["number"])),
                        "token": str(self.state["ec_token"]),
                    },
                    stage="signup_installments",
                )
            except PayPalPaymentError:
                pass
            self._send_signup_signals()
            result = self._graphql(
                "SignUpNewMemberMutation",
                SIGNUP_MUTATION,
                self._signup_variables(),
                stage="signup",
                mutation=True,
                extra_body={
                    "fn_sync_data": self._build_fn_sync_data(str(self.state["ec_token"]), signup=True)
                },
            )
            item = self._result_item(result)
            errors = self._error_items(item)
            data = item.get("data") or {}
            onboard = data.get("onboardAccount") if isinstance(data, Mapping) else None
            onboard = onboard if isinstance(onboard, Mapping) else {}
            access_token = self._find_value([onboard, errors], "accessToken")
            user_id = self._find_value([onboard, errors], "userId")

            if errors:
                error_codes = sorted({
                    str(error.get("message") or error.get("_name") or "UNKNOWN")[:80]
                    for error in errors
                })
                error_checkpoints = sorted({
                    str(checkpoint)[:80]
                    for error in errors
                    for checkpoint in (error.get("checkpoints") or [])
                    if str(checkpoint)
                })
                self._emit_trace(
                    status="warning",
                    stage="signup",
                    message=(
                        f"PayPal signup 返回业务错误：attempt={attempt}/{self.max_card_attempts} "
                        f"codes={','.join(error_codes) or '-'} "
                        f"checkpoints={','.join(error_checkpoints) or '-'} "
                        f"accessToken={'yes' if access_token else 'no'}"
                    ),
                )

            if onboard:
                if not access_token:
                    payment_contingencies = onboard.get("paymentContingencies")
                    if isinstance(payment_contingencies, Mapping) and payment_contingencies:
                        self.state["signup_verification"] = {"type": "funding_instrument"}
                        raise PayPalPaymentUncertainError(
                            "FUNDING_INSTRUMENT_VERIFICATION_REQUIRED",
                            stage="signup",
                        )
                    raise PayPalPaymentUncertainError(
                        "SIGNUP_ACCESS_TOKEN_MISSING",
                        stage="signup",
                    )
                self._set_euat_token(access_token)
                if user_id:
                    self.state["user_id"] = user_id
                self.checkpoint("member_created")
                return {"member_created": True, "funding_contingency": False}

            if access_token:
                self._set_euat_token(access_token)
                if user_id:
                    self.state["user_id"] = user_id
                checkpoints = sorted({
                    str(checkpoint)
                    for error in errors
                    for checkpoint in (error.get("checkpoints") or [])
                    if str(checkpoint)
                })
                self._emit_trace(
                    status="checkpoint",
                    stage="member_created",
                    message=(
                        "PayPal 会员账号已创建；资金工具步骤失败但已返回访问令牌，"
                        "跳过再次 signup 并继续授权"
                    ),
                    funding_contingency=True,
                    checkpoints=checkpoints,
                )
                self.checkpoint("member_created")
                return {"member_created": True, "funding_contingency": bool(errors)}

            messages = {str(error.get("message") or "") for error in errors}
            if "FI_CONFIRMATION_CONTINGENCY" in messages:
                self.state["signup_verification"] = {"type": "funding_instrument"}
                raise PayPalPaymentUncertainError(
                    "FUNDING_INSTRUMENT_VERIFICATION_REQUIRED",
                    stage="signup",
                )
            if "ACCOUNT_ALREADY_EXISTS" in messages:
                raise PayPalPaymentUncertainError(
                    "SIGNUP_ACCOUNT_STATE_UNCERTAIN",
                    stage="signup",
                )
            if self._is_pre_account_card_error(errors):
                if attempt < self.max_card_attempts:
                    self._emit_trace(
                        status="retry",
                        stage="signup",
                        message=(
                            "PayPal 在 createMemberAccount 前拒绝当前卡片；"
                            f"保留已验证手机号并更换卡片，准备 signup {attempt + 1}/{self.max_card_attempts}"
                        ),
                    )
                    self.profile["card"] = _generate_card()
                    continue
                raise PayPalPaymentError(
                    "CARD_VALIDATION_REJECTED",
                    stage="signup",
                    retryable=False,
                )
            if self._has_post_account_card_error(errors):
                raise PayPalPaymentUncertainError(
                    "SIGNUP_ACCOUNT_STATE_UNCERTAIN",
                    stage="signup",
                )
            if self._is_create_member_oas_error(errors):
                self._emit_oas_diagnostic(attempt=attempt)
                if self.country == "GB" and attempt < self.max_card_attempts:
                    self._rotate_gb_signup_profile(next_attempt=attempt + 1)
                    continue
                self._emit_trace(
                    status="warning",
                    stage="signup",
                    message=(
                        "PayPal createMemberAccount 返回 OAS_ERROR；"
                        "当前号码下的 profile 重试已耗尽，交由服务层换号"
                    ),
                    failure_code="OAS_ERROR",
                    checkpoint="createMemberAccount",
                )
                raise PayPalPaymentError("OAS_ERROR", stage="signup")
            if errors:
                raise PayPalPaymentError(
                    _safe_graphql_code(errors, "SIGNUP_REJECTED"),
                    stage="signup",
                )
            raise PayPalPaymentUncertainError("SIGNUP_RESPONSE_UNCERTAIN", stage="signup")
        raise PayPalPaymentError("CARD_VALIDATION_REJECTED", stage="signup")

    def _review_urls(self) -> dict[str, str]:
        params = {
            "ul": "1",
            "modxo_redirect_reason": "guest_user",
            "locale.x": str(self.country_profile["locale"]),
            "country.x": self.country,
            "ba_token": str(self.state["ba_token"]),
            "token": str(self.state["ec_token"]),
            "rcache": "1",
            "cookieBannerVariant": "hidden",
            "fromSignupLite": "true",
            "fallback": "1",
            "reason": "Q0FSRF9HRU5FUklDX0VSUk9S",
        }
        if self.state.get("ssrt"):
            params["ssrt"] = str(self.state["ssrt"])
        base = f"{PAYPAL_ORIGIN}/webapps/hermes?{urlencode(params)}"
        contingency_params = {
            **params,
            "addFIContingency": "noretry",
            "redirectToHermes": "true",
        }
        contingency = f"{PAYPAL_ORIGIN}/webapps/hermes?{urlencode(contingency_params)}"
        referer = base + "&billingLite=1"
        return {
            "base": base,
            "contingency": contingency,
            "referer": referer,
            "review": referer + "#/billingweb/review",
        }

    def _identity_elevation_review_url(self) -> str:
        params = {
            "ul": "1",
            "modxo_redirect_reason": "guest_user",
            "locale.x": str(self.country_profile["locale"]),
            "country.x": self.country,
            "ba_token": str(self.state["ba_token"]),
            "token": str(self.state["ec_token"]),
            "rcache": "1",
            "cookieBannerVariant": "hidden",
            "fromSignupLite": "true",
            "billingLite": "1",
        }
        if self.state.get("ssrt"):
            params["ssrt"] = str(self.state["ssrt"])
        return f"{PAYPAL_ORIGIN}/webapps/hermes?{urlencode(params)}"

    def _load_review_context(self, url: str, referer: str) -> Any:
        response = self._request(
            "GET",
            url,
            stage="review_context",
            accepted_statuses=set(range(200, 300)) | {301, 302, 303, 307, 308},
            headers=self._navigation_headers(referer=referer),
        )
        return self._follow_paypal_response(
            response,
            stage="review_context_redirect",
            referer=referer,
        )

    @staticmethod
    def _buyer_from_result(result: Any) -> dict[str, Any]:
        item = _LivePayPalProtocol._result_item(result)
        data = item.get("data") or {}
        checkout = data.get("checkoutSession") if isinstance(data, Mapping) else None
        buyer = checkout.get("buyer") if isinstance(checkout, Mapping) else None
        return dict(buyer) if isinstance(buyer, Mapping) else {}

    def _query_buyer_context(self, referer: str, *, funding: bool) -> bool:
        operation = "BuyerFundingContextQuery" if funding else "BuyerContextQuery"
        query = BUYER_FUNDING_QUERY if funding else BUYER_CONTEXT_QUERY
        result = self._graphql(
            operation,
            query,
            {"token": str(self.state["ec_token"])},
            stage="buyer_context",
            endpoint=f"{GRAPHQL_URL}/",
            referer=referer,
            app_name="checkoutuinodeweb",
            client_metadata_id=str(self.state["paypal_client_metadata_id"]),
        )
        item = self._result_item(result)
        errors = self._error_items(item)
        fatal_codes = {
            "ACCOUNT_LOCKED",
            "ACCOUNT_RESTRICTED",
            "PAYER_ACCOUNT_RESTRICTED",
            "PAYER_INVALID_FOR_PAYMENT",
            "TRANSACTION_REFUSED",
        }
        fatal = next(
            (
                str(error.get("message") or error.get("name") or "")
                for error in errors
                if str(error.get("message") or error.get("name") or "") in fatal_codes
            ),
            "",
        )
        if fatal:
            raise PayPalPaymentError(fatal, stage="buyer_context")
        buyer = self._buyer_from_result(result)
        if funding and not str(buyer.get("userId") or ""):
            result = self._graphql(
                "BuyerContextQuery",
                BUYER_CONTEXT_QUERY,
                {"token": str(self.state["ec_token"])},
                stage="buyer_context",
                endpoint=f"{GRAPHQL_URL}/",
                referer=referer,
                app_name="checkoutuinodeweb",
                client_metadata_id=str(self.state["paypal_client_metadata_id"]),
            )
            buyer = self._buyer_from_result(result)
        auth = buyer.get("auth")
        auth = auth if isinstance(auth, Mapping) else {}
        refreshed = str(auth.get("accessToken") or "")
        if refreshed:
            self._set_euat_token(refreshed)
        user_id = str(buyer.get("userId") or "")
        if user_id:
            self.state["user_id"] = user_id
        ready = bool(user_id and self.state.get("euat_token"))
        self.state["buyer_ready"] = ready
        return ready

    def _protocol_identity_elevation(self) -> bool:
        token = str(self.state.get("ec_token") or "")
        signup_url = str(self.state.get("signup_url") or "")
        saved_euat = str(self.state.get("euat_token") or "")
        if not token.startswith("EC-"):
            raise PayPalPaymentError(
                "IDENTITY_ELEVATION_EC_MISSING",
                stage="buyer_context",
                replay_safe=False,
            )
        if not signup_url or not self.state.get("content_identifier"):
            raise PayPalPaymentError(
                "IDENTITY_ELEVATION_SIGNUP_CONTEXT_MISSING",
                stage="buyer_context",
                replay_safe=False,
            )
        if not saved_euat:
            raise PayPalPaymentError(
                "IDENTITY_ELEVATION_EUAT_MISSING",
                stage="buyer_context",
                replay_safe=False,
            )

        self._set_euat_token(saved_euat)
        if self.country == "AE":
            self._emit_trace(
                status="step",
                stage="identity_elevation",
                message="AE checkout 在页面导航前执行买家身份 hydration",
            )
            if self._query_buyer_context(signup_url, funding=True):
                self.state["identity_elevated"] = True
                self.state["identity_pre_hydrated"] = True
                return True
            self._set_euat_token(saved_euat)

        self._emit_trace(
            status="step",
            stage="identity_elevation",
            message="携带 PayPal 会员会话重新进入 checkout signup",
        )
        self._request(
            "GET",
            signup_url,
            stage="identity_signup_reentry",
            accepted_statuses=set(range(200, 300)) | {301, 302, 303, 307, 308},
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": signup_url,
                "Upgrade-Insecure-Requests": "1",
            },
        )
        self._sync_euat_after_navigation(saved_euat)

        elevation_review = self._identity_elevation_review_url()
        self._load_review_context(elevation_review, signup_url)
        self._sync_euat_after_navigation(saved_euat)
        if not self._query_buyer_context(elevation_review, funding=True):
            raise PayPalPaymentError(
                "IDENTITY_ELEVATION_FAILED",
                stage="buyer_context",
                replay_safe=False,
            )
        self.state["identity_elevated"] = True
        self.state["identity_review_url"] = elevation_review
        return False

    def _prepare_review_context(self, *, skip_navigation: bool = False) -> dict[str, str]:
        urls = self._review_urls()
        self._set_euat_token(str(self.state.get("euat_token") or ""))
        saved_euat = str(self.state.get("euat_token") or "")
        if not skip_navigation:
            self._load_review_context(urls["contingency"], str(self.state["signup_url"]))
            self._sync_euat_after_navigation(saved_euat)
            self._load_review_context(urls["referer"], urls["contingency"])
            self._sync_euat_after_navigation(saved_euat)
        self._send_tealeaf(urls["review"], stage="review_tealeaf")
        ready = self._query_buyer_context(urls["referer"], funding=False)
        if self.context["buyer_mode"] == "identity_elevation" and not ready:
            raise PayPalPaymentError(
                "IDENTITY_ELEVATION_FAILED",
                stage="buyer_context",
                replay_safe=False,
            )
        self.state["review_url"] = urls["review"]
        return urls

    def _authorize(self) -> dict[str, str]:
        skip_navigation = False
        if self.context["buyer_mode"] == "identity_elevation":
            skip_navigation = self._protocol_identity_elevation()
        urls = self._prepare_review_context(skip_navigation=skip_navigation)
        billing_agreement_id = str(self.state["ec_token"])

        def send_authorize(*, include_context: bool) -> Any:
            return self._graphql(
                "authorize",
                AUTHORIZE_MUTATION,
                {
                    "billingAgreementId": billing_agreement_id,
                    "fundingPreference": {"balancePreference": "OPT_OUT"},
                    "legalAgreements": {},
                },
                stage="authorize",
                mutation=True,
                endpoint=f"{GRAPHQL_URL}/",
                referer=urls["referer"],
                app_name="checkoutuinodeweb",
                batched=True,
                omit_context_headers=not include_context,
                client_metadata_id=str(self.state["paypal_client_metadata_id"]),
            )

        result = send_authorize(include_context=False)
        for retry in range(1, 3):
            if not self._has_buyer_not_set(result):
                break
            urls = self._prepare_review_context(skip_navigation=skip_navigation)
            self.sleep(float(retry))
            result = send_authorize(include_context=True)

        item = self._result_item(result)
        errors = self._error_items(item)
        if self._has_buyer_not_set(result):
            raise PayPalPaymentError("BUYER_NOT_SET", stage="authorize")
        data = item.get("data") or {}
        billing = data.get("billing") if isinstance(data, Mapping) else None
        authorize = billing.get("authorize") if isinstance(billing, Mapping) else None
        if not isinstance(authorize, Mapping):
            raise PayPalPaymentError(
                _safe_graphql_code(errors, "AUTHORIZE_REJECTED"),
                stage="authorize",
            )
        agreement_id = str(authorize.get("billingAgreementToken") or "")
        buyer = authorize.get("buyer")
        buyer = buyer if isinstance(buyer, Mapping) else {}
        reference = str(buyer.get("userId") or self.state.get("user_id") or "")
        return_url = authorize.get("returnURL")
        return_url = return_url if isinstance(return_url, Mapping) else {}
        if not agreement_id:
            raise PayPalPaymentUncertainError("AUTHORIZE_RESPONSE_UNCERTAIN", stage="authorize")
        self.state["agreement_id"] = agreement_id
        self.state["user_id"] = reference
        self.state["return_url"] = str(return_url.get("href") or "")
        self.state["payment_action"] = str(authorize.get("paymentAction") or "")
        self.checkpoint("authorized")
        return {
            "agreement_id": agreement_id,
            "reference": reference,
            "return_url": str(self.state["return_url"]),
            "payment_action": str(self.state["payment_action"]),
            "review_url": urls["review"],
        }

    @staticmethod
    def _merchant_url(current: str, target: str) -> str:
        value = urljoin(current, str(target or ""))
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise PayPalPaymentError("MERCHANT_RETURN_URL_INVALID", stage="merchant_return") from exc
        host = (parsed.hostname or "").lower()
        paypal_host = host == "paypal.com" or host.endswith(".paypal.com")
        if (
            parsed.scheme != "https"
            or (not paypal_host and host not in _MERCHANT_CONFIRMATION_HOSTS)
            or port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise PayPalPaymentError("MERCHANT_RETURN_URL_INVALID", stage="merchant_return")
        return value

    @staticmethod
    def _confirmation_from_url(final_url: str) -> dict[str, Any]:
        redirect_status = ""
        verification_url = ""
        merchant_terminal = False
        if final_url:
            parsed = urlsplit(final_url)
            merchant_terminal = (parsed.hostname or "").lower() in _MERCHANT_CONFIRMATION_HOSTS
            query = parse_qs(parsed.query, keep_blank_values=True)
            redirect_status = str((query.get("redirect_status") or [""])[0]).lower()
            verification_url = str((query.get("success_return_url") or [""])[0])
            if not verification_url and (parsed.hostname or "").lower() == "chatgpt.com" and parsed.path.startswith("/checkout/verify"):
                verification_url = final_url
        if merchant_terminal and redirect_status in {"cancelled", "canceled", "error", "failed", "failure"}:
            status, confirmed = "failed", False
        else:
            status, confirmed = "pending_verification", None
        return {
            "status": status,
            "confirmed": confirmed,
            "redirect_status": redirect_status,
            "final_url": final_url,
            "verification_url": verification_url,
            "source": "merchant_return",
        }

    def _follow_merchant_return(self, return_url: str, review_url: str) -> dict[str, Any]:
        if not return_url:
            return self._confirmation_from_url("")
        try:
            current = self._merchant_url(return_url, return_url)
            referer = review_url
            final_url = current
            for _ in range(9):
                response = self._request(
                    "GET",
                    current,
                    stage="merchant_return",
                    accepted_statuses=set(range(200, 300)) | {301, 302, 303, 307, 308},
                    headers=self._navigation_headers(referer=referer),
                )
                final_url = str(getattr(response, "url", "") or current)
                status = int(getattr(response, "status_code", 0) or 0)
                if status not in {301, 302, 303, 307, 308}:
                    return self._confirmation_from_url(final_url)
                location = str(getattr(response, "headers", {}).get("Location") or "")
                if not location:
                    raise PayPalPaymentError("MERCHANT_REDIRECT_MISSING", stage="merchant_return")
                referer, current = final_url, self._merchant_url(final_url, location)
            raise PayPalPaymentError("MERCHANT_REDIRECT_LIMIT", stage="merchant_return")
        except PayPalPaymentError as exc:
            confirmation = self._confirmation_from_url("")
            confirmation["error"] = exc.as_dict()
            confirmation["replay_safe"] = False
            return confirmation
        except Exception:
            confirmation = self._confirmation_from_url("")
            confirmation["error"] = PayPalPaymentError(
                "MERCHANT_RETURN_UNCERTAIN",
                stage="merchant_return",
                replay_safe=False,
            ).as_dict()
            confirmation["replay_safe"] = False
            return confirmation

    @staticmethod
    def _run_plus_verifier(
        confirmation: dict[str, Any],
        verifier: Callable[[Mapping[str, Any]], Any] | None,
        authorization: Mapping[str, str],
    ) -> dict[str, Any]:
        if verifier is None:
            return confirmation
        payload = {
            "agreement_id": str(authorization.get("agreement_id") or ""),
            "reference": str(authorization.get("reference") or ""),
            "final_url": str(confirmation.get("final_url") or ""),
            "verification_url": str(confirmation.get("verification_url") or ""),
        }
        try:
            result = verifier(payload)
        except Exception:
            return {
                **confirmation,
                "status": "pending_verification",
                "confirmed": None,
                "source": "plus_verifier",
                "error": {
                    "code": "PLUS_VERIFIER_ERROR",
                    "stage": "plus_verification",
                    "retryable": True,
                    "replay_safe": True,
                    "http_status": None,
                },
            }
        try:
            if isinstance(result, bool):
                confirmed = result
                status = "confirmed" if result else "failed"
            elif isinstance(result, Mapping):
                value = result.get("confirmed")
                result_status = str(result.get("status") or "").lower()
                if isinstance(value, bool):
                    confirmed = value
                    status = "confirmed" if value else "failed"
                elif result_status in {"confirmed", "success", "succeeded"}:
                    confirmed, status = True, "confirmed"
                elif result_status in {"failed", "failure", "cancelled", "canceled"}:
                    confirmed, status = False, "failed"
                elif result_status in {"pending", "pending_verification", "processing", "requires_action"}:
                    confirmed, status = None, "pending_verification"
                else:
                    confirmed, status = None, "pending_verification"
            else:
                confirmed, status = None, "pending_verification"
        except Exception:
            confirmed, status = None, "pending_verification"
        return {
            **confirmation,
            "status": status,
            "confirmed": confirmed,
            "source": "plus_verifier",
        }

    def confirm_and_authorize(
        self,
        otp: str,
        *,
        plus_verifier: Callable[[Mapping[str, Any]], Any] | None = None,
    ) -> dict[str, Any]:
        self._emit_trace(
            status="step", stage="otp_confirm",
            message="开始确认 PayPal 短信验证码",
        )
        if not self._confirm_otp(otp):
            return {"otp_confirmed": False}
        self.checkpoint("otp_confirmed")
        self._emit_trace(
            status="step", stage="signup",
            message="验证码通过，开始创建/提升 PayPal 买家身份",
        )
        self._signup_member()
        try:
            self._send_analytics(
                "main:billing:hagrid:billingwithoutpurchase:member:review",
                stage="analytics_member_review",
            )
            self._emit_trace(
                status="step", stage="authorize",
                message="买家身份准备完成，开始授权 Billing Agreement",
            )
            authorization = self._authorize()
            confirmation = self._follow_merchant_return(
                authorization["return_url"],
                authorization["review_url"],
            )
            self._send_analytics(
                "main:billing:hagrid:billingwithoutpurchase:member:submitButtonFullEvent",
                stage="analytics_authorized",
                event="cl",
            )
            confirmation = self._run_plus_verifier(confirmation, plus_verifier, authorization)
            self.state["plus_confirmation"] = {
                "status": str(confirmation["status"]),
                "confirmed": confirmation["confirmed"],
            }
            self.checkpoint("authorized")
            return {
                "otp_confirmed": True,
                **authorization,
                "plus_confirmation": confirmation,
            }
        except PayPalPaymentError as exc:
            if not exc.replay_safe:
                raise
            raise PayPalPaymentError(
                exc.code,
                stage=exc.stage,
                retryable=exc.retryable,
                replay_safe=False,
                http_status=exc.http_status,
            ) from exc
        except Exception as exc:
            raise PayPalPaymentUncertainError(
                "POST_SIGNUP_FLOW_UNCERTAIN",
                stage="post_signup",
            ) from exc


def _json_copy(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(dict(value), allow_nan=False))


def _now_value(now: Callable[[], float] | float | None) -> float:
    try:
        value = time.time() if now is None else (now() if callable(now) else now)
        result = float(value)
    except Exception:
        raise PayPalPaymentInputError("NOW_INVALID", stage="input") from None
    if not math.isfinite(result) or result < 0:
        raise PayPalPaymentInputError("NOW_INVALID", stage="input")
    return result


def _bounded_float(value: object, *, name: str, minimum: float, maximum: float) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise PayPalPaymentInputError(f"{name}_INVALID", stage="input") from None
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise PayPalPaymentInputError(f"{name}_INVALID", stage="input")
    return result


def _card_attempt_count(value: object) -> int:
    if isinstance(value, bool):
        raise PayPalPaymentInputError("MAX_CARD_ATTEMPTS_INVALID", stage="input")
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise PayPalPaymentInputError("MAX_CARD_ATTEMPTS_INVALID", stage="input") from None
    if result != value or not 1 <= result <= 5:
        raise PayPalPaymentInputError("MAX_CARD_ATTEMPTS_INVALID", stage="input")
    return result


def _waiting_result(
    context: Mapping[str, Any],
    *,
    otp_error: str = "",
) -> dict[str, Any]:
    saved = _json_copy(context)
    challenge: dict[str, Any] = {
        "status": "pending",
        "phone_hint": _phone_hint(saved),
        "expires_at": float(saved["expires_at"]),
        "attempts": int(saved.get("otp_attempts") or 0),
    }
    if otp_error:
        safe_code = otp_error if _SAFE_ERROR_CODE_RE.fullmatch(otp_error) else "OTP_INVALID"
        challenge["error_code"] = safe_code
    return {
        "status": "waiting_otp",
        "authorized": False,
        "plus_confirmed": False,
        "plus_confirmation": {"status": "not_started", "confirmed": False},
        "context_id": str(saved["context_id"]),
        "challenge": challenge,
        "context": saved,
        "otp_context": saved,
        "ambiguous": False,
        "retryable": False,
        "replay_safe": True,
    }


def _failed_result(error: PayPalPaymentError, *, context_id: str = "") -> dict[str, Any]:
    return {
        "status": "failed",
        "authorized": False,
        "plus_confirmed": False,
        "plus_confirmation": {"status": "not_started", "confirmed": False},
        "context_id": str(context_id or ""),
        "error": error.as_dict(),
        "error_code": error.code,
        "stage": error.stage,
        "ambiguous": error.ambiguous,
        "retryable": error.retryable,
        "replay_safe": error.replay_safe,
    }


def _pending_result(
    error: PayPalPaymentError,
    *,
    context: Mapping[str, Any],
    authorized: bool | None = None,
) -> dict[str, Any]:
    saved = _json_copy(context)
    return {
        "status": "pending_verification",
        "authorized": authorized,
        "plus_confirmed": None,
        "plus_confirmation": {"status": "pending_verification", "confirmed": None},
        "context_id": str(saved.get("context_id") or ""),
        "error": error.as_dict(),
        "error_code": error.code,
        "stage": error.stage,
        "ambiguous": error.ambiguous,
        "retryable": False,
        "replay_safe": False,
        "context": saved,
        "payment_context": saved,
    }


def _authorized_result(
    authorization: Mapping[str, Any],
    *,
    context: Mapping[str, Any],
) -> dict[str, Any]:
    saved = _json_copy(context)
    confirmation = authorization.get("plus_confirmation")
    confirmation = dict(confirmation) if isinstance(confirmation, Mapping) else {
        "status": "pending_verification",
        "confirmed": None,
    }
    return {
        "status": "authorized",
        "authorized": True,
        "agreement_id": str(authorization.get("agreement_id") or ""),
        "reference": str(authorization.get("reference") or ""),
        "payment_action": str(authorization.get("payment_action") or ""),
        "plus_confirmed": confirmation.get("confirmed") if isinstance(confirmation.get("confirmed"), bool) else None,
        "plus_confirmation": confirmation,
        "context_id": str(saved["context_id"]),
        "context": saved,
        "payment_context": saved,
        "ambiguous": False,
        "retryable": False,
        "replay_safe": False,
    }


def start_paypal_payment(
    *,
    ba_url: str = "",
    ba_token: str = "",
    phone: str,
    country: str,
    buyer_mode: str,
    proxy: str,
    timeout: float = DEFAULT_TIMEOUT,
    context_ttl: float = DEFAULT_CONTEXT_TTL,
    session_factory: Callable[..., Any] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] | float | None = None,
    trace: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Start a fixed-proxy PayPal agreement flow and send its SMS challenge."""

    token = _extract_ba_token(ba_url=ba_url, ba_token=ba_token)
    normalized_country = str(country or "").strip().upper()
    if normalized_country not in _COUNTRIES:
        raise PayPalPaymentInputError("COUNTRY_UNSUPPORTED", stage="input")
    normalized_mode = str(buyer_mode or "").strip().lower()
    if normalized_mode not in {"original", "identity_elevation"}:
        raise PayPalPaymentInputError("BUYER_MODE_INVALID", stage="input")
    normalized_proxy = _normalize_proxy(proxy)
    declared_country = _declared_proxy_country(normalized_proxy)
    if declared_country and declared_country != normalized_country:
        raise PayPalPaymentInputError("PROXY_COUNTRY_MISMATCH", stage="input")
    normalized_phone = _normalize_phone(phone, normalized_country)
    request_timeout = _bounded_float(timeout, name="TIMEOUT", minimum=1.0, maximum=300.0)
    ttl = _bounded_float(context_ttl, name="CONTEXT_TTL", minimum=1.0, maximum=86400.0)
    if session_factory is not None and not callable(session_factory):
        raise PayPalPaymentInputError("SESSION_FACTORY_INVALID", stage="input")
    if trace is not None and not callable(trace):
        raise PayPalPaymentInputError("TRACE_INVALID", stage="input")
    if not callable(sleep):
        raise PayPalPaymentInputError("SLEEP_INVALID", stage="input")
    current_time = _now_value(now)
    context = _new_context(
        ba_token=token,
        phone=normalized_phone,
        country=normalized_country,
        buyer_mode=normalized_mode,
        proxy_fingerprint=_proxy_fingerprint(normalized_proxy),
        now=current_time,
        ttl=ttl,
    )
    protocol: _LivePayPalProtocol | None = None
    try:
        protocol = _LivePayPalProtocol(
            proxy=normalized_proxy,
            timeout=request_timeout,
            context=context,
            session_factory=session_factory,
            trace=trace,
            sleep=sleep,
        )
        protocol.start()
        return _waiting_result(context)
    except PayPalPaymentError as exc:
        _emit_trace_callback(trace, {
            "status": "failed", "stage": exc.stage,
            "message": f"PayPal 授权初始化失败：{exc.code}",
            "http_status": exc.http_status,
        })
        if not exc.replay_safe:
            if protocol is not None:
                protocol.checkpoint("pending_verification")
            else:
                context["phase"] = "pending_verification"
            return _pending_result(exc, context=context)
        return _failed_result(exc, context_id=str(context["context_id"]))
    except Exception:
        _emit_trace_callback(trace, {
            "status": "failed", "stage": "internal",
            "message": "PayPal 授权初始化异常：INTERNAL_ERROR",
        })
        return _failed_result(
            PayPalPaymentError("INTERNAL_ERROR", stage="internal"),
            context_id=str(context["context_id"]),
        )
    finally:
        if protocol is not None:
            protocol.close()


def submit_paypal_otp(
    *,
    context: Mapping[str, Any],
    otp: str,
    proxy: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_card_attempts: int = DEFAULT_MAX_CARD_ATTEMPTS,
    session_factory: Callable[..., Any] | None = None,
    plus_verifier: Callable[[Mapping[str, Any]], Any] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] | float | None = None,
    trace: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Resume a persisted SMS challenge, then sign up and authorize once."""

    normalized_proxy = _normalize_proxy(proxy)
    if not isinstance(context, Mapping):
        raise PayPalPaymentInputError("CONTEXT_INVALID", stage="input")
    otp_value = str(otp or "")
    if not _OTP_RE.fullmatch(otp_value):
        raise PayPalPaymentInputError("OTP_INVALID", stage="input")
    request_timeout = _bounded_float(timeout, name="TIMEOUT", minimum=1.0, maximum=300.0)
    attempts = _card_attempt_count(max_card_attempts)
    if session_factory is not None and not callable(session_factory):
        raise PayPalPaymentInputError("SESSION_FACTORY_INVALID", stage="input")
    if plus_verifier is not None and not callable(plus_verifier):
        raise PayPalPaymentInputError("PLUS_VERIFIER_INVALID", stage="input")
    if trace is not None and not callable(trace):
        raise PayPalPaymentInputError("TRACE_INVALID", stage="input")
    if not callable(sleep):
        raise PayPalPaymentInputError("SLEEP_INVALID", stage="input")
    saved = _validate_context(context, proxy=normalized_proxy, now=_now_value(now))
    protocol: _LivePayPalProtocol | None = None
    try:
        protocol = _LivePayPalProtocol(
            proxy=normalized_proxy,
            timeout=request_timeout,
            context=saved,
            max_card_attempts=attempts,
            session_factory=session_factory,
            trace=trace,
            sleep=sleep,
        )
        authorization = protocol.confirm_and_authorize(
            otp_value,
            plus_verifier=plus_verifier,
        )
        if not authorization.get("otp_confirmed"):
            return _waiting_result(
                saved,
                otp_error=str(saved["state"].get("last_otp_error") or "OTP_INVALID"),
            )
        return _authorized_result(authorization, context=saved)
    except PayPalPaymentError as exc:
        _emit_trace_callback(trace, {
            "status": "failed", "stage": exc.stage,
            "message": f"PayPal OTP/授权继续失败：{exc.code}",
            "http_status": exc.http_status,
        })
        if not exc.replay_safe:
            if protocol is not None:
                protocol.checkpoint("pending_verification")
            else:
                saved["phase"] = "pending_verification"
            return _pending_result(exc, context=saved)
        return _failed_result(exc, context_id=str(saved["context_id"]))
    except Exception:
        _emit_trace_callback(trace, {
            "status": "failed", "stage": "internal",
            "message": "PayPal OTP/授权继续异常：INTERNAL_ERROR",
        })
        return _failed_result(
            PayPalPaymentError("INTERNAL_ERROR", stage="internal"),
            context_id=str(saved["context_id"]),
        )
    finally:
        if protocol is not None:
            protocol.close()


__all__ = [
    "PayPalPaymentError",
    "PayPalPaymentInputError",
    "PayPalPaymentUncertainError",
    "start_paypal_payment",
    "submit_paypal_otp",
]
