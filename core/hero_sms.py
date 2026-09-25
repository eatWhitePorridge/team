# -*- coding: utf-8 -*-
"""HeroSMS SMS-Activate compatibility client for Codex phone verification."""
from __future__ import annotations

import json
import threading
from typing import Any


class HeroSmsError(RuntimeError):
    pass


class HeroSmsNoNumbers(HeroSmsError):
    pass


class HeroSmsNoBalance(HeroSmsError):
    pass


_STATE_LOCK = threading.Lock()
_ACTIVATIONS: dict[str, dict] = {}


def _clean_number(value: Any) -> str:
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    if not 8 <= len(digits) <= 15:
        raise HeroSmsError(
            f"HeroSMS 返回的手机号不符合 E.164 长度要求：digits={len(digits)}"
        )
    return digits


def _as_cost(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        cost = float(value)
    except (TypeError, ValueError):
        return None
    return cost if cost >= 0 else None


def _redact(value: object, *secrets: object) -> str:
    text = str(value or "")
    for secret in secrets:
        raw = str(secret or "").strip()
        if raw:
            text = text.replace(raw, "***")
    return text[:300]


def _error_code(text: str, data: Any) -> tuple[str, str]:
    if isinstance(data, dict):
        code = str(
            data.get("title")
            or data.get("error")
            or data.get("code")
            or data.get("message")
            or ""
        ).strip()
        details = str(data.get("details") or data.get("message") or "").strip()
        return code.upper(), details
    value = str(data if isinstance(data, str) else text or "").strip()
    return value.split(":", 1)[0].upper(), value


def _raise_api_error(*, status_code: int, text: str, data: Any) -> None:
    code, details = _error_code(text, data)
    detail = f"：{details}" if details and details.upper() != code else ""
    if status_code == 402 or code == "NO_BALANCE":
        raise HeroSmsNoBalance(f"HeroSMS 余额不足（NO_BALANCE）{detail}")
    if code in {"NO_NUMBERS", "NO_NUMBERS_FOR_MAX_PRICE"}:
        raise HeroSmsNoNumbers(f"HeroSMS 暂无符合条件的号码（{code}）{detail}")
    if status_code == 401 or code == "BAD_KEY":
        raise HeroSmsError("HeroSMS API key 无效（BAD_KEY）")
    if status_code != 200:
        label = code or "HTTP_ERROR"
        raise HeroSmsError(f"HeroSMS HTTP {status_code}（{label}）{detail}")
    if code in {
        "BAD_ACTION",
        "BAD_SERVICE",
        "BAD_STATUS",
        "WRONG_SERVICE",
        "WRONG_COUNTRY",
        "WRONG_MAX_PRICE",
        "WRONG_ACTIVATION_ID",
        "NO_ACTIVATION",
        "NOT_FOUND",
        "CHANNELS_LIMIT",
        "SERVICE_NOT_AVAILABLE",
        "ACCOUNT_INACTIVE",
        "BANNED",
        "EARLY_CANCEL_DENIED",
    }:
        raise HeroSmsError(f"HeroSMS 请求失败（{code}）{detail}")


def _call(http: Any, options: dict, params: dict) -> tuple[str, Any]:
    endpoint = str(
        options.get("handler_url")
        or "https://hero-sms.com/stubs/handler_api.php"
    ).strip()
    api_key = str(options.get("api_key") or "").strip()
    proxy = str(options.get("proxy") or "").strip()
    if not api_key:
        raise HeroSmsError("未配置 HEROSMS_API_KEY")
    if not endpoint:
        raise HeroSmsError("HEROSMS_HANDLER_URL 不能为空")

    kwargs: dict[str, Any] = {
        "params": {"api_key": api_key, **params},
        "timeout": float(options.get("request_timeout") or 30),
    }
    if proxy:
        kwargs["proxies"] = {"http": proxy, "https": proxy}
    try:
        response = http.get(endpoint, **kwargs)
    except Exception as exc:
        detail = _redact(exc, api_key, proxy)
        raise HeroSmsError(
            f"HeroSMS 请求失败：{type(exc).__name__}: {detail}"
        ) from exc

    text = str(response.text or "").strip()
    try:
        data = response.json()
    except Exception:
        try:
            data = json.loads(text)
        except Exception:
            data = None
    if isinstance(data, str):
        text = data.strip()
    _raise_api_error(status_code=int(response.status_code), text=text, data=data)
    return text, data


def acquire_number(
    http: Any,
    options: dict,
    *,
    service: str | None = None,
    country: str | None = None,
) -> tuple[str, str, dict]:
    selected_service = str(service or options.get("service") or "dr").strip()
    selected_country = str(country or options.get("country") or "").strip()
    if not selected_service:
        raise HeroSmsError("HEROSMS_SERVICE 不能为空")
    if not selected_country:
        raise HeroSmsError("HEROSMS_COUNTRY 和 SMS_COUNTRY 不能同时为空")

    params = {
        "action": "getNumberV2",
        "service": selected_service,
        "country": selected_country,
    }
    optional = {
        "operator": options.get("operator"),
        "maxPrice": options.get("max_price"),
        "fixedPrice": options.get("fixed_price"),
        "phoneException": options.get("phone_exception"),
    }
    for key, value in optional.items():
        if value not in (None, ""):
            params[key] = str(value).strip()
    if str(params.get("fixedPrice") or "").casefold() == "true" and "maxPrice" not in params:
        raise HeroSmsError("HEROSMS_FIXED_PRICE=true 时必须配置 SMS_MAX_PRICE")

    text, data = _call(http, options, params)
    if not isinstance(data, dict):
        raise HeroSmsError(f"HeroSMS getNumberV2 响应不是 JSON 对象：{text[:200]}")
    activation_id = str(
        data.get("activationId") or data.get("activation_id") or data.get("id") or ""
    ).strip()
    phone = _clean_number(data.get("phoneNumber") or data.get("phone") or "")
    if not activation_id:
        raise HeroSmsError("HeroSMS getNumberV2 响应缺少 activationId")
    metadata = {
        "sms_country": data.get("countryCode", selected_country),
        "sms_provider_id": "herosms",
        "sms_cost": _as_cost(data.get("activationCost")),
        "activation_operator": str(data.get("activationOperator") or "").strip(),
    }
    with _STATE_LOCK:
        _ACTIVATIONS[activation_id] = metadata
    return activation_id, phone, dict(metadata)


def get_status(http: Any, options: dict, activation_id: str) -> str:
    text, data = _call(
        http,
        options,
        {"action": "getStatus", "id": str(activation_id)},
    )
    return str(data if isinstance(data, str) else text).strip()


def set_status(http: Any, options: dict, activation_id: str, status: int) -> str:
    text, data = _call(
        http,
        options,
        {
            "action": "setStatus",
            "id": str(activation_id),
            "status": str(int(status)),
        },
    )
    return str(data if isinstance(data, str) else text).strip()


def activation_metadata(activation_id: str) -> dict:
    with _STATE_LOCK:
        stored = dict(_ACTIVATIONS.get(str(activation_id)) or {})
    if not stored:
        return {}
    stored.pop("activation_operator", None)
    return stored


def forget_activation(activation_id: str) -> None:
    with _STATE_LOCK:
        _ACTIVATIONS.pop(str(activation_id), None)


def clear_state() -> None:
    """Test helper for resetting in-memory activation metadata."""
    with _STATE_LOCK:
        _ACTIVATIONS.clear()
