# -*- coding: utf-8 -*-
"""PayPal SMS channel registry with Luban, SMSBower, and HeroSMS implementations.

The SMS API route is intentionally independent from the extraction and PayPal
payment proxies.  This module never owns the PayPal payment lifecycle: it only
acquires, polls, and safely rejects a number when the caller proves payment has
not been mutated.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

import requests


logger = logging.getLogger(__name__)


class PayPalSmsError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        stage: str = "sms",
        code: str = "sms_error",
        retryable: bool = False,
    ) -> None:
        self.stage = str(stage or "sms")
        self.code = str(code or "sms_error")
        self.retryable = bool(retryable)
        super().__init__(str(message or "PayPal 接码失败"))


class PayPalSmsConfigurationError(PayPalSmsError):
    def __init__(self, message: str) -> None:
        super().__init__(message, stage="sms_config", code="configuration")


class PayPalSmsNoNumbers(PayPalSmsError):
    def __init__(self, message: str = "接码平台暂无符合条件的号码") -> None:
        super().__init__(message, stage="sms_acquire", code="no_numbers", retryable=True)


class PayPalSmsTimeout(PayPalSmsError):
    def __init__(self, message: str = "等待 PayPal 短信验证码超时") -> None:
        super().__init__(message, stage="sms_poll", code="timeout", retryable=True)


@dataclass(frozen=True)
class LubanOffer:
    service_id: str
    provider: str
    country: str
    service: str
    cost: float


def _csv(value: object) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        raw = value
    else:
        raw = re.split(r"[,;\n]", str(value or ""))
    result: list[str] = []
    seen: set[str] = set()
    for item in raw:
        normalized = str(item or "").strip()
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            result.append(normalized)
    return result


def _positive_float(value: object, *, name: str, allow_empty: bool = False) -> float | None:
    if allow_empty and value in {None, ""}:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise PayPalSmsConfigurationError(f"{name} 必须是非负数字") from exc
    if number < 0:
        raise PayPalSmsConfigurationError(f"{name} 必须是非负数字")
    return number


def _bounded_int(value: object, *, name: str, default: int, lower: int, upper: int) -> int:
    try:
        number = int(value if value not in {None, ""} else default)
    except (TypeError, ValueError) as exc:
        raise PayPalSmsConfigurationError(f"{name} 必须是整数") from exc
    if not lower <= number <= upper:
        raise PayPalSmsConfigurationError(f"{name} 必须在 {lower}-{upper} 之间")
    return number


def normalize_country(value: object) -> tuple[str, str, str]:
    """Return API country name, ISO code, and dial code."""
    raw = str(value or "Brazil").strip()
    key = re.sub(r"[^a-z]", "", raw.lower())
    if key in {"brazil", "br", "brasil"}:
        return "Brazil", "BR", "55"
    if key in {
        "england", "gb", "uk", "unitedkingdom", "greatbritain",
        "unitedkingdomengland",
    }:
        return "England", "GB", "44"
    if key in {"southafrica", "za", "rsa", "republicofsouthafrica"}:
        return "South Africa", "ZA", "27"
    raise PayPalSmsConfigurationError(
        "PayPal 接码当前仅支持 England / GB / +44、Brazil / BR / +55 或 South Africa / ZA / +27"
    )


def normalize_smsbower_country(value: object) -> tuple[str, str, str, str]:
    """Return SMSBower country ID, display name, ISO code, and dial code."""
    raw = str(value or "16").strip()
    key = re.sub(r"[^a-z0-9]", "", raw.lower())
    if key in {"16", "england", "gb", "uk", "unitedkingdom", "greatbritain"}:
        return "16", "England", "GB", "44"
    if key in {"73", "brazil", "br", "brasil"}:
        return "73", "Brazil", "BR", "55"
    raise PayPalSmsConfigurationError(
        "PAYPAL_SMSBOWER_COUNTRY_ID 当前仅支持 16/GB（英国）或 73/BR（巴西）"
    )


def normalize_herosms_country(value: object) -> tuple[str, str, str, str]:
    """Return HeroSMS country ID, display name, ISO code, and dial code."""
    raw = str(value or "16").strip()
    key = re.sub(r"[^a-z0-9]", "", raw.lower())
    if key in {"16", "england", "gb", "uk", "unitedkingdom", "greatbritain"}:
        return "16", "England", "GB", "44"
    if key in {"73", "brazil", "br", "brasil"}:
        return "73", "Brazil", "BR", "55"
    raise PayPalSmsConfigurationError(
        "PAYPAL_HEROSMS_COUNTRY_ID 当前仅支持 16/GB（英国）或 73/BR（巴西）"
    )


def resolve_channel_country(settings: dict) -> tuple[str, str, str]:
    """Resolve and validate the country shared by ordered SMS fallbacks."""
    channels = _csv((settings or {}).get("channels"))
    resolved: list[tuple[str, str, str]] = []
    for name in channels:
        normalized = name.casefold()
        if normalized in {"smsbower", "sms_bower", "smsb"}:
            settings_key = "smsbower"
        elif normalized in {"herosms", "hero_sms", "hero"}:
            settings_key = "herosms"
        else:
            settings_key = normalized
        channel = (settings or {}).get(settings_key)
        if not isinstance(channel, dict):
            continue
        if normalized == "luban":
            resolved.append(normalize_country(channel.get("country")))
        elif normalized in {"smsbower", "sms_bower", "smsb"}:
            _, display, iso, dial = normalize_smsbower_country(
                channel.get("country_id") or channel.get("country")
            )
            resolved.append((display, iso, dial))
        elif normalized in {"herosms", "hero_sms", "hero"}:
            _, display, iso, dial = normalize_herosms_country(
                channel.get("country_id") or channel.get("country")
            )
            resolved.append((display, iso, dial))
    if not resolved:
        raise PayPalSmsConfigurationError("没有可用于 PayPal 自动接码的已配置渠道")
    country = resolved[0]
    if any(item[1] != country[1] for item in resolved[1:]):
        raise PayPalSmsConfigurationError("PayPal 接码回退渠道必须配置为同一个国家")
    return country


def mask_phone(value: object) -> str:
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    if not digits:
        return ""
    return f"+{'*' * max(2, len(digits) - 4)}{digits[-4:]}"


def normalize_phone(value: object, *, country: object = "Brazil") -> str:
    _, iso, dial = normalize_country(country)
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    if digits.startswith(dial):
        local = digits[len(dial):]
    else:
        local = digits
    if iso == "GB":
        if local.startswith("0") and len(local) == 11:
            local = local[1:]
        if not re.fullmatch(r"7\d{9}", local):
            raise PayPalSmsError(
                "接码平台返回的英国手机号格式无效",
                stage="sms_acquire",
                code="phone_invalid",
            )
        return f"+{dial}{local}"

    if iso == "ZA":
        if local.startswith("0") and len(local) == 10:
            local = local[1:]
        if not re.fullmatch(r"[6-8]\d{8}", local):
            raise PayPalSmsError(
                "接码平台返回的南非手机号格式无效",
                stage="sms_acquire",
                code="phone_invalid",
            )
        return f"+{dial}{local}"

    while local.startswith("0") and len(local) > 11:
        local = local[1:]
    if not re.fullmatch(r"\d{10,11}", local):
        raise PayPalSmsError(
            "接码平台返回的巴西手机号格式无效",
            stage="sms_acquire",
            code="phone_invalid",
        )
    return f"+{dial}{local}"


def _safe_base_url(value: object) -> str:
    base = str(value or "https://lubansms.com/v2/api").strip().rstrip("/") + "/"
    try:
        parsed = urlsplit(base)
        port = parsed.port
    except ValueError as exc:
        raise PayPalSmsConfigurationError("Luban API 地址无效") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or port not in {None, 80, 443}:
        raise PayPalSmsConfigurationError("Luban API 地址必须是有效的 HTTP(S) 地址")
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise PayPalSmsConfigurationError("Luban API 地址不能包含凭证、查询参数或 fragment")
    return base


def _sanitize(value: object, *, secrets: tuple[str, ...] = ()) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    for secret in sorted((str(item) for item in secrets if str(item)), key=len, reverse=True):
        text = text.replace(secret, "***")
    text = re.sub(r"(?i)(apikey|authorization|token)([\"']?\s*[:=]\s*[\"']?)[^\s,&}\]]+", r"\1\2***", text)
    text = re.sub(r"\+?\d{9,15}", "***PHONE***", text)
    return text[:300]


class LubanClient:
    def __init__(self, settings: dict, *, http: Any | None = None) -> None:
        self.settings = dict(settings or {})
        self.api_base = _safe_base_url(self.settings.get("api_base"))
        self.api_key = str(self.settings.get("api_key") or "").strip()
        if not self.api_key:
            raise PayPalSmsConfigurationError("未配置 PAYPAL_LUBAN_API_KEY")
        self.country, self.country_code, self.dial_code = normalize_country(
            self.settings.get("country") or "Brazil"
        )
        self.service = str(self.settings.get("service") or "PayPal").strip()
        if not self.service:
            raise PayPalSmsConfigurationError("PAYPAL_LUBAN_SERVICE 不能为空")
        self.service_aliases = {
            item.casefold()
            for item in [self.service, *_csv(self.settings.get("service_aliases"))]
            if str(item or "").strip()
        }
        self.providers = _csv(self.settings.get("providers"))
        self.service_ids = set(_csv(self.settings.get("service_ids")))
        self.max_price = _positive_float(
            self.settings.get("max_price"), name="PAYPAL_LUBAN_MAX_PRICE", allow_empty=True,
        )
        self.max_attempts = _bounded_int(
            self.settings.get("max_attempts"), name="PAYPAL_LUBAN_MAX_ATTEMPTS",
            default=3, lower=1, upper=50,
        )
        self.max_pages = _bounded_int(
            self.settings.get("list_max_pages"), name="PAYPAL_LUBAN_LIST_MAX_PAGES",
            default=5, lower=1, upper=100,
        )
        timeout = _positive_float(
            self.settings.get("request_timeout") or 20,
            name="PAYPAL_LUBAN_REQUEST_TIMEOUT",
        )
        self.timeout = max(1.0, min(120.0, float(timeout or 20)))
        self.proxy = str(self.settings.get("proxy") or "").strip()
        self._owns_http = http is None
        self.http = http or requests.Session()

    def close(self) -> None:
        if self._owns_http and callable(getattr(self.http, "close", None)):
            self.http.close()

    def _get(self, path: str, params: dict[str, object]) -> Any:
        url = urljoin(self.api_base, str(path or "").lstrip("/"))
        kwargs: dict[str, Any] = {
            "params": {"apikey": self.api_key, **params},
            "timeout": self.timeout,
        }
        if self.proxy:
            kwargs["proxies"] = {"http": self.proxy, "https": self.proxy}
        try:
            response = self.http.get(url, **kwargs)
        except Exception as exc:
            raise PayPalSmsError(
                f"Luban API 请求失败: {_sanitize(exc, secrets=(self.api_key, self.proxy))}",
                stage="sms_api", code="transport", retryable=True,
            ) from exc
        status = int(getattr(response, "status_code", 0) or 0)
        if status != 200:
            body = _sanitize(getattr(response, "text", ""), secrets=(self.api_key, self.proxy))
            raise PayPalSmsError(
                f"Luban API HTTP {status}: {body}",
                stage="sms_api", code="http_error", retryable=status in {408, 425, 429} or status >= 500,
            )
        try:
            payload = response.json()
        except Exception as exc:
            raise PayPalSmsError(
                "Luban API 返回的不是 JSON",
                stage="sms_api", code="invalid_json", retryable=True,
            ) from exc
        if not isinstance(payload, dict):
            raise PayPalSmsError(
                "Luban API 返回结构无效",
                stage="sms_api", code="invalid_response", retryable=True,
            )
        try:
            code = int(payload.get("code", -1))
        except (TypeError, ValueError):
            code = -1
        if code != 0:
            message = _sanitize(payload.get("msg") or "unknown error", secrets=(self.api_key, self.proxy))
            lower = message.lower()
            retryable = any(word in lower for word in ("wait", "busy", "later", "timeout", "number"))
            raise PayPalSmsError(
                f"Luban API 返回失败: {message}",
                stage="sms_api", code=f"luban_{code}", retryable=retryable,
            )
        return payload.get("msg"), payload

    def list_offers(self) -> list[LubanOffer]:
        offers: dict[str, LubanOffer] = {}
        seen_page_ids: set[str] = set()
        for page in range(1, self.max_pages + 1):
            message, _ = self._get("List", {
                "country": self.country,
                "service": self.service,
                "language": "en",
                "page": page,
            })
            if not isinstance(message, list) or not message:
                break
            page_ids: set[str] = set()
            for raw in message:
                if not isinstance(raw, dict):
                    continue
                service_id = str(raw.get("service_id") or "").strip()
                if service_id:
                    page_ids.add(service_id)
                provider = str(raw.get("provider") or "").strip()
                country = str(
                    raw.get("country_name_en") or raw.get("country_name") or raw.get("country") or ""
                ).strip()
                try:
                    _, offer_country_code, _ = normalize_country(country)
                except PayPalSmsConfigurationError:
                    offer_country_code = ""
                service = str(
                    raw.get("service_name") or raw.get("service_name_en") or raw.get("service") or ""
                ).strip()
                try:
                    cost = float(raw.get("cost"))
                except (TypeError, ValueError):
                    continue
                if (
                    not service_id or not provider or cost < 0
                    or offer_country_code != self.country_code
                    or service.casefold() not in self.service_aliases
                    or (self.service_ids and service_id not in self.service_ids)
                    or (self.max_price is not None and cost > self.max_price + 1e-9)
                ):
                    continue
                if service_id not in offers:
                    offers[service_id] = LubanOffer(
                        service_id=service_id,
                        provider=provider,
                        country=country,
                        service=service,
                        cost=cost,
                    )
            if page_ids and page_ids.issubset(seen_page_ids):
                break
            seen_page_ids.update(page_ids)

        provider_order = {name.casefold(): index for index, name in enumerate(self.providers)}
        selected = [
            offer for offer in offers.values()
            if not provider_order or offer.provider.casefold() in provider_order
        ]
        if provider_order:
            selected.sort(key=lambda offer: (
                provider_order[offer.provider.casefold()], offer.cost, offer.service_id,
            ))
        else:
            selected.sort(key=lambda offer: (offer.cost, offer.provider.casefold(), offer.service_id))
        return selected

    def acquire(self) -> dict[str, Any]:
        offers = self.list_offers()
        if not offers:
            raise PayPalSmsNoNumbers("Luban 没有符合国家、服务、Provider 和价格限制的号码")
        errors: list[str] = []
        for offer in offers[: self.max_attempts]:
            try:
                _, payload = self._get("getNumber", {"service_id": offer.service_id})
                request_id = str(payload.get("request_id") or "").strip()
                phone = normalize_phone(payload.get("number"), country=self.country)
                if not request_id:
                    raise PayPalSmsError(
                        "Luban getNumber 缺少 request_id",
                        stage="sms_acquire", code="invalid_response", retryable=True,
                    )
                now = time.time()
                return {
                    "channel": "luban",
                    "provider": offer.provider,
                    "service_id": offer.service_id,
                    "request_id": request_id,
                    "country": self.country,
                    "country_code": self.country_code,
                    "service": self.service,
                    "cost": offer.cost,
                    "phone": phone,
                    "phone_masked": mask_phone(phone),
                    "status": "acquired",
                    "acquired_at": now,
                }
            except PayPalSmsConfigurationError:
                raise
            except PayPalSmsError as exc:
                errors.append(_sanitize(exc, secrets=(self.api_key, self.proxy)))
                if not exc.retryable:
                    raise
        raise PayPalSmsNoNumbers(errors[-1] if errors else "Luban 取号尝试已耗尽")

    def poll_code(
        self,
        activation: dict,
        *,
        timeout: float | None = None,
        poll_interval: float | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> str:
        request_id = str((activation or {}).get("request_id") or "").strip()
        if not request_id:
            raise PayPalSmsConfigurationError("Luban activation 缺少 request_id")
        configured_wait = _positive_float(
            self.settings.get("code_wait") or 120, name="PAYPAL_LUBAN_CODE_WAIT",
        )
        configured_poll = _positive_float(
            self.settings.get("poll_interval") or 5, name="PAYPAL_LUBAN_POLL_INTERVAL",
        )
        wait_seconds = max(1.0, min(1800.0, float(timeout if timeout is not None else configured_wait or 120)))
        interval = max(0.1, min(60.0, float(poll_interval if poll_interval is not None else configured_poll or 5)))
        deadline = monotonic() + wait_seconds
        last_error: PayPalSmsError | None = None
        while True:
            try:
                message, payload = self._get("getSms", {"request_id": request_id})
                state = str(message or "").strip().lower()
                code = str(payload.get("sms_code") or "").strip()
                if state == "success" or code:
                    if not re.fullmatch(r"\d{6}", code):
                        raise PayPalSmsError(
                            "Luban 返回的 PayPal 验证码不是 6 位数字",
                            stage="sms_poll", code="invalid_code", retryable=True,
                        )
                    return code
                if state not in {"", "wait", "waiting", "pending"}:
                    raise PayPalSmsError(
                        f"Luban 短信订单状态异常: {_sanitize(state)}",
                        stage="sms_poll", code="terminal_status", retryable=False,
                    )
                last_error = None
            except PayPalSmsError as exc:
                if not exc.retryable:
                    raise
                last_error = exc
            remaining = deadline - monotonic()
            if remaining <= 0:
                detail = f": {_sanitize(last_error)}" if last_error else ""
                raise PayPalSmsTimeout(f"等待 PayPal 短信验证码超时{detail}")
            sleep(min(interval, remaining))

    def reject(self, activation: dict) -> None:
        request_id = str((activation or {}).get("request_id") or "").strip()
        if not request_id:
            raise PayPalSmsConfigurationError("Luban activation 缺少 request_id")
        try:
            self._get("setStatus", {"request_id": request_id, "status": "reject"})
        except PayPalSmsError as exc:
            message = str(exc).casefold()
            terminal_markers = (
                "已释放", "已取消", "already released", "already cancelled", "already canceled",
            )
            if not any(marker in message for marker in terminal_markers):
                raise
            logger.info("[PayPal][SMS] Luban 号码已处于释放状态: request_id=%s", request_id)


class _RequestsAdapter:
    """Apply timeout/proxy policy to the shared SMSBower protocol helpers."""

    def __init__(self, session: Any, *, timeout: float, proxy: str) -> None:
        self.session = session
        self.timeout = timeout
        self.proxy = proxy

    def get(self, url: str, params: dict | None = None):
        kwargs: dict[str, Any] = {"params": params, "timeout": self.timeout}
        if self.proxy:
            kwargs["proxies"] = {"http": self.proxy, "https": self.proxy}
        return self.session.get(url, **kwargs)


class SmsBowerClient:
    def __init__(self, settings: dict, *, http: Any | None = None) -> None:
        self.settings = dict(settings or {})
        self.api_key = str(self.settings.get("api_key") or "").strip()
        if not self.api_key:
            raise PayPalSmsConfigurationError(
                "未配置 PAYPAL_SMSBOWER_API_KEY 或全局 SMSBOWER_API_KEY"
            )
        endpoint = str(
            self.settings.get("handler_url")
            or "https://smsbower.page/stubs/handler_api.php"
        ).strip()
        try:
            parsed = urlsplit(endpoint)
            port = parsed.port
        except ValueError as exc:
            raise PayPalSmsConfigurationError("SMSBower API 地址无效") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or port not in {None, 80, 443}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise PayPalSmsConfigurationError(
                "SMSBower API 地址必须是无凭证、无查询参数的 HTTP(S) 地址"
            )
        self.handler_url = endpoint
        (
            self.country_id,
            self.country,
            self.country_code,
            self.dial_code,
        ) = normalize_smsbower_country(self.settings.get("country_id") or "16")
        self.service = str(self.settings.get("service") or "ts").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", self.service):
            raise PayPalSmsConfigurationError("PAYPAL_SMSBOWER_SERVICE 格式无效")
        self.min_price = _positive_float(
            self.settings.get("min_price"),
            name="PAYPAL_SMSBOWER_MIN_PRICE",
            allow_empty=True,
        )
        self.max_price = _positive_float(
            self.settings.get("max_price"),
            name="PAYPAL_SMSBOWER_MAX_PRICE",
            allow_empty=True,
        )
        if (
            self.min_price is not None
            and self.max_price is not None
            and self.min_price > self.max_price + 1e-9
        ):
            raise PayPalSmsConfigurationError(
                "PAYPAL_SMSBOWER_MIN_PRICE 不能大于 PAYPAL_SMSBOWER_MAX_PRICE"
            )
        timeout = _positive_float(
            self.settings.get("request_timeout") or 20,
            name="PAYPAL_SMSBOWER_REQUEST_TIMEOUT",
        )
        self.timeout = max(1.0, min(120.0, float(timeout or 20)))
        self.proxy = str(self.settings.get("proxy") or "").strip()
        self._owns_http = http is None
        self.http = http or requests.Session()
        self.api_http = (
            _RequestsAdapter(self.http, timeout=self.timeout, proxy=self.proxy)
            if self._owns_http
            else self.http
        )

    def close(self) -> None:
        if self._owns_http and callable(getattr(self.http, "close", None)):
            self.http.close()

    def _options(self) -> dict[str, Any]:
        return {
            "api_key": self.api_key,
            "handler_url": self.handler_url,
            "service": self.service,
            "country": self.country_id,
            "min_price": self.min_price if self.min_price is not None else "",
            "max_price": self.max_price if self.max_price is not None else "",
            "budget": "",
        }

    def _translate(self, exc: Exception, *, stage: str) -> PayPalSmsError:
        from core import sms_bower

        message = _sanitize(exc, secrets=(self.api_key, self.proxy))
        if isinstance(exc, sms_bower.SmsBowerNoNumbers):
            return PayPalSmsNoNumbers(message)
        if isinstance(exc, sms_bower.SmsBowerNoBalance):
            return PayPalSmsError(
                message, stage=stage, code="no_balance", retryable=False,
            )
        if isinstance(exc, sms_bower.SmsBowerBudgetExceeded):
            return PayPalSmsError(
                message, stage=stage, code="price_limit", retryable=False,
            )
        lower = message.casefold()
        retryable = not any(
            marker in lower for marker in ("bad_key", "api key", "bad_service", "bad_country")
        )
        return PayPalSmsError(
            f"SMSBower 请求失败: {message}",
            stage=stage,
            code="smsbower_error",
            retryable=retryable,
        )

    def acquire(self) -> dict[str, Any]:
        from core import sms_bower

        try:
            request_id, digits, metadata = sms_bower.acquire_number(
                self.api_http, self._options(),
            )
        except sms_bower.SmsBowerError as exc:
            raise self._translate(exc, stage="sms_acquire") from exc
        phone = normalize_phone(digits, country=self.country)
        provider_id = str(metadata.get("sms_provider_id") or "").strip()
        cost = metadata.get("sms_cost")
        now = time.time()
        return {
            "channel": "smsbower",
            "provider": f"smsbower:{provider_id}" if provider_id else "smsbower",
            "service_id": self.service,
            "request_id": request_id,
            "country": self.country,
            "country_code": self.country_code,
            "country_id": self.country_id,
            "service": self.service,
            "cost": cost,
            "phone": phone,
            "phone_masked": mask_phone(phone),
            "status": "acquired",
            "acquired_at": now,
        }

    def poll_code(
        self,
        activation: dict,
        *,
        timeout: float | None = None,
        poll_interval: float | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> str:
        from core import sms_bower

        request_id = str((activation or {}).get("request_id") or "").strip()
        if not request_id:
            raise PayPalSmsConfigurationError("SMSBower activation 缺少 request_id")
        configured_wait = _positive_float(
            self.settings.get("code_wait") or 120,
            name="PAYPAL_SMSBOWER_CODE_WAIT",
        )
        configured_poll = _positive_float(
            self.settings.get("poll_interval") or 5,
            name="PAYPAL_SMSBOWER_POLL_INTERVAL",
        )
        wait_seconds = max(
            1.0,
            min(1800.0, float(timeout if timeout is not None else configured_wait or 120)),
        )
        interval = max(
            0.1,
            min(60.0, float(poll_interval if poll_interval is not None else configured_poll or 5)),
        )
        deadline = monotonic() + wait_seconds
        last_error: PayPalSmsError | None = None
        while True:
            try:
                state = sms_bower.get_status(
                    self.api_http, self._options(), request_id,
                ).strip()
                if state.startswith("STATUS_OK:"):
                    code = state.split(":", 1)[1].strip().strip("'\"")
                    if not re.fullmatch(r"\d{6}", code):
                        raise PayPalSmsError(
                            "SMSBower 返回的 PayPal 验证码不是 6 位数字",
                            stage="sms_poll",
                            code="invalid_code",
                            retryable=True,
                        )
                    try:
                        sms_bower.call_status(
                            self.api_http, self._options(), request_id, 6,
                        )
                    except sms_bower.SmsBowerError as exc:
                        logger.warning(
                            "[PayPal][SMS] SMSBower 标记完成失败，不影响验证码提交: %s",
                            _sanitize(exc, secrets=(self.api_key, self.proxy)),
                        )
                    else:
                        sms_bower.forget_activation(request_id)
                    return code
                if state == "STATUS_CANCEL":
                    raise PayPalSmsError(
                        "SMSBower 激活已取消",
                        stage="sms_poll",
                        code="terminal_status",
                        retryable=False,
                    )
                if not state.startswith(("STATUS_WAIT", "STATUS_PREPARE")):
                    raise PayPalSmsError(
                        f"SMSBower 激活状态异常: {_sanitize(state)}",
                        stage="sms_poll",
                        code="terminal_status",
                        retryable=False,
                    )
                last_error = None
            except sms_bower.SmsBowerError as exc:
                translated = self._translate(exc, stage="sms_poll")
                if not translated.retryable:
                    raise translated from exc
                last_error = translated
            remaining = deadline - monotonic()
            if remaining <= 0:
                detail = f": {_sanitize(last_error)}" if last_error else ""
                raise PayPalSmsTimeout(f"等待 PayPal 短信验证码超时{detail}")
            sleep(min(interval, remaining))

    def reject(self, activation: dict) -> None:
        from core import sms_bower

        request_id = str((activation or {}).get("request_id") or "").strip()
        if not request_id:
            raise PayPalSmsConfigurationError("SMSBower activation 缺少 request_id")
        try:
            sms_bower.call_status(self.api_http, self._options(), request_id, 8)
        except sms_bower.SmsBowerError as exc:
            message = str(exc).casefold()
            if not any(
                marker in message
                for marker in ("no_activation", "status_cancel", "already cancel", "already released")
            ):
                raise self._translate(exc, stage="sms_reject") from exc
        else:
            sms_bower.forget_activation(request_id)


class HeroSmsClient:
    """PayPal adapter for the shared SMS-Activate-compatible HeroSMS client."""

    def __init__(self, settings: dict, *, http: Any | None = None) -> None:
        self.settings = dict(settings or {})
        self.api_key = str(self.settings.get("api_key") or "").strip()
        if not self.api_key:
            raise PayPalSmsConfigurationError(
                "未配置 PAYPAL_HEROSMS_API_KEY 或全局 HEROSMS_API_KEY"
            )
        endpoint = str(
            self.settings.get("handler_url")
            or "https://hero-sms.com/stubs/handler_api.php"
        ).strip()
        try:
            parsed = urlsplit(endpoint)
            port = parsed.port
        except ValueError as exc:
            raise PayPalSmsConfigurationError("HeroSMS API 地址无效") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or port not in {None, 80, 443}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise PayPalSmsConfigurationError(
                "HeroSMS API 地址必须是无凭证、无查询参数的 HTTP(S) 地址"
            )
        self.handler_url = endpoint
        (
            self.country_id,
            self.country,
            self.country_code,
            self.dial_code,
        ) = normalize_herosms_country(self.settings.get("country_id") or "16")
        self.service = str(self.settings.get("service") or "ts").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", self.service):
            raise PayPalSmsConfigurationError("PAYPAL_HEROSMS_SERVICE 格式无效")
        self.max_price = _positive_float(
            self.settings.get("max_price"),
            name="PAYPAL_HEROSMS_MAX_PRICE",
            allow_empty=True,
        )
        timeout = _positive_float(
            self.settings.get("request_timeout") or 20,
            name="PAYPAL_HEROSMS_REQUEST_TIMEOUT",
        )
        self.timeout = max(1.0, min(120.0, float(timeout or 20)))
        self.proxy = str(self.settings.get("proxy") or "").strip()
        self._owns_http = http is None
        self.http = http or requests.Session()

    def close(self) -> None:
        if self._owns_http and callable(getattr(self.http, "close", None)):
            self.http.close()

    def _options(self) -> dict[str, Any]:
        return {
            "handler_url": self.handler_url,
            "api_key": self.api_key,
            "service": self.service,
            "country": self.country_id,
            "max_price": self.max_price if self.max_price is not None else "",
            "operator": str(self.settings.get("operator") or "").strip(),
            "fixed_price": str(self.settings.get("fixed_price") or "").strip(),
            "phone_exception": str(self.settings.get("phone_exception") or "").strip(),
            "request_timeout": self.timeout,
            "proxy": self.proxy,
        }

    def _translate(self, exc: Exception, *, stage: str) -> PayPalSmsError:
        from core import hero_sms

        message = _sanitize(exc, secrets=(self.api_key, self.proxy))
        if isinstance(exc, hero_sms.HeroSmsNoNumbers):
            return PayPalSmsNoNumbers(message)
        if isinstance(exc, hero_sms.HeroSmsNoBalance):
            return PayPalSmsError(
                message, stage=stage, code="no_balance", retryable=False,
            )
        lower = message.casefold()
        non_retryable = any(marker in lower for marker in (
            "bad_key", "api key", "bad_service", "wrong_service",
            "wrong_country", "wrong_max_price", "account_inactive", "banned",
        ))
        return PayPalSmsError(
            f"HeroSMS 请求失败: {message}",
            stage=stage,
            code="herosms_error",
            retryable=not non_retryable,
        )

    def acquire(self) -> dict[str, Any]:
        from core import hero_sms

        try:
            request_id, digits, metadata = hero_sms.acquire_number(
                self.http, self._options(),
            )
        except hero_sms.HeroSmsError as exc:
            raise self._translate(exc, stage="sms_acquire") from exc
        phone = normalize_phone(digits, country=self.country)
        now = time.time()
        return {
            "channel": "herosms",
            "provider": "herosms",
            "service_id": self.service,
            "request_id": request_id,
            "country": self.country,
            "country_code": self.country_code,
            "country_id": self.country_id,
            "service": self.service,
            "cost": metadata.get("sms_cost"),
            "phone": phone,
            "phone_masked": mask_phone(phone),
            "status": "acquired",
            "acquired_at": now,
        }

    def poll_code(
        self,
        activation: dict,
        *,
        timeout: float | None = None,
        poll_interval: float | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> str:
        from core import hero_sms

        request_id = str((activation or {}).get("request_id") or "").strip()
        if not request_id:
            raise PayPalSmsConfigurationError("HeroSMS activation 缺少 request_id")
        configured_wait = _positive_float(
            self.settings.get("code_wait") or 120,
            name="PAYPAL_HEROSMS_CODE_WAIT",
        )
        configured_poll = _positive_float(
            self.settings.get("poll_interval") or 5,
            name="PAYPAL_HEROSMS_POLL_INTERVAL",
        )
        wait_seconds = max(
            1.0,
            min(1800.0, float(timeout if timeout is not None else configured_wait or 120)),
        )
        interval = max(
            0.1,
            min(60.0, float(poll_interval if poll_interval is not None else configured_poll or 5)),
        )
        deadline = monotonic() + wait_seconds
        last_error: PayPalSmsError | None = None
        while True:
            try:
                state = hero_sms.get_status(
                    self.http, self._options(), request_id,
                ).strip()
                if state.upper().startswith("STATUS_OK:"):
                    code = state.split(":", 1)[1].strip().strip("'\"")
                    if not re.fullmatch(r"\d{6}", code):
                        raise PayPalSmsError(
                            "HeroSMS 返回的 PayPal 验证码不是 6 位数字",
                            stage="sms_poll",
                            code="invalid_code",
                            retryable=True,
                        )
                    try:
                        hero_sms.set_status(
                            self.http, self._options(), request_id, 6,
                        )
                    except hero_sms.HeroSmsError as exc:
                        logger.warning(
                            "[PayPal][SMS] HeroSMS 标记完成失败，不影响验证码提交: %s",
                            _sanitize(exc, secrets=(self.api_key, self.proxy)),
                        )
                    else:
                        hero_sms.forget_activation(request_id)
                    return code
                normalized = state.upper()
                if normalized == "STATUS_CANCEL":
                    raise PayPalSmsError(
                        "HeroSMS 激活已取消",
                        stage="sms_poll",
                        code="terminal_status",
                        retryable=False,
                    )
                if not normalized.startswith(("STATUS_WAIT", "STATUS_PREPARE")):
                    raise PayPalSmsError(
                        f"HeroSMS 激活状态异常: {_sanitize(state)}",
                        stage="sms_poll",
                        code="terminal_status",
                        retryable=False,
                    )
                last_error = None
            except hero_sms.HeroSmsError as exc:
                translated = self._translate(exc, stage="sms_poll")
                if not translated.retryable:
                    raise translated from exc
                last_error = translated
            remaining = deadline - monotonic()
            if remaining <= 0:
                detail = f": {_sanitize(last_error)}" if last_error else ""
                raise PayPalSmsTimeout(f"等待 PayPal 短信验证码超时{detail}")
            sleep(min(interval, remaining))

    def reject(self, activation: dict) -> None:
        from core import hero_sms

        request_id = str((activation or {}).get("request_id") or "").strip()
        if not request_id:
            raise PayPalSmsConfigurationError("HeroSMS activation 缺少 request_id")
        try:
            hero_sms.set_status(self.http, self._options(), request_id, 8)
        except hero_sms.HeroSmsError as exc:
            message = str(exc).casefold()
            if not any(marker in message for marker in (
                "no_activation", "not_found", "status_cancel",
                "already cancel", "already released",
            )):
                raise self._translate(exc, stage="sms_reject") from exc
        else:
            hero_sms.forget_activation(request_id)


_CHANNELS: dict[str, type[Any]] = {
    "luban": LubanClient,
    "smsbower": SmsBowerClient,
    "sms_bower": SmsBowerClient,
    "smsb": SmsBowerClient,
    "herosms": HeroSmsClient,
    "hero_sms": HeroSmsClient,
    "hero": HeroSmsClient,
}


def register_channel(name: str, channel_class: type[Any]) -> None:
    normalized = str(name or "").strip().lower()
    if not normalized or not callable(channel_class):
        raise ValueError("PayPal SMS channel 注册参数无效")
    _CHANNELS[normalized] = channel_class


def _channel_settings(settings: dict, name: str) -> dict:
    if name in {"smsbower", "sms_bower", "smsb"}:
        settings_key = "smsbower"
    elif name in {"herosms", "hero_sms", "hero"}:
        settings_key = "herosms"
    else:
        settings_key = name
    value = (settings or {}).get(settings_key)
    if not isinstance(value, dict):
        raise PayPalSmsConfigurationError(f"缺少 PayPal SMS 渠道配置: {name}")
    return dict(value)


def acquire_number(settings: dict, *, http: Any | None = None) -> dict[str, Any]:
    channels = _csv((settings or {}).get("channels"))
    if not channels:
        raise PayPalSmsConfigurationError("PAYPAL_SMS_CHANNELS 不能为空")
    errors: list[str] = []
    for name in channels:
        normalized = name.lower()
        channel_class = _CHANNELS.get(normalized)
        if channel_class is None:
            errors.append(f"不支持的 PayPal SMS 渠道: {name}")
            continue
        try:
            client = channel_class(_channel_settings(settings, normalized), http=http)
            try:
                return client.acquire()
            finally:
                client.close()
        except PayPalSmsConfigurationError:
            raise
        except PayPalSmsError as exc:
            errors.append(_sanitize(exc))
    raise PayPalSmsNoNumbers(errors[-1] if errors else "PayPal 自动接码取号失败")


def wait_for_sms_code(
    settings: dict,
    activation: dict,
    *,
    http: Any | None = None,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> str:
    name = str((activation or {}).get("channel") or "").strip().lower()
    channel_class = _CHANNELS.get(name)
    if channel_class is None:
        raise PayPalSmsConfigurationError(f"不支持的 PayPal SMS 渠道: {name or 'empty'}")
    client = channel_class(_channel_settings(settings, name), http=http)
    try:
        return client.poll_code(
            activation, sleep=sleep, monotonic=monotonic,
        )
    finally:
        client.close()


def reject_number(settings: dict, activation: dict, *, http: Any | None = None) -> None:
    name = str((activation or {}).get("channel") or "").strip().lower()
    channel_class = _CHANNELS.get(name)
    if channel_class is None:
        raise PayPalSmsConfigurationError(f"不支持的 PayPal SMS 渠道: {name or 'empty'}")
    client = channel_class(_channel_settings(settings, name), http=http)
    try:
        client.reject(activation)
    finally:
        client.close()


__all__ = [
    "HeroSmsClient", "LubanClient", "LubanOffer", "SmsBowerClient",
    "PayPalSmsConfigurationError", "PayPalSmsError",
    "PayPalSmsNoNumbers", "PayPalSmsTimeout", "acquire_number", "mask_phone",
    "normalize_country", "normalize_herosms_country", "normalize_smsbower_country", "normalize_phone",
    "resolve_channel_country", "register_channel", "reject_number",
    "wait_for_sms_code",
]
