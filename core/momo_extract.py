# -*- coding: utf-8 -*-
"""Local ChatGPT/Stripe MoMo link extraction protocol.

This module intentionally performs one deterministic VN/VND checkout flow.  It
does not rotate proxies, retry with another checkout, or synthesize a MoMo URL.
Only a gateway URL returned by Stripe's ``next_action.redirect_to_url`` chain
is accepted as a successful result.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

try:
    from curl_cffi import CurlOpt
    from curl_cffi import requests as curl_requests
except ImportError:  # pragma: no cover - requirements.txt installs curl_cffi
    CurlOpt = None
    curl_requests = None


CHATGPT_CHECKOUT_URL = "https://chatgpt.com/backend-api/payments/checkout"
CHATGPT_CHECKOUT_UPDATE_URL = "https://chatgpt.com/backend-api/payments/checkout/update"
CHATGPT_CHECKOUT_APPROVE_URL = "https://chatgpt.com/backend-api/payments/checkout/approve"
STRIPE_API_BASE = "https://api.stripe.com/v1"

DEFAULT_TIMEOUT = 30.0
CHATGPT_TIMEOUT = 45.0
STRIPE_VERSION = (
    "2025-03-31.basil; checkout_server_update_beta=v1; "
    "checkout_manual_approval_preview=v1"
)
STRIPE_RUNTIME_VERSION = "6f8494a281"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15"
)
CHATGPT_CLIENT_VERSION = "prod-db390ebea64862bf1899c420a4c736e0cf639747"
CHATGPT_CLIENT_BUILD_NUMBER = "7904904"

_PROXY_COUNTRY_SELECTOR_RE = re.compile(
    r"(?i)(?<![a-z0-9])(?P<name>country|region|zone)(?P<separator>[-_=])"
    r"(?P<value>[a-z]{2}(?:,[a-z]{2})*)(?=$|[-_=;,&:@])"
)


class MomoExtractionError(RuntimeError):
    """A runtime/protocol failure which must not be recorded as ``no_momo``."""

    code = "failed"

    def __init__(
        self,
        message: str,
        *,
        stage: str = "",
        retryable: bool = False,
        http_status: int | None = None,
    ) -> None:
        self.stage = str(stage or "unknown")
        self.detail = str(message or "MoMo extraction failed")
        self.retryable = bool(retryable)
        self.http_status = int(http_status) if http_status is not None else None
        super().__init__(f"[{self.stage}] {self.detail}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.code,
            "stage": self.stage,
            "error": self.detail,
            "retryable": self.retryable,
            "http_status": self.http_status,
        }


class MomoUnavailableError(MomoExtractionError):
    """Stripe definitively did not expose MoMo for this checkout/account."""

    code = "no_momo"

    def __init__(
        self,
        message: str,
        *,
        stage: str,
        methods: list[str] | None,
        currency: str,
        amount: int | None = None,
    ) -> None:
        self.methods = list(methods) if methods is not None else None
        self.currency = str(currency or "")
        self.amount = amount
        super().__init__(message, stage=stage)

    def as_dict(self) -> dict[str, Any]:
        data = super().as_dict()
        data.update(
            {
                "methods": self.methods,
                "currency": self.currency,
                "amount": self.amount,
            }
        )
        return data


class _ApprovalRequired(Exception):
    pass


def _normalize_proxy_url(proxy: str) -> str:
    value = str(proxy or "").strip()
    if not value:
        raise MomoExtractionError("代理为空，MoMo 流程禁止直连", stage="proxy")
    if "://" not in value:
        value = f"socks5h://{value}"

    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.hostname:
        raise MomoExtractionError("代理 URL 无效", stage="proxy")
    if parsed.username is None and parsed.password is None:
        return value

    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    username = quote(unquote(parsed.username or ""), safe="-._~")
    auth = username
    if parsed.password is not None:
        auth = f"{auth}:{quote(unquote(parsed.password), safe='-._~')}"
    return urlunsplit(
        (parsed.scheme, f"{auth}@{host}", parsed.path, parsed.query, parsed.fragment)
    )


def derive_vn_proxy(proxy: str) -> str:
    """Rewrite country/region/zone selectors in proxy auth while retaining sticky data."""

    normalized = _normalize_proxy_url(proxy)
    parsed = urlsplit(normalized)
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    replacements = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal replacements
        replacements += 1
        current = match.group("value")
        country = "VN" if current.isupper() else "vn"
        return f"{match.group('name')}{match.group('separator')}{country}"

    username = _PROXY_COUNTRY_SELECTOR_RE.sub(replace, username)
    password = _PROXY_COUNTRY_SELECTOR_RE.sub(replace, password)
    if replacements == 0:
        raise MomoExtractionError(
            "代理认证信息未包含可改写的 country/region/zone 选择器",
            stage="proxy",
        )

    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    auth = quote(username, safe="-._~")
    if parsed.password is not None:
        auth = f"{auth}:{quote(password, safe='-._~')}"
    return urlunsplit(
        (parsed.scheme, f"{auth}@{host}", parsed.path, parsed.query, parsed.fragment)
    )


def proxy_chain_id(proxy: str) -> str:
    """Return a redacted identity which remains stable after the VN rewrite."""

    normalized = unquote(_normalize_proxy_url(proxy))
    without_country = _PROXY_COUNTRY_SELECTOR_RE.sub(
        lambda match: f"{match.group('name')}{match.group('separator')}*",
        normalized,
    )
    return hashlib.sha256(without_country.encode()).hexdigest()[:12]


def is_momo_gateway_url(url: str) -> bool:
    """Accept only the real MoMo v2 gateway URL with non-empty t/s values."""

    raw = str(url or "")
    if not raw or any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        return False
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return False
    if parsed.scheme.lower() != "https" or parsed.netloc.lower() != "payment.momo.vn":
        return False
    if parsed.path != "/v2/gateway/pay" or "#" in raw:
        return False
    if parsed.query.startswith("&") or parsed.query.endswith("&") or "&&" in parsed.query:
        return False
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if [key for key, _value in query] != ["t", "s"]:
        return False
    return all(
        value and not any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in value)
        for _key, value in query
    )


def first_value_by_key(payload: Any, key: str) -> Any:
    if isinstance(payload, dict):
        if key in payload:
            return payload[key]
        for value in payload.values():
            found = first_value_by_key(value, key)
            if found not in (None, "", [], {}):
                return found
    elif isinstance(payload, list):
        for item in payload:
            found = first_value_by_key(item, key)
            if found not in (None, "", [], {}):
                return found
    return None


def extract_next_action_redirect(payload: Any) -> str:
    """Read only a Stripe ``next_action.redirect_to_url`` value."""

    if isinstance(payload, dict):
        next_action = payload.get("next_action")
        if isinstance(next_action, dict):
            redirect = next_action.get("redirect_to_url")
            if isinstance(redirect, dict):
                value = str(redirect.get("url") or "").strip()
                if value.startswith(("https://", "http://")):
                    return value
            elif isinstance(redirect, str):
                value = redirect.strip()
                if value.startswith(("https://", "http://")):
                    return value
        for value in payload.values():
            found = extract_next_action_redirect(value)
            if found:
                return found
    elif isinstance(payload, list):
        for item in payload:
            found = extract_next_action_redirect(item)
            if found:
                return found
    return ""


def _collect_gateway_urls(text: str) -> list[str]:
    return [
        match.rstrip("),.;]")
        for match in re.findall(r"https?://[^\s\"'<>]+", str(text or ""))
        if is_momo_gateway_url(match.rstrip("),.;]"))
    ]


def _response_text(response: Any, limit: int = 500) -> str:
    return str(getattr(response, "text", "") or "")[:limit]


def _is_retryable_http_status(status_code: int) -> bool:
    return status_code in {403, 408, 425, 429} or status_code >= 500


def _raise_http_error(response: Any, *, label: str, stage: str) -> None:
    status_code = int(getattr(response, "status_code", 0) or 0)
    raise MomoExtractionError(
        f"{label} HTTP {status_code}: {_response_text(response)}",
        stage=stage,
        retryable=_is_retryable_http_status(status_code),
        http_status=status_code,
    )


def _response_json(response: Any, *, stage: str) -> dict[str, Any]:
    try:
        payload = response.json() or {}
    except Exception as exc:
        raise MomoExtractionError("响应不是有效 JSON", stage=stage) from exc
    if not isinstance(payload, dict):
        raise MomoExtractionError("响应 JSON 不是对象", stage=stage)
    return payload


def _amount_from_payload(payload: Any) -> int | None:
    if not isinstance(payload, dict):
        return None
    total = first_value_by_key(payload, "total_summary")
    if isinstance(total, dict) and total.get("due") is not None:
        try:
            return int(total.get("due") or 0)
        except (TypeError, ValueError):
            return None
    for key in ("amount_due", "amount_total", "checkout_amount", "amount"):
        value = first_value_by_key(payload, key)
        if value is not None:
            try:
                return int(value or 0)
            except (TypeError, ValueError):
                continue
    return None


def _submission_state(payload: Any) -> str:
    attempt = first_value_by_key(payload, "submission_attempt")
    if isinstance(attempt, dict):
        return str(attempt.get("state") or attempt.get("status") or "").lower()
    return ""


def _processor_entity(checkout: Mapping[str, Any]) -> str:
    return str(checkout.get("processor_entity") or "openai_ie")


def _checkout_page_url(checkout: Mapping[str, Any]) -> str:
    return (
        f"https://chatgpt.com/checkout/{_processor_entity(checkout)}/"
        f"{checkout['cs_id']}"
    )


def _stripe_browser_id() -> str:
    return f"{uuid.uuid4()}{uuid.uuid4().hex[:8]}"


def _elements_session_params(ctx: Mapping[str, Any]) -> dict[str, str]:
    return {
        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[session_id]": str(ctx["elements_session_id"]),
        "elements_session_client[stripe_js_id]": str(ctx["stripe_js_id"]),
        "elements_session_client[locale]": "vi",
        "elements_session_client[is_aggregation_expected]": "false",
        "elements_options_client[saved_payment_method][enable_save]": "never",
        "elements_options_client[saved_payment_method][enable_redisplay]": "never",
    }


class MomoExtractor:
    """Execute one non-rotating ChatGPT/Stripe MoMo extraction flow."""

    def __init__(
        self,
        *,
        access_token: str,
        proxy: str,
        pre_proxy: str = "",
        session_token: str = "",
        email: str = "",
        billing: Mapping[str, str] | None = None,
        stripe_publishable_key: str = "",
        proxy_is_vn: bool = False,
        promo_id: str = "plus-1-month-free",
        request_timeout: float = DEFAULT_TIMEOUT,
        poll_timeout: float = 45.0,
        poll_interval: float = 1.0,
        max_redirect_hops: int = 5,
        session_factory: Callable[[str, str], Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not str(access_token or "").strip():
            raise MomoExtractionError("access_token 为空", stage="input")
        self.access_token = str(access_token).strip()
        self.session_token = str(session_token or "").strip()
        self.proxy_seed = str(proxy or "").strip()
        self.proxy = (
            _normalize_proxy_url(self.proxy_seed)
            if proxy_is_vn
            else derive_vn_proxy(self.proxy_seed)
        )
        self.pre_proxy = _normalize_proxy_url(pre_proxy) if str(pre_proxy or "").strip() else ""
        if proxy_chain_id(self.proxy_seed) != proxy_chain_id(self.proxy):
            raise MomoExtractionError("VN 改写改变了 sticky session", stage="proxy")
        self.chain_id = proxy_chain_id(self.proxy)
        self.device_id = str(uuid.uuid4())
        self.stripe_publishable_key = str(stripe_publishable_key or "").strip()
        self.promo_id = str(promo_id or "plus-1-month-free").strip()
        self.request_timeout = max(1.0, float(request_timeout))
        self.poll_timeout = max(0.1, float(poll_timeout))
        self.poll_interval = max(0.0, float(poll_interval))
        self.max_redirect_hops = max(1, int(max_redirect_hops))
        self.session_factory = session_factory
        self.sleep = sleep
        self.billing = self._billing_profile(email=email, billing=billing)
        self.stage = "init"
        self.chatgpt: Any = None
        self.stripe: Any = None

    @staticmethod
    def _billing_profile(
        *, email: str, billing: Mapping[str, str] | None
    ) -> dict[str, str]:
        profile = {
            "email": str(email or "").strip() or f"momo.{uuid.uuid4().hex[:12]}@outlook.com",
            "name": "Nguyen Minh Anh",
            "country": "VN",
            "line1": "22 Nguyen Hue",
            "line2": "",
            "city": "Ho Chi Minh City",
            "postal_code": "700000",
            "state": "",
        }
        if billing:
            for key in profile:
                value = billing.get(key)
                if value not in (None, ""):
                    profile[key] = str(value).strip()
        profile["country"] = "VN"
        return profile

    def _new_session(self, role: str) -> Any:
        if self.session_factory is not None:
            session = self.session_factory(role, self.proxy)
        else:
            if curl_requests is None:
                raise MomoExtractionError(
                    "缺少 curl_cffi，无法启动本地 MoMo 协议会话", stage="session"
                )
            kwargs: dict[str, Any] = {"impersonate": "chrome136"}
            if self.pre_proxy:
                if CurlOpt is None:
                    raise MomoExtractionError(
                        "前置代理需要 curl_cffi CurlOpt.PRE_PROXY 支持",
                        stage="session",
                    )
                kwargs["curl_options"] = {CurlOpt.PRE_PROXY: self.pre_proxy}
            session = curl_requests.Session(**kwargs)
        if not hasattr(session, "headers"):
            session.headers = {}
        if hasattr(session, "trust_env"):
            session.trust_env = False
        self._pin_proxy(session)
        return session

    def _pin_proxy(self, session: Any) -> None:
        # Re-apply before every request: no stage may silently inherit env/direct mode.
        session.proxies = {"http": self.proxy, "https": self.proxy}

    def _request(self, session: Any, method: str, url: str, **kwargs: Any) -> Any:
        self._pin_proxy(session)
        try:
            return getattr(session, method.lower())(url, **kwargs)
        except MomoExtractionError:
            raise
        except Exception as exc:
            raise MomoExtractionError(
                str(exc), stage=self.stage, retryable=True
            ) from exc

    def _configure_sessions(self) -> None:
        self.chatgpt = self._new_session("chatgpt")
        self.stripe = self._new_session("stripe")
        cookie = f"oai-did={self.device_id}"
        if self.session_token:
            cookie += f"; __Secure-next-auth.session-token={self.session_token}"
        self.chatgpt.headers.update(
            {
                "User-Agent": DEFAULT_USER_AGENT,
                "Accept": "*/*",
                "Accept-Language": "vi-VN,vi;q=0.9,en;q=0.8",
                "Authorization": f"Bearer {self.access_token}",
                "Origin": "https://chatgpt.com",
                "Referer": "https://chatgpt.com/",
                "Content-Type": "application/json",
                "oai-device-id": self.device_id,
                "oai-language": "vi-VN",
                "oai-session-id": self.device_id,
                "oai-client-version": CHATGPT_CLIENT_VERSION,
                "oai-client-build-number": CHATGPT_CLIENT_BUILD_NUMBER,
                "sec-ch-ua": '"Safari";v="17", "Not.A/Brand";v="8"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"macOS"',
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "Cookie": cookie,
            }
        )
        self.stripe.headers.update(
            {
                "User-Agent": DEFAULT_USER_AGENT,
                "Accept-Language": "vi-VN,vi;q=0.9,en;q=0.8",
            }
        )

    def _create_checkout(self) -> dict[str, Any]:
        self.stage = "checkout"
        body = {
            "entry_point": "all_plans_pricing_modal",
            "plan_name": "chatgptplusplan",
            "billing_details": {"country": "VN", "currency": "VND"},
            "checkout_ui_mode": "custom",
            "promo_campaign": {
                "promo_campaign_id": self.promo_id,
                "is_coupon_from_query_param": False,
            },
        }
        response = self._request(
            self.chatgpt,
            "post",
            CHATGPT_CHECKOUT_URL,
            json=body,
            headers={
                "Referer": "https://chatgpt.com/",
                "x-openai-target-path": "/backend-api/payments/checkout",
                "x-openai-target-route": "/backend-api/payments/checkout",
            },
            timeout=CHATGPT_TIMEOUT,
        )
        if response.status_code >= 400:
            _raise_http_error(response, label="ChatGPT checkout", stage=self.stage)
        payload = _response_json(response, stage=self.stage)
        cs_id = payload.get("checkout_session_id") or payload.get("session_id") or payload.get("id")
        if not str(cs_id or "").startswith("cs_"):
            raise MomoExtractionError("checkout 响应缺少 cs_id", stage=self.stage)
        raw_key = (
            payload.get("stripe_publishable_key")
            or payload.get("publishable_key")
            or payload.get("publishableKey")
            or payload.get("stripePublishableKey")
            or payload.get("key")
            or self.stripe_publishable_key
            or os.getenv("STRIPE_PUBLISHABLE_KEY", "")
        )
        match = re.search(r"pk_live_[A-Za-z0-9]+", str(raw_key or ""))
        if not match:
            raise MomoExtractionError("checkout 响应缺少 Stripe publishable key", stage=self.stage)
        return {
            "cs_id": str(cs_id),
            "stripe_pk": match.group(0),
            "processor_entity": str(
                payload.get("processor_entity") or payload.get("processorEntity") or ""
            ),
            "billing_country": "VN",
            "currency": "vnd",
        }

    def _stripe_init(self, checkout: Mapping[str, Any], stage: str) -> dict[str, Any]:
        self.stage = stage
        stripe_js_id = str(uuid.uuid4())
        body = {
            "browser_locale": "vi-VN",
            "browser_timezone": "Asia/Ho_Chi_Minh",
            "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
            "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
            "elements_session_client[elements_init_source]": "custom_checkout",
            "elements_session_client[referrer_host]": "chatgpt.com",
            "elements_session_client[stripe_js_id]": stripe_js_id,
            "elements_session_client[locale]": "vi",
            "elements_session_client[is_aggregation_expected]": "false",
            "elements_options_client[saved_payment_method][enable_save]": "never",
            "elements_options_client[saved_payment_method][enable_redisplay]": "never",
            "key": checkout["stripe_pk"],
            "_stripe_version": STRIPE_VERSION,
        }
        url = f"{STRIPE_API_BASE}/payment_pages/{checkout['cs_id']}/init"
        response = self._request(
            self.stripe, "post", url, data=body, timeout=self.request_timeout
        )
        if response.status_code >= 400:
            _raise_http_error(response, label="Stripe init", stage=self.stage)
        payload = _response_json(response, stage=self.stage)
        payload["_client_context"] = {"stripe_js_id": stripe_js_id}
        return payload

    def _inspect_init(self, payload: Mapping[str, Any], stage: str) -> dict[str, Any]:
        raw_methods = first_value_by_key(payload, "payment_method_types")
        currency = str(first_value_by_key(payload, "currency") or "").strip().lower()
        amount = _amount_from_payload(payload)
        methods: list[str] | None
        if isinstance(raw_methods, list):
            methods = list(
                dict.fromkeys(
                    str(value).strip().lower()
                    for value in raw_methods
                    if str(value).strip()
                )
            )
        else:
            methods = None
        if methods is None:
            raise MomoExtractionError(
                "Stripe init 未返回 payment_method_types 列表",
                stage=stage,
            )
        if currency != "vnd":
            raise MomoExtractionError(
                f"MoMo Checkout 币种不是 VND: {currency or 'unknown'}",
                stage=stage,
            )
        if "momo" not in methods:
            raise MomoUnavailableError(
                "当前账号或 Checkout 未提供 MoMo",
                stage=stage,
                methods=methods,
                currency=currency,
                amount=amount,
            )
        return {"methods": methods, "currency": currency, "amount": amount}

    def _update_checkout(self, checkout: Mapping[str, Any]) -> None:
        self.stage = "checkout_update"
        body = {
            "checkout_session_id": checkout["cs_id"],
            "processor_entity": _processor_entity(checkout),
            "plan_name": "chatgptplusplan",
            "price_interval": "month",
            "seat_quantity": 1,
            "promo_campaign": {
                "promo_campaign_id": self.promo_id,
                "is_coupon_from_query_param": False,
            },
        }
        response = self._request(
            self.chatgpt,
            "post",
            CHATGPT_CHECKOUT_UPDATE_URL,
            json=body,
            headers={
                "Referer": _checkout_page_url(checkout),
                "x-openai-target-path": "/backend-api/payments/checkout/update",
                "x-openai-target-route": "/backend-api/payments/checkout/update",
            },
            timeout=CHATGPT_TIMEOUT,
        )
        if response.status_code >= 400:
            _raise_http_error(response, label="checkout/update", stage=self.stage)
        payload = _response_json(response, stage=self.stage)
        if payload.get("success") is False:
            raise MomoExtractionError("checkout/update rejected", stage=self.stage)

    def _build_ctx(
        self, init_payload: Mapping[str, Any], checkout: Mapping[str, Any]
    ) -> dict[str, Any]:
        client_context = init_payload.get("_client_context")
        if not isinstance(client_context, dict):
            client_context = {}
        return {
            "stripe_js_id": str(client_context.get("stripe_js_id") or uuid.uuid4()),
            "client_session_id": str(uuid.uuid4()),
            "guid": _stripe_browser_id(),
            "muid": _stripe_browser_id(),
            "sid": _stripe_browser_id(),
            "elements_session_id": f"elements_session_{uuid.uuid4().hex[:11]}",
            "elements_session_config_id": str(init_payload.get("config_id") or uuid.uuid4()),
            "config_id": str(init_payload.get("config_id") or ""),
            "init_checksum": str(init_payload.get("init_checksum") or ""),
            "checkout_amount": _amount_from_payload(init_payload) or 0,
            "currency": str(first_value_by_key(init_payload, "currency") or "vnd").lower(),
            "runtime_version": STRIPE_RUNTIME_VERSION,
            "stripe_version": STRIPE_VERSION,
        }

    def _confirm_return_url(
        self, checkout: Mapping[str, Any], init_payload: Mapping[str, Any]
    ) -> str:
        cs_id = str(checkout["cs_id"])
        hosted = str(init_payload.get("stripe_hosted_url") or "").strip()
        processor = _processor_entity(checkout)
        success = (
            "https://chatgpt.com/checkout/verify?stripe_session_id="
            f"{cs_id}&processor_entity={processor}&plan_type=plus"
        )
        if not hosted:
            hosted = (
                f"https://checkout.stripe.com/c/pay/{cs_id}"
                f"?returned_from_redirect=true&ui_mode=custom&return_url={quote(success, safe='')}"
            )
        parsed = urlsplit(hosted)
        if parsed.netloc.lower() == "checkout.stripe.com":
            hosted = urlunsplit(
                (parsed.scheme or "https", "pay.openai.com", parsed.path, parsed.query, parsed.fragment)
            )
        if "pay.openai.com/" in hosted or "checkout.stripe.com/" in hosted:
            parsed = urlsplit(hosted)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query.setdefault("success_return_url", success)
            return urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)
            )
        return hosted

    def _inline_payment_method_data(
        self, checkout: Mapping[str, Any], ctx: Mapping[str, Any]
    ) -> dict[str, str]:
        billing = self.billing
        values = {
            "payment_method_data[type]": "momo",
            "payment_method_data[allow_redisplay]": "limited",
            "payment_method_data[billing_details][name]": billing["name"],
            "payment_method_data[billing_details][email]": billing["email"],
            "payment_method_data[billing_details][address][country]": "VN",
            "payment_method_data[billing_details][address][line1]": billing["line1"],
            "payment_method_data[billing_details][address][city]": billing["city"],
            "payment_method_data[billing_details][address][postal_code]": billing["postal_code"],
            "payment_method_data[payment_user_agent]": (
                f"stripe.js/{STRIPE_RUNTIME_VERSION}; stripe-js-v3/{STRIPE_RUNTIME_VERSION}; "
                "payment-element; deferred-intent"
            ),
            "payment_method_data[referrer]": "https://chatgpt.com",
            "payment_method_data[time_on_page]": "25000",
            "payment_method_data[client_attribution_metadata][checkout_session_id]": str(
                checkout["cs_id"]
            ),
            "payment_method_data[client_attribution_metadata][client_session_id]": str(
                ctx["stripe_js_id"]
            ),
            "payment_method_data[client_attribution_metadata][checkout_config_id]": str(
                ctx.get("config_id") or ""
            ),
            "payment_method_data[client_attribution_metadata][elements_session_id]": str(
                ctx["elements_session_id"]
            ),
            "payment_method_data[client_attribution_metadata][elements_session_config_id]": str(
                ctx["elements_session_config_id"]
            ),
            "payment_method_data[client_attribution_metadata][merchant_integration_source]": "elements",
            "payment_method_data[client_attribution_metadata][merchant_integration_subtype]": "payment-element",
            "payment_method_data[client_attribution_metadata][merchant_integration_version]": "2021",
            "payment_method_data[client_attribution_metadata][payment_intent_creation_flow]": "deferred",
            "payment_method_data[client_attribution_metadata][payment_method_selection_flow]": "automatic",
            "payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][0]": "expressCheckout",
            "payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][1]": "payment",
            "payment_method_data[client_attribution_metadata][merchant_integration_additional_elements][2]": "address",
        }
        if billing.get("state"):
            values["payment_method_data[billing_details][address][state]"] = billing["state"]
        return values

    def _create_standalone_pm(
        self, checkout: Mapping[str, Any]
    ) -> str:
        self.stage = "stripe_payment_method"
        billing = self.billing
        body = {
            "billing_details[name]": billing["name"],
            "billing_details[email]": billing["email"],
            "billing_details[address][country]": "VN",
            "billing_details[address][line1]": billing["line1"],
            "billing_details[address][city]": billing["city"],
            "billing_details[address][postal_code]": billing["postal_code"],
            "type": "momo",
            "client_attribution_metadata[checkout_session_id]": checkout["cs_id"],
            "key": checkout["stripe_pk"],
        }
        response = self._request(
            self.stripe,
            "post",
            f"{STRIPE_API_BASE}/payment_methods",
            data=body,
            timeout=self.request_timeout,
        )
        if response.status_code >= 400:
            _raise_http_error(
                response, label="创建 MoMo PaymentMethod", stage=self.stage
            )
        pm_id = str(_response_json(response, stage=self.stage).get("id") or "")
        if not pm_id.startswith("pm_"):
            raise MomoExtractionError("MoMo PaymentMethod 响应缺少 pm_id", stage=self.stage)
        return pm_id

    def _confirm(
        self,
        checkout: Mapping[str, Any],
        init_payload: Mapping[str, Any],
        ctx: Mapping[str, Any],
    ) -> tuple[dict[str, Any], str]:
        self.stage = "stripe_confirm"
        body: dict[str, Any] = {
            "eid": "NA",
            "expected_amount": str(ctx.get("checkout_amount") or 0),
            "expected_payment_method_type": "momo",
            "return_url": self._confirm_return_url(checkout, init_payload),
            "_stripe_version": STRIPE_VERSION,
            "guid": ctx["guid"],
            "muid": ctx["muid"],
            "sid": ctx["sid"],
            "key": checkout["stripe_pk"],
            "version": STRIPE_RUNTIME_VERSION,
            "init_checksum": str(init_payload.get("init_checksum") or ctx.get("init_checksum") or ""),
            "client_attribution_metadata[client_session_id]": ctx["client_session_id"],
            "client_attribution_metadata[checkout_session_id]": checkout["cs_id"],
            "client_attribution_metadata[checkout_config_id]": ctx.get("config_id") or "",
            "client_attribution_metadata[merchant_integration_source]": "checkout",
            "client_attribution_metadata[merchant_integration_subtype]": "payment-element",
            "client_attribution_metadata[merchant_integration_version]": "custom_checkout",
            "client_attribution_metadata[payment_intent_creation_flow]": "deferred",
            "client_attribution_metadata[payment_method_selection_flow]": "automatic",
            "client_attribution_metadata[elements_session_id]": ctx["elements_session_id"],
            "client_attribution_metadata[elements_session_config_id]": ctx[
                "elements_session_config_id"
            ],
            "client_attribution_metadata[merchant_integration_additional_elements][0]": "payment",
            "client_attribution_metadata[merchant_integration_additional_elements][1]": "address",
            "consent[terms_of_service]": "accepted",
            "link_brand": "link",
        }
        body.update(_elements_session_params(ctx))
        body.update(self._inline_payment_method_data(checkout, ctx))
        url = f"{STRIPE_API_BASE}/payment_pages/{checkout['cs_id']}/confirm"
        response = self._request(
            self.stripe, "post", url, data=body, timeout=self.request_timeout
        )
        pm_id = ""
        if response.status_code >= 400:
            if _is_retryable_http_status(int(response.status_code)):
                _raise_http_error(response, label="MoMo confirm", stage=self.stage)
            pm_id = self._create_standalone_pm(checkout)
            self.stage = "stripe_confirm_fallback"
            body = {
                key: value
                for key, value in body.items()
                if not key.startswith("payment_method_data[")
            }
            body["payment_method"] = pm_id
            response = self._request(
                self.stripe, "post", url, data=body, timeout=self.request_timeout
            )
        if response.status_code >= 400:
            _raise_http_error(response, label="MoMo confirm", stage=self.stage)
        return _response_json(response, stage=self.stage), pm_id

    def _approve(self, checkout: Mapping[str, Any]) -> None:
        self.stage = "checkout_approve"
        body = {
            "checkout_session_id": checkout["cs_id"],
            "processor_entity": _processor_entity(checkout),
        }
        response = self._request(
            self.chatgpt,
            "post",
            CHATGPT_CHECKOUT_APPROVE_URL,
            json=body,
            headers={
                "Referer": _checkout_page_url(checkout),
                "x-openai-target-path": "/backend-api/payments/checkout/approve",
                "x-openai-target-route": "/backend-api/payments/checkout/approve",
            },
            timeout=CHATGPT_TIMEOUT,
        )
        if response.status_code >= 400:
            _raise_http_error(response, label="checkout/approve", stage=self.stage)
        payload = _response_json(response, stage=self.stage)
        if str(payload.get("result") or "") != "approved":
            raise MomoExtractionError(
                f"checkout/approve 未通过: {payload.get('result') or 'unknown'}",
                stage=self.stage,
            )

    @staticmethod
    def _raise_intent_error(payload: Any, stage: str) -> None:
        error = first_value_by_key(payload, "last_setup_error")
        if error in (None, "", {}, []):
            return
        raise MomoExtractionError(f"SetupIntent failed: {error}", stage=stage)

    def _setup_intent_redirect(
        self,
        payload: Mapping[str, Any],
        checkout: Mapping[str, Any],
        *,
        timeout: float | None = None,
    ) -> str:
        setup_intent = first_value_by_key(payload, "setup_intent")
        intent_id = ""
        client_secret = ""
        if isinstance(setup_intent, dict):
            direct = extract_next_action_redirect(setup_intent)
            if direct:
                return direct
            intent_id = str(setup_intent.get("id") or "").strip()
            client_secret = str(setup_intent.get("client_secret") or "").strip()
        elif isinstance(setup_intent, str):
            intent_id = setup_intent.strip()
            client_secret = str(
                first_value_by_key(payload, "setup_intent_client_secret")
                or first_value_by_key(payload, "client_secret")
                or ""
            ).strip()
        if not intent_id.startswith("seti_") or not client_secret:
            return ""
        request_timeout = self.request_timeout
        if timeout is not None:
            if timeout <= 0:
                return ""
            request_timeout = max(0.001, min(request_timeout, timeout))

        self.stage = "stripe_setup_intent"
        response = self._request(
            self.stripe,
            "get",
            f"{STRIPE_API_BASE}/setup_intents/{intent_id}",
            params={"key": checkout["stripe_pk"], "client_secret": client_secret},
            timeout=request_timeout,
        )
        if response.status_code >= 400:
            if _is_retryable_http_status(int(response.status_code)):
                _raise_http_error(response, label="SetupIntent", stage=self.stage)
            return ""
        intent_payload = _response_json(response, stage=self.stage)
        self._raise_intent_error(intent_payload, self.stage)
        return extract_next_action_redirect(intent_payload)

    def _poll_payment_page(
        self,
        checkout: Mapping[str, Any],
        ctx: Mapping[str, Any],
        *,
        approval_done: bool,
    ) -> tuple[str, bool]:
        max_attempts = max(
            1,
            int(math.ceil(self.poll_timeout / max(self.poll_interval, 0.1))),
        )
        deadline = time.monotonic() + self.poll_timeout
        params = {
            **_elements_session_params(ctx),
            "key": checkout["stripe_pk"],
            "_stripe_version": STRIPE_VERSION,
        }
        url = f"{STRIPE_API_BASE}/payment_pages/{checkout['cs_id']}"
        last_state = "waiting"
        for attempt in range(max_attempts):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self.stage = "stripe_poll"
            response = self._request(
                self.stripe,
                "get",
                url,
                params=params,
                timeout=max(0.001, min(self.request_timeout, remaining)),
            )
            if response.status_code < 400:
                payload = _response_json(response, stage=self.stage)
                self._raise_intent_error(payload, self.stage)
                redirect = extract_next_action_redirect(payload)
                if redirect:
                    return redirect, approval_done
                redirect = self._setup_intent_redirect(
                    payload,
                    checkout,
                    timeout=deadline - time.monotonic(),
                )
                if redirect:
                    return redirect, approval_done
                state = _submission_state(payload)
                last_state = state or "waiting"
                if state == "requires_approval" and not approval_done:
                    raise _ApprovalRequired
                if state == "failed":
                    raise MomoExtractionError(
                        "Stripe submission failed", stage="stripe_poll"
                    )
            else:
                if _is_retryable_http_status(int(response.status_code)):
                    _raise_http_error(response, label="Stripe poll", stage=self.stage)
                last_state = f"HTTP {response.status_code}"
            if attempt + 1 < max_attempts and self.poll_interval:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.sleep(min(self.poll_interval, remaining))
        raise MomoExtractionError(
            f"redirect url resolution timeout: {last_state}", stage="stripe_poll"
        )

    def _resolve_external_redirect(self, start_url: str) -> str:
        current = str(start_url or "").strip()
        for _ in range(self.max_redirect_hops + 1):
            if is_momo_gateway_url(current):
                return current
            try:
                parsed = urlsplit(current)
            except ValueError:
                return ""
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
                return ""
            self.stage = "redirect"
            response = self._request(
                self.stripe,
                "get",
                current,
                timeout=self.request_timeout,
                allow_redirects=False,
                headers={
                    "Referer": "https://checkout.stripe.com/",
                    "Sec-Fetch-Site": "cross-site",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Dest": "document",
                },
            )
            if response.status_code >= 400 and _is_retryable_http_status(
                int(response.status_code)
            ):
                _raise_http_error(response, label="Stripe redirect", stage=self.stage)
            location = str(
                (getattr(response, "headers", {}) or {}).get("location")
                or (getattr(response, "headers", {}) or {}).get("Location")
                or ""
            ).strip()
            if location:
                current = urljoin(current, location)
                continue
            candidates = _collect_gateway_urls(_response_text(response, limit=100_000))
            return candidates[0] if candidates else ""
        return ""

    def run(self) -> dict[str, Any]:
        """Run the flow once and return a structure suitable for account service storage."""

        self._configure_sessions()
        approval_done = False
        try:
            checkout = self._create_checkout()
            first_init = self._stripe_init(checkout, "stripe_init")
            self._inspect_init(first_init, "stripe_init")

            self._update_checkout(checkout)
            final_init = self._stripe_init(checkout, "stripe_init_after_update")
            summary = self._inspect_init(final_init, "stripe_init_after_update")
            ctx = self._build_ctx(final_init, checkout)

            confirm_payload, pm_id = self._confirm(checkout, final_init, ctx)
            state = _submission_state(confirm_payload)
            if state == "failed":
                raise MomoExtractionError(
                    "Stripe submission failed", stage="stripe_confirm"
                )

            if state == "requires_approval":
                self._approve(checkout)
                approval_done = True
                redirect_url, approval_done = self._poll_payment_page(
                    checkout, ctx, approval_done=approval_done
                )
            else:
                redirect_url = extract_next_action_redirect(confirm_payload)
                if not redirect_url:
                    redirect_url = self._setup_intent_redirect(confirm_payload, checkout)
                if not redirect_url:
                    try:
                        redirect_url, approval_done = self._poll_payment_page(
                            checkout, ctx, approval_done=approval_done
                        )
                    except _ApprovalRequired:
                        self._approve(checkout)
                        approval_done = True
                        redirect_url, approval_done = self._poll_payment_page(
                            checkout, ctx, approval_done=approval_done
                        )

            final_url = self._resolve_external_redirect(redirect_url)
            if not final_url:
                raise MomoExtractionError(
                    "Stripe next_action 未解析到有效 MoMo 网关 URL",
                    stage="redirect",
                )
            return {
                "long_url": final_url,
                "payment_method": "momo",
                "payment_link_type": "momo",
                "currency": summary["currency"],
                "methods": summary["methods"],
                "amount": summary["amount"],
                "checkout_session_id": checkout["cs_id"],
                "approval_performed": approval_done,
                "payment_method_id": pm_id,
                "proxy_chain_id": self.chain_id,
            }
        except MomoUnavailableError:
            raise
        except MomoExtractionError:
            raise
        except _ApprovalRequired as exc:
            raise MomoExtractionError(
                "Stripe 重复要求 checkout approval", stage="stripe_poll"
            ) from exc
        except Exception as exc:
            raise MomoExtractionError(str(exc), stage=self.stage) from exc
        finally:
            seen: set[int] = set()
            for session in (self.chatgpt, self.stripe):
                if session is None or id(session) in seen:
                    continue
                seen.add(id(session))
                try:
                    session.close()
                except Exception:
                    pass


def extract_momo_link(
    *,
    access_token: str,
    proxy: str,
    pre_proxy: str = "",
    session_token: str = "",
    email: str = "",
    billing: Mapping[str, str] | None = None,
    stripe_publishable_key: str = "",
    proxy_is_vn: bool = False,
    promo_id: str = "plus-1-month-free",
    request_timeout: float = DEFAULT_TIMEOUT,
    poll_timeout: float = 45.0,
    poll_interval: float = 1.0,
    max_redirect_hops: int = 5,
    session_factory: Callable[[str, str], Any] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Public one-shot MoMo extraction entry point used by account services."""

    return MomoExtractor(
        access_token=access_token,
        proxy=proxy,
        pre_proxy=pre_proxy,
        session_token=session_token,
        email=email,
        billing=billing,
        stripe_publishable_key=stripe_publishable_key,
        proxy_is_vn=proxy_is_vn,
        promo_id=promo_id,
        request_timeout=request_timeout,
        poll_timeout=poll_timeout,
        poll_interval=poll_interval,
        max_redirect_hops=max_redirect_hops,
        session_factory=session_factory,
        sleep=sleep,
    ).run()


__all__ = [
    "MomoExtractionError",
    "MomoUnavailableError",
    "MomoExtractor",
    "derive_vn_proxy",
    "extract_momo_link",
    "extract_next_action_redirect",
    "is_momo_gateway_url",
    "proxy_chain_id",
]
