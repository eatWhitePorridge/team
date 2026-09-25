# -*- coding: utf-8 -*-
"""ChatGPT Web 的低流量 bootstrap 链路。

请求顺序和字段来自 2026-08-12 的完整注册 HAR。这里只复现会改变首页、账号、
定价或 Sentinel 状态的 JSON 请求；静态资源、Datadog/RUM、图片和通知请求不复制。
"""
from __future__ import annotations

import json
import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Callable, Iterable

from config import CHATGPT_SENTINEL_SV
from core.chatgpt_plan import (
    DEFAULT_PLUS_PROMO,
    now_iso,
    annotate_promo_state,
    parse_accounts_check,
    parse_coupon_check,
)
from core.ces_telemetry import (
    begin_authenticated_identity,
    emit_sync_anonymous,
    emit_sync_authenticated,
    prime_sync_settings,
)
from core.sentinel_runner import (
    generate_chat_requirements_artifacts,
    generate_sentinel_prepare_token,
    load_sentinel_sdk_from_frame,
    load_sentinel_sdk_from_url,
)
from core.session import BrowserSession

logger = logging.getLogger(__name__)

_ANON_BASE = "https://chatgpt.com/backend-anon"
_API_BASE = "https://chatgpt.com/backend-api"
_OBI_SYNC_URL = "https://bzr.openai.com/v1/obi/sync"
_PAGE_URL = "https://chatgpt.com/"
_BILLING_PAGE_CONFIG_PATH = "/backend-api/pageConfigs/billing"
_APP_STORE_BILLING_RETRY_PATH = (
    "/backend-api/subscriptions/has_app_store_subscription_in_billing_retry"
)
_CHATGPT_SENTINEL_FRAME_URL = (
    "https://chatgpt.com/backend-api/sentinel/frame.html"
)
_CHATGPT_SENTINEL_SDK_URL = (
    f"https://chatgpt.com/sentinel/{CHATGPT_SENTINEL_SV}/sdk.js"
)


@dataclass(slots=True)
class _ChatRequirementsState:
    challenge: dict
    requirements_token: str
    sdk_url: str
    sdk_source: str
    sdk_hash: str


@dataclass(frozen=True, slots=True)
class AnonymousBootstrapResult:
    country: str
    region: str
    region_code: str
    obi_synced: bool


@dataclass(frozen=True, slots=True)
class AuthenticatedBootstrapResult:
    country: str
    region: str
    plan_type: str
    plus_trial_eligible: bool
    campaign_id: str
    obi_synced: bool
    promo_state: str = ""
    promo_redeemed: bool = False
    promo_check_ok: bool = False


class AnonymousBootstrapRetryableError(RuntimeError):
    """匿名 bootstrap 的当前出口不可继续，应在提交邮箱前更换会话。"""


def _edge_rejection_status(exc: Exception) -> int:
    match = re.search(
        r"(?i)\b(?:http|status)\s*[=:]?\s*(403|429)\b",
        str(exc or ""),
    )
    return int(match.group(1)) if match else 0


def _json_post(
    session: BrowserSession,
    url: str,
    payload: dict,
    *,
    headers: dict,
):
    return session.post(
        url,
        headers=headers,
        data=json.dumps(payload, separators=(",", ":")),
    )


def _safe_request(
    label: str,
    fn: Callable,
    *,
    strict: bool = False,
    retry_edge: bool = False,
):
    try:
        result = fn()
        status = int(getattr(result, "status_code", 0) or 0)
        if status >= 400:
            raise RuntimeError(
                f"HTTP {status}: {(getattr(result, 'text', '') or '')[:180]}"
            )
        return result
    except Exception as exc:
        edge_status = _edge_rejection_status(exc)
        if retry_edge and edge_status:
            raise AnonymousBootstrapRetryableError(
                f"匿名 bootstrap {label} HTTP {edge_status}"
            ) from exc
        if strict:
            raise
        logger.debug(
            "[Bootstrap] %s 跳过/失败：%s: %s",
            label,
            type(exc).__name__,
            str(exc)[:180],
        )
        return None


def _get(
    session: BrowserSession,
    url: str,
    headers: Callable[[], dict],
    *,
    strict: bool,
    retry_edge: bool = False,
):
    return _safe_request(
        url,
        lambda: session.get(url, headers=headers()),
        strict=strict,
        retry_edge=retry_edge,
    )


def _post(
    session: BrowserSession,
    url: str,
    payload: dict,
    headers: Callable[[], dict],
    *,
    strict: bool,
    retry_edge: bool = False,
):
    def post_headers() -> dict:
        value = headers()
        value["content-type"] = "application/json"
        value["origin"] = "https://chatgpt.com"
        return value

    return _safe_request(
        url,
        lambda: _json_post(session, url, payload, headers=post_headers()),
        strict=strict,
        retry_edge=retry_edge,
    )


def _response_json(response) -> dict:
    if response is None:
        return {}
    try:
        value = response.json()
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _response_digest(response) -> tuple[int, str]:
    if response is None:
        return 0, ""
    body = getattr(response, "content", None)
    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")
    if not isinstance(body, (bytes, bytearray)):
        body = str(getattr(response, "text", "") or "").encode(
            "utf-8", errors="replace"
        )
    raw = bytes(body)
    return len(raw), hashlib.sha256(raw).hexdigest()[:16]


def _promo_keys(payload: dict) -> list[str]:
    accounts = payload.get("accounts") if isinstance(payload, dict) else None
    if not isinstance(accounts, dict):
        return []
    candidates = []
    if isinstance(accounts.get("default"), dict):
        candidates.append(accounts["default"])
    candidates.extend(
        item
        for key, item in accounts.items()
        if key != "default" and isinstance(item, dict)
    )
    for item in candidates:
        promos = item.get("eligible_promo_campaigns") or {}
        if isinstance(promos, dict):
            return sorted(str(key) for key in promos if str(key))
    return []


def _parse_accounts_response(
    response,
    *,
    access_token: str | None,
    country: str,
    region: str,
    phase: str,
    strict: bool,
    auth_mode: str = "unknown",
) -> dict:
    payload = _response_json(response)
    body_bytes, body_sha256 = _response_digest(response)
    status = int(getattr(response, "status_code", 0) or 0) if response else 0
    plan = {}
    if payload:
        try:
            plan = parse_accounts_check(payload, token=access_token or "")
        except Exception as exc:
            if strict:
                raise
            logger.warning(
                "[Bootstrap][资格:%s] accounts/check 解析失败: %s: %s",
                phase,
                type(exc).__name__,
                str(exc)[:180],
            )
    if plan:
        plan.update({
            "http_status": status,
            "network_route": "registration_session",
            "proxy_mode": "registration_session",
            "country": country,
            "region": region,
            "check_phase": phase,
            "accounts_check_auth_mode": auth_mode,
            "response_bytes": body_bytes,
            "response_sha256": body_sha256,
        })
        if access_token and str(plan.get("current_plan_type") or "").lower() == "guest":
            plan.update({
                "ok": False,
                "error_type": "auth_context_error",
                "error": "登录态 accounts/check 返回 guest，未识别 Web AT",
            })
            logger.warning(
                "[Bootstrap][资格:%s] 登录态携带 Web AT 后仍返回 guest，"
                "不保存该匿名结果，后续回退独立 AT 查询",
                phase,
            )
    logger.info(
        "[Bootstrap][资格:%s] status=%s auth=%s bytes=%s sha256=%s "
        "promo_keys=%s plan=%s plus_trial=%s campaign=%s",
        phase,
        status or "无",
        auth_mode,
        body_bytes,
        body_sha256 or "无",
        _promo_keys(payload) or [],
        plan.get("current_plan_type") or "未知",
        bool(plan.get("plus_trial_eligible")),
        plan.get("plus_trial_campaign_id") or "无",
    )
    return plan


def _authenticated_coupon_check(
    session: BrowserSession,
    campaign_id: str,
    headers: Callable[[], dict],
    *,
    strict: bool,
) -> dict:
    """读取 Web billing 页使用的 campaign 状态。

    这是资格诊断，不是兑换动作。任何失败都作为独立字段返回，不覆盖
    ``accounts/check`` 已经确认的套餐和试用资格。
    """
    campaign = str(campaign_id or DEFAULT_PLUS_PROMO).strip() or DEFAULT_PLUS_PROMO
    from urllib.parse import quote

    url = (
        f"{_API_BASE}/promo_campaign/check_coupon?coupon={quote(campaign, safe='')}"
        "&is_coupon_from_query_param=true"
    )
    def coupon_headers() -> dict:
        value = headers()
        value["x-openai-target-path"] = "/backend-api/promo_campaign/check_coupon"
        value["x-openai-target-route"] = "/backend-api/promo_campaign/check_coupon"
        value["referer"] = (
            "https://chatgpt.com/?promo_campaign=" + quote(campaign, safe="")
        )
        return value

    # Do not use ``_get`` here: it deliberately turns HTTP >= 400 into None,
    # while this diagnostic must retain the concrete 403/429 evidence.
    try:
        response = session.get(url, headers=coupon_headers())
    except Exception as exc:
        return {
            "promo_check_ok": False,
            "promo_check_http_status": None,
            "promo_check_error": f"{type(exc).__name__}: {str(exc)[:400]}",
            "promo_error_type": type(exc).__name__,
            "promo_retryable": True,
            "promo_checked_at": now_iso(),
        }
    status = int(getattr(response, "status_code", 0) or 0)
    response_text = str(getattr(response, "text", "") or "")
    body_bytes, body_sha256 = _response_digest(response)
    response_headers = getattr(response, "headers", {}) or {}
    retry_after = str(response_headers.get("retry-after") or "").strip() or None
    payload = _response_json(response)
    if status < 200 or status >= 300:
        return {
            "promo_check_ok": False,
            "promo_check_http_status": status,
            "promo_check_error": f"HTTP {status}",
            "promo_response_preview": response_text[:500],
            "promo_response_bytes": body_bytes,
            "promo_response_sha256": body_sha256,
            "promo_retry_after": retry_after,
            "promo_retryable": status in {408, 409, 425, 429} or status >= 500,
            "promo_checked_at": now_iso(),
        }
    if not payload:
        return {
            "promo_check_ok": False,
            "promo_check_http_status": status,
            "promo_check_error": "优惠资格接口响应为空或不是 JSON 对象",
            "promo_response_preview": response_text[:500],
            "promo_response_bytes": body_bytes,
            "promo_response_sha256": body_sha256,
            "promo_retryable": True,
            "promo_checked_at": now_iso(),
        }
    result = parse_coupon_check(payload, campaign_id=campaign)
    result.update({
        "promo_check_ok": True,
        "promo_check_http_status": status,
        "promo_response_bytes": body_bytes,
        "promo_response_sha256": body_sha256,
        "promo_retry_after": retry_after,
        "promo_retryable": False,
        "promo_checked_at": now_iso(),
    })
    logger.info(
        "[Bootstrap][优惠] campaign=%s state=%s redeemed=%s",
        result.get("promo_coupon") or campaign,
        result.get("promo_state") or "unknown",
        bool(result.get("promo_redeemed")),
    )
    return result


def _authenticated_billing_probe(
    session: BrowserSession,
    headers: Callable[[], dict],
) -> dict:
    """Read the two small billing-page probes present in the Web HAR.

    These calls describe whether the billing surface is available; they do not
    redeem a campaign and must never change the authoritative plan value.
    Keeping their status separately makes a 403/edge response distinguishable
    from a genuine ``eligible=false`` response.
    """

    def request(path: str, referer: str) -> tuple[object | None, dict]:
        url = f"{_API_BASE}{path}"
        request_headers = headers()
        request_headers["x-openai-target-path"] = path
        request_headers["x-openai-target-route"] = path
        request_headers["referer"] = referer
        try:
            response = session.get(url, headers=request_headers)
        except Exception as exc:
            return None, {
                "ok": False,
                "http_status": None,
                "error": f"{type(exc).__name__}: {str(exc)[:400]}",
            }
        status = int(getattr(response, "status_code", 0) or 0)
        payload = _response_json(response)
        return response, {
            "ok": 200 <= status < 300 and isinstance(payload, dict),
            "http_status": status,
            "payload": payload,
            "error": None if 200 <= status < 300 else f"HTTP {status}",
            "preview": str(getattr(response, "text", "") or "")[:500],
        }

    billing_response, billing = request(_BILLING_PAGE_CONFIG_PATH, _PAGE_URL)
    retry_response, retry = request(
        _APP_STORE_BILLING_RETRY_PATH,
        "https://chatgpt.com/?promo_campaign=" + DEFAULT_PLUS_PROMO,
    )
    billing_payload = billing.get("payload") if isinstance(billing, dict) else {}
    account_gate = billing_payload.get("account") if isinstance(billing_payload, dict) else {}
    plan_gate = billing_payload.get("plan_management") if isinstance(billing_payload, dict) else {}
    upgrade_gate = billing_payload.get("free_workspace_upgrade") if isinstance(billing_payload, dict) else {}
    retry_payload = retry.get("payload") if isinstance(retry, dict) else {}
    return {
        "billing_page_config_ok": bool(billing.get("ok")),
        "billing_page_config_http_status": billing.get("http_status"),
        "billing_page_config_error": billing.get("error"),
        "billing_account_eligible": (
            bool(account_gate.get("eligible")) if isinstance(account_gate, dict) else None
        ),
        "billing_plan_management_eligible": (
            bool(plan_gate.get("eligible")) if isinstance(plan_gate, dict) else None
        ),
        "billing_free_workspace_upgrade_eligible": (
            bool(upgrade_gate.get("eligible")) if isinstance(upgrade_gate, dict) else None
        ),
        "billing_page_config_preview": billing.get("preview"),
        "app_store_billing_retry_check_ok": bool(retry.get("ok")),
        "app_store_billing_retry_http_status": retry.get("http_status"),
        "app_store_billing_retry_error": retry.get("error"),
        "app_store_subscription_in_billing_retry": (
            bool(retry_payload.get("value"))
            if isinstance(retry_payload, dict) and "value" in retry_payload
            else None
        ),
        "app_store_billing_retry_preview": retry.get("preview"),
    }


def _accounts_plan_usable(plan: dict) -> bool:
    """判断 Cookie-only 的 accounts/check 是否已经识别到真实账号。"""
    if not isinstance(plan, dict) or not plan.get("ok"):
        return False
    plan_type = str(plan.get("current_plan_type") or "").strip().lower()
    return bool(plan_type and plan_type != "guest")


def _mark_accounts_auth_context_error(plan: dict, *, message: str) -> dict:
    """把仅返回 guest 的 Cookie 结果标为不可落库的认证上下文错误。"""
    out = dict(plan or {})
    out.update({
        "ok": False,
        "error_type": "auth_context_error",
        "error": message,
    })
    return out


def _authenticated_accounts_check(
    session: BrowserSession,
    url: str,
    *,
    access_token: str | None,
    country: str,
    region: str,
    phase: str,
    cookie_headers: Callable[[], dict],
    bearer_headers: Callable[[], dict],
    has_session_cookie: bool,
    strict: bool,
) -> dict:
    """Cookie 优先读取登录态套餐，只有未识别时才回退 Web AT。

    浏览器真实 HAR 的 accounts/check 依赖 Cookie。Bearer 仍作为明确的
    兼容回退，避免 Cookie 还未完全落地时把 guest 误保存成套餐结果。
    """
    cookie_plan: dict = {}
    if has_session_cookie:
        cookie_response = _get(
            session,
            url,
            cookie_headers,
            # Cookie 探测失败不能阻断后面的 Bearer 回退。
            strict=False,
        )
        cookie_plan = _parse_accounts_response(
            cookie_response,
            access_token=None,
            country=country,
            region=region,
            phase=phase,
            auth_mode="cookie",
            strict=False,
        )
        if _accounts_plan_usable(cookie_plan):
            return cookie_plan

    if access_token:
        bearer_response = _get(
            session,
            url,
            bearer_headers,
            strict=strict,
        )
        bearer_plan = _parse_accounts_response(
            bearer_response,
            access_token=access_token,
            country=country,
            region=region,
            phase=phase,
            auth_mode="bearer",
            strict=strict,
        )
        if bearer_plan:
            return bearer_plan

    if cookie_plan:
        return _mark_accounts_auth_context_error(
            cookie_plan,
            message="登录态 accounts/check 仅返回 guest，未识别 Web 会话",
        )
    return {}


def _obi_sync_token(
    session: BrowserSession,
    base: str,
    headers: Callable[[], dict],
    *,
    strict: bool,
    retry_edge: bool = False,
):
    """从 ChatGPT 获取仅供本次 bzr OBI 同步使用的短期 token。"""

    def perform():
        obi = str(getattr(session, "obi_id", "") or "").strip()
        if not obi:
            raise RuntimeError("BrowserSession 缺少稳定 obi_id")
        token_response = _json_post(
            session,
            f"{base}/bazaar/obi/sync-token",
            {"operation": "set", "obi": obi},
            headers={
                **headers(),
                "content-type": "application/json",
                "origin": "https://chatgpt.com",
            },
        )
        if int(getattr(token_response, "status_code", 0) or 0) >= 400:
            raise RuntimeError(f"sync-token HTTP {token_response.status_code}")
        token = str(_response_json(token_response).get("token") or "").strip()
        if not token:
            raise RuntimeError("sync-token 响应缺少 token")

        return token

    result = _safe_request(
        "OBI sync-token",
        perform,
        strict=strict,
        retry_edge=retry_edge,
    )
    return str(result or "").strip()


def _obi_sync_commit(
    session: BrowserSession,
    token: str,
    *,
    phase: str,
    strict: bool,
    retry_edge: bool = False,
):
    """把 ChatGPT 签发的 token 原样提交给 bzr；正文是 text/plain JSON。"""

    def perform():
        if not token:
            raise RuntimeError("缺少 OBI sync token")
        bzr_headers = session._get_common_headers()
        bzr_headers.update({
            "accept": "*/*",
            "content-type": "text/plain",
            "origin": "https://chatgpt.com",
            "referer": _PAGE_URL,
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "sec-fetch-storage-access": "active",
            "priority": "u=1, i",
        })
        response = session.post(
            _OBI_SYNC_URL,
            headers=bzr_headers,
            data=json.dumps({"token": token}, separators=(",", ":")),
        )
        status = int(getattr(response, "status_code", 0) or 0)
        if status >= 400:
            raise RuntimeError(f"bzr sync HTTP {status}")
        obi = str(getattr(session, "obi_id", "") or "")
        logger.info(
            "[Bootstrap][OBI] 同步完成 phase=%s obi=%s...",
            phase,
            obi[:8],
        )
        return response

    return _safe_request(
        "OBI bzr sync",
        perform,
        strict=strict,
        retry_edge=retry_edge,
    )


def _pricing_country(session: BrowserSession) -> str:
    profile = getattr(session, "browser_profile", {}) or {}
    geo_country = str((profile.get("geo") or {}).get("country") or "").upper()
    if len(geo_country) == 2:
        return geo_country
    locale_country = {
        "jp": "JP",
        "cn": "CN",
        "hk": "HK",
        "tw": "TW",
        "us": "US",
        "sg": "SG",
        "gb": "GB",
        "de": "DE",
        "fr": "FR",
        "nl": "NL",
    }.get(str(profile.get("locale_profile") or "").lower())
    return locale_country or "JP"


def _conversation_prepare_payload(
    session: BrowserSession,
    *,
    state: str,
    dispatch: str,
    source: str,
    authenticated: bool,
) -> dict:
    profile = getattr(session, "browser_profile", {}) or {}
    payload = {
        "action": "next",
        "parent_message_id": "client-created-root",
        "model": "auto",
        "client_prepare_state": state,
        "client_prepare_dispatch": dispatch,
        "client_prepare_source": source,
        "timezone_offset_min": session.js_timezone_offset_min(),
        "timezone": str(profile.get("timezone_iana") or "Asia/Tokyo"),
        "conversation_mode": {"kind": "primary_assistant"},
        "system_hints": [],
        "supports_buffering": True,
        "supported_encodings": ["v1"],
        "client_contextual_info": {
            "app_name": "chatgpt.com",
            "has_web_push_capabilities": True,
            "web_push_notification_permission": "default",
        },
    }
    if authenticated:
        payload["local_function_names"] = ["local.continue_in_work"]
    return payload


def _load_chatgpt_sentinel_sdk(
    session: BrowserSession,
) -> tuple[str, str, str]:
    """优先从当前 ChatGPT 会话的 frame 发现 SDK，固定版本仅作回退。"""
    session.chat_requirements_sdk_discovery_status = "started"
    session.chat_requirements_sdk_resolution = "pending"
    session.chat_requirements_sdk_discovery_error_type = ""
    session.chat_requirements_sdk_fallback_error_type = ""
    try:
        asset = load_sentinel_sdk_from_frame(
            session,
            _CHATGPT_SENTINEL_FRAME_URL,
            referer=_PAGE_URL,
            session_cache_attr="_chatgpt_sentinel_sdk_asset",
        )
    except Exception as discovery_exc:
        session.chat_requirements_sdk_discovery_status = "fallback"
        session.chat_requirements_sdk_discovery_error_type = type(
            discovery_exc
        ).__name__
        logger.warning(
            "[Bootstrap][Sentinel] frame 动态发现失败，尝试配置版本回退: %s: %s",
            type(discovery_exc).__name__,
            str(discovery_exc)[:180],
        )
        try:
            asset = load_sentinel_sdk_from_url(
                session,
                _CHATGPT_SENTINEL_SDK_URL,
                referer=_PAGE_URL,
            )
        except Exception as fallback_exc:
            session.chat_requirements_sdk_discovery_status = "failed"
            session.chat_requirements_sdk_resolution = "failed"
            session.chat_requirements_sdk_fallback_error_type = type(
                fallback_exc
            ).__name__
            raise RuntimeError(
                "ChatGPT Sentinel SDK 加载失败: "
                f"frame={type(discovery_exc).__name__}: "
                f"{str(discovery_exc)[:120]}; "
                f"fallback={type(fallback_exc).__name__}: "
                f"{str(fallback_exc)[:120]}"
            ) from fallback_exc
        session.chat_requirements_sdk_resolution = "configured_fallback"
    else:
        session.chat_requirements_sdk_discovery_status = "ok"
        session.chat_requirements_sdk_resolution = "frame"

    sdk_url, _sdk_source, sdk_hash = asset
    session.chat_requirements_sdk_url = sdk_url
    session.chat_requirements_sdk_hash = sdk_hash
    return asset


def _chat_requirements_prepare(
    session: BrowserSession,
    base: str,
    headers: Callable[[], dict],
    *,
    strict: bool,
    retry_edge: bool = False,
) -> _ChatRequirementsState | None:
    def perform() -> _ChatRequirementsState:
        sdk_url, sdk_source, sdk_hash = _load_chatgpt_sentinel_sdk(session)
        profile = getattr(session, "browser_profile", {}) or {}
        runner_context = {
            "browser_profile": profile,
            "sentinel_sid": getattr(
                session,
                "chatgpt_sentinel_sid",
                getattr(session, "sentinel_sid", ""),
            ),
            "react_listening_key": getattr(session, "react_listening_key", ""),
            "react_container_key": getattr(session, "react_container_key", ""),
            "react_resources_key": getattr(session, "react_resources_key", ""),
            "cookie": session.chatgpt_cookie_header(),
            "page_url": _PAGE_URL,
        }
        requirements_token = generate_sentinel_prepare_token(
            sdk_source=sdk_source,
            sdk_url=sdk_url,
            flow="chat",
            device_id=session.device_id,
            **runner_context,
        )
        response = _json_post(
            session,
            f"{base}/sentinel/chat-requirements/prepare",
            {"p": requirements_token},
            headers={
                **headers(),
                "content-type": "application/json",
                "origin": "https://chatgpt.com",
            },
        )
        if int(getattr(response, "status_code", 0) or 0) >= 400:
            raise RuntimeError(f"prepare HTTP {response.status_code}")
        challenge = response.json()
        if not isinstance(challenge, dict):
            raise RuntimeError("prepare 响应结构不是对象")
        if not str(challenge.get("prepare_token") or "").strip():
            raise RuntimeError("prepare 响应缺少 prepare_token")
        state = _ChatRequirementsState(
            challenge=challenge,
            requirements_token=requirements_token,
            sdk_url=sdk_url,
            sdk_source=sdk_source,
            sdk_hash=sdk_hash,
        )
        # Keep non-secret SDK diagnostics on the session.  OAuth's protocol
        # adapter may need to export the same bootstrap context after this
        # short-lived session is closed; the source itself is never persisted.
        session.chat_requirements_prepare_status = "ok"
        session.chat_requirements_prepare_http_status = int(
            getattr(response, "status_code", 0) or 0
        )
        return state

    session.chat_requirements_prepare_status = "started"
    result = _safe_request(
        f"{base}/sentinel/chat-requirements/prepare",
        perform,
        strict=strict,
        retry_edge=retry_edge,
    )
    if result is None and getattr(session, "chat_requirements_prepare_status", "") == "started":
        session.chat_requirements_prepare_status = "failed"
    return result


def _chat_requirements_finalize(
    session: BrowserSession,
    base: str,
    state: _ChatRequirementsState | None,
    headers: Callable[[], dict],
    *,
    strict: bool,
    retry_edge: bool = False,
):
    if state is None:
        session.chat_requirements_finalize_status = "skipped"
        return None

    def perform():
        profile = getattr(session, "browser_profile", {}) or {}
        artifacts = generate_chat_requirements_artifacts(
            state.challenge,
            requirements_token=state.requirements_token,
            sdk_source=state.sdk_source,
            sdk_url=state.sdk_url,
            sdk_hash=state.sdk_hash,
            device_id=session.device_id,
            browser_profile=profile,
            sentinel_sid=getattr(
                session,
                "chatgpt_sentinel_sid",
                getattr(session, "sentinel_sid", ""),
            ),
            react_listening_key=getattr(session, "react_listening_key", ""),
            react_container_key=getattr(session, "react_container_key", ""),
            react_resources_key=getattr(session, "react_resources_key", ""),
            cookie=session.chatgpt_cookie_header(),
            page_url=_PAGE_URL,
        )
        payload = {
            "prepare_token": str(state.challenge["prepare_token"]),
            "proofofwork": artifacts.proof_token,
            "turnstile": artifacts.turnstile_token,
        }
        response = _json_post(
            session,
            f"{base}/sentinel/chat-requirements/finalize",
            payload,
            headers={
                **headers(),
                "content-type": "application/json",
                "origin": "https://chatgpt.com",
            },
        )
        status = int(getattr(response, "status_code", 0) or 0)
        session.chat_requirements_finalize_http_status = status
        session.chat_requirements_finalize_status = (
            "ok" if 200 <= status < 400 else "failed"
        )
        if status < 400:
            try:
                data = response.json()
                token = str(data.get("token") or "") if isinstance(data, dict) else ""
                if token:
                    session.chat_requirements_token = token
            except Exception:
                pass
        return response

    result = _safe_request(
        f"{base}/sentinel/chat-requirements/finalize",
        perform,
        strict=strict,
        retry_edge=retry_edge,
    )
    if result is None and not getattr(session, "chat_requirements_finalize_status", ""):
        session.chat_requirements_finalize_status = "failed"
    return result


def _system_hints(
    session: BrowserSession,
    base: str,
    specs: Iterable[tuple[str, bool]],
    headers: Callable[[], dict],
    *,
    strict: bool,
    retry_edge: bool = False,
) -> None:
    for mode, suggestions in specs:
        suffix = "&suggestions=true" if suggestions else ""
        _get(
            session,
            f"{base}/system_hints?mode={mode}{suffix}",
            headers,
            strict=strict,
            retry_edge=retry_edge,
        )


def anonymous_bootstrap(
    session: BrowserSession,
    *,
    strict: bool = False,
) -> AnonymousBootstrapResult:
    """注册前匿名首页 bootstrap，按 HAR 保持同一 ChatGPT 会话。"""
    tz = session.js_timezone_offset_min()
    def headers() -> dict:
        value = session.get_chatgpt_headers(referer=_PAGE_URL)
        value.pop("content-type", None)
        return value
    logger.info("[Bootstrap] 匿名态 ChatGPT 预热开始")

    _safe_request(
        "CES anonymous settings",
        lambda: prime_sync_settings(session, phase="anonymous"),
        strict=strict,
        retry_edge=True,
    )
    obi_token = _obi_sync_token(
        session,
        _ANON_BASE,
        headers,
        strict=strict,
        retry_edge=True,
    )
    if not obi_token:
        raise AnonymousBootstrapRetryableError(
            "匿名 bootstrap OBI sync-token 未完成"
        )
    _get(
        session,
        f"{_ANON_BASE}/accounts/check/v4-2023-04-27?timezone_offset_min={tz}",
        headers,
        strict=strict,
        retry_edge=True,
    )
    me_response = _get(
        session,
        f"{_ANON_BASE}/me",
        headers,
        strict=strict,
        retry_edge=True,
    )
    me = _response_json(me_response)
    country = str(me.get("country") or "").strip().upper()
    region = str(me.get("region") or "").strip()
    region_code = str(me.get("region_code") or "").strip()
    session.chatgpt_detected_country = country
    session.chatgpt_detected_region = region
    logger.info(
        "[Bootstrap][匿名国家] country=%s region=%s region_code=%s",
        country or "未知",
        region or "未知",
        region_code or "未知",
    )
    requirements = _chat_requirements_prepare(
        session,
        _ANON_BASE,
        headers,
        strict=strict,
        retry_edge=True,
    )
    _system_hints(
        session,
        _ANON_BASE,
        (("basic", True), ("plugins", True)),
        headers,
        strict=strict,
        retry_edge=True,
    )
    _get(
        session,
        f"{_ANON_BASE}/models?iim=false&is_gizmo=false&supports_model_picker_upgrade_presets=true",
        headers,
        strict=strict,
        retry_edge=True,
    )
    _post(
        session,
        f"{_ANON_BASE}/conversation/init",
        {
            "requested_default_model": None,
            "conversation_id": None,
            "timezone_offset_min": tz,
            "conversation_origin": None,
        },
        headers,
        strict=strict,
        retry_edge=True,
    )
    _get(
        session,
        f"{_ANON_BASE}/checkout_pricing_config/configs/{_pricing_country(session)}",
        headers,
        strict=strict,
        retry_edge=True,
    )
    _get(
        session,
        f"{_ANON_BASE}/settings/voices?voice_mode=advanced",
        headers,
        strict=strict,
        retry_edge=True,
    )
    _post(
        session,
        f"{_ANON_BASE}/f/conversation/prepare",
        _conversation_prepare_payload(
            session,
            state="none",
            dispatch="debounced",
            source="composer_editor_state",
            authenticated=False,
        ),
        headers,
        strict=strict,
        retry_edge=True,
    )
    _safe_request(
        "CES anonymous lifecycle",
        lambda: emit_sync_anonymous(session),
        strict=strict,
        retry_edge=True,
    )
    _post(
        session,
        f"{_ANON_BASE}/f/conversation/prepare",
        _conversation_prepare_payload(
            session,
            state="sent",
            dispatch="immediate",
            source="context_change",
            authenticated=False,
        ),
        headers,
        strict=strict,
        retry_edge=True,
    )
    _chat_requirements_finalize(
        session,
        _ANON_BASE,
        requirements,
        headers,
        strict=strict,
        retry_edge=True,
    )
    obi_response = _obi_sync_commit(
        session,
        obi_token,
        phase="anon",
        strict=strict,
        retry_edge=True,
    )
    logger.info("[Bootstrap] 匿名态 ChatGPT 预热完成")
    return AnonymousBootstrapResult(
        country=country,
        region=region,
        region_code=region_code,
        obi_synced=obi_response is not None,
    )


def authenticated_bootstrap(
    session: BrowserSession,
    access_token: str | None = None,
    *,
    session_info: dict | None = None,
    strict: bool = False,
    emit_telemetry: bool = True,
) -> AuthenticatedBootstrapResult:
    """OAuth callback 后按 Web Session Cookie + Web AT 执行登录态 bootstrap。"""
    tz = session.js_timezone_offset_min()
    begin_authenticated_identity(session)

    def headers() -> dict:
        value = session.get_chatgpt_headers(referer=_PAGE_URL)
        value.pop("content-type", None)
        token = str(access_token or "").strip()
        if token:
            value["authorization"] = (
                token if token.lower().startswith("bearer ") else f"Bearer {token}"
            )
        return value

    def cookie_headers() -> dict:
        value = session.get_chatgpt_headers(referer=_PAGE_URL)
        value.pop("content-type", None)
        return value

    cookie_header = session.chatgpt_cookie_header()
    cookie_header_lower = cookie_header.lower()
    has_session_cookie = any(
        marker in cookie_header_lower
        for marker in (
            "__secure-next-auth.session-token",
            "__host-next-auth.session-token",
            "__secure-authjs.session-token",
            "__host-authjs.session-token",
            "next-auth.session-token=",
            "authjs.session-token=",
            "session-token=",
        )
    )
    observation = str(
        getattr(session, "chatgpt_client_observation", "") or ""
    ).strip()
    logger.info(
        "[Bootstrap] 登录态 ChatGPT 预热开始 auth=cookie-first+bearer-fallback "
        "has_session_cookie=%s has_web_at=%s delivery_observation=%s",
        has_session_cookie,
        bool(str(access_token or "").strip()),
        "yes" if observation else "no",
    )
    if emit_telemetry:
        _safe_request(
            "CES authenticated lifecycle",
            lambda: emit_sync_authenticated(
                session,
                session_info or {},
                access_token=access_token,
            ),
            strict=strict,
        )
    _get(session, f"{_API_BASE}/user_granular_consent", headers, strict=strict)
    _get(session, f"{_API_BASE}/accounts/optimized/check", headers, strict=strict)
    me_response = _get(session, f"{_API_BASE}/me", headers, strict=strict)

    me = _response_json(me_response)
    country = str(me.get("country") or "").strip().upper()
    region = str(me.get("region") or "").strip()
    accounts_check_url = (
        f"{_API_BASE}/accounts/check/v4-2023-04-27?timezone_offset_min={tz}"
    )
    first_plan = _authenticated_accounts_check(
        session,
        accounts_check_url,
        access_token=access_token,
        country=country,
        region=region,
        phase="initial",
        cookie_headers=cookie_headers,
        bearer_headers=headers,
        has_session_cookie=has_session_cookie,
        strict=strict,
    )
    session.first_accounts_check = dict(first_plan)
    _get(session, f"{_API_BASE}/settings/user", headers, strict=strict)

    requirements = _chat_requirements_prepare(
        session, _API_BASE, headers, strict=strict
    )
    _system_hints(
        session,
        _API_BASE,
        (("basic", False), ("plugins", False), ("custom_agents", False)),
        headers,
        strict=strict,
    )
    _get(
        session,
        f"{_API_BASE}/models?iim=false&is_gizmo=false&supports_model_picker_upgrade_presets=true",
        headers,
        strict=strict,
    )
    _get(
        session,
        f"{_API_BASE}/conversations?offset=0&limit=28&order=updated&is_archived=false&is_starred=false",
        headers,
        strict=strict,
    )
    _get(
        session,
        f"{_API_BASE}/system_hints?mode=plugins&suggestions=true",
        headers,
        strict=strict,
    )
    _get(
        session,
        f"{_API_BASE}/settings/voices?voice_mode=advanced",
        headers,
        strict=strict,
    )
    _post(
        session,
        f"{_API_BASE}/conversation/init",
        {
            "requested_default_model": None,
            "conversation_id": None,
            "timezone_offset_min": tz,
            "conversation_origin": None,
        },
        headers,
        strict=strict,
    )
    _get(
        session,
        f"{_API_BASE}/checkout_pricing_config/configs/{_pricing_country(session)}",
        headers,
        strict=strict,
    )
    _get(session, f"{_API_BASE}/client/strings", headers, strict=strict)
    _post(
        session,
        f"{_API_BASE}/f/conversation/prepare",
        _conversation_prepare_payload(
            session,
            state="none",
            dispatch="debounced",
            source="composer_editor_state",
            authenticated=True,
        ),
        headers,
        strict=strict,
    )
    _post(
        session,
        f"{_API_BASE}/f/conversation/prepare",
        _conversation_prepare_payload(
            session,
            state="sent",
            dispatch="immediate",
            source="context_change",
            authenticated=True,
        ),
        headers,
        strict=strict,
    )
    obi_token = _obi_sync_token(session, _API_BASE, headers, strict=strict)
    _chat_requirements_finalize(
        session, _API_BASE, requirements, headers, strict=strict
    )
    obi_response = _obi_sync_commit(
        session,
        obi_token,
        phase="auth",
        strict=strict,
    )

    # 首次响应在真实 HAR 的相同位置获取；完整 bootstrap 后只额外复查一次，
    # 用于识别服务端是否在同一会话内延迟落活动。两次均保存摘要，不把缺失活动
    # 推断成有活动，也不切换代理或 AT 查询。
    final_plan = _authenticated_accounts_check(
        session,
        accounts_check_url,
        access_token=access_token,
        country=country,
        region=region,
        phase="final",
        cookie_headers=cookie_headers,
        bearer_headers=headers,
        has_session_cookie=has_session_cookie,
        strict=strict,
    )
    usable_final_plan = final_plan if final_plan.get("ok") else {}
    usable_first_plan = first_plan if first_plan.get("ok") else {}
    plan = usable_final_plan or usable_first_plan
    session.final_accounts_check = dict(final_plan)
    auth_context_error = next(
        (
            item
            for item in (final_plan, first_plan)
            if item.get("error_type") == "auth_context_error"
        ),
        {},
    )
    session.authenticated_accounts_check_error = dict(auth_context_error)
    # 保留旧字段名供落库调用方兼容；它现在表示同一注册会话的最终真实结果。
    session.initial_accounts_check = dict(plan)
    # The billing page makes two small permission probes before the coupon
    # request. Keep all three on the same authenticated session and merge only
    # diagnostic fields; none of them changes the current entitlement.
    billing_result = _authenticated_billing_probe(session, headers)
    plan.update(billing_result)
    if first_plan:
        first_plan.update(billing_result)
    if final_plan:
        final_plan.update(billing_result)
    promo_result = {}
    if plan.get("plus_trial_campaign_id") or str(
        plan.get("current_plan_type") or ""
    ).lower() == "free":
        promo_result = _authenticated_coupon_check(
            session,
            str(plan.get("plus_trial_campaign_id") or DEFAULT_PLUS_PROMO),
            headers,
            strict=strict,
        )
        plan.update(promo_result)
        if first_plan:
            first_plan.update({
                key: value
                for key, value in promo_result.items()
                if key.startswith("promo_")
            })
        if final_plan:
            final_plan.update({
                key: value
                for key, value in promo_result.items()
                if key.startswith("promo_")
            })
    plan = annotate_promo_state(plan)
    session.promo_check = dict(promo_result)
    session.billing_probe = dict(billing_result)
    if final_plan:
        final_plan.update({
            key: value
            for key, value in plan.items()
            if key.startswith("promo_")
            or key.startswith("plus_trial_")
            or key.startswith("billing_")
            or key.startswith("app_store_")
        })
        session.final_accounts_check = dict(final_plan)
    # ``initial_accounts_check`` is the compatibility field consumed by the
    # account exporter; it was copied before the coupon probe above.
    if promo_result and session.initial_accounts_check:
        session.initial_accounts_check.update({
            key: value
            for key, value in promo_result.items()
            if key.startswith("promo_")
        })
    if session.initial_accounts_check:
        session.initial_accounts_check.update(billing_result)
    if session.initial_accounts_check:
        session.initial_accounts_check.update({
            "plus_trial_status": plan.get("plus_trial_status"),
            "plus_trial_actionable": bool(plan.get("plus_trial_actionable")),
        })
    if first_plan and final_plan:
        logger.info(
            "[Bootstrap][资格变化] initial=%s/%s final=%s/%s",
            bool(first_plan.get("plus_trial_eligible")),
            first_plan.get("plus_trial_campaign_id") or "无",
            bool(final_plan.get("plus_trial_eligible")),
            final_plan.get("plus_trial_campaign_id") or "无",
        )

    plan_type = str(plan.get("current_plan_type") or "")
    plus_trial_eligible = bool(plan.get("plus_trial_eligible"))
    campaign_id = str(plan.get("plus_trial_campaign_id") or "")
    logger.info("[Bootstrap] 登录态 ChatGPT 预热完成")
    return AuthenticatedBootstrapResult(
        country=country,
        region=region,
        plan_type=plan_type,
        plus_trial_eligible=plus_trial_eligible,
        campaign_id=campaign_id,
        obi_synced=obi_response is not None,
        promo_state=str(plan.get("promo_state") or ""),
        promo_redeemed=bool(plan.get("promo_redeemed")),
        promo_check_ok=bool(plan.get("promo_check_ok")),
    )
