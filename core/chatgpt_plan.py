# -*- coding: utf-8 -*-
"""ChatGPT 账号套餐/试用资格查询。"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import quote, urlencode, urlparse

from core.session import BrowserSession
from core.account_proxy import rewrite_proxy_country

logger = logging.getLogger(__name__)

ACCOUNTS_CHECK_PATH = "/backend-api/accounts/check/v4-2023-04-27"
PROMO_CHECK_PATH = "/backend-api/promo_campaign/check_coupon"
DEFAULT_PLUS_PROMO = "plus-1-month-free"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def normalize_token(token: str) -> str:
    token = (token or "").strip().strip('"').strip("'")
    if token.lower().startswith("authorization:"):
        token = token.split(":", 1)[1].strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def _mask_proxy(proxy: str) -> str:
    """返回可用于日志/API 结果的代理摘要，不泄露用户名和密码。"""
    value = str(proxy or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        scheme = f"{parsed.scheme}://" if parsed.scheme else ""
        auth = "***:***@" if parsed.username or parsed.password else ""
        return f"{scheme}{auth}{host}{port}" or "***"
    except Exception:
        return "***"


def _local_proxy_status(proxy: str) -> tuple[bool, bool, str | None]:
    """检查回环代理端口；非本地代理不做预探测，避免额外网络请求。"""
    value = str(proxy or "").strip()
    if not value:
        return False, False, None
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
        is_loopback = host.lower() == "localhost"
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            return False, True, None
        if not parsed.port:
            return True, False, "本地代理未配置端口"
        try:
            with socket.create_connection((host, parsed.port), timeout=0.5):
                return True, True, None
        except OSError as exc:
            return True, False, f"本地代理 {host}:{parsed.port} 未监听（{type(exc).__name__}）"
    except Exception as exc:
        return False, False, f"代理地址解析失败（{type(exc).__name__}）"


def resolve_plan_check_route(explicit_proxy: Optional[str] = None) -> dict:
    """解析套餐查询的实际网络路径。

    explicit_proxy 不是 None 时表示 API 调用方明确覆盖配置；空字符串代表直连。
    """
    if explicit_proxy is not None:
        selected = str(explicit_proxy or "").strip()
        return {
            "proxy": selected,
            "proxy_mode": "request",
            "network_route": "proxy" if selected else "direct",
            "proxy_used": _mask_proxy(selected) or None,
            "proxy_fallback_reason": None,
        }

    from config import proxy as proxy_cfg

    mode = str(getattr(proxy_cfg, "PLAN_CHECK_PROXY_MODE", "auto") or "auto").strip().lower()
    if mode not in {"auto", "proxy", "direct"}:
        raise ValueError(f"PLAN_CHECK_PROXY_MODE={mode!r} 无效，可选 auto / proxy / direct")
    if mode == "direct":
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct",
            "proxy_used": None,
            "proxy_fallback_reason": None,
        }

    selected = str(getattr(proxy_cfg, "PLAN_CHECK_PROXY", "") or "").strip()
    if not selected:
        selected = str(proxy_cfg.pick_proxy() or "").strip()
    if not selected:
        if mode == "proxy":
            raise ValueError("套餐查询网络模式为 proxy，但未配置 PLAN_CHECK_PROXY 或 PROXY_POOL")
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct",
            "proxy_used": None,
            "proxy_fallback_reason": "未配置套餐查询代理或代理池",
        }

    # Qualification checks must follow the same country-selected sticky pool
    # as Roxy.  The override is intentionally applied only to a proxy chosen
    # from current configuration; an explicit per-request proxy remains an
    # escape hatch for non-qualification callers.
    try:
        selected = proxy_cfg.normalize_proxy_url(selected)
        from config import roxybrowser as roxy_cfg

        selected = rewrite_proxy_country(
            selected,
            getattr(roxy_cfg, "ROXY_PROXY_COUNTRY_OVERRIDE", ""),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"套餐查询代理配置无效: {exc}") from exc

    is_local, available, reason = _local_proxy_status(selected)
    if mode == "auto" and is_local and not available:
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct_fallback",
            "proxy_used": _mask_proxy(selected),
            "proxy_fallback_reason": reason,
        }
    return {
        "proxy": selected,
        "proxy_mode": mode,
        "network_route": "proxy",
        "proxy_used": _mask_proxy(selected),
        "proxy_fallback_reason": None,
    }


def resolve_current_plan_check_proxy() -> str:
    """Return the proxy selected from the current qualification configuration.

    An empty string is a deliberate direct route (for ``PLAN_CHECK_PROXY_MODE``
    ``direct`` or an ``auto`` fallback).  The helper exists so account-level
    stored registration proxies cannot accidentally become qualification
    request overrides.
    """
    return str(resolve_plan_check_route(None).get("proxy") or "").strip()


def decode_jwt_payload_unverified(token: str) -> dict:
    """仅本地解析 JWT payload，不校验签名。"""
    token = normalize_token(token)
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return {}


def token_claims(token: str) -> dict:
    payload = decode_jwt_payload_unverified(token)
    auth = payload.get("https://api.openai.com/auth") or {}
    profile = payload.get("https://api.openai.com/profile") or {}
    exp = payload.get("exp")
    exp_iso = None
    expired = None
    if isinstance(exp, (int, float)):
        exp_iso = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        expired = datetime.now(tz=timezone.utc).timestamp() >= float(exp)
    return {
        "payload": payload,
        "email": profile.get("email"),
        "user_name": profile.get("name"),
        "user_id": auth.get("chatgpt_user_id") or auth.get("user_id"),
        "account_id": auth.get("chatgpt_account_id"),
        "claim_plan_type": auth.get("chatgpt_plan_type"),
        "exp": exp,
        "token_expires_at": exp_iso,
        "token_expired": expired,
    }


def _common_headers(env: BrowserSession, token: str) -> dict[str, str]:
    headers = env._get_common_headers()
    headers.update({
        "accept": "*/*",
        "authorization": f"Bearer {normalize_token(token)}",
        "oai-device-id": env.device_id,
        "oai-language": env.navigator_language(),
        "referer": "https://chatgpt.com/",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "x-openai-target-path": ACCOUNTS_CHECK_PATH,
        "x-openai-target-route": ACCOUNTS_CHECK_PATH,
    })
    return headers


def _promo_headers(env: BrowserSession, token: str, campaign_id: str) -> dict[str, str]:
    """Build the header set used by the Web coupon probe.

    The coupon request is a same-origin GET, but its target headers differ from
    ``accounts/check``. Keeping the target route accurate matters for the edge
    router and also makes the request traceable without copying browser-only
    telemetry headers.
    """
    headers = _common_headers(env, token)
    headers["x-openai-target-path"] = PROMO_CHECK_PATH
    headers["x-openai-target-route"] = PROMO_CHECK_PATH
    headers["referer"] = (
        "https://chatgpt.com/?promo_campaign="
        + quote(str(campaign_id or DEFAULT_PLUS_PROMO), safe="")
    )
    return headers


def parse_coupon_check(data: dict, *, campaign_id: str = "") -> dict:
    """Normalize ``promo_campaign/check_coupon`` without inferring redemption.

    ``state=eligible`` means the campaign can currently be used; it does not
    mean that a subscription has already been created. The latter is only true
    when the response's redemption flags explicitly say so.
    """
    payload = data if isinstance(data, dict) else {}
    redemption = payload.get("redemption")
    if not isinstance(redemption, dict):
        redemption = {}
    coupon = str(payload.get("coupon") or campaign_id or "").strip()
    state = str(payload.get("state") or "").strip().lower()
    def as_bool(value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        return str(value or "").strip().lower() in {"1", "true", "yes"}

    redeemed = bool(
        as_bool(redemption.get("redeemed"))
        or as_bool(redemption.get("redeemed_by_user"))
        or as_bool(redemption.get("redeemed_by_workspace"))
    )
    return {
        "promo_coupon": coupon,
        "promo_state": state,
        "promo_redeemed": redeemed,
        "promo_redeemed_at": (
            redemption.get("redeemed_at")
            or redemption.get("user_redeemed_at")
            or redemption.get("workspace_redeemed_at")
        ),
        "promo_redeemed_by_user": as_bool(redemption.get("redeemed_by_user")),
        "promo_redeemed_by_workspace": as_bool(redemption.get("redeemed_by_workspace")),
        "promo_expires_at": redemption.get("expires_at"),
        "promo_promotion_length_days": redemption.get("promotion_length_days"),
    }


def annotate_promo_state(result: dict | None) -> dict:
    """Add an explicit, non-ambiguous state for management and extraction.

    ``current_plan_type=free`` remains the authoritative current entitlement.
    These fields only describe whether the separate Plus campaign can be acted
    on, has already been redeemed, or could not be checked.
    """
    out = dict(result or {})
    plan = str(out.get("current_plan_type") or out.get("plan_type") or "").lower()
    eligible = bool(out.get("plus_trial_eligible"))
    if plan != "free" or not eligible:
        status = "not_eligible"
    elif not bool(out.get("promo_check_ok")):
        status = "unknown"
    elif bool(out.get("promo_redeemed")):
        status = "redeemed"
    elif str(out.get("promo_state") or "").lower() in {"eligible", "available"}:
        status = "available"
    else:
        status = "unavailable"
    out["plus_trial_status"] = status
    out["plus_trial_actionable"] = status == "available"
    return out


def _check_coupon(
    env: BrowserSession,
    token: str,
    campaign_id: str,
    *,
    timeout: float,
) -> dict:
    """Probe campaign state on an already-authenticated session.

    Coupon failures are diagnostic only. A temporary 403/429 or malformed body
    must not erase a successful ``accounts/check`` result.
    """
    campaign = str(campaign_id or DEFAULT_PLUS_PROMO).strip() or DEFAULT_PLUS_PROMO
    query = urlencode({"coupon": campaign, "is_coupon_from_query_param": "true"})
    url = f"https://chatgpt.com{PROMO_CHECK_PATH}?{query}"
    response = env.session.get(
        url,
        headers=_promo_headers(env, token, campaign),
        allow_redirects=False,
        timeout=timeout,
    )
    status = int(getattr(response, "status_code", 0) or 0)
    text = str(getattr(response, "text", "") or "")
    if status < 200 or status >= 300:
        retry_after = str(
            (getattr(response, "headers", {}) or {}).get("retry-after") or ""
        ).strip() or None
        return {
            "promo_check_ok": False,
            "promo_check_http_status": status,
            "promo_check_error": f"HTTP {status}",
            "promo_response_preview": text[:500],
            "promo_response_bytes": len(text.encode("utf-8", errors="replace")),
            "promo_retry_after": retry_after,
            "promo_retryable": status in {408, 409, 425, 429} or status >= 500,
            "promo_checked_at": now_iso(),
        }
    try:
        data = response.json()
    except Exception:
        try:
            data = json.loads(text)
        except Exception:
            data = None
    if not isinstance(data, dict):
        return {
            "promo_check_ok": False,
            "promo_check_http_status": status,
            "promo_check_error": "优惠接口响应不是 JSON 对象",
            "promo_response_preview": text[:500],
            "promo_response_bytes": len(text.encode("utf-8", errors="replace")),
            "promo_retryable": True,
            "promo_checked_at": now_iso(),
        }
    parsed = parse_coupon_check(data, campaign_id=campaign)
    parsed.update({
        "promo_check_ok": True,
        "promo_check_http_status": status,
        "promo_response_bytes": len(text.encode("utf-8", errors="replace")),
        "promo_retryable": False,
        "promo_checked_at": now_iso(),
    })
    return parsed


def parse_accounts_check(data: dict, *, token: str = "") -> dict:
    """从 accounts/check 响应提取套餐和 Plus 试用资格。"""
    claims = token_claims(token) if token else {}
    claim_account_id = claims.get("account_id")
    accounts = data.get("accounts") if isinstance(data, dict) else None
    if not isinstance(accounts, dict):
        raise ValueError("响应缺少 accounts 对象")

    item = None
    account_key = None
    if claim_account_id and isinstance(accounts.get(claim_account_id), dict):
        item = accounts.get(claim_account_id)
        account_key = claim_account_id
    elif isinstance(accounts.get("default"), dict):
        item = accounts.get("default")
        account = item.get("account") or {}
        account_key = account.get("account_id") or "default"
    else:
        for k, v in accounts.items():
            if k != "default" and isinstance(v, dict):
                item = v
                account_key = k
                break
    if not isinstance(item, dict):
        raise ValueError("未找到可解析的账号条目")

    account = item.get("account") or {}
    entitlement = item.get("entitlement") or {}
    last_sub = item.get("last_active_subscription") or {}
    eligible_promo_campaigns = item.get("eligible_promo_campaigns") or {}
    plus_campaign = eligible_promo_campaigns.get("plus") if isinstance(eligible_promo_campaigns, dict) else None
    plus_meta = (plus_campaign or {}).get("metadata") or {}
    discount = plus_meta.get("discount") or {}
    duration = plus_meta.get("duration") or {}

    plan_type = account.get("plan_type") or claims.get("claim_plan_type") or ""
    subscription_plan = entitlement.get("subscription_plan") or ""
    has_active_subscription = bool(entitlement.get("has_active_subscription"))
    is_free = str(plan_type).lower() == "free" or str(subscription_plan).lower() == "chatgptfreeplan"
    plus_trial_eligible = bool(is_free and plus_campaign)

    offers = ((item.get("eligible_offers") or {}).get("offers") or [])
    eligible_offer_ids = [o.get("id") for o in offers if isinstance(o, dict) and o.get("id")]

    result = {
        "ok": True,
        "checked_at": now_iso(),
        "account_id": account.get("account_id") or account_key or claim_account_id,
        "account_user_role": account.get("account_user_role"),
        "current_plan_type": plan_type,
        "subscription_plan": subscription_plan,
        "has_active_subscription": has_active_subscription,
        "is_active_subscription_gratis": bool(entitlement.get("is_active_subscription_gratis")),
        "expires_at": entitlement.get("expires_at"),
        "renews_at": entitlement.get("renews_at"),
        "cancels_at": entitlement.get("cancels_at"),
        "billing_period": entitlement.get("billing_period"),
        "billing_currency": entitlement.get("billing_currency"),
        "is_delinquent": bool(entitlement.get("is_delinquent")),
        "discount_type": (entitlement.get("discount") or {}).get("discount_type"),
        "discount_amount": (entitlement.get("discount") or {}).get("amount"),
        "discount_duration_num_periods": (entitlement.get("discount") or {}).get("duration_num_periods"),
        "discount_expires_at": (entitlement.get("discount") or {}).get("discount_expires_at"),
        "discount_cancellation_policy": (entitlement.get("discount") or {}).get("cancellation_policy"),
        "discount_promo_campaign_id": (entitlement.get("discount") or {}).get("promo_campaign_id"),
        "last_purchase_origin_platform": last_sub.get("purchase_origin_platform"),
        "last_will_renew": bool(last_sub.get("will_renew")),
        "plus_trial_eligible": plus_trial_eligible,
        "plus_trial_campaign_id": (plus_campaign or {}).get("id"),
        "plus_trial_title": plus_meta.get("title"),
        "plus_trial_summary": plus_meta.get("summary"),
        "plus_trial_discount_percentage": discount.get("percentage"),
        "plus_trial_duration_num_periods": duration.get("num_periods"),
        "plus_trial_duration_period": duration.get("period"),
        "plus_trial_promotion_type_label": plus_meta.get("promotion_type_label"),
        "eligible_offer_ids": eligible_offer_ids,
        "features_count": len(item.get("features") or []),
        "can_access_with_session": bool(item.get("can_access_with_session")),
        "raw_account_plan_type": account.get("plan_type"),
    }
    result.update({k: v for k, v in claims.items() if k != "payload" and v is not None})
    return result


def _plan_check_settings(
    timeout: float | None,
    max_attempts: int | None,
    retry_delay: float | None,
) -> tuple[float, int, float]:
    from config import proxy as proxy_cfg

    timeout_value = timeout if timeout is not None else getattr(proxy_cfg, "PLAN_CHECK_TIMEOUT", 15.0)
    attempts_value = max_attempts if max_attempts is not None else getattr(proxy_cfg, "PLAN_CHECK_MAX_ATTEMPTS", 2)
    delay_value = retry_delay if retry_delay is not None else getattr(proxy_cfg, "PLAN_CHECK_RETRY_DELAY", 1.5)
    return (
        max(1.0, min(60.0, float(timeout_value or 15.0))),
        max(1, min(4, int(attempts_value or 1))),
        max(0.0, min(30.0, float(delay_value or 0.0))),
    )


def resolve_plan_check_browser_family(browser_family: str | None = None) -> str:
    """Resolve the HTTP/TLS profile used by plan and offer checks."""
    if browser_family is None:
        from config import proxy as proxy_cfg

        browser_family = getattr(proxy_cfg, "PLAN_CHECK_BROWSER_FAMILY", "firefox")
    family = str(browser_family or "firefox").strip().lower()
    return family if family in {"chrome", "firefox"} else "firefox"


def _looks_like_edge_challenge(response_text: str) -> bool:
    low = str(response_text or "").strip().lower()
    if not low:
        return False
    return any(marker in low for marker in (
        "<!doctype", "<html", "cloudflare", "cf-chl-", "turnstile", "captcha",
    ))


def _retryable_plan_error(http_status: int | None, response_text: str = "") -> bool:
    if http_status is None:
        return True
    if http_status in {401, 403} and _looks_like_edge_challenge(response_text):
        return True
    return http_status in {408, 409, 425, 429} or http_status >= 500


def _retry_wait_seconds(resp: Any, base_delay: float, attempt: int) -> float:
    try:
        retry_after = (getattr(resp, "headers", {}) or {}).get("retry-after")
        if retry_after is not None:
            return max(0.0, min(30.0, float(retry_after)))
    except (TypeError, ValueError):
        pass
    return max(0.0, min(30.0, base_delay * attempt))


def _apply_request_context_cookies(env: BrowserSession, cookies: Any) -> int:
    """Restore managed Web cookies without allowing oai-did/header divergence."""
    if cookies is None:
        return 0
    from core.account_cookie_store import normalize_cookies

    applied = 0
    now = time.time()
    for cookie in normalize_cookies(cookies, source="plan_check"):
        expires = cookie.get("expires")
        if isinstance(expires, (int, float)) and expires > 0 and expires <= now:
            continue
        name = str(cookie.get("name") or "")
        value = str(cookie.get("value") or "")
        if name.lower() == "oai-did" and value != env.device_id:
            continue
        env.session.cookies.set(
            name,
            value,
            domain=str(cookie.get("domain") or "chatgpt.com"),
            path=str(cookie.get("path") or "/"),
        )
        applied += 1
    return applied


def check_account_plan(
    token: str,
    *,
    proxy: Optional[str] = None,
    timezone_offset_min: str = "-",
    timeout: float | None = None,
    max_attempts: int | None = None,
    retry_delay: float | None = None,
    device_id: str | None = None,
    cookies: Any = None,
    browser_family: str | None = None,
    check_promo: bool = True,
) -> dict:
    token = normalize_token(token)
    if not token:
        return {"ok": False, "checked_at": now_iso(), "error": "token 为空"}
    claims = token_claims(token)
    if claims.get("token_expired") is True:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": "token 已过期",
            **{k: v for k, v in claims.items() if k != "payload"},
        }

    try:
        route = resolve_plan_check_route(proxy)
    except Exception as exc:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": f"套餐查询网络配置错误: {exc}",
            **{k: v for k, v in claims.items() if k != "payload"},
        }
    route_meta = {k: v for k, v in route.items() if k != "proxy"}
    url = f"https://chatgpt.com{ACCOUNTS_CHECK_PATH}?timezone_offset_min={quote(str(timezone_offset_min))}"
    try:
        timeout_seconds, attempts, base_delay = _plan_check_settings(timeout, max_attempts, retry_delay)
    except Exception as exc:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": f"套餐查询重试配置错误: {exc}",
            "retryable": False,
            **route_meta,
            **{k: v for k, v in claims.items() if k != "payload"},
        }

    last_result: dict | None = None
    for attempt in range(1, attempts + 1):
        env = None
        resp = None
        try:
            # 套餐查询只需要稳定的请求头，不需要额外访问 IP 地理信息接口。
            session_kwargs = {
                "proxy": route["proxy"],
                "detect_exit_geo": False,
            }
            if str(device_id or "").strip():
                session_kwargs["device_id"] = str(device_id).strip()
            session_kwargs["browser_family"] = resolve_plan_check_browser_family(
                browser_family
            )
            env = BrowserSession(**session_kwargs)
            restored_cookie_count = _apply_request_context_cookies(env, cookies)
            resp = env.session.get(
                url,
                headers=_common_headers(env, token),
                allow_redirects=False,
                timeout=timeout_seconds,
            )
            response_text = resp.text or ""
            http_status = int(resp.status_code)
            if not (200 <= http_status < 300):
                last_result = {
                    "ok": False,
                    "checked_at": now_iso(),
                    "http_status": http_status,
                    "error": f"HTTP {http_status}",
                    "response_preview": response_text[:500],
                    "retryable": _retryable_plan_error(http_status, response_text),
                }
            else:
                try:
                    data: Any = resp.json()
                except Exception:
                    data = json.loads(response_text) if response_text.strip().startswith(("{", "[")) else None
                if not isinstance(data, dict):
                    last_result = {
                        "ok": False,
                        "checked_at": now_iso(),
                        "http_status": http_status,
                        "error": "响应不是 JSON 对象",
                        "response_preview": response_text[:500],
                        "retryable": True,
                    }
                else:
                    parsed = parse_accounts_check(data, token=token)
                    parsed["http_status"] = http_status
                    parsed["attempt_count"] = attempt
                    parsed["max_attempts"] = attempts
                    parsed["request_timeout"] = timeout_seconds
                    parsed["retryable"] = False
                    parsed["request_context_device_reused"] = bool(
                        str(device_id or "").strip()
                    )
                    parsed["request_context_cookie_count"] = restored_cookie_count
                    parsed.update(route_meta)
                    # The accounts endpoint reports eligibility, while the Web
                    # billing page separately reports whether the campaign has
                    # already been redeemed. Probe it on the same session so a
                    # temporary coupon failure cannot turn a valid plan result
                    # into a failed query.
                    campaign = str(
                        parsed.get("plus_trial_campaign_id") or DEFAULT_PLUS_PROMO
                    ).strip()
                    if check_promo and str(parsed.get("current_plan_type") or "").lower() == "free":
                        try:
                            parsed.update(
                                _check_coupon(
                                    env,
                                    token,
                                    campaign,
                                    timeout=timeout_seconds,
                                )
                            )
                        except Exception as coupon_exc:
                            logger.debug(
                                "优惠资格接口查询失败: %s: %s",
                                type(coupon_exc).__name__,
                                coupon_exc,
                            )
                            parsed.update({
                                "promo_check_ok": False,
                                "promo_check_http_status": None,
                                "promo_check_error": (
                                    f"{type(coupon_exc).__name__}: {coupon_exc}"
                                )[:500],
                                "promo_checked_at": now_iso(),
                            })
                    parsed = annotate_promo_state(parsed)
                    return parsed
        except Exception as exc:
            logger.debug("套餐查询失败: %s: %s", type(exc).__name__, exc, exc_info=True)
            last_result = {
                "ok": False,
                "checked_at": now_iso(),
                "http_status": int(resp.status_code) if resp is not None and getattr(resp, "status_code", None) else None,
                "error": f"{type(exc).__name__}: {exc}",
                "retryable": True,
            }
        finally:
            if env is not None:
                try:
                    env.session.close()
                except Exception:
                    pass

        last_result = last_result or {"ok": False, "checked_at": now_iso(), "error": "未知错误", "retryable": True}
        last_result.update({
            "attempt_count": attempt,
            "max_attempts": attempts,
            "request_timeout": timeout_seconds,
            **route_meta,
            **{k: v for k, v in claims.items() if k != "payload"},
        })
        if not last_result.get("retryable") or attempt >= attempts:
            return last_result

        wait_seconds = _retry_wait_seconds(resp, base_delay, attempt)
        logger.warning(
            "套餐查询临时失败，第 %s/%s 次，%.1fs 后重试: %s",
            attempt,
            attempts,
            wait_seconds,
            last_result.get("error"),
        )
        if wait_seconds > 0:
            time.sleep(wait_seconds)

    return last_result or {
        "ok": False,
        "checked_at": now_iso(),
        "http_status": None,
        "error": "套餐查询未执行",
        "retryable": False,
        **route_meta,
        **{k: v for k, v in claims.items() if k != "payload"},
    }


def classify_account_health(result: dict | None) -> dict:
    """把认证请求结果归类为账号验活状态。

    Web AT 失效不等于账号被删除。只有响应明确说明账号已停用/删除时才判
    dead；JWT 到期、401 和 invalid_token 统一归为 token_invalid。
    限流、代理、挑战页和响应解析问题属于 error。
    """
    source = dict(result or {})
    http_status = source.get("http_status")
    token_expired = source.get("token_expired") is True
    response_preview = str(source.get("response_preview") or "").strip().lower()
    looks_like_challenge = any(marker in response_preview for marker in (
        "<html", "<!doctype", "cloudflare", "cf-chl-", "captcha", "turnstile",
    ))
    account_gone = bool(response_preview) and not looks_like_challenge and any(
        marker in response_preview for marker in (
            "account_deactivated", "account_deleted", "account_disabled",
        )
    )
    token_rejected = token_expired or (http_status == 401 and not looks_like_challenge) or (
        bool(response_preview)
        and not looks_like_challenge
        and any(marker in response_preview for marker in (
            "token_expired", "invalid_token", "invalid token",
            "authentication token is expired", "authentication token has expired",
        ))
    )

    if account_gone and http_status in {401, 403}:
        status = "dead"
        reason = "account_unavailable"
        message = f"服务端确认账号已停用或删除（HTTP {http_status}）"
        alive: bool | None = False
        error = None
    elif source.get("ok"):
        status = "alive"
        reason = "authenticated"
        message = "认证请求成功"
        alive = True
        error = None
    elif token_rejected:
        status = "token_invalid"
        reason = "token_expired" if token_expired or "token_expired" in response_preview else "token_rejected"
        message = "Web AT 已失效；不能据此判定账号失活"
        alive = None
        error = None
    elif looks_like_challenge:
        status = "error"
        reason = "edge_challenge"
        rendered_status = str(http_status) if http_status is not None else "未知"
        message = f"验活请求被边缘挑战拦截（HTTP {rendered_status}），账号状态未判定"
        alive = None
        error = message
    else:
        status = "error"
        reason = "check_failed"
        message = str(source.get("error") or "验活请求失败")[:500]
        alive = None
        error = message

    source.update({
        "status": status,
        "alive": alive,
        "reason": reason,
        "message": message,
        "error": error,
        "checked_at": source.get("checked_at") or now_iso(),
    })
    return source


def check_account_alive(
    token: str,
    *,
    proxy: Optional[str] = None,
    timezone_offset_min: str = "-",
    timeout: float | None = None,
    max_attempts: int | None = None,
    retry_delay: float | None = None,
    device_id: str | None = None,
    cookies: Any = None,
    browser_family: str | None = None,
) -> dict:
    """使用 Web AT 访问 accounts/check，并返回保守的账号验活结论。"""
    normalized = normalize_token(token)
    if not normalized:
        return {
            "ok": True,
            "status": "no_token",
            "alive": None,
            "reason": "missing_token",
            "message": "账号缺少 Web AT",
            "error": None,
            "http_status": None,
            "checked_at": now_iso(),
        }
    # Authentication evidence is already in accounts/check. A free account's
    # coupon eligibility is irrelevant to health and can add another timeout.
    result = check_account_plan(
        normalized,
        proxy=proxy,
        timezone_offset_min=timezone_offset_min,
        timeout=timeout,
        max_attempts=max_attempts,
        retry_delay=retry_delay,
        device_id=device_id,
        cookies=cookies,
        browser_family=browser_family,
        check_promo=False,
    )
    return classify_account_health(result)
