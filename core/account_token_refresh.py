# -*- coding: utf-8 -*-
"""Refresh a rejected ChatGPT Web access token from saved session cookies."""
from __future__ import annotations

import time
from typing import Any

from core import db
from core.account_cookie_store import (
    has_session_cookie,
    normalize_cookies,
)
from core.chatgpt_plan import token_claims
from core.session import BrowserSession

_SESSION_URL = "https://chatgpt.com/api/auth/session"


def _cookie_key(cookie: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(cookie.get("domain") or "").lower(),
        str(cookie.get("path") or "/"),
        str(cookie.get("name") or ""),
    )


def _seed_cookie_jar(env: BrowserSession, cookies: list[dict[str, Any]]) -> None:
    try:
        env.session.cookies.delete("oai-did")
    except Exception:
        pass
    for cookie in cookies:
        env.session.cookies.set(
            str(cookie.get("name") or ""),
            str(cookie.get("value") or ""),
            domain=str(cookie.get("domain") or ""),
            path=str(cookie.get("path") or "/"),
            secure=bool(cookie.get("secure")),
        )
        if (
            str(cookie.get("name") or "") == "oai-did"
            and str(cookie.get("domain") or "").lstrip(".").lower() == "chatgpt.com"
        ):
            env.device_id = str(cookie.get("value") or env.device_id)


def _merged_cookie_snapshot(
    original: list[dict[str, Any]],
    runtime_cookies: Any,
) -> list[dict[str, Any]]:
    original_by_key = {
        _cookie_key(cookie): dict(cookie) for cookie in normalize_cookies(original)
    }
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for runtime in normalize_cookies(runtime_cookies):
        key = _cookie_key(runtime)
        previous = original_by_key.get(key)
        if previous is None:
            merged[key] = dict(runtime)
            continue
        updated = dict(previous)
        updated["value"] = str(runtime.get("value") or "")
        if runtime.get("expires") not in (None, 0, -1):
            updated["expires"] = runtime.get("expires")
        updated["secure"] = bool(runtime.get("secure", previous.get("secure")))
        merged[key] = updated
    return list(merged.values())


def _session_headers(env: BrowserSession) -> dict[str, str]:
    headers = env.get_nextauth_headers("https://chatgpt.com/")
    headers.update({
        "accept": "application/json",
        "cache-control": "no-cache",
        "oai-device-id": env.device_id,
        "oai-language": env.navigator_language(),
        "x-openai-target-path": "/api/auth/session",
        "x-openai-target-route": "/api/auth/session",
    })
    return headers


def _validate_replacement(account: dict, old_token: str, new_token: str) -> str | None:
    if not new_token or new_token == old_token:
        return "session 刷新未签发新的 Web AT"
    old_claims = token_claims(old_token)
    new_claims = token_claims(new_token)
    expected_email = str(account.get("email") or old_claims.get("email") or "").strip().lower()
    refreshed_email = str(new_claims.get("email") or "").strip().lower()
    if not refreshed_email or (expected_email and refreshed_email != expected_email):
        return "刷新后的 Web AT 邮箱与账号不匹配"
    expected_account_id = str(
        account.get("account_id") or old_claims.get("account_id") or ""
    ).strip()
    refreshed_account_id = str(new_claims.get("account_id") or "").strip()
    if expected_account_id and refreshed_account_id != expected_account_id:
        return "刷新后的 Web AT workspace 与账号不匹配"
    if new_claims.get("token_expired") is True:
        return "刷新后的 Web AT 已过期"
    return None


def refresh_account_web_access_token(
    account_id: int,
    expected_access_token: str,
    *,
    proxy: str | None = None,
    max_attempts: int = 3,
    browser_family: str | None = None,
) -> dict:
    """Return a claim-validated replacement token without exposing it to logs/API."""
    account = db.get_account(int(account_id))
    if not account:
        return {"ok": False, "error_code": "account_not_found", "error": "账号不存在"}
    try:
        credential = db.load_account_web_cookie_credential(int(account_id))
    except Exception as exc:
        return {
            "ok": False,
            "error_code": "web_cookies_invalid",
            "error": f"Cookie 凭证读取失败: {type(exc).__name__}",
        }
    cookies = normalize_cookies((credential or {}).get("cookies") or [])
    if not cookies or not has_session_cookie(cookies):
        return {
            "ok": False,
            "error_code": "web_cookies_missing",
            "error": "没有有效的 ChatGPT session Cookie",
        }

    selected_proxy = proxy if proxy is not None else (account.get("proxy_used") or None)
    env: BrowserSession | None = None
    last_error = "Cookie session 刷新失败"
    error_code = "cookie_refresh_failed"
    retryable_network = False
    try:
        session_kwargs = {
            "proxy": selected_proxy,
            "detect_exit_geo": False,
        }
        if str(browser_family or "").strip():
            session_kwargs["browser_family"] = str(browser_family).strip().lower()
        env = BrowserSession(**session_kwargs)
        _seed_cookie_jar(env, cookies)
        headers = _session_headers(env)
        attempts = max(1, min(3, int(max_attempts or 1)))
        for attempt in range(1, attempts + 1):
            try:
                warm = env.session.get(
                    _SESSION_URL,
                    headers=headers,
                    allow_redirects=False,
                    timeout=20,
                )
                refreshed = env.session.get(
                    _SESSION_URL,
                    params={"refresh": "true"},
                    headers=headers,
                    allow_redirects=False,
                    timeout=20,
                )
                if int(refreshed.status_code) == 200:
                    try:
                        payload = refreshed.json()
                    except Exception:
                        payload = None
                    new_token = str((payload or {}).get("accessToken") or "") if isinstance(payload, dict) else ""
                    mismatch = _validate_replacement(account, expected_access_token, new_token)
                    if not mismatch:
                        merged_cookies = _merged_cookie_snapshot(cookies, env.session.cookies.jar)
                        return {
                            "ok": True,
                            "access_token": new_token,
                            "cookies": merged_cookies,
                            "proxy": selected_proxy,
                            "attempt_count": attempt,
                        }
                    last_error = mismatch
                    if mismatch != "session 刷新未签发新的 Web AT":
                        error_code = "replacement_identity_mismatch"
                        break
                else:
                    body = str(refreshed.text or "")[:500].lower()
                    challenge = int(refreshed.status_code) == 403 and any(
                        marker in body for marker in ("<html", "cloudflare", "cf-chl-", "turnstile")
                    )
                    retryable = challenge or int(refreshed.status_code) in {408, 425, 429} or int(refreshed.status_code) >= 500
                    last_error = f"Cookie session 刷新 HTTP {int(refreshed.status_code)}"
                    retryable_network = retryable
                    if not retryable:
                        break
                if int(warm.status_code) in {401, 403} and int(refreshed.status_code) in {401, 403}:
                    last_error = "保存的 Cookie session 已失效或被当前出口拒绝"
            except Exception as exc:
                last_error = f"Cookie session 刷新失败: {type(exc).__name__}: {str(exc)[:160]}"
                retryable_network = True
            if attempt < attempts:
                time.sleep(float(attempt))
        return {
            "ok": False,
            "error_code": error_code,
            "error": last_error,
            "retryable_network": retryable_network,
        }
    finally:
        if env is not None:
            try:
                env.session.close()
            except Exception:
                pass


__all__ = ["refresh_account_web_access_token"]
