# -*- coding: utf-8 -*-
"""ChatGPT CES 的最小、可验证前端生命周期遥测。"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from config import (
    LOGIN_WEB_APP_VERSION,
    OAI_CLIENT_BUILD_NUMBER,
    OAI_CLIENT_VERSION,
    OPENAI_CLIENT_ID,
)

logger = logging.getLogger(__name__)

_CES_BASE = "https://chatgpt.com/ces/v1"
_APP_VERSION = str(OAI_CLIENT_VERSION).removeprefix("prod-")


def _profile_value(profile: Any, key: str, default: Any = "") -> Any:
    if isinstance(profile, dict):
        return profile.get(key, default)
    return getattr(profile, key, default)


def _identity(owner: Any) -> tuple[str, str]:
    session_id = str(getattr(owner, "oai_session_id", "") or "")
    anonymous_id = str(getattr(owner, "anonymous_id", "") or "")
    if not session_id:
        session_id = str(uuid.uuid4())
        setattr(owner, "oai_session_id", session_id)
    if not anonymous_id:
        anonymous_id = str(uuid.uuid4())
        setattr(owner, "anonymous_id", anonymous_id)
    return session_id, anonymous_id


def _login_web_identity(owner: Any) -> tuple[str, str, str]:
    stable_id = str(getattr(owner, "oaicom_stable_id", "") or "")
    anonymous_id = str(getattr(owner, "login_web_anonymous_id", "") or "")
    auth_logging_id = str(getattr(owner, "auth_session_logging_id", "") or "")
    if not stable_id:
        stable_id = str(uuid.uuid4())
        setattr(owner, "oaicom_stable_id", stable_id)
    if not anonymous_id:
        anonymous_id = str(uuid.uuid4())
        setattr(owner, "login_web_anonymous_id", anonymous_id)
    if not auth_logging_id:
        auth_logging_id = str(uuid.uuid4())
        setattr(owner, "auth_session_logging_id", auth_logging_id)
    return stable_id, anonymous_id, auth_logging_id


def _transition_authenticated_identity(owner: Any) -> tuple[str, str]:
    identity = getattr(owner, "_ces_authenticated_identity", None)
    if (
        isinstance(identity, tuple)
        and len(identity) == 2
        and all(str(value or "") for value in identity)
    ):
        return str(identity[0]), str(identity[1])
    session_id = str(uuid.uuid4())
    anonymous_id = str(uuid.uuid4())
    setattr(owner, "oai_session_id", session_id)
    setattr(owner, "anonymous_id", anonymous_id)
    identity = (session_id, anonymous_id)
    setattr(owner, "_ces_authenticated_identity", identity)
    return identity


def _was_emitted(owner: Any, key: str) -> bool:
    emitted = getattr(owner, "_ces_emitted", None)
    return isinstance(emitted, set) and key in emitted


def _mark_emitted(owner: Any, key: str) -> None:
    emitted = getattr(owner, "_ces_emitted", None)
    if not isinstance(emitted, set):
        emitted = set()
        setattr(owner, "_ces_emitted", emitted)
    emitted.add(key)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _page(*, logged_in: bool) -> dict[str, str]:
    return {
        "path": "/",
        "referrer": "https://auth.openai.com/" if logged_in else "",
        "search": "/",
        "title": "ChatGPT",
        "url": "https://chatgpt.com/",
        "hash": "",
    }


def _context(
    profile: Any,
    device_id: str,
    *,
    logged_in: bool,
    user_traits: dict[str, Any] | None = None,
) -> dict[str, Any]:
    language = str(
        _profile_value(profile, "navigator_language")
        or _profile_value(profile, "language")
        or "ja-JP"
    )
    major = str(
        _profile_value(profile, "chrome_major")
        or _profile_value(profile, "browser_major")
        or "146"
    )
    platform = str(
        _profile_value(profile, "user_agent_data_platform")
        or str(_profile_value(profile, "sec_ch_ua_platform", '"macOS"')).strip('"')
        or "macOS"
    )
    context: dict[str, Any] = {
        "page": _page(logged_in=logged_in),
        "userAgent": str(_profile_value(profile, "user_agent")),
        "userAgentData": {
            "brands": [
                {"brand": "Google Chrome", "version": major},
                {"brand": "Chromium", "version": major},
                {"brand": "Not)A;Brand", "version": "24"},
            ],
            "mobile": False,
            "platform": platform,
        },
        "locale": language,
        "library": {"name": "analytics.js", "version": "npm:next-1.81.1"},
        "campaign": {},
        "timezone": str(_profile_value(profile, "timezone_iana") or "Asia/Tokyo"),
        "app_name": "chatgpt",
        "app_version": _APP_VERSION,
        "browser_locale": language,
        "device_id": device_id,
        "auth_status": "logged_in" if logged_in else "logged_out",
    }
    if logged_in:
        context["user_traits"] = dict(user_traits or {})
    return context


def _base_payload(anonymous_id: str) -> dict[str, Any]:
    now = _iso_now()
    return {
        "timestamp": now,
        "integrations": {"Segment.io": True},
        "messageId": f"ajs-next-{int(time.time() * 1000)}-{uuid.uuid4()}",
        "anonymousId": anonymous_id,
        "writeKey": "oai",
        "sentAt": now,
        "_metadata": {
            "bundled": ["Segment.io"],
            "unbundled": [],
            "bundledIds": [],
        },
    }


def page_payload(
    profile: Any,
    device_id: str,
    anonymous_id: str,
    *,
    logged_in: bool,
    user_id: str | None = None,
    user_traits: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = _base_payload(anonymous_id)
    payload.update({
        "type": "page",
        "properties": _page(logged_in=logged_in),
        "context": _context(
            profile,
            device_id,
            logged_in=logged_in,
            user_traits=user_traits,
        ),
        "userId": user_id if logged_in else None,
    })
    return payload


def track_payload(
    event: str,
    properties: dict[str, Any],
    profile: Any,
    device_id: str,
    anonymous_id: str,
    *,
    logged_in: bool,
    user_id: str | None = None,
    user_traits: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = _base_payload(anonymous_id)
    event_properties = dict(properties)
    event_properties.setdefault("origin", "chat")
    event_properties.setdefault("app_version", _APP_VERSION)
    payload.update({
        "event": event,
        "type": "track",
        "properties": event_properties,
        "context": _context(
            profile,
            device_id,
            logged_in=logged_in,
            user_traits=user_traits,
        ),
        "userId": user_id if logged_in else None,
    })
    return payload


def identify_payload(
    profile: Any,
    device_id: str,
    anonymous_id: str,
    *,
    user_id: str,
    user_traits: dict[str, Any],
) -> dict[str, Any]:
    payload = _base_payload(anonymous_id)
    payload.update({
        "type": "identify",
        "userId": user_id,
        "traits": dict(user_traits),
        "context": _context(
            profile,
            device_id,
            logged_in=True,
            user_traits=user_traits,
        ),
    })
    return payload


_LOGIN_WEB_ROUTES = {
    "email_verification": {
        "path": "/email-verification",
        "route_id": "EMAIL_VERIFICATION",
        "title": "メールを確認してください - OpenAI",
        "name": "Email Verification",
    },
    "about_you": {
        "path": "/about-you",
        "route_id": "ABOUT_YOU",
        "title": "あなたについて - OpenAI",
        "name": "About You",
    },
}


def _login_web_context(
    profile: Any,
    device_id: str,
    *,
    stable_id: str,
    auth_logging_id: str,
    route: str,
    redacted: bool,
) -> dict[str, Any]:
    spec = _LOGIN_WEB_ROUTES[route]
    language = str(
        _profile_value(profile, "navigator_language")
        or _profile_value(profile, "language")
        or "ja-JP"
    )
    major = str(
        _profile_value(profile, "chrome_major")
        or _profile_value(profile, "browser_major")
        or "146"
    )
    platform = str(
        _profile_value(profile, "user_agent_data_platform")
        or str(_profile_value(profile, "sec_ch_ua_platform", '"macOS"')).strip('"')
        or "macOS"
    )
    page = {
        "path": spec["path"],
        "referrer": "redacted" if redacted else "https://chatgpt.com/",
        "search": "redacted" if redacted else "",
        "title": spec["title"],
        "url": "redacted" if redacted else f"https://auth.openai.com{spec['path']}",
    }
    context: dict[str, Any] = {
        "page": page,
        "userAgent": str(_profile_value(profile, "user_agent")),
        "userAgentData": {
            "brands": [
                {"brand": "Google Chrome", "version": major},
                {"brand": "Chromium", "version": major},
                {"brand": "Not)A;Brand", "version": "24"},
            ],
            "mobile": False,
            "platform": platform,
        },
        "locale": language,
        "library": {"name": "analytics.js", "version": "npm:next-1.81.1"},
        "timezone": str(_profile_value(profile, "timezone_iana") or "Asia/Tokyo"),
        "app_name": "login_web",
        "app_version": LOGIN_WEB_APP_VERSION,
        "device_id": device_id,
        "oaicom_stable_id": stable_id,
        "auth_session_logging_id": auth_logging_id,
        "openai_client_id": OPENAI_CLIENT_ID,
        "app_name_enum": "chat",
    }
    if redacted:
        context["campaign"] = {}
    return context


def login_web_event_payload(
    event: str | None,
    properties: dict[str, Any],
    profile: Any,
    device_id: str,
    anonymous_id: str,
    *,
    stable_id: str,
    auth_logging_id: str,
    route: str,
    page: bool = False,
) -> dict[str, Any]:
    if route not in _LOGIN_WEB_ROUTES:
        raise ValueError(f"不支持的 Login Web route: {route}")
    spec = _LOGIN_WEB_ROUTES[route]
    payload = _base_payload(anonymous_id)
    if page:
        page_properties = dict(
            _login_web_context(
                profile,
                device_id,
                stable_id=stable_id,
                auth_logging_id=auth_logging_id,
                route=route,
                redacted=True,
            )["page"]
        )
        page_properties.update({
            "route_id": spec["route_id"],
            "is_error": False,
            "origin": "login-web",
            "category": "Identity",
            "name": spec["name"],
        })
        payload.update({
            "type": "page",
            "properties": page_properties,
            "category": "Identity",
            "name": spec["name"],
        })
    else:
        event_properties = dict(properties)
        event_properties.setdefault("openai_app", "login_web")
        event_properties.setdefault("origin", "login-web")
        payload.update({
            "event": str(event or ""),
            "type": "track",
            "properties": event_properties,
        })
    payload["context"] = _login_web_context(
        profile,
        device_id,
        stable_id=stable_id,
        auth_logging_id=auth_logging_id,
        route=route,
        redacted=page,
    )
    payload["userId"] = None
    return payload


def login_web_batch_payload(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {"writeKey": "oai", "batch": list(events), "sentAt": _iso_now()}


def _sync_headers(session: Any, *, access_token: str | None = None) -> dict[str, str]:
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/")
    headers["content-type"] = "text/plain"
    if access_token:
        headers["authorization"] = (
            access_token if access_token.lower().startswith("bearer ") else f"Bearer {access_token}"
        )
    return headers


def _sync_post(session: Any, endpoint: str, payload: dict[str, Any], *, access_token: str | None = None) -> None:
    response = session.post(
        f"{_CES_BASE}/{endpoint}",
        headers=_sync_headers(session, access_token=access_token),
        data=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
    )
    if int(getattr(response, "status_code", 0) or 0) >= 400:
        raise RuntimeError(f"CES {endpoint} HTTP {response.status_code}: {(response.text or '')[:180]}")


def _sync_login_web_post(session: Any, payload: dict[str, Any]) -> None:
    response = session.post(
        f"{_CES_BASE}/b",
        headers={"content-type": "text/plain"},
        data=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
    )
    if int(getattr(response, "status_code", 0) or 0) >= 400:
        raise RuntimeError(f"CES b HTTP {response.status_code}: {(response.text or '')[:180]}")


def prime_sync_settings(session: Any, *, phase: str = "anonymous") -> None:
    """加载 ChatGPT CES 配置；匿名态和登录态各请求一次。"""
    emitted_key = f"settings:{phase}"
    if _was_emitted(session, emitted_key):
        return
    settings = session.get(
        f"{_CES_BASE}/projects/oai/settings",
        headers=session._get_common_headers(),
    )
    if int(getattr(settings, "status_code", 0) or 0) >= 400:
        raise RuntimeError(f"CES settings HTTP {settings.status_code}")
    _mark_emitted(session, emitted_key)


def begin_authenticated_identity(session: Any) -> None:
    """在首次登录态 backend 请求前切换 OAI session/analytics identity。"""
    _transition_authenticated_identity(session)


def emit_sync_login_web_stage(session: Any, stage: str) -> None:
    stage_key = str(stage or "").strip().lower()
    emitted_key = f"login_web:{stage_key}"
    if _was_emitted(session, emitted_key):
        return
    stable_id, anonymous_id, auth_logging_id = _login_web_identity(session)
    profile = session.browser_profile
    device_id = session.device_id
    if stage_key == "email_verification":
        events = [login_web_event_payload(
            None,
            {},
            profile,
            device_id,
            anonymous_id,
            stable_id=stable_id,
            auth_logging_id=auth_logging_id,
            route="email_verification",
            page=True,
        )]
    elif stage_key == "otp_validated":
        events = [login_web_event_payload(
            "Validate OTP",
            {"intent": "validate", "kind": "email", "routeId": "email_otp_verification"},
            profile,
            device_id,
            anonymous_id,
            stable_id=stable_id,
            auth_logging_id=auth_logging_id,
            route="email_verification",
        )]
    elif stage_key in {"about_you", "otp_validated_about_you"}:
        events = []
        if stage_key == "otp_validated_about_you":
            events.append(login_web_event_payload(
                "Validate OTP",
                {"intent": "validate", "kind": "email", "routeId": "email_otp_verification"},
                profile,
                device_id,
                anonymous_id,
                stable_id=stable_id,
                auth_logging_id=auth_logging_id,
                route="email_verification",
            ))
        events.extend([
            login_web_event_payload(
                "Onboarding: Age Fallback Triggered",
                {"flow": "authapi", "loginWebUI": "new", "route": "ABOUT_YOU"},
                profile,
                device_id,
                anonymous_id,
                stable_id=stable_id,
                auth_logging_id=auth_logging_id,
                route="about_you",
            ),
            login_web_event_payload(
                None,
                {},
                profile,
                device_id,
                anonymous_id,
                stable_id=stable_id,
                auth_logging_id=auth_logging_id,
                route="about_you",
                page=True,
            ),
        ])
    elif stage_key == "profile_submitted":
        events = [
            login_web_event_payload(
                "Onboarding: User Info: Complete",
                {"flow": "authapi", "loginWebUI": "new"},
                profile,
                device_id,
                anonymous_id,
                stable_id=stable_id,
                auth_logging_id=auth_logging_id,
                route="about_you",
            ),
            login_web_event_payload(
                "Onboarding: Age Fallback Submit",
                {"flow": "authapi", "loginWebUI": "new", "route": "ABOUT_YOU"},
                profile,
                device_id,
                anonymous_id,
                stable_id=stable_id,
                auth_logging_id=auth_logging_id,
                route="about_you",
            ),
        ]
    else:
        raise ValueError(f"不支持的 Login Web stage: {stage}")
    _sync_login_web_post(session, login_web_batch_payload(events))
    _mark_emitted(session, emitted_key)


def emit_sync_anonymous(session: Any) -> None:
    if _was_emitted(session, "anonymous"):
        return
    _, anonymous_id = _identity(session)
    profile = session.browser_profile
    device_id = session.device_id
    prime_sync_settings(session, phase="anonymous")
    _sync_post(session, "p", page_payload(profile, device_id, anonymous_id, logged_in=False))
    _sync_post(session, "t", track_payload(
        "Sidebar Show",
        {"type": "slideover"},
        profile,
        device_id,
        anonymous_id,
        logged_in=False,
    ))
    language = str(profile.get("navigator_language") or "ja-JP")
    _sync_post(session, "t", track_payload(
        "Locale Loaded",
        {"loaded_locale": language, "raw_browser_locale": language, "suggested_locale": language},
        profile,
        device_id,
        anonymous_id,
        logged_in=False,
    ))
    _mark_emitted(session, "anonymous")


def emit_sync_signup(session: Any) -> None:
    if _was_emitted(session, "signup"):
        return
    _, anonymous_id = _identity(session)
    _sync_post(session, "t", track_payload(
        "Auth: Signup",
        {"location": "Chat header", "provider": "openai"},
        session.browser_profile,
        session.device_id,
        anonymous_id,
        logged_in=False,
    ))
    _mark_emitted(session, "signup")


def _session_traits(session_info: Any) -> tuple[str, dict[str, Any]]:
    if isinstance(session_info, dict):
        user = session_info.get("user") if isinstance(session_info.get("user"), dict) else {}
        account = session_info.get("account") if isinstance(session_info.get("account"), dict) else {}
        user_id = str(user.get("id") or "")
        plan_type = str(account.get("planType") or "free")
        workspace_id = None
        workspace_type = None
    else:
        user = getattr(session_info, "user", {}) or {}
        account = getattr(session_info, "account", {}) or {}
        user_id = str(
            getattr(session_info, "chatgpt_user_id", "")
            or (user.get("id") if isinstance(user, dict) else "")
        )
        plan_type = str(
            getattr(session_info, "plan_type", "")
            or (account.get("planType") if isinstance(account, dict) else "")
            or "free"
        )
        workspace_id = None
        workspace_type = None
    return user_id, {
        "plan_type": plan_type,
        "workspace_id": workspace_id,
        "workspace_type": workspace_type,
        "is_openai_internal": False,
    }


def emit_sync_authenticated(session: Any, session_info: Any, *, access_token: str | None = None) -> None:
    user_id, traits = _session_traits(session_info)
    if not user_id:
        logger.debug("[CES] 登录态缺 user_id，跳过 Identify/Onboarding")
        return
    if _was_emitted(session, "authenticated"):
        return
    _, anonymous_id = _transition_authenticated_identity(session)
    profile = session.browser_profile
    device_id = session.device_id
    prime_sync_settings(session, phase="authenticated")
    _sync_post(session, "p", page_payload(
        profile, device_id, anonymous_id, logged_in=True, user_id=user_id, user_traits=traits,
    ), access_token=access_token)
    _sync_post(session, "t", track_payload(
        "Sidebar Show", {"type": "slideover"}, profile, device_id, anonymous_id,
        logged_in=True, user_id=user_id, user_traits=traits,
    ), access_token=access_token)
    language = str(profile.get("navigator_language") or "ja-JP")
    _sync_post(session, "t", track_payload(
        "Locale Loaded",
        {"loaded_locale": language, "raw_browser_locale": language, "suggested_locale": language},
        profile, device_id, anonymous_id,
        logged_in=True, user_id=user_id, user_traits=traits,
    ), access_token=access_token)
    _sync_post(session, "i", identify_payload(
        profile, device_id, anonymous_id, user_id=user_id, user_traits=traits,
    ), access_token=access_token)
    _sync_post(session, "t", track_payload(
        "Onboarding Shown", {}, profile, device_id, anonymous_id,
        logged_in=True, user_id=user_id, user_traits=traits,
    ), access_token=access_token)
    _mark_emitted(session, "authenticated")


def _async_headers(client: Any, profile: Any, device_id: str, *, access_token: str | None = None) -> dict[str, str]:
    from core.protocol_v2.core.http_client import chatgpt_frontend_headers

    session_id, _ = _identity(client)
    headers = chatgpt_frontend_headers(
        profile,
        device_id,
        session_id,
        content_type="text/plain",
    )
    if access_token:
        headers["authorization"] = (
            access_token if access_token.lower().startswith("bearer ") else f"Bearer {access_token}"
        )
    return headers


async def _async_post(
    client: Any,
    profile: Any,
    device_id: str,
    endpoint: str,
    payload: dict[str, Any],
    *,
    access_token: str | None = None,
) -> None:
    response = await client.post(
        f"{_CES_BASE}/{endpoint}",
        headers=_async_headers(client, profile, device_id, access_token=access_token),
        content=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
    )
    if int(getattr(response, "status_code", 0) or 0) >= 400:
        raise RuntimeError(f"CES {endpoint} HTTP {response.status_code}: {(response.text or '')[:180]}")


async def _async_login_web_post(client: Any, payload: dict[str, Any]) -> None:
    response = await client.post(
        f"{_CES_BASE}/b",
        headers={"content-type": "text/plain"},
        content=json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
    )
    if int(getattr(response, "status_code", 0) or 0) >= 400:
        raise RuntimeError(f"CES b HTTP {response.status_code}: {(response.text or '')[:180]}")


async def emit_async_login_web_stage(
    client: Any,
    profile: Any,
    device_id: str,
    stage: str,
) -> None:
    stage_key = str(stage or "").strip().lower()
    emitted_key = f"login_web:{stage_key}"
    if _was_emitted(client, emitted_key):
        return
    stable_id, anonymous_id, auth_logging_id = _login_web_identity(client)
    if stage_key == "email_verification":
        events = [login_web_event_payload(
            None,
            {},
            profile,
            device_id,
            anonymous_id,
            stable_id=stable_id,
            auth_logging_id=auth_logging_id,
            route="email_verification",
            page=True,
        )]
    elif stage_key == "otp_validated":
        events = [login_web_event_payload(
            "Validate OTP",
            {"intent": "validate", "kind": "email", "routeId": "email_otp_verification"},
            profile,
            device_id,
            anonymous_id,
            stable_id=stable_id,
            auth_logging_id=auth_logging_id,
            route="email_verification",
        )]
    elif stage_key in {"about_you", "otp_validated_about_you"}:
        events = []
        if stage_key == "otp_validated_about_you":
            events.append(login_web_event_payload(
                "Validate OTP",
                {"intent": "validate", "kind": "email", "routeId": "email_otp_verification"},
                profile,
                device_id,
                anonymous_id,
                stable_id=stable_id,
                auth_logging_id=auth_logging_id,
                route="email_verification",
            ))
        events.extend([
            login_web_event_payload(
                "Onboarding: Age Fallback Triggered",
                {"flow": "authapi", "loginWebUI": "new", "route": "ABOUT_YOU"},
                profile,
                device_id,
                anonymous_id,
                stable_id=stable_id,
                auth_logging_id=auth_logging_id,
                route="about_you",
            ),
            login_web_event_payload(
                None,
                {},
                profile,
                device_id,
                anonymous_id,
                stable_id=stable_id,
                auth_logging_id=auth_logging_id,
                route="about_you",
                page=True,
            ),
        ])
    elif stage_key == "profile_submitted":
        events = [
            login_web_event_payload(
                "Onboarding: User Info: Complete",
                {"flow": "authapi", "loginWebUI": "new"},
                profile,
                device_id,
                anonymous_id,
                stable_id=stable_id,
                auth_logging_id=auth_logging_id,
                route="about_you",
            ),
            login_web_event_payload(
                "Onboarding: Age Fallback Submit",
                {"flow": "authapi", "loginWebUI": "new", "route": "ABOUT_YOU"},
                profile,
                device_id,
                anonymous_id,
                stable_id=stable_id,
                auth_logging_id=auth_logging_id,
                route="about_you",
            ),
        ]
    else:
        raise ValueError(f"不支持的 Login Web stage: {stage}")
    await _async_login_web_post(client, login_web_batch_payload(events))
    _mark_emitted(client, emitted_key)


async def emit_async_anonymous(client: Any, profile: Any, device_id: str) -> None:
    if _was_emitted(client, "anonymous"):
        return
    _, anonymous_id = _identity(client)
    settings = await client.get(
        f"{_CES_BASE}/projects/oai/settings",
        headers={"user-agent": profile.user_agent, "accept-language": profile.locale},
    )
    if int(getattr(settings, "status_code", 0) or 0) >= 400:
        raise RuntimeError(f"CES settings HTTP {settings.status_code}")
    await _async_post(
        client, profile, device_id, "p",
        page_payload(profile, device_id, anonymous_id, logged_in=False),
    )
    await _async_post(
        client, profile, device_id, "t",
        track_payload(
            "Sidebar Show",
            {"type": "slideover"},
            profile,
            device_id,
            anonymous_id,
            logged_in=False,
        ),
    )
    language = profile.language
    await _async_post(
        client, profile, device_id, "t",
        track_payload(
            "Locale Loaded",
            {"loaded_locale": language, "raw_browser_locale": language, "suggested_locale": language},
            profile,
            device_id,
            anonymous_id,
            logged_in=False,
        ),
    )
    _mark_emitted(client, "anonymous")


async def emit_async_signup(client: Any, profile: Any, device_id: str) -> None:
    if _was_emitted(client, "signup"):
        return
    _, anonymous_id = _identity(client)
    await _async_post(
        client, profile, device_id, "t",
        track_payload(
            "Auth: Signup",
            {"location": "Chat header", "provider": "openai"},
            profile,
            device_id,
            anonymous_id,
            logged_in=False,
        ),
    )
    _mark_emitted(client, "signup")


async def emit_async_authenticated(
    client: Any,
    profile: Any,
    device_id: str,
    session_info: Any,
    *,
    access_token: str | None = None,
) -> None:
    user_id, traits = _session_traits(session_info)
    if not user_id:
        logger.debug("[CES] OAuth 登录态缺 user_id，跳过 Identify/Onboarding")
        return
    if _was_emitted(client, "authenticated"):
        return
    _, anonymous_id = _transition_authenticated_identity(client)
    settings = await client.get(
        f"{_CES_BASE}/projects/oai/settings",
        headers={"user-agent": profile.user_agent, "accept-language": profile.locale},
    )
    if int(getattr(settings, "status_code", 0) or 0) >= 400:
        raise RuntimeError(f"CES settings HTTP {settings.status_code}")
    await _async_post(
        client, profile, device_id, "p",
        page_payload(profile, device_id, anonymous_id, logged_in=True, user_id=user_id, user_traits=traits),
        access_token=access_token,
    )
    await _async_post(
        client, profile, device_id, "t",
        track_payload(
            "Sidebar Show", {"type": "slideover"}, profile, device_id, anonymous_id,
            logged_in=True, user_id=user_id, user_traits=traits,
        ),
        access_token=access_token,
    )
    language = str(getattr(profile, "language", "ja-JP") or "ja-JP")
    await _async_post(
        client, profile, device_id, "t",
        track_payload(
            "Locale Loaded",
            {"loaded_locale": language, "raw_browser_locale": language, "suggested_locale": language},
            profile, device_id, anonymous_id,
            logged_in=True, user_id=user_id, user_traits=traits,
        ),
        access_token=access_token,
    )
    await _async_post(
        client, profile, device_id, "i",
        identify_payload(profile, device_id, anonymous_id, user_id=user_id, user_traits=traits),
        access_token=access_token,
    )
    await _async_post(
        client, profile, device_id, "t",
        track_payload(
            "Onboarding Shown", {}, profile, device_id, anonymous_id,
            logged_in=True, user_id=user_id, user_traits=traits,
        ),
        access_token=access_token,
    )
    _mark_emitted(client, "authenticated")


__all__ = [
    "emit_async_anonymous",
    "emit_async_authenticated",
    "emit_async_login_web_stage",
    "emit_async_signup",
    "emit_sync_anonymous",
    "emit_sync_authenticated",
    "emit_sync_login_web_stage",
    "emit_sync_signup",
    "identify_payload",
    "login_web_batch_payload",
    "login_web_event_payload",
    "page_payload",
    "track_payload",
]
