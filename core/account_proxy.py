# -*- coding: utf-8 -*-
"""Resolve the registration proxy needed to reuse an account session."""
from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import quote, unquote, urlparse, urlunparse


_ALLOWED_SCHEMES = {"http", "https", "socks4", "socks5", "socks5h"}
_PROXY_COUNTRY_SELECTOR_RE = re.compile(
    r"(?i)(?P<prefix>(?:country|region|zone)[_-])(?P<value>[a-z]{2})(?=[_-]|$)"
)
_IPWO_COUNTRY_TOKEN_RE = re.compile(
    r"(?i)(?P<prefix>[_-])(?P<value>[a-z]{2})(?=[_-]|$)"
)
_STICKY_SESSION_RE = re.compile(
    r"(?i)(?P<prefix>(?:session|sid)[_-])(?P<value>[a-z0-9]+)"
)


def rewrite_proxy_country(proxy_url: str, country: str | None) -> str:
    """Rewrite a provider country selector without exposing proxy credentials.

    Roxy and the HTTP qualification checker use the same sticky proxy pool.
    Their country override must therefore be applied before a qualification
    request too.  Providers that do not expose a named selector are left
    unchanged; changing an opaque username would risk breaking its session.
    """
    text = str(proxy_url or "").strip()
    target = str(country or "").strip().upper()
    if target and not re.fullmatch(r"[A-Z]{2}", target):
        raise ValueError("代理国家覆盖必须是两位国家码，例如 PH、JP 或 GB")
    if not text or not target:
        return text

    try:
        parsed = urlparse(text)
        username = unquote(parsed.username or "")
        hostname = parsed.hostname or ""
    except (TypeError, ValueError):
        return text
    if not username or not hostname:
        return text

    rewritten, count = _PROXY_COUNTRY_SELECTOR_RE.subn(
        lambda match: f"{match.group('prefix')}{target}",
        username,
    )
    # IPWO uses a standalone country token such as ``_JP_``.  Only rewrite it
    # when the username has exactly one such token, avoiding ambiguous edits.
    if count == 0 and hostname.lower().endswith(".ipwo.net"):
        token_matches = list(_IPWO_COUNTRY_TOKEN_RE.finditer(username))
        if len(token_matches) == 1:
            match = token_matches[0]
            start, end = match.span("value")
            rewritten = f"{username[:start]}{target}{username[end:]}"
            count = 1
    if count == 0 or rewritten == username:
        return text

    userinfo = quote(rewritten, safe="-._~")
    if parsed.password is not None:
        userinfo += ":" + quote(unquote(parsed.password or ""), safe="-._~")
    host = hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        return text
    return urlunparse(parsed._replace(netloc=f"{userinfo}@{host}{port}"))


def _normalized_proxy(raw: object) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    try:
        from config import proxy as proxy_config

        value = proxy_config.normalize_proxy_url(value)
        parsed = urlparse(value)
        if (
            parsed.scheme.lower() not in _ALLOWED_SCHEMES
            or not parsed.hostname
            or parsed.port is None
            or parsed.username == "***"
            or parsed.password == "***"
        ):
            return ""
    except (TypeError, ValueError):
        return ""
    return value


def _endpoint_key(raw: object) -> tuple[str, str, int] | None:
    value = str(raw or "").strip()
    if not value:
        return None
    try:
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        if scheme not in _ALLOWED_SCHEMES or not parsed.hostname or parsed.port is None:
            return None
    except (TypeError, ValueError):
        return None
    family = "socks" if scheme.startswith("socks") else "http"
    return family, parsed.hostname.lower(), int(parsed.port)


def _proxy_credential_key(raw: object) -> tuple[str, int, str, str] | None:
    """Return the exact endpoint and credentials, ignoring only the scheme."""
    value = str(raw or "").strip()
    if not value:
        return None
    try:
        parsed = urlparse(value)
        if not parsed.hostname or parsed.port is None:
            return None
    except (TypeError, ValueError):
        return None
    return (
        parsed.hostname.lower(),
        int(parsed.port),
        unquote(parsed.username or ""),
        unquote(parsed.password or ""),
    )


def _sticky_proxy_credential_key(raw: object) -> tuple[str, int, str, str] | None:
    """Match dynamic proxies while ignoring exactly one sticky-session value."""
    value = str(raw or "").strip()
    if not value:
        return None
    try:
        parsed = urlparse(value)
        if not parsed.hostname or parsed.port is None:
            return None
    except (TypeError, ValueError):
        return None
    username = unquote(parsed.username or "")
    normalized_username, count = _STICKY_SESSION_RE.subn(
        lambda match: f"{match.group('prefix')}<sticky-session>",
        username,
        count=1,
    )
    if count != 1:
        return None
    return (
        parsed.hostname.lower(),
        int(parsed.port),
        normalized_username,
        unquote(parsed.password or ""),
    )


def _replace_proxy_scheme(proxy_url: str, scheme: str) -> str:
    try:
        return urlunparse(urlparse(proxy_url)._replace(scheme=scheme))
    except (TypeError, ValueError):
        return proxy_url


def _configured_proxies() -> list[str]:
    try:
        from config import proxy as proxy_config

        return [
            candidate
            for candidate in (
                _normalized_proxy(raw)
                for raw in list(getattr(proxy_config, "PROXY_POOL", []) or [])
            )
            if candidate
        ]
    except (ImportError, AttributeError, TypeError):
        return []


def resolve_registration_proxy(account: Mapping[str, object] | None) -> str:
    """Return a usable proxy without exposing masked task credentials.

    New accounts persist the exact upstream proxy.  Older Roxy accounts only
    have a masked host/port in their traffic snapshot, so match that endpoint
    back to the current configured pool.
    """
    if not isinstance(account, Mapping):
        return ""

    persisted = _normalized_proxy(account.get("proxy_used"))
    if persisted:
        # 旧版本机 Rod 注册为了兼容 Chromium，把 socks5h:// 转换成
        # socks5:// 后误存入账号。补 2FA 直接复用该值时会改成本地 DNS
        # 解析，部分出口因此拿到错误站点证书。只有当前代理池存在端点和
        # 凭证完全一致的 socks5h 条目时才纠正，避免改动真实 socks5 配置。
        driver = str(account.get("registration_driver") or "").strip().lower()
        try:
            persisted_scheme = urlparse(persisted).scheme.lower()
        except ValueError:
            persisted_scheme = ""
        if driver == "local_browser" and persisted_scheme == "socks5":
            persisted_key = _proxy_credential_key(persisted)
            persisted_sticky_key = _sticky_proxy_credential_key(persisted)
            for candidate in _configured_proxies():
                try:
                    candidate_scheme = urlparse(candidate).scheme.lower()
                except ValueError:
                    continue
                if (
                    candidate_scheme == "socks5h"
                    and persisted_key is not None
                    and _proxy_credential_key(candidate) == persisted_key
                ):
                    return _replace_proxy_scheme(persisted, "socks5h")
                # 注册启动失败后的代理轮换只会改 username 中的一段
                # session/sid。允许这一段不同，同时严格校验端点、密码和
                # username 的其余部分，并保留账号实际使用的 sticky 值。
                if (
                    candidate_scheme == "socks5h"
                    and persisted_sticky_key is not None
                    and _sticky_proxy_credential_key(candidate) == persisted_sticky_key
                ):
                    return _replace_proxy_scheme(persisted, "socks5h")
        return persisted

    configured = _configured_proxies()
    if not configured:
        return ""

    job = None
    try:
        job_id = int(account.get("registration_job_id") or 0)
        if job_id:
            from core import db

            job = db.get_job(job_id)
    except (TypeError, ValueError):
        job = None
    traffic = (job or {}).get("roxy_traffic") if isinstance(job, Mapping) else None
    hint = _endpoint_key(
        (traffic or {}).get("upstream_proxy") if isinstance(traffic, Mapping) else ""
    )
    if hint is not None:
        for candidate in configured:
            if _endpoint_key(candidate) == hint:
                return candidate

    if (
        len(configured) == 1
        and str(account.get("registration_driver") or "").strip().lower() == "roxy"
    ):
        return configured[0]
    return ""


__all__ = ["resolve_registration_proxy", "rewrite_proxy_country"]
