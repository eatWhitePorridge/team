"""Reconcile NextAuth session rotation with curl_cffi's additive cookie jar."""
from __future__ import annotations

import re
import time
from datetime import timezone
from email.utils import parsedate_to_datetime
from http.cookies import CookieError, SimpleCookie
from urllib.parse import urlsplit


_SESSION_NAME = re.compile(
    r"^((?:__Secure-|__Host-)?(?:next-auth|authjs)\.session-token)(?:\.([0-9]+))?$"
)


def session_cookie_scope(name: str, domain: str, path: str = "/") -> tuple[str, str, str] | None:
    match = _SESSION_NAME.fullmatch(name)
    if match is None:
        return None
    return (domain.lower().lstrip("."), path or "/", match[1])


def reconcile_session_cookies(cookies, response, url: str) -> int:
    """Honor session-cookie deletion/rotation before the next callback hop.

    curl_cffi merges surviving libcurl cookies back into its Python jar, so
    cookies deleted by the response can remain in Python and be sent again.
    Only an explicit deletion or a complete newly issued session replaces
    existing state; partial chunk updates cannot discard a working session.
    """
    target = urlsplit(url)
    if target.scheme != "https" or target.hostname != "chatgpt.com":
        return 0
    jar = getattr(cookies, "jar", None)
    if jar is None:
        return 0
    headers = getattr(response, "headers", {})
    get_list = getattr(headers, "get_list", None)
    raw_headers = (
        get_list("set-cookie") if callable(get_list)
        else [headers.get("set-cookie", "")]
    )
    issued: dict[tuple[str, str, str], dict[str, str | None]] = {}
    default_path = target.path.rsplit("/", 1)[0] or "/"
    for raw in raw_headers:
        parsed = SimpleCookie()
        try:
            parsed.load(raw)
        except (CookieError, TypeError):
            continue
        for name, morsel in parsed.items():
            domain = morsel["domain"] or target.hostname
            path = morsel["path"] or default_path
            scope = session_cookie_scope(name, domain, path)
            if scope is None or scope[0] != target.hostname:
                continue
            deleted = not morsel.value
            max_age = None
            try:
                max_age = int(morsel["max-age"])
            except (TypeError, ValueError):
                pass
            if max_age is not None:
                deleted |= max_age <= 0
            elif morsel["expires"]:
                try:
                    expires = parsedate_to_datetime(morsel["expires"])
                    if expires.tzinfo is None:
                        expires = expires.replace(tzinfo=timezone.utc)
                    deleted |= expires.timestamp() <= time.time()
                except (TypeError, ValueError, OverflowError):
                    pass
            issued.setdefault(scope, {})[name] = None if deleted else morsel.value

    removed = 0
    for scope, values in issued.items():
        current = {name: value for name, value in values.items() if value is not None}
        indices = sorted(
            int(_SESSION_NAME.fullmatch(name)[2])
            for name in current if name != scope[2]
        )
        whole = set(current) == {scope[2]}
        complete = (
            whole
            or len(indices) >= 2 and scope[2] not in current
            and indices == list(range(len(indices)))
        )
        # Require the transport to have accepted every new cookie before
        # removing any older representation that was not explicitly deleted.
        accepted = {
            c.name for c in jar
            if session_cookie_scope(c.name, c.domain, c.path) == scope
            and c.name in current and c.value == current[c.name]
        }
        replacement = complete and accepted == set(current)
        for cookie in list(jar):
            if session_cookie_scope(cookie.name, cookie.domain, cookie.path) != scope:
                continue
            explicit_delete = cookie.name in values and values[cookie.name] is None
            # A chunk suffix absent from this response may be unchanged, not
            # deleted. Require its explicit expiry before pruning that tail.
            superseded = replacement and (
                (whole and cookie.name != scope[2])
                or (not whole and cookie.name == scope[2])
                or (cookie.name in current and cookie.value != current[cookie.name])
            )
            if explicit_delete or superseded:
                jar.clear(cookie.domain, cookie.path, cookie.name)
                removed += 1
    return removed
