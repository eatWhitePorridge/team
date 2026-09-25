# -*- coding: utf-8 -*-
"""ChatGPT account cookie credential storage.

The stored document is intentionally browser-neutral.  It keeps the fields
needed by Chromium while accepting either a requests/curl_cffi CookieJar or
Selenium/CDP cookie dictionaries as input.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_COOKIE_DIR = _PROJECT_ROOT / "account_cookies"
_ALLOWED_DOMAIN_SUFFIXES = ("chatgpt.com", "openai.com")
_MAX_CREDENTIAL_BYTES = 16 * 1024 * 1024
_SESSION_COOKIE_PREFIXES = (
    "__secure-next-auth.session-token",
    "__host-next-auth.session-token",
    "__secure-authjs.session-token",
    "__host-authjs.session-token",
    # Current ChatGPT web sessions also expose a signed workspace/session
    # cookie under this name. Treat it as a session credential for capture and
    # validation so a modern browser jar is not rejected as "empty".
    "oai-client-auth-session",
)
_SAME_SITE_VALUES = {
    "strict": "Strict",
    "lax": "Lax",
    "none": "None",
    "no_restriction": "None",
    "no-restriction": "None",
}


class CookieCredentialError(ValueError):
    """Raised when a cookie credential is malformed or outside managed storage."""


def _cookie_dir() -> Path:
    """Resolve the managed directory at call time so isolated DB tests work."""
    try:
        from core import db

        configured = getattr(db, "_COOKIE_DIR", _DEFAULT_COOKIE_DIR)
    except (ImportError, AttributeError):
        configured = _DEFAULT_COOKIE_DIR
    return Path(configured).expanduser()


def _as_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _mapping_value(data: Mapping[str, Any], *keys: str) -> tuple[bool, Any]:
    for key in keys:
        if key in data:
            return True, data[key]
    return False, None


def _object_value(cookie: Any, *names: str) -> tuple[bool, Any]:
    for name in names:
        if hasattr(cookie, name):
            return True, getattr(cookie, name)
    return False, None


def _cookie_value(cookie: Any, *names: str) -> tuple[bool, Any]:
    if isinstance(cookie, Mapping):
        return _mapping_value(cookie, *names)
    return _object_value(cookie, *names)


def _cookie_rest(cookie: Any) -> Mapping[str, Any]:
    if isinstance(cookie, Mapping):
        rest = cookie.get("rest") or cookie.get("_rest")
    else:
        rest = getattr(cookie, "_rest", None) or getattr(cookie, "rest", None)
    return rest if isinstance(rest, Mapping) else {}


def _rest_value(rest: Mapping[str, Any], *names: str) -> tuple[bool, Any]:
    wanted = {name.lower() for name in names}
    for key, value in rest.items():
        if str(key).lower() in wanted:
            return True, value
    return False, None


def _as_bool(value: Any, *, presence_means_true: bool = False) -> bool:
    if value is None:
        return presence_means_true
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _normalise_expires(value: Any) -> int | float | None:
    if value in (None, ""):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not (number == number) or number in (float("inf"), float("-inf")):
        return None
    return int(number) if number.is_integer() else number


def _normalise_same_site(value: Any) -> str | None:
    if value is None:
        return None
    return _SAME_SITE_VALUES.get(str(value).strip().lower())


def _domain_from_url(value: Any) -> str:
    if not value:
        return ""
    try:
        return (urlparse(str(value)).hostname or "").lower()
    except ValueError:
        return ""


def is_managed_cookie_domain(domain: str) -> bool:
    """Return whether *domain* is ChatGPT/OpenAI itself or a subdomain."""
    host = str(domain or "").strip().lower().lstrip(".").rstrip(".")
    if not host or any(ch in host for ch in "/\\:@ \t\r\n"):
        return False
    return any(host == suffix or host.endswith("." + suffix) for suffix in _ALLOWED_DOMAIN_SUFFIXES)


def _iter_raw_cookies(raw: Any) -> Iterable[Any]:
    if raw is None:
        return ()
    # curl_cffi.requests.Cookies implements Mapping as well as exposing the
    # underlying CookieJar.  Unwrap it before treating regular dict payloads
    # as CDP/Selenium records.
    jar = getattr(raw, "jar", None)
    if jar is not None and jar is not raw:
        raw = jar
    if isinstance(raw, Mapping):
        if "cookies" in raw:
            nested = raw.get("cookies")
            if nested is None:
                return ()
            if isinstance(nested, (str, bytes, Mapping)):
                raise CookieCredentialError("cookies 字段必须是列表")
            return nested
        if "name" in raw:
            return (raw,)
        raise CookieCredentialError("Cookie 字典缺少 name 或 cookies 字段")
    if isinstance(raw, (str, bytes)):
        raise CookieCredentialError("Cookie 输入不能是字符串")
    try:
        return iter(raw)
    except TypeError as exc:
        raise CookieCredentialError("不支持的 Cookie 输入类型") from exc


def _normalise_cookie(cookie: Any) -> dict[str, Any] | None:
    name_found, raw_name = _cookie_value(cookie, "name")
    value_found, raw_value = _cookie_value(cookie, "value")
    if not name_found or not value_found or raw_name is None:
        return None

    name = _as_text(raw_name)
    value = "" if raw_value is None else _as_text(raw_value)
    if not name or any(ch in name for ch in ";\r\n"):
        return None
    if "\r" in value or "\n" in value:
        return None

    _, raw_domain = _cookie_value(cookie, "domain")
    domain = str(raw_domain or "").strip().lower().rstrip(".")
    if not domain:
        _, raw_url = _cookie_value(cookie, "url")
        domain = _domain_from_url(raw_url)
    if not is_managed_cookie_domain(domain):
        return None

    _, raw_path = _cookie_value(cookie, "path")
    path = str(raw_path or "/").strip() or "/"
    if not path.startswith("/") or "\r" in path or "\n" in path:
        path = "/"

    _, raw_expires = _cookie_value(cookie, "expires", "expiry")
    _, raw_secure = _cookie_value(cookie, "secure")
    http_only_found, raw_http_only = _cookie_value(
        cookie, "httpOnly", "httponly", "http_only"
    )
    same_site_found, raw_same_site = _cookie_value(
        cookie, "sameSite", "samesite", "same_site"
    )
    rest = _cookie_rest(cookie)
    if not http_only_found:
        http_only_found, raw_http_only = _rest_value(rest, "HttpOnly", "Http-Only")
    if not same_site_found:
        same_site_found, raw_same_site = _rest_value(rest, "SameSite")

    return {
        "name": name,
        "value": value,
        "domain": domain,
        "path": path,
        "expires": _normalise_expires(raw_expires),
        "httpOnly": _as_bool(raw_http_only, presence_means_true=http_only_found),
        "secure": _as_bool(raw_secure),
        "sameSite": _normalise_same_site(raw_same_site) if same_site_found else None,
    }


def normalize_cookies(raw: Any, source: str = "") -> list[dict[str, Any]]:
    """Normalize CookieJar, Selenium, or CDP cookies for Chromium reuse.

    ``source`` is accepted for capture metadata/call-site clarity; normalization
    is shape-driven so mixed Selenium and CDP payloads are also supported.
    Unrelated domains and malformed cookie records are discarded.
    """
    del source
    deduplicated: dict[tuple[str, str, str], dict[str, Any]] = {}
    for raw_cookie in _iter_raw_cookies(raw):
        cookie = _normalise_cookie(raw_cookie)
        if cookie is None:
            continue
        key = (cookie["domain"], cookie["path"], cookie["name"])
        deduplicated[key] = cookie
    return list(deduplicated.values())


def capture_selenium_cookies(
    driver: Any,
    *,
    attempts: int = 3,
    retry_delay: float = 0.4,
) -> list[dict[str, Any]]:
    """Capture Chromium cookies, allowing the session jar time to settle.

    Chromium may report an empty ``Network.getAllCookies`` result for a short
    window after the auth callback.  An empty result is therefore not treated
    as authoritative: the other CDP command and Selenium fallback are tried,
    then the whole read is retried briefly.
    """
    execute_cdp = getattr(driver, "execute_cdp_cmd", None)
    errors: list[Exception] = []
    had_valid_response = False
    max_attempts = max(1, int(attempts or 1))
    delay = max(0.0, float(retry_delay or 0.0))

    for attempt in range(1, max_attempts + 1):
        if callable(execute_cdp):
            for command in ("Network.getAllCookies", "Storage.getCookies"):
                try:
                    result = execute_cdp(command, {})
                    if isinstance(result, Mapping) and isinstance(result.get("cookies"), list):
                        had_valid_response = True
                        normalized = normalize_cookies(result, source="cdp")
                        if normalized:
                            return normalized
                except Exception as exc:  # Selenium wraps CDP failures by browser/version.
                    errors.append(exc)

        get_cookies = getattr(driver, "get_cookies", None)
        if callable(get_cookies):
            try:
                raw_cookies = get_cookies()
                had_valid_response = True
                normalized = normalize_cookies(raw_cookies, source="selenium")
                if normalized:
                    return normalized
            except Exception as exc:
                errors.append(exc)

        if attempt < max_attempts and delay:
            time.sleep(delay)

    if not had_valid_response and errors:
        raise CookieCredentialError(f"无法读取浏览器 Cookie: {errors[-1]}") from errors[-1]
    if not had_valid_response:
        raise CookieCredentialError("driver 不支持 CDP 或 Selenium Cookie 读取")
    return []


def _is_expired(cookie: Mapping[str, Any], now: float | None = None) -> bool:
    expires = _normalise_expires(cookie.get("expires"))
    return expires is not None and expires > 0 and expires <= (time.time() if now is None else now)


def has_session_cookie(cookies: Any, *, now: float | None = None) -> bool:
    for cookie in normalize_cookies(cookies):
        name = cookie["name"].lower()
        if (
            cookie["value"]
            and any(name == prefix or name.startswith(prefix + ".") for prefix in _SESSION_COOKIE_PREFIXES)
            and not _is_expired(cookie, now)
        ):
            return True
    return False


def _safe_filename(email: str) -> str:
    canonical = str(email or "").strip().lower()
    if not canonical:
        raise CookieCredentialError("邮箱不能为空")
    readable = re.sub(r"[^A-Za-z0-9@._+-]+", "_", canonical).strip(".")
    while ".." in readable:
        readable = readable.replace("..", "_")
    readable = readable[:120] or "account"
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    return f"cookies-{readable}-{digest}.json"


def _normalise_account_id(account_id: Any) -> int | None:
    if account_id is None:
        return None
    if isinstance(account_id, bool):
        raise CookieCredentialError("account_id 必须是正整数")
    try:
        normalized = int(account_id)
    except (TypeError, ValueError) as exc:
        raise CookieCredentialError("account_id 必须是正整数") from exc
    if normalized <= 0 or str(account_id).strip() != str(normalized):
        raise CookieCredentialError("account_id 必须是正整数")
    return normalized


def _managed_path(path: str | os.PathLike[str], *, must_exist: bool = False) -> Path:
    root = _cookie_dir().resolve()
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=must_exist)
    except (OSError, RuntimeError) as exc:
        raise CookieCredentialError("Cookie 凭证路径无效") from exc
    if resolved == root or not resolved.is_relative_to(root):
        raise CookieCredentialError("Cookie 凭证路径越出托管目录")
    if resolved.suffix.lower() != ".json":
        raise CookieCredentialError("Cookie 凭证必须是 JSON 文件")
    return resolved


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    try:
        directory.chmod(0o700)
    except OSError:
        pass

    fd, temp_name = tempfile.mkstemp(prefix=".cookie-", suffix=".tmp", dir=str(directory))
    temp_path = Path(temp_name)
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


def persist_cookie_credential(
    email: str,
    cookies: Any,
    source: str = "",
    account_id: int | None = None,
    *, version: str = "",
) -> dict[str, Any]:
    """Atomically persist a normalized account Cookie Jar.

    The return value contains metadata only; cookie values remain in the
    managed credential file and should not be copied into account rows.
    """
    normalized = normalize_cookies(cookies, source=source)
    normalized_account_id = _normalise_account_id(account_id)
    captured_at = _utc_now()
    session_present = has_session_cookie(normalized)
    root = _cookie_dir().resolve()
    root.mkdir(parents=True, exist_ok=True)
    filename = (
        f"account-{normalized_account_id}.json"
        if normalized_account_id is not None
        else _safe_filename(email)
    )
    if version:
        if not re.fullmatch(r"[a-f0-9]{32}", version):
            raise ValueError("Cookie 凭证版本无效")
        filename = filename.removesuffix(".json") + f"-{version}.json"
    path = _managed_path(root / filename)
    document = {
        "schema_version": 1,
        "type": "chatgpt_web_cookies",
        "account_id": normalized_account_id,
        "email": str(email).strip(),
        "captured_at": captured_at,
        "cookies": normalized,
        # Compatibility keys for the first storage implementation.
        "format": "chatgpt-chromium-cookie-jar",
        "version": 1,
        "source": str(source or "").strip(),
        "saved_at": captured_at,
        "count": len(normalized),
        "has_session_cookie": session_present,
    }
    _atomic_write_json(path, document)
    return {
        "path": str(path),
        "credential_path": path.name,
        "saved_at": captured_at,
        "count": len(normalized),
        "has_session_cookie": session_present,
    }


def load_cookie_credential(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Safely load and revalidate a cookie credential from managed storage."""
    managed = _managed_path(path, must_exist=True)
    try:
        if managed.stat().st_size > _MAX_CREDENTIAL_BYTES:
            raise CookieCredentialError("Cookie 凭证文件过大")
        payload = json.loads(managed.read_text(encoding="utf-8"))
    except CookieCredentialError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CookieCredentialError("Cookie 凭证读取失败") from exc
    if not isinstance(payload, Mapping) or not isinstance(payload.get("cookies"), list):
        raise CookieCredentialError("Cookie 凭证格式无效")

    cookies = normalize_cookies(payload["cookies"], source=str(payload.get("source") or ""))
    account_id = _normalise_account_id(payload.get("account_id"))
    captured_at = str(payload.get("captured_at") or payload.get("saved_at") or "")
    return {
        "schema_version": 1,
        "type": "chatgpt_web_cookies",
        "account_id": account_id,
        "email": str(payload.get("email") or ""),
        "captured_at": captured_at,
        "cookies": cookies,
        # Compatibility keys for existing callers.
        "format": "chatgpt-chromium-cookie-jar",
        "version": 1,
        "source": str(payload.get("source") or ""),
        "saved_at": captured_at,
        "count": len(cookies),
        "has_session_cookie": has_session_cookie(cookies),
    }


def delete_cookie_credential(path: str | os.PathLike[str]) -> bool:
    """Delete one credential, refusing paths outside the managed directory."""
    managed = _managed_path(path)
    try:
        managed.unlink()
        return True
    except FileNotFoundError:
        return False


def to_cdp_cookies(cookies: Any) -> list[dict[str, Any]]:
    """Convert stored cookies to ``Network.setCookies`` CookieParam records."""
    output: list[dict[str, Any]] = []
    now = time.time()
    for cookie in normalize_cookies(cookies):
        if _is_expired(cookie, now):
            continue
        item: dict[str, Any] = {
            "name": cookie["name"],
            "value": cookie["value"],
            "domain": cookie["domain"],
            "path": cookie["path"],
            "httpOnly": cookie["httpOnly"],
            "secure": cookie["secure"],
        }
        expires = cookie["expires"]
        if expires is not None and expires > 0:
            item["expires"] = expires
        if cookie["sameSite"] is not None:
            item["sameSite"] = cookie["sameSite"]
        output.append(item)
    return output


def to_browser_import_cookies(cookies: Any) -> list[dict[str, Any]]:
    """Convert stored cookies to the top-level array used by browser importers.

    The managed credential document contains account metadata around its
    ``cookies`` member.  Roxy/Chromium cookie import expects the array itself
    and the cookie-detail fields returned by Chromium's cookie API.
    """
    output: list[dict[str, Any]] = []
    now = time.time()
    for cookie in normalize_cookies(cookies):
        if _is_expired(cookie, now):
            continue
        expires = cookie["expires"]
        is_session = expires is None or expires <= 0
        name = cookie["name"]
        value = cookie["value"]
        output.append({
            "domain": cookie["domain"],
            "expires": -1 if is_session else int(expires),
            "httpOnly": cookie["httpOnly"],
            "name": name,
            "path": cookie["path"],
            "priority": "Medium",
            "sameSite": cookie["sameSite"] or "Lax",
            "secure": cookie["secure"],
            "session": is_session,
            "size": len(name.encode("utf-8")) + len(value.encode("utf-8")),
            "sourcePort": 443,
            "sourceScheme": "Secure",
            "value": value,
        })
    return output


def inject_selenium_cookies(driver: Any, cookies: Any) -> int:
    """Inject cookies into Chromium, preferring one atomic CDP operation."""
    cdp_cookies = to_cdp_cookies(cookies)
    if not cdp_cookies:
        return 0

    execute_cdp = getattr(driver, "execute_cdp_cmd", None)
    if callable(execute_cdp):
        execute_cdp("Network.setCookies", {"cookies": cdp_cookies})
        return len(cdp_cookies)

    add_cookie = getattr(driver, "add_cookie", None)
    if not callable(add_cookie):
        raise CookieCredentialError("driver 不支持 CDP 或 Selenium Cookie 注入")

    navigate = getattr(driver, "get", None)
    if not callable(navigate):
        raise CookieCredentialError("Selenium Cookie 注入需要 driver.get 以切换目标域名")

    original_url = str(getattr(driver, "current_url", "") or "")
    grouped: dict[str, list[dict[str, Any]]] = {}
    for cookie in cdp_cookies:
        host = str(cookie.get("domain") or "").lstrip(".")
        grouped.setdefault(host, []).append(cookie)

    added = 0
    try:
        for host, domain_cookies in grouped.items():
            navigate(f"https://{host}/")
            for cookie in domain_cookies:
                selenium_cookie = dict(cookie)
                if "expires" in selenium_cookie:
                    selenium_cookie["expiry"] = int(selenium_cookie.pop("expires"))
                add_cookie(selenium_cookie)
                added += 1
    finally:
        if original_url.startswith(("http://", "https://")):
            navigate(original_url)
    return added


def to_cookie_header(cookies: Any, url: str = "https://chatgpt.com/") -> str:
    """Build an RFC-style Cookie header for one URL (mainly for diagnostics)."""
    parsed = urlparse(url if "://" in str(url) else "https://" + str(url))
    host = (parsed.hostname or "").lower()
    request_path = parsed.path or "/"
    is_secure = parsed.scheme.lower() == "https"
    matched: list[dict[str, Any]] = []
    now = time.time()
    for cookie in normalize_cookies(cookies):
        domain = cookie["domain"].lower()
        bare_domain = domain.lstrip(".")
        domain_matches = (
            host == bare_domain
            if not domain.startswith(".")
            else host == bare_domain or host.endswith("." + bare_domain)
        )
        cookie_path = cookie["path"] or "/"
        path_matches = request_path == cookie_path or (
            request_path.startswith(cookie_path)
            and (cookie_path.endswith("/") or request_path[len(cookie_path):].startswith("/"))
        )
        if (
            domain_matches
            and path_matches
            and (is_secure or not cookie["secure"])
            and not _is_expired(cookie, now)
        ):
            matched.append(cookie)
    matched.sort(key=lambda item: len(item["path"]), reverse=True)
    return "; ".join(f"{cookie['name']}={cookie['value']}" for cookie in matched)


__all__ = [
    "CookieCredentialError",
    "capture_selenium_cookies",
    "delete_cookie_credential",
    "has_session_cookie",
    "inject_selenium_cookies",
    "is_managed_cookie_domain",
    "load_cookie_credential",
    "normalize_cookies",
    "persist_cookie_credential",
    "to_browser_import_cookies",
    "to_cdp_cookies",
    "to_cookie_header",
]
