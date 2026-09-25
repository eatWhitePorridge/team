# -*- coding: utf-8 -*-
"""RoxyBrowser 本地 API 客户端。"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, unquote, urljoin, urlparse, urlunparse

import requests

from config import roxybrowser as _cfg
from config.env_loader import build_subprocess_env
from core.protocol_rate_limit import rotate_sticky_proxy_session

logger = logging.getLogger(__name__)

# RoxyBrowser only accepts one /browser/create operation at a time. Registration
# workers may still open and use separate profiles concurrently after creation.
_PROFILE_CREATE_LOCK = threading.Lock()
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DISK_CACHE_SLOT_CONDITION = threading.Condition()
_DISK_CACHE_SLOTS_IN_USE: set[int] = set()
_PROXY_SESSION_LOCK = threading.RLock()
_PROXY_SESSION_ACTIVE_OWNERS: dict[str, str] = {}
_PROXY_SESSION_RECENT: dict[str, float] = {}
_ROXY_PROCESS_CLOSE_GRACE_SECONDS = 2.0
_ROXY_PROCESS_TERM_GRACE_SECONDS = 1.0
_ROXY_PROCESS_POLL_SECONDS = 0.1


def _check_registration_stop_requested() -> None:
    """Lazy import avoids a module cycle while preserving task-local stop state."""
    try:
        from core.registration_service import check_stop_requested
    except ImportError:
        return
    check_stop_requested()


def _sleep_with_stop(seconds: float, *, respect_stop: bool = True) -> None:
    remaining = max(0.0, float(seconds or 0.0))
    while remaining > 0:
        if respect_stop:
            _check_registration_stop_requested()
        step = min(0.25, remaining)
        time.sleep(step)
        remaining -= step
    if respect_stop:
        _check_registration_stop_requested()

_LOW_TRAFFIC_CHROME_ARGS = (
    "--blink-settings=imagesEnabled=false",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-sync",
    "--metrics-recording-only",
    "--no-first-run",
)

# 只阻止不参与认证状态机的静态大资源和观测上报。字体会参与浏览器字体画像，
# 必须正常加载；也不要加入 SVG/CSS/JS 或认证、挑战域名。
_LOW_TRAFFIC_BLOCKED_URLS = (
    "*://auth.openai.com/awe/api/v2/rum*",
    "*://browser-intake-datadoghq.com/*",
    "*://*.browser-intake-datadoghq.com/*",
    "*://*/*.bmp*",
    "*://*/*.gif*",
    "*://*/*.ico*",
    "*://*/*.jpeg*",
    "*://*/*.jpg*",
    "*://*/*.png*",
    "*://*/*.webp*",
    "*://*/*.avif*",
    "*://*/*.flac*",
    "*://*/*.m4a*",
    "*://*/*.mov*",
    "*://*/*.mp3*",
    "*://*/*.mp4*",
    "*://*/*.ogg*",
    "*://*/*.wav*",
    "*://*/*.webm*",
)


@dataclass(frozen=True)
class _RoxyProcessIdentity:
    pid: int
    profile_id: str
    start_marker: str
    command_line: str


@dataclass
class RoxyOpenResult:
    profile_id: str
    raw: dict
    debugger_address: str | None = None
    webdriver_url: str | None = None
    ws_endpoint: str | None = None
    created_by_run: bool = False
    keep_open: bool = False
    browser_pid: int | None = None
    process_identity: _RoxyProcessIdentity | None = None


def _run_process_query(command: list[str]) -> subprocess.CompletedProcess:
    kwargs = {
        "capture_output": True,
        "text": True,
        "timeout": 2,
        "check": False,
        "env": build_subprocess_env(),
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(command, **kwargs)


def _read_process_snapshot(pid: int) -> tuple[str, str] | None:
    """Return a stable start marker and command line for one PID.

    Process inspection is deliberately PID-based.  We never enumerate and kill
    processes by name, because the Roxy desktop app and other profiles may be
    running at the same time.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None
    if pid <= 1:
        return None

    if os.name == "nt":
        script = (
            "$p=Get-CimInstance Win32_Process -Filter 'ProcessId = "
            f"{pid}' ; if ($null -ne $p) {{ @{{started=[string]$p.CreationDate;"
            "command=[string]$p.CommandLine}} | ConvertTo-Json -Compress }}"
        )
        try:
            result = _run_process_query([
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script,
            ])
            payload = json.loads((result.stdout or "").strip() or "null")
            if result.returncode != 0 or not isinstance(payload, dict):
                return None
            started = str(payload.get("started") or "").strip()
            command_line = str(payload.get("command") or "").strip()
            return (started, command_line) if started and command_line else None
        except Exception:
            return None

    proc_dir = Path(f"/proc/{pid}")
    if proc_dir.is_dir():
        try:
            command_line = (
                (proc_dir / "cmdline")
                .read_bytes()
                .replace(b"\0", b" ")
                .decode("utf-8", errors="replace")
                .strip()
            )
            stat = (proc_dir / "stat").read_text(encoding="utf-8", errors="replace")
            # Field 22 is process starttime.  The comm field may contain spaces
            # and parentheses, so split only after its final closing parenthesis.
            fields_after_comm = stat.rsplit(")", 1)[1].strip().split()
            start_marker = fields_after_comm[19]
            return (start_marker, command_line) if command_line else None
        except (IndexError, OSError):
            return None

    try:
        started = _run_process_query([
            "ps", "-p", str(pid), "-o", "lstart=",
        ])
        command = _run_process_query([
            "ps", "-p", str(pid), "-o", "command=",
        ])
        start_marker = (started.stdout or "").strip()
        command_line = (command.stdout or "").strip()
        if started.returncode != 0 or command.returncode != 0:
            return None
        return (start_marker, command_line) if start_marker and command_line else None
    except Exception:
        return None


def _process_exists(pid: int) -> bool:
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 1:
        return False
    if os.name == "nt":
        try:
            import ctypes

            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return ctypes.get_last_error() == 5  # access denied still means alive
        except Exception:
            return _read_process_snapshot(pid) is not None
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _is_owned_roxy_profile_process(command_line: str, profile_id: str) -> bool:
    """Accept only the top-level Roxy Chromium process for one exact profile."""
    command = str(command_line or "").strip()
    profile = str(profile_id or "").strip()
    if not command or not profile:
        return False
    lowered = command.lower().replace("\\", "/")
    profile_lower = profile.lower()
    if "--type=" in lowered:
        return False
    if not (
        "roxychrome" in lowered
        or ("roxybrowser" in lowered and "/chrome-bin/" in lowered)
    ):
        return False
    escaped = re.escape(profile_lower)
    return bool(re.search(
        rf"(?:/browser-cache/|[?&]id=){escaped}(?=$|[/\\?&#\s\"'])",
        lowered,
    ))


def _capture_roxy_process_identity(
    pid: int | None,
    profile_id: str,
) -> _RoxyProcessIdentity | None:
    if not pid:
        return None
    snapshot = _read_process_snapshot(pid)
    if snapshot is None:
        return None
    start_marker, command_line = snapshot
    if not _is_owned_roxy_profile_process(command_line, profile_id):
        return None
    return _RoxyProcessIdentity(
        pid=int(pid),
        profile_id=str(profile_id),
        start_marker=start_marker,
        command_line=command_line,
    )


def _owned_process_state(identity: _RoxyProcessIdentity) -> str:
    """Return same, exited, changed, or unverifiable for a captured PID."""
    snapshot = _read_process_snapshot(identity.pid)
    if snapshot is None:
        return "unverifiable" if _process_exists(identity.pid) else "exited"
    start_marker, command_line = snapshot
    if start_marker != identity.start_marker:
        return "changed"
    if not _is_owned_roxy_profile_process(command_line, identity.profile_id):
        return "changed"
    return "same"


def _wait_for_roxy_process_exit(
    identity: _RoxyProcessIdentity,
    timeout: float,
) -> str:
    deadline = time.monotonic() + max(0.0, float(timeout or 0.0))
    while True:
        state = _owned_process_state(identity)
        if state != "same":
            return state
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "same"
        time.sleep(min(_ROXY_PROCESS_POLL_SECONDS, remaining))


def _signal_owned_roxy_process(
    identity: _RoxyProcessIdentity,
    *,
    force: bool,
) -> bool:
    # Revalidate immediately before every signal.  If the PID was reused, do
    # nothing instead of risking the Roxy desktop app or an unrelated profile.
    if _owned_process_state(identity) != "same":
        return False
    try:
        if os.name == "nt":
            command = ["taskkill", "/PID", str(identity.pid), "/T"]
            if force:
                command.append("/F")
            _run_process_query(command)
        else:
            os.kill(identity.pid, signal.SIGKILL if force else signal.SIGTERM)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _terminate_owned_roxy_process(identity: _RoxyProcessIdentity) -> bool:
    _signal_owned_roxy_process(identity, force=False)
    state = _wait_for_roxy_process_exit(
        identity,
        _ROXY_PROCESS_TERM_GRACE_SECONDS,
    )
    if state in {"exited", "changed"}:
        return True
    if state != "same" or not _signal_owned_roxy_process(identity, force=True):
        return False
    return _wait_for_roxy_process_exit(identity, 1.0) in {"exited", "changed"}


def build_roxy_driver(opened: RoxyOpenResult):
    """Attach Selenium to a Roxy profile returned by ``open_profile``."""
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.remote.webdriver import WebDriver as RemoteWebDriver

    if opened.debugger_address:
        logger.info("[Roxy] Selenium 连接 debuggerAddress=%s", opened.debugger_address)
        options = Options()
        options.page_load_strategy = "eager"
        options.add_experimental_option("debuggerAddress", opened.debugger_address)
        driver_path = ""
        try:
            raw_data = opened.raw.get("data") if isinstance(opened.raw, dict) else {}
            if isinstance(raw_data, dict):
                driver_path = str(
                    raw_data.get("driver")
                    or raw_data.get("driverPath")
                    or raw_data.get("driver_path")
                    or ""
                ).strip()
        except Exception:
            driver_path = ""
        if driver_path:
            logger.info("[Roxy] 使用 Roxy chromedriver=%s", driver_path)
            service = Service(
                executable_path=driver_path,
                env=build_subprocess_env(),
            )
            return webdriver.Chrome(service=service, options=options)
        return webdriver.Chrome(
            service=Service(env=build_subprocess_env()),
            options=options,
        )

    if opened.webdriver_url:
        logger.info("[Roxy] Selenium 连接 webdriver_url=%s", opened.webdriver_url)
        options = Options()
        options.page_load_strategy = "eager"
        return RemoteWebDriver(command_executor=opened.webdriver_url, options=options)

    raise RuntimeError("Roxy 未返回可连接的 Selenium 地址")


def _strip_slashes(value: str) -> str:
    return str(value or "").strip().strip("/")


def _join_url(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _merge_chrome_args(existing, additions=()) -> list[str]:
    """保留用户参数顺序，并以精确参数值去重后追加默认参数。"""
    if existing is None:
        values = []
    elif isinstance(existing, (list, tuple)):
        values = list(existing)
    else:
        values = [existing]

    merged: list[str] = []
    seen: set[str] = set()
    for raw in [*values, *list(additions or ())]:
        value = str(raw or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        merged.append(value)
    return merged


def _replace_chrome_args(existing, replacements=()) -> list[str]:
    """Merge singleton Chromium flags while ensuring our final value wins."""
    replacement_values = _merge_chrome_args([], replacements)
    prefixes = {
        value.split("=", 1)[0]
        for value in replacement_values
        if value.startswith("--") and "=" in value
    }
    retained = [
        value
        for value in _merge_chrome_args(existing)
        if value.split("=", 1)[0] not in prefixes
    ]
    return _merge_chrome_args(retained, replacement_values)


def _resolve_disk_cache_root() -> Path:
    raw = str(
        getattr(_cfg, "ROXY_DISK_CACHE_DIR", "data/roxy-static-cache")
        or "data/roxy-static-cache"
    ).strip()
    root = Path(raw).expanduser()
    if not root.is_absolute():
        root = _PROJECT_ROOT / root
    return root.resolve(strict=False)


def _acquire_disk_cache_slot() -> tuple[int, Path]:
    """Reserve one cache directory so separate Chromium processes never share a writer."""
    slot_count = max(1, int(getattr(_cfg, "ROXY_DISK_CACHE_SLOTS", 10) or 10))
    root = _resolve_disk_cache_root()
    while True:
        _check_registration_stop_requested()
        with _DISK_CACHE_SLOT_CONDITION:
            for slot in range(slot_count):
                if slot in _DISK_CACHE_SLOTS_IN_USE:
                    continue
                _DISK_CACHE_SLOTS_IN_USE.add(slot)
                try:
                    cache_dir = root / f"slot-{slot}"
                    cache_dir.mkdir(parents=True, exist_ok=True)
                except Exception:
                    _DISK_CACHE_SLOTS_IN_USE.discard(slot)
                    _DISK_CACHE_SLOT_CONDITION.notify_all()
                    raise
                return slot, cache_dir
            _DISK_CACHE_SLOT_CONDITION.wait(timeout=0.25)


def _release_disk_cache_slot(slot: int | None) -> None:
    if slot is None:
        return
    with _DISK_CACHE_SLOT_CONDITION:
        _DISK_CACHE_SLOTS_IN_USE.discard(int(slot))
        _DISK_CACHE_SLOT_CONDITION.notify_all()


def configure_roxy_low_traffic_cdp(driver, *, enabled: bool | None = None) -> bool:
    """为已连接的 Selenium driver 启用缓存和保守资源拦截；失败时不阻断注册。"""
    if enabled is None:
        enabled = bool(getattr(_cfg, "ROXY_LOW_TRAFFIC_MODE", True))
    if not enabled:
        return False
    try:
        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd("Network.setCacheDisabled", {"cacheDisabled": False})
        driver.execute_cdp_cmd(
            "Network.setBlockedURLs",
            {"urls": list(_LOW_TRAFFIC_BLOCKED_URLS)},
        )
        logger.info(
            "[Roxy][低流量] 已启用浏览器缓存并拦截 %s 条保守资源规则",
            len(_LOW_TRAFFIC_BLOCKED_URLS),
        )
        return True
    except Exception as exc:
        logger.warning(
            "[Roxy][低流量] CDP 配置失败，保持默认加载策略继续：%s: %s",
            type(exc).__name__,
            str(exc)[:180],
        )
        return False


def _mask_proxy(proxy_url: str) -> str:
    parsed = urlparse(str(proxy_url or "").strip())
    if parsed.username or parsed.password:
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://***:***@{host}{port}"
    return str(proxy_url or "").strip()


_DYNAMIC_PROXY_SESSION_RE = re.compile(
    r"(?i)(?P<prefix>(?:session|sid)[_-])(?P<value>[a-z0-9]+)"
)
_PROXY_COUNTRY_SELECTOR_RE = re.compile(
    r"(?i)(?P<prefix>(?:country|region|zone)[_-])(?P<value>[a-z]{2})(?=[_-]|$)"
)
_IPWO_COUNTRY_TOKEN_RE = re.compile(
    r"(?i)(?P<prefix>[_-])(?P<value>[a-z]{2})(?=[_-]|$)"
)


def _roxy_proxy_country_override() -> str:
    value = str(getattr(_cfg, "ROXY_PROXY_COUNTRY_OVERRIDE", "") or "").strip().upper()
    if value and not re.fullmatch(r"[A-Z]{2}", value):
        raise ValueError(
            "ROXY_PROXY_COUNTRY_OVERRIDE 必须是两位国家码，例如 GB、JP 或 BR"
        )
    return value


def _rewrite_roxy_proxy_country(proxy_url: str) -> str:
    """Rewrite only the provider country selector used by a Roxy task."""
    text = str(proxy_url or "").strip()
    target = _roxy_proxy_country_override()
    if not text or not target:
        return text
    try:
        parsed = urlparse(text)
        username = unquote(parsed.username or "")
    except (TypeError, ValueError):
        return text
    if not username or not parsed.hostname:
        return text

    rewritten, count = _PROXY_COUNTRY_SELECTOR_RE.subn(
        lambda match: f"{match.group('prefix')}{target}",
        username,
    )
    # IPWO uses a standalone country token such as `_JP_` instead of a named
    # `region-JP` selector. Only rewrite it for IPWO and only when exactly one
    # alphabetic two-letter token exists, avoiding ambiguous credential edits.
    if count == 0 and str(parsed.hostname or "").lower().endswith(".ipwo.net"):
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
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port else ""
    return urlunparse(parsed._replace(netloc=f"{userinfo}@{host}{port}"))


def _proxy_session_identity(proxy_url: str) -> tuple[str, bool, str]:
    """Return a credential-free lease key, dynamic marker and log-safe summary."""
    text = str(proxy_url or "").strip()
    try:
        parsed = urlparse(text)
        username = unquote(parsed.username or "")
        host = str(parsed.hostname or "").lower()
        port = int(parsed.port or 0)
    except (TypeError, ValueError):
        return (f"invalid:{text}", False, "session=invalid")

    match = _DYNAMIC_PROXY_SESSION_RE.search(username)
    dynamic = match is not None
    # Passwords are intentionally excluded. The key never reaches logs or disk.
    key = f"{str(parsed.scheme or '').lower()}|{host}|{port}|{username}"
    if match:
        value = str(match.group("value") or "")
        if len(value) >= 8:
            masked = f"{value[:4]}***{value[-4:]}"
        elif len(value) >= 4:
            masked = f"{value[:2]}***{value[-2:]}"
        else:
            masked = "***"
        summary = f"{match.group('prefix').rstrip('_-').lower()}-{masked}"
    else:
        summary = f"fixed@{host}:{port}"
    return key, dynamic, summary


def _proxy_session_cooldown_seconds() -> float:
    return max(
        0.0,
        float(
            getattr(_cfg, "ROXY_PROXY_SESSION_REUSE_COOLDOWN_SECONDS", 1800)
            or 0
        ),
    )


def _reserve_proxy_session(proxy_url: str, owner: str) -> tuple[bool, str]:
    """Reserve one upstream identity across concurrent Roxy tasks in this process."""
    key, dynamic, summary = _proxy_session_identity(proxy_url)
    now = time.monotonic()
    cooldown = _proxy_session_cooldown_seconds()
    with _PROXY_SESSION_LOCK:
        if cooldown <= 0:
            _PROXY_SESSION_RECENT.clear()
        else:
            expired = [
                item_key
                for item_key, released_at in _PROXY_SESSION_RECENT.items()
                if now - released_at >= cooldown
            ]
            for item_key in expired:
                _PROXY_SESSION_RECENT.pop(item_key, None)

        active_owner = _PROXY_SESSION_ACTIVE_OWNERS.get(key)
        if active_owner == owner:
            return True, summary
        if active_owner:
            return False, f"{summary} 正被另一任务使用"
        if dynamic and key in _PROXY_SESSION_RECENT:
            remaining = max(0, int(cooldown - (now - _PROXY_SESSION_RECENT[key])))
            return False, f"{summary} 仍在复用冷却（约 {remaining}s）"
        _PROXY_SESSION_ACTIVE_OWNERS[key] = owner
    return True, summary


def _release_proxy_session(
    proxy_url: str,
    owner: str,
    *,
    remember: bool = True,
) -> None:
    key, dynamic, _summary = _proxy_session_identity(proxy_url)
    with _PROXY_SESSION_LOCK:
        if _PROXY_SESSION_ACTIVE_OWNERS.get(key) != owner:
            return
        _PROXY_SESSION_ACTIVE_OWNERS.pop(key, None)
        if dynamic and remember and _proxy_session_cooldown_seconds() > 0:
            _PROXY_SESSION_RECENT[key] = time.monotonic()


def _reset_proxy_session_leases_for_tests() -> None:
    """Clear process-local leases; production code never calls this helper."""
    with _PROXY_SESSION_LOCK:
        _PROXY_SESSION_ACTIVE_OWNERS.clear()
        _PROXY_SESSION_RECENT.clear()


def _safe_proxy_error(exc: Exception, proxy_url: str) -> str:
    """保留代理错误类型，同时确保日志不会带出认证信息。"""
    text = str(exc or "").replace(str(proxy_url or ""), _mask_proxy(proxy_url))
    text = re.sub(
        r"(?i)(https?|socks5h?)://[^/@\s]+@",
        r"\1://***:***@",
        text,
    )
    return f"{type(exc).__name__}: {text[:300]}"


def _probe_proxy_exit(proxy_url: str) -> tuple[bool, dict, str]:
    """Query the real exit GeoIP through the exact proxy assigned to Roxy."""
    target = str(
        getattr(_cfg, "ROXY_EXIT_GEOIP_URL", "")
        or "http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,timezone,query"
    ).strip()
    timeout = max(
        1,
        int(getattr(_cfg, "ROXY_EXIT_GEOIP_TIMEOUT", 8) or 8),
    )
    response = None
    try:
        response = requests.get(
            target,
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=(min(5, timeout), timeout),
            allow_redirects=True,
            headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
        )
        status_code = int(response.status_code or 0)
        if not 200 <= status_code < 300:
            return False, {}, f"GeoIP HTTP {status_code}"
        try:
            payload = response.json()
        except Exception as exc:
            return False, {}, f"GeoIP JSON 解析失败: {type(exc).__name__}"
        if not isinstance(payload, dict):
            return False, {}, "GeoIP 响应不是 JSON object"
        status = str(payload.get("status") or "").strip().lower()
        success = payload.get("success")
        if status in {"fail", "failed", "error"} or success is False:
            message = str(payload.get("message") or payload.get("error") or status)
            return False, {}, f"GeoIP 服务返回失败: {message[:160]}"

        timezone_value = payload.get("timezone")
        if isinstance(timezone_value, dict):
            timezone_value = timezone_value.get("id") or timezone_value.get("name")
        country_code = str(
            payload.get("countryCode")
            or payload.get("country_code")
            or payload.get("country_code2")
            or ""
        ).strip().upper()
        if not country_code:
            candidate = str(payload.get("country") or "").strip().upper()
            if len(candidate) == 2:
                country_code = candidate
        geo = {
            "ip": str(payload.get("query") or payload.get("ip") or "").strip(),
            "country": country_code,
            "country_name": str(payload.get("country") or "").strip(),
            "region": str(
                payload.get("regionName") or payload.get("region") or ""
            ).strip(),
            "city": str(payload.get("city") or "").strip(),
            "timezone": str(timezone_value or "").strip(),
        }
        if not geo["ip"] or not geo["country"]:
            return False, geo, "GeoIP 缺少 ip/country"
        return True, geo, "ok"
    except Exception as exc:
        return False, {}, _safe_proxy_error(exc, proxy_url)
    finally:
        if response is not None:
            response.close()


def _expected_exit_countries() -> set[str]:
    override = _roxy_proxy_country_override()
    if override:
        return {override}
    raw = str(getattr(_cfg, "ROXY_EXPECTED_COUNTRY", "JP") or "JP")
    return {
        item.strip().upper()
        for item in re.split(r"[,;\s]+", raw)
        if item.strip()
    } or {"JP"}


def _validate_proxy_candidate(
    proxy_url: str,
    *,
    check_chatgpt: bool,
) -> tuple[bool, str]:
    """Apply the exit-country gate first, then the optional ChatGPT reachability probe."""
    if bool(getattr(_cfg, "ROXY_STRICT_EXIT_COUNTRY", True)):
        geo_ok, geo, geo_detail = _probe_proxy_exit(proxy_url)
        if not geo_ok:
            return False, geo_detail
        actual_country = str(geo.get("country") or "").upper()
        expected = _expected_exit_countries()
        if actual_country not in expected:
            return (
                False,
                "出口国家不匹配: "
                f"actual={actual_country or '-'} expected={','.join(sorted(expected))} "
                f"ip={geo.get('ip') or '-'} city={geo.get('city') or '-'}",
            )
        _key, _dynamic, session_summary = _proxy_session_identity(proxy_url)
        logger.info(
            "[Roxy] 代理出口校验通过：ip=%s country=%s city=%s timezone=%s session=%s",
            geo.get("ip") or "-",
            actual_country,
            geo.get("city") or "-",
            geo.get("timezone") or "-",
            session_summary,
        )

    if not check_chatgpt:
        return True, "GeoIP gate passed"
    return _probe_proxy(proxy_url)


def _probe_proxy(proxy_url: str) -> tuple[bool, str]:
    """验证代理到 ChatGPT 的 SOCKS/CONNECT、TLS 和 HTTP 响应链路。"""
    target = str(
        getattr(_cfg, "ROXY_PROXY_PREFLIGHT_URL", "https://chatgpt.com/auth/login")
        or "https://chatgpt.com/auth/login"
    ).strip()
    timeout = max(1, int(getattr(_cfg, "ROXY_PROXY_PREFLIGHT_TIMEOUT", 10) or 10))
    response = None
    try:
        response = requests.get(
            target,
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=(min(5, timeout), timeout),
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        status_code = int(response.status_code or 0)
        # 403 可能只是 ChatGPT/Cloudflare 的业务挑战，仍能证明代理认证、TLS
        # 和目标站链路已打通。407 是代理认证失败；429 和 5xx 会让随后启动的
        # 浏览器高概率重复失败，因此在创建 Profile 前直接换代理/session。
        if status_code == 407:
            return False, "HTTP 407 proxy authentication required"
        if status_code == 429:
            return False, "HTTP 429 target rate limited"
        if status_code >= 500:
            return False, f"HTTP {status_code} upstream unavailable"
        if status_code <= 0:
            return False, f"invalid HTTP status {status_code}"
        return True, f"HTTP {status_code}"
    except Exception as exc:
        return False, _safe_proxy_error(exc, proxy_url)
    finally:
        if response is not None:
            response.close()


def _rotated_proxy_candidate(proxy_url: str, seen: set[str]) -> str:
    """Generate a distinct sticky session without looping on random collisions."""
    current = str(proxy_url or "").strip()
    for _ in range(8):
        rotated = rotate_sticky_proxy_session(current)
        if not rotated or rotated == current:
            return ""
        if rotated not in seen:
            return rotated
        current = rotated
    return ""


def _pick_working_proxy(
    excluded_proxy_urls: set[str] | None = None,
    *,
    lease_owner: str | None = None,
) -> str:
    """Pick a target-country exit that reaches ChatGPT."""
    from config import proxy as _proxy_cfg

    excluded = {str(value or "").strip() for value in (excluded_proxy_urls or set()) if value}
    candidates = []
    seen = set()
    for raw in list(getattr(_proxy_cfg, "PROXY_POOL", []) or []):
        proxy_url = _rewrite_roxy_proxy_country(
            _proxy_cfg.normalize_proxy_url(raw)
        )
        if proxy_url and proxy_url not in seen:
            candidates.append(proxy_url)
            seen.add(proxy_url)
    if not candidates:
        return ""

    random.shuffle(candidates)
    max_attempts = max(1, int(getattr(_cfg, "ROXY_PROXY_PREFLIGHT_ATTEMPTS", 5) or 5))
    queue = list(candidates)
    queued_or_tested = set(queue)
    attempts = 0
    considered = 0
    last_error = ""
    while queue and attempts < max_attempts and considered < max_attempts * 4:
        proxy_url = queue.pop(0)
        considered += 1
        if proxy_url in excluded:
            rotated = _rotated_proxy_candidate(proxy_url, queued_or_tested | excluded)
            if rotated:
                queue.append(rotated)
                queued_or_tested.add(rotated)
            continue

        reserved = False
        if lease_owner:
            reserved, lease_detail = _reserve_proxy_session(proxy_url, lease_owner)
            if not reserved:
                last_error = lease_detail
                logger.info("[Roxy] 跳过重复代理 session：%s", lease_detail)
                rotated = _rotated_proxy_candidate(proxy_url, queued_or_tested | excluded)
                if rotated:
                    queue.append(rotated)
                    queued_or_tested.add(rotated)
                continue

        attempts += 1
        try:
            _check_registration_stop_requested()
            logger.info(
                "[Roxy] 代理预检：attempt=%s/%s proxy=%s",
                attempts,
                max_attempts,
                _mask_proxy(proxy_url),
            )
            ok, detail = _validate_proxy_candidate(
                proxy_url,
                check_chatgpt=True,
            )
            _check_registration_stop_requested()
        except Exception:
            if reserved:
                _release_proxy_session(
                    proxy_url, lease_owner or "", remember=False
                )
            raise
        if ok:
            logger.info("[Roxy] 代理预检成功：%s %s", _mask_proxy(proxy_url), detail)
            return proxy_url
        if reserved:
            _release_proxy_session(proxy_url, lease_owner or "", remember=True)
        last_error = detail
        if excluded_proxy_urls is not None:
            excluded_proxy_urls.add(proxy_url)
        excluded.add(proxy_url)
        logger.warning(
            "[Roxy] 代理预检失败，换下一条：attempt=%s/%s proxy=%s error=%s",
            attempts,
            max_attempts,
            _mask_proxy(proxy_url),
            detail,
        )
        rotated = _rotated_proxy_candidate(proxy_url, queued_or_tested | excluded)
        if rotated:
            queue.append(rotated)
            queued_or_tested.add(rotated)

    raise RuntimeError(
        f"Roxy 代理预检失败：抽测 {attempts} 条均未通过出口/连通性检查；"
        f"上游代理可能认证失效、余额耗尽或并发额度已满。最后错误: {last_error}"
    )


def _claim_proxy_candidate(
    proxy_url: str,
    *,
    lease_owner: str,
    excluded_proxy_urls: set[str] | None,
    already_validated: bool,
    check_chatgpt: bool,
) -> str:
    """Own a candidate for one client; rotate and revalidate on races/cooldown."""
    candidate = str(proxy_url or "").strip()
    original = candidate
    seen = {candidate}
    excluded = {
        str(value or "").strip()
        for value in (excluded_proxy_urls or set())
        if value
    }
    max_attempts = max(
        1,
        int(getattr(_cfg, "ROXY_PROXY_PREFLIGHT_ATTEMPTS", 5) or 5),
    )
    last_error = ""

    for _ in range(max_attempts):
        if candidate in excluded:
            rotated = _rotated_proxy_candidate(candidate, seen | excluded)
            if not rotated:
                last_error = "代理已被本任务使用且不支持 sticky session 改写"
                break
            candidate = rotated
            seen.add(candidate)

        reserved, lease_detail = _reserve_proxy_session(candidate, lease_owner)
        if not reserved:
            last_error = lease_detail
            logger.info("[Roxy] 代理 session 冲突，生成新 session：%s", lease_detail)
            rotated = _rotated_proxy_candidate(candidate, seen | excluded)
            if not rotated:
                break
            candidate = rotated
            seen.add(candidate)
            continue

        candidate_was_validated = already_validated and candidate == original
        try:
            if candidate_was_validated:
                ok, detail = True, "already validated"
            else:
                ok, detail = _validate_proxy_candidate(
                    candidate,
                    check_chatgpt=check_chatgpt,
                )
            _check_registration_stop_requested()
        except Exception:
            _release_proxy_session(candidate, lease_owner, remember=False)
            raise
        if ok:
            logger.info("[Roxy] 已租用代理 session：%s", lease_detail)
            return candidate

        _release_proxy_session(candidate, lease_owner, remember=True)
        last_error = detail
        excluded.add(candidate)
        if excluded_proxy_urls is not None:
            excluded_proxy_urls.add(candidate)
        logger.warning(
            "[Roxy] 代理 session 校验失败，准备轮换：proxy=%s error=%s",
            _mask_proxy(candidate),
            detail,
        )
        rotated = _rotated_proxy_candidate(candidate, seen | excluded)
        if not rotated:
            break
        candidate = rotated
        seen.add(candidate)

    raise RuntimeError(last_error or "没有可租用的代理 session")


def _proxy_url_to_roxy_info(proxy_url: str) -> dict:
    """
    将 config/proxy.py 里的代理 URL 转成 Roxy /browser/create 的 proxyInfo。

    支持：
      http://user:pass@host:port
      https://user:pass@host:port
      socks5://user:pass@host:port
      socks5h://user:pass@host:port  -> Roxy 侧按 SOCKS5 处理
    """
    text = str(proxy_url or "").strip()
    if not text:
        raise ValueError("代理为空")
    parsed = urlparse(text)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https", "socks5", "socks5h"):
        raise ValueError(f"Roxy 暂不支持该代理协议: {scheme or '-'}")
    if not parsed.hostname or not parsed.port:
        raise ValueError(f"代理格式缺少 host/port: {_mask_proxy(text)}")

    protocol = {
        "http": "HTTP",
        "https": "HTTPS",
        "socks5": "SOCKS5",
        "socks5h": "SOCKS5",
    }[scheme]
    # Roxy /browser/create 官方字段是：
    # proxyMethod / proxyCategory / ipType / protocol / host / port / proxyUserName / proxyPassword / checkChannel
    # 之前误用了 proxyType/proxyHost/proxyPort/proxyAccount，Roxy 会忽略，导致创建窗口实际未设置代理。
    info = {
        "moduleId": 0,
        "proxyMethod": "custom",
        "proxyCategory": protocol,
        "ipType": "IPV4",
        "protocol": protocol,
        "host": parsed.hostname,
        "port": str(parsed.port),
    }
    if parsed.username:
        info["proxyUserName"] = unquote(parsed.username)
    if parsed.password:
        info["proxyPassword"] = unquote(parsed.password)
    check_channel = str(getattr(_cfg, "ROXY_PROXY_CHECK_CHANNEL", "") or "").strip()
    if check_channel:
        info["checkChannel"] = check_channel
    return info


def _dig(payload: dict, *keys: str):
    cur = payload
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _first(payload: dict, paths: list[tuple[str, ...]]) -> str:
    for path in paths:
        value = _dig(payload, *path)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _workspace_id_value() -> str | int:
    raw = str(getattr(_cfg, "ROXY_WORKSPACE_ID", "") or "").strip()
    if not raw:
        return ""
    return int(raw) if raw.isdigit() else raw


def _project_id_value() -> str | int:
    raw = str(getattr(_cfg, "ROXY_PROJECT_ID", "") or "").strip()
    if not raw:
        return ""
    return int(raw) if raw.isdigit() else raw


def _random_roxy_os() -> str:
    raw = str(
        getattr(_cfg, "ROXY_RANDOM_OS_CHOICES", "Windows,macOS")
        or "Windows,macOS"
    )
    choices = [
        part.strip()
        for part in raw.replace("\n", ",").replace(";", ",").split(",")
        if part.strip()
    ]
    valid = {"Windows", "macOS", "Linux", "IOS", "Android"}
    choices = [value for value in choices if value in valid]
    if not choices:
        choices = ["Windows", "macOS"]
    return random.choice(choices)


def _random_roxy_profile_name() -> str:
    prefix = str(
        getattr(_cfg, "ROXY_PROFILE_NAME_PREFIX", "rb") or "rb"
    ).strip() or "rb"
    return f"{prefix}-{int(time.time() * 1000)}-{random.randrange(0x10000):04x}"


class RoxyBrowserClient:
    def __init__(self, api_base: str | None = None, token: str | None = None):
        self.api_base = (api_base or _cfg.ROXY_API_BASE).strip()
        self.token = (token if token is not None else _cfg.ROXY_API_TOKEN).strip()
        self.http = requests.Session()
        self._close_lock = threading.Lock()
        self._http_closed = False
        self._traffic_bridge = None
        self._traffic_upstream = ""
        self._traffic_unavailable_reason = ""
        self._selected_proxy_url = ""
        self._proxy_lease_owner = uuid.uuid4().hex
        self._leased_proxy_url = ""
        self._disk_cache_slot: int | None = None
        self._disk_cache_dir: Path | None = None
        if self.token:
            # 官方文档要求所有接口请求头必须加 token。这里同时兼容 token / Authorization。
            self.http.headers.update({
                "token": self.token,
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            })

    @staticmethod
    def _is_retryable_error(exc: Exception) -> bool:
        text = str(exc or "").lower()
        return (
            "timeout" in text
            or "timed out" in text
            or "connection" in text
            or "temporarily" in text
            or "http 500" in text
            or "http 502" in text
            or "http 503" in text
            or "http 504" in text
            or "http 429" in text
        )

    @staticmethod
    def _is_create_busy_error(exc: Exception) -> bool:
        text = str(exc or "").strip().lower()
        return any(marker in text for marker in (
            "正在创建中",
            "创建中，请稍等",
            "creation in progress",
            "already creating",
        ))

    @staticmethod
    def _is_create_retryable_response_error(exc: Exception) -> bool:
        """仅识别服务端明确返回的临时状态；连接/读取超时可能已创建，不能重试。"""
        text = str(exc or "").strip().lower()
        if re.search(r"(?:http|status\s+code)\s+(?:429|502|503|504)\b", text):
            return True
        # 这是 Roxy /browser/create 已经返回的控制端错误，不是本地请求超时。
        # Node 在建立上游 TLS 前即失败，创建动作没有送达，原请求可以安全重试。
        return "client network socket disconnected before secure tls connection was established" in text

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
        respect_stop: bool = True,
    ) -> dict:
        url = _join_url(self.api_base, path)
        method_u = method.upper()
        # create 超时后服务端可能已创建环境，直接重试可能产生孤儿环境；默认不重试 create。
        is_create = str(path or "").rstrip("/").endswith("/create") or "browser/create" in str(path or "")
        max_attempts = 1 if is_create else max(1, int(getattr(_cfg, "ROXY_API_RETRIES", 3) or 3))
        base_delay = max(0.5, float(getattr(_cfg, "ROXY_API_RETRY_DELAY", 2) or 2))
        last_exc: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            if respect_stop:
                _check_registration_stop_requested()
            try:
                logger.debug(
                    "[Roxy] %s %s params=%s body=%s attempt=%s/%s",
                    method, url, params, json_body, attempt, max_attempts,
                )
                resp = self.http.request(
                    method_u,
                    url,
                    params=params or None,
                    json=json_body if json_body is not None else None,
                    timeout=(
                        3,
                        max(3, int(getattr(_cfg, "ROXY_API_TIMEOUT", 15) or 15)),
                    ),
                )
                text = resp.text or ""
                try:
                    payload = resp.json()
                except Exception:
                    payload = {"raw": text}
                if not (200 <= resp.status_code < 300):
                    raise RuntimeError(f"Roxy API 请求失败 {method_u} {path} HTTP {resp.status_code}: {text[:500]}")
                if isinstance(payload, dict):
                    code = payload.get("code")
                    ok = payload.get("ok")
                    success = payload.get("success")
                    if code not in (None, 0, 200, "0", "200") and ok is not True and success is not True:
                        msg = payload.get("msg") or payload.get("message") or payload.get("error") or json.dumps(payload, ensure_ascii=False)[:500]
                        raise RuntimeError(f"Roxy API 返回失败 {method_u} {path}: {msg}")
                if attempt > 1:
                    logger.info("[Roxy] API 重试成功：%s %s attempt=%s/%s", method_u, path, attempt, max_attempts)
                return payload if isinstance(payload, dict) else {"data": payload}
            except Exception as exc:
                last_exc = exc
                if respect_stop:
                    _check_registration_stop_requested()
                retryable = self._is_retryable_error(exc)
                if attempt >= max_attempts or not retryable:
                    raise
                delay = base_delay * attempt
                logger.warning(
                    "[Roxy] API 请求失败，将在 %.1fs 后重试：%s %s attempt=%s/%s error=%s",
                    delay, method_u, path, attempt, max_attempts, exc,
                )
                _sleep_with_stop(delay, respect_stop=respect_stop)
        raise last_exc or RuntimeError(f"Roxy API 请求失败 {method_u} {path}")

    def try_request(self, method: str, path: str, *, params: dict | None = None, json_body: dict | None = None) -> tuple[bool, dict | str]:
        """宽松请求：用于探测不同 Roxy 版本接口，失败不抛出。"""
        try:
            return True, self.request(method, path, params=params, json_body=json_body)
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _extract_workspace_items(payload: dict) -> list[dict]:
        """解析 /browser/workspace：团队 rows + project_details 项目列表；兼容递归兜底。"""
        out = []

        # 官方结构：data.rows[].id/workspaceName/project_details[].projectId/projectName
        rows = None
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, dict):
                rows = data.get("rows") or data.get("list") or data.get("records")
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                wid = row.get("id") or row.get("workspaceId") or row.get("workspace_id")
                wname = row.get("workspaceName") or row.get("workspace_name") or row.get("name") or str(wid or "")
                projects = row.get("project_details") or row.get("projectDetails") or row.get("projects") or []
                if isinstance(projects, list) and projects:
                    for proj in projects:
                        if not isinstance(proj, dict):
                            continue
                        pid = proj.get("projectId") or proj.get("project_id") or proj.get("id")
                        pname = proj.get("projectName") or proj.get("project_name") or proj.get("name") or str(pid or "")
                        if wid:
                            out.append({
                                "id": str(wid),
                                "name": str(wname),
                                "projectId": str(pid or ""),
                                "projectName": str(pname or ""),
                                "label": f"{wname} / {pname} ({wid}/{pid})" if pid else f"{wname} ({wid})",
                                "raw": {"workspace": row, "project": proj},
                            })
                elif wid:
                    out.append({
                        "id": str(wid),
                        "name": str(wname),
                        "projectId": "",
                        "projectName": "",
                        "label": f"{wname} ({wid})",
                        "raw": row,
                    })

        if out:
            return out

        # 兜底：递归抽 workspace/team/company 结构。
        def pick_id_name(item: dict) -> tuple[str, str]:
            wid = _first(item, [
                ("workspaceId",), ("workspace_id",), ("workspaceID",),
                ("teamId",), ("team_id",), ("teamID",),
                ("companyId",), ("company_id",), ("orgId",), ("org_id",),
                ("id",), ("value",), ("key",),
            ])
            name = _first(item, [
                ("workspaceName",), ("workspace_name",),
                ("teamName",), ("team_name",),
                ("companyName",), ("company_name",),
                ("orgName",), ("org_name",),
                ("name",), ("label",), ("title",), ("remark",),
            ])
            return wid, name

        def looks_like_workspace(item: dict) -> bool:
            keys = {str(k).lower() for k in item.keys()}
            joined = " ".join(keys)
            return any(x in joined for x in ("workspace", "team", "company", "org")) or ("id" in keys and "name" in keys)

        def walk(node):
            if isinstance(node, dict):
                wid, name = pick_id_name(node)
                if wid and looks_like_workspace(node):
                    out.append({"id": wid, "name": name or wid, "projectId": "", "projectName": "", "label": f"{name or wid} ({wid})", "raw": node})
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(payload)
        dedup = {}
        for item in out:
            raw_keys = {str(k).lower() for k in (item.get("raw") or {}).keys()}
            if "dirid" in raw_keys and not any(k in raw_keys for k in ("workspaceid", "teamid", "companyid")):
                continue
            key = f"{item.get('id')}::{item.get('projectId','')}"
            dedup[key] = item
        return list(dedup.values())

    def list_workspaces(self) -> dict:
        """
        获取 Roxy 团队/工作区列表。
        Roxy 不同版本路径可能有差异，因此先试配置路径，再试常见路径。
        """
        configured = str(getattr(_cfg, "ROXY_WORKSPACE_LIST_PATH", "") or "").strip()
        method = str(getattr(_cfg, "ROXY_WORKSPACE_LIST_METHOD", "GET") or "GET").upper()
        candidates = []
        if configured:
            candidates.append((method, configured))
        candidates.extend([
            ("GET", "/browser/workspace"),
            ("POST", "/browser/workspace"),
            ("GET", "/workspace/list"),
            ("POST", "/workspace/list"),
            ("GET", "/workspace"),
            ("POST", "/workspace"),
            ("GET", "/team/list"),
            ("POST", "/team/list"),
            ("GET", "/team"),
            ("POST", "/team"),
            ("GET", "/workspaces"),
            ("GET", "/teams"),
            ("GET", "/user/workspace/list"),
            ("POST", "/user/workspace/list"),
            ("GET", "/user/team/list"),
            ("POST", "/user/team/list"),
            ("GET", "/api/workspace/list"),
            ("POST", "/api/workspace/list"),
            ("GET", "/api/team/list"),
            ("POST", "/api/team/list"),
            ("GET", "/browser/workspace/list"),
            ("POST", "/browser/workspace/list"),
            ("GET", "/browser/team/list"),
            ("POST", "/browser/team/list"),
        ])

        errors = []
        seen = set()
        for m, path in candidates:
            key = (m, path)
            if key in seen:
                continue
            seen.add(key)
            ok, payload = self.try_request(m, path)
            if not ok:
                errors.append({"method": m, "path": path, "error": payload})
                continue
            items = self._extract_workspace_items(payload if isinstance(payload, dict) else {})
            if items:
                return {"ok": True, "path": path, "method": m, "items": items, "raw": payload}
            errors.append({"method": m, "path": path, "error": "响应中未解析到团队/工作区列表", "payload": payload})

        return {"ok": False, "items": [], "errors": errors}

    def create_profile(self, payload: dict | None = None) -> str:
        body = dict(getattr(_cfg, "ROXY_PROFILE_CREATE_PAYLOAD", {}) or {})
        random_name_enabled = bool(
            getattr(_cfg, "ROXY_RANDOM_PROFILE_NAME_ON_CREATE", True)
        )
        if random_name_enabled:
            body["name"] = _random_roxy_profile_name()
        random_os_enabled = bool(getattr(_cfg, "ROXY_RANDOM_OS_ON_CREATE", True))
        if random_os_enabled:
            body["os"] = _random_roxy_os()
            # 系统版本必须与本轮 OS 匹配，交给 Roxy 为随机系统生成一致版本。
            body.pop("osVersion", None)
        else:
            default_os = str(
                getattr(_cfg, "ROXY_DEFAULT_OS", "macOS") or "macOS"
            ).strip()
            if default_os:
                body.setdefault("os", default_os)
            default_os_version = str(
                getattr(_cfg, "ROXY_DEFAULT_OS_VERSION", "") or ""
            ).strip()
            if default_os_version:
                body.setdefault("osVersion", default_os_version)
        workspace_id = _workspace_id_value()
        if workspace_id:
            # Roxy 官方 /browser/create 要求 workspaceId。
            body.setdefault("workspaceId", workspace_id)
        project_id = _project_id_value()
        if project_id:
            body.setdefault("projectId", project_id)
        # 显式 payload 优先。流量统计会在调用 create 前先启动本地 SOCKS5
        # 计数桥，并通过 payload 把 Profile 指向该桥，不能再被代理池覆盖。
        if payload:
            body.update(payload)
        if bool(getattr(_cfg, "ROXY_CREATE_USE_PROXY_POOL", False)) and not body.get("proxyInfo"):
            from config import proxy as _proxy_cfg

            if bool(getattr(_cfg, "ROXY_PROXY_PREFLIGHT_ENABLED", True)):
                proxy_url = _pick_working_proxy()
            else:
                proxy_url = _rewrite_roxy_proxy_country(_proxy_cfg.pick_proxy())
            if proxy_url:
                proxy_info = _proxy_url_to_roxy_info(proxy_url)
                body["proxyInfo"] = proxy_info
                logger.info(
                    "[Roxy] 创建环境启用代理池：proxy=%s type=%s host=%s port=%s",
                    _mask_proxy(proxy_url),
                    proxy_info.get("protocol") or proxy_info.get("proxyCategory"),
                    proxy_info.get("host"),
                    proxy_info.get("port"),
                )
            else:
                logger.warning("[Roxy] 已启用 ROXY_CREATE_USE_PROXY_POOL，但 PROXY_POOL 为空，本次创建环境不设置代理")
        if not body.get("workspaceId"):
            raise RuntimeError(
                "Roxy 创建环境需要 workspaceId。请在 config/roxybrowser.py 或 WebUI 的 RoxyBrowser 配置中填写 ROXY_WORKSPACE_ID，"
                "或直接在 ROXY_PROFILE_CREATE_PAYLOAD 里加入 {'workspaceId': '你的工作区ID'}。"
            )
        logger.info(
            "[Roxy] 创建环境参数：workspaceId=%s projectId=%s name=%s "
            "random_name=%s os=%s osVersion=%s random_os=%s",
            body.get("workspaceId"),
            body.get("projectId") or "-",
            body.get("name") or "-",
            random_name_enabled,
            body.get("os") or "-",
            body.get("osVersion") or "-",
            random_os_enabled,
        )
        busy_attempts = max(1, int(getattr(_cfg, "ROXY_API_RETRIES", 3) or 3))
        busy_delay = max(0.5, float(getattr(_cfg, "ROXY_API_RETRY_DELAY", 2) or 2))
        while not _PROFILE_CREATE_LOCK.acquire(timeout=0.25):
            _check_registration_stop_requested()
        try:
            for attempt in range(1, busy_attempts + 1):
                _check_registration_stop_requested()
                try:
                    result = self.request(
                        _cfg.ROXY_CREATE_METHOD,
                        _cfg.ROXY_CREATE_PATH,
                        json_body=body,
                    )
                    break
                except Exception as exc:
                    retryable_response = self._is_create_retryable_response_error(exc)
                    if (
                        not self._is_create_busy_error(exc)
                        and not retryable_response
                    ) or attempt >= busy_attempts:
                        raise
                    delay = busy_delay * attempt
                    logger.warning(
                        "[Roxy] 环境创建临时失败，%.1fs 后重试 attempt=%s/%s error=%s",
                        delay,
                        attempt,
                        busy_attempts,
                        str(exc)[:180],
                    )
                    _sleep_with_stop(delay)
        finally:
            _PROFILE_CREATE_LOCK.release()
        profile_id = _first(result, [
            ("id",), ("dirId",), ("dir_id",), ("profile_id",), ("profileId",), ("browser_id",),
            ("data", "id"), ("data", "dirId"), ("data", "dir_id"),
            ("data", "profile_id"), ("data", "profileId"), ("data", "browser_id"),
        ])
        if not profile_id:
            raise RuntimeError(f"Roxy 创建环境成功但未返回 dirId/profile_id: {result}")
        return profile_id

    @staticmethod
    def _normalize_profile_id(value: str | None) -> str:
        text = str(value or "").strip()
        # WebUI/人工配置里常用 - 表示“未配置”，这里统一按空处理。
        if text in ("-", "—", "无", "空", "none", "None", "null", "NULL"):
            return ""
        return text

    def _start_traffic_bridge(self, upstream_proxy: str) -> dict | None:
        """为 SOCKS5 上游启动任务级计数桥；其他代理仍可用但不伪造流量。"""
        self.stop_traffic_bridge()
        parsed = urlparse(str(upstream_proxy or "").strip())
        if parsed.scheme.lower() not in ("socks5", "socks5h"):
            self._traffic_unavailable_reason = f"unsupported_proxy_scheme:{parsed.scheme or 'unknown'}"
            return None

        from core.local_browser_driver import _Socks5AuthBridge, _playwright_proxy

        proxy_config = _playwright_proxy(upstream_proxy)
        if not proxy_config:
            self._traffic_unavailable_reason = "invalid_proxy"
            return None
        bridge = _Socks5AuthBridge(proxy_config)
        bridge.start()
        self._traffic_bridge = bridge
        self._traffic_upstream = _mask_proxy(upstream_proxy)
        self._traffic_unavailable_reason = ""
        logger.info(
            "[Roxy][流量] 已启用 SOCKS5 计数桥：local=%s upstream=%s",
            bridge.server,
            self._traffic_upstream,
        )
        return _proxy_url_to_roxy_info(bridge.server)

    def traffic_snapshot(self) -> dict:
        bridge = self._traffic_bridge
        if bridge is None:
            return {
                "measurement": "unavailable",
                "uploaded_bytes": 0,
                "downloaded_bytes": 0,
                "total_bytes": 0,
                "connection_count": 0,
                "upstream_proxy": self._traffic_upstream,
                "unavailable_reason": self._traffic_unavailable_reason or "proxy_bridge_not_started",
            }
        snapshot = bridge.traffic_snapshot()
        return {
            "measurement": "socks5_tunnel_payload",
            **snapshot,
            "upstream_proxy": self._traffic_upstream,
            "unavailable_reason": "",
        }

    @property
    def selected_proxy_url(self) -> str:
        """返回当前 Profile 的真实上游代理；调用方不得写入普通日志。"""
        return self._selected_proxy_url

    def release_proxy_session_lease(self, *, remember: bool = True) -> None:
        leased = self._leased_proxy_url
        self._leased_proxy_url = ""
        if leased:
            _release_proxy_session(
                leased,
                self._proxy_lease_owner,
                remember=remember,
            )

    def stop_traffic_bridge(self) -> None:
        bridge = self._traffic_bridge
        self._traffic_bridge = None
        if bridge is not None:
            bridge.stop()

    def close(self, *, preserve_profile_resources: bool = False) -> None:
        """Release task-owned transports; retained Profiles keep their network resources."""
        if not preserve_profile_resources:
            self.stop_traffic_bridge()
            self.release_shared_disk_cache()
            self.release_proxy_session_lease(remember=True)
        with self._close_lock:
            if self._http_closed:
                return
            self._http_closed = True
        self.http.close()

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def _acquire_shared_disk_cache(self, *, retain_profile: bool) -> list[str]:
        enabled = bool(getattr(_cfg, "ROXY_SHARED_DISK_CACHE", True))
        keep_open = bool(retain_profile) or bool(
            getattr(_cfg, "ROXY_KEEP_BROWSER_OPEN", False)
        )
        if not enabled or keep_open:
            if enabled and keep_open:
                logger.info("[Roxy][低流量] 保留浏览器时不启用共享磁盘缓存")
            return []
        if self._disk_cache_slot is None:
            slot, cache_dir = _acquire_disk_cache_slot()
            self._disk_cache_slot = slot
            self._disk_cache_dir = cache_dir
        size_mb = max(16, int(getattr(_cfg, "ROXY_DISK_CACHE_SIZE_MB", 300) or 300))
        logger.info(
            "[Roxy][低流量] 使用共享静态缓存槽：slot=%s size=%sMB path=%s",
            self._disk_cache_slot,
            size_mb,
            self._disk_cache_dir,
        )
        return [
            f"--disk-cache-dir={self._disk_cache_dir}",
            f"--disk-cache-size={size_mb * 1024 * 1024}",
        ]

    def release_shared_disk_cache(self) -> None:
        slot = self._disk_cache_slot
        self._disk_cache_slot = None
        self._disk_cache_dir = None
        _release_disk_cache_slot(slot)

    def open_profile(
        self,
        profile_id: str | None = None,
        *,
        proxy_url: str | None = None,
        excluded_proxy_urls: set[str] | None = None,
        headless_override: bool | None = None,
        retain_profile: bool = False,
    ) -> RoxyOpenResult:
        one_profile = bool(getattr(_cfg, "ROXY_ONE_PROFILE_PER_ACCOUNT", True))
        keep_open = bool(retain_profile) or bool(
            getattr(_cfg, "ROXY_KEEP_BROWSER_OPEN", False)
        )
        configured_pid = self._normalize_profile_id(profile_id if profile_id is not None else getattr(_cfg, "ROXY_PROFILE_ID", ""))
        if one_profile and configured_pid:
            raise RuntimeError(
                "已启用 ROXY_ONE_PROFILE_PER_ACCOUNT=True（一号一环境），"
                "不能配置/传入固定 ROXY_PROFILE_ID；请留空以便每个账号创建新环境。"
            )

        pid = configured_pid
        created_by_run = False
        if not pid:
            create_payload = None
            use_proxy_pool = bool(getattr(_cfg, "ROXY_CREATE_USE_PROXY_POOL", False))
            selected_proxy = str(proxy_url or "").strip()
            explicit_proxy = bool(selected_proxy)
            selected_by_preflight = False
            preflight_enabled = bool(
                getattr(_cfg, "ROXY_PROXY_PREFLIGHT_ENABLED", True)
            )
            from config import proxy as _proxy_cfg
            if selected_proxy:
                selected_proxy = _rewrite_roxy_proxy_country(
                    _proxy_cfg.normalize_proxy_url(selected_proxy)
                )
            if not selected_proxy and use_proxy_pool:
                if preflight_enabled:
                    selected_proxy = _pick_working_proxy(
                        excluded_proxy_urls=excluded_proxy_urls,
                        lease_owner=self._proxy_lease_owner,
                    )
                    selected_by_preflight = True
                else:
                    selected_proxy = _rewrite_roxy_proxy_country(
                        _proxy_cfg.pick_proxy()
                    )
            if selected_proxy:
                if preflight_enabled and not selected_by_preflight:
                    logger.info(
                        "[Roxy] 显式代理预检：proxy=%s",
                        _mask_proxy(selected_proxy),
                    )
                try:
                    selected_proxy = _claim_proxy_candidate(
                        selected_proxy,
                        lease_owner=self._proxy_lease_owner,
                        excluded_proxy_urls=excluded_proxy_urls,
                        already_validated=selected_by_preflight,
                        check_chatgpt=preflight_enabled,
                    )
                except Exception as exc:
                    prefix = (
                        "Roxy 显式代理预检失败"
                        if explicit_proxy
                        else "Roxy 代理预检失败"
                    )
                    raise RuntimeError(f"{prefix}：{exc}") from exc
                self._leased_proxy_url = selected_proxy
                if preflight_enabled and not selected_by_preflight:
                    logger.info(
                        "[Roxy] 显式代理预检成功：%s",
                        _mask_proxy(selected_proxy),
                    )
                self._selected_proxy_url = selected_proxy
                self._traffic_upstream = _mask_proxy(selected_proxy)
                delete_after_run = bool(getattr(_cfg, "ROXY_DELETE_PROFILE_AFTER_RUN", True))
                # 任何会保留 Profile 的配置都不能依赖任务级本地桥；任务结束后桥
                # 会关闭，残留的 127.0.0.1 随机端口将让 Profile 再次打开时断网。
                if keep_open or not one_profile or not delete_after_run:
                    self._traffic_unavailable_reason = (
                        "keep_browser_open" if keep_open else "profile_retained"
                    )
                    bridge_info = None
                else:
                    bridge_info = self._start_traffic_bridge(selected_proxy)
                create_payload = {
                    "proxyInfo": bridge_info or _proxy_url_to_roxy_info(selected_proxy),
                }
            elif use_proxy_pool:
                self._traffic_unavailable_reason = "proxy_pool_empty"
            else:
                self._traffic_unavailable_reason = "system_network"
                logger.info(
                    "[Roxy] 创建环境不写入 proxyInfo，浏览器继承本机网络/TUN"
                )
            try:
                pid = self.create_profile(payload=create_payload)
                created_by_run = True
                logger.info("[Roxy] 已创建临时环境：%s", pid)
            except Exception:
                self.stop_traffic_bridge()
                self.release_proxy_session_lease(remember=True)
                raise
        else:
            self._traffic_unavailable_reason = "reused_profile_proxy_not_observable"

        path = str(_cfg.ROXY_OPEN_PATH).format(profile_id=pid)
        params = dict(getattr(_cfg, "ROXY_OPEN_EXTRA_PARAMS", {}) or {})
        # Roxy 官方 /browser/open body: {workspaceId, dirId, args, forceOpen, headless}
        params.setdefault("workspaceId", _workspace_id_value())
        params.setdefault("dirId", int(pid) if str(pid).isdigit() else pid)
        low_traffic = bool(getattr(_cfg, "ROXY_LOW_TRAFFIC_MODE", True))
        params["args"] = _merge_chrome_args(
            params.get("args"),
            _LOW_TRAFFIC_CHROME_ARGS if low_traffic else (),
        )
        params.setdefault("forceOpen", True)
        # ROXY_OPEN_HEADLESS 是显式开关，优先级应高于 ROXY_OPEN_EXTRA_PARAMS，
        # 否则 extra 里残留 headless=False 会导致 WebUI 保存无头后仍弹窗口。
        params["headless"] = (
            bool(headless_override)
            if headless_override is not None
            else bool(getattr(_cfg, "ROXY_OPEN_HEADLESS", False))
        )
        window_offscreen = bool(
            getattr(_cfg, "ROXY_WINDOW_OFFSCREEN", False)
        ) and not bool(params["headless"])
        if window_offscreen:
            offscreen_x = max(
                10000,
                int(getattr(_cfg, "ROXY_WINDOW_OFFSCREEN_X", 30000) or 30000),
            )
            params["args"] = _merge_chrome_args(
                params["args"], (
                    f"--window-position={offscreen_x},0",
                    "--window-size=1280,900",
                    "--disable-background-timer-throttling",
                    "--disable-backgrounding-occluded-windows",
                    "--disable-renderer-backgrounding",
                )
            )
        logger.info(
            "[Roxy] open 参数：profile=%s headless=%s offscreen=%s keep_open=%s",
            pid,
            params.get("headless"),
            window_offscreen,
            bool(retain_profile) or bool(getattr(_cfg, "ROXY_KEEP_BROWSER_OPEN", False)),
        )
        result: dict = {}
        browser_pid: int | None = None
        process_identity: _RoxyProcessIdentity | None = None
        try:
            if low_traffic:
                cache_args = self._acquire_shared_disk_cache(
                    retain_profile=retain_profile
                )
                params["args"] = _replace_chrome_args(
                    params["args"], cache_args
                )
            result = self.request(
                _cfg.ROXY_OPEN_METHOD,
                path,
                params=params if _cfg.ROXY_OPEN_METHOD.upper() == "GET" else None,
                json_body=params if _cfg.ROXY_OPEN_METHOD.upper() != "GET" else None,
            )
            browser_pid = self._extract_browser_pid(result)
            process_identity = _capture_roxy_process_identity(browser_pid, pid)
            if browser_pid and process_identity is None:
                logger.warning(
                    "[Roxy] 无法确认 open 返回 PID 的 Profile 身份，结束时仅调用 API，"
                    "不会执行本机进程兜底：profile=%s pid=%s",
                    pid,
                    browser_pid,
                )
            debugger_address = self._extract_debugger_address(result)
            logger.info("[Roxy] open 返回摘要: debugger=%s raw=%s", debugger_address, json.dumps(result, ensure_ascii=False)[:800])
            webdriver_url = _first(result, [
                ("webdriver",), ("webDriver",), ("webdriver_url",), ("webdriverUrl",),
                ("selenium",), ("selenium_url",), ("seleniumUrl",),
                ("data", "webdriver"), ("data", "webDriver"), ("data", "webdriver_url"), ("data", "webdriverUrl"),
                ("data", "selenium"), ("data", "selenium_url"), ("data", "seleniumUrl"),
            ]) or None
            ws_endpoint = _first(result, [
                ("ws",), ("wsEndpoint",), ("ws_endpoint",), ("debuggerWsUrl",),
                ("data", "ws"), ("data", "wsEndpoint"), ("data", "ws_endpoint"), ("data", "debuggerWsUrl"),
            ]) or None
            if not debugger_address and not webdriver_url:
                raise RuntimeError(f"Roxy 已打开环境但未返回 Selenium/调试地址，请检查 ROXY_OPEN_PATH 或接口响应: {result}")
        except Exception:
            # create 已成功但 open/响应解析失败时，调用方拿不到 RoxyOpenResult，
            # 后续 finally 无法清理。本轮临时 Profile 不能留成指向已停止本地桥的孤儿环境。
            if created_by_run and pid:
                self.cleanup_profile(RoxyOpenResult(
                    profile_id=pid,
                    raw=result,
                    created_by_run=True,
                    keep_open=keep_open,
                    browser_pid=browser_pid,
                    process_identity=process_identity,
                ))
            else:
                self.stop_traffic_bridge()
                self.release_shared_disk_cache()
                self.release_proxy_session_lease(remember=True)
            raise
        return RoxyOpenResult(
            pid,
            result,
            debugger_address=debugger_address,
            webdriver_url=webdriver_url,
            ws_endpoint=ws_endpoint,
            created_by_run=created_by_run,
            keep_open=keep_open,
            browser_pid=browser_pid,
            process_identity=process_identity,
        )

    def close_profile(self, profile_id: str) -> None:
        if not profile_id:
            return
        path = str(_cfg.ROXY_CLOSE_PATH).format(profile_id=profile_id)
        try:
            body = {
                "workspaceId": _workspace_id_value(),
                "dirId": int(profile_id) if str(profile_id).isdigit() else profile_id,
            }
            self.request(
                _cfg.ROXY_CLOSE_METHOD,
                path,
                params=body if str(_cfg.ROXY_CLOSE_METHOD).upper() == "GET" else None,
                json_body=body if str(_cfg.ROXY_CLOSE_METHOD).upper() != "GET" else None,
                respect_stop=False,
            )
            logger.info("[Roxy] 已关闭环境：%s", profile_id)
        except Exception as exc:
            logger.warning("[Roxy] 关闭环境失败：%s", exc)

    def delete_profile(self, profile_id: str) -> None:
        if not profile_id:
            return
        path = str(getattr(_cfg, "ROXY_DELETE_PATH", "/browser/delete")).format(profile_id=profile_id)
        method = str(getattr(_cfg, "ROXY_DELETE_METHOD", "POST") or "POST")
        try:
            body = {
                "workspaceId": _workspace_id_value(),
                "dirIds": [int(profile_id) if str(profile_id).isdigit() else profile_id],
            }
            self.request(
                method,
                path,
                params=body if method.upper() == "GET" else None,
                json_body=body if method.upper() != "GET" else None,
                respect_stop=False,
            )
            logger.info("[Roxy] 已删除环境：%s", profile_id)
        except Exception as exc:
            logger.warning("[Roxy] 删除环境失败：%s", exc)

    def cleanup_profile(self, opened: RoxyOpenResult | None) -> None:
        """任务结束清理：关闭窗口；一号一环境时删除本轮创建的 Profile。"""
        if not opened or not opened.profile_id:
            self.stop_traffic_bridge()
            self.release_shared_disk_cache()
            self.release_proxy_session_lease(remember=True)
            return
        keep_open = bool(opened.keep_open) or bool(
            getattr(_cfg, "ROXY_KEEP_BROWSER_OPEN", False)
        )
        try:
            if keep_open:
                logger.info(
                    "[Roxy] keep_open=True，保留环境：%s",
                    opened.profile_id,
                )
                return

            self.close_profile(opened.profile_id)
            if bool(opened.created_by_run):
                self._ensure_owned_browser_exited(opened)

            should_delete = (
                bool(getattr(_cfg, "ROXY_ONE_PROFILE_PER_ACCOUNT", True))
                and bool(getattr(_cfg, "ROXY_DELETE_PROFILE_AFTER_RUN", True))
                and bool(opened.created_by_run)
            )
            if should_delete:
                self.delete_profile(opened.profile_id)
        finally:
            self.stop_traffic_bridge()
            self.release_shared_disk_cache()
            self.release_proxy_session_lease(remember=True)

    @staticmethod
    def _ensure_owned_browser_exited(opened: RoxyOpenResult) -> bool:
        identity = opened.process_identity
        if identity is None:
            if opened.browser_pid:
                logger.warning(
                    "[Roxy] 未保存可信进程身份，跳过本机终止：profile=%s pid=%s",
                    opened.profile_id,
                    opened.browser_pid,
                )
            return False
        if (
            identity.profile_id != str(opened.profile_id)
            or opened.browser_pid != identity.pid
        ):
            logger.error(
                "[Roxy] 进程身份与 open 结果不一致，拒绝本机终止："
                "profile=%s pid=%s identity_profile=%s identity_pid=%s",
                opened.profile_id,
                opened.browser_pid,
                identity.profile_id,
                identity.pid,
            )
            return False

        state = _wait_for_roxy_process_exit(
            identity,
            _ROXY_PROCESS_CLOSE_GRACE_SECONDS,
        )
        if state in {"exited", "changed"}:
            return True
        if state != "same":
            logger.warning(
                "[Roxy] close 后无法复核进程状态，基于安全策略不终止："
                "profile=%s pid=%s state=%s",
                opened.profile_id,
                identity.pid,
                state,
            )
            return False

        logger.warning(
            "[Roxy] close 后浏览器进程仍存活，执行本轮 Profile 的 PID 兜底终止："
            "profile=%s pid=%s",
            opened.profile_id,
            identity.pid,
        )
        terminated = _terminate_owned_roxy_process(identity)
        if not terminated:
            logger.error(
                "[Roxy] 本轮 Profile 进程兜底终止失败：profile=%s pid=%s",
                opened.profile_id,
                identity.pid,
            )
        return terminated

    @staticmethod
    def _extract_browser_pid(payload: dict) -> int | None:
        value = _first(payload, [
            ("pid",), ("browserPid",), ("browser_pid",),
            ("data", "pid"), ("data", "browserPid"), ("data", "browser_pid"),
        ])
        try:
            pid = int(str(value).strip())
        except (TypeError, ValueError):
            return None
        return pid if pid > 1 else None

    @staticmethod
    def _extract_debugger_address(payload: dict) -> str | None:
        value = _first(payload, [
            ("debuggerAddress",), ("debugger_address",), ("debugAddress",),
            ("debuggingPortUrl",), ("debugging_port_url",),
            ("remoteDebuggingAddress",), ("remote_debugging_address",),
            ("http",), ("debugHttp",), ("debug_http",),
            ("data", "debuggerAddress"), ("data", "debugger_address"), ("data", "debugAddress"),
            ("data", "debuggingPortUrl"), ("data", "debugging_port_url"),
            ("data", "remoteDebuggingAddress"), ("data", "remote_debugging_address"),
            ("data", "http"), ("data", "debugHttp"), ("data", "debug_http"),
        ])
        if value:
            value = value.strip()
            # 兼容 http://127.0.0.1:xxxx / 127.0.0.1:xxxx / :xxxx / 9222
            value = value.replace("http://", "").replace("https://", "").strip("/")
            if value.startswith(":") and value[1:].isdigit():
                return f"127.0.0.1{value}"
            if value.isdigit():
                return f"127.0.0.1:{value}"
            if ":" in value and not value.startswith(":"):
                return value
        port = _first(payload, [
            ("debuggingPort",), ("debugging_port",), ("debug_port",), ("port",),
            ("data", "debuggingPort"), ("data", "debugging_port"), ("data", "debug_port"), ("data", "port"),
        ])
        if port:
            port = str(port).strip()
            if port.startswith(":"):
                port = port[1:]
            if port.isdigit():
                return f"127.0.0.1:{port}"
        return None
