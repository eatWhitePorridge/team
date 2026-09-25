# -*- coding: utf-8 -*-
"""本机 Playwright Chromium 的 Selenium 风格适配入口。"""
from __future__ import annotations

import logging
import select
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

from config import local_browser as _cfg
from core.cloakbrowser_driver import CloakSeleniumDriver


logger = logging.getLogger(__name__)


_SOCKS5_RELAY_POLL_SECONDS = 1.0
_SOCKS5_RELAY_SEND_TIMEOUT_SECONDS = 15.0
_SOCKS5_RELAY_IDLE_TIMEOUT_SECONDS = 300.0


_UPSTREAM_LOCALE_BY_COUNTRY = {
    "US": ("en-US", "en-US,en;q=0.9"),
    "GB": ("en-GB", "en-GB,en;q=0.9"),
    "UK": ("en-GB", "en-GB,en;q=0.9"),
    "CA": ("en-CA", "en-CA,en;q=0.9,fr-CA;q=0.8"),
    "AU": ("en-AU", "en-AU,en;q=0.9"),
    "DE": ("de-DE", "de-DE,de;q=0.9,en;q=0.8"),
    "FR": ("fr-FR", "fr-FR,fr;q=0.9,en;q=0.8"),
    "ES": ("es-ES", "es-ES,es;q=0.9,en;q=0.8"),
    "IT": ("it-IT", "it-IT,it;q=0.9,en;q=0.8"),
    "NL": ("nl-NL", "nl-NL,nl;q=0.9,en;q=0.8"),
    "JP": ("ja-JP", "ja-JP,ja;q=0.9,en;q=0.8"),
    "KR": ("ko-KR", "ko-KR,ko;q=0.9,en;q=0.8"),
    "BR": ("pt-BR", "pt-BR,pt;q=0.9,en;q=0.8"),
    "RU": ("ru-RU", "ru-RU,ru;q=0.9,en;q=0.8"),
    "IN": ("en-IN", "en-IN,en;q=0.9,hi;q=0.8"),
    "SG": ("en-SG", "en-SG,en;q=0.9"),
}


@dataclass
class LocalBrowserOpenResult:
    profile_id: str = "local-browser"
    raw: dict | None = None


class LocalBrowserDriver(CloakSeleniumDriver):
    """复用现有页面状态机所需的 WebDriver 子集，并管理 Playwright 生命周期。"""

    def __init__(self, playwright, browser, context, page, proxy_bridge=None):
        super().__init__(browser=browser, context=context, page=page)
        self._playwright = playwright
        self._proxy_bridge = proxy_bridge

    def quit(self) -> None:
        try:
            super().quit()
        finally:
            try:
                self._playwright.stop()
            except Exception:
                pass
            if self._proxy_bridge is not None:
                self._proxy_bridge.stop()


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("SOCKS5 connection closed unexpectedly")
        chunks.extend(chunk)
    return bytes(chunks)


def _recv_socks_address(sock: socket.socket, atyp: int) -> bytes:
    if atyp == 0x01:
        return _recv_exact(sock, 4)
    if atyp == 0x04:
        return _recv_exact(sock, 16)
    if atyp == 0x03:
        length = _recv_exact(sock, 1)
        return length + _recv_exact(sock, length[0])
    raise ValueError(f"unsupported SOCKS5 address type: {atyp}")


class _Socks5AuthBridge:
    """把 Chromium 的无认证 SOCKS5 连接桥接到带账号密码的上游 SOCKS5。"""

    def __init__(self, upstream: dict):
        parsed = urlparse(str(upstream.get("server") or ""))
        if parsed.scheme.lower() != "socks5" or not parsed.hostname or not parsed.port:
            raise ValueError("SOCKS5 认证桥上游地址无效")
        self._host = parsed.hostname
        self._port = parsed.port
        self._username = str(upstream.get("username") or "")
        self._password = str(upstream.get("password") or "")
        if len(self._username.encode()) > 255 or len(self._password.encode()) > 255:
            raise ValueError("SOCKS5 用户名或密码超过 255 字节")
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._worker_threads: set[threading.Thread] = set()
        self._uploaded_bytes = 0
        self._downloaded_bytes = 0
        self._tunnel_count = 0
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(64)
        self._listener.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, name="local-socks5-auth-bridge", daemon=True)

    @property
    def server(self) -> str:
        return f"socks5://127.0.0.1:{self._listener.getsockname()[1]}"

    def start(self) -> None:
        self._thread.start()

    def traffic_snapshot(self) -> dict:
        """返回已成功转发的 SOCKS 隧道载荷，不含握手和 TCP/IP 包头。"""
        with self._lock:
            uploaded = int(self._uploaded_bytes)
            downloaded = int(self._downloaded_bytes)
            tunnels = int(self._tunnel_count)
        return {
            "uploaded_bytes": uploaded,
            "downloaded_bytes": downloaded,
            "total_bytes": uploaded + downloaded,
            "connection_count": tunnels,
        }

    def stop(self) -> None:
        self._stop.set()
        deadline = time.monotonic() + 2.0
        try:
            self._listener.close()
        except OSError:
            pass

        # Close tunnels before joining their workers. A worker blocked in
        # sendall/recv cannot otherwise observe the stop event promptly.
        self._close_tracked_connections()
        if self._thread.is_alive() and threading.current_thread() is not self._thread:
            self._thread.join(timeout=max(0.0, deadline - time.monotonic()))

        # accept() can win the race with listener.close() and register one last
        # client after the first snapshot, so collect active sockets again.
        self._close_tracked_connections()
        with self._lock:
            workers = list(self._worker_threads)
        current = threading.current_thread()
        for worker in workers:
            if worker.is_alive() and worker is not current:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                worker.join(timeout=remaining)
        self._close_tracked_connections()

    def _close_tracked_connections(self) -> None:
        with self._lock:
            connections = tuple(self._connections)
        for conn in connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

    def _track(self, *sockets: socket.socket) -> None:
        close_now = False
        with self._lock:
            if self._stop.is_set():
                close_now = True
            else:
                self._connections.update(sockets)
        if close_now:
            for item in sockets:
                try:
                    item.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    item.close()
                except OSError:
                    pass

    def _untrack(self, *sockets: socket.socket) -> None:
        with self._lock:
            for item in sockets:
                self._connections.discard(item)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._track(client)
            worker = threading.Thread(
                target=self._handle_client,
                args=(client,),
                name="local-socks5-auth-connection",
                daemon=True,
            )
            with self._lock:
                self._worker_threads.add(worker)
            worker.start()

    def _handle_client(self, client: socket.socket) -> None:
        upstream = None
        try:
            client.settimeout(20)
            version, method_count = _recv_exact(client, 2)
            methods = _recv_exact(client, method_count)
            if version != 0x05 or 0x00 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x00")

            request_head = _recv_exact(client, 4)
            if request_head[0] != 0x05 or request_head[1] != 0x01:
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            address = _recv_socks_address(client, request_head[3])
            port = _recv_exact(client, 2)
            request = request_head + address + port

            upstream = socket.create_connection((self._host, self._port), timeout=20)
            self._track(upstream)
            # 有凭证时只能声明 USERNAME/PASSWORD。部分住宅代理在同时收到
            # NO_AUTH 和 USERNAME/PASSWORD 时会优先选 NO_AUTH，随后用 reply=1
            # 拒绝 CONNECT，Chromium 侧只会看到 ERR_SOCKS_CONNECTION_FAILED。
            if self._username or self._password:
                upstream.sendall(b"\x05\x01\x02")
            else:
                upstream.sendall(b"\x05\x01\x00")
            upstream_version, method = _recv_exact(upstream, 2)
            if upstream_version != 0x05 or method == 0xFF:
                raise ConnectionError("上游 SOCKS5 不接受可用认证方式")
            if method == 0x02:
                username = self._username.encode()
                password = self._password.encode()
                upstream.sendall(
                    b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password
                )
                auth_version, auth_status = _recv_exact(upstream, 2)
                if auth_version != 0x01 or auth_status != 0x00:
                    raise ConnectionError("上游 SOCKS5 用户名或密码认证失败")
            elif method != 0x00:
                raise ConnectionError(f"上游 SOCKS5 返回不支持的认证方式: {method}")

            upstream.sendall(request)
            response_head = _recv_exact(upstream, 4)
            response_address = _recv_socks_address(upstream, response_head[3])
            response_port = _recv_exact(upstream, 2)
            client.sendall(response_head + response_address + response_port)
            if response_head[1] != 0x00:
                logger.warning(
                    "[本机浏览器] 上游 SOCKS5 拒绝 CONNECT：reply=%s target_type=%s",
                    response_head[1],
                    request_head[3],
                )
                return

            with self._lock:
                self._tunnel_count += 1
            client.settimeout(None)
            upstream.settimeout(None)
            self._relay(client, upstream)
        except Exception as exc:
            logger.debug("[本机浏览器] SOCKS5 认证桥连接失败: %s: %s", type(exc).__name__, exc)
            try:
                client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
        finally:
            sockets = [client] + ([upstream] if upstream is not None else [])
            self._untrack(*sockets)
            for item in sockets:
                try:
                    item.close()
                except OSError:
                    pass
            with self._lock:
                self._worker_threads.discard(threading.current_thread())

    def _relay(self, client: socket.socket, upstream: socket.socket) -> None:
        sockets = [client, upstream]
        for item in sockets:
            try:
                item.settimeout(_SOCKS5_RELAY_SEND_TIMEOUT_SECONDS)
            except OSError:
                return
        idle_deadline = time.monotonic() + _SOCKS5_RELAY_IDLE_TIMEOUT_SECONDS
        while not self._stop.is_set():
            remaining = idle_deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                readable, _, exceptional = select.select(
                    sockets,
                    [],
                    sockets,
                    min(_SOCKS5_RELAY_POLL_SECONDS, remaining),
                )
            except (OSError, ValueError):
                return
            if exceptional:
                return
            for source in readable:
                try:
                    data = source.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                idle_deadline = time.monotonic() + _SOCKS5_RELAY_IDLE_TIMEOUT_SECONDS
                target = upstream if source is client else client
                try:
                    target.sendall(data)
                except OSError:
                    return
                with self._lock:
                    if source is client:
                        self._uploaded_bytes += len(data)
                    else:
                        self._downloaded_bytes += len(data)


def _normalize_proxy(raw: str | None) -> str:
    from config.proxy import normalize_proxy_url

    value = normalize_proxy_url(raw)
    if not value:
        return ""
    if value.lower().startswith("socks5h://"):
        value = "socks5://" + value[len("socks5h://") :]
    return value


def _playwright_proxy(raw: str | None) -> dict | None:
    """把认证代理 URL 拆成 Playwright 的 server/username/password 结构。"""
    normalized = _normalize_proxy(raw)
    if not normalized:
        return None
    parsed = urlparse(normalized)
    if not parsed.hostname:
        raise ValueError("代理地址缺少 host")
    scheme = (parsed.scheme or "http").lower()
    if scheme not in {"http", "https", "socks5"}:
        raise ValueError(f"本机 Chromium 不支持代理类型: {scheme}")
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    server = f"{scheme}://{host}"
    if parsed.port:
        server += f":{parsed.port}"
    out = {"server": server}
    if parsed.username is not None:
        out["username"] = unquote(parsed.username)
    if parsed.password is not None:
        out["password"] = unquote(parsed.password)
    return out


def _proxy_label(proxy: dict | None) -> str:
    if not proxy:
        return "无"
    return str(proxy.get("server") or "-") + ("（已认证）" if proxy.get("username") else "")


def _align_locale_with_upstream(profile: dict, geo: dict) -> dict:
    """复刻上游 localeForCountry；未知出口必须回退 en-US，而不是固定日语。"""
    result = dict(profile or {})
    country = str((geo or {}).get("country") or "").strip().upper()
    locale, accept_language = _UPSTREAM_LOCALE_BY_COUNTRY.get(
        country,
        ("en-US", "en-US,en;q=0.9"),
    )
    result["navigator_language"] = locale
    result["navigator_languages"] = [locale, locale.split("-", 1)[0]]
    result["accept_language"] = accept_language
    timezone = str((geo or {}).get("timezone") or "").strip()
    if timezone:
        result["timezone_iana"] = timezone
    return result


def _detect_exit_profile(proxy_url: str) -> tuple[dict, dict]:
    """通过当前出口探测地区，并生成与出口一致的语言/时区画像。"""
    try:
        from config import browser as browser_cfg
    except Exception:
        browser_cfg = None

    def fallback_profile() -> dict:
        if browser_cfg is None:
            return _align_locale_with_upstream({}, {})
        try:
            return _align_locale_with_upstream(browser_cfg.build_browser_environment({}), {})
        except Exception:
            return _align_locale_with_upstream({}, {})

    if not bool(getattr(_cfg, "LOCAL_BROWSER_GEOIP", True)):
        return {}, fallback_profile()
    try:
        from curl_cffi import requests as curl_requests

        endpoints = list(getattr(browser_cfg, "IP_GEO_ENDPOINTS", []) or [])
        timeout = float(getattr(browser_cfg, "IP_GEO_TIMEOUT", 6) or 6)
        proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
        for endpoint in endpoints:
            try:
                response = curl_requests.get(
                    endpoint,
                    headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
                    proxies=proxies,
                    timeout=timeout,
                    impersonate="chrome",
                )
                if response.status_code != 200:
                    continue
                data = response.json()
                timezone = data.get("timezone")
                if isinstance(timezone, dict):
                    timezone = timezone.get("id") or timezone.get("name")
                geo = {
                    "ip": data.get("ip") or data.get("query"),
                    "country": str(data.get("country_code") or data.get("countryCode") or data.get("country") or "").upper(),
                    "region": data.get("region") or data.get("regionName"),
                    "city": data.get("city"),
                    "timezone": timezone or "",
                    "org": data.get("org") or data.get("isp") or (data.get("connection") or {}).get("org"),
                }
                if geo.get("country") or geo.get("timezone"):
                    profile = _align_locale_with_upstream(
                        browser_cfg.build_browser_environment(geo),
                        geo,
                    )
                    logger.info(
                        "[本机浏览器] 出口IP地理信息：ip=%s country=%s city=%s timezone=%s",
                        geo.get("ip") or "?",
                        geo.get("country") or "?",
                        geo.get("city") or "?",
                        geo.get("timezone") or "?",
                    )
                    return geo, profile
            except Exception as exc:
                logger.debug(
                    "[本机浏览器] 出口 IP 探测失败 endpoint=%s: %s: %s",
                    endpoint,
                    type(exc).__name__,
                    exc,
                )
    except Exception as exc:
        logger.debug("[本机浏览器] 构建地区画像失败: %s: %s", type(exc).__name__, exc)
    return {}, fallback_profile()


def _launch_chromium(playwright, launch_kwargs: dict, installer_module: str = "patchright"):
    try:
        return playwright.chromium.launch(**launch_kwargs)
    except Exception as first_exc:
        message = str(first_exc)
        missing = "Executable doesn't exist" in message or "playwright install" in message.lower()
        if not missing or not bool(getattr(_cfg, "LOCAL_BROWSER_AUTO_INSTALL", True)):
            raise
        logger.warning("[本机浏览器] 缺少 Patchright Chromium，开始自动下载")
        completed = subprocess.run(
            [sys.executable, "-m", installer_module, "install", "chromium"],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()[-800:]
            raise RuntimeError(f"Patchright Chromium 自动下载失败: {detail}") from first_exc
        retry_kwargs = dict(launch_kwargs)
        retry_kwargs.pop("channel", None)
        retry_kwargs.pop("executable_path", None)
        return playwright.chromium.launch(**retry_kwargs)


def _start_patched_playwright():
    """启动带 CDP 隐身补丁的 Playwright 兼容后端。"""
    try:
        from patchright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "未安装 patchright，请执行 pip install -r requirements.txt 后重试"
        ) from exc
    return sync_playwright().start()


def _apply_stealth_evasions(context, profile: dict) -> None:
    """移植上游 Rod stealth 的浏览器侧 evasions，并保持画像字段一致。"""
    if not bool(getattr(_cfg, "LOCAL_BROWSER_STEALTH", True)):
        return
    try:
        from playwright_stealth import Stealth
    except ImportError as exc:
        raise RuntimeError(
            "未安装 playwright-stealth，请执行 pip install -r requirements.txt 后重试"
        ) from exc

    languages = tuple(profile.get("navigator_languages") or ())
    if not languages:
        locale = str(profile.get("navigator_language") or "en-US")
        languages = (locale, locale.split("-", 1)[0])
    stealth = Stealth(
        navigator_languages_override=languages,
        navigator_platform_override=str(profile.get("navigator_platform") or "MacIntel"),
        navigator_user_agent_override=str(profile.get("user_agent") or "") or None,
        navigator_vendor_override=str(profile.get("navigator_vendor") or "Google Inc."),
        sec_ch_ua_override=str(profile.get("sec_ch_ua") or "") or None,
    )
    stealth.apply_stealth_sync(context)


def _chromium_launch_args(*, proxy_bridge: bool) -> list[str]:
    args = [
        "--disable-blink-features=AutomationControlled",
        "--disable-infobars",
        "--no-first-run",
        "--no-default-browser-check",
        "--window-size=1280,800",
    ]
    if proxy_bridge:
        # Chromium 默认可能先在本机解析域名，再把 IPv4/IPv6 交给 SOCKS。
        # ipwo 等住宅代理要求域名型 CONNECT；强制解析失败后 Chromium 会把
        # 原始域名交给 SOCKS5，同时排除本机认证桥地址。
        args.append(
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1"
        )
    return args


def build_local_browser_driver(proxy: str | None = None) -> tuple[LocalBrowserDriver, LocalBrowserOpenResult]:
    """启动每账号独立的本机 Chromium；不创建或复用 Roxy Profile。"""
    if proxy is None and bool(getattr(_cfg, "LOCAL_BROWSER_USE_PROXY", True)):
        try:
            from config.proxy import pick_proxy

            proxy = pick_proxy()
        except Exception:
            proxy = None
    if not bool(getattr(_cfg, "LOCAL_BROWSER_USE_PROXY", True)):
        proxy = ""

    normalized_proxy = _normalize_proxy(proxy)
    playwright_proxy = _playwright_proxy(normalized_proxy)
    geo, profile = _detect_exit_profile(normalized_proxy)

    proxy_bridge = None
    launch_proxy = playwright_proxy
    if playwright_proxy and str(playwright_proxy.get("server") or "").startswith("socks5://") and (
        playwright_proxy.get("username") is not None or playwright_proxy.get("password") is not None
    ):
        proxy_bridge = _Socks5AuthBridge(playwright_proxy)
        proxy_bridge.start()
        launch_proxy = {"server": proxy_bridge.server}
        logger.info(
            "[本机浏览器] 已启用 SOCKS5 认证桥：local=%s upstream=%s",
            proxy_bridge.server,
            playwright_proxy.get("server"),
        )

    playwright = _start_patched_playwright()
    browser = None
    try:
        launch_kwargs = {
            "headless": bool(getattr(_cfg, "LOCAL_BROWSER_HEADLESS", True)),
            "args": _chromium_launch_args(proxy_bridge=proxy_bridge is not None),
        }
        channel = str(getattr(_cfg, "LOCAL_BROWSER_CHANNEL", "") or "").strip()
        executable = str(getattr(_cfg, "LOCAL_BROWSER_EXECUTABLE_PATH", "") or "").strip()
        if executable:
            launch_kwargs["executable_path"] = executable
        elif channel:
            launch_kwargs["channel"] = channel
        if launch_proxy:
            launch_kwargs["proxy"] = launch_proxy

        logger.info(
            "[本机浏览器] 启动 Patchright Chromium：headless=%s proxy=%s locale=%s timezone=%s stealth=%s",
            launch_kwargs["headless"],
            _proxy_label(playwright_proxy) + ("（本地认证桥）" if proxy_bridge else ""),
            profile.get("navigator_language") or "默认",
            profile.get("timezone_iana") or geo.get("timezone") or "默认",
            bool(getattr(_cfg, "LOCAL_BROWSER_STEALTH", True)),
        )
        browser = _launch_chromium(playwright, launch_kwargs, installer_module="patchright")

        context_kwargs = {
            "viewport": {"width": 1280, "height": 800},
        }
        locale = str(profile.get("navigator_language") or "").strip()
        timezone = str(profile.get("timezone_iana") or geo.get("timezone") or "").strip()
        accept_language = str(profile.get("accept_language") or "").strip()
        if locale:
            context_kwargs["locale"] = locale
        if timezone:
            context_kwargs["timezone_id"] = timezone
        if accept_language:
            context_kwargs["extra_http_headers"] = {"Accept-Language": accept_language}
        user_agent = str(profile.get("user_agent") or "").strip()
        if user_agent:
            context_kwargs["user_agent"] = user_agent

        context = browser.new_context(**context_kwargs)
        _apply_stealth_evasions(context, profile)
        page = context.new_page()
        driver = LocalBrowserDriver(
            playwright=playwright,
            browser=browser,
            context=context,
            page=page,
            proxy_bridge=proxy_bridge,
        )
        driver._registration_log_prefix = "[本机浏览器注册]"
        driver.set_page_load_timeout(int(getattr(_cfg, "LOCAL_BROWSER_TIMEOUT", 90) or 90))
        return driver, LocalBrowserOpenResult(
            raw={
                "driver": "local_browser",
                "engine": "patchright",
                "stealth": bool(getattr(_cfg, "LOCAL_BROWSER_STEALTH", True)),
                "headless": launch_kwargs["headless"],
                "proxy": normalized_proxy or None,
                "geo": geo,
                "locale": locale or None,
                "timezone": timezone or None,
            }
        )
    except Exception:
        try:
            if browser is not None:
                browser.close()
        finally:
            try:
                playwright.stop()
            finally:
                if proxy_bridge is not None:
                    proxy_bridge.stop()
        raise
