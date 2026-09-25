# -*- coding: utf-8 -*-
"""
curl_cffi Session 封装
统一管理 Cookie、请求头和 TLS 指纹
"""
import logging
import secrets
import threading
import uuid
from urllib.parse import urlparse
from curl_cffi.requests import Session
from config import browser as _browser_cfg

from config import (
    USER_AGENT, SEC_CH_UA, SEC_CH_UA_PLATFORM, SEC_CH_UA_MOBILE,
    SEC_CH_UA_FULL_VERSION_LIST, SEC_CH_UA_PLATFORM_VERSION, SEC_CH_UA_ARCH,
    SEC_CH_UA_BITNESS, SEC_CH_UA_MODEL, SEND_HIGH_ENTROPY_CLIENT_HINTS,
    ACCEPT_LANGUAGE, IMPERSONATE, OAI_CLIENT_BUILD_NUMBER, OAI_CLIENT_VERSION,
    REQUEST_TIMEOUT, pick_proxy, pick_browser_profile, validate_browser_profile,
)


logger = logging.getLogger(__name__)
_GEO_CACHE: dict[str, dict] = {}
_GEO_CACHE_LOCK = threading.Lock()
_CF_COOKIE_NAMES = ("cf_clearance", "__cf_bm", "__cfseq", "cf_chl_rc_i", "cf_chl_rc_ni", "cf_chl_rc_m")


class BrowserSession:
    """
    模拟 Chrome 浏览器的 HTTP 会话管理器。
    使用 curl_cffi 的 impersonate 功能绕过 Cloudflare TLS 指纹检测。
    """

    def __init__(
        self,
        proxy: str = None,
        *,
        detect_exit_geo: bool = True,
        device_id: str | None = None,
        browser_family: str | None = None,
    ):
        """
        初始化会话。

        Args:
            proxy: 代理地址，如 "socks5h://user:pass@host:port"。
                   不传则从 config.PROXY_POOL 随机抽一个。
                   显式传 "" 表示禁用代理。
            detect_exit_geo: 是否探测出口 IP 并自动选择语言/时区画像。
                             套餐查询等短请求可关闭，避免额外网络等待。
            device_id: 可选的既有 oai-did。注册后复查可用它保持设备上下文。
            browser_family: 可选的网络/JS 浏览器画像，目前支持 chrome、firefox。
        """
        # proxy=None  → 从池里随机抽（默认行为）
        # proxy=""    → 禁用代理（直连）
        # proxy="..." → 使用指定代理
        if proxy is None:
            self.proxy = pick_proxy()
        else:
            self.proxy = proxy

        self.browser_family = str(browser_family or _browser_cfg.BROWSER_FAMILY).strip().lower()
        if self.browser_family not in {"chrome", "firefox"}:
            raise ValueError(f"不支持的浏览器画像: {self.browser_family!r}")
        self.impersonate = (
            _browser_cfg.FIREFOX_IMPERSONATE
            if self.browser_family == "firefox"
            else _browser_cfg.IMPERSONATE
        )

        # 默认生成设备 ID；注册后复查可显式复用浏览器 Cookie 中的 oai-did。
        supplied_device_id = str(device_id or "").strip()
        if supplied_device_id and (
            len(supplied_device_id) > 256
            or "\r" in supplied_device_id
            or "\n" in supplied_device_id
        ):
            raise ValueError("device_id 格式无效")
        self.device_id = supplied_device_id or str(uuid.uuid4())

        # 生成 auth_session_logging_id
        self.auth_session_logging_id = str(uuid.uuid4())

        # Auth Web 在同一次文档生命周期内复用该 ID；每个 JSON 请求自己的
        # x-access-flow-invocation-id / trace 仍按请求重新生成。
        self.document_navigation_id = str(uuid.uuid4())

        # Login Web (auth.openai.com) has its own Segment identity. It remains
        # stable through email verification/about-you and is separate from the
        # ChatGPT page analytics identity.
        self.oaicom_stable_id = str(uuid.uuid4())
        self.login_web_anonymous_id = str(uuid.uuid4())

        # ChatGPT 前端会话 ID：CES / Statsig / API 链路内保持稳定。
        self.oai_session_id = str(uuid.uuid4())

        # Bazaar OBI 是 ChatGPT 首页生成的匿名标识。HAR 中匿名态和登录态会用
        # 同一个值分别换取一次短期 sync token，因此必须在整个注册会话内稳定。
        self.obi_id = secrets.token_urlsafe(16)

        # Auth JSON 的 trace 是请求级上下文。设备、OAI session 和匿名身份才是会话级。
        self.datadog_origin = "rum"
        self.anonymous_id = str(uuid.uuid4())

        # Sentinel SDK 内部 sid：真实 SDK 会单独生成一个 UUID，和 oai-did 不是同一个值。
        # Python 初始 p 与 Node Runner 最终 token 都复用这个 sid，保持同一 SDK 实例语义。
        self.sentinel_sid = str(uuid.uuid4())
        # ChatGPT 首页和 Auth Web 是两个独立 SDK 实例，各自持有内部 sid。
        self.chatgpt_sentinel_sid = str(uuid.uuid4())
        self.react_listening_key = "_reactListening" + uuid.uuid4().hex[:12]
        self.react_container_key = "__reactContainer$" + uuid.uuid4().hex[:11]
        self.react_resources_key = "__reactResources$" + self.react_container_key.split("$", 1)[1]

        # 创建 curl_cffi 会话
        self.session = Session(impersonate=self.impersonate)

        # 设置代理
        if self.proxy:
            self.session.proxies = {
                "http": self.proxy,
                "https": self.proxy,
            }

        # 设置超时
        self.session.timeout = REQUEST_TIMEOUT

        # 仅在显式开启自动画像时探测 GeoIP；默认固定 JP，避免额外流量和画像漂移。
        self.exit_geo = self._detect_exit_geo() if detect_exit_geo else {}
        self._enforce_proxy_quality()
        self.browser_profile = _browser_cfg.pick_browser_profile(
            self.exit_geo,
            proxy=self.proxy,
            browser_family=self.browser_family,
        )
        self.browser_profile["react_listening_key"] = self.react_listening_key
        self.browser_profile["react_container_key"] = self.react_container_key
        self.browser_profile["react_resources_key"] = self.react_resources_key
        issues = validate_browser_profile(self.browser_profile)
        if issues:
            logger.warning("[指纹] 浏览器画像存在不一致: %s", "; ".join(issues))

        # 让 HTTP Cookie、OAuth 参数 ext-oai-did、Sentinel 里的 id 三者一致。
        # 浏览器里 oai-did 通常会作为一方 Cookie 存在；协议层主动补齐可减少同一会话内
        # “头部/参数/JS 指纹有设备 ID，但 Cookie Jar 为空”的不一致。
        for domain in ("chatgpt.com", "auth.openai.com", "sentinel.openai.com"):
            self.session.cookies.set("oai-did", self.device_id, domain=domain, path="/")

        # Cloudflare 状态只能来自真实响应 Set-Cookie；这里仅记录变化，不主动伪造/覆盖。
        self._cf_cookie_seen = self.cf_cookie_snapshot()

    def cf_cookie_snapshot(self) -> dict:
        """返回当前 CookieJar 中的 Cloudflare 关键 Cookie 摘要，便于确认同 IP/同会话连续性。"""
        out = {}
        try:
            for cookie in self.session.cookies.jar:
                name = getattr(cookie, "name", "")
                if name in _CF_COOKIE_NAMES:
                    out[f"{getattr(cookie, 'domain', '')}:{name}"] = len(str(getattr(cookie, "value", "") or ""))
        except Exception:
            pass
        return out

    def _observe_cf_cookie_changes(self, url: str) -> None:
        current = self.cf_cookie_snapshot()
        if current != getattr(self, "_cf_cookie_seen", {}):
            logger.info("[CF] Cookie 状态更新 url=%s keys=%s", self._log_url(url), sorted(current.keys()))
            self._cf_cookie_seen = current

    def _log_url(self, url: str) -> str:
        return "<private-auth-request>" if getattr(self, "redact_request_urls", False) else url

    def _enforce_proxy_quality(self) -> None:
        """根据 GeoIP org/ASN 粗判代理质量，默认拒绝云厂商/DC 出口。"""
        try:
            from config import browser as _browser_cfg
            reject = bool(getattr(_browser_cfg, "REJECT_CLOUD_PROXY", False))
            keywords = list(getattr(_browser_cfg, "CLOUD_PROXY_ORG_KEYWORDS", []) or [])
        except Exception:
            return
        if not reject or not self.exit_geo:
            return
        org = str(self.exit_geo.get("org") or "").lower()
        if not org:
            return
        hit = next((kw for kw in keywords if kw and str(kw).lower() in org), "")
        if hit:
            raise RuntimeError(
                f"代理出口疑似云厂商/DC，已拒绝继续注册："
                f"ip={self.exit_geo.get('ip') or '?'} country={self.exit_geo.get('country') or '?'} "
                f"org={self.exit_geo.get('org') or '?'} hit={hit}. "
                f"如确认是住宅代理，可设置 REJECT_CLOUD_PROXY=False。"
            )

    def _cookie_header_for_domain(self, domain: str) -> str:
        """导出当前会话给指定域名可见的 Cookie，供 Node VM document.cookie 使用。"""
        pairs = []
        wanted = domain.lower().lstrip(".")
        try:
            for cookie in self.session.cookies.jar:
                name = getattr(cookie, "name", "")
                value = getattr(cookie, "value", "")
                cdom = str(getattr(cookie, "domain", "") or "").lower().lstrip(".")
                if not name:
                    continue
                if cdom and not (wanted == cdom or wanted.endswith("." + cdom) or cdom.endswith("." + wanted)):
                    continue
                pairs.append(f"{name}={value}")
        except Exception:
            pass
        return "; ".join(pairs)

    def auth_cookie_header(self) -> str:
        return self._cookie_header_for_domain("auth.openai.com") or f"oai-did={self.device_id}"

    def sentinel_cookie_header(self) -> str:
        return self._cookie_header_for_domain("sentinel.openai.com") or f"oai-did={self.device_id}"

    def chatgpt_cookie_header(self) -> str:
        return self._cookie_header_for_domain("chatgpt.com") or f"oai-did={self.device_id}"

    def _detect_exit_geo(self, *, force: bool = False) -> dict:
        """通过当前代理检测出口 IP 地理信息。

        ``AUTO_BROWSER_LOCALE_FROM_IP`` 只控制是否用 GeoIP 改写浏览器画像，
        不应阻止注册前的国家一致性诊断。调用方可用 ``force=True`` 低成本
        探测出口国家，同时继续保留固定语言/时区画像。
        """
        try:
            from config import browser as _browser_cfg
            if (
                not force
                and not getattr(_browser_cfg, "AUTO_BROWSER_LOCALE_FROM_IP", True)
            ):
                return {}
            endpoints = list(getattr(_browser_cfg, "IP_GEO_ENDPOINTS", []) or [])
            timeout = float(getattr(_browser_cfg, "IP_GEO_TIMEOUT", 6) or 6)
        except Exception:
            return {}

        cache_key = self.proxy or "__direct__"
        with _GEO_CACHE_LOCK:
            cached = _GEO_CACHE.get(cache_key)
            if cached is not None:
                return dict(cached)

        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        for url in endpoints:
            try:
                resp = self.session.get(url, headers=headers, timeout=timeout)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                geo = self._normalize_geo_response(data)
                if geo.get("country") or geo.get("timezone"):
                    with _GEO_CACHE_LOCK:
                        _GEO_CACHE[cache_key] = dict(geo)
                    logger.info(
                        "[指纹] 出口IP地理信息: ip=%s country=%s city=%s timezone=%s",
                        geo.get("ip") or "?", geo.get("country") or "?",
                        geo.get("city") or "?", geo.get("timezone") or "?",
                    )
                    return geo
            except Exception as exc:
                logger.debug(f"[指纹] 出口 IP 地理检测失败 endpoint={url}: {type(exc).__name__}: {exc}")
                continue
        with _GEO_CACHE_LOCK:
            _GEO_CACHE[cache_key] = {}
        return {}

    def probe_exit_geo(self) -> dict:
        """在固定画像模式下仅探测出口 GeoIP，绝不改写语言/时区。"""
        geo = self._detect_exit_geo(force=True)
        self.exit_geo = dict(geo or {})
        return dict(self.exit_geo)

    @staticmethod
    def _normalize_geo_response(data: dict) -> dict:
        """兼容 ipinfo / ipapi / ipwho.is 等常见 JSON 字段。"""
        if not isinstance(data, dict):
            return {}
        timezone = data.get("timezone")
        if isinstance(timezone, dict):
            timezone = timezone.get("id") or timezone.get("name")
        return {
            "ip": data.get("ip") or data.get("query"),
            "country": (data.get("country") or data.get("country_code") or data.get("countryCode") or "").upper(),
            "region": data.get("region") or data.get("regionName"),
            "city": data.get("city"),
            "timezone": timezone or "",
            "org": data.get("org") or data.get("isp") or data.get("connection", {}).get("org"),
        }

    def _get_common_headers(self) -> dict:
        """获取通用请求头，优先使用本 BrowserSession 的稳定画像。"""
        profile = getattr(self, "browser_profile", {}) or {}
        headers = {
            "User-Agent": str(profile.get("user_agent") or USER_AGENT),
            "accept-language": str(profile.get("accept_language") or ACCEPT_LANGUAGE),
        }

        # Firefox/Safari 不发送 Chromium Client Hints；Chrome 画像才补 sec-ch-*。
        send_client_hints = bool(profile.get("send_client_hints", bool(SEC_CH_UA)))
        if send_client_hints:
            if profile.get("sec_ch_ua") or SEC_CH_UA:
                headers["sec-ch-ua"] = str(profile.get("sec_ch_ua") or SEC_CH_UA)
            if profile.get("sec_ch_ua_mobile") or SEC_CH_UA_MOBILE:
                headers["sec-ch-ua-mobile"] = str(profile.get("sec_ch_ua_mobile") or SEC_CH_UA_MOBILE)
            if profile.get("sec_ch_ua_platform") or SEC_CH_UA_PLATFORM:
                headers["sec-ch-ua-platform"] = str(profile.get("sec_ch_ua_platform") or SEC_CH_UA_PLATFORM)
            if SEND_HIGH_ENTROPY_CLIENT_HINTS:
                headers.update({
                    "sec-ch-ua-full-version-list": SEC_CH_UA_FULL_VERSION_LIST,
                    "sec-ch-ua-platform-version": SEC_CH_UA_PLATFORM_VERSION,
                    "sec-ch-ua-arch": SEC_CH_UA_ARCH,
                    "sec-ch-ua-bitness": SEC_CH_UA_BITNESS,
                    "sec-ch-ua-model": SEC_CH_UA_MODEL,
                })
        return headers

    def navigator_language(self) -> str:
        """当前会话画像里的 navigator.language。"""
        return str((getattr(self, "browser_profile", {}) or {}).get("navigator_language") or "ja-JP")

    def _navigation_accept(self) -> str:
        profile = getattr(self, "browser_profile", {}) or {}
        if str(profile.get("browser_family") or "").lower() == "firefox":
            return "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        return (
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
            "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        )

    @staticmethod
    def _sec_fetch_site_for(target_origin: str, referer: str) -> str:
        """按 Referer 粗略模拟浏览器的 Sec-Fetch-Site。"""
        ref = (referer or "").lower()
        target = target_origin.lower().rstrip("/")
        if ref.startswith(target):
            return "same-origin"
        if ref.startswith("https://chatgpt.com") or ref.startswith("https://auth.openai.com") or ref.startswith("https://sentinel.openai.com"):
            return "cross-site"
        return "none"

    def make_auth_trace_headers(self) -> dict:
        """生成一组内部配对一致、仅用于当前 Auth JSON 请求的 trace 头。"""
        trace_id_int = (uuid.uuid4().int & ((1 << 63) - 1)) or 1
        parent_id_int = (uuid.uuid4().int & ((1 << 63) - 1)) or 1
        trace_id = str(trace_id_int)
        parent_id = str(parent_id_int)
        trace_hex = format(trace_id_int, "032x")
        parent_hex = format(parent_id_int, "016x")
        return {
            "traceparent": f"00-{trace_hex}-{parent_hex}-01",
            "tracestate": f"dd=s:1;o:{self.datadog_origin}",
            "x-datadog-origin": self.datadog_origin,
            "x-datadog-sampling-priority": "1",
            "x-datadog-trace-id": trace_id,
            "x-datadog-parent-id": parent_id,
        }

    def _attach_auth_rum_headers(self, headers: dict) -> dict:
        """Auth Web JSON 接口头：HAR 中只出现 RUM/trace/access-flow，不带 oai-client-*。"""
        headers.update(self.make_auth_trace_headers())
        headers["x-access-flow-invocation-id"] = str(uuid.uuid4())
        navigation_id = str(getattr(self, "document_navigation_id", "") or "")
        if not navigation_id:
            navigation_id = str(uuid.uuid4())
            self.document_navigation_id = navigation_id
        headers["x-openai-document-navigation-id"] = navigation_id
        return headers

    def js_timezone_offset_min(self) -> int:
        """返回 JS Date.getTimezoneOffset() 语义：UTC-local，东八区为 -480。"""
        profile = getattr(self, "browser_profile", {}) or {}
        return -int(profile.get("timezone_offset_minutes", 0) or 0)

    def _attach_oai_context_headers(self, headers: dict) -> dict:
        """补齐同一设备上下文头，和 oai-did Cookie / OAuth ext-oai-did 保持一致。"""
        headers["oai-client-build-number"] = OAI_CLIENT_BUILD_NUMBER
        headers["oai-client-version"] = OAI_CLIENT_VERSION
        headers["oai-device-id"] = self.device_id
        headers["oai-language"] = self.navigator_language()
        headers["oai-session-id"] = self.oai_session_id
        return headers

    def _attach_frontend_api_headers(self, headers: dict) -> dict:
        """前端 API 统一头：BrowserProfile + 稳定的 OAI 设备上下文。"""
        self._attach_oai_context_headers(headers)
        return headers

    def get_nextauth_headers(self, referer: str = "https://chatgpt.com/") -> dict:
        """NextAuth `/api/auth/*` 头；HAR 中不携带 oai-client-*。"""
        headers = self._get_common_headers()
        headers.update({
            "accept": "*/*",
            "content-type": "application/json",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": referer,
            "priority": "u=1, i",
        })
        return headers

    def get_chatgpt_headers(self, referer: str = "https://chatgpt.com/login") -> dict:
        """
        获取 chatgpt.com 域名的请求头。
        用于步骤1-3。
        """
        headers = self._get_common_headers()
        headers.update({
            "accept": "*/*",
            "content-type": "application/json",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": referer,
            "priority": "u=1, i",
        })
        return self._attach_frontend_api_headers(headers)

    def get_auth_headers(self, referer: str = "https://auth.openai.com/create-account/password") -> dict:
        """
        获取 auth.openai.com 域名的请求头。
        用于步骤7、10、12。
        """
        headers = self._get_common_headers()
        headers.update({
            "accept": "application/json",
            "content-type": "application/json",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": referer,
            "priority": "u=1, i",
            "origin": "https://auth.openai.com",
        })
        return self._attach_auth_rum_headers(headers)

    def get_auth_navigate_headers(self, referer: str = "https://chatgpt.com/", user_initiated: bool = True, target_origin: str = "https://auth.openai.com") -> dict:
        """
        获取 auth.openai.com 导航请求头（用于GET页面请求）。
        用于步骤4、5、8。
        """
        headers = self._get_common_headers()
        headers.update({
            "accept": self._navigation_accept(),
            "sec-fetch-site": self._sec_fetch_site_for(target_origin, referer),
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "referer": referer,
            "priority": "u=0, i",
            "upgrade-insecure-requests": "1",
        })
        if user_initiated:
            headers["sec-fetch-user"] = "?1"
        return headers

    def get_chatgpt_navigate_headers(self, referer: str = "https://chatgpt.com/", user_initiated: bool = True) -> dict:
        """获取 chatgpt.com 页面导航请求头，用于预热登录页 / 回到应用页。"""
        headers = self._get_common_headers()
        headers.update({
            "accept": self._navigation_accept(),
            "sec-fetch-site": self._sec_fetch_site_for("https://chatgpt.com", referer),
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "referer": referer,
            "priority": "u=0, i",
            "upgrade-insecure-requests": "1",
        })
        if user_initiated:
            headers["sec-fetch-user"] = "?1"
        return headers

    def get_sentinel_headers(self) -> dict:
        """
        获取 sentinel.openai.com 的请求头。
        用于步骤6、9、11。
        """
        from config import SENTINEL_SV
        headers = self._get_common_headers()
        headers.update({
            "accept": "*/*",
            "content-type": "text/plain;charset=UTF-8",
            "origin": "https://sentinel.openai.com",
            "referer": f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={SENTINEL_SV}",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "priority": "u=1, i",
        })
        # Sentinel iframe 是独立站点上下文；HAR 中不携带 ChatGPT backend 的
        # oai-client-* / oai-session-id 头。
        return headers

    def get_sentinel_frame_headers(self) -> dict:
        """构造 Auth Web 内嵌 Sentinel iframe 的导航头。"""
        headers = self.get_auth_navigate_headers(
            referer="https://auth.openai.com/",
            user_initiated=False,
            target_origin="https://sentinel.openai.com",
        )
        # auth.openai.com -> sentinel.openai.com 是 same-site iframe 导航，
        # 不是顶层 document，也不是用户点击触发。
        headers["sec-fetch-site"] = "same-site"
        headers["sec-fetch-dest"] = "iframe"
        headers.pop("sec-fetch-user", None)
        return headers


    @staticmethod
    def _chatgpt_target_route(path: str) -> str:
        """把真实 URL path 归一成 HAR 里的 x-openai-target-route 形态。"""
        if path.startswith("/backend-api/accounts/check/"):
            return "/backend-api/accounts/check/{version}"
        if path.startswith("/backend-anon/accounts/check/"):
            return "/backend-anon/accounts/check/{version}"
        if path.startswith("/backend-api/conversation/") and path != "/backend-api/conversation/init":
            return "/backend-api/conversation/{conversation_id}"
        if path.startswith("/backend-anon/conversation/") and path != "/backend-anon/conversation/init":
            return "/backend-anon/conversation/{conversation_id}"
        return path

    def _attach_openai_target_headers_for_url(self, url: str, headers: dict | None) -> dict | None:
        """
        自动补齐 HAR 中 chatgpt.com 前端 API 的 target 诊断头。

        NextAuth `/api/auth/*` 和 auth.openai.com JSON 接口在抓包中不带这些头，
        这里仅对 chatgpt.com 的 backend/ces 前端接口补齐，避免各调用点手动维护。
        """
        if headers is None:
            return headers
        try:
            parsed = urlparse(str(url))
        except Exception:
            return headers
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        if host != "chatgpt.com":
            return headers
        if not (path.startswith("/backend-api/") or path.startswith("/backend-anon/")):
            return headers
        # 不覆盖调用方显式指定的值，便于后续特殊接口单独调整。
        headers.setdefault("x-openai-target-path", path)
        headers.setdefault("x-openai-target-route", self._chatgpt_target_route(path))
        headers.setdefault("x-oai-is-pending-updates", '{"v":3,"updates":[]}')
        observation = str(
            getattr(self, "chatgpt_client_observation", "") or ""
        ).strip()
        if observation:
            headers.setdefault("x-oai-is-client-observation", observation)
        return headers

    def _observe_response(self, resp, url: str, method: str = "UNKNOWN"):
        """记录边缘拒绝，但不让一个响应冻结整个会话。

        是否重试由调用阶段决定：匿名预热可以换新 sticky 会话，已经触发邮箱
        OTP 的认证阶段则应保留当前状态并失败退出。全局 900 秒熔断会把这两种情况
        混在一起，并让同一请求后面的诊断链全部变成假失败。
        """
        status = int(getattr(resp, "status_code", 0) or 0)
        self._observe_cf_cookie_changes(url)
        try:
            response_headers = getattr(resp, "headers", {}) or {}
            delivery_nonce = str(
                response_headers.get("x-oai-is-delivery-nonce") or ""
            ).strip()
            if delivery_nonce:
                observation = f"v1.r.p.{delivery_nonce}"
                if observation != getattr(
                    self, "chatgpt_client_observation", ""
                ):
                    self.chatgpt_delivery_nonce = delivery_nonce
                    self.chatgpt_client_observation = observation
                    source = str(
                        response_headers.get("x-oai-is-delivery-source") or ""
                    ).strip()
                    logger.info(
                        "[HTTP] 已接收 ChatGPT delivery observation: "
                        "source=%s nonce=%s...",
                        source or "未知",
                        delivery_nonce[:8],
                    )
        except Exception:
            logger.debug("[HTTP] 解析 ChatGPT delivery observation 失败", exc_info=True)
        if status in (403, 429):
            from core.http_diagnostics import record_forbidden, safe_target

            if status == 403:
                record_forbidden(self, resp, url, method)
            retry_after = ""
            try:
                retry_after = str((getattr(resp, "headers", {}) or {}).get("retry-after") or "")
            except Exception:
                pass
            logger.warning(
                "[HTTP] 当前会话收到 HTTP %s，不做全局熔断，交由当前阶段处理：url=%s retry_after=%s",
                status,
                safe_target(url),
                retry_after or "无",
            )
        return resp

    def get(self, url: str, headers: dict = None, **kwargs):
        """发送 GET 请求"""
        headers = self._attach_openai_target_headers_for_url(url, headers)
        resp = self.session.get(url, headers=headers, **kwargs)
        return self._observe_response(resp, url, "GET")

    def post(self, url: str, headers: dict = None, **kwargs):
        """发送 POST 请求"""
        headers = self._attach_openai_target_headers_for_url(url, headers)
        resp = self.session.post(url, headers=headers, **kwargs)
        return self._observe_response(resp, url, "POST")

    def delete(self, url: str, headers: dict = None, **kwargs):
        """发送 DELETE 请求"""
        headers = self._attach_openai_target_headers_for_url(url, headers)
        resp = self.session.delete(url, headers=headers, **kwargs)
        return self._observe_response(resp, url, "DELETE")
