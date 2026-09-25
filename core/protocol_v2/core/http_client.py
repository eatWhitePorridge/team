"""Chrome 指纹 HTTP 客户端 + 标准头集合 + W3C/Datadog trace headers。

对应 newgpt2api browser/client.go + jsonHeaders/navHeaders 函数。
"""

from __future__ import annotations

import asyncio
import secrets
import socket
import uuid
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any, Optional
from urllib.parse import urlparse

from curl_cffi.requests import AsyncSession, Session
from curl_cffi.requests.errors import RequestsError

from .profile import Profile
from config import OAI_CLIENT_BUILD_NUMBER, OAI_CLIENT_VERSION

AUTH_BASE = "https://auth.openai.com"
PLATFORM_BASE = "https://platform.openai.com"

# === Platform OAuth client（不强制 add-phone，MVP 用这条）===
PLATFORM_CLIENT_ID = "app_2SKx67EdpoN0G6j64rFvigXD"
PLATFORM_REDIRECT_URI = PLATFORM_BASE + "/auth/callback"
PLATFORM_AUDIENCE = "https://api.openai.com/v1"
PLATFORM_AUTH0_CLIENT = "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"
DEFAULT_SCOPE = "openid profile email offline_access"


def make_trace_headers() -> dict[str, str]:
    """W3C traceparent + Datadog 追踪头。OpenAI 前端 SPA 真实在带。"""
    trace_id_int = secrets.randbits(63) or 1
    parent_id_int = secrets.randbits(63) or 1
    trace_id = str(trace_id_int)
    parent_id = str(parent_id_int)
    return {
        "traceparent": f"00-{trace_id_int:032x}-{parent_id_int:016x}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def json_headers(
    profile: Profile,
    device_id: str,
    referer: str,
    *,
    document_navigation_id: str = "",
) -> dict[str, str]:
    """application/json POST 用的标准头（不含 sentinel）。"""
    h = {
        "accept": "application/json",
        "content-type": "application/json",
        "accept-language": profile.locale,
        "origin": AUTH_BASE,
        "priority": "u=1, i",
        "referer": referer,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sec-ch-ua": profile.sec_ch_ua,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": profile.sec_ch_ua_platform,
        "user-agent": profile.user_agent,
    }
    h.update(make_trace_headers())
    h["x-access-flow-invocation-id"] = str(uuid.uuid4())
    if document_navigation_id:
        h["x-openai-document-navigation-id"] = document_navigation_id
    return h


def nav_headers(profile: Profile, device_id: str, *, site: str = "same-origin") -> dict[str, str]:
    """整页跳转类 GET 用的头集合（authorize / email-otp/send / consent 链）。

    ``device_id`` 保留在签名里兼容旧调用。设备身份由 ``oai-did`` Cookie 和
    authorize 查询参数携带；普通 document navigation 不主动添加自定义 OAI 头。
    """
    return {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,*/*;q=0.8",
        "accept-language": profile.locale,
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": site,
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "sec-ch-ua": profile.sec_ch_ua,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": profile.sec_ch_ua_platform,
        "user-agent": profile.user_agent,
    }


def chatgpt_frontend_headers(
    profile: Profile,
    device_id: str,
    oai_session_id: str,
    *,
    content_type: str | None = None,
) -> dict[str, str]:
    """ChatGPT backend/CES 共享的稳定前端上下文头。"""
    headers = {
        "accept-language": profile.locale,
        "user-agent": profile.user_agent,
        "oai-client-build-number": OAI_CLIENT_BUILD_NUMBER,
        "oai-client-version": OAI_CLIENT_VERSION,
        "oai-device-id": device_id,
        "oai-language": profile.oai_language,
        "oai-session-id": oai_session_id,
    }
    if content_type:
        headers["content-type"] = content_type
    return headers


class BrowserAsyncClient:
    """Async facade over curl_cffi with a stable SOCKS transport.

    curl_cffi 0.14's AsyncSession can stall when one SOCKS session switches
    origins (for example auth.openai.com -> sentinel.openai.com).  Its regular
    Session does not have that problem, so SOCKS clients run one synchronous
    Session on a dedicated worker thread.  Direct and HTTP-proxy clients keep
    the native AsyncSession path.
    """

    def __init__(
        self,
        *,
        profile: Profile,
        proxy: Optional[str],
        timeout_s: float,
    ) -> None:
        headers = {
            "user-agent": profile.user_agent,
            "accept-language": profile.locale,
            "sec-ch-ua": profile.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": profile.sec_ch_ua_platform,
        }
        self.profile = profile
        self.device_id = ""
        self.auth_session_logging_id = str(uuid.uuid4())
        self.oaicom_stable_id = str(uuid.uuid4())
        self.login_web_anonymous_id = str(uuid.uuid4())
        self.oai_session_id = str(uuid.uuid4())
        self.anonymous_id = str(uuid.uuid4())
        # Auth Web keeps this value stable for the lifetime of one document,
        # while trace and access-flow IDs are regenerated for each JSON call.
        self.document_navigation_id = str(uuid.uuid4())
        self.proxy_url = (proxy or "").strip() or None
        self._closed = False
        self._executor: ThreadPoolExecutor | None = None
        proxy_scheme = urlparse(self.proxy_url or "").scheme.lower()
        self._sync_thread_transport = proxy_scheme.startswith("socks")

        options = dict(
            headers=headers,
            impersonate=profile.impersonate,
            proxy=self.proxy_url,
            timeout=float(timeout_s),
            allow_redirects=True,
            trust_env=False,
            default_headers=True,
        )
        if self._sync_thread_transport:
            self._executor = ThreadPoolExecutor(
                max_workers=1,
                thread_name_prefix="curl-cffi-socks",
            )
            self._client: Session | AsyncSession = Session(**options)
            self.transport_mode = "sync_thread"
        else:
            self._client = AsyncSession(max_clients=4, **options)
            self.transport_mode = "async"

    @property
    def cookies(self):
        return self._client.cookies

    @property
    def headers(self):
        return self._client.headers

    def cookie_header_for_domain(self, domain: str) -> str:
        wanted = str(domain or "").lower().lstrip(".")
        pairs: list[str] = []
        for cookie in self.cookies.jar:
            name = str(getattr(cookie, "name", "") or "")
            value = str(getattr(cookie, "value", "") or "")
            cookie_domain = str(getattr(cookie, "domain", "") or "").lower().lstrip(".")
            if not name:
                continue
            if cookie_domain and not (
                wanted == cookie_domain
                or wanted.endswith("." + cookie_domain)
                or cookie_domain.endswith("." + wanted)
            ):
                continue
            pairs.append(f"{name}={value}")
        return "; ".join(pairs)

    async def request(self, method: str, url: str, **kwargs: Any):
        # Existing flow code uses httpx names. curl_cffi calls these data and
        # allow_redirects; translating here keeps every caller on one session.
        if "content" in kwargs:
            if "data" in kwargs:
                raise TypeError("request cannot contain both content and data")
            kwargs["data"] = kwargs.pop("content")
        if "follow_redirects" in kwargs:
            kwargs["allow_redirects"] = kwargs.pop("follow_redirects")
        if self._closed:
            raise RuntimeError("BrowserAsyncClient is closed")
        if self._sync_thread_transport:
            assert self._executor is not None
            call = partial(self._client.request, method=method, url=url, **kwargs)
            return await asyncio.get_running_loop().run_in_executor(self._executor, call)
        return await self._client.request(method=method, url=url, **kwargs)

    async def get(self, url: str, **kwargs: Any):
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any):
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any):
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any):
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any):
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs: Any):
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any):
        return await self.request("OPTIONS", url, **kwargs)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._sync_thread_transport:
            assert self._executor is not None
            try:
                await asyncio.get_running_loop().run_in_executor(
                    self._executor,
                    self._client.close,
                )
            finally:
                self._executor.shutdown(wait=True, cancel_futures=True)
            return
        await self._client.close()

    async def aclose(self) -> None:
        await self.close()

    async def __aenter__(self) -> "BrowserAsyncClient":
        if self._closed:
            raise RuntimeError("BrowserAsyncClient is closed")
        return self

    async def __aexit__(self, _exc_type, _exc, _tb) -> None:
        await self.close()


def build_client(
    *,
    profile: Profile,
    proxy: Optional[str],
    timeout_s: float = 60.0,
) -> BrowserAsyncClient:
    """构建全流程复用的 Chrome TLS 指纹异步客户端。

    - cookie jar 自动管理
    - proxy 单一 URL（http/https/socks 任意）
    - 默认跟随重定向；兼容现有 follow_redirects 调用
    - TLS / HTTP2 / UA / Client Hints 使用同一个 Chrome target
    """
    return BrowserAsyncClient(profile=profile, proxy=proxy, timeout_s=timeout_s)


async def request_with_retry(
    client: BrowserAsyncClient,
    method: str,
    url: str,
    *,
    retries: int = 2,
    backoff_s: float = 1.0,
    **kwargs: Any,
) -> Any:
    """Chrome 指纹请求 + 应用层网络重试。

    捕获 RemoteProtocolError / ReadError / ConnectError 共 N 次。
    OpenAI / 代理 keep-alive 在 IMAP 长等候后断开是常见的，必须能恢复。
    """
    import asyncio

    last_exc: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            return await client.request(method, url, **kwargs)
        except (RequestsError, OSError) as exc:
            last_exc = exc
            if attempt >= retries:
                break
            # macOS / 本地 DNS 偶发 Errno 8，立即重试大概率仍失败；先让解析器缓一下。
            msg = str(exc).lower()
            if "nodename nor servname" in msg or "temporary failure in name resolution" in msg:
                try:
                    host = urlparse(url).hostname
                    if host:
                        await asyncio.to_thread(socket.getaddrinfo, host, 443)
                except Exception:  # noqa: BLE001
                    pass
            await asyncio.sleep(backoff_s * (attempt + 1))
    assert last_exc is not None
    raise last_exc


def set_oai_did_cookie(client: BrowserAsyncClient, device_id: str) -> None:
    """OpenAI 通过 `.auth.openai.com` 域的 oai-did cookie 识别"同一会话"，
    sentinel.openai.com 后端会校验。**必须**在第一次 authorize 之前设置。"""
    client.device_id = device_id
    for domain in ("auth.openai.com", "chatgpt.com", "sentinel.openai.com"):
        client.cookies.set("oai-did", device_id, domain=domain, path="/")


def clear_oauth_session_cookies(client: BrowserAsyncClient) -> None:
    """清掉 OAuth login flow 的 session cookies（重新走 OAuth 前用）。

    严格对齐 Go `clearOAuthSessionCookies`：注册阶段的 oai-client-auth-session /
    login_session 没有 workspaces[] 字段，必须清掉让 OpenAI 重新种一份带
    workspaces 的 cookie。**保留** oai-did、oai-allow-* 等设备级 cookie。
    """
    names_to_clear = {
        "oai-client-auth-session",
        "login_session",
        "oai-sc",
        "_cfuvid",
        "oai-csrf-cookie",
        "_oai_workspace",
        "oai-allow-organic",
    }
    to_remove: list[tuple[str, str, str]] = []
    for cookie in client.cookies.jar:
        if (cookie.name or "") in names_to_clear:
            to_remove.append((cookie.name, cookie.domain or "", cookie.path or "/"))
    for n, d, p in to_remove:
        try:
            client.cookies.delete(n, domain=d, path=p)
        except Exception:  # noqa: BLE001
            pass
