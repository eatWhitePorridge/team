# -*- coding: utf-8 -*-
"""Platform passwordless/PKCE 基础注册，并转换为可管理的 ChatGPT Web AT。"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from core.account_cookie_store import normalize_cookies
from core.account_export import save_account_data
from core.email_provider import resolve_email_source, wait_for_otp
from core.protocol_rate_limit import acquire_protocol_exit_lease
from core.protocol_v2.chatgpt_web import chatgpt_web_login_with_client
from core.protocol_v2.core.profile import random_profile
from core.protocol_v2.flow import register_via_platform_passwordless

logger = logging.getLogger(__name__)


def _profile_browser_environment(profile: Any) -> dict:
    """将 OAuth v2 Profile 转成 BrowserSession/VM 使用的同一画像字典。"""
    environment = dict(getattr(profile, "browser_environment", {}) or {})

    def value(name: str, default: Any = "") -> Any:
        return getattr(profile, name, default)

    # Profile 是 OAuth 客户端的单一事实来源；browser_environment 可能来自
    # 较早版本的缓存，因此显式字段优先，避免 HTTP UA 与 VM 指纹分叉。
    browser_family = str(environment.get("browser_family") or "chrome").lower()
    fields = {
        "user_agent": value("user_agent"),
        "accept_language": value("locale"),
        "navigator_language": value("language"),
        "navigator_languages": list(value("navigator_languages", ()) or ()),
        "timezone_iana": value("timezone_iana"),
        "timezone_name": value("timezone_name"),
        "timezone_offset_minutes": value("timezone_offset_minutes"),
        "screen_width": value("screen_width"),
        "screen_height": value("screen_height"),
        "hardware_concurrency": value("hardware_concurrency"),
        "device_memory": value("device_memory"),
        "device_pixel_ratio": value("device_pixel_ratio"),
        "sec_ch_ua": value("sec_ch_ua"),
        "sec_ch_ua_platform": value("sec_ch_ua_platform"),
        "browser_major": value("browser_major"),
        "chrome_major": value("browser_major"),
        "browser_family": browser_family,
        "send_client_hints": browser_family == "chrome",
    }
    for key, field_value in fields.items():
        if field_value not in (None, "", []):
            environment[key] = field_value
    environment.setdefault("locale_profile", str(value("region", "JP") or "JP").lower())
    environment.setdefault("geo", {"country": str(value("region", "JP") or "JP").upper()})
    return environment


def _merge_cookie_snapshots(*snapshots: Any) -> list[dict]:
    """按 domain/path/name 合并 Cookie，后面的快照覆盖前面的值。"""
    merged: dict[tuple[str, str, str], dict] = {}
    for snapshot in snapshots:
        try:
            values = normalize_cookies(snapshot, source="protocol_oauth_bootstrap")
        except Exception:
            values = []
        for cookie in values:
            key = (
                str(cookie.get("domain") or "").lower(),
                str(cookie.get("path") or "/"),
                str(cookie.get("name") or ""),
            )
            if key[2]:
                merged[key] = dict(cookie)
    return list(merged.values())


def _install_cookie_snapshot(session: Any, cookies: list[dict]) -> None:
    """把已校验的 Web Cookie 快照装入一个短生命周期 BrowserSession。"""
    now = time.time()
    for cookie in cookies:
        try:
            name = str(cookie.get("name") or "")
            value = str(cookie.get("value") or "")
            expires = cookie.get("expires")
            try:
                expires_at = float(expires) if expires not in (None, "") else 0.0
            except (TypeError, ValueError):
                expires_at = 0.0
            if expires_at > 0 and expires_at <= now:
                continue
            if name.lower() == "oai-did" and value != str(session.device_id or ""):
                continue
            cookie_kwargs = {
                "domain": str(cookie.get("domain") or "chatgpt.com"),
                "path": str(cookie.get("path") or "/"),
                "secure": bool(cookie.get("secure"))
                or name.lower().startswith(("__secure-", "__host-")),
            }
            session.session.cookies.set(
                name,
                value,
                **cookie_kwargs,
            )
        except Exception:
            logger.debug("[Cookie][OAuth] bootstrap Cookie 导入失败", exc_info=True)


def _cookie_snapshot_input(session: Any) -> Any:
    """Return the active transport's Cookie container in a normalizable shape."""
    transport = getattr(session, "session", session)
    cookies = getattr(transport, "cookies", None)
    if cookies is None:
        return None
    # curl_cffi/httpx expose a ``jar`` attribute, while lightweight test and
    # compatibility clients may expose the iterable container directly.
    return getattr(cookies, "jar", None) or cookies


def _copy_client_context(client: Any, target: Any) -> None:
    """复制不会泄露秘密、但会影响同一 Web 生命周期的稳定标识。"""
    for name in (
        "auth_session_logging_id",
        "document_navigation_id",
        "oaicom_stable_id",
        "login_web_anonymous_id",
        "oai_session_id",
        "anonymous_id",
        "datadog_origin",
        "chatgpt_client_observation",
        "chatgpt_delivery_nonce",
        "sentinel_sid",
        "chatgpt_sentinel_sid",
        "react_listening_key",
        "react_container_key",
        "react_resources_key",
        "obi_id",
        "_ces_authenticated_identity",
    ):
        current = getattr(client, name, None)
        if current not in (None, ""):
            setattr(target, name, current)
    emitted = getattr(client, "_ces_emitted", None)
    if isinstance(emitted, set):
        # Web login already emitted the async authenticated lifecycle.  Reusing
        # the marks avoids sending a duplicate telemetry batch from the bridge.
        target._ces_emitted = set(emitted)


def _supports_shared_async_client(client: Any) -> bool:
    """Return whether the original OAuth client can be driven on its loop."""
    get = getattr(client, "get", None)
    post = getattr(client, "post", None)
    request = getattr(client, "request", None)
    if not callable(get) or not callable(post):
        return False
    # The bridge must share the live Cookie Jar as well as the transport. An
    # async test/compatibility client without cookies can still use the local
    # BrowserSession snapshot path safely.
    try:
        if getattr(client, "cookies", None) is None:
            return False
    except Exception:
        return False
    # BrowserAsyncClient exposes coroutine methods directly. The request
    # fallback also covers wrappers whose verb methods return an awaitable but
    # are not marked as coroutine functions.
    return bool(
        inspect.iscoroutinefunction(get)
        or inspect.iscoroutinefunction(post)
        or inspect.iscoroutinefunction(request)
    )


def _attach_shared_async_transport(
    bridge: Any,
    client: Any,
    event_loop: asyncio.AbstractEventLoop,
) -> Any:
    """Route a sync bootstrap session through the still-open async client.

    The VM and response parsing stay in the worker thread, while each HTTP
    operation is submitted back to the OAuth event loop. This preserves the
    original client cookie jar and transport/edge state without requiring a
    second async implementation of the bootstrap sequence.
    """
    local_transport = getattr(bridge, "session", None)
    client_cookies = getattr(client, "cookies", None)
    if client_cookies is None:
        raise RuntimeError("OAuth client 缺少可复用 Cookie Jar")

    bridge.session = SimpleNamespace(
        cookies=client_cookies,
        # The shared client is owned by register_via_platform_passwordless.
        close=lambda: None,
    )

    def request(method: str, url: str, **kwargs: Any):
        async def invoke():
            fn = getattr(client, method)
            result = fn(url, **kwargs)
            if inspect.isawaitable(result):
                result = await result
            return result

        if event_loop.is_closed() or not event_loop.is_running():
            raise RuntimeError("OAuth event loop 已关闭，无法复用 Web client")
        # BrowserSession.get/post normally add these headers immediately before
        # touching the transport. The bridge replaces those methods, so apply
        # the same route decoration here to keep the shared client wire shape.
        request_headers = kwargs.get("headers")
        if request_headers is not None:
            attach_headers = getattr(
                bridge, "_attach_openai_target_headers_for_url", None
            )
            if callable(attach_headers):
                kwargs["headers"] = attach_headers(url, dict(request_headers))

        coroutine = invoke()
        try:
            response = asyncio.run_coroutine_threadsafe(coroutine, event_loop).result()
        except RuntimeError:
            # A loop can close between the check above and submission. Closing
            # the unscheduled coroutine avoids an unawaited-coroutine warning.
            coroutine.close()
            raise
        observe = getattr(bridge, "_observe_response", None)
        if callable(observe):
            return observe(response, url)
        return response

    def shared_get(url: str, headers: dict | None = None, **kwargs: Any):
        if headers is not None:
            kwargs["headers"] = headers
        return request("get", url, **kwargs)

    def shared_post(url: str, headers: dict | None = None, **kwargs: Any):
        if headers is not None:
            kwargs["headers"] = headers
        return request("post", url, **kwargs)

    # Functions assigned on an instance are intentionally plain callables; the
    # closures above already capture the bridge/client and need no descriptor.
    bridge.get = shared_get
    bridge.post = shared_post
    bridge._oauth_local_transport = local_transport
    bridge._oauth_http_client_reused = True
    return local_transport


def _oauth_bootstrap_sync(
    *,
    access_token: str,
    web: Any,
    client: Any,
    profile: Any,
    proxy: str | None,
    cookies: list[dict],
    strict: bool,
    event_loop: asyncio.AbstractEventLoop | None = None,
) -> dict:
    """在工作线程中运行完整 ChatGPT authenticated bootstrap。

    Platform OAuth 使用的是 async curl 客户端，而现有低流量 bootstrap 是
    同步 BrowserSession。能复用原 async client 时，HTTP 请求会回到原 event
    loop；旧/测试 client 则回退到已验证的 Cookie/画像快照桥接。两种路径都
    不会重新注册、兑换优惠或生成任何新的凭证。
    """
    from core.chatgpt_bootstrap import authenticated_bootstrap
    from core.session import BrowserSession

    device_id = str(
        getattr(web, "device_id", "") or ""
    ).strip()
    if not device_id:
        return {
            "status": "unknown",
            "error_type": "missing_device_id",
            "error": "Web 登录结果缺少 device_id",
            "plan": {},
            "cookies": list(cookies or []),
            "metadata": {
                "attempted": True,
                "status": "unknown",
                "error_type": "missing_device_id",
                "error": "Web 登录结果缺少 device_id",
                "device_id_reused": False,
                "proxy_reused": bool(str(proxy or "").strip()),
                "http_client_reused": False,
            },
        }

    environment = _profile_browser_environment(profile)
    browser_family = str(environment.get("browser_family") or "chrome").lower()
    if browser_family not in {"chrome", "firefox"}:
        browser_family = "chrome"
    bridge = None
    local_transport = None
    source_cookies = list(cookies or [])
    reuse_http_client = bool(
        event_loop is not None
        and _supports_shared_async_client(client)
    )
    try:
        bridge = BrowserSession(
            # A shared client already owns the proxy/TLS transport. The local
            # BrowserSession below is used only for header/profile helpers.
            proxy="" if reuse_http_client else proxy,
            detect_exit_geo=False,
            device_id=device_id,
            browser_family=browser_family,
        )
        _copy_client_context(client, bridge)
        if reuse_http_client:
            local_transport = getattr(bridge, "session", None)
            local_transport = _attach_shared_async_transport(
                bridge,
                client,
                event_loop,
            )
        for key in (
            "react_listening_key",
            "react_container_key",
            "react_resources_key",
        ):
            current = getattr(bridge, key, None)
            if current not in (None, ""):
                environment[key] = current
        bridge.browser_profile = environment
        _install_cookie_snapshot(bridge, source_cookies)
        session_info = {
            "user": getattr(web, "user", None) or {},
            "account": getattr(web, "account", None) or {},
            "expires": getattr(web, "expires", None),
        }
        result = authenticated_bootstrap(
            bridge,
            access_token,
            session_info=session_info,
            strict=strict,
            # chatgpt_web_login_with_client already emitted async CES events.
            emit_telemetry=False,
        )
        observed_plan = dict(getattr(bridge, "initial_accounts_check", {}) or {})
        plan_type = str(observed_plan.get("current_plan_type") or "").strip().lower()
        usable = bool(observed_plan.get("ok")) and plan_type not in {"", "guest", "unknown"}
        # A guest/unknown response is an authentication-context diagnostic, not
        # a negative trial decision.  Keep it out of the authoritative plan
        # payload so persistence and callers continue with background recheck.
        plan = observed_plan if usable else {}
        metadata = {
            "attempted": True,
            "status": "ok" if usable else "unknown",
            "obi_synced": bool(getattr(result, "obi_synced", False)),
            "plan_type": plan_type or None,
            "accounts_check_ok": observed_plan.get("ok") is True,
            "plus_trial_eligible": (
                bool(observed_plan.get("plus_trial_eligible")) if usable else None
            ),
            "plus_trial_status": (
                (str(observed_plan.get("plus_trial_status") or "") or None)
                if usable else None
            ),
            "promo_check_ok": (
                (observed_plan.get("promo_check_ok") is True) if usable else None
            ),
            "accounts_check_auth_mode": observed_plan.get("accounts_check_auth_mode"),
            "accounts_check_error_type": observed_plan.get("error_type") if not usable else None,
            "chat_requirements_sdk_url": getattr(bridge, "chat_requirements_sdk_url", ""),
            "chat_requirements_sdk_hash": getattr(bridge, "chat_requirements_sdk_hash", ""),
            "chat_requirements_sdk_execution": "node_vm",
            "chat_requirements_sdk_resolution": getattr(
                bridge, "chat_requirements_sdk_resolution", "unknown"
            ),
            "chat_requirements_sdk_discovery_status": getattr(
                bridge, "chat_requirements_sdk_discovery_status", "unknown"
            ),
            "chat_requirements_sdk_discovery_error_type": (
                getattr(bridge, "chat_requirements_sdk_discovery_error_type", "")
                or None
            ),
            "chat_requirements_sdk_fallback_error_type": (
                getattr(bridge, "chat_requirements_sdk_fallback_error_type", "")
                or None
            ),
            "chat_requirements_prepare_status": getattr(
                bridge, "chat_requirements_prepare_status", "unknown"
            ),
            "chat_requirements_finalize_status": getattr(
                bridge, "chat_requirements_finalize_status", "unknown"
            ),
            "chat_requirements_prepare_http_status": getattr(
                bridge, "chat_requirements_prepare_http_status", None
            ),
            "chat_requirements_finalize_http_status": getattr(
                bridge, "chat_requirements_finalize_http_status", None
            ),
            "device_id_reused": True,
            "proxy_reused": bool(str(proxy or "").strip()),
            "http_client_reused": reuse_http_client,
        }
        merged_cookies = _merge_cookie_snapshots(
            source_cookies,
            _cookie_snapshot_input(bridge),
        )
        return {"status": metadata["status"], "plan": plan, "cookies": merged_cookies, "metadata": metadata}
    except Exception as exc:
        if strict:
            raise
        failed_cookies = source_cookies
        if bridge is not None:
            failed_cookies = _merge_cookie_snapshots(
                source_cookies,
                _cookie_snapshot_input(bridge),
            ) or source_cookies
        logger.warning(
            "[Bootstrap][OAuth] 登录态资格预热失败，保留 unknown 并回退后台复查: %s: %s",
            type(exc).__name__,
            str(exc)[:180],
        )
        return {
            "status": "unknown",
            "error_type": type(exc).__name__,
            "error": str(exc)[:500],
            "plan": {},
            "cookies": failed_cookies,
            "metadata": {
                "attempted": True,
                "status": "unknown",
                "error_type": type(exc).__name__,
                "error": str(exc)[:500],
                "device_id_reused": True,
                "proxy_reused": bool(str(proxy or "").strip()),
                "http_client_reused": reuse_http_client,
            },
        }
    finally:
        if bridge is not None:
            try:
                if local_transport is not None:
                    local_transport.close()
                else:
                    bridge.session.close()
            except Exception:
                logger.debug("[Bootstrap][OAuth] bridge session close failed", exc_info=True)


async def _run_oauth_authenticated_bootstrap(
    *,
    client: Any,
    profile: Any,
    web: Any,
    proxy: str | None,
    cookies: list[dict],
    strict: bool,
) -> dict:
    """异步包装：不阻塞当前 Platform OAuth event loop。"""
    if not callable(getattr(client, "get", None)) or not callable(
        getattr(client, "post", None)
    ):
        return {
            "status": "skipped",
            "plan": {},
            "cookies": list(cookies or []),
            "metadata": {
                "attempted": False,
                "status": "skipped",
                "reason": "client_not_runnable",
                "http_client_reused": False,
            },
        }
    return await asyncio.to_thread(
        _oauth_bootstrap_sync,
        access_token=str(getattr(web, "access_token", "") or ""),
        web=web,
        client=client,
        profile=profile,
        proxy=proxy,
        cookies=list(cookies or []),
        strict=strict,
        event_loop=asyncio.get_running_loop(),
    )


def _platform_result_metadata(platform_result) -> dict:
    """Whitelist non-secret Platform OAuth metadata for account persistence."""
    return {
        "access_token_obtained": bool(getattr(platform_result, "access_token", "")),
        "refresh_token_obtained": bool(getattr(platform_result, "refresh_token", "")),
        "expires_in": int(getattr(platform_result, "expires_in", 0) or 0),
        "token_source": str(getattr(platform_result, "token_source", "") or ""),
    }


@dataclass
class _CurrentOtpFetcher:
    """把当前项目的同步邮箱池适配为参考协议实现的异步 OTP 接口。"""

    initial_code: str = ""
    after_ts: float = field(default_factory=time.time)
    rejected_codes: set[str] = field(default_factory=set)

    async def mark_send_started(self, _email: str) -> None:
        self.after_ts = time.time()

    async def mark_bad(self, _email: str, code: str) -> None:
        value = str(code or "").strip()
        if value:
            self.rejected_codes.add(value)

    async def __call__(self, email: str) -> str:
        if self.initial_code:
            code, self.initial_code = self.initial_code, ""
            return code

        for _ in range(3):
            code = await asyncio.to_thread(
                wait_for_otp,
                email,
                after_ts=self.after_ts,
            )
            code = str(code or "").strip()
            if code and code not in self.rejected_codes:
                return code
            await asyncio.sleep(1)
        raise RuntimeError("邮箱接口重复返回已拒绝的 OTP")


async def _register_and_get_web_at(
    *,
    email: str,
    name: str,
    birthday: str,
    proxy: str | None,
    otp_fetcher: _CurrentOtpFetcher,
) -> dict:
    profile = random_profile(proxy=proxy)
    name_parts = [part for part in str(name or "").split() if part]
    first_name = name_parts[0] if name_parts else None
    last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else None
    captured: dict = {}

    async def web_at_hook(client, hook_profile, device_id, platform_result) -> None:
        # Platform passwordless 产出的 AT/RT 只用于证明 OAuth 注册成功；账号主字段
        # 必须继续保存 ChatGPT Web AT，不能被 Platform 或 Codex token 覆盖。
        captured["platform"] = _platform_result_metadata(platform_result)
        captured["web"] = await chatgpt_web_login_with_client(
            client,
            email=email,
            password="",
            profile=hook_profile,
            device_id=device_id,
            otp_fetcher=otp_fetcher,
            proxy=proxy,
            log=logger.info,
        )
        # post_token_hook 在 register_via_platform_passwordless 的 client 上下文
        # 内执行。必须在 hook 返回、client 关闭前复制 Cookie Jar。
        try:
            captured["web_cookies"] = normalize_cookies(
                client.cookies,
                source="protocol_oauth",
            )
            logger.info(
                "[Cookie][OAuth] 已捕获 ChatGPT Web Cookie：%s，共 %s 条",
                email,
                len(captured["web_cookies"]),
            )
        except Exception as exc:
            captured["web_cookies"] = []
            logger.warning(
                "[Cookie][OAuth] 捕获 ChatGPT Web Cookie 失败（不影响账号保存）：%s: %s",
                type(exc).__name__,
                str(exc)[:180],
            )

        try:
            from config import openai_protocol as protocol_cfg

            bootstrap_enabled = bool(
                getattr(protocol_cfg, "CHATGPT_AUTH_BOOTSTRAP_ENABLED", True)
            )
            bootstrap_strict = bool(
                getattr(protocol_cfg, "CHATGPT_BOOTSTRAP_STRICT", False)
            )
        except Exception:
            bootstrap_enabled = True
            bootstrap_strict = False

        if bootstrap_enabled:
            bootstrap = await _run_oauth_authenticated_bootstrap(
                client=client,
                profile=hook_profile,
                web=captured["web"],
                proxy=proxy,
                cookies=captured.get("web_cookies") or [],
                strict=bootstrap_strict,
            )
        else:
            bootstrap = {
                "status": "skipped",
                "plan": {},
                "cookies": captured.get("web_cookies") or [],
                "metadata": {
                    "attempted": False,
                    "status": "skipped",
                    "reason": "disabled",
                    "http_client_reused": False,
                },
            }
        captured["bootstrap"] = bootstrap.get("metadata") or {
            "attempted": False,
            "status": bootstrap.get("status") or "unknown",
        }
        captured["initial_plan"] = dict(bootstrap.get("plan") or {})
        captured["web_cookies"] = _merge_cookie_snapshots(
            captured.get("web_cookies") or [],
            bootstrap.get("cookies") or [],
        )
        logger.info(
            "[Bootstrap][OAuth] 资格上下文 status=%s plan=%s plus_trial=%s cookies=%s",
            captured["bootstrap"].get("status") or "unknown",
            captured["initial_plan"].get("current_plan_type") or "unknown",
            bool(captured["initial_plan"].get("plus_trial_eligible")),
            len(captured["web_cookies"]),
        )

    platform_result = await register_via_platform_passwordless(
        email=email,
        proxy=proxy,
        otp_fetcher=otp_fetcher,
        first_name=first_name,
        last_name=last_name,
        birthday=birthday,
        log=logger.info,
        profile=profile,
        post_token_hook=web_at_hook,
    )
    web = captured.get("web")
    if web is None or not str(getattr(web, "access_token", "") or ""):
        raise RuntimeError("Platform OAuth 注册完成，但未取得 ChatGPT Web AT")
    return {
        "web": web,
        "platform": captured.get("platform") or {},
        "device_id": str(getattr(web, "device_id", "") or platform_result.device_id),
        "web_cookies": captured.get("web_cookies") or [],
        "initial_plan_result": captured.get("initial_plan") or {},
        "bootstrap": captured.get("bootstrap") or {},
        "browser_profile": _profile_browser_environment(profile),
    }


def run_platform_oauth_registration(
    *,
    email: str,
    name: str,
    birthday: str,
    proxy: str | None = None,
    otp_code: str | None = None,
    batch_dir=None,
    codex_oauth: bool | None = None,
) -> dict:
    """同步入口，供现有注册线程分派 `protocol_mode=oauth`。"""
    if proxy is None:
        from config.proxy import pick_proxy

        proxy = pick_proxy()

    # OAuth v2 客户端不额外做 GeoIP 请求；相同代理端点仍会共用一个节流键。
    lease = acquire_protocol_exit_lease(
        SimpleNamespace(exit_geo={}, proxy=proxy)
    )
    try:
        result = asyncio.run(_register_and_get_web_at(
            email=email,
            name=name,
            birthday=birthday,
            proxy=proxy,
            otp_fetcher=_CurrentOtpFetcher(initial_code=str(otp_code or "").strip()),
        ))
    finally:
        lease.release()

    web = result["web"]
    codex_result = {"status": "skipped", "ok": False, "message": "未选择接码"}
    if bool(codex_oauth):
        try:
            from core.codex_oauth import run_codex_oauth

            codex_result = run_codex_oauth(email, force=True)
        except Exception as exc:
            codex_result = {
                "status": "failed",
                "ok": False,
                "message": f"{type(exc).__name__}: {str(exc)[:180]}",
            }

    account_id = save_account_data(
        email=email,
        access_token=web.access_token,
        totp_secret=None,
        email_source=resolve_email_source(email),
        proxy_used=proxy,
        batch_dir=batch_dir,
        web_cookies=result.get("web_cookies") or [],
        web_cookie_source="protocol_oauth",
        initial_plan_result=(
            result.get("initial_plan_result")
            if isinstance(result.get("initial_plan_result"), dict)
            else None
        ),
        extra={
            "user": getattr(web, "user", None),
            "account": getattr(web, "account", None),
            "device_id": result["device_id"],
            "browser_profile": result.get("browser_profile") or None,
            "initial_accounts_check": result.get("initial_plan_result") or None,
            "oauth_bootstrap": result.get("bootstrap") or None,
            "protocol_mode": "oauth",
            "token_source": "chatgpt_web_after_platform_passwordless",
            "platform_oauth": result["platform"],
            "codex": codex_result,
        },
    )

    flow_result = {"status": "skipped", "ok": False, "message": "未触发"}
    try:
        from core.flow_trigger import trigger_flow

        flow_result = trigger_flow(web.access_token)
    except Exception as exc:
        flow_result = {
            "status": "failed",
            "ok": False,
            "message": f"{type(exc).__name__}: {exc}",
        }

    logger.info("[完成][OAuth] %s，账号ID=%s，Web AT=%s...", email, account_id, web.access_token[:16])
    plan_result = (
        result.get("initial_plan_result")
        if isinstance(result.get("initial_plan_result"), dict)
        else {}
    )
    trial_status = str(plan_result.get("plus_trial_status") or "unknown").strip().lower()
    return {
        "success": True,
        "email": email,
        "account_id": account_id,
        "access_token": web.access_token,
        "totp_secret": None,
        "flow": flow_result,
        "codex": codex_result,
        "protocol_mode": "oauth",
        "trial_eligibility": {
            "status": trial_status or "unknown",
            "eligible": (
                bool(plan_result.get("plus_trial_eligible"))
                if isinstance(plan_result, dict) and plan_result
                else None
            ),
            "campaign_id": str(plan_result.get("plus_trial_campaign_id") or "") or None,
            "source": "registration_session" if plan_result else "background_pending",
        },
        "error": None,
    }
