# -*- coding: utf-8 -*-
"""通过 RoxyBrowser 指纹浏览器 + Selenium 执行 ChatGPT 注册。"""
from __future__ import annotations

import logging
import random
import string
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from config import roxybrowser as _cfg
from config import twofa as _twofa_cfg  # noqa: F401 - compatibility for driver tests
from core.account_cookie_store import capture_selenium_cookies
from core.account_export import save_account_data
from core.chatgpt_plan import token_claims
from core.email_provider import wait_for_otp, resolve_email_source
from core.humanize import delay as human_delay
from core.roxy_retry_policy import classify_roxy_failure, retry_delay_seconds
from core.roxybrowser_client import (
    RoxyBrowserClient,
    RoxyOpenResult,
    build_roxy_driver,
    configure_roxy_low_traffic_cdp,
)

logger = logging.getLogger(__name__)

_CHATGPT_LOGIN_URL = "https://chatgpt.com/auth/login"
_PASSWORD_SIGNUP_URL = "https://auth.openai.com/create-account/password"

_ROXY_RUN_LIMIT = max(1, int(getattr(_cfg, "ROXY_MAX_CONCURRENT_RUNS", 200) or 200))
_ROXY_RUN_SLOTS = threading.BoundedSemaphore(_ROXY_RUN_LIMIT)
_ROXY_TRAFFIC_HEARTBEAT_SECONDS = 5.0
_ACCESS_TOKEN_PROBE_MIN_INTERVAL_SECONDS = 2.0
_EMAIL_SECOND_STAGE_STABLE_SECONDS = 10.0


class SessionIdentityError(RuntimeError):
    """The browser session belongs to a different or unverifiable account."""


class RegistrationPasswordRequiredError(RuntimeError):
    """The signup session could not confirm a remotely accepted password."""


class ChatGPTAccountMissingError(RuntimeError):
    """The profile submission was accepted by the UI but rejected by ChatGPT."""


class RegistrationAccountExistsError(RuntimeError):
    """The server reports an existing account instead of completing signup."""


class BrowserSessionLostError(RuntimeError):
    """The Roxy/Chrome WebDriver session disappeared during registration."""

_PAGE_LOAD_TIMEOUT_MARKERS = (
    "timed out receiving message from renderer",
    "page load timed out",
    "timeout: timed out receiving message from renderer",
)

_BROWSER_NETWORK_ERROR_MARKERS = (
    "chrome-error://",
    "err_socks_connection_failed",
    "err_proxy_connection_failed",
    "err_ssl_protocol_error",
    "err_tunnel_connection_failed",
    "err_connection_closed",
    "err_connection_reset",
    "err_connection_refused",
    "this site can’t be reached",
    "this site can't be reached",
    "proxy connection failed",
    "无法访问此网站",
    "このサイトにアクセスできません",
)

_DRIVER_SESSION_LOST_MARKERS = (
    "invalid session id",
    "session deleted as the browser has closed the connection",
    "disconnected: not connected to devtools",
    "target window already closed",
    "no such window",
)

_CHATGPT_ACCOUNT_MISSING_MARKERS = (
    "chatgpt_account_missing",
    "no eligible chatgpt account found",
)


def _is_driver_session_lost_error(error: object) -> bool:
    text = f"{type(error).__name__}: {error}".lower()
    return any(marker in text for marker in _DRIVER_SESSION_LOST_MARKERS)


def _raise_for_driver_session_lost(state: dict | None, *, stage: str) -> None:
    error = str((state or {}).get("error") or "")
    if error and _is_driver_session_lost_error(error):
        raise BrowserSessionLostError(
            f"{stage}期间 Roxy/Chrome 会话已丢失: {error}"
        )


def _is_chatgpt_account_missing_state(state: dict | None) -> bool:
    snapshot = state or {}
    content = " ".join(
        str(snapshot.get(key) or "")
        for key in ("title", "text", "error")
    ).lower()
    errors = " ".join(str(item or "") for item in (snapshot.get("errors") or [])).lower()
    content = f"{content} {errors}"
    return any(marker in content for marker in _CHATGPT_ACCOUNT_MISSING_MARKERS)


def _raise_for_chatgpt_account_missing(state: dict | None) -> None:
    if _is_chatgpt_account_missing_state(state):
        raise ChatGPTAccountMissingError(
            "About you 提交后服务端拒绝创建账号: "
            "chatgpt_account_missing (No eligible ChatGPT account found)"
        )


def _raise_for_registration_account_exists(state: dict | None) -> None:
    snapshot = state or {}
    content = " ".join(
        str(snapshot.get(key) or "") for key in ("title", "text", "error")
    ).lower()
    content += " " + " ".join(
        str(item or "") for item in (snapshot.get("errors") or [])
    ).lower()
    if (
        "user_already_exists" in content
        or "an account already exists for this email address or phone number" in content
    ):
        raise RegistrationAccountExistsError(
            "服务端返回 user_already_exists：该邮箱或手机号已有关联账号；"
            "本次注册未确认成功，需核对已有账号状态"
        )


def _log_prefix(driver=None) -> str:
    """按当前浏览器实现返回注册日志前缀。

    CloakBrowser 复用 Roxy 的页面操作函数；这些共享函数必须跟随实际 driver
    输出 `[Cloak注册]`，避免 Cloak 流程里混入 `[Roxy注册]` 日志。
    """
    try:
        explicit = str(getattr(driver, "_registration_log_prefix", "") or "").strip()
        if explicit:
            return explicit
        if driver is not None and driver.__class__.__name__ == "CloakSeleniumDriver":
            return "[Cloak注册]"
    except Exception:
        pass
    return "[Roxy注册]"


def _browser_network_error_reason(driver, state: dict | None = None) -> str:
    snapshot = state or {}
    values = [
        snapshot.get("url"),
        snapshot.get("title"),
        snapshot.get("text"),
        snapshot.get("error"),
    ]
    try:
        values.append(driver.current_url)
    except Exception as exc:
        values.append(f"{type(exc).__name__}: {exc}")
    try:
        values.append(driver.title)
    except Exception:
        pass
    content = " ".join(str(value or "") for value in values).lower()
    return next((marker for marker in _BROWSER_NETWORK_ERROR_MARKERS if marker in content), "")


def _raise_for_browser_network_error(driver, state: dict | None = None) -> None:
    reason = _browser_network_error_reason(driver, state)
    if reason:
        url = str((state or {}).get("url") or getattr(driver, "current_url", "") or "")
        raise RuntimeError(f"浏览器网络错误页: marker={reason} url={url[:240]}")


def _navigation_page_state(driver) -> dict:
    """读取超时后的最小页面状态，判断 DOM 是否已经足够继续注册。"""
    try:
        return driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
        return {
          url: location.href,
          title: document.title || '',
          readyState: document.readyState || '',
          bodyTextLength: (document.body?.innerText || '').trim().length,
          visibleInputs: [...document.querySelectorAll('input')].filter(visible).length,
          visibleActions: [...document.querySelectorAll('button,a,[role=button]')].filter(visible).length,
        };
        """) or {}
    except Exception as exc:
        try:
            current_url = str(driver.current_url or "")
        except Exception:
            current_url = ""
        return {"url": current_url, "error": f"{type(exc).__name__}: {exc}"}


def _is_usable_navigation_state(state: dict, requested_url: str) -> bool:
    """只接受已到 OpenAI/ChatGPT 且 DOM 可交互的页面，不能吞掉真实导航失败。"""
    actual = urlparse(str((state or {}).get("url") or ""))
    requested = urlparse(str(requested_url or ""))
    allowed_hosts = {"chatgpt.com", "auth.openai.com"}
    actual_host = str(actual.hostname or "").lower()
    requested_host = str(requested.hostname or "").lower()
    if actual_host not in allowed_hosts:
        return False
    if requested_host not in allowed_hosts:
        return actual_host == requested_host
    ready = str((state or {}).get("readyState") or "").lower()
    if ready not in {"interactive", "complete"}:
        return False
    visible_inputs = int((state or {}).get("visibleInputs") or 0)
    if str(requested.path or "").startswith("/api/"):
        return int((state or {}).get("bodyTextLength") or 0) > 0
    actual_path = str(actual.path or "").lower()
    body_ready = int((state or {}).get("bodyTextLength") or 0) > 0
    if actual_host == "chatgpt.com" and not actual_path.startswith("/auth/login"):
        return body_ready
    if actual_host == "auth.openai.com" and any(
        marker in actual_path for marker in ("/oauth/callback", "/callback")
    ):
        return body_ready
    # OpenAI 域名上的 Cloudflare/通用错误页也可能带可点击按钮。只有出现
    # 认证流程输入控件时才把 renderer timeout 当成“尾部资源未结束”。
    return visible_inputs > 0


def _navigate_page(driver, url: str, *, timeout: int | None = None) -> dict:
    """导航页面；renderer 仅剩资源未完成时停止加载并沿用当前 DOM。"""
    default_timeout = int(getattr(_cfg, "ROXY_PAGE_LOAD_TIMEOUT", 35) or 35)
    if driver.__class__.__name__ in {"CloakSeleniumDriver", "LocalBrowserDriver"}:
        adapter_timeout_ms = int(getattr(driver, "_page_load_timeout_ms", 0) or 0)
        if adapter_timeout_ms > 0:
            default_timeout = max(5, adapter_timeout_ms // 1000)
    page_timeout = max(
        5,
        int(timeout or default_timeout),
    )
    driver.set_page_load_timeout(page_timeout)
    try:
        driver.get(url)
    except Exception as exc:
        error_text = f"{type(exc).__name__}: {exc}".lower()
        if not any(marker in error_text for marker in _PAGE_LOAD_TIMEOUT_MARKERS):
            raise
        state = _navigation_page_state(driver)
        _raise_for_browser_network_error(driver, state)
        if not _is_usable_navigation_state(state, url):
            raise
        try:
            driver.execute_script("window.stop();")
        except Exception:
            logger.debug("%s renderer 超时后停止剩余资源失败", _log_prefix(driver), exc_info=True)
        logger.warning(
            "%s 页面加载超时但 DOM 已可用，停止剩余资源后继续：timeout=%ss state=%s",
            _log_prefix(driver), page_timeout, state,
        )
        return state
    state = _navigation_page_state(driver)
    _raise_for_browser_network_error(driver, state)
    return state


def _build_driver(opened: RoxyOpenResult):
    """连接 Roxy，并统一应用所有 Roxy 页面会话需要的初始化。"""
    driver = build_roxy_driver(opened)
    _apply_browser_automation_mask(driver)
    configure_roxy_low_traffic_cdp(driver)
    return driver


def _center_browser_window(driver) -> None:
    """把有头窗口移出工作区；未启用时仅在 Windows 上居中。"""
    if bool(getattr(_cfg, "ROXY_OPEN_HEADLESS", False)):
        return
    if bool(getattr(_cfg, "ROXY_WINDOW_OFFSCREEN", False)):
        try:
            offscreen_x = max(
                10000,
                int(getattr(_cfg, "ROXY_WINDOW_OFFSCREEN_X", 30000) or 30000),
            )
            driver.set_window_size(1280, 900)
            driver.set_window_position(offscreen_x, 0)
            logger.info(
                "[Roxy] 有头浏览器窗口已移出工作区：x=%s，不抢占前台",
                offscreen_x,
            )
            return
        except Exception as exc:
            logger.warning("[Roxy] 浏览器窗口移出工作区失败，继续执行：%s", exc)
    try:
        import platform

        if platform.system().lower() != "windows":
            return
        import ctypes

        class _Rect(ctypes.Structure):
            _fields_ = [
                ("left", ctypes.c_long),
                ("top", ctypes.c_long),
                ("right", ctypes.c_long),
                ("bottom", ctypes.c_long),
            ]

        work_area = _Rect()
        if not ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(work_area), 0):
            raise OSError("无法读取 Windows 工作区")
        size = driver.get_window_size()
        width = max(1, int(size.get("width") or 1))
        height = max(1, int(size.get("height") or 1))
        x = int(work_area.left + max(0, (work_area.right - work_area.left - width) // 2))
        y = int(work_area.top + max(0, (work_area.bottom - work_area.top - height) // 2))
        driver.set_window_position(x, y)
        logger.info("[Roxy] 浏览器窗口已居中：x=%s y=%s width=%s height=%s", x, y, width, height)
    except Exception as exc:
        logger.warning("[Roxy] 浏览器窗口居中失败，继续执行：%s", exc)


def _wait(driver, timeout: int | None = None):
    from selenium.webdriver.support.ui import WebDriverWait
    return WebDriverWait(driver, timeout or int(_cfg.ROXY_SELENIUM_TIMEOUT))


def _visible(el) -> bool:
    try:
        return el.is_displayed() and el.is_enabled()
    except Exception:
        return False


def _browser_actions_enabled() -> bool:
    try:
        from config import humanize as _humanize_cfg

        return bool(getattr(_humanize_cfg, "ENABLE_HUMANIZE_BROWSER_ACTIONS", True))
    except Exception:
        return True


def _apply_browser_automation_mask(driver) -> bool:
    """尽量弱化 Selenium 的明显标记；不支持 CDP 时不影响注册。"""
    if not _browser_actions_enabled():
        return False
    script = r"""
    try {
      Object.defineProperty(Navigator.prototype, 'webdriver', {
        configurable: true,
        get: () => undefined
      });
    } catch (_) {}
    if (!window.chrome) window.chrome = {};
    if (!window.chrome.runtime) window.chrome.runtime = {};
    try {
      const permissions = window.navigator && window.navigator.permissions;
      const originalQuery = permissions && permissions.query;
      if (originalQuery && !permissions.__roxyWrapped) {
        permissions.query = function(parameters) {
          if (parameters && parameters.name === 'notifications') {
            return Promise.resolve({state: Notification.permission});
          }
          return originalQuery.call(this, parameters);
        };
        Object.defineProperty(permissions, '__roxyWrapped', {value: true});
      }
    } catch (_) {}
    """
    installed = False
    try:
        execute_cdp = getattr(driver, "execute_cdp_cmd", None)
        if callable(execute_cdp):
            execute_cdp("Page.addScriptToEvaluateOnNewDocument", {"source": script})
            installed = True
    except Exception as exc:
        logger.debug("%s 注入新页面自动化特征处理脚本失败：%s", _log_prefix(driver), exc)
    try:
        driver.execute_script(script)
        installed = True
    except Exception as exc:
        logger.debug("%s 当前页面自动化特征处理失败：%s", _log_prefix(driver), exc)
    if installed:
        logger.info("%s 已应用浏览器自动化特征处理", _log_prefix(driver))
    return installed


def _human_scroll_to(driver, el) -> None:
    try:
        block = random.choice(("center", "nearest", "center"))
        driver.execute_script(
            "arguments[0].scrollIntoView({block: arguments[1], inline:'nearest'});",
            el,
            block,
        )
        if _browser_actions_enabled():
            _sleep_with_manual_stop(random.uniform(0.08, 0.35))
            driver.execute_script("window.scrollBy(0, arguments[0]);", random.randint(-90, 90))
            _sleep_with_manual_stop(random.uniform(0.05, 0.22))
            driver.execute_script(
                "arguments[0].scrollIntoView({block:'center', inline:'nearest'});",
                el,
            )
    except Exception:
        try:
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
        except Exception:
            pass


def _human_click(driver, el, *, label: str = "", retry_ambiguous: bool = True) -> None:
    """在元素范围内选取随机坐标点击，CDP 不可用时回退页面事件。"""
    _human_scroll_to(driver, el)
    if not _browser_actions_enabled():
        _sleep_with_manual_stop(0.2)
        el.click()
        return
    execute_cdp = None
    cdp_pressed = False
    release_payload = None
    click_attempted = False
    try:
        human_delay("click")
        point = driver.execute_script(r"""
        const rect = arguments[0].getBoundingClientRect();
        return {
          x: rect.left + rect.width * (0.30 + Math.random() * 0.40),
          y: rect.top + rect.height * (0.35 + Math.random() * 0.30)
        };
        """, el) or {}
        x = float(point.get("x") or 0)
        y = float(point.get("y") or 0)
        execute_cdp = getattr(driver, "execute_cdp_cmd", None)
        if callable(execute_cdp) and x > 0 and y > 0:
            release_payload = {
                "type": "mouseReleased", "x": x, "y": y,
                "button": "left", "clickCount": 1,
            }
            move_result = execute_cdp("Input.dispatchMouseEvent", {
                "type": "mouseMoved", "x": x, "y": y,
            })
            if move_result is None:
                raise RuntimeError("CDP mouseMoved 未确认执行")
            _sleep_with_manual_stop(random.uniform(0.05, 0.22))
            if not retry_ambiguous:
                # 即使按下事件的响应丢失，也只能补一次释放，不能再回退点击。
                cdp_pressed = True
            press_result = execute_cdp("Input.dispatchMouseEvent", {
                "type": "mousePressed", "x": x, "y": y,
                "button": "left", "clickCount": 1,
            })
            if press_result is None:
                raise RuntimeError("CDP mousePressed 未确认执行")
            cdp_pressed = True
            _sleep_with_manual_stop(random.uniform(0.035, 0.13))
            click_attempted = True
            release_result = execute_cdp("Input.dispatchMouseEvent", release_payload)
            if release_result is None:
                raise RuntimeError("CDP mouseReleased 未确认执行")
            cdp_pressed = False
            return
        click_attempted = True
        driver.execute_script(r"""
        const el = arguments[0];
        el.dispatchEvent(new PointerEvent('pointerdown', {
          bubbles:true, cancelable:true, pointerType:'mouse'
        }));
        el.dispatchEvent(new MouseEvent('mousedown', {bubbles:true, cancelable:true, view:window}));
        el.dispatchEvent(new MouseEvent('mouseup', {bubbles:true, cancelable:true, view:window}));
        el.click();
        """, el)
    except Exception as exc:
        _check_manual_stop()
        if (
            cdp_pressed and callable(execute_cdp) and release_payload is not None
            and (retry_ambiguous or not click_attempted)
        ):
            click_attempted = True
            try:
                execute_cdp("Input.dispatchMouseEvent", release_payload)
            except Exception:
                logger.debug("%s CDP 鼠标释放补偿失败", _log_prefix(driver), exc_info=True)
        if click_attempted and not retry_ambiguous:
            raise RuntimeError(
                f"点击结果未确认，停止重复点击并等待页面状态: label={label} error={type(exc).__name__}"
            ) from exc
        logger.debug(
            "%s 人工化点击失败，回退原生点击：label=%s error=%s",
            _log_prefix(driver), label, exc,
        )
        _sleep_with_manual_stop(random.uniform(0.12, 0.45))
        try:
            driver.execute_script("arguments[0].click();", el)
        except Exception:
            if not retry_ambiguous:
                raise
            el.click()


def _human_type_text(driver, el, value: str, *, clear: bool = True) -> None:
    """按字符或短分组输入并触发键盘事件；异常时回退 React setter。"""
    if not _browser_actions_enabled():
        if clear:
            try:
                el.clear()
            except Exception:
                pass
        el.send_keys(value)
        return
    try:
        _human_scroll_to(driver, el)
        try:
            _human_click(driver, el, label="input_focus")
        except Exception:
            driver.execute_script("arguments[0].focus();", el)
        if clear:
            from selenium.webdriver.common.keys import Keys
            import platform

            modifier = Keys.COMMAND if platform.system().lower() == "darwin" else Keys.CONTROL
            try:
                el.send_keys(modifier, "a")
                _sleep_with_manual_stop(random.uniform(0.04, 0.16))
                el.send_keys(Keys.BACKSPACE)
            except Exception:
                try:
                    el.clear()
                except Exception:
                    pass
        text = str(value)
        index = 0
        while index < len(text):
            step = 2 if random.random() < 0.12 and index + 1 < len(text) else 1
            el.send_keys(text[index:index + step])
            index += step
            human_delay("keystroke")
            if index < len(text) and random.random() < 0.08:
                human_delay("typing_pause")
        driver.execute_script(
            "arguments[0].dispatchEvent(new Event('input', {bubbles:true}));"
            "arguments[0].dispatchEvent(new Event('change', {bubbles:true}));",
            el,
        )
    except Exception as exc:
        logger.debug("%s 人工化输入失败，回退受控值写入：%s", _log_prefix(driver), exc)
        _set_element_value(driver, el, value)


def _page_warmup(driver, *, reason: str = "") -> None:
    """仅在当前页面做短暂停留和指针移动，不产生额外导航。"""
    if not _browser_actions_enabled():
        return
    try:
        human_delay("page_warmup")
        execute_cdp = getattr(driver, "execute_cdp_cmd", None)
        if callable(execute_cdp):
            execute_cdp("Input.dispatchMouseEvent", {
                "type": "mouseMoved",
                "x": random.randint(80, 360),
                "y": random.randint(80, 260),
            })
        logger.debug("%s 页面短预热完成：%s", _log_prefix(driver), reason or "-")
    except Exception:
        logger.debug("%s 页面短预热失败", _log_prefix(driver), exc_info=True)


def _find_any(driver, selectors: list[str], timeout: int | None = None):
    from selenium.webdriver.common.by import By

    end = time.time() + (timeout or int(_cfg.ROXY_SELENIUM_TIMEOUT))
    last = None
    while time.time() < end:
        _check_manual_stop()
        _raise_for_browser_network_error(driver)
        for selector in selectors:
            try:
                by = By.XPATH if selector.startswith("//") else By.CSS_SELECTOR
                items = driver.find_elements(by, selector)
                for item in items:
                    if _visible(item):
                        return item
            except Exception as exc:
                last = exc
        _sleep_with_manual_stop(0.4)
    raise RuntimeError(f"找不到页面元素: {selectors}; last={last}")


def _click_any(driver, selectors: list[str], timeout: int | None = None) -> None:
    el = _find_any(driver, selectors, timeout)
    _human_click(driver, el, label="click_any")


def _type_any(driver, selectors: list[str], value: str, timeout: int | None = None, clear: bool = True) -> None:
    el = _find_any(driver, selectors, timeout)
    _human_type_text(driver, el, value, clear=clear)


_EMAIL_INPUT_SELECTORS = [
    "input[type='email']",
    "input[name='email']",
    "input[name='username']",
    "input#email-input",
    "input[autocomplete='email']",
]


def _email_entry_state(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled;
        const attrText = el => [
          el.id, el.getAttribute('name'), el.getAttribute('type'), el.getAttribute('autocomplete'),
          el.getAttribute('data-testid'), el.getAttribute('data-test-id'), el.getAttribute('data-provider'),
          el.getAttribute('data-auth-provider'), el.getAttribute('href'), el.getAttribute('action'),
          el.getAttribute('formaction'), el.getAttribute('value')
        ].filter(Boolean).join(' ').toLowerCase();
        const inputs = [...document.querySelectorAll('input')].filter(visible).map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          autocomplete: el.getAttribute('autocomplete') || '', value: el.value || ''
        })).slice(0, 30);
        const actions = [...document.querySelectorAll('button,a,[role=button],input[type=button],input[type=submit]')]
          .filter(visible).map(el => ({tag: el.tagName, type: el.getAttribute('type') || '', attrs: attrText(el)})).slice(0, 40);
        return {url: location.href, title: document.title, inputs, actions};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, "current_url", ""), "error": f"{type(exc).__name__}: {exc}"}


def _find_visible_email_input_js(driver):
    return driver.execute_script(r"""
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && !el.readOnly;
    const selectors = [
      'input[type="email"]',
      'input[name="email"]',
      'input[name="username"]',
      'input#email-input',
      'input[autocomplete="email"]'
    ];
    for (const sel of selectors) {
      const el = [...document.querySelectorAll(sel)].find(visible);
      if (el) return el;
    }
    return null;
    """)


def _is_oauth_consent_like(driver) -> bool:
    """检测是否已到 OAuth 授权/consent 页。这里不能再点任何邮箱分支或全局提交按钮。"""
    try:
        return bool(driver.execute_script(r"""
        const url = String(location.href || '').toLowerCase();
        if (/oauth|authorize|consent/.test(url) && !/login|signup|identifier|email-verification/.test(url)) return true;
        const formsWithEmail = [...document.querySelectorAll('form')]
          .some(form => form.querySelector('input[type="email"],input[name="email"],input[name="username"],input[autocomplete="email"]'));
        if (formsWithEmail) return false;
        const actions = [...document.querySelectorAll('button,a,[role="button"],input[type="submit"],input[type="button"]')]
          .map(el => [el.id, el.name, el.type, el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
            el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.getAttribute('href'),
            el.getAttribute('formaction'), el.value, el.className].filter(Boolean).join(' ').toLowerCase())
          .join(' ');
        return /oauth|authorize|consent|grant|allow/.test(actions) && !/email|username/.test(actions);
        """))
    except Exception:
        return False


def _is_external_idp_url(url: str) -> bool:
    u = str(url or '').lower()
    return any(x in u for x in (
        'accounts.google.', 'google.com/o/oauth', 'appleid.apple.', 'login.microsoftonline.',
        'login.live.', 'github.com/login/oauth', 'facebook.com/', 'saml', 'sso'
    ))


def _assert_not_external_idp(driver, label: str = '') -> None:
    try:
        current = str(driver.current_url or '')
    except Exception:
        current = ''
    if _is_external_idp_url(current):
        raise RuntimeError(f"误入第三方账号授权页（{label}）：{current}")


def _click_email_entry_option(driver) -> bool:
    """点击“邮箱方式”入口；只看 DOM 技术属性，不看按钮可见文案，并显式排除 Google 等第三方。"""
    if _is_oauth_consent_like(driver):
        logger.info("%s 当前疑似 OAuth 授权页，跳过邮箱入口兜底点击", _log_prefix(driver))
        return False
    target = driver.execute_script(r"""
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
    const attrText = el => {
      const own = [
        el.id, el.getAttribute('name'), el.getAttribute('type'), el.getAttribute('autocomplete'),
        el.getAttribute('data-testid'), el.getAttribute('data-test-id'), el.getAttribute('data-provider'),
        el.getAttribute('data-auth-provider'), el.getAttribute('data-idp'), el.getAttribute('href'), el.getAttribute('action'),
        el.getAttribute('formaction'), el.getAttribute('value'), el.getAttribute('aria-label'), el.className
      ].filter(Boolean).join(' ');
      const desc = [...el.querySelectorAll('img,svg,use,[aria-label],[data-provider],[data-testid],[data-test-id]')]
        .map(x => [x.getAttribute('alt'), x.getAttribute('src'), x.getAttribute('href'), x.getAttribute('xlink:href'),
          x.getAttribute('aria-label'), x.getAttribute('data-provider'), x.getAttribute('data-testid'), x.getAttribute('data-test-id'), x.className]
          .filter(Boolean).join(' ')).join(' ');
      return `${own} ${desc}`.toLowerCase();
    };
    const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|provider|authorize|consent|grant|allow/;
    const good = /(^|[^a-z])(email|mail|username|passwordless|otp|magic)([^a-z]|$)/;
    const candidates = [...document.querySelectorAll('button,a,[role="button"],input[type="button"],input[type="submit"]')]
      .filter(visible)
      .map(el => ({el, attrs: attrText(el), hasLogo: !!el.querySelector('img,svg,use')}))
      .filter(x => good.test(x.attrs) && !bad.test(x.attrs) && !x.hasLogo);
    if (candidates.length !== 1) return null;
    candidates[0].el.scrollIntoView({block:'center'});
    return candidates[0].el;
    """)
    if not target:
        return False
    _human_click(driver, target, label="email_entry")
    return True


def _type_email_address(driver, email: str, timeout: int | None = None) -> None:
    """进入邮箱登录/注册方式并填写邮箱。全程不依赖页面可见文字，避免非日本出口本地化后误点 Google。"""
    end = time.time() + (timeout or int(_cfg.ROXY_SELENIUM_TIMEOUT))
    last_state = None
    clicked_email_option = False
    while time.time() < end:
        _check_manual_stop()
        el = _find_visible_email_input_js(driver)
        if el:
            _human_type_text(driver, el, email, clear=True)
            return
        last_state = _email_entry_state(driver)
        if not clicked_email_option and _click_email_entry_option(driver):
            clicked_email_option = True
            _sleep_with_manual_stop(1.0)
            _assert_not_external_idp(driver, "点击邮箱入口后")
            continue
        _sleep_with_manual_stop(0.4)
    raise RuntimeError(f"找不到邮箱输入框/邮箱入口（未使用文字识别），state={last_state}")


def _submit_nearest_form_for_active_input(driver) -> bool:
    if _is_oauth_consent_like(driver):
        logger.info("%s 当前疑似 OAuth 授权页，禁止执行邮箱提交", _log_prefix(driver))
        return False
    target = driver.execute_script(r"""
    window.__roxy_email_submit_debug = {ok:false, reason:'not_started'};
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
    const input = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete="email"]')]
      .find(visible);
    if (!input) {
      window.__roxy_email_submit_debug = {ok:false, reason:'missing_email_input'};
      return null;
    }
    const value = String(input.value || '').trim();
    if (!value || !value.includes('@')) {
      window.__roxy_email_submit_debug = {ok:false, reason:'email_value_not_ready', value};
      return null;
    }
    const form = input.closest('form');
    if (!form) {
      window.__roxy_email_submit_debug = {ok:false, reason:'missing_form'};
      return null;
    }

    const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|sso|saml|idp|provider|authorize|consent|grant|allow/;
    const attrText = el => {
      const own = [el.id, el.name, el.type, el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
        el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'), el.getAttribute('data-idp'),
        el.getAttribute('aria-label'), el.getAttribute('href'), el.getAttribute('formaction'), el.value, el.className]
        .filter(Boolean).join(' ');
      const desc = [...el.querySelectorAll('img,svg,use,[aria-label],[data-provider],[data-testid],[data-test-id]')]
        .map(x => [x.getAttribute('alt'), x.getAttribute('src'), x.getAttribute('href'), x.getAttribute('xlink:href'),
          x.getAttribute('aria-label'), x.getAttribute('data-provider'), x.getAttribute('data-testid'), x.getAttribute('data-test-id'), x.className]
          .filter(Boolean).join(' '))
        .join(' ');
      return `${own} ${desc}`.toLowerCase();
    };
    const inputRect = input.getBoundingClientRect();
    const formId = form.getAttribute('id') || '';
    const scopedButtons = [
      ...form.querySelectorAll('button,input[type="submit"]'),
      ...(formId ? [...document.querySelectorAll(`button[form="${CSS.escape(formId)}"],input[type="submit"][form="${CSS.escape(formId)}"]`)] : [])
    ].filter((el, idx, arr) => arr.indexOf(el) === idx);
    const rawButtons = scopedButtons
      .filter(visible)
      .map((el, idx) => {
        const r = el.getBoundingClientRect();
        const attrs = attrText(el);
        const hasLogo = !!el.querySelector('img,svg,use');
        const isBad = bad.test(attrs) || hasLogo;
        const belowInput = r.top >= inputRect.bottom - 10;
        const distance = Math.max(0, r.top - inputRect.bottom) + Math.abs((r.left + r.right) / 2 - (inputRect.left + inputRect.right) / 2) / 10;
        const cls = String(el.className || '').toLowerCase();
        const type = String(el.getAttribute('type') || '').toLowerCase();
        // ChatGPT 新版邮箱页的主按钮形如：
        // <button class="... btn-primary ... w-full ..." type="submit"><div>続行</div></button>
        // 优先选择同 form 下的 primary submit，而不是因为多个按钮距离接近误判歧义。
        const isPrimarySubmit = (el.tagName === 'BUTTON' || el.tagName === 'INPUT') && type === 'submit'
          && (/\bbtn-primary\b/.test(cls) || /\b_primary_/.test(cls) || /\bw-full\b/.test(cls));
        const score = (isPrimarySubmit ? 1000 : 0) + (type === 'submit' ? 100 : 0) - distance;
        return {el, idx, attrs, isBad, hasLogo, belowInput, distance, score, isPrimarySubmit, tag: el.tagName, type};
      });
    const safe = rawButtons.filter(x => !x.isBad && x.belowInput)
      .sort((a,b) => b.score - a.score || a.distance - b.distance || a.idx - b.idx);
    if (!safe.length) {
      window.__roxy_email_submit_debug = {ok:false, reason:'no_safe_submit', buttons: rawButtons.map(x => ({idx:x.idx, isBad:x.isBad, hasLogo:x.hasLogo, belowInput:x.belowInput, primary:x.isPrimarySubmit, attrs:x.attrs.slice(0,160), type:x.type}))};
      return null;
    }
    // 多个安全按钮时，若没有明确 primary submit，且距离接近，才认为页面歧义。
    if (!safe[0].isPrimarySubmit && safe.length > 1 && Math.abs(safe[0].distance - safe[1].distance) < 8) {
      window.__roxy_email_submit_debug = {ok:false, reason:'ambiguous_submit', buttons: safe.slice(0,3).map(x => ({idx:x.idx, distance:x.distance, score:x.score, primary:x.isPrimarySubmit, attrs:x.attrs.slice(0,160), type:x.type}))};
      return null;
    }
    const target = safe[0].el;
    target.scrollIntoView({block:'center'});
    window.__roxy_email_submit_debug = {
      ok:true,
      reason:safe[0].isPrimarySubmit ? 'primary_submit' : 'safe_submit',
      at:Date.now(),
      targetAttrs:safe[0].attrs.slice(0,160),
      buttonCount:rawButtons.length,
      primary:safe[0].isPrimarySubmit
    };
    return target;
    """)
    detail = driver.execute_script(
        "return window.__roxy_email_submit_debug || {ok:false, reason:'missing_debug'};"
    ) or {"ok": False, "reason": "missing_debug"}
    if target is not None:
        _human_click(driver, target, label="email_submit")
        logger.info("%s 邮箱表单安全提交：%s", _log_prefix(driver), detail)
        _sleep_with_manual_stop(0.8)
        _assert_not_external_idp(driver, "提交邮箱后")
        return True
    logger.warning("%s 未执行邮箱提交：%s", _log_prefix(driver), detail)
    return False


def _current_email_input_value(driver) -> str:
    try:
        state = _email_input_value_state(driver)
        for item in state.get("inputs") or []:
            value = str(item.get("value") or "").strip()
            if "@" in value:
                return value
    except Exception:
        pass
    return ""


def _stabilize_email_input_before_submit(driver, email: str) -> dict:
    """提交前统一 DOM value、React 受控状态以及 blur/change 校验状态。"""
    try:
        return driver.execute_script(r"""
        const email = String(arguments[0] || '').trim();
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]')]
          .find(visible);
        if (!input) return {ok:false, reason:'missing_email_input'};

        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        input.scrollIntoView({block:'center', inline:'nearest'});
        input.focus();
        if (setter) setter.call(input, email); else input.value = email;
        try {
          input.dispatchEvent(new InputEvent('beforeinput', {
            bubbles:true, cancelable:true, inputType:'insertText', data:email
          }));
        } catch (_) {}
        try {
          input.dispatchEvent(new InputEvent('input', {
            bubbles:true, inputType:'insertText', data:email
          }));
        } catch (_) {
          input.dispatchEvent(new Event('input', {bubbles:true}));
        }
        input.dispatchEvent(new Event('change', {bubbles:true}));
        input.dispatchEvent(new FocusEvent('blur', {bubbles:true}));
        input.blur();
        input.focus();

        const form = input.closest('form');
        const submit = form?.querySelector('button[type="submit"],input[type="submit"]');
        return {
          ok:true,
          value:input.value,
          hasForm:!!form,
          hasSubmit:!!submit,
          submitDisabled:submit
            ? (!!submit.disabled || String(submit.getAttribute('aria-disabled') || '').toLowerCase() === 'true')
            : null,
          url:location.href
        };
        """, email) or {}
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _submit_email_form_stable(driver, email: str) -> dict:
    """稳定 React 值后异步触发 Enter 与安全 submit，避免 WebDriver 等待卡死。"""
    try:
        return driver.execute_script(r"""
        const email = String(arguments[0] || '').trim();
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && el.getAttribute('aria-disabled') !== 'true';
        const editable = el => visible(el) && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]')]
          .find(editable);
        if (!input) return {ok:false, reason:'missing_email_input'};
        if (!email || !email.includes('@')) return {ok:false, reason:'empty_email'};
        const form = input.closest('form');
        if (!form) return {ok:false, reason:'missing_form'};

        const bad = /google|apple|microsoft|github|facebook|saml|sso|oauth|social|oidc|idp|provider|authorize|consent|grant|allow/;
        const attrs = el => [
          el.id, el.name, el.type, el.getAttribute('data-testid'), el.getAttribute('data-test-id'),
          el.getAttribute('data-provider'), el.getAttribute('data-auth-provider'),
          el.getAttribute('data-idp'), el.getAttribute('aria-label'),
          el.getAttribute('href'), el.getAttribute('formaction'), el.value, el.className
        ].filter(Boolean).join(' ').toLowerCase();
        const formId = form.getAttribute('id') || '';
        const candidates = [
          ...form.querySelectorAll('button,input[type="submit"]'),
          ...(formId ? [...document.querySelectorAll(`button[form="${CSS.escape(formId)}"],input[type="submit"][form="${CSS.escape(formId)}"]`)] : [])
        ].filter((el, index, all) => all.indexOf(el) === index)
          .filter(el => visible(el) && !bad.test(attrs(el)) && !el.querySelector('img,svg,use'));
        const submit = candidates.find(el => String(el.getAttribute('type') || '').toLowerCase() === 'submit')
          || candidates[0]
          || null;
        if (!submit) return {ok:false, reason:'missing_safe_submit'};

        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        input.focus();
        if (setter) setter.call(input, email); else input.value = email;
        try {
          input.dispatchEvent(new InputEvent('input', {
            bubbles:true, inputType:'insertText', data:email
          }));
        } catch (_) {
          input.dispatchEvent(new Event('input', {bubbles:true}));
        }
        input.dispatchEvent(new Event('change', {bubbles:true}));
        input.dispatchEvent(new FocusEvent('blur', {bubbles:true}));
        input.blur();
        input.focus();
        submit.scrollIntoView({block:'center', inline:'nearest'});

        setTimeout(() => {
          try {
            input.focus();
            input.dispatchEvent(new KeyboardEvent('keydown', {
              bubbles:true, cancelable:true, key:'Enter', code:'Enter'
            }));
            input.dispatchEvent(new KeyboardEvent('keypress', {
              bubbles:true, cancelable:true, key:'Enter', code:'Enter'
            }));
            input.dispatchEvent(new KeyboardEvent('keyup', {
              bubbles:true, cancelable:true, key:'Enter', code:'Enter'
            }));
            if (!submit.disabled) submit.click();
            else if (typeof form.requestSubmit === 'function') form.requestSubmit();
          } catch (_) {}
        }, 80);
        window.__roxy_email_submit_debug = {
          at:Date.now(), mode:'stable_async_enter_click', value:input.value,
          submitAttrs:attrs(submit).slice(0, 240)
        };
        return {
          ok:true,
          reason:'stable_async_enter_click',
          value:input.value,
          submitDisabled:!!submit.disabled || String(submit.getAttribute('aria-disabled') || '').toLowerCase() === 'true',
          submitAttrs:attrs(submit).slice(0, 180),
          url:location.href
        };
        """, email) or {}
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _submit_email_step(driver, email: str | None = None) -> None:
    email_value = str(email or _current_email_input_value(driver) or "").strip()
    stable = _stabilize_email_input_before_submit(driver, email_value)
    logger.info("%s 邮箱提交前状态稳定：%s", _log_prefix(driver), stable)
    _sleep_with_manual_stop(
        random.uniform(0.8, 1.8) if _browser_actions_enabled() else 0.4
    )
    submitted = _submit_email_form_stable(driver, email_value)
    if submitted.get("ok"):
        logger.info("%s 邮箱稳定表单提交：%s", _log_prefix(driver), submitted)
        _sleep_with_manual_stop(1.0)
        _assert_not_external_idp(driver, "稳定表单提交邮箱后")
        return
    logger.warning("%s 邮箱稳定表单提交失败，回退 UI 点击：%s", _log_prefix(driver), submitted)
    if _submit_nearest_form_for_active_input(driver):
        return
    raise RuntimeError(f"无法提交邮箱步骤（拒绝按页面文字或首个 submit 兜底，避免误点第三方登录），state={_email_entry_state(driver)}")


def _email_input_value_state(driver) -> dict:
    """读取当前可见邮箱框状态，用于提交后确认是否真的进入下一步。"""
    try:
        return driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const inputs = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]')]
          .filter(visible)
          .map(el => {
            const form = el.form;
            const submitters = [...(form || document).querySelectorAll('button[type="submit"],input[type="submit"]')];
            const hasEnabledSubmit = submitters.some(btn => visible(btn)
              && String(btn.getAttribute('aria-disabled') || '').toLowerCase() !== 'true');
            return {
              type: el.getAttribute('type') || '', name: el.name || '', id: el.id || '',
              autocomplete: el.getAttribute('autocomplete') || '', value: el.value || '',
              hasEnabledSubmit,
            };
          });
        return {url: location.href, readyState: document.readyState || '', inputs};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, "current_url", ""), "error": f"{type(exc).__name__}: {exc}"}


def _is_email_login_page_still_present(driver) -> bool:
    state = _email_input_value_state(driver)
    return bool(state.get("inputs"))


def _is_confirmed_email_second_stage(state: dict, expected_email: str) -> bool:
    """识别 login?email=... 上已稳定可交互的第二次邮箱表单。"""
    try:
        parsed = urlparse(str((state or {}).get("url") or ""))
        query_emails = [
            str(value or "").strip().lower()
            for value in parse_qs(parsed.query).get("email", [])
        ]
    except Exception:
        return False
    if str(parsed.hostname or "").lower() != "chatgpt.com":
        return False
    if str(parsed.path or "").rstrip("/").lower() != "/auth/login":
        return False
    if str(expected_email or "").strip().lower() not in query_emails:
        return False
    if str((state or {}).get("readyState") or "").lower() not in {"interactive", "complete"}:
        return False
    inputs = [item for item in ((state or {}).get("inputs") or []) if isinstance(item, dict)]
    if not inputs or any(str(item.get("value") or "").strip() for item in inputs):
        return False
    return any(bool(item.get("hasEnabledSubmit")) for item in inputs)


def _recover_email_submit_if_stuck(driver, email: str) -> dict:
    """停在 login?email 且输入框清空时，在同一 Profile 内补交一次表单。"""
    try:
        return driver.execute_script(r"""
        const email = String(arguments[0] || '').trim();
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="email"],input[name="email"],input[name="username"],input[autocomplete*="email"]')]
          .find(visible);
        if (!input) return {ok:false, reason:'missing_email_input'};
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        input.focus();
        if (setter) setter.call(input, email); else input.value = email;
        try {
          input.dispatchEvent(new InputEvent('input', {
            bubbles:true, inputType:'insertText', data:email
          }));
        } catch (_) {
          input.dispatchEvent(new Event('input', {bubbles:true}));
        }
        input.dispatchEvent(new Event('change', {bubbles:true}));
        const form = input.closest('form');
        const submit = form?.querySelector('button[type="submit"],input[type="submit"]');
        setTimeout(() => {
          try {
            input.dispatchEvent(new KeyboardEvent('keydown', {
              bubbles:true, cancelable:true, key:'Enter', code:'Enter'
            }));
            input.dispatchEvent(new KeyboardEvent('keyup', {
              bubbles:true, cancelable:true, key:'Enter', code:'Enter'
            }));
            if (submit && !submit.disabled) submit.click();
            else if (form && typeof form.requestSubmit === 'function') form.requestSubmit();
          } catch (_) {}
        }, 80);
        return {
          ok:true, reason:'resubmitted_email_form', value:input.value,
          hasForm:!!form, hasSubmit:!!submit
        };
        """, email) or {}
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _wait_email_submit_next_state(driver, email: str, timeout: int = 18) -> str:
    """邮箱提交后等待进入 password / otp / logged_in；仍停留邮箱页则返回 email_page。

    Cloak/Playwright 路径里，点击 submit 后页面经常先发生一次 SPA 导航：
    `chatgpt.com/auth/login?email=...`，同时 React 会短暂把 email input 清空。
    旧逻辑一看到空 input 就立刻返回 `email_cleared`，导致在真正跳到
    `auth.openai.com/...` 前过早重填，形成“提交 -> 清空 -> 重填”的循环。
    这里不再用一个很短的清空阈值提前重试：只记录并观察完整等待窗口；
    若期间进入 password/otp/login_password/logged_in 则按真实状态返回，
    直到窗口结束仍持续清空才让上层重试。
    """
    end = time.time() + timeout
    last = None
    cleared_seen_at: float | None = None
    cleared_last_log_at = 0.0
    cleared_recover_done = False
    expected_email = str(email or "").strip().lower()
    while time.time() < end:
        _check_manual_stop()
        _raise_for_browser_network_error(driver, last)
        if _has_access_token(driver):
            return "logged_in"
        if _is_login_password_page(driver):
            return "login_password"
        if _is_email_verification_page(driver):
            return "otp"
        if _is_signup_password_page(driver):
            return "password"
        state = _email_input_value_state(driver)
        _raise_for_browser_network_error(driver, state)
        last = state
        inputs = state.get("inputs") or []
        if inputs:
            values = [str(i.get("value") or "") for i in inputs]
            url = str(state.get("url") or "")
            has_blank = any(v == "" for v in values)
            has_expected = any(v.strip().lower() == expected_email for v in values)
            if has_blank and not has_expected:
                now = time.time()
                if cleared_seen_at is None:
                    cleared_seen_at = now
                if now - cleared_last_log_at > 2.0:
                    logger.info(
                        "%s 邮箱提交后检测到输入框短暂清空，继续等待真实跳转：elapsed=%.1fs url=%s",
                        _log_prefix(driver), now - cleared_seen_at, url[:180],
                    )
                    cleared_last_log_at = now
                if (
                    not cleared_recover_done
                    and "/auth/login" in url
                    and "email=" in url
                    and now - cleared_seen_at >= 2.0
                ):
                    recovery = _recover_email_submit_if_stuck(driver, email)
                    cleared_recover_done = True
                    logger.info(
                        "%s 邮箱中间页未继续跳转，在当前 Profile 补交一次表单：%s",
                        _log_prefix(driver), recovery,
                    )
                if (
                    now - cleared_seen_at >= _EMAIL_SECOND_STAGE_STABLE_SECONDS
                    and _is_confirmed_email_second_stage(state, expected_email)
                ):
                    logger.info(
                        "%s 已确认邮箱第二阶段表单稳定，结束首轮等待：elapsed=%.1fs url=%s",
                        _log_prefix(driver), now - cleared_seen_at, url[:180],
                    )
                    return "email_second_stage"
            else:
                cleared_seen_at = None
            # 仍是当前邮箱页，继续短等。
        _sleep_with_manual_stop(0.8)
    # WebDriver 命令可能被正在进行的导航阻塞到等待窗口之外。先读取一次最新
    # 页面，再复核终态，避免页面已到 OTP/密码页却沿用循环内的旧快照。
    final_state = _email_input_value_state(driver)
    _raise_for_browser_network_error(driver, final_state)
    if final_state:
        last = final_state
    final_url = str((last or {}).get("url") or "").lower()
    if "/log-in/password" in final_url:
        return "login_password"
    if "email-verification" in final_url or "email-otp" in final_url:
        return "otp"
    if _has_access_token(driver):
        return "logged_in"
    if _is_login_password_page(driver):
        return "login_password"
    if _is_email_verification_page(driver):
        return "otp"
    if _is_signup_password_page(driver):
        return "password"
    logger.info("%s 邮箱提交后等待下一步超时，最后邮箱页状态=%s", _log_prefix(driver), last)
    inputs = (last or {}).get("inputs") or []
    values = [str(item.get("value") or "") for item in inputs if isinstance(item, dict)]
    if inputs and any(value == "" for value in values) and not any(
        value.strip().lower() == expected_email for value in values
    ):
        return "email_cleared"
    return "email_page" if inputs else "unknown"


def _is_empty_auth_login_shell(state: dict) -> bool:
    """提交后 SPA 偶发只留下 Get started 外壳，此时必须重载登录入口。"""
    url = str((state or {}).get("url") or "").lower()
    return "/auth/login" in url and not ((state or {}).get("inputs") or [])


def _recover_email_entry_page(driver, timeout: int = 8) -> bool:
    """重新加载登录页，并确认邮箱输入框或邮箱入口已恢复。"""
    logger.warning("%s 邮箱提交后页面未跳转且输入框已消失，重新加载登录页", _log_prefix(driver))
    try:
        _navigate_page(driver, _CHATGPT_LOGIN_URL)
        _maybe_accept(driver)
    except Exception as exc:
        _check_manual_stop()
        logger.warning("%s 重新加载登录页失败：%s: %s", _log_prefix(driver), type(exc).__name__, exc)
        return False

    end = time.time() + timeout
    clicked_email_option = False
    while time.time() < end:
        _check_manual_stop()
        try:
            if _find_visible_email_input_js(driver):
                logger.info("%s 登录页已恢复，准备重新填写邮箱", _log_prefix(driver))
                return True
            if not clicked_email_option and _click_email_entry_option(driver):
                clicked_email_option = True
        except Exception as exc:
            logger.debug("%s 等待邮箱入口恢复时页面尚未就绪：%s", _log_prefix(driver), exc)
        _sleep_with_manual_stop(0.4)
    logger.warning("%s 重载登录页后邮箱入口仍未恢复：state=%s", _log_prefix(driver), _email_entry_state(driver))
    return False


def _submit_email_and_wait_next(
    driver,
    email: str,
    attempts: int = 3,
    on_email_submitted=None,
    on_email_submit_attempted=None,
) -> str:
    """填写并提交邮箱，必须确认进入 password/otp/logged_in 才返回。"""
    last_state = None
    submit_failures: list[dict] = []
    retry_entry_error = ""
    for attempt in range(1, attempts + 1):
        _check_manual_stop()
        try:
            _type_email_address(driver, email, timeout=20)
        except Exception as exc:
            _check_manual_stop()
            if not submit_failures:
                raise
            retry_entry_error = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "%s 邮箱提交未跳转后的第 %s/%s 次页面恢复失败：%s",
                _log_prefix(driver), attempt, attempts, retry_entry_error,
            )
            current = _email_input_value_state(driver)
            if attempt < attempts and _is_empty_auth_login_shell(current):
                _recover_email_entry_page(driver)
                continue
            break
        state = _email_input_value_state(driver)
        last_state = state
        values = [str(i.get("value") or "") for i in (state.get("inputs") or [])]
        if not any(v.strip().lower() == email.strip().lower() for v in values):
            logger.warning("%s 邮箱写入校验失败，准备重试：attempt=%s/%s state=%s", _log_prefix(driver), attempt, attempts, state)
            _sleep_with_manual_stop(0.8)
            continue
        logger.info("%s 已填写邮箱并校验通过：%s", _log_prefix(driver), email)
        human_delay("form")
        _submit_email_step(driver, email)
        if on_email_submit_attempted is not None:
            on_email_submit_attempted()
        logger.info("%s 已触发邮箱提交，等待服务端进入密码页或验证码页（%s/%s）", _log_prefix(driver), attempt, attempts)
        state_name = _wait_email_submit_next_state(driver, email, timeout=20)
        if state_name == "login_password":
            if on_email_submitted is not None:
                on_email_submitted()
            raise RuntimeError(f"邮箱提交后进入登录密码页，按已注册/不可用邮箱处理并停用: url={getattr(driver, 'current_url', '') or 'https://auth.openai.com/log-in/password'}")
        if state_name in ("password", "otp", "logged_in"):
            if on_email_submitted is not None:
                on_email_submitted()
            logger.info("%s 邮箱提交后已进入下一步：%s", _log_prefix(driver), state_name)
            return state_name
        post_submit_state = _email_input_value_state(driver)
        submit_failures.append({"attempt": attempt, "state": state_name, "page": post_submit_state})
        if state_name == "email_second_stage":
            logger.info("%s 邮箱首轮提交已进入第二阶段，复用当前页面再次填写并提交", _log_prefix(driver))
        else:
            logger.warning("%s 邮箱提交后仍未进入下一步：%s，准备恢复页面后重试 state=%s", _log_prefix(driver), state_name, post_submit_state)
        if attempt < attempts and _is_empty_auth_login_shell(post_submit_state):
            _recover_email_entry_page(driver)
        _sleep_with_manual_stop(1.0)
    if submit_failures:
        last_failure = submit_failures[-1]
        detail = f"；重试页面错误={retry_entry_error}" if retry_entry_error else ""
        raise RuntimeError(
            "邮箱提交未跳转到密码页/验证码页"
            f"，尝试次数={len(submit_failures)}，最后提交状态={last_failure['state']}"
            f"，最后页面={last_failure['page']}{detail}"
        )
    raise RuntimeError(f"邮箱提交前未能完成邮箱填写/校验，最后状态={last_state}")


def _type_otp(driver, code: str) -> None:
    inputs, segmented = _strict_otp_elements(driver)
    if len(inputs) == 1 and not segmented:
        _human_type_text(driver, inputs[0], code, clear=True)
        return
    if segmented and len(inputs) == len(code):
        for element, char in zip(inputs, code):
            if _browser_actions_enabled():
                _human_scroll_to(driver, element)
                _sleep_with_manual_stop(random.uniform(0.04, 0.18))
            element.send_keys(char)
            if _browser_actions_enabled():
                human_delay("keystroke")
        return

    raise RuntimeError(f"找不到 OTP 输入框，state={_email_otp_page_state(driver)}")


def _email_otp_page_state(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const inputs = [...document.querySelectorAll('input')].filter(visible).map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          autocomplete: el.getAttribute('autocomplete') || '', inputmode: el.getAttribute('inputmode') || '',
          aria: el.getAttribute('aria-label') || '', placeholder: el.getAttribute('placeholder') || '',
          maxLength: el.maxLength, ariaInvalid: el.getAttribute('aria-invalid') || '', value: el.value || ''
        }));
        const buttons = [...document.querySelectorAll('button,a,[role=button],input[type=button],input[type=submit]')].filter(visible).map(el => ({
          tag: el.tagName, type: el.getAttribute('type') || '', value: el.getAttribute('value') || '',
          action: el.getAttribute('data-dd-action-name') || '', aria: el.getAttribute('aria-label') || '',
          testid: el.getAttribute('data-testid') || '',
          disabled: !!el.disabled || String(el.getAttribute('aria-disabled') || '').toLowerCase() === 'true',
          text: (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 120)
        }));
        const errors = [...document.querySelectorAll('.react-aria-FieldError,[slot="errorMessage"],[id$="-error"],[aria-invalid="true"] + *,[class*="error"]')]
          .filter(visible).map(el => (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim()).filter(Boolean);
        return {url: location.href, title: document.title, inputs, buttons, errors, text: (document.body?.innerText || '').slice(0, 1200)};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, 'current_url', ''), "error": f"{type(exc).__name__}: {exc}"}


def _is_email_verification_page(driver) -> bool:
    try:
        url = str(driver.current_url or '').lower()
    except Exception:
        url = ''
    if '/log-in/password' in url:
        return False
    if 'email-verification' in url or 'email-otp' in url:
        return True
    state = _email_otp_page_state(driver)
    return _otp_inputs_ready(state)


def _has_otp_input_marker(item: dict) -> bool:
    autocomplete = str(item.get("autocomplete") or "").strip().lower()
    if "one-time-code" in autocomplete:
        return True
    values = [
        str(item.get(key) or "").strip().lower()
        for key in ("name", "id", "aria", "placeholder")
    ]
    content = " ".join(values)
    if any(marker in content for marker in (
        "one-time", "one time", "otp", "passcode", "verification code",
        "security code", "authentication code", "验证码", "驗證碼", "認証コード",
    )):
        return True
    return any(value in {"code", "pin"} for value in values)


def _is_segmented_otp_input(item: dict) -> bool:
    try:
        max_length = int(item.get("maxLength"))
    except (TypeError, ValueError):
        return False
    input_kind = " ".join(
        str(item.get(key) or "") for key in ("type", "inputmode")
    ).lower()
    return max_length == 1 and any(marker in input_kind for marker in ("numeric", "tel"))


def _otp_inputs_ready(state: dict) -> bool:
    """只接受明确 OTP 控件或 4–8 个单字符数字分格，避免把电话/数字字段当成 OTP。"""
    inputs = [item for item in ((state or {}).get("inputs") or []) if isinstance(item, dict)]
    if any(_has_otp_input_marker(item) for item in inputs):
        return True
    segmented = [item for item in inputs if _is_segmented_otp_input(item)]
    return 4 <= len(segmented) <= 8


def _otp_element_state(element) -> dict:
    return {
        "type": element.get_attribute("type") or "",
        "name": element.get_attribute("name") or "",
        "id": element.get_attribute("id") or "",
        "autocomplete": element.get_attribute("autocomplete") or "",
        "inputmode": element.get_attribute("inputmode") or "",
        "aria": element.get_attribute("aria-label") or "",
        "placeholder": element.get_attribute("placeholder") or "",
        "maxLength": element.get_attribute("maxlength"),
    }


def _strict_otp_elements(driver) -> tuple[list, bool]:
    """返回严格识别出的 OTP 输入控件，以及它们是否为分格输入。"""
    from selenium.webdriver.common.by import By

    elements = [element for element in driver.find_elements(By.CSS_SELECTOR, "input") if _visible(element)]
    states = [_otp_element_state(element) for element in elements]
    explicit = [
        element for element, state in zip(elements, states)
        if _has_otp_input_marker(state)
    ]
    segmented = [
        element for element, state in zip(elements, states)
        if _is_segmented_otp_input(state)
    ]
    if 4 <= len(segmented) <= 8:
        return segmented, True
    if len(explicit) == 1:
        return explicit, False
    return [], False


def _is_email_verified_success_state(state: dict) -> bool:
    """识别 OTP 已被接受但仍停留在 email-verification URL 的成功页。"""
    content = " ".join(
        str((state or {}).get(key) or "")
        for key in ("title", "text")
    ).lower()
    return any(marker in content for marker in (
        "email verified",
        "email has been verified",
        "has already been verified",
        "メールアドレスが確認されました",
        "メールアドレスは確認済みです",
        "メールアドレスは既に確認されています",
        "邮箱已验证",
        "电子邮件已验证",
        "電子郵件地址已驗證",
    ))


def _is_chatgpt_logged_in_state(state: dict) -> bool:
    """识别 ChatGPT 应用中强登录态 UI，作为 session API 暂时不可用时的兜底。"""
    snapshot = state or {}
    try:
        parsed = urlparse(str(snapshot.get("url") or ""))
    except Exception:
        return False
    path = str(parsed.path or "/").lower()
    if str(parsed.hostname or "").lower() != "chatgpt.com" or path.startswith("/auth/"):
        return False

    controls = " ".join(
        " ".join(
            str(button.get(key) or "")
            for key in ("testid", "action", "aria", "text")
        )
        for button in (snapshot.get("buttons") or [])
        if isinstance(button, dict)
    ).lower()
    return any(marker in controls for marker in (
        "profile-button",
        "profile menu",
        "account menu",
        "user menu",
        "プロファイルメニュー",
        "プロフィールメニュー",
        "프로필 메뉴",
        "个人资料菜单",
        "個人資料選單",
        "个人菜单",
        "個人選單",
    ))


def _classify_email_otp_state(state: dict) -> str:
    """将 OTP 提交后的页面快照归一为稳定状态，避免把通用错误页当成验证码错误。"""
    snapshot = state or {}
    url = str(snapshot.get("url") or "").strip().lower()
    title = str(snapshot.get("title") or "").strip().lower()
    text = str(snapshot.get("text") or "").strip().lower()
    errors = " ".join(str(item or "") for item in (snapshot.get("errors") or [])).lower()
    driver_error = str(snapshot.get("error") or "").strip().lower()
    content = " ".join(part for part in (title, text, errors, driver_error) if part)

    route_markers = (
        "route error",
        "route_error",
        "internal server error",
        "server encountered an error",
    )
    if any(marker in content for marker in route_markers):
        return "route_error"

    network_markers = (
        "chrome-error://",
        "err_socks_connection_failed",
        "err_proxy_connection_failed",
        "err_ssl_protocol_error",
        "err_tunnel_connection_failed",
        "err_connection_closed",
        "err_connection_reset",
        "this site can’t be reached",
        "this site can't be reached",
        "proxy connection failed",
        "无法访问此网站",
        "このサイトにアクセスできません",
    )
    if any(marker in url or marker in content for marker in network_markers):
        return "network_error"

    if _is_chatgpt_logged_in_state(snapshot):
        return "accepted"

    # 错误优先于 URL：callback/about-you 也可能实际展示 Route Error。
    accepted_url_markers = (
        "/about-you",
        "/create-account/profile",
        "/oauth/callback",
        "/callback",
        "/workspace",
    )
    if any(marker in url for marker in accepted_url_markers):
        return "accepted"

    if _is_email_verified_success_state(snapshot):
        return "accepted"

    inputs = [item for item in (snapshot.get("inputs") or []) if isinstance(item, dict)]
    segmented_inputs = [item for item in inputs if _is_segmented_otp_input(item)]
    has_segmented_otp = 4 <= len(segmented_inputs) <= 8
    invalid_input = any(
        str(item.get("ariaInvalid") or "").lower() == "true"
        and (_has_otp_input_marker(item) or (has_segmented_otp and item in segmented_inputs))
        for item in inputs
    )
    invalid_markers = (
        "invalid code",
        "code is invalid",
        "incorrect code",
        "code is incorrect",
        "code has expired",
        "expired code",
        "verification code is invalid",
        "verification code has expired",
        "验证码错误",
        "验证码无效",
        "验证码已过期",
        "認証コードが正しくありません",
        "無効な認証コード",
        "認証コードの有効期限",
    )
    if invalid_input or any(marker in content for marker in invalid_markers):
        return "explicit_invalid"

    buttons = snapshot.get("buttons") or []
    button_text = " ".join(
        " ".join(str(button.get(key) or "") for key in ("text", "action", "aria", "value"))
        for button in buttons
        if isinstance(button, dict)
    ).lower()
    route_retry_visible = "try again" in button_text and ("error" in content or "/error" in url)
    if route_retry_visible:
        return "route_error"

    if _otp_inputs_ready(snapshot) or "email-verification" in url or "email-otp" in url:
        return "pending"

    return "pending"


def _can_retry_same_otp_submission(state: dict, code: str) -> bool:
    """仅在原 OTP 仍完整保留且 validate 按钮可用时允许同页重提。"""
    snapshot = state or {}
    inputs = [item for item in (snapshot.get("inputs") or []) if isinstance(item, dict)]
    explicit = [item for item in inputs if _has_otp_input_marker(item)]
    segmented = [item for item in inputs if _is_segmented_otp_input(item)]
    expected = str(code or "")
    if len(explicit) == 1:
        value_matches = str(explicit[0].get("value") or "") == expected
    elif 4 <= len(segmented) <= 8:
        value_matches = "".join(str(item.get("value") or "") for item in segmented) == expected
    else:
        value_matches = False
    if not value_matches:
        return False

    for button in (snapshot.get("buttons") or []):
        if not isinstance(button, dict) or bool(button.get("disabled")):
            continue
        attrs = " ".join(
            str(button.get(key) or "")
            for key in ("action", "value", "type", "testid", "aria")
        ).lower()
        if "resend" in attrs:
            continue
        if "validate" in attrs or "verify" in attrs or "submit_otp" in attrs:
            return True
    return False


def _wait_for_otp_form_ready(
    driver,
    *,
    timeout: float = 15,
    reload_after: float = 8.0,
    fallback_url: str = "",
    email: str = "",
) -> dict:
    """等待重发后的 OTP 表单恢复；丢失上下文时重新提交邮箱。"""
    started = time.time()
    end = started + max(1.0, float(timeout or 15))
    reloaded = False
    last: dict = {}
    while time.time() < end:
        _check_manual_stop()
        last = _email_otp_page_state(driver)
        outcome = _classify_email_otp_state(last)
        if outcome == "accepted":
            last["_verified"] = True
            return last
        if outcome == "network_error":
            raise RuntimeError(f"OTP 页面恢复期间发生浏览器网络异常: {last}")
        if _otp_inputs_ready(last):
            return last

        elapsed = time.time() - started
        if outcome != "route_error" and not reloaded:
            current_url = str(last.get("url") or getattr(driver, "current_url", "") or "")
            lowered_url = current_url.lower()
            # 只有明确退回登录页时才重新提交邮箱。验证页短暂卸载输入框时
            # 重开登录页会再次触发邮件并让刚取得的验证码立即失效。
            if (
                str(email or "").strip()
                and "/auth/login" in lowered_url
                and elapsed >= min(2.5, max(0.0, float(reload_after or 0)))
            ):
                try:
                    recovered_at = time.time()
                    logger.warning(
                        "%s[OTP] 验证页丢失邮箱上下文，返回登录页重新提交邮箱：url=%s",
                        _log_prefix(driver), current_url[:200],
                    )
                    _navigate_page(driver, _CHATGPT_LOGIN_URL)
                    _maybe_accept(driver)
                    next_state = _submit_email_and_wait_next(driver, str(email).strip(), attempts=2)
                    if next_state == "logged_in":
                        last["_verified"] = True
                        return last
                    if next_state != "otp":
                        raise RuntimeError(f"重新提交邮箱后未进入 OTP 页面: {next_state}")
                    reloaded = True
                    _sleep_with_manual_stop(1.0)
                    last = _email_otp_page_state(driver)
                    if _otp_inputs_ready(last):
                        last["_recovered"] = True
                        last["_recovered_at"] = recovered_at
                        return last
                except Exception as exc:
                    _check_manual_stop()
                    reloaded = True
                    logger.warning("%s[OTP] 重新提交邮箱恢复验证页失败：%s: %s", _log_prefix(driver), type(exc).__name__, exc)
            elif elapsed >= max(0.0, float(reload_after or 0)):
                target_url = current_url if "email-verification" in lowered_url else str(fallback_url or "")
                if target_url and "email-verification" in target_url.lower():
                    try:
                        logger.warning(
                            "%s[OTP] 验证页输入框长时间未恢复，仅刷新当前验证页：%s",
                            _log_prefix(driver), target_url[:200],
                        )
                        _navigate_page(driver, target_url)
                        reloaded = True
                        _sleep_with_manual_stop(1.0)
                        continue
                    except Exception as exc:
                        _check_manual_stop()
                        reloaded = True
                        logger.warning("%s[OTP] 刷新邮箱验证页失败：%s: %s", _log_prefix(driver), type(exc).__name__, exc)
        _sleep_with_manual_stop(0.4)

    raise RuntimeError(f"OTP 页面未恢复可填写输入框，最后状态={last}")


def _clear_otp_inputs(driver) -> None:
    try:
        inputs, _segmented = _strict_otp_elements(driver)
        for element in inputs:
            driver.execute_script(r"""
          const el = arguments[0];
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
          if (setter) setter.call(el, ''); else el.value = '';
          el.dispatchEvent(new Event('input', {bubbles:true}));
          el.dispatchEvent(new Event('change', {bubbles:true}));
            """, element)
    except Exception:
        pass


def _click_resend_email_otp(driver, timeout: int = 20) -> dict:
    """点击重新发送邮箱验证码。优先按 DOM 属性识别，文本仅兜底。"""
    initial_state = _email_otp_page_state(driver)
    if _classify_email_otp_state(initial_state) == "route_error":
        raise RuntimeError("当前是 Route Error 页面，不能把 Try again 当成重发验证码")
    end = time.time() + timeout
    last = None
    last_state: dict = initial_state
    while time.time() < end:
        _check_manual_stop()
        try:
            last_state = _email_otp_page_state(driver)
            if _classify_email_otp_state(last_state) == "route_error":
                raise RuntimeError("当前是 Route Error 页面，不能把 Try again 当成重发验证码")
            btn = driver.execute_script(r"""
            const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
            const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
            const candidates = [...document.querySelectorAll('button,a,[role=button],[role=link],input[type=button],input[type=submit]')].filter(visible);
            const attrHit = candidates.find(el => {
              if (!enabled(el)) return false;
              const attrs = [el.id, el.getAttribute('name'), el.getAttribute('value'), el.getAttribute('data-dd-action-name'), el.getAttribute('aria-label'), el.getAttribute('title'), el.getAttribute('data-testid')]
                .join(' ').toLowerCase();
              const name = String(el.getAttribute('name') || '').toLowerCase();
              const value = String(el.getAttribute('value') || '').toLowerCase();
              if (name === 'intent' && value === 'resend') return true;
              return /resend|send.*new|new.*code|send.*again/.test(attrs);
            });
            if (attrHit) return attrHit;
            // 兜底：多语言文本，避免因页面没有稳定属性时卡死。
            return candidates.find(el => enabled(el) && /resend|send\s+(?:a\s+)?new\s+code|send\s+again|重新发送|重新发送电子邮件|重发|再次发送|再送信|新しい|届かない/.test((el.innerText || el.textContent || '').toLowerCase())) || null;
            """)
            if btn:
                text = str(btn.text or btn.get_attribute('value') or btn.get_attribute('data-dd-action-name') or '').strip()
                _human_click(driver, btn, label="resend_otp")
                logger.info("%s[OTP] 已点击重新发送验证码按钮：%s", _log_prefix(driver), text or '-')
                _sleep_with_manual_stop(
                    random.uniform(1.1, 2.4) if _browser_actions_enabled() else 1.5
                )
                return {"ok": True, "text": text, "url": str(last_state.get("url") or "")}
        except Exception as exc:
            _check_manual_stop()
            last = exc
        _sleep_with_manual_stop(0.5)
    raise RuntimeError(f"找不到可点击的重新发送验证码按钮: last={last}, state={_email_otp_page_state(driver)}")


def _click_route_error_retry(driver, timeout: int = 10) -> dict:
    """只在 Route Error 页面点击精确的 Try again/retry 控件。"""
    end = time.time() + max(0.1, float(timeout or 0.1))
    last_state: dict = {}
    last_error: Exception | None = None
    while time.time() < end:
        _check_manual_stop()
        try:
            last_state = _email_otp_page_state(driver)
            if _classify_email_otp_state(last_state) != "route_error":
                raise RuntimeError("当前页面不是 Route Error")
            button = driver.execute_script(r"""
            const visible = el => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
            const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
            const candidates = [...document.querySelectorAll('button,a,[role=button],input[type=button],input[type=submit]')]
              .filter(el => visible(el) && enabled(el));
            const normalized = el => String(el.innerText || el.textContent || el.value || el.getAttribute('aria-label') || '')
              .replace(/\s+/g, ' ').trim().toLowerCase();
            const exactText = /^(try again|retry|重试|再试一次|再試行|もう一度試す)$/;
            const byText = candidates.find(el => exactText.test(normalized(el)));
            if (byText) return byText;
            return candidates.find(el => {
              const attrs = [el.id, el.name, el.getAttribute('data-dd-action-name'), el.getAttribute('data-testid'), el.getAttribute('aria-label')]
                .join(' ').toLowerCase();
              return /(^|[-_\s])(retry|try[-_\s]?again)([-_\s]|$)/.test(attrs)
                && !/resend|send.*code/.test(attrs);
            }) || null;
            """)
            if button:
                text = str(
                    button.text
                    or button.get_attribute("value")
                    or button.get_attribute("aria-label")
                    or ""
                ).strip()
                _human_click(driver, button, label="route_error_retry")
                logger.info("%s[OTP] Route Error 页面已点击 Try again：%s", _log_prefix(driver), text or "-")
                _sleep_with_manual_stop(0.8)
                return {"ok": True, "text": text, "url": str(last_state.get("url") or "")}
        except Exception as exc:
            _check_manual_stop()
            last_error = exc
        _sleep_with_manual_stop(0.4)
    raise RuntimeError(f"Route Error 页面未找到可点击的 Try again: last={last_error}, state={last_state}")


def _wait_after_email_otp_submit(driver, timeout: int = 10) -> str:
    """提交 OTP 后等待明确结果；超时但无错误时保持 pending。"""
    end = time.time() + max(0.0, float(timeout or 0))
    last = {}
    while time.time() < end:
        _check_manual_stop()
        if _has_access_token(driver):
            return "accepted"
        _sleep_with_manual_stop(0.5)
        last = _email_otp_page_state(driver)
        outcome = _classify_email_otp_state(last)
        if outcome != "pending":
            return outcome
    last = _email_otp_page_state(driver)
    outcome = _classify_email_otp_state(last)
    if outcome == "pending":
        logger.warning("%s[OTP] 提交后仍无明确结果，保持 pending snapshot=%s", _log_prefix(driver), last)
    return outcome


def _wait_for_route_error_recovery(driver, timeout: float = 15) -> tuple[str, dict]:
    """等待 Try again 后恢复 OTP 表单或直接完成跳转，不主动刷新或重开登录页。"""
    end = time.time() + max(0.1, float(timeout or 0.1))
    last: dict = {}
    while time.time() < end:
        _check_manual_stop()
        last = _email_otp_page_state(driver)
        outcome = _classify_email_otp_state(last)
        if outcome == "accepted":
            return outcome, last
        if outcome in {"network_error", "explicit_invalid"}:
            return outcome, last
        if _otp_inputs_ready(last):
            return "pending", last
        _sleep_with_manual_stop(0.4)
    return _classify_email_otp_state(last), last


def _submit_email_otp_with_route_recovery(
    driver,
    code: str,
    *,
    wait_timeout: int = 10,
    max_route_retries: int = 2,
    max_pending_retries: int = 0,
    on_otp_entered=None,
) -> tuple[str, bool]:
    """提交当前 OTP；仅显式允许时才对 pending 状态复用同一个验证码。"""
    submitted = False
    route_attempt = 0
    pending_attempt = 0
    reuse_existing_value = False
    while True:
        _check_manual_stop()
        if not reuse_existing_value:
            _clear_otp_inputs(driver)
            _type_otp(driver, code)
            if on_otp_entered is not None:
                on_otp_entered()
            logger.info("%s[OTP] 已填写邮箱验证码", _log_prefix(driver))
            _check_manual_stop()
            human_delay("otp_input")
        reuse_existing_value = False
        try:
            clicked = _submit_email_otp_if_needed(driver)
            submitted = submitted or bool(clicked)
            if clicked:
                logger.info("%s[OTP] 已提交邮箱验证码，等待资料页或登录态", _log_prefix(driver))
        except Exception as exc:
            logger.info("%s[OTP] 未找到显式提交按钮，继续等待页面状态：%s", _log_prefix(driver), str(exc)[:120])

        outcome = _wait_after_email_otp_submit(driver, timeout=wait_timeout)
        if outcome in {"accepted", "explicit_invalid", "route_error"}:
            # 自动提交时没有显式 click 返回值，但这些服务端结果足以证明验证码已提交。
            submitted = True
        if outcome == "pending":
            pending_state = _email_otp_page_state(driver)
            if (
                _can_retry_same_otp_submission(pending_state, code)
                and pending_attempt < max(0, int(max_pending_retries or 0))
            ):
                pending_attempt += 1
                logger.warning(
                    "%s[OTP] 提交后原验证码和 validate 按钮仍在，同一 Profile 不重填、不重发，仅再次提交原表单（%s/%s）",
                    _log_prefix(driver), pending_attempt, max_pending_retries,
                )
                _check_manual_stop()
                _sleep_with_manual_stop(1.0)
                reuse_existing_value = True
                continue
        if outcome != "route_error":
            return outcome, submitted

        while outcome == "route_error":
            _check_manual_stop()
            if route_attempt >= max(0, int(max_route_retries or 0)):
                return outcome, submitted
            route_attempt += 1
            logger.warning(
                "%s[OTP] 检测到 Route Error，同页点击 Try again 并复用当前验证码（%s/%s）",
                _log_prefix(driver), route_attempt, max_route_retries,
            )
            _click_route_error_retry(driver, timeout=10)
            outcome, _recovered = _wait_for_route_error_recovery(driver, timeout=15)
            if outcome == "accepted":
                return outcome, submitted
            if outcome in {"network_error", "explicit_invalid"}:
                return outcome, submitted
            if outcome == "pending":
                break


def _complete_email_otp_challenge(
    driver,
    email: str,
    *,
    otp_code: str | None = None,
    otp_after_ts: float | None = None,
    max_otp_attempts: int = 3,
    on_otp_entered=None,
) -> set[str]:
    """完成邮箱 OTP 状态机，仅 explicit_invalid 会触发重发并重新取码。"""
    requested_after = float(otp_after_ts if otp_after_ts is not None else time.time())
    current_otp = otp_code
    submitted_otp_codes: set[str] = set()
    attempts = max(1, int(max_otp_attempts or 1))

    for otp_attempt in range(1, attempts + 1):
        _check_manual_stop()
        initial_state = _email_otp_page_state(driver)
        initial_outcome = _classify_email_otp_state(initial_state)
        if initial_outcome == "accepted" or _has_access_token(driver):
            logger.info("%s[OTP] 页面已进入资料页/登录态，跳过邮箱取码", _log_prefix(driver))
            return submitted_otp_codes
        if initial_outcome == "network_error":
            raise RuntimeError(f"OTP 前页面发生浏览器网络异常: {initial_state}")
        if initial_outcome == "route_error":
            raise RuntimeError(f"OTP 前页面发生 Route Error: {initial_state}")
        if current_otp is None:
            logger.info("%s[OTP] 等待验证码：%s（第 %s/%s 次）", _log_prefix(driver), email, otp_attempt, attempts)
            try:
                current_otp = wait_for_otp(
                    email,
                    after_ts=requested_after,
                    exclude_codes=submitted_otp_codes,
                )
            except Exception as exc:
                _check_manual_stop()
                if getattr(exc, "resend_recommended", True) is False:
                    logger.warning(
                        "%s[OTP] 邮箱取码基础设施失败，不触发验证码重发：%s: %s",
                        _log_prefix(driver), type(exc).__name__, str(exc)[:220],
                    )
                    raise
                if otp_attempt >= attempts:
                    raise
                logger.warning(
                    "%s[OTP] 一直未收到验证码，点击“重新发送电子邮件”后继续等待（下一轮 %s/%s）：%s: %s",
                    _log_prefix(driver), otp_attempt + 1, attempts, type(exc).__name__, str(exc)[:180],
                )
                requested_after = time.time()
                resend = _click_resend_email_otp(driver, timeout=25)
                recovered_state = _wait_for_otp_form_ready(
                    driver,
                    fallback_url=str(resend.get("url") or ""),
                    email=email,
                )
                if recovered_state.get("_verified"):
                    logger.info("%s[OTP] 邮箱已验证，无需继续取码", _log_prefix(driver))
                    return submitted_otp_codes
                human_delay("api")
                current_otp = None
                continue

        logger.info("%s[OTP] 收到验证码：%s", _log_prefix(driver), current_otp)
        ready_state = _wait_for_otp_form_ready(driver, email=email)
        if ready_state.get("_verified"):
            logger.info("%s[OTP] 邮箱已验证，无需再次填写验证码", _log_prefix(driver))
            return submitted_otp_codes
        if ready_state.get("_recovered"):
            requested_after = float(ready_state.get("_recovered_at") or time.time())
            logger.warning("%s[OTP] 填码前验证页已重建，丢弃此前取得的验证码并等待新码", _log_prefix(driver))
            current_otp = None
            continue

        outcome, was_submitted = _submit_email_otp_with_route_recovery(
            driver,
            str(current_otp),
            # 服务端确认可能明显晚于按钮点击；先完整观察 30 秒。只有原值和
            # validate 按钮都还在时，才在同一 Profile 原样重提一次，不重发邮件。
            wait_timeout=30,
            max_route_retries=2,
            max_pending_retries=1,
            on_otp_entered=on_otp_entered,
        )
        if was_submitted:
            submitted_otp_codes.add(str(current_otp))
        if outcome == "accepted":
            return submitted_otp_codes
        if outcome == "network_error":
            raise RuntimeError("OTP 提交后浏览器网络异常，未判定为验证码错误")
        if outcome == "route_error":
            raise RuntimeError("OTP 提交后 Route Error 同页重试仍失败")
        if outcome == "pending":
            raise RuntimeError("OTP 提交后页面未返回明确结果，未重发验证码")
        if outcome != "explicit_invalid":
            raise RuntimeError(f"OTP 提交后返回未知状态: {outcome}")
        if otp_attempt >= attempts:
            raise RuntimeError("邮箱验证码连续错误/过期，已达到最大重试次数")

        logger.warning(
            "%s[OTP] 验证码错误/过期，准备重新发送并重新获取验证码（%s/%s）",
            _log_prefix(driver), otp_attempt + 1, attempts,
        )
        requested_after = time.time()
        resend = _click_resend_email_otp(driver, timeout=25)
        recovered_state = _wait_for_otp_form_ready(
            driver,
            fallback_url=str(resend.get("url") or ""),
            email=email,
        )
        if recovered_state.get("_verified"):
            logger.info("%s[OTP] 邮箱已验证，无需继续重试验证码", _log_prefix(driver))
            return submitted_otp_codes
        human_delay("api")
        current_otp = None

    raise RuntimeError("邮箱验证码流程未完成")


def _submit_email_otp_if_needed(driver) -> bool:
    """OTP 控件仍存在时才点击提交；控件消失通常表示页面已自动提交。"""
    state = _email_otp_page_state(driver)
    if _is_email_verified_success_state(state):
        logger.info("%s[OTP] 页面已显示 Email verified，不再点击提交按钮", _log_prefix(driver))
        return False
    if not _otp_inputs_ready(state):
        logger.info("%s[OTP] OTP 输入框已消失，按自动提交处理，不再点击页面按钮", _log_prefix(driver))
        return False
    submit_button = driver.execute_script(r"""
    window.__roxy_otp_submit_debug = {ok:false, reason:'not_started'};
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
    const enabled = el => visible(el) && !el.disabled
      && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
    const otpMarker = el => {
      const attrs = [el.name, el.id, el.autocomplete, el.getAttribute('aria-label'), el.placeholder]
        .join(' ').toLowerCase();
      return /one-time|otp|code/.test(attrs);
    };
    const inputs = [...document.querySelectorAll('input')].filter(visible);
    const segmented = inputs.filter(el => el.maxLength === 1 && /numeric|tel/.test(`${el.type} ${el.inputMode}`.toLowerCase()));
    const otp = inputs.find(otpMarker) || ((segmented.length >= 4 && segmented.length <= 8) ? segmented[0] : null);
    if (!otp) {
      window.__roxy_otp_submit_debug = {ok:false, reason:'missing_otp_input'};
      return null;
    }
    const form = otp.closest('form');
    if (!form) {
      window.__roxy_otp_submit_debug = {ok:false, reason:'missing_otp_form'};
      return null;
    }
    const candidates = [...form.querySelectorAll('button,input[type="submit"],[role="button"]')].filter(enabled);
    const attrs = el => [
      el.name, el.value, el.id, el.getAttribute('data-dd-action-name'),
      el.getAttribute('data-testid'), el.getAttribute('aria-label'), el.type
    ].join(' ').toLowerCase();
    const bad = /resend|send[-_\s]*(new|again)|retry|try[-_\s]*again/;
    const strong = /validate|verify|verification|submit[-_\s]*(otp|code)|continue/;
    const submit = candidates.find(el => strong.test(attrs(el)) && !bad.test(attrs(el)))
      || (() => {
        const safe = candidates.filter(el => !bad.test(attrs(el)) && String(el.type || '').toLowerCase() === 'submit');
        return safe.length === 1 ? safe[0] : null;
      })();
    if (!submit) {
      window.__roxy_otp_submit_debug = {ok:false, reason:'missing_unambiguous_otp_submit'};
      return null;
    }
    submit.scrollIntoView({block:'center'});
    window.__roxy_otp_submit_debug = {
      ok:true,
      reason:'otp_form_submit_target',
      attrs:attrs(submit).slice(0,160)
    };
    return submit;
    """)
    detail = driver.execute_script(
        "return window.__roxy_otp_submit_debug || {ok:false, reason:'missing_debug'};"
    ) or {"ok": False, "reason": "missing_debug"}
    if submit_button is None:
        raise RuntimeError(f"找不到明确的 OTP 提交按钮: result={detail}, state={state}")
    if submit_button is not None:
        _human_click(driver, submit_button, label="otp_submit")
        detail["reason"] = "clicked_otp_form_submit"
    logger.info("%s[OTP] 已点击验证码表单提交按钮：%s", _log_prefix(driver), detail)
    return True


def _advance_from_email_verified_page(driver, timeout: float = 5.0) -> bool:
    """成功页未自动跳转时进入资料页，保留当前认证会话上下文。"""
    state = _email_otp_page_state(driver)
    if not _is_email_verified_success_state(state):
        return False
    end = time.time() + max(0.0, float(timeout or 0))
    while time.time() < end:
        _check_manual_stop()
        _sleep_with_manual_stop(0.5)
        state = _email_otp_page_state(driver)
        if not _is_email_verified_success_state(state):
            return True
    logger.info("%s[OTP] Email verified 成功页未自动跳转，进入 about-you", _log_prefix(driver))
    _navigate_page(driver, "https://auth.openai.com/about-you")
    return True


def _click_continue(driver) -> None:
    _click_any(driver, [
        "button[type='submit']",
        "//button[contains(., 'Continue')]",
        "//button[contains(., '继续')]",
        "//button[contains(., 'Sign up')]",
        "//button[contains(., 'Create')]",
        "//button[contains(., 'Next')]",
    ], timeout=20)


def _maybe_accept(driver) -> None:
    # 只处理明确的 welcome/cookie/consent 弹层按钮；不要用 “Continue” 兜底，
    # 非日本出口时 “Continue with Google” 也会命中，导致误点 Google 登录。
    for selectors in ([
        "a#dismiss-welcome",
        "button#dismiss-welcome",
        "button#onetrust-accept-btn-handler",
        "button[data-testid='cookie-accept']",
        "button[data-testid='accept-cookies']",
        "//button[contains(., 'Accept')]",
        "//button[contains(., '同意')]",
        "//button[contains(., 'Agree')]",
    ],):
        try:
            _click_any(driver, selectors, timeout=3)
            time.sleep(0.5)
        except Exception:
            pass


def _page_snapshot(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const inputs = [...document.querySelectorAll('input,select,textarea')].map(el => ({
          tag: el.tagName, type: el.getAttribute('type') || '', name: el.getAttribute('name') || '',
          id: el.id || '', placeholder: el.getAttribute('placeholder') || '',
          autocomplete: el.getAttribute('autocomplete') || '', aria: el.getAttribute('aria-label') || '',
          value: el.value || '', visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        })).filter(x => x.visible).slice(0, 30);
        const buttons = [...document.querySelectorAll('button,[role=button],input[type=submit]')].map(el => ({
          text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim(),
          type: el.getAttribute('type') || '', visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length),
          action: el.getAttribute('data-dd-action-name') || '', aria: el.getAttribute('aria-label') || '',
          testid: el.getAttribute('data-testid') || '', disabled: !!el.disabled
        })).filter(x => x.visible).slice(0, 30);
        const widgets = [...document.querySelectorAll('[role=spinbutton], .react-aria-Select, [data-testid="hidden-select-container"] select')].map(el => ({
          tag: el.tagName, role: el.getAttribute('role') || '', dataType: el.getAttribute('data-type') || '',
          aria: el.getAttribute('aria-label') || '', text: (el.innerText || el.textContent || '').trim().slice(0, 80),
          visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        })).slice(0, 30);
        return {url: location.href, title: document.title, text: (document.body?.innerText || '').slice(0, 2000), inputs, buttons, widgets};
        """) or {}
    except Exception as exc:
        try:
            current_url = str(driver.current_url or '')
        except Exception:
            current_url = ''
        return {"error": f"{type(exc).__name__}: {exc}", "url": current_url}


def _stop_background_loading_after_auth(driver) -> bool:
    """AT 已确认后停止首页尾部资源；不会在认证完成前调用。"""
    if not bool(getattr(_cfg, "ROXY_LOW_TRAFFIC_MODE", True)):
        return False
    cache = getattr(driver, "__dict__", None)
    if isinstance(cache, dict) and cache.get("_roxy_post_auth_loading_stopped"):
        return True
    stopped = False
    try:
        driver.execute_cdp_cmd("Page.stopLoading", {})
        stopped = True
    except Exception:
        try:
            driver.execute_script("window.stop();")
            stopped = True
        except Exception:
            logger.debug("%s AT 已确认但停止尾部资源失败", _log_prefix(driver), exc_info=True)
    if stopped and isinstance(cache, dict):
        cache["_roxy_post_auth_loading_stopped"] = True
    return stopped


def _has_access_token(driver) -> bool:
    try:
        current = urlparse(str(driver.current_url or ""))
    except Exception:
        return False
    if str(current.hostname or "").lower() != "chatgpt.com" or str(current.path or "").startswith("/auth/login"):
        return False

    cache = getattr(driver, "__dict__", None)
    now = time.monotonic()
    if isinstance(cache, dict):
        last_at = cache.get("_roxy_access_token_probe_at")
        if isinstance(last_at, (int, float)) and now - last_at < _ACCESS_TOKEN_PROBE_MIN_INTERVAL_SECONDS:
            return bool(cache.get("_roxy_access_token_probe_result", False))
    try:
        result = driver.execute_async_script(r"""
        const done = arguments[0];
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3000);
        fetch('/api/auth/session', {credentials:'include', signal:controller.signal})
          .then(r => r.json()).then(j => done(Boolean(j && j.accessToken)))
          .catch(() => done(false)).finally(() => clearTimeout(timer));
        """)
        found = bool(result)
    except Exception:
        found = False
    if found:
        _stop_background_loading_after_auth(driver)
    if isinstance(cache, dict):
        cache["_roxy_access_token_probe_at"] = now
        cache["_roxy_access_token_probe_result"] = found
    return found


def _is_profile_like(snapshot: dict) -> bool:
    """资料页识别：兼容 about-you/profile；年龄/生日控件可能不是 input，而是 React Aria widget。"""
    url = str(snapshot.get('url') or '').lower()
    inputs = snapshot.get('inputs') or []
    widgets = snapshot.get('widgets') or []
    attrs = ' '.join(
        ' '.join(str(i.get(k) or '') for k in ('name', 'id', 'placeholder', 'autocomplete', 'aria', 'type')).lower()
        for i in inputs
    )
    widget_attrs = ' '.join(
        ' '.join(str(i.get(k) or '') for k in ('role', 'dataType', 'aria', 'text', 'tag')).lower()
        for i in widgets
    )
    has_profile_url = any(x in url for x in ('about-you', 'profile', 'signup/profile', 'create-account/profile'))
    has_name_field = (
        'autocomplete name' in attrs
        or ' name ' in f' {attrs} '
        or 'fullname' in attrs
        or 'full_name' in attrs
        or 'firstname' in attrs
        or 'lastname' in attrs
    )
    has_age_or_birth_field = any(x in f' {attrs} {widget_attrs} ' for x in (
        ' age', '-age', '_age', 'birth', 'birthday', 'birthdate',
        ' month', '-month', '_month', 'data-type month',
        ' day', '-day', '_day', 'data-type day',
        ' year', '-year', '_year', 'data-type year',
        'spinbutton', 'react-aria-select', 'type number',
    ))
    # about-you/profile URL 本身已经足够强；部分新版页面会用无 name 的 React Aria 控件。
    return has_profile_url and (has_name_field or has_age_or_birth_field or bool(inputs) or bool(widgets))


def _set_element_value(driver, el, value: str) -> None:
    """兼容 React 受控输入框：用原生 setter 设置值并派发 input/change。"""
    driver.execute_script(r"""
    const el = arguments[0];
    const value = String(arguments[1]);
    const tag = (el.tagName || '').toLowerCase();
    el.scrollIntoView({block:'center'});
    el.focus();
    if (tag === 'select') {
      el.value = value;
    } else {
      const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      if (setter) setter.call(el, value);
      else el.value = value;
    }
    el.dispatchEvent(new Event('input', {bubbles:true}));
    el.dispatchEvent(new Event('change', {bubbles:true}));
    el.blur();
    """, el, value)


def _select_or_type(driver, selectors: list[str], value: str, timeout: int = 3) -> bool:
    try:
        el = _find_any(driver, selectors, timeout=timeout)
    except Exception:
        return False
    try:
        tag = (el.tag_name or '').lower()
        if tag == 'select':
            if el.__class__.__name__ == 'CloakElement':
                driver.execute_script(r"""
                const el = arguments[0], value = String(arguments[1]);
                const n = parseInt(value, 10);
                const opts = [...el.options];
                const match = opts.find(o => o.value === value)
                  || opts.find(o => (o.textContent || '').trim() === value)
                  || opts[Math.max(0, n - 1)];
                if (match) el.value = match.value; else el.value = value;
                el.dispatchEvent(new Event('input', {bubbles:true}));
                el.dispatchEvent(new Event('change', {bubbles:true}));
                """, el, str(value))
            else:
                from selenium.webdriver.support.ui import Select
                sel = Select(el)
                try:
                    sel.select_by_value(str(int(value)))
                except Exception:
                    try:
                        sel.select_by_visible_text(str(int(value)))
                    except Exception:
                        # 月份 select 可能是 0-based，也可能是 1-based；先 value/text，不行再 index。
                        sel.select_by_index(max(0, int(value)-1))
                driver.execute_script("arguments[0].dispatchEvent(new Event('change', {bubbles:true}));", el)
        else:
            _human_type_text(driver, el, str(value), clear=True)
        return True
    except Exception as exc:
        logger.debug('%s 填写字段失败 selectors=%s value=%s err=%s', _log_prefix(driver), selectors, value, exc)
        return False


def _fill_birthday_or_age(driver, birthday: str, age: int) -> str | None:
    """填写 about-you 的年龄/生日控件。

    参考 FlowPilot：优先处理直接年龄 input；否则兼容 hidden birthday/date、原生年月日
    select/input、React Aria hidden native select、role=spinbutton[data-type=year/month/day]。
    返回 age / birthday / ymd / react_select / spinbutton / None。
    """
    y, m, d = birthday.split('-')
    result = driver.execute_script(r"""
    const birthday = String(arguments[0]);
    const year = String(arguments[1]);
    const month = String(Number(arguments[2]));
    const month2 = String(arguments[2]).padStart(2, '0');
    const day = String(Number(arguments[3]));
    const day2 = String(arguments[3]).padStart(2, '0');
    const age = String(arguments[4]);
    const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
      && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
      && !el.disabled && !el.readOnly;
    const setValue = (el, value) => {
      if (!el) return false;
      el.scrollIntoView?.({block:'center'});
      el.focus?.();
      const tag = (el.tagName || '').toLowerCase();
      const proto = tag === 'textarea' ? HTMLTextAreaElement.prototype
        : tag === 'select' ? HTMLSelectElement.prototype
        : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
      if (setter) setter.call(el, String(value)); else el.value = String(value);
      if (tag === 'select') {
        [...el.options].forEach(opt => { opt.selected = String(opt.value) === String(value); });
      }
      el.dispatchEvent(new Event('input', {bubbles:true}));
      el.dispatchEvent(new Event('change', {bubbles:true}));
      el.blur?.();
      return true;
    };
    const ageInput = [...document.querySelectorAll('input[name="age"], input#age, input[id$="-age"], input[type="number"]')]
      .find(visible);
    if (ageInput && setValue(ageInput, age)) return {ok:true, mode:'age'};

    const dateInput = [...document.querySelectorAll('input[name="birthdate"], input[type="date"], input[name="birthday"]')]
      .find(el => visible(el) || String(el.getAttribute('type') || '').toLowerCase() === 'date');
    if (dateInput && setValue(dateInput, birthday)) return {ok:true, mode:'birthday'};

    const setFirst = (selectors, values) => {
      for (const sel of selectors) {
        for (const el of [...document.querySelectorAll(sel)]) {
          if (!visible(el)) continue;
          for (const val of values) {
            if (el.tagName === 'SELECT') {
              const has = [...el.options].some(o => String(o.value) === String(val) || String(o.textContent || '').trim() === String(val));
              if (!has) continue;
            }
            if (setValue(el, val)) return true;
          }
        }
      }
      return false;
    };
    const yOk = setFirst(['select[name="year"]','input[name="year"]','select[id*="year"]','input[id*="year"]'], [year]);
    const mOk = setFirst(['select[name="month"]','input[name="month"]','select[id*="month"]','input[id*="month"]'], [month, month2]);
    const dOk = setFirst(['select[name="day"]','input[name="day"]','select[id*="day"]','input[id*="day"]'], [day, day2]);
    if (yOk && mOk && dOk) {
      const hidden = document.querySelector('input[name="birthday"]');
      if (hidden) setValue(hidden, birthday);
      return {ok:true, mode:'ymd'};
    }

    // React Aria Select 通常有 hidden native select；不依赖标签文字，按 option 数值范围和 DOM 顺序推断年/月/日。
    const selects = [...document.querySelectorAll('[data-testid="hidden-select-container"] select, .react-aria-Select select, select')]
      .filter(el => !el.disabled);
    const nums = sel => [...sel.options].map(o => Number(o.value)).filter(Number.isFinite);
    const maxNum = sel => Math.max(...nums(sel), -Infinity);
    const minNum = sel => Math.min(...nums(sel), Infinity);
    const hasOption = (sel, val) => [...sel.options].some(o => String(o.value) === String(val));
    const yearSelects = selects.filter(sel => hasOption(sel, year) && maxNum(sel) > 1900);
    const smallSelects = selects.filter(sel => !yearSelects.includes(sel));
    const monthSelects = smallSelects.filter(sel => (hasOption(sel, month) || hasOption(sel, month2)) && minNum(sel) <= 1 && maxNum(sel) <= 12);
    const daySelects = smallSelects.filter(sel => (hasOption(sel, day) || hasOption(sel, day2)) && maxNum(sel) >= 28);
    if (yearSelects.length && monthSelects.length && daySelects.length) {
      const ys = yearSelects[0];
      let ms = monthSelects[0];
      let ds = daySelects.find(x => x !== ms) || daySelects[0];
      setValue(ys, year);
      setValue(ms, hasOption(ms, month) ? month : month2);
      setValue(ds, hasOption(ds, day) ? day : day2);
      const hidden = document.querySelector('input[name="birthday"]');
      if (hidden) setValue(hidden, birthday);
      return {ok:true, mode:'react_select'};
    }

    const spinYear = document.querySelector('[role="spinbutton"][data-type="year"]');
    const spinMonth = document.querySelector('[role="spinbutton"][data-type="month"]');
    const spinDay = document.querySelector('[role="spinbutton"][data-type="day"]');
    if (spinYear && spinMonth && spinDay) return {ok:false, mode:'spinbutton_needed'};
    return {ok:false, mode:'missing'};
    """, birthday, y, m, d, str(age)) or {}
    if result.get('ok'):
        return str(result.get('mode') or 'birthday')
    if result.get('mode') != 'spinbutton_needed':
        return None

    try:
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.keys import Keys
        mod = Keys.COMMAND
        try:
            import platform
            if platform.system().lower() != 'darwin':
                mod = Keys.CONTROL
        except Exception:
            pass
        for selector, value in [
            ('[role="spinbutton"][data-type="year"]', y),
            ('[role="spinbutton"][data-type="month"]', str(m).zfill(2)),
            ('[role="spinbutton"][data-type="day"]', str(d).zfill(2)),
        ]:
            el = driver.find_element(By.CSS_SELECTOR, selector)
            driver.execute_script("arguments[0].scrollIntoView({block:'center'}); arguments[0].focus();", el)
            time.sleep(0.1)
            el.send_keys(mod, 'a')
            time.sleep(0.05)
            el.send_keys(str(value))
            time.sleep(0.1)
            driver.execute_script("arguments[0].dispatchEvent(new Event('input', {bubbles:true})); arguments[0].dispatchEvent(new Event('change', {bubbles:true})); arguments[0].blur();", el)
        driver.execute_script(r"""
        const hidden = document.querySelector('input[name="birthday"]');
        if (hidden) {
          const value = arguments[0];
          const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
          if (setter) setter.call(hidden, value); else hidden.value = value;
          hidden.dispatchEvent(new Event('input', {bubbles:true}));
          hidden.dispatchEvent(new Event('change', {bubbles:true}));
        }
        """, birthday)
        return 'spinbutton'
    except Exception as exc:
        logger.debug('%s spinbutton 生日填写失败：%s', _log_prefix(driver), exc)
        return None


def _generate_roxy_password() -> str:
    """参考 FlowPilot 密码策略：8~64 位，含大小写、数字、符号。"""
    upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    lower = 'abcdefghjkmnpqrstuvwxyz'
    digits = '23456789'
    # '-' is reserved by the account export delimiter (``----``).
    symbols = "!@#$%^&*?_+="
    groups = [upper, lower, digits, symbols]
    all_chars = ''.join(groups)
    chars = [random.choice(g) for g in groups]
    while len(chars) < 14:
        chars.append(random.choice(all_chars))
    random.shuffle(chars)
    return ''.join(chars)


def _registration_password() -> str:
    try:
        from config import register as _register_cfg
        configured = str(getattr(_register_cfg, 'REGISTER_PASSWORD', '') or '').strip()
        if configured:
            return configured
    except Exception:
        pass
    return _generate_roxy_password()


def _registration_password_required() -> bool:
    try:
        from config import register as _register_cfg

        return bool(getattr(_register_cfg, "REQUIRE_REGISTRATION_PASSWORD", True))
    except Exception:
        return True


def _password_page_state(driver) -> dict:
    try:
        return driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const inputs = [...document.querySelectorAll('input')].map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          autocomplete: el.getAttribute('autocomplete') || '', visible: visible(el), value: el.type === 'password' ? '<password>' : (el.value || '')
        })).slice(0, 30);
        const forms = [...document.querySelectorAll('form')].map(f => ({action: f.getAttribute('action') || ''}));
        const buttons = [...document.querySelectorAll('button,input[type="submit"]')].map(el => ({
          type: el.getAttribute('type') || '', name: el.getAttribute('name') || '', id: el.id || '',
          disabled: !!el.disabled, visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
        })).slice(0, 30);
        const secrets = [...document.querySelectorAll('input')].filter(el =>
          el.type === 'password' || el.autocomplete === 'one-time-code' || /^(code|otp|passcode)$/.test(el.name)
        ).map(el => el.value).filter(Boolean);
        const redact = value => {
          let text = String(value || '');
          for (const secret of secrets) text = text.split(secret).join('<redacted>');
          return text.slice(0, 300);
        };
        const errors = [...document.querySelectorAll('[role="alert"],.react-aria-FieldError,[slot="errorMessage"],[id$="-error"]')]
          .filter(el => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length))
          .map(el => redact(el.innerText || el.textContent)).filter(Boolean).slice(0, 5);
        const invalid = [...document.querySelectorAll('input')].filter(el => visible(el) && el.validity && !el.validity.valid)
          .map(el => ({name: el.name || '', valueMissing: el.validity.valueMissing,
            patternMismatch: el.validity.patternMismatch, tooShort: el.validity.tooShort, tooLong: el.validity.tooLong}));
        for (const input of inputs) {
          if (secrets.includes(input.value)) input.value = '<redacted>';
        }
        return {url: location.href, title: document.title, inputs, forms, buttons, errors, invalid};
        """) or {}
    except Exception as exc:
        return {"url": getattr(driver, "current_url", ""), "error": f"{type(exc).__name__}: {exc}"}


def _is_signup_password_page(driver) -> bool:
    state = _password_page_state(driver)
    url = str(state.get('url') or '').lower()
    if any(x in url for x in ('/create-account/password', '/u/signup/password', '/signup/password')):
        return True
    if '/log-in/password' in url:
        return False
    inputs = state.get('inputs') or []
    return any(
        i.get('visible') and (
            str(i.get('type') or '').lower() == 'password'
            or 'password' in str(i.get('name') or '').lower()
            or str(i.get('autocomplete') or '').lower() == 'new-password'
        )
        for i in inputs
    )


def _is_login_password_page(driver) -> bool:
    try:
        url = str(driver.current_url or '').lower()
    except Exception:
        url = ''
    if '/log-in/password' in url:
        return True
    state = _password_page_state(driver)
    url = str(state.get('url') or '').lower()
    return '/log-in/password' in url


def _click_passwordless_signup_if_present(driver) -> dict:
    """
    新版注册/登录流在 password 页可能默认要求密码。
    如果页面提供“使用一次性验证码”按钮，优先点击进入邮箱 OTP 页面。
    """
    try:
        button = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none';
        const enabled = el => !el.disabled && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
        const norm = s => String(s || '').replace(/\s+/g, '').toLowerCase();
        const candidates = [...document.querySelectorAll('button,a,input[type="submit"],[role="button"],[role="link"]')].filter(el => visible(el) && enabled(el));
        const isPasswordlessOtp = el => {
          const name = String(el.getAttribute('name') || '').toLowerCase();
          const value = String(el.getAttribute('value') || '').toLowerCase();
          const attrs = [
            el.id, name, value, el.getAttribute('aria-label'), el.getAttribute('title'),
            el.getAttribute('data-testid'), el.getAttribute('data-dd-action-name'), el.className, el.textContent
          ].join(' ').toLowerCase();
          const text = norm(el.textContent || el.getAttribute('value') || '');
          return (
            (name === 'intent' && value.includes('passwordless') && value.includes('send_otp')) ||
            (name === 'intent' && value.includes('passwordless') && value.includes('otp')) ||
            (name === 'intent' && value === 'passwordless_signup_send_otp') ||
            (name === 'intent' && value === 'passwordless_login_send_otp') ||
            attrs.includes('passwordless_signup_send_otp') ||
            attrs.includes('passwordless_login_send_otp') ||
            /passwordless.*otp|otp.*passwordless|one[-_\s]?time.*code|code.*one[-_\s]?time/.test(attrs) ||
            text.includes('使用一次性验证码注册') ||
            text.includes('使用一次性验证码登录') ||
            text.includes('使用一次性验证码') ||
            text.includes('使用一次性驗證碼註冊') ||
            text.includes('使用一次性驗證碼登入') ||
            text.includes('一次性验证码') ||
            text.includes('一次性驗證碼') ||
            text.includes('メールでコード') ||
            text.includes('ワンタイムコード') ||
            text.includes('認証コード') ||
            text.includes('useonetimeregistrationcode') ||
            text.includes('useaone-timecodetosignup') ||
            text.includes('useaone-timecodetoregister') ||
            text.includes('useaone-timecodetologin') ||
            text.includes('continuewithaone-timecode') ||
            text.includes('loginwithaone-timecode') ||
            text.includes('signupwithaone-timecode') ||
            text.includes('one-timecode')
          );
        };
        const btn = candidates.find(isPasswordlessOtp);
        if (!btn) return null;
        btn.scrollIntoView({block:'center'});
        return btn;
        """)
        if button is None:
            return {"ok": False, "reason": "missing_passwordless_button"}
        result = driver.execute_script(r"""
        const btn = arguments[0];
        return {
          ok:true,
          reason:'passwordless_send_otp_target',
          name:btn.getAttribute('name') || '',
          value:btn.getAttribute('value') || '',
          text:(btn.textContent || '').trim().slice(0, 80)
        };
        """, button) or {"ok": True, "reason": "passwordless_send_otp_target"}
        _human_click(driver, button, label="passwordless_otp")
        result["reason"] = "clicked_passwordless_send_otp"
        return result
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _wait_for_password_submission(driver, timeout: float = 40.0) -> None:
    """只确认当前密码提交；截止时先读最终状态，避免跳转恰好被判成超时。"""
    end = time.monotonic() + max(0.0, float(timeout))
    while True:
        _check_manual_stop()
        if _is_email_verification_page(driver):
            logger.info("%s 密码提交后已进入邮箱验证码页", _log_prefix(driver))
            return
        if _has_access_token(driver):
            logger.info("%s 密码提交后已检测到登录态", _log_prefix(driver))
            return
        remaining = end - time.monotonic()
        if remaining <= 0:
            # 最后一次 URL 检查与 DOM 快照之间仍可能发生跳转，以最新快照为准。
            state = _password_page_state(driver)
            _raise_for_driver_session_lost(state, stage="密码提交后")
            _raise_for_browser_network_error(driver, state)
            _raise_for_registration_account_exists(state)
            url = str(state.get("url") or "").lower()
            if (
                "/log-in/password" not in url
                and ("email-verification" in url or "email-otp" in url or _otp_inputs_ready(state))
            ):
                logger.info("%s 密码提交等待结束时已确认邮箱验证码页", _log_prefix(driver))
                return
            if _has_access_token(driver):
                return
            raise RegistrationPasswordRequiredError(
                f"密码已提交，但远端未进入邮箱验证码或登录态，不能确认密码已生效: state={state}"
            )
        _sleep_with_manual_stop(min(0.5, remaining))


def _fill_password_page_if_present(driver, email: str, timeout: int = 25) -> str | None:
    """填写注册密码，并且只在远端进入后续步骤后返回本次密码。"""
    end = time.time() + timeout
    last = {}
    while time.time() < end:
        _check_manual_stop()
        if _is_email_verification_page(driver):
            return None
        if _has_access_token(driver):
            return None
        last = _password_page_state(driver)
        is_signup_password = _is_signup_password_page(driver)
        is_login_password = _is_login_password_page(driver)
        if not (is_signup_password or is_login_password):
            _sleep_with_manual_stop(0.5)
            continue
        if is_login_password:
            raise RegistrationPasswordRequiredError(
                "邮箱进入已有账号的登录密码页，不能确认本次注册密码"
            )
        password = _registration_password()
        logger.info("%s 检测到 create-account/password，准备设置密码（%s 位）：email=%s", _log_prefix(driver), len(password), email)
        input_element = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled && !el.readOnly;
        const input = [...document.querySelectorAll('input[type="password"],input[name*="password" i],input[autocomplete="new-password"]')]
          .find(visible);
        if (!input) return null;
        input.scrollIntoView({block:'center'});
        return input;
        """)
        if input_element is None:
            raise RuntimeError(f"密码页处理失败：missing_password_input state={last}")
        submit_button = driver.execute_script(r"""
        const input = arguments[0];
        const form = input && input.closest('form');
        const scope = form || document;
        const buttons = [...scope.querySelectorAll('button,input[type="submit"]')]
          .filter(el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && !el.disabled && el.getAttribute('aria-disabled') !== 'true')
          .map((el, idx) => {
            const r = el.getBoundingClientRect();
            const ir = input.getBoundingClientRect();
            return {el, idx, below: r.top >= ir.bottom - 10, dist: Math.max(0, r.top - ir.bottom) + Math.abs((r.left+r.right-ir.left-ir.right)/2)/10};
          })
          .filter(x => x.below)
          .sort((a,b) => a.dist - b.dist || a.idx - b.idx);
        if (!buttons.length) return null;
        buttons[0].el.scrollIntoView({block:'center'});
        return buttons[0].el;
        """, input_element)
        if submit_button is None:
            raise RuntimeError(f"密码页处理失败：missing_submit state={last}")
        _human_type_text(driver, input_element, password, clear=True)
        human_delay("form", minimum=0.4, maximum=1.4)
        _human_click(driver, submit_button, label="password_submit")
        logger.info("%s 已填写并提交密码页", _log_prefix(driver))
        _wait_for_password_submission(driver)
        return password
    logger.info("%s 未检测到密码页，继续后续流程 last=%s", _log_prefix(driver), last)
    return None


def _prepare_registration_password(
    driver,
    email: str,
    next_state: str,
    *,
    timeout: int = 25,
) -> str | None:
    """Prepare a real signup password or fail before a passwordless account is saved."""
    required = _registration_password_required()
    state = str(next_state or "").strip().lower()
    if state == "logged_in":
        if required:
            raise RegistrationPasswordRequiredError(
                "邮箱提交后直接进入登录态，无法确认本次注册密码"
            )
        return None

    if state == "otp" and required:
        logger.info(
            "%s 服务端默认进入 passwordless OTP，尝试切换到密码注册页",
            _log_prefix(driver),
        )
        _navigate_page(driver, _PASSWORD_SIGNUP_URL)
        _check_manual_stop()

    password = _fill_password_page_if_present(driver, email, timeout=timeout)
    if required and not password:
        raise RegistrationPasswordRequiredError(
            "服务端未提供可确认的密码注册路径；已阻止保存 passwordless 账号"
        )
    return password


def _accept_profile_consents(driver) -> int:
    """about-you/profile 下出现韩国/日本个人信息同意协议时，默认全部勾选。

    不依赖可见文字；优先处理 allCheckboxes，再处理所有必选 consent checkbox。
    """
    try:
        result = driver.execute_script(r"""
        const visible = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
          && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'
          && !el.disabled;
        const isChecked = el => el.checked === true || String(el.getAttribute('aria-checked') || el.closest('[role="checkbox"]')?.getAttribute('aria-checked') || '').toLowerCase() === 'true';
        const mark = el => {
          if (!el || isChecked(el)) return false;
          const label = el.closest('label');
          try {
            (label && visible(label) ? label : el).scrollIntoView({block:'center'});
            (label && visible(label) ? label : el).click();
          } catch (_) {}
          if (!isChecked(el)) {
            const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'checked')?.set;
            if (setter) setter.call(el, true); else el.checked = true;
            el.dispatchEvent(new MouseEvent('click', {bubbles:true}));
            el.dispatchEvent(new Event('input', {bubbles:true}));
            el.dispatchEvent(new Event('change', {bubbles:true}));
          }
          return isChecked(el);
        };
        const all = [...document.querySelectorAll('input[type="checkbox"]')]
          .filter(el => visible(el) || visible(el.closest('label')));
        if (!all.length) return {count:0, names:[]};
        const byName = name => all.find(el => String(el.name || '').toLowerCase() === name.toLowerCase());
        const ordered = [];
        const add = el => { if (el && !ordered.includes(el)) ordered.push(el); };
        add(byName('allCheckboxes'));
        for (const name of ['personalInfoConsent', 'thirdPartyConsent', 'overseasTransferConsent']) add(byName(name));
        for (const el of all) {
          const n = String(el.name || '').toLowerCase();
          const id = String(el.id || '').toLowerCase();
          if (/consent|checkbox|agree|required|personal|third|overseas/.test(`${n} ${id}`)) add(el);
        }
        // about-you/profile 页面里的 checkbox 基本都是必选 consent；剩余可见 checkbox 也全部勾选。
        for (const el of all) add(el);
        const clicked = [];
        for (const el of ordered) {
          if (mark(el)) clicked.push(el.name || el.id || 'checkbox');
        }
        return {count: clicked.length, names: clicked};
        """) or {}
        count = int(result.get('count') or 0)
        if count:
            logger.info("%s 已勾选 about-you/profile 同意协议复选框：%s", _log_prefix(driver), result.get('names'))
        return count
    except Exception as exc:
        logger.debug('%s 勾选 profile consent 失败：%s', _log_prefix(driver), exc)
        return 0


def _complete_profile_page(driver, name: str, birthday: str, timeout: int = 45) -> bool:
    """等待并完成姓名/生日页；若已经登录成功则返回 False，不把它当失败。"""
    end = time.time() + timeout
    y, m, d = birthday.split('-')
    from datetime import date
    today = date.today()
    age = today.year - int(y) - ((today.month, today.day) < (int(m), int(d)))
    last_snapshot = {}
    while time.time() < end:
        _check_manual_stop()
        _sleep_with_manual_stop(1)
        if _has_access_token(driver):
            logger.info('%s 已检测到登录态，资料页可能已跳过', _log_prefix(driver))
            return False
        snap = _page_snapshot(driver)
        last_snapshot = snap
        _raise_for_driver_session_lost(snap, stage="等待资料页")
        _raise_for_chatgpt_account_missing(snap)
        _raise_for_registration_account_exists(snap)
        outcome = _classify_email_otp_state(snap)
        if outcome == 'route_error':
            raise RuntimeError(f'等待资料页期间发生 Route Error: {snap}')
        if outcome == 'network_error':
            raise RuntimeError(f'等待资料页期间发生浏览器网络异常: {snap}')
        if _is_chatgpt_logged_in_state(snap):
            logger.info('%s 已进入 ChatGPT 登录界面，资料页已跳过', _log_prefix(driver))
            return False
        if not _is_profile_like(snap):
            logger.info('%s 等待资料页中：url=%s', _log_prefix(driver), snap.get('url'))
            continue

        logger.info('%s 检测到资料页，开始填写姓名生日：url=%s inputs=%s', _log_prefix(driver), snap.get('url'), snap.get('inputs'))
        name_ok = False
        # 常见单姓名字段
        for selectors in [
            ["input[name='name']", "input[name='fullName']", "input[name='full_name']", "input[autocomplete='name']"],
            ["input[placeholder*='Name']", "input[placeholder*='name']", "input[aria-label*='Name']", "input[aria-label*='name']"],
        ]:
            if _select_or_type(driver, selectors, name, timeout=3):
                logger.info("%s 已填写姓名字段：%s", _log_prefix(driver), name)
                name_ok = True
                break
        # 兼容 first/last 分开
        if not name_ok:
            parts = name.split(' ', 1)
            first = parts[0]
            last = parts[1] if len(parts) > 1 else 'User'
            first_ok = _select_or_type(driver, ["input[name='firstName']", "input[name='first_name']", "input[placeholder*='First']", "input[aria-label*='First']"], first, timeout=2)
            last_ok = _select_or_type(driver, ["input[name='lastName']", "input[name='last_name']", "input[placeholder*='Last']", "input[aria-label*='Last']"], last, timeout=2)
            name_ok = first_ok or last_ok

        birth_mode = _fill_birthday_or_age(driver, birthday, age)
        birth_ok = bool(birth_mode)
        if birth_ok:
            if birth_mode == 'age':
                logger.info("%s 已填写年龄字段：%s", _log_prefix(driver), age)
            else:
                logger.info("%s 已填写生日字段 mode=%s value=%s", _log_prefix(driver), birth_mode, birthday)

        if not name_ok or not birth_ok:
            logger.warning('%s 资料页字段未填完整 name_ok=%s birth_ok=%s snapshot=%s', _log_prefix(driver), name_ok, birth_ok, snap)
            continue

        _accept_profile_consents(driver)
        human_delay('form')
        for _ in range(3):
            _check_manual_stop()
            if _click_if_enabled_submit(driver):
                logger.info('%s 已尝试提交资料页，等待服务端结果', _log_prefix(driver))
                # 创建账号不可盲目重复提交；慢响应继续观察同一次请求，直到阶段截止。
                if _wait_after_profile_submit(driver, timeout=max(0.5, end - time.time())):
                    return True
                raise RuntimeError(
                    '资料页已尝试提交，但未确认服务端接受；已停止重复提交，需核对账号状态'
                )
            _sleep_with_manual_stop(1)
        logger.warning('%s 找不到可点击的资料页提交按钮 snapshot=%s', _log_prefix(driver), _page_snapshot(driver))
    raise RuntimeError(f'等待/填写资料页超时，最后页面：{last_snapshot}')


def _wait_after_profile_submit(driver, timeout: float = 15.0) -> bool:
    """确认资料提交真正离开 profile；点击动作本身不代表服务端已接受。"""
    end = time.time() + max(0.5, float(timeout or 0.5))
    last_snapshot: dict = {}
    while True:
        _check_manual_stop()
        if _has_access_token(driver):
            logger.info('%s 资料页提交后已检测到登录态', _log_prefix(driver))
            return True
        last_snapshot = _page_snapshot(driver)
        _raise_for_driver_session_lost(last_snapshot, stage="资料页提交后")
        _raise_for_chatgpt_account_missing(last_snapshot)
        _raise_for_registration_account_exists(last_snapshot)
        _raise_for_browser_network_error(driver, last_snapshot)
        outcome = _classify_email_otp_state(last_snapshot)
        if outcome == 'route_error':
            raise RuntimeError(f'资料页提交后 Route Error: {last_snapshot}')
        if outcome == 'network_error':
            raise RuntimeError(f'资料页提交后浏览器网络异常: {last_snapshot}')
        if not _is_profile_like(last_snapshot):
            url = str(last_snapshot.get('url') or '')
            if any(marker in url.lower() for marker in (
                'chatgpt.com', '/oauth/callback', '/callback', '/workspace',
            )):
                logger.info('%s 资料页已离开，等待 session：url=%s', _log_prefix(driver), url[:200])
                return True
        remaining = end - time.time()
        if remaining <= 0:
            break
        _sleep_with_manual_stop(min(0.5, remaining))
    logger.warning('%s 资料页提交后未观察到跳转：snapshot=%s', _log_prefix(driver), last_snapshot)
    return False


def _click_if_enabled_submit(driver) -> bool:
    """提交资料页：优先 form.requestSubmit/button[type=submit]，不依赖按钮文字。"""
    try:
        target = driver.execute_script(r"""
        const visible = (el) => !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
        const enabled = (el) => visible(el) && !el.disabled
          && String(el.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
        const forms = [...document.querySelectorAll('form')].filter(visible);
        for (const form of forms) {
          const submit = form.querySelector('button[type="submit"], input[type="submit"]');
          if (submit && enabled(submit)) {
            submit.scrollIntoView({block:'center'});
            return submit;
          }
          if (!submit && typeof form.requestSubmit === 'function' && (!form.checkValidity || form.checkValidity())) {
            form.requestSubmit();
            return 'submitted_by_requestSubmit';
          }
        }
        const submitters = [...document.querySelectorAll('button[type="submit"], input[type="submit"]')]
          .filter(enabled);
        if (submitters.length) {
          submitters[0].scrollIntoView({block:'center'});
          return submitters[0];
        }
        // 兜底：页面只有一个可点击 button 时点击它，但仍不读文字。
        const buttons = [...document.querySelectorAll('button:not([disabled])')].filter(enabled);
        if (buttons.length === 1) {
          buttons[0].scrollIntoView({block:'center'});
          return buttons[0];
        }
        return null;
        """)
        if not target:
            return False
        if isinstance(target, str):
            return True
        _human_click(driver, target, label="profile_submit", retry_ambiguous=False)
        return True
    except Exception as exc:
        _check_manual_stop()
        # requestSubmit/CDP/原生点击抛错时，请求可能已经送出。按已尝试处理，
        # 交由页面结果判断，不能返回 False 让外层再次创建账号。
        logger.warning(
            '%s 资料页提交动作未确认，等待页面结果：error=%s',
            _log_prefix(driver), type(exc).__name__,
        )
        return True


def _read_chatgpt_session_once(driver) -> dict | None:
    """当前页面必须在 chatgpt.com；读取 /api/auth/session，拿不到 token 返回 None。"""
    script = r"""
    const done = arguments[0];
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    fetch('/api/auth/session', {credentials: 'include', signal: controller.signal})
      .then(r => r.json())
      .then(j => done({ok: true, data: j}))
      .catch(e => done({ok: false, error: String(e)}))
      .finally(() => clearTimeout(timer));
    """
    result = driver.execute_async_script(script)
    if result and result.get("ok"):
        data = result.get("data") or {}
        if data.get("accessToken"):
            logger.info("%s /api/auth/session 已返回 accessToken", _log_prefix(driver))
            return data
        logger.info("%s 等待 ChatGPT session 写入 accessToken，当前响应 keys=%s", _log_prefix(driver), list(data.keys()))
    return None


def _validate_chatgpt_session_identity(
    session_info: dict,
    *,
    expected_email: str | None = None,
    previous_token: str | None = None,
) -> dict:
    token = str((session_info or {}).get("accessToken") or "")
    claims = token_claims(token)
    expected = str(expected_email or "").strip().lower()
    reported_emails = set()
    user = (session_info or {}).get("user")
    if isinstance(user, dict) and user.get("email"):
        reported_emails.add(str(user.get("email") or "").strip().lower())
    if claims.get("email"):
        reported_emails.add(str(claims.get("email") or "").strip().lower())
    reported_emails.discard("")
    if expected and not reported_emails:
        raise SessionIdentityError("ChatGPT session 缺少可校验邮箱，拒绝保存账号")
    if expected and any(value != expected for value in reported_emails):
        raise SessionIdentityError("ChatGPT session 邮箱与任务邮箱不匹配，拒绝保存账号")

    previous_claims = token_claims(str(previous_token or ""))
    previous_workspace = str(previous_claims.get("account_id") or "").strip()
    current_workspace = str(claims.get("account_id") or "").strip()
    if previous_workspace and current_workspace != previous_workspace:
        raise SessionIdentityError("ChatGPT session 刷新前后 workspace 不匹配，拒绝保存账号")
    if claims.get("token_expired") is True:
        raise SessionIdentityError("ChatGPT session 返回的 Web AT 已过期，拒绝保存账号")
    return session_info


def _refresh_chatgpt_session(
    driver,
    current: dict,
    attempts: int = 3,
    *,
    expected_email: str | None = None,
) -> dict:
    """Force one NextAuth rotation before freezing the newly registered session."""
    original_token = str((current or {}).get("accessToken") or "")
    best = dict(current or {})
    _validate_chatgpt_session_identity(best, expected_email=expected_email)
    max_attempts = max(1, min(3, int(attempts or 1)))
    script = r"""
    const done = arguments[0];
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    fetch('/api/auth/session?refresh=true', {
      method: 'GET', credentials: 'include', cache: 'no-store',
      headers: {'Accept': 'application/json'}, signal: controller.signal
    }).then(async r => {
      let data = null;
      try { data = await r.json(); } catch (_) {}
      done({ok: r.ok, status: r.status, data});
    }).catch(e => done({ok: false, status: 0, error: String(e)}))
      .finally(() => clearTimeout(timer));
    """
    for attempt in range(1, max_attempts + 1):
        try:
            result = driver.execute_async_script(script)
            data = (result or {}).get("data") if isinstance(result, dict) else None
            token = str((data or {}).get("accessToken") or "") if isinstance(data, dict) else ""
            if token:
                candidate = {**best, **data}
                _validate_chatgpt_session_identity(
                    candidate,
                    expected_email=expected_email,
                    previous_token=original_token,
                )
                best = candidate
                if token != original_token:
                    logger.info(
                        "%s /api/auth/session?refresh=true 已签发稳定 Web AT（第 %s 次）",
                        _log_prefix(driver),
                        attempt,
                    )
                    return best
        except Exception as exc:
            logger.debug(
                "%s 强制刷新 Web AT 暂时失败: %s: %s",
                _log_prefix(driver), type(exc).__name__, str(exc)[:160],
            )
        if attempt < max_attempts:
            _sleep_with_manual_stop(float(attempt))
    logger.warning(
        "%s session 强制刷新未观察到新 Web AT；保留当前登录态，后续验活可用 Cookie 自愈",
        _log_prefix(driver),
    )
    return best


def _switch_to_chatgpt_window_if_any(driver) -> bool:
    """有些浏览器/适配层会在新窗口完成 callback；尝试切到已有 chatgpt.com 句柄。"""
    try:
        handles = list(getattr(driver, "window_handles", []) or [])
        current_handle = None
        try:
            current_handle = getattr(driver, "current_window_handle", None)
        except Exception:
            current_handle = None
        for handle in handles:
            try:
                driver.switch_to.window(handle)
                if "chatgpt.com" in str(getattr(driver, "current_url", "") or ""):
                    return True
            except Exception:
                continue
        if current_handle is not None:
            try:
                driver.switch_to.window(current_handle)
            except Exception:
                pass
    except Exception:
        pass
    return False


def _open_session_probe_tab(driver) -> bool:
    """在新标签打开轻量 Session 接口，避免覆盖仍在完成的 OAuth callback。"""
    original_handle = None
    probe_handle = None
    try:
        switch_to = getattr(driver, "switch_to", None)
        new_window = getattr(switch_to, "new_window", None)
        if not callable(new_window):
            return False
        original_handle = getattr(driver, "current_window_handle", None)
        new_window("tab")
        probe_handle = getattr(driver, "current_window_handle", None)
        _navigate_page(driver, "https://chatgpt.com/api/auth/session", timeout=20)
        logger.info("%s 已在独立标签打开轻量 session 接口，保留原 OAuth 回调页", _log_prefix(driver))
        return True
    except Exception as exc:
        if original_handle is not None:
            try:
                if probe_handle is not None and probe_handle != original_handle:
                    driver.close()
                driver.switch_to.window(original_handle)
            except Exception:
                logger.debug("%s session 探测标签失败后恢复原窗口失败", _log_prefix(driver), exc_info=True)
        logger.warning(
            "%s 无法创建独立 session 探测标签，继续等待回调：%s: %s",
            _log_prefix(driver), type(exc).__name__, str(exc)[:180],
        )
        return False


def _fetch_chatgpt_session(
    driver,
    timeout: int = 90,
    auto_jump_wait: int = 15,
    *,
    expected_email: str | None = None,
) -> dict:
    """等待页面完成跳转并从 ChatGPT 页面内读取登录 session/accessToken。

    旧逻辑会在 auth.openai.com 上一直等到总超时，Cloak/部分 Chromium 场景下
    实际账号已创建成功但当前句柄 URL 没及时更新，导致白等 120 秒。现在只给
    自动跳转 `auto_jump_wait` 秒；超过后直接打开轻量 session 接口，不加载首页。
    """
    end = time.time() + timeout
    auto_jump_end = time.time() + max(3, int(auto_jump_wait or 15))
    destructive_fallback_end = auto_jump_end + 15
    last_data = None
    probe_tab_attempted = False
    destructive_open_attempted = False

    while time.time() < end:
        _check_manual_stop()
        try:
            current = str(driver.current_url or '')
        except Exception as exc:
            if _is_driver_session_lost_error(exc):
                raise BrowserSessionLostError(
                    f"About you 提交后 Roxy/Chrome 会话已丢失: {type(exc).__name__}: {exc}"
                ) from exc
            current = ''

        if 'chatgpt.com' not in current:
            if _switch_to_chatgpt_window_if_any(driver):
                current = str(getattr(driver, "current_url", "") or "")
            elif (
                time.time() >= auto_jump_end
                and any(marker in current.lower() for marker in ('/about-you', '/create-account/profile'))
            ):
                # 资料页尚未真正提交时不能导航到 session 接口，否则会销毁仍可恢复的表单。
                raise RuntimeError(f"资料页尚未完成，拒绝离开当前页面读取 session: {current[:240]}")
            elif time.time() >= auto_jump_end and not probe_tab_attempted:
                probe_tab_attempted = True
                if _open_session_probe_tab(driver):
                    current = str(getattr(driver, "current_url", "") or "")
                else:
                    last_data = "浏览器不支持独立 session 探测标签，继续等待 OAuth 回调"
            elif time.time() >= destructive_fallback_end and not destructive_open_attempted:
                # 兼容不支持新标签的适配层；额外等待 15 秒后才允许覆盖当前页，
                # 且只执行一次，避免中断一个只是稍慢的 OAuth callback。
                destructive_open_attempted = True
                try:
                    logger.info(
                        "%s 未在 %ss 内观察到回调完成，当前适配层无法新开标签，打开轻量 session 接口",
                        _log_prefix(driver), int(auto_jump_wait or 15) + 15,
                    )
                    _navigate_page(driver, "https://chatgpt.com/api/auth/session", timeout=20)
                    _sleep_with_manual_stop(0.5)
                    current = str(getattr(driver, "current_url", "") or "")
                except Exception as exc:
                    _check_manual_stop()
                    last_data = f"{type(exc).__name__}: {exc}"
            else:
                _sleep_with_manual_stop(1)
                continue

        if 'chatgpt.com' in current:
            try:
                data = _read_chatgpt_session_once(driver)
                if data:
                    data = _refresh_chatgpt_session(
                        driver,
                        data,
                        expected_email=expected_email,
                    )
                    _stop_background_loading_after_auth(driver)
                    return data
                last_data = "session 暂无 accessToken"
            except SessionIdentityError:
                raise
            except Exception as exc:
                _check_manual_stop()
                if _is_driver_session_lost_error(exc):
                    raise BrowserSessionLostError(
                        f"About you 提交后 Roxy/Chrome 会话已丢失: {type(exc).__name__}: {exc}"
                    ) from exc
                last_data = f"{type(exc).__name__}: {exc}"
        _sleep_with_manual_stop(2)

    raise RuntimeError(f"等待 /api/auth/session accessToken 超时，最后响应: {str(last_data)[:800]}")


def _load_chatgpt_app_after_registration(driver) -> bool:
    """AT 稳定后加载真实应用首页；导航失败不回滚已经完成的注册。"""
    if not bool(getattr(_cfg, "ROXY_POST_REGISTER_LOAD_APP", False)):
        return False
    try:
        dwell_seconds = max(
            0.0,
            float(getattr(_cfg, "ROXY_POST_REGISTER_DWELL_SECONDS", 5.0) or 0.0),
        )
    except (TypeError, ValueError):
        dwell_seconds = 5.0

    logger.info(
        "%s 注册会话已稳定，加载 ChatGPT 应用首页并驻留 %.1fs",
        _log_prefix(driver),
        dwell_seconds,
    )
    try:
        state = _navigate_page(driver, "https://chatgpt.com/")
        landed_url = str(
            (state or {}).get("url")
            or getattr(driver, "current_url", "")
            or ""
        )
        landed = urlparse(landed_url)
        if str(landed.hostname or "").lower() != "chatgpt.com":
            raise RuntimeError(f"应用首页落点异常: {landed_url[:240]}")
    except Exception as exc:
        logger.warning(
            "%s 注册后加载 ChatGPT 应用首页失败，保留已取得的账号继续保存：%s: %s",
            _log_prefix(driver),
            type(exc).__name__,
            str(exc)[:180],
        )
        return False

    if dwell_seconds > 0:
        _sleep_with_manual_stop(dwell_seconds)
    logger.info("%s ChatGPT 应用首页驻留完成", _log_prefix(driver))
    return True


def _check_manual_stop() -> None:
    try:
        from core.registration_service import check_stop_requested
        check_stop_requested()
    except ImportError:
        return


def _sleep_with_manual_stop(seconds: float) -> None:
    remaining = max(0.0, float(seconds or 0.0))
    while remaining > 0:
        _check_manual_stop()
        step = min(0.5, remaining)
        time.sleep(step)
        remaining -= step
    _check_manual_stop()


def _acquire_roxy_run_slot() -> None:
    if _ROXY_RUN_SLOTS.acquire(blocking=False):
        return
    logger.info("[Roxy] 当前运行数已达上限 %s，等待可用执行位", _ROXY_RUN_LIMIT)
    while True:
        _check_manual_stop()
        if _ROXY_RUN_SLOTS.acquire(timeout=0.5):
            return


def _sleep_before_roxy_retry(seconds: float) -> None:
    remaining = max(0.0, float(seconds or 0.0))
    while remaining > 0:
        _check_manual_stop()
        step = min(0.5, remaining)
        time.sleep(step)
        remaining -= step
    _check_manual_stop()


def _traffic_snapshot_with_base(snapshot: dict, base: dict | None = None) -> dict:
    """把当前 Profile 计数加到前序 Profile 基数，交给 DB 的单调快照逻辑。"""
    out = dict(snapshot or {})
    previous = dict(base or {})
    if str(out.get("measurement") or "") != "socks5_tunnel_payload":
        return out
    if str(previous.get("measurement") or "") != "socks5_tunnel_payload":
        return out
    for key in ("uploaded_bytes", "downloaded_bytes", "connection_count"):
        try:
            out[key] = max(0, int(previous.get(key) or 0)) + max(0, int(out.get(key) or 0))
        except (TypeError, ValueError):
            out[key] = max(0, int(out.get(key) or 0))
    out["total_bytes"] = int(out.get("uploaded_bytes") or 0) + int(out.get("downloaded_bytes") or 0)
    return out


def _job_roxy_traffic_base(job_id: int | None) -> dict:
    if job_id is None:
        return {}
    try:
        from core import db

        job = db.get_job(int(job_id)) or {}
        traffic = job.get("roxy_traffic")
        return dict(traffic) if isinstance(traffic, dict) else {}
    except Exception:
        logger.debug("[Roxy][流量] 读取重试累计基数失败", exc_info=True)
        return {}


def _finalize_job_roxy_traffic(job_id: int | None, outcome: str) -> None:
    if job_id is None:
        return
    try:
        from core import db

        job = db.get_job(int(job_id)) or {}
        traffic = job.get("roxy_traffic")
        if not isinstance(traffic, dict):
            return
        payload = dict(traffic)
        payload.update({
            "status": "complete" if payload.get("measurement") == "socks5_tunnel_payload" else "unavailable",
            "registration_outcome": "success" if outcome == "success" else "failed",
            "finished_at": datetime.now().isoformat(timespec="seconds"),
        })
        db.update_job_roxy_traffic(int(job_id), payload)
    except Exception:
        logger.exception("[Roxy][流量] 完成任务级流量统计失败")


def _release_standalone_roxy_email(result: dict) -> None:
    """CLI 直调没有 registration_service 托管时，最终失败仍需归还邮箱。"""
    try:
        from core.email_provider import release_email

        consumed = bool(result.get("email_consumed"))
        release_email(
            str(result.get("email") or ""),
            status="failed" if consumed else "available",
            note=f"Roxy注册最终失败: {str(result.get('error') or '')[:180]}",
        )
    except Exception:
        logger.debug("[Roxy] CLI 最终邮箱状态更新失败", exc_info=True)


def run_roxy_registration(
    email: str, name: str, birthday: str, proxy: str = None, otp_code: str = None,
    batch_dir: Path | None = None, codex_oauth: bool | None = None,
    job_id: int | None = None,
) -> dict:
    """限制全局并发，并在同一任务/邮箱内恢复可重试的网络故障。"""
    _acquire_roxy_run_slot()
    try:
        max_attempts = max(1, int(getattr(_cfg, "ROXY_REGISTRATION_MAX_ATTEMPTS", 3) or 3))
        base_delay = max(0.0, float(getattr(_cfg, "ROXY_REGISTRATION_RETRY_DELAY", 2.0) or 0.0))
        traffic_base: dict = {}
        used_proxy_urls: set[str] = set()
        last_result: dict = {
            "success": False,
            "email": email,
            "error": "Roxy 注册未执行",
            "retryable": False,
        }

        for attempt in range(1, max_attempts + 1):
            _check_manual_stop()
            logger.info("[Roxy注册] Profile 尝试 %s/%s，任务邮箱=%s", attempt, max_attempts, email)
            result = _run_roxy_registration_once(
                email,
                name,
                birthday,
                proxy=proxy,
                otp_code=otp_code,
                batch_dir=batch_dir,
                codex_oauth=codex_oauth,
                job_id=job_id,
                traffic_base=traffic_base,
                defer_traffic_finalization=True,
                used_proxy_urls=used_proxy_urls,
            )
            if not isinstance(result, dict):
                result = {
                    "success": False,
                    "email": email,
                    "error": "Roxy 注册未返回结构化结果",
                    "failure_stage": "result",
                    "retryable": False,
                    "retry_action": "none",
                }
            result["registration_attempt"] = attempt
            result["registration_max_attempts"] = max_attempts
            last_result = result
            traffic_base = _job_roxy_traffic_base(job_id)

            if result.get("success"):
                _finalize_job_roxy_traffic(job_id, "success")
                return result
            if bool(result.get("email_submitted")):
                if bool(result.get("retryable")) or result.get("retry_action") == "new_profile":
                    logger.error(
                        "[Roxy注册] 防御性终止跨 Profile 重试：邮箱提交状态已不确定，"
                        "stage=%s code=%s",
                        result.get("failure_stage") or "unknown",
                        result.get("failure_code") or "account_state_uncertain",
                    )
                    result["retryable"] = False
                    result["retry_action"] = "inspect_account"
                    result["failure_code"] = "account_state_uncertain"
                break
            if not bool(result.get("retryable")) or attempt >= max_attempts:
                break

            delay = retry_delay_seconds(attempt, base_delay=base_delay)
            logger.warning(
                "[Roxy注册] 可恢复失败，将关闭旧环境并在 %.1fs 后换新 Profile："
                "attempt=%s/%s stage=%s code=%s error=%s",
                delay,
                attempt,
                max_attempts,
                result.get("failure_stage") or "unknown",
                result.get("failure_code") or "registration_failed",
                str(result.get("error") or "")[:220],
            )
            _sleep_before_roxy_retry(delay)

        _finalize_job_roxy_traffic(job_id, "failed")
        if job_id is None:
            _release_standalone_roxy_email(last_result)
        return last_result
    finally:
        _ROXY_RUN_SLOTS.release()


def _run_roxy_registration_once(
    email: str, name: str, birthday: str, proxy: str = None, otp_code: str = None,
    batch_dir: Path | None = None, codex_oauth: bool | None = None,
    job_id: int | None = None,
    traffic_base: dict | None = None,
    defer_traffic_finalization: bool = False,
    used_proxy_urls: set[str] | None = None,
) -> dict:
    """Roxy 指纹浏览器自动化注册入口。"""
    client = RoxyBrowserClient()
    opened: RoxyOpenResult | None = None
    driver = None
    create_acknowledged = False
    email_submit_attempted = False
    email_submitted = False
    email_verified = False
    email_otp_entered = False
    failure_stage = "profile_open"
    openai_password: str | None = None
    traffic_started_at = datetime.now().isoformat(timespec="seconds")
    traffic_outcome = "failed"
    traffic_report_stop = threading.Event()
    traffic_reporter: threading.Thread | None = None

    def mark_email_otp_entered() -> None:
        nonlocal email_otp_entered
        email_otp_entered = True

    def mark_email_submitted() -> None:
        nonlocal email_submitted
        email_submitted = True

    def mark_email_submit_attempted() -> None:
        nonlocal email_submit_attempted
        email_submit_attempted = True

    def persist_traffic(status: str) -> None:
        if job_id is None:
            return
        from core import db

        snapshot = _traffic_snapshot_with_base(client.traffic_snapshot(), traffic_base)
        measurement = str(snapshot.get("measurement") or "unavailable")
        effective_status = (
            status
            if measurement == "socks5_tunnel_payload" or status == "running"
            else "unavailable"
        )
        payload = {
            **snapshot,
            "status": effective_status,
            "registration_outcome": None if status == "running" else traffic_outcome,
            "started_at": traffic_started_at,
            "finished_at": (
                datetime.now().isoformat(timespec="seconds")
                if status != "running" else None
            ),
        }
        db.update_job_roxy_traffic(int(job_id), payload)

    def start_traffic_reporter() -> None:
        nonlocal traffic_reporter
        if job_id is None or client.traffic_snapshot().get("measurement") != "socks5_tunnel_payload":
            return

        def report() -> None:
            while not traffic_report_stop.wait(_ROXY_TRAFFIC_HEARTBEAT_SECONDS):
                try:
                    persist_traffic("running")
                except Exception as exc:
                    logger.debug("[Roxy][流量] 心跳保存失败：%s: %s", type(exc).__name__, exc)

        traffic_reporter = threading.Thread(
            target=report,
            name=f"roxy-traffic-{job_id}",
            daemon=True,
        )
        traffic_reporter.start()

    try:
        opened = client.open_profile(
            proxy_url=proxy or None,
            excluded_proxy_urls=used_proxy_urls,
        )
        persist_traffic("running")
        start_traffic_reporter()
        failure_stage = "driver_attach"
        driver = _build_driver(opened)
        _center_browser_window(driver)
        driver.set_page_load_timeout(int(getattr(_cfg, "ROXY_PAGE_LOAD_TIMEOUT", 35) or 35))
        logger.info("[Roxy注册] 开始：%s，profile=%s", email, opened.profile_id)

        failure_stage = "login_navigation"
        otp_after_ts = time.time()
        logger.info("[Roxy注册] 打开登录页：https://chatgpt.com/auth/login")
        _navigate_page(driver, _CHATGPT_LOGIN_URL)
        human_delay("navigate")
        _page_warmup(driver, reason="login_page")
        logger.info("[Roxy注册] 登录页加载完成，准备填写邮箱")
        _maybe_accept(driver)
        _check_manual_stop()

        # 填邮箱。OpenAI UI 会随出口 IP/语言变化；这里只按 DOM 技术属性找邮箱入口，
        # 并排除 Google/Apple/Microsoft 等第三方入口，不依赖按钮可见文字。
        failure_stage = "email_submit"
        next_state = _submit_email_and_wait_next(
            driver,
            email,
            attempts=3,
            on_email_submitted=mark_email_submitted,
            on_email_submit_attempted=mark_email_submit_attempted,
        )
        _check_manual_stop()

        # 只有服务端确认密码提交并进入后续步骤才继续。默认直达 OTP 时先尝试
        # 切回密码注册页；无法切换则终止，禁止保存 passwordless 账号。
        failure_stage = "password"
        openai_password = _prepare_registration_password(
            driver,
            email,
            next_state,
            timeout=25,
        )
        _check_manual_stop()

        failure_stage = "email_otp"
        if next_state == "logged_in":
            logger.info("[Roxy注册][OTP] 邮箱提交后已检测到登录态，跳过邮箱取码")
        else:
            _complete_email_otp_challenge(
                driver,
                email,
                otp_code=otp_code,
                otp_after_ts=otp_after_ts,
                max_otp_attempts=3,
                on_otp_entered=mark_email_otp_entered,
            )
        email_verified = True

        # about-you / profile 信息页：必须完成或确认已有登录态，不能静默跳过。
        failure_stage = "profile"
        logger.info("[Roxy注册] 开始等待资料页/登录态")
        _check_manual_stop()
        _advance_from_email_verified_page(driver)
        profile_submitted = _complete_profile_page(driver, name, birthday, timeout=60)
        if profile_submitted:
            create_acknowledged = True
            # 给 OAuth 回调 / session cookie 写入一点时间。
            human_delay("post_auth")

        failure_stage = "session"
        logger.info("[Roxy注册] 等待 ChatGPT 跳转并写入 session/accessToken")
        _check_manual_stop()
        session_info = _fetch_chatgpt_session(driver, timeout=120, expected_email=email)
        access_token = session_info["accessToken"]
        logger.info("[Roxy注册] 已拿到 accessToken：%s", email)
        _check_manual_stop()

        _load_chatgpt_app_after_registration(driver)

        # Codex 会复用当前 Profile 并清理 Cookie；必须先保存 Web 登录态。
        try:
            web_cookies = capture_selenium_cookies(driver)
            logger.info("[Roxy注册][Cookie] 已捕获 Web Cookie：%s，共 %s 条", email, len(web_cookies))
        except Exception as exc:
            web_cookies = []
            logger.warning(
                "[Roxy注册][Cookie] 捕获失败（不影响账号保存）：%s: %s",
                type(exc).__name__,
                str(exc)[:180],
            )

        totp_secret = None

        codex_result = {
            "status": "skipped",
            "ok": True,
            "message": "ENABLE_CODEX_AUTO=False，跳过 Codex",
        }
        try:
            from config import codex as _codex_cfg
            should_run_codex = bool(codex_oauth) if codex_oauth is not None else bool(getattr(_codex_cfg, "ENABLE_CODEX_AUTO", False))
            if should_run_codex:
                # 注册流程本身已创建 Roxy 一号一环境。这里不能再新建第二个 Roxy 环境；
                # 复用当前注册窗口，先清理 Cookie/session/localStorage/cache，再开始 Codex 授权。
                from core.roxy_codex_oauth import run_roxy_codex_oauth
                logger.info("[Roxy注册][Codex] ENABLE_CODEX_AUTO=True，复用当前注册 Roxy 窗口执行 Codex 授权，不创建新环境")
                _check_manual_stop()
                codex_result = run_roxy_codex_oauth(
                    email,
                    reuse_existing_profile=True,
                    existing_driver=driver,
                    existing_opened=opened,
                    force=True,
                    clear_existing_state=True,
                )
            else:
                logger.info("[Roxy注册][Codex] ENABLE_CODEX_AUTO=False，注册后跳过 Codex OAuth")
        except Exception as exc:
            codex_result = {"status": "failed", "ok": False, "message": f"{type(exc).__name__}: {str(exc)[:180]}"}

        failure_stage = "account_save"
        selected_proxy = getattr(client, "selected_proxy_url", "")
        effective_proxy = (
            selected_proxy.strip()
            if isinstance(selected_proxy, str) and selected_proxy.strip()
            else str(proxy or "").strip()
        )
        account_id = save_account_data(
            email=email,
            access_token=access_token,
            totp_secret=totp_secret,
            email_source=resolve_email_source(email),
            proxy_used=effective_proxy or None,
            batch_dir=batch_dir,
            web_cookies=web_cookies,
            web_cookie_source="roxy",
            extra={
                "user": session_info.get("user"),
                "account": session_info.get("account"),
                "expires": session_info.get("expires"),
                "roxybrowser": {"profile_id": opened.profile_id, "open_result": opened.raw},
                "registration_password": openai_password,
                "codex": codex_result,
            },
        )
        traffic_outcome = "success"
        return {
            "success": True,
            "email": email,
            "account_id": account_id,
            "access_token": access_token,
            "totp_secret": totp_secret,
            "codex": codex_result,
            "error": None,
            "failure_stage": None,
            "failure_code": None,
            "retryable": False,
            "retry_action": "none",
            "email_verified": True,
            "email_consumed": True,
            "email_submit_attempted": True,
            "email_submitted": True,
        }
    except Exception as exc:
        if type(exc).__name__ == "StopRequested":
            logger.warning("[Roxy注册] 已按用户请求停止：%s", exc)
        else:
            logger.error("[Roxy注册] 失败：%s: %s", type(exc).__name__, exc)
            logger.debug("[Roxy注册] 失败详情", exc_info=True)
        # OTP 输入控件可能自动提交；只要验证码已写入，服务端状态就不再确定。
        # 此时禁止归还邮箱或换 Profile 重走注册，避免撞到已验证的半成品账号。
        email_consumed = bool(
            email_submitted or email_verified or create_acknowledged or email_otp_entered
        )
        decision = classify_roxy_failure(
            exc,
            failure_stage=failure_stage,
            email_verified=email_verified,
            email_consumed=email_consumed,
            email_submitted=email_submitted,
        )
        return {
            "success": False,
            "email": email,
            "error": f"{type(exc).__name__}: {str(exc)[:500]}",
            **decision,
            "email_verified": email_verified,
            "email_consumed": email_consumed,
            # 到 About you 之前密码和邮箱验证码均已提交；即使 ChatGPT workspace
            # 没创建出来，认证身份也可能已经占用该邮箱，禁止自动重新领取。
            "email_reusable": False,
            "email_submit_attempted": email_submit_attempted,
            "email_submitted": email_submitted,
        }
    finally:
        keep_profile_open = bool(opened) and (
            bool(getattr(opened, "keep_open", False))
            or bool(_cfg.ROXY_KEEP_BROWSER_OPEN)
        )
        selected_proxy_url = str(getattr(client, "selected_proxy_url", "") or "").strip()
        if selected_proxy_url and used_proxy_urls is not None:
            # 动态 sticky 地址应在下一次 Profile 尝试时换 session；固定代理（尤其
            # 127.0.0.1 的本机代理入口）无法改写，排除后会让唯一候选变成“抽测 0 条”。
            # 固定入口仍会重新走预检，因此瞬时故障恢复后可安全复用。
            from core.roxybrowser_client import _proxy_session_identity

            _lease_key, is_dynamic_proxy, _summary = _proxy_session_identity(
                selected_proxy_url
            )
            if is_dynamic_proxy:
                used_proxy_urls.add(selected_proxy_url)
        traffic_report_stop.set()
        if traffic_reporter is not None and traffic_reporter.is_alive():
            traffic_reporter.join(timeout=2)
        if driver and not keep_profile_open:
            try:
                driver.quit()
            except Exception:
                pass
        try:
            persist_traffic("running" if defer_traffic_finalization else "complete")
            traffic = _traffic_snapshot_with_base(client.traffic_snapshot(), traffic_base)
            if traffic.get("measurement") == "socks5_tunnel_payload":
                logger.info(
                    "[Roxy][流量] 任务统计：上传=%sB 下载=%sB 总计=%sB 连接=%s",
                    traffic.get("uploaded_bytes", 0),
                    traffic.get("downloaded_bytes", 0),
                    traffic.get("total_bytes", 0),
                    traffic.get("connection_count", 0),
                )
        except Exception:
            logger.exception("[Roxy][流量] 保存任务流量失败")
        try:
            if opened is not None and not keep_profile_open:
                client.cleanup_profile(opened)
            elif opened is None:
                # Preflight/bridge/create failures happen before RoxyOpenResult exists,
                # but may already own a process-local proxy-session lease.
                client.cleanup_profile(None)
            else:
                # A retained Profile keeps using its upstream; move the dynamic
                # session into cooldown so another registration rotates instead.
                client.release_proxy_session_lease(remember=True)
        finally:
            client.close(preserve_profile_resources=keep_profile_open)
