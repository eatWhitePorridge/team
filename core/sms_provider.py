# -*- coding: utf-8 -*-
"""
接码平台客户端。

用于 Codex OAuth "全新 session" 流程过 OpenAI 的 /phone-verification 手机号验证：
    1. acquire_number()       getNumber 取一个手机号（返回 激活ID + 号码）
    2. wait_for_sms_code()    轮询 getStatus 直到拿到短信验证码
    3. complete() / cancel()  setStatus 标记完成(6) / 取消(8)

当前支持：
    - SMSBower：最低价选号、单号限价和共享批次预算
    - Luban：复用 PayPal 的 Luban API 凭证与线路配置
    - HeroSMS：SMS-Activate 兼容接口，使用 getNumberV2 保留成本元数据
    - GrizzlySMS：GET 文本接口，文档 https://api.grizzlysms.com
    - L：本地 JSON 管理接口，文档 L_API.md
    - H：本地 JSON 管理接口，文档 H_API.md

价格相关：每取一个号、收到短信都会计费，所以：
    - 取号后若收不到短信，必须 cancel(8) 释放，避免白扣钱；
    - 成功拿到码后 complete(6) 正式完成激活。
"""
import json
import logging
import threading
import time
from contextlib import contextmanager
from urllib.parse import urljoin

from curl_cffi.requests import Session as CurlSession

# 注意：用 `from config import codex` 而不是 `from config.codex import X`，
# 这样 WebUI 调 config.reload_all() 后，本模块通过 codex.X 读到的是最新值。
from config import codex as _cfg
from config import IMPERSONATE

logger = logging.getLogger(__name__)

# GrizzlySMS 规则：号码取出后 2 分钟内不允许取消（防薅号）。
# 这里留 5 秒缓冲，时间到了再发 setStatus=8。
_MIN_CANCEL_DELAY = 125

# 记录每个 activation_id 的取号时间，供 cancel() 判断是否要等。
# 用模块级 dict 而不是改 acquire_number 返回值，保持向后兼容。
_ACQUIRED_AT: dict[str, float] = {}
_LUBAN_ACTIVATIONS: dict[str, dict] = {}
_LUBAN_LOCK = threading.Lock()
_RUNTIME = threading.local()
_HEROSMS_PROVIDERS = {"herosms", "hero_sms", "hero"}


class SmsProviderError(RuntimeError):
    """接码平台通用错误。"""


class SmsNoNumbersError(SmsProviderError):
    """暂无可用号码（NO_NUMBERS），可换国家或稍后重试。"""


class SmsNoBalanceError(SmsProviderError):
    """余额不足（NO_BALANCE），必须充值，重试无意义——上层应立即停止。"""


class SmsCodeTimeout(SmsProviderError):
    """单个号等短信超时（OpenAI 没发或没到达）。"""


class SmsBudgetExceededError(SmsProviderError):
    """任务级共享短信预算已耗尽，上层必须立即停止该批后续接码。"""


def _http() -> CurlSession:
    s = CurlSession(impersonate=IMPERSONATE)
    s.timeout = _cfg.SMS_REQUEST_TIMEOUT
    return s


def _provider() -> str:
    options = getattr(_RUNTIME, "options", {}) or {}
    return str(options.get("provider") or getattr(_cfg, "SMS_PROVIDER", "smsbower") or "smsbower").strip().lower()


def runtime_options() -> dict:
    options = dict(getattr(_RUNTIME, "options", {}) or {})
    provider = str(
        options.get("provider") or getattr(_cfg, "SMS_PROVIDER", "smsbower") or "smsbower"
    ).strip().lower()
    options.setdefault("provider", provider)
    if provider == "luban":
        from config import paypal as paypal_cfg

        options.setdefault("service", getattr(_cfg, "SMS_LUBAN_SERVICE", "OpenAI"))
        options.setdefault(
            "service_aliases",
            getattr(
                _cfg,
                "SMS_LUBAN_SERVICE_ALIASES",
                "OpenAI,OpenAI / ChatGPT,OpenAI / ChatGpt,ChatGPT | OpenAI,OpenAI/ChatGPT",
            ),
        )
        options.setdefault(
            "country",
            str(getattr(_cfg, "SMS_LUBAN_COUNTRY", "") or "").strip()
            or getattr(paypal_cfg, "PAYPAL_LUBAN_COUNTRY", "England"),
        )
        options.setdefault("api_base", getattr(paypal_cfg, "PAYPAL_LUBAN_API_BASE", ""))
        options.setdefault("api_key", getattr(paypal_cfg, "PAYPAL_LUBAN_API_KEY", ""))
        options.setdefault(
            "providers",
            str(getattr(_cfg, "SMS_LUBAN_PROVIDERS", "") or "").strip()
            or getattr(paypal_cfg, "PAYPAL_LUBAN_PROVIDERS", ""),
        )
        options.setdefault("service_ids", getattr(_cfg, "SMS_LUBAN_SERVICE_IDS", ""))
        options.setdefault("max_attempts", getattr(paypal_cfg, "PAYPAL_LUBAN_MAX_ATTEMPTS", 3))
        options.setdefault("list_max_pages", getattr(paypal_cfg, "PAYPAL_LUBAN_LIST_MAX_PAGES", 5))
        options.setdefault("request_timeout", getattr(paypal_cfg, "PAYPAL_LUBAN_REQUEST_TIMEOUT", 20))
        options.setdefault("proxy", getattr(paypal_cfg, "PAYPAL_LUBAN_PROXY", ""))
    elif provider in _HEROSMS_PROVIDERS:
        hero_country = str(getattr(_cfg, "HEROSMS_COUNTRY", "") or "").strip()
        options.setdefault("service", getattr(_cfg, "HEROSMS_SERVICE", "dr"))
        options.setdefault(
            "country",
            hero_country or str(getattr(_cfg, "SMS_COUNTRY", "") or "").strip(),
        )
        options.setdefault("api_key", getattr(_cfg, "HEROSMS_API_KEY", ""))
        options.setdefault(
            "handler_url",
            getattr(
                _cfg,
                "HEROSMS_HANDLER_URL",
                "https://hero-sms.com/stubs/handler_api.php",
            ),
        )
        options.setdefault("operator", getattr(_cfg, "HEROSMS_OPERATOR", ""))
        options.setdefault("fixed_price", getattr(_cfg, "HEROSMS_FIXED_PRICE", ""))
        options.setdefault(
            "phone_exception", getattr(_cfg, "HEROSMS_PHONE_EXCEPTION", "")
        )
        options.setdefault("proxy", getattr(_cfg, "HEROSMS_PROXY", ""))
        options.setdefault(
            "request_timeout", getattr(_cfg, "HEROSMS_REQUEST_TIMEOUT", 30)
        )
    else:
        options.setdefault("service", getattr(_cfg, "SMS_SERVICE", "dr"))
        options.setdefault("country", getattr(_cfg, "SMS_COUNTRY", ""))
        options.setdefault("api_key", getattr(_cfg, "SMSBOWER_API_KEY", ""))
        options.setdefault(
            "handler_url",
            getattr(_cfg, "SMSBOWER_HANDLER_URL", "https://smsbower.page/stubs/handler_api.php"),
        )
    options.setdefault("max_price", getattr(_cfg, "SMS_MAX_PRICE", ""))
    options.setdefault("max_retries", getattr(_cfg, "SMS_MAX_RETRIES", 10))
    options.setdefault("code_wait", getattr(_cfg, "SMS_CODE_WAIT", 120))
    options.setdefault("poll_interval", getattr(_cfg, "SMS_POLL_INTERVAL", 5))
    options.setdefault("budget", getattr(_cfg, "SMSBOWER_TASK_BUDGET", ""))
    return options


def runtime_setting(key: str, default=None):
    return runtime_options().get(key, default)


def activation_metadata(activation_id: str) -> dict:
    if _provider() in {"smsbower", "sms_bower", "smsb"}:
        from core import sms_bower
        return sms_bower.activation_metadata(activation_id)
    if _provider() == "luban":
        with _LUBAN_LOCK:
            activation = dict(_LUBAN_ACTIVATIONS.get(str(activation_id)) or {})
        provider = str(activation.get("provider") or "").strip()
        return {
            "sms_country": activation.get("country_code") or activation.get("country") or runtime_setting("country", ""),
            "sms_provider_id": f"luban:{provider}" if provider else "luban",
            "sms_cost": activation.get("cost"),
        }
    if _provider() in _HEROSMS_PROVIDERS:
        from core import hero_sms

        return hero_sms.activation_metadata(activation_id)
    return {"sms_country": runtime_setting("country", ""), "sms_provider_id": _provider(), "sms_cost": None}


@contextmanager
def runtime_context(options: dict | None):
    previous = getattr(_RUNTIME, "options", None)
    _RUNTIME.options = dict(options or {})
    try:
        yield
    finally:
        if previous is None:
            try:
                delattr(_RUNTIME, "options")
            except AttributeError:
                pass
        else:
            _RUNTIME.options = previous


def _luban_client(http):
    from core.paypal_sms import LubanClient

    return LubanClient(runtime_options(), http=http)


def _map_luban_error(exc: Exception) -> SmsProviderError:
    from core.paypal_sms import PayPalSmsNoNumbers, PayPalSmsTimeout

    message = str(exc or "Luban 接码失败")
    lowered = message.casefold()
    if isinstance(exc, PayPalSmsNoNumbers):
        return SmsNoNumbersError(message)
    if isinstance(exc, PayPalSmsTimeout):
        return SmsCodeTimeout(message)
    if any(marker in lowered for marker in ("no balance", "insufficient balance", "余额不足")):
        return SmsNoBalanceError(message)
    return SmsProviderError(message)


def _map_hero_error(exc: Exception) -> SmsProviderError:
    from core import hero_sms

    message = str(exc or "HeroSMS 接码失败")
    if isinstance(exc, hero_sms.HeroSmsNoNumbers):
        return SmsNoNumbersError(message)
    if isinstance(exc, hero_sms.HeroSmsNoBalance):
        return SmsNoBalanceError(message)
    return SmsProviderError(message)


def _luban_activation(activation_id: str) -> dict:
    key = str(activation_id or "").strip()
    with _LUBAN_LOCK:
        stored = dict(_LUBAN_ACTIVATIONS.get(key) or {})
    return stored or {"channel": "luban", "request_id": key}


def _forget_luban_activation(activation_id: str) -> None:
    key = str(activation_id or "").strip()
    with _LUBAN_LOCK:
        _LUBAN_ACTIVATIONS.pop(key, None)
    _ACQUIRED_AT.pop(key, None)


def _request_grizzly(http: CurlSession, params: dict) -> str:
    """
    发一个 GrizzlySMS API 请求，返回去空白的响应文本。
    统一识别公共错误码并抛对应异常。
    """
    base_params = {"api_key": _cfg.SMS_API_KEY}
    base_params.update(params)
    resp = http.get(_cfg.SMS_API_BASE, params=base_params)
    if resp.status_code != 200:
        raise SmsProviderError(
            f"GrizzlySMS HTTP {resp.status_code}: {(resp.text or '')[:200]}"
        )
    text = (resp.text or "").strip()

    # 公共错误码（任何 action 都可能返回）
    if text == "BAD_KEY":
        raise SmsProviderError("接码平台 API key 无效（BAD_KEY）")
    if text == "NO_BALANCE":
        raise SmsNoBalanceError("接码平台余额不足（NO_BALANCE），请充值")
    if text == "NO_NUMBERS":
        raise SmsNoNumbersError("接码平台暂无可用号码（NO_NUMBERS）")
    if text == "SERVICE_UNAVAILABLE_REGION":
        raise SmsProviderError("接码平台地区受限（SERVICE_UNAVAILABLE_REGION），请换 IP")
    if text in ("BAD_ACTION", "BAD_SERVICE", "BAD_STATUS"):
        raise SmsProviderError(f"接码平台请求参数错误：{text}")
    if text == "NO_ACTIVATION":
        raise SmsProviderError("激活 ID 不存在（NO_ACTIVATION）")
    if text.startswith("The service is prohibited"):
        raise SmsProviderError(f"该服务被平台禁售：{text}")

    return text


def _l_url(path: str) -> str:
    base = str(getattr(_cfg, "L_API_BASE", "") or "").strip()
    if not base:
        raise SmsProviderError("L_API_BASE 不能为空")
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _l_headers() -> dict:
    token = str(getattr(_cfg, "L_ADMIN_AUTH_CODE", "") or "").strip()
    if not token:
        raise SmsProviderError("L_ADMIN_AUTH_CODE 不能为空")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _post_l_json(http: CurlSession, path: str, payload: dict) -> dict:
    resp = http.post(_l_url(path), headers=_l_headers(), data=json.dumps(payload))
    text = (resp.text or "").strip()
    try:
        data = resp.json()
    except Exception:
        data = {}

    if resp.status_code != 200:
        msg = data.get("error") if isinstance(data, dict) else ""
        raise SmsProviderError(f"L HTTP {resp.status_code}: {(msg or text)[:200]}")
    if isinstance(data, dict) and data.get("error"):
        error = str(data.get("error") or "")
        raw = str(data.get("raw") or "")
        combined = f"{error} {raw}".strip()
        if "NO_BALANCE" in combined or "余额不足" in combined:
            raise SmsNoBalanceError(f"L 余额不足：{combined}")
        if "NO_NUMBERS" in combined or "暂无号码" in combined:
            raise SmsNoNumbersError(f"L 暂无可用号码：{combined}")
        raise SmsProviderError(f"L 请求失败：{combined}")
    if not isinstance(data, dict):
        raise SmsProviderError(f"L 响应不是 JSON 对象：{text[:200]}")
    return data


def _h_url(path: str) -> str:
    base = str(getattr(_cfg, "H_API_BASE", "") or "").strip()
    if not base:
        raise SmsProviderError("H_API_BASE 不能为空")
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _h_headers() -> dict:
    token = str(getattr(_cfg, "H_ADMIN_AUTH_CODE", "") or "").strip()
    if not token:
        raise SmsProviderError("H_ADMIN_AUTH_CODE 不能为空")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _post_h_json(http: CurlSession, path: str, payload: dict) -> dict:
    resp = http.post(_h_url(path), headers=_h_headers(), data=json.dumps(payload))
    text = (resp.text or "").strip()
    try:
        data = resp.json()
    except Exception:
        data = {}

    if resp.status_code != 200:
        msg = data.get("error") if isinstance(data, dict) else ""
        raise SmsProviderError(f"H HTTP {resp.status_code}: {(msg or text)[:200]}")
    if isinstance(data, dict) and data.get("error"):
        error = str(data.get("error") or "")
        raw = str(data.get("raw") or "")
        combined = f"{error} {raw}".strip()
        if "NO_BALANCE" in combined or "余额不足" in combined:
            raise SmsNoBalanceError(f"H 余额不足：{combined}")
        if "NO_NUMBERS" in combined or "暂无号码" in combined:
            raise SmsNoNumbersError(f"H 暂无可用号码：{combined}")
        raise SmsProviderError(f"H 请求失败：{combined}")
    if not isinstance(data, dict):
        raise SmsProviderError(f"H 响应不是 JSON 对象：{text[:200]}")
    return data


def _release_h_number(activation_id: str, http: CurlSession | None = None) -> dict:
    """调用 H_API /api/admin/h/release 释放单个号码。"""
    activation_id = str(activation_id or "").strip()
    if not activation_id:
        raise SmsProviderError("H release 缺少 id")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_h_json(http, "/api/admin/h/release", {"id": activation_id})
        failed = data.get("failed") if isinstance(data, dict) else None
        if isinstance(failed, list) and failed:
            detail = json.dumps(failed, ensure_ascii=False)[:300]
            raise SmsProviderError(f"H release 失败 id={activation_id}: {detail}")
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        logger.info(f"[SMS:H] 已释放号码 id={activation_id}, released={released}")
        _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def release_h_numbers(ids: list[str], http: CurlSession | None = None) -> dict:
    """批量释放 H 号码。"""
    ids = [str(x or "").strip() for x in (ids or []) if str(x or "").strip()]
    if not ids:
        raise SmsProviderError("H release 缺少 ids")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_h_json(http, "/api/admin/h/release", {"ids": ids})
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        failed = data.get("failed") if isinstance(data, dict) else []
        logger.info(f"[SMS:H] 批量释放号码完成 released={released}, failed={len(failed) if isinstance(failed, list) else 0}")
        for activation_id in ids:
            _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def _release_l_number(activation_id: str, http: CurlSession | None = None) -> dict:
    """调用 L_API /api/admin/l/release 释放单个号码。"""
    activation_id = str(activation_id or "").strip()
    if not activation_id:
        raise SmsProviderError("L release 缺少 id")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_l_json(http, "/api/admin/l/release", {"id": activation_id})
        failed = data.get("failed") if isinstance(data, dict) else None
        if isinstance(failed, list) and failed:
            # 接口允许部分失败。单个释放时 failed 非空基本代表这个 id 释放失败。
            detail = json.dumps(failed, ensure_ascii=False)[:300]
            raise SmsProviderError(f"L release 失败 id={activation_id}: {detail}")
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        logger.info(f"[SMS:L] 已释放号码 id={activation_id}, released={released}")
        _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def release_l_numbers(ids: list[str], http: CurlSession | None = None) -> dict:
    """批量释放 L 号码，供工具/后续批处理复用。"""
    ids = [str(x or "").strip() for x in (ids or []) if str(x or "").strip()]
    if not ids:
        raise SmsProviderError("L release 缺少 ids")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_l_json(http, "/api/admin/l/release", {"ids": ids})
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        failed = data.get("failed") if isinstance(data, dict) else []
        logger.info(f"[SMS:L] 批量释放号码完成 released={released}, failed={len(failed) if isinstance(failed, list) else 0}")
        for activation_id in ids:
            _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def _normalize_phone_digits(value: str) -> str:
    """把平台返回/配置的号码片段规范化为纯数字，避免 +-849... 这类非法 E.164。"""
    return "".join(ch for ch in str(value or "").strip() if ch.isdigit())


def _normalize_l_phone(phone: str) -> str:
    phone = _normalize_phone_digits(phone)
    prefix = _normalize_phone_digits(getattr(_cfg, "L_PHONE_PREFIX", ""))
    if prefix and phone and not phone.startswith(prefix):
        return f"{prefix}{phone}"
    return phone


def _normalize_h_phone(phone: str) -> str:
    phone = _normalize_phone_digits(phone)
    prefix = _normalize_phone_digits(getattr(_cfg, "H_PHONE_PREFIX", ""))
    if prefix and phone and not phone.startswith(prefix):
        return f"{prefix}{phone}"
    return phone


def _h_phone_acquire_mode() -> str:
    """
    H 取号模式：
      - reusable/reuse/prefer_reuse：优先复用，调用 /api/admin/h/take-reusable-phone
      - new/fresh/always_new：每次取新号，调用 /api/admin/h/take-phone
    """
    raw = str(getattr(_cfg, "H_PHONE_ACQUIRE_MODE", "reusable") or "reusable").strip().lower()
    if raw in ("new", "fresh", "always_new", "take_phone", "take-phone", "每次取新号", "新号"):
        return "new"
    return "reusable"


# ============================================================
# 取号
# ============================================================

def acquire_number(
    http: CurlSession | None = None,
    service: str | None = None,
    country: str | None = None,
) -> tuple[str, str]:
    """
    取一个手机号（getNumber）。

    Returns:
        (activation_id, phone_number) —— phone_number 不带 + 前缀（如 16195366483）

    Raises:
        SmsNoNumbersError / SmsNoBalanceError / SmsProviderError
    """
    own_http = http is None
    http = http or _http()
    try:
        if _provider() in {"smsbower", "sms_bower", "smsb"}:
            from core import sms_bower
            try:
                activation_id, phone, metadata = sms_bower.acquire_number(http, runtime_options())
            except sms_bower.SmsBowerNoBalance as exc:
                raise SmsNoBalanceError(str(exc)) from exc
            except sms_bower.SmsBowerNoNumbers as exc:
                raise SmsNoNumbersError(str(exc)) from exc
            except sms_bower.SmsBowerBudgetExceeded as exc:
                if getattr(exc, "scope", "batch") == "batch":
                    raise SmsBudgetExceededError(str(exc)) from exc
                raise SmsProviderError(str(exc)) from exc
            except sms_bower.SmsBowerError as exc:
                raise SmsProviderError(str(exc)) from exc
            _ACQUIRED_AT[activation_id] = time.time()
            logger.info(
                "[SMSBower] 最低价取号成功 id=%s country=%s provider=%s cost=%s phone=+%s",
                activation_id, metadata.get("sms_country"), metadata.get("sms_provider_id"), metadata.get("sms_cost"), phone,
            )
            return activation_id, phone

        if _provider() == "luban":
            client = _luban_client(http)
            try:
                activation = client.acquire()
            except Exception as exc:
                raise _map_luban_error(exc) from exc
            finally:
                client.close()
            activation_id = str(activation.get("request_id") or "").strip()
            phone = _normalize_phone_digits(activation.get("phone") or "")
            if not activation_id or not phone:
                raise SmsProviderError("Luban getNumber 响应缺少 request_id/phone")
            with _LUBAN_LOCK:
                _LUBAN_ACTIVATIONS[activation_id] = dict(activation)
            _ACQUIRED_AT[activation_id] = time.time()
            logger.info(
                "[SMS:Luban] 取号成功 id=%s country=%s provider=%s cost=%s phone=+%s",
                activation_id,
                activation.get("country_code") or activation.get("country"),
                activation.get("provider"),
                activation.get("cost"),
                phone,
            )
            return activation_id, phone

        if _provider() in _HEROSMS_PROVIDERS:
            from core import hero_sms

            try:
                activation_id, phone, metadata = hero_sms.acquire_number(
                    http,
                    runtime_options(),
                    service=service,
                    country=country,
                )
            except Exception as exc:
                raise _map_hero_error(exc) from exc
            _ACQUIRED_AT[activation_id] = time.time()
            logger.info(
                "[SMS:HeroSMS] 取号成功 id=%s country=%s cost=%s phone=+%s",
                activation_id,
                metadata.get("sms_country"),
                metadata.get("sms_cost"),
                phone,
            )
            return activation_id, phone

        if _provider() == "l":
            payload = {
                "service": service or runtime_setting("service", _cfg.SMS_SERVICE),
                "country": country or runtime_setting("country", _cfg.SMS_COUNTRY),
            }
            max_price = runtime_setting("max_price", _cfg.SMS_MAX_PRICE)
            if max_price not in (None, ""):
                payload["maxPrice"] = max_price

            data = _post_l_json(http, "/api/admin/l/take-phone", payload)
            item = data.get("item") or {}
            activation_id = str(item.get("id") or "").strip()
            raw_phone = str(item.get("phone") or "")
            raw_prefix = str(getattr(_cfg, "L_PHONE_PREFIX", "") or "")
            phone = _normalize_l_phone(raw_phone)
            if raw_phone.strip() != phone or raw_prefix.strip():
                logger.info(
                    f"[SMS:L] 号码规范化：raw_phone={raw_phone!r}, "
                    f"prefix={raw_prefix!r}, normalized=+{phone}"
                )
            if not activation_id or not phone:
                raise SmsProviderError(f"L take-phone 响应缺少 item.id/item.phone：{str(data)[:200]}")
            _ACQUIRED_AT[activation_id] = time.time()
            logger.info(f"[SMS:L] 取号成功：id={activation_id}, phone=+{phone}")
            return activation_id, phone

        if _provider() == "h":
            # H_API 使用 projectId + country；统一复用 SMS_SERVICE / SMS_COUNTRY，
            # 避免接码平台之间出现重复的“服务/国家”配置。
            project_id = str(service or runtime_setting("service", _cfg.SMS_SERVICE)).strip()
            h_country = str(country or runtime_setting("country", _cfg.SMS_COUNTRY)).strip()
            if not project_id:
                raise SmsProviderError("H projectId 不能为空：请填写 SMS_SERVICE")
            if not h_country:
                raise SmsProviderError("H country 不能为空：请填写 SMS_COUNTRY")
            payload = {
                "projectId": project_id,
                "country": h_country,
            }
            mode = _h_phone_acquire_mode()
            api_path = "/api/admin/h/take-phone" if mode == "new" else "/api/admin/h/take-reusable-phone"
            data = _post_h_json(http, api_path, payload)
            item = data.get("item") or {}
            activation_id = str(item.get("id") or "").strip()
            raw_phone = str(item.get("phone") or "")
            raw_prefix = str(getattr(_cfg, "H_PHONE_PREFIX", "") or "")
            phone = _normalize_h_phone(raw_phone)
            if raw_phone.strip() != phone or raw_prefix.strip():
                logger.info(
                    f"[SMS:H] 号码规范化：raw_phone={raw_phone!r}, "
                    f"prefix={raw_prefix!r}, normalized=+{phone}"
                )
            if not activation_id or not phone:
                raise SmsProviderError(f"H {api_path.rsplit('/', 1)[-1]} 响应缺少 item.id/item.phone：{str(data)[:200]}")
            _ACQUIRED_AT[activation_id] = time.time()
            logger.info(
                f"[SMS:H] 取号成功：mode={mode}, api={api_path}, id={activation_id}, phone=+{phone}, "
                f"reused={bool(data.get('reused'))}, duplicate={bool(data.get('duplicate'))}"
            )
            return activation_id, phone

        params = {
            "action": "getNumber",
            "service": service or runtime_setting("service", _cfg.SMS_SERVICE),
            "country": country or runtime_setting("country", _cfg.SMS_COUNTRY),
        }
        max_price = runtime_setting("max_price", _cfg.SMS_MAX_PRICE)
        if max_price not in (None, ""):
            params["maxPrice"] = max_price

        text = _request_grizzly(http, params)
        # 成功格式：ACCESS_NUMBER:激活ID:号码
        if not text.startswith("ACCESS_NUMBER:"):
            raise SmsProviderError(f"getNumber 非预期响应：{text[:200]}")
        parts = text.split(":")
        if len(parts) < 3:
            raise SmsProviderError(f"getNumber 响应格式异常：{text[:200]}")
        activation_id = parts[1].strip()
        phone = parts[2].strip()
        _ACQUIRED_AT[activation_id] = time.time()
        logger.info(f"[SMS] 取号成功：activation_id={activation_id}, phone=+{phone}")
        return activation_id, phone
    finally:
        if own_http:
            http.close()


# ============================================================
# 取短信验证码
# ============================================================

def wait_for_sms_code(
    activation_id: str,
    http: CurlSession | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
) -> str:
    """
    轮询 getStatus 直到拿到短信验证码。

    Returns:
        验证码字符串

    Raises:
        SmsCodeTimeout —— 超时没收到（上层可换号重试）
        SmsProviderError —— 激活被取消等
    """
    own_http = http is None
    http = http or _http()
    deadline = time.time() + (max_wait if max_wait is not None else int(runtime_setting("code_wait", _cfg.SMS_CODE_WAIT)))
    interval = poll_interval if poll_interval is not None else float(runtime_setting("poll_interval", _cfg.SMS_POLL_INTERVAL))
    try:
        provider = _provider()
        total_wait = max_wait if max_wait is not None else int(runtime_setting("code_wait", _cfg.SMS_CODE_WAIT))
        logger.info(f"[SMS] 等待短信验证码 activation_id={activation_id}，最长 {total_wait}s...")
        if provider == "luban":
            client = _luban_client(http)

            def _interruptible_sleep(delay: float) -> None:
                try:
                    from core.registration_service import check_stop_requested
                    check_stop_requested()
                except ImportError:
                    pass
                time.sleep(delay)

            try:
                code = client.poll_code(
                    _luban_activation(activation_id),
                    timeout=total_wait,
                    poll_interval=interval,
                    sleep=_interruptible_sleep,
                )
            except Exception as exc:
                raise _map_luban_error(exc) from exc
            finally:
                client.close()
            logger.info("[SMS:Luban] 收到验证码：%s**", code[:2])
            return code

        round_no = 0
        while time.time() < deadline:
            try:
                from core.registration_service import check_stop_requested
                check_stop_requested()
            except ImportError:
                pass
            round_no += 1
            elapsed = max(0, int(total_wait - max(0, deadline - time.time())))
            remaining_before = max(0, int(deadline - time.time()))
            logger.info(
                f"[SMS] 第 {round_no} 轮获取验证码 activation_id={activation_id}，"
                f"已等 {elapsed}s，剩余约 {remaining_before}s"
            )
            if provider in {"smsbower", "sms_bower", "smsb"}:
                from core import sms_bower
                try:
                    text = sms_bower.get_status(http, runtime_options(), activation_id)
                except sms_bower.SmsBowerError as exc:
                    raise SmsProviderError(str(exc)) from exc
                if text.startswith("STATUS_OK:"):
                    code = text.split(":", 1)[1].strip().strip("'\"")
                    if code:
                        logger.info("[SMSBower] 收到验证码：%s**", code[:2])
                        return code
                if text == "STATUS_CANCEL":
                    raise SmsProviderError("SMSBower 激活已取消")
                time.sleep(interval)
                continue

            if provider in _HEROSMS_PROVIDERS:
                from core import hero_sms

                try:
                    text = hero_sms.get_status(http, runtime_options(), activation_id)
                except Exception as exc:
                    raise _map_hero_error(exc) from exc
                if text.startswith("STATUS_OK:"):
                    code = text.split(":", 1)[1].strip().strip("'\"")
                    if code:
                        logger.info("[SMS:HeroSMS] 收到验证码：%s**", code[:2])
                        return code
                if text == "STATUS_CANCEL":
                    raise SmsProviderError("HeroSMS 激活已取消（STATUS_CANCEL）")
                remaining = max(0, int(deadline - time.time()))
                logger.info(
                    "[SMS:HeroSMS] 第 %s 轮未收到验证码，状态=%s，%ss 后重试（剩余 %ss）",
                    round_no,
                    text or "UNKNOWN",
                    interval,
                    remaining,
                )
                time.sleep(interval)
                continue

            if provider == "l":
                data = _post_l_json(http, "/api/admin/l/fetch-code", {"id": activation_id})
                code = str(data.get("code") or "").strip()
                raw = str(data.get("raw") or "").strip()
                status = str((data.get("item") or {}).get("status") or "").strip()
                if code:
                    logger.info(f"[SMS:L] 第 {round_no} 轮收到验证码：{code}")
                    return code
                remaining = max(0, int(deadline - time.time()))
                logger.info(
                    f"[SMS:L] 第 {round_no} 轮未收到验证码，状态={status or raw or 'WAIT'}，"
                    f"{interval}s 后重试（剩余 {remaining}s）"
                )
                time.sleep(interval)
                continue

            if provider == "h":
                data = _post_h_json(http, "/api/admin/h/fetch-code", {"id": activation_id})
                code = str(data.get("code") or "").strip()
                raw = str(data.get("raw") or "").strip()
                status = str((data.get("item") or {}).get("status") or "").strip()
                if code:
                    logger.info(f"[SMS:H] 第 {round_no} 轮收到验证码：{code}")
                    return code
                remaining = max(0, int(deadline - time.time()))
                logger.info(
                    f"[SMS:H] 第 {round_no} 轮未收到验证码，状态={status or raw or 'WAIT'}，"
                    f"{interval}s 后重试（剩余 {remaining}s）"
                )
                time.sleep(interval)
                continue

            text = _request_grizzly(http, {"action": "getStatus", "id": activation_id})

            if text.startswith("STATUS_OK:"):
                code = text.split(":", 1)[1].strip()
                logger.info(f"[SMS] 第 {round_no} 轮收到验证码：{code}")
                return code
            if text == "STATUS_CANCEL":
                raise SmsProviderError("激活已被取消（STATUS_CANCEL）")
            # STATUS_WAIT_CODE / STATUS_WAIT_RETRY:* / STATUS_WAIT_RESEND → 继续等
            remaining = max(0, int(deadline - time.time()))
            logger.info(f"[SMS] 第 {round_no} 轮未收到验证码，状态={text}，{interval}s 后重试（剩余 {remaining}s）")
            time.sleep(interval)

        raise SmsCodeTimeout(f"等待短信超时（>{total_wait}s），activation_id={activation_id}")
    finally:
        if own_http:
            http.close()


# ============================================================
# 改状态
# ============================================================

def set_status(activation_id: str, status: int, http: CurlSession | None = None) -> str:
    """
    设置激活状态（setStatus）。
        1 = 号码已就绪（短信已发出）
        3 = 等下一条短信（重发）
        6 = 完成激活
        8 = 取消激活
    """
    own_http = http is None
    http = http or _http()
    try:
        if _provider() in {"smsbower", "sms_bower", "smsb"}:
            from core import sms_bower
            try:
                return sms_bower.call_status(http, runtime_options(), activation_id, status)
            except sms_bower.SmsBowerError as exc:
                raise SmsProviderError(str(exc)) from exc
        if _provider() == "luban":
            if int(status) != 8:
                logger.debug("[SMS:Luban] 忽略状态设置 id=%s status=%s", activation_id, status)
                return "OK"
            client = _luban_client(http)
            try:
                client.reject(_luban_activation(activation_id))
                return "OK"
            except Exception as exc:
                raise _map_luban_error(exc) from exc
            finally:
                client.close()
        if _provider() in _HEROSMS_PROVIDERS:
            from core import hero_sms

            if int(status) == 1:
                # HeroSMS 文档只保证 3/6/8；新激活默认已经处于等码状态。
                logger.debug(
                    "[SMS:HeroSMS] 本地确认短信已发送 id=%s，不提交 status=1",
                    activation_id,
                )
                return "ACCESS_READY"
            try:
                return hero_sms.set_status(
                    http, runtime_options(), activation_id, int(status)
                )
            except Exception as exc:
                raise _map_hero_error(exc) from exc
        if _provider() == "l":
            logger.debug(f"[SMS:L] 忽略状态设置 id={activation_id}, status={status}")
            return "OK"
        return _request_grizzly(http, {"action": "setStatus", "status": str(status), "id": activation_id})
    finally:
        if own_http:
            http.close()


def complete(activation_id: str, http: CurlSession | None = None) -> None:
    """标记激活完成（status=6）。失败只告警不抛，避免影响主流程。"""
    if _provider() in {"smsbower", "sms_bower", "smsb"}:
        from core import sms_bower
        try:
            set_status(activation_id, 6, http=http)
        except Exception as exc:
            # 保留激活元数据，便于调用方记录成本，也允许后续人工核对平台状态。
            logger.warning("[SMSBower] 标记完成失败（不影响 OAuth 结果）id=%s: %s", activation_id, exc)
        else:
            sms_bower.forget_activation(activation_id)
            _ACQUIRED_AT.pop(activation_id, None)
        return
    if _provider() == "luban":
        logger.info("[SMS:Luban] 已完成 id=%s", activation_id)
        _forget_luban_activation(activation_id)
        return
    if _provider() in _HEROSMS_PROVIDERS:
        from core import hero_sms

        try:
            set_status(activation_id, 6, http=http)
        except Exception as exc:
            logger.warning(
                "[SMS:HeroSMS] 标记完成失败（不影响 OAuth 结果）id=%s: %s",
                activation_id,
                exc,
            )
        else:
            hero_sms.forget_activation(activation_id)
            _ACQUIRED_AT.pop(activation_id, None)
            logger.info("[SMS:HeroSMS] 已标记完成 id=%s", activation_id)
        return
    if _provider() == "l":
        logger.info(f"[SMS:L] 已完成 id={activation_id}")
        _ACQUIRED_AT.pop(activation_id, None)
        return
    if _provider() == "h":
        # H 成功 fetch-code 后后台会自动按多次收码策略重取；这里不 release。
        logger.info(f"[SMS:H] 已完成 id={activation_id}")
        _ACQUIRED_AT.pop(activation_id, None)
        return
    try:
        set_status(activation_id, 6, http=http)
        logger.info(f"[SMS] 已标记完成 activation_id={activation_id}")
        _ACQUIRED_AT.pop(activation_id, None)
    except Exception as exc:
        logger.warning(f"[SMS] 标记完成失败（不影响结果）：{exc}")


def _do_cancel_sync(activation_id: str, http_factory) -> None:
    """实际的同步取消逻辑：等够 2 分钟限制 → 发请求 → 失败重试一次。"""
    acquired_at = _ACQUIRED_AT.get(activation_id)
    if acquired_at is not None:
        elapsed = time.time() - acquired_at
        if elapsed < _MIN_CANCEL_DELAY:
            wait = _MIN_CANCEL_DELAY - elapsed
            logger.info(
                f"[SMS] 取消等待 GrizzlySMS 2 分钟限制：activation_id={activation_id}，"
                f"还需等 {wait:.0f}s..."
            )
            time.sleep(wait)

    # 后台线程不能复用外部 http session（curl_cffi 非线程安全），自己建一个
    http = http_factory()
    try:
        for attempt in range(1, 3):
            try:
                set_status(activation_id, 8, http=http)
                logger.info(f"[SMS] 已取消 activation_id={activation_id}")
                _ACQUIRED_AT.pop(activation_id, None)
                return
            except Exception as exc:
                if attempt == 1:
                    logger.warning(f"[SMS] 取消失败（{exc}），5s 后重试...")
                    time.sleep(5)
                else:
                    logger.warning(
                        f"[SMS] 取消最终失败（不影响结果，需到平台手动取消）：activation_id={activation_id}, {exc}"
                    )
    finally:
        try:
            http.close()
        except Exception:
            pass


def _cancel_hero_sync(
    activation_id: str,
    options: dict,
    http: CurlSession | None = None,
) -> None:
    """Cancel HeroSMS while retaining the task's runtime options in worker threads."""
    from core import hero_sms

    acquired_at = _ACQUIRED_AT.get(activation_id)
    if acquired_at is not None:
        elapsed = time.time() - acquired_at
        if elapsed < _MIN_CANCEL_DELAY:
            wait = _MIN_CANCEL_DELAY - elapsed
            logger.info(
                "[SMS:HeroSMS] 取消前等待平台最短持有期：id=%s remaining=%.0fs",
                activation_id,
                wait,
            )
            time.sleep(wait)

    own_http = http is None
    hero_http = http or _http()
    try:
        for attempt in range(1, 3):
            try:
                hero_sms.set_status(hero_http, options, activation_id, 8)
                logger.info("[SMS:HeroSMS] 已取消 id=%s", activation_id)
                return
            except Exception as exc:
                if attempt == 1:
                    logger.warning(
                        "[SMS:HeroSMS] 取消失败（%s），5s 后重试", _map_hero_error(exc)
                    )
                    time.sleep(5)
                else:
                    logger.warning(
                        "[SMS:HeroSMS] 取消最终失败（需到平台人工核对）id=%s: %s",
                        activation_id,
                        _map_hero_error(exc),
                    )
    finally:
        hero_sms.forget_activation(activation_id)
        _ACQUIRED_AT.pop(activation_id, None)
        if own_http:
            try:
                hero_http.close()
            except Exception:
                pass


def cancel(
    activation_id: str,
    http: CurlSession | None = None,
    background: bool = True,
    rejected: bool = False,
) -> None:
    """
    取消激活（status=8），释放号码避免白扣费。

    GrizzlySMS/SMSBower 规则：号码取出后约 2 分钟内不允许取消。本函数默认 background=True，
    把"等 2 分钟+取消"放到后台守护线程里执行，主流程立刻返回继续走（如换下一个号），
    避免被这 2 分钟阻塞。

    background=False 时同步等够时间再返回（少数场景需要确认取消完成时用）。

    失败只告警不抛，不影响主流程。
    """
    if _provider() in {"smsbower", "sms_bower", "smsb"}:
        from core import sms_bower
        options = runtime_options()
        if rejected:
            sms_bower.reject_offer(activation_id, options)

        def _cancel_bower() -> None:
            own = _http()
            try:
                acquired_at = _ACQUIRED_AT.get(activation_id)
                if acquired_at is not None:
                    delay = max(0.0, _MIN_CANCEL_DELAY - (time.time() - acquired_at))
                    if delay:
                        time.sleep(delay)
                sms_bower.call_status(own, options, activation_id, 8)
            except Exception as exc:
                logger.warning("[SMSBower] 取消失败 id=%s: %s", activation_id, exc)
            finally:
                sms_bower.forget_activation(activation_id)
                _ACQUIRED_AT.pop(activation_id, None)
                own.close()

        if background:
            threading.Thread(target=_cancel_bower, name=f"smsbower-cancel-{activation_id}", daemon=True).start()
        else:
            _cancel_bower()
        return
    if _provider() == "luban":
        own_http = http is None
        luban_http = http or _http()
        client = None
        try:
            client = _luban_client(luban_http)
            client.reject(_luban_activation(activation_id))
            logger.info("[SMS:Luban] 已拒号并释放 id=%s", activation_id)
        except Exception as exc:
            logger.warning(
                "[SMS:Luban] 拒号失败（不影响主流程）id=%s: %s: %s",
                activation_id, type(exc).__name__, _map_luban_error(exc),
            )
        finally:
            if client is not None:
                client.close()
            _forget_luban_activation(activation_id)
            if own_http:
                luban_http.close()
        return
    if _provider() in _HEROSMS_PROVIDERS:
        options = runtime_options()
        if not background:
            _cancel_hero_sync(activation_id, options, http=http)
            return
        threading.Thread(
            target=_cancel_hero_sync,
            args=(activation_id, options),
            name=f"herosms-cancel-{activation_id}",
            daemon=True,
        ).start()
        logger.debug("[SMS:HeroSMS] 取消任务已派后台：id=%s", activation_id)
        return
    if _provider() == "l":
        try:
            _release_l_number(activation_id, http=http)
        except Exception as exc:
            logger.warning(f"[SMS:L] 释放号码失败（不影响主流程）：id={activation_id}, {type(exc).__name__}: {exc}")
            _ACQUIRED_AT.pop(activation_id, None)
        return
    if _provider() == "h":
        try:
            _release_h_number(activation_id, http=http)
        except Exception as exc:
            logger.warning(f"[SMS:H] 释放号码失败（不影响主流程）：id={activation_id}, {type(exc).__name__}: {exc}")
            _ACQUIRED_AT.pop(activation_id, None)
        return

    if not background:
        _do_cancel_sync(activation_id, _http)
        return

    t = threading.Thread(
        target=_do_cancel_sync,
        args=(activation_id, _http),
        name=f"sms-cancel-{activation_id}",
        daemon=True,
    )
    t.start()
    logger.debug(f"[SMS] 取消任务已派后台：activation_id={activation_id}")
