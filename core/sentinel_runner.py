# -*- coding: utf-8 -*-
"""
Sentinel Runner 适配层
通过 subprocess 调用项目根目录的 sentinel-runner.js，
让 Node.js 在 vm 沙箱中真实运行 sdk.js，生成可通过校验的 sentinel-token。

工作原理：
1. 从 Sentinel frame 动态发现当前 SDK，并由 SDK 生成 prepare token
2. Python 使用同一会话和 prepare token 请求 challenge
3. Runner 将 challenge 与 prepare token 喂回 SDK，生成 Proof、Turnstile 和 SO
4. Python 严格校验主 token 与独立 SO token 后再交给注册请求
"""
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from config import (
    USER_AGENT,
    CHROME_MAJOR,
    CHROME_FULL_VERSION,
    SEC_CH_UA,
    SEC_CH_UA_PLATFORM,
    SEC_CH_UA_FULL_VERSION_LIST,
    SEC_CH_UA_PLATFORM_VERSION,
    SEC_CH_UA_ARCH,
    SEC_CH_UA_BITNESS,
    SEC_CH_UA_MODEL,
    TIMEZONE_IANA,
    TIMEZONE_NAME,
    TIMEZONE_OFFSET_MINUTES,
    NAVIGATOR_LANGUAGE,
    NAVIGATOR_LANGUAGES,
    SCREEN_WIDTH,
    SCREEN_HEIGHT,
    HARDWARE_CONCURRENCY,
    JS_HEAP_SIZE_LIMIT,
    DEVICE_MEMORY,
    SENTINEL_SV,
    OPENAI_BUILD_ID,
)

logger = logging.getLogger(__name__)

# 项目根目录（core 的上一级）
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Node 资源放在项目根的 sentinel/ 子目录下
_SENTINEL_DIR = _PROJECT_ROOT / "sentinel"
_RUNNER_PATH = _SENTINEL_DIR / "sentinel-runner.js"
_SDK_PATH = _SENTINEL_DIR / "sdk.js"

_SENTINEL_FRAME_URL = (
    "https://sentinel.openai.com/backend-api/sentinel/frame.html"
    f"?sv={SENTINEL_SV}"
)
_SENTINEL_ASSET_TTL_SECONDS = 1800.0
_SENTINEL_ASSET_MAX_BYTES = 2 * 1024 * 1024
_SENTINEL_FRAME_MAX_BYTES = 512 * 1024
_SENTINEL_ASSET_CACHE: dict[str, Any] = {}
_SENTINEL_ASSET_LOCK = threading.Lock()

# 各 flow 对应的 page-url（与浏览器实际页面一致，影响 sdk.js 指纹生成）
_FLOW_PAGE_URL = {
    "username_password_create": "https://auth.openai.com/create-account/password",
    "authorize_continue": "https://auth.openai.com/email-verification",
    "email_otp_validate": "https://auth.openai.com/email-verification",
    "oauth_create_account": "https://auth.openai.com/about-you",
}

# Node 子进程超时（秒）。sdk.js 内部可能要做 PoW，留充裕一点
_RUNNER_TIMEOUT = 120


@dataclass(slots=True)
class SentinelArtifacts:
    token: str
    so_token: str = ""
    proof_token: str = ""
    turnstile_token: str = ""
    challenge_token: str = ""
    token_error: str = ""
    proof_error: str = ""
    turnstile_error: str = ""
    collector_error: str = ""
    so_error: str = ""
    proof_required: bool = False
    turnstile_required: bool = False
    so_required: bool = False
    oai_sc_value: str = ""
    sdk_url: str = ""
    sdk_hash: str = ""


@dataclass(slots=True)
class ChatRequirementsArtifacts:
    """ChatGPT chat-requirements/finalize 需要的两个 SDK 字符串。"""

    proof_token: str
    turnstile_token: str
    proof_error: str = ""
    turnstile_error: str = ""
    collector_error: str = ""
    so_error: str = ""
    sdk_url: str = ""
    sdk_hash: str = ""


class SentinelArtifactError(RuntimeError):
    """SDK 已运行，但返回的 Sentinel 产物不完整或上下文不一致。"""


def _required(challenge: dict, key: str) -> bool:
    value = challenge.get(key)
    return bool(isinstance(value, dict) and value.get("required"))


def _parse_composite_token(raw: str, label: str) -> dict:
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise SentinelArtifactError(f"Sentinel {label} 不是合法 JSON") from exc
    if not isinstance(parsed, dict):
        raise SentinelArtifactError(f"Sentinel {label} 结构不是对象")
    return parsed


def _validate_sentinel_artifacts(
    artifacts: SentinelArtifacts,
    *,
    challenge: dict,
    flow: str,
    device_id: str,
) -> None:
    errors: list[str] = []
    for name in ("token", "proof", "turnstile", "collector", "so"):
        error = str(getattr(artifacts, f"{name}_error", "") or "").strip()
        if error:
            errors.append(f"{name}={error[:180]}")

    if not artifacts.challenge_token:
        errors.append("challenge token 为空")
    if not artifacts.token:
        errors.append("组合 token 为空")
    if artifacts.proof_required and not artifacts.proof_token:
        errors.append("Proof 必需但为空")
    if artifacts.turnstile_required and not artifacts.turnstile_token:
        errors.append("Turnstile 必需但为空")
    if artifacts.so_required and not artifacts.so_token:
        errors.append("SO 必需但为空")
    if errors:
        raise SentinelArtifactError(
            f"Sentinel SDK 产物无效 flow={flow}: " + "; ".join(dict.fromkeys(errors))
        )

    token = _parse_composite_token(artifacts.token, "token")
    expected = {
        "c": artifacts.challenge_token,
        "id": device_id,
        "flow": flow,
    }
    for key, value in expected.items():
        if str(token.get(key) or "") != str(value or ""):
            raise SentinelArtifactError(f"Sentinel token 字段不一致: {key}")
    if artifacts.proof_required or artifacts.proof_token or "p" in token:
        if token.get("p") != artifacts.proof_token:
            raise SentinelArtifactError("Sentinel token 的 Proof 与 SDK 产物不一致")
    if artifacts.turnstile_required or artifacts.turnstile_token or "t" in token:
        if token.get("t") != artifacts.turnstile_token:
            raise SentinelArtifactError("Sentinel token 的 Turnstile 与 SDK 产物不一致")

    if artifacts.so_token:
        so_token = _parse_composite_token(artifacts.so_token, "SO token")
        for key, value in expected.items():
            if str(so_token.get(key) or "") != str(value or ""):
                raise SentinelArtifactError(f"Sentinel SO token 字段不一致: {key}")
        if not so_token.get("so"):
            raise SentinelArtifactError("Sentinel SO token 缺少 so 字段")


def _validated_sentinel_url(
    value: str,
    *,
    base_url: str,
    label: str,
) -> str:
    try:
        url = urljoin(base_url, str(value or "").strip())
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"Sentinel {label} URL 非法") from exc
    if (
        parsed.scheme.lower() != "https"
        or hostname not in {
            "sentinel.openai.com",
            "chatgpt.com",
        }
        or port not in (None, 443)
        or parsed.username
        or parsed.password
    ):
        raise RuntimeError(f"Sentinel {label} URL 非法")
    return url


def _validated_sdk_url(value: str, *, base_url: str = _SENTINEL_FRAME_URL) -> str:
    return _validated_sentinel_url(
        value,
        base_url=base_url,
        label="SDK",
    )


class _SentinelFrameParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.script_sources: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.casefold() != "script":
            return
        for name, value in attrs:
            if name.casefold() == "src" and value:
                self.script_sources.append(str(value).strip())
                break

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)


def _discover_sentinel_sdk_url(frame_source: str, *, frame_url: str) -> str:
    parser = _SentinelFrameParser()
    parser.feed(str(frame_source or ""))
    parser.close()
    for source in parser.script_sources:
        try:
            candidate = urljoin(frame_url, source)
            path = urlparse(candidate).path
        except (TypeError, ValueError) as exc:
            if "/sentinel/" in source and "sdk.js" in source:
                raise RuntimeError("Sentinel SDK URL 非法") from exc
            continue
        if not re.search(r"(?:^|/)sentinel/[^/]+/sdk\.js$", path):
            continue
        return _validated_sdk_url(candidate, base_url=frame_url)
    raise RuntimeError("Sentinel frame 未发现 sdk.js")


def _cached_sdk_asset(cache_key: str) -> tuple[str, str, str] | None:
    entry = _SENTINEL_ASSET_CACHE.get(cache_key)
    if not isinstance(entry, dict):
        return None
    fetched_at = float(entry.get("fetched_at") or 0.0)
    url = str(entry.get("url") or "")
    source = str(entry.get("source") or "")
    sdk_hash = str(entry.get("hash") or "")
    if (
        url
        and source
        and sdk_hash
        and time.time() - fetched_at < _SENTINEL_ASSET_TTL_SECONDS
    ):
        return url, source, sdk_hash
    return None


def _store_sdk_asset(cache_key: str, url: str, source: str) -> tuple[str, str, str]:
    sdk_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    _SENTINEL_ASSET_CACHE[cache_key] = {
        "url": url,
        "source": source,
        "hash": sdk_hash,
        "fetched_at": time.time(),
    }
    return url, source, sdk_hash


def load_sentinel_sdk_assets(session) -> tuple[str, str, str]:
    """从 Auth Sentinel iframe 发现 SDK，并为每个注册会话建立页面状态。"""
    session_asset = getattr(session, "_auth_sentinel_sdk_asset", None)
    if (
        isinstance(session_asset, tuple)
        and len(session_asset) == 3
        and all(str(value or "") for value in session_asset)
    ):
        return session_asset

    frame_headers_factory = getattr(session, "get_sentinel_frame_headers", None)
    if callable(frame_headers_factory):
        frame_headers = frame_headers_factory()
    else:
        frame_headers = session.get_auth_navigate_headers(
            referer="https://auth.openai.com/",
            user_initiated=False,
            target_origin="https://sentinel.openai.com",
        )
        frame_headers["sec-fetch-site"] = "same-site"
        frame_headers["sec-fetch-dest"] = "iframe"
        frame_headers.pop("sec-fetch-user", None)
    frame = session.get(_SENTINEL_FRAME_URL, headers=frame_headers)
    if frame.status_code != 200:
        raise RuntimeError(f"Sentinel frame HTTP {frame.status_code}")
    frame_url = str(getattr(frame, "url", "") or _SENTINEL_FRAME_URL)
    setattr(session, "_auth_sentinel_frame_url", frame_url)
    sdk_url = _discover_sentinel_sdk_url(
        frame.text or "",
        frame_url=frame_url,
    )
    cache_key = f"auth-sdk:{sdk_url}"
    with _SENTINEL_ASSET_LOCK:
        cached = _cached_sdk_asset(cache_key)
    if cached:
        setattr(session, "_auth_sentinel_sdk_asset", cached)
        return cached

    sdk_headers = session.get_sentinel_headers()
    sdk_headers.update({
        "accept": "*/*",
        "referer": frame_url,
        "sec-fetch-dest": "script",
        "sec-fetch-mode": "no-cors",
        "sec-fetch-site": "same-origin",
        "priority": "u=1",
    })
    sdk_headers.pop("content-type", None)
    sdk_headers.pop("origin", None)
    sdk_response = session.get(sdk_url, headers=sdk_headers)
    source = sdk_response.text or ""
    size = len(source.encode("utf-8", errors="replace"))
    if sdk_response.status_code != 200 or "SentinelSDK" not in source:
        raise RuntimeError(f"Sentinel SDK HTTP {sdk_response.status_code}")
    if size > _SENTINEL_ASSET_MAX_BYTES:
        raise RuntimeError("Sentinel SDK 文件过大")

    with _SENTINEL_ASSET_LOCK:
        asset = _store_sdk_asset(cache_key, sdk_url, source)
    setattr(session, "_auth_sentinel_sdk_asset", asset)
    return asset


def load_sentinel_sdk_from_url(
    session,
    sdk_url: str,
    *,
    referer: str = "https://chatgpt.com/",
) -> tuple[str, str, str]:
    """加载指定页面实际使用的 SDK，按完整 URL 独立缓存。"""
    validated_url = _validated_sdk_url(sdk_url, base_url=referer)
    cache_key = f"url:{validated_url}"
    with _SENTINEL_ASSET_LOCK:
        cached = _cached_sdk_asset(cache_key)
    if cached:
        return cached

    headers = session._get_common_headers()
    headers.update({
        "accept": "*/*",
        "referer": referer,
        "sec-fetch-dest": "script",
        "sec-fetch-mode": "no-cors",
        "sec-fetch-site": "same-origin",
    })
    response = session.get(validated_url, headers=headers)
    source = response.text or ""
    size = len(source.encode("utf-8", errors="replace"))
    if response.status_code != 200 or "SentinelSDK" not in source:
        raise RuntimeError(f"Sentinel SDK HTTP {response.status_code}")
    if size > _SENTINEL_ASSET_MAX_BYTES:
        raise RuntimeError("Sentinel SDK 文件过大")

    with _SENTINEL_ASSET_LOCK:
        cached = _cached_sdk_asset(cache_key)
        if cached:
            return cached
        return _store_sdk_asset(cache_key, validated_url, source)


def load_sentinel_sdk_from_frame(
    session,
    frame_url: str,
    *,
    referer: str = "https://chatgpt.com/",
    session_cache_attr: str = "",
) -> tuple[str, str, str]:
    """使用当前会话访问 Sentinel frame，并加载该 frame 声明的 SDK。"""
    if session_cache_attr:
        session_asset = getattr(session, session_cache_attr, None)
        if (
            isinstance(session_asset, tuple)
            and len(session_asset) == 3
            and all(str(value or "") for value in session_asset)
        ):
            return session_asset

    validated_frame_url = _validated_sentinel_url(
        frame_url,
        base_url=referer,
        label="frame",
    )
    headers = session._get_common_headers()
    headers.update({
        "accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "*/*;q=0.8"
        ),
        "referer": referer,
        "sec-fetch-dest": "iframe",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "priority": "u=0, i",
        "upgrade-insecure-requests": "1",
    })
    frame = session.get(validated_frame_url, headers=headers)
    status = int(getattr(frame, "status_code", 0) or 0)
    if status != 200:
        raise RuntimeError(f"Sentinel frame HTTP {status}")

    resolved_frame_url = _validated_sentinel_url(
        str(getattr(frame, "url", "") or validated_frame_url),
        base_url=validated_frame_url,
        label="frame",
    )
    frame_source = str(getattr(frame, "text", "") or "")
    if len(frame_source.encode("utf-8", errors="replace")) > _SENTINEL_FRAME_MAX_BYTES:
        raise RuntimeError("Sentinel frame 文件过大")
    sdk_url = _discover_sentinel_sdk_url(
        frame_source,
        frame_url=resolved_frame_url,
    )
    asset = load_sentinel_sdk_from_url(
        session,
        sdk_url,
        referer=resolved_frame_url,
    )
    if session_cache_attr:
        setattr(session, session_cache_attr, asset)
    return asset


def _resolve_node_executable() -> str:
    """
    解析 Node 可执行文件名。Windows 下默认 node.exe，类 Unix 为 node。
    允许通过环境变量 NODE_EXECUTABLE 覆盖。
    """
    default_name = "node.exe" if sys.platform.startswith("win") else "node"
    override = str(os.environ.get("NODE_EXECUTABLE") or "").strip()
    if override:
        expanded = os.path.expandvars(os.path.expanduser(override))
        has_path_separator = os.path.sep in expanded or bool(
            os.path.altsep and os.path.altsep in expanded
        )
        if not has_path_separator:
            return shutil.which(expanded) or expanded
        if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
            return expanded

        # .env may have been copied from another host (for example a macOS
        # nvm path into Linux Docker). Prefer the deployment's PATH runtime.
        fallback = shutil.which(Path(expanded).name) or shutil.which(default_name)
        if fallback:
            return fallback
        return expanded
    return shutil.which(default_name) or default_name


def _ensure_runner_environment() -> None:
    """启动前的强制检查：runner.js / sdk.js 必须存在。"""
    if not _RUNNER_PATH.exists():
        raise FileNotFoundError(f"找不到 sentinel-runner.js: {_RUNNER_PATH}")
    if not _SDK_PATH.exists():
        raise FileNotFoundError(f"找不到 sdk.js: {_SDK_PATH}")


def _runner_context_args(
    *,
    flow: str,
    device_id: str,
    sdk_path: str,
    sdk_url: str,
    user_agent: str | None = None,
    page_url: str | None = None,
    browser_profile: dict | None = None,
    sentinel_sid: str | None = None,
    react_listening_key: str | None = None,
    react_container_key: str | None = None,
    react_resources_key: str | None = None,
    cookie: str | None = None,
) -> tuple[list[str], str]:
    profile = browser_profile or {}
    browser_family = str(profile.get("browser_family") or "chrome")
    request_idle_callback = int(
        (profile.get("window_feature_flags") or {}).get("requestIdleCallback", 0)
    )
    ua = user_agent or str(profile.get("user_agent") or USER_AGENT)
    screen_width = int(profile.get("screen_width", SCREEN_WIDTH))
    screen_height = int(profile.get("screen_height", SCREEN_HEIGHT))
    hardware_concurrency = int(profile.get("hardware_concurrency", HARDWARE_CONCURRENCY))
    js_heap_size_limit = int(profile.get("js_heap_size_limit", JS_HEAP_SIZE_LIMIT))
    device_memory = int(profile.get("device_memory", DEVICE_MEMORY))
    device_pixel_ratio = float(profile.get("device_pixel_ratio", 2))
    navigator_language = str(profile.get("navigator_language", NAVIGATOR_LANGUAGE))
    navigator_languages = list(profile.get("navigator_languages", NAVIGATOR_LANGUAGES))
    chrome_major = str(profile.get("chrome_major", CHROME_MAJOR))
    chrome_full_version = str(profile.get("chrome_full_version", CHROME_FULL_VERSION))
    sec_ch_ua = str(profile.get("sec_ch_ua", SEC_CH_UA))
    sec_ch_ua_platform = str(profile.get("sec_ch_ua_platform", SEC_CH_UA_PLATFORM))
    navigator_platform = str(profile.get("navigator_platform", "MacIntel"))
    navigator_vendor = str(profile.get("navigator_vendor", "Google Inc."))
    ua_data_platform = str(
        profile.get("user_agent_data_platform", sec_ch_ua_platform.strip('"') or "macOS")
    )
    sec_ch_ua_full_version_list = str(
        profile.get("sec_ch_ua_full_version_list", SEC_CH_UA_FULL_VERSION_LIST)
    )
    sec_ch_ua_platform_version = str(
        profile.get("sec_ch_ua_platform_version", SEC_CH_UA_PLATFORM_VERSION)
    )
    sec_ch_ua_arch = str(profile.get("sec_ch_ua_arch", SEC_CH_UA_ARCH))
    sec_ch_ua_bitness = str(profile.get("sec_ch_ua_bitness", SEC_CH_UA_BITNESS))
    sec_ch_ua_model = str(profile.get("sec_ch_ua_model", SEC_CH_UA_MODEL))
    build_id = str(profile.get("build_id", OPENAI_BUILD_ID))
    runner_build_id = (
        ""
        if page_url is None
        and flow in {
            "authorize_continue",
            "email_otp_validate",
            "oauth_create_account",
            "username_password_create",
        }
        else build_id
    )
    timezone_iana = str(profile.get("timezone_iana", TIMEZONE_IANA))
    timezone_name = str(profile.get("timezone_name", TIMEZONE_NAME))
    timezone_offset_minutes = int(
        profile.get("timezone_offset_minutes", TIMEZONE_OFFSET_MINUTES)
    )
    runner_cookie = cookie or f"oai-did={device_id}"
    page = page_url or _FLOW_PAGE_URL.get(
        flow, "https://auth.openai.com/create-account/password"
    )

    return [
        "--flow", flow,
        "--device-id", device_id,
        "--sentinel-sid", sentinel_sid or "",
        "--react-listening-key", react_listening_key or str(profile.get("react_listening_key") or ""),
        "--react-container-key", react_container_key or str(profile.get("react_container_key") or ""),
        "--react-resources-key", react_resources_key or str(profile.get("react_resources_key") or ""),
        "--page-url", page,
        "--user-agent", ua,
        "--browser-family", browser_family,
        "--navigator-platform", navigator_platform,
        "--navigator-vendor", navigator_vendor,
        "--user-agent-data-platform", ua_data_platform,
        "--request-idle-callback", "1" if request_idle_callback else "0",
        "--sdk", sdk_path,
        "--script-src", sdk_url,
        "--build-id", runner_build_id,
        "--width", str(screen_width),
        "--height", str(screen_height),
        "--cores", str(hardware_concurrency),
        "--language", navigator_language,
        "--languages", ",".join(navigator_languages),
        "--time-zone", timezone_iana,
        "--timezone-name", timezone_name,
        "--timezone-offset-minutes", str(timezone_offset_minutes),
        "--js-heap-size-limit", str(js_heap_size_limit),
        "--device-memory", str(device_memory),
        "--device-pixel-ratio", str(device_pixel_ratio),
        "--chrome-major", chrome_major,
        "--chrome-full-version", chrome_full_version,
        "--sec-ch-ua", sec_ch_ua,
        "--sec-ch-ua-platform", sec_ch_ua_platform,
        "--sec-ch-ua-full-version-list", sec_ch_ua_full_version_list,
        "--sec-ch-ua-platform-version", sec_ch_ua_platform_version,
        "--sec-ch-ua-arch", sec_ch_ua_arch,
        "--sec-ch-ua-bitness", sec_ch_ua_bitness,
        "--sec-ch-ua-model", sec_ch_ua_model,
        "--cookie", runner_cookie,
    ], timezone_iana


def _invoke_sdk_mode(
    mode: str,
    *,
    sdk_source: str,
    sdk_url: str,
    flow: str,
    device_id: str,
    challenge: dict | None = None,
    prepare_token: str = "",
    observer_timeout_ms: int = 5000,
    user_agent: str | None = None,
    page_url: str | None = None,
    browser_profile: dict | None = None,
    sentinel_sid: str | None = None,
    react_listening_key: str | None = None,
    react_container_key: str | None = None,
    react_resources_key: str | None = None,
    cookie: str | None = None,
) -> dict:
    if mode not in {"prepare", "artifacts"}:
        raise ValueError(f"不支持的 Sentinel Runner 模式: {mode}")
    if not _RUNNER_PATH.exists():
        raise FileNotFoundError(f"找不到 sentinel-runner.js: {_RUNNER_PATH}")
    if not sdk_source:
        raise ValueError("Sentinel SDK source 不能为空")
    if not flow:
        raise ValueError("flow 不能为空")
    if not device_id:
        raise ValueError("device_id 不能为空")

    temp_paths: list[str] = []
    try:
        sdk_tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".js", prefix="sentinel-sdk-", delete=False, encoding="utf-8"
        )
        sdk_tmp.write(sdk_source)
        sdk_tmp.flush()
        sdk_tmp.close()
        temp_paths.append(sdk_tmp.name)

        cmd = [_resolve_node_executable(), str(_RUNNER_PATH), "--mode", mode]
        context_args, timezone_iana = _runner_context_args(
            flow=flow,
            device_id=device_id,
            sdk_path=sdk_tmp.name,
            sdk_url=_validated_sdk_url(sdk_url),
            user_agent=user_agent,
            page_url=page_url,
            browser_profile=browser_profile,
            sentinel_sid=sentinel_sid,
            react_listening_key=react_listening_key,
            react_container_key=react_container_key,
            react_resources_key=react_resources_key,
            cookie=cookie,
        )
        cmd.extend(context_args)

        if mode == "artifacts":
            if not isinstance(challenge, dict):
                raise ValueError("artifacts 模式缺少 challenge")
            if not prepare_token:
                raise ValueError("artifacts 模式缺少 prepare_token")

            challenge_tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", prefix="sentinel-challenge-", delete=False, encoding="utf-8"
            )
            json.dump(challenge, challenge_tmp, ensure_ascii=False)
            challenge_tmp.flush()
            challenge_tmp.close()
            temp_paths.append(challenge_tmp.name)

            prepare_tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", prefix="sentinel-prepare-", delete=False, encoding="utf-8"
            )
            prepare_tmp.write(prepare_token)
            prepare_tmp.flush()
            prepare_tmp.close()
            temp_paths.append(prepare_tmp.name)
            cmd.extend([
                "--challenge-file", challenge_tmp.name,
                "--prepare-token-file", prepare_tmp.name,
                "--observer-timeout-ms", str(max(0, int(observer_timeout_ms))),
            ])

        env = os.environ.copy()
        env.pop("SENTINEL_CONFIG", None)
        env["SENTINEL_CONFIG"] = "__none__"
        env["TZ"] = timezone_iana
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                cwd=str(_PROJECT_ROOT),
                timeout=_RUNNER_TIMEOUT,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"sentinel-runner.js 执行超时（>{_RUNNER_TIMEOUT}s），mode={mode}, flow={flow}"
            ) from exc
        except FileNotFoundError as exc:
            raise RuntimeError(
                "未找到 Node 可执行文件，请确认已安装 Node.js 并加入 PATH，"
                "或通过 NODE_EXECUTABLE 环境变量指定绝对路径。"
            ) from exc

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or f"exit_{proc.returncode}").strip()
            raise RuntimeError(f"Sentinel SDK Runner 失败: {detail[:1000]}")
        try:
            result = json.loads((proc.stdout or "").strip())
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Sentinel SDK Runner 输出不是合法 JSON: {(proc.stdout or '')[:300]}"
            ) from exc
        if not isinstance(result, dict):
            raise RuntimeError("Sentinel SDK Runner 输出结构不是对象")
        return result
    finally:
        for temp_path in temp_paths:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def generate_sentinel_prepare_token(
    *,
    sdk_source: str,
    sdk_url: str,
    flow: str,
    device_id: str,
    **runner_context,
) -> str:
    result = _invoke_sdk_mode(
        "prepare",
        sdk_source=sdk_source,
        sdk_url=sdk_url,
        flow=flow,
        device_id=device_id,
        **runner_context,
    )
    prepare_token = str(result.get("prepare_token") or "").strip()
    if not prepare_token:
        raise SentinelArtifactError("Sentinel SDK 未生成 prepare token")
    return prepare_token


def generate_sentinel_artifacts(
    challenge: dict,
    *,
    prepare_token: str,
    sdk_source: str,
    sdk_url: str,
    sdk_hash: str = "",
    flow: str,
    device_id: str,
    observer_timeout_ms: int = 5000,
    **runner_context,
) -> SentinelArtifacts:
    result = _invoke_sdk_mode(
        "artifacts",
        sdk_source=sdk_source,
        sdk_url=sdk_url,
        flow=flow,
        device_id=device_id,
        challenge=challenge,
        prepare_token=prepare_token,
        observer_timeout_ms=observer_timeout_ms,
        **runner_context,
    )
    challenge_token = str(challenge.get("token") or "").strip()
    artifacts = SentinelArtifacts(
        token=str(result.get("token") or "").strip(),
        so_token=str(result.get("so_token") or "").strip(),
        proof_token=str(result.get("proof_token") or "").strip(),
        turnstile_token=str(result.get("turnstile_token") or "").strip(),
        challenge_token=challenge_token,
        token_error=str(result.get("token_error") or "").strip(),
        proof_error=str(result.get("proof_error") or "").strip(),
        turnstile_error=str(result.get("turnstile_error") or "").strip(),
        collector_error=str(result.get("collector_error") or "").strip(),
        so_error=str(result.get("so_error") or "").strip(),
        proof_required=_required(challenge, "proofofwork"),
        turnstile_required=_required(challenge, "turnstile"),
        so_required=_required(challenge, "so"),
        oai_sc_value="0" + challenge_token if challenge_token else "",
        sdk_url=sdk_url,
        sdk_hash=sdk_hash,
    )
    _validate_sentinel_artifacts(
        artifacts,
        challenge=challenge,
        flow=flow,
        device_id=device_id,
    )
    return artifacts


def generate_chat_requirements_artifacts(
    challenge: dict,
    *,
    requirements_token: str,
    sdk_source: str,
    sdk_url: str,
    sdk_hash: str = "",
    device_id: str,
    observer_timeout_ms: int = 5000,
    **runner_context,
) -> ChatRequirementsArtifacts:
    """生成 ChatGPT chat-requirements/finalize 的 proof 与 turnstile。

    这里的 ``requirements_token`` 是 prepare 请求中的 ``p``。HAR 证明 SDK
    enforcement 必须继续绑定这个值；prepare 响应中的 ``prepare_token`` 只原样
    交回 finalize，不能作为 SDK enforcement 输入。
    """
    if not isinstance(challenge, dict):
        raise ValueError("chat-requirements challenge 必须是对象")
    if not str(challenge.get("prepare_token") or "").strip():
        raise SentinelArtifactError("chat-requirements 响应缺少 prepare_token")
    if not requirements_token:
        raise SentinelArtifactError("chat-requirements 原始 requirements token 为空")

    result = _invoke_sdk_mode(
        "artifacts",
        sdk_source=sdk_source,
        sdk_url=sdk_url,
        flow="chat",
        device_id=device_id,
        challenge=challenge,
        prepare_token=requirements_token,
        observer_timeout_ms=observer_timeout_ms,
        **runner_context,
    )
    artifacts = ChatRequirementsArtifacts(
        proof_token=str(result.get("proof_token") or "").strip(),
        turnstile_token=str(result.get("turnstile_token") or "").strip(),
        proof_error=str(result.get("proof_error") or "").strip(),
        turnstile_error=str(result.get("turnstile_error") or "").strip(),
        collector_error=str(result.get("collector_error") or "").strip(),
        so_error=str(result.get("so_error") or "").strip(),
        sdk_url=sdk_url,
        sdk_hash=sdk_hash,
    )
    errors = [
        f"proof={artifacts.proof_error}" if artifacts.proof_error else "",
        f"turnstile={artifacts.turnstile_error}" if artifacts.turnstile_error else "",
        f"collector={artifacts.collector_error}" if artifacts.collector_error else "",
        f"so={artifacts.so_error}" if artifacts.so_error else "",
    ]
    if _required(challenge, "proofofwork") and not artifacts.proof_token:
        errors.append("Proof 必需但为空")
    if _required(challenge, "turnstile") and not artifacts.turnstile_token:
        errors.append("Turnstile 必需但为空")
    errors = [item for item in errors if item]
    if errors:
        raise SentinelArtifactError(
            "ChatGPT Sentinel SDK 产物无效: " + "; ".join(dict.fromkeys(errors))
        )
    return artifacts


def generate_sentinel_token(
    challenge: dict,
    flow: str,
    device_id: str,
    user_agent: str | None = None,
    page_url: str | None = None,
    browser_profile: dict | None = None,
    sentinel_sid: str | None = None,
    react_listening_key: str | None = None,
    react_container_key: str | None = None,
    react_resources_key: str | None = None,
    cookie: str | None = None,
) -> str:
    """
    把 sentinel.openai.com 返回的 challenge 喂给 sdk.js，生成最终 sentinel-token 字符串。

    Args:
        challenge: sentinel/req 返回的完整 JSON（含 token / proofofwork / turnstile / so 字段）
        flow: 流程标识，例如 username_password_create / email_otp_validate / oauth_create_account
        device_id: oai-did，必须与 Python 端 BrowserSession 持有的同一个值
        user_agent: 必须与 Python 端请求 UA 完全一致；默认读取 config.USER_AGENT
        page_url: 当前所在页面 URL（影响 referer / location 指纹）；默认按 flow 推断

    Returns:
        openai-sentinel-token 头的完整字符串值（runner 的 stdout 原样返回，已是 JSON 字符串）

    Raises:
        FileNotFoundError: runner.js 或 sdk.js 缺失
        RuntimeError: Node 子进程异常或返回非零退出码
    """
    _ensure_runner_environment()

    if not flow:
        raise ValueError("flow 不能为空")
    if not device_id:
        raise ValueError("device_id 不能为空")

    profile = browser_profile or {}
    browser_family = str(profile.get("browser_family") or "chrome")
    request_idle_callback = int((profile.get("window_feature_flags") or {}).get("requestIdleCallback", 0))
    ua = user_agent or str(profile.get("user_agent") or USER_AGENT)
    screen_width = int(profile.get("screen_width", SCREEN_WIDTH))
    screen_height = int(profile.get("screen_height", SCREEN_HEIGHT))
    hardware_concurrency = int(profile.get("hardware_concurrency", HARDWARE_CONCURRENCY))
    js_heap_size_limit = int(profile.get("js_heap_size_limit", JS_HEAP_SIZE_LIMIT))
    device_memory = int(profile.get("device_memory", DEVICE_MEMORY))
    device_pixel_ratio = float(profile.get("device_pixel_ratio", 2))
    navigator_language = str(profile.get("navigator_language", NAVIGATOR_LANGUAGE))
    navigator_languages = list(profile.get("navigator_languages", NAVIGATOR_LANGUAGES))
    chrome_major = str(profile.get("chrome_major", CHROME_MAJOR))
    chrome_full_version = str(profile.get("chrome_full_version", CHROME_FULL_VERSION))
    sec_ch_ua = str(profile.get("sec_ch_ua", SEC_CH_UA))
    sec_ch_ua_platform = str(profile.get("sec_ch_ua_platform", SEC_CH_UA_PLATFORM))
    navigator_platform = str(profile.get("navigator_platform", "MacIntel"))
    navigator_vendor = str(profile.get("navigator_vendor", "Google Inc."))
    user_agent_data_platform = str(profile.get("user_agent_data_platform", sec_ch_ua_platform.strip('\"') or "macOS"))
    sec_ch_ua_full_version_list = str(profile.get("sec_ch_ua_full_version_list", SEC_CH_UA_FULL_VERSION_LIST))
    sec_ch_ua_platform_version = str(profile.get("sec_ch_ua_platform_version", SEC_CH_UA_PLATFORM_VERSION))
    sec_ch_ua_arch = str(profile.get("sec_ch_ua_arch", SEC_CH_UA_ARCH))
    sec_ch_ua_bitness = str(profile.get("sec_ch_ua_bitness", SEC_CH_UA_BITNESS))
    sec_ch_ua_model = str(profile.get("sec_ch_ua_model", SEC_CH_UA_MODEL))
    build_id = str(profile.get("build_id", OPENAI_BUILD_ID))
    # Auth 页面 Sentinel token 的 documentElement 通常没有 data-build；
    # ChatGPT 页面 prepare/finalize 的 p 才带前端 build。
    runner_build_id = "" if page_url is None and flow in {
        "authorize_continue",
        "email_otp_validate",
        "oauth_create_account",
        "username_password_create",
    } else build_id
    timezone_iana = str(profile.get("timezone_iana", TIMEZONE_IANA))
    timezone_name = str(profile.get("timezone_name", TIMEZONE_NAME))
    timezone_offset_minutes = int(profile.get("timezone_offset_minutes", TIMEZONE_OFFSET_MINUTES))
    runner_cookie = cookie or f"oai-did={device_id}"

    page = page_url or _FLOW_PAGE_URL.get(
        flow, "https://auth.openai.com/create-account/password"
    )

    # 把 challenge 写入临时文件，避免命令行长度 / 转义问题
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        prefix=f"sentinel-challenge-{flow}-",
        delete=False,
        encoding="utf-8",
    )
    try:
        json.dump(challenge, tmp, ensure_ascii=False)
        tmp.flush()
        tmp.close()

        cmd = [
            _resolve_node_executable(),
            str(_RUNNER_PATH),
            "--challenge-file", tmp.name,
            "--flow", flow,
            "--device-id", device_id,
            "--sentinel-sid", sentinel_sid or "",
            "--react-listening-key", react_listening_key or str(profile.get("react_listening_key") or ""),
            "--react-container-key", react_container_key or str(profile.get("react_container_key") or ""),
            "--react-resources-key", react_resources_key or str(profile.get("react_resources_key") or ""),
            "--page-url", page,
            "--user-agent", ua,
            "--browser-family", browser_family,
            "--navigator-platform", navigator_platform,
            "--navigator-vendor", navigator_vendor,
            "--user-agent-data-platform", user_agent_data_platform,
            "--request-idle-callback", "1" if request_idle_callback else "0",
            "--sdk", str(_SDK_PATH),
            "--script-src", f"https://sentinel.openai.com/sentinel/{SENTINEL_SV}/sdk.js",
            "--build-id", runner_build_id,
            # 与 config.browser / core.sentinel.py 中的指纹默认值保持一致
            "--width", str(screen_width),
            "--height", str(screen_height),
            "--cores", str(hardware_concurrency),
            "--language", navigator_language,
            "--languages", ",".join(navigator_languages),
            "--time-zone", timezone_iana,
            "--timezone-name", timezone_name,
            "--timezone-offset-minutes", str(timezone_offset_minutes),
            "--js-heap-size-limit", str(js_heap_size_limit),
            "--device-memory", str(device_memory),
            "--device-pixel-ratio", str(device_pixel_ratio),
            "--chrome-major", chrome_major,
            "--chrome-full-version", chrome_full_version,
            "--sec-ch-ua", sec_ch_ua,
            "--sec-ch-ua-platform", sec_ch_ua_platform,
            "--sec-ch-ua-full-version-list", sec_ch_ua_full_version_list,
            "--sec-ch-ua-platform-version", sec_ch_ua_platform_version,
            "--sec-ch-ua-arch", sec_ch_ua_arch,
            "--sec-ch-ua-bitness", sec_ch_ua_bitness,
            "--sec-ch-ua-model", sec_ch_ua_model,
            "--cookie", runner_cookie,
        ]

        logger.info(f"[SentinelRunner] 调用 Node 生成 token, flow={flow}")
        logger.debug(f"[SentinelRunner] 命令: {' '.join(cmd)}")

        # 关键：禁用 sentinel.config.json 自动发现（避免外部配置干扰）
        env = os.environ.copy()
        env.pop("SENTINEL_CONFIG", None)
        env["SENTINEL_CONFIG"] = "__none__"  # 故意指向不存在的文件，跳过 fallback 列表
        env["TZ"] = timezone_iana  # 让 Node VM 里的 Date.toString() 与 Python p 指纹时区一致

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                cwd=str(_PROJECT_ROOT),
                timeout=_RUNNER_TIMEOUT,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"sentinel-runner.js 执行超时（>{_RUNNER_TIMEOUT}s），flow={flow}"
            ) from exc
        except FileNotFoundError as exc:
            raise RuntimeError(
                "未找到 Node 可执行文件，请确认已安装 Node.js 并加入 PATH，"
                "或通过 NODE_EXECUTABLE 环境变量指定绝对路径。"
            ) from exc

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            raise RuntimeError(
                f"sentinel-runner.js 退出码 {proc.returncode}\n"
                f"stderr: {stderr}\n"
                f"stdout: {stdout}"
            )

        token_text = (proc.stdout or "").strip()
        if not token_text:
            raise RuntimeError(
                f"sentinel-runner.js 输出为空, stderr: {(proc.stderr or '').strip()}"
            )

        # 简单合法性校验：必须是合法 JSON 且包含关键字段
        try:
            parsed = json.loads(token_text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"runner 输出不是合法 JSON: {token_text[:200]}"
            ) from exc

        for required_key in ("p", "c", "id", "flow"):
            if required_key not in parsed:
                raise RuntimeError(
                    f"runner 输出缺少字段 {required_key}: {token_text[:200]}"
                )

        # 详细诊断：打印输出 JSON 的所有顶层字段名 + 值长度
        field_summary = {
            k: (len(v) if isinstance(v, str) else type(v).__name__)
            for k, v in parsed.items()
        }
        logger.info(
            f"[SentinelRunner] token 生成成功, flow={flow}, "
            f"包含 turnstile={'t' in parsed and bool(parsed.get('t'))}, "
            f"包含 so={bool(parsed.get('so'))}, "
            f"字段: {field_summary}"
        )
        return token_text

    finally:
        # 清理临时文件
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
