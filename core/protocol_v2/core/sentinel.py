"""OpenAI Sentinel 工作量证明（PoW）。

严格对齐 newgpt2api/backend/internal/regkit/dispatcher/gpt/sentinel.go
（该实现又对齐 basketikun/chatgpt2api 的 Python 参考）。

关键算法：
  - configArray   : 18 字段的"反指纹"数组（顺序写死）
  - b64(v)        : json.dumps(v, separators=(",",":")) → base64.b64encode
                    禁止任何空格，否则 hash 不匹配
  - SolvePoW      : 暴力求解 i ∈ [0, 500000)，让 fnv1a_32(seed+payload) 的
                    hex 前缀 ≤ difficulty（字典序）
  - SentinelToken : POST /backend-api/sentinel/req 拿 seed/difficulty，
                    解 PoW，最终返回 openai-sentinel-token 头值（JSON 字符串）

必须用与下游 API 同一个 http client（共享 cookie / UA / proxy），否则 sentinel
后端会判 token 来源异常。
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import random
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from config import browser as browser_config
from .pkce import new_device_id
from core.sentinel_runner import (
    SentinelArtifactError as SharedSentinelArtifactError,
    generate_sentinel_artifacts as generate_shared_sentinel_artifacts,
    generate_sentinel_prepare_token as generate_shared_sentinel_prepare_token,
)

logger = logging.getLogger(__name__)

_SENTINEL_MAX_ATTEMPTS = 500_000
_SENTINEL_ERR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"
_SENTINEL_SDK_URL = "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js"
_SENTINEL_FRAME_URL = "https://sentinel.openai.com/backend-api/sentinel/frame.html"
_SENTINEL_ASSET_TTL_S = 1800.0
_SENTINEL_ASSET_CACHE: dict[str, Any] = {}

_VENDOR_FLAGS = (
    "vendorSub-undefined",
    "plugins-undefined",
    "mimeTypes-undefined",
    "hardwareConcurrency-undefined",
)
_DOC_FLAGS = ("location", "implementation", "URL", "documentURI", "compatMode")
_GLOBAL_FLAGS = ("Object", "Function", "Array", "Number", "parseFloat", "undefined")
_CORES = (4, 8, 12, 16)


def _runtime_suffix(length: int) -> str:
    return new_device_id().replace("-", "")[:length]


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
    sdk_version: str = ""


class SentinelArtifactError(RuntimeError):
    """The SDK ran, but one or more returned challenge artifacts are invalid."""


class SentinelRequiredTokenError(RuntimeError):
    """A basic-token caller encountered a challenge that requires SDK artifacts."""


def _required(challenge: dict[str, Any], key: str) -> bool:
    value = challenge.get(key)
    return bool(isinstance(value, dict) and value.get("required"))


def _parse_composite_token(raw: str, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except Exception as exc:  # noqa: BLE001
        raise SentinelArtifactError(f"Sentinel {label} 不是合法 JSON") from exc
    if not isinstance(parsed, dict):
        raise SentinelArtifactError(f"Sentinel {label} 结构不是对象")
    return parsed


def _validate_sentinel_artifacts(
    artifacts: SentinelArtifacts,
    *,
    challenge: dict[str, Any],
    flow: str,
    device_id: str,
) -> None:
    errors: list[str] = []
    for name in ("token", "proof", "turnstile", "collector", "so"):
        value = str(getattr(artifacts, f"{name}_error", "") or "").strip()
        if value:
            errors.append(f"{name}={value[:180]}")

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
    if artifacts.proof_required and token.get("p") != artifacts.proof_token:
        raise SentinelArtifactError("Sentinel token 的 Proof 与 SDK 产物不一致")
    if artifacts.turnstile_required and token.get("t") != artifacts.turnstile_token:
        raise SentinelArtifactError("Sentinel token 的 Turnstile 与 SDK 产物不一致")

    if artifacts.so_token:
        so_token = _parse_composite_token(artifacts.so_token, "SO token")
        for key, value in expected.items():
            if str(so_token.get(key) or "") != str(value or ""):
                raise SentinelArtifactError(f"Sentinel SO token 字段不一致: {key}")
        if artifacts.so_required and not so_token.get("so"):
            raise SentinelArtifactError("Sentinel SO token 缺少 so 字段")


def _validated_sdk_url(value: str, *, base_url: str = _SENTINEL_FRAME_URL) -> str:
    url = urljoin(base_url, str(value or "").strip())
    parsed = urlparse(url)
    if (
        parsed.scheme.lower() != "https"
        or (parsed.hostname or "").lower() != "sentinel.openai.com"
        or parsed.port not in (None, 443)
        or parsed.username
        or parsed.password
    ):
        raise RuntimeError("sentinel sdk URL 非法")
    return url


def _sdk_version(sdk_url: str) -> str:
    match = re.search(r"/sentinel/([^/]+)/sdk\.js", sdk_url)
    return match.group(1) if match else ""


def _fnv1a_32(data: bytes) -> int:
    """FNV-1a 32-bit hash。OpenAI sentinel 用它做 PoW。"""
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def _b64_compact(v: Any) -> str:
    """json.dumps(separators=(",",":")) + base64 标准编码（含 padding）。

    Go 默认 json.Marshal 也是 compact 输出（无空格），这里与之严格对齐。
    """
    raw = json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


@dataclass(slots=True)
class SentinelGenerator:
    """一个 task 持有一个 generator；deviceID / sid 在生命周期内固定。"""

    device_id: str
    user_agent: str = browser_config.USER_AGENT
    sid: str = field(default_factory=new_device_id)
    resolution: str = f"{browser_config.SCREEN_WIDTH}x{browser_config.SCREEN_HEIGHT}"
    language: str = browser_config.NAVIGATOR_LANGUAGE
    platform: str = browser_config.USER_AGENT_DATA_PLATFORM
    browser_major: int = int(browser_config.CHROME_MAJOR)
    navigator_languages: tuple[str, ...] = tuple(browser_config.NAVIGATOR_LANGUAGES)
    timezone_iana: str = browser_config.TIMEZONE_IANA
    timezone_name: str = browser_config.TIMEZONE_NAME
    timezone_offset_minutes: int = browser_config.TIMEZONE_OFFSET_MINUTES
    device_memory: int = browser_config.DEVICE_MEMORY
    device_pixel_ratio: float = 2
    browser_environment: dict[str, Any] = field(default_factory=dict, repr=False)
    cores: int = browser_config.HARDWARE_CONCURRENCY
    history_len: int = 4_294_705_152
    flags_vendor: str = field(default_factory=lambda: random.choice(_VENDOR_FLAGS))
    flags_doc: str = field(default_factory=lambda: random.choice(_DOC_FLAGS))
    flags_global: str = field(default_factory=lambda: random.choice(_GLOBAL_FLAGS))
    react_listening_key: str = field(
        default_factory=lambda: "_reactListening" + _runtime_suffix(12)
    )
    react_container_key: str = field(
        default_factory=lambda: "__reactContainer$" + _runtime_suffix(11)
    )
    react_resources_key: str = ""
    last_so_token: str = ""
    last_oai_sc_value: str = ""

    def __post_init__(self) -> None:
        if not self.react_resources_key:
            suffix = self.react_container_key.split("$", 1)[-1]
            self.react_resources_key = "__reactResources$" + suffix
        self.browser_environment.setdefault("react_listening_key", self.react_listening_key)
        self.browser_environment.setdefault("react_container_key", self.react_container_key)
        self.browser_environment.setdefault("react_resources_key", self.react_resources_key)

    @classmethod
    def from_profile(cls, device_id: str, profile: Any) -> "SentinelGenerator":
        return cls(
            device_id=device_id,
            user_agent=str(getattr(profile, "user_agent", browser_config.USER_AGENT) or browser_config.USER_AGENT),
            language=str(
                getattr(profile, "language", browser_config.NAVIGATOR_LANGUAGE)
                or browser_config.NAVIGATOR_LANGUAGE
            ),
            platform=str(
                getattr(profile, "sec_ch_ua_platform", browser_config.SEC_CH_UA_PLATFORM)
                or browser_config.SEC_CH_UA_PLATFORM
            ).strip('"'),
            browser_major=int(
                getattr(profile, "browser_major", browser_config.CHROME_MAJOR)
                or browser_config.CHROME_MAJOR
            ),
            navigator_languages=tuple(
                getattr(profile, "navigator_languages", ())
                or tuple(browser_config.NAVIGATOR_LANGUAGES)
            ),
            timezone_iana=str(
                getattr(profile, "timezone_iana", browser_config.TIMEZONE_IANA)
                or browser_config.TIMEZONE_IANA
            ),
            timezone_name=str(
                getattr(profile, "timezone_name", browser_config.TIMEZONE_NAME)
                or browser_config.TIMEZONE_NAME
            ),
            timezone_offset_minutes=int(
                getattr(
                    profile,
                    "timezone_offset_minutes",
                    browser_config.TIMEZONE_OFFSET_MINUTES,
                )
                or browser_config.TIMEZONE_OFFSET_MINUTES
            ),
            resolution=(
                f"{int(getattr(profile, 'screen_width', browser_config.SCREEN_WIDTH) or browser_config.SCREEN_WIDTH)}"
                f"x{int(getattr(profile, 'screen_height', browser_config.SCREEN_HEIGHT) or browser_config.SCREEN_HEIGHT)}"
            ),
            cores=int(
                getattr(profile, "hardware_concurrency", browser_config.HARDWARE_CONCURRENCY)
                or browser_config.HARDWARE_CONCURRENCY
            ),
            device_memory=int(
                getattr(profile, "device_memory", browser_config.DEVICE_MEMORY)
                or browser_config.DEVICE_MEMORY
            ),
            device_pixel_ratio=float(getattr(profile, "device_pixel_ratio", 2) or 2),
            browser_environment=dict(getattr(profile, "browser_environment", {}) or {}),
        )

    def _runner_fingerprint(self) -> dict[str, Any]:
        width, _, height = self.resolution.partition("x")
        return {
            "language": self.language,
            "languages": list(self.navigator_languages),
            "timezone_iana": self.timezone_iana,
            "timezone_name": self.timezone_name,
            "timezone_offset_minutes": self.timezone_offset_minutes,
            "platform": self.platform,
            "browser_major": self.browser_major,
            "screen_width": int(width or 1920),
            "screen_height": int(height or 1080),
            "hardware_concurrency": self.cores,
            "device_memory": self.device_memory,
            "device_pixel_ratio": self.device_pixel_ratio,
            "react_listening_key": self.react_listening_key,
            "react_container_key": self.react_container_key,
            "react_resources_key": self.react_resources_key,
            "browser_profile": dict(self.browser_environment),
        }

    def _config_array(self) -> list[Any]:
        """18 字段反指纹数组。布局严格对齐 Python ref / Go sentinel.go：

          [0]  屏幕分辨率
          [1]  当前 GMT 时间字符串（Mon Jan _2 2026 ...）
          [2]  history.length 等大数
          [3]  随机/迭代计数（SolvePoW 时被覆写）
          [4]  user-agent
          [5]  sentinel sdk.js URL
          [6]  null
          [7]  null
          [8]  navigator.language
          [9]  随机值（SolvePoW 时被覆写为 elapsed_ms）
          [10] vendor 反指纹标志
          [11] document 反指纹标志
          [12] global 反指纹标志
          [13] performance.now() 抖动
          [14] sid（UUID）
          [15] ""
          [16] hardwareConcurrency
          [17] (Date.now() * 1000 - perf_now)
        """
        perf_now = 1000.0 + random.random() * 49000.0
        rng = random.random()
        # Date.toString() 使用画像本地时区，不是 UTC。显式拼英文星期/月名，
        # 避免宿主机 LC_TIME 改变 Sentinel p[1]。
        local_tz = timezone(timedelta(minutes=self.timezone_offset_minutes))
        now = datetime.now(local_tz)
        weekdays = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
        months = (
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        )
        offset = self.timezone_offset_minutes
        sign = "+" if offset >= 0 else "-"
        absolute = abs(offset)
        gmt = f"GMT{sign}{absolute // 60:02d}{absolute % 60:02d}"
        tstr = (
            f"{weekdays[now.weekday()]} {months[now.month - 1]} {now.day:>2d} "
            f"{now.year:04d} {now:%H:%M:%S} {gmt} ({self.timezone_name})"
        )
        return [
            self.resolution,
            tstr,
            self.history_len,
            rng,
            self.user_agent,
            _SENTINEL_SDK_URL,
            None,
            None,
            self.language,
            rng,
            self.flags_vendor,
            self.flags_doc,
            self.flags_global,
            perf_now,
            self.sid,
            "",
            self.cores,
            float(int(time.time() * 1000)) - perf_now,
        ]

    def requirements_token(self) -> str:
        """先验 token，用于初次发 /sentinel/req 时携带。

        data[3]=1, data[9]=int(uniform(5,50))（与 Python ref 一致）。
        """
        data = self._config_array()
        data[3] = 1
        data[9] = float(int(5 + random.random() * 45))
        return "gAAAAAC" + _b64_compact(data)

    def solve_pow(self, seed: str, difficulty: str) -> str:
        """暴力求解 PoW。失败回到占位字符串（与 Python ref 一致）。"""
        if not difficulty:
            difficulty = "0"
        start = time.monotonic()
        data = self._config_array()
        seed_b = seed.encode("ascii")
        dl = len(difficulty)
        for i in range(_SENTINEL_MAX_ATTEMPTS):
            data[3] = i
            data[9] = float(int((time.monotonic() - start) * 1000))
            payload = _b64_compact(data)
            h = _fnv1a_32(seed_b + payload.encode("ascii"))
            hex_str = f"{h:08x}"
            cmp_len = min(dl, len(hex_str))
            if hex_str[:cmp_len] <= difficulty[:cmp_len]:
                return "gAAAAAB" + payload + "~S"
        return "gAAAAAB" + _SENTINEL_ERR_PREFIX + _b64_compact(None)

    async def _load_sdk_assets(self, client: httpx.AsyncClient) -> tuple[str, str]:
        now = time.time()
        cached_url = str(_SENTINEL_ASSET_CACHE.get("url") or "")
        cached_source = str(_SENTINEL_ASSET_CACHE.get("source") or "")
        fetched_at = float(_SENTINEL_ASSET_CACHE.get("fetched_at") or 0.0)
        if cached_url and cached_source and now - fetched_at < _SENTINEL_ASSET_TTL_S:
            return cached_url, cached_source

        frame = await client.get(
            _SENTINEL_FRAME_URL,
            headers={
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "user-agent": self.user_agent,
                "sec-fetch-dest": "document",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "same-origin",
            },
        )
        if frame.status_code != 200:
            raise RuntimeError(f"Sentinel frame HTTP {frame.status_code}")
        match = re.search(
            r'''src=["']([^"']*/sentinel/[^"']+/sdk\.js[^"']*)["']''',
            frame.text or "",
        )
        if not match:
            raise RuntimeError("Sentinel frame 未发现 sdk.js")
        sdk_url = _validated_sdk_url(match.group(1), base_url=str(frame.url))
        sdk_resp = await client.get(
            sdk_url,
            headers={
                "accept": "*/*",
                "referer": _SENTINEL_FRAME_URL,
                "origin": "https://sentinel.openai.com",
                "user-agent": self.user_agent,
            },
        )
        source = sdk_resp.text or ""
        if sdk_resp.status_code != 200 or "SentinelSDK" not in source:
            raise RuntimeError(f"Sentinel sdk HTTP {sdk_resp.status_code}")
        if len(source.encode("utf-8", errors="replace")) > 2 * 1024 * 1024:
            raise RuntimeError("Sentinel sdk 文件过大")
        _SENTINEL_ASSET_CACHE.update(
            {"url": sdk_url, "source": source, "fetched_at": now}
        )
        return sdk_url, source

    async def _sdk_artifacts(
        self,
        client: httpx.AsyncClient,
        flow: str,
        *,
        observer_timeout_ms: int = 5000,
    ) -> SentinelArtifacts:
        sdk_url, sdk_source = await self._load_sdk_assets(client)
        fingerprint = self._runner_fingerprint()
        browser_profile = dict(fingerprint.pop("browser_profile", {}) or {})
        browser_profile.update({
            "user_agent": self.user_agent,
            "navigator_language": self.language,
            "navigator_languages": list(self.navigator_languages),
            "timezone_iana": self.timezone_iana,
            "timezone_name": self.timezone_name,
            "timezone_offset_minutes": self.timezone_offset_minutes,
            "screen_width": int(self.resolution.partition("x")[0] or 1920),
            "screen_height": int(self.resolution.partition("x")[2] or 1080),
            "hardware_concurrency": self.cores,
            "device_memory": self.device_memory,
            "device_pixel_ratio": self.device_pixel_ratio,
            "chrome_major": str(self.browser_major),
            "chrome_full_version": f"{self.browser_major}.0.0.0",
            "sec_ch_ua_platform": f'"{self.platform}"',
            "react_listening_key": self.react_listening_key,
            "react_container_key": self.react_container_key,
            "react_resources_key": self.react_resources_key,
        })
        cookie = (
            client.cookie_header_for_domain("sentinel.openai.com")
            if hasattr(client, "cookie_header_for_domain")
            else f"oai-did={self.device_id}"
        ) or f"oai-did={self.device_id}"
        prepare_token = await asyncio.to_thread(
            generate_shared_sentinel_prepare_token,
            sdk_source=sdk_source,
            sdk_url=sdk_url,
            flow=flow,
            device_id=self.device_id,
            user_agent=self.user_agent,
            browser_profile=browser_profile,
            sentinel_sid=self.sid,
            react_listening_key=self.react_listening_key,
            react_container_key=self.react_container_key,
            react_resources_key=self.react_resources_key,
            cookie=cookie,
        )
        if not prepare_token:
            raise RuntimeError("Sentinel SDK 未生成 prepare_token")

        body = {"p": prepare_token, "id": self.device_id, "flow": flow}
        resp = await client.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            content=json.dumps(body, separators=(",", ":")),
            headers={
                "content-type": "text/plain;charset=UTF-8",
                "origin": "https://sentinel.openai.com",
                "referer": _SENTINEL_FRAME_URL,
                "user-agent": self.user_agent,
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            },
        )
        if resp.status_code != 200:
            raise RuntimeError(f"sentinel/req HTTP {resp.status_code}: {resp.text[:240]}")
        challenge = resp.json()
        challenge_token = str(challenge.get("token") or "").strip()
        if not challenge_token:
            raise RuntimeError("sentinel/req 响应缺 token")

        try:
            shared = await asyncio.to_thread(
                generate_shared_sentinel_artifacts,
                challenge,
                prepare_token=prepare_token,
                sdk_source=sdk_source,
                sdk_url=sdk_url,
                flow=flow,
                device_id=self.device_id,
                observer_timeout_ms=max(0, int(observer_timeout_ms)),
                user_agent=self.user_agent,
                browser_profile=browser_profile,
                sentinel_sid=self.sid,
                react_listening_key=self.react_listening_key,
                react_container_key=self.react_container_key,
                react_resources_key=self.react_resources_key,
                cookie=cookie,
            )
        except SharedSentinelArtifactError as exc:
            raise SentinelArtifactError(str(exc)) from exc
        token = shared.token
        so_token = shared.so_token
        proof_token = shared.proof_token
        turnstile_token = shared.turnstile_token
        oai_sc_value = "0" + challenge_token
        for domain in (".openai.com", "openai.com", ".auth.openai.com", "auth.openai.com"):
            try:
                client.cookies.set("oai-sc", oai_sc_value, domain=domain, path="/")
            except Exception:  # noqa: BLE001
                pass
        artifacts = SentinelArtifacts(
            token=token,
            so_token=so_token,
            proof_token=proof_token,
            turnstile_token=turnstile_token,
            challenge_token=challenge_token,
            token_error=shared.token_error,
            proof_error=shared.proof_error,
            turnstile_error=shared.turnstile_error,
            collector_error=shared.collector_error,
            so_error=shared.so_error,
            proof_required=_required(challenge, "proofofwork"),
            turnstile_required=_required(challenge, "turnstile"),
            so_required=_required(challenge, "so"),
            oai_sc_value=oai_sc_value,
            sdk_url=sdk_url,
            sdk_version=_sdk_version(sdk_url),
        )
        _validate_sentinel_artifacts(
            artifacts,
            challenge=challenge,
            flow=flow,
            device_id=self.device_id,
        )
        return artifacts

    async def sentinel_headers(
        self,
        client: httpx.AsyncClient,
        flow: str,
        *,
        observer_timeout_ms: int = 5000,
    ) -> dict[str, str]:
        artifacts = await self._sdk_artifacts(
            client,
            flow,
            observer_timeout_ms=observer_timeout_ms,
        )
        self.last_so_token = artifacts.so_token
        self.last_oai_sc_value = artifacts.oai_sc_value
        logger.info(
            "Sentinel SDK OK flow=%s mode=sdk_vm sdk=%s p=%s t=%s c=%s so=%s",
            flow,
            artifacts.sdk_version or "?",
            len(artifacts.proof_token),
            len(artifacts.turnstile_token),
            len(artifacts.challenge_token),
            len(artifacts.so_token),
        )
        headers = {"openai-sentinel-token": artifacts.token}
        if artifacts.so_token:
            headers["openai-sentinel-so-token"] = artifacts.so_token
        return headers

    async def sentinel_token(
        self, client: httpx.AsyncClient, flow: str
    ) -> str:
        """完整 token：调 /sentinel/req → 解 PoW → 拼 JSON。

        失败重试一次；都失败时退化为 RequirementsToken 兜底（与 Python ref 一致：
        弱端点如 email-otp/validate 仍能继续，强端点如 create_account 可能拒）。
        """
        try:
            return await self._call_sentinel_req(client, flow)
        except SentinelRequiredTokenError:
            raise
        except Exception as e:  # noqa: BLE001
            logger.warning("sentinel/req 失败一次 (%s), 重试", e)
            try:
                return await self._call_sentinel_req(client, flow)
            except SentinelRequiredTokenError:
                raise
            except Exception as e2:  # noqa: BLE001
                logger.warning(
                    "sentinel/req 二次失败 (%s)，退化使用 fallback token", e2
                )
                return self._fallback_token(flow)

    async def _call_sentinel_req(
        self, client: httpx.AsyncClient, flow: str
    ) -> str:
        body = {
            "p": self.requirements_token(),
            "id": self.device_id,
            "flow": flow,
        }
        headers = {
            "Content-Type": "text/plain;charset=UTF-8",
            "Origin": "https://sentinel.openai.com",
            "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
            "User-Agent": self.user_agent,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": f'"{self.platform}"',
            "accept-language": self.language,
        }
        # text/plain 但 body 实际是 JSON —— OpenAI 接受
        resp = await client.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            content=json.dumps(body, separators=(",", ":")),
            headers=headers,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"sentinel/req HTTP {resp.status_code}: {resp.text[:240]}"
            )
        data = resp.json()
        token = data.get("token") or ""
        if not token:
            raise RuntimeError(f"sentinel/req 响应缺 token: {resp.text[:240]}")
        required_sdk_parts = [
            name
            for name in ("turnstile", "so")
            if _required(data, name)
        ]
        if required_sdk_parts:
            raise SentinelRequiredTokenError(
                f"Sentinel flow={flow} 要求 {','.join(required_sdk_parts)}，"
                "必须使用 sentinel_headers/sdk_vm，禁止提交弱 token"
            )
        pow_cfg = data.get("proofofwork") or {}
        if pow_cfg.get("required") and pow_cfg.get("seed"):
            p = self.solve_pow(pow_cfg["seed"], pow_cfg.get("difficulty") or "")
        else:
            p = self.requirements_token()
        out = {
            "p": p,
            "t": "",
            "c": token,
            "id": self.device_id,
            "flow": flow,
        }
        return json.dumps(out, separators=(",", ":"))

    def _fallback_token(self, flow: str) -> str:
        """sentinel.openai.com 完全不通时的兜底 token。"""
        out = {
            "p": self.requirements_token(),
            "t": "",
            "c": "",
            "id": self.device_id,
            "flow": flow,
        }
        return json.dumps(out, separators=(",", ":"))
