"""OAuth v2 适配层使用的共享浏览器画像。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from config import browser as browser_config


@dataclass(slots=True)
class Profile:
    user_agent: str
    sec_ch_ua: str
    sec_ch_ua_platform: str
    locale: str
    impersonate: str = browser_config.IMPERSONATE
    browser_major: int = int(browser_config.CHROME_MAJOR)
    navigator_languages: tuple[str, ...] = ("ja-JP", "ja", "en-US", "en")
    timezone_iana: str = "Asia/Tokyo"
    timezone_name: str = "Japan Standard Time"
    timezone_offset_minutes: int = 540
    screen_width: int = 1680
    screen_height: int = 1050
    hardware_concurrency: int = 6
    device_memory: int = 8
    device_pixel_ratio: float = 2
    region: str = "JP"
    city: str = ""
    browser_environment: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def language(self) -> str:
        return self.navigator_languages[0] if self.navigator_languages else "ja-JP"

    @property
    def oai_language(self) -> str:
        return self.language


def proxy_region(proxy: str | None) -> str:
    """兼容旧调用，地区解析由共享画像模块统一实现。"""
    return browser_config.extract_proxy_region(proxy)


def random_profile(
    *,
    proxy: str | None = None,
    region: str | None = None,
    geo: dict[str, object] | None = None,
) -> Profile:
    """从 ``config.browser`` 创建 OAuth/Next 共用的 macOS Chrome 画像。"""
    selected_region = str(region or proxy_region(proxy) or "").strip().upper()
    env = browser_config.build_browser_environment(
        dict(geo or {}),
        region=selected_region,
    )
    locale_profile = str(env.get("locale_profile") or browser_config.BROWSER_LOCALE_PROFILE)
    country = next(
        (
            code
            for code, key in browser_config.COUNTRY_LOCALE_PROFILE_MAP.items()
            if key == locale_profile
        ),
        selected_region or "JP",
    )
    return Profile(
        user_agent=str(env["user_agent"]),
        sec_ch_ua=str(env["sec_ch_ua"]),
        sec_ch_ua_platform=str(env["sec_ch_ua_platform"]),
        locale=str(env["accept_language"]),
        impersonate=browser_config.IMPERSONATE,
        browser_major=int(env["chrome_major"]),
        navigator_languages=tuple(env["navigator_languages"]),
        timezone_iana=str(env["timezone_iana"]),
        timezone_name=str(env["timezone_name"]),
        timezone_offset_minutes=int(env["timezone_offset_minutes"]),
        screen_width=int(env["screen_width"]),
        screen_height=int(env["screen_height"]),
        hardware_concurrency=int(env["hardware_concurrency"]),
        device_memory=int(env["device_memory"]),
        device_pixel_ratio=float(env["device_pixel_ratio"]),
        region=country,
        city=str((geo or {}).get("city") or "").strip(),
        browser_environment=env,
    )


__all__ = ["Profile", "proxy_region", "random_profile"]
