# -*- coding: utf-8 -*-
"""本机 Chromium 自动化注册配置。"""
from config.env_loader import apply_env_overrides


# 默认无头运行，避免批量任务持续弹出浏览器窗口。
LOCAL_BROWSER_HEADLESS: bool = True

# 兼容旧配置；当前实现始终使用 Go Rod stealth 页面并追加一致性修正。
LOCAL_BROWSER_STEALTH: bool = True

# 是否使用任务传入的代理；任务未显式传入时从 PROXY_POOL 抽取。
LOCAL_BROWSER_USE_PROXY: bool = True

# 兼容旧配置；当前实现始终探测代理出口并对齐语言、时区和坐标。
LOCAL_BROWSER_GEOIP: bool = True

# 注册前校验代理真实出口。国家不匹配或 GeoIP 无法确认时，会在提交邮箱前
# 结束当前 helper，并由 Python 监管层旋转 sticky session 后重试。
LOCAL_BROWSER_STRICT_EXIT_COUNTRY: bool = True
LOCAL_BROWSER_EXPECTED_COUNTRY: str = "JP"

# 旧 Patchright 配置，仅为兼容已有 .env 保留，Rod 实现不读取。
LOCAL_BROWSER_CHANNEL: str = ""

# 可选浏览器可执行文件绝对路径；留空时优先使用系统 Chromium，找不到再由 Rod 管理。
LOCAL_BROWSER_EXECUTABLE_PATH: str = ""

# Rod helper 可执行文件。留空时按当前系统从 tools/rod_register/bin 自动选择。
LOCAL_BROWSER_ROD_HELPER_PATH: str = ""

# 单个 Rod helper 进程总超时，包含页面等待和邮箱 OTP 等待。
LOCAL_BROWSER_PROCESS_TIMEOUT: int = 900

# 本机 Chrome 独立并发上限。注册线程池可以更大，但同时运行过多浏览器会抢占
# CPU/内存并放大页面超时；该限制只约束 local_browser 驱动。
LOCAL_BROWSER_MAX_CONCURRENT_RUNS: int = 3

# 同一注册流程允许 helper 重新请求验证码的次数。第二次起会排除本轮已经提交的旧码。
LOCAL_BROWSER_MAX_OTP_REQUESTS: int = 3

# Python 监管层检查手动停止的间隔；不依赖浏览器页面进入下一个检查点。
LOCAL_BROWSER_STOP_POLL_INTERVAL: float = 0.25

# helper 停止时先给进程组的优雅退出时间，超时后强制清理整个进程组。
LOCAL_BROWSER_TERMINATE_GRACE_SECONDS: float = 3.0

# 拿到 Web AT 后保留原页面/原代理/原 Cookie 的最长时间，让首页自然
# 完成 Sentinel/PoW 和最终 accounts/check。Go helper 会把上限硬限制为 5 秒。
LOCAL_BROWSER_POST_AUTH_SETTLE_SECONDS: float = 5.0

# 只复用 Chromium 的静态 HTTP 磁盘缓存；每次任务的 UserDataDir/Cookie 仍独立。
LOCAL_BROWSER_SHARED_DISK_CACHE: bool = True
LOCAL_BROWSER_DISK_CACHE_DIR: str = "data/local-browser-static-cache"
LOCAL_BROWSER_DISK_CACHE_SLOTS: int = 3
LOCAL_BROWSER_DISK_CACHE_SIZE_MB: int = 256

# 仅在邮箱 OTP 尚未提交/接受且错误明确可恢复时换新浏览器会话重试。
LOCAL_BROWSER_MAX_ATTEMPTS: int = 2
LOCAL_BROWSER_RETRY_DELAY: float = 2.0

# 旧 Patchright 配置，仅为兼容已有 .env 保留，Rod 实现不读取。
LOCAL_BROWSER_AUTO_INSTALL: bool = True

# 旧 Patchright 配置，仅为兼容已有 .env 保留，Rod 使用上游固定阶段超时。
LOCAL_BROWSER_TIMEOUT: int = 90

# 旧 Patchright 配置，仅为兼容已有 .env 保留。
LOCAL_BROWSER_CHALLENGE_TIMEOUT: int = 90

# 旧 Patchright 配置，仅为兼容已有 .env 保留；Rod helper 始终回收浏览器。
LOCAL_BROWSER_KEEP_OPEN: bool = False


apply_env_overrides(
    globals(),
    {
        "LOCAL_BROWSER_HEADLESS": "bool",
        "LOCAL_BROWSER_STEALTH": "bool",
        "LOCAL_BROWSER_USE_PROXY": "bool",
        "LOCAL_BROWSER_GEOIP": "bool",
        "LOCAL_BROWSER_STRICT_EXIT_COUNTRY": "bool",
        "LOCAL_BROWSER_EXPECTED_COUNTRY": "str",
        "LOCAL_BROWSER_CHANNEL": "str",
        "LOCAL_BROWSER_EXECUTABLE_PATH": "str",
        "LOCAL_BROWSER_ROD_HELPER_PATH": "str",
        "LOCAL_BROWSER_PROCESS_TIMEOUT": "int",
        "LOCAL_BROWSER_MAX_CONCURRENT_RUNS": "int",
        "LOCAL_BROWSER_MAX_OTP_REQUESTS": "int",
        "LOCAL_BROWSER_STOP_POLL_INTERVAL": "float",
        "LOCAL_BROWSER_TERMINATE_GRACE_SECONDS": "float",
        "LOCAL_BROWSER_POST_AUTH_SETTLE_SECONDS": "float",
        "LOCAL_BROWSER_SHARED_DISK_CACHE": "bool",
        "LOCAL_BROWSER_DISK_CACHE_DIR": "str",
        "LOCAL_BROWSER_DISK_CACHE_SLOTS": "int",
        "LOCAL_BROWSER_DISK_CACHE_SIZE_MB": "int",
        "LOCAL_BROWSER_MAX_ATTEMPTS": "int",
        "LOCAL_BROWSER_RETRY_DELAY": "float",
        "LOCAL_BROWSER_AUTO_INSTALL": "bool",
        "LOCAL_BROWSER_TIMEOUT": "int",
        "LOCAL_BROWSER_CHALLENGE_TIMEOUT": "int",
        "LOCAL_BROWSER_KEEP_OPEN": "bool",
    },
)
