# -*- coding: utf-8 -*-
"""
RoxyBrowser 指纹浏览器自动化注册配置。

官方文档：
- API 默认 host: http://127.0.0.1:50000
- 所有接口请求头必须带 token
- 可配合 Selenium / Puppeteer / Playwright 自动化
"""
from config.env_loader import env_str, apply_env_overrides


# 注册驱动：
#   "protocol"     = 原有 curl_cffi 纯协议注册
#   "local_browser" = 本机 Go Rod Chromium，默认无头
#   "roxy"         = 调用 RoxyBrowser 指纹浏览器 + Selenium 自动化注册
#   "cloak"        = 调用 CloakBrowser + Playwright/Selenium 适配层注册
#   "browser_use"  = Browser Use Cloud stealth Chromium + Playwright
#   "skyvern"      = Skyvern Browser Sessions + Playwright
REGISTRATION_DRIVER: str = "browser_use"

# RoxyBrowser 本地 API
ROXY_API_BASE: str = "http://127.0.0.1:50000"
ROXY_API_TOKEN: str = env_str("ROXY_API_TOKEN", "")

# Roxy 环境/Profile ID；留空时使用 ROXY_PROFILE_CREATE_* 先创建临时环境（如果接口支持）
ROXY_PROFILE_ID: str = ""

# Roxy 工作区 ID。Roxy 创建 Profile 时接口要求 workspaceId，必须填写。
# 可在 Roxy 工作区/团队页面或 API 返回中查看。
ROXY_WORKSPACE_ID: str = "149778"

# Roxy 项目 ID。/browser/workspace 返回 project_details.projectId；创建 Profile 时一并提交。
ROXY_PROJECT_ID: str = "160904"

# 获取团队/工作区列表接口路径。不同版本若不同，可在 WebUI 修改；客户端也会自动尝试多个常见路径。
ROXY_WORKSPACE_LIST_PATH: str = "/browser/workspace"
ROXY_WORKSPACE_LIST_METHOD: str = "GET"

# 接口路径模板。不同版本如有差异，只改这里即可。
# {profile_id} 会替换为 ROXY_PROFILE_ID。
ROXY_OPEN_PATH: str = "/browser/open"
ROXY_CLOSE_PATH: str = "/browser/close"
ROXY_CREATE_PATH: str = "/browser/create"

# 接口方法：常见 open/close 为 GET；若你的版本要求 POST，可在 WebUI/配置里改。
ROXY_OPEN_METHOD: str = "POST"
ROXY_CLOSE_METHOD: str = "POST"
ROXY_CREATE_METHOD: str = "POST"

# 打开浏览器时是否无头启动：
#   False = 显示 Roxy 浏览器窗口（便于观察/调试）
#   True  = 无头启动，不显示窗口（如果当前 Roxy 版本支持 headless）
ROXY_OPEN_HEADLESS: bool = False

# 有头模式下把保持正常渲染的窗口移到工作区外，不最小化。最小化会让部分
# Roxy/Chromium 组合停止接受键盘输入，不能用于自动注册。
ROXY_WINDOW_OFFSCREEN: bool = False
ROXY_WINDOW_OFFSCREEN_X: int = 30000

# 打开浏览器时附加参数；会合并到 /browser/open 请求体，优先级高于默认值。
ROXY_OPEN_EXTRA_PARAMS: dict = {}

# 保守低流量模式：关闭 Chromium 后台同步/更新等非注册流量，并允许 Selenium
# 连接后通过 CDP 启用缓存、拦截明确不影响认证的静态资源与遥测请求。
ROXY_LOW_TRAFFIC_MODE: bool = True

# 一号一 Profile 仍保持 Cookie/Storage 隔离，只让各并发槽复用 Chromium HTTP
# Disk Cache。每个槽同一时间只分配给一个浏览器进程，避免并发写缓存损坏。
ROXY_SHARED_DISK_CACHE: bool = True
ROXY_DISK_CACHE_DIR: str = "data/roxy-static-cache"
ROXY_DISK_CACHE_SLOTS: int = 10
ROXY_DISK_CACHE_SIZE_MB: int = 300

# Selenium 行为
ROXY_SELENIUM_TIMEOUT: int = 90
# 页面导航只等到 DOM 可交互；若仍有图片/遥测等尾部资源，超时后会停止它们并继续。
ROXY_PAGE_LOAD_TIMEOUT: int = 35
# 可选调试动作：Web AT 稳定后再打开一次 ChatGPT 应用首页。基础注册完成时
# session Cookie 已经可复用，默认不做二次导航，避免额外流量和无效驻留。
ROXY_POST_REGISTER_LOAD_APP: bool = False
ROXY_POST_REGISTER_DWELL_SECONDS: float = 5.0
ROXY_KEEP_BROWSER_OPEN: bool = False

# Roxy API transient 错误重试。create 接口默认不重试，避免超时后重复创建孤儿环境；open/close/delete 会重试。
ROXY_API_RETRIES: int = 3
ROXY_API_RETRY_DELAY: int = 2
# Roxy API 是本机服务，不应复用 Selenium 的 90 秒等待。连接/读取分别最多
# 3 秒/15 秒；停止任务时，最迟在当前读取超时后进入清理。
ROXY_API_TIMEOUT: int = 15

# 完整注册的任务级重试。仅结构化判定为网络/Profile 临时故障时生效；
# 每轮都会关闭并删除旧 Profile，再用同一任务和邮箱创建新 Profile。
ROXY_REGISTRATION_MAX_ATTEMPTS: int = 3
ROXY_REGISTRATION_RETRY_DELAY: float = 2.0

# 环境生命周期：
#   True  = 一号一环境：每个账号强制创建新 Profile，用完关闭并删除，不允许复用 ROXY_PROFILE_ID
#   False = 可复用 ROXY_PROFILE_ID 或只关闭不删除
ROXY_ONE_PROFILE_PER_ACCOUNT: bool = True

# 一号一环境结束后是否删除 Profile。建议保持 True。
ROXY_DELETE_PROFILE_AFTER_RUN: bool = True

# 删除环境接口路径/方法；如你的 Roxy 版本不同，只改这里。
ROXY_DELETE_PATH: str = "/browser/delete"
ROXY_DELETE_METHOD: str = "POST"

# 创建 Roxy 环境时随机系统指纹；开启后每次 /browser/create 从配置列表中
# 选择一个系统，避免所有一次性 Profile 固定为同一系统。
ROXY_RANDOM_OS_ON_CREATE: bool = True
ROXY_RANDOM_OS_CHOICES: str = "Windows,macOS"

# 创建 Roxy 环境时随机名称；开启后覆盖 ROXY_PROFILE_CREATE_PAYLOAD 里的固定 name。
ROXY_RANDOM_PROFILE_NAME_ON_CREATE: bool = True
ROXY_PROFILE_NAME_PREFIX: str = "rb"

# 创建 Roxy 环境时默认系统指纹。仅在 ROXY_RANDOM_OS_ON_CREATE=False 时使用。
# Roxy 官方 os 枚举：Windows / macOS / Linux / IOS / Android。
ROXY_DEFAULT_OS: str = "macOS"
# 留空则使用 Roxy 对应系统的默认/最大版本；如需固定可填 15.3.2、14.7 等。
ROXY_DEFAULT_OS_VERSION: str = ""

# 创建 Roxy 环境时是否使用 config/proxy.py 的 PROXY_POOL：
#   False = 不主动给 Roxy 环境设置代理
#   True  = 每次创建环境时从 PROXY_POOL 随机取一个代理写入 proxyInfo
ROXY_CREATE_USE_PROXY_POOL: bool = False

# 创建 Roxy 环境前先使用同一条代理请求 ChatGPT。正常响应、跳转和
# 403 挑战页均算链路已打通；407、429、5xx、超时或 TLS 异常会换代理/session。
ROXY_PROXY_PREFLIGHT_ENABLED: bool = True
ROXY_PROXY_PREFLIGHT_URL: str = "https://chatgpt.com/auth/login"
ROXY_PROXY_PREFLIGHT_TIMEOUT: int = 10
ROXY_PROXY_PREFLIGHT_ATTEMPTS: int = 5

# Roxy 与套餐检测共用国家覆盖。填写两位国家码后，仅改写各自请求副本中的
# region/country/zone 国家选择器，不修改共享 PROXY_POOL，支付等其他流程不受影响。
# sticky session、密码、代理主机和端口均保持不变；留空则不改写。
ROXY_PROXY_COUNTRY_OVERRIDE: str = ""

# Roxy 的 ChatGPT 预检只能证明网络可达，不能证明动态代理落在目标国家。
# 严格门禁会在创建 Profile 前用同一条代理查询 GeoIP；未知或国家不匹配均换
# sticky session。配置了国家覆盖时，门禁自动以覆盖国家为准。
ROXY_STRICT_EXIT_COUNTRY: bool = True
ROXY_EXPECTED_COUNTRY: str = "JP"
ROXY_EXIT_GEOIP_URL: str = (
    "http://ip-api.com/json/"
    "?fields=status,message,country,countryCode,regionName,city,timezone,query"
)
ROXY_EXIT_GEOIP_TIMEOUT: int = 8

# 动态代理 session 在任务结束后的短期内不复用；再次抽到时自动改写 session。
# 仅对用户名含 session-/sid- 的动态代理应用冷却，固定代理只做并发去重。
ROXY_PROXY_SESSION_REUSE_COOLDOWN_SECONDS: int = 1800

# registration_service 切换 workers 时，旧线程池会继续跑完已提交任务。这里对
# Roxy 整条注册流程再设一个全局上限，避免新旧批次叠加耗尽上游代理连接额度。
ROXY_MAX_CONCURRENT_RUNS: int = 200

# 补 Team 专用窗口并发。每个 worker 独占一个账号的 Roxy Profile；默认 10，
# 与注册并发分开控制，账号级 claim 仍会阻止同一账号重复执行。
ROXY_TEAM_INVITE_WORKERS: int = 10

# Roxy 代理检测通道；留空则不传 checkChannel。
ROXY_PROXY_CHECK_CHANNEL: str = "IPRust.io"

# 没有 ROXY_PROFILE_ID 时创建环境的最小 payload；随机开关开启时会覆盖这里的
# name/os，调用 create_profile(payload=...) 传入的任务级字段仍具有最高优先级。
ROXY_PROFILE_CREATE_PAYLOAD: dict = {
    "name": "gpt-free-register",
    "os": "macOS",
}


# Roxy Codex 授权等待 callback 的最长秒数
ROXY_CODEX_CALLBACK_TIMEOUT: int = 180

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'REGISTRATION_DRIVER': 'str', 'ROXY_API_BASE': 'str', 'ROXY_API_TOKEN': 'str', 'ROXY_PROFILE_ID': 'str', 'ROXY_WORKSPACE_ID': 'str', 'ROXY_PROJECT_ID': 'str', 'ROXY_WORKSPACE_LIST_PATH': 'str', 'ROXY_OPEN_PATH': 'str', 'ROXY_OPEN_HEADLESS': 'bool', 'ROXY_WINDOW_OFFSCREEN': 'bool', 'ROXY_WINDOW_OFFSCREEN_X': 'int', 'ROXY_LOW_TRAFFIC_MODE': 'bool', 'ROXY_SHARED_DISK_CACHE': 'bool', 'ROXY_DISK_CACHE_DIR': 'str', 'ROXY_DISK_CACHE_SLOTS': 'int', 'ROXY_DISK_CACHE_SIZE_MB': 'int', 'ROXY_PAGE_LOAD_TIMEOUT': 'int', 'ROXY_POST_REGISTER_LOAD_APP': 'bool', 'ROXY_POST_REGISTER_DWELL_SECONDS': 'float', 'ROXY_API_TIMEOUT': 'int', 'ROXY_CLOSE_PATH': 'str', 'ROXY_KEEP_BROWSER_OPEN': 'bool', 'ROXY_ONE_PROFILE_PER_ACCOUNT': 'bool', 'ROXY_DELETE_PROFILE_AFTER_RUN': 'bool', 'ROXY_RANDOM_OS_ON_CREATE': 'bool', 'ROXY_RANDOM_OS_CHOICES': 'str', 'ROXY_RANDOM_PROFILE_NAME_ON_CREATE': 'bool', 'ROXY_PROFILE_NAME_PREFIX': 'str', 'ROXY_CREATE_USE_PROXY_POOL': 'bool', 'ROXY_PROXY_PREFLIGHT_ENABLED': 'bool', 'ROXY_PROXY_PREFLIGHT_URL': 'str', 'ROXY_PROXY_PREFLIGHT_TIMEOUT': 'int', 'ROXY_PROXY_PREFLIGHT_ATTEMPTS': 'int', 'ROXY_PROXY_COUNTRY_OVERRIDE': 'str', 'ROXY_STRICT_EXIT_COUNTRY': 'bool', 'ROXY_EXPECTED_COUNTRY': 'str', 'ROXY_EXIT_GEOIP_URL': 'str', 'ROXY_EXIT_GEOIP_TIMEOUT': 'int', 'ROXY_PROXY_SESSION_REUSE_COOLDOWN_SECONDS': 'int', 'ROXY_MAX_CONCURRENT_RUNS': 'int', 'ROXY_TEAM_INVITE_WORKERS': 'int', 'ROXY_REGISTRATION_MAX_ATTEMPTS': 'int', 'ROXY_REGISTRATION_RETRY_DELAY': 'float', 'ROXY_PROXY_CHECK_CHANNEL': 'str', 'ROXY_DELETE_PATH': 'str', 'ROXY_CODEX_CALLBACK_TIMEOUT': 'int'})
