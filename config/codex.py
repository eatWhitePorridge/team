# -*- coding: utf-8 -*-
"""
注册成功后自动跑 Codex OAuth 授权的配置项。
设置 ENABLE_CODEX = False 可完全跳过此步骤。

参数来源：CLIProxyAPI 源码 internal/auth/codex/openai_auth.go + pkce.go，
对照 https://github.com/router-for-me/CLIProxyAPI 逐行确认。
"""
from config.env_loader import env_str, apply_env_overrides


# 是否启用 Codex OAuth 授权（False = 跳过，不影响注册结果）
ENABLE_CODEX: bool = False

# Codex OAuth 客户端 ID（固定值，来自 CLIProxyAPI openai_auth.go:27 ClientID）
CODEX_CLIENT_ID: str = "app_EMoamEEZ73f0CkXaXp7hrann"

# 授权端点（openai_auth.go:25 AuthURL）
CODEX_AUTH_URL: str = "https://auth.openai.com/oauth/authorize"

# 换 token 端点（openai_auth.go:26 TokenURL）
CODEX_TOKEN_URL: str = "https://auth.openai.com/oauth/token"

# 回调地址（openai_auth.go:28 RedirectURI）
# 注意：本地并不真的起这个 server，只用来拦截重定向并从 Location 提取 code。
CODEX_REDIRECT_URI: str = "http://localhost:1455/auth/callback"

# OAuth scopes（openai_auth.go:75 GenerateAuthURL 里的 scope）
CODEX_SCOPE: str = "openid email profile offline_access"

# 输出目录名（仅名字，运行时拼到项目根；与 OUTLOOK_ACCOUNTS_FILE 同级风格）
CODEX_OUTPUT_DIRNAME: str = "codex_accounts"

# 请求超时（秒）
CODEX_REQUEST_TIMEOUT: int = 30

# 一次 Codex OAuth 失败后，最多重建多少次完整授权会话。这里的重试会重新生成
# device/session/PKCE，并在自动代理池模式下优先换出口；它与单个 HTTP 请求的
# 短重试是两层机制。
CODEX_FLOW_MAX_ATTEMPTS: int = 3

# 完整授权会话重建前的基础退避秒数；第 N 次失败后按 N 倍等待。
CODEX_FLOW_RETRY_DELAY: float = 2.0

# 提交邮箱之前可以低成本筛选更多代理；这些失败不会发送 OTP 或购买号码。
CODEX_PROXY_PREFLIGHT_MAX_ATTEMPTS: int = 10

# 换下一条预检代理前的固定短等待。坏 SOCKS 会话会立即切换，不在原会话反复等待。
CODEX_PROXY_PREFLIGHT_RETRY_DELAY: float = 0.5

# 自动代理池或带 session/sid 的动态代理在整轮失败后是否轮换。
# 显式直连（proxy=""）始终保持直连，不会被切到代理池。
CODEX_ROTATE_PROXY_ON_RETRY: bool = True

# Codex 协议 HTTP/TLS 浏览器画像。Firefox 不发送 Chromium Client Hints，且
# 与 curl_cffi firefox147 的 TLS/HTTP2 指纹保持一致。
CODEX_BROWSER_FAMILY: str = "firefox"


# ============================================================
# Codex 授权方式（2026-06-15 改造）
#
# 旧方案"复用注册的已登录 session"会撞 /choose-an-account 卡死；
# 新方案用全新干净 session 从头登录，走 OpenAI 标准风控路径
# （邮箱 OTP → 手机短信验证 → 选 workspace → 拿 code），
# 手机验证靠接码平台 GrizzlySMS 自动收码。
# ============================================================

# 注册成功后是否自动跑 Codex 授权（True=自动，False=跳过）
ENABLE_CODEX_AUTO: bool = False

# OAuth 补 Codex 专用线程池默认并发。与注册线程池完全独立；批量接口传入
# workers 时仅调整本次 Codex 批次，未传入时使用此值。
CODEX_RETRY_WORKERS: int = 50

# Codex OAuth 固定走协议（curl_cffi）。roxy/cloak 注册时会在自己已经打开的
# 浏览器里就地跑授权，不经过这里，所以不需要再给授权单独选驱动。




# ============================================================
# CPA 管理接口（Codex 授权地址由 CPA 生成，本地只负责跑登录并提交回调）
# ============================================================

# 授权地址来源：
#   "cpa"   = 通过 CPA 管理接口 /v0/management/codex-auth-url 生成（推荐）
#   "sub2"  = 通过 sub2 管理接口生成，并把 callback 上传到 sub2
#   "local" = 使用本模块保留的本地 PKCE 生成逻辑（兼容旧方案）
CODEX_AUTH_URL_SOURCE: str = "cpa"

# CPA 管理页面或服务地址，例如 http://localhost:8317/admin/oauth
# 实际请求会取 origin，调用：
#   GET  /v0/management/codex-auth-url
#   POST /v0/management/oauth-callback
CPA_MANAGEMENT_URL: str = "http://127.0.0.1:8317/management.html"#/oauth"

# CPA 管理密钥，同时作为 Authorization: Bearer 和 X-Management-Key
CPA_MANAGEMENT_KEY: str = env_str("CPA_MANAGEMENT_KEY", "")

# CPA 管理接口请求超时（秒）
CPA_REQUEST_TIMEOUT: int = 30

# 提交 OAuth callback 给 CPA 的重试次数/基础间隔。
# 遇到 409 Timeout waiting for OAuth callback、网络超时或 5xx 时，会按同一个 callback URL 重试。
CPA_CALLBACK_SUBMIT_RETRIES: int = 5
CPA_CALLBACK_SUBMIT_RETRY_DELAY: int = 6

# CPA 未返回完整 auth json 时，是否仍在本地 codex_accounts/ 记录一份回调提交凭据
CPA_SAVE_CALLBACK_RECEIPT: bool = True

# ============================================================
# NexusVault（Codex 授权凭证手动入库）
# ============================================================

# 固定使用 NexusVault 官方导入接口。客户端还会校验 HTTPS、域名和路径，
# 防止配置被误改后把 OAuth 凭证发送到其他地址。
NEXUSVAULT_API_URL: str = "https://nvtokens.com/api/inventory/cards/import"

# API Key 只从 .env 读取，不进入前端 Codex 页面或日志。
NEXUSVAULT_API_KEY: str = env_str("NEXUSVAULT_API_KEY", "")

# 单份凭证上传超时（秒）。批量上传走独立的 5 路并发，支持部分成功。
NEXUSVAULT_REQUEST_TIMEOUT: int = 30

# ============================================================
# 接码平台（手机短信验证用）
# SMS_PROVIDER:
#   "smsbower" = SMSBower，最低价选号并支持批次预算（默认）
#   "luban"    = Luban，复用 PayPal 的 Luban API 凭证、Provider 和代理配置
#   "herosms"  = HeroSMS，使用 SMS-Activate 兼容 API
#   "grizzly" = GrizzlySMS，接口说明见 https://api.grizzlysms.com
#   "l"       = 本地 L 取号服务，接口说明见 L_API.md
#   "h"       = 本地 H 取号服务，接口说明见 H_API.md
# ============================================================

SMS_PROVIDER: str = "smsbower"

# 接码 API 基址（GET handler）
SMS_API_BASE: str = "https://api.grizzlysms.com/stubs/handler_api.php"

# 接码 API 密钥（在 GrizzlySMS 后台 → 设置 获取）
# 留空时 Codex 授权的手机验证步会失败；如不需要 Codex 自动授权，把 ENABLE_CODEX_AUTO=False。
SMS_API_KEY: str = env_str("SMS_API_KEY", "")

# 服务代码：OpenAI = "dr"
SMS_SERVICE: str = "dr"

# 国家代码：葡萄牙 = "117" / 美国 = "187"
SMS_COUNTRY: str = "10"

# 单个号愿意支付的最高价格（留空=不限）。透传给 getNumber 的 maxPrice。
SMS_MAX_PRICE: str = ""

# 一个号收不到短信/被拒时，换号重试的最大次数
SMS_MAX_RETRIES: int = 10

# 单个号等待短信的最长秒数（超时则取消该号换下一个）
SMS_CODE_WAIT: int = 120

# 轮询接码平台查短信的间隔（秒）
SMS_POLL_INTERVAL: int = 5

# 接码平台 HTTP 请求超时（秒）
SMS_REQUEST_TIMEOUT: int = 30

# SMSBower 专用配置。任务创建时只允许覆盖国家、价格、预算和重试次数，密钥/地址始终取全局配置。
SMSBOWER_API_KEY: str = env_str("SMSBOWER_API_KEY", "")
SMSBOWER_HANDLER_URL: str = "https://smsbower.page/stubs/handler_api.php"
SMSBOWER_TASK_BUDGET: str = ""

# Codex 使用 Luban 时只需要覆盖 OpenAI 特有的国家、服务名、Provider 和 Service ID；
# API 地址、Key、请求超时和代理均复用 PAYPAL_LUBAN_* 配置。
# 国家留空时跟随 PAYPAL_LUBAN_COUNTRY，避免同一平台维护两套线路配置。
SMS_LUBAN_COUNTRY: str = ""
SMS_LUBAN_SERVICE: str = "OpenAI"
SMS_LUBAN_SERVICE_ALIASES: str = (
    "OpenAI,OpenAI / ChatGPT,OpenAI / ChatGpt,ChatGPT | OpenAI,OpenAI/ChatGPT"
)
SMS_LUBAN_PROVIDERS: str = ""
SMS_LUBAN_SERVICE_IDS: str = ""


# HeroSMS 专用配置（SMS_PROVIDER="herosms" 时使用）。
# HEROSMS_COUNTRY 留空时回退到通用 SMS_COUNTRY。
HEROSMS_API_KEY: str = env_str("HEROSMS_API_KEY", "")
HEROSMS_HANDLER_URL: str = "https://hero-sms.com/stubs/handler_api.php"
HEROSMS_SERVICE: str = "dr"
HEROSMS_COUNTRY: str = ""
HEROSMS_OPERATOR: str = ""
HEROSMS_FIXED_PRICE: str = ""
HEROSMS_PHONE_EXCEPTION: str = ""
HEROSMS_PROXY: str = env_str("HEROSMS_PROXY", "")
HEROSMS_REQUEST_TIMEOUT: int = 30


# ============================================================
# H 取号服务（SMS_PROVIDER="h" 时使用）
# ============================================================

# H API 基址，例如本地后台：http://localhost:8788
H_API_BASE: str = "http://localhost:8788"

# H 后台授权码，对应 H_API.md 里的 Authorization: Bearer <ADMIN_AUTH_CODE>
H_ADMIN_AUTH_CODE: str = env_str("H_ADMIN_AUTH_CODE", "")

# H 返回的号码如果不含国家码，可在这里补前缀；留空则直接使用 H 返回的 item.phone。
H_PHONE_PREFIX: str = ""

# H 取号方式：
#   "reusable" = 优先复用号码，调用 /api/admin/h/take-reusable-phone（默认）
#   "new"      = 每次取新号，调用 /api/admin/h/take-phone
H_PHONE_ACQUIRE_MODE: str = "reusable"


# ============================================================
# L 取号服务（SMS_PROVIDER="l" 时使用）
# ============================================================

# L API 基址，例如本地后台：http://localhost:8788
L_API_BASE: str = "http://localhost:8788"

# L 后台授权码，对应 L_API.md 里的 Authorization: Bearer <ADMIN_AUTH_CODE>
L_ADMIN_AUTH_CODE: str = env_str("L_ADMIN_AUTH_CODE", "")

# L 返回的号码如果不含国家码，可在这里补前缀；例如美国本地 10 位号填 "1"。
# 留空则直接使用 L 返回的 item.phone。
L_PHONE_PREFIX: str = ""

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'ENABLE_CODEX_AUTO': 'bool', 'CODEX_RETRY_WORKERS': 'int', 'CODEX_REQUEST_TIMEOUT': 'int', 'CODEX_FLOW_MAX_ATTEMPTS': 'int', 'CODEX_FLOW_RETRY_DELAY': 'float', 'CODEX_PROXY_PREFLIGHT_MAX_ATTEMPTS': 'int', 'CODEX_PROXY_PREFLIGHT_RETRY_DELAY': 'float', 'CODEX_ROTATE_PROXY_ON_RETRY': 'bool', 'CODEX_BROWSER_FAMILY': 'str', 'CODEX_AUTH_URL_SOURCE': 'str', 'CPA_MANAGEMENT_URL': 'str', 'CPA_MANAGEMENT_KEY': 'str', 'CPA_REQUEST_TIMEOUT': 'int', 'CPA_CALLBACK_SUBMIT_RETRIES': 'int', 'CPA_CALLBACK_SUBMIT_RETRY_DELAY': 'int', 'CPA_SAVE_CALLBACK_RECEIPT': 'bool', 'NEXUSVAULT_API_URL': 'str', 'NEXUSVAULT_API_KEY': 'str', 'NEXUSVAULT_REQUEST_TIMEOUT': 'int', 'SMS_PROVIDER': 'str', 'SMS_COUNTRY': 'str', 'SMS_SERVICE': 'str', 'SMS_MAX_PRICE': 'str', 'SMS_MAX_RETRIES': 'int', 'SMS_CODE_WAIT': 'int', 'SMS_POLL_INTERVAL': 'int', 'SMS_API_KEY': 'str', 'SMSBOWER_API_KEY': 'str', 'SMSBOWER_HANDLER_URL': 'str', 'SMSBOWER_TASK_BUDGET': 'str', 'SMS_LUBAN_COUNTRY': 'str', 'SMS_LUBAN_SERVICE': 'str', 'SMS_LUBAN_SERVICE_ALIASES': 'str', 'SMS_LUBAN_PROVIDERS': 'str', 'SMS_LUBAN_SERVICE_IDS': 'str', 'HEROSMS_API_KEY': 'str', 'HEROSMS_HANDLER_URL': 'str', 'HEROSMS_SERVICE': 'str', 'HEROSMS_COUNTRY': 'str', 'HEROSMS_OPERATOR': 'str', 'HEROSMS_FIXED_PRICE': 'str', 'HEROSMS_PHONE_EXCEPTION': 'str', 'HEROSMS_PROXY': 'str', 'HEROSMS_REQUEST_TIMEOUT': 'int', 'H_API_BASE': 'str', 'H_ADMIN_AUTH_CODE': 'str', 'H_PHONE_PREFIX': 'str', 'H_PHONE_ACQUIRE_MODE': 'str', 'L_API_BASE': 'str', 'L_ADMIN_AUTH_CODE': 'str', 'L_PHONE_PREFIX': 'str'})
