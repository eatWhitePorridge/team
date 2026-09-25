# -*- coding: utf-8 -*-
"""
OpenAI / ChatGPT OAuth 协议固定参数

来自抓包，OpenAI 自己的 client_id 是固定值。
SENTINEL_SV 是 sdk.js 的版本号，会随 OpenAI 更新而变化，
更新时去 https://sentinel.openai.com/sentinel/<version>/sdk.js 找当前版本。
"""

from config.env_loader import apply_env_overrides

# OAuth 客户端 ID（固定）
OPENAI_CLIENT_ID = "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"

# OAuth scopes
OPENAI_SCOPE = (
    "openid email profile offline_access "
    "model.request model.read "
    "organization.read organization.write"
)

# OAuth audience
OPENAI_AUDIENCE = "https://api.openai.com/v1"

# OAuth 回调（chatgpt.com 端）
OPENAI_REDIRECT_URI = "https://chatgpt.com/api/auth/callback/openai"

# Auth Web Sentinel SDK 版本号（影响 sentinel iframe URL 与 referer header）
SENTINEL_SV = "20260219f9f6"

# ChatGPT 首页 chat-requirements 使用独立 SDK，不能与 Auth Web SDK 混用。
CHATGPT_SENTINEL_SV = "20260423af3c"

# ChatGPT 页面 build 标识（用于 Sentinel p[6] / documentElement data-build 模拟）。
# 来自 2026-08-12 完整注册 HAR；TLS 画像仍由 config/browser.py 独立约束。
OPENAI_BUILD_ID = "prod-82ad76a4a789d44a58fd4b511085d37cac93a185"

# ChatGPT 前端 CES / API 上报头，来自 2026-08-12 完整注册 HAR。
OAI_CLIENT_BUILD_NUMBER = "9259676"
OAI_CLIENT_VERSION = OPENAI_BUILD_ID

# auth.openai.com Login Web analytics build from the same 2026-08-12 capture.
# It is intentionally separate from the ChatGPT Web build above.
LOGIN_WEB_APP_VERSION = "edd9dabf4d5bf6121a65de9b9c4aa8fb3067bc21"

# Statsig / Analytics SDK 版本，纯协议补齐前端同形态链路时使用。
STATSIG_CLIENT_KEY = "client-nb0qtYlZuy2tCMN5s5ncnuIBCJncjRViT0IzFm7GqST"
STATSIG_SDK_VERSION = "3.32.6"
STATSIG_SDK_TYPE = "javascript-client"
AB_CLIENT_KEY = "client-tN5GMyzpIPKXd3KNv7ANIfiqjRSvNNTTWbZdbdabF58"
AB_SDK_VERSION = "3.32.4"

# 2026-08-12 HAR 中 email-otp/validate 同时携带主 Sentinel 与 SO token。
# 保留开关便于服务端旧分支回退，但当前默认必须对齐新链路。
SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE = True

# 是否补齐 HAR 中 ChatGPT Web 首屏 bootstrap 预热链路。
CHATGPT_ANON_BOOTSTRAP_ENABLED = True
CHATGPT_AUTH_BOOTSTRAP_ENABLED = True
# True 时预热失败会中断主流程；默认 False，仅记录日志并继续。
CHATGPT_BOOTSTRAP_STRICT = False

# 纯协议 Next 注册在提交邮箱前，以 `/backend-anon/me` 为准校验 ChatGPT 实际
# 识别国家。GeoIP 或代理用户名只用于构建画像，不能覆盖服务端观测结果。
CHATGPT_COUNTRY_GATE_ENABLED = True
CHATGPT_EXPECTED_COUNTRY = "JP"
CHATGPT_PRE_AUTH_MAX_ATTEMPTS = 3

# 完成匿名 bootstrap 后的被动驻留。期间不发网络请求，并支持任务停止。
CHATGPT_ANON_DWELL_SECONDS = 5.0

# OTP 成功进入 About You 后，在已预取 oauth_create_account challenge 的同一
# 页面状态中驻留。完整 HAR 更长，但产品要求固定为 5 秒。
CHATGPT_ABOUT_YOU_DWELL_SECONDS = 5.0

# 同一出口上的协议注册节流。并发为 0 表示不限制并发；启动间隔为 0 表示不做错峰。
PROTOCOL_EXIT_MAX_CONCURRENCY = 100
PROTOCOL_EXIT_MIN_START_INTERVAL = 8.0


apply_env_overrides(globals(), {
    "SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE": "bool",
    "CHATGPT_ANON_BOOTSTRAP_ENABLED": "bool",
    "CHATGPT_AUTH_BOOTSTRAP_ENABLED": "bool",
    "CHATGPT_BOOTSTRAP_STRICT": "bool",
    "CHATGPT_COUNTRY_GATE_ENABLED": "bool",
    "CHATGPT_EXPECTED_COUNTRY": "str",
    "CHATGPT_PRE_AUTH_MAX_ATTEMPTS": "int",
    "CHATGPT_ANON_DWELL_SECONDS": "float",
    "CHATGPT_ABOUT_YOU_DWELL_SECONDS": "float",
    "PROTOCOL_EXIT_MAX_CONCURRENCY": "int",
    "PROTOCOL_EXIT_MIN_START_INTERVAL": "float",
})
