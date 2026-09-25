# -*- coding: utf-8 -*-
"""
Outlook 邮箱账号池配置。

注册邮箱与 OTP 均只走 Outlook 账号池：
    1. 把邮箱素材写入项目根目录 `用于注册的邮箱.txt`
    2. 每行格式：email====password====clientId====refreshToken
    3. 运行注册时会自动导入新增邮箱
"""
from config.env_loader import env_str, apply_env_overrides


# True: REGISTER_EMAIL 留空时从 Outlook 账号池自动获取邮箱，OTP 自动收取
# False: 走人工输入邮箱 + 人工填 OTP 的流程
USE_EMAIL_SERVICE = False

# 可选值（也可以用英文逗号配置多个，按顺序兜底，例如 "outlook,generic_api,mailnest"）：
#   "outlook"           — 外购 Outlook 账号池 + mail.chatai.codes 远端取信
#   "cloudflare_domain" — Cloudflare 域名邮箱（转发到 QQ 邮箱），通过 IMAP 取信
#   "cloudflare" — Cloudflare Worker 临时邮箱（cloudflare_temp_email），API 创建并取码
#   "generic_api"       — 通用 API 取码邮箱池（邮箱----取码地址）
#   "icloud"            — iCloud 邮箱池（FlySMS / query.php / mczero 分享链接）
#   "mailcom"           — Mail.com 账号池（邮箱----密码，IMAP 取码，支持 Plus alias）
#   "gptmail"           — GPTMail 临时邮箱 API（运行时随机生成邮箱并自动收码）
#   "mailnest"          — MailNest/迈巢临时邮箱 API（运行时购买邮箱并自动收码）
#   "cloudmail"         — CloudMail/Cloud Mail API（自动从平台获取域名并随机生成邮箱）
#   "fastmail"          — Fastmail JMAP API（fma Token + Web Cookie，运行时创建普通 Alias 并自动收码）
#   "lof"               — LOF Mail API（固定域名随机地址并自动收码）
EMAIL_SOURCE = "outlook,generic_api,mailnest"


# ============================================================
# Outlook 模式（外购账号池 + 取信服务）
# ============================================================

OUTLOOK_ACCOUNTS_FILE = "用于注册的邮箱.txt"

# Outlook 取件模式：
#   "auto"   = 先用远端 mail.chatai.codes；远端 402/DEPLOYMENT_DISABLED 时自动切 Microsoft Graph 直连
#   "remote" = 只用远端 mail.chatai.codes
#   "direct" = 只用 Microsoft Graph 直连（使用 clientId + refreshToken 换 access_token）
OUTLOOK_FETCH_MODE = "auto"

# 取邮件 API 的根 URL（远端模式使用）
OUTLOOK_API_BASE = "https://mail.chatai.codes"


# ============================================================
# OTP 轮询参数
# ============================================================

OTP_POLL_INTERVAL = 3
OTP_MAX_WAIT = 90

# Outlook 双协议取件：抓到一封 OTP 后再多等多少秒看是否有更晚到达的邮件。
OTP_SETTLE_SECONDS = 5

# Plus alias 模式下，同一基础邮箱完成一次分配后至少间隔多久再分配。
# 设为 0 可关闭；默认 5 分钟，避免短时间内连续使用同一收件箱。
PLUS_ALIAS_BASE_COOLDOWN_SECONDS = 300


# ============================================================
# Mail.com 邮箱池（账号----密码，IMAP 取码）
# ============================================================

MAILCOM_ACCOUNTS_FILE = "用于注册的Mailcom邮箱.txt"
MAILCOM_IMAP_HOST = "imap.mail.com"
MAILCOM_IMAP_PORT = 993
MAILCOM_IMAP_TIMEOUT = 20
MAILCOM_WEB_TIMEOUT = 25
# Cache only a few authenticated base mailboxes. Every cached curl transport
# owns sockets and wakeup pipes, so an unbounded cache exhausts process FDs.
MAILCOM_WEB_CACHE_SIZE = 4
# Mail.com 的 Web 登录存在出口信誉/频率控制。Alias 创建和邮件 OTP 查询默认
# 共用全局注册代理池；如需独立出口可填写 MAILCOM_WEB_PROXY。关闭后回退 IMAP。
MAILCOM_WEB_USE_PROXY = True
MAILCOM_WEB_PROXY = ""
# 当前出口被 Mail.com 拒绝或网络失败时，最多重建多少个 sticky session。
MAILCOM_WEB_PROXY_ATTEMPTS = 3
# 代理会话全部被 Mail.com 拒绝时，允许用本机出口再尝试一次并复用该会话。
MAILCOM_WEB_DIRECT_FALLBACK = True
# Mail.com Web 前端使用的公开 OAuth 客户端密钥；上游轮换时可通过环境变量覆盖。
MAILCOM_OAUTH_PUBLIC_SECRET = "*******"
# Mail.com 单邮箱最多使用 7 个 Alias；后端还会强制封顶，不能由请求放大。
MAILCOM_ALIAS_MAX = 7


# ============================================================
# FlySMS iCloud 邮箱池
# ============================================================

ICLOUD_ACCOUNTS_FILE = "用于注册的iCloud邮箱.txt"
ICLOUD_API_BASE = "https://flysms.xyz/icloud"
ICLOUD_LATEST_MESSAGES_PATH = "/api/pickup/messages/latest"
ICLOUD_REQUEST_TIMEOUT = 20


# ============================================================
# Cloudflare 域名邮箱模式（转发到 QQ 邮箱，通过 IMAP 取信）
# ============================================================

# 你的 Cloudflare 域名，如 "mydomain.com"
# 注册时会自动生成 random@mydomain.com 作为注册邮箱
EMAIL_DOMAIN = ""

# QQ 邮箱 IMAP 服务器地址（固定为 imap.qq.com）
QQ_IMAP_SERVER = "imap.qq.com"

# QQ 邮箱 IMAP 端口（SSL）
QQ_IMAP_PORT = 993

# QQ 邮箱地址（接收 Cloudflare 转发的邮件），如 "123456@qq.com"
QQ_EMAIL = ""

# QQ 邮箱 IMAP 授权码（在 QQ 邮箱网页版 → 设置 → 账户 → POP3/IMAP/SMTP 服务 中生成）
# 注意：这是 16 位授权码，不是 QQ 密码
QQ_IMAP_PASSWORD = env_str("QQ_IMAP_PASSWORD", "")


# ============================================================
# GPTMail 临时邮箱 API（固定地址：https://mail.chatgpt.org.uk）
# ============================================================

# 选择 EMAIL_SOURCE="gptmail" 时必填；请在 WebUI「配置 → 邮箱 / OTP」填写。
GPTMAIL_API_KEY = env_str("GPTMAIL_API_KEY", "")


# ============================================================
# Cloudflare Worker 临时邮箱（cloudflare_temp_email 兼容）
# EMAIL_SOURCE 含 "cloudflare" 时启用；与 cloudflare_domain（QQ IMAP）不同。
# ============================================================

# Worker API 根地址，例如 https://mail.example.com
CLOUDFLARE_API_BASE = env_str("CLOUDFLARE_API_BASE", "")

# 匿名模式可留空；admin 模式填 ADMIN_PASSWORD
CLOUDFLARE_API_KEY = env_str("CLOUDFLARE_API_KEY", "")

# none / bearer / x-api-key / x-admin-auth / query-key
CLOUDFLARE_AUTH_MODE = "none"

# Worker 全局密码（PASSWORDS），注入请求头 x-custom-auth
CLOUDFLARE_CUSTOM_AUTH = env_str("CLOUDFLARE_CUSTOM_AUTH", "")

CLOUDFLARE_PATH_ACCOUNTS = "/api/new_address"
CLOUDFLARE_PATH_MESSAGES = "/api/mails"

# 默认收信域名，多个可用换行或逗号分隔；留空则由 Worker 决定
CLOUDFLARE_DEFAULT_DOMAINS = []

CLOUDFLARE_REQUEST_TIMEOUT = 20
CLOUDFLARE_NAME_LENGTH = 10


# ============================================================
# MailNest-迈巢 Outlook 临时邮箱：https://mailnest.top/
# ============================================================

# 选择 EMAIL_SOURCE="mailnest" 时必填；请在 WebUI「配置 → 邮箱 / OTP」填写。
MAIL_NEST_API_KEY = env_str("MAIL_NEST_API_KEY", "")

# MailNest 项目代码；OpenAI/ChatGPT 默认 chatgpt001。
MAIL_NEST_PROJECT_CODE = "chatgpt001"


# ============================================================
# LOF Mail 临时邮箱 API（https://mail.lof.pub/mail-api）
# ============================================================

# LOF 没有创建地址接口；客户端会在以下固定收信域名中本地生成随机地址。
LOF_MAIL_API_BASE = "https://mail.lof.pub/mail-api"
LOF_MAIL_API_TOKEN = env_str("LOF_MAIL_API_TOKEN", "")
LOF_MAIL_DOMAINS = ["lof.pub", "zeanl.com", "ssmmail.com", "sinas3.net"]
LOF_MAIL_REQUEST_TIMEOUT = 20
LOF_MAIL_RANDOM_LOCAL_LENGTH = 12

# ============================================================
# CloudMail API 文档：https://doc.skymail.ink/api/api-doc
# ============================================================

# Cloud Mail Worker/API 地址，例如：https://mail.example.com
CLOUDMAIL_API_BASE = ""

# CloudMail 管理员邮箱/密码；用于手动生成 Token，也用于域名被隐藏时自动登录获取域名。
CLOUDMAIL_ADMIN_EMAIL = env_str("CLOUDMAIL_ADMIN_EMAIL", "")
CLOUDMAIL_PASSWORD = env_str("CLOUDMAIL_PASSWORD", "")

# CloudMail 生成 Token 接口路径；默认按 Cloud Mail 公共 API 风格。
CLOUDMAIL_TOKEN_PATH = "/api/public/genToken"

# CloudMail/Cloud Mail API Authorization Token；可手动填写，也可由账号密码自动获取。
CLOUDMAIL_AUTH_TOKEN = env_str("CLOUDMAIL_AUTH_TOKEN", "")

# 邮箱域名列表，每行一个或用英文逗号分隔；可留空，运行时会从 CloudMail 平台自动获取。
CLOUDMAIL_DOMAINS = []

# 生成邮箱后是否调用 /api/public/addUser 创建邮箱用户。
CLOUDMAIL_AUTO_ADD_USER = True

# 随机邮箱 local-part 长度。
CLOUDMAIL_RANDOM_LOCAL_LENGTH = 12


# ============================================================
# Fastmail JMAP API（Token + 可选 Web Cookie，不导入邮箱）
# ============================================================

# 在 Fastmail「Privacy & Security → Manage API tokens」创建。Session 至少应提供
# urn:ietf:params:jmap:mail；普通 Alias 优先使用 UserAlias，旧版回退 customer
# capability，不会回退到 Masked Email。开启 Identity 同步时还会声明 submission。
# Token 只从 .env 读取，不会写入邮箱池或任务记录。
FASTMAIL_API_TOKEN = env_str("FASTMAIL_API_TOKEN", "")
# 新版 UserAlias/JMAP mail 路径只需要 API Token；旧版 customer Alias 和
# sudo 回收仍可能需要同一 Web 会话 Cookie。Cookie 仅保存在 .env，不写入
# 邮箱记录、日志或前端响应。Cookie 不能续期已失效的 API Token。
FASTMAIL_SESSION_COOKIE = env_str("FASTMAIL_SESSION_COOKIE", "")
# Alias 停用需要 Fastmail sudo；密码只在运行时完成一次解锁，不落入日志。
FASTMAIL_SUDO_PASSWORD = env_str("FASTMAIL_SUDO_PASSWORD", "")
FASTMAIL_API_BASE = "https://api.fastmail.com"
FASTMAIL_SESSION_PATH = "/jmap/session"
FASTMAIL_SESSION_URL = ""
FASTMAIL_REQUEST_TIMEOUT = 20
FASTMAIL_POLL_INTERVAL = 3
FASTMAIL_MESSAGE_LIMIT = 10
# JMAP mail accountId；留空从 Session 的 primaryAccounts 自动发现。
FASTMAIL_ACCOUNT_ID = ""
# customer accountId 与 mail accountId 通常不同；留空自动发现。
FASTMAIL_ALIAS_ACCOUNT_ID = ""
# Alias 收信转发目标；留空使用 Session username / mail account name。
FASTMAIL_ALIAS_TARGET_EMAIL = ""
# 当前 Fastmail 账号可用的普通 Alias 域名，每行一个。HAR 已验证 150mail.com。
FASTMAIL_ALIAS_DOMAINS = ["150mail.com"]
FASTMAIL_ALIAS_LOCAL_LENGTH = 12
FASTMAIL_ALIAS_CREATE_ATTEMPTS = 10
FASTMAIL_ALIAS_DESCRIPTION = "ChatGPT registration"
# 与 Fastmail Web 端一致，创建/删除 Alias 时同步对应 Identity。
FASTMAIL_ALIAS_UPDATE_IDENTITIES = True

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'USE_EMAIL_SERVICE': 'bool', 'OTP_MAX_WAIT': 'int', 'OTP_POLL_INTERVAL': 'int', 'PLUS_ALIAS_BASE_COOLDOWN_SECONDS': 'int', 'EMAIL_SOURCE': 'str', 'EMAIL_DOMAIN': 'str', 'QQ_EMAIL': 'str', 'QQ_IMAP_PASSWORD': 'str', 'GPTMAIL_API_KEY': 'str', 'OUTLOOK_FETCH_MODE': 'str', 'ICLOUD_API_BASE': 'str', 'ICLOUD_LATEST_MESSAGES_PATH': 'str', 'ICLOUD_REQUEST_TIMEOUT': 'int', 'MAILCOM_IMAP_TIMEOUT': 'int', 'MAILCOM_WEB_TIMEOUT': 'int', 'MAILCOM_WEB_CACHE_SIZE': 'int', 'MAILCOM_WEB_USE_PROXY': 'bool', 'MAILCOM_WEB_PROXY': 'str', 'MAILCOM_WEB_PROXY_ATTEMPTS': 'int', 'MAILCOM_WEB_DIRECT_FALLBACK': 'bool', 'MAILCOM_OAUTH_PUBLIC_SECRET': 'str', 'MAILCOM_ALIAS_MAX': 'int', 'MAIL_NEST_API_KEY': 'str', 'MAIL_NEST_PROJECT_CODE': 'str', 'LOF_MAIL_API_BASE': 'str', 'LOF_MAIL_API_TOKEN': 'str', 'LOF_MAIL_DOMAINS': 'list_str_multiline', 'LOF_MAIL_REQUEST_TIMEOUT': 'int', 'LOF_MAIL_RANDOM_LOCAL_LENGTH': 'int', 'CLOUDFLARE_API_BASE': 'str', 'CLOUDFLARE_API_KEY': 'str', 'CLOUDFLARE_AUTH_MODE': 'str', 'CLOUDFLARE_CUSTOM_AUTH': 'str', 'CLOUDFLARE_PATH_ACCOUNTS': 'str', 'CLOUDFLARE_PATH_MESSAGES': 'str', 'CLOUDFLARE_DEFAULT_DOMAINS': 'list_str_multiline', 'CLOUDFLARE_REQUEST_TIMEOUT': 'int', 'CLOUDFLARE_NAME_LENGTH': 'int', 'CLOUDMAIL_API_BASE': 'str', 'CLOUDMAIL_ADMIN_EMAIL': 'str', 'CLOUDMAIL_PASSWORD': 'str', 'CLOUDMAIL_TOKEN_PATH': 'str', 'CLOUDMAIL_AUTH_TOKEN': 'str', 'CLOUDMAIL_DOMAINS': 'list_str_multiline', 'CLOUDMAIL_AUTO_ADD_USER': 'bool', 'CLOUDMAIL_RANDOM_LOCAL_LENGTH': 'int', 'FASTMAIL_API_TOKEN': 'str', 'FASTMAIL_SESSION_COOKIE': 'str', 'FASTMAIL_SUDO_PASSWORD': 'str', 'FASTMAIL_API_BASE': 'str', 'FASTMAIL_SESSION_PATH': 'str', 'FASTMAIL_SESSION_URL': 'str', 'FASTMAIL_REQUEST_TIMEOUT': 'int', 'FASTMAIL_POLL_INTERVAL': 'int', 'FASTMAIL_MESSAGE_LIMIT': 'int', 'FASTMAIL_ACCOUNT_ID': 'str', 'FASTMAIL_ALIAS_ACCOUNT_ID': 'str', 'FASTMAIL_ALIAS_TARGET_EMAIL': 'str', 'FASTMAIL_ALIAS_DOMAINS': 'list_str_multiline', 'FASTMAIL_ALIAS_LOCAL_LENGTH': 'int', 'FASTMAIL_ALIAS_CREATE_ATTEMPTS': 'int', 'FASTMAIL_ALIAS_DESCRIPTION': 'str', 'FASTMAIL_ALIAS_UPDATE_IDENTITIES': 'bool'})
