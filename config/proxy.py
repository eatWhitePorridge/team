# -*- coding: utf-8 -*-
"""
代理池配置

每次注册随机抽取一个代理，保证不同 sid 之间彼此独立，避免风控关联。

协议说明：
    - http:// / https://   HTTP(S) 代理
    - socks5://            SOCKS5（DNS 本地解析，可能泄漏）
    - socks5h://           SOCKS5（DNS 在代理端解析，推荐，避免 DNS-IP 错配）
"""
import random
from urllib.parse import quote

from config.env_loader import apply_env_overrides


# 本地代理入口；实际出口地区以代理/分流规则为准。
# 推荐使用 socks5h://（DNS 在代理端解析），避免本地 DNS 与出口 IP 地区错配。
PROXY_POOL = [
    "socks5://127.0.0.1:7897",
]

# 套餐/Plus 试用资格查询与 Codex Agent Token 生成共用这组独立网络策略，
# 避免批量请求被注册代理池中的临时本地代理拖垮，也避免无条件直连造成出口策略失控。
#   auto   = 优先使用 PLAN_CHECK_PROXY 或代理池；本地代理端口未监听时回退直连
#   proxy  = 强制使用 PLAN_CHECK_PROXY 或代理池，失败直接报错
#   direct = 始终直连
PLAN_CHECK_PROXY_MODE = "auto"

# 套餐查询 / Codex Agent Token 生成专用代理。留空时 auto/proxy 模式从 PROXY_POOL 选择。
# 代理可能包含账号密码，因此 WebUI 会把它保存到 .env。
PLAN_CHECK_PROXY = ""

# 查套餐 / 生成 Codex Agent Token 使用独立的短超时和有限重试，避免后台任务长时间卡住。
PLAN_CHECK_TIMEOUT = 15.0
PLAN_CHECK_MAX_ATTEMPTS = 2
PLAN_CHECK_RETRY_DELAY = 1.5

# 新注册账号的权益可能存在短暂同步延迟。首次查询失败，或返回 free 且暂未发现
# Plus 试用资格时，等待该秒数后再复查一次；设为 0 可关闭复查。
PLAN_CHECK_REGISTRATION_RECHECK_DELAY = 2.0

# 自动、手动和批量套餐查询共用同一个后台队列；Codex Agent Token 使用独立队列，
# 但复用这里的网络模式、请求启动间隔与随机抖动，避免批量后台请求过于集中。
PLAN_CHECK_WORKERS = 3
PLAN_CHECK_QUEUE_LIMIT = 500
PLAN_CHECK_MIN_INTERVAL = 0.4
PLAN_CHECK_JITTER = 0.3

# 套餐、优惠与 PayPal 前后资格核验统一使用 Firefox TLS/HTTP 画像。
# 这类纯 HTTP 请求不应隐式继承注册协议的默认 Chrome 画像。
PLAN_CHECK_BROWSER_FAMILY = "firefox"

# 独立账号验活使用 Firefox TLS/HTTP 画像，避免与批量套餐查询共用 Chrome 指纹。
# 仅影响 /api/accounts/check-alive，不改变注册与注册后优惠查询。
ACCOUNT_HEALTH_BROWSER_FAMILY = "firefox"

# 额度检测复用当前套餐检测网络配置，但队列与请求节流独立。
QUOTA_CHECK_WORKERS = 3
QUOTA_CHECK_QUEUE_LIMIT = 500
QUOTA_CHECK_TIMEOUT = 20.0
QUOTA_CHECK_MAX_ATTEMPTS = 2
QUOTA_CHECK_RETRY_DELAY = 1.0
QUOTA_CHECK_MIN_INTERVAL = 0.25


def normalize_proxy_url(raw: str | None) -> str:
    """把代理池常见的四段 SOCKS5 格式转换为标准 URL。"""
    value = str(raw or "").strip()
    if not value or "://" in value:
        return value
    parts = value.split(":", 3)
    if len(parts) == 4 and parts[0] and parts[1].isdigit() and parts[2]:
        host, port, username, password = parts
        return (
            f"socks5h://{quote(username, safe='')}:{quote(password, safe='')}"
            f"@{host}:{port}"
        )
    return "http://" + value


def pick_proxy() -> str:
    """从代理池中随机抽取并规范化代理 URL；池为空时返回空串。"""
    pool = PROXY_POOL  # A hot update can replace the pool while a session starts.
    return normalize_proxy_url(random.choice(pool)) if pool else ""


# 兼容入口：默认每次进程启动随机选一个，作为本次注册全程的固定代理
PROXY = pick_proxy()

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {
    'PROXY_POOL': 'list_str_multiline',
    'PLAN_CHECK_PROXY_MODE': 'str',
    'PLAN_CHECK_PROXY': 'str',
    'PLAN_CHECK_TIMEOUT': 'float',
    'PLAN_CHECK_MAX_ATTEMPTS': 'int',
    'PLAN_CHECK_RETRY_DELAY': 'float',
    'PLAN_CHECK_REGISTRATION_RECHECK_DELAY': 'float',
    'PLAN_CHECK_WORKERS': 'int',
    'PLAN_CHECK_QUEUE_LIMIT': 'int',
    'PLAN_CHECK_MIN_INTERVAL': 'float',
    'PLAN_CHECK_JITTER': 'float',
    'PLAN_CHECK_BROWSER_FAMILY': 'str',
    'ACCOUNT_HEALTH_BROWSER_FAMILY': 'str',
    'QUOTA_CHECK_WORKERS': 'int',
    'QUOTA_CHECK_QUEUE_LIMIT': 'int',
    'QUOTA_CHECK_TIMEOUT': 'float',
    'QUOTA_CHECK_MAX_ATTEMPTS': 'int',
    'QUOTA_CHECK_RETRY_DELAY': 'float',
    'QUOTA_CHECK_MIN_INTERVAL': 'float',
})
PROXY = pick_proxy()
