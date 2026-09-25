# -*- coding: utf-8 -*-
"""Plus 试用提链服务配置。"""
from config.env_loader import apply_env_overrides

# 提链服务地址
EXTRACT_LINK_API_BASE: str = ""

# 提链 CDK；创建任务和监听事件都需要。
EXTRACT_LINK_CDK: str = ""

# 提链类型：pix / upi
EXTRACT_LINK_TYPE: str = "pix"

# 后台提链并发与超时
EXTRACT_LINK_WORKERS: int = 3
EXTRACT_LINK_QUEUE_LIMIT: int = 500
EXTRACT_LINK_REQUEST_TIMEOUT: int = 30
EXTRACT_LINK_EVENT_TIMEOUT: int = 180

# MoMo 在本地执行完整 VN/VND 协议链，不调用上面的远程 CDK 服务。
# 动态代理 API 优先于固定代理池；接口必须返回一行 host:port 的 VN SOCKS5 代理。
MOMO_PROXY_API_URL: str = ""
MOMO_PROXY_API_TIMEOUT: int = 15

# 每行必须是带 country/region/zone 与 sticky 标识的上游代理 seed。
MOMO_PROXY_POOL: list[str] = []

# 可选本机前置代理；仅负责连接上游 seed，不作为 MoMo 出口身份。
MOMO_PRE_PROXY: str = ""

MOMO_WORKERS: int = 2
MOMO_QUEUE_LIMIT: int = 500
MOMO_REQUEST_TIMEOUT: int = 30
MOMO_POLL_TIMEOUT: int = 45
MOMO_POLL_INTERVAL: float = 1.0
MOMO_PROMO_ID: str = "plus-1-month-free"
# 仅对代理/风控类临时故障换代理重跑；0 表示不限制尝试次数。
MOMO_PROXY_MAX_ATTEMPTS: int = 0
MOMO_PROXY_RETRY_INTERVAL: float = 1.0

apply_env_overrides(globals(), {
    'EXTRACT_LINK_API_BASE': 'str',
    'EXTRACT_LINK_CDK': 'str',
    'EXTRACT_LINK_TYPE': 'str',
    'EXTRACT_LINK_WORKERS': 'int',
    'EXTRACT_LINK_QUEUE_LIMIT': 'int',
    'EXTRACT_LINK_REQUEST_TIMEOUT': 'int',
    'EXTRACT_LINK_EVENT_TIMEOUT': 'int',
    'MOMO_PROXY_API_URL': 'str',
    'MOMO_PROXY_API_TIMEOUT': 'int',
    'MOMO_PROXY_POOL': 'list_str_multiline',
    'MOMO_PRE_PROXY': 'str',
    'MOMO_WORKERS': 'int',
    'MOMO_QUEUE_LIMIT': 'int',
    'MOMO_REQUEST_TIMEOUT': 'int',
    'MOMO_POLL_TIMEOUT': 'int',
    'MOMO_POLL_INTERVAL': 'float',
    'MOMO_PROMO_ID': 'str',
    'MOMO_PROXY_MAX_ATTEMPTS': 'int',
    'MOMO_PROXY_RETRY_INTERVAL': 'float',
})
