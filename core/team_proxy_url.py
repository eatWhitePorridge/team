"""Validate fixed mother proxy URLs without reflecting credentials in errors."""
from urllib.parse import quote, unquote, urlsplit


def normalize_proxy(value) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ValueError("代理地址不能为空或超过 4096 字符")
    value = value.strip()
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        raise ValueError("代理地址不能包含空白或控制字符")
    if "://" not in value:
        parts = value.split(":", 3)
        if len(parts) == 4 and parts[1].isdigit() and parts[2]:
            value = f'socks5h://{quote(parts[2], safe="")}:{quote(parts[3], safe="")}@{parts[0]}:{parts[1]}'
        else:
            value = "http://" + value
    try:
        parsed = urlsplit(value)
        if not (parsed.scheme in {"http", "https", "socks5", "socks5h"} and parsed.hostname
                and parsed.port and not parsed.query and not parsed.fragment and parsed.path in {"", "/"}):
            raise ValueError()
        if "***" in unquote(parsed.username or "") or "***" in unquote(parsed.password or ""):
            raise ValueError()
    except ValueError:
        raise ValueError("代理格式无效，请填写完整 HTTP/SOCKS5 地址，不要使用脱敏地址") from None
    return value


def masked_proxy(value: str) -> str:
    parsed = urlsplit(normalize_proxy(value))
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    auth = "***:***@" if parsed.username is not None else ""
    return f"{parsed.scheme}://{auth}{host}:{parsed.port}"
