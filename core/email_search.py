"""Normalize exact email lists for local account and member searches."""
import re


def parse_email_search(value: str = "") -> tuple[str, ...]:
    if not isinstance(value, str):
        raise ValueError("批量搜索需要一行一个邮箱")
    if len(value) > 128 * 1024:
        raise ValueError("批量搜索内容过长，最多 500 个邮箱")
    emails = {}
    for number, line in enumerate(value.splitlines(), 1):
        email = line.strip().casefold()
        if not email:
            continue
        if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise ValueError(f"批量搜索第 {number} 行邮箱格式无效，请一行填写一个完整邮箱")
        emails[email] = None
        if len(emails) > 500:
            raise ValueError("批量搜索最多支持 500 个邮箱")
    return tuple(emails)
