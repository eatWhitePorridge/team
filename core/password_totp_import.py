"""Strict, offline parsers for the opt-in credential/Team workflow."""
from __future__ import annotations

import re

from core.codex_password_totp import login_material, PasswordTotpLoginError
from core.team_invite_service import manual_invite


def parse_accounts(text: str) -> list[dict]:
    if not isinstance(text, str) or not text.strip() or len(text) > 2_000_000:
        raise ValueError("请提供 1-500 行账号信息")
    records = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        # Peel the optional link and secret from the right. Passwords can
        # contain hyphens (even the delimiter) and leading/trailing spaces.
        try:
            email, rest = line.split("----", 1)
            before, last = rest.rsplit("----", 1)
            invite_url = ""
            if last.strip().lower().startswith("https://"):
                invite_url = manual_invite(last)["url"]
                password, secret = before.rsplit("----", 1)
            else:
                password, secret = before, last
            email = email.strip().casefold()
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 254:
                raise ValueError("邮箱格式无效")
            record = {"email": email, "registration_password": password, "totp_secret": secret}
            password, secret = login_material(record)
            records.append({**record, "totp_secret": secret, "invite_url": invite_url})
        except (ValueError, PasswordTotpLoginError):
            raise ValueError(f"第 {number} 行格式无效：需要邮箱----ChatGPT密码----Base32密钥，可附加----邀请链接") from None
        if len(records) > 500:
            raise ValueError("单次最多导入 500 个账号")
    if not records:
        raise ValueError("请提供账号信息")
    return records


def parse_invite_links(text: str, accounts: dict[int, dict]) -> dict[int, str]:
    if not isinstance(text, str) or len(text) > 2_000_000:
        raise ValueError("邀请链接格式无效")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return {}
    if len(lines) > 500:
        raise ValueError("单次最多 500 条邀请链接")
    if len(accounts) == 1 and len(lines) == 1 and lines[0].startswith("https://"):
        return {next(iter(accounts)): manual_invite(lines[0])["url"]}
    by_email = {str(row["email"]).casefold(): account_id for account_id, row in accounts.items()}
    result = {}
    for number, line in enumerate(lines, 1):
        email, separator, url = line.partition("----")
        account_id = by_email.get(email.strip().casefold())
        if not separator or account_id is None or account_id in result:
            raise ValueError(f"第 {number} 行需要所选邮箱----邀请链接，每个邮箱仅一条")
        result[account_id] = manual_invite(url)["url"]
    return result


def account_ids(value) -> list[int]:
    if not isinstance(value, list) or not 1 <= len(value) <= 500:
        raise ValueError("account_ids 必须包含 1-500 个账号 ID")
    if any(type(item) is not int or item <= 0 for item in value):
        raise ValueError("账号 ID 必须是正整数")
    return list(dict.fromkeys(value))
