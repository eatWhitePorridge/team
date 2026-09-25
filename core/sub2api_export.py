"""Local Codex OAuth to sub2api conversion; never refresh or send credentials."""
from __future__ import annotations

import base64
import json
import logging
import math
import re
from datetime import datetime, timezone

from core import db

logger = logging.getLogger(__name__)
MAX_ACCOUNTS = 5000
MAX_CREDENTIAL_BYTES = 512 * 1024
AUTH_CLAIM = "https://api.openai.com/auth"
PROFILE_CLAIM = "https://api.openai.com/profile"
# Keep the user's converter template. These are mappings, not availability checks.
DEFAULT_MODELS = (
    "codex-auto-review", "gpt-4o-audio-preview", "gpt-4o-realtime-preview",
    "gpt-5.2", "gpt-5.2-2025-12-11", "gpt-5.2-chat-latest",
    "gpt-5.2-pro", "gpt-5.2-pro-2025-12-11", "gpt-5.3-codex-spark",
    "gpt-5.4", "gpt-5.4-2026-03-05", "gpt-5.4-mini",
    "gpt-5.5", "gpt-5.6", "gpt-5.6-luna", "gpt-5.6-sol", "gpt-5.6-terra",
    "gpt-6", "gpt-6-astra", "gpt-image-1", "gpt-image-1.5", "gpt-image-2",
    "gpt-image-2.5-flare", "gpt-image-2.5-sunburst",
)
DEFAULT_EXTRA = {
    "openai_long_context_billing_enabled": False,
    "openai_oauth_responses_websockets_v2_enabled": False,
    "openai_oauth_responses_websockets_v2_mode": "off",
    "privacy_mode": "training_off",
}


class Sub2apiExportError(ValueError):
    """A conversion error safe to show without including source credentials."""


def _object(value) -> dict:
    return value if isinstance(value, dict) else {}


def _text(*values) -> str:
    return next((value.strip() for value in values if isinstance(value, str) and value.strip()), "")


def _jwt_claims(token: str) -> dict:
    """Decode metadata only; this does not verify a JWT or authorize a request."""
    try:
        parts = token.split(".")
        if len(parts) != 3 or not re.fullmatch(r"[A-Za-z0-9_-]+", parts[1]):
            return {}
        return _object(json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))))
    except (ValueError, UnicodeError):
        return {}


def _timestamp(value) -> int | None:
    try:
        if type(value) in (int, float) or isinstance(value, str) and re.fullmatch(r"\d+(?:\.\d+)?", value.strip()):
            stamp = float(value)
            if stamp >= 1e11:
                stamp /= 1000
        elif isinstance(value, str) and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})",
            value.strip(), re.IGNORECASE,
        ):
            stamp = datetime.fromisoformat(value.strip().upper().replace("Z", "+00:00")).timestamp()
        else:
            return None
        return int(stamp) if math.isfinite(stamp) and 0 < stamp < 253402300800 else None
    except (TypeError, ValueError, OverflowError):
        return None


def convert_codex_credential(source: dict, *, account_email: str) -> tuple[dict, list[str]]:
    if not isinstance(source, dict):
        raise Sub2apiExportError("Codex 凭证必须是 JSON 对象")
    if _text(source.get("platform")).lower() not in ("", "openai", "codex"):
        raise Sub2apiExportError("凭证不属于 OpenAI / Codex 平台")
    if _text(source.get("type")).lower() not in ("", "oauth", "codex"):
        raise Sub2apiExportError("凭证不是 Codex OAuth 类型")
    nested = isinstance(source.get("credentials"), dict)
    c = source["credentials"] if nested else source
    # Tokens are copied verbatim; never substitute account Web AT or mailbox RT.
    tokens = {key: c.get(key) if isinstance(c.get(key), str) else "" for key in (
        "access_token", "refresh_token", "id_token",
    )}
    missing = [key for key in ("access_token", "refresh_token") if not tokens[key].strip()]
    if missing:
        raise Sub2apiExportError("缺少 Codex OAuth " + "、".join(missing) + "，请先补跑 Codex")
    access, identity = _jwt_claims(tokens["access_token"]), _jwt_claims(tokens["id_token"])
    access_auth, identity_auth = _object(access.get(AUTH_CLAIM)), _object(identity.get(AUTH_CLAIM))
    profile, extra = _object(access.get(PROFILE_CLAIM)), _object(source.get("extra"))
    email_name = _text(source.get("name"))
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email_name):
        email_name = ""
    emails = [c.get("email"), source.get("email"), extra.get("email"), profile.get("email"),
              access.get("email"), identity.get("email"), email_name, account_email]
    email = _text(*emails)
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise Sub2apiExportError("Codex 凭证缺少有效邮箱")
    if any(_text(value) and _text(value).casefold() != email.casefold() for value in emails):
        raise Sub2apiExportError("Codex 凭证邮箱与所选账号或令牌邮箱不一致")
    workspaces = [c.get("chatgpt_account_id"), c.get("account_id"),
                  access_auth.get("chatgpt_account_id"), identity_auth.get("chatgpt_account_id")]
    workspace = _text(*workspaces)
    if not workspace:
        raise Sub2apiExportError("Codex 凭证缺少 account_id / chatgpt_account_id")
    if any(_text(value) and _text(value) != workspace for value in workspaces):
        raise Sub2apiExportError("Codex 凭证与令牌中的工作空间不一致")
    expiry_keys = ("expires_at", "expired") if nested else ("expired", "expires_at")
    expiries = [c.get(key) for key in expiry_keys] + [access.get("exp")]
    expires_at = next((stamp for value in expiries if (stamp := _timestamp(value)) is not None), None)
    if expires_at is None:
        raise Sub2apiExportError("Codex 凭证缺少有效的 expired、expires_at 或令牌 exp")
    warnings = []
    if not tokens["id_token"].strip():
        warnings.append("缺少 id_token，已留空")
    primary = next((value for value in expiries[:2] if value is not None and value != ""), None)
    if primary is not None and _timestamp(primary) is None:
        warnings.append("首选到期时间无效，已使用其他有效到期时间")
    organizations = identity_auth.get("organizations")
    organizations = [item for item in organizations if isinstance(item, dict)] if isinstance(organizations, list) else []
    organization = next((item for item in organizations if item.get("is_default") is True),
                        organizations[0] if len(organizations) == 1 else {})
    audience = identity.get("aud")
    if isinstance(audience, list):
        audience = audience[0] if len(audience) == 1 else ""
    credentials = {
        **tokens,
        "chatgpt_account_id": workspace,
        "chatgpt_user_id": _text(c.get("chatgpt_user_id"), access_auth.get("chatgpt_user_id"), identity_auth.get("chatgpt_user_id")),
        "client_id": _text(c.get("client_id"), access.get("client_id"), audience),
        "email": email,
        "expires_at": expires_at,
        "model_mapping": dict(c["model_mapping"]) if isinstance(c.get("model_mapping"), dict) else {model: model for model in DEFAULT_MODELS},
        "organization_id": _text(c.get("organization_id"), access_auth.get("organization_id"), identity_auth.get("organization_id"), organization.get("id")),
        "plan_type": _text(c.get("plan_type"), access_auth.get("chatgpt_plan_type"), identity_auth.get("chatgpt_plan_type")),
        "subscription_expires_at": _text(c.get("subscription_expires_at"), identity_auth.get("chatgpt_subscription_active_until")),
    }

    def number_setting(key, default, integer=True):
        value = source.get(key, default)
        if type(value) in (int, float) and math.isfinite(value) and value >= 0 and (not integer or int(value) == value):
            return int(value) if integer else value
        warnings.append(f"{key} 无效，已使用模板值 {default}")
        return default

    return {
        "name": _text(source.get("name"), email), "platform": "openai", "type": "oauth",
        "credentials": credentials,
        "extra": {**DEFAULT_EXTRA, **extra, "email": email},
        "concurrency": number_setting("concurrency", 100),
        "priority": number_setting("priority", 1),
        "rate_multiplier": number_setting("rate_multiplier", 1, integer=False),
        "auto_pause_on_expired": source.get("auto_pause_on_expired") if isinstance(source.get("auto_pause_on_expired"), bool) else True,
    }, warnings


def _read_credential(account: dict) -> tuple[dict, str]:
    raw = _text(account.get("codex_credential_path"))
    if not raw:
        raise Sub2apiExportError("没有本地 Codex OAuth 凭证，请先补跑 Codex")
    # Rebase stored paths after moving to another computer, including Windows.
    filename = raw.replace("\\", "/").rsplit("/", 1)[-1]
    if not filename.startswith("codex-") or not filename.endswith(".json") or ".." in filename:
        raise Sub2apiExportError("Codex 凭证文件名无效")
    root = db._CODEX_DIR.resolve()
    path = (root / filename).resolve()
    if not path.is_relative_to(root):
        raise Sub2apiExportError("Codex 凭证路径无效")
    if not path.is_file():
        raise Sub2apiExportError("本地 Codex 凭证文件不存在，请先补跑 Codex")
    with path.open("rb") as handle:
        raw_bytes = handle.read(MAX_CREDENTIAL_BYTES + 1)
    if len(raw_bytes) > MAX_CREDENTIAL_BYTES:
        raise Sub2apiExportError("Codex 凭证文件过大")
    try:
        source = json.loads(raw_bytes.decode("utf-8-sig"))
    except (ValueError, UnicodeError):
        raise Sub2apiExportError("Codex 凭证不是有效 JSON") from None
    return source, filename


def export_accounts(account_ids: list[int]) -> dict:
    if not isinstance(account_ids, list) or not 1 <= len(account_ids) <= MAX_ACCOUNTS:
        raise Sub2apiExportError(f"一次请选择 1-{MAX_ACCOUNTS} 个账号")
    if any(type(item) is not int or item <= 0 for item in account_ids):
        raise Sub2apiExportError("account_ids 必须为正整数")
    ids = list(dict.fromkeys(account_ids))
    candidates = db.get_account_codex_export_candidates(ids)
    accounts, filenames, failed, warnings = [], [], [], []
    for account_id in ids:
        row = candidates.get(account_id)
        label = {"account_id": account_id, "email": _text((row or {}).get("email"))}
        try:
            if row is None:
                raise Sub2apiExportError("账号不存在")
            source, filename = _read_credential(row)
            entry, notes = convert_codex_credential(source, account_email=label["email"])
            # Validate before marking exported; parser errors must never echo tokens.
            json.dumps(entry, ensure_ascii=False, allow_nan=False)
            accounts.append(entry)
            filenames.append(filename)
            if notes:
                warnings.append({**label, "error": "；".join(notes)})
        except Sub2apiExportError as exc:
            failed.append({**label, "error": str(exc)})
        except Exception as exc:
            logger.warning("[sub2api] 账号导出失败: account_id=%s error=%s", account_id, type(exc).__name__)
            failed.append({**label, "error": "Codex 凭证读取或转换失败，请检查本地文件"})
    marked = False
    if filenames:
        try:
            db.mark_codex_exported_bulk(filenames)
            marked = True
        except Exception as exc:
            logger.warning("[sub2api] 导出标记保存失败: error=%s", type(exc).__name__)
            warnings.append({"account_id": None, "email": "", "error": "文件已生成，但已导出标记保存失败"})
    now = datetime.now(timezone.utc)
    return {
        "ok": bool(accounts), "requested_count": len(ids), "exported_count": len(accounts),
        "failed_count": len(failed), "failed": failed, "warnings": warnings, "export_marked": marked,
        "filename": f"sub2api-accounts-{now.strftime('%Y%m%d-%H%M%S')}.json",
        "data": {"exported_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
                 "proxies": [], "accounts": accounts},
    }
