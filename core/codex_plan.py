"""Read-only display metadata for the saved OAuth credential, not Web plans."""
from __future__ import annotations

import base64
import json
import re
from functools import lru_cache
from pathlib import Path

TEAM_PLANS = frozenset({
    "team", "business", "self_serve_business",
    "self_serve_business_usage_based", "self_serve_business_prolite",
})


def normalize_plan(value) -> str:
    value = value.strip().lower() if isinstance(value, str) else ""
    return value if re.fullmatch(r"[a-z0-9_+-]{1,96}", value) else ""


def _token_fields(token) -> dict:
    if not isinstance(token, str) or len(token) > 512 * 1024:
        return {}
    try:
        part = token.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (ValueError, IndexError, UnicodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    auth = payload.get("https://api.openai.com/auth")
    profile = payload.get("https://api.openai.com/profile")
    auth = auth if isinstance(auth, dict) else {}
    profile = profile if isinstance(profile, dict) else {}
    return {
        "email": payload.get("email") or profile.get("email"),
        "account_id": auth.get("chatgpt_account_id"),
        "plan_type": auth.get("chatgpt_plan_type"),
    }


def credential_summary(credential: dict) -> dict[str, str]:
    """Decode claims for display only; never use this result to authorize access."""
    tokens = [_token_fields(credential.get(key)) for key in ("access_token", "id_token")]
    summary = {}
    for key in ("email", "account_id"):
        values = {str(item[key]).strip() for item in [credential, *tokens] if isinstance(item.get(key), str) and item[key].strip()}
        if key == "email":
            values = {value.casefold() for value in values}
        if len(values) > 1:
            return {"email": "", "account_id": "", "plan_type": ""}
        summary[key] = next(iter(values), "")
    plans = {plan for item in tokens if (plan := normalize_plan(item.get("plan_type")))}
    summary["plan_type"] = (
        next(iter(plans)) if len(plans) == 1 else "" if plans else normalize_plan(credential.get("plan_type"))
    )
    return summary


@lru_cache(maxsize=1024)
def _file_summary(path: str, signature: tuple[int, int, int]) -> dict[str, str]:
    # Cache only these three display fields. Replacement signatures invalidate
    # old metadata; credential contents and tokens are never retained here.
    if signature[1] > 512 * 1024:
        return {}
    try:
        credential = json.loads(Path(path).read_text(encoding="utf-8"))
    except (ValueError, UnicodeError):
        return {}
    return credential_summary(credential) if isinstance(credential, dict) else {}


def account_plan(account: dict, credential_root: Path) -> str:
    """Resolve only this account's saved credential; never scan the directory."""
    saved_plan = normalize_plan(account.get("codex_plan_type"))
    raw_path = str(account.get("codex_credential_path") or "").strip()
    if not raw_path:
        return saved_plan
    try:
        root = credential_root.resolve()
        path = (root / Path(raw_path).name).resolve()
        if not path.is_relative_to(root):
            return ""
        stat = path.stat()
        summary = _file_summary(str(path), (stat.st_mtime_ns, stat.st_size, stat.st_ino))
    except (OSError, ValueError, RuntimeError):
        return saved_plan
    email = str(account.get("email") or "").strip().casefold()
    workspace = str(account.get("codex_workspace_id") or "").strip()
    if summary.get("email") and summary["email"] != email:
        return ""
    if workspace and summary.get("account_id") and summary["account_id"] != workspace:
        return ""
    return summary.get("plan_type", "")
