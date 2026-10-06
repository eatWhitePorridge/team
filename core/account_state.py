"""Terminal account state, independent of HTTP status and stored credentials."""

UNUSABLE_ACCOUNT_CODES = frozenset({
    "account_deactivated", "account_deleted", "account_banned",
})


def unusable_account_code(record: dict | None) -> str:
    if not isinstance(record, dict):
        return ""
    for key in ("error_code", "codex_error_code"):
        code = str(record.get(key) or "").strip().lower()
        if code in UNUSABLE_ACCOUNT_CODES:
            return code
    for key in ("codex_status", "status"):
        if str(record.get(key) or "").strip().lower() == "deactivated":
            return "account_deactivated"
    return ""
