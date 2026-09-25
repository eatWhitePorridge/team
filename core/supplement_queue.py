"""Batch admission only. Workers/pools and remote operations remain independent."""
import logging
from typing import Callable

from core import db

logger = logging.getLogger(__name__)


def enqueue_supplement_batch(
    account_ids: list, *, kind: str, trigger: str, slots,
    submit: Callable, valid_email: Callable | None = None,
) -> dict:
    """Reserve bounded slots, commit claims once, then dispatch individually.

    No futures are awaited. Successful workers retain ownership of their slot;
    every rejected claim or failed submission releases it here.
    """
    label = {"team": "协议补 Team", "totp": "TOTP 补接", "health": "验活", "quota": "查询额度"}[kind]
    credential_key = {"team": "has_web_cookies", "quota": "has_quota_credential"}.get(kind, "has_access_token")
    buckets = {"started": [], "busy": [], "failed": [], "skipped": []}
    if kind == "health":
        buckets["no_token"] = []
    ids = []
    seen = set()
    for raw in account_ids:
        try:
            account_id = int(raw)
        except (TypeError, ValueError):
            buckets["skipped"].append({"id": raw, "reason": "ID 非法"})
            continue
        if account_id not in seen:
            seen.add(account_id)
            ids.append(account_id)
    accounts = db.get_account_supplement_candidates(ids)
    reserved = []
    held = set()

    def release_slot(item):
        if item["id"] in held:
            held.remove(item["id"])
            slots.release()

    for account_id in ids:
        account = accounts.get(account_id)
        if account is None:
            buckets["skipped"].append({"id": account_id, "reason": "账号不存在"})
            continue
        item = {"id": account_id, "email": account["email"]}
        if kind == "health" and account["health_busy"]:
            buckets["busy"].append({**item, "accepted": False, "busy": True, "error": "该账号正在验活"})
        elif kind == "health" and not account["has_access_token"]:
            reserved.append({**item, "record_no_token": True})
        elif not account[credential_key]:
            buckets["skipped"].append({
                **item, "reason": {"team": "缺少可用的 Web Cookie", "quota": "缺少 Web AT 或 Codex 凭证"}.get(kind, "缺少 access_token"),
                **({"error_code": "web_cookies_missing"} if kind == "team" else {}),
            })
        elif valid_email is not None and not valid_email(account["email"]):
            buckets["failed"].append({**item, "accepted": False, "busy": False, "error": "账号邮箱格式无效", "error_code": "invalid_email"})
        elif account[f"{kind}_busy"]:
            buckets["busy"].append({**item, "accepted": False, "busy": True, "error": f"该账号正在{label}"})
        elif not slots.acquire(blocking=False):
            buckets["failed"].append({**item, "accepted": False, "busy": False, "queue_full": True, "error": f"{label}队列已满，请稍后重试"})
        else:
            reserved.append(item)
            held.add(account_id)

    try:
        claims = db.claim_account_supplements_bulk(reserved, kind=kind, trigger=trigger) if reserved else {}
    except Exception as exc:
        logger.warning("[%s] 批量状态保存失败: count=%s error=%s", label, len(reserved), type(exc).__name__)
        for item in reserved:
            release_slot(item)
            buckets["failed"].append({"id": item["id"], "email": item["email"], "accepted": False, "busy": False, "error": "批量入队状态保存失败，请重试", "error_code": "enqueue_failed"})
        reserved = []
        claims = {}
    except BaseException:
        for item in reserved:
            release_slot(item)
        raise

    for item in reserved:
        result = claims[item["id"]]
        item = {"id": item["id"], "email": item["email"]}
        claim_id = result.get("claim_id")
        if result.get("recorded"):
            release_slot(item)
            buckets["no_token"].append({**item, "account_id": item["id"], "accepted": False, "busy": False, **result})
            continue
        if not claim_id:
            release_slot(item)
            buckets["busy" if result.get("busy") else "failed"].append({
                **item, "accepted": False, "busy": bool(result.get("busy")), **result,
            })
            continue
        try:
            submit(account_id=item["id"], email=item["email"], claim_id=claim_id, trigger=trigger)
        except Exception as exc:
            release_slot(item)
            logger.warning("[%s] 提交失败: account_id=%s error=%s", label, item["id"], type(exc).__name__)
            error = {"status": "failed", "message": "任务入队失败，请重试", "error": "任务入队失败，请重试", "error_code": "enqueue_failed"}
            try:
                if kind == "health":
                    db.update_account_health_check(item["id"], result={**error, "status": "error", "reason": "enqueue_failed"}, check_id=claim_id)
                elif kind == "quota":
                    db.update_account_quota_check(item["id"], result=error, check_id=claim_id)
                else:
                    persist = db.update_account_team_invite if kind == "team" else db.update_account_totp
                    persist(item["id"], result=error, claim_id=claim_id)
            except Exception as persist_exc:
                logger.error("[%s] 入队失败状态保存失败: account_id=%s error=%s", label, item["id"], type(persist_exc).__name__)
            buckets["failed"].append({**item, "accepted": False, "busy": False, "error": error["error"], "error_code": "enqueue_failed"})
        else:
            held.discard(item["id"])  # Worker owns the slot from now on.
            buckets["started"].append({
                **item, "account_id": item["id"], "accepted": True, "busy": False,
                "status": "queued", "trigger": trigger,
                **({"mode": "protocol"} if kind == "team" else {}),
            })
    return {
        "ok": True, **buckets,
        **{f"{name}_count": len(items) for name, items in buckets.items()},
    }
