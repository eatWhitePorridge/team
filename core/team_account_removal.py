"""Match local OAuth identities to a chosen parent's workspace, without email lookup."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from core import db, team_admin_store as store
from core.chatgpt_plan import decode_jwt_payload_unverified
from core.codex_plan import TEAM_PLANS, credential_summary

Error = store.TeamAdminError
_USER_ID = re.compile(r"user-[A-Za-z0-9_-]{1,190}")


def _scope(data: dict) -> dict:
    ids, batch = data.get("account_ids"), data.get("batch_id")
    if bool(batch) == (ids is not None):
        raise Error("请选择账号或一个批次")
    if batch:
        if not isinstance(batch, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", batch):
            raise Error("批次 ID 无效")
        return {"batch_id": batch}
    if (not isinstance(ids, list) or not ids
            or any(type(value) is not int or value <= 0 for value in ids)):
        raise Error("一次至少选择 1 个账号")
    return {"account_ids": sorted(set(ids))}


def _identity(account: dict, workspace_id: str) -> dict:
    raw = str(account.get("codex_credential_path") or "")
    if not raw:
        raise ValueError("没有已保存的授权凭据")
    try:
        root = db._CODEX_DIR.resolve()
        path = (root / Path(raw).name).resolve()
        if not path.is_relative_to(root) or path.stat().st_size > 512 * 1024:
            raise ValueError()
        credential = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(credential, dict):
            raise ValueError()
    except (OSError, ValueError, RuntimeError):
        raise ValueError("授权凭据不存在或不可读取") from None
    summary = credential_summary(credential)
    email = str(account.get("email") or "").strip().casefold()
    if not email or summary.get("email") != email:
        raise ValueError("授权凭据邮箱与本地账号不一致或缺失")
    if summary.get("plan_type") not in TEAM_PLANS:
        raise ValueError("保存的授权不是 Team 套餐，或授权信息不一致")
    if summary.get("account_id") != workspace_id:
        raise ValueError("授权工作区与所选母号工作区不同")
    if account.get("codex_workspace_id") and account["codex_workspace_id"] != workspace_id:
        raise ValueError("本地工作区与授权凭据不一致")
    user_ids, memberships = set(), set()
    for key in ("access_token", "id_token"):
        value = credential.get(key)
        payload = decode_jwt_payload_unverified(value if isinstance(value, str) else "")
        if not isinstance(payload, dict):
            continue
        auth = payload.get("https://api.openai.com/auth")
        if not isinstance(auth, dict):
            continue
        for field in ("chatgpt_user_id", "user_id"):
            if auth.get(field):
                user_ids.add(str(auth[field]))
        if auth.get("chatgpt_account_user_id"):
            memberships.add(str(auth["chatgpt_account_user_id"]))
    for membership in memberships:
        if "__" in membership:
            member_id, space = membership.rsplit("__", 1)
            if space != workspace_id:
                raise ValueError("授权成员 ID 的工作区不一致")
            user_ids.add(member_id)
    if len(user_ids) != 1 or not _USER_ID.fullmatch(next(iter(user_ids), "")):
        raise ValueError("授权缺少明确的成员 ID，或多个 Token 的成员 ID 不一致")
    if len(memberships) > 1:
        raise ValueError("多个 Token 的工作区成员标识不一致")
    return {"user_id": next(iter(user_ids)), "membership_ids": sorted(memberships),
            "plan_type": summary["plan_type"]}


def preview(parent_id: int, data: dict) -> dict:
    parent = store.get_parent(parent_id)
    workspace_id = data.get("workspace_id")
    space = next((row for row in store.workspaces(parent_id) if row["id"] == workspace_id), None)
    if not space or not space.get("can_manage"):
        raise Error("请选择该母号有管理权限的工作区", code="workspace_forbidden", status=422)
    scope = _scope(data)
    accounts = db.get_team_removal_candidates(**scope)
    if not accounts:
        raise Error("所选批次或账号中没有本地账号", code="accounts_missing", status=404)
    items, seen = [], set()
    for account in accounts:
        item = {"account_id": account["id"], "email": str(account.get("email") or ""),
                "user_id": "", "status": "skipped", "message": ""}
        try:
            if item["email"].strip().casefold() == parent["email"].casefold():
                raise ValueError("母号自身不移除")
            item.update(_identity(account, workspace_id))
            if item["user_id"] in seen:
                raise ValueError("重复的成员 ID，已合并到同一移除目标")
            seen.add(item["user_id"])
            item.update(status="ready", message="按授权成员 ID 匹配，执行前核对官网名单")
        except ValueError as exc:
            item["message"] = str(exc)
        items.append(item)
    for missing in sorted(set(scope.get("account_ids", [])) - {row["id"] for row in accounts}):
        items.append({"account_id": missing, "email": "", "user_id": "", "status": "skipped", "message": "本地账号已不存在"})
    plan = {"parent_id": parent_id, "workspace_id": workspace_id, "scope": scope, "items": items}
    digest = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    count = sum(item["status"] == "ready" for item in items)
    return {**plan, "workspace_name": space.get("name") or workspace_id, "parent_email": parent["email"],
            "total": len(items), "eligible_count": count, "skipped_count": len(items) - count, "selection_hash": digest}


def validate_plan(plan: dict):
    current = preview(plan["parent_id"], {**plan["scope"], "workspace_id": plan["workspace_id"]})
    if current["selection_hash"] != plan["selection_hash"]:
        raise Error("账号或授权身份已变化，请重新预览后移除", code="selection_changed", status=409)


def enqueue(parent_id: int, data: dict) -> dict:
    from core import team_admin_service as admin
    plan = preview(parent_id, data)
    if plan["selection_hash"] != data.get("selection_hash"):
        raise Error("账号或授权身份已变化，请重新预览后移除", code="selection_changed", status=409)
    if not plan["eligible_count"]:
        raise Error("没有属于所选工作区且含成员 ID 的 Team 授权账号")
    return admin.enqueue_account_removal(plan)


def check_live_member(member: dict, target: dict):
    """Decoded claims locate a candidate; only the live owner API grants access."""
    if member.get("role") != "standard-user":
        raise Error("目标不是普通成员，已保护，未移除")
    live_email = str(member.get("email") or "").strip().casefold()
    if live_email and live_email != target["email"].strip().casefold():
        raise Error("官网成员邮箱与所选账号不一致，未移除")
    memberships = target.get("membership_ids") or []
    if memberships and member.get("account_user_id") and member["account_user_id"] not in memberships:
        raise Error("官网工作区成员标识与授权不一致，未移除")
