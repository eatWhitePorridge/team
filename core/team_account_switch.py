"""Preview and enqueue Team seat changes for local accounts.

The preview resolves the member identity from the saved OAuth credential.  The
worker still verifies the live member list immediately before writing the seat
mutation, so the client never submits arbitrary member IDs.
"""
from __future__ import annotations

import hashlib
import json

from core import db, team_account_removal as removal, team_admin_store as store

Error = store.TeamAdminError
SEAT_TYPES = {"default", "usage_based", "prolite"}


def _target(data: dict) -> str:
    value = data.get("seat_type")
    if not isinstance(value, str) or value not in SEAT_TYPES:
        raise Error("请选择 default、usage_based 或 prolite 目标席位")
    return value


def _scope(data: dict) -> dict:
    # Keep the same strict scope rules as account removal.
    return removal._scope(data)


def preview(parent_id: int, data: dict) -> dict:
    parent = store.get_parent(parent_id)
    workspace_id = data.get("workspace_id")
    space = next((row for row in store.workspaces(parent_id) if row["id"] == workspace_id), None)
    if not space or not space.get("can_manage"):
        raise Error("请选择该母号有管理权限的工作区", code="workspace_forbidden", status=422)
    seat_type = _target(data)
    if seat_type == "usage_based" and space.get("is_usage_based_seat_enabled") is not True:
        raise Error("当前工作区未开放 Codex（usage_based）席位", code="seat_type_not_supported", status=422)
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
                raise ValueError("母号自身不切换")
            identity = removal._identity(account, workspace_id)
            item.update(identity)
            if item["user_id"] in seen:
                raise ValueError("重复的成员 ID，已合并到同一切换目标")
            seen.add(item["user_id"])
            item.update(status="ready", message=f"按授权成员 ID 匹配，目标席位：{seat_type}")
        except ValueError as exc:
            item["message"] = str(exc)
        items.append(item)
    for missing in sorted(set(scope.get("account_ids", [])) - {row["id"] for row in accounts}):
        items.append({"account_id": missing, "email": "", "user_id": "", "status": "skipped", "message": "本地账号已不存在"})
    plan = {"kind": "switch", "parent_id": parent_id, "workspace_id": workspace_id,
            "seat_type": seat_type, "scope": scope, "items": items}
    digest = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    count = sum(item["status"] == "ready" for item in items)
    return {**plan, "workspace_name": space.get("name") or workspace_id, "parent_email": parent["email"],
            "total": len(items), "eligible_count": count, "skipped_count": len(items) - count,
            "selection_hash": digest}


def validate_plan(plan: dict):
    current = preview(plan["parent_id"], {**plan["scope"], "workspace_id": plan["workspace_id"],
                                          "seat_type": plan["seat_type"]})
    if current["selection_hash"] != plan["selection_hash"]:
        raise Error("账号、授权身份或目标席位已变化，请重新预览后切换", code="selection_changed", status=409)


def enqueue(parent_id: int, data: dict) -> dict:
    from core import team_admin_service as admin
    plan = preview(parent_id, data)
    if plan["selection_hash"] != data.get("selection_hash"):
        raise Error("账号、授权身份或目标席位已变化，请重新预览后切换", code="selection_changed", status=409)
    if not plan["eligible_count"]:
        raise Error("没有属于所选工作区且含成员 ID 的 Team 授权账号")
    return admin.enqueue_account_switch(plan)
