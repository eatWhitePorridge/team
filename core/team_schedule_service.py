"""Seat-scoped owner operations followed by independent account completion queues."""
from __future__ import annotations

import hashlib
import json

from core import db, team_admin_store as store

Error = store.TeamAdminError


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _member_targets(members: list[dict], seat: str, parent_email: str) -> list[dict]:
    return sorted([
        {key: row.get(key) or "" for key in ("id", "email", "role", "seat_type", "pending_seat_type")}
        for row in members
        if row.get("seat_type") == seat and row.get("role") == "standard-user"
        and row.get("email", "").casefold() != parent_email.casefold()
        and not row.get("deactivated_time")
    ], key=lambda row: row["id"])


def _batch_targets(batch_id: str) -> list[dict]:
    from core.team_admin_service import _valid_invite_email
    if not batch_id or not db.get_registration_batch(batch_id):
        raise Error("请选择有效的注册批次", code="batch_missing", status=404)
    accounts = db.get_batch_schedule_candidates(batch_id)
    if not 1 <= len(accounts) <= 200:
        raise Error("所选批次需要包含 1-200 个未归档账号", code="batch_size_invalid")
    if any(not _valid_invite_email(row["email"]) for row in accounts):
        raise Error("批次内有无效邮箱，请先修正")
    if any(not row["has_web_cookies"] for row in accounts):
        raise Error("批次内有账号缺少登录态，无法执行协议补 Team，请先补充或移出该批次")
    if any(row["team_busy"] or row["totp_busy"] or row["codex_status"] in {"queued", "running", "retrying"} for row in accounts):
        raise Error("批次中有账号正在补跑，请等待完成后调度", code="accounts_busy", status=409)
    targets = [{"id": row["id"], "email": row["email"].strip().casefold()} for row in accounts]
    if len({row["email"] for row in targets}) != len(targets):
        raise Error("批次中存在重复邮箱，请先合并重复账号")
    return targets


def _plan(parent_id: int, data: dict) -> dict:
    from core.team_admin_service import _SEAT_TYPES, _require_seat_support
    parent = store.get_parent(parent_id)
    workspace_id = str(data.get("workspace_id") or "")
    space = next((row for row in store.workspaces(parent_id) if row["id"] == workspace_id), None)
    if not space or not space.get("can_manage"):
        raise Error("请选择有管理权限的工作区", code="workspace_forbidden", status=422)
    if not space.get("members_synced_at") or space.get("members_stale"):
        raise Error("请先同步该母号成员，再预览调度", code="members_stale", status=409)
    source, action = str(data.get("source_seat_type") or ""), str(data.get("action") or "")
    target, invite_seat = str(data.get("target_seat_type") or ""), str(data.get("invite_seat_type") or "")
    if source not in _SEAT_TYPES or invite_seat not in _SEAT_TYPES or action not in {"remove", "switch"}:
        raise Error("请选择来源席位、成员操作和邀请席位")
    if action == "switch":
        if target not in _SEAT_TYPES or target == source:
            raise Error("切换后的席位必须与来源席位不同")
        _require_seat_support(space, target)
    else:
        target = ""
    _require_seat_support(space, invite_seat)
    members = store.workspace_members(parent_id, workspace_id)
    targets = _member_targets(members, source, parent["email"])
    if len(targets) > 200:
        raise Error("该席位超过 200 名普通成员，请先分批处理成员")
    if any(row["pending_seat_type"] for row in targets):
        raise Error("该席位有尚未完成切换的成员，请同步确认后调度")
    batch_id = str(data.get("batch_id") or "")
    accounts = _batch_targets(batch_id)
    existing = {row["email"].strip().casefold() for row in members}
    if any(row["email"] in existing for row in accounts):
        raise Error("所选批次包含已在此工作区的账号，请选择待邀请批次", code="batch_already_member", status=409)
    return {
        "workspace_id": workspace_id, "workspace_name": space.get("name") or workspace_id,
        "source_seat_type": source, "action": action, "target_seat_type": target,
        "invite_seat_type": invite_seat, "batch_id": batch_id, "members": targets, "accounts": accounts,
        "protected_count": sum(row.get("seat_type") == source and (
            row.get("role") != "standard-user" or row.get("email", "").casefold() == parent["email"].casefold()
        ) for row in members),
        "members_synced_at": space["members_synced_at"],
    }


def _selection(plan: dict) -> str:
    return _digest({key: plan[key] for key in (
        "workspace_id", "source_seat_type", "action", "target_seat_type", "invite_seat_type",
        "batch_id", "members", "accounts",
    )})


def preview(parent_id: int, data: dict) -> dict:
    return store.save_schedule_preview(parent_id, _plan(parent_id, data))


def enqueue(parent_id: int, data: dict) -> dict:
    from core import team_admin_service as admin
    preview_id = str(data.get("preview_id") or "")
    plan = store.schedule_preview(parent_id, preview_id)
    if _selection(plan) != _selection(_plan(parent_id, plan)):
        raise Error("成员或批次内容已变化，请重新预览", code="selection_changed", status=409)
    if not admin._SLOTS.acquire(blocking=False):
        raise Error("母号管理队列已满", code="queue_full", status=429)
    job = None
    try:
        job = store.create_job(parent_id, "schedule", plan["workspace_id"], [], plan["invite_seat_type"],
                               schedule_preview_id=preview_id)
        admin._EXECUTOR.submit(admin._run, job["id"])
    except BaseException:
        admin._SLOTS.release()
        if job:
            store.update_job(job["id"], status="failed", message="调度入队失败")
        raise
    return {key: value for key, value in job.items() if key != "schedule_plan"}


def run(client, job: dict, members: list[dict], workspace: dict):
    """Return after dispatching successors; never wait in an admin worker."""
    from core import account_completion_service as completion, team_admin_service as admin
    plan, job_id = job["schedule_plan"], job["id"]
    for seat in [plan["invite_seat_type"], plan["target_seat_type"]]:
        admin._require_seat_support(workspace, seat)
    current = _member_targets(members, plan["source_seat_type"], client.parent["email"])
    if current != plan["members"]:
        raise Error("远端席位成员已变化，调度未执行；请重新同步并预览", code="selection_changed", status=409)
    if _batch_targets(plan["batch_id"]) != plan["accounts"]:
        raise Error("批次账号已变化，调度未执行；请重新预览", code="selection_changed", status=409)
    existing = {row["email"].strip().casefold() for row in members}
    if any(row["email"] in existing for row in plan["accounts"]):
        raise Error("待邀请账号已加入此工作区，调度未执行；请重新预览", code="selection_changed", status=409)
    before = {row["email"]: row for row in admin._sync_invites(client)}
    if any((old := before.get(row["email"])) and old["status"] == 2
           and not admin._invite_matches(old, plan["invite_seat_type"]) for row in plan["accounts"]):
        raise Error("待邀请账号已有不同席位或角色的邀请，请先处理邀请", code="invite_conflict", status=409)
    results = []
    indexed = {row["id"]: row for row in members}
    for member in current:
        admin._check_cancel(job_id)
        # Seat switches use the validated initial snapshot, with no intervening
        # member scans. Removal keeps its existing pre-mutation validation.
        fresh = (indexed.get(member["id"]) if plan["action"] == "switch" else
                 next((row for row in client.members(query=member["email"]) if row["id"] == member["id"]), None))
        if _member_targets([fresh] if fresh else [], plan["source_seat_type"], client.parent["email"]) != [member]:
            raise Error("成员席位或权限已变化，剩余调度已停止", code="selection_changed", status=409)
        store.update_job(job_id, message=f"正在处理 {member['email']} 的 {plan['source_seat_type']} 席位")
        try:
            result = (admin._remove(client, fresh) if plan["action"] == "remove"
                      else admin._switch(client, fresh, plan["target_seat_type"]))
        except Exception as exc:
            results.append({"stage": "members", "user_id": member["id"], "email": member["email"],
                            "status": "unconfirmed", "message": str(exc) if isinstance(exc, Error) else "成员操作结果未确认"})
            store.update_job(job_id, results=results, completed=len(results))
            raise
        results.append({**result, "stage": "members"})
        store.update_job(job_id, results=results, completed=len(results))
        if result["status"] not in {"success", "unchanged"}:
            raise Error("成员处理未确认成功，邀请及补全未执行", code="member_operation_failed", status=409)
    admin._check_cancel(job_id)
    if _batch_targets(plan["batch_id"]) != plan["accounts"]:
        raise Error("批次账号已变化，邀请及补全未执行", code="selection_changed", status=409)
    if plan["action"] == "remove":
        members = admin._sync_members(client)
        indexed = {row["id"]: row for row in members}
        if any(old["id"] in indexed for old in current):
            raise Error("成员处理最终状态未确认，邀请及补全未执行", code="member_operation_unconfirmed", status=409)
    store.update_job(job_id, stage="inviting", message="成员处理完成，正在邀请批次账号")
    completion_ids = []
    invite_job = {**job, "resend_emails": True}
    for offset in range(0, len(plan["accounts"]), admin._INVITE_BATCH_SIZE):
        admin._check_cancel(job_id)
        accounts = plan["accounts"][offset:offset + admin._INVITE_BATCH_SIZE]
        emails = [row["email"] for row in accounts]
        store.mark_invites_stale(client.workspace_id)
        store.update_job(job_id, inflight_emails=emails)
        batch, stop = admin._invite_batch(client, invite_job, emails)
        results.extend({**row, "stage": "invite"} for row in batch)
        store.update_job(job_id, results=results, completed=len(results), inflight_emails=[])
        admin._check_cancel(job_id)
        confirmed = {row["email"] for row in batch if row["status"] == "success"}
        results.extend({"stage": "completion", "email": row["email"], "status": "failed",
                        "message": "邀请未确认成功，补全未执行"} for row in batch if row["email"] not in confirmed)
        ids = [row["id"] for row in accounts if row["email"] in confirmed]
        if ids:
            queued = completion.enqueue_accounts(ids, expected_workspace_id=client.workspace_id, source_job_id=job_id)
            completion_ids.extend(row["id"] for row in queued["started"])
            for row in [*queued["busy"], *queued["skipped"]]:
                results.append({"stage": "completion", "email": row.get("email"), "status": "failed",
                                "message": row.get("reason") or "一键补全未入队"})
        store.update_job(job_id, completion_ids=completion_ids, results=results, completed=len(results))
        if stop:
            raise stop
    admin._check_cancel(job_id)
    store.update_job(job_id, stage="completion_waiting", message="邀请已处理，等待各账号依次补 Team → Codex → 2FA")
    try:
        if plan["action"] != "switch":
            admin._sync_seat_summary(client)
    except Error as exc:
        if exc.code == "cancelled":
            raise
    refresh(job_id)


def refresh(job_id: str):
    from core import account_completion_service as completion
    job = store.get_job(job_id)
    if job["status"] != "running" or job.get("stage") != "completion_waiting":
        return
    if job.get("cancel_requested"):
        cancel(job_id)
        return
    items = completion.items_by_source(job_id)
    results = [row for row in job["results"] if not row.get("pipeline_id")]
    results.extend({"stage": "completion", "pipeline_id": row["id"], "email": row["email"],
                    "status": row["status"], "message": row["message"]} for row in items)
    known = {row.get("email") for row in results if row.get("stage") == "completion"}
    results.extend({"stage": "completion", "email": row["email"], "status": "failed", "message": "补全任务记录缺失，未继续执行"}
                   for row in list(results) if row.get("stage") == "invite" and row["status"] == "success" and row["email"] not in known)
    active = any(row["status"] in {"queued", "running"} for row in items)
    finished = sum(row["status"] not in {"queued", "running"} for row in results)
    changes = {"results": results, "completed": finished}
    if not active:
        failed = sum(row["status"] not in {"success", "unchanged"} for row in results)
        succeeded = sum(row["status"] == "success" for row in items)
        if len(items) < len(job.get("completion_ids", [])):
            failed += 1
        changes.update(status="partial" if failed else "success", finished_at=store.now(),
                       message=f"调度结束：{succeeded} 个账号补全成功，{failed} 项失败或未确认")
    if any(job.get(key) != value for key, value in changes.items() if key != "finished_at"):
        store.update_schedule_progress(job_id, **changes)


def refresh_waiting():
    for job in store.waiting_schedule_jobs():
        refresh(job["id"])


def cancel(job_id: str):
    from core import account_completion_service as completion
    job = store.get_job(job_id)
    if job.get("kind") == "schedule":
        completion.cancel_source(job_id)
        if job.get("stage") == "completion_waiting":
            store.update_job(job_id, status="cancelled", message="调度已取消；当前已提交步骤结束后不再继续后续步骤")
