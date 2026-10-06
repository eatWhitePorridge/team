"""Bulk admission and prompt result reconciliation for the isolated console.

Only password/TOTP authorization is handled here. Legacy Team -> Codex ->
TOTP and mother-account schedule chains keep their existing coordinator.
"""
from collections import defaultdict

CHUNK_SIZE = 100


def eligible(item):
    return (item.get("login_mode") == "password_totp" and not item.get("source_job_id")
            and item.get("status") in {"queued", "running"}
            and item.get("stage") in {"codex_pending", "codex_waiting"})


def live_items(service):
    with service._LOCK:
        return [dict(row) for row in service._read_rows() if eligible(row)]


def reconcile(service):
    waiting = [row for row in live_items(service) if row["stage"] == "codex_waiting"]
    if not waiting:
        return
    snapshot = service.db.authorization_dispatch_snapshot(
        [row["account_id"] for row in waiting], [row["codex_job_id"] for row in waiting if row.get("codex_job_id")])
    ready = [row for row in waiting
             if snapshot["jobs"].get(row.get("codex_job_id"), {}).get("status") not in service._JOB_ACTIVE]
    with service._batch_item_updates(ready):
        for row in ready:
            try:
                # Reuse the original per-attempt identity/workspace/Team plan
                # checks. A successful child alone is NOT a successful Team job.
                service._advance(row, snapshot=snapshot)
            except Exception as exc:
                service._finish(row, ok=False, message="授权结果确认失败", error=type(exc).__name__)


def admit(service, items):
    wanted = {row["id"] for row in items}
    rows = [row for row in live_items(service) if row["id"] in wanted and row["stage"] == "codex_pending"]
    if not rows:
        return
    accounts = service.db.authorization_dispatch_snapshot([row["account_id"] for row in rows], [])["accounts"]
    candidates = []
    with service._batch_item_updates(rows):
        for row in rows:
            account = accounts.get(row["account_id"])
            if not account:
                service._finish(row, ok=False, message="账号不存在")
            elif str(account.get("email") or "").casefold() != str(row.get("email") or "").casefold():
                service._finish(row, ok=False, message="调度账号邮箱已变化，后续步骤不执行")
            elif service._stop_for_account_ban(row, account):
                continue
            elif row.get("team_authorization") and int(row.get("codex_attempt_count") or 0) >= service._TEAM_AUTH_MAX_ATTEMPTS:
                service._finish(row, ok=False, message=f"补 Team 授权已达到最多 {service._TEAM_AUTH_MAX_ATTEMPTS} 次尝试，停止重试")
            elif row.get("team_authorization") and service.time.time() < float(row.get("next_attempt_at") or 0):
                continue
            else:
                candidates.append(row)
        if not candidates:
            return
        team = bool(candidates[0].get("team_authorization"))
        workspace = str(candidates[0].get("expected_workspace_id") or "")
        assert all(bool(row.get("team_authorization")) == team
                   and str(row.get("expected_workspace_id") or "") == workspace for row in candidates)
        try:
            result = service.registration_service.submit_account_codex_oauth(
                [row["account_id"] for row in candidates], login_mode="password_totp",
                **({"team_authorization": True} if team else {}),
                **({"expected_workspace_id": workspace} if workspace else {}))
        except Exception as exc:
            for row in candidates:
                if team:
                    attempt = int(row.get("codex_attempt_count") or 0) + 1
                    service._set_item(row["id"], codex_attempt_count=attempt)
                    service._retry_team_authorization({**row, "codex_attempt_count": attempt}, f"授权入队异常：{type(exc).__name__}")
                else:
                    service._finish(row, ok=False, message="密码 + 2FA 授权未能入队", error=type(exc).__name__)
            return
        submitted = {int(job["account_id"]): job for job in result.get("submitted") or []}
        skipped = defaultdict(list)
        for skip in result.get("skipped") or []:
            skipped[int(skip["id"])].append(skip)
        # Admission may reject an account that became banned after our initial
        # snapshot. Do not turn that rejection into six more coordinator retries.
        rejected = [row["account_id"] for row in candidates if row["account_id"] not in submitted]
        latest_accounts = (service.db.authorization_dispatch_snapshot(rejected, [])["accounts"]
                           if rejected else {})
        for row in candidates:
            account_id = row["account_id"]
            attempt = int(row.get("codex_attempt_count") or 0) + 1
            if account_id in submitted:
                service._move(row, "codex_waiting",
                    f"补 Team 授权第 {attempt}/{service._TEAM_AUTH_MAX_ATTEMPTS} 次，等待授权结果" if team else "等待补 Codex 完成",
                    codex_job_id=int(submitted[account_id]["id"]),
                    **({"codex_attempt_count": attempt, "next_attempt_at": None} if team else {}))
                continue
            if service._stop_for_account_ban(row, latest_accounts.get(account_id)):
                continue
            reasons = "; ".join(str(skip.get("reason") or "") for skip in skipped[account_id])
            # Never adopt another authorization's result or spend retry budget
            # merely because the same account already owns a worker reservation.
            if any(skip.get("job_id") for skip in skipped[account_id]) or "已有 Codex 补跑占用" in reasons:
                continue
            if team:
                service._set_item(row["id"], codex_attempt_count=attempt)
                service._retry_team_authorization({**row, "codex_attempt_count": attempt}, reasons or "授权未能入队")
            else:
                service._finish(row, ok=False, message="密码 + 2FA 授权未能入队", error=reasons or "没有可授权任务")


def tick(service):
    reconcile(service)
    groups = defaultdict(list)
    for row in live_items(service):
        if row["stage"] == "codex_pending" and (not row.get("team_authorization")
                or service.time.time() >= float(row.get("next_attempt_at") or 0)):
            groups[(bool(row.get("team_authorization")), str(row.get("expected_workspace_id") or ""))].append(row)
    for rows in groups.values():
        for offset in range(0, len(rows), CHUNK_SIZE):
            admit(service, rows[offset:offset + CHUNK_SIZE])
            # Interleave result confirmation with admission. Do not postpone
            # 1/351 until all 351 records have been individually dispatched.
            reconcile(service)
