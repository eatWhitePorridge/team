# -*- coding: utf-8 -*-
"""Strict Team -> Codex -> TOTP account completion pipeline.

The coordinator never executes the three operations itself.  It only submits
work to their existing queues, observes persisted terminal state, and releases
an account to the next queue after the previous stage succeeded.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from core import db, registration_service, team_invite_service, totp_service

logger = logging.getLogger(__name__)

_STATE_PATH = Path(__file__).resolve().parent.parent / "一键补全任务.json"
_LOCK = threading.RLock()
_WAKE = threading.Event()
_THREAD: threading.Thread | None = None
_POLL_SECONDS = 1.0
_MAX_STAGE_ADVANCES_PER_TICK = 8
_ACTIVE_STATUSES = frozenset({"queued", "running"})
_WAITING_STAGES = frozenset({"team_waiting", "codex_waiting", "totp_waiting"})
_TEAM_SUCCESS = frozenset({"joined", "already_member"})
_TOTP_SUCCESS = frozenset({"active", "active_external"})
_TOTP_ATTEMPT_SUCCESS = frozenset({"active", "already_active"})
_JOB_ACTIVE = frozenset({"pending", "running", "stopping"})
_TERMINAL = frozenset({"success", "failed", "cancelled"})
_MAX_ITEMS = 500
_TEAM_AUTH_MAX_RETRIES = 6
_TEAM_AUTH_MAX_ATTEMPTS = 1 + _TEAM_AUTH_MAX_RETRIES
_TEAM_AUTH_RETRY_DELAY = 2.0
_STATE_CACHE: tuple[tuple[Any, ...], list[dict[str, Any]], dict[str, dict[str, Any]]] | None = None


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _read_rows() -> list[dict[str, Any]]:
    global _STATE_CACHE
    try:
        stat = _STATE_PATH.stat()
        signature = (str(_STATE_PATH), stat.st_mtime_ns, stat.st_size, stat.st_ino)
        if _STATE_CACHE is not None and _STATE_CACHE[0] == signature:
            return _STATE_CACHE[1]
        value = json.loads(_STATE_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        _STATE_CACHE = None
        return []
    except Exception:
        _STATE_CACHE = None
        logger.exception("[一键补全] 读取流水线状态失败")
        return []
    rows = value if isinstance(value, list) else []
    _STATE_CACHE = (signature, rows, {str(row.get("id")): row for row in rows})
    return rows


def _write_rows(rows: list[dict[str, Any]]) -> None:
    global _STATE_CACHE
    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{_STATE_PATH.name}.", suffix=".tmp", dir=str(_STATE_PATH.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            db._dump_storage_json(rows, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, _STATE_PATH)
        stat = _STATE_PATH.stat()
        signature = (str(_STATE_PATH), stat.st_mtime_ns, stat.st_size, stat.st_ino)
        _STATE_CACHE = (signature, rows, {str(row.get("id")): row for row in rows})
    except BaseException:
        # Callers mutate cached rows before saving; failed writes must be
        # followed by a disk read, not an apparent in-memory success.
        _STATE_CACHE = None
        raise
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def _public_item(row: dict[str, Any]) -> dict[str, Any]:
    return {
        key: row.get(key)
        for key in (
            "id", "batch_id", "batch_total", "account_id", "email", "status", "stage", "message",
            "error", "created_at", "updated_at", "completed_at", "expected_workspace_id", "source_job_id", "login_mode",
            "codex_plan_type",
            "team_authorization", "codex_attempt_count", "codex_max_attempts",
        )
    }


def _set_item(item_id: str, **changes: Any) -> dict[str, Any] | None:
    with _LOCK:
        rows = _read_rows()
        row = _STATE_CACHE[2].get(str(item_id)) if _STATE_CACHE else None
        if row is None:
            return None
        if row.get("status") == "cancelled":
            return dict(row)
        if all(row.get(key) == value for key, value in changes.items()):
            return dict(row)
        row.update(changes)
        row["updated_at"] = _now_iso()
        _write_rows(rows)
        return dict(row)


def _get_item(item_id: str) -> dict[str, Any] | None:
    with _LOCK:
        _read_rows()
        row = _STATE_CACHE[2].get(str(item_id)) if _STATE_CACHE else None
        return dict(row) if row is not None else None


def _item_signature(row: dict[str, Any]) -> tuple[Any, ...]:
    """Fields that indicate the coordinator made progress for one account."""
    return tuple(
        row.get(key)
        for key in (
            "status",
            "stage",
            "message",
            "error",
            "codex_job_id",
            "codex_attempt_count", "next_attempt_at",
            "team_attempt_count",
            "totp_attempt_count",
            "completed_at",
        )
    )


def _finish(item: dict[str, Any], *, ok: bool, message: str, error: str = "", codex_plan_type: str | None = None) -> None:
    status = "success" if ok else "failed"
    _set_item(
        str(item["id"]),
        status=status,
        stage="complete" if ok else str(item.get("stage") or "failed"),
        message=str(message or "")[:500],
        error=(str(error or message or "")[:500] if not ok else None),
        completed_at=_now_iso(),
        **({"invite_url": None} if item.get("login_mode") == "password_totp" else {}),
        **({"codex_plan_type": codex_plan_type} if codex_plan_type is not None else {}),
    )
    logger.info(
        "[一键补全] 账号流水线%s: account_id=%s stage=%s message=%s",
        "完成" if ok else "停止",
        item.get("account_id"),
        item.get("stage"),
        str(message or "")[:200],
    )


def _move(item: dict[str, Any], stage: str, message: str, **extra: Any) -> None:
    _set_item(
        str(item["id"]),
        status="running",
        stage=stage,
        message=str(message or "")[:500],
        error=None,
        stage_started_at=_now_iso(),
        **extra,
    )


def _retry_team_authorization(item: dict[str, Any], error: str, *, plan: str = "") -> None:
    attempt = int(item.get("codex_attempt_count") or 0)
    if attempt >= _TEAM_AUTH_MAX_ATTEMPTS:
        _finish(item, ok=False, message=f"补 Team 授权失败，已尝试 {attempt} 次（重试 {_TEAM_AUTH_MAX_RETRIES} 次）",
                error=f"已尝试 {attempt} 次：{error}", codex_plan_type=plan)
        return
    _move(item, "codex_pending",
          f"第 {attempt} 次未成功：{error}；准备重试 {attempt}/{_TEAM_AUTH_MAX_RETRIES}",
          codex_job_id=None, codex_plan_type=plan,
          next_attempt_at=time.time() + _TEAM_AUTH_RETRY_DELAY)
    logger.info("[Team授权] 等待重试: account_id=%s attempt=%s/%s plan=%s reason=%s",
                item.get("account_id"), attempt, _TEAM_AUTH_MAX_ATTEMPTS, plan or "unknown", error[:200])


def _advance(item: dict[str, Any]) -> None:
    expected_workspace_id = str(item.get("expected_workspace_id") or "")
    password_totp = item.get("login_mode") == "password_totp"
    team_authorization = password_totp and bool(item.get("team_authorization"))
    if item.get("source_job_id"):
        from core import team_admin_store
        try:
            parent_job = team_admin_store.get_job(item["source_job_id"])
        except team_admin_store.TeamAdminError:
            parent_job = {}
        if parent_job.get("status") not in _ACTIVE_STATUSES or parent_job.get("cancel_requested"):
            cancel_source(item["source_job_id"])
            return
        latest = _get_item(str(item["id"]))
        if latest is None or latest.get("status") not in _ACTIVE_STATUSES:
            return
    account_id = int(item.get("account_id") or 0)
    account = db.get_account(account_id)
    if not account:
        _finish(item, ok=False, message="账号不存在")
        return

    stage = str(item.get("stage") or "team_pending")
    email = str(account.get("email") or "").strip()

    if (expected_workspace_id or password_totp) and email.casefold() != str(item.get("email") or "").casefold():
        _finish(item, ok=False, message="调度账号邮箱已变化，后续步骤不执行")
        return
    codex_matches = bool(str(account.get("codex_refresh_token") or "").strip()) and (
        not expected_workspace_id or account.get("codex_workspace_id") == expected_workspace_id
    )

    # Older password/TOTP records may still point at the removed Team stage.
    # Wait for any already-running attempt, then continue directly with OAuth;
    # membership state and mail availability are not prerequisites for this mode.
    if password_totp and stage in {"team_pending", "team_waiting"}:
        if stage == "team_waiting" and str(account.get("team_status") or "").lower() in _ACTIVE_STATUSES:
            return
        _move(item, "codex_pending", "准备直接进行密码 + 2FA 授权", invite_url=None)
        return

    if stage == "team_pending":
        queued = team_invite_service.enqueue_account_team_invite_protocol(
            account_id=account_id,
            email=email,
            trigger="complete_pipeline",
            **({"expected_workspace_id": expected_workspace_id} if expected_workspace_id else {}),
        )
        if expected_workspace_id and queued.get("busy"):
            return
        if queued.get("accepted") or queued.get("busy"):
            current = db.get_account(account_id) or account
            _move(
                item,
                "team_waiting",
                "等待协议补 Team 完成",
                team_attempt_count=int(queued.get("attempt_count") or current.get("team_invite_attempt_count") or 0),
            )
        elif queued.get("queue_full"):
            return
        else:
            _finish(item, ok=False, message="协议补 Team 未能入队", error=str(queued.get("error") or "入队失败"))
        return

    if stage == "team_waiting":
        status = str(account.get("team_status") or account.get("team_invite_status") or "").lower()
        if status in _ACTIVE_STATUSES:
            return
        expected_attempt = int(item.get("team_attempt_count") or 0)
        current_attempt = int(account.get("team_invite_attempt_count") or 0)
        if expected_attempt and current_attempt < expected_attempt:
            return
        # team_status may deliberately preserve an older joined state after a
        # failed reconciliation.  A pipeline must use this attempt's terminal
        # result, never that historical effective state.
        attempt_status = str(account.get("team_invite_last_attempt_status") or "").lower()
        succeeded = (
            attempt_status in _TEAM_SUCCESS
            if expected_attempt
            else (attempt_status or status) in _TEAM_SUCCESS
        )
        target_error = ""
        if expected_workspace_id:
            if account.get("team_workspace_id") != expected_workspace_id:
                target_error = "补 Team 的工作区与当前母号不一致"
            elif current_attempt != expected_attempt:
                target_error = "本次补 Team 的结果已被其他任务覆盖"
            succeeded = succeeded and not target_error
        if succeeded:
            _move(item, "codex_pending", "Team 已成功，准备补 Codex")
        else:
            error = target_error or str(account.get("team_invite_error") or account.get("team_invite_message") or status or "未知失败")
            _finish(item, ok=False, message="协议补 Team 未成功，后续步骤不执行", error=error)
        return

    if stage == "codex_pending":
        if team_authorization and int(item.get("codex_attempt_count") or 0) >= _TEAM_AUTH_MAX_ATTEMPTS:
            _finish(item, ok=False, message=f"补 Team 授权已达到最多 {_TEAM_AUTH_MAX_ATTEMPTS} 次尝试，停止重试")
            return
        if team_authorization and time.time() < float(item.get("next_attempt_at") or 0):
            return
        if codex_matches and not password_totp:
            _move(item, "totp_pending", "Codex 已存在，准备补 2FA", codex_job_id=None)
            return
        attempt = int(item.get("codex_attempt_count") or 0) + 1
        try:
            result = registration_service.submit_account_codex_oauth([account_id],
                **({"login_mode": "password_totp"} if password_totp else {}),
                **({"team_authorization": True} if team_authorization else {}),
                **({"expected_workspace_id": expected_workspace_id} if expected_workspace_id else {}))
        except Exception as exc:
            if not team_authorization:
                raise
            _set_item(str(item["id"]), codex_attempt_count=attempt)
            _retry_team_authorization({**item, "codex_attempt_count": attempt}, f"授权入队异常：{type(exc).__name__}")
            return
        submitted = list(result.get("submitted") or [])
        if submitted:
            job_id = int(submitted[0].get("id") or 0)
            _move(item, "codex_waiting",
                  f"补 Team 授权第 {attempt}/{_TEAM_AUTH_MAX_ATTEMPTS} 次，等待授权结果" if team_authorization else "等待补 Codex 完成",
                  codex_job_id=job_id or None,
                  **({"codex_attempt_count": attempt, "next_attempt_at": None} if team_authorization else {}))
            return
        active_job_id = next(
            (
                int(skipped.get("job_id") or 0)
                for skipped in result.get("skipped") or []
                if int(skipped.get("job_id") or 0) > 0
            ),
            0,
        )
        if (expected_workspace_id or password_totp) and active_job_id:
            return
        if active_job_id:
            _move(
                item,
                "codex_waiting",
                "等待已有补 Codex 任务完成",
                codex_job_id=active_job_id,
            )
            return
        account = db.get_account(account_id) or account
        if not password_totp and str(account.get("codex_refresh_token") or "").strip() and (
            not expected_workspace_id or account.get("codex_workspace_id") == expected_workspace_id
        ):
            _move(item, "totp_pending", "Codex 已存在，准备补 2FA", codex_job_id=None)
            return
        reasons = "; ".join(str(x.get("reason") or "") for x in result.get("skipped") or [] if x.get("reason"))
        if team_authorization:
            if "已有 Codex 补跑占用" in reasons:
                return
            _set_item(str(item["id"]), codex_attempt_count=attempt)
            _retry_team_authorization({**item, "codex_attempt_count": attempt}, reasons or "授权未能入队")
            return
        _finish(item, ok=False, message="密码 + 2FA 授权未能入队" if password_totp else "补 Codex 未能入队，2FA 不执行", error=reasons or "没有可补跑的 Codex 任务")
        return

    if stage == "codex_waiting":
        job_id = int(item.get("codex_job_id") or 0)
        job = db.get_job(job_id) if job_id else None
        if job and str(job.get("status") or "") in _JOB_ACTIVE:
            return
        account = db.get_account(account_id) or account
        if team_authorization:
            from core.codex_plan import TEAM_PLANS, normalize_plan
            if job and job.get("status") in {"stopped", "cancelled"}:
                _finish(item, ok=False, message="Team 授权已停止，不再自动重试")
                return
            # Use this job's returned claims, never a previous account token.
            summary = (job or {}).get("codex_authorization") or {}
            plan = normalize_plan(summary.get("plan_type"))
            workspace = str(summary.get("account_id") or "")
            confirmed = bool(
                job and job.get("status") == "success"
                and (job.get("flow_snapshot") or {}).get("codex_login_mode") == "password_totp"
                and int(job.get("account_id") or 0) == account_id
                and str(summary.get("email") or "").casefold() == email.casefold()
                and workspace and account.get("codex_workspace_id") == workspace
                and str(account.get("codex_refresh_token") or "").strip()
                and (not expected_workspace_id or workspace == expected_workspace_id)
            )
            if confirmed and plan in TEAM_PLANS:
                _finish(item, ok=True, message=f"Team 授权完成（第 {item.get('codex_attempt_count')} 次），工作区：{workspace}",
                        codex_plan_type=plan)
            else:
                error = (f"本次授权套餐为 {plan or '未知'}，未获得 Team 授权" if confirmed
                         else str((job or {}).get("error_message") or "未确认本次授权凭证与账号、工作区一致"))
                _retry_team_authorization(item, error, plan=plan)
            return
        if (job and (not password_totp or (job.get("flow_snapshot") or {}).get("codex_login_mode") == "password_totp")
                and str(job.get("status") or "") == "success" and str(account.get("codex_refresh_token") or "").strip()
                and (not password_totp or bool(account.get("codex_workspace_id")))
                and (not expected_workspace_id or account.get("codex_workspace_id") == expected_workspace_id)):
            if password_totp:
                from core.codex_plan import account_plan
                _finish(item, ok=True, message=f"密码 + 2FA 授权完成，工作区：{account['codex_workspace_id']}",
                        codex_plan_type=account_plan(account, db._CODEX_DIR))
            else:
                _move(item, "totp_pending", "Codex 已成功，准备补 2FA")
            return
        error = ""
        if job:
            error = str(job.get("error_message") or job.get("error") or job.get("status") or "")
        if expected_workspace_id and account.get("codex_workspace_id") != expected_workspace_id:
            error = "Codex 授权未确认属于当前母号工作区"
        error = error or str(account.get("codex_error") or "Codex 任务未成功")
        _finish(item, ok=False, message="密码 + 2FA 授权未成功" if password_totp else "补 Codex 未成功，2FA 不执行", error=error)
        return

    if password_totp:
        _finish(item, ok=False, message="密码 + 2FA 流水线阶段无效，已停止")
        return

    if stage == "totp_pending":
        status = str(account.get("totp_status") or "").lower()
        if status in _TOTP_SUCCESS:
            _finish(item, ok=True, message="Team、Codex、2FA 均已完成")
            return
        access_token = str(account.get("access_token") or "").strip()
        if not access_token:
            _finish(item, ok=False, message="2FA 未能入队", error="账号缺少 access_token")
            return
        queued = totp_service.enqueue_account_totp(
            account_id=account_id,
            email=email,
            access_token=access_token,
            trigger="complete_pipeline",
        )
        if queued.get("accepted") or queued.get("busy"):
            current = db.get_account(account_id) or account
            _move(
                item,
                "totp_waiting",
                "等待补 2FA 完成",
                totp_attempt_count=int(current.get("totp_attempt_count") or 0),
            )
        elif queued.get("queue_full"):
            return
        else:
            _finish(item, ok=False, message="2FA 未能入队", error=str(queued.get("error") or "入队失败"))
        return

    if stage == "totp_waiting":
        status = str(account.get("totp_status") or "").lower()
        if status in _ACTIVE_STATUSES:
            return
        expected_attempt = int(item.get("totp_attempt_count") or 0)
        current_attempt = int(account.get("totp_attempt_count") or 0)
        if expected_attempt and current_attempt < expected_attempt:
            return
        # Like Team, totp_status preserves an older active factor when the
        # current reconciliation fails.  Only this attempt may release the
        # pipeline to its successful terminal state.
        attempt_status = str(account.get("totp_last_attempt_status") or "").lower()
        succeeded = (
            attempt_status in _TOTP_ATTEMPT_SUCCESS
            if expected_attempt
            else (attempt_status in _TOTP_ATTEMPT_SUCCESS or (not attempt_status and status in _TOTP_SUCCESS))
        )
        if succeeded:
            _finish(item, ok=True, message="Team、Codex、2FA 均已完成")
        else:
            error = str(account.get("totp_error") or account.get("totp_message") or status or "未知失败")
            _finish(item, ok=False, message="补 2FA 未成功", error=error)
        return

    _finish(item, ok=False, message="流水线状态无效", error=stage)


def _advance_until_blocked(item: dict[str, Any]) -> int:
    """Advance one account through coordinator-only states without occupying workers.

    The completion pipeline is only an orchestrator: it should hand work to the
    Team/Codex/TOTP queues, then wait for their persisted terminal state.  When a
    previous stage is already terminal, keep moving the same account in this
    scheduler tick so it does not wait for a synthetic "batch" boundary.
    """
    item_id = str(item.get("id") or "").strip()
    if not item_id:
        return 0
    current = dict(item)
    changes = 0
    for _ in range(_MAX_STAGE_ADVANCES_PER_TICK):
        before = _item_signature(current)
        _advance(current)
        latest = _get_item(item_id)
        if latest is None:
            return changes
        after = _item_signature(latest)
        if after == before:
            return changes
        changes += 1
        if str(latest.get("status") or "") not in _ACTIVE_STATUSES:
            return changes
        before_stage = str(current.get("stage") or "")
        after_stage = str(latest.get("stage") or "")
        if after_stage in _WAITING_STAGES and after_stage != before_stage:
            return changes
        current = latest
    logger.warning(
        "[一键补全] 单账号连续推进次数过多，暂停到下一轮: account_id=%s stage=%s",
        current.get("account_id"),
        current.get("stage"),
    )
    return changes


def _still_waiting(item: dict[str, Any], snapshot: dict) -> bool:
    """Skip unchanged queue state; readiness is revalidated by _advance."""
    account = snapshot["accounts"].get(int(item.get("account_id") or 0))
    if account is None:
        return False
    stage = str(item.get("stage") or "")
    if stage in {"team_waiting", "totp_waiting"}:
        if stage == "team_waiting":
            status = account.get("team_status") or account.get("team_invite_status")
            attempt_key, account_attempt_key = "team_attempt_count", "team_invite_attempt_count"
        else:
            status = account.get("totp_status")
            attempt_key = account_attempt_key = "totp_attempt_count"
        if str(status or "").lower() in _ACTIVE_STATUSES:
            return True
        return int(account.get(account_attempt_key) or 0) < int(item.get(attempt_key) or 0)
    if stage == "codex_waiting":
        job = snapshot["jobs"].get(int(item.get("codex_job_id") or 0))
        return bool(job and str(job.get("status") or "") in _JOB_ACTIVE)
    return False


def _scheduler_tick() -> int:
    with _LOCK:
        active = [dict(row) for row in _read_rows() if str(row.get("status")) in _ACTIVE_STATUSES]
    if not active:
        return 0
    snapshot = db.account_completion_snapshot(
        [int(item.get("account_id") or 0) for item in active],
        [int(item["codex_job_id"]) for item in active if item.get("codex_job_id")],
    )
    # Let completed stages release successors before filling new first-stage
    # work. This is scheduling order only; each operation keeps its own pool.
    active.sort(key=lambda item: str(item.get("stage")) not in _WAITING_STAGES)
    for item in active:
        try:
            if not _still_waiting(item, snapshot):
                _advance_until_blocked(item)
        except Exception as exc:
            logger.exception("[一键补全] 编排异常: account_id=%s", item.get("account_id"))
            _finish(item, ok=False, message="一键补全编排异常", error=f"{type(exc).__name__}: {str(exc)[:300]}")
    return len(active)


def _scheduler() -> None:
    while True:
        try:
            active_count = _scheduler_tick()
            from core import team_schedule_service
            team_schedule_service.refresh_waiting()
        except Exception:
            logger.exception("[一键补全] 本轮状态读取失败，稍后重试")
            active_count = 1
        _WAKE.wait(_POLL_SECONDS if active_count else 5.0)
        _WAKE.clear()


def _ensure_scheduler() -> None:
    global _THREAD
    with _LOCK:
        if _THREAD is not None and _THREAD.is_alive():
            return
        _THREAD = threading.Thread(target=_scheduler, name="account-completion", daemon=True)
        _THREAD.start()


def enqueue_accounts(account_ids: list[int], *, expected_workspace_id: str = "", source_job_id: str = "",
                     login_mode: str = "cookie", team_authorization: bool = False) -> dict[str, Any]:
    if login_mode not in {"cookie", "password_totp"}:
        raise ValueError("不支持的流水线登录模式")
    password_totp = login_mode == "password_totp"
    if team_authorization and not password_totp:
        raise ValueError("Team 授权需要密码 + 2FA 登录")
    source_targets = None
    if source_job_id:
        from core import team_admin_store
        source = team_admin_store.get_job(source_job_id)
        if (source.get("kind") != "schedule" or source.get("status") != "running" or source.get("cancel_requested")
                or not expected_workspace_id or source.get("workspace_id") != expected_workspace_id):
            raise ValueError("调度已停止或目标工作区不匹配")
        source_targets = {row["id"]: row["email"] for row in source["schedule_plan"]["accounts"]}
    ids: list[int] = []
    skipped: list[dict[str, Any]] = []
    for raw in account_ids or []:
        try:
            account_id = int(raw)
        except (TypeError, ValueError):
            skipped.append({"id": raw, "reason": "ID 非法"})
            continue
        if account_id not in ids:
            ids.append(account_id)
    if not ids:
        raise ValueError("account_ids 必须是非空整数数组")
    if len(ids) > _MAX_ITEMS:
        raise ValueError(f"单次最多一键补全 {_MAX_ITEMS} 个账号")
    material_errors = db.password_totp_account_errors(ids) if password_totp else {}

    started: list[dict[str, Any]] = []
    busy: list[dict[str, Any]] = []
    with _LOCK:
        rows = _read_rows()
        active_ids = {
            int(row.get("account_id") or 0)
            for row in rows
            if str(row.get("status") or "") in _ACTIVE_STATUSES
        }
        now = _now_iso()
        batch_id = uuid.uuid4().hex
        accounts = db.account_completion_snapshot(ids)["accounts"]
        for account_id in ids:
            account = accounts.get(account_id)
            if not account:
                skipped.append({"id": account_id, "reason": "账号不存在"})
                continue
            email = str(account.get("email") or "").strip()
            if account_id in material_errors:
                skipped.append({"id": account_id, "email": email, "reason": material_errors[account_id]})
                continue
            if source_targets is not None and source_targets.get(account_id) != email.casefold():
                skipped.append({"id": account_id, "email": email, "reason": "账号已不在已确认的调度名单中"})
                continue
            if account_id in active_ids:
                busy.append({"id": account_id, "email": email, "reason": "该账号正在执行一键补全"})
                continue
            row = {
                **({"team_authorization": True, "codex_attempt_count": 0,
                    "codex_max_attempts": _TEAM_AUTH_MAX_ATTEMPTS} if team_authorization else {}),
                **({"login_mode": "password_totp"} if password_totp else {}),
                **({"expected_workspace_id": expected_workspace_id} if expected_workspace_id else {}),
                **({"source_job_id": source_job_id} if source_job_id else {}),
                "id": uuid.uuid4().hex,
                "batch_id": batch_id,
                "account_id": account_id,
                "email": email,
                "status": "queued",
                "stage": "codex_pending" if password_totp else "team_pending",
                "message": (f"等待补 Team 授权（失败或 Free 自动重试 {_TEAM_AUTH_MAX_RETRIES} 次）" if team_authorization
                            else "等待直接进行密码 + 2FA 授权" if password_totp else "等待进入协议补 Team 队列"),
                "error": None,
                "codex_job_id": None,
                "created_at": now,
                "updated_at": now,
                "completed_at": None,
            }
            rows.append(row)
            active_ids.add(account_id)
            started.append(_public_item(row))
        if started:
            for row in rows[-len(started):]:
                row["batch_total"] = len(started)
            # Keep terminal history bounded while retaining all active work.
            terminal = [row for row in rows if str(row.get("status")) in _TERMINAL]
            if len(terminal) > 5000:
                remove_ids = {str(row.get("id")) for row in terminal[:-5000]}
                rows = [row for row in rows if str(row.get("id")) not in remove_ids]
            _write_rows(rows)

    if started:
        _ensure_scheduler()
        _WAKE.set()
        logger.info(
            "[一键补全] 已创建严格流水线: batch=%s started=%s busy=%s skipped=%s",
            batch_id,
            len(started),
            len(busy),
            len(skipped),
        )
    return {
        "batch_id": batch_id,
        "started": started,
        "started_count": len(started),
        "busy": busy,
        "busy_count": len(busy),
        "skipped": skipped,
        "skipped_count": len(skipped),
        "order": ["codex"] if password_totp else ["team", "codex", "totp"],
    }


def resume_incomplete() -> int:
    """Resume persisted coordinators after the operation queues recovered."""
    with _LOCK:
        count = sum(1 for row in _read_rows() if str(row.get("status")) in _ACTIVE_STATUSES)
    if count:
        _ensure_scheduler()
        _WAKE.set()
    return count


def list_items(*, limit: int = 500, batch_id: str = "") -> list[dict[str, Any]]:
    with _LOCK:
        rows = _read_rows()
        if batch_id:
            rows = [row for row in rows if row.get("batch_id") == batch_id]
    return [_public_item(row) for row in rows[-max(1, min(5000, int(limit))):][::-1]]


def list_authorization_batches(*, limit: int = 4) -> list[dict[str, Any]]:
    """Discover persisted authorization batches without returning credentials or emails.

    Retain every active batch and a few recent finished batches of each mode.
    Group before limiting so an older running task cannot be hidden by history.
    """
    groups: dict[str, dict[str, Any]] = {}
    with _LOCK:
        for row in _read_rows():
            if row.get("login_mode") != "password_totp" or not row.get("batch_id"):
                continue
            batch_id = str(row["batch_id"])
            batch = groups.setdefault(batch_id, {
                "batch_id": batch_id,
                "team_authorization": bool(row.get("team_authorization")),
                "created_at": str(row.get("created_at") or ""),
                "total": 0, "known": 0, "active": 0, "finished": 0,
            })
            batch["known"] += 1
            batch["active"] += row.get("status") in _ACTIVE_STATUSES
            batch["finished"] += row.get("status") in _TERMINAL
            batch["total"] = max(batch["total"], int(row.get("batch_total") or 0), batch["known"])
            batch["created_at"] = min(batch["created_at"], str(row.get("created_at") or ""))
    kept = []
    counts = {False: 0, True: 0}
    history_limit = max(1, min(20, int(limit)))
    for batch in sorted(groups.values(), key=lambda item: (item["created_at"], item["batch_id"]), reverse=True):
        mode = batch["team_authorization"]
        if not batch["active"]:
            if counts[mode] >= history_limit:
                continue
            counts[mode] += 1
        batch["completed"] = batch["finished"] == batch["total"]
        if batch["created_at"]:
            batch["created_at"] = datetime.fromisoformat(batch["created_at"]).astimezone().isoformat()
        kept.append(batch)
    return kept


def items_by_source(source_job_id: str) -> list[dict]:
    with _LOCK:
        return [_public_item(row) for row in _read_rows() if row.get("source_job_id") == source_job_id]


def cancel_source(source_job_id: str) -> None:
    with _LOCK:
        rows = _read_rows()
        changed = False
        for row in rows:
            if row.get("source_job_id") == source_job_id and row.get("status") in _ACTIVE_STATUSES:
                row.update(status="cancelled", message="调度已停止，后续步骤不执行", updated_at=_now_iso(), completed_at=_now_iso())
                changed = True
        if changed:
            _write_rows(rows)


__all__ = ["enqueue_accounts", "list_items", "list_authorization_batches", "resume_incomplete", "items_by_source", "cancel_source"]
