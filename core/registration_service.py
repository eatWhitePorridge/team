# -*- coding: utf-8 -*-
"""
注册任务服务层：
    - 线程池并发执行 run_registration
    - 每个任务在 data/registration_jobs.json 里有一条记录
    - 每个任务的日志写到 data/logs/<job_uuid>.log，便于 Web UI 实时尾巴

使用：
    submit_registration(email_source="outlook", count=5)
    → 创建 5 个任务，丢入线程池，立即返回 [job_dict, ...]
"""
import logging
import math
import threading
from time import perf_counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any

from core import codex_retry_service, db

logger = logging.getLogger(__name__)

# 注册专用全局线程池，最大并发数（WebUI 每次提交时可按最新 workers 重建）。
# OAuth 补 Codex 使用 codex_retry_service 内的另一套线程池，不占用这里的槽位。
_DEFAULT_MAX_WORKERS = 5
_MIN_MAX_WORKERS = 1
_MAX_MAX_WORKERS = 16
_executor: ThreadPoolExecutor | None = None
_executor_workers = _DEFAULT_MAX_WORKERS
_executor_generation = 0
_retired_executors: list[ThreadPoolExecutor] = []
_executor_lock = threading.RLock()
_codex_submission_lock = threading.RLock()

_STOP_EVENTS: dict[int, threading.Event] = {}
_ACTIVE_JOBS: set[int] = set()
_STOP_LOCK = threading.Lock()
_THREAD_CTX = threading.local()


class StopRequested(RuntimeError):
    """用户手动停止注册任务。"""


def _registration_failure_text(result: Any) -> str:
    """从不同注册驱动的失败结果中提取稳定、非空的任务错误。"""
    if isinstance(result, dict):
        for key in ("error", "message", "reason"):
            text = str(result.get(key) or "").strip()
            if text and text.lower() not in {"none", "null"}:
                return text[:500]
    return "注册失败，未返回错误详情"


def _activate_job(job_id: int) -> None:
    _THREAD_CTX.job_id = int(job_id)
    with _STOP_LOCK:
        _STOP_EVENTS.setdefault(int(job_id), threading.Event())
        _ACTIVE_JOBS.add(int(job_id))


def _deactivate_job(job_id: int) -> None:
    with _STOP_LOCK:
        _STOP_EVENTS.pop(int(job_id), None)
        _ACTIVE_JOBS.discard(int(job_id))
    try:
        delattr(_THREAD_CTX, "job_id")
    except Exception:
        pass


def is_stop_requested(job_id: int | None = None) -> bool:
    if job_id is None:
        job_id = getattr(_THREAD_CTX, "job_id", None)
    if not job_id:
        return False
    with _STOP_LOCK:
        ev = _STOP_EVENTS.get(int(job_id))
        if ev is not None:
            return ev.is_set()
    job = db.get_job(int(job_id))
    return bool(job and job.get("status") in ("stopping", "stopped", "cancelled"))


def check_stop_requested() -> None:
    job_id = getattr(_THREAD_CTX, "job_id", None)
    if is_stop_requested(job_id):
        raise StopRequested(f"任务 #{job_id} 已被用户手动停止")


def _append_job_log(job_id: int, message: str) -> None:
    try:
        job = db.get_job(job_id)
        log_file = job.get("log_file") if job else None
        if not log_file:
            return
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%H:%M:%S")
        with Path(log_file).open("a", encoding="utf-8") as f:
            f.write(f"{ts} [WARNING] [manual-stop] {message}\n")
    except Exception:
        pass


def _random_display_name() -> str:
    """生成符合 OpenAI 限制的英文字母显示名。"""
    from core.name_samples import random_display_name

    return random_display_name()


def _prepare_registration_args(job: dict | None = None) -> tuple[str, str, str]:
    """复用 CLI 的默认规则，为旧 Web 任务入口补齐注册参数。"""
    # 用模块属性读，支持 WebUI 热加载
    from config import register as _r, email as _e
    from core.email_provider import acquire_email
    from core.profile_utils import generate_random_birthday

    email = str(getattr(_r, "REGISTER_EMAIL", "") or "").strip()
    name = str(getattr(_r, "REGISTER_NAME", "") or "").strip()
    # WebUI/配置里有时会把空值存成 "-"，这不是合法 OpenAI 显示名，按空处理并自动生成
    if name in {"-", "—", "无", "空", "none", "None", "null", "NULL"}:
        name = ""

    if not name:
        # 手动模式也自动生成显示名，减少配置负担
        name = _random_display_name()

    birthday = generate_random_birthday()

    # 邮箱领取会把池状态置为 used，因此放在所有其他准备逻辑之后。
    if not email:
        if _e.USE_EMAIL_SERVICE:
            snapshot = (job or {}).get("flow_snapshot") if isinstance((job or {}).get("flow_snapshot"), dict) else {}
            email = acquire_email(
                email_source=(job or {}).get("email_source"),
                email_mode=str(snapshot.get("email_mode") or "single"),
                alias_limit=snapshot.get("alias_limit"),
                job_id=(job or {}).get("id"),
                batch_id=(job or {}).get("batch_id"),
            )
        else:
            raise RuntimeError(
                "手动模式未配置邮箱。请在 WebUI 配置页设置 REGISTER_EMAIL，"
                "或开启 USE_EMAIL_SERVICE 并从邮箱池领取。"
            )

    return email, name, birthday


def _release_unconsumed_job_email(email: str | None, reason: str) -> None:
    """任务失败兜底：只回收尚未生成账号、仍处于 used 的邮箱领取。"""
    if not email:
        return
    try:
        from core.email_provider import release_email_if_unconsumed

        release_email_if_unconsumed(email, note=f"任务未消耗，已自动回收: {reason[:180]}")
    except Exception:
        logger.exception("[Service] 回收未消耗邮箱失败: %s", email)


def _is_final_session_access_token_timeout(error: object) -> bool:
    """
    识别注册最后一步已经返回 /api/auth/session 200 但没有 accessToken 的失败。
    这种邮箱后续继续注册通常会卡在同一状态，按要求直接停用邮箱池条目。
    """
    text = str(error or "")
    if not text:
        return False
    return (
        "等待 /api/auth/session accessToken 超时" in text
        and "WARNING_BANNER" in text
        and "'_http_status': 200" in text
    )


def _should_disable_failed_registration_email(error: object) -> bool:
    """需要直接停用邮箱的注册失败类型。"""
    text = str(error or "")
    if not text:
        return False
    return (
        _is_final_session_access_token_timeout(text)
        or "邮箱提交后进入登录密码页" in text
        or "auth.openai.com/log-in/password" in text
        or "/log-in/password" in text
        or "Invalid pickup credentials" in text
        or "INVALID_PICKUP_CREDENTIALS" in text
        or "Share URL 凭证无效" in text
        or "SQ API 凭证无效" in text
        or "Mail.com IMAP 登录失败" in text
        or "Mail.com Web 取码失败 [bad_credentials]" in text
    )


def _should_reuse_failed_registration_email(error: object) -> bool:
    """邮箱 Web 取码的出口/上游故障不能作为邮箱失效证据。"""
    text = str(error or "")
    if "Mail.com Web" not in text:
        return False
    return "[bad_credentials]" not in text and (
        "取码" in text
        or "代理" in text
        or "Web Alias 失败 [blocked]" in text
        or "Web Alias 失败 [network]" in text
        or "Web Alias 失败 [rate_limited]" in text
    )


def _registration_paypal_mode(snapshot: dict | None) -> str:
    value = snapshot.get("paypal") if isinstance(snapshot, dict) else None
    value = value if isinstance(value, dict) else {}
    return str(value.get("mode") or "none").strip().lower()


def _registration_codex_waits_for_plus(snapshot: dict | None) -> bool:
    """Registration-time Codex is a post-PayPal continuation, never a direct step."""
    return bool(isinstance(snapshot, dict) and snapshot.get("codex_oauth")) and (
        _registration_paypal_mode(snapshot) == "extract_and_pay"
    )


def _mark_registration_codex_without_plus(
    *, account_id: int, email: str, job_id: int, message: str,
) -> None:
    account = db.get_account(int(account_id)) or {}
    if not account.get("oauth_requested") or account.get("codex_refresh_token"):
        return
    db.update_account_codex_status(
        email,
        "blocked_no_plus",
        message,
        failure_stage="plus_required",
    )
    db.update_job(
        int(job_id),
        oauth_status="not_connected",
        oauth_error=message[:500],
    )


def _registration_codex_parent_id(job: dict | None) -> int | None:
    """Return the original registration job for an automatic Codex child."""
    if not isinstance(job, dict) or job.get("job_type") not in {"codex_oauth", "codex_retry"}:
        return None
    current = job
    visited: set[int] = set()
    for _ in range(8):
        try:
            parent_id = int(current.get("parent_job_id") or 0)
        except (TypeError, ValueError):
            return None
        if parent_id <= 0 or parent_id in visited:
            return None
        visited.add(parent_id)
        parent = db.get_job(parent_id)
        if not parent:
            return None
        if parent.get("job_type", "registration") == "registration":
            return parent_id
        if parent.get("job_type") not in {"codex_oauth", "codex_retry"}:
            return None
        current = parent
    return None


def _sync_registration_codex_parent(
    job: dict | None, *, status: str, error: str = "",
) -> None:
    parent_id = _registration_codex_parent_id(job)
    if parent_id is None:
        return
    db.update_job(
        parent_id,
        oauth_status=status,
        oauth_error=str(error or "")[:500],
    )


def _codex_email_source(account: dict, email: str, *, mailbox_present: bool | None = None) -> str:
    """Validate that the registered mailbox can still receive Codex OTP mail."""
    from core.email_provider import resolve_email_source

    source = str(account.get("email_source") or "").strip().lower()
    resolved = source or resolve_email_source(email)
    checks = {
        "generic_api": (db.get_generic_api_email_by_email, "找不到关联的取码 URL"),
        "icloud": (db.get_icloud_email_by_email, "找不到关联的 iCloud token"),
        "mailcom": (db.get_mailcom_by_email, "找不到关联的 Mail.com IMAP 凭证"),
    }
    if resolved in checks:
        lookup, error = checks[resolved]
        present = mailbox_present if mailbox_present is not None else lookup(email) is not None
        if not present:
            raise RuntimeError(error)
    return resolved


def continue_registration_codex_after_plus(
    account_id: int, *, recover_interrupted: bool = False,
) -> dict:
    """Idempotently queue registration-time Codex only after confirmed Plus."""
    account = db.get_account(int(account_id)) or {}
    if not account:
        return {"accepted": False, "status": "missing"}
    if not account.get("oauth_requested"):
        return {"accepted": False, "status": "not_requested"}
    if account.get("archived"):
        return {"accepted": False, "status": "archived"}
    if str(account.get("codex_status") or "").strip().lower() == "deactivated":
        return {"accepted": False, "status": "deactivated"}
    if account.get("codex_refresh_token"):
        job_id = account.get("registration_job_id")
        if str(job_id or "").isdigit():
            db.update_job(int(job_id), oauth_status="success", oauth_error="")
        return {"accepted": False, "status": "already_connected"}

    payment_status = str(account.get("paypal_payment_status") or "").strip().lower()
    plan = str(
        account.get("current_plan_type") or account.get("plan_type") or ""
    ).strip().lower()
    if payment_status != "confirmed" or plan != "plus":
        return {"accepted": False, "status": "plus_not_confirmed"}

    try:
        parent_job_id = int(account.get("registration_job_id") or 0)
    except (TypeError, ValueError):
        parent_job_id = 0
    parent = db.get_job(parent_job_id) if parent_job_id > 0 else None
    if not parent or str(parent.get("status") or "").lower() != "success":
        return {"accepted": False, "status": "registration_job_missing"}
    snapshot = parent.get("flow_snapshot") if isinstance(parent.get("flow_snapshot"), dict) else {}
    if not _registration_codex_waits_for_plus(snapshot):
        return {"accepted": False, "status": "not_registration_auto"}

    email = str(account.get("email") or parent.get("email") or "").strip()
    if not email:
        message = "账号邮箱为空，无法执行 Plus 后 Codex 接码"
        db.update_job(parent_job_id, oauth_status="not_connected", oauth_error=message)
        return {"accepted": False, "status": "email_missing", "error": message}
    try:
        source = _codex_email_source(account, email)
    except Exception as exc:
        message = f"邮箱取码不可用: {exc}"
        db.update_account_codex_status(email, "failed", message, failure_stage="oauth")
        db.update_job(parent_job_id, oauth_status="not_connected", oauth_error=message)
        return {"accepted": False, "status": "email_unavailable", "error": message}

    batch_id = str(parent.get("batch_id") or account.get("registration_batch_id") or "") or None
    sms_snapshot = snapshot.get("sms") if isinstance(snapshot.get("sms"), dict) else {}
    with _executor_lock:
        executor = get_codex_executor()
        job, created = db.create_account_codex_job(
            account_id=int(account_id),
            email=email,
            email_source=str(account.get("email_source") or source),
            sms_snapshot=sms_snapshot,
            batch_id=batch_id,
            parent_job_id=parent_job_id,
        )
        if not created:
            status = str(job.get("status") or "").strip().lower()
            if recover_interrupted and job.get("restart_recoverable") is True:
                recovered = db.requeue_restart_interrupted_codex_job(int(job["id"]))
                if recovered is not None:
                    job = recovered
                    created = True
                    status = "pending"
            if not created:
                if status == "success" and account.get("codex_refresh_token"):
                    db.update_job(parent_job_id, oauth_status="success", oauth_error="")
                elif status in {"pending", "running", "stopping"}:
                    parent_status = "running" if status in {"running", "stopping"} else "queued"
                    db.update_job(parent_job_id, oauth_status=parent_status, oauth_error="")
                else:
                    message = str(job.get("error_message") or "Codex 自动接码已执行过")
                    db.update_job(
                        parent_job_id, oauth_status="not_connected", oauth_error=message[:500],
                    )
                return {
                    "accepted": False,
                    "status": "already_queued" if status in {"pending", "running", "stopping"} else "already_attempted",
                    "job": job,
                }

        if not codex_retry_service.reserve(email):
            message = "已有 Codex 补跑占用"
            db.update_job(
                int(job["id"]), status="cancelled", error=message,
                completed_at=datetime.now().isoformat(timespec="seconds"),
            )
            db.update_account_codex_status(email, "failed", message, failure_stage="oauth")
            db.update_job(parent_job_id, oauth_status="not_connected", oauth_error=message)
            return {"accepted": False, "status": "busy", "error": message, "job": job}

        db.update_account_codex_status(email, "queued", None)
        db.update_job(parent_job_id, oauth_status="queued", oauth_error="")
        try:
            executor.submit(
                _run_codex_retry_job, int(job["id"]), job["log_file"], email, int(account_id),
            )
        except Exception as exc:
            codex_retry_service.release(email)
            message = f"Codex 队列提交失败：{type(exc).__name__}: {exc}"[:500]
            db.update_job(
                int(job["id"]), status="failed", error=message,
                completed_at=datetime.now().isoformat(timespec="seconds"),
            )
            db.update_account_codex_status(email, "failed", message, failure_stage="oauth")
            db.update_job(parent_job_id, oauth_status="not_connected", oauth_error=message)
            return {"accepted": False, "status": "queue_failed", "error": message, "job": job}

    logger.info(
        "[Codex] Plus 已确认，注册后自动接码已入队: account=%s email=%s job=%s",
        account_id, email, job["id"],
    )
    return {"accepted": True, "status": "queued", "job": db.get_job(int(job["id"])) or job}


def _enqueue_registration_paypal(
    *, account_id: int, email: str, snapshot: dict, job_id: int, log_logger: logging.Logger,
) -> dict:
    """Queue the selected PP continuation only after a conclusive trial check."""
    paypal_snapshot = snapshot.get("paypal") if isinstance(snapshot.get("paypal"), dict) else {}
    mode = str(paypal_snapshot.get("mode") or "none").strip().lower()
    if mode == "none":
        return {"accepted": False, "status": "disabled"}

    account = db.get_account(int(account_id)) or {}
    plan_status = str(account.get("plan_check_status") or "unchecked").strip().lower()
    plan_type = str(
        account.get("current_plan_type") or account.get("plan_type") or ""
    ).strip().lower()
    trial_status = str(account.get("plus_trial_status") or "").strip().lower()
    eligible = (
        plan_status == "success"
        and plan_type == "free"
        and account.get("plus_trial_eligible") is True
        and account.get("promo_check_ok") is True
        and trial_status == "available"
    )
    if not eligible:
        if plan_status in {"queued", "running", "unchecked", ""}:
            log_logger.info(
                "[Job %s] 注册后 PP 流程等待 0 元 Plus 资格检测: %s status=%s",
                job_id, email, plan_status or "unchecked",
            )
            return {"accepted": False, "status": "waiting_plan_check"}
        if plan_status == "success":
            _mark_registration_codex_without_plus(
                account_id=account_id,
                email=email,
                job_id=job_id,
                message="未确认可用的 0 元 Plus 资格，不执行 Codex 自动接码",
            )
        log_logger.info(
            "[Job %s] 注册后 PP 流程已跳过：账号没有明确可用的 0 元 Plus 资格 "
            "email=%s plan=%s trial=%s check=%s",
            job_id, email, plan_type or "unknown", trial_status or "unknown", plan_status,
        )
        return {"accepted": False, "status": "not_eligible"}

    action = "extract" if mode == "extract" else "extract_and_pay"
    try:
        from core import paypal_service

        queued = paypal_service.enqueue_account_paypal(
            account_id=int(account_id),
            action=action,
            trigger="registration_auto",
            force=False,
            flow_snapshot=paypal_snapshot,
        )
        if queued.get("accepted"):
            log_logger.info(
                "[Job %s] 注册后 PP 流程已立即入队: %s action=%s",
                job_id, email, action,
            )
        else:
            log_logger.warning(
                "[Job %s] PP 流程未入队（不影响注册结果）: %s",
                job_id, queued.get("error") or queued.get("status") or "未知原因",
            )
        return queued
    except Exception as exc:
        log_logger.warning(
            "[Job %s] PP 流程入队异常（不影响注册结果）: %s: %s",
            job_id, type(exc).__name__, str(exc)[:180],
        )
        return {"accepted": False, "status": "error", "error": str(exc)[:180]}


def continue_registration_paypal_after_plan(account_id: int) -> dict:
    """Idempotently continue registration-time PayPal after plan detection."""
    account = db.get_account(int(account_id)) or {}
    if not account:
        return {"accepted": False, "status": "missing"}
    job_id = account.get("registration_job_id")
    if not str(job_id or "").isdigit():
        return {"accepted": False, "status": "no_registration_job"}
    job = db.get_job(int(job_id)) or {}
    if str(job.get("status") or "").strip().lower() != "success":
        return {"accepted": False, "status": "registration_not_complete"}
    snapshot = job.get("flow_snapshot") if isinstance(job.get("flow_snapshot"), dict) else {}
    return _enqueue_registration_paypal(
        account_id=int(account_id),
        email=str(account.get("email") or job.get("email") or ""),
        snapshot=snapshot,
        job_id=int(job_id),
        log_logger=logger,
    )


def _disable_job_email(email: str | None, reason: str) -> bool:
    """把本次任务邮箱停用，避免后续再次领取。"""
    if not email:
        return False
    try:
        from core.email_provider import release_email

        source = release_email(email, status="disabled", note=f"自动停用: {reason[:180]}")
        logger.warning("[Service] 已自动停用邮箱: source=%s email=%s reason=%s", source, email, reason[:220])
        return True
    except Exception:
        logger.exception("[Service] 自动停用邮箱失败: %s", email)
        return False


def _release_reusable_job_email(email: str | None, reason: str) -> bool:
    """资料页明确未创建账号时，在租约结算后把邮箱恢复为可领取。"""
    if not email:
        return False
    try:
        from core.email_provider import release_email

        source = release_email(
            email,
            status="available",
            note=f"账号未创建，邮箱可重试: {reason[:180]}",
        )
        logger.info(
            "[Service] 已恢复可重试邮箱: source=%s email=%s reason=%s",
            source,
            email,
            reason[:220],
        )
        return True
    except Exception:
        logger.exception("[Service] 恢复可重试邮箱失败: %s", email)
        return False


def _normalize_workers(max_workers: int | None) -> int:
    if max_workers is None:
        return _DEFAULT_MAX_WORKERS
    try:
        value = int(max_workers)
    except (TypeError, ValueError):
        value = _DEFAULT_MAX_WORKERS
    return max(_MIN_MAX_WORKERS, min(_MAX_MAX_WORKERS, value))


def get_executor(
    max_workers: int | None = None, pool: str = "registration",
) -> ThreadPoolExecutor:
    """返回指定任务池；默认返回注册专用线程池。

    ``pool="codex"`` 仅作为兼容层把请求转发到 Codex 专用线程池。保留
    这个入口可以让旧的宿主/测试代码继续 monkey-patch ``get_executor``，
    同时确保实际运行时两个池的生命周期和并发计数完全独立。

    旧逻辑只在首次创建线程池时使用 max_workers，后续 WebUI 改线程数再提交仍会复用
    上一次的池。这里改成：每次传入的 max_workers 和当前池不一致时，立即创建新池供
    新提交任务使用；旧池不接收新任务，但会继续把已经排队/运行的任务跑完。
    """
    if str(pool or "registration").strip().lower() == "codex":
        return codex_retry_service.get_executor(max_workers=max_workers)
    if str(pool or "registration").strip().lower() != "registration":
        raise ValueError(f"未知任务池: {pool}")
    global _executor, _executor_workers, _executor_generation
    requested_workers = _normalize_workers(max_workers) if max_workers is not None else _executor_workers
    with _executor_lock:
        if _executor is None or requested_workers != _executor_workers:
            old_executor = _executor
            if old_executor is not None:
                # 不取消旧池里已提交的任务，只是不再往旧池追加新任务。
                old_executor.shutdown(wait=False, cancel_futures=False)
                _retired_executors.append(old_executor)
                logger.info(
                    "[Service] 注册线程池 workers 从 %s 切换为 %s；旧池继续处理已排队任务",
                    _executor_workers,
                    requested_workers,
                )
            _executor_workers = requested_workers
            _executor_generation += 1
            _executor = ThreadPoolExecutor(
                max_workers=requested_workers,
                thread_name_prefix=f"reg-worker-{_executor_generation}",
            )
    return _executor


def get_codex_executor(max_workers: int | None = None) -> ThreadPoolExecutor:
    """返回 OAuth 补 Codex 专用线程池。"""
    return get_executor(max_workers=max_workers, pool="codex")


def get_executor_workers(pool: str = "registration") -> int:
    """返回指定任务池当前新提交任务使用的线程数。"""
    if str(pool or "registration").strip().lower() == "codex":
        return codex_retry_service.get_executor_workers()
    if str(pool or "registration").strip().lower() != "registration":
        raise ValueError(f"未知任务池: {pool}")
    with _executor_lock:
        return _executor_workers


def get_codex_executor_workers() -> int:
    """返回 OAuth 补 Codex 专用线程池的并发数。"""
    return get_executor_workers(pool="codex")


def shutdown_executor(wait: bool = True) -> None:
    global _executor
    with _executor_lock:
        executors = []
        if _executor is not None:
            executors.append(_executor)
            _executor = None
        executors.extend(_retired_executors)
        _retired_executors.clear()
    for ex in executors:
        ex.shutdown(wait=wait, cancel_futures=False)


def shutdown_codex_executor(wait: bool = True) -> None:
    """关闭 OAuth 补 Codex 专用线程池。"""
    codex_retry_service.shutdown_executor(wait=wait)


# ============================================================
# 单任务执行：日志重定向到任务专属文件
# ============================================================

class _JobLogContext:
    """让本线程的根 logger 多一个 FileHandler，结束后移除。"""

    def __init__(self, log_path: str):
        self.log_path = log_path
        self.handler: logging.FileHandler | None = None

    def __enter__(self):
        Path(self.log_path).parent.mkdir(parents=True, exist_ok=True)
        self.handler = logging.FileHandler(self.log_path, encoding="utf-8")
        self.handler.setLevel(logging.INFO)
        self.handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        # 仅给本线程过滤 —— 用 thread name 做区分，避免污染其他任务的日志
        thread_name = threading.current_thread().name
        self.handler.addFilter(lambda r: r.threadName == thread_name)
        logging.getLogger().addHandler(self.handler)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.handler is not None:
            self.handler.close()
            logging.getLogger().removeHandler(self.handler)


def _run_one_job(job_id: int, log_file: str) -> None:
    """单任务入口（线程池里跑这个）。"""
    log_logger = logging.getLogger(__name__)
    _activate_job(job_id)

    # 取消检查：用户可能在任务排队期间点了"取消排队"，把 status 改成了 cancelled。
    # 因为 Future 已经 submit 进线程池无法撤回，只能在真正执行前自检一下，跳过 cancelled 的。
    current = db.get_job(job_id)
    if not current:
        log_logger.info(f"[Job {job_id}] 任务记录已删除，跳过执行")
        _deactivate_job(job_id)
        return
    if current.get("status") == "cancelled":
        log_logger.info(f"[Job {job_id}] 已被用户取消，跳过执行")
        _deactivate_job(job_id)
        return

    email: str | None = None
    try:
        db.update_job(job_id, status="running", started_at=datetime.now().isoformat(timespec="seconds"))
        with _JobLogContext(log_file):
            from main import run_registration
            log_logger.info(f"[Job {job_id}] 开始注册任务")
            current_job = db.get_job(job_id) or current
            snapshot = current_job.get("flow_snapshot") if isinstance(current_job.get("flow_snapshot"), dict) else {}
            prepare_started = perf_counter()
            check_stop_requested()
            email, name, birthday = _prepare_registration_args(current_job)
            db.update_job(job_id, email=email)
            log_logger.info("[Job %s] 参数准备及邮箱分配耗时 %.3fs", job_id, perf_counter() - prepare_started)
            check_stop_requested()
            result = run_registration(
                email=email,
                name=name,
                birthday=birthday,
                registration_driver=str(snapshot.get("registration_driver") or "protocol"),
                protocol_mode=str(snapshot.get("protocol_mode") or "next"),
                codex_oauth=False,
                job_id=job_id,
            )
            if is_stop_requested(job_id):
                result_ok = isinstance(result, dict) and result.get("success") and result.get("account_id") is not None
                if result_ok:
                    account_id = int(result["account_id"])
                    result_email = str(result.get("email") or email)
                    allocation = db.get_email_allocation_by_actual_email(result_email)
                    db.update_account_registration_context(
                        account_id,
                        registration_driver=str(snapshot.get("registration_driver") or "protocol"),
                        registration_job_id=job_id,
                        registration_batch_id=str(current_job.get("batch_id") or "") or None,
                        email_allocation_id=(allocation or {}).get("id"),
                        oauth_requested=bool(snapshot.get("codex_oauth")),
                    )
                    db.complete_email_allocation(
                        result_email,
                        account_id=account_id,
                        status="registered",
                    )
                    db.update_job(
                        job_id,
                        status="stopped",
                        email=result_email,
                        account_id=account_id,
                        email_allocation_id=(allocation or {}).get("id"),
                        oauth_status="not_connected",
                        oauth_error="用户手动停止，未执行 Codex OAuth",
                        error="用户手动停止",
                        completed_at=datetime.now().isoformat(timespec="seconds"),
                    )
                else:
                    result_email = str(
                        ((result or {}).get("email") if isinstance(result, dict) else email)
                        or email
                        or ""
                    ).strip()
                    email_consumed = bool(
                        isinstance(result, dict) and result.get("email_consumed")
                    )
                    db.complete_email_allocation(
                        result_email,
                        status="failed",
                        error="用户手动停止",
                    )
                    if email_consumed:
                        _disable_job_email(result_email, "用户手动停止（邮箱验证码已通过）")
                    else:
                        _release_unconsumed_job_email(result_email, "用户手动停止")
                    db.update_job(
                        job_id,
                        status="stopped",
                        email=result_email,
                        error="用户手动停止",
                        completed_at=datetime.now().isoformat(timespec="seconds"),
                    )
                log_logger.warning(f"[Job {job_id}] 已按用户请求停止")
                return
            if isinstance(result, dict) and result.get("success"):
                account_id = int(result.get("account_id"))
                allocation = db.get_email_allocation_by_actual_email(str(result.get("email") or email))
                db.update_account_registration_context(
                    account_id,
                    registration_driver=str(snapshot.get("registration_driver") or "protocol"),
                    registration_job_id=job_id,
                    registration_batch_id=str(current_job.get("batch_id") or "") or None,
                    email_allocation_id=(allocation or {}).get("id"),
                    oauth_requested=bool(snapshot.get("codex_oauth")),
                )

                oauth_result = {"status": "skipped", "ok": False, "message": "未选择接码"}
                if bool(snapshot.get("codex_oauth")):
                    if _registration_codex_waits_for_plus(snapshot):
                        oauth_result = {
                            "status": "waiting_plus",
                            "ok": False,
                            "message": "等待 PayPal 授权并确认 Plus 后自动执行 Codex 接码",
                        }
                        db.update_account_codex_status(email, "waiting_plus", None)
                        db.update_job(
                            job_id,
                            oauth_status="waiting_plus",
                            oauth_error="",
                        )
                    else:
                        oauth_result = {
                            "status": "blocked_config",
                            "ok": False,
                            "message": "注册自动 Codex 接码必须配置 PayPal 提链并支付",
                        }
                        db.update_account_codex_status(
                            email,
                            "blocked_config",
                            oauth_result["message"],
                            failure_stage="plus_required",
                        )
                        db.update_job(
                            job_id,
                            oauth_status="not_connected",
                            oauth_error=oauth_result["message"],
                        )
                else:
                    db.update_account_codex_status(email, "skipped", None)
                    db.update_job(job_id, oauth_status="not_connected", oauth_error="")

                db.complete_email_allocation(
                    str(result.get("email") or email),
                    account_id=account_id,
                    status="registered",
                )
                db.update_job(
                    job_id,
                    status="success",
                    email=result.get("email"),
                    account_id=account_id,
                    email_allocation_id=(allocation or {}).get("id"),
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                log_logger.info(
                    "[Job %s] 基础注册成功: %s, Codex=%s",
                    job_id, result.get("email"), oauth_result.get("status"),
                )
                _enqueue_registration_paypal(
                    account_id=account_id,
                    email=str(result.get("email") or email),
                    snapshot=snapshot,
                    job_id=job_id,
                    log_logger=log_logger,
                )
            else:
                # 注意：失败也可能伴随 account_id（如 Codex 失败但账号已注册成功）
                err = _registration_failure_text(result)
                result_email = (result or {}).get("email") if isinstance(result, dict) else None
                db.update_job(
                    job_id,
                    status="failed",
                    email=result_email,
                    account_id=(result or {}).get("account_id") if isinstance(result, dict) else None,
                    error=str(err)[:500],
                    completed_at=datetime.now().isoformat(timespec="seconds"),
                )
                email_to_handle = str(result_email or email or "").strip()
                db.complete_email_allocation(email_to_handle, status="failed", error=str(err)[:500])
                email_consumed = bool(
                    isinstance(result, dict) and result.get("email_consumed")
                )
                email_reusable = bool(
                    isinstance(result, dict) and result.get("email_reusable")
                )
                if email_reusable or _should_reuse_failed_registration_email(err):
                    _release_reusable_job_email(email_to_handle, str(err))
                elif email_consumed or _should_disable_failed_registration_email(err):
                    _disable_job_email(email_to_handle, str(err))
                else:
                    _release_unconsumed_job_email(email_to_handle, str(err))
                log_logger.error(f"[Job {job_id}] 失败: {err}")
    except StopRequested as exc:
        db.complete_email_allocation(str(email or ""), status="failed", error=str(exc))
        _release_unconsumed_job_email(email, str(exc))
        log_logger.warning(f"[Job {job_id}] 已停止: {exc}")
        db.update_job(
            job_id,
            status="stopped",
            error="用户手动停止",
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
    except Exception as exc:
        err_text = f"{type(exc).__name__}: {exc}"
        db.complete_email_allocation(str(email or ""), status="failed", error=err_text[:500])
        if _should_reuse_failed_registration_email(err_text):
            _release_reusable_job_email(email, err_text)
        elif _should_disable_failed_registration_email(err_text):
            _disable_job_email(email, err_text)
        else:
            _release_unconsumed_job_email(email, err_text)
        if is_stop_requested(job_id):
            log_logger.warning(f"[Job {job_id}] 停止中捕获异常，按停止处理: {type(exc).__name__}: {exc}")
            db.update_job(
                job_id,
                status="stopped",
                error="用户手动停止",
                completed_at=datetime.now().isoformat(timespec="seconds"),
            )
            return
        log_logger.exception(f"[Job {job_id}] 异常")
        db.update_job(
            job_id,
            status="failed",
            error=f"{type(exc).__name__}: {exc}"[:500],
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
    finally:
        _deactivate_job(job_id)


def _run_codex_retry_job(job_id: int, log_file: str, email: str, account_id: int) -> None:
    """把 Codex 补跑作为标准任务执行，并复用任务状态、日志和停止入口。"""
    _activate_job(job_id)
    current = None
    try:
        current = db.get_job(job_id)
        if not current or current.get("status") == "cancelled":
            _sync_registration_codex_parent(
                current, status="not_connected", error="Codex 子任务已取消",
            )
            codex_retry_service.release(email)
            return
        db.update_job(job_id, status="running", started_at=datetime.now().isoformat(timespec="seconds"))
        _sync_registration_codex_parent(current, status="running", error="")
        snapshot = current.get("flow_snapshot") if isinstance(current.get("flow_snapshot"), dict) else {}
        login_mode = str(snapshot.get("codex_login_mode") or "email_otp")
        budget_error = (
            db.get_batch_sms_budget_error(current.get("batch_id"))
            if login_mode == "email_otp" else None
        )
        if budget_error:
            result = {
                "status": "failed",
                "ok": False,
                "failure_stage": "sms_budget",
                "message": f"批次短信预算已耗尽，跳过接码：{budget_error}"[:1000],
            }
            db.update_account_codex_result(email, result)
            codex_retry_service.release(email)
            _append_job_log(job_id, result["message"])
        else:
            result = codex_retry_service.run_worker(
                email,
                clear_log=False,
                **({"expected_workspace_id": snapshot["expected_workspace_id"]} if snapshot.get("expected_workspace_id") else {}),
                target_log_path=log_file,
                sms_options={
                    **dict(snapshot.get("sms") or {}),
                    "batch_id": current.get("batch_id"),
                    "job_id": job_id,
                },
                **({"login_mode": login_mode} if login_mode != "email_otp" else {}),
                **({"oauth_auto_retry": False} if snapshot.get("team_authorization") else {}),
            )
        now_iso = datetime.now().isoformat(timespec="seconds")
        if is_stop_requested(job_id) or result.get("status") == "stopped":
            message = str(result.get("message") or "用户手动停止")[:500]
            db.update_job(job_id, status="stopped", email=email, account_id=account_id, error=message, completed_at=now_iso)
            _sync_registration_codex_parent(current, status="not_connected", error=message)
        elif result.get("ok"):
            authorization_fields = {}
            if snapshot.get("team_authorization"):
                from core.codex_plan import credential_summary
                authorization_fields["codex_authorization"] = credential_summary(result.get("credential") or {})
            db.update_job(
                job_id,
                status="success",
                email=email,
                account_id=account_id,
                completed_at=now_iso,
                **authorization_fields,
            )
            _sync_registration_codex_parent(current, status="success", error="")
        else:
            message = str(result.get("message") or "Codex 补跑失败")[:500]
            db.update_job(
                job_id,
                status="failed",
                email=email,
                account_id=account_id,
                error=message,
                completed_at=now_iso,
            )
            _sync_registration_codex_parent(current, status="not_connected", error=message)
    except Exception as exc:
        message = f"{type(exc).__name__}: {exc}"[:500]
        try:
            db.update_job(
                job_id,
                status="failed",
                error=message,
                completed_at=datetime.now().isoformat(timespec="seconds"),
            )
            _sync_registration_codex_parent(current, status="not_connected", error=message)
        finally:
            codex_retry_service.release(email)
            logger.exception("[Job %s] Codex 补跑异常", job_id)
    finally:
        _deactivate_job(job_id)


def submit_account_codex_oauth(
    account_ids: list[int], *, workers: int | None = None, sms: dict | None = None,
    login_mode: str = "email_otp", expected_workspace_id: str = "",
    team_authorization: bool = False,
) -> dict:
    """把已有账号的补接码加入标准任务队列。"""
    if login_mode not in {"email_otp", "password_totp"}:
        raise ValueError("不支持的 Codex 登录模式")
    if team_authorization and login_mode != "password_totp":
        raise ValueError("Team 授权需要密码 + 2FA 登录")
    ids: list[int] = []
    seen: set[int] = set()
    for raw in account_ids or []:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            continue
        if value not in seen:
            seen.add(value)
            ids.append(value)
    if not ids:
        raise ValueError("account_ids 必须是非空整数数组")

    # 已有账号补跑固定走协议流程，只补 Codex OAuth，不再新建邮箱
    snapshot = _registration_flow_snapshot(
        registration_driver="protocol",
        codex_oauth=True,
        email_mode="single",
        alias_limit=None,
        sms=sms,
    )
    if login_mode != "email_otp":
        snapshot["codex_login_mode"] = login_mode
    if expected_workspace_id:
        snapshot["expected_workspace_id"] = expected_workspace_id
    if team_authorization:
        snapshot["team_authorization"] = True
    submitted = []
    skipped = []
    accounts = db.get_account_supplement_candidates(ids)
    mailbox_presence = db.codex_mailbox_presence(list(accounts.values())) if login_mode == "email_otp" else {}
    candidates = []
    for account_id in ids:
        account = accounts.get(account_id)
        if account is None:
            skipped.append({"id": account_id, "reason": "账号不存在"})
            continue
        email = account["email"]
        reason = (
            "已有 Codex RT" if (login_mode == "email_otp" and account["has_codex_refresh_token"]
                and (not expected_workspace_id or account.get("codex_workspace_id") == expected_workspace_id)) else
            "账号已废号" if str(account.get("codex_status") or "").lower() == "deactivated" else
            "账号邮箱为空" if not email else None
        )
        if reason:
            skipped.append({"id": account_id, "email": email, "reason": reason})
            continue
        try:
            source = (
                _codex_email_source(account, email, mailbox_present=mailbox_presence.get(account_id))
                if login_mode == "email_otp" else str(account.get("email_source") or "existing_account")
            )
        except Exception as exc:
            skipped.append({"id": account_id, "email": email, "reason": f"邮箱取码不可用: {exc}"})
            continue
        candidates.append({"id": account_id, "email": email, "email_source": str(account.get("email_source") or source)})

    # This admission lock is separate from registration's executor lock. No
    # network work or future waits occur here; workers keep independent pools.
    with _codex_submission_lock:
        executor = get_codex_executor(max_workers=workers)
        effective_workers = get_codex_executor_workers()
        batch = db.create_registration_batch(
            count=len(ids),
            workers=effective_workers,
            email_source="existing_account",
            flow_snapshot=snapshot,
        )
        try:
            prepared = db.create_account_codex_jobs_bulk(
                candidates, sms_snapshot=snapshot["sms"], batch_id=batch["batch_id"],
                **({"team_authorization": True} if team_authorization else {}),
                **({"expected_workspace_id": expected_workspace_id} if expected_workspace_id else {}),
                **({"login_mode": login_mode} if login_mode != "email_otp" else {}),
            )
        except Exception:
            db.delete_registration_batch_if_orphan(str(batch["batch_id"]))
            raise
        skipped.extend(prepared["skipped"])
        pending = {job["id"]: job for job in prepared["created"]}
        held = {}
        failures = []
        try:
            for job in prepared["created"]:
                if codex_retry_service.reserve(job["email"]):
                    held[job["id"]] = job
                else:
                    failures.append({"id": job["id"], "status": "cancelled", "error": "已有 Codex 补跑占用"})
                    skipped.append({"id": job["account_id"], "email": job["email"], "reason": "已有 Codex 补跑占用"})
            db.update_account_codex_statuses_bulk([
                {"account_id": job["account_id"], "email": job["email"], "status": "queued"}
                for job in held.values()
            ])
            rejected_accounts = []
            for job in list(held.values()):
                try:
                    executor.submit(_run_codex_retry_job, job["id"], job["log_file"], job["email"], job["account_id"])
                except Exception as exc:
                    codex_retry_service.release(job["email"])
                    del held[job["id"]]
                    failures.append({"id": job["id"], "status": "failed", "error": "队列提交失败"})
                    rejected_accounts.append({"account_id": job["account_id"], "email": job["email"], "status": "failed", "error": "队列提交失败"})
                    skipped.append({"id": job["account_id"], "email": job["email"], "reason": "队列提交失败"})
                    logger.warning("[Codex] 批量提交失败: job_id=%s error=%s", job["id"], type(exc).__name__)
                else:
                    # From this point the worker owns its reservation/state.
                    del held[job["id"]]
                    del pending[job["id"]]
                    submitted.append(job)
            if failures:
                now = datetime.now().isoformat(timespec="seconds")
                db.update_jobs_bulk([{**item, "completed_at": now} for item in failures])
            db.update_account_codex_statuses_bulk(rejected_accounts)
        except BaseException:
            for job in held.values():
                codex_retry_service.release(job["email"])
            if pending:
                db.update_jobs_bulk([
                    {"id": job["id"], "status": "failed", "error": "批量入队中断", "completed_at": datetime.now().isoformat(timespec="seconds")}
                    for job in pending.values()
                ])
                db.update_account_codex_statuses_bulk([
                    {"account_id": job["account_id"], "email": job["email"], "status": "failed", "error": "批量入队中断"}
                    for job in held.values()
                ])
            raise
    response_batch_id = str(batch["batch_id"])
    if not submitted and db.delete_registration_batch_if_orphan(response_batch_id):
        response_batch_id = None
    return {
        "submitted": submitted,
        "skipped": skipped,
        "workers": get_codex_executor_workers(),
        "batch_id": response_batch_id,
    }


def _registration_flow_snapshot(
    *,
    registration_driver: str | None,
    codex_oauth: bool | None,
    email_mode: str | None,
    alias_limit: int | None,
    sms: dict | None,
    protocol_mode: str | None = None,
    paypal_mode: str | None = None,
) -> dict:
    from config import codex as codex_cfg
    from config import paypal as paypal_cfg
    from config import roxybrowser as roxy_cfg
    from core.paypal_proxy_pool import pool_snapshot

    driver = str(registration_driver or getattr(roxy_cfg, "REGISTRATION_DRIVER", "protocol") or "protocol").strip().lower()
    aliases = {
        "api": "protocol", "http": "protocol", "roxybrowser": "roxy", "cloakbrowser": "cloak",
        "browseruse": "browser_use", "browser-use": "browser_use", "sv": "skyvern",
        "local": "local_browser", "local-browser": "local_browser", "chromium": "local_browser", "rod": "local_browser",
    }
    driver = aliases.get(driver, driver)
    if driver not in {"protocol", "local_browser", "roxy", "cloak", "browser_use", "skyvern"}:
        raise ValueError("registration_driver 非法")
    selected_protocol_mode = str(protocol_mode or "next").strip().lower()
    protocol_aliases = {
        "nextauth": "next", "web": "next", "web_nextauth": "next",
        "platform": "oauth", "platform_oauth": "oauth", "passwordless": "oauth",
    }
    selected_protocol_mode = protocol_aliases.get(
        selected_protocol_mode, selected_protocol_mode
    )
    if selected_protocol_mode not in {"next", "oauth"}:
        raise ValueError("protocol_mode 仅支持 next / oauth")
    mode = str(email_mode or "single").strip().lower()
    if mode not in {"single", "plus_alias"}:
        raise ValueError("email_mode 仅支持 single / plus_alias")
    if mode == "plus_alias":
        try:
            alias_limit = int(alias_limit or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("alias_limit 必须是正整数") from exc
        if alias_limit <= 0:
            raise ValueError("alias_limit 必须是正整数")
    else:
        alias_limit = None

    selected_paypal_mode = str(
        paypal_mode
        if paypal_mode is not None
        else getattr(paypal_cfg, "PAYPAL_DEFAULT_MODE", "none")
    ).strip().lower()
    paypal_aliases = {
        "off": "none", "false": "none", "link": "extract",
        "extract_only": "extract", "pay": "extract_and_pay",
        "full": "extract_and_pay",
    }
    selected_paypal_mode = paypal_aliases.get(selected_paypal_mode, selected_paypal_mode)
    if selected_paypal_mode not in {"none", "extract", "extract_and_pay"}:
        raise ValueError("paypal_mode 仅支持 none / extract / extract_and_pay")

    promo_strategy = str(
        getattr(paypal_cfg, "PAYPAL_STRIPE_PROMO_STRATEGY", "post_update")
        or "post_update"
    ).strip().lower()
    if promo_strategy not in {"upfront", "post_update"}:
        raise ValueError("PAYPAL_STRIPE_PROMO_STRATEGY 仅支持 upfront / post_update")
    paypal_buyer_mode = str(
        getattr(paypal_cfg, "PAYPAL_BUYER_MODE", "identity_elevation")
        or "identity_elevation"
    ).strip().lower()
    if paypal_buyer_mode not in {"original", "identity_elevation"}:
        raise ValueError("PAYPAL_BUYER_MODE 仅支持 original / identity_elevation")
    paypal_payment_executor = str(
        getattr(paypal_cfg, "PAYPAL_PAYMENT_EXECUTOR", "local") or "local"
    ).strip().lower()
    if paypal_payment_executor not in {"local", "remote"}:
        raise ValueError("PAYPAL_PAYMENT_EXECUTOR 仅支持 local / remote")
    paypal_phone = str(getattr(paypal_cfg, "PAYPAL_PAYMENT_PHONE", "") or "").strip()
    paypal_sms_mode = str(
        getattr(paypal_cfg, "PAYPAL_SMS_MODE", "manual") or "manual"
    ).strip().lower()
    if paypal_sms_mode not in {"manual", "auto"}:
        raise ValueError("PAYPAL_SMS_MODE 仅支持 manual / auto")
    paypal_sms_snapshot = {
        "mode": paypal_sms_mode,
        "channels": str(getattr(paypal_cfg, "PAYPAL_SMS_CHANNELS", "herosms") or "herosms"),
        "max_retries": getattr(paypal_cfg, "PAYPAL_SMS_MAX_RETRIES", 3),
        "herosms": {
            "handler_url": str(getattr(
                paypal_cfg, "PAYPAL_HEROSMS_HANDLER_URL",
                "https://hero-sms.com/stubs/handler_api.php",
            ) or ""),
            "api_key": str(getattr(paypal_cfg, "PAYPAL_HEROSMS_API_KEY", "") or ""),
            "country_id": str(getattr(
                paypal_cfg, "PAYPAL_HEROSMS_COUNTRY_ID", "16",
            ) or "16"),
            "service": str(getattr(paypal_cfg, "PAYPAL_HEROSMS_SERVICE", "ts") or "ts"),
            "max_price": getattr(paypal_cfg, "PAYPAL_HEROSMS_MAX_PRICE", 0.2),
            "operator": str(getattr(paypal_cfg, "PAYPAL_HEROSMS_OPERATOR", "") or ""),
            "fixed_price": str(getattr(
                paypal_cfg, "PAYPAL_HEROSMS_FIXED_PRICE", "",
            ) or ""),
            "phone_exception": str(getattr(
                paypal_cfg, "PAYPAL_HEROSMS_PHONE_EXCEPTION", "",
            ) or ""),
            "code_wait": getattr(paypal_cfg, "PAYPAL_HEROSMS_CODE_WAIT", 120),
            "poll_interval": getattr(paypal_cfg, "PAYPAL_HEROSMS_POLL_INTERVAL", 5),
            "request_timeout": getattr(
                paypal_cfg, "PAYPAL_HEROSMS_REQUEST_TIMEOUT", 20,
            ),
            "proxy": str(getattr(paypal_cfg, "PAYPAL_HEROSMS_PROXY", "") or ""),
        },
        "smsbower": {
            "handler_url": str(getattr(
                paypal_cfg, "PAYPAL_SMSBOWER_HANDLER_URL",
                "https://smsbower.page/stubs/handler_api.php",
            ) or ""),
            "api_key": str(getattr(paypal_cfg, "PAYPAL_SMSBOWER_API_KEY", "") or ""),
            "country_id": str(getattr(paypal_cfg, "PAYPAL_SMSBOWER_COUNTRY_ID", "16") or "16"),
            "service": str(getattr(paypal_cfg, "PAYPAL_SMSBOWER_SERVICE", "ts") or "ts"),
            "min_price": getattr(paypal_cfg, "PAYPAL_SMSBOWER_MIN_PRICE", 0.07),
            "max_price": getattr(paypal_cfg, "PAYPAL_SMSBOWER_MAX_PRICE", 0.2),
            "code_wait": getattr(paypal_cfg, "PAYPAL_SMSBOWER_CODE_WAIT", 120),
            "poll_interval": getattr(paypal_cfg, "PAYPAL_SMSBOWER_POLL_INTERVAL", 5),
            "request_timeout": getattr(paypal_cfg, "PAYPAL_SMSBOWER_REQUEST_TIMEOUT", 20),
            "proxy": str(getattr(paypal_cfg, "PAYPAL_SMSBOWER_PROXY", "") or ""),
        },
        "luban": {
            "api_base": str(getattr(paypal_cfg, "PAYPAL_LUBAN_API_BASE", "https://lubansms.com/v2/api") or ""),
            "api_key": str(getattr(paypal_cfg, "PAYPAL_LUBAN_API_KEY", "") or ""),
            "country": str(getattr(paypal_cfg, "PAYPAL_LUBAN_COUNTRY", "Brazil") or "Brazil"),
            "service": str(getattr(paypal_cfg, "PAYPAL_LUBAN_SERVICE", "PayPal") or "PayPal"),
            "providers": str(getattr(paypal_cfg, "PAYPAL_LUBAN_PROVIDERS", "") or ""),
            "service_ids": str(getattr(paypal_cfg, "PAYPAL_LUBAN_SERVICE_IDS", "") or ""),
            "max_price": getattr(paypal_cfg, "PAYPAL_LUBAN_MAX_PRICE", ""),
            "max_attempts": getattr(paypal_cfg, "PAYPAL_LUBAN_MAX_ATTEMPTS", 3),
            "list_max_pages": getattr(paypal_cfg, "PAYPAL_LUBAN_LIST_MAX_PAGES", 5),
            "code_wait": getattr(paypal_cfg, "PAYPAL_LUBAN_CODE_WAIT", 120),
            "poll_interval": getattr(paypal_cfg, "PAYPAL_LUBAN_POLL_INTERVAL", 5),
            "request_timeout": getattr(paypal_cfg, "PAYPAL_LUBAN_REQUEST_TIMEOUT", 20),
            "proxy": str(getattr(paypal_cfg, "PAYPAL_LUBAN_PROXY", "") or ""),
        },
    }
    paypal_payment_country = str(
        getattr(paypal_cfg, "PAYPAL_PAYMENT_COUNTRY", "US") or "US"
    ).upper()
    if not paypal_phone and paypal_sms_mode == "auto":
        from core.paypal_sms import resolve_channel_country

        _, paypal_payment_country, _ = resolve_channel_country(paypal_sms_snapshot)
    paypal_snapshot = {
        "mode": selected_paypal_mode,
        "requested_mode": "stripe",
        "promo_strategy": promo_strategy,
        "promo_id": str(getattr(paypal_cfg, "PAYPAL_PROMO_ID", "plus-1-month-free") or "plus-1-month-free"),
        "extract_country": str(getattr(paypal_cfg, "PAYPAL_EXTRACT_COUNTRY", "BR") or "BR").upper(),
        "billing_country": str(getattr(paypal_cfg, "PAYPAL_BILLING_COUNTRY", "DE") or "DE").upper(),
        "payment_country": paypal_payment_country,
        "buyer_mode": paypal_buyer_mode,
        "payment_executor": paypal_payment_executor,
        "remote_api_base": str(getattr(
            paypal_cfg, "PAYPAL_REMOTE_API_BASE",
            "https://paypal.173.249.205.56.sslip.io/paypal-pay/api",
        ) or ""),
        "remote_poll_interval": getattr(paypal_cfg, "PAYPAL_REMOTE_POLL_INTERVAL", 1.0),
        "remote_job_timeout": getattr(paypal_cfg, "PAYPAL_REMOTE_JOB_TIMEOUT", 600),
        "phone": paypal_phone,
        "sms": paypal_sms_snapshot,
        "request_timeout": getattr(paypal_cfg, "PAYPAL_REQUEST_TIMEOUT", 30),
        "checkout_attempts": getattr(paypal_cfg, "PAYPAL_CHECKOUT_MAX_ATTEMPTS", 5),
        "extract_attempts": getattr(paypal_cfg, "PAYPAL_EXTRACT_MAX_ATTEMPTS", 3),
        "payment_attempts": getattr(paypal_cfg, "PAYPAL_PAYMENT_MAX_ATTEMPTS", 2),
        "retry_interval": getattr(paypal_cfg, "PAYPAL_RETRY_INTERVAL", 1.0),
        "verify_delays": getattr(paypal_cfg, "PAYPAL_PLUS_VERIFY_DELAYS", "5,30,120"),
        "extract_pool": pool_snapshot("extract"),
        "payment_pool": pool_snapshot("payment"),
    }

    overrides = dict(sms or {})
    codex_sms_provider = str(
        getattr(codex_cfg, "SMS_PROVIDER", "smsbower") or "smsbower"
    ).strip().lower()
    if codex_sms_provider == "luban":
        codex_sms_service = str(
            getattr(codex_cfg, "SMS_LUBAN_SERVICE", "OpenAI") or "OpenAI"
        ).strip()
        codex_sms_country = str(
            getattr(codex_cfg, "SMS_LUBAN_COUNTRY", "") or ""
        ).strip() or str(
            getattr(paypal_cfg, "PAYPAL_LUBAN_COUNTRY", "England") or "England"
        ).strip()
        codex_sms_api_key = str(getattr(paypal_cfg, "PAYPAL_LUBAN_API_KEY", "") or "")
        codex_sms_handler_url = ""
    elif codex_sms_provider in {"herosms", "hero_sms", "hero"}:
        codex_sms_service = str(
            getattr(codex_cfg, "HEROSMS_SERVICE", "dr") or "dr"
        ).strip()
        codex_sms_country = str(
            getattr(codex_cfg, "HEROSMS_COUNTRY", "") or ""
        ).strip() or str(
            getattr(codex_cfg, "SMS_COUNTRY", "") or ""
        ).strip()
        codex_sms_api_key = str(getattr(codex_cfg, "HEROSMS_API_KEY", "") or "")
        codex_sms_handler_url = str(
            getattr(
                codex_cfg,
                "HEROSMS_HANDLER_URL",
                "https://hero-sms.com/stubs/handler_api.php",
            )
            or ""
        )
    else:
        codex_sms_service = str(getattr(codex_cfg, "SMS_SERVICE", "dr") or "dr")
        codex_sms_country = str(getattr(codex_cfg, "SMS_COUNTRY", "") or "")
        codex_sms_api_key = str(getattr(codex_cfg, "SMSBOWER_API_KEY", "") or "")
        codex_sms_handler_url = str(getattr(codex_cfg, "SMSBOWER_HANDLER_URL", "") or "")
    sms_snapshot = {
        "provider": codex_sms_provider,
        "service": codex_sms_service,
        "country": str(overrides.get("country", codex_sms_country) or ""),
        "max_price": overrides.get("max_price", getattr(codex_cfg, "SMS_MAX_PRICE", "")),
        "budget": overrides.get("budget", getattr(codex_cfg, "SMSBOWER_TASK_BUDGET", "")),
        "max_retries": overrides.get("max_retries", getattr(codex_cfg, "SMS_MAX_RETRIES", 10)),
        "code_wait": getattr(codex_cfg, "SMS_CODE_WAIT", 120),
        "poll_interval": getattr(codex_cfg, "SMS_POLL_INTERVAL", 5),
        "api_key": codex_sms_api_key,
        "handler_url": codex_sms_handler_url,
    }
    if codex_sms_provider == "luban":
        sms_snapshot.update({
            "api_base": str(getattr(paypal_cfg, "PAYPAL_LUBAN_API_BASE", "") or ""),
            "service_aliases": str(getattr(
                codex_cfg,
                "SMS_LUBAN_SERVICE_ALIASES",
                "OpenAI,OpenAI / ChatGPT,OpenAI / ChatGpt,ChatGPT | OpenAI,OpenAI/ChatGPT",
            ) or ""),
            "providers": str(
                getattr(codex_cfg, "SMS_LUBAN_PROVIDERS", "") or ""
            ).strip() or str(getattr(paypal_cfg, "PAYPAL_LUBAN_PROVIDERS", "") or ""),
            "service_ids": str(getattr(codex_cfg, "SMS_LUBAN_SERVICE_IDS", "") or ""),
            "max_attempts": getattr(paypal_cfg, "PAYPAL_LUBAN_MAX_ATTEMPTS", 3),
            "list_max_pages": getattr(paypal_cfg, "PAYPAL_LUBAN_LIST_MAX_PAGES", 5),
            "request_timeout": getattr(paypal_cfg, "PAYPAL_LUBAN_REQUEST_TIMEOUT", 20),
            "proxy": str(getattr(paypal_cfg, "PAYPAL_LUBAN_PROXY", "") or ""),
        })
    elif codex_sms_provider in {"herosms", "hero_sms", "hero"}:
        sms_snapshot.update({
            "operator": str(getattr(codex_cfg, "HEROSMS_OPERATOR", "") or ""),
            "fixed_price": str(
                getattr(codex_cfg, "HEROSMS_FIXED_PRICE", "") or ""
            ),
            "phone_exception": str(
                getattr(codex_cfg, "HEROSMS_PHONE_EXCEPTION", "") or ""
            ),
            "request_timeout": getattr(codex_cfg, "HEROSMS_REQUEST_TIMEOUT", 30),
            "proxy": str(getattr(codex_cfg, "HEROSMS_PROXY", "") or ""),
        })

    try:
        sms_snapshot["max_retries"] = int(sms_snapshot["max_retries"])
    except (TypeError, ValueError) as exc:
        raise ValueError("sms.max_retries 必须是正整数") from exc
    if sms_snapshot["max_retries"] <= 0:
        raise ValueError("sms.max_retries 必须是正整数")

    for key in ("max_price", "budget"):
        if sms_snapshot[key] not in (None, ""):
            try:
                value = float(sms_snapshot[key])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"sms.{key} 必须是非负数字") from exc
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"sms.{key} 必须是非负数字")
            sms_snapshot[key] = value

    return {
        "registration_driver": driver,
        "protocol_mode": selected_protocol_mode,
        "codex_oauth": bool(getattr(codex_cfg, "ENABLE_CODEX_AUTO", False)) if codex_oauth is None else bool(codex_oauth),
        "email_mode": mode,
        "alias_limit": alias_limit,
        "sms": sms_snapshot,
        "paypal": paypal_snapshot,
    }


# ============================================================
# 公共接口
# ============================================================

def submit_registration(
    count: int = 1,
    email_source: str | None = None,
    workers: int | None = None,
    *,
    registration_driver: str | None = None,
    codex_oauth: bool | None = None,
    email_mode: str | None = "single",
    alias_limit: int | None = None,
    sms: dict | None = None,
    protocol_mode: str | None = None,
    paypal_mode: str | None = None,
) -> list[dict]:
    """
    创建 N 个注册任务并提交到线程池。
    email_source 记录到 DB；实际地址由统一 EmailProvider 按来源领取，
    Fastmail 为 Token + Web Cookie 动态普通 Alias，LOF 为固定域名随机地址；两者都不产生本地邮箱池记录。

    Returns:
        N 个新创建的 job dict
    """
    try:
        count = int(count)
    except (TypeError, ValueError) as exc:
        raise ValueError("count 必须是正整数") from exc
    if count <= 0:
        raise ValueError("count 必须是正整数")
    if email_source is None:
        from config import email as _email_cfg
        email_source = _email_cfg.EMAIL_SOURCE

    snapshot = _registration_flow_snapshot(
        registration_driver=registration_driver,
        codex_oauth=codex_oauth,
        email_mode=email_mode,
        alias_limit=alias_limit,
        sms=sms,
        protocol_mode=protocol_mode,
        paypal_mode=paypal_mode,
    )
    if snapshot.get("codex_oauth") and not _registration_codex_waits_for_plus(snapshot):
        raise ValueError("注册自动 Codex 接码必须选择 PayPal“提链并支付”")

    # 创建/切换线程池和提交本批任务必须整体串行化：否则另一请求在本批提交中途
    # 切换 workers 并 shutdown 旧池，会导致后续 submit 报 cannot schedule new futures after shutdown。
    submission_started = perf_counter()
    with _executor_lock:
        executor = get_executor(max_workers=workers)
        effective_workers = get_executor_workers()
        batch = db.create_registration_batch(
            count=count,
            workers=effective_workers,
            email_source=email_source,
            flow_snapshot=snapshot,
        )
        jobs = db.create_registration_jobs_bulk(
            count=count, email_source=email_source,
            batch_id=batch["batch_id"], flow_snapshot=snapshot,
        )
        failed_updates = []
        for job in jobs:
            try:
                executor.submit(_run_one_job, job["id"], job["log_file"])
            except Exception as exc:
                message = f"队列提交失败：{type(exc).__name__}: {exc}"[:500]
                completed_at = datetime.now().isoformat(timespec="seconds")
                failed_updates.append({
                    "job_id": job["id"], "status": "failed",
                    "error": message, "completed_at": completed_at,
                })
                job.update(status="failed", error_message=message, completed_at=completed_at)
                logger.exception("[Service] 注册任务 #%s 提交线程池失败", job["id"])
        if failed_updates:
            db.update_jobs_bulk(failed_updates)
    logger.info(
        "[Service] 已提交 %s 个注册任务，batch=%s driver=%s oauth=%s paypal=%s source=%s workers=%s 入队耗时=%.3fs",
        count, batch["batch_id"], snapshot["registration_driver"], snapshot["codex_oauth"],
        snapshot["paypal"]["mode"], email_source, effective_workers, perf_counter() - submission_started,
    )
    return jobs


def _account_for_job(job: dict) -> dict | None:
    account_id = job.get("account_id")
    if account_id is not None:
        try:
            account = db.get_account(int(account_id))
            if account is not None:
                return account
        except (TypeError, ValueError):
            pass
    email = str(job.get("email") or "").strip()
    return db.get_account_by_email(email) if email else None


def _build_retry_context(all_jobs: list[dict]) -> dict:
    """Build lookup tables once for task-list retry metadata."""
    successful_retry_by_root: dict[int, dict] = {}
    for candidate in all_jobs:
        if str(candidate.get("status") or "") != "success":
            continue
        try:
            root_id = int(candidate.get("root_job_id") or 0)
            candidate_id = int(candidate.get("id") or 0)
        except (TypeError, ValueError):
            continue
        if root_id <= 0:
            continue
        previous = successful_retry_by_root.get(root_id)
        if previous is None or candidate_id > int(previous.get("id") or 0):
            successful_retry_by_root[root_id] = candidate

    accounts = db.list_job_retry_accounts()
    accounts_by_id = {}
    accounts_by_email = {}
    for account in accounts:
        try:
            accounts_by_id[int(account.get("id"))] = account
        except (TypeError, ValueError):
            pass
        email = str(account.get("email") or "").strip().lower()
        if email:
            accounts_by_email[email] = account
    return {
        "successful_retry_by_root": successful_retry_by_root,
        "accounts_by_id": accounts_by_id,
        "accounts_by_email": accounts_by_email,
    }


def enrich_jobs_with_retry_info(
    jobs: list[dict], *, all_jobs: list[dict] | None = None,
) -> list[dict]:
    """Enrich a task page without reloading both JSON stores for every row."""
    context = _build_retry_context(
        all_jobs if all_jobs is not None else db.list_jobs(limit=100_000)
    )
    for job in jobs:
        job.update(get_retry_info(job, context=context))
    return jobs


def get_retry_info(job: dict, *, context: dict | None = None) -> dict:
    """返回给 API/UI 的重试能力描述，不依赖前端猜测错误阶段。"""
    status = str(job.get("status") or "")
    info = {
        "retryable": False,
        "retry_action": None,
        "retry_label": None,
        "retry_reason": None,
        "display_status": status,
    }
    if status not in ("failed", "stopped", "cancelled"):
        return info

    if context is None:
        successful_retry = db.get_successful_retry_for_job(int(job.get("id") or 0))
    else:
        root_id = int(job.get("root_job_id") or job.get("id") or 0)
        successful_retry = context["successful_retry_by_root"].get(root_id)
    if successful_retry is not None:
        info["retry_reason"] = f"后续重试任务 #{successful_retry.get('id')} 已成功"
        info["successful_retry_job_id"] = successful_retry.get("id")
        return info

    if context is None:
        account = _account_for_job(job)
    else:
        try:
            account = context["accounts_by_id"].get(int(job.get("account_id")))
        except (TypeError, ValueError):
            account = None
        if account is None:
            email = str(job.get("email") or "").strip().lower()
            account = context["accounts_by_email"].get(email) if email else None
    if account and job.get("account_id") is not None and status in ("failed", "stopped"):
        info["display_status"] = "success" if (account.get("codex_status") or "") == "success" else "partial_success"

    if account:
        codex_status = str(account.get("codex_status") or "")
        if codex_status == "deactivated":
            info["retry_reason"] = "账号已废号，不能补跑 Codex"
            return info
        if codex_status == "success":
            info["retry_reason"] = "账号和 Codex 授权均已完成"
            return info
        info.update({
            "retryable": True,
            "retry_action": "codex",
            "retry_label": "补跑 Codex",
        })
        return info

    info.update({
        "retryable": True,
        "retry_action": "registration",
        "retry_label": "重试",
    })
    return info


def retry_job(job_id: int, workers: int | None = None) -> dict:
    """智能重试终态任务：未生成账号则重新注册，已有账号则仅补跑 Codex。"""
    source = db.get_job(job_id)
    if source is None:
        return {"ok": False, "error": "任务不存在", "status": 404}

    retry_info = get_retry_info(source)
    if not retry_info["retryable"]:
        reason = retry_info.get("retry_reason") or f"当前状态不支持重试：{source.get('status')}"
        return {"ok": False, "error": reason, "status": 409}

    action = str(retry_info["retry_action"])
    account = _account_for_job(source)
    email = str((account or {}).get("email") or source.get("email") or "").strip()
    account_id = int(account["id"]) if account and account.get("id") is not None else None
    reserved_codex = False
    if action == "codex":
        if not email or account_id is None:
            return {"ok": False, "error": "已注册账号信息不完整，无法补跑 Codex", "status": 409}
        if not codex_retry_service.reserve(email):
            return {"ok": False, "error": "该账号正在补跑 Codex，请稍候", "status": 409}
        reserved_codex = True

    try:
        job, created = db.create_retry_job(
            int(job_id),
            job_type="codex_retry" if action == "codex" else "registration",
            email_source=str(source.get("email_source") or "outlook"),
            email=email if action == "codex" else None,
            account_id=account_id if action == "codex" else None,
        )
    except LookupError as exc:
        if reserved_codex:
            codex_retry_service.release(email)
        return {"ok": False, "error": str(exc), "status": 404}
    except ValueError as exc:
        if reserved_codex:
            codex_retry_service.release(email)
        return {"ok": False, "error": str(exc), "status": 409}

    if not created:
        if reserved_codex:
            codex_retry_service.release(email)
        return {
            "ok": True,
            "created": False,
            "reused": True,
            "message": f"已有重试任务 #{job['id']} 在排队或运行中",
            "source_job_id": int(job_id),
            "retry_action": action,
            "job": job,
        }

    try:
        if action == "codex":
            db.update_account_codex_status(email, "retrying", None)
        with _executor_lock:
            executor = get_codex_executor(max_workers=workers)
            if action == "codex":
                executor.submit(_run_codex_retry_job, job["id"], job["log_file"], email, int(account_id))
            else:
                executor.submit(_run_one_job, job["id"], job["log_file"])
    except Exception as exc:
        if reserved_codex:
            codex_retry_service.release(email)
            db.update_account_codex_status(email, "failed", f"队列提交失败：{type(exc).__name__}: {exc}"[:500])
        db.update_job(
            int(job["id"]),
            status="failed",
            error=f"队列提交失败：{type(exc).__name__}: {exc}"[:500],
            completed_at=datetime.now().isoformat(timespec="seconds"),
        )
        logger.exception("[Service] 重试任务 #%s 提交线程池失败", job["id"])
        return {"ok": False, "error": "重试任务创建成功，但提交执行失败", "status": 500, "job": db.get_job(int(job["id"]))}

    return {
        "ok": True,
        "created": True,
        "reused": False,
        "message": f"已创建重试任务 #{job['id']}（{'Codex 补跑' if action == 'codex' else '完整注册'}）",
        "source_job_id": int(job_id),
        "retry_action": action,
        "job": job,
    }


def cancel_pending_jobs() -> int:
    """
    把所有 status=pending 的任务批量改成 cancelled，避免它们被执行。
    已经在 running 的任务不动（线程池中无法中途打断）。
    返回成功取消的数量。

    实际"不执行"的保证在 _run_one_job 开头——它真要跑起来时会先看 status 决定是否跳过。
    """
    jobs = db.list_jobs(limit=1000)
    cancelled = 0
    now_iso = datetime.now().isoformat(timespec="seconds")
    for job in jobs:
        if job.get("status") == "pending":
            db.update_job(
                int(job["id"]),
                status="cancelled",
                completed_at=now_iso,
                error="用户手动取消",
            )
            # 排队中的 Codex 补跑还占着号码预约，取消时要一并释放并把账号状态收回
            if job.get("job_type") in {"codex_retry", "codex_oauth"} and job.get("email"):
                codex_retry_service.release(str(job["email"]))
                db.update_account_codex_status(
                    str(job["email"]),
                    "stopped",
                    "用户手动取消排队中的 Codex 补跑",
                    failure_stage="cancelled",
                )
                _sync_registration_codex_parent(
                    job,
                    status="not_connected",
                    error="用户手动取消排队中的 Codex 自动接码",
                )
            cancelled += 1
    logger.info(f"[Service] 已取消 {cancelled} 个排队任务")
    return cancelled


def recover_interrupted_jobs() -> int:
    """Close persisted queue/running states left behind by a previous process."""
    with _STOP_LOCK:
        active_ids = set(_ACTIVE_JOBS)
    now_iso = datetime.now().isoformat(timespec="seconds")
    recovery_plan: list[dict] = []
    for job in db.list_jobs(limit=100000):
        job_id = int(job.get("id") or 0)
        status = str(job.get("status") or "")
        if not job_id or job_id in active_ids or status not in {"pending", "running", "stopping"}:
            continue

        is_codex = job.get("job_type") in {"codex_retry", "codex_oauth"}
        email = str(job.get("email") or "").strip()
        terminal = "cancelled" if status == "pending" else "stopped"
        message = "服务重启，排队任务未恢复执行" if status == "pending" else "服务重启，运行任务已中断"
        automatic_codex = bool(
            is_codex
            and job.get("job_type") == "codex_oauth"
            and _registration_codex_parent_id(job) is not None
            and db.get_job(int(job.get("parent_job_id") or 0)) is not None
        )
        account = None
        allocation = None
        if not is_codex and email:
            account = _account_for_job(job)
            if account:
                allocation = db.get_email_allocation_by_actual_email(email)
        update = {
            "job_id": job_id,
            "status": terminal,
            "completed_at": now_iso,
            "error": message,
            "restart_recoverable": automatic_codex,
        }
        if allocation:
            update["email_allocation_id"] = allocation.get("id")
        recovery_plan.append({
            "job": job,
            "job_id": job_id,
            "is_codex": is_codex,
            "email": email,
            "message": message,
            "automatic_codex": automatic_codex,
            "account": account,
            "allocation": allocation,
            "update": update,
        })

    if not recovery_plan:
        return 0

    updated = db.update_jobs_bulk([item["update"] for item in recovery_plan])
    if updated != len(recovery_plan):
        logger.warning(
            "[Service] 中断任务批量恢复数量不一致: planned=%s updated=%s",
            len(recovery_plan), updated,
        )

    for item in recovery_plan:
        job = item["job"]
        job_id = item["job_id"]
        is_codex = item["is_codex"]
        email = item["email"]
        message = item["message"]
        automatic_codex = item["automatic_codex"]
        if is_codex and email:
            codex_retry_service.release(email)
            if automatic_codex:
                db.update_account_codex_status(email, "queued", None)
                _sync_registration_codex_parent(
                    job,
                    status="queued",
                    error="服务重启中断 Codex 自动接码，正在恢复排队",
                )
            else:
                db.update_account_codex_status(
                    email,
                    "stopped",
                    message,
                    failure_stage="restart",
                )
        elif email:
            account = item["account"]
            if account:
                allocation = item["allocation"]
                db.complete_email_allocation(
                    email,
                    account_id=int(account["id"]),
                    status="registered",
                )
                # 账号已经落盘了，只有 Codex 那一段被打断，别把基础注册也标成失败
                if str(job.get("oauth_status") or "") == "running" and not account.get("codex_refresh_token"):
                    db.update_account_codex_status(
                        email,
                        "stopped",
                        message,
                        failure_stage="restart",
                    )
            else:
                _release_unconsumed_job_email(email, message)
        _append_job_log(job_id, message)
    logger.warning(
        "[Service] 已批量恢复 %s 个因进程重启中断的注册/Codex 任务",
        len(recovery_plan),
    )
    return len(recovery_plan)


def recover_deferred_registration_codex() -> dict[str, int]:
    """Resume confirmed-Plus registration continuations after process restart."""
    result = {"queued": 0, "reused": 0, "skipped": 0, "failed": 0}
    accounts = db.list_accounts(limit=1_000_000, archived="all")
    by_registration_job: dict[int, dict] = {}
    for account in accounts:
        try:
            registration_job_id = int(account.get("registration_job_id") or 0)
        except (TypeError, ValueError):
            continue
        if registration_job_id > 0:
            by_registration_job[registration_job_id] = account

    for parent in db.list_jobs(limit=100_000):
        try:
            parent_id = int(parent.get("id") or 0)
        except (TypeError, ValueError):
            continue
        if (
            parent.get("job_type", "registration") != "registration"
            or str(parent.get("status") or "").strip().lower() != "success"
            or str(parent.get("oauth_status") or "").strip().lower()
            not in {"waiting_plus", "queued", "running"}
        ):
            continue
        account = by_registration_job.get(parent_id)
        if not account:
            result["skipped"] += 1
            continue
        payment_status = str(account.get("paypal_payment_status") or "").strip().lower()
        plan = str(
            account.get("current_plan_type") or account.get("plan_type") or ""
        ).strip().lower()
        if not account.get("oauth_requested") or account.get("archived"):
            result["skipped"] += 1
            continue
        if account.get("has_codex_refresh_token") or account.get("codex_refresh_token"):
            db.update_job(parent_id, oauth_status="success", oauth_error="")
            result["reused"] += 1
            continue
        if payment_status != "confirmed" or plan != "plus":
            result["skipped"] += 1
            continue
        try:
            queued = continue_registration_codex_after_plus(
                int(account["id"]), recover_interrupted=True,
            )
        except Exception:
            logger.exception(
                "[Codex] 恢复 Plus 后自动接码异常: account=%s",
                account.get("id"),
            )
            result["failed"] += 1
            continue
        if queued.get("accepted"):
            result["queued"] += 1
        elif queued.get("status") == "already_queued":
            result["reused"] += 1
        else:
            result["failed"] += 1
    return result


def request_stop_job(job_id: int) -> dict:
    """手动停止单个注册任务。pending 直接取消；running 设置停止标记，运行线程会在检查点退出。"""
    job = db.get_job(job_id)
    if not job:
        return {"ok": False, "error": "任务不存在", "status": 404}
    status = job.get("status")
    now_iso = datetime.now().isoformat(timespec="seconds")
    if status == "pending":
        db.update_job(job_id, status="cancelled", completed_at=now_iso, error="用户手动停止/取消排队")
        if job.get("job_type") in {"codex_retry", "codex_oauth"} and job.get("email"):
            codex_retry_service.release(str(job["email"]))
            db.update_account_codex_status(
                str(job["email"]),
                "stopped",
                "用户手动停止/取消排队中的 Codex 补跑",
                failure_stage="cancelled",
            )
            _sync_registration_codex_parent(
                job,
                status="not_connected",
                error="用户手动停止/取消排队中的 Codex 自动接码",
            )
        _append_job_log(job_id, "用户手动停止：任务尚未运行，已取消排队。")
        return {"ok": True, "message": "排队任务已取消", "job_id": job_id, "state": "cancelled"}
    if status in ("success", "failed", "cancelled", "stopped"):
        return {"ok": True, "message": f"任务已结束：{status}", "job_id": job_id, "state": status}
    if status in ("running", "stopping"):
        with _STOP_LOCK:
            active = int(job_id) in _ACTIVE_JOBS
            ev = _STOP_EVENTS.get(int(job_id)) if active else None
            if ev is not None:
                ev.set()
        if not active or ev is None:
            # Web 服务重启、线程异常退出、历史残留 stopping，或之前手动停止时只创建了 stop event
            # 但没有真实线程实例：直接落为 stopped，避免永远卡在“停止中”。
            with _STOP_LOCK:
                _STOP_EVENTS.pop(int(job_id), None)
                _ACTIVE_JOBS.discard(int(job_id))
            db.update_job(
                job_id,
                status="stopped",
                completed_at=now_iso,
                error="用户手动停止（任务实例不存在）",
            )
            email = str(job.get("email") or "").strip()
            if job.get("job_type") in {"codex_retry", "codex_oauth"} and email:
                codex_retry_service.release(email)
                db.update_account_codex_status(
                    email,
                    "stopped",
                    "用户手动停止（任务实例不存在）",
                    failure_stage="stopped",
                )
                _sync_registration_codex_parent(
                    job,
                    status="not_connected",
                    error="用户手动停止（任务实例不存在）",
                )
            else:
                _release_unconsumed_job_email(
                    email or None,
                    "任务实例不存在，确认未继续执行",
                )
            _append_job_log(job_id, "用户手动停止：未找到运行中的任务实例，已直接标记为已停止。")
            logger.warning("[Service] 用户停止任务 #%s：任务实例不存在，已直接标记 stopped", job_id)
            return {"ok": True, "message": "任务实例不存在，已直接标记为已停止", "job_id": job_id, "state": "stopped"}
        if job.get("job_type") in {"codex_retry", "codex_oauth"} and job.get("email"):
            codex_retry_service.request_stop(str(job["email"]))
        db.update_job(job_id, status="stopping", error="用户手动停止中")
        _append_job_log(job_id, "用户手动停止：已发送停止信号，任务会在当前步骤检查点退出。")
        logger.warning("[Service] 用户请求停止任务 #%s", job_id)
        return {"ok": True, "message": "已发送停止信号", "job_id": job_id, "state": "stopping"}
    return {"ok": False, "error": f"当前状态不支持停止：{status}", "status": 409}


def read_job_log(job_id: int, max_bytes: int = 50_000) -> str:
    """读取任务日志文件最后 max_bytes 字节，给 Web UI 显示。"""
    job = db.get_job(job_id)
    if not job or not job.get("log_file"):
        return ""
    p = Path(job["log_file"])
    if not p.exists():
        return ""
    size = p.stat().st_size
    with p.open("rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
        data = f.read()
    return data.decode("utf-8", errors="replace")
