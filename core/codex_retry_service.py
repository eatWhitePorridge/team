# -*- coding: utf-8 -*-
"""Codex 授权补跑服务，供账号页和注册任务队列共同使用。"""
import ctypes
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from core import db
from core import progress_events

logger = logging.getLogger(__name__)

_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"
_RETRYING: set[str] = set()
_RETRYING_LOCK = threading.Lock()
_STOP_REQUESTED: set[str] = set()
_RUNNING_THREADS: dict[str, int] = {}
_RESERVED_AT: dict[str, float] = {}

# OAuth 补跑使用独立线程池，不与 registration_service 的注册线程池共享。
# 批量接口仍可通过 workers 参数临时调整；未传参数时读取 CODEX_RETRY_WORKERS。
_CODEX_DEFAULT_MAX_WORKERS = 50
_CODEX_MIN_MAX_WORKERS = 1
_CODEX_MAX_MAX_WORKERS = 100
_codex_executor: ThreadPoolExecutor | None = None
_codex_executor_workers: int | None = None
_codex_executor_limit: int | None = None
_codex_executor_generation = 0
_codex_retired_executors: list[ThreadPoolExecutor] = []
_codex_executor_lock = threading.RLock()


class _TrackedExecutor(ThreadPoolExecutor):
    """Measure actual executing callables, not persisted 'active' queue rows."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._metrics_lock = threading.Lock()
        self._running_count = 0
        self._queued_count = 0
        self._peak_running = 0

    def submit(self, fn, /, *args, **kwargs):
        state = ["queued"]
        with self._metrics_lock:
            self._queued_count += 1
        progress_events.notify('runtime')

        def run():
            with self._metrics_lock:
                if state[0] != "queued":
                    return None
                state[0] = "running"
                self._queued_count -= 1
                self._running_count += 1
                self._peak_running = max(self._peak_running, self._running_count)
            progress_events.notify('runtime')
            try:
                return fn(*args, **kwargs)
            finally:
                with self._metrics_lock:
                    self._running_count -= 1
                    state[0] = "finished"
                progress_events.notify('runtime')

        def discard_queued():
            with self._metrics_lock:
                if state[0] == "queued":
                    self._queued_count -= 1
                    state[0] = "discarded"
            progress_events.notify('runtime')

        try:
            future = super().submit(run)
        except BaseException:
            discard_queued()
            raise
        future.add_done_callback(lambda done: discard_queued() if done.cancelled() else None)
        return future

    def counters(self) -> dict:
        with self._metrics_lock:
            return {"running": self._running_count, "queued": self._queued_count,
                    "peak_running": self._peak_running}


def configure_executor_limit(workers: int) -> None:
    """Pin an isolated host's shared OAuth pool once, before accepting work.

    Legacy hosts do not call this and retain their existing configured default.
    An isolated console must not create a second pool after config reloads or
    per-batch worker hints: ordinary and Team authorization share one hard cap.
    """
    global _codex_executor_limit
    if type(workers) is not int or not _CODEX_MIN_MAX_WORKERS <= workers <= _CODEX_MAX_MAX_WORKERS:
        raise ValueError("授权并发必须为 1–100 的整数")
    with _codex_executor_lock:
        if _codex_executor_limit is not None and _codex_executor_limit != workers:
            raise RuntimeError("授权并发已固定，请重启独立服务后修改")
        if (_codex_executor is not None and _codex_executor_workers != workers) or _codex_retired_executors:
            raise RuntimeError("必须在授权线程池启动前设置固定并发")
        _codex_executor_limit = workers


def executor_status() -> dict:
    """Small credential-free snapshot; never creates a pool or scans JSON."""
    with _codex_executor_lock:
        workers = _codex_executor_workers or _normalize_executor_workers(None)
        pools = [*_codex_retired_executors, *([_codex_executor] if _codex_executor is not None else [])]
        counters = [pool.counters() for pool in pools]
        running = sum(row["running"] for row in counters)
        return {"workers": workers, "running": running,
                "queued": sum(row["queued"] for row in counters),
                "available": max(0, workers - running),
                "peak_running": max((row["peak_running"] for row in counters), default=0),
                "fixed": _codex_executor_limit is not None}


class CodexRetryStopped(Exception):
    """用户手动停止 Codex 补跑。"""


def _configured_codex_workers() -> int:
    """读取未显式传入 workers 时使用的 Codex 补跑并发。"""
    try:
        from config import codex as codex_cfg

        value = int(
            getattr(codex_cfg, "CODEX_RETRY_WORKERS", _CODEX_DEFAULT_MAX_WORKERS)
            or _CODEX_DEFAULT_MAX_WORKERS
        )
    except (TypeError, ValueError, ImportError, AttributeError):
        value = _CODEX_DEFAULT_MAX_WORKERS
    return value


def _normalize_executor_workers(max_workers: int | None) -> int:
    if _codex_executor_limit is not None:
        return _codex_executor_limit
    value = _configured_codex_workers() if max_workers is None else max_workers
    try:
        value = int(value)
    except (TypeError, ValueError):
        value = _CODEX_DEFAULT_MAX_WORKERS
    return max(_CODEX_MIN_MAX_WORKERS, min(_CODEX_MAX_MAX_WORKERS, value))


def get_executor(max_workers: int | None = None) -> ThreadPoolExecutor:
    """返回 OAuth 补跑专用线程池，并在并发配置变化时切换新池。

    旧池里的任务不取消，避免把已经开始的邮箱授权强行截断；新提交的
    Codex 任务只进入新池。该状态与 registration_service 的线程池完全分离。
    """
    global _codex_executor, _codex_executor_workers, _codex_executor_generation
    with _codex_executor_lock:
        requested_workers = _normalize_executor_workers(max_workers)
        if _codex_executor is None or requested_workers != _codex_executor_workers:
            old_executor = _codex_executor
            if old_executor is not None:
                old_executor.shutdown(wait=False, cancel_futures=False)
                _codex_retired_executors.append(old_executor)
                logger.info(
                    "[Codex] 补跑线程池 workers 从 %s 切换为 %s；旧池继续处理已排队任务",
                    _codex_executor_workers,
                    requested_workers,
                )
            _codex_executor_workers = requested_workers
            _codex_executor_generation += 1
            _codex_executor = _TrackedExecutor(
                max_workers=requested_workers,
                thread_name_prefix=f"codex-retry-{_codex_executor_generation}",
            )
    return _codex_executor


def get_executor_workers() -> int:
    """返回当前新提交 OAuth 补跑任务使用的线程数。"""
    with _codex_executor_lock:
        if _codex_executor_workers is None:
            return _normalize_executor_workers(None)
        return _codex_executor_workers


def shutdown_executor(wait: bool = True) -> None:
    """关闭 Codex 补跑线程池；供宿主进程退出或测试清理使用。"""
    global _codex_executor, _codex_executor_workers
    with _codex_executor_lock:
        executors: list[ThreadPoolExecutor] = []
        if _codex_executor is not None:
            executors.append(_codex_executor)
            _codex_executor = None
        executors.extend(_codex_retired_executors)
        _codex_retired_executors.clear()
        _codex_executor_workers = None
    for executor in executors:
        executor.shutdown(wait=wait, cancel_futures=False)


def _thread_alive(thread_id: int | None) -> bool:
    if not thread_id:
        return False
    try:
        tid = int(thread_id)
    except Exception:
        return False
    return any(getattr(t, "ident", None) == tid and t.is_alive() for t in threading.enumerate())


def _clear_state_locked(key: str) -> None:
    _RETRYING.discard(key)
    _RUNNING_THREADS.pop(key, None)
    _RESERVED_AT.pop(key, None)


def log_path(email: str) -> Path:
    safe = email.replace("/", "_").replace("\\", "_").replace(":", "_")
    return _LOG_DIR / f"codex-retry-{safe}.log"


def reserve(email: str) -> bool:
    """进程内防止同一账号被重复补跑。"""
    key = (email or "").strip().lower()
    if not key:
        return False
    with _RETRYING_LOCK:
        if key in _RETRYING:
            thread_id = _RUNNING_THREADS.get(key)
            alive = _thread_alive(thread_id)
            age = time.time() - float(_RESERVED_AT.get(key) or 0)
            stop_req = key in _STOP_REQUESTED
            try:
                acc = db.get_account_by_email(email)
                status = str((acc or {}).get("codex_status") or "").lower()
            except Exception:
                status = ""
            # 修复“实际已停止/线程已结束，但进程内占位未释放”导致无法再次补跑。
            # 用户点停止后，部分浏览器/短信等待步骤可能不会立刻退出，UI 已是 stopped 但进程占位仍在。
            # 这种场景允许清理占位后重新补跑；旧线程仍保留 stop_requested，会在检查点退出。
            terminal_status = status in {"stopped", "failed", "success", "deactivated", "skipped", "cancelled"}
            if ((not alive) and (status != "retrying" or age > 15 * 60)) or (terminal_status and (stop_req or age > 30)):
                logger.warning(
                    "[Codex 补跑] 清理脏占位：email=%s status=%s thread_id=%s alive=%s stop_requested=%s age=%.1fs",
                    email, status or "-", thread_id or "-", alive, stop_req, age,
                )
                _clear_state_locked(key)
            else:
                return False
        _STOP_REQUESTED.discard(key)
        _RUNNING_THREADS.pop(key, None)
        _RETRYING.add(key)
        _RESERVED_AT[key] = time.time()
        return True


def release(email: str) -> None:
    key = (email or "").strip().lower()
    with _RETRYING_LOCK:
        _clear_state_locked(key)


def is_retrying(email: str) -> bool:
    with _RETRYING_LOCK:
        return (email or "").strip().lower() in _RETRYING


def is_stop_requested(email: str) -> bool:
    with _RETRYING_LOCK:
        return (email or "").strip().lower() in _STOP_REQUESTED


def check_stop_requested(email: str) -> None:
    if is_stop_requested(email):
        raise CodexRetryStopped("用户手动停止 Codex 补跑")


def _async_raise(thread_id: int, exc_type: type[BaseException]) -> bool:
    """向指定 Python 线程注入异常，用于尽快中断阻塞中的补跑流程。"""
    if not thread_id:
        return False
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(thread_id),
        ctypes.py_object(exc_type),
    )
    if res == 0:
        return False
    if res != 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(thread_id), None)
        return False
    return True


def request_stop(email: str) -> dict:
    """请求停止单个 Codex 补跑。运行中会注入停止异常；排队中会在启动前退出。"""
    key = (email or "").strip().lower()
    if not key:
        return {"ok": False, "error": "email 为空", "status": 400}
    with _RETRYING_LOCK:
        retrying = key in _RETRYING
        thread_id = _RUNNING_THREADS.get(key)
        _STOP_REQUESTED.add(key)
    if not retrying:
        db.update_account_codex_status(email, "stopped", "用户手动停止（未发现运行中的补跑）")
        return {"ok": True, "message": "未发现运行中的补跑，已标记为已停止", "state": "stopped", "running": False}

    injected = bool(thread_id and _async_raise(int(thread_id), CodexRetryStopped))
    db.update_account_codex_status(email, "stopped", "用户手动停止 Codex 补跑")
    # 如果没有可注入的存活线程，立即释放进程内占位，避免 UI 显示已停止但再次补跑仍 409。
    with _RETRYING_LOCK:
        if not _thread_alive(thread_id):
            _clear_state_locked(key)
    if injected:
        # 异常注入通常会很快让线程进入 finally/release；若浏览器/CDP/短信等待阻塞导致线程
        # 短时间内仍未退出，延迟清理占位，避免 UI 已显示“已停止”但再次补跑仍 409。
        def _delayed_release() -> None:
            time.sleep(5)
            with _RETRYING_LOCK:
                if key in _RETRYING and key in _STOP_REQUESTED:
                    try:
                        acc = db.get_account_by_email(email)
                        status = str((acc or {}).get("codex_status") or "").lower()
                    except Exception:
                        status = ""
                    if status == "stopped":
                        logger.warning("[Codex 补跑] 停止后延迟释放占位：email=%s thread_id=%s", email, thread_id or "-")
                        _clear_state_locked(key)

        threading.Thread(target=_delayed_release, name=f"codex-stop-release-{key}", daemon=True).start()
    try:
        p = log_path(email)
        p.parent.mkdir(parents=True, exist_ok=True)
        from datetime import datetime as _dt
        with p.open("a", encoding="utf-8") as f:
            f.write(f"{_dt.now().strftime('%H:%M:%S')} [WARNING] [Codex 补跑] 用户手动停止，已发送停止信号 injected={injected}\n")
    except Exception:
        logger.exception("写入 Codex 停止日志失败")
    return {"ok": True, "message": "已发送停止信号", "state": "stopped", "running": True, "injected": injected}


def run_worker(
    email: str,
    *,
    batch_label: str | None = None,
    clear_log: bool = True,
    target_log_path: str | Path | None = None,
    sms_options: dict | None = None,
    login_mode: str = "email_otp", expected_workspace_id: str = "",
    oauth_auto_retry: bool = True,
) -> dict:
    """执行一次 Codex 补跑。调用前必须先 reserve，结束时会自动 release。"""
    fh: logging.FileHandler | None = None
    root_logger = logging.getLogger()
    result: dict = {"status": "failed", "ok": False, "message": "Codex 补跑未返回结果"}
    key = (email or "").strip().lower()
    try:
        with _RETRYING_LOCK:
            _RUNNING_THREADS[key] = threading.get_ident()
            _RESERVED_AT[key] = time.time()
        check_stop_requested(email)

        from core.codex_oauth import run_codex_oauth
        from core import sms_provider

        path = Path(target_log_path) if target_log_path else log_path(email)
        path.parent.mkdir(parents=True, exist_ok=True)
        if clear_log:
            path.write_text("", encoding="utf-8")

        thread_name = threading.current_thread().name
        fh = logging.FileHandler(str(path), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        fh.addFilter(lambda record: record.threadName == thread_name)
        root_logger.addHandler(fh)

        # Isolated hosts load configuration at startup and explicitly apply
        # supported hot settings. Reloading every module from 100 worker threads
        # races global values and would erase the console's live proxy override.
        if _codex_executor_limit is None:
            try:
                import config as config_pkg
                config_pkg.reload_all()
                from config import roxybrowser as roxy_cfg
                logger.info(
                    "[Codex 补跑] 已热加载配置：ROXY_OPEN_HEADLESS=%s ROXY_KEEP_BROWSER_OPEN=%s",
                    getattr(roxy_cfg, "ROXY_OPEN_HEADLESS", ""),
                    getattr(roxy_cfg, "ROXY_KEEP_BROWSER_OPEN", ""),
                )
            except Exception as exc:
                logger.warning("[Codex 补跑] 配置热加载失败，将继续使用当前内存配置：%s: %s", type(exc).__name__, exc)

        if batch_label:
            logger.info("[Codex 补跑] 批量任务：%s", batch_label)
        logger.info("[Codex 补跑] 开始：%s", email)
        if login_mode == "password_totp":
            logger.info("[Codex 补跑] 独立密码 + 2FA 授权：新 OAuth 会话 → 密码 → TOTP → 工作区 → 保存新凭证")
        else:
            logger.info("[Codex 补跑] 阶段说明：获取授权地址 → 登录邮箱 → 邮箱 OTP → 手机验证 → 捕获 callback → 提交/保存凭证")
        check_stop_requested(email)
        options = dict(sms_options or {})
        options.setdefault("job_id", f"retry:{email}")
        with sms_provider.runtime_context(options), progress_events.job_context(options.get('job_id')):
            progress_events.phase('starting')
            result = run_codex_oauth(
                email,
                force=True,
                auth_source="local",
                **({"expected_workspace_id": expected_workspace_id} if expected_workspace_id else {}),
                **({"login_mode": login_mode} if login_mode != "email_otp" else {}),
                **({"auto_retry": False} if not oauth_auto_retry else {}),
            )
            progress_events.phase('persisting')
        check_stop_requested(email)
        logger.info(
            "[Codex 补跑] 结果：status=%s ok=%s file=%s callback=%s",
            result.get("status"), result.get("ok"), result.get("file_path"), result.get("callback_url"),
        )
        result_status = result.get("status", "failed")
        if result.get("ok"):
            db.update_account_codex_result(email, result)
            account = db.get_account_by_email(email) or {}
            if account.get("codex_refresh_token"):
                logger.info("[Codex 补跑] %s 成功", email)
            else:
                result = {**result, "ok": False, "status": "failed", "message": "Codex OAuth 未返回 refresh_token"}
                db.update_account_codex_result(email, result)
        elif result_status == "deactivated":
            db.update_account_codex_result(email, result)
            logger.warning("[Codex 补跑] %s 账号已废: %s", email, result.get("message"))
        else:
            db.update_account_codex_result(email, result)
            logger.warning("[Codex 补跑] %s 失败: %s", email, result.get("message"))
        return result
    except CodexRetryStopped as exc:
        result = {"status": "stopped", "ok": False, "message": str(exc) or "用户手动停止 Codex 补跑"}
        db.update_account_codex_status(email, "stopped", result["message"])
        logger.warning("[Codex 补跑] %s 已停止: %s", email, result["message"])
        return result
    except Exception as exc:
        if is_stop_requested(email):
            result = {"status": "stopped", "ok": False, "message": "用户手动停止 Codex 补跑"}
            db.update_account_codex_status(email, "stopped", result["message"])
            logger.warning("[Codex 补跑] %s 已停止", email)
            return result
        result = {"status": "failed", "ok": False, "message": f"{type(exc).__name__}: {exc}"}
        db.update_account_codex_status(email, "failed", result["message"])
        logger.exception("[Codex 补跑] %s 异常", email)
        logger.error("[Codex 补跑] 已结束：异常失败")
        return result
    finally:
        try:
            logger.info("[Codex 补跑] 结束：%s", email)
            if fh is not None:
                root_logger.removeHandler(fh)
                fh.close()
        finally:
            release(email)
            with _RETRYING_LOCK:
                if key:
                    _STOP_REQUESTED.discard(key)
