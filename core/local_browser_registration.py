# -*- coding: utf-8 -*-
"""通过上游 go-rod/stealth 流程注册 ChatGPT，并保存 Web 登录凭证。"""
from __future__ import annotations

import json
import logging
import math
import os
import platform
import queue
import signal
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from config import local_browser as _cfg
from config import twofa as _twofa_cfg  # noqa: F401 - compatibility for driver tests
from config.env_loader import build_subprocess_env
from config.proxy import normalize_proxy_url
from core.account_export import save_account_data
from core.email_provider import resolve_email_source, wait_for_otp
from core.local_browser_driver import _Socks5AuthBridge, _normalize_proxy, _playwright_proxy
from core.openai_auth import generate_openai_registration_password


logger = logging.getLogger(__name__)


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_UPSTREAM_COMMIT = "5acc496afe6528d75a0b72f141883e765b268c0c"


@dataclass
class RodHelperProgress:
    """Python 监管层保存的 helper 进度；异常退出后仍可判断邮箱是否已消费。"""

    stage: str = ""
    otp_requests: int = 0
    otp_accepted: bool = False
    profile_submitted: bool = False
    email_reusable: bool = False
    submitted_otp_codes: set[str] = field(default_factory=set)

    @property
    def email_consumed(self) -> bool:
        return bool(
            not self.email_reusable
            and (self.otp_accepted or self.profile_submitted)
        )

    def observe_stage(self, stage: object) -> None:
        key = str(stage or "").strip().lower()
        if not key:
            return
        self.stage = key
        if key in {"otp_accepted", "email_verified"}:
            self.otp_accepted = True
        if key == "profile_submitted":
            # 能提交资料页说明邮箱 OTP 已经通过，即使旧 helper 未单独发送
            # otp_accepted 阶段，也不能在后续异常时把邮箱归还为 available。
            self.otp_accepted = True
            self.profile_submitted = True
        if key == "account_creation_rejected":
            # 资料页经过有限重提后仍被拒绝，但账号并未创建。该邮箱允许
            # 后续重新领取，不能沿用普通 OTP 后失败的停用策略。
            self.otp_accepted = True
            self.email_reusable = True

    def snapshot(self) -> "RodHelperProgress":
        return RodHelperProgress(
            stage=self.stage,
            otp_requests=self.otp_requests,
            otp_accepted=self.otp_accepted,
            profile_submitted=self.profile_submitted,
            email_reusable=self.email_reusable,
            submitted_otp_codes=set(self.submitted_otp_codes),
        )


class RodHelperError(RuntimeError):
    """携带 helper 已完成阶段的错误，防止异常路径丢失邮箱消费状态。"""

    def __init__(
        self,
        message: str,
        *,
        progress: RodHelperProgress | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.progress = (progress or RodHelperProgress()).snapshot()
        self.cause = cause

    @property
    def email_consumed(self) -> bool:
        return self.progress.email_consumed


class _LocalBrowserConcurrencyLimiter:
    """支持热配置容量的轻量信号量。"""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._active = 0

    def acquire(self, job_id: int | None) -> None:
        waiting_logged = False
        while True:
            _raise_if_job_stopped(job_id)
            limit = max(
                1,
                int(getattr(_cfg, "LOCAL_BROWSER_MAX_CONCURRENT_RUNS", 3) or 3),
            )
            with self._condition:
                if self._active < limit:
                    self._active += 1
                    return
                if not waiting_logged:
                    logger.info(
                        "[本机Rod] 已达到本机浏览器并发上限 %s，等待空闲槽位",
                        limit,
                    )
                    waiting_logged = True
                self._condition.wait(timeout=_stop_poll_interval())

    def release(self) -> None:
        with self._condition:
            if self._active <= 0:
                raise RuntimeError("本机浏览器并发槽位释放次数异常")
            self._active -= 1
            self._condition.notify_all()


_LOCAL_BROWSER_LIMITER = _LocalBrowserConcurrencyLimiter()


class _LocalBrowserCachePool:
    """为并发 Chromium 分配独占写入槽，后续任务复用同一静态缓存。"""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._active: set[int] = set()

    def acquire(self, job_id: int | None) -> tuple[int, Path]:
        waiting_logged = False
        while True:
            _raise_if_job_stopped(job_id)
            slot_count = max(
                1,
                int(getattr(_cfg, "LOCAL_BROWSER_DISK_CACHE_SLOTS", 3) or 3),
            )
            with self._condition:
                for slot in range(slot_count):
                    if slot in self._active:
                        continue
                    self._active.add(slot)
                    try:
                        cache_dir = _resolve_cache_root() / f"slot-{slot}"
                        cache_dir.mkdir(parents=True, exist_ok=True)
                    except Exception:
                        self._active.discard(slot)
                        self._condition.notify_all()
                        raise
                    return slot, cache_dir
                if not waiting_logged:
                    logger.info(
                        "[本机Rod][低流量] %s 个缓存槽均在使用，等待空闲槽位",
                        slot_count,
                    )
                    waiting_logged = True
                self._condition.wait(timeout=_stop_poll_interval())

    def release(self, slot: int) -> None:
        with self._condition:
            self._active.discard(int(slot))
            self._condition.notify_all()


_LOCAL_BROWSER_CACHE_POOL = _LocalBrowserCachePool()


def _resolve_cache_root() -> Path:
    raw = str(
        getattr(
            _cfg,
            "LOCAL_BROWSER_DISK_CACHE_DIR",
            "data/local-browser-static-cache",
        )
        or "data/local-browser-static-cache"
    ).strip()
    root = Path(raw).expanduser()
    if not root.is_absolute():
        root = _PROJECT_ROOT / root
    return root.resolve(strict=False)


@contextmanager
def _local_browser_cache_slot(job_id: int | None):
    if not bool(getattr(_cfg, "LOCAL_BROWSER_SHARED_DISK_CACHE", True)):
        yield None
        return
    slot, cache_dir = _LOCAL_BROWSER_CACHE_POOL.acquire(job_id)
    try:
        logger.info(
            "[本机Rod][低流量] 使用静态缓存槽：slot=%s path=%s",
            slot,
            cache_dir,
        )
        yield cache_dir
    finally:
        _LOCAL_BROWSER_CACHE_POOL.release(slot)


_LOCAL_BROWSER_RETRYABLE_MARKERS = (
    "代理/网络",
    "代理连接",
    "代理出口",
    "network",
    "connection",
    "err_",
    "socks",
    "打开注册页",
    "认证路由异常",
    "安全挑战",
    "context deadline",
    "页面状态",
    "等待邮箱提交后",
    "启动 chrome",
    "连接 chrome",
)


def _is_retryable_local_browser_error(exc: Exception) -> bool:
    """只允许在 OTP 尚未提交时重建浏览器，避免账号状态不确定。"""

    progress = exc.progress if isinstance(exc, RodHelperError) else RodHelperProgress()
    if progress.email_consumed or progress.submitted_otp_codes or progress.stage in {
        "otp_entered",
        "otp_accepted",
        "email_verified",
        "profile_submitted",
    }:
        return False
    cause = exc.cause if isinstance(exc, RodHelperError) and exc.cause else exc
    if type(cause).__name__ == "StopRequested":
        return False
    text = f"{type(cause).__name__}: {exc}".lower()
    return any(marker in text for marker in _LOCAL_BROWSER_RETRYABLE_MARKERS)


def _sleep_with_stop(seconds: float, job_id: int | None) -> None:
    deadline = time.monotonic() + max(0.0, float(seconds or 0.0))
    while True:
        _raise_if_job_stopped(job_id)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(_stop_poll_interval(), remaining))


def _next_local_browser_proxy(current: str, *, allow_pool_pick: bool) -> str:
    try:
        from core.protocol_rate_limit import rotate_sticky_proxy_session

        # 保留 socks5h://，数据库中的代理会被补 2FA/Codex 等纯 HTTP
        # 流程复用；只有交给 Rod 运行时才转换为 socks5://。
        rotated = normalize_proxy_url(rotate_sticky_proxy_session(current))
    except Exception:
        rotated = current
    if rotated and rotated != current:
        return rotated
    if allow_pool_pick:
        return _select_proxy(None)
    return current


def _stop_proxy_bridge(bridge: _Socks5AuthBridge | None) -> None:
    if bridge is None:
        return
    traffic = bridge.traffic_snapshot()
    logger.info(
        "[本机Rod][流量] 上传=%sB 下载=%sB 总计=%sB 连接=%s",
        traffic.get("uploaded_bytes", 0),
        traffic.get("downloaded_bytes", 0),
        traffic.get("total_bytes", 0),
        traffic.get("connection_count", 0),
    )
    bridge.stop()


def _age_from_birthday(birthday: str, *, today: date | None = None) -> str:
    try:
        born = date.fromisoformat(str(birthday))
    except ValueError as exc:
        raise RuntimeError(f"生日格式应为 YYYY-MM-DD: {birthday}") from exc
    now = today or date.today()
    age = now.year - born.year - ((now.month, now.day) < (born.month, born.day))
    if age < 0:
        raise RuntimeError(f"生日不能晚于今天: {birthday}")
    return str(age)


def _platform_binary_name() -> str:
    machine = platform.machine().strip().lower()
    if machine in {"x86_64", "amd64"}:
        arch = "amd64"
    elif machine in {"arm64", "aarch64"}:
        arch = "arm64"
    else:
        raise RuntimeError(f"Rod helper 不支持当前 CPU 架构: {machine or 'unknown'}")
    if os.name == "nt":
        return f"rod-register-windows-{arch}.exe"
    if platform.system().lower() == "darwin":
        return f"rod-register-darwin-{arch}"
    if platform.system().lower() == "linux":
        return f"rod-register-linux-{arch}"
    raise RuntimeError(f"Rod helper 不支持当前系统: {platform.system()}")


def _resolve_helper_path(explicit: str | Path | None = None) -> Path:
    configured = str(
        explicit
        or os.environ.get("LOCAL_BROWSER_ROD_HELPER_PATH")
        or getattr(_cfg, "LOCAL_BROWSER_ROD_HELPER_PATH", "")
        or ""
    ).strip()
    path = Path(configured).expanduser() if configured else (
        _PROJECT_ROOT / "tools" / "rod_register" / "bin" / _platform_binary_name()
    )
    path = path.resolve()
    if not path.is_file():
        raise RuntimeError(
            f"未找到 Rod 注册 helper: {path}；请构建 tools/rod_register 后重试"
        )
    if not os.access(path, os.X_OK):
        raise RuntimeError(f"Rod 注册 helper 不可执行: {path}")
    return path


def _resolve_browser_binary(explicit: str | Path | None = None) -> str:
    configured = str(
        explicit
        or os.environ.get("ROD_BROWSER_BIN")
        or getattr(_cfg, "LOCAL_BROWSER_EXECUTABLE_PATH", "")
        or ""
    ).strip()
    if configured:
        path = Path(configured).expanduser().resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RuntimeError(f"Rod Chromium 路径无效或不可执行: {path}")
        return str(path)
    # 与上游一致：未显式覆盖时由 Rod launcher 定位/下载固定 revision。
    # 不复用 Playwright 浏览器，避免实际内核与上游启动链发生漂移。
    return ""


def _select_proxy(proxy: str | None) -> str:
    if not bool(getattr(_cfg, "LOCAL_BROWSER_USE_PROXY", True)):
        return ""
    if proxy is None:
        try:
            from config.proxy import pick_proxy

            proxy = pick_proxy()
        except Exception:
            proxy = ""
    return normalize_proxy_url(proxy)


def _prepare_proxy(proxy: str) -> tuple[str, _Socks5AuthBridge | None]:
    parsed = _playwright_proxy(proxy)
    if not parsed:
        return "", None
    server = str(parsed.get("server") or "")
    has_auth = parsed.get("username") is not None or parsed.get("password") is not None
    if server.startswith("socks5://") and has_auth:
        bridge = _Socks5AuthBridge(parsed)
        bridge.start()
        logger.info(
            "[本机Rod] 已启用 SOCKS5 认证桥：local=%s upstream=%s",
            bridge.server,
            server,
        )
        return bridge.server, bridge
    # Rod/Chromium 不接受 socks5h scheme。无认证代理无需桥接，但仍要
    # 仅在运行时转换，不能把这个值作为账号的持久化代理保存。
    return _normalize_proxy(proxy), None


def _stop_poll_interval() -> float:
    try:
        configured = float(
            getattr(_cfg, "LOCAL_BROWSER_STOP_POLL_INTERVAL", 0.25) or 0.25
        )
    except (TypeError, ValueError):
        configured = 0.25
    return max(0.05, min(2.0, configured))


def _raise_if_job_stopped(job_id: int | None) -> None:
    if not job_id:
        return
    try:
        from core import registration_service

        requested = registration_service.is_stop_requested(int(job_id))
    except Exception:
        logger.debug("[本机Rod] 检查任务停止状态失败: job_id=%s", job_id, exc_info=True)
        return
    if requested:
        raise registration_service.StopRequested(f"任务 #{job_id} 已被用户手动停止")


@contextmanager
def _local_browser_slot(job_id: int | None):
    _LOCAL_BROWSER_LIMITER.acquire(job_id)
    try:
        yield
    finally:
        _LOCAL_BROWSER_LIMITER.release()


def _write_event(proc: subprocess.Popen, value: dict) -> None:
    if proc.stdin is None:
        raise RuntimeError("Rod helper stdin 不可用")
    proc.stdin.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")
    proc.stdin.flush()


def _request_helper_stop(proc: subprocess.Popen, job_id: int | None = None) -> None:
    try:
        _write_event(proc, {"type": "stop", "job_id": job_id})
    except Exception:
        pass
    if proc.stdin is not None:
        try:
            proc.stdin.close()
        except Exception:
            pass


def _wait_process(proc: subprocess.Popen, timeout: float) -> bool:
    try:
        proc.wait(timeout=max(0.01, timeout))
        return True
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return proc.poll() is not None


def _signal_process_group(
    proc: subprocess.Popen,
    *,
    process_group_id: int | None,
    force: bool,
) -> None:
    if os.name == "nt":
        args = ["taskkill", "/PID", str(proc.pid), "/T"]
        if force:
            args.append("/F")
        try:
            subprocess.run(
                args,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except Exception:
            try:
                proc.kill() if force else proc.terminate()
            except Exception:
                pass
        return

    pgid = int(process_group_id or 0)
    if pgid <= 0:
        return
    try:
        os.killpg(pgid, signal.SIGKILL if force else signal.SIGTERM)
    except ProcessLookupError:
        pass
    except Exception:
        logger.debug(
            "[本机Rod] %s helper 进程组失败: pgid=%s",
            "强制清理" if force else "终止",
            pgid,
            exc_info=True,
        )


def _process_group_alive(process_group_id: int | None) -> bool:
    if os.name == "nt" or not process_group_id:
        return False
    try:
        os.killpg(int(process_group_id), 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        logger.debug(
            "[本机Rod] 检查 helper 进程组失败: pgid=%s",
            process_group_id,
            exc_info=True,
        )
        return False


def _wait_process_group_exit(process_group_id: int | None, timeout: float) -> bool:
    deadline = time.monotonic() + max(0.0, float(timeout or 0.0))
    while _process_group_alive(process_group_id):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.05, remaining))
    return True


def _stop_process(
    proc: subprocess.Popen,
    *,
    process_group_id: int | None = None,
    job_id: int | None = None,
) -> None:
    """停止 helper 及其 Chromium 子进程，并等待进程句柄完成回收。"""

    try:
        grace = float(
            getattr(_cfg, "LOCAL_BROWSER_TERMINATE_GRACE_SECONDS", 3.0) or 3.0
        )
    except (TypeError, ValueError):
        grace = 3.0
    grace = max(0.2, min(15.0, grace))

    if proc.poll() is None:
        _request_helper_stop(proc, job_id)
        if not _wait_process(proc, min(0.2, grace)):
            _signal_process_group(
                proc,
                process_group_id=process_group_id,
                force=False,
            )
            if not _wait_process(proc, grace):
                _signal_process_group(
                    proc,
                    process_group_id=process_group_id,
                    force=True,
                )
                if not _wait_process(proc, max(1.0, grace)):
                    try:
                        proc.kill()
                    finally:
                        proc.wait(timeout=2)
    if os.name != "nt" and process_group_id and _process_group_alive(process_group_id):
        # helper 可能在入口前或 stop/EOF 后先退出，而 Chromium 子进程仍留在
        # 原进程组。无论 helper 何时结束，都检查整个专属组并兜底清理。
        _signal_process_group(
            proc,
            process_group_id=process_group_id,
            force=False,
        )
        if not _wait_process_group_exit(process_group_id, grace):
            _signal_process_group(
                proc,
                process_group_id=process_group_id,
                force=True,
            )
            _wait_process_group_exit(process_group_id, max(0.2, min(1.0, grace)))


def _wait_for_otp_interruptibly(
    email: str,
    *,
    job_id: int | None,
    otp_kwargs: dict[str, object],
) -> str:
    """等信放到 daemon 线程，主监管线程继续响应任务停止。"""

    if not job_id:
        return str(wait_for_otp(email, **otp_kwargs) or "").strip()

    result_queue: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

    def fetch() -> None:
        from core import registration_service

        thread_ctx = registration_service._THREAD_CTX
        had_job_id = hasattr(thread_ctx, "job_id")
        previous_job_id = getattr(thread_ctx, "job_id", None)
        thread_ctx.job_id = int(job_id)
        try:
            try:
                result_queue.put((True, wait_for_otp(email, **otp_kwargs)))
            except BaseException as exc:  # 在线程边界原样转交给监管线程
                result_queue.put((False, exc))
        finally:
            if had_job_id:
                thread_ctx.job_id = previous_job_id
            else:
                try:
                    del thread_ctx.job_id
                except AttributeError:
                    pass

    threading.Thread(
        target=fetch,
        name=f"rod-otp-{int(job_id)}",
        daemon=True,
    ).start()
    while True:
        _raise_if_job_stopped(job_id)
        try:
            ok, value = result_queue.get(timeout=_stop_poll_interval())
        except queue.Empty:
            continue
        if ok:
            return str(value or "").strip()
        if isinstance(value, BaseException):
            raise value
        raise RuntimeError(str(value or "OTP 获取失败"))


def _post_auth_settle_seconds() -> float:
    try:
        value = float(
            getattr(_cfg, "LOCAL_BROWSER_POST_AUTH_SETTLE_SECONDS", 5.0)
        )
    except (TypeError, ValueError):
        value = 5.0
    if not math.isfinite(value):
        value = 5.0
    return max(0.0, min(5.0, value))


def _normalize_post_auth_observation(value: object) -> dict:
    """Whitelist the helper's observability-only result before persistence."""

    if not isinstance(value, dict):
        return {}
    result: dict[str, object] = {}
    for key in (
        "completed",
        "window_exhausted",
        "final_accounts_check_seen",
        "pricing_seen",
        "sentinel_prepare_seen",
        "sentinel_finalize_seen",
    ):
        if isinstance(value.get(key), bool):
            result[key] = value[key]
    for key in (
        "accounts_check_count",
        "pricing_status",
        "sentinel_prepare_status",
        "sentinel_finalize_status",
    ):
        raw = value.get(key)
        if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0:
            result[key] = raw
    raw_seconds = value.get("settle_seconds")
    if isinstance(raw_seconds, (int, float)) and not isinstance(raw_seconds, bool):
        seconds = float(raw_seconds)
        if math.isfinite(seconds):
            result["settle_seconds"] = max(0.0, min(5.0, seconds))
    return result


def _run_rod_helper(
    *,
    email: str,
    password: str,
    name: str,
    age: str,
    birthday: str,
    proxy: str,
    otp_after_ts: float,
    otp_code: str | None = None,
    helper_path: str | Path | None = None,
    browser_bin: str | Path | None = None,
    cache_dir: str | Path | None = None,
    job_id: int | None = None,
) -> tuple[dict, list[dict] | None, bool, dict]:
    helper = _resolve_helper_path(helper_path)
    browser = _resolve_browser_binary(browser_bin)
    timeout = max(
        120.0,
        float(getattr(_cfg, "LOCAL_BROWSER_PROCESS_TIMEOUT", 900) or 900),
    )
    process_options: dict[str, object] = {}
    if os.name == "nt":
        process_options["creationflags"] = getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    else:
        process_options["start_new_session"] = True
    proc = subprocess.Popen(
        [str(helper)],
        cwd=str(_PROJECT_ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        env=build_subprocess_env(),
        **process_options,
    )
    process_group_id = proc.pid if os.name != "nt" else None
    events: queue.Queue[str | None] = queue.Queue()

    def read_output() -> None:
        try:
            if proc.stdout is not None:
                for line in proc.stdout:
                    events.put(line.rstrip("\r\n"))
        finally:
            events.put(None)

    output_thread = threading.Thread(
        target=read_output,
        name="rod-helper-output",
        daemon=True,
    )
    output_thread.start()
    progress = RodHelperProgress()
    otp_request_after_ts = float(otp_after_ts)
    max_otp_requests = max(
        1,
        int(getattr(_cfg, "LOCAL_BROWSER_MAX_OTP_REQUESTS", 3) or 3),
    )
    deadline = time.monotonic() + timeout
    try:
        _write_event(proc, {
            "type": "start",
            "job_id": job_id,
            "email": email,
            "password": password,
            "full_name": name,
            "age": age,
            "birthday": birthday,
            "proxy": proxy,
            "headless": bool(getattr(_cfg, "LOCAL_BROWSER_HEADLESS", True)),
            "browser_bin": browser,
            "cache_dir": str(cache_dir or ""),
            "cache_size_mb": max(
                16,
                int(getattr(_cfg, "LOCAL_BROWSER_DISK_CACHE_SIZE_MB", 256) or 256),
            ),
            "strict_exit_country": bool(
                getattr(_cfg, "LOCAL_BROWSER_STRICT_EXIT_COUNTRY", True)
            ),
            "expected_country": str(
                getattr(_cfg, "LOCAL_BROWSER_EXPECTED_COUNTRY", "JP") or ""
            ).strip().upper(),
            "post_auth_settle_seconds": _post_auth_settle_seconds(),
        })
        logger.info(
            "[本机Rod] helper 已启动：headless=%s chromium=%s upstream=%s",
            bool(getattr(_cfg, "LOCAL_BROWSER_HEADLESS", True)),
            browser or "Rod 自动管理",
            _UPSTREAM_COMMIT[:7],
        )
        while True:
            try:
                _raise_if_job_stopped(job_id)
            except Exception:
                _request_helper_stop(proc, job_id)
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Rod 注册 helper 运行超时（{timeout:.0f}s）")
            try:
                line = events.get(timeout=min(_stop_poll_interval(), remaining))
            except queue.Empty:
                if proc.poll() is not None:
                    raise RuntimeError(f"Rod helper 提前退出: exit={proc.returncode}")
                continue
            if line is None:
                if proc.poll() is None:
                    continue
                raise RuntimeError(f"Rod helper 未返回结果: exit={proc.returncode}")
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError:
                # Rod 首次下载固定 revision Chromium 时直接向 stdout 输出进度。
                logger.info("[本机Rod][launcher] %s", line[:500])
                continue
            if not isinstance(event, dict):
                continue
            event_type = str(event.get("type") or "")
            if event_type == "log":
                logger.info("[本机Rod] %s", str(event.get("message") or ""))
                continue
            if event_type == "stage":
                stage = str(event.get("stage") or "").strip().lower()
                progress.observe_stage(stage)
                if stage == "otp_resend_requested":
                    otp_request_after_ts = time.time()
                continue
            if event_type == "otp_required":
                progress.otp_requests += 1
                try:
                    event_after_ts = float(event.get("after_ts") or 0.0)
                except (TypeError, ValueError):
                    event_after_ts = 0.0
                if event_after_ts > 0:
                    otp_request_after_ts = event_after_ts
                if progress.otp_requests > max_otp_requests:
                    raise RuntimeError(
                        f"Rod helper 请求 OTP 超过上限 {max_otp_requests} 次"
                    )
                code = (
                    str(otp_code or "").strip()
                    if progress.otp_requests == 1
                    else ""
                )
                try:
                    if not code:
                        logger.info(
                            "[本机Rod] 从邮箱读取验证码：%s（第 %s/%s 次）",
                            email,
                            progress.otp_requests,
                            max_otp_requests,
                        )
                        otp_kwargs: dict[str, object] = {"after_ts": otp_request_after_ts}
                        if progress.submitted_otp_codes:
                            otp_kwargs["exclude_codes"] = set(
                                progress.submitted_otp_codes
                            )
                        code = _wait_for_otp_interruptibly(
                            email,
                            job_id=job_id,
                            otp_kwargs=otp_kwargs,
                        )
                    if not code:
                        raise RuntimeError("未获取到验证码")
                    _write_event(proc, {"type": "otp", "code": code})
                    progress.submitted_otp_codes.add(code)
                except Exception as exc:
                    try:
                        _write_event(proc, {"type": "otp", "error": str(exc)[:300]})
                    except Exception:
                        pass
                    raise
                continue
            if event_type == "result":
                progress.observe_stage(event.get("stage"))
                if bool(event.get("email_consumed")):
                    progress.otp_accepted = True
                if not bool(event.get("ok")):
                    raise RuntimeError(str(event.get("error") or "Rod helper 注册失败"))
                session = event.get("session")
                if not isinstance(session, dict):
                    raise RuntimeError("Rod helper 未返回 session 对象")
                access_token = str(session.get("accessToken") or "").strip()
                if not access_token:
                    raise RuntimeError("Rod helper session 缺少 accessToken")
                # Even an old helper can return a real account without having
                # submitted its generated password. Never save that password or
                # return the now-consumed email to the allocation pool.
                progress.observe_stage("otp_accepted")
                if event.get("password_confirmed") is not True:
                    progress.observe_stage("password_unconfirmed")
                    raise RuntimeError(
                        "Rod helper 未确认注册密码，已阻止保存未生效密码；"
                        "请确认使用已更新的 tools/rod_register helper"
                    )
                raw_web_cookies = event.get("web_cookies")
                if raw_web_cookies is not None and not isinstance(raw_web_cookies, list):
                    raise RuntimeError("Rod helper 返回的 web_cookies 格式错误")
                web_cookie_error = str(event.get("web_cookie_error") or "").strip()
                if web_cookie_error:
                    logger.warning(
                        "[本机Rod] Web Cookie 捕获失败，账号仍按成功保存：%s",
                        web_cookie_error[:300],
                    )
                raw_post_auth = event.get("post_auth")
                if raw_post_auth is not None and not isinstance(raw_post_auth, dict):
                    logger.warning("[本机Rod] 忽略格式错误的认证后观察结果")
                return (
                    session,
                    raw_web_cookies,
                    progress.profile_submitted,
                    _normalize_post_auth_observation(raw_post_auth),
                )
    except RodHelperError:
        raise
    except Exception as exc:
        raise RodHelperError(
            str(exc) or type(exc).__name__,
            progress=progress,
            cause=exc,
        ) from exc
    finally:
        _stop_process(
            proc,
            process_group_id=process_group_id,
            job_id=job_id,
        )
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass
        output_thread.join(timeout=1)


def run_local_browser_registration(
    email: str,
    name: str,
    birthday: str,
    proxy: str = None,
    otp_code: str = None,
    batch_dir: Path | None = None,
    codex_oauth: bool | None = None,
    job_id: int | None = None,
) -> dict:
    """运行上游 Rod Web 注册；Codex OAuth 仍由任务服务在独立会话中执行。"""
    helper_progress = RodHelperProgress()
    post_auth_observation: dict = {}
    proxy_bridge = None
    selected_proxy = ""
    registration_password = generate_openai_registration_password(length=16)
    try:
        with _local_browser_slot(job_id), _local_browser_cache_slot(job_id) as cache_dir:
            selected_proxy = _select_proxy(proxy)
            max_attempts = max(
                1,
                int(getattr(_cfg, "LOCAL_BROWSER_MAX_ATTEMPTS", 2) or 2),
            )
            for attempt in range(1, max_attempts + 1):
                if attempt > 1:
                    selected_proxy = _next_local_browser_proxy(
                        selected_proxy,
                        allow_pool_pick=proxy is None,
                    )
                attempt_progress = RodHelperProgress()
                proxy_bridge = None
                try:
                    helper_proxy, proxy_bridge = _prepare_proxy(selected_proxy)
                    otp_after_ts = time.time()
                    logger.info(
                        "[本机Rod注册] 开始：%s（尝试 %s/%s）",
                        email,
                        attempt,
                        max_attempts,
                    )
                    session_info, web_cookies, profile_submitted, post_auth_observation = _run_rod_helper(
                        email=email,
                        password=registration_password,
                        name=name,
                        age=_age_from_birthday(birthday),
                        birthday=birthday,
                        proxy=helper_proxy,
                        otp_after_ts=otp_after_ts,
                        otp_code=otp_code if attempt == 1 else None,
                        cache_dir=cache_dir,
                        job_id=job_id,
                    )
                    # 非空 accessToken 是邮箱/账号已消费的运行时真值。即使后续
                    # 保存账号失败或该分支没有资料页，也不能把邮箱恢复 available。
                    helper_progress.observe_stage("otp_accepted")
                    helper_progress.profile_submitted = bool(profile_submitted)
                    break
                except RodHelperError as exc:
                    attempt_progress = exc.progress
                    helper_progress = attempt_progress
                    if attempt >= max_attempts or not _is_retryable_local_browser_error(exc):
                        raise
                    delay = max(
                        0.0,
                        float(getattr(_cfg, "LOCAL_BROWSER_RETRY_DELAY", 2.0) or 0.0),
                    )
                    logger.warning(
                        "[本机Rod注册] 可恢复失败，将换新浏览器会话重试：attempt=%s/%s stage=%s error=%s",
                        attempt,
                        max_attempts,
                        attempt_progress.stage or "startup",
                        str(exc)[:240],
                    )
                    _stop_proxy_bridge(proxy_bridge)
                    proxy_bridge = None
                    _sleep_with_stop(delay, job_id)
                finally:
                    _stop_proxy_bridge(proxy_bridge)
                    proxy_bridge = None
        access_token = str(session_info["accessToken"])
        logger.info("[本机Rod注册] 已拿到 Web accessToken：%s", email)

        codex_result = {
            "status": "skipped",
            "ok": True,
            "message": "基础注册不内嵌 Codex；任务服务按接码开关使用独立 OAuth 会话",
        }
        metadata = {
            "driver": "local_browser",
            "engine": "go-rod",
            "stealth": "github.com/go-rod/stealth@v0.4.9",
            "upstream": f"cyi-cc/chatgpt-register@{_UPSTREAM_COMMIT}",
            "headless": bool(getattr(_cfg, "LOCAL_BROWSER_HEADLESS", True)),
            "proxy": selected_proxy or None,
            "post_auth": post_auth_observation,
            "password_confirmed": True,
        }
        account_id = save_account_data(
            email=email,
            access_token=access_token,
            totp_secret=None,
            email_source=resolve_email_source(email),
            proxy_used=selected_proxy or None,
            batch_dir=batch_dir,
            web_cookies=web_cookies,
            web_cookie_source="local_browser",
            extra={
                "user": session_info.get("user"),
                "account": session_info.get("account"),
                "expires": session_info.get("expires"),
                "local_browser": metadata,
                "registration_password": registration_password,
                "codex": codex_result,
            },
        )
        return {
            "success": True,
            "email": email,
            "account_id": account_id,
            "access_token": access_token,
            "totp_secret": None,
            "codex": codex_result,
            "error": None,
            "email_consumed": True,
            "email_verified": True,
            "profile_submitted": helper_progress.profile_submitted,
            "post_auth": post_auth_observation,
        }
    except Exception as exc:
        if isinstance(exc, RodHelperError):
            helper_progress = exc.progress
            original = exc.cause or exc
        else:
            original = exc
        error_type = type(original).__name__
        logger.error("[本机Rod注册] 失败：%s: %s", error_type, exc)
        logger.debug("[本机Rod注册] 失败详情", exc_info=True)
        email_consumed = helper_progress.email_consumed
        email_reusable = helper_progress.email_reusable
        release_status = "available" if email_reusable or not email_consumed else "failed"
        try:
            from core.email_provider import release_email

            release_email(
                email,
                status=release_status,
                note=f"本机Rod注册失败: {str(exc)[:180]}",
            )
        except Exception:
            pass
        return {
            "success": False,
            "email": email,
            "error": f"{error_type}: {str(exc)[:300]}",
            "failure_stage": helper_progress.stage or None,
            "email_consumed": email_consumed,
            "email_reusable": email_reusable,
            "email_verified": helper_progress.otp_accepted,
            "profile_submitted": helper_progress.profile_submitted,
        }
    finally:
        _stop_proxy_bridge(proxy_bridge)
