"""Optional, process-local observability. Never carries credentials or changes work.

Listeners must only signal/coalesce; no business I/O or storage reads in callbacks.
Legacy hosts have no subscribers. A failed observer must never fail authorization.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from threading import RLock

_lock = RLock()
_listeners = set()
_job = ContextVar('progress_job', default=None)
PHASES = {
    'starting': '开始执行', 'credentials': '读取登录资料', 'session_init': '建立会话',
    'network_preflight': '检查代理连接', 'bootstrap': '初始化授权', 'email_submit': '提交账号',
    'password': '验证密码', 'mfa': '验证 2FA', 'workspace': '选择并确认工作区',
    'token_exchange': '交换授权凭证', 'save_credential': '保存新凭证',
    'persisting': '保存本次授权结果', 'retrying': '等待重试',
}


def subscribe(callback):
    with _lock:
        _listeners.add(callback)
    def unsubscribe():
        with _lock:
            _listeners.discard(callback)
    return unsubscribe


def notify(topic, job_id=None, phase=None):
    if topic not in {'job', 'phase', 'pipeline', 'team', 'runtime'}:
        return
    if topic == 'phase' and (type(job_id) is not int or job_id <= 0 or phase not in PHASES):
        return
    with _lock:
        listeners = tuple(_listeners)
    for callback in listeners:
        try:
            callback(topic, job_id, phase)
        except Exception:
            pass  # Observability must not change a business result or retry.


@contextmanager
def job_context(job_id):
    token = _job.set(job_id if type(job_id) is int and job_id > 0 else None)
    try:
        yield
    finally:
        _job.reset(token)


def phase(value):
    notify('phase', _job.get(), value)
