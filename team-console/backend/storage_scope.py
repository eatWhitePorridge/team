"""Bind reused business code to this console's own data, before workers start.

Only Python module attributes in this process are changed. No legacy files are
moved, copied, deleted or rewritten. Run this console as a separate process.
"""
from __future__ import annotations

import os
from pathlib import Path

CONSOLE_ROOT = Path(__file__).resolve().parents[1]


def data_directory():
    configured = os.getenv('TEAM_CONSOLE_DATA_DIR', '').strip()
    path = Path(configured).expanduser() if configured else CONSOLE_ROOT / 'data/store'
    return (path if path.is_absolute() else CONSOLE_ROOT / path).resolve()


def bind_database(db, directory):
    directory = Path(directory).resolve()
    bound = getattr(db, '_TEAM_CONSOLE_STORE_PATH', None)
    if bound is not None:
        if Path(bound) != directory:
            raise RuntimeError('当前进程已绑定其他数据目录，请使用独立进程')
        return directory
    original_base = Path(db._PROJECT_ROOT)
    original_root = original_base.resolve()
    if directory == original_root or original_root.is_relative_to(directory):
        raise ValueError('新后台的数据目录不能使用旧项目根目录或其上级')
    if getattr(db, '_JSON_CACHE', {}):
        raise RuntimeError('业务存储已被使用，不能在当前进程内切换数据目录')
    replacements = {}
    for name, value in vars(db).items():
        if not name.startswith('_') or not name.isupper() or not isinstance(value, Path):
            continue
        try:
            relative = value.relative_to(original_base)
        except ValueError:
            continue
        target = directory / relative
        if not target.resolve().is_relative_to(directory):
            raise ValueError('数据目录含有指向目录外的链接，拒绝加载')
        replacements[name] = target
    required = {'_PROJECT_ROOT', '_DATA_DIR', '_ACCOUNTS_JSON', '_BATCHES_JSON', '_JOBS_JSON', '_COOKIE_DIR', '_CODEX_DIR'}
    if not required.issubset(replacements):
        raise RuntimeError('存储接口不完整，未绑定数据目录')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Create only missing files. Later restarts retain newly imported accounts.
    for name in ('注册成功的邮箱.json', '注册批次.json', '注册任务.json', '一键补全任务.json'):
        path = directory / name
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write('[]\n')
    for name, value in replacements.items():
        setattr(db, name, value)
    db._TEAM_CONSOLE_STORE_PATH = directory
    db._TEAM_CONSOLE_ORIGINAL_ROOT = original_root
    return directory


def bind_service_paths(directory, *, completion, retry, oauth, cookies, diagnostics, account_export):
    directory = Path(directory)
    bound = getattr(completion, '_TEAM_CONSOLE_STORE_PATH', None)
    if bound is not None:
        if Path(bound) != directory:
            raise RuntimeError('业务服务已绑定其他数据目录，请使用独立进程')
        return
    # These modules define separate constants instead of referring to core.db.
    completion._STATE_PATH = directory / '一键补全任务.json'
    completion._STATE_CACHE = None
    retry._LOG_DIR = directory / '注册日志'
    oauth._PROJECT_ROOT = directory
    oauth._cfg.CODEX_OUTPUT_DIRNAME = 'codex_accounts'
    cookies._PROJECT_ROOT = directory
    cookies._DEFAULT_COOKIE_DIR = directory / 'account_cookies'
    diagnostics._LOG_PATH = directory / '注册日志/http-diagnostics/403.jsonl'
    account_export._PROJECT_ROOT = directory
    account_export._ACCOUNTS_DIR = directory / 'accounts'
    completion._TEAM_CONSOLE_STORE_PATH = directory
