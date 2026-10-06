"""Confirmed import-batch operations; shared business data stays authoritative."""
from __future__ import annotations

import logging

from .account_deletion import busy_accounts
from .index_store import safe_batch_projection

logger = logging.getLogger(__name__)


class BatchOperationError(ValueError):
    def __init__(self, message, *, status=409, busy=None):
        super().__init__(message)
        self.status, self.busy = status, busy or []


def batch_ids(data, *, minimum=1):
    raw = data.get('batch_ids')
    if not isinstance(raw, list) or not minimum <= len(raw) <= 200:
        raise ValueError(f'请选择 {minimum}-200 个批次')
    if any(not isinstance(value, str) or not value.strip() or len(value) > 128 for value in raw):
        raise ValueError('批次 ID 必须是非空字符串，且不超过 128 字符')
    ids = list(dict.fromkeys(value.strip() for value in raw))
    if len(ids) < minimum:
        raise ValueError(f'请至少选择 {minimum} 个不同的批次')
    return ids


def _validate_scope(db, completion, selected, *, operation):
    by_id = {str(row.get('batch_id') or ''): row for row in db._load_batches()}
    if set(selected) - by_id.keys():
        raise BatchOperationError('部分批次不存在或已被合并，请刷新列表', status=404)
    if any(safe_batch_projection(by_id[key])['registration_drivers'] != ['imported'] for key in selected):
        raise BatchOperationError('此处仅支持账号导入批次，不能操作内部授权任务批次')
    selected_ids = set(selected)
    # Include archived accounts too, not only the visible account-list page.
    accounts = [int(row['id']) for row in db._load_accounts()
                if row.get('registration_batch_id') in selected_ids]
    busy = busy_accounts(db, completion, accounts, operation=operation)
    if busy:
        raise BatchOperationError(f'所选批次仍有进行中的账号任务，本次{operation}未执行', busy=busy)
    return accounts


def _update_index(operation):
    try:
        operation()
        return []
    except Exception as exc:
        # The business mutation already committed; never invite an automatic
        # replay just because the disposable read index needs another refresh.
        logger.warning('[Team Console] 批次操作后索引更新延迟: %s', type(exc).__name__)
        return [{'reason': '操作已完成，列表索引正在刷新，请勿重复提交'}]


def merge_batches(db, completion, selected, target, *, indexer):
    if not isinstance(target, str) or target.strip() not in selected:
        raise ValueError('请选择所选批次中的一个作为保留的目标批次')
    target = target.strip()
    with completion._LOCK, db._LOCK:
        _validate_scope(db, completion, selected, operation='合并')
        try:
            result = db.merge_registration_batches(target_batch_id=target, batch_ids=selected)
        except db.BatchMergeConflict as exc:
            raise BatchOperationError(str(exc)) from exc
        warnings = _update_index(lambda: indexer.apply_batch_merge(
            result, safe_batch_projection(db.get_registration_batch(target))))
    logger.info('[Team Console] 合并导入批次: batches=%s accounts=%s', result['merged_count'], result['moved_accounts'])
    return {'ok': True, **{key: result[key] for key in (
        'target_batch_id', 'merged_batch_ids', 'merged_count', 'moved_accounts', 'moved_jobs',
        'moved_allocations', 'already_merged')}, 'warnings': warnings}


def delete_batches(db, completion, selected, *, indexer):
    with completion._LOCK, db._LOCK:
        accounts = _validate_scope(db, completion, selected, operation='删除')
        try:
            result = db.delete_registration_batches(batch_ids=selected)
        except db.BatchDeleteConflict as exc:
            raise BatchOperationError(str(exc)) from exc
        warnings = _update_index(lambda: indexer.apply_batch_delete(result['deleted_batch_ids'], accounts))
    logger.info('[Team Console] 删除导入批次: batches=%s accounts=%s', result['deleted_count'], result['deleted_account_count'])
    return {'ok': True, **{key: result[key] for key in (
        'deleted_batch_ids', 'deleted_count', 'deleted_account_count', 'deleted_job_count',
        'deleted_allocation_count')}, 'warnings': warnings}


def split_accounts(db, completion, account_ids, request_id, *, indexer):
    with completion._LOCK, db._LOCK, indexer.membership_change():
        busy = busy_accounts(db, completion, account_ids, operation='拆分批次')
        if busy:
            raise BatchOperationError('所选账号仍有进行中的任务，本次拆分未执行', busy=busy)
        try:
            result = db.split_registration_batch(account_ids=account_ids, request_id=request_id)
        except db.BatchSplitConflict as exc:
            raise BatchOperationError(str(exc)) from exc
        except LookupError as exc:
            raise BatchOperationError(str(exc), status=404) from exc
        changed_ids = {*result['source_batch_ids'], result['batch_id']}
        warnings = _update_index(lambda: indexer.apply_batch_split(result, [
            safe_batch_projection(row) for row in db._load_batches() if row.get('batch_id') in changed_ids
        ]))
    logger.info('[Team Console] 拆分导入批次: accounts=%s already_split=%s',
                result['moved_accounts'], result['already_split'])
    return {'ok': True, **{key: result[key] for key in (
        'batch_id', 'source_batch_ids', 'moved_accounts', 'already_split')}, 'warnings': warnings}
