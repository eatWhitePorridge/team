"""Local account deletion only; never remove members or revoke remote accounts."""
from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)
ACTIVE = frozenset({'pending', 'queued', 'running', 'retrying', 'stopping'})


def _active_authorizations(completion):
    # Read the complete coordinator state, not the capped task-list API. A
    # failed attempt can be between retries with no active Codex job yet.
    # Unlike the scheduler's best-effort reader, fail closed on unreadable data.
    try:
        rows = json.loads(completion._STATE_PATH.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return set()
    except (OSError, ValueError) as exc:
        raise RuntimeError('无法确认授权任务状态，未执行账号变更') from exc
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise RuntimeError('授权任务状态格式无效，未执行账号变更')
    active = set()
    for row in rows:
        if str(row.get('status') or '').lower() in ACTIVE:
            account_id = row.get('account_id')
            if type(account_id) is not int or account_id <= 0:
                raise RuntimeError('授权任务账号信息无效，未执行账号变更')
            active.add(account_id)
    return active


def busy_accounts(db, completion, account_ids, *, operation='删除'):
    """Caller holds completion._LOCK then db._LOCK until its mutation ends."""
    active = _active_authorizations(completion)
    candidates = db.get_account_supplement_candidates(account_ids)
    busy = []
    for account_id in account_ids:
        account = candidates.get(account_id, {})
        reason = ''
        if account_id in active or str(account.get('codex_status') or '').lower() in ACTIVE:
            reason = f'账号授权仍在排队、执行或重试，请等待任务结束后再{operation}'
        else:
            for key, label in (('quota_busy', '额度查询'), ('team_busy', '补 Team'),
                               ('totp_busy', '2FA'), ('health_busy', '验活')):
                if account.get(key):
                    reason = f'账号的{label}任务尚未结束，请稍后再{operation}'
                    break
        if reason:
            busy.append({'id': account_id, 'email': account.get('email'), 'reason': reason})
    return busy


def delete_accounts(db, completion, account_ids, *, index):
    skipped, warnings = [], []
    # Match enqueue_accounts' lock order. Hold the DB lock through cache
    # invalidation, so a concurrent import cannot reuse an ID in this gap.
    with completion._LOCK, db._LOCK:
        skipped = busy_accounts(db, completion, account_ids)
        blocked = {row['id'] for row in skipped}
        eligible = [account_id for account_id in account_ids if account_id not in blocked]

        # One batch mutation, not N full JSON rewrites. The core operation also
        # rechecks linked active jobs and cleans scoped credentials / cookies.
        deleted, db_skipped = db.delete_accounts(account_ids=eligible) if eligible else ([], [])
        skipped.extend(db_skipped)
        # Whitelist the response; never return a raw account or its credentials.
        deleted = [{key: row[key] for key in ('id', 'email') if key in row} for row in deleted]
        skipped = [{key: row[key] for key in ('id', 'email', 'reason') if key in row} for row in skipped]
        if deleted:
            try:
                index.remove_accounts([row['id'] for row in deleted])
            except Exception as exc:
                # The deletion is already committed. Do not report a failure
                # that encourages repeating a destructive operation.
                logger.warning('[Team Console] 删除后索引更新延迟: %s', type(exc).__name__)
                warnings.append({'reason': '账号已删除，列表索引正在刷新，请勿重复删除'})

    logger.info('[Team Console] 删除本地账号: deleted=%s skipped=%s', len(deleted), len(skipped))
    result = {'ok': bool(deleted), 'deleted': deleted, 'deleted_count': len(deleted),
              'skipped': skipped, 'skipped_count': len(skipped), 'warnings': warnings}
    if not deleted:
        result['error'] = '没有账号被删除，请查看跳过原因'
    return result
