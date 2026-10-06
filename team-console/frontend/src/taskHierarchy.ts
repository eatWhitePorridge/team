// Presentation-only grouping: one submission is one task, retries remain inside it.
import type { AuthorizationBatch, Job, Jobs } from './types';
import type { JobRow } from './jobProgress';

const active = new Set(['pending', 'queued', 'running', 'retrying', 'confirming', 'stopping']);
const terminal = new Set(['success', 'failed', 'cancelled']);

export function authorizationTaskStatus(batch: AuthorizationBatch): string {
  if (batch.active > 0) return batch.queued === batch.active ? 'queued' : 'running';
  if (!batch.total || batch.finished !== batch.total || (batch.known ?? batch.total) < batch.total) return 'incomplete';
  const success = batch.success || 0, failed = batch.failed || 0, cancelled = batch.cancelled || 0;
  if (success + failed + cancelled !== batch.total) return 'incomplete';
  if (failed) return failed === batch.total ? 'failed' : 'partial_failed';
  if (cancelled) return cancelled === batch.total ? 'cancelled' : 'partial_cancelled';
  return 'success';
}

export function authorizationCounts(batch: AuthorizationBatch): string {
  return `成功 ${batch.success || 0} · 失败 ${batch.failed || 0}` + (batch.cancelled ? ` · 取消 ${batch.cancelled}` : '');
}

export function authorizationActivity(batch: AuthorizationBatch): string {
  return `执行 ${batch.running || 0} · 排队 ${batch.queued || 0} · 重试 ${batch.retrying || 0}`
    + (batch.confirming ? ` · 确认 ${batch.confirming}` : '');
}

export function taskRows(data: Jobs | undefined): JobRow[] {
  const names: Record<string, string> = { discover: '同步母号', invite: '邀请成员', invites: '同步邀请',
    switch: '成员切席', invite_switch: '邀请切席', remove: '移除成员', schedule: '母号调度' };
  const tasks: JobRow[] = (data?.authorization || []).filter(batch => !!batch.batch_id).map(batch => ({
    id: batch.batch_id, batch_id: batch.batch_id, source: 'authorization', authorization_batch: batch,
    type: batch.team_authorization ? 'Team 授权' : '普通授权', status: authorizationTaskStatus(batch),
    total: batch.total, completed: batch.finished, created_at: batch.created_at, updated_at: batch.updated_at,
    expected_workspace_id: batch.expected_workspace_id,
    message: batch.active ? authorizationActivity(batch) : authorizationCounts(batch),
  }));
  tasks.push(...(data?.team || []).map((row): JobRow => ({ ...row, source: 'team', type: names[row.kind || ''] || '母号操作' })));
  return tasks.sort((a, b) => Number(active.has(b.status || '')) - Number(active.has(a.status || ''))
    || (Date.parse(b.created_at || '') || 0) - (Date.parse(a.created_at || '') || 0)
    || a.id.localeCompare(b.id));
}

export function matchesTaskFilter(row: JobRow, filter: string): boolean {
  if (filter === 'active') return active.has(row.status || '');
  if (filter === 'failed') return !!(row.authorization_batch?.failed || row.authorization_batch?.cancelled)
    || (!active.has(row.status || '') && row.status !== 'success');
  return true;
}

function fresher(before: Job | undefined, next: Job): Job {
  if (!before) return next;
  // A completed coordinator row cannot start again; a new submission has a new ID.
  if (terminal.has(before.status || '') !== terminal.has(next.status || '')) return terminal.has(next.status || '') ? next : before;
  const attempt = (next.codex_attempt_count || 0) - (before.codex_attempt_count || 0);
  if (attempt) return attempt > 0 ? next : before;
  const changed = (next.updated_at || '').localeCompare(before.updated_at || '');
  if (changed) return changed > 0 ? next : before;
  if (next.codex_job_id === before.codex_job_id && next.progress_status !== before.progress_status) {
    if (next.progress_status === 'confirming') return next;
    if (before.progress_status === 'confirming') return before;
  }
  const phase = (Date.parse(next.progress_updated_at || '') || 0) - (Date.parse(before.progress_updated_at || '') || 0);
  return phase < 0 ? before : next;
}

export function mergeAuthorizationItems(previous: readonly Job[], fetched: readonly Job[], live: readonly Job[], batchId: string): Job[] {
  const byId = new Map<string, Job>();
  for (const row of [...previous, ...fetched, ...live]) {
    if (row.batch_id === batchId) byId.set(row.id, fresher(byId.get(row.id), row));
  }
  // Keep completed rows locally when the global recent-100 SSE window advances.
  return [...byId.values()].sort((a, b) => (a.account_id || 0) - (b.account_id || 0) || a.id.localeCompare(b.id));
}

export function authorizationItems(rows: readonly Job[], query: string, filter: string): Job[] {
  const search = query.trim().toLowerCase();
  return rows.filter(row => (!search || (row.email || '').toLowerCase().includes(search) || String(row.account_id || '').includes(search))
    && (filter === 'active' ? active.has(row.progress_status || row.status || '')
      : filter === 'success' ? row.status === 'success'
        : filter === 'failed' ? ['failed', 'cancelled'].includes(row.status || '') : true));
}
