import type { AuthorizationBatch, Job, Jobs } from './types';

const activeStatuses = new Set(['queued', 'running', 'retrying', 'pending', 'stopping']);

export function jobsPollInterval(data: Jobs | undefined): number {
  const active = data?.authorization.some((row) => row.active > 0)
    || data?.pipeline.some((row) => activeStatuses.has(row.status || ''))
    || data?.team.some((row) => activeStatuses.has(row.status || ''))
    || (data?.runtime?.running || 0) > 0 || (data?.runtime?.queued || 0) > 0;
  return active ? 1000 : 5000;
}

export interface JobRow extends Job { source: 'authorization' | 'team'; type: string; authorization_batch?: AuthorizationBatch }
export function jobRows(data: Jobs | undefined): JobRow[] {
  return [
    ...(data?.pipeline || []).map((row): JobRow => ({ ...row, source: 'authorization', type: row.team_authorization ? 'Team 授权' : '普通授权' })),
    ...(data?.team || []).map((row): JobRow => ({ ...row, source: 'team', type: row.kind === 'invite_switch' ? '邀请切席' : row.kind === 'invites' ? '同步邀请' : '母号操作' })),
  ];
}
export function jobKey(row: JobRow): string { return row.source + ':' + row.id; }
export function canCancelSeatJob(row: JobRow | undefined): boolean {
  return !!row && row.source === 'team' && ['switch', 'invite_switch'].includes(row.kind || '')
    && ['queued', 'running'].includes(row.status || '') && !row.cancel_requested;
}
export function findJob(rows: JobRow[], key: string | undefined): JobRow | undefined {
  return key === undefined ? undefined : rows.find((row) => jobKey(row) === key);
}
