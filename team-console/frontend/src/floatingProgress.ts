import { matchesTaskFilter, taskRows } from './taskHierarchy.ts';
import { jobKey } from './jobProgress.ts';
import type { JobRow } from './jobProgress';
import type { Jobs } from './types';

export function floatingTaskModel(data: Jobs | undefined, recentLimit = 3, expandedKey?: string) {
  const tasks = taskRows(data);
  const active = tasks.filter(row => matchesTaskFilter(row, 'active'));
  const recent = tasks.filter(row => !matchesTaskFilter(row, 'active')).sort((a, b) =>
    (Date.parse(b.updated_at || b.created_at || '') || 0) - (Date.parse(a.updated_at || a.created_at || '') || 0));
  // Root submissions only, never the recent per-account pipeline. Keep every
  // active task; the compact panel scrolls instead of dropping pending work.
  const rows = [...active, ...recent.slice(0, Math.max(0, recentLimit))];
  const expanded = tasks.find(row => jobKey(row) === expandedKey);
  // Keep an open result visible when other tasks finish and push it past the
  // recent-three window. Do not pin a snapshot after the backend removes it.
  if (expanded && !rows.some(row => jobKey(row) === expandedKey)) rows.push(expanded);
  return { tasks, activeCount: active.length, rows };
}

export function toggleFloatingTask(current: string | undefined, next: string): string | undefined {
  return current === next ? undefined : next;
}

export function floatingTaskProgress(row: JobRow) {
  const total = Number.isFinite(row.total) ? Math.max(0, Math.floor(row.total!)) : 0;
  const finished = Number.isFinite(row.completed) ? Math.min(total, Math.max(0, Math.floor(row.completed!))) : 0;
  const active = matchesTaskFilter(row, 'active');
  const status = row.status === 'success' ? 'success' : !active ? 'exception' : 'normal';
  return { total, finished, percent: total ? Math.floor(finished * 100 / total) : undefined, status } as const;
}
