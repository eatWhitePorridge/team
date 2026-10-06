// Display projections only: missing data is never presented as a real zero.
export function metricCount(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : undefined;
}
export function coverage(value: unknown, total: unknown): number | undefined {
  const n = metricCount(value), all = metricCount(total);
  return n === undefined || all === undefined || all === 0 ? undefined : Math.max(0, Math.min(100, Math.floor(n * 100 / all)));
}
export function accountMetrics(stats?: Record<string, number>) {
  const total = metricCount(stats?.total), connected = metricCount(stats?.codex_connected);
  return { total, connected, totp: metricCount(stats?.totp_active), quota: metricCount(stats?.quota_checked),
    remaining: total !== undefined && connected !== undefined ? Math.max(0, total - connected) : undefined,
    coverage: coverage(connected, total) };
}
