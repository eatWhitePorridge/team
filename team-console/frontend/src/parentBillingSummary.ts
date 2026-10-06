import { BILLING_TIME_LABEL, billingTime, workspaceBillingView } from './billingTime.ts';
import type { Parent } from './types';

/** Cached invoice dates only; the navigator never starts a remote lookup. */
export function parentBillingView(parent: Pick<Parent, 'workspace_count' | 'billing_workspaces'>) {
  const entries = (parent.billing_workspaces || []).map(workspace => ({
    workspace,
    time: workspaceBillingView({ id: workspace.id, renewal_date: workspace.renewal_date,
      billing_renewal_date: workspace.billing_renewal_date }).renewal,
  }));
  const valid = entries.filter(entry => entry.time.state === 'valid')
    .sort((a, b) => a.time.epoch! - b.time.epoch! || a.workspace.id.localeCompare(b.workspace.id));
  // Retain the earliest cached date even if past due. Selecting only future
  // dates would hide an overdue workspace. Unknown zones cannot be compared.
  const selected = valid[0] || entries.find(entry => entry.time.state !== 'missing')
    || entries.find(entry => entry.workspace.query_failed) || entries[0];
  const time = selected?.time || billingTime(undefined);
  const count = Math.max(parent.workspace_count || 0, entries.length);
  const partial = valid.length > 0 && valid.length < count;
  const stale = !!selected?.workspace.query_failed && time.state !== 'missing';
  const label = valid.length && count > 1 ? '最早账单' : '账单';
  const text = time.state === 'missing' && selected?.workspace.query_failed ? '查询失败' : time.text;
  const note = [partial && '部分结果', stale && '上次结果'].filter(Boolean).join(' · ');
  const details = entries.map(({ workspace, time: value }) => {
    const date = value.state === 'valid' ? `${value.text}（${BILLING_TIME_LABEL}）`
      : value.state === 'date_only' ? `${value.text}（时区未提供）`
      : value.state === 'missing' && workspace.query_failed ? '查询失败' : value.text;
    return `${workspace.name || workspace.id}：${date}${workspace.query_failed && value.state !== 'missing' ? ' · 上次结果' : ''}`;
  }).join('\n');
  return { label, time, text, note, details };
}
