import type { Quota } from './types';

function numeric(value: unknown): number | null {
  if ((typeof value !== 'number' && typeof value !== 'string') || (typeof value === 'string' && !value.trim())) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function windowLabel(value: unknown, fallback: string): string {
  const seconds = numeric(value);
  if (seconds === null || seconds <= 0) return fallback;
  if (seconds % 86400 === 0) return seconds / 86400 + ' 天';
  if (seconds % 3600 === 0) return seconds / 3600 + ' 小时';
  return seconds < 60 ? seconds + ' 秒' : Math.ceil(seconds / 60) + ' 分钟';
}

// Pure data formatting; never equate request success, absent data, or reset
// counts with a full allowance. Shared by accounts and matched Team members.
export function quotaPresentation(value: Quota) {
  const status = value.quota_status || 'unchecked';
  const success = ['success', 'active'].includes(status);
  const windows = (['primary', 'secondary'] as const).flatMap((name) => {
    const used = numeric(value[`quota_${name}_used_percent`]);
    if (used === null || used < 0) return [];
    const remaining = Math.max(0, Math.min(100, 100 - used));
    return [{ key: name, remaining, text: windowLabel(value[`quota_${name}_limit_window_seconds`], name === 'primary' ? '主窗口' : '次窗口') + ' · 剩余 ' + Number(remaining.toFixed(2)) + '%' }];
  });
  const unlimited = value.quota_credits_unlimited === true || value.quota_credits_unlimited === 1;
  const balance = numeric(value.quota_credits_balance);
  // Included rolling allowance remains primary; zero purchased credits does
  // not mean a regular 5h/7d account has zero remaining allowance.
  const showCredits = !windows.length || (value.quota_plan_type || '').includes('usage_based');
  const credits = showCredits ? (unlimited ? '点数不限量' : balance !== null ? '点数余额 ' + balance + ' credits' : null) : null;
  const hasData = windows.length > 0 || credits !== null;
  const limitation = success && (value.quota_limit_reached === true || value.quota_limit_reached === 1) ? '已达上限'
    : success && (value.quota_allowed === false || value.quota_allowed === 0) ? '当前不可用' : null;
  return { windows, credits, limitation, status: success ? null : status, previous: hasData && !success,
    missing: success && !hasData ? '暂无额度数据' : null };
}
