// Billing dates are instants only when the source includes a zone or a Unix
// unit. Never let Date.parse guess the user's local timezone, or add 8h twice.
export const BILLING_TIME_ZONE = 'Asia/Shanghai';
export const BILLING_TIME_LABEL = '北京时间 UTC+8';
export type BillingTime = {
  state: 'valid' | 'missing' | 'date_only' | 'unknown_timezone' | 'invalid';
  raw: string; text: string; note?: string; epoch?: number; iso?: string;
};

const formatter = new Intl.DateTimeFormat('zh-CN', {
  timeZone: BILLING_TIME_ZONE, calendar: 'gregory', numberingSystem: 'latn',
  year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
});

function instant(raw: string, epoch: number): BillingTime {
  if (!Number.isFinite(epoch) || Math.abs(epoch) > 8.64e15) return invalid(raw);
  const parts = Object.fromEntries(formatter.formatToParts(new Date(epoch)).map(part => [part.type, part.value]));
  return { state: 'valid', raw, epoch, iso: new Date(epoch).toISOString(),
    text: `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}` };
}
function invalid(raw: string): BillingTime {
  return { state: 'invalid', raw, text: '时间格式异常', note: '无法可靠换算，请核对原始值。' };
}
function calendarEpoch(year: number, month: number, day: number, hour = 0, minute = 0, second = 0, millisecond = 0): number | undefined {
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, millisecond);
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day
    && date.getUTCHours() === hour && date.getUTCMinutes() === minute && date.getUTCSeconds() === second
    ? date.getTime() : undefined;
}

export function billingTime(value: unknown): BillingTime {
  if (value == null || (typeof value === 'string' && !value.trim())) return { state: 'missing', raw: '', text: '未查询' };
  if (typeof value !== 'string' && typeof value !== 'number') return invalid('');
  const raw = String(value).trim();
  // Modern Unix timestamps: explicit 10-digit seconds / 13-digit milliseconds.
  // Reject microseconds and ambiguous short numbers rather than guess a date.
  if (/^\d{10}(?:\.\d{1,6})?$/.test(raw)) return instant(raw, Math.trunc(Number(raw) * 1000));
  if (/^\d{13}$/.test(raw)) return instant(raw, Number(raw));
  const dateOnly = /^(\d{4})-(\d{2})-(\d{2})$/.exec(raw);
  if (dateOnly) {
    if (calendarEpoch(+dateOnly[1], +dateOnly[2], +dateOnly[3]) === undefined) return invalid(raw);
    return { state: 'date_only', raw, text: raw, note: '仅返回日期，未提供具体时间和时区。' };
  }
  const match = /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?([Zz]|[+-]\d{2}:?\d{2})?$/.exec(raw);
  if (!match) return invalid(raw);
  const [, year, month, day, hour, minute, second = '0', fraction = '', zone] = match;
  const localEpoch = calendarEpoch(+year, +month, +day, +hour, +minute, +second, Number((fraction + '000').slice(0, 3)));
  if (localEpoch === undefined) return invalid(raw);
  if (!zone || zone === '-00:00' || zone === '-0000') {
    return { state: 'unknown_timezone', raw, text: '时区未提供', note: '未按电脑时区解析，也未自动加 8 小时。' };
  }
  let offset = 0;
  if (!/z/i.test(zone)) {
    const digits = zone.slice(1).replace(':', ''), hours = +digits.slice(0, 2), minutes = +digits.slice(2);
    if (hours > 23 || minutes > 59) return invalid(raw);
    offset = (hours * 60 + minutes) * (zone[0] === '+' ? 1 : -1);
  }
  return instant(raw, localEpoch - offset * 60_000);
}

export type WorkspaceBillingFields = {
  id: string; renewal_date?: string | number; billing_renewal_date?: string | number; expires_at?: string | number;
  expiration_checked_at?: string; expiration_succeeded_at?: string; expiration_error?: string;
};

// A POST result can arrive ahead of the next cached parent GET. Prefer it only
// for the same workspace and until a newer server observation arrives.
export function latestBillingSnapshot(current: WorkspaceBillingFields, queried?: WorkspaceBillingFields): WorkspaceBillingFields {
  if (!queried || queried.id !== current.id) return current;
  const currentTime = billingTime(current.expiration_checked_at).epoch;
  const queryTime = billingTime(queried.expiration_checked_at).epoch;
  if (currentTime !== undefined && (queryTime === undefined || currentTime > queryTime)) return current;
  return { ...current, renewal_date: queried.renewal_date, billing_renewal_date: queried.billing_renewal_date,
    expiration_checked_at: queried.expiration_checked_at, expiration_succeeded_at: queried.expiration_succeeded_at,
    expiration_error: queried.expiration_error };
}

export function workspaceBillingView(workspace: WorkspaceBillingFields) {
  // expires_at is an entitlement timestamp, not proof of the next invoice date.
  const explicitPreview = workspace.billing_renewal_date != null && workspace.billing_renewal_date !== '';
  return {
    renewal: billingTime(explicitPreview ? workspace.billing_renewal_date : workspace.renewal_date),
    entitlement: billingTime(workspace.expires_at),
    checked: billingTime(workspace.expiration_checked_at),
    succeeded: billingTime(workspace.expiration_succeeded_at),
    source: explicitPreview ? '账单预览 · renewal_date' : '工作区缓存 · renewal_date',
    error: workspace.expiration_error || '',
  };
}
