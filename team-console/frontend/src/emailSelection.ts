// Keep only public email fields for cross-page copying, never account credentials.
export interface EmailRow { id: number; email: string }
export interface EmailSelection { scope: string; keys: number[]; emails: Record<number, string> }

export function selectAccountEmails(scope: string, ids: readonly number[], rows: readonly EmailRow[], previous?: EmailSelection): EmailSelection {
  if (ids.some(id => !Number.isSafeInteger(id) || id <= 0)) throw new Error('请选择有效账号');
  const keys = [...new Set(ids)];
  const current = new Map(rows.map(row => [row.id, row.email]));
  const emails: Record<number, string> = {};
  for (const id of keys) {
    const email = current.has(id) ? current.get(id) : previous?.scope === scope ? previous.emails[id] : undefined;
    if (typeof email === 'string') emails[id] = email;
  }
  return { scope, keys, emails };
}

export function selectedEmailText(selection: EmailSelection): { text: string; count: number } {
  if (!selection.keys.length) throw new Error('请先选择账号');
  const unique = new Map<string, string>();
  for (const id of selection.keys) {
    const email = selection.emails[id]?.trim();
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      // Never silently copy a partial page when a selected row is unavailable.
      throw new Error('所选账号邮箱不完整，请重新勾选后复制');
    }
    if (!unique.has(email.toLowerCase())) unique.set(email.toLowerCase(), email);
  }
  return { text: [...unique.values()].join('\n'), count: unique.size };
}
