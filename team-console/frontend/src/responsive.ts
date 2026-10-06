// Pure data helpers: mobile and desktop keep the same selection and page scope.
export const MOBILE_QUERY = '(max-width: 767px)';

export function toggleSelection<K>(keys: readonly K[], key: K, checked: boolean): K[] {
  const next = new Set(keys);
  if (checked) next.add(key); else next.delete(key);
  return [...next];
}

export function selectPage<K>(keys: readonly K[], pageKeys: readonly K[], checked: boolean): K[] {
  const next = new Set(keys);
  for (const key of pageKeys) { if (checked) next.add(key); else next.delete(key); }
  return [...next];
}

export function pageSelection<K>(keys: readonly K[], pageKeys: readonly K[]) {
  const selected = new Set(keys);
  const count = pageKeys.filter(key => selected.has(key)).length;
  return { checked: pageKeys.length > 0 && count === pageKeys.length, indeterminate: count > 0 && count < pageKeys.length };
}

export function pageNumber(page: number, total: number, pageSize: number) {
  return Math.max(1, Math.min(Math.max(1, Math.trunc(page)), Math.ceil(Math.max(0, total) / Math.max(1, pageSize))));
}

export function pageRows<T>(rows: readonly T[], page: number, pageSize: number) {
  const current = pageNumber(page, rows.length, pageSize);
  return { page: current, items: rows.slice((current - 1) * pageSize, current * pageSize) };
}
