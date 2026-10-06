// Same-origin session coordination. No browser/React dependency: storage and
// notifications are injected, so races can be checked with in-memory fixtures.
export const ACCESS_STORAGE_KEY = 'team-console-access-v1';
export const LEGACY_ACCESS_KEY = 'team-console-key';
export interface AccessSnapshot { key: string; revision: string }
export interface AccessChange { snapshot: AccessSnapshot; reason: 'verified' | 'logout' | 'expired' | 'external' }
type StoragePort = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

export function createAccessSession({ shared, legacy, external, revision = () => `${Date.now()}-${Math.random()}` }: {
  shared: () => StoragePort; legacy: () => StoragePort;
  external: (notify: () => void) => () => void;
  revision?: () => string;
}) {
  let initialized = false, memoryOnly = false;
  let memory: AccessSnapshot = { key: '', revision: 'empty' };
  const listeners = new Set<(change: AccessChange) => void>();
  let unsubscribe: (() => void) | undefined;
  const clearLegacy = () => { try { legacy().removeItem(LEGACY_ACCESS_KEY); } catch { /* Storage unavailable. */ } };
  const read = (): AccessSnapshot => {
    if (memoryOnly) return { ...memory };
    try {
      const raw = shared().getItem(ACCESS_STORAGE_KEY);
      if (raw !== null) {
        // An explicit empty record is a logout tombstone. Never resurrect an
        // old tab's sessionStorage key after another tab has logged out.
        let next: AccessSnapshot = { key: '', revision: 'invalid' };
        try {
          const item = JSON.parse(raw);
          if (item?.version === 1 && typeof item.key === 'string' && typeof item.revision === 'string' && item.revision) {
            next = { key: item.key.trim(), revision: item.revision };
          }
        } catch { /* Corrupt shared data is locked, not a legacy-key fallback. */ }
        memory = next; initialized = true; clearLegacy();
        return { ...memory };
      }
      if (initialized) {
        if (memory.revision !== 'legacy') memory = { key: '', revision: 'empty' };
        return { ...memory };
      }
    } catch { memoryOnly = true; }
    if (!initialized) {
      let saved = '';
      try { saved = legacy().getItem(LEGACY_ACCESS_KEY)?.trim() || ''; } catch { /* Memory-only login is still available. */ }
      memory = { key: saved, revision: saved ? 'legacy' : 'empty' };
      initialized = true;
    }
    return { ...memory };
  };
  const current = (expected: AccessSnapshot) => {
    const now = read();
    return now.revision === expected.revision && now.key === expected.key;
  };
  const notify = (reason: AccessChange['reason']) => {
    const change = { reason, snapshot: read() };
    for (const listener of listeners) listener(change);
  };
  const write = (key: string) => {
    memory = { key, revision: revision() }; initialized = true;
    try {
      shared().setItem(ACCESS_STORAGE_KEY, JSON.stringify({ version: 1, ...memory }));
      memoryOnly = false;
    } catch { memoryOnly = true; }
    clearLegacy();
  };
  return {
    read, current,
    // Call only after server verification. A logout/key change while a request
    // was pending must win over its late success response.
    acceptVerified(key: string, expected: AccessSnapshot): boolean {
      key = key.trim();
      if (!key || !current(expected)) return false;
      if (key !== expected.key || expected.revision === 'legacy') write(key);
      notify('verified');
      return true;
    },
    logout() { write(''); notify('logout'); },
    expire(expected: AccessSnapshot): boolean {
      if (!expected.key || !current(expected)) return false;
      write(''); notify('expired'); return true;
    },
    subscribe(listener: (change: AccessChange) => void) {
      listeners.add(listener);
      if (!unsubscribe) unsubscribe = external(() => {
        // Read authoritative storage instead of event.newValue: background
        // tabs may receive old events after a more recent login/logout.
        memoryOnly = false; initialized = true; memory = { key: '', revision: 'empty' };
        notify('external');
      });
      return () => {
        listeners.delete(listener);
        if (!listeners.size) { unsubscribe?.(); unsubscribe = undefined; }
      };
    },
  };
}
