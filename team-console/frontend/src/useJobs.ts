import { useCallback, useEffect, useRef, useState } from 'react';
import { accessSession, get } from './api';
import { watchJobs } from './liveJobs';
import type { ProgressTransport } from './liveJobs';
import type { Jobs } from './types';

export function useJobs() {
  const [state, setState] = useState<{ data?: Jobs; loading: boolean; error?: string; transport: ProgressTransport }>({ loading: true, transport: 'connecting' });
  const source = useRef<ReturnType<typeof watchJobs> | null>(null);
  const reload = useCallback(() => source.current?.refresh(), []);
  const resync = useCallback(() => source.current?.resync(), []);
  useEffect(() => {
    const snapshot = accessSession.read();
    const watcher = watchJobs({
      connect: (signal) => fetch('/api/jobs/events', { signal, cache: 'no-store',
        headers: { Accept: 'text/event-stream', 'X-Team-Console-Key': snapshot.key } }),
      fallback: (signal) => get<Jobs>('/api/jobs', {}, signal),
      onData: (data) => setState((old) => ({ ...old, data, loading: false })),
      onMode: (transport) => setState((old) => old.transport === transport ? old : { ...old, transport }),
      onError: (error) => setState((old) => old.error === error ? old : { ...old, error, loading: false }),
      onExpired: () => { accessSession.expire(snapshot); },
    });
    source.current = watcher;
    const resume = () => { if (!document.hidden) watcher.resync(); };
    document.addEventListener('visibilitychange', resume);
    window.addEventListener('online', resume);
    return () => {
      watcher.stop(); source.current = null;
      document.removeEventListener('visibilitychange', resume);
      window.removeEventListener('online', resume);
    };
  }, []);
  return { ...state, reload, resync };
}
