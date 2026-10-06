import { createPoller } from './polling.ts';
import { jobsPollInterval } from './jobProgress.ts';
import { applyJobsEvent, createSSEParser } from './sse.ts';
import type { JobsSnapshot } from './sse';
import type { Jobs } from './types';

export type ProgressTransport = 'connecting' | 'live' | 'fallback';

// One stream per mounted console. Only GETs are retried; mutations never enter
// this transport. Disconnected polling cannot overwrite a recovered SSE stream.
export function watchJobs({ connect, fallback, onData, onMode, onError, onExpired,
  reconnectMs = 1000, openTimeout = 10_000, staleTimeout = 45_000 }: {
  connect: (signal: AbortSignal) => Promise<Response>;
  fallback: (signal: AbortSignal) => Promise<Jobs>;
  onData: (data: Jobs) => void;
  onMode: (mode: ProgressTransport) => void;
  onError: (message: string | undefined) => void;
  onExpired: () => void;
  reconnectMs?: number; openTimeout?: number; staleTimeout?: number;
}) {
  let stopped = false, live = false, failures = 0, opening = false, immediate = false;
  let retry: ReturnType<typeof setTimeout> | undefined;
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  let controller: AbortController | undefined;
  let poller: ReturnType<typeof createPoller<Jobs>> | undefined;
  const startFallback = () => {
    if (stopped || poller) return;
    poller = createPoller<Jobs>({ read: fallback, interval: jobsPollInterval,
      onData: (data) => { if (!stopped && !live) { onData(data); onError(undefined); } },
      onError: () => { if (!stopped && !live) onError('进度连接中断，正在重连'); },
    });
    poller.refresh();
  };
  const stop = () => {
    stopped = true; clearTimeout(retry); clearTimeout(watchdog);
    controller?.abort(); poller?.stop(); poller = undefined;
  };
  const expired = () => { if (!stopped) { stop(); onExpired(); } };
  const open = async () => {
    if (stopped) return;
    opening = true;
    const request = new AbortController(); controller = request;
    let snapshot: JobsSnapshot | undefined;
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    const arm = (ms: number) => { clearTimeout(watchdog); watchdog = setTimeout(() => request.abort(), ms); };
    try {
      arm(openTimeout);
      const response = await connect(request.signal);
      if (stopped) return;
      if (response.status === 401) { expired(); return; }
      if (!response.ok || !response.headers.get('content-type')?.includes('text/event-stream') || !response.body) throw new Error('进度流不可用');
      reader = response.body.getReader();
      const decoder = new TextDecoder();
      const parse = createSSEParser((event) => {
        if (stopped) return;
        if (event.event === 'access_expired') { expired(); return; }
        if (event.event === 'unavailable') throw new Error('状态暂不可用');
        const next = applyJobsEvent(snapshot, event);
        if (next && next !== snapshot) {
          snapshot = next;
          live = true; failures = 0;
          poller?.stop(); poller = undefined;
          onMode('live'); onError(undefined); onData(next.data);
        }
      });
      while (!stopped && !request.signal.aborted) {
        const chunk = await reader.read();
        if (chunk.done) break;
        if (stopped || request.signal.aborted) break;
        parse(decoder.decode(chunk.value, { stream: true }));
        if (!stopped && snapshot) arm(staleTimeout);
      }
    } catch {
      // Fallback GETs report useful connection state, not an alarming error on
      // every harmless reconnect. Never log stream data or the access key.
    } finally {
      request.abort(); clearTimeout(watchdog);
      if (reader) { try { await reader.cancel(); } catch { /* Already aborted. */ } }
      opening = false;
      if (!stopped) {
        live = false; failures += 1; onMode('fallback'); startFallback();
        const delay = immediate ? 0 : Math.min(30_000, reconnectMs * 2 ** Math.min(failures - 1, 5));
        immediate = false;
        retry = setTimeout(() => void open(), delay);
      }
    }
  };
  onMode('connecting'); startFallback(); void open();
  return {
    stop,
    resync() {
      if (stopped) return;
      clearTimeout(retry);
      if (opening) { immediate = true; controller?.abort(); }
      else { immediate = false; void open(); }
    },
    refresh() {
      if (stopped) return;
      // A healthy stream already delivers every change; do not launch another
      // stream or a racing GET after each task submission.
      if (!live) poller?.refresh();
    },
  };
}
