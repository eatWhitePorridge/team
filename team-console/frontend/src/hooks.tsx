import { useCallback, useEffect, useRef, useState } from 'react';
import { App, List } from 'antd';
import { ApiError, errorText, get } from './api';
import { createPoller } from './polling';
import type { PollInterval } from './polling';
import type { Detail, QueueResult } from './types';

// One request at a time; old responses cannot overwrite a new page/filter/scope.
export function useResource<T>(url: string | null, params: Record<string, unknown> = {}, pollMs: PollInterval<T> = 0) {
  const serialized = JSON.stringify(params);
  const key = JSON.stringify([url, serialized]);
  const refreshRef = useRef<() => void>(() => {});
  const [state, setState] = useState<{ key: string; data?: T; loading: boolean; error?: string }>({ key, loading: !!url });
  const reload = useCallback(() => refreshRef.current(), []);
  useEffect(() => {
    if (!url) { setState({ key, loading: false }); return; }
    const polling = typeof pollMs === 'function' || pollMs > 0;
    const poller = createPoller<T>({
      interval: pollMs, visible: !polling || !document.hidden,
      read: (signal) => get<T>(url, JSON.parse(serialized), signal),
      onStart: (manual) => setState((old) => !manual && old.key === key && old.data !== undefined ? old
        : { key, data: old.key === key ? old.data : undefined, loading: true, error: old.key === key ? old.error : undefined }),
      onData: (data) => setState({ key, data, loading: false }),
      onError: (error) => setState((old) => ({ ...old, key, loading: false, error: errorText(error) })),
    });
    refreshRef.current = poller.refresh;
    const onVisibility = () => poller.setVisible(!document.hidden);
    if (polling) {
      document.addEventListener('visibilitychange', onVisibility);
      window.addEventListener('focus', poller.wake);
      window.addEventListener('online', poller.wake);
    }
    poller.refresh();
    return () => {
      refreshRef.current = () => {};
      poller.stop();
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('focus', poller.wake);
      window.removeEventListener('online', poller.wake);
    };
  }, [url, serialized, key, pollMs]);
  return { ...(state.key === key ? state : { loading: !!url, data: undefined, error: undefined }), reload };
}

export function useAction() {
  const { message, modal } = App.useApp();
  const [pending, setPending] = useState(false);
  const lock = useRef(false);
  const details = (title: string, rows: Detail[]) => {
    if (!rows.length) return;
    modal.info({ title, width: 640, content: <List className="result-details" size="small" dataSource={rows} renderItem={(row) => <List.Item>{row.email || row.id || row.account_id || '提示'}：{row.reason || row.error || '未处理'}</List.Item>} /> });
  };
  const queue = (result: QueueResult) => {
    const skipped = [...(result.busy || []), ...(result.skipped || []), ...(result.failed || []), ...(result.no_token || [])];
    if (result.started_count > 0) void message.success('已提交 ' + result.started_count + ' 个账号');
    else void message.warning(result.error || '没有新任务入队');
    details('未入队明细', skipped);
  };
  const run = async (task: () => Promise<void>) => {
    if (lock.current) return;
    lock.current = true; setPending(true);
    try { await task(); }
    catch (error) {
      void message.error(errorText(error));
      if (error instanceof ApiError) details('操作明细', error.details);
    } finally { lock.current = false; setPending(false); }
  };
  return { pending, run, queue, details, message };
}
