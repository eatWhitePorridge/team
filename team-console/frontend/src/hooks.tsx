import { useCallback, useEffect, useRef, useState } from 'react';
import { App, List } from 'antd';
import { ApiError, errorText, get } from './api';
import type { Detail, QueueResult } from './types';

// One request at a time; old responses cannot overwrite a new page/filter/scope.
export function useResource<T>(url: string | null, params: Record<string, unknown> = {}, pollMs = 0) {
  const serialized = JSON.stringify(params);
  const key = JSON.stringify([url, serialized]);
  const [revision, setRevision] = useState(0);
  const [state, setState] = useState<{ key: string; data?: T; loading: boolean; error?: string }>({ key, loading: !!url });
  const reload = useCallback(() => setRevision((n) => n + 1), []);
  useEffect(() => {
    let live = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const controller = new AbortController();
    if (!url) { setState({ key, loading: false }); return; }
    const load = async () => {
      setState((old) => ({ key, data: old.key === key ? old.data : undefined, loading: true }));
      try {
        const data = await get<T>(url, JSON.parse(serialized), controller.signal);
        if (live) setState({ key, data, loading: false });
      } catch (error) {
        if (live && !controller.signal.aborted) setState((old) => ({ ...old, key, loading: false, error: errorText(error) }));
      } finally {
        if (live && pollMs) timer = setTimeout(tick, pollMs);
      }
    };
    const tick = () => {
      if (document.hidden) timer = setTimeout(tick, pollMs);
      else void load();
    };
    void load();
    return () => { live = false; controller.abort(); clearTimeout(timer); };
  }, [url, serialized, key, revision, pollMs]);
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
    if (result.started_count > 0) void message.success('已入队 ' + result.started_count + ' 个任务');
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
