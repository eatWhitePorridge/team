import type { Job, Jobs } from './types';

export interface JobsSnapshot { epoch: string; version: number; data: Jobs }
export interface ServerEvent { event: string; data: string }

// Incremental SSE framing, including CR/LF boundaries and multiline data.
export function createSSEParser(emit: (event: ServerEvent) => void) {
  let line = '', kind = '', data: string[] = [], size = 0, skipLF = false;
  const finishLine = () => {
    if (!line) {
      if (data.length) emit({ event: kind || 'message', data: data.join('\n') });
      kind = ''; data = []; size = 0;
    } else if (!line.startsWith(':')) {
      const colon = line.indexOf(':');
      const key = colon < 0 ? line : line.slice(0, colon);
      let value = colon < 0 ? '' : line.slice(colon + 1);
      if (value.startsWith(' ')) value = value.slice(1);
      if (key === 'event') kind = value;
      if (key === 'data') data.push(value);
    }
    line = '';
  };
  return (chunk: string) => {
    for (const char of chunk) {
      if (skipLF) { skipLF = false; if (char === '\n') continue; }
      if (++size > 4 * 1024 * 1024) throw new Error('进度事件过大');
      if (char === '\r' || char === '\n') { finishLine(); skipLF = char === '\r'; }
      else line += char;
    }
  };
}

function validJobs(value: Jobs) {
  return value && ['pipeline', 'team', 'authorization'].every((key) => Array.isArray(value[key as keyof Jobs]));
}
function patchRows(rows: Job[], patch: { upsert: Job[]; remove: string[]; order: string[] }): Job[] {
  if (!patch || !Array.isArray(patch.upsert) || !Array.isArray(patch.remove) || !Array.isArray(patch.order)) throw new Error('无效进度增量');
  const byId = new Map(rows.map((row) => [row.id, row]));
  for (const id of patch.remove) byId.delete(id);
  for (const row of patch.upsert) {
    if (!row || typeof row.id !== 'string') throw new Error('无效任务 ID');
    byId.set(row.id, row);
  }
  if (new Set(patch.order).size !== byId.size || patch.order.length !== byId.size || patch.order.some((id) => !byId.has(id))) throw new Error('进度顺序不完整');
  return patch.order.map((id) => byId.get(id)!);
}
export function applyJobsEvent(previous: JobsSnapshot | undefined, event: ServerEvent): JobsSnapshot | undefined {
  if (!['snapshot', 'update'].includes(event.event)) return previous;
  const value = JSON.parse(event.data);
  if (!value || typeof value.epoch !== 'string' || !Number.isSafeInteger(value.version) || value.version <= 0) throw new Error('无效进度版本');
  if (event.event === 'snapshot') {
    if (!validJobs(value.data)) throw new Error('无效进度快照');
    return value as JobsSnapshot;
  }
  if (!previous || value.epoch !== previous.epoch || value.base !== previous.version || value.version <= previous.version || !value.delta) throw new Error('进度版本不连续，需要重新同步');
  const data = { ...previous.data };
  for (const key of ['pipeline', 'team'] as const) if (value.delta[key]) data[key] = patchRows(data[key], value.delta[key]);
  if (value.delta.authorization) data.authorization = value.delta.authorization;
  if (value.delta.runtime) data.runtime = value.delta.runtime;
  if (!validJobs(data)) throw new Error('无效进度数据');
  return { epoch: value.epoch, version: value.version, data };
}
