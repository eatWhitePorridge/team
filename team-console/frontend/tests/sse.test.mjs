import assert from 'node:assert/strict';
import test from 'node:test';
import { applyJobsEvent, createSSEParser } from '../src/sse.ts';
import { watchJobs } from '../src/liveJobs.ts';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(check) {
  const deadline = Date.now() + 1500;
  while (!check() && Date.now() < deadline) await sleep(2);
  assert.ok(check(), 'condition timed out');
}
const jobs = (stage = 'password') => ({ pipeline: [{ id: 'job', status: 'running', progress_stage: stage }], team: [],
  authorization: [{ batch_id: 'batch', active: 1, total: 1, finished: 0 }] });
const snapshot = (epoch = 'one', version = 1, data = jobs()) => ({ epoch, version, data });
const event = (kind, data) => ({ event: kind, data: JSON.stringify(data) });
const frame = (kind, data) => `event: ${kind}\ndata: ${JSON.stringify(data)}\n\n`;
function stream(signal) {
  let control;
  const body = new ReadableStream({ start(controller) { control = controller; } });
  signal.addEventListener('abort', () => { try { control.error(new Error('cancelled fixture')); } catch {} }, { once: true });
  return { response: new Response(body, { headers: { 'content-type': 'text/event-stream' } }),
    send(kind, data) { control.enqueue(new TextEncoder().encode(frame(kind, data))); }, end() { control.close(); } };
}

test('SSE parser handles fragmented CRLF, comments, multiple frames and multiline JSON', () => {
  const received = [];
  const parse = createSSEParser((value) => received.push(value));
  const source = ': heartbeat\r\nevent: snapshot\r\ndata: {"message":\r\ndata: "验证 2FA"}\r\n\r\nevent: update\ndata: {}\n\n';
  for (const char of source) parse(char);
  assert.equal(received.length, 2);
  assert.equal(received[0].event, 'snapshot');
  assert.deepEqual(JSON.parse(received[0].data), { message: '验证 2FA' });
  assert.equal(received[1].event, 'update');
});

test('UTF-8 decoding tolerates splitting every byte, and incomplete EOF does not publish', () => {
  const received = [], decode = new TextDecoder();
  const parse = createSSEParser((value) => received.push(value));
  const bytes = new TextEncoder().encode(frame('snapshot', { message: '密码验证→2FA' }));
  for (const byte of bytes) parse(decode.decode(new Uint8Array([byte]), { stream: true }));
  parse('event: update\ndata: {"partial":');
  assert.equal(received.length, 1);
  assert.equal(JSON.parse(received[0].data).message, '密码验证→2FA');
});

test('delta updates live phases without fabricating completion or mutating old snapshots', () => {
  const initial = applyJobsEvent(undefined, event('snapshot', snapshot()));
  const next = applyJobsEvent(initial, event('update', { epoch: 'one', base: 1, version: 3,
    delta: { pipeline: { upsert: [{ id: 'job', status: 'running', progress_stage: 'mfa' }], remove: [], order: ['job'] } } }));
  assert.equal(initial.data.pipeline[0].progress_stage, 'password');
  assert.equal(next.data.pipeline[0].progress_stage, 'mfa');
  assert.equal(next.data.authorization[0].finished, 0);
  assert.equal(next.version, 3); // Coalesced/skipped intermediate revisions are legal with a matching base.
});

test('version gaps, old epochs and bad row orders require resynchronization', () => {
  const initial = snapshot();
  for (const change of [
    { epoch: 'old', base: 1, version: 2, delta: {} },
    { epoch: 'one', base: 2, version: 3, delta: {} },
    { epoch: 'one', base: 1, version: 1, delta: {} },
    { epoch: 'one', base: 1, version: 2, delta: { pipeline: { upsert: [], remove: [], order: [] } } },
  ]) assert.throws(() => applyJobsEvent(initial, event('update', change)));
  const reset = applyJobsEvent(initial, event('snapshot', snapshot('new-epoch', 1, jobs('workspace'))));
  assert.equal(reset.epoch, 'new-epoch');
  assert.equal(reset.data.pipeline[0].progress_stage, 'workspace');
});

test('changed rows can be removed or reordered independently across both task types', () => {
  const initial = snapshot('one', 1, { ...jobs(), team: [{ id: 'job', status: 'success' }] });
  const result = applyJobsEvent(initial, event('update', { epoch: 'one', base: 1, version: 2,
    delta: { pipeline: { upsert: [{ id: 'new', status: 'queued' }], remove: ['job'], order: ['new'] } } }));
  assert.deepEqual(result.data.pipeline.map((row) => row.id), ['new']);
  assert.equal(result.data.team[0].id, 'job');
});

test('live streaming stops fallback and stale GETs cannot overwrite newer stages', async () => {
  let transport, resolveFallback, fallbackSignal;
  const values = [], modes = [];
  const watcher = watchJobs({
    connect: async (signal) => { transport = stream(signal); return transport.response; },
    fallback: (signal) => { fallbackSignal = signal; return new Promise((resolve) => { resolveFallback = resolve; }); },
    onData: (value) => values.push(value), onMode: (mode) => modes.push(mode), onError() {}, onExpired() { assert.fail('unexpected expiry'); },
  });
  try {
    await until(() => transport);
    transport.send('snapshot', snapshot());
    await until(() => modes.includes('live'));
    assert.equal(fallbackSignal.aborted, true);
    transport.send('update', { epoch: 'one', base: 1, version: 2,
      delta: { pipeline: { upsert: jobs('mfa').pipeline, remove: [], order: ['job'] } } });
    await until(() => values.at(-1)?.pipeline[0].progress_stage === 'mfa');
    resolveFallback(jobs('STALE')); await sleep(5);
    assert.equal(values.at(-1).pipeline[0].progress_stage, 'mfa');
    assert.equal(values.at(-1).authorization[0].finished, 0);
    const count = values.length;
    watcher.stop(); await sleep(5);
    assert.equal(values.length, count);
  } finally { watcher.stop(); }
});

test('disconnect falls back, reconnect replaces the snapshot and never submits business work', async () => {
  const streams = [], modes = [], values = [];
  let gets = 0;
  const watcher = watchJobs({ reconnectMs: 5,
    connect: async (signal) => { const next = stream(signal); streams.push(next); return next.response; },
    fallback: async () => { gets += 1; return jobs('fallback'); },
    onData: (value) => values.push(value), onMode: (mode) => modes.push(mode), onError() {}, onExpired() {},
  });
  try {
    await until(() => streams.length === 1);
    streams[0].send('snapshot', snapshot()); await until(() => modes.includes('live'));
    streams[0].end(); await until(() => streams.length === 2);
    assert.ok(modes.includes('fallback')); assert.ok(gets >= 2);
    streams[1].send('snapshot', snapshot('restarted', 1, jobs('token_exchange')));
    await until(() => values.at(-1)?.pipeline[0].progress_stage === 'token_exchange');
    assert.equal(streams.length, 2);
  } finally { watcher.stop(); }
});

test('invalid delta reconnects for a full snapshot rather than silently losing updates', async () => {
  const streams = [], values = [];
  const watcher = watchJobs({ reconnectMs: 5,
    connect: async (signal) => { const next = stream(signal); streams.push(next); return next.response; },
    fallback: async () => jobs('fallback'), onData: (value) => values.push(value), onMode() {}, onError() {}, onExpired() {},
  });
  try {
    await until(() => streams.length === 1);
    streams[0].send('snapshot', snapshot()); await until(() => values.at(-1)?.pipeline[0].progress_stage === 'password');
    streams[0].send('update', { epoch: 'one', base: 100, version: 101, delta: {} });
    await until(() => streams.length === 2);
    streams[1].send('snapshot', snapshot('one', 102, jobs('workspace')));
    await until(() => values.at(-1)?.pipeline[0].progress_stage === 'workspace');
  } finally { watcher.stop(); }
});

test('401 ends streaming and fallback without a retry loop', async () => {
  let expired = 0, connects = 0, signal;
  const watcher = watchJobs({ reconnectMs: 1,
    connect: async () => { connects += 1; return new Response('{}', { status: 401 }); },
    fallback: (value) => { signal = value; return new Promise(() => {}); },
    onData() {}, onMode() {}, onError() {}, onExpired() { expired += 1; },
  });
  await until(() => expired === 1); await sleep(10);
  assert.equal(connects, 1); assert.equal(signal.aborted, true);
  watcher.stop();
});

test('stalled stream is aborted and falls back instead of staying silently connected', async () => {
  let transport, signal;
  const modes = [];
  const watcher = watchJobs({ reconnectMs: 1000, openTimeout: 50, staleTimeout: 20,
    connect: async (value) => { signal = value; transport = stream(value); return transport.response; },
    fallback: async () => jobs(), onData() {}, onMode: (mode) => modes.push(mode), onError() {}, onExpired() {},
  });
  try {
    await until(() => transport);
    transport.send('snapshot', snapshot());
    await until(() => modes.includes('live'));
    await until(() => modes.includes('fallback'));
    assert.equal(signal.aborted, true);
  } finally { watcher.stop(); }
});

test('explicit refresh coalesces into one replacement stream, without waiting for retry backoff', async () => {
  const streams = [], signals = [], values = [];
  const watcher = watchJobs({ reconnectMs: 30_000,
    connect: async (signal) => { const next = stream(signal); streams.push(next); signals.push(signal); return next.response; },
    fallback: async () => jobs('fallback'), onData: (data) => values.push(data), onMode() {}, onError() {}, onExpired() {},
  });
  try {
    await until(() => streams.length === 1);
    streams[0].send('snapshot', snapshot()); await until(() => values.at(-1)?.pipeline[0].progress_stage === 'password');
    for (let n = 0; n < 10; n += 1) watcher.resync();
    await until(() => streams.length === 2);
    assert.equal(signals[0].aborted, true);
    streams[1].send('snapshot', snapshot('new', 1, jobs('workspace')));
    await until(() => values.at(-1)?.pipeline[0].progress_stage === 'workspace');
    assert.equal(streams.length, 2);
  } finally { watcher.stop(); }
});
