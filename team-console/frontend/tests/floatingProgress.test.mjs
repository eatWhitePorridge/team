import assert from 'node:assert/strict';
import test from 'node:test';
import { floatingTaskModel, floatingTaskProgress, toggleFloatingTask } from '../src/floatingProgress.ts';
import { jobKey } from '../src/jobProgress.ts';
import { applyJobsEvent } from '../src/sse.ts';

const batch = (extra = {}) => ({ batch_id: 'batch', team_authorization: false, total: 351, active: 351, finished: 0, known: 351, success: 0, failed: 0, running: 100, queued: 251, ...extra });
const jobs = (extra = {}) => ({ authorization: [batch()], team: [], pipeline: [], ...extra });

test('351 child records remain one floating task and root identity distinguishes sources', () => {
  const data = jobs({ pipeline: Array.from({ length: 351 }, (_, i) => ({ id: String(i), batch_id: 'batch', status: 'running' })), team: [{ id: 'batch', kind: 'invite_switch', status: 'running' }] });
  const model = floatingTaskModel(data);
  assert.equal(model.rows.length, 2); assert.equal(model.activeCount, 2);
  assert.equal(new Set(model.rows.map(jobKey)).size, 2);
  assert.match(model.rows.find(r => r.source === 'authorization').message, /执行 100.*排队 251/);
});

test('all active tasks remain visible while completed history is limited to recent results', () => {
  const team = Array.from({ length: 50 }, (_, i) => ({ id: 'active-' + i, status: 'queued' }));
  team.push(...Array.from({ length: 10 }, (_, i) => ({ id: 'done-' + i, status: 'success', updated_at: `2026-10-${String(i + 1).padStart(2, '0')}T12:00:00Z` })));
  const data = jobs({ team }), before = JSON.stringify(data);
  const model = floatingTaskModel(data);
  assert.equal(model.activeCount, 51); assert.equal(model.rows.length, 54);
  assert.deepEqual(model.rows.slice(-3).map(r => r.id), ['done-9', 'done-8', 'done-7']);
  assert.equal(JSON.stringify(data), before);
});

test('finishing a task preserves its result; failures and cancellation are not success', () => {
  for (const [extra, status] of [[{ success: 351 }, 'success'], [{ success: 350, failed: 1 }, 'exception'], [{ cancelled: 351 }, 'exception']]) {
    const model = floatingTaskModel(jobs({ authorization: [batch({ active: 0, finished: 351, ...extra })] }));
    assert.equal(model.activeCount, 0); assert.equal(model.rows.length, 1);
    assert.equal(floatingTaskProgress(model.rows[0]).status, status);
    assert.equal(floatingTaskProgress(model.rows[0]).percent, 100);
  }
});

test('progress uses confirmed terminal counts, floors percentages, and does not invent unknown totals', () => {
  const [row] = floatingTaskModel(jobs({ authorization: [batch({ finished: 350, active: 1, success: 350 })] })).rows;
  assert.equal(floatingTaskProgress(row).percent, 99);
  assert.equal(floatingTaskProgress({ status: 'running' }).percent, undefined);
  assert.equal(floatingTaskProgress({ total: 20, completed: -3, status: 'running' }).finished, 0);
  assert.equal(floatingTaskProgress({ total: 20, completed: 21, status: 'success' }).finished, 20);
});

test('SSE summary increments update floating progress before all accounts finish', () => {
  const initial = { epoch: 'fixture', version: 1, data: jobs() };
  const next = applyJobsEvent(initial, { event: 'update', data: JSON.stringify({ epoch: 'fixture', base: 1, version: 2,
    delta: { authorization: [batch({ active: 350, finished: 1, success: 1, running: 100, queued: 250 })] } }) });
  const row = floatingTaskModel(next.data).rows[0];
  assert.equal(floatingTaskProgress(row).finished, 1);
  assert.equal(floatingTaskModel(next.data).activeCount, 1);
  assert.equal(floatingTaskProgress(floatingTaskModel(initial.data).rows[0]).finished, 0);
});

test('empty snapshot stays empty; Team retry/stopping remain active', () => {
  assert.deepEqual(floatingTaskModel(undefined), { tasks: [], rows: [], activeCount: 0 });
  const model = floatingTaskModel(jobs({ authorization: [], team: [{ id: 'r', status: 'retrying' }, { id: 's', status: 'stopping' }] }));
  assert.equal(model.activeCount, 2);
});

test('one task expands at a time, toggles closed, and same ids from two sources remain independent', () => {
  let selected = toggleFloatingTask(undefined, 'authorization:batch');
  assert.equal(selected, 'authorization:batch');
  selected = toggleFloatingTask(selected, 'team:batch');
  assert.equal(selected, 'team:batch');
  assert.equal(toggleFloatingTask(selected, 'team:batch'), undefined);
});

test('expanded task stays visible after finishing outside the recent-three window', () => {
  const data = jobs({ authorization: [batch({ active: 0, finished: 351, success: 351, updated_at: '2026-10-01T01:00:00Z' })],
    team: Array.from({ length: 6 }, (_, i) => ({ id: 'new-' + i, status: 'success', updated_at: '2026-10-03T01:00:00Z' })) });
  assert.equal(floatingTaskModel(data).rows.length, 3);
  const selected = floatingTaskModel(data, 3, 'authorization:batch');
  assert.equal(selected.rows.length, 4);
  assert.equal(selected.rows.at(-1).authorization_batch.success, 351);
  assert.equal(selected.activeCount, 0);
});

test('expanded live task is not duplicated and follows new progress, not the clicked snapshot', () => {
  const before = floatingTaskModel(jobs(), 3, 'authorization:batch');
  const after = floatingTaskModel(jobs({ authorization: [batch({ active: 350, finished: 1, success: 1 })] }), 3, 'authorization:batch');
  assert.equal(after.rows.length, 1);
  assert.equal(after.rows[0].completed, 1);
  assert.equal(before.rows[0].completed, 0);
});

test('removed task cannot be resurrected by a stale expansion key', () => {
  const model = floatingTaskModel(jobs({ authorization: [] }), 3, 'authorization:batch');
  assert.equal(model.rows.length, 0);
  assert.equal(model.tasks.length, 0);
});

test('pinning a mother result never opens an authorization with the same id', () => {
  const data = jobs({ team: [{ id: 'batch', status: 'success', kind: 'invite_switch', message: 'fixture-complete' }] });
  const model = floatingTaskModel(data, 0, 'team:batch');
  assert.equal(model.rows.length, 2);
  assert.equal(model.rows.at(-1).source, 'team');
  assert.equal(model.rows.at(-1).message, 'fixture-complete');
  assert.equal(model.rows.at(-1).authorization_batch, undefined);
});
