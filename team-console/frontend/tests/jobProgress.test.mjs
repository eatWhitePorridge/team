import assert from 'node:assert/strict';
import test from 'node:test';
import { canCancelSeatJob, findJob, jobKey, jobRows, jobsPollInterval } from '../src/jobProgress.ts';

const jobs = (overrides = {}) => ({ authorization: [], pipeline: [], team: [], ...overrides });

test('seat cancellation only targets active Team switches, never OAuth or completed jobs', () => {
  const seat = { id: 'same', source: 'team', kind: 'switch', status: 'running' };
  assert.equal(canCancelSeatJob(seat), true);
  assert.equal(canCancelSeatJob({ ...seat, status: 'queued' }), true);
  assert.equal(canCancelSeatJob({ ...seat, kind: 'invite_switch' }), true);
  assert.equal(canCancelSeatJob({ ...seat, kind: 'invite_switch', source: 'authorization' }), false);
  for (const row of [undefined, { ...seat, source: 'authorization' }, { ...seat, kind: 'invite' },
    { ...seat, cancel_requested: true }, ...['success', 'failed', 'cancelled', 'interrupted'].map(status => ({ ...seat, status }))]) {
    assert.equal(canCancelSeatJob(row), false);
  }
});

test('idle or ended tasks use 5s, including failures; polling does not resubmit tasks', () => {
  for (const value of [undefined, jobs(), jobs({ pipeline: [{ id: 'a', status: 'failed' }, { id: 'b', status: 'success' }] })]) {
    assert.equal(jobsPollInterval(value), 5000);
  }
});

test('any active authorization, Team operation, queued executor or retry gets the fast cadence', () => {
  for (const value of [
    jobs({ authorization: [{ active: 1, team_authorization: false }] }),
    jobs({ authorization: [{ active: 1, team_authorization: true }] }),
    jobs({ pipeline: [{ id: 'a', status: 'retrying' }] }),
    jobs({ team: [{ id: 'a', status: 'running' }] }),
    jobs({ team: [{ id: 'a', status: 'queued' }] }),
    jobs({ runtime: { running: 100, queued: 0 } }),
    jobs({ runtime: { running: 0, queued: 30 } }),
  ]) assert.equal(jobsPollInterval(value), 1000);
});

test('detail identity resolves against each new snapshot, never the clicked object', () => {
  const before = jobRows(jobs({ pipeline: [{ id: 'task', status: 'running', stage: 'codex_waiting', updated_at: 'first' }] }));
  const selection = jobKey(before[0]);
  const after = jobRows(jobs({ pipeline: [{ id: 'task', status: 'success', stage: 'complete', updated_at: 'second' }] }));
  assert.equal(findJob(after, selection).status, 'success');
  assert.equal(findJob(after, selection).updated_at, 'second');
  assert.equal(before[0].status, 'running');
});

test('Team and authorization IDs cannot collide, and removed records do not display stale progress', () => {
  const rows = jobRows(jobs({ pipeline: [{ id: 'same', status: 'running' }], team: [{ id: 'same', status: 'success' }] }));
  const selection = jobKey(rows[0]);
  assert.notEqual(selection, jobKey(rows[1]));
  assert.equal(findJob(rows, selection).source, 'authorization');
  assert.equal(findJob(rows.slice(1), selection), undefined);
  assert.equal(findJob(rows, undefined), undefined);
});
