import assert from 'node:assert/strict';
import test from 'node:test';
import { authorizationActivity, authorizationCounts, authorizationItems, authorizationTaskStatus, matchesTaskFilter, mergeAuthorizationItems, taskRows } from '../src/taskHierarchy.ts';
import { canCancelSeatJob, findJob, jobKey } from '../src/jobProgress.ts';

const batch = (extra = {}) => ({ batch_id: 'one', team_authorization: false, total: 500, known: 500,
  active: 400, finished: 100, success: 90, failed: 10, cancelled: 0,
  queued: 300, running: 99, confirming: 1, retrying: 0, created_at: '2026-09-30T12:00:00+08:00', ...extra });
const child = (n, extra = {}) => ({ id: `account-${n}`, batch_id: 'one', account_id: n,
  email: `fixture-${n}@example.invalid`, status: 'running', codex_attempt_count: 1,
  codex_job_id: n, updated_at: '2026-09-30T12:00:00', ...extra });
const jobs = (extra = {}) => ({ authorization: [batch()], pipeline: [], team: [], ...extra });

test('500 accounts or a 351-account submission produce exactly one root authorization task', () => {
  for (const total of [351, 500]) {
    const rows = taskRows(jobs({ authorization: [batch({ total, known: total, active: total - 100 })], pipeline: Array.from({ length: total }, (_, i) => child(i)) }));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].id, 'one');
    assert.equal(rows[0].total, total);
    assert.equal(rows[0].completed, 100);
    assert.equal(rows[0].email, undefined);
  }
});

test('separate submissions and modes stay separate; account retries are not root tasks', () => {
  const data = jobs({ authorization: [batch(), batch({ batch_id: 'two', team_authorization: true })], pipeline: [child(1), child(2, { codex_attempt_count: 7 })] });
  assert.equal(taskRows(data).length, 2);
  assert.deepEqual(new Set(taskRows(data).map(r => r.type)), new Set(['普通授权', 'Team 授权']));
  assert.deepEqual(taskRows(jobs({ authorization: [] })), []);
  assert.deepEqual(taskRows(undefined), []);
});

test('all-success, partial-failure, all-failed, and cancelled results are never conflated', () => {
  const done = batch({ active: 0, finished: 500, success: 500, failed: 0 });
  for (const [extra, expected] of [[{}, 'success'], [{ success: 499, failed: 1 }, 'partial_failed'],
    [{ success: 0, failed: 500 }, 'failed'], [{ success: 0, cancelled: 500 }, 'cancelled'],
    [{ success: 499, cancelled: 1 }, 'partial_cancelled']]) {
    assert.equal(authorizationTaskStatus({ ...done, ...extra }), expected);
  }
});

test('missing historical rows or unknown counters are incomplete, never success', () => {
  for (const extra of [{ known: 100 }, { finished: 100 }, { success: undefined, failed: undefined }, { total: 0 }]) {
    assert.equal(authorizationTaskStatus(batch({ active: 0, finished: 500, success: 500, failed: 0, ...extra })), 'incomplete');
  }
});

test('pending and coordinator-confirming are not counted as completed authorization', () => {
  assert.equal(authorizationTaskStatus(batch({ queued: 400 })), 'queued');
  assert.equal(authorizationTaskStatus(batch({ active: 1, finished: 499, confirming: 1 })), 'running');
  assert.match(authorizationActivity(batch()), /执行 99.*排队 300.*确认 1/);
  assert.match(authorizationCounts(batch({ cancelled: 2 })), /成功 90.*失败 10.*取消 2/);
});

test('root filter includes mixed failures and retained incomplete history', () => {
  const [running] = taskRows(jobs());
  assert.equal(matchesTaskFilter(running, 'active'), true);
  assert.equal(matchesTaskFilter(running, 'failed'), true);
  assert.equal(matchesTaskFilter(running, 'all'), true);
  const [done] = taskRows(jobs({ authorization: [batch({ active: 0, finished: 500, success: 500, failed: 0 })] }));
  assert.equal(matchesTaskFilter(done, 'failed'), false);
  assert.equal(matchesTaskFilter(done, 'active'), false);
});

test('active tasks sort first and selected task follows the current summary', () => {
  const first = taskRows(jobs());
  const key = jobKey(first[0]);
  const next = taskRows(jobs({ authorization: [batch({ finished: 101, active: 399, success: 91 }), batch({ batch_id: 'later', active: 0, finished: 500, created_at: '2026-10-01' })] }));
  assert.equal(next[0].id, 'one');
  assert.equal(findJob(next, key).completed, 101);
  assert.equal(first[0].completed, 100);
});

test('mother operation and authorization identities do not collide and only seat tasks can cancel', () => {
  const rows = taskRows(jobs({ team: [{ id: 'one', kind: 'switch', status: 'running' }] }));
  const seat = rows.find(r => r.source === 'team');
  const auth = rows.find(r => r.source === 'authorization');
  assert.notEqual(jobKey(seat), jobKey(auth));
  assert.equal(canCancelSeatJob(seat), true);
  assert.equal(canCancelSeatJob(auth), false);
  assert.equal(seat.type, '成员切席');
});

test('full detail remains available when the shared SSE recent-100 window moves', () => {
  const fetched = Array.from({ length: 500 }, (_, n) => child(n, { status: 'success' }));
  const previous = mergeAuthorizationItems([], fetched, [], 'one');
  const rows = mergeAuthorizationItems(previous, [], [child(900, { batch_id: 'other' })], 'one');
  assert.equal(rows.length, 500);
  assert.equal(rows[0].account_id, 0);
  assert.equal(rows.at(-1).account_id, 499);
});

test('a stale HTTP response cannot regress a terminal result or retain an old live phase', () => {
  const finished = child(1, { status: 'success', updated_at: '2026-09-30T12:01:00' });
  const stale = child(1, { progress_status: 'running', progress_message: '验证密码' });
  assert.deepEqual(mergeAuthorizationItems([finished], [stale], [], 'one'), [finished]);
  assert.deepEqual(mergeAuthorizationItems([stale], [], [finished], 'one'), [finished]);
  assert.equal(stale.progress_status, 'running');
});

test('newer live phases win against stale HTTP and confirmation cannot regress to running', () => {
  const running = child(1, { progress_status: 'running', progress_stage: 'mfa', progress_updated_at: '2026-09-30T04:00:02Z' });
  const stale = { ...running, progress_stage: 'password', progress_updated_at: '2026-09-30T04:00:01Z' };
  assert.equal(mergeAuthorizationItems([running], [stale], [], 'one')[0].progress_stage, 'mfa');
  const confirming = { ...running, progress_status: 'confirming' };
  assert.equal(mergeAuthorizationItems([confirming], [running], [], 'one')[0].progress_status, 'confirming');
});

test('new attempt replaces old confirmation; retry gap drops previous job phase', () => {
  const old = child(1, { progress_status: 'confirming', progress_stage: 'save_credential' });
  const retry = child(1, { codex_attempt_count: 2, codex_job_id: 500, progress_status: 'running', progress_stage: 'password' });
  assert.deepEqual(mergeAuthorizationItems([old], [retry], [old], 'one'), [retry]);
  const gap = child(1, { codex_job_id: undefined, updated_at: '2026-09-30T12:00:01', progress_status: 'retrying', progress_stage: 'retrying' });
  assert.deepEqual(mergeAuthorizationItems([old], [gap], [], 'one'), [gap]);
});

test('detail filters search only within task, by email or account ID, and show failures/cancellations', () => {
  const rows = [child(1, { status: 'success' }), child(2, { status: 'failed' }), child(3, { status: 'cancelled' }), child(4, { progress_status: 'confirming' })];
  assert.deepEqual(authorizationItems(rows, '', 'active').map(r => r.account_id), [4]);
  assert.deepEqual(authorizationItems(rows, '', 'failed').map(r => r.account_id), [2, 3]);
  assert.deepEqual(authorizationItems(rows, ' Fixture-1@EXAMPLE.invalid ', 'success').map(r => r.account_id), [1]);
  assert.deepEqual(authorizationItems(rows, '4', 'all').map(r => r.account_id), [4]);
  assert.equal(rows.length, 4);
});
