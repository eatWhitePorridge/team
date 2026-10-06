import test from 'node:test';
import assert from 'node:assert/strict';
import { accountMetrics, coverage, metricCount } from '../src/bentoMetrics.ts';

test('unknown statistics never masquerade as real zero values', () => {
  for (const value of [undefined, null, NaN, Infinity, -1, '100']) assert.equal(metricCount(value), undefined);
  assert.equal(metricCount(0), 0);
  assert.equal(metricCount(1614), 1614);
  assert.deepEqual(accountMetrics(), { total: undefined, connected: undefined, remaining: undefined, totp: undefined, quota: undefined, coverage: undefined });
});
test('coverage is derived from real authorized counts, never a rounded-up completion', () => {
  assert.equal(coverage(499, 500), 99);
  assert.equal(coverage(500, 500), 100);
  assert.equal(coverage(0, 500), 0);
  assert.equal(coverage(0, 0), undefined);
  assert.equal(coverage(undefined, 500), undefined);
  assert.equal(coverage(20, undefined), undefined);
  assert.equal(coverage(600, 500), 100);
});
test('dashboard metrics are independent projections and do not mutate persisted status', () => {
  const original = Object.freeze({ total: 1614, codex_connected: 1000, totp_active: 1500, quota_checked: 50 });
  assert.deepEqual(accountMetrics(original), { total: 1614, connected: 1000, remaining: 614, totp: 1500, quota: 50, coverage: 61 });
  assert.equal(accountMetrics({ total: 0, codex_connected: 0 }).remaining, 0);
  assert.equal(accountMetrics({ total: 10 }).remaining, undefined);
});
