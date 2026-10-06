import assert from 'node:assert/strict';
import test from 'node:test';
import { parentBillingView } from '../src/parentBillingSummary.ts';

test('parent navigator uses the same Beijing invoice conversion as workspace details', () => {
  for (const raw of ['2026-10-05T20:30:15Z', '2026-10-06T04:30:15+08:00', Date.UTC(2026, 9, 5, 20, 30, 15)]) {
    const view = parentBillingView({ workspace_count: 1, billing_workspaces: [{ id: 'a', billing_renewal_date: raw }] });
    assert.equal(view.label, '账单');
    assert.equal(view.text, '2026-10-06 04:30:15');
    assert.equal(view.time.iso, '2026-10-05T20:30:15.000Z');
    assert.match(view.details, /北京时间 UTC\+8/);
    assert.equal(view.note, '');
  }
});

test('multiple workspaces show earliest cached invoice, including overdue dates, without mutating input', () => {
  const input = { workspace_count: 2, billing_workspaces: [
    { id: 'b', name: 'Later', billing_renewal_date: '2026-10-10T00:00:00Z' },
    { id: 'a', name: 'Earlier', billing_renewal_date: '2025-09-17T10:48:44Z' },
  ] };
  const before = JSON.stringify(input), view = parentBillingView(input);
  assert.equal(view.label, '最早账单');
  assert.equal(view.text, '2025-09-17 18:48:44');
  assert.equal(view.note, '');
  assert.match(view.details, /Earlier：2025-09-17 18:48:44/);
  assert.match(view.details, /Later：2026-10-10 08:00:00/);
  assert.equal(JSON.stringify(input), before);
});

test('invoice selection compares instants rather than local date strings', () => {
  const view = parentBillingView({ billing_workspaces: [
    { id: 'a', billing_renewal_date: '2026-10-05T01:00:00-07:00' },
    { id: 'b', billing_renewal_date: '2026-10-05T09:00:00+08:00' },
  ] });
  assert.equal(view.text, '2026-10-05 09:00:00');
});

test('a failed refresh retains the cached invoice with an explicit previous-result marker', () => {
  const view = parentBillingView({ billing_workspaces: [{ id: 'a', query_failed: true,
    billing_renewal_date: '2026-10-05T00:00:00Z', renewal_date: '2026-11-05T00:00:00Z' }] });
  assert.equal(view.text, '2026-10-05 08:00:00');
  assert.equal(view.note, '上次结果');
  assert.match(view.details, /上次结果/);
});

test('unqueried, failed and old-server responses never substitute entitlement or the Unix epoch', () => {
  for (const input of [{}, { workspace_count: 1 }, { billing_workspaces: [] },
    { billing_workspaces: [{ id: 'a', expires_at: '2026-10-05T00:00:00Z' }] }]) {
    const view = parentBillingView(input);
    assert.equal(view.time.state, 'missing');
    assert.equal(view.text, '未查询');
    assert.equal(view.time.iso, undefined);
  }
  assert.equal(parentBillingView({ billing_workspaces: [{ id: 'a', query_failed: true }] }).text, '查询失败');
});

test('unknown zones and date-only responses cannot claim to be Beijing instants', () => {
  for (const [raw, state, text] of [
    ['2026-10-05T00:00:00', 'unknown_timezone', '时区未提供'],
    ['2026-10-05', 'date_only', '2026-10-05'],
    ['not-a-date', 'invalid', '时间格式异常'],
  ]) {
    const view = parentBillingView({ billing_workspaces: [{ id: 'a', billing_renewal_date: raw }] });
    assert.equal(view.time.state, state); assert.equal(view.text, text);
    assert.equal(view.time.iso, undefined); assert.doesNotMatch(view.details, /北京时间/);
  }
});

test('partial multi-workspace caches and failed cached dates are marked rather than hiding missing data', () => {
  const view = parentBillingView({ workspace_count: 4, billing_workspaces: [
    { id: 'a' }, { id: 'b', billing_renewal_date: '2026-10-05T00:00:00' },
    { id: 'c', query_failed: true, billing_renewal_date: '2026-10-06T00:00:00Z' },
  ] });
  assert.equal(view.label, '最早账单'); assert.equal(view.time.state, 'valid');
  assert.equal(view.text, '2026-10-06 08:00:00');
  assert.equal(view.note, '部分结果 · 上次结果');
  assert.match(view.details, /a：未查询/); assert.match(view.details, /b：时区未提供/);
});

test('legacy renewal cache is supported while explicit billing preview takes precedence', () => {
  const old = { id: 'a', renewal_date: '2026-10-05T00:00:00Z' };
  assert.equal(parentBillingView({ billing_workspaces: [old] }).text, '2026-10-05 08:00:00');
  assert.equal(parentBillingView({ billing_workspaces: [{ ...old, billing_renewal_date: '2026-10-06T00:00:00Z' }] }).text, '2026-10-06 08:00:00');
});
