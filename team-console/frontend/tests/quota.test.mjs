// Data formatting only: no browser, DOM, React rendering or UI tests.
import assert from 'node:assert/strict';
import test from 'node:test';
import { quotaPresentation } from '../src/quota.ts';

test('success with no quota is explicit unknown, never a success badge or 100%', () => {
  const view = quotaPresentation({ quota_status: 'success' });
  assert.equal(view.status, null);
  assert.equal(view.missing, '暂无额度数据');
  assert.deepEqual(view.windows, []);
  assert.equal(view.credits, null);
});

test('usage-based zero and numeric string balances are displayed, not lost as falsy', () => {
  for (const balance of [0, '0', 125.5, '125.5', -2.25, '0.0001']) {
    const view = quotaPresentation({ quota_status: 'success', quota_plan_type: 'self_serve_business_usage_based', quota_credits_balance: balance });
    assert.equal(view.credits, `点数余额 ${Number(balance)} credits`);
    assert.equal(view.missing, null);
    assert.equal(view.status, null);
    assert.deepEqual(view.windows, []);
  }
});

test('ordinary allowance preserves actual 5h/7d/31d windows and zero usage', () => {
  for (const [seconds, label] of [[18000, '5 小时'], [604800, '7 天'], ['2678400', '31 天']]) {
    const view = quotaPresentation({ quota_status: 'success', quota_primary_used_percent: 0, quota_primary_limit_window_seconds: seconds, quota_secondary_used_percent: 25.5, quota_secondary_limit_window_seconds: '604800', quota_credits_balance: 0 });
    assert.equal(view.windows[0].text, `${label} · 剩余 100%`);
    assert.equal(view.windows[1].text, '7 天 · 剩余 74.5%');
    assert.equal(view.credits, null); // No misleading "0" purchased-credits label.
    assert.equal(view.missing, null);
  }
});

test('invalid balances and windows are unknown, not zero or full allowance', () => {
  for (const raw of [undefined, null, '', ' ', 'bad', true, false, [], {}, NaN, Infinity, 'NaN', 'Infinity']) {
    const view = quotaPresentation({ quota_status: 'success', quota_primary_used_percent: raw, quota_credits_balance: raw });
    assert.equal(view.missing, '暂无额度数据');
    assert.equal(view.credits, null);
    assert.deepEqual(view.windows, []);
  }
  assert.equal(quotaPresentation({ quota_status: 'success', quota_primary_used_percent: -1 }).missing, '暂无额度数据');
});

test('only an explicit unlimited flag grants an unlimited credits label', () => {
  for (const flag of [true, 1]) assert.equal(quotaPresentation({ quota_status: 'success', quota_credits_unlimited: flag }).credits, '点数不限量');
  for (const flag of [undefined, null, false, 0, 'true', 'false']) assert.equal(quotaPresentation({ quota_status: 'success', quota_credits_unlimited: flag }).credits, null);
});

test('reset counts and has_credits are not substituted for actual balance', () => {
  const view = quotaPresentation({ quota_status: 'success', quota_reset_credits_available_count: 99, quota_credits_has_credits: true });
  assert.equal(view.credits, null);
  assert.equal(view.missing, '暂无额度数据');
});

test('failed or running checks identify the retained snapshot as the last result', () => {
  for (const status of ['failed', 'running', 'queued']) {
    const view = quotaPresentation({ quota_status: status, quota_credits_balance: 20 });
    assert.equal(view.status, status);
    assert.equal(view.previous, true);
    assert.equal(view.credits, '点数余额 20 credits');
    assert.equal(view.missing, null);
  }
  assert.equal(quotaPresentation({ quota_status: 'failed' }).previous, false);
  assert.equal(quotaPresentation({}).status, 'unchecked');
});

test('limit flags do not disappear behind a request-success badge', () => {
  assert.equal(quotaPresentation({ quota_status: 'success', quota_limit_reached: 1, quota_primary_used_percent: 105 }).windows[0].remaining, 0);
  assert.equal(quotaPresentation({ quota_status: 'success', quota_limit_reached: true }).limitation, '已达上限');
  assert.equal(quotaPresentation({ quota_status: 'success', quota_allowed: 0 }).limitation, '当前不可用');
  assert.equal(quotaPresentation({ quota_status: 'success', quota_allowed: null }).limitation, null);
});

test('a short measured window is not rounded to zero hours', () => {
  assert.equal(quotaPresentation({ quota_status: 'success', quota_primary_used_percent: 1, quota_primary_limit_window_seconds: 1800 }).windows[0].text, '30 分钟 · 剩余 99%');
});
