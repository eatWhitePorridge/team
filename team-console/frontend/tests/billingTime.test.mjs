import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { BILLING_TIME_LABEL, BILLING_TIME_ZONE, billingTime, latestBillingSnapshot, workspaceBillingView } from '../src/billingTime.ts';

test('billing time always identifies Beijing, not the runtime local zone', () => {
  assert.equal(BILLING_TIME_ZONE, 'Asia/Shanghai');
  assert.equal(BILLING_TIME_LABEL, '北京时间 UTC+8');
});

test('UTC Z and explicit UTC offsets become the same Beijing instant', () => {
  for (const input of ['2026-09-17T10:48:44Z', '2026-09-17T10:48:44+00:00', '2026-09-17 10:48:44+0000']) {
    const value = billingTime(input);
    assert.equal(value.state, 'valid');
    assert.equal(value.text, '2026-09-17 18:48:44');
    assert.equal(value.raw, input);
  }
});

test('an already Beijing offset is not increased by another eight hours', () => {
  for (const input of ['2026-09-17T18:48:44+08:00', '2026-09-17T18:48:44+0800']) {
    assert.equal(billingTime(input).text, '2026-09-17 18:48:44');
    assert.equal(billingTime(input).iso, '2026-09-17T10:48:44.000Z');
  }
});

test('negative and fractional positive offsets are converted, not ignored', () => {
  assert.equal(billingTime('2026-09-17T03:48:44-07:00').text, '2026-09-17 18:48:44');
  assert.equal(billingTime('2026-09-17T16:18:44+05:30').text, '2026-09-17 18:48:44');
});

test('rollover across day, month, year and leap day uses calendar time', () => {
  for (const [input, expected] of [
    ['2026-09-17T20:21:59+00:00', '2026-09-18 04:21:59'],
    ['2026-09-30T18:00:00Z', '2026-10-01 02:00:00'],
    ['2026-12-31T18:00:00Z', '2027-01-01 02:00:00'],
    ['2028-02-29T16:00:00Z', '2028-03-01 00:00:00'],
  ]) assert.equal(billingTime(input).text, expected);
});

test('midnight is 00:00 rather than locale-dependent 24:00', () => {
  assert.equal(billingTime('2026-09-17T16:00:00Z').text, '2026-09-18 00:00:00');
});

test('fractional seconds are preserved to milliseconds but display second precision', () => {
  const value = billingTime('2026-09-17T10:48:44.123456+00:00');
  assert.equal(value.text, '2026-09-17 18:48:44');
  assert.equal(value.iso, '2026-09-17T10:48:44.123Z');
});

test('10 digit Unix seconds and 13 digit milliseconds work as numbers or strings', () => {
  const ms = Date.UTC(2026, 8, 17, 10, 48, 44);
  for (const input of [ms, String(ms), ms / 1000, String(ms / 1000), `${ms / 1000}.123`]) {
    assert.equal(billingTime(input).text, '2026-09-17 18:48:44');
  }
});

test('absent values never appear as the Unix epoch', () => {
  for (const input of [undefined, null, '', '  ']) {
    const value = billingTime(input);
    assert.equal(value.state, 'missing'); assert.equal(value.epoch, undefined); assert.equal(value.text, '未查询');
  }
});

test('naive date-times and unknown negative-zero offset never guess UTC or local time', () => {
  for (const input of ['2026-09-17T10:48:44', '2026-09-17 10:48', '2026-09-17T10:48:44-00:00', '2026-09-17T10:48:44-0000']) {
    const value = billingTime(input);
    assert.equal(value.state, 'unknown_timezone'); assert.equal(value.raw, input); assert.equal(value.epoch, undefined);
    assert.equal(value.text, '时区未提供');
  }
});

test('date-only response remains a date, not fabricated Beijing midnight', () => {
  const value = billingTime('2026-09-17');
  assert.equal(value.state, 'date_only'); assert.equal(value.text, '2026-09-17'); assert.equal(value.iso, undefined);
});

test('invalid calendar dates, offsets and ambiguous numeric units are rejected', () => {
  for (const input of ['2026-02-29T00:00:00Z', '2026-04-31', '2026-13-01T00:00:00Z',
    '2026-00-00T00:00:00Z', '2026-09-17T24:00:00Z', '2026-09-17T12:60:00Z', '2026-09-17T12:00:60Z',
    '2026-09-17T12:00:00+24:00', '2026-09-17T12:00:00+08:60', '09/17/2026', '20260917',
    '1789642124000000', 123, NaN, Infinity, true, {}, [], '<script>']) {
    assert.equal(billingTime(input).state, 'invalid', String(input));
  }
});

test('entitlement expiry cannot stand in for the invoice renewal date', () => {
  const view = workspaceBillingView({ id: 'space', expires_at: '2026-09-17T10:48:44Z' });
  assert.equal(view.renewal.state, 'missing'); assert.equal(view.entitlement.text, '2026-09-17 18:48:44');
});

test('preview cache has its own provenance and survives entitlement metadata refresh', () => {
  const raw = '2026-09-17T18:48:44+08:00';
  const input = { id: 'space', billing_renewal_date: raw, renewal_date: '', expires_at: '2026-09-11T00:00:00Z',
    expiration_succeeded_at: '2026-09-10T00:00:00Z', expiration_checked_at: '2026-09-12T00:00:00Z', expiration_error: 'fixture-failure' };
  const before = JSON.stringify(input), view = workspaceBillingView(input);
  assert.equal(view.renewal.raw, raw); assert.equal(view.renewal.text, '2026-09-17 18:48:44');
  assert.match(view.source, /账单预览/); assert.equal(view.error, 'fixture-failure');
  assert.notEqual(view.succeeded.text, view.checked.text); assert.equal(JSON.stringify(input), before);
});

test('legacy cached renewal stays supported, with no fabricated success time', () => {
  const view = workspaceBillingView({ id: 'space', renewal_date: '2026-09-17T10:48:44Z' });
  assert.equal(view.renewal.state, 'valid'); assert.match(view.source, /工作区缓存/);
  assert.equal(view.succeeded.state, 'missing');
});

test('fresh query overlays stale GET only for its own workspace', () => {
  const cached = { id: 'a', expiration_checked_at: '2026-09-10T00:00:00Z' };
  const fresh = { id: 'a', expiration_checked_at: '2026-09-10T00:00:01Z', renewal_date: '2026-10-10T00:00:00Z' };
  assert.equal(latestBillingSnapshot(cached, fresh).renewal_date, fresh.renewal_date);
  assert.equal(latestBillingSnapshot(cached, fresh).expiration_checked_at, fresh.expiration_checked_at);
  assert.equal(latestBillingSnapshot(cached, { ...fresh, id: 'b' }), cached);
  const newer = { ...cached, expiration_checked_at: '2026-09-10T00:00:02Z', expiration_error: 'later-failure' };
  assert.equal(latestBillingSnapshot(newer, fresh), newer);
});

test('query overlay does not freeze newer independently synced entitlement information', () => {
  const cached = { id: 'a', expires_at: '2026-11-01T00:00:00Z', expiration_checked_at: '2026-09-10T00:00:01Z' };
  const fresh = { id: 'a', expires_at: '2026-10-01T00:00:00Z', expiration_checked_at: cached.expiration_checked_at,
    billing_renewal_date: '2026-10-10T00:00:00Z' };
  const result = latestBillingSnapshot(cached, fresh);
  assert.equal(result.expires_at, cached.expires_at);
  assert.equal(result.billing_renewal_date, fresh.billing_renewal_date);
});

test('the same API values display identically in six process timezones (no browser)', () => {
  const url = new URL('../src/billingTime.ts', import.meta.url).href;
  const code = `import {billingTime} from ${JSON.stringify(url)};console.log(JSON.stringify(['2026-09-17T10:48:44Z','2026-09-17T18:48:44+08:00','2026-09-17T10:48:44','2026-09-17',1789642124000].map(billingTime)));`;
  let baseline;
  for (const TZ of ['UTC', 'Asia/Shanghai', 'America/Los_Angeles', 'Europe/London', 'Asia/Tokyo', 'Pacific/Honolulu']) {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8', env: { ...process.env, TZ }, timeout: 15_000 });
    assert.equal(result.status, 0, result.stderr); baseline ??= result.stdout;
    assert.equal(result.stdout, baseline, TZ);
  }
});
