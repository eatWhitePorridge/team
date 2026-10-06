import assert from 'node:assert/strict';
import test from 'node:test';
import { createPoller } from '../src/polling.ts';

const flush = async () => { for (let n = 0; n < 5; n += 1) await Promise.resolve(); };
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
class FakeClock {
  time = 0;
  next = 0;
  timers = new Map();
  now = () => this.time;
  setTimeout = (callback, delay) => {
    const id = ++this.next;
    this.timers.set(id, { at: this.time + delay, callback });
    return id;
  };
  clearTimeout = (id) => { this.timers.delete(id); };
  async advance(ms) {
    const target = this.time + ms;
    for (;;) {
      const item = [...this.timers].sort((a, b) => a[1].at - b[1].at)[0];
      if (!item || item[1].at > target) break;
      const [id, timer] = item;
      this.time = timer.at;
      this.timers.delete(id);
      timer.callback();
      await flush();
    }
    this.time = target;
    await flush();
  }
}
function fixture(options = {}) {
  const clock = new FakeClock();
  const values = [], errors = [], starts = [];
  const poller = createPoller({ clock, interval: 1000, read: async () => 'ok',
    onData: (data) => values.push(data), onError: (error) => errors.push(error),
    onStart: (manual) => starts.push({ at: clock.now(), manual }), ...options });
  return { clock, values, errors, starts, poller };
}

test('successful requests use start-to-start cadence instead of response plus interval', async () => {
  const request = deferred();
  const { clock, starts, values, poller } = fixture({ read: () => request.promise });
  poller.refresh();
  await clock.advance(200);
  request.resolve('result');
  await flush();
  assert.deepEqual(values, ['result']);
  await clock.advance(799);
  assert.equal(starts.length, 1);
  await clock.advance(1);
  assert.deepEqual(starts.map((row) => row.at), [0, 1000]);
  assert.equal(starts[1].manual, false);
  poller.stop();
  assert.equal(clock.timers.size, 0);
});

test('latest response switches active cadence back to idle without another effect/request', async () => {
  let active = true;
  const { clock, starts, poller } = fixture({ read: async () => ({ active }), interval: (data) => data?.active ? 1000 : 5000 });
  poller.refresh(); await flush();
  await clock.advance(1000);
  active = false;
  await clock.advance(1000);
  await clock.advance(4999);
  assert.equal(starts.length, 3);
  await clock.advance(1);
  assert.deepEqual(starts.map((row) => row.at), [0, 1000, 2000, 7000]);
  poller.stop();
});

test('slow reads never overlap and keep a minimum gap after completing', async () => {
  const request = deferred();
  const { clock, starts, poller } = fixture({ read: () => request.promise });
  poller.refresh();
  await clock.advance(20_000);
  assert.equal(starts.length, 1);
  request.resolve('ok'); await flush();
  await clock.advance(249);
  assert.equal(starts.length, 1);
  await clock.advance(1);
  assert.deepEqual(starts.map((row) => row.at), [0, 20_250]);
  poller.stop();
});

test('many refresh requests during a read queue only one follow-up, without aborting the read', async () => {
  const request = deferred();
  let signal;
  const { clock, starts, poller } = fixture({ read: (value) => { signal = value; return request.promise; } });
  poller.refresh();
  for (let n = 0; n < 20; n += 1) poller.refresh();
  assert.equal(starts.length, 1);
  assert.equal(signal.aborted, false);
  await clock.advance(100);
  request.resolve('ok'); await flush();
  await clock.advance(149);
  assert.equal(starts.length, 1);
  await clock.advance(1);
  assert.deepEqual(starts.map((row) => row.at), [0, 250]);
  await clock.advance(999);
  assert.equal(starts.length, 2);
  poller.stop();
  assert.equal(signal.aborted, true);
});

test('hidden state cancels timers; becoming visible refreshes immediately and coalesces focus', async () => {
  const { clock, starts, poller } = fixture();
  poller.refresh(); await flush();
  await clock.advance(300);
  poller.setVisible(false);
  assert.equal(clock.timers.size, 0);
  await clock.advance(60_000);
  poller.wake(); poller.refresh();
  assert.equal(starts.length, 1);
  poller.setVisible(true);
  poller.wake(); await flush(); poller.wake();
  assert.deepEqual(starts.map((row) => row.at), [0, 60_300]);
  await clock.advance(1000);
  assert.equal(starts.length, 3);
  poller.stop();
});

test('focus or network recovery interrupts an idle wait, but repeated events do not duplicate reads', async () => {
  const { clock, starts, poller } = fixture({ interval: 5000 });
  poller.refresh(); await flush();
  await clock.advance(2000);
  poller.wake(); poller.wake(); await flush(); poller.wake();
  assert.deepEqual(starts.map((row) => row.at), [0, 2000]);
  await clock.advance(4999);
  assert.equal(starts.length, 2);
  await clock.advance(1);
  assert.equal(starts.length, 3);
  poller.stop();
});

test('a resource created while hidden waits for visibility', async () => {
  const { clock, starts, poller } = fixture({ visible: false });
  poller.refresh(); await clock.advance(60_000);
  assert.equal(starts.length, 0);
  poller.setVisible(true); await flush();
  assert.deepEqual(starts.map((row) => row.at), [60_000]);
  poller.stop();
});

test('read failures back off up to 30 seconds, then success resets the cadence', async () => {
  let fail = true;
  const { clock, starts, errors, poller } = fixture({ read: async () => { if (fail) throw new Error('offline fixture'); return 'ok'; } });
  poller.refresh(); await flush();
  for (const gap of [2000, 4000, 8000, 16_000, 30_000, 30_000]) await clock.advance(gap);
  assert.deepEqual(starts.map((row) => row.at), [0, 2000, 6000, 14_000, 30_000, 60_000, 90_000]);
  assert.equal(errors.length, 7);
  fail = false;
  await clock.advance(30_000);
  await clock.advance(1000);
  assert.deepEqual(starts.slice(-2).map((row) => row.at), [120_000, 121_000]);
  poller.stop();
});

test('one-shot reads are not automatically retried or polled', async () => {
  const { clock, starts, poller } = fixture({ interval: 0, read: async () => { throw new Error('offline fixture'); } });
  poller.refresh(); await flush();
  await clock.advance(60_000);
  assert.equal(starts.length, 1);
  poller.refresh(); await flush();
  assert.equal(starts.length, 2);
  assert.equal(clock.timers.size, 0);
  poller.stop();
});

test('stopped old scopes cannot publish stale data or errors even if read ignores cancellation', async () => {
  for (const outcome of ['resolve', 'reject']) {
    const request = deferred();
    let signal;
    const old = fixture({ read: (value) => { signal = value; return request.promise; } });
    old.poller.refresh(); old.poller.refresh(); old.poller.stop();
    assert.equal(signal.aborted, true);
    const fresh = fixture(); fresh.poller.refresh(); await flush();
    request[outcome](outcome === 'resolve' ? 'stale' : new Error('stale')); await flush();
    assert.deepEqual(old.values, []);
    assert.deepEqual(old.errors, []);
    assert.equal(old.clock.timers.size, 0);
    old.poller.refresh(); old.poller.setVisible(true); old.poller.wake();
    assert.equal(old.starts.length, 1);
    assert.deepEqual(fresh.values, ['ok']);
    fresh.poller.stop();
  }
});

test('finishing a read while hidden does not restart timers', async () => {
  const request = deferred();
  const { clock, starts, poller } = fixture({ read: () => request.promise });
  poller.refresh(); poller.refresh(); poller.setVisible(false);
  request.resolve('ok'); await flush();
  assert.equal(clock.timers.size, 0);
  await clock.advance(10_000);
  assert.equal(starts.length, 1);
  poller.setVisible(true); await flush();
  assert.equal(starts.length, 2);
  poller.stop();
});
