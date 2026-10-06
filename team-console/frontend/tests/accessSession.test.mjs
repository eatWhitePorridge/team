import assert from 'node:assert/strict';
import test from 'node:test';
import { ACCESS_STORAGE_KEY, LEGACY_ACCESS_KEY, createAccessSession } from '../src/accessSession.ts';

// Data ports only: no window, DOM, browser storage or React mounting.
function fixture() {
  const values = new Map(), clients = [], events = [];
  let version = 0, writes = 0;
  function tab(legacyKey = '') {
    const previous = new Map(legacyKey ? [[LEGACY_ACCESS_KEY, legacyKey]] : []);
    const client = { listener: null, changes: [], blocked: false };
    clients.push(client);
    const port = {
      getItem(key) { if (client.blocked) throw new Error('fixture storage disabled'); return values.get(key) ?? null; },
      setItem(key, value) {
        if (client.blocked) throw new Error('fixture storage disabled');
        values.set(key, value); writes++;
        for (const other of clients) if (other !== client) events.push(() => other.listener?.());
      },
      removeItem(key) { values.delete(key); },
    };
    const session = createAccessSession({ shared: () => port, legacy: () => ({
      getItem: key => previous.get(key) ?? null, setItem: (key, value) => previous.set(key, value), removeItem: key => previous.delete(key),
    }), revision: () => 'fixture-' + ++version,
    external(notify) { client.listener = notify; return () => { client.listener = null; }; } });
    const stop = session.subscribe(change => client.changes.push(change));
    return { ...client, session, changes: client.changes, previous, stop, block: () => { client.blocked = true; } };
  }
  return { tab, values, writes: () => writes, flush() { while (events.length) events.shift()(); } };
}
const login = (tab, key = 'fixture-only') => tab.session.acceptVerified(key, tab.session.read());

test('verified login shares a key across tabs and reopening; verification does not bounce storage events', () => {
  const f = fixture(), a = f.tab(), b = f.tab();
  assert.equal(login(a), true); f.flush();
  const saved = b.session.read();
  assert.equal(saved.key, 'fixture-only');
  assert.equal(b.changes.at(-1).reason, 'external');
  assert.equal(b.session.acceptVerified(saved.key, saved), true);
  assert.equal(f.writes(), 1);
  assert.deepEqual(f.tab().session.read(), saved);
  assert.equal(a.changes.at(-1).reason, 'verified');
});

test('legacy tab key is kept through repeated reads, then migrated only after verification', () => {
  const f = fixture(), a = f.tab('legacy-fixture');
  const saved = a.session.read();
  assert.equal(saved.revision, 'legacy');
  assert.deepEqual(a.session.read(), saved);
  assert.equal(f.values.size, 0);
  assert.equal(a.session.acceptVerified(saved.key, saved), true);
  assert.equal(a.previous.size, 0);
  assert.equal(f.tab().session.read().key, 'legacy-fixture');
  assert.equal(f.writes(), 1);
});

test('logout clears all tabs; tombstone prevents old sessionStorage credentials from returning', () => {
  const f = fixture(), a = f.tab(), b = f.tab();
  login(a); f.flush(); a.session.logout(); f.flush();
  assert.equal(a.session.read().key, '');
  assert.equal(b.session.read().key, '');
  assert.equal(f.tab('stale-legacy-fixture').session.read().key, '');
  assert.equal(JSON.parse(f.values.get(ACCESS_STORAGE_KEY)).key, '');
});

test('logout during pending first login wins even before the external event is delivered', () => {
  const f = fixture(), a = f.tab(), b = f.tab();
  const pending = a.session.read();
  b.session.logout();
  assert.equal(a.session.acceptVerified('late-candidate', pending), false);
  assert.equal(a.session.read().key, '');
});

test('late initial verification cannot overwrite another tab replacing the key', () => {
  const f = fixture(), a = f.tab(), b = f.tab();
  login(a, 'fixture-old'); const pending = a.session.read();
  login(b, 'fixture-new');
  assert.equal(a.session.acceptVerified(pending.key, pending), false);
  assert.equal(a.session.read().key, 'fixture-new');
});

test('a stale 401 or SSE expiry cannot log out a newer session, including same-key re-login', () => {
  const f = fixture(), a = f.tab();
  login(a); const old = a.session.read();
  a.session.logout(); login(a);
  assert.equal(a.session.expire(old), false);
  assert.equal(a.session.read().key, 'fixture-only');
  assert.equal(a.session.expire(a.session.read()), true);
  assert.equal(a.session.read().key, '');
  assert.equal(a.changes.at(-1).reason, 'expired');
});

test('queued external events read latest state rather than replaying stale keys', () => {
  const f = fixture(), a = f.tab(), b = f.tab();
  login(a); a.session.logout(); login(a, 'new-fixture'); f.flush();
  assert.equal(b.changes.length, 3);
  assert.ok(b.changes.every(change => change.snapshot.key === 'new-fixture'));
});

test('shared logout invalidates legacy validation already in flight', () => {
  const f = fixture(), a = f.tab('legacy-fixture'), b = f.tab();
  const pending = a.session.read(); b.session.logout();
  assert.equal(a.session.acceptVerified(pending.key, pending), false);
  assert.equal(a.previous.size, 0);
});

test('unavailable shared storage preserves memory login and local logout', () => {
  const f = fixture(), a = f.tab(); a.block();
  assert.equal(login(a), true);
  assert.equal(a.session.read().key, 'fixture-only');
  assert.equal(f.writes(), 0);
  a.session.logout(); assert.equal(a.session.read().key, '');
});

test('invalid or unknown shared record locks and does not restore legacy credentials', () => {
  for (const raw of ['bad-json', 'null', '{"version":9,"key":"fixture"}', '{"version":1,"key":5,"revision":"r"}']) {
    const f = fixture(); f.values.set(ACCESS_STORAGE_KEY, raw);
    const a = f.tab('stale-fixture');
    assert.equal(a.session.read().key, '');
    assert.equal(a.previous.size, 0);
    assert.equal(login(a), true);
  }
});

test('storage clear locks existing tabs; unsubscribed listeners stop receiving updates', () => {
  const f = fixture(), a = f.tab(), b = f.tab(); login(a); f.flush();
  b.stop(); const count = b.changes.length;
  a.session.logout(); f.flush(); assert.equal(b.changes.length, count);
  f.values.clear(); assert.equal(a.session.read().key, '');
});

test('blank candidates are not stored or accepted', () => {
  const f = fixture(), a = f.tab();
  assert.equal(login(a, '   '), false);
  assert.equal(f.writes(), 0);
  assert.equal(a.changes.length, 0);
});
