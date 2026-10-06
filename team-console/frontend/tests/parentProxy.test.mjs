import test from 'node:test';
import assert from 'node:assert/strict';
import { parentProxyTarget, parentProxyChanged, parentProxyPayload } from '../src/parentProxySettings.ts';

test('proxy target freezes only identity and revision, not credentials', () => {
  const parent = { id: 4, email: 'mother@example.invalid', access_token: 'private', proxy: { revision: 'r1', preview: 'masked' } };
  const target = parentProxyTarget(parent);
  parent.id = 5; parent.proxy.revision = 'r2';
  assert.deepEqual(target, { id: 4, email: 'mother@example.invalid', revision: 'r1' });
  assert.ok(Object.isFrozen(target));
  assert.ok(parentProxyChanged(target, parent));
});
test('manual proxy is sent only when explicitly chosen; pool action excludes stale input', () => {
  const target = parentProxyTarget({ id: 1, email: 'mother@example.invalid' });
  assert.deepEqual(parentProxyPayload(target, 'pool', 'stale-private'), {
    confirm: true, expected_email: target.email, expected_revision: '', action: 'pool',
  });
  assert.equal(parentProxyPayload(target, 'manual', '  http://host:1234 ').proxy_url, 'http://host:1234');
  assert.throws(() => parentProxyPayload(target, 'manual', '  '));
  assert.throws(() => parentProxyPayload(target, 'clear', ''));
});
test('any reused ID, changed email or changed binding invalidates the confirmation', () => {
  const parent = { id: 1, email: 'mother@example.invalid', proxy: { revision: 'r1' } };
  const target = parentProxyTarget(parent);
  assert.equal(parentProxyChanged(target, parent), false);
  for (const other of [{ ...parent, id: 2 }, { ...parent, email: 'another@example.invalid' }, { ...parent, proxy: { revision: 'r2' } }, { ...parent, proxy: undefined }]) {
    assert.equal(parentProxyChanged(target, other), true);
  }
});
test('invalid parent selection is not submitted', () => {
  for (const id of [0, -1, 1.5, NaN, '2']) assert.throws(() => parentProxyTarget({ id, email: 'mother@example.invalid' }));
  assert.throws(() => parentProxyTarget({ id: 1, email: ' ' }));
});
