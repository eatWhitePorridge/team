import assert from 'node:assert/strict';
import test from 'node:test';
import { inviteSwitchPayload, pendingInviteParams } from '../src/invitationActions.ts';

test('pending invitation queries always request all cached results with independent filters', () => {
  assert.deepEqual(pendingInviteParams(), { page_size: 'all', status: 'pending', q: '', seat_type: '' });
  assert.deepEqual(pendingInviteParams('fixture@example.invalid', 'prolite'), { page_size: 'all', status: 'pending', q: 'fixture@example.invalid', seat_type: 'prolite' });
});

test('invitation selection is frozen and deduplicated without a 200-row ceiling', () => {
  const ids = Array.from({ length: 631 }, (_, i) => 'invite-' + i);
  const result = inviteSwitchPayload('workspace-test', [...ids, ids[0]], 'prolite');
  ids.pop();
  assert.equal(result.invite_ids.length, 631);
  assert.equal(result.kind, 'invite_switch');
  assert.equal(result.seat_type, 'prolite');
  assert.equal(result.concurrency, 5);
  assert.equal('user_ids' in result, false);
  assert.equal('email_addresses' in result, false);
});

test('invitation switch concurrency is independent of the selection count and strictly validated', () => {
  for (const concurrency of [1, 5, 10, 20]) {
    assert.equal(inviteSwitchPayload('workspace-test', ['invite-1'], 'prolite', concurrency).concurrency, concurrency);
  }
  for (const concurrency of [0, -1, 21, 1.5, '5', null, true, NaN, Infinity]) {
    assert.throws(() => inviteSwitchPayload('workspace-test', ['invite-1'], 'prolite', concurrency));
  }
});

test('invalid invitation IDs and seats are not converted into member or invitation POST requests', () => {
  for (const ids of [[], ['invite/bad'], [''], [12]]) assert.throws(() => inviteSwitchPayload('workspace-test', ids, 'prolite'));
  assert.throws(() => inviteSwitchPayload('workspace/bad', ['invite-1'], 'prolite'));
  assert.throws(() => inviteSwitchPayload('workspace-test', ['invite-1'], 'invalid'));
});
