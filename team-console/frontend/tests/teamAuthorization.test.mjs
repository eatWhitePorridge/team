// Pure payload tests; no DOM, browser, React rendering, or UI tests.
import assert from 'node:assert/strict';
import test from 'node:test';
import { freezeAuthorizationAccounts, teamAuthorizationPayload } from '../src/teamAuthorization.ts';

test('manual workspace uses an explicit target without requiring or sending a mother ID', () => {
  const payload = teamAuthorizationPayload([1, 22, 1], { mode: 'manual', workspaceId: ' team-target_2 \n' });
  assert.deepEqual(payload, { account_ids: [1, 22], team_authorization: true, expected_workspace_id: 'team-target_2' });
});

test('mother selection sends both the chosen mother and exact cached workspace', () => {
  assert.deepEqual(teamAuthorizationPayload([7], {
    mode: 'parent', parentId: 9, workspaceId: 'second-team', workspaces: [{ id: 'first-team' }, { id: 'second-team' }],
  }), { account_ids: [7], team_authorization: true, expected_workspace_id: 'second-team', parent_id: 9 });
});

test('changing mothers cannot reuse a workspace from the previous mother or fall back to the first', () => {
  for (const parentId of [undefined, null, true, '9', 0, -1, 1.5]) {
    assert.throws(() => teamAuthorizationPayload([1], { mode: 'parent', parentId, workspaceId: 'a', workspaces: [{ id: 'a' }] }));
  }
  assert.throws(() => teamAuthorizationPayload([1], { mode: 'parent', parentId: 2, workspaceId: 'old-team', workspaces: [{ id: 'new-team' }] }));
  assert.throws(() => teamAuthorizationPayload([1], { mode: 'parent', parentId: 2, workspaceId: '', workspaces: [{ id: 'new-team' }] }));
});

test('mode switching only uses the active choice, not hidden previous mother fields', () => {
  const choice = { mode: 'manual', workspaceId: 'manual-team', parentId: 42, workspaces: [{ id: 'old-team' }] };
  assert.equal(teamAuthorizationPayload([1], choice).expected_workspace_id, 'manual-team');
  assert.equal('parent_id' in teamAuthorizationPayload([1], choice), false);
});

test('freezes cross-page account selection independently of background list updates', () => {
  const selected = [1, 22, 400, 1];
  const frozen = freezeAuthorizationAccounts(selected);
  selected.splice(0, selected.length, 2);
  const payload = teamAuthorizationPayload(frozen, { mode: 'manual', workspaceId: 'fixed-team' });
  payload.account_ids.push(8);
  assert.deepEqual(frozen, [1, 22, 400]);
  assert.deepEqual(teamAuthorizationPayload(frozen, { mode: 'manual', workspaceId: 'fixed-team' }).account_ids, [1, 22, 400]);
});

test('invalid or absent target never becomes implicit automatic workspace selection', () => {
  for (const workspaceId of ['', '  ', 'https://example.invalid/a', 'a/b', 'a b', 'a\nb', '../workspace', '工作区', 'a'.repeat(201)]) {
    assert.throws(() => teamAuthorizationPayload([1], { mode: 'manual', workspaceId }));
  }
  assert.equal(teamAuthorizationPayload([1], { mode: 'manual', workspaceId: 'a'.repeat(200) }).expected_workspace_id.length, 200);
});

test('invalid or oversized account selections cannot reach the request builder', () => {
  for (const ids of [[], [true], [0], [-1], [1.5], [NaN], ['1'], Array(501).fill(1)]) assert.throws(() => freezeAuthorizationAccounts(ids));
  assert.equal(freezeAuthorizationAccounts(Array.from({ length: 500 }, (_, i) => i + 1)).length, 500);
});
