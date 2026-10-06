import assert from 'node:assert/strict';
import test from 'node:test';
import { childAccountScope, childAccountParams } from '../src/childAccounts.ts';

test('child navigation freezes only the selected parent/workspace identity', () => {
  const parent = { id: 7, email: 'owner@example.invalid', access_token: 'private' };
  const workspace = { id: 'space-2', name: 'Second workspace', members_synced_at: 'now', members: ['private'] };
  const scope = childAccountScope(parent, workspace);
  assert.deepEqual(scope, { parentId: 7, parentEmail: parent.email, workspaceId: 'space-2', workspaceName: workspace.name });
  assert.equal(Object.isFrozen(scope), true);
  parent.id = 8; workspace.id = 'space-3';
  assert.deepEqual(childAccountParams(scope), { team_parent_id: '7', team_workspace_id: 'space-2' });
  assert.equal(JSON.stringify(scope).includes('private'), false);
});

test('all/batch account navigation has no inherited team filter', () => {
  assert.deepEqual(childAccountParams(), {});
  assert.equal(childAccountScope({ id: 1, email: 'owner@example.invalid' }, { id: 'space-1' }).workspaceName, 'space-1');
});

test('incomplete or invalid child scope fails instead of querying every account', () => {
  for (const parentId of [0, -1, NaN, 1.5, '1']) {
    assert.throws(() => childAccountScope({ id: parentId, email: '' }, { id: 'workspace' }));
    assert.throws(() => childAccountParams({ parentId, workspaceId: 'workspace' }));
  }
  assert.throws(() => childAccountScope({ id: 1, email: '' }, { id: ' ' }));
  assert.throws(() => childAccountParams({ parentId: 1, workspaceId: ' ' }));
});

test('different parent/workspace selections produce different selection scopes', () => {
  const filters = { q: '', batch_id: '', codex_plan_type: 'free' };
  const keys = new Set([[1, 'a'], [1, 'b'], [2, 'a']].map(([id, workspace]) => {
    const scope = childAccountScope({ id, email: 'owner@example.invalid' }, { id: workspace });
    const params = childAccountParams(scope);
    assert.equal(params.batch_id, undefined);
    assert.equal(params.codex_plan_type, undefined);
    return JSON.stringify([filters, params]);
  }));
  assert.equal(keys.size, 3);
});
