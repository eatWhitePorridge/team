// Pure request data; shared by both target selectors, with no UI dependencies.
export type WorkspaceChoice =
  | { mode: 'manual'; workspaceId: string }
  | { mode: 'parent'; workspaceId: string; parentId?: number; workspaces: readonly { id: string }[] };

export function freezeAuthorizationAccounts(ids: readonly number[]): number[] {
  if (!ids.length || ids.length > 500 || ids.some(id => !Number.isSafeInteger(id) || id <= 0)) {
    throw new Error('请选择 1–500 个有效账号');
  }
  return [...new Set(ids)];
}

export function teamAuthorizationPayload(ids: readonly number[], choice: WorkspaceChoice) {
  const account_ids = freezeAuthorizationAccounts(ids);
  const workspace = choice.workspaceId.trim();
  if (!/^[A-Za-z0-9_-]{1,200}$/.test(workspace)) throw new Error('请填写有效的工作区 ID');
  if (choice.mode === 'parent' && (!Number.isSafeInteger(choice.parentId) || choice.parentId! <= 0
      || !choice.workspaces.some(row => row.id === workspace))) {
    throw new Error('请选择该母号的工作区');
  }
  return { account_ids, team_authorization: true, expected_workspace_id: workspace,
    ...(choice.mode === 'parent' ? { parent_id: choice.parentId! } : {}) };
}
