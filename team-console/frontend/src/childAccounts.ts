import type { Parent, Workspace } from './types';

/** Snapshot just the navigation identity, never parent credentials or members. */
export type ChildAccountScope = Readonly<{
  parentId: number; parentEmail: string; workspaceId: string; workspaceName: string;
}>;

export function childAccountScope(parent: Parent, workspace: Workspace): ChildAccountScope {
  if (!Number.isSafeInteger(parent.id) || parent.id <= 0 || !workspace.id.trim()) {
    throw new Error('请选择母号和工作区');
  }
  return Object.freeze({ parentId: parent.id, parentEmail: parent.email,
    workspaceId: workspace.id.trim(), workspaceName: workspace.name || workspace.id });
}

export function childAccountParams(scope?: ChildAccountScope): Record<string, string> {
  if (!scope) return {};
  if (!Number.isSafeInteger(scope.parentId) || scope.parentId <= 0 || !scope.workspaceId.trim()) {
    throw new Error('子号筛选缺少母号或工作区');
  }
  return { team_parent_id: String(scope.parentId), team_workspace_id: scope.workspaceId.trim() };
}
