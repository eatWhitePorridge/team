import type { Workspace } from './types';

export const seatLabels: Record<string, string> = { default: '标准席位', usage_based: 'Codex 席位', prolite: '基础席位' };
export function workspaceSeats(workspace?: Workspace, filter = false) {
  return Object.entries(seatLabels).filter(([value]) => value !== 'usage_based'
    || workspace?.is_usage_based_seat_enabled === true
    || (filter && (workspace?.assigned?.usage_based ?? workspace?.seat_type_counts?.usage_based ?? 0) > 0))
    .map(([value, label]) => ({ value, label }));
}
