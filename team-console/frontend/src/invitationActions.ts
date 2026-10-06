export function pendingInviteParams(q = '', seatType = '') {
  return { page_size: 'all', status: 'pending', q, seat_type: seatType };
}

export function inviteSwitchPayload(workspaceId: string, inviteIds: string[], seatType: string, concurrency = 5) {
  const validId = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_-]{1,200}$/.test(value);
  if (!validId(workspaceId) || !inviteIds.length || !inviteIds.every(validId)) throw new Error('请选择有效的工作区和待接受邀请');
  if (!['default', 'usage_based', 'prolite'].includes(seatType)) throw new Error('请选择有效的目标席位');
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 20) throw new Error('邀请切席并发需为 1-20 的整数');
  // Freeze/deduplicate invitation IDs; never reuse the member user_ids payload.
  return { kind: 'invite_switch', workspace_id: workspaceId, invite_ids: [...new Set(inviteIds)], seat_type: seatType, concurrency };
}
