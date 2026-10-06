import type { Parent } from './types';

export function parentProxyTarget(parent: Parent) {
  if (!Number.isSafeInteger(parent.id) || parent.id < 1 || !parent.email.trim()) throw new Error('请刷新母号信息');
  return Object.freeze({ id: parent.id, email: parent.email, revision: parent.proxy?.revision || '' });
}
export type ParentProxyTarget = ReturnType<typeof parentProxyTarget>;
export function parentProxyChanged(target: ParentProxyTarget, parent: Parent) {
  return target.id !== parent.id || target.email !== parent.email || target.revision !== (parent.proxy?.revision || '');
}
export function parentProxyPayload(target: ParentProxyTarget, action: 'manual' | 'pool', value: string) {
  if (!['manual', 'pool'].includes(action) || (action === 'manual' && !value.trim())) throw new Error('请填写固定代理地址');
  return { confirm: true, expected_email: target.email, expected_revision: target.revision, action,
    ...(action === 'manual' ? { proxy_url: value.trim() } : {}) };
}
