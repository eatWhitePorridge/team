// Selection/request data only; no React or browser UI dependencies.
export interface SplitTarget { ids: number[]; requestId: string }

export function createSplitTarget(ids: readonly number[], random: Pick<Crypto, 'getRandomValues'> = globalThis.crypto): SplitTarget {
  if (!ids.length || ids.length > 5000 || ids.some((id) => !Number.isSafeInteger(id) || id <= 0)) {
    throw new Error('请选择 1-5000 个有效账号');
  }
  // randomUUID() requires HTTPS; getRandomValues also works on our HTTP LAN UI.
  const bytes = random.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return { ids: [...new Set(ids)], requestId: Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('') };
}

export function splitPayload(target: SplitTarget) {
  return { account_ids: [...target.ids], request_id: target.requestId, confirm: true };
}
