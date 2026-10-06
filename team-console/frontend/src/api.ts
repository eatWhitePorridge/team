import axios from 'axios';
import type { InternalAxiosRequestConfig } from 'axios';
import { ACCESS_STORAGE_KEY, createAccessSession } from './accessSession';
import type { AccessSnapshot } from './accessSession';
import type { Detail } from './types';

const client = axios.create({ timeout: 30_000 });
export class ApiError extends Error {
  constructor(message: string, readonly details: Detail[] = []) { super(message); }
}
export class InvalidAccessKeyError extends ApiError {}
export const accessSession = createAccessSession({
  shared: () => localStorage, legacy: () => sessionStorage,
  external: (notify) => {
    const changed = (event: StorageEvent) => {
      if (event.key !== null && event.key !== ACCESS_STORAGE_KEY) return;
      try { if (event.storageArea !== localStorage) return; } catch { return; }
      notify();
    };
    window.addEventListener('storage', changed);
    return () => window.removeEventListener('storage', changed);
  },
});
export function getAccessKey() { return accessSession.read().key; }
type AuthenticatedRequest = InternalAxiosRequestConfig & { consoleSession?: AccessSnapshot };
export async function verifyAccessKey(key: string, signal?: AbortSignal): Promise<void> {
  if (!key.trim()) throw new InvalidAccessKeyError('请输入访问密钥');
  try {
    // Separate from client: a previously saved key must never replace the
    // candidate, and a failed login must not replay any business request.
    const response = await axios.get('/api/auth/verify', {
      headers: { 'X-Team-Console-Key': key.trim() }, timeout: 15_000, signal,
    });
    if (response.data?.ok !== true) throw new ApiError('密钥验证失败，请稍后重试');
  } catch (error) {
    if (axios.isCancel(error) || error instanceof ApiError) throw error;
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      throw new InvalidAccessKeyError('密钥不正确，请重新输入');
    }
    if (axios.isAxiosError(error) && error.response?.data?.code === 'access_key_unconfigured') {
      throw new ApiError('后台尚未配置访问密钥，请先设置 TEAM_CONSOLE_API_KEY');
    }
    throw new ApiError('无法连接验证服务，请稍后重试');
  }
}
client.interceptors.request.use((config) => {
  const snapshot = accessSession.read();
  (config as AuthenticatedRequest).consoleSession = snapshot;
  if (snapshot.key) config.headers.set('X-Team-Console-Key', snapshot.key);
  return config;
});
// Never replay POST/PATCH/DELETE after timeouts or authentication failures.
client.interceptors.response.use((response) => {
  if (response.data?.ok === false) throw responseError(response.data);
  return response;
}, (error) => {
  if (axios.isCancel(error)) throw error;
  // Upstream Team credentials can also return 401. Only our own API guard's
  // explicit code invalidates this login; ignore stale requests from old keys.
  if (error.response?.status === 401 && error.response?.data?.code === 'access_key_invalid') {
    const snapshot = (error.config as AuthenticatedRequest | undefined)?.consoleSession;
    if (snapshot) accessSession.expire(snapshot);
  }
  if (error.response?.data && typeof error.response.data === 'object') throw responseError(error.response.data);
  throw new ApiError('网络请求失败；写入操作未自动重试，请先查看任务记录');
});
function responseError(data: { error?: string; busy?: Detail[]; skipped?: Detail[]; failed?: Detail[]; no_token?: Detail[] }) {
  return new ApiError(data.error || '操作未成功', [...(data.busy || []), ...(data.skipped || []), ...(data.failed || []), ...(data.no_token || [])]);
}
export async function get<T>(url: string, params?: Record<string, unknown>, signal?: AbortSignal): Promise<T> {
  return (await client.get<T>(url, { params, signal })).data;
}
export async function post<T>(url: string, data?: unknown, options?: { timeout?: number; signal?: AbortSignal }): Promise<T> {
  return (await client.post<T>(url, data, options)).data;
}
export async function deleteResource<T>(url: string, data?: unknown): Promise<T> {
  return (await client.delete<T>(url, { data })).data;
}
export function saveDownload(data: unknown, filename: string) {
  saveBlob(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }), filename);
}
export function saveTextDownload(text: string, filename: string) {
  saveBlob(new Blob([text], { type: 'text/plain;charset=utf-8' }), filename);
}
function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename.replace(/[/\\]/g, '_');
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}
export function errorText(error: unknown) { return error instanceof Error ? error.message : '请求失败'; }
