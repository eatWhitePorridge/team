import axios from 'axios';
import type { Detail } from './types';

const client = axios.create({ timeout: 30_000 });
export class ApiError extends Error {
  constructor(message: string, readonly details: Detail[] = []) { super(message); }
}
export class InvalidAccessKeyError extends ApiError {}
export const AUTH_EXPIRED_EVENT = 'team-console:auth-expired';
let activeKey: string | undefined;
export function getAccessKey() {
  if (activeKey === undefined) {
    try { activeKey = sessionStorage.getItem('team-console-key') || ''; }
    catch { activeKey = ''; }
  }
  return activeKey;
}
export function setAccessKey(key: string) {
  activeKey = key.trim();
  try {
    if (activeKey) sessionStorage.setItem('team-console-key', activeKey);
    else sessionStorage.removeItem('team-console-key');
  } catch { /* Private storage disabled: keep this tab's key in memory only. */ }
}
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
  const key = getAccessKey();
  if (key) config.headers.set('X-Team-Console-Key', key);
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
    const requestKey = error.config?.headers?.get('X-Team-Console-Key');
    if (getAccessKey() && requestKey === getAccessKey()) {
      setAccessKey('');
      window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT));
    }
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
export async function post<T>(url: string, data?: unknown): Promise<T> {
  return (await client.post<T>(url, data)).data;
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
