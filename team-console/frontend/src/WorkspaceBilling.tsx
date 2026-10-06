import { useEffect, useRef, useState } from 'react';
import { Button, Tag, Tooltip, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { errorText, post } from './api';
import { BILLING_TIME_LABEL, latestBillingSnapshot, workspaceBillingView } from './billingTime';
import type { BillingTime } from './billingTime';
import type { Parent, Workspace } from './types';

function TimeValue({ value }: { value: BillingTime }) {
  return value.state === 'valid' ? <time dateTime={value.iso} className="tabular">{value.text}（{BILLING_TIME_LABEL}）</time>
    : <span>{value.text}{value.note && <span className="muted"> · {value.note}</span>}</span>;
}

export default function WorkspaceBilling({ parent, workspace, disabled, onRefresh, onBusyChange }: {
  parent: Parent; workspace: Workspace; disabled: boolean; onRefresh: () => void; onBusyChange: (busy: boolean) => void;
}) {
  const [queried, setQueried] = useState<Workspace>();
  const [pending, setPending] = useState(false), [queryError, setQueryError] = useState('');
  const active = useRef(false), lock = useRef(false), controller = useRef<AbortController | undefined>(undefined);
  useEffect(() => {
    active.current = true;
    return () => { active.current = false; controller.current?.abort(); onBusyChange(false); };
  }, [onBusyChange]);
  const snapshot = latestBillingSnapshot(workspace, queried), view = workspaceBillingView(snapshot);
  const error = queryError || view.error;
  const blocked = disabled || !workspace.can_manage || parent.has_access_token === false;
  const query = async () => {
    if (blocked || lock.current) return;
    lock.current = true;
    const abort = new AbortController(); controller.current = abort;
    setPending(true); setQueryError(''); onBusyChange(true);
    try {
      // Existing read-only upstream preview. No member/seat operation, no
      // automatic refresh loop; its two/three GET probes can exceed 30 seconds.
      const result = await post<{ workspace: Workspace }>(
        `/api/team-admin/parents/${parent.id}/workspaces/${encodeURIComponent(workspace.id)}/subscription-expiration`,
        {}, { timeout: 90_000, signal: abort.signal },
      );
      if (!active.current || abort.signal.aborted) return;
      if (!result.workspace || result.workspace.id !== workspace.id) throw new Error('返回的工作区不匹配，请刷新后重试');
      setQueried(result.workspace);
    } catch (err) {
      if (!active.current || abort.signal.aborted) return;
      const message = errorText(err);
      setQueryError(message.startsWith('网络请求失败；') ? '账单查询网络异常或超时，请稍后手动重试。' : message);
    } finally {
      if (active.current && !abort.signal.aborted) {
        lock.current = false; setPending(false); onBusyChange(false); onRefresh();
      }
    }
  };
  const hasDetails = !!(view.renewal.raw || view.checked.raw || view.entitlement.raw || view.succeeded.raw);
  return <section className="workspace-billing" aria-label="工作区账单时间" aria-busy={pending}>
    <div className="billing-line">
      <div className="billing-value" aria-live="polite"><span className="muted">账单续费</span>
        {view.renewal.state === 'valid' ? <><strong><time className="tabular" dateTime={view.renewal.iso}>{view.renewal.text}</time></strong><span className="billing-zone">{BILLING_TIME_LABEL}</span></>
          : <span className={view.renewal.state === 'missing' ? 'muted' : 'billing-warning'}>{view.renewal.text}{view.renewal.state === 'date_only' && ' · 时区未提供'}</span>}
        {error && view.renewal.state !== 'missing' && <Tag color="warning">上次结果</Tag>}
      </div>
      <Tooltip title={parent.has_access_token === false ? '请先补充母号 Web AT' : !workspace.can_manage ? '当前工作区没有管理权限' : '只查询账单预览，不修改席位'}>
        <Button size="small" icon={<ReloadOutlined />} loading={pending} disabled={blocked} onClick={() => void query()}>查询账单</Button>
      </Tooltip>
    </div>
    {error && <p className="billing-error" role="alert">查询失败：{error}</p>}
    {hasDetails && <details className="billing-details"><summary>时间详情</summary><dl>
      {view.renewal.raw && <><dt>原始账单值</dt><dd><Typography.Text copyable>{view.renewal.raw}</Typography.Text>{view.renewal.note && <p>{view.renewal.note}</p>}</dd><dt>来源</dt><dd>{view.source}</dd></>}
      {view.succeeded.raw && <><dt>成功查询</dt><dd><TimeValue value={view.succeeded} /></dd></>}
      {view.checked.raw && view.checked.raw !== view.succeeded.raw && <><dt>最近尝试</dt><dd><TimeValue value={view.checked} /></dd></>}
      {view.entitlement.raw && <><dt>权益到期</dt><dd><TimeValue value={view.entitlement} /></dd></>}
    </dl></details>}
  </section>;
}
