import { Alert, Button, Progress, Tag, Tooltip, Typography } from 'antd';
import type { AuthorizationBatch, IndexStatus, Quota } from './types';
import { quotaPresentation } from './quota';
const labels: Record<string, string> = {
  success: '成功', failed: '失败', queued: '排队中', running: '进行中', retrying: '重试中', confirming: '确认结果',
  active: '已接入', active_external: '已接入', connected: '已授权', not_connected: '未授权',
  deactivated: '已封禁',
  not_configured: '未配置', activation_uncertain: '待验证', unchecked: '未查询',
  interrupted: '已中断', cancelled: '已取消', not_synced: '未同步',
  partial: '部分完成', partial_failed: '部分失败', partial_cancelled: '部分取消', incomplete: '明细不完整',
};
export function Status({ value }: { value?: string | number }) {
  const key = String(value ?? '—');
  const color = ['success', 'active', 'active_external', 'connected'].includes(key) ? 'success' : ['failed', 'interrupted', 'deactivated'].includes(key) ? 'error' : ['partial', 'partial_failed', 'partial_cancelled', 'incomplete'].includes(key) ? 'warning' : ['running', 'queued', 'retrying'].includes(key) ? 'info' : 'default';
  return <Tag className={"status-tag status-" + color}>{labels[key] || key}</Tag>;
}
export function IndexNotice({ value }: { value?: IndexStatus }) {
  if (!value) return null;
  if (value.error) return <Alert type="warning" showIcon message={value.error} className="notice" />;
  if (!value.ready) return <Alert type="info" showIcon message="正在更新列表…" className="notice" />;
  return null;
}
export function RequestError({ value }: { value?: string }) {
  return value ? <Alert type="error" showIcon message={value} className="notice" /> : null;
}
export function QuotaCell({ value }: { value?: Quota | null }) {
  if (!value) return <Tooltip title="未匹配本地账号"><Typography.Text type="secondary">—</Typography.Text></Tooltip>;
  const view = quotaPresentation(value);
  return <div className="quota-cell">
    {view.status && <Status value={view.status} />}
    {view.previous && <Typography.Text type="secondary">上次结果</Typography.Text>}
    {view.limitation && <Typography.Text type="warning">{view.limitation}</Typography.Text>}
    {view.windows.map((window) => <Typography.Text key={window.key} type="secondary">{window.text}</Typography.Text>)}
    {view.credits && <Typography.Text type="secondary">{view.credits}</Typography.Text>}
    {view.missing && <Tooltip title="没有可显示的额度窗口或点数余额。旧查询记录可能未保存余额，请重新查额度。"><Typography.Text type="secondary">{view.missing}</Typography.Text></Tooltip>}
  </div>;
}
export function AuthorizationSummary({ batches, onOpen }: { batches: AuthorizationBatch[]; onOpen: () => void }) {
  return <div className="authorization-strip" aria-label="进行中的授权">
    <div className="authorization-strip-groups">{[false, true].map((team) => {
      const matching = batches.filter((item) => item.team_authorization === team);
      if (!matching.length) return null;
      const total = matching.reduce((sum, item) => sum + item.total, 0);
      const finished = matching.reduce((sum, item) => sum + item.finished, 0);
      return <div className="authorization-strip-item" key={String(team)}><span>{team ? 'Team 授权' : '普通授权'}</span>
        <Progress percent={total ? Math.min(100, Math.round(finished * 100 / total)) : 0} size="small" showInfo={false} status="active" />
        <span className="muted tabular">{finished}/{total} · 执行 {matching.reduce((sum, item) => sum + (item.running || 0), 0)}</span>
      </div>;
    })}</div><Button type="link" size="small" onClick={onOpen}>查看进度</Button>
  </div>;
}
