import { Alert, Button, Progress, Space, Tag, Tooltip, Typography } from 'antd';
import type { AuthorizationBatch, IndexStatus, Numeric, Quota } from './types';
const labels: Record<string, string> = {
  success: '成功', failed: '失败', queued: '排队中', running: '进行中', retrying: '重试中',
  active: '已接入', active_external: '已接入', connected: '已授权', not_connected: '未授权',
  not_configured: '未配置', activation_uncertain: '待验证', unchecked: '未查询',
  interrupted: '已中断', cancelled: '已取消', not_synced: '未同步',
};
export function Status({ value }: { value?: string | number }) {
  const key = String(value ?? '—');
  const color = ['success', 'active', 'active_external', 'connected'].includes(key) ? 'green' : ['failed', 'interrupted'].includes(key) ? 'red' : ['running', 'queued', 'retrying'].includes(key) ? 'blue' : 'default';
  return <Tag color={color}>{labels[key] || key}</Tag>;
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
function windowLabel(raw: Numeric | undefined, fallback: string) {
  const n = Number(raw);
  return n > 0 ? (n >= 86400 ? Math.round(n / 86400) + ' 天' : Math.round(n / 3600) + ' 小时') : fallback;
}
export function QuotaCell({ value }: { value?: Quota | null }) {
  if (!value) return <Tooltip title="未匹配本地账号"><Typography.Text type="secondary">—</Typography.Text></Tooltip>;
  const hasWindows = (['primary', 'secondary'] as const).some((name) => {
    const raw = value['quota_' + name + '_used_percent' as keyof Quota];
    return raw !== null && raw !== undefined && Number.isFinite(Number(raw));
  });
  return <Space direction="vertical" size={1} className="quota-cell">
    {(!hasWindows || !['success', 'active'].includes(value.quota_status || '')) && <Status value={value.quota_status} />}
    {(['primary', 'secondary'] as const).map((name) => {
      const raw = value['quota_' + name + '_used_percent' as keyof Quota];
      if (raw === null || raw === undefined || !Number.isFinite(Number(raw))) return null;
      const remaining = Math.max(0, Math.min(100, 100 - Number(raw)));
      return <Typography.Text key={name} type="secondary">{windowLabel(value['quota_' + name + '_limit_window_seconds' as keyof Quota], name === 'primary' ? '主窗口' : '次窗口')} · 剩余 {remaining.toFixed(0)}%</Typography.Text>;
    })}
  </Space>;
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
        <span className="muted tabular">{finished}/{total}</span>
      </div>;
    })}</div><Button type="link" size="small" onClick={onOpen}>查看进度</Button>
  </div>;
}
export function AuthorizationProgress({ batches }: { batches: AuthorizationBatch[] }) {
  return <div className="progress-grid">{batches.map((item) => <div className="progress-item" key={item.batch_id}>
    <Space><Typography.Text strong>{item.team_authorization ? 'Team 授权' : '普通授权'}</Typography.Text><Tag>{item.active ? '进行中 ' + item.active : '已结束'}</Tag></Space>
    <Progress percent={item.total ? Math.min(100, Math.round(item.finished * 100 / item.total)) : 0} size="small" status={item.active ? 'active' : 'normal'} />
    <Typography.Text type="secondary">已结束 {item.finished} / {item.total} · {item.batch_id.slice(0, 8)}</Typography.Text>
  </div>)}</div>;
}
