import { useState } from 'react';
import { Button, Card, Empty, Modal, Progress, Segmented, Table, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { AuthorizationProgress, RequestError, Status } from '../components';
import type { Job, Jobs as JobsData } from '../types';
export default function Jobs({ data, loading, error, reload }: { data?: JobsData; loading: boolean; error?: string; reload: () => void }) {
  const [filter, setFilter] = useState('all');
  const [detail, setDetail] = useState<Job>();
  const rows = [...(data?.pipeline || []).map((row) => ({ ...row, type: row.team_authorization ? 'Team 授权' : '普通授权' })), ...(data?.team || []).map((row) => ({ ...row, type: '母号操作' }))];
  const active = data?.authorization.filter((item) => item.active > 0) || [];
  const finished = data?.authorization.filter((item) => !item.active) || [];
  const filtered = rows.filter((row) => filter === 'all' || (filter === 'active' ? ['queued', 'running', 'retrying'].includes(row.status || '') : row.status === 'failed'));
  return <div className="page-stack">
    {!!active.length && <Card className="data-card" size="small" title="正在授权"><div className="progress-viewport"><AuthorizationProgress batches={active} /></div></Card>}
    <Card className="data-card">
      <div className="table-toolbar"><Segmented aria-label="任务状态" value={filter} onChange={setFilter} options={[{ value: 'all', label: '全部任务' }, { value: 'active', label: '进行中' }, { value: 'failed', label: '失败' }]} /><Button icon={<ReloadOutlined />} onClick={reload} loading={loading}>刷新</Button></div>
      <RequestError value={error} />
      <Table<Job & { type: string }> size="middle" rowKey={(row) => row.type + '-' + row.id} dataSource={filtered} scroll={{ x: 1050, y: 'max(280px, calc(100dvh - 420px))' }} pagination={{ defaultPageSize: 30, showTotal: (total) => '共 ' + total + ' 条记录' }} columns={[
        { title: '类型', dataIndex: 'type', width: 110 }, { title: '账号 / 母号', render: (_, row) => row.email || row.parent_email || row.account_id, width: 230, ellipsis: true },
        { title: '状态', dataIndex: 'status', width: 105, render: (value) => <Status value={value} /> },
        { title: '进度', width: 130, render: (_, row) => row.total ? <Progress size="small" percent={Math.min(100, Math.round((row.completed || 0) * 100 / row.total))} status={row.status === 'failed' ? 'exception' : 'normal'} /> : '—' },
        { title: '信息', ellipsis: true, render: (_, row) => row.message || row.error || row.stage || '—' },
        { title: '更新时间', dataIndex: 'updated_at', width: 180 },
        { title: '操作', width: 75, render: (_, row) => <Button type="link" size="small" onClick={() => setDetail(row)}>详情</Button> },
      ]} />
    </Card>
    {!!finished.length && <details className="history-panel"><summary>已结束授权批次 <span className="muted">{finished.length}</span></summary><div className="progress-viewport details-body"><AuthorizationProgress batches={finished} /></div></details>}
    <Modal title="任务详情" open={!!detail} onCancel={() => setDetail(undefined)} footer={<Button onClick={() => setDetail(undefined)}>关闭</Button>}>
      {detail ? <><div className="operation-context"><Typography.Text strong>{detail.email || detail.parent_email || detail.account_id}</Typography.Text><Status value={detail.status} /></div><dl className="detail-list"><dt>阶段</dt><dd>{detail.stage || detail.kind || '—'}</dd><dt>更新时间</dt><dd>{detail.updated_at || '—'}</dd><dt>任务 ID</dt><dd>{detail.id}</dd></dl><Typography.Paragraph className="task-message">{detail.error || detail.message || '暂无更多信息'}</Typography.Paragraph>{detail.error && detail.message && detail.error !== detail.message && <Typography.Paragraph className="task-message">{detail.message}</Typography.Paragraph>}</> : <Empty />}
    </Modal>
  </div>;
}
