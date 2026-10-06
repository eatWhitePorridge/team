import { useMemo, useState } from 'react';
import { Button, Card, Empty, Modal, Progress, Segmented, Table, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { RequestError, Status } from '../components';
import { canCancelSeatJob, findJob, jobKey } from '../jobProgress';
import { authorizationCounts, matchesTaskFilter, taskRows } from '../taskHierarchy';
import AuthorizationTaskModal from '../AuthorizationTaskModal';
import { post } from '../api';
import { useAction } from '../hooks';
import type { JobRow } from '../jobProgress';
import type { Jobs as JobsData } from '../types';
import MobileList from '../MobileList';
import { useIsMobile } from '../useResponsive';
import { pageRows } from '../responsive';

export default function Jobs({ data, loading, error, reload }: { data?: JobsData; loading: boolean; error?: string; reload: () => void }) {
  const mobile = useIsMobile();
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState('all');
  const [detailKey, setDetailKey] = useState<string>();
  const [authorizationId, setAuthorizationId] = useState<string>();
  const [cancelKey, setCancelKey] = useState<string>();
  const action = useAction();
  const rows = useMemo(() => taskRows(data), [data?.authorization, data?.team]);
  // Keep identity, not the clicked snapshot: open details follow live updates.
  const detail = findJob(rows, detailKey);
  const cancelTarget = findJob(rows, cancelKey);
  const cancel = () => action.run(async () => {
    if (!canCancelSeatJob(cancelTarget) || !cancelTarget) { setCancelKey(undefined); return; }
    try {
      await post('/api/team-admin/jobs/' + encodeURIComponent(cancelTarget.id) + '/cancel');
      setCancelKey(undefined);
      void action.message.success('已请求取消，已成功的操作不会撤销');
    } finally { reload(); }
  });
  const filtered = rows.filter(row => matchesTaskFilter(row, filter));
  const filters = [{ value: 'all', label: '全部', count: rows.length }, { value: 'active', label: '进行中', count: rows.filter(row => matchesTaskFilter(row, 'active')).length }, { value: 'failed', label: '未成功', count: rows.filter(row => matchesTaskFilter(row, 'failed')).length }];
  const mobilePage = pageRows(filtered, page, 20);
  const target = (row: JobRow) => row.authorization_batch ? `${row.total} 个账号` : row.parent_email || '—';
  const progress = (row: JobRow) => row.total ? <div className="cell-stack">
    <Progress size="small" percent={Math.min(100, Math.floor((row.completed || 0) * 100 / row.total))} status={row.status === 'success' ? 'success' : ['failed', 'partial_failed', 'cancelled', 'partial_cancelled', 'incomplete', 'interrupted'].includes(row.status || '') ? 'exception' : 'normal'} />
    <span className="cell-secondary">已结束 {row.completed || 0}/{row.total}{row.kind === 'invite_switch' ? ' · 执行 ' + (row.running || 0) + '/' + (row.concurrency || 1) : ''}</span>
    {row.authorization_batch && <span className="cell-secondary">{authorizationCounts(row.authorization_batch)}</span>}
  </div> : null;
  const operations = (row: JobRow) => <><Button type="link" size="small" onClick={() => row.source === 'authorization' ? setAuthorizationId(row.id) : setDetailKey(jobKey(row))}>{row.source === 'authorization' ? '查看账号' : '详情'}</Button>{canCancelSeatJob(row) && <Button type="link" danger size="small" disabled={action.pending} onClick={() => setCancelKey(jobKey(row))}>取消</Button>}{row.cancel_requested && ['queued', 'running'].includes(row.status || '') && <Typography.Text type="secondary">取消中</Typography.Text>}</>;
  return <div className="page-stack">
    <Card className="data-card">
      <div className="table-toolbar jobs-toolbar"><Segmented className="task-filters" aria-label="任务状态" value={filter} onChange={value => { setFilter(value); setPage(1); }} options={filters.map(item => ({ value: item.value, label: <span className="task-filter-label">{item.label} <strong>{data ? item.count : '—'}</strong></span> }))} /><Button aria-label="刷新任务" icon={<ReloadOutlined />} onClick={reload} loading={loading}>{!mobile && '刷新'}</Button></div>
      <RequestError value={error} />
      {mobile ? <MobileList rows={mobilePage.items} rowKey={jobKey} label={row => row.type} loading={loading && !data}
        pagination={{ page: mobilePage.page, pageSize: 20, total: filtered.length, onChange: setPage }} renderItem={row => <>
          <div className="record-heading"><strong>{row.type}</strong><Status value={row.status} /></div>
          <div className="record-identity">{target(row)} <span className="muted">· {row.id.slice(0, 8)}</span></div>
          <div className="record-progress">{progress(row)}</div>
          <p className="record-message">{row.message || row.error || row.stage || '—'}</p>
          <div className="record-footer"><span className="muted">{row.updated_at || '—'}</span><div className="record-actions">{operations(row)}</div></div>
        </>} /> : <Table<JobRow> size="middle" loading={loading && !data} rowKey={jobKey} dataSource={filtered} scroll={{ x: 1050, y: 'max(320px, calc(100dvh - 280px))' }} pagination={{ defaultPageSize: 30, showTotal: total => `共 ${total} 个任务` }} columns={[
        { title: '任务', width: 140, render: (_, row) => <div className="cell-stack"><strong>{row.type}</strong><Typography.Text className="cell-secondary" copyable={{ text: row.id }}>{row.id.slice(0, 8)}</Typography.Text></div> },
        { title: '范围 / 母号', render: (_, row) => target(row), width: 205, ellipsis: true },
        { title: '状态', width: 105, render: (_, row) => <Status value={row.status} /> },
        { title: '进度', width: 195, render: (_, row) => progress(row) || '—' },
        { title: '当前信息', ellipsis: true, render: (_, row) => row.message || row.error || row.stage || '—' },
        { title: '更新时间', width: 180, render: (_, row) => row.updated_at || '—' },
        { title: '操作', width: 140, render: (_, row) => operations(row) },
      ]} />}
    </Card>
    {authorizationId && <AuthorizationTaskModal key={authorizationId} batchId={authorizationId} summary={data?.authorization.find(row => row.batch_id === authorizationId)} pipeline={data?.pipeline || []} onClose={() => setAuthorizationId(undefined)} />}
    <Modal title="任务详情" open={detailKey !== undefined} onCancel={() => setDetailKey(undefined)} footer={<>{canCancelSeatJob(detail) && <Button danger disabled={action.pending} onClick={() => setCancelKey(detailKey)}>取消切席任务</Button>}<Button onClick={() => setDetailKey(undefined)}>关闭</Button></>}>
      {detail ? <><div className="operation-context"><Typography.Text strong>{detail.parent_email}</Typography.Text><Status value={detail.status} /></div><dl className="detail-list"><dt>阶段</dt><dd>{detail.stage || detail.kind || '—'}</dd><dt>更新时间</dt><dd>{detail.updated_at || '—'}</dd><dt>任务 ID</dt><dd>{detail.id}</dd></dl><Typography.Paragraph className="task-message">{detail.error || detail.message || '暂无更多信息'}</Typography.Paragraph>{detail.error && detail.message && detail.error !== detail.message && <Typography.Paragraph className="task-message">{detail.message}</Typography.Paragraph>}</> : <Empty description="该任务已移出最近记录" />}
    </Modal>
    <Modal title="取消切席任务" open={cancelKey !== undefined} confirmLoading={action.pending} okText="确认取消" okButtonProps={{ danger: true, disabled: !canCancelSeatJob(cancelTarget) }} onOk={() => void cancel()} onCancel={() => { if (!action.pending) setCancelKey(undefined); }}>
      <Typography.Paragraph>{cancelTarget?.parent_email}</Typography.Paragraph>
      <Typography.Paragraph>{canCancelSeatJob(cancelTarget) ? '停止等待和后续切席；已成功的操作不会撤销，正在发送的请求需等待返回。' : '该任务已结束或正在取消，无需再次提交。'}</Typography.Paragraph>
    </Modal>
  </div>;
}
