import { useMemo, useState } from 'react';
import { Alert, Button, Input, Modal, Progress, Segmented, Table, Tooltip, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { RequestError, Status } from './components';
import { useAuthorizationDetail } from './useAuthorizationDetail';
import { useIsMobile } from './useResponsive';
import MobileList from './MobileList';
import { pageRows } from './responsive';
import { authorizationActivity, authorizationCounts, authorizationItems } from './taskHierarchy';
import type { AuthorizationBatch, Job } from './types';

export default function AuthorizationTaskModal({ batchId, summary, pipeline, onClose }: {
  batchId: string; summary?: AuthorizationBatch; pipeline: Job[]; onClose: () => void;
}) {
  const mobile = useIsMobile();
  const [page, setPage] = useState(1), [query, setQuery] = useState(''), [filter, setFilter] = useState('all');
  const { resource, rows, batch, status } = useAuthorizationDetail({ batchId, summary, pipeline });
  const filtered = useMemo(() => authorizationItems(rows, query, filter), [rows, query, filter]);
  const visible = pageRows(filtered, page, mobile ? 20 : 50);
  const result = (row: Job) => row.error || row.progress_message || row.message || row.stage || '—';
  const attempts = (row: Job) => row.codex_attempt_count ? `${row.codex_attempt_count}/${row.codex_max_attempts || row.codex_attempt_count}` : '—';
  return <Modal title={batch?.team_authorization ? 'Team 授权 · 账号明细' : '普通授权 · 账号明细'} open width={1040} onCancel={onClose} footer={<Button onClick={onClose}>关闭</Button>}>
    <RequestError value={resource.error} />
    <div className="task-detail-meta"><Typography.Text type="secondary" copyable={{ text: batchId }}>任务 {batchId.slice(0, 8)}</Typography.Text>{batch && <Status value={status} />}</div>
    {batch && <div className="task-detail-progress"><Progress percent={Math.min(100, Math.floor(batch.finished * 100 / Math.max(1, batch.total)))} status={status === 'success' ? 'success' : !batch.active || batch.failed ? 'exception' : 'normal'} />
      <div className="task-detail-meta"><span>已结束 {batch.finished}/{batch.total}</span><span>{authorizationCounts(batch)}</span>{!!batch.active && <span className="muted">{authorizationActivity(batch)}</span>}</div>
    </div>}
    {batch?.expected_workspace_id && <div className="task-detail-meta"><span className="muted">目标工作区</span><Typography.Text copyable>{batch.expected_workspace_id}</Typography.Text></div>}
    {!!batch?.missing && <Alert className="notice" type="warning" showIcon message={`部分历史明细已清理，保留 ${batch.known}/${batch.total} 条；缺失部分不计为成功。`} />}
    <div className="table-toolbar task-detail-toolbar">
      <Input.Search className="search-control" aria-label="搜索任务内账号" placeholder="搜索邮箱或账号 ID" allowClear onSearch={value => { setQuery(value); setPage(1); }} />
      <Segmented aria-label="任务内账号状态" value={filter} options={[{ value: 'all', label: '全部' }, { value: 'active', label: '进行中' }, { value: 'success', label: '成功' }, { value: 'failed', label: '未成功' }]} onChange={value => { setFilter(value); setPage(1); }} />
      <Button aria-label="刷新任务账号明细" icon={<ReloadOutlined />} loading={resource.loading} onClick={resource.reload} />
    </div>
    {mobile ? <MobileList rows={visible.items} rowKey={row => row.id} label={row => row.email || row.id} loading={resource.loading && !resource.data}
      pagination={{ page: visible.page, pageSize: 20, total: filtered.length, onChange: setPage }} renderItem={row => <>
        <Typography.Text className="record-identity" copyable>{row.email || row.account_id || row.id}</Typography.Text>
        <div className="record-tags"><Status value={row.progress_status || row.status} />{row.codex_plan_type && <span className="record-plan">{row.codex_plan_type}</span>}</div>
        <Typography.Paragraph className="task-child-result" ellipsis={{ rows: 3, expandable: 'collapsible' }}>{result(row)}</Typography.Paragraph>
        <div className="record-meta"><span>账号 {row.account_id}</span>{!!row.codex_attempt_count && <span>尝试 {attempts(row)}</span>}</div>
      </>} /> : <Table<Job> size="small" rowKey="id" loading={resource.loading && !resource.data} dataSource={filtered} scroll={{ x: 870, y: 'min(420px, 48dvh)' }}
      pagination={{ current: visible.page, pageSize: 50, total: filtered.length, showSizeChanger: false, showTotal: total => `共 ${total} 个账号`, onChange: setPage }}
      columns={[
        { title: '账号', width: 245, render: (_, row) => <div className="cell-stack"><Typography.Text copyable={{ text: row.email }} ellipsis={{ tooltip: row.email }}>{row.email || row.account_id}</Typography.Text><span className="cell-secondary">ID {row.account_id}</span></div> },
        { title: '状态', width: 100, render: (_, row) => <Status value={row.progress_status || row.status} /> },
        { title: '阶段 / 结果', render: (_, row) => <Tooltip title={result(row)}><div className="task-child-result">{result(row)}</div></Tooltip> },
        { title: '尝试', width: 70, render: (_, row) => attempts(row) },
        { title: '套餐', width: 145, render: (_, row) => <Tooltip title={row.codex_plan_type}>{row.codex_plan_type === 'self_serve_business_prolite' ? 'Team · ProLite' : row.codex_plan_type || '—'}</Tooltip> },
      ]} />}
  </Modal>;
}
