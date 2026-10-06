import { useMemo, useState } from 'react';
import { Alert, Button, Empty, Input, Pagination, Select, Spin, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { RequestError, Status } from './components';
import { useAuthorizationDetail } from './useAuthorizationDetail';
import { authorizationItems } from './taskHierarchy';
import { pageRows } from './responsive';
import { useIsMobile } from './useResponsive';
import type { AuthorizationBatch, Job } from './types';

export default function TaskAuthorizationExpansion({ batchId, summary, pipeline }: {
  batchId: string; summary: AuthorizationBatch; pipeline: Job[];
}) {
  const { resource, rows, batch } = useAuthorizationDetail({ batchId, summary, pipeline });
  const [query, setQuery] = useState(''), [filter, setFilter] = useState('all'), [page, setPage] = useState(1);
  const mobile = useIsMobile();
  const pageSize = mobile ? 5 : 10;
  const filtered = useMemo(() => authorizationItems(rows, query, filter), [rows, query, filter]);
  const visible = pageRows(filtered, page, pageSize);
  return <div className="float-authorization-detail">
    <RequestError value={resource.error} />
    {batch?.expected_workspace_id && <div className="float-detail-target"><span>工作区</span><Typography.Text copyable>{batch.expected_workspace_id}</Typography.Text></div>}
    {!!batch?.missing && <Alert type="warning" showIcon message={`历史明细保留 ${batch.known}/${batch.total} 条，缺失不计为成功。`} />}
    <div className="float-account-filters">
      <Input.Search aria-label="搜索展开任务内账号" placeholder="邮箱 / ID" allowClear onSearch={value => { setQuery(value); setPage(1); }} />
      <Select aria-label="展开任务账号状态" value={filter} onChange={value => { setFilter(value); setPage(1); }} options={[
        { value: 'all', label: '全部状态' }, { value: 'active', label: '进行中' }, { value: 'success', label: '成功' }, { value: 'failed', label: '未成功' },
      ]} />
      <Button aria-label="刷新展开任务明细" icon={<ReloadOutlined />} loading={resource.loading} onClick={resource.reload} />
    </div>
    {resource.loading && !rows.length ? <div className="task-float-empty" role="status"><Spin size="small" />加载账号明细…</div> : !filtered.length ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={resource.error && !rows.length ? '未获取到账号明细' : '没有匹配的账号'} /> : <ul className="float-account-list">{visible.items.map(row => <li key={row.id}>
      <div className="float-account-heading"><Typography.Text copyable={{ text: row.email || String(row.account_id || row.id) }}>{row.email || row.account_id || row.id}</Typography.Text><Status value={row.progress_status || row.status} /></div>
      <p className="float-account-message">{row.error || row.progress_message || row.message || row.stage || '—'}</p>
      <div className="float-account-meta"><span>ID {row.account_id || '—'}</span>{!!row.codex_attempt_count && <span>尝试 {row.codex_attempt_count}/{row.codex_max_attempts || row.codex_attempt_count}</span>}{row.codex_plan_type && <span>{row.codex_plan_type === 'self_serve_business_prolite' ? 'Team · ProLite' : row.codex_plan_type}</span>}</div>
    </li>)}</ul>}
    <div className="float-account-pagination"><span className="muted">{filtered.length} 条{batch && rows.length < (batch.known ?? batch.total) ? ` · 已加载 ${rows.length}/${batch.known ?? batch.total}` : ''}</span>
      {filtered.length > pageSize && <Pagination aria-label="展开任务账号分页" size="small" simple current={visible.page} total={filtered.length} pageSize={pageSize} showSizeChanger={false} onChange={setPage} />}
    </div>
  </div>;
}
