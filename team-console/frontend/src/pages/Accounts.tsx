import { useState } from 'react';
import { Button, Card, Checkbox, Dropdown, Input, Modal, Select, Table, Tooltip, Typography } from 'antd';
import { DownOutlined, FilterOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import type { Key } from 'react';
import type { ColumnsType } from 'antd/es/table';
import { post, saveDownload, saveTextDownload } from '../api';
import { IndexNotice, QuotaCell, RequestError, Status } from '../components';
import { useAction, useResource } from '../hooks';
import type { Account, ExportResult, ImportResult, Page, QueueResult, TotpExportResult } from '../types';
import TeamOperationModal from '../TeamOperationModal';

export default function Accounts({ onJobsChanged, initialBatchId = '' }: { onJobsChanged: () => void; initialBatchId?: string }) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [filters, setFilters] = useState({ q: '', batch_id: initialBatchId, totp_status: '', codex_state: '', codex_plan_type: '' });
  const [filtersOpen, setFiltersOpen] = useState(!!initialBatchId);
  const [batchInput, setBatchInput] = useState(initialBatchId);
  const scope = JSON.stringify(filters);
  const [selection, setSelection] = useState<{ scope: string; keys: Key[] }>({ scope, keys: [] });
  const selected = selection.scope === scope ? selection.keys : [];
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState('');
  const [autoAuthorize, setAutoAuthorize] = useState(false);
  const [teamOperation, setTeamOperation] = useState<'switch' | 'remove' | null>(null);
  const data = useResource<Page<Account>>('/api/accounts', { page, page_size: pageSize, ...filters }, 5000);
  const action = useAction();
  const setFilter = (key: keyof typeof filters, value: string) => { setFilters((old) => ({ ...old, [key]: value })); setPage(1); setSelection({ scope: '', keys: [] }); };
  const rows = data.data?.items || [];
  const columns: ColumnsType<Account> = [
    { title: '账号', dataIndex: 'email', width: 260, ellipsis: true, render: (value, row) => <Tooltip title={'账号 ID：' + row.id}><span className="cell-primary">{value}</span></Tooltip> },
    { title: '授权 / 套餐', width: 210, render: (_, row) => <div className="cell-stack"><Status value={row.codex_connection_state} />{row.codex_plan_type && <Typography.Text className="cell-secondary" ellipsis={{ tooltip: row.codex_plan_type }}>{row.codex_plan_type}</Typography.Text>}</div> },
    { title: '2FA', dataIndex: 'totp_status', width: 105, render: (value) => <Status value={value} /> },
    { title: '额度', width: 160, render: (_, row) => <QuotaCell value={row} /> },
    { title: '批次', dataIndex: 'registration_batch_id', width: 125, render: (value?: string) => value ? <Tooltip title={value}><Typography.Text className="cell-secondary" copyable={{ text: value }}>{value.slice(0, 8)}</Typography.Text></Tooltip> : '—' },
  ];
  const authorize = (team: boolean) => action.run(async () => {
    const result = await post<QueueResult>('/api/accounts/authorize', { account_ids: selected, team_authorization: team });
    action.queue(result); onJobsChanged(); data.reload();
  });
  const quota = () => action.run(async () => {
    action.queue(await post<QueueResult>('/api/accounts/check-quota', { account_ids: selected })); data.reload();
  });
  const exportAccounts = () => action.run(async () => {
    const result = await post<ExportResult>('/api/accounts/export-sub2api', { account_ids: selected });
    saveDownload(result.data, result.filename);
    void action.message.success('已生成 ' + result.exported_count + ' 个账号的导出文件');
    action.details('导出失败 / 提示', [...result.failed, ...result.warnings]);
  });
  const exportTotp = () => action.run(async () => {
    const result = await post<TotpExportResult>('/api/accounts/export-totp', { account_ids: selected });
    saveTextDownload(result.data, result.filename);
    void action.message.success('已导出 ' + result.exported_count + ' 个账号的 2FA 三段式');
    action.details('导出失败 / 提示', [...result.failed, ...result.warnings]);
  });
  const importAccounts = () => action.run(async () => {
    const result = await post<ImportResult>('/api/accounts/import-password-totp', { text: importText, start_authorization: autoAuthorize });
    setImportOpen(false); setImportText('');
    if (result.imported_count) void action.message.success('已导入 ' + result.imported_count + ' 个账号');
    else void action.message.warning('没有新增账号');
    action.details('导入跳过明细', result.skipped || []);
    if (result.authorization) { action.queue(result.authorization); onJobsChanged(); }
    data.reload();
  });
  return <Card className="data-card">
    <RequestError value={data.error} /><IndexNotice value={data.data?.index} />
    <div className="table-toolbar">
      <div className="toolbar-controls">
        <Input.Search allowClear aria-label="搜索账号" placeholder="搜索邮箱、备注" onSearch={(value) => setFilter('q', value)} className="search-control" />
        <Select allowClear aria-label="授权状态" placeholder="全部授权" value={filters.codex_state || undefined} className="filter-select" options={[{ value: 'connected', label: '已授权' }, { value: 'running', label: '进行中' }, { value: 'not_connected', label: '未授权' }]} onChange={(value) => setFilter('codex_state', value || '')} />
        <Tooltip title="按最近保存的 OAuth 授权套餐筛选；未授权不视为 Free"><Select allowClear aria-label="授权套餐" placeholder="全部套餐" value={filters.codex_plan_type || undefined} className="filter-select" options={[{ value: 'free', label: 'Free' }, { value: 'self_serve_business_prolite', label: 'Team · ProLite' }]} onChange={(value) => setFilter('codex_plan_type', value || '')} /></Tooltip>
        <Button icon={<FilterOutlined />} aria-expanded={filtersOpen} aria-controls="account-filters" type={filtersOpen || filters.batch_id || filters.totp_status ? 'dashed' : 'default'} onClick={() => setFiltersOpen(!filtersOpen)}>筛选{[filters.batch_id, filters.totp_status].filter(Boolean).length ? ' · ' + [filters.batch_id, filters.totp_status].filter(Boolean).length : ''}</Button>
      </div>
      <div className="toolbar-controls">
        <Tooltip title="刷新列表"><Button aria-label="刷新账号列表" icon={<ReloadOutlined />} onClick={data.reload} loading={data.loading} /></Tooltip>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setImportOpen(true)} disabled={action.pending}>导入账号</Button>
      </div>
    </div>
    {filtersOpen && <div className="filter-panel" id="account-filters">
      <label className="field-inline"><span>批次</span><Input.Search aria-label="按批次查询账号" value={batchInput} allowClear placeholder="输入完整批次 ID" onChange={(event) => setBatchInput(event.target.value)} onSearch={(value) => setFilter('batch_id', value.trim())} className="search-control" /></label>
      <label className="field-inline"><span>2FA</span><Select allowClear value={filters.totp_status || undefined} placeholder="全部" className="filter-select" options={[{ value: 'active', label: '已接入' }, { value: 'not_configured', label: '未配置' }, { value: 'activation_uncertain', label: '待验证' }, { value: 'failed', label: '失败' }]} onChange={(value) => setFilter('totp_status', value || '')} /></label>
      <Button type="link" onClick={() => { setBatchInput(''); setFilters((old) => ({ ...old, batch_id: '', totp_status: '' })); setPage(1); setSelection({ scope: '', keys: [] }); }}>重置</Button>
    </div>}
    {!!selected.length && <div className="selection-bar">
      <span className="selection-count">已选 {selected.length}</span>
      <div className="toolbar-controls">
        <Button type="primary" disabled={action.pending} onClick={() => void authorize(false)}>普通授权</Button>
        <Button disabled={action.pending} onClick={() => void authorize(true)}>Team 授权</Button>
        <Button disabled={action.pending} onClick={() => void quota()}>查额度</Button>
        <Dropdown trigger={['click']} disabled={action.pending} menu={{ items: [
          { key: 'export_totp', label: '导出 2FA 三段式 TXT', onClick: () => void exportTotp() },
          { key: 'export', label: '导出 Sub2API', onClick: () => void exportAccounts() },
          { key: 'switch', label: '切换 Team 席位', onClick: () => setTeamOperation('switch') },
          { type: 'divider' }, { key: 'remove', label: '移出 Team', danger: true, onClick: () => setTeamOperation('remove') },
        ] }}><Button disabled={action.pending}>更多 <DownOutlined /></Button></Dropdown>
        <Button type="text" disabled={action.pending} onClick={() => setSelection({ scope, keys: [] })}>取消选择</Button>
      </div>
    </div>}
    <Table<Account> size="middle" rowKey="id" loading={data.loading && !data.data} dataSource={rows} columns={columns} scroll={{ x: 935, y: 'max(280px, calc(100dvh - 370px))' }}
      rowSelection={{ selectedRowKeys: selected, preserveSelectedRowKeys: true, onChange: (keys) => setSelection({ scope, keys }) }}
      pagination={{ current: data.data?.page || page, pageSize, total: data.data?.total || 0, showTotal: (total) => '共 ' + total + ' 个账号', showSizeChanger: true, pageSizeOptions: [22, 50, 100], onChange: (next, size) => { setPage(next); setPageSize(size); } }} />
    <Modal title="导入账号" open={importOpen} onCancel={() => { if (!action.pending) setImportOpen(false); }} onOk={() => void importAccounts()} confirmLoading={action.pending} okButtonProps={{ disabled: !importText.trim() }} okText={autoAuthorize ? '导入并普通授权' : '仅导入'} width={680}>
      <Typography.Text type="secondary">每行一个账号，导入后生成新批次。</Typography.Text>
      <Input.TextArea className="import-text" rows={9} placeholder="邮箱----ChatGPT 密码----Base32 密钥[----邀请链接]" value={importText} onChange={(event) => setImportText(event.target.value)} disabled={action.pending} />
      <Checkbox checked={autoAuthorize} onChange={(event) => setAutoAuthorize(event.target.checked)} disabled={action.pending}>导入后立即提交普通授权</Checkbox>
    </Modal>
    {teamOperation && <TeamOperationModal kind={teamOperation} scope={{ account_ids: selected.map(Number) }} onClose={() => setTeamOperation(null)} onSubmitted={() => { onJobsChanged(); data.reload(); }} />}
  </Card>;
}
