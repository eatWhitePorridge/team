import { useState } from 'react';
import { ListHeading } from '../Bento';
import { Button, Card, Checkbox, Dropdown, Input, Modal, Select, Table, Tooltip, Typography } from 'antd';
import { CopyOutlined, DeleteOutlined, DownOutlined, FilterOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import copy from 'copy-to-clipboard';
import type { Key } from 'react';
import type { ColumnsType } from 'antd/es/table';
import { post, saveDownload, saveTextDownload } from '../api';
import { IndexNotice, QuotaCell, RequestError, Status } from '../components';
import { useAction, useResource } from '../hooks';
import type { Account, DeleteAccountsResult, ExportResult, ImportResult, Page, QueueResult, SplitBatchResult, TotpExportResult } from '../types';
import { createSplitTarget, splitPayload, type SplitTarget } from '../batchSplit';
import TeamOperationModal from '../TeamOperationModal';
import MobileList from '../MobileList';
import { useIsMobile } from '../useResponsive';
import TeamAuthorizationModal from '../TeamAuthorizationModal';
import { freezeAuthorizationAccounts } from '../teamAuthorization';
import { selectAccountEmails, selectedEmailText, type EmailSelection } from '../emailSelection';
import { childAccountParams, type ChildAccountScope } from '../childAccounts';

const accountPageSizes = [9, 22, 50, 100];

export default function Accounts({ onJobsChanged, initialBatchId = '', teamScope, onClearTeam, onReturnTeam }: {
  onJobsChanged: () => void; initialBatchId?: string; teamScope?: ChildAccountScope;
  onClearTeam: () => void; onReturnTeam: () => void;
}) {
  const mobile = useIsMobile();
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [filters, setFilters] = useState({ q: '', batch_id: initialBatchId, totp_status: '', codex_state: '', codex_plan_type: '' });
  const [filtersOpen, setFiltersOpen] = useState(!!initialBatchId);
  const [batchInput, setBatchInput] = useState(initialBatchId);
  const teamParams = childAccountParams(teamScope);
  const scope = JSON.stringify([filters, teamParams]);
  const [selection, setSelection] = useState<EmailSelection>({ scope, keys: [], emails: {} });
  const selected = selection.scope === scope ? selection.keys : [];
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState('');
  const [autoAuthorize, setAutoAuthorize] = useState(false);
  const [teamOperation, setTeamOperation] = useState<'switch' | 'remove' | null>(null);
  const [teamAuthorizationIds, setTeamAuthorizationIds] = useState<number[] | null>(null);
  // Freeze the targets when opening confirmation, including cross-page picks.
  const [deleteTarget, setDeleteTarget] = useState<{ ids: number[]; email?: string } | null>(null);
  const [splitTarget, setSplitTarget] = useState<SplitTarget | null>(null);
  const data = useResource<Page<Account>>('/api/accounts', { page, page_size: pageSize, ...filters, ...teamParams }, 5000);
  const action = useAction();
  const setFilter = (key: keyof typeof filters, value: string) => { setFilters((old) => ({ ...old, [key]: value })); setPage(1); setSelection({ scope: '', keys: [], emails: {} }); };
  const rows = data.data?.items || [];
  const changeSelection = (keys: Key[]) => setSelection(old => selectAccountEmails(scope, keys.map(Number), rows, old));
  const copyEmails = (row?: Account) => {
    try {
      const target = row ? selectAccountEmails(scope, [row.id], [row]) : selectAccountEmails(scope, selected, rows, selection);
      const { text, count } = selectedEmailText(target);
      // Synchronous user-gesture copy also supports the deployed HTTP address.
      if (copy(text, { format: 'text/plain', message: '请按 #{key} 复制邮箱，然后回车' })) {
        void action.message.success('已复制 ' + count + ' 个邮箱');
      } else {
        void action.message.warning('自动复制未确认，请使用弹出的文本手动复制');
      }
    } catch (error) {
      void action.message.error(error instanceof Error ? error.message : '复制失败，请重试');
    }
  };
  const emailCell = (row: Account) => <div className="account-email">
    <Tooltip title={<>{row.email}<br />账号 ID：{row.id}</>}><span className="cell-primary account-email-text">{row.email}</span></Tooltip>
    <Tooltip title="复制邮箱"><Button type="text" size="small" icon={<CopyOutlined />} aria-label={'复制邮箱 ' + row.email} onClick={() => copyEmails(row)} /></Tooltip>
  </div>;
  const columns: ColumnsType<Account> = [
    { title: '账号', dataIndex: 'email', width: 260, ellipsis: true, render: (_, row) => emailCell(row) },
    { title: '授权 / 套餐', width: 210, render: (_, row) => <div className="cell-stack"><Status value={row.codex_connection_state} />{row.codex_plan_type && <Typography.Text className="cell-secondary" ellipsis={{ tooltip: row.codex_plan_type }}>{row.codex_plan_type}</Typography.Text>}</div> },
    { title: '2FA', dataIndex: 'totp_status', width: 105, render: (value) => <Status value={value} /> },
    { title: '额度', width: 160, render: (_, row) => <QuotaCell value={row} /> },
    { title: '批次', dataIndex: 'registration_batch_id', width: 125, render: (value?: string) => value ? <Tooltip title={value}><Typography.Text className="cell-secondary" copyable={{ text: value }}>{value.slice(0, 8)}</Typography.Text></Tooltip> : '—' },
    { title: '操作', width: 72, fixed: 'right', render: (_, row) => <Tooltip title="删除账号"><Button type="text" danger size="small" icon={<DeleteOutlined />} aria-label={'删除账号 ' + row.email} disabled={action.pending} onClick={() => setDeleteTarget({ ids: [row.id], email: row.email })} /></Tooltip> },
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
  const deleteAccounts = () => action.run(async () => {
    if (!deleteTarget) return;
    try {
      const result = await post<DeleteAccountsResult>('/api/accounts/delete', { account_ids: deleteTarget.ids, confirm: true });
      const deleted = new Set(result.deleted.map((row) => row.id));
      setSelection((old) => ({ ...old, keys: old.keys.filter((key) => !deleted.has(Number(key))) }));
      setDeleteTarget(null);
      setPage((old) => Math.max(1, Math.min(old, Math.ceil(((data.data?.total || 0) - result.deleted_count) / pageSize))));
      void action.message.success('已删除 ' + result.deleted_count + ' 个账号' + (result.skipped_count ? '，跳过 ' + result.skipped_count + ' 个' : ''));
      action.details('未删除 / 提示', [...result.skipped, ...result.warnings]);
      onJobsChanged();
    } finally {
      // A timeout is not proof of failure: refresh, but never replay the POST.
      data.reload();
    }
  });
  const splitAccounts = () => action.run(async () => {
    if (!splitTarget) return;
    try {
      const result = await post<SplitBatchResult>('/api/accounts/split-batch', splitPayload(splitTarget));
      setSplitTarget(null);
      setFilter('batch_id', result.batch_id);
      setBatchInput(result.batch_id); setFiltersOpen(true);
      void action.message.success('已将 ' + result.moved_accounts + ' 个账号移入新批次，当前已切换到该批次');
      action.details('拆分提示', result.warnings);
      onJobsChanged();
    } finally {
      // Keep the same frozen request ID for a manual retry after a timeout.
      // Never replay the mutation automatically or generate an ID on submit.
      data.reload();
    }
  });
  const authorizationFilters = <>
    <Select allowClear aria-label="授权状态" placeholder="全部授权" value={filters.codex_state || undefined} className="filter-select" options={[{ value: 'connected', label: '已授权' }, { value: 'running', label: '进行中' }, { value: 'not_connected', label: '未授权' }, { value: 'deactivated', label: '已封禁' }]} onChange={(value) => setFilter('codex_state', value || '')} />
    <Tooltip title="按最近保存的 OAuth 授权套餐筛选；未授权不视为 Free"><Select allowClear aria-label="授权套餐" placeholder="全部套餐" value={filters.codex_plan_type || undefined} className="filter-select" options={[{ value: 'free', label: 'Free' }, { value: 'self_serve_business_prolite', label: 'Team · ProLite' }]} onChange={(value) => setFilter('codex_plan_type', value || '')} /></Tooltip>
  </>;
  const filterCount = [filters.batch_id, filters.totp_status, ...(mobile ? [filters.codex_state, filters.codex_plan_type] : [])].filter(Boolean).length;
  return <div className="page-stack">
    <Card className="data-card account-panel">
    <ListHeading title={teamScope ? '本地子号' : Object.values(filters).some(Boolean) ? '筛选结果' : '全部账号'} count={data.data?.total} action={<Button type="primary" icon={<PlusOutlined />} onClick={() => setImportOpen(true)} disabled={action.pending}>导入账号</Button>} />
    {teamScope && <div className="child-account-context">
      <div className="cell-stack"><Typography.Text strong>{teamScope.workspaceName}</Typography.Text><Typography.Text type="secondary">{teamScope.parentEmail} · 按成员缓存匹配邮箱</Typography.Text></div>
      <div className="toolbar-controls"><Button size="small" disabled={action.pending} onClick={onReturnTeam}>返回母号</Button><Button size="small" type="text" disabled={action.pending} onClick={onClearTeam}>全部账号</Button></div>
    </div>}
    <RequestError value={data.error} /><IndexNotice value={data.data?.index} />
    <div className="table-toolbar account-toolbar">
      <div className="toolbar-controls">
        <Input.Search allowClear aria-label="搜索账号" placeholder="搜索邮箱、备注" onSearch={(value) => setFilter('q', value)} className="search-control" />
        {!mobile && authorizationFilters}
        <Button icon={<FilterOutlined />} aria-expanded={filtersOpen} aria-controls="account-filters" type={filtersOpen || filterCount ? 'dashed' : 'default'} onClick={() => setFiltersOpen(!filtersOpen)}>筛选{filterCount ? ' · ' + filterCount : ''}</Button>
      </div>
      <div className="toolbar-controls">
        <Tooltip title="刷新列表"><Button aria-label="刷新账号列表" icon={<ReloadOutlined />} onClick={data.reload} loading={data.loading} /></Tooltip>
      </div>
    </div>
    {filtersOpen && <div className="filter-panel" id="account-filters">
      {mobile && <div className="mobile-filter-pair">{authorizationFilters}</div>}
      <label className="field-inline batch-filter"><span>批次</span><Input.Search aria-label="按批次查询账号" value={batchInput} allowClear placeholder="输入完整批次 ID" onChange={(event) => setBatchInput(event.target.value)} onSearch={(value) => setFilter('batch_id', value.trim())} className="search-control" /></label>
      <label className="field-inline"><span>2FA</span><Select allowClear value={filters.totp_status || undefined} placeholder="全部" className="filter-select" options={[{ value: 'active', label: '已接入' }, { value: 'not_configured', label: '未配置' }, { value: 'activation_uncertain', label: '待验证' }, { value: 'failed', label: '失败' }]} onChange={(value) => setFilter('totp_status', value || '')} /></label>
      <Button type="link" onClick={() => { setBatchInput(''); setFilters((old) => ({ ...old, batch_id: '', totp_status: '', ...(mobile ? { codex_state: '', codex_plan_type: '' } : {}) })); setPage(1); setSelection({ scope: '', keys: [], emails: {} }); }}>重置筛选</Button>
    </div>}
    {!!selected.length && <div className="selection-bar account-selection">
      <div className="selection-top"><span className="selection-count">已选 {selected.length}</span>{mobile && <Button type="text" disabled={action.pending} onClick={() => changeSelection([])}>取消选择</Button>}</div>
      <div className="toolbar-controls">
        <Button type="primary" disabled={action.pending} onClick={() => void authorize(false)}>普通授权</Button>
        <Button disabled={action.pending} onClick={() => void action.run(async () => setTeamAuthorizationIds(freezeAuthorizationAccounts(selected.map(Number))))}>Team 授权</Button>
        {!mobile && <Button icon={<CopyOutlined />} disabled={action.pending} onClick={() => copyEmails()}>复制邮箱</Button>}
        {!mobile && <Button disabled={action.pending} onClick={() => void quota()}>查额度</Button>}
        <Dropdown trigger={['click']} disabled={action.pending} menu={{ items: [
          ...(mobile ? [{ key: 'copy_emails', label: '复制邮箱', icon: <CopyOutlined />, onClick: () => copyEmails() },
            { key: 'quota', label: '查额度', onClick: () => void quota() }] : []),
          { key: 'export_totp', label: '导出 2FA 三段式 TXT', onClick: () => void exportTotp() },
          { key: 'export', label: '导出 Sub2API', onClick: () => void exportAccounts() },
          { type: 'divider' },
          { key: 'split', label: '拆分批次', onClick: () => void action.run(async () => setSplitTarget(createSplitTarget(selected.map(Number)))) },
          { key: 'switch', label: '切换 Team 席位', onClick: () => setTeamOperation('switch') },
          { type: 'divider' }, { key: 'remove', label: '移出 Team', danger: true, onClick: () => setTeamOperation('remove') },
          ...(mobile ? [{ key: 'delete', label: '删除本地账号', danger: true, onClick: () => setDeleteTarget({ ids: selected.map(Number) }) }] : []),
        ] }}><Button disabled={action.pending}>更多 <DownOutlined /></Button></Dropdown>
        {!mobile && <><Button danger icon={<DeleteOutlined />} disabled={action.pending} onClick={() => setDeleteTarget({ ids: selected.map(Number) })}>删除账号</Button>
        <Button type="text" disabled={action.pending} onClick={() => changeSelection([])}>取消选择</Button></>}
      </div>
    </div>}
    {mobile ? <MobileList rows={rows} rowKey={row => row.id} label={row => row.email} loading={data.loading && !data.data}
      selection={{ keys: selected, onChange: changeSelection, disabled: action.pending || !!data.error }}
      pagination={{ page: data.data?.page || page, pageSize, total: data.data?.total || 0, pageSizeOptions: accountPageSizes, onChange: (next, size) => { setPage(next); setPageSize(size); } }}
      renderItem={row => <>
        <div className="record-heading">{emailCell(row)}<Button type="text" danger icon={<DeleteOutlined />} aria-label={'删除账号 ' + row.email} disabled={action.pending} onClick={() => setDeleteTarget({ ids: [row.id], email: row.email })} /></div>
        <div className="record-tags"><Status value={row.codex_connection_state} />{row.codex_plan_type && <span className="record-plan">{row.codex_plan_type === 'self_serve_business_prolite' ? 'Team · ProLite' : row.codex_plan_type}</span>}</div>
        <div className="record-meta"><span>2FA</span><Status value={row.totp_status} /><span>ID {row.id}</span></div>
        <div className="record-quota"><span className="muted">额度</span><QuotaCell value={row} /></div>
        {row.registration_batch_id && <div className="record-meta"><span>批次</span><Typography.Text copyable={{ text: row.registration_batch_id }}>{row.registration_batch_id.slice(0, 8)}</Typography.Text></div>}
      </>} /> : <Table<Account> size="middle" rowKey="id" loading={data.loading && !data.data} dataSource={rows} columns={columns} scroll={{ x: 1007, y: 'max(320px, calc(100dvh - 360px))' }}
      rowSelection={{ selectedRowKeys: selected, preserveSelectedRowKeys: true, onChange: changeSelection }}
      pagination={{ current: data.data?.page || page, pageSize, total: data.data?.total || 0, showTotal: (total) => '共 ' + total + ' 个账号', showSizeChanger: true, pageSizeOptions: accountPageSizes, onChange: (next, size) => { setPage(next); setPageSize(size); } }} />}
    </Card>
    <Modal title="导入账号" open={importOpen} onCancel={() => { if (!action.pending) setImportOpen(false); }} onOk={() => void importAccounts()} confirmLoading={action.pending} okButtonProps={{ disabled: !importText.trim() }} okText={autoAuthorize ? '导入并普通授权' : '仅导入'} width={680}>
      <Typography.Text type="secondary">每行一个账号，导入后生成新批次。</Typography.Text>
      <Input.TextArea className="import-text" aria-label="待导入账号，每行一个" rows={9} placeholder="邮箱----ChatGPT 密码----Base32 密钥[----邀请链接]" value={importText} onChange={(event) => setImportText(event.target.value)} disabled={action.pending} />
      <Checkbox checked={autoAuthorize} onChange={(event) => setAutoAuthorize(event.target.checked)} disabled={action.pending}>导入后立即提交普通授权</Checkbox>
    </Modal>
    <Modal title="删除账号" open={!!deleteTarget} okText="确认删除" cancelText="取消" okButtonProps={{ danger: true, disabled: !deleteTarget?.ids.length }} confirmLoading={action.pending}
      closable={!action.pending} maskClosable={!action.pending} keyboard={!action.pending} cancelButtonProps={{ disabled: action.pending }}
      onCancel={() => { if (!action.pending) setDeleteTarget(null); }} onOk={() => void deleteAccounts()}>
      <Typography.Paragraph>确定删除{deleteTarget?.email ? <Typography.Text strong> {deleteTarget.email} </Typography.Text> : <>选中的 <strong>{deleteTarget?.ids.length || 0}</strong> 个账号</>}？</Typography.Paragraph>
      <Typography.Paragraph>将删除本系统保存的账号及关联授权凭据、Cookie，无法撤销。不会注销远端账号，也不会将成员移出 Team。</Typography.Paragraph>
      <Typography.Text type="secondary">正在执行授权、查额度等任务的账号会跳过，并显示原因。</Typography.Text>
    </Modal>
    <Modal title="拆分到新批次" open={!!splitTarget} okText="确认拆分" cancelText="取消" confirmLoading={action.pending} okButtonProps={{ disabled: !splitTarget?.ids.length }}
      closable={!action.pending} maskClosable={!action.pending} keyboard={!action.pending} cancelButtonProps={{ disabled: action.pending }}
      onCancel={() => { if (!action.pending) setSplitTarget(null); }} onOk={() => void splitAccounts()}>
      <Typography.Paragraph>将选中的 <strong>{splitTarget?.ids.length || 0}</strong> 个账号移入一个新批次？</Typography.Paragraph>
      <Typography.Paragraph>仅移动所选账号的批次，账号信息和 Team 成员不变。</Typography.Paragraph>
      <Typography.Text type="secondary">有运行中任务时不可拆分。</Typography.Text>
    </Modal>
    {teamOperation && <TeamOperationModal kind={teamOperation} scope={{ account_ids: selected.map(Number) }} onClose={() => setTeamOperation(null)} onSubmitted={() => { onJobsChanged(); data.reload(); }} />}
    {teamAuthorizationIds && <TeamAuthorizationModal accountIds={teamAuthorizationIds} onClose={() => setTeamAuthorizationIds(null)} onSubmitted={() => { onJobsChanged(); data.reload(); }} />}
  </div>;
}
