import { useState } from 'react';
import type { Key } from 'react';
import { Alert, Button, Card, Dropdown, Empty, Form, Input, List, Modal, Select, Space, Table, Tabs, Tag, Tooltip, Typography } from 'antd';
import { ApartmentOutlined, DeleteOutlined, MoreOutlined, PlusOutlined, ReloadOutlined, SyncOutlined, TeamOutlined } from '@ant-design/icons';
import { deleteResource, post } from '../api';
import { IndexNotice, QuotaCell, RequestError, Status } from '../components';
import { useAction, useResource } from '../hooks';
import { seatLabels, workspaceSeats } from '../teamSeats';
import WorkspaceInvites from './WorkspaceInvites';
import WorkspaceBilling from '../WorkspaceBilling';
import ParentBilling from '../ParentBilling';
import ParentProxy from '../ParentProxy';
import { useContentWidth, useIsMobile } from '../useResponsive';
import type { Job, Member, Page, Parent, Workspace } from '../types';
import { childAccountScope, type ChildAccountScope } from '../childAccounts';
const roleLabels: Record<string, string> = { 'account-owner': '所有者', 'account-admin': '管理员', 'standard-user': '成员' };

export default function Team({ onJobsChanged, onViewChildren, initialTarget }: {
  onJobsChanged: () => void; onViewChildren: (scope: ChildAccountScope) => void; initialTarget?: ChildAccountScope;
}) {
  const parents = useResource<{ items: Parent[] }>('/api/team-admin/parents', {}, 10000);
  const [selected, setSelected] = useState<number | undefined>(initialTarget?.parentId);
  const [addOpen, setAddOpen] = useState(false);
  const parent = parents.data?.items.find((row) => row.id === selected) || parents.data?.items[0];
  return <><RequestError value={parents.error} /><div className="team-layout">
    <Card className="parent-navigator" title={<span className="panel-title"><ApartmentOutlined />母号 <span className="muted count-label">{parents.data?.items.length || 0}</span></span>} extra={<Button size="small" icon={<PlusOutlined />} onClick={() => setAddOpen(true)}>添加</Button>}>
      <div className="parent-mobile-select"><Select aria-label="选择母号" showSearch optionFilterProp="label" value={parent?.id} placeholder="选择母号" loading={parents.loading && !parents.data} options={parents.data?.items.map((item) => ({ value: item.id, label: item.email }))} onChange={setSelected} />{parent && <ParentBilling parent={parent} />}</div>
      <List loading={parents.loading && !parents.data} className="parent-list" dataSource={parents.data?.items || []} renderItem={(item) => <List.Item className={parent?.id === item.id ? 'selected-list-item' : ''}><button className="parent-choice" aria-pressed={parent?.id === item.id} onClick={() => setSelected(item.id)}><Typography.Text className="parent-email" ellipsis={{ tooltip: item.email }} strong>{item.email}</Typography.Text><span className="parent-meta"><span>{item.workspace_count || 0} 个工作区</span><Status value={item.status || 'not_synced'} /></span><ParentBilling parent={item} /></button></List.Item>} />
    </Card>
    <div className="team-detail">{parent ? <ParentDetail key={parent.id + ':' + parent.email} parent={parent} initialWorkspaceId={initialTarget?.parentId === parent.id ? initialTarget.workspaceId : undefined} onViewChildren={onViewChildren} onJobsChanged={onJobsChanged} onParentsChanged={deletedId => { if (deletedId !== undefined) setSelected(current => current === deletedId ? undefined : current); parents.reload(); }} /> : <Card><Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无母号"><Button type="primary" onClick={() => setAddOpen(true)}>添加母号</Button></Empty></Card>}</div>
  </div><ParentModal open={addOpen} onClose={() => setAddOpen(false)} onDone={(item) => { setSelected(item.id); setAddOpen(false); parents.reload(); }} /></>;
}

function ParentDetail({ parent, onJobsChanged, onParentsChanged, onViewChildren, initialWorkspaceId }: {
  parent: Parent; onJobsChanged: () => void; onParentsChanged: (deletedId?: number) => void;
  onViewChildren: (scope: ChildAccountScope) => void; initialWorkspaceId?: string;
}) {
  const mobile = useIsMobile();
  const data = useResource<{ item: Parent; workspaces: Workspace[]; jobs: Job[] }>('/api/team-admin/parents/' + parent.id, {}, 6000);
  const [workspaceId, setWorkspaceId] = useState<string | undefined>(initialWorkspaceId);
  const [billingPending, setBillingPending] = useState(false);
  const [proxyEditing, setProxyEditing] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<Pick<Parent, 'id' | 'email'> | null>(null);
  const spaces = data.data?.workspaces || [];
  const workspace = spaces.find((item) => item.id === workspaceId) || spaces[0];
  const busy = !!parent.active_job_id || data.data?.jobs.some((job) => ['queued', 'running'].includes(job.status || '')) || false;
  const action = useAction();
  const deleteBlocked = busy || billingPending || proxyEditing || !data.data || !!data.error;
  const changed = () => { onJobsChanged(); data.reload(); };
  const sync = () => action.run(async () => {
    await post('/api/team-admin/parents/' + parent.id + '/jobs', { kind: 'discover' });
    void action.message.success('工作区同步已入队'); changed();
  });
  const deleteParent = () => action.run(async () => {
    if (!deleteTarget || deleteBlocked) return;
    let deleted = false;
    try {
      await deleteResource<{ ok: boolean }>('/api/team-admin/parents/' + deleteTarget.id, { confirm: true, expected_email: deleteTarget.email });
      deleted = true;
      setDeleteTarget(null);
      void action.message.success('母号已删除');
    } finally {
      // A timeout can still mean the delete committed. Refresh only; never
      // replay the mutation, and never switch the frozen confirmation target.
      onParentsChanged(deleted ? deleteTarget.id : undefined); onJobsChanged();
      if (!deleted) data.reload();
    }
  });
  return <div className="workspace-stack"><Card className="workspace-card" title={<Typography.Text ellipsis={{ tooltip: parent.email }}>{parent.email}</Typography.Text>} extra={<Space size={16}>
    <Button size="small" icon={<SyncOutlined />} onClick={() => void sync()} loading={action.pending && !deleteTarget} disabled={busy || billingPending || proxyEditing || action.pending || !!deleteTarget}>同步工作区</Button>
    <Tooltip title={busy ? '请先完成或取消母号任务' : '删除母号'}><Button size="small" danger icon={<DeleteOutlined />} aria-label={'删除母号 ' + parent.email} disabled={deleteBlocked || action.pending} onClick={() => setDeleteTarget({ id: parent.id, email: parent.email })}>{!mobile && '删除母号'}</Button></Tooltip>
    </Space>}>
    <RequestError value={data.error} />
    <ParentProxy parent={data.data?.item || parent} disabled={busy || billingPending || action.pending || !!deleteTarget || !data.data || !!data.error}
      onChanged={() => { data.reload(); onParentsChanged(); }} onBusyChange={setProxyEditing} />
    <div className="workspace-context"><Select aria-label="工作区" value={workspace?.id} placeholder="选择工作区" loading={data.loading && !data.data} disabled={billingPending}
      options={spaces.map((item) => ({ value: item.id, label: item.name || item.id }))} onChange={setWorkspaceId} />
      <Tooltip title={!workspace?.members_synced_at ? '请先同步成员' : '查看此工作区匹配到的本地账号'}><Button icon={<TeamOutlined />} disabled={!workspace?.members_synced_at || !!data.error || !!deleteTarget || action.pending || billingPending} onClick={() => { if (workspace) onViewChildren(childAccountScope(parent, workspace)); }}>查看子号</Button></Tooltip>
      {busy && <Tag color="processing">任务执行中</Tag>}{workspace && !workspace.can_manage && <Tag>只读</Tag>}
    </div>
    {workspace && <WorkspaceBilling key={parent.id + ':' + workspace.id} parent={parent} workspace={workspace}
      disabled={!!data.error || !!deleteTarget || action.pending || proxyEditing} onRefresh={() => { data.reload(); onParentsChanged(); }} onBusyChange={setBillingPending} />}
    </Card>
    {workspace ? <WorkspaceContent key={parent.id + ':' + workspace.id} parent={parent} workspace={workspace} onJobsChanged={changed} disabled={busy || !!data.error || !!deleteTarget || action.pending || proxyEditing} /> : <Card className="data-card"><Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="同步工作区后查看成员" /></Card>}
    <Modal title="删除母号" open={!!deleteTarget} okText="确认删除" cancelText="取消" confirmLoading={action.pending} okButtonProps={{ danger: true, disabled: deleteBlocked || !deleteTarget }}
      closable={!action.pending} maskClosable={!action.pending} keyboard={!action.pending} cancelButtonProps={{ disabled: action.pending }}
      onCancel={() => { if (!action.pending) setDeleteTarget(null); }} onOk={() => void deleteParent()}>
      <Typography.Paragraph>删除母号 <Typography.Text strong>{deleteTarget?.email}</Typography.Text>？</Typography.Paragraph>
      <Typography.Paragraph>将清除本系统中的母号凭据、成员缓存和任务记录，无法撤销。不会删除账号列表中的账号，也不会移出远端 Team 成员。</Typography.Paragraph>
      {busy && <Alert type="warning" showIcon message="母号任务执行中，请完成或取消后再删除。" />}
    </Modal>
  </div>;
}

function WorkspaceContent(props: { parent: Parent; workspace: Workspace; onJobsChanged: () => void; disabled: boolean }) {
  const [tab, setTab] = useState('members');
  return <><Tabs className="workspace-tabs" activeKey={tab} onChange={setTab} items={[{ key: 'members', label: '已加入成员' }, { key: 'invites', label: '待接受邀请' }]} />
    {tab === 'members' ? <WorkspaceMembers {...props} /> : <Card className="data-card"><WorkspaceInvites {...props} /></Card>}
  </>;
}

type MemberDialog = { kind: 'remove' | 'switch' | 'invite'; members: Member[] };
function WorkspaceMembers({ parent, workspace, onJobsChanged, disabled }: { parent: Parent; workspace: Workspace; onJobsChanged: () => void; disabled: boolean }) {
  const mobile = useIsMobile();
  const tableContainer = useContentWidth();
  const [detailId, setDetailId] = useState<string>();
  const [filter, setFilter] = useState({ q: '', seat_type: '', seat_status: '' });
  const scope = JSON.stringify([parent.id, workspace.id, filter]);
  const [selection, setSelection] = useState<{ scope: string; keys: Key[] }>({ scope, keys: [] });
  const [dialog, setDialog] = useState<MemberDialog | null>(null);
  const [emails, setEmails] = useState('');
  const [seat, setSeat] = useState('prolite');
  const url = '/api/team-admin/parents/' + parent.id;
  // All cached matches, rendered virtually. Official remote pagination remains 100.
  const data = useResource<Page<Member>>('/api/team/parents/' + parent.id + '/workspaces/' + workspace.id + '/members', { page_size: 'all', ...filter }, 8000);
  const rows = data.data?.items || [];
  const rowById = new Map(rows.map((row) => [row.id, row]));
  const detail = rows.find(row => row.id + ':' + (row.reclaimable_seat_type || '') === detailId);
  const selected = selection.scope === scope ? selection.keys.filter((id) => rowById.has(String(id))) : [];
  const selectedSet = new Set(selected);
  const selectedRows = rows.filter((row) => selectedSet.has(row.id));
  const action = useAction();
  const holds = filter.seat_status === 'hold';
  const seats = workspaceSeats(workspace);
  const filterSeats = workspaceSeats(workspace, true).filter((item) => !holds || item.value !== 'usage_based');
  const blocked = disabled || action.pending || !!data.error || !data.data || !workspace.can_manage;
  const filterLocked = action.pending || !!dialog;
  const activeRows = (members: Member[]) => members.filter((row) => rowById.has(row.id) && !rowById.get(row.id)?.deactivated_time);
  const openDialog = (kind: MemberDialog['kind'], members: Member[] = []) => { setSeat('prolite'); setDialog({ kind, members }); };
  const syncMembers = () => action.run(async () => {
    await post(url + '/jobs', { kind: 'members', workspace_id: workspace.id });
    void action.message.success('成员同步已入队'); onJobsChanged();
  });
  const submit = () => action.run(async () => {
    if (blocked || !dialog) return;
    if (dialog.kind !== 'remove' && !seats.some((item) => item.value === seat)) { void action.message.warning('该工作区不支持目标席位，请重新选择'); return; }
    if (dialog.kind === 'invite') {
      const recipients = [...new Set(emails.split(/\r?\n/).map((item) => item.trim()).filter(Boolean))];
      if (!recipients.length || recipients.length > 200) { void action.message.warning('请填写 1–200 个邮箱，每行一个'); return; }
      await post(url + '/jobs', { kind: 'invite', workspace_id: workspace.id, email_addresses: recipients, seat_type: seat, role: 'standard-user', resend_emails: false });
    } else {
      const targets = activeRows(dialog.members);
      if (holds || !targets.length || targets.length !== dialog.members.length) { void action.message.warning('成员缓存已变化，请重新选择'); return; }
      if (dialog.kind === 'remove' && targets.some((row) => row.role === 'account-owner')) { void action.message.warning('不能移除工作区所有者'); return; }
      await post(url + '/jobs', { kind: dialog.kind, workspace_id: workspace.id, user_ids: targets.map((row) => row.id), ...(dialog.kind === 'switch' ? { seat_type: seat } : {}) });
    }
    void action.message.success('操作已入队');
    setDialog(null); setEmails(''); setSelection({ scope, keys: [] }); onJobsChanged();
  });
  const selectSeat = (seat_type: string, seat_status = '') => setFilter((old) => ({ ...old, seat_type, seat_status }));
  const holdCapacity = workspace.seat_capacity?.filter((item) => ['default', 'prolite'].includes(item.type));
  const held = holdCapacity?.length && holdCapacity.every((item) => item.held != null) ? holdCapacity.reduce((sum, item) => sum + item.held!, 0) : undefined;
  const warnings = [
    workspace.summary_error && '席位统计：' + workspace.summary_error,
    workspace.holds_error && 'Hold 同步：' + workspace.holds_error,
    (holds ? workspace.holds_stale : workspace.members_stale) && '当前为缓存，请同步成员。',
  ].filter((item): item is string => !!item);
  const seatTags = (row: Member) => <Space size={[16, 16]} wrap><Tag>{seatLabels[row.seat_type || ''] || row.seat_type || '—'}</Tag>{row.pending_seat_type && <Tooltip title={'待生效：' + (seatLabels[row.pending_seat_type] || row.pending_seat_type)}><Tag color="processing">待生效</Tag></Tooltip>}{row.reclaimable_seat_type && <Tag color="orange">Hold · {seatLabels[row.reclaimable_seat_type] || row.reclaimable_seat_type}</Tag>}{row.deactivated_time && <Tooltip title={row.deactivated_time}><Tag>已离开</Tag></Tooltip>}</Space>;
  const memberActions = (row: Member) => holds ? null : <Space size={16}><Button type="link" size="small" disabled={blocked || !!row.deactivated_time} onClick={() => openDialog('switch', [row])}>切席</Button><Dropdown trigger={['click']} disabled={blocked || !!row.deactivated_time} menu={{ items: [{ key: 'remove', label: '移出 Team', danger: true, disabled: row.role === 'account-owner', onClick: () => openDialog('remove', [row]) }] }}><Button aria-label="更多成员操作" type="text" size="small" icon={<MoreOutlined />} disabled={blocked || !!row.deactivated_time} /></Dropdown></Space>;
  return <>
    {mobile ? <div className="bento-tile seat-picker"><label htmlFor="workspace-seat-filter">席位分布</label><Select id="workspace-seat-filter" aria-label="按席位筛选" value={holds ? 'hold' : filter.seat_type || 'all'} disabled={filterLocked} onChange={value => value === 'hold' ? selectSeat('', 'hold') : selectSeat(value === 'all' ? '' : value)} options={[
      { value: 'all', label: '全部成员 · ' + (workspace.member_count ?? '—') },
      ...workspaceSeats(workspace, true).map(item => ({ value: item.value, label: item.label + ' · ' + (workspace.assigned?.[item.value] ?? workspace.seat_type_counts?.[item.value] ?? '—') })),
      { value: 'hold', label: 'Hold · ' + (held ?? '—') },
    ]} /></div> : <div className="seat-overview" aria-label="按席位筛选">
      <button className={'seat-summary ' + (!filter.seat_type && !holds ? 'selected' : '')} aria-pressed={!filter.seat_type && !holds} disabled={filterLocked} onClick={() => selectSeat('')}><span>全部成员</span><strong>{workspace.member_count ?? '—'}</strong></button>
      {workspaceSeats(workspace, true).map(({ value, label }) => {
        const capacity = workspace.seat_capacity?.find((item) => item.type === value);
        return <Tooltip key={value} title={'可用 ' + (capacity?.available ?? '—') + ' · 已购 ' + (capacity?.paid ?? '—') + ' · Hold ' + (capacity?.held ?? '—')}><button className={'seat-summary ' + (filter.seat_type === value && !holds ? 'selected' : '')} aria-pressed={filter.seat_type === value && !holds} disabled={filterLocked} onClick={() => selectSeat(value)}><span>{label}</span><strong>{workspace.assigned?.[value] ?? workspace.seat_type_counts?.[value] ?? '—'}</strong></button></Tooltip>;
      })}
      <button className={'seat-summary ' + (holds ? 'selected' : '')} aria-pressed={holds} disabled={filterLocked} onClick={() => selectSeat('', 'hold')}><span>Hold</span><strong>{held ?? '—'}</strong></button>
    </div>}
    <Card className="data-card member-panel">
    <details className="inline-details seat-details"><summary>席位明细</summary><div className="details-body">
      <Table size="small" rowKey="value" pagination={false} dataSource={workspaceSeats(workspace, true).map((item) => ({ ...item, ...workspace.seat_capacity?.find((capacity) => capacity.type === item.value), assigned: workspace.assigned?.[item.value] ?? workspace.seat_type_counts?.[item.value] }))}
        columns={[{ title: '席位', dataIndex: 'label' }, ...[['已分配', 'assigned'], ['可用', 'available'], ['已购', 'paid'], ['Hold', 'held']].map(([title, dataIndex]) => ({ title, dataIndex, render: (value?: number) => value ?? '—' }))]} />
      {workspace.is_usage_based_seat_enabled !== true && <p className="muted">{workspace.is_usage_based_seat_enabled === false ? '此工作区未开放 Codex 席位。' : 'Codex 席位能力待同步确认。'}</p>}
    </div></details>
    <RequestError value={data.error} /><IndexNotice value={data.data?.index} />
    {!!warnings.length && <Alert className="notice" type="warning" showIcon message={<details className="alert-details"><summary>数据未完全更新 · 查看详情</summary>{warnings.map((warning, index) => <p key={index}>{warning}</p>)}</details>} />}
    <div className="table-toolbar member-toolbar">
      <div className="toolbar-controls"><Input.Search allowClear aria-label="搜索成员" placeholder="邮箱、姓名或 ID" disabled={filterLocked} onSearch={(q) => setFilter((old) => ({ ...old, q }))} className="search-control" />
        {holds && <Select aria-label="Hold 席位类型" allowClear placeholder="全部席位" value={filter.seat_type || undefined} disabled={filterLocked} className="filter-select" options={filterSeats} onChange={(value) => selectSeat(value || '', 'hold')} />}
      </div>
      <div className="toolbar-controls"><Tooltip title="刷新本地缓存"><Button aria-label="刷新成员缓存" icon={<ReloadOutlined />} onClick={data.reload} loading={data.loading} /></Tooltip>
        <Button icon={<SyncOutlined />} onClick={() => void syncMembers()} disabled={disabled || action.pending || !workspace.can_manage}>同步成员</Button>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => openDialog('invite')} disabled={blocked}>邀请</Button>
      </div>
    </div>
    <div className="list-meta"><span>{data.data?.total || 0} {holds ? '条保留记录 · 只读' : '位成员'}</span>
      {!holds && <Button type="link" size="small" onClick={() => setSelection({ scope, keys: rows.filter((row) => !row.deactivated_time).map((row) => row.id) })} disabled={blocked || !rows.length}>全选筛选结果</Button>}
    </div>
    {!holds && !!selected.length && <div className="selection-bar"><span className="selection-count">已选 {selected.length}</span><div className="toolbar-controls">
      <Button onClick={() => openDialog('switch', selectedRows)} disabled={blocked}>切换席位</Button>
      <Tooltip title={selectedRows.some((row) => row.role === 'account-owner') ? '不能移出工作区所有者' : undefined}><Button danger onClick={() => openDialog('remove', selectedRows)} disabled={blocked || selectedRows.some((row) => row.role === 'account-owner')}>移出 Team</Button></Tooltip>
      <Button type="text" disabled={action.pending} onClick={() => setSelection({ scope, keys: [] })}>取消选择</Button>
    </div></div>}
    <div ref={tableContainer.ref} className={mobile ? 'compact-virtual' : undefined}><Table<Member> virtual rowKey={(row) => holds ? row.id + ':' + row.reclaimable_seat_type : row.id} size="small" loading={data.loading && !data.data} dataSource={rows} scroll={{ x: mobile ? tableContainer.width : 940, y: 460 }} pagination={false}
      rowSelection={holds ? undefined : { columnWidth: mobile ? 40 : undefined, selectedRowKeys: selected, onChange: (keys) => setSelection({ scope, keys }), getCheckboxProps: (row) => ({ disabled: blocked || !!row.deactivated_time }) }}
      columns={mobile ? [{ title: holds ? '保留记录' : '成员', width: Math.max(1, tableContainer.width - (holds ? 0 : 40)), render: (_, row) => <div className="compact-record">
        <Typography.Text className="record-identity">{row.email || row.name || row.id}</Typography.Text>
        <div className="record-tags">{seatTags(row)}</div>
        <div className="record-footer"><span className="muted">{roleLabels[row.role || ''] || row.role || '—'}</span><div className="record-actions"><Button type="link" size="small" onClick={() => setDetailId(row.id + ':' + (row.reclaimable_seat_type || ''))}>详情</Button>{memberActions(row)}</div></div>
        <QuotaCell value={row.local_account} />
      </div> }] : [
        { title: '成员', width: 260, render: (_, row) => <Typography.Text className="member-identity" ellipsis={{ tooltip: (row.email || row.name || '无邮箱') + ' · ' + row.id }}>{row.email || row.name || row.id}</Typography.Text> },
        { title: '角色', width: 95, render: (_, row) => (roleLabels[row.role || ''] || row.role || '—') },
        { title: '席位 / 状态', width: 245, render: (_, row) => seatTags(row) },
        { title: '额度', width: 175, render: (_, row) => <QuotaCell value={row.local_account} /> },
        { title: '操作', width: 125, render: (_, row) => memberActions(row) || <Typography.Text type="secondary">—</Typography.Text> },
      ]} /></div>
    </Card>
    <Modal title="成员详情" open={detailId !== undefined} onCancel={() => setDetailId(undefined)} footer={<Button onClick={() => setDetailId(undefined)}>关闭</Button>}>
      {detail ? <><dl className="detail-list"><dt>邮箱</dt><dd>{detail.email ? <Typography.Text copyable>{detail.email}</Typography.Text> : '未返回邮箱'}</dd><dt>成员 ID</dt><dd><Typography.Text copyable>{detail.id}</Typography.Text></dd><dt>姓名</dt><dd>{detail.name || '—'}</dd><dt>角色</dt><dd>{roleLabels[detail.role || ''] || detail.role || '—'}</dd><dt>席位</dt><dd>{seatTags(detail)}</dd>{detail.pending_seat_type && <><dt>待生效席位</dt><dd>{seatLabels[detail.pending_seat_type] || detail.pending_seat_type}</dd></>}{detail.deactivated_time && <><dt>离开时间</dt><dd>{detail.deactivated_time}</dd></>}<dt>额度</dt><dd><QuotaCell value={detail.local_account} /></dd></dl></> : <Empty description="该成员已不在当前筛选结果中" />}
    </Modal>
    <Modal title={dialog?.kind === 'invite' ? '邀请成员' : dialog?.kind === 'switch' ? '切换席位' : '确认移出 Team'} open={!!dialog} confirmLoading={action.pending} onCancel={() => { if (!action.pending) setDialog(null); }} onOk={() => void submit()} okButtonProps={{ danger: dialog?.kind === 'remove', disabled: blocked }}>
      <div className="operation-context"><Typography.Text strong>{workspace.name || workspace.id}</Typography.Text><Typography.Text type="secondary">{parent.email}</Typography.Text></div>
      {dialog?.kind === 'remove' && <Alert type="warning" showIcon message={'将移出 ' + dialog.members.length + ' 位成员，请确认目标。'} className="notice" />}
      {dialog?.kind === 'switch' && <Typography.Paragraph type="secondary">已选 {dialog.members.length} 位成员</Typography.Paragraph>}
      {dialog?.kind === 'invite' && <Input.TextArea value={emails} onChange={(event) => setEmails(event.target.value)} rows={7} aria-label="受邀邮箱，每行一个" placeholder="每行一个邮箱" disabled={action.pending} />}
      {dialog?.kind !== 'remove' && <label className="dialog-field"><span>目标席位</span><Select value={seat} onChange={setSeat} disabled={action.pending} options={seats} /></label>}
    </Modal>
  </>;
}

function ParentModal({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: (item: Parent) => void }) {
  const [form] = Form.useForm<{ email: string; access_token: string; proxy_url?: string }>();
  const action = useAction();
  const submit = () => {
    void form.validateFields().then((values) => action.run(async () => {
      const data = await post<{ item: Parent }>('/api/team-admin/parents', values);
      void action.message.success('母号已添加'); form.resetFields(); onDone(data.item);
    })).catch(() => { /* Form displays validation errors inline. */ });
  };
  return <Modal title="添加母号" open={open} onCancel={() => { if (!action.pending) { form.resetFields(); onClose(); } }} onOk={submit} confirmLoading={action.pending} okText="保存">
    <Form form={form} layout="vertical" disabled={action.pending}><Form.Item name="email" label="邮箱" rules={[{ required: true, type: 'email' }]}><Input /></Form.Item><Form.Item name="access_token" label="Web AT" rules={[{ required: true }]}><Input.Password autoComplete="off" /></Form.Item>
      <Form.Item name="proxy_url" label="固定代理（可选）"><Input.Password autoComplete="new-password" placeholder="留空则首次使用从代理池绑定" /></Form.Item></Form>
  </Modal>;
}
