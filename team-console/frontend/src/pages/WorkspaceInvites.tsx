import { useEffect, useRef, useState } from 'react';
import type { Key } from 'react';
import { Alert, Button, Input, InputNumber, Modal, Select, Table, Tag, Tooltip, Typography } from 'antd';
import { ReloadOutlined, SyncOutlined } from '@ant-design/icons';
import { post } from '../api';
import { RequestError } from '../components';
import { useAction, useResource } from '../hooks';
import { inviteSwitchPayload, pendingInviteParams } from '../invitationActions';
import { seatLabels, workspaceSeats } from '../teamSeats';
import { useContentWidth, useIsMobile } from '../useResponsive';
import type { Invitation, Page, Parent, Workspace } from '../types';

const roles: Record<string, string> = { 'account-owner': '所有者', 'account-admin': '管理员', 'standard-user': '成员' };
function createdTime(value?: string) {
  if (!value) return '—';
  const time = new Date(value);
  return Number.isNaN(time.getTime()) ? '—' : time.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false });
}

export default function WorkspaceInvites({ parent, workspace, onJobsChanged, disabled }: {
  parent: Parent; workspace: Workspace; onJobsChanged: () => void; disabled: boolean;
}) {
  const mobile = useIsMobile();
  const tableContainer = useContentWidth();
  const [filter, setFilter] = useState({ q: '', seat: '' });
  const scope = JSON.stringify([parent.id, workspace.id, filter]);
  const [selection, setSelection] = useState<{ scope: string; keys: Key[] }>({ scope, keys: [] });
  const [targets, setTargets] = useState<Invitation[] | null>(null);
  const [seat, setSeat] = useState('prolite');
  const [concurrency, setConcurrency] = useState(5);
  const data = useResource<Page<Invitation>>('/api/team-admin/parents/' + parent.id + '/workspaces/' + workspace.id + '/invites', pendingInviteParams(filter.q, filter.seat), 8000);
  const action = useAction();
  const rows = data.data?.items || [];
  const byId = new Map(rows.map(row => [row.id, row]));
  const selected = selection.scope === scope ? selection.keys.filter(key => byId.get(String(key))?.status === 2) : [];
  const selectedSet = new Set(selected);
  const blocked = disabled || action.pending || !!data.error || !data.data || !workspace.can_manage;
  const filterLocked = action.pending || !!targets;
  const seats = workspaceSeats(workspace);
  // Pull the updated local cache when a sync/switch finishes; no remote GET here.
  const cacheVersion = JSON.stringify([disabled, workspace.invites_synced_at, workspace.invites_stale]);
  const previousCacheVersion = useRef(cacheVersion);
  useEffect(() => {
    if (previousCacheVersion.current !== cacheVersion) { previousCacheVersion.current = cacheVersion; data.reload(); }
  }, [cacheVersion, data.reload]);
  const sync = () => action.run(async () => {
    if (disabled || !workspace.can_manage) return;
    await post('/api/team-admin/parents/' + parent.id + '/jobs', { kind: 'invites', workspace_id: workspace.id });
    void action.message.success('邀请同步已入队'); onJobsChanged();
  });
  const openSwitch = (items: Invitation[]) => { setSeat('prolite'); setTargets(items.map(row => ({ ...row }))); };
  const submit = () => action.run(async () => {
    if (blocked || !targets?.length) return;
    if (!seats.some(item => item.value === seat)) { void action.message.warning('该工作区不支持目标席位'); return; }
    if (targets.some(row => byId.get(row.id)?.status !== 2 || byId.get(row.id)?.email !== row.email)) {
      void action.message.warning('邀请缓存已变化，请重新选择'); return;
    }
    await post('/api/team-admin/parents/' + parent.id + '/jobs', inviteSwitchPayload(workspace.id, targets.map(row => row.id), seat, concurrency));
    void action.message.success('已入队 ' + targets.length + ' 条邀请切席');
    setTargets(null); setSelection({ scope, keys: [] }); onJobsChanged();
  });
  return <>
    <RequestError value={data.error} />
    {workspace.invites_error ? <Alert className="notice" showIcon type="warning" message={workspace.invites_error} />
      : !workspace.invites_synced_at ? <Alert className="notice" showIcon type="info" message="尚未同步，请点击“同步邀请”。" />
      : workspace.invites_stale ? <Alert className="notice" showIcon type="info" message="邀请列表可能过期，请同步。" /> : null}
    <div className="table-toolbar member-toolbar"><div className="toolbar-controls">
      <Input.Search allowClear placeholder="邮箱或邀请 ID" aria-label="搜索待接受邀请" className="search-control" disabled={filterLocked} onSearch={q => setFilter(old => ({ ...old, q }))} />
      <Select allowClear placeholder="全部席位" aria-label="筛选邀请席位" className="filter-select" disabled={filterLocked} value={filter.seat || undefined} options={Object.entries(seatLabels).map(([value, label]) => ({ value, label }))} onChange={value => setFilter(old => ({ ...old, seat: value || '' }))} />
    </div><div className="toolbar-controls">
      <Tooltip title="刷新本地缓存"><Button icon={<ReloadOutlined />} aria-label="刷新邀请缓存" onClick={data.reload} loading={data.loading} /></Tooltip>
      <Button icon={<SyncOutlined />} disabled={disabled || action.pending || !workspace.can_manage} onClick={() => void sync()}>同步邀请</Button>
    </div></div>
    <div className="list-meta"><span>{data.data?.total || 0} 条待接受邀请</span><Button type="link" size="small" disabled={blocked || !rows.length} onClick={() => setSelection({ scope, keys: rows.filter(row => row.status === 2).map(row => row.id) })}>全选筛选结果</Button></div>
    {!!selected.length && <div className="selection-bar"><span className="selection-count">已选 {selected.length}</span><div className="toolbar-controls">
      <Button disabled={blocked} onClick={() => openSwitch(rows.filter(row => selectedSet.has(row.id)))}>切换邀请席位</Button>
      <Button type="text" disabled={action.pending} onClick={() => setSelection({ scope, keys: [] })}>取消选择</Button>
    </div></div>}
    <div ref={tableContainer.ref} className={mobile ? 'compact-virtual' : undefined}><Table<Invitation> virtual rowKey="id" size="small" dataSource={rows} loading={data.loading && !data.data} pagination={false} scroll={{ x: mobile ? tableContainer.width : 870, y: 460 }}
      rowSelection={{ columnWidth: mobile ? 40 : undefined, selectedRowKeys: selected, onChange: keys => setSelection({ scope, keys }), getCheckboxProps: row => ({ disabled: blocked || row.status !== 2 }) }}
      columns={mobile ? [{ title: '待接受邀请', width: Math.max(1, tableContainer.width - 40), render: (_, row) => <div className="compact-record">
        <Typography.Text className="record-identity" copyable>{row.email || row.id}</Typography.Text>
        <div className="record-tags"><Tag>{seatLabels[row.seat_type || ''] || row.seat_type || '—'}</Tag><span className="muted">{roles[row.role || ''] || row.role || '—'}</span></div>
        <div className="record-footer"><span className="muted">{createdTime(row.created_time)}（北京）</span><Button type="link" size="small" disabled={blocked || row.status !== 2} onClick={() => openSwitch([row])}>切席</Button></div>
      </div> }] : [
        { title: '受邀邮箱', width: 285, render: (_, row) => <Typography.Text className="member-identity" ellipsis={{ tooltip: row.email + ' · ' + row.id }}>{row.email}</Typography.Text> },
        { title: '邀请席位', width: 140, render: (_, row) => <Tag>{seatLabels[row.seat_type || ''] || row.seat_type || '—'}</Tag> },
        { title: '角色', width: 95, render: (_, row) => roles[row.role || ''] || row.role || '—' },
        { title: '邀请时间（北京）', width: 200, render: (_, row) => createdTime(row.created_time) },
        { title: '操作', width: 95, render: (_, row) => <Button type="link" size="small" disabled={blocked || row.status !== 2} onClick={() => openSwitch([row])}>切席</Button> },
      ]} /></div>
    <Modal title="切换待接受邀请席位" open={!!targets} confirmLoading={action.pending} okButtonProps={{ disabled: blocked }} onCancel={() => { if (!action.pending) setTargets(null); }} onOk={() => void submit()}>
      <div className="operation-context"><Typography.Text strong>{workspace.name || workspace.id}</Typography.Text><Typography.Text type="secondary">{parent.email}</Typography.Text></div>
      <Typography.Paragraph>已选 {targets?.length || 0} 条邀请</Typography.Paragraph>
      <label className="dialog-field"><span>目标席位</span><Select value={seat} options={seats} onChange={setSeat} disabled={action.pending} /></label>
      <label className="dialog-field"><span>并发数（1–20）</span><InputNumber aria-label="邀请切席并发数" min={1} max={20} precision={0} value={concurrency} onChange={value => setConcurrency(value ?? 5)} disabled={action.pending} /></label>
    </Modal>
  </>;
}
