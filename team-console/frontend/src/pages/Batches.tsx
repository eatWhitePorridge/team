import { useState } from 'react';
import { ListHeading } from '../Bento';
import { Button, Card, Checkbox, Dropdown, Input, Modal, Select, Space, Table, Tooltip, Typography } from 'antd';
import { DeleteOutlined, DownOutlined, ReloadOutlined } from '@ant-design/icons';
import { post } from '../api';
import { IndexNotice, RequestError } from '../components';
import { useAction, useResource } from '../hooks';
import type { Batch, DeleteBatchesResult, MergeBatchesResult, Page } from '../types';
import TeamOperationModal from '../TeamOperationModal';
import MobileList from '../MobileList';
import { useIsMobile } from '../useResponsive';
export default function Batches({ onJobsChanged, onViewAccounts }: { onJobsChanged: () => void; onViewAccounts: (batchId: string) => void }) {
  const mobile = useIsMobile();
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [operation, setOperation] = useState<{ kind: 'switch' | 'remove'; batch_id: string }>();
  const [selection, setSelection] = useState<{ scope: string; rows: Batch[] }>({ scope: '', rows: [] });
  const selected = selection.scope === query ? selection.rows : [];
  const [mergeTarget, setMergeTarget] = useState<{ batches: Batch[]; targetId: string } | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Batch[] | null>(null);
  const [cascadeConfirmed, setCascadeConfirmed] = useState(false);
  const action = useAction();
  const data = useResource<Page<Batch>>('/api/batches', { q: query, page, page_size: 50 }, 6000);
  const openDelete = (batches: Batch[]) => { setDeleteTarget([...batches]); setCascadeConfirmed(false); };
  const clearProcessed = (ids: string[]) => {
    const processed = new Set(ids);
    setSelection((old) => ({ ...old, rows: old.rows.filter((row) => !processed.has(row.batch_id)) }));
    setPage(1); onJobsChanged();
  };
  const mergeBatches = () => action.run(async () => {
    if (!mergeTarget) return;
    try {
      const ids = mergeTarget.batches.map((row) => row.batch_id);
      const result = await post<MergeBatchesResult>('/api/batches/merge', { batch_ids: ids, target_batch_id: mergeTarget.targetId, confirm: true });
      setMergeTarget(null); clearProcessed(ids);
      void action.message.success(result.already_merged ? '这些批次已合并' : '已合并 ' + result.merged_count + ' 个来源批次，归入 ' + result.moved_accounts + ' 个账号');
      action.details('合并提示', result.warnings);
    } finally { data.reload(); }
  });
  const deleteBatches = () => action.run(async () => {
    if (!deleteTarget?.length || !cascadeConfirmed) return;
    try {
      const result = await post<DeleteBatchesResult>('/api/batches/delete', { batch_ids: deleteTarget.map((row) => row.batch_id), confirm: true, cascade_accounts: true });
      setDeleteTarget(null); setCascadeConfirmed(false); clearProcessed(result.deleted_batch_ids);
      void action.message.success('已删除 ' + result.deleted_count + ' 个批次及 ' + result.deleted_account_count + ' 个账号');
      action.details('删除提示', result.warnings);
    } finally { data.reload(); }
  });
  const batchActions = (row: Batch) => <Space size={16} wrap><Button type="link" size="small" onClick={() => onViewAccounts(row.batch_id)}>查看账号</Button><Dropdown trigger={['click']} disabled={action.pending} menu={{ items: [
    { key: 'switch', label: '切换席位', onClick: () => setOperation({ kind: 'switch', batch_id: row.batch_id }) },
    { key: 'remove', label: '移出 Team', danger: true, onClick: () => setOperation({ kind: 'remove', batch_id: row.batch_id }) },
  ] }}><Button type="text" size="small" disabled={action.pending}>更多 <DownOutlined /></Button></Dropdown><Tooltip title="删除批次及账号"><Button danger type="text" size="small" icon={<DeleteOutlined />} aria-label={'删除批次 ' + row.batch_id} disabled={action.pending} onClick={() => openDelete([row])} /></Tooltip></Space>;
  return <div className="page-stack"><Card className="data-card">
    <ListHeading title={query ? '筛选结果' : '导入批次'} count={data.data?.total} />
    <RequestError value={data.error} /><IndexNotice value={data.data?.index} />
    <div className="table-toolbar compact-toolbar"><div className="toolbar-controls">
      <Input.Search aria-label="搜索批次 ID" className="search-control" placeholder="搜索批次 ID" allowClear onSearch={(q) => { setQuery(q); setPage(1); setSelection({ scope: q, rows: [] }); }} />
    </div><Tooltip title="刷新列表"><Button aria-label="刷新批次列表" icon={<ReloadOutlined />} onClick={data.reload} loading={data.loading} /></Tooltip></div>
    {!!selected.length && <div className="selection-bar">
      <span className="selection-count">已选 {selected.length} 个批次</span>
      <div className="toolbar-controls">
        <Button type="primary" disabled={action.pending || selected.length < 2} onClick={() => setMergeTarget({ batches: [...selected], targetId: selected[0].batch_id })}>合并批次</Button>
        <Button danger icon={<DeleteOutlined />} disabled={action.pending} onClick={() => openDelete(selected)}>删除批次</Button>
        <Button type="text" disabled={action.pending} onClick={() => setSelection({ scope: query, rows: [] })}>取消选择</Button>
      </div>
    </div>}
    {mobile ? <MobileList rows={data.data?.items || []} rowKey={row => row.batch_id} label={row => '批次 ' + row.batch_id} loading={data.loading && !data.data}
      selection={{ keys: selected.map(row => row.batch_id), disabled: action.pending || !!data.error, onChange: keys => {
        const byId = new Map([...selected, ...(data.data?.items || [])].map(row => [row.batch_id, row]));
        setSelection({ scope: query, rows: keys.map(key => byId.get(String(key))).filter((row): row is Batch => !!row) });
      } }}
      pagination={{ page: data.data?.page || page, pageSize: 50, total: data.data?.total || 0, onChange: setPage }}
      renderItem={row => <>
        <div className="record-heading"><Typography.Text className="record-identity" copyable={{ text: row.batch_id }}>批次 {row.batch_id.slice(0, 8)}</Typography.Text><span className="record-count">{row.account_total} 个账号</span></div>
        <div className="record-meta">导入于 {row.created_at || '—'}</div>
        <div className="record-actions">{batchActions(row)}</div>
      </>} /> : <Table<Batch> size="middle" rowKey="batch_id" dataSource={data.data?.items || []} loading={data.loading && !data.data} scroll={{ x: 780, y: 'max(280px, calc(100dvh - 360px))' }}
      rowSelection={{ selectedRowKeys: selected.map((row) => row.batch_id), preserveSelectedRowKeys: true, onChange: (_, rows) => setSelection({ scope: query, rows }) }}
      columns={[{ title: '批次', dataIndex: 'batch_id', width: 190, render: (value: string) => <Tooltip title={value}><Typography.Text copyable={{ text: value }}>{value.slice(0, 8)}</Typography.Text></Tooltip> }, { title: '账号数', dataIndex: 'account_total', width: 90 }, { title: '导入时间', dataIndex: 'created_at', width: 190 }, { title: '操作', width: 260, fixed: 'right', render: (_, row) => batchActions(row) }]}
      pagination={{ current: data.data?.page || page, pageSize: 50, total: data.data?.total || 0, showTotal: (total) => '共 ' + total + ' 个批次', showSizeChanger: false, onChange: setPage }} />}
  </Card>
    <Modal title="合并批次" open={!!mergeTarget} okText="确认合并" cancelText="取消" confirmLoading={action.pending} okButtonProps={{ disabled: !mergeTarget?.targetId }}
      closable={!action.pending} maskClosable={!action.pending} keyboard={!action.pending} cancelButtonProps={{ disabled: action.pending }}
      onCancel={() => { if (!action.pending) setMergeTarget(null); }} onOk={() => void mergeBatches()}>
      <Typography.Paragraph>合并 {mergeTarget?.batches.length || 0} 个批次，保留以下批次 ID；账号信息不变。</Typography.Paragraph>
      <Select aria-label="保留的目标批次" style={{ width: '100%' }} value={mergeTarget?.targetId} disabled={action.pending}
        options={mergeTarget?.batches.map((row) => ({ value: row.batch_id, label: row.batch_id }))}
        onChange={(targetId) => setMergeTarget((old) => old && ({ ...old, targetId }))} />
    </Modal>
    <Modal title="删除批次及账号" open={!!deleteTarget} okText="确认级联删除" cancelText="取消" confirmLoading={action.pending} okButtonProps={{ danger: true, disabled: !cascadeConfirmed || !deleteTarget?.length }}
      closable={!action.pending} maskClosable={!action.pending} keyboard={!action.pending} cancelButtonProps={{ disabled: action.pending }}
      onCancel={() => { if (!action.pending) setDeleteTarget(null); }} onOk={() => void deleteBatches()}>
      <Typography.Paragraph>将永久删除所选 <strong>{deleteTarget?.length || 0}</strong> 个批次，以及批次下全部本地账号（含归档账号）、关联凭据和 Cookie。不会注销远端账号，也不会移出 Team。</Typography.Paragraph>
      {deleteTarget?.length === 1 && <Typography.Paragraph code copyable>{deleteTarget[0].batch_id}</Typography.Paragraph>}
      <Typography.Paragraph type="secondary">存在授权、查额度等运行中任务时，整次操作将被阻止，不会只删一部分。</Typography.Paragraph>
      <Checkbox checked={cascadeConfirmed} disabled={action.pending} onChange={(event) => setCascadeConfirmed(event.target.checked)}>我确认一并删除批次下全部本地账号，无法撤销</Checkbox>
    </Modal>
    {operation && <TeamOperationModal kind={operation.kind} scope={{ batch_id: operation.batch_id }} onClose={() => setOperation(undefined)} onSubmitted={() => { onJobsChanged(); data.reload(); }} />}</div>;
}
