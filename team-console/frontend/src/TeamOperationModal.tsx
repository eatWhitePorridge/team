import { useState } from 'react';
import { Alert, Button, Form, Modal, Select, Space, Table, Tooltip, Typography } from 'antd';
import { post } from './api';
import { RequestError } from './components';
import { useAction, useResource } from './hooks';
import { workspaceSeats } from './teamSeats';
import type { Parent, TeamOperationPreview, TeamScope, Workspace } from './types';
import { useIsMobile } from './useResponsive';

export default function TeamOperationModal({ kind, scope, onClose, onSubmitted }: {
  kind: 'switch' | 'remove'; scope: TeamScope; onClose: () => void; onSubmitted: () => void;
}) {
  const mobile = useIsMobile();
  const parents = useResource<{ items: Parent[] }>('/api/team-admin/parents');
  const [parentId, setParentId] = useState<number>();
  const [workspaceId, setWorkspaceId] = useState<string>();
  const [seat, setSeat] = useState('prolite');
  const parent = parents.data?.items.find((row) => row.id === parentId);
  const detail = useResource<{ workspaces: Workspace[] }>(parentId ? '/api/team-admin/parents/' + parentId : null);
  const workspace = detail.data?.workspaces.find((row) => row.id === workspaceId);
  const seats = workspaceSeats(workspace);
  const stamp = JSON.stringify([kind, scope, parentId, workspaceId, seat]);
  const [preview, setPreview] = useState<{ stamp: string; data: TeamOperationPreview }>();
  const current = preview?.stamp === stamp ? preview.data : undefined;
  const action = useAction();
  const ready = !!parent && !!workspace?.can_manage && !parent.active_job_id && !parents.error && !detail.error && (kind !== 'switch' || seats.some((row) => row.value === seat));
  const endpoint = '/api/team-admin/parents/' + parentId + '/' + kind + '-accounts';
  const payload = { ...scope, workspace_id: workspaceId, ...(kind === 'switch' ? { seat_type: seat } : {}) };
  const inspect = () => action.run(async () => {
    if (!ready) return;
    setPreview(undefined);
    setPreview({ stamp, data: await post<TeamOperationPreview>(endpoint + '/preview', payload) });
  });
  const submit = () => action.run(async () => {
    if (!ready || !current?.eligible_count) return;
    await post(endpoint, { ...payload, selection_hash: current.selection_hash });
    void action.message.success('已入队 ' + current.eligible_count + ' 个成员');
    onSubmitted(); onClose();
  });
  return <Modal open title={kind === 'switch' ? '切换 Team 席位' : '移出 Team'} width={720} onCancel={() => { if (!action.pending) onClose(); }} footer={<Space size={16} wrap className="operation-footer">
    <Button onClick={onClose} disabled={action.pending}>取消</Button><Button onClick={() => void inspect()} disabled={!ready || action.pending}>预览成员</Button>
    <Button type="primary" danger={kind === 'remove'} loading={action.pending} disabled={!ready || !current?.eligible_count} onClick={() => void submit()}>确认{kind === 'switch' ? '切换' : '移出'}</Button>
  </Space>}>
    <RequestError value={parents.error || detail.error} />
    <Typography.Paragraph type="secondary">{scope.batch_id ? <>批次 <Tooltip title={scope.batch_id}><Typography.Text copyable={{ text: scope.batch_id }}>{scope.batch_id.slice(0, 8)}</Typography.Text></Tooltip></> : '已选择 ' + scope.account_ids!.length + ' 个账号'}</Typography.Paragraph>
    <Form layout="vertical" className="dialog-grid">
      <Form.Item label="母号"><Select placeholder="选择母号" showSearch optionFilterProp="label" value={parentId} disabled={action.pending} loading={parents.loading} options={parents.data?.items.map((row) => ({ value: row.id, label: row.email }))} onChange={(id) => { setParentId(id); setWorkspaceId(undefined); setPreview(undefined); }} /></Form.Item>
      <Form.Item label="工作区"><Select placeholder="选择工作区" value={workspaceId} disabled={!parentId || action.pending} loading={detail.loading} options={detail.data?.workspaces.map((row) => ({ value: row.id, label: row.name || row.id, disabled: !row.can_manage }))} onChange={setWorkspaceId} /></Form.Item>
      {kind === 'switch' && <Form.Item label="目标席位"><Select value={seat} options={seats} disabled={!workspace || action.pending} onChange={setSeat} /></Form.Item>}
    </Form>
    {!!parent?.active_job_id && <Alert className="notice" type="warning" message="母号任务执行中，请稍后操作。" />}
    {current && <><div className="preview-summary"><strong>可处理 {current.eligible_count} 人</strong><span className="muted">跳过 {current.skipped_count} 人</span></div>
      <Table rowKey="account_id" size="small" dataSource={current.items} scroll={mobile ? { y: 280 } : { x: 620, y: 280 }} pagination={{ pageSize: 10, hideOnSinglePage: true, showSizeChanger: false, simple: mobile ? { readOnly: true } : false }} columns={mobile ? [{ title: '匹配结果', render: (_, row) => <div className="compact-record"><Typography.Text className="record-identity">{row.email || '账号 ' + row.account_id}</Typography.Text><span className="record-meta">成员 ID：{row.user_id || '—'}</span><span className="record-meta">{row.message}</span></div> }] : [{ title: '账号', dataIndex: 'email', width: 230, ellipsis: true }, { title: '成员 ID', dataIndex: 'user_id', width: 150, ellipsis: true }, { title: '说明', dataIndex: 'message' }]} />
    </>}
  </Modal>;
}
