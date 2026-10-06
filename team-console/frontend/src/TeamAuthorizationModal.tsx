import { useState } from 'react';
import { Button, Form, Input, Modal, Segmented, Select, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { post } from './api';
import { RequestError } from './components';
import { useAction, useResource } from './hooks';
import { teamAuthorizationPayload } from './teamAuthorization';
import type { WorkspaceChoice } from './teamAuthorization';
import type { Parent, QueueResult, Workspace } from './types';

export default function TeamAuthorizationModal({ accountIds, onClose, onSubmitted }: {
  accountIds: number[]; onClose: () => void; onSubmitted: () => void;
}) {
  const [mode, setMode] = useState<'parent' | 'manual'>('parent');
  const [parentId, setParentId] = useState<number>();
  const [workspaceId, setWorkspaceId] = useState('');
  const [manualId, setManualId] = useState('');
  const action = useAction();
  const parents = useResource<{ items: Parent[] }>(mode === 'parent' ? '/api/team-admin/parents' : null);
  const parent = parents.data?.items.find(row => row.id === parentId);
  const detail = useResource<{ workspaces: Workspace[] }>(mode === 'parent' && parentId ? '/api/team-admin/parents/' + parentId : null);
  const choice: WorkspaceChoice = mode === 'manual' ? { mode, workspaceId: manualId }
    : { mode, parentId, workspaceId, workspaces: detail.data?.workspaces || [] };
  let payload: ReturnType<typeof teamAuthorizationPayload> | undefined;
  try { payload = teamAuthorizationPayload(accountIds, choice); } catch { /* Incomplete input is not submitted. */ }
  const ready = !!payload && (mode === 'manual' || (!!parent && !parents.loading && !detail.loading && !parents.error && !detail.error));
  const submit = () => action.run(async () => {
    if (!ready || !payload) return;
    // One request only. The server freezes this target into every queued item
    // and keeps it through retries; no fallback to a different workspace.
    const result = await post<QueueResult>('/api/accounts/authorize', payload);
    action.queue(result); onSubmitted(); onClose();
  });
  const refresh = () => { parents.reload(); detail.reload(); };
  return <Modal title="Team 授权 · 选择工作区" open okText="开始 Team 授权" cancelText="取消" width={560}
    confirmLoading={action.pending} okButtonProps={{ disabled: !ready }} cancelButtonProps={{ disabled: action.pending }}
    closable={!action.pending} maskClosable={!action.pending} keyboard={!action.pending}
    onCancel={() => { if (!action.pending) onClose(); }} onOk={() => void submit()}>
    <Typography.Paragraph type="secondary">已选 {accountIds.length} 个账号</Typography.Paragraph>
    <Segmented block className="authorization-mode" aria-label="工作区选择方式" value={mode} disabled={action.pending}
      options={[{ value: 'parent', label: '从母号选择' }, { value: 'manual', label: '手动填写 ID' }]}
      onChange={value => setMode(value as 'parent' | 'manual')} />
    <Form layout="vertical" disabled={action.pending}>
      {mode === 'parent' ? <>
        <RequestError value={parents.error || detail.error} />
        <Form.Item label="母号"><Select aria-label="Team 授权母号" showSearch allowClear optionFilterProp="label" placeholder="选择母号"
          value={parentId} loading={parents.loading} options={parents.data?.items.map(row => ({ value: row.id, label: row.email }))}
          onChange={id => { setParentId(id); setWorkspaceId(''); }} /></Form.Item>
        <Form.Item label="目标工作区"><Select aria-label="Team 授权工作区" showSearch allowClear optionFilterProp="label" placeholder="选择工作区"
          value={workspaceId || undefined} disabled={!parent || action.pending || !!detail.error} loading={detail.loading}
          options={detail.data?.workspaces.map(row => ({ value: row.id, label: (row.name || '工作区') + ' · ' + row.id }))}
          onChange={id => setWorkspaceId(id || '')} /></Form.Item>
        {parent && !detail.loading && detail.data && !detail.data.workspaces.length && <Typography.Paragraph type="secondary">暂无工作区，请同步母号或手动填写 ID。</Typography.Paragraph>}
        <Button type="text" icon={<ReloadOutlined />} disabled={action.pending} loading={parents.loading || detail.loading} onClick={refresh}>刷新列表</Button>
      </> : <Form.Item label="目标工作区 ID" help={manualId && !payload ? '仅支持 1–200 位字母、数字、下划线或连字符；请勿粘贴链接或成员 ID。' : undefined} validateStatus={manualId && !payload ? 'error' : undefined}>
        <Input aria-label="手动填写 Team 工作区 ID" placeholder="粘贴工作区 ID" autoComplete="off" autoCapitalize="none" spellCheck={false}
          value={manualId} onChange={event => setManualId(event.target.value)} maxLength={220} allowClear />
      </Form.Item>}
    </Form>
    {ready && <div className="authorization-target"><span className="muted">确认目标</span><Typography.Text code copyable>{payload!.expected_workspace_id}</Typography.Text></div>}
  </Modal>;
}
