import { useState } from 'react';
import { Alert, Button, Input, Modal, Select, Tag, Tooltip, Typography } from 'antd';
import { LockOutlined } from '@ant-design/icons';
import { post } from './api';
import { useAction } from './hooks';
import { parentProxyChanged, parentProxyPayload, parentProxyTarget, type ParentProxyTarget } from './parentProxySettings';
import type { Parent } from './types';

export default function ParentProxy({ parent, disabled, onChanged, onBusyChange }: {
  parent: Parent; disabled: boolean; onChanged: () => void; onBusyChange: (busy: boolean) => void;
}) {
  const [target, setTarget] = useState<ParentProxyTarget | null>(null);
  const [mode, setMode] = useState<'manual' | 'pool'>('manual');
  const [value, setValue] = useState('');
  const action = useAction();
  const stale = !!target && parentProxyChanged(target, parent);
  const open = () => {
    setValue(''); setMode(parent.proxy?.configured ? 'manual' : 'pool');
    setTarget(parentProxyTarget(parent)); onBusyChange(true);
  };
  const close = () => { setTarget(null); setValue(''); onBusyChange(false); };
  const submit = () => action.run(async () => {
    if (!target || stale || disabled) return;
    try {
      await post('/api/team-admin/parents/' + target.id + '/proxy', parentProxyPayload(target, mode, value));
      void action.message.success('固定代理已保存'); close();
    } finally {
      // Refresh on uncertain outcomes; never replay a pool reassignment.
      onChanged();
    }
  });
  return <><div className="parent-proxy-row">
    <Tag icon={<LockOutlined />} color={parent.proxy?.configured ? 'green' : undefined}>{parent.proxy?.configured ? '固定代理' : '待绑定'}</Tag>
    <Typography.Text type="secondary" className="parent-proxy-summary" ellipsis={{ tooltip: true }}>
      {parent.proxy?.configured ? parent.proxy.preview + ' · #' + parent.proxy.revision.slice(0, 8) : '首次使用从代理池绑定'}
    </Typography.Text>
    <Tooltip title={disabled ? '请先完成母号操作' : '设置此母号的固定代理'}><Button size="small" disabled={disabled || !!target} onClick={open}>设置代理</Button></Tooltip>
  </div>
  <Modal title="母号固定代理" open={!!target} okText="保存" cancelText="取消" confirmLoading={action.pending}
    onCancel={() => { if (!action.pending) close(); }} onOk={() => void submit()}
    closable={!action.pending} maskClosable={!action.pending} keyboard={!action.pending} cancelButtonProps={{ disabled: action.pending }}
    okButtonProps={{ disabled: disabled || stale || (mode === 'manual' && !value.trim()) }}>
    <Typography.Paragraph className="record-identity">{target?.email}</Typography.Paragraph>
    <label className="dialog-field"><span>绑定方式</span><Select value={mode} disabled={action.pending} onChange={next => { setMode(next); setValue(''); }} options={[
      { value: 'manual', label: '手动指定代理' }, { value: 'pool', label: parent.proxy?.configured ? '从代理池换一条' : '从代理池分配一条' },
    ]} /></label>
    {mode === 'manual' && <label className="dialog-field"><span>代理地址</span><Input.Password value={value} onChange={event => setValue(event.target.value)} autoComplete="new-password" spellCheck={false}
      placeholder="socks5h://用户:密码@主机:端口" disabled={action.pending} /></label>}
    <Typography.Paragraph type="secondary">同一母号所有管理请求固定使用，失败不换线、不直连。固定地址不保证供应商出口 IP 不变。</Typography.Paragraph>
    {stale && <Alert type="warning" showIcon message="代理信息已变化，请关闭后重新打开。" />}
  </Modal></>;
}
