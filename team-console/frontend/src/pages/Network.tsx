import { useEffect, useRef } from 'react';
import { Alert, Button, Card, Form, Input, Select, Typography } from 'antd';
import { CloudServerOutlined, ReloadOutlined } from '@ant-design/icons';
import { post } from '../api';
import { RequestError } from '../components';
import { useAction, useResource } from '../hooks';
import type { NetworkSettings } from '../types';

const operations = [{ value: 'keep', label: '保留当前配置' }, { value: 'replace', label: '替换为新代理' }, { value: 'clear', label: '清空配置' }];
const routes: Record<string, string> = { proxy: '强制代理', auto: '自动路由', direct: '直连' };
export default function Network() {
  const data = useResource<{ settings: NetworkSettings }>('/api/settings/network');
  const [form] = Form.useForm();
  const quotaSection = useRef<HTMLDetailsElement>(null);
  const poolAction = Form.useWatch('pool_action', form);
  const quotaAction = Form.useWatch('quota_proxy_action', form);
  const action = useAction();
  const settings = data.data?.settings;
  useEffect(() => { if (settings) form.setFieldsValue({ quota_proxy_mode: settings.quota_proxy_mode }); }, [settings, form]);
  const save = (values: Record<string, unknown>) => action.run(async () => {
    const result = await post<{ settings: NetworkSettings }>('/api/settings/network', values);
    form.resetFields(); form.setFieldsValue({ quota_proxy_mode: result.settings.quota_proxy_mode });
    data.reload(); void action.message.success('已保存，新会话立即生效');
  });
  return <div className="bento-grid network-grid"><Card className="data-card settings-card bento-wide">
    <RequestError value={data.error} />
    <div className="settings-heading"><Typography.Title level={4}>代理设置</Typography.Title><Button aria-label="刷新代理状态" icon={<ReloadOutlined />} onClick={data.reload} loading={data.loading} /></div>
    <Form form={form} layout="vertical" onFinish={(values) => void save(values)} onFinishFailed={({ errorFields }) => {
      if (quotaSection.current && errorFields.some((field) => String(field.name[0]).startsWith('quota_'))) quotaSection.current.open = true;
    }} initialValues={{ pool_action: 'keep', quota_proxy_action: 'keep' }} disabled={action.pending || !settings || !!data.error} className="network-form">
      <Form.Item name="pool_action" label="配置操作"><Select options={operations} /></Form.Item>
      {poolAction === 'replace' && <Form.Item name="proxy_pool" label="新代理 · 每行一个" rules={[{ required: true, whitespace: true }]} tooltip="支持 socks5h://、socks5://、http(s):// 和 主机:端口:用户:密码。">
        <Input.TextArea rows={7} autoComplete="off" placeholder="socks5h://username:password@host:port" />
      </Form.Item>}
      {poolAction === 'clear' && <Alert className="notice" type="warning" showIcon message="保存后，新会话将不再使用代理池。" />}
      {!!settings?.pool_preview.length && <details className="inline-details network-preview"><summary>查看代理示例</summary><pre>{settings.pool_preview.join('\n')}</pre></details>}
      <details className="settings-section" ref={quotaSection}><summary>额度查询代理 <span className="muted">{routes[settings?.quota_proxy_mode || ''] || '—'}</span></summary><div className="details-body">
        <Form.Item name="quota_proxy_mode" label="连接方式" rules={[{ required: true }]}><Select options={[{ value: 'proxy', label: '强制代理' }, { value: 'auto', label: '自动路由（优先代理）' }, { value: 'direct', label: '直连' }]} /></Form.Item>
        <Form.Item name="quota_proxy_action" label="专用代理" tooltip="未单独设置时，代理模式使用上面的代理池。" extra={settings?.quota_proxy_preview || undefined}><Select options={operations} /></Form.Item>
        {quotaAction === 'replace' && <Form.Item name="quota_proxy" label="专用代理地址" rules={[{ required: true, whitespace: true }]}><Input.Password autoComplete="off" /></Form.Item>}
        {quotaAction === 'clear' && <Typography.Paragraph type="warning">保存后移除专用代理，代理模式改用代理池。</Typography.Paragraph>}
      </div></details>
      <div className="settings-footer"><Button type="primary" htmlType="submit" loading={action.pending} disabled={!settings || !!data.error}>保存配置</Button><Typography.Text type="secondary">新会话生效</Typography.Text></div>
    </Form>
  </Card>
    <section className="bento-tile network-summary bento-wide">
      <div className="tile-heading"><h2>代理池</h2><span className="tile-icon" aria-hidden="true"><CloudServerOutlined /></span></div>
      <div className="network-pool-count"><strong className="bento-value">{settings?.pool_count ?? '—'}</strong><span className="muted">条</span></div>
      <dl className="settings-facts"><div><dt>额度连接</dt><dd>{settings ? routes[settings.quota_proxy_mode] || settings.quota_proxy_mode : '—'}</dd></div><div><dt>额度专用代理</dt><dd>{settings ? settings.quota_proxy_configured ? '已设置' : '未设置' : '—'}</dd></div><div><dt>配置来源</dt><dd>{settings ? settings.source === 'deployment' ? '部署配置' : '自定义' : '—'}</dd></div></dl>
    </section>
  </div>;
}
