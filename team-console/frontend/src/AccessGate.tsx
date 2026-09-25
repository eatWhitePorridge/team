import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Alert, Button, Form, Input, Spin, Typography } from 'antd';
import { ArrowRightOutlined, LockOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { AUTH_EXPIRED_EVENT, errorText, getAccessKey, InvalidAccessKeyError, setAccessKey, verifyAccessKey } from './api';

type Phase = 'checking' | 'locked' | 'authenticated';

export default function AccessGate({ children }: { children: (logout: () => void) => ReactNode }) {
  const [phase, setPhase] = useState<Phase>(() => getAccessKey() ? 'checking' : 'locked');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [form] = Form.useForm<{ accessKey: string }>();
  const verification = useRef<AbortController | null>(null);
  const pending = useRef(false);

  useEffect(() => {
    const expired = () => {
      verification.current?.abort();
      pending.current = false;
      setSubmitting(false);
      setAccessKey('');
      setError('访问密钥已失效，请重新登录。');
      form.resetFields();
      setPhase('locked');
    };
    window.addEventListener(AUTH_EXPIRED_EVENT, expired);
    const saved = getAccessKey();
    const controller = new AbortController();
    verification.current = controller;
    if (saved) {
      void verifyAccessKey(saved, controller.signal).then(() => {
        if (!controller.signal.aborted) setPhase('authenticated');
      }).catch((reason: unknown) => {
        if (controller.signal.aborted) return;
        if (reason instanceof InvalidAccessKeyError) setAccessKey('');
        setError(errorText(reason));
        setPhase('locked');
      });
    }
    return () => {
      controller.abort();
      verification.current?.abort();
      window.removeEventListener(AUTH_EXPIRED_EVENT, expired);
    };
  }, [form]);

  const login = async ({ accessKey }: { accessKey: string }) => {
    if (pending.current) return;
    pending.current = true;
    const controller = new AbortController();
    verification.current?.abort();
    verification.current = controller;
    setSubmitting(true);
    setError('');
    try {
      // Do not save an unverified candidate or mount any business page yet.
      await verifyAccessKey(accessKey, controller.signal);
      if (controller.signal.aborted) return;
      setAccessKey(accessKey);
      form.resetFields();
      setPhase('authenticated');
    } catch (reason) {
      if (!controller.signal.aborted) setError(errorText(reason));
    } finally {
      if (!controller.signal.aborted) {
        pending.current = false;
        setSubmitting(false);
      }
    }
  };

  const logout = () => {
    verification.current?.abort();
    setAccessKey('');
    form.resetFields();
    setError('');
    setPhase('locked');
  };

  if (phase === 'authenticated') return <>{children(logout)}</>;

  return <main className="access-page">
    <section className="access-panel" aria-labelledby="access-title">
      <div className="access-brand"><span className="brand-mark">T</span><span>Team Console</span></div>
      <div className="access-lock"><SafetyCertificateOutlined /></div>
      <Typography.Title id="access-title" level={2}>登录管理台</Typography.Title>
      <Typography.Paragraph type="secondary" className="access-description">输入访问密钥，继续管理 Team 和账号。</Typography.Paragraph>
      {phase === 'checking' ? <div className="access-checking" role="status"><Spin /><span>正在验证访问密钥…</span></div> : <>
        {error && <Alert className="access-error" type="error" showIcon message={error} role="alert" />}
        <Form form={form} layout="vertical" onFinish={login} requiredMark={false} disabled={submitting}>
          <Form.Item name="accessKey" label="访问密钥" rules={[{ required: true, whitespace: true, message: '请输入访问密钥' }]}>
            <Input.Password prefix={<LockOutlined />} placeholder="请输入访问密钥" autoComplete="current-password" autoFocus size="large" />
          </Form.Item>
          <Button type="primary" size="large" htmlType="submit" block loading={submitting} icon={<ArrowRightOutlined />}>进入后台</Button>
        </Form>
      </>}
      <div className="access-footer"><LockOutlined /><span>密钥仅保存在当前标签页，退出后清除</span></div>
    </section>
  </main>;
}
