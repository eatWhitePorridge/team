import { Fragment, useEffect, useRef, useState, type ReactNode } from 'react';
import { Alert, Button, Form, Input, Spin } from 'antd';
import { ApartmentOutlined, ArrowRightOutlined, LockOutlined, SafetyCertificateOutlined, TeamOutlined } from '@ant-design/icons';
import { accessSession, errorText, getAccessKey, InvalidAccessKeyError, verifyAccessKey } from './api';
import type { AccessSnapshot } from './accessSession';

import { Brand } from './Bento';

type Phase = 'checking' | 'locked' | 'authenticated';

export default function AccessGate({ children }: { children: (logout: () => void) => ReactNode }) {
  const [phase, setPhase] = useState<Phase>(() => getAccessKey() ? 'checking' : 'locked');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [form] = Form.useForm<{ accessKey: string }>();
  const verification = useRef<AbortController | null>(null);
  const pending = useRef(false);
  const resync = useRef<() => void>(() => {});
  const [sessionRevision, setSessionRevision] = useState('');

  useEffect(() => {
    const reset = () => {
      verification.current?.abort();
      pending.current = false;
      setSubmitting(false);
      form.resetFields();
    };
    const checkSaved = (snapshot: AccessSnapshot) => {
      reset(); setError('');
      if (!snapshot.key) { setPhase('locked'); return; }
      const controller = new AbortController();
      verification.current = controller;
      setPhase('checking');
      void verifyAccessKey(snapshot.key, controller.signal).then(() => {
        if (controller.signal.aborted) return;
        if (!accessSession.acceptVerified(snapshot.key, snapshot)) resync.current();
      }).catch((reason: unknown) => {
        if (controller.signal.aborted) return;
        if (!accessSession.current(snapshot)) { resync.current(); return; }
        if (reason instanceof InvalidAccessKeyError) accessSession.expire(snapshot);
        setError(errorText(reason));
        setPhase('locked');
      });
    };
    resync.current = () => checkSaved(accessSession.read());
    const unsubscribe = accessSession.subscribe(({ snapshot, reason }) => {
      if (reason === 'external') { checkSaved(snapshot); return; }
      reset();
      setError(reason === 'expired' ? '访问密钥已失效，请重新登录。' : '');
      setSessionRevision(snapshot.revision);
      setPhase(reason === 'verified' && snapshot.key ? 'authenticated' : 'locked');
    });
    resync.current();
    return () => {
      verification.current?.abort();
      unsubscribe(); resync.current = () => {};
    };
  }, [form]);

  const login = async ({ accessKey }: { accessKey: string }) => {
    if (pending.current) return;
    pending.current = true;
    const before = accessSession.read();
    const controller = new AbortController();
    verification.current?.abort();
    verification.current = controller;
    setSubmitting(true);
    setError('');
    try {
      // Do not save an unverified candidate or mount any business page yet.
      await verifyAccessKey(accessKey, controller.signal);
      if (controller.signal.aborted) return;
      if (!accessSession.acceptVerified(accessKey, before)) resync.current();
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
    accessSession.logout();
  };

  if (phase === 'authenticated') return <Fragment key={sessionRevision}>{children(logout)}</Fragment>;

  return <main className="access-page">
    <div className="access-grid bento-grid">
      <section className="bento-tile access-intro tone-dark bento-wide">
        <Brand />
        <div className="access-intro-copy"><h1>账号与工作区，<br />集中管理。</h1></div>
        <div className="access-mosaic" aria-hidden="true"><span><ApartmentOutlined /></span><span /><span /><span><TeamOutlined /></span></div>
      </section>
      <section className="bento-tile access-panel bento-wide" aria-labelledby="access-title">
        <div className="access-lock"><SafetyCertificateOutlined aria-hidden="true" /></div>
        <h2 id="access-title">登录管理台</h2>
        {phase === 'checking' ? <div className="access-checking" role="status"><Spin /><span>正在验证访问密钥…</span></div> : <>
          {error && <Alert className="access-error" type="error" showIcon message={error} role="alert" />}
          <Form form={form} layout="vertical" onFinish={login} requiredMark={false} disabled={submitting}>
            <Form.Item name="accessKey" label="访问密钥" rules={[{ required: true, whitespace: true, message: '请输入访问密钥' }]}>
              <Input.Password prefix={<LockOutlined />} placeholder="请输入访问密钥" autoComplete="current-password" autoFocus size="large" />
            </Form.Item>
            <Button type="primary" size="large" htmlType="submit" block loading={submitting} icon={<ArrowRightOutlined />}>进入管理台</Button>
          </Form>
        </>}
      </section>
      <section className="bento-tile access-feature tone-lime"><span className="tile-icon" aria-hidden="true"><TeamOutlined /></span><h2>账号与批次</h2></section>
      <section className="bento-tile access-feature"><span className="tile-icon" aria-hidden="true"><ApartmentOutlined /></span><h2>母号与席位</h2></section>
    </div>
  </main>;
}
