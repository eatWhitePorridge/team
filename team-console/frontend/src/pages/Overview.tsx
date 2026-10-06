import { useState } from 'react';
import { Button, Card, Table, Typography } from 'antd';
import { ApartmentOutlined, ArrowRightOutlined, DatabaseOutlined, PieChartOutlined, ReloadOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { IndexNotice, RequestError, Status } from '../components';
import { BentoLead, BentoStat } from '../Bento';
import { accountMetrics } from '../bentoMetrics';
import { useResource } from '../hooks';
import type { Overview as OverviewData, Parent } from '../types';
import type { View } from '../App';
import MobileList from '../MobileList';
import { useIsMobile } from '../useResponsive';
import { pageRows } from '../responsive';

export default function Overview({ onNavigate }: { onNavigate: (view: View) => void }) {
  const mobile = useIsMobile();
  const [page, setPage] = useState(1);
  const data = useResource<OverviewData>('/api/overview', {}, 10000);
  const metrics = accountMetrics(data.data?.accounts);
  const parents = data.data?.parents || [];
  const mobilePage = pageRows(parents, page, 10);
  return <div className="page-stack">
    <RequestError value={data.error} /><IndexNotice value={data.data?.index} />
    <div className="bento-grid overview-grid">
      <section className="bento-tile overview-primary bento-wide tone-dark" aria-label="账号资产概览">
        <div className="tile-heading"><span className="tile-label">账号总数</span><span className="tile-icon" aria-hidden="true"><DatabaseOutlined /></span></div>
        <div className="overview-total"><strong>{metrics.total?.toLocaleString('zh-CN') ?? '—'}</strong><span>已导入账号</span></div>
        <div className="coverage-block"><div className="tile-heading"><span>授权覆盖</span><strong>{metrics.coverage === undefined ? '—' : metrics.coverage + '%'}</strong></div><div className="coverage-meter" role="progressbar" aria-label="账号授权覆盖率" aria-valuemin={0} aria-valuemax={100} aria-valuenow={metrics.coverage}><span style={{ width: (metrics.coverage ?? 0) + '%' }} /></div></div>
        <dl className="overview-breakdown"><div><dt>已授权</dt><dd>{metrics.connected?.toLocaleString('zh-CN') ?? '—'}</dd></div><div><dt>未授权</dt><dd>{metrics.remaining?.toLocaleString('zh-CN') ?? '—'}</dd></div></dl>
        <Button className="accent-button" icon={<ArrowRightOutlined />} onClick={() => onNavigate('accounts')}>管理账号</Button>
      </section>
      <BentoStat title="2FA 已接入" value={metrics.totp?.toLocaleString('zh-CN')} icon={<SafetyCertificateOutlined />} tone="lime" />
      <BentoStat title="额度已查询" value={metrics.quota?.toLocaleString('zh-CN')} icon={<PieChartOutlined />} />
      <BentoLead title="母号" value={data.data ? parents.length : undefined} icon={<ApartmentOutlined />} action={<Button type="text" aria-label="进入母号管理" icon={<ArrowRightOutlined />} onClick={() => onNavigate('team')} />} />
      <Card className="data-card bento-full" title={<div className="panel-title"><ApartmentOutlined /><span>母号一览</span></div>} extra={<Button icon={<ReloadOutlined />} aria-label="刷新母号概览" onClick={data.reload} loading={data.loading}>{!mobile && '刷新'}</Button>}>
        {mobile ? <MobileList rows={mobilePage.items} rowKey={row => row.id} label={row => row.email} loading={data.loading && !data.data}
          pagination={parents.length > 10 ? { page: mobilePage.page, pageSize: 10, total: parents.length, onChange: setPage } : undefined}
          renderItem={row => <><Typography.Text className="record-identity" copyable>{row.email}</Typography.Text><div className="record-tags"><Status value={row.status} /><span>{row.workspace_count ?? '—'} 个工作区</span></div><div className="record-meta">更新于 {row.updated_at || '—'}</div></>} />
          : <Table<Parent> size="middle" rowKey="id" scroll={{ x: 680 }} loading={data.loading && !data.data} pagination={{ pageSize: 10, showSizeChanger: false, hideOnSinglePage: true }} dataSource={parents} columns={[{ title: '母号', dataIndex: 'email', ellipsis: true }, { title: '状态', dataIndex: 'status', width: 110, render: value => <Status value={value} /> }, { title: '工作区', dataIndex: 'workspace_count', width: 90, render: value => value ?? '—' }, { title: '更新时间', dataIndex: 'updated_at', width: 185 }]} />}
      </Card>
    </div>
  </div>;
}
