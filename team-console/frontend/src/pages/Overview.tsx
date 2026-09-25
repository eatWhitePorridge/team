import { Button, Card, Col, Row, Statistic, Table } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { IndexNotice, RequestError, Status } from '../components';
import { useResource } from '../hooks';
import type { Overview as OverviewData, Parent } from '../types';
export default function Overview() {
  const data = useResource<OverviewData>('/api/overview', {}, 10000);
  const stats = data.data?.accounts;
  return <div className="page-stack">
    <RequestError value={data.error} /><IndexNotice value={data.data?.index} />
    <Row gutter={[14, 14]}>{[['账号总数', 'total'], ['Codex 已授权', 'codex_connected'], ['2FA 已接入', 'totp_active'], ['额度已查询', 'quota_checked']].map(([title, key]) => <Col xs={12} lg={6} key={key}><Card className="metric-card"><Statistic title={title} value={stats?.[key] ?? '—'} /></Card></Col>)}</Row>
    <Card className="data-card" title="母号概览" extra={<Button icon={<ReloadOutlined />} onClick={data.reload} loading={data.loading}>刷新</Button>}><Table<Parent> size="middle" rowKey="id" scroll={{ x: 680 }} pagination={{ pageSize: 10, showSizeChanger: false, hideOnSinglePage: true }} dataSource={data.data?.parents || []} columns={[{ title: '母号', dataIndex: 'email', ellipsis: true }, { title: '状态', dataIndex: 'status', width: 110, render: (value) => <Status value={value} /> }, { title: '工作区', dataIndex: 'workspace_count', width: 90 }, { title: '更新时间', dataIndex: 'updated_at', width: 185 }]} /></Card>
  </div>;
}
