import { lazy, Suspense, useState } from 'react';
import { Badge, Button, Dropdown, Layout, Menu, Space, Spin, Tooltip, Typography } from 'antd';
import { ApartmentOutlined, CheckCircleOutlined, DashboardOutlined, DatabaseOutlined, LogoutOutlined, MenuFoldOutlined, MenuUnfoldOutlined, SettingOutlined, TeamOutlined } from '@ant-design/icons';
import AccessGate from './AccessGate';
import { AuthorizationSummary, RequestError } from './components';
import { useResource } from './hooks';
import type { Jobs as JobsData } from './types';

const Overview = lazy(() => import('./pages/Overview'));
const Accounts = lazy(() => import('./pages/Accounts'));
const Batches = lazy(() => import('./pages/Batches'));
const Team = lazy(() => import('./pages/Team'));
const Jobs = lazy(() => import('./pages/Jobs'));
const Network = lazy(() => import('./pages/Network'));
type View = 'overview' | 'accounts' | 'batches' | 'team' | 'jobs' | 'network';
const items = [
  { key: 'overview', label: '总览', icon: <DashboardOutlined /> },
  { key: 'accounts', label: '账号', icon: <TeamOutlined /> },
  { key: 'batches', label: '批次', icon: <DatabaseOutlined /> },
  { key: 'team', label: '母号管理', icon: <ApartmentOutlined /> },
  { key: 'jobs', label: '任务中心', icon: <CheckCircleOutlined /> },
  { key: 'network', label: '网络代理', icon: <SettingOutlined /> },
];
export default function App() {
  const [variant, setVariant] = useState(localStorage.getItem('team-console-ui') || 'classic');
  return <AccessGate>{(logout) => <Console variant={variant} toggleVariant={() => { const next = variant === 'classic' ? 'workspace' : 'classic'; setVariant(next); localStorage.setItem('team-console-ui', next); }} logout={logout} />}</AccessGate>;
}
function Console({ variant, toggleVariant, logout }: { variant: string; toggleVariant: () => void; logout: () => void }) {
  const [view, setView] = useState<View>('overview');
  const [accountBatch, setAccountBatch] = useState('');
  const [collapsed, setCollapsed] = useState(false);
  const jobs = useResource<JobsData>('/api/jobs', {}, 5000);
  const active = jobs.data?.authorization.filter((row) => row.active > 0) || [];
  const activeCount = active.reduce((sum, row) => sum + row.active, 0) + (jobs.data?.team.filter((row) => ['queued', 'running'].includes(row.status || '')).length || 0);
  return <Layout className={'console-layout ' + (variant === 'workspace' ? 'workspace-layout' : '')}>
    <Layout.Sider breakpoint="lg" collapsedWidth={60} collapsed={collapsed} onBreakpoint={setCollapsed} className="console-sider">
      <div className="brand"><span className="brand-mark">T</span>{!collapsed && <span>Team Console</span>}</div>
      <Menu mode="inline" selectedKeys={[view]} items={items} onClick={({ key }) => { if (key === 'accounts') setAccountBatch(''); setView(key as View); }} />
    </Layout.Sider>
    <Layout>
      <Layout.Header className="console-header">
        <Button type="text" aria-label="展开或收起导航" icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} onClick={() => setCollapsed(!collapsed)} />
        <Space size={12}>
          <Tooltip title={jobs.error ? '连接异常' : jobs.data ? '服务已连接' : '正在连接'}><span className="connection-dot" aria-label={jobs.error ? '连接异常' : jobs.data ? '服务已连接' : '正在连接'}><Badge status={jobs.error ? 'error' : jobs.data ? 'success' : 'processing'} /></span></Tooltip>
          <Badge count={activeCount} size="small"><Button type="text" onClick={() => setView('jobs')}>任务中心</Button></Badge>
          <Dropdown trigger={['click']} menu={{ items: [
            { key: 'style', icon: <SettingOutlined />, label: variant === 'classic' ? '切换工作台样式' : '切换浅色样式', onClick: toggleVariant },
            { type: 'divider' }, { key: 'logout', icon: <LogoutOutlined />, label: '退出登录', onClick: logout },
          ] }}><Button type="text" aria-label="界面设置与退出登录" icon={<SettingOutlined />} /></Dropdown>
        </Space>
      </Layout.Header>
      <Layout.Content className="console-content">
        <div className="page-heading"><Typography.Title level={2}>{items.find((item) => item.key === view)?.label}</Typography.Title>
          {jobs.data?.runtime && ['accounts', 'jobs'].includes(view) && <Tooltip title={'普通 / Team 授权共享执行槽；池内排队不计入执行数。峰值 ' + jobs.data.runtime.peak_running}><Typography.Text className="muted tabular">执行 {jobs.data.runtime.running}/{jobs.data.runtime.workers} · 排队 {jobs.data.runtime.queued}</Typography.Text></Tooltip>}
        </div>
        <RequestError value={jobs.error} />
        {!!active.length && view !== 'jobs' && <AuthorizationSummary batches={active} onOpen={() => setView('jobs')} />}
        <Suspense fallback={<div className="page-loading"><Spin /></div>}>
          {view === 'overview' && <Overview />}
          {view === 'accounts' && <Accounts key={accountBatch} initialBatchId={accountBatch} onJobsChanged={jobs.reload} />}
          {view === 'batches' && <Batches onJobsChanged={jobs.reload} onViewAccounts={(batchId) => { setAccountBatch(batchId); setView('accounts'); }} />}
          {view === 'team' && <Team onJobsChanged={jobs.reload} />}
          {view === 'jobs' && <Jobs data={jobs.data} loading={jobs.loading} error={jobs.error} reload={jobs.reload} />}
          {view === 'network' && <Network />}
        </Suspense>
      </Layout.Content>
    </Layout>
  </Layout>;
}
