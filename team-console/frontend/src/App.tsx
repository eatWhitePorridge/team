import { lazy, memo, Suspense, useCallback, useEffect, useState } from 'react';
import { Badge, Button, Drawer, Spin, Tooltip } from 'antd';
import { ApartmentOutlined, ArrowUpOutlined, CheckCircleOutlined, DashboardOutlined, DatabaseOutlined, LogoutOutlined, MenuOutlined, SettingOutlined, TeamOutlined } from '@ant-design/icons';
import AccessGate from './AccessGate';
import { Brand } from './Bento';
import { RequestError } from './components';
import TaskProgressFloat from './TaskProgressFloat';
import { useJobs } from './useJobs';
import { useIsMobile } from './useResponsive';
import type { ChildAccountScope } from './childAccounts';

const Overview = memo(lazy(() => import('./pages/Overview')));
const Accounts = memo(lazy(() => import('./pages/Accounts')));
const Batches = memo(lazy(() => import('./pages/Batches')));
const Team = memo(lazy(() => import('./pages/Team')));
const Jobs = lazy(() => import('./pages/Jobs'));
const Network = memo(lazy(() => import('./pages/Network')));
export type View = 'overview' | 'accounts' | 'batches' | 'team' | 'jobs' | 'network';
const items = [
  { key: 'overview', label: '工作台', icon: <DashboardOutlined /> },
  { key: 'accounts', label: '账号管理', icon: <TeamOutlined /> },
  { key: 'batches', label: '批次管理', icon: <DatabaseOutlined /> },
  { key: 'team', label: '母号管理', icon: <ApartmentOutlined /> },
  { key: 'jobs', label: '任务中心', icon: <CheckCircleOutlined /> },
  { key: 'network', label: '网络代理', icon: <SettingOutlined /> },
] as const;
export default function App() {
  return <AccessGate>{logout => <Console logout={logout} />}</AccessGate>;
}
function Console({ logout }: { logout: () => void }) {
  const [view, setView] = useState<View>('overview');
  const [accountBatch, setAccountBatch] = useState('');
  const [accountTeam, setAccountTeam] = useState<ChildAccountScope>();
  const [teamTarget, setTeamTarget] = useState<ChildAccountScope>();
  const [navigationOpen, setNavigationOpen] = useState(false);
  const mobile = useIsMobile();
  useEffect(() => { if (!mobile) setNavigationOpen(false); }, [mobile]);
  const jobs = useJobs();
  const viewAccounts = useCallback((batchId: string) => { setAccountTeam(undefined); setAccountBatch(batchId); setView('accounts'); }, []);
  const viewChildren = useCallback((scope: ChildAccountScope) => { setAccountBatch(''); setAccountTeam(scope); setTeamTarget(scope); setView('accounts'); }, []);
  const navigate = useCallback((key: View) => { if (key === 'accounts') { setAccountBatch(''); setAccountTeam(undefined); } setView(key); setNavigationOpen(false); }, []);
  const clearTeamScope = useCallback(() => navigate('accounts'), [navigate]);
  const returnToTeam = useCallback(() => navigate('team'), [navigate]);
  const active = jobs.data?.authorization.filter(row => row.active > 0) || [];
  const activeCount = active.length + (jobs.data?.team.filter(row => ['queued', 'running'].includes(row.status || '')).length || 0);
  const title = items.find(item => item.key === view)?.label;
  const connection = jobs.error ? '连接异常' : jobs.transport === 'live' ? '实时连接' : jobs.transport === 'fallback' ? '轮询更新' : '连接中';
  const navigation = <nav className="main-navigation" aria-label="主导航">{items.map(item => <button key={item.key} type="button" className={'nav-item' + (view === item.key ? ' is-current' : '')} aria-current={view === item.key ? 'page' : undefined} onClick={() => navigate(item.key)}>
    <span className="nav-icon" aria-hidden="true">{item.icon}</span><span>{item.label}</span>{item.key === 'jobs' && activeCount > 0 && <span className="nav-count">{activeCount}</span>}
  </button>)}</nav>;
  return <div className="console-layout">
    <a className="skip-link" href="#main-content">跳到主要内容</a>
    {!mobile && <aside className="console-sidebar"><Brand />{navigation}<div className="sidebar-footer"><Button type="text" icon={<LogoutOutlined />} onClick={logout}>退出登录</Button></div></aside>}
    {mobile && <Drawer title={<Brand />} placement="left" width="min(320px, 88vw)" className="mobile-navigation" open={navigationOpen} onClose={() => setNavigationOpen(false)}>
      {navigation}<div className="sidebar-footer"><Button type="text" icon={<LogoutOutlined />} onClick={logout}>退出登录</Button></div>
    </Drawer>}
    <div className="console-main">
      <header className="console-header">
        <div className="header-leading">{mobile && <Button type="text" aria-label="打开导航菜单" aria-expanded={navigationOpen} icon={<MenuOutlined />} onClick={() => setNavigationOpen(true)} />}<h1 className="header-page-name">{title}</h1></div>
        <div className="header-actions"><Tooltip title={jobs.error ? '请检查网络连接' : connection}><span aria-label={connection} className={'connection-state' + (jobs.error ? ' has-error' : '')}><Badge status={jobs.error ? 'error' : jobs.transport === 'live' ? 'success' : 'processing'} /><span>{connection}</span></span></Tooltip>
          <Button className="header-task-button" icon={<CheckCircleOutlined />} onClick={() => navigate('jobs')}>任务{activeCount > 0 ? ' · ' + activeCount : ''}</Button>
        </div>
      </header>
      <main id="main-content" tabIndex={-1} className="console-content">
        {jobs.data?.runtime && ['accounts', 'jobs'].includes(view) && (jobs.data.runtime.running > 0 || jobs.data.runtime.queued > 0) && <div className="runtime-bar"><Tooltip title={'授权并发 ' + jobs.data.runtime.workers + ' · 峰值 ' + jobs.data.runtime.peak_running}><span className="runtime-status"><span className="status-dot" aria-hidden="true" />执行 <b>{jobs.data.runtime.running}/{jobs.data.runtime.workers}</b><span>排队 {jobs.data.runtime.queued}</span></span></Tooltip></div>}
        <RequestError value={jobs.error} />
        <Suspense fallback={<div className="page-loading" role="status"><Spin /><span>加载中…</span></div>}>
          {view === 'overview' && <Overview onNavigate={navigate} />}
          {view === 'accounts' && <Accounts key={JSON.stringify([accountBatch, accountTeam])} initialBatchId={accountBatch} teamScope={accountTeam} onClearTeam={clearTeamScope} onReturnTeam={returnToTeam} onJobsChanged={jobs.reload} />}
          {view === 'batches' && <Batches onJobsChanged={jobs.reload} onViewAccounts={viewAccounts} />}
          {view === 'team' && <Team onJobsChanged={jobs.reload} initialTarget={teamTarget} onViewChildren={viewChildren} />}
          {view === 'jobs' && <Jobs data={jobs.data} loading={jobs.loading} error={jobs.error} reload={jobs.resync} />}
          {view === 'network' && <Network />}
        </Suspense>
        <footer className="console-footer"><a href="#main-content" aria-label="返回主要内容顶部">顶部 <ArrowUpOutlined /></a></footer>
      </main>
    </div>
    <TaskProgressFloat data={jobs.data} transport={jobs.transport} error={jobs.error} loading={jobs.loading} onResync={jobs.resync} onOpenJobs={() => navigate('jobs')} />
  </div>;
}
