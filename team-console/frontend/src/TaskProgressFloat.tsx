import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { Badge, Button, Empty, Progress, Spin, Tooltip, Typography } from 'antd';
import { ApartmentOutlined, ArrowRightOutlined, CheckCircleOutlined, DownOutlined, MinusOutlined, ReloadOutlined, ThunderboltOutlined, UnorderedListOutlined, UpOutlined } from '@ant-design/icons';
import { Status } from './components';
import { floatingTaskModel, floatingTaskProgress, toggleFloatingTask } from './floatingProgress';
import { findJob, jobKey } from './jobProgress';
import { authorizationCounts } from './taskHierarchy';
import { useIsMobile } from './useResponsive';
import type { JobRow } from './jobProgress';
import type { Jobs } from './types';
import type { ProgressTransport } from './liveJobs';

const TaskAuthorizationExpansion = lazy(() => import('./TaskAuthorizationExpansion'));
const FLOAT_PREFERENCE = 'team-console-task-float';
function savedExpansion(): boolean | null {
  try {
    const value = sessionStorage.getItem(FLOAT_PREFERENCE);
    return value === 'open' ? true : value === 'closed' ? false : null;
  } catch { return null; }
}

export default function TaskProgressFloat({ data, transport, error, loading, onOpenJobs, onResync }: {
  data?: Jobs; transport: ProgressTransport; error?: string; loading: boolean;
  onOpenJobs: () => void; onResync: () => void;
}) {
  const mobile = useIsMobile();
  const [expanded, setExpanded] = useState<boolean | null>(savedExpansion);
  const [detailKey, setDetailKey] = useState<string>();
  const model = useMemo(() => floatingTaskModel(data, 3, detailKey), [data?.authorization, data?.team, detailKey]);
  const trigger = useRef<HTMLButtonElement>(null), minimize = useRef<HTMLButtonElement>(null);
  const pendingFocus = useRef<'launcher' | 'panel' | null>(null);
  useEffect(() => {
    if (expanded === null && model.activeCount > 0 && !mobile) setExpanded(true);
  }, [expanded, model.activeCount, mobile]);
  useEffect(() => {
    if (expanded && pendingFocus.current === 'panel') minimize.current?.focus();
    if (!expanded && pendingFocus.current === 'launcher') trigger.current?.focus();
    pendingFocus.current = null;
  }, [expanded]);
  useEffect(() => {
    if (data && detailKey && !findJob(model.tasks, detailKey)) setDetailKey(undefined);
  }, [data, detailKey, model.tasks]);
  const changeExpansion = (open: boolean) => {
    pendingFocus.current = open ? 'panel' : 'launcher';
    setExpanded(open);
    try { sessionStorage.setItem(FLOAT_PREFERENCE, open ? 'open' : 'closed'); } catch { /* Optional preference only. */ }
  };
  const focus = findJob(model.tasks, detailKey) || model.rows[0];
  const focusProgress = focus ? floatingTaskProgress(focus) : undefined;
  const runtime = data?.runtime;
  const connection = error ? '连接异常' : transport === 'live' ? '实时' : transport === 'fallback' ? '重连中' : '连接中';
  const compactMetrics = <dl className="float-compact-metrics">
    <div><dt>授权执行</dt><dd>{runtime ? `${runtime.running}/${runtime.workers}` : '—'}</dd></div>
    <div><dt>排队账号</dt><dd>{runtime?.queued ?? '—'}</dd></div>
    <div><dt>进行中任务</dt><dd>{data ? model.activeCount : '—'}</dd></div>
  </dl>;
  const renderProgress = (row: JobRow) => {
    const progress = floatingTaskProgress(row);
    return progress.percent === undefined ? null : <div className="float-task-progress" aria-label={row.type + '已结束 ' + progress.finished + '/' + progress.total}>
      <Progress percent={progress.percent} status={progress.status} size="small" showInfo={false} />
      <span className="tabular">{progress.finished}/{progress.total}</span>
    </div>;
  };
  return <aside className={'task-float' + (expanded ? ' is-expanded' : '')} aria-label="全局任务进度">
    {!expanded ? <Button ref={trigger} className="task-float-trigger" icon={<UnorderedListOutlined />} aria-expanded={false} onClick={() => changeExpansion(true)}>
      {error ? '任务 · 连接异常' : model.activeCount ? `任务 · ${model.activeCount} 进行中` : '任务进度'}
    </Button> : <section id="global-task-panel" className="task-float-panel" aria-labelledby="global-task-title">
      <header className="task-float-heading">
        <div className="float-heading-title"><span className="float-heading-icon" aria-hidden="true"><UnorderedListOutlined /></span><h2 id="global-task-title">任务进度</h2></div>
        <div className="float-heading-actions"><Tooltip title={error ? '连接中断，显示上次进度' : transport === 'fallback' ? '正在重连，暂用轮询更新' : connection}><span className="float-connection"><Badge status={error ? 'error' : transport === 'live' ? 'success' : 'processing'} />{connection}</span></Tooltip>
          {(error || transport === 'fallback') && <Button type="text" aria-label="重新连接进度" icon={<ReloadOutlined />} onClick={onResync} />}
          <Button ref={minimize} type="text" aria-label="收起任务进度" aria-expanded={true} aria-controls="global-task-panel" icon={<MinusOutlined />} onClick={() => changeExpansion(false)} />
        </div>
      </header>
      <div className="task-float-scroll" tabIndex={0} aria-label="任务进度列表">
        <div className="float-summary-grid">
          <section className="bento-tile float-summary-primary tone-lime" aria-label="当前任务进度">
            <div className="tile-heading"><span className="tile-label">{focus?.type || '任务进度'}</span><span className="tile-icon" aria-hidden="true">{focus?.source === 'team' ? <ApartmentOutlined /> : <CheckCircleOutlined />}</span></div>
            <div className="float-primary-value tabular">{focusProgress?.percent ?? '—'}{focusProgress?.percent !== undefined && <span>%</span>}</div>
            <div className="float-primary-caption"><span>{focusProgress?.total ? `${focusProgress.finished}/${focusProgress.total} 已结束` : focus ? '等待进度' : loading ? '连接中' : '暂无任务'}</span>{focus && <Status value={focus.status} />}</div>
            <div className="float-mobile-metrics">{compactMetrics}</div>
          </section>
          <section className="bento-tile float-summary-pool" aria-label="授权执行池">
            <div className="tile-heading"><span className="tile-label">授权执行</span><span className="tile-icon" aria-hidden="true"><ThunderboltOutlined /></span></div>
            <div className="float-pool-value tabular"><strong>{runtime?.running ?? '—'}</strong><span>/ {runtime?.workers ?? '—'}</span></div>
            <div className="float-tablet-metrics">{compactMetrics}</div>
          </section>
          <section className="bento-tile float-summary-mini" aria-label="进行中任务数"><span className="tile-label">进行中任务</span><strong className="tabular">{data ? model.activeCount : '—'}</strong></section>
          <section className="bento-tile float-summary-mini" aria-label="排队账号数"><span className="tile-label">排队账号</span><strong className="tabular">{runtime?.queued ?? '—'}</strong></section>
        </div>
        <section className="float-task-list-panel" aria-label="可展开的任务">
          <div className="float-list-heading"><h3>任务列表</h3><span className="muted">{model.activeCount ? `${model.activeCount} 个进行中` : '最近任务'}</span></div>
          {loading && !data ? <div className="task-float-empty" role="status"><Spin size="small" />加载任务…</div> : !model.rows.length ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={error ? '暂时无法读取任务' : '暂无任务'} /> : <ul className="float-task-list">{model.rows.map(row => {
            const key = jobKey(row), open = key === detailKey;
            const headingId = 'float-task-heading-' + encodeURIComponent(key), detailId = 'float-task-detail-' + encodeURIComponent(key);
            return <li key={key} className={open ? 'is-open' : undefined}>
              <div className="float-task-summary">
                <button id={headingId} type="button" className="float-task-toggle" aria-expanded={open} aria-controls={detailId} onClick={() => setDetailKey(current => toggleFloatingTask(current, key))}>
                  <span className="float-task-type-icon" aria-hidden="true">{row.source === 'team' ? <ApartmentOutlined /> : <CheckCircleOutlined />}</span>
                  <span className="float-task-identity"><strong>{row.type}</strong><span>{row.authorization_batch ? `${row.total} 个账号 · ${row.id.slice(0, 8)}` : row.parent_email || row.id.slice(0, 8)}</span></span>
                  <span className="float-task-expand-label">{open ? '收起' : '展开'}{open ? <UpOutlined aria-hidden="true" /> : <DownOutlined aria-hidden="true" />}</span>
                </button>
                <div className="float-task-result"><Status value={row.status} />{row.authorization_batch && <span>{authorizationCounts(row.authorization_batch)}</span>}</div>
                {renderProgress(row)}
                {!!row.authorization_batch?.active && <p className="float-task-message">{row.message}</p>}
                {!open && !row.authorization_batch && <p className="float-task-message">{row.error || row.message || row.stage || '—'}</p>}
              </div>
              <div id={detailId} className="float-task-expansion" role="region" aria-labelledby={headingId} hidden={!open}>
                {open && (row.authorization_batch ? <Suspense fallback={<div className="task-float-empty" role="status"><Spin size="small" />加载账号明细…</div>}><TaskAuthorizationExpansion key={key} batchId={row.id} summary={row.authorization_batch} pipeline={data?.pipeline || []} /></Suspense> : <>
                  <p className="float-operation-message">{row.error || row.message || row.stage || '暂无更多信息'}</p>
                  {row.error && row.message && row.error !== row.message && <p className="float-operation-message">{row.message}</p>}
                  <dl className="float-operation-meta"><dt>阶段</dt><dd>{row.stage || row.kind || '—'}</dd><dt>更新</dt><dd>{row.updated_at || '—'}</dd>{row.cancel_requested && <><dt>取消</dt><dd>正在停止后续操作</dd></>}</dl>
                </>)}
                {open && <div className="float-detail-id"><span>任务 ID</span><Typography.Text copyable>{row.id}</Typography.Text></div>}
              </div>
            </li>;
          })}</ul>}
        </section>
      </div>
      <footer className="task-float-footer"><Button type="text" icon={<ArrowRightOutlined />} onClick={() => { changeExpansion(false); onOpenJobs(); }}>打开任务中心</Button></footer>
    </section>}
  </aside>;
}
