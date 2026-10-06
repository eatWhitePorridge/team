"""One coalescing reader for all clients; business threads only signal changes."""
from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timezone

ACTIVE = {'queued', 'running', 'retrying'}
JOB_FIELDS = frozenset('id batch_id batch_total account_id email status stage message error created_at updated_at completed_at expected_workspace_id source_job_id login_mode codex_plan_type team_authorization codex_attempt_count codex_max_attempts codex_job_id parent_email parent_id kind total completed cancel_requested concurrency running'.split())
logger = logging.getLogger(__name__)


def _pipeline_progress(services, rows, phases=None):
    from core.progress_events import PHASES
    pipeline = [{k: v for k, v in row.items() if k in JOB_FIELDS} for row in rows]
    job_ids = [row['codex_job_id'] for row in pipeline if row.get('status') in ACTIVE and row.get('codex_job_id')]
    # Empty account selection avoids reading the large account JSON entirely.
    states = services.db.account_completion_snapshot([], job_ids)['jobs'] if job_ids else {}
    counts = {}
    for row in pipeline:
        if row.get('status') not in ACTIVE:
            continue
        job_id = row.get('codex_job_id')
        state = states.get(job_id, {}).get('status')
        phase = (phases or {}).get(job_id, {})
        stage = phase.get('stage') if state == 'running' else None
        if state in {'success', 'failed', 'stopped', 'cancelled'}:
            status, message = 'confirming', '本次执行已结束，正在确认结果'
        elif stage == 'retrying' or (row.get('stage') == 'codex_pending' and row.get('codex_attempt_count')):
            status, message = 'retrying', '等待下一次授权尝试'
        elif state == 'running':
            status, message = 'running', PHASES.get(stage, '正在执行授权')
        else:
            status, message = 'queued', '等待执行槽位'
        row.update(progress_status=status, progress_stage=stage or status, progress_message=message)
        if stage and phase.get('updated_at'):
            row['progress_updated_at'] = phase['updated_at']
        counter = counts.setdefault(row.get('batch_id'), Counter())
        counter[status] += 1
    return pipeline, counts


def collect_jobs(services, phases=None):
    snapshot = getattr(services.completion, 'progress_snapshot', None)
    data = snapshot(batch_limit=20) if callable(snapshot) else {
        'pipeline': services.completion.list_items(limit=5000),
        'authorization': services.completion.list_authorization_batches(limit=20)}
    pipeline, counts = _pipeline_progress(services, data['pipeline'], phases)
    batches = [{**row, **{key: counts.get(row['batch_id'], {}).get(key, 0)
                         for key in ('queued', 'running', 'retrying', 'confirming')}}
               for row in data['authorization'] if row.get('batch_id')]
    # Preserve old/mock summaries without identifiers for compatibility.
    batches.extend(row for row in data['authorization'] if not row.get('batch_id'))
    team = []
    for parent in services.team_store.list_parents():
        for item in services.team_store.recent_jobs(parent['id']):
            team.append({**{k: v for k, v in item.items() if k in JOB_FIELDS}, 'parent_email': parent.get('email')})
    team.sort(key=lambda row: (row.get('status') in ACTIVE, row.get('created_at') or ''), reverse=True)
    return {'pipeline': pipeline, 'authorization': batches, 'team': team[:100],
            'runtime': services.authorization.executor_status()}


def authorization_detail(services, batch_id, phases=None):
    """Separate read path so old accounts do not disappear behind the global SSE window."""
    data = services.completion.authorization_batch_detail(batch_id)
    if data is None:
        return None
    items, counts = _pipeline_progress(services, data['items'], phases)
    batch = {**data['batch'], **{key: counts.get(batch_id, {}).get(key, 0)
                               for key in ('queued', 'running', 'retrying', 'confirming')}}
    return {'batch': batch, 'items': items, 'total': len(items)}


def difference(before, after):
    """Only changed rows cross the wire; ordering and removals remain explicit."""
    delta = {}
    for key in ('pipeline', 'team'):
        old = {row['id']: row for row in before[key]}
        new = {row['id']: row for row in after[key]}
        upsert = [row for ident, row in new.items() if old.get(ident) != row]
        remove = [ident for ident in old if ident not in new]
        order = list(new)
        if upsert or remove or list(old) != order:
            delta[key] = {'upsert': upsert, 'remove': remove, 'order': order}
    for key in ('authorization', 'runtime'):
        if before.get(key) != after.get(key):
            delta[key] = after.get(key)
    return delta


def event_frame(event, data):
    return ('event: ' + event + '\ndata: ' + json.dumps(data, ensure_ascii=False, separators=(',', ':')) + '\n\n').encode()


class ProgressFeed:
    def __init__(self, services, *, coalesce=0.15, reconcile=30.0):
        self.services = services
        self.coalesce, self.reconcile = coalesce, reconcile
        self.epoch = uuid.uuid4().hex
        self._lock = threading.RLock()
        self._wake, self._stop = threading.Event(), threading.Event()
        self._thread = None
        self._unsubscribe = None
        self._phases = {}
        self._clients = {}
        self._snapshot = None
        self._version = 0
        self._error = False

    def changed(self, topic, job_id=None, phase=None):
        if topic == 'phase':
            with self._lock:
                self._phases[job_id] = {'stage': phase, 'updated_at': datetime.now(timezone.utc).isoformat(timespec='milliseconds')}
                while len(self._phases) > 5000:
                    self._phases.pop(next(iter(self._phases)))
        if topic == 'job':
            wake = getattr(self.services.completion, '_WAKE', None)
            if wake is not None:
                wake.set()  # Observe a committed child result without the 1s sleep.
        self._wake.set()

    def start(self):
        from core.progress_events import subscribe
        with self._lock:
            if self._thread is not None:
                return
            self._unsubscribe = subscribe(self.changed)
            self._thread = threading.Thread(target=self._run, name='progress-feed', daemon=True)
            self._wake.set()
            self._thread.start()

    def stop(self):
        if self._unsubscribe:
            self._unsubscribe()
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _signal_clients(self):
        with self._lock:
            clients = list(self._clients.values())
        for loop, event in clients:
            try:
                loop.call_soon_threadsafe(event.set)
            except RuntimeError:
                pass

    def refresh(self):
        with self._lock:
            phases = dict(self._phases)
        snapshot = collect_jobs(self.services, phases)
        with self._lock:
            changed = snapshot != self._snapshot or self._error
            self._error = False
            if changed:
                self._snapshot = snapshot
                self._version += 1
        if changed:
            self._signal_clients()
        return snapshot

    def _run(self):
        last = 0.0
        failures = 0
        while not self._stop.is_set():
            self._wake.wait(min(30, 2 ** min(failures - 1, 5)) if failures else self.reconcile)
            self._wake.clear()
            if self._stop.wait(max(0, last + self.coalesce - time.monotonic())):
                return
            try:
                self.refresh()
                failures = 0
            except Exception:
                failures += 1
                logger.warning('[Progress] 状态快照读取失败，等待恢复')
                with self._lock:
                    self._error = True
                self._signal_clients()
            last = time.monotonic()

    def current(self):
        with self._lock:
            return self._version, self._snapshot, self._error

    def phases(self):
        with self._lock:
            return dict(self._phases)

    def subscribe(self, *, limit=64):
        # Called on the ASGI event loop. One Event per connection, not a queue
        # of snapshots: slow readers keep only the newest authoritative state.
        with self._lock:
            if len(self._clients) >= limit:
                return None
            event = asyncio.Event()
            token = object()
            self._clients[token] = (asyncio.get_running_loop(), event)
        self._wake.set()  # Reconnect/manual refresh also reconciles external edits.
        return token, event

    def unsubscribe(self, token):
        with self._lock:
            self._clients.pop(token, None)
