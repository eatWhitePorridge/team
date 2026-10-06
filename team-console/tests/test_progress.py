import asyncio
import json
import threading
import time
import unittest
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

from flask import Flask
from backend.asgi import ConsoleASGI
from backend.progress import ProgressFeed, collect_jobs, difference, event_frame
from core import progress_events


def fixtures():
    row = {'id': 'pipeline-one', 'batch_id': 'batch', 'status': 'running',
           'stage': 'codex_waiting', 'codex_job_id': 41, 'account_id': 1,
           'password': 'PRIVATE', 'access_token': 'PRIVATE', 'totp_secret': 'PRIVATE'}
    batch = {'batch_id': 'batch', 'active': 1, 'total': 1, 'finished': 0, 'completed': False, 'team_authorization': False}
    services = SimpleNamespace(
        completion=SimpleNamespace(progress_snapshot=Mock(return_value={'pipeline': [row], 'authorization': [batch]}), _WAKE=threading.Event()),
        db=SimpleNamespace(account_completion_snapshot=Mock(return_value={'jobs': {41: {'id': 41, 'status': 'running'}}})),
        team_store=SimpleNamespace(list_parents=Mock(return_value=[])),
        authorization=SimpleNamespace(executor_status=Mock(return_value={'workers': 100, 'running': 1, 'queued': 0})),
    )
    return services


class ProgressTests(unittest.TestCase):
    def test_phase_is_visible_before_authorization_finishes_and_has_no_credentials(self):
        services = fixtures()
        snapshot = collect_jobs(services, {41: {'stage': 'mfa', 'updated_at': 'fixture-time'}})
        row = snapshot['pipeline'][0]
        self.assertEqual(row['progress_stage'], 'mfa')
        self.assertEqual(row['progress_message'], '验证 2FA')
        self.assertEqual(row['status'], 'running')
        self.assertEqual(snapshot['authorization'][0]['finished'], 0)
        self.assertEqual(snapshot['authorization'][0]['running'], 1)
        self.assertNotIn('PRIVATE', json.dumps(snapshot))
        services.db.account_completion_snapshot.assert_called_once_with([], [41])

    def test_terminal_child_is_not_false_team_success_until_coordinator_confirms(self):
        services = fixtures()
        services.db.account_completion_snapshot.return_value['jobs'][41]['status'] = 'success'
        snapshot = collect_jobs(services, {41: {'stage': 'save_credential'}})
        self.assertEqual(snapshot['pipeline'][0]['progress_status'], 'confirming')
        self.assertEqual(snapshot['authorization'][0]['finished'], 0)
        self.assertEqual(snapshot['authorization'][0]['confirming'], 1)
        services.completion.progress_snapshot.return_value['pipeline'][0].update(status='success')
        self.assertNotIn('progress_status', collect_jobs(services)['pipeline'][0])

    def test_retry_gap_does_not_reuse_old_phase_and_pending_is_not_running(self):
        services = fixtures()
        row = services.completion.progress_snapshot.return_value['pipeline'][0]
        row.update(stage='codex_pending', codex_job_id=None, codex_attempt_count=1)
        self.assertEqual(collect_jobs(services, {41: {'stage': 'mfa'}})['pipeline'][0]['progress_status'], 'retrying')
        row.update(codex_attempt_count=0)
        self.assertEqual(collect_jobs(services)['pipeline'][0]['progress_status'], 'queued')

    def test_feed_notifications_are_coalesced_and_wake_coordinator_without_json_reads_in_worker(self):
        services = fixtures()
        feed = ProgressFeed(services, coalesce=0.02, reconcile=60)
        feed.start(); self.addCleanup(feed.stop)
        deadline = time.monotonic() + 2
        while feed.current()[1] is None and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertIsNotNone(feed.current()[1])
        with progress_events.job_context(41):
            for _ in range(100): progress_events.phase('password')
            progress_events.phase('mfa')
        progress_events.notify('job', 41)
        self.assertTrue(services.completion._WAKE.is_set())
        start = time.monotonic()
        while time.monotonic() - start < 1:
            if feed.current()[1]['pipeline'][0].get('progress_stage') == 'mfa': break
            time.sleep(0.005)
        self.assertEqual(feed.current()[1]['pipeline'][0]['progress_stage'], 'mfa')
        self.assertLess(time.monotonic() - start, 1)
        self.assertLess(services.completion.progress_snapshot.call_count, 10)

    def test_contexts_are_isolated_and_broken_observers_do_not_change_business(self):
        received = []
        unsubscribe = progress_events.subscribe(lambda *args: received.append(args))
        broken = progress_events.subscribe(lambda *args: 1 / 0)
        self.addCleanup(unsubscribe); self.addCleanup(broken)
        def run(ident):
            with progress_events.job_context(ident): progress_events.phase('password')
        threads = [threading.Thread(target=run, args=(n,)) for n in range(1, 101)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual({row[1] for row in received}, set(range(1, 101)))
        progress_events.phase('mfa')  # Outside a job has no identity; never leaks the last task.
        progress_events.notify('phase', 1, 'PRIVATE')
        self.assertEqual(len(received), 100)

    def test_delta_only_contains_changed_rows_and_handles_removal_order(self):
        before = collect_jobs(fixtures())
        after = deepcopy(before)
        after['pipeline'][0]['progress_stage'] = 'mfa'
        delta = difference(before, after)
        self.assertEqual(set(delta), {'pipeline'})
        self.assertEqual(len(delta['pipeline']['upsert']), 1)
        after['pipeline'] = []
        delta = difference(before, after)
        self.assertEqual(delta['pipeline']['remove'], ['pipeline-one'])
        self.assertEqual(delta['pipeline']['order'], [])
        self.assertEqual(difference(before, before), {})
        encoded = event_frame('snapshot', {'data': '中文\n多行'})
        self.assertEqual(encoded.count(b'\ndata:'), 1)
        self.assertTrue(encoded.endswith(b'\n\n'))

    def test_old_active_rows_are_not_hidden_by_new_history(self):
        from unittest.mock import patch
        from core import account_completion_service as completion
        rows = [{'id': 'old-active', 'status': 'running', 'codex_job_id': 41, 'password': 'PRIVATE'}]
        rows.extend({'id': 'done-' + str(n), 'status': 'success'} for n in range(6000))
        with patch.object(completion, '_read_rows', return_value=rows):
            result = completion.progress_snapshot()
        self.assertEqual(result['pipeline'][0]['id'], 'old-active')
        self.assertEqual(len(result['pipeline']), 101)
        self.assertNotIn('PRIVATE', json.dumps(result))


class StreamTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.services = fixtures()
        self.feed = ProgressFeed(self.services)
        self.feed.refresh()
        self.app = Flask(__name__)
        self.app.config['TEAM_CONSOLE_API_KEY'] = 'fixture-key'
        self.app.extensions['team_console'] = {'progress': self.feed}
        self.app.add_url_rule('/probe', view_func=lambda: {'ok': True})
        self.gateway = ConsoleASGI(self.app, threads=2, heartbeat=0.04, send_timeout=0.06, max_streams=32)
        self.tasks = []

    async def asyncTearDown(self):
        for task, incoming in self.tasks:
            if not task.done(): incoming.put_nowait({'type': 'http.disconnect'})
        await asyncio.gather(*(task for task, _ in self.tasks), return_exceptions=True)
        self.feed.stop()
        self.gateway.wsgi.executor.shutdown(wait=True)
        self.assertEqual(len(self.feed._clients), 0)

    async def request(self, *, key='fixture-key', path='/api/jobs/events', method='GET', **extras):
        incoming, outgoing = asyncio.Queue(), asyncio.Queue()
        incoming.put_nowait({'type': 'http.request', 'body': b'', 'more_body': False})
        scope = {'type': 'http', 'method': method, 'path': path, 'headers': [(b'x-team-console-key', key.encode())],
                 'query_string': b'', 'http_version': '1.1', 'scheme': 'http', 'server': ('localhost', 5050), **extras}
        task = asyncio.create_task(self.gateway(scope, incoming.get, outgoing.put))
        self.tasks.append((task, incoming))
        start = await asyncio.wait_for(outgoing.get(), 1)
        return start, incoming, outgoing, task

    async def frame(self, outgoing):
        while True:
            body = (await asyncio.wait_for(outgoing.get(), 1)).get('body', b'')
            if body.startswith(b'event:'):
                kind, data = body.decode().strip().split('\n', 1)
                return kind[7:], json.loads(data[6:])

    async def test_authentication_no_query_credentials_and_no_mutations(self):
        for key in ('', 'wrong'):
            start, _, _, task = await self.request(key=key, query_string=b'key=fixture-key')
            self.assertEqual(start['status'], 401); await task
        start, _, _, task = await self.request(method='POST')
        self.assertEqual(start['status'], 405); await task
        self.app.config['TEAM_CONSOLE_API_KEY'] = ''
        start, _, _, task = await self.request(key='')
        self.assertEqual(start['status'], 401); await task
        self.assertEqual(len(self.feed._clients), 0)

    async def test_initial_snapshot_delta_reconnect_and_key_invalidation(self):
        start, incoming, outgoing, task = await self.request()
        self.assertEqual(start['status'], 200)
        self.assertIn((b'x-accel-buffering', b'no'), start['headers'])
        kind, first = await self.frame(outgoing)
        self.assertEqual(kind, 'snapshot')
        self.feed.changed('phase', 41, 'mfa'); self.feed.refresh()
        kind, update = await self.frame(outgoing)
        self.assertEqual(kind, 'update')
        self.assertEqual(update['base'], first['version'])
        self.assertEqual(update['delta']['pipeline']['upsert'][0]['progress_stage'], 'mfa')
        self.assertNotIn('PRIVATE', json.dumps(update))
        incoming.put_nowait({'type': 'http.disconnect'}); await task
        _, _, resumed, _ = await self.request()
        kind, snapshot = await self.frame(resumed)
        self.assertEqual(kind, 'snapshot')
        self.assertEqual(snapshot['version'], update['version'])
        self.app.config['TEAM_CONSOLE_API_KEY'] = 'rotated'
        kind, _ = await self.frame(resumed)
        self.assertEqual(kind, 'access_expired')

    async def test_more_sse_connections_than_http_threads_do_not_starve_api(self):
        for _ in range(24):
            start, _, outgoing, _ = await self.request()
            self.assertEqual(start['status'], 200)
            await self.frame(outgoing)
        self.assertEqual(len(self.gateway.wsgi.executor._threads), 0)
        start, _, outgoing, task = await self.request(path='/probe')
        self.assertEqual(start['status'], 200)
        self.assertIn(b'"ok":true', (await asyncio.wait_for(outgoing.get(), 1))['body'])
        await task
        self.assertLessEqual(len(self.gateway.wsgi.executor._threads), 2)

    async def test_connection_capacity_and_disconnection_release(self):
        self.gateway.max_streams = 1
        _, incoming, outgoing, task = await self.request(); await self.frame(outgoing)
        start, _, _, rejected = await self.request()
        self.assertEqual(start['status'], 503); await rejected
        incoming.put_nowait({'type': 'http.disconnect'}); await task
        start, _, outgoing, _ = await self.request()
        self.assertEqual(start['status'], 200); await self.frame(outgoing)

    async def test_snapshot_failure_is_signalled_instead_of_pretending_freshness(self):
        _, _, outgoing, _ = await self.request(); await self.frame(outgoing)
        self.feed._error = True; self.feed._signal_clients()
        kind, _ = await self.frame(outgoing)
        self.assertEqual(kind, 'unavailable')

    async def test_bounded_send_timeout_reclaims_slow_connection(self):
        incoming = asyncio.Queue()
        incoming.put_nowait({'type': 'http.request', 'body': b''})
        async def slow_send(message):
            if message['type'] == 'http.response.body': await asyncio.Future()
        scope = {'type': 'http', 'method': 'GET', 'path': '/api/jobs/events',
                 'headers': [(b'x-team-console-key', b'fixture-key')]}
        task = asyncio.create_task(self.gateway(scope, incoming.get, slow_send))
        self.tasks.append((task, incoming))
        await asyncio.wait_for(task, 1)
        self.assertEqual(len(self.feed._clients), 0)
