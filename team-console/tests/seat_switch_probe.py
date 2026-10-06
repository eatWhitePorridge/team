"""Real Flask routes, queue, SQLite, worker and progress projection; fake HTTP/clock.

No browser, UI test, business data or external mutation is involved.
"""
import copy
import json
import logging
import os
import threading
import unittest
import uuid
from contextlib import ExitStack
from datetime import datetime, timezone
from email.utils import format_datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch

assert os.environ['PYTHON_DOTENV_DISABLED'] == '1'
assert os.environ['TEAM_CONSOLE_DATA_DIR']
logging.disable(logging.CRITICAL)
from backend.services import load_services
services = load_services()
from backend.app import create_app
from backend.progress import collect_jobs, event_frame
from core import team_admin_service as s, team_account_switch as switch, progress_events
store = services.team_store
SPACE = 'fixture-workspace'
HEADERS = {'X-Team-Console-Key': 'fixture-key'}


def response(status=200, payload=None, headers=None):
    return SimpleNamespace(status_code=status, headers=headers or {},
                           json=Mock(return_value=payload if payload is not None else {'success': True}))


class BackoffTests(unittest.TestCase):
    def test_retry_after_seconds_and_http_date_are_not_capped(self):
        self.assertEqual(s._seat_rate_limit_wait({'Retry-After': '600'}, 1), 600)
        self.assertEqual(s._seat_rate_limit_wait({'retry-after': '45'}, 20), 45)
        now = 1800000000
        future = format_datetime(datetime.fromtimestamp(now + 900, timezone.utc), usegmt=True)
        with patch.object(s.time, 'time', return_value=now):
            self.assertEqual(s._seat_rate_limit_wait({'Retry-After': future}, 1), 900)
        self.assertEqual(s._seat_rate_limit_wait({'Retry-After': '0'}, 1), 10)

    def test_invalid_header_uses_bounded_exponential_wait_not_bounded_attempts(self):
        for header in [None, {}, {'Retry-After': 'invalid'}, {'Retry-After': '-5'},
                       {'Retry-After': 'nan'}, {'Retry-After': 'inf'}]:
            self.assertEqual([s._seat_rate_limit_wait(header, n) for n in [1, 2, 3, 100000]],
                             [60, 120, 180, 180])


class SeatFlowTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for target in ['requests.sessions.Session.request', 'curl_cffi.requests.Session.request']:
            self.stack.enter_context(patch(target, side_effect=AssertionError('external network forbidden')))
        for name, value in [('_EXECUTOR', Mock()), ('_SLOTS', threading.BoundedSemaphore(1)),
                            ('_WORKSPACE_LOCKS', {}), ('_SEAT_NEXT_AT', {}),
                            ('_SEAT_SWITCH_INTERVAL', .25), ('_SEAT_429_DEFAULT_WAIT', 1), ('_SEAT_429_MAX_WAIT', 3)]:
            self.stack.enter_context(patch.object(s, name, value))
        self.clock = 1000.0
        self.sleeps, self.calls, self.post_outcomes = [], [], []
        self.on_sleep = None
        self.stack.enter_context(patch.object(s.time, 'monotonic', side_effect=lambda: self.clock))
        self.stack.enter_context(patch.object(s.time, 'sleep', side_effect=self.sleep))
        from config import proxy
        self.stack.enter_context(patch.object(proxy, 'PROXY_POOL', ['socks5h://fixture-proxy.invalid:1080']))
        self.email = f'owner-{uuid.uuid4().hex}@example.invalid'
        self.parent = store.save_parent(self.email, {}, {'access_token': 'fixture-token'})
        self.workspace = {'id': SPACE, 'can_manage': True, 'role': 'account-owner',
                          'is_usage_based_seat_enabled': True, 'plan_type': 'team'}
        store.replace_workspaces(self.parent['id'], [self.workspace])
        self.members = [self.member(n) for n in range(1, 4)]
        self.env = SimpleNamespace(get=self.get, post=self.post, delete=self.delete,
            get_chatgpt_headers=lambda *a: {}, session=SimpleNamespace(close=Mock()))
        self.stack.enter_context(patch.object(s, 'BrowserSession', return_value=self.env))
        self.stack.enter_context(patch.object(s.TeamAdminClient, 'discover', return_value=[self.workspace]))
        self.app = create_app(services=services, api_key='fixture-key')
        self.client = self.app.test_client()
        self.url = f'/api/team-admin/parents/{self.parent["id"]}/jobs'
        self.events = []
        self.stack.callback(progress_events.subscribe(lambda *a: self.events.append(a)))

    @staticmethod
    def member(n):
        return {'id': f'user-fixture-{n}', 'email': f'member-{n}@example.invalid',
                'account_user_id': f'membership-{n}', 'role': 'standard-user', 'seat_type': 'usage_based'}

    def sleep(self, seconds):
        self.assertLessEqual(seconds, .25)
        self.sleeps.append(seconds)
        if self.on_sleep:
            self.on_sleep()
        self.clock += seconds

    def get(self, url, *, params=None, **kwargs):
        self.calls.append(('GET', url, copy.deepcopy(params), self.clock))
        self.assertTrue(url.endswith('/users'), 'Unexpected readback or endpoint')
        self.assertEqual(params['limit'], 100)
        offset = params['offset']
        return response(payload={'items': self.members[offset:offset + 100], 'total': len(self.members)})

    def post(self, url, *, json, **kwargs):
        self.calls.append(('POST', url, copy.deepcopy(json), self.clock))
        outcome = self.post_outcomes.pop(0) if self.post_outcomes else 200
        if isinstance(outcome, BaseException):
            raise outcome
        if isinstance(outcome, int):
            return response(outcome)
        return outcome

    def delete(self, url, **kwargs):
        self.calls.append(('DELETE', url, None, self.clock))
        return response(429)

    def enqueue(self, ids=None):
        response_ = self.client.post(self.url, headers=HEADERS, json={'kind': 'switch', 'workspace_id': SPACE,
            'seat_type': 'default', 'user_ids': ids or [row['id'] for row in self.members]})
        self.assertEqual(response_.status_code, 202, response_.get_json())
        return response_.get_json()['job']['id']

    def run_job(self, ids=None):
        ident = self.enqueue(ids)
        s._run(ident)
        return store.get_job(ident)

    def test_direct_api_accepts_201_and_larger_selections_without_a_count_cap(self):
        self.members = [self.member(n) for n in range(201)]
        job = self.run_job()
        self.assertEqual((job['status'], job['total'], job['completed']), ('success', 201, 201))
        self.assertEqual(len([c for c in self.calls if c[0] == 'POST']), 201)
        self.assertEqual([c[2]['offset'] for c in self.calls if c[0] == 'GET'], [0, 100, 200])
        self.assertFalse(any(c[0] == 'GET' for c in self.calls[3:]))
        with patch.object(s, '_enqueue_job', return_value={'id': 'fixture-large'}) as queued:
            for count in [631, 10001]:
                ids = [f'user-fixture-{i}' for i in range(count)]
                result = self.client.post(self.url, headers=HEADERS, json={
                    'kind': 'switch', 'workspace_id': SPACE, 'seat_type': 'default', 'user_ids': ids})
                self.assertEqual(result.status_code, 202)
                self.assertEqual(queued.call_args.args[3], ids)

    def test_repeated_429_only_retries_current_member_and_pushes_pending_progress(self):
        self.post_outcomes = [200] + [429] * 7 + [200, 200]
        job_id = self.enqueue()
        observed = []
        def inspect():
            snapshot = collect_jobs(services)
            row = next(r for r in snapshot['team'] if r['id'] == job_id)
            if 'HTTP 429' in row['message']:
                self.assertEqual((row['status'], row['completed'], row['total']), ('running', 1, 3))
                self.assertFalse(row['cancel_requested'])
                observed.append(row['message'])
                self.assertIn(b'429', event_frame('snapshot', snapshot))
                self.assertNotIn('fixture-token', json.dumps(snapshot))
        self.on_sleep = inspect
        s._run(job_id)
        job = store.get_job(job_id)
        self.assertEqual((job['status'], job['completed']), ('success', 3))
        posts = [c for c in self.calls if c[0] == 'POST']
        current = [c for c in posts if '/user-fixture-2/' in c[1]]
        self.assertEqual(len(posts), 10)
        self.assertEqual(len(current), 8)
        self.assertTrue(all(c[2] == current[0][2] for c in current))
        self.assertEqual([b[3] - a[3] for a, b in zip(current, current[1:])], [1, 2, 3, 3, 3, 3, 3])
        self.assertTrue(observed)
        self.assertTrue(any('第 7 次' in msg for msg in observed))
        self.assertTrue(any(e[0] == 'team' for e in self.events))
        self.assertFalse(any(c[0] == 'GET' for c in self.calls[1:]))

    def test_cancellation_during_429_wait_is_prompt_preserves_success_and_releases_slot(self):
        self.post_outcomes = [200, response(429, headers={'Retry-After': '600'})]
        ident = self.enqueue()
        cancelled = []
        def cancel():
            if cancelled or 'HTTP 429' not in store.get_job(ident)['message']:
                return
            before = self.clock
            result = self.client.post(f'/api/team-admin/jobs/{ident}/cancel', headers=HEADERS)
            self.assertEqual(result.status_code, 200)
            row = next(r for r in collect_jobs(services)['team'] if r['id'] == ident)
            self.assertTrue(row['cancel_requested'])
            cancelled.append(before)
        self.on_sleep = cancel
        s._run(ident)
        job = store.get_job(ident)
        self.assertEqual((job['status'], job['completed']), ('cancelled', 1))
        self.assertEqual(job['results'][0]['status'], 'success')
        self.assertLessEqual(self.clock - cancelled[0], .25)
        self.assertEqual(len([c for c in self.calls if c[0] == 'POST']), 2)
        self.assertFalse(s._WORKSPACE_LOCKS[SPACE].locked())
        self.on_sleep = None
        following = self.enqueue([self.members[-1]['id']])
        self.assertEqual(self.client.post(f'/api/team-admin/jobs/{following}/cancel', headers=HEADERS).status_code, 200)
        s._run(following)
        self.assertEqual(store.get_job(following)['status'], 'cancelled')
        self.assertEqual(self.client.post(f'/api/team-admin/jobs/{ident}/cancel', headers=HEADERS).status_code, 409)

    def test_other_write_errors_are_not_replayed(self):
        invalid_json = response()
        invalid_json.json.side_effect = ValueError('fixture non-json')
        for outcome in [400, 401, 403, 500, TimeoutError('fixture timeout'), invalid_json]:
            with self.subTest(outcome=type(outcome).__name__):
                self.calls = []
                self.post_outcomes = [outcome]
                job = self.run_job()
                self.assertEqual(job['status'], 'failed')
                self.assertEqual(job['completed'], 1)
                self.assertEqual(len([c for c in self.calls if c[0] == 'POST']), 1)

    def test_429_does_not_enable_retries_for_invites_or_removal(self):
        client = s.TeamAdminClient(self.parent)
        self.addCleanup(client.close)
        client.workspace_id = SPACE
        for method, path in [('POST', f'/backend-api/accounts/{SPACE}/invites'),
                             ('DELETE', f'/backend-api/accounts/{SPACE}/users/user-fixture-1')]:
            self.calls = []
            self.post_outcomes = [429]
            with self.assertRaises(s.RemoteError) as error:
                client.request(method, path, body={'email_addresses': ['fixture@example.invalid']})
            self.assertEqual(error.exception.http_status, 429)
            self.assertEqual(len(self.calls), 1)

    def test_read_retry_budget_remains_one_and_does_not_retry_get_429(self):
        client = s.TeamAdminClient(self.parent)
        self.addCleanup(client.close)
        for outcomes, succeeds, count in [([TimeoutError(), response()], True, 2),
                                         ([response(500), response(500)], False, 2),
                                         ([response(429)], False, 1)]:
            with patch.object(self.env, 'get', side_effect=outcomes) as read:
                if succeeds:
                    self.assertEqual(client.request('GET', '/fixture-read'), {'success': True})
                else:
                    with self.assertRaises(s.RemoteError):
                        client.request('GET', '/fixture-read')
                self.assertEqual(read.call_count, count)

    def test_account_and_batch_preview_over_5000_and_stale_identity_validation(self):
        accounts = [{'id': n, 'email': f'local-{n}@example.invalid'} for n in range(1, 5002)]
        def identity(account, workspace):
            self.assertEqual(workspace, SPACE)
            return {'user_id': f'user-fixture-{account["id"]}', 'membership_ids': [], 'plan_type': 'team'}
        with patch.object(services.db, 'get_team_removal_candidates', return_value=accounts), \
             patch.object(switch.removal, '_identity', side_effect=identity), \
             patch.object(s, 'enqueue_account_switch', return_value={'id': 'fixture-plan'}) as enqueue:
            for scope in [{'batch_id': 'fixture-import'}, {'account_ids': [row['id'] for row in accounts]}]:
                data = {**scope, 'workspace_id': SPACE, 'seat_type': 'default'}
                plan = switch.preview(self.parent['id'], data)
                self.assertEqual(plan['eligible_count'], 5001)
                self.assertEqual(plan['total'], 5001)
                switch.enqueue(self.parent['id'], {**data, 'selection_hash': plan['selection_hash']})
                self.assertEqual(len(enqueue.call_args.args[0]['items']), 5001)
                with self.assertRaises(store.TeamAdminError) as error:
                    switch.enqueue(self.parent['id'], {**data, 'selection_hash': 'stale'})
                self.assertEqual(error.exception.code, 'selection_changed')

    def test_invalid_ids_and_unsupported_seats_still_fail_and_duplicates_are_merged(self):
        with patch.object(s, '_enqueue_job', return_value={'id': 'fixture-validated'}) as enqueue:
            for ids in [[], ['bad/id'], [123]]:
                result = self.client.post(self.url, headers=HEADERS, json={
                    'kind': 'switch', 'workspace_id': SPACE, 'seat_type': 'default', 'user_ids': ids})
                self.assertEqual(result.status_code, 400)
            result = self.client.post(self.url, headers=HEADERS, json={
                'kind': 'switch', 'workspace_id': SPACE, 'seat_type': 'unknown', 'user_ids': ['user-fixture-1']})
            self.assertEqual(result.status_code, 400)
            enqueue.assert_not_called()
            self.enqueue(['user-fixture-1', 'user-fixture-1'])
            self.assertEqual(enqueue.call_args.args[3], ['user-fixture-1'])
            store.replace_workspaces(self.parent['id'], [{**self.workspace, 'is_usage_based_seat_enabled': False}])
            result = self.client.post(self.url, headers=HEADERS, json={
                'kind': 'switch', 'workspace_id': SPACE, 'seat_type': 'usage_based', 'user_ids': ['user-fixture-1']})
            self.assertEqual(result.status_code, 422)


if __name__ == '__main__':
    unittest.main()
