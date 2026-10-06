"""Real queue / SQLite / API using the existing isolated fake transport fixture.

Only synthetic invitations are used. All real HTTP methods are blocked.
"""
import copy
import json
import threading
import time
import unittest
from http.cookiejar import CookieJar
from types import SimpleNamespace
from unittest.mock import Mock, patch

import seat_switch_probe as base
from backend.progress import collect_jobs, event_frame
from core.session import BrowserSession

s, store, services = base.s, base.store, base.services
SPACE, HEADERS = base.SPACE, base.HEADERS
REAL_MONOTONIC, REAL_SLEEP = time.monotonic, time.sleep


class PendingInvitationTests(unittest.TestCase):
    def setUp(self):
        self.f = base.SeatFlowTests('test_direct_api_accepts_201_and_larger_selections_without_a_count_cap')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.items = [self.invite(n) for n in range(3)]
        self.page_limit, self.page_failure, self.patch_outcomes = 100, '', []
        self.f.env.get = self.get
        self.f.env.patch = self.patch
        self.f.env.post = Mock(side_effect=AssertionError('invitation POST must not be used'))
        self.url = f'/api/team-admin/parents/{self.f.parent["id"]}/workspaces/{SPACE}/invites'

    @staticmethod
    def invite(n):
        return {'id': f'invite-fixture-{n}', 'email_address': f'invited-{n}@example.invalid',
                'account_user_id': None, 'status': 2, 'seat_type': 'usage_based', 'role': 'standard-user',
                'created_time': '2026-09-28T07:30:00Z'}

    def get(self, url, *, params=None, headers=None, **kwargs):
        self.f.calls.append(('GET', url, copy.deepcopy(params), self.f.clock))
        self.assertTrue(url.endswith(f'/{SPACE}/invites'), 'No members/seat-summary lookup in invitation flow')
        self.assertEqual(params['limit'], 100)
        self.assertEqual(headers['chatgpt-account-id'], SPACE)
        offset = params['offset']
        rows, total = self.items[offset:offset + self.page_limit], len(self.items)
        if offset and self.page_failure == 'duplicate': rows = self.items[:self.page_limit]
        if offset and self.page_failure == 'total_changed': total += 1
        if offset and self.page_failure == 'empty': rows = []
        return base.response(payload={'items': copy.deepcopy(rows), 'total': total, 'offset': offset, 'limit': 100})

    def patch(self, url, *, json, headers=None, **kwargs):
        self.assertEqual(headers['chatgpt-account-id'], SPACE)
        self.assertFalse(kwargs['allow_redirects'])
        self.assertEqual(set(json), {'seat_type'})
        self.assertIn('/invites/invite-fixture-', url)
        self.f.calls.append(('PATCH', url, copy.deepcopy(json), self.f.clock))
        outcome = self.patch_outcomes.pop(0) if self.patch_outcomes else 200
        if isinstance(outcome, Exception): raise outcome
        if isinstance(outcome, int): outcome = base.response(outcome)
        if outcome.status_code == 200:
            # The transport never mutates a real account, and the production
            # worker still has to parse the success response before caching it.
            try: accepted = outcome.json().get('success') is True
            except (ValueError, AttributeError): accepted = False
            if accepted:
                next(row for row in self.items if row['id'] == url.rsplit('/', 1)[-1])['seat_type'] = json['seat_type']
        return outcome

    def enqueue(self, kind='invite_switch', ids=None, seat='prolite', **extra):
        data = {'kind': kind, 'workspace_id': SPACE, 'concurrency': 1, **extra}
        if kind == 'invite_switch':
            data.update(invite_ids=ids if ids is not None else [item['id'] for item in self.items], seat_type=seat)
        response = self.f.client.post(self.f.url, headers=HEADERS, json=data)
        self.assertEqual(response.status_code, 202, response.get_json())
        self.assertNotIn('invite_ids', response.get_json()['job'])
        return response.get_json()['job']['id']

    def run_job(self, *args, **kwargs):
        ident = self.enqueue(*args, **kwargs)
        s._run(ident)
        return store.get_job(ident)

    def cached(self, **query):
        response = self.f.client.get(self.url, headers=HEADERS, query_string={'page_size': 'all', **query})
        self.assertEqual(response.status_code, 200, response.get_json())
        return response.get_json()

    def test_har_shaped_283_invites_use_three_100_pages_and_unpaginated_cached_api(self):
        self.items = [self.invite(n) for n in range(283)]
        job = self.run_job('invites')
        self.assertEqual((job['status'], job['total'], job['completed']), ('success', 1, 1))
        self.assertEqual([c[2]['offset'] for c in self.f.calls], [0, 100, 200])
        before = len(self.f.calls)
        data = self.cached(status='pending')
        self.assertEqual((len(data['items']), data['total'], data['page'], data['page_size']), (283, 283, 1, None))
        self.assertEqual(len(self.cached(page=10)['items']), 283)
        self.assertEqual(self.cached(q='INVITE-FIXTURE-282')['total'], 1)
        self.assertEqual(self.cached(q='INVITED-282@')['total'], 1)
        self.assertEqual(len(self.f.calls), before)
        self.assertTrue(any(event[0] == 'team' for event in self.f.events))

    def test_short_server_pages_advance_by_actual_count_while_always_requesting_100(self):
        self.items = [self.invite(n) for n in range(63)]
        self.page_limit = 25
        self.assertEqual(self.run_job('invites')['status'], 'success')
        self.assertEqual([c[2]['offset'] for c in self.f.calls], [0, 25, 50])
        self.assertEqual(self.cached()['total'], 63)

    def test_filtering_pending_seats_and_legacy_pagination_does_not_read_upstream(self):
        self.items = [self.invite(n) for n in range(205)]
        self.items[-1].update(status=1)
        self.items[0].update(seat_type='prolite')
        self.assertEqual(self.run_job('invites')['status'], 'success')
        self.assertEqual(self.cached(status='pending')['total'], 204)
        self.assertEqual(self.cached(status='pending', seat_type='prolite')['total'], 1)
        self.assertEqual(self.cached(status='pending', seat_type='usage_based')['total'], 203)
        response = self.f.client.get(self.url, headers=HEADERS, query_string={'page': 3, 'page_size': 100})
        self.assertEqual(len(response.get_json()['items']), 5)
        for query in [{'status': 'unknown'}, {'seat_type': 'unknown'}, {'page_size': 'invalid'}]:
            self.assertEqual(self.f.client.get(self.url, headers=HEADERS, query_string=query).status_code, 400)
        self.assertEqual(self.f.client.get(self.url).status_code, 401)

    def test_invalid_pages_preserve_the_previous_complete_snapshot(self):
        self.assertEqual(self.run_job('invites')['status'], 'success')
        original = self.cached()['items']
        self.items = [self.invite(n) for n in range(150)]
        for mode in ['duplicate', 'total_changed', 'empty']:
            self.page_failure = mode
            self.assertEqual(self.run_job('invites')['status'], 'failed')
            self.assertEqual(self.cached()['items'], original)
            self.assertTrue(store.workspaces(self.f.parent['id'])[0]['invites_stale'])

    def test_bulk_switch_over_200_uses_only_patch_then_updates_cached_seats(self):
        self.items = [self.invite(n) for n in range(201)]
        job = self.run_job()
        self.assertEqual((job['status'], job['total'], job['completed']), ('success', 201, 201))
        calls = self.f.calls
        self.assertEqual([c[2]['offset'] for c in calls if c[0] == 'GET'], [0, 100, 200])
        self.assertEqual(len([c for c in calls if c[0] == 'PATCH']), 201)
        self.assertFalse(any(c[0] != 'PATCH' for c in calls[3:]))
        self.f.env.post.assert_not_called()
        self.assertTrue(all(row['seat_type'] == 'prolite' for row in self.cached()['items']))
        self.assertTrue(all(row['invite_id'].startswith('invite-') for row in job['results']))
        self.assertNotIn('invite_ids', store.recent_jobs(self.f.parent['id'])[0])

    def test_same_seat_nonpending_or_missing_invites_never_fall_back_to_member_switch_or_reinvite(self):
        self.items[0]['seat_type'] = 'prolite'
        self.items[1]['status'] = 1
        job = self.run_job(ids=[row['id'] for row in self.items] + ['foreign-invite'])
        self.assertEqual(job['status'], 'partial')
        self.assertEqual([row['status'] for row in job['results']], ['unchanged', 'skipped', 'success', 'skipped'])
        self.assertEqual(len([c for c in self.f.calls if c[0] == 'PATCH']), 1)
        self.f.env.post.assert_not_called()

    def test_429_continues_with_live_progress_then_can_cancel_without_repeating_success(self):
        self.patch_outcomes = [200] + [429] * 7
        ident = self.enqueue()
        seen = []
        def inspect():
            row = next(r for r in collect_jobs(services)['team'] if r['id'] == ident)
            if 'HTTP 429' not in row['message']: return
            self.assertEqual((row['kind'], row['status'], row['completed'], row['total']), ('invite_switch', 'running', 1, 3))
            self.assertIn(b'429', event_frame('snapshot', row))
            seen.append(row['message'])
            if '第 7 次' in row['message']:
                response = self.f.client.post(f'/api/team-admin/jobs/{ident}/cancel', headers=HEADERS)
                self.assertEqual(response.status_code, 200)
        self.f.on_sleep = inspect
        s._run(ident)
        job = store.get_job(ident)
        self.assertEqual((job['status'], job['completed']), ('cancelled', 1))
        self.assertTrue(any('第 7 次' in msg for msg in seen))
        patches = [c for c in self.f.calls if c[0] == 'PATCH']
        self.assertEqual(len(patches), 8)
        self.assertTrue(all(c[1] == patches[1][1] and c[2] == {'seat_type': 'prolite'} for c in patches[1:]))
        self.assertEqual(self.cached(q='invited-0@')['items'][0]['seat_type'], 'prolite')
        self.assertEqual(self.cached(q='invited-1@')['items'][0]['seat_type'], 'usage_based')
        self.assertFalse(s._WORKSPACE_LOCKS[SPACE].locked())

    def test_429_retry_can_succeed_without_post_write_readback(self):
        self.patch_outcomes = [429] * 7 + [200]
        job = self.run_job(ids=[self.items[0]['id']])
        self.assertEqual((job['status'], job['completed']), ('success', 1))
        self.assertEqual([c[0] for c in self.f.calls], ['GET'] + ['PATCH'] * 8)

    def test_non429_errors_stop_without_replaying_or_publishing_false_seats(self):
        invalid = base.response()
        invalid.json.side_effect = ValueError('fixture malformed JSON')
        for outcome in [400, 401, 403, 404, 500, TimeoutError(), invalid, base.response(payload={'success': False})]:
            self.f.calls = []
            self.patch_outcomes = [outcome]
            job = self.run_job()
            self.assertEqual((job['status'], job['completed']), ('failed', 1))
            self.assertEqual([c[0] for c in self.f.calls], ['GET', 'PATCH'])
            self.assertTrue(all(row['seat_type'] == 'usage_based' for row in self.cached()['items']))

    def test_cache_failure_does_not_erase_remote_success_or_trigger_resubmission(self):
        with patch.object(store, 'update_invite', side_effect=OSError('fixture cache error')):
            job = self.run_job(ids=[self.items[0]['id']])
        self.assertEqual(job['status'], 'success')
        self.assertEqual(job['results'][0]['status'], 'success')
        self.assertIn('本地缓存未更新', job['results'][0]['message'])
        self.assertEqual([c[0] for c in self.f.calls], ['GET', 'PATCH'])

    def test_job_rejects_member_ids_bad_seats_and_preserves_workspace_permissions(self):
        payload = {'kind': 'invite_switch', 'workspace_id': SPACE, 'seat_type': 'prolite', 'invite_ids': [self.items[0]['id']]}
        for changes in [{'invite_ids': []}, {'invite_ids': ['bad/id']}, {'invite_ids': [True]},
                        {'seat_type': 'invalid'}, {'user_ids': ['user-1']},
                        *({'concurrency': value} for value in [0, 21, 2.5, '5', True, None])]:
            response = self.f.client.post(self.f.url, headers=HEADERS, json={**payload, **changes})
            self.assertEqual(response.status_code, 400)
        self.assertFalse(self.f.calls)
        ids = [row['id'] for row in self.items]
        job = self.run_job(ids=ids + ids)
        self.assertEqual(job['total'], len(ids))
        self.f.calls = []
        self.f.workspace['can_manage'] = False
        self.assertEqual(self.run_job()['status'], 'failed')
        self.assertFalse(self.f.calls)
        self.f.workspace.update(can_manage=True, is_usage_based_seat_enabled=False)
        store.replace_workspaces(self.f.parent['id'], [self.f.workspace])
        response = self.f.client.post(self.f.url, headers=HEADERS, json={**payload, 'seat_type': 'usage_based'})
        self.assertEqual(response.status_code, 422)

    def parallel_transport(self, patch_handler):
        """Use real worker threads and fork logic, but entirely fake transports."""
        from requests.cookies import create_cookie
        jar = CookieJar()
        jar.set_cookie(create_cookie('fixture-cookie', 'fixture-value', domain='chatgpt.com'))
        self.f.env.session.cookies = SimpleNamespace(jar=jar, clear=jar.clear)
        self.f.env.proxy = 'socks5h://fixture-proxy.invalid:1080'
        self.f.env.device_id = 'fixture-device'
        self.f.env.browser_family = 'chrome'
        self.f.env.browser_profile = {'fixture': ['profile']}
        self.f.env.oai_session_id = 'fixture-oai-session'
        self.f.env.chatgpt_client_observation = 'fixture-observation'
        transports, calls = [], []
        source = [True]
        lock = threading.Lock()

        def factory(**kwargs):
            if source[0]:
                source[0] = False
                self.f.env.proxy = kwargs['proxy']
                return self.f.env
            cookies = CookieJar()
            transport = SimpleNamespace(session=SimpleNamespace(cookies=SimpleNamespace(jar=cookies, clear=cookies.clear)),
                                        get_chatgpt_headers=lambda *a: {}, options=kwargs, owner=threading.get_ident(), closed=False)
            def send(url, **options):
                self.assertEqual(threading.get_ident(), transport.owner)
                self.assertEqual(options['json'], {'seat_type': 'prolite'})
                self.assertEqual(options['headers']['chatgpt-account-id'], SPACE)
                self.assertEqual(options['headers']['authorization'], 'Bearer fixture-token')
                self.assertFalse(options['allow_redirects'])
                with lock:
                    calls.append((url.rsplit('/', 1)[-1], REAL_MONOTONIC(), transport.owner))
                return patch_handler(url.rsplit('/', 1)[-1])
            def close():
                self.assertEqual(threading.get_ident(), transport.owner)
                transport.closed = True
            transport.patch, transport.session.close = send, close
            transports.append(transport)
            return transport

        self.f.stack.enter_context(patch.object(s, 'BrowserSession', side_effect=factory))
        self.f.stack.enter_context(patch.object(s.time, 'monotonic', REAL_MONOTONIC))
        self.f.stack.enter_context(patch.object(s.time, 'sleep', REAL_SLEEP))
        return transports, calls

    def start_job(self, ident):
        thread = threading.Thread(target=s._run, args=(ident,), daemon=True)
        thread.start()
        return thread

    def test_default_concurrency_is_five_without_changing_member_switch_configuration(self):
        payload = {'kind': 'invite_switch', 'workspace_id': SPACE, 'seat_type': 'prolite',
                   'invite_ids': [self.items[0]['id']]}
        response = self.f.client.post(self.f.url, headers=HEADERS, json=payload)
        self.assertEqual(response.status_code, 202)
        job = response.get_json()['job']
        self.assertEqual((job['concurrency'], job['running']), (5, 0))
        self.assertNotIn('inflight_invites', job)
        store.update_job(job['id'], status='cancelled')
        s._SLOTS.release()

    def test_true_bounded_parallelism_refills_before_slowest_finishes_and_isolates_sessions(self):
        self.items = [self.invite(n) for n in range(12)]
        barrier = threading.Barrier(5)
        all_started, next_started, release = threading.Event(), threading.Event(), threading.Event()
        self.addCleanup(release.set)
        active, peak = [0], [0]
        lock = threading.Lock()
        def send(ident):
            n = int(ident.rsplit('-', 1)[-1])
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            try:
                if n < 5:
                    barrier.wait(5)
                    all_started.set()
                if n == 0:
                    self.assertTrue(release.wait(5))
                elif n >= 5:
                    next_started.set()
                return base.response()
            finally:
                with lock: active[0] -= 1
        transports, calls = self.parallel_transport(send)
        ident = self.enqueue(concurrency=5)
        thread = self.start_job(ident)
        try:
            self.assertTrue(all_started.wait(5))
            self.assertTrue(next_started.wait(5), 'A free worker must refill while invite 0 is still pending')
            self.assertTrue(thread.is_alive())
            snapshot = next(row for row in collect_jobs(services)['team'] if row['id'] == ident)
            self.assertEqual(snapshot['concurrency'], 5)
            self.assertGreater(snapshot['running'], 0)
            self.assertLessEqual(snapshot['running'], 5)
            self.assertNotIn('inflight_invites', snapshot)
        finally:
            release.set(); thread.join(10)
        self.assertFalse(thread.is_alive())
        job = store.get_job(ident)
        self.assertEqual((job['status'], job['completed'], job['running']), ('success', 12, 0))
        self.assertEqual(peak[0], 5)
        self.assertEqual(len(calls), 12)
        self.assertEqual(len({row[0] for row in calls}), 12)
        self.assertEqual(len(transports), 5)
        self.assertEqual(len({row.owner for row in transports}), 5)
        for transport in transports:
            self.assertTrue(transport.closed)
            self.assertEqual(transport.options, {'proxy': self.f.env.proxy, 'detect_exit_geo': False,
                'device_id': 'fixture-device', 'browser_family': 'chrome'})
            self.assertIsNot(transport.session.cookies.jar, self.f.env.session.cookies.jar)
            self.assertEqual([(c.name, c.value) for c in transport.session.cookies.jar], [('fixture-cookie', 'fixture-value')])
            self.assertIsNot(transport.browser_profile, self.f.env.browser_profile)
        self.assertEqual([call[0] for call in self.f.calls], ['GET'])
        self.assertTrue(all(row['seat_type'] == 'prolite' for row in self.cached()['items']))

    def test_cancelling_parallel_work_stops_new_items_but_collects_inflight_success(self):
        self.items = [self.invite(n) for n in range(20)]
        started, release = threading.Event(), threading.Event()
        barrier = threading.Barrier(3)
        self.addCleanup(release.set)
        def send(ident):
            barrier.wait(5); started.set()
            self.assertTrue(release.wait(5))
            return base.response()
        transports, calls = self.parallel_transport(send)
        ident = self.enqueue(concurrency=3)
        thread = self.start_job(ident)
        try:
            self.assertTrue(started.wait(5))
            response = self.f.client.post(f'/api/team-admin/jobs/{ident}/cancel', headers=HEADERS)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(store.get_job(ident)['running'], 3)
        finally:
            release.set(); thread.join(10)
        self.assertFalse(thread.is_alive())
        job = store.get_job(ident)
        self.assertEqual((job['status'], job['completed'], job['running']), ('cancelled', 3, 0))
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(row['status'] == 'success' for row in job['results']))
        self.assertTrue(all(row.closed for row in transports))
        self.assertFalse(s._WORKSPACE_LOCKS[SPACE].locked())

    def test_parallel_429_pauses_new_items_and_retries_without_a_retry_wave(self):
        self.items = [self.invite(n) for n in range(8)]
        barrier, limited = threading.Barrier(5), threading.Event()
        seen, rate_at = {}, []
        lock = threading.Lock()
        original = s._InviteSeatControl.rate_limited
        def rate(control, delay, retry):
            original(control, delay, retry)
            rate_at.append(REAL_MONOTONIC()); limited.set()
        self.f.stack.enter_context(patch.object(s._InviteSeatControl, 'rate_limited', rate))
        self.f.stack.enter_context(patch.object(s, '_SEAT_SWITCH_INTERVAL', .04))
        def send(ident):
            n = int(ident.rsplit('-', 1)[-1])
            with lock:
                seen[ident] = seen.get(ident, 0) + 1
                count = seen[ident]
            if n < 5 and count == 1:
                barrier.wait(5)
                if n == 0: return base.response(429, headers={'Retry-After': '0.2'})
                self.assertTrue(limited.wait(5))
            return base.response()
        transports, calls = self.parallel_transport(send)
        job = self.run_job(concurrency=5)
        self.assertEqual((job['status'], job['completed']), ('success', 8))
        self.assertEqual(len(calls), 9)
        self.assertEqual(seen['invite-fixture-0'], 2)
        self.assertTrue(all(count == 1 for ident, count in seen.items() if ident != 'invite-fixture-0'))
        self.assertTrue(all(at >= rate_at[0] + .17 for _, at, _ in calls[5:]))
        self.assertTrue(all(b[1] - a[1] >= .02 for a, b in zip(calls[5:], calls[6:])))
        self.assertTrue(all(row.closed for row in transports))
        self.assertEqual([call[0] for call in self.f.calls], ['GET'])

    def test_parallel_failure_stops_dispatch_but_preserves_other_acknowledgements(self):
        self.items = [self.invite(n) for n in range(8)]
        barrier = threading.Barrier(2)
        failed, release = threading.Event(), threading.Event()
        original_update = store.update_job
        def update(ident, **fields):
            result = original_update(ident, **fields)
            if any(row.get('status') == 'failed' for row in fields.get('results', [])): failed.set()
            return result
        self.f.stack.enter_context(patch.object(store, 'update_job', side_effect=update))
        self.addCleanup(release.set)
        def send(ident):
            barrier.wait(5)
            if ident.endswith('-0'): return base.response(403)
            self.assertTrue(release.wait(5))
            return base.response()
        transports, calls = self.parallel_transport(send)
        ident = self.enqueue(concurrency=2)
        thread = self.start_job(ident)
        try:
            self.assertTrue(failed.wait(5))
            self.assertTrue(thread.is_alive(), 'Do not finish/release workspace while an acknowledgement is pending')
        finally:
            release.set(); thread.join(10)
        self.assertFalse(thread.is_alive())
        job = store.get_job(ident)
        self.assertEqual((job['status'], job['completed'], job['running']), ('failed', 2, 0))
        self.assertEqual(sorted(row['status'] for row in job['results']), ['failed', 'success'])
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(row.closed for row in transports))

    def test_cancellation_during_parallel_cooldown_does_not_wait_for_retry_after(self):
        self.items = [self.invite(n) for n in range(20)]
        barrier, limited = threading.Barrier(3), threading.Event()
        original = s._InviteSeatControl.rate_limited
        def rate(control, delay, retry):
            original(control, delay, retry); limited.set()
        self.f.stack.enter_context(patch.object(s._InviteSeatControl, 'rate_limited', rate))
        def send(ident):
            barrier.wait(5)
            return base.response(429, headers={'Retry-After': '600'})
        transports, calls = self.parallel_transport(send)
        ident = self.enqueue(concurrency=3)
        thread = self.start_job(ident)
        self.assertTrue(limited.wait(5))
        start = REAL_MONOTONIC()
        self.assertEqual(self.f.client.post(f'/api/team-admin/jobs/{ident}/cancel', headers=HEADERS).status_code, 200)
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertLess(REAL_MONOTONIC() - start, 1)
        job = store.get_job(ident)
        self.assertEqual((job['status'], job['completed'], job['running']), ('cancelled', 0, 0))
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(row.closed for row in transports))

    def test_cooldown_does_not_pause_a_different_workspace(self):
        first = s._InviteSeatControl(SPACE)
        other = s._InviteSeatControl('other-fixture-workspace')
        first.rate_limited(600, 1)
        initial = self.f.clock
        other.wait(SimpleNamespace(job_id=''))
        self.assertEqual(self.f.clock, initial)
        self.assertNotIn('other-fixture-workspace', s._SEAT_NEXT_AT)

    def test_restart_marks_inflight_invites_unconfirmed_without_replaying_confirmed_items(self):
        ident = self.enqueue(concurrency=5)
        acknowledged = {'invite_id': self.items[0]['id'], 'status': 'success'}
        inflight = [{'invite_id': row['id'], 'email': row['email_address'], 'target': 'prolite'} for row in self.items]
        store.update_job(ident, status='running', results=[acknowledged], completed=1, running=3, inflight_invites=inflight)
        store.recover_interrupted()
        job = store.get_job(ident)
        self.assertEqual((job['status'], job['running'], job['completed']), ('interrupted', 0, 3))
        self.assertEqual([row['status'] for row in job['results']], ['success', 'unconfirmed', 'unconfirmed'])
        self.assertEqual(job['inflight_invites'], [])
        self.assertIn('请先同步待接受邀请', job['message'])
        self.assertFalse(self.f.calls)

    def test_patch_transport_attaches_headers_observes_response_and_cannot_become_post(self):
        transport = BrowserSession.__new__(BrowserSession)
        transport.session = SimpleNamespace(patch=Mock(return_value='response'), post=Mock())
        transport._attach_openai_target_headers_for_url = Mock(return_value={'fixture': 'header'})
        transport._observe_response = Mock(return_value='observed')
        url = 'https://chatgpt.com/backend-api/accounts/fixture/invites/invite-fixture'
        result = transport.patch(url, headers={'before': 'header'}, json={'seat_type': 'prolite'}, allow_redirects=False, timeout=20)
        self.assertEqual(result, 'observed')
        transport.session.patch.assert_called_once_with(url, headers={'fixture': 'header'}, json={'seat_type': 'prolite'}, allow_redirects=False, timeout=20)
        transport._observe_response.assert_called_once_with('response', url, 'PATCH')
        transport.session.post.assert_not_called()


if __name__ == '__main__':
    unittest.main()
