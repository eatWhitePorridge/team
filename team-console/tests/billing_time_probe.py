"""Billing routes and cache in isolated SQLite; all upstream requests are fake."""
import logging
import os
import unittest
import uuid
from contextlib import ExitStack, contextmanager
from datetime import datetime
from unittest.mock import Mock, patch

assert os.environ['PYTHON_DOTENV_DISABLED'] == '1'
assert os.environ['TEAM_CONSOLE_DATA_DIR']
logging.disable(logging.CRITICAL)
from backend.services import load_services
services = load_services()
from backend.app import create_app
from core import team_admin_service as service

store = services.team_store
HEADERS = {'X-Team-Console-Key': 'fixture-key'}
SPACE = 'billing-workspace-fixture'


class BillingTimeTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for target in ('requests.sessions.Session.request', 'curl_cffi.requests.Session.request'):
            self.stack.enter_context(patch(target, side_effect=AssertionError('external network forbidden')))
        self.parent = store.save_parent(f'owner-{uuid.uuid4().hex}@example.invalid',
                                       {'has_access_token': True}, {'access_token': 'fixture-private-at'})
        store.replace_workspaces(self.parent['id'], [{'id': SPACE, 'can_manage': True, 'expires_at': '2026-09-01T00:00:00Z'}])
        store.replace_members(self.parent['id'], SPACE, [{'id': 'fixture-user', 'email': 'fixture@example.invalid'}], {})
        self.app = create_app(services=services, api_key='fixture-key')
        self.client = self.app.test_client()
        self.url = f'/api/team-admin/parents/{self.parent["id"]}/workspaces/{SPACE}/subscription-expiration'
        # Exercise the real preview method, replacing only its HTTP transport.
        self.remote = object.__new__(service.TeamAdminClient)
        self.remote.token = 'fixture-private-at'
        self.remote.workspace_id = ''
        self.remote.close = Mock()
        self.remote.request = Mock(side_effect=self.preview)
        self.raw = '2026-09-17T10:48:44+00:00'
        self.factory = self.stack.enter_context(patch.object(service, 'TeamAdminClient', return_value=self.remote))

    def preview(self, method, path, *, params):
        self.assertEqual(method, 'GET')
        self.assertEqual(path, '/backend-api/subscriptions/update/preview')
        self.assertEqual(params['account_id'], SPACE)
        return {'current_seat_quantity': 4, 'renewal_date': self.raw, 'access_token': 'fixture-private-at'}

    def lookup(self):
        return self.client.post(self.url, json={}, headers=HEADERS)

    def cached(self):
        return store.workspaces(self.parent['id'])[0]

    def test_real_preview_uses_get_only_and_preserves_original_offset(self):
        response = self.lookup()
        self.assertEqual(response.status_code, 200)
        data = response.get_json()['workspace']
        self.assertEqual(data['renewal_date'], self.raw)
        self.assertEqual(data['billing_renewal_date'], self.raw)
        self.assertEqual(data['expiration_checked_at'], data['expiration_succeeded_at'])
        self.assertEqual(datetime.fromisoformat(data['expiration_checked_at']).utcoffset().total_seconds(), 0)
        self.assertEqual([call.kwargs['params']['updated_seats'] for call in self.remote.request.call_args_list], [3, 5])
        self.assertNotIn('fixture-private-at', response.get_data(as_text=True))
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.remote.close.assert_called_once()

    def test_unix_and_unknown_zone_values_are_not_silently_reinterpreted_by_server(self):
        for raw in [1789642124, 1789642124000, '2026-09-17T18:48:44+08:00', '2026-09-17T10:48:44', '2026-09-17']:
            with self.subTest(raw=raw):
                self.raw = raw
                response = self.lookup()
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()['workspace']['billing_renewal_date'], str(raw))

    def test_failed_refresh_keeps_last_date_and_success_time_but_records_attempt(self):
        with patch.object(store, 'now', return_value='2026-09-10T00:00:00+00:00'):
            self.assertEqual(self.lookup().status_code, 200)
        previous = self.cached()
        self.remote.request.side_effect = service.RemoteError('fixture lookup failure', 503)
        with patch.object(store, 'now', return_value='2026-09-10T00:00:10+00:00'):
            response = self.lookup()
        self.assertEqual(response.status_code, 422)
        current = self.cached()
        self.assertEqual(current['billing_renewal_date'], previous['billing_renewal_date'])
        self.assertEqual(current['expiration_succeeded_at'], previous['expiration_succeeded_at'])
        self.assertNotEqual(current['expiration_checked_at'], previous['expiration_checked_at'])
        self.assertEqual(current['expiration_error'], 'fixture lookup failure')

    def test_workspace_sync_cannot_erase_preview_cache_or_replace_it_with_entitlement(self):
        self.assertEqual(self.lookup().status_code, 200)
        previous = self.cached()
        store.replace_workspaces(self.parent['id'], [{'id': SPACE, 'can_manage': True, 'renewal_date': '', 'expires_at': '2026-11-01T00:00:00Z'}])
        current = self.cached()
        self.assertEqual(current['renewal_date'], '')
        self.assertEqual(current['billing_renewal_date'], self.raw)
        self.assertEqual(current['expiration_succeeded_at'], previous['expiration_succeeded_at'])
        self.assertEqual(current['expires_at'], '2026-11-01T00:00:00Z')

    def test_query_does_not_enqueue_or_change_members_even_when_a_member_job_is_running(self):
        job = store.create_job(self.parent['id'], 'members', SPACE, [], '')
        before = store.member_page(self.parent['id'], SPACE)
        jobs = store.recent_jobs(self.parent['id'])
        self.assertEqual(self.lookup().status_code, 200)
        self.assertEqual(store.recent_jobs(self.parent['id']), jobs)
        self.assertEqual(store.member_page(self.parent['id'], SPACE), before)
        store.update_job(job['id'], status='cancelled')

    def test_api_key_required_before_any_billing_read(self):
        self.assertEqual(self.client.post(self.url, json={}).status_code, 401)
        self.factory.assert_not_called()

    def test_missing_workspace_or_manager_rights_cannot_query_another_workspace(self):
        missing = self.url.replace(SPACE, 'missing-workspace')
        self.assertEqual(self.client.post(missing, json={}, headers=HEADERS).status_code, 404)
        store.update_workspace(self.parent['id'], SPACE, {'can_manage': False})
        self.assertEqual(self.lookup().status_code, 422)
        self.factory.assert_not_called()

    def test_missing_token_and_missing_date_are_errors_not_entitlement_fallback(self):
        self.remote.token = ''
        self.assertEqual(self.lookup().status_code, 422)
        self.remote.request.assert_not_called()
        self.remote.token = 'fixture-private-at'
        self.raw = ''
        self.assertEqual(self.lookup().status_code, 422)
        self.assertNotIn('billing_renewal_date', self.cached())
        self.assertEqual(self.cached()['expires_at'], '2026-09-01T00:00:00Z')

    def test_parent_list_contains_cached_invoice_without_upstream_requests_or_sensitive_metadata(self):
        self.assertEqual(self.lookup().status_code, 200)
        self.factory.reset_mock()
        store.update_workspace(self.parent['id'], SPACE, {
            'name': 'Billing fixture', 'access_token': 'fixture-private-at',
            'members': [{'email': 'private-member@example.invalid'}],
            'expiration_error': 'fixture-private-transport-error',
        })
        response = self.client.get('/api/team-admin/parents', headers=HEADERS)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        parent = next(row for row in response.get_json()['items'] if row['id'] == self.parent['id'])
        self.assertEqual(parent['workspace_count'], 1)
        self.assertEqual(parent['billing_workspaces'], [{
            'id': SPACE, 'name': 'Billing fixture', 'query_failed': True,
            'renewal_date': self.raw, 'billing_renewal_date': self.raw,
            'expiration_checked_at': self.cached()['expiration_checked_at'],
        }])
        for value in ('fixture-private-at', 'private-member@example.invalid',
                      'fixture-private-transport-error', 'expires_at', 'expiration_error'):
            self.assertNotIn(value, response.get_data(as_text=True))
        self.factory.assert_not_called()

    def test_parent_billing_summaries_stay_scoped_and_handle_empty_workspaces(self):
        other = store.save_parent(f'other-{uuid.uuid4().hex}@example.invalid', {}, {})
        empty = store.save_parent(f'empty-{uuid.uuid4().hex}@example.invalid', {}, {})
        store.replace_workspaces(other['id'], [{'id': SPACE, 'billing_renewal_date': 1789642124000}])
        store.replace_workspaces(self.parent['id'], [
            {'id': SPACE, 'renewal_date': '2026-09-17T10:48:44'},
            {'id': 'z-space', 'expires_at': '2026-10-10T00:00:00Z'},
        ])
        parents = {row['id']: row for row in store.list_parents()}
        self.assertEqual(parents[self.parent['id']]['workspace_count'], 2)
        self.assertEqual(parents[self.parent['id']]['billing_workspaces'], [
            {'id': SPACE, 'query_failed': False, 'renewal_date': '2026-09-17T10:48:44'},
            {'id': 'z-space', 'query_failed': False},
        ])
        self.assertEqual(parents[other['id']]['billing_workspaces'], [
            {'id': SPACE, 'query_failed': False, 'billing_renewal_date': 1789642124000},
        ])
        self.assertEqual(parents[empty['id']]['workspace_count'], 0)
        self.assertEqual(parents[empty['id']]['billing_workspaces'], [])
        self.factory.assert_not_called()

    def test_parent_list_refresh_reads_billing_cache_once_for_all_parents(self):
        for index in range(5):
            parent = store.save_parent(f'bulk-{index}-{uuid.uuid4().hex}@example.invalid', {}, {})
            store.replace_workspaces(parent['id'], [{'id': SPACE, 'renewal_date': self.raw}])
        queries = []
        original = store.connection

        @contextmanager
        def traced_connection():
            with original() as conn:
                conn.set_trace_callback(queries.append)
                yield conn

        with patch.object(store, 'connection', traced_connection):
            store.list_parents()
        reads = [sql for sql in queries if sql.lower().startswith('select') and 'from workspaces' in sql.lower()]
        self.assertEqual(len(reads), 1, reads)
        self.factory.assert_not_called()

    def test_parent_list_does_not_fail_for_malformed_cached_billing_metadata(self):
        with store.connection() as conn:
            conn.execute('UPDATE workspaces SET data=? WHERE parent_id=? AND id=?',
                         ('broken-json', self.parent['id'], SPACE))
        response = self.client.get('/api/team-admin/parents', headers=HEADERS)
        self.assertEqual(response.status_code, 200)
        parent = next(row for row in response.get_json()['items'] if row['id'] == self.parent['id'])
        self.assertEqual(parent['workspace_count'], 1)
        self.assertEqual(parent['billing_workspaces'], [{'id': SPACE, 'query_failed': False}])
        self.factory.assert_not_called()

    def test_parent_list_requires_auth_before_reading_cache(self):
        with patch.object(store, 'list_parents', side_effect=AssertionError('unauthenticated cache read')) as read:
            self.assertEqual(self.client.get('/api/team-admin/parents').status_code, 401)
            read.assert_not_called()


if __name__ == '__main__':
    unittest.main()
