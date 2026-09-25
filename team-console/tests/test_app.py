import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from flask import Blueprint
from backend.app import create_app


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.accounts = self.root / 'accounts.json'
        self.batches = self.root / 'batches.json'
        self.accounts.write_text(json.dumps([{'id': 1, 'email': 'fixture@example.invalid', 'password': 'FIXTURE_PRIVATE', 'totp_secret': 'FIXTURE_PRIVATE', 'registration_batch_id': 'b1'}]))
        self.batches.write_text(json.dumps([{'batch_id': 'b1', 'flow_snapshot': {'registration_driver': 'imported', 'sms': {'api_key': 'FIXTURE_PRIVATE'}}}, {'batch_id': 'oauth-job-batch', 'flow_snapshot': {'registration_driver': 'protocol'}}]))
        self.blueprint = Blueprint('fixture_team', __name__, url_prefix='/api/team-admin')
        self.blueprint.add_url_rule('/probe', view_func=lambda: {'ok': True})
        self.db = SimpleNamespace(_ACCOUNTS_JSON=self.accounts, _BATCHES_JSON=self.batches,
                                  get_account_totp_export_candidates=Mock(return_value={}),
                                  _load_accounts=Mock(side_effect=AssertionError('legacy recovery read')),
                                  _load_batches=Mock(side_effect=AssertionError('legacy recovery read')),
                                  import_password_totp_accounts=Mock(return_value={'imported': [{'id': 1, 'email': 'fixture@example.invalid'}], 'imported_count': 1, 'skipped': [], 'batch_id': 'b1'}))
        self.services = SimpleNamespace(
            db=self.db, team_blueprint=self.blueprint,
            network=SimpleNamespace(public=Mock(return_value={'pool_count': 2}), update=Mock(return_value={'pool_count': 3})),
            authorization=SimpleNamespace(executor_status=Mock(return_value={'workers':100, 'running':0, 'queued':0, 'available':100, 'peak_running':0, 'fixed':True})),
            completion=SimpleNamespace(enqueue_accounts=Mock(return_value={'started': []}), list_authorization_batches=Mock(return_value=[]), list_items=Mock(return_value=[])),
            quota=SimpleNamespace(enqueue_accounts_quota_check=Mock(return_value={'ok': True, 'started': []})),
            export=SimpleNamespace(export_accounts=Mock(return_value={'ok': False, 'exported_count': 0, 'failed_count': 1, 'failed': [{'account_id': 1, 'error': 'fixture missing'}], 'data': {'accounts': []}})),
            parse_accounts=Mock(return_value=[{'id': 1}]),
            team_store=SimpleNamespace(list_parents=Mock(return_value=[]), recent_jobs=Mock(return_value=[]), recover_interrupted=Mock()),
        )
        self.app = create_app(services=self.services, index_path=self.root / 'index.sqlite3', api_key='')
        self.client = self.app.test_client()
        self.index = self.app.extensions['team_console']
        self.index['indexer'].refresh_once()

    def test_factory_does_not_recover_or_start_legacy_tasks(self):
        self.services.team_store.recover_interrupted.assert_not_called()
        self.db._load_accounts.assert_not_called()
        self.db._load_batches.assert_not_called()
        self.assertIsNone(self.index['indexer']._thread)
        self.services.completion.enqueue_accounts.assert_not_called()

    def test_list_routes_never_load_legacy_json(self):
        with patch.object(self.index['accounts'], 'refresh_if_stale', side_effect=AssertionError('blocking refresh')):
            for path in ('/api/accounts', '/api/accounts/1', '/api/batches', '/api/overview'):
                with self.subTest(path=path):
                    response = self.client.get(path)
                    self.assertEqual(response.status_code, 200)
                    self.assertNotIn('FIXTURE_PRIVATE', response.get_data(as_text=True))
                    self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.db._load_accounts.assert_not_called()
        self.db._load_batches.assert_not_called()

    def test_batch_data_mapping(self):
        result = self.client.get('/api/batches?driver=protocol').get_json()
        self.assertEqual(result['total'], 1)
        row = result['items'][0]
        self.assertEqual(row['account_total'], 1)
        self.assertEqual(row['registration_driver'], 'imported')
        self.assertNotIn('flow_snapshot', row)

    def test_account_plan_and_batch_filters_are_combined_in_sql(self):
        rows = [
            {'id': 1, 'email': 'free@example.invalid', 'registration_batch_id': 'one', 'codex_plan_type': 'free'},
            {'id': 2, 'email': 'team@example.invalid', 'registration_batch_id': 'one', 'codex_plan_type': 'self_serve_business_prolite', 'plan_type': 'free'},
            {'id': 3, 'email': 'other@example.invalid', 'registration_batch_id': 'two', 'codex_plan_type': 'free'},
            {'id': 4, 'email': 'unknown@example.invalid', 'registration_batch_id': 'one', 'plan_type': 'free'},
        ]
        self.accounts.write_text(json.dumps(rows))
        self.index['indexer'].refresh_once()
        for params, expected in [('batch_id=one', [4, 2, 1]), ('batch_id=one&codex_plan_type=free', [1]),
                                 ('batch_id=one&codex_plan_type=self_serve_business_prolite', [2]),
                                 ('batch_id=missing', [])]:
            with self.subTest(params=params):
                result = self.client.get('/api/accounts?' + params).get_json()
                self.assertEqual([row['id'] for row in result['items']], expected)
                self.assertEqual(result['total'], len(expected))
        self.db._load_accounts.assert_not_called()

    def test_totp_export_is_explicit_authenticated_and_not_cached(self):
        self.app.config['TEAM_CONSOLE_API_KEY'] = 'offline-key'
        self.assertEqual(self.client.post('/api/accounts/export-totp', json={'account_ids': [1]}).status_code, 401)
        self.db.get_account_totp_export_candidates.assert_not_called()
        self.db.get_account_totp_export_candidates.return_value = {
            1: {'id': 1, 'email': 'fixture@example.invalid', 'registration_password': '  password----tail- ',
                'totp_secret': 'JBSWY3DPEHPK3PXP', 'totp_status': 'activation_uncertain'},
        }
        response = self.client.post('/api/accounts/export-totp', json={'account_ids': [1, 2, 1]}, headers={'X-Team-Console-Key': 'offline-key'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        data = response.get_json()
        self.assertEqual(data['data'], 'fixture@example.invalid----  password----tail- ----JBSWY3DPEHPK3PXP\n')
        self.assertTrue(data['filename'].endswith('.txt'))
        self.assertEqual((data['requested_count'], data['exported_count'], data['failed_count']), (2, 1, 1))
        self.assertEqual(len(data['warnings']), 1)
        self.db.get_account_totp_export_candidates.assert_called_once_with([1, 2])
        self.services.export.export_accounts.assert_not_called()
        self.services.completion.enqueue_accounts.assert_not_called()

    def test_totp_export_empty_or_invalid_selection_does_not_create_download(self):
        # The SPA fallback deliberately returns 404 for unknown GET /api paths.
        self.assertIn(self.client.get('/api/accounts/export-totp').status_code, (404, 405))
        for ids in ([], [True], [0], ['1'], list(range(1, 5002))):
            with self.subTest(ids=ids[:2]):
                self.assertEqual(self.client.post('/api/accounts/export-totp', json={'account_ids': ids}).status_code, 400)
        self.db.get_account_totp_export_candidates.assert_not_called()
        response = self.client.post('/api/accounts/export-totp', json={'account_ids': [1]})
        self.assertEqual(response.status_code, 422)
        self.assertFalse(response.get_json()['ok'])
        self.assertEqual(response.get_json()['data'], '')

    def test_jobs_runtime_uses_live_executor_counters_not_active_batch_rows(self):
        self.services.completion.list_authorization_batches.return_value = [{'active':200}]
        self.services.authorization.executor_status.return_value.update(running=100, queued=100, available=0, peak_running=100)
        response = self.client.get('/api/jobs')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['runtime']['running'], 100)
        self.assertEqual(response.get_json()['runtime']['queued'], 100)
        self.db._load_accounts.assert_not_called()
        self.app.config['TEAM_CONSOLE_API_KEY'] = 'fixture-key'
        self.assertEqual(self.client.get('/api/jobs').status_code, 401)

    def test_authorization_empty_queue_is_conflict(self):
        self.services.completion.enqueue_accounts.return_value = {'started': [], 'busy': [{'id': 1, 'reason': 'busy'}]}
        response = self.client.post('/api/accounts/authorize', json={'account_ids': [1]})
        self.assertEqual(response.status_code, 409)
        self.assertFalse(response.get_json()['ok'])
        self.assertEqual(response.get_json()['busy_count'], 1)

    def test_partial_authorization_preserves_counts_and_mode(self):
        self.services.completion.enqueue_accounts.return_value = {'started': [{'id': 1}], 'skipped': [{'id': 2, 'reason': 'fixture'}]}
        response = self.client.post('/api/accounts/authorize', json={'account_ids': [1, 2], 'team_authorization': True})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json()['started_count'], 1)
        self.assertEqual(response.get_json()['skipped_count'], 1)
        self.services.completion.enqueue_accounts.assert_called_once_with([1, 2], login_mode='password_totp', team_authorization=True)

    def test_invalid_boolean_and_ids_never_enqueue(self):
        for data in ({'account_ids': [True]}, {'account_ids': [1], 'team_authorization': 'false'}, {'account_ids': []}):
            response = self.client.post('/api/accounts/authorize', json=data)
            self.assertEqual(response.status_code, 400)
        self.services.completion.enqueue_accounts.assert_not_called()

    def test_empty_quota_queue_not_reported_as_success(self):
        response = self.client.post('/api/accounts/check-quota', json={'account_ids': [1]})
        self.assertEqual(response.status_code, 409)
        self.assertFalse(response.get_json()['ok'])

    def test_failed_export_returns_report_not_empty_download(self):
        response = self.client.post('/api/accounts/export-sub2api', json={'account_ids': [1]})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.get_json()['failed_count'], 1)
        self.assertNotIn('Content-Disposition', response.headers)

    def test_partial_export_keeps_data_and_failures(self):
        self.services.export.export_accounts.return_value = {'ok': True, 'exported_count': 1, 'failed_count': 1, 'failed': [{'account_id': 2, 'error': 'fixture'}], 'warnings': [], 'filename': 'fixture.json', 'data': {'accounts': [{'email': 'fixture@example.invalid'}]}}
        response = self.client.post('/api/accounts/export-sub2api', json={'account_ids': [1, 2]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['failed_count'], 1)
        self.assertEqual(len(response.get_json()['data']['accounts']), 1)

    def test_import_success_with_enqueue_failure_not_misreported(self):
        self.services.completion.enqueue_accounts.side_effect = RuntimeError('PRIVATE_PROVIDER_RESPONSE')
        response = self.client.post('/api/accounts/import-password-totp', json={'text': 'fixture', 'start_authorization': True})
        result = response.get_json()
        self.assertEqual(response.status_code, 201)
        self.assertTrue(result['ok'])
        self.assertEqual(result['imported_count'], 1)
        self.assertFalse(result['authorization']['ok'])
        self.assertNotIn('PRIVATE_PROVIDER_RESPONSE', response.get_data(as_text=True))
        self.db.import_password_totp_accounts.assert_called_once()

    def test_import_does_not_synchronously_reindex(self):
        with patch.object(self.index['accounts'], 'refresh_if_stale', side_effect=AssertionError('blocking refresh')):
            response = self.client.post('/api/accounts/import-password-totp', json={'text': 'fixture'})
        self.assertEqual(response.status_code, 201)
        self.assertTrue(self.index['indexer']._wake.is_set())
        self.services.completion.enqueue_accounts.assert_not_called()

    def test_access_key_also_protects_reused_team_routes(self):
        self.app.config['TEAM_CONSOLE_API_KEY'] = 'offline-key'
        for path in ('/api/batches', '/api/team-admin/probe'):
            self.assertEqual(self.client.get(path).status_code, 401)
            self.assertEqual(self.client.get(path, headers={'X-Team-Console-Key': 'offline-key'}).status_code, 200)

    def test_login_rejects_missing_and_wrong_key(self):
        self.app.config['TEAM_CONSOLE_API_KEY'] = 'offline-key'
        for headers in ({}, {'X-Team-Console-Key': 'wrong-key'}):
            response = self.client.get('/api/auth/verify', headers=headers)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.get_json()['code'], 'access_key_invalid')
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            self.assertNotIn('offline-key', response.get_data(as_text=True))

    def test_login_accepts_valid_key_without_echoing_it(self):
        self.app.config['TEAM_CONSOLE_API_KEY'] = 'offline-key'
        response = self.client.get('/api/auth/verify', headers={'X-Team-Console-Key': 'offline-key'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {'ok': True})
        self.assertEqual(response.headers['Cache-Control'], 'no-store')

    def test_login_fails_closed_without_server_configuration(self):
        response = self.client.get('/api/auth/verify', headers={'X-Team-Console-Key': 'arbitrary'})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()['code'], 'access_key_unconfigured')

    def test_unauthenticated_write_does_not_enqueue(self):
        self.app.config['TEAM_CONSOLE_API_KEY'] = 'offline-key'
        response = self.client.post('/api/accounts/authorize', json={'account_ids': [1]}, headers={'X-Team-Console-Key': 'wrong-key'})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()['code'], 'access_key_invalid')
        self.services.completion.enqueue_accounts.assert_not_called()

    def test_unknown_api_and_path_traversal_not_served_as_frontend(self):
        self.assertEqual(self.client.get('/api/does-not-exist').status_code, 404)
        self.assertEqual(self.client.get('/../server.py').status_code, 404)

    def test_no_automatic_write_retries(self):
        self.services.completion.enqueue_accounts.side_effect = OSError('fixture')
        response = self.client.post('/api/accounts/authorize', json={'account_ids': [1]})
        self.assertEqual(response.status_code, 500)
        self.services.completion.enqueue_accounts.assert_called_once()

    def test_member_pagination_matches_quota_without_reading_json(self):
        self.services.team_store.workspaces = Mock(return_value=[{'id': 'workspace1'}])
        self.services.team_store.member_page = Mock(return_value={'items': [{'id': 'user1', 'email': 'fixture@example.invalid'}], 'page': 2, 'page_size': 100, 'total': 140})
        response = self.client.get('/api/team/parents/1/workspaces/workspace1/members?page=2&page_size=100')
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(result['total'], 140)
        self.assertEqual(result['items'][0]['local_account']['id'], 1)
        self.assertNotIn('FIXTURE_PRIVATE', response.get_data(as_text=True))
        self.services.team_store.member_page.assert_called_once_with(1, 'workspace1', page=2, page_size=100, query='', seat_type='', seat_status='', emails='', email_status='')
        self.db._load_accounts.assert_not_called()

    def test_member_page_rejects_large_remote_page_size(self):
        response = self.client.get('/api/team/parents/1/workspaces/w/members?page_size=101')
        self.assertEqual(response.status_code, 400)

    def test_all_cached_members_and_hold_filter_are_forwarded(self):
        self.services.team_store.workspaces = Mock(return_value=[{'id': 'w'}])
        self.services.team_store.member_page = Mock(return_value={'items': [], 'total': 0})
        response = self.client.get('/api/team/parents/1/workspaces/w/members?page_size=all&seat_status=hold&seat_type=prolite')
        self.assertEqual(response.status_code, 200)
        self.services.team_store.member_page.assert_called_once_with(1, 'w', page=1, page_size=None, query='', seat_type='prolite', seat_status='hold', emails='', email_status='')

    def test_bulk_member_email_search_uses_cached_store(self):
        self.services.team_store.workspaces = Mock(return_value=[{'id': 'w'}])
        self.services.team_store.member_page = Mock(return_value={'items': [], 'total': 0})
        response = self.client.post('/api/team/parents/1/workspaces/w/members/search', json={'page_size': 'all', 'emails': 'a@example.invalid\nb@example.invalid'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.services.team_store.member_page.call_args.kwargs['emails'], 'a@example.invalid\nb@example.invalid')

    def test_all_member_quota_matches_are_chunked_and_do_not_load_account_json(self):
        self.services.team_store.workspaces = Mock(return_value=[{'id': 'w'}])
        self.services.team_store.member_page = Mock(return_value={'items': [{'id': str(n), 'email': f'{n}@example.invalid'} for n in range(241)], 'total': 241})
        with patch.object(self.index['accounts'], 'by_emails', return_value={}) as match:
            response = self.client.get('/api/team/parents/1/workspaces/w/members?page_size=all')
        self.assertEqual(response.status_code, 200)
        self.assertEqual([len(c.args[0]) for c in match.call_args_list], [100, 100, 41])
        self.db._load_accounts.assert_not_called()

    def test_network_settings_authentication_and_explicit_update(self):
        self.app.config['TEAM_CONSOLE_API_KEY'] = 'offline-key'
        self.assertEqual(self.client.get('/api/settings/network').status_code, 401)
        self.assertEqual(self.client.post('/api/settings/network', json={'pool_action': 'clear'}).status_code, 401)
        self.services.network.update.assert_not_called()
        response = self.client.post('/api/settings/network', headers={'X-Team-Console-Key': 'offline-key'}, json={'pool_action': 'keep'})
        self.assertEqual(response.status_code, 200)
        self.services.network.update.assert_called_once_with({'pool_action': 'keep'})


class LegacyStartupIntegrationTests(unittest.TestCase):
    def test_existing_running_job_survives_new_factory(self):
        """Use the real old store and routes, but only in a temporary directory."""
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            accounts, batches = path / 'accounts.json', path / 'batches.json'
            accounts.write_text('[]'); batches.write_text('[]')
            core = types.ModuleType('core'); core.__path__ = []
            db = types.ModuleType('core.db')
            db._DATA_DIR, db._ACCOUNTS_JSON, db._BATCHES_JSON = path, accounts, batches
            core.db = db
            service = types.ModuleType('core.team_admin_service')
            core.team_admin_service = service
            schedule = types.ModuleType('core.team_schedule_service')
            schedule.refresh_waiting = Mock()
            core.team_schedule_service = schedule
            webui = types.ModuleType('webui'); webui.__path__ = []
            def load(name, file):
                spec = importlib.util.spec_from_file_location(name, file)
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module; spec.loader.exec_module(module)
                return module
            with patch.dict(sys.modules, {'core': core, 'core.db': db, 'core.team_admin_service': service, 'core.team_schedule_service': schedule, 'webui': webui}):
                store = load('core.team_admin_store', root / 'core/team_admin_store.py')
                core.team_admin_store = store
                routes = load('webui.team_admin_routes', root / 'webui/team_admin_routes.py')
                parent = store.save_parent('offline@example.invalid', {}, {})
                job = store.create_job(parent['id'], 'discover', '', [], '')
                store.update_job(job['id'], status='running')
                services = SimpleNamespace(db=db, team_blueprint=routes.blueprint, team_store=store)
                create_app(services=services, index_path=path / 'index.sqlite3')
                self.assertEqual(store.get_job(job['id'])['status'], 'running')
                schedule.refresh_waiting.assert_not_called()


if __name__ == '__main__':
    unittest.main()
