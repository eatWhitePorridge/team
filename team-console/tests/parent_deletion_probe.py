"""Real API/SQLite deletion in a throwaway directory; external HTTP is forbidden."""
import json
import logging
import os
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

assert os.environ['PYTHON_DOTENV_DISABLED'] == '1'
assert os.environ['TEAM_CONSOLE_DATA_DIR']
logging.disable(logging.CRITICAL)
from backend.services import load_services
services = load_services()
from backend.app import create_app
store = services.team_store
HEADERS = {'X-Team-Console-Key': 'fixture-key'}
SPACE = 'workspace-fixture'
TABLES = ('workspaces', 'members', 'seat_holds', 'invites', 'jobs', 'schedule_previews')


class ParentDeletionFlowTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for target in ('requests.sessions.Session.request', 'curl_cffi.requests.Session.request',
                       'core.team_admin_service.TeamAdminClient.request'):
            self.stack.enter_context(patch(target, side_effect=AssertionError('external network forbidden')))
        self.parent = self.seed_parent()
        self.other = self.seed_parent()
        self.app = create_app(services=services, api_key='fixture-key')
        self.client = self.app.test_client()
        self.url = f'/api/team-admin/parents/{self.parent["id"]}'
        # Account imports, authorization files and cookies are outside mother
        # metadata. Every test checks their exact bytes remain unchanged.
        self.account_files = {}
        for path in (services.db._ACCOUNTS_JSON, services.db._BATCHES_JSON, services.db._JOBS_JSON,
                     services.db._COOKIE_DIR / 'fixture.json', services.db._CODEX_DIR / 'fixture.json'):
            path = Path(path)
            self.assertTrue(path.resolve().is_relative_to(Path(os.environ['TEAM_CONSOLE_DATA_DIR']).resolve()))
            path.parent.mkdir(parents=True, exist_ok=True)
            content = b'[{"id":77,"email":"child@example.invalid","fixture":true}]\n'
            path.write_bytes(content)
            self.account_files[path] = content

    def tearDown(self):
        for path, expected in self.account_files.items():
            self.assertEqual(path.read_bytes(), expected)

    def seed_parent(self):
        parent = store.save_parent(f'owner-{uuid.uuid4().hex}@example.invalid', {}, {'access_token': 'fixture-token'})
        pid = parent['id']
        store.replace_workspaces(pid, [{'id': SPACE, 'name': 'Fixture', 'can_manage': True}])
        store.replace_members(pid, SPACE, [{'id': 'child-fixture', 'email': 'child@example.invalid', 'seat_type': 'prolite'}], {})
        store.replace_seat_holds(pid, SPACE, [{'id': 'held-fixture', 'email': 'held@example.invalid', 'reclaimable_seat_type': 'default'}])
        store.replace_invites(pid, SPACE, [{'id': 'invite-fixture', 'email': 'invited@example.invalid', 'status': 2}])
        job = store.create_job(pid, 'members', SPACE, [], '')
        store.update_job(job['id'], status='success')
        store.save_schedule_preview(pid, {'workspace_id': SPACE})
        return parent

    def counts(self, pid):
        with store.connection() as conn:
            return {table: conn.execute(f'SELECT COUNT(*) FROM {table} WHERE parent_id=?', (pid,)).fetchone()[0] for table in TABLES}

    def delete(self, parent=None, **kwargs):
        parent = parent or self.parent
        return self.client.delete(f'/api/team-admin/parents/{parent["id"]}', headers=HEADERS,
                                  json={'confirm': True, 'expected_email': parent['email']}, **kwargs)

    def test_delete_cascades_only_target_cache_credentials_and_history(self):
        other_counts = self.counts(self.other['id'])
        self.assertTrue(all(self.counts(self.parent['id']).values()))
        response = self.delete()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {'ok': True})
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertTrue(all(count == 0 for count in self.counts(self.parent['id']).values()))
        self.assertEqual(self.counts(self.other['id']), other_counts)
        self.assertEqual(store.credentials(self.other['id']), {'access_token': 'fixture-token'})
        with self.assertRaises(store.TeamAdminError) as exc:
            store.credentials(self.parent['id'])
        self.assertEqual(exc.exception.code, 'parent_not_found')
        self.assertNotIn(self.parent['id'], [p['id'] for p in self.client.get('/api/team-admin/parents', headers=HEADERS).get_json()['items']])

    def test_missing_access_key_cannot_delete(self):
        response = self.client.delete(self.url, json={'confirm': True, 'expected_email': self.parent['email']})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(store.get_parent(self.parent['id'])['email'], self.parent['email'])

    def test_active_jobs_block_deletion_until_completed(self):
        job = store.create_job(self.parent['id'], 'invite_switch', SPACE, [], 'prolite', invite_ids=['invite-fixture'])
        original = self.counts(self.parent['id'])
        for status in ('queued', 'running'):
            store.update_job(job['id'], status=status)
            response = self.delete()
            self.assertEqual(response.status_code, 409)
            self.assertEqual(response.get_json()['code'], 'parent_busy')
            self.assertEqual(self.counts(self.parent['id']), original)
        store.update_job(job['id'], status='cancelled')
        self.assertEqual(self.delete().status_code, 200)

    def test_deleted_parent_is_not_silently_replayed(self):
        self.assertEqual(self.delete().status_code, 200)
        response = self.delete()
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json()['code'], 'parent_not_found')
        self.assertEqual(store.get_parent(self.other['id'])['email'], self.other['email'])

    def test_legacy_bodyless_delete_remains_compatible(self):
        response = self.client.delete(self.url, headers={**HEADERS, 'Content-Type': 'application/json'})
        self.assertEqual(response.status_code, 200)

    def test_confirmation_and_identity_payload_are_validated(self):
        for payload in ({}, [], None, {'confirm': False, 'expected_email': self.parent['email']},
                        {'confirm': 'true', 'expected_email': self.parent['email']},
                        {'confirm': True}, {'confirm': True, 'expected_email': 7},
                        {'confirm': True, 'expected_email': '  '}):
            with self.subTest(payload=payload):
                response = self.client.delete(self.url, headers=HEADERS, data=json.dumps(payload), content_type='application/json')
                self.assertEqual(response.status_code, 400)
                self.assertEqual(store.get_parent(self.parent['id'])['email'], self.parent['email'])

    def test_reused_numeric_id_cannot_delete_a_different_parent(self):
        old = self.other  # Newest (largest) ID is intentionally reusable in SQLite.
        self.assertEqual(self.delete(old).status_code, 200)
        replacement = self.seed_parent()
        self.assertEqual(old['id'], replacement['id'])
        response = self.delete(old)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()['code'], 'parent_changed')
        self.assertEqual(store.get_parent(replacement['id'])['email'], replacement['email'])

    def test_storage_error_is_reported_once_without_secrets(self):
        with patch.object(store, 'delete_parent', side_effect=OSError('fixture-private-details')) as called:
            response = self.delete()
        self.assertEqual(response.status_code, 500)
        self.assertEqual(called.call_count, 1)
        self.assertNotIn('fixture-private-details', response.get_data(as_text=True))
        self.assertEqual(store.get_parent(self.parent['id'])['email'], self.parent['email'])

    def test_concurrent_enqueue_and_delete_are_serialized(self):
        for _ in range(6):
            parent = self.seed_parent()
            barrier = threading.Barrier(2)

            def operation(delete):
                barrier.wait(timeout=5)
                try:
                    if delete:
                        store.delete_parent(parent['id'], expected_email=parent['email'])
                    else:
                        store.create_job(parent['id'], 'members', SPACE, [], '')
                    return 'ok'
                except store.TeamAdminError as exc:
                    return exc.code

            with ThreadPoolExecutor(max_workers=2) as pool:
                deleted = pool.submit(operation, True)
                queued = pool.submit(operation, False)
                outcome = deleted.result(timeout=10), queued.result(timeout=10)
            self.assertIn(outcome, [('ok', 'parent_not_found'), ('parent_busy', 'ok')])
            if outcome[0] == 'ok':
                self.assertEqual(self.counts(parent['id'])['jobs'], 0)
            else:
                self.assertTrue(store.get_parent(parent['id']))


if __name__ == '__main__':
    unittest.main()
