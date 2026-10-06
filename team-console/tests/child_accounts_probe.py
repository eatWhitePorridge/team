"""Offline fixture: no live accounts, workers, upstream reads or UI tests."""
import json
import logging
import os
import unittest
import uuid
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

assert os.environ['PYTHON_DOTENV_DISABLED'] == '1'
assert os.environ['TEAM_CONSOLE_DATA_DIR']
logging.disable(logging.CRITICAL)
from backend.services import load_services
from backend.app import create_app
services = load_services()
store = services.team_store
HEADERS = {'X-Team-Console-Key': 'fixture-key'}


class ChildAccountsTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        for target in ('requests.sessions.Session.request', 'curl_cffi.requests.Session.request'):
            self.stack.enter_context(patch(target, side_effect=AssertionError('external network forbidden')))
        self.parent = store.save_parent(f'owner-{uuid.uuid4().hex}@example.invalid', {}, {'access_token': 'fixture-private-at'})
        self.other = store.save_parent(f'other-{uuid.uuid4().hex}@example.invalid', {}, {})
        store.replace_workspaces(self.parent['id'], [{'id': 'a'}, {'id': 'b'}, {'id': 'empty'}, {'id': 'not-synced'}])
        store.replace_workspaces(self.other['id'], [{'id': 'foreign'}])
        self.members = [
            {'id': 'owner', 'email': self.parent['email'], 'role': 'account-owner'},
            {'id': 'admin', 'email': 'admin@example.invalid', 'role': 'account-admin'},
            {'id': 'member1', 'email': 'CHILD1@example.invalid', 'role': 'standard-user', 'seat_type': 'prolite'},
            {'id': 'member2', 'email': 'child2@example.invalid', 'role': 'standard-user', 'seat_type': 'default'},
            {'id': 'archived', 'email': 'archived@example.invalid', 'role': 'standard-user'},
            {'id': 'no-email', 'email': '', 'role': 'standard-user'},
        ]
        store.replace_members(self.parent['id'], 'a', self.members, {})
        store.replace_members(self.parent['id'], 'b', [{'id': 'other-child', 'email': 'other-child@example.invalid'}], {})
        store.replace_members(self.parent['id'], 'empty', [], {})
        rows = [
            {'id': 1, 'email': self.parent['email']}, {'id': 2, 'email': 'admin@example.invalid'},
            {'id': 3, 'email': 'child1@example.invalid', 'codex_plan_type': 'free', 'registration_batch_id': 'batch-a'},
            {'id': 4, 'email': 'child2@example.invalid', 'codex_plan_type': 'self_serve_business_prolite', 'registration_batch_id': 'batch-b'},
            {'id': 5, 'email': 'archived@example.invalid', 'archived': True},
            {'id': 6, 'email': 'other-child@example.invalid'},
            {'id': 7, 'email': 'stale-tag@example.invalid', 'team_parent_id': str(self.parent['id']), 'team_workspace_id': 'a', 'codex_workspace_id': 'a'},
            {'id': 8, 'email': ''},
        ]
        for row in rows:
            row.update(password='fixture-private', totp_secret='fixture-private', access_token='fixture-private')
        Path(services.db._ACCOUNTS_JSON).write_text(json.dumps(rows))
        self.app = create_app(services=services, api_key='fixture-key')
        self.index = self.app.extensions['team_console']
        self.index['indexer'].refresh_once()
        self.client = self.app.test_client()
        self.params = {'team_parent_id': str(self.parent['id']), 'team_workspace_id': 'a'}
        for name in ('_load_accounts', '_load_batches'):
            self.stack.enter_context(patch.object(services.db, name, side_effect=AssertionError('legacy JSON read')))
        self.stack.enter_context(patch.object(self.index['accounts'], 'refresh_if_stale', side_effect=AssertionError('blocking refresh')))

    def query(self, **params):
        return self.client.get('/api/accounts', query_string={**self.params, **params}, headers=HEADERS)

    def test_selected_workspace_not_saved_tags_and_secrets_never_return(self):
        response = self.query()
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual([row['id'] for row in data['items']], [4, 3])
        self.assertEqual(data['summary']['total'], 2)
        self.assertNotIn('fixture-private', response.get_data(as_text=True))
        self.assertEqual(response.headers['Cache-Control'], 'no-store')

    def test_other_workspace_empty_scope_and_unfiltered_list_are_isolated(self):
        self.assertEqual([row['id'] for row in self.query(team_workspace_id='b').get_json()['items']], [6])
        self.assertEqual(self.query(team_workspace_id='empty').get_json()['total'], 0)
        self.assertEqual(self.client.get('/api/accounts', headers=HEADERS).get_json()['total'], 7)

    def test_pagination_and_account_filters_are_intersected_with_full_scope(self):
        result = self.query(page=2, page_size=1).get_json()
        self.assertEqual([row['id'] for row in result['items']], [3])
        self.assertEqual(result['total'], 2)
        for params in [{'batch_id': 'batch-a'}, {'codex_plan_type': 'free'}, {'q': 'child1'}, {'team_seat_type': 'prolite'}]:
            self.assertEqual([row['id'] for row in self.query(**params).get_json()['items']], [3])

    def test_missing_unsynced_and_foreign_workspace_never_fall_back_to_all(self):
        for params, status in [({'team_workspace_id': ''}, 400), ({'team_parent_id': ''}, 400),
                               ({'team_parent_id': '-1'}, 400), ({'team_seat_type': 'invalid'}, 400),
                               ({'team_workspace_id': 'not-synced'}, 409), ({'team_workspace_id': 'foreign'}, 404),
                               ({'team_workspace_id': 'missing'}, 404)]:
            with self.subTest(params=params):
                response = self.query(**params)
                self.assertEqual(response.status_code, status)
                self.assertNotIn('items', response.get_json())

    def test_member_cache_changes_take_effect_without_account_json_refresh(self):
        store.replace_members(self.parent['id'], 'a', self.members[:3], {})
        self.assertEqual([row['id'] for row in self.query().get_json()['items']], [3])
        store.replace_members(self.parent['id'], 'a', [], {})
        self.assertEqual(self.query().get_json()['total'], 0)

    def test_api_key_required_before_any_membership_read(self):
        with patch.object(store, 'child_account_emails', side_effect=AssertionError('unauthorized scope read')):
            response = self.client.get('/api/accounts', query_string=self.params)
        self.assertEqual(response.status_code, 401)

    def test_reading_children_does_not_sync_or_mutate_members_or_jobs(self):
        before = store.member_page(self.parent['id'], 'a'), store.recent_jobs(self.parent['id'])
        with patch.object(services.completion, 'enqueue_accounts', side_effect=AssertionError('authorization triggered')):
            self.assertEqual(self.query().status_code, 200)
        self.assertEqual(before, (store.member_page(self.parent['id'], 'a'), store.recent_jobs(self.parent['id'])))


if __name__ == '__main__':
    unittest.main()
