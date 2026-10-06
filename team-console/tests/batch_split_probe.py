"""Temporary real business storage only; all network primitives are blocked."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from backend.services import load_services
from backend.app import create_app

s = load_services()
db = s.db


class SplitTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        for name, value in list(vars(db).items()):
            if name.startswith('_') and name.isupper() and isinstance(value, Path) and value.is_relative_to(s.data_dir):
                self.stack.enter_context(patch.object(db, name, self.root / value.relative_to(s.data_dir)))
        self.stack.enter_context(patch.object(s.completion, '_STATE_PATH', self.root / 'pipeline.json'))
        self.stack.enter_context(patch('curl_cffi.requests.Session.request', side_effect=AssertionError('live HTTP forbidden')))
        self.stack.enter_context(patch('requests.sessions.Session.request', side_effect=AssertionError('live HTTP forbidden')))
        db._JSON_CACHE.clear()
        self.a = self.imported('one', 'two', 'three')
        self.b = self.imported('four', 'five')
        self.ids = [row['id'] for group in (self.a, self.b) for row in group['imported']]
        rows = deepcopy(db._load_accounts())
        rows[0].update(codex_refresh_token='FIXTURE_TOKEN', access_token='FIXTURE_TOKEN',
                       codex_plan_type='self_serve_business_prolite', quota_credits_balance=17,
                       quota_status='success', team_workspace_id='fixture-workspace',
                       web_cookie_credential_path='fixture-cookie.json')
        db._save_accounts(rows)
        db._COOKIE_DIR.mkdir(parents=True, exist_ok=True)
        (db._COOKIE_DIR / 'fixture-cookie.json').write_text('FIXTURE_COOKIE')
        db._save_jobs([{'id': 1, 'account_id': self.ids[0], 'batch_id': 'internal-oauth', 'status': 'success'}])
        self.headers = {'X-Team-Console-Key': 'fixture-key'}
        self.app = create_app(services=s, api_key='fixture-key', index_path=self.root / 'read.sqlite3')
        self.client = self.app.test_client()
        self.indexer = self.app.extensions['team_console']['indexer']
        self.indexer.refresh_once()

    def imported(self, *names):
        return db.import_password_totp_accounts(s.parse_accounts('\n'.join(
            f'{name}@example.invalid----FixturePassword123!----JBSWY3DPEHPK3PXP' for name in names)))

    def split(self, ids=None, request_id=None, **extra):
        return self.client.post('/api/accounts/split-batch', headers=self.headers, json={
            'account_ids': self.ids[:2] if ids is None else ids,
            'request_id': request_id or str(uuid.uuid4()), 'confirm': True, **extra})

    def query(self, batch_id):
        return self.client.get('/api/accounts', headers=self.headers, query_string={'batch_id': batch_id}).get_json()

    def assert_committed(self, result, ids):
        self.assertEqual(set(row['id'] for row in self.query(result['batch_id'])['items']), set(ids))
        self.assertEqual(db.get_registration_batch(result['batch_id'])['count'], len(set(ids)))
        self.assertFalse(db._batch_split_journal_path().exists())

    def test_subset_keeps_all_other_fields_artifacts_and_uses_one_small_journal(self):
        before = deepcopy(db._load_accounts())
        files = {p: p.read_bytes() for p in (db._ACCOUNTS_JSON, db._ACCOUNTS_TXT, db._TOKENS_TXT,
                                             db._JOBS_JSON, db._COOKIE_DIR / 'fixture-cookie.json')}
        with patch.object(db, '_write_json', wraps=db._write_json) as writes:
            response = self.split([self.ids[0], self.ids[1], self.ids[0]])
        self.assertEqual(response.status_code, 200, response.get_json())
        result = response.get_json()
        self.assert_committed(result, self.ids[:2])
        paths = [call.args[0] for call in writes.call_args_list]
        self.assertEqual(len(paths), 4)  # intent, progress, batch metadata, receipt
        self.assertEqual(paths.count(db._account_progress_context()[0]), 1)
        self.assertNotIn(db._ACCOUNTS_JSON, paths)
        for path, value in files.items():
            self.assertEqual(path.read_bytes(), value)
        for old, new in zip(before, db._load_accounts()):
            keys = {'registration_batch_id', 'updated_at'} if old['id'] in self.ids[:2] else set()
            self.assertEqual({k: v for k, v in old.items() if k not in keys},
                             {k: v for k, v in new.items() if k not in keys})
        self.assertEqual(self.query(self.a['batch_id'])['total'], 1)
        self.assertEqual(db.get_registration_batch(self.a['batch_id'])['count'], 1)
        self.indexer.refresh_once()
        self.assert_committed(result, self.ids[:2])
        encoded = json.dumps(result) + json.dumps(db.get_registration_batch(result['batch_id']))
        encoded += db._batch_split_receipt_path(result['batch_id']).read_text()
        for secret in ('FixturePassword', 'FIXTURE_TOKEN', 'JBSWY3DPEHPK3PXP', 'FIXTURE_COOKIE'):
            self.assertNotIn(secret, encoded)

    def test_cross_batch_and_whole_source_keep_empty_source(self):
        selected = self.ids[:3] + self.ids[3:4]
        response = self.split(selected)
        self.assertEqual(response.status_code, 200)
        self.assert_committed(response.get_json(), selected)
        self.assertEqual(self.query(self.a['batch_id'])['total'], 0)
        self.assertEqual(db.get_registration_batch(self.a['batch_id'])['count'], 0)
        self.assertEqual(self.query(self.b['batch_id'])['total'], 1)

    def test_retry_is_idempotent_and_reused_id_cannot_move_other_accounts(self):
        request_id = uuid.uuid4().hex
        first = self.split(request_id=request_id).get_json()
        with patch.object(db, '_write_json', wraps=db._write_json) as writes:
            again = self.split(ids=self.ids[1::-1], request_id=request_id)
            conflict = self.split(ids=self.ids[2:3], request_id=request_id)
        self.assertEqual(again.status_code, 200)
        self.assertTrue(again.get_json()['already_split'])
        self.assertEqual(again.get_json()['batch_id'], first['batch_id'])
        self.assertEqual(conflict.status_code, 409)
        writes.assert_not_called()
        # An already-completed request must not pull members back after another split.
        self.split(ids=self.ids[:2])
        self.assertEqual(self.split(request_id=request_id).status_code, 409)

    def test_validation_missing_archived_internal_and_authentication_fail_atomically(self):
        with patch.object(db, '_write_json', wraps=db._write_json) as writes:
            for payload in ({'confirm': False}, {'confirm': 'yes'}, {'request_id': '../bad'},
                            {'request_id': self.a['batch_id']}):
                self.assertIn(self.split(**payload).status_code, (400, 409))
            for ids in ([], [True], [0], ['1'], self.ids + [99999], [1] * 5001):
                self.assertIn(self.split(ids).status_code, (400, 404))
            self.assertEqual(self.client.post('/api/accounts/split-batch', json={}).status_code, 401)
            writes.assert_not_called()
        for fields in ({'archived': True}, {'registration_driver': 'roxy'}, {'registration_batch_id': None}):
            rows = deepcopy(db._load_accounts()); original = deepcopy(rows)
            rows[0].update(fields); db._save_accounts(rows)
            self.assertEqual(self.split().status_code, 409)
            db._save_accounts(original)
        batches = db._load_batches()
        batches[0]['registration_drivers'] = ['imported', 'roxy']; db._save_batches(batches)
        self.assertEqual(self.split().status_code, 409)

    def test_busy_retry_gap_quota_and_linked_jobs_block_entire_selection(self):
        s.completion._STATE_PATH.write_text(json.dumps([
            {'account_id': self.ids[1], 'status': 'running'},
            *[{'account_id': self.ids[4], 'status': 'success'} for _ in range(5001)]]))
        response = self.split()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()['busy'][0]['id'], self.ids[1])
        s.completion._STATE_PATH.write_text('[]')
        original = deepcopy(db._load_accounts())
        for fields in ({'quota_status': 'queued', 'quota_check_id': 'fixture-claim'},
                       {'totp_status': 'running'}, {'codex_status': 'retrying'}):
            rows = deepcopy(original); rows[1].update(fields); db._save_accounts(rows)
            self.assertEqual(self.split().status_code, 409)
        db._save_accounts(original)
        db._save_jobs([{'id': 1, 'account_id': self.ids[1], 'batch_id': 'other-internal', 'status': 'pending'}])
        self.assertEqual(self.split().status_code, 409)
        self.assertEqual(len(db._load_batches()), 2)
        self.assertFalse(db._batch_split_journal_path().exists())

    def test_unselected_busy_account_does_not_block_other_members_of_same_batch(self):
        s.completion._STATE_PATH.write_text(json.dumps([{'account_id': self.ids[2], 'status': 'running'}]))
        self.assertEqual(self.split().status_code, 200)

    def test_index_failure_is_warning_not_false_failure_or_replayed_mutation(self):
        with patch.object(self.indexer, 'apply_batch_split', side_effect=OSError('fixture index failure')):
            response = self.split()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()['warnings']), 1)
        self.indexer.refresh_once()
        self.assert_committed(response.get_json(), self.ids[:2])

    def test_failed_intent_is_not_a_commit(self):
        before = deepcopy([db._load_accounts(), db._load_batches()])
        with patch.object(db, '_write_json', side_effect=OSError('fixture failure')) as writes:
            self.assertEqual(self.split().status_code, 500)
            writes.assert_called_once()
        self.assertEqual([db._load_accounts(), db._load_batches()], before)
        self.assertFalse(db._batch_split_journal_path().exists())

    def test_every_partial_commit_recovers_once_without_publishing_partial_index(self):
        for phase in ('progress', 'batches', 'receipt', 'cleanup'):
            with self.subTest(phase=phase):
                request_id = str(uuid.uuid4())
                before_index = self.indexer.accounts.query()
                failing_path = {'progress': db._account_progress_context()[0], 'batches': db._BATCHES_JSON,
                                'receipt': db._batch_split_receipt_path(request_id),
                                'cleanup': db._batch_split_journal_path()}[phase]
                original_write, original_unlink = db._write_json, Path.unlink
                def write(path, data):
                    if phase != 'cleanup' and path == failing_path:
                        raise OSError('fixture partial write')
                    original_write(path, data)
                def unlink(path, *args, **kwargs):
                    if phase == 'cleanup' and path == failing_path:
                        raise OSError('fixture cleanup failure')
                    return original_unlink(path, *args, **kwargs)
                with patch.object(db, '_write_json', side_effect=write), patch.object(Path, 'unlink', unlink):
                    self.assertEqual(self.split(request_id=request_id).status_code, 500)
                    self.assertTrue(db._batch_split_journal_path().exists())
                    self.assertIsNone(self.indexer.refresh_once())
                    self.assertEqual(self.indexer.accounts.query(), before_index)
                db._JSON_CACHE.clear()
                # Either table read must roll forward before exposing its rows.
                db._load_batches()
                again = self.split(request_id=request_id)
                self.assertEqual(again.status_code, 200, again.get_json())
                self.assertTrue(again.get_json()['already_split'])
                self.assert_committed(again.get_json(), self.ids[:2])

    def test_fresh_process_startup_completes_committed_split_only(self):
        request_id = str(uuid.uuid4())
        with patch.object(db, '_save_account_progress_many', side_effect=OSError('fixture crash')):
            self.assertEqual(self.split(request_id=request_id).status_code, 500)
        env = {**os.environ, 'TEAM_CONSOLE_DATA_DIR': str(self.root)}
        script = 'from backend.services import load_services; s=load_services(); assert not s.db._batch_split_journal_path().exists(); assert s.completion._THREAD is None'
        result = subprocess.run([sys.executable, '-c', script], env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        db._JSON_CACHE.clear(); self.indexer.refresh_once()
        self.assertEqual(self.query(request_id)['total'], 2)

    def test_large_cross_page_selection_has_constant_write_count_and_rebuilds(self):
        group = self.imported(*(f'bulk{i}' for i in range(351)))
        ids = [row['id'] for row in group['imported']]
        rows = db._load_accounts(); rows[-1]['fixture_history'] = 'x' * (10 * 1024 * 1024)
        db._save_accounts(rows); self.indexer.refresh_once()
        checkpoint = db._ACCOUNTS_JSON.read_bytes()
        with patch.object(db, '_write_json', wraps=db._write_json) as writes:
            response = self.split(ids[::2])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(writes.call_count, 4)
        self.assertEqual(db._ACCOUNTS_JSON.read_bytes(), checkpoint)
        self.indexer.refresh_once()
        self.assertEqual(self.query(response.get_json()['batch_id'])['total'], 176)
        self.assertEqual(self.query(group['batch_id'])['total'], 175)

    def test_concurrent_duplicate_request_creates_exactly_one_batch(self):
        request_id = str(uuid.uuid4())
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.split(request_id=request_id).get_json(), range(2)))
        self.assertEqual(sum(not row['already_split'] for row in results), 1)
        self.assertEqual(len(db._load_batches()), 3)

    def test_corrupt_intent_fails_closed(self):
        db._batch_split_journal_path().write_text('{broken')
        with self.assertRaises(ValueError):
            db._load_accounts()
        self.assertIsNone(self.indexer.refresh_once())

    def test_preserves_symlink_storage(self):
        volume = self.root / 'volume'; volume.mkdir()
        for path in (db._ACCOUNTS_JSON, db._BATCHES_JSON):
            path.rename(volume / path.name); path.symlink_to(volume / path.name)
        response = self.split()
        self.assertEqual(response.status_code, 200)
        self.assert_committed(response.get_json(), self.ids[:2])
        self.assertTrue(db._ACCOUNTS_JSON.is_symlink())
        self.assertTrue(db._BATCHES_JSON.is_symlink())


if __name__ == '__main__':
    unittest.main(verbosity=2)
