import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from backend.index_store import AccountIndex, BatchIndex, IndexRefresher, safe_projection, safe_batch_projection, file_signature


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'accounts.json'
        self.batch_source = self.root / 'batches.json'
        self.path = self.root / 'index.sqlite3'
        self.rows = [{'id': i, 'email': f'user_{i}@example.invalid', 'created_at': '2026-01-01', 'registration_batch_id': 'batch1', 'quota_status': 'unchecked'} for i in range(1, 7)]
        self.write_rows()
        self.batch_source.write_text(json.dumps([{'batch_id': 'batch1', 'created_at': '2026-01-01', 'flow_snapshot': {'registration_driver': 'roxy', 'sms': {'api_key': 'FIXTURE_SECRET'}}, 'unknown_secret': 'FIXTURE_SECRET'}]))
        self.index = AccountIndex(self.source, self.path)
        self.batches = BatchIndex(self.path, None, self.index, source_path=self.batch_source)
        self.indexer = IndexRefresher(self.index, self.batches)
        self.assertIsNotNone(self.indexer.refresh_once())

    def write_rows(self):
        self.source.write_text(json.dumps(self.rows))

    def journal(self, fields, *, email='user_1@example.invalid', signature=None):
        self.source.with_name(self.source.name + '.progress.json').write_text(json.dumps({'accounts_signature': signature or list(file_signature(self.source)), 'updates': {'1': {'email': email, 'created_at': '2026-01-01', 'fields': fields}}}))

    def test_projection_drops_credentials_and_nested_values(self):
        result = safe_projection({'id': 7, 'email': 'one@example.invalid', 'password': 'secret', 'totp_secret': 'secret', 'access_token': 'secret', 'codex_refresh_token': 'secret', 'note': {'token': 'secret'}})
        self.assertNotIn('secret', json.dumps(result))
        self.assertTrue(result['has_codex_refresh_token'])
        self.assertEqual(result['codex_connection_state'], 'connected')
        self.assertEqual(result['totp_status'], 'active')

    def test_pagination_and_literal_search(self):
        result = self.index.query(page=2, page_size=2)
        self.assertEqual([row['id'] for row in result['items']], [4, 3])
        self.assertEqual(self.index.query(q='user_1')['total'], 1)
        self.assertEqual(self.index.query(q='%')['total'], 0)

    def test_queries_never_call_source_or_refresh(self):
        self.index.loader = Mock(side_effect=AssertionError('request scanned JSON'))
        with patch.object(self.index, 'refresh_if_stale', side_effect=AssertionError('request refreshed JSON')):
            self.assertEqual(self.index.query()['total'], 6)
            self.assertEqual(self.index.summary()['total'], 6)
            self.assertEqual(self.index.get(1)['id'], 1)
            self.assertEqual(self.batches.query()['items'][0]['account_total'], 6)
        self.index.loader.assert_not_called()

    def test_authorization_plan_filter_is_exact_and_does_not_guess_free(self):
        self.rows[0].update(codex_plan_type=' FREE ', plan_type='team')
        self.rows[1].update(codex_plan_type='self_serve_business_prolite', plan_type='free')
        self.rows[2].update(codex_plan_type='free', registration_batch_id='batch2')
        self.rows[3].update(codex_plan_type='self_serve_business_usage_based')
        self.rows[4].update(plan_type='free')  # No saved OAuth plan.
        self.rows[5].update(codex_plan_type='free', archived=True)
        self.write_rows(); self.index.refresh_if_stale()
        self.index.loader = Mock(side_effect=AssertionError('filter scanned JSON'))
        self.assertEqual(self.index.query(codex_plan_type='free')['total'], 2)
        self.assertEqual(self.index.query(batch_id='batch1', codex_plan_type='free')['items'][0]['id'], 1)
        result = self.index.query(batch_id='batch1', codex_plan_type='self_serve_business_prolite')
        self.assertEqual([row['id'] for row in result['items']], [2])
        self.assertEqual(result['summary']['total'], 1)
        for plan in ('self_serve_business', 'free%', "free' OR 1=1 --"):
            self.assertEqual(self.index.query(codex_plan_type=plan)['total'], 0)
        self.index.loader.assert_not_called()
        conn = sqlite3.connect(self.path)
        try:
            names = {row[1] for row in conn.execute('PRAGMA index_list(accounts)')}
            self.assertIn('account_codex_plan_type_ci', names)
            self.assertIn('account_batch_plan_ci', names)
        finally:
            conn.close()

    def test_latest_authorization_plan_progress_updates_filter(self):
        self.journal({'codex_plan_type': 'free'})
        self.index.refresh_if_stale()
        self.assertEqual(self.index.query(codex_plan_type='free')['total'], 1)
        self.journal({'codex_plan_type': 'self_serve_business_prolite'})
        self.index.refresh_if_stale()
        self.assertEqual(self.index.query(codex_plan_type='free')['total'], 0)
        self.assertEqual(self.index.query(codex_plan_type='self_serve_business_prolite')['total'], 1)

    def test_one_changed_row_only_updates_one_index_row(self):
        self.journal({'quota_status': 'success'})
        result = self.index.refresh_if_stale()
        self.assertEqual(result['changed'], 1)
        self.assertEqual(self.index.get(1)['quota_status'], 'success')
        self.assertEqual(self.index.refresh_if_stale(force=True)['changed'], 0)

    def test_progress_does_not_reread_checkpoint(self):
        self.journal({'codex_status': 'running'})
        original = Path.read_text
        def read(path, *args, **kwargs):
            if path == self.source:
                raise AssertionError('checkpoint read on journal update')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'read_text', read):
            self.index.refresh_if_stale()
        self.assertEqual(self.index.get(1)['codex_connection_state'], 'running')

    def test_progress_cannot_smuggle_credentials_or_identity(self):
        self.journal({'email': 'changed@example.invalid', 'id': 999, 'totp_secret': 'FIXTURE_SECRET', 'has_codex_refresh_token': True, 'quota_status': 'success'})
        self.index.refresh_if_stale()
        row = self.index.get(1)
        self.assertEqual(row['email'], 'user_1@example.invalid')
        self.assertFalse(row['has_codex_refresh_token'])
        self.assertNotIn('FIXTURE_SECRET', json.dumps(row))

    def test_journal_identity_and_signature_checked(self):
        self.journal({'quota_status': 'success'}, email='other@example.invalid')
        self.index.refresh_if_stale()
        self.assertEqual(self.index.get(1)['quota_status'], 'unchecked')
        self.journal({'quota_status': 'success'}, signature=[1, 2, 3])
        self.index.refresh_if_stale()
        self.assertEqual(self.index.get(1)['quota_status'], 'unchecked')

    def test_journal_removal_restores_baseline(self):
        self.journal({'quota_status': 'success'})
        self.index.refresh_if_stale()
        self.source.with_name(self.source.name + '.progress.json').unlink()
        self.assertEqual(self.index.refresh_if_stale()['changed'], 1)
        self.assertEqual(self.index.get(1)['quota_status'], 'unchecked')

    def test_numeric_quota_values_do_not_trigger_false_updates(self):
        self.rows[0].update(quota_primary_used_percent=0, quota_secondary_used_percent=10, quota_ok=True)
        self.write_rows()
        self.assertEqual(self.index.refresh_if_stale()['changed'], 1)
        self.assertEqual(self.index.refresh_if_stale(force=True)['changed'], 0)

    def test_external_totp_in_active_filter(self):
        self.journal({'totp_status': 'active_external'})
        self.index.refresh_if_stale()
        self.assertEqual(self.index.query(totp_status='active')['total'], 1)

    def test_bad_quota_value_does_not_break_entire_index(self):
        self.journal({'quota_primary_used_percent': 'not-a-number', 'quota_status': 'success'})
        self.assertIsNotNone(self.indexer.refresh_once())
        self.assertIsNone(self.index.get(1)['quota_primary_used_percent'])
        self.assertEqual(self.index.get(1)['quota_status'], 'success')

    def test_changed_checkpoint_is_not_published_mid_read(self):
        def racing_loader():
            self.rows[0]['note'] = 'changed during read'
            self.write_rows()
            return self.rows
        self.index.loader = racing_loader
        with self.assertRaises(RuntimeError):
            self.index.refresh_if_stale(force=True)
        self.assertIsNone(self.index.get(1)['note'])

    def test_invalid_or_missing_source_preserves_last_good_snapshot(self):
        self.source.write_text('{invalid json')
        self.assertIsNone(self.indexer.refresh_once())
        self.assertEqual(self.index.count(), 6)
        self.assertTrue(self.indexer.status()['error'])
        self.source.unlink()
        self.assertIsNone(self.indexer.refresh_once())
        self.assertEqual(self.index.count(), 6)

    def test_checkpoint_deletion_updates_counts_without_batch_write(self):
        self.rows = self.rows[:-1]
        self.write_rows()
        result = self.index.refresh_if_stale()
        self.assertEqual(result['deleted'], 1)
        self.assertEqual(self.batches.query()['items'][0]['account_total'], 5)
        self.assertFalse(self.batches.refresh_if_stale()['refreshed'])

    def test_batches_are_safe_correctly_classified_and_counted(self):
        result = self.batches.query(driver='roxy')
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['items'][0]['account_total'], 6)
        self.assertNotIn('FIXTURE_SECRET', json.dumps(result))
        self.assertNotIn('flow_snapshot', result['items'][0])
        with sqlite3.connect(self.path) as conn:
            self.assertNotIn('FIXTURE_SECRET', conn.execute('SELECT data FROM batches').fetchone()[0])

    def test_mixed_batches_match_each_driver(self):
        self.batch_source.write_text(json.dumps([{'batch_id': 'batch1', 'registration_drivers': ['roxy', 'imported']}]))
        self.batches.refresh_if_stale()
        self.assertEqual(self.batches.query(driver='roxy')['total'], 1)
        self.assertEqual(self.batches.query(driver='imported')['total'], 1)
        self.assertEqual(self.batches.query()['items'][0]['registration_driver'], 'mixed')

    def test_batch_pagination(self):
        self.batch_source.write_text(json.dumps([{'batch_id': f'batch{i:04d}', 'created_at': '2026-01-01'} for i in range(150)]))
        self.batches.refresh_if_stale()
        result = self.batches.query(page=3, page_size=50)
        self.assertEqual(result['total'], 150)
        self.assertEqual(result['items'][0]['batch_id'], 'batch0049')

    def test_member_matching_does_not_guess_duplicate_email(self):
        self.rows[1]['email'] = self.rows[0]['email'].upper()
        self.write_rows()
        self.index.refresh_if_stale()
        matches = self.index.by_emails(['USER_1@EXAMPLE.INVALID', 'user_3@example.invalid'])
        self.assertIsNone(matches['user_1@example.invalid'])
        self.assertEqual(matches['user_3@example.invalid']['id'], 3)

    def test_legacy_raw_batch_cache_migration(self):
        path = self.root / 'old.sqlite3'
        accounts = AccountIndex(self.source, path)
        with sqlite3.connect(path) as conn:
            conn.execute('CREATE TABLE batches (batch_id TEXT PRIMARY KEY, data TEXT)')
            conn.execute('INSERT INTO batches VALUES (?, ?)', ('old', json.dumps({'flow_snapshot': {'api_key': 'LEGACY_MARKER_TO_PURGE'}})))
        migrated = BatchIndex(path, None, accounts, source_path=self.batch_source)
        self.assertEqual(migrated.query()['total'], 0)
        self.assertNotIn(b'LEGACY_MARKER_TO_PURGE', path.read_bytes())

    def test_sql_reads_do_not_wait_for_background_source_loader(self):
        entered, release = threading.Event(), threading.Event()
        def loader():
            entered.set()
            release.wait(5)
            return self.rows
        self.index.loader = loader
        thread = threading.Thread(target=lambda: self.index.refresh_if_stale(force=True))
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertEqual(self.index.query()['total'], 6)
        finally:
            release.set(); thread.join(2)
        self.assertFalse(thread.is_alive())

    def test_symlink_progress_uses_resolved_target(self):
        target = self.root / 'real' / 'accounts.json'
        target.parent.mkdir()
        self.source.rename(target)
        self.source.symlink_to(target)
        self.index.refresh_if_stale()
        target.with_name(target.name + '.progress.json').write_text(json.dumps({'accounts_signature': list(file_signature(target)), 'updates': {'1': {'email': 'user_1@example.invalid', 'created_at': '2026-01-01', 'fields': {'quota_status': 'success'}}}}))
        self.index.refresh_if_stale()
        self.assertEqual(self.index.get(1)['quota_status'], 'success')


if __name__ == '__main__':
    unittest.main()
