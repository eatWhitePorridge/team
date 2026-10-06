import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from backend.account_deletion import delete_accounts


class AccountDeletionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / 'pipeline.json'
        self.state.write_text('[]')
        self.completion = SimpleNamespace(_STATE_PATH=self.state, _LOCK=threading.RLock())
        self.db = SimpleNamespace(_LOCK=threading.RLock(),
                                  get_account_supplement_candidates=Mock(return_value={}),
                                  delete_accounts=Mock(return_value=([{'id': 1, 'email': 'one@example.invalid'}], [])))
        self.index = SimpleNamespace(remove_accounts=Mock())

    def delete(self, ids):
        return delete_accounts(self.db, self.completion, ids, index=self.index)

    def test_bulk_operation_is_one_call_and_reports_only_public_fields(self):
        self.db.delete_accounts.return_value = (
            [{'id': 1, 'email': 'one@example.invalid', 'password': 'SECRET'}],
            [{'id': 2, 'reason': '账号不存在', 'access_token': 'SECRET'}],
        )
        result = self.delete([1, 2])
        self.db.get_account_supplement_candidates.assert_called_once_with([1, 2])
        self.db.delete_accounts.assert_called_once_with(account_ids=[1, 2])
        self.index.remove_accounts.assert_called_once_with([1])
        self.assertTrue(result['ok'])
        self.assertEqual((result['deleted_count'], result['skipped_count']), (1, 1))
        self.assertNotIn('SECRET', json.dumps(result))

    def test_active_authorization_beyond_task_page_and_between_retries_is_protected(self):
        self.state.write_text(json.dumps([
            {'account_id': 1, 'status': 'running', 'stage': 'codex_pending', 'next_attempt_at': 9999999999},
            *[{'account_id': 2, 'status': 'success'} for _ in range(5001)],
        ]))
        result = self.delete([1])
        self.assertFalse(result['ok'])
        self.assertIn('重试', result['skipped'][0]['reason'])
        self.db.delete_accounts.assert_not_called()
        self.index.remove_accounts.assert_not_called()

    def test_all_active_coordinator_states_block_deletion(self):
        for status in ('pending', 'queued', 'running', 'retrying', 'stopping'):
            with self.subTest(status=status):
                self.state.write_text(json.dumps([{'account_id': 1, 'status': status}]))
                self.assertFalse(self.delete([1])['ok'])
        self.db.delete_accounts.assert_not_called()

    def test_active_supplement_tasks_are_skipped_not_cancelled(self):
        for field in ('quota_busy', 'team_busy', 'totp_busy', 'health_busy', 'codex_status'):
            with self.subTest(field=field):
                self.db.get_account_supplement_candidates.return_value = {
                    1: {'id': 1, field: 'running' if field == 'codex_status' else True},
                }
                self.assertFalse(self.delete([1])['ok'])
        self.db.delete_accounts.assert_not_called()

    def test_mixed_selection_preserves_busy_account(self):
        self.db.get_account_supplement_candidates.return_value = {2: {'id': 2, 'quota_busy': True}}
        result = self.delete([1, 2])
        self.db.delete_accounts.assert_called_once_with(account_ids=[1])
        self.assertEqual(result['skipped'][0]['id'], 2)
        self.assertEqual(result['deleted_count'], 1)

    def test_terminal_pipeline_does_not_permanently_block_delete(self):
        for status in ('success', 'failed', 'cancelled'):
            with self.subTest(status=status):
                self.state.write_text(json.dumps([{'account_id': 1, 'status': status}]))
                self.assertTrue(self.delete([1])['ok'])

    def test_unreadable_task_state_fails_closed(self):
        for payload in ('{invalid', '{}', '[null]', '[{"account_id":true,"status":"running"}]'):
            with self.subTest(payload=payload):
                self.state.write_text(payload)
                with self.assertRaises(RuntimeError):
                    self.delete([1])
        self.db.delete_accounts.assert_not_called()
        self.index.remove_accounts.assert_not_called()

    def test_db_error_does_not_evict_accounts_or_report_success(self):
        self.db.delete_accounts.side_effect = OSError('fixture storage failure')
        with self.assertRaises(OSError):
            self.delete([1])
        self.index.remove_accounts.assert_not_called()

    def test_index_error_does_not_misreport_committed_delete_as_failure(self):
        self.index.remove_accounts.side_effect = OSError('fixture index failure')
        result = self.delete([1])
        self.assertTrue(result['ok'])
        self.assertEqual(result['deleted_count'], 1)
        self.assertEqual(len(result['warnings']), 1)
        self.db.delete_accounts.assert_called_once()

    def test_enqueue_cannot_enter_between_busy_check_and_deletion(self):
        attempted, entered = threading.Event(), threading.Event()

        def enqueue():
            attempted.set()
            with self.completion._LOCK, self.db._LOCK:
                entered.set()

        thread = threading.Thread(target=enqueue)

        def evict(ids):
            thread.start()
            self.assertTrue(attempted.wait(1))
            self.assertFalse(entered.wait(0.05))

        self.index.remove_accounts.side_effect = evict
        try:
            self.assertTrue(self.delete([1])['ok'])
        finally:
            thread.join(2)
        self.assertTrue(entered.is_set())
        self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()
