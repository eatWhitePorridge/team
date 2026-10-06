import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from backend.batch_operations import BatchOperationError, batch_ids, delete_batches, merge_batches


class BatchOperationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        state = Path(self.tmp.name) / 'pipeline.json'
        state.write_text('[]')
        self.completion = SimpleNamespace(_STATE_PATH=state, _LOCK=threading.RLock())
        self.batches = [{'batch_id': name, 'flow_snapshot': {'registration_driver': 'imported', 'api_key': 'SECRET'}}
                        for name in ('a', 'b', 'empty')]
        self.accounts = [{'id': 1, 'registration_batch_id': 'a'},
                         {'id': 2, 'registration_batch_id': 'b', 'archived': True},
                         {'id': 3, 'registration_batch_id': 'unrelated'}]
        self.db = SimpleNamespace(
            _LOCK=threading.RLock(), _load_batches=Mock(return_value=self.batches),
            _load_accounts=Mock(return_value=self.accounts),
            get_account_supplement_candidates=Mock(return_value={}),
            get_registration_batch=Mock(return_value=self.batches[0]),
            BatchMergeConflict=type('MergeConflict', (ValueError,), {}),
            BatchDeleteConflict=type('DeleteConflict', (ValueError,), {}),
            merge_registration_batches=Mock(return_value={
                'target_batch_id': 'a', 'merged_batch_ids': ['b'], 'merged_count': 1,
                'moved_accounts': 1, 'moved_jobs': 0, 'moved_allocations': 0, 'already_merged': False,
                'private': 'SECRET'}),
            delete_registration_batches=Mock(return_value={
                'deleted_batch_ids': ['a', 'b'], 'deleted_count': 2,
                'deleted_account_count': 2, 'deleted_job_count': 0, 'deleted_allocation_count': 0,
                'private': 'SECRET'}),
        )
        self.indexer = SimpleNamespace(apply_batch_merge=Mock(), apply_batch_delete=Mock())

    def merge(self, ids=None, target='a'):
        return merge_batches(self.db, self.completion, ids or ['a', 'b'], target, indexer=self.indexer)

    def delete(self, ids=None):
        return delete_batches(self.db, self.completion, ids or ['a', 'b'], indexer=self.indexer)

    def test_batch_id_validation_and_deduplication(self):
        self.assertEqual(batch_ids({'batch_ids': [' a ', 'b', 'a']}, minimum=2), ['a', 'b'])
        for ids in (None, 'all', [], [True], [1], [' '], ['x' * 129], ['a'] * 201):
            with self.subTest(ids_type=type(ids).__name__):
                with self.assertRaises(ValueError):
                    batch_ids({'batch_ids': ids})
        with self.assertRaises(ValueError):
            batch_ids({'batch_ids': ['a', 'a']}, minimum=2)

    def test_merge_preserves_target_and_whitelists_result_and_index_payload(self):
        result = self.merge()
        self.db.merge_registration_batches.assert_called_once_with(target_batch_id='a', batch_ids=['a', 'b'])
        self.db.get_account_supplement_candidates.assert_called_once_with([1, 2])
        self.assertEqual(result['target_batch_id'], 'a')
        self.assertEqual(result['moved_accounts'], 1)
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertNotIn('SECRET', json.dumps(self.indexer.apply_batch_merge.call_args.args[1]))

    def test_delete_is_one_cascade_and_includes_archived_accounts(self):
        result = self.delete()
        self.db.delete_registration_batches.assert_called_once_with(batch_ids=['a', 'b'])
        self.indexer.apply_batch_delete.assert_called_once_with(['a', 'b'], [1, 2])
        self.assertEqual(result['deleted_account_count'], 2)
        self.assertNotIn('SECRET', json.dumps(result))

    def test_empty_import_batch_can_be_deleted(self):
        self.db.delete_registration_batches.return_value.update(deleted_batch_ids=['empty'], deleted_count=1, deleted_account_count=0)
        self.assertTrue(self.delete(['empty'])['ok'])
        self.indexer.apply_batch_delete.assert_called_once_with(['empty'], [])

    def test_invalid_target_is_rejected_before_loading_business_state(self):
        for target in (None, 1, 'outside', ' '):
            with self.assertRaises(ValueError):
                self.merge(target=target)
        self.db._load_batches.assert_not_called()
        self.db.merge_registration_batches.assert_not_called()

    def test_missing_batch_aborts_whole_selection_before_any_write(self):
        for operation in (self.merge, self.delete):
            with self.assertRaises(BatchOperationError) as raised:
                operation(['a', 'missing'])
            self.assertEqual(raised.exception.status, 404)
        self.db.merge_registration_batches.assert_not_called()
        self.db.delete_registration_batches.assert_not_called()

    def test_internal_and_mixed_batches_are_not_allowed(self):
        for fields in ({'flow_snapshot': {'registration_driver': 'protocol'}},
                       {'registration_drivers': ['imported', 'roxy']}):
            with self.subTest(fields=fields):
                self.batches[1].update(fields)
                for operation in (self.merge, self.delete):
                    with self.assertRaises(BatchOperationError):
                        operation()
        self.db.merge_registration_batches.assert_not_called()
        self.db.delete_registration_batches.assert_not_called()

    def test_queued_authorization_and_retry_gap_block_whole_selection(self):
        for status in ('queued', 'running'):
            self.completion._STATE_PATH.write_text(json.dumps([
                {'account_id': 2, 'status': status, 'stage': 'codex_pending'},
                *[{'account_id': 3, 'status': 'success'} for _ in range(5001)],
            ]))
            for operation in (self.merge, self.delete):
                with self.assertRaises(BatchOperationError) as raised:
                    operation()
                self.assertEqual(raised.exception.busy[0]['id'], 2)
        self.db.merge_registration_batches.assert_not_called()
        self.db.delete_registration_batches.assert_not_called()

    def test_quota_tasks_block_both_operations_but_unrelated_authorization_does_not(self):
        self.completion._STATE_PATH.write_text('[{"account_id":3,"status":"running"}]')
        self.assertTrue(self.merge()['ok'])
        self.assertTrue(self.delete()['ok'])
        self.db.get_account_supplement_candidates.return_value = {2: {'id': 2, 'quota_busy': True}}
        for operation in (self.merge, self.delete):
            with self.assertRaises(BatchOperationError) as raised:
                operation()
            self.assertIn('额度', raised.exception.busy[0]['reason'])

    def test_core_busy_conflicts_are_reported_without_changing_index(self):
        self.db.merge_registration_batches.side_effect = self.db.BatchMergeConflict('关联任务运行中')
        self.db.delete_registration_batches.side_effect = self.db.BatchDeleteConflict('关联任务运行中')
        for operation in (self.merge, self.delete):
            with self.assertRaises(BatchOperationError) as raised:
                operation()
            self.assertEqual(raised.exception.status, 409)
        self.indexer.apply_batch_merge.assert_not_called()
        self.indexer.apply_batch_delete.assert_not_called()

    def test_persist_error_is_not_retried_or_reported_as_success(self):
        self.db.merge_registration_batches.side_effect = OSError('fixture disk failure')
        self.db.delete_registration_batches.side_effect = OSError('fixture disk failure')
        for operation in (self.merge, self.delete):
            with self.assertRaises(OSError):
                operation()
        self.db.merge_registration_batches.assert_called_once()
        self.db.delete_registration_batches.assert_called_once()
        self.indexer.apply_batch_merge.assert_not_called()
        self.indexer.apply_batch_delete.assert_not_called()

    def test_index_failure_keeps_committed_mutation_success(self):
        self.indexer.apply_batch_merge.side_effect = OSError('fixture cache failure')
        self.indexer.apply_batch_delete.side_effect = OSError('fixture cache failure')
        for operation in (self.merge, self.delete):
            result = operation()
            self.assertTrue(result['ok'])
            self.assertEqual(len(result['warnings']), 1)

    def test_lock_is_held_until_both_indexes_are_updated(self):
        entered, attempted = threading.Event(), threading.Event()

        def enqueue():
            attempted.set()
            with self.completion._LOCK, self.db._LOCK:
                entered.set()

        worker = threading.Thread(target=enqueue)

        def update(*args):
            worker.start()
            self.assertTrue(attempted.wait(1))
            self.assertFalse(entered.wait(0.05))

        self.indexer.apply_batch_merge.side_effect = update
        try:
            self.merge()
        finally:
            worker.join(2)
        self.assertTrue(entered.is_set())
        self.assertFalse(worker.is_alive())


if __name__ == '__main__':
    unittest.main()
