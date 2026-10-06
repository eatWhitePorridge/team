"""Read-only authorization task hierarchy; no real accounts or network calls."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from backend.progress import authorization_detail, collect_jobs
from core import account_completion_service as completion


def row(n, *, batch='submission', status='success', team=False, **extra):
    return dict(id=f'{batch}-{n}', batch_id=batch, batch_total=500, account_id=n,
                email=f'fixture-{n}@example.invalid', login_mode='password_totp',
                status=status, team_authorization=team, created_at='2026-09-30T12:00:00',
                updated_at='2026-09-30T12:01:00', password='PRIVATE',
                access_token='PRIVATE', refresh_token='PRIVATE', totp_secret='PRIVATE',
                cookies={'secret': 'PRIVATE'}, **extra)


class TaskDetailsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'pipeline.json'
        for name, value in (('_STATE_PATH', self.path), ('_STATE_CACHE', None)):
            p = patch.object(completion, name, value)
            p.start(); self.addCleanup(p.stop)
        self.services = SimpleNamespace(
            completion=completion,
            db=SimpleNamespace(account_completion_snapshot=Mock(return_value={'jobs': {}}),
                               _load_accounts=Mock(side_effect=AssertionError('no account scan'))),
            team_store=SimpleNamespace(list_parents=Mock(return_value=[])),
            authorization=SimpleNamespace(executor_status=Mock(return_value={'workers': 100, 'running': 0})))

    def save(self, rows):
        # Match production's atomic replacement, including on coarse-mtime tmpfs.
        pending = self.path.with_suffix('.tmp')
        pending.write_text(json.dumps(rows))
        pending.replace(self.path)

    def test_500_account_task_has_full_details_despite_shared_recent_100_window(self):
        self.save([row(n, status='failed' if n >= 490 else 'success') for n in range(500)])
        before = self.path.read_bytes(), self.path.stat().st_mtime_ns
        live = collect_jobs(self.services)
        self.assertEqual(len(live['pipeline']), 100)
        self.assertEqual(len(live['authorization']), 1)
        detail = authorization_detail(self.services, 'submission')
        self.assertEqual(len(detail['items']), 500)
        self.assertEqual(detail['total'], 500)
        batch = detail['batch']
        self.assertEqual((batch['success'], batch['failed'], batch['finished'], batch['active']), (490, 10, 500, 0))
        self.assertEqual((batch['known'], batch['missing']), (500, 0))
        self.assertTrue(batch['completed'])
        self.assertNotIn('PRIVATE', json.dumps(detail))
        self.assertEqual(before, (self.path.read_bytes(), self.path.stat().st_mtime_ns))
        self.services.db._load_accounts.assert_not_called()
        self.services.db.account_completion_snapshot.assert_not_called()

    def test_separate_submissions_modes_and_workspace_are_preserved(self):
        self.save([row(1), row(1, batch='team', team=True, expected_workspace_id='workspace-target'),
                   row(2, batch='team', team=True, expected_workspace_id='workspace-target')])
        normal = completion.authorization_batch_detail('submission')
        team = completion.authorization_batch_detail('team')
        self.assertEqual(len(normal['items']), 1)
        self.assertFalse(normal['batch']['team_authorization'])
        self.assertEqual(len(team['items']), 2)
        self.assertTrue(team['batch']['team_authorization'])
        self.assertEqual(team['batch']['expected_workspace_id'], 'workspace-target')
        self.assertTrue(all(r['batch_id'] == 'team' for r in team['items']))
        self.assertIsNone(completion.authorization_batch_detail('missing'))

    def test_missing_history_is_not_reported_as_success_or_full_completion(self):
        self.save([row(1, status='success'), row(2, status='cancelled')])
        batch = completion.authorization_batch_detail('submission')['batch']
        self.assertEqual((batch['known'], batch['total'], batch['missing']), (2, 500, 498))
        self.assertEqual((batch['success'], batch['cancelled'], batch['finished']), (1, 1, 2))
        self.assertFalse(batch['completed'])

    def test_active_child_phases_and_confirmation_match_global_live_progress(self):
        self.save([row(1, status='running', codex_job_id=1001), row(2, status='running', codex_job_id=1002)])
        self.services.db.account_completion_snapshot.return_value = {'jobs': {1001: {'status': 'running'}, 1002: {'status': 'success'}}}
        phases = {1001: {'stage': 'mfa', 'updated_at': 'fixture-time'}, 1002: {'stage': 'save_credential'}}
        detail = authorization_detail(self.services, 'submission', phases)
        self.assertEqual([r['progress_status'] for r in detail['items']], ['running', 'confirming'])
        self.assertEqual(detail['items'][0]['progress_message'], '验证 2FA')
        self.assertEqual((detail['batch']['running'], detail['batch']['confirming'], detail['batch']['finished']), (1, 1, 0))
        self.assertEqual(collect_jobs(self.services, phases)['authorization'][0], detail['batch'])
        self.services.db.account_completion_snapshot.assert_any_call([], [1001, 1002])
        persisted = json.loads(self.path.read_text())
        self.assertNotIn('progress_status', persisted[0])

    def test_reopening_or_refreshing_reads_persisted_results_without_starting_jobs(self):
        self.save([row(1, status='running')])
        with patch.object(completion, 'enqueue_accounts') as enqueue, patch.object(completion, '_write_rows') as write:
            first = completion.authorization_batch_detail('submission')
            self.save([row(1, status='success')])
            second = completion.authorization_batch_detail('submission')
            self.assertEqual(first['batch']['active'], 1)
            self.assertEqual(second['batch']['active'], 0)
            self.assertEqual(second['batch']['success'], 1)
            enqueue.assert_not_called(); write.assert_not_called()

    def test_unknown_or_cookie_flow_is_not_an_authorization_task(self):
        self.assertIsNone(completion.authorization_batch_detail('missing'))
        record = row(1); record['login_mode'] = 'cookie'
        self.save([record])
        self.assertIsNone(completion.authorization_batch_detail('submission'))

    def test_unreadable_progress_is_an_error_not_an_empty_success(self):
        self.path.write_text('{broken')
        with self.assertLogs(completion.logger, level='ERROR'):
            with self.assertRaisesRegex(RuntimeError, '读取失败'):
                completion.authorization_batch_detail('submission')

    def test_recent_task_limit_does_not_hide_active_or_directly_addressable_history(self):
        self.save([row(n, batch=f'b{n:02}', status='running' if n == 0 else 'success') for n in range(30)])
        snapshot = completion.progress_snapshot(batch_limit=20)
        self.assertEqual(len(snapshot['authorization']), 21)
        self.assertTrue(any(r['batch_id'] == 'b00' for r in snapshot['authorization']))
        self.assertNotIn('b01', [r['batch_id'] for r in snapshot['authorization']])
        self.assertEqual(completion.authorization_batch_detail('b01')['total'], 1)
        self.assertEqual(len(completion.progress_snapshot()['authorization']), 5)


if __name__ == '__main__':
    unittest.main()
