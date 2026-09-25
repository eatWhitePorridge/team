import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backend.storage_scope import bind_database, bind_service_paths, data_directory, CONSOLE_ROOT


class StorageScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.legacy = self.root / 'legacy'
        self.legacy.mkdir()
        self.directory = self.root / 'console'
        self.db = SimpleNamespace(_PROJECT_ROOT=self.legacy, _DATA_DIR=self.legacy,
                                  _ACCOUNTS_JSON=self.legacy / '注册成功的邮箱.json',
                                  _BATCHES_JSON=self.legacy / '注册批次.json',
                                  _JOBS_JSON=self.legacy / '注册任务.json',
                                  _COOKIE_DIR=self.legacy / 'account_cookies',
                                  _CODEX_DIR=self.legacy / 'codex_accounts',
                                  _LEGACY_ACCOUNTS_JSON=self.legacy / 'data/registered_accounts.json',
                                  _JSON_CACHE={})
        self.db._ACCOUNTS_JSON.write_text('[{"id":777,"email":"history@example.invalid"}]')
        self.legacy_bytes = self.db._ACCOUNTS_JSON.read_bytes()

    def test_default_directory_is_new_console_store(self):
        with patch.dict(os.environ, {'TEAM_CONSOLE_DATA_DIR': ''}):
            self.assertEqual(data_directory(), CONSOLE_ROOT / 'data/store')

    def test_rebinds_all_data_paths_without_copying_or_deleting_history(self):
        bind_database(self.db, self.directory)
        for name, value in vars(self.db).items():
            if isinstance(value, Path) and name != '_TEAM_CONSOLE_ORIGINAL_ROOT':
                self.assertTrue(value.is_relative_to(self.directory), name)
        self.assertEqual(json.loads(self.db._ACCOUNTS_JSON.read_text()), [])
        self.assertEqual((self.legacy / '注册成功的邮箱.json').read_bytes(), self.legacy_bytes)
        self.assertFalse(self.db._LEGACY_ACCOUNTS_JSON.exists())

    def test_new_records_are_retained_across_rebinding(self):
        bind_database(self.db, self.directory)
        self.db._ACCOUNTS_JSON.write_text('[{"id":1}]')
        bind_database(self.db, self.directory)
        self.assertEqual(json.loads(self.db._ACCOUNTS_JSON.read_text()), [{'id': 1}])

    def test_refuses_hot_switch_of_bound_process(self):
        bind_database(self.db, self.directory)
        with self.assertRaises(RuntimeError):
            bind_database(self.db, self.root / 'different')

    def test_refuses_old_project_root_or_parent(self):
        for path in (self.legacy, self.root):
            with self.assertRaises(ValueError):
                bind_database(self.db, path)
        self.assertEqual(self.db._ACCOUNTS_JSON.read_bytes(), self.legacy_bytes)

    def test_refuses_symlink_back_to_history(self):
        self.directory.mkdir()
        (self.directory / '注册成功的邮箱.json').symlink_to(self.db._ACCOUNTS_JSON)
        with self.assertRaises(ValueError):
            bind_database(self.db, self.directory)
        self.assertEqual(self.db._ACCOUNTS_JSON.read_bytes(), self.legacy_bytes)

    def test_refuses_rebinding_an_already_used_legacy_database(self):
        self.db._JSON_CACHE['old'] = object()
        with self.assertRaises(RuntimeError):
            bind_database(self.db, self.directory)
        self.assertFalse(self.directory.exists())

    def test_secondary_stores_scoped_and_cache_not_reset_again(self):
        modules = {name: SimpleNamespace() for name in ('completion', 'retry', 'oauth', 'cookies', 'diagnostics', 'account_export')}
        modules['oauth']._cfg = SimpleNamespace(CODEX_OUTPUT_DIRNAME='/old/output')
        bind_service_paths(self.directory, **modules)
        self.assertEqual(modules['completion']._STATE_PATH, self.directory / '一键补全任务.json')
        self.assertEqual(modules['retry']._LOG_DIR, self.directory / '注册日志')
        self.assertEqual(modules['oauth']._PROJECT_ROOT, self.directory)
        self.assertEqual(modules['oauth']._cfg.CODEX_OUTPUT_DIRNAME, 'codex_accounts')
        self.assertEqual(modules['cookies']._DEFAULT_COOKIE_DIR, self.directory / 'account_cookies')
        self.assertTrue(modules['diagnostics']._LOG_PATH.is_relative_to(self.directory))
        self.assertTrue(modules['account_export']._ACCOUNTS_DIR.is_relative_to(self.directory))
        modules['completion']._STATE_CACHE = 'new-live-state'
        bind_service_paths(self.directory, **modules)
        self.assertEqual(modules['completion']._STATE_CACHE, 'new-live-state')


if __name__ == '__main__':
    unittest.main()
