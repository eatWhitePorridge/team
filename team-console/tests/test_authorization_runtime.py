import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from backend.authorization_runtime import configure


class AuthorizationRuntimeTests(unittest.TestCase):
    def test_legacy_default_and_fixed_pool_cannot_be_resized_by_reload(self):
        script = r'''
import sys
sys.path.insert(0, sys.argv[1])
from core import codex_retry_service as retry
from config import codex
import config
assert retry.get_executor_workers() == codex.CODEX_RETRY_WORKERS == 50
retry.get_executor(6)
try: retry.configure_executor_limit(100)
except RuntimeError: pass
else: raise AssertionError('unsafe pool replacement allowed')
retry.shutdown_executor()
for invalid in (0, 101, True, '100'):
    try: retry.configure_executor_limit(invalid)
    except ValueError: pass
    else: raise AssertionError('invalid limit accepted')
retry.configure_executor_limit(100)
pool = retry.get_executor(2)
config.reload_all()
assert retry.get_executor() is pool and pool._max_workers == 100
assert retry.get_executor(50) is pool and not retry._codex_retired_executors
try: retry.configure_executor_limit(99)
except RuntimeError: pass
else: raise AssertionError('fixed cap changed')
retry.configure_executor_limit(100)
assert retry.executor_status()['workers'] == 100
retry.shutdown_executor()
'''
        root = Path(__file__).resolve().parents[2]
        env = {**os.environ, 'PYTHON_DOTENV_DISABLED':'1', 'PYTHONDONTWRITEBYTECODE':'1', 'CODEX_RETRY_WORKERS':'50'}
        result = subprocess.run([sys.executable, '-c', script, str(root)], env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_isolated_console_defaults_to_100(self):
        retry = Mock()
        with patch.dict(os.environ, {}, clear=True):
            self.assertIs(configure(retry), retry)
        retry.configure_executor_limit.assert_called_once_with(100)

    def test_explicit_capacity_validation(self):
        for value in ('1', '50', '100'):
            with self.subTest(value=value), patch.dict(os.environ, {'TEAM_CONSOLE_AUTH_WORKERS':value}):
                retry = Mock(); configure(retry)
                retry.configure_executor_limit.assert_called_once_with(int(value))
        for value in ('0', '101', '-1', '2.5', 'true'):
            with self.subTest(value=value), patch.dict(os.environ, {'TEAM_CONSOLE_AUTH_WORKERS':value}):
                retry = Mock()
                with self.assertRaises(ValueError): configure(retry)
                retry.configure_executor_limit.assert_not_called()

    def test_100_real_workers_and_immediate_refill_through_both_api_modes(self):
        console = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, 'TEAM_CONSOLE_DATA_DIR':directory, 'PYTHON_DOTENV_DISABLED':'1',
                   'TEAM_CONSOLE_AUTH_WORKERS':'100', 'PYTHONDONTWRITEBYTECODE':'1', 'PYTHONPATH':str(console)}
            result = subprocess.run([sys.executable, str(console/'tests/concurrency_probe.py')],
                                    env=env, capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            report = json.loads(result.stdout.splitlines()[0])
            self.assertEqual(report['peak_oauth_calls'], 100)
            self.assertEqual(report['initial_queued'], 20)
            self.assertEqual(report['refill_started_before_batch_finished'], 101)
            self.assertEqual(report['external_requests'], 0)
            self.assertIn('cleanup passed', result.stdout)
