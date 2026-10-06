import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class DispatchScaleTests(unittest.TestCase):
    def test_351_accounts_large_history_full_capacity_and_first_completion_over_sse(self):
        console = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, 'PYTHON_DOTENV_DISABLED': '1', 'TEAM_CONSOLE_DATA_DIR': directory,
                   'TEAM_CONSOLE_AUTH_WORKERS': '100', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(console)}
            result = subprocess.run([sys.executable, str(console / 'tests/dispatch_scale_probe.py')],
                                    env=env, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        report = json.loads(result.stdout.splitlines()[0])
        self.assertEqual(report['peak_oauth_calls'], 100)
        self.assertEqual(report['bulk_submissions'], 4)
        self.assertTrue(report['next_started_while_350_unfinished'])
        self.assertGreater(sum(report['history_bytes'].values()), 10 * 1024 * 1024)
        self.assertLess(report['ramp_seconds'], 10)
        self.assertLess(report['commit_to_sse_ms'], 2000)
        self.assertEqual(report['external_requests'], 0)
