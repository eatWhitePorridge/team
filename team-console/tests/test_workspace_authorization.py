"""Isolated real authorization path; no real network, browser, or UI tests."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class WorkspaceAuthorizationTests(unittest.TestCase):
    def test_both_selectors_preserve_exact_target_through_worker_and_retries(self):
        console = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(console / 'tests/workspace_authorization_probe.py')],
                env={**os.environ, 'TEAM_CONSOLE_DATA_DIR': directory, 'PYTHON_DOTENV_DISABLED': '1',
                     'PYTHONDONTWRITEBYTECODE': '1', 'TEAM_CONSOLE_AUTH_WORKERS': '100', 'PYTHONPATH': str(console)},
                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report['selectors_verified'], 2)
        self.assertEqual(report['external_requests'], 0)
        for key in ('non_first_workspace_selected', 'target_survives_persistence_and_six_retries',
                    'wrong_workspace_never_saved', 'ordinary_unchanged'):
            self.assertTrue(report[key])
