"""Isolated preflight/authorization budgets; no upstream requests or UI tests."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class PreflightRetryTests(unittest.TestCase):
    def test_separate_budget_in_both_authorization_modes_and_coordinator(self):
        console = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(console / 'tests/preflight_retry_probe.py')],
                env={**os.environ, 'TEAM_CONSOLE_DATA_DIR': directory, 'PYTHON_DOTENV_DISABLED': '1',
                     'PYTHONDONTWRITEBYTECODE': '1', 'TEAM_CONSOLE_AUTH_WORKERS': '100',
                     'PYTHONPATH': str(console)}, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report['integration_flows'], 5)
        self.assertEqual(report['boundary_cases'], 10)
        self.assertEqual(report['external_requests'], 0)
        self.assertEqual(report['preflight_limit'], 10)
        self.assertTrue(report['team_budget_preserved'])
        self.assertTrue(report['all_sessions_closed'])
