"""Billing cache/API tests run only in disposable storage with mocked HTTP."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class BillingTimeIntegrationTests(unittest.TestCase):
    def test_read_only_preview_timezone_provenance_and_cache(self):
        console = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(console / 'tests/billing_time_probe.py')],
                env={**os.environ, 'TEAM_CONSOLE_DATA_DIR': directory,
                     'PYTHON_DOTENV_DISABLED': '1', 'PYTHONDONTWRITEBYTECODE': '1',
                     'PYTHONPATH': str(console)}, capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('Ran 13 tests', result.stderr)
        self.assertIn('OK', result.stderr)
