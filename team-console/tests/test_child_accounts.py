"""Real cached membership and account route, in disposable storage only."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ChildAccountsIntegrationTests(unittest.TestCase):
    def test_workspace_scoped_local_accounts(self):
        console = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(console / 'tests/child_accounts_probe.py')],
                env={**os.environ, 'TEAM_CONSOLE_DATA_DIR': directory,
                     'PYTHON_DOTENV_DISABLED': '1', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(console)},
                capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('Ran 7 tests', result.stderr)
        self.assertIn('OK', result.stderr)
