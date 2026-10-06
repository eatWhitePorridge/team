"""Mother deletion uses isolated storage, never a real account or upstream API."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ParentDeletionTests(unittest.TestCase):
    def test_routes_scope_busy_and_identity_guards(self):
        console = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(console / 'tests/parent_deletion_probe.py')],
                env={**os.environ, 'TEAM_CONSOLE_DATA_DIR': directory,
                     'PYTHON_DOTENV_DISABLED': '1', 'PYTHONDONTWRITEBYTECODE': '1',
                     'PYTHONPATH': str(console)},
                capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('Ran 9 tests', result.stderr)
        self.assertIn('OK', result.stderr)
