"""Offline end-to-end fixed mother proxy regression; never touches live storage."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ParentProxyIntegrationTests(unittest.TestCase):
    def test_fixed_proxy_contract(self):
        console = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(console / 'tests/parent_proxy_probe.py')],
                env={**os.environ, 'TEAM_CONSOLE_DATA_DIR': directory, 'PYTHON_DOTENV_DISABLED': '1',
                     'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(console)},
                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('OK', result.stderr)
        self.assertIn('Ran 17 tests', result.stderr)
