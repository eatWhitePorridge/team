"""Independent pending invitation regression flow; no browser or remote writes."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class PendingInvitationTests(unittest.TestCase):
    def test_real_routes_storage_worker_patch_and_progress(self):
        console = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(console / 'tests/pending_invites_probe.py')],
                env={**os.environ, 'TEAM_CONSOLE_DATA_DIR': directory, 'PYTHON_DOTENV_DISABLED': '1',
                     'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(console)},
                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('OK', result.stderr)
