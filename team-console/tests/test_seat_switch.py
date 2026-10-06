"""Seat-switch regressions in isolated storage; never contacts upstream APIs."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class SeatSwitchTests(unittest.TestCase):
    def test_limits_backoff_cancellation_and_progress(self):
        console = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, 'TEAM_CONSOLE_DATA_DIR': directory,
                   'PYTHON_DOTENV_DISABLED': '1', 'PYTHONDONTWRITEBYTECODE': '1',
                   'PYTHONPATH': str(console)}
            result = subprocess.run([sys.executable, str(console / 'tests/seat_switch_probe.py')],
                                    env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('Ran 10 tests', result.stderr)
        self.assertIn('OK', result.stderr)
