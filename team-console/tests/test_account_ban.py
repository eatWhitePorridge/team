"""Terminal authorization outcomes through real storage/queues; no live HTTP/UI."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class AccountBanTests(unittest.TestCase):
    def test_ban_stops_both_retry_layers_and_is_visible(self):
        console = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(console / 'tests/account_ban_probe.py')],
                env={**os.environ, 'TEAM_CONSOLE_DATA_DIR': directory, 'PYTHON_DOTENV_DISABLED': '1',
                     'PYTHONDONTWRITEBYTECODE': '1', 'TEAM_CONSOLE_AUTH_WORKERS': '100',
                     'PYTHONPATH': str(console)}, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report['terminal_flows'], 8)
        self.assertEqual(report['external_requests'], 0)
        self.assertTrue(report['admission_race_stopped'])
        self.assertTrue(report['generic_403_not_banned'])
