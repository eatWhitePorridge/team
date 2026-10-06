import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class LiveProgressIntegrationTests(unittest.TestCase):
    def test_both_authorization_modes_push_real_intermediate_phases_before_completion(self):
        console = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, 'PYTHON_DOTENV_DISABLED': '1', 'PYTHONDONTWRITEBYTECODE': '1',
                   'TEAM_CONSOLE_DATA_DIR': directory, 'TEAM_CONSOLE_AUTH_WORKERS': '100', 'PYTHONPATH': str(console)}
            result = subprocess.run([sys.executable, str(console / 'tests/progress_probe.py')],
                                    env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        data = json.loads(result.stdout.splitlines()[0])
        self.assertEqual(data['modes'], 2)
        self.assertTrue(data['visible_before_completion'])
        self.assertEqual(data['workers'], 100)
        self.assertLess(data['phase_to_sse_ms'], 2000)
        self.assertEqual(data['external_requests'], 0)
