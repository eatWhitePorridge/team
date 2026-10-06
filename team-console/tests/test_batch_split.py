"""Run real split persistence/API/index checks in a completely isolated process."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class BatchSplitIntegrationTests(unittest.TestCase):
    def test_isolated_split_suite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(__file__).resolve().parents[1]
            env = {**os.environ, 'TEAM_CONSOLE_DATA_DIR': directory, 'PYTHON_DOTENV_DISABLED': '1',
                   'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(root)}
            result = subprocess.run([sys.executable, str(root / 'tests/batch_split_probe.py')],
                                    env=env, capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('OK', result.stderr)


if __name__ == '__main__':
    unittest.main()
