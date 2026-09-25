import io
import json
import os
import unittest
from unittest.mock import patch

from container_server import server_options
from docker_healthcheck import check_health


class ContainerTests(unittest.TestCase):
    def test_http_threads_are_separate_from_business_concurrency(self):
        with patch.dict(os.environ, {'CODEX_RETRY_WORKERS': '50'}, clear=True):
            options = server_options()
        self.assertEqual(options['threads'], 16)
        self.assertEqual(options['max_request_body_size'], 8 * 1024 * 1024)

    def test_http_threads_are_bounded(self):
        for value in ('0', '-1', '65', 'many'):
            with patch.dict(os.environ, {'TEAM_CONSOLE_HTTP_THREADS': value}, clear=True):
                with self.assertRaises(ValueError):
                    server_options()

    def probe(self, payload, key='fixture-only'):
        with patch.dict(os.environ, {'TEAM_CONSOLE_API_KEY': key}, clear=True), \
             patch('docker_healthcheck.load_dotenv'), \
             patch('docker_healthcheck.urlopen', return_value=io.BytesIO(json.dumps(payload).encode())) as fetch:
            check_health()
            return fetch.call_args.args[0]

    def test_authenticated_healthcheck(self):
        req = self.probe({'ok': True, 'index': {'ready': True, 'error': ''}})
        self.assertEqual(req.full_url, 'http://127.0.0.1:5050/api/health')
        self.assertEqual(req.headers['X-team-console-key'], 'fixture-only')
        self.assertNotIn('fixture-only', req.full_url)

    def test_healthcheck_rejects_unready_or_stale_index(self):
        for index in ({'ready': False}, {'ready': True, 'error': 'source unreadable'}):
            with self.assertRaises(RuntimeError):
                self.probe({'ok': True, 'index': index})

    def test_healthcheck_fails_closed_without_key(self):
        with self.assertRaises(RuntimeError):
            self.probe({'ok': True, 'index': {'ready': True}}, key='')
