import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from container_server import run, server_options
from docker_healthcheck import check_health
from static_assets import check_static_assets


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

    def test_single_process_async_frontend_keeps_separate_wsgi_threads(self):
        from types import SimpleNamespace
        app = SimpleNamespace(extensions={'team_console': {'progress': object()}})
        with patch.dict(os.environ, {}, clear=True), patch('uvicorn.run') as serve:
            run(app)
        options = serve.call_args.kwargs
        self.assertEqual(options['workers'], 1)
        self.assertEqual(options['loop'], 'asyncio')
        self.assertEqual(options['ws'], 'none')
        adapter = serve.call_args.args[0]
        self.assertEqual(adapter.wsgi.executor._max_workers, 16)
        adapter.wsgi.executor.shutdown(wait=True)

    def probe(self, payload, key='fixture-only'):
        entry = MagicMock()
        entry.__enter__.return_value = entry
        entry.status = 200
        entry.headers = {'Content-Type': 'text/html; charset=utf-8'}
        with patch.dict(os.environ, {'TEAM_CONSOLE_API_KEY': key}, clear=True), \
             patch('docker_healthcheck.load_dotenv'), \
             patch('docker_healthcheck.check_static_assets'), \
             patch('docker_healthcheck.urlopen', side_effect=[io.BytesIO(json.dumps(payload).encode()), entry]) as fetch:
            check_health()
            self.assertEqual(fetch.call_args_list[1].args[0].get_method(), 'HEAD')
            self.assertNotIn('X-team-console-key', fetch.call_args_list[1].args[0].headers)
            return fetch.call_args_list[0].args[0]

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

    def test_healthcheck_fails_for_unreadable_frontend_before_http(self):
        with patch.dict(os.environ, {'TEAM_CONSOLE_API_KEY': 'fixture-only'}, clear=True), \
             patch('docker_healthcheck.load_dotenv'), \
             patch('docker_healthcheck.check_static_assets', side_effect=PermissionError(13, 'fixture')), \
             patch('docker_healthcheck.urlopen') as fetch:
            with self.assertRaises(PermissionError):
                check_health()
            fetch.assert_not_called()

    def test_healthcheck_rejects_bad_homepage_even_if_backend_is_healthy(self):
        for status, content_type in ((500, 'application/json'), (200, 'application/json')):
            entry = MagicMock()
            entry.__enter__.return_value = entry
            entry.status = status
            entry.headers = {'Content-Type': content_type}
            with patch.dict(os.environ, {'TEAM_CONSOLE_API_KEY': 'fixture-only'}, clear=True), \
                 patch('docker_healthcheck.load_dotenv'), patch('docker_healthcheck.check_static_assets'), \
                 patch('docker_healthcheck.urlopen', side_effect=[io.BytesIO(b'{"ok":true,"index":{"ready":true}}'), entry]):
                with self.assertRaises(RuntimeError):
                    check_health()


class StaticAssetsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / 'assets').mkdir()
        (self.root / 'index.html').write_text('<html><script src="/assets/index.js"></script><link href="/assets/index.css" rel="stylesheet"></html>')
        for name in ('index.js', 'index.css', 'lazy.js'):
            (self.root / 'assets' / name).write_text('fixture')

    def test_entry_and_lazy_chunks_are_checked(self):
        check_static_assets(self.root)
        (self.root / 'assets/lazy.js').write_text('')
        with self.assertRaises(RuntimeError):
            check_static_assets(self.root)

    def test_missing_referenced_asset_fails(self):
        (self.root / 'assets/index.js').unlink()
        with self.assertRaises(FileNotFoundError):
            check_static_assets(self.root)

    def test_unreadable_directory_fails(self):
        self.root.chmod(0o700)
        with patch.object(Path, 'read_text', side_effect=PermissionError(13, 'fixture')):
            with self.assertRaises(PermissionError):
                check_static_assets(self.root)

    def test_bundle_cannot_reference_private_file(self):
        (self.root / 'index.html').write_text('<script src="/assets/../private.env"></script>')
        with self.assertRaises(RuntimeError):
            check_static_assets(self.root)

    def test_docker_normalizes_only_public_assets_and_checks_nonroot(self):
        text = (Path(__file__).resolve().parents[1] / 'Dockerfile').read_text()
        self.assertIn('find team-console/frontend/dist -type d -exec chmod 755', text)
        self.assertIn('find team-console/frontend/dist -type f -exec chmod 644', text)
        self.assertLess(text.index('USER 10001:10001'), text.index('RUN python static_assets.py'))
        self.assertNotIn('chmod -R 777', text)
