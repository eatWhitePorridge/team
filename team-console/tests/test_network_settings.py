import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backend.network_settings import NetworkSettings, masked_proxy, normalize_proxy


class NetworkSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'network-settings.json'
        self.config = SimpleNamespace(PROXY_POOL=['socks5h://fixture-user:fixture-secret@proxy.invalid:1080'],
                                      PLAN_CHECK_PROXY_MODE='proxy', PLAN_CHECK_PROXY='')
        self.top = SimpleNamespace()
        self.store = NetworkSettings(self.path, self.config, self.top)

    def test_deployment_configuration_is_kept_without_writing_overrides(self):
        self.assertEqual(self.store.public()['pool_count'], 1)
        self.assertEqual(self.store.public()['source'], 'deployment')
        self.assertFalse(self.path.exists())

    def test_public_response_never_contains_proxy_credentials(self):
        self.store.update({'quota_proxy_action': 'replace', 'quota_proxy': 'socks5h://another-user:another-secret@quota.invalid:1080'})
        text = json.dumps(self.store.public())
        for credential in ('fixture-user', 'fixture-secret', 'another-user', 'another-secret'):
            self.assertNotIn(credential, text)
        self.assertIn('***:***@quota.invalid:1080', text)

    def test_replace_applies_to_shared_runtime_config_and_retains_previous_session_snapshot(self):
        previous_pool = self.config.PROXY_POOL
        self.store.update({'pool_action': 'replace', 'proxy_pool': 'proxy.invalid:1081:user:p@ss\nproxy.invalid:1081:user:p@ss'})
        self.assertEqual(self.config.PROXY_POOL, ['socks5h://user:p%40ss@proxy.invalid:1081'])
        self.assertEqual(self.top.PROXY_POOL, self.config.PROXY_POOL)
        self.assertIn('fixture-secret', previous_pool[0])
        self.assertEqual(self.store.public()['pool_count'], 1)

    def test_restart_retains_private_overrides(self):
        self.store.update({'pool_action': 'clear', 'quota_proxy_mode': 'direct'})
        proxy = SimpleNamespace(PROXY_POOL=['http://old.invalid:1'], PLAN_CHECK_PROXY_MODE='proxy', PLAN_CHECK_PROXY='')
        restored = NetworkSettings(self.path, proxy, SimpleNamespace())
        self.assertEqual(proxy.PROXY_POOL, [])
        self.assertEqual(proxy.PLAN_CHECK_PROXY_MODE, 'direct')
        self.assertEqual(restored.public()['source'], 'override')
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_keep_does_not_clear_existing_pool(self):
        self.store.update({'pool_action': 'keep', 'proxy_pool': '', 'quota_proxy_mode': 'auto'})
        self.assertEqual(self.store.public()['pool_count'], 1)
        self.assertEqual(self.config.PLAN_CHECK_PROXY_MODE, 'auto')

    def test_invalid_input_never_changes_runtime_or_disk(self):
        for data in ({'pool_action': 'replace', 'proxy_pool': ''},
                     {'pool_action': 'replace', 'proxy_pool': 'file://secret.invalid:123'},
                     {'pool_action': 'replace', 'proxy_pool': 'socks5h://fixture-secret@bad.invalid:bad'},
                     {'quota_proxy_mode': 'invalid'}, {'unexpected': 'value'}):
            with self.assertRaises(ValueError) as caught:
                self.store.update(data)
            self.assertNotIn('fixture-secret', str(caught.exception))
            self.assertFalse(self.path.exists())
            self.assertEqual(self.store.public()['source'], 'deployment')

    def test_write_failure_preserves_previous_settings_and_cleans_temp_file(self):
        self.store.update({'quota_proxy_mode': 'auto'})
        before = self.path.read_bytes()
        with patch('backend.network_settings.os.replace', side_effect=OSError('fixture')):
            with self.assertRaises(OSError):
                self.store.update({'pool_action': 'clear'})
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(len(self.config.PROXY_POOL), 1)
        self.assertEqual(list(self.path.parent.glob('.network-*')), [])

    def test_proxy_validation_and_masking(self):
        self.assertEqual(normalize_proxy('localhost:8080'), 'http://localhost:8080')
        self.assertEqual(masked_proxy('socks5h://user:secret@[::1]:1080'), 'socks5h://***:***@[::1]:1080')
        for value in ('socks5h://***:***@host:1234', 'http://host:90000', 'http://host:12/?secret=x'):
            with self.assertRaises(ValueError):
                normalize_proxy(value)
