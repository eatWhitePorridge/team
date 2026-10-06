"""Real SQLite, Flask APIs, transport and jobs; all outbound HTTP is stubbed."""
import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch
from requests.cookies import RequestsCookieJar

assert os.environ['PYTHON_DOTENV_DISABLED'] == '1'
assert os.environ['TEAM_CONSOLE_DATA_DIR']
logging.disable(logging.CRITICAL)
from backend.services import load_services
from backend.app import create_app
services = load_services()
from core import team_admin_service as service
from core.team_proxy_url import normalize_proxy, masked_proxy
from config import proxy as proxy_config
store = services.team_store
HEADERS = {'X-Team-Console-Key': 'fixture-key'}
PROXY = 'socks5h://fixture-user:fixture-secret@proxy.invalid:1080'
OTHER = 'http://fixture-other:fixture-password@second.invalid:8080'


def response(payload=None, status=200):
    return SimpleNamespace(status_code=status, headers={}, json=lambda: payload if payload is not None else {})


class FixedProxyTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        for name in ('requests.sessions.Session.request', 'curl_cffi.requests.Session.request'):
            self.stack.enter_context(patch(name, side_effect=AssertionError('external network forbidden')))
        self.stack.enter_context(patch.object(proxy_config, 'PROXY_POOL', [PROXY, OTHER]))
        self.parent = store.save_parent(f'owner-{uuid.uuid4().hex}@example.invalid', {}, {'access_token': 'fixture-at'})
        self.pid = self.parent['id']
        self.app = create_app(services=services, api_key='fixture-key')
        self.api = self.app.test_client()
        self.base = f'/api/team-admin/parents/{self.pid}'
        self.transports = []
        self.browser = self.stack.enter_context(patch.object(service, 'BrowserSession', side_effect=self.new_transport))

    def new_transport(self, **kwargs):
        env = SimpleNamespace(**{'device_id': 'fixture-device', 'browser_family': 'chrome', **kwargs})
        env.session = SimpleNamespace(cookies=SimpleNamespace(jar=RequestsCookieJar(), clear=Mock(), set=Mock()), close=Mock())
        env.get_chatgpt_headers = Mock(return_value={})
        env.get_nextauth_headers = Mock(return_value={})
        env.get = Mock(return_value=response())
        env.post = Mock(return_value=response())
        env.delete = Mock(return_value=response())
        self.transports.append(env)
        return env

    def client(self):
        client = service.TeamAdminClient(store.get_parent(self.pid))
        self.addCleanup(client.close)
        return client

    def settings(self, **values):
        return {'confirm': True, 'expected_email': self.parent['email'],
                'expected_revision': store.get_parent(self.pid)['proxy']['revision'],
                'action': 'manual', 'proxy_url': PROXY, **values}

    def set_proxy(self, **values):
        return self.api.post(self.base + '/proxy', json=self.settings(**values), headers=HEADERS)

    def assert_no_secret(self, value):
        text = json.dumps(value)
        for secret in ('fixture-user', 'fixture-secret', 'fixture-password', 'fixture-other', 'fixture-at'):
            self.assertNotIn(secret, text)

    def test_read_only_lists_do_not_bind_and_write_route_requires_auth(self):
        for path in (self.base, '/api/team-admin/parents'):
            result = self.api.get(path, headers=HEADERS)
            self.assertEqual(result.status_code, 200)
            self.assert_no_secret(result.get_json())
        self.assertFalse(store.get_parent(self.pid)['proxy']['configured'])
        self.assertEqual(self.api.post(self.base + '/proxy', json=self.settings()).status_code, 401)
        self.browser.assert_not_called()

    def test_manual_binding_encrypted_and_all_public_views_masked(self):
        result = self.set_proxy()
        self.assertEqual(result.status_code, 200)
        item = result.get_json()['item']
        self.assertTrue(item['proxy']['configured'])
        self.assertEqual(item['proxy']['source'], 'manual')
        self.assertEqual(item['proxy']['preview'], 'socks5h://***:***@proxy.invalid:1080')
        self.assertEqual(result.headers['Cache-Control'], 'no-store')
        self.assert_no_secret(item)
        with store.connection() as conn:
            row = dict(conn.execute('SELECT * FROM parent_proxies WHERE parent_id=?', (self.pid,)).fetchone())
            self.assert_no_secret(row)
            self.assertEqual(store._cipher().decrypt(row['encrypted'].encode()).decode(), PROXY)
        self.assert_no_secret(self.api.get(self.base, headers=HEADERS).get_json())
        self.assert_no_secret(self.api.get('/api/team-admin/parents', headers=HEADERS).get_json())

    def test_auto_binding_is_atomic_under_parallel_first_use_and_persists(self):
        barrier = threading.Barrier(12)
        def lease(_):
            barrier.wait()
            with store.parent_proxy_session(self.pid, expected_email=self.parent['email']) as value:
                return value
        with ThreadPoolExecutor(max_workers=12) as executor:
            used = list(executor.map(lease, range(12)))
        self.assertEqual(len(set(used)), 1)
        before = store.get_parent(self.pid)['proxy']
        self.assertEqual(before['source'], 'pool')
        with patch.object(proxy_config, 'PROXY_POOL', []):
            self.assertEqual(self.client().env.proxy, used[0])
        self.assertEqual(store.get_parent(self.pid)['proxy'], before)

    def test_pool_prefers_unbound_entries_for_different_mothers(self):
        a, b = [store.save_parent(f'new-{uuid.uuid4().hex}@example.invalid', {}, {}) for _ in range(2)]
        unique = ['http://unique-a.invalid:1080', 'http://unique-b.invalid:1080']
        with patch.object(proxy_config, 'PROXY_POOL', unique):
            with store.parent_proxy_session(a['id'], expected_email=a['email']) as first:
                with store.parent_proxy_session(b['id'], expected_email=b['email']) as second:
                    self.assertNotEqual(first, second)

    def test_binding_survives_process_restart_empty_pool_and_token_replacement(self):
        self.assertEqual(self.set_proxy().status_code, 200)
        before = store.get_parent(self.pid)['proxy']
        store.update_credentials(self.pid, {'access_token': 'fixture-new-at'})
        service.edit_parent(self.pid, {'label': 'renamed'})
        self.assertEqual(store.get_parent(self.pid)['proxy'], before)
        code = '''from backend.services import load_services
import hashlib
s=load_services()
from config import proxy
proxy.PROXY_POOL=[]
p=s.team_store.get_parent(PARENT)
with s.team_store.parent_proxy_session(PARENT, expected_email=p['email']) as value:
    print(hashlib.sha256(value.encode()).hexdigest())
'''.replace('PARENT', str(self.pid))
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip().splitlines()[-1], hashlib.sha256(PROXY.encode()).hexdigest())

    def test_invalid_proxy_empty_pool_and_corrupt_binding_fail_closed(self):
        for value in ('', 'ftp://proxy.invalid:1080', 'http://secret@host:99999', 'socks5h://***:***@host:1234', 'http://host:123/?secret=x', 'http://a.invalid:12\nX:secret'):
            result = self.set_proxy(proxy_url=value)
            self.assertEqual(result.status_code, 400)
            self.assertNotIn('secret', result.get_data(as_text=True))
        with patch.object(proxy_config, 'PROXY_POOL', []):
            with self.assertRaises(store.TeamAdminError) as caught:
                self.client()
            self.assertEqual(caught.exception.code, 'proxy_pool_empty')
        self.browser.assert_not_called()
        self.assertEqual(self.set_proxy().status_code, 200)
        with store.connection() as conn:
            conn.execute('UPDATE parent_proxies SET encrypted=? WHERE parent_id=?', ('broken', self.pid))
        with self.assertRaises(store.TeamAdminError) as caught:
            self.client()
        self.assertEqual(caught.exception.code, 'parent_proxy_unreadable')
        self.browser.assert_not_called()

    def test_stale_revision_identity_confirmation_and_clear_are_rejected(self):
        original = self.settings()
        self.assertEqual(self.set_proxy().status_code, 200)
        self.assertEqual(self.api.post(self.base+'/proxy', json=original, headers=HEADERS).status_code, 409)
        for changes, expected in [({'expected_email': 'stale@example.invalid'}, 409),
                                  ({'confirm': False}, 400), ({'expected_revision': None}, 400),
                                  ({'action':'clear'}, 400), ({'action': []}, 400), ({'extra': True}, 400)]:
            self.assertEqual(self.set_proxy(**changes).status_code, expected)
        self.assertEqual(self.client().env.proxy, PROXY)

    def test_active_clients_and_invitation_forks_block_change_until_all_close(self):
        self.assertEqual(self.set_proxy().status_code, 200)
        client = self.client()
        fork = client.fork_for_invites(); self.addCleanup(fork.close)
        self.assertEqual(client.env.proxy, PROXY)
        self.assertEqual(fork.env.proxy, PROXY)
        self.assertIsNot(fork.env.session, client.env.session)
        client.close(); client.close()
        self.assertEqual(self.set_proxy(proxy_url=OTHER).status_code, 409)
        self.assertEqual(self.api.delete(self.base, headers=HEADERS).status_code, 409)
        fork.close(); fork.close()
        self.assertEqual(self.set_proxy(proxy_url=OTHER).status_code, 200)
        self.assertEqual(self.client().env.proxy, OTHER)

    def test_queued_job_blocks_proxy_change_but_uses_binding_in_worker(self):
        self.assertEqual(self.set_proxy().status_code, 200)
        job = store.create_job(self.pid, 'discover', '', [], '')
        self.assertEqual(self.set_proxy(proxy_url=OTHER).status_code, 409)
        for state in ('queued', 'running'):
            store.update_job(job['id'], status=state)
            self.assertEqual(self.set_proxy(proxy_url=OTHER).status_code, 409)
        # Execute the real worker, but use a local fake discovery result.
        with patch.object(service.TeamAdminClient, 'discover', return_value=[{'id': 'workspace', 'can_manage': True}]), \
             patch.object(service, '_sync_members', return_value=[]), patch.object(service, '_sync_seat_summary'), \
             patch.object(service, '_SLOTS', Mock()):
            service._run(job['id'])
        self.assertEqual(store.get_job(job['id'])['status'], 'success')
        self.assertEqual(self.transports[-1].proxy, PROXY)
        self.assertEqual(self.set_proxy(proxy_url=OTHER).status_code, 200)

    def test_transport_failure_does_not_rebind_or_retain_busy_lease(self):
        self.assertEqual(self.set_proxy().status_code, 200)
        before = store.get_parent(self.pid)['proxy']
        with patch.object(service, 'BrowserSession', side_effect=ConnectionError(PROXY)) as failed:
            for _ in range(2):
                with self.assertRaises(ConnectionError):
                    self.client()
            self.assertEqual(failed.call_count, 2)
            self.assertTrue(all(call.kwargs['proxy'] == PROXY for call in failed.call_args_list))
        self.assertEqual(store.get_parent(self.pid)['proxy'], before)
        self.assertEqual(self.set_proxy(proxy_url=OTHER).status_code, 200)

    def test_request_network_failure_does_not_rebind_or_retry_write(self):
        self.assertEqual(self.set_proxy().status_code, 200)
        client = self.client()
        client.env.post.side_effect = ConnectionError(PROXY)
        with self.assertRaises(service.RemoteError) as caught:
            client.request('POST', '/backend-api/accounts/fixture/invites', body={})
        self.assertNotIn('fixture-secret', str(caught.exception))
        self.assertEqual(client.env.post.call_count, 1)
        self.assertEqual(self.browser.call_count, 1)
        self.assertEqual(store.get_parent(self.pid)['proxy']['source'], 'manual')
        client.close()
        self.assertEqual(self.client().env.proxy, PROXY)

    def test_billing_path_uses_fixed_proxy_and_releases_on_error(self):
        self.assertEqual(self.set_proxy().status_code, 200)
        store.replace_workspaces(self.pid, [{'id': 'workspace', 'can_manage': True}])
        def preview(client):
            self.assertEqual(client.env.proxy, PROXY)
            self.assertEqual(self.set_proxy(proxy_url=OTHER).status_code, 409)
            raise service.RemoteError('fixture network failure')
        with patch.object(service.TeamAdminClient, 'subscription_preview', autospec=True, side_effect=preview):
            with self.assertRaises(service.RemoteError):
                service.check_workspace_expiration(self.pid, 'workspace')
        self.assertEqual(self.set_proxy(proxy_url=OTHER).status_code, 200)

    def test_create_with_manual_proxy_is_atomic_and_delete_cascades(self):
        email = f'created-{uuid.uuid4().hex}@example.invalid'
        payload = {'email': email, 'access_token': 'fixture-at', 'proxy_url': 'ftp://host:12'}
        self.assertEqual(self.api.post('/api/team-admin/parents', json=payload, headers=HEADERS).status_code, 400)
        self.assertFalse(any(row['email']==email for row in store.list_parents()))
        payload['proxy_url'] = OTHER
        result = self.api.post('/api/team-admin/parents', json=payload, headers=HEADERS)
        self.assertEqual(result.status_code, 201)
        item = result.get_json()['item']; self.assert_no_secret(item)
        self.assertTrue(item['proxy']['configured'])
        store.delete_parent(item['id'], expected_email=email)
        with store.connection() as conn:
            self.assertIsNone(conn.execute('SELECT 1 FROM parent_proxies WHERE parent_id=?', (item['id'],)).fetchone())

    def test_explicit_pool_reassignment_is_cas_and_does_not_change_other_mothers(self):
        self.assertEqual(self.set_proxy().status_code, 200)
        other = store.save_parent(f'other-{uuid.uuid4().hex}@example.invalid', {}, {}, proxy=OTHER)
        data = self.settings(action='pool')
        first = self.api.post(self.base+'/proxy', json=data, headers=HEADERS)
        self.assertEqual(first.status_code, 200)
        self.assertNotEqual(first.get_json()['item']['proxy']['revision'], data['expected_revision'])
        self.assertEqual(self.api.post(self.base+'/proxy', json=data, headers=HEADERS).status_code, 409)
        self.assertEqual(store.get_parent(other['id'])['proxy'], other['proxy'])
        self.assertEqual(self.client().env.proxy, OTHER)

    def test_closing_or_fork_failure_releases_transport_lease(self):
        client = self.client()
        with patch.object(service, 'BrowserSession', side_effect=RuntimeError('fixture fork failure')):
            with self.assertRaises(RuntimeError):
                client.fork_for_invites()
        client.env.session.close.side_effect = RuntimeError('fixture close failure')
        with self.assertRaises(RuntimeError):
            client.close()
        client.close()
        self.assertEqual(self.set_proxy().status_code, 200)

    def test_real_transport_uses_exact_saved_url_without_proxy_pool_lookup(self):
        from core.session import BrowserSession
        self.assertEqual(self.set_proxy().status_code, 200)
        with patch.object(service, 'BrowserSession', BrowserSession), patch.object(proxy_config, 'PROXY_POOL', []), \
             patch('core.session.pick_proxy', side_effect=AssertionError('random pool selection forbidden')):
            client = self.client()
            self.assertEqual(client.env.proxy, PROXY)
            self.assertEqual(client.env.session.proxies, {'http': PROXY, 'https': PROXY})
            client.close()

    def test_proxy_formats_ipv6_short_and_auth_masking(self):
        self.assertEqual(normalize_proxy('host.invalid:1080:u:p@ss'), 'socks5h://u:p%40ss@host.invalid:1080')
        self.assertEqual(masked_proxy('socks5://u:secret@[::1]:1080'), 'socks5://***:***@[::1]:1080')
        self.assertEqual(normalize_proxy('host.invalid:8080'), 'http://host.invalid:8080')
        for scheme in ('http', 'https', 'socks5', 'socks5h'):
            self.assertEqual(normalize_proxy(scheme+'://host.invalid:1080'), scheme+'://host.invalid:1080')
        for value in (None, [], 1, 'http://host:0', 'http://host:90000', 'file://host:1234', 'http://%2A%2A%2A:s@host:123'):
            with self.assertRaises(ValueError):
                normalize_proxy(value)


if __name__ == '__main__':
    unittest.main(verbosity=2)
