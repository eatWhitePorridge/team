"""Real business adapters, temporary storage, no upstream requests or workers."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class RuntimeIntegrationTests(unittest.TestCase):
    def test_proxy_hot_reload_and_seat_cache_routes(self):
        script = r'''
from unittest.mock import patch
from backend.services import load_services
from backend.app import create_app
s = load_services()
s.network.update({'pool_action':'replace', 'proxy_pool':'socks5h://fixture:secret@proxy.invalid:1080'})
from core.session import BrowserSession
session = BrowserSession(detect_exit_geo=False)
assert session.proxy == 'socks5h://fixture:secret@proxy.invalid:1080'
s.network.update({'pool_action':'clear'})
another = BrowserSession(detect_exit_geo=False)
assert another.proxy == ''
assert session.proxy == 'socks5h://fixture:secret@proxy.invalid:1080'
session.session.close(); another.session.close()
parent = s.team_store.save_parent('owner@example.invalid', {}, {'access_token':'fixture-only'})
pid = parent['id']
s.team_store.replace_workspaces(pid, [{'id':'workspace-fixture', 'can_manage':True, 'is_usage_based_seat_enabled':False}])
s.team_store.replace_members(pid, 'workspace-fixture', [{'id':f'user-{n}', 'email':f'fixture-{n}@example.invalid', 'seat_type':'prolite', 'role':'standard-user'} for n in range(241)], {})
s.team_store.replace_seat_holds(pid, 'workspace-fixture', [{'id':'departed', 'email':'', 'reclaimable_seat_type':'default', 'deactivated_time':'fixture'}])
app = create_app(services=s, api_key='fixture-key')
app.extensions['team_console']['indexer'].refresh_once()
client = app.test_client()
headers = {'X-Team-Console-Key':'fixture-key'}
base = f'/api/team/parents/{pid}/workspaces/workspace-fixture/members'
current = client.get(base+'?page_size=all', headers=headers)
assert current.status_code == 200 and current.get_json()['total'] == 241
holds = client.get(base+'?page_size=all&seat_status=hold', headers=headers)
assert holds.status_code == 200 and holds.get_json()['total'] == 1
assert holds.get_json()['items'][0]['id'] == 'departed'
from core import team_admin_service
with patch.object(team_admin_service, '_enqueue_job', return_value={'id':'fixture-job'}) as enqueue:
    url = f'/api/team-admin/parents/{pid}/jobs'
    denied = client.post(url, headers=headers, json={'kind':'switch','workspace_id':'workspace-fixture','seat_type':'usage_based','user_ids':['user-0']})
    assert denied.status_code == 422
    enqueue.assert_not_called()
    accepted = client.post(url, headers=headers, json={'kind':'switch','workspace_id':'workspace-fixture','seat_type':'default','user_ids':['user-0']})
    assert accepted.status_code == 202
    assert enqueue.call_args.args == (pid, 'switch', 'workspace-fixture', ['user-0'], 'default')
print('runtime binding and cached seat API checks passed; no remote writes')
'''
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, 'TEAM_CONSOLE_DATA_DIR': directory, 'PYTHON_DOTENV_DISABLED': '1',
                   'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(Path(__file__).resolve().parents[1])}
            result = subprocess.run([sys.executable, '-c', script], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('checks passed', result.stdout)
