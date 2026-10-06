"""Real business adapters, temporary storage, no upstream requests or workers."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class RuntimeIntegrationTests(unittest.TestCase):
    def test_import_batch_merge_then_cascade_delete_and_index_rebuild(self):
        script = r'''
import json
from copy import deepcopy
from unittest.mock import patch
from backend.services import load_services
from backend.app import create_app
s = load_services()
db = s.db
headers = {'X-Team-Console-Key': 'fixture-key'}
with patch('curl_cffi.requests.Session.request', side_effect=AssertionError('live HTTP forbidden')), \
     patch('requests.sessions.Session.request', side_effect=AssertionError('live HTTP forbidden')):
    def imported(*names):
        return db.import_password_totp_accounts(s.parse_accounts('\n'.join(
            f'{name}@example.invalid----FixturePassword123!----JBSWY3DPEHPK3PXP' for name in names)))
    a, b, keep = imported('target'), imported('source', 'archived'), imported('unrelated')
    target_id, source_id = a['batch_id'], b['batch_id']
    source_account = b['imported'][0]['id']
    archived_account = b['imported'][1]['id']
    kept_account = keep['imported'][0]['id']
    batches = db._load_batches()
    db._save_batches([*batches,
        {'batch_id': 'empty-fixture', 'flow_snapshot': {'registration_driver': 'imported'}, 'count': 0},
        {'batch_id': 'oauth-internal', 'flow_snapshot': {'registration_driver': 'protocol'}, 'count': 0}])
    db._CODEX_DIR.mkdir(parents=True, exist_ok=True)
    db._COOKIE_DIR.mkdir(parents=True, exist_ok=True)
    token = db._CODEX_DIR / 'codex-source.json'
    token.write_text(json.dumps({'email': 'source@example.invalid', 'refresh_token': 'FIXTURE_SECRET'}))
    cookie = db._COOKIE_DIR / f'account-{archived_account}.json'
    cookie.write_text('{"cookies":[{"name":"session","value":"FIXTURE_SECRET"}]}')
    rows = db._load_accounts()
    for row in rows:
        if row['id'] == source_account:
            row['codex_credential_path'] = str(token)
        if row['id'] == archived_account:
            row.update(archived=True, web_cookie_credential_path=cookie.name)
    db._save_accounts(rows)
    before_accounts = deepcopy(db._load_accounts())
    app = create_app(services=s, api_key='fixture-key')
    indexer = app.extensions['team_console']['indexer']
    indexer.refresh_once()
    client = app.test_client()

    def mutate(kind, ids=None):
        return client.post('/api/batches/' + kind, headers=headers, json={
            'batch_ids': ids or [target_id, source_id], 'target_batch_id': target_id,
            'confirm': True, 'cascade_accounts': True})

    # A retry gap has no active child job yet, and must still block both writes.
    s.completion._STATE_PATH.write_text(json.dumps([
        {'account_id': source_account, 'status': 'running', 'stage': 'codex_pending'}]))
    with patch.object(db, '_write_json', wraps=db._write_json) as write:
        for kind in ('merge', 'delete'):
            response = mutate(kind)
            assert response.status_code == 409, response.get_data(as_text=True)
            assert response.get_json()['busy'][0]['id'] == source_account
        write.assert_not_called()
    s.completion._STATE_PATH.write_text('[]')

    rows = db._load_accounts()
    next(row for row in rows if row['id'] == source_account).update(quota_status='queued', quota_check_id='fixture-claim')
    db._save_accounts(rows)
    with patch.object(db, '_write_json', wraps=db._write_json) as write:
        for kind in ('merge', 'delete'):
            assert mutate(kind).status_code == 409
        write.assert_not_called()
    db._save_accounts(deepcopy(before_accounts))

    # Internal OAuth jobs have a different batch ID; core rechecks the link.
    db._save_jobs([{'id': 900, 'status': 'pending', 'account_id': source_account,
                   'email': 'source@example.invalid', 'batch_id': 'oauth-internal'}])
    with patch.object(db, '_write_json', wraps=db._write_json) as write:
        for kind in ('merge', 'delete'):
            assert mutate(kind).status_code == 409
        write.assert_not_called()
    db._save_jobs([])
    for kind in ('merge', 'delete'):
        assert mutate(kind, [target_id, 'oauth-internal']).status_code == 409
        assert mutate(kind, [target_id, 'missing']).status_code == 404

    checkpoint = db._ACCOUNTS_JSON.read_bytes()
    with patch.object(db, '_save_accounts', wraps=db._save_accounts) as save, \
         patch.object(db, 'merge_registration_batches', wraps=db.merge_registration_batches) as merge:
        response = mutate('merge', [target_id, source_id, source_id])
        assert response.status_code == 200, response.get_data(as_text=True)
        merge.assert_called_once_with(target_batch_id=target_id, batch_ids=[target_id, source_id])
        save.assert_not_called()  # Membership is a small progress-journal write.
    result = response.get_json()
    assert result['merged_count'] == 1 and result['moved_accounts'] == 2
    assert db._ACCOUNTS_JSON.read_bytes() == checkpoint
    assert token.exists() and cookie.exists()
    after_accounts = {row['id']: row for row in db._load_accounts()}
    for old in before_accounts:
        new = after_accounts[old['id']]
        assert {k: v for k, v in old.items() if k not in {'registration_batch_id', 'updated_at'}} == \
               {k: v for k, v in new.items() if k not in {'registration_batch_id', 'updated_at'}}
    assert 'FixturePassword' not in response.get_data(as_text=True)
    assert 'FIXTURE_SECRET' not in response.get_data(as_text=True)

    def verify_merged(api):
        assert api.get('/api/accounts', query_string={'batch_id': target_id}, headers=headers).get_json()['total'] == 2
        assert api.get('/api/accounts', query_string={'batch_id': source_id}, headers=headers).get_json()['total'] == 0
        listing = api.get('/api/batches', headers=headers).get_json()
        assert listing['total'] == 3
        assert next(row for row in listing['items'] if row['batch_id'] == target_id)['account_total'] == 2
    verify_merged(client)  # Immediately, before the background refresh.
    indexer.refresh_once()
    verify_merged(client)
    rebuilt = create_app(services=s, api_key='fixture-key', index_path=db._DATA_DIR / 'rebuilt.sqlite3')
    rebuilt.extensions['team_console']['indexer'].refresh_once()
    verify_merged(rebuilt.test_client())

    kept_before = deepcopy(db.get_account(kept_account))
    with patch.object(db, '_save_accounts', wraps=db._save_accounts) as save, \
         patch.object(db, 'delete_registration_batches', wraps=db.delete_registration_batches) as delete:
        response = mutate('delete', [target_id, 'empty-fixture'])
        assert response.status_code == 200, response.get_data(as_text=True)
        delete.assert_called_once_with(batch_ids=[target_id, 'empty-fixture'])
        save.assert_called_once()
    assert response.get_json()['deleted_count'] == 2
    assert response.get_json()['deleted_account_count'] == 3  # Includes archived.
    assert not token.exists() and not cookie.exists()
    assert db.get_account(kept_account) == kept_before
    assert client.get('/api/accounts', headers=headers).get_json()['total'] == 1
    assert client.get('/api/batches', headers=headers).get_json()['total'] == 1
    indexer.refresh_once()
    assert client.get('/api/accounts', query_string={'batch_id': target_id}, headers=headers).get_json()['total'] == 0
    assert client.get('/api/batches', headers=headers).get_json()['items'][0]['batch_id'] == keep['batch_id']
    assert s.completion._THREAD is None
print('isolated batch merge and deletion checks passed; no remote writes or workers')
'''
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, 'TEAM_CONSOLE_DATA_DIR': directory, 'PYTHON_DOTENV_DISABLED': '1',
                   'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(Path(__file__).resolve().parents[1])}
            result = subprocess.run([sys.executable, '-c', script], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('checks passed', result.stdout)

    def test_account_delete_cascade_uses_only_isolated_local_storage(self):
        script = r'''
import json
from unittest.mock import patch
from backend.services import load_services
from backend.app import create_app
s = load_services()
db = s.db
headers = {'X-Team-Console-Key': 'fixture-key'}
with patch('curl_cffi.requests.Session.request', side_effect=AssertionError('live HTTP forbidden')), \
     patch('requests.sessions.Session.request', side_effect=AssertionError('live HTTP forbidden')):
    first = db.import_password_totp_accounts(s.parse_accounts('\n'.join(
        f'{name}@example.invalid----FixturePassword123!----JBSWY3DPEHPK3PXP'
        for name in ('delete-me', 'keep-active-job', 'keep-active-quota'))))
    solo = db.import_password_totp_accounts(s.parse_accounts(
        'last-in-batch@example.invalid----FixturePassword123!----JBSWY3DPEHPK3PXP'))
    ids = [row['id'] for row in first['imported']]
    target, job_busy, quota_busy = ids
    last = solo['imported'][0]['id']
    db._CODEX_DIR.mkdir(parents=True, exist_ok=True)
    db._COOKIE_DIR.mkdir(parents=True, exist_ok=True)
    db._LOG_DIR.mkdir(parents=True, exist_ok=True)
    token = db._CODEX_DIR / 'codex-delete.json'
    token.write_text(json.dumps({'email': 'delete-me@example.invalid', 'refresh_token': 'FIXTURE_SECRET'}))
    untouched = db._CODEX_DIR / 'codex-keep.json'
    untouched.write_text(json.dumps({'email': 'keep-active-job@example.invalid', 'refresh_token': 'FIXTURE_OTHER'}))
    outside = db._DATA_DIR / 'outside-credential.json'
    outside.write_text(token.read_text())
    escaped = db._CODEX_DIR / 'codex-escape.json'
    escaped.symlink_to(outside)
    cookie = db._COOKIE_DIR / f'account-{target}.json'
    cookie.write_text('{"cookies":[{"name":"session","value":"FIXTURE_SECRET"}]}')
    log = db._LOG_DIR / 'fixture-delete.log'
    log.write_text('fixture log')
    rows = db._load_accounts()
    for row in rows:
        if row['id'] == target:
            row.update(codex_credential_path=str(token), web_cookie_credential_path=cookie.name, web_cookie_count=1)
        if row['id'] == last:
            row['codex_credential_path'] = str(outside)  # Invalid path must never be unlinked.
        if row['id'] == quota_busy:
            row.update(quota_status='queued', quota_check_id='fixture-claim')
    db._save_accounts(rows)
    db._save_jobs([
        {'id': 41, 'account_id': target, 'email': 'delete-me@example.invalid', 'status': 'success',
         'batch_id': first['batch_id'], 'log_file': str(log)},
        {'id': 42, 'account_id': job_busy, 'email': 'keep-active-job@example.invalid', 'status': 'pending',
         'batch_id': first['batch_id']},
    ])
    parent = s.team_store.save_parent('owner@example.invalid', {}, {'access_token': 'FIXTURE_PARENT'})
    s.team_store.replace_workspaces(parent['id'], [{'id': 'fixture-workspace', 'can_manage': True}])
    s.team_store.replace_members(parent['id'], 'fixture-workspace', [
        {'id': 'remote-user', 'email': 'delete-me@example.invalid', 'seat_type': 'default'}], {})
    before_keep = dict(db.get_account(job_busy))
    app = create_app(services=s, api_key='fixture-key')
    app.extensions['team_console']['indexer'].refresh_once()
    client = app.test_client()
    with patch.object(db, '_save_accounts', wraps=db._save_accounts) as save:
        response = client.post('/api/accounts/delete', headers=headers,
                               json={'account_ids': [target, job_busy, quota_busy, last, 9999, target], 'confirm': True})
    assert response.status_code == 200, response.get_data(as_text=True)
    result = response.get_json()
    assert {row['id'] for row in result['deleted']} == {target, last}
    assert {row['id'] for row in result['skipped']} == {job_busy, quota_busy, 9999}
    save.assert_called_once()
    assert 'FIXTURE_SECRET' not in response.get_data(as_text=True)
    assert not token.exists() and not cookie.exists() and not log.exists()
    assert untouched.exists() and outside.exists() and escaped.is_symlink()
    assert db.get_account(job_busy) == before_keep
    assert db.get_account(quota_busy)['quota_status'] == 'queued'
    assert [row['id'] for row in db._load_jobs()] == [42]
    assert client.get('/api/accounts', headers=headers).get_json()['total'] == 2
    assert client.get(f'/api/accounts/{target}', headers=headers).status_code == 404
    app.extensions['team_console']['indexer'].refresh_once()
    batches = client.get('/api/batches', headers=headers).get_json()
    assert batches['total'] == 1 and batches['items'][0]['account_total'] == 2
    assert batches['items'][0]['batch_id'] == first['batch_id']
    members = s.team_store.member_page(parent['id'], 'fixture-workspace')
    assert members['total'] == 1 and members['items'][0]['id'] == 'remote-user'
    assert s.completion._THREAD is None
print('isolated account deletion checks passed; no remote writes or workers')
'''
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, 'TEAM_CONSOLE_DATA_DIR': directory, 'PYTHON_DOTENV_DISABLED': '1',
                   'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(Path(__file__).resolve().parents[1])}
            result = subprocess.run([sys.executable, '-c', script], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('checks passed', result.stdout)

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
