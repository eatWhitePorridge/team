"""Quota result -> progress journal -> public index/API, isolated and offline."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class QuotaCreditsIntegrationTests(unittest.TestCase):
    def test_credits_round_trip_and_failure_preserves_snapshot_without_large_writes(self):
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
    imported = db.import_password_totp_accounts(s.parse_accounts(
        'quota@example.invalid----FixturePassword123!----JBSWY3DPEHPK3PXP'))
    account_id = imported['imported'][0]['id']
    rows = db._load_accounts()
    rows[0]['access_token'] = 'FIXTURE_PRIVATE_TOKEN'
    db._save_accounts(rows)
    checkpoint = db._ACCOUNTS_JSON.read_bytes()
    app = create_app(services=s, api_key='fixture-key')
    index = app.extensions['team_console']
    index['indexer'].refresh_once()
    client = app.test_client()

    def finish(result):
        candidate = db.get_account_supplement_candidates([account_id])[account_id]
        claim_id = db.claim_account_supplements_bulk([candidate], kind='quota', trigger='test')[account_id]['claim_id']
        assert db.mark_account_quota_check_running(account_id, check_id=claim_id)
        assert db.update_account_quota_check(account_id, result=result, check_id=claim_id)
        db._JSON_CACHE.clear()
        index['indexer'].refresh_once()
        response = client.get('/api/accounts/' + str(account_id), headers=headers)
        assert response.status_code == 200
        assert 'FIXTURE_PRIVATE_TOKEN' not in response.get_data(as_text=True)
        assert 'FixturePassword123!' not in response.get_data(as_text=True)
        assert 'JBSWY3DPEHPK3PXP' not in response.get_data(as_text=True)
        return response.get_json()['account']

    with patch.object(db, '_save_accounts', side_effect=AssertionError('full JSON rewrite')):
        for raw in ('0', '125.5', '-2.25'):
            parsed = s.quota.parse_usage({'plan_type': 'self_serve_business_usage_based',
                'rate_limit': None, 'credits': {'balance': raw, 'has_credits': False, 'unlimited': False},
                'rate_limit_reset_credits': {'available_count': 99}})
            current = finish(parsed)
            assert current['quota_status'] == 'success'
            assert current['quota_credits_balance'] == float(raw)
            assert current['quota_credits_unlimited'] == 0
            assert current['quota_primary_used_percent'] is None
            # Team member enrichment and list results use the exact same fields.
            assert index['accounts'].by_emails(['quota@example.invalid'])['quota@example.invalid']['quota_credits_balance'] == float(raw)
            assert client.get('/api/accounts', headers=headers).get_json()['items'][0]['quota_credits_balance'] == float(raw)
            stored = db.get_account(account_id)
            assert stored['quota_credits_balance'] == float(raw)
            assert stored['access_token'] == 'FIXTURE_PRIVATE_TOKEN'
        failed = finish({'ok': False, 'error': 'fixture query failed', 'error_code': 'http_401'})
        assert failed['quota_status'] == 'failed' and failed['quota_credits_balance'] == -2.25
        assert failed['quota_last_success_at'] == current['quota_last_success_at']
        # Subsequent successful replies with absent credits must clear OLD balances.
        absent = finish(s.quota.parse_usage({'rate_limit': None}))
        assert absent['quota_status'] == 'success' and absent['quota_credits_balance'] is None
        unlimited = finish(s.quota.parse_usage({'credits': {'unlimited': True}}))
        assert unlimited['quota_credits_unlimited'] == 1 and unlimited['quota_credits_balance'] is None
    assert checkpoint == db._ACCOUNTS_JSON.read_bytes()
    rebuilt = create_app(services=s, api_key='fixture-key', index_path=db._DATA_DIR / 'rebuilt.sqlite3')
    rebuilt.extensions['team_console']['indexer'].refresh_once()
    row = rebuilt.test_client().get('/api/accounts/' + str(account_id), headers=headers).get_json()['account']
    assert row['quota_credits_unlimited'] == 1 and row['quota_credits_balance'] is None
print('quota credits round-trip passed; no remote requests or main JSON rewrites')
'''
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, 'TEAM_CONSOLE_DATA_DIR': directory, 'PYTHON_DOTENV_DISABLED': '1',
                   'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(Path(__file__).resolve().parents[1])}
            result = subprocess.run([sys.executable, '-c', script], env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn('round-trip passed', result.stdout)
