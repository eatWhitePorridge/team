"""Synthetic-account API -> queue -> password/TOTP -> persisted ban -> index."""
from contextlib import ExitStack
import json
import logging
import os
from types import SimpleNamespace
from unittest.mock import Mock, patch


def main():
    assert os.environ['PYTHON_DOTENV_DISABLED'] == '1'
    assert os.environ['TEAM_CONSOLE_DATA_DIR']
    logging.disable(logging.CRITICAL)
    from backend.services import load_services
    from backend.app import create_app
    services = load_services()
    from core import codex_oauth as oauth, codex_password_totp as login
    from core import registration_service as registration, authorization_dispatch
    from core.account_state import UNUSABLE_ACCOUNT_CODES
    db, completion = services.db, services.completion
    headers = {'X-Team-Console-Key': 'fixture-key'}
    factor = 'fixture-factor-01234'
    session = lambda **kw: SimpleNamespace(session=SimpleNamespace(close=Mock()), browser_profile={'impersonate': 'chrome146'})
    with ExitStack() as stack:
        for method in ['requests.sessions.Session.request', 'curl_cffi.requests.Session.request']:
            stack.enter_context(patch(method, side_effect=AssertionError('external network forbidden')))
        stack.enter_context(patch.object(completion, '_ensure_scheduler'))
        stack.enter_context(patch.object(completion, '_TEAM_AUTH_RETRY_DELAY', 0))
        stack.enter_context(patch.object(registration, 'get_codex_executor', return_value=Mock()))
        stack.enter_context(patch.object(oauth, '_initial_codex_proxy', return_value=''))
        rotate = stack.enter_context(patch.object(oauth, '_next_codex_proxy', side_effect=AssertionError('ban rotated proxy')))
        constructor = stack.enter_context(patch.object(oauth, 'BrowserSession', side_effect=session))
        for name, kw in {
            'network_preflight': {}, '_bootstrap_authorize': {},
            '_submit_email_identifier': {'return_value': {'page_type': 'login_password'}},
            '_submit_password_step': {'return_value': {'mfa_required': True, 'continue_url': '/mfa-challenge/' + factor}},
            '_prepare_mfa_step': {'return_value': ('https://auth.openai.com/mfa-challenge/' + factor, factor)},
        }.items():
            stack.enter_context(patch.object(oauth, name, **kw))
        stack.enter_context(patch.object(login, '_navigate_password', return_value='https://auth.openai.com/log-in/password'))
        app = create_app(services=services, api_key='fixture-key')
        client = app.test_client()
        indexer = app.extensions['team_console']['indexer']
        serial = 0

        def enqueue(team):
            nonlocal serial
            serial += 1
            email = f'ban-{serial}@example.invalid'
            imported = db.import_password_totp_accounts(services.parse_accounts(
                email + '----FixturePassword123!----JBSWY3DPEHPK3PXP'))
            ident = imported['imported'][0]['id']
            db.update_account_codex_result(email, {'ok': True, 'status': 'success',
                'refresh_token': 'FIXTURE_PRIVATE_RT', 'credential': {'email': email,
                'account_id': 'fixture-old-team', 'plan_type': 'self_serve_business_prolite'}})
            response = client.post('/api/accounts/authorize', headers=headers,
                                   json={'account_ids': [ident], 'team_authorization': team})
            assert response.status_code == 202, response.get_json()
            return response.get_json()['started'][0]['id'], ident, email

        terminal_flows = 0
        for team in (False, True):
            for code, stage in [(code, 'mfa') for code in sorted(UNUSABLE_ACCOUNT_CODES)] + [('account_deactivated', 'password')]:
                item_id, account_id, email = enqueue(team)
                completion._scheduler_tick()
                item = completion._get_item(item_id)
                job = db.get_job(item['codex_job_id'])
                calls = constructor.call_count
                error = (oauth.AccountUnusableError('fixture ban', error_code=code) if stage == 'password'
                         else login.PasswordTotpLoginError('HTTP 403 fixture ban', code=code, retryable=True))
                with patch.object(oauth, '_submit_password_step' if stage == 'password' else '_verify_totp_challenge', side_effect=error):
                    registration._run_codex_retry_job(job['id'], job['log_file'], email, account_id)
                assert constructor.call_count == calls + 1
                account = db.get_account(account_id)
                assert account['codex_status'] == 'deactivated', account.get('codex_error')
                assert account['codex_error_code'] == code
                assert account['codex_refresh_token'] == 'FIXTURE_PRIVATE_RT'
                assert db.get_job(job['id'])['codex_error_code'] == code
                for _ in range(4): completion._scheduler_tick()
                finished = completion._get_item(item_id)
                assert finished['status'] == 'failed' and finished['error'] == code, finished
                if team: assert finished['codex_attempt_count'] == 1
                jobs_before = len(db._load_jobs())
                response = client.post('/api/accounts/authorize', headers=headers,
                    json={'account_ids': [account_id], 'team_authorization': team})
                assert response.status_code == 409 and len(db._load_jobs()) == jobs_before
                # Also verify the legacy per-item coordinator, without a read snapshot.
                with patch.object(completion, '_finish') as finish, patch.object(registration, 'submit_account_codex_oauth') as submit:
                    completion._advance({**item, 'stage': 'codex_pending'})
                    finish.assert_called_once(); submit.assert_not_called()
                terminal_flows += 1

        # Explicit codes defeat retryable=True/status=failed in either entrypoint.
        for mode in ('password_totp', 'email_otp'):
            target, name = (login, 'run_once') if mode == 'password_totp' else (oauth, '_run_codex_oauth_once')
            with patch.object(target, name, return_value={'status': 'failed', 'http_status': 403,
                    'retryable': True, 'error_code': 'account_deactivated'}) as once:
                result = oauth.run_codex_oauth('fixture@example.invalid', force=True, auth_source='local', login_mode=mode, proxy='')
                assert result['status'] == 'deactivated' and result['oauth_attempts'] == 1
                once.assert_called_once()
        rotate.assert_not_called()

        # An account banned after a batch snapshot must not spend Team retry budget.
        item_id, account_id, email = enqueue(True)
        row = completion._get_item(item_id)
        def rejected(*args, **kwargs):
            db.update_account_codex_result(email, {'status': 'deactivated', 'error_code': 'account_deactivated'})
            return {'submitted': [], 'skipped': [{'id': account_id, 'reason': '账号已封禁'}]}
        with patch.object(registration, 'submit_account_codex_oauth', side_effect=rejected) as submit:
            authorization_dispatch.admit(completion, [row])
            for _ in range(4): completion._scheduler_tick()
            submit.assert_called_once()
        assert completion._get_item(item_id)['status'] == 'failed'

        indexer.refresh_once()
        payload = client.get('/api/accounts?codex_state=deactivated', headers=headers).get_json()
        assert payload['total'] == 9, payload['total']
        assert all(row['codex_connection_state'] == 'deactivated' for row in payload['items'])
        assert 'FIXTURE_PRIVATE_RT' not in json.dumps(payload)
        assert client.get('/api/accounts?codex_state=connected', headers=headers).get_json()['total'] == 0
        generic = login._failure(RuntimeError('HTTP 403 challenge'), stage='bootstrap', email='fixture@example.invalid', password='', secret='')
        assert generic['status'] == 'failed' and generic['retryable']
        assert login.retry_reason(generic) == 'edge_rejected'
        print(json.dumps({'terminal_flows': terminal_flows, 'external_requests': 0,
                          'admission_race_stopped': True, 'generic_403_not_banned': True}))


if __name__ == '__main__':
    main()
