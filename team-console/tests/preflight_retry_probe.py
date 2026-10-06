"""Real authorization queues with synthetic accounts and no external requests."""
import base64
import json
import logging
import os
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch


def main():
    assert os.environ['PYTHON_DOTENV_DISABLED'] == '1'
    assert os.environ['TEAM_CONSOLE_DATA_DIR']
    logging.disable(logging.CRITICAL)
    from backend.services import load_services
    from backend.app import create_app
    from curl_cffi.requests.exceptions import ProxyError
    services = load_services()
    from core import codex_oauth as oauth, codex_password_totp as login
    from core import registration_service as registration, codex_retry_service as retry
    original_sleep = oauth._sleep_codex_retry
    db, completion = services.db, services.completion
    proxies = [f'socks5h://fixture-{i}:fixture@proxy.invalid:12321' for i in range(20)]
    sessions, plans = [], {}
    remaining = 0
    target = 'fixture-team-workspace'
    factor = 'fixture-factor-01234'
    headers = {'X-Team-Console-Key': 'fixture-key'}

    def make_session(**kwargs):
        session = SimpleNamespace(session=SimpleNamespace(close=Mock()), proxy=kwargs['proxy'])
        sessions.append(session)
        return session

    def preflight(session):
        nonlocal remaining
        if remaining:
            remaining -= 1
            # An opaque message still gets classified by its exception type.
            raise ProxyError('opaque fixture failure')

    def bootstrap(session, state, challenge):
        session.state = state

    def submit_email(session, email):
        session.email = email
        return {'page_type': 'login_password'}

    def callback(session, step, state, email, expected_workspace_id=''):
        assert expected_workspace_id in {'', target}
        session._codex_selected_workspace_id = target
        return 'http://localhost:1455/auth/callback?code=fixture-code&state=' + state

    def exchange(session, code, verifier):
        assert code == 'fixture-code'
        claims = {'email': session.email, 'https://api.openai.com/auth': {
            'chatgpt_account_id': target,
            'chatgpt_plan_type': plans.get(session.email, 'self_serve_business_prolite')}}
        encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()
        jwt = 'fixture.' + encoded + '.signature'
        return {'access_token': jwt, 'refresh_token': 'fixture-private-rt',
                'id_token': jwt, 'expires_in': 3600}

    with ExitStack() as stack:
        for method in ['requests.sessions.Session.request', 'curl_cffi.requests.Session.request']:
            stack.enter_context(patch(method, side_effect=AssertionError('external network forbidden')))
        stack.enter_context(patch.object(completion, '_ensure_scheduler'))
        stack.enter_context(patch.object(completion, '_TEAM_AUTH_RETRY_DELAY', 9999))
        stack.enter_context(patch.object(registration, 'get_codex_executor', return_value=Mock()))
        stack.enter_context(patch.object(oauth._cfg, 'CODEX_PROXY_PREFLIGHT_MAX_ATTEMPTS', 10))
        stack.enter_context(patch.object(oauth._cfg, 'CODEX_FLOW_MAX_ATTEMPTS', 3))
        stack.enter_context(patch.object(oauth._cfg, 'CODEX_ROTATE_PROXY_ON_RETRY', True))
        stack.enter_context(patch.object(oauth, '_configured_codex_proxies', return_value=proxies))
        sleep = stack.enter_context(patch.object(oauth, '_sleep_codex_retry'))
        for name, kwargs in {
            'BrowserSession': {'side_effect': make_session},
            'network_preflight': {'side_effect': preflight},
            '_bootstrap_authorize': {'side_effect': bootstrap},
            '_submit_email_identifier': {'side_effect': submit_email},
            '_submit_password_step': {'return_value': {'mfa_required': True, 'continue_url': '/mfa-challenge/' + factor}},
            '_prepare_mfa_step': {'return_value': ('https://auth.openai.com/mfa-challenge/' + factor, factor)},
            '_verify_totp_challenge': {'return_value': {'page_type': 'consent'}},
            'exchange_codex_token': {'side_effect': exchange},
        }.items():
            stack.enter_context(patch.object(oauth, name, **kwargs))
        stack.enter_context(patch.object(login, '_navigate_password', return_value='https://auth.openai.com/log-in/password'))
        stack.enter_context(patch.object(login, '_callback', side_effect=callback))
        app = create_app(services=services, api_key='fixture-key')
        client = app.test_client()
        serial = 0

        def enqueue(team=True):
            nonlocal serial
            serial += 1
            email = f'preflight-{serial}@example.invalid'
            imported = db.import_password_totp_accounts(services.parse_accounts(
                email + '----FixturePassword123!----JBSWY3DPEHPK3PXP'))
            account_id = imported['imported'][0]['id']
            result = client.post('/api/accounts/authorize', headers=headers, json={
                'account_ids': [account_id], 'team_authorization': team,
                **({'expected_workspace_id': target} if team else {}),
            })
            assert result.status_code == 202, result.get_json()
            ident = result.get_json()['started'][0]['id']
            completion._scheduler_tick()
            return ident, account_id, email

        def run(ident, failures):
            nonlocal remaining
            remaining = failures
            item = completion._get_item(ident)
            job = db.get_job(item['codex_job_id'])
            start = len(sessions)
            preflight_before = oauth.network_preflight.call_count
            bootstrap_before = oauth._bootstrap_authorize.call_count
            email_before = oauth._submit_email_identifier.call_count
            registration._run_codex_retry_job(job['id'], job['log_file'], job['email'], job['account_id'])
            used = sessions[start:]
            for session in used:
                session.session.close.assert_called_once()
            assert len({session.proxy for session in used}) == len(used)
            assert oauth.network_preflight.call_count - preflight_before == min(failures + 1, 10)
            expected_business = int(failures < 10)
            assert oauth._bootstrap_authorize.call_count - bootstrap_before == expected_business
            assert oauth._submit_email_identifier.call_count - email_before == expected_business
            # Drop coordinator cache to verify the persisted metadata path.
            completion._STATE_CACHE = None
            completion._scheduler_tick()
            return db.get_job(job['id']), len(used)

        integration_flows = 0
        for team in (False, True):
            ident, account_id, _ = enqueue(team)
            job, count = run(ident, 6)
            assert count == 7 and job['status'] == 'success'
            row = completion._get_item(ident)
            assert row['status'] == 'success', row
            if team:
                assert row['codex_attempt_count'] == 1
            assert db.get_account(account_id)['codex_workspace_id'] == target
            integration_flows += 1

            ident, account_id, _ = enqueue(team)
            job, count = run(ident, 100)
            assert count == 10 and job['status'] == 'failed'
            assert job['codex_preflight_exhausted'] is True
            assert db.authorization_dispatch_snapshot([account_id], [job['id']])['jobs'][job['id']]['codex_preflight_exhausted'] is True
            assert not db.get_account(account_id).get('codex_refresh_token')
            jobs_before = len(db._load_jobs())
            for _ in range(8):
                completion._scheduler_tick()
            row = completion._get_item(ident)
            assert row['status'] == 'failed' and '代理预检' in row['message']
            if team:
                assert row['codex_attempt_count'] == 0
            assert len(db._load_jobs()) == jobs_before
            # Legacy single-item reconciliation must agree with bulk snapshots.
            with patch.object(completion, '_finish') as finish, patch.object(completion, '_retry_team_authorization') as requeue:
                completion._advance({**row, 'status': 'running', 'stage': 'codex_waiting', 'codex_attempt_count': 1})
                requeue.assert_not_called()
                assert finish.call_args.kwargs.get('codex_attempt_count') == (0 if team else None)
            # Reusing a stopped job must not retain a stale exhaustion marker.
            db.update_job(job['id'], status='running')
            db._JSON_CACHE.clear()
            assert not db.get_job(job['id']).get('codex_preflight_exhausted')
            db.update_job(job['id'], status='failed')
            integration_flows += 1

        # A real Free result costs one Team attempt; the subsequent preflight
        # outage must neither erase that count nor release the old credential.
        ident, account_id, email = enqueue()
        plans[email] = 'free'
        job, _ = run(ident, 0)
        assert job['status'] == 'success'
        assert completion._get_item(ident)['stage'] == 'codex_pending'
        completion._set_item(ident, next_attempt_at=0)
        completion._scheduler_tick()
        assert completion._get_item(ident)['codex_attempt_count'] == 2
        run(ident, 100)
        row = completion._get_item(ident)
        assert row['status'] == 'failed' and row['codex_attempt_count'] == 1
        assert db.get_account(account_id)['codex_plan_type'] == 'free'
        integration_flows += 1

        def failure(stage, exc=None):
            return login._failure(exc or ProxyError('proxy fixture failure'), stage=stage,
                                  email='boundary@example.invalid', password='', secret='')

        def authorize(team, **kwargs):
            return oauth.run_codex_oauth('boundary@example.invalid', force=True, auth_source='local',
                                        login_mode='password_totp', auto_retry=not team, **kwargs)

        # Proxy authentication rejection is also preflight, not account auth.
        assert oauth._is_proxy_preflight_failure(failure('network_preflight', ProxyError('HTTP 407 proxy authentication required')))
        assert not oauth._is_proxy_preflight_failure(failure('network_preflight', RuntimeError('HTTP 403 challenge')))

        # No replacement candidate / disabled rotation still uses the independent
        # budget, never falls back to direct and never has an unbounded loop.
        boundary_cases = 0
        for team in (False, True):
            with patch.object(oauth._cfg, 'CODEX_ROTATE_PROXY_ON_RETRY', False), \
                 patch.object(login, 'run_once', return_value=failure('network_preflight')) as once:
                result = authorize(team, proxy=proxies[0])
                assert once.call_count == 10 and result['oauth_attempts'] == 10
                assert result['oauth_flow_attempts'] == 0 and result['proxy_preflight_failures'] == 10
                assert result['proxy_preflight_exhausted'] and result['retry_scope'] == 'proxy_preflight'
                assert {call.kwargs['proxy'] for call in once.call_args_list} == {proxies[0]}
            boundary_cases += 1

        # Interleaved proxy checks must not eat the three real OAuth attempts.
        with patch.object(oauth._cfg, 'CODEX_ROTATE_PROXY_ON_RETRY', False), \
             patch.object(login, 'run_once', side_effect=[
                 failure('network_preflight'), failure('password'), failure('network_preflight'),
                 failure('password'), failure('password'),
             ]) as once:
            result = authorize(False, proxy=proxies[0])
            assert once.call_count == 5 and result['oauth_flow_attempts'] == 3
            assert result['proxy_preflight_failures'] == 2 and result['retry_scope'] == 'oauth_flow'
            assert not result.get('proxy_preflight_exhausted')
        boundary_cases += 1

        for stage, exc in [('password', None), ('mfa', None), ('workspace', None),
                           ('network_preflight', RuntimeError('HTTP 403 challenge'))]:
            with patch.object(login, 'run_once', return_value=failure(stage, exc)) as once:
                result = authorize(True, proxy=proxies[0])
                once.assert_called_once()
                assert result['oauth_flow_attempts'] == 1
                assert not result.get('proxy_preflight_exhausted')
            boundary_cases += 1

        # A terminal ban defeats even malformed preflight retry metadata.
        with patch.object(login, 'run_once', return_value={**failure('network_preflight'),
                    'error_code': 'account_deactivated', 'retryable': True}) as once:
            result = authorize(True, proxy=proxies[0])
            once.assert_called_once()
            assert result['status'] == 'deactivated' and not result['retryable']
        boundary_cases += 1

        # The two flows share this wrapper; legacy email OTP also keeps the
        # exception type when its real preflight raises (before sending email).
        remaining = 100
        with patch.object(oauth, '_submit_email') as email_otp:
            result = oauth.run_codex_oauth('legacy@example.invalid', force=True,
                                           auth_source='local', auto_retry=False)
            assert result['proxy_preflight_exhausted'] and result['oauth_flow_attempts'] == 0
            email_otp.assert_not_called()
        boundary_cases += 1

        with patch.object(login, 'run_once', return_value=failure('network_preflight')) as once, \
             patch.object(oauth, '_check_codex_flow_stop', side_effect=[None, retry.CodexRetryStopped('fixture stop')]):
            # Exercise the real interruptible wait, not the mocked backoff.
            sleep.side_effect = original_sleep
            try:
                authorize(True, proxy=proxies[0])
                raise AssertionError('stop must escape the retry loop')
            except retry.CodexRetryStopped:
                pass
            once.assert_called_once()
            sleep.side_effect = None
        boundary_cases += 1

        for session in sessions:
            session.session.close.assert_called_once()
        print(json.dumps({'integration_flows': integration_flows, 'boundary_cases': boundary_cases,
                          'external_requests': 0, 'preflight_limit': 10,
                          'team_budget_preserved': True, 'all_sessions_closed': True}))


if __name__ == '__main__':
    main()
