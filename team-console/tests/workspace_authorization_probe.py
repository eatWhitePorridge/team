"""API -> persisted queue -> password/TOTP -> workspace -> saved claims, offline.

Only synthetic accounts in a temporary bound store; HTTP primitives are mocked.
No browser, UI rendering, real credentials, invitations, or upstream requests.
"""
import base64
import json
import logging
import os
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch


def main():
    assert os.getenv('PYTHON_DOTENV_DISABLED') == '1'
    assert os.getenv('TEAM_CONSOLE_DATA_DIR')
    logging.disable(logging.CRITICAL)
    from backend.services import load_services
    from backend.app import create_app
    services = load_services()
    from core import codex_oauth as oauth, registration_service as registration
    db, completion = services.db, services.completion
    target, manual, first = 'fixture-team-target', 'fixture-manual-team', 'fixture-personal-first'
    factor = 'fixture-factor-01234'
    headers = {'X-Team-Console-Key': 'fixture-key'}
    plans, claim_overrides, direct_callbacks, selected = {}, {}, set(), []
    current = {}

    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b'=').decode()

    def session(**kwargs):
        return SimpleNamespace(session=SimpleNamespace(close=Mock(), cookies=SimpleNamespace(jar=[], get=lambda _: None)),
            get=Mock(return_value=SimpleNamespace(status_code=200, text='', headers={}, url='https://auth.openai.com/log-in/password')),
            get_auth_navigate_headers=Mock(return_value={}))

    def bootstrap(current, state, challenge):
        current.state = state

    def email_step(session, email):
        session.email = email
        current[email] = session
        return {'page_type': 'login_password', 'continue_url': '/log-in/password'}

    def mfa(session, **kwargs):
        session.session.cookies.jar.append(SimpleNamespace(name='oai-client-auth-session', domain='auth.openai.com', path='/',
            value=encode({'workspaces': [{'id': first}, {'id': target}, {'id': manual}]})))
        if session.email in direct_callbacks:
            return {'continue_url': 'http://localhost:1455/auth/callback?code=fixture-code&state=' + session.state}
        return {'page_type': 'consent', 'continue_url': '/sign-in-with-chatgpt/codex/consent'}

    def post_json(session, url, payload, **kwargs):
        assert url.endswith('/api/accounts/workspace/select')
        assert set(payload) == {'workspace_id'}
        selected.append((session.email, payload['workspace_id']))
        return SimpleNamespace(status_code=302, text='', json=lambda: {},
            headers={'Location': 'http://localhost:1455/auth/callback?code=fixture-code&state=' + session.state})

    def exchange(session, code, verifier):
        assert code == 'fixture-code'
        workspace = claim_overrides.get(session.email, session._codex_selected_workspace_id)
        claims = {'email': session.email, 'https://api.openai.com/auth': {
            'chatgpt_account_id': workspace, 'chatgpt_plan_type': plans.get(session.email, 'self_serve_business_prolite')}}
        jwt = 'fixture.' + encode(claims) + '.signature'
        return {'access_token': jwt, 'id_token': jwt, 'refresh_token': 'fixture-private-rt', 'expires_in': 3600}

    with ExitStack() as stack:
        for method in ['requests.sessions.Session.request', 'curl_cffi.requests.Session.request']:
            stack.enter_context(patch(method, side_effect=AssertionError('external network forbidden')))
        stack.enter_context(patch.object(completion, '_ensure_scheduler'))
        stack.enter_context(patch.object(completion, '_TEAM_AUTH_RETRY_DELAY', 9999))
        executor = stack.enter_context(patch.object(registration, 'get_codex_executor', return_value=Mock()))
        for name, options in {
            'BrowserSession': {'side_effect': session}, '_initial_codex_proxy': {'return_value': ''},
            'network_preflight': {}, '_bootstrap_authorize': {'side_effect': bootstrap}, '_sync_auth_document_context': {},
            '_submit_email_identifier': {'side_effect': email_step},
            '_submit_password_step': {'return_value': {'page_type': 'mfa_challenge', 'continue_url': '/mfa-challenge/' + factor, 'mfa_required': True}},
            '_prepare_mfa_step': {'return_value': ('https://auth.openai.com/mfa-challenge/' + factor, factor)},
            '_verify_totp_challenge': {'side_effect': mfa}, '_post_json': {'side_effect': post_json},
            '_load_consent_workspaces': {'return_value': ''}, 'exchange_codex_token': {'side_effect': exchange},
        }.items():
            stack.enter_context(patch.object(oauth, name, **options))
        app = create_app(services=services, api_key='fixture-key')
        client = app.test_client()
        parent = services.team_store.save_parent('parent@example.invalid', {}, {'access_token': 'fixture-parent-at'})
        services.team_store.replace_workspaces(parent['id'], [{'id': target, 'name': 'Fixture', 'can_manage': True}])

        def enqueue(name, *, workspace=None, from_parent=False, team=True):
            email = name + '@example.invalid'
            imported = client.post('/api/accounts/import-password-totp', headers=headers,
                json={'text': email + '----FixturePassword123!----JBSWY3DPEHPK3PXP'})
            assert imported.status_code == 201
            account_id = imported.get_json()['imported'][0]['id']
            body = {'account_ids': [account_id], 'team_authorization': team}
            if workspace is not None: body['expected_workspace_id'] = workspace
            if from_parent: body['parent_id'] = parent['id']
            response = client.post('/api/accounts/authorize', headers=headers, json=body)
            assert response.status_code == 202, response.get_json()
            ident = response.get_json()['started'][0]['id']
            completion._STATE_CACHE = None  # Read back persisted targets, not an in-memory request.
            completion._scheduler_tick()
            return ident, email, account_id

        def run(ident, expected):
            row = completion._get_item(ident)
            job = db.get_job(row['codex_job_id'])
            assert row.get('expected_workspace_id', '') == expected
            assert job['flow_snapshot'].get('expected_workspace_id', '') == expected
            registration._run_codex_retry_job(job['id'], job['log_file'], job['email'], job['account_id'])
            completion._scheduler_tick()
            return db.get_job(job['id'])

        # Both selectors reach the same real selector and save the non-first target.
        for name, workspace, mother in [('mother', target, True), ('manual', manual, False)]:
            ident, email, account_id = enqueue(name, workspace=workspace, from_parent=mother)
            assert run(ident, workspace)['status'] == 'success'
            assert completion._get_item(ident)['status'] == 'success'
            assert selected[-1] == (email, workspace)
            assert db.get_account(account_id)['codex_workspace_id'] == workspace
            assert db.get_account(account_id)['codex_plan_type'] == 'self_serve_business_prolite'
            current[email].session.close.assert_called_once()

        # An unavailable ID must not silently choose another Team or the first Free space.
        ident, email, account_id = enqueue('missing', workspace='not-in-auth-response')
        assert run(ident, 'not-in-auth-response')['status'] == 'failed'
        assert all(item[0] != email for item in selected)
        assert not db.get_account(account_id).get('codex_refresh_token')
        assert completion._get_item(ident)['stage'] == 'codex_pending'

        # A direct callback still has to prove the target before saving any credential.
        ident, email, account_id = enqueue('wrong-callback', workspace=target)
        claim_overrides[email] = first
        direct_callbacks.add(email)
        assert run(ident, target)['status'] == 'failed'
        assert not db.get_account(account_id).get('codex_refresh_token')
        assert completion._get_item(ident)['status'] != 'success'

        # Free at the requested ID is NOT Team success; all seven tries keep the same ID.
        ident, email, account_id = enqueue('free-target', workspace=target)
        plans[email] = 'free'
        job_ids = []
        for attempt in range(1, 8):
            job_ids.append(run(ident, target)['id'])
            row = completion._get_item(ident)
            assert row['codex_attempt_count'] == attempt and row['status'] != 'success'
            if attempt < 7:
                completion._set_item(ident, next_attempt_at=0)
                completion._STATE_CACHE = None
                completion._scheduler_tick()
        assert completion._get_item(ident)['status'] == 'failed'
        assert len(set(job_ids)) == 7
        assert [wid for mail, wid in selected if mail == email] == [target] * 7

        # Ordinary mode still accepts its actual Free plan and has no explicit target.
        ident, email, account_id = enqueue('ordinary', team=False)
        plans[email] = 'free'
        assert run(ident, '')['status'] == 'success'
        assert completion._get_item(ident)['status'] == 'success'
        assert selected[-1] == (email, first)
        assert db.get_account(account_id)['codex_plan_type'] == 'free'

        visible = client.get('/api/jobs', headers=headers).get_json()
        assert any(row.get('expected_workspace_id') == target for row in visible['pipeline'])
        encoded = json.dumps(visible)
        assert all(value not in encoded for value in ['FixturePassword123!', 'JBSWY3DPEHPK3PXP', 'fixture-private-rt'])
        assert visible['runtime']['workers'] == 100
        assert executor.called
        print(json.dumps({'selectors_verified': 2, 'non_first_workspace_selected': True,
            'target_survives_persistence_and_six_retries': True, 'wrong_workspace_never_saved': True,
            'ordinary_unchanged': True, 'external_requests': 0}), flush=True)


if __name__ == '__main__':
    main()
