"""Real queue -> password/TOTP phase -> SSE, paused before OAuth completion.

Temporary storage and mocked network primitives only. No browser or UI tests.
"""
import asyncio
import json
import logging
import os
import threading
import time
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch


def main():
    assert os.getenv('PYTHON_DOTENV_DISABLED') == '1'
    assert os.getenv('TEAM_CONSOLE_DATA_DIR')
    logging.disable(logging.CRITICAL)
    from backend.services import load_services
    from backend.app import create_app
    from backend.asgi import ConsoleASGI
    services = load_services()
    from core import codex_oauth as oauth, codex_retry_service as retry, progress_events
    emails = ['ordinary@example.invalid', 'team@example.invalid']
    at_mfa, release = threading.Event(), threading.Event()
    arrived, phases, event_times = set(), [], []
    lock = threading.Lock()
    factor = 'fixture-factor-01234'

    def session(**kwargs):
        return SimpleNamespace(session=SimpleNamespace(close=Mock(), cookies=SimpleNamespace(jar=[], get=lambda _: None)),
            get=Mock(return_value=SimpleNamespace(status_code=200, text='', headers={}, url='https://auth.openai.com/log-in/password')),
            get_auth_navigate_headers=Mock(return_value={}))

    def email_step(current, email):
        current.email = email
        return {'page_type': 'login_password', 'continue_url': '/log-in/password'}

    def verify(current, **kwargs):
        with lock:
            arrived.add(current.email)
            event_times.append(time.monotonic())
            if len(arrived) == 2: at_mfa.set()
        assert release.wait(10), 'fixture release timed out'
        raise oauth.CodexAuthResponseError('offline fixture completed', http_status=401, error_code='invalid_credentials')

    with ExitStack() as stack:
        stack.enter_context(patch('requests.sessions.Session.request', side_effect=AssertionError('external HTTP forbidden')))
        stack.enter_context(patch('curl_cffi.requests.Session.request', side_effect=AssertionError('external HTTP forbidden')))
        stack.enter_context(patch.object(services.completion, '_ensure_scheduler'))
        for name, kwargs in {
            'BrowserSession': {'side_effect': session}, '_initial_codex_proxy': {'return_value': ''},
            'network_preflight': {}, '_bootstrap_authorize': {}, '_sync_auth_document_context': {},
            '_submit_email_identifier': {'side_effect': email_step},
            '_submit_password_step': {'return_value': {'page_type': 'mfa_challenge', 'continue_url': '/mfa-challenge/' + factor, 'mfa_required': True}},
            '_prepare_mfa_step': {'return_value': ('https://auth.openai.com/mfa-challenge/' + factor, factor)},
            '_verify_totp_challenge': {'side_effect': verify},
        }.items():
            stack.enter_context(patch.object(oauth, name, **kwargs))
        unsubscribe = progress_events.subscribe(lambda *args: phases.append(args))
        stack.callback(unsubscribe)
        app = create_app(services=services, api_key='fixture-key')
        client = app.test_client()
        headers = {'X-Team-Console-Key': 'fixture-key'}
        ids = client.post('/api/accounts/import-password-totp', headers=headers, json={
            'text': '\n'.join(f'{email}----FixturePassword123!----JBSWY3DPEHPK3PXP' for email in emails)
        }).get_json()['imported']
        feed = app.extensions['team_console']['progress']
        feed.start()
        gateway = ConsoleASGI(app, threads=2)
        try:
            for team, row in zip([False, True], ids):
                response = client.post('/api/accounts/authorize', headers=headers, json={'account_ids': [row['id']], 'team_authorization': team})
                assert response.status_code == 202
            services.completion._scheduler_tick()
            assert at_mfa.wait(5), 'both modes must enter the real password/TOTP function'
            assert not release.is_set()

            async def inspect_stream():
                incoming, outgoing = asyncio.Queue(), asyncio.Queue()
                incoming.put_nowait({'type': 'http.request', 'body': b''})
                scope = {'type': 'http', 'method': 'GET', 'path': '/api/jobs/events',
                         'headers': [(b'x-team-console-key', b'fixture-key')]}
                task = asyncio.create_task(gateway(scope, incoming.get, outgoing.put))
                latest = None
                try:
                    response = await asyncio.wait_for(outgoing.get(), 2)
                    assert response['status'] == 200
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline:
                        body = (await asyncio.wait_for(outgoing.get(), 2)).get('body', b'')
                        if not body.startswith(b'event:'): continue
                        kind, raw = body.decode().strip().split('\n', 1)
                        payload = json.loads(raw[6:])
                        if kind == 'event: snapshot': latest = payload['data']
                        else:
                            delta = payload['delta']
                            for key in ('team', 'pipeline'):
                                if key in delta:
                                    by_id = {row['id']: row for row in latest[key]}
                                    for ident in delta[key]['remove']: by_id.pop(ident, None)
                                    by_id.update({row['id']: row for row in delta[key]['upsert']})
                                    latest[key] = [by_id[ident] for ident in delta[key]['order']]
                            for key in ('authorization', 'runtime'):
                                if key in delta: latest[key] = delta[key]
                        if len(latest['pipeline']) == 2 and all(row.get('progress_stage') == 'mfa' for row in latest['pipeline']):
                            break
                    assert all(row.get('progress_stage') == 'mfa' for row in latest['pipeline']), latest
                    assert all(row['finished'] == 0 and row['running'] == 1 for row in latest['authorization'])
                    assert latest['runtime']['workers'] == 100 and latest['runtime']['running'] == 2
                    assert {row['team_authorization'] for row in latest['authorization']} == {False, True}
                    assert not release.is_set(), 'progress must arrive BEFORE either authorization completes'
                    encoded = json.dumps(latest)
                    assert 'FixturePassword' not in encoded and 'JBSWY3DPEHPK3PXP' not in encoded
                    return {'modes': 2, 'visible_before_completion': True, 'workers': 100,
                            'phase_to_sse_ms': round((time.monotonic() - max(event_times)) * 1000, 1), 'external_requests': 0}
                finally:
                    incoming.put_nowait({'type': 'http.disconnect'})
                    await task
            report = asyncio.run(inspect_stream())
            stage_events = [event for event in phases if event[0] == 'phase']
            for ident in {event[1] for event in stage_events}:
                order = [event[2] for event in stage_events if event[1] == ident]
                assert order == ['starting', 'credentials', 'session_init', 'network_preflight', 'bootstrap', 'email_submit', 'password', 'mfa'], order
            print(json.dumps(report), flush=True)
        finally:
            release.set()
            retry.shutdown_executor(wait=True)
            feed.stop()
            gateway.wsgi.executor.shutdown(wait=True)


if __name__ == '__main__':
    main()
