"""Offline real queue probe. Temporary storage and mocked OAuth transport only.

Run via test_authorization_runtime.py, which supplies an empty temporary data
directory, disables deployment dotenv, and enforces a process timeout.
"""
import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from unittest.mock import patch


def main():
    assert os.getenv('PYTHON_DOTENV_DISABLED') == '1'
    assert os.getenv('TEAM_CONSOLE_DATA_DIR')
    logging.disable(logging.CRITICAL)
    from backend.services import load_services
    from backend.app import create_app
    services = load_services()
    from core import codex_retry_service as retry, codex_oauth, registration_service
    from config import codex
    import config

    workers = 100
    emails = [f'worker-{n}@example.invalid' for n in range(120)]
    gates = {email: threading.Event() for email in emails}
    condition = threading.Condition()
    entered = set()
    active = set()
    modes = set()
    peak = 0

    def oauth(email, **kwargs):
        nonlocal peak
        assert kwargs['login_mode'] == 'password_totp'
        mode = 'ordinary' if kwargs.get('auto_retry', True) else 'team'
        with condition:
            entered.add(email)
            active.add(email)
            modes.add(mode)
            peak = max(peak, len(active))
            condition.notify_all()
        try:
            assert gates[email].wait(30), 'fixture release timed out'
            return {'ok':False, 'status':'failed', 'message':'offline transport fixture'}
        finally:
            with condition:
                active.remove(email)

    def await_entries(total):
        with condition:
            assert condition.wait_for(lambda: len(entered) >= total, timeout=20), f'only {len(entered)} tasks entered'

    report = {}
    with ExitStack() as stack:
        stack.enter_context(patch('requests.sessions.Session.request', side_effect=AssertionError('network forbidden')))
        stack.enter_context(patch('curl_cffi.requests.Session.request', side_effect=AssertionError('network forbidden')))
        stack.enter_context(patch.object(codex_oauth, 'run_codex_oauth', side_effect=oauth))
        stack.enter_context(patch.object(services.completion, '_ensure_scheduler'))
        reload_config = stack.enter_context(patch.object(config, 'reload_all', side_effect=AssertionError('per-task config reload forbidden')))
        # A legacy worker hint/config value must not shrink or replace this pool.
        stack.enter_context(patch.object(codex, 'CODEX_RETRY_WORKERS', 7))
        pool = retry.get_executor()
        assert retry.get_executor(max_workers=2) is pool
        assert pool._max_workers == workers
        with patch.object(registration_service, 'get_executor', wraps=registration_service.get_executor) as executor_route:
            app = create_app(services=services, api_key='fixture-key')
            client = app.test_client()
            headers = {'X-Team-Console-Key':'fixture-key'}
            imported = client.post('/api/accounts/import-password-totp', headers=headers, json={
                'text':'\n'.join(f'{email}----FixturePassword123!----JBSWY3DPEHPK3PXP' for email in emails),
            })
            assert imported.status_code == 201
            ids = [row['id'] for row in imported.get_json()['imported']]
            started = time.monotonic()
            try:
                for team, selected in [(False, ids[:60]), (True, ids[60:])]:
                    response = client.post('/api/accounts/authorize', headers=headers, json={'account_ids':selected, 'team_authorization':team})
                    assert response.status_code == 202 and response.get_json()['started_count'] == 60
                assert services.completion._scheduler_tick() == 120
                await_entries(100)
                first = client.get('/api/jobs', headers=headers).get_json()['runtime']
                assert first['workers'] == first['running'] == first['peak_running'] == workers, first
                assert first['queued'] == 20 and len(entered) == 100, first
                assert modes == {'ordinary', 'team'}
                ramp = time.monotonic() - started
                gates[emails[0]].set()
                await_entries(101)
                second = client.get('/api/jobs', headers=headers).get_json()['runtime']
                assert second['running'] == 100 and second['queued'] == 19, second
                assert sum(gate.is_set() for gate in gates.values()) == 1
                assert peak == 100
                assert all(call.kwargs.get('pool') == 'codex' for call in executor_route.call_args_list)
                assert registration_service._executor is None
                reload_config.assert_not_called()
                # Internal OAuth job batches must not pollute imported batches.
                app.extensions['team_console']['indexer'].refresh_once()
                batches = client.get('/api/batches', headers=headers).get_json()
                assert batches['total'] == 1 and batches['items'][0]['account_total'] == 120
                report = {'workers':workers, 'peak_oauth_calls':peak, 'initial_running':first['running'],
                          'initial_queued':first['queued'], 'refill_started_before_batch_finished':len(entered),
                          'after_refill_queued':second['queued'], 'ramp_seconds':round(ramp, 3),
                          'modes':sorted(modes), 'import_batches':batches['total'], 'external_requests':0}
            finally:
                for gate in gates.values(): gate.set()
                retry.shutdown_executor(wait=True)
    print(json.dumps(report), flush=True)

    # Futures cancelled before start, exceptions and failed submit cannot leak
    # counters. This is a separate synthetic pool, never an authorization pool.
    pool = retry._TrackedExecutor(max_workers=1)
    gate = threading.Event()
    started = threading.Event()
    try:
        def block():
            started.set()
            assert gate.wait(5)
        first = pool.submit(block)
        assert started.wait(5)
        second = pool.submit(lambda: None)
        assert pool.counters()['queued'] == 1 and second.cancel()
        assert pool.counters()['queued'] == 0
        gate.set(); first.result(timeout=5)
        def fail(): raise ValueError('fixture error')
        failed = pool.submit(fail)
        try: failed.result(timeout=5)
        except ValueError: pass
        else: raise AssertionError('missing future error')
    finally:
        gate.set(); pool.shutdown(wait=True)
    try: pool.submit(lambda: None)
    except RuntimeError: pass
    else: raise AssertionError('submit after shutdown succeeded')
    assert pool.counters() == {'running':0, 'queued':0, 'peak_running':1}
    print('counter cancellation/error cleanup passed', flush=True)


if __name__ == '__main__':
    main()
