"""351-account dispatch with large synthetic history, real workers and SSE.

All storage is temporary, all OAuth/network calls are mocked. No browser/UI.
"""
import asyncio
import json
import logging
import os
import threading
import time
from collections import Counter
from contextlib import ExitStack
from unittest.mock import patch


def main():
    assert os.getenv('PYTHON_DOTENV_DISABLED') == '1' and os.getenv('TEAM_CONSOLE_DATA_DIR')
    logging.disable(logging.CRITICAL)
    from backend.services import load_services
    from backend.app import create_app
    from backend.asgi import ConsoleASGI
    services = load_services()
    from core import codex_oauth, codex_retry_service as retry, progress_events, team_schedule_service
    db, completion = services.db, services.completion
    emails = [f'worker-{n}@example.invalid' for n in range(351)]
    gates = {email: threading.Event() for email in emails}
    entered, active, entered_at = set(), set(), {}
    condition, stopping = threading.Condition(), threading.Event()
    peak = 0
    terminal_at = []
    first_job = [None]

    def oauth(email, **kwargs):
        nonlocal peak
        progress_events.phase('mfa')
        with condition:
            entered.add(email); active.add(email); entered_at[email] = time.monotonic()
            peak = max(peak, len(active)); condition.notify_all()
        try:
            assert gates[email].wait(40), 'fixture release timed out'
            return {'ok': True, 'status': 'success', 'credential': {
                'email': email, 'refresh_token': 'fixture-only-refresh-token', 'account_id': 'fixture-workspace',
                'plan_type': 'free' if kwargs.get('auto_retry', True) else 'self_serve_business_prolite'}}
        finally:
            with condition:
                active.remove(email)

    def scheduled():
        if stopping.is_set(): raise SystemExit()

    def commit_event(topic, job_id=None, phase=None):
        if topic == 'job' and job_id == first_job[0] and gates[emails[0]].is_set():
            terminal_at.append(time.monotonic())

    with ExitStack() as stack:
        stack.enter_context(patch('requests.sessions.Session.request', side_effect=AssertionError('network forbidden')))
        stack.enter_context(patch('curl_cffi.requests.Session.request', side_effect=AssertionError('network forbidden')))
        stack.enter_context(patch.object(codex_oauth, 'run_codex_oauth', side_effect=oauth))
        stack.enter_context(patch.object(team_schedule_service, 'refresh_waiting', side_effect=scheduled))
        stack.callback(progress_events.subscribe(commit_event))
        for start in range(0, 875, 500):
            db.import_password_totp_accounts(services.parse_accounts('\n'.join(
                f'history-{n}@example.invalid----FixturePassword123!----JBSWY3DPEHPK3PXP'
                for n in range(start, min(start + 500, 875)))))
        accounts = db._load_accounts()
        for row in accounts: row['fixture_history'] = 'x' * 1400
        db._save_accounts(accounts)
        batches = db._load_batches()
        template = db._registration_batch_row(batches, count=1, workers=100, email_source='existing_account',
                                               flow_snapshot={'registration_driver': 'protocol'})
        db._save_batches([*batches, *[{**template, 'batch_id': f'old-internal-{n}', 'fixture_history': 'x' * 400} for n in range(3000)]])
        jobs = db.create_registration_jobs_bulk(count=3000, email_source='existing_account', batch_id='old-internal-0')
        for row in jobs: row.update(status='success', fixture_history='x' * 900)
        db._save_jobs(jobs)
        completion._write_rows([{'id': f'history-{n}', 'batch_id': 'history', 'batch_total': 5000,
            'account_id': 1, 'login_mode': 'password_totp', 'status': 'success', 'stage': 'complete',
            'created_at': '2026-09-01T00:00:00', 'message': 'x' * 300} for n in range(5000)])
        sizes = {name: path.stat().st_size for name, path in {
            'accounts': db._ACCOUNTS_JSON, 'jobs': db._JOBS_JSON, 'batches': db._BATCHES_JSON,
            'pipeline': completion._STATE_PATH}.items()}
        app = create_app(services=services, api_key='fixture-key')
        client = app.test_client(); headers = {'X-Team-Console-Key': 'fixture-key'}
        ids = [row['id'] for row in client.post('/api/accounts/import-password-totp', headers=headers, json={
            'text': '\n'.join(f'{email}----FixturePassword123!----JBSWY3DPEHPK3PXP' for email in emails)
        }).get_json()['imported']]
        feed = app.extensions['team_console']['progress']; feed.start()
        gateway = ConsoleASGI(app, threads=2)
        submissions = stack.enter_context(patch.object(completion.registration_service, 'submit_account_codex_oauth',
            wraps=completion.registration_service.submit_account_codex_oauth))
        writes = Counter()
        original_write = db._write_json
        def write(path, data):
            writes[path.name] += 1
            return original_write(path, data)
        stack.enter_context(patch.object(db, '_write_json', side_effect=write))
        started = time.monotonic()
        try:
            response = client.post('/api/accounts/authorize', headers=headers, json={'account_ids': ids})
            assert response.status_code == 202
            batch_id = response.get_json()['batch_id']
            with condition:
                assert condition.wait_for(lambda: len(entered) >= 100, timeout=20), f'only {len(entered)} entered OAuth'
            ramp = max(entered_at.values()) - started
            assert peak == 100 and len(entered) == 100
            deadline = time.monotonic() + 10
            while retry.executor_status()['queued'] != 251 and time.monotonic() < deadline: time.sleep(.01)
            assert retry.executor_status()['queued'] == 251
            assert submissions.call_count == 4, '351 accounts must use four bulk admissions, not 351'
            assert writes[db._JOBS_JSON.name] == 4, dict(writes)
            assert writes[db._BATCHES_JSON.name] == 4, dict(writes)
            first_job[0] = next(row['codex_job_id'] for row in completion.list_items(limit=5000) if row['account_id'] == ids[0])

            async def measure_completion():
                incoming, outgoing = asyncio.Queue(), asyncio.Queue()
                incoming.put_nowait({'type': 'http.request', 'body': b''})
                task = asyncio.create_task(gateway({'type': 'http', 'method': 'GET', 'path': '/api/jobs/events',
                    'headers': [(b'x-team-console-key', b'fixture-key')]}, incoming.get, outgoing.put))
                try:
                    assert (await asyncio.wait_for(outgoing.get(), 3))['status'] == 200
                    while True:
                        body = (await asyncio.wait_for(outgoing.get(), 3))['body']
                        if body.startswith(b'event: snapshot'): break
                    payload = json.loads(body.decode().split('\ndata: ', 1)[1])
                    assert next(b for b in payload['data']['authorization'] if b['batch_id'] == batch_id)['finished'] == 0
                    release_at = time.monotonic(); gates[emails[0]].set()
                    while True:
                        body = (await asyncio.wait_for(outgoing.get(), 5))['body']
                        if not body.startswith(b'event: update'): continue
                        delta = json.loads(body.decode().split('\ndata: ', 1)[1])['delta']
                        batch = next((b for b in delta.get('authorization', []) if b['batch_id'] == batch_id), None)
                        if batch and batch['finished'] >= 1:
                            assert batch['finished'] == 1 and batch['active'] == 350
                            assert sum(g.is_set() for g in gates.values()) == 1
                            assert terminal_at, 'progress must follow the committed child result'
                            return {'release_to_sse_ms': round((time.monotonic() - release_at) * 1000, 1),
                                    'commit_to_sse_ms': round((time.monotonic() - terminal_at[0]) * 1000, 1)}
                finally:
                    incoming.put_nowait({'type': 'http.disconnect'}); await task
            latency = asyncio.run(measure_completion())
            with condition:
                assert condition.wait_for(lambda: len(entered) == 101, timeout=5), 'slot not refilled'
            report = {'accounts': 351, 'history_bytes': sizes, 'workers': 100, 'peak_oauth_calls': peak,
                      'ramp_seconds': round(ramp, 3), 'bulk_submissions': submissions.call_count,
                      'next_started_while_350_unfinished': len(entered) == 101, 'external_requests': 0, **latency}
            print(json.dumps(report), flush=True)
        finally:
            stopping.set(); completion._WAKE.set()
            if completion._THREAD: completion._THREAD.join(timeout=10)
            assert not completion._THREAD or not completion._THREAD.is_alive()
            # Cancel fixture-only queued futures so cleanup need not authorize
            # the other 250 fake accounts. No production storage is mounted.
            retry.get_executor().shutdown(wait=False, cancel_futures=True)
            for gate in gates.values(): gate.set()
            retry.shutdown_executor(wait=True)
            feed.stop(); gateway.wsgi.executor.shutdown(wait=True)


if __name__ == '__main__': main()
