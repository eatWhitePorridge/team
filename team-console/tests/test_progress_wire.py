"""Loopback HTTP framing test; ephemeral fixture app, never the user's service."""
import json
import socket
import threading
import time
import unittest

import httpx
import uvicorn
from flask import Flask, request
from backend.asgi import ConsoleASGI
from backend.progress import ProgressFeed
from test_progress import fixtures


class ProgressWireTests(unittest.TestCase):
    def test_uvicorn_flushes_phase_while_stream_remains_open_and_wsgi_api_works(self):
        feed = ProgressFeed(fixtures())
        app = Flask(__name__)
        app.config['TEAM_CONSOLE_API_KEY'] = 'fixture-key'
        app.extensions['team_console'] = {'progress': feed}
        app.add_url_rule('/probe', view_func=lambda: {'ok': True})
        app.add_url_rule('/echo', endpoint='echo', view_func=lambda: {'message': request.get_json()['message']}, methods=['POST'])
        gateway = ConsoleASGI(app, threads=1)
        server = uvicorn.Server(uvicorn.Config(gateway, workers=1, loop='asyncio', http='h11', ws='none',
                                               access_log=False, log_level='critical', lifespan='on', timeout_graceful_shutdown=1))
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        thread = threading.Thread(target=server.run, kwargs={'sockets': [sock]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 3
            while not server.started and time.monotonic() < deadline: time.sleep(0.005)
            self.assertTrue(server.started)
            with httpx.Client(base_url=f'http://127.0.0.1:{port}', trust_env=False, timeout=2) as client:
                self.assertEqual(client.get('/api/jobs/events').status_code, 401)
                with client.stream('GET', '/api/jobs/events', headers={'X-Team-Console-Key': 'fixture-key'}) as response:
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.headers['x-accel-buffering'], 'no')
                    lines = response.iter_lines()
                    def frame():
                        kind = ''
                        for line in lines:
                            if line.startswith('event: '): kind = line[7:]
                            if line.startswith('data: '): return kind, json.loads(line[6:])
                        raise AssertionError('stream closed unexpectedly')
                    kind, snapshot = frame()
                    self.assertEqual(kind, 'snapshot')
                    # The only WSGI thread remains available during this SSE.
                    self.assertTrue(client.get('/probe').json()['ok'])
                    self.assertEqual(client.post('/echo', json={'message': '离线请求体校验'}).json(), {'message': '离线请求体校验'})
                    start = time.monotonic()
                    feed.changed('phase', 41, 'mfa')
                    kind, delta = frame()
                    self.assertEqual(kind, 'update')
                    self.assertEqual(delta['delta']['pipeline']['upsert'][0]['progress_stage'], 'mfa')
                    self.assertLess(time.monotonic() - start, 2)
                    self.assertEqual(snapshot['data']['authorization'][0]['finished'], 0)
        finally:
            server.should_exit = True
            thread.join(timeout=5)
            feed.stop()
            sock.close()
            self.assertFalse(thread.is_alive(), 'isolated fixture server did not stop')
