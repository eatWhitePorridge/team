"""Native async SSE alongside the existing, bounded-thread Flask application."""
import asyncio
import hmac
import json

from a2wsgi import WSGIMiddleware
from .progress import difference, event_frame


class ConsoleASGI:
    def __init__(self, app, *, threads=16, max_body=8 * 1024 * 1024, heartbeat=15, send_timeout=10, max_streams=64):
        self.app = app
        self.wsgi = WSGIMiddleware(app, workers=threads, send_queue_size=8)
        self.feed = app.extensions['team_console']['progress']
        self.max_body, self.heartbeat, self.send_timeout = max_body, heartbeat, send_timeout
        self.max_streams = max_streams

    async def _json(self, send, status, **data):
        await send({'type': 'http.response.start', 'status': status,
                    'headers': [(b'content-type', b'application/json'), (b'cache-control', b'no-store')]})
        await send({'type': 'http.response.body', 'body': json.dumps(data).encode()})

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'lifespan':
            while True:
                event = await receive()
                if event['type'] == 'lifespan.startup':
                    self.feed.start()
                    await send({'type': 'lifespan.startup.complete'})
                elif event['type'] == 'lifespan.shutdown':
                    await asyncio.to_thread(self.feed.stop)
                    self.wsgi.executor.shutdown(wait=False, cancel_futures=True)
                    await send({'type': 'lifespan.shutdown.complete'})
                    return
        if scope['type'] != 'http':
            await send({'type': 'websocket.close', 'code': 1008})
            return
        headers = dict(scope.get('headers', []))
        try:
            length = int(headers.get(b'content-length', b'0'))
        except ValueError:
            return await self._json(send, 400, ok=False, error='无效请求长度')
        if length < 0 or length > self.max_body:
            return await self._json(send, 413, ok=False, error='请求体过大')
        if scope['path'] != '/api/jobs/events':
            return await self.wsgi(scope, receive, send)
        if scope['method'] != 'GET':
            return await self._json(send, 405, ok=False, error='仅支持读取任务进度')
        provided = headers.get(b'x-team-console-key', b'')
        def authorized():
            expected = self.app.config.get('TEAM_CONSOLE_API_KEY', '').strip().encode()
            return bool(expected) and hmac.compare_digest(expected, provided)
        if not authorized():
            return await self._json(send, 401, ok=False, code='access_key_invalid', error='访问密钥无效，请重新登录')
        subscription = self.feed.subscribe(limit=self.max_streams)
        if subscription is None:
            return await self._json(send, 503, ok=False, error='进度连接已满，请稍后重试')
        token, changed = subscription
        async def disconnect():
            while (await receive())['type'] != 'http.disconnect':
                pass
        closed = asyncio.create_task(disconnect())
        previous, version = None, 0
        async def write(body):
            await asyncio.wait_for(send({'type': 'http.response.body', 'body': body, 'more_body': True}), self.send_timeout)
        try:
            await send({'type': 'http.response.start', 'status': 200, 'headers': [
                (b'content-type', b'text/event-stream; charset=utf-8'),
                (b'cache-control', b'no-cache, no-store, no-transform'),
                (b'x-accel-buffering', b'no'),
            ]})
            while not closed.done():
                changed.clear()
                if not authorized():
                    await write(event_frame('access_expired', {}))
                    break
                current_version, current, failed = self.feed.current()
                if failed:
                    await write(event_frame('unavailable', {}))
                    break
                if current is not None and current_version != version:
                    if previous is None:
                        payload = {'epoch': self.feed.epoch, 'version': current_version, 'data': current}
                        kind = 'snapshot'
                    else:
                        payload = {'epoch': self.feed.epoch, 'base': version, 'version': current_version,
                                   'delta': difference(previous, current)}
                        kind = 'update'
                    await write(event_frame(kind, payload))
                    previous, version = current, current_version
                signal = asyncio.create_task(changed.wait())
                try:
                    ready, _ = await asyncio.wait([signal, closed], timeout=self.heartbeat, return_when=asyncio.FIRST_COMPLETED)
                    if not ready:
                        await write(b': heartbeat\n\n')
                finally:
                    signal.cancel()
                    await asyncio.gather(signal, return_exceptions=True)
            if not closed.done():
                await send({'type': 'http.response.body', 'body': b'', 'more_body': False})
        except (TimeoutError, ConnectionError, OSError):
            pass
        finally:
            self.feed.unsubscribe(token)
            closed.cancel()
            await asyncio.gather(closed, return_exceptions=True)
