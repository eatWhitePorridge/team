"""Authenticated, read-only probe. Never put the key in argv or log output."""
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

from dotenv import load_dotenv
from static_assets import check_static_assets


def check_health():
    load_dotenv(Path(__file__).with_name('.env'), override=False)
    key = os.getenv('TEAM_CONSOLE_API_KEY', '').strip()
    if not key:
        raise RuntimeError('access key is missing')
    check_static_assets()
    port = int(os.getenv('TEAM_CONSOLE_PORT', '5050'))
    req = Request(f'http://127.0.0.1:{port}/api/health',
                  headers={'X-Team-Console-Key': key})
    with urlopen(req, timeout=5) as response:
        payload = json.load(response)
    status = payload.get('index', {})
    if not payload.get('ok') or not status.get('ready') or status.get('error'):
        raise RuntimeError('read index is not healthy')
    # Backend health alone cannot detect a broken login page/static deployment.
    with urlopen(Request(f'http://127.0.0.1:{port}/', method='HEAD'), timeout=5) as response:
        if response.status != 200 or 'text/html' not in response.headers.get('Content-Type', ''):
            raise RuntimeError('frontend entry is not healthy')


if __name__ == '__main__':
    try:
        check_health()
    except Exception as exc:
        print(f'health check failed: {type(exc).__name__}')
        raise SystemExit(1)
