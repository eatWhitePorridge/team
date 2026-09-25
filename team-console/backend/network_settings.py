"""Private, atomic network overrides for the new console only."""
from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from urllib.parse import quote, urlsplit


def normalize_proxy(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ValueError('代理地址不能为空或超过 4096 字符')
    value = value.strip()
    if '://' not in value:
        parts = value.split(':', 3)
        if len(parts) == 4 and parts[1].isdigit() and parts[2]:
            value = f'socks5h://{quote(parts[2], safe="")}:{quote(parts[3], safe="")}@{parts[0]}:{parts[1]}'
        else:
            value = 'http://' + value
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme in {'http', 'https', 'socks5', 'socks5h'} and parsed.hostname
                 and parsed.port and not parsed.query and not parsed.fragment
                 and parsed.path in {'', '/'} and not any(c.isspace() for c in value))
        if not valid or (parsed.username and ('***' in parsed.username or '***' in (parsed.password or ''))):
            raise ValueError()
    except ValueError:
        # Never reflect a rejected URL: it may contain a password.
        raise ValueError('代理格式无效，请使用 socks5h://用户:密码@主机:端口 等完整地址') from None
    return value


def masked_proxy(value):
    if not value:
        return ''
    try:
        parsed = urlsplit(normalize_proxy(value))
        host = f'[{parsed.hostname}]' if ':' in parsed.hostname else parsed.hostname
        credentials = '***:***@' if parsed.username is not None else ''
        return f'{parsed.scheme}://{credentials}{host}:{parsed.port}'
    except (ValueError, TypeError):
        return '（已有代理格式无法识别，请替换）'


class NetworkSettings:
    def __init__(self, path, proxy_config, top_config):
        self.path = Path(path)
        self.proxy_config, self.top_config = proxy_config, top_config
        self.lock = threading.RLock()
        self.state = {
            'proxy_pool': list(proxy_config.PROXY_POOL),
            'quota_proxy_mode': str(proxy_config.PLAN_CHECK_PROXY_MODE),
            'quota_proxy': str(proxy_config.PLAN_CHECK_PROXY or ''),
        }
        self.overridden = False
        if self.path.exists():
            data = json.loads(self.path.read_text())
            if not isinstance(data, dict) or data.get('version') != 1:
                raise RuntimeError('网络配置文件损坏，未回退为直连')
            self.state = self._validate(data['settings'])
            self.overridden = True
            self._apply()

    @staticmethod
    def _validate(data):
        if not isinstance(data, dict) or set(data) != {'proxy_pool', 'quota_proxy_mode', 'quota_proxy'}:
            raise ValueError('网络配置字段不完整')
        pool = data['proxy_pool']
        if not isinstance(pool, list) or len(pool) > 10000:
            raise ValueError('代理池最多 10000 条')
        if not isinstance(data['quota_proxy_mode'], str) or data['quota_proxy_mode'] not in {'auto', 'proxy', 'direct'}:
            raise ValueError('额度代理模式必须是 auto、proxy 或 direct')
        return {'proxy_pool': list(dict.fromkeys(normalize_proxy(x) for x in pool)),
                'quota_proxy_mode': data['quota_proxy_mode'],
                'quota_proxy': normalize_proxy(data['quota_proxy']) if data['quota_proxy'] else ''}

    def _apply(self):
        values = {'PROXY_POOL': list(self.state['proxy_pool']),
                  'PLAN_CHECK_PROXY_MODE': self.state['quota_proxy_mode'],
                  'PLAN_CHECK_PROXY': self.state['quota_proxy']}
        for module in (self.proxy_config, self.top_config):
            for name, value in values.items():
                setattr(module, name, value)

    def public(self):
        with self.lock:
            return {'source': 'override' if self.overridden else 'deployment',
                    'pool_count': len(self.state['proxy_pool']),
                    'pool_preview': [masked_proxy(x) for x in self.state['proxy_pool'][:10]],
                    'quota_proxy_mode': self.state['quota_proxy_mode'],
                    'quota_proxy_configured': bool(self.state['quota_proxy']),
                    'quota_proxy_preview': masked_proxy(self.state['quota_proxy'])}

    def update(self, data):
        allowed = {'pool_action', 'proxy_pool', 'quota_proxy_mode', 'quota_proxy_action', 'quota_proxy'}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError('不支持的网络配置字段')
        with self.lock:
            candidate = dict(self.state)
            for action_key, field in (('pool_action', 'proxy_pool'), ('quota_proxy_action', 'quota_proxy')):
                action = data.get(action_key, 'keep')
                if not isinstance(action, str) or action not in {'keep', 'replace', 'clear'}:
                    raise ValueError('请选择保留、替换或清空代理')
                if action == 'replace':
                    value = data.get(field)
                    if not isinstance(value, str) or not value.strip() or len(value.encode()) > 2 * 1024 * 1024:
                        raise ValueError('替换代理不能为空或超过 2MB；清空请显式选择“清空”')
                    candidate[field] = [x.strip() for x in value.splitlines() if x.strip()] if field == 'proxy_pool' else value
                elif action == 'clear':
                    candidate[field] = [] if field == 'proxy_pool' else ''
            if 'quota_proxy_mode' in data:
                candidate['quota_proxy_mode'] = data['quota_proxy_mode']
            candidate = self._validate(candidate)
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            temporary = None
            try:
                with tempfile.NamedTemporaryFile('w', dir=self.path.parent, prefix='.network-', delete=False) as handle:
                    temporary = Path(handle.name)
                    json.dump({'version': 1, 'settings': candidate}, handle)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.path)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
            self.state, self.overridden = candidate, True
            self._apply()
            return self.public()
