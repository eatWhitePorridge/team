from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

from .index_store import AccountIndex, BatchIndex, IndexRefresher

logger = logging.getLogger(__name__)
CONSOLE_ROOT = Path(__file__).resolve().parents[1]


def _json_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValueError('请求必须是 JSON 对象')
    return data


def _ids(data, *, max_count=500):
    raw = data.get('account_ids')
    if not isinstance(raw, list) or not 1 <= len(raw) <= max_count:
        raise ValueError(f'请选择 1-{max_count} 个账号')
    if any(type(value) is not int or value <= 0 for value in raw):
        raise ValueError('账号 ID 必须是正整数')
    return list(dict.fromkeys(raw))


def _boolean(data, key):
    value = data.get(key, False)
    if type(value) is not bool:
        raise ValueError(f'{key} 必须是布尔值')
    return value


def _queue_result(result):
    out = dict(result)
    for name in ('started', 'busy', 'skipped', 'failed', 'no_token'):
        out.setdefault(name, [])
        out[name + '_count'] = len(out[name])
    out['ok'] = out['started_count'] > 0
    if not out['ok']:
        out['error'] = f"没有新任务入队：进行中 {out['busy_count']}，跳过 {out['skipped_count']}，失败 {out['failed_count']}，无凭证 {out['no_token_count']}"
    return out


def create_app(*, services=None, index_path=None, start_indexer=False, api_key=None):
    # No data files, indexes, workers, recovery or imports of core.db at module import time.
    if services is None:
        from .services import load_services
        services = load_services()
    db = services.db
    index_path = Path(index_path or Path(getattr(services, 'data_dir', CONSOLE_ROOT / 'data')) / 'read-model.sqlite3')
    accounts_index = AccountIndex(db._ACCOUNTS_JSON, index_path)
    batches_index = BatchIndex(index_path, None, accounts_index, source_path=db._BATCHES_JSON)
    indexer = IndexRefresher(accounts_index, batches_index)
    static_root = CONSOLE_ROOT / 'frontend/dist'
    app = Flask(__name__, static_folder=None)
    app.config.update(MAX_CONTENT_LENGTH=8 * 1024 * 1024,
                      TEAM_CONSOLE_API_KEY=os.getenv('TEAM_CONSOLE_API_KEY', '') if api_key is None else api_key)
    app.extensions['team_console'] = {'accounts': accounts_index, 'batches': batches_index, 'indexer': indexer}

    @app.before_request
    def api_key_guard():
        import hmac
        expected = app.config['TEAM_CONSOLE_API_KEY'].strip()
        if expected and request.path.startswith('/api/') and not hmac.compare_digest(request.headers.get('X-Team-Console-Key', '').encode(), expected.encode()):
            return jsonify(ok=False, code='access_key_invalid', error='访问密钥无效，请重新登录'), 401

    @app.after_request
    def prevent_caching(response):
        if request.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store'
        return response

    @app.errorhandler(ValueError)
    def invalid_request(exc):
        return jsonify(ok=False, error=str(exc)), 400

    @app.errorhandler(Exception)
    def unexpected_error(exc):
        if isinstance(exc, HTTPException):
            return jsonify(ok=False, error=exc.name), exc.code
        logger.error('[Team Console] 请求失败: %s %s', request.path, type(exc).__name__)
        return jsonify(ok=False, error='处理失败，请检查服务日志；写入操作未自动重试'), 500

    @app.get('/api/health')
    def health():
        return jsonify(ok=True, service='team-console', index=indexer.status())

    @app.get('/api/auth/verify')
    def verify_access_key():
        # An empty development configuration must not authenticate arbitrary
        # input. Valid keys have already passed api_key_guard above.
        if not app.config['TEAM_CONSOLE_API_KEY'].strip():
            return jsonify(ok=False, code='access_key_unconfigured', error='后台尚未配置访问密钥'), 503
        return jsonify(ok=True)

    @app.get('/api/overview')
    def overview():
        return jsonify(ok=True, accounts=accounts_index.summary(), parents=services.team_store.list_parents(), index=indexer.status())

    @app.get('/api/settings/network')
    def network_settings():
        return jsonify(ok=True, settings=services.network.public())

    @app.post('/api/settings/network')
    def save_network_settings():
        return jsonify(ok=True, settings=services.network.update(_json_body()))

    @app.get('/api/accounts')
    def accounts():
        params = {key: request.args.get(key, '') for key in ('q', 'batch_id', 'totp_status', 'codex_state', 'codex_plan_type', 'quota_status', 'team_parent_id', 'team_seat_type', 'team_seat_status', 'driver', 'email_source', 'sort_by', 'sort_order')}
        result = accounts_index.query(page=request.args.get('page', 1, type=int), page_size=request.args.get('page_size', 50, type=int), **params)
        return jsonify(**result, index=indexer.status())

    @app.get('/api/accounts/<int:account_id>')
    def account_detail(account_id):
        row = accounts_index.get(account_id)
        if row is None:
            return jsonify(ok=False, error='账号不存在或索引尚未就绪'), 404
        return jsonify(ok=True, account=row)

    @app.post('/api/accounts/import-password-totp')
    def import_accounts():
        data = _json_body()
        start_authorization = _boolean(data, 'start_authorization')
        result = db.import_password_totp_accounts(services.parse_accounts(data.get('text')))
        indexer.request_refresh()
        # Import is already committed. Report enqueue failure separately so the
        # UI never suggests repeating the import after a partial success.
        if start_authorization and result.get('imported'):
            try:
                result['authorization'] = _queue_result(services.completion.enqueue_accounts([row['id'] for row in result['imported']], login_mode='password_totp'))
            except Exception as exc:
                logger.warning('[Team Console] 导入后授权入队失败: %s', type(exc).__name__)
                result['authorization'] = {'ok': False, 'started_count': 0, 'error': '账号已导入，但授权未入队，请选中账号单独授权'}
        return jsonify({**result, 'ok': True}), 201 if result.get('imported') else 200

    @app.post('/api/accounts/authorize')
    def authorize():
        data = _json_body()
        ids = _ids(data)
        team = _boolean(data, 'team_authorization')
        result = _queue_result(services.completion.enqueue_accounts(ids, login_mode='password_totp', team_authorization=team))
        indexer.request_refresh()
        return jsonify(result), 202 if result['ok'] else 409

    @app.post('/api/accounts/check-quota')
    def check_quota():
        result = _queue_result(services.quota.enqueue_accounts_quota_check(_ids(_json_body())))
        indexer.request_refresh()
        return jsonify(result), 202 if result['ok'] else 409

    @app.post('/api/accounts/export-totp')
    def export_totp():
        from .totp_export import export_accounts
        result = export_accounts(db, _ids(_json_body(), max_count=5000))
        if not result['exported_count']:
            return jsonify({**result, 'error': '没有可导出的三段式账号，请查看失败明细'}), 422
        return jsonify(result)

    @app.post('/api/accounts/export-sub2api')
    def export_sub2api():
        result = services.export.export_accounts(_ids(_json_body(), max_count=5000))
        if not result.get('ok') or not result.get('exported_count'):
            return jsonify({**result, 'ok': False, 'error': '没有可导出的账号，请查看失败明细'}), 422
        # Explicit download request only. Preserve per-account failures/warnings;
        # the client downloads data, not this report wrapper.
        return jsonify(result)

    @app.get('/api/batches')
    def batches():
        # OAuth uses internal job batches; these are not account imports and
        # must not appear as hundreds of new import batches after authorization.
        result = batches_index.query(page=request.args.get('page', 1, type=int), page_size=request.args.get('page_size', 50, type=int), q=request.args.get('q', ''), driver='imported')
        return jsonify(**result, index=indexer.status())

    @app.get('/api/jobs')
    def jobs():
        team_jobs = []
        for parent in services.team_store.list_parents():
            for item in services.team_store.recent_jobs(parent['id']):
                team_jobs.append({**item, 'parent_email': parent.get('email')})
        team_jobs.sort(key=lambda row: (row.get('status') in {'queued', 'running'}, row.get('created_at') or ''), reverse=True)
        return jsonify(team=team_jobs[:100], authorization=services.completion.list_authorization_batches(limit=4), pipeline=services.completion.list_items(limit=100), runtime=services.authorization.executor_status())

    @app.get('/api/team/parents/<int:parent_id>/workspaces/<workspace_id>/members')
    @app.post('/api/team/parents/<int:parent_id>/workspaces/<workspace_id>/members/search')
    def members(parent_id, workspace_id):
        args = _json_body() if request.method == 'POST' else request.args
        if any(isinstance(value, (dict, list, bool)) for value in args.values()):
            raise ValueError('成员筛选参数必须为文本或数字')
        try:
            page = int(args.get('page', 1))
            size = None if args.get('page_size') == 'all' else int(args.get('page_size', 100))
        except (ValueError, TypeError):
            raise ValueError('成员分页参数无效') from None
        if not 1 <= page <= 100000 or (size is not None and not 1 <= size <= 100):
            raise ValueError('成员分页参数超出范围')
        if size is None:
            page = 1
        if not any(row['id'] == workspace_id for row in services.team_store.workspaces(parent_id)):
            return jsonify(ok=False, error='工作区不存在'), 404
        filters = {key: str(args.get(key) or '') for key in ('seat_type', 'seat_status', 'emails', 'email_status')}
        result = services.team_store.member_page(parent_id, workspace_id, page=page, page_size=size,
                                                query=str(args.get('q') or '')[:254], **filters)
        # The legacy enrichment scans the account JSON. Match only this page
        # against our indexed public projection, with ambiguous emails explicit.
        emails = sorted({str(row.get('email') or '').strip().casefold() for row in result['items']} - {''})
        matches = {}
        for offset in range(0, len(emails), 100):
            matches.update(accounts_index.by_emails(emails[offset:offset + 100]))
        items = []
        for row in result['items']:
            email = str(row.get('email') or '').strip().casefold()
            match = matches.get(email)
            items.append({**row, 'local_account': match,
                          'local_account_match': 'matched' if match is not None else 'ambiguous' if email in matches else 'missing'})
        return jsonify({**result, 'items': items, 'index': indexer.status()})

    # Deliberately bypass register_team_admin(): it mutates existing jobs and
    # starts schedule recovery, which belongs to the original service owner.
    app.register_blueprint(services.team_blueprint)

    @app.get('/')
    @app.get('/<path:path>')
    def frontend(path=''):
        if path.startswith('api/'):
            abort(404)
        if not (static_root / 'index.html').is_file():
            return '前端尚未构建，请在 team-console/frontend 执行 npm run build', 503
        if path:
            return send_from_directory(static_root, path)
        return send_from_directory(static_root, 'index.html')

    if start_indexer:
        indexer.start()
    return app
