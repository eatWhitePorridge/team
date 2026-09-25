"""Legacy operation adapters, loaded only by an explicitly created application."""
from pathlib import Path
import sys
from types import SimpleNamespace
from .storage_scope import bind_database, bind_service_paths, data_directory


def load_services():
    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from core import db
    directory = bind_database(db, data_directory())
    from core import account_completion_service, quota_check_service, sub2api_export, team_admin_store
    from core import codex_retry_service, codex_oauth, account_cookie_store, http_diagnostics, account_export
    bind_service_paths(directory, completion=account_completion_service, retry=codex_retry_service,
                       oauth=codex_oauth, cookies=account_cookie_store,
                       diagnostics=http_diagnostics, account_export=account_export)
    from core.password_totp_import import parse_accounts
    import config
    from config import proxy
    from .network_settings import NetworkSettings
    network = NetworkSettings(directory / 'network-settings.json', proxy, config)
    from .authorization_runtime import configure
    authorization = configure(codex_retry_service)
    from webui.team_admin_routes import blueprint
    # Register routes only. register_team_admin() also recovers old jobs and
    # resumes schedules; a second management surface must NEVER call it.
    return SimpleNamespace(db=db, data_dir=directory, network=network, authorization=authorization, completion=account_completion_service,
                           quota=quota_check_service, export=sub2api_export,
                           team_store=team_admin_store, parse_accounts=parse_accounts,
                           team_blueprint=blueprint)
