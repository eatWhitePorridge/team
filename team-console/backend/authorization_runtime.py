"""Process-local authorization capacity, independent of legacy .env reloads."""
import os


def configure(retry_service):
    raw = os.getenv('TEAM_CONSOLE_AUTH_WORKERS', '100').strip() or '100'
    try:
        workers = int(raw)
    except ValueError:
        raise ValueError('TEAM_CONSOLE_AUTH_WORKERS must be an integer from 1 to 100') from None
    if not 1 <= workers <= 100:
        raise ValueError('TEAM_CONSOLE_AUTH_WORKERS must be between 1 and 100')
    retry_service.configure_executor_limit(workers)
    return retry_service
