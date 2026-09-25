"""Single-process production entrypoint; business queues use their own pools."""
import logging
import os


def server_options():
    threads = int(os.getenv('TEAM_CONSOLE_HTTP_THREADS', '16'))
    if not 1 <= threads <= 64:
        raise ValueError('TEAM_CONSOLE_HTTP_THREADS must be between 1 and 64')
    return {
        'host': os.getenv('TEAM_CONSOLE_HOST', '127.0.0.1'),
        'port': int(os.getenv('TEAM_CONSOLE_PORT', '5050')),
        'threads': threads,
        'channel_timeout': 120,
        'max_request_body_size': 8 * 1024 * 1024,
        'ident': 'Team Console',
    }


def main():
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s')
    from waitress import serve
    from server import app
    # Do not use multiple WSGI processes: locks, queues and JSON caches are
    # process-local. The imported entrypoint starts exactly one index writer.
    serve(app, **server_options())


if __name__ == '__main__':
    main()
