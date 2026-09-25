import os
from pathlib import Path

from dotenv import load_dotenv
from backend.app import create_app

load_dotenv(Path(__file__).with_name('.env'), override=False)
host = os.getenv('TEAM_CONSOLE_HOST', '127.0.0.1')
if host not in {'127.0.0.1', 'localhost', '::1'} and not os.getenv('TEAM_CONSOLE_API_KEY', '').strip():
    raise RuntimeError('对外监听必须设置 TEAM_CONSOLE_API_KEY')

# Only this entry point starts the new read-index worker; no legacy recovery.
app = create_app(start_indexer=True)

if __name__ == '__main__':
    app.run(host=host, port=int(os.getenv('TEAM_CONSOLE_PORT', '5050')), threaded=True)
