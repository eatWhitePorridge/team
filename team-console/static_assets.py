"""Read-only deployment check. No browser, application startup or business I/O."""
from html.parser import HTMLParser
import os
from pathlib import Path
from urllib.parse import unquote, urlsplit


class _AssetReferences(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name in {'src', 'href'} and value and value.startswith('/assets/'):
                self.paths.append(unquote(urlsplit(value).path).lstrip('/'))


def check_static_assets(root=None):
    root = Path(root or Path(__file__).parent / 'frontend' / 'dist').resolve()
    # read_text, traversal and open must all succeed with the service UID.
    html = (root / 'index.html').read_text(encoding='utf-8')
    references = _AssetReferences()
    references.feed(html)
    if not html.strip() or not references.paths:
        raise RuntimeError('frontend entry has no bundled assets')
    assets = root / 'assets'
    if not assets.is_dir() or not assets.resolve().is_relative_to(root):
        raise RuntimeError('frontend assets directory is missing')
    # Includes lazy-loaded route chunks, not only the entrypoint in index.html.
    # rglob can silently suppress PermissionError in inaccessible directories.
    def unreadable(error):
        raise error
    paths = {root / path for path in references.paths}
    for directory, directories, files in os.walk(assets, onerror=unreadable):
        paths.update(Path(directory) / name for name in [*directories, *files])
    for path in paths:
        if not path.resolve().is_relative_to(assets.resolve()):
            raise RuntimeError('frontend asset points outside bundle')
        if path.is_dir():
            continue
        with path.open('rb') as handle:
            if not handle.read(1):
                raise RuntimeError('frontend asset is empty')


if __name__ == '__main__':
    check_static_assets()
    print('Frontend files readable by service user.')
