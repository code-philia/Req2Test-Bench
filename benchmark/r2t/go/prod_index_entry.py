"""Trusted stdlib-only entry point staged beside the Go index in its image."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def source_inventory(root):
    """Bind the complete supplied copy, including fixture links and empty dirs."""
    root = Path(root)
    rows = {}

    def visit(directory):
        for path in sorted(directory.iterdir()):
            relative = path.relative_to(root).as_posix()
            if relative == '.git':
                continue
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                row = {'link': os.readlink(path)}
            elif stat.S_ISDIR(mode):
                row = {'directory': True}
                visit(path)
            elif stat.S_ISREG(mode):
                digest = hashlib.sha256()
                with path.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(chunk)
                row = {'sha256': digest.hexdigest()}
            else:
                raise ValueError(f'non-file source input: {relative}')
            rows[relative] = row
    visit(root)
    return rows


def main(request_path):
    from .prod_index import build_prod_index
    request = json.loads(Path(request_path).read_text())
    root = '/r2t-go/run/work'
    expected = request['inventory']
    if source_inventory(root) != expected:
        raise ValueError('staged original source differs from the host snapshot')
    # Qualify the image's actual environment before the index normalizes it.
    variables = ['GOVERSION', 'GOOS', 'GOARCH', 'CGO_ENABLED', 'GOTOOLCHAIN',
                 'GOPROXY', 'GOWORK', 'GOFLAGS', 'GOMODCACHE']
    probe = subprocess.run(['/usr/local/go/bin/go', 'env', '-json', *variables],
                           capture_output=True, check=True, text=True)
    observed = json.loads(probe.stdout)
    required = {'GOVERSION': 'go1.25.0', 'GOOS': 'linux', 'GOARCH': 'amd64',
                'CGO_ENABLED': '1', 'GOTOOLCHAIN': 'local', 'GOPROXY': 'off',
                'GOWORK': 'off', 'GOFLAGS': '-mod=readonly',
                'GOMODCACHE': '/opt/r2t-go/pkg/mod'}
    if observed != required:
        raise ValueError(f'unqualified Go image environment: {observed}')
    try:
        result = build_prod_index(root, go='/usr/local/go/bin/go',
            go_contexts=request['contexts'], go_closures=request['closures'],
            removable_paths=request['removable_paths'],
            paths=request['paths'], go_scratch='/r2t-go/run/index-support')
    finally:
        if source_inventory(root) != expected:
            raise ValueError('original source changed during Go indexing')
    result['root'] = request['original_root']
    result['image_id'] = request['image_id']
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main(sys.argv[1])
