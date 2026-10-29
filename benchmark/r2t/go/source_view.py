"""Go 1.25 syntax inventories from original bytes, without loading subject code.

The shared builder owns edits and nesting. Target selection checks active-file
membership; all-production declaration checks deliberately include inactive
files. Inventories are not cached: source bytes or item tags cannot reuse a
previous file's resolution.
"""
from __future__ import annotations

import atexit
import base64
from dataclasses import dataclass
from functools import lru_cache
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tempfile

from ..core.source_view import BodyEdit, BodyRef, ViewRefused


@dataclass(frozen=True)
class GoSourceInventory:
    bodies: tuple[BodyEdit, ...]
    declarations: tuple[dict, ...]
    contract_only_reasons: tuple[dict, ...]
    active: bool
    runtime: dict


def _context(go_context):
    # The stack owns this existing carrier's closed shape and semantics.
    from .context import validate_suite_context, ContextRefused
    try:
        return validate_suite_context(go_context)
    except ContextRefused as exc:
        raise ViewRefused(f'Go source-view context: {exc}') from exc


def _environment(scratch):
    env = {key: value for key, value in os.environ.items() if not key.startswith('GO')}
    env.update(GOTOOLCHAIN='local', GOWORK='off', GOPROXY='off', GOSUMDB='off',
               GOENV='off', GO111MODULE='off', GOFLAGS='',
               GOCACHE=str(scratch / 'cache'), GOTMPDIR=str(scratch / 'tmp'),
               TMPDIR=str(scratch / 'tmp'))
    return env


def _tools(go, go_scratch):
    if not isinstance(go, str) or not Path(go).is_absolute():
        raise ViewRefused('Go source views require an explicit absolute go executable')
    if not isinstance(go_scratch, str) or not Path(go_scratch).is_absolute():
        raise ViewRefused('Go source views require explicit absolute trusted scratch')
    scratch = Path(go_scratch).resolve()
    if scratch == Path('/work') or Path('/work') in scratch.parents:
        raise ViewRefused('Go source-view helper scratch must be outside /work')
    try:
        scratch.mkdir(parents=True, exist_ok=True)
        (scratch / 'tmp').mkdir(exist_ok=True)
        stat = Path(go).stat()
        # Only trusted-helper compilation is cached, with the executable file
        # identity and helper bytes; source resolution below is always fresh.
        return _compiler(go, str(scratch), (stat.st_dev, stat.st_ino, stat.st_size,
                         stat.st_mtime_ns, stat.st_ctime_ns),
                         Path(__file__).with_suffix('.go').read_bytes())
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise ViewRefused(f'cannot prepare Go source-view helper: {exc}') from exc


@lru_cache(maxsize=None)
def _compiler(go, scratch_name, tool_identity, helper_bytes):
    scratch = Path(scratch_name)
    env = _environment(scratch)
    observed = subprocess.run([go, 'env', '-json', 'GOVERSION', 'GOOS', 'GOARCH',
                               'CGO_ENABLED', 'GOROOT'],
                              capture_output=True, check=True, env=env)
    runtime = json.loads(observed.stdout)
    if runtime['GOVERSION'] != 'go1.25.0':
        raise ViewRefused('Go source views require qualified go1.25.0')
    directory = tempfile.TemporaryDirectory(prefix='source-view-', dir=scratch)
    try:
        source = Path(directory.name) / 'source_view.go'
        source.write_bytes(helper_bytes)
        binary = Path(directory.name) / 'source-view'
        result = subprocess.run([go, 'build', '-o', str(binary), str(source)],
                                capture_output=True, env=env)
        if result.returncode:
            raise ViewRefused('cannot compile trusted Go source-view helper: ' +
                              result.stderr.decode('utf-8', errors='replace'))
    except BaseException:
        directory.cleanup()
        raise
    atexit.register(directory.cleanup)
    return str(binary), env, runtime


def source_inventories(sources: dict[str, bytes], *, go: str, go_context: dict,
                       go_scratch: str) -> dict[str, GoSourceInventory]:
    """Parse all supplied files, including tag-inactive source, in one helper.

    Caller supplies the stack-validated canonical suite carrier. Toolchain and
    platform facts come from the explicit image/worker executable, separately
    from that carrier. No subject imports, type checking, generation or tests.
    """
    context = _context(go_context)
    binary, env, observed = _tools(go, go_scratch)
    requests = []
    for path, raw in sources.items():
        if not isinstance(path, str) or PurePosixPath(path).is_absolute() \
                or '..' in PurePosixPath(path).parts or not path.endswith('.go'):
            raise ViewRefused(f'invalid Go source path: {path}')
        try:
            raw.decode('utf-8')
        except UnicodeError as exc:
            raise ViewRefused(f'{path}: Go source must be UTF-8') from exc
        requests.append(json.dumps({'path': path, 'raw': base64.b64encode(raw).decode('ascii'),
                                    'build_tags': context['go_build_tags']}))
    try:
        result = subprocess.run([binary], input='\n'.join(requests).encode('utf-8'),
                                capture_output=True, env=env)
    except OSError as exc:
        raise ViewRefused(f'cannot launch Go source parser: {exc}') from exc
    if result.returncode:
        raise ViewRefused('Go source parsing failed: ' + result.stderr.decode('utf-8', errors='replace'))
    try:
        rows = [json.loads(line) for line in result.stdout.splitlines()]
    except ValueError as exc:
        raise ViewRefused('Go source parser returned invalid output') from exc
    if len(rows) != len(sources):
        raise ViewRefused('Go source parser did not return every requested file')
    inventories = {}
    for (path, raw), row in zip(sources.items(), rows):
        if row.get('error'):
            raise ViewRefused(f'{path}: {row["error"]}')
        runtime = {key: row[key] for key in ('toolchain', 'goos', 'goarch', 'cgo_enabled',
                                            'release_tags', 'tool_tags')}
        if (runtime['toolchain'], runtime['goos'], runtime['goarch'], runtime['cgo_enabled']) != (
                observed['GOVERSION'], observed['GOOS'], observed['GOARCH'], observed['CGO_ENABLED'] == '1'):
            raise ViewRefused('Go helper runtime differs from the qualified toolchain')
        edits = []
        for body in row['bodies']:
            start, end = body['start_byte'], body['end_byte']
            if not 0 <= start < end <= len(raw) or raw[start:start+1] != b'{' or raw[end-1:end] != b'}':
                raise ViewRefused(f'{path}: invalid physical Go body span')
            edits.append(BodyEdit(BodyRef(path, body['declaration_id'], body['kind'], start, end),
                                  b'{ panic("implementation hidden") }'))
        inventories[path] = GoSourceInventory(tuple(edits), tuple(row['bodies']),
                                              tuple(row['issues']), row['active'], runtime)
    return inventories


def source_inventory(path: str, raw: bytes, **tools) -> GoSourceInventory:
    return source_inventories({path: raw}, **tools)[path]


def source_bodies(path: str, raw: bytes, **tools) -> tuple[BodyEdit, ...]:
    """Resolve targets only in active files; declaration refusals are all-scope.

    A supported callable remains targetable in a file whose unrelated computed
    initializer needs an explicit all-production contract-only omission.
    """
    inventory = source_inventory(path, raw, **tools)
    if not inventory.active:
        raise ViewRefused(f'{path}: target implementation is inactive for this Go suite context')
    return inventory.bodies


def parse_source(path: str, raw: bytes, **tools) -> None:
    """Syntax acceptance of supplied bytes, also for inactive transformed files."""
    source_inventory(path, raw, **tools)
