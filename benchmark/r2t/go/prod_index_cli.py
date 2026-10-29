"""Go-only original-source index producer; no runnable-stack registration."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile

from .context import ContextTable
from .prod_index import GO_PROD_PATHS, GoIndexRefused, _removables
from .prod_index_entry import source_inventory

RUN = '/r2t-go/run'
SOURCE = RUN + '/work'
PAYLOAD = RUN + '/index-payload'
ANALYSIS_TIMEOUT = 1800  # static producer deadline, not an item test timeout


def _refuse(message):
    raise GoIndexRefused('REFUSED: Go index-prod: ' + message)


def _processes(text):
    lines = text.splitlines()
    if len(lines) < 3 or lines[0] != 'R2T_PROCESSES/1' or lines[-1] != 'R2T_PROCESSES_END':
        _refuse('incomplete process census')
    rows = lines[1:-1]
    if any(not re.fullmatch(r'[1-9][0-9]* [0-9]+ [0-9]+ [0-9]+ [0-9]+', row) for row in rows) \
            or len({row.split()[0] for row in rows}) != len(rows):
        _refuse('corrupt process census')
    return base64.b64encode(('\n'.join(rows)+'\n').encode()).decode()


class IndexTransport:
    """Own only run state in an operator-named, otherwise idle analysis container.

    The qualified Bash process/execute/cleanup/retire leaves are reused without
    constructing ExecutionCopy, whose stripped-seed preconditions do not apply.
    """
    def __init__(self, container, image_id):
        self.container, self.image_id = container, image_id
        self.reference = None
        self.quarantined = False

    def _docker(self, args, timeout=120):
        from ..core import docker_cli as DC
        DC.reset_phase()
        DC.require_authority_reference(self.reference, live=True)
        return subprocess.run(DC.docker_command(args), capture_output=True,
                              text=True, timeout=timeout)

    def _checked(self, args, timeout=120):
        result = self._docker(args, timeout)
        if result.returncode:
            _refuse(f'Docker {args[0]} failed: {result.stderr or result.stdout}')
        return result.stdout

    def _support(self, verb, *args, timeout=120):
        script = Path(__file__).with_name('execution_support.sh').read_text()
        return self._docker(['exec', self.container, '/bin/bash', '-c', script,
                             'r2t-index', verb, *args], timeout)

    def _support_checked(self, verb, *args, timeout=120):
        result = self._support(verb, *args, timeout=timeout)
        if result.returncode:
            _refuse(f'{verb} failed: {result.stderr or result.stdout}')
        return result.stdout

    def _inspect(self):
        rows = json.loads(self._checked(['inspect', self.container]))
        if len(rows) != 1:
            _refuse('ambiguous analysis container')
        info = rows[0]
        if not re.fullmatch(r'[0-9a-f]{64}', info['Id']) \
                or info['Image'] != self.image_id or not info['State']['Running'] \
                or info['HostConfig']['NetworkMode'] != 'none' or info['Mounts']:
            _refuse('analysis container must be running, unmounted, network-none and match --image-id')
        self.container = info['Id']  # no later command resolves a mutable name

    def _payload_files(self):
        return ('prod_index.py', 'prod_index.go', 'context.py', 'prod_index_entry.py')

    def _entry_module(self):
        return 'r2t.go.prod_index_entry'

    def run(self, source, request):
        from ..core import docker_cli as DC
        from .execution import _payload
        _, self.reference = DC.begin_phase()
        self._inspect()
        baseline = _processes(self._support_checked('processes'))
        owned = False
        previous_term = signal.getsignal(signal.SIGTERM)
        def interrupted(signum, frame):
            raise KeyboardInterrupt('Go index producer interrupted by SIGTERM')
        signal.signal(signal.SIGTERM, interrupted)
        try:
            # An absent run directory is the ownership boundary. Never reuse
            # or erase another invocation's run state or a benchmark worker.
            self._checked(['exec', self.container, '/bin/mkdir', RUN])
            owned = True
            self._checked(['exec', self.container, '/bin/mkdir', SOURCE, PAYLOAD])
            self._checked(['cp', str(source)+'/.', self.container+':'+SOURCE])
            with tempfile.TemporaryDirectory(prefix='go-index-payload-') as temporary:
                payload = Path(temporary)
                package = payload/'r2t/go'; package.mkdir(parents=True)
                for name in self._payload_files():
                    shutil.copyfile(Path(__file__).with_name(name), package/name)
                (payload/'request.json').write_text(json.dumps(request))
                self._checked(['cp', str(payload)+'/.', self.container+':'+PAYLOAD])
            self._inspect()
            result = self._support('execute', str(ANALYSIS_TIMEOUT), '/usr/bin/env',
                'PYTHONDONTWRITEBYTECODE=1', 'PYTHONPATH='+PAYLOAD,
                '/usr/bin/python3', '-m', self._entry_module(), PAYLOAD+'/request.json',
                timeout=ANALYSIS_TIMEOUT+15)
            output = _payload(self._support_checked('read', RUN, 'stdout.log'), 'BYTES').decode()
            if result.returncode:
                _refuse(f'analysis failed (rc={result.returncode}): {output}')
            document = json.loads(output)
            if document.get('root') != request['original_root'] or document.get('image_id') != self.image_id \
                    or [row['go_suite'] for row in document.get('contexts', [])] != request['contexts']:
                _refuse('index output differs from original root/image/context inputs')
            table = ContextTable(request['closures'], boundary=None, project='coddy-agent')
            for row in document['contexts']:
                context = row['go_suite']
                if row.get('answer_files') != list(table.files_for(
                        context['feature_path'], context['scenario_line'])):
                    _refuse('index output differs from witnessed answer files')
            return document
        finally:
            # A second catchable cancellation must not strand the compiler
            # while the existing process-group cleanup establishes quiescence.
            previous_int = signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            try:
                if owned:
                    cleanup = self._support_checked('cleanup', baseline, timeout=15)
                    if cleanup != 'R2T_CLEANUP/1\ncomplete\nR2T_CLEANUP_END\n':
                        _refuse('process cleanup was not proved')
                    self._support_checked('retire')
            except BaseException as error:
                self.quarantined = True
                _refuse(f'analysis container {self.container} quarantined; cleanup failed: {error}')
            finally:
                signal.signal(signal.SIGINT, previous_int)
                signal.signal(signal.SIGTERM, previous_term)


def _destination(args, project):
    from ..core.constants import PROD_INDEX_NAMES
    from ..core.paths import project_path
    expected = Path(project_path(project, 'artifacts')).absolute()
    artifacts = Path(args.artifacts).absolute()
    if artifacts != expected:
        _refuse(f'--artifacts must name this project artifacts directory: {expected}')
    if artifacts.resolve() != artifacts:
        _refuse('artifact directory traverses a symlink')
    output = artifacts / PROD_INDEX_NAMES['go']
    if os.path.lexists(output):
        _refuse(f'output already exists: {output}')
    return output


def _publish_index(output, document):
    # The final name becomes visible only after complete, durable serialization.
    # A same-directory hard link publishes atomically and refuses an existing
    # destination, including one created after the caller's last check.
    descriptor, temporary = tempfile.mkstemp(prefix='.go-prod-index-', dir=output.parent)
    stage = Path(temporary)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(document, stream, indent=1, sort_keys=True)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.link(stage, output)
    finally:
        stage.unlink(missing_ok=True)


def cmd_index_prod(args, profile):
    from ..bench import cli as bench_cli
    from .prod_index import _compilation_view
    if (profile.project, profile.language, profile.framework) != ('coddy-agent', 'go', 'godog'):
        _refuse('unsupported project/language/framework')
    boundary = bench_cli._boundary(args)
    if Path(args.boundary).resolve() != Path(profile.boundary_path).resolve():
        _refuse('CLI boundary differs from the validated profile boundary')
    if boundary.project != profile.project:
        _refuse('boundary and profile project differ')
    if not getattr(args, 'closures', None):
        _refuse('--closures must explicitly name the complete witnessed closure table')
    image_id = getattr(args, 'image_id', None)
    if not isinstance(image_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        _refuse('--image-id must name the qualified immutable image')
    if not getattr(args, '_container_explicit', False):
        _refuse('--container must explicitly name the exclusive analysis container')
    records = json.loads(Path(args.closures).read_text())
    table = ContextTable(records, boundary=boundary, project=profile.project)
    contexts = sorted((table.context_for(row['feature_file'], row['scenario_line']) for row in records),
                      key=lambda row: (row['feature_path'], row['scenario_line']))
    root = Path(boundary.repo_root).resolve()
    if not (root/'go.mod').is_file():
        _refuse('original source must contain go.mod and every removable file')
    removable = sorted(_removables(root, [p for p, _ in boundary.removable], contexts))
    paths = list(args.path or GO_PROD_PATHS)
    if any(not isinstance(path, str) or path.startswith('/') or '..' in Path(path).parts
           or Path(path).as_posix() != path or path in ('', '.') for path in paths) \
            or len(paths) != len(set(paths)):
        _refuse('production roots must be unique exact relative paths')
    output = _destination(args, profile.project)
    original = source_inventory(root)
    with tempfile.TemporaryDirectory(prefix='go-index-source-') as temporary:
        temporary = Path(temporary).resolve()
        if temporary.is_relative_to(root) or root.is_relative_to(temporary):
            _refuse('host temporary directory must be disjoint from original source')
        snapshot = temporary/'source'
        _compilation_view(root, snapshot, set())
        if source_inventory(snapshot) != original or source_inventory(root) != original:
            _refuse('source changed while preparing the original snapshot')
        request = {'original_root': str(root), 'inventory': original, 'contexts': contexts,
                   'closures': records, 'removable_paths': removable, 'paths': paths, 'image_id': image_id}
        document = IndexTransport(args.container, image_id).run(snapshot, request)
    if source_inventory(root) != original:
        _refuse('original host source changed during indexing')
    output.parent.mkdir(parents=True, exist_ok=True)
    _destination(args, profile.project)  # recheck after the live operation
    _publish_index(output, document)
    print(json.dumps({'wrote': str(output), 'image_id': image_id, **document['counts']}))
    return 0
