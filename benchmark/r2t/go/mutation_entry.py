"""Stdlib-only original-source Go mutation producer for the qualified image.

The native helper owns typed enumeration and compile validity. Shared manifest
validation and identity arithmetic stay on the host, outside this payload.
"""
from __future__ import annotations

import io
import os
import tarfile
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from .interfaces_attribution import partitions
from .prod_index import GO_PROD_PATHS, _inputs, _compilation_view, _removables
from .prod_index_entry import source_inventory

SCHEMA = 'r2t.go-mutation-enumeration/1'


def _require(value, reason):
    if not value:
        raise ValueError('REFUSED: Go mutation producer: ' + reason)


def _save(path, document):
    Path(path).write_text(json.dumps(document, sort_keys=True, indent=2) + '\n')


def _invoke(argv, *, cwd, env, evidence):
    evidence = Path(evidence)
    _save(evidence.with_suffix('.command.json'), {'argv': list(argv), 'cwd': str(cwd)})
    stdout_path, stderr_path = evidence.with_suffix('.stdout'), evidence.with_suffix('.stderr')
    try:
        # The outer deadline can kill this coordinator before run() returns.
        # Give the child the evidence descriptors so already-written bytes survive.
        with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
            result = subprocess.run(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr)
    except BaseException as error:
        _save(evidence.with_suffix('.failure.json'), {'error': repr(error)})
        raise
    _save(evidence.with_suffix('.result.json'), {'returncode': result.returncode})
    return subprocess.CompletedProcess(result.args, result.returncode,
                                       stdout_path.read_bytes(), stderr_path.read_bytes())


def enumerate_copy(source_root, *, go, go_scratch, closures, prod_index,
                   removable_paths, original_inventory, evidence_dir,
                   engine_source, expected_engine_sha256, compile_workers=1):
    """Run the existing engine once in fresh exact-context compilation views.

    Inputs are already authenticated by the host. Recheck the staged bytes;
    preserve complete/partial compiler evidence even when the census refuses.
    No executable test binary leaves scratch or runs here.
    """
    _require(type(compile_workers) is int and 1 <= compile_workers <= 32,
             "compile workers must be between 1 and 32")
    root = Path(source_root).resolve()
    evidence = Path(evidence_dir).resolve()
    scratch = Path(go_scratch).resolve()
    _require(not evidence.is_relative_to(root) and not root.is_relative_to(evidence),
             'evidence must be disjoint from original source')
    _require(not evidence.is_relative_to(scratch) and not scratch.is_relative_to(evidence),
             'evidence must be disjoint from compiler scratch')
    engine = Path(engine_source).read_bytes()
    _require(hashlib.sha256(engine).hexdigest() == expected_engine_sha256,
             'staged engine differs from pinned authority')
    groups, contexts = partitions(closures, prod_index)
    _require(source_inventory(root) == original_inventory, 'original source differs before enumeration')
    root, scratch, _, env, _ = _inputs(str(root), go, go_scratch, GO_PROD_PATHS)
    # _inputs removes inherited Go settings. Limit each construction compiler
    # here; measured tests and the shared source-index environment are unchanged.
    env['GOMAXPROCS'] = '1'
    removable = _removables(root, removable_paths, [g['context'] for g in groups])
    evidence.mkdir(parents=True, exist_ok=False)
    try:
        version = _invoke([go, 'version'], cwd=root, env=env, evidence=evidence/'go-version')
        _require(version.returncode == 0, 'independent Go version probe failed')
        parser = version.stdout.decode().strip()
        _require(parser == 'go version go1.25.0 linux/amd64', 'unqualified parser version')
        source_files = {p: row['sha256'] for p, row in original_inventory.items() if 'sha256' in row}
        with tempfile.TemporaryDirectory(prefix='go-mutations-', dir=scratch) as directory:
            support = Path(directory)
            binary, helper = support/'mutate', support/'mutate.go'
            helper.write_bytes(engine)
            (evidence/'mutate.go').write_bytes(engine)
            try:
                built = _invoke([go, 'build', '-p=1', '-o', str(binary), str(helper)],
                                cwd=support, env=env, evidence=evidence/'build-engine')
                _require(built.returncode == 0, 'Go mutation engine did not compile')
                requests = []
                for i, group in enumerate(groups):
                    view = support/('view-' + str(i))
                    _compilation_view(root, view, removable - set(group['files']))
                    c = group['context']
                    requests.append({'root': str(view), 'package_dir': c['package_dir'],
                        'package_name': c['package_name'], 'glue_path': c['glue_path'],
                        'go_build_tags': c['go_build_tags']})
                request_path, output = support/'contexts.json', support/'enumeration.json'
                _save(request_path, {'contexts': requests, 'source_files': source_files})
                result = _invoke([str(binary), '--root', str(root), '--build-contexts', str(request_path),
                    '--operator-profile', 'v2', '--record-enumerator-rev',
                    '--compile-workers', str(compile_workers), '--out', str(output)],
                    cwd=support, env=env, evidence=evidence/'engine')
                _require(result.returncode == 0, 'native typed/compile-valid enumeration failed')
                report = json.loads((support/'typed-candidates.json').read_text())
                expected = [{'package_dir': g['context']['package_dir'],
                    'go_build_tags': g['context']['go_build_tags'], 'production_files': g['production_files']}
                    for g in groups]
                _require(report.get('contexts') == expected, 'compiled production contexts differ from index')
                return {'parser': parser, 'envelope': json.loads(output.read_text()),
                        'typed_candidates': report, 'contexts': contexts,
                        'engine_sha256': expected_engine_sha256}
            finally:
                for path in support.iterdir():
                    if path.is_file() and (path.suffix in ('.json', '.stdout', '.stderr') or path.name == 'mutate.go'):
                        (evidence/path.name).write_bytes(path.read_bytes())
    finally:
        _require(source_inventory(root) == original_inventory, 'original source changed during enumeration')


def main(request_path):
    request = json.loads(Path(request_path).read_text())
    root, evidence = '/r2t-go/run/work', Path('/r2t-go/run/mutation-evidence')
    result = {'schema': SCHEMA, 'root': request['original_root'], 'image_id': request['image_id']}
    try:
        _require(source_inventory(root) == request['inventory'], 'staged original source differs')
        names = ['GOVERSION', 'GOOS', 'GOARCH', 'CGO_ENABLED', 'GOTOOLCHAIN',
                 'GOPROXY', 'GOWORK', 'GOFLAGS', 'GOMODCACHE']
        probe = subprocess.run(['/usr/local/go/bin/go', 'env', '-json', *names],
                               capture_output=True, check=True, text=True)
        observed = json.loads(probe.stdout)
        _require(observed == {'GOVERSION': 'go1.25.0', 'GOOS': 'linux', 'GOARCH': 'amd64',
            'CGO_ENABLED': '1', 'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOWORK': 'off',
            'GOFLAGS': '-mod=readonly', 'GOMODCACHE': '/opt/r2t-go/pkg/mod'}, 'unqualified image environment')
        result['runtime'] = observed
        result.update(enumerate_copy(root, go='/usr/local/go/bin/go',
            go_scratch='/r2t-go/run/mutation-support', closures=request['closures'],
            prod_index=request['prod_index'], removable_paths=request['removable_paths'],
            original_inventory=request['inventory'], evidence_dir=evidence,
            engine_source=Path(__file__).with_name('mutate.go'),
            expected_engine_sha256=request['engine_sha256'],
            compile_workers=request['compile_workers']))
    except BaseException as error:
        result['failure'] = repr(error)
    finally:
        print(json.dumps(result, sort_keys=True))
    return 1 if 'failure' in result else 0


EVIDENCE_END = '.r2t-evidence-complete.json'


def export_evidence(output=None, *, evidence_root='/r2t-go/run/mutation-evidence',
                    support_root='/r2t-go/run/mutation-support'):
    """Stream flat diagnostics after cleanup, including interrupted engines.

    Support leaves override copied evidence leaves, matching the previous JSON
    export. Directory iteration and archive writes never collect all filenames
    or file contents in memory.
    """
    output = sys.stdout.buffer if output is None else output
    support = Path(support_root)
    roots = sorted(p for p in support.glob('go-mutations-*') if p.is_dir())
    roots.insert(0, Path(evidence_root))
    count = size = 0
    with tarfile.open(fileobj=output, mode='w|') as archive:
        for index, root in enumerate(roots):
            if not root.exists():
                continue
            with os.scandir(root) as entries:
                for entry in entries:
                    name = entry.name
                    if not entry.is_file(follow_symlinks=False) or not (
                            Path(name).suffix in ('.json', '.stdout', '.stderr') or name == 'mutate.go'):
                        continue
                    if any((later/name).is_file() for later in roots[index+1:]):
                        continue
                    _require(name != EVIDENCE_END, 'reserved evidence filename')
                    info = archive.gettarinfo(entry.path, arcname=name)
                    with open(entry.path, 'rb') as stream:
                        archive.addfile(info, stream)
                    archive.members.clear()
                    archive.inodes.clear()
                    count += 1
                    size += info.size
        complete = json.dumps({'files': count, 'bytes': size}).encode()
        info = tarfile.TarInfo(EVIDENCE_END)
        info.size = len(complete)
        archive.addfile(info, io.BytesIO(complete))


if __name__ == '__main__':
    if sys.argv[1:] == ['--evidence']:
        export_evidence()
    else:
        raise SystemExit(main(sys.argv[1]))
