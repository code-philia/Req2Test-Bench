"""Go indexing on an exclusive bound worker; closure promotion replays S3.

The operator reserves this worker/container for this entire command. Bootstrap,
compiler preparation and native captures share its existing copy lifecycle;
other evaluations or index-prod must not use it concurrently. The parser stage
claims native feature selection only, never a subject test or admission.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess

from ..bench import cli as bench_cli
from ..bench.validate import HARNESS_VERSION
from ..bench.worker import validate_live_worker_runtime
from ..core.paths import project_path
from . import bootstrap
from .closure import recompute, gold_sidecar
from .closure_plan import _snapshot, _seed_files, _removable
from .execution import ExecutionCopy
from .registry import index_items, _require
from .workspace import load_worker_workspace

INDEX_DIR = 'go-index'
COLLECTION = 'collection'
PROMOTED = ('closures.json', 'gold-sidecars.json', 'go_closure_census.json')
PARSER_ARGV = ['/bin/bash', '-c',
    'exec /usr/local/go/bin/go run -p=1 ./_bench/go/support/bootstrap_select.go < _bench/go/bootstrap-request.json']


def _save(path, document):
    path.write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')


def _inputs(args):
    profile = bench_cli._stack_profile(args)
    boundary = bench_cli._boundary(args)
    _require((profile.project, profile.language, profile.framework) == ('coddy-agent', 'go', 'godog')
             and boundary.project == profile.project, 'Go index requires the coddy-agent profile and boundary')
    _require(Path(args.boundary).resolve() == Path(profile.boundary_path).resolve(),
             'CLI boundary differs from the validated profile boundary')
    _require(getattr(args, 'features', None) == 'features',
             'Go index requires the original --features features census')
    source = Path(getattr(args, 'source_root', None) or project_path(profile.project, 'source')).resolve()
    artifacts = Path(args.artifacts).resolve()
    workspace = Path(boundary.repo_root).resolve()
    for first, second in ((source, artifacts), (source, workspace), (artifacts, workspace)):
        _require(not first.is_relative_to(second) and not second.is_relative_to(first),
                 'original source, workspace and artifacts must be disjoint')
    return boundary, source, artifacts


class BootstrapSelector:
    """One native parsing command, guarded by the existing execution-copy API."""
    def __init__(self, execution_copy, evidence, binding):
        self.copy, self.evidence, self.binding = execution_copy, Path(evidence), binding

    def __call__(self, request, *, helper, deadline):
        self.evidence.mkdir()
        helper_bytes = Path(helper).read_bytes()
        request_bytes = (json.dumps(request) + '\n').encode()
        (self.evidence / 'bootstrap_select.go').write_bytes(helper_bytes)
        (self.evidence / 'request.json').write_bytes(request_bytes)
        observed = {'purpose': 'native-feature-parsing', 'subject_executed': False,
                    'argv': list(PARSER_ARGV), 'worker_binding': self.binding,
                    'timeout': False, 'cleanup_baseline_restored': False}
        try:
            self.copy.prepare_bootstrap({
                '_bench/go/support/bootstrap_select.go': helper_bytes,
                '_bench/go/bootstrap-request.json': request_bytes}, deadline=deadline)
            observed['inventory_before'] = self.copy.inventory(forward=True)
            result = self.copy.run_planner(PARSER_ARGV)
            observed.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
            observed['inventory_after'] = self.copy.inventory()
        except BaseException as exc:
            observed['error'] = type(exc).__name__ + ': ' + str(exc)
            observed['timeout'] = isinstance(exc, subprocess.TimeoutExpired)
            if isinstance(exc, subprocess.TimeoutExpired):
                observed['stdout'] = exc.output.decode(errors='replace') if isinstance(exc.output, bytes) else exc.output
                observed['stderr'] = exc.stderr.decode(errors='replace') if isinstance(exc.stderr, bytes) else exc.stderr
            raise
        finally:
            observed['processes'] = deepcopy(self.copy.process_evidence)
            try:
                if not self.copy.quarantined and self.copy._state in {'prepared', 'planned', 'ready', 'executed'}:
                    self.copy.retire()
                    observed['cleanup_baseline_restored'] = True
            except BaseException as exc:
                observed['cleanup_error'] = type(exc).__name__ + ': ' + str(exc)
                raise
            finally:
                _save(self.evidence / 'observed.json', observed)
        return observed


def cmd_index(args):
    """Bootstrap all 282 headers, derive 58 preparations and collect once."""
    boundary, source, artifacts = _inputs(args)
    output = artifacts / INDEX_DIR
    _require(not output.exists(), 'Go index output must be fresh; failed evidence is not resumed')
    _require(not any((artifacts / name).exists() for name in (*PROMOTED, 'items.jsonl')),
             'Go index cannot replace already promoted artifacts')
    go = shutil.which('go')
    _require(go is not None, 'Go index requires the pinned host Go executable')
    manifest, bound_boundary, runner, inventory, bound = load_worker_workspace(args)
    _require(bound_boundary == boundary, 'bound workspace boundary differs')
    original = _snapshot(source)
    expected = _seed_files({'source_files': {p: hashlib.sha256(raw).hexdigest() for p, raw in original.items()}},
                           _removable(boundary, original))
    _require(inventory == expected, 'bound stripped seed differs from the exact original source and Go support')
    copy = ExecutionCopy(runner, original_inventory=inventory, boundary=boundary, original_manifest=manifest)
    # Shared v3 validation authenticates the whole pool and live authority before
    # the first container operation. Existing worker mount policy is unchanged.
    live = validate_live_worker_runtime(args.worker, bound['worker'], HARNESS_VERSION,
        needs_database=False, answer_paths=(str(source), str(artifacts), str(Path(args.gold).resolve())),
        expected_runtime={key: bound['runtime'][key] for key in (
            'harness_version', 'container_image_digest', 'workspace_seed_digest', 'database_dump_digest')})
    selected = live['selected']
    runner.container = selected['binding']['container']['id']
    binding = {'runtime_path': selected['runtime_path'], 'runtime_sha256': selected['runtime_sha256'],
               'container': selected['binding']['container'],
               'docker_execution_authority': live['docker_execution_authority'],
               'docker_execution_pool_digest': live['docker_execution_pool_digest'],
               'exclusive_indexing_worker': True}
    output.mkdir(parents=True)
    previous = signal.getsignal(signal.SIGTERM)
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Go indexing interrupted by SIGTERM')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        packet = bootstrap.bootstrap_items(source, go=str(Path(go).resolve()),
            selector=BootstrapSelector(copy, output / 'bootstrap', binding))
        _save(output / 'bootstrap.json', packet)
        index_items(packet['items'], execution_copy=copy, boundary=boundary, source_root=source,
                    output_dir=output / COLLECTION, go=str(Path(go).resolve()))
    except BaseException as exc:
        _save(output / 'failure.json', {'error': type(exc).__name__, 'message': str(exc)})
        raise
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(f"Indexed {len(packet['items'])} Go candidates -> {output / COLLECTION}; run closures to validate and promote")
    return 0


def _verified_bootstrap(packet, source_root):
    """Rejoin saved native parser evidence to the clean source without Go."""
    proof = packet['proof']
    _require(proof['source_commit'] == bootstrap.PINNED_COMMIT
             and proof['inspection']['source_commit'] == bootstrap.PINNED_COMMIT
             and proof['closure_qualified'] is False and proof['admitted'] is False,
             'bootstrap proof source or preparation status differs')
    for field, name in (('ast_helper_sha256', 'bootstrap.go'), ('selection_helper_sha256', 'bootstrap_select.go')):
        saved = proof['inspection'][field] if field == 'ast_helper_sha256' else proof[field]
        _require(saved == bootstrap._sha(bootstrap._helper(name).read_bytes()), 'bootstrap helper identity differs')
    source = _snapshot(source_root)
    bootstrap.verify_suites(proof['inspection']['ast'], source)
    request = bootstrap.selection_request(proof['inspection']['ast'], source)
    _require(proof['request'] == request, 'saved parser request differs from original suite source')
    observed = proof['observed']
    _require(observed['returncode'] == 0 and observed['timeout'] is False
             and observed['cleanup_baseline_restored'] is True,
             'saved native parser did not complete cleanly')
    native = json.loads(observed['stdout'])
    raw, counts = bootstrap.extract_project('coddy-agent', str(source_root), subdir='features', language='go', framework='godog')
    _require(len(raw) == 354 and counts == {'features': 61, 'skipped': []}, 'original raw extraction differs')
    census = bootstrap.candidate_census(source_root)
    _require(json.loads(json.dumps(census)) == proof['candidate_census'], 'saved candidate census differs')
    items = bootstrap.assemble_items(raw, census, proof['inspection'], request, native)
    _require(items == packet['items'], 'saved items differ from source-bound native selection')
    # Context insertion order is part of the captured JSON bytes hashed by S3.
    # Equality proves the values; preserve the verified packet's recorded order.
    return deepcopy(packet['items'])


def cmd_closures(args):
    """Reconstruct S3, then promote the existing producer bytes; no native calls."""
    boundary, source, artifacts = _inputs(args)
    output = artifacts / INDEX_DIR
    collection = output / COLLECTION
    packet = json.loads((output / 'bootstrap.json').read_text())
    items = _verified_bootstrap(packet, source)
    witnesses = json.loads((collection / 'witnesses.json').read_text())
    closures, census = recompute(items, witnesses, boundary=boundary, repo_root=boundary.repo_root,
                                 artifacts=collection, source_root=source)
    expected = {'closures.json': closures, 'go_closure_census.json': census,
                'gold-sidecars.json': [gold_sidecar(row) for row in closures]}
    staged = {}
    for name, value in expected.items():
        path = collection / name
        raw = path.read_bytes()
        _require(json.loads(raw) == value, 'saved ' + name + ' differs from S3 reconstruction')
        staged[name] = (path, raw)
    by_id = {row['item_id']: row for row in closures}
    _require(len(by_id) == len(items) and set(by_id) == {item['item_id'] for item in items},
             'reconstructed closures differ from the bootstrap item population')
    joined = deepcopy(items)
    for item in joined:
        row = by_id[item['item_id']]
        _require(row['go_suite'] == item['go_suite'], 'closure changed original suite context')
        item['files'] = list(row['files'])
    item_bytes = ''.join(json.dumps(item, ensure_ascii=False) + '\n' for item in joined).encode()
    staged['items.jsonl'] = (output / 'items.jsonl', item_bytes)
    # Check every destination before any promotion. Identical completed output
    # may be reused; changed or partial evidence never replaces previous bytes.
    for name, (_, raw) in staged.items():
        path = artifacts / name
        _require(not path.exists() or path.read_bytes() == raw, 'existing ' + name + ' differs')
    item_stage = staged['items.jsonl'][0]
    if item_stage.exists():
        _require(item_stage.read_bytes() == item_bytes, 'staged enriched items differ')
    else:
        with item_stage.open('xb') as stream:
            stream.write(item_bytes)
    for name, (path, raw) in staged.items():
        destination = artifacts / name
        if not destination.exists():
            os.link(path, destination)
    print(f'Validated and promoted {len(items)} Go closures and multi-file items -> {artifacts}')
    return 0
