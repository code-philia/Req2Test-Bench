"""Go population build/map over the existing source-only analysis transport.

The complete shared attestation reader is mandatory. No Go field is removed
or rehashed to make an unsupported population acceptable to that reader.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import subprocess
import tempfile
import time

from ..data import mutation as M
from ..data import mutation_attestation as A
from ..toolkit import mutation_audit as AUDIT
from ..toolkit import mutation_go as G
from .context import ContextTable
from .interfaces_attribution import partitions
from .mutation_entry import SCHEMA, EVIDENCE_END
from .prod_index import GO_PROD_PATHS, _compilation_view, _removables
from .prod_index_cli import IndexTransport, PAYLOAD, ANALYSIS_TIMEOUT
from .prod_index_entry import source_inventory


def _require(value, reason):
    if not value:
        raise G.GoMutationRefused('REFUSED: Go mutants: ' + reason)


def _save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


class MutationTransport(IndexTransport):
    """Same exclusive analysis lifecycle, retaining all transport/engine facts."""
    def __init__(self, container, image_id, evidence_dir, construction_timeout=ANALYSIS_TIMEOUT):
        super().__init__(container, image_id)
        self.evidence = Path(evidence_dir)
        self.sequence = 0
        self.construction_timeout = construction_timeout

    def _payload_files(self):
        return ('prod_index.py', 'context.py', 'prod_index_entry.py',
                'interfaces_attribution.py', 'mutation_entry.py', 'mutate.go')

    def _entry_module(self):
        return 'r2t.go.mutation_entry'

    def _docker(self, args, timeout=120):
        prefix = self.evidence / ('transport-%05d' % self.sequence)
        self.sequence += 1
        row = {'argv': args, 'timeout_seconds': timeout, 'started_unix': time.time()}
        _save(prefix.with_suffix('.json'), row)
        started = time.monotonic()
        try:
            result = super()._docker(args, timeout)
            prefix.with_suffix('.stdout').write_text(result.stdout)
            prefix.with_suffix('.stderr').write_text(result.stderr)
            row['returncode'] = result.returncode
            return result
        except subprocess.TimeoutExpired as error:
            for suffix, raw in (('.stdout', error.output), ('.stderr', error.stderr)):
                if raw is not None:
                    prefix.with_suffix(suffix).write_bytes(raw if isinstance(raw, bytes) else raw.encode())
            row['error'] = repr(error)
            raise
        except BaseException as error:
            row['error'] = repr(error)
            raise
        finally:
            row['duration_seconds'] = time.monotonic() - started
            _save(prefix.with_suffix('.json'), row)

    def _support(self, verb, *args, timeout=120):
        if verb == 'execute':
            budget = getattr(self, 'construction_timeout', ANALYSIS_TIMEOUT)
            args = (str(budget), *args[1:])
            timeout = budget + 15
        if verb == 'retire':
            # Housekeeping is construction work, never a measured test. The
            # complete diagnostic tree can exceed the short Docker default.
            timeout = max(ANALYSIS_TIMEOUT, getattr(self, 'construction_timeout', ANALYSIS_TIMEOUT))
            archive = self._export_evidence(timeout)
            _extract_evidence(archive, self.evidence/'native')
        return super()._support(verb, *args, timeout=timeout)

    def _export_evidence(self, timeout):
        from ..core import docker_cli as DC
        DC.reset_phase()
        DC.require_authority_reference(self.reference, live=True)
        args = ['exec', self.container, '/usr/bin/env',
            'PYTHONDONTWRITEBYTECODE=1', 'PYTHONPATH=' + PAYLOAD,
            '/usr/bin/python3', '-m', self._entry_module(), '--evidence']
        prefix = self.evidence / ('transport-%05d' % self.sequence)
        self.sequence += 1
        archive = prefix.with_suffix('.tar')
        row = {'argv': args, 'timeout_seconds': timeout, 'started_unix': time.time(),
               'stdout_format': 'tar'}
        _save(prefix.with_suffix('.json'), row)
        started = time.monotonic()
        try:
            with archive.open('xb') as stdout, prefix.with_suffix('.stderr').open('xb') as stderr:
                result = subprocess.run(DC.docker_command(args), stdout=stdout,
                                        stderr=stderr, timeout=timeout)
            row['returncode'] = result.returncode
            _require(result.returncode == 0, 'cannot preserve native diagnostics before retirement')
            return archive
        except BaseException as error:
            row['error'] = repr(error)
            raise
        finally:
            row['duration_seconds'] = time.monotonic() - started
            _save(prefix.with_suffix('.json'), row)


def _extract_evidence(path, native):
    """Validate a complete streamed archive while preserving loose-file names."""
    native.mkdir()
    count = size = 0
    complete = False
    with tarfile.open(path, mode='r|') as archive:
        for member in archive:
            archive.members.clear()
            name = member.name
            _require(not complete and member.isfile() and Path(name).name == name
                     and name not in ('.', '..'), 'invalid native evidence path or member')
            stream = archive.extractfile(member)
            if name == EVIDENCE_END:
                _require(member.size <= 128, 'malformed native evidence completion')
                _require(json.loads(stream.read()) == {'files': count, 'bytes': size},
                         'native evidence completion differs')
                complete = True
            else:
                with (native/name).open('xb') as target:
                    shutil.copyfileobj(stream, target, length=1024*1024)
                count += 1
                size += member.size
    _require(complete, 'incomplete native evidence archive')


def _authority(args, boundary):
    artifacts = Path(args.artifacts).resolve()
    closures_path, index_path = artifacts/'closures.json', artifacts/'go_prod_index.json'
    closures = json.loads(closures_path.read_text())
    index = json.loads(index_path.read_text())
    table = ContextTable(closures, boundary=boundary, project=boundary.project)
    groups, contexts = partitions(closures, index)
    _require(index.get('paths') == list(GO_PROD_PATHS), 'index must cover the complete Go production roots')
    return closures, index, table, groups, contexts, (closures_path, index_path)


def _build_contexts(groups):
    return G._context_union([{'package_dir': g['context']['package_dir'],
        'go_build_tags': g['context']['go_build_tags'], 'production_files': g['production_files']} for g in groups])


def validate_document(document, request, groups, contexts):
    """Check source/context transport, then validate the untouched shared envelope."""
    _require(document.get('schema') == SCHEMA and 'failure' not in document
        and document.get('root') == request['original_root']
        and document.get('image_id') == request['image_id']
        and document.get('contexts') == contexts
        and document.get('engine_sha256') == request['engine_sha256'], 'producer binding differs')
    parser = document.get('parser')
    _require(parser == 'go version go1.25.0 linux/amd64', 'independent parser probe differs')
    envelope = document['envelope']
    # Required shared authority: never validate a field-stripped replacement.
    A.validate_enumerator_envelope(envelope, expected_engine=G.ENGINE,
        expected_engine_version=G.ENGINE_VERSION, expected_parser_version=parser,
        expected_enumerator_rev=G.ENUMERATOR_REV)
    report = document['typed_candidates']
    expected = [{'package_dir': g['context']['package_dir'], 'go_build_tags': g['context']['go_build_tags'],
                 'production_files': g['production_files']} for g in groups]
    _require(report.get('schema') == 'r2t.go-mutation-candidates/1'
        and report.get('engine') == G.ENGINE and report.get('engine_version') == G.ENGINE_VERSION
        and report.get('enumerator_rev') == G.ENUMERATOR_REV and report.get('parser') == parser
        and report.get('operators') == list(M.OPERATORS) and report.get('contexts') == expected,
        'typed census identity or compiled membership differs')
    _require(envelope.get('go_build_contexts') == _build_contexts(groups), 'final compiled contexts differ')
    files = {p for g in groups for p in g['production_files']}
    _require(envelope['files'] == report['files'] == len(files), 'compiled file census differs')
    M.build_manifest(report['candidates'], parser_version=parser, engine=G.ENGINE,
                     engine_version=G.ENGINE_VERSION, operators=M.OPERATORS, exclusions=G.EXCLUDED_PREFIXES)
    for row in report['candidates']:
        G._row(row)
        _require(row['file'] in files, 'typed candidate outside compiled production inventory')
    return envelope


def _outputs(args, source, inputs):
    outputs = [args.out] + ([args.raw_out] if getattr(args, 'raw_out', None) else [])
    evidence = Path(os.path.abspath(args.out + '.evidence'))
    _require(evidence.resolve() == evidence and not os.path.lexists(evidence), 'fresh non-symlink evidence directory required')
    for path in outputs:
        target = Path(path).resolve()
        _require(not target.is_relative_to(source) and not source.is_relative_to(target), 'output overlaps original source')
        _require(not target.is_relative_to(evidence) and not evidence.is_relative_to(target), 'output overlaps evidence directory')
        AUDIT._check_output_destination(path, (*inputs, *[p for p in outputs if p != path]))
    _require(len(set(map(os.path.abspath, outputs))) == len(outputs), 'duplicate output paths')
    _require(not evidence.is_relative_to(source) and not source.is_relative_to(evidence), 'evidence overlaps original source')
    for path in inputs:
        target = Path(path).resolve()
        _require(not target.is_relative_to(evidence) and not evidence.is_relative_to(target), 'evidence overlaps an input')
    return outputs, evidence


def _build(args, boundary):
    from .closure_plan import _snapshot
    _require(getattr(args, 'operator_profile', 'v2') == 'v2', 'Go has no historical v1 operator profile')
    _require(not args.path or list(args.path) == list(GO_PROD_PATHS), 'Go build requires every production root')
    image = getattr(args, 'image_id', None)
    _require(isinstance(image, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image)
        and getattr(args, '_container_explicit', False), 'explicit exclusive analysis container and immutable image required')
    workers = getattr(args, 'compile_workers', 1)
    budget = getattr(args, 'construction_timeout', ANALYSIS_TIMEOUT)
    _require(type(workers) is int and 1 <= workers <= 32, 'compile workers must be between 1 and 32')
    _require(type(budget) is int and budget > 0, 'construction timeout must be positive seconds')
    source = Path(boundary.repo_root).resolve()
    _snapshot(source)  # Existing clean full original-source pin; no subject code.
    closures, index, _, groups, contexts, authority_paths = _authority(args, boundary)
    _require(index.get('root') == str(source) and index.get('image_id') == image, 'index original source/image differs')
    pin = A.pinned_enumerator_identity('r2t/go/mutate.go')
    _require(pin['enumerator_rev'] == G.ENUMERATOR_REV, 'pinned enumerator revision differs')
    inputs = (args.boundary, *authority_paths, G.GO_SOURCE)
    outputs, evidence = _outputs(args, source, inputs)
    removable = sorted(_removables(source, [p for p, _ in boundary.removable], [r['go_suite'] for r in contexts]))
    inventory = source_inventory(source)
    request = {'original_root': str(source), 'inventory': inventory,
        'contexts': [r['go_suite'] for r in contexts], 'closures': closures, 'prod_index': index,
        'removable_paths': removable, 'image_id': image, 'engine_sha256': pin['sha256'],
        'compile_workers': workers, 'construction_timeout_seconds': budget}
    evidence.mkdir()
    _save(evidence/'request.json', request)
    _save(evidence/'inputs.json', {str(p): A.sha256_file(str(p)) for p in inputs})
    try:
        with tempfile.TemporaryDirectory(prefix='go-mutation-source-') as directory:
            temporary = Path(directory).resolve()
            _require(not temporary.is_relative_to(source) and not source.is_relative_to(temporary), 'temporary copy overlaps original source')
            snapshot = temporary/'source'; _compilation_view(source, snapshot, set())
            _require(source_inventory(snapshot) == inventory and source_inventory(source) == inventory, 'source changed while snapshotting')
            document = MutationTransport(args.container, image, evidence, budget).run(snapshot, request)
        _save(evidence/'document.json', document)
        _require(source_inventory(source) == inventory, 'original source changed during production')
        envelope = validate_document(document, request, groups, contexts)
        raw = G.build_population(envelope['mutants'], parser_version=document['parser'],
            go_build_contexts=envelope['go_build_contexts'], n_invalid=envelope.get('n_invalid'),
            enumerator_rev=envelope['enumerator_rev'])
        A.validate_manifest(raw, expected_engine=G.ENGINE)
        boundary_sha256 = A.sha256_file(args.boundary)
        scored = A.derive_boundary_scored_manifest(raw, boundary, args.boundary,
            boundary_sha256, sample=args.sample, seed=args.seed)
        if args.sample is None and scored['n_non_production_excluded'] == 0:
            # The index's zero-exclusion role preserves the complete raw
            # identity; prove it through the shared boundary derivation.
            scored = A.derive_raw_equals_scored_manifest(raw, boundary,
                args.boundary, boundary_sha256)
        _save(evidence/'raw-manifest.json', raw)
        fds = AUDIT.reserve_outputs(outputs, input_paths=inputs)
        for fd, payload in zip(fds, [scored, raw]):
            AUDIT.write_reserved_json(fd, payload)
    except BaseException as error:
        _save(evidence/'failure.json', {'error': repr(error)})
        raise
    finally:
        _require(source_inventory(source) == inventory, 'original source changed during production')
    counts = {name: sum(r['operator'] == name for r in scored['mutants']) for name in M.OPERATORS}
    print(json.dumps({'out': args.out, 'raw_out': getattr(args, 'raw_out', None), 'evidence': str(evidence),
        'n': scored['n'], 'raw_n': raw['n'], 'digest': scored['digest'], 'raw_digest': raw['digest'],
        'engine': G.ENGINE, 'parser': document['parser'], 'image_id': image, 'per_operator': counts}, indent=1))
    return 0


def _map(args, boundary):
    _require(getattr(args, 'release', None), 'Go map requires the exact release items')
    manifest = json.loads(Path(args.manifest).read_text())
    A.validate_manifest(manifest, expected_engine=G.ENGINE)
    closures, _, table, groups, contexts, paths = _authority(args, boundary)
    _require(manifest.get('go_build_contexts') == _build_contexts(groups), 'manifest and closure/index compiler contexts differ')
    released = A.load_jsonl(args.release)
    for item in released:
        table.check_context(item)
    release_ids = A.load_release_ids(args.release)
    coverage = A.coverage_from_rows(A.load_jsonl(args.coverage_run))
    _require(set(coverage) <= release_ids, 'coverage contains items outside the context-checked release')
    membership = {closure['item_id']: set(context['files']) for closure, context in zip(closures, contexts)}
    for item, lines in coverage.items():
        _require(isinstance(lines, dict) and set(lines) <= membership[item],
                 'coverage file lies outside its item compiler context')
    by_mutant, uncovered = M.map_mutants_to_items(manifest, coverage)
    payload = A.build_map_artifact(manifest, by_mutant, uncovered,
        coverage_sha256=A.sha256_file(args.coverage_run), release_sha256=A.sha256_file(args.release))
    A.validate_map(payload, manifest, release_ids=release_ids, coverage_by_item=coverage)
    fd = AUDIT.reserve_output(args.out, input_paths=(*paths, args.manifest, args.coverage_run, args.release, args.boundary))
    AUDIT.write_reserved_json(fd, payload)
    print(json.dumps({'out': args.out, 'mutants': manifest['n'], 'covered': len(by_mutant),
        'uncovered': len(uncovered), 'items_with_coverage': len(coverage)}, indent=1))
    return 0


def cmd_mutants(args):
    from ..bench import cli as bench_cli
    profile, boundary = bench_cli._stack_profile(args), bench_cli._boundary(args)
    _require((profile.project, profile.language, profile.framework) == ('coddy-agent', 'go', 'godog')
        and boundary.project == profile.project
        and Path(args.boundary).resolve() == Path(profile.boundary_path).resolve(), 'coddy-agent profile/boundary required')
    _require(args.action in ('build', 'map'), 'Go producer supports build and map only')
    return (_build if args.action == 'build' else _map)(args, boundary)
