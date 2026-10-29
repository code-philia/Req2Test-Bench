"""Real seed/archive and offline worker-binding fixtures; no Docker or Go runs."""
from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

from .. import docker_authority as authority
from ..bench import seed, worker
from ..bench.harness import DockerRunner, Solution
from ..bench.validate import HARNESS_VERSION
from ..core.boundary import Boundary
from ..stacks import godog
from .workspace import seed_inventory


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')


def _fixture(base):
    native = Path(__file__).with_name('fixtures') / 'native'
    context = json.loads((native / 'context.json').read_text())
    source = base / 'stripped'; source.mkdir()
    gold = base / 'gold'; workspace = base / 'workspace'
    helper = 'internal/r2tfixture/bdd_helper_test.go'
    files = {context['glue_path']: (native / 'bdd_fixture_test.go').read_bytes(),
             helper: b'package fixture\n',
             'internal/r2tfixture/retained_test.go': b'package fixture\n// retained\n',
             'internal/r2tfixture/prod.go': b'package fixture\nfunc Product() {}\n',
             context['feature_path']: (native / 'shape.feature').read_bytes(),
             'go.mod': b'module fixture\n', 'go.sum': b''}
    for rel, raw in files.items():
        path = source / rel; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    answers = [context['glue_path'], helper]
    boundary = Boundary(1, 'coddy-agent', str(source),
        removable=[(rel, 'answer') for rel in answers],
        retained=[('internal/r2tfixture/retained_test.go', 'retained')])
    manifest = godog.strip(boundary, str(gold))
    godog.integrity_baseline(manifest, boundary)
    seed_dir = base / 'seed'
    seed.build_seed(str(source), boundary, str(seed_dir), seed.NO_DATABASE, None,
                    manifest=manifest, rules=seed.GO_RULES, needs_database=False)
    assert seed.verify_seed(str(seed_dir))['artifacts_ok']
    seed.unpack_workspace(str(seed_dir), str(workspace))
    boundary_path = base / 'boundary.yml'
    # JSON is also YAML; use the real boundary loader at construction.
    _write(boundary_path, {'version': 1, 'project': 'coddy-agent',
        'repo_root': str(source),
        'removable': [{'path': rel, 'why': 'answer'} for rel in answers],
        'retained': [{'path': 'internal/r2tfixture/retained_test.go', 'why': 'retained'}]})
    artifacts = base / 'artifacts'; artifacts.mkdir()
    closure = {'item_id': 'coddy-agent/features/shape.feature:6',
               'feature_file': context['feature_path'], 'scenario_line': 6,
               'files': answers, 'go_suite': context}
    _write(artifacts / 'closures.json', [closure])
    spec = worker.WorkerSpec(0, str(workspace), 'worker0', '', '',
        str(base / 'worker.env'), '/work', str(base / 'rows.jsonl'), str(artifacts))
    spec_path = base / 'worker.json'; _write(spec_path, spec.to_json())
    authority_path = base / 'authority.json'
    authority.write_evidence_no_clobber(str(authority_path), authority._fixture_authority())
    _, reference = authority.evidence_reference(str(authority_path),
        expected_schema=authority.AUTHORITY_SCHEMA,
        validator=lambda value: authority.validate_authority_document(value, current_source=False),
        label='fixture authority')
    binding = authority._fixture_binding()
    binding['authority'] = reference
    binding['pool'] = worker.build_execution_pool([spec], [str(spec_path)],
        database_container=None, internal_network=None)
    binding['worker_spec_sha256'] = binding['pool']['workers'][0]['worker_spec_sha256']
    binding['digest'] = authority.semantic_digest(binding)
    binding_path = worker.binding_attestation_path(str(spec_path))
    authority.write_evidence_no_clobber(binding_path, binding)
    args = SimpleNamespace(worker=str(spec_path), boundary=str(boundary_path),
        repo=str(workspace), container='worker0', workdir='/work', artifacts=str(artifacts),
        gold=str(gold), profile=str(Path(__file__).resolve().parents[2] /
                                   'config/profile_coddy_agent.yml'))
    result = SimpleNamespace(args=args, context=context, answers=answers, seed=seed_dir,
        workspace=workspace, gold=gold, spec=spec, binding_path=binding_path,
        closures=artifacts / 'closures.json', runtime=Path(worker.runtime_attestation_path(str(spec_path))))
    _refresh_runtime(result)
    return result


def _refresh_runtime(fixture):
    identity = worker.verified_seed_identity(str(fixture.seed), False)
    document = worker.build_worker_runtime_attestation(fixture.spec, fixture.args.worker,
        identity, HARNESS_VERSION, binding_path=fixture.binding_path)
    _write(fixture.runtime, document)
    return document


def _test_quality_workers(base):
    """Admit two real bound workspaces through test-quality's CLI dispatch."""
    from ..bench import cli

    fixtures = []
    for index in range(2):
        root = base / str(index); root.mkdir(parents=True)
        fixture = _fixture(root)
        fixture.spec = replace(fixture.spec, index=index, container=f'worker{index}')
        _write(Path(fixture.args.worker), fixture.spec.to_json())
        fixtures.append(fixture)
    paths = [fixture.args.worker for fixture in fixtures]
    pool = worker.build_execution_pool([fixture.spec for fixture in fixtures], paths,
        database_container=None, internal_network=None)
    authority_ref = json.loads(Path(fixtures[0].binding_path).read_text())['authority']
    for fixture in fixtures:
        binding = json.loads(Path(fixture.binding_path).read_text())
        binding.update(authority=authority_ref, pool=pool, worker_index=fixture.spec.index,
            worker_spec_sha256=pool['workers'][fixture.spec.index]['worker_spec_sha256'])
        binding['container'].update(name=fixture.spec.container,
            id=str(5 + fixture.spec.index) * 64)
        binding['digest'] = authority.semantic_digest(binding)
        _write(Path(fixture.binding_path), binding)
        fixture.seed = fixtures[0].seed
        _refresh_runtime(fixture)

    args = copy.copy(fixtures[0].args)
    args.artifacts = str(base / 'shared-analysis-artifacts')
    # Both documented --workers-only use and inherited --worker 0 must select
    # the assigned spec, including its distinct authoritative artifacts.
    for inherited in (None, paths[0]):
        args.worker = inherited
        for fixture in reversed(fixtures):
            harness, boundary, manifest = cli._test_quality_worker_harness(
                args, fixture.args.worker, fixture.spec)
            assert isinstance(harness, godog.GodogHarness)
            assert harness.root == boundary.repo_root == str(fixture.workspace)
            assert manifest.gold_root == str(fixtures[0].gold)
            assert harness.artifacts_dir == fixture.spec.artifacts_root
            assert harness._worker_runtime['worker'] == fixture.spec.to_json()
        assert args.worker == inherited and args.artifacts == str(base / 'shared-analysis-artifacts')
    print('  [PASS] test-quality dispatch authenticates each of two Go workers and its own artifacts without a global worker')

    # Existing PHP/Java factories intentionally read shared analysis artifacts.
    # Their arguments keep that behavior when jobs move between worker roots.
    for project in ('coreshop', 'kapua'):
        args.profile = str(Path(__file__).resolve().parents[2] / 'config' / f'profile_{project}.yml')
        with patch.object(cli, '_harness', side_effect=lambda selected: selected):
            selected = cli._test_quality_worker_harness(args, paths[1], fixtures[1].spec)
        assert selected.repo == str(fixtures[1].workspace)
        assert selected.container == fixtures[1].spec.container
        assert selected.workdir == fixtures[1].spec.workdir
        assert selected.artifacts == args.artifacts and selected.worker == args.worker
    print('  [PASS] test-quality retains shared PHP/Java artifact arguments')


def _control_dispatch(fixture, harness):
    """Exercise real factories/runner/S5; observe the still-gated native boundary."""
    from .. import stacks
    from ..bench import fixtures, runner, validate
    from .context import canonical_item
    from .control_adapter import GoControlAdapter

    closure = json.loads(fixture.closures.read_text())[0]
    item = canonical_item()
    item.update(item_id=closure['item_id'], files=closure['files'],
                go_suite=closure['go_suite'],
                provenance={'file_path': closure['feature_file'],
                            'line': closure['scenario_line']})
    with patch.dict(stacks.KNOWN_FRAMEWORKS, {'godog': 'godog'}):
        empty = fixtures._build_empty(fixture.args, harness)
        stub = fixtures._build_stub(fixture.args, harness)
    assert isinstance(empty, GoControlAdapter) and isinstance(stub, GoControlAdapter)
    assert empty._harness is stub._harness is harness
    assert empty._mode == 'empty' and stub._mode == 'noop'

    calls = []
    class BoundaryObserved(Exception):
        pass
    def candidate(feature, scenario, solution, **options):
        calls.append(('candidate', solution, options))
        raise BoundaryObserved()
    def control(feature, scenario, **options):
        calls.append(('control', None, options))
        raise BoundaryObserved()
    def observe(adapter):
        before = len(calls)
        row = runner.run_one(harness, adapter, item, coverage=True,
                             timeout=600, repeats=3)
        assert row['outcome'] == 'harness_error'
        assert row['metadata']['harness_error'].startswith('BoundaryObserved:')
        assert len(calls) == before + 1
        return calls[-1]

    with patch.object(harness, 'run_solution', side_effect=candidate), \
            patch.object(harness, 'run_control', side_effect=control):
        kind, _, options = observe(empty)
        assert kind == 'control' and options['mode'] == 'empty'
        assert options['closure'] == closure and options['prepared'] is None
        assert options['deadline'] is None and options['repeats'] == 3
        assert options['timeout'] == 600 and options['coverage'] is True
        payload = {'files': [], 'metadata': {'control': 'empty', 'mode': 'noop'}}
        for name in ('empty', 'stub', 'model'):
            kind, solution, _ = observe(fixtures.Adapter(name, lambda task: copy.deepcopy(payload)))
            assert kind == 'candidate' and not solution.files
        replay_path = fixture.workspace.parent / 'replayed-control.jsonl'
        replay_path.write_text(json.dumps({'item_id': item['item_id'], 'adapter': 'stub',
                                          'produced_files': [], 'metadata': payload['metadata']}) + '\n')
        kind, _, _ = observe(fixtures.make_replay_adapter(str(replay_path)))
        assert kind == 'candidate'
        submitted_path = fixture.workspace.parent / 'submitted-control.jsonl'
        submitted_path.write_text(json.dumps({'item_id': item['item_id'], 'adapter': 'empty',
                                             'produced_files': [], 'metadata': payload['metadata']}) + '\n')
        kind, _, _ = observe(fixtures.make_submitted_adapter(str(submitted_path), {item['item_id']}))
        assert kind == 'candidate'
    print('  [PASS] real Go control factories bind one harness; model/empty/replayed/submitted bytes cannot select control preparation')

    # Only route selection is under test. No synthetic measurement or native
    # outcome is offered as qualification; stop at the restored-gold boundary.
    def empty_leg(feature, scenario, **options):
        calls.append(('control', None, options))
        return {'runs': [{'outcome': 'undefined'}]}
    calls.clear()
    with patch.object(harness, 'run_control', side_effect=empty_leg), \
            patch.object(harness, 'run_solution', side_effect=candidate), \
            patch.object(validate, '_thin', side_effect=lambda run: {'outcome': run['outcome']}):
        try:
            validate.validate_item(harness, str(fixture.gold), closure, repeats=3)
        except BoundaryObserved:
            pass
        else:
            raise AssertionError('S5 did not reach restored gold execution')
    assert [call[0] for call in calls] == ['control', 'candidate']
    assert calls[0][2]['mode'] == 'empty' and calls[0][2]['closure'] == closure
    assert calls[0][2]['repeats'] == 3 and calls[0][2]['prepared'] is None
    assert {f.file_path: f.code.encode() for f in calls[1][1].files} == {
        path: (fixture.gold / path).read_bytes() for path in fixture.answers}
    assert all(not (fixture.workspace / path).exists() for path in fixture.answers)
    print('  [PASS] S5 routes only its empty fail leg through controls and restores exact gold through ordinary execution')


def _installed_release(base):
    """Use real release sidecars and worker authentication, stopping before Docker."""
    from ..bench import fixtures, runner
    from ..data import release
    from ..toolkit.release_build import build_release
    from .context import canonical_item, ContextRefused

    base.mkdir()
    fixture = _fixture(base)
    closure = json.loads(fixture.closures.read_text())[0]
    closure.update(di_fragment={}, context_classes=[], counts={'steps_unmatched': 0})
    _write(fixture.closures, [closure])
    item = canonical_item()
    item.update(item_id=closure['item_id'], files=closure['files'],
                go_suite=closure['go_suite'],
                provenance={'file_path': closure['feature_file'], 'line': closure['scenario_line']})
    items_path = base / 'extracted.jsonl'
    items_path.write_text(json.dumps(item) + '\n')
    artifacts = Path(fixture.args.artifacts)
    _write(artifacts / 'quality.json', {item['item_id']: {
        'has_oracle': True, 'live_effective_step_count': 3}})
    (artifacts / 'validation.jsonl').write_text(json.dumps({
        'item_id': item['item_id'], 'admitted': True, 'seconds': 0}) + '\n')
    # The same shared builder supplies the existing release_gold bundle role.
    installed = artifacts / 'release'
    assert build_release(str(artifacts), str(items_path), str(installed),
                         project='coddy-agent')['included'] == 1
    fixture.args.release = str(installed / release.DEFAULT_ITEMS_NAME)
    item = release._load_jsonl(fixture.args.release)[0]
    sidecar = release.load_gold(str(installed), item['item_id'])
    assert set(sidecar) == {'item_id', 'files', 'di_fragment', 'context_classes',
                            'feature_file', 'scenario_line', 'go_suite'}
    fixture.closures.unlink()  # Extraction closures are not an installed bundle role.
    harness, _, _ = godog.make_harness(fixture.args)
    assert harness.contexts.files_for(closure['feature_file'], closure['scenario_line']) == tuple(sorted(fixture.answers))
    assert harness.select(closure['feature_file'], closure['scenario_line']) == fixture.context
    harness.check_context(item)

    gold = fixtures._build_gold(fixture.args, harness)
    candidate_files = [{'file_path': rel, 'code': 'package fixture\n// generated answer\n'}
                       for rel in fixture.answers]
    generated = fixtures.Adapter('model', lambda task: {'files': candidate_files, 'metadata': {}})
    observed = []
    class NativeBoundary(Exception):
        pass
    def observe(feature, scenario, solution, **options):
        assert feature.path == str(fixture.workspace / closure['feature_file'])
        assert scenario.line == closure['scenario_line']
        observed.append({f.file_path: f.code for f in solution.files})
        raise NativeBoundary()
    with patch.object(harness, 'run_solution', side_effect=observe), \
            patch.object(harness, 'run_control', side_effect=AssertionError('ordinary execution became a control')):
        for adapter in (gold, generated):
            row = runner.run_one(harness, adapter, item)
            assert row['outcome'] == 'harness_error'
            assert row['metadata']['harness_error'].startswith('NativeBoundary:')
    assert observed == [{rel: (fixture.gold / rel).read_text() for rel in fixture.answers},
                        {row['file_path']: row['code'] for row in candidate_files}]
    print('  [PASS] installed shared release sidecars support ordinary multi-file gold and generated execution without extraction closures')

    for factory in (
            lambda: godog.make_empty_adapter(harness=harness, closures_path=str(fixture.closures)),
            lambda: godog.make_stub_adapter(str(fixture.closures), harness=harness),
            lambda: godog.make_strip_adapter(str(fixture.gold), str(fixture.closures), harness=harness)):
        try:
            factory()
        except FileNotFoundError:
            pass
        else:
            raise AssertionError('release execution context fabricated full control/Then bindings')
    print('  [PASS] controls and Then stripping still require their separate complete closure file')

    manifest = installed / 'gold' / 'manifest.json'
    original_manifest = manifest.read_text()
    sidecar_path = installed / 'gold' / json.loads(original_manifest)[item['item_id']]
    original_sidecar = sidecar_path.read_text()
    def refuses(label):
        try:
            godog.make_harness(fixture.args)
        except (ValueError, RuntimeError):
            print('  [PASS] ' + label)
        else:
            raise AssertionError(label)
    _write(manifest, {})
    refuses('missing release sidecar refuses before execution')
    manifest.write_text(original_manifest)
    changed = copy.deepcopy(sidecar); changed.pop('go_suite')
    _write(sidecar_path, changed)
    refuses('missing sidecar suite context refuses before execution')
    changed = copy.deepcopy(sidecar); changed['go_suite']['test_name'] = 'TestDifferentFeature'
    _write(sidecar_path, changed)
    refuses('release item and sidecar suite mismatch refuses before execution')
    changed = copy.deepcopy(sidecar); changed['files'] = changed['files'][:1]
    _write(sidecar_path, changed)
    refuses('release sidecar cannot drop a companion answer file')
    # A constructed harness retains the checked snapshot, not future disk edits.
    harness.check_context(item)
    try:
        harness.check_context(changed)
    except ContextRefused:
        pass
    else:
        raise AssertionError('sidecar edit changed the immutable execution context')
    sidecar_path.write_text(original_sidecar)
    _write(fixture.closures, [{}])
    refuses('an existing invalid closure artifact cannot silently fall back to release sidecars')


def selftest():
    def refuses(label, operation):
        try:
            operation()
        except (RuntimeError, ValueError):
            print('  [PASS] ' + label)
        else:
            raise AssertionError(label)

    with tempfile.TemporaryDirectory() as td, \
            patch.object(DockerRunner, 'run', side_effect=AssertionError('unexpected Docker contact')), \
            patch.object(worker, '_docker', side_effect=AssertionError('unexpected Docker contact')):
        fixture = _fixture(Path(td))
        args = fixture.args
        harness, boundary, manifest = godog.make_harness(args)
        assert harness.man is harness.manifest is manifest
        assert harness.root == boundary.repo_root == str(fixture.workspace)
        assert manifest.gold_root == str(fixture.gold) and harness.workdir_root == '/work'
        assert not harness.expected_mutations and harness.copy._state == 'idle'
        verified = worker.validate_worker_runtime_v3(args.worker, needs_database=False,
                                                     harness_version=HARNESS_VERSION)
        expected = seed_inventory(verified['runtime'])
        assert harness.copy.original_inventory == expected
        assert all(rel not in expected for rel in fixture.answers)
        assert '_bench/go/support/harness.go' in expected
        print('  [PASS] actual Go seed and authenticated worker binding construct a relocated harness without Docker')

        from .. import stacks
        from ..bench import cli
        routed, _, _ = cli._harness(args)
        assert isinstance(routed, godog.GodogHarness)
        print('  [PASS] existing CLI construction dispatch reaches the Go adapter through its registered stack')
        _control_dispatch(fixture, harness)

        pristine = {rel: (fixture.workspace / rel).read_bytes() for rel in expected}
        harness.select(fixture.context['feature_path'], 6)
        answer = Solution.from_json({'files': [{'file_path': rel, 'code': 'package fixture\n// prior answer\n'}
                                               for rel in fixture.answers]})
        harness.install_solution(answer, 'criterion_to_test')
        record = fixture.workspace / '_bench/run_record.jsonl'; record.write_text('prior record\n')
        # Constructing with answers present must retain the seed's original map.
        another, _, _ = godog.make_harness(args)
        assert another.copy.original_inventory == expected
        harness.prepare_for_generation()
        assert all(not (fixture.workspace / rel).exists() for rel in fixture.answers)
        assert not record.exists() and harness._selected is None
        assert all((fixture.workspace / rel).read_bytes() == raw for rel, raw in pristine.items())
        print('  [PASS] prior multi-file answers and export are removed; retained tests, features and trusted support survive')

        # Real runner lock bytes used to make every strict copy refuse. Bind
        # the coordinator's expected PID bytes rather than adopting a scan.
        from ..bench.runner import _ExecutionLock
        from .execution import ExecutionCopy, ExecutionRefused
        from .execution_selftest import Remote
        import os
        assert harness.coordination_inputs() == {}
        with _ExecutionLock(harness.root):
            canonical_lock = f'{os.getpid()}\n'.encode('ascii')
            assert harness.coordination_inputs() == {'.r2t-exec.lock': canonical_lock}
            current = dict(pristine, **{'.r2t-exec.lock':
                           (fixture.workspace / '.r2t-exec.lock').read_bytes()})
            def prepare_remote(contents):
                remote = Remote(contents)
                adapter = ExecutionCopy(remote, original_inventory=expected,
                    boundary=boundary, original_manifest=manifest)
                adapter.prepare(fixture.context, None, {}, allowed_paths=fixture.answers,
                                coordination_inputs=harness.coordination_inputs())
                return adapter, remote
            adapter, remote = prepare_remote(current)
            assert remote.copy['.r2t-exec.lock'] == canonical_lock
            adapter.retire()
            try:
                prepare_remote(dict(current, **{'.r2t-exec.lock': b'foreign coordinator\n'}))
            except ExecutionRefused:
                pass
            else:
                raise AssertionError('foreign lock became an accepted copy baseline')
        print('  [PASS] actual runner lock permits copies; foreign lock bytes refuse')

        harness.select(fixture.context['feature_path'], 6)
        harness.install_solution(answer, 'criterion_to_test'); record.write_text('must survive refusal\n')
        harness.copy._state = 'planned'
        refuses('unfinished execution prevents cleanup effects', harness.prepare_for_generation)
        assert record.exists() and all((fixture.workspace / rel).exists() for rel in fixture.answers)
        harness.copy._state = 'idle'; harness.copy.quarantined = True
        refuses('quarantine prevents cleanup and verification', harness.prepare_for_generation)
        assert record.exists()
        harness.copy.quarantined = False
        harness.prepare_for_generation()
        record.write_text('last record\n'); harness.clear_registration()
        assert not record.exists()
        refuses('complete execution is still unavailable', harness.execute)

        for field, value in [('repo', str(fixture.gold)), ('container', 'other-worker'),
                             ('workdir', '/var/www/html'), ('artifacts', str(fixture.gold)),
                             ('worker', None)]:
            changed = copy.copy(args); setattr(changed, field, value)
            refuses('constructor rejects mismatched ' + field, lambda: godog.make_harness(changed))
        spec_path = Path(args.worker); original = spec_path.read_bytes()
        changed = json.loads(original); changed['container'] = 'changed-worker'; _write(spec_path, changed)
        refuses('actual WorkerSpec byte drift is rejected by shared binding validation', lambda: godog.make_harness(args))
        spec_path.write_bytes(original)

        archive = fixture.seed / seed.WORKSPACE_TAR; original = archive.read_bytes()
        archive.write_bytes(original + b'changed archive')
        refuses('actual seed archive corruption refuses construction', lambda: godog.make_harness(args))
        archive.write_bytes(original)
        seed_path = fixture.seed / seed.SEED_MANIFEST; original = seed_path.read_bytes()
        changed = json.loads(original); changed['recreate'] = [['_bench/run_record.jsonl', '']]
        changed['rules_digest'] = seed.SeedRules.from_manifest(changed).digest()
        _write(seed_path, changed); _refresh_runtime(fixture)
        refuses('authentic worker bound to non-Go seed rules refuses', lambda: godog.make_harness(args))
        seed_path.write_bytes(original); _refresh_runtime(fixture)

        manifest_path = fixture.gold / 'strip_manifest.json'; original = manifest_path.read_bytes()
        changed = json.loads(original); changed['substrate_roots'] = ['src']; _write(manifest_path, changed)
        refuses('another stack manifest cannot define the Go baseline', lambda: godog.make_harness(args))
        manifest_path.write_bytes(original)
        original = fixture.closures.read_bytes(); changed = json.loads(original)
        changed[0]['files'] = ['internal/r2tfixture/retained_test.go']; _write(fixture.closures, changed)
        refuses('invalid closure file authority refuses construction', lambda: godog.make_harness(args))
        fixture.closures.write_bytes(original)

        production = fixture.workspace / 'internal/r2tfixture/prod.go'; original = production.read_bytes()
        production.write_text('package fixture\n// modified production\n')
        refuses('live worker bytes cannot redefine the seed or protected baseline', lambda: godog.make_harness(args))
        refuses('housekeeping detects protected drift', harness.prepare_for_generation)
        assert harness.copy.quarantined
        production.write_bytes(original)
        refuses('a detected integrity failure prevents worker reuse', harness.prepare_for_generation)
        _test_quality_workers(Path(td) / 'test-quality-workers')
        _installed_release(Path(td) / 'release-only')
    print('ALL PASS (Go host construction and lifecycle; no native execution)')
    return 0


if __name__ == '__main__':
    raise SystemExit(selftest())
