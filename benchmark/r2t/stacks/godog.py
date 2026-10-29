"""Go/godog stack over the shared benchmark contracts and bound copy runtime."""
from __future__ import annotations

from pathlib import Path
import json
import shutil

from ..bench import repo
from ..core.boundary import REMOVABLE
from ..data import release as release_data
from ..go.context import compare_context, validate_context
from ..go.assertion_strip import make_strip_adapter, stripped_solution
from ..go.closure import empty_scaffold, extract_closure, stub_solution
from ..go.control_adapter import make_empty_adapter, make_stub_adapter
from ..go.index_cli import cmd_index, cmd_closures
from ..go.interfaces_cli import cmd_interfaces
from ..go.mutation_cli import cmd_mutants
from ..go.stub_cli import cmd_stub_accept
from ..go.registry import GodogRefused, _require

FRAMEWORK = 'godog'
LANGUAGE = 'go'


from ..go.runtime import execute, run_solution as _run_solution, run_control as _run_control
from ..toolkit import mutation_go as _mutation_go

mutant_population = _mutation_go.build_population
engine = _mutation_go.ENGINE
engine_version = _mutation_go.ENGINE_VERSION
engine_dir = _mutation_go.GO_ENGINE_DIR
applier = _mutation_go.applier
excluded_prefixes = _mutation_go.EXCLUDED_PREFIXES


def strip(boundary, gold_root: str, harness_dir=None, dry_run=False):
    """Move exact approved answers from a disposable copy, preserving gold bytes."""
    from ..go.registry import support_files
    root = Path(boundary.repo_root).resolve();gold = Path(gold_root).resolve()
    _require(boundary.project == 'coddy-agent', 'unsupported Go project')
    for protected in repo.declared_corpus_roots():
        pin = Path(protected).resolve()
        _require(root != pin and pin not in root.parents, 'strip refuses the pinned corpus tree')
    _require(root != gold and root not in gold.parents, 'gold must be outside the stripped copy')
    _require(not (root / '.git').is_file(), 'strip requires a disposable copy, not a Git worktree')
    _require(not (gold / '_git').exists(), 'gold already contains preserved Git history')
    _require((root / 'go.mod').is_file() and (root / 'features').is_dir(), 'missing Go module/features')
    _require(not boundary.removable_config, 'Go has no removable wiring')
    paths = [p for p, _ in boundary.removable]
    _require(len(paths) == len(set(paths)) and all(
        p.endswith('_test.go') and not any(c in p for c in '*?[')
        and boundary.classify(p) == REMOVABLE and (root / p).is_file()
        and (root / p).resolve().is_relative_to(root) for p in paths),
        'removable census must contain existing exact original files')
    _require(all(not (gold / p).exists() for p in paths), 'gold already contains an answer')
    supports = support_files()
    _require(all(not (root / p).exists() for p in supports), 'reserved Go support already exists')
    manifest = repo.StripManifest(str(root), str(gold), moved=sorted(paths),
        installed=sorted(supports), boundary_version=boundary.version,
        substrate_roots=list(repo.GO_SUBSTRATE_ROOTS),
        substrate_volatile=sorted(repo.GO_SUBSTRATE_VOLATILE))
    if dry_run:
        return manifest
    gold.mkdir(parents=True, exist_ok=True)
    for path in paths:
        (gold / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(root / path), str(gold / path))
    for path, content in supports.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_bytes(content)
    manifest.installed += repo.sanitise_repo(str(root), str(gold))
    manifest.save(str(gold / 'strip_manifest.json'))
    return manifest



def cmd_strip(args) -> int:
    """Expose Go's existing strip operation through the shared CLI contract."""
    import os
    from ..core.boundary import load_boundary
    from ..core.paths import DATA_ROOT_ENV, project_path

    # Preserve the same protection against the shared CoreShop --gold default
    # as the Python and Java CLI adapters.
    gold = Path(args.gold).resolve()
    protected = [Path('/data2/binhang/coreshop_bench')]
    if os.environ.get(DATA_ROOT_ENV):
        protected.append(Path(project_path('coreshop', 'gold')).resolve())
    _require(not any(gold == path or path in gold.parents for path in protected),
             'Go strip needs its own --gold directory, outside the CoreShop gold tree')
    boundary = load_boundary(args.boundary, repo_root=getattr(args, 'repo', None))
    manifest = strip(boundary, str(gold), dry_run=args.dry_run)
    print(f"{'would move' if args.dry_run else 'moved'} {len(manifest.moved)} "
          f"test-code files and {len(manifest.moved_config)} config files -> {gold}")
    if not args.dry_run:
        print(f'installed: {manifest.installed}')
    return 0



def baseline_inputs(args):
    """Load the original disposable strip copy before any worker exists."""
    from ..core.boundary import load_boundary

    boundary = load_boundary(args.boundary, repo_root=getattr(args, 'repo', None))
    gold = Path(args.gold).resolve()
    manifest = repo.load_manifest(str(gold / 'strip_manifest.json'))
    root = Path(boundary.repo_root).resolve()
    _require(boundary.project == 'coddy-agent'
             and root == Path(manifest.repo_root).resolve()
             and gold == Path(manifest.gold_root).resolve(),
             'Go baseline must name the original preserved strip copy and gold tree')
    _require(not getattr(args, 'worker', None),
             'Go baseline precedes worker provisioning; do not rebaseline a worker')
    return boundary, manifest


def integrity_baseline(manifest, boundary, manifest_path=None):
    _require(manifest.substrate_roots == list(repo.GO_SUBSTRATE_ROOTS)
             and set(manifest.substrate_volatile) == set(repo.GO_SUBSTRATE_VOLATILE),
             'Go manifest must use its own reviewed substrate policy')
    return repo.baseline_substrate(manifest, boundary, manifest_path or
                                   str(Path(manifest.gold_root) / "strip_manifest.json"))


class GodogHarness:
    """Exact-path installation and native precollection with immutable context."""
    def __init__(self, manifest, boundary, runner, closures, *, original_inventory):
        from ..go.context import ContextTable
        from ..go.execution import ExecutionCopy
        root = Path(manifest.repo_root).resolve()
        _require(root == Path(boundary.repo_root).resolve(),
                 'boundary and manifest must identify one Go workspace')
        _require(root.is_dir() and runner.workdir == '/work',
                 'Go harness requires an existing workspace and explicit /work')
        self.man = self.manifest = manifest
        self.boundary, self.runner = boundary, runner
        self.root = str(root)
        self.expected_mutations = {}
        self.contexts = ContextTable(closures, boundary=boundary, project=boundary.project)
        self.copy = ExecutionCopy(runner, original_inventory=original_inventory,
                                  boundary=boundary, original_manifest=manifest)
        self._selected = None

    @property
    def workdir_root(self):
        return self.runner.workdir

    def _require_idle(self):
        self.copy._available()
        _require(self.copy._state == 'idle',
                 'retire the current Go execution copy before workspace housekeeping')

    def verify_substrate(self):
        from ..bench.harness import Harness
        self._require_idle()
        _require(not self.expected_mutations, 'Go mutations must stay in disposable execution copies')
        try:
            return Harness.verify_substrate(self)
        except repo.SubstrateTampered:
            self.copy.quarantined = True
            raise

    def clear_registration(self):
        """Go has no wiring; discard only its exported per-item record."""
        from ..bench.harness import RECORD_REL
        self._require_idle()
        path = Path(self.root) / RECORD_REL
        _require(path.resolve().is_relative_to(Path(self.root)),
                 'Go exported record escapes the workspace')
        path.unlink(missing_ok=True)
        self._selected = None

    def prepare_for_generation(self):
        """Remove prior answers before generation; never select or compile."""
        self._require_idle()
        repo.clean_workspace(self.man, self.boundary)
        self.clear_registration()
        self.verify_substrate()

    def check_context(self, item):
        self.contexts.check_context(item)

    def select(self, feature_path, scenario_line):
        self._selected = self.contexts.context_for(feature_path, scenario_line)
        from copy import deepcopy
        return deepcopy(self._selected)

    def install_solution(self, solution, task):
        _require(task == 'criterion_to_test' and self._selected is not None,
                 'select witnessed context before installation')
        _require(not solution.services_fragment, 'Go accepts no wiring')
        allowed = self.contexts.files_for(self._selected['feature_path'],
                                          self._selected['scenario_line'])
        paths = [answer.file_path for answer in solution.files]
        _require(len(paths) == len(set(paths)) and set(paths) == set(allowed),
                 'answer paths differ from the witnessed closure files')
        root = Path(self.root).resolve()
        prepared = []
        for answer in solution.files:
            _require(self.boundary.classify(answer.file_path) == REMOVABLE,
                     'answer file is not removable')
            path = root / answer.file_path
            _require(path.resolve().is_relative_to(root), 'answer path escapes workspace')
            prepared.append((path, answer.code.encode('utf-8')))
        for path, content in prepared:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        return paths

    def coordination_inputs(self):
        """Expect only the known bytes of this coordinator's execution lock.

        The shared runner writes PID + newline while holding _ExecutionLock.
        A direct operator may have no lock. Existing lock contents never become
        a new baseline: the remote copy check compares them to these known bytes.
        """
        import os
        return ({'.r2t-exec.lock': f'{os.getpid()}\n'.encode('ascii')}
                if (Path(self.root) / '.r2t-exec.lock').exists() else {})

    def collect_native(self, *, empty=False, coordination_inputs=None):
        """Use the runtime's immutable context; bootstrap indexing is separate."""
        from ..go.registry import capture_native
        if coordination_inputs is None:
            coordination_inputs = self.coordination_inputs()
        _require(self._selected is not None, 'select witnessed context before collection')
        context = self._selected
        paths = self.contexts.files_for(context['feature_path'], context['scenario_line'])
        root = Path(self.root).resolve()
        targets = {path: root / path for path in paths}
        _require(all(path.resolve().is_relative_to(root) for path in targets.values()),
                 'installed answer path escapes workspace')
        present = {path: target.exists() for path, target in targets.items()}
        _require(all(present.values()) or not any(present.values()),
                 'partial installed answer set differs from witnessed closure')
        installed = ({path: target.read_bytes() for path, target in targets.items()}
                     if all(present.values()) else None)
        if empty:
            _require(installed is None, 'empty control requires all answers actually absent')
            return self.collect_control(mode='empty', coordination_inputs=coordination_inputs)
        source = (root / context['feature_path']).read_text(encoding='utf-8')
        return capture_native(self.copy, context=context, feature_source=source,
                              installed_answers=installed, allowed_paths=paths, empty=empty,
                              coordination_inputs=coordination_inputs)

    def collect_control(self, *, mode, closure=None, coordination_inputs=None, evidence_dir=None):
        """Sanity controls read preserved gold through this coordinator-only route."""
        from ..go.controls import capture_control
        if coordination_inputs is None:
            coordination_inputs = self.coordination_inputs()
        _require(self._selected is not None, 'select witnessed context before collection')
        context = self._selected
        paths = self.contexts.files_for(context['feature_path'], context['scenario_line'])
        if closure is not None:
            self.contexts.check_context(closure)
        gold = Path(self.manifest.gold_root).resolve()
        originals = {}
        for path in paths:
            target = gold / path
            _require(target.resolve().is_relative_to(gold) and target.is_file(),
                     'control original is absent or escapes preserved gold')
            originals[path] = target.read_bytes()
        return capture_control(self.copy, context=context,
            feature_source=(Path(self.root) / context['feature_path']).read_text(encoding='utf-8'),
            original_answers=originals, allowed_paths=paths, mode=mode, closure=closure,
            coordination_inputs=coordination_inputs, evidence_dir=evidence_dir)

    execute = execute
    run_solution = _run_solution
    run_control = _run_control


def make_harness(args):
    """Construct from the bound worker and extraction or installed release context."""
    from ..go.workspace import load_worker_workspace

    manifest, boundary, runner, original_inventory, _bound = load_worker_workspace(args)
    closures_path = Path(args.artifacts).resolve() / 'closures.json'
    if closures_path.exists():
        with closures_path.open(encoding='utf-8') as stream:
            contexts = json.load(stream)
    else:
        release_path = getattr(args, 'release', None)
        _require(release_path, 'Go execution requires closures.json or --release with gold sidecars')
        release_dir = str(Path(release_path).resolve().parent)
        contexts = []
        for item in release_data._load_jsonl(release_path):
            validate_context(item, boundary=boundary, project=boundary.project)
            sidecar = release_data.load_gold(release_dir, item['item_id'])
            _require(sidecar is not None, f"Go item {item['item_id']} has no release gold sidecar")
            compare_context(item, sidecar, boundary=boundary, project=boundary.project)
            # release_gold carries execution context, not native step bindings.
            # Controls and Then stripping still read their complete closure file.
            contexts.append({key: sidecar[key] for key in (
                'item_id', 'feature_file', 'scenario_line', 'files', 'go_suite')})
    harness = GodogHarness(manifest, boundary, runner, contexts,
                          original_inventory=original_inventory)
    harness.artifacts_dir = str(Path(args.artifacts).resolve())
    harness.image_id = _bound['runtime']['container_image_digest']
    harness._worker_runtime = _bound['runtime']
    harness.verify_substrate()
    return harness, boundary, manifest


install_solution = GodogHarness.install_solution
