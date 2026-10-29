"""Ruby/Cucumber execution, stripping and the seven stack seams.

The native listener produces complete source-step records; the shared fold
and process exit witness decide outcomes. API collection uses the reviewed Ruby binding contract.
"""
from __future__ import annotations

import importlib
import json
import os
import shlex
import shutil
import subprocess
import time

from ..bench import harness as _hz, repo as _repo
from ..core.boundary import REMOVABLE as _REMOVABLE
from ..core.gherkin import standalone_feature
from ..core.paths import DATA_ROOT_ENV, project_path
from . import base as _base

FRAMEWORK = "cucumber_ruby"
LANGUAGE = "ruby"
FEATURE_REL = _hz.FEATURE_REL
COMPILE_CHECK_REL = "_bench/compile_check.rb"
RECORDER_REL = "_bench/bench_recorder.rb"
COVERAGE_PRELOAD_REL = "_bench/coverage_preload.rb"
COVERAGE_HOOKS_REL = "_bench/coverage_hooks.rb"
DIRECT_CALLS_REL = "_bench/direct_calls.rb"
#: Owner-approved post-hoc sensitivity overlays, by row label: a harness-owned
#: file loaded at final execution only, never part of the substrate or of any
#: candidate (specifications/E_PETITIONS_WEBMOCK_WORLD_SENSITIVITY_SPEC.md).
SENSITIVITY_OVERLAYS = {
    "webmock_world_v1": ("_bench/sensitivity_webmock_world.rb", "require 'webmock/cucumber'\n"),
}
EXEC_HELPER = "/usr/local/bin/r2t-ruby-exec"
RESET_HELPER = "/usr/local/bin/r2t-ruby-reset"
RUBY_ERROR_MARKERS = ("LoadError", "SyntaxError", "NameError", "NoMethodError",
                      "Cucumber::", "Ruby record error", "Ruby bootstrap failed")

DockerRunner = _hz.DockerRunner
Solution = _hz.Solution
RunResult = _hz.RunResult
record_outcome = _hz.record_outcome
fold_scenario_records = _hz.fold_scenario_records
gold_solution = _hz.gold_solution
verify_substrate = _repo.verify_substrate
clean_workspace = _repo.clean_workspace
integrity_baseline = _repo.baseline_substrate
record_rel = _hz.RECORD_REL


def _complete_record(record: object, coverage: bool) -> bool:
    """An interrupted JSON line or a nonterminal scenario is not a pass."""
    if not isinstance(record, dict) or not set(_base.RECORD_FIELDS) <= record.keys():
        return False
    if record["scenario_result"] not in _base.SCENARIO_RESULTS \
            or record["suite"] != FRAMEWORK \
            or not isinstance(record["scenario_line"], int) \
            or not isinstance(record["steps"], list):
        return False
    if any(not isinstance(step, dict) or not set(_base.STEP_FIELDS) <= step.keys()
           or step["result"] not in _base.STEP_RESULTS for step in record["steps"]):
        return False
    measured = record["coverage"]
    return (measured is None if not coverage else
            isinstance(measured, dict) and set(measured) == set(_base.COVERAGE_FIELDS)
            and isinstance(measured["files"], dict) and isinstance(measured["units"], list))


class RubyHarness:
    """One explicitly rooted Ruby workspace; no PHP registration channel."""

    _abs = _hz.Harness._abs
    install_solution = _hz.Harness.install_solution
    verify_substrate = _hz.Harness.verify_substrate
    purge_bytecode = _hz.Harness.purge_bytecode

    def __init__(self, manifest: _repo.StripManifest, boundary, runner):
        root = os.path.abspath(manifest.repo_root)
        if os.path.abspath(boundary.repo_root) != root:
            raise ValueError("Ruby boundary and manifest must name the same workspace")
        if tuple(manifest.substrate_roots) != _repo.RUBY_SUBSTRATE_ROOTS \
                or frozenset(manifest.substrate_volatile) != _repo.RUBY_SUBSTRATE_VOLATILE:
            raise ValueError("Ruby manifest must record its reviewed substrate roots and volatility")
        if runner.workdir != "/app":
            raise ValueError("Ruby worker workdir must explicitly be /app")
        self.man, self.boundary, self.runner, self.root = manifest, boundary, runner, root
        self.expected_mutations: dict = {}
        self._unquiescent_cleanup = None
        #: A SENSITIVITY_OVERLAYS label, set only for a labelled replay.
        self.sensitivity = None

    @property
    def workdir_root(self) -> str:
        return self.runner.workdir

    def _remove_run_files(self) -> None:
        for rel in (FEATURE_REL, record_rel):
            path = self._abs(rel)
            if os.path.isfile(path):
                os.remove(path)

    def _require_quiescent(self) -> None:
        if self._unquiescent_cleanup is not None:
            raise RuntimeError(
                "REFUSED: Ruby timeout cleanup did not establish quiescence "
                f"({self._unquiescent_cleanup}); reprovision the worker before reuse")

    def _reset_runtime(self) -> None:
        self._require_quiescent()
        cp = self.runner.run(RESET_HELPER, timeout=300)
        if cp.returncode:
            raise RuntimeError("Ruby bootstrap failed during reset: " +
                               (cp.stderr or cp.stdout or "")[-2000:])

    def prepare_for_generation(self) -> None:
        self.verify_substrate()
        self._reset_runtime()
        clean_workspace(self.man, self.boundary)
        self._remove_run_files()
        self.verify_substrate()

    def clear_registration(self) -> None:
        self._remove_run_files()

    def write_feature(self, feature, scenario, override=None):
        text = override if override is not None else standalone_feature(feature, scenario)
        os.makedirs(os.path.dirname(self._abs(FEATURE_REL)), exist_ok=True)
        with open(self._abs(FEATURE_REL), "w", encoding="utf-8") as stream:
            stream.write(text)
        lines = [i for i, line in enumerate(text.split("\n"), 1)
                 if _hz._SCENARIO_LINE.match(line)]
        expected_line = lines[-1] if lines else None
        expected_lines = ([expected_line] + _hz.Harness._example_row_lines(text, expected_line)
                          if expected_line is not None else None)
        return text, expected_line, expected_lines

    def index_paths(self, rel_paths: list) -> dict:
        if not rel_paths:
            return {"root": self.workdir_root, "files": {}, "errors": {}}
        args = " ".join(f"--path {shlex.quote(path)}" for path in sorted(set(rel_paths)))
        cp = self.runner.run(f"{EXEC_HELPER} bundle exec ruby {COMPILE_CHECK_REL} {args}", timeout=300)
        try:
            doc = json.loads(cp.stdout or "")
        except ValueError:
            doc = None
        if cp.returncode or not isinstance(doc, dict) \
                or not isinstance(doc.get("files"), dict) or not isinstance(doc.get("errors"), dict):
            return {"root": self.workdir_root, "files": {},
                    "errors": {"analyzer": (cp.stderr or cp.stdout or "invalid Ruby syntax response")[-2000:]}}
        return doc

    def execute(self, coverage: bool = False, timeout: int = 600,
                expected_line=None, expected_lines=None) -> RunResult:
        # The caller already prepared the item. Resetting here would erase
        # its rendered feature and any staged mutation-applier state.
        self._require_quiescent()
        record = self._abs(record_rel)
        if os.path.exists(record):
            os.remove(record)
        os.makedirs(os.path.dirname(record), exist_ok=True)
        env = {"BENCH_RECORD_PATH": self.runner.in_container(record_rel),
               "BENCH_REPO_ROOT": self.workdir_root,
               "BENCH_COVERAGE": "1" if coverage else "0"}
        pid_file = f"/tmp/r2t-ruby-{os.getpid()}-{next(_hz._EXEC_SEQ)}.pid"
        overlay = SENSITIVITY_OVERLAYS[self.sensitivity] if self.sensitivity else None
        command = (
            f"printf '%s' $$ > {shlex.quote(pid_file)} && exec {EXEC_HELPER} "
            f"bundle exec ruby -r ./{COVERAGE_PRELOAD_REL} -r ./{RECORDER_REL} -S cucumber "
            f"--no-profile --strict --publish-quiet --require {COVERAGE_HOOKS_REL} "
            + (f"--require {overlay[0]} " if overlay else "")
            + f"--require features --format R2T::Recorder {FEATURE_REL}")
        started = time.monotonic()
        timed_out, cleanup = False, None
        if overlay:
            with open(self._abs(overlay[0]), "w", encoding="utf-8") as stream:
                stream.write(overlay[1])
        try:
            cp = self.runner.run(command, env=env, timeout=timeout)
            code, out = cp.returncode, (cp.stdout or "") + (cp.stderr or "")
        except subprocess.TimeoutExpired as error:
            timed_out = True
            cleanup = _hz._kill_process_tree(self.runner, pid_file)
            if cleanup != "killed":
                self._unquiescent_cleanup = cleanup
            code = -1
            raw = error.stdout or ""
            out = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        finally:
            if overlay and os.path.exists(self._abs(overlay[0])):
                os.remove(self._abs(overlay[0]))
        wall = time.monotonic() - started
        if not timed_out:
            self.runner.run(f"rm -f {shlex.quote(pid_file)}", timeout=60)
        records = []
        malformed = False
        if os.path.isfile(record):
            with open(record, encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        malformed = True
                        break
                    if not _complete_record(row, coverage):
                        malformed = True
                        break
                    records.append(row)
        required = set(expected_lines or ([] if expected_line is None else [expected_line]))
        if len(required) > 1:
            required.discard(expected_line)
        if records and required and not required <= {row["scenario_line"] for row in records}:
            malformed = True
        if malformed:
            # Do not hand a partially completed outline to the shared fold.
            records = []
            code = code or 1
            out += "\nRuby record error: incomplete or invalid scenario record\n"
        return RunResult(exit_code=code, stdout=out, wall_seconds=wall,
                         records=records, timed_out=timed_out, timeout_cleanup=cleanup,
                         expected_line=expected_line, expected_lines=expected_lines,
                         error_markers=RUBY_ERROR_MARKERS)

    def run_solution(self, feature, scenario, solution: Solution,
                     coverage: bool = False, timeout: int = 600,
                     repeats: int = 1, task: str = "criterion_to_test",
                     keep_stdout: bool = False) -> dict:
        self.verify_substrate()
        self._reset_runtime()
        clean_workspace(self.man, self.boundary)
        self._remove_run_files()
        written, rejected = self.install_solution(solution, task=task)
        if solution.services_fragment:
            rejected = rejected + [{"file_path": _hz.SERVICES_FRAGMENT_NAME,
                                    "why": "no_wiring_channel:cucumber_ruby"}]
        ruby_paths = [path for path in written if path.endswith(".rb")]
        index = self.index_paths(ruby_paths)
        produced_feature = (next((f.code for f in solution.files
                                  if f.file_path.endswith(".feature")), None)
                            if task == "requirement_to_test" else None)
        runs = []
        for ordinal in range(max(1, repeats)):
            if ordinal:
                self._reset_runtime()
            _, line, lines = self.write_feature(feature, scenario, override=produced_feature)
            runs.append(self.execute(coverage=coverage, timeout=timeout,
                                     expected_line=line, expected_lines=lines))
            after = verify_substrate(self.man, self.boundary, expected=self.expected_mutations)
            if after["baseline"] and any(after[key] for key in ("changed", "missing", "added")):
                break  # Preserve the violating run before any reset can hide its writes.
            if self._unquiescent_cleanup is not None:
                break  # Keep the timeout row; no repeat may race a surviving process.
        violation = ({key: after[key][:8] for key in ("changed", "missing", "added")}
                     if after["baseline"] and any(after[key] for key in ("changed", "missing", "added"))
                     else None)
        return {"substrate_violation": violation, "written_files": written,
                "rejected_files": rejected, "feature_from_solution": produced_feature is not None,
                "index_errors": index["errors"], "registered_contexts": sorted(ruby_paths),
                "runs": [run.to_json(keep_stdout=keep_stdout) for run in runs],
                "outcomes": [run.outcome for run in runs]}


def strip_repo_ruby(boundary, gold_root: str, harness_dir=None,
                    dry_run: bool = False) -> _repo.StripManifest:
    root = os.path.abspath(boundary.repo_root)
    gold = os.path.abspath(gold_root)
    for protected in _repo.declared_corpus_roots():
        if root == protected or root.startswith(protected + os.sep):
            raise SystemExit("REFUSED: strip a clone, not a pinned corpus")
    if gold == root or gold.startswith(root + os.sep):
        raise SystemExit("REFUSED: gold must be outside the stripped workspace")
    if not os.path.isdir(os.path.join(root, "features", "step_definitions")) \
            or not os.path.isfile(os.path.join(root, "Gemfile")):
        raise SystemExit("REFUSED: Ruby strip requires Gemfile and features/step_definitions")
    harness_dir = harness_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), "ruby")
    installed = (RECORDER_REL, COVERAGE_PRELOAD_REL, COVERAGE_HOOKS_REL, COMPILE_CHECK_REL, DIRECT_CALLS_REL)
    for rel in installed:
        if not os.path.isfile(os.path.join(harness_dir, os.path.basename(rel))):
            raise SystemExit(f"REFUSED: missing Ruby harness input {rel}")
    man = _repo.StripManifest(repo_root=root, gold_root=gold,
                              boundary_version=boundary.version,
                              substrate_roots=list(_repo.RUBY_SUBSTRATE_ROOTS),
                              substrate_volatile=sorted(_repo.RUBY_SUBSTRATE_VOLATILE),
                              bytecode_roots=[], build_roots=[])
    seen = set()
    for prefix, _ in boundary.removable:
        for rel in _repo._iter_files(root, prefix):
            if rel in seen or boundary.classify(rel) != _REMOVABLE:
                continue
            seen.add(rel)
            is_config = any(rel == p.rstrip("/") or rel.startswith(p.rstrip("/") + "/")
                            for p in boundary.removable_config)
            (man.moved_config if is_config else man.moved).append(rel)
    if dry_run:
        return man
    # Resolve destination collisions before moving any answer bytes.
    if any(os.path.exists(os.path.join(gold, name)) for name in ("strip_manifest.json", "_git")):
        raise SystemExit("REFUSED: gold already contains a strip manifest or preserved repository")
    for rel in man.moved + man.moved_config:
        if os.path.exists(os.path.join(gold, rel)):
            raise SystemExit(f"REFUSED: gold already contains {rel}")
    for rel in installed:
        if os.path.exists(os.path.join(root, rel)):
            raise SystemExit(f"REFUSED: Ruby harness destination already exists: {rel}")
    for rel in man.moved + man.moved_config:
        _repo._move(root, gold, rel)
    for prefix, _ in boundary.removable:
        _repo._prune_empty_dirs(root, prefix)
    os.makedirs(os.path.join(root, "features", "step_definitions"), exist_ok=True)
    os.makedirs(os.path.join(root, "_bench"), exist_ok=True)
    for rel in installed:
        destination = os.path.join(root, rel)
        shutil.copyfile(os.path.join(harness_dir, os.path.basename(rel)), destination)
        man.installed.append(rel)
    man.installed += _repo.sanitise_repo(root, gold, ())
    man.save(os.path.join(gold, "strip_manifest.json"))
    return man


def make_harness(args):
    from ..core.boundary import load_boundary
    boundary = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    path = os.path.join(args.gold, "strip_manifest.json")
    if not os.path.isfile(path):
        raise SystemExit(f"REFUSED: no Ruby strip manifest at {path}")
    manifest = _repo.load_manifest(path)
    manifest.repo_root = os.path.abspath(boundary.repo_root)
    manifest.gold_root = os.path.abspath(args.gold)
    if getattr(args, "workdir", None) != "/app":
        raise SystemExit("REFUSED: Ruby requires explicit --workdir /app")
    runner = DockerRunner(args.container, workdir=args.workdir)
    harness = RubyHarness(manifest, boundary, runner)
    if getattr(args, "sensitivity", None) in SENSITIVITY_OVERLAYS:
        harness.sensitivity = args.sensitivity
    return harness, boundary, manifest


def cmd_strip(args) -> int:
    from ..core.boundary import load_boundary
    protected = ["/data2/binhang/coreshop_bench"]
    if os.environ.get(DATA_ROOT_ENV):
        protected.append(os.path.abspath(project_path("coreshop", "gold")))
    gold = os.path.abspath(args.gold)
    if any(gold == path or gold.startswith(path + os.sep) for path in protected):
        raise SystemExit("REFUSED: Ruby gold cannot overwrite CoreShop's gold tree")
    boundary = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    manifest = strip_repo_ruby(boundary, args.gold, dry_run=args.dry_run)
    print(f"{'would move' if args.dry_run else 'moved'} {len(manifest.moved)} Ruby answer files -> {args.gold}")
    return 0


strip = strip_repo_ruby
install_solution = RubyHarness.install_solution
execute = RubyHarness.execute

# Lazy resolution keeps execution-only imports independent of extraction's
# optional parsers. Returned values are the original objects, never wrappers.
_EXPORTS = {
    "extract_closure": "r2t.toolkit.closure_rb.load_extractor",
    "cmd_closures": "r2t.toolkit.closure_rb.cmd_closures",
    "cmd_interfaces": "r2t.toolkit.interfaces_rb.cmd_interfaces",
    "cmd_index": "r2t.toolkit.rbstep_index.cmd_index",
    "run_matcher": "r2t.toolkit.rbstep_index.run_matcher",
    "crosscheck": "r2t.toolkit.rbstep_index.crosscheck",
    "item_steps": "r2t.toolkit.rbstep_index.item_steps",
    "effective_steps": "r2t.toolkit.rbstep_index.effective_steps",
    "examples_rows": "r2t.toolkit.rbstep_index.examples_rows",
    "image": "r2t.toolkit.rbstep_index.DEFAULT_IMAGE",
    "container_root": "r2t.toolkit.rbstep_index.CONTAINER_ROOT",
    "stub_solution": "r2t.toolkit.stub_rb.stub_solution",
    "make_stub_adapter": "r2t.toolkit.stub_rb.make_stub_adapter",
    "cmd_stub_accept": "r2t.toolkit.stub_rb.cmd_stub_accept",
    "stripped_solution": "r2t.toolkit.strip_rb.stripped_solution",
    "make_strip_adapter": "r2t.toolkit.strip_rb.make_strip_adapter",
    "mutant_population": "r2t.toolkit.mutation_rb.build_population",
    "cmd_mutants": "r2t.toolkit.mutation_rb.cmd_mutants",
    "engine": "r2t.toolkit.mutation_rb.ENGINE",
    "engine_version": "r2t.toolkit.mutation_rb.ENGINE_VERSION",
    "engine_dir": "r2t.toolkit.mutation_rb.RB_ENGINE_DIR",
    "excluded_prefixes": "r2t.toolkit.mutation_rb.EXCLUDED_PREFIXES",
    "applier": "r2t.toolkit.mutation_rb.applier",
}


def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(name)
    module, attribute = _EXPORTS[name].rsplit(".", 1)
    value = getattr(importlib.import_module(module), attribute)
    globals()[name] = value
    return value


MEMBERS = {**_EXPORTS, **{name: f"r2t.bench.harness.{name}" for name in (
    "DockerRunner", "Solution", "RunResult", "record_outcome", "fold_scenario_records", "gold_solution")},
    "integrity_baseline": "r2t.bench.repo.baseline_substrate",
    "verify_substrate": "r2t.bench.repo.verify_substrate",
    "clean_workspace": "r2t.bench.repo.clean_workspace",
    "record_rel": "r2t.bench.harness.RECORD_REL",
    "install_solution": "r2t.bench.harness.Harness.install_solution"}
OWN_MEMBERS = ("RubyHarness", "__getattr__", "_complete_record", "cmd_strip", "execute",
               "make_harness", "selftest", "strip", "strip_repo_ruby")
PENDING = {}


def selftest() -> int:
    """Network-free shared-fold, strip, acceptance and timeout regression checks."""
    import copy
    import tempfile
    from pathlib import Path
    from unittest.mock import patch
    from ..core.boundary import Boundary

    def row(line=2, result="passed", coverage=None):
        return {"feature_file": FEATURE_REL, "feature_title": "F", "scenario_title": "S",
                "scenario_line": line, "suite": FRAMEWORK,
                "steps": [{"line": line + 1, "keyword": "Given ", "text": "a step",
                           "result": result, "seconds": 0.0, "exception": None}],
                "coverage": coverage, "direct_calls": None, "seconds": 0.0,
                "scenario_result": "passed" if result == "passed" else "not-passed"}

    class FakeRunner(DockerRunner):
        def __init__(self, root):
            super().__init__("fixture", workdir="/app", docker_group=False)
            self.root, self.calls = root, []
            self.payload, self.code, self.timeout = [], 0, False
            self.add_asset = False
            self.overlay_seen = None

        def run(self, command, env=None, timeout=900):
            self.calls.append((command, env or {}))
            if "-S cucumber" in command:
                overlay = Path(self.root) / SENSITIVITY_OVERLAYS["webmock_world_v1"][0]
                self.overlay_seen = overlay.read_text() if overlay.exists() else None
                if self.timeout:
                    raise subprocess.TimeoutExpired(command, timeout, output=b"partial")
                with open(os.path.join(self.root, record_rel), "w", encoding="utf-8") as stream:
                    for item in self.payload:
                        stream.write((json.dumps(item) if not isinstance(item, str) else item) + "\n")
                if self.add_asset:
                    asset = Path(self.root) / "public/assets/unexpected.js"
                    asset.parent.mkdir(parents=True, exist_ok=True)
                    asset.write_text("unexpected substrate addition")
                return subprocess.CompletedProcess([], self.code, "", "")
            if "compile_check.rb" in command:
                return subprocess.CompletedProcess([], 0, '{"files":{},"errors":{}}', "")
            return subprocess.CompletedProcess([], 0, "", "")

    own = sorted(name for name, value in globals().items()
                 if callable(value) and getattr(value, "__module__", None) == __name__)
    assert own == sorted(OWN_MEMBERS), own
    assert install_solution is _hz.Harness.install_solution
    assert integrity_baseline is _repo.baseline_substrate
    assert record_outcome is _hz.record_outcome and fold_scenario_records is _hz.fold_scenario_records
    assert _complete_record(row(), False)
    assert not _complete_record({"steps": row()["steps"]}, False)
    assert not _complete_record(row(), True)
    measured = {"files": {"app/a.rb": 1}, "units": ["app/a.rb::L2"]}
    assert _complete_record(row(coverage=measured), True)

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp) / "workspace"
        gold = Path(temp) / "gold"
        (root / "features/step_definitions").mkdir(parents=True)
        (root / "features/support").mkdir()
        (root / "app/models").mkdir(parents=True)
        (root / "Gemfile").write_text("# fixture\n")
        answer = root / "features/step_definitions/answer.rb"
        answer.write_bytes(b"Given('a step') {}\r\n")
        support = root / "features/support/env.rb"
        support.write_bytes(b"# retained exactly\r\n")
        (root / "app/models/a.rb").write_text("class A; end\n")
        boundary = Boundary(1, "ruby_fixture", str(root),
                            removable=[("features/step_definitions/", "answer")],
                            retained=[("features/support/", "support")])
        plan = strip_repo_ruby(boundary, str(gold), dry_run=True)
        assert plan.moved == ["features/step_definitions/answer.rb"] and answer.exists()
        manifest = strip_repo_ruby(boundary, str(gold))
        assert not answer.exists() and (gold / plan.moved[0]).read_bytes() == b"Given('a step') {}\r\n"
        assert support.read_bytes() == b"# retained exactly\r\n"
        assert set(manifest.installed) >= {RECORDER_REL, COVERAGE_PRELOAD_REL, COVERAGE_HOOKS_REL, COMPILE_CHECK_REL, DIRECT_CALLS_REL}
        assert not manifest.bytecode_roots and not manifest.build_roots
        integrity_baseline(manifest, boundary, str(gold / "strip_manifest.json"))
        runner = FakeRunner(str(root))
        harness = RubyHarness(manifest, boundary, runner)
        harness.verify_substrate()
        runner.payload = [row()]
        assert harness.execute(expected_line=2).outcome == "passed"
        command, env = next(call for call in runner.calls if "-S cucumber" in call[0])
        assert "--strict" in command and "--no-profile" in command
        assert command.index("coverage_preload.rb") < command.index("-S cucumber")
        assert env["BENCH_COVERAGE"] == "0" and "RUBYOPT" not in env
        assert RESET_HELPER not in command
        overlay_rel, overlay_text = SENSITIVITY_OVERLAYS["webmock_world_v1"]
        assert overlay_rel not in command and runner.overlay_seen is None
        # A labelled sensitivity replay loads its harness-owned overlay before
        # the features and removes it afterwards, also after a timeout.
        harness.sensitivity = "webmock_world_v1"
        runner.calls.clear()
        assert harness.execute(expected_line=2).outcome == "passed"
        command = next(call[0] for call in runner.calls if "-S cucumber" in call[0])
        assert command.index(f"--require {overlay_rel}") < command.index("--require features")
        assert runner.overlay_seen == overlay_text == "require 'webmock/cucumber'\n"
        assert not (root / overlay_rel).exists()
        runner.timeout = True
        with patch.object(_hz, "_kill_process_tree", return_value="killed"):
            assert harness.execute(timeout=1, expected_line=2).outcome == "timeout"
        assert runner.overlay_seen == overlay_text and not (root / overlay_rel).exists()
        runner.timeout, harness.sensitivity = False, None
        # Only this stack's labels reach the harness; `run` refuses any other.
        from types import SimpleNamespace
        with patch("r2t.core.boundary.load_boundary", return_value=boundary):
            for label, kept in (("webmock_world_v1", "webmock_world_v1"),
                                ("coddy_retained_helpers_v1", None), (None, None)):
                made, _, _ = make_harness(SimpleNamespace(
                    boundary="unused.yml", gold=str(gold), workdir="/app",
                    container="unused", sensitivity=label))
                assert made.sensitivity == kept, label
        runner.code = 1
        assert harness.execute(expected_line=2).outcome == "passed_but_nonzero_exit"
        runner.payload = [row(result="skipped")]
        assert harness.execute(expected_line=2).outcome == "not_passed"
        runner.payload = [row(result="undefined")]
        assert harness.execute(expected_line=2).outcome == "undefined_steps"
        runner.code = 0
        runner.payload = [row(6)]
        assert harness.execute(expected_line=2, expected_lines=[2, 6, 7]).outcome == "container_error"
        runner.payload = [row(6), row(7)]
        assert harness.execute(expected_line=2, expected_lines=[2, 6, 7]).outcome == "passed"
        runner.payload = [row(), '{"steps":']
        assert harness.execute(expected_line=2).outcome == "container_error"
        runner.payload = []
        assert harness.execute(expected_line=2).outcome == "no_scenario_ran"
        runner.timeout = True
        with patch.object(_hz, "_kill_process_tree", return_value="killed") as kill:
            result = harness.execute(timeout=1, expected_line=2)
            assert result.outcome == "timeout" and result.timeout_cleanup == "killed"
            kill.assert_called_once()
            assert kill.call_args.args[1].startswith("/tmp/r2t-ruby-")
        runner.timeout = False
        wrong = copy.deepcopy(manifest)
        wrong.substrate_roots = []
        try:
            RubyHarness(wrong, boundary, runner)
        except ValueError:
            pass
        else:
            raise AssertionError("Ruby accepted a legacy CoreShop manifest")
        assert (root / "_bench/compile_check.rb").is_file()
        from ..core.gherkin import parse_feature_file
        feature = parse_feature_file("memory.feature", "Feature: F\n  Scenario: S\n    Given a step\n")
        for verdict in ("survived", "cleanup_failed:TimeoutExpired", "no_pid", "unknown"):
            failed_runner = FakeRunner(str(root))
            failed_runner.timeout = True
            failed_harness = RubyHarness(manifest, boundary, failed_runner)
            with patch.object(_hz, "_kill_process_tree", return_value=verdict):
                timed = failed_harness.run_solution(
                    feature, feature.scenarios[0], Solution(), repeats=2)
            assert timed["outcomes"] == ["timeout"]
            assert timed["runs"][0]["timeout_cleanup"] == verdict
            assert sum(cmd == RESET_HELPER for cmd, _ in failed_runner.calls) == 1
            calls_before = len(failed_runner.calls)
            for reuse in (failed_harness.prepare_for_generation,
                          failed_harness.execute,
                          lambda: failed_harness.run_solution(
                              feature, feature.scenarios[0], Solution())):
                try:
                    reuse()
                except RuntimeError as exc:
                    assert "reprovision the worker" in str(exc)
                else:
                    raise AssertionError("Ruby reused a worker without confirmed timeout cleanup")
                assert len(failed_runner.calls) == calls_before
        killed_runner = FakeRunner(str(root))
        killed_runner.timeout = True
        with patch.object(_hz, "_kill_process_tree", return_value="killed"):
            timed = RubyHarness(manifest, boundary, killed_runner).run_solution(
                feature, feature.scenarios[0], Solution(), repeats=2)
        assert timed["outcomes"] == ["timeout", "timeout"]
        assert sum(cmd == RESET_HELPER for cmd, _ in killed_runner.calls) == 2
        runner.calls.clear()
        runner.payload, runner.add_asset = [row()], True
        repeated = harness.run_solution(feature, feature.scenarios[0], Solution(), repeats=2)
        assert len(repeated["runs"]) == 1
        assert "public/assets/unexpected.js" in repeated["substrate_violation"]["added"]
        assert sum(command == RESET_HELPER for command, _ in runner.calls) == 1
        runner.add_asset = False
        assert (root / "public/assets/unexpected.js").exists()
        (root / "public/assets").mkdir(parents=True, exist_ok=True)
        added = root / "public/assets/unexpected.js"
        added.write_text("unexpected substrate addition")
        runner.calls.clear()
        try:
            harness.prepare_for_generation()
        except _repo.SubstrateTampered:
            pass
        else:
            raise AssertionError("reset concealed an unexpected hashed asset")
        assert added.exists() and not runner.calls
        (root / "app/models/a.rb").write_text("class A; CHANGED = true; end\n")
        report = verify_substrate(manifest, boundary)
        assert "app/models/a.rb" in report["changed"]
    print("  [PASS] Ruby strip, exact shared plumbing, strict/exit witness, incomplete records, timeout cleanup "
          "and the sensitivity overlay")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())
