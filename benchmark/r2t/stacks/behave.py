"""The behave/Python stack — S3's index half plus S4's execution half.

`behat.py` is a façade over code that already existed; this is the stack that
is being WRITTEN, so it lands in the order the milestones land it and says so.
S3 landed the index half (`extract_closure`, `cmd_index`, `cmd_closures`);
this file now also carries S4's execution half:

* `BehaveHarness` — duck-types exactly the surface `validate`, `runner` and
  `mutation_run` consume, and REUSES verbatim (checked with `is` where the
  object allows it): `RunResult` and its fold, `record_outcome`,
  `gold_solution`, `DockerRunner`, `Solution`, `clean_workspace`,
  `verify_substrate`, and `Harness.install_solution` itself — nothing in
  that method is PHP: it is boundary classification and a `.feature`
  refusal, and two implementations of "where may a solution write" would be
  two chances for them to disagree.
* `strip_repo_behave` — the answer out of a CLONE (never the pinned corpus;
  refused by prefix) and into gold, recording the behave substrate roots and
  bytecode roots in the manifest; installs the recorder
  (`r2t/py/bench_environment.py` → `features/environment.py`, the original
  moving to gold) and the in-container syntax gate
  (`r2t/py/compile_check.py` → `_bench/compile_check.py`).
* `make_harness` — the construction `cli._harness` dispatches to for
  `framework: behave`.

Nothing is pending here any more.  S5 landed `stub_solution` and
`mutant_population`, and both are bound at the FOOT of this file, which
is also where `PENDING` loses their entries — it is empty from that line
on, so `stacks.verb` has nothing left to refuse and `closure_py`'s
absence check nothing left to assert.  This paragraph and `PENDING` are
the two halves of one statement, so a seam that lands moves in both or
the file lies to whoever reads only one.

Execution decisions, each verified against the REAL behave 1.3.3 in
`r2t_docx_img:base` before being written down:

* **No `--strict`.**  behave 1.3.3 has no such flag (`--strict` exits 2,
  "unrecognized arguments") and needs none: an all-undefined feature exits 1
  BY DEFAULT, which is the half of the two-witness rule the exit code
  carries.  The selftest pins the invocation bytes; the S4 gate pins the
  exit-1-on-undefined default live, in the image.
* **The synthesised feature lives at `features/_bench_item.feature`.**
  behave's base-dir discovery, handed that file path, selects `features/` as
  base dir (it holds `steps/`), loads `features/environment.py` (the
  recorder) and `features/steps/` (the solution) — verified live, so no
  generated `behave.ini` is needed.  The path is under no substrate root, so
  it needs no volatile exemption.
* **`PYTHONPATH=<workdir>/src`, no `pip install -e`.**  The repository's own
  editable install points at a dead path and its `a1_coverage.pth` runs a
  coverage hook at interpreter start — the two confounds exploration found —
  so the import path is set per exec, derived from the runner's own workdir
  (the H2 lesson: derive from the mount point, never hard-code it).
* **`PYTHONDONTWRITEBYTECODE=1` at the exec, plus the purge hooks.**  The
  image bakes the variable, but the exec sets it again (an env the container
  was started without must not depend on the image being the pinned one),
  and the S2 purge hooks run at the same four sites as the PHP stack's
  container invalidation — bytecode inside a substrate root is a tampering
  abort one item later.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import time

from ..toolkit import closure_py as _closure_py, interfaces_py as _interfaces_py
from ..bench import harness as _hz
from ..toolkit import pystep_index as _pystep_index
from ..bench import repo as _repo
from ..toolkit import strip_py as _assertion_strip
from ..core.gherkin import standalone_feature
from ..core.paths import DATA_ROOT_ENV, project_path
from ..py import analyze_py as _analyze_py

#: The value of `framework:` in `config/profile_python_docx.yml`, and the key
#: `stacks.for_framework` dispatches on.  It is checked against the registry
#: name there: a module derived from `behat.py` that kept `FRAMEWORK =
#: "behat"` would be routed under its own name and then take the behat branch
#: of every dispatch, i.e. run a Python project through the PHP harness.
FRAMEWORK = "behave"

#: The language, checked against `framework:` when a profile loads.
LANGUAGE = "python"

# --------------------------------------------------------------- the seven
#
# Five of the seven, in the order a project passes through them.  The other
# two raise through `stacks.verb` until S5 lands them.

#: `closure_py.load_extractor` — builds the extractor whose
#: `closure_for(item, feature, scenario)` is one item's gold closure.  The
#: object rather than a per-item function, for the same reason the Behat one
#: is: it holds the static index and behave's whole match table.
extract_closure = _closure_py.load_extractor

#: `repo.baseline_substrate` — genuinely shared, not a twin: it hashes
#: whatever roots the MANIFEST records, and a behave manifest records the
#: behave roots.  Same object as `behat.integrity_baseline`, on purpose.
integrity_baseline = _repo.baseline_substrate

# `strip`, `install_solution` and `execute` are defined below with the
# harness; the module-level aliases sit after their definitions.

# ------------------------------------------------------------- the CLI verbs
#
# `cli.cmd_index` and `cli.cmd_closures` are PHP-bound end to end (they run
# `analyze_php.php`, read `services.yml`, build Behat suites), so they are
# dispatched rather than parameterised.  These are their behave bodies.
# `cmd_strip` joins them below: `repo.strip_repo` refuses any tree that is
# not CoreShop, so the strip verb dispatches too.

cmd_index = _pystep_index.cmd_index
cmd_closures = _closure_py.cmd_closures
cmd_interfaces = _interfaces_py.cmd_interfaces

# ------------------------------------------- the objects those verbs live on

#: The static index (host, `ast`) and the in-container matcher (behave's own
#: registry).  Re-exported so a caller that has the stack does not have to
#: know which module inside it to import from.
build_index = _analyze_py.build_index
run_matcher = _pystep_index.run_matcher
crosscheck = _pystep_index.crosscheck

#: Everything a step IS before it is matched: And/But/`*` resolved the way
#: behave's parser resolves them, and Examples rows substituted the way
#: `ScenarioOutlineBuilder` substitutes them.
item_steps = _pystep_index.item_steps
effective_steps = _pystep_index.effective_steps
examples_rows = _pystep_index.examples_rows

#: The execution image and where a workspace is mounted inside it.
image = _pystep_index.DEFAULT_IMAGE
container_root = _pystep_index.CONTAINER_ROOT

# ------------------------------------------------ the shared record plumbing
#
# Reused BY IDENTITY (`closure_py.selftest` walks MEMBERS with `is`): what a
# record says happened, how an outline folds, how a gold solution is
# assembled, and the two workspace guards.  One implementation each, because
# "what does this record mean" must not have two answers.

DockerRunner = _hz.DockerRunner
Solution = _hz.Solution
RunResult = _hz.RunResult
record_outcome = _hz.record_outcome
fold_scenario_records = _hz.fold_scenario_records
gold_solution = _hz.gold_solution
verify_substrate = _repo.verify_substrate
clean_workspace = _repo.clean_workspace

#: Where this stack's recorder writes, repo-relative — the SAME path as the
#: PHP stack's (`_bench/run_record.jsonl`), which is what
#: `repo.BEHAVE_SUBSTRATE_VOLATILE` exempts.
record_rel = _hz.RECORD_REL

# Candidate-blind assertion screen, additive to the historical seven stack
# seams.  The adapter registry dispatches this exactly as it dispatches stub.
stripped_solution = _assertion_strip.stripped_solution
make_strip_adapter = _assertion_strip.make_strip_adapter

# ----------------------------------------------------------- S4 constants

#: The synthesised feature.  Under `features/` so behave's base-dir
#: discovery (walk up from the given path looking for a directory holding
#: `steps/`) lands on `features/` and loads the recorder and the solution;
#: under NO substrate root, so writing it per item disturbs no baseline.
FEATURE_REL = "features/_bench_item.feature"

#: The in-container syntax gate, installed at strip time so its hash is part
#: of the substrate baseline (the `_bench/analyze_php.php` precedent).
COMPILE_CHECK_REL = f"{_repo.BENCH_DIR}/compile_check.py"

#: The recorder's installation target — a FILE substrate root.
ENVIRONMENT_REL = "features/environment.py"

#: stdout substrings that mean "the environment failed before the test could
#: run" — `container_error`, not a verdict about the generated test.  These
#: are behave 1.3.3's OWN framings, probed live in the image:
#:
#:   * `HOOK-ERROR` / `ABORTED:` — the recorder (environment.py) raised;
#:   * `ConfigError` / `FileNotFoundError` — no steps directory to load;
#:   * `ParserError` — the synthesised feature did not parse;
#:   * `ModuleNotFoundError` / `ImportError` / `SyntaxError` — a step module
#:     (the solution's, or a retained one) failed at import, which is this
#:     framework's spelling of Behat's DI-compile failure;
#:   * `Exception ` — behave prefixes any other pre-run crash as
#:     `Exception <Class>: <msg>` before its own traceback.
#:
#: They are consulted ONLY when no record matched the scenario
#: (`RunResult.outcome`), so a failing step whose captured output happens to
#: contain one of these words cannot be misread: a run with records never
#: reaches the marker check.
BEHAVE_ERROR_MARKERS = ("HOOK-ERROR", "ABORTED:", "ConfigError",
                        "ParserError", "ModuleNotFoundError", "ImportError",
                        "SyntaxError", "FileNotFoundError", "Exception ")

#: Gold trees `cmd_strip` refuses to write into, by prefix.  A behave strip
#: pointed at the CoreShop gold default would overwrite CoreShop's integrity
#: baseline with a Python manifest, and every CoreShop worker would abort its
#: next item as tampered.  The portable entry is checkable only under a
#: configured data root; the archived Kilo tree stays protected always.
PROTECTED_GOLD = (
    project_path("coreshop", "gold"),
    "/data2/binhang/coreshop_bench",
)


# ------------------------------------------------------------- the harness
class BehaveHarness:
    """One behave workspace: install, synthesise, execute, verify.

    NOT a subclass of `harness.Harness`: four of that class's ten methods are
    Symfony (registration vetting, DI aliasing, container invalidation, the
    services file), and inheriting them would hand this stack a `vet_fragment`
    that silently accepts anything and a `write_registration` that writes YAML
    nothing reads.  What IS the same is assigned, not copied — the class
    attributes below are the PHP harness's own function objects, so the
    selftest can hold them to identity and a fix to either is a fix to both.
    """

    #: Same path arithmetic, same escape refusal.
    _abs = _hz.Harness._abs

    #: Same acceptance rule.  Nothing in it is PHP: boundary classification,
    #: the `.feature` refusal for `criterion_to_test`, the path-escape
    #: refusal.  Two implementations of "where may a solution write" would be
    #: two chances to disagree about the answer space.
    install_solution = _hz.Harness.install_solution

    #: Same integrity check (it reads the MANIFEST's roots — recorded by the
    #: behave strip as the behave roots) and same raise-on-mismatch.
    verify_substrate = _hz.Harness.verify_substrate

    #: Same two-halves purge: in-container `rm` first (the files are written
    #: by root on a bind mount), host-side re-scan that RAISES on survivors.
    purge_bytecode = _hz.Harness.purge_bytecode

    def __init__(self, manifest: _repo.StripManifest, boundary, runner):
        root = os.path.abspath(manifest.repo_root)
        if os.path.abspath(boundary.repo_root) != root:
            # The H1 refusal, verbatim in spirit: one workspace per harness.
            raise ValueError(
                f"the boundary classifies against {boundary.repo_root} while "
                f"the manifest writes into {manifest.repo_root}. One workspace "
                f"per harness: pass --repo, which sets both.")
        if not manifest.bytecode_roots:
            # A python stack whose manifest declares no bytecode roots is a
            # sweep that aborts itself: `PYTHONPATH=src` + `import docx`
            # writes `src/docx/__pycache__`, the purge (keyed on these roots)
            # is a no-op, and the NEXT item's verify reports tampering.  The
            # common way to get here is pointing --gold at another stack's
            # tree — a CoreShop manifest records no bytecode roots because a
            # PHP tree has no bytecode.
            raise ValueError(
                "this manifest declares no bytecode_roots, so it was not "
                "written by strip_repo_behave — most likely --gold points at "
                "another stack's gold tree. A behave workspace run under it "
                "would abort its second item as tampered with its own "
                "__pycache__.")
        self.man = manifest
        self.boundary = boundary
        self.runner = runner
        self.root = root
        #: `rel -> sha256` for production files a MUTATION campaign has
        #: deliberately edited (S5's seam, same shape as the PHP harness's).
        self.expected_mutations: dict = {}

    @property
    def workdir_root(self) -> str:
        return self.runner.workdir

    # -------------------------------------------------------- housekeeping
    def _remove_run_files(self) -> None:
        """The two per-item files this harness owns, gone.

        The record file is volatile (exempt from the baseline) and the
        synthesised feature is under no root, so neither can trip the
        substrate check — they are removed because each is the PREVIOUS
        item's: a stale record is the forgery surface the fold defends
        against, and a stale feature is the previous item's scenario sitting
        where an agent that reads the workspace can see it.
        """
        for rel in (FEATURE_REL, _hz.RECORD_REL):
            path = self._abs(rel)
            if os.path.exists(path):
                os.remove(path)

    def prepare_for_generation(self) -> None:
        """Everything that must be gone BEFORE a system generates.

        The behave twin of the PHP harness's method, minus the two Symfony
        artifacts (no compiled container, no solution index file — the
        syntax gate reports over stdout precisely so that no answer-bearing
        index ever exists on disk).  The purge-then-verify order is the S2
        rule: bytecode inside a substrate root must be swept BEFORE the
        check that would call it tampering.
        """
        _repo.clean_workspace(self.man, self.boundary)
        self._remove_run_files()
        self.purge_bytecode()
        self.verify_substrate()

    def clear_registration(self) -> None:
        """End-of-sweep tidy-up, same contract as the PHP harness's.

        behave has no registration file; what this stack leaves behind is
        the synthesised feature and the last record, and "leave the
        workspace as we found it" is the same rule either way.
        """
        self._remove_run_files()

    # -------------------------------------------------------------- suite
    def write_feature(self, feature, scenario, override=None):
        """The one scenario that will run, at `features/_bench_item.feature`.

        Same synthesis and same line arithmetic as the PHP harness — the
        expected lines are derived from the file we WRITE (the standalone
        file re-headers and inlines the Background, so every line moves),
        and `Harness._example_row_lines` is called rather than re-implemented
        because the Examples-row derivation is the fold's other half and two
        copies of it would be two chances to disagree about which rows an
        outline may claim.
        """
        text = override if override is not None else standalone_feature(
            feature, scenario)
        with open(self._abs(FEATURE_REL), "w", encoding="utf-8") as fh:
            fh.write(text)
        lines = [i for i, ln in enumerate(text.split("\n"), 1)
                 if _hz._SCENARIO_LINE.match(ln)]
        expected_line = lines[-1] if lines else None
        expected_lines = None
        if expected_line is not None:
            expected_lines = [expected_line] + _hz.Harness._example_row_lines(
                text, expected_line)
        return text, expected_line, expected_lines

    # ----------------------------------------------------------- indexing
    def index_paths(self, rel_paths: list) -> dict:
        """The syntax gate: compile every written `.py` in-container.

        The IMAGE's interpreter answers, not the host's: "does this parse"
        is a question about the python that will execute it (the host runs
        3.10, the image 3.12, and 3.12 accepts source 3.10 refuses).  The
        checker compiles and never imports — a solution must not get a
        side-effect channel out of its own syntax check — and reports over
        stdout, so no per-item index file exists for `prepare_for_generation`
        to have to scrub.

        A non-empty `errors` map routes the run to `parse_or_compile_error`
        through the same `runner._record` branch the PHP stack uses.
        """
        if not rel_paths:
            return {"root": self.workdir_root, "files": {}, "errors": {}}
        args = " ".join(f"--path {shlex.quote(p)}"
                        for p in sorted(set(rel_paths)))
        cp = self.runner.run(f"python {COMPILE_CHECK_REL} {args}", timeout=300)
        doc = None
        try:
            doc = json.loads(cp.stdout or "")
        except ValueError:
            doc = None
        if cp.returncode != 0 or not isinstance(doc, dict):
            # The checker itself failing is an analyzer fault, reported in
            # the same shape the PHP analyzer faults in — the row then reads
            # `parse_or_compile_error` with the reason attached, rather than
            # the sweep dying on one item.
            return {"root": self.workdir_root, "files": {},
                    "errors": {"analyzer": (cp.stderr or cp.stdout
                                            or "")[-2000:]}}
        doc["files"] = doc.get("files") or {}
        doc["errors"] = doc.get("errors") or {}
        return doc

    # ---------------------------------------------------------- execution
    def execute(self, coverage: bool = False, timeout: int = 600,
                expected_line=None, expected_lines=None) -> _hz.RunResult:
        record = self._abs(_hz.RECORD_REL)
        if os.path.exists(record):
            os.remove(record)
        os.makedirs(os.path.dirname(record), exist_ok=True)
        # Derived from the runner's own workdir, never hard-coded (H2): the
        # recorder is told where to write as the CONTAINER sees it, and the
        # import path points at the workspace THIS runner mounts.
        workdir = self.runner.workdir.rstrip("/")
        env = {"BENCH_RECORD_PATH": self.runner.in_container(_hz.RECORD_REL),
               "PYTHONDONTWRITEBYTECODE": "1",
               "PYTHONPATH": f"{workdir}/src"}
        if coverage:
            env["BENCH_COVERAGE"] = "1"
        # Outside the bind mount on purpose (`_bench/` is a substrate root);
        # the shared counter distinguishes concurrent executions in one
        # process whichever stack they belong to.
        pid_file = (f"/tmp/r2t-behave-{os.getpid()}-"
                    f"{next(_hz._EXEC_SEQ)}.pid")
        started = time.time()
        timed_out = False
        cleanup = None
        try:
            # NO --strict: behave 1.3.3 has no such flag (probed live — it
            # exits 2 "unrecognized arguments", which would wear
            # container_error's face on every item).  The exit-code witness
            # rests on 1.3.3's DEFAULT: an all-undefined feature exits 1.
            # The selftest pins these invocation bytes; the S4 gate pins the
            # default live, in the image the sweeps run.
            cp = self.runner.run(
                f"printf '%s' $$ > {shlex.quote(pid_file)} && "
                f"exec behave --no-color {FEATURE_REL}",
                env=env, timeout=timeout)
            code, out = cp.returncode, (cp.stdout or "") + (cp.stderr or "")
        except subprocess.TimeoutExpired as e:
            timed_out = True
            # `docker exec` without a TTY does not forward the kill into the
            # container; the shared tree-killer walks the recorded pid's
            # whole subtree and reports whether anything survived.
            cleanup = _hz._kill_process_tree(self.runner, pid_file)
            code = -1
            out = (e.stdout or b"").decode("utf-8", "replace") if isinstance(
                e.stdout, bytes) else (e.stdout or "")
        wall = time.time() - started
        if not timed_out:
            self.runner.run(f"rm -f {shlex.quote(pid_file)}", timeout=60)

        records = []
        if os.path.isfile(record):
            with open(record, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
        return _hz.RunResult(exit_code=code, stdout=out, wall_seconds=wall,
                             records=records, timed_out=timed_out,
                             expected_line=expected_line,
                             timeout_cleanup=cleanup,
                             expected_lines=expected_lines,
                             # This stack's environment-failure vocabulary;
                             # None would mean Symfony's (`_DI_MARKERS`).
                             error_markers=BEHAVE_ERROR_MARKERS)

    # ------------------------------------------------------------- driver
    def run_solution(self, feature, scenario, solution: _hz.Solution,
                     coverage: bool = False, timeout: int = 600,
                     repeats: int = 1, task: str = "criterion_to_test",
                     keep_stdout: bool = False) -> dict:
        # Integrity at the execution boundary, before AND after — the same
        # two checks, for the same reasons, as the PHP harness: before,
        # raise, because a tree already wrong makes nothing attributable;
        # after, REPORT, because raising would discard the evidence of what
        # the submission did, and `runner._record` turns the report into
        # `substrate_violation` so the row can never read as a pass.
        self.verify_substrate()
        _repo.clean_workspace(self.man, self.boundary)
        self._remove_run_files()
        written, rejected = self.install_solution(solution, task=task)
        if solution.services_fragment:
            # behave has no wiring channel (`wiring_channel: null` in the
            # profile), so a `behat_services.yml` in a solution is a file
            # aimed at another framework.  Recorded as a rejection — the
            # same route a refused file takes — rather than silently
            # dropped: a solution author debugging "why is my context not
            # wired" deserves the answer on the row.
            rejected = rejected + [{"file_path": _hz.SERVICES_FRAGMENT_NAME,
                                    "why": "no_wiring_channel:behave"}]
        py_written = [p for p in written if p.endswith(".py")]
        index = self.index_paths(py_written)
        produced_feature = None
        if task == "requirement_to_test":
            produced_feature = next(
                (f.code for f in solution.files
                 if f.file_path.endswith(".feature")), None)
        _text, expected_line, expected_lines = self.write_feature(
            feature, scenario, override=produced_feature)

        runs = [self.execute(coverage=coverage, timeout=timeout,
                             expected_line=expected_line,
                             expected_lines=expected_lines)
                for _ in range(max(1, repeats))]

        after = _repo.verify_substrate(self.man, self.boundary,
                                       expected=self.expected_mutations)
        violation = None
        if after["baseline"] and (after["changed"] or after["missing"]
                                  or after["added"]):
            violation = {k: after[k][:8]
                         for k in ("changed", "missing", "added")}
        # The module import names behave will load — this stack's honest
        # reading of "registered contexts", the same reading `closure_py`
        # gives `context_classes`.  behave loads top-level modules of the
        # steps directory, so the name is the basename.
        modules = sorted({os.path.splitext(os.path.basename(p))[0]
                          for p in py_written})
        return {
            "substrate_violation": violation,
            "written_files": written,
            "rejected_files": rejected,
            "feature_from_solution": produced_feature is not None,
            "index_errors": index.get("errors") or {},
            "registered_contexts": modules,
            "runs": [r.to_json(keep_stdout=keep_stdout) for r in runs],
            "outcomes": [r.outcome for r in runs],
        }


# ------------------------------------------------------------------ strip
def strip_repo_behave(boundary, gold_root: str, harness_py_dir=None,
                      dry_run: bool = False) -> _repo.StripManifest:
    """Move the answer out of a behave CLONE and install the harness's files.

    The behave arm of `repo.strip_repo`, sharing its mechanics
    (`_iter_files`/`_move`/`_prune_empty_dirs`, classify-every-file,
    `sanitise_repo` for the `.git` copy of the answer) and differing in
    exactly what the stacks differ in: the manifest records the BEHAVE
    substrate/bytecode roots, and the two installed files are the recorder
    and the syntax gate rather than a services graph.

    The recorder swap is the one move CoreShop has no analogue for: the
    project's own `features/environment.py` (twelve lines, creates
    `features/_scratch/`) goes to gold and `r2t/py/bench_environment.py`
    takes its place — which reproduces the scratch-dir behaviour, because
    the frozen profile prompt promises it to the agent.
    """
    repo_root = os.path.abspath(boundary.repo_root)
    # Every checkout `config/corpora.yml` declares, by prefix.  The pinned
    # corpora are the S0 gate's ground truth — python-docx at `e454546` must
    # re-derive its 306 items byte-identically — and
    # `boundary_python_docx.yml`'s default `repo_root` points INTO one of
    # them, so "strip with the default flags" must be a refusal rather than a
    # corpus-destroying default.
    for protected in _repo.declared_corpus_roots():
        if repo_root == protected \
                or repo_root.startswith(protected + os.sep):
            raise SystemExit(
                f"REFUSED: {repo_root} is inside the pinned corpus tree "
                f"({protected}). The corpora are the S0 gate's ground "
                f"truth — python-docx at e454546 must re-derive its "
                f"items byte-identically — and the boundary config's "
                f"default repo_root points here precisely so that "
                f"extraction reads the pinned bytes. Strip a CLONE: "
                f"pass --repo at a copy.")
    if not (os.path.isdir(os.path.join(repo_root, "features", "steps"))
            and os.path.isfile(os.path.join(repo_root, ENVIRONMENT_REL))):
        raise SystemExit(
            f"REFUSED: {repo_root} does not look like a behave project "
            f"(no features/steps/ directory or no features/environment.py).")
    harness_py_dir = harness_py_dir or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "py")

    man = _repo.StripManifest(
        repo_root=repo_root, gold_root=os.path.abspath(gold_root),
        boundary_version=boundary.version,
        # Recorded, not defaulted: an empty roots list on this manifest
        # would mean CoreShop's roots, i.e. a substrate check walking
        # `vendor/behat` in a python checkout and verifying a tree it never
        # looked at.  `BehaveHarness.__init__` refuses a manifest whose
        # bytecode_roots are empty for the same reason from the other side.
        substrate_roots=list(_repo.BEHAVE_SUBSTRATE_ROOTS),
        substrate_volatile=sorted(_repo.BEHAVE_SUBSTRATE_VOLATILE),
        bytecode_roots=list(_repo.BEHAVE_BYTECODE_ROOTS))

    config_prefixes = set(boundary.removable_config)
    seen: set = set()
    for prefix, _ in boundary.removable:
        for rel in _repo._iter_files(repo_root, prefix):
            if rel in seen or boundary.classify(rel) != _REMOVABLE:
                continue
            seen.add(rel)
            (man.moved_config if any(rel.startswith(c.rstrip("/"))
                                     for c in config_prefixes)
             else man.moved).append(rel)

    if dry_run:
        return man

    for rel in man.moved + man.moved_config:
        _repo._move(repo_root, man.gold_root, rel)
    for prefix, _ in boundary.removable:
        _repo._prune_empty_dirs(repo_root, prefix)

    # The harness's two files.  Both are hashed into the baseline the moment
    # `manifest-baseline` runs, so a solution that rewrites either is a
    # tampering abort, not a quiet re-scoring.
    bench = os.path.join(repo_root, _repo.BENCH_DIR)
    os.makedirs(bench, exist_ok=True)
    shutil.copyfile(os.path.join(harness_py_dir, "compile_check.py"),
                    os.path.join(repo_root, COMPILE_CHECK_REL))
    man.installed.append(COMPILE_CHECK_REL)

    # The recorder swap: original to gold (auditable, reversible), recorder
    # in its place.  Recorded under moved_config — it is lifecycle plumbing,
    # not part of any item's closure — and under installed, because the file
    # now at that path is the harness's.
    _repo._move(repo_root, man.gold_root, ENVIRONMENT_REL)
    man.moved_config.append(ENVIRONMENT_REL)
    shutil.copyfile(os.path.join(harness_py_dir, "bench_environment.py"),
                    os.path.join(repo_root, ENVIRONMENT_REL))
    man.installed.append(ENVIRONMENT_REL)

    # The answer's other copies: `.git` (every removed file at HEAD) moves to
    # gold; bytecode compiled from the moved code is purged.  Shared code,
    # shared reasons — see `repo.sanitise_repo`.
    man.installed += _repo.sanitise_repo(repo_root, man.gold_root,
                                         man.bytecode_roots)
    man.save(os.path.join(man.gold_root, "strip_manifest.json"))
    return man


# ------------------------------------------------------- CLI construction
def make_harness(args):
    """`(harness, boundary, manifest)` for `framework: behave` — the branch
    `cli._harness` dispatches to.

    Mirrors the behat body's resolution rule (one `--repo`, setting both the
    classification root and the write root) and adds two refusals the PHP
    path cannot need: the manifest must be a behave strip's own (see the
    constructor), and the workdir must be explicit — `/var/www/html` is both
    argparse's default and the CoreShop convention, so its presence here
    means "nobody said where this worker mounts", and executing against a
    guessed mount point is the H2 failure (every item `no_scenario_ran` off
    an empty record file).
    """
    from ..core.boundary import load_boundary
    b = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    manifest_path = os.path.join(args.gold, "strip_manifest.json")
    if not os.path.isfile(manifest_path):
        raise SystemExit(
            f"REFUSED: no strip manifest at {manifest_path}. Strip a clone "
            f"first (`r2t strip --profile config/profile_python_docx.yml "
            f"--repo <clone> --gold <gold>`), and point --gold at THAT gold "
            f"tree — the default --gold is CoreShop's.")
    man = _repo.load_manifest(manifest_path)
    man.repo_root = os.path.abspath(b.repo_root)
    man.gold_root = os.path.abspath(args.gold)
    if not os.path.isdir(man.repo_root):
        raise SystemExit(f"REFUSED: no such workspace: {man.repo_root}")
    workdir = getattr(args, "workdir", None)
    if workdir in (None, "/var/www/html"):
        raise SystemExit(
            "REFUSED: no workdir for a behave worker. `/var/www/html` is "
            "argparse's default and the CoreShop mount convention, so it "
            "cannot mean 'this behave container'; pass --worker FILE from "
            "`r2t worker plan` (which sets --repo, --container and "
            "--workdir together), or an explicit --workdir — the docx "
            "image mounts the workspace at /work.")
    runner = _hz.DockerRunner(args.container, workdir=workdir)
    return BehaveHarness(man, b, runner), b, man


def cmd_strip(args) -> int:
    """`r2t strip --profile config/profile_python_docx.yml --repo <clone>
    --gold <gold>` — the behave arm, reached through `cli._other_stack`."""
    from ..core.boundary import load_boundary
    gold_abs = os.path.abspath(args.gold)
    for protected_path in PROTECTED_GOLD:
        # A data-root default can only be materialized (or violated) under a
        # configured data root; the archived absolute entries always apply.
        if not isinstance(protected_path, str) \
                and not os.environ.get(DATA_ROOT_ENV):
            continue
        protected = os.path.abspath(protected_path)
        if gold_abs == protected \
                or gold_abs.startswith(protected + os.sep):
            raise SystemExit(
                f"REFUSED: --gold {args.gold} is inside {protected}, the "
                f"CoreShop data root. A behave strip manifest written "
                f"there would replace CoreShop's integrity baseline, "
                f"and every CoreShop worker would abort its next item as "
                f"tampered. Pass a gold tree of this project's own.")
    b = load_boundary(args.boundary, repo_root=getattr(args, "repo", None))
    man = strip_repo_behave(b, args.gold, dry_run=args.dry_run)
    print(f"{'would move' if args.dry_run else 'moved'} {len(man.moved)} "
          f"test-code files and {len(man.moved_config)} lifecycle/config "
          f"files -> {args.gold}")
    if not args.dry_run:
        print(f"installed: {man.installed}")
    return 0


# ----------------------------------------------------- module-level seams
#
# The `StackRunner` names, so `stacks.verb(stack, "strip")` and the protocol
# check find them.  `install_solution` and `execute` are the unbound methods,
# exactly as `behat.py` exposes its harness's.

strip = strip_repo_behave
install_solution = BehaveHarness.install_solution
execute = BehaveHarness.execute


#: Every re-exported member, and the dotted path of the object it must BE.
#: Walked with `is` by `closure_py.selftest` — a member that starts WRAPPING
#: something instead of re-exporting it fails that walk.
MEMBERS: dict[str, str] = {
    "extract_closure": "r2t.toolkit.closure_py.load_extractor",
    "integrity_baseline": "r2t.bench.repo.baseline_substrate",
    "cmd_index": "r2t.toolkit.pystep_index.cmd_index",
    "cmd_closures": "r2t.toolkit.closure_py.cmd_closures",
    "cmd_interfaces": "r2t.toolkit.interfaces_py.cmd_interfaces",
    "build_index": "r2t.py.analyze_py.build_index",
    "run_matcher": "r2t.toolkit.pystep_index.run_matcher",
    "crosscheck": "r2t.toolkit.pystep_index.crosscheck",
    "item_steps": "r2t.toolkit.pystep_index.item_steps",
    "effective_steps": "r2t.toolkit.pystep_index.effective_steps",
    "examples_rows": "r2t.toolkit.pystep_index.examples_rows",
    # the shared execution plumbing (S4) — reused by identity, never copied
    "DockerRunner": "r2t.bench.harness.DockerRunner",
    "Solution": "r2t.bench.harness.Solution",
    "RunResult": "r2t.bench.harness.RunResult",
    "record_outcome": "r2t.bench.harness.record_outcome",
    "fold_scenario_records": "r2t.bench.harness.fold_scenario_records",
    "gold_solution": "r2t.bench.harness.gold_solution",
    "verify_substrate": "r2t.bench.repo.verify_substrate",
    "clean_workspace": "r2t.bench.repo.clean_workspace",
    "record_rel": "r2t.bench.harness.RECORD_REL",
    # the acceptance rule is the SAME function on both stacks' harnesses
    "install_solution": "r2t.bench.harness.Harness.install_solution",
}

#: What this module defines ITSELF — the execution half S4 wrote, as opposed
#: to the façade half above.  `closure_py.selftest` compares the module's
#: own callables against exactly this tuple, so a helper that creeps in
#: without being declared here fails a check rather than accreting silently.
#: (S5 appends its names when it lands its half.)
OWN_MEMBERS: tuple[str, ...] = (
    "BehaveHarness", "cmd_strip", "execute", "make_harness", "selftest",
    "strip", "strip_repo_behave")

#: The seams that have NOT landed, and which milestone lands each.  Read by
#: `closure_py.selftest`, which asserts each one is genuinely ABSENT: "not
#: implemented yet" is then a checked claim rather than an absence nobody
#: notices, and a stub that returned something would let a sweep run.
PENDING: dict[str, str] = {
    "stub_solution": "S5 (vacuity)",
    "mutant_population": "S5 (vacuity)",
}

# `boundary.REMOVABLE` under the name the strip walk uses; imported late to
# keep the top of the file about the seams rather than the plumbing.
from ..core.boundary import REMOVABLE as _REMOVABLE  # noqa: E402


# ----------------------------------------------------------------- selftest
def selftest() -> int:
    """The execution half, checked without a container.

    What CAN drift silently is checked here: the recorder's status mapping
    against behave 1.3.3's full probed vocabulary, the record shape against
    the schema constants, the invocation bytes (no `--strict`, env derived
    from the runner's workdir), the reuse-by-identity table, the fail-leg
    construction, and every refusal.  What NEEDS the framework — the exit-1
    default, base-dir discovery, per-row records — is pinned by the S4 gate
    against the real behave in the real image, and the constants it rests on
    are pinned here so a drive-by edit fails a named check first.
    """
    import argparse
    import ast
    import tempfile

    from ..bench import cli as _cli
    from ..bench import runner as _runner
    from ..core.boundary import Boundary, load_boundary
    from ..core.gherkin import parse_feature_file
    from ..py import bench_environment as _rec
    from . import base as _base

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    here = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))

    # ------------------------------------------------ the recorder's purity
    #
    # Stdlib-only at import is what lets THIS selftest drive it: a top-level
    # `import behave` (or `coverage`) would make the recorder untestable
    # anywhere but inside the image, i.e. checked by nothing that runs on
    # every commit.
    rec_path = os.path.join(here, "r2t", "py", "bench_environment.py")
    with open(rec_path, encoding="utf-8") as fh:
        rec_src = fh.read()
    top_imports = {n.name.split(".")[0]
                   for node in ast.parse(rec_src).body
                   if isinstance(node, (ast.Import, ast.ImportFrom))
                   for n in (node.names if isinstance(node, ast.Import)
                             else [ast.alias(name=node.module or "")])}
    check("the recorder imports only stdlib at module level -- behave and "
          "coverage stay lazy, so these checks can run it",
          top_imports <= {"json", "os", "sys", "time", "annotations",
                          "__future__"},
          str(sorted(top_imports)))

    # --------------------------------------------------- the status mapping
    #
    # The FULL Status vocabulary of behave 1.3.3, probed live in
    # r2t_docx_img:base (python -c "from behave.model_core import Status;
    # print([s.name for s in Status])").  If a behave upgrade adds a name,
    # the recorder records it as failed-with-exception (fail-closed) and the
    # gate's live run is where the new name gets a deliberate mapping.
    probed = ("unknown", "untested", "executing", "skipped", "passed",
              "xfailed", "xpassed", "failed", "error", "hook_error",
              "cleanup_error", "undefined", "pending", "pending_warn",
              "untested_pending", "untested_undefined")
    results = {name: _rec.map_status(name) for name in probed}
    check("every probed behave status maps into the five-value vocabulary",
          all(r in _base.STEP_RESULTS for r, _e in results.values()),
          str({n: r for n, (r, _e) in results.items()
               if r not in _base.STEP_RESULTS}))
    check("untested means skipped -- behave's 'never reached' is the "
          "schema's skipped, the mapping the plan pins",
          results["untested"][0] == "skipped"
          and results["skipped"][0] == "skipped")
    check("a raised step is failed whichever of behave's three error "
          "statuses it wears",
          {results[n][0] for n in ("error", "hook_error", "cleanup_error",
                                   "failed")} == {"failed"})
    check("undefined stays undefined -- the fail leg's whole vocabulary",
          results["undefined"][0] == "undefined"
          and results["untested_undefined"][0] == "undefined")
    check("a status outside the map is failed WITH a synthetic exception, "
          "never a quiet default",
          results["xpassed"][0] == "failed"
          and results["xpassed"][1] is not None
          and "UnmappedStatus" in results["xpassed"][1]["class"]
          and results["unknown"][0] == "failed")
    check("behave's own pending family maps to the schema's pending",
          {results[n][0] for n in ("pending", "pending_warn",
                                   "untested_pending")} == {"pending"})

    # ----------------------------------------------------- the record shape
    class _O:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    def step(status, **kw):
        base_kw = dict(line=7, keyword="Given", name="a font", status=status,
                       duration=0.01, exception=None, error_message=None)
        base_kw.update(kw)
        return _O(**base_kw)

    feature = _O(name="F")
    scen = _O(filename="features/_bench_item.feature", feature=feature,
              name="Rows -- @1.2", line=19, status="failed")
    steps = [step("passed"),
             step("failed", exception=AssertionError("v was 2")),
             step("untested")]
    doc = _rec.build_record(scen, steps, 0.123, None, None)
    check("the Python record carries common fields plus its collector identity",
          set(doc) == set(_base.RECORD_FIELDS) | {"direct_calls_schema"},
          str(sorted(doc)))
    check("each step's keys are exactly STEP_FIELDS",
          all(set(s) == set(_base.STEP_FIELDS) for s in doc["steps"]))
    check("scenario_line is the line behave stamped -- for an outline row, "
          "the DATA ROW's own (probed live)", doc["scenario_line"] == 19)
    check("the failed step carries its exception class and message",
          doc["steps"][1]["exception"] == {"class": "AssertionError",
                                           "message": "v was 2"},
          str(doc["steps"][1]["exception"]))
    check("the recorder's own verdict uses the two-value vocabulary and "
          "the run's verdict never comes from it",
          doc["scenario_result"] in _base.SCENARIO_RESULTS
          and doc["scenario_result"] == "not-passed")
    check("coverage is null when not requested -- readers distinguish "
          "'not measured' from 'measured, empty' by exactly this",
          doc["coverage"] is None)
    check("the folded outcome of that record is failed, through the SHARED "
          "record_outcome",
          record_outcome(doc) == "failed")
    green = _rec.build_record(_O(filename="f", feature=feature, name="s",
                                 line=6, status=_O(name="passed")),
                              [step("passed")], 0.1,
                              {"files": {}, "units": []}, [])
    check("a passing scenario's record folds to passed and an empty "
          "measured coverage block survives as a dict, not null",
          record_outcome(green) == "passed" and green["coverage"] == {
              "files": {}, "units": []})
    check("direct_calls carries the same distinction: null where the hook "
          "was not installed, `[]` where it ran and the scenario called no "
          "production method",
          doc["direct_calls"] is None and green["direct_calls"] == [])
    undef = _rec.build_record(scen, [step("undefined"), step("undefined")],
                              0.1, None, None)
    check("an all-undefined record folds to undefined_steps -- the fail "
          "leg's label, via the shared fold",
          record_outcome(undef) == "undefined_steps")

    # ------------------------------------------------ coverage restriction
    cov = _rec.coverage_doc({"/w/src/docx/api.py": [3, 1],
                             "/w/features/steps/mine.py": [2],
                             "/w/src/docx/empty.py": []}, "/w")
    check("coverage keeps only src/ files -- the second fence against "
          "instrument-crediting, applied to the collected paths",
          cov["files"] == {"src/docx/api.py": 2}
          and cov["units"] == ["src/docx/api.py::L1", "src/docx/api.py::L3"],
          str(cov))

    # --------------------------------------------- reuse is BY IDENTITY
    check("install_solution IS the PHP harness's -- one acceptance rule, "
          "not two that can disagree",
          BehaveHarness.install_solution is _hz.Harness.install_solution)
    check("verify_substrate and purge_bytecode are the same functions too",
          BehaveHarness.verify_substrate is _hz.Harness.verify_substrate
          and BehaveHarness.purge_bytecode is _hz.Harness.purge_bytecode
          and BehaveHarness._abs is _hz.Harness._abs)
    check("the record path is the SAME constant the volatile exemption "
          "names", record_rel is _hz.RECORD_REL
          and record_rel in _repo.BEHAVE_SUBSTRATE_VOLATILE)
    check("the synthesised feature sits under NO substrate root, so writing "
          "it per item cannot trip the baseline",
          not any(FEATURE_REL == r or FEATURE_REL.startswith(r + "/")
                  for r in _repo.BEHAVE_SUBSTRATE_ROOTS))
    check("the syntax gate lives inside _bench, so its hash is in the "
          "baseline the moment one is taken",
          COMPILE_CHECK_REL.startswith(_repo.BENCH_DIR + "/"))

    # ------------------------------------------------- a mini workspace
    class _FakeRunner(_hz.DockerRunner):
        """Records what it was asked; answers the syntax gate with JSON."""

        def __init__(self, workdir="/work", raise_timeout=False,
                     compile_doc=None):
            super().__init__("fake", workdir=workdir, docker_group=False)
            self.calls: list = []
            self.raise_timeout = raise_timeout
            self.compile_doc = compile_doc if compile_doc is not None else {
                "root": workdir, "files": {}, "errors": {}}

        def run(self, inner, env=None, timeout=900):
            _hz._docker_exec_env_args(env)
            self.calls.append((inner, dict(env or {})))
            if "compile_check.py" in inner:
                return subprocess.CompletedProcess(
                    [], 0, json.dumps(self.compile_doc), "")
            if self.raise_timeout and "exec behave" in inner:
                self.raise_timeout = False
                raise subprocess.TimeoutExpired("behave", timeout,
                                                output="tail")
            return subprocess.CompletedProcess([], 0, "killed\n", "")

    with tempfile.TemporaryDirectory() as root:
        def write(rel, text="x"):
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text)

        write("src/docx/__init__.py", "VERSION = 1\n")
        write("features/environment.py", "# recorder stand-in\n")
        write("features/steps/test_files/doc-default.docx", "PK")
        write("features/steps/leftover.py", "# previous item\n")
        write("features/f.feature",
              "Feature: F\n\n  Scenario: S\n    Given a font\n")
        write("pyproject.toml", "[project]\n")
        b = load_boundary(os.path.join(here, "config",
                                       "boundary_python_docx.yml"),
                          repo_root=root)
        man = _repo.StripManifest(
            repo_root=root, gold_root=os.path.join(root, "_gold"),
            substrate_roots=list(_repo.BEHAVE_SUBSTRATE_ROOTS),
            substrate_volatile=sorted(_repo.BEHAVE_SUBSTRATE_VOLATILE),
            bytecode_roots=list(_repo.BEHAVE_BYTECODE_ROOTS))

        # -- constructor refusals
        try:
            BehaveHarness(_repo.StripManifest(repo_root=root,
                                              gold_root=root), b,
                          _FakeRunner())
            check("a manifest with no bytecode roots is refused -- it is "
                  "another stack's, and running under it aborts item 2",
                  False, "constructed anyway")
        except ValueError as e:
            check("a manifest with no bytecode roots is refused -- it is "
                  "another stack's, and running under it aborts item 2",
                  "bytecode_roots" in str(e))
        other = load_boundary(os.path.join(here, "config",
                                           "boundary_python_docx.yml"),
                              repo_root=os.path.join(root, "elsewhere"))
        try:
            BehaveHarness(man, other, _FakeRunner())
            check("a harness whose boundary and manifest disagree is "
                  "refused (H1)", False, "constructed anyway")
        except ValueError:
            check("a harness whose boundary and manifest disagree is "
                  "refused (H1)", True)

        h = BehaveHarness(man, b, _FakeRunner())

        # -- the fail leg is clean BY CONSTRUCTION: sweeping removable
        #    territory leaves `features/steps/` existing (the test_files
        #    carve-out), so behave finds an empty steps dir, every step is
        #    undefined, and 1.3.3's default exit is 1.
        _repo.clean_workspace(man, b)
        steps_dir = os.path.join(root, "features", "steps")
        check("after the sweep, features/steps/ still exists (test_files "
              "holds it open) and holds no .py -- the undefined-steps fail "
              "leg needs exactly this",
              os.path.isdir(steps_dir)
              and os.path.isfile(os.path.join(steps_dir, "test_files",
                                              "doc-default.docx"))
              and not any(f.endswith(".py")
                          for f in os.listdir(steps_dir)))

        # -- the invocation bytes
        r = _FakeRunner(workdir="/srv/w7")
        h2 = BehaveHarness(man, b, r)
        h2.execute(coverage=False, timeout=5)
        behave_call = [c for c in r.calls if "exec behave" in c[0]][0]
        check("the record path follows the worker's mount point (H2 twin)",
              behave_call[1]["BENCH_RECORD_PATH"]
              == f"/srv/w7/{_hz.RECORD_REL}",
              str(behave_call[1].get("BENCH_RECORD_PATH")))
        check("the import path is derived from the same workdir -- no "
              "editable install, no .pth hook",
              behave_call[1]["PYTHONPATH"] == "/srv/w7/src")
        check("bytecode suppression rides every exec, not only the image",
              behave_call[1]["PYTHONDONTWRITEBYTECODE"] == "1")
        check("NO --strict: behave 1.3.3 has no such flag (probed: exit 2, "
              "'unrecognized arguments') -- the exit witness is the "
              "exits-1-on-undefined DEFAULT, pinned live by the gate",
              "--strict" not in behave_call[0]
              and "exec behave" in behave_call[0]
              and "--no-color" in behave_call[0], behave_call[0][:120])
        check("the synthesised feature is what behave is pointed at",
              FEATURE_REL in behave_call[0])
        check("coverage mode adds the recorder's switch and keeps the "
              "record path",
              (lambda rr: (BehaveHarness(man, b, rr).execute(coverage=True,
                                                             timeout=5),
                           [c for c in rr.calls if "exec behave" in c[0]]
                           [0][1])[1])(_FakeRunner(workdir="/srv/w9"))
              .get("BENCH_COVERAGE") == "1")

        # -- the timeout kill is the SHARED tree-killer
        rt = _FakeRunner(raise_timeout=True)
        res = BehaveHarness(man, b, rt).execute(coverage=False, timeout=5)
        killer = rt.calls[-1][0]
        check("a timed-out behave is killed by the shared subtree walker, "
              "scoped to the recorded pid",
              res.timed_out and res.timeout_cleanup == "killed"
              and "/proc/" in killer and "pgrep" not in killer and "pkill -f" not in killer)
        check("the pid file lives outside the hashed substrate roots",
              "/tmp/r2t-behave-" in rt.calls[0][0]
              and _repo.BENCH_DIR not in killer)

        # -- this stack's error vocabulary, not Symfony's
        def stdout_run(text):
            return _hz.RunResult(exit_code=1, stdout=text, wall_seconds=0.1,
                                 records=[], expected_line=7,
                                 error_markers=BEHAVE_ERROR_MARKERS)

        check("a step-module import failure is a container_error in this "
              "stack's own vocabulary",
              stdout_run("ModuleNotFoundError: No module named 'helpers'"
                         ).outcome == "container_error")
        check("a recorder crash (HOOK-ERROR) is a container_error too -- "
              "an environment fault, charged to nobody's solution",
              stdout_run("HOOK-ERROR in before_all: RuntimeError: x"
                         ).outcome == "container_error")
        check("Symfony's DI vocabulary is NOT recognised here",
              stdout_run("Cannot autowire service").outcome
              == "no_scenario_ran")

        # -- write_feature: the outline fold's lines come from the file we
        #    write, through the SAME derivation the PHP harness uses.
        outline_src = ("Feature: F\n\n"
                       "  Scenario Outline: T\n"
                       "    Given a <x>\n\n"
                       "    Examples:\n"
                       "      | x |\n"
                       "      | a |\n"
                       "      | b |\n")
        f = parse_feature_file("mem.feature", outline_src)
        text, kw_line, lines = h.write_feature(f, f.scenarios[0])
        written_lines = text.split("\n")
        check("the synthesised feature landed at features/_bench_item"
              ".feature", os.path.isfile(os.path.join(root, FEATURE_REL)))
        check("expected_lines carries the keyword line plus every Examples "
              "DATA row of the written file",
              lines[0] == kw_line and len(lines) == 3
              and all(written_lines[i - 1].strip() in ("| a |", "| b |")
                      for i in lines[1:]), str(lines))

        # -- run_solution end to end (container faked), the keys the three
        #    consumers read, and the row runner._record builds from it.
        sol = Solution(files=[
            _hz.SourceFile("features/steps/mine.py",
                           "from behave import given\n"),
            _hz.SourceFile("src/docx/evil.py", "PATCHED = True\n")])
        result = h.run_solution(f, f.scenarios[0], sol, timeout=5)
        check("a production-path file is refused and the step module is "
              "written",
              result["written_files"] == ["features/steps/mine.py"]
              and any(r["why"].startswith("not_test_code")
                      for r in result["rejected_files"]),
              str(result["rejected_files"]))
        check("the result carries every key validate/runner/mutation_run "
              "read",
              {"substrate_violation", "written_files", "rejected_files",
               "feature_from_solution", "index_errors",
               "registered_contexts", "runs", "outcomes"} <= set(result))
        check("registered_contexts are the module import names behave will "
              "load -- the same reading closure_py gives context_classes",
              result["registered_contexts"] == ["mine"])
        rec_row = _runner._record("t/x.feature:3", {}, {"files": []}, 0.0,
                                  result)
        check("with no records and no marker, the row is no_scenario_ran "
              "(the fake container ran nothing)",
              rec_row["outcome"] == "no_scenario_ran", rec_row["outcome"])

        broken = BehaveHarness(man, b, _FakeRunner(compile_doc={
            "root": "/work", "files": {},
            "errors": {"features/steps/mine.py": "SyntaxError: bad"}}))
        result2 = broken.run_solution(f, f.scenarios[0], sol, timeout=5)
        rec_row2 = _runner._record("t/x.feature:3", {}, {"files": []}, 0.0,
                                   result2)
        check("a syntax-broken solution routes to parse_or_compile_error "
              "through the existing index_errors branch",
              rec_row2["outcome"] == "parse_or_compile_error",
              rec_row2["outcome"])

        frag = Solution(services_fragment={"my.ctx": {"class": "X"}})
        result3 = h.run_solution(f, f.scenarios[0], frag, timeout=5)
        check("a behat_services.yml aimed at this stack is recorded as "
              "rejected -- behave has no wiring channel",
              any(r.get("why") == "no_wiring_channel:behave"
                  for r in result3["rejected_files"]))

        # -- prepare/clear leave no per-item residue
        h.prepare_for_generation()
        check("prepare_for_generation sweeps the previous item's feature "
              "and record and leaves a verified tree",
              not os.path.exists(os.path.join(root, FEATURE_REL)))

    # ------------------------------------------------------------ the strip
    with tempfile.TemporaryDirectory() as root:
        def write(rel, text="x"):
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(text)

        write("features/steps/font.py", "from behave import given\n")
        write("features/steps/helpers.py", "def test_docx(n): pass\n")
        write("features/steps/test_files/doc-default.docx", "PK")
        write("features/environment.py", "ORIGINAL = True\n")
        write("features/f.feature", "Feature: F\n")
        write("src/docx/__init__.py", "VERSION = 1\n")
        write("pyproject.toml", "[project]\n")
        write(".git/HEAD", "ref: refs/heads/master\n")
        b = load_boundary(os.path.join(here, "config",
                                       "boundary_python_docx.yml"),
                          repo_root=root)
        gold = os.path.join(root, "_gold")

        dry = strip_repo_behave(b, gold, dry_run=True)
        check("dry run names the moves and makes none",
              sorted(dry.moved) == ["features/steps/font.py",
                                    "features/steps/helpers.py"]
              and os.path.isfile(os.path.join(root,
                                              "features/steps/font.py")))

        man = strip_repo_behave(b, gold)
        check("step modules moved to gold; the fixtures did not",
              not os.path.exists(os.path.join(root,
                                              "features/steps/font.py"))
              and os.path.isfile(os.path.join(gold,
                                              "features/steps/font.py"))
              and os.path.isfile(os.path.join(
                  root, "features/steps/test_files/doc-default.docx")))
        with open(os.path.join(root, ENVIRONMENT_REL),
                  encoding="utf-8") as fh:
            installed_env = fh.read()
        with open(rec_path, encoding="utf-8") as fh:
            recorder_bytes = fh.read()
        check("the recorder replaced environment.py BYTE-FOR-BYTE and the "
              "original moved to gold",
              installed_env == recorder_bytes
              and open(os.path.join(gold, ENVIRONMENT_REL),
                       encoding="utf-8").read() == "ORIGINAL = True\n")
        check("the syntax gate is installed under _bench",
              os.path.isfile(os.path.join(root, COMPILE_CHECK_REL))
              and COMPILE_CHECK_REL in man.installed)
        check("the manifest records the behave roots -- data, not the "
              "CoreShop fallback",
              man.roots() == _repo.BEHAVE_SUBSTRATE_ROOTS
              and man.bytecode_roots == list(_repo.BEHAVE_BYTECODE_ROOTS))
        check(".git moved to gold (the answer at HEAD) and the manifest "
              "saved OUTSIDE the repo",
              not os.path.isdir(os.path.join(root, ".git"))
              and os.path.isdir(os.path.join(gold, "_git"))
              and os.path.isfile(os.path.join(gold, "strip_manifest.json")))

        # -- make_harness refusals and construction
        ns = argparse.Namespace(
            boundary=os.path.join(here, "config",
                                  "boundary_python_docx.yml"),
            repo=root, gold=gold, container="c", workdir="/var/www/html")
        try:
            make_harness(ns)
            check("the CoreShop default workdir is refused -- a behave "
                  "worker's mount point must be said, not guessed",
                  False, "accepted")
        except SystemExit as e:
            check("the CoreShop default workdir is refused -- a behave "
                  "worker's mount point must be said, not guessed",
                  "workdir" in str(e))
        ns.workdir = "/work"
        h3, b3, man3 = make_harness(ns)
        check("an explicit workdir yields a harness pointed at one "
              "workspace",
              isinstance(h3, BehaveHarness) and h3.root == root
              and h3.runner.workdir == "/work")
        try:
            make_harness(argparse.Namespace(
                boundary=ns.boundary, repo=root,
                gold=os.path.join(root, "nowhere"), container="c",
                workdir="/work"))
            check("a missing strip manifest is refused with the strip "
                  "command named", False, "accepted")
        except SystemExit as e:
            check("a missing strip manifest is refused with the strip "
                  "command named", "strip" in str(e))

    # -- no corpus can be stripped: the guard fires on the PREFIX, before
    #    any tree is touched or even required to exist, and it covers every
    #    checkout `corpora.yml` declares rather than a hand-kept subset.
    saved_data_root = os.environ.get(DATA_ROOT_ENV)
    try:
        with tempfile.TemporaryDirectory() as fixture_data_root:
            os.environ[DATA_ROOT_ENV] = fixture_data_root

            def strip_refusal(root):
                b = Boundary(version=1, project="python-docx", repo_root=root,
                             removable=[("features/steps/", "")], retained=[])
                try:
                    strip_repo_behave(b, os.path.join(fixture_data_root,
                                                      "gold"))
                    return "accepted"
                except SystemExit as e:
                    return str(e)

            from r2t.toolkit.extract import corpus_entries
            declared = _repo.declared_corpus_roots()
            names = [e["name"] for e in corpus_entries()]
            check("the guard reads corpora.yml: every declared checkout is "
                  "covered, the algorand step definitions included",
                  len(declared) == len(names) + 1
                  and all(os.path.join(fixture_data_root, "projects", n,
                                       "source") in declared for n in names)
                  and os.path.join(fixture_data_root, "projects",
                                   "algorand-java-sdk", "source") in declared,
                  str(declared))
            # The three the hand-kept literal named, unchanged, plus the two
            # it did not: a python corpus is only accidentally the shape this
            # arm strips, and epubcheck's tree is as pinned as docx's.
            for project in ("python-docx", "python-pptx", "algorand-sdk",
                            "epubcheck", "coreshop"):
                refusal = strip_refusal(os.path.join(
                    fixture_data_root, "projects", project, "source"))
                check(f"stripping inside the pinned {project} tree is "
                      f"refused by prefix, before anything is touched",
                      "pinned corpus" in refusal, refusal)
            check("...and a file inside one is refused too, by the same "
                  "prefix", "pinned corpus" in strip_refusal(os.path.join(
                      fixture_data_root, "projects", "python-docx", "source",
                      "features", "steps")))
            check("a clone outside every declared corpus is not refused "
                  "here -- it reaches the shape check, which is what stops "
                  "a non-behave tree",
                  "does not look like a behave project" in strip_refusal(
                      os.path.join(fixture_data_root, "clone")))
            check("...and nothing was created on the way to either answer",
                  os.listdir(fixture_data_root) == [],
                  str(os.listdir(fixture_data_root)))
    finally:
        if saved_data_root is None:
            os.environ.pop(DATA_ROOT_ENV, None)
        else:
            os.environ[DATA_ROOT_ENV] = saved_data_root
    from ..bench.cli import DEFAULT_GOLD as _DEFAULT_GOLD
    check("the active portable CoreShop gold default is protected from a "
          "behave strip",
          any(_DEFAULT_GOLD == protected for protected in PROTECTED_GOLD))

    # ------------------------------------------------------- CLI dispatch
    profile = os.path.join(here, "config", "profile_python_docx.yml")
    if os.path.isfile(profile):
        # Compared against the CANONICALLY imported module's attributes, not
        # this file's globals: under `python -m r2t.stacks.behave` this code
        # runs as `__main__` while the dispatcher imports `r2t.stacks.behave`
        # fresh, and the two hold distinct (equal-bytes) function objects.
        from . import behave as _canonical
        ns = argparse.Namespace(profile=profile)
        check("the docx profile routes make_harness and cmd_strip to THIS "
              "stack -- read out of the file, digests and all",
              _cli._other_stack(ns, "make_harness")
              is _canonical.make_harness
              and _cli._other_stack(ns, "cmd_strip")
              is _canonical.cmd_strip)
    else:
        print(f"  [SKIP] no {profile}, so the real dispatch could not be "
              f"resolved")
    check("no profile still means behat for both -- every CoreShop "
          "invocation unchanged",
          _cli._other_stack(argparse.Namespace(), "make_harness") is None
          and _cli._other_stack(argparse.Namespace(profile=None),
                                "cmd_strip") is None)

    print("\n" + ("ALL PASS (stacks.behave)" if ok
                  else "FAILURES (stacks.behave)"))
    return 0 if ok else 1



# =========================================================== S5 (vacuity) ===
#
# The two anti-vacuity seams, appended rather than written into the tables
# above.  S4 lands its four in the same file in the same round; a dict
# UPDATE touches no line either milestone owns, so the two merge without a
# conflict and neither can silently drop the other's entry.  Everything else
# in this section is a re-export, exactly as the rest of the module is.

from ..toolkit import mutation_py as _mutation_py                    # noqa: E402
from ..toolkit import stub_py as _stub_py                            # noqa: E402

#: Seam 6 — the anti-vacuity control: a submission whose steps are
#: syntactically valid and semantically empty.  One module per item under
#: `features/steps/`, keyed on (effective keyword, text) because behave
#: matches per keyword.
stub_solution = _stub_py.stub_solution

#: ...and the adapter the sweep drives it through, dispatched from
#: `fixtures._stub_maker`.  A PHP context class installed into a
#: behave workspace defines nothing, so the floor would read 0.00 for the
#: wrong reason; that is why the fixture is per-stack at all.
make_stub_adapter = _stub_py.make_stub_adapter

#: Seam 7 — the mutant manifest this stack's engine defines, digest and all.
#: `r2t-mutate-py` over the same `mutation.build_manifest` the PHP engine
#: uses, with the python engine's identity and keep root supplied.
mutant_population = _mutation_py.build_population

#: The two remaining PHP-bound CLI verbs, reached from `cli.cmd_mutants` and
#: `cli.cmd_stub_accept` through `cli._other_stack`.  With `cmd_index` and
#: `cmd_closures` above, that is all four.
cmd_mutants = _mutation_py.cmd_mutants
cmd_stub_accept = _stub_py.cmd_stub_accept

#: The mutation engine, under the names `stacks.base.ENGINE_MEMBERS` gives it
#: on every stack.  `r2t-mutate-py` and its version are inside every mutant id
#: this stack mints, so they are identity and not a label, and the exclusion
#: policy is what that population is defined over.
engine = _mutation_py.ENGINE
engine_version = _mutation_py.ENGINE_VERSION
excluded_prefixes = _mutation_py.EXCLUDED_PREFIXES

#: Where the enumerator/applier program lives, and how it is staged into a
#: workspace: `mutation_run.run_slice(..., engine_dir=..., applier=...)`.
#: `var/`, never `_bench/` — see `mutation_py.applier`.
engine_dir = _mutation_py.PY_ENGINE_DIR
applier = _mutation_py.applier

MEMBERS.update({
    "stub_solution": "r2t.toolkit.stub_py.stub_solution",
    "make_stub_adapter": "r2t.toolkit.stub_py.make_stub_adapter",
    "stripped_solution": "r2t.toolkit.strip_py.stripped_solution",
    "make_strip_adapter": "r2t.toolkit.strip_py.make_strip_adapter",
    "mutant_population": "r2t.toolkit.mutation_py.build_population",
    "cmd_mutants": "r2t.toolkit.mutation_py.cmd_mutants",
    "cmd_stub_accept": "r2t.toolkit.stub_py.cmd_stub_accept",
    "engine": "r2t.toolkit.mutation_py.ENGINE",
    "engine_version": "r2t.toolkit.mutation_py.ENGINE_VERSION",
    "excluded_prefixes": "r2t.toolkit.mutation_py.EXCLUDED_PREFIXES",
    "engine_dir": "r2t.toolkit.mutation_py.PY_ENGINE_DIR",
    "applier": "r2t.toolkit.mutation_py.applier",
})
for _landed in ("stub_solution", "mutant_population"):
    PENDING.pop(_landed, None)
del _landed

if __name__ == "__main__":
    raise SystemExit(selftest())
