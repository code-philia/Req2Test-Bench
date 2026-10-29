"""Mutation execution for passing instances, restricted to their GT kill sets.

For each instance whose prediction passed, the candidate test runs only on
G_i: the pool pairs the ground-truth test killed (`gold_outcome == killed` in
the kit's `mutation/pools.jsonl.zst`) minus the kit's
`reference_excluded.jsonl`, minus the pairs of the engine's reviewed
nondeterministic mutants (`req2test.score`).  Running only G_i
gives the same recall and KillComplete as running the whole pool (harness
plan, decision 4).

Ground-truth predictions (`req2test validate`) run as gold runs, under the
rules gold always ran under: their execution rows carry `metadata.source`
`gold` (`req2test.execute`), and their mutation baselines and slices here
are gold runs as well (the baseline adapter's `gold_run`, the slices' gold
side).

The bridge drives the engine's `r2t.bench.mutation_run.run_slice` directly:
mutants are applied by the engine's applier for the manifest's engine, each
pair executes the candidate's own bytes (the `produced_files` of its
`exec.jsonl` row), and the engine retries an infrastructure outcome once.
Pairs are spread over the environment's K workers by mutant (one thread per
worker; a mutant's pairs stay together so it is applied once).

Before its pairs, each passing instance's test runs once unmutated on the
mutation workers (the mutation baseline).  A baseline that ends in an
infrastructure outcome (`BASELINE_RETRY`: the engine's mutation retry set
plus `harness_error`, an exception at execution) is retried once at once and
again on every resume; its row says `class: infrastructure`.  An instance
whose baseline does not pass gets no mutation rows, so the scorer reports it
as unscored, as the paper did for such passes; `mutation.done.json` and the
report say whether its baseline failed or hit infrastructure.  Baselines are
recorded in `mutation.baseline.jsonl` beside `mutation/`.

Rows: `mutation/w<k>.jsonl`, one per pair,
`{instance_id, mutant_id, outcome, harness_version}` with the engine's own
outcome label, plus `crash` and `retried_infrastructure` when the engine
reports them.  They are written as each pair finishes, so an interrupted run
resumes at the pair level: a rerun plans only the pairs that have no row yet.
The engine's own shard files and any per-pair native evidence (Go evidence
directories) are deleted as soon as they are no longer needed; the slim rows
are the record kept, and `mutation.plan.json` keeps the campaign identity
(kit, image, seed and applier digests) of every attempt that ran pairs.

`mutation.done.json` is written only after the completeness check (every
planned pair has a row) and removed when a run starts, so a stage that
stopped early (Ctrl-C, a staging error) has none; `req2test report` refuses
a `mutation/` without it.  A host-sharded run (`shard`) never writes it: one
host's shard is not the whole stage.

Projects in `SWEEP_BEFORE_EACH_MUTANT` (CoreShop) run each worker's mutants
as one engine slice per mutant, and before each slice they sweep the worker:
one unmutated execution of the mutant's first item with an empty solution.
CoreShop has no database reset between executions; its only isolation is the
retained `@BeforeScenario` purge, which loads every leftover DataObject
through the model.  Under a mutant in DataObject-loading code that purge
crashes on objects an earlier execution left behind, so the scenario never
runs (`no_scenario_ran`, dropped), and the crash leaves the store as it was
for every later pair of the mutant.  The sweep runs the purge on unmutated
code.  The empty solution defines no steps, but the retained contexts answer
the leading steps of a few items (15 of the 334 eval items), and those steps
run in the sweep: 13 of these items create class definitions, and
`optimistic_entity_lock/lock.feature:14` and `:22` also create a DataObject.
A resumed mutant is swept again before its remaining pairs.  Sweeps are
recorded in `mutation.sweep.jsonl`, one row per attempt; a sweep whose
scenario did not run is retried once, and a second failure stops the stage.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Optional

from .execute import (RETRY_OUTCOMES, bind_environment, engine_namespace,
                      ensure_engine_path, sha256_file, worker_spec_paths)
from . import score as S
from .layout import decompressed, iter_jsonl, kit_inputs, read_json

ROW_KEYS = ("instance_id", "mutant_id", "outcome", "harness_version")
BASELINE_FILE = "mutation.baseline.jsonl"
PLAN_FILE = "mutation.plan.json"
DONE_FILE = "mutation.done.json"
DONE_SCHEMA = "req2test.mutation-done/1"
#: `class` of a mutation baseline row.
PASSED, FAILED, INFRASTRUCTURE = "passed", "failed", "infrastructure"

#: Projects whose workers are swept before every mutant (module docstring).
SWEEP_BEFORE_EACH_MUTANT = frozenset({"coreshop"})
SWEEP_FILE = "mutation.sweep.jsonl"
#: `class` of a sweep row whose scenario ran, so its hooks (the purge) ran.
SWEPT = "swept"
#: Behat outcomes of a sweep whose scenario ran.  An empty solution normally
#: leaves the item's steps undefined; anything without a scenario record
#: (`no_scenario_ran`, `no_steps_ran`, a timeout, an infrastructure outcome)
#: is a failed sweep.
SWEEP_RAN = frozenset({"undefined_steps", "failed", "pending", "passed",
                       "passed_but_nonzero_exit"})


class SweepRefused(RuntimeError):
    """A worker's sweep before a mutant failed twice."""


# ----------------------------------------------------------- kill sets
def kill_sets(kit, ids: Optional[Iterable[str]] = None) -> dict:
    """`{instance_id: [mutant_id, ...]}`: G_i for `ids` (all when None)."""
    kin = kit_inputs(kit)
    wanted = None if ids is None else set(ids)
    excluded = set()
    if kin.mutation.get("reference_excluded"):
        for row in iter_jsonl(kin.mutation["reference_excluded"]):
            excluded.add((row["item_id"], row["mutant_id"]))
    unscored = S.nondeterministic_mutants()
    out: dict = defaultdict(list)
    for row in iter_jsonl(kin.mutation["pools"]):
        iid = row["item_id"]
        if wanted is not None and iid not in wanted:
            continue
        if row.get("gold_outcome") == "killed" \
                and (iid, row["mutant_id"]) not in excluded \
                and row["mutant_id"] not in unscored:
            out[iid].append(row["mutant_id"])
    return {iid: sorted(set(mids)) for iid, mids in out.items()}


def gold_mark(exec_row: dict) -> bool:
    """Whether an execution row is a ground-truth prediction's gold run.

    `req2test.execute` stamps `source: gold` on the rows of `validate`'s
    ground-truth predictions, whose execution was a gold run; their mutation
    baselines and slices are gold runs too (gold's suite and wiring
    rules).  Any other row is a candidate's.
    """
    return (exec_row.get("metadata") or {}).get("source") == "gold"


def pool_ids(kit) -> set:
    """The instance ids that have mutation pool pairs in the kit."""
    path = kit_inputs(kit).mutation.get("pools")
    return set() if path is None else {
        row["item_id"] for row in iter_jsonl(path)}


def read_rows(mutation_dir: Path) -> dict:
    """`{(instance_id, mutant_id): row}` over every slim row file."""
    rows = {}
    for path in sorted(Path(mutation_dir).glob("*.jsonl")):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    row = json.loads(line)
                    rows[(row["instance_id"], row["mutant_id"])] = row
    return rows


def verdict(row: dict, rules) -> str:
    """`kill`, `survived` or `dropped` of one candidate row under the kit's
    `rules` (`score.classify`), for the progress lines; `unknown` for an
    outcome the scorer does not know (it refuses it at scoring)."""
    try:
        return S.classify(row, rules)
    except ValueError:
        return "unknown"


def describe_verdicts(verdicts: dict) -> str:
    """`killed=K survived=S dropped=D` (plus `unknown=U` when any)."""
    text = (f"killed={verdicts.get(S.KILL, 0)} "
            f"survived={verdicts.get(S.SURVIVED, 0)} "
            f"dropped={verdicts.get(S.DROPPED, 0)}")
    return text + (f" unknown={verdicts['unknown']}"
                   if verdicts.get("unknown") else "")


def allocate(pairs_by_mutant: dict, workers: int) -> list:
    """Mutant ids per worker: longest-first onto the least loaded worker."""
    loads = [0] * workers
    shards: list = [[] for _ in range(workers)]
    for mid in sorted(pairs_by_mutant,
                      key=lambda m: (-len(pairs_by_mutant[m]), m)):
        k = min(range(workers), key=lambda i: (loads[i], i))
        shards[k].append(mid)
        loads[k] += len(pairs_by_mutant[mid])
    return [sorted(s) for s in shards]


def _host_shard(mutant_id: str, shard) -> bool:
    if shard is None:
        return True
    index, of = shard
    digest = hashlib.sha256(mutant_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % of == index


# ------------------------------------------------------------------ run
def _read_exec(run_dir: Path) -> dict:
    rows = {}
    with open(run_dir / "exec.jsonl", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                row = json.loads(line)
                rows[row["item_id"]] = row
    return rows


def read_baselines(run_dir: Path) -> dict:
    """`{instance_id: outcome}` from `mutation.baseline.jsonl` (last row)."""
    path = Path(run_dir) / BASELINE_FILE
    out = {}
    if path.is_file():
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    row = json.loads(line)
                    out[row["instance_id"]] = row["outcome"]
    return out


def baseline_retry_outcomes() -> frozenset:
    """Baseline outcomes after which the baseline runs again: the harness,
    not the test, failed.  The engine's mutation retry set
    (`mutation_run.INFRASTRUCTURE_OUTCOMES`) plus `execute.RETRY_OUTCOMES`
    (`harness_error` is any exception at execution)."""
    ensure_engine_path()
    from r2t.bench.mutation_run import INFRASTRUCTURE_OUTCOMES
    return frozenset(INFRASTRUCTURE_OUTCOMES) | RETRY_OUTCOMES


def baseline_class(outcome: str) -> str:
    """`passed`, `infrastructure` (run it again) or `failed` (final)."""
    if outcome == "passed":
        return PASSED
    return INFRASTRUCTURE if outcome in baseline_retry_outcomes() else FAILED


def read_sweeps(run_dir: Path) -> list:
    """Every row of `mutation.sweep.jsonl`, in the order written."""
    path = Path(run_dir) / SWEEP_FILE
    if not path.is_file():
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def sweep_outcome(rec: dict) -> str:
    """What a sweep's execution did.  `run_one` labels an empty solution
    `no_files_returned` whatever Behat reported, so the run's own outcome is
    read from `outcomes_all_runs`; any other label (`harness_error`,
    `substrate_violation`, ...) is the outcome itself."""
    if rec.get("outcome") != "no_files_returned":
        return rec.get("outcome") or "no_run"
    runs = rec.get("outcomes_all_runs") or []
    return runs[0] if runs else "no_run"


def sweep_class(outcome: str) -> str:
    """`swept`, or `infrastructure` / `failed` for a sweep that did not run
    its scenario (both are retried once, then stop the stage)."""
    if outcome in SWEEP_RAN:
        return SWEPT
    return INFRASTRUCTURE if outcome in baseline_retry_outcomes() else FAILED


def read_done(run_dir: Path) -> Optional[dict]:
    """The `mutation.done.json` of a run directory, or None."""
    path = Path(run_dir) / DONE_FILE
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def forks(env) -> bool:
    """Whether workers run in forked processes (else threads): always.

    A pair spends most of its time in pure-Python substrate hashing and
    restores, so threads of one interpreter take turns on its lock while the
    containers idle (the engine's test-quality route forks for the same
    reason, `test_quality._drain_in_processes`).
    """
    return True


def _parallel(k: int, work, log, processes: bool = True) -> list:
    """Run `work(index, cancel_event)` for every worker index, in forked
    processes or threads, under the engine's coordinator cancellation
    (SIGINT or SIGTERM stops every worker at its next safe point)."""
    import multiprocessing
    from r2t.bench import mutation_run as MR
    from r2t.bench import test_quality as TQ
    event = multiprocessing.get_context("fork").Event()
    jobs = [{"side": "candidate", "worker": i} for i in range(k)]
    with MR.coordinator_cancellation(event) as cancel_event:
        try:
            return TQ.execute_jobs(
                jobs, lambda job: work(job["worker"], cancel_event),
                cancel_event=cancel_event, processes=processes and k > 1)
        except (TQ.TestQualityRefused, TQ.TestQualityCancelled) as exc:
            raise RuntimeError(f"mutate: {exc}") from exc


_STAGED_JAR = re.compile(r"^\d{4}-[0-9a-f]{16}-\d{4}-(.+\.jar)$")
JAVA_CLASSPATH_REL = "var/bench_java_analysis/classpath"
#: Where the Java worker images keep the Maven repository the study's
#: analysis classpath was exported from (`toolkit/mutation_java.py`
#: `image_classpath_export`).
IMAGE_M2 = "/opt/m2"


def stage_java_classpath(spec, recipe: dict, log=print) -> int:
    """Put a Java manifest's analysis classpath into one worker's workspace.

    The manifest's `analysis_recipe` names each jar by workspace path and
    sha256 (`var/bench_java_analysis/classpath/<n>-<sha16>-<n>-<jar>`, the
    layout `mutation_java.stage_classpath_bundle` writes).  A missing jar is
    copied out of the worker's own image (`/opt/m2`, where the study exported
    it from) and kept only if its sha256 is the recipe's.  Returns how many
    jars were staged.
    """
    import subprocess
    import tempfile
    from r2t.core.docker_cli import docker_command
    root = Path(spec.workspace)
    entries = [c for c in recipe.get("classpath") or ()
               if c.get("kind") == "file"
               and c["path"].startswith(JAVA_CLASSPATH_REL + "/")]
    missing = [c for c in entries
               if not (root / c["path"]).is_file()
               or sha256_file(root / c["path"]) != c["sha256"]]
    if not missing:
        return 0
    current = root
    for part in JAVA_CLASSPATH_REL.split("/"):
        current = current / part
        current.mkdir(mode=0o700, exist_ok=True)
    listing = subprocess.run(
        docker_command(["exec", spec.container, "find", IMAGE_M2, "-type",
                        "f", "-name", "*.jar"]),
        capture_output=True, text=True)
    if listing.returncode != 0:
        raise RuntimeError(f"cannot list {IMAGE_M2} in {spec.container}: "
                           f"{listing.stderr[-500:]}")
    by_name: dict = defaultdict(list)
    for line in listing.stdout.splitlines():
        by_name[line.rsplit("/", 1)[-1]].append(line.strip())
    with tempfile.TemporaryDirectory(dir=current) as scratch:
        for entry in missing:
            match = _STAGED_JAR.match(Path(entry["path"]).name)
            candidates = by_name.get(match.group(1)) if match else None
            staged = False
            for n, source in enumerate(candidates or ()):
                tmp = Path(scratch) / f"{n}.jar"
                cp = subprocess.run(docker_command(
                    ["cp", f"{spec.container}:{source}", str(tmp)]),
                    capture_output=True, text=True)
                if cp.returncode == 0 and sha256_file(tmp) == entry["sha256"]:
                    tmp.chmod(0o600)
                    tmp.replace(root / entry["path"])
                    staged = True
                    break
            if not staged:
                raise RuntimeError(
                    f"the Java analysis classpath jar {entry['path']} "
                    f"(sha256 {entry['sha256'][:12]}) is not in "
                    f"{spec.container}:{IMAGE_M2}")
    log(f"mutate: staged {len(missing)} analysis classpath jar(s) in "
        f"worker {spec.index}")
    return len(missing)


#: What Go mutation preparation reads beside each worker's artifacts root
#: (`go/mutation_runtime._prepare_original`): the full282 closures, the
#: production index and interface attribution of the worker image.
GO_ARTIFACTS = ("closures.json", "go_prod_index.json",
                "go_interface_attribution.json")


def stage_go_artifacts(kit, kin, env, k: int, log=print) -> None:
    """Copy the kit's Go mutation artifacts into each worker's artifacts root.

    An identical file already there is kept; a different one is refused,
    because the engine joins all three to the worker image and seed.
    """
    import shutil as _shutil
    source = kin.mutation.get("go_artifacts")
    if source is None or not all((Path(source) / n).is_file()
                                 for n in GO_ARTIFACTS):
        raise RuntimeError(
            f"kit {kit.project} {kit.version} has no mutation/go/ with "
            f"{', '.join(GO_ARTIFACTS)}; Go mutation preparation needs them "
            f"in every worker's artifacts directory")
    for index in range(k):
        target = Path(env.artifacts_for(index))
        target.mkdir(parents=True, exist_ok=True)
        for name in GO_ARTIFACTS:
            src, dst = Path(source) / name, target / name
            if dst.exists():
                if sha256_file(dst) != sha256_file(src):
                    raise RuntimeError(
                        f"{dst} differs from the kit's {name}; use a fresh "
                        f"environment")
                continue
            _shutil.copyfile(src, dst)
    log(f"mutate: staged the Go mutation artifacts in {k} worker(s)")


def mutation_gold(kit, kin, env, log=print) -> Optional[Path]:
    """The gold tree mutation runs against, when the kit gives mutation its
    own strip manifest: a copy of the environment's gold tree with that
    manifest in place (made once per kit version).  None otherwise.

    Runs that share an environment may make it at once: each builds its own
    copy, and one that finds another's in place uses that one."""
    import shutil as _shutil
    import tempfile
    manifest = kin.mutation.get("strip_manifest")
    if manifest is None:
        return None
    target = (Path(env.data_root) / "inputs" / kit.project
              / f"{kit.version}-mutation-gold-{sha256_file(manifest)[:12]}")
    if (target / "strip_manifest.json").is_file():
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f".{target.name}.", dir=target.parent))
    try:
        _shutil.copytree(env.gold_root, work, symlinks=True, dirs_exist_ok=True)
        _shutil.copyfile(manifest, work / "strip_manifest.json")
        try:
            os.rename(work, target)
        except OSError:
            if not (target / "strip_manifest.json").is_file():
                raise
    finally:
        _shutil.rmtree(work, ignore_errors=True)
    log(f"mutate: gold tree with the kit's mutation strip manifest at {target}")
    return target


def _with_gold(argv: list, gold: Optional[Path]) -> list:
    if gold is None:
        return list(argv)
    out = list(argv)
    out[out.index("--gold") + 1] = str(gold)
    return out


class _Workers:
    """The environment's first K workers.  Each harness is built (and its
    live worker authenticated) inside the process that uses it: a Go
    worker's execution copy belongs to the process that opened it."""

    def __init__(self, env, k: int, gold: Optional[Path] = None):
        import threading
        self.env, self.k, self.gold = env, k, gold
        self._built: dict = {}
        self._lock = threading.Lock()

    def harness(self, index: int):
        import os as _os
        key = (_os.getpid(), index)
        with self._lock:
            return self._harness(key, index)

    def _harness(self, key, index: int):
        if key not in self._built:
            from r2t.bench import cli as C
            env, seed_dir = self.env, str(self.env.seed_dir)
            args = engine_namespace([
                *_with_gold(env.global_args(index), self.gold),
                "run", "--adapter", "gold",
                "--release", str(env.release_items),
                "--profile", str(env.profile), "--seed", seed_dir])
            C._require_bound_live_worker(args)
            harness, _b, _m = C._harness(args)
            derived = C._derived_baseline(args, seed_dir)
            if derived:
                harness.derived_baseline = derived
            self._built[key] = harness
        return self._built[key]


def _run_baselines(workers: _Workers, ids: list, exec_rows: dict,
                   items_by_id: dict, timeout: int, out: Path,
                   harness_version, log, processes: bool = True) -> None:
    """Each instance's test, unmutated, once on a mutation worker."""
    from r2t.bench.fixtures import Adapter
    from r2t.bench.runner import run_one
    k = workers.k
    retry = baseline_retry_outcomes()
    # Ground-truth predictions' baselines are gold runs, like their execution.
    gold_runs = bool(ids) and all(gold_mark(exec_rows[iid]) for iid in ids)
    adapter = Adapter("mutation-baseline", lambda task: {
        "files": exec_rows[task["item_id"]].get("produced_files") or [],
        "metadata": {}}, {"gold_run": True} if gold_runs else {})

    def work(index, cancel_event):
        from r2t.bench.runner import _ExecutionLock
        harness = workers.harness(index)
        with _ExecutionLock(harness.root):
            run(index, harness, cancel_event)

    def run(index, harness, cancel_event):
        try:
            for iid in ids[index::k]:
                if cancel_event.is_set():
                    return
                for attempt in (1, 2):
                    rec = run_one(harness, adapter, items_by_id[iid],
                                  coverage=False, timeout=timeout)
                    if rec["outcome"] not in retry:
                        break
                row = {"instance_id": iid, "outcome": rec["outcome"],
                       "class": baseline_class(rec["outcome"]),
                       "attempt": attempt, "harness_version": harness_version}
                error = (rec.get("metadata") or {}).get("harness_error")
                if error:
                    row["harness_error"] = error[:500]
                with open(out, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(row, sort_keys=True) + "\n")
        finally:
            _settle(harness, "after mutation baselines")

    _parallel(k, work, log, processes)


def _settle(harness, when: str) -> None:
    """Leave a worker as an unmutated execution found it: no answer, no
    registration, derived state back to the seed's bytes."""
    from r2t.bench.repo import clean_workspace
    clean_workspace(harness.man, harness.boundary)
    harness.clear_registration()
    if hasattr(harness, "restore_derived_state"):
        harness.restore_derived_state(when=when)


def _sweep(harness, item: dict, timeout: int, *, worker: int, mutant_id: str,
           out: Path, harness_version) -> dict:
    """One unmutated empty-solution execution of `item` on this worker before
    `mutant_id` (a CoreShop sweep: its purge hooks run on clean code).  A
    sweep whose scenario did not run is retried once; a second failure
    raises `SweepRefused`.  Each attempt is a row of `out`."""
    from r2t.bench.fixtures import Adapter
    from r2t.bench.runner import run_one
    adapter = Adapter("mutation-sweep",
                      lambda task: {"files": [], "metadata": {}})
    for attempt in (1, 2):
        try:
            rec = run_one(harness, adapter, item, coverage=False,
                          timeout=timeout)
        finally:
            _settle(harness, "after the sweep")
        outcome = sweep_outcome(rec)
        row = {"worker": worker, "mutant_id": mutant_id,
               "instance_id": item["item_id"], "outcome": outcome,
               "class": sweep_class(outcome), "attempt": attempt,
               "harness_version": harness_version}
        error = (rec.get("metadata") or {}).get("harness_error")
        if error:
            row["harness_error"] = error[:500]
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
        if row["class"] == SWEPT:
            return row
    raise SweepRefused(
        f"REFUSED: the sweep of worker {worker} before mutant {mutant_id} "
        f"({item['item_id']}, empty solution) did not run its scenario "
        f"twice (last: {outcome}); the worker's store may hold objects the "
        f"mutant cannot load, so its pairs are not run.  Rerun the same "
        f"command to resume")


def _classes(baselines: dict) -> dict:
    return {iid: baseline_class(outcome) for iid, outcome in baselines.items()}


def _outstanding(kit, run_dir: Path, shard) -> tuple:
    """What the stage still has to do for `run_dir/exec.jsonl`:
    `(exec_rows, passing, g, with_g, classes, need_baseline, planned_all,
    done)`."""
    exec_rows = _read_exec(run_dir)
    passing = sorted(iid for iid, row in exec_rows.items()
                     if row.get("outcome") == "passed")
    g = kill_sets(kit, passing)
    with_g = [iid for iid in passing if g.get(iid)]
    classes = _classes(read_baselines(run_dir))
    # A missing baseline, or one that hit infrastructure, runs (again).
    need_baseline = [iid for iid in with_g
                     if classes.get(iid) in (None, INFRASTRUCTURE)]
    planned_all = {(iid, mid) for iid in with_g for mid in g[iid]
                   if _host_shard(mid, shard)}
    done = {pair for pair in read_rows(run_dir / "mutation")
            if pair in planned_all}
    return (exec_rows, passing, g, with_g, classes, need_baseline,
            planned_all, done)


def has_work(kit, run_dir, shard=None) -> bool:
    """Whether `run` would execute anything on workers (a mutation baseline
    or a G pair) for `run_dir/exec.jsonl`; when not, it needs no
    environment."""
    *_, classes, need_baseline, planned_all, done = _outstanding(
        kit, Path(run_dir), shard)
    return bool(need_baseline) or any(
        pair not in done for pair in planned_all
        if classes.get(pair[0]) == PASSED)


def run(kit, env, run_dir, workers: Optional[int] = None, shard=None, *,
        log=print) -> Path:
    """Run G_i for every passing instance of `run_dir/exec.jsonl`.

    `shard` is an optional `(index, of)` host shard over mutants, for spreading
    one run over several hosts.  `env` may be None when the stage has no
    work (`has_work`).  Returns the `mutation/` directory.
    """
    ensure_engine_path()
    run_dir = Path(run_dir)
    kin = kit_inputs(kit)
    sweep = kit.project in SWEEP_BEFORE_EACH_MUTANT
    mut_dir = run_dir / "mutation"
    raw_root = run_dir / "mutation-raw"
    # Written again by `_finish` only once every planned pair has a row.
    (run_dir / DONE_FILE).unlink(missing_ok=True)
    mut_dir.mkdir(parents=True, exist_ok=True)
    (exec_rows, passing, g, with_g, classes, need_baseline, planned_all,
     done) = _outstanding(kit, run_dir, shard)
    if not need_baseline:
        planned = {(iid, mid) for iid, mid in planned_all
                   if classes.get(iid) == PASSED}
        if not planned - done:
            _write_plan(run_dir, passing, g, classes, planned, done, shard)
            _finish(run_dir, passing, with_g, classes, planned, shard, log,
                    sweep=sweep)
            shutil.rmtree(raw_root, ignore_errors=True)
            log(f"mutate: {len(passing)} passing instance(s), "
                f"{len(planned)} G pairs, all done")
            return mut_dir

    from r2t.bench import mutation_run as MR
    from r2t.bench import worker as W
    from r2t.bench.validate import HARNESS_VERSION

    bind_environment(env)
    timeout = int(kin.timeout)
    items_by_id = {row["item_id"]: row
                   for row in iter_jsonl(Path(env.release_items))}
    specs_paths = worker_spec_paths(env)
    k_max = max(1, min(workers or len(specs_paths), len(specs_paths)))
    pool_paths = [str(p) for p in specs_paths]
    pool_specs = [W.load_worker_spec(p) for p in pool_paths]
    needs_db = kin.needs_database
    seed_dir = str(env.seed_dir)
    runtime = W.validate_mutation_runtime(
        pool_paths, pool_specs, seed_dir, HARNESS_VERSION, needs_db,
        project=kit.project)
    harness_version = runtime["harness_version"]
    manifest_path = decompressed(kin.mutation["manifest"], run_dir / "cache")
    manifest = read_json(manifest_path)
    engine = manifest["engine"]
    # The campaign identity every slice is bound to; kept in the plan.
    common = {
        "asset_index_sha256": sha256_file(kit.root / "kit.json"),
        "asset_project": kit.project,
        "mutation_validation_sha256": sha256_file(kin.mutation["pools"]),
        "mutation_validation_class": "native",
        "manifest_sha256": sha256_file(manifest_path),
        "manifest_digest": manifest.get("digest"),
        "map_sha256": sha256_file(kin.mutation["pools"]),
        "release_sha256": sha256_file(env.release_items),
        "candidate_run_sha256": sha256_file(run_dir / "exec.jsonl"),
        "worker_resources_sha256": runtime["worker_resources_sha256"],
        "harness_version": harness_version,
        "container_image_digest": runtime["container_image_digest"],
        "workspace_seed_digest": runtime["workspace_seed_digest"],
        "database_dump_digest": runtime["database_dump_digest"],
        "applier_sha256": MR.runtime_applier_sha256(engine, seed_dir),
        "engine": engine, "engine_version": manifest["engine_version"],
        "parser": manifest["parser"],
        # Ground-truth predictions are the gold side, so their slices are
        # gold runs (`mutation_run.is_gold_run_slice`).
        "side": ("gold" if with_g and all(gold_mark(exec_rows[iid])
                                          for iid in with_g)
                 else "candidate"),
        "generation_provenance_class": MR.GENERATION_PROVENANCE_DEVELOPMENT,
    }
    recipe = manifest.get("analysis_recipe") or {}
    if recipe.get("classpath"):
        for spec in pool_specs[:k_max]:
            stage_java_classpath(spec, recipe, log)
    if engine == "r2t-mutate-go":
        stage_go_artifacts(kit, kin, env, k_max, log)
    pool = _Workers(env, k_max, gold=mutation_gold(kit, kin, env, log))

    if need_baseline:
        log(f"mutate: baseline of {len(need_baseline)} passing instance(s)")
        _run_baselines(pool, need_baseline, exec_rows, items_by_id, timeout,
                       run_dir / BASELINE_FILE, harness_version, log,
                       forks(env))
        classes = _classes(read_baselines(run_dir))
    failed = sorted(iid for iid in with_g if classes.get(iid) == FAILED)
    infra = sorted(iid for iid in with_g if classes.get(iid) == INFRASTRUCTURE)
    if failed:
        log(f"mutate: {len(failed)} instance(s) failed their mutation "
            f"baseline and get no mutation rows: {failed[:5]}")
    if infra:
        log(f"mutate: {len(infra)} instance(s) hit infrastructure in their "
            f"mutation baseline twice and get no mutation rows; rerun the "
            f"same command to retry them: {infra[:5]}")
    planned = {(iid, mid) for iid, mid in planned_all
               if classes.get(iid) == PASSED}
    remaining = planned - done
    _write_plan(run_dir, passing, g, classes, planned, done, shard, common)
    log(f"mutate: {len(passing)} passing instance(s), {len(planned)} G pairs, "
        f"{len(done)} already done, {len(remaining)} to run")
    if not remaining:
        _finish(run_dir, passing, with_g, classes, planned, shard, log,
                sweep=sweep)
        shutil.rmtree(raw_root, ignore_errors=True)
        return mut_dir

    rules = S.reference(kit).rules
    by_id = {m["id"]: m for m in manifest["mutants"]}
    unknown = sorted({mid for _iid, mid in remaining if mid not in by_id})
    if unknown:
        raise RuntimeError(f"mutate: {len(unknown)} G mutant(s) are not in "
                           f"the kit manifest, e.g. {unknown[:3]}")
    pairs_by_mutant: dict = defaultdict(list)
    for iid, mid in sorted(remaining):
        pairs_by_mutant[mid].append(iid)
    k = min(k_max, len(pairs_by_mutant))
    allocation = allocate(pairs_by_mutant, k)
    engine_dir, applier = MR.binding_for(engine)
    operator_profile = MR.operator_profile_for(manifest["operators"])

    attempt = 1 + max([int(p.name[1:]) for p in raw_root.glob("a*")
                       if p.name[1:].isdigit()] or [0])
    raw_dir = raw_root / f"a{attempt}"
    raw_dir.mkdir(parents=True, exist_ok=True)
    java_root = None
    if kin.mutation.get("java_analysis_root"):
        from .layout import extract_tree
        source = Path(kin.mutation["java_analysis_root"])
        java_root = str(extract_tree(
            source, Path(env.data_root) / "inputs" / kit.project
            / f"{kit.version}-java-analysis-root")
            if source.name.endswith((".tar", ".tar.zst")) else source)

    def job(index: int, cancel_event) -> dict:
        mids = allocation[index]
        if not mids:
            return {"worker": index, "rows": 0}
        harness = pool.harness(index)
        # Hold the runner's execution lock on this worker, as `run_adapter`
        # does: one executor per workspace, and the lock file then names
        # this process (a Go copy checks it against its own pid).
        from r2t.bench.runner import _ExecutionLock
        with _ExecutionLock(harness.root):
            return slice_job(index, harness, cancel_event)

    def slice_job(index: int, harness, cancel_event) -> dict:
        mids = allocation[index]
        # The sweep `run_one` makes before every execution: remove a prior
        # answer and registration, and verify the substrate.  A fresh pool
        # comes out of its gold-control qualification holding the control's
        # files, and a Go worker quarantines itself on that dirt.
        harness.prepare_for_generation()
        mutants = [by_id[mid] for mid in sorted(
            mids, key=lambda m: (by_id[m]["file"], by_id[m]["start_line"], m))]
        by_mutant = {mid: pairs_by_mutant[mid] for mid in mids}
        shard_items = sorted({iid for mid in mids for iid in by_mutant[mid]})
        files_by_item = {iid: exec_rows[iid].get("produced_files") or []
                         for iid in shard_items}
        digest = MR.candidate_digest(files_by_item)
        substrate = MR.substrate_baseline_digest(harness)
        slim_path = mut_dir / f"w{index}.jsonl"
        spec = pool_specs[index]
        resources = [(name, getattr(spec, name))
                     for name in W.resource_fields(needs_db)
                     if getattr(spec, name)]
        verdicts: Counter = Counter()

        def run_part(part: list, out_path: Path) -> dict:
            """One engine slice over the mutants `part`."""
            expected = {(iid, m["id"]) for m in part
                        for iid in by_mutant[m["id"]]}
            identity = MR.build_campaign_identity(
                **common,
                candidate_generated_tests_sha256=digest,
                solution_generated_tests_sha256=digest,
                substrate_baseline_sha256=substrate,
                expected_pairs=expected, shard=index, of=k, timeout=timeout)
            evidence_root = Path(str(out_path) + ".go-evidence")

            def on_row(row: dict) -> None:
                slim = {"instance_id": row["item_id"],
                        "mutant_id": row["mutant_id"],
                        "outcome": row["outcome"],
                        "harness_version": harness_version}
                for key in ("crash", "retried_infrastructure"):
                    if row.get(key):
                        slim[key] = row[key]
                verdicts[verdict(slim, rules)] += 1
                with open(slim_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(slim, sort_keys=True) + "\n")
                if evidence_root.is_dir():
                    for child in evidence_root.glob(f"{row['mutant_id']}.*"):
                        shutil.rmtree(child, ignore_errors=True)

            info = MR.run_slice(
                harness, part, items_by_id, files_by_item,
                {m["id"]: by_mutant[m["id"]] for m in part},
                engine_dir, str(out_path), identity=identity,
                manifest=manifest, planned_pairs=expected, timeout=timeout,
                applier=applier, operator_profile=operator_profile,
                engine=engine, engine_version=manifest["engine_version"],
                java_analysis_root=java_root, on_row=on_row,
                cancel_event=cancel_event, resource_identities=resources,
                provenance={"req2test_run": str(run_dir), "worker": index})
            for path in (out_path, Path(MR.provenance_path(str(out_path)))):
                path.unlink(missing_ok=True)
            shutil.rmtree(evidence_root, ignore_errors=True)
            return info

        if not sweep:
            info = run_part(mutants, raw_dir / f"cand-w{index}.jsonl")
            return {"worker": index, "rows": info.get("rows"),
                    "outcomes": dict(info.get("outcomes") or {}),
                    "verdicts": dict(verdicts),
                    "seconds": info.get("seconds")}
        # One slice per mutant, each after a sweep of this worker.
        rows, outcomes, seconds = 0, defaultdict(int), 0.0
        for mutant in mutants:
            mid = mutant["id"]
            if cancel_event.is_set():
                raise MR.MutationCancelled(
                    f"mutation campaign cancelled before the sweep of "
                    f"mutant {mid}")
            _sweep(harness, items_by_id[by_mutant[mid][0]], timeout,
                   worker=index, mutant_id=mid, out=run_dir / SWEEP_FILE,
                   harness_version=harness_version)
            info = run_part([mutant], raw_dir / f"cand-w{index}-{mid}.jsonl")
            rows += info.get("rows") or 0
            for outcome, n in (info.get("outcomes") or {}).items():
                outcomes[outcome] += n
            seconds += info.get("seconds") or 0.0
        return {"worker": index, "rows": rows, "outcomes": dict(outcomes),
                "verdicts": dict(verdicts),
                "seconds": round(seconds, 1), "sweeps": len(mutants)}

    if sweep:
        log(f"mutate: {kit.project}: each worker is swept (one unmutated "
            f"empty-solution execution) before each mutant "
            f"({len(pairs_by_mutant)} in all)")
    for result in _parallel(k, job, log, forks(env)):
        log(f"mutate: worker {result['worker']}: {result.get('rows')} "
            f"pair(s), {describe_verdicts(result.get('verdicts') or {})}, "
            f"{result.get('seconds')} s"
            + (f", {result['sweeps']} sweep(s)" if "sweeps" in result else ""))
    _finish(run_dir, passing, with_g, classes, planned, shard, log,
            sweep=sweep)
    shutil.rmtree(raw_root, ignore_errors=True)
    return mut_dir


def _write_json(path: Path, doc: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n",
                   encoding="utf-8")
    os.replace(tmp, path)


def sweep_summary(run_dir: Path) -> dict:
    """The sweeps of `mutation.sweep.jsonl` so far, counted."""
    rows = read_sweeps(run_dir)

    def count(key: str) -> dict:
        return dict(sorted(Counter(r[key] for r in rows).items()))
    return {"runs": len(rows),
            "mutants": len({r["mutant_id"] for r in rows
                            if r["class"] == SWEPT}),
            "classes": count("class"), "outcomes": count("outcome")}


def _write_plan(run_dir, passing, g, classes, planned, done, shard,
                identity: Optional[dict] = None) -> None:
    """`mutation.plan.json`; `identities` lists the campaign identity of
    every attempt that ran baselines or pairs, oldest first."""
    path = Path(run_dir) / PLAN_FILE
    identities = []
    if path.is_file():
        identities = json.loads(path.read_text(encoding="utf-8")) \
            .get("identities") or []
    if identity is not None and identity not in identities:
        identities.append(identity)
    with_g = [iid for iid in passing if g.get(iid)]
    doc = {"passing": len(passing), "pairs": len(planned), "done": len(done),
           "g_sizes": {iid: len(g.get(iid, ())) for iid in passing},
           "baseline_failed": sorted(
               iid for iid in with_g if classes.get(iid) == FAILED),
           "baseline_infrastructure": sorted(
               iid for iid in with_g if classes.get(iid) == INFRASTRUCTURE),
           "host_shard": list(shard) if shard else None,
           "identities": identities}
    _write_json(path, doc)


def _finish(run_dir, passing, with_g, classes, planned, shard, log, *,
            sweep: bool) -> None:
    """Check that the stage is complete; then write `mutation.done.json`."""
    run_dir = Path(run_dir)
    no_baseline = [iid for iid in with_g if iid not in classes]
    if no_baseline:
        raise RuntimeError(f"mutate: {len(no_baseline)} passing instance(s) "
                           f"have no mutation baseline, e.g. "
                           f"{no_baseline[:3]}")
    left = planned - set(read_rows(run_dir / "mutation"))
    if left:
        raise RuntimeError(f"mutate: {len(left)} planned pair(s) have no row")
    if shard is not None:
        log(f"mutate: host shard {shard[0]} of {shard[1]} is complete; "
            f"{DONE_FILE} is written by an unsharded run over every "
            f"shard's rows")
        return
    _write_json(run_dir / DONE_FILE, {
        "schema": DONE_SCHEMA, "passing": len(passing),
        "pairs": len(planned),
        # The execution rows this stage planned from: a later execute
        # resume that changes them makes this stage stale.
        "exec_sha256": sha256_file(run_dir / "exec.jsonl"),
        "baselines": {iid: classes[iid] for iid in with_g},
        "baseline_failed": sorted(
            iid for iid in with_g if classes[iid] == FAILED),
        "baseline_infrastructure": sorted(
            iid for iid in with_g if classes[iid] == INFRASTRUCTURE),
        "sweeps": sweep_summary(run_dir) if sweep else None,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")})
