"""`req2test evaluate` and `req2test validate`: the evaluation pipeline.

    env up -> execute -> behaviour -> mutate -> score -> aggregate -> report

Per project and view, outputs go to `runs/<run_id>/<project>/<view>/`
(`layout.run_dir`): `predictions.norm.jsonl`, `exec.jsonl`, `behaviour.json`,
`mutation/w<k>.jsonl`, `instances.jsonl`; `summary.json` and `report.md` sit at
`runs/<run_id>/`.  Every stage resumes: rerunning the same command with the
same run id continues where it stopped.

The environment is `req2test.env.up/down` (a qualified worker pool on a
rootless Docker daemon; `docs/environments.md`), brought up only when a stage
has work for it: a resumed run with nothing left to execute or mutate goes
straight to scoring.  Scoring, aggregation and the report are
`req2test.report.build/write`, which score every instance with
`req2test.score.score_instance`.

`--instances FILE` or `--sample N [--seed S]` evaluates part of the split (the
sample is drawn as `validate` draws it, `sample_ids`); such a run records its
selection in `runs/<run_id>/subset.json`, and its summary and report are
marked SUBSET runs, not comparable to the leaderboard.  A `--split full` run
records its split in `runs/<run_id>/split.json`, and is marked NOT COMPARABLE:
the leaderboard covers the eval split only.  A run evaluates benchmark 1.1
(TH only) and records it in `runs/<run_id>/benchmark.json`; a rerun into a run
of another version is refused.  Before any Docker work the clone must be clean
(`req2test.env.check_clean_clone`).
"""
from __future__ import annotations

import json
import math
import random
import signal
import threading
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from . import behaviour, execute, mutate
from . import predictions as P
from . import score as S
from .layout import (Kit, check_split, load_kit, release_item_ids,
                     run_dir as make_run_dir, run_root)

METRICS = ("exec", "all")
#: The benchmark version every run evaluates (`req2test.predictions`).
BENCHMARK_VERSION = P.BENCHMARK_VERSIONS[-1]


def _log(*parts) -> None:
    print(*parts, flush=True)


VALIDATE_SEED = 20261004
#: `validate` passes (exit 0) within single-observation noise: at most
#: max(1, floor(FLIP_TOLERANCE x the G pairs run)) G pairs may flip (survive
#: or drop), not counting pairs of the kit's `known_host_dependent` mutants
#: (`flips_allowed`).
FLIP_TOLERANCE = 0.001
#: Mean (and per-instance warning) floor of coverage J in `validate`.
COVERAGE_FLOOR = 0.99


# =================================================================== env
def env_up(kit: Kit, workers: Optional[int], run_dir, *, docker_host=None,
           log=_log):
    """A qualified worker pool for `kit` (`req2test.env.up`)."""
    from . import env
    log(f"env: bringing up {workers or 'the default number of'} worker(s) "
        f"for {kit.project}")
    return env.up(kit, workers, run_dir, docker_host=docker_host)


def env_down(handle) -> None:
    from . import env
    env.down(handle)


def check_clone() -> None:
    """Refuse a clone that is not clean before any Docker work."""
    from . import env
    env.check_clean_clone()


# ============================================================= pipeline
def eval_ids(project: str, split: str = "eval") -> list:
    from . import dataset
    from .layout import data_dir
    return [row["instance_id"] for row in
            dataset.iter_instances(split, project, data_dir=data_dir())]


def sample_ids(project: str, n: int, split: str = "eval",
               seed: int = VALIDATE_SEED) -> list:
    """`n` instances of `project`, drawn with `random.Random("<seed>:<project>")`
    from the sorted split ids; returned sorted."""
    ids = sorted(eval_ids(project, split))
    rng = random.Random(f"{seed}:{project}")
    return sorted(rng.sample(ids, min(n, len(ids))))


def read_instance_ids(path) -> list:
    """The instance ids of an `--instances` file: one per line; blank lines
    and lines starting with `#` are skipped; repeats are refused."""
    ids, seen = [], set()
    with open(path, encoding="utf-8") as fh:
        for number, line in enumerate(fh, 1):
            iid = line.strip()
            if not iid or iid.startswith("#"):
                continue
            if iid in seen:
                raise ValueError(f"{path}:{number}: {iid} is listed twice")
            seen.add(iid)
            ids.append(iid)
    if not ids:
        raise ValueError(f"{path} lists no instance id")
    return ids


def _check_run_predictions(run_dir: Path, digest: str) -> None:
    marker = run_dir / "predictions.sha256"
    if marker.is_file():
        recorded = marker.read_text(encoding="utf-8").strip()
        if recorded != digest:
            raise RuntimeError(
                f"{run_dir} already holds a run of other predictions "
                f"(sha256 {recorded[:12]}); use a new --run-id")
    else:
        marker.write_text(digest + "\n", encoding="utf-8")


@contextmanager
def sigterm_exits():
    """SIGTERM raises SystemExit in the main thread, so `finally` blocks (the
    environment's `env down`) run.  Execute and mutate install the engine's
    cooperative cancellation over it while their workers run."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def _exit(signum, _frame):
        raise SystemExit(128 + signum)

    previous = signal.signal(signal.SIGTERM, _exit)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def check_population(kit: Kit, ids: list, metrics: str, split: str) -> None:
    """Refuse instances the kit cannot execute, and mutation for instances
    without mutation pools (kits cover the eval population; `full` is a
    Pass@1, API F1 and coverage split for python-docx only, and data only
    elsewhere: `layout.check_split`)."""
    check_split(kit.project, split)
    items = release_item_ids(kit)
    outside = sorted(set(ids) - items)
    if outside:
        raise ValueError(
            f"{kit.project}: kit {kit.version} cannot execute {len(outside)} "
            f"of the {len(ids)} {split} instance(s) (not in its execution "
            f"release), e.g. {outside[:3]}; only --split eval is fully "
            f"covered")
    if metrics == "all":
        pooled = mutate.pool_ids(kit)
        unpooled = sorted(set(ids) - pooled)
        if unpooled:
            raise ValueError(
                f"{kit.project}: {len(unpooled)} {split} instance(s) have no "
                f"mutation pool in kit {kit.version}, e.g. {unpooled[:3]}; "
                f"only --split eval has all metrics. Use --metrics exec "
                f"(Pass@1, API F1, coverage) for them")


def evaluate_project(project: str, view: str, preds: dict, *, run_id: str,
                     ids: list, workers: Optional[int], metrics: str,
                     docker_host=None, log=_log) -> tuple:
    """Run every stage for one project and view; return its run directory
    and whether a worker pool was brought up.

    The pool comes up only for work: before execution when an instance is
    left to execute (`execute.pending`), else before mutation when a
    baseline or G pair is left to run (`mutate.has_work`).  A resumed run
    with nothing left goes straight to scoring.
    """
    kit = load_kit(project)
    rdir = make_run_dir(run_id, project, view)
    rdir.mkdir(parents=True, exist_ok=True)
    _check_run_predictions(rdir, P.digest(preds))
    started = time.time()
    env = None
    if execute.pending(preds, ids, rdir):
        env = env_up(kit, workers, rdir, docker_host=docker_host, log=log)
    try:
        with sigterm_exits():
            execute.run(kit, env, preds, view, rdir, workers, ids=ids,
                        log=log)
            behaviour.run(kit, rdir)
            if metrics == "all":
                if env is None and mutate.has_work(kit, rdir):
                    env = env_up(kit, workers, rdir, docker_host=docker_host,
                                 log=log)
                mutate.run(kit, env, rdir, workers, log=log)
    finally:
        if env is not None:
            env_down(env)
    if env is None:
        log(f"{project}/{view}: nothing left to run on workers; no worker "
            f"pool was brought up")
    log(f"{project}/{view}: stages done in {time.time() - started:.0f} s")
    return rdir, env is not None


def _read_instances(rdir: Path) -> list:
    with open(rdir / "instances.jsonl", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def score_and_report(run_id: str, cells: list) -> tuple:
    """Score, aggregate and report a run with WP6's report; return the
    summary and the instance rows of `cells` [(project, view, run_dir)]."""
    from . import report
    root = run_root(run_id)
    summary = report.build(root, kit_for=load_kit)
    report.write(root, summary)
    instances = [row for _p, _v, rdir in cells
                 for row in _read_instances(rdir)]
    return summary, instances


def _version_name(version: Optional[str]) -> str:
    return version or "not stated"


def run_version(plan: list) -> str:
    """The run's benchmark version, `BENCHMARK_VERSION`; refuses a view
    other than th."""
    other = sorted(f"{proj}/{v}" for proj, v, _m, _i in plan if v != "th")
    if other:
        raise ValueError(f"benchmark {BENCHMARK_VERSION} offers the th view "
                         f"only; refusing {other}")
    return BENCHMARK_VERSION


def record_version(path: Path, version: Optional[str]) -> None:
    """Write the run's benchmark version to `path`, or refuse a run that
    already records another.  A run root that holds cells but no `path`
    was made before the field existed, and records none."""
    if path.is_file():
        recorded = json.loads(path.read_text(encoding="utf-8"))[
            "benchmark_version"]
    elif any(path.parent.glob("*/*/exec.jsonl")):
        recorded = None
    else:
        recorded = version
    if recorded != version:
        raise RuntimeError(
            f"{path.parent} holds a run of benchmark version "
            f"{_version_name(recorded)}, these predictions are "
            f"{_version_name(version)}; use a new --run-id")
    path.write_text(json.dumps({"benchmark_version": version}) + "\n",
                    encoding="utf-8")


def _subset_record(selection: dict, split: str, counts: dict) -> dict:
    return {"selection": selection.get("selection"), "split": split,
            "sample": selection.get("sample"), "seed": selection.get("seed"),
            "instances_file": selection.get("instances_file"),
            "projects": {p: {"n": n, "of": of}
                         for p, (n, of) in sorted(counts.items())}}


def evaluate(predictions_path: Optional[str], *, run_id: str,
             split: str = "eval", project: Optional[str] = None,
             view: Optional[str] = None, workers: Optional[int] = None,
             metrics: str = "all", predictions: Optional[dict] = None,
             ids_by_project: Optional[dict] = None,
             instances: Optional[list] = None,
             instances_file: Optional[str] = None,
             sample: Optional[int] = None, seed: int = VALIDATE_SEED,
             docker_host=None, log=_log) -> dict:
    """The `evaluate` verb: `{"summary", "instances", "pools"}` of the run,
    `pools` being how many worker pools it brought up (0 when nothing was
    left to run).

    `instances` (ids, e.g. `read_instance_ids(instances_file)`) or `sample`
    (per project, `sample_ids(project, sample, split, seed)`) restricts each
    project to part of the split: a SUBSET run.  With `instances`, the
    projects are those it names; predictions outside the selection are
    ignored.  `ids_by_project` sets the population directly (API).
    """
    if metrics not in METRICS:
        raise ValueError(f"--metrics must be one of {METRICS}")
    if instances is not None and sample is not None:
        raise ValueError("give --instances or --sample, not both")
    if sample is not None and sample < 1:
        raise ValueError("--sample must be at least 1")
    # A removed `repo/` prefix is warned about below, only for the
    # predictions of the selected instances.
    preds_all = (predictions if predictions is not None
                 else P.load(predictions_path, project=project, view=view,
                             warn=None))
    from .dataset import PROJECTS
    if instances is not None:
        named = {iid.split("/", 1)[0] for iid in instances}
        unknown = sorted(named - set(PROJECTS))
        if unknown:
            raise ValueError(f"{instances_file or '--instances'} names "
                             f"unknown project(s) {unknown}")
        if project and project not in named:
            raise ValueError(f"{instances_file or '--instances'} lists no "
                             f"{project} instance")
        projects = [project] if project else sorted(named)
    else:
        projects = ([project] if project else
                    sorted({iid.split("/", 1)[0] for iid in preds_all}
                           & set(PROJECTS)))
    if not projects:
        raise ValueError("no predictions for any benchmark project")
    plan, counts = [], {}
    for proj in projects:
        check_split(proj, split)
        mine = {iid: p for iid, p in preds_all.items()
                if iid.startswith(proj + "/")}
        if not mine:
            raise ValueError(
                f"no prediction is for project {proj} (instance ids "
                f"'{proj}/...'); evaluating it would score every instance as "
                f"a generation failure")
        views = {p.view for p in mine.values() if p.view}
        if view and views - {view}:
            raise ValueError(f"{proj}: predictions name view(s) "
                             f"{sorted(views - {view})}, but --view is "
                             f"{view!r}")
        if view:
            v = view
        elif len(views) <= 1:
            v = views.pop() if views else "th"
        else:
            raise ValueError(f"{proj}: predictions mix views {sorted(views)}; "
                             f"split the file by view")
        population = eval_ids(proj, split)
        ids = (ids_by_project or {}).get(proj)
        if ids is None and sample is not None:
            ids = sample_ids(proj, sample, split, seed)
        elif ids is None and instances is not None:
            listed = {iid for iid in instances if iid.startswith(proj + "/")}
            outside = sorted(listed - set(population))
            if outside:
                raise ValueError(
                    f"{proj}: {len(outside)} listed instance(s) are not in "
                    f"the {split} split, e.g. {outside[:3]}")
            ids = [iid for iid in population if iid in listed]
        ids = population if ids is None else ids
        extra = sorted(set(mine) - set(population if ids_by_project is None
                                       else ids))
        if extra:
            raise ValueError(f"{proj}: {len(extra)} prediction(s) are not in "
                             f"the {split} split, e.g. {extra[:3]}")
        chosen = set(ids)
        if len(chosen) < len(population):
            outside = [iid for iid in mine if iid not in chosen]
            if outside:
                log(f"{proj}: ignoring {len(outside)} prediction(s) outside "
                    f"the selected {len(ids)} instance(s)")
            mine = {iid: p for iid, p in mine.items() if iid in chosen}
        P.warn_notes(mine)
        check_population(load_kit(proj), ids, metrics, split)
        counts[proj] = (len(ids), len(population))
        plan.append((proj, v, mine, ids))
    root = run_root(run_id)
    selection = ({"selection": "sample", "sample": sample, "seed": seed}
                 if sample is not None else
                 {"selection": "instances", "instances_file": instances_file}
                 if instances is not None else None)
    if selection is None and ids_by_project is not None:
        selection = {"selection": "instances"}
    subset = (selection is not None
              and any(n < of for n, of in counts.values()))
    version = run_version(plan)
    check_clone()
    from .report import (BENCHMARK_FILE, SPLIT_FILE, SUBSET_FILE,
                         population_exclusions)
    # A 1.1 run needs its population list: refuse before any execution.
    population_exclusions(version)
    root.mkdir(parents=True, exist_ok=True)
    record_version(root / BENCHMARK_FILE, version)
    _mark(root / SUBSET_FILE, _subset_record(selection, split, counts)
          if subset else None)
    # The leaderboard covers the eval split only.
    _mark(root / SPLIT_FILE, {"split": split, "projects": sorted(counts)}
          if split != "eval" else None)
    cells, pools = [], 0
    for proj, v, mine, ids in plan:
        log(f"== {proj}/{v}: {len(ids)} instance(s), {len(mine)} prediction(s)")
        rdir, brought_up = evaluate_project(
            proj, v, mine, run_id=run_id, ids=ids, workers=workers,
            metrics=metrics, docker_host=docker_host, log=log)
        cells.append((proj, v, rdir))
        pools += brought_up
    summary, instances = score_and_report(run_id, cells)
    return {"summary": summary, "instances": instances, "pools": pools}


def _mark(path: Path, doc: Optional[dict]) -> None:
    """Write the run marker `path` with `doc`, or remove it (None)."""
    if doc is None:
        path.unlink(missing_ok=True)
    else:
        path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n",
                        encoding="utf-8")


# ============================================================= validate
def _mean(values):
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if values else None


def pair_flips(kit, rows: list, mutation_rows: dict) -> dict:
    """The G pairs of the passing `rows` that were not killed, by mutant.

    `mutation_rows` is `{(instance_id, mutant_id): row}` (`mutate.read_rows`).
    Each survived or dropped pair is grouped under its mutant id with the
    instances it affects; a mutant the kit's `rules.json` lists in
    `known_host_dependent` is marked so.  The flip rate is survived plus
    dropped over the G pairs that have a row.
    """
    ref = S.reference(kit)
    known = set(ref.rules.known_host_dependent)
    counts: Counter = Counter()
    groups: dict = {"survived": {}, "dropped": {}}
    for r in rows:
        if not r["passed"]:
            continue
        iid = r["instance_id"]
        for mid in sorted(ref.gold_set(iid)):
            row = mutation_rows.get((iid, mid))
            if row is None:
                counts["no_row"] += 1
                continue
            verdict = S.classify(row, ref.rules)
            counts[verdict] += 1
            if verdict == S.KILL:
                continue
            key = "survived" if verdict == S.SURVIVED else "dropped"
            group = groups[key].setdefault(mid, {
                "n": 0, "instances": [], "outcomes": {},
                "known_host_dependent": mid in known})
            group["n"] += 1
            group["instances"].append(iid)
            outcome = row.get("outcome")
            group["outcomes"][outcome] = group["outcomes"].get(outcome, 0) + 1
    with_rows = counts[S.KILL] + counts[S.SURVIVED] + counts[S.DROPPED]
    flips = counts[S.SURVIVED] + counts[S.DROPPED]
    unknown = sum(g["n"] for by_mutant in groups.values()
                  for g in by_mutant.values() if not g["known_host_dependent"])
    return {"g_pairs": with_rows + counts["no_row"],
            "g_pairs_with_rows": with_rows, "killed": counts[S.KILL],
            "survived": counts[S.SURVIVED], "dropped": counts[S.DROPPED],
            "flip_rate": flips / with_rows if with_rows else None,
            "flips_not_known_host_dependent": unknown,
            "survived_by_mutant": groups["survived"],
            "dropped_by_mutant": groups["dropped"]}


def _flipped_by_instance(pairs: dict) -> dict:
    """`{instance_id: {"survived": [mid], "dropped": [mid]}}`."""
    out: dict = {}
    for key in ("survived", "dropped"):
        for mid, group in pairs[f"{key}_by_mutant"].items():
            for iid in group["instances"]:
                out.setdefault(iid, {"survived": [], "dropped": []})[key] \
                    .append(mid)
    return out


def flips_allowed(pairs_run: int) -> int:
    """The flips `validate` tolerates among `pairs_run` G pairs:
    max(1, floor(FLIP_TOLERANCE x pairs_run))."""
    return max(1, math.floor(FLIP_TOLERANCE * pairs_run + 1e-9))


#: Per-instance levels of `validate`, most severe first.
LEVELS = ("deviation", "warning", "noise", "known")


def validation_result(project: str, run_id: str, rows: list,
                      pairs: dict) -> dict:
    """The installation verdict of scored ground-truth `rows` and their
    `pair_flips`.

    `ok` (exit 0: "OK, within single-observation noise") when all of these
    hold, else DEVIATIONS:

    * every sampled ground-truth test passes (and, where mutation ran, its
      unmutated mutation baseline passed, so its pairs were scored);
    * the mean API F1 over the scored instances is 1.0;
    * the mean coverage J is at least 0.99;
    * the flips -- survived plus dropped G pairs, not counting pairs of the
      kit's `known_host_dependent` mutants -- are at most
      `flips_allowed(G pairs run)`, max(1, floor(0.001 x G pairs run)).

    Each instance with something to report is listed with its causes at the
    most severe of these levels: `deviation` (it breaks a check), `warning`
    (coverage J below 0.99 while the mean holds, or no scored G pair),
    `noise` (flips within the tolerance), `known` (only pairs of
    known host-dependent mutants).
    """
    groups = {**{("survived", m): g
                 for m, g in pairs["survived_by_mutant"].items()},
              **{("dropped", m): g
                 for m, g in pairs["dropped_by_mutant"].items()}}
    flipped = _flipped_by_instance(pairs)
    n = len(rows)
    passed = sum(1 for r in rows if r["passed"])
    kc = sum(1 for r in rows if r["kill_complete"])
    api = [r["api_f1"] for r in rows if r["api_f1"] is not None]
    cov = [r["coverage_j"] for r in rows if r["coverage_j"] is not None]
    api_mean, cov_mean = _mean(api), _mean(cov)
    run = pairs["g_pairs_with_rows"]
    flips = pairs["flips_not_known_host_dependent"]
    allowed = flips_allowed(run)
    gt_ok = [r for r in rows if r["passed"] and r.get("mutation_status")
             in (S.SCORED, S.NOT_SCORABLE)]
    checks = {
        "ground_truth_passes": len(gt_ok) == n,
        "api_f1_mean_is_1": api_mean is None or api_mean >= 1.0 - 1e-9,
        "coverage_j_mean_at_least_0.99":
            cov_mean is None or cov_mean >= COVERAGE_FLOOR,
        "flips_within_tolerance": flips <= allowed,
    }
    flip_level = "noise" if checks["flips_within_tolerance"] else "deviation"
    cov_level = ("warning" if checks["coverage_j_mean_at_least_0.99"]
                 else "deviation")
    listed = []
    for r in rows:
        iid = r["instance_id"]
        causes = []                         # (level, text)
        status = r.get("mutation_status")
        if not r["passed"]:
            causes.append(("deviation", f"outcome {r['outcome']}"))
        elif status not in (S.SCORED, S.NOT_SCORABLE):
            baseline = r.get("mutation_baseline")
            causes.append(("deviation", f"mutation {status}" + (
                f" (mutation baseline {baseline})"
                if baseline not in (None, "passed") else "")))
        for key in ("survived", "dropped"):
            mids = (flipped.get(iid) or {}).get(key) or []
            if not mids:
                continue
            known = [m for m in mids
                     if groups[(key, m)]["known_host_dependent"]]
            causes.append((
                "known" if len(known) == len(mids) else flip_level,
                f"{len(mids)} G pair(s) {key}: {', '.join(mids)}"
                + (f" ({len(known)} known host-dependent)" if known else "")))
        if r["passed"] and status == S.NOT_SCORABLE \
                and not (flipped.get(iid) or {}).get("dropped"):
            causes.append(("warning", "mutation not_scorable (no scored G "
                                      "pair)"))
        if r["api_f1"] is not None and r["api_f1"] < 1.0:
            causes.append(("deviation", f"API F1 {r['api_f1']:.4f}"))
        if r["coverage_j"] is not None and r["coverage_j"] < COVERAGE_FLOOR:
            causes.append((cov_level, f"coverage J {r['coverage_j']:.4f}"))
        if causes:
            level = min((lv for lv, _ in causes), key=LEVELS.index)
            listed.append({"instance_id": iid, "level": level,
                           "causes": [text for _, text in causes],
                           "recall": r.get("recall")})
    return {"project": project, "run_id": run_id, "n": n,
            "sample_seed": f"{VALIDATE_SEED}:{project}",
            "instances": [r["instance_id"] for r in rows],
            "pass": passed, "kill_complete": kc,
            "api_f1_scored": len(api),
            "api_f1_mean": api_mean, "api_f1_min": min(api) if api else None,
            "coverage_j_scored": len(cov),
            "coverage_j_mean": cov_mean,
            "coverage_j_min": min(cov) if cov else None,
            "flips_counted": flips, "flip_tolerance": FLIP_TOLERANCE,
            "flips_allowed": allowed,
            "pairs": pairs, "checks": checks, "deviations": listed,
            "ok": all(checks.values())}


def _yes(value: bool) -> str:
    return "yes" if value else "NO"


def describe(result: dict) -> list:
    """The installation verdict as lines for people."""
    pairs = result["pairs"]
    checks = result["checks"]
    run = pairs["g_pairs_with_rows"]
    flips = result["flips_counted"]
    lines = [
        f"validate {result['project']}: pass {result['pass']}/{result['n']}, "
        f"kill_complete {result['kill_complete']}/{result['n']}, API F1 "
        f"{result['api_f1_mean']} (min {result['api_f1_min']}, "
        f"{result['api_f1_scored']} scored), coverage J "
        f"{result['coverage_j_mean']} (min {result['coverage_j_min']}) -> "
        + ("OK, within single-observation noise" if result["ok"]
           else "DEVIATIONS"),
        f"G pairs of the passes: {run} run, {pairs['killed']} killed, "
        f"{pairs['survived']} survived, {pairs['dropped']} dropped; flips "
        f"not known host-dependent: {flips}"
        + (f" ({100 * flips / run:.3f}%)" if run else "")
        + f", at most {result['flips_allowed']} allowed (max(1, floor("
          f"{result['flip_tolerance']:g} x {run})))",
        f"checks: every ground-truth test passes "
        f"{_yes(checks['ground_truth_passes'])}; mean API F1 is 1 "
        f"{_yes(checks['api_f1_mean_is_1'])}; mean coverage J >= "
        f"{COVERAGE_FLOOR} {_yes(checks['coverage_j_mean_at_least_0.99'])}; "
        f"flips within tolerance {_yes(checks['flips_within_tolerance'])}"]
    for key in ("survived", "dropped"):
        for mid, g in sorted(pairs[f"{key}_by_mutant"].items()):
            outcomes = ", ".join(f"{o} {c}" for o, c in
                                 sorted(g["outcomes"].items()))
            lines.append(
                f"  {key} mutant {mid}: {g['n']} pair(s) ({outcomes})"
                + (" [known host-dependent]" if g["known_host_dependent"]
                   else "") + ": " + ", ".join(g["instances"]))
    for d in sorted(result["deviations"],
                    key=lambda d: LEVELS.index(d["level"])):
        lines.append(f"  {d['level']} {d['instance_id']}: "
                     f"{'; '.join(d['causes'])}")
    return lines


def validate(project: str, *, sample: int = 20, run_id: Optional[str] = None,
             workers: Optional[int] = None, view: str = "th",
             docker_host=None, log=_log) -> dict:
    """The installation check: ground-truth tests as predictions on `sample`
    instances, with every survived or dropped G pair listed by mutant
    (`validation_result` decides)."""
    ids = sample_ids(project, sample)
    run_id = run_id or f"validate-{project}-{sample}"
    preds = P.from_gt(project, ids, view=view)
    rows = evaluate(None, run_id=run_id, project=project, view=view,
                    workers=workers, metrics="all", predictions=preds,
                    sample=sample, docker_host=docker_host,
                    log=log)["instances"]
    kit = load_kit(project)
    pairs = pair_flips(kit, rows, mutate.read_rows(
        make_run_dir(run_id, project, view) / "mutation"))
    result = validation_result(project, run_id, rows, pairs)
    (run_root(run_id) / "validate.json").write_text(
        json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return result
