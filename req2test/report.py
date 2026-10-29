"""`req2test report --run-id R`: score a run, aggregate it, write its report.

Reads, for every `<project>/<view>/` of `$REQ2TEST_HOME/runs/<run_id>/`
(INTERFACES.md):

    exec.jsonl          one execution row per instance (engine rows)
    behaviour.json      {instance_id: {api_f1, coverage_j}}  (optional)
    mutation/*.jsonl    candidate rows {instance_id, mutant_id, outcome}
                        for the G_i of passing instances      (optional)

and writes

    <project>/<view>/instances.jsonl   one scored row per instance
    summary.json                       both aggregation modes per
                                       project/view and the 8-project mean
    report.md                          the same for people, headline
                                       `leaderboard`, `exact` beside it

A missing `behaviour.json` or `mutation/` means that measure was not run
(`--metrics exec`); its columns are then empty, never 0.  A `mutation/`
without `mutation.done.json` (`req2test.mutate`) is a stage that stopped
early, and so is one whose marker names other execution rows: both are
refused until `req2test evaluate` resumes the run.

A run whose root holds `subset.json` (`evaluate --instances/--sample`,
`validate`) evaluated part of a split: summary.json (`subset`) and report.md
mark it a SUBSET run, not comparable to the leaderboard.  A run whose root
holds `split.json` (`evaluate --split full`) evaluated the full split, which
the leaderboard does not cover: summary.json (`full_split`) and report.md
mark it NOT COMPARABLE.  Prediction files the engine rejected are listed per
instance (`disclosures.*.rejected_files`).  `benchmark.json` (`evaluate`) gives
the run's benchmark version, `benchmark_version` in summary.json; report.md
states it.

A 1.1 run gets benchmark 1.1's population
(`benchmark/config/benchmark_2.0_population.yml`): the instances on that list
are still scored into `instances.jsonl`, but no measure or disclosure counts
them, and summary.json (`population`) and report.md name them.  A run
directory without `benchmark.json` (a run merged from several hosts) is read
as 1.1, the only version this package evaluates.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Callable, Optional

from . import REPO_ROOT
from . import aggregate as A
from . import score as S
from .predictions import BENCHMARK_VERSIONS

SUMMARY_SCHEMA = "req2test.summary/1"
VIEWS = ("th", "ah")
HEADLINE = "leaderboard"
#: What each mode is, beside its heading in report.md.
MODE_NOTES = {
    HEADLINE: "the headline: the leaderboard's aggregation; "
              "`docs/metrics.md`",
    "exact": "each measure over the instances it is defined for; "
             "`docs/metrics.md`",
}
#: Fields of an `instances.jsonl` row, in order (INTERFACES.md plus the
#: scorer's companions and disclosures).
INSTANCE_FIELDS = (
    "instance_id", "project", "view", "outcome", "passed", "api_f1",
    "coverage_j", "recall", "kill_complete", "kill_complete_strict",
    "kill_complete_95", "mutation_status", "mutation_baseline",
    "behaviour_status", "n_gt_kills",
    "n_scored", "n_killed", "n_dropped", "n_crash_kills", "n_timeout_kills",
    "exclusion", "engine_outcome", "harness_version", "rejected_files")
#: `runs/<run_id>/subset.json`: written by `req2test evaluate --instances`
#: or `--sample` (and by `validate`); its presence marks a SUBSET run.
SUBSET_FILE = "subset.json"
SUBSET_NOTE = ("SUBSET run: not every instance of the split was evaluated, "
               "so its values are not comparable to the leaderboard")
#: `runs/<run_id>/split.json`: written by `req2test evaluate --split full`
#: (`{"split", "projects"}`); its presence marks a FULL-SPLIT run.
SPLIT_FILE = "split.json"
FULL_SPLIT_NOTE = ("FULL-SPLIT run: NOT COMPARABLE with the leaderboard, "
                   "which covers only the eval split")
POPULATION_NOTE = ("benchmark 1.1 population: these instances were scored, "
                   "and no measure counts them "
                   "(benchmark/config/benchmark_2.0_population.yml)")
#: `runs/<run_id>/benchmark.json`: `{"benchmark_version": ...}`, written by
#: `req2test evaluate` from the predictions (`req2test.predictions`).
BENCHMARK_FILE = "benchmark.json"


def work_root() -> Path:
    return Path(os.environ.get("REQ2TEST_HOME", "~/.req2test")).expanduser()


def run_dir(run_id: str, root: Optional[Path] = None) -> Path:
    return (root or work_root()) / "runs" / run_id


def _jsonl(path: Path) -> list:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _default_kit(project: str):
    from .kits import load_kit  # WP2
    return load_kit(project)


def kit_ids(kit, key: str) -> Optional[list]:
    """The kit's `behaviour/<key>.json` id list (`I_api`, `I_cov`), or None."""
    path = S._kit_root(kit) / "behaviour" / f"{key}.json"
    return json.loads(path.read_text()) if path.exists() else None


def finished_mutation(cell: Path) -> dict:
    """The `mutation.done.json` of a cell with a `mutation/` directory;
    refuses a stage that has not finished or predates `exec.jsonl`."""
    from .execute import sha256_file
    from .mutate import DONE_FILE, read_done
    done = read_done(cell)
    if done is None:
        raise ValueError(
            f"{cell}: the mutation stage did not finish ({DONE_FILE} is "
            f"missing); rerun `req2test evaluate` with the same --run-id to "
            f"resume it")
    if done.get("exec_sha256") != sha256_file(cell / "exec.jsonl"):
        raise ValueError(
            f"{cell}: the mutation stage was planned from other execution "
            f"rows than exec.jsonl now holds; rerun `req2test evaluate` with "
            f"the same --run-id to bring it up to date")
    return done


def cell_instances(kit, project: str, view: str, cell: Path) -> list:
    """The scored `instances.jsonl` rows of one project/view directory.

    API F1 and coverage are kept only for passes in the kit's `I_api` and
    `I_cov` (when the kit has the lists): the measures are defined there.
    `mutation_baseline` is the class of a pass's unmutated mutation baseline
    (`passed`, `failed` or `infrastructure`) when mutation ran.
    `rejected_files` are the prediction files the engine refused to write
    (not test code, a `.feature` file, a path outside `repo/`, or on
    coddy-agent a file outside the instance's set), as its execution row
    lists them (`[{file_path, why}]`).
    """
    exec_rows = _jsonl(cell / "exec.jsonl")
    seen = set()
    for row in exec_rows:
        iid = S.instance_id_of(row)
        if iid in seen:
            raise ValueError(f"{cell / 'exec.jsonl'}: two execution rows for "
                             f"{iid}; keep one row per instance")
        seen.add(iid)
    i_api, i_cov = (kit_ids(kit, k) for k in ("I_api", "I_cov"))
    i_api = None if i_api is None else set(i_api)
    i_cov = None if i_cov is None else set(i_cov)
    behaviour = None
    if (cell / "behaviour.json").exists():
        behaviour = json.loads((cell / "behaviour.json").read_text())
    mutation, baselines = None, {}
    if (cell / "mutation").is_dir():
        baselines = finished_mutation(cell).get("baselines") or {}
        mutation = [row for path in sorted((cell / "mutation").glob("*.jsonl"))
                    for row in _jsonl(path)]
    scored = S.score_instances(kit, exec_rows, mutation)
    rows = []
    for exec_row, s in zip(exec_rows, scored):
        iid = s["instance_id"]
        b = (behaviour or {}).get(iid) or {}
        row = {**s, "project": project, "view": view,
               "behaviour_status": "measured" if behaviour is not None
               else S.NOT_RUN,
               "api_f1": b.get("api_f1") if s["passed"] and (
                   i_api is None or iid in i_api) else None,
               "coverage_j": b.get("coverage_j") if s["passed"] and (
                   i_cov is None or iid in i_cov) else None,
               "mutation_baseline": baselines.get(iid) if s["passed"]
               else None,
               "harness_version": exec_row.get("harness_version"),
               "rejected_files": exec_row.get("rejected_files") or []}
        rows.append({k: row.get(k) for k in INSTANCE_FIELDS})
    return rows


def _shown(path: str) -> str:
    """A path under the clone relative to it, so summaries name no host."""
    try:
        return str(Path(path).resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def population_exclusions(benchmark_version: Optional[str]) -> Optional[dict]:
    """The engine's population list for a benchmark version, or None for none.

    For 1.1 it is `benchmark/config/benchmark_2.0_population.yml`, read with
    the engine's `r2t.bench.population`: the returned document's `excluded`
    is `{instance_id: reason}`.
    """
    if benchmark_version is None:
        return None
    if benchmark_version not in BENCHMARK_VERSIONS:
        raise ValueError(f"benchmark version must be one of "
                         f"{BENCHMARK_VERSIONS}, not {benchmark_version!r}")
    from r2t.bench import population as P   # the engine, on sys.path (score)
    try:
        return P.load_benchmark_population()
    except FileNotFoundError:
        raise FileNotFoundError(
            f"benchmark 1.1's population list {P.BENCHMARK_POPULATION} is "
            f"not in this checkout; 1.1 measures need it") from None


def _i_sets_for(kits: dict) -> dict:
    """Bundled I-set counts, replaced by the kit's id lists where it has them."""
    i_sets = A.load_i_sets()
    for project, kit in kits.items():
        entry = dict(i_sets[project])
        for key in ("I_api", "I_cov"):
            ids = kit_ids(kit, key)
            if ids is not None:
                entry[key] = ids
        i_sets[project] = entry
    return i_sets


def build(run: Path, kit_for: Optional[Callable] = None, ci: int = 0) -> dict:
    """Score every project/view of a run; write instances.jsonl; summarize.

    `kit_for(project)` returns the project's kit (default: the installed
    kit, `req2test.kits.load_kit`).  The run's benchmark version
    (`BENCHMARK_FILE`) chooses the population: "1.1" applies that version's
    (`population_exclusions`); a run without the file is read as 1.1.
    """
    version = BENCHMARK_VERSIONS[-1]
    if (run / BENCHMARK_FILE).is_file():
        version = json.loads((run / BENCHMARK_FILE).read_text(
            encoding="utf-8"))["benchmark_version"]
    population = population_exclusions(version)
    excluded = None if population is None else population["excluded"]
    kit_for = kit_for or _default_kit
    instances, kits = [], {}
    for project_dir in sorted(p for p in run.iterdir() if p.is_dir()):
        project = project_dir.name
        views = [v for v in VIEWS if (project_dir / v / "exec.jsonl").exists()]
        if not views:
            continue
        kits[project] = kit_for(project)
        for view in views:
            rows = cell_instances(kits[project], project, view,
                                  project_dir / view)
            with open(project_dir / view / "instances.jsonl", "w",
                      encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row) + "\n")
            instances.extend(rows)
    if not instances:
        raise FileNotFoundError(f"{run} has no <project>/<view>/exec.jsonl")
    i_sets = _i_sets_for(kits)
    summary = {
        "schema": SUMMARY_SCHEMA, "run_id": run.name, "headline": HEADLINE,
        "benchmark_version": version,
        "modes": {mode: A.aggregate(instances, mode, i_sets=i_sets,
                                    excluded=excluded)
                  for mode in (HEADLINE, "exact")},
        "disclosures": disclosures(A.without_excluded(instances, excluded)),
        "rules": {p: {**S.reference(k).rules.to_json(),
                      "nondeterministic_excluded":
                          list(S.reference(k).nondeterministic)}
                  for p, k in kits.items()},
    }
    if (run / SUBSET_FILE).is_file():
        summary["subset"] = {
            "note": SUBSET_NOTE,
            **json.loads((run / SUBSET_FILE).read_text(encoding="utf-8"))}
    if (run / SPLIT_FILE).is_file():
        summary["full_split"] = {
            "note": FULL_SPLIT_NOTE,
            **json.loads((run / SPLIT_FILE).read_text(encoding="utf-8"))}
    if population is not None:
        left_out = {r["instance_id"]: excluded[r["instance_id"]]
                    for r in instances if r["instance_id"] in excluded}
        summary["population"] = {
            "benchmark_version": version,
            "note": POPULATION_NOTE, "list": _shown(population["path"]),
            "excluded_n": len(left_out),
            "excluded": dict(sorted(left_out.items()))}
    if ci:
        summary["ci"] = {"method": "cluster bootstrap over feature files, "
                                   "95% percentile intervals",
                         "n_boot": ci,
                         "exact": A.bootstrap(instances, "exact",
                                              i_sets=i_sets, n_boot=ci,
                                              excluded=excluded)}
    return summary


def disclosures(instances: list) -> dict:
    """Per project/view counts a reader needs beside the measures."""
    out: dict = {}
    for r in instances:
        d = out.setdefault(f"{r['project']}/{r['view']}", {
            "infrastructure_excluded": [], "outside_ladder_excluded": {},
            "unscored_passes": [], "not_scorable_passes": [],
            "baseline_failed": [], "baseline_infrastructure": [],
            "dropped_pairs": 0, "crash_kills": 0, "timeout_kills": 0,
            "kill_complete_with_dropped_pairs": 0, "rejected_files": {}})
        if r.get("rejected_files"):
            d["rejected_files"][r["instance_id"]] = r["rejected_files"]
        if r["exclusion"] == S.OUTSIDE_LADDER:
            d["outside_ladder_excluded"][r["instance_id"]] = r["engine_outcome"]
        elif r["outcome"] == S.EXCLUDED:
            d["infrastructure_excluded"].append(r["instance_id"])
        if r["mutation_status"] == S.UNSCORED:
            d["unscored_passes"].append(r["instance_id"])
            if r.get("mutation_baseline") in ("failed", "infrastructure"):
                d["baseline_" + r["mutation_baseline"]].append(
                    r["instance_id"])
        if r["mutation_status"] == S.NOT_SCORABLE:
            d["not_scorable_passes"].append(r["instance_id"])
        d["dropped_pairs"] += r["n_dropped"]
        d["crash_kills"] += r["n_crash_kills"]
        d["timeout_kills"] += r["n_timeout_kills"]
        d["kill_complete_with_dropped_pairs"] += (
            r["kill_complete"] and not r["kill_complete_strict"])
    return out


# --------------------------------------------------------------- markdown
LABELS = {"pass_at_1": "Pass@1", "kill_complete_at_1": "KillComplete@1",
          "api_f1": "API F1", "coverage_j": "Coverage J",
          "mutation_recall": "Mutation R",
          "kill_complete_strict_at_1": "KillComplete@1 (strict)",
          "kill_complete_95_at_1": "KillComplete@1 (recall ≥ 0.95)"}


def _pct(x) -> str:
    return "–" if x is None else f"{100 * x:.1f}"


def _coverage_note(mean: dict) -> str:
    """How far a mean is from the 8-project mean ("" when it is one)."""
    if mean["complete"]:
        return ""
    if mean["projects"] == len(A.PROJECTS):
        return " (8 projects, not all complete)"
    return f" ({mean['projects']} of {len(A.PROJECTS)} projects)"


def describe_rejected(files: list) -> str:
    """`path (why)` for each file the engine rejected, joined."""
    return "; ".join(
        f"`{f.get('file_path')}`"
        + (f" service `{f['service_id']}`" if f.get("service_id") else "")
        + f" ({f.get('why')})" for f in files)


def describe_subset(subset: dict) -> str:
    """The selection of a SUBSET run, for people."""
    if subset.get("selection") == "sample":
        how = (f"a seeded sample of {subset.get('sample')} instance(s) per "
               f"project (seed {subset.get('seed')})")
    else:
        how = f"the instances listed in {subset.get('instances_file')}"
    counts = ", ".join(f"{p} {c['n']} of {c['of']}" for p, c in
                       sorted((subset.get("projects") or {}).items()))
    return (f"Selection: {how} from the {subset.get('split')} split"
            + (f" ({counts})" if counts else "") + ".")


def markdown(summary: dict) -> str:
    subset = summary.get("subset")
    full = summary.get("full_split")
    version = summary.get("benchmark_version")
    lines = [f"# Req2Test-Bench report: run `{summary['run_id']}`", "",
             f"Benchmark version: {version}." if version else
             "Benchmark version: not stated in the predictions "
             "(`benchmark_version`).", ""]
    if full:
        lines += [f"**{FULL_SPLIT_NOTE}.** This run evaluated the "
                  f"{full.get('split')} split of "
                  f"{', '.join(full.get('projects') or [])}.", ""]
    if subset:
        lines += [f"**{SUBSET_NOTE}.** {describe_subset(subset)}", ""]
    population = summary.get("population")
    if population:
        reasons = sorted(set(population["excluded"].values()))
        lines += [f"**Benchmark {population['benchmark_version']} "
                  f"population.** {population['excluded_n']} instance(s) of "
                  f"this run are outside it"
                  + (f" ({', '.join(reasons)})" if reasons else "")
                  + ": they were scored into `instances.jsonl`, and no "
                  "measure or disclosure below counts them; summary.json "
                  "(`population`) lists them "
                  "(`benchmark/config/benchmark_2.0_population.yml`).", ""]
    if full:
        comparable = (" of the leaderboard, but this run is NOT COMPARABLE "
                      "with the leaderboard (`results/leaderboard.md` covers "
                      "only the eval split)")
    elif subset:
        comparable = " of the leaderboard"
    else:
        comparable = (" of `results/leaderboard.md`, so a run of all eight "
                      "projects compares with the leaderboard")
    lines += ["Values are percentages, and a non-passing test counts as 0 in "
              "every column. The headline is `leaderboard` mode, the "
              "aggregation" + comparable + ". `exact` mode is printed beside "
              "it (`docs/metrics.md`).",
              ""]
    for mode in (HEADLINE, "exact"):
        agg = summary["modes"][mode]
        metrics = A.METRICS + (A.COMPANIONS if mode == "exact" else ())
        lines += [f"## Mode `{mode}` ({MODE_NOTES[mode]})", "",
                  "| Project | View | N | " + " | ".join(
                      LABELS[m] for m in metrics) + " |",
                  "|---|---|---:|" + "---:|" * len(metrics)]
        for cell in agg["cells"].values():
            lines.append(f"| {cell['project']} | {cell['view'].upper()} | "
                         f"{cell['n']} | " + " | ".join(
                             _pct(cell[m]) for m in metrics) + " |")
        for view, row in agg["mean"].items():
            # A value is the 8-project mean only when all eight projects are
            # complete and contribute to it; otherwise its count is printed.
            label = "8-project mean" if row["complete"] else "mean"
            lines.append(f"| **{label}** | {view.upper()} | | " + " | ".join(
                f"**{_pct(row[m]['value'])}**" + _coverage_note(row[m])
                for m in metrics) + " |")
        lines.append("")
    if "ci" in summary:
        lines += ["## 95% intervals (exact mode, cluster bootstrap over "
                  "feature files)", ""]
        for view, row in summary["ci"]["exact"].items():
            lines.append(f"- {view.upper()}: " + "; ".join(
                f"{LABELS[m]} {_pct(lo)}–{_pct(hi)}"
                for m, (lo, hi) in row.items() if m in LABELS))
        lines.append("")
    lines += ["## Disclosures", ""]
    cells = summary["modes"][HEADLINE]["cells"]
    for key, d in summary["disclosures"].items():
        parts = []
        if cells.get(key, {}).get("population_excluded"):
            parts.append(f"{len(cells[key]['population_excluded'])} "
                         f"instance(s) outside the benchmark "
                         f"{population['benchmark_version']} population "
                         f"(scored, counted in no measure)")
        if d["infrastructure_excluded"]:
            parts.append(f"{len(d['infrastructure_excluded'])} instance(s) "
                         f"excluded for harness infrastructure failures")
        if d["outside_ladder_excluded"]:
            outcomes = sorted(set(d["outside_ladder_excluded"].values()))
            parts.append(f"{len(d['outside_ladder_excluded'])} instance(s) "
                         f"excluded with an outcome outside the ladder "
                         f"({', '.join(outcomes)})")
        if d["unscored_passes"]:
            why = [f"{len(d[key])} {text}" for key, text in (
                ("baseline_failed", "failed the unmutated mutation baseline"),
                ("baseline_infrastructure",
                 "hit infrastructure in that baseline")) if d.get(key)]
            parts.append(f"{len(d['unscored_passes'])} unscored pass(es) "
                         f"(no mutation row; not kill-complete"
                         + "".join(f"; {w}" for w in why) + ")")
        if d["not_scorable_passes"]:
            parts.append(f"{len(d['not_scorable_passes'])} not-scorable "
                         f"pass(es) (no scored G_i pair)")
        if d["dropped_pairs"]:
            parts.append(f"{d['dropped_pairs']} dropped G_i pair(s); "
                         f"{d['kill_complete_with_dropped_pairs']} "
                         f"kill-complete pass(es) had one")
        if d["crash_kills"]:
            parts.append(f"{d['crash_kills']} crash kill(s)")
        if d["timeout_kills"]:
            parts.append(f"{d['timeout_kills']} timeout kill(s)")
        rejected = d.get("rejected_files") or {}
        if rejected:
            parts.append(f"{len(rejected)} instance(s) with prediction files "
                         f"the engine rejected (listed below, with its reason)")
        lines.append(f"- {key}: " + ("; ".join(parts) if parts else "none"))
        for iid, files in sorted(rejected.items()):
            lines.append(f"  - `{iid}`: {describe_rejected(files)}")
    lines += ["", "## Scoring rules", ""]
    for project, rules in summary["rules"].items():
        extra = (f"; host-dependent mutants disclosed: "
                 f"{', '.join(rules['known_host_dependent'])}"
                 if rules["known_host_dependent"] else "")
        if rules.get("nondeterministic_excluded"):
            extra += (f"; nondeterministic mutants excluded from G_i: "
                      f"{', '.join(rules['nondeterministic_excluded'])}")
        lines.append(f"- {project}: {rules['family']} family, candidate "
                     f"timeout = {rules['candidate_timeout']}, crash kill = "
                     f"{str(rules['crash_kill']).lower()}{extra}")
    return "\n".join(lines) + "\n"


def write(run: Path, summary: dict) -> None:
    (run / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    (run / "report.md").write_text(markdown(summary))


# -------------------------------------------------------------------- CLI
def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run-id", required=True,
                        help="run under $REQ2TEST_HOME/runs/")
    parser.add_argument("--work-dir", type=Path, default=None,
                        help="work root instead of $REQ2TEST_HOME "
                             "(~/.req2test)")
    parser.add_argument("--ci", type=int, default=0, metavar="N",
                        help="add cluster-bootstrap intervals over feature "
                             "files with N replicates")


def main(args: argparse.Namespace) -> int:
    """`req2test report`; errors propagate to `req2test.cli.main`."""
    run = run_dir(args.run_id, args.work_dir)
    if not run.is_dir():
        raise FileNotFoundError(f"no run {args.run_id!r} at {run}")
    summary = build(run, ci=args.ci)
    write(run, summary)
    for view, row in summary["modes"][HEADLINE]["mean"].items():
        print(f"{view}: " + "  ".join(
            f"{LABELS[m]} {_pct(row[m]['value'])}" for m in A.METRICS))
    print(f"wrote {run / 'summary.json'} and {run / 'report.md'}")
    return 0
