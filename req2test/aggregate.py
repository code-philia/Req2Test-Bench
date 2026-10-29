"""Per project/view metrics and the 8-project mean (harness plan E.4).

Two modes over the instance rows of one configuration (`instances.jsonl`):

`exact` (product default), per project and view, with N the instances,
E the executed ones (N minus `infrastructure_excluded`) and P the passes:

    Pass@1         = |P| / |E|
    KillComplete@1 = KC / N
    API F1         = sum over P of F1 / |I_api ∩ E|
    Coverage J     = sum over P of J  / |I_cov ∩ E|
    Mutation R     = sum over P of recall / |E|   (unscored passes score 0)

`leaderboard` is the aggregation of the leaderboard and the paper's tables:

    pass = p / den            kill = kc / N
    api  = f1 * api_n / (|I_api| * den / N)
    cov  = J * p / (|I_cov| * den / N)
    mut  = full_recall_macro * p / den

with f1, J and full_recall_macro the means over the passes that have the
value, `api_n` the number of passes with an API value, and den = |E|.
`|I_api|` and `|I_cov|` are the per-project counts of `data/i_sets.json`,
or the run's instances in the kit's id lists (`behaviour/I_api.json`); a
count for a run that covers part of a project is scaled by N/census_n.

Non-passing tests score 0 in every measure.  The 8-project mean weights the
projects equally.  A measure a cell did not run (behaviour or mutation
`not_run`) is None, never 0.

A benchmark population's exclusion list (`excluded`, benchmark 1.1's from
`req2test.report.population_exclusions`) takes its instances out before
anything is counted: their rows were scored, but they are in no N, E or P,
and each cell's census is the population's (`census_n` minus the project's
listed instances).  The I-sets stay as given: id lists are intersected with
the remaining instances, and counts are scaled as for a partial run.
"""
from __future__ import annotations

import json
import random
import statistics
from pathlib import Path
from typing import Iterable, Optional

from .score import EXCLUDED, NOT_PASSED, NOT_RUN, SCORED

MODES = ("exact", "leaderboard")
METRICS = ("pass_at_1", "kill_complete_at_1", "api_f1", "coverage_j",
           "mutation_recall")
#: Companion measures (exact counts, printed beside the primary ones).
COMPANIONS = ("kill_complete_strict_at_1", "kill_complete_95_at_1")
PROJECTS = ("python-docx", "algorand-sdk", "coddy-agent", "kapua",
            "e-petitions", "sylius", "prestashop", "coreshop")
DATA = Path(__file__).resolve().parent / "data"


def load_i_sets(path: Optional[Path] = None) -> dict:
    """`{project: {"I_api", "I_cov", "census_n"}}` (counts or id lists)."""
    with open(path or DATA / "i_sets.json", encoding="utf-8") as fh:
        doc = json.load(fh)
    return doc.get("projects", doc)


def _size(value) -> int:
    return value if isinstance(value, int) else len(value)


# ------------------------------------------------------------ per cell
def cell_counts(rows: Iterable[dict]) -> dict:
    """The sums one cell's measures are made of."""
    rows = list(rows)
    c = {"n": len(rows), "excluded": 0, "passes": 0, "kc": 0, "kc_strict": 0,
         "kc_95": 0, "api_sum": 0.0, "api_n": 0, "cov_sum": 0.0, "cov_n": 0,
         "recall_sum": 0.0, "recall_n": 0, "unscored_passes": 0,
         "behaviour_run": True, "mutation_run": True}
    for r in rows:
        if r.get("behaviour_status") == NOT_RUN:
            c["behaviour_run"] = False
        if r.get("mutation_status") == NOT_RUN:
            c["mutation_run"] = False
        if r.get("outcome") == EXCLUDED:
            c["excluded"] += 1
            continue
        if not r.get("passed"):
            continue
        c["passes"] += 1
        c["kc"] += bool(r.get("kill_complete"))
        c["kc_strict"] += bool(r.get("kill_complete_strict"))
        c["kc_95"] += bool(r.get("kill_complete_95"))
        if r.get("api_f1") is not None:
            c["api_sum"] += r["api_f1"]
            c["api_n"] += 1
        if r.get("coverage_j") is not None:
            c["cov_sum"] += r["coverage_j"]
            c["cov_n"] += 1
        if r.get("recall") is not None:
            c["recall_sum"] += r["recall"]
            c["recall_n"] += 1
        elif r.get("mutation_status", SCORED) not in (SCORED, NOT_PASSED,
                                                      NOT_RUN):
            c["unscored_passes"] += 1
    return c


def _i_set_size(iset: dict, key: str, rows: Optional[list], den: int,
                n: int) -> float:
    """`|I_key ∩ E|`: exact with id lists, else the count pro rata."""
    value = iset[key]
    if rows is not None and not isinstance(value, int):
        ids = set(value)
        return sum(1 for r in rows if r["instance_id"] in ids
                   and r.get("outcome") != EXCLUDED)
    return _size(value) * den / iset.get("census_n", n)


def _run_counts(iset: dict, rows: list) -> dict:
    """An I-set entry in counts: id lists become their size within the run's
    own instances, whose census is then the run (a complete run gives the
    project's counts unchanged)."""
    if all(isinstance(iset[k], int) for k in ("I_api", "I_cov")):
        return iset
    out = {"census_n": len(rows)}
    for key in ("I_api", "I_cov"):
        ids = set(iset[key])
        out[key] = sum(1 for r in rows if r["instance_id"] in ids)
    return out


def exact_values(counts: dict, iset: dict, rows: Optional[list] = None) -> dict:
    """The `exact` mode measures of one cell."""
    n, p = counts["n"], counts["passes"]
    den = n - counts["excluded"]
    v = dict.fromkeys(METRICS + COMPANIONS)
    if den:
        v["pass_at_1"] = p / den
    if counts["mutation_run"] and n:
        v["kill_complete_at_1"] = counts["kc"] / n
        v["kill_complete_strict_at_1"] = counts["kc_strict"] / n
        v["kill_complete_95_at_1"] = counts["kc_95"] / n
        if den:
            v["mutation_recall"] = counts["recall_sum"] / den
    if counts["behaviour_run"] and den:
        # An empty |I ∩ E| leaves the measure undefined for this cell.
        i_api = _i_set_size(iset, "I_api", rows, den, n)
        i_cov = _i_set_size(iset, "I_cov", rows, den, n)
        v["api_f1"] = counts["api_sum"] / i_api if i_api else None
        v["coverage_j"] = counts["cov_sum"] / i_cov if i_cov else None
    return v


def paper_cell(counts: dict) -> dict:
    """The paper generator's cell shape (`data/cells.json`) from counts."""
    p = counts["passes"]
    return {
        "population": counts["n"], "pass": p,
        "pass_den": counts["n"] - counts["excluded"],
        "kc": counts["kc"] if counts["mutation_run"] else None,
        "api_f1": (counts["api_sum"] / counts["api_n"]
                   if counts["behaviour_run"] and counts["api_n"] else None),
        "api_n": counts["api_n"] if counts["behaviour_run"] else None,
        "cov_j": (counts["cov_sum"] / counts["cov_n"]
                  if counts["behaviour_run"] and counts["cov_n"] else None),
        "mut_recall": (counts["recall_sum"] / counts["recall_n"]
                       if counts["mutation_run"] and counts["recall_n"]
                       else None),
    }


def leaderboard_values(cell: dict, iset: dict) -> dict:
    """`make_overall.cell_values` of one cell, keyed by `METRICS`.

    `cell` has the generator's fields: population, pass, pass_den, kc,
    api_f1, api_n, cov_j, mut_recall (None where not measured).  The I-set
    counts are scaled by den / census_n, which is the generator's den / N
    for a complete cell.
    """
    n, den, p = cell["population"], cell["pass_den"], cell.get("pass")
    v = dict.fromkeys(METRICS)
    if p is None or not den:
        return v
    scale = den / iset.get("census_n", n)
    v["pass_at_1"] = p / den
    if cell.get("kc") is not None:
        v["kill_complete_at_1"] = cell["kc"] / n
    # An empty I-set leaves the measure undefined (a partial run without
    # one such instance); a complete cell always has one.
    i_api_e = _size(iset["I_api"]) * scale
    i_cov_e = _size(iset["I_cov"]) * scale
    if i_api_e:
        if cell.get("api_n") == 0 or p == 0:
            v["api_f1"] = 0.0
        elif cell.get("api_f1") is not None and cell.get("api_n") is not None:
            v["api_f1"] = cell["api_f1"] * cell["api_n"] / i_api_e
    if i_cov_e:
        if p == 0:
            v["coverage_j"] = 0.0
        elif cell.get("cov_j") is not None:
            v["coverage_j"] = cell["cov_j"] * p / i_cov_e
    if cell.get("kc") is not None:
        if p == 0:
            v["mutation_recall"] = 0.0
        elif cell.get("mut_recall") is not None:
            v["mutation_recall"] = cell["mut_recall"] * p / den
    return v


# ------------------------------------------------------------- macro
def macro(cells: dict, metrics: Iterable[str] = METRICS) -> dict:
    """Equal-weight mean over projects, per view.

    `cells` is `{(project, view): values}`.  Returns `{view: {metric:
    {"value", "projects"}}}`; a metric no project measured is None.  Each
    metric carries its own count of contributing projects.
    """
    out: dict = {}
    for view in sorted({v for _, v in cells}):
        out[view] = {}
        for m in metrics:
            xs = [vals[m] for (_, v), vals in sorted(cells.items())
                  if v == view and vals.get(m) is not None]
            out[view][m] = {"value": statistics.mean(xs) if xs else None,
                            "projects": len(xs)}
    return out


def _group(instances: Iterable[dict]) -> dict:
    groups: dict = {}
    for r in instances:
        groups.setdefault((r["project"], r["view"]), []).append(r)
    return groups


def without_excluded(instances: Iterable[dict],
                     excluded: Optional[dict]) -> list:
    """The instances a population counts: all of them unless `excluded`."""
    instances = list(instances)
    if not excluded:
        return instances
    return [r for r in instances if r["instance_id"] not in excluded]


def aggregate(instances: Iterable[dict], mode: str = "exact", *,
              i_sets: Optional[dict] = None,
              excluded: Optional[dict] = None) -> dict:
    """Per project/view measures and the 8-project mean of one run.

    `instances` are `instances.jsonl` rows (`project`, `view`, `outcome`,
    `passed`, `api_f1`, `coverage_j`, `recall`, `kill_complete`, ...).
    `excluded` (`{instance_id: reason}`) is a population's exclusion list;
    each cell then also lists its `population_excluded` instances.
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, not {mode!r}")
    i_sets = load_i_sets() if i_sets is None else i_sets
    instances = list(instances)
    left_out = _group(r for r in instances
                      if excluded and r["instance_id"] in excluded)
    cells, values = {}, {}
    for (project, view), rows in sorted(
            _group(without_excluded(instances, excluded)).items()):
        iset = i_sets[project]
        counts = cell_counts(rows)
        if mode == "exact":
            vals = exact_values(counts, iset, rows)
        else:
            vals = leaderboard_values(paper_cell(counts),
                                   _run_counts(iset, rows))
        values[(project, view)] = vals
        census = iset.get("census_n")
        if excluded is not None and census is not None:
            census -= sum(1 for iid in excluded
                          if iid.split("/", 1)[0] == project)
        cells[f"{project}/{view}"] = {
            "project": project, "view": view, "n": counts["n"],
            "census_n": census,
            "complete": counts["n"] == census,
            "excluded": counts["excluded"], "passes": counts["passes"],
            "kill_complete": counts["kc"] if counts["mutation_run"] else None,
            "unscored_passes": counts["unscored_passes"],
            **vals}
        if excluded is not None:
            cells[f"{project}/{view}"]["population_excluded"] = sorted(
                r["instance_id"] for r in left_out.get((project, view), ()))
    metrics = METRICS + (COMPANIONS if mode == "exact" else ())
    means = macro(values, metrics)
    for view, row in means.items():
        projects = {p for p, v in values if v == view}
        whole = projects == set(PROJECTS) and all(
            cells[f"{p}/{view}"]["complete"] for p in projects)
        # The 8-project mean: all eight projects complete and contributing.
        for m in metrics:
            row[m]["complete"] = whole and row[m]["projects"] == len(PROJECTS)
        row["complete"] = all(row[m]["complete"] for m in metrics)
    return {"mode": mode, "cells": cells, "mean": means}


# ---------------------------------------------------------- bootstrap
def feature_file(instance_id: str) -> str:
    """The cluster of an instance: its feature file (id minus `:line`)."""
    return instance_id.rsplit(":", 1)[0]


def bootstrap(instances: Iterable[dict], mode: str = "exact", *,
              i_sets: Optional[dict] = None, n_boot: int = 1000,
              seed: int = 20261004, alpha: float = 0.05,
              excluded: Optional[dict] = None) -> dict:
    """Cluster-bootstrap CIs of the 8-project means over feature files.

    Each replicate resamples, independently per project and view, that
    cell's feature files with replacement and recomputes the mean.  Returns
    `{view: {metric: [low, high]}}` (percentile intervals).  `excluded`
    instances are left out first, as in `aggregate`.
    """
    i_sets = load_i_sets() if i_sets is None else i_sets
    groups = _group(without_excluded(instances, excluded))
    clusters = {}
    for key, rows in groups.items():
        by_file: dict = {}
        for r in rows:
            by_file.setdefault(feature_file(r["instance_id"]), []).append(r)
        clusters[key] = list(by_file.values())
    rng = random.Random(seed)
    draws: dict = {}
    for _ in range(n_boot):
        sample = []
        for key in sorted(clusters):
            files = clusters[key]
            for _ in range(len(files)):
                sample.extend(files[rng.randrange(len(files))])
        # I-set counts scale with each draw's executed instances (N/census_n).
        result = aggregate(sample, mode, i_sets=i_sets)
        for view, row in result["mean"].items():
            for m, cell in row.items():
                if isinstance(cell, dict) and cell["value"] is not None:
                    draws.setdefault(view, {}).setdefault(m, []).append(
                        cell["value"])
    out: dict = {}
    for view, metrics in draws.items():
        out[view] = {}
        for m, xs in metrics.items():
            xs.sort()
            lo = xs[int(alpha / 2 * (len(xs) - 1))]
            hi = xs[int((1 - alpha / 2) * (len(xs) - 1))]
            out[view][m] = [lo, hi]
    return out
