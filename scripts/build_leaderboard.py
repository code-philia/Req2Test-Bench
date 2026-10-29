#!/usr/bin/env python3
"""Build the leaderboard: `results/leaderboard.json` and
`results/leaderboard.md`, and (with `--readme`) the table in `README.md`.

Audience: maintainers.  Four modes, all aggregating with
`req2test.aggregate` in `leaderboard` mode.  The first three build the
paper's board, `req2test/data/leaderboard_paper.json` (the configurations
the paper reports, both views, 2,051 instances); the fourth builds the
published board from it and the benchmark 1.1 rows.

**The board (`--v2-cells FILE`).**  It needs no research checkout.  It
takes the target-hidden rows and cells of the paper's board (`--paper-board`)
and adds the benchmark 1.1 rows, whose cells `FILE` holds (schema
`r2t.board-cells-v2/1`: per row `label`, `system`, `model`, `reasoning`, per
cell the fields of the paper cells, with the I-sets of the 1.1 population).
It checks that the file's exclusions are the engine's 1.1 population list,
recomputes every value and row mean and checks them against the file.  A row
mean over fewer than eight projects is not given (null, printed `–`), except
where a cell is still `pending`: that mean is printed as the placeholder
`PENDING` until the file is complete.  It writes `OUT/leaderboard.json`,
`OUT/leaderboard.md` and, with `--readme PATH`, the table between the
`README_START` and `README_END` markers of PATH (sorted by Pass@1).

**Base cells (`--research R`).**  It reads the committed cells of the
research repository through `git show` at one commit, never its working
tree, and writes them to `req2test/data/leaderboard_base.json` (`--base`):

* 96 cells of six configurations: `experiments/*/paper-cells/*.json`
  (block `primary`), the fields the paper's table generator reads;
* 16 cells of Codex CLI / DeepSeek-V4.1-Flash with reasoning off:
  `experiments/codex-deepseek-reasoning-off/results/summary.json`, the
  Pass@1 denominator from `results/per-item/<cell>.items.jsonl` as the
  paper's generator read it: rows outside the six outcome categories leave
  the denominator;
* the three attempt exclusions, `req2test/data/attempt_exclusions.json`.

With `--paper-table` it checks every value against a printed table (to 0.1)
and fails on any difference.

**Supplementary cells (`--supplement R --renders D`).**  The eighth row,
Claude Code / Claude Sonnet 5.5 (`SUPPLEMENT_CONFIGURATIONS`), has no
paper-cell file.  This mode writes its 16 cells, in the fields of the base
cells, to `req2test/data/claude_code_sonnet55_cells.json`
(`--supplement-cells`).  It reads the arm's committed record at
`--supplement-commit` (default `7d27db13`) with the paper cells'
definitions:

* `<SONNET_RECORD>/<project>/<cell>-evidence.json`: Pass@1 count and
  denominator (`generation.pass`; an infrastructure row leaves the
  denominator, as in the paper cells), KillComplete (`mutation.kill_complete`,
  each project's paper definition, the twin's lead) and Mutation recall
  (`mutation.full_recall`, the mean full-gold recall over the scored passes);
* API F1 and its count of scored passes (`api.values.f1`, `api.n_scored`)
  and coverage J (`coverage.values.jaccard`) from each cell's finalize render
  `D/<cell>/results.json` (the arm's preserved generation outputs), which
  must have the sha256 the evidence names; for algorand-sdk, as in its paper
  cells, API F1 comes from the labelled reporting-only render
  (`generation.render.api_reporting_only`).

It stops unless every API F1 and coverage J equals the committed render
`<cell>-results.md` (or `-results.api.md`) to its printed 0.001, and unless
the evidence's figures for the twin (pass, KillComplete, recall) equal the
twin's paper cell (`claude-code-deepseek-flash`) at `--commit`, which shows
that the evidence's quantities are those of the paper cells.

**The paper's board (`--h25-manifest M`).**  It needs no research checkout.
It starts from the base cells in `--base` and the supplementary cells in
`--supplement-cells`, and replaces every cell of the four projects whose
scoring rules changed at harness 25 (`H25_PROJECTS`) with the re-scored
cell the manifest names.  The other four projects keep their base or
supplementary cells.  It writes the paper's board to `--paper-board`.
The manifest is JSON, `{"cells": [entry, ...]}` (a
bare list is accepted too), one entry per configuration, affected project
and view:

    {"config": "codex-ds", "project": "coreshop", "view": "th",
     "path": "coreshop/codex-ds__th/result.json", "sha256": "<hex>"}

`config` is a row id of `CONFIGURATIONS` or `SUPPLEMENT_CONFIGURATIONS`,
`view` is `th` or `ah`, and `path` is relative to the manifest's directory.
An entry may instead keep the base cell, for a cell with no affected
attempt: `{"config", "project", "view", "keep_recorded":
"<reason>"}`.  Every one of the 8 x 4 x 2 cells needs an entry, and the
supplementary file every one of its 16 cells; a missing cell, a file whose
sha256 differs, or a cell whose KillComplete is not final stops the build.

Each cell file is one per-cell result of the re-scoring, in one of two
formats.  The re-scoring's own format, `h25-cell/1`:

    {"schema": "h25-cell/1", "project", "cell", "config",
     "view": "target_hidden" | "all_hidden", "harness_version": 25,
     "recorded": M, "rebuilt": M, "gates": {"gate2": "pass", ...},
     "lost_passes": [...], "files": {"results_rebuilt": ..., ...}}
    M = {"passed", "denominator", "pass_rate", "excluded_infrastructure",
         "kill_complete", "recall_mean", "recall_n", "api_f1",
         "coverage_jaccard"}

It has no count of the passes with an API value, which the leaderboard API F1
scales by; the builder reads it from the render `files.results_rebuilt`
names (`api.n_scored`) and records that file's sha256.  A cell with an API
F1 whose render is not beside the cell file, or has no `api.n_scored`,
stops the build.  Or the stub agreed
before that format existed:

    {"recorded": {"pass": {"count", "denominator", "excluded"}},
     "rebuilt":  {"pass": {"count", "denominator", "excluded"},
                  "kill_complete": int, "recall_mean": float,
                  "api_f1": float, "api_n": int, "coverage_j": float},
     "gates": {...}, "sources": {...}}

In both, the recorded pass count must equal that of the cell it replaces
(the base cell, or for Sonnet 5.5 the supplementary cell), and a file that
names its project, config or view must name the entry's, which checks that
the entry names the right cell.  The three cells the paper's exclusions
changed are the exception: their recorded count is not compared (the
producer may withhold it); instead the rebuilt `excluded_infrastructure`
must list the attempt the paper excluded (as the id or its path suffix), or
the build stops, and the cell keeps the base cell's `override`.  An
`h25-cell/1` file may list the attempt in `excluded_unknown_terminal`
instead (an unknown terminal outcome, which also leaves the denominator).  A gate
whose value is not "pass", "n/a" or "disclosed" (`GATE_ACCEPTED`) stops the
build unless the entry has a `gate_note` saying why it is accepted.  `recall_mean`, `api_f1`, the API
count and `coverage_j`/`coverage_jaccard` may be null (a cell without
passes, or a value not rendered); a null leaves that measure out of the
project mean and the table prints it as not measured.  `sources` (stub) and
`lost_passes` are copied into the board's provenance without being read.

Usage:
    python scripts/build_leaderboard.py --research R [--commit 21f1cb23] \\
        [--paper-table P/tables/overall_performance.tex] [--base FILE]
    python scripts/build_leaderboard.py --supplement R --renders D \\
        [--supplement-commit 7d27db13] [--commit 21f1cb23]
    python scripts/build_leaderboard.py --h25-manifest M [--base FILE] \\
        [--paper-board FILE]
    python scripts/build_leaderboard.py --v2-cells FILE [--paper-board FILE] \\
        [--out results] [--readme README.md]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from req2test import aggregate as A  # noqa: E402

#: The DeepSeek model's name, as the README and the paper's text give it
#: (the paper's table abbreviates it `DS`).
DEEPSEEK = "DeepSeek-V4.1-Flash"
#: The paper's rows (`make_overall.py` ROWS), in table order.
CONFIGURATIONS = [
    {"id": "aider-ds", "system": "Aider", "model": DEEPSEEK,
     "reasoning": "off", "arm": "aider"},
    {"id": "openhands-ds", "system": "OpenHands", "model": DEEPSEEK,
     "reasoning": "off", "arm": "openhands"},
    {"id": "claude-code-ds", "system": "Claude Code", "model": DEEPSEEK,
     "reasoning": "high", "arm": "claude-code-deepseek-flash"},
    {"id": "codex-ds-off", "system": "Codex CLI", "model": DEEPSEEK,
     "reasoning": "off", "arm": "codex2-deepseek-flash-ro"},
    {"id": "codex-ds", "system": "Codex CLI", "model": DEEPSEEK,
     "reasoning": "high", "arm": "codex2-deepseek-flash"},
    {"id": "codex-luna", "system": "Codex CLI", "model": "GPT-6 Luna",
     "reasoning": "high", "arm": "codex2-gpt-6-luna"},
    {"id": "codex-sol", "system": "Codex CLI", "model": "GPT-6 Sol",
     "reasoning": "high", "arm": "codex2-gpt-6-sol"},
]
#: Configurations whose base cells are `req2test/data/<SUPPLEMENT_FILE>`.
SUPPLEMENT_CONFIGURATIONS = [
    {"id": "claude-code-sonnet55", "system": "Claude Code",
     "model": "Claude Sonnet 5.5", "reasoning": "high",
     "arm": "claude-code-sonnet-5-5"},
]
SUPPLEMENT_FILE = "claude_code_sonnet55_cells.json"
SUPPLEMENT_ABOUT = ("Base cells of Claude Code / Claude Sonnet 5.5, in the "
                    "fields of req2test/data/leaderboard_base.json. The "
                    "leaderboard keeps those of the four projects it does not "
                    "re-score and compares the re-scored cells' recorded pass "
                    "counts with the others.")
#: The Sonnet 5.5 arm's committed record in the research repository, and the
#: commit that holds it (merges of #1064 and #1065).
SONNET_RECORD = "experiments/claude-code-checked-interfaces/sonnet-5-5/results"
SONNET_COMMIT = "7d27db13"
SONNET_PREFIX = {"python-docx": "pdx", "algorand-sdk": "alg",
                 "coddy-agent": "cdy", "coreshop": "csh", "e-petitions": "epe",
                 "kapua": "kap", "prestashop": "psh", "sylius": "syl"}
#: The paper cells of the arm's twin, Claude Code / DeepSeek-V4.1-Flash.
TWIN_CELLS = "experiments/claude-code-checked-interfaces/paper-cells"
TWIN_ARM = "claude-code-deepseek-flash"
VIEWS = {"target_hidden": "th", "all_hidden": "ah"}
RO_ARM = "codex2-deepseek-flash-ro"
RO = "experiments/codex-deepseek-reasoning-off/results"
RO_PROJECT = {"pdx": "python-docx", "alg": "algorand-sdk", "csh": "coreshop",
              "syl": "sylius", "kap": "kapua", "cdy": "coddy-agent",
              "psh": "prestashop", "epe": "e-petitions"}
RUNG = ("generation_failure", "compilation_failure", "binding_failure",
        "execution_failure", "assertion_failure", "pass_rate")
OUT_OF_LADDER = ("excluded_infrastructure", "unknown_terminal_outcome")
FIELDS = ("population", "pass", "pass_den", "kc", "api_f1", "api_n", "cov_j",
          "mut_recall")
REPO = Path(__file__).resolve().parents[1]
#: The projects whose cells are re-scored (their scoring rules changed at
#: harness 25).
H25_PROJECTS = ("coddy-agent", "coreshop", "prestashop", "sylius")
#: The published board, in `--out`.
H25_FILE = "leaderboard.json"
#: The paper's board (`--h25-manifest` writes it, `--v2-cells` reads it).
PAPER_FILE = "leaderboard_paper.json"
#: The benchmark 1.1 rows' cells file.
V2_SCHEMA = "r2t.board-cells-v2/1"
#: Marks after a row's system name, and the sentence under the table for each.
PAPER_MARK = "\u2020"
PAPER_NOTE = ("\u2020 Results reported in the "
              "[paper](https://arxiv.org/abs/2610.36584), on the 2,051 eval "
              "instances, generated without the runtime packs, so the agent "
              "could not run the application.")
V2_MARKS = {"codex-ds-runtime": "\u2021"}
V2_NOTES = {"\u2021": ("\u2021 Algorand SDK, Kapua and 135 PrestaShop "
                       "instances ran on DeepSeek's 17 October 2026 update of "
                       "DeepSeek-V4.1-Flash.")}
#: What the table prints for a row mean that waits for a pending cell; the
#: release snapshot refuses a tree that still holds it.
PENDING = "{{SOL_CSH}}"
#: The base cells (`--research` writes them, the leaderboard reads them).
BASE_FILE = "leaderboard_base.json"
RESEARCH = "the study's research repository (not public)"
#: The generated block of `README.md` (`--readme`).
README_START = ("<!-- leaderboard:start (generated by "
                "scripts/build_leaderboard.py; do not edit) -->")
README_END = "<!-- leaderboard:end -->"
#: Metric order of the table's five columns, and their print scale.
COLUMNS = [("pass_at_1", "Pass@1"), ("kill_complete_at_1", "KillComplete@1"),
           ("api_f1", "API F1"), ("coverage_j", "Coverage J"),
           ("mutation_recall", "Mutation R")]


class Tree:
    """Files of one commit of a git checkout, read with `git show`."""

    def __init__(self, repo: Path, commit: str):
        self.repo = repo
        self.commit = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", commit], check=True,
            capture_output=True, text=True).stdout.strip()

    def read(self, path: str) -> bytes:
        return subprocess.run(
            ["git", "-C", str(self.repo), "show", f"{self.commit}:{path}"],
            check=True, capture_output=True).stdout

    def list(self, prefix: str) -> list:
        return subprocess.run(
            ["git", "-C", str(self.repo), "ls-tree", "-r", "--name-only",
             self.commit, prefix], check=True, capture_output=True,
            text=True).stdout.split()


def paper_cells(tree: Tree) -> list:
    out = []
    for path in sorted(tree.list("experiments")):
        parts = path.split("/")
        if not (len(parts) == 4 and parts[2] == "paper-cells"
                and parts[3].endswith(".json")):
            continue
        raw = tree.read(path)
        c = json.loads(raw)
        if c["block"] != "primary":
            continue
        api = c.get("api") or {}
        out.append({
            "project": c["project"], "arm": c["arm"]["slug"],
            "view": VIEWS[c["setting"]],
            "population": c["population"]["n"], "pass": c["pass"]["count"],
            "pass_den": c["pass"]["denominator"],
            "kc": c["nv_full_gold"]["count"],
            "mut_recall": c["nv_full_gold"].get("recall_mean"),
            "api_f1": api.get("value"), "api_n": api.get("n"),
            "cov_j": c["coverage"]["value"],
            "source": {"path": path,
                       "sha256": hashlib.sha256(raw).hexdigest()}})
    return out


def reasoning_off_cells(tree: Tree) -> list:
    raw = tree.read(f"{RO}/summary.json")
    doc = json.loads(raw)
    ok = ("code_of_record", "derived_fg_s2")
    out = []
    for key, r in sorted(doc["results"].items()):
        pk, view = key.split("-")
        cl = doc["cells"][key]
        items_path = f"{RO}/per-item/{key}.items.jsonl"
        items_raw = tree.read(items_path)
        items = [json.loads(line) for line in items_raw.decode().splitlines()
                 if line.strip()]
        rungs = [i.get("ladder_rung") for i in items]
        unknown = sorted({x for x in rungs if x not in RUNG + OUT_OF_LADDER})
        if unknown:
            raise SystemExit(f"{key}: unknown ladder rungs {unknown}")
        passes = r["pass"]["count"]
        if rungs.count("pass_rate") != passes:
            raise SystemExit(f"{key}: per-item passes {rungs.count('pass_rate')}"
                             f" differ from the summary's {passes}")
        fg = r.get("nv_full_gold") or {}
        mut = fg.get("recall_mean")
        if mut is None and view == "th":
            mut = (doc.get(f"{pk}_nv") or {}).get("full_recall_macro")
        out.append({
            "project": RO_PROJECT[pk], "arm": RO_ARM, "view": view,
            "population": r["planned_n"], "pass": passes,
            "pass_den": len(items) - sum(rungs.count(x) for x in OUT_OF_LADDER),
            "kc": fg.get("count"),
            "mut_recall": mut if fg.get("count") is not None else None,
            "api_f1": (r["api_f1"]["value"]
                       if (r.get("api_f1") or {}).get("status") in ok else None),
            "api_n": (cl.get("api_scored")
                      if (r.get("api_f1") or {}).get("status") in ok else None),
            "cov_j": (r["coverage"]["value"]
                      if (r.get("coverage") or {}).get("status") in ok else None),
            "source": {"path": f"{RO}/summary.json",
                       "sha256": hashlib.sha256(raw).hexdigest(),
                       "per_item": items_path,
                       "per_item_sha256": hashlib.sha256(items_raw).hexdigest()}})
    return out


def apply_overrides(cells: list, overrides: dict) -> list:
    """The paper's attempt exclusions (`make_overall.load`)."""
    by_key = {(c["project"], c["arm"], c["view"]): c for c in cells}
    for o in overrides["exclude_attempts"]:
        c = by_key[(o["project"], o["arm"], VIEWS[o["setting"]])]
        c["pass"], c["pass_den"] = o["pass"], o["pass_den"]
        c["override"] = {"item": o["item"], "reason": o["reason"]}
    return cells


def build(tree: Tree, i_sets: dict, overrides: dict) -> dict:
    cells = apply_overrides(paper_cells(tree) + reasoning_off_cells(tree),
                            overrides)
    return aggregate_cells(cells, i_sets)


def _render_row(text: str, label: str, where: str) -> str:
    """The printed value of row `label` of a committed results render."""
    m = re.search(r"^\| " + re.escape(label) + r" \| ([^|]*) \|$", text, re.M)
    if not m:
        raise SystemExit(f"{where}: no '{label}' row")
    return m.group(1).strip()


def sonnet_cells(record: Tree, paper: Tree, renders: Path) -> list:
    """The 16 cells of Claude Code / Claude Sonnet 5.5 in the fields of
    `paper_cells`, with the paper cells' definitions (module docstring)."""
    arm = SUPPLEMENT_CONFIGURATIONS[0]["arm"]
    out = []
    for project, pk in sorted(SONNET_PREFIX.items()):
        for setting, view in VIEWS.items():
            cid = f"{pk}-{view}"
            where = f"{project}/{cid}"
            ev_path = f"{SONNET_RECORD}/{project}/{cid}-evidence.json"
            ev_raw = record.read(ev_path)
            ev = json.loads(ev_raw)
            named = (ev.get("project"), ev.get("setting"),
                     (ev.get("arm") or {}).get("slug"))
            if named != (project, setting, arm):
                raise SystemExit(f"{ev_path}: is for {named}")
            gen, mut = ev["generation"], ev["mutation"]
            n = gen["planned_n"]
            passes = gen["pass"]["count"]
            den = gen["pass"]["denominator"]
            if mut["kill_complete_denominator"] != n:
                raise SystemExit(f"{where}: KillComplete is over "
                                 f"{mut['kill_complete_denominator']}, not {n}")
            # The finalize render's JSON, the file the evidence names by
            # digest; the paper cells read API F1 and coverage J from it.
            render = gen["render"]
            rpath = renders / cid / "results.json"
            if not rpath.is_file():
                raise SystemExit(f"{where}: {rpath} not found")
            rraw = rpath.read_bytes()
            digest = hashlib.sha256(rraw).hexdigest()
            if digest != render["json_sha256"]:
                raise SystemExit(f"{where}: {rpath} has sha256 {digest}, the "
                                 f"evidence names {render['json_sha256']}")
            res = json.loads(rraw)
            if (res["n_passed"], res["ladder"]["denominator"]) != (passes, den):
                raise SystemExit(f"{where}: the render's pass "
                                 f"{res['n_passed']}/{res['ladder']['denominator']}"
                                 f" is not the evidence's {passes}/{den}")
            md_name = f"{cid}-results.md"
            md = record.read(f"{SONNET_RECORD}/{project}/{md_name}").decode()
            cov = res["coverage"]
            cov_j = cov["values"]["jaccard"] if cov["scored"] else None
            printed = [("coverage jaccard similarity", cov_j, md, md_name)]
            if project == "algorand-sdk":
                # As the paper's algorand-sdk cells: the labelled
                # reporting-only API render (the finalize render reads
                # not_measured).
                api = render["api_reporting_only"]
                api_f1, api_n = api["api_f1"], api["n_scored"]
                api_name = f"{cid}-results.api.md"
                printed.append(("api f1", api_f1, record.read(
                    f"{SONNET_RECORD}/{project}/{api_name}").decode(),
                    api_name))
                api_from = ("evidence generation.render.api_reporting_only "
                            "(api_f1, n_scored)")
            else:
                api = res["api"]
                api_f1 = api["values"]["f1"] if api["scored"] else None
                api_n = api["n_scored"] if api["scored"] else None
                printed.append(("api f1", api_f1, md, md_name))
                api_from = "render api.values.f1, api.n_scored"
            for label, value, text, name in printed:
                shown = _render_row(text, label, f"{where} {name}")
                if value is None or shown != f"{value:.3f}":
                    raise SystemExit(f"{where}: {label} {value} is not the "
                                     f"{shown} that {name} prints")
            # The evidence's figures for the twin equal the twin's paper
            # cell: its kill_complete and full_recall are the quantities the
            # paper cells call nv_full_gold count and recall_mean.
            tw_path = f"{TWIN_CELLS}/{project}__{TWIN_ARM}__{setting}.json"
            tw_raw = paper.read(tw_path)
            tw = json.loads(tw_raw)
            twin = ev["twin"]
            want = (tw["pass"]["count"], tw["nv_full_gold"]["count"],
                    tw["nv_full_gold"]["recall_mean"])
            got = (twin.get("pass"), twin.get("kill_complete"),
                   twin.get("full_recall"))
            if got != want:
                raise SystemExit(f"{where}: the evidence's twin figures {got} "
                                 f"are not the twin paper cell's {want}; the "
                                 f"quantities may be defined differently")
            out.append({
                "project": project, "arm": arm, "view": view,
                "population": n, "pass": passes, "pass_den": den,
                "kc": mut["kill_complete"], "mut_recall": mut["full_recall"],
                "api_f1": api_f1, "api_n": api_n, "cov_j": cov_j,
                "source": {
                    "path": ev_path,
                    "sha256": hashlib.sha256(ev_raw).hexdigest(),
                    "render": {"file": "analysis/results.json of the cell's "
                                       "finalize render",
                               "sha256": digest},
                    "api_from": api_from,
                    "printed": f"API F1 and coverage J equal {md_name} to "
                               f"its 0.001",
                    "twin": {"path": tw_path,
                             "sha256": hashlib.sha256(tw_raw).hexdigest()}}})
    return out


def build_supplement(record: Tree, paper: Tree, renders: Path,
                     i_sets: dict) -> dict:
    """The document `req2test/data/<SUPPLEMENT_FILE>`."""
    cells = sonnet_cells(record, paper, renders)
    board = aggregate_cells(cells, i_sets, SUPPLEMENT_CONFIGURATIONS)
    return {
        "schema": "req2test.supplement-cells/1",
        "about": SUPPLEMENT_ABOUT,
        "configurations": SUPPLEMENT_CONFIGURATIONS,
        "provenance": {
            "research_repo": RESEARCH,
            "record": SONNET_RECORD,
            "record_commit": record.commit,
            "twin_cells": TWIN_CELLS,
            "paper_commit": paper.commit,
            "renders": "each cell's finalize render analysis/results.json, "
                       "from the arm's preserved generation outputs, checked "
                       "against the sha256 its evidence file names",
            "aggregation": "req2test.aggregate leaderboard"},
        "rows_before_h25": board["rows"],
        "cells": board["cells"]}


def aggregate_cells(cells: list, i_sets: dict,
                    configurations: list = CONFIGURATIONS) -> dict:
    """The rows of `configurations` from per-cell fields (`FIELDS`); each
    cell gains its `values`."""
    for c in cells:
        census = i_sets[c["project"]]["census_n"]
        if c["population"] != census:
            raise SystemExit(f"{c['project']}/{c['arm']}/{c['view']}: "
                             f"population {c['population']} != {census}")
    rows = []
    for cfg in configurations:
        mine = [c for c in cells if c["arm"] == cfg["arm"]]
        values = {(c["project"], c["view"]):
                  A.leaderboard_values(c, i_sets[c["project"]]) for c in mine}
        means = A.macro(values)
        rows.append({**cfg, "views": {
            view: {m: means[view][m]["value"] for m, _ in COLUMNS}
            | {"projects": min(means[view][m]["projects"] for m, _ in COLUMNS)}
            for view in ("th", "ah")}})
        for c in mine:
            c["values"] = values[(c["project"], c["view"])]
    return {"cells": cells, "rows": rows}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest(path: Path) -> list:
    doc = json.loads(path.read_text())
    entries = doc if isinstance(doc, list) else doc.get("cells")
    if not isinstance(entries, list):
        raise SystemExit(f"{path}: expected {{\"cells\": [...]}} or a list")
    return entries


def _count(block, key: str, where: str) -> int:
    value = (block or {}).get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise SystemExit(f"{where}: {key} is {value!r}, not an integer")
    return value


def _number(block: dict, key: str, where: str):
    value = block.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SystemExit(f"{where}: {key} is {value!r}, not a number")
    return value


H25_CELL_SCHEMA = "h25-cell/1"
#: Gate values of the re-scoring that pass: "n/a" (the gate does not apply
#: to the cell) and "disclosed" (a deviation the re-scoring's specification
#: lists and discloses) as well as "pass".
GATE_ACCEPTED = ("pass", "n/a", "disclosed")
SETTING_VIEW = {"target_hidden": "th", "all_hidden": "ah", "th": "th",
                "ah": "ah"}


def _recorded(block: dict, keys: tuple, where: str) -> tuple:
    """The recorded `(pass, den)`; None where the producer withheld a
    count (only a cell the paper's exclusions changed may do that)."""
    return tuple(None if block.get(k) is None else _count(block, k, where)
                 for k in keys)


def _excluded(block: dict) -> list:
    """Item ids the rebuilt cell left out of the denominator: as
    infrastructure, or as an unknown terminal outcome."""
    ids = block.get("excluded_infrastructure")
    if ids is None and isinstance(block.get("pass"), dict):
        ids = block["pass"].get("excluded_infrastructure")
    ids = list(ids or []) + list(block.get("excluded_unknown_terminal") or [])
    return [i for i in ids if isinstance(i, str)]


def _measures(result: dict, where: str, cell_dir: Path) -> tuple:
    """`(recorded (pass, den), rebuilt fields, extra provenance, rebuilt
    infrastructure exclusions)` of one re-scored cell, in either of the two
    per-cell formats (docstring)."""
    if result.get("schema") == H25_CELL_SCHEMA:
        rec, reb = result.get("recorded"), result.get("rebuilt")
        if not isinstance(rec, dict) or not isinstance(reb, dict):
            raise SystemExit(f"{where}: needs recorded and rebuilt")
        recorded = _recorded(rec, ("passed", "denominator"),
                             f"{where} recorded")
        fields = {"pass": _count(reb, "passed", f"{where} rebuilt"),
                  "pass_den": _count(reb, "denominator", f"{where} rebuilt"),
                  "kc": reb.get("kill_complete"),
                  "mut_recall": _number(reb, "recall_mean", where),
                  "api_f1": _number(reb, "api_f1", where),
                  "api_n": reb.get("api_n"),
                  "cov_j": _number(reb, "coverage_jaccard", where)}
        extra = {"lost_passes": result.get("lost_passes")}
        # h25-cell/1 has no API pass count; the render it names has it.
        if fields["api_n"] is None and fields["api_f1"] is not None:
            render = (result.get("files") or {}).get("results_rebuilt")
            path = cell_dir / render if render else None
            if path is None or not path.is_file():
                raise SystemExit(f"{where}: rebuilt api_f1 needs its API pass "
                                 f"count from the results render "
                                 f"{render or '(files.results_rebuilt)'}, "
                                 f"which is not beside the cell file")
            fields["api_n"] = (json.loads(path.read_text()).get("api")
                               or {}).get("n_scored")
            if fields["api_n"] is None:
                raise SystemExit(f"{where}: {render} has no api.n_scored")
            extra["api_n_from"] = {"path": render, "sha256": _sha256(path)}
        return recorded, fields, extra, _excluded(reb)
    rec = (result.get("recorded") or {}).get("pass")
    reb = result.get("rebuilt")
    if not isinstance(rec, dict) or not isinstance(reb, dict):
        raise SystemExit(f"{where}: needs recorded.pass and rebuilt "
                         f"(or schema {H25_CELL_SCHEMA})")
    recorded = _recorded(rec, ("count", "denominator"),
                         f"{where} recorded.pass")
    fields = {"pass": _count(reb.get("pass"), "count", f"{where} rebuilt.pass"),
              "pass_den": _count(reb.get("pass"), "denominator",
                                 f"{where} rebuilt.pass"),
              "kc": reb.get("kill_complete"),
              "mut_recall": _number(reb, "recall_mean", where),
              "api_f1": _number(reb, "api_f1", where),
              "api_n": reb.get("api_n"),
              "cov_j": _number(reb, "coverage_j", where)}
    return recorded, fields, {"sources": result.get("sources")}, \
        _excluded(reb)


def h25_cell(result: dict, base: dict, where: str,
             cell_dir: Path = Path(".")) -> tuple:
    """`(FIELDS, provenance)` of one re-scored cell, checked against the
    base cell `base` it replaces."""
    recorded, f, extra, excluded = _measures(result, where, cell_dir)
    override = base.get("override")
    if override:
        # The paper took this attempt out of the denominator by hand; the
        # rebuilt cell must leave it out too (harness 25 classifies it as
        # infrastructure), or its pass count is not comparable.
        item = override["item"]
        if not any(i == item or i.endswith("/" + item) for i in excluded):
            raise SystemExit(f"{where}: the paper excluded {item} "
                             f"({override['reason']}) from this cell, but "
                             f"the rebuilt cell does not list it in "
                             f"excluded_infrastructure or "
                             f"excluded_unknown_terminal")
        extra["override"] = ("the paper's exclusion, also excluded by the "
                             "re-scored cell")
    elif recorded != (base["pass"], base["pass_den"]):
        raise SystemExit(f"{where}: recorded pass {recorded[0]}/{recorded[1]} "
                         f"is not the base cell's "
                         f"{base['pass']}/{base['pass_den']}; does the entry "
                         f"name the right cell?")
    if f["kc"] is None:
        raise SystemExit(f"{where}: rebuilt kill_complete is null; the cell "
                         f"is not final")
    f["kc"] = _count(f, "kc", f"{where} rebuilt kill_complete")
    if f["api_n"] is not None:
        f["api_n"] = _count(f, "api_n", f"{where} rebuilt api_n")
    elif f["api_f1"] is not None:
        f["api_f1"] = None          # a mean without its count cannot be scaled
        extra["api_f1"] = "no API pass count; not measured"
    if not 0 <= f["kc"] <= f["pass"] <= f["pass_den"] <= base["population"]:
        raise SystemExit(f"{where}: needs 0 <= kill_complete {f['kc']} <= "
                         f"passes {f['pass']} <= denominator {f['pass_den']} "
                         f"<= population {base['population']}")
    return {"population": base["population"], **f}, extra


def _check_identity(result: dict, key: tuple, where: str) -> None:
    """A cell file that names its own cell must name this one."""
    config, project, view = key
    named = {"config": result.get("config"), "project": result.get("project"),
             "view": SETTING_VIEW.get(result.get("view"), result.get("view"))}
    want = {"config": config, "project": project, "view": view}
    wrong = {k: v for k, v in named.items() if v is not None and v != want[k]}
    if wrong:
        raise SystemExit(f"{where}: the file is for {wrong}, not {want}")


def _check_gates(result: dict, entry: dict, where: str) -> None:
    """Every recorded gate passed, or the entry says why it is accepted."""
    gates = result.get("gates")
    if not isinstance(gates, dict):
        return
    failed = {k: v for k, v in gates.items() if v not in GATE_ACCEPTED}
    if failed and not entry.get("gate_note"):
        raise SystemExit(f"{where}: gates {failed} did not pass; add a "
                         f"gate_note to the manifest entry to accept them")


def check_supplement(supplement: dict, i_sets: dict) -> list:
    """The supplementary cells, after checking that the document is for
    `SUPPLEMENT_CONFIGURATIONS` and has every cell of each of them."""
    if supplement.get("configurations") != SUPPLEMENT_CONFIGURATIONS:
        raise SystemExit(f"{SUPPLEMENT_FILE}: its configurations are not "
                         f"SUPPLEMENT_CONFIGURATIONS")
    cells = supplement.get("cells") or []
    have = [(c["arm"], c["project"], c["view"]) for c in cells]
    want = {(cfg["arm"], p, v) for cfg in SUPPLEMENT_CONFIGURATIONS
            for p in i_sets for v in ("th", "ah")}
    if len(have) != len(set(have)) or set(have) != want:
        missing = sorted(want - set(have))
        raise SystemExit(f"{SUPPLEMENT_FILE}: needs each of the {len(want)} "
                         f"cells once; missing {missing[:3]}, "
                         f"{len(have) - len(set(have))} listed twice")
    return cells


def build_h25(base_board: dict, manifest: Path, i_sets: dict,
              supplement: dict) -> dict:
    """The base cells and the supplementary cells (`supplement`), with
    every affected cell replaced by its re-scored cell (or kept, where the
    manifest says so)."""
    configurations = CONFIGURATIONS + SUPPLEMENT_CONFIGURATIONS
    later = {c["arm"] for c in SUPPLEMENT_CONFIGURATIONS}
    arm_of = {c["id"]: c["arm"] for c in configurations}
    base_cells = [c for c in base_board["cells"] if c["arm"] not in later]
    if len(base_cells) != len(base_board["cells"]):
        raise SystemExit("the base board has cells of a supplementary "
                         "configuration; is it the published board instead "
                         f"of {BASE_FILE}?")
    base_cells += check_supplement(supplement, i_sets)
    chosen = {}
    for entry in load_manifest(manifest):
        key = (entry.get("config"), entry.get("project"), entry.get("view"))
        where = f"{manifest.name}: {'/'.join(map(str, key))}"
        if key[0] not in arm_of:
            raise SystemExit(f"{where}: config is not a leaderboard row "
                             f"({', '.join(arm_of)})")
        if key[1] not in H25_PROJECTS or key[2] not in ("th", "ah"):
            raise SystemExit(f"{where}: project must be one of "
                             f"{', '.join(H25_PROJECTS)} and view th or ah")
        if key in chosen:
            raise SystemExit(f"{where}: listed twice")
        chosen[key] = entry
    wanted = [(c, p, v) for c in arm_of for p in H25_PROJECTS
              for v in ("th", "ah")]
    missing = [k for k in wanted if k not in chosen]
    if missing:
        raise SystemExit(f"{manifest.name}: {len(missing)} affected cell(s) "
                         f"have no entry, e.g. "
                         f"{', '.join('/'.join(k) for k in missing[:5])}")
    cells = []
    for old in base_cells:
        cfg = next(c for c, a in arm_of.items() if a == old["arm"])
        key = (cfg, old["project"], old["view"])
        cell = {k: old[k] for k in ("project", "arm", "view") + FIELDS}
        if key not in chosen or chosen[key].get("keep_recorded"):
            base_name = (f"the cell of req2test/data/{SUPPLEMENT_FILE}"
                         if old["arm"] in later
                         else f"the cell of req2test/data/{BASE_FILE}")
            how = (f"unaffected project; {base_name}" if key not in chosen
                   else f"kept: {chosen[key]['keep_recorded']}")
            cell["source"] = {"scoring": how, **old["source"]}
            if "override" in old:
                cell["override"] = old["override"]
        else:
            entry = chosen[key]
            where = f"{manifest.name}: {'/'.join(key)}"
            path = manifest.parent / entry["path"]
            digest = _sha256(path)
            if digest != entry.get("sha256"):
                raise SystemExit(f"{where}: {path} has sha256 {digest}, the "
                                 f"manifest says {entry.get('sha256')}")
            result = json.loads(path.read_text())
            _check_identity(result, key, where)
            _check_gates(result, entry, where)
            fields, extra = h25_cell(result, old, where, path.parent)
            cell.update(fields)
            if "override" in old:
                cell["override"] = old["override"]
            cell["source"] = {"scoring": "re-scored", "path": entry["path"],
                              "sha256": digest,
                              "schema": result.get("schema"),
                              "gates": result.get("gates"),
                              "gate_note": entry.get("gate_note"), **extra}
        cells.append(cell)
    covered = {(c["arm"], c["project"], c["view"]) for c in cells}
    absent = [k for k in wanted if (arm_of[k[0]], k[1], k[2]) not in covered]
    if absent:
        raise SystemExit(f"the base board has no cell for {absent[:3]}")
    board = aggregate_cells(cells, i_sets, configurations)
    return {
        "schema": "req2test.leaderboard/1",
        "release": "paper",
        "harness_version": 25,
        "provenance": {
            "base": {"board": f"req2test/data/{BASE_FILE}",
                     "sha256": base_board.get("_sha256")},
            "supplement": {"cells": f"req2test/data/{SUPPLEMENT_FILE}",
                           "sha256": supplement.get("_sha256"),
                           "record_commit": (supplement.get("provenance")
                                             or {}).get("record_commit")},
            "manifest_sha256": _sha256(manifest),
            "affected_projects": list(H25_PROJECTS),
            "aggregation": "req2test.aggregate leaderboard"},
        "metrics": [m for m, _ in COLUMNS],
        "rows": board["rows"], "cells": board["cells"]}


def _sha_doc(doc: dict) -> str:
    return doc.get("_sha256")


def load_v2(path: Path) -> dict:
    doc = json.loads(path.read_text())
    if doc.get("schema") != V2_SCHEMA:
        raise SystemExit(f"{path}: schema is {doc.get('schema')!r}, not "
                         f"{V2_SCHEMA}")
    doc["_sha256"] = _sha256(path)
    return doc


def check_v2_population(doc: dict, i_sets: dict) -> None:
    """The file's exclusions are the engine's 1.1 population list, and each
    project's census is the paper's census minus its excluded instances."""
    from req2test.report import population_exclusions
    excluded = population_exclusions("1.1")["excluded"]
    if sorted(doc["population_excluded"]) != sorted(excluded):
        raise SystemExit("the 1.1 cells' population_excluded is not the "
                         "engine's benchmark 1.1 population list")
    for project, iset in i_sets.items():
        want = iset["census_n"] - sum(
            1 for iid in excluded if iid.split("/", 1)[0] == project)
        if doc["i_sets"][project]["census_n"] != want:
            raise SystemExit(f"{project}: 1.1 census "
                             f"{doc['i_sets'][project]['census_n']} != {want}")


def _same(a, b) -> bool:
    return (a is None and b is None) or (
        a is not None and b is not None and abs(a - b) <= 1e-9)


def v2_rows(doc: dict) -> tuple:
    """`(rows, cells)` of the benchmark 1.1 rows, in the board's fields."""
    i_sets = doc["i_sets"]
    rows, cells = [], []
    for rid, meta in doc["rows"].items():
        mine = [c for c in doc["cells"] if c["row"] == rid]
        if sorted(c["project"] for c in mine) != sorted(i_sets):
            raise SystemExit(f"{rid}: needs one cell per project")
        values = {}
        for c in mine:
            v = A.leaderboard_values(c, i_sets[c["project"]])
            for m, _ in COLUMNS:
                want = (c.get("values") or {}).get(m)
                if not _same(v[m], want):
                    raise SystemExit(f"{rid}/{c['project']}: {m} {v[m]} is "
                                     f"not the file's {want}")
            values[(c["project"], "th")] = v
            cells.append({"project": c["project"], "arm": rid, "view": "th",
                          **{k: c[k] for k in FIELDS}, "values": v})
        means = A.macro(values)["th"]
        th, pending = {}, []
        for m, _ in COLUMNS:
            got = means[m]
            want = (meta.get("mean") or {}).get(m) or {}
            if not _same(got["value"], want.get("value")) or \
                    got["projects"] != want.get("projects"):
                raise SystemExit(f"{rid}: mean {m} {got} is not the file's "
                                 f"{want}")
            full = got["projects"] == len(i_sets)
            th[m] = got["value"] if full else None
            if not full and any(c.get("pending") and values[(c["project"],
                                "th")][m] is None for c in mine):
                pending.append(m)
        th["projects"] = min(means[m]["projects"] for m, _ in COLUMNS)
        rows.append({"id": rid, "system": meta["system"],
                     "model": meta["model"], "reasoning": meta["reasoning"],
                     "arm": rid, "results": "1.1", "mark": V2_MARKS.get(rid),
                     "views": {"th": th}, "pending": pending})
    return rows, cells


def build_board(paper: dict, v2: dict, i_sets: dict) -> dict:
    """The published board: the 1.1 rows and the paper's target-hidden
    rows."""
    check_v2_population(v2, i_sets)
    rows, cells = v2_rows(v2)
    for row in paper["rows"]:
        rows.append({k: row[k] for k in ("id", "system", "model",
                                         "reasoning", "arm")}
                    | {"results": "paper", "mark": PAPER_MARK,
                       "views": {"th": row["views"]["th"]}, "pending": []})
    cells += [c for c in paper["cells"] if c["view"] == "th"]
    marks = {r["mark"] for r in rows}
    notes = {PAPER_MARK: PAPER_NOTE, **V2_NOTES}
    return {
        "schema": "req2test.leaderboard/2",
        "release": "1.1",
        "complete": not any(r["pending"] for r in rows),
        "provenance": {
            "paper_board": {"path": f"req2test/data/{PAPER_FILE}",
                            "sha256": _sha_doc(paper)},
            "v2_cells_sha256": _sha_doc(v2),
            "aggregation": "req2test.aggregate leaderboard"},
        "metrics": [m for m, _ in COLUMNS],
        "notes": {k: v for k, v in notes.items() if k in marks},
        "rows": rows, "cells": cells}


def _pct(value) -> str:
    return "\u2013" if value is None else f"{100 * value:.1f}"


def _values(row: dict) -> str:
    return " | ".join(PENDING if m in row.get("pending", ()) else
                      _pct(row["views"]["th"][m]) for m, _ in COLUMNS)


def ranked(board: dict) -> list:
    """The board's rows by target-hidden Pass@1, highest first (stable)."""
    return sorted(board["rows"],
                  key=lambda r: -(r["views"]["th"]["pass_at_1"] or 0))


def readme_table(board: dict) -> list:
    """The table, in the `ranked` order, and a sentence per mark used."""
    lines = ["| System | Model | Reasoning | Pass@1 | KillComplete@1 | "
             "API F1 | Coverage J | Mutation R |",
             "|---|---|---|---:|---:|---:|---:|---:|"]
    lines += [f"| {r['system']}{r.get('mark') or ''} | {r['model']} | "
              f"{r['reasoning']} | {_values(r)} |" for r in ranked(board)]
    for note in board.get("notes", {}).values():
        lines += ["", note]
    return lines


def write_readme(path: Path, board: dict) -> None:
    """Replace the block between the README markers with `readme_table`."""
    text = path.read_text()
    for marker in (README_START, README_END):
        if text.count(marker) != 1:
            raise SystemExit(f"{path}: needs {marker!r} exactly once")
    i = text.index(README_START) + len(README_START)
    j = text.index(README_END)
    if j < i:
        raise SystemExit(f"{path}: {README_END!r} comes before the start")
    block = "\n".join(readme_table(board))
    path.write_text(text[:i] + "\n" + block + "\n" + text[j:])


def parse_paper_table(path: Path) -> dict:
    """`{(system, model, reasoning): {"th": [5 values], "ah": [...]}}`."""
    text = path.read_text()
    out = {}
    pattern = re.compile(
        r"\\resultpair\{([^}]*)\}\{([^}]*)\}\{([^}]*)\}\s*\{([^}]*)\}\s*\{([^}]*)\}")
    for m in pattern.finditer(text):
        system, model, reasoning, th, ah = m.groups()
        out[(system, model, reasoning)] = {
            "th": [float(x) for x in th.split("&")],
            "ah": [float(x) for x in ah.split("&")]}
    return out


def paper_model(model: str) -> str:
    return "DS" if model == DEEPSEEK else model


def check_against(board: dict, table: dict) -> list:
    problems = []
    for row in board["rows"]:
        key = (row["system"], paper_model(row["model"]), row["reasoning"])
        printed = table.get(key)
        if printed is None:
            problems.append(f"{key}: not in the paper's table")
            continue
        for view in ("th", "ah"):
            for (m, label), want in zip(COLUMNS, printed[view]):
                got = round(100 * row["views"][view][m], 1)
                if got != want:
                    problems.append(f"{key} {view} {label}: {got} != {want}")
    return problems


def markdown(board: dict) -> str:
    """`leaderboard.md`: the table, its notes and where the data is."""
    lines = [
        "# Req2Test-Bench leaderboard",
        "",
        "Means over the eight projects (equal weight), in percent, "
        "target-hidden view, aggregated by `req2test.aggregate` in "
        "`leaderboard` mode. A non-passing test counts as 0 in every column, "
        "and \u2013 marks a measure not available for every project. Benchmark "
        "1.1 scores 2,037 of the 2,051 `eval` instances "
        "([population](../docs/evaluation.md#population)). A run is "
        "comparable with this table when the system follows the generation "
        "protocol of `docs/agents.md` on the whole `eval` split.",
        "",
    ] + readme_table(board) + [
        "",
        "## Data",
        "",
        "- Every cell's counts and values are in `results/leaderboard.json`.",
        "- Instance-set sizes for API F1 and coverage are in "
        "`req2test/data/i_sets.json`, and the three excluded attempts of the "
        "paper's runs in `req2test/data/attempt_exclusions.json`.",
        "",
    ]
    return "\n".join(lines)


def write_markdown(out: Path) -> None:
    board = json.loads((out / H25_FILE).read_text())
    (out / "leaderboard.md").write_text(markdown(board))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--research", type=Path,
                      help="the base cells: a checkout of the research "
                           "repository")
    mode.add_argument("--h25-manifest", type=Path,
                      help="the paper's board: the manifest of the "
                           "re-scored cells")
    mode.add_argument("--supplement", type=Path,
                      help="the supplementary cells: a checkout of the "
                           "research repository")
    mode.add_argument("--v2-cells", type=Path,
                      help="the published board: the benchmark 1.1 rows' "
                           "cells file")
    ap.add_argument("--commit", default="21f1cb23",
                    help="the paper cells' commit (also the twin cells' of "
                         "--supplement)")
    ap.add_argument("--supplement-commit", default=SONNET_COMMIT,
                    help="--supplement: the commit of the arm's record")
    ap.add_argument("--renders", type=Path,
                    help="--supplement: a directory with <cell>/results.json, "
                         "each cell's finalize render (e.g. pdx-th/)")
    ap.add_argument("--supplement-cells", type=Path,
                    default=A.DATA / SUPPLEMENT_FILE,
                    help="what --supplement writes and the paper's board "
                         "reads")
    ap.add_argument("--paper-table", type=Path)
    ap.add_argument("--base", type=Path, default=A.DATA / BASE_FILE,
                    help="the base cells: what --research writes and the "
                         "paper's board reads")
    ap.add_argument("--paper-board", type=Path, default=A.DATA / PAPER_FILE,
                    help="what --h25-manifest writes and --v2-cells reads")
    ap.add_argument("--out", type=Path, default=REPO / "results",
                    help="--v2-cells: where leaderboard.json and "
                         "leaderboard.md are written")
    ap.add_argument("--readme", type=Path,
                    help="--v2-cells: also write the table into this "
                         "README's leaderboard block")
    a = ap.parse_args(argv)
    if a.readme and not a.v2_cells:
        ap.error("--readme needs --v2-cells")
    i_sets = A.load_i_sets()
    if a.supplement:
        if not a.renders:
            ap.error("--supplement needs --renders")
        doc = build_supplement(Tree(a.supplement, a.supplement_commit),
                               Tree(a.supplement, a.commit), a.renders,
                               i_sets)
        a.supplement_cells.write_text(json.dumps(doc, indent=1) + "\n")
        _print_rows({"rows": doc["rows_before_h25"]})
        return 0
    if a.h25_manifest:
        base = json.loads(a.base.read_text())
        base["_sha256"] = _sha256(a.base)
        supplement = json.loads(a.supplement_cells.read_text())
        supplement["_sha256"] = _sha256(a.supplement_cells)
        board = build_h25(base, a.h25_manifest, i_sets, supplement)
        a.paper_board.write_text(json.dumps(board, indent=1) + "\n")
        _print_rows(board)
        return 0
    if a.v2_cells:
        paper = json.loads(a.paper_board.read_text())
        paper["_sha256"] = _sha256(a.paper_board)
        board = build_board(paper, load_v2(a.v2_cells), i_sets)
        if a.readme:
            write_readme(a.readme, board)     # checks the markers first
        a.out.mkdir(parents=True, exist_ok=True)
        (a.out / H25_FILE).write_text(json.dumps(board, indent=1,
                                                 ensure_ascii=False) + "\n")
        write_markdown(a.out)
        _print_rows(board)
        for row in board["rows"]:
            if row["pending"]:
                print(f"{row['id']}: {', '.join(row['pending'])} pending, "
                      f"printed as {PENDING}")
        return 0
    tree = Tree(a.research, a.commit)
    overrides = json.loads(
        (A.DATA / "attempt_exclusions.json").read_text())
    board = build(tree, i_sets, overrides)
    check = "not checked"
    table_sha = None
    if a.paper_table:
        problems = check_against(board, parse_paper_table(a.paper_table))
        table_sha = hashlib.sha256(a.paper_table.read_bytes()).hexdigest()
        if problems:
            print("\n".join(problems))
            return 1
        check = "all 70 values equal"
    board = {
        "schema": "req2test.leaderboard/1",
        "release": "1.0",
        "provenance": {
            "research_repo": RESEARCH,
            "research_commit": tree.commit,
            "aggregation": "req2test.aggregate leaderboard (replicates the "
                           "paper's table generator)",
            "paper_table": "tables/overall_performance.tex",
            "paper_table_sha256": table_sha,
            "paper_table_check": check},
        "metrics": [m for m, _ in COLUMNS],
        "rows": board["rows"], "cells": board["cells"]}
    a.base.write_text(json.dumps(board, indent=1) + "\n")
    _print_rows(board)
    print(f"paper table: {check}")
    return 0


def _print_rows(board: dict) -> None:
    for row in board["rows"]:
        print(row["id"], {v: [None if row["views"][v][m] is None
                              else round(100 * row["views"][v][m], 1)
                              for m, _ in COLUMNS] for v in row["views"]})


if __name__ == "__main__":
    sys.exit(main())
