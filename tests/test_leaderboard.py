"""The leaderboard builder and the committed leaderboard: the paper's board
of eight configurations, and the published board (the benchmark 1.1 rows and
the paper's target-hidden rows), rendered into `results/leaderboard.md` and
the README."""
import importlib.util
import json
import re
from pathlib import Path

from req2test import aggregate as A

ROOT = Path(__file__).resolve().parents[1]


def builder():
    spec = importlib.util.spec_from_file_location(
        "build_leaderboard", ROOT / "scripts" / "build_leaderboard.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_deepseek_has_one_name():
    B = builder()
    assert B.DEEPSEEK == "DeepSeek-V4.1-Flash"
    assert B.paper_model(B.DEEPSEEK) == "DS"
    board = json.loads((A.DATA / B.BASE_FILE).read_text())
    models = {row["model"] for row in board["rows"]}
    assert {m for m in models if "DeepSeek" in m} == {B.DEEPSEEK}
    text = (ROOT / "results" / "leaderboard.md").read_text()
    assert "DeepSeek Flash" not in text and "/ DS " not in text


# ---------------------------------------------------- re-scored cells
import hashlib  # noqa: E402

import pytest  # noqa: E402


def _cells(configurations, i_sets, source="paper"):
    """Every cell of `configurations`, with the census populations of
    `i_sets` and small round values."""
    cells = []
    for cfg in configurations:
        for project, iset in i_sets.items():
            n = iset["census_n"]
            for view in ("th", "ah"):
                cells.append({"project": project, "arm": cfg["arm"],
                              "view": view, "population": n,
                              "pass": n // 2, "pass_den": n, "kc": n // 4,
                              "mut_recall": 0.9, "api_f1": 0.8,
                              "api_n": n // 2, "cov_j": 0.7,
                              "source": {"path": f"{source}/{project}.json",
                                         "sha256": "0" * 64}})
    return cells


def _base_board(B, i_sets):
    """A synthetic base board: every configuration, project and view."""
    board = B.aggregate_cells(_cells(B.CONFIGURATIONS, i_sets), i_sets)
    return {"schema": "req2test.leaderboard/1", "release": "1.0",
            "provenance": {"research_repo": B.RESEARCH,
                           "research_commit": "c" * 40,
                           "paper_table": "tables/overall_performance.tex",
                           "paper_table_sha256": "d" * 64,
                           "paper_table_check": "all 70 values equal"},
            "metrics": [m for m, _ in B.COLUMNS],
            "rows": board["rows"], "cells": board["cells"]}


def _result(base_cell, passes, kc, **rebuilt):
    n = base_cell["population"]
    return {"recorded": {"pass": {"count": base_cell["pass"],
                                  "denominator": base_cell["pass_den"],
                                  "excluded": 0}},
            "rebuilt": {"pass": {"count": passes, "denominator": n,
                                 "excluded": 0},
                        "kill_complete": kc, "recall_mean": 0.95,
                        "api_f1": 0.85, "api_n": passes, "coverage_j": 0.75,
                        **rebuilt},
            "gates": {"gate2": "pass"}, "sources": {"rows": "x.jsonl"}}


@pytest.fixture
def h25(tmp_path):
    """The builder, a synthetic base board and a complete manifest whose
    re-scored cells raise every affected pass count to 3/4 of N."""
    B = builder()
    i_sets = A.load_i_sets()
    base = _base_board(B, i_sets)
    supp = {"configurations": B.SUPPLEMENT_CONFIGURATIONS,
            "provenance": {"record_commit": "e" * 40}, "_sha256": "f" * 64,
            "cells": _cells(B.SUPPLEMENT_CONFIGURATIONS, i_sets, "later")}
    by = {(c["arm"], c["project"], c["view"]): c
          for c in base["cells"] + supp["cells"]}
    entries = []
    for cfg in B.CONFIGURATIONS + B.SUPPLEMENT_CONFIGURATIONS:
        for project in B.H25_PROJECTS:
            for view in ("th", "ah"):
                cell = by[(cfg["arm"], project, view)]
                n = cell["population"]
                rel = f"{project}/{cfg['id']}__{view}/result.json"
                path = tmp_path / rel
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps(_result(cell, 3 * n // 4, n // 3)))
                entries.append({"config": cfg["id"], "project": project,
                                "view": view, "path": rel,
                                "sha256": hashlib.sha256(
                                    path.read_bytes()).hexdigest()})
    manifest = tmp_path / "manifest.json"

    def write(entries=entries):
        manifest.write_text(json.dumps({"cells": entries}))
        return manifest
    write()
    return B, i_sets, base, entries, write, tmp_path, supp


def test_h25_overlays_only_the_affected_projects(h25):
    B, i_sets, base, _entries, write, _tmp, supp = h25
    board = B.build_h25(base, write(), i_sets, supp)
    assert board["harness_version"] == 25 and board["release"] == "paper"
    old = {(c["arm"], c["project"], c["view"]): c
           for c in base["cells"] + supp["cells"]}
    assert len(board["cells"]) == 8 * 8 * 2
    for cell in board["cells"]:
        before = old[(cell["arm"], cell["project"], cell["view"])]
        n = before["population"]
        if cell["project"] in B.H25_PROJECTS:
            assert (cell["pass"], cell["kc"]) == (3 * n // 4, n // 3)
            assert cell["source"]["scoring"] == "re-scored"
            assert cell["source"]["gates"] == {"gate2": "pass"}
        else:
            assert {k: cell[k] for k in B.FIELDS} == \
                {k: before[k] for k in B.FIELDS}
            assert cell["source"]["scoring"].startswith("unaffected")
    # The row mean is the leaderboard aggregation of the overlaid cells.
    cfg = B.CONFIGURATIONS[0]
    values = {(c["project"], c["view"]): A.leaderboard_values(
        c, i_sets[c["project"]]) for c in board["cells"]
        if c["arm"] == cfg["arm"]}
    want = A.macro(values)["th"]["pass_at_1"]["value"]
    assert board["rows"][0]["views"]["th"]["pass_at_1"] == pytest.approx(want)
    assert board["rows"][0]["views"]["th"]["projects"] == 8


def test_h25_has_eight_ordinary_rows(h25):
    """The board has the seven base configurations and Claude Code /
    Claude Sonnet 5.5, all alike: no row carries a mark."""
    B, i_sets, base, _entries, write, _tmp, supp = h25
    board = B.build_h25(base, write(), i_sets, supp)
    ids = [r["id"] for r in board["rows"]]
    assert ids == [c["id"] for c in B.CONFIGURATIONS] + ["claude-code-sonnet55"]
    later = board["rows"][-1]
    assert (later["system"], later["model"]) == ("Claude Code",
                                                 "Claude Sonnet 5.5")
    assert all(set(r) == {"id", "system", "model", "reasoning", "arm",
                          "views"} for r in board["rows"])
    kept = [c for c in board["cells"] if c["arm"] == later["arm"]
            and c["project"] not in B.H25_PROJECTS]
    assert len(kept) == 8 and all(
        c["source"]["scoring"] == "unaffected project; the cell of "
        "req2test/data/claude_code_sonnet55_cells.json"
        and c["source"]["path"].startswith("later/") for c in kept)
    assert board["provenance"]["supplement"]["sha256"] == "f" * 64
    assert board["provenance"]["base"]["board"] == \
        "req2test/data/leaderboard_base.json"
    # The base board is the seven configurations with base cells.
    paper = json.loads((A.DATA / B.BASE_FILE).read_text())
    assert [r["id"] for r in paper["rows"]] == \
        [c["id"] for c in B.CONFIGURATIONS]
    assert {c["arm"] for c in paper["cells"]} == \
        {c["arm"] for c in B.CONFIGURATIONS}


def _data_rows(text: str) -> list:
    """The data rows (lists of cells) of every Markdown table in `text`."""
    rows = []
    for line in text.splitlines():
        if line.startswith("| ") and not line.startswith("| System |"):
            rows.append([c.strip() for c in line.strip("|").split("|")])
    return rows


def test_h25_refuses_a_missing_cell(h25):
    B, i_sets, base, entries, write, _tmp, supp = h25
    with pytest.raises(SystemExit, match="1 affected cell\\(s\\) have no "
                                         "entry"):
        B.build_h25(base, write(entries[1:]), i_sets, supp)
    later = [e for e in entries if e["config"] == "claude-code-sonnet55"]
    assert len(later) == 8
    with pytest.raises(SystemExit, match="claude-code-sonnet55/coddy-agent"):
        B.build_h25(base, write([e for e in entries if e is not later[0]]),
                    i_sets, supp)


def test_h25_needs_every_supplementary_cell(h25):
    B, i_sets, base, _entries, write, _tmp, supp = h25
    short = dict(supp, cells=supp["cells"][1:])
    with pytest.raises(SystemExit, match="needs each of the 16 cells"):
        B.build_h25(base, write(), i_sets, short)
    twice = dict(supp, cells=supp["cells"] + supp["cells"][:1])
    with pytest.raises(SystemExit, match="listed twice"):
        B.build_h25(base, write(), i_sets, twice)
    other = dict(supp, configurations=[dict(
        B.SUPPLEMENT_CONFIGURATIONS[0], model="another")])
    with pytest.raises(SystemExit, match="SUPPLEMENT_CONFIGURATIONS"):
        B.build_h25(base, write(), i_sets, other)
    mixed = dict(base, cells=base["cells"] + supp["cells"][:1])
    with pytest.raises(SystemExit, match="supplementary configuration"):
        B.build_h25(mixed, write(), i_sets, supp)


def test_h25_compares_a_later_cell_with_its_supplementary_cell(h25):
    """A re-scored Sonnet 5.5 cell's recorded pass count must be that of its
    supplementary cell."""
    B, i_sets, base, entries, write, tmp, supp = h25
    i = next(k for k, e in enumerate(entries)
             if e["config"] == "claude-code-sonnet55")
    path = tmp / entries[i]["path"]
    doc = json.loads(path.read_text())
    doc["recorded"]["pass"]["count"] += 1
    path.write_text(json.dumps(doc))
    entries[i]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(SystemExit, match="right cell"):
        B.build_h25(base, write(), i_sets, supp)


def test_h25_refuses_a_changed_file(h25):
    B, i_sets, base, entries, write, tmp, supp = h25
    (tmp / entries[0]["path"]).write_text("{}")
    with pytest.raises(SystemExit, match="the manifest says"):
        B.build_h25(base, write(), i_sets, supp)


def test_h25_refuses_a_cell_that_is_not_final(h25):
    B, i_sets, base, entries, write, tmp, supp = h25
    path = tmp / entries[0]["path"]
    doc = json.loads(path.read_text())
    doc["rebuilt"]["kill_complete"] = None
    path.write_text(json.dumps(doc))
    entries[0]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(SystemExit, match="is not final"):
        B.build_h25(base, write(), i_sets, supp)


def test_h25_refuses_an_entry_for_another_cell(h25):
    B, i_sets, base, entries, write, tmp, supp = h25
    path = tmp / entries[0]["path"]
    doc = json.loads(path.read_text())
    doc["recorded"]["pass"]["count"] += 1
    path.write_text(json.dumps(doc))
    entries[0]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(SystemExit, match="right cell"):
        B.build_h25(base, write(), i_sets, supp)
    # A cell the paper's exclusions changed is not compared on its recorded
    # count, but its rebuilt cell must exclude the same attempt.
    _base_cell(B, base, entries[0])["override"] = {"item": "a.feature:7",
                                                   "reason": "y"}
    with pytest.raises(SystemExit, match="the paper excluded a.feature:7"):
        B.build_h25(base, write(), i_sets, supp)
    doc["recorded"]["pass"]["count"] = None
    doc["rebuilt"]["pass"]["excluded_infrastructure"] = ["p/f/a.feature:7"]
    path.write_text(json.dumps(doc))
    entries[0]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    board = B.build_h25(base, write(), i_sets, supp)
    got = next(c for c in board["cells"] if c["source"].get("path")
               == entries[0]["path"])
    assert got["override"]["item"] == "a.feature:7"


def test_h25_keeps_a_recorded_cell_and_refuses_unknown_configs(h25):
    B, i_sets, base, entries, write, _tmp, supp = h25
    first = dict(entries[0])
    entries[0] = {k: first[k] for k in ("config", "project", "view")}
    entries[0]["keep_recorded"] = "no affected attempt"
    board = B.build_h25(base, write(), i_sets, supp)
    arm = next(c["arm"] for c in B.CONFIGURATIONS
               if c["id"] == first["config"])
    kept = next(c for c in board["cells"] if (c["arm"], c["project"],
                c["view"]) == (arm, first["project"], first["view"]))
    old = next(c for c in base["cells"] if (c["arm"], c["project"],
               c["view"]) == (arm, first["project"], first["view"]))
    assert kept["pass"] == old["pass"]
    assert kept["source"]["scoring"] == "kept: no affected attempt"
    with pytest.raises(SystemExit, match="not a leaderboard row"):
        B.build_h25(base, write(entries + [dict(first, config="sonnet")]),
                    i_sets, supp)


#: Wording that belongs to a development record, not to the leaderboard.
BANNED = re.compile(r"pending|expected late|after the paper|"
                    r"not in the paper|harness[ -]2[5-7]|1\.0 table|"
                    r"research repository|will be replaced|\bAH\b", re.I)


def _v2_doc(B, i_sets, pending=False):
    """A synthetic 1.1 cells file: two rows over the 1.1 population; the
    first row's algorand-sdk API F1 is not measured, and with `pending` the
    second row's coreshop KillComplete is still pending."""
    from req2test.report import population_exclusions
    excluded = sorted(population_exclusions("1.1")["excluded"])
    v2_sets = {}
    for project, iset in i_sets.items():
        n = iset["census_n"] - sum(1 for iid in excluded
                                   if iid.startswith(project + "/"))
        v2_sets[project] = {"I_api": n, "I_cov": n, "census_n": n}
    doc = {"schema": B.V2_SCHEMA, "population_excluded": excluded,
           "i_sets": v2_sets, "rows": {}, "cells": []}
    for rid, model in (("codex-ds-runtime", B.DEEPSEEK),
                       ("codex-sol61", "GPT-6.1 Sol")):
        values = {}
        for project, iset in v2_sets.items():
            n = iset["census_n"]
            cell = {"row": rid, "project": project, "population": n,
                    "pass": n - 2, "pass_den": n, "kc": n // 3,
                    "api_f1": 0.8, "api_n": n - 2, "cov_j": 0.9,
                    "mut_recall": 0.95}
            if rid == "codex-ds-runtime" and project == "algorand-sdk":
                cell.update(api_f1=None, api_n=None)
            if pending and rid == "codex-sol61" and project == "coreshop":
                cell.update(kc=None, mut_recall=None,
                            pending=["KillComplete map"])
            cell["values"] = A.leaderboard_values(cell, iset)
            values[(project, "th")] = cell["values"]
            doc["cells"].append(cell)
        doc["rows"][rid] = {"label": rid, "system": "Codex CLI",
                            "model": model, "reasoning": "high",
                            "mean": A.macro(values)["th"]}
    return doc


def _paper_board():
    B = builder()
    paper = json.loads((A.DATA / B.PAPER_FILE).read_text())
    paper["_sha256"] = "a" * 64
    return paper


def test_board_has_the_1_1_rows_and_the_papers_th_rows():
    B = builder()
    i_sets = A.load_i_sets()
    doc = _v2_doc(B, i_sets)
    board = B.build_board(_paper_board(), doc, i_sets)
    assert board["release"] == "1.1" and board["complete"]
    assert len(board["rows"]) == 10
    assert {c["view"] for c in board["cells"]} == {"th"}
    assert len(board["cells"]) == 10 * 8
    marks = {r["id"]: r["mark"] for r in board["rows"]}
    assert marks["codex-ds-runtime"] == "\u2021"
    assert marks["codex-sol61"] is None
    assert all(m == "\u2020" for k, m in marks.items()
               if k not in ("codex-ds-runtime", "codex-sol61"))
    ds = next(r for r in board["rows"] if r["id"] == "codex-ds-runtime")
    # Algorand's API F1 is not measured: no eight-project mean.
    assert ds["views"]["th"]["api_f1"] is None and not ds["pending"]
    text = B.markdown(board)
    assert text.count("| System |") == 1 and len(_data_rows(text)) == 10
    assert B.PAPER_NOTE in text and B.V2_NOTES["\u2021"] in text
    assert "| Codex CLI\u2021 | DeepSeek-V4.1-Flash | high |" in text
    assert "\u2013" in text and B.PENDING not in text
    assert not BANNED.search(text)
    readme = B.readme_table(board)
    tp = [float(line.split(" | ")[3]) for line in readme[2:12]]
    assert tp == sorted(tp, reverse=True)


def test_board_prints_a_pending_mean_as_the_placeholder():
    B = builder()
    i_sets = A.load_i_sets()
    board = B.build_board(_paper_board(), _v2_doc(B, i_sets, pending=True),
                          i_sets)
    assert not board["complete"]
    sol = next(r for r in board["rows"] if r["id"] == "codex-sol61")
    assert sol["pending"] == ["kill_complete_at_1", "mutation_recall"]
    line = next(x for x in B.readme_table(board) if "GPT-6.1 Sol" in x)
    assert line.count(B.PENDING) == 2


def test_board_refuses_cells_that_do_not_match():
    B = builder()
    i_sets = A.load_i_sets()
    doc = _v2_doc(B, i_sets)
    doc["population_excluded"] = doc["population_excluded"][1:]
    with pytest.raises(SystemExit, match="population list"):
        B.build_board(_paper_board(), doc, i_sets)
    doc = _v2_doc(B, i_sets)
    doc["cells"][0]["kc"] += 1
    with pytest.raises(SystemExit, match="not the file's"):
        B.build_board(_paper_board(), doc, i_sets)
    doc = _v2_doc(B, i_sets)
    doc["rows"]["codex-sol61"]["mean"]["pass_at_1"]["value"] += 0.01
    with pytest.raises(SystemExit, match="mean pass_at_1"):
        B.build_board(_paper_board(), doc, i_sets)


def test_main_writes_the_board_markdown_and_readme(h25, tmp_path):
    B, i_sets, base, _entries, write, _tmp, supp = h25
    out = tmp_path / "out"
    base_file = tmp_path / "base.json"
    base_file.write_text(json.dumps(base))
    cells = tmp_path / "supplement.json"
    cells.write_text(json.dumps({k: v for k, v in supp.items()
                                 if k != "_sha256"}))
    paper = tmp_path / "paper.json"
    assert B.main(["--h25-manifest", str(write()), "--base", str(base_file),
                   "--supplement-cells", str(cells),
                   "--paper-board", str(paper)]) == 0
    doc = json.loads(paper.read_text())
    assert doc["provenance"]["base"]["sha256"] == hashlib.sha256(
        base_file.read_bytes()).hexdigest()
    assert len(doc["rows"]) == 8
    v2 = tmp_path / "cells_v2.json"
    v2.write_text(json.dumps(_v2_doc(B, i_sets)))
    readme = tmp_path / "README.md"
    readme.write_text(f"# x\n\n{B.README_START}\nold\n{B.README_END}\n\nend\n")
    args = ["--v2-cells", str(v2), "--paper-board", str(paper),
            "--out", str(out)]
    assert B.main(args + ["--readme", str(readme)]) == 0
    board = json.loads((out / B.H25_FILE).read_text())
    assert B.H25_FILE == "leaderboard.json"
    assert board["provenance"]["v2_cells_sha256"] == hashlib.sha256(
        v2.read_bytes()).hexdigest()
    assert len(board["rows"]) == 10
    assert (out / "leaderboard.md").read_text() == B.markdown(board)
    block = "\n".join(B.readme_table(board))
    assert readme.read_text() == (f"# x\n\n{B.README_START}\n{block}\n"
                                  f"{B.README_END}\n\nend\n")
    # Without the markers nothing is written.
    readme.write_text("# x\n")
    (out / B.H25_FILE).unlink()
    with pytest.raises(SystemExit, match="exactly once"):
        B.main(args + ["--readme", str(readme)])
    assert not (out / B.H25_FILE).exists()
    # README writing is opt-in and needs the board mode.
    with pytest.raises(SystemExit):
        B.main(["--research", str(tmp_path), "--readme", str(readme)])


def _readme_block(text: str, B) -> list:
    assert text.count(B.README_START) == 1 and text.count(B.README_END) == 1
    block = text[text.index(B.README_START):text.index(B.README_END)]
    return _data_rows(block)


def test_committed_leaderboard_is_one_rendered_board():
    """`results/leaderboard.md` and the README's block are the rendering of
    `results/leaderboard.json`: ten target-hidden rows, the paper's
    eight marked."""
    B = builder()
    md = (ROOT / "results" / "leaderboard.md").read_text()
    readme = (ROOT / "README.md").read_text()
    rows = _readme_block(readme, B)
    assert len(rows) == 10 and all(len(r) == 8 for r in rows)
    assert readme.count("| System |") == 1     # one leaderboard table
    board = json.loads((ROOT / "results" / B.H25_FILE).read_text())
    assert board["release"] == "1.1"
    assert md == B.markdown(board)
    assert rows == _data_rows("\n".join(B.readme_table(board)))
    assert sum(r[0].endswith("\u2020") for r in rows) == 8
    assert _data_rows(md) == rows
    assert not BANNED.search(md)
    paper = json.loads((A.DATA / B.PAPER_FILE).read_text())
    assert [r for r in board["rows"] if r["results"] == "paper"] == [
        {k: r[k] for k in ("id", "system", "model", "reasoning", "arm")}
        | {"results": "paper", "mark": "\u2020",
           "views": {"th": r["views"]["th"]}, "pending": []}
        for r in paper["rows"]]


def _h25_cell_file(tmp, entry, base_cell, passes, kc, api_render=True,
                   **extra):
    """Rewrite `entry`'s cell as an `h25-cell/1` file (the re-scoring's
    format), with its results render beside it."""
    path = tmp / entry["path"]
    m = {"passed": passes, "denominator": base_cell["population"],
         "pass_rate": passes / base_cell["population"],
         "excluded_infrastructure": [], "kill_complete": kc,
         "recall_mean": 0.95, "recall_n": passes, "api_f1": 0.85,
         "coverage_jaccard": 0.75}
    rec = dict(m, passed=base_cell["pass"], denominator=base_cell["pass_den"])
    doc = {"schema": "h25-cell/1", "project": entry["project"],
           "cell": f"{entry['config']}__{entry['view']}",
           "config": entry["config"],
           "view": {"th": "target_hidden", "ah": "all_hidden"}[entry["view"]],
           "harness_version": 25, "recorded": rec, "rebuilt": m,
           "gates": {"gate2": "pass", "gate3": "pass"}, "lost_passes": [],
           "files": {"results_rebuilt": "results.rebuilt.json"}}
    doc.update(extra)
    path.write_text(json.dumps(doc))
    if api_render:
        (path.parent / "results.rebuilt.json").write_text(json.dumps(
            {"api": {"n_passed": passes, "n_scored": passes - 1}}))
    entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return path


def _base_cell(B, base, entry):
    arm = next(c["arm"] for c in B.CONFIGURATIONS if c["id"] == entry["config"])
    return next(c for c in base["cells"] if (c["arm"], c["project"],
                c["view"]) == (arm, entry["project"], entry["view"]))


def test_h25_reads_the_rescoring_cell_format(h25):
    B, i_sets, base, entries, write, tmp, supp = h25
    cell0 = _base_cell(B, base, entries[0])
    _h25_cell_file(tmp, entries[0], cell0, 10, 4)
    board = B.build_h25(base, write(), i_sets, supp)
    got = next(c for c in board["cells"] if c["source"].get("schema")
               == "h25-cell/1")
    assert (got["pass"], got["kc"], got["api_n"], got["cov_j"]) == \
        (10, 4, 9, 0.75)
    assert got["source"]["api_n_from"]["path"] == "results.rebuilt.json"
    # Without the render there is no API count to scale API F1 by: stop.
    (tmp / entries[0]["path"]).parent.joinpath("results.rebuilt.json").unlink()
    with pytest.raises(SystemExit, match="not beside the cell file"):
        B.build_h25(base, write(), i_sets, supp)


def test_h25_cell_must_name_its_own_cell_and_pass_its_gates(h25):
    B, i_sets, base, entries, write, tmp, supp = h25
    cell0 = _base_cell(B, base, entries[0])
    _h25_cell_file(tmp, entries[0], cell0, 10, 4, config="codex-sol"
                   if entries[0]["config"] != "codex-sol" else "aider-ds")
    with pytest.raises(SystemExit, match="the file is for"):
        B.build_h25(base, write(), i_sets, supp)
    _h25_cell_file(tmp, entries[0], cell0, 10, 4,
                   gates={"gate2": "pass", "gate4": "fail"})
    with pytest.raises(SystemExit, match="did not pass"):
        B.build_h25(base, write(), i_sets, supp)
    # The re-scoring's "n/a" and "disclosed" pass without a note.
    _h25_cell_file(tmp, entries[0], cell0, 10, 4,
                   gates={"gate2": "pass", "gate3": "n/a",
                          "gate5": "disclosed"})
    B.build_h25(base, write(), i_sets, supp)
    _h25_cell_file(tmp, entries[0], cell0, 10, 4,
                   gates={"gate2": "pass", "gate4": "fail"})
    entries[0]["gate_note"] = "label difference, ruled equivalent"
    board = B.build_h25(base, write(), i_sets, supp)
    got = next(c for c in board["cells"] if c["source"].get("schema")
               == "h25-cell/1")
    assert got["source"]["gate_note"] == "label difference, ruled equivalent"


def test_h25_carries_the_papers_real_exclusions(tmp_path):
    """The base board's three exclusion cells: a rebuilt cell that
    still counts the excluded attempt stops the build; one that lists it in
    `excluded_infrastructure` or `excluded_unknown_terminal` keeps the
    override, even when the producer withholds the recorded count."""
    B = builder()
    i_sets = A.load_i_sets()
    base = json.loads((A.DATA / B.BASE_FILE).read_text())
    supp = json.loads((A.DATA / B.SUPPLEMENT_FILE).read_text())
    cfg_of = {c["arm"]: c["id"] for c in B.CONFIGURATIONS
              + B.SUPPLEMENT_CONFIGURATIONS}
    special = {(cfg_of[c["arm"]], c["project"], c["view"]): c
               for c in base["cells"] if "override" in c}
    assert len(special) == 3
    entries = [{"config": c, "project": p, "view": v, "keep_recorded": "x"}
               for c in cfg_of.values() for p in B.H25_PROJECTS
               for v in ("th", "ah") if (c, p, v) not in special]

    def write(listed):
        out = list(entries)
        for (c, p, v), cell in special.items():
            entry = {"config": c, "project": p, "view": v,
                     "path": f"{p}/{c}__{v}/h25-cell.json"}
            item = f"{p}/features/{cell['override']['item']}"
            path = _h25_cell_file(tmp_path, entry, cell,
                                  cell["pass_den"] // 2, 3)
            doc = json.loads(path.read_text())
            doc["recorded"]["passed"] = None
            doc["rebuilt"]["denominator"] = cell["pass_den"]
            doc["rebuilt"]["excluded_infrastructure"] = []
            if listed:
                doc["rebuilt"][listed] = [item]
            path.write_text(json.dumps(doc))
            entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            out.append(entry)
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({"cells": out}))
        return manifest

    for c, p, v in special:
        (tmp_path / p / f"{c}__{v}").mkdir(parents=True)
    with pytest.raises(SystemExit, match="the paper excluded"):
        B.build_h25(base, write(listed=None), i_sets, supp)
    for listed in ("excluded_infrastructure", "excluded_unknown_terminal"):
        board = B.build_h25(base, write(listed=listed), i_sets, supp)
        got = [c for c in board["cells"] if "override" in c]
        assert len(got) == 3
        assert all(c["source"]["scoring"] == "re-scored" for c in got)


def test_committed_supplement_is_the_sonnet_arms_cells():
    """The committed base cells of Claude Code / Claude Sonnet 5.5: all 16,
    each with its source in the arm's record, aggregating to the rows they
    carry and to the eight-project means the arm's record reported (in
    percent, to 0.1)."""
    B = builder()
    i_sets = A.load_i_sets()
    doc = json.loads((A.DATA / B.SUPPLEMENT_FILE).read_text())
    cells = B.check_supplement(doc, i_sets)
    assert len(cells) == 16
    assert len(doc["provenance"]["record_commit"]) == 40
    for c in cells:
        assert c["source"]["path"].startswith(B.SONNET_RECORD + "/")
        assert len(c["source"]["sha256"]) == 64
        assert len(c["source"]["render"]["sha256"]) == 64
    fresh = [{k: c[k] for k in ("project", "arm", "view", "source") + B.FIELDS}
             for c in cells]
    rows = B.aggregate_cells(fresh, i_sets, B.SUPPLEMENT_CONFIGURATIONS)["rows"]
    assert rows == doc["rows_before_h25"]
    reported = {"th": [72.1, 33.8, 54.8, 68.0, 67.6],
                "ah": [70.1, 32.5, 52.6, 66.4, 66.2]}
    assert {v: [round(100 * rows[0]["views"][v][m], 1) for m, _ in B.COLUMNS]
            for v in ("th", "ah")} == reported


def test_render_row_reads_a_printed_value():
    B = builder()
    text = "| metric | value |\n| api f1 | 0.929 |\n| api f1 (full) | 0.8 |\n"
    assert B._render_row(text, "api f1", "x") == "0.929"
    with pytest.raises(SystemExit, match="no 'coverage"):
        B._render_row(text, "coverage jaccard similarity", "x")
