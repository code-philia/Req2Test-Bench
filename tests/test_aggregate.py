"""`req2test.aggregate`: both modes, the macro, the paper's table, bootstrap."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from req2test import aggregate as A

REPO = Path(__file__).resolve().parents[1]

#: Table `tab:overall-performance` of the paper (v9, 2026-10-03), as printed:
#: Pass@1, KillComplete@1, API F1, Coverage J, Mutation R per view.
PAPER_TABLE = {
    "aider-ds": {"th": [9.3, 4.5, 6.4, 7.8, 8.3], "ah": [9.4, 4.4, 6.6, 7.9, 8.5]},
    "openhands-ds": {"th": [30.1, 17.5, 24.2, 28.5, 28.8],
                     "ah": [25.1, 16.1, 20.0, 23.8, 24.0]},
    "claude-code-ds": {"th": [72.8, 32.9, 55.8, 66.3, 66.5],
                       "ah": [66.2, 29.2, 51.6, 61.3, 60.7]},
    "codex-ds-off": {"th": [53.4, 22.8, 38.6, 49.2, 49.5],
                     "ah": [43.1, 20.3, 30.6, 40.1, 40.1]},
    "codex-ds": {"th": [76.5, 32.7, 59.3, 70.3, 70.6],
                 "ah": [68.5, 32.0, 50.9, 63.8, 63.0]},
    "codex-luna": {"th": [59.1, 26.4, 44.3, 53.1, 54.1],
                   "ah": [49.6, 25.5, 37.3, 45.9, 46.8]},
    "codex-sol": {"th": [63.9, 29.5, 47.4, 57.5, 58.3],
                  "ah": [57.1, 27.4, 42.3, 52.8, 53.5]},
}


def inst(iid, outcome="pass", **kw):
    row = {"instance_id": iid, "project": "e-petitions", "view": "th",
           "outcome": outcome, "passed": outcome == "pass", "api_f1": None,
           "coverage_j": None, "recall": None, "kill_complete": False,
           "kill_complete_strict": False, "kill_complete_95": False,
           "mutation_status": "scored" if outcome == "pass" else "not_passed",
           "behaviour_status": "measured"}
    row.update(kw)
    return row


ISETS = {"e-petitions": {"I_api": 2, "I_cov": 4, "census_n": 4}}


class CellTest(unittest.TestCase):
    def rows(self):
        return [
            inst("e/a.feature:1", api_f1=1.0, coverage_j=0.8, recall=1.0,
                 kill_complete=True, kill_complete_strict=True,
                 kill_complete_95=True),
            inst("e/a.feature:9", coverage_j=0.6, recall=0.5),
            inst("e/b.feature:1", "assertion_failure"),
            inst("e/b.feature:5", "infrastructure_excluded"),
        ]

    def test_leaderboard_mode(self):
        got = A.aggregate(self.rows(), "leaderboard", i_sets=ISETS)
        cell = got["cells"]["e-petitions/th"]
        den = 3
        self.assertAlmostEqual(cell["pass_at_1"], 2 / den)
        self.assertAlmostEqual(cell["kill_complete_at_1"], 1 / 4)
        # api = f1 * api_n / (I_api * den / N)
        self.assertAlmostEqual(cell["api_f1"], 1.0 * 1 / (2 * den / 4))
        # cov = J * p / (I_cov * den / N), J the mean over passes with J
        self.assertAlmostEqual(cell["coverage_j"], 0.7 * 2 / (4 * den / 4))
        # mut = mean recall over scored passes * p / den
        self.assertAlmostEqual(cell["mutation_recall"], 0.75 * 2 / den)
        self.assertFalse(got["mean"]["th"]["complete"])

    def test_exact(self):
        isets = {"e-petitions": {"I_api": ["e/a.feature:1", "e/b.feature:5"],
                                 "I_cov": [r["instance_id"] for r in self.rows()],
                                 "census_n": 4}}
        cell = A.aggregate(self.rows(), "exact", i_sets=isets)["cells"][
            "e-petitions/th"]
        self.assertAlmostEqual(cell["pass_at_1"], 2 / 3)
        self.assertAlmostEqual(cell["kill_complete_at_1"], 1 / 4)
        self.assertAlmostEqual(cell["api_f1"], 1.0 / 1)   # |I_api ∩ E| = 1
        self.assertAlmostEqual(cell["coverage_j"], 1.4 / 3)
        self.assertAlmostEqual(cell["mutation_recall"], 1.5 / 3)
        self.assertAlmostEqual(cell["kill_complete_strict_at_1"], 1 / 4)

    def test_unscored_pass(self):
        rows = self.rows()[:2] + [inst("e/c.feature:1",
                                       mutation_status="unscored")]
        paper = A.aggregate(rows, "leaderboard", i_sets=ISETS)["cells"][
            "e-petitions/th"]
        exact = A.aggregate(rows, "exact", i_sets=ISETS)["cells"][
            "e-petitions/th"]
        # leaderboard: the unscored pass leaves the recall mean; exact: it is 0
        self.assertAlmostEqual(paper["mutation_recall"], 0.75 * 3 / 3)
        self.assertAlmostEqual(exact["mutation_recall"], 1.5 / 3)
        self.assertEqual(exact["unscored_passes"], 1)

    def test_not_run_is_none(self):
        rows = [dict(r, behaviour_status="not_run",
                     mutation_status="not_run" if r["passed"] else "not_passed")
                for r in self.rows()]
        for mode in A.MODES:
            cell = A.aggregate(rows, mode, i_sets=ISETS)["cells"][
                "e-petitions/th"]
            self.assertIsNotNone(cell["pass_at_1"])
            for m in ("kill_complete_at_1", "api_f1", "coverage_j",
                      "mutation_recall"):
                self.assertIsNone(cell[m], (mode, m))

    def test_zero_passes(self):
        cell = A.leaderboard_values({"population": 4, "pass": 0, "pass_den": 4,
                                  "kc": 0, "api_f1": None, "api_n": 0,
                                  "cov_j": None, "mut_recall": None},
                                 ISETS["e-petitions"])
        self.assertEqual([cell[m] for m in A.METRICS], [0.0] * 5)

    def test_empty_i_set_and_denominator(self):
        cell = {"population": 3, "pass": 1, "pass_den": 3, "kc": 1,
                "api_f1": 0.5, "api_n": 1, "cov_j": 0.5, "mut_recall": 1.0}
        got = A.leaderboard_values(cell, {"I_api": 0, "I_cov": 3, "census_n": 3})
        self.assertIsNone(got["api_f1"])
        self.assertAlmostEqual(got["coverage_j"], 0.5 / 3)
        none = A.leaderboard_values(dict(cell, pass_den=0),
                                 {"I_api": 1, "I_cov": 3, "census_n": 3})
        self.assertEqual([none[m] for m in A.METRICS], [None] * 5)

    def test_macro_equal_weight(self):
        cells = {("a", "th"): {"pass_at_1": 1.0}, ("b", "th"): {"pass_at_1": 0.0},
                 ("c", "th"): {"pass_at_1": None}}
        got = A.macro(cells, ["pass_at_1"])["th"]["pass_at_1"]
        self.assertEqual(got, {"value": 0.5, "projects": 2})


class LeaderboardTest(unittest.TestCase):
    """The leaderboard's base cells (`req2test/data/leaderboard_base.json`),
    aggregated in `leaderboard` mode, give the paper's overall table to the
    printed 0.1."""

    def test_reproduces_paper_table(self):
        board = json.loads((A.DATA / "leaderboard_base.json").read_text())
        i_sets = A.load_i_sets()
        self.assertEqual(len(board["cells"]), 112)
        metrics = ["pass_at_1", "kill_complete_at_1", "api_f1", "coverage_j",
                   "mutation_recall"]
        for row in board["rows"]:
            cells = [c for c in board["cells"] if c["arm"] == row["arm"]]
            self.assertEqual(len(cells), 16, row["id"])
            values = {(c["project"], c["view"]):
                      A.leaderboard_values(c, i_sets[c["project"]]) for c in cells}
            means = A.macro(values, metrics)
            for view in ("th", "ah"):
                got = [round(100 * means[view][m]["value"], 1) for m in metrics]
                self.assertEqual(got, PAPER_TABLE[row["id"]][view],
                                 (row["id"], view))
                self.assertTrue(all(means[view][m]["projects"] == 8
                                    for m in metrics))


class PopulationExclusionTest(unittest.TestCase):
    """A population's exclusion list (benchmark 1.1, synthetic here)."""

    def rows(self):
        # real ids carry their project, which the census adjustment reads
        return [dict(r, instance_id="e-petitions/" + r["instance_id"][2:])
                for r in CellTest.rows(self)]

    def test_excluded_instances_leave_every_measure(self):
        excluded = {"e-petitions/a.feature:1": "census_pass",
                    "e-petitions/other.feature:7": "zero_body",  # not run
                    "sylius/x.feature:3": "census_pass"}     # another project
        rows = self.rows()
        for mode in A.MODES:
            got = A.aggregate(rows, mode, i_sets=ISETS, excluded=excluded)
            cell = got["cells"]["e-petitions/th"]
            want = A.aggregate(rows[1:], mode, i_sets=ISETS)[
                "cells"]["e-petitions/th"]
            for m in A.METRICS:
                self.assertEqual(cell[m], want[m], (mode, m))
            self.assertEqual((cell["n"], cell["passes"]), (3, 1))
            # the census is the population's: 4 minus the listed 2
            self.assertEqual((cell["census_n"], cell["complete"]), (2, False))
            self.assertEqual(cell["population_excluded"],
                             ["e-petitions/a.feature:1"])

    def test_no_list_changes_nothing(self):
        rows = self.rows()
        for mode in A.MODES:
            got = A.aggregate(rows, mode, i_sets=ISETS)
            self.assertNotIn("population_excluded",
                             got["cells"]["e-petitions/th"])
            self.assertEqual(got, A.aggregate(rows, mode, i_sets=ISETS,
                                              excluded=None))

    def test_bootstrap_leaves_them_out(self):
        rows = self.rows()
        excluded = {"e-petitions/a.feature:1": "census_pass"}
        self.assertEqual(
            A.bootstrap(rows, i_sets=ISETS, n_boot=50, excluded=excluded),
            A.bootstrap(rows[1:], i_sets=ISETS, n_boot=50))


class ISetsTest(unittest.TestCase):
    def test_bundled_counts(self):
        i_sets = A.load_i_sets()
        self.assertEqual(set(i_sets), set(A.PROJECTS))
        self.assertEqual(sum(v["census_n"] for v in i_sets.values()), 2051)
        for v in i_sets.values():
            self.assertLessEqual(v["I_api"], v["census_n"])
            self.assertLessEqual(v["I_cov"], v["census_n"])


class BootstrapTest(unittest.TestCase):
    def test_deterministic_and_brackets(self):
        rows = []
        for f in range(12):
            for line in (1, 2):
                passed = (f + line) % 3 != 0
                rows.append(inst(f"e/f{f}.feature:{line}",
                                 "pass" if passed else "assertion_failure",
                                 recall=1.0 if passed else None,
                                 kill_complete=passed and f % 2 == 0,
                                 api_f1=0.5 if passed else None,
                                 coverage_j=0.5 if passed else None))
        isets = {"e-petitions": {"I_api": 24, "I_cov": 24, "census_n": 24}}
        a = A.bootstrap(rows, i_sets=isets, n_boot=200)
        b = A.bootstrap(rows, i_sets=isets, n_boot=200)
        self.assertEqual(a, b)
        point = A.aggregate(rows, i_sets=isets)["mean"]["th"]
        for m in ("pass_at_1", "kill_complete_at_1"):
            lo, hi = a["th"][m]
            self.assertLessEqual(lo, point[m]["value"])
            self.assertGreaterEqual(hi, point[m]["value"])
            self.assertLess(lo, hi)


if __name__ == "__main__":
    unittest.main()
