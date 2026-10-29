"""`req2test.report` and the `report --run-id` verb on a small run."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from req2test import cli, report
from req2test import score as S
from r2t.bench import population as P   # the engine, on sys.path (score)
from kitfixture import NATIVE, SINGLE, write_done, write_kit


def write_jsonl(path: Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.kits = {
            "python-docx": write_kit(root / "kits", "python-docx", [
                ("python-docx/f.feature:1", "m0", "killed"),
                ("python-docx/f.feature:1", "m1", "killed"),
                ("python-docx/g.feature:2", "m0", "killed")], rules=SINGLE,
                i_api=["python-docx/f.feature:1"],
                i_cov=["python-docx/f.feature:1", "python-docx/g.feature:2"]),
            "e-petitions": write_kit(root / "kits", "e-petitions", [
                ("e-petitions/a.feature:3", "m0", "killed")], rules=NATIVE),
        }
        self.run = root / "runs" / "r1"
        pdx = self.run / "python-docx" / "th"
        write_jsonl(pdx / "exec.jsonl", [
            {"item_id": "python-docx/f.feature:1", "outcome": "passed",
             "harness_version": 24},
            {"item_id": "python-docx/g.feature:2", "outcome": "failed",
             "harness_version": 24}])
        (pdx / "behaviour.json").write_text(json.dumps({
            "python-docx/f.feature:1": {"api_f1": 0.5, "coverage_j": 0.9},
            "python-docx/g.feature:2": {"api_f1": None, "coverage_j": 0.4}}))
        write_jsonl(pdx / "mutation" / "shard-0.jsonl", [
            {"instance_id": "python-docx/f.feature:1", "mutant_id": "m0",
             "outcome": "failed"},
            {"instance_id": "python-docx/f.feature:1", "mutant_id": "m1",
             "outcome": "timeout"}])
        write_done(pdx)
        # e-petitions: execution only (no behaviour.json, no mutation/)
        write_jsonl(self.run / "e-petitions" / "th" / "exec.jsonl", [
            {"item_id": "e-petitions/a.feature:3", "outcome": "passed"}])

    def tearDown(self):
        self.tmp.cleanup()

    def kit_for(self, project):
        return self.kits[project]

    def test_build_and_write(self):
        summary = report.build(self.run, kit_for=self.kit_for)
        report.write(self.run, summary)
        rows = [json.loads(line) for line in
                (self.run / "python-docx" / "th" / "instances.jsonl")
                .read_text().splitlines()]
        self.assertEqual(list(rows[0]), list(report.INSTANCE_FIELDS))
        first = rows[0]
        self.assertEqual((first["outcome"], first["kill_complete"],
                          first["kill_complete_strict"], first["n_dropped"],
                          first["api_f1"], first["harness_version"]),
                         ("pass", True, False, 1, 0.5, 24))
        self.assertEqual((rows[1]["outcome"], rows[1]["coverage_j"]),
                         ("assertion_failure", None))

        exact = summary["modes"]["exact"]["cells"]
        self.assertEqual(exact["python-docx/th"]["pass_at_1"], 0.5)
        # the kit's id lists: |I_api ∩ E| = 1, |I_cov ∩ E| = 2
        self.assertEqual(exact["python-docx/th"]["api_f1"], 0.5)
        self.assertEqual(exact["python-docx/th"]["coverage_j"], 0.45)
        # leaderboard sizes the kit's id lists within the run's own instances
        paper = summary["modes"]["leaderboard"]["cells"]["python-docx/th"]
        self.assertEqual((paper["api_f1"], paper["coverage_j"]), (0.5, 0.45))
        epe = summary["modes"]["leaderboard"]["cells"]["e-petitions/th"]
        self.assertEqual(epe["pass_at_1"], 1.0)
        for m in ("kill_complete_at_1", "api_f1", "coverage_j",
                  "mutation_recall"):
            self.assertIsNone(epe[m], m)
        self.assertEqual(summary["disclosures"]["python-docx/th"]
                         ["kill_complete_with_dropped_pairs"], 1)
        self.assertEqual(summary["rules"]["e-petitions"]["family"], "native")
        self.assertEqual(
            summary["rules"]["python-docx"]["nondeterministic_excluded"], [])
        md = (self.run / "report.md").read_text()
        self.assertIn("Mode `leaderboard`", md)
        # The headline mode says what it is, beside its name.
        self.assertIn("## Mode `leaderboard` (the headline: the leaderboard's "
                      "aggregation", md)
        self.assertIn("`docs/metrics.md`)", md.split("## Mode `exact`")[0]
                      .split("## Mode `leaderboard`")[1].splitlines()[0])
        self.assertNotIn("8-project mean", md)
        self.assertIn("**75.0** (2 of 8 projects)", md)
        self.assertIn("**50.0** (1 of 8 projects)", md)

    def test_duplicate_exec_rows_refused(self):
        path = self.run / "python-docx" / "th" / "exec.jsonl"
        path.write_text(path.read_text() + path.read_text().splitlines()[0]
                        + "\n")
        with self.assertRaisesRegex(ValueError, "two execution rows"):
            report.build(self.run, kit_for=self.kit_for)

    def test_measures_only_on_their_instance_sets(self):
        # the pass is outside I_api: its API F1 is dropped, and with no I_api
        # instance in the run the measure is empty rather than a division by 0
        kit = self.kits["python-docx"]
        (kit / "behaviour" / "I_api.json").write_text("[]")
        summary = report.build(self.run, kit_for=self.kit_for)
        row = json.loads((self.run / "python-docx" / "th" / "instances.jsonl")
                         .read_text().splitlines()[0])
        self.assertIsNone(row["api_f1"])
        self.assertEqual(row["coverage_j"], 0.9)
        for mode in ("leaderboard", "exact"):
            cell = summary["modes"][mode]["cells"]["python-docx/th"]
            self.assertIsNone(cell["api_f1"], mode)
            self.assertEqual(cell["coverage_j"], 0.45, mode)

    def test_exclusions_disclosed_by_kind(self):
        write_jsonl(self.run / "e-petitions" / "th" / "exec.jsonl", [
            {"item_id": "e-petitions/a.feature:3", "outcome": "passed"},
            {"item_id": "e-petitions/b.feature:4", "outcome": "harness_error"},
            {"item_id": "e-petitions/c.feature:5",
             "outcome": "passed_but_nonzero_exit"}])
        summary = report.build(self.run, kit_for=self.kit_for)
        d = summary["disclosures"]["e-petitions/th"]
        self.assertEqual(d["infrastructure_excluded"],
                         ["e-petitions/b.feature:4"])
        self.assertEqual(d["outside_ladder_excluded"],
                         {"e-petitions/c.feature:5": "passed_but_nonzero_exit"})
        self.assertEqual(summary["modes"]["exact"]["cells"]["e-petitions/th"]
                         ["pass_at_1"], 1.0)

    def test_cli_missing_run(self):
        rc = cli.main(["report", "--run-id", "nope", "--work-dir",
                       str(Path(self.tmp.name))])
        self.assertEqual(rc, 2)

    def test_cli_verb(self):
        with mock.patch.object(report, "_default_kit", self.kit_for):
            rc = cli.main(["report", "--run-id", "r1", "--work-dir",
                           str(Path(self.tmp.name)), "--ci", "20"])
        self.assertEqual(rc, 0)
        summary = json.loads((self.run / "summary.json").read_text())
        self.assertEqual(summary["headline"], "leaderboard")
        self.assertIn("th", summary["ci"]["exact"])

    def test_cli_rejects_unknown_arguments(self):
        with self.assertRaises(SystemExit):
            cli.main(["report", "--run-id", "r1", "--bogus"])

    def test_rejected_files_listed_per_instance(self):
        path = self.run / "python-docx" / "th" / "exec.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[1]["rejected_files"] = [
            {"file_path": "src/docx/api.py",
             "why": "not_test_code:production"},
            {"file_path": "behat_services.yml", "service_id": "ctx",
             "why": "protected_service_id:ctx"}]
        write_jsonl(path, rows)
        write_done(path.parent)
        summary = report.build(self.run, kit_for=self.kit_for)
        d = summary["disclosures"]["python-docx/th"]
        self.assertEqual(list(d["rejected_files"]),
                         ["python-docx/g.feature:2"])
        md = report.markdown(summary)
        self.assertIn("1 instance(s) with prediction files the engine "
                      "rejected", md)
        self.assertIn("  - `python-docx/g.feature:2`: `src/docx/api.py` "
                      "(not_test_code:production); `behat_services.yml` "
                      "service `ctx` (protected_service_id:ctx)", md)
        self.assertIn("- e-petitions/th: none", md)

    def test_subset_runs_are_marked(self):
        summary = report.build(self.run, kit_for=self.kit_for)
        self.assertNotIn("subset", summary)
        md = report.markdown(summary)
        self.assertNotIn("SUBSET", md)
        self.assertIn("the aggregation of `results/leaderboard.md`, so a "
                      "run of all eight projects compares with the "
                      "leaderboard.", md)
        (self.run / report.SUBSET_FILE).write_text(json.dumps({
            "selection": "sample", "sample": 1, "seed": 7, "split": "eval",
            "projects": {"python-docx": {"n": 2, "of": 237}}}))
        summary = report.build(self.run, kit_for=self.kit_for)
        self.assertEqual(summary["subset"]["note"], report.SUBSET_NOTE)
        md = report.markdown(summary)
        self.assertIn("**SUBSET run: not every instance of the split was "
                      "evaluated, so its values are not comparable to the "
                      "leaderboard.** Selection: a seeded sample of 1 "
                      "instance(s) per project (seed 7) from the eval split "
                      "(python-docx 2 of 237).", md)
        self.assertNotIn("the aggregation of `results/leaderboard.md`", md)
        self.assertNotIn("compare with the leaderboard", md)

    def test_the_benchmark_version_is_reported(self):
        comparable = ("so a run of all eight projects compares with the "
                      "leaderboard")
        (self.run / report.BENCHMARK_FILE).write_text(json.dumps(
            {"benchmark_version": "1.1"}))
        with self.assertRaisesRegex(FileNotFoundError, "not in this checkout"), \
                mock.patch.object(P, "BENCHMARK_POPULATION",
                                  str(Path(self.tmp.name) / "absent.yml")):
            report.build(self.run, kit_for=self.kit_for)
        listed = Path(self.tmp.name) / "population.yml"
        listed.write_text("schema: r2t.benchmark-population/1\n"
                          "benchmark_version: \"2.0\"\ncensus: synthetic\n"
                          "protocols: [9001]\nexcluded: []\n")
        with mock.patch.object(P, "BENCHMARK_POPULATION", str(listed)):
            summary = report.build(self.run, kit_for=self.kit_for)
        self.assertEqual(summary["benchmark_version"], "1.1")
        md = report.markdown(summary)
        self.assertIn("Benchmark version: 1.1.", md)
        self.assertIn(comparable, md)

    def test_full_split_runs_are_marked_not_comparable(self):
        (self.run / report.SPLIT_FILE).write_text(json.dumps({
            "split": "full", "projects": ["python-docx"]}))
        summary = report.build(self.run, kit_for=self.kit_for)
        self.assertEqual(summary["full_split"],
                         {"note": report.FULL_SPLIT_NOTE, "split": "full",
                          "projects": ["python-docx"]})
        self.assertNotIn("subset", summary)
        md = report.markdown(summary)
        self.assertIn("**FULL-SPLIT run: NOT COMPARABLE with the leaderboard, "
                      "which covers only the eval split.** This run evaluated "
                      "the full split of python-docx.", md)
        # The standard comparability line is replaced.
        self.assertNotIn("the aggregation of `results/leaderboard.md`", md)
        self.assertIn("the aggregation of the leaderboard, but this run is "
                      "NOT COMPARABLE with the leaderboard (`results/"
                      "leaderboard.md` covers only the eval split). `exact` "
                      "mode", md)
        # A full-split SUBSET run carries both marks.
        (self.run / report.SUBSET_FILE).write_text(json.dumps({
            "selection": "sample", "sample": 1, "seed": 7, "split": "full",
            "projects": {"python-docx": {"n": 2, "of": 239}}}))
        md = report.markdown(report.build(self.run, kit_for=self.kit_for))
        self.assertIn("**FULL-SPLIT run", md)
        self.assertIn("**SUBSET run", md)
        self.assertIn("NOT COMPARABLE with the leaderboard (`results/", md)

    def test_exec_only_cell_without_passes_is_not_measured(self):
        """`--metrics exec` leaves KillComplete and Mutation R empty even
        when nothing passed (every row is `not_run`, not `not_passed`)."""
        cell = self.run / "e-petitions" / "th"
        write_jsonl(cell / "exec.jsonl", [
            {"item_id": "e-petitions/a.feature:3", "outcome": "failed"}])
        (cell / "behaviour.json").write_text(json.dumps({
            "e-petitions/a.feature:3": {"api_f1": None, "coverage_j": None}}))
        summary = report.build(self.run, kit_for=self.kit_for)
        rows = [json.loads(line) for line in
                (cell / "instances.jsonl").read_text().splitlines()]
        self.assertEqual(rows[0]["mutation_status"], S.NOT_RUN)
        for mode in ("exact", "leaderboard"):
            values = summary["modes"][mode]["cells"]["e-petitions/th"]
            self.assertEqual(values["pass_at_1"], 0.0)
            self.assertIsNone(values["kill_complete_at_1"], mode)
            self.assertIsNone(values["mutation_recall"], mode)
        # Pass@1, KillComplete@1, API F1, Coverage J, Mutation R.
        line = [line for line in report.markdown(summary).splitlines()
                if line.startswith("| e-petitions | TH |")][0]
        self.assertEqual(line, "| e-petitions | TH | 1 | 0.0 | – | 0.0 | 0.0 "
                               "| – |")

    def test_header_cites_no_internal_plan(self):
        md = report.markdown(report.build(self.run, kit_for=self.kit_for))
        header = md.split("## Mode")[0]
        self.assertNotIn("harness plan", header)
        self.assertIn("`docs/metrics.md`", header)

    def test_empty_run(self):
        empty = Path(self.tmp.name) / "runs" / "empty"
        empty.mkdir(parents=True)
        with self.assertRaises(FileNotFoundError):
            report.build(empty, kit_for=self.kit_for)


if __name__ == "__main__":
    unittest.main()


class PopulationTest(ReportTest):
    """A run whose `benchmark.json` says 1.1, with a synthetic 1.1 list."""

    LISTED = "python-docx/g.feature:2"

    def build(self, version):
        """`report.build` on the run, as `evaluate` left it for `version`."""
        marker = self.run / report.BENCHMARK_FILE
        if version is None:
            marker.unlink(missing_ok=True)
        else:
            marker.write_text(json.dumps({"benchmark_version": version}))
        return report.build(self.run, kit_for=self.kit_for)

    def write_list(self, excluded):
        path = Path(self.tmp.name) / "benchmark_2.0_population.yml"
        path.write_text(
            "schema: r2t.benchmark-population/1\n"
            "benchmark_version: \"2.0\"\n"
            "census: synthetic census\n"
            "protocols: [9001]\n"
            "excluded:\n" + "".join(
                f"  - instance_id: {iid}\n    reason: census_pass\n"
                for iid in excluded))
        return mock.patch.object(P, "BENCHMARK_POPULATION", str(path))

    def test_1_1_leaves_listed_instances_out_of_every_measure(self):
        with self.write_list([self.LISTED, "sylius/x.feature:1"]):
            summary = self.build("1.1")
        report.write(self.run, summary)
        # the row is still scored and kept
        rows = (self.run / "python-docx" / "th" / "instances.jsonl") \
            .read_text().splitlines()
        self.assertEqual(len(rows), 2)
        for mode in report.A.MODES:
            cell = summary["modes"][mode]["cells"]["python-docx/th"]
            self.assertEqual((cell["n"], cell["pass_at_1"]), (1, 1.0), mode)
            self.assertEqual(cell["census_n"], 236)      # 237 minus 1 listed
            self.assertEqual(cell["population_excluded"], [self.LISTED])
            epe = summary["modes"][mode]["cells"]["e-petitions/th"]
            self.assertEqual((epe["census_n"], epe["population_excluded"]),
                             (98, []))
        self.assertEqual(summary["population"]["excluded"],
                         {self.LISTED: "census_pass"})
        self.assertEqual((summary["population"]["benchmark_version"],
                          summary["population"]["excluded_n"]), ("1.1", 1))
        md = (self.run / "report.md").read_text()
        self.assertIn("**Benchmark 1.1 population.** 1 instance(s) of this "
                      "run are outside it (census_pass)", md)
        self.assertIn("- python-docx/th: 1 instance(s) outside the benchmark "
                      "1.1 population (scored, counted in no measure)", md)

    def test_a_run_without_a_version_reads_as_1_1(self):
        """A run merged from several hosts has no benchmark.json."""
        with self.write_list([self.LISTED]):
            stated = self.build("1.1")
            merged = self.build(None)
        self.assertEqual(merged["benchmark_version"], "1.1")
        self.assertEqual(merged["population"]["excluded"],
                         {self.LISTED: "census_pass"})
        self.assertEqual(merged, stated)

    def test_1_1_needs_the_list_and_a_known_version(self):
        with mock.patch.object(P, "BENCHMARK_POPULATION",
                               str(Path(self.tmp.name) / "absent.yml")):
            with self.assertRaisesRegex(FileNotFoundError,
                                        "not in this checkout"):
                self.build("1.1")
        with self.assertRaisesRegex(ValueError, "benchmark version"):
            self.build("3.0")


class NondeterministicDisclosureTest(unittest.TestCase):
    def test_report_prints_the_excluded_mutants(self):
        """Harness 25 (D): the report says which listed mutants left G_i."""
        listed = "96e02276fdb04ae5"
        with tempfile.TemporaryDirectory() as tmp:
            kit = write_kit(Path(tmp) / "kits", "coreshop", [
                ("coreshop/a.feature:1", "m0", "killed"),
                ("coreshop/a.feature:1", listed, "killed")], rules=SINGLE)
            run = Path(tmp) / "runs" / "r1"
            write_jsonl(run / "coreshop" / "th" / "exec.jsonl", [
                {"item_id": "coreshop/a.feature:1", "outcome": "failed"}])
            summary = report.build(run, kit_for=lambda project: kit)
            self.assertEqual(
                summary["rules"]["coreshop"]["nondeterministic_excluded"],
                [listed])
            self.assertIn(f"nondeterministic mutants excluded from G_i: "
                          f"{listed}", report.markdown(summary))
