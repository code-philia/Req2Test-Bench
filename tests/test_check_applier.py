"""`scripts/check_applier.py` (V-applier): G selection, the byte splice, the splice route.

The script-applier route needs Docker and a kit image; it is exercised by the
reports in engine/applier_check/. These tests cover what runs without them.
"""
from __future__ import annotations

import importlib.util
import io
import json
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_applier", ROOT / "scripts" / "check_applier.py")
CA = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CA)

SOURCE = b"class A {\n  int f(int x) {\n    return x + 1;\n  }\n}\n"


def mutant(mid, line, col, original, mutated, end_col=None):
    return {"id": mid, "file": "src/A.java", "operator": "ArithmeticOperator",
            "start_line": line, "start_col": col, "end_line": line,
            "end_col": end_col if end_col is not None else col + len(original) - 1,
            "original": original, "mutated": mutated}


def write_kit(root: Path, project: str, engine: str, mutants, pools, excluded, files):
    (root / "mutation").mkdir(parents=True)
    (root / "exec" / "seed").mkdir(parents=True)
    (root / "kit.json").write_text(json.dumps({
        "project": project, "kit_version": "test",
        "exec_env": {"seed": {"dir": "exec/seed"}}}))
    manifest = json.dumps({"engine": engine, "digest": "d", "operators": [], "mutants": mutants}).encode()
    pool_lines = "".join(json.dumps(row) + "\n" for row in pools).encode()
    for name, raw in (("manifest.json.zst", manifest), ("pools.jsonl.zst", pool_lines)):
        (root / "mutation" / name).write_bytes(
            subprocess.run(["zstd", "-q", "-c"], input=raw, capture_output=True, check=True).stdout)
    (root / "mutation" / "reference_excluded.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in excluded))
    with tarfile.open(root / "exec" / "seed" / "workspace.tar", "w") as archive:
        for name, raw in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))


@unittest.skipIf(shutil.which("zstd") is None, "needs the zstd command")
class SpliceRouteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="check-applier-"))
        self.addCleanup(shutil.rmtree, self.tmp)

    def run_kit(self, project, engine, mutants, pools, excluded, files):
        kit = self.tmp / "kit"
        write_kit(kit, project, engine, mutants, pools, excluded, files)
        out = self.tmp / "report.json"
        rc = CA.main(["run", "--project", project, "--kit", str(kit), "--out", str(out),
                      "--work", str(self.tmp / "work")])
        return rc, json.loads(out.read_text())

    def test_g_is_killed_minus_excluded_and_every_mutant_splices(self):
        mutants = [mutant("m1", 3, 14, "+", "-"), mutant("m2", 3, 16, "1", "0"),
                   mutant("m3", 3, 12, "x", "y"), mutant("m4", 2, 3, "int", "long")]
        pools = [{"item_id": "i1", "mutant_id": "m1", "gold_outcome": "killed"},
                 {"item_id": "i2", "mutant_id": "m1", "gold_outcome": "killed"},
                 {"item_id": "i1", "mutant_id": "m2", "gold_outcome": "killed"},
                 {"item_id": "i1", "mutant_id": "m3", "gold_outcome": "survived"},
                 {"item_id": "i2", "mutant_id": "m4", "gold_outcome": "killed"}]
        excluded = [{"item_id": "i2", "mutant_id": "m4", "role": "full_gold", "outcome": "timeout"}]
        rc, report = self.run_kit("kapua", "r2t-mutate-java", mutants, pools, excluded,
                                  {"src/A.java": SOURCE})
        self.assertEqual(rc, 0)
        self.assertEqual(report["verdict"], "equal")
        self.assertEqual(report["kit"]["gt_killed_pairs"], 4)
        self.assertEqual(report["summary"], {"g_mutants": 2, "splices_on_seed": 2, "splice_refused": 0})
        self.assertTrue(report["appliers"]["same_source"])
        # No applier runs on the splice route, and the rows say so.
        self.assertIs(report["appliers_run"], False)
        self.assertEqual(report["exceptions"], [])

    def test_splice_rows_hold_no_applier_measurement(self):
        mutants = [mutant("m1", 3, 14, "+", "-")]
        pools = [{"item_id": "i1", "mutant_id": "m1", "gold_outcome": "killed"}]
        kit = self.tmp / "kit"
        write_kit(kit, "kapua", "r2t-mutate-java", mutants, pools, [], {"src/A.java": SOURCE})
        rows = self.tmp / "rows.jsonl"
        CA.main(["run", "--project", "kapua", "--kit", str(kit), "--out", str(self.tmp / "r.json"),
                 "--rows", str(rows), "--work", str(self.tmp / "work")])
        [row] = [json.loads(line) for line in rows.read_text().splitlines()]
        self.assertEqual((row["paper"], row["master"]), ({"rc": None, "sha256": None},) * 2)
        self.assertEqual(row["splice_sha256"], CA.sha256_bytes(SOURCE.replace(b"x + 1", b"x - 1")))

    def test_a_splice_source_difference_needs_a_reviewed_diff(self):
        mutants = [mutant("m1", 3, 14, "+", "-")]
        pools = [{"item_id": "i1", "mutant_id": "m1", "gold_outcome": "killed"}]
        files = {"src/A.java": SOURCE}
        rc, report = self.run_kit("algorand-sdk", "r2t-mutate-java", mutants, pools, [], files)
        self.assertEqual((rc, report["verdict"]), (0, "equal"))
        self.assertFalse(report["appliers"]["same_source"])
        self.assertIn("compiler_argv []", report["appliers"]["reviewed_diff"])
        shutil.rmtree(self.tmp / "kit")
        row = dict(CA.PAPER["algorand-sdk"])
        del row["reviewed_diff"]
        original = CA.PAPER["algorand-sdk"]
        CA.PAPER["algorand-sdk"] = row
        self.addCleanup(CA.PAPER.__setitem__, "algorand-sdk", original)
        rc, report = self.run_kit("algorand-sdk", "r2t-mutate-java", mutants, pools, [], files)
        self.assertEqual((rc, report["verdict"]), (1, "unreviewed_diff"))

    def test_a_recipe_the_seed_does_not_hold_is_reported(self):
        mutants = [mutant("m1", 3, 14, "-", "+")]  # the seed has `+` there
        pools = [{"item_id": "i1", "mutant_id": "m1", "gold_outcome": "killed"}]
        rc, report = self.run_kit("kapua", "r2t-mutate-java", mutants, pools, [],
                                  {"src/A.java": SOURCE})
        self.assertEqual(rc, 1)
        self.assertEqual(report["verdict"], "differs")
        self.assertEqual(report["summary"]["splice_refused"], 1)
        self.assertEqual([r["mutant_id"] for r in report["exceptions"]], ["m1"])

    def test_go_checks_the_applier_the_seed_installs(self):
        go = b'package main\nconst ENGINE = "r2t-mutate-go"\n'
        mutants = [dict(mutant("m1", 3, 14, "+", "-"), file="internal/a.go")]
        pools = [{"item_id": "i1", "mutant_id": "m1", "gold_outcome": "killed"}]
        rc, report = self.run_kit("coddy-agent", "r2t-mutate-go", mutants, pools, [],
                                  {"internal/a.go": SOURCE, "_bench/go/support/mutate.go": go})
        self.assertEqual(rc, 1)  # not the paper's applier bytes
        self.assertEqual(report["verdict"], "differs")
        self.assertEqual(report["summary"]["splices_on_seed"], 1)
        self.assertFalse(report["appliers"]["same_source"])
        self.assertEqual(report["environment"]["seed_applier"]["identity_constants"]["ENGINE"],
                         "r2t-mutate-go")


class SpliceTest(unittest.TestCase):
    def test_script_and_inclusive_end_splices(self):
        m = mutant("m", 3, 14, "+", "-")
        expected = SOURCE.replace(b"x + 1", b"x - 1")
        self.assertEqual(CA.descriptor_splice(SOURCE, m, inclusive_end=False), expected)
        self.assertEqual(CA.descriptor_splice(SOURCE, m, inclusive_end=True), expected)
        # An end that does not close the original span refuses the splice.
        self.assertIsNone(CA.descriptor_splice(SOURCE, dict(m, end_col=15), inclusive_end=True))
        self.assertIsNone(CA.descriptor_splice(SOURCE, dict(m, original="*"), inclusive_end=False))
        self.assertIsNone(CA.descriptor_splice(SOURCE, dict(m, start_line=9), inclusive_end=False))
        # Deletion (an empty replacement) is a splice too.
        self.assertEqual(CA.descriptor_splice(SOURCE, mutant("m", 3, 12, "x + 1", "x", end_col=16),
                                              inclusive_end=True), SOURCE.replace(b"x + 1", b"x"))

    def test_paper_table_names_known_engines_and_full_commits(self):
        for project, row in CA.PAPER.items():
            self.assertIn(row["engine"], CA.ENGINES, project)
            self.assertRegex(row["applier_sha256"], "^[0-9a-f]{64}$")
            for _tag, commit, _role in row["refs"]:
                self.assertRegex(commit, "^[0-9a-f]{40}$")

    def test_operator_profile_follows_the_manifest(self):
        self.assertEqual(CA.operator_profile("r2t-mutate", {"operators": list(CA.OPERATORS_V1)}), "v1")
        self.assertEqual(CA.operator_profile("r2t-mutate", {"operators": [*CA.OPERATORS_V1, "LogicalConnector"]}),
                         "v2")
        self.assertEqual(CA.operator_profile("r2t-mutate-rb", {"operators": list(CA.OPERATORS_V1)}), "v2")


if __name__ == "__main__":
    unittest.main()
