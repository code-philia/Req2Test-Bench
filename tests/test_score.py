"""`req2test.score`: the rule table, KillComplete, and two engine oracles.

The oracles are the engine's own scorers: `r2t.data.mutation.recall`
(native family) and `r2t.bench.test_quality.score_single_observation`
(single-observation family).  Both run here on the same synthetic rows as
`score_instance`, and every per-instance recall and KillComplete must agree.
"""
from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from req2test import score as S
from kitfixture import CODDY, NATIVE, SINGLE, write_kit

from r2t.data import mutation as M  # on sys.path once req2test.score loads


def rows_for(iid, outcomes):
    return [{"instance_id": iid, "mutant_id": mid, "outcome": out}
            for mid, out in outcomes.items()]


class RulesTest(unittest.TestCase):
    def test_families(self):
        self.assertEqual(S.Rules.from_json(NATIVE).family, "native")
        self.assertEqual(S.Rules.from_json(SINGLE).family, "single_observation")
        with self.assertRaises(ValueError):
            S.Rules("sometimes")

    def test_classify(self):
        native, single = S.Rules.from_json(NATIVE), S.Rules.from_json(SINGLE)
        coddy = S.Rules.from_json(CODDY)
        cases = [("failed", S.KILL, S.KILL), ("passed", S.SURVIVED, S.SURVIVED),
                 ("timeout", S.KILL, S.DROPPED),
                 ("no_scenario_ran", S.DROPPED, S.DROPPED),
                 ("passed_but_nonzero_exit", S.DROPPED, S.DROPPED),
                 ("unscorable_substrate", S.DROPPED, S.DROPPED),
                 ("fixture_consumed", S.DROPPED, S.DROPPED)]
        for outcome, want_native, want_single in cases:
            row = {"outcome": outcome}
            self.assertEqual(S.classify(row, native), want_native, outcome)
            self.assertEqual(S.classify(row, single), want_single, outcome)
        crash = {"outcome": "failed", "crash": "go_panic"}
        self.assertEqual(S.classify(crash, coddy), S.KILL)
        self.assertEqual(S.classify(crash, single), S.DROPPED)
        with self.assertRaises(ValueError):
            S.classify({"outcome": "mystery"}, single)

    def test_instance_outcome(self):
        self.assertEqual(S.instance_outcome({"outcome": "pass"}), "pass")
        self.assertEqual(S.instance_outcome({"outcome": "passed"}), "pass")
        self.assertEqual(S.instance_outcome({"outcome": "failed"}),
                         "assertion_failure")
        self.assertEqual(S.instance_outcome({"outcome": "undefined_steps"}),
                         "binding_failure")
        self.assertEqual(S.instance_outcome({"outcome": "container_error"}),
                         "compilation_failure")
        self.assertEqual(S.instance_outcome({"outcome": "no_files_returned"}),
                         "generation_failure")
        # predictions: nothing usable written is a generation failure
        self.assertEqual(S.instance_outcome({"outcome": "no_writable_files"}),
                         "generation_failure")
        self.assertEqual(S.instance_outcome({"outcome": "harness_error"}),
                         S.EXCLUDED)
        # outside the ladder: excluded, as the paper's exception rule did
        self.assertEqual(S.instance_outcome(
            {"outcome": "passed_but_nonzero_exit"}), S.EXCLUDED)


class ScoreInstanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        pools = [("p/a.feature:1", f"m{k}", "killed") for k in range(4)]
        pools += [("p/a.feature:1", "s0", "survived"),
                  ("p/a.feature:1", "x0", "killed"),      # reference-excluded
                  ("p/b.feature:2", "m0", "killed"),
                  ("p/c.feature:3", "s0", "survived")]
        self.single = write_kit(Path(self.tmp.name) / "single", "p", pools,
                                excluded=[("p/a.feature:1", "x0")],
                                rules=SINGLE)
        self.native = write_kit(Path(self.tmp.name) / "native", "p", pools,
                                excluded=[("p/a.feature:1", "x0")],
                                rules=NATIVE)

    def tearDown(self):
        self.tmp.cleanup()

    def score(self, kit, outcomes, iid="p/a.feature:1", passed=True):
        exec_row = {"instance_id": iid,
                    "outcome": "pass" if passed else "assertion_failure"}
        rows = None if outcomes is None else rows_for(iid, outcomes)
        return S.score_instance(kit, exec_row, rows)

    def test_gold_set(self):
        ref = S.reference(self.single)
        self.assertEqual(ref.gold_set("p/a.feature:1"),
                         {"m0", "m1", "m2", "m3"})
        self.assertEqual(ref.gold_set("p/c.feature:3"), frozenset())
        self.assertEqual((ref.n_pool_pairs, ref.n_reference_excluded), (8, 1))

    def test_nondeterministic_mutants_leave_g(self):
        """Harness 25 (D): a kill set holding a listed mutant is scored
        without it; a pass that kills the rest is kill-complete."""
        listed = "96e02276fdb04ae5"
        self.assertIn(listed, S.nondeterministic_mutants())
        pools = [("p/a.feature:1", f"m{k}", "killed") for k in range(2)]
        pools.append(("p/a.feature:1", listed, "killed"))
        kit = write_kit(Path(self.tmp.name) / "listed", "p", pools,
                        rules=SINGLE)
        self.assertEqual(S.reference(kit).gold_set("p/a.feature:1"),
                         {"m0", "m1"})
        self.assertEqual(S.reference(kit).nondeterministic, (listed,))
        self.assertEqual(S.reference(self.single).nondeterministic, ())
        for outcome in ("passed", "failed"):
            result = self.score(kit, {"m0": "failed", "m1": "failed",
                                      listed: outcome})
            self.assertTrue(result["kill_complete"], outcome)
            self.assertEqual((result["n_gt_kills"], result["n_scored"],
                              result["n_killed"]), (2, 2, 2))

    def test_kill_complete(self):
        r = self.score(self.single, {f"m{k}": "failed" for k in range(4)})
        self.assertEqual((r["recall"], r["kill_complete"],
                          r["kill_complete_strict"], r["n_scored"]),
                         (1.0, True, True, 4))
        self.assertEqual(r["mutation_status"], S.SCORED)

    def test_partial_and_companions(self):
        r = self.score(self.single, {"m0": "failed", "m1": "failed",
                                     "m2": "failed", "m3": "passed"})
        self.assertEqual((r["recall"], r["kill_complete"],
                          r["kill_complete_95"]), (0.75, False, False))

    def test_timeout_by_family(self):
        outcomes = {"m0": "failed", "m1": "failed", "m2": "failed",
                    "m3": "timeout"}
        single = self.score(self.single, outcomes)
        self.assertEqual((single["n_scored"], single["n_dropped"],
                          single["kill_complete"],
                          single["kill_complete_strict"]), (3, 1, True, False))
        self.assertEqual(single["dropped_outcomes"], {"timeout": 1})
        native = self.score(self.native, outcomes)
        self.assertEqual((native["n_scored"], native["n_timeout_kills"],
                          native["kill_complete_strict"]), (4, 1, True))

    def test_rows_outside_g_are_ignored(self):
        outcomes = {f"m{k}": "failed" for k in range(4)}
        outcomes.update({"s0": "no_scenario_ran", "x0": "passed"})
        r = self.score(self.single, outcomes)
        self.assertEqual((r["kill_complete"], r["n_dropped"]), (True, 0))

    def test_partial_run_refused(self):
        # some but not all G_i rows: an incomplete run, never kill-complete
        with self.assertRaisesRegex(ValueError, "incomplete mutation run"):
            self.score(self.single, {"m0": "failed", "m1": "failed"})
        with self.assertRaisesRegex(ValueError, "incomplete mutation run"):
            self.score(self.native, {"m0": "failed", "s0": "failed"})

    def test_statuses(self):
        self.assertEqual(self.score(self.single, {}, passed=False)
                         ["mutation_status"], S.NOT_PASSED)
        unscored = self.score(self.single, {})
        self.assertEqual((unscored["mutation_status"], unscored["recall"],
                          unscored["kill_complete"]), (S.UNSCORED, None, False))
        dropped = self.score(self.single, {f"m{k}": "container_error"
                                           for k in range(4)})
        self.assertEqual((dropped["mutation_status"], dropped["kill_complete"]),
                         (S.NOT_SCORABLE, False))
        empty_g = self.score(self.single, {}, iid="p/c.feature:3")
        self.assertEqual(empty_g["mutation_status"], S.NOT_SCORABLE)
        not_run = self.score(self.single, None)
        self.assertEqual((not_run["mutation_status"], not_run["kill_complete"]),
                         (S.NOT_RUN, False))
        # Without mutation rows (`--metrics exec`) a non-pass is not_run too.
        self.assertEqual(self.score(self.single, None, passed=False)
                         ["mutation_status"], S.NOT_RUN)
        excluded = S.score_instance(self.single, {
            "instance_id": "p/a.feature:1", "outcome": "harness_error"}, [])
        self.assertEqual((excluded["excluded"], excluded["exclusion"],
                          excluded["engine_outcome"]),
                         (True, S.INFRASTRUCTURE, "harness_error"))
        odd = S.score_instance(self.single, {
            "instance_id": "p/a.feature:1",
            "outcome": "passed_but_nonzero_exit"}, [])
        self.assertEqual((odd["outcome"], odd["exclusion"],
                          odd["engine_outcome"]),
                         (S.EXCLUDED, S.OUTSIDE_LADDER,
                          "passed_but_nonzero_exit"))

    def test_duplicate_rows_refused(self):
        rows = rows_for("p/a.feature:1", {"m0": "failed"}) * 2
        with self.assertRaises(ValueError):
            S.score_instance(self.single, {"instance_id": "p/a.feature:1",
                                           "outcome": "pass"}, rows)

    def test_crash_kill(self):
        kit = write_kit(Path(self.tmp.name) / "coddy", "p",
                        [("p/a.feature:1", "m0", "killed")], rules=CODDY)
        r = S.score_instance(kit, {"instance_id": "p/a.feature:1",
                                   "outcome": "pass"},
                             [{"item_id": "p/a.feature:1", "mutant_id": "m0",
                               "outcome": "failed", "crash": "go_fatal_error"}])
        self.assertEqual((r["kill_complete"], r["n_crash_kills"]), (True, 1))

    def test_zstd_pools(self):
        try:
            import zstandard
        except ImportError:
            self.skipTest("zstandard not installed")
        pools = self.single / "mutation" / "pools.jsonl"
        (self.single / "mutation" / "pools.jsonl.zst").write_bytes(
            zstandard.ZstdCompressor().compress(pools.read_bytes()))
        pools.unlink()
        ref = S.Reference.from_kit(self.single)
        self.assertEqual(ref.gold_set("p/a.feature:1"),
                         {"m0", "m1", "m2", "m3"})


# ------------------------------------------------------------ oracles
OUTCOMES = ("failed", "failed", "failed", "passed", "timeout",
            "no_scenario_ran", "container_error", "passed_but_nonzero_exit")


def synthetic(seed, n_items=60, n_mutants=12):
    """Pools, GT kill sets and one candidate observation per pool pair."""
    rng = random.Random(seed)
    pools, gold, cand = [], {}, []
    for i in range(n_items):
        iid = f"p/f{i % 17}.feature:{i}"
        all_kill = rng.random() < 0.3
        for k in range(rng.randint(0, n_mutants)):
            mid = f"m{k:02d}"
            killed = rng.random() < 0.6
            pools.append((iid, mid, "killed" if killed else "survived"))
            if killed:
                gold.setdefault(iid, set()).add(mid)
            out = "failed" if all_kill else rng.choice(OUTCOMES)
            cand.append({"item_id": iid, "mutant_id": mid, "outcome": out})
    return pools, gold, cand


class NativeOracleTest(unittest.TestCase):
    """Native family == `r2t.data.mutation.recall` (passing baselines)."""

    def test_against_engine_recall(self):
        with tempfile.TemporaryDirectory() as tmp:
            for seed in range(5):
                pools, gold, cand = synthetic(seed)
                kit = write_kit(Path(tmp) / f"k{seed}", "p", pools,
                                rules=NATIVE)
                items = sorted({p[0] for p in pools})
                # candidate executes G_i only (the gold-killed scope)
                g_rows = [r for r in cand
                          if r["mutant_id"] in gold.get(r["item_id"], ())]
                engine = M.recall({iid: "passed" for iid in items}, g_rows,
                                  gold)
                mine = S.score_instances(
                    kit, [{"instance_id": iid, "outcome": "pass"}
                          for iid in items], g_rows)
                for r in mine:
                    e = engine["per_item"].get(r["instance_id"])
                    if e is None or e["recall"] is None:
                        self.assertIsNone(r["recall"], r["instance_id"])
                        self.assertFalse(r["kill_complete"])
                        continue
                    self.assertEqual(round(r["recall"], 6), e["recall"])
                    self.assertEqual((r["n_killed"], r["n_scored"]),
                                     (e["killed"], e["denominator"]))
                    self.assertEqual(r["kill_complete"], e["recall"] == 1.0)


class SingleObservationOracleTest(unittest.TestCase):
    """Single-observation family == `test_quality.score_single_observation`,
    both for the gold-killed scope (full-gold basis) and the paper's
    all-pairs scope (hard-subset basis)."""

    def authority(self, expected, gold, full_gold):
        from r2t.bench import reference_controls as RC
        from r2t.bench import test_quality as TQ
        items = sorted({iid for iid, _ in expected})
        sets = RC.ReferenceSets(
            expected_pairs=frozenset(expected), excluded_count=0,
            full_gold_kills={iid: frozenset(gold.get(iid, ())) for iid in items},
            hard_subset={iid: frozenset(sorted(gold.get(iid, ()))[:1])
                         for iid in items},
            stub_recall_by_item={iid: 0.0 for iid in items},
            stub_macro_recall=0.0, stub_threshold=0.5, eligible=True,
            seal=RC._SETS_SEAL,
            **({"reference_basis": "full_gold"} if full_gold else {}))
        # The engine's own test fixture builds the scoring authority the
        # same way (bench/results.py, `_single_observation_fixture`).
        return TQ._SingleObservationScoringAuthority(
            {"digest": "a" * 64}, sets, TQ._SINGLE_OBSERVATION_AUTHORITY_SEAL)

    def test_against_engine(self):
        from r2t.bench import test_quality as TQ
        with tempfile.TemporaryDirectory() as tmp:
            for seed in range(5):
                pools, gold, cand = synthetic(100 + seed)
                kit = write_kit(Path(tmp) / f"k{seed}", "p", pools,
                                rules=SINGLE)
                items = sorted({p[0] for p in pools})
                rng = random.Random(seed)
                passed = [iid for iid in items if rng.random() < 0.8]
                for full_gold in (True, False):
                    if full_gold:
                        expected = {(r["item_id"], r["mutant_id"]) for r in cand
                                    if r["mutant_id"] in gold.get(r["item_id"], ())}
                    else:
                        expected = {(r["item_id"], r["mutant_id"]) for r in cand}
                    rows = [r for r in cand
                            if (r["item_id"], r["mutant_id"]) in expected
                            and r["item_id"] in passed]
                    if not passed:
                        continue
                    engine = TQ.score_single_observation(
                        {iid: True for iid in passed}, rows,
                        authority=self.authority(expected, gold, full_gold))
                    mine = {r["instance_id"]: r for r in S.score_instances(
                        kit, [{"instance_id": iid, "outcome": "pass"}
                              for iid in items], rows)}
                    for iid in passed:
                        e, r = engine["per_item"][iid], mine[iid]
                        self.assertEqual(r["recall"], e["full_recall"], iid)
                        self.assertEqual(r["n_scored"], e["full_denominator"])
                        self.assertEqual(r["n_killed"],
                                         e["full_candidate_killed"])
                        self.assertEqual(
                            r["kill_complete"],
                            e["full_recall"] is not None
                            and e["full_recall"] >= 1.0)
                        if full_gold:
                            self.assertEqual(r["n_dropped"],
                                             e["candidate_excluded"])
                            self.assertEqual(
                                r["kill_complete"],
                                e["verdict"] == TQ.EQUIVALENT)


if __name__ == "__main__":
    unittest.main()
