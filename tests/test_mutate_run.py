"""`mutate.run` end to end on a fake engine (no Docker): the completion
marker, resume, baseline retries and the recorded campaign identity."""
import json
import threading
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from kitfixture import write_kit
from req2test import mutate as M
from req2test import report
from req2test.layout import Kit

A, B, C = ("python-docx/a.feature:1", "python-docx/b.feature:2",
           "python-docx/c.feature:3")


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


class FakeEngine:
    """Records what the bridge asks of the engine and answers from scripts.

    `baseline[iid]` is the list of outcomes successive baselines of `iid`
    return (the last repeats); `pair_outcome(iid, mid)` is a pair's outcome;
    `stop_after` raises KeyboardInterrupt in `run_slice` after that many rows.
    `sweeps` lists the Behat outcomes of successive sweeps (then
    `undefined_steps`, an empty solution's usual result); `events` is every
    sweep and pair in execution order, `slices` the mutants of each slice.
    `clears` holds, for each `clear_registration` on the harness, how many
    events preceded it; `cancel_after_slices` sets the slice's cancel event
    once that many slices have run.
    """

    def __init__(self):
        self.baseline = {}
        self.baseline_calls = []
        self.pairs_run = []
        self.stop_after = None
        self.pair_outcome = lambda iid, mid: "failed"
        self.sweeps = []
        self.events = []
        self.slices = []
        self.clears = []
        self.cancel_after_slices = None

    def clear_registration(self):
        self.clears.append(len(self.events))

    def run_one(self, harness, adapter, item, coverage=False, timeout=600):
        iid = item["item_id"]
        if adapter.name == "mutation-sweep":
            assert adapter({})["files"] == []
            self.events.append(("sweep", iid))
            outcome = self.sweeps.pop(0) if self.sweeps else "undefined_steps"
            if outcome == "harness_error":
                return {"item_id": iid, "outcome": outcome,
                        "metadata": {"harness_error": "OSError: gone"}}
            return {"item_id": iid, "outcome": "no_files_returned",
                    "outcomes_all_runs": [outcome]}
        self.baseline_calls.append(iid)
        script = self.baseline.get(iid, ["passed"])
        n = sum(1 for c in self.baseline_calls if c == iid)
        outcome = script[min(n, len(script)) - 1]
        rec = {"item_id": iid, "outcome": outcome}
        if outcome == "harness_error":
            rec["metadata"] = {"harness_error": "OSError: docker went away"}
        return rec

    def run_slice(self, harness, mutants, items_by_id, files_by_item,
                  by_mutant, engine_dir, out_path, *, on_row, **kw):
        self.slices.append([m["id"] for m in mutants])
        # The slice is bound to exactly its own pairs.
        assert set(by_mutant) == {m["id"] for m in mutants}
        own = {(iid, m["id"]) for m in mutants for iid in by_mutant[m["id"]]}
        assert kw["planned_pairs"] == own
        assert kw["identity"]["expected_pairs"] == own
        for mutant in mutants:
            for iid in by_mutant[mutant["id"]]:
                if self.stop_after is not None \
                        and len(self.pairs_run) >= self.stop_after:
                    raise KeyboardInterrupt
                self.pairs_run.append((iid, mutant["id"]))
                self.events.append(("pair", iid, mutant["id"]))
                on_row({"item_id": iid, "mutant_id": mutant["id"],
                        "outcome": self.pair_outcome(iid, mutant["id"])})
        if self.cancel_after_slices is not None \
                and len(self.slices) >= self.cancel_after_slices:
            kw["cancel_event"].set()
        return {"rows": len(self.pairs_run), "outcomes": {}, "seconds": 0}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    from r2t.bench import mutation_run as MR
    from r2t.bench import repo as R
    from r2t.bench import runner as RN
    from r2t.bench import worker as W
    pools = [(A, "m1", "killed"), (A, "m2", "killed"), (A, "m3", "survived"),
             (B, "m1", "killed"), (C, "m2", "killed")]
    root = write_kit(tmp_path / "kits", "python-docx", pools)
    meta = json.loads((root / "kit.json").read_text())
    meta["mutation"] = {"files": {
        "pools": "mutation/pools.jsonl",
        "reference_excluded": "mutation/reference_excluded.jsonl",
        "manifest": "mutation/manifest.json"}}
    (root / "kit.json").write_text(json.dumps(meta))
    (root / "mutation" / "manifest.json").write_text(json.dumps({
        "engine": "r2t-mutate-py", "engine_version": "1", "parser": "p",
        "operators": [], "digest": "d",
        "mutants": [{"id": m, "file": "docx/x.py", "start_line": i}
                    for i, m in enumerate(("m1", "m2", "m3"))]}))
    kit = Kit("python-docx", "1.0", root, meta)
    items = tmp_path / "items.jsonl"
    write_jsonl(items, [{"item_id": i} for i in (A, B, C)])
    env = SimpleNamespace(release_items=str(items), seed_dir=tmp_path,
                          data_root=tmp_path / "engine")
    run_dir = tmp_path / "run"
    write_jsonl(run_dir / "exec.jsonl", [
        {"item_id": iid, "outcome": "passed",
         "produced_files": [{"file_path": "f.py", "code": "x"}]}
        for iid in (A, B, C)])

    fake = FakeEngine()
    harness = SimpleNamespace(root=str(tmp_path), man=None, boundary=None,
                              clear_registration=fake.clear_registration,
                              prepare_for_generation=lambda: None)

    class Workers:
        def __init__(self, env, k, gold=None):
            self.k = k

        def harness(self, index):
            return harness

    def sequential(k, work, log, processes=True):
        event = threading.Event()
        return [work(i, event) for i in range(k)]

    runtime = {"harness_version": 24, "worker_resources_sha256": "r",
               "container_image_digest": "sha256:image",
               "workspace_seed_digest": "seed", "database_dump_digest": None}
    patches = [
        (M, "bind_environment", lambda env: None),
        (M, "worker_spec_paths", lambda env: [Path("w0"), Path("w1")]),
        (M, "_Workers", Workers), (M, "_parallel", sequential),
        (W, "load_worker_spec", lambda p: SimpleNamespace()),
        (W, "validate_mutation_runtime", lambda *a, **k: dict(runtime)),
        (W, "resource_fields", lambda needs_db: ()),
        (MR, "runtime_applier_sha256", lambda engine, seed: "applier"),
        (MR, "binding_for", lambda engine: ("engine_dir", "applier")),
        (MR, "operator_profile_for", lambda ops: None),
        (MR, "candidate_digest", lambda files: "cand"),
        (MR, "build_campaign_identity", lambda **kw: kw),
        (MR, "substrate_baseline_digest", lambda h: "sub"),
        (MR, "run_slice", fake.run_slice),
        (RN, "run_one", fake.run_one),
        (RN, "_ExecutionLock", lambda root: nullcontext()),
        (R, "clean_workspace", lambda man, boundary: None),
    ]
    for module, name, value in patches:
        monkeypatch.setattr(module, name, value)
    return SimpleNamespace(kit=kit, env=env, run_dir=run_dir, fake=fake,
                           runtime=runtime)


def run(s):
    return M.run(s.kit, s.env, s.run_dir, log=lambda *a: None)


def report_rows(s, tmp_path=None):
    return report.cell_instances(s.kit, "python-docx", "th", s.run_dir)


def test_complete_run_writes_the_marker_and_identity(setup):
    run(setup)
    done = M.read_done(setup.run_dir)
    assert done["schema"] == M.DONE_SCHEMA and done["pairs"] == 4
    assert done["baselines"] == {A: "passed", B: "passed", C: "passed"}
    plan = json.loads((setup.run_dir / M.PLAN_FILE).read_text())
    (identity,) = plan["identities"]
    assert identity["container_image_digest"] == "sha256:image"
    assert identity["workspace_seed_digest"] == "seed"
    assert identity["applier_sha256"] == "applier"
    rows = {r["instance_id"]: r for r in report_rows(setup)}
    assert all(r["kill_complete"] for r in rows.values())
    assert rows[A]["mutation_baseline"] == "passed"

    # A rerun with nothing left keeps the identity and the marker.
    run(setup)
    plan = json.loads((setup.run_dir / M.PLAN_FILE).read_text())
    assert plan["identities"] == [identity]
    assert M.read_done(setup.run_dir) is not None


def test_worker_lines_count_killed_survived_and_dropped(setup):
    """The progress line classifies each pair as the scorer does; the
    engine's `failed` is a kill and is not printed as a failure."""
    import re
    outcomes = {(A, "m1"): "failed", (A, "m2"): "passed",
                (B, "m1"): "timeout", (C, "m2"): "failed"}
    setup.fake.pair_outcome = lambda iid, mid: outcomes[(iid, mid)]
    lines = []
    M.run(setup.kit, setup.env, setup.run_dir,
          log=lambda *a: lines.append(" ".join(map(str, a))))
    workers = [line for line in lines if line.startswith("mutate: worker")]
    assert workers and not any("failed" in line for line in workers)
    totals = [0, 0, 0]
    for line in workers:
        counts = re.search(r"killed=(\d+) survived=(\d+) dropped=(\d+),",
                           line)
        assert counts, line
        totals = [t + int(n) for t, n in zip(totals, counts.groups())]
    assert totals == [2, 1, 1]          # timeout drops (single observation)


def test_describe_verdicts():
    assert M.describe_verdicts({"kill": 3, "dropped": 1}) == \
        "killed=3 survived=0 dropped=1"
    assert M.describe_verdicts({"unknown": 2}) == \
        "killed=0 survived=0 dropped=0 unknown=2"


def test_interrupted_pairs_leave_no_marker_and_resume(setup):
    setup.fake.stop_after = 2
    with pytest.raises(KeyboardInterrupt):
        run(setup)
    assert (setup.run_dir / "mutation").is_dir()
    assert M.read_done(setup.run_dir) is None
    with pytest.raises(ValueError, match="did not finish"):
        report_rows(setup)

    setup.fake.stop_after = None
    first = list(setup.fake.pairs_run)
    run(setup)
    assert M.read_done(setup.run_dir)["pairs"] == 4
    # the resume ran only the pairs that had no row
    assert sorted(setup.fake.pairs_run[len(first):]) == sorted(
        {(A, "m1"), (A, "m2"), (B, "m1"), (C, "m2")} - set(first))
    assert all(r["kill_complete"] for r in report_rows(setup))


def test_ground_truth_predictions_mutate_as_gold_runs(setup, monkeypatch):
    """Harness 25: the mutation baselines and slices of `validate`'s
    ground-truth predictions are gold runs (the baseline adapter's
    `gold_run`, the slices' gold side); any other prediction's are a
    candidate's."""
    from r2t.bench import mutation_run as MR
    from r2t.bench import runner as RN
    configs, sides = [], []

    def run_one(harness, adapter, item, **kwargs):
        if adapter.name == "mutation-baseline":
            configs.append(dict(adapter.config))
        return setup.fake.run_one(harness, adapter, item, **kwargs)

    def run_slice(*args, **kwargs):
        sides.append(kwargs["identity"]["side"])
        return setup.fake.run_slice(*args, **kwargs)

    monkeypatch.setattr(RN, "run_one", run_one)
    monkeypatch.setattr(MR, "run_slice", run_slice)
    run(setup)
    assert configs and all(config == {} for config in configs)
    assert sides and set(sides) == {"candidate"}

    configs.clear()
    sides.clear()
    ground_truth = setup.run_dir.parent / "ground-truth"
    write_jsonl(ground_truth / "exec.jsonl", [
        {"item_id": iid, "outcome": "passed", "metadata": {"source": "gold"},
         "produced_files": [{"file_path": "f.py", "code": "x"}]}
        for iid in (A, B, C)])
    M.run(setup.kit, setup.env, ground_truth, log=lambda *a: None)
    assert configs and all(config == {"gold_run": True} for config in configs)
    assert sides and set(sides) == {"gold"}


def test_interrupted_baselines_leave_no_marker(setup, monkeypatch):
    run(setup)                                   # a finished stage ...
    assert M.read_done(setup.run_dir) is not None

    def stopped(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(M, "_run_baselines", stopped)
    (setup.run_dir / M.BASELINE_FILE).unlink()   # ... rerun from baselines
    with pytest.raises(KeyboardInterrupt):
        run(setup)
    assert M.read_done(setup.run_dir) is None
    with pytest.raises(ValueError, match="did not finish"):
        report_rows(setup)


def test_marker_from_other_exec_rows_is_refused(setup):
    run(setup)
    exec_path = setup.run_dir / "exec.jsonl"
    exec_path.write_text(exec_path.read_text().replace('"passed"',
                                                       '"failed"', 1))
    with pytest.raises(ValueError, match="other execution rows"):
        report_rows(setup)


def test_baseline_infrastructure_is_retried_on_resume(setup):
    # B: harness_error twice in the first run, then passes on resume.
    # C: fails its baseline (a verdict, never retried).
    setup.fake.baseline = {B: ["harness_error", "harness_error", "passed"],
                           C: ["failed"]}
    run(setup)
    rows = [json.loads(line) for line in
            (setup.run_dir / M.BASELINE_FILE).read_text().splitlines()]
    b_row = next(r for r in rows if r["instance_id"] == B)
    assert (b_row["class"], b_row["attempt"]) == ("infrastructure", 2)
    assert "docker went away" in b_row["harness_error"]
    done = M.read_done(setup.run_dir)
    assert done["baseline_infrastructure"] == [B]
    assert done["baseline_failed"] == [C]
    assert {p for p in setup.fake.pairs_run} == {(A, "m1"), (A, "m2")}
    scored = {r["instance_id"]: r for r in report_rows(setup)}
    assert scored[B]["mutation_status"] == "unscored"
    assert scored[B]["mutation_baseline"] == "infrastructure"
    assert scored[C]["mutation_baseline"] == "failed"
    disclosed = report.disclosures(list(scored.values()))["python-docx/th"]
    assert disclosed["baseline_infrastructure"] == [B]
    assert disclosed["baseline_failed"] == [C]

    calls = len(setup.fake.baseline_calls)
    run(setup)                                    # resume
    assert setup.fake.baseline_calls[calls:] == [B]   # C is not rerun
    done = M.read_done(setup.run_dir)
    assert done["baseline_infrastructure"] == [] and done["baselines"][B] \
        == "passed"
    assert (B, "m1") in setup.fake.pairs_run
    scored = {r["instance_id"]: r for r in report_rows(setup)}
    assert scored[B]["kill_complete"]


def test_baseline_classes():
    assert M.baseline_class("passed") == M.PASSED
    for outcome in ("harness_error", "container_error", "scenario_not_found",
                    "substrate_violation"):
        assert M.baseline_class(outcome) == M.INFRASTRUCTURE
    for outcome in ("failed", "timeout", "undefined_steps"):
        assert M.baseline_class(outcome) == M.FAILED


def test_host_shard_never_writes_the_marker(setup):
    M.run(setup.kit, setup.env, setup.run_dir, shard=(0, 1),
          log=lambda *a: None)
    assert M.read_done(setup.run_dir) is None
    run(setup)                     # an unsharded run over the same rows
    assert M.read_done(setup.run_dir)["pairs"] == 4


# ------------------------------------------------- sweep before each mutant
@pytest.fixture
def swept(setup, monkeypatch):
    """`setup` on one worker, with python-docx swept like CoreShop."""
    monkeypatch.setattr(M, "SWEEP_BEFORE_EACH_MUTANT",
                        frozenset({"python-docx"}))
    monkeypatch.setattr(M, "worker_spec_paths", lambda env: [Path("w0")])
    return setup


def test_only_coreshop_is_swept_by_default():
    assert M.SWEEP_BEFORE_EACH_MUTANT == {"coreshop"}


def test_sweep_runs_once_per_mutant_per_worker_in_order(swept):
    run(swept)
    # m1 (start line 0) then m2, each its own slice after a sweep of its
    # first item; baselines are unchanged.
    assert swept.fake.events == [
        ("sweep", A), ("pair", A, "m1"), ("pair", B, "m1"),
        ("sweep", A), ("pair", A, "m2"), ("pair", C, "m2")]
    assert swept.fake.slices == [["m1"], ["m2"]]
    assert sorted(swept.fake.baseline_calls) == [A, B, C]
    rows = M.read_sweeps(swept.run_dir)
    assert [(r["worker"], r["mutant_id"], r["instance_id"], r["class"],
             r["attempt"]) for r in rows] == [
        (0, "m1", A, "swept", 1), (0, "m2", A, "swept", 1)]
    summary = {"runs": 2, "mutants": 2, "classes": {"swept": 2},
               "outcomes": {"undefined_steps": 2}}
    assert M.read_done(swept.run_dir)["sweeps"] == summary
    assert "sweeps" not in json.loads(
        (swept.run_dir / M.PLAN_FILE).read_text())
    # The worker is settled once after its baselines (no events yet) and
    # right after each sweep, before the mutant's pairs.
    assert swept.fake.clears == [0, 1, 4]
    assert all(r["kill_complete"] for r in report_rows(swept))


def test_sweeps_on_two_workers(swept, monkeypatch):
    monkeypatch.setattr(M, "worker_spec_paths",
                        lambda env: [Path("w0"), Path("w1")])
    run(swept)
    rows = M.read_sweeps(swept.run_dir)
    assert sorted((r["worker"], r["mutant_id"]) for r in rows) == [
        (0, "m1"), (1, "m2")]
    assert M.read_done(swept.run_dir)["pairs"] == 4


def test_resume_sweeps_again_before_the_remaining_pairs(swept):
    swept.fake.stop_after = 1
    with pytest.raises(KeyboardInterrupt):
        run(swept)
    assert swept.fake.events == [("sweep", A), ("pair", A, "m1")]
    assert M.read_done(swept.run_dir) is None

    swept.fake.stop_after = None
    swept.fake.events.clear()
    run(swept)
    # m1 is swept again (with its first remaining item) before its last pair
    assert swept.fake.events == [
        ("sweep", B), ("pair", B, "m1"),
        ("sweep", A), ("pair", A, "m2"), ("pair", C, "m2")]
    assert [r["mutant_id"] for r in M.read_sweeps(swept.run_dir)] == [
        "m1", "m1", "m2"]
    done = M.read_done(swept.run_dir)
    assert done["pairs"] == 4 and done["sweeps"]["runs"] == 3


def test_projects_outside_the_set_get_no_sweep(setup, monkeypatch):
    monkeypatch.setattr(M, "worker_spec_paths", lambda env: [Path("w0")])
    run(setup)
    assert not [e for e in setup.fake.events if e[0] == "sweep"]
    assert setup.fake.slices == [["m1", "m2"]]     # one slice per worker
    assert not (setup.run_dir / M.SWEEP_FILE).exists()
    assert M.read_done(setup.run_dir)["sweeps"] is None
    assert "sweeps" not in json.loads(
        (setup.run_dir / M.PLAN_FILE).read_text())
    assert setup.fake.clears == [0]                # after the baselines


def test_a_failed_sweep_is_retried_once(swept):
    swept.fake.sweeps = ["no_scenario_ran"]
    run(swept)
    rows = M.read_sweeps(swept.run_dir)
    assert [(r["mutant_id"], r["outcome"], r["class"], r["attempt"])
            for r in rows] == [
        ("m1", "no_scenario_ran", "infrastructure", 1),
        ("m1", "undefined_steps", "swept", 2),
        ("m2", "undefined_steps", "swept", 1)]
    assert M.read_done(swept.run_dir)["sweeps"]["classes"] == {
        "infrastructure": 1, "swept": 2}
    # settled after the failed attempt too: the baselines, m1's two
    # attempts, then m2's sweep
    assert swept.fake.clears == [0, 1, 2, 5]


def test_a_sweep_failing_twice_refuses_the_slice(swept):
    swept.fake.sweeps = ["undefined_steps", "harness_error", "timeout"]
    with pytest.raises(M.SweepRefused, match="before mutant m2"):
        run(swept)
    # m1 ran; m2 ran no pair, and the stage is not complete
    assert swept.fake.pairs_run == [(A, "m1"), (B, "m1")]
    assert M.read_done(swept.run_dir) is None
    rows = M.read_sweeps(swept.run_dir)
    assert [(r["class"], r["attempt"]) for r in rows[1:]] == [
        ("infrastructure", 1), ("failed", 2)]
    assert "gone" in rows[1]["harness_error"]
    assert swept.fake.clears == [0, 1, 4, 5]

    run(swept)                       # resume: m2 is swept, then its pairs
    assert swept.fake.events[-3:] == [
        ("sweep", A), ("pair", A, "m2"), ("pair", C, "m2")]
    assert M.read_done(swept.run_dir)["pairs"] == 4


def test_cancel_after_a_slice_stops_before_the_next_sweep(swept):
    from r2t.bench import mutation_run as MR
    swept.fake.cancel_after_slices = 1
    with pytest.raises(MR.MutationCancelled, match="before the sweep of "
                                                  "mutant m2"):
        run(swept)
    assert swept.fake.events == [
        ("sweep", A), ("pair", A, "m1"), ("pair", B, "m1")]
    assert [r["mutant_id"] for r in M.read_sweeps(swept.run_dir)] == ["m1"]
    assert M.read_done(swept.run_dir) is None

    swept.fake.cancel_after_slices = None
    run(swept)                       # resume: m2 is swept, then its pairs
    assert swept.fake.events[3:] == [
        ("sweep", A), ("pair", A, "m2"), ("pair", C, "m2")]
    assert M.read_done(swept.run_dir)["pairs"] == 4


def test_sweep_outcome_and_class():
    def sweep(raw):
        return M.sweep_class(M.sweep_outcome(
            {"outcome": "no_files_returned", "outcomes_all_runs": [raw]}))
    assert sweep("undefined_steps") == M.SWEPT
    assert sweep("failed") == M.SWEPT
    assert sweep("no_scenario_ran") == M.INFRASTRUCTURE
    assert sweep("container_error") == M.INFRASTRUCTURE
    for raw in ("no_steps_ran", "timeout", "not_passed"):
        assert sweep(raw) == M.FAILED
    assert M.sweep_outcome({"outcome": "no_files_returned"}) == "no_run"
    for label in ("harness_error", "substrate_violation"):
        assert M.sweep_class(M.sweep_outcome(
            {"outcome": label, "outcomes_all_runs": ["undefined_steps"]})) \
            == M.INFRASTRUCTURE
