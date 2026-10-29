"""Kill sets, pair allocation, slim rows and their scoring (no Docker)."""
import json

import pytest

from req2test import evaluate as E
from req2test import mutate as M
from req2test.layout import Kit


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


@pytest.fixture
def kit(tmp_path):
    write_jsonl(tmp_path / "mutation" / "pools.jsonl", [
        {"item_id": "p/a:1", "mutant_id": "m1", "gold_outcome": "killed"},
        {"item_id": "p/a:1", "mutant_id": "m2", "gold_outcome": "survived"},
        {"item_id": "p/a:1", "mutant_id": "m3", "gold_outcome": "killed"},
        {"item_id": "p/b:2", "mutant_id": "m1", "gold_outcome": "killed"},
        {"item_id": "p/b:2", "mutant_id": "m4", "gold_outcome": "excluded"},
    ])
    write_jsonl(tmp_path / "mutation" / "reference_excluded.jsonl", [
        {"item_id": "p/a:1", "mutant_id": "m3", "role": "stub",
         "outcome": "timeout"}])
    meta = {"schema": "req2test.kit/1", "project": "python-docx",
            "mutation": {"files": {
                "pools": "mutation/pools.jsonl",
                "reference_excluded": "mutation/reference_excluded.jsonl"}}}
    return Kit("python-docx", "1.0", tmp_path, meta)


def test_kill_sets_subtract_exclusions(kit):
    assert M.kill_sets(kit) == {"p/a:1": ["m1"], "p/b:2": ["m1"]}
    assert M.kill_sets(kit, ["p/b:2"]) == {"p/b:2": ["m1"]}


def test_kill_sets_leave_out_the_reviewed_nondeterministic_mutants(kit):
    """Harness 25 (D): a listed mutant's pairs are not planned at all."""
    pools = kit.root / "mutation" / "pools.jsonl"
    pools.write_text(pools.read_text() + json.dumps(
        {"item_id": "p/a:1", "mutant_id": "96e02276fdb04ae5",
         "gold_outcome": "killed"}) + "\n")
    assert "96e02276fdb04ae5" in M.S.nondeterministic_mutants()
    assert M.kill_sets(kit) == {"p/a:1": ["m1"], "p/b:2": ["m1"]}


def test_ground_truth_rows_run_as_gold():
    """`validate`'s ground-truth predictions keep gold's rules (harness 25):
    the rows their execution stamped make their mutation runs gold runs."""
    assert M.gold_mark({"metadata": {"source": "gold",
                                     "req2test_prediction": "ok"}})
    assert not M.gold_mark({"metadata": {"req2test_prediction": "ok"}})
    assert not M.gold_mark({})


def test_allocate_is_balanced_and_deterministic():
    pairs = {"m1": ["a", "b", "c"], "m2": ["a"], "m3": ["a", "b"],
             "m4": ["c"]}
    shards = M.allocate(pairs, 2)
    assert shards == M.allocate(pairs, 2)
    assert sorted(m for s in shards for m in s) == ["m1", "m2", "m3", "m4"]
    loads = [sum(len(pairs[m]) for m in s) for s in shards]
    assert max(loads) - min(loads) <= 1


def test_read_rows_last_row_wins(tmp_path):
    write_jsonl(tmp_path / "w0.jsonl", [
        {"instance_id": "a", "mutant_id": "m", "outcome": "container_error"}])
    write_jsonl(tmp_path / "w1.jsonl", [
        {"instance_id": "a", "mutant_id": "m", "outcome": "failed"}])
    assert M.read_rows(tmp_path)[("a", "m")]["outcome"] == "failed"


def test_run_files_score_through_wp6_report(tmp_path, monkeypatch):
    """exec.jsonl, behaviour.json and slim mutation rows, as this package
    writes them, are what WP6's report scores."""
    from kitfixture import write_kit
    kit_root = write_kit(tmp_path / "kits", "python-docx", [
        ("python-docx/a:1", "m1", "killed"), ("python-docx/a:1", "m2", "killed"),
        ("python-docx/a:1", "m3", "survived"),
        ("python-docx/b:2", "m1", "killed")])
    kit = Kit("python-docx", "test", kit_root,
              json.loads((kit_root / "kit.json").read_text()))
    monkeypatch.setattr(E, "load_kit", lambda project: kit)
    monkeypatch.setenv("REQ2TEST_HOME", str(tmp_path / "home"))
    cell = tmp_path / "home" / "runs" / "r" / "python-docx" / "th"
    write_jsonl(cell / "exec.jsonl", [
        {"item_id": "python-docx/a:1", "outcome": "passed",
         "harness_version": 24, "produced_files": [{"file_path": "x",
                                                    "code": ""}]},
        {"item_id": "python-docx/b:2", "outcome": "failed",
         "harness_version": 24, "produced_files": [{"file_path": "x",
                                                    "code": ""}]}])
    (cell / "behaviour.json").write_text(json.dumps({
        "python-docx/a:1": {"api_f1": 0.5, "coverage_j": 0.75},
        "python-docx/b:2": {"api_f1": None, "coverage_j": None}}))
    write_jsonl(cell / "mutation" / "w0.jsonl", [
        {"instance_id": "python-docx/a:1", "mutant_id": "m1",
         "outcome": "failed", "harness_version": 24},
        {"instance_id": "python-docx/a:1", "mutant_id": "m2",
         "outcome": "passed", "harness_version": 24}])
    from kitfixture import write_done
    write_done(cell, {"python-docx/a:1": "passed"})
    summary, rows = E.score_and_report("r", [("python-docx", "th", cell)])
    a, b = rows
    assert a["passed"] and a["recall"] == 0.5 and not a["kill_complete"]
    assert a["api_f1"] == 0.5 and a["coverage_j"] == 0.75
    assert not b["passed"] and b["outcome"] == "assertion_failure"
    assert (tmp_path / "home" / "runs" / "r" / "report.md").is_file()
    assert "exact" in summary["modes"]


def test_staged_jar_names_map_to_maven_basenames():
    name = "0003-d3999291855de495-0003-gson-2.8.9.jar"
    assert M._STAGED_JAR.match(name).group(1) == "gson-2.8.9.jar"
    assert M._STAGED_JAR.match("gson-2.8.9.jar") is None


def test_mutation_gold_replaces_only_the_strip_manifest(tmp_path):
    from types import SimpleNamespace
    gold = tmp_path / "gold"
    (gold / "features").mkdir(parents=True)
    (gold / "features" / "a.rb").write_text("x")
    (gold / "strip_manifest.json").write_text('{"digests": {}}')
    kit_root = tmp_path / "kit"
    (kit_root / "mutation" / "engine").mkdir(parents=True)
    (kit_root / "mutation" / "engine" / "strip_manifest.json").write_text(
        '{"digests": {"a": "b"}}')
    kit = Kit("e-petitions", "1.0", kit_root, {})
    from req2test.layout import kit_inputs
    env = SimpleNamespace(data_root=str(tmp_path / "engine"),
                          gold_root=str(gold))
    out = M.mutation_gold(kit, kit_inputs(kit), env, log=lambda *a: None)
    assert (out / "features" / "a.rb").read_text() == "x"
    assert json.loads((out / "strip_manifest.json").read_text())["digests"]
    assert M.mutation_gold(kit, kit_inputs(kit), env,
                           log=lambda *a: None) == out
    assert M._with_gold(["--gold", "g", "--x"], out) == [
        "--gold", str(out), "--x"]
    assert M.mutation_gold(Kit("python-docx", "1.0", tmp_path / "none", {}),
                           kit_inputs(Kit("python-docx", "1.0",
                                          tmp_path / "none", {})),
                           env) is None


def test_runs_that_make_the_mutation_gold_tree_at_once_share_it(
        tmp_path, monkeypatch):
    import shutil
    import threading
    from types import SimpleNamespace
    from req2test.layout import kit_inputs
    gold = tmp_path / "gold"
    (gold / "features").mkdir(parents=True)
    (gold / "features" / "a.rb").write_text("x")
    kit_root = tmp_path / "kit"
    (kit_root / "mutation" / "engine").mkdir(parents=True)
    (kit_root / "mutation" / "engine" / "strip_manifest.json").write_text(
        '{"digests": {"a": "b"}}')
    kit = Kit("e-petitions", "1.0", kit_root, {})
    env = SimpleNamespace(data_root=str(tmp_path / "engine"),
                          gold_root=str(gold))
    both, copytree = threading.Barrier(2), shutil.copytree

    def copy_together(src, *args, **kwargs):
        if src == env.gold_root:        # not its calls for subdirectories
            both.wait(timeout=30)
        return copytree(src, *args, **kwargs)

    monkeypatch.setattr(shutil, "copytree", copy_together)
    results, errors = [], []

    def make():
        try:
            results.append(M.mutation_gold(kit, kit_inputs(kit), env,
                                           log=lambda *a: None))
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=make) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    out, again = results
    assert out == again and (out / "features" / "a.rb").read_text() == "x"
    assert [p.name for p in out.parent.iterdir()] == [out.name]
