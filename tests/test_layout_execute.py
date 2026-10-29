"""Kit field resolution, the engine namespace bridge and run-row merging."""
import json

from req2test import evaluate as E
from req2test import execute as X
from req2test import predictions as P
from req2test.layout import Kit, kit_inputs


def test_kit_inputs_python_docx(tmp_path):
    meta = {"exec_env": {"worker": {"max_k_hint": 16},
                         "timeout_seconds": 600},
            "behaviour": {"gold_run": {"file": "behaviour/g.jsonl.zst"},
                          "I_api": {"file": "behaviour/I_api.json"}},
            "mutation": {"engine": "r2t-mutate-py",
                         "files": {"pools": "mutation/pools.jsonl.zst"}}}
    kin = kit_inputs(Kit("python-docx", "1.0", tmp_path, meta))
    assert kin.view_profile("th").name.endswith("target_hidden.yml")
    assert kin.worker_profile.name == "profile_python_docx.yml"
    assert kin.release_items == tmp_path / "exec/release/items.jsonl"
    assert not kin.needs_database and kin.timeout == 600
    assert kin.mutation["pools"].name == "pools.jsonl.zst"
    assert kin.gold_run.name == "g.jsonl.zst"


def test_kit_inputs_defaults_and_database_projects(tmp_path):
    for rel in ("behaviour/api_profile.yml", "behaviour/prod_index.json.zst",
                "mutation/rules.json"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("")
    kin = kit_inputs(Kit("coreshop", "1.0", tmp_path, {}))
    assert kin.needs_database and kin.timeout == 600
    assert kin.prod_index.name == "prod_index.json.zst"
    assert kin.api_profile.name == "api_profile.yml"
    assert kin.mutation["rules"].name == "rules.json"
    assert kin.mutation["pools"] is None


def test_extract_tree_descends_into_single_directory(tmp_path):
    import tarfile
    from req2test.layout import extract_tree
    src = tmp_path / "src" / "top"
    src.mkdir(parents=True)
    (src / "a.txt").write_text("x")
    archive = tmp_path / "t.tar"
    with tarfile.open(archive, "w") as tar:
        tar.add(src, arcname="top")
    tree = extract_tree(archive, tmp_path / "out")
    assert (tree / "a.txt").read_text() == "x"
    assert extract_tree(archive, tmp_path / "out") == tree   # once only
    assert extract_tree(archive, tmp_path / "out", "top") == tree


def test_engine_namespace_stops_before_the_verb(tmp_path):
    args = X.engine_namespace([
        "--boundary", "benchmark/config/boundary_python_docx.yml",
        "--gold", str(tmp_path), "--artifacts", str(tmp_path),
        "run", "--adapter", "gold", "--release", str(tmp_path / "i.jsonl"),
        "--profile", "benchmark/config/profile_python_docx.yml",
        "--coverage", "--timeout", "600", "--out", str(tmp_path / "o.jsonl")])
    assert args.cmd == "run" and args.coverage and args.timeout == 600
    assert args.out == str(tmp_path / "o.jsonl")


def test_adapter_serves_predictions():
    pred = P.validate_row({"instance_id": "a", "model_name_or_path": "m",
                           "files": [{"path": "f.py", "content": "x"}]}, "t")
    adapter = X.make_adapter({"a": pred}, "m", "0" * 64)
    assert adapter({"item_id": "a"})["files"] == [{"file_path": "f.py",
                                                    "code": "x"}]
    missing = adapter({"item_id": "b"})
    assert missing["files"] == [] and \
        missing["metadata"]["req2test_prediction"] == "missing"
    assert "source" not in adapter({"item_id": "a"})["metadata"]


def test_adapter_runs_ground_truth_as_gold():
    """Ground-truth predictions are gold runs: the engine keeps gold's suite
    and wiring rules for them (harness 25), and nothing in a predictions
    file can ask for that."""
    from r2t.bench.runner import is_gold_run_adapter

    def pred(ground_truth):
        p = P.validate_row({"instance_id": "a", "model_name_or_path": "m",
                            "files": [{"path": "f.py", "content": "x"}]}, "t")
        p.ground_truth = ground_truth
        return p

    gold = X.make_adapter({"a": pred(True)}, "m", "0" * 64)
    assert is_gold_run_adapter(gold)
    assert gold({"item_id": "a"})["metadata"] == {
        "req2test_prediction": "ok", "source": "gold"}
    submitted = X.make_adapter({"a": pred(False)}, "m", "0" * 64)
    assert not is_gold_run_adapter(submitted)
    assert "source" not in submitted({"item_id": "a"})["metadata"]


def test_final_rows_prefer_final_outcomes(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "w0.jsonl").write_text(
        json.dumps({"item_id": "a", "outcome": "harness_error"}) + "\n"
        + json.dumps({"item_id": "b", "outcome": "failed"}) + "\n")
    (raw / "w1.jsonl").write_text(
        json.dumps({"item_id": "a", "outcome": "passed"}) + "\n"
        + json.dumps({"item_id": "b", "outcome": "harness_error"}) + "\n")
    rows = X.merge(raw, ["b", "a"], tmp_path / "exec.jsonl")
    assert rows["a"]["outcome"] == "passed" and rows["b"]["outcome"] == "failed"
    assert [json.loads(line)["item_id"] for line in
            (tmp_path / "exec.jsonl").read_text().splitlines()] == ["b", "a"]


def test_sample_ids_deterministic(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    rows = [{"instance_id": f"python-docx/f.feature:{i}",
             "project": "python-docx"} for i in range(50)]
    (data / "eval.jsonl").write_text("".join(json.dumps(r) + "\n"
                                             for r in rows))
    monkeypatch.setenv("REQ2TEST_DATA_DIR", str(data))
    first = E.sample_ids("python-docx", 20)
    assert first == E.sample_ids("python-docx", 20) and len(first) == 20
    assert first == sorted(first)


ADVICE = ("  reproducibility check: SKIPPED — non-replayable adapter "
          "predictions:m: re-running would re-invoke the system under test. "
          "Re-execute this run with `--adapter replay --replay <run file>` "
          "to check it for free.")


def test_engine_replay_advice_is_dropped_whole_lines_only():
    import io
    out = io.StringIO()
    stream = X._LineFilter(out, X.ENGINE_ADVICE)
    stream.write("execute: 3 instances\n")
    cut = ADVICE.index("--adapter replay") + 20
    stream.write(ADVICE[:20])            # pieces of one line are judged whole
    stream.write(ADVICE[20:cut])
    stream.flush()                       # a held piece of the advice waits
    stream.write(ADVICE[cut:])
    stream.write("\n")
    stream.write("partial")
    stream.flush()
    stream.write(" line\n")
    assert out.getvalue() == "execute: 3 instances\npartial line\n"


def test_engine_advice_filtered_in_forked_workers(tmp_path, monkeypatch):
    import multiprocessing
    import sys
    log = open(tmp_path / "out.txt", "w", encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", log)

    def child():
        print(ADVICE, flush=True)
        print("worker 0: 1 instance(s)", flush=True)
    with X.engine_advice_filtered():
        print(ADVICE)
        print("coordinator")
        sys.stdout.flush()
        process = multiprocessing.get_context("fork").Process(target=child)
        process.start()
        process.join()
    assert sys.stdout is log
    log.close()
    assert (tmp_path / "out.txt").read_text() == (
        "coordinator\nworker 0: 1 instance(s)\n")
