"""`evaluate`'s refusals and SIGTERM handling in execute and evaluate (fake
kits and engine, no Docker)."""
import json
import os
import signal
import time
from types import SimpleNamespace

import pytest

from kitfixture import write_kit
from req2test import cli
from req2test import evaluate as E
from req2test import execute as X
from req2test import predictions as P
from req2test.layout import Kit

A, B, C = ("python-docx/a.feature:1", "python-docx/b.feature:2",
           "python-docx/c.feature:3")


def pred(iid, view=None):
    row = {"instance_id": iid, "model_name_or_path": "m",
           "files": [{"path": "features/steps/x.py", "content": "x"}]}
    if view:
        row["view"] = view
    return row


def write_preds(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return str(path)


@pytest.fixture
def no_env(monkeypatch, tmp_path):
    """Any attempt to bring up an environment fails the test."""
    def env_up(*args, **kwargs):
        raise AssertionError("an environment was brought up")
    monkeypatch.setattr(E, "env_up", env_up)
    monkeypatch.setenv("REQ2TEST_HOME", str(tmp_path / "home"))


def test_other_views_are_refused(tmp_path, no_env):
    path = write_preds(tmp_path / "p.jsonl", [pred(A, "ah")])
    with pytest.raises(P.PredictionError,
                       match=r"view must be one of \('th',\)"):
        E.evaluate(path, run_id="r", project="python-docx", view="th")


def test_project_without_predictions_is_refused(tmp_path, no_env):
    path = write_preds(tmp_path / "p.jsonl",
                       [pred("coreshop/features/x.feature:1")])
    with pytest.raises(ValueError, match="no prediction is for project "
                                         "python-docx"):
        E.evaluate(path, run_id="r", project="python-docx")


def population_kit(tmp_path):
    root = write_kit(tmp_path / "kits", "python-docx",
                     [(A, "m1", "killed"), (B, "m1", "killed")])
    (root / "exec" / "release").mkdir(parents=True)
    (root / "exec" / "release" / "items.jsonl").write_text("".join(
        json.dumps({"item_id": i}) + "\n" for i in (A, B, C)))
    meta = {"mutation": {"files": {"pools": "mutation/pools.jsonl"}}}
    return Kit("python-docx", "1.0", root, meta)


def test_full_split_population_checks(tmp_path):
    kit = population_kit(tmp_path)
    E.check_population(kit, [A, B, C], "exec", "full")
    E.check_population(kit, [A, B], "all", "eval")
    with pytest.raises(ValueError, match="1 full instance.* no mutation "
                                         "pool.*only --split eval has all"):
        E.check_population(kit, [A, B, C], "all", "full")
    with pytest.raises(ValueError, match="cannot execute 1 of the 4 full"):
        E.check_population(kit, [A, B, C, "python-docx/d.feature:4"],
                           "exec", "full")
    # Every other project's full split is data only, whatever its kit holds.
    other = Kit("coreshop", "1.1", kit.root, kit.meta)
    E.check_population(other, [A, B], "exec", "eval")
    with pytest.raises(ValueError, match="^the full split is data-only for "
                                         "coreshop; use --split eval$"):
        E.check_population(other, [A], "exec", "full")


def test_full_split_executes_for_python_docx_only():
    from req2test.dataset import PROJECTS
    from req2test.layout import FULL_SPLIT_PROJECTS, check_split
    assert FULL_SPLIT_PROJECTS == {"python-docx"}
    for project in PROJECTS:
        check_split(project, "eval")
        if project == "python-docx":
            check_split(project, "full")
            continue
        with pytest.raises(ValueError, match=f"^the full split is data-only "
                                             f"for {project}; use --split "
                                             f"eval$"):
            check_split(project, "full")


def test_full_split_mutation_refused_before_any_environment(
        tmp_path, no_env, monkeypatch):
    kit = population_kit(tmp_path)
    monkeypatch.setattr(E, "load_kit", lambda project: kit)
    monkeypatch.setattr(E, "eval_ids", lambda project, split: [A, B, C])
    path = write_preds(tmp_path / "p.jsonl", [pred(A)])
    with pytest.raises(ValueError, match="no mutation pool"):
        E.evaluate(path, run_id="r", split="full", metrics="all")


def test_evaluate_project_takes_the_environment_down_on_sigterm(
        tmp_path, monkeypatch):
    monkeypatch.setenv("REQ2TEST_HOME", str(tmp_path / "home"))
    kit = population_kit(tmp_path)
    monkeypatch.setattr(E, "load_kit", lambda project: kit)
    downs = []
    monkeypatch.setattr(E, "env_up", lambda *a, **k: SimpleNamespace(
        worker_specs=["w0"]))
    monkeypatch.setattr(E, "env_down", downs.append)

    def execute(*args, **kwargs):
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(5)
        raise AssertionError("SIGTERM did not stop the stage")
    monkeypatch.setattr(E.execute, "run", execute)
    previous = signal.getsignal(signal.SIGTERM)
    with pytest.raises(SystemExit):
        E.evaluate_project("python-docx", "th",
                           {A: P.validate_row(pred(A), "t")}, run_id="r",
                           ids=[A], workers=None, metrics="exec",
                           log=lambda *a: None)
    assert len(downs) == 1
    assert signal.getsignal(signal.SIGTERM) is previous


def test_execute_stops_at_the_next_instance_on_sigterm(tmp_path,
                                                       monkeypatch):
    from r2t.bench import runner as RN
    kit = Kit("python-docx", "1.0", tmp_path / "kit", {})
    env = SimpleNamespace(worker_specs=["w0"], global_args=lambda i: [],
                          release_items="items.jsonl", profile="p.yml")
    monkeypatch.setattr(X, "bind_environment", lambda env: None)
    monkeypatch.setattr(X, "worker_harness", lambda args: object())
    monkeypatch.setattr(X, "engine_namespace", lambda argv: SimpleNamespace(
        out=argv[argv.index("--out") + 1], artifacts=None))
    state = {"signal": True, "served": []}

    def run_adapter(harness, args, artifacts, adapter):
        with open(args.out, "a", encoding="utf-8") as fh:
            for iid in args.item:
                adapter({"item_id": iid})
                state["served"].append(iid)
                fh.write(json.dumps({"item_id": iid, "outcome": "passed"})
                         + "\n")
                fh.flush()
                if state["signal"]:
                    state["signal"] = False
                    os.kill(os.getpid(), signal.SIGTERM)
                    time.sleep(0.5)
        return {"n": len(args.item), "outcomes": {}}
    monkeypatch.setattr(RN, "run_adapter", run_adapter)
    preds = {i: P.validate_row(pred(i), "t") for i in (A, B, C)}
    previous = signal.getsignal(signal.SIGTERM)
    run_dir = tmp_path / "run"
    with pytest.raises(RuntimeError, match="stopped by SIGINT or SIGTERM"):
        X.run(kit, env, preds, "th", run_dir, 1, ids=[A, B, C],
              log=lambda *a: None)
    assert state["served"] == [A]
    assert signal.getsignal(signal.SIGTERM) is previous
    assert not (run_dir / "exec.jsonl").exists()

    X.run(kit, env, preds, "th", run_dir, 1, ids=[A, B, C],
          log=lambda *a: None)
    assert state["served"] == [A, B, C]           # A was not run again
    assert len((run_dir / "exec.jsonl").read_text().splitlines()) == 3


def test_instances_without_a_prediction_are_not_executed(tmp_path,
                                                         monkeypatch):
    """No prediction, no files, or `no_output`: a generation-failure row is
    written without an engine run, one console line counts them, and the
    report reads the rows as it reads the engine's `no_files_returned`."""
    from r2t.bench import runner as RN
    from r2t.bench.validate import HARNESS_VERSION
    from kitfixture import write_kit
    from req2test import report
    from req2test import score as S
    D = "python-docx/d.feature:4"
    kit = Kit("python-docx", "1.0", tmp_path / "kit", {})
    env = SimpleNamespace(worker_specs=["w0", "w1"], global_args=lambda i: [],
                          release_items="items.jsonl", profile="p.yml")
    monkeypatch.setattr(X, "bind_environment", lambda env: None)
    monkeypatch.setattr(X, "worker_harness", lambda args: object())
    monkeypatch.setattr(X, "engine_namespace", lambda argv: SimpleNamespace(
        out=argv[argv.index("--out") + 1], artifacts=None))
    served = []

    def run_adapter(harness, args, artifacts, adapter):
        with open(args.out, "a", encoding="utf-8") as fh:
            for iid in args.item:
                produced = adapter({"item_id": iid})
                served.append(iid)
                fh.write(json.dumps({"item_id": iid, "outcome": "passed",
                                     "produced_files": produced["files"]})
                         + "\n")
        return {"n": len(args.item), "outcomes": {"passed": len(args.item)}}
    monkeypatch.setattr(RN, "run_adapter", run_adapter)
    preds = {A: P.validate_row(pred(A), "t"),
             B: P.validate_row({"instance_id": B, "model_name_or_path": "m",
                                "files": []}, "t"),
             C: P.validate_row(dict(pred(C), status="no_output"), "t")}
    lines = []
    run_dir = tmp_path / "run"
    for attempt in (1, 2):                     # the second run resumes
        lines.clear()
        X.run(kit, env, preds, "th", run_dir, 2, ids=[A, B, C, D],
              log=lambda *a: lines.append(" ".join(map(str, a))))
        assert served == [A]
        assert [line for line in lines if "without a prediction" in line] \
            == ["execute: 3 instances without a prediction: "
                "generation_failure"]
    assert lines[0] == "execute: 4 instances, 1 already done, 0 to run"
    raw = run_dir / "exec" / "raw" / X.NO_PREDICTION_FILE
    assert len(raw.read_text().splitlines()) == 3        # written once
    rows = [json.loads(line) for line in
            (run_dir / "exec.jsonl").read_text().splitlines()]
    assert [r["item_id"] for r in rows] == [A, B, C, D]
    states = {B: "empty", C: "no_output", D: "missing"}
    for r in rows[1:]:
        assert r["outcome"] == "no_files_returned" and r["executed"] is False
        assert r["produced_files"] == [] and r["n_files"] == 0
        assert r["metadata"] == {"req2test_prediction": states[r["item_id"]]}
        assert r["harness_version"] == HARNESS_VERSION
        assert S.classify_exec(r) == ("generation_failure", None)

    # The report reads them as it reads the engine's own rows for an empty
    # solution (`runner._record` with the `no_files_returned` override).
    def engine_row(iid):
        return {"item_id": iid, "outcome": "no_files_returned",
                "n_files": 0, "produced_files": [], "written_files": [],
                "rejected_files": [], "index_errors": {},
                "metadata": {"req2test_prediction": states[iid]},
                "per_step": [], "coverage_lines": {"src/x.py": [1]},
                "adapter": "predictions:m", "harness_version": HARNESS_VERSION}
    scored = write_kit(tmp_path / "kits", "python-docx", [(A, "m1", "killed")])
    engine_cell = tmp_path / "engine-cell"
    engine_cell.mkdir()
    (engine_cell / "exec.jsonl").write_text("".join(
        json.dumps(r if r["item_id"] == A else engine_row(r["item_id"]))
        + "\n" for r in rows))
    ours = report.cell_instances(scored, "python-docx", "th", run_dir)
    theirs = report.cell_instances(scored, "python-docx", "th", engine_cell)
    assert ours == theirs
    assert [r["outcome"] for r in ours] == ["pass"] + ["generation_failure"] * 3


def test_forked_workers_stop_when_the_coordinator_gets_sigterm(
        tmp_path, monkeypatch):
    from r2t.bench import runner as RN
    ids = [f"python-docx/{c}.feature:1" for c in "abcdef"]
    kit = Kit("python-docx", "1.0", tmp_path / "kit", {})
    env = SimpleNamespace(worker_specs=["w0", "w1"], global_args=lambda i: [],
                          release_items="items.jsonl", profile="p.yml")
    monkeypatch.setattr(X, "bind_environment", lambda env: None)
    monkeypatch.setattr(X, "worker_harness", lambda args: object())
    monkeypatch.setattr(X, "engine_namespace", lambda argv: SimpleNamespace(
        out=argv[argv.index("--out") + 1], artifacts=None))
    coordinator = os.getpid()

    def run_adapter(harness, args, artifacts, adapter):   # in a fork
        with open(args.out, "a", encoding="utf-8") as fh:
            for n, iid in enumerate(args.item):
                adapter({"item_id": iid})
                fh.write(json.dumps({"item_id": iid, "outcome": "passed"})
                         + "\n")
                fh.flush()
                if n == 0 and args.out.endswith("w0.jsonl"):
                    os.kill(coordinator, signal.SIGTERM)
                time.sleep(0.5)
        return {"n": len(args.item), "outcomes": {}}
    monkeypatch.setattr(RN, "run_adapter", run_adapter)
    preds = {i: P.validate_row(pred(i), "t") for i in ids}
    with pytest.raises(RuntimeError, match="stopped by SIGINT or SIGTERM"):
        X.run(kit, env, preds, "th", tmp_path / "run", 2, ids=ids,
              log=lambda *a: None)
    raw = tmp_path / "run" / "exec" / "raw"
    written = sum(len(p.read_text().splitlines()) for p in raw.glob("w*.jsonl"))
    assert 1 <= written <= 2           # each worker stopped after its first


def test_workers_help_names_the_real_defaults():
    parser = cli.build_parser()
    sub = parser._subparsers._group_actions[0].choices["evaluate"]
    text = next(a.help for a in sub._actions if "--workers" in
                a.option_strings)
    assert "at most 8" not in text and "40 for coddy-agent" in text


# ----------------------------------------- clean clone, data-only, subsets
def test_dirty_clone_is_refused_before_any_environment(tmp_path, no_env,
                                                       monkeypatch):
    from req2test.env import EnvError
    kit = population_kit(tmp_path)
    monkeypatch.setattr(E, "load_kit", lambda project: kit)
    monkeypatch.setattr(E, "eval_ids", lambda project, split: [A, B, C])

    def dirty():
        raise EnvError("the clone /c is not clean")
    monkeypatch.setattr(E, "check_clone", dirty)
    path = write_preds(tmp_path / "p.jsonl", [pred(A)])
    with pytest.raises(EnvError, match="not clean"):
        E.evaluate(path, run_id="r", metrics="exec")


def test_full_split_is_data_only_outside_python_docx(tmp_path, no_env,
                                                     monkeypatch):
    def unread(*args):
        raise AssertionError("the split was read")
    monkeypatch.setattr(E, "eval_ids", unread)
    monkeypatch.setattr(E, "load_kit", unread)
    path = write_preds(tmp_path / "p.jsonl",
                       [pred("coreshop/features/x.feature:1")])
    with pytest.raises(ValueError, match="^the full split is data-only for "
                                         "coreshop; use --split eval$"):
        E.evaluate(path, run_id="r", split="full", metrics="exec")
    # A sample is refused all the same.
    with pytest.raises(ValueError, match="data-only for coreshop"):
        E.evaluate(path, run_id="r", split="full", metrics="exec", sample=1)


def test_tasks_full_split_refused_without_a_traceback(monkeypatch):
    from req2test import dataset
    from req2test import tasks as T

    def unread(*args, **kwargs):
        raise AssertionError("the kit or the split was read")
    monkeypatch.setattr(T, "load_kit", unread)
    monkeypatch.setattr(dataset, "iter_instances", unread)
    with pytest.raises(ValueError, match="^the full split is data-only for "
                                         "coddy-agent; use --split eval$"):
        T.task_rows("coddy-agent", "th", "full")


def test_missing_full_split_names_the_fetch(tmp_path, no_env, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    (data / "eval.jsonl").write_text(json.dumps(
        {"instance_id": A, "project": "python-docx"}) + "\n")
    monkeypatch.setenv("REQ2TEST_DATA_DIR", str(data))
    fetch = "req2test fetch --split full --dataset-only"
    hint = (f"run `{fetch}`; on a host without Internet access, run "
            f"`{fetch} --download-only DIR` on one that has it, copy DIR "
            f"here and run `{fetch} --from-dir DIR`")
    with pytest.raises(FileNotFoundError, match="full.jsonl does not exist; "
                                                + __import__("re").escape(hint)):
        E.evaluate(None, run_id="r", split="full", metrics="exec",
                   predictions={A: P.validate_row(pred(A), "t")})
    code, _out, err = _cli(["tasks", "--split", "full", "--project",
                            "python-docx", "--view", "th", "--out",
                            str(tmp_path / "t.jsonl")])
    assert code == 2
    assert err.startswith("req2test: error: ") and err.rstrip().endswith(hint)


def _cli(argv):
    import contextlib
    import io
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class _Recorder:
    """`evaluate_project` and `score_and_report` stand-ins."""

    def __init__(self):
        self.calls = []

    def project(self, project, view, preds, *, run_id, ids, workers,
                metrics, docker_host=None, log=None):
        self.calls.append((project, view, sorted(preds), list(ids)))
        return E.run_root(run_id) / project / view, True

    def report(self, run_id, cells):
        from req2test import report
        root = E.run_root(run_id)
        subset = root / report.SUBSET_FILE
        return ({"subset": json.loads(subset.read_text())
                 if subset.exists() else None}, [])


@pytest.fixture
def recorded(tmp_path, monkeypatch):
    monkeypatch.setenv("REQ2TEST_HOME", str(tmp_path / "home"))
    kit = population_kit(tmp_path)
    monkeypatch.setattr(E, "load_kit", lambda project: kit)
    monkeypatch.setattr(E, "eval_ids", lambda project, split: [A, B, C])
    clone = []
    monkeypatch.setattr(E, "check_clone", lambda: clone.append(1))
    rec = _Recorder()
    rec.clone = clone
    monkeypatch.setattr(E, "evaluate_project", rec.project)
    monkeypatch.setattr(E, "score_and_report", rec.report)
    return rec


def test_sample_is_validates_draw_and_marks_a_subset(tmp_path, recorded,
                                                     monkeypatch):
    ids = E.sample_ids("python-docx", 2)
    assert len(ids) == 2
    path = write_preds(tmp_path / "p.jsonl", [pred(i) for i in (A, B, C)])
    result = E.evaluate(path, run_id="s", metrics="exec", sample=2)
    (project, view, preds, run_ids), = recorded.calls
    assert (project, view, run_ids) == ("python-docx", "th", ids)
    assert preds == ids               # the third prediction is ignored
    assert recorded.clone == [1]
    subset = result["summary"]["subset"]
    assert subset["selection"] == "sample"
    assert subset["seed"] == E.VALIDATE_SEED
    assert subset["projects"] == {"python-docx": {"n": 2, "of": 3}}
    # The same run id without a selection is no longer a subset.
    E.evaluate(path, run_id="s2", metrics="exec")
    assert not (E.run_root("s2") / "subset.json").exists()


def test_instances_file_selects_in_population_order(tmp_path, recorded):
    listing = tmp_path / "ids.txt"
    listing.write_text(f"# chosen\n{C}\n\n{A}\n")
    ids = E.read_instance_ids(listing)
    assert ids == [C, A]
    path = write_preds(tmp_path / "p.jsonl", [pred(A), pred(B)])
    result = E.evaluate(path, run_id="i", metrics="exec", instances=ids,
                        instances_file=str(listing))
    (_p, _v, preds, run_ids), = recorded.calls
    assert run_ids == [A, C] and preds == [A]
    assert result["summary"]["subset"]["instances_file"] == str(listing)
    with pytest.raises(ValueError, match="not in the eval split"):
        E.evaluate(path, run_id="j", metrics="exec",
                   instances=[A, "python-docx/zz.feature:9"])
    with pytest.raises(ValueError, match="unknown project"):
        E.evaluate(path, run_id="j", metrics="exec",
                   instances=["nope/a.feature:1"])


def test_instances_file_refuses_repeats_and_empty(tmp_path):
    listing = tmp_path / "ids.txt"
    listing.write_text(f"{A}\n{A}\n")
    with pytest.raises(ValueError, match="listed twice"):
        E.read_instance_ids(listing)
    listing.write_text("# nothing\n\n")
    with pytest.raises(ValueError, match="lists no instance id"):
        E.read_instance_ids(listing)


# ------------------------------------------- no worker pool for idle stages
@pytest.fixture
def pools(tmp_path, monkeypatch):
    """`evaluate_project` with real execute bookkeeping and mutation
    planning, a stub behaviour stage, and recorded environment calls."""
    monkeypatch.setenv("REQ2TEST_HOME", str(tmp_path / "home"))
    kit = population_kit(tmp_path)
    monkeypatch.setattr(E, "load_kit", lambda project: kit)
    rec = SimpleNamespace(ups=[], downs=[], lines=[], kit=kit,
                          env=SimpleNamespace(worker_specs=["w0"]))

    def env_up(*args, **kwargs):
        rec.ups.append(args[0].project)
        return rec.env
    monkeypatch.setattr(E, "env_up", env_up)
    monkeypatch.setattr(E, "env_down", rec.downs.append)
    monkeypatch.setattr(E.behaviour, "run", lambda kit, rdir: None)
    rec.rdir = E.make_run_dir("r", "python-docx", "th")
    rec.preds = {A: P.validate_row(pred(A), "t")}       # B and C: none

    def run(metrics):
        rec.lines.clear()
        return E.evaluate_project(
            "python-docx", "th", rec.preds, run_id="r", ids=[A, B, C],
            workers=None, metrics=metrics,
            log=lambda *a: rec.lines.append(" ".join(map(str, a))))
    rec.run = run
    return rec


def _write_rows(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_nothing_left_to_run_brings_up_no_pool(pools):
    """Every instance done or without a prediction, and mutation finished:
    no environment; the rows are still merged and the stage marked done."""
    _write_rows(pools.rdir / "exec" / "raw" / "w0.jsonl",
                [{"item_id": A, "outcome": "passed"}])
    rdir, brought_up = pools.run("exec")
    assert (rdir, brought_up) == (pools.rdir, False)
    assert pools.ups == [] and pools.downs == []
    assert [json.loads(line)["item_id"] for line in
            (rdir / "exec.jsonl").read_text().splitlines()] == [A, B, C]
    assert "execute: 3 instances, 1 already done, 0 to run" in pools.lines
    assert ("python-docx/th: nothing left to run on workers; no worker pool "
            "was brought up") in pools.lines

    # With mutation: A's baseline passed and its one G pair has a row.
    from req2test import mutate as M
    _write_rows(rdir / M.BASELINE_FILE,
                [{"instance_id": A, "outcome": "passed", "class": "passed"}])
    _write_rows(rdir / "mutation" / "w0.jsonl",
                [{"instance_id": A, "mutant_id": "m1", "outcome": "failed"}])
    assert pools.run("all") == (pools.rdir, False)
    assert pools.ups == [] and pools.downs == []
    assert M.read_done(rdir)["pairs"] == 1


def test_pool_comes_up_for_mutation_only_when_it_has_work(pools,
                                                          monkeypatch):
    _write_rows(pools.rdir / "exec" / "raw" / "w0.jsonl",
                [{"item_id": A, "outcome": "passed"}])
    seen = []
    monkeypatch.setattr(E.mutate, "run",
                        lambda kit, env, rdir, workers, log: seen.append(env))
    # A's baseline has not run: the pool comes up after execution.
    assert pools.run("all") == (pools.rdir, True)
    assert pools.ups == ["python-docx"] and seen == [pools.env]
    assert pools.downs == [pools.env]
    assert "execute: 3 instances, 1 already done, 0 to run" in pools.lines


def test_retryable_rows_still_bring_up_the_pool(pools, monkeypatch):
    """Resume semantics are kept: a harness_error row runs again."""
    _write_rows(pools.rdir / "exec" / "raw" / "w0.jsonl",
                [{"item_id": A, "outcome": "harness_error"}])
    assert X.pending(pools.preds, [A, B, C], pools.rdir) == [A]
    seen = []

    def execute(kit, env, *args, **kwargs):
        seen.append(env)
    monkeypatch.setattr(E.execute, "run", execute)
    assert pools.run("exec") == (pools.rdir, True)
    assert seen == [pools.env] and pools.downs == [pools.env]


def test_evaluate_counts_the_pools(tmp_path, recorded, monkeypatch):
    path = write_preds(tmp_path / "p.jsonl", [pred(A)])
    assert E.evaluate(path, run_id="n", metrics="exec")["pools"] == 1
    monkeypatch.setattr(E, "evaluate_project", lambda *a, run_id, **k: (
        E.run_root(run_id), False))
    assert E.evaluate(path, run_id="n", metrics="exec")["pools"] == 0


# ------------------------------------------- warnings of the selection only
def repo_pred(iid):
    return dict(pred(iid), files=[{"path": "repo/features/steps/x.py",
                                   "content": "x"}])


def test_repo_prefix_warning_only_for_selected_instances(tmp_path, recorded,
                                                         capsys):
    path = write_preds(tmp_path / "p.jsonl",
                       [repo_pred(A), repo_pred(B), repo_pred(C)])
    E.evaluate(path, run_id="w", metrics="exec", instances=[B])
    err = capsys.readouterr().err
    assert err.count("removed the leading 'repo/'") == 1
    assert f": {B}: removed the leading 'repo/'" in err
    (_p, _v, preds, _ids), = recorded.calls
    assert preds == [B]
    # Without a selection every prediction is evaluated and warned about.
    E.evaluate(path, run_id="w2", metrics="exec")
    assert capsys.readouterr().err.count("removed the leading 'repo/'") == 3


def test_load_can_keep_the_warnings_for_the_caller(tmp_path):
    path = write_preds(tmp_path / "p.jsonl", [repo_pred(A), pred(B)])
    preds = P.load(path, warn=None)
    assert preds[A].files[0]["path"] == "features/steps/x.py"
    assert len(preds[A].notes) == 1 and preds[B].notes == []
    warned = []
    P.warn_notes({B: preds[B]}, warned.append)
    assert warned == []
    P.warn_notes(preds, warned.append)
    assert warned == preds[A].notes
    assert "notes" not in preds[A].to_json()


# ------------------------------------------------------ full-split marker
def test_full_split_run_is_marked(tmp_path, recorded):
    from req2test import report
    path = write_preds(tmp_path / "p.jsonl", [pred(A)])
    E.evaluate(path, run_id="f", split="full", metrics="exec")
    marker = E.run_root("f") / report.SPLIT_FILE
    assert json.loads(marker.read_text()) == {"split": "full",
                                              "projects": ["python-docx"]}
    # The same run id on the eval split is no longer marked.
    E.evaluate(path, run_id="f", metrics="exec")
    assert not marker.exists()


def test_a_run_evaluates_benchmark_1_1_th_only():
    assert E.run_version([("python-docx", "th", {}, [A])]) == "1.1"
    with pytest.raises(ValueError, match=r"1.1 offers the th view only; "
                                         r"refusing \['python-docx/ah'\]"):
        E.run_version([("python-docx", "ah", {}, [A])])


def test_a_1_1_run_without_its_population_list_is_refused_first(
        tmp_path, no_env, monkeypatch):
    from r2t.bench import population as BP
    two = {A: P.validate_row({**pred(A), "benchmark_version": "1.1"}, "t")}
    monkeypatch.setattr(E, "check_population", lambda *a: None)
    monkeypatch.setattr(E, "load_kit", lambda project: None)
    monkeypatch.setattr(E, "eval_ids", lambda project, split: [A])
    monkeypatch.setattr(E, "check_clone", lambda: None)
    monkeypatch.setattr(E, "evaluate_project",
                        lambda *a, **k: pytest.fail("executed"))
    monkeypatch.setattr(BP, "BENCHMARK_POPULATION",
                        str(tmp_path / "absent.yml"))
    with pytest.raises(FileNotFoundError, match="not in this checkout"):
        E.evaluate(None, run_id="r2", project="python-docx", predictions=two,
                   ids_by_project={"python-docx": [A]})
    assert not E.run_root("r2").exists()


def test_a_run_keeps_its_benchmark_version(tmp_path):
    marker = tmp_path / "benchmark.json"
    E.record_version(marker, "1.1")
    assert json.loads(marker.read_text()) == {"benchmark_version": "1.1"}
    E.record_version(marker, "1.1")
    for other in ("3.0", None):
        with pytest.raises(RuntimeError, match=r"holds a run of benchmark "
                                               r"version 1.1.*use a new "
                                               r"--run-id"):
            E.record_version(marker, other)
    # A run made before benchmark.json existed records no version.
    legacy = tmp_path / "legacy"
    (legacy / "python-docx" / "th").mkdir(parents=True)
    (legacy / "python-docx" / "th" / "exec.jsonl").write_text("")
    for other in ("1.1",):
        with pytest.raises(RuntimeError, match=r"version not stated, these "
                                               r"predictions are " + other):
            E.record_version(legacy / "benchmark.json", other)
    assert not (legacy / "benchmark.json").exists()
    E.record_version(legacy / "benchmark.json", None)
    assert json.loads((legacy / "benchmark.json").read_text()) == {
        "benchmark_version": None}
