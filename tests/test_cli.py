"""The `req2test` command line: known errors as one line (exit 2, traceback
with --debug), bare `selftest`, evaluate's subset flags and what it prints
(fake stages, no Docker)."""
import contextlib
import io

import pytest

from req2test import cli
from req2test import evaluate as E
from req2test.env import EnvError

A = "python-docx/a.feature:1"


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def refuse(exc):
    def fail(*args, **kwargs):
        raise exc
    return fail


EVALUATE = ["evaluate", "--predictions", "p.jsonl", "--run-id", "r"]


@pytest.mark.parametrize("exc", [
    EnvError("the clone /c is not clean (1 changed or untracked path(s)):\n"
             "  ?? tasks.jsonl\nkeep tasks, views and predictions outside "
             "the clone (e.g. ~/r2t-work) or under ./work/"),
    ValueError("the full split is data-only for kapua; use --split eval"),
    RuntimeError("execute: stopped by SIGINT or SIGTERM"),
    FileNotFoundError("no kapua kit under /h/kits/kapua; run `req2test "
                      "fetch --project kapua`")])
def test_known_errors_are_one_line_and_exit_2(monkeypatch, exc):
    monkeypatch.setattr(E, "evaluate", refuse(exc))
    code, _out, err = run(EVALUATE)
    assert code == 2
    lines = err.splitlines()
    assert lines[0] == "req2test: error: " + str(exc).splitlines()[0]
    assert lines[1:] == str(exc).splitlines()[1:]
    assert "Traceback" not in err


def test_debug_prints_the_traceback_before_or_after_the_verb(monkeypatch):
    monkeypatch.setattr(E, "validate", refuse(EnvError("no daemon")))
    for argv in (["--debug", "validate", "--project", "kapua"],
                 ["validate", "--project", "kapua", "--debug"]):
        code, _out, err = run(argv)
        assert code == 2 and "Traceback" in err
        assert err.rstrip().endswith("req2test: error: no daemon")


def test_env_errors_and_debug_pass_through(monkeypatch):
    from req2test import env
    seen = []

    def main(argv):
        seen.append(argv)
        raise EnvError("2 live kapua environments")
    monkeypatch.setattr(env, "main", main)
    code, _out, err = run(["env", "down", "--project", "kapua", "--debug"])
    assert code == 2 and seen == [["down", "--project", "kapua"]]
    assert "Traceback" in err
    code, _out, err = run(["env", "down", "--project", "kapua"])
    assert err == "req2test: error: 2 live kapua environments\n"


def test_tasks_refusal_exits_2(monkeypatch):
    from req2test import tasks
    monkeypatch.setattr(tasks, "export", refuse(ValueError(
        "the full split is data-only for kapua; use --split eval")))
    code, _out, err = run(["tasks", "--split", "full", "--project", "kapua",
                           "--view", "th", "--out", "t.jsonl"])
    assert code == 2
    assert err == ("req2test: error: the full split is data-only for kapua; "
                   "use --split eval\n")


def test_bare_selftest_names_the_engine_flag_and_exits_0():
    code, out, err = run(["selftest"])
    assert code == 0 and err == ""
    assert "req2test selftest --engine" in out
    assert "not implemented" not in out


def test_debug_prints_the_traceback_then_the_error_and_hints(monkeypatch):
    monkeypatch.setattr(E, "evaluate", refuse(ValueError(
        "first line\nhint line")))
    code, _out, err = run(["--debug"] + EVALUATE)
    assert code == 2
    lines = err.rstrip().splitlines()
    assert lines[0].startswith("Traceback")
    assert lines[-2:] == ["req2test: error: first line", "hint line"]


def test_evaluate_subset_flags(monkeypatch, tmp_path):
    seen = {}

    def evaluate(path, **kw):
        seen.update(kw)
        return {"summary": {"subset": {"selection": "sample"}},
                "instances": [], "pools": 1}
    monkeypatch.setattr(E, "evaluate", evaluate)
    monkeypatch.setenv("REQ2TEST_HOME", str(tmp_path))
    code, out, _err = run(EVALUATE + ["--sample", "3", "--seed", "7"])
    assert code == 0
    assert (seen["sample"], seen["seed"], seen["instances"]) == (3, 7, None)
    assert "SUBSET run" in out and "not comparable to the leaderboard" in out
    assert "req2test env stop-daemon" in out
    code, _out, _err = run(EVALUATE + ["--sample", "3"])
    assert seen["seed"] == E.VALIDATE_SEED
    listing = tmp_path / "ids.txt"
    listing.write_text(A + "\n")
    code, _out, _err = run(EVALUATE + ["--instances", str(listing)])
    assert seen["instances"] == [A] and seen["sample"] is None
    assert seen["instances_file"] == str(listing)
    code, _out, err = run(EVALUATE + ["--seed", "7"])
    assert code == 2 and "--seed applies to --sample only" in err
    with pytest.raises(SystemExit), \
            contextlib.redirect_stderr(io.StringIO()):
        cli.main(EVALUATE + ["--sample", "3", "--instances", str(listing)])


def test_evaluate_prints_rejected_prediction_files(monkeypatch, tmp_path):
    rows = [{"instance_id": A, "project": "python-docx", "view": "th",
             "passed": False, "api_f1": None, "coverage_j": None,
             "kill_complete": False, "mutation_status": "not_run",
             "rejected_files": [
                 {"file_path": "src/docx/api.py",
                  "why": "not_test_code:production"}]}]
    monkeypatch.setattr(E, "evaluate", lambda path, **kw: {
        "summary": {}, "instances": rows, "pools": 1})
    monkeypatch.setenv("REQ2TEST_HOME", str(tmp_path))
    code, out, _err = run(EVALUATE + ["--docker-host", "unix:///x.sock"])
    assert code == 0
    assert ("prediction files the engine rejected, with its reason, "
            "1 instance(s):") in out
    assert f"  {A}: src/docx/api.py (not_test_code:production)" in out
    assert "SUBSET" not in out and "stop-daemon" not in out


def _row(passed, status, kc=False, iid=A):
    return {"instance_id": iid, "project": "python-docx", "view": "th",
            "passed": passed, "api_f1": 1.0 if passed else None,
            "coverage_j": 1.0 if passed else None, "kill_complete": kc,
            "mutation_status": status, "rejected_files": []}


def test_exec_only_console_prints_kill_complete_as_not_measured(
        monkeypatch, tmp_path):
    B = "python-docx/b.feature:2"
    monkeypatch.setenv("REQ2TEST_HOME", str(tmp_path))
    rows = [_row(True, "not_run"), _row(False, "not_run", iid=B)]
    monkeypatch.setattr(E, "evaluate", lambda path, **kw: {
        "summary": {}, "instances": rows, "pools": 1})
    code, out, _err = run(EVALUATE + ["--metrics", "exec"])
    assert code == 0
    assert ("python-docx/th: pass 1/2, kill_complete – (mutation not "
            "measured), API F1 (passing) 1.0, coverage J (passing) 1.0") in out
    assert "0/2" not in out
    # Rows scored before every exec-only row was `not_run` (the failure
    # `not_passed`) read the same.
    rows[1]["mutation_status"] = "not_passed"
    code, out, _err = run(EVALUATE + ["--metrics", "exec"])
    assert "kill_complete – (mutation not measured)" in out
    # With mutation the count is printed, a zero included.
    rows[:] = [_row(True, "scored"), _row(False, "not_passed", iid=B)]
    code, out, _err = run(EVALUATE)
    assert "kill_complete 0/2" in out and "not measured" not in out


def test_full_split_note_and_no_daemon_note_without_a_pool(monkeypatch,
                                                           tmp_path):
    from req2test.report import FULL_SPLIT_NOTE
    monkeypatch.setenv("REQ2TEST_HOME", str(tmp_path))
    monkeypatch.setattr(E, "evaluate", lambda path, **kw: {
        "summary": {"full_split": {"split": "full"}},
        "instances": [_row(True, "not_run")], "pools": 0})
    code, out, _err = run(EVALUATE + ["--split", "full", "--metrics", "exec"])
    assert code == 0
    assert FULL_SPLIT_NOTE in out and "NOT COMPARABLE" in out
    assert "SUBSET" not in out
    # No worker pool came up, so no daemon was started for this run.
    assert "stop-daemon" not in out
