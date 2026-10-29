"""Execute predictions once against the full production code.

Each prediction runs through the engine's own runner,
`r2t.bench.runner.run_adapter`, with an adapter object built here (harness
plan A.4, P1): the engine needs no edit, because `run_adapter` accepts any
adapter and only the reserved name `submitted` triggers the engine's
two-project submission admission.  The engine row is the record: outcome,
per-step results, coverage lines and direct calls, exactly as the study's
runs wrote them.  Coverage is always on and the timeout is the kit's (600 s).

Work is spread over the environment's K workers, one forked process per
worker, each on its own workspace and container.  Rows land in
`exec/raw/w<k>.jsonl` and are merged into `exec.jsonl` (one row per instance,
population order).  A rerun with the same run id resumes: an instance with a
final row is not run again, and a `harness_error` or `scenario_not_found` row
is retried.  When no instance is left to execute (`pending`), no environment
is needed.

An instance without a prediction (no row, an empty `files` list, or
`status: no_output`) is not executed: it is a generation failure whatever an
execution would show, so its row is written here
(`generation_failure_row`, in `exec/raw/no-prediction.jsonl`) with the
outcome fields the engine writes for an empty solution (`no_files_returned`,
no files), and the console gets one summary line for all of them instead of
one engine line each.

SIGINT and SIGTERM stop execution cooperatively, under the engine's
coordinator cancellation (as `req2test.mutate` runs): each worker finishes
the instance it is executing, starts no other, and `run` raises, so the
caller's `env down` runs.  The rows already written are kept for the resume.

The engine's command-line bindings (Docker authority, worker spec, data
defaults) are applied by parsing an `r2t run` command line with the engine's
own parser and stopping before its handler (`engine_namespace`), so this
module never re-implements them.  The runner's console advice to re-execute
with `--adapter replay`, an engine option req2test does not have, is dropped
from the output (`engine_advice_filtered`); the engine is not edited.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Optional

from . import ENGINE_ROOT
from . import predictions as P

#: Outcomes after which an instance is run again on resume: the harness, not
#: the prediction, failed (`runner._RETRYABLE_OUTCOMES` minus `timeout`, which
#: is a verdict on the test).
RETRY_OUTCOMES = frozenset({"harness_error", "scenario_not_found"})
ADAPTER_PREFIX = "predictions"
#: Raw rows of the instances without a prediction (`generation_failure_row`).
NO_PREDICTION_FILE = "no-prediction.jsonl"
#: Console lines of the engine that address its own command line, not
#: req2test's: the runner's advice to re-execute with `--adapter replay`
#: (`runner._repro_check`), which req2test has no option for.
ENGINE_ADVICE = ("--adapter replay",)


class _LineFilter:
    """A text stream that drops whole lines containing any of `needles`.

    Partial lines are held until their newline (or a flush), so a line
    written in pieces is judged whole.  Everything else is delegated to the
    wrapped stream.
    """

    def __init__(self, stream, needles):
        self._stream = stream
        self._needles = tuple(needles)
        self._pending = ""
        self._lock = threading.Lock()

    def _keep(self, line: str) -> bool:
        return not any(n in line for n in self._needles)

    def write(self, text: str) -> int:
        with self._lock:
            self._pending += text
            *lines, self._pending = self._pending.split("\n")
            kept = "".join(line + "\n" for line in lines if self._keep(line))
            if kept:
                self._stream.write(kept)
        return len(text)

    def flush(self) -> None:
        with self._lock:
            # A held piece of a dropped line waits for its newline.
            if self._pending and self._keep(self._pending):
                self._stream.write(self._pending)
                self._pending = ""
            self._stream.flush()

    def __getattr__(self, name):
        return getattr(self._stream, name)


@contextmanager
def engine_advice_filtered():
    """Drop `ENGINE_ADVICE` lines from this process's stdout (and from the
    forked workers', which inherit `sys.stdout`) while the engine runs."""
    previous = sys.stdout
    sys.stdout = _LineFilter(previous, ENGINE_ADVICE)
    try:
        yield
    finally:
        try:
            sys.stdout.flush()
        finally:
            sys.stdout = previous


def ensure_engine_path() -> None:
    root = str(ENGINE_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


# ------------------------------------------------------- engine bindings
class _Capture:
    """An engine CLI component that registers the consumer verbs and then
    replaces one verb's handler with a recorder of its parsed namespace."""

    def __init__(self, verb: str):
        from r2t.bench import cli as bench_cli
        self._bench = bench_cli
        self.PERSONA = bench_cli.PERSONA
        self.verb = verb
        self.args = None

    def register(self, verbs, request) -> None:
        self._bench.register(verbs, request)
        table = verbs._table.choices        # the argparse subcommand table
        table[self.verb].set_defaults(func=self._capture)

    def _capture(self, args) -> int:
        self.args = args
        return 0


def engine_namespace(argv: list) -> argparse.Namespace:
    """The namespace `r2t <argv>` would hand its verb, with every post-parse
    binding applied (Docker authority, `--worker`, data defaults)."""
    ensure_engine_path()
    from r2t.bench import cli as bench_cli
    verb = next(token for token in argv
                if not token.startswith("-") and token in
                ("run", "results", "worker", "mutation-run"))
    capture = _Capture(verb)
    bench_cli.dispatch(list(argv), (capture,), description="req2test")
    if capture.args is None:
        raise RuntimeError(f"engine parser did not reach {verb!r}")
    return capture.args


def bind_environment(env) -> None:
    """Point this process's engine at the environment: its data root
    (`R2T_DATA_ROOT`, as `req2test.env` runs the engine) and its Docker
    authority."""
    for key, value in env.engine_env().items():
        if key in ("R2T_DATA_ROOT",):
            os.environ[key] = value
    ensure_engine_path()
    from r2t.core.docker_cli import configure
    configure(authority_path=str(env.authority_path))


def worker_spec_paths(env) -> list:
    return [Path(p) for p in env.worker_specs]


def worker_harness(args):
    """Authenticate the bound live worker and build its harness."""
    from r2t.bench import cli as C
    C._require_bound_live_worker(args)
    harness, _boundary, _man = C._harness(args)
    return harness


# --------------------------------------------------------------- adapter
def prediction_state(pred) -> str:
    """`missing`, `no_output`, `empty` or `ok`: only `ok` has test code."""
    return ("missing" if pred is None else
            "no_output" if pred.status == "no_output" else
            "empty" if not pred.files else "ok")


def generation_failure_row(iid: str, state: str, adapter_name: str) -> dict:
    """The execution row of an instance without a prediction (`state` is
    not `ok`), written without running it.

    It has the outcome fields the engine's row of an empty solution has
    (`runner.run_one` labels it `no_files_returned` whatever the scenario
    did; `runner._record`): no files produced, written or rejected, the
    adapter's `req2test_prediction` metadata, and the run stamp's adapter
    and harness version.  No infrastructure marker, so the scorer's ladder
    reads it as a generation failure, as it reads the engine's row.
    `executed: false` says that nothing ran.
    """
    ensure_engine_path()
    from r2t.bench.validate import HARNESS_VERSION
    return {"item_id": iid, "outcome": "no_files_returned", "n_files": 0,
            "produced_files": [], "written_files": [], "rejected_files": [],
            "index_errors": {}, "metadata": {"req2test_prediction": state},
            "adapter": adapter_name, "harness_version": HARNESS_VERSION,
            "executed": False}


class Stopped(BaseException):
    """Raised by the adapter for the next instance after a stop request.

    A BaseException, so the engine's per-instance guards (`except Exception`
    in `run_one` and `run_adapter`) let it through without writing a row:
    the instance is simply not run, and a resume runs it.
    """


def make_adapter(preds: dict, model: str, predictions_sha256: str,
                 cancel_event=None):
    """The engine adapter that serves submitted predictions by instance id.

    Once `cancel_event` is set it raises `Stopped` instead of answering.
    """
    ensure_engine_path()
    from r2t.bench.fixtures import Adapter

    def serve(task: dict) -> dict:
        if cancel_event is not None and cancel_event.is_set():
            raise Stopped(task["item_id"])
        pred = preds.get(task["item_id"])
        metadata = {"req2test_prediction": prediction_state(pred)}
        if gold_run:
            metadata["source"] = "gold"
        return {"files": P.to_engine(pred), "metadata": metadata}

    # Ground-truth predictions (`req2test validate`, `predictions.from_gt`)
    # are gold runs: the engine keeps gold's suite and wiring rules for them
    # (`runner.is_gold_run_adapter`), and their rows say `source: gold` for
    # the mutation stage.  A predictions file cannot set this.
    gold_run = bool(preds) and all(pred.ground_truth for pred in preds.values())
    config = {"predictions_sha256": predictions_sha256,
              "model_name_or_path": model}
    if gold_run:
        config["gold_run"] = True
    return Adapter(f"{ADAPTER_PREFIX}:{model}", serve, config)


# -------------------------------------------------------------- run rows
def _read_rows(path: Path) -> list:
    rows = []
    if path.is_file():
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    rows.append(json.loads(line))
    return rows


def final_rows(raw_dir: Path) -> dict:
    """`{item_id: row}`: the last final row per instance across raw files
    (the workers' and `NO_PREDICTION_FILE`), else its last retryable row."""
    best: dict = {}
    for path in [*sorted(raw_dir.glob("w*.jsonl")),
                 raw_dir / NO_PREDICTION_FILE]:
        for row in _read_rows(path):
            iid = row["item_id"]
            prior = best.get(iid)
            if prior is None or row.get("outcome") not in RETRY_OUTCOMES \
                    or prior.get("outcome") in RETRY_OUTCOMES:
                best[iid] = row
    return best


def _finished(raw_dir: Path) -> set:
    """The instances with a final (not retryable) row in `raw_dir`."""
    return {iid for iid, row in final_rows(raw_dir).items()
            if row.get("outcome") not in RETRY_OUTCOMES}


def pending(predictions: dict, ids: Iterable[str], run_dir) -> list:
    """The instances of `ids` that `run` would execute on workers: those
    with a prediction (`prediction_state` `ok`) and no final row yet in
    `run_dir`.  When there are none, `run` needs no environment."""
    done = _finished(Path(run_dir) / "exec" / "raw")
    return [iid for iid in ids if iid not in done
            and prediction_state(predictions.get(iid)) == "ok"]


def merge(raw_dir: Path, ids: list, out_path: Path) -> dict:
    rows = final_rows(raw_dir)
    tmp = out_path.with_name(out_path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        for iid in ids:
            if iid in rows:
                fh.write(json.dumps(rows[iid], sort_keys=True) + "\n")
    os.replace(tmp, out_path)
    return rows


def run(kit, env, predictions: dict, view: str, run_dir: Path,
        workers: Optional[int] = None, *, ids: Iterable[str],
        timeout: Optional[int] = None, log=print) -> Path:
    """Execute `predictions` for population `ids`; write `exec.jsonl`.

    `ids` is the evaluated population in order; an id without a prediction
    (`prediction_state` not `ok`) is not executed but gets a generation
    failure row (`generation_failure_row`).  `env` may be None when nothing
    is `pending`: the rows are then written and merged without a worker.
    Returns the path of `exec.jsonl`.
    """
    from .layout import kit_inputs
    kit_in = kit_inputs(kit)
    ids = list(ids)
    run_dir = Path(run_dir)
    exec_dir = run_dir / "exec"
    raw_dir = exec_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_path = run_dir / "exec.jsonl"
    P.write_normalized(predictions, ids, run_dir / "predictions.norm.jsonl")

    import multiprocessing
    models = sorted({p.model_name_or_path for p in predictions.values()})
    model = models[0] if len(models) == 1 else "+".join(models) or "none"
    digest = P.digest(predictions)
    # A fork-context event: a stop set in the coordinator reaches every
    # forked worker.
    cancel_event = multiprocessing.get_context("fork").Event()
    adapter = make_adapter(predictions, model, digest, cancel_event)

    done = _finished(raw_dir)
    states = {iid: prediction_state(predictions.get(iid)) for iid in ids}
    without = [iid for iid in ids if states[iid] != "ok"]
    unwritten = [iid for iid in without if iid not in done]
    if unwritten:
        with open(raw_dir / NO_PREDICTION_FILE, "a", encoding="utf-8") as fh:
            for iid in unwritten:
                fh.write(json.dumps(generation_failure_row(
                    iid, states[iid], adapter.name), sort_keys=True) + "\n")
    to_run = [iid for iid in ids if iid not in done and states[iid] == "ok"]
    k = 0
    if to_run:
        bind_environment(env)
        specs = worker_spec_paths(env)
        k = max(1, min(workers or len(specs), len(specs), len(to_run)))
    log(f"execute: {len(ids)} instances, "
        f"{len(ids) - len(to_run) - len(without)} already done, "
        f"{len(to_run)} to run" + (f" on {k} worker(s)" if k else ""))
    if without:
        log(f"execute: {len(without)} instances without a prediction: "
            f"generation_failure")
    timeout = int(timeout or kit_in.timeout)
    # Every worker runs in its own forked process (an execution spends much
    # of its time in pure-Python substrate checks, which threads of one
    # interpreter would serialize) and builds its namespace and harness
    # there.
    bind_lock = threading.Lock()

    def bind(index: int, mine: list):
        with bind_lock:      # argument parsing and Docker binding are global
            return _bind(index, mine)

    def _bind(index: int, mine: list):
        args = engine_namespace([
            *env.global_args(index),
            "run", "--adapter", "gold",
            "--release", str(env.release_items),
            "--profile", str(env.profile),
            "--coverage", "--timeout", str(timeout),
            "--repro-check", "0", "--retry-failed",
            "--out", str(raw_dir / f"w{index}.jsonl")])
        args.adapter = adapter.name
        args.item = list(mine)
        return args, worker_harness(args)

    bound = {index: to_run[index::k] for index in range(k)
             if to_run[index::k]}

    def one_worker(job: dict) -> dict:
        from r2t.bench.mutation_run import MutationCancelled
        from r2t.bench.runner import run_adapter
        args, harness = bind(job["worker"], bound[job["worker"]])
        try:
            info = run_adapter(harness, args, args.artifacts, adapter=adapter)
        except Stopped:
            # The engine's type for a cooperative stop, so `execute_jobs`
            # reports the pool as cancelled rather than failed.
            raise MutationCancelled(
                f"execute: worker {job['worker']} stopped before its next "
                f"instance") from None
        return {"worker": job["worker"],
                "n": info.get("n"), "seconds": info.get("seconds"),
                "outcomes": dict(info.get("outcomes") or {})}

    if bound:
        from r2t.bench import mutation_run as MR
        from r2t.bench import test_quality as TQ
        try:
            with engine_advice_filtered(), \
                    MR.coordinator_cancellation(cancel_event):
                results = TQ.execute_jobs(
                    [{"side": "execute", "worker": i} for i in sorted(bound)],
                    one_worker, cancel_event=cancel_event,
                    processes=len(bound) > 1)
        except TQ.TestQualityCancelled as exc:
            raise RuntimeError(
                "execute: stopped by SIGINT or SIGTERM; the rows already "
                "written are kept, and rerunning the same command resumes "
                "the rest") from exc
        except TQ.TestQualityRefused as exc:
            raise RuntimeError(f"execute: {exc}") from exc
        for result in results:
            log(f"execute: worker {result['worker']}: {result.get('n')} "
                f"instance(s), outcomes {result.get('outcomes')}")
    rows = merge(raw_dir, ids, out_path)
    missing = [iid for iid in ids if iid not in rows]
    if missing:
        raise RuntimeError(f"execute: {len(missing)} instance(s) have no row, "
                           f"e.g. {missing[:3]}")
    (exec_dir / "identity.json").write_text(json.dumps({
        "predictions_sha256": digest, "model_name_or_path": model,
        "view": view, "n": len(ids), "timeout_seconds": timeout,
        "exec_sha256": sha256_file(out_path)}, indent=1) + "\n",
        encoding="utf-8")
    return out_path


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()
