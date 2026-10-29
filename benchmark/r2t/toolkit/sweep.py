"""S6 — the round-trip sweep, K workers wide and resumable by construction.

`validate.validate_all` is the serial sweep: one harness, one workspace, one
item at a time.  That is the right shape for a corpus whose scenarios take
thirty seconds each, and the wrong one for 239 items × 6 executions against a
library whose scenarios take milliseconds — there the wall is 1,434 container
round trips, not the work inside any of them.

What this module adds is not a thread pool.  It is the three pieces of
arithmetic that make a parallel sweep something a reader can trust:

* **one worker per thread, never two threads per workspace.**  The 29%
  outcome disagreement `r2t/bench/worker.py` exists to prevent came from two
  executors sharing one workspace 76 seconds apart, and a sweep that hands
  the same `(workspace, container)` pair to two threads reproduces it
  exactly.  So a worker is CHECKED OUT for the length of an item and every
  row records which one produced it.
* **an append-only checkpoint keyed by (item_id, harness_version).**  An
  interrupted sweep must resume, or a corpus this size is never re-run at
  all; a sweep resumed across a harness change must NOT resume, because
  those verdicts came from a different judge.  `validate_all` already makes
  that rule — it was written after a sweep was silently poisoned by a
  container invalidation that never ran — and this keeps it verbatim, adding
  only that the LAST row for an item wins, since an append-only file re-run
  with `resume=False` holds both.
* **a fuse.**  One item that raises is an exclusion with a name
  (`sweep_error`).  Five in a row is Docker being gone, and carrying on
  would publish 239 exclusions that describe the host rather than the
  corpus.

`run_one(worker, closure) -> row` is a parameter rather than a call to
`validate.validate_item`, for the same reason `validate` takes its harness as
an argument: the sweep's arithmetic is checkable without a container, and the
one live caller (`scripts/sweep_round_trip.py`) supplies the real function.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
from typing import Callable, Iterable, Optional

from ..bench.validate import (CLOSURE_INCOMPLETE, CONTAINER_ERROR, EMPTY_CLOSURE,
                       FAIL_LEG_ERROR, FLAKY, HARNESS_VERSION, PASS_LEG_ERROR,
                       PASSES_WITHOUT_GLUE, PASSES_WITHOUT_GLUE as _PWG,
                       TIMEOUT)

#: The row an item gets when `run_one` RAISES.  Not one of `validate`'s
#: reasons, and deliberately so: those describe what the two legs said about
#: an item, and this one says the sweep never got an answer.  Folding it into
#: `fail_leg_harness_error` would put a coordinator crash into the number
#: SPEC §9.2 reads as the extractor's error rate.
SWEEP_ERROR = "sweep_error"

#: `scenario_not_found` is spelled in `validate_item` rather than named there;
#: it is the one verdict that precedes both legs, so it heads the order below.
SCENARIO_NOT_FOUND = "scenario_not_found"

#: Every class a row can carry, in the order `validate_item` TESTS them: the
#: pre-leg refusal, then the fail leg's five, then the pass leg's four, then
#: this module's own.  Published with its zeros — "no item was excluded as
#: `passes_without_glue`" is a finding about the boundary, and a taxonomy
#: that prints only its non-empty classes cannot say it.
TAXONOMY: tuple[str, ...] = (
    SCENARIO_NOT_FOUND, FLAKY, PASSES_WITHOUT_GLUE, CONTAINER_ERROR,
    FAIL_LEG_ERROR, TIMEOUT, EMPTY_CLOSURE, PASS_LEG_ERROR, CLOSURE_INCOMPLETE,
    SWEEP_ERROR)

ADMITTED = "admitted"


class SweepRefused(RuntimeError):
    """The fuse, or a shape the sweep must not paper over."""


# --------------------------------------------------------------- checkpoint

def read_rows(path: str) -> list[dict]:
    """Every row in an append-only checkpoint, in file order."""
    out: list[dict] = []
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SweepRefused(
                    f"REFUSED: {path}:{lineno} is not JSON ({exc}). A "
                    f"half-written checkpoint line is a verdict nobody can "
                    f"read; delete the line or the file, but do not resume "
                    f"over it.") from exc
    return out


def resumable(rows: Iterable[dict],
              harness_version: int = HARNESS_VERSION) -> tuple[dict, int]:
    """`({item_id: row}, n_stale)` — what a resume may trust, and what it drops.

    A row produced by another harness version is DROPPED rather than kept:
    the constant moves only when a change could alter a verdict, so keeping
    one would mean publishing two judges' answers in one exclusion table.
    The last row for an item wins, because the file is append-only and a
    re-run with `resume=False` leaves both.
    """
    keep: dict[str, dict] = {}
    stale = 0
    for row in rows:
        if row.get("harness_version") != harness_version:
            stale += 1
            continue
        keep[row["item_id"]] = row
    return keep, stale


class Checkpoint:
    """One append per item, flushed and fsync'd, safe across threads.

    Flushed because the value of a checkpoint is entirely in what survives
    the interruption; fsync'd for the same reason one level down; and behind
    a lock because two threads appending to one file descriptor is the only
    way this module could ever produce a line that is not a row.
    """

    def __init__(self, path: str):
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.Lock()
        self._fh = open(path, "a", encoding="utf-8")

    def append(self, row: dict) -> None:
        line = json.dumps(row, sort_keys=True) + "\n"
        with self._lock:
            self._fh.write(line)
            self._fh.flush()
            os.fsync(self._fh.fileno())

    def close(self) -> None:
        with self._lock:
            self._fh.close()

    def __enter__(self) -> "Checkpoint":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# ------------------------------------------------------------------- sweep

def sweep(workers: list, run_one: Callable[[object, dict], dict],
          closures: list[dict], checkpoint: Checkpoint, *,
          progress_every: int = 25, abort_after: int = 5,
          log: Callable[[str], None] = print) -> dict:
    """Run every closure once, on K workers, appending a row per item.

    `workers` is whatever `run_one` needs — a harness, a `(harness, spec)`
    pair, an integer in a test.  This module never looks inside one; it only
    guarantees that no two threads hold the same element at the same time.

    Returns the tally.  Raises `SweepRefused` when the fuse trips, AFTER the
    rows already produced are on disk — an aborted sweep that also lost its
    checkpoint would have to start from zero, which is the thing the
    checkpoint exists to prevent.
    """
    if not workers:
        raise SweepRefused("REFUSED: a sweep with no workers is not a sweep.")
    todo: "queue.Queue" = queue.Queue()
    for cl in closures:
        todo.put(cl)
    n = len(closures)
    counts: dict[str, int] = {}
    tally_lock = threading.Lock()
    stop = threading.Event()
    consecutive = 0
    started = time.time()
    done = 0
    fatal: list[str] = []

    def record(row: dict) -> None:
        nonlocal consecutive, done
        checkpoint.append(row)
        key = ADMITTED if row.get("admitted") else (row.get("reason")
                                                    or "unknown")
        with tally_lock:
            counts[key] = counts.get(key, 0) + 1
            done += 1
            if key == SWEEP_ERROR:
                consecutive += 1
                if abort_after and consecutive >= abort_after:
                    fatal.append(
                        f"{consecutive} consecutive items raised; the last "
                        f"was {row['item_id']}: {row.get('error')}")
                    stop.set()
            else:
                consecutive = 0
            if done % progress_every == 0 or done == n:
                el = time.time() - started
                log(f"[{done}/{n}] {el / 60:.1f} min, {el / done:.1f}s/item "
                    f":: " + ", ".join(f"{k}={counts[k]}"
                                       for k in sorted(counts)))

    def worker_loop(index: int, worker: object) -> None:
        while not stop.is_set():
            try:
                cl = todo.get_nowait()
            except queue.Empty:
                return
            try:
                row = run_one(worker, cl)
            except Exception as exc:                          # noqa: BLE001
                # An item that raised is an EXCLUSION with a name, not a lost
                # sweep and not a repaired item: refuse-don't-repair applies
                # to the coordinator too.
                row = {"item_id": cl["item_id"], "admitted": False,
                       "reason": SWEEP_ERROR,
                       "harness_version": HARNESS_VERSION,
                       "error": f"{type(exc).__name__}: {exc}"[:600]}
            row.setdefault("item_id", cl["item_id"])
            row["worker_index"] = index
            record(row)

    threads = [threading.Thread(target=worker_loop, args=(i, w),
                               name=f"sweep-{i}", daemon=True)
               for i, w in enumerate(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if fatal:
        raise SweepRefused(
            f"REFUSED: the sweep stopped after {done} of {n} items — "
            f"{fatal[0]}. That is the host, not the corpus: publishing the "
            f"remaining items as exclusions would describe this machine. The "
            f"checkpoint at {checkpoint.path} holds what was measured; fix "
            f"the workers and resume.")
    return {"n": n, "counts": counts,
            "seconds": round(time.time() - started, 1)}


# ---------------------------------------------------------------- taxonomy

def taxonomy(rows: Iterable[dict]) -> dict:
    """`{class: count}` over every class, zeros included, in TAXONOMY order.

    `admitted` first because it is the one class that is not an exclusion.
    A reason this module has never heard of is appended rather than dropped —
    a new exclusion class must show up in the published table on the day it
    is invented, not on the day somebody remembers to list it here.
    """
    rows = list(rows)
    seen: dict[str, int] = {}
    for row in rows:
        key = ADMITTED if row.get("admitted") else (row.get("reason")
                                                    or "unknown")
        seen[key] = seen.get(key, 0) + 1
    out = {ADMITTED: seen.pop(ADMITTED, 0)}
    for name in TAXONOMY:
        out[name] = seen.pop(name, 0)
    for name in sorted(seen):
        out[name] = seen[name]
    return out


def summarise(rows: Iterable[dict]) -> dict:
    rows = list(rows)
    counts = taxonomy(rows)
    admitted = counts[ADMITTED]
    seconds = [r.get("seconds") or 0.0 for r in rows]
    return {
        "n": len(rows),
        "admitted": admitted,
        "excluded": len(rows) - admitted,
        "admitted_rate": (round(admitted / len(rows), 4) if rows else None),
        "taxonomy": counts,
        "wall_seconds_recorded": round(sum(seconds), 1),
        "harness_version": HARNESS_VERSION,
    }


def outlines_with_example_results(rows: Iterable[dict]) -> list[str]:
    """Admitted items whose pass leg reports a verdict PER Examples row.

    The S6 gate wants at least one, and it wants it read off the published
    validation records rather than off the corpus: `example_results` appears
    only when the fold matched more than one record, so an outline that
    silently scored on a single row would be invisible in every other count.
    """
    out = []
    for row in rows:
        if not row.get("admitted"):
            continue
        legs = row.get("pass_leg") or []
        if legs and legs[0].get("example_results"):
            out.append(row["item_id"])
    return sorted(out)


# ------------------------------------------------------------------ selftest

def selftest() -> int:                                            # noqa: C901
    import shutil
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    check("the fail-leg reason names come from validate, not from a copy",
          PASSES_WITHOUT_GLUE is _PWG and FLAKY in TAXONOMY
          and CLOSURE_INCOMPLETE in TAXONOMY)

    tmp = tempfile.mkdtemp(prefix="r2t_sweep_")
    try:
        # ---- the checkpoint, and what a resume may trust.
        path = os.path.join(tmp, "validation.jsonl")
        with Checkpoint(path) as cp:
            cp.append({"item_id": "a", "admitted": True,
                       "harness_version": HARNESS_VERSION})
            cp.append({"item_id": "b", "admitted": False, "reason": FLAKY,
                       "harness_version": HARNESS_VERSION - 1})
            cp.append({"item_id": "a", "admitted": False, "reason": TIMEOUT,
                       "harness_version": HARNESS_VERSION})
        rows = read_rows(path)
        keep, stale = resumable(rows)
        check("a resume trusts only rows this harness version produced",
              set(keep) == {"a"} and stale == 1, f"{sorted(keep)} stale={stale}")
        check("...and the LAST row for an item wins, because the file appends",
              keep["a"]["reason"] == TIMEOUT, str(keep["a"]))
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("{not json\n")
        try:
            read_rows(path)
            check("a truncated checkpoint line refuses", False, "no exception")
        except SweepRefused as exc:
            check("a truncated checkpoint line refuses rather than resuming "
                  "over a verdict nobody can read",
                  str(exc).startswith("REFUSED:"), str(exc)[:120])

        # ---- concurrent appends produce whole lines, never interleaved bytes.
        conc = os.path.join(tmp, "concurrent.jsonl")
        with Checkpoint(conc) as cp:
            def spam(t):
                for i in range(40):
                    cp.append({"item_id": f"{t}-{i}", "admitted": True,
                               "pad": "x" * 500,
                               "harness_version": HARNESS_VERSION})
            ts = [threading.Thread(target=spam, args=(t,)) for t in range(8)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
        wrote = read_rows(conc)
        check("8 threads appending 40 rows each produce 320 whole JSON lines",
              len(wrote) == 320 and len({r["item_id"] for r in wrote}) == 320,
              str(len(wrote)))

        # ---- the sweep: every item once, no worker in two threads at once.
        closures = [{"item_id": f"i{i:03d}"} for i in range(60)]
        held = {i: 0 for i in range(6)}
        overlaps: list[int] = []
        held_lock = threading.Lock()

        def run_one(worker, cl):
            with held_lock:
                held[worker] += 1
                if held[worker] > 1:
                    overlaps.append(worker)
            time.sleep(0.002)
            with held_lock:
                held[worker] -= 1
            return {"item_id": cl["item_id"], "admitted": True,
                    "harness_version": HARNESS_VERSION, "seconds": 0.5}

        out = os.path.join(tmp, "sweep.jsonl")
        with Checkpoint(out) as cp:
            info = sweep(list(range(6)), run_one, closures, cp,
                         progress_every=1000, log=lambda _m: None)
        rows = read_rows(out)
        check("every item produced exactly one row",
              len(rows) == 60
              and sorted(r["item_id"] for r in rows)
              == sorted(c["item_id"] for c in closures), str(len(rows)))
        check("no two threads ever held the same worker at once -- the 29% "
              "disagreement that shared workspaces produce cannot happen here",
              not overlaps, str(overlaps[:3]))
        check("every worker was used, and every row says which one",
              {r["worker_index"] for r in rows} == set(range(6)),
              str(sorted({r["worker_index"] for r in rows})))
        check("the tally counts what the checkpoint holds",
              info["counts"] == {ADMITTED: 60}, str(info["counts"]))

        # ---- an item that raises is one exclusion, not a lost sweep.
        def sometimes_raises(worker, cl):
            if cl["item_id"] == "i007":
                raise RuntimeError("boom")
            return {"item_id": cl["item_id"], "admitted": True,
                    "harness_version": HARNESS_VERSION}

        out2 = os.path.join(tmp, "sweep2.jsonl")
        with Checkpoint(out2) as cp:
            info2 = sweep(list(range(4)), sometimes_raises, closures, cp,
                          progress_every=1000, log=lambda _m: None)
        rows2 = read_rows(out2)
        bad = [r for r in rows2 if r["item_id"] == "i007"]
        check("one raising item becomes one named exclusion and the other 59 "
              "still measure",
              len(rows2) == 60 and info2["counts"][ADMITTED] == 59
              and bad and bad[0]["reason"] == SWEEP_ERROR
              and "boom" in bad[0]["error"], str(info2["counts"]))

        # ---- the fuse: five in a row is the host, and it says so.
        out3 = os.path.join(tmp, "sweep3.jsonl")
        try:
            with Checkpoint(out3) as cp:
                sweep([0], lambda w, c: (_ for _ in ()).throw(
                    RuntimeError("docker gone")), closures, cp,
                    progress_every=1000, abort_after=5, log=lambda _m: None)
            check("a sweep whose every item raises refuses", False, "returned")
        except SweepRefused as exc:
            rows3 = read_rows(out3)
            check("five consecutive failures trip the fuse instead of "
                  "publishing 60 exclusions about the host",
                  str(exc).startswith("REFUSED:") and len(rows3) == 5,
                  f"{len(rows3)} rows :: {str(exc)[:120]}")
            check("...and the rows measured before it are still on disk",
                  all(r["reason"] == SWEEP_ERROR for r in rows3))
        check("a sweep with no workers refuses rather than hanging",
              _refused(lambda: sweep([], run_one, closures,
                                     Checkpoint(os.path.join(tmp, "x.jsonl")),
                                     log=lambda _m: None)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # ---- the published taxonomy.
    fixture = ([{"item_id": f"a{i}", "admitted": True} for i in range(3)]
               + [{"item_id": "b", "admitted": False, "reason": FLAKY},
                  {"item_id": "c", "admitted": False, "reason": FLAKY},
                  {"item_id": "d", "admitted": False,
                   "reason": "a_class_invented_tomorrow"}])
    tax = taxonomy(fixture)
    check("the taxonomy publishes every class, zeros included",
          set(TAXONOMY) <= set(tax) and tax[PASSES_WITHOUT_GLUE] == 0
          and tax[FLAKY] == 2, json.dumps(tax))
    check("...admitted heads it, and the counts sum to the rows",
          list(tax)[0] == ADMITTED and sum(tax.values()) == len(fixture),
          json.dumps(tax))
    check("a reason nobody listed here is still counted, not dropped",
          tax.get("a_class_invented_tomorrow") == 1, json.dumps(tax))
    check("...and it sorts after the known classes, so the table's shape is "
          "stable while its tail grows",
          list(tax).index("a_class_invented_tomorrow") == len(TAXONOMY) + 1,
          str(list(tax)))
    summary = summarise(fixture)
    check("the summary's rate is admitted over the rows measured",
          summary["admitted"] == 3 and summary["n"] == 6
          and summary["admitted_rate"] == 0.5, json.dumps(summary))

    outlines = outlines_with_example_results([
        {"item_id": "plain", "admitted": True,
         "pass_leg": [{"outcome": "passed"}]},
        {"item_id": "outline", "admitted": True,
         "pass_leg": [{"outcome": "passed",
                       "example_results": ["passed", "passed"]}]},
        {"item_id": "excluded", "admitted": False,
         "pass_leg": [{"example_results": ["passed"]}]}])
    check("an outline is recognised by its pass leg's per-row breakdown, and "
          "an excluded item is never one of them",
          outlines == ["outline"], str(outlines))

    print("\n" + ("ALL PASS (sweep)" if ok else "FAILURES (sweep)"))
    return 0 if ok else 1


def _refused(fn) -> bool:
    try:
        fn()
        return False
    except SweepRefused:
        return True


if __name__ == "__main__":
    raise SystemExit(selftest())
