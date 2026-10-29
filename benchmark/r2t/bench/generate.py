"""S6a — generation, decoupled from execution so it can run in parallel.

A sweep is two phases with opposite constraints.  GENERATION is pure
network I/O against the system under test: no shared state, embarrassingly
parallel.  EXECUTION is the opposite — one bind-mounted workspace, one
MySQL schema, one compiled Symfony container — so it is strictly serial,
and the red-team's parallelism analysis says it cannot be made otherwise
without provisioning K databases.

Running them interleaved, as `run` does, costs the serial execution time
on *every* generation.  Measured on this benchmark that is 95% waste for a
single-shot model (145 s generate / 19 s execute) and 97% for an agent
(718 s / 19 s): a 100-item agent sweep takes 20 hours serially and about
three with generation fanned out.

The cache this writes is also the answer to a second problem.  A sweep
costs hours and, for an agent, real money, so a harness fix or a new
metric must not force regeneration.  `run --adapter replay --replay
<cache>` re-executes exactly the same bytes the system produced, which is
how the same generation gets scored under a metric invented later.
"""
from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from ..data.release import task_view


def _read_rows(path: str) -> tuple[list[dict], int]:
    """Usable rows, and the count of lines that were not.

    A crash or a Ctrl-C mid-append leaves a truncated final line.  Refusing
    to load the whole cache because of it converts a recoverable
    interruption into the loss of every row written before it — hours of
    paid generation thrown away by one half-written byte sequence.  A
    skipped row simply looks not-done and is regenerated, which is the
    correct recovery.  A line that parses but is not a row (no `item_id`)
    is unusable for the same reason and counted the same way.
    """
    rows: list[dict] = []
    bad = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                row = None
            if isinstance(row, dict) and "item_id" in row:
                rows.append(row)
            else:
                bad += 1
    return rows, bad


def _load(path: str) -> list[dict]:
    rows, _bad = _read_rows(path)
    return rows


def load_cache(path: str) -> dict[str, dict]:
    """item_id -> the row generation recorded for it (last wins)."""
    if not os.path.isfile(path):
        return {}
    rows, bad = _read_rows(path)
    if bad:
        print(f"  NOTE: {bad} unparseable line(s) in {path} skipped; those "
              f"items look not-done and will be regenerated.", flush=True)
    return {r["item_id"]: r for r in rows}


def _resume(cached: dict[str, dict], stamp: dict, retry_failed: bool,
            out_path: str) -> tuple[set[str], set[str]]:
    """Which cached items count as done — refusing to mix configurations.

    Resume used to key on `item_id` alone, so a cache could silently hold
    two conditions, two models or two budgets and be neither.  The rule is
    `runner._resume_set`'s outside campaign mode: a stamp field is compared
    only when it is PRESENT in the row, because an absent field is
    unverifiable rather than wrong.
    """
    done: set[str] = set()
    retryable: set[str] = set()
    conflicts: list[str] = []
    for item_id, row in cached.items():
        if "visibility" in row or "visibility" in stamp:
            if row.get("visibility") != stamp.get("visibility"):
                raise SystemExit("REFUSED: source-view identity differs or is missing; use a fresh cache")
        mismatched = sorted(k for k, v in stamp.items()
                            if k in row and row[k] != v)
        if mismatched:
            conflicts.append(f"{item_id}: {mismatched}")
            continue
        # Supplied view evidence is checked even when this row will be retried.
        if row.get("visibility") is not None:
            from ..core.source_view import verify_recorded_view, ViewRefused
            try:
                verify_recorded_view(row)
            except ViewRefused as exc:
                raise SystemExit(f"REFUSED: generation source-view evidence: {exc}") from exc
        meta = row.get("metadata") or {}
        # INFRASTRUCTURE failures are not answers: `adapter_error` is an
        # exception inside the adapter (usually transport), while a
        # `driver_error` with no candidate is an agent driver that failed
        # before producing an answer.  Caching those as final is how a
        # transient outage becomes permanent, so `retry_failed` regenerates
        # them.  A driver marker WITH files is already a draw and stays cached;
        # re-rolling it would be result-shopping.  `parse_error` and an empty
        # file list without an infrastructure marker are RESULTS too, so no
        # flag retries them.
        # A third infrastructure shape, found the expensive way: the agent's
        # CONVERSATION was killed by the transport (the driver records the
        # exception in `agent_stats.run_errors` and exits 0), and the row
        # reads "the system wrote nothing".  Measured 2026-08-01: an upstream
        # that demands `reasoning_content` passback 400'd 44 conversations
        # mid-run and every one cached as a zero-file RESULT.  A run error
        # with files written is a partial answer and stays; a run error with
        # NOTHING written is the outage, not the system.
        run_errors = (meta.get("agent_stats") or {}).get("run_errors")
        if retry_failed and (
                meta.get("adapter_error")
                or (meta.get("driver_error")
                    and not row.get("produced_files"))
                or (run_errors and not row.get("produced_files"))):
            retryable.add(item_id)
            continue
        done.add(item_id)
    if conflicts:
        raise SystemExit(
            f"REFUSED: {out_path} holds {len(conflicts)} row(s) produced under "
            f"a different generation configuration, e.g. {conflicts[0]}. "
            f"Appending would produce a cache that is neither generation. "
            f"Use a fresh --out path.")
    return done, retryable


def generate_all(adapter, items: list[dict], out_path: str,
                 workers: int = 8, stamp: Optional[dict] = None,
                 prepare=None, *, retry_failed: bool = False) -> dict:
    """Generate for every item not already cached, `workers` at a time.

    `prepare` is called ONCE before the pool starts, not per item.  In the
    interleaved runner the workspace is swept before every generation so a
    repo-reading agent cannot see the previous item's installed closure;
    here nothing is ever installed, so one sweep establishes the same
    property for the whole phase — and does it more consistently, since
    every agent then reads a byte-identical tree.

    `retry_failed` regenerates rows whose metadata records an
    infrastructure failure only; see `_resume` for why results are exempt.
    """
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    done, retryable = _resume(load_cache(out_path), stamp or {}, retry_failed,
                              out_path)
    pending = [i for i in items if i["item_id"] not in done]
    # `retried` counts what THIS call regenerates, not every failed row in the
    # cache: under --limit the two differ and only the former is honest.
    retried = sum(1 for i in pending if i["item_id"] in retryable)
    if not pending:
        return {"generated": 0, "cached": len(done), "retried": retried,
                "seconds": 0.0}

    if prepare is not None:
        prepare()

    lock = threading.Lock()
    counts: dict[str, int] = {}
    started = time.time()
    n_done = 0

    def one(item: dict) -> dict:
        t0 = time.time()
        try:
            produced = adapter(task_view(item))
        except Exception as e:                            # noqa: BLE001
            produced = {"files": [],
                        "metadata": {"adapter_error": f"{type(e).__name__}: {e}"}}
        row = {
            "item_id": item["item_id"],
            "produced_files": produced.get("files") or [],
            "metadata": produced.get("metadata") or {},
            "generation_seconds": round(time.time() - t0, 2),
        }
        row.update(stamp or {})
        return row

    # A crash mid-append leaves a partial line with no newline; appending to it
    # would glue the next row onto the wreckage and lose that row too.  One
    # newline turns the damage back into a single line `_read_rows` can skip.
    if os.path.isfile(out_path) and os.path.getsize(out_path):
        with open(out_path, "rb+") as raw:
            raw.seek(-1, os.SEEK_END)
            if raw.read(1) != b"\n":
                raw.write(b"\n")

    with open(out_path, "a", encoding="utf-8") as fh, \
            ThreadPoolExecutor(max_workers=max(1, workers)) as pool:

        def record(row: dict) -> None:
            nonlocal n_done
            key = ("adapter_error" if row["metadata"].get("adapter_error")
                   else "driver_error" if row["metadata"].get("driver_error")
                   else "parse_error" if row["metadata"].get("parse_error")
                   else "no_files" if not row["produced_files"] else "ok")
            with lock:
                # One writer at a time: threads finish in arbitrary order and a
                # half-written line would make the cache unparseable, which is
                # exactly the failure this file exists to prevent.
                fh.write(json.dumps(row, sort_keys=True) + "\n")
                fh.flush()
                counts[key] = counts.get(key, 0) + 1
                n_done += 1
                el = time.time() - started
                print(f"[{n_done}/{len(pending)}] {row['item_id']} -> {key} "
                      f"({row['generation_seconds']:.0f}s, "
                      f"{el/n_done:.0f}s/item wall)", flush=True)

        futures = {pool.submit(one, it): it for it in pending}
        banked: set = set()
        try:
            for fut in as_completed(futures):
                record(fut.result())
                banked.add(fut)
        except KeyboardInterrupt:
            # Ctrl-C used to discard every result that had finished but was not
            # yet written — on an agent sweep, up to `workers` generations that
            # were already paid for — and then block in __exit__ waiting for
            # the whole queue to drain anyway.  Cancel what has not started,
            # bank what has already finished, and let the `with` join only the
            # calls still in flight: an agent subprocess cannot be killed
            # safely from here, but no COMPLETED result is lost and no NEW work
            # starts.  A row banked twice (interrupt inside `record`) is
            # harmless — `load_cache` is last-wins over identical content.
            pool.shutdown(wait=False, cancel_futures=True)
            in_flight = 0
            for fut in futures:
                if fut in banked or fut.cancelled():
                    continue
                if not fut.done():
                    in_flight += 1
                    continue
                try:
                    record(fut.result())
                except Exception:                         # noqa: BLE001
                    pass  # one unusable future must not cost us the others
            print(f"\ninterrupted: {n_done} result(s) banked in {out_path}; "
                  f"queued work cancelled, {in_flight} generation(s) still "
                  f"running are waited for and discarded. Re-run with the same "
                  f"--out to resume.", flush=True)
            raise

    return {"generated": len(pending), "cached": len(done), "retried": retried,
            "outcomes": counts, "seconds": round(time.time() - started, 1),
            "out": out_path, "workers": workers}


def selftest() -> int:
    import contextlib
    import io
    import tempfile
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    items = [{"item_id": f"p/f.feature:{i}", "task": "criterion_to_test",
              "provenance": {"file_path": "f.feature", "line": i},
              "requirement": {}, "criterion": {}, "bench_meta": {"x": 1}}
             for i in range(1, 21)]

    seen = []
    seen_lock = threading.Lock()

    def adapter(task):
        with seen_lock:
            seen.append(task["item_id"])
        return {"files": [{"file_path": "a.php", "code": "<?php"}],
                "metadata": {"ok": True}}

    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "gen.jsonl")
        prepared = []
        info = generate_all(adapter, items, out, workers=5,
                            stamp={"adapter": "t"}, prepare=lambda: prepared.append(1))
        rows = _load(out)
        check("every item generated exactly once", len(rows) == 20 and
              len({r["item_id"] for r in rows}) == 20, str(len(rows)))
        check("prepare runs once for the phase, not per item", prepared == [1],
              str(prepared))
        check("the stamp is on every row", all(r.get("adapter") == "t" for r in rows))
        check("concurrency actually happened", info["workers"] == 5)
        check("cache rows are individually parseable",
              all(isinstance(r["produced_files"], list) for r in rows))

        # resume: a second call must generate nothing and must not rewrite
        before = open(out, encoding="utf-8").read()
        info2 = generate_all(adapter, items, out, workers=5, stamp={"adapter": "t"})
        check("resume generates nothing", info2["generated"] == 0, str(info2))
        check("resume leaves the cache byte-identical",
              open(out, encoding="utf-8").read() == before)
        check("the adapter was called once per item, not once per call",
              len(seen) == 20, str(len(seen)))

        # a throwing adapter is recorded, never allowed to kill the phase
        out2 = os.path.join(d, "gen2.jsonl")

        def boom(task):
            raise RuntimeError("endpoint down")

        generate_all(boom, items[:3], out2, workers=3, stamp={})
        rows2 = _load(out2)
        check("an adapter that throws is recorded, not fatal",
              len(rows2) == 3 and all(r["metadata"].get("adapter_error")
                                      for r in rows2))

        # FIX 1: resume must key on the stamp, not on item_id alone.
        try:
            generate_all(adapter, items, out, workers=2,
                         stamp={"adapter": "u", "model": "other"})
            refusal = ""
        except SystemExit as e:
            refusal = str(e)
        check("a cache from another configuration is REFUSED, not appended to",
              "REFUSED" in refusal and "adapter" in refusal, refusal or "no exit")
        check("the refusal names an item and points at a fresh --out",
              "p/f.feature:" in refusal and "--out" in refusal, refusal)
        check("refusing does not touch the cache",
              open(out, encoding="utf-8").read() == before)
        # A field ABSENT from the row is unverifiable, not wrong -- refusing on
        # it would make every pre-stamp cache unusable.
        info3 = generate_all(adapter, items, out, workers=2,
                             stamp={"adapter": "t", "harness_version": "9"})
        check("a field the row does not carry is unverifiable, not a conflict",
              info3["generated"] == 0, str(info3))

        # FIX 2: infrastructure failures are retryable, results are not.
        info_keep = generate_all(adapter, items[:3], out2, workers=3, stamp={})
        check("adapter_error rows stay done without retry_failed",
              info_keep["generated"] == 0 and info_keep["retried"] == 0,
              str(info_keep))
        info_retry = generate_all(adapter, items[:3], out2, workers=3, stamp={},
                                  retry_failed=True)
        cache2 = load_cache(out2)
        check("retry_failed regenerates adapter_error rows",
              info_retry["generated"] == 3 and info_retry["retried"] == 3,
              str(info_retry))
        check("the retry appends and last-wins on read",
              len(_load(out2)) == 6 and len(cache2) == 3
              and not any(r["metadata"].get("adapter_error")
                          for r in cache2.values()),
              f"{len(_load(out2))} rows, {len(cache2)} items")
        info_again = generate_all(adapter, items[:3], out2, workers=3, stamp={},
                                  retry_failed=True)
        check("a retried item is retried exactly once, not every run",
              info_again["generated"] == 0 and info_again["retried"] == 0,
              str(info_again))

        out2b = os.path.join(d, "gen2b.jsonl")
        generate_all(boom, items[:3], out2b, workers=3, stamp={})
        info_lim = generate_all(adapter, items[:1], out2b, workers=1, stamp={},
                                retry_failed=True)
        check("retried counts this call's work, not every failure in the cache",
              info_lim["generated"] == 1 and info_lim["retried"] == 1,
              str(info_lim))

        out3 = os.path.join(d, "gen3.jsonl")

        def bad_result(task):
            return {"files": [], "metadata": {"parse_error": "no fenced block"}}

        generate_all(bad_result, items[:2], out3, workers=2, stamp={})
        info_shop = generate_all(adapter, items[:2], out3, workers=2, stamp={},
                                 retry_failed=True)
        check("parse_error/no-files rows are RESULTS and are never retried",
              info_shop["generated"] == 0 and info_shop["retried"] == 0,
              str(info_shop))

        # A driver timeout is retryable only before a candidate exists.  Both
        # the legacy marker-only timeout and the modern termination record are
        # observed cache shapes; neither earns a second draw after writing.
        out3a = os.path.join(d, "gen3a.jsonl")
        timeout_cache = [
            {"item_id": items[0]["item_id"],
             "produced_files": [{"file_path": "a.php", "code": "<?php"}],
             "metadata": {"driver_error": "timeout", "returncode": -1}},
            {"item_id": items[1]["item_id"],
             "produced_files": [{"file_path": "b.php", "code": "<?php"}],
             "metadata": {"driver_error": "timeout", "returncode": -1,
                          "termination": {"reason": "envelope_expired"}}},
            {"item_id": items[2]["item_id"], "produced_files": [],
             "metadata": {"driver_error": "transport unavailable",
                          "returncode": 1}},
        ]
        with open(out3a, "w", encoding="utf-8") as fh3a:
            for cached_row in timeout_cache:
                fh3a.write(json.dumps(cached_row, sort_keys=True) + "\n")
        driver_retries = []

        def recover_driver(task):
            driver_retries.append(task["item_id"])
            return {"files": [{"file_path": "recovered.php", "code": "<?php"}],
                    "metadata": {}}

        info_driver = generate_all(
            recover_driver, items[:3], out3a, workers=1, stamp={},
            retry_failed=True)
        driver_rows = _load(out3a)
        check("candidate-producing driver timeouts are cached, while the true "
              "pre-candidate driver failure is retried",
              info_driver["generated"] == 1
              and info_driver["cached"] == 2
              and info_driver["retried"] == 1
              and driver_retries == [items[2]["item_id"]], str(info_driver))
        check("neither observed candidate-producing timeout shape receives a "
              "second draw",
              sum(r["item_id"] == items[0]["item_id"] for r in driver_rows) == 1
              and sum(r["item_id"] == items[1]["item_id"]
                      for r in driver_rows) == 1
              and sum(r["item_id"] == items[2]["item_id"]
                      for r in driver_rows) == 2, str(driver_rows))

        # A transport-killed CONVERSATION (run_errors recorded by the driver,
        # nothing written) is infrastructure; the same errors WITH files is a
        # partial answer and stays.
        out3b = os.path.join(d, "gen3b.jsonl")

        def killed(task):
            return {"files": [], "metadata": {"agent_stats": {
                "run_errors": {"main": "RateLimitError: 400"}}}}

        def partial(task):
            return {"files": [{"file_path": "a.php", "code": "<?php"}],
                    "metadata": {"agent_stats": {
                        "run_errors": {"main": "RateLimitError: 400"}}}}

        generate_all(killed, items[:1], out3b, workers=1, stamp={})
        generate_all(partial, items[1:2], out3b, workers=1, stamp={})
        info_kill = generate_all(adapter, items[:2], out3b, workers=1, stamp={},
                                 retry_failed=True)
        check("a run-error row with NO files is retried as infrastructure",
              info_kill["retried"] == 1 and info_kill["generated"] == 1,
              str(info_kill))
        rows3b = _load(out3b)
        check("a run-error row WITH files is a partial answer and stays",
              sum(1 for r in rows3b if r["item_id"] == items[1]["item_id"]) == 1)

        # FIX 4: one truncated line must not make the cache unloadable.
        out4 = os.path.join(d, "gen4.jsonl")
        generate_all(adapter, items[:2], out4, workers=2, stamp={})
        with open(out4, "a", encoding="utf-8") as fh4:
            fh4.write('{"item_id": "p/f.feature:3", "produced_fi')
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            info_trunc = generate_all(adapter, items[:3], out4, workers=3,
                                      stamp={}, retry_failed=False)
        noise = buf.getvalue()
        check("a truncated line is skipped, not fatal, and warns once",
              noise.count("unparseable") == 1 and "gen4.jsonl" in noise,
              noise.strip()[:200])
        check("the item behind a truncated line is regenerated",
              info_trunc["generated"] == 1
              and set(load_cache(out4)) == {i["item_id"] for i in items[:3]},
              str(info_trunc))
        check("the regenerated row is not glued onto the wreckage",
              len(load_cache(out4)["p/f.feature:3"]["produced_files"]) == 1)

    print("\n" + ("ALL PASS (generate)" if ok else "FAILURES (generate)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
