"""aider's native counts, reconciled against the normalized stream.

The package docstring states the contract and the F5 findings behind it; this
module is the Aider instance of it and nothing more.  What it knows about
aider is exactly what the A1 battery verified at the 0.86.2 pin
(docs/AIDER_A1_VERIFICATION.md, F5):

* `message_send` in the analytics log is emitted once per MAIN-LOOP model
  call (`base_coder.calculate_and_show_tokens_and_cost` →
  `show_usage_report`), and never for the chat-history summarizer.  Counted
  by EXACT event name — `message_send_starting` and `message_send_exception`
  are different events about the same send and counting them would double a
  call the model made once.
* "Attempt to fix test errors?" appears in the chat log once per FAILING
  --auto-test run; a passing run leaves no native trace at all.
* "Applied edit to {path}" appears once per path per turn; the DISTINCT
  paths equal `Coder.aider_edited_files`, which is what the driver's
  normalized edit events are written from.

Every rule here refuses rather than repairs: a count that is absent, null or
mis-typed is a problem, because a manifest that cannot state its own numbers
is not an account of the run.
"""
from __future__ import annotations

import json
import os

#: This module reads Aider's native artifacts and no other system's.
AGENT = "aider"

#: The counts the manifest MUST carry, with the type each must be.  A bool is
#: refused where an int belongs — `isinstance(True, int)` is Python trivia,
#: not an event count.
_REQUIRED_COUNTS = {"llm_calls_main": int, "test_failures": int, "edits": int}


def _count_message_send(path: str) -> tuple:
    """`(count, problem)` — `message_send` events in one analytics log.

    The validator's own read of the native bytes, which is what makes the
    manifest's `llm_calls_main` a checkable claim rather than a self-report.
    An unreadable line is a problem, not a skip: the analytics log is a
    machine-written JSONL and a line that will not parse means the artifact
    is not what the manifest preserved it as.
    """
    count = 0
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    doc = json.loads(line)
                except ValueError:
                    return None, (f"analytics log line {number} is not JSON "
                                  "-- the native stream cannot be recounted")
                if isinstance(doc, dict) and doc.get("event") == "message_send":
                    count += 1
    except OSError as exc:
        return None, (f"analytics log could not be read: "
                      f"{type(exc).__name__}: {exc}")
    return count, None


def reconcile(directory: str, manifest: dict, events: list,
              by_role: dict) -> list:
    """Problems with this attempt's native/normalized agreement; `[]` if none.

    `events` are the parsed normalized events the validator read; `by_role` maps
    the manifest's declared roles to VERIFIED file names (existence and
    sha256 already checked by the caller — a file that failed those checks
    never reaches this function, and its absence from `by_role` is refused
    here as the native stream being incomplete).
    """
    problems = []
    counts = manifest.get("counts") or {}
    for key, want in _REQUIRED_COUNTS.items():
        value = counts.get(key)
        if not isinstance(value, want) or isinstance(value, bool):
            problems.append(
                f"the manifest's counts.{key} is {value!r}, not a count -- "
                "the native stream is incomplete")
    if problems:
        return problems

    # What the normalized stream actually holds.  The shapes are the driver's
    # side of the contract (`r2t/confined/aider_driver.py`): one MessageEvent per
    # litellm-callback record, one `autotest` ActionEvent per wrapper
    # invocation, one `file_edit` ActionEvent per distinct edited file.
    n_calls = sum(1 for event in events
                  if isinstance(event, dict)
                  and event.get("kind") == "MessageEvent"
                  and isinstance(event.get("llm_call"), dict))
    n_failed_tests = sum(1 for event in events
                         if isinstance(event, dict)
                         and event.get("tool_name") == "autotest"
                         and isinstance(event.get("exit_code"), int)
                         and not isinstance(event.get("exit_code"), bool)
                         and event.get("exit_code") != 0)
    n_edits = sum(1 for event in events
                  if isinstance(event, dict)
                  and event.get("tool_name") == "file_edit")

    # Rule 1, exact: the manifest against the native bytes it declares.
    analytics = by_role.get("analytics_log")
    if not analytics:
        problems.append(
            "the manifest declares no verified analytics_log, so its "
            "llm_calls_main cannot be recounted from native bytes")
    else:
        native, problem = _count_message_send(
            os.path.join(directory, analytics))
        if problem:
            problems.append(problem)
        elif native != counts["llm_calls_main"]:
            problems.append(
                f"the manifest declares {counts['llm_calls_main']} main-loop "
                f"llm calls but a recount of {analytics} finds {native} "
                "message_send events -- the manifest misstates its own "
                "native file")
    if not by_role.get("chat_log"):
        problems.append(
            "the manifest declares no verified chat_log -- the native "
            "stream is incomplete")

    # Rule 2, directional and F5-aware: every native main-loop call must be
    # inside the driver's accounting.  A FLOOR, not an equality — the
    # normalized stream also accounts the summarizer calls the native stream
    # cannot see (F5(ii)), so a surplus is expected on long runs and equality
    # would refuse correct ones.  A shortfall is the dropped-record failure
    # the whole seam exists to catch.
    if n_calls < counts["llm_calls_main"]:
        problems.append(
            f"the driver's normalized stream accounts {n_calls} llm call(s), "
            f"fewer than the {counts['llm_calls_main']} main-loop call(s) "
            "aider's own analytics recorded -- a native record was dropped")

    # Rules 3 and 4, exact: failed test runs and distinct edited files are
    # witnessed by both recorders (F5's table), so the two counts must agree
    # to the digit.
    if n_failed_tests != counts["test_failures"]:
        problems.append(
            f"the chat log records {counts['test_failures']} failing "
            f"auto-test run(s) and the normalized stream {n_failed_tests} -- "
            "the two recorders disagree")
    if n_edits != counts["edits"]:
        problems.append(
            f"the chat log names {counts['edits']} distinct edited file(s) "
            f"and the normalized stream {n_edits} -- the two recorders "
            "disagree")

    # A TERMINATED attempt is held to exactly these rules, unchanged.  The
    # temptation is to relax rules 3 and 4 for one — the envelope can expire
    # between aider printing "Applied edit to" (base_coder.py:2334) and
    # updating `aider_edited_files` (base_coder.py:1588), or between the
    # autotest wrapper appending its record and aider printing the gate — and
    # a slack of "one turn" would make those windows pass.  It is not taken:
    # the whole point of the second recorder is that it holds the driver to
    # the digit, and a rule with slack in it is a rule a dropped record can
    # hide inside.  Instead the disagreement is NAMED, so a reader of an
    # validation problem can distinguish a mid-turn snapshot from a driver bug.
    #
    # In practice this costs almost nothing: `r2t.confined.terminate` raises in the
    # driver's MAIN thread, so aider is stopped before anything is copied,
    # and both windows above are microseconds inside a run that spends 95.7%
    # of its wall clock waiting on the model (A5 cell 1, 93 priced rows).
    if problems and isinstance(manifest.get("termination"), dict):
        reason = manifest["termination"].get("reason")
        problems.append(
            f"this attempt was terminated before it finished ({reason!r}), "
            "so its two recorders were snapshotted mid-turn -- the "
            "disagreement above is named rather than waived, so incomplete "
            "evidence does not pass quietly")
    return problems
