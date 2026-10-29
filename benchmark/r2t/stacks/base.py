"""What a STACK is: the seven seams, the record schema, the step vocabulary.

A "stack" is a (language, BDD framework) pair the benchmark can measure —
`behat` over PHP today, `behave` over Python next.  Everything the rest of
`r2t` does to a project goes through the seven operations named in
`StackRunner`, and this module is where they are written down.

**This module defines and documents; it does not implement.**  There is no
adapter layer here, no shared base class and no dispatch table of behaviour:
`behat.py` is a façade whose every member IS the object `harness.py`,
`repo.py`, `closure.py`, `stub.py` and `mutation.py` already export (checked
with `is`, in this package's selftest).  That is the honest shape for an
abstraction with exactly one implementation.  A `StackRunner` extracted from
one stack and then bent to fit a second is an abstraction discovered twice;
the point of naming the seams BEFORE the second stack exists is that the
second one is written against a contract rather than against PHP's shadow,
and the point of moving no code is that CoreShop's byte-stability is a
property of the code not having moved.

The one thing that is genuinely shared, and the reason this file is not just
a docstring, is the RECORD — `r2t.record/1`.  Both stacks' recorders write it,
`validate`, `runner` and `metrics` all read it, and it is the only interface
across which a Python run and a PHP run have to mean the same thing.  So it is
specified here, and its two vocabularies are DERIVED FROM THE CODE THAT
PRODUCES AND CONSUMES THEM rather than retyped (see `selftest`).
"""
from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable

#: The version of the per-scenario record every stack's recorder writes.
#:
#: Versioned as a STRING with a slash rather than an int because it is written
#: into artifacts that outlive this repository's layout, and a bare `1` in a
#: JSON file says nothing about whose schema it is.  `/1` changes only when a
#: reader of an older file would be wrong — a renamed key, a re-scoped value —
#: never for an added optional field.
RECORD_SCHEMA = "r2t.record/1"

#: The record file, one JSON object per line, appended per scenario.
#:
#:     {"feature_file":    "features/domain/cart/add.feature",
#:      "feature_title":   "Cart",
#:      "scenario_title":  "Adding a product",
#:      "scenario_line":   14,
#:      "suite":           "bench",
#:      "steps":  [{"line": 15, "keyword": "Given", "text": "a store",
#:                  "result": "passed", "seconds": 0.12,
#:                  "exception": {"class": "...", "message": "..."}}],
#:      "coverage": {"files": {"src/X.php": 12},
#:                   "units": ["src/X.php::L41", ...]},
#:      "direct_calls": [{"callee_file": "src/X.php", "callee_line": 41,
#:                        "callee": "Cart::add",
#:                        "caller_file": "features/bootstrap/Ctx.php",
#:                        "step": 1}],
#:      "seconds": 3.4,
#:      "scenario_result": "passed"}
#:
#: Four properties are load-bearing, and each of them cost something:
#:
#: * **`scenario_line` is the line the RUN was at, which for a Scenario
#:   Outline is the EXAMPLES DATA ROW, not the `Scenario Outline:` keyword
#:   line.**  One record per Examples row, and `harness.fold_scenario_records`
#:   folds them.  Selecting on the keyword line alone matched nothing for an
#:   outline (`no_scenario_ran`); had the lines happened to align it would
#:   have scored only the LAST row.  Roughly half of the Python corpus is
#:   outlines, so this is not a corner case there.
#: * **The record file is inside the bind-mounted workspace**, so a context
#:   supplied by the system under test can append to it.  The fold therefore
#:   selects by identity (the lines the harness synthesised) and never by
#:   position, and `runner._record` counts the records to make an extra one
#:   visible.
#: * **`coverage` is per SCENARIO and restricted to the project's own source
#:   root.**  `files` is `{path: covered_line_count}` and `units` is the
#:   `path::L<line>` list the mutation map joins on; a coverage collector left
#:   at whole-tree scope credits the instrumentation itself.
#: * **`direct_calls` is every production method activation of the scenario,
#:   with the file the CALLER was in.**  Present on every record — null where
#:   the stack did not collect it, `[]` where it collected nothing, the same
#:   distinction `coverage` carries.  The recorder applies one fence, the
#:   production root the coverage collector already uses, and no boundary:
#:   which of those activations is DIRECT (a production callee reached from a
#:   removable caller) is decided at scoring, so a run stays re-scorable when
#:   a boundary is corrected.  `API_DIRECT_INVOCATION_SPEC.md` §2.5.
#: Go uses one selected parent-test-process window for coverage and API,
#: including initialization, setup and normal cleanup. Every Examples record
#: keeps its own identity and carries the same process-wide union; child
#: processes are excluded. API_DIRECT_INVOCATION_SPEC.md owns this exception.
#: Stack-specific collection identity may extend these common fields. Every
#: event carries `step`, the index of the step that made it in `steps` (null
#: outside any step; TARGET_INTERFACES_V2_SPEC section 4). Python, Ruby and
#: PHP add `direct_calls_schema` so even an empty direct-call list identifies
#: the recorder that produced it; it is null when collection was disabled.
RECORD_FIELDS: tuple[str, ...] = (
    "feature_file", "feature_title", "scenario_title", "scenario_line",
    "suite", "steps", "coverage", "direct_calls", "seconds",
    "scenario_result")

#: The per-step object inside `steps`.  `exception` is null or
#: `{class, message}`; `runner._record` reads only the message, and the class
#: is kept because "which exception" is the difference between a failed
#: assertion and a broken container.
STEP_FIELDS: tuple[str, ...] = (
    "line", "keyword", "text", "result", "seconds", "exception")

#: The two halves of `coverage`.  Both, not one: `files` is what a human
#: reads and `units` is what the mutation map joins on, and a run where they
#: disagree is flagged (`runner._coverage_mismatch`) rather than trusted.
COVERAGE_FIELDS: tuple[str, ...] = ("files", "units")

#: The FIVE values a step's `result` may take.
#:
#: Not invented here: they are Behat's own TestResult codes (0/10/20/30/99)
#: as `r2t/php/BenchRecorderHook.php` names them, and `selftest` re-derives
#: them from that file rather than trusting this line.  A second stack maps
#: ITS framework's statuses onto these five — behave has no `pending` of its
#: own and its `untested` is this `skipped` — because `harness.record_outcome`
#: is the one function that turns per-step results into an outcome and it must
#: not learn a second vocabulary.
#:
#: The order is the RECORDER's (by result code), not the fold's precedence.
STEP_RESULTS: tuple[str, ...] = ("passed", "skipped", "pending", "undefined",
                                 "failed")

#: What `record_outcome` actually branches on, in ITS order, which is a
#: PRECEDENCE and not a list: all-passed, else any undefined, else any failed,
#: else any pending, else `not_passed`.  `skipped` is deliberately absent —
#: a scenario whose steps were skipped did not pass and is not undefined, and
#: falling through to `not_passed` is the correct answer for it.
STEP_RESULTS_FOLDED: tuple[str, ...] = ("passed", "undefined", "failed",
                                        "pending")

#: `scenario_result` is the recorder's own verdict for the scenario.  It is
#: recorded but NEVER the benchmark's verdict: the harness folds the per-step
#: results and cross-checks them against the framework's exit code (the
#: two-witness rule), because a recorder that lives inside the workspace is
#: not an independent witness to its own run.
SCENARIO_RESULTS: tuple[str, ...] = ("passed", "not-passed")


@runtime_checkable
class StackRunner(Protocol):
    """The seven operations a stack must provide, at the signatures it has.

    Deliberately NOT a base class.  Nothing inherits from this and nothing is
    constructed through it; it is the written-down list of what the CLI and
    the sweeps need from a stack, so that adding one is a matter of answering
    seven questions rather than of reading `cli.py` to find out which imports
    are PHP.  `behat.py` satisfies it by re-export.

    The seven, in the order a project passes through them:

    1. `strip` — remove the answer from a clone and keep it in `gold/`,
       recording a manifest of exactly what moved.
    2. `integrity_baseline` — hash the substrate roots, so that a submission
       editing production code during its own run is a finding rather than a
       silently better score.
    3. `extract_closure` — for each item, which files the reference answer
       needs (its gold closure), derived from the framework's own step
       registry rather than from a regex over the sources.
    4. `install_solution` — write a submission into the workspace under the
       boundary's acceptance rules, refusing what it may not write.
    5. `execute` — run the one scenario, in a container, and return a
       `RunResult` folded over `r2t.record/1`.
    6. `stub_solution` — the anti-vacuity control: a submission whose steps
       are syntactically valid and semantically empty.  The corpus gate
       measures it and requires ≤ 0.02.
    7. `mutant_population` — the mutant manifest this stack's engine defines,
       digest and all, which is what turns "passed" into "passed and is not
       vacuous".

    `install_solution` and `execute` are METHODS of the stack's harness class
    (the harness is per-workspace state: a manifest, a boundary, a container
    handle), so a stack exposes them as the unbound functions they are; the
    façade's identity check is over those. Everything else is module-level.
    """

    def strip(self, boundary: Any, gold_root: str, harness_dir: str,
              dry_run: bool = False) -> Any:
        ...

    def integrity_baseline(self, manifest: Any, boundary: Any) -> Any:
        ...

    def extract_closure(self, *args: Any, **kwargs: Any) -> Any:
        ...

    def install_solution(self, solution: Any, task: str) -> Any:
        ...

    def execute(self, coverage: bool = False, timeout: int = 600,
                expected_line: Optional[int] = None,
                expected_lines: Optional[list] = None) -> Any:
        ...

    def stub_solution(self, item: dict, closure: Optional[dict]) -> dict:
        # A stack whose closure producer cannot state a step's multiline
        # argument takes one more input than this: cucumber's module-level
        # `stub_solution` requires `feature_root`, the pinned corpus tree,
        # because `arg_kind` is a fact about the source line rather than
        # about the binding, and a stub with the wrong arity ERRORS instead
        # of vacuously passing.  Named here so the extra argument reads as a
        # property of that producer rather than as a drifted signature.
        ...

    def mutant_population(self, raw: list, **kwargs: Any) -> dict:
        ...


#: The members a stack module must expose beside the seven, for the CLI to be
#: able to dispatch on `framework:` at all.  `FRAMEWORK` is the profile field's
#: value; `make_harness(args)` builds this stack's harness from parsed CLI
#: arguments and returns `(harness, boundary, manifest)` exactly as
#: `cli._harness` always has.
#:
#: `behat` is the exception that proves the rule: its harness construction
#: still lives in `cli._harness`, where it was, because S1 moves no logic.
#: When it moves, that branch becomes one more `make_harness` call and this
#: comment goes away.
DISPATCH_MEMBERS: tuple[str, ...] = ("FRAMEWORK",)

#: The mutation engine a stack measures with, named the same way on every
#: stack.  Each member re-exports the constant its engine module owns, and
#: `stacks.selftest` holds all five against `mutation_run.engines()` — so a
#: façade cannot name one engine and borrow another's directory, applier or
#: exclusion policy, which is exactly what an unevenly filled façade allowed.
#:
#: `applier` is the one member whose KIND differs: behat re-exports the
#: `mutation_run.Applier` object (five signatures default to it), while the
#: other two re-export the zero-argument factory their engine module exports
#: so that the module can be imported without `mutation_run`.  Same fact,
#: two spellings; the selftest resolves before comparing.
ENGINE_MEMBERS: tuple[str, ...] = ("engine", "engine_version", "engine_dir",
                                   "applier", "excluded_prefixes")
