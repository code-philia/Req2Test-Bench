"""S4 — the harness-owned behave recorder, installed as `features/environment.py`.

`strip_repo_behave` copies this file over the project's own twelve-line
`environment.py` (which moves to gold) — the same move CoreShop makes when it
installs `BenchRecorderHook.php` under the retained tree.  From then on it is
SUBSTRATE: `features/environment.py` is a file root in
`repo.BEHAVE_SUBSTRATE_ROOTS`, its hash is in the strip baseline, and a
solution that rewrites the recorder that scores it is a `substrate_violation`,
not a better number.

It writes `r2t.record/1` (`stacks.base.RECORD_SCHEMA`): one JSON line per
scenario into the file named by `$BENCH_RECORD_PATH`, appended at
`after_scenario`.  Four properties carry the measurement and each is pinned
by a selftest or a live probe rather than assumed:

* **One record per Examples row.**  behave builds a real Scenario per data row
  (`ScenarioOutlineBuilder`) and fires `after_scenario` for each, stamping
  `scenario.line` with the DATA ROW's line — verified live against behave
  1.3.3 in `r2t_docx_img:base`.  That is exactly the shape
  `harness.fold_scenario_records` folds, so an outline needs no code here.
* **Coverage is per scenario, in memory, and `src/`-restricted.**
  `Coverage(source=["src"], data_file=None)` — a `.coverage` file on disk
  would be a file ADDED under a hashed root, i.e. this recorder tampering
  with the substrate it is part of.  The `src/` filter is applied AGAIN on
  the collected paths, because instrument-crediting (a collector at
  whole-tree scope crediting the harness's own code) is the documented
  failure mode of the measure.
* **`direct_calls` records the CALLER of every production call.**  A
  `sys.setprofile` hook installed beside the coverage collector and under the
  same `$BENCH_COVERAGE=1` condition, so an in-trajectory trial pays neither
  the hook nor the field, and its record carries `null` for the same reason it
  carries a null `coverage`.  Per activation it keeps the callee's file, its
  `co_firstlineno` and `co_qualname`, and the file the CALLING frame is in,
  walking past descriptor frames. Generated xmlchemy properties additionally
  identify the actual installed accessor through its function and closure;
  ordinary calls carry `accessor_binding: null`. It applies ONE fence, the `src/` root the
  collector already uses, and no boundary: the removable test, the public test
  and the index mapping are applied at scoring on the host, exactly as
  `production_lines` applies the boundary to coverage
  (`API_DIRECT_INVOCATION_SPEC.md` §2.4).  `co_qualname` is 3.11+ and the
  execution image is pinned to `python:3.12-slim`, so `stacks.behave.
  selftest` pins the field's SHAPE on the host and the hook's behaviour is
  pinned by the spec's §8 validation, run in that image.
* **Every event names the step that made it.**  `before_step` looks the
  step up by identity in the list `after_scenario` serialises (the
  Background's steps, then the scenario's own) and the hook stamps that index
  on each event as `step`; `after_step` clears it, so a call made by a hook
  between two steps carries `null`.  Identity rather than a counter, because
  behave runs no hook for a step it skips after a failure.  That index is
  what `toolkit/checked_interfaces.py` reads (TARGET_INTERFACES_V2_SPEC §4);
  which steps are actions or checks is decided there, from the feature, never
  here.  The marker moved to `r2t.python_direct_calls/3` with the field.
* **The recorder never decides the run.**  `scenario_result` is behave's own
  verdict, recorded for the row but never trusted: the harness folds the
  per-step results and cross-checks the process exit code (the two-witness
  rule), because a recorder living inside the bind-mounted workspace is not
  an independent witness to its own run.

STDLIB-ONLY AT IMPORT, deliberately.  Hooks receive live behave objects and
never need to import the framework; `coverage` is imported lazily and only
under `$BENCH_COVERAGE=1`.  That is what lets `stacks.behave.selftest` drive
every mapping and record-building path on the host with fake step objects —
no container, no behave — so the parts that can drift are checked on every
selftest run and only the framework's own behaviour is left to the live gate.

The one piece of PROJECT behaviour reproduced from the file this replaces:
upstream's `before_all` creates `features/_scratch/`, and the frozen prompt
promises the agent that a scenario which saves a document may write there.
A recorder that dropped that would fail every save-scenario for a reason
that is not test generation.
"""
from __future__ import annotations

import json
import os
import sys
import time

#: Where the record file lives, as the CONTAINER sees it.  Set by
#: `BehaveHarness.execute`, derived from the runner's own workdir — never
#: hard-coded, which is the H2 lesson (a worker mounted elsewhere used to
#: score every item `no_scenario_ran` off an empty record file).
RECORD_ENV = "BENCH_RECORD_PATH"

#: `"1"` switches per-scenario coverage on.  Anything else leaves the
#: `coverage` key null, which readers distinguish from "measured, empty".
COVERAGE_ENV = "BENCH_COVERAGE"

#: Recorded even for an empty list: a new harness can execute an older seed,
#: so its version alone cannot attest that this recorder measured accessors
#: (`/2`) or stamped each event with its step (`/3`).
DIRECT_CALLS_SCHEMA = "r2t.python_direct_calls/3"

#: The descriptor protocol: NOT itself an API call, and its frame is
#: TRANSPARENT.  `table.rows` under python-docx's `lazyproperty` must credit
#: `Table.rows` with the step as its caller, not `lazyproperty.__get__` with
#: the step as its caller and `Table.rows` with the descriptor as its.  Both
#: halves of that are this one set (spec §2.2).
_DESCRIPTOR = frozenset({"__get__", "__set__", "__delete__", "__set_name__"})

#: behave step status -> the five-value vocabulary of `r2t.record/1`
#: (`stacks.base.STEP_RESULTS`).  Derived from the FULL `Status` enum of
#: behave 1.3.3 as probed live in the execution image; `stacks.behave.
#: selftest` re-walks that probed list and fails if a name maps outside the
#: vocabulary.  A status NOT in this table is recorded as `failed` with a
#: synthetic exception naming it — fail-closed, because an unmapped status
#: that defaulted to anything softer could let a run pass on a word this
#: schema has never heard of.
STATUS_MAP = {
    "passed": "passed",
    "failed": "failed",
    # behave 1.3.x splits "the assertion was false" (failed) from "the step
    # raised" (error) and adds hook/cleanup variants; r2t.record/1 folds all
    # of them into `failed` — the distinction survives in `exception.class`.
    "error": "failed",
    "hook_error": "failed",
    "cleanup_error": "failed",
    "undefined": "undefined",
    "untested_undefined": "undefined",
    # `untested` is behave's "never reached" (a step after the failure);
    # the record schema spells that `skipped` (see stacks/base.py).
    "untested": "skipped",
    "skipped": "skipped",
    # behave 1.3.3 does have a pending vocabulary (its JSON formatter does
    # not, which is why the plan says "tolerate it"); it maps onto the
    # schema's own `pending` rather than being flattened away.
    "pending": "pending",
    "pending_warn": "pending",
    "untested_pending": "pending",
}

_MSG_LIMIT = 2000


def _status_name(status) -> str:
    """The bare name, whether behave hands over an enum or a string."""
    return getattr(status, "name", None) or str(status)


def map_status(status) -> tuple[str, dict | None]:
    """`(result, synthetic_exception_or_None)` for one behave step status.

    The synthetic exception exists so an unmapped status is never silent:
    the step is recorded `failed` AND the record says why, in the slot
    every reader already looks at for failure detail.
    """
    name = _status_name(status)
    mapped = STATUS_MAP.get(name)
    if mapped is not None:
        return mapped, None
    return "failed", {
        "class": "UnmappedStatus",
        "message": (f"behave reported step status {name!r}, which "
                    f"r2t.record/1 cannot express; recorded as failed so it "
                    f"can never read as a pass")}


def step_record(step) -> dict:
    """One element of `steps`, in `stacks.base.STEP_FIELDS` exactly."""
    result, synthetic = map_status(getattr(step, "status", None))
    exc = getattr(step, "exception", None)
    error_message = getattr(step, "error_message", None)
    exception = None
    if exc is not None:
        exception = {"class": type(exc).__name__,
                     "message": (str(exc) or error_message
                                 or "")[:_MSG_LIMIT]}
    elif result == "failed":
        exception = synthetic or {
            "class": "StepError",
            "message": (error_message or "no exception recorded")[:_MSG_LIMIT]}
    return {"line": getattr(step, "line", None),
            "keyword": getattr(step, "keyword", ""),
            "text": getattr(step, "name", ""),
            "result": result,
            "seconds": round(float(getattr(step, "duration", 0) or 0), 6),
            "exception": exception}


def coverage_doc(measured: dict, base: str) -> dict:
    """`{files, units}` from `{abs_path: [executed 1-based lines]}`.

    Restricted to `base`-relative paths under `src/` — again, even though the
    collector was already constructed with `source=["src"]`.  Two fences,
    because the failure mode they close (crediting the instrumentation or the
    step definitions themselves) deflates nothing and inflates recall, i.e.
    it is invisible in every row it corrupts.
    """
    files: dict = {}
    units: list = []
    for path in sorted(measured):
        rel = os.path.relpath(path, base).replace(os.sep, "/")
        lines = sorted(measured[path] or [])
        if not rel.startswith("src/") or not lines:
            continue
        files[rel] = len(lines)
        units += [f"{rel}::L{n}" for n in lines]
    return {"files": files, "units": units}


class _AccessorBindingRefused(ValueError):
    """An xmlchemy property ran but its installed declaration was unresolved."""


def _accessor_codes(namespace: dict) -> set:
    """The actual nested function codes supplied by xmlchemy's properties.

    Factory names select the descriptor implementation, not the credited
    attribute. Attribution additionally matches the installed function and
    every closure cell against the live frame below.
    """
    codes = set()
    for cls in namespace.values():
        if not isinstance(cls, type) or cls.__module__ != namespace["__name__"]:
            continue
        for name in ("_getter", "_setter", "_list_getter", "_choice_getter"):
            factory = vars(cls).get(name)
            if not isinstance(factory, property) or factory.fget is None:
                continue
            code = factory.fget.__code__
            codes.update(value for value in code.co_consts
                         if isinstance(value, type(code)))
    return codes


def _assignment_line(owner, descriptor, cache: dict) -> tuple[str, int]:
    """Read the source assignment of this actual descriptor's declaring class.

    This is source-location evidence, not a production index: no public test,
    method inventory or boundary is loaded into the recorder.
    """
    import ast

    module = sys.modules.get(owner.__module__)
    filename = getattr(module, "__file__", None)
    if not filename:
        raise _AccessorBindingRefused("declaring class has no source file")
    if filename not in cache:
        with open(filename, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=filename)
        classes = {}

        def collect(body, prefix=""):
            for node in body:
                if isinstance(node, ast.ClassDef):
                    name = prefix + node.name
                    classes[name] = node
                    collect(node.body, name + ".")

        collect(tree.body)
        cache[filename] = classes
    cls = cache[filename].get(owner.__qualname__)
    prop_name = vars(descriptor).get("_prop_name")
    if cls is None or not isinstance(prop_name, str):
        raise _AccessorBindingRefused("descriptor has no declaring assignment")
    for node in cls.body:
        targets = (node.targets if isinstance(node, ast.Assign) else
                   [node.target] if isinstance(node, ast.AnnAssign) else [])
        if not any(isinstance(target, ast.Name) and target.id == prop_name
                   for target in targets):
            continue
        value = node.value
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) \
                and vars(module).get(value.func.id) is type(descriptor):
            return filename, node.lineno
    raise _AccessorBindingRefused("installed accessor lacks its descriptor assignment")


def _accessor_binding(frame, code_cache: dict, declarations: dict):
    """Return a binding tuple, or None for an ordinary method activation."""
    code = frame.f_code
    namespace = frame.f_globals
    if namespace.get("__name__") != "docx.oxml.xmlchemy" \
            or "self" not in code.co_freevars:
        return None
    # The first closure activation occurs after xmlchemy's classes exist,
    # including when the candidate imports docx inside the measured window.
    if not code_cache:
        code_cache["codes"] = _accessor_codes(namespace)
    if code not in code_cache["codes"]:
        return None
    descriptor = frame.f_locals["self"]
    owner = vars(descriptor).get("_element_cls")
    if not isinstance(owner, type):
        raise _AccessorBindingRefused("accessor closure has no declaring class")
    matches = []
    for attribute, prop in vars(owner).items():
        if not isinstance(prop, property):
            continue
        for kind, function in (("get", prop.fget), ("set", prop.fset),
                               ("delete", prop.fdel)):
            if function is None or function.__code__ is not code:
                continue
            if all(cell.cell_contents is frame.f_locals.get(name)
                   for name, cell in zip(code.co_freevars,
                                         function.__closure__ or ())):
                matches.append((attribute, kind))
    if len(matches) != 1:
        raise _AccessorBindingRefused(
            f"accessor activation matches {len(matches)} installed properties")
    filename, line = _assignment_line(owner, descriptor, declarations)
    attribute, kind = matches[0]
    return filename, line, owner.__module__ + "." + owner.__qualname__, attribute, kind


def _direct_event(value: tuple) -> dict:
    filename, line, qualified, caller, binding, step = value
    return {"callee_file": filename, "callee_line": line, "callee": qualified,
            "caller_file": caller, "accessor_binding": (
                dict(zip(("declaring_file", "declaring_line", "owner",
                          "attribute", "access_kind"), binding))
                if binding is not None else None),
            "step": step}


class _DirectCalls:
    """One scenario's events and source-location cache, without scoring rules."""

    def __init__(self, root: str):
        self.root = root
        self.src = os.path.join(root, "src") + os.sep
        self.paths = {}
        self.codes = {}
        self.declarations = {}
        self.seen = set()
        self.failures = {}
        #: The index of the executing step, set by `before_step`; None
        #: between steps, so hook-made calls are never charged to a step.
        #: `steps` is the stack of executing steps (outer first) that
        #: `context.execute_steps()` nesting needs.
        self.step = None
        self.steps = []

    def relative(self, filename: str) -> str:
        if filename not in self.paths:
            self.paths[filename] = os.path.relpath(filename, self.root)
        return self.paths[filename]

    def record(self, frame, qualified_name: str) -> None:
        code = frame.f_code
        name = code.co_filename
        if (not name.startswith(self.src) or code.co_name.startswith("<")
                or code.co_name in _DESCRIPTOR):
            return
        back = frame.f_back
        while back is not None and back.f_code.co_name in _DESCRIPTOR:
            back = back.f_back
        caller = self.relative(back.f_code.co_filename) if back else ""
        event = (self.relative(name), code.co_firstlineno, qualified_name, caller)
        binding = None
        try:
            binding = _accessor_binding(frame, self.codes, self.declarations)
            if binding is not None:
                binding = (self.relative(binding[0]), *binding[1:])
        except (ValueError, OSError, SyntaxError, TypeError, AttributeError) as exc:
            self.failures[event] = str(exc)
        self.seen.add((*event, binding, self.step))

    def events(self) -> list:
        return [_direct_event(value) for value in sorted(
            self.seen, key=lambda value: (*value[:4], value[4] or (),
                                          value[5] is not None, value[5] or 0))]


def _install(context, root: str) -> None:
    """Start the production-root recorder beside coverage for one scenario."""
    recorder = _DirectCalls(root)

    def profile(frame, event, arg):
        if event == "call":
            recorder.record(frame, frame.f_code.co_qualname)

    context._bench_direct = recorder
    sys.setprofile(profile)


def _uninstall(context) -> list | None:
    """Stop recording; unresolved accessors withhold API evidence only.

    The full structured diagnostic bypasses behave's captured stdout and is
    flushed before another Examples row can time out. The harness retains
    stdout on both its normal and timeout paths in the kept stdout.log. It includes the
    unresolved activation and every observed event, even though the scored
    record must carry null rather than a partial API set.
    """
    sys.setprofile(None)
    recorder = context._bench_direct
    events = recorder.events()
    if recorder.failures:
        diagnostic = {"direct_calls_schema": DIRECT_CALLS_SCHEMA,
                      "direct_calls_raw": events,
                      "errors": [{"event": _direct_event((*event, None, None)),
                                  "reason": reason}
                                 for event, reason in sorted(recorder.failures.items())]}
        print("R2T_ACCESSOR_BINDING_REFUSED " + json.dumps(diagnostic, sort_keys=True),
              file=sys.__stdout__, flush=True)
        return None
    return events


def build_record(scenario, steps: list, seconds: float,
                 coverage: dict | None, direct_calls: list | None, *,
                 direct_calls_schema: str | None = None) -> dict:
    """Common `r2t.record/1` fields plus Python recorder completeness identity."""
    feature = getattr(scenario, "feature", None)
    status = _status_name(getattr(scenario, "status", None))
    return {
        "feature_file": getattr(scenario, "filename", None),
        "feature_title": getattr(feature, "name", "") if feature else "",
        "scenario_title": getattr(scenario, "name", ""),
        # For a Scenario Outline this is the EXAMPLES DATA ROW's line —
        # behave's own numbering for the generated scenario, verified live —
        # which is the identity the fold selects on.
        "scenario_line": getattr(scenario, "line", None),
        "suite": "bench",
        "steps": [step_record(s) for s in steps],
        # Null when coverage was not requested; `{"files": {}, "units": []}`
        # when it was requested and nothing under src/ executed.  The two are
        # different findings and `runner._record` tells them apart by
        # truthiness, so the recorder must not conflate them.
        "coverage": coverage,
        # Null when collection is off or an activated accessor could not
        # be resolved. `[]` means it ran and saw no production activation;
        # the separate schema field identifies even that empty observation.
        "direct_calls": direct_calls,
        "direct_calls_schema": (DIRECT_CALLS_SCHEMA if direct_calls is not None
                                else direct_calls_schema),
        "seconds": round(seconds, 6),
        # The recorder's OWN verdict, in the two-value vocabulary the PHP
        # recorder uses.  Recorded, cross-checked, never decisive.
        "scenario_result": ("passed" if status == "passed" else "not-passed"),
    }


def _append_record(doc: dict) -> None:
    path = os.environ[RECORD_ENV]
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, sort_keys=True) + "\n")


# ------------------------------------------------------------ behave hooks
def before_all(context):
    # Loud, not lenient: a recorder with nowhere to write would produce a run
    # whose every item scores `no_scenario_ran` off an empty record file, and
    # the operator would go looking for a harness bug.  Raising here surfaces
    # as behave's `HOOK-ERROR in before_all` (exit non-zero), which the
    # harness classifies as `container_error` — an environment fault, charged
    # to nobody's solution.
    if RECORD_ENV not in os.environ:
        raise RuntimeError(
            f"{RECORD_ENV} is not set. This environment.py is the r2t bench "
            f"recorder and only runs under the harness, which derives the "
            f"record path from the worker's own mount point. To run behave "
            f"by hand here, set {RECORD_ENV}=/tmp/run_record.jsonl first.")
    # The one behaviour kept from the environment.py this file replaced:
    # scenarios that save documents write into `features/_scratch/`, and the
    # frozen profile prompt tells the agent so.  Created before the run, as
    # upstream's hook did, relative to this file rather than to the cwd.
    scratch = os.path.abspath(
        os.path.join(os.path.split(__file__)[0], "_scratch"))
    if not os.path.isdir(scratch):
        os.mkdir(scratch)


def before_scenario(context, scenario):
    context._bench_started = time.perf_counter()
    context._bench_cov = None
    context._bench_direct = None
    # The Background's steps and then the scenario's own -- the list
    # `after_scenario` serialises, so a step's index here is its index in the
    # record.  behave copies the Background's steps per scenario once and
    # keeps them, so identity holds from this hook to `after_scenario`.
    context._bench_steps = list(getattr(scenario, "all_steps", None)
                                or scenario.steps)
    if os.environ.get(COVERAGE_ENV) == "1":
        import coverage

        # A fresh in-memory collector per scenario: `data_file=None` keeps it
        # off the disk (a `.coverage` under a hashed root is substrate
        # tampering by the instrument itself), and per-scenario construction
        # is what makes the attribution per scenario rather than cumulative.
        cov = coverage.Coverage(source=["src"], data_file=None)
        try:
            cov._warn_no_data = False       # noqa: SLF001 — silence only
        except Exception:                                   # noqa: BLE001
            pass
        cov.start()
        context._bench_cov = cov
        _install(context, os.getcwd())


def before_step(context, step):
    recorder = getattr(context, "_bench_direct", None)
    if recorder is not None:
        # A stack, because `context.execute_steps()` runs nested steps with
        # their own hooks inside the outer step: the nested steps are not in
        # the record's list (index None), and the outer step's index is
        # restored when they finish.
        recorder.steps.append(next((i for i, s in enumerate(context._bench_steps)
                                    if s is step), None))
        recorder.step = recorder.steps[-1]


def after_step(context, step):
    recorder = getattr(context, "_bench_direct", None)
    if recorder is not None:
        if recorder.steps:
            recorder.steps.pop()
        recorder.step = recorder.steps[-1] if recorder.steps else None


def after_scenario(context, scenario):
    seconds = time.perf_counter() - getattr(context, "_bench_started",
                                            time.perf_counter())
    cov_doc = None
    direct = None
    direct_schema = None
    cov = getattr(context, "_bench_cov", None)
    if cov is not None:
        direct = _uninstall(context)
        direct_schema = DIRECT_CALLS_SCHEMA
        cov.stop()
        data = cov.get_data()
        measured = {f: (data.lines(f) or []) for f in data.measured_files()}
        cov_doc = coverage_doc(measured, os.getcwd())
        context._bench_cov = None
    # `all_steps` walks the Background's steps and then the scenario's own,
    # each with its executed status — the Background is part of the item
    # (its definitions are part of the answer), so its steps are part of the
    # record.  The same list `before_scenario` captured, so an event's `step`
    # indexes exactly this sequence.
    steps = getattr(context, "_bench_steps", None) or list(
        getattr(scenario, "all_steps", None) or scenario.steps)
    _append_record(build_record(scenario, steps, seconds, cov_doc, direct,
                                direct_calls_schema=direct_schema))
