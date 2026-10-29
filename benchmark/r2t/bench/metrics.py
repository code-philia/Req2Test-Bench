"""S8 — behavioural metrics: did the produced test EXERCISE what gold exercised?

A pass rate answers "did the scenario go green"; it says nothing about the
run that did not.  These two metrics read the evidence a run leaves about
what it actually did -- the per-scenario line coverage
(`php/BenchRecorderHook.php`, `py/bench_environment.py`) and the per-scenario
call events (`py/bench_environment.py`, `php/BenchRecorderHook.php`, and the
Java direct-call agent) -- against the GOLD run of the SAME item.

    CoverageSimilarity   which production lines the scenario drove
    ApiCallSimilarity    which public production methods the TEST called

**Both are restricted to files that classify PRODUCTION, and that
restriction is load-bearing.**  The recorder's coverage filter is
`<root>/src`, and `src` holds three different things: production code,
the retained TestBundle, and — in a gold run — the restored gold test
code itself.  Comparing unrestricted would therefore measure, in part,
how closely the system's own PHP resembles gold's own PHP line for line:
a solution that writes the same behaviour with an extra guard clause
shifts every later line number in its own file and scores near zero for a
purely stylistic difference.  Restricting to production removes that
term, and it is sound precisely because `install_solution` refuses writes
outside removable territory: production files are byte-identical across
the two runs, so a production line number means the same thing on both
sides.  (`vendor/` and `features/` also classify production, but the
recorder never emits them, so "production" here means "src minus the test
tree".)

**ApiCallSimilarity is defined over DIRECT invocation, not over coverage.**
Its two sets are the public production methods gold and the candidate each
called THEMSELVES: a call event whose callee is production and whose CALLER
is removable, i.e. part of the answer.  They are read from the recorder's
`direct_calls` field (API_DIRECT_INVOCATION_SPEC.md 2.1-2.3) and never
derived from the line sets, because everything the library runs underneath
one call is a property of the library and not of the test.  There is no
fallback: a row recorded before the recorder existed carries no
`direct_calls`, and its API rows are NOT SCORED rather than recomputed under
a different definition (2.6).  A gold row whose test called nothing directly
is unscorable and LEAVES the API denominator (3.1) instead of handing every
system the empty-set identity.

**Direction matters, so the directional pair is primary.**  Jaccard is
symmetric: a solution that builds MORE fixture than gold — extra
products, an extra store, a fuller cart — is punished exactly as hard as
one that skips the behaviour under test entirely, and those are not the
same failure.  `recall` (how much of gold's behaviour was reached) and
`excess` (how much of what ran was not gold's) separate them; the Jaccard
pair is reported second because it is the form ART states and comparison
with ART's numbers is worth keeping possible.  `excess` is the one
inverted-polarity number here: 0.0 is perfect.

**Definedness.**  A metric is DEFINED for an item iff the system's run
produced a coverage block at all, i.e. the scenario reached
`@AfterScenario`.  It is UNDEFINED when the run never got that far
(`container_error`, `solution_error`, `timeout`, `no_scenario_ran`, or no
submission at all).  Undefined is not zero and must never be silently
averaged as zero, so `summarise` always reports BOTH aggregates together:

  * `mean_defined` — the conditional mean, always printed with `n_defined`,
    which is the number that makes it readable.  Alone it is a trap: a
    system that only reaches `@AfterScenario` on the three easiest items
    can post a higher conditional mean than one that reaches it on all.
  * `over_total` — undefined items substituted with the worst score,
    denominator the full item set.  This is ART's `avg_over_total`
    convention, and it makes each reward-polarity metric mathematically
    <= the pass rate, which is stated wherever it is printed.

The three `api.*` keys carry a SECOND gate on top of this one: an item whose
gold or system row has no `direct_calls`, or whose gold test invoked nothing
directly, is EXCLUDED from both API aggregates rather than substituted
(`compare`'s `api_excluded`), so their `n_items` can be smaller than the
coverage keys'.  A crashed run is still substituted, as above.

One deliberate deviation from that convention: the substituted value for
`excess` is 1.0, not 0.0, because 0.0 is `excess`'s BEST score — scoring
crashed items 0.0 would make a system that never runs look maximally
precise.  Every metric entry carries the `undefined_score` it used, so
the substitution is never implicit.  The same polarity trap exists one
level down and is closed in `coverage_similarity`: a system that RAN and
covered no production line scores `excess` 1.0, not the arithmetic 0/0.

**What these metrics are for, measured.**  A Behat context of
syntactically valid step definitions with EMPTY bodies binds, runs, and
PASSES — the pass rate cannot tell it from a real test.  Measured on
`cart_base_item_taxes.feature:22`: outcome `passed`, and every metric
here at its worst (recall 0.000, excess 1.000, and an empty API set -- it
calls no production method at all, so nothing is credited to it under
either definition).  The production restriction is what makes that true: the
48 lines such a solution does cover are its own step definitions, the
retained TestBundle hooks and the benchmark's own recorder.  Unrestricted,
those same 22 harness lines score it recall 0.011 — the instrument
crediting a system for executing the instrument.

Degenerate items are flagged, not hidden: an item whose GOLD run covers
no production line hands every system a free perfect score, because both
sides are then empty and the comparison is an identity.  `summarise`
counts them and the CLI prints the count; they should be excluded or
repaired, never averaged over quietly.  The API axis does not flag its
degenerate items, it excludes them -- see above.

Inputs are produced elsewhere and this module refuses to guess at them:
run records must carry `coverage_lines` ({relative path: [line, ...]}),
and the method index must carry per-class `methods` with `name`, `start`,
`end` and `public`.  A missing field raises `MetricsInputError` naming
the item and the file rather than scoring the item zero.  `direct_calls`
is the one input whose ABSENCE is not an error -- it is how a row from
before the recorder says its API rows cannot be computed -- while a Python
index carrying no `decl` line IS one, because it maps every callee unmapped
and so looks exactly like a test that called nothing.  That refusal is
applied where the index is USED for API mapping (`direct_methods`), never
on loading it, and `r2t.bench.results` applies it once up front so that it
withholds the API rows alone.

`--boundary` and `--index` default to CoreShop's; any other project passes
both, and the CLI refuses a non-CoreShop boundary without `--index`.

    python3 -m r2t.bench.metrics --gold runs/gold.jsonl --run runs/sys.jsonl [--per-item]
    python3 -m r2t.bench.metrics --selftest
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import statistics
from dataclasses import dataclass
from typing import Iterable, Optional

from ..core.boundary import PRODUCTION, REMOVABLE, Boundary
from ..core.paths import project_path

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCHMARK = os.path.dirname(HERE)
#: Mirrors r2t.cli rather than importing it: this module must stay
#: importable from an analysis script that has no CLI arguments.
DEFAULT_BOUNDARY = os.path.join(BENCHMARK, "config", "boundary_coreshop.yml")
DEFAULT_ARTIFACTS = project_path("coreshop", "artifacts")

#: The per-scenario line coverage a run record carries: {relpath: [line, ...]}.
#: Distinct from `coverage_files` (per-file counts) and from the `coverage`
#: boolean the run stamp records.
COVERAGE_FIELD = "coverage_lines"

#: The call events a run record carries, or null where the stack did not
#: collect them.  The API rows are defined over this field and over nothing
#: else; `null` is "not collected" and `[]` is "the test called nothing".
DIRECT_CALLS_FIELD = "direct_calls"

#: SHA-256 of the approved API_DIRECT_INVOCATION_SPEC.md these rows implement.
APPROVED_SPEC_SHA256 = \
    "8fd87fc2593be3eb3ef9490eacb9f9796ae7402e484592e838936b2009c31592"

PYTHON_PROD_INDEX_SCHEMA = "r2t.py_prod_index/2"
PYTHON_DIRECT_CALLS_SCHEMA = "r2t.python_direct_calls/2"
RUBY_PROD_INDEX_SCHEMA = "r2t.rb_prod_index/1"
RUBY_DIRECT_CALLS_SCHEMA = "r2t.ruby_direct_calls/1"
#: Every recorder marker this scorer reads the API set from.  The `/3` and
#: `/2` successors add one field per event, `step` (TARGET_INTERFACES_V2_SPEC
#: section 4); the API set is the same pairs either way, so both shapes score.
PYTHON_DIRECT_CALLS_SCHEMAS = (PYTHON_DIRECT_CALLS_SCHEMA, "r2t.python_direct_calls/3")
RUBY_DIRECT_CALLS_SCHEMAS = (RUBY_DIRECT_CALLS_SCHEMA, "r2t.ruby_direct_calls/2")
OUTLINE_UNION_HARNESS_VERSION = 12
API_RECORD_EXCLUSIONS = (
    "gold_without_direct_calls", "run_without_direct_calls",
    "gold_before_api_amendment_2", "run_before_api_amendment_2",
    "invalid_production_index")
RUBY_API_RECORD_EXCLUSIONS = ("gold_before_api_amendment_3", "run_before_api_amendment_3")

#: Reported metrics, in the order a table should print them.  The
#: directional pair leads; Jaccard follows as the comparable-with-ART form.
METRIC_KEYS = ("coverage.recall", "coverage.excess",
               "coverage.micro_jaccard", "coverage.macro_jaccard",
               "api.precision", "api.recall", "api.f1")

#: What an UNDEFINED item scores in the `over_total` aggregate.  1.0 for
#: `excess` because low is good there; see the module docstring.
UNDEFINED_SCORE = {k: (1.0 if k == "coverage.excess" else 0.0)
                   for k in METRIC_KEYS}


class MetricsInputError(RuntimeError):
    """A run record or method index lacks a field the metrics are defined over.

    Raised instead of scoring the item zero: an absent field means the
    producing stage did not run (or ran without `--coverage`), and a
    benchmark that reports 0.0 for that is reporting its own plumbing.
    """


# --------------------------------------------------------------------------
# inputs

def _norm(path: str) -> str:
    return path.replace(os.sep, "/").lstrip("./")


def read_runs(path: str) -> dict[str, dict]:
    """Read a run file into {item_id: record}, WITHOUT the scorability checks.

    Run files are appended to, and `--retry-failed` re-runs an item in
    place, so the same `item_id` can appear twice; the LAST row wins,
    which is the row the run finished with.

    Split from `load_runs` for one caller: `r2t.bench.results` scores only the
    PASSED subset of a run, and the checks below are about rows that would
    enter an aggregate.  Refusing a whole file because an item that returned
    no submission was also recorded without coverage would withhold a number
    the surviving rows fully support — so that caller reads here and calls
    `check_scorable` on the subset it actually averages.  Every other caller
    scores the whole file and must keep using `load_runs`.
    """
    rows: dict[str, dict] = {}
    labels = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            rows[row["item_id"]] = row
            labels.add(row.get("sensitivity"))
    # A labelled post-hoc sensitivity re-execution is never scored together
    # with, or in place of, the primary observations it re-executes.
    if len(labels) > 1:
        raise MetricsInputError(
            f"{path} mixes sensitivity labels {sorted(map(str, labels))}; a sensitivity "
            f"re-execution and the primary rows are separate run files")
    return rows


def check_scorable(rows: dict[str, dict], path: str) -> None:
    """Refuse the two conditions that would silently deflate every similarity.

    Raises `MetricsInputError`; returns None when the rows are scorable.
    """
    # ANY such row, not only an all-such file.  A row stamped coverage=false
    # carries no coverage block, so it reads UNDEFINED and is substituted with
    # the worst score — charging the system for a harness setting.  In a MIXED
    # file that is invisible, because the undefined-reason breakdown prints the
    # row's OUTCOME: an item that passed cleanly without coverage appears as
    # "undefined: passed" and quietly drags the aggregate down.
    off = sorted(iid for iid, r in rows.items() if r.get("coverage") is False)
    if off:
        raise MetricsInputError(
            f"{path}: {len(off)} of {len(rows)} row(s) are stamped "
            f"coverage=false (e.g. {off[0]}), so they recorded no coverage "
            f"block. Every one would score UNDEFINED and the aggregate would "
            f"read a harness setting, not the system. Re-run with --coverage.")
    # `coverage_mismatch` is the runner's own witness that the recorder's
    # per-file line COUNTS disagreed with the per-line data kept beside them —
    # i.e. lines were lost while the block still looked collected.  Every
    # similarity below would be deflated by exactly what was lost, with no
    # other symptom, so such a row is refused rather than scored.
    bad = sorted(iid for iid, r in rows.items() if r.get("coverage_mismatch"))
    if bad:
        raise MetricsInputError(
            f"{path}: {len(bad)} row(s) carry a non-empty 'coverage_mismatch' "
            f"(e.g. {bad[0]}): the recorder's per-file line counts disagree "
            f"with the lines kept for them, so coverage data was lost between "
            f"the recorder and the run file. Scoring them would understate "
            f"every similarity.")


def load_runs(path: str) -> dict[str, dict]:
    """Read a run file and refuse it if its rows are not scorable.

    The whole-file path, and what every caller that aggregates over a whole
    run must use.  `read_runs` + `check_scorable` is the same thing with the
    seam exposed, for the one caller that aggregates over a subset.
    """
    rows = read_runs(path)
    check_scorable(rows, path)
    return rows


def load_items(path: str) -> list[str]:
    """Item ids from a release file — used to pin the `over_total` denominator."""
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line)["item_id"])
    return out


@dataclass(frozen=True)
class Method:
    """One declared method, with its source span and direct-call identity."""
    fqcn: str
    name: str
    start: int
    end: int
    public: bool
    static: bool = False
    abstract: bool = False
    #: The DECLARATION line -- the first decorator where there is one -- which
    #: is what a call event reports and what tells a setter from its getter.
    #: `start` is the first body statement, a different line on every
    #: decorated method.  Optional: the PHP index carries no `decl` and joins
    #: on `start`, which is already its declaration line.
    decl: Optional[int] = None
    #: Java's JVM descriptor distinguishes overloads; Python/PHP omit it.
    descriptor: Optional[str] = None
    method_kind: Optional[str] = None

    @property
    def key(self) -> tuple:
        if self.method_kind is not None:
            return self.fqcn, self.method_kind, self.name
        name = (f"{self.name}:{self.descriptor}"
                if self.descriptor is not None else self.name)
        return (self.fqcn, name)


@dataclass(frozen=True)
class Accessor:
    """An installed property binding, separate from ordinary method spans."""
    fqcn: str
    attribute: str
    access_kind: str
    declaring_line: int
    public: bool

    @property
    def key(self) -> tuple[str, str]:
        suffix = {"get": "", "set": ".setter", "delete": ".deleter"}
        return self.fqcn, self.attribute + suffix[self.access_kind]


class ProductionIndex(dict[str, list[Method]]):
    """Method mapping plus separately indexed accessor identities.

    Keeping accessors outside the method lists prevents them entering any
    body-span or nested-function lookup. The input schema survives loading
    so a historical Python index cannot claim accessor completeness.
    """

    def __init__(self, *args, schema=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.schema = schema
        self.accessors: dict[tuple[str, int, str, str, str], Accessor] = {}
        self.ruby_bindings: dict[tuple, Method] = {}


def load_prod_index(path: str) -> ProductionIndex:
    """Read the method index into {relative path: [Method, ...]}.

    Java's `descriptor` is retained for its exact runtime-identity join.

    Accepts either the `{"root":..., "files": {...}}` envelope the PHP
    indexer emits or a bare {path: entry} mapping, and either
    `{"classes": [...]}` or a bare class list per file.  It does NOT
    accept a method without `name`/`start`/`end`/`public`: those four are
    what the metric is defined over, and defaulting any of them would
    silently change which methods count.  `decl` is read where present and
    is never required -- `refuse_stale_python_index` is the check for a
    PYTHON index that has it nowhere, applied where the index is used for
    API mapping and not here, so that a caller scoring coverage alone never
    trips over an index it does not read.
    """
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    files = doc.get("files") if isinstance(doc, dict) and "files" in doc else doc
    if not isinstance(files, dict):
        raise MetricsInputError(
            f"{path}: expected a mapping of file path -> classes (optionally "
            f"under a top-level 'files' key), got {type(files).__name__}")

    index = ProductionIndex(schema=doc.get("schema"))
    for rel, entry in files.items():
        classes = entry.get("classes") if isinstance(entry, dict) else entry
        if classes is None:
            raise MetricsInputError(f"{path}: {rel} has no 'classes'")
        methods: list[Method] = []
        for cls in classes:
            fqcn = cls.get("name")
            if fqcn is None:
                raise MetricsInputError(f"{path}: {rel} has a class with no 'name'")
            if "methods" not in cls:
                raise MetricsInputError(
                    f"{path}: class {fqcn} ({rel}) has no 'methods' — this index "
                    f"predates the method spans ApiCallSimilarity is defined over; "
                    f"rebuild it before scoring.")
            for m in cls["methods"] or []:
                missing = [k for k in ("name", "start", "end", "public")
                           if k not in m]
                if missing:
                    raise MetricsInputError(
                        f"{path}: method {fqcn}::{m.get('name', '?')} is missing "
                        f"{missing}")
                if index.schema == RUBY_PROD_INDEX_SCHEMA:
                    if (m.get("method_kind") not in {"instance", "singleton"}
                            or not isinstance(fqcn, str) or not fqcn
                            or not isinstance(m.get("name"), str) or not m["name"]
                            or not isinstance(m.get("public"), bool)
                            or any(type(m.get(k)) is not int or m[k] <= 0 for k in ("start", "end", "decl"))
                            or m["end"] < m["start"] or not rel.endswith(".rb")):
                        raise MetricsInputError(f"{path}: invalid Ruby method binding in {fqcn} ({rel})")
                methods.append(Method(
                    fqcn=fqcn, name=m["name"],
                    start=int(m["start"]), end=int(m["end"]),
                    public=bool(m["public"]),
                    static=bool(m.get("static", False)),
                    abstract=bool(m.get("abstract", False)),
                    decl=(int(m["decl"]) if m.get("decl") is not None
                          else None),
                    descriptor=m.get("descriptor"),
                    method_kind=m.get("method_kind") if index.schema == RUBY_PROD_INDEX_SCHEMA else None))
                if index.schema == RUBY_PROD_INDEX_SCHEMA:
                    method = methods[-1]
                    identity = (_norm(rel), method.decl, fqcn, method.method_kind, method.name)
                    if identity in index.ruby_bindings:
                        raise MetricsInputError(f"{path}: duplicate Ruby binding {identity}")
                    index.ruby_bindings[identity] = method
            if index.schema == PYTHON_PROD_INDEX_SCHEMA:
                accessors = cls.get("accessors")
                if not isinstance(accessors, list):
                    raise MetricsInputError(
                        f"{path}: class {fqcn} ({rel}) lacks its schema-2 accessors list")
                for accessor in accessors:
                    required = {"declaring_line", "attribute", "access_kind", "public"}
                    if not isinstance(accessor, dict) or set(accessor) != required \
                            or not isinstance(accessor["declaring_line"], int) \
                            or accessor["declaring_line"] <= 0 \
                            or not isinstance(accessor["attribute"], str) \
                            or not accessor["attribute"] \
                            or accessor["access_kind"] not in {"get", "set", "delete"} \
                            or not isinstance(accessor["public"], bool):
                        raise MetricsInputError(
                            f"{path}: invalid accessor binding in {fqcn} ({rel})")
                    binding = Accessor(fqcn=fqcn, **accessor)
                    identity = (_norm(rel), binding.declaring_line, fqcn,
                                binding.attribute, binding.access_kind)
                    if identity in index.accessors:
                        raise MetricsInputError(f"{path}: duplicate accessor binding {identity}")
                    index.accessors[identity] = binding
        index[_norm(rel)] = methods
    return index


def refuse_stale_python_index(index: dict[str, list[Method]],
                              path: Optional[str] = None) -> None:
    """Require Python declaration lines and the schema-2 accessor inventory.

    Such an index joins on the body's first statement, which is never a
    declaration line: every callee would come back unmapped, and an
    all-unmapped run reads exactly like a test that called nothing.  Refused
    rather than scored 0.0 -- by `direct_methods` where the index is used,
    and once up front by `r2t.bench.results`, which withholds the API rows
    alone on it while coverage, which never reads the index, keeps scoring.
    A PHP index carries no `decl` and is not a Python index; it passes.
    A schema-2 class with accessors only needs no ordinary method span.
    """
    python_methods = [m for rel, methods in index.items()
                      if rel.endswith(".py") for m in methods]
    if python_methods and not any(m.decl is not None for m in python_methods):
        raise MetricsInputError(
            f"{path + ': ' if path else ''}this production index carries no "
            f"`decl` line on any method; a stale Python index maps every "
            f"callee unmapped and looks like a test that called nothing; "
            f"rebuild it with r2t.py.prod_index before scoring the API rows.")
    if any(rel.endswith(".py") for rel in index) \
            and getattr(index, "schema", None) != PYTHON_PROD_INDEX_SCHEMA:
        raise MetricsInputError(
            f"{path + ': ' if path else ''}API Amendment 2 requires "
            f"{PYTHON_PROD_INDEX_SCHEMA}; a historical Python index does not "
            "establish generated-accessor identities. Rebuild the index; "
            "compatible new recordings are also required.")


# --------------------------------------------------------------------------
# per-run views

def production_lines(rec: Optional[dict],
                     boundary: Boundary) -> Optional[dict[str, set[int]]]:
    """Covered production lines of one run, or None when the run has no block.

    None is the UNDEFINED signal and means "the scenario never reached
    `@AfterScenario`" — categorically different from an empty mapping,
    which means "it got there and covered no production line".
    """
    if rec is None:
        return None
    if COVERAGE_FIELD not in rec:
        raise MetricsInputError(
            f"run record {rec.get('item_id', '?')} has no '{COVERAGE_FIELD}' "
            f"field. The metrics are defined over per-scenario line coverage; "
            f"a record without it was produced by a harness that discarded the "
            f"line data (or by a run without --coverage).")
    cov = rec[COVERAGE_FIELD]
    if cov is None:
        return None
    return {_norm(f): {int(x) for x in lines}
            for f, lines in cov.items()
            if boundary.classify(_norm(f)) == PRODUCTION}


def direct_record_issue(rec: Optional[dict], index: dict) -> Optional[str]:
    """Why recorded calls cannot supply the approved API set, if anything.

    The Python marker comes from the recorder, not the coordinator: a new
    coordinator can still execute an old seed whose empty event list lacks
    X1 evidence. Raw per-scenario records need no item-fold stamp; emitted
    multi-record Python/PHP items need the harness that performs O1. Java
    already collected the complete fork-wide union before this amendment.
    """
    if rec is None or rec.get(DIRECT_CALLS_FIELD) is None:
        return "without_direct_calls"
    ruby = getattr(index, "schema", None) == RUBY_PROD_INDEX_SCHEMA or any(path.endswith(".rb") for path in index)
    if ruby:
        if getattr(index, "schema", None) != RUBY_PROD_INDEX_SCHEMA:
            raise MetricsInputError("Ruby API scoring requires r2t.rb_prod_index/1")
        if rec.get("direct_calls_schema") not in RUBY_DIRECT_CALLS_SCHEMAS \
                or not isinstance(rec[DIRECT_CALLS_FIELD], list):
            return "before_api_amendment_3"
        for event in rec[DIRECT_CALLS_FIELD]:
            required = {"callee_file", "callee_line", "callee", "caller_file", "ruby_binding", "ruby_binding_issue"}
            if not isinstance(event, dict) or not required <= event.keys():
                return "before_api_amendment_3"
            if (not isinstance(event["callee"], str)
                    or any(event[k] is not None and not isinstance(event[k], str) for k in ("callee_file", "caller_file"))
                    or (event["callee_line"] is not None and type(event["callee_line"]) is not int)):
                return "before_api_amendment_3"
            binding = event["ruby_binding"]
            if binding is None:
                if event["ruby_binding_issue"] not in {"generated_method", "unresolved_declaration"}:
                    return "before_api_amendment_3"
            elif (not isinstance(binding, dict)
                  or set(binding) != {"declaring_file", "declaring_line", "owner", "method_kind", "method_name"}
                  or event["ruby_binding_issue"] is not None
                  or any(not isinstance(binding[k], str) or not binding[k] for k in ("declaring_file", "owner", "method_kind", "method_name"))
                  or binding["method_kind"] not in {"instance", "singleton"}
                  or type(binding["declaring_line"]) is not int or binding["declaring_line"] <= 0
                  or not binding["declaring_file"].endswith(".rb")
                  or binding["declaring_file"] != event["callee_file"]
                  or binding["declaring_line"] != event["callee_line"]):
                return "before_api_amendment_3"
        return None
    python = any(path.endswith(".py") for path in index)
    if python:
        if rec.get("direct_calls_schema") not in PYTHON_DIRECT_CALLS_SCHEMAS \
                or any("accessor_binding" not in event
                       for event in rec[DIRECT_CALLS_FIELD]):
            return "before_api_amendment_2"
        if any(field in rec for field in ("item_id", "record_count", "harness_version")) and (
                not isinstance(rec.get("harness_version"), int)
                or rec["harness_version"] < OUTLINE_UNION_HARNESS_VERSION):
            return "before_api_amendment_2"
    if rec.get("record_count", 1) > 1 \
            and not any(path.endswith(".java") for path in index) \
            and (not isinstance(rec.get("harness_version"), int)
                 or rec["harness_version"] < OUTLINE_UNION_HARNESS_VERSION):
        return "before_api_amendment_2"
    return None


def direct_methods(rec: Optional[dict], boundary: Boundary,
                   index: dict[str, list[Method]]
                   ) -> Optional[tuple[set[tuple[str, str]], int]]:
    """Public production methods the TEST called, and the unmapped-event count.

    None means recording is absent or incompatible with the approved method,
    which differs from a complete empty set. Neither case derives API credit
    from coverage (API_DIRECT_INVOCATION_SPEC.md 2.6 and Amendment 2).

    An event is DIRECT when its callee's file classifies production and its
    caller's file classifies removable, i.e. the caller is part of the answer
    the system wrote.  Every other event — production calling production, the
    retained substrate, a caller with no source file — is ignored entirely
    and counted nowhere, which is what makes the second return value a
    diagnostic of the INDEX and of nothing else.

    Java joins the binary declaring class, name and descriptor encoded in
    `callee`; its null `callee_line` is never used as a source-line join.
    """
    if rec is None:
        return None
    events = rec.get(DIRECT_CALLS_FIELD)
    if events is None:
        return None
    refuse_stale_python_index(index)
    if direct_record_issue(rec, index) is not None:
        return None
    pairs: set[tuple] = set()
    unmapped = 0
    ruby = getattr(index, "schema", None) == RUBY_PROD_INDEX_SCHEMA
    for event in events:
        callee = event["callee"]
        if event["callee_file"] is None:
            continue
        callee_file = _norm(event["callee_file"])
        java = callee_file.endswith(".java")
        # Module bodies, lambdas and comprehensions are not method
        # activations, and their names are written in angle brackets (2.3).
        # Java's public <init> IS credited; <clinit> is not (2.2).
        name = callee.split(":", 1)[0] if java else callee
        name = name.rsplit(".", 1)[-1]
        if not ruby and name.startswith("<") and not (java and name == "<init>"):
            continue
        caller_file = event["caller_file"]
        if boundary.classify(callee_file) != PRODUCTION:
            continue
        if not isinstance(caller_file, str) \
                or boundary.classify(_norm(caller_file)) != REMOVABLE:
            continue
        if ruby:
            binding = event["ruby_binding"]
            identity = tuple(binding[k] for k in ("declaring_file", "declaring_line", "owner", "method_kind", "method_name")) if binding else None
            method = index.ruby_bindings.get(identity)
            if method is None:
                unmapped += 1
            elif method.public:
                pairs.add(method.key)
            continue
        binding = event.get("accessor_binding") if callee_file.endswith(".py") else None
        if binding is not None:
            try:
                declaring_file = _norm(binding["declaring_file"])
                identity = (declaring_file, binding["declaring_line"],
                            binding["owner"], binding["attribute"], binding["access_kind"])
                accessor = index.accessors.get(identity)
            except (KeyError, TypeError, AttributeError):
                # Incomplete binding evidence is not an empty measured set.
                return None
            if boundary.classify(declaring_file) != PRODUCTION:
                continue
            if accessor is None:
                unmapped += 1
            elif accessor.public:
                pairs.add(accessor.key)
            continue
        line = event["callee_line"]
        methods = index.get(callee_file, ())
        if java:
            exact = [m for m in methods if m.descriptor is not None
                     and f"{m.fqcn}.{m.name}:{m.descriptor}" == callee]
        else:
            exact = [m for m in methods
                     if (m.decl if m.decl is not None else m.start) == line]
        if exact:
            # A non-public exact match is MAPPED and not credited: the index
            # knows that method and the definition excludes it.  Counting it
            # unmapped would report a private call as a gap in the index.
            pairs.update(m.key for m in exact if m.public)
        elif not java and "<locals>" in callee:
            # A named nested function has no index entry of its own and folds
            # to the innermost method whose span holds it, as the index folds
            # its lines (2.3).
            enclosing = [m for m in methods if m.start <= line <= m.end]
            if not enclosing:
                unmapped += 1
            else:
                fold = max(enclosing, key=lambda m: m.start)
                if fold.public:
                    pairs.add(fold.key)
        elif callee_file.endswith(".php"):
            # PHP reflection reports a method's `function` line, while the
            # index starts an attributed method on its `#[...]` line -- eight
            # methods on the pinned CoreShop index, two of them executed by
            # 81 and 87 of the 100 eval100 gold items -- so the join takes the
            # index method whose span holds the reflected line (2.3).  PHP
            # only: a Python callee's `co_firstlineno` IS the index's `decl`,
            # and a body line there is a stale index, not an attribute.
            spanning = [m for m in methods if m.start <= line <= m.end]
            if not spanning:
                unmapped += 1
            else:
                hit = max(spanning, key=lambda m: m.start)
                if hit.public:
                    pairs.add(hit.key)
        else:
            unmapped += 1
    return pairs, unmapped


# --------------------------------------------------------------------------
# the metrics

def _jaccard(a: set, b: set) -> float:
    union = a | b
    # Both empty is an identity, not a disagreement — this is what keeps the
    # gold-vs-gold self-check at exactly 1.0 on items whose gold covers
    # nothing.  Such items are flagged degenerate by `compare`.
    return (len(a & b) / len(union)) if union else 1.0


def coverage_similarity(gold: dict[str, set[int]],
                        sys_: dict[str, set[int]]) -> dict:
    """CoverageSimilarity over (file, line) pairs — see the module docstring."""
    lg = {(f, ln) for f, lines in gold.items() for ln in lines}
    ls = {(f, ln) for f, lines in sys_.items() for ln in lines}
    inter, union = lg & ls, lg | ls
    per_file = [_jaccard(gold.get(f, set()), sys_.get(f, set()))
                for f in set(gold) | set(sys_)
                if gold.get(f) or sys_.get(f)]
    return {
        "recall": (len(inter) / len(lg)) if lg else 1.0,
        # `excess` is 0/0 when the system covered no production line, and 0.0
        # is excess's BEST score — so the arithmetic reading of 0/0 hands a
        # perfect precision number to a system that ran nothing.  This is not
        # hypothetical: on CoreShop an adapter returning NO files still
        # reaches `@AfterScenario` (the steps are merely undefined), and a
        # context of syntactically valid step definitions with EMPTY bodies
        # PASSES the scenario; both cover zero production lines and both
        # scored `cov.excess` 0.000.  Empty-with-a-non-empty-gold is therefore
        # the WORST value, which is what `api_call_similarity` already does
        # for the same situation (`precision` 0.0).  Both sides empty stays
        # 0.0, the identity `gold_self_check` needs; `compare` flags it.
        "excess": (len(ls - lg) / len(ls)) if ls else (0.0 if not lg else 1.0),
        "micro_jaccard": (len(inter) / len(union)) if union else 1.0,
        "macro_jaccard": statistics.mean(per_file) if per_file else 1.0,
    }


def api_call_similarity(gold: set[tuple[str, str]],
                        sys_: set[tuple[str, str]]) -> dict:
    """ApiCallSimilarity over (fqcn, public method) pairs.

    Empty system side scores 0.0 — a run that called no public production
    method matched nothing, whatever else it did.  Both sides empty is the
    identity 1.0, kept for the two-set function's own sake; `compare` never
    reaches it, because an empty gold set is unscorable (3.1) and gets no
    `api` block at all.
    """
    if not gold and not sys_:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    inter = gold & sys_
    p = (len(inter) / len(sys_)) if sys_ else 0.0
    r = (len(inter) / len(gold)) if gold else 1.0
    return {"precision": p, "recall": r,
            "f1": (2 * p * r / (p + r)) if (p + r) else 0.0}


# --------------------------------------------------------------------------
# the checked-interface secondary metrics (TARGET_INTERFACES_V2_SPEC 6.2)
#
# Both are SECONDARY: they restrict one of the two existing metrics to a
# region the study declares in advance -- the reviewed target bodies for
# coverage, the calls the item did NOT disclose for the API set -- and
# neither replaces the row it narrows.  Both are pure set functions here;
# where the region and the disclosed list come from is the caller's business
# (`toolkit.target_regions` and the item's `checked_interfaces` field), so
# this module acquires no parser and no release reader.

#: The item is in the API population and its whole gold set was disclosed, so
#: `D_G \ I` is empty and there is nothing left to agree about.  It is the
#: `gold_no_methods` case one subtraction later, and it is a reason token for
#: the same reason: an empty gold side is an identity every candidate gets
#: for free (`api_call_similarity` returns 1.0 for two empty sets).
UNDISCLOSED_FULLY_DISCLOSED = "gold_no_undisclosed_methods"

#: The item's gold run covered no line of its reviewed target region, so the
#: region-recall denominator is empty.  Counted and named, never scored 1.0
#: by the empty-set identity: an item whose gold never entered the region
#: says nothing about whether a candidate reached it.
REGION_NO_GOLD_LINES = "gold_covers_no_region_line"


#: The two offline artifacts the section 6 secondary rows read, and their
#: readers.  Both are WRITTEN by a toolkit verb that needs a language parser
#: (`toolkit.target_regions`) or the whole gold corpus
#: (`toolkit.control_floors`); both are READ here, so the consumer route --
#: `core + data + bench`, which is what the benchmark-only mirror ships --
#: can render the rows without acquiring either dependency.  One home for
#: each schema string: the producer imports it from this module.
TARGET_REGIONS_SCHEMA = "r2t.target-regions/1"
CONTROL_FLOORS_SCHEMA = "r2t.control-floors/1"


def _load_artifact(path: str, schema: str) -> dict:
    with open(path, encoding="utf-8") as stream:
        doc = json.load(stream)
    if doc.get("schema") != schema:
        raise MetricsInputError(
            f"{path}: expected {schema}, got {doc.get('schema')!r}")
    return doc


def load_target_regions(path: str) -> dict[str, dict[str, set[int]]]:
    """`{item_id: {path: {lines}}}` from a `r2t.target-regions/1` artifact."""
    doc = _load_artifact(path, TARGET_REGIONS_SCHEMA)
    return {item_id: {p: {int(n) for n in lines}
                      for p, lines in region.items()}
            for item_id, region in doc["items"].items()}


def load_control_floors(path: str) -> dict:
    """A `r2t.control-floors/1` table, as written, for rendering beside rows."""
    return _load_artifact(path, CONTROL_FLOORS_SCHEMA)


def index_method_keys(index: dict[str, list[Method]]) -> set[tuple]:
    """Every `Method.key` the production index knows, accessors included.

    The key space the disclosed list is subtracted in.  Built from the index
    rather than from the gold set, because a disclosed entry the index does
    not know is a mint-time error that must be refused -- and an entry gold
    merely did not call is not.
    """
    keys = {m.key for methods in index.values() for m in methods}
    keys |= {a.key for a in getattr(index, "accessors", {}).values()}
    keys |= {m.key for m in getattr(index, "ruby_bindings", {}).values()}
    return keys


def undisclosed_api(gold: set[tuple], sys_: set[tuple],
                    disclosed: Iterable[tuple],
                    index_keys: set[tuple]) -> dict:
    """ApiCallSimilarity over `D_G \\ I` against `D_C \\ I` (spec 6.2).

    `I` is the item's disclosed list -- the `key` of every entry in its
    `checked_interfaces` field -- and the subtraction is an exact tuple
    match against the SAME key space `direct_methods` produces.  That is
    why a disclosed entry which is not a key of the pinned index REFUSES
    here: a list of type names, of `Class::method` strings, or of JSON lists
    would subtract nothing at all, and the row would then be the ordinary
    API row wearing a label that says the disclosed calls were removed.
    Silently scoring the wrong thing is the one outcome this row cannot
    survive, so the shape is checked once, loudly, on the way in.

    An item with nothing left on the gold side is UNSCORED with a reason,
    exactly as `compare` leaves `gold_no_methods` out of the API rows.
    """
    # Consume the argument ONCE, before anything iterates it: a generator read
    # by the shape check below would leave `set(...)` empty, subtract nothing
    # and print the ordinary API row under this row's label -- the exact
    # silence the shape check exists to prevent.  The set is built after that
    # check, so an unhashable key is refused by shape, not by `TypeError`.
    keys = tuple(disclosed)
    bad_shape = [k for k in keys
                 if not isinstance(k, tuple)
                 or not all(isinstance(part, str) for part in k)]
    if bad_shape:
        raise MetricsInputError(
            f"REFUSED: {len(bad_shape)} disclosed interface key(s) are not "
            f"tuples of strings, e.g. {bad_shape[0]!r}. The undisclosed-API "
            f"row subtracts them from the direct-call set by exact tuple "
            f"match; a differently shaped key subtracts nothing and would "
            f"report the ordinary API row under this row's label.")
    disclosed = set(keys)
    unknown = sorted(k for k in disclosed if k not in index_keys)
    if unknown:
        raise MetricsInputError(
            f"REFUSED: {len(unknown)} disclosed interface key(s) are absent "
            f"from the pinned production index, e.g. {unknown[0]!r}. The "
            f"disclosed list and the API set must be in one key space; a key "
            f"the index does not know cannot be a method the gold test "
            f"called, so subtracting it is a no-op that hides a stale list.")
    gold_rest, sys_rest = set(gold) - disclosed, set(sys_) - disclosed
    counts = {"gold_methods": len(gold), "sys_methods": len(sys_),
              "disclosed": len(disclosed),
              "gold_undisclosed": len(gold_rest),
              "sys_undisclosed": len(sys_rest),
              "shared_undisclosed": len(gold_rest & sys_rest)}
    if not gold_rest:
        return {"scored": False, "reason": UNDISCLOSED_FULLY_DISCLOSED,
                "api": None, "counts": counts}
    return {"scored": True, "reason": None,
            "api": api_call_similarity(gold_rest, sys_rest), "counts": counts}


def target_region_recall(gold: dict[str, set[int]], sys_: dict[str, set[int]],
                         region: dict[str, set[int]]) -> dict:
    """Recall of GOLD's covered lines inside the item's target region (6.2).

    The denominator is `gold's covered lines INTERSECT the region`, not the
    region's executable lines: the question is whether the candidate drove
    the target behaviour gold drove, and a region line gold itself never
    executed is not evidence about the candidate either way.  The price is
    that an item whose gold covers no region line has an empty denominator;
    it is `not_scorable` and named, never the 1.0 the empty-set identity
    would hand out (`coverage_similarity` documents that trap).

    `reaches_target` is the per-item flag section 6.2 asks for beside the
    mean: the candidate covered ALL of gold's region lines, not merely some.
    """
    lg = {(f, ln) for f, lines in gold.items()
          for ln in lines & set(region.get(f, ()))}
    if not lg:
        return {"scorable": False, "reason": REGION_NO_GOLD_LINES,
                "recall": None, "reaches_target": None,
                "n_gold_region_lines": 0, "n_covered": 0}
    ls = {(f, ln) for f, lines in sys_.items() for ln in lines}
    covered = lg & ls
    return {"scorable": True, "reason": None,
            "recall": len(covered) / len(lg),
            "reaches_target": covered == lg,
            "n_gold_region_lines": len(lg), "n_covered": len(covered)}


def undefined_reason(rec: Optional[dict]) -> str:
    if rec is None:
        return "no_submission"
    return rec.get("outcome") or "no_coverage_block"


def _comparison_lines(gold_rec: dict, sys_rec: Optional[dict],
                      boundary: Boundary):
    """The production-line inputs shared by coverage and API comparison."""
    gold_lines = production_lines(gold_rec, boundary)
    if gold_lines is None:
        raise MetricsInputError(
            f"gold run for {gold_rec.get('item_id', '?')} has no coverage "
            f"block (outcome={gold_rec.get('outcome')!r}); the item has no "
            f"upper bound to measure against and must be excluded, not "
            f"scored.")
    sys_lines = production_lines(sys_rec, boundary)
    item_id = gold_rec.get("item_id") or (sys_rec or {}).get("item_id")
    return item_id, gold_lines, sys_lines


def compare_coverage(gold_rec: dict, sys_rec: Optional[dict],
                     boundary: Boundary) -> dict:
    """Coverage comparison for one item, with no method-index dependency."""
    item_id, gold_lines, sys_lines = _comparison_lines(
        gold_rec, sys_rec, boundary)
    defined = sys_lines is not None
    return {
        "item_id": item_id,
        "defined": defined,
        "undefined_reason": None if defined else undefined_reason(sys_rec),
        "gold_empty_coverage": not any(gold_lines.values()),
        "counts": {
            "gold_lines": sum(len(v) for v in gold_lines.values()),
            "sys_lines": (sum(len(v) for v in sys_lines.values())
                          if defined else 0),
            "gold_files": len(gold_lines),
            "sys_files": len(sys_lines) if defined else 0,
        },
        "coverage": (coverage_similarity(gold_lines, sys_lines)
                     if defined else None),
    }


def compare(gold_rec: dict, sys_rec: Optional[dict],
            prod_index: dict[str, list[Method]], boundary: Boundary) -> dict:
    """Both metrics for one item, or an UNDEFINED verdict with the reason why.

    A gold record without a coverage block is not an undefined item, it is
    a broken upper bound: without it there is nothing to compare against,
    so it raises rather than scoring the system 0.0 for the harness's
    failure.

    Two axes, gated separately.  `defined` is about the coverage block;
    `api_defined` is about `direct_calls`, on either side, and it is where
    2.6 is decided once per item.  An item excluded on the API axis LEAVES
    every API denominator instead of being substituted with the worst score,
    because a missing recorder is the harness's gap and not the candidate's
    (3.3); a candidate that crashed is still substituted, as before.
    """
    item_id, gold_lines, sys_lines = _comparison_lines(
        gold_rec, sys_rec, boundary)
    defined = sys_lines is not None
    index_error = None
    try:
        gold_direct = direct_methods(gold_rec, boundary, prod_index)
        sys_direct = (direct_methods(sys_rec, boundary, prod_index)
                      if defined else None)
    except MetricsInputError as exc:
        # Index compatibility is an API concern at this combined entry
        # point too. The standalone metrics report must still return its
        # coverage numbers, just as results.behaviour does.
        index_error = str(exc)
        gold_direct = sys_direct = None
    api_defined = (defined and gold_direct is not None
                   and sys_direct is not None)
    gold_methods = gold_direct[0] if gold_direct is not None else set()
    sys_methods = sys_direct[0] if sys_direct is not None else set()
    # False, not True, where gold carries no `direct_calls`: nobody looked,
    # so "its test called nothing" is not something this row can say.
    gold_no_methods = gold_direct is not None and not gold_methods
    if index_error is not None:
        api_undefined_reason = "invalid_production_index"
    elif api_defined:
        api_undefined_reason = None
    elif gold_direct is None:
        api_undefined_reason = "gold_" + (
            direct_record_issue(gold_rec, prod_index) or "before_api_amendment_2")
    elif not defined:
        api_undefined_reason = undefined_reason(sys_rec)
    else:
        api_undefined_reason = "run_" + (
            direct_record_issue(sys_rec, prod_index) or "before_api_amendment_2")

    return {
        "item_id": item_id,
        "defined": defined,
        "undefined_reason": None if defined else undefined_reason(sys_rec),
        "api_defined": api_defined,
        "api_undefined_reason": api_undefined_reason,
        "api_index_error": index_error,
        # An item whose gold side is empty is an identity for every system:
        # it discriminates nothing and inflates every aggregate it enters.
        "gold_empty_coverage": not any(gold_lines.values()),
        "gold_no_methods": gold_no_methods,
        # Coverage FLAGS its degenerate item and still scores it; the API
        # axis excludes it, together with the two ways `direct_calls` can be
        # missing.  A plain undefined run is not here: it is substituted.
        "api_excluded": (api_undefined_reason in API_RECORD_EXCLUSIONS + RUBY_API_RECORD_EXCLUSIONS
                         or gold_no_methods),
        "counts": {
            "gold_lines": sum(len(v) for v in gold_lines.values()),
            "sys_lines": (sum(len(v) for v in sys_lines.values())
                          if defined else 0),
            "gold_files": len(gold_lines),
            "sys_files": len(sys_lines) if defined else 0,
            "gold_methods": len(gold_methods),
            "sys_methods": len(sys_methods),
            "shared_methods": len(gold_methods & sys_methods),
            "gold_unmapped": gold_direct[1] if gold_direct is not None else 0,
            "sys_unmapped": sys_direct[1] if sys_direct is not None else 0,
        },
        "coverage": (coverage_similarity(gold_lines, sys_lines)
                     if defined else None),
        "api": (api_call_similarity(gold_methods, sys_methods)
                if api_defined and not gold_no_methods else None),
    }


def scorable_gold(gold_runs: dict[str, dict],
                  boundary: Boundary) -> tuple[dict[str, dict], dict[str, str]]:
    """Split gold into items that have an upper bound and items that do not.

    `compare` refuses a gold record with no coverage block, and it is right
    to: that item has nothing to measure against.  But refusing there means
    ONE flaky gold item — a timeout in a 422-item sweep — makes every system
    unscoreable, and the obvious workaround (drop it by hand) changes the
    denominator per run, so two systems stop being comparable.  Partitioned
    once here instead, so the same exclusion applies to every run and gets
    printed rather than absorbed.
    """
    ok, dropped = {}, {}
    for iid, rec in gold_runs.items():
        if production_lines(rec, boundary) is None:
            dropped[iid] = rec.get("outcome") or "no_coverage_block"
        else:
            ok[iid] = rec
    return ok, dropped


def compare_runs(gold_runs: dict[str, dict], sys_runs: dict[str, dict],
                 prod_index: dict[str, list[Method]], boundary: Boundary,
                 item_ids: Optional[Iterable[str]] = None) -> list[dict]:
    """Compare every scored item.  Default denominator: the attempted set.

    `item_ids` pins the `over_total` denominator (pass the release ids to
    score a partial run against the whole benchmark).  Without it the
    denominator is gold ∩ system, i.e. what this run actually attempted —
    the honest default for a probe over a subset, and the reason the CLI
    prints how many gold items were left out.  A system row with no gold
    row raises: there is nothing to score it against.
    """
    orphans = sorted(set(sys_runs) - set(gold_runs))
    if orphans:
        raise MetricsInputError(
            f"{len(orphans)} run row(s) have no gold row, e.g. {orphans[0]} — "
            f"the gold run does not cover this run's item set.")
    ids = (list(item_ids) if item_ids is not None
           else sorted(set(gold_runs) & set(sys_runs)))
    # A pinned id with no gold row would otherwise be a bare KeyError, and
    # `--items` is exactly the flag someone reaches for when the gold run is
    # older than the release it is being scored against.
    missing = [i for i in ids if i not in gold_runs]
    if missing:
        raise MetricsInputError(
            f"{len(missing)} pinned item(s) have no scorable gold row, e.g. "
            f"{missing[0]} — they have no upper bound, so they cannot be part "
            f"of the denominator either.")
    return [compare(gold_runs[i], sys_runs.get(i), prod_index, boundary)
            for i in ids]


def _value(pair: dict, key: str) -> Optional[float]:
    group, name = key.split(".")
    block = pair.get(group)
    return None if block is None else block[name]


def summarise(pairs: list[dict]) -> dict:
    """Aggregate comparisons: conditional mean AND over_total, never one alone.

    `n_defined` travels with the conditional mean because the mean is
    unreadable without it, and `undefined_score` travels with `over_total`
    because the substituted value differs by metric polarity.

    The API rows carry their own population: an item excluded by 2.6 or 3.1
    is in NEITHER API aggregate, so `api.*` entries can report a smaller
    `n_items` than the coverage ones and the two are printed together.
    """
    n = len(pairs)
    defined = [p for p in pairs if p["defined"]]
    api_population = [p for p in pairs if not p["api_excluded"]]
    api_scored = [p for p in api_population if p["api"] is not None]
    metrics = {}
    for key in METRIC_KEYS:
        api = key.startswith("api.")
        scored = api_scored if api else defined
        items = len(api_population) if api else n
        vals = [_value(p, key) for p in scored]
        sub = UNDEFINED_SCORE[key]
        total = vals + [sub] * (items - len(scored))
        metrics[key] = {
            "mean_defined": statistics.mean(vals) if vals else None,
            "over_total": statistics.mean(total) if total else None,
            "n_defined": len(scored),
            "n_items": items,
            "undefined_score": sub,
            "higher_is_better": key != "coverage.excess",
        }
    return {
        "n_items": n,
        "n_defined": len(defined),
        "defined_rate": (len(defined) / n) if n else 0.0,
        "n_api_scored": len(api_scored),
        "n_gold_empty_coverage": sum(1 for p in pairs if p["gold_empty_coverage"]),
        "n_gold_no_methods": sum(1 for p in pairs if p["gold_no_methods"]),
        "api_excluded": {
            **{reason: sum(p["api_undefined_reason"] == reason for p in pairs)
               for reason in API_RECORD_EXCLUSIONS + tuple(
                   reason for reason in RUBY_API_RECORD_EXCLUSIONS
                   if any(p["api_undefined_reason"] == reason for p in pairs))},
            "gold_no_direct_methods": sum(1 for p in pairs
                                          if p["gold_no_methods"])},
        "api_index_errors": sorted({p["api_index_error"] for p in pairs
                                    if p.get("api_index_error")}),
        "undefined_reasons": _counts(p["undefined_reason"] for p in pairs
                                     if not p["defined"]),
        "unmapped_direct_events": {
            "gold": sum(p["counts"]["gold_unmapped"] for p in pairs),
            "sys": sum(p["counts"]["sys_unmapped"] for p in pairs)},
        "metrics": metrics,
    }


def _counts(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))


# --------------------------------------------------------------------------
# cluster-aware statistics
#
# Every interval and every test below resamples or collapses CLOSURE
# CLUSTERS (`release.closure_clusters`), because items are not independent
# draws: 422 items share 142 distinct gold closures, and a system's outcome
# on the 21 items behind one closure is very nearly one observation.  An
# interval over items would count those 21 as 21, and would be about that
# much too narrow.

#: The ONLY label a Wilson interval out of this module may be printed with.
#: It is a constant so the caller cannot paraphrase it into something that
#: reads like a claim about the corpus: this interval is the number you get
#: by PRETENDING items are independent, and it is printed beside the
#: cluster interval to show what that pretence buys.
WILSON_LABEL = "item-level, clusters ignored"

#: Two-sided 95% normal quantile.  Hard-coded rather than computed: there is
#: no scipy here and one constant is easier to audit than an inverse-erf.
Z_95 = 1.959963984540054

#: The default bootstrap seed.  Fixed and stated wherever a CI is printed, so
#: two people running the comparison get the same interval to the digit.
BOOTSTRAP_SEED = 20260802

#: The preregistered floor for an inferential closure-cluster analysis.  The
#: item-level and cluster-collapsed descriptive counts remain meaningful below
#: this floor; a confidence interval or paired p-value does not become more
#: informative because fifty correlated item rows sit behind five closures.
MIN_INFERENCE_CLUSTERS = 20


def wilson_interval(k: int, n: int, z: float = Z_95) -> tuple[float, float]:
    """Wilson score interval for k passes out of n — items treated as independent.

    Implemented by hand (stdlib only) and deliberately kept, even though the
    assumption behind it is false here: readers know this interval, and
    printing it beside the cluster bootstrap is how the correlation is made
    visible.  It must never be printed without `WILSON_LABEL`.

    Wilson rather than the normal approximation because the pass rates this
    benchmark produces are near zero (5/100, 2/100), where the Wald interval
    reaches below 0 and degenerates entirely at k=0.
    """
    if n <= 0:
        raise MetricsInputError(
            "REFUSED: a Wilson interval over n=0 items. There is no rate to "
            "bound; an empty denominator is a measurement that did not happen, "
            "not a rate of 0.0.")
    if not 0 <= k <= n:
        raise MetricsInputError(
            f"REFUSED: {k} passes out of {n} items is not a proportion.")
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    lo, hi = max(0.0, centre - half), min(1.0, centre + half)
    # At k=0 the algebra cancels to exactly 0 and floating point leaves ~7e-18
    # behind; the same at k=n for the upper bound.  Clamped, because a lower
    # bound printed as 0.000 should BE zero -- a reader who takes the tuple
    # rather than the rendering must not find a nonzero rate excluded.
    if k == 0:
        lo = 0.0
    if k == n:
        hi = 1.0
    return (lo, hi)


def _cluster_groups(values: dict[str, object],
                    cluster_map: dict[str, str]) -> dict[str, list]:
    """{cluster_id: [value, ...]}, refusing an item with no known closure.

    The grouping and its two refusals, once, for both resampling routines:
    the proportion bootstrap below coerces to `bool`, the mean bootstrap
    keeps the float, and neither owns a second copy of "which cluster is
    this item in, and what if nobody knows".
    """
    if not values:
        raise MetricsInputError(
            "REFUSED: no outcomes to resample. An empty item set has no rate.")
    missing = sorted(i for i in values if i not in cluster_map)
    if missing:
        raise MetricsInputError(
            f"REFUSED: {len(missing)} item(s) have no closure cluster (e.g. "
            f"{missing[0]}). Without its gold sidecar an item's correlation "
            f"with the rest of the corpus is unknown, and putting it in a "
            f"cluster of its own would assume the answer -- that it is "
            f"independent -- which is the very thing being measured.")
    groups: dict[str, list] = {}
    for iid, value in values.items():
        groups.setdefault(cluster_map[iid], []).append(value)
    return groups


def _cluster_members(outcomes: dict[str, bool],
                     cluster_map: dict[str, str]) -> dict[str, list[bool]]:
    """{cluster_id: [outcome, ...]}, refusing an item with no known closure."""
    return {cid: [bool(v) for v in vals]
            for cid, vals in _cluster_groups(outcomes, cluster_map).items()}


def _require_inference_floor(n_clusters: int, procedure: str) -> None:
    """Refuse an inferential procedure below the preregistered cluster floor."""
    if n_clusters < MIN_INFERENCE_CLUSTERS:
        raise MetricsInputError(
            f"REFUSED: {procedure} requires at least "
            f"{MIN_INFERENCE_CLUSTERS} distinct closure clusters; got "
            f"{n_clusters}. Items sharing one closure are correlated, so more "
            f"sibling rows do not add independent units of inference. "
            f"Descriptive item rates and cluster-collapsed tallies remain "
            f"available, but no inferential interval or p-value is produced.")


def require_inference_clusters(outcomes: dict[str, bool],
                               cluster_map: dict[str, str],
                               procedure: str = "cluster inference") -> int:
    """Validate and return the effective cluster count for an inference API.

    This public preflight lets a renderer refuse before printing a partial
    inferential table.  `cluster_bootstrap` and `mcnemar_cluster_collapsed`
    repeat the same check themselves, so calling a function directly cannot
    bypass the floor.
    """
    n_clusters = len(_cluster_members(outcomes, cluster_map))
    _require_inference_floor(n_clusters, procedure)
    return n_clusters


def _percentile(values: list[float], q: float) -> float:
    """Linear-interpolated percentile of an ALREADY SORTED list, q in [0, 1]."""
    if len(values) == 1:
        return values[0]
    pos = q * (len(values) - 1)
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return values[int(pos)]
    return values[lo] + (values[hi] - values[lo]) * (pos - lo)


def cluster_bootstrap(outcomes: dict[str, bool], cluster_map: dict[str, str],
                      n_boot: int = 10000, seed: int = BOOTSTRAP_SEED,
                      ) -> tuple[float, float]:
    """95% CI of the PASS RATE, resampling closure clusters with replacement.

    The cluster bootstrap: draw as many clusters as the item set has
    clusters, and take ALL of each drawn cluster's items — so a closure that
    twenty items share is resampled as the one thing it is.  The interval is
    the 2.5/97.5 percentiles of the resampled rates.

    The rate is recomputed per replicate as (passes drawn / items drawn),
    which lets the denominator wobble with the draw; that wobble is real, and
    fixing the denominator to the original item count would put the
    correlation back in by the back door.

    Deterministic: `random.Random(seed)` and nothing else, and the clusters
    are indexed in SORTED cluster-id order, so the draw sequence is a pure
    function of (data, seed).  Iterating `members` in dict order would leave
    it a function of the order the items happened to be inserted in as well,
    and the same outcomes read from a differently-ordered file would print a
    different interval -- which is exactly the reproducibility the seed
    printed beside the number is supposed to promise.

    One known degeneracy, which callers must SAY rather than hide: when no
    cluster passes (or all do), every resample has the same rate and the
    percentile interval collapses to a point.  That is not a claim that the
    rate is known to four decimals -- the nonparametric bootstrap simply
    cannot bound a boundary rate, because it can only ever redraw outcomes it
    has seen.  `cli compare` prints the collapse as a caveat beside the
    Wilson bound, which does stay informative there.
    """
    if n_boot < 1:
        raise MetricsInputError(
            f"REFUSED: n_boot={n_boot}. An interval needs resamples.")
    members = _cluster_members(outcomes, cluster_map)
    _require_inference_floor(len(members), "the cluster bootstrap")
    # (passes, items) per cluster, in sorted cluster-id order: a replicate is
    # then integer arithmetic, and `rnd.randrange(k)` indexes a list whose
    # contents AND order come from the data alone.  Each cluster's outcomes
    # are sorted too -- the pair below cannot depend on their order, and
    # sorting says so locally instead of leaving it to be argued.
    sizes = [(sum(1 for v in vals if v), len(vals))
             for vals in (sorted(members[cid]) for cid in sorted(members))]
    k = len(sizes)
    rnd = random.Random(seed)
    rates = []
    for _ in range(n_boot):
        passes = items = 0
        for _draw in range(k):
            p, n = sizes[rnd.randrange(k)]
            passes += p
            items += n
        rates.append(passes / items)
    rates.sort()
    return (_percentile(rates, 0.025), _percentile(rates, 0.975))


def cluster_bootstrap_mean(values: dict[str, float],
                           cluster_map: dict[str, str],
                           n_boot: int = 10000, seed: int = BOOTSTRAP_SEED,
                           ) -> tuple[float, float]:
    """95% CI of the MEAN of a per-item value, resampling closure clusters.

    `cluster_bootstrap` above bounds a proportion; the section 6.2 secondary
    rows are per-item means of a continuous value (target-region recall,
    undisclosed-API F1), and those needed an inference route of their own.
    Everything else is shared with the proportion routine on purpose: the
    same `_cluster_groups` refusals, the same preregistered 20-cluster floor,
    the same seed, the same sorted cluster order, the same percentiles, and
    the same wobbling denominator (mean over the items DRAWN, not over the
    original item count).  Only the numerator changes, from "passes" to "the
    sum of the drawn items' values".

    The known degeneracy is the same one, and callers must say it rather
    than hide it: where every cluster carries the same value, every resample
    reproduces it and the interval collapses to a point.
    """
    if n_boot < 1:
        raise MetricsInputError(
            f"REFUSED: n_boot={n_boot}. An interval needs resamples.")
    bad = sorted(i for i, v in values.items()
                 if isinstance(v, bool) or not isinstance(v, (int, float)))
    if bad:
        raise MetricsInputError(
            f"REFUSED: {len(bad)} item value(s) are not numbers (e.g. "
            f"{bad[0]}). This routine bounds the mean of a per-item "
            f"measurement; a boolean outcome belongs in `cluster_bootstrap`, "
            f"which bounds a proportion.")
    groups = _cluster_groups(values, cluster_map)
    _require_inference_floor(len(groups), "the cluster bootstrap of a mean")
    # (sum, count) per cluster in sorted cluster-id order, and each cluster's
    # values sorted before summing: the draw sequence AND the floating-point
    # sum are then functions of (data, seed) alone, never of the order the
    # items happened to be read in.
    sizes = [(math.fsum(vals), len(vals))
             for vals in (sorted(groups[cid]) for cid in sorted(groups))]
    k = len(sizes)
    rnd = random.Random(seed)
    means = []
    for _ in range(n_boot):
        total = 0.0
        items = 0
        for _draw in range(k):
            s, n = sizes[rnd.randrange(k)]
            total += s
            items += n
        means.append(total / items)
    means.sort()
    return (_percentile(means, 0.025), _percentile(means, 0.975))


def collapse_clusters(outcomes: dict[str, bool],
                      cluster_map: dict[str, str]) -> dict[str, bool]:
    """One binary outcome per cluster, under the ALL-pass rule.

    A cluster passes iff EVERY item in it passes.  This is the same fold the
    benchmark already applies everywhere else — an item passes only if all
    its repeats pass, a scenario outline passes only if all its examples do —
    so a shared closure is treated as one thing that either works or does
    not, and a system cannot earn a cluster by solving the easiest criterion
    behind it.  The measurement contract pins this rule; it is not a knob.
    """
    members = _cluster_members(outcomes, cluster_map)
    return {cid: all(vals) for cid, vals in members.items()}


def mcnemar_cluster_collapsed(a_outcomes: dict[str, bool],
                              b_outcomes: dict[str, bool],
                              cluster_map: dict[str, str]) -> dict:
    """Exact McNemar on cluster-collapsed outcomes: is A different from B?

    Paired, because both systems face the SAME items; collapsed to clusters
    first, because the pairs have to be independent for the test to mean
    anything and items behind one closure are not.  `b` counts clusters A
    passed and B did not, `c` the reverse; concordant clusters carry no
    information about a difference and are not counted, which is the whole
    idea of the test.

    Exact binomial rather than the chi-square approximation: with 77 clusters
    and pass counts in the single digits the discordant count is tiny, and
    the approximation is not defined there.

    Refuses two outcome dicts over different item sets.  The denominator is
    fixed before execution and never moves afterwards: silently intersecting
    them would let a run that crashed on its hard items be compared on its
    easy ones.
    """
    if set(a_outcomes) != set(b_outcomes):
        only_a = sorted(set(a_outcomes) - set(b_outcomes))
        only_b = sorted(set(b_outcomes) - set(a_outcomes))
        raise MetricsInputError(
            f"REFUSED: the two systems were scored over different item sets "
            f"({len(a_outcomes)} vs {len(b_outcomes)} items; "
            f"{len(only_a)} only in A e.g. {only_a[:1]}, "
            f"{len(only_b)} only in B e.g. {only_b[:1]}). A paired test needs "
            f"pairs, and intersecting them here would move a denominator that "
            f"was fixed before either system ran.")
    ca = collapse_clusters(a_outcomes, cluster_map)
    cb = collapse_clusters(b_outcomes, cluster_map)
    _require_inference_floor(len(ca), "exact cluster-collapsed McNemar")
    b = sum(1 for cid in ca if ca[cid] and not cb[cid])
    c = sum(1 for cid in ca if cb[cid] and not ca[cid])
    n = b + c
    if n == 0:
        # No discordant cluster: the data contain no evidence of a difference.
        # p = 1.0 is the honest reading, not "not scored" -- the test ran.
        p = 1.0
    else:
        m = min(b, c)
        tail = sum(math.comb(n, i) for i in range(m + 1)) / (2 ** n)
        p = min(1.0, 2.0 * tail)
    return {"b": b, "c": c, "p": p, "n_clusters": len(ca)}


def comparison_class(rows: Iterable[dict]) -> Optional[str]:
    """The one `comparison_class` these rows share, or None if none carry it.

    The stamp says what an outcome is comparable WITH — same harness, same
    fold, same item view.  Rows written before the stamp existed carry
    nothing and read as grandfathered-unknown, which is comparable with
    other unknowns by convention and with a known class by assumption; two
    DIFFERENT known classes are refused, because that is the one case where
    the runs are on record as measuring different things.
    """
    known = {r["comparison_class"] for r in rows
             if r.get("comparison_class") is not None}
    if len(known) > 1:
        raise MetricsInputError(
            f"REFUSED: the rows carry {len(known)} different comparison_class "
            f"values ({', '.join(sorted(known))}). They are on record as not "
            f"being comparable with each other; a difference between them "
            f"would measure the harness change, not the systems.")
    return known.pop() if known else None


def gold_self_check(gold_runs: dict[str, dict],
                    prod_index: dict[str, list[Method]],
                    boundary: Boundary) -> dict:
    """Score gold against itself: every metric must be exactly perfect.

    Perfect means 1.0 everywhere except `excess`, whose perfect score is
    0.0.  The check is also the join test between the call events and the
    method index: if the index resolves none of them, D_g is empty and the
    API keys are skipped rather than checked, so a PASS can be measuring
    nothing — which is why `n_with_methods` is returned and must be read
    alongside the verdict.

    The API keys are checked only where they were computed.  A gold baseline
    collected before the recorder has no `direct_calls` and its API rows are
    ABSENT rather than imperfect (2.6), so it self-checks PASS on coverage
    with `n_api_skipped` saying how many rows carried no API verdict.
    """
    violations, with_lines, with_methods, api_skipped = [], 0, 0, 0
    for iid, rec in sorted(gold_runs.items()):
        p = compare(rec, rec, prod_index, boundary)
        with_lines += 0 if p["gold_empty_coverage"] else 1
        if not p["api_defined"]:
            api_skipped += 1
        elif not p["gold_no_methods"]:
            with_methods += 1
        for key in METRIC_KEYS:
            if key.startswith("api.") and p["api"] is None:
                continue
            want = 0.0 if key == "coverage.excess" else 1.0
            got = _value(p, key)
            if got != want:
                violations.append(f"{iid} {key}={got!r} want {want}")
    return {"n": len(gold_runs), "n_with_lines": with_lines,
            "n_with_methods": with_methods, "n_api_skipped": api_skipped,
            "violations": violations, "ok": not violations}


# --------------------------------------------------------------------------
# CLI

def _fmt(v: Optional[float]) -> str:
    return "-" if v is None else f"{v:.3f}"


def report(gold_path: str, run_paths: list[str], index_path: str,
           boundary: Boundary, per_item: bool = False,
           items_path: str = "", self_check: bool = True) -> dict:
    gold_runs = load_runs(gold_path)
    prod_index = load_prod_index(index_path)
    pinned = load_items(items_path) if items_path else None

    gold_runs, dropped = scorable_gold(gold_runs, boundary)
    if dropped:
        print(f"EXCLUDED: {len(dropped)} gold item(s) have no coverage block "
              f"and therefore no upper bound. They are out of EVERY run's "
              f"denominator, so the runs stay comparable:")
        for reason, k in _counts(dropped.values()).items():
            print(f"  {k:>4}  {reason}")
    if not gold_runs:
        raise MetricsInputError(
            f"{gold_path}: no gold row has a coverage block, so no item has an "
            f"upper bound. Re-run gold with --coverage.")
    if pinned:
        pinned = [i for i in pinned if i not in dropped]

    print(f"gold  : {gold_path} ({len(gold_runs)} items)")
    print(f"index : {index_path} ({len(prod_index)} files, "
          f"{sum(len(v) for v in prod_index.values())} methods)")
    if self_check:
        chk = gold_self_check(gold_runs, prod_index, boundary)
        state = "PASS" if chk["ok"] else "FAIL"
        print(f"gold-vs-gold self-check: {state} over {chk['n']} items "
              f"({chk['n_with_lines']} with production coverage, "
              f"{chk['n_with_methods']} with direct method calls, "
              f"{chk['n_api_skipped']} with unavailable or incompatible API evidence)")
        for v in chk["violations"][:5]:
            print(f"    {v}")

    out = {}
    for path in run_paths:
        name = os.path.basename(path).replace(".jsonl", "")
        sys_runs = load_runs(path)
        # A run row for an excluded gold item is not an orphan — the gold row
        # exists, it just has no upper bound — so it is dropped here rather
        # than tripping `compare_runs`.
        sys_runs = {k: v for k, v in sys_runs.items() if k not in dropped}
        pairs = compare_runs(gold_runs, sys_runs, prod_index, boundary,
                             item_ids=pinned)
        out[name] = {"summary": summarise(pairs), "pairs": pairs,
                     "not_attempted": len(set(gold_runs) - set(sys_runs))}

    width = max([len(k) for k in out] + [10])
    col = 17
    head = "  ".join(f"{k.replace('coverage.', 'cov.'):>{col}}" for k in METRIC_KEYS)
    print(f"\n{'run':<{width}}  {'n':>4} {'def':>4}  {head}")
    print(f"{'':<{width}}  {'':>4} {'':>4}  "
          + "  ".join(f"{'cond|total':>{col}}" for _ in METRIC_KEYS))
    for name, r in out.items():
        s = r["summary"]
        cells = "  ".join(
            f"{_fmt(s['metrics'][k]['mean_defined']) + '|' + _fmt(s['metrics'][k]['over_total']):>{col}}"
            for k in METRIC_KEYS)
        print(f"{name:<{width}}  {s['n_items']:>4} {s['n_defined']:>4}  {cells}")

    print("\ncond = mean over items whose run reached @AfterScenario (n = def); "
          "the three api columns are over their own population, printed "
          "below.")
    print("total = ART's avg_over_total: undefined items substituted with "
          f"{UNDEFINED_SCORE['coverage.recall']:.1f} "
          f"({UNDEFINED_SCORE['coverage.excess']:.1f} for cov.excess, whose "
          "perfect score is 0), denominator all n.")
    print("      Every reward-polarity 'total' is therefore <= the run's pass "
          "rate and must be quoted as such.")
    print("Read (cov.recall, cov.excess) as the primary PAIR: Jaccard is "
          "symmetric and punishes\n      building MORE fixture than gold as "
          "hard as skipping the behaviour, and cov.recall\n      alone is "
          "gameable — a step body that walks the container and calls "
          "everything\n      raises recall towards 1.0. That solution's "
          "cov.excess goes to nearly 1.0 too,\n      which is the only reason "
          "the pair is safe to quote. Never quote one half.")
    if pinned:
        print(f"Denominator pinned to {items_path} ({len(pinned)} items).")

    for name, r in out.items():
        s = r["summary"]
        if r["not_attempted"] and not pinned:
            print(f"\nNOTE {name}: {r['not_attempted']} gold item(s) were not "
                  f"attempted by this run and are in NEITHER aggregate; the "
                  f"denominator is this run's attempted set. Use --items to pin "
                  f"it to the release.")
        if s["undefined_reasons"]:
            print(f"\n{name}: undefined ({s['n_items'] - s['n_defined']} of "
                  f"{s['n_items']})")
            for reason, k in s["undefined_reasons"].items():
                print(f"  {k:>4}  {reason}")
        if s["n_gold_empty_coverage"]:
            print(f"WARNING {name}: {s['n_gold_empty_coverage']} item(s) whose "
                  f"gold run covers no production line. Both sides are empty "
                  f"there, so the coverage comparison is an identity and "
                  f"every system scores 1.0 for free — exclude or repair "
                  f"them.")
        exc = s["api_excluded"]
        if any(exc.values()):
            print(f"\n{name}: excluded from the API rows, which are therefore "
                  f"over {s['n_api_scored']} item(s) and not "
                  f"{s['metrics']['coverage.recall']['n_items']}. These leave "
                  f"the denominator rather than being scored 0 — a missing "
                  f"recorder is not a candidate's failure:")
            for reason, k in exc.items():
                if k:
                    print(f"  {k:>4}  {reason}")
        for error in s["api_index_errors"]:
            print(f"NOTE {name}: API index unavailable: {error}")
        unmapped = s["unmapped_direct_events"]
        if unmapped["gold"] or unmapped["sys"]:
            print(f"NOTE {name}: {unmapped['gold']} gold and "
                  f"{unmapped['sys']} run direct call(s) matched no index "
                  f"method. Not credited and not a refusal: it is a gap in "
                  f"the production method index.")

    if per_item:
        for name, r in out.items():
            print(f"\n{name}: per item")
            for p in r["pairs"]:
                short = (p["item_id"] or "?").split("features/domain/")[-1]
                if not p["defined"]:
                    print(f"  UNDEFINED {p['undefined_reason']:<22} {short}")
                    continue
                c, a = p["coverage"], p["api"]
                api = ("api=not scored" if a is None else
                       f"f1={a['f1']:.3f} m={p['counts']['shared_methods']}/"
                       f"{p['counts']['gold_methods']}")
                print(f"  recall={c['recall']:.3f} excess={c['excess']:.3f} "
                      f"J={c['micro_jaccard']:.3f} {api}  {short}")

    return {k: v["summary"] for k, v in out.items()}


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python3 -m r2t.bench.metrics",
        description="behavioural metrics for a run, against the gold run")
    ap.add_argument("--gold", help="gold run .jsonl (the upper bound)")
    ap.add_argument("--run", action="append", default=[],
                    help="run .jsonl to score (repeatable)")
    ap.add_argument("--index", default=None,
                    help="the boundary project's production method index; "
                         "required for every project except CoreShop, "
                         "whose php_prod_index.json is the default")
    ap.add_argument("--boundary", default=DEFAULT_BOUNDARY)
    ap.add_argument("--repo", default=None)
    ap.add_argument("--items", default="",
                    help="release .jsonl: pin the over_total denominator")
    ap.add_argument("--per-item", action="store_true")
    ap.add_argument("--no-self-check", action="store_true")
    ap.add_argument("--json", default="", help="write the summaries here")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.gold or not args.run:
        ap.error("--gold and at least one --run are required")

    from ..core.boundary import load_boundary
    from .report import project_of
    b = load_boundary(args.boundary, repo_root=args.repo)
    if args.index is None:
        if b.project != "coreshop":
            ap.error(f"--index is required for project {b.project!r}; "
                     "the default production method index is CoreShop's, "
                     f"so pass {b.project}'s own index")
        args.index = project_path("coreshop", "artifacts", "php_prod_index.json")
    # `--boundary` and `--index` both default to CoreShop's, so a run from
    # any other project scored through this entry point was measured against
    # a production surface it has no lines in -- and printed a full table of
    # recall, excess and Jaccard with nothing in it saying the two disagree.
    # `r2t.bench.results` refuses exactly this pairing (run project vs boundary
    # project) before any arithmetic; this is that refusal at the other door
    # into the same numbers.  `--index` is named too because it defaults
    # alongside the boundary and is the other half of the wrong surface.
    for path in args.run:
        others = sorted({p for p in
                         {project_of(r) for r in read_runs(path).values()}
                         if p != b.project})
        if others:
            raise SystemExit(
                f"REFUSED: {path} holds rows for project "
                f"{', '.join(repr(p) for p in others)}, but --boundary "
                f"{args.boundary!r} and --index {args.index!r} describe "
                f"project {b.project!r}. Pass that project's boundary and "
                f"index; a run is scored only against its own project's "
                f"surface.")
    try:
        summaries = report(args.gold, args.run, args.index, b,
                           per_item=args.per_item, items_path=args.items,
                           self_check=not args.no_self_check)
    except MetricsInputError as e:
        raise SystemExit(f"REFUSED: {e}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(summaries, fh, indent=1, sort_keys=True)
        print(f"\nwrote {args.json}")
    return 0


# --------------------------------------------------------------------------
# selftest

def _fixture_boundary() -> Boundary:
    return Boundary(version=1, project="t", repo_root="/x",
                    removable=[("src/Test/", "generated test code")],
                    retained=[("src/Test/Kept/", "harness fixture")])


def _fixture_index() -> dict[str, list[Method]]:
    """Two production classes plus one in test territory, and a Python twin.

    `Cart::total` spans 10-20 and `Cart::secret` 22-30 so a coverage set can
    hit exactly a start line, exactly an end line, or the private span.  The
    PHP methods carry no `decl`: their `start` IS the declaration line.

    The `.py` files carry one, because that is what a Python call event
    names: `price` and `price.setter` are two keys declared five lines apart
    under one runtime name, `recalc` is wide enough to hold a nested function
    with no entry of its own, and `Base.shared` lives in the file that
    declares it rather than in any class the test names.
    """
    return ProductionIndex({
        "src/Prod/Cart.php": [
            Method("App\\Cart", "total", 10, 20, True),
            Method("App\\Cart", "secret", 22, 30, False),
            Method("App\\Cart", "clear", 32, 40, True),
        ],
        "src/Prod/Tax.php": [Method("App\\Tax", "rate", 5, 9, True)],
        "src/Test/CartContext.php": [Method("T\\CartContext", "iAdd", 1, 50, True)],
        "src/prod/cart.py": [
            Method("prod.cart.Cart", "price", 12, 14, True, decl=11),
            Method("prod.cart.Cart", "price.setter", 17, 19, True, decl=16),
            Method("prod.cart.Cart", "recalc", 22, 30, True, decl=21),
            Method("prod.cart.Cart", "_hidden", 33, 35, False, decl=32),
        ],
        "src/prod/base.py": [
            Method("prod.base.Base", "shared", 5, 7, True, decl=4)],
    }, schema=PYTHON_PROD_INDEX_SCHEMA)


def _rec(item_id: str, cov, outcome="passed", direct=None) -> dict:
    rec = {"item_id": item_id, "outcome": outcome, COVERAGE_FIELD: cov}
    # Absent, not null: a row from before the recorder does not carry the key
    # at all, and both spellings must read as "not collected".
    if direct is not None:
        rec[DIRECT_CALLS_FIELD] = direct
        rec["direct_calls_schema"] = PYTHON_DIRECT_CALLS_SCHEMA
        rec["harness_version"] = OUTLINE_UNION_HARNESS_VERSION
    return rec


def _call(callee_file: str, callee_line, callee: str, caller_file) -> dict:
    """One recorded call event, in the record's own key order."""
    return {"callee_file": callee_file, "callee_line": callee_line,
            "callee": callee, "caller_file": caller_file,
            "accessor_binding": None}


def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    b, idx = _fixture_boundary(), _fixture_index()
    gold_cov = {"src/Prod/Cart.php": [10, 11, 20], "src/Prod/Tax.php": [5, 6]}

    g = _rec("i1", gold_cov)
    same = compare(g, _rec("i1", dict(gold_cov)), idx, b)
    check("identical coverage: defined", same["defined"])
    check("identical coverage: every similarity is 1.0",
          same["coverage"]["recall"] == 1.0
          and same["coverage"]["micro_jaccard"] == 1.0
          and same["coverage"]["macro_jaccard"] == 1.0,
          str(same))
    check("identical coverage: excess is 0.0 (its perfect score)",
          same["coverage"]["excess"] == 0.0)

    sup = compare(g, _rec("i1", {"src/Prod/Cart.php": [10, 11, 20, 33],
                                 "src/Prod/Tax.php": [5, 6, 7]}), idx, b)
    check("strict superset: recall stays 1.0", sup["coverage"]["recall"] == 1.0)
    check("strict superset: excess > 0", sup["coverage"]["excess"] > 0)
    check("strict superset: jaccard < 1 (symmetry punishes doing more)",
          sup["coverage"]["micro_jaccard"] < 1.0
          and sup["coverage"]["macro_jaccard"] < 1.0)

    dis = compare(g, _rec("i1", {"src/Prod/Cart.php": [34, 35]}), idx, b)
    check("disjoint: recall and jaccard 0.0",
          dis["coverage"]["recall"] == 0.0
          and dis["coverage"]["micro_jaccard"] == 0.0
          and dis["coverage"]["macro_jaccard"] == 0.0, str(dis["coverage"]))
    check("disjoint: excess 1.0", dis["coverage"]["excess"] == 1.0)

    none_ = compare(g, _rec("i1", None, outcome="container_error"), idx, b)
    check("no coverage block: UNDEFINED, not zero",
          none_["defined"] is False and none_["coverage"] is None
          and none_["api"] is None)
    check("undefined carries the outcome as its reason",
          none_["undefined_reason"] == "container_error")
    check("no submission at all is undefined too",
          compare(g, None, idx, b)["undefined_reason"] == "no_submission")

    empty = compare(g, _rec("i1", {}), idx, b)
    check("reached @AfterScenario covering nothing is DEFINED and scores 0",
          empty["defined"] and empty["coverage"]["recall"] == 0.0)
    # The real adapter this models — a context of empty step bodies — PASSES
    # the scenario, so this is the one number a vacuous system could have
    # posted as perfect.
    check("covering nothing scores the WORST excess, not 0/0's best",
          empty["coverage"]["excess"] == 1.0, str(empty["coverage"]))

    # The test tree lives under the recorder's own <root>/src filter, so it
    # arrives in the coverage block and must be dropped on BOTH sides.
    tt = compare(_rec("i1", dict(gold_cov, **{"src/Test/CartContext.php": [3, 4]})),
                 _rec("i1", dict(gold_cov, **{"src/Test/CartContext.php": [9]})),
                 idx, b)
    check("non-production files excluded from both sides",
          tt["counts"]["gold_files"] == 2 and tt["counts"]["sys_files"] == 2
          and tt["coverage"]["micro_jaccard"] == 1.0, str(tt["counts"]))
    check("retained test code is excluded as well",
          production_lines(_rec("i1", {"src/Test/Kept/Setup.php": [1]}), b) == {})

    pairs = [same, sup, dis, none_, empty]
    s = summarise(pairs)
    check("summarise reports n_defined with the conditional mean",
          s["n_defined"] == 4 and s["n_items"] == 5
          and s["metrics"]["coverage.recall"]["n_defined"] == 4)
    cond = s["metrics"]["coverage.recall"]["mean_defined"]
    tot = s["metrics"]["coverage.recall"]["over_total"]
    # recalls over the four defined items are 1, 1, 0, 0.
    check("over_total scores undefined items 0 and is <= the conditional mean",
          abs(cond - 2 / 4) < 1e-12 and abs(tot - 2 / 5) < 1e-12 and tot <= cond,
          f"cond={cond} total={tot}")
    check("excess substitutes 1.0 for undefined, so crashing is not 'precise'",
          s["metrics"]["coverage.excess"]["undefined_score"] == 1.0
          and s["metrics"]["coverage.excess"]["over_total"]
          > s["metrics"]["coverage.excess"]["mean_defined"])
    check("undefined reasons are counted, not collapsed",
          s["undefined_reasons"] == {"container_error": 1}, str(s["undefined_reasons"]))

    step_call = [_call("src/Prod/Cart.php", 10, "App\\Cart::total",
                       "src/Test/CartContext.php")]
    chk = gold_self_check(
        {"i1": _rec("i1", gold_cov, direct=step_call),
         "i2": _rec("i2", {"src/Prod/Tax.php": [5]}, direct=step_call)},
        idx, b)
    check("gold vs gold is exactly perfect on every metric",
          chk["ok"] and chk["n_with_methods"] == 2
          and chk["n_api_skipped"] == 0, str(chk["violations"][:3]))

    degen = compare(_rec("i3", {}), _rec("i3", {}), idx, b)
    check("an item whose gold covers nothing is flagged degenerate",
          degen["gold_empty_coverage"]
          and degen["coverage"]["micro_jaccard"] == 1.0)
    check("both sides empty is still the identity excess 0.0",
          degen["coverage"]["excess"] == 0.0)
    check("degenerate items are counted in the summary",
          summarise([degen])["n_gold_empty_coverage"] == 1)

    # One gold item without a coverage block must not make every OTHER item
    # unscoreable — but it must not vanish either.
    ok_gold, dropped = scorable_gold(
        {"i1": g, "i2": _rec("i2", None, outcome="timeout")}, b)
    check("gold without a coverage block is excluded, not fatal",
          set(ok_gold) == {"i1"} and dropped == {"i2": "timeout"}, str(dropped))
    try:
        compare_runs(ok_gold, {"i1": _rec("i1", gold_cov)}, idx, b,
                     item_ids=["i1", "i2"])
        check("a pinned item with no scorable gold raises", False, "no exception")
    except MetricsInputError as e:
        check("pinning an item gold cannot score fails loudly, not by KeyError",
              "no scorable gold row" in str(e))

    try:
        production_lines({"item_id": "i1", "outcome": "passed"}, b)
        check(f"a record without {COVERAGE_FIELD} raises", False, "no exception")
    except MetricsInputError as e:
        check(f"a record without {COVERAGE_FIELD} fails loudly",
              COVERAGE_FIELD in str(e))
    try:
        compare(_rec("i1", None), _rec("i1", gold_cov), idx, b)
        check("gold without coverage raises", False, "no exception")
    except MetricsInputError as e:
        check("gold without a coverage block raises rather than scoring 0",
              "upper bound" in str(e))

    # ----------------------------------------------------------------
    # ApiCallSimilarity over DIRECT invocation: what is credited, over
    # synthetic `direct_calls` records (API_DIRECT_INVOCATION_SPEC.md 8).
    # Nothing here reads a coverage line, which is the whole change.

    step = "src/Test/CartContext.php"
    total = ("App\\Cart", "total")

    def direct(*events):
        return direct_methods(_rec("i1", gold_cov, direct=list(events)),
                              b, idx)

    credited = _call("src/Prod/Cart.php", 10, "App\\Cart::total", step)
    check("a production method called from a REMOVABLE file is credited",
          direct(credited) == ({total}, 0), str(direct(credited)))
    check("the same method reached only from PRODUCTION is not credited, and "
          "is not unmapped either -- it is not an event of this definition",
          direct(_call("src/Prod/Cart.php", 10, "App\\Cart::total",
                       "src/Prod/Tax.php")) == (set(), 0))
    check("a call from RETAINED substrate is not credited: it is the same "
          "for every candidate",
          direct(_call("src/Prod/Cart.php", 10, "App\\Cart::total",
                       "src/Test/Kept/Setup.php")) == (set(), 0))
    # One runtime name, two keys: the declaration line is what tells the
    # setter from its getter, and `co_qualname` cannot.
    check("a property's getter and its setter are two keys",
          direct(_call("src/prod/cart.py", 11, "prod.cart.Cart.price", step),
                 _call("src/prod/cart.py", 16, "prod.cart.Cart.price", step))
          == ({("prod.cart.Cart", "price"),
               ("prod.cart.Cart", "price.setter")}, 0))
    check("an inherited method is attributed to the file that DECLARES its "
          "body, never to the class the test named",
          direct(_call("src/prod/base.py", 4, "prod.base.Base.shared", step))
          == ({("prod.base.Base", "shared")}, 0))
    check("a named nested function folds to the enclosing method whose span "
          "holds its declaration",
          direct(_call("src/prod/cart.py", 25,
                       "prod.cart.Cart.recalc.<locals>.apply", step))
          == ({("prod.cart.Cart", "recalc")}, 0))
    check("a non-public exact match is MAPPED and not credited: a private "
          "call is not a gap in the index",
          direct(_call("src/prod/cart.py", 32, "prod.cart.Cart._hidden", step))
          == (set(), 0))
    # PHP reflection names the `function` line; the index starts an
    # attributed method one line above, on its `#[...]` (2.3, measured on
    # `CoreShop\Component\Pimcore\PriorityQueue::getIterator`: reflected 229,
    # index 228-234).  The reflected line is inside the span and joins.
    check("a PHP callee reflected inside a method's span but not on its start "
          "line -- an attributed method -- is credited to that method",
          direct(_call("src/Prod/Cart.php", 11, "App\\Cart->total", step))
          == ({total}, 0),
          str(direct(_call("src/Prod/Cart.php", 11, "App\\Cart->total", step))))
    check("...while a Python callee inside a span but off its `decl` stays "
          "unmapped: there the line is a stale index, not an attribute",
          direct(_call("src/prod/cart.py", 13, "prod.cart.Cart.price", step))
          == (set(), 1))
    check("a direct call the index cannot place is counted unmapped and "
          "credited nowhere",
          direct(_call("src/prod/cart.py", 99, "prod.cart.Cart.gone", step))
          == (set(), 1))
    check("a module body and a lambda are not method activations, so they "
          "are neither credited nor unmapped",
          direct(_call("src/prod/cart.py", 1, "prod.cart.<module>", step),
                 _call("src/prod/cart.py", 24,
                       "prod.cart.Cart.recalc.<locals>.<lambda>", step))
          == (set(), 0))
    stale_py = {"src/prod/cart.py": [
        Method("prod.cart.Cart", "price", 12, 14, True)]}
    try:
        direct_methods(_rec("i1", gold_cov, direct=[]), b, stale_py)
        check("a Python index with no `decl` refuses", False, "no exception")
    except MetricsInputError as e:
        check("a Python index minted before `decl` is REFUSED where it is "
              "used, not scored: every callee unmapped reads exactly like a "
              "test that called nothing",
              "`decl`" in str(e) and "r2t.py.prod_index" in str(e), str(e))
    check("...and a row with no `direct_calls` never reaches that refusal, "
          "so a coverage-only comparison is not the index's business",
          direct_methods(_rec("i1", gold_cov), b, stale_py) is None
          and compare(_rec("i1", gold_cov), _rec("i1", gold_cov), stale_py,
                      b)["api_undefined_reason"] == "gold_without_direct_calls")

    # 2.6 and 3.1, on `compare`: which items the API rows are defined over.
    called = _rec("i1", gold_cov,
                  direct=[_call("src/Prod/Cart.php", 10, "App\\Cart::total",
                                step)])
    nofield = compare(called, _rec("i1", dict(gold_cov)), idx, b)
    check("a row without `direct_calls` is NOT SCORED on the API rows and "
          "never falls back to coverage, while coverage still scores",
          nofield["api"] is None and nofield["api_defined"] is False
          and nofield["api_undefined_reason"] == "run_without_direct_calls"
          and nofield["api_excluded"] is True
          and nofield["counts"]["sys_methods"] == 0
          and nofield["coverage"]["micro_jaccard"] == 1.0, str(nofield))
    stubbed = compare(called, _rec("i1", dict(gold_cov), direct=[]), idx, b)
    check("a candidate that called nothing scores the WORST precision, not "
          "the empty-set identity -- only an empty GOLD set excludes",
          stubbed["api"] == {"precision": 0.0, "recall": 0.0, "f1": 0.0}
          and stubbed["api_excluded"] is False, str(stubbed))
    nothing = compare(_rec("i4", gold_cov, direct=[]),
                      _rec("i4", dict(gold_cov), direct=[]), idx, b)
    check("a gold test that invoked nothing directly is UNSCORABLE: excluded "
          "from the API rows rather than handed the identity 1.0",
          nothing["gold_no_methods"] is True and nothing["api"] is None
          and nothing["api_excluded"] is True
          and nothing["api_undefined_reason"] is None
          and nothing["coverage"]["micro_jaccard"] == 1.0, str(nothing))
    skipped = gold_self_check({"i1": called, "i2": _rec("i2", gold_cov)},
                              idx, b)
    check("gold self-check PASSES on a gold row with no `direct_calls` and "
          "reports how many rows it could not check",
          skipped["ok"] and skipped["n_api_skipped"] == 1
          and skipped["n_with_methods"] == 1, str(skipped))

    # The two definedness axes have different denominators, and both are
    # reported.  `both` also carries one unmapped event, so the diagnostic
    # is summed rather than recomputed from a set size.
    both = _rec("i1", gold_cov, direct=[
        _call("src/Prod/Cart.php", 10, "App\\Cart::total", step),
        _call("src/prod/cart.py", 99, "prod.cart.Cart.gone", step)])
    crashed = compare(called, _rec("i5", None, outcome="container_error"),
                      idx, b)
    no_gold_field = compare(_rec("i6", gold_cov), _rec("i6", dict(gold_cov)),
                            idx, b)
    api_s = summarise([compare(both, both, idx, b), nothing, nofield,
                       crashed, no_gold_field])
    check("the API axis excludes the unscorable pairs from its own "
          "denominator and still substitutes a crashed run",
          api_s["metrics"]["api.f1"]["n_items"] == 2
          and api_s["metrics"]["api.f1"]["n_defined"] == 1
          and api_s["metrics"]["api.f1"]["mean_defined"] == 1.0
          and api_s["metrics"]["api.f1"]["over_total"] == 0.5
          and api_s["metrics"]["coverage.recall"]["n_items"] == 5
          and api_s["n_api_scored"] == 1, str(api_s["metrics"]["api.f1"]))
    check("every excluded item is counted under the reason that excluded it, "
          "and a missing gold field outranks a missing run field",
          api_s["api_excluded"] == {"run_without_direct_calls": 1,
                                    "gold_without_direct_calls": 1,
                                    "gold_before_api_amendment_2": 0,
                                    "run_before_api_amendment_2": 0,
                                    "invalid_production_index": 0,
                                    "gold_no_direct_methods": 1}
          and no_gold_field["api_undefined_reason"]
          == "gold_without_direct_calls"
          and api_s["unmapped_direct_events"] == {"gold": 1, "sys": 1},
          str(api_s))

    # ----------------------------------------------------------------
    # cluster-aware statistics

    check("the Wilson label is the pinned string and says what it ignores",
          WILSON_LABEL == "item-level, clusters ignored", WILSON_LABEL)
    lo, hi = wilson_interval(5, 100)
    # The published Wilson interval for 5/100 is (0.0216, 0.1118).
    check("wilson_interval reproduces the textbook interval for 5/100",
          abs(lo - 0.02154) < 5e-5 and abs(hi - 0.11175) < 5e-5, f"{lo} {hi}")
    lo0, hi0 = wilson_interval(0, 50)
    check("wilson_interval at k=0 is not the degenerate (0, 0)",
          lo0 == 0.0 and 0.05 < hi0 < 0.10, f"{lo0} {hi0}")
    lon, hin = wilson_interval(50, 50)
    check("wilson_interval at k=n clamps the upper bound to exactly 1.0",
          hin == 1.0 and 0.90 < lon < 0.95, f"{lon} {hin}")
    try:
        wilson_interval(0, 0)
        check("wilson over an empty denominator refuses", False, "no exception")
    except MetricsInputError as e:
        check("wilson over n=0 refuses instead of reporting a rate",
              str(e).startswith("REFUSED:"), str(e))

    # Twenty one-item clusters, so the collapse is the identity.  The first
    # four carry the hand-checkable discordance pattern; the rest are
    # concordant failures and therefore do not change b/c.
    one_each = {f"x{i}": f"c{i}" for i in range(1, 21)}
    a20 = {iid: False for iid in one_each}
    b20 = {iid: False for iid in one_each}
    a20.update({"x1": True, "x2": True, "x3": True})
    b20.update({"x3": True, "x4": True})
    mc = mcnemar_cluster_collapsed(a20, b20, one_each)
    # b=2, c=1, so n=3 discordant and p = 2 * (C(3,0)+C(3,1))/2^3 = 2 * 4/8 = 1.
    check("mcnemar counts discordant clusters by hand: b=2 c=1 over the "
          "20-cluster floor",
          mc == {"b": 2, "c": 1, "p": 1.0, "n_clusters": 20}, str(mc))
    twenty = {f"y{i}": f"d{i}" for i in range(1, 21)}
    mc20 = mcnemar_cluster_collapsed({k: True for k in twenty},
                                     {k: False for k in twenty}, twenty)
    # b=20, c=0: p = 2 / 2^20.
    check("a clean sweep at the floor has the exact two-sided binomial p",
          mc20["b"] == 20 and mc20["c"] == 0
          and abs(mc20["p"] - 2 / (2 ** 20)) < 1e-15,
          str(mc20))
    same_sys = mcnemar_cluster_collapsed(a20, dict(a20), one_each)
    check("no discordant cluster reads p=1.0, not 'not scored'",
          same_sys == {"b": 0, "c": 0, "p": 1.0, "n_clusters": 20},
          str(same_sys))

    five = {f"z{i}": f"small{i}" for i in range(5)}
    five_out = {iid: i < 2 for i, iid in enumerate(five)}
    check("descriptive cluster collapse remains available below the floor",
          collapse_clusters(five_out, five)
          == {f"small{i}": i < 2 for i in range(5)})
    for label, fn in (
            ("bootstrap", lambda: cluster_bootstrap(five_out, five)),
            ("McNemar", lambda: mcnemar_cluster_collapsed(
                five_out, {iid: not value for iid, value in five_out.items()},
                five))):
        try:
            fn()
            check(f"{label} below 20 clusters refuses", False, "no exception")
        except MetricsInputError as e:
            check(f"{label} below 20 clusters refuses with the usable "
                  "descriptive alternative named",
                  "at least 20" in str(e) and "got 5" in str(e)
                  and "Descriptive" in str(e), str(e))

    # The collapse rule itself: one failure sinks the cluster.
    mixed = collapse_clusters({"m1": True, "m2": False, "m3": True},
                              {"m1": "k1", "m2": "k1", "m3": "k2"})
    check("a cluster with a pass AND a fail collapses to FAIL (all-pass rule)",
          mixed == {"k1": False, "k2": True}, str(mixed))

    # Why any of this exists: 100 items, but only 20 independent things.  Each
    # cluster's 5 items agree perfectly, which is what a shared closure does.
    corr_map, corr_out = {}, {}
    for g in range(20):
        for j in range(5):
            iid = f"g{g}i{j}"
            corr_map[iid] = f"cl{g}"
            corr_out[iid] = g < 6          # 6 clusters pass: 30/100
    blo, bhi = cluster_bootstrap(corr_out, corr_map)
    wlo, whi = wilson_interval(30, 100)
    check("the cluster bootstrap brackets the observed rate",
          blo <= 0.30 <= bhi, f"[{blo}, {bhi}]")
    check("clustering WIDENS the interval -- the whole point of the exercise",
          (bhi - blo) > (whi - wlo) * 1.5,
          f"cluster [{blo:.3f}, {bhi:.3f}] vs wilson [{wlo:.3f}, {whi:.3f}]")
    check("the same seed gives the same interval, to the digit",
          cluster_bootstrap(corr_out, corr_map) == (blo, bhi))
    # Determinism the check above CANNOT see: it hands the same dict objects
    # back, so it re-runs the same iteration order.  The same outcomes read
    # from a file whose rows are in another order are the SAME measurement and
    # must print the same interval to the digit -- otherwise the seed beside
    # the number promises a reproducibility it does not have.
    #
    # The clusters here are deliberately of UNEQUAL size, which is what makes
    # the check bite: with equal-sized clusters a permutation moves the same
    # denominators around and can hide itself, while the real corpus (largest
    # cluster 7, most of them 1) is uneven and does not.
    un_map, un_out = {}, {}
    uneven_shapes = ([(7, 1), (3, 0), (1, 1), (5, 2), (2, 0), (4, 4),
                      (6, 0)] * 3)[:20]
    for cid, (n_items, n_pass) in enumerate(uneven_shapes):
        for j in range(n_items):
            un_map[f"v{cid}_{j}"] = f"w{cid}"
            un_out[f"v{cid}_{j}"] = j < n_pass
    un_ci = cluster_bootstrap(un_out, un_map)
    un_keys = list(un_out)
    random.Random(11).shuffle(un_keys)
    un_shuf = cluster_bootstrap({k: un_out[k] for k in un_keys},
                                {k: un_map[k] for k in un_keys})
    check("the same data re-inserted in a SHUFFLED order gives the identical "
          "interval, to the digit",
          un_shuf == un_ci, f"shuffled {un_shuf} vs {un_ci}")
    # With no correlation to find, the cluster interval must NOT be absurdly
    # wide -- one item per cluster is the item bootstrap.
    flat_out = {f"s{i}": i < 15 for i in range(50)}
    flat_map = {f"s{i}": f"u{i}" for i in range(50)}
    ilo, ihi = cluster_bootstrap(flat_out, flat_map)
    flat_wlo, flat_whi = wilson_interval(15, 50)
    # Seed-SENSITIVE, not seed-by-seed different: over 50 one-item clusters a
    # replicate rate can only land on a 1/50 grid, so two seeds can honestly
    # agree to the digit.  The claim being checked is that the interval is a
    # resample rather than a formula, and one moving seed shows that.
    moved = [s for s in (1, 2, 3)
             if cluster_bootstrap(flat_out, flat_map, seed=s) != (ilo, ihi)]
    check("a different seed moves it (the CI is a resample, not a formula)",
          bool(moved), f"no seed of (1, 2, 3) moved [{ilo}, {ihi}]")
    check("one item per cluster gives back roughly the item-level interval",
          abs((ihi - ilo) - (flat_whi - flat_wlo)) < 0.05,
          f"cluster [{ilo:.3f}, {ihi:.3f}] vs wilson "
          f"[{flat_wlo:.3f}, {flat_whi:.3f}]")

    try:
        cluster_bootstrap({"x1": True, "zz": False}, one_each)
        check("an item with no cluster refuses", False, "no exception")
    except MetricsInputError as e:
        check("an item with no closure cluster is refused, not made its own",
              str(e).startswith("REFUSED:") and "zz" in str(e), str(e))
    try:
        mcnemar_cluster_collapsed(a20,
                                  {k: v for k, v in b20.items() if k != "x4"},
                                  one_each)
        check("comparing different item sets refuses", False, "no exception")
    except MetricsInputError as e:
        check("two runs over different item sets are refused, never intersected",
              str(e).startswith("REFUSED:") and "different item sets" in str(e),
              str(e))

    # The mean bootstrap, beside the proportion one it shares its floor,
    # seed, grouping and percentiles with.
    mean_vals = {iid: (1.0 if passed else 0.25)
                 for iid, passed in corr_out.items()}
    mlo, mhi = cluster_bootstrap_mean(mean_vals, corr_map)
    check("the cluster bootstrap of a mean brackets the observed mean",
          mlo <= statistics.mean(mean_vals.values()) <= mhi,
          f"[{mlo}, {mhi}] around {statistics.mean(mean_vals.values())}")
    check("a 0/1-valued mean reproduces the proportion bootstrap's interval",
          cluster_bootstrap_mean({k: float(v) for k, v in corr_out.items()},
                                 corr_map) == (blo, bhi))
    mean_shuffled = {k: mean_vals[k] for k in reversed(list(mean_vals))}
    check("the mean bootstrap is a function of (data, seed) alone",
          cluster_bootstrap_mean(mean_shuffled, corr_map) == (mlo, mhi))
    check("one value per cluster, all equal, collapses the interval onto the "
          "point -- a degeneracy the caller must say out loud",
          cluster_bootstrap_mean({f"d{i}": 0.5 for i in range(20)},
                                 {f"d{i}": f"e{i}" for i in range(20)})
          == (0.5, 0.5))
    try:
        cluster_bootstrap_mean({f"f{i}": 0.5 for i in range(5)},
                               {f"f{i}": f"g{i}" for i in range(5)})
        check("the mean bootstrap honours the cluster floor", False,
              "no exception")
    except MetricsInputError as e:
        check("the mean bootstrap refuses below the SAME 20-cluster floor",
              f"at least {MIN_INFERENCE_CLUSTERS}" in str(e)
              and "got 5" in str(e), str(e))
    try:
        cluster_bootstrap_mean({f"h{i}": i < 6 for i in range(20)},
                               {f"h{i}": f"j{i}" for i in range(20)})
        check("a boolean outcome is refused by the mean routine", False,
              "no exception")
    except MetricsInputError as e:
        check("a boolean outcome is sent to `cluster_bootstrap`, not averaged",
              "cluster_bootstrap" in str(e), str(e))

    # The undisclosed-API subtraction (spec 6.2).
    keys = index_method_keys(idx)
    check("the index key space holds the keys `direct_methods` produces",
          ("App\\Cart", "total") in keys
          and ("prod.cart.Cart", "price.setter") in keys
          and ("App\\Cart", "secret") in keys)
    dg = {("App\\Cart", "total"), ("App\\Tax", "rate")}
    dc = {("App\\Cart", "total"), ("App\\Cart", "clear")}
    und = undisclosed_api(dg, dc, [("App\\Cart", "total")], keys)
    check("subtracting the disclosed list leaves the rest of the row scorable",
          und["scored"] and und["counts"]["gold_undisclosed"] == 1
          and und["counts"]["sys_undisclosed"] == 1
          and und["api"]["f1"] == 0.0, str(und))
    same_rest = undisclosed_api(dg, dg, [("App\\Cart", "total")], keys)
    check("agreement on the undisclosed rest scores 1.0",
          same_rest["api"]["f1"] == 1.0)
    from_iter = undisclosed_api(dg, dc, iter([("App\\Cart", "total")]), keys)
    check("a disclosed ITERATOR subtracts the same as the list does -- it is "
          "consumed once, not exhausted by the shape check and then emptied",
          from_iter["counts"] == und["counts"]
          and from_iter["api"]["f1"] == und["api"]["f1"], str(from_iter))
    try:
        undisclosed_api(dg, dc, iter([["App\\Cart", "total"]]), keys)
        check("a JSON-list key from an iterator refuses", False,
              "no exception")
    except MetricsInputError as e:
        check("...and an unhashable key inside one is still the SHAPE "
              "refusal, not a TypeError out of the set constructor",
              str(e).startswith("REFUSED:") and "tuples of strings" in str(e),
              str(e))
    covered = undisclosed_api(dg, dc, dg, keys)
    check("an item whose whole gold set is disclosed is UNSCORED with a "
          "reason, not handed the empty-set identity",
          not covered["scored"]
          and covered["reason"] == UNDISCLOSED_FULLY_DISCLOSED
          and covered["api"] is None, str(covered))
    try:
        undisclosed_api(dg, dc, [["App\\Cart", "total"]], keys)
        check("a JSON-list disclosed key refuses", False, "no exception")
    except MetricsInputError as e:
        check("a disclosed key that is not a tuple REFUSES rather than "
              "subtracting nothing",
              str(e).startswith("REFUSED:") and "tuples of strings" in str(e),
              str(e))
    try:
        undisclosed_api(dg, dc, [("App\\Cart",)], keys)
        check("a one-element disclosed key refuses", False, "no exception")
    except MetricsInputError as e:
        check("a disclosed key absent from the pinned index REFUSES rather "
              "than subtracting nothing",
              str(e).startswith("REFUSED:") and "absent" in str(e), str(e))

    # Target-region recall (spec 6.2).
    region = {"src/Prod/Cart.php": {10, 11, 12}}
    full = target_region_recall(
        {"src/Prod/Cart.php": {10, 11, 20}, "src/Prod/Tax.php": {5}},
        {"src/Prod/Cart.php": {10, 11}}, region)
    check("region recall is over gold's covered lines INSIDE the region",
          full["scorable"] and full["recall"] == 1.0
          and full["n_gold_region_lines"] == 2 and full["reaches_target"],
          str(full))
    part = target_region_recall(
        {"src/Prod/Cart.php": {10, 11, 20}},
        {"src/Prod/Cart.php": {10, 20}}, region)
    check("covering only part of gold's region lines does not reach the target",
          part["recall"] == 0.5 and part["reaches_target"] is False, str(part))
    none_ = target_region_recall(
        {"src/Prod/Cart.php": {10, 11}}, {"src/Prod/Tax.php": {5}}, region)
    check("a region the candidate never entered scores 0.0, not 1.0",
          none_["recall"] == 0.0 and none_["reaches_target"] is False)
    outside = target_region_recall(
        {"src/Prod/Tax.php": {5, 6}}, {"src/Prod/Tax.php": {5, 6}}, region)
    check("an item whose gold covers no region line is not_scorable and "
          "named, never a free 1.0",
          not outside["scorable"]
          and outside["reason"] == REGION_NO_GOLD_LINES
          and outside["recall"] is None, str(outside))

    check("no row carrying a comparison_class reads as unknown, not a conflict",
          comparison_class([{"item_id": "a"}, {"item_id": "b"}]) is None)
    check("an unstamped row is grandfathered against a stamped one",
          comparison_class([{"comparison_class": "v2.strict"}, {"item_id": "b"}])
          == "v2.strict")
    try:
        comparison_class([{"comparison_class": "v2.strict"},
                          {"comparison_class": "v1.legacy"}])
        check("two known comparison classes refuse", False, "no exception")
    except MetricsInputError as e:
        check("rows on record as incomparable are refused",
              str(e).startswith("REFUSED:") and "comparison_class" in str(e),
              str(e))

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "idx.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump({"files": {"src/Prod/Cart.php": {"classes": [
                {"name": "App\\Cart", "methods": [
                    {"name": "total", "start": 10, "end": 20, "public": True,
                     "static": False, "abstract": False}]}]}}}, fh)
        loaded = load_prod_index(p)
        check("index loads through the {files: {classes: [...]}} envelope",
              loaded["src/Prod/Cart.php"][0].key == ("App\\Cart", "total"))
        with open(p, "w", encoding="utf-8") as fh:
            json.dump({"files": {"src/Prod/Cart.php": {"classes": [
                {"name": "App\\Cart", "methods": [{"name": "total", "start": 10}]}]}}},
                fh)
        try:
            load_prod_index(p)
            check("index missing a method field raises", False, "no exception")
        except MetricsInputError as e:
            check("a method without end/public fails loudly",
                  "'end'" in str(e) or "end" in str(e))
        stale_doc = {"files": {"src/prod/cart.py": {"classes": [
            {"name": "prod.cart.Cart", "methods": [
                {"name": "price", "start": 12, "end": 14, "public": True}]}]}}}
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(stale_doc, fh)
        stale_loaded = load_prod_index(p)
        try:
            refuse_stale_python_index(stale_loaded, p)
            check("the up-front refusal names the file", False, "no exception")
        except MetricsInputError as e:
            check("a Python index with no `decl` LOADS (coverage never reads "
                  "it) and the up-front refusal names the file",
                  stale_loaded["src/prod/cart.py"][0].decl is None
                  and str(e).startswith(p + ": ") and "`decl`" in str(e),
                  str(e))
        stale_doc["files"]["src/prod/cart.py"]["classes"][0]["methods"][0]["decl"] = 11
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(stale_doc, fh)
        try:
            refuse_stale_python_index(load_prod_index(p), p)
            check("a declaration-only historical index cannot claim X1", False)
        except MetricsInputError as exc:
            check("declaration lines do not establish schema-2 accessors",
                  PYTHON_PROD_INDEX_SCHEMA in str(exc))
        stale_doc["schema"] = PYTHON_PROD_INDEX_SCHEMA
        stale_doc["files"]["src/prod/cart.py"]["classes"][0]["accessors"] = []
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(stale_doc, fh)
        refuse_stale_python_index(load_prod_index(p), p)
        check("a current index retains the ordinary declaration-line join",
              load_prod_index(p)["src/prod/cart.py"][0].decl == 11)

        owner = "docx.oxml.Example"
        element_file = "src/prod/elements.py"
        accessor_doc = {"schema": PYTHON_PROD_INDEX_SCHEMA, "files": {
            element_file: {"classes": [{"name": owner, "methods": [],
                "accessors": [
                    {"declaring_line": 40, "attribute": "graphic", "access_kind": "get", "public": True},
                    {"declaring_line": 41, "attribute": "embed", "access_kind": "get", "public": True},
                    {"declaring_line": 41, "attribute": "embed", "access_kind": "set", "public": True},
                    {"declaring_line": 42, "attribute": "_private", "access_kind": "get", "public": False}]}]}}}
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(accessor_doc, fh)
        accessor_index = load_prod_index(p)

        def activation(attribute, line, kind="get", declaring_owner=owner):
            return dict(_call("src/prod/xmlchemy.py", 100,
                              "xmlchemy.Factory._getter.<locals>.get_child", step),
                        accessor_binding={"declaring_file": element_file,
                            "declaring_line": line, "owner": declaring_owner,
                            "attribute": attribute, "access_kind": kind})

        current = _rec("accessors", {element_file: [40]}, direct=[
            activation("graphic", 40), activation("embed", 41),
            activation("embed", 41, "set"), activation("_private", 42)])
        check("accessor-only classes need no fabricated method span: shared "
              "factory activations credit distinct public bindings and access kinds",
              direct_methods(current, b, accessor_index) == ({
                  (owner, "graphic"), (owner, "embed"), (owner, "embed.setter")}, 0)
              and accessor_index[element_file] == [])
        wrong_owner = _rec("accessors", {element_file: [40]}, direct=[
            activation("graphic", 40, declaring_owner="docx.oxml.RuntimeChild")])
        wrong_line = _rec("accessors", {element_file: [40]}, direct=[activation("graphic", 39)])
        check("declaring owner and assignment line are exact identities, "
              "with no receiver or factory fallback",
              direct_methods(wrong_owner, b, accessor_index) == (set(), 1)
              and direct_methods(wrong_line, b, accessor_index) == (set(), 1))
        for caller in ("src/prod/other.py", "src/Test/Kept/Setup.php"):
            indirect = dict(current, direct_calls=[dict(activation("graphic", 40), caller_file=caller)])
            check("an accessor activated by production or retained code gets no direct credit",
                  direct_methods(indirect, b, accessor_index) == (set(), 0))

        old_event = dict(activation("graphic", 40))
        old_event.pop("accessor_binding")
        old = dict(current, direct_calls=[old_event])
        old_empty = dict(current, direct_calls=[])
        old_empty.pop("direct_calls_schema")
        old_version = dict(current, harness_version=11)
        unstamped_item = dict(current, record_count=1)
        unstamped_item.pop("harness_version")
        unstamped_without_count = dict(current)
        unstamped_without_count.pop("harness_version")
        for label, historical in (("missing binding", old),
                                  ("old empty recorder", old_empty),
                                  ("older evaluator", old_version),
                                  ("unstamped emitted item", unstamped_item),
                                  ("unstamped item without record count", unstamped_without_count)):
            comparison = compare(current, historical, accessor_index, b)
            check(label + " withholds only API; current coverage still compares",
                  comparison["api"] is None
                  and comparison["api_undefined_reason"] == "run_before_api_amendment_2"
                  and comparison["api_excluded"]
                  and comparison["coverage"]["micro_jaccard"] == 1.0)
        check("a complete new empty recording is measured, not historical",
              direct_methods(dict(current, direct_calls=[]), b, accessor_index) == (set(), 0))
        check("raw per-scenario evidence needs its recorder schema, not a "
              "manufactured item stamp",
              direct_methods({"direct_calls": current["direct_calls"],
                              "direct_calls_schema": PYTHON_DIRECT_CALLS_SCHEMA},
                             b, accessor_index) == direct_methods(current, b, accessor_index))
        old_index = ProductionIndex(dict(accessor_index), schema="r2t.py_prod_index/1")
        incompatible = compare(current, current, old_index, b)
        incompatible_summary = summarise([incompatible])
        incompatible_self = gold_self_check({"accessors": current}, old_index, b)
        check("the combined comparison and self-check retain coverage for "
              "an old index, with an explicit API-only index diagnostic",
              incompatible["coverage"]["micro_jaccard"] == 1.0
              and incompatible["api"] is None and incompatible["api_excluded"]
              and incompatible["api_undefined_reason"] == "invalid_production_index"
              and incompatible_summary["api_excluded"]["invalid_production_index"] == 1
              and len(incompatible_summary["api_index_errors"]) == 1
              and incompatible_self["ok"] and incompatible_self["n_api_skipped"] == 1)
        import contextlib
        import io
        old_doc = dict(accessor_doc, schema="r2t.py_prod_index/1")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(old_doc, fh)
        old_report_run = os.path.join(d, "old-index-report.jsonl")
        with open(old_report_run, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(current) + "\n")
        report_output = io.StringIO()
        with contextlib.redirect_stdout(report_output):
            old_report = report(old_report_run, [old_report_run], p, b)
        old_report_summary = old_report["old-index-report"]
        check("the complete standalone metrics report emits coverage and "
              "names the incompatible index instead of aborting",
              old_report_summary["metrics"]["coverage.recall"]["mean_defined"] == 1.0
              and old_report_summary["metrics"]["api.f1"]["n_items"] == 0
              and "API index unavailable" in report_output.getvalue())

        php_index = ProductionIndex({"src/Prod/Cart.php": idx["src/Prod/Cart.php"]})
        old_outline = dict(called, record_count=2, harness_version=11)
        new_outline = dict(called, record_count=2, harness_version=12)
        check("PHP multi-record rows require the union evaluator; plain legacy "
              "rows retain their unchanged set meaning",
              direct_methods(old_outline, b, php_index) is None
              and direct_methods(new_outline, b, php_index) == ({total}, 0)
              and direct_methods(dict(old_outline, record_count=1), b, php_index) == ({total}, 0))

        r = os.path.join(d, "run.jsonl")
        with open(r, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i1", "coverage": False}) + "\n")
        try:
            load_runs(r)
            check("a run stamped coverage=false raises", False, "no exception")
        except MetricsInputError as e:
            check("a run recorded without --coverage refuses to be scored",
                  "--coverage" in str(e))
        # A sensitivity re-execution never shares a file with primary rows,
        # even when the labelled row is the one that survives.
        with open(r, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i1", "outcome": "not_passed"}) + "\n")
            fh.write(json.dumps({"item_id": "i1", "outcome": "passed",
                                 "sensitivity": "webmock_world_v1"}) + "\n")
        try:
            read_runs(r)
            check("a file mixing sensitivity labels raises", False, "no exception")
        except MetricsInputError as e:
            check("a sensitivity row cannot hide in a primary run file",
                  "mixes sensitivity labels" in str(e), str(e))
        with open(r, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i1", "outcome": "passed",
                                 "sensitivity": "webmock_world_v1"}) + "\n")
        check("a file of one sensitivity label reads as usual",
              read_runs(r)["i1"]["sensitivity"] == "webmock_world_v1")
        # A MIXED file is the dangerous one: the all-false file is obvious.
        with open(r, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(_rec("i1", {"src/Prod/Tax.php": [5]}),
                                     coverage=True)) + "\n")
            fh.write(json.dumps({"item_id": "i2", "outcome": "passed",
                                 "coverage": False}) + "\n")
        try:
            load_runs(r)
            check("ONE uncovered row in a mixed file raises", False, "no exception")
        except MetricsInputError as e:
            check("a single coverage=false row cannot hide in a mixed run file",
                  "1 of 2" in str(e), str(e))
        with open(r, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(_rec("i1", {"src/Prod/Tax.php": [5]}),
                                     coverage_mismatch=["src/Prod/Tax.php"])) + "\n")
        try:
            load_runs(r)
            check("a lossy coverage row raises", False, "no exception")
        except MetricsInputError as e:
            check("a row whose coverage lines were lost is refused, not scored",
                  "coverage_mismatch" in str(e))
        with open(r, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(_rec("i1", {"src/Prod/Tax.php": [5]},
                                     outcome="failed")) + "\n")
            fh.write(json.dumps(_rec("i1", {"src/Prod/Tax.php": [5, 6]})) + "\n")
        check("a re-run item keeps its LAST row",
              load_runs(r)["i1"][COVERAGE_FIELD]["src/Prod/Tax.php"] == [5, 6])

    # ----------------------------------------------------------------------
    # The SECOND producer of this loader's input.  `php_prod_index.json` came
    # from `r2t/php/analyze_php.php`; `py_prod_index.json` comes from
    # `r2t/py/prod_index.py`, and the whole value of the second one is that
    # this loader accepts it -- an index the metric cannot read is not an
    # index.  Checked by BUILDING one here rather than against a fixture
    # copied out of the producer, because a fixture is exactly what stops
    # tracking a producer that changed.
    from ..py.prod_index import build_prod_index
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "src", "lib"))
        with open(os.path.join(d, "src", "lib", "api.py"), "w",
                  encoding="utf-8") as fh:
            fh.write("def Document(path):\n"
                     "    return Doc(path)\n"
                     "\n"
                     "\n"
                     "class Doc:\n"
                     "    def __init__(self, path):\n"
                     "        self._p = path\n"
                     "\n"
                     "    @property\n"
                     "    def text(self):\n"
                     "        return self._p\n"
                     "\n"
                     "    def _hidden(self):\n"
                     "        return 2\n")
        built = os.path.join(d, "py_prod_index.json")
        with open(built, "w", encoding="utf-8") as fh:
            json.dump(build_prod_index(d), fh)
        py_index = load_prod_index(built)
        rel = "src/lib/api.py"
        keys = {m.key for m in py_index[rel]}
        check("the Python producer's envelope loads through the SAME loader "
              "the PHP one does",
              rel in py_index and ("lib.api.Doc", "text") in keys, str(keys))
        # `load_prod_index` reads `cls["name"]` and requires `cls["methods"]`;
        # it never asks what KIND of owner that is.  That is what lets a
        # module-level function -- `docx.api.Document`, the entry point of
        # python-docx and 21 others like it -- be indexed at all, and it is
        # a property of the loader rather than of the producer, so it is
        # pinned on this side of the seam.
        check("a module-level function survives the loader under its "
              "MODULE's name",
              ("lib.api", "Document") in keys, str(keys))
        hidden = _rec("i1", {}, direct=[
            _call(rel, 13, "lib.api.Doc._hidden", "src/Test/steps.py")])
        check("visibility crosses the seam: a `_`-prefixed method is loaded "
              "and then excluded by the metric, not dropped by the producer",
              ("lib.api.Doc", "_hidden") in keys
              and direct_methods(hidden, b, py_index) == (set(), 0),
              str(direct_methods(hidden, b, py_index)))
        # The producer's `decl` and this module's join are one contract, and
        # a decorated method is where they can disagree: `text` is declared
        # on line 9 (`@property`) and its body starts on 11.
        decorated = _rec("i1", {}, direct=[
            _call(rel, 9, "lib.api.Doc.text", "src/Test/steps.py")])
        check("a decorated property joins on the DECORATOR line the producer "
              "recorded, which is the line a call event names",
              direct_methods(decorated, b, py_index)
              == ({("lib.api.Doc", "text")}, 0),
              str(direct_methods(decorated, b, py_index)))

    # ----------------------------------------------------------------------
    # The standalone entry point resolves `--boundary` and `--index` to
    # CoreShop by default, so it is the one route into these numbers that
    # can be handed a run it knows nothing about.  Both directions are
    # pinned here through `main` itself, because the defect was never in the
    # arithmetic -- it was that nothing between argv and the table asked
    # which project the run belonged to.
    import contextlib
    import io
    with tempfile.TemporaryDirectory() as d:
        cfg = os.path.join(d, "boundary.yml")
        with open(cfg, "w", encoding="utf-8") as fh:
            fh.write("version: 1\nproject: t\nrepo_root: /x\n"
                     "removable:\n  - path: src/Test/\n")
        idx = os.path.join(d, "idx.json")
        with open(idx, "w", encoding="utf-8") as fh:
            json.dump({"files": {"src/Prod/Tax.php": {"classes": [
                {"name": "App\\Tax", "methods": [
                    {"name": "rate", "start": 5, "end": 9, "public": True,
                     "static": False, "abstract": False}]}]}}}, fh)
        cov = {"src/Prod/Tax.php": [5, 6]}
        gold = os.path.join(d, "gold.jsonl")
        with open(gold, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(_rec("t/features/domain/a.feature:3", cov))
                     + "\n")
        foreign = os.path.join(d, "foreign.jsonl")
        with open(foreign, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(_rec("other/features/domain/a.feature:3", cov))
                     + "\n")
        argv = ["--gold", gold, "--boundary", cfg, "--repo", "/x",
                "--index", idx, "--no-self-check"]
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                main(argv + ["--run", foreign])
            check("a run from another project refuses", False, "no exception")
        except SystemExit as e:
            check("a run whose rows name another project is refused BY NAME, "
                  "before one metric of the wrong surface is printed",
                  str(e).startswith("REFUSED:") and "'other'" in str(e)
                  and "'t'" in str(e) and out.getvalue() == "",
                  str(e) + " | stdout=" + repr(out.getvalue()))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = main(argv + ["--run", gold])
        check("a run scored against its OWN project's surface still scores",
              rc == 0 and "1.000" in out.getvalue(), out.getvalue())

    # Java's collector and index already share the JVM identity. Exercise
    # their JSON shapes through the normal loader and scoring entry point,
    # without compiling the collector or provisioning a Java workspace.
    with tempfile.TemporaryDirectory() as d:
        java_file = "src/main/java/app/Api.java"
        glue = "src/test/java/app/Steps.java"
        kept = "src/test/java/app/unit/utils/Helper.java"
        jb = Boundary(version=1, project="t", repo_root=d,
                      removable=[("src/test/java/", "glue")],
                      retained=[("src/test/java/app/unit/utils/", "helpers")])
        # All spans coincide deliberately: source lines cannot distinguish
        # these overloads or the two binary classes in the same source file.
        methods = [dict(name=name, descriptor=desc, start=10, end=20,
                        public=public)
                   for name, desc, public in (
                       ("call", "()I", True), ("call", "(I)I", True),
                       ("<init>", "()V", True),
                       ("<init>", "(I)V", False),
                       ("hidden", "()I", False),
                       ("transitive", "()I", True))]
        java_index = os.path.join(d, "java_prod_index.json")
        with open(java_index, "w", encoding="utf-8") as fh:
            json.dump({"schema": "r2t.java_prod_index/1", "language": "java",
                       "root": "src/main/java", "files": {
                           java_file: {"classes": [
                               {"name": "app.Api", "methods": methods},
                               {"name": "app.Api$1", "methods": [methods[0]]}]}}},
                      fh)
        ji = load_prod_index(java_index)
        check("Java descriptors survive loading and overloads keep distinct keys",
              [m.key for m in ji[java_file]][:3]
              == [("app.Api", "call:()I"), ("app.Api", "call:(I)I"),
                  ("app.Api", "<init>:()V")]
              and ji[java_file][1].descriptor == "(I)I")

        def jcall(method, caller=glue, callee_file=java_file, cls="app.Api"):
            return _call(callee_file, None, f"{cls}.{method}", caller)

        constructor = jcall("<init>:()V")
        overload_a, overload_b = jcall("call:()I"), jcall("call:(I)I")
        check("Java public constructors count once; private methods and "
              "constructors are mapped without credit or unmapped diagnostics",
              direct_methods(_rec("j", {}, direct=[
                  constructor, constructor, jcall("<init>:(I)V"),
                  jcall("hidden:()I")]), jb, ji)
              == ({("app.Api", "<init>:()V")}, 0))
        check("Java uses binary declaring class and full descriptor with "
              "null lines, including nested classes without folding",
              direct_methods(_rec("j", {}, direct=[
                  overload_a, overload_b, jcall("call:()I", cls="app.Api$1"),
                  jcall("call:()I", cls="app.Api$Missing"),
                  jcall("call:(J)I")]), jb, ji)
              == ({("app.Api", "call:()I"), ("app.Api", "call:(I)I"),
                   ("app.Api$1", "call:()I")}, 2))
        check("Java ignores production, retained and unresolved callers, "
              "non-production and unresolved callees, and class initialisers",
              direct_methods(_rec("j", {}, direct=[
                  jcall("transitive:()I", caller=java_file),
                  jcall("call:()I", caller=kept),
                  jcall("call:()I", caller=None),
                  jcall("missing:()I", caller=kept),
                  jcall("call:()I", callee_file=glue),
                  jcall("call:()I", callee_file=kept),
                  jcall("call:()I", callee_file=None),
                  jcall("<clinit>:()V")]), jb, ji) == (set(), 0))

        cov = {java_file: [10, 11]}
        jgold = _rec("j", cov, direct=[constructor, overload_a])
        jrun = _rec("j", cov, direct=[constructor, overload_b])
        missing = _rec("j", cov)
        null = dict(missing, direct_calls=None)
        empty = _rec("j", cov, direct=[])
        check("Java missing/null direct_calls stay unmeasured; an empty "
              "candidate is measured zero and empty gold is excluded",
              direct_methods(None, jb, ji) is None
              and all(direct_methods(r, jb, ji) is None
                      and compare(jgold, r, ji, jb)["api_undefined_reason"]
                      == "run_without_direct_calls" for r in (missing, null))
              and direct_methods(empty, jb, ji) == (set(), 0)
              and compare(jgold, empty, ji, jb)["api"]
              == {"precision": 0.0, "recall": 0.0, "f1": 0.0}
              and compare(empty, jrun, ji, jb)["api_excluded"]
              and compare(empty, jrun, ji, jb)["gold_no_methods"])

        gold_path, run_path = (os.path.join(d, name)
                               for name in ("gold.jsonl", "candidate.jsonl"))
        for path, row in ((gold_path, jgold), (run_path, jrun)):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(row) + "\n")
        with contextlib.redirect_stdout(io.StringIO()):
            scored = report(gold_path, [run_path], java_index, jb)["candidate"]
        check("ordinary metrics report scores distinct Java overloads plus "
              "their shared constructor at API 0.5 with identical coverage",
              all(scored["metrics"][f"api.{metric}"]["mean_defined"] == 0.5
                  for metric in ("precision", "recall", "f1"))
              and scored["metrics"]["coverage.recall"]["mean_defined"] == 1.0
              and scored["n_api_scored"] == 1
              and scored["unmapped_direct_events"]
              == {"gold": 0, "sys": 0}, str(scored))

        cfg = os.path.join(d, "boundary.yml")
        with open(cfg, "w", encoding="utf-8") as fh:
            fh.write("version: 1\nproject: algorand-sdk\n"
                     "removable:\n  - path: src/test/java/\n")
        for path, row in ((gold_path, jgold), (run_path, jrun)):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(dict(
                    row, item_id="algorand-sdk/features/unit/a.feature:1"))
                         + "\n")
        argv = ["--gold", gold_path, "--run", run_path,
                "--boundary", cfg, "--repo", d]
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                main(argv)
            rc = 0
        except SystemExit as exc:
            rc = exc.code
        check("the Java metrics CLI requires an explicit index before "
              "reading CoreShop's installed default or printing a score",
              rc == 2 and "--index is required for project 'algorand-sdk'"
              in err.getvalue() and out.getvalue() == "", err.getvalue())
        with contextlib.redirect_stdout(out):
            rc = main(argv + ["--index", java_index])
        check("the Java metrics CLI uses the explicitly selected index",
              rc == 0 and f"index : {java_index}" in out.getvalue(),
              out.getvalue())

        # Not a Java rule: only CoreShop's index is a default, so any other
        # project -- here a Python one with its own rows -- refuses the same.
        with open(cfg, "w", encoding="utf-8") as fh:
            fh.write("version: 1\nproject: python-docx\n"
                     "removable:\n  - path: features/steps/\n")
        for path, row in ((gold_path, jgold), (run_path, jrun)):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(dict(
                    row, item_id="python-docx/features/a.feature:1")) + "\n")
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                main(argv)
            rc = 0
        except SystemExit as exc:
            rc = exc.code
        check("a non-CoreShop, non-Java boundary also requires an explicit "
              "index before reading CoreShop's default or printing a score",
              rc == 2 and "--index is required for project 'python-docx'"
              in err.getvalue() and out.getvalue() == "", err.getvalue())

    print("\n" + ("ALL PASS (metrics)" if ok else "FAILURES (metrics)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
