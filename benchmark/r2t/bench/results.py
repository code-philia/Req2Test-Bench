"""THE canonical results table: `python3 -m r2t.cli results --run <run.jsonl>`

Evaluating any approach or any agent on this benchmark returns ONE table, of
one fixed shape, in one fixed row order.  Thirteen rows:

    generation failure           ran to completion, wrote no test code
    compilation failure          parse_or_compile_error + container_error
    binding failure              undefined_steps + pending
    execution failure            solution_error + no_scenario_ran + timeout
    assertion failure            failed
    pass rate                    passed
    mutation recall              |C n G| / |G|
    mutation only-generated kills  |C \\ G| / |C u G|
    mutation jaccard similarity  |C n G| / |C u G|
    coverage jaccard similarity  production lines the scenario drove
    api precision                (fqcn, public production method) pairs
    api recall
    api f1

The first six are THE FAILURE LADDER and they are over ALL instances, with no
sub-breakdown: the ladder answers "how far did this system get, over the whole
benchmark".  `report.py` keeps the finer picture (sixteen outcomes, a
partial-credit tally, the cost accounting) and that is the right place for it;
what a results table needs is the six stages a reader can act on.

**The ladder is ordered by the execution pipeline, and generation comes
first.**  You cannot compile what was never written, so "the system produced
no test code" is the ladder's first rung by the ladder's own logic -- not a
footnote under it.  Two things follow.  The six stages sum to 100% of the
instances, so a reader sees the whole benchmark in one column instead of a
ladder that accounts for 7% of the mass with the other 93% in a line labelled
"outside the ladder"; and the row reads uniformly with its neighbours
(generation -> compilation -> binding -> execution -> assertion -> pass),
which is what makes the column scannable.

**What `generation failure` means, exactly, and what it must never absorb.**
It means THE SYSTEM RAN TO COMPLETION AND PRODUCED NO TEST CODE -- the agent
declined, gave up, or wrote only outside the removable tree.  It does NOT mean
"no files reached the harness", because that is also what a killed driver, a
dropped transport or a crashed metadata read look like from the outside, and
those are the benchmark failing rather than the system declining.  A row is
therefore a generation failure only when its outcome is `no_files_returned`
AND it carries no infrastructure marker (`metadata.driver_error`,
`metadata.metadata_error`, or `agent_stats.run_errors`, each meaningful only
with nothing produced);
`harness_error`, `scenario_not_found` and PrestaShop's `fixture_consumed` are
infrastructure whatever else they carry.  This is not a hypothetical
distinction: four rows of the standard-setting sweep were killed by the
transport and were re-run under the protocol precisely because they were not
the system's failure.  Any that
survive into a run file are counted on a `not scored (infrastructure)` line
below the table and are OUT of the ladder denominator, which is printed
whenever it is not n.  One driver stop is the system's own and marks nothing:
a run the driver ended at the agent's native request cap
(`NATIVE_BUDGET_STOPS`) is the system running out of budget without writing a
test, a generation failure (owner decision 2026-09-25) exactly as an OpenHands
row that exhausts its iterations already is.

**Why compilation is one row and not two.**  `parse_or_compile_error` (the
submitted PHP does not parse or does not compile) and `container_error` (it
compiled, and the DI container could not be built from it) are a syntax
failure and a wiring failure.  The distinction is real and the harness is
right to record it, but at table altitude both say "the submission never
became runnable code", and two rows invite a reader to compare them as if the
split were a finding about the system rather than about where PHP happens to
stop.  The split therefore stays in the detail dict (and in `--format json`)
and never becomes a table row.

WHY THE DENOMINATORS DIFFER
---------------------------
The ladder describes what a system DID over the whole benchmark, so it is over
all instances.  The seven quality rows describe how good a WORKING test is, and
they are undefined for a system that produced nothing, or produced something
that does not run: there is no test to measure.  Computing them over all
instances does not make them more honest, it makes them a second copy of the
pass rate -- measured on the standard run, coverage jaccard is 0.060 over the
100 items and 0.922 over the 5 that passed, and the 0.060 is 0.922 x (5/100)
plus rounding.  Reporting them over the passed instances only is therefore the
honest choice, and the count of passed instances is printed with the table so
that 0.92 can never be read as a whole-benchmark claim.  With no passed
instance at all the rows print `n/a (0 passed)` -- never 0.0, and never a
division by zero: a system that solved nothing did not test nothing perfectly.

MACRO, NOT MICRO
----------------
Every quality row is the MEAN OVER PASSED INSTANCES of that instance's own
value.  Pooling (summing numerators and denominators across instances) is
available in `--format json` and is deliberately not printed, because pooling
lets one instance outvote the rest and that is live on this benchmark, not
hypothetical: of the 300 scored gold kills over the five passed items, 249
belong to `install_demo_data_command.feature:7` alone, so a pooled mutation
figure would be 83% one instance's test.  The mutation gate (SPEC 3.10)
already aggregates macro for exactly this reason, and a results table that
aggregated the other way would disagree with the benchmark's own gate.

`--format json` keeps every input a micro figure needs (per-instance killed /
denominator / candidate-only counts, per-instance coverage and api values), so
a reader who wants the pooled number can compute it and say that they did.

NOT SCORED IS NOT ZERO
----------------------
A metric that was not computed prints why, never a number.  No test-quality
sidecar beside the run means nobody has run `r2t.cli test-quality` yet -- not
that the passes test nothing.  No gold run, or a run recorded without
`--coverage`, means the comparison has no upper bound or no evidence -- not
that the system covered nothing.  This is the same distinction `metrics.py`
keeps with `undefined_reason` and it is the whole point of having one.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import statistics
import textwrap
from collections import Counter
from typing import Optional

from . import draws
from . import metrics as M
from . import population as P
from . import test_quality as TQ
from ..core.boundary import Boundary
from ..core.constants import PROD_INDEX_NAMES
from ..core.paths import project_path
from ..data.profile import (API_SCORING_METHOD_INDEX, API_SCORING_MODES,
                      API_SCORING_NONE)

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCHMARK = os.path.dirname(HERE)
#: Mirrors `cli.py` rather than importing it, as `metrics.py` does: this
#: module must stay importable from an analysis script with no CLI.
DEFAULT_BOUNDARY = os.path.join(BENCHMARK, "config", "boundary_coreshop.yml")
DEFAULT_ARTIFACTS = project_path("coreshop", "artifacts")
RUNS_DIR = "runs"
#: The gold run to compare against when `--gold` is not given, tried in this
#: order under `<artifacts>/runs`.  A list rather than one name because the
#: gold sweep is named after the release it covers; whichever is found is
#: PRINTED in the provenance block, so a default can never be a mystery.
GOLD_RUN_NAMES = ("eval100_gold.jsonl", "gold.jsonl")

#: The standard-setting run, and the frozen rendering of its table payload.
#: The fixture is committed; the run is an archived artifact that only exists
#: on the machine that produced it, so the byte-check that binds them is
#: GUARDED on the run being present and is skipped, loudly, where it is not.
ARCHIVED_RUN_NAME = "eval100_std.merged.jsonl"
LEGACY_FIXTURE = os.path.join(BENCHMARK, "release", "v1",
                              "legacy_table_eval100_std.md")
LEGACY_RELEASE = os.path.join(BENCHMARK, "release", "eval100.jsonl")

#: How the archived byte pin is ARMED (R4 item 9).
#:
#: The pin was disarmed by construction, at both call sites: the archived
#: sidecar is preserved LEGACY evidence with no `r2t.test-quality-binding/v1`
#: binding, so `load_bound_test_quality` refuses it -- `results.selftest`
#: turned that into a printed SKIP and `scripts/gate_s6_release.py` into an
#: uncaught refusal.  Neither is a check.  The pin needs a validated legacy
#: WRAPPER (plan §4 step J3 produces one with `r2t test-quality-bind`), and a
#: wrapper is an operator artifact that lives outside the repository, so the
#: path has to be supplied rather than discovered.  Supplying it is what arms
#: the pin; every way of supplying it wrongly is a NAMED failure below.
LEGACY_PIN_ENV = "R2T_CORESHOP_TEST_QUALITY_WRAPPER"


def legacy_pin_verdict(wrapper_path: Optional[str], *,
                       run_path: Optional[str] = None,
                       fixture_path: Optional[str] = None,
                       artifacts: str = DEFAULT_ARTIFACTS):
    """`True`, or a string saying exactly what stopped the byte pin.

    Never raises and never returns a bare False: a gate that says "the pin did
    not pass" without saying WHY is a gate an operator works around.  The
    caller decides whether an unarmed pin is a skip (the selftest, on a machine
    with no archive) or a failure (the S6 gate, whose whole job is this
    comparison) -- which is why the unarmed case is distinguishable by the
    `wrapper_path is None` argument rather than by parsing this string.

    The comparison is over the NINE non-API rows.  The published table's API
    numbers were computed under the coverage-derived definition, the caller
    of each production call was never recorded for that run, and nothing
    recomputes them: they are `legacy_consistency` evidence at harness
    version 5, read back by `legacy_api_rows` (spec 7.1).  Narrowed rather
    than satisfied by a special case -- the nine rows the current code can
    still reproduce are still compared byte for byte.
    """
    if not wrapper_path:
        return (f"no test-quality wrapper supplied: set ${LEGACY_PIN_ENV} or "
                f"pass --coreshop-test-quality-wrapper. The archived sidecar "
                f"is unbound legacy evidence, so the pin is INERT until the "
                f"plan §4 J3 ceremony produces a wrapper for it")
    run = run_path or os.path.join(artifacts, RUNS_DIR, ARCHIVED_RUN_NAME)
    fixture = fixture_path or LEGACY_FIXTURE
    if os.path.islink(wrapper_path) or not os.path.isfile(wrapper_path):
        return f"the supplied test-quality wrapper is not a regular file: {wrapper_path}"
    if not os.path.isfile(run):
        return f"the archived run {run} is not on this machine"
    if not os.path.isfile(fixture):
        return f"no frozen payload at {fixture}"
    try:
        res = results(run, test_quality_path=wrapper_path, artifacts=artifacts,
                      gold_path=default_gold_run(artifacts) or "",
                      language="php", release_path=LEGACY_RELEASE)
        rendered = render(res, "markdown-legacy")
    except (ResultsInputError, M.MetricsInputError, draws.DrawRefusal,
            OSError, ValueError) as e:
        # A stale or tampered wrapper arrives here as its own refusal text.
        # Returned rather than raised so the gate can NAME it beside the
        # check, instead of dying with a traceback that says nothing about
        # which comparison was being made.
        return f"the wrapper did not validate: {e}"
    with open(fixture, encoding="utf-8") as fh:
        frozen = fh.read()
    frozen_rows, rendered_rows = _table_rows(frozen), _table_rows(rendered)
    compared = [label for label in frozen_rows
                if label not in LEGACY_API_LABELS]
    if any(rendered_rows.get(label) != frozen_rows[label]
           for label in compared):
        frozen_label = (os.path.relpath(LEGACY_FIXTURE,
                                        os.path.dirname(BENCHMARK))
                        if not fixture_path else os.fspath(fixture))
        diff = "".join(difflib.unified_diff(
            [f"| {label} | {frozen_rows[label]} |\n" for label in compared],
            [f"| {label} | {rendered_rows.get(label, MISSING_ROW)} |\n"
             for label in compared],
            fromfile=frozen_label, tofile="rendered"))
        return ("the rendering differs from the frozen payload on the "
                "non-API rows:\n" + diff)
    return True


def _table_rows(markdown: str) -> dict[str, str]:
    """`{label: value}` from a rendered payload's `| label | value |` rows."""
    rows = {}
    for line in markdown.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) == 2 and cells[0] not in ("metric", "---"):
            rows[cells[0]] = cells[1]
    return rows


def legacy_api_rows(fixture_path: Optional[str] = None) -> dict:
    """The published table's three API rows, labelled as the history they are.

    Read out of the FROZEN file and never out of a fresh rendering: those
    numbers were computed from covered lines at harness version 5, this code
    no longer computes anything of the kind, and a value re-derived today
    would be a different measurement wearing their label.  Printed beside the
    verdict by `selftest` and by `scripts/gate_s6_release.py`, so the rows the
    pin stopped comparing are still shown rather than dropped.
    """
    with open(fixture_path or LEGACY_FIXTURE, encoding="utf-8") as fh:
        rows = _table_rows(fh.read())
    return {"label": LEGACY_CONSISTENCY,
            "harness_version": LEGACY_TABLE_HARNESS_VERSION,
            "rows": {label: rows[label] for label in LEGACY_API_LABELS}}


#: The ladder, in pipeline order: generation, then compilation, then binding,
#: then execution, then assertion, then the pass.  `(key, label, outcomes)`.
#: The legacy payload's order is frozen separately in `LEGACY_ROWS`.  The
#: current canonical table changes only through a recorded SPEC decision, so
#: two systems' current tables still mean the same thing by row three.
LADDER: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    # Exactly one outcome, and no near-neighbours folded in.  `parse_error`
    # (the adapter's own output could not be read) and `no_writable_files`
    # (something was written, all of it outside the removable tree) are also
    # "no test code arrived", and both are deliberately NOT here: widening a
    # rung silently changes what a published percentage means.  They land on
    # the `not scored` line below the table instead, where a human can see
    # them and decide -- adding a rung is an edit to this tuple, made on
    # purpose.
    ("generation_failure", "generation failure",
     ("no_files_returned",)),
    ("compilation_failure", "compilation failure",
     ("parse_or_compile_error", "container_error")),
    ("binding_failure", "binding failure",
     ("undefined_steps", "pending")),
    ("execution_failure", "execution failure",
     ("solution_error", "no_scenario_ran", "timeout", "not_passed")),
    ("assertion_failure", "assertion failure",
     ("failed",)),
    ("pass_rate", "pass rate",
     ("passed",)),
)

#: Outcomes that are the BENCHMARK failing, not the system.  They are never a
#: rung: a scenario the harness could not find and a harness that raised say
#: nothing whatever about the submission.  `fixture_consumed` is the PrestaShop
#: harness restoring a shared upload fixture the row's own execution used up;
#: the resource reset spec's rule 3 calls it infrastructure, and the owner
#: applied that to generation rows on 2026-09-29 (its rule 5).
INFRASTRUCTURE_OUTCOMES = ("harness_error", "scenario_not_found", "fixture_consumed")

#: Row fields that mark a driver/transport failure.  Checked only on the
#: ambiguous `no_files_returned` outcome when the row carries no candidate
#: evidence: that is where infrastructure failure is INDISTINGUISHABLE from
#: the system declining.  Every other terminal outcome is the evidence.
DRIVER_ERROR_FIELDS = ("driver_error", "metadata_error", "adapter_error")

#: Termination reasons a driver declares when the agent's own native budget
#: stopped it: the Codex relay's request cap (`confined.codex_driver`).  Such
#: a stop is an observation of the system, not the benchmark failing (owner
#: decision 2026-09-25).  A wall-clock envelope is not one: the adapter records
#: it as `timeout`, and the ladder's treatment of timeouts is unchanged.
NATIVE_BUDGET_STOPS = ("max_model_calls", "content_fallback")
#: `content_fallback` is the Claude Sonnet 5.5 arm's (owner ruling 2026-10-08,
#: specifications/CLAUDE_CODE_SONNET_5_5_AMENDMENT.md section 5.3): the relay's
#: model check ended the attempt, so the ladder treats it as it treats the cap
#: -- files harvested at the stop are the attempt's submission, and an attempt
#: without files is a generation failure, never infrastructure.

#: Termination reasons the same arm's relay declares on its subscription route
#: when the ACCOUNT, not the system, ended an attempt (section 5.3): a rate
#: limit, a plan limit or an account refusal. The launcher requeues such a cut
#: automatically; a cut row that is not requeued is infrastructure whether or
#: not it wrote files, so that pass rates do not measure the account's
#: throttling.
ACCOUNT_CUT_STOPS = ("rate_limit", "plan_limit", "account_auth")

#: The exit of a driver that stopped and preserved its evidence
#: (`confined.terminate.EXIT_TERMINATED`, restated because the consumer route
#: does not import the agent component; the Codex driver self-test binds both).
DRIVER_TERMINATED_EXIT = 75

#: Outcomes deliberately left outside the methodology's ladder.  They remain
#: disclosed below the table and leave its denominator; every other outcome
#: absent from `LADDER` is genuinely unknown and withholds the primary ladder.
DISCLOSED_EXCLUDED_OUTCOMES = ("parse_error", "no_writable_files")

#: Buckets that are not rungs.  The first two deliberately leave the ladder
#: denominator and retain their existing disclose-and-exclude behaviour.  A
#: genuinely unknown terminal outcome stays IN the expected system population
#: but cannot be placed on a rung, so it withholds every primary ladder rate.
INFRASTRUCTURE = "infrastructure"
UNCLASSIFIED = "unclassified"
UNKNOWN = "unknown"
EXCLUDED_LABEL = {INFRASTRUCTURE: "not scored (infrastructure)",
                  UNCLASSIFIED: "not scored (outcome not in the ladder)"}

#: The seven quality rows, in table order.  `(key, label, block, path)` where
#: `path` addresses the value inside its block's `values` dict.
QUALITY_ROWS: tuple[tuple[str, str, str, str], ...] = (
    ("mutation_recall", "mutation recall", "mutation", "recall"),
    ("mutation_only_gen", "mutation only-generated kills", "mutation",
     "only_gen"),
    ("mutation_jaccard", "mutation jaccard similarity", "mutation", "jaccard"),
    ("coverage_jaccard", "coverage jaccard similarity", "coverage", "jaccard"),
    ("api_precision", "api precision", "api", "precision"),
    ("api_recall", "api recall", "api", "recall"),
    ("api_f1", "api f1", "api", "f1"),
)

#: What a v2 summary says it is, per FULL_POPULATION_SINGLE_OBSERVATION_SPEC.
#: Spelled here rather than imported from `test_quality`: the scorer that
#: WRITES a v2 summary lands on its own branch, and this renderer is written
#: against the reviewed contract, not against whichever module happens to
#: define the token first.  Integration folds the two into one definition.
TEST_QUALITY_SUMMARY_SCHEMA_V2 = "r2t.test-quality-summary/v2"
SINGLE_OBSERVATION_METHOD = "single_observation"
FULL_POPULATION_SINGLE_OBSERVATION_POLICY = \
    "r2t.full-population-single-observation/1"

#: v2 adds a SAME-OBSERVATION companion view without changing the historical
#: quality rows above.  The hard-basis rows remain visible first: recall is
#: the primary, while only-generated and Jaccard are explicitly n/a because
#: the reviewed method defines neither over H_i.  These three are then the
#: separately labelled full-population companion over G_i.
V2_COMPANION_ROWS: tuple[tuple[str, str, str, str], ...] = (
    ("mutation_full_recall_companion",
     "mutation recall (companion, full population)",
     "mutation_companion", "recall"),
    ("mutation_full_only_gen_companion",
     "mutation only-generated kills (companion, full population)",
     "mutation_companion", "only_gen"),
    ("mutation_full_jaccard_companion",
     "mutation jaccard similarity (companion, full population)",
     "mutation_companion", "jaccard"),
)

#: The checked-interface SECONDARY rows (TARGET_INTERFACES_V2_SPEC 6.2/6.3),
#: rendered below the thirteen and never among them.  A separate tuple, not an
#: addition to `QUALITY_ROWS` and emphatically not to `LEGACY_ROWS`: the
#: canonical table's shape is a methodology decision, `legacy_pin_verdict`
#: iterates the frozen labels, and none of these rows moves a canonical value.
#: They appear only when their inputs are given, so an ordinary `results`
#: invocation renders exactly what it rendered before.
#:
#: `(key, label, block, path)` where `block` names a sub-block of
#: `res["secondary"]` and `path` a key of its `values`.
SECONDARY_ROWS: tuple[tuple[str, str, str, str], ...] = (
    ("target_region_recall", "target-region recall (mean over scored)",
     "target_region", "recall"),
    ("reaches_target_rate", "reaches-target rate (full denominator)",
     "target_region", "reaches_rate"),
    ("undisclosed_api_f1", "undisclosed-api f1 (mean over scored)",
     "undisclosed_api", "f1"),
    ("coverage_jaccard_over_total",
     "coverage jaccard similarity (full denominator)",
     "full_denominator", "coverage.micro_jaccard"),
    ("api_precision_over_total", "api precision (full denominator)",
     "full_denominator", "api.precision"),
    ("api_recall_over_total", "api recall (full denominator)",
     "full_denominator", "api.recall"),
    ("api_f1_over_total", "api f1 (full denominator)",
     "full_denominator", "api.f1"),
)

#: Why a secondary row prints no number.  Each is a different action for the
#: reader, which is why there is no single "n/a".
NO_TARGET_REGIONS = ("not scored (no target-region artifact; build one with "
                     "`r2t target-regions`)")
NO_CHECKED_INTERFACES = ("not scored (no item carries `checked_interfaces`; "
                         "pass the release items file that does)")
NO_REGION_SCORABLE = ("not scored (no item's gold run covers a line of its "
                      "reviewed target region)")
NO_UNDISCLOSED_SCORABLE = ("not scored (every scorable item's whole gold "
                           "direct-call set is disclosed)")
#: What the interval says when the corpus cannot support one.  The descriptive
#: mean is still printed beside it: below the floor the point estimate remains
#: meaningful, the interval does not.
INTERVAL_NO_CLUSTERS = "no closure-cluster map supplied"

#: The published v1 payload, by key and in its original order.  This tuple is
#: deliberately explicit rather than derived from `LADDER` or `QUALITY_ROWS`:
#: adding a current canonical row must not silently add it to the byte-pinned
#: legacy rendering.
LEGACY_ROWS: tuple[str, ...] = (
    "generation_failure",
    "compilation_failure",
    "binding_failure",
    "execution_failure",
    "assertion_failure",
    "pass_rate",
    "mutation_recall",
    "mutation_jaccard",
    "coverage_jaccard",
    "api_precision",
    "api_recall",
    "api_f1",
)

#: The three rows §7.1 stops comparing against the published payload, by the
#: key `QUALITY_ROWS` gives them and by the label the frozen file carries.
#: The labels are derived: two hand-kept copies of one row name is exactly
#: how a narrowed check quietly stops narrowing the row it meant to.
LEGACY_API_ROWS: tuple[str, ...] = ("api_precision", "api_recall", "api_f1")
LEGACY_API_LABELS: tuple[str, ...] = tuple(
    label for key, label, _block, _name in QUALITY_ROWS
    if key in LEGACY_API_ROWS)
#: The evaluator identity those three numbers were computed under, and the
#: label `AGENTS.md` reserves for historical evidence.
LEGACY_TABLE_HARNESS_VERSION = 5
LEGACY_CONSISTENCY = "legacy_consistency"
#: What a narrowed diff prints for a row the rendering did not produce at all.
MISSING_ROW = "(absent)"

#: What a row prints when the metric was not computed.  One string per cause,
#: because "nobody scored this yet" and "this run has no coverage" call for
#: different actions and a single "n/a" would hide which.
NOT_SCORED_MUTATION = "not scored (no bound test-quality evidence)"
NOT_SCORED_COVERAGE = "not scored (run with --coverage)"
NOT_MEASURED_API = "not_measured"
#: The API rows are computed from `direct_calls` and from nothing else, so a
#: run recorded before the recorder existed says THIS rather than a number
#: derived from its coverage (API_DIRECT_INVOCATION_SPEC.md 2.6).  Distinct
#: from `NOT_MEASURED_API`, which stays reserved for `api_scoring: none`.
NOT_SCORED_API_DIRECT = "not scored (no direct_calls in this run)"
NOT_SCORED_API_AMENDMENT = "not scored (recording predates API Amendment 2)"
NO_PASS = "n/a (0 passed)"
HARD_SUBSET_ONLY_GEN_REASON = (
    "hard-subset basis cannot measure full-population candidate-only kills"
)
HARD_SUBSET_ONLY_GEN = f"n/a ({HARD_SUBSET_ONLY_GEN_REASON})"
HARD_SUBSET_JACCARD_REASON = (
    "the single-observation method defines no hard-subset Jaccard"
)
HARD_SUBSET_JACCARD = f"n/a ({HARD_SUBSET_JACCARD_REASON})"
#: A gold-killed candidate slice observes no pair gold did not kill, so the
#: two measures that count such pairs were not measured
#: (GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md).  Never 0, never computed as if the
#: candidate had killed nothing outside gold's set.
GOLD_KILLED_NOT_MEASURED_REASON = (
    "candidate pairs restricted to gold-killed pairs"
)
GOLD_KILLED_NOT_MEASURED = f"not measured ({GOLD_KILLED_NOT_MEASURED_REASON})"
GOLD_KILLED_ROWS = ("mutation_only_gen", "mutation_jaccard")
#: The v2 companion rows a gold-killed slice of a hard-subset reference did
#: not measure (SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md section 6).
V2_GOLD_KILLED_ROWS = ("mutation_full_only_gen_companion",
                       "mutation_full_jaccard_companion")


def excluded_pairs_note(reference_excluded: object,
                        run_excluded: object,
                        omitted_items: object = None) -> str:
    """Section 5.1's mandatory suffix: what the denominator is missing.

    The scored universe is the mapped population minus the pairs whose
    terminal outcome was a timeout or an infrastructure failure -- the ones
    the reference observations lost, plus the ones this candidate run lost of
    its own.  Under the gold-killed candidate scope the run-side count covers
    only the executed `G_i` slice; candidate outcomes outside it are never
    observed, which the notes say beside it.  The spec requires both counts beside every number derived from
    the artifact, and requires them SEPARATELY: they are different sets,
    discovered at different times, and only the second moves per run.

    Both arguments are COUNTS, spelled `reference_excluded_count` and
    `candidate_excluded_count` everywhere from the producing summary to here.
    The producer also records `candidate_excluded_pairs`, the excluded pairs
    themselves; that is evidence, not a number, and passing it here would
    render a list of dicts where a reader expects a total.

    `omitted_items` is the declared-subset disclosure, which narrows the same
    denominator at the item layer rather than the pair layer.  It is appended
    only when a reference actually declared a subset, so an undeclared
    project's rendered string is unchanged.

    One string, shared with `report`, so a reader who meets the same fact in
    the canonical table and again in a report block does not have to work out
    whether the two are saying the same thing.
    """
    note = (f"(excluded pairs: {reference_excluded} reference, "
            f"{run_excluded} run)")
    if omitted_items:
        note += f" (declared subset: {omitted_items} item(s) omitted)"
    return note


class ResultsInputError(RuntimeError):
    """An input the table cannot be built from at all (a missing run file).

    Deliberately rare: everything that can degrade to a named "not scored"
    cell does so instead of raising, because a table with one honest gap is
    more useful than no table.
    """


# --------------------------------------------------------------------------
# inputs

def default_gold_run(artifacts: str,
                     project: Optional[str] = None) -> Optional[str]:
    """Prefer the installed bundle's validated scoring reference, if any.

    The legacy pin reader omits `project` to retain its historical inputs.
    Ordinary results supply the boundary's project. A declared reference
    that fails validation refuses; it cannot fall back to an older baseline.
    """
    if project is not None:
        from ..data.bundle import BundleRefused, installed_scoring_gold
        try:
            declared = installed_scoring_gold(artifacts, project)
        except BundleRefused as exc:
            raise ResultsInputError(
                f"invalid installed scoring gold: {exc}") from exc
        if declared is not None:
            return declared
    for name in GOLD_RUN_NAMES:
        path = os.path.join(artifacts, RUNS_DIR, name)
        if os.path.isfile(path):
            return path
    return None


def default_prod_index(artifacts: str,
                       language: Optional[str] = "php") -> Optional[str]:
    """Find the project's language-specific production index.

    PHP and Python indexes come from `index-prod`; the Java operator stages
    the compiled index as `java_prod_index.json`. Unknown languages have no
    default. An explicit `--prod-index` still takes precedence.
    """
    name = PROD_INDEX_NAMES.get(language or "")
    if name is None:
        return None
    path = os.path.join(artifacts, name)
    return path if os.path.isfile(path) else None


def _count_rows(path: str) -> int:
    with open(path, encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


def _all_rows(path: str) -> list[dict]:
    """EVERY line of the run file, uncollapsed.

    `M.read_runs` keeps the last row per item, which is the row a table is
    about; the lines it dropped are the only on-disk trace of an item that was
    re-run IN PLACE, and `r2t.bench.draws` needs them to say so.
    """
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _publication_rows(path: str) -> list[dict]:
    """Uncollapsed rows, refused unless each item occurs exactly once."""
    rows = _all_rows(path)
    # Lazy to keep `report`'s selftest import of this module cycle-free.
    from . import report as RP
    try:
        RP.check_unique_item_ids(rows, path)
    except RP.ReportRefusal as e:
        message = str(e)
        if message.startswith("REFUSED: "):
            message = message[len("REFUSED: "):]
        raise ResultsInputError(message) from None
    return rows


def _mean(values: list) -> Optional[float]:
    return statistics.mean(values) if values else None


def _digests(rows: dict[str, dict],
             field: str = "campaign_digest") -> Optional[list[str]]:
    """The value(s) the rows carry for one stamp field, or None.

    A list, not a string, even when there is one: a merged file whose shards
    were fingerprinted differently is a file whose rows were produced under
    two configurations, and collapsing that to "the" digest is how a table
    ends up quoting a provenance it does not have.

    The field is a parameter because the citation line needs the same
    convention for eight more fields, and every one of them can differ across
    a merged file for exactly the same reason.  `None` when NO row carries it
    -- which the citation renders as `?`, never as a default.

    PRESENCE, NOT TRUTHINESS.  The test is `field in r and r[field] is not
    None`, because the two questions differ for every falsy value a stamp can
    legitimately hold: `trials: 0` (no execution channel), `of: 0`, a
    `protocol_version` that could one day be 0, an empty-string label.  A
    truthiness filter renders all of them `?`, i.e. "nobody recorded this",
    which is the one thing `?` must never say about a value that WAS recorded.
    `None` stays excluded on purpose: `_run_stamp` writes explicit nulls for
    knobs a run did not have (`model`, `of` outside a campaign), and a null is
    genuinely "unrecorded".
    """
    seen = sorted({str(r[field]) for r in rows.values()
                   if field in r and r[field] is not None})
    return seen or None


def _cite(rows: dict[str, dict], field: str) -> str:
    """One citation field: its value, every value if the rows disagree, or `?`.

    `?` is load-bearing.  Rows produced before a field existed cannot carry
    it, and the honest rendering of "nobody recorded this" is a question mark
    -- not the current value of the constant, not the manifest's value, not a
    guess from a neighbouring field.  The archived eval100 table cites
    `D?(?) ... P?` for exactly that reason: it predates every one of these
    stamps, and a citation that filled them in from today's code would be
    asserting that a run from 2026-08-01 followed a protocol written on
    2026-08-02.
    """
    values = _digests(rows, field)
    if not values:
        return "?"
    return values[0] if len(values) == 1 else "|".join(values)


def citation(rows: dict[str, dict]) -> str:
    """The one-line identity of a table, assembled from its own rows.

    THE POINT.  A published number is only citable if a reader can say what
    it was measured on, by what, under which recipe, and in what setting --
    and until now the answer lived in prose beside the table.  This line puts
    it IN the table's provenance block, computed from the rows rather than
    from the code that is printing them, so a re-render of an archived run
    cites what that run recorded and not what this checkout currently is.

    Format, fixed:

        req2test D<dataset>(<subset>) / H<harness>@<commit> / P<protocol>
                 / <adapter> / <setting> / <class> (<model>, K=<k>)

    `K=` appears only for a campaign run, because K is a sharding fact and a
    single-process run has no such number -- printing `K=1` would claim one.
    """
    dataset = _cite(rows, "dataset_version")
    subset = _cite(rows, "subset_id")
    harness = _cite(rows, "harness_version")
    commit = _cite(rows, "harness_commit")
    proto = _cite(rows, "protocol_version")
    # `adapter_version` is `openhands@1`. Absent, the rows still name the
    # SYSTEM (`agent_system`, or the built adapter's own label), and the
    # honest rendering is that system at an unknown version -- `openhands@?`
    # -- rather than a bare `?`, which would throw away a fact the rows have.
    adapter = _cite(rows, "adapter_version")
    if adapter == "?":
        system = _cite(rows, "agent_system")
        if system == "?":
            # `openhands:deepseek` -> `openhands`: the built adapter's label
            # carries the model after a colon, and the model is printed
            # separately below.
            system = "|".join(sorted({v.split(":")[0] for v in
                                      (_digests(rows, "adapter") or [])})) or "?"
        adapter = f"{system}@?"
    setting = _cite(rows, "setting")
    klass = _cite(rows, "comparison_class")
    model = _cite(rows, "model")
    tail = model
    if _digests(rows, "campaign_digest"):
        tail += f", K={_cite(rows, 'of')}"
    return (f"req2test D{dataset}({subset}) / H{harness}@{commit} / P{proto} "
            f"/ {adapter} / {setting} / {klass} ({tail})")


# --------------------------------------------------------------------------
# the failure ladder, over all instances

def infrastructure_marker(row: dict) -> Optional[str]:
    """Why this row is the harness's failure rather than the system's, or None.

    Driver metadata is meaningful only on the ambiguous generation outcome
    that produced nothing.  Explicit infrastructure outcomes are authoritative
    first; every other terminal outcome is its own evidence, including an
    unknown one that must withhold the ladder.  On `no_files_returned`, check
    the driver's own error fields and then a recorded run error.

    Driver fields and `run_errors` count only when nothing was produced,
    deliberately.  An agent that hit an error but still wrote its files did
    not fail to generate, and treating a recorded error as fatal would remove
    an authoritative harness outcome from the system's denominator.

    A native budget stop (`_native_budget_stop`) waives the driver's exit
    (`driver_error` "rc=75") and the run error the native process it stopped
    leaves behind: that is what reaching the cap looks like, not the harness
    failing.  Adapter and metadata errors still mark the row.
    """
    outcome = row.get("outcome")
    if outcome in INFRASTRUCTURE_OUTCOMES:
        return outcome
    md = row.get("metadata") or {}
    cut = _declared_stop(md, ACCOUNT_CUT_STOPS)
    if cut:
        return "account_cut:" + cut
    if outcome != "no_files_returned":
        return None
    if not (row.get("produced_files") or row.get("n_files")):
        budget_stop = _native_budget_stop(md)
        for field in DRIVER_ERROR_FIELDS:
            if md.get(field) and not (budget_stop and field == "driver_error"):
                return field
        stats = md.get("agent_stats") or {}
        if stats.get("run_errors") and not budget_stop:
            return "agent_stats.run_errors"
    return None


def _native_budget_stop(md: dict) -> Optional[str]:
    """The native budget the driver declared it stopped at, or None.

    Read from evidence every such row already carries: the adapter's
    `returncode` is the driver's terminated exit, and the termination record
    the driver wrote into `agent_stats` names the budget.  Any other exit,
    including the adapter's envelope timeout (`returncode` -1), and any other
    declared reason, such as a stray signal's `envelope_expired`, is not one.
    """
    return _declared_stop(md, NATIVE_BUDGET_STOPS)


def _declared_stop(md: dict, reasons: tuple) -> Optional[str]:
    """The reason in `reasons` a driver declared with its terminated exit, or None."""
    termination = (md.get("agent_stats") or {}).get("termination") or {}
    if (md.get("returncode") == DRIVER_TERMINATED_EXIT
            and termination.get("reason") in reasons):
        return termination["reason"]
    return None


def classify_row(row: dict) -> tuple[str, Optional[str]]:
    """`(bucket, marker)` for one run row -- the ladder's whole taxonomy.

    Infrastructure is tested BEFORE the rungs, because the distinction it
    draws is invisible afterwards: a driver killed mid-flight and an agent
    that declined to write anything both arrive as `no_files_returned`, and a
    ladder that read the outcome alone would publish the harness's failures as
    the system's generation rate -- 93% of the standard-setting sweep sits in
    that one row, so the rule that fills it has to be the careful one.
    """
    marker = infrastructure_marker(row)
    if marker:
        return INFRASTRUCTURE, marker
    outcome = row.get("outcome")
    for key, _label, outcomes in LADDER:
        if outcome in outcomes:
            return key, None
    if outcome in DISCLOSED_EXCLUDED_OUTCOMES:
        return UNCLASSIFIED, outcome
    return UNKNOWN, outcome


def ladder(rows: dict[str, dict]) -> dict:
    """The six stages, over the instances that are the SYSTEM's to answer for.

    `rows` is {item_id: record}, so an item re-run by `--retry-failed` counts
    once: the run file is appended to, and counting LINES would put the same
    item in two stages at once -- its abandoned attempt and its final one --
    while inflating the denominator every rate is read against.

    ONE DENOMINATOR RULE, stated here and printed in the output.  The rates
    are over every instance in the run file, minus infrastructure and the two
    deliberate disclose-and-exclude outcomes.  A genuinely unknown terminal
    outcome cannot silently become another exclusion: counts remain visible,
    but every primary ladder rate is withheld until the methodology defines
    what that outcome means.  When no genuinely unknown outcome is present,
    the six stages sum to the printed denominator as before.
    """
    n = len(rows)
    buckets: dict[str, Counter] = {}
    markers: Counter = Counter()
    items: dict[str, list[str]] = {}
    for iid, row in rows.items():
        bucket, marker = classify_row(row)
        buckets.setdefault(bucket, Counter())[row.get("outcome")] += 1
        if bucket in (INFRASTRUCTURE, UNCLASSIFIED, UNKNOWN):
            items.setdefault(bucket, []).append(iid)
            if bucket == INFRASTRUCTURE and marker:
                markers[marker] += 1

    excluded = {}
    for bucket in (INFRASTRUCTURE, UNCLASSIFIED):
        counter = buckets.get(bucket) or Counter()
        excluded[bucket] = {
            "label": EXCLUDED_LABEL[bucket],
            "count": sum(counter.values()),
            "outcomes": dict(counter.most_common()),
            "items": sorted(items.get(bucket) or ()),
            "markers": (dict(markers.most_common())
                        if bucket == INFRASTRUCTURE else {}),
        }
    n_excluded = sum(e["count"] for e in excluded.values())
    denominator = n - n_excluded
    unknown_counter = buckets.get(UNKNOWN) or Counter()
    unknown = {
        "label": "primary ladder withheld (unknown terminal outcome)",
        "count": sum(unknown_counter.values()),
        "outcomes": dict(sorted(unknown_counter.items())),
        "items": sorted(items.get(UNKNOWN) or ()),
    }
    withheld_reasons = []
    if unknown["outcomes"]:
        detail = ", ".join(f"{outcome} ({count})"
                           for outcome, count in unknown["outcomes"].items())
        withheld_reasons.append(f"unknown terminal outcome(s): {detail}")
    withheld = bool(withheld_reasons)

    out_rows = []
    for key, label, group in LADDER:
        counter = buckets.get(key) or Counter()
        count = sum(counter.values())
        out_rows.append({
            "key": key, "label": label, "count": count,
            "rate": (None if withheld else
                     (count / denominator) if denominator else 0.0),
            # The syntax/wiring split of `compilation failure` lives HERE and
            # only here.  It is kept because it is a real distinction the
            # harness measured, and it is not a row because at table altitude
            # both readings are "the submission never became runnable code".
            "outcomes": {o: counter[o] for o in group if counter.get(o)},
        })
    classified_n = sum(r["count"] for r in out_rows)
    return {
        "n": n,
        "classified_n": classified_n,
        "n_excluded": n_excluded,
        "denominator": denominator,
        "reduced": n_excluded > 0,
        "withheld": withheld,
        "withheld_reasons": withheld_reasons,
        "unknown": unknown,
        "rows": out_rows,
        "excluded": excluded,
        # True for a publishable ladder.  A genuinely unknown terminal outcome
        # makes the classified count short of the expected denominator and is
        # exactly the condition that withholds the rates above.
        "sums_to_denominator": classified_n == denominator,
    }


# --------------------------------------------------------------------------
# mutation, over the passed instances

def _is_single_observation_summary(tq: dict) -> bool:
    return tq.get("schema") == TEST_QUALITY_SUMMARY_SCHEMA_V2


def _single_observation_mutation(tq: dict, passed: set[str]) -> dict:
    """Project the already-validated v2 summary into the results vocabulary.

    Validation belongs to `load_bound_test_quality`.  This consumer still
    fails closed if a test seam or a future caller hands it a partial or stale
    v2 object: defaulting any of these fields to zero would manufacture a hard
    primary, a full-population companion, or -- worst of the three -- an
    excluded count of 0 printed beside a narrowed denominator.
    """
    from . import test_quality as TQ
    required = {
        "method", "policy", "candidate_observation_count",
        "reference_observation_count", "verdict_basis", "companion_basis",
        "hard_recall_macro", "full_recall_macro",
        "full_only_generated_macro", "full_jaccard_macro", "per_item",
        "reference_controls", "reference_excluded_count",
        "candidate_excluded_count",
    }
    missing = sorted(required - set(tq))
    if missing:
        raise ResultsInputError(
            f"validated v2 test-quality summary is missing field(s) {missing}")
    full_gold = tq["verdict_basis"] == "full_gold"
    basis_valid = ((full_gold and tq["companion_basis"] is None)
                   or (tq["verdict_basis"] == "hard_subset"
                       and tq["companion_basis"] == "full_gold"))
    if tq["method"] != SINGLE_OBSERVATION_METHOD \
            or tq["policy"] != FULL_POPULATION_SINGLE_OBSERVATION_POLICY \
            or tq["candidate_observation_count"] != 1 \
            or tq["reference_observation_count"] != 1 \
            or not basis_valid:
        raise ResultsInputError(
            "validated v2 test-quality summary does not identify the reviewed "
            "one-candidate/one-reference-observation reference basis")
    # v2 has no standalone hard-subset artifact to cite: the hard subset is
    # installed INSIDE the authenticated reference controls, so their digest
    # is the identity every number below is derived under.
    digest = (tq["reference_controls"] or {}).get("digest")
    if not isinstance(digest, str) or not digest:
        raise ResultsInputError(
            "validated v2 test-quality summary carries no installed "
            "reference-controls digest to name its numbers under")
    per_item = tq["per_item"]
    if not isinstance(per_item, dict):
        raise ResultsInputError(
            "validated v2 test-quality summary has no per-item mapping")
    if set(per_item) != passed:
        raise ResultsInputError(
            f"validated v2 test-quality summary scores {len(per_item)} item(s) "
            f"that are not this run's {len(passed)} pass(es) -- it is stale")
    per_item_required = {
        "verdict", "hard_candidate_killed", "hard_denominator",
        "hard_recall", "full_candidate_killed", "full_denominator",
        "full_recall", "candidate_only_kills", "full_union",
        "full_only_generated", "full_jaccard",
    }
    malformed = sorted(
        iid for iid, entry in per_item.items()
        if not isinstance(entry, dict)
        or not per_item_required.issubset(entry))
    if malformed:
        raise ResultsInputError(
            "validated v2 test-quality summary has incomplete per-item "
            f"evidence for {malformed}")

    if full_gold:
        if tq.get("candidate_pair_scope") != TQ.CANDIDATE_PAIRS_GOLD_KILLED:
            raise ResultsInputError("full-gold v2 requires gold-killed candidate scope")
        if any(tq[name] is not None for name in (
                "hard_recall_macro", "full_only_generated_macro", "full_jaccard_macro")):
            raise ResultsInputError("full-gold v2 contains undefined aggregate measures")
        if any(entry[name] is not None for entry in per_item.values() for name in (
                "hard_candidate_killed", "hard_denominator", "hard_recall",
                "candidate_only_kills", "full_union", "full_only_generated", "full_jaccard")):
            raise ResultsInputError("full-gold v2 contains unmeasured per-item values")

    # A gold-killed slice of a hard-subset reference measured neither
    # companion that needs a candidate outcome off G; a number there did not
    # come from this campaign.
    hard_gold_killed = not full_gold and (
        tq.get("candidate_pair_scope") == TQ.CANDIDATE_PAIRS_GOLD_KILLED)
    if hard_gold_killed and (
            tq["full_only_generated_macro"] is not None
            or tq["full_jaccard_macro"] is not None
            or any(entry[key] is not None for entry in per_item.values()
                   for key in ("candidate_only_kills", "full_union",
                               "full_only_generated", "full_jaccard"))):
        raise ResultsInputError(
            "validated v2 test-quality summary restricts candidate pairs to "
            "gold-killed pairs but carries a number for a measure that "
            "needs pairs outside them")
    hard_items = {
        iid: {
            "killed": entry["hard_candidate_killed"],
            "denominator": entry["hard_denominator"],
            "recall": entry["hard_recall"],
            "verdict": entry["verdict"],
        }
        for iid, entry in sorted(per_item.items())
        if entry["hard_recall"] is not None
    }
    full_items = {
        iid: {
            "killed": entry["full_candidate_killed"],
            "denominator": entry["full_denominator"],
            "candidate_only_kills": entry["candidate_only_kills"],
            "union": entry["full_union"],
            "recall": entry["full_recall"],
            "only_gen": entry["full_only_generated"],
            "jaccard": entry["full_jaccard"],
        }
        for iid, entry in sorted(per_item.items())
        if entry["full_recall"] is not None
    }
    companion = {
        "basis": tq["companion_basis"],
        "scored": bool(full_items),
        "reason": (None if full_items else
                   "not scored (the reference kills nothing on the full "
                   "population for any passed item)"),
        **({"not_measured": {"only_gen": GOLD_KILLED_NOT_MEASURED,
                             "jaccard": GOLD_KILLED_NOT_MEASURED}}
           if hard_gold_killed else {}),
        "n_scored": len(full_items),
        "not_scorable": sorted(set(per_item) - set(full_items)),
        # Lift the validated summary's exact values.  Re-averaging rounded
        # per-item values here would make JSON disagree with its source.
        "values": {
            "recall": tq["full_recall_macro"],
            "only_gen": tq["full_only_generated_macro"],
            "jaccard": tq["full_jaccard_macro"],
        },
        "per_item": full_items,
    }
    qualifier = TQ.publication_qualifier(tq)
    primary_items = full_items if full_gold else hard_items
    if full_gold:
        for iid, entry in primary_items.items():
            entry["verdict"] = per_item[iid]["verdict"]
    return {
        "schema": tq["schema"], "scored": bool(primary_items),
        "reason": (None if primary_items else
                   "no full-gold-scorable passed items" if full_gold else
                   "no hard-scorable passed items"),
        **({"candidate_pair_scope": tq["candidate_pair_scope"],
            "withheld_measures": tq.get("withheld_measures"),
            "not_measured": {"only_gen": GOLD_KILLED_NOT_MEASURED,
                             "jaccard": GOLD_KILLED_NOT_MEASURED}}
           if full_gold else {}),
        **({"candidate_pair_scope": TQ.CANDIDATE_PAIRS_GOLD_KILLED}
           if hard_gold_killed else {}),
        **qualifier,
        "method": tq["method"], "policy": tq["policy"],
        "candidate_observation_count": tq["candidate_observation_count"],
        "reference_observation_count": tq["reference_observation_count"],
        "verdict_basis": tq["verdict_basis"],
        "companion_basis": tq["companion_basis"],
        "reference_controls_digest": digest,
        # Section 5.1's two counts keep the PRODUCER's spelling all the way
        # through the consumer.  Renaming them here is what let the two sides
        # drift: `..._pairs` is a different field on the producing summary
        # (`candidate_excluded_pairs` is the excluded pair list) and reading
        # it as a count printed a list of dicts inside the mandatory note.
        "reference_excluded_count": tq["reference_excluded_count"],
        "candidate_excluded_count": tq["candidate_excluded_count"],
        # Optional: a summary written for an undeclared reference carries no
        # declaration, and a zero here renders no note at all.  The reason is
        # the operator's own words for WHY the reference omits those items,
        # and it travels with the count rather than being left in an artifact
        # the reader would have to open separately.
        "reference_omitted_items": tq.get("reference_omitted_items"),
        "reference_declared_reason": tq.get("reference_declared_reason"),
        "n_passed": len(passed), "n_scored": len(primary_items),
        "not_scorable": sorted(set(per_item) - set(primary_items)),
        "values": {
            "recall": tq["full_recall_macro"] if full_gold else tq["hard_recall_macro"],
            "only_gen": None,
            "jaccard": None,
        },
        "companion": None if full_gold else companion,
        "per_item": primary_items,
        "source_per_item": per_item,
        "mutants_in_population": tq.get("mutants_in_population"),
        "pairs_expected": tq.get("pairs_expected"),
    }


def _gold_killed_mutation(tq: dict, passed: set[str],
                          per_item: dict) -> dict:
    """Recall only: a gold-killed slice measured nothing outside gold's set.

    The same recall arithmetic as the full-scope branch below, over the same
    per-item counts; only-generated kills and Jaccard are `None` and named
    as not measured rather than computed from a candidate-only count the
    campaign never observed.
    """
    items = {}
    unscorable = []
    for iid, entry in sorted(per_item.items()):
        killed = entry.get("candidate_killed") or 0
        denominator = entry.get("denominator") or 0
        if entry.get("recall") is None or denominator <= 0:
            unscorable.append(iid)
            continue
        items[iid] = {"killed": killed, "denominator": denominator,
                      "candidate_only_kills": None,
                      "basis_candidate_only_kills": None,
                      "recall": killed / denominator, "only_gen": None,
                      "jaccard": None, "verdict": entry.get("verdict")}
    not_measured = {"basis": "full_gold", "number": None, "n_scored": 0,
                    "per_item": {}, "reason": GOLD_KILLED_NOT_MEASURED}
    if not items:
        return {"scored": False, "n_passed": len(passed), "values": None,
                "only_gen_sensitivity": not_measured,
                "candidate_pair_scope": TQ.CANDIDATE_PAIRS_GOLD_KILLED,
                "reason": (f"not scored (gold kills nothing on any of the "
                           f"{len(passed)} passed item(s), so none of them "
                           f"can separate a test from a no-op)")}
    recorded = tq.get("recall_macro")
    macro_recall = _mean([v["recall"] for v in items.values()])
    return {
        "scored": True,
        "reason": None,
        **TQ.publication_qualifier(tq),
        "verdict_basis": tq.get("verdict_basis"),
        "candidate_pair_scope": TQ.CANDIDATE_PAIRS_GOLD_KILLED,
        "not_measured": {"only_gen": GOLD_KILLED_NOT_MEASURED,
                         "jaccard": GOLD_KILLED_NOT_MEASURED},
        "n_passed": len(passed),
        "n_scored": len(items),
        "not_scorable": unscorable,
        "values": {"recall": macro_recall, "only_gen": None,
                   "jaccard": None},
        "only_gen_sensitivity": not_measured,
        "micro": {
            "killed": sum(v["killed"] for v in items.values()),
            "denominator": sum(v["denominator"] for v in items.values()),
            "candidate_only_kills": None,
            "basis_candidate_only_kills": None,
        },
        "per_item": items,
        "mutants_in_population": tq.get("mutants_in_population"),
        "pairs_expected": tq.get("pairs_expected"),
        "recall_macro_recorded": recorded,
        "macro_mismatch": (recorded is not None and macro_recall is not None
                           and abs(recorded - macro_recall) > 5e-4),
    }


def mutation(tq: Optional[dict], passed: set[str]) -> dict:
    """Macro recall, only-generated share and Jaccard from test quality.

    All three come from counts `test_quality.score` already records per item.
    Under the full-gold basis, `candidate_killed` = |C n G|, `denominator` =
    |G| as actually scored, and `candidate_only_kills` = |C \\ G|.  A
    hard-subset summary also records `full_denominator`, which is paired with
    that full-gold candidate-only count for the onlyGen sensitivity number.
    Its structurally empty hard-basis difference is not reported as zero.

    Jaccard deliberately keeps the pre-D6 calculation: it uses the persisted
    full-gold `candidate_only_kills` count even for a hard-subset summary.
    That compatibility behavior is not redefined by adding onlyGen.  The
    three-way set partition therefore applies to full-gold summaries only;
    changing hard-subset Jaccard needs its own methodology decision.

    Recomputing from the counts (instead of lifting macros out of the summary)
    lets the table score a sidecar written before the Jaccard existed, which is
    every sidecar produced before today.  The summary's own recall macro is
    cross-checked against the recomputation and a disagreement is printed, not
    absorbed.

    An item is scored iff `recall` is not None, i.e. iff gold killed something
    on it that survived the eligibility rule.  A `not_scorable` item is not a
    zero: gold kills nothing there, so the item cannot tell a test from a
    no-op and averaging it in would be a claim the mutants do not support.

    Everything above is the v1 summary.  A v2 single-observation summary is
    projected by `_single_observation_mutation` instead: its macros are LIFTED
    rather than recomputed, because the validator that admitted it already
    re-derived them from the candidate rows.
    """
    if not passed:
        return {"scored": False, "reason": NO_PASS, "values": None,
                "n_passed": 0}
    if not tq:
        return {"scored": False, "reason": NOT_SCORED_MUTATION,
                "values": None, "n_passed": len(passed)}
    if _is_single_observation_summary(tq):
        return _single_observation_mutation(tq, passed)

    per_item = tq.get("per_item") or {}
    if set(per_item) != passed:
        # `report.non_vacuous` withholds on exactly this condition and for
        # exactly this reason: a summary left over from another sweep scores
        # a different set of passes, every number in it looks reasonable, and
        # nothing in the output would say the two do not correspond.
        return {"scored": False, "n_passed": len(passed), "values": None,
                "reason": (f"not scored (the test-quality summary scores "
                           f"{len(per_item)} item(s) that are not this run's "
                           f"{len(passed)} pass(es) -- it is from another "
                           f"sweep)")}

    hard_mode = tq.get("verdict_basis") == "hard_subset"
    if tq.get("candidate_pair_scope") == TQ.CANDIDATE_PAIRS_GOLD_KILLED:
        return _gold_killed_mutation(tq, passed, per_item)
    items, unscorable, sensitivity_items = {}, [], {}
    for iid, entry in sorted(per_item.items()):
        killed = entry.get("candidate_killed") or 0
        denominator = entry.get("denominator") or 0
        full_only = entry.get("candidate_only_kills") or 0
        full_denominator = ((entry.get("full_denominator") or 0)
                            if hard_mode else denominator)
        full_scorable = ((entry.get("full_recall") is not None)
                         if hard_mode else entry.get("recall") is not None)
        if full_scorable and full_denominator > 0:
            sensitivity_items[iid] = {
                "denominator": full_denominator,
                "candidate_only_kills": full_only,
                "only_gen": full_only / (full_denominator + full_only),
            }
        basis_only = 0 if hard_mode else full_only
        # Preserve the canonical Jaccard calculation that predates D6.
        jaccard = TQ.jaccard_for(killed, denominator, full_only)
        if entry.get("recall") is None or jaccard is None:
            unscorable.append(iid)
            continue
        full_only_gen = (None if hard_mode
                         else sensitivity_items[iid]["only_gen"])
        items[iid] = {"killed": killed, "denominator": denominator,
                      "candidate_only_kills": full_only,
                      "basis_candidate_only_kills": basis_only,
                      "recall": killed / denominator,
                      "only_gen": (None if hard_mode else full_only_gen),
                      "jaccard": jaccard,
                      "verdict": entry.get("verdict")}
    only_gen_sensitivity = {
        "basis": "full_gold",
        "number": (_mean([
            v["only_gen"] for v in sensitivity_items.values()])
            if sensitivity_items else None),
        "n_scored": len(sensitivity_items),
        "per_item": sensitivity_items,
    }
    if not items:
        return {"scored": False, "n_passed": len(passed), "values": None,
                "only_gen_sensitivity": only_gen_sensitivity,
                "reason": (f"not scored (gold kills nothing on any of the "
                           f"{len(passed)} passed item(s), so none of them "
                           f"can separate a test from a no-op)")}

    recorded = tq.get("recall_macro")
    macro_recall = _mean([v["recall"] for v in items.values()])
    macro_only_gen_sensitivity = only_gen_sensitivity["number"]
    macro_jaccard = _mean([v["jaccard"] for v in items.values()])
    # R4 items 4 and 6.  The qualifier travels into the canonical table's
    # mutation cell exactly as it travels into `report`'s headline, and
    # `publication_ready` decides only whether `table_rows` RENDERS the number
    # The canonical hard-basis `values.only_gen` is deliberately None; the
    # separately named sensitivity block keeps the full-gold arithmetic a
    # reader needs to see what was unavailable or withheld and why.
    qualifier = TQ.publication_qualifier(tq)
    return {
        "scored": True,
        "reason": None,
        **qualifier,
        "verdict_basis": tq.get("verdict_basis"),
        **({"reference_method": tq["reference_method"],
            "reference_observation_count": tq["reference_observation_count"],
            "candidate_observation_count": tq["candidate_observation_count"]}
           if "prestashop_reference_evidence" in tq else {}),
        "n_passed": len(passed),
        "n_scored": len(items),
        "not_scorable": unscorable,
        "values": {"recall": macro_recall,
                   "only_gen": (None if hard_mode
                                else macro_only_gen_sensitivity),
                   "jaccard": macro_jaccard},
        "only_gen_sensitivity": only_gen_sensitivity,
        # Kept for `--format json` and never printed: see MACRO, NOT MICRO.
        "micro": {
            "killed": sum(v["killed"] for v in items.values()),
            "denominator": sum(v["denominator"] for v in items.values()),
            "candidate_only_kills": sum(v["candidate_only_kills"]
                                        for v in items.values()),
            "basis_candidate_only_kills": sum(
                v["basis_candidate_only_kills"] for v in items.values()),
        },
        "per_item": items,
        "mutants_in_population": tq.get("mutants_in_population"),
        "pairs_expected": tq.get("pairs_expected"),
        "recall_macro_recorded": recorded,
        # 5e-4 because the summary rounds its per-item recalls to six places
        # and the table prints three: anything this check can see is a real
        # disagreement about which items were averaged, not float noise.
        "macro_mismatch": (recorded is not None and macro_recall is not None
                           and abs(recorded - macro_recall) > 5e-4),
    }


# --------------------------------------------------------------------------
# coverage and api, over the passed instances

def _unscored(reason: str, n_passed: int, *, excluded=None) -> dict:
    """One complete unscored quality block, with no fabricated evidence."""
    return {"scored": False, "reason": reason, "values": None,
            "n_scored": 0, "n_passed": n_passed,
            "excluded": excluded or {"no_gold_row": [],
                                      "gold_without_coverage": {},
                                      "run_without_coverage": {}},
            "per_item": {}}


def _size_distribution(sizes: list[int]) -> dict:
    """The `|D_G|` shape that travels with every API number (spec 3.2).

    Direct sets are an order of magnitude smaller than the coverage-derived
    sets they replace, so a per-item score takes few values and two items can
    be separated by one call.  That is disclosed by reporting the shape, not
    repaired by widening the set again -- and the histogram is by exact size
    because at a median of five a reader wants counts, not a curve.
    """
    ordered = sorted(sizes)
    quartiles = (statistics.quantiles(ordered, n=4, method="inclusive")
                 if len(ordered) > 1 else [ordered[0]] * 3)
    histogram: dict[str, int] = {}
    for size in ordered:
        histogram[str(size)] = histogram.get(str(size), 0) + 1
    return {"n": len(ordered), "min": ordered[0], "p25": quartiles[0],
            "median": statistics.median(ordered),
            "mean": statistics.mean(ordered), "p75": quartiles[2],
            "max": ordered[-1], "histogram": histogram}


def production_coverage(run_rows: dict[str, dict], passed: set[str],
                        boundary: Boundary,
                        denominator: int) -> dict:
    """How many passes executed production code at all.  A DIAGNOSTIC.

    A pass means the scenario ran green.  It does not mean the scenario
    exercised the system under test: a candidate that defines every step with
    an empty body, or that asserts only over its own fixtures, runs green
    while covering no production line at all.  On the algorand-sdk aider cell
    that is not a corner case -- 44 of 72 passes cover nothing, so a 64.9%
    pass rate is a 25.2% rate of passes that touch production code.  Pass rate
    alone cannot show that difference, and the difference is the finding.

    This is a property of the evaluated system, correctly measured, not a
    harness defect: `coverage_lines` is already on every row, so the number
    costs one pass over rows the table has already read.  It is deliberately
    NOT one of the thirteen canonical rows -- adding a rung or a quality row
    is a methodology change -- and no canonical value moves because of it.

    It is also NOT `report.non_vacuous_pass_at_1`, which is a stronger,
    mutation-based claim (the candidate kills what the reference kills).  A
    pass can cover production lines and still kill nothing.  This row is the
    floor below that one and needs no mutation campaign to compute.

    Three outcomes per pass, and the third is why this cannot be a single
    count.  A row whose coverage was never collected -- no `coverage_lines`
    field, a `coverage=false` stamp, a `coverage_mismatch` witness, or a
    scenario that never reached `@AfterScenario` -- did not cover zero
    production lines; nobody looked.  Counting those as zero would accuse the
    evaluated system of writing a vacuous test on the strength of a run
    launched without `--coverage`, so any such row withholds the rate and is
    named instead.
    """
    covering, zero, not_collected = [], [], []
    for item_id in sorted(passed):
        row = run_rows[item_id]
        try:
            # `check_scorable` is already this project's definition of "this
            # row's coverage block cannot be believed" -- absent, stamped
            # `coverage=false`, or contradicted by `coverage_mismatch`.  Asked
            # here rather than restated, so the diagnostic and the coverage
            # rows cannot drift into disagreeing about which rows were
            # measured at all.
            M.check_scorable({item_id: row}, "this passed row")
            lines = M.production_lines(row, boundary)
        except M.MetricsInputError:
            not_collected.append(item_id)
            continue
        if lines is None:
            not_collected.append(item_id)
        elif any(lines.values()):
            covering.append(item_id)
        else:
            zero.append(item_id)

    block = {
        "scored": False, "reason": None, "rate": None,
        "n_passed": len(passed),
        "n_covering": len(covering),
        "n_zero_production_lines": len(zero),
        "n_not_collected": len(not_collected),
        "denominator": denominator,
        "covering_items": covering,
        "zero_production_line_items": zero,
        "not_collected_items": not_collected,
    }
    if not passed:
        block["reason"] = NO_PASS
    elif not_collected:
        block["reason"] = (
            f"{NOT_SCORED_COVERAGE}: coverage was not collected for "
            f"{len(not_collected)} of {len(passed)} passed instance(s), "
            f"which is not the same finding as covering no production line")
    else:
        # Every pass is on the `pass rate` rung, so the ladder denominator is
        # the denominator here too: the two rates are directly comparable, and
        # a reader who divides by the passes instead gets a different question.
        block.update({"scored": True, "rate": len(covering) / denominator})
    return block


def behaviour(run_rows: dict[str, dict], passed: set[str],
              gold_path: Optional[str], index_path: Optional[str],
              boundary: Boundary,
              api_scoring: str = API_SCORING_METHOD_INDEX) -> dict:
    """Independently gated coverage and API quality blocks.

    Coverage is defined over production-line sets and needs no method index.
    API similarity is defined over the call events the recorder wrote, mapped
    through a production-method index; it reads no line set at all
    (API_DIRECT_INVOCATION_SPEC.md 2.1-2.3).  A project that declares
    ``api_scoring: none`` therefore withholds only API; a missing or invalid
    index for an API-capable project does the same, and so does a run whose
    records predate the recorder -- with its own reason, because "this
    project never measures API" and "this run cannot" are different facts.

    The two blocks therefore have DIFFERENT scored populations, and both
    `n_scored` are printed: an item with no `direct_calls` on either side,
    and an item whose gold test invoked nothing directly, leave the API
    denominator instead of being scored 0 (2.6, 3.1).

    **Which Jaccard.**  `metrics.coverage_similarity` returns two, and they
    are both WITHIN an instance: `micro_jaccard` pools that instance's
    production lines into one set, `macro_jaccard` averages per file.  The
    table uses `micro_jaccard` -- one set of lines per instance, which is what
    "the lines this scenario drove" means -- and then averages THAT over the
    passed instances.  The per-file variant is kept in the JSON; it is a
    different question (was the work spread over the same files) and is not
    the row.

    Every exclusion is counted and named.  A passed item whose gold row has no
    coverage block has no upper bound, and a passed item whose own row has no
    coverage block was recorded without `--coverage`; both are measurement
    gaps, and scoring either as 0.0 would charge the system for the harness.
    """
    if api_scoring not in API_SCORING_MODES:
        raise ResultsInputError(
            f"unknown api_scoring {api_scoring!r}; expected one of "
            f"{', '.join(sorted(API_SCORING_MODES))}")

    n_passed = len(passed)
    api = (_unscored(NOT_MEASURED_API, n_passed)
           if api_scoring == API_SCORING_NONE else None)
    if not passed:
        return {"coverage": _unscored(NO_PASS, 0),
                "api": api or _unscored(NO_PASS, 0)}
    no_gold = ("not scored (no gold run to compare against; pass "
               "--gold RUN.jsonl)")
    if not gold_path:
        return {"coverage": _unscored(no_gold, n_passed),
                "api": api or _unscored(no_gold, n_passed)}

    prod_index = None
    index_provenance = {}
    if api_scoring == API_SCORING_METHOD_INDEX:
        if not index_path:
            api = _unscored(
                "not scored (no production method index; pass "
                "--prod-index FILE)", n_passed)
        else:
            try:
                loaded = M.load_prod_index(index_path)
                # Loading an input is provenance even when no item can be
                # scored.  Keep it through the unscored exits below too.
                index_provenance = {
                    "prod_index": os.path.abspath(index_path),
                    "prod_index_files": len(loaded),
                    "prod_index_methods": sum(len(v)
                                              for v in loaded.values()),
                    "prod_index_accessors": len(loaded.accessors),
                }
                # Applied once here, before any item is compared: for a row
                # that carries `direct_calls`, `compare` raises this refusal
                # per item, and the loop below files a per-item refusal
                # under `run_without_coverage`, taking the item's coverage
                # numbers with it for an index coverage never reads.
                M.refuse_stale_python_index(loaded, index_path)
                prod_index = loaded
            except M.MetricsInputError as e:
                api = _unscored(
                    f"not scored (invalid production method index): {e}",
                    n_passed)

    try:
        # Scoped to the passed rows on purpose -- see `metrics.read_runs`.
        # The 93 no-submission rows of the standard run are not scored here
        # and must not be able to refuse the five rows that are.
        scored_rows = {iid: run_rows[iid] for iid in passed}
        M.check_scorable(scored_rows, "the passed rows of this run")
        gold_runs = M.load_runs(gold_path)
    except M.MetricsInputError as e:
        reason = f"{NOT_SCORED_COVERAGE}: {e}"
        return {"coverage": _unscored(reason, n_passed),
                "api": dict(api or _unscored(reason, n_passed),
                            **index_provenance)}

    missing_gold = sorted(iid for iid in passed if iid not in gold_runs)
    have = {iid: gold_runs[iid] for iid in passed if iid in gold_runs}
    gold_ok, gold_no_bound = M.scorable_gold(have, boundary)

    pairs, undefined = [], {}
    for iid in sorted(gold_ok):
        try:
            pair = (M.compare(gold_ok[iid], run_rows[iid], prod_index,
                              boundary)
                    if prod_index is not None
                    else M.compare_coverage(gold_ok[iid], run_rows[iid],
                                            boundary))
        except M.MetricsInputError as e:
            # A passed row with no `coverage_lines` field at all: the run was
            # produced by a harness that discarded the line data.  One item's
            # plumbing failure must not withhold the other items' numbers, so
            # it is excluded and named rather than raising.
            undefined[iid] = str(e).split(".")[0]
            continue
        if not pair["defined"]:
            undefined[iid] = pair["undefined_reason"]
            continue
        pairs.append(pair)

    excluded = {"no_gold_row": missing_gold,
                "gold_without_coverage": gold_no_bound,
                "run_without_coverage": undefined}
    if api is not None:
        api["excluded"] = dict(excluded)

    if not pairs:
        reasons = sorted(set(undefined.values())) or ["no gold upper bound"]
        reason = f"{NOT_SCORED_COVERAGE}: {reasons[0]}"
        return {"coverage": _unscored(reason, n_passed,
                                       excluded=excluded),
                "api": dict(api or _unscored(reason, n_passed,
                                             excluded=excluded),
                            **index_provenance)}

    cov = {"jaccard": _mean([p["coverage"]["micro_jaccard"] for p in pairs]),
           "macro_jaccard_within_item":
               _mean([p["coverage"]["macro_jaccard"] for p in pairs]),
           "recall": _mean([p["coverage"]["recall"] for p in pairs]),
           "excess": _mean([p["coverage"]["excess"] for p in pairs])}
    coverage_block = {
        "scored": True,
        "reason": None,
        "values": cov,
        "n_passed": n_passed,
        "n_scored": len(pairs),
        "gold": os.path.abspath(gold_path),
        "excluded": dict(excluded),
        # Both sides empty is an identity, so such an item hands every system
        # a free 1.0.  Counted here and warned about at render time, exactly
        # as `metrics.report` does -- an aggregate over five items moves a
        # long way on one free perfect score.
        "degenerate_gold": {
            "empty_coverage": sum(1 for p in pairs
                                 if p["gold_empty_coverage"]),
        },
        "per_item": {p["item_id"]: {
            "coverage": p["coverage"],
            "counts": {k: p["counts"][k] for k in
                       ("gold_lines", "sys_lines", "gold_files",
                        "sys_files")}}
                     for p in pairs},
    }
    if prod_index is not None:
        api_pairs = [p for p in pairs if p["api"] is not None]
        # Three exclusions the coverage block does not have, each an item the
        # API rows are not DEFINED over.  Beside the coverage exclusions
        # rather than instead of them: an item can be out for both reasons.
        api_only_excluded = {
            **{reason: sorted(p["item_id"] for p in pairs
                              if p["api_undefined_reason"] == reason)
               for reason in M.API_RECORD_EXCLUSIONS},
            "gold_no_direct_methods": sorted(
                p["item_id"] for p in pairs if p["gold_no_methods"]),
        }
        api_excluded = dict(excluded, **api_only_excluded)
        # `unmapped` is the index's own diagnostic beside the rows (§3.2),
        # summed over every coverage-compared item (`pairs`) and not the
        # API-scored ones: an item whose gold calls all failed to map leaves
        # the API rows as `gold_no_direct_methods`, and it is exactly the
        # item this count exists to expose -- also when it is the only item
        # and the API block is therefore unscored.  Summing over `api_pairs`
        # reported zero for it, and the unscored block carried nothing.
        unmapped = {"gold": sum(p["counts"]["gold_unmapped"] for p in pairs),
                    "run": sum(p["counts"]["sys_unmapped"] for p in pairs)}
        if not api_pairs:
            api = _unscored(
                NOT_SCORED_API_AMENDMENT
                if (api_only_excluded["run_before_api_amendment_2"]
                    or api_only_excluded["gold_before_api_amendment_2"])
                else NOT_SCORED_API_DIRECT
                if (api_only_excluded["run_without_direct_calls"]
                    or api_only_excluded["gold_without_direct_calls"])
                else "not scored (every scorable gold run invokes no "
                     "production method directly)",
                n_passed, excluded=api_excluded)
            api["unmapped_direct_events"] = unmapped
        else:
            api = {
                "scored": True,
                "reason": None,
                "values": {k: _mean([p["api"][k] for p in api_pairs])
                           for k in ("precision", "recall", "f1")},
                "n_passed": n_passed,
                "n_scored": len(api_pairs),
                "gold": os.path.abspath(gold_path),
                "excluded": api_excluded,
                # The sets are small, so the per-item scores are coarse; §3.2
                # discloses that with the distribution rather than describing
                # it, and `unmapped` is the index's own diagnostic beside it.
                "d_g_sizes": _size_distribution(
                    [p["counts"]["gold_methods"] for p in api_pairs]),
                "unmapped_direct_events": unmapped,
                "per_item": {p["item_id"]: {
                    "api": p["api"],
                    "counts": {k: p["counts"][k] for k in
                               ("gold_methods", "sys_methods",
                                "shared_methods", "gold_unmapped",
                                "sys_unmapped")}}
                             for p in api_pairs},
            }
    return {"coverage": coverage_block,
            "api": dict(api, **index_provenance)}


# --------------------------------------------------------------------------
# the checked-interface secondary block (TARGET_INTERFACES_V2_SPEC 6.2/6.3)

def checked_interfaces_keys(items_path: str) -> dict[str, set[tuple]]:
    """{item_id: disclosed key set} from a release items file.

    The disclosed list `I` is the item's own `checked_interfaces` field, and
    each entry's `key` is the metric's `Method.key` as a JSON list -- which is
    the whole reason the subtraction downstream is an exact tuple match.  An
    item whose field is absent is absent here too: it is not an item with an
    empty disclosed list, it is an item minted before the field existed, and
    the row says so rather than scoring it as if nothing had been disclosed.
    """
    disclosed: dict[str, set[tuple]] = {}
    for row in _all_rows(items_path):
        field = row.get("checked_interfaces")
        if field is None:
            continue
        if not isinstance(field, dict) or "checked" not in field:
            raise ResultsInputError(
                f"{row.get('item_id', '?')}: `checked_interfaces` is not the "
                f"reviewed object {{checked, empty_reason}}; the undisclosed-"
                f"API row subtracts `checked[*].key` and cannot read this.")
        disclosed[row["item_id"]] = {tuple(entry["key"])
                                     for entry in field["checked"]}
    return disclosed


def _killed_without_row(entry) -> bool:
    """The evidence `run_agent_cells.py finalize` records for an exclusion:
    a finished attempt with a nonzero or no exit, no row, and a trajectory."""
    evidence = entry.get("evidence") if isinstance(entry, dict) else None
    if not isinstance(evidence, dict):
        return False
    finished, trajectories = evidence.get("finished"), evidence.get("trajectories")
    row_file = evidence.get("row_file")
    return (isinstance(finished, dict) and type(finished.get("rows")) is int
            and finished["rows"] == 0 and finished.get("exit_code") != 0
            and isinstance(trajectories, list) and bool(trajectories)
            and all(isinstance(t, str) and t for t in trajectories)
            and isinstance(row_file, str)
            and (row_file == "absent" or row_file.endswith(" bytes of whitespace")))


def _ratified_exclusions(path: str, run_path: str) -> tuple[list, dict]:
    """The exclusions of a finalize-written file bound to this run, and its identity.

    Fails closed unless the file names this exact run (its candidate sha256)
    and every exclusion carries finalize's killed-without-row evidence.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        document = json.loads(raw.decode("utf-8"))
        with open(run_path, "rb") as fh:
            run_sha256 = hashlib.sha256(fh.read()).hexdigest()
    except (OSError, ValueError) as exc:
        raise ResultsInputError(
            f"cannot read --infrastructure-exclusions {path}: {exc}") from None
    exclusions = document.get("exclusions") if isinstance(document, dict) else None
    if not isinstance(exclusions, list) or not exclusions:
        raise ResultsInputError(
            f"--infrastructure-exclusions {path} has no `exclusions` list")
    candidate = document.get("candidate")
    if document.get("written_by") != "run_agent_cells.py finalize" \
            or not isinstance(candidate, dict) \
            or candidate.get("sha256") != run_sha256:
        raise ResultsInputError(
            f"--infrastructure-exclusions {path} is not the finalize record "
            f"for this --run (sha256 {run_sha256}); only the file finalize "
            "wrote beside this candidate can ratify its missing items")
    unsupported = [entry.get("item_id") if isinstance(entry, dict) else entry
                   for entry in exclusions if not _killed_without_row(entry)]
    if unsupported:
        raise ResultsInputError(
            f"--infrastructure-exclusions {path}: {unsupported} lack finalize's "
            "evidence of a finished attempt with a nonzero or no exit, no row "
            "and a trajectory")
    return exclusions, {"path": os.path.abspath(path),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "cell": document.get("cell"),
                        "run_sha256": run_sha256}


def _cluster_map(source: str, run_rows: dict[str, dict]) -> dict[str, str]:
    """{item_id: closure cluster} for this run's items, from the release map.

    The same `closure_clusters.json` `bench.cli compare` resamples, read the
    same way (`data.release.closure_clusters`): one map, so an interval
    printed here and an interval printed there are over the same units.
    """
    from ..data.release import closure_clusters
    source = os.path.dirname(source) if os.path.isfile(source) else source
    clusters = closure_clusters(source)
    return {iid: clusters[iid] for iid in run_rows if iid in clusters}


def _interval(values: dict, cluster_map: Optional[dict], *,
              proportion: bool = False) -> tuple[Optional[list], Optional[str]]:
    """The cluster interval for one secondary row, or why there is none.

    Withheld rather than widened: below the preregistered 20-cluster floor an
    interval is not a wider interval, it is an interval over correlated rows
    pretending to be independent.  The descriptive mean is printed either way
    (`bench.cli compare` does the same thing with the same floor).
    """
    if cluster_map is None:
        return None, INTERVAL_NO_CLUSTERS
    if not values:
        return None, "no scored item"
    try:
        lo, hi = (M.cluster_bootstrap(values, cluster_map) if proportion
                  else M.cluster_bootstrap_mean(values, cluster_map))
    except M.MetricsInputError as exc:
        return None, str(exc).replace("REFUSED: ", "")
    return [lo, hi], ("degenerate: every cluster scored the same, so every "
                      "resample does too" if lo == hi else None)


def _companion_pairs(pairs: list[dict], reason: str) -> list[dict]:
    """Coverage-only comparisons, completed with an ABSENT API axis.

    `metrics.summarise` is the one home of the `over_total` arithmetic and of
    the substituted-score polarity, and it reads both axes.  A run scored
    without a production index has coverage pairs only, so the API fields are
    filled in as "this item is not in the API population" -- which is what
    `api_excluded` already means -- rather than duplicating the aggregation
    here with the API half deleted.
    """
    return [dict(pair, api=None, api_defined=False, api_excluded=True,
                 gold_no_methods=False, api_undefined_reason=reason,
                 api_index_error=None,
                 counts={**pair["counts"], "gold_methods": 0,
                         "sys_methods": 0, "shared_methods": 0,
                         "gold_unmapped": 0, "sys_unmapped": 0})
            for pair in pairs]


def secondary(run_rows: dict[str, dict], passed: set[str],
              gold_path: Optional[str], index_path: Optional[str],
              boundary: Boundary, *,
              regions: Optional[dict] = None,
              disclosed: Optional[dict] = None,
              floors: Optional[dict] = None,
              cluster_map: Optional[dict] = None,
              api_scoring: str = API_SCORING_METHOD_INDEX) -> dict:
    """The section 6.2/6.3 secondary rows, over the FULL denominator.

    Three things distinguish this block from `behaviour` above, and all three
    are the specification's, not a preference:

    * **The denominator is every item with a scorable gold row**, not the
      passed ones.  A candidate that crashed did not reach the target region
      and did not call the undisclosed API; counting only its successes is
      the selection `over_total` exists to remove (`metrics.summarise`).
      The passed-only mean travels beside it, never instead of it.
    * **`behaviour` is not touched.**  The seven quality rows keep their
      passed-only means and their published meaning; this block is rendered
      below them and moves no canonical value.
    * **Every exclusion is a named reason with a count.**  An item whose gold
      covers no region line, and an item whose whole gold call set was
      disclosed, are `not_scorable` for their row -- disclosed, never scored
      0.0 and never handed the empty-set identity.
    """
    inputs_given = any(x is not None for x in (regions, disclosed, floors))
    block = {"control_floors": floors, "n_passed": len(passed)}
    if not inputs_given:
        return block
    if not gold_path:
        reason = ("not scored (no gold run to compare against; pass "
                  "--gold RUN.jsonl)")
        return {**block, "target_region": _unscored(reason, len(passed)),
                "undisclosed_api": _unscored(reason, len(passed)),
                "full_denominator": _unscored(reason, len(passed))}

    prod_index, index_reason = None, None
    if api_scoring == API_SCORING_NONE:
        index_reason = NOT_MEASURED_API
    elif not index_path:
        index_reason = ("not scored (no production method index; pass "
                        "--prod-index FILE)")
    else:
        try:
            prod_index = M.load_prod_index(index_path)
            M.refuse_stale_python_index(prod_index, index_path)
        except M.MetricsInputError as exc:
            prod_index, index_reason = None, (
                f"not scored (invalid production method index): {exc}")

    try:
        gold_runs = M.load_runs(gold_path)
    except M.MetricsInputError as exc:
        reason = f"{NOT_SCORED_COVERAGE}: {exc}"
        return {**block, "target_region": _unscored(reason, len(passed)),
                "undisclosed_api": _unscored(reason, len(passed)),
                "full_denominator": _unscored(reason, len(passed))}
    have = {iid: gold_runs[iid] for iid in run_rows if iid in gold_runs}
    gold_ok, gold_no_bound = M.scorable_gold(have, boundary)
    excluded = {"no_gold_row": sorted(set(run_rows) - set(gold_runs)),
                "gold_without_coverage": gold_no_bound,
                "unreadable_run_row": {}}

    pairs, region_scores, undisclosed_scores = [], {}, {}
    region_excluded: dict[str, list] = {"not_in_target_map": [],
                                        M.REGION_NO_GOLD_LINES: [],
                                        "run_without_coverage": []}
    api_excluded: dict[str, list] = {"no_checked_interfaces": [],
                                     M.UNDISCLOSED_FULLY_DISCLOSED: [],
                                     "api_not_defined": []}
    reaches: dict[str, bool] = {}
    index_keys = M.index_method_keys(prod_index) if prod_index is not None \
        else set()
    for iid in sorted(gold_ok):
        run_row = run_rows[iid] if iid in passed else None
        try:
            pair = (M.compare(gold_ok[iid], run_row, prod_index, boundary)
                    if prod_index is not None
                    else M.compare_coverage(gold_ok[iid], run_row, boundary))
            gold_lines = M.production_lines(gold_ok[iid], boundary)
            sys_lines = (M.production_lines(run_row, boundary)
                         if run_row is not None else None)
        except M.MetricsInputError as exc:
            excluded["unreadable_run_row"][iid] = str(exc).split(".")[0]
            continue
        pairs.append(pair)
        if regions is not None:
            if iid not in regions:
                region_excluded["not_in_target_map"].append(iid)
            else:
                scored = M.target_region_recall(gold_lines, sys_lines or {},
                                                regions[iid])
                if not scored["scorable"]:
                    region_excluded[M.REGION_NO_GOLD_LINES].append(iid)
                else:
                    # In the reaches-target denominator whether or not the
                    # candidate ran: a crash does not reach the target.
                    reaches[iid] = bool(scored["reaches_target"])
                    if sys_lines is None:
                        region_excluded["run_without_coverage"].append(iid)
                    else:
                        region_scores[iid] = scored["recall"]
        if disclosed is not None:
            if iid not in disclosed:
                api_excluded["no_checked_interfaces"].append(iid)
            elif not pair.get("api_defined"):
                api_excluded["api_not_defined"].append(iid)
            else:
                gold_direct = M.direct_methods(gold_ok[iid], boundary,
                                               prod_index)
                sys_direct = M.direct_methods(run_row, boundary, prod_index)
                scored = M.undisclosed_api(gold_direct[0], sys_direct[0],
                                           disclosed[iid], index_keys)
                if scored["scored"]:
                    undisclosed_scores[iid] = scored["api"]
                else:
                    api_excluded[scored["reason"]].append(iid)

    if regions is None:
        block["target_region"] = _unscored(NO_TARGET_REGIONS, len(passed))
    elif not reaches:
        block["target_region"] = _unscored(
            NO_REGION_SCORABLE, len(passed), excluded=dict(excluded))
        block["target_region"]["excluded"].update(region_excluded)
    else:
        recall_ci, recall_note = _interval(region_scores, cluster_map)
        reach_ci, reach_note = _interval(reaches, cluster_map, proportion=True)
        block["target_region"] = {
            "scored": True, "reason": None,
            "values": {"recall": _mean(list(region_scores.values())),
                       "reaches_rate": (sum(reaches.values()) / len(reaches))},
            "n_passed": len(passed), "n_scored": len(region_scores),
            "n_items": len(reaches),
            "gold": os.path.abspath(gold_path),
            "excluded": dict(excluded, **region_excluded),
            "intervals": {"recall": recall_ci, "reaches_rate": reach_ci},
            "interval_notes": {"recall": recall_note,
                               "reaches_rate": reach_note},
            "per_item": {"recall": region_scores, "reaches_target": reaches},
        }
    if disclosed is None:
        block["undisclosed_api"] = _unscored(NO_CHECKED_INTERFACES,
                                             len(passed))
    elif not undisclosed_scores:
        reason = (index_reason if prod_index is None
                  else NO_CHECKED_INTERFACES
                  if not any(iid in disclosed for iid in gold_ok)
                  else NO_UNDISCLOSED_SCORABLE)
        block["undisclosed_api"] = _unscored(reason, len(passed),
                                             excluded=dict(excluded))
        block["undisclosed_api"]["excluded"].update(api_excluded)
    else:
        f1s = {iid: api["f1"] for iid, api in undisclosed_scores.items()}
        interval, note = _interval(f1s, cluster_map)
        block["undisclosed_api"] = {
            "scored": True, "reason": None,
            "values": {name: _mean([api[name]
                                    for api in undisclosed_scores.values()])
                       for name in ("precision", "recall", "f1")},
            "n_passed": len(passed), "n_scored": len(undisclosed_scores),
            "n_items": len(undisclosed_scores) + sum(
                len(v) for v in api_excluded.values()),
            "gold": os.path.abspath(gold_path),
            "excluded": dict(excluded, **api_excluded),
            "intervals": {"f1": interval}, "interval_notes": {"f1": note},
            "per_item": undisclosed_scores,
        }

    if not pairs:
        block["full_denominator"] = _unscored(
            f"{NOT_SCORED_COVERAGE}: no item has a gold upper bound",
            len(passed), excluded=dict(excluded))
    else:
        summary = M.summarise(
            pairs if prod_index is not None
            else _companion_pairs(pairs, index_reason or NOT_MEASURED_API))
        values = {key: summary["metrics"][key]["over_total"]
                  for key in M.METRIC_KEYS}
        block["full_denominator"] = {
            "scored": True,
            "reason": None if prod_index is not None else index_reason,
            "values": values,
            "passed_only": {key: summary["metrics"][key]["mean_defined"]
                            for key in M.METRIC_KEYS},
            "undefined_score": dict(M.UNDEFINED_SCORE),
            "n_passed": len(passed), "n_scored": summary["n_defined"],
            "n_items": summary["n_items"],
            "n_api_items": summary["metrics"]["api.f1"]["n_items"],
            "n_api_scored": summary["n_api_scored"],
            "gold": os.path.abspath(gold_path),
            "excluded": dict(excluded),
            "per_item": {},
        }
    return block


# --------------------------------------------------------------------------
# effort: what the system SPENT to produce the table above

def _dist(values: list) -> dict:
    """`{mean, max, n}` over the values that are PRESENT.

    `None` and not `0.0` on an empty list, for the reason the module header
    gives: a run that recorded no LLM call and a run that made none are
    different findings, and only one of them is a fact about the system.
    """
    vals = [v for v in values
            if isinstance(v, (int, float)) and not isinstance(v, bool)]
    return {"mean": (statistics.mean(vals) if vals else None),
            "max": (max(vals) if vals else None),
            "n": len(vals)}


def effort(rows: dict[str, dict]) -> dict:
    """How much work the system was allowed, and how much it used.

    A results table says how far a system got.  It does not say what the
    system was ALLOWED to spend getting there, and the two numbers are not
    separable in an agentic benchmark: an agent with a hundred iterations and
    an agent with ten are not the same system, and a pass rate quoted without
    the budget is a number that cannot be reproduced or compared.  Every
    figure here is read off the row's own stamps, so it describes the run
    that produced this table rather than the configuration someone remembers
    launching.

    Nothing here is ever a rung and nothing here enters a denominator: it
    renders BELOW the table, in `notes`.  Effort is context for the thirteen
    rows, not a fourteenth.
    """
    n_stats = 0
    calls, seconds, trials_used = [], [], []
    budgets = set()
    for row in rows.values():
        md = row.get("metadata") or {}
        stats = md.get("agent_stats")
        if isinstance(stats, dict) and stats:
            n_stats += 1
            calls.append(stats.get("llm_calls"))
        if isinstance(md.get("agent_seconds"), (int, float)):
            seconds.append(md["agent_seconds"])
        tr = md.get("trials")
        if isinstance(tr, dict):
            trials_used.append(tr.get("used"))
        if row.get("max_iterations") is not None:
            budgets.add(row["max_iterations"])
    # Sorted within each type: an int budget and the string `"unlimited"` are
    # not comparable, and a crash here would take out a table over a note.
    values = sorted(budgets, key=lambda v: (str(type(v)), v))
    return {
        "n": len(rows),
        "n_rows_with_agent_stats": n_stats,
        "llm_calls": _dist(calls),
        "agent_seconds": _dist(seconds),
        "trials_used": _dist(trials_used),
        # A list, for the same reason `_digests` is one: a file whose rows
        # were produced under two iteration budgets is a file whose rows are
        # not one system, and collapsing that to "the" budget is how a table
        # ends up quoting a configuration it does not have.
        "iterations_budget": values[0] if len(values) == 1 else None,
        "iterations_budget_values": values,
    }


def _compact(v: float) -> str:
    """`100`, `3`, `834.5`, `0.38` -- two places, with the noise trimmed."""
    return f"{v:.2f}".rstrip("0").rstrip(".") or "0"


def _effort_note(eff: dict) -> str:
    """The effort block as one note line, with every gap named."""
    def part(label: str, d: dict) -> str:
        if not d["n"]:
            return f"{label} not recorded"
        return (f"{label} mean {_compact(d['mean'])}, max "
                f"{_compact(d['max'])} (n={d['n']})")

    budget = eff["iterations_budget_values"]
    if not budget:
        cap = "iteration budget not recorded"
    elif len(budget) == 1:
        cap = f"iteration budget {budget[0]}"
    else:
        cap = ("MIXED iteration budgets "
               + ", ".join(str(v) for v in budget)
               + " -- these rows are not one system")
    return (f"effort (what the system spent, not what it achieved; never a "
            f"table row): {eff['n_rows_with_agent_stats']} of {eff['n']} "
            f"instance(s) carry agent stats; "
            + "; ".join([part("llm calls", eff["llm_calls"]),
                         part("agent seconds", eff["agent_seconds"]),
                         part("trials used", eff["trials_used"])])
            + f"; {cap}. A pass rate is only comparable between systems "
              f"that were allowed comparable budgets.")


# --------------------------------------------------------------------------
# the table

def results(run_path: str, *, gold_path: Optional[str] = None,
            test_quality_path: Optional[str] = None,
            prod_index_path: Optional[str] = None,
            boundary: Optional[Boundary] = None,
            artifacts: str = DEFAULT_ARTIFACTS,
            api_scoring: str = API_SCORING_METHOD_INDEX,
            language: Optional[str] = "php",
            release_path: Optional[str] = None,
            reference_controls_reader: object = None,
            target_regions_path: Optional[str] = None,
            items_path: Optional[str] = None,
            control_floors_path: Optional[str] = None,
            cluster_source: Optional[str] = None,
            infrastructure_exclusions_path: Optional[str] = None) -> dict:
    return _results_impl(
        run_path, gold_path=gold_path, test_quality_path=test_quality_path,
        prod_index_path=prod_index_path, boundary=boundary,
        artifacts=artifacts, api_scoring=api_scoring, language=language,
        release_path=release_path,
        reference_controls_reader=reference_controls_reader,
        target_regions_path=target_regions_path, items_path=items_path,
        control_floors_path=control_floors_path,
        cluster_source=cluster_source,
        infrastructure_exclusions_path=infrastructure_exclusions_path)


def publication_results(run_path: str, *, gold_path: str,
                        boundary: Boundary, population_scope: dict) -> dict:
    """Publication-v3 results: explicit gold, no default or sidecar lookup."""
    return _results_impl(
        run_path, gold_path=gold_path, test_quality_path=None,
        prod_index_path=None, boundary=boundary, artifacts="",
        publication=True, validated_population_scope=population_scope)


def _results_impl(run_path: str, *, gold_path: Optional[str] = None,
                  test_quality_path: Optional[str] = None,
                  prod_index_path: Optional[str] = None,
                  boundary: Optional[Boundary] = None,
                  artifacts: str = DEFAULT_ARTIFACTS,
                  api_scoring: str = API_SCORING_METHOD_INDEX,
                  language: Optional[str] = "php",
                  publication: bool = False,
                  release_path: Optional[str] = None,
                  validated_population_scope: Optional[dict] = None,
                  reference_controls_reader: object = None,
                  target_regions_path: Optional[str] = None,
                  items_path: Optional[str] = None,
                  control_floors_path: Optional[str] = None,
                  cluster_source: Optional[str] = None,
                  infrastructure_exclusions_path: Optional[str] = None) -> dict:
    """Every number in the canonical table, plus the provenance for each.

    Nothing here is optional-but-silent: an input that could not be resolved
    turns into a named "not scored" cell, and the paths that WERE used are
    reported so that every printed number can be recomputed from the files
    the table itself names. The default language remains PHP, matching the
    CoreShop boundary and artifacts defaults; the CLI supplies its profile's
    language. A v2 caller must supply
    `reference_controls_reader`: this consumer forwards that authenticated
    installed-controls callback to `load_bound_test_quality` and never derives
    bundle authority from summary fields or paths.  V1 callers leave it None.
    """
    if not os.path.isfile(run_path):
        raise ResultsInputError(f"no such run file: {run_path}")
    raw_rows = _publication_rows(run_path)
    # BEFORE any arithmetic and long before any rendering (R4 item 7).  Until
    # R4 the single-project guarantee held here only procedurally -- `report`
    # called the gate and this verb did not -- so a run file carrying two
    # projects' rows produced one pooled canonical table with nothing in it
    # saying so.  `results` has no `--group-by`: this table IS one system on
    # one project, so the refusal is the whole answer here rather than a
    # partition instruction.
    from .report import ReportRefusal, check_single_project, check_single_tier
    try:
        projects = check_single_project(raw_rows)
        submitted_tier = check_single_tier(raw_rows)
    except ReportRefusal as e:
        message = str(e)
        raise ResultsInputError(
            message[len("REFUSED: "):] if message.startswith("REFUSED: ")
            else message) from None
    # Before any number is computed, let alone rendered: if a merged run's
    # `<run>.campaign.json` no longer describes the bytes beside it, the
    # provenance block this table prints is about a different file. Silent
    # when the pair holds and when there is no sidecar to hold, which between
    # them is every archived run.
    draws.check_campaign_pair(run_path)
    if boundary is None:
        from ..core.boundary import load_boundary
        boundary = load_boundary(DEFAULT_BOUNDARY)
    if projects and projects[0] != boundary.project:
        raise ResultsInputError(
            f"run project {projects[0]!r} differs from boundary project "
            f"{boundary.project!r}")

    rows = M.read_runs(run_path)
    n_rows = len(raw_rows)
    passed = {iid for iid, r in rows.items() if r.get("outcome") == "passed"}

    if gold_path is None and not publication:
        gold_path = default_gold_run(artifacts, boundary.project)
    elif os.path.isdir(gold_path):
        # `--gold` on the top-level parser is the gold TREE (a directory of
        # restored test code); here it is the gold RUN.  Same word, different
        # object, and pointing this one at the tree is the obvious mistake --
        # so it is refused by name instead of failing inside a JSON parser.
        raise ResultsInputError(
            f"--gold must be the gold RUN (.jsonl), not the gold tree: "
            f"{gold_path}")
    if gold_path and os.path.isfile(gold_path):
        _publication_rows(gold_path)
    if prod_index_path is None and not publication \
            and api_scoring == API_SCORING_METHOD_INDEX:
        prod_index_path = default_prod_index(artifacts, language)

    # Publication-v3 has no admitted mutation or production-index input, so
    # neither resolver is called and both cells render `not scored`.
    tq, tq_path = None, test_quality_path
    if not publication:
        try:
            loader_kwargs = {"summary_path": test_quality_path}
            if reference_controls_reader is not None:
                loader_kwargs["reference_controls_reader"] = \
                    reference_controls_reader
            tq = TQ.load_bound_test_quality(run_path, **loader_kwargs)
        except TQ.TestQualityRefused as e:
            message = str(e)
            if message.startswith("REFUSED: "):
                message = message[len("REFUSED: "):]
            raise ResultsInputError(message) from None
        if tq_path is None:
            tq_path = TQ.find_sidecar(run_path)

    # Population admission follows every refusal-capable input binding but
    # precedes all table arithmetic. A stale test-quality wrapper therefore
    # remains named as stale rather than being masked by a second invalid
    # input, while no canonical value is ever computed before P is resolved.
    try:
        population = P.resolve(
            raw_rows, os.path.abspath(run_path),
            explicit_release=release_path,
            validated_scope=validated_population_scope)
        exclusions_binding = None
        if infrastructure_exclusions_path is not None:
            ratified_entries, exclusions_binding = _ratified_exclusions(
                infrastructure_exclusions_path, run_path)
            population = P.with_ratified_exclusions(population,
                                                    ratified_entries)
    except P.PopulationRefusal as exc:
        message = str(exc)
        raise ResultsInputError(
            message[len("REFUSED: "):] if message.startswith("REFUSED: ")
            else message) from None
    # Benchmark 2.0's excluded instances leave every count from here on, the
    # test-quality macros included: their rows were collected, and the
    # population block discloses them (BENCHMARK_V2_SPEC.md section 6).
    excluded = P.excluded_ids(population)
    if excluded:
        from .report import partition_test_quality
        rows = {iid: r for iid, r in rows.items() if iid not in excluded}
        raw_rows = [r for r in raw_rows if r["item_id"] not in excluded]
        passed = passed - excluded
        if tq is not None:
            tq = partition_test_quality(tq, passed)

    lad = ladder(rows)
    try:
        population = P.with_ladder(population, lad)
    except P.PopulationRefusal as exc:
        message = str(exc)
        raise ResultsInputError(
            message[len("REFUSED: "):] if message.startswith("REFUSED: ")
            else message) from None
    mut = mutation(tq, passed)
    beh = behaviour(rows, passed, gold_path, prod_index_path, boundary,
                    api_scoring)
    coverage, api = beh["coverage"], beh["api"]
    # Needs no gold run and no mutation campaign, so it is computed here
    # unconditionally: a cell whose every quality row is unscored still gets
    # to say whether its passes executed any production code.
    prod_cov = production_coverage(rows, passed, boundary, lad["denominator"])
    # The section 6.2/6.3 secondary block, and ONLY when one of its own
    # inputs was given: without them this call returns nothing and the
    # rendering is byte-for-byte the one every pinned table already has.
    sec = None
    if any(path is not None for path in
           (target_regions_path, items_path, control_floors_path)):
        try:
            sec = secondary(
                rows, passed, gold_path, prod_index_path, boundary,
                regions=(M.load_target_regions(target_regions_path)
                         if target_regions_path else None),
                disclosed=(checked_interfaces_keys(items_path)
                           if items_path else None),
                floors=(M.load_control_floors(control_floors_path)
                        if control_floors_path else None),
                cluster_map=(_cluster_map(cluster_source, rows)
                             if cluster_source else None),
                api_scoring=api_scoring)
        except M.MetricsInputError as exc:
            raise ResultsInputError(str(exc)) from None
    if not population["canonical_values_admitted"]:
        reasons = list(population["withheld_reasons"])
        # Issue #202 owns `withheld` and `withheld_reasons`: they continue to
        # describe only unknown PRESENT rows. Population admission is a second,
        # independent gate over the values those classified rows could expose.
        lad["population_withheld"] = True
        lad["population_withheld_reasons"] = reasons
        for row in lad["rows"]:
            row["rate"] = None
        for block in (mut, coverage, api):
            block["population_withheld"] = True
            block["publication_ready"] = False
            existing = list(block.get("withheld_reasons") or ())
            existing.extend(reason for reason in reasons
                            if reason not in existing)
            block["withheld_reasons"] = existing
            # Retain counts, exclusions and per-item measurements, but expose
            # no aggregate over the rows that merely happened to arrive.
            block["values"] = None
        companion = mut.get("companion")
        if companion is not None:
            # The companion is a second aggregate over the same rows, so it
            # falls under the same admission gate as the primary above.
            companion["population_withheld"] = True
            companion["publication_ready"] = False
            companion["withheld_reasons"] = list(mut["withheld_reasons"])
            companion["values"] = None
        if mut.get("only_gen_sensitivity"):
            mut["only_gen_sensitivity"] = dict(
                mut["only_gen_sensitivity"], number=None)
        if "micro" in mut:
            mut["micro"] = None
        if "recall_macro_recorded" in mut:
            mut["recall_macro_recorded"] = None
            mut["macro_mismatch"] = False
        # The diagnostic is not canonical, but it is still a rate over rows
        # that merely happened to arrive, and printing it beside thirteen
        # withheld values would read as the one number that survived.
        prod_cov.update({"scored": False, "rate": None,
                         "reason": "; ".join(reasons)})
        # Secondary, but still an aggregate over the rows that happened to
        # arrive: the same admission gate, for the same reason.
        for name in ("target_region", "undisclosed_api", "full_denominator"):
            sub = (sec or {}).get(name)
            if sub is not None:
                sub.update({"scored": False, "values": None,
                            "population_withheld": True,
                            "publication_ready": False,
                            "withheld_reasons": list(reasons),
                            "reason": "; ".join(reasons)})
    result = {
        "run": os.path.abspath(run_path),
        "run_name": os.path.basename(run_path).replace(".jsonl", ""),
        "gold": os.path.abspath(gold_path) if gold_path else None,
        "prod_index": api.get("prod_index"),
        "test_quality": os.path.abspath(tq_path) if tq_path else None,
        # Which generation provenance the bound sidecar resolved to.  Carried
        # onto the provenance block because a development-route candidate is
        # unstamped BY CONSTRUCTION, and a reader of this table has to see
        # that without opening the sidecar to find out.
        "test_quality_generation_class": (
            (tq or {}).get("generation_provenance_class")),
        "campaign_digest": _digests(rows),
        "citation": citation(rows),
        "n": len(rows),
        "n_rows_in_file": n_rows,
        # The file's rows outside benchmark 2.0's population, so the note on
        # observed_n still names only items re-run in place.
        **({"n_rows_outside_population": n_rows - len(raw_rows)}
           if excluded else {}),
        "n_passed": len(passed),
        "ladder": lad,
        "population": P.public_view(population),
        # Beside the table and never in it: see `effort`.
        "effort": effort(rows),
        # Which of these instances are NOT first observations, and why the
        # prior attempt was discarded.  Below the table for the same reason
        # `effort` is -- it is context for every row rather than a row -- and
        # computed over the uncollapsed file, because an item re-run in place
        # leaves its earlier attempt on a line `read_runs` drops.
        "draws": draws.summarise(raw_rows),
        "mutation": mut,
        "coverage": coverage,
        "api": api,
        # Beside the thirteen and never in them: see `production_coverage`.
        "production_coverage": prod_cov,
    }
    if sec is not None:
        result["secondary"] = sec
    if exclusions_binding is not None:
        result["infrastructure_exclusions"] = exclusions_binding
    if submitted_tier:
        from ..core.constants import SUBMITTED_CONDITION
        from .report import environment_proven_label
        result["tier"] = SUBMITTED_CONDITION
        # Decision 7's stamp travels with the tier: every rendering shows,
        # beside the tier label, whether an accepted environment record
        # covered the worker(s) that scored these rows.
        result["environment_proven"] = environment_proven_label(raw_rows)
    return result


# `_results_impl` is `results`' body, so what it documents IS `results`'
# contract.  Restated by assignment rather than copied: splitting the
# publication route out of the function must not quietly empty
# `help(results.results)`, which is part of the pre-I5 Python surface I5
# promises to leave alone.
results.__doc__ = _results_impl.__doc__



def _quality_rows_for(res: dict) -> tuple[tuple[str, str, str, str], ...]:
    """The frozen v1 rows, or v2's labelled primary/companion extension."""
    if (res.get("mutation") or {}).get("schema") \
            != TEST_QUALITY_SUMMARY_SCHEMA_V2:
        return QUALITY_ROWS
    if res["mutation"].get("verdict_basis") == "full_gold":
        return QUALITY_ROWS
    v2_primary = (
        ("mutation_recall", "mutation recall (primary, hard subset)",
         "mutation", "recall"),
        ("mutation_only_gen",
         "mutation only-generated kills (hard subset)",
         "mutation", "only_gen"),
        ("mutation_jaccard", "mutation jaccard similarity (hard subset)",
         "mutation", "jaccard"),
    )
    return v2_primary + V2_COMPANION_ROWS + QUALITY_ROWS[3:]


def table_rows(res: dict) -> list[dict]:
    """The canonical rows, in order, each already rendered to a value string.

    One list, used by all three formats: text, markdown and JSON cannot
    disagree about the table's shape or about which cell said "not scored",
    because there is only one place that decides.
    """
    lad = res["ladder"]
    n = lad["denominator"]
    withheld_reasons = list(lad.get("withheld_reasons") or ())
    withheld_reasons.extend(
        reason for reason in lad.get("population_withheld_reasons") or ()
        if reason not in withheld_reasons)
    withheld_reason = "; ".join(withheld_reasons)
    values_withheld = (lad.get("withheld")
                       or lad.get("population_withheld"))
    out = []
    for row in lad["rows"]:
        rendered = {
            "key": row["key"], "label": row["label"],
            "value": (_ladder_value(row, n) if not values_withheld
                      else f"withheld ({withheld_reason})"),
            "count": row["count"], "rate": row["rate"],
            "in_ladder": True, "outcomes": row["outcomes"],
        }
        if values_withheld:
            rendered.update({"scored": False, "withheld": True,
                             "reason": withheld_reason})
        out.append(rendered)
    mutation_block = res["mutation"]
    v2 = mutation_block.get("schema") == TEST_QUALITY_SUMMARY_SCHEMA_V2
    # Section 5.1: every v2 number is over the mapped population MINUS the
    # excluded pairs, so the two counts travel on the value itself -- the
    # rendered cell is what gets quoted, and a narrowed denominator that does
    # not say it is narrowed is exactly what the ruling forbids.
    exclusions = (excluded_pairs_note(
        mutation_block["reference_excluded_count"],
        mutation_block["candidate_excluded_count"],
        mutation_block.get("reference_omitted_items")) if v2 else "")
    for key, label, block, name in _quality_rows_for(res):
        companion_row = block == "mutation_companion"
        b = ((mutation_block.get("companion") or {}) if companion_row
             else res[block])
        # A companion aggregate is admitted or withheld with the primary it
        # accompanies, so both are gated on the mutation block itself.
        gate = mutation_block if companion_row else b
        value = (b["values"] or {}).get(name) if b["scored"] else None
        sensitivity = ((b.get("only_gen_sensitivity") or {}).get("number")
                       if key == "mutation_only_gen" else value)
        withheld = (gate.get("publication_ready") is False
                    and gate.get("withheld_reasons"))
        # Population admission controls every canonical row, including the
        # hard-subset onlyGen row that is ordinarily not applicable.  Keep the
        # older qualifier behavior below independent: it still leaves that
        # row n/a when population completeness itself has been established.
        # Not measured, not withheld: a gold-killed slice has no number here
        # for any qualifier to hold back (GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md).
        if key in V2_GOLD_KILLED_ROWS and b["scored"] \
                and mutation_block.get("candidate_pair_scope") \
                == TQ.CANDIDATE_PAIRS_GOLD_KILLED:
            out.append({"key": key, "label": label,
                        "value": GOLD_KILLED_NOT_MEASURED,
                        "number": None, "in_ladder": None,
                        "scored": False, "not_measured": True,
                        "reason": GOLD_KILLED_NOT_MEASURED_REASON})
            continue
        if withheld and gate.get("population_withheld"):
            reason = "; ".join(gate["withheld_reasons"])
            out.append({"key": key, "label": label,
                        "value": f"withheld ({reason})",
                        "number": None, "in_ladder": None, "scored": False,
                        "withheld": True, "reason": reason,
                        "sensitivity_number": sensitivity})
            continue
        if key == "mutation_only_gen" \
                and b.get("verdict_basis") == "hard_subset" \
                and b["scored"]:
            out.append({"key": key, "label": label,
                        "value": HARD_SUBSET_ONLY_GEN,
                        "number": None, "in_ladder": None,
                        "scored": False,
                        "not_applicable": True,
                        "reason": HARD_SUBSET_ONLY_GEN_REASON,
                        "sensitivity_number": sensitivity})
            continue
        # A v2 hard-subset basis defines neither row over H_i (n/a below),
        # whatever its candidate slice.
        if key in GOLD_KILLED_ROWS \
                and (b["scored"] or (v2 and b.get("verdict_basis") == "full_gold")) \
                and not (v2 and b.get("verdict_basis") == "hard_subset") \
                and b.get("candidate_pair_scope") \
                == TQ.CANDIDATE_PAIRS_GOLD_KILLED:
            out.append({"key": key, "label": label,
                        "value": GOLD_KILLED_NOT_MEASURED,
                        "number": None, "in_ladder": None,
                        "scored": False, "not_measured": True,
                        "reason": GOLD_KILLED_NOT_MEASURED_REASON})
            continue
        if key == "mutation_jaccard" and v2 and b["scored"] \
                and b.get("verdict_basis") == "hard_subset":
            out.append({"key": key, "label": label,
                        "value": HARD_SUBSET_JACCARD,
                        "number": None, "in_ladder": None,
                        "scored": False, "not_applicable": True,
                        "reason": HARD_SUBSET_JACCARD_REASON})
            continue
        # R4 item 6: a scored-but-unpublishable mutation cell renders as
        # WITHHELD rather than as its number.  The block keeps the number --
        # `--format json` prints it, and the reasons beside it -- but the
        # rendered table is what gets quoted, so the qualifier has to be able
        # to stop a number there or it is not a qualifier.
        if withheld:
            reason = "; ".join(gate["withheld_reasons"])
            out.append({"key": key, "label": label,
                        "value": f"withheld ({reason})",
                        "number": None, "in_ladder": None, "scored": False,
                        "withheld": True, "reason": reason,
                        "sensitivity_number": sensitivity})
            continue
        rendered_value = (f"{value:.3f}" if value is not None
                          else b["reason"])
        if v2 and value is not None and (companion_row or block == "mutation"):
            rendered_value += f"  {exclusions}"
        out.append({"key": key, "label": label,
                    "value": rendered_value,
                    "number": value, "in_ladder": None,
                    "scored": b["scored"]})
    out.extend(secondary_rows(res))
    return out


def secondary_rows(res: dict) -> list[dict]:
    """The section 6.2/6.3 rows, or nothing at all.

    Nothing at all is the default and is the point: a `results` invocation
    without the new inputs renders exactly the table it rendered before, and
    every pinned rendering keeps its bytes.
    """
    block = res.get("secondary")
    if not block:
        return []
    out = []
    for key, label, name, path in SECONDARY_ROWS:
        sub = block.get(name)
        if sub is None:
            continue
        value = (sub["values"] or {}).get(path) if sub["scored"] else None
        if value is None:
            out.append({"key": key, "label": label,
                        "value": sub["reason"] or MISSING_ROW,
                        "number": None, "in_ladder": None, "scored": False,
                        "secondary": True})
            continue
        interval = (sub.get("intervals") or {}).get(path)
        note = (sub.get("interval_notes") or {}).get(path)
        rendered = f"{value:.3f}"
        if interval:
            rendered += f"  95% CI [{interval[0]:.3f}, {interval[1]:.3f}]"
            if note:
                rendered += f"  ({note})"
        out.append({"key": key, "label": label, "value": rendered,
                    "number": value, "in_ladder": None, "scored": True,
                    "secondary": True, "interval": interval,
                    "interval_reason": None if interval else note})
    return out


def _ladder_value(row: dict, n: int) -> str:
    """`2.0% (2/100)` -- the percentage a reader quotes, over the count that
    makes it checkable.  Both, always: a percentage alone hides how few
    instances it is over, and a count alone has to be divided by hand."""
    return f"{row['rate'] * 100:.1f}% ({row['count']}/{n})"


#: How the diagnostic introduces itself wherever it is rendered.  One string,
#: because a reader who meets it in the text table and again in a campaign
#: column must not have to work out whether they are the same number, and
#: because "diagnostic, not canonical" is the whole point of the row.
PRODUCTION_COVERAGE_LABEL = "passes covering production code"


def production_coverage_note(block: dict) -> str:
    """The diagnostic as one line of prose, with its caveat attached.

    Every branch prints the counts it actually has.  The unscored branch in
    particular still reports how many measured passes covered nothing -- the
    absent input is the rate, not the observation -- while refusing to divide.
    """
    n_passed = block["n_passed"]
    measured = n_passed - block["n_not_collected"]
    head = (f"{PRODUCTION_COVERAGE_LABEL.upper()} -- a DIAGNOSTIC, not one of "
            f"the thirteen canonical rows and not part of any of them: ")
    if block["scored"]:
        return (
            head
            + f"{block['n_covering']} of the {n_passed} passed instance(s) "
              f"executed at least one production line and "
              f"{block['n_zero_production_lines']} executed none, so "
              f"{block['rate'] * 100:.1f}% ({block['n_covering']}/"
              f"{block['denominator']}) of the ladder population passed with "
              f"a test that touches the system under test. Same denominator "
              f"as `pass rate` above, so the two are directly comparable. A "
              f"pass that runs green over no production line asserts nothing "
              f"about the system; that is a property of the evaluated system, "
              f"read from the `coverage_lines` already on every row.")
    tail = (f" Of the {measured} passed instance(s) that were measured, "
            f"{block['n_zero_production_lines']} covered no production line "
            f"and {block['n_covering']} covered at least one."
            if measured else "")
    return head + f"not scored -- {block['reason']}." + tail


#: The order and the labels the floors table prints, per control.  One table
#: rather than rows in the canonical table: a control arm is not a run, and
#: `table_rows` has no arm dimension.
FLOOR_LABELS: tuple[tuple[str, str], ...] = (
    ("sibling_gold", "sibling gold (another scenario of the same feature)"),
    ("assertion_stripped_gold", "assertion-stripped gold"),
    ("stub", "stub"),
)
FLOOR_FIELDS: tuple[tuple[str, str], ...] = (
    ("line_recall_typical", "whole-execution line recall, typical sibling"),
    ("line_recall_best", "whole-execution line recall, best sibling"),
    ("api_f1_typical", "api f1, typical sibling"),
    ("api_f1_best", "api f1, best sibling"),
    ("target_region_recall_typical", "target-region recall, typical sibling"),
    ("target_region_recall_best", "target-region recall, best sibling"),
    ("coverage_recall", "whole-execution line recall"),
    ("coverage_jaccard", "coverage jaccard similarity"),
    ("api_f1", "api f1"),
    ("target_region_recall", "target-region recall"),
)


def secondary_notes(block: Optional[dict]) -> list[str]:
    """What the secondary rows are over -- without which they misread badly.

    Two misreadings in particular. A full-denominator number is NOT comparable
    with the passed-only row of the same name above it, and a `not_scorable`
    item is not an item that scored zero.
    """
    if not block:
        return []
    lines = []
    full = block.get("full_denominator")
    if full is not None and full["scored"]:
        lines.append(
            f"the rows marked `full denominator` are over "
            f"{full['n_items']} item(s) with a scorable gold row "
            f"({full['n_api_items']} for the api rows), with failures and "
            f"absent runs SUBSTITUTED at "
            f"{full['undefined_score']['coverage.recall']:g} (1.0 for "
            f"`excess`, whose polarity is inverted). They are not comparable "
            f"with the passed-only quality rows above, which are means over "
            f"the {full['n_scored']} scored pass(es); both are in the JSON.")
    region = block.get("target_region")
    if region is not None and region["scored"]:
        not_scorable = len(region["excluded"].get(M.REGION_NO_GOLD_LINES, ()))
        no_coverage = len(region["excluded"].get("run_without_coverage", ()))
        lines.append(
            f"target-region recall is over gold's covered lines INSIDE the "
            f"item's reviewed target bodies, so its denominator is "
            f"{region['n_scored']} item(s) whose candidate ran; "
            f"{no_coverage} further scorable item(s) were recorded without "
            f"coverage, {not_scorable} item(s) are not_scorable because "
            f"their gold run covers no region line, and "
            f"{len(region['excluded'].get('not_in_target_map', ()))} are "
            f"absent from the map. `reaches-target` is over all "
            f"{region['n_items']} scorable item(s): the share whose candidate "
            f"covered ALL of gold's region lines, counting failures as not "
            f"reaching.")
    api = block.get("undisclosed_api")
    if api is not None and api["scored"]:
        lines.append(
            f"the undisclosed-api row is `D_G \\ I` against `D_C \\ I`, where "
            f"`I` is the item's disclosed `checked_interfaces` list: it is "
            f"overlap with the related APIs the reference test used, never "
            f"test quality. {api['n_scored']} of {api['n_items']} item(s) "
            f"scored; "
            f"{len(api['excluded'].get(M.UNDISCLOSED_FULLY_DISCLOSED, ()))} "
            f"had nothing left after the subtraction and are unscored.")
    return lines


def control_floors_lines(block: Optional[dict]) -> list[str]:
    """The measured floors as their own small table, medians with counts.

    A floor is what a test that is NOT the answer already scores on the row
    above it; without it a coverage recall of 0.95 reads as a good result when
    another scenario's gold test scores 0.999 on the same item.  Medians, each
    with the number of items behind it, because a floor over 12 of 422 items
    is a different claim from one over all of them.
    """
    if not block:
        return []
    lines = [f"MEASURED FLOORS -- {block['project']}, "
             f"{block['n_gold_items']} gold item(s). What a test that is NOT "
             f"this item's answer already scores. Not run rows, not a "
             f"canonical row, and never subtracted from one."]
    for role, label in FLOOR_LABELS:
        floors = block["floors"].get(role)
        if floors is None:
            lines.append(f"  {label}: not supplied")
            continue
        head = label
        if "n_scored" in floors:
            refused = floors.get("n_construction_refused")
            head += (f" ({floors['n_scored']} item(s) scored of "
                     f"{floors['n_rows']} row(s), {floors['n_passed']} passed"
                     + (f", {refused} refused construction and not scored"
                        if refused else "") + ")")
        elif floors.get("n_items_without_sibling"):
            head += (f" ({floors['n_items_without_sibling']} item(s) have no "
                     f"sibling and are not scored)")
        lines.append(f"  {head}")
        for field, field_label in FLOOR_FIELDS:
            entry = floors.get(field)
            if not isinstance(entry, dict) or entry.get("median") is None:
                continue
            lines.append(f"    {field_label:<46}  median "
                         f"{entry['median']:.3f}  (n={entry['n']})")
    return lines


def notes(res: dict) -> list[str]:
    """The lines that must travel with the table for it to be readable.

    Not decoration.  Every one of them exists because the number above it can
    be misread in a specific way, and the misreading is worse than the space.
    """
    from ..core.constants import SUBMITTED_CONDITION

    coverage, api = res["coverage"], res["api"]
    mut, lad = res["mutation"], res["ladder"]
    v2_mutation = mut.get("schema") == TEST_QUALITY_SUMMARY_SCHEMA_V2
    population = res["population"]
    if lad.get("withheld") or lad.get("population_withheld"):
        reasons = list(lad.get("withheld_reasons") or ())
        reasons.extend(
            reason for reason in lad.get("population_withheld_reasons") or ()
            if reason not in reasons)
        ladder_note = (
            f"observed_n = {population['observed_n']} instance(s) in the run "
            f"file; ladder_n = "
            f"{lad['denominator']} after {lad['n_excluded']} deliberate or "
            f"infrastructure exclusion(s); classified_n = "
            f"{lad['classified_n']}. The primary ladder is WITHHELD because "
            f"{'; '.join(reasons)}. Counts are retained for "
            "diagnosis, but no ladder percentage is reported.")
    else:
        ladder_note = (
            f"observed_n = {population['observed_n']} instance(s). The six "
            f"ladder rows are over ladder_n = "
            f"{lad['denominator']} of them and sum to 100%: they are the "
            "execution pipeline in order, so each instance stops at exactly "
            "one rung.")
    missing = population["missing_planned_ids"]
    if population["status"] == "complete":
        population_note = (
            f"population binding COMPLETE from {population['source']}: "
            f"planned_n = {population['planned_n']}, observed_n = "
            f"{population['observed_n']}, missing_planned_ids = [].")
    elif population["status"] == P.RATIFIED_STATUS:
        excluded = "; ".join(
            f"{entry['item_id']} ({entry['note']})"
            for entry in population["ratified_infrastructure_exclusions"])
        population_note = (
            f"population binding COMPLETE AFTER RATIFIED INFRASTRUCTURE "
            f"EXCLUSION(S) from {population['source']}: planned_n = "
            f"{population['planned_n']}, observed_n = "
            f"{population['observed_n']}, missing_planned_ids = {missing}. "
            f"{len(population['ratified_infrastructure_exclusions'])} "
            f"infrastructure (killed or failed without a row, "
            f"owner-ratified): {excluded}. Such an attempt created its "
            "trajectory and finished with a nonzero or no exit and no row; "
            "it receives no outcome and enters no numerator, denominator or "
            "rung.")
    elif population["status"] == "incomplete":
        population_note = (
            f"POPULATION INCOMPLETE from {population['source']}: planned_n = "
            f"{population['planned_n']}, observed_n = "
            f"{population['observed_n']}, missing_planned_ids = "
            f"{missing}. All thirteen canonical values are WITHHELD; missing "
            "items receive no imputed outcome.")
    elif population["status"] == "count_only":
        population_note = (
            f"COUNT-ONLY PINNED POPULATION from {population['source']}: "
            f"planned_n = {population['planned_n']}, observed_n = "
            f"{population['observed_n']}, missing_planned_ids = unavailable. "
            "Exact completeness is not established, so all thirteen canonical "
            "values are WITHHELD and no missing outcome is imputed.")
    else:
        population_note = (
            "UNPINNED DEVELOPMENT OUTPUT: planned_n = unavailable, observed_n "
            f"= {population['observed_n']}, missing_planned_ids = unavailable. "
            "No observed-only canonical arithmetic is reported.")
    block = population.get("population_exclusions")
    if block is not None:
        population_note += (
            f" BENCHMARK {block['benchmark_version']} POPULATION: planned_n "
            f"and observed_n count it; {block['count']} instance(s) of this "
            f"cell are outside it ({block['path']}). Their rows were "
            "collected and enter no numerator, denominator or rung.")
    lines = [
        population_note,
        ladder_note,
        production_coverage_note(res["production_coverage"]),
        f"The {'ten' if v2_mutation and mut.get('verdict_basis') == 'hard_subset' else 'seven'} quality rows are MEANS OVER "
        f"THE {res['n_passed']} PASSED INSTANCE(S) -- they measure how good a "
        f"working test is, and they are undefined where no test ran. They are "
        f"NOT whole-benchmark rates.",
        "`generation failure` means the system ran to completion and wrote no "
        "test code. It is a rung, not a footnote: nothing can compile that "
        "was never written.",
    ]
    if population.get("inference_valid") is False:
        lines.insert(0, "Population is descriptive-only: " + population["inference_reason"] + ".")
        if population.get("source_run"):
            lines.insert(1, "Generation evidence remains the original census C run "
                         + population["source_run"]["path"] + "; this table scores only L.")
    if res.get("tier") == SUBMITTED_CONDITION:
        lines.insert(
            0,
            "SUBMITTED TIER: candidate bytes were produced outside the "
            "benchmark's declared and reviewed C2/C3 generation protocols. "
            "This table is non-canonical, must not be published, and must "
            "not be combined with study-condition results. "
            f"environment_proven: {res.get('environment_proven')} -- whether "
            "an accepted `environment up` bring-up record covered the "
            "worker that scored these rows (external-candidate amendment, "
            "decision 7).")
    for bucket in (INFRASTRUCTURE, UNCLASSIFIED):
        exc = lad["excluded"][bucket]
        if not exc["count"]:
            continue
        detail = ", ".join(f"{o} {k}" for o, k in exc["outcomes"].items())
        why = (", ".join(f"{m} {k}" for m, k in exc["markers"].items())
               if exc["markers"] else "")
        prefix = (f"{exc['label']}: {exc['count']} instance(s) [{detail}"
                  + (f"; markers: {why}" if why else "")
                  + f"]. EXCLUDED from the ladder denominator, which is "
                    f"therefore {lad['denominator']} and not {res['n']} -- ")
        if bucket == INFRASTRUCTURE:
            lines.append(
                prefix + "these rows are the benchmark failing, not the "
                "system, and the protocol re-runs or quarantines them.")
        else:
            lines.append(
                prefix + "these are documented deliberate non-rungs; adding "
                "one to the ladder requires an explicit methodology change, "
                "not a retry.")
    unknown = lad.get("unknown") or {}
    if unknown.get("count"):
        detail = ", ".join(f"{o} {k}"
                           for o, k in unknown["outcomes"].items())
        lines.append(
            f"{unknown['label']}: {unknown['count']} instance(s) [{detail}]. "
            "IN the ladder population but not classified on any rung; no "
            "smaller denominator or primary rate is reported.")
    if not lad.get("withheld") and not lad["sums_to_denominator"]:
        lines.append("WARNING: the ladder rows do not sum to the denominator "
                     "-- an instance was counted twice or dropped. Do not "
                     "publish this table.")
    if mut.get("scored") and mut.get("n_scored") != mut.get("n_passed") \
            and not v2_mutation:
        lines.append(
            f"mutation rows are over {mut['n_scored']} of the "
            f"{mut['n_passed']} passed instance(s): gold kills nothing on the "
            f"other {len(mut['not_scorable'])}, so they cannot separate a "
            f"test from a no-op and are excluded rather than scored 0.")
    if mut.get("reference_method") == "single_observation":
        lines.append("Mutation method: single_observation, one reference observation per role "
                     "and one candidate observation; full_gold on the declared B100 development "
                     "population. Reference rows are reused; repeat-run stability was not measured.")
    if v2_mutation:
        if mut.get("verdict_basis") == "full_gold":
            lines.append(
                f"Mutation basis: full gold, method {mut['method']}, one candidate "
                f"and one full-gold reference observation; installed reference controls "
                f"{mut['reference_controls_digest']}. Full-gold non-vacuous passes lead; "
                f"recall is a companion over {mut['n_scored']} of {mut['n_passed']} "
                f"passed items. Empty full-gold kill sets are not scorable. "
                "Candidates observe gold-killed pairs only; only-generated kills and "
                "Jaccard are not measured. No stripped or stub mutation reference "
                "was collected: assertion-sensitive recall and the stub gate are "
                "undefined, and this basis cannot distinguish exercising more "
                "behaviour from checking more assertions.")
        else:
            # The two v2 estimands have DIFFERENT scored populations -- an item
            # with an empty hard subset can still have a nonempty full-gold kill
            # set -- so one shared "n_scored" line would be wrong for one of them.
            companion = mut.get("companion") or {}
            lines.append(
                f"Mutation primary: hard-subset recall from method "
                f"{mut['method']} with {mut['candidate_observation_count']} "
                f"candidate observation and {mut['reference_observation_count']} "
                f"reference observation, over the installed reference controls "
                f"{mut['reference_controls_digest']}; n_scored = "
                f"{mut['n_scored']} of {mut['n_passed']} passed instance(s). "
                f"Eligibility excludes an empty hard subset "
                f"({len(mut.get('not_scorable') or ())} excluded here) rather "
                f"than scoring it 0. Hard-subset only-generated and Jaccard are "
                f"not defined.")
            lines.append(
                f"Mutation companion: full-population recall, only-generated and "
                f"Jaccard; n_scored = {companion.get('n_scored', 0)} of "
                f"{mut['n_passed']} passed instance(s). Eligibility excludes an "
                f"empty full-gold reference kill set "
                f"({len(companion.get('not_scorable') or ())} excluded here) "
                f"rather than scoring it 0. These are companion metrics from the "
                f"same candidate observation and are not combined with the hard "
                f"denominator.")
        # A v2 gold-killed summary executes only G_i, so its run-side count
        # covers exclusions inside that slice and nothing outside it is seen.
        run_part = (
            f"minus {mut['candidate_excluded_count']} pair(s) of the "
            f"gold-killed candidate slice this candidate run lost of its own; "
            f"candidate outcomes outside the slice were not observed"
            if v2_mutation and mut.get("candidate_pair_scope")
            == TQ.CANDIDATE_PAIRS_GOLD_KILLED else
            f"minus {mut['candidate_excluded_count']} further pair(s) this "
            f"candidate run lost of its own")
        lines.append(
            f"SECTION 5.1 EXCLUSIONS: the scored pair universe is the mapped "
            f"population minus {mut['reference_excluded_count']} pair(s) the "
            f"reference observations lost to a terminal timeout or "
            f"infrastructure outcome, {run_part}. Both counts "
            f"are printed beside every mutation number above. Nothing is "
            f"imputed for an excluded pair, and the narrowed population must "
            f"not be analysed as if it were the registered one.")
        if mut.get("reference_omitted_items"):
            lines.append(
                f"DECLARED REFERENCE SUBSET: the reference covers a declared "
                f"subset of its mapped item population; "
                f"{mut['reference_omitted_items']} released item(s) are "
                f"omitted, declared reason: "
                f"{mut.get('reference_declared_reason') or 'not recorded'}. "
                f"The omitted ids are recorded in the reference-controls "
                f"artifact cited above. Every mutation number here is "
                f"macro-averaged over the declared items only.")
    if mut.get("macro_mismatch"):
        lines.append(
            f"WARNING: the test-quality summary records recall_macro "
            f"{mut['recall_macro_recorded']} but its own per-item counts give "
            f"{mut['values']['recall']:.6f}. The counts are what this table "
            f"used; the summary and its evidence disagree.")
    for label, block in (("coverage", coverage), ("api", api)):
        if not block.get("scored") or block["n_scored"] == block["n_passed"]:
            continue
        exc = block["excluded"]
        note = (
            f"{label} rows are over {block['n_scored']} of the "
            f"{block['n_passed']} passed instance(s): "
            f"{len(exc['no_gold_row'])} have no gold row, "
            f"{len(exc['gold_without_coverage'])} have a gold run with no "
            f"coverage block (no upper bound), and "
            f"{len(exc['run_without_coverage'])} were recorded without "
            f"coverage.")
        if label == "api":
            note += (
                f" A further {len(exc['run_without_direct_calls'])} carry no "
                f"`direct_calls` and {len(exc['gold_without_direct_calls'])} "
                f"have a gold run that carries none, so their API rows are "
                f"not defined; "
                f"{len(exc['run_before_api_amendment_2'])} candidate and "
                f"{len(exc['gold_before_api_amendment_2'])} gold recordings "
                f"lack API Amendment 2 collection/fold identity; "
                f"{len(exc['gold_no_direct_methods'])} have a gold test that "
                f"invoked no production method directly, which is unscorable "
                f"rather than a free 1.0.")
        lines.append(note + " Excluded, not scored 0.")
    unmapped = api.get("unmapped_direct_events")
    if api.get("scored"):
        sizes = api["d_g_sizes"]
        lines.append(
            f"api sets: |D_G| median {sizes['median']:g} (min {sizes['min']}, "
            f"max {sizes['max']}) over {sizes['n']} scored item(s); unmapped "
            f"direct events over every coverage-compared item: gold "
            f"{unmapped['gold']}, run {unmapped['run']}.")
    elif unmapped is not None:
        # Unscored after comparing, so the diagnostic exists and is the
        # one thing the block can still say about the index.
        lines.append(
            f"api sets: none scored; unmapped direct events over every "
            f"coverage-compared item: gold {unmapped['gold']}, run "
            f"{unmapped['run']}.")
    empty_coverage = coverage.get("degenerate_gold", {}).get(
        "empty_coverage", 0)
    if empty_coverage:
        lines.append(
            f"WARNING: {empty_coverage} scored instance(s) have a gold run "
            f"covering no production line. Both sides empty is an identity, "
            f"so every system scores 1.0 there for free -- exclude or repair "
            f"those items.")
    # Which instances are not first observations.  A NOTE and not a filter:
    # the re-drawn rows are inside every percentage above, dropping them would
    # move a denominator fixed before execution, and a reader who is not told
    # cannot tell -- which is the state A5 cell 4 shipped in.  Silent on every
    # run whose rows are all first draws, i.e. on every archived one.
    lines.extend(line.strip() for line in
                 draws.disclosure(res.get("draws") or {}, indent=""))
    lines.extend(secondary_notes(res.get("secondary")))
    # Last, and below the table: effort is the context the thirteen rows are
    # read in, not a caveat about any one of them.
    if res.get("effort"):
        lines.append(_effort_note(res["effort"]))
    return lines


# --------------------------------------------------------------------------
# rendering

def _submitted_tier(res: dict) -> bool:
    """Whether this result is the submitted, non-canonical tier.

    One predicate for all three labelled formats and for the legacy refusal,
    so a renderer cannot disagree with the notes about which tier a table is.
    """
    from ..core.constants import SUBMITTED_CONDITION
    return res.get("tier") == SUBMITTED_CONDITION


def _provenance(res: dict) -> list[tuple[str, str]]:
    """Where every number came from: one line per file, plus the sizes.

    Printed above the table in all three formats, because a canonical table
    whose inputs are implicit is a table nobody can re-derive -- and the
    defaults this command resolves (a gold run found by name, a sidecar found
    beside the run) are exactly the ones a reader would otherwise have to
    guess at.
    """
    mut, api = res["mutation"], res["api"]
    digest = res["campaign_digest"]
    index = res["prod_index"] or "-"
    if api.get("prod_index_files"):
        index += (f"  ({api['prod_index_files']} files, "
                  f"{api['prod_index_methods']} methods)")
    quality = res["test_quality"] or "-"
    if mut.get("mutants_in_population"):
        # A v2 gold-killed summary counts its executed slice, `G_i` of the
        # passes; a v1 one still counts gold's complete pair set.
        where = ("the gold-killed candidate slice"
                 if mut.get("schema") == TEST_QUALITY_SUMMARY_SCHEMA_V2
                 and mut.get("candidate_pair_scope")
                 == TQ.CANDIDATE_PAIRS_GOLD_KILLED else "the population")
        quality += (f"  ({mut['mutants_in_population']} mutant(s) / "
                    f"{mut['pairs_expected']} execution(s) in {where})")
    if mut.get("schema") == TEST_QUALITY_SUMMARY_SCHEMA_V2:
        quality += (
            f"  [method: {mut['method']}; candidate observations: "
            f"{mut['candidate_observation_count']}; reference observations: "
            f"{mut['reference_observation_count']}; reference controls: "
            f"{mut['reference_controls_digest']}; "
            + excluded_pairs_note(
                mut["reference_excluded_count"],
                mut["candidate_excluded_count"],
                mut.get("reference_omitted_items")) + "]")
    from .mutation_run import GENERATION_PROVENANCE_DEVELOPMENT
    if res.get("test_quality_generation_class") \
            == GENERATION_PROVENANCE_DEVELOPMENT:
        quality += "  [development route: unstamped candidate]"
    # FIRST, because it is the table's identity and everything under it is
    # where the identity's parts were read from. Above the payload in every
    # format that has a provenance block, and absent from `markdown-legacy`,
    # which is the payload alone -- see `markdown_payload_lines`.
    out = [("citation", res.get("citation") or "?"),
           ("run", res["run"]),
           ("gold", res["gold"] or "-"),
           ("prod index", index),
           ("test quality", quality)]
    if digest:
        out.append(("campaign", digest[0] if len(digest) == 1
                    else f"{len(digest)} DIFFERENT digests: "
                         f"{', '.join(digest)}"))
    population = res["population"]
    out.append(("population", f"{population['status']} ({population['source']})"))
    out.append(("planned_n", (str(population["planned_n"])
                               if population["planned_n"] is not None
                               else "unavailable")))
    out.append(("observed_n", str(population["observed_n"])
                + ("" if res["n"] == res["n_rows_in_file"]
                   - res.get("n_rows_outside_population", 0)
                   else f"  ({res['n_rows_in_file']} row(s) in the file; an "
                        f"item re-run in place counts once)")))
    lad = res["ladder"]
    ladder_text = str(population["ladder_n"])
    if lad["reduced"]:
        ladder_text += (f"  ({lad['n_excluded']} instance(s) excluded -- see "
                        "below the table)")
    out.append(("ladder_n", ladder_text))
    out.append(("classified_n", str(population["classified_n"])))
    missing = population["missing_planned_ids"]
    out.append(("missing_planned_ids",
                "unavailable" if missing is None
                else "[]" if not missing else ", ".join(missing)))
    ratified = population.get("ratified_infrastructure_exclusions")
    if ratified:
        out.append(("infrastructure exclusions",
                    f"{len(ratified)} infrastructure (killed or failed "
                    f"without a row, owner-ratified): "
                    + ", ".join(entry["item_id"] for entry in ratified)
                    + f"  [{res['infrastructure_exclusions']['path']} "
                    f"sha256 {res['infrastructure_exclusions']['sha256']}]"))
    if population.get("population_exclusions") is not None:
        from .report import population_exclusions_text
        out.append(("2.0 excluded", population_exclusions_text(
            population["population_exclusions"])))
    out.append(("passed", str(res["n_passed"])))
    return out


def _population_heading(res: dict, *, markdown: bool = False) -> str:
    """A prominent admission label for every non-legacy human rendering."""
    population = res["population"]
    if _submitted_tier(res):
        base = (f"Submitted tier results (non-canonical; environment_proven: "
                f"{res.get('environment_proven')})" if markdown else
                f"SUBMITTED TIER RESULTS (non-canonical; environment_proven: "
                f"{res.get('environment_proven')})")
        return f"{base}; population {population['status']}"
    if population["canonical_values_admitted"]:
        return "Canonical results" if markdown else "CANONICAL RESULTS"
    label = population["status"].replace("_", "-")
    return (f"Non-canonical results ({label}; canonical values withheld)"
            if markdown else
            f"NON-CANONICAL RESULTS ({label.upper()}; CANONICAL VALUES WITHHELD)")


def render_text(res: dict) -> str:
    rows = table_rows(res)
    width = max(len(r["label"]) for r in rows)
    # The heading is what a pasted table leads with, so the tier lives there
    # and not only in the notes below the rows: `CANONICAL RESULTS` over
    # submitted bytes would be the exact over-claim the tier exists to stop.
    # The environment-proven stamp sits beside the tier label (amendment
    # decision 7): a reader who sees a submitted number sees, in the same
    # glance, whether the environment that scored it was proven up.
    heading = _population_heading(res)
    lines = [f"{heading} -- {res['run_name']}", ""]
    key_w = max(len(k) for k, _ in _provenance(res))
    for key, value in _provenance(res):
        lines.append(f"  {key:<{key_w}}  {value}")
    lines.append("")
    for row in rows:
        # The visual breaks in the table: the first separates the rows that
        # are over n from the rows that are over the passes, which is the one
        # distinction a reader has to hold on to; the second separates the
        # canonical thirteen from the secondary rows below them, which are
        # over a different denominator again.
        if row["key"] == QUALITY_ROWS[0][0] \
                or row["key"] == SECONDARY_ROWS[0][0]:
            lines.append(f"  {'-' * (width + 2 + 24)}")
        lines.append(f"  {row['label']:<{width}}  {row['value']}")
    lines.append("")
    floors = control_floors_lines((res.get("secondary") or {})
                                  .get("control_floors"))
    if floors:
        lines.extend(floors)
        lines.append("")
    # Wrapped, because these notes are not optional reading: an unwrapped
    # 300-character line in a terminal is a line that gets skipped, and the
    # thing being skipped is which denominator the numbers above are over.
    for note in notes(res):
        wrapped = textwrap.wrap(note, width=76)
        lines.append(f"  * {wrapped[0]}")
        lines.extend(f"    {part}" for part in wrapped[1:])
    return "\n".join(lines) + "\n"


def render_markdown(res: dict) -> str:
    # Same rule as `render_text`: the tier is the heading, not a footnote,
    # and the environment-proven stamp sits beside the tier label.
    heading = _population_heading(res, markdown=True)
    lines = [f"### {heading} -- `{res['run_name']}`", ""]
    for key, value in _provenance(res):
        lines.append(f"- **{key}**: `{value}`")
    # The payload comes from `markdown_payload_lines` rather than being
    # written out again here.  Current and legacy payloads share one Markdown
    # dialect below, while `LEGACY_ROWS` deliberately gives them different
    # row sets.
    lines.append("")
    lines.extend(markdown_payload_lines(res))
    lines.append("")
    floors = control_floors_lines((res.get("secondary") or {})
                                  .get("control_floors"))
    if floors:
        # Fenced: the floors are a fixed-width table of medians and counts,
        # and a Markdown renderer that reflows them turns a column of numbers
        # into a paragraph.
        lines.extend(["```text", *floors, "```", ""])
    for note in notes(res):
        lines.append(f"*{note}*")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _markdown_table_lines(rows: list[dict]) -> list[str]:
    """One Markdown dialect for either the current or legacy row set."""
    lines = ["| metric | value |", "| --- | --- |"]
    for row in rows:
        lines.append(f"| {row['label']} | {row['value']} |")
    return lines


def markdown_payload_lines(res: dict) -> list[str]:
    """The current table payload alone: header, separator, thirteen rows."""
    return _markdown_table_lines(table_rows(res))


def render_markdown_legacy(res: dict) -> str:
    """The payload and nothing else -- the frozen shape a published table has.

    `markdown` grows: it carries a provenance block, and its notes gain a line
    whenever a number acquires a new way of being misread.  That is right for
    a table someone is reading, and wrong for a table someone is DIFFING, so
    this format exists to be diffed.  It is pinned byte-for-byte against
    `release/v1/legacy_table_eval100_std.md`, generated from the archived
    standard-setting run, and the pin is the thing that would fail loudly if
    a future edit changed a label, a rounding, or the order of the rungs --
    all of which would silently change what every published percentage means.

    It therefore fails closed on the submitted tier.  The format is payload
    ONLY -- no heading, no provenance, no notes -- so it has no line the
    mandated tier label could live on, and rendering the twelve rows bare
    would produce a table indistinguishable from a published canonical one.
    Ordinary runs are untouched, which is what keeps the release pin green.
    """
    population = res.get("population") or {}
    if population.get("complete") is not True:
        status = population.get("status", "unresolved")
        detail = ("pinned population is incomplete"
                  if status == "incomplete" else
                  "population has ratified infrastructure exclusions that "
                  "must be disclosed" if status == P.RATIFIED_STATUS else
                  "exact population completeness is unavailable")
        raise ResultsInputError(
            f"markdown-legacy cannot render population status {status!r}: the "
            f"{detail}, and the frozen payload-only shape has no line for the "
            "required population disclosure. Use text, markdown or json.")
    if P.excluded_ids(population):
        raise ResultsInputError(
            "markdown-legacy cannot render a benchmark 2.0 population that "
            "leaves instances out: the frozen payload-only shape has no line "
            "for that disclosure. Use text, markdown or json.")
    if _submitted_tier(res):
        raise ResultsInputError(
            "markdown-legacy cannot render the submitted tier: the frozen "
            "payload-only shape has no line for the mandated tier label, so "
            "its output would be indistinguishable from a canonical table. "
            "Use text, markdown or json, which all label the tier.")
    if (res.get("mutation") or {}).get("schema") \
            == TEST_QUALITY_SUMMARY_SCHEMA_V2:
        raise ResultsInputError(
            "markdown-legacy cannot render a v2 single-observation mutation "
            "result: the frozen payload has no line for the labelled "
            "full-population companion rows and none for section 5.1's "
            "excluded counts. Use text, markdown or json.")
    rows = {row["key"]: row for row in table_rows(res)}
    lines = _markdown_table_lines([rows[key] for key in LEGACY_ROWS])
    return "\n".join(lines) + "\n"


def render_json(res: dict) -> str:
    """The same numbers as data, plus everything a micro figure would need.

    `table` is the rendered table (so a consumer cannot draw a different one
    by accident) and the blocks beside it carry the per-instance evidence the
    table deliberately does not print.
    """
    payload = dict(res)
    quality_keys = {q[0] for q in _quality_rows_for(res)}
    payload["table"] = [{k: v for k, v in row.items() if k != "outcomes"}
                        if row["key"] in quality_keys
                        else row for row in table_rows(res)]
    payload["notes"] = notes(res)
    return json.dumps(payload, indent=1, sort_keys=True, default=str) + "\n"


FORMATS = {"text": render_text, "markdown": render_markdown,
           "markdown-legacy": render_markdown_legacy,
           "json": render_json}


def render(res: dict, fmt: str = "text") -> str:
    if fmt not in FORMATS:
        raise ResultsInputError(
            f"unknown --format {fmt!r}; expected one of "
            f"{', '.join(sorted(FORMATS))}")
    return FORMATS[fmt](res)


# --------------------------------------------------------------------------
# selftest

def _boundary_fixture() -> Boundary:
    return Boundary(version=1, project="t", repo_root="/x",
                    removable=[("src/Test/", "generated test code")],
                    retained=[])


def _index_fixture(path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"files": {
            "src/Prod/Cart.php": {"classes": [{"name": "App\\Cart", "methods": [
                {"name": "total", "start": 10, "end": 20, "public": True},
                {"name": "clear", "start": 32, "end": 40, "public": True}]}]},
            "src/Prod/Tax.php": {"classes": [{"name": "App\\Tax", "methods": [
                {"name": "rate", "start": 5, "end": 9, "public": True}]}]},
        }}, fh)


def _write(path: str, rows: list[dict]) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    return path


def _producer_shaped_single_observation_summary(
        items: list[str], *, candidate_items=None, reference_excluded_count: int = 131,
        omitted_items: tuple = (), declared_reason=None,
        population_id: str = "fixture-v1", full_gold: bool = False,
        labelled_gold_killed: bool = False) -> dict:
    """A v2 summary the PRODUCER built, for the consumers' own selftests.

    `labelled_gold_killed` scores the hard-subset reference under the
    labelled stub-gate-waived basis on its gold-killed slice
    (SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md section 2).

    The renderer defect this exists to prevent was invisible for one reason:
    both consumer fixtures were hand-written in the CONSUMER's vocabulary, so
    no test ever joined `test_quality`'s summary to `results`/`report`.  A
    fixture that asserts what the consumer already believes proves nothing.

    So the arithmetic half here is not written at all -- it is what
    `test_quality.score_single_observation` returns for synthetic mutation
    rows -- and the identity half is filled by iterating the producer's own
    closed field list.  The key set is then asserted EQUAL to that list, so
    adding a field to the producer, or renaming one, fails here rather than
    six months later on a real run.
    """
    from . import reference_controls as RC
    from . import test_quality as TQ

    mutants = ["m0", "m1", "m2", "m3"]
    # The reference's SCORED universe: full population minus what section 5.1
    # already took out of it, which is what `expected_pairs` means.
    expected_pairs = frozenset((iid, mid) for iid in items for mid in mutants)
    # The last item is deliberately given an EMPTY hard subset and a nonempty
    # full-gold kill set: the two v2 estimands have different scored
    # populations, and a fixture where they coincide hides that.
    full_gold_kills = {iid: frozenset(mutants[:3]) for iid in items}
    hard_subset = {iid: (frozenset() if iid == items[-1]
                         else frozenset(mutants[:2])) for iid in items}
    sets = RC.ReferenceSets(
        expected_pairs=expected_pairs,
        excluded_count=reference_excluded_count,
        full_gold_kills=full_gold_kills, hard_subset=hard_subset,
        stub_recall_by_item={iid: 0.0 for iid in items},
        stub_macro_recall=0.0, stub_threshold=0.5, eligible=True,
        omitted_items=omitted_items, declared_reason=declared_reason,
        seal=RC._SETS_SEAL,
        **({"reference_basis": "full_gold"} if full_gold else {}),
        **({"sensitivity": "sylius_stub_gate_waived_v1"}
           if labelled_gold_killed else {}))
    authority = TQ._SingleObservationScoringAuthority(
        {"digest": "a" * 64,
         **({"gold_disagreements": {"source": None, "sha256": None,
                                    "pairs": []}}
            if labelled_gold_killed else {})},
        sets, TQ._SINGLE_OBSERVATION_AUTHORITY_SEAL)
    gold_killed = full_gold or labelled_gold_killed

    rows = []
    for n, iid in enumerate(items):
        for mid in mutants:
            if gold_killed and mid not in full_gold_kills[iid]:
                continue
            if iid == items[-1] and mid == ("m2" if full_gold else "m3"):
                # One terminal timeout, so `candidate_excluded_count` is a
                # real discovered number and not a hard-coded 0.
                outcome = "timeout"
            elif n == 0:
                outcome = "failed"            # kills m0..m3: one only-kill
            else:
                outcome = "failed" if mid == "m0" else "passed"
            rows.append({"item_id": iid, "mutant_id": mid,
                         "outcome": outcome})
    selected = set(items if candidate_items is None else candidate_items)
    rows = [row for row in rows if row["item_id"] in selected]
    summary = TQ.score_single_observation(
        {iid: True for iid in selected}, rows, authority=authority,
        candidate_pair_scope=(TQ.CANDIDATE_PAIRS_GOLD_KILLED
                              if labelled_gold_killed
                              else TQ.CANDIDATE_PAIRS_ALL))

    identity = {
        "schema": TEST_QUALITY_SUMMARY_SCHEMA_V2,
        "reference_controls": {"digest": "a" * 64},
        "require_complete": True,
        "generation_provenance_class": "native_v2",
        # A full-gold summary executes and counts only its gold-killed slice.
        "mutants_in_population": (len({row["mutant_id"] for row in rows})
                                  if gold_killed else len(mutants)),
        "pairs_expected": len(rows) if gold_killed else len(expected_pairs),
        "pairs_executed_candidate": len(rows),
        "pairs_executed_gold": len(rows),
        "population_id": population_id,
        "engine": "r2t-mutate", "engine_version": "1.0",
    }
    expected_fields = TQ._single_observation_summary_fields(full_gold) if full_gold else TQ._single_observation_summary_fields()
    if labelled_gold_killed:
        expected_fields |= (TQ.GOLD_KILLED_SUMMARY_FIELDS
                            | TQ.SENSITIVITY_SUMMARY_FIELDS)
    for field in expected_fields:
        # Every remaining identity field is present and None: the closed
        # contract is about which KEYS exist, and a consumer that reads one
        # must survive an unset one rather than only a populated one.
        # `setdefault`, never `update`: what the producer computed wins.
        summary.setdefault(field, identity.get(field))
    if set(summary) != expected_fields:
        raise AssertionError(
            "producer-shaped fixture drifted from the producer's closed "
            f"field list: missing={sorted(expected_fields - set(summary))}, "
            f"unknown={sorted(set(summary) - expected_fields)}")
    return summary


def selftest() -> int:
    """The table's shape, its denominators, and every honest-degradation path.

    Synthetic throughout: no container, no gold sweep, no mutation campaign.
    What is checked is what a reader will actually see -- a value that is
    right in the dict and wrong in the cell is still wrong -- and above all
    the four ways a number can be absent (no pass, no sidecar, a stale
    sidecar, no coverage), because printing 0.0 for any of them is the one
    failure mode this whole module exists to prevent.
    """
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    b = _boundary_fixture()
    GOLD_COV = {"src/Prod/Cart.php": [10, 11], "src/Prod/Tax.php": [5]}

    # ONE project namespace for every fixture row.  Real item ids are
    # `<project>/features/...` and `project_of` reads the namespace off the id
    # itself; a fixture id with no `/` is its OWN project, so the sixteen rows
    # below would be sixteen projects and `results` would refuse them as a
    # pooled table (R4 item 7).  Prefixing here rather than at seventeen call
    # sites keeps the fixture readable and the gate honest.
    P = "t/"

    def item(name: str) -> str:
        return P + name

    def row(iid, outcome, cov=..., **kw):
        r = {"item_id": item(iid), "outcome": outcome,
             "campaign_digest": "cafe1234cafe1234"}
        if cov is not ...:
            r["coverage_lines"] = cov
        r.update(kw)
        return r

    # The API rows are over CALL EVENTS, so a scored fixture row has to carry
    # them.  `STEP` is the answer's own file (removable), which is what makes
    # a call direct; the callee lines are the index fixture's declarations.
    STEP = "src/Test/GeneratedTest.php"

    def call(callee_file, callee_line, callee):
        return {"callee_file": callee_file, "callee_line": callee_line,
                "callee": callee, "caller_file": STEP}

    # {Cart::total, Tax::rate} -- and one call into the answer's own file,
    # which is not a production callee and must reach no set.
    GOLD_CALLS = [call("src/Prod/Cart.php", 10, "App\\Cart::total"),
                  call("src/Prod/Tax.php", 5, "App\\Tax::rate"),
                  call(STEP, 1, "T\\GeneratedTest::helper")]
    # {Cart::total, Cart::clear}: one shared with gold, one gold never made.
    P2_CALLS = [call("src/Prod/Cart.php", 10, "App\\Cart::total"),
                call("src/Prod/Cart.php", 32, "App\\Cart::clear")]

    # Every ladder rung, both merged outcomes of `compilation failure`, both
    # kinds of infrastructure row, and one deliberate disclose-and-exclude
    # outcome.
    # 16 instances, hand-counted:
    #   generation 1, compilation 2, binding 2, execution 3, assertion 1,
    #   pass 2               -> 11 in the ladder
    #   infrastructure 4, deliberate non-rung 1 -> 5 excluded, denominator 11
    run_rows = [
        row("i_nofiles", "no_files_returned", None),
        row("i_parse", "parse_or_compile_error", None),
        row("i_container", "container_error", None),
        row("i_undef", "undefined_steps", {}),
        row("i_pending", "pending", {}),
        row("i_solution", "solution_error", None),
        row("i_noscen", "no_scenario_ran", None),
        row("i_timeout", "timeout", None),
        row("i_failed", "failed", {"src/Prod/Cart.php": [10]}),
        row("p1", "passed", dict(GOLD_COV),
            direct_calls=list(GOLD_CALLS)),
        # p2 misses Tax entirely and covers a line of `clear` gold never ran:
        #   lines   gold {C10,C11,T5} vs {C10,C11,C33} -> inter 2, union 4
        #   methods gold {total,rate}  vs {total,clear} -> inter 1 of 2 and 2
        row("p2", "passed", {"src/Prod/Cart.php": [10, 11, 33]},
            direct_calls=list(P2_CALLS)),
        # The four rows that LOOK like a generation failure and are not: two
        # by outcome, two by marker on the very same `no_files_returned`.
        row("i_harness", "harness_error", None),
        row("i_notfound", "scenario_not_found", None),
        row("i_driver", "no_files_returned", None,
            metadata={"driver_error": "transport closed mid-run"}),
        row("i_runerr", "no_files_returned", None,
            metadata={"agent_stats": {"run_errors": ["429 exhausted"]}}),
        # A deliberate non-rung: named and excluded, but not genuinely unknown.
        row("i_unknown", "no_writable_files", None),
    ]
    # The ids are already namespaced by `row`; passing them back through it
    # would prefix twice and make gold a different item set than the run.
    gold_rows = [{"item_id": r["item_id"], "outcome": "passed",
                  "campaign_digest": "cafe1234cafe1234",
                  "coverage_lines": dict(GOLD_COV),
                  "direct_calls": list(GOLD_CALLS)} for r in run_rows]

    def sidecar(items: dict, **qualifier) -> dict:
        # Publication-ready by default -- what a real complete campaign
        # writes.  `**qualifier` is how a check asks for the short or degraded
        # state instead, one named field at a time (R4 items 4-6).
        return {"_results_selftest_fixture": True,
                "n_passed": len(items), "recall_macro": None,
                "mutants_in_population": 40,
                **TQ.COMPLETE_QUALIFIER_FIXTURE, **qualifier,
                "per_item": items}

    # The recorded candidate-only counts are full-gold sensitivity evidence.
    # The default fixture is publication-ready hard-subset: onlyGen is n/a in
    # the table but its full-gold sensitivity number remains in JSON, while
    # Jaccard retains its pre-D6 calculation.
    # A direct full-gold calculation below exercises the non-zero onlyGen:
    #   p1  killed 4 of 4, plus ONE kill gold does not make
    #         recall 1.000   onlyGen 1/5 = 0.200   jaccard 4/5 = 0.800
    #   p2  killed 1 of 2, no candidate-only kill
    #         recall 0.500   onlyGen 0.000         jaccard 0.500
    #   full-gold macros: recall 0.750, onlyGen 0.100, jaccard 0.650
    TQ_ITEMS = {
        item("p1"): {"candidate_killed": 4, "denominator": 4, "recall": 1.0,
               "full_candidate_killed": 8, "full_denominator": 9,
               "full_recall": 8 / 9, "candidate_only_kills": 1,
               "verdict": TQ.EQUIVALENT},
        item("p2"): {"candidate_killed": 1, "denominator": 2, "recall": 0.5,
               "full_candidate_killed": 2, "full_denominator": 4,
               "full_recall": 0.5, "candidate_only_kills": 0,
               "verdict": TQ.WEAKER},
    }
    FULL_TQ_ITEMS = {
        item("p1"): {"candidate_killed": 4, "denominator": 4, "recall": 1.0,
                     "candidate_only_kills": 1,
                     "verdict": TQ.EQUIVALENT},
        item("p2"): {"candidate_killed": 1, "denominator": 2, "recall": 0.5,
                     "candidate_only_kills": 0, "verdict": TQ.WEAKER},
    }

    # These table fixtures exercise rendering without constructing a complete
    # mutation campaign.  Production summaries still take the native
    # fail-closed path; only explicitly marked temporary fixtures are accepted,
    # and their exact run/generated-test binding is still verified.
    _real_tq_loader = TQ.load_bound_test_quality

    def _results_fixture_loader(run_path, summary_path=None):
        path = summary_path or TQ.find_sidecar(run_path)
        if not path:
            return None
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        if doc.get("_results_selftest_fixture") is not True:
            return _real_tq_loader(run_path, summary_path=summary_path)
        if doc.get("binding") != TQ.run_binding(run_path):
            raise TQ.TestQualityRefused(
                "REFUSED: results fixture sidecar is stale or tampered; "
                "run_sha256/generated_tests_sha256 disagree.")
        return doc

    TQ.load_bound_test_quality = _results_fixture_loader

    with tempfile.TemporaryDirectory() as d:
        run = _write(os.path.join(d, "sweep.jsonl"), run_rows)
        gold = _write(os.path.join(d, "gold.jsonl"), gold_rows)
        index = os.path.join(d, "index.json")
        _index_fixture(index)

        def fixture_population_scope(
                item_ids, *, campaign_digest=None, shard_rule=None,
                shard_count=None, source="selftest frozen workset") -> dict:
            from . import campaign as campaign_module
            from . import population as population_module
            from . import result_ledger
            ids = tuple(item_ids)
            if campaign_digest is not None and shard_rule is None:
                shard_rule = campaign_module.SHARD_RULE
            if campaign_digest is not None and shard_count is None:
                shard_count = 1
            return population_module.frozen_scope(
                item_ids=ids,
                workset={
                    "item_count": len(ids),
                    "ordered_item_ids_digest":
                        result_ledger.ordered_item_ids_digest(ids),
                },
                campaign_digest=campaign_digest,
                shard_rule=shard_rule, shard_count=shard_count, source=source)

        def pinned_results(run_path: str, **kwargs) -> dict:
            """Give ordinary table fixtures an explicit complete workset."""
            if not os.path.isfile(run_path):
                return results(run_path, **kwargs)
            fixture_rows = _publication_rows(run_path)
            item_ids = tuple(row["item_id"] for row in fixture_rows)
            campaigns = {row.get("campaign_digest") for row in fixture_rows
                         if row.get("campaign_digest") is not None}
            campaign_digest = (next(iter(campaigns))
                               if len(campaigns) == 1 else None)
            scope = fixture_population_scope(
                item_ids, campaign_digest=campaign_digest)
            return _results_impl(
                run_path, validated_population_scope=scope, **kwargs)

        def sidecar_for(run_path: str, value: dict, name: str) -> str:
            """Write through the binding seam, then give it an explicit path."""
            canonical = TQ.write_sidecar(value, run_path)
            path = os.path.join(d, name)
            os.replace(canonical, path)
            return path

        tq_path = sidecar_for(run, sidecar(TQ_ITEMS), "tq.json")

        wrong_boundary = _boundary_fixture()
        wrong_boundary.project = "another-project"
        check("canonical results refuses a run paired with another project's "
              "boundary before scoring",
              _raises(lambda: pinned_results(run, boundary=wrong_boundary),
                      "run project 't' differs from boundary project "
                      "'another-project'"))

        mixed_tier = _write(os.path.join(d, "mixed-tier.jsonl"), [
            row("submitted", "no_files_returned", None,
                condition="submitted", adapter="submitted:fixture"),
            row("study", "no_files_returned", None, condition="c3"),
        ])
        check("canonical results refuses a submitted/study-tier mixture",
              _raises(lambda: pinned_results(
                  mixed_tier, gold_path="", prod_index_path="", boundary=b,
                  artifacts="", api_scoring=API_SCORING_NONE),
                  "submitted rows cannot share one table"))

        submitted_run = _write(os.path.join(d, "submitted.jsonl"), [{
            "item_id": item("submitted"),
            "outcome": "no_files_returned",
            "condition": "submitted",
            "adapter": "submitted:fixture",
            "environment_proven": False,
        }])
        submitted_res = pinned_results(
            submitted_run, gold_path="", prod_index_path="", boundary=b,
            artifacts="", api_scoring=API_SCORING_NONE)
        submitted_text = render_text(submitted_res)
        submitted_markdown = render_markdown(submitted_res)
        submitted_json = json.loads(render_json(submitted_res))
        check("a pure submitted run is visibly non-canonical in every "
              "non-legacy format",
              submitted_res.get("tier") == "submitted"
              and "submitted@?" in submitted_res["citation"]
              and "SUBMITTED TIER" in submitted_text
              and "SUBMITTED TIER" in submitted_markdown
              and any("SUBMITTED TIER" in note
                      for note in submitted_json["notes"]),
              submitted_text)
        check("...and its HEADING says so -- no submitted table ever leads "
              "with the canonical banner",
              submitted_text.startswith(
                  "SUBMITTED TIER RESULTS (non-canonical; "
                  "environment_proven: false)")
              and "CANONICAL RESULTS" not in submitted_text
              and submitted_markdown.startswith(
                  "### Submitted tier results (non-canonical; "
                  "environment_proven: false)")
              and "### Canonical results" not in submitted_markdown,
              submitted_text.split("\n")[0])
        proven_run = _write(os.path.join(d, "submitted-proven.jsonl"), [{
            "item_id": item("submitted"),
            "outcome": "no_files_returned",
            "condition": "submitted",
            "adapter": "submitted:fixture",
            "environment_proven": True,
        }])
        proven_res = pinned_results(
            proven_run, gold_path="", prod_index_path="", boundary=b,
            artifacts="", api_scoring=API_SCORING_NONE)
        proven_text = render_text(proven_res)
        check("the environment-proven stamp (amendment decision 7) is "
              "displayed beside the tier label in both states",
              submitted_res.get("environment_proven") == "false"
              and proven_res.get("environment_proven") == "true"
              and proven_text.startswith(
                  "SUBMITTED TIER RESULTS (non-canonical; "
                  "environment_proven: true)")
              and "environment_proven: true" in render_markdown(proven_res)
              and any("environment_proven: false" in note
                      for note in submitted_json["notes"])
              and any("environment_proven: true" in note
                      for note in json.loads(
                          render_json(proven_res))["notes"]),
              proven_text.split("\n")[0])
        check("markdown-legacy fails closed on the submitted tier rather "
              "than rendering an unlabelled payload",
              _raises(lambda: render_markdown_legacy(submitted_res),
                      "markdown-legacy cannot render the submitted tier"))

        res = pinned_results(run, gold_path=gold, prod_index_path=index,
                      test_quality_path=tq_path, boundary=b)
        check("ordinary study results do not acquire submitted-tier fields "
              "or notes",
              "tier" not in res
              and "SUBMITTED TIER" not in render_text(res)
              and "SUBMITTED TIER" not in render_json(res))
        had_bound_loader = hasattr(TQ, "load_bound_test_quality")
        old_bound_loader = getattr(TQ, "load_bound_test_quality", None)
        bound_calls = []

        def fake_bound_loader(run_path, summary_path=None, *,
                              reference_controls_reader=None):
            bound_calls.append((run_path, summary_path,
                                reference_controls_reader))
            with open(summary_path, encoding="utf-8") as fh:
                return json.load(fh)

        reader = object()
        TQ.load_bound_test_quality = fake_bound_loader
        try:
            pinned_results(run, gold_path=gold, prod_index_path=index,
                    test_quality_path=tq_path, boundary=b)
            pinned_results(run, gold_path=gold, prod_index_path=index,
                           test_quality_path=tq_path, boundary=b,
                           reference_controls_reader=reader)
        finally:
            if had_bound_loader:
                TQ.load_bound_test_quality = old_bound_loader
            else:
                del TQ.load_bound_test_quality
        check("canonical results consumes PR-3's binding-aware sidecar loader "
              "and forwards v2's installed reference-controls reader when "
              "supplied",
              bound_calls == [(run, tq_path, None),
                              (run, tq_path, reader)], str(bound_calls))

        # ----------------------------------------- population binding (#165)
        population = res["population"]
        check("a complete frozen workset exposes the approved population "
              "counts and exact empty missing set",
              population["status"] == "complete"
              and population["planned_n"] == 16
              and population["observed_n"] == 16
              and population["ladder_n"] == 11
              and population["classified_n"] == 11
              and population["missing_planned_ids"] == []
              and population["canonical_values_admitted"], str(population))

        missing_id = item("zz_missing")
        incomplete_scope = fixture_population_scope(
            [row["item_id"] for row in run_rows] + [missing_id],
            campaign_digest="cafe1234cafe1234",
            source="selftest incomplete frozen workset")
        incomplete_res = _results_impl(
            run, gold_path=gold, prod_index_path=index,
            test_quality_path=tq_path, boundary=b,
            validated_population_scope=incomplete_scope)
        incomplete_population = incomplete_res["population"]
        incomplete_rows = table_rows(incomplete_res)
        incomplete_text = render_text(incomplete_res)
        incomplete_markdown = render_markdown(incomplete_res)
        incomplete_json = json.loads(render_json(incomplete_res))
        check("an enumerable missing suffix exposes its exact ID and never "
              "turns that absence into a result or classification",
              incomplete_population["status"] == "incomplete"
              and incomplete_population["planned_n"] == 17
              and incomplete_population["observed_n"] == 16
              and incomplete_population["missing_planned_ids"] == [missing_id]
              and incomplete_res["n"] == 16
              and incomplete_res["ladder"]["denominator"] == 11
              and missing_id not in incomplete_res["mutation"]["per_item"]
              and missing_id not in incomplete_res["coverage"]["per_item"]
              and missing_id not in incomplete_res["api"]["per_item"],
              str(incomplete_population))
        check("population incompleteness withholds all thirteen canonical "
              "values while retaining counts and per-item measurements",
              len(incomplete_rows) == 13
              and all(row.get("withheld") and row.get("number") is None
                      and "population incomplete" in row.get("reason", "")
                      for row in incomplete_rows)
              and all(row["rate"] is None
                      for row in incomplete_res["ladder"]["rows"])
              and incomplete_res["mutation"]["values"] is None
              and incomplete_res["coverage"]["values"] is None
              and incomplete_res["api"]["values"] is None
              and set(incomplete_res["mutation"]["per_item"])
              == {item("p1"), item("p2")}
              and set(incomplete_res["coverage"]["per_item"])
              == {item("p1"), item("p2")}, str(incomplete_rows))
        check("all supported non-legacy results formats disclose the exact "
              "population fields and missing ID",
              "POPULATION INCOMPLETE" in incomplete_text
              and "planned_n" in incomplete_text
              and missing_id in incomplete_text
              and "missing_planned_ids" in incomplete_markdown
              and missing_id in incomplete_markdown
              and incomplete_json["population"] == incomplete_population
              and incomplete_json["table"] == incomplete_rows,
              incomplete_text)
        check("incomplete pinned evidence is refused by markdown-legacy",
              _raises(lambda: render_markdown_legacy(incomplete_res),
                      "pinned population is incomplete"))

        # Section 9: a missing item the owner ratified as infrastructure (an
        # attempt that created its trajectory and finished without a row).
        note = "operator drain killed the attempt; owner-ratified 2026-09-27"
        exclusions = os.path.join(d, "infrastructure-exclusions.json")
        with open(run, "rb") as fh:
            run_digest = hashlib.sha256(fh.read()).hexdigest()
        killed = {"finished": {"exit_code": -15, "rows": 0},
                  "trajectories": [os.path.join(d, "trajectories", "c2", "x")],
                  "row_file": "0 bytes of whitespace"}

        def write_exclusions(ids, evidence=killed, candidate_sha=run_digest):
            document = {"cell": "selftest", "written_by": "run_agent_cells.py finalize",
                        "candidate": {"path": run, "sha256": candidate_sha},
                        "exclusions": [dict({"item_id": i, "note": note},
                                            **({} if evidence is None
                                               else {"evidence": evidence}))
                                       for i in ids]}
            with open(exclusions, "w", encoding="utf-8") as fh:
                json.dump(document, fh)
            with open(exclusions, "rb") as fh:
                return hashlib.sha256(fh.read()).hexdigest()

        def ratified_run(scope=incomplete_scope):
            return _results_impl(
                run, gold_path=gold, prod_index_path=index,
                test_quality_path=tq_path, boundary=b,
                validated_population_scope=scope,
                infrastructure_exclusions_path=exclusions)

        exclusions_sha = write_exclusions([missing_id])
        ratified_res = ratified_run()
        ratified = ratified_res["population"]
        ratified_markdown = render_markdown(ratified_res)
        ratified_json = json.loads(render_json(ratified_res))
        check("a ratified infrastructure exclusion without a row admits the "
              "canonical values over the observed items and stays disclosed "
              "as a missing planned ID",
              ratified["status"] == "complete_with_ratified_exclusions"
              and ratified["planned_n"] == 17 and ratified["observed_n"] == 16
              and ratified["ladder_n"] == 11
              and ratified["missing_planned_ids"] == [missing_id]
              and ratified["complete"] is False
              and ratified["canonical_values_admitted"]
              and ratified["ratified_infrastructure_exclusions"]
              == [{"item_id": missing_id, "note": note}]
              and [row.get("number") for row in table_rows(ratified_res)]
              == [row.get("number") for row in table_rows(res)]
              and missing_id not in ratified_res["mutation"]["per_item"],
              str(ratified))
        check("the ratified exclusion is disclosed in markdown and json with "
              "the exclusions file's digest, and markdown-legacy still refuses",
              "owner-ratified" in ratified_markdown
              and missing_id in ratified_markdown and note in ratified_markdown
              and exclusions in ratified_markdown
              and exclusions_sha in ratified_markdown
              and ratified_json["population"] == ratified
              and ratified_json["infrastructure_exclusions"]
              == {"path": exclusions, "sha256": exclusions_sha,
                  "cell": "selftest", "run_sha256": run_digest}
              and _raises(lambda: render_markdown_legacy(ratified_res),
                          "ratified infrastructure exclusions"),
              ratified_markdown)
        write_exclusions([missing_id], evidence=None)
        check("an exclusion without finalize's evidence is refused",
              _raises(ratified_run, "lack finalize's evidence"))
        for label, evidence in (
                ("a clean exit", dict(killed, finished={"exit_code": 0, "rows": 0})),
                ("a row", dict(killed, finished={"exit_code": -15, "rows": 1})),
                ("no trajectory", dict(killed, trajectories=[]))):
            write_exclusions([missing_id], evidence=evidence)
            check(f"an exclusion whose evidence shows {label} is refused",
                  _raises(ratified_run, "lack finalize's evidence"))
        write_exclusions([missing_id], candidate_sha="0" * 64)
        check("an exclusions file finalize wrote for another run is refused",
              _raises(ratified_run, "is not the finalize record for this --run"))
        write_exclusions([run_rows[0]["item_id"]])
        check("an item with a row cannot be excluded as ratified "
              "infrastructure",
              _raises(ratified_run, "are not missing planned IDs"))
        two_missing = fixture_population_scope(
            [row["item_id"] for row in run_rows] + [missing_id, item("zz_other")],
            campaign_digest="cafe1234cafe1234",
            source="selftest incomplete frozen workset")
        write_exclusions([missing_id])
        partial = ratified_run(two_missing)
        check("an unratified missing item still withholds every canonical "
              "value",
              partial["population"]["status"] == "incomplete"
              and not partial["population"]["canonical_values_admitted"]
              and all(row.get("number") is None for row in table_rows(partial)),
              str(partial["population"]))

        # Benchmark 2.0's population (BENCHMARK_V2_SPEC.md section 6), with a
        # synthetic list: protocol 9001 stands for a 2.0 protocol, and one
        # pass with test quality (p1) and one assertion failure leave the
        # metrics while their rows stay in the run file.
        from . import population as population_module
        v2_list = os.path.join(d, "benchmark_2.0_population.yml")

        def write_v2_list(excluded):
            with open(v2_list, "w", encoding="utf-8") as fh:
                fh.write(
                    "schema: r2t.benchmark-population/1\n"
                    "benchmark_version: \"2.0\"\n"
                    "census: selftest census\n"
                    "protocols: [9001]\n"
                    "excluded:\n" + "".join(
                        f"  - instance_id: {iid}\n    reason: {reason}\n"
                        for iid, reason in excluded))

        write_v2_list([(item("p1"), "census_pass"),
                       (item("i_failed"), "zero_body")])
        v2_rows = [dict(r, protocol_version=9001) for r in run_rows]
        v2_run = _write(os.path.join(d, "v2-sweep.jsonl"), v2_rows)
        v2_tq = sidecar_for(v2_run, sidecar(TQ_ITEMS), "tq-v2.json")
        v2_scope = fixture_population_scope(
            [r["item_id"] for r in v2_rows], campaign_digest="cafe1234cafe1234")
        short_run = _write(os.path.join(d, "v2-short.jsonl"), [
            r for r in v2_rows if r["item_id"] != item("i_failed")])
        mixed_run = _write(os.path.join(d, "v2-mixed.jsonl"),
                           v2_rows[:-1] + run_rows[-1:])
        listed_path = population_module.BENCHMARK_POPULATION
        population_module.BENCHMARK_POPULATION = v2_list
        try:
            v2_res = _results_impl(
                v2_run, gold_path=gold, prod_index_path=index,
                test_quality_path=v2_tq, boundary=b,
                validated_population_scope=v2_scope)
            same_res = pinned_results(
                run, gold_path=gold, prod_index_path=index,
                test_quality_path=tq_path, boundary=b)
            short_res = _results_impl(
                short_run, gold_path=gold, prod_index_path=index, boundary=b,
                validated_population_scope=v2_scope)
            mixed_refused = _raises(lambda: _results_impl(
                mixed_run, gold_path=gold, prod_index_path=index, boundary=b,
                validated_population_scope=v2_scope),
                "a 2.0 row is never pooled")
            write_v2_list([(item("p1"), "flaky")])
            malformed_refused = _raises(lambda: _results_impl(
                v2_run, gold_path=gold, prod_index_path=index,
                test_quality_path=v2_tq, boundary=b,
                validated_population_scope=v2_scope),
                "is not a r2t.benchmark-population/1 document")
        finally:
            population_module.BENCHMARK_POPULATION = listed_path
        v2_population = v2_res["population"]
        v2_text = render_text(v2_res)
        v2_markdown = render_markdown(v2_res)
        v2_json = json.loads(render_json(v2_res))
        check("a 2.0 run's population and every count leave out its "
              "excluded instances, test quality included",
              v2_population["status"] == "complete"
              and v2_population["planned_n"] == 14
              and v2_population["observed_n"] == 14
              and v2_population["ladder_n"] == 9
              and v2_population["classified_n"] == 9
              and v2_population["missing_planned_ids"] == []
              and v2_res["n"] == 14 and v2_res["n_passed"] == 1
              and set(v2_res["mutation"]["per_item"]) == {item("p2")}
              and v2_res["mutation"]["values"]["recall"] == 0.5
              and not v2_res["mutation"]["macro_mismatch"]
              and set(v2_res["coverage"]["per_item"]) == {item("p2")}
              and res["mutation"]["values"]["recall"] == 0.75,
              str(v2_population))
        check("every non-legacy format discloses the 2.0 excluded count and "
              "instances, and markdown-legacy refuses",
              v2_population["population_exclusions"] == {
                  "benchmark_version": "2.0", "path": v2_list, "count": 2,
                  "excluded": [
                      {"item_id": item("i_failed"), "reason": "zero_body"},
                      {"item_id": item("p1"), "reason": "census_pass"}]}
              and "2.0 excluded" in v2_text
              and "BENCHMARK 2.0 POPULATION" in v2_text
              and "2 instance(s) outside benchmark 2.0's population"
                  in v2_markdown
              and v2_json["population"] == v2_population
              and _raises(lambda: render_markdown_legacy(v2_res),
                          "benchmark 2.0 population"), v2_text)
        check("rows of other protocols read exactly as before while the 2.0 "
              "list exists",
              render_text(same_res) == render_text(res)
              and "population_exclusions" not in same_res["population"])
        check("an excluded instance without a row is not a missing planned "
              "ID of the 2.0 population",
              short_res["population"]["status"] == "complete"
              and short_res["population"]["planned_n"] == 14
              and short_res["population"]["observed_n"] == 14
              and short_res["population"]["population_exclusions"]["count"]
              == 2, str(short_res["population"]))
        check("a run mixing 2.0 and other rows, and a malformed 2.0 list, "
              "are refused", mixed_refused and malformed_refused)
        check("n_rows_in_file stays the file's row count, and the excluded "
              "rows do not read as items re-run in place",
              v2_res["n_rows_in_file"] == len(v2_rows) == 16
              and v2_res["n_rows_outside_population"] == 2
              and "row(s) in the file" not in v2_text,
              str(v2_res["n_rows_in_file"]))

        explicit_rows = [
            {"item_id": item("explicit_a"), "outcome": "failed"},
            {"item_id": item("explicit_b"), "outcome": "passed"},
        ]
        explicit_run = _write(
            os.path.join(d, "explicit-run.jsonl"), explicit_rows)
        explicit_release = _write(
            os.path.join(d, "explicit-release.jsonl"),
            [{"item_id": row["item_id"]} for row in explicit_rows])
        explicit_res = results(
            explicit_run, gold_path="", prod_index_path="", boundary=b,
            artifacts="", api_scoring=API_SCORING_NONE,
            release_path=explicit_release)
        check("an explicit validated release is the enumerable planned "
              "population rather than the rows that happen to exist",
              explicit_res["population"]["status"] == "complete"
              and explicit_res["population"]["planned_n"] == 2
              and explicit_res["population"]["observed_n"] == 2
              and explicit_res["population"]["source"]
              == f"explicit release {explicit_release}"
              and explicit_res["population"]["missing_planned_ids"] == [],
              str(explicit_res["population"]))

        malformed_release = _write(
            os.path.join(d, "malformed-release.jsonl"), [[]])
        check("an explicit release containing a non-object JSON value is a "
              "named population refusal rather than a traceback",
              _raises(lambda: results(
                  explicit_run, gold_path="", prod_index_path="", boundary=b,
                  artifacts="", api_scoring=API_SCORING_NONE,
                  release_path=malformed_release),
                  "contains a JSON value that is not an item object"))
        check("an unreadable explicit release is a named terminal population "
              "refusal rather than a traceback or lower-source fallback",
              _raises(lambda: results(
                  explicit_run, gold_path="", prod_index_path="", boundary=b,
                  artifacts="", api_scoring=API_SCORING_NONE,
                  release_path=os.path.join(d, "missing-release.jsonl")),
                  "no items file at"))

        from . import result_ledger as population_ledger
        invalid_receipt_path = (
            explicit_run + population_ledger.RECEIPT_SUFFIX)
        with open(invalid_receipt_path, "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        try:
            invalid_receipt_refused = _raises(
                lambda: results(
                    explicit_run, gold_path="", prod_index_path="",
                    boundary=b, artifacts="",
                    api_scoring=API_SCORING_NONE,
                    release_path=explicit_release),
                "cannot verify applicable result receipt")
        finally:
            os.unlink(invalid_receipt_path)
        check("an invalid adjacent receipt is terminal even when an explicit "
              "release could otherwise enumerate the rows",
              invalid_receipt_refused)

        unpinned_res = results(
            explicit_run, gold_path="", prod_index_path="", boundary=b,
            artifacts="", api_scoring=API_SCORING_NONE)
        unpinned_rows = table_rows(unpinned_res)
        unpinned_json = json.loads(render_json(unpinned_res))
        check("a genuinely unstamped development run renders as unpinned with "
              "no observed-only canonical arithmetic",
              unpinned_res["population"]["status"] == "unpinned"
              and unpinned_res["population"]["planned_n"] is None
              and unpinned_res["population"]["observed_n"] == 2
              and unpinned_res["population"]["missing_planned_ids"] is None
              and len(unpinned_rows) == 13
              and all(row.get("withheld") and row.get("number") is None
                      for row in unpinned_rows)
              and "UNPINNED DEVELOPMENT OUTPUT" in render_text(unpinned_res)
              and "Non-canonical results (unpinned" in
                  render_markdown(unpinned_res)
              and unpinned_json["population"]["status"] == "unpinned",
              render_text(unpinned_res))
        check("markdown-legacy refuses an unpinned development population",
              _raises(lambda: render_markdown_legacy(unpinned_res),
                      "population status 'unpinned'"))

        foreign_release = _write(
            os.path.join(d, "foreign-release.jsonl"),
            [{"item_id": explicit_rows[0]["item_id"]}])
        check("an observed item outside the explicit planned workset is a "
              "named foreign-identity refusal",
              _raises(lambda: results(
                  explicit_run, gold_path="", prod_index_path="", boundary=b,
                  artifacts="", api_scoring=API_SCORING_NONE,
                  release_path=foreign_release), "foreign item ID"))

        campaign_release = _write(
            os.path.join(d, "campaign-release.jsonl"),
            [{"item_id": row["item_id"]} for row in run_rows])
        check("an explicit release cannot replace an unresolved campaign "
              "workset even when it contains the observed IDs",
              _raises(lambda: results(
                  run, gold_path=gold, prod_index_path=index,
                  test_quality_path=tq_path, boundary=b,
                  release_path=campaign_release),
                  "cannot reconcile an explicit release with campaign-stamped"))
        check("campaign-stamped rows without a validated workset or checkpoint "
              "refuse rather than becoming unpinned",
              _raises(lambda: results(
                  run, gold_path=gold, prod_index_path=index,
                  test_quality_path=tq_path, boundary=b),
                  "cannot resolve campaign 'cafe1234cafe1234'"))

        from . import campaign as campaign_module
        from . import population as population_module
        from . import result_ledger
        from ..data import subsets
        from ..toolkit.subset_writer import write_subset

        def population_refuses(fn, needle: str) -> bool:
            try:
                fn()
            except population_module.PopulationRefusal as exc:
                return needle in str(exc)
            except Exception:                                  # noqa: BLE001
                return False
            return False

        mixed_identity_rows = [
            {"item_id": item("mixed_a"), "campaign_digest": "a" * 16},
            {"item_id": item("mixed_b"), "campaign_digest": "b" * 16},
        ]
        check("mixed and malformed asserted identities are named refusals",
              population_refuses(
                  lambda: population_module.resolve(
                      mixed_identity_rows,
                      os.path.join(d, "mixed-identities.jsonl")),
                  "mixed 'campaign_digest' identities")
              and population_refuses(
                  lambda: population_module.resolve(
                      [{"item_id": item("invalid"),
                        "campaign_digest": ["not", "a", "digest"]}],
                      os.path.join(d, "invalid-identity.jsonl")),
                  "invalid non-scalar 'campaign_digest'"))
        check("Boolean shard identities cannot collapse into equal-looking "
              "integer identities",
              population_refuses(
                  lambda: population_module.resolve(
                      [{"item_id": item("integer-shard"),
                        "campaign_digest": "a" * 16,
                        "shard": 0, "of": 1},
                       {"item_id": item("boolean-shard"),
                        "campaign_digest": "a" * 16,
                        "shard": False, "of": 1}],
                      os.path.join(d, "boolean-shard.jsonl")),
                  "shard value(s) outside"))

        incompatible_scope = fixture_population_scope(
            [mixed_identity_rows[0]["item_id"]],
            campaign_digest="b" * 16)
        check("an asserted campaign identity must agree with the validated "
              "frozen workset identity before that source is accepted",
              population_refuses(
                  lambda: population_module.resolve(
                      [mixed_identity_rows[0]],
                      os.path.join(d, "incompatible-scope.jsonl"),
                      validated_scope=incompatible_scope),
                  "row-stamped campaign_digest 'aaaaaaaaaaaaaaaa' "
                  "disagrees"))

        subset_root = os.path.join(d, "subset-release")
        os.makedirs(subset_root)
        subset_items = [
            ("t/features/alpha/a.feature:1", "alpha"),
            ("t/features/beta/b.feature:2", "beta"),
        ]
        subset_pool, subset_gold = subsets._fixture(
            subset_root, subset_items)
        subset = subsets.sample(
            subset_pool, subset_gold, n=2, seed=20260827)
        subset_path, _subset_sidecar = write_subset(
            subset, os.path.join(subset_root, "eval2.jsonl"))
        subset_identity = subsets.identify_for_inference(subset_path)
        subset_row = {
            "item_id": subset_items[0][0], "outcome": "failed",
            "subset_id": subset_identity["subset_id"],
            "subset_digest": subset_identity["subset_digest"],
        }
        subset_population = population_module.resolve(
            [subset_row], os.path.join(d, "subset-run.jsonl"),
            release_roots=[subset_root])
        check("matching row-stamped subset bytes enumerate the planned "
              "population and its exact missing IDs",
              subset_population["status"] == "incomplete"
              and subset_population["planned_n"] == 2
              and subset_population["observed_n"] == 1
              and subset_population["missing_planned_ids"]
              == [subset_items[1][0]]
              and subset_population["source"]
              == f"row-stamped subset {subset_path}",
              str(subset_population))

        malformed_subset_path = _write(
            os.path.join(subset_root, "eval-malformed.jsonl"),
            [{"item_id": subset_items[0][0]}])
        with open(malformed_subset_path[:-len(".jsonl")]
                  + ".provenance.json", "w", encoding="utf-8") as fh:
            json.dump([], fh)
        check("a non-object subset provenance document becomes a named "
              "population refusal rather than leaking a type error",
              population_refuses(
                  lambda: population_module.resolve(
                      [], os.path.join(d, "malformed-provenance-run.jsonl"),
                      explicit_release=malformed_subset_path),
                  "cannot validate planned workset provenance"))

        scoped_subset_ids = tuple(item_id for item_id, _label in subset_items)
        scoped_subset = population_module.frozen_scope(
            item_ids=scoped_subset_ids,
            workset={
                "item_count": len(scoped_subset_ids),
                "ordered_item_ids_digest":
                    result_ledger.ordered_item_ids_digest(scoped_subset_ids),
            }, campaign_digest="e" * 16,
            subset_id=subset_identity["subset_id"],
            subset_digest=subset_identity["subset_digest"],
            shard_rule=campaign_module.SHARD_RULE, shard_count=1,
            source="validated publication workset")
        absent_subset_root = os.path.join(d, "no-local-subset-copy")
        os.makedirs(absent_subset_root)
        scoped_subset_population = population_module.resolve(
            [{**subset_row, "campaign_digest": "e" * 16,
              "shard": 0, "of": 1}],
            os.path.join(d, "scoped-subset-run.jsonl"),
            validated_scope=scoped_subset,
            release_roots=[absent_subset_root])
        check("a validated frozen scope reconciles its row-stamped subset "
              "identity without requiring a second repository-local copy",
              scoped_subset_population["status"] == "incomplete"
              and scoped_subset_population["source"]
              == "validated publication workset"
              and scoped_subset_population["planned_n"] == 2
              and scoped_subset_population["missing_planned_ids"]
              == [subset_items[1][0]],
              str(scoped_subset_population))
        import types
        mismatched_publication_role = types.SimpleNamespace(
            item_ids=scoped_subset_ids,
            workset=scoped_subset["workset"],
            release_reference={"path": subset_path},
            substrate={"effective_run_stamp": {
                "subset_id": subset_identity["subset_id"],
                "subset_digest": "0" * 16,
            }},
            agent_control_inputs={"campaign": {}},
        )
        check("a publication frozen workset cannot carry a subset pair over "
              "different exact release bytes",
              population_refuses(
                  lambda: population_module.publication_scope(
                      mismatched_publication_role),
                  "disagrees with its exact release bytes"))
        unresolvable_subset = dict(subset_row, subset_digest="0" * 16)
        check("an asserted subset identity that cannot resolve to matching "
              "published bytes refuses instead of falling through",
              population_refuses(
                  lambda: population_module.resolve(
                      [unresolvable_subset],
                      os.path.join(d, "bad-subset-run.jsonl"),
                      release_roots=[subset_root]),
                  "matching validated bytes"))

        campaign_subset_run = os.path.join(d, "campaign-subset.jsonl")
        with open(campaign_subset_run + result_ledger.CHECKPOINT_SUFFIX,
                  "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        real_verify_subset_checkpoint = result_ledger.verify_checkpoint

        def verified_subset_checkpoint(_path):
            ids = tuple(item_id for item_id, _label in subset_items)
            return {
                "artifact_kind": "run_shard",
                "workset": {
                    "item_count": len(ids),
                    "ordered_item_ids_digest":
                        result_ledger.ordered_item_ids_digest(ids),
                },
                "population_identity": {
                    "campaign_digest": "d" * 16,
                    "subset_id": subset_identity["subset_id"],
                    "subset_digest": subset_identity["subset_digest"],
                    "shard_rule": campaign_module.SHARD_RULE,
                    "shard_count": 1,
                },
                "release_path": os.path.abspath(subset_path),
                "verified": True,
            }

        try:
            result_ledger.verify_checkpoint = verified_subset_checkpoint
            campaign_subset_population = population_module.resolve(
                [{**subset_row, "campaign_digest": "d" * 16,
                  "shard": 0, "of": 1}], campaign_subset_run,
                release_roots=[subset_root])
        finally:
            result_ledger.verify_checkpoint = real_verify_subset_checkpoint
        check("matching row-stamped subset bytes outrank a count-only "
              "checkpoint when its already-validated campaign workset is "
              "exactly the same ordered set",
              campaign_subset_population["status"] == "incomplete"
              and campaign_subset_population["source"]
              == f"row-stamped subset {subset_path}"
              and campaign_subset_population["planned_n"] == 2
              and campaign_subset_population["missing_planned_ids"]
              == [subset_items[1][0]],
              str(campaign_subset_population))

        zero_checkpoint_run = _write(
            os.path.join(d, "zero-row-checkpoint.jsonl"), [])
        with open(zero_checkpoint_run + result_ledger.CHECKPOINT_SUFFIX,
                  "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        zero_ids = tuple(item_id for item_id, _label in subset_items)
        zero_workset = {
            "item_count": len(zero_ids),
            "ordered_item_ids_digest":
                result_ledger.ordered_item_ids_digest(zero_ids),
        }
        incompatible_zero_scope = population_module.frozen_scope(
            item_ids=zero_ids, workset=zero_workset,
            campaign_digest="e" * 16,
            subset_id=subset_identity["subset_id"],
            subset_digest=subset_identity["subset_digest"],
            shard_rule=campaign_module.SHARD_RULE, shard_count=1,
            source="incompatible zero-row frozen workset")
        unlabeled_zero_release = _write(
            os.path.join(d, "zero-row-explicit.jsonl"),
            [{"item_id": item_id} for item_id in zero_ids])

        def verified_zero_checkpoint(_path):
            return {
                "artifact_kind": "run_shard",
                "workset": zero_workset,
                "population_identity": {
                    "campaign_digest": "d" * 16,
                    "subset_id": subset_identity["subset_id"],
                    "subset_digest": subset_identity["subset_digest"],
                    "shard_rule": campaign_module.SHARD_RULE,
                    "shard_count": 1,
                },
                "release_path": os.path.abspath(subset_path),
                "verified": True,
            }

        real_verify_zero_checkpoint = result_ledger.verify_checkpoint
        try:
            result_ledger.verify_checkpoint = verified_zero_checkpoint
            zero_scope_refused = population_refuses(
                lambda: population_module.resolve(
                    [], zero_checkpoint_run,
                    validated_scope=incompatible_zero_scope),
                "checkpoint campaign_digest")
            zero_release_refused = population_refuses(
                lambda: population_module.resolve(
                    [], zero_checkpoint_run,
                    explicit_release=unlabeled_zero_release),
                "applicable checkpoint asserts")
        finally:
            result_ledger.verify_checkpoint = real_verify_zero_checkpoint
        check("a zero-row checkpoint still reconciles its verified campaign "
              "and subset identities with frozen and explicit sources",
              zero_scope_refused and zero_release_refused)

        shard_results = []
        for rule_index, rule in enumerate((
                campaign_module.SHARD_RULE,
                campaign_module.POSITIONAL_SHARD_RULE)):
            shard_id = f"t/features/shards/r{rule_index}.feature:1"
            digest = f"{rule_index + 1:x}" * 16
            scope = fixture_population_scope(
                [shard_id], campaign_digest=digest, shard_rule=rule,
                shard_count=4, source=f"validated {rule} workset")
            shard_results.append(population_module.resolve(
                [{"item_id": shard_id, "outcome": "passed",
                  "campaign_digest": digest, "shard": rule_index, "of": 4}],
                os.path.join(d, f"shard-rule-{rule_index}.jsonl"),
                validated_scope=scope))
        check("reporting consumes exact worksets validated under both admitted "
              "shard rules without selecting or inferring a rule",
              all(value["status"] == "complete"
                  and value["planned_n"] == 1
                  and value["missing_planned_ids"] == []
                  for value in shard_results), str(shard_results))

        checkpoint_run = _write(
            os.path.join(d, "checkpoint-run.jsonl"),
            [{"item_id": item("checkpoint"), "outcome": "failed"}])
        checkpoint_path = checkpoint_run + result_ledger.CHECKPOINT_SUFFIX
        with open(checkpoint_path, "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        real_verify_checkpoint = result_ledger.verify_checkpoint
        checkpoint_count = [2]

        def verified_checkpoint(_path):
            return {
                "artifact_kind": "run_shard",
                "workset": {
                    "item_count": checkpoint_count[0],
                    "ordered_item_ids_digest": "0" * 64,
                },
                "population_identity": {
                    "campaign_digest": "f" * 16,
                    "subset_id": None, "subset_digest": None,
                    "shard_rule": campaign_module.SHARD_RULE,
                    "shard_count": 1,
                },
                "release_path": os.path.abspath(checkpoint_run),
                "verified": True,
            }

        try:
            result_ledger.verify_checkpoint = verified_checkpoint
            count_only_res = results(
                checkpoint_run, gold_path="", prod_index_path="", boundary=b,
                artifacts="", api_scoring=API_SCORING_NONE)
            checkpoint_count[0] = 1
            equal_count_res = results(
                checkpoint_run, gold_path="", prod_index_path="", boundary=b,
                artifacts="", api_scoring=API_SCORING_NONE)

            def invalid_checkpoint(_path):
                raise result_ledger.ResultLedgerRefused(
                    "REFUSED: invalid checkpoint fixture")

            result_ledger.verify_checkpoint = invalid_checkpoint
            malformed_checkpoint_refused = _raises(
                lambda: results(
                    checkpoint_run, gold_path="", prod_index_path="",
                    boundary=b, artifacts="",
                    api_scoring=API_SCORING_NONE),
                "cannot verify applicable checkpoint")
        finally:
            result_ledger.verify_checkpoint = real_verify_checkpoint
        check("a verified checkpoint supplies count-only planned_n and no "
              "invented missing IDs or canonical values",
              count_only_res["population"]["status"] == "count_only"
              and count_only_res["population"]["planned_n"] == 2
              and count_only_res["population"]["observed_n"] == 1
              and count_only_res["population"]["missing_planned_ids"] is None
              and all(row.get("withheld") for row in
                      table_rows(count_only_res)),
              str(count_only_res["population"]))
        check("count equality on a checkpoint still cannot prove exact set "
              "equality, and a malformed applicable checkpoint is terminal",
              equal_count_res["population"]["status"] == "count_only"
              and not equal_count_res["population"][
                  "canonical_values_admitted"]
              and malformed_checkpoint_refused,
              str(equal_count_res["population"]))

        from ..core.boundary import load_boundary
        real_checkpoint_fixture = result_ledger._build_selftest_fixture(
            os.path.join(d, "verified-checkpoint"))
        os.unlink(real_checkpoint_fixture["receipt_path"])
        real_checkpoint_res = results(
            real_checkpoint_fixture["result_path"], gold_path="",
            prod_index_path="",
            boundary=load_boundary(os.path.join(
                real_checkpoint_fixture["root"], "config",
                "boundary_python_docx.yml")),
            artifacts="", api_scoring=API_SCORING_NONE)
        real_checkpoint_json = json.loads(render_json(real_checkpoint_res))
        real_checkpoint_text = render_text(real_checkpoint_res)
        check("a real verified ledger checkpoint reaches the count-only "
              "population renderer without inventing exact completeness",
              real_checkpoint_res["population"]["status"] == "count_only"
              and real_checkpoint_res["population"]["planned_n"] == 1
              and real_checkpoint_res["population"]["observed_n"] == 1
              and real_checkpoint_res["population"][
                  "missing_planned_ids"] is None
              and not real_checkpoint_res["population"][
                  "canonical_values_admitted"]
              and real_checkpoint_json["population"][
                  "missing_planned_ids"] is None
              and "COUNT-ONLY PINNED POPULATION" in real_checkpoint_text
              and "missing_planned_ids = unavailable" in
                  real_checkpoint_text,
              real_checkpoint_text)

        lad = {r["key"]: r for r in res["ladder"]["rows"]}

        # ------------------------------------------------------- the ladder
        check("the ladder has exactly the six rungs, in pipeline order, "
              "generation first",
              [r["key"] for r in res["ladder"]["rows"]]
              == [k for k, _l, _o in LADDER]
              and res["ladder"]["rows"][0]["key"] == "generation_failure",
              str(list(lad)))
        check("generation failure = ran to completion, wrote no test code",
              lad["generation_failure"]["count"] == 1,
              str(lad["generation_failure"]))
        check("compilation MERGES the syntax and the wiring failure",
              lad["compilation_failure"]["count"] == 2)
        check("the syntax/wiring split survives in the detail dict",
              lad["compilation_failure"]["outcomes"]
              == {"parse_or_compile_error": 1, "container_error": 1},
              str(lad["compilation_failure"]["outcomes"]))
        check("the split is NOT a table row",
              [r["label"] for r in table_rows(res)].count("compilation "
                                                          "failure") == 1
              and not any("container_error" in r["label"]
                          for r in table_rows(res)))
        check("binding = undefined_steps + pending",
              lad["binding_failure"]["count"] == 2)
        check("execution = solution_error + no_scenario_ran + timeout",
              lad["execution_failure"]["count"] == 3)
        check("assertion = failed", lad["assertion_failure"]["count"] == 1)
        check("pass rate = passed", lad["pass_rate"]["count"] == 2)

        # The shared fold deliberately preserves skipped-step executions as
        # not_passed (NEW_STACK_SPEC); the approved taxonomy assigns that
        # existing outcome to execution, not an invented failed assertion.
        from .harness import record_outcome
        skipped_outcome = record_outcome({"steps": [{"result": "skipped"}]})
        skipped_rows = {
            item("skipped_setup"): row("skipped_setup", skipped_outcome, None),
            item("known_pass"): row("known_pass", "passed", None),
        }
        skipped_lad = ladder(skipped_rows)
        skipped_rungs = {r["key"]: r for r in skipped_lad["rows"]}
        check("the native skipped-step outcome is an execution failure, "
              "with every complete observation still in the denominator",
              skipped_outcome == "not_passed"
              and classify_row(skipped_rows[item("skipped_setup")])
                  == ("execution_failure", None)
              and skipped_lad["denominator"] == 2
              and skipped_lad["classified_n"] == 2
              and skipped_lad["sums_to_denominator"]
              and not skipped_lad["withheld"]
              and skipped_rungs["execution_failure"]["count"] == 1
              and skipped_rungs["assertion_failure"]["count"] == 0
              and skipped_rungs["pass_rate"]["count"] == 1
              and skipped_rungs["pass_rate"]["rate"] == 0.5,
              str(skipped_lad))
        still_unknown = ladder({
            **skipped_rows,
            item("future_terminal"): row("future_terminal", "future_terminal", None),
        })
        check("classifying not_passed does not admit a different unknown "
              "outcome or shrink the denominator to classified rows",
              still_unknown["denominator"] == 3
              and still_unknown["classified_n"] == 2
              and still_unknown["unknown"]["outcomes"] == {"future_terminal": 1}
              and still_unknown["withheld"]
              and all(r["rate"] is None for r in still_unknown["rows"]),
              str(still_unknown))

        exc = res["ladder"]["excluded"]
        check("a harness failure is infrastructure, never a rung",
              exc[INFRASTRUCTURE]["outcomes"].get("harness_error") == 1
              and exc[INFRASTRUCTURE]["outcomes"].get("scenario_not_found")
              == 1, str(exc[INFRASTRUCTURE]))
        check("a driver error on a no-files row is infrastructure, NOT a "
              "generation failure",
              exc[INFRASTRUCTURE]["count"] == 4
              and exc[INFRASTRUCTURE]["markers"] == {
                  "harness_error": 1, "scenario_not_found": 1,
                  "driver_error": 1, "agent_stats.run_errors": 1,
              }, str(exc[INFRASTRUCTURE]))
        check("the excluded rows are named by item, so they can be re-run",
              exc[INFRASTRUCTURE]["items"]
              == [item("i_driver"), item("i_harness"), item("i_notfound"),
                  item("i_runerr")],
              str(exc[INFRASTRUCTURE]["items"]))
        check("a deliberate non-rung is named, not absorbed",
              exc[UNCLASSIFIED]["outcomes"] == {"no_writable_files": 1},
              str(exc[UNCLASSIFIED]))
        check("the excluded rows leave the denominator, and it is stated",
              res["ladder"]["denominator"] == 11 and res["n"] == 16
              and res["ladder"]["reduced"], str(res["ladder"]["denominator"]))
        check("every remaining instance is on exactly one rung",
              res["ladder"]["sums_to_denominator"])
        check("the rungs are over the stated denominator",
              abs(lad["pass_rate"]["rate"] - 2 / 11) < 1e-12)
        check("the reduced denominator is printed where a reader will see it",
              "ladder_n" in render_text(res) and "11" in render_text(res))

        # Issue #202: a primary-envelope timeout can arrive in either of the
        # candidate-presence shapes the run reader supports.  The harness's
        # authoritative `failed` wins over driver metadata in both shapes.
        candidate_timeouts = [
            row("candidate_files", "failed", None,
                produced_files=[{"file_path": "tests/a.py", "code": "a"}],
                metadata={"driver_error": "timeout", "returncode": -1,
                          "termination": {"reason": "envelope_expired"}}),
            row("candidate_count", "failed", None, n_files=1,
                metadata={"driver_error": "timeout", "returncode": -1}),
        ]
        timeout_lad = ladder({r["item_id"]: r for r in candidate_timeouts})
        timeout_rows = {r["key"]: r for r in timeout_lad["rows"]}
        check("candidate-producing timeout rows stay assertion failures in "
              "both observed candidate-evidence shapes",
              all(classify_row(r) == ("assertion_failure", None)
                  for r in candidate_timeouts)
              and timeout_rows["assertion_failure"]["count"] == 2
              and timeout_lad["denominator"] == 2
              and not timeout_lad["withheld"], str(timeout_lad))

        consumed = dict(outcome="fixture_consumed", n_files=1,
                        fixture_consumed=["tests/Resources/dummyFile/app_icon.png"])
        consumed_lad = ladder({"c": consumed, "p": dict(outcome="passed", n_files=1)})
        check("a generation row ending fixture_consumed is infrastructure, out of the "
              "denominator, and does not withhold the ladder (resource reset spec rule 5)",
              classify_row(consumed) == (INFRASTRUCTURE, "fixture_consumed")
              and consumed_lad["denominator"] == 1
              and consumed_lad["excluded"][INFRASTRUCTURE]["items"] == ["c"]
              and not consumed_lad["withheld"], str(consumed_lad))

        adapter_refusal = dict(outcome="no_files_returned", n_files=0,
                               metadata={"adapter_error": "ViewRefused: source mount refused"})
        check("a pre-driver adapter refusal is infrastructure, not a candidate failure",
              classify_row(adapter_refusal) == (INFRASTRUCTURE, "adapter_error"))
        check("adapter error metadata does not override a produced candidate outcome",
              classify_row(dict(adapter_refusal, outcome="passed", n_files=1))[0] != INFRASTRUCTURE)
        pre_candidate = row(
            "pre_candidate_driver", "no_files_returned", None,
            n_files=0, produced_files=[],
            metadata={"driver_error": "timeout", "returncode": -1})
        check("a genuine pre-candidate driver failure remains infrastructure",
              classify_row(pre_candidate) == (INFRASTRUCTURE, "driver_error"),
              str(classify_row(pre_candidate)))

        # Owner decision 2026-09-25: a Codex attempt the relay stopped at its
        # 200-request cap with nothing written is the system's generation
        # failure.  The shape is what the adapter records for the driver's
        # terminated exit: `rc=75`, and the stopped native process's return
        # code in `run_errors`.
        def codex_stop(iid, returncode, reason, outcome="no_files_returned",
                       n_files=0):
            return row(iid, outcome, None, n_files=n_files,
                       produced_files=[], adapter="codex:deepseek-flash",
                       metadata={"driver_error": f"rc={returncode}",
                                 "returncode": returncode, "termination": None,
                                 "agent_stats": {
                                     "llm_calls": 200,
                                     "run_errors": {"native_returncode": -15},
                                     **({"termination": {
                                         "schema": "r2t.termination/1",
                                         "reason": reason, "complete": False,
                                         "source": "responses_relay",
                                         "preserved_by": "main"}}
                                        if reason else {})}})
        capped = codex_stop("codex_capped", 75, "max_model_calls")
        crashed = codex_stop("codex_crashed", 3, None)
        signalled = codex_stop("codex_signalled", 75, "envelope_expired")
        capped_late = codex_stop("codex_capped_timeout", -1, "max_model_calls")
        capped_late["metadata"]["driver_error"] = "timeout"
        capped_files = codex_stop("codex_capped_files", 75, "max_model_calls",
                                  outcome="failed", n_files=1)
        check("a no-file row the driver stopped at its request cap is a "
              "generation failure, not infrastructure",
              classify_row(capped) == ("generation_failure", None),
              str(classify_row(capped)))
        check("a no-file driver failure (rc=3) stays infrastructure",
              classify_row(crashed) == (INFRASTRUCTURE, "driver_error"),
              str(classify_row(crashed)))
        check("a terminated exit for any other declared reason stays "
              "infrastructure",
              classify_row(signalled) == (INFRASTRUCTURE, "driver_error"),
              str(classify_row(signalled)))
        check("the adapter's envelope timeout stays infrastructure even when "
              "the driver had declared the cap",
              classify_row(capped_late) == (INFRASTRUCTURE, "driver_error"),
              str(classify_row(capped_late)))
        check("a capped row that wrote files keeps its harness outcome",
              classify_row(capped_files) == ("assertion_failure", None),
              str(classify_row(capped_files)))
        capped_meta = dict(capped["metadata"], driver_error=None,
                           metadata_error="KeyError: 'files'")
        check("the cap waives only the driver's exit and run error",
              classify_row(dict(capped, metadata=capped_meta))
              == (INFRASTRUCTURE, "metadata_error"))
        codex_lad = ladder({r["item_id"]: r for r in
                            (capped, crashed, capped_files)})
        codex_rungs = {r["key"]: r for r in codex_lad["rows"]}
        check("the capped row is counted on the generation rung and in the "
              "denominator; only the rc=3 row leaves it",
              codex_rungs["generation_failure"]["count"] == 1
              and codex_rungs["assertion_failure"]["count"] == 1
              and codex_lad["denominator"] == 2
              and codex_lad["excluded"][INFRASTRUCTURE]["items"]
              == [item("codex_crashed")], str(codex_lad))

        # The Claude Sonnet 5.5 arm (CLAUDE_CODE_SONNET_5_5_AMENDMENT.md
        # section 5.3): a content-fallback stop is judged like the cap;
        # an account cut that was not requeued is infrastructure whatever it
        # wrote, and only with the driver's terminated exit.
        fallback_empty = codex_stop("cc_fallback", 75, "content_fallback")
        fallback_empty["metadata"]["agent_stats"]["run_errors"]["request_refused"] = \
            "request model differs from the configured model"
        fallback_files = codex_stop("cc_fallback_files", 75, "content_fallback",
                                    outcome="passed", n_files=1)
        cut_files = codex_stop("cc_cut_files", 75, "rate_limit", outcome="passed", n_files=1)
        cut_empty = codex_stop("cc_cut_empty", 75, "plan_limit")
        cut_late = codex_stop("cc_cut_timeout", -1, "account_auth", outcome="passed", n_files=1)
        check("a content-fallback stop without files is a generation failure",
              classify_row(fallback_empty) == ("generation_failure", None),
              str(classify_row(fallback_empty)))
        check("...and one with files keeps its harness outcome",
              classify_row(fallback_files) == ("pass_rate", None),
              str(classify_row(fallback_files)))
        check("an account cut is infrastructure whether or not it wrote files",
              classify_row(cut_files) == (INFRASTRUCTURE, "account_cut:rate_limit")
              and classify_row(cut_empty) == (INFRASTRUCTURE, "account_cut:plan_limit"),
              f"{classify_row(cut_files)} {classify_row(cut_empty)}")
        check("...but only with the driver's terminated exit",
              classify_row(cut_late) == ("pass_rate", None), str(classify_row(cut_late)))
        check("the account cuts are not native budget stops",
              not set(ACCOUNT_CUT_STOPS) & set(NATIVE_BUDGET_STOPS))

        deliberate_rows = [
            row("deliberate_pass", "passed", {}),
            row("deliberate_parse", "parse_error", None),
            row("deliberate_unwritable", "no_writable_files", None),
        ]
        deliberate_run = _write(
            os.path.join(d, "deliberate-non-rungs.jsonl"), deliberate_rows)
        deliberate_res = pinned_results(
            deliberate_run, gold_path="", prod_index_path="", boundary=b,
            artifacts="", api_scoring=API_SCORING_NONE)
        deliberate_lad = deliberate_res["ladder"]
        check("parse_error and no_writable_files preserve deliberate "
              "disclose-and-exclude behaviour",
              not deliberate_lad["withheld"]
              and deliberate_lad["denominator"] == 1
              and deliberate_lad["classified_n"] == 1
              and deliberate_lad["excluded"][UNCLASSIFIED]["outcomes"]
              == {"parse_error": 1, "no_writable_files": 1},
              str(deliberate_lad))
        deliberate_text = render_text(deliberate_res)
        check("the deliberate exclusions are disclosed as non-rungs, never as "
              "infrastructure to retry",
              "documented deliberate non-rungs" in deliberate_text
              and "not a retry" in deliberate_text
              and "protocol re-runs or quarantines them" not in deliberate_text,
              deliberate_text)

        unknown_driver = row(
            "unknown_driver", "substrate_violation", None,
            n_files=0, produced_files=[],
            metadata={"driver_error": "timeout", "returncode": -1})
        unknown_driver_lad = ladder(
            {unknown_driver["item_id"]: unknown_driver})
        check("an authoritative unknown terminal outcome with no candidate is "
              "not erased by driver metadata",
              classify_row(unknown_driver) == (UNKNOWN,
                                                "substrate_violation")
              and unknown_driver_lad["withheld"]
              and unknown_driver_lad["denominator"] == 1
              and unknown_driver_lad["classified_n"] == 0,
              str(unknown_driver_lad))
        mixed_unknown_lad = ladder({
            pre_candidate["item_id"]: pre_candidate,
            unknown_driver["item_id"]: unknown_driver,
        })
        check("unknown outcome names never leak into infrastructure markers",
              mixed_unknown_lad["excluded"][INFRASTRUCTURE]["markers"]
              == {"driver_error": 1}, str(mixed_unknown_lad))

        unknown_run = _write(os.path.join(d, "unknown-terminal.jsonl"), [
            row("known_terminal", "failed", None),
            row("unknown_terminal", "substrate_violation", None, n_files=1,
                produced_files=[{"file_path": "tests/b.py", "code": "b"}]),
        ])
        unknown_res = pinned_results(
            unknown_run, gold_path="", prod_index_path="", boundary=b,
            artifacts="", api_scoring=API_SCORING_NONE)
        unknown_lad = unknown_res["ladder"]
        unknown_table = table_rows(unknown_res)
        unknown_json = json.loads(render_json(unknown_res))
        unknown_reason = "unknown terminal outcome(s): substrate_violation (1)"
        check("a population can be complete while issue #202 independently "
              "withholds its ladder for an unknown present row",
              unknown_res["population"]["status"] == "complete"
              and unknown_res["population"]["planned_n"] == 2
              and unknown_res["population"]["observed_n"] == 2
              and unknown_res["population"]["missing_planned_ids"] == []
              and unknown_res["population"]["canonical_values_admitted"]
              and unknown_res["ladder"]["withheld_reasons"]
              == [unknown_reason], str(unknown_res["population"]))
        check("a genuinely unknown terminal outcome stays in ladder n but "
              "withholds the primary ladder",
              unknown_lad["denominator"] == 2
              and unknown_lad["classified_n"] == 1
              and unknown_lad["n_excluded"] == 0
              and unknown_lad["unknown"]["outcomes"]
              == {"substrate_violation": 1}
              and unknown_lad["withheld"]
              and unknown_lad["withheld_reasons"] == [unknown_reason]
              and not unknown_lad["sums_to_denominator"], str(unknown_lad))
        check("unknown-outcome withholding removes every quotable ladder rate "
              "from the human and machine tables",
              unknown_json["ladder"]["denominator"] == 2
              and unknown_json["ladder"]["classified_n"] == 1
              and all(r["rate"] is None for r in unknown_lad["rows"])
              and all(r.get("withheld") and r["value"]
                      == f"withheld ({unknown_reason})"
                      for r in unknown_table[:len(LADDER)])
              and all(r["rate"] is None
                      for r in unknown_json["table"][:len(LADDER)]),
              render_text(unknown_res))
        unknown_text = render_text(unknown_res)
        unknown_markdown = render_markdown(unknown_res)
        check("unknown-outcome reports expose observed_n, ladder_n, "
              "classified_n, "
              "and the withholding reason",
              "observed_n = 2 instance(s) in the run file; ladder_n = 2"
              in unknown_text
              and "classified_n = 1" in unknown_text
              and unknown_reason in unknown_text
              and "classified_n = 1" in unknown_markdown
              and any(unknown_reason in note
                      for note in unknown_json["notes"]), unknown_text)
        check("markdown-legacy discloses withholding inside its payload-only "
              "shape instead of printing a reduced percentage",
              f"| pass rate | withheld ({unknown_reason}) |"
              in render_markdown_legacy(unknown_res),
              render_markdown_legacy(unknown_res))

        rows = {r["key"]: r for r in table_rows(res)}
        check("a ladder cell is a percentage OVER its counts",
              rows["pass_rate"]["value"] == "18.2% (2/11)"
              and rows["generation_failure"]["value"] == "9.1% (1/11)",
              rows["pass_rate"]["value"])
        check("the current table is thirteen rows: six rungs and seven quality "
              "rows, in canonical order",
              len(table_rows(res)) == 13
              and [r["key"] for r in table_rows(res)]
              == [k for k, _l, _o in LADDER]
                 + [k for k, _l, _b, _n in QUALITY_ROWS],
              str([r["key"] for r in table_rows(res)]))
        check("the excluded rows are BELOW the table, not in it",
              not any(r["key"] in (INFRASTRUCTURE, UNCLASSIFIED)
                      for r in table_rows(res))
              and any("not scored (infrastructure): 4" in n
                      for n in notes(res)), str(notes(res)))

        # ------------------------- PC5, the RENDER-TIME half at THIS surface
        #
        # The canonical table's own withholding, driven through the real
        # `results` and the real `table_rows`.  Named so that deleting the
        # withhold branch reddens a check: the R3 review recorded a correct
        # property with no red-on-delete witness as a finding, and R4's
        # controlling mechanism must not repeat it.
        short_tq = sidecar_for(run, sidecar(TQ_ITEMS, gold_rows_missing=3,
                                            pairs_executed_gold=77),
                               "tq-short.json")
        short_res = pinned_results(run, gold_path=gold, prod_index_path=index,
                            test_quality_path=short_tq, boundary=b)
        short_rows = {r["key"]: r for r in table_rows(short_res)}
        check("PC5: the canonical table WITHHOLDS recall and Jaccard when the "
              "qualifier says they are not publishable, while hard-subset "
              "onlyGen remains n/a rather than borrowing that state",
              short_rows["mutation_recall"]["value"].startswith("withheld (")
              and "3 gold row(s) are missing"
              in short_rows["mutation_recall"]["value"]
              and short_rows["mutation_only_gen"]["value"]
              == HARD_SUBSET_ONLY_GEN
              and not short_rows["mutation_only_gen"].get("withheld")
              and short_rows["mutation_jaccard"]["value"].startswith(
                  "withheld (")
              and short_rows["mutation_recall"]["number"] is None,
              str(short_rows["mutation_recall"]["value"]))
        check("PC5: ...and the ARITHMETIC survives it: the withheld row keeps "
              "its sensitivity number and `--format json` still carries the "
              "block, so a reader can see what was withheld and why",
              short_rows["mutation_recall"]["sensitivity_number"] == 0.75
              and abs(short_rows["mutation_only_gen"]["sensitivity_number"]
                      - 0.05) < 1e-12
              and json.loads(render_json(short_res))["mutation"]["values"][
                  "recall"] == 0.75
              and json.loads(render_json(short_res))["mutation"][
                  "withheld_reasons"],
              render_json(short_res)[:400])
        check("PC5: ...and the publication-ready control adds onlyGen without "
              "moving the existing mutation rows",
              rows["mutation_recall"]["value"] == "0.750"
              and rows["mutation_only_gen"]["value"]
              == HARD_SUBSET_ONLY_GEN
              and rows["mutation_jaccard"]["value"] == "0.650",
              str({key: row["value"] for key, row in rows.items()}))

        # ----------------------------------------------------- the mutation
        mut = res["mutation"]
        check("mutation recall is the MEAN OVER PASSED INSTANCES",
              abs(mut["values"]["recall"] - 0.75) < 1e-12,
              str(mut["values"]))
        check("hard-subset Jaccard keeps its pre-D6 compatibility value",
              abs(mut["per_item"][item("p1")]["recall"] - 1.0) < 1e-12
              and abs(mut["per_item"][item("p1")]["jaccard"] - 0.8) < 1e-12
              and mut["per_item"][item("p1")]["candidate_only_kills"] == 1
              and mut["per_item"][item("p1")][
                  "basis_candidate_only_kills"] == 0,
              str(mut["per_item"][item("p1")]))
        check("hard-subset onlyGen is n/a while JSON keeps the correctly "
              "denominated full-gold sensitivity number",
              rows["mutation_only_gen"]["number"] is None
              and rows["mutation_only_gen"]["not_applicable"] is True
              and rows["mutation_only_gen"]["reason"]
              == HARD_SUBSET_ONLY_GEN_REASON
              and mut["values"]["only_gen"] is None
              and mut["only_gen_sensitivity"]["basis"] == "full_gold"
              and abs(mut["only_gen_sensitivity"]["number"] - 0.05) < 1e-12
              and mut["only_gen_sensitivity"]["n_scored"] == 2
              and mut["only_gen_sensitivity"]["per_item"][item("p1")]
              ["denominator"] == 9
              and abs(mut["only_gen_sensitivity"]["per_item"][item("p1")]
                      ["only_gen"] - 0.1) < 1e-12
              and abs(mut["values"]["jaccard"] - 0.65) < 1e-12
              and mut["values"]["jaccard"] != mut["values"]["recall"],
              str(mut["values"]))
        full_mut = mutation(
            sidecar(FULL_TQ_ITEMS, verdict_basis="full_gold"),
            set(FULL_TQ_ITEMS))
        full_missed = _mean([
            (v["denominator"] - v["killed"])
            / (v["denominator"] + v["basis_candidate_only_kills"])
            for v in full_mut["per_item"].values()
        ])
        check("full-gold onlyGen is the non-zero candidate-only share",
              abs(full_mut["per_item"][item("p1")]["only_gen"] - 0.2) < 1e-12
              and abs(full_mut["values"]["only_gen"] - 0.1) < 1e-12
              and abs(full_mut["values"]["jaccard"] - 0.65) < 1e-12,
              str(full_mut["values"]))
        full_tq = sidecar_for(
            run, sidecar(FULL_TQ_ITEMS, verdict_basis="full_gold"),
            "tq-full.json")
        full_res = pinned_results(run, gold_path=gold, prod_index_path=index,
                           test_quality_path=full_tq, boundary=b)
        full_rows = {r["key"]: r for r in table_rows(full_res)}
        check("a full-gold table withholds onlyGen as a sensitivity result "
              "without losing its non-zero number in JSON",
              full_rows["mutation_only_gen"]["value"].startswith("withheld (")
              and abs(full_rows["mutation_only_gen"]["sensitivity_number"]
                      - 0.1) < 1e-12
              and abs(json.loads(render_json(full_res))["mutation"]["values"]
                      ["only_gen"] - 0.1) < 1e-12,
              str(full_rows["mutation_only_gen"]))
        # THE DEVELOPMENT ROUTE'S TABLE.  What kills a table is not the
        # mutation rows going withheld -- that is the qualifier working -- but
        # `load_bound_test_quality` raising, which `results` converts into a
        # whole-table `ResultsInputError`.  So this renders a development
        # sidecar end to end and checks three things: the table exists, the
        # mutation cells say withheld with the reason named, and the
        # provenance block says which route the candidate came from.
        dev_tq = sidecar_for(
            run, sidecar(FULL_TQ_ITEMS, verdict_basis="full_gold",
                         generation_provenance_class="development_unstamped"),
            "tq-development.json")
        dev_res = pinned_results(run, gold_path=gold, prod_index_path=index,
                                 test_quality_path=dev_tq, boundary=b)
        dev_rows = {r["key"]: r for r in table_rows(dev_res)}
        dev_text = render_text(dev_res)
        check("a development-route sidecar renders a complete table whose "
              "mutation rows are withheld with a named reason, and whose "
              "provenance block says which route the candidate came from",
              dev_rows["mutation_recall"]["value"].startswith("withheld (")
              and dev_rows["mutation_jaccard"]["value"].startswith(
                  "withheld (")
              and dev_rows["mutation_only_gen"]["value"].startswith(
                  "withheld (")
              and "no bound test-quality evidence"
              not in dev_rows["mutation_recall"]["value"]
              and "[development route: unstamped candidate]" in dev_text
              and abs(json.loads(render_json(dev_res))["mutation"]["values"]
                      ["recall"] - 0.75) < 1e-12,
              str({key: dev_rows[key]["value"] for key in (
                  "mutation_recall", "mutation_only_gen",
                  "mutation_jaccard")}))

        hard_with_full_only = dict(TQ_ITEMS)
        hard_with_full_only[item("p3")] = {
            "candidate_killed": 0, "denominator": 0, "recall": None,
            "full_candidate_killed": 1, "full_denominator": 2,
            "full_recall": 0.5, "candidate_only_kills": 2,
            "verdict": TQ.NOT_SCORABLE,
        }
        split_population = mutation(
            sidecar(hard_with_full_only), set(hard_with_full_only))
        check("hard and full-gold scoring populations stay distinct when an "
              "empty hard subset is still full-gold-scorable",
              split_population["n_scored"] == 2
              and split_population["only_gen_sensitivity"]["n_scored"] == 3
              and item("p3") not in split_population["per_item"]
              and item("p3")
              in split_population["only_gen_sensitivity"]["per_item"]
              and abs(split_population["only_gen_sensitivity"]["number"]
                      - 0.2) < 1e-12,
              str(split_population["only_gen_sensitivity"]))
        hard_only_item = {
            item("p4"): {
                "candidate_killed": 1, "denominator": 1, "recall": 1.0,
                "full_candidate_killed": 0, "full_denominator": 0,
                "full_recall": None, "candidate_only_kills": 0,
                "verdict": TQ.EQUIVALENT,
            },
        }
        hard_only = mutation(sidecar(hard_only_item), set(hard_only_item))
        check("a hard-scorable item with no full-gold score keeps the primary "
              "recall/Jaccard without fabricating sensitivity",
              hard_only["scored"]
              and hard_only["values"]["recall"] == 1.0
              and hard_only["values"]["jaccard"] == 1.0
              and hard_only["values"]["only_gen"] is None
              and hard_only["only_gen_sensitivity"]["number"] is None
              and hard_only["only_gen_sensitivity"]["n_scored"] == 0,
              str(hard_only))
        check("jaccard + onlyGen + missed = 1 per item and after the same "
              "macro average",
              all(abs(v["jaccard"] + v["only_gen"]
                      + (v["denominator"] - v["killed"])
                        / (v["denominator"]
                           + v["basis_candidate_only_kills"]) - 1) < 1e-12
                  for v in full_mut["per_item"].values())
              and abs(full_mut["values"]["jaccard"]
                      + full_mut["values"]["only_gen"]
                      + full_missed - 1) < 1e-12,
              str({"values": full_mut["values"], "missed": full_missed}))
        check("the pooled counts stay in the data for a micro recomputation",
              mut["micro"] == {"killed": 5, "denominator": 6,
                               "candidate_only_kills": 1,
                               "basis_candidate_only_kills": 0},
              str(mut["micro"]))
        check("micro is NOT printed anywhere in the table",
              "5/6" not in render_text(res) and "5/6" not in
              render_markdown(res))

        # ------------------------------------ the v2 consumer contract
        #
        # THE JOIN.  This fixture is not written in the consumer's vocabulary:
        # it is what `test_quality` produces, arithmetic and all, with its key
        # set asserted equal to the producer's own closed field list.  Every
        # defect this block now covers -- a consumer field the producer never
        # emits, a count read off the excluded-pair LIST -- was invisible for
        # exactly as long as this fixture was hand-written.
        v2_tq = _producer_shaped_single_observation_summary(
            [item("p1"), item("p2")])
        v2_items = v2_tq["per_item"]
        check("the producer-built v2 fixture carries the producer's spelling "
              "and its own discovered exclusion evidence",
              set(v2_tq) == TQ._single_observation_summary_fields()
              and v2_tq["reference_excluded_count"] == 131
              and v2_tq["candidate_excluded_count"] == 1
              and v2_tq["candidate_excluded_pairs"] == [
                  {"item_id": item("p2"), "mutant_id": "m3",
                   "outcome": "timeout"}]
              and "reference_excluded_pairs" not in v2_tq
              and v2_tq["hard_recall_macro"] == 1.0
              and abs(v2_tq["full_recall_macro"] - 2 / 3) < 1e-12,
              str({key: v2_tq[key] for key in sorted(v2_tq)
                   if "excluded" in key or "macro" in key}))
        fullgold_tq = _producer_shaped_single_observation_summary(
            [item("p1"), item("p2")], full_gold=True)
        fullgold_mutation = mutation(fullgold_tq, {item("p1"), item("p2")})
        fullgold_res = dict(res, mutation=fullgold_mutation)
        fullgold_rows = {row["key"]: row for row in table_rows(fullgold_res)}
        check("full-gold v2 renders producer recall and exclusions without invented hard or companion measures",
              fullgold_mutation["values"]["recall"] == fullgold_tq["full_recall_macro"]
              and fullgold_mutation["companion"] is None
              and fullgold_rows["mutation_recall"]["number"] == fullgold_tq["full_recall_macro"]
              and fullgold_rows["mutation_only_gen"].get("not_measured")
              and fullgold_rows["mutation_jaccard"].get("not_measured")
              and not any(key.endswith("_companion") for key in fullgold_rows)
              and "131" in fullgold_rows["mutation_recall"]["value"]
              and fullgold_mutation["candidate_excluded_count"] == 1
              and "No stripped or stub mutation reference" in " ".join(render_text(fullgold_res).split())
              and "Mutation primary: hard-subset" not in render_markdown(fullgold_res)
              and json.loads(render_json(fullgold_res))["mutation"]["companion"] is None,
              str({"rows": fullgold_rows, "mutation": fullgold_mutation}))
        fullgold_text = " ".join(render_text(fullgold_res).split())
        hard_v2_text = " ".join(render_text(dict(
            res, mutation=mutation(v2_tq, set(v2_items)))).split())
        check("full-gold v2 provenance counts the gold-killed candidate "
              "slice it executed, not the population; hard-subset v2 keeps "
              "the population wording",
              "(3 mutant(s) / 6 execution(s) in the gold-killed candidate "
              "slice)" in fullgold_text
              and "(4 mutant(s) / 8 execution(s) in the population)"
              in hard_v2_text
              and "gold-killed candidate slice" not in hard_v2_text,
              fullgold_text[:600])
        check("full-gold v2 section 5.1 note counts run exclusions inside the "
              "gold-killed slice and says nothing outside it was observed; "
              "hard-subset v2 keeps the population wording",
              "pair(s) of the gold-killed candidate slice this candidate run "
              "lost of its own; candidate outcomes outside the slice were not "
              "observed" in fullgold_text
              and "further pair(s) this candidate run lost of its own"
              in hard_v2_text
              and "candidate outcomes outside the slice" not in hard_v2_text,
              fullgold_text[:800])
        for field in ("full_only_generated_macro", "full_jaccard_macro", "hard_recall_macro"):
            invalid_fullgold = dict(fullgold_tq, **{field: 0.0})
            check("full-gold v2 refuses invented " + field,
                  _raises(lambda: mutation(invalid_fullgold, {item("p1"), item("p2")}),
                          "undefined aggregate"))
        v2_reader = object()
        saved_v2_loader = TQ.load_bound_test_quality

        def guarded_v2_loader(_run_path, summary_path=None, *,
                              reference_controls_reader=None):
            if reference_controls_reader is None:
                raise TQ.TestQualityRefused(
                    "REFUSED: a v2 summary requires its authenticated "
                    "installed ReferenceControls reader")
            return v2_tq

        TQ.load_bound_test_quality = guarded_v2_loader
        try:
            v2_without_reader_refused = _raises(
                lambda: pinned_results(
                    run, gold_path=gold, prod_index_path=index,
                    test_quality_path=tq_path, boundary=b),
                "requires its authenticated installed ReferenceControls")
            v2_loaded_res = pinned_results(
                run, gold_path=gold, prod_index_path=index,
                test_quality_path=tq_path, boundary=b,
                reference_controls_reader=v2_reader)
            v2_incomplete_res = _results_impl(
                run, gold_path=gold, prod_index_path=index,
                test_quality_path=tq_path, boundary=b,
                reference_controls_reader=v2_reader,
                validated_population_scope=incomplete_scope)
        finally:
            TQ.load_bound_test_quality = saved_v2_loader
        check("the results entry point leaves v2 fail-closed without its "
              "installed reader and consumes it when supplied",
              v2_without_reader_refused
              and v2_loaded_res["mutation"]["schema"]
              == TEST_QUALITY_SUMMARY_SCHEMA_V2)
        v2_incomplete_rows = {
            row["key"]: row for row in table_rows(v2_incomplete_res)}
        v2_companion_keys = {q[0] for q in V2_COMPANION_ROWS}
        check("an incomplete parent population clears v2 companion aggregates "
              "and withholds every companion table row",
              v2_incomplete_res["mutation"]["values"] is None
              and v2_incomplete_res["mutation"]["companion"]["values"] is None
              and all(v2_incomplete_rows[key].get("withheld")
                      and v2_incomplete_rows[key]["number"] is None
                      and "population incomplete"
                      in v2_incomplete_rows[key]["reason"]
                      for key in v2_companion_keys)
              and json.loads(render_json(v2_incomplete_res))["mutation"]
              ["companion"]["values"] is None,
              str({key: v2_incomplete_rows[key]
                   for key in v2_companion_keys}))
        v2_res = dict(res, mutation=mutation(v2_tq, set(v2_items)))
        v2_rows = {row["key"]: row for row in table_rows(v2_res)}
        check("v2 renders hard recall as primary, keeps undefined hard "
              "onlyGen/Jaccard n/a, and labels all three full-population "
              "companions separately",
              v2_rows["mutation_recall"]["number"]
              == v2_tq["hard_recall_macro"]
              and v2_rows["mutation_only_gen"]["value"] == HARD_SUBSET_ONLY_GEN
              and v2_rows["mutation_jaccard"]["value"] == HARD_SUBSET_JACCARD
              and v2_rows["mutation_full_recall_companion"]["number"]
              == v2_tq["full_recall_macro"]
              and v2_rows["mutation_full_only_gen_companion"]["number"]
              == v2_tq["full_only_generated_macro"]
              and v2_rows["mutation_full_jaccard_companion"]["number"]
              == v2_tq["full_jaccard_macro"]
              and all("companion, full population" in v2_rows[key]["label"]
                      for key in v2_companion_keys),
              str(v2_rows))
        check("section 5.1's two excluded counts travel ON every rendered v2 "
              "mutation number, separately named, and on the provenance line",
              all(v2_rows[key]["value"].endswith(
                  "(excluded pairs: 131 reference, 1 run)")
                  for key in {"mutation_recall"} | v2_companion_keys)
              and "(excluded pairs: 131 reference, 1 run)]"
              in render_text(v2_res)
              and any("131 pair(s) the reference observations lost" in note
                      and "1 further pair(s) this candidate run lost" in note
                      for note in notes(v2_res)),
              v2_rows["mutation_recall"]["value"])
        # SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md: the same producer-built
        # outcomes under the labelled basis on the full-gold kills only.  The
        # all-pairs fixture's only-kill (p1 kills m3) is off G, so its
        # companions are real numbers there that this slice cannot have.
        gk_tq = _producer_shaped_single_observation_summary(
            [item("p1"), item("p2")], labelled_gold_killed=True)
        gk_res = dict(res, mutation=mutation(gk_tq, set(v2_items)))
        gk_rows = {row["key"]: row for row in table_rows(gk_res)}
        check("a labelled gold-killed v2 summary keeps every recall, withholds "
              "its measured rows for the label, and renders the only-"
              "generated and Jaccard companions as not measured",
              gk_res["mutation"]["values"]["recall"]
              == v2_res["mutation"]["values"]["recall"]
              and gk_res["mutation"]["companion"]["values"]["recall"]
              == v2_res["mutation"]["companion"]["values"]["recall"]
              and v2_rows["mutation_full_jaccard_companion"]["number"]
              is not None
              and all(gk_rows[key]["value"] == GOLD_KILLED_NOT_MEASURED
                      and gk_rows[key]["number"] is None
                      and gk_rows[key]["not_measured"] is True
                      for key in V2_GOLD_KILLED_ROWS)
              and gk_rows["mutation_jaccard"]["value"] == HARD_SUBSET_JACCARD
              and gk_rows["mutation_recall"].get("withheld") is True
              and any("sensitivity" in reason for reason in
                      gk_res["mutation"]["withheld_reasons"])
              and gk_res["mutation"]["candidate_pair_scope"]
              == TQ.CANDIDATE_PAIRS_GOLD_KILLED
              and "candidate_pair_scope" not in v2_res["mutation"]
              and "execution(s) in the gold-killed candidate slice"
              in render_text(gk_res),
              str({key: gk_rows[key]["value"] for key in gk_rows
                   if key.startswith("mutation")}))
        check("a labelled gold-killed v2 summary carrying an off-G number is "
              "refused rather than rendered",
              _raises(lambda: mutation(dict(gk_tq, full_jaccard_macro=0.5),
                                       set(v2_items)), "gold-killed"))
        empty_hard_tq = _producer_shaped_single_observation_summary(
            [item("p1"), item("p2")], candidate_items=[item("p2")])
        empty_hard = mutation(empty_hard_tq, {item("p2")})
        empty_hard_res = dict(v2_res, mutation=empty_hard)
        empty_hard_rows = {row["key"]: row for row in table_rows(empty_hard_res)}
        check("an admitted reference with no hard-scorable candidate passes retains defined companions",
              empty_hard["scored"] is False
              and empty_hard["values"]["recall"] is None
              and empty_hard["companion"]["scored"] is True
              and empty_hard_rows["mutation_recall"]["number"] is None
              and empty_hard["companion"]["values"]["recall"] == 1 / 3)
        v2_declared_tq = _producer_shaped_single_observation_summary(
            [item("p1"), item("p2")],
            omitted_items=tuple(f"t/omitted{n}" for n in range(6)),
            declared_reason="the control run has no gold row for them")
        v2_declared = mutation(v2_declared_tq, set(v2_items))
        v2_declared_notes = notes(dict(v2_res, mutation=v2_declared))
        check("a declared reference subset the PRODUCER wrote adds its own "
              "omitted-item count and the operator's reason to the rendered "
              "output, and an undeclared one adds neither",
              excluded_pairs_note(131, 1)
              == "(excluded pairs: 131 reference, 1 run)"
              and excluded_pairs_note(131, 1, 0)
              == "(excluded pairs: 131 reference, 1 run)"
              and excluded_pairs_note(131, 1, 6)
              == ("(excluded pairs: 131 reference, 1 run) "
                  "(declared subset: 6 item(s) omitted)")
              and v2_declared_tq["reference_omitted_items"] == 6
              and v2_declared["reference_omitted_items"] == 6
              and v2_declared["reference_declared_reason"]
              == "the control run has no gold row for them"
              and any("DECLARED REFERENCE SUBSET" in note
                      and "6 released item(s) are omitted" in note
                      and "declared reason: the control run has no gold row"
                      in note for note in v2_declared_notes)
              and mutation(v2_tq, set(v2_items))[
                  "reference_omitted_items"] == 0
              and not any("DECLARED REFERENCE SUBSET" in note
                          for note in notes(v2_res)),
              str(v2_declared_notes))
        v2_json = json.loads(render_json(v2_res))
        check("v2 JSON preserves the exact summary values plus method, both "
              "observation counts and the installed controls identity",
              v2_json["mutation"]["values"]["recall"]
              == v2_tq["hard_recall_macro"]
              and v2_json["mutation"]["companion"]["values"] == {
                  "recall": v2_tq["full_recall_macro"],
                  "only_gen": v2_tq["full_only_generated_macro"],
                  "jaccard": v2_tq["full_jaccard_macro"]}
              and v2_json["mutation"]["method"] == "single_observation"
              and v2_json["mutation"]["candidate_observation_count"] == 1
              and v2_json["mutation"]["reference_observation_count"] == 1
              and v2_json["mutation"]["reference_controls_digest"] == "a" * 64,
              str(v2_json["mutation"]))
        check("v2 text and Markdown carry primary/companion and observation "
              "labels while markdown-legacy refuses the new shape",
              "mutation recall (primary, hard subset)" in render_text(v2_res)
              and "mutation recall (companion, full population)"
              in render_markdown(v2_res)
              and "candidate observations: 1; reference observations: 1"
              in render_text(v2_res)
              and _raises(lambda: render_markdown_legacy(v2_res),
                          "cannot render a v2 single-observation"))
        v2_notes = notes(v2_res)
        check("v2 notes disclose ten rows and two distinct scored "
              "populations, and drop v1's single-population sentence",
              any("The ten quality rows" in note for note in v2_notes)
              and any("Mutation primary:" in note
                      and "n_scored = 1 of 2" in note
                      and "empty hard subset" in note for note in v2_notes)
              and any("Mutation companion:" in note
                      and "n_scored = 2 of 2" in note
                      and "full-gold reference kill set" in note
                      for note in v2_notes)
              and not any("gold kills nothing" in note for note in v2_notes),
              str(v2_notes))
        check("stale or incomplete v2 summaries refuse instead of defaulting "
              "missing evidence -- including an excluded count -- to zero",
              _raises(lambda: mutation(
                  dict(v2_tq, per_item={item("p1"): v2_items[item("p1")]}),
                  set(v2_items)), "it is stale")
              and _raises(lambda: mutation(
                  {key: value for key, value in v2_tq.items()
                   if key != "full_jaccard_macro"}, set(v2_items)),
                  "missing field")
              and _raises(lambda: mutation(
                  {key: value for key, value in v2_tq.items()
                   if key != "candidate_excluded_count"}, set(v2_items)),
                  "candidate_excluded_count")
              # The defect itself, pinned: the producer emits a COUNT and an
              # excluded-pair LIST under two different names.  A consumer
              # reading the list as the count renders `[{...}] run` in the
              # mandatory note, so the count must be absent-not-substitutable.
              and _raises(lambda: mutation(
                  {key: value for key, value in v2_tq.items()
                   if key != "reference_excluded_count"}, set(v2_items)),
                  "reference_excluded_count"))

        # ------------------------------------------------ coverage and api
        check("coverage jaccard is the mean of the per-instance LINE jaccard",
              abs(res["coverage"]["values"]["jaccard"] - 0.75) < 1e-12,
              str(res["coverage"]["values"]))
        check("the per-file variant is kept beside it, not printed",
              abs(res["coverage"]["values"]["macro_jaccard_within_item"]
                  - (1.0 + 1 / 3) / 2) < 1e-12,
              str(res["coverage"]["values"]))
        check("api precision/recall/f1 are means over the passed instances",
              all(abs(res["api"]["values"][k] - 0.75) < 1e-12
                  for k in ("precision", "recall", "f1")),
              str(res["api"]["values"]))
        expected_coverage = {
            "jaccard": 0.75,
            "macro_jaccard_within_item": (1.0 + 1 / 3) / 2,
            "recall": (1.0 + 2 / 3) / 2,
            "excess": (0.0 + 1 / 3) / 2,
        }
        expected_excluded = {"no_gold_row": [],
                             "gold_without_coverage": {},
                             "run_without_coverage": {}}
        # The API block carries three exclusions of its own beside those
        # three, and they are present-and-empty here rather than absent: a
        # reader must be able to see that nothing was excluded for them.
        expected_api_excluded = dict(expected_excluded,
                                     run_without_direct_calls=[],
                                     gold_without_direct_calls=[],
                                     run_before_api_amendment_2=[],
                                     gold_before_api_amendment_2=[],
                                     invalid_production_index=[],
                                     gold_no_direct_methods=[])
        check("CoreShop method-index parity: every scored value, n_scored "
              "and exclusion is unchanged",
              all(abs(res["coverage"]["values"][k] - v) < 1e-12
                  for k, v in expected_coverage.items())
              and res["api"]["values"] == {
                  "precision": 0.75, "recall": 0.75, "f1": 0.75}
              and res["coverage"]["n_scored"] == 2
              and res["api"]["n_scored"] == 2
              and res["coverage"]["excluded"] == expected_excluded
              and res["api"]["excluded"] == expected_api_excluded,
              f"coverage={res['coverage']}; api={res['api']}")
        check("only production methods count -- a call whose CALLEE is the "
              "answer's own file never enters a set",
              res["api"]["per_item"][item("p2")]["counts"]
              ["gold_methods"] == 2)
        check("the |D_G| shape and the unmapped-event count travel with the "
              "rows, in the JSON and in the notes",
              res["api"]["d_g_sizes"] == {
                  "n": 2, "min": 2, "p25": 2, "median": 2, "mean": 2,
                  "p75": 2, "max": 2, "histogram": {"2": 2}}
              and res["api"]["unmapped_direct_events"] == {"gold": 0,
                                                           "run": 0}
              and any("|D_G| median 2 (min 2, max 2) over 2 scored item(s); "
                      "unmapped direct events over every coverage-compared "
                      "item: gold 0, run 0" in note
                      for note in notes(res)),
              str(res["api"]["d_g_sizes"]))
        check("the quality rows are over the PASSED instances only",
              res["coverage"]["n_scored"] == 2 and res["n_passed"] == 2
              and res["n"] == 16)

        text = render_text(res)
        check("the passed-instance count travels with the table",
              "MEANS OVER THE 2 PASSED INSTANCE(S)" in text, text)
        check("provenance names every file a number came from",
              run in text and gold in text and index in text
              and tq_path in text)
        check("the campaign digest is printed when the rows carry one",
              "cafe1234" in text)

        # ------------------------------------------------- the citation line
        #
        # PINNED ON A ROW SET THAT CARRIES NONE OF THE NEW STAMPS, because
        # that is the archived case -- every published run predates them --
        # and because a `?` that quietly became a default is the one failure
        # here that would look like success. `K=` appears because these rows
        # carry a campaign digest; `of` is unstamped, so the K itself is `?`.
        cite = res["citation"]
        check("a row set with none of the identity stamps cites `?` for every "
              "one of them, and invents nothing",
              cite == "req2test D?(?) / H?@? / P? / ?@? / ? / ? (?, K=?)",
              cite)
        check("the citation is printed ABOVE the table in text and markdown",
              cite in text and f"- **citation**: `{cite}`" in render_markdown(res),
              text.splitlines()[2] if len(text.splitlines()) > 2 else text)
        check("...and NEVER inside the payload -- markdown-legacy is the "
              "twelve rows alone",
              "req2test" not in render_markdown_legacy(res))
        stamped = {r["item_id"]: dict(
            r, dataset_version="1.0", subset_id="eval100", harness_version=6,
            harness_commit="abc1234", protocol_version=2,
            adapter_version="openhands@1", setting="cold_start", model="m",
            comparison_class="fixed_model_scaffold", of=16)
            for r in run_rows}
        check("a fully stamped row set cites every field it carries",
              citation(stamped) == "req2test D1.0(eval100) / H6@abc1234 / P2 "
                                   "/ openhands@1 / cold_start "
                                   "/ fixed_model_scaffold (m, K=16)",
              citation(stamped))
        # Rows that disagree are SHOWN disagreeing: the whole reason `_digests`
        # returns a list is that collapsing two values to one is how a table
        # ends up quoting a provenance it does not have.
        mixed = dict(stamped)
        first = sorted(mixed)[0]
        mixed[first] = dict(mixed[first], protocol_version=1)
        check("rows produced under two protocols cite BOTH, never the first",
              "P1|2" in citation(mixed), citation(mixed))
        # A shard resumed after a merge carries two commits (section 16.5);
        # the citation names both rather than the plan's.
        resumed = dict(stamped)
        resumed[first] = dict(resumed[first], harness_commit="def5678")
        check("rows produced under two harness commits cite both",
              "H6@abc1234|def5678" in citation(resumed), citation(resumed))
        # No campaign digest -> no K at all. `K=1` would be a claim.
        nocamp = {k: {kk: vv for kk, vv in v.items()
                      if kk != "campaign_digest"}
                  for k, v in stamped.items()}
        check("a run with no campaign cites no K -- a single process is not "
              "K=1, it is a run with no sharding fact to state",
              citation(nocamp).endswith("(m)"), citation(nocamp))
        # The system survives an absent adapter_version, because the rows
        # still say WHICH system; only its version is unknown.
        halfway = {k: {kk: vv for kk, vv in v.items()
                       if kk != "adapter_version"}
                   for k, v in stamped.items()}
        halfway = {k: dict(v, adapter="openhands:deepseek")
                   for k, v in halfway.items()}
        check("an unversioned but named system cites `openhands@?`, not `?`",
              "openhands@?" in citation(halfway), citation(halfway))
        # PRESENCE, NOT TRUTHINESS. `?` means "nobody recorded this", and a
        # recorded falsy value -- `trials: 0`, `of: 0`, an empty label -- is
        # not that. The two halves are pinned together because only having the
        # first is how a filter drifts back to `if r.get(field)`.
        falsy = {k: dict(v, of=0) for k, v in stamped.items()}
        check("a field recorded as 0 cites 0, not `?` -- a legitimate falsy "
              "value was still recorded",
              _digests(falsy, "of") == ["0"] and citation(falsy).endswith(
                  "(m, K=0)"), citation(falsy))
        absent = {k: {kk: vv for kk, vv in v.items() if kk != "of"}
                  for k, v in stamped.items()}
        nulled = {k: dict(v, of=None) for k, v in stamped.items()}
        check("...while an ABSENT field, and an explicitly null one, both "
              "still cite `?`",
              _digests(absent, "of") is None and _digests(nulled, "of") is None
              and citation(absent).endswith("(m, K=?)")
              and citation(nulled).endswith("(m, K=?)"),
              f"{citation(absent)} / {citation(nulled)}")
        check("markdown renders a pasteable table with the same numbers",
              "| metric | value |" in render_markdown(res)
              and "| pass rate | 18.2% (2/11) |" in render_markdown(res)
              and ("| mutation only-generated kills | "
                   + HARD_SUBSET_ONLY_GEN + " |")
              in render_markdown(res)
              and "| coverage jaccard similarity | 0.750 |"
              in render_markdown(res), render_markdown(res))
        # ------------------------------------ the legacy payload, and only it
        legacy = render_markdown_legacy(res)
        legacy_lines = legacy.rstrip("\n").split("\n")
        expected_legacy_bytes = (
            "| metric | value |\n"
            "| --- | --- |\n"
            "| generation failure | 9.1% (1/11) |\n"
            "| compilation failure | 18.2% (2/11) |\n"
            "| binding failure | 18.2% (2/11) |\n"
            "| execution failure | 27.3% (3/11) |\n"
            "| assertion failure | 9.1% (1/11) |\n"
            "| pass rate | 18.2% (2/11) |\n"
            "| mutation recall | 0.750 |\n"
            "| mutation jaccard similarity | 0.650 |\n"
            "| coverage jaccard similarity | 0.750 |\n"
            "| api precision | 0.750 |\n"
            "| api recall | 0.750 |\n"
            "| api f1 | 0.750 |\n")
        check("a complete byte-pinned markdown-legacy result remains exactly "
              "the pre-population-binding payload",
              legacy == expected_legacy_bytes, legacy)
        md_lines = render_markdown(res).split("\n")
        start = md_lines.index("| metric | value |")
        payload_in_markdown = md_lines[start:start + 15]
        check("the current Markdown payload is the same thirteen-row payload "
              "returned by markdown_payload_lines",
              payload_in_markdown == markdown_payload_lines(res),
              str(payload_in_markdown))
        expected_legacy = (
            "generation_failure", "compilation_failure", "binding_failure",
            "execution_failure", "assertion_failure", "pass_rate",
            "mutation_recall", "mutation_jaccard", "coverage_jaccard",
            "api_precision", "api_recall", "api_f1",
        )
        check("the legacy selector is the explicit original twelve keys",
              LEGACY_ROWS == expected_legacy, str(LEGACY_ROWS))
        only_gen_line = ("| mutation only-generated kills | "
                         + HARD_SUBSET_ONLY_GEN + " |")
        check("markdown-legacy shares the dialect but filters onlyGen out of "
              "the current payload",
              legacy_lines
              == [line for line in payload_in_markdown
                  if line != only_gen_line]
              and only_gen_line not in legacy_lines,
              legacy)
        check("the legacy rendering is fourteen lines: header, separator and "
              "the twelve pinned rows",
              legacy.endswith("\n") and len(legacy_lines) == 14,
              str(len(legacy_lines)))
        check("the legacy rendering carries NO provenance and NO notes -- the "
              "new blocks render around the payload, never inside it",
              "Canonical results" not in legacy and "effort" not in legacy
              and "**" not in legacy and "instance(s)" not in legacy, legacy)
        check("markdown-legacy is reachable by name from render()",
              render(res, "markdown-legacy") == legacy
              and "markdown-legacy" in FORMATS)

        # ------------------------------------------------------- the effort
        eff = res["effort"]
        check("effort counts the rows that carry agent stats, over n",
              eff["n"] == 16 and eff["n_rows_with_agent_stats"] == 1,
              str(eff))
        check("an unmeasured effort figure is None, never 0.0",
              eff["llm_calls"] == {"mean": None, "max": None, "n": 0}
              and eff["agent_seconds"]["mean"] is None
              and eff["iterations_budget"] is None, str(eff))
        check("effort renders BELOW the table and NEVER as a row: the table "
              "is still thirteen rows",
              len(table_rows(res)) == 13
              and any(n.startswith("effort (") for n in notes(res))
              and not any("effort" in r["label"] for r in table_rows(res)),
              str(notes(res)[-1]))
        check("the effort note travels in every format that has notes",
              "effort (what the system spent" in render_text(res)
              and "effort (what the system spent" in render_markdown(res)
              and any("effort" in n for n in
                      json.loads(render_json(res))["notes"]))
        check("an unrecorded effort figure SAYS it was not recorded",
              "llm calls not recorded" in notes(res)[-1]
              and "iteration budget not recorded" in notes(res)[-1],
              notes(res)[-1])

        measured = effort({
            "a": {"metadata": {"agent_stats": {"llm_calls": 10},
                               "agent_seconds": 100.0,
                               "trials": {"used": 1}},
                  "max_iterations": 100},
            "b": {"metadata": {"agent_stats": {"llm_calls": 30},
                               "agent_seconds": 300.0,
                               "trials": {"used": 3}},
                  "max_iterations": 100},
        })
        check("effort means and maxima come off the rows' own stamps",
              measured["llm_calls"] == {"mean": 20, "max": 30, "n": 2}
              and measured["agent_seconds"]["mean"] == 200.0
              and measured["trials_used"]["max"] == 3
              and measured["iterations_budget"] == 100, str(measured))
        mixed = effort({"a": {"max_iterations": 50},
                        "b": {"max_iterations": 100}})
        check("two iteration budgets in one file are NOT collapsed to one",
              mixed["iterations_budget"] is None
              and mixed["iterations_budget_values"] == [50, 100]
              and "MIXED iteration budgets" in _effort_note(mixed),
              _effort_note(mixed))

        payload = json.loads(render_json(res))
        check("json carries the same numbers as data",
              payload["mutation"]["values"]["recall"] == 0.75
              and payload["mutation"]["values"]["only_gen"] is None
              and abs(payload["mutation"]["only_gen_sensitivity"]["number"]
                      - 0.05) < 1e-12
              and payload["n"] == 16 and payload["n_passed"] == 2)
        check("json keeps the per-instance evidence micro would need",
              payload["mutation"]["per_item"][item("p1")]["denominator"] == 4
              and payload["mutation"]["per_item"][item("p1")][
                  "candidate_only_kills"] == 1
              and payload["mutation"]["per_item"][item("p1")][
                  "basis_candidate_only_kills"] == 0
              and item("p1") in payload["coverage"]["per_item"]
              and item("p1") in payload["api"]["per_item"])
        check("an unknown --format is refused, not guessed",
              _raises(lambda: render(res, "latex"), "unknown --format"))

        # --------------------------------------------- honest degradation
        no_side = pinned_results(run, gold_path=gold, prod_index_path=index,
                          boundary=b)
        cell = {r["key"]: r for r in table_rows(no_side)}
        check("no test-quality sidecar: the mutation rows say so, and do NOT "
              "say 0.0",
              cell["mutation_recall"]["value"] == NOT_SCORED_MUTATION
              and cell["mutation_only_gen"]["value"] == NOT_SCORED_MUTATION
              and cell["mutation_jaccard"]["value"] == NOT_SCORED_MUTATION
              and cell["mutation_recall"]["number"] is None,
              cell["mutation_recall"]["value"])
        unscored_renderings = [render(no_side, fmt) for fmt in FORMATS]
        check("every results renderer names the missing bound evidence and "
              "never recommends the closed test-quality command",
              all("not scored (no bound test-quality evidence)" in rendered
                  for rendered in unscored_renderings)
              and all("r2t.cli test-quality" not in rendered
                      for rendered in unscored_renderings),
              "\n".join(unscored_renderings))
        check("a missing sidecar leaves coverage and api scored",
              no_side["coverage"]["scored"] and no_side["api"]["scored"])

        no_index_artifacts = os.path.join(d, "no-index-artifacts")
        docx = pinned_results(run, gold_path=gold, boundary=b,
                       artifacts=no_index_artifacts,
                       api_scoring=API_SCORING_NONE)
        docx_rows = {r["key"]: r for r in table_rows(docx)}
        check("python-docx coverage stays numeric without a production "
              "method index",
              docx["coverage"]["scored"]
              and docx["coverage"]["values"] == res["coverage"]["values"]
              and docx_rows["coverage_jaccard"]["number"] == 0.75,
              str(docx["coverage"]))
        check("python-docx api rows render exactly not_measured, with no "
              "fabricated zero",
              not docx["api"]["scored"]
              and docx["api"]["reason"] == NOT_MEASURED_API
              and docx["api"]["n_scored"] == 0
              and docx["api"]["per_item"] == {}
              and all(docx_rows[k]["value"] == NOT_MEASURED_API
                      and docx_rows[k]["number"] is None
                      for k in ("api_precision", "api_recall", "api_f1")),
              str({k: docx_rows[k] for k in
                   ("api_precision", "api_recall", "api_f1")}))

        missing_index = pinned_results(
            run, gold_path=gold, boundary=b, artifacts=no_index_artifacts,
            api_scoring=API_SCORING_METHOD_INDEX)
        missing_index_rows = {r["key"]: r
                              for r in table_rows(missing_index)}
        check("an API-capable project missing its index keeps coverage and "
              "gets the actionable API reason",
              missing_index["coverage"]["scored"]
              and missing_index["coverage"]["values"]
              == res["coverage"]["values"]
              and not missing_index["api"]["scored"]
              and missing_index["api"]["reason"] ==
              "not scored (no production method index; pass --prod-index FILE)"
              and missing_index_rows["api_f1"]["number"] is None,
              str(missing_index["api"]))

        # ISSUE #282: the default index is looked up BY LANGUAGE.  Two
        # producers write two names into the same artifacts-directory shape,
        # so one fixed name meant every python-docx table asked for
        # `php_prod_index.json`, found nothing, and printed the reason above
        # beside a directory holding the right file.
        py_art = os.path.join(d, "py-artifacts")
        php_art = os.path.join(d, "php-artifacts")
        os.makedirs(py_art)
        os.makedirs(php_art)
        py_index = os.path.join(py_art, "py_prod_index.json")
        with open(py_index, "w", encoding="utf-8") as fh:
            json.dump({"schema": M.PYTHON_PROD_INDEX_SCHEMA,
                "files": {"src/prod/cart.py": {"classes": [
                {"name": "prod.cart.Cart", "accessors": [], "methods": [
                    {"name": "total", "start": 11, "end": 20,
                     "public": True, "decl": 10}]}]}}}, fh)
        php_index = os.path.join(php_art, "php_prod_index.json")
        _index_fixture(php_index)
        php_default = pinned_results(run, gold_path=gold, boundary=b,
                                     artifacts=php_art)
        check("existing Python API callers keep PHP index discovery when "
              "they omit language",
              default_prod_index(php_art) == php_index
              and php_default["prod_index"] == os.path.abspath(php_index)
              and php_default["api"]["scored"]
              and php_default["api"]["values"] == res["api"]["values"],
              str(php_default["api"]))

        from ..data import bundle as bundle_data
        runs_dir = os.path.join(php_art, "runs")
        os.makedirs(runs_dir)
        historical_gold = _write(os.path.join(runs_dir, "eval100_gold.jsonl"),
                                 gold_rows)
        scoring_gold = _write(os.path.join(runs_dir, "gold_direct.jsonl"),
                              gold_rows)
        check("a gold_direct filename without an installed declaration "
              "cannot override the historical gold default",
              default_gold_run(php_art, b.project) == historical_gold)
        real_installed_scoring_gold = bundle_data.installed_scoring_gold
        gold_lookups = []
        try:
            def declared_gold(artifacts, project):
                gold_lookups.append((artifacts, project))
                return scoring_gold
            bundle_data.installed_scoring_gold = declared_gold
            selected_gold = pinned_results(run, boundary=b, artifacts=php_art)
            check("ordinary results selects the validated declared scoring "
                  "reference and reports its path; legacy pin lookup keeps "
                  "its historical reference",
                  selected_gold["gold"] == os.path.abspath(scoring_gold)
                  and selected_gold["api"]["values"] == res["api"]["values"]
                  and gold_lookups == [(php_art, b.project)]
                  and default_gold_run(php_art) == historical_gold,
                  str(selected_gold["gold"]))

            def invalid_gold(artifacts, project):
                raise bundle_data.BundleRefused("declared scoring_gold drift")
            bundle_data.installed_scoring_gold = invalid_gold
            check("invalid declared scoring gold refuses rather than "
                  "silently falling back to the historical run",
                  _raises(lambda: pinned_results(
                      run, boundary=b, artifacts=php_art),
                      "invalid installed scoring gold"))
            explicit_gold = pinned_results(
                run, gold_path=historical_gold, boundary=b, artifacts=php_art)
            check("an explicit gold run bypasses default role selection",
                  explicit_gold["gold"] == os.path.abspath(historical_gold)
                  and explicit_gold["api"]["values"] == res["api"]["values"])
        finally:
            bundle_data.installed_scoring_gold = real_installed_scoring_gold

        py_step = "src/Test/generated_test.py"
        py_rows = [{"item_id": item("py1"), "outcome": "passed",
                    "campaign_digest": "cafe1234cafe1234",
                    "harness_version": M.OUTLINE_UNION_HARNESS_VERSION,
                    "direct_calls_schema": M.PYTHON_DIRECT_CALLS_SCHEMA,
                    "coverage_lines": {"src/prod/cart.py": [11, 12]},
                    "direct_calls": [{"callee_file": "src/prod/cart.py",
                                      "callee_line": 10,
                                      "callee": "prod.cart.Cart.total",
                                      "caller_file": py_step,
                                      "accessor_binding": None}]}]
        py_run = _write(os.path.join(d, "py-sweep.jsonl"), py_rows)
        py_gold = _write(os.path.join(d, "py-gold.jsonl"), py_rows)

        def py_table(artifacts, **kw):
            return pinned_results(py_run, gold_path=py_gold, boundary=b,
                                  artifacts=artifacts,
                                  api_scoring=API_SCORING_METHOD_INDEX, **kw)

        py_default = py_table(py_art, language="python")
        check("a Python project resolves `py_prod_index.json` from its "
              "artifacts directory and scores the API rows on it (#282)",
              py_default["api"]["scored"]
              and py_default["prod_index"] == os.path.abspath(py_index)
              and py_default["api"]["n_scored"] == 1
              and py_default["api"]["values"]["f1"] == 1.0,
              str(py_default["api"]))
        mixed_gold_rows = [py_rows[0], dict(py_rows[0], item_id=item("py2"))]
        mixed_old = dict(mixed_gold_rows[1], direct_calls=[])
        mixed_old.pop("direct_calls_schema")
        mixed_gold = _write(os.path.join(d, "mixed-py-gold.jsonl"), mixed_gold_rows)
        mixed_run = _write(os.path.join(d, "mixed-py-run.jsonl"), [py_rows[0], mixed_old])
        mixed_result = pinned_results(mixed_run, gold_path=mixed_gold, boundary=b,
                                      artifacts=py_art, language="python")
        check("a stale seeded recorder among current rows withholds only "
              "that API item and explains the reduced denominator in Markdown",
              mixed_result["coverage"]["n_scored"] == 2
              and mixed_result["api"]["n_scored"] == 1
              and mixed_result["api"]["excluded"]["run_before_api_amendment_2"] == [item("py2")]
              and any("1 candidate and 0 gold recordings lack API Amendment 2" in note
                      for note in notes(mixed_result)))
        wrong_language = py_table(py_art, language="php")
        no_language = py_table(py_art, language=None)
        wrong_directory = py_table(php_art, language="python")
        check("the same directory resolves NOTHING for another language, "
              "for no language, and a PHP directory resolves nothing for "
              "Python -- each naming --prod-index rather than scoring 0.0",
              all(not r["api"]["scored"] and r["prod_index"] is None
                  and r["api"]["reason"] ==
                  "not scored (no production method index; pass "
                  "--prod-index FILE)"
                  for r in (wrong_language, no_language, wrong_directory)),
              str([r["api"]["reason"] for r in
                   (wrong_language, no_language, wrong_directory)]))
        check("the resolver finds only its language's file; missing and "
              "unsupported languages have no default",
              default_prod_index(py_art, "python") == py_index
              and default_prod_index(php_art, "php") == php_index
              and default_prod_index(py_art, "php") is None
              and default_prod_index(php_art, "python") is None
              and default_prod_index(py_art, "ruby") is None
              and default_prod_index(py_art, None) is None,
              str([default_prod_index(py_art, lang)
                   for lang in ("python", "php", "ruby", None)]))

        java_art = os.path.join(d, "java-artifacts")
        os.makedirs(java_art)
        java_index = os.path.join(java_art, "java_prod_index.json")
        java_source = "src/prod/Cart.java"
        java_step = "src/Test/GeneratedTest.java"
        with open(java_index, "w", encoding="utf-8") as fh:
            json.dump({"files": {java_source: {"classes": [
                {"name": "prod.Cart", "methods": [
                    {"name": "total", "descriptor": "()I", "start": 10,
                     "end": 12, "public": True},
                    {"name": "clear", "descriptor": "()V", "start": 14,
                     "end": 16, "public": True}]}]}}}, fh)
        def java_call(method):
            return {"callee_file": java_source, "callee_line": None,
                    "callee": "prod.Cart." + method,
                    "caller_file": java_step}

        java_row = {"item_id": item("java1"), "outcome": "passed",
                    "campaign_digest": "cafe1234cafe1234",
                    "coverage_lines": {java_source: [11]},
                    "direct_calls": [java_call("total:()I")]}
        java_gold = _write(os.path.join(d, "java-gold.jsonl"), [java_row])
        java_run = _write(os.path.join(d, "java-run.jsonl"), [
            dict(java_row, direct_calls=[java_call("total:()I"),
                                         java_call("clear:()V")])])
        java_default = pinned_results(
            java_run, gold_path=java_gold, boundary=b, artifacts=java_art,
            language="java", api_scoring=API_SCORING_METHOD_INDEX)
        java_disabled = pinned_results(
            java_run, gold_path=java_gold, boundary=b, artifacts=java_art,
            language="java", api_scoring=API_SCORING_NONE)
        check("Java discovers its compiled index and scores descriptor "
              "identities, while a disabled profile stays not_measured",
              java_default["prod_index"] == os.path.abspath(java_index)
              and java_default["api"]["scored"]
              and java_default["api"]["n_scored"] == 1
              and java_default["api"]["values"] == {
                  "precision": 0.5, "recall": 1.0, "f1": 2 / 3}
              and java_disabled["api"]["reason"] == NOT_MEASURED_API
              and java_disabled["prod_index"] is None,
              str(java_default["api"]))

        stale_index = os.path.join(d, "stale-index.json")
        with open(stale_index, "w", encoding="utf-8") as fh:
            json.dump({"files": {"src/prod/cart.py": {"classes": [
                {"name": "prod.cart.Cart", "methods": [
                    {"name": "total", "start": 10, "end": 20,
                     "public": True}]}]}}}, fh)
        stale_res = pinned_results(run, gold_path=gold,
                                   prod_index_path=stale_index, boundary=b)
        check("a Python index minted before `decl` withholds the API rows "
              "ALONE: coverage keeps every item and its numbers, and the "
              "API reason names the rebuild instead of filing the items "
              "under run_without_coverage",
              stale_res["coverage"]["scored"]
              and stale_res["coverage"]["n_scored"] == 2
              and stale_res["coverage"]["values"] == res["coverage"]["values"]
              and stale_res["coverage"]["excluded"]["run_without_coverage"]
              == {}
              and not stale_res["api"]["scored"]
              and stale_res["api"]["reason"].startswith(
                  "not scored (invalid production method index)")
              and "`decl`" in stale_res["api"]["reason"]
              and stale_res["api"]["excluded"]["run_without_coverage"] == {}
              and stale_res["prod_index"] == stale_index
              and stale_res["api"]["prod_index"] == stale_index
              and stale_res["api"]["prod_index_files"] == 1
              and stale_res["api"]["prod_index_methods"] == 1,
              f"coverage={stale_res['coverage']}; api={stale_res['api']}")

        partial = _write(
            os.path.join(d, "partial-coverage.jsonl"),
            [dict(r, coverage_lines=None)
             if r["item_id"] == item("p2") else r for r in run_rows])
        partial_res = pinned_results(partial, gold_path=gold,
                              prod_index_path=index, boundary=b)
        partial_rows = {r["key"]: r for r in table_rows(partial_res)}
        check("a partial coverage run scores the supported item in each "
              "metric and names the omitted item instead of scoring it zero",
              partial_res["coverage"]["n_scored"] == 1
              and partial_res["api"]["n_scored"] == 1
              and partial_res["coverage"]["excluded"]
              ["run_without_coverage"] == {item("p2"): "passed"}
              and partial_res["api"]["excluded"]
              ["run_without_coverage"] == {item("p2"): "passed"}
              and set(partial_res["coverage"]["per_item"]) == {item("p1")}
              and set(partial_res["api"]["per_item"]) == {item("p1")}
              and partial_rows["coverage_jaccard"]["number"] == 1.0
              and partial_rows["api_f1"]["number"] == 1.0,
              f"coverage={partial_res['coverage']}; api={partial_res['api']}")

        # 2.6: a run whose records predate the recorder.  Coverage is
        # unaffected and must STAY numeric -- the two rows measure different
        # things, and one of them is still measured here.
        nodirect = _write(
            os.path.join(d, "nodirect.jsonl"),
            [{k: v for k, v in r.items() if k != "direct_calls"}
             for r in run_rows])
        nodirect_res = pinned_results(nodirect, gold_path=gold,
                                      prod_index_path=index, boundary=b)
        nodirect_rows = {r["key"]: r for r in table_rows(nodirect_res)}
        check("a run with no `direct_calls` says so on the API rows, keeps "
              "coverage numeric, and never falls back to it",
              not nodirect_res["api"]["scored"]
              and nodirect_res["api"]["reason"] == NOT_SCORED_API_DIRECT
              and nodirect_res["api"]["n_scored"] == 0
              and nodirect_res["api"]["excluded"]["run_without_direct_calls"]
              == [item("p1"), item("p2")]
              and all(nodirect_rows[k]["value"] == NOT_SCORED_API_DIRECT
                      and nodirect_rows[k]["number"] is None
                      for k in ("api_precision", "api_recall", "api_f1"))
              and nodirect_res["coverage"]["scored"]
              and nodirect_rows["coverage_jaccard"]["number"] == 0.75,
              str(nodirect_res["api"]))
        index_provenance = {"prod_index": index, "prod_index_files": 2,
                            "prod_index_methods": 3}
        check("an unscored API block still names the index it loaded and "
              "its sizes, in data and rendering",
              nodirect_res["prod_index"] == index
              and all(nodirect_res["api"].get(key) == value
                      for key, value in index_provenance.items())
              and f"{index}  (2 files, 3 methods)"
              in render_text(nodirect_res), str(nodirect_res["api"]))

        halfdirect = _write(
            os.path.join(d, "halfdirect.jsonl"),
            [{k: v for k, v in r.items() if k != "direct_calls"}
             if r["item_id"] == item("p2") else r for r in run_rows])
        half_res = pinned_results(halfdirect, gold_path=gold,
                                  prod_index_path=index, boundary=b)
        half_rows = {r["key"]: r for r in table_rows(half_res)}
        check("the API block's n_scored can be SMALLER than coverage's, and "
              "both are printed rather than one standing for the other",
              half_res["coverage"]["n_scored"] == 2
              and half_res["api"]["n_scored"] == 1
              and half_res["api"]["excluded"]["run_without_direct_calls"]
              == [item("p2")]
              and set(half_res["api"]["per_item"]) == {item("p1")}
              and half_rows["api_f1"]["number"] == 1.0
              and half_rows["coverage_jaccard"]["number"] == 0.75
              and any("api rows are over 1 of the 2 passed instance(s)" in n
                      and "A further 1 carry no `direct_calls`" in n
                      for n in notes(half_res)),
              f"api={half_res['api']}; notes={notes(half_res)}")

        # The unmapped count is a diagnostic of the INDEX, so it is summed
        # over every coverage-compared item and not only the API-scored
        # ones: an item whose gold calls ALL failed to map is excluded from
        # the API rows as `gold_no_direct_methods`, and it is exactly the
        # item the count is there to expose.
        ghost = call("src/Prod/Cart.php", 99, "App\\Cart::gone")
        ghost_gold = _write(
            os.path.join(d, "ghost-gold.jsonl"),
            [dict(g, direct_calls=[ghost]) if g["item_id"] == item("p2")
             else g for g in gold_rows])
        ghost_run = _write(
            os.path.join(d, "ghost-run.jsonl"),
            [dict(r, direct_calls=list(P2_CALLS) + [ghost])
             if r["item_id"] == item("p2") else r for r in run_rows])
        ghost_res = pinned_results(ghost_run, gold_path=ghost_gold,
                                   prod_index_path=index, boundary=b)
        check("unmapped direct events are counted over every compared item, "
              "including one the API rows exclude because its gold calls all "
              "failed to map",
              ghost_res["api"]["scored"]
              and ghost_res["api"]["n_scored"] == 1
              and ghost_res["api"]["excluded"]["gold_no_direct_methods"]
              == [item("p2")]
              and ghost_res["api"]["unmapped_direct_events"]
              == {"gold": 1, "run": 1}
              and any("unmapped direct events over every coverage-compared "
                      "item: gold 1, run 1" in n for n in notes(ghost_res)),
              str(ghost_res["api"]))

        allghost_gold = _write(
            os.path.join(d, "allghost-gold.jsonl"),
            [dict(g, direct_calls=[ghost]) for g in gold_rows])
        allghost_res = pinned_results(ghost_run, gold_path=allghost_gold,
                                      prod_index_path=index, boundary=b)
        check("...and when EVERY compared item is API-excluded the "
              "diagnostic still travels on the unscored block, in the JSON "
              "and in the notes",
              not allghost_res["api"]["scored"]
              and allghost_res["api"]["reason"]
              == ("not scored (every scorable gold run invokes no "
                  "production method directly)")
              and allghost_res["api"]["excluded"]["gold_no_direct_methods"]
              == [item("p1"), item("p2")]
              and allghost_res["api"]["unmapped_direct_events"]
              == {"gold": 2, "run": 1}
              and json.loads(render_json(allghost_res))["api"]
              ["unmapped_direct_events"] == {"gold": 2, "run": 1}
              and any("api sets: none scored; unmapped direct events over "
                      "every coverage-compared item: gold 2, run 1" in n
                      for n in notes(allghost_res)),
              str(allghost_res["api"]))

        stale_path = sidecar_for(
            run, sidecar({item("other_item"): TQ_ITEMS[item("p1")]}), "stale.json")
        stale = pinned_results(run, gold_path=gold, prod_index_path=index,
                        test_quality_path=stale_path, boundary=b)
        check("a sidecar from ANOTHER sweep is withheld, not averaged",
              not stale["mutation"]["scored"]
              and "another sweep" in stale["mutation"]["reason"],
              str(stale["mutation"]["reason"]))

        nocov = _write(os.path.join(d, "nocov.jsonl"),
                       [dict(r) for r in run_rows if r["outcome"] != "passed"]
                       + [{"item_id": item("p1"), "outcome": "passed",
                           "campaign_digest": "cafe1234cafe1234"},
                          {"item_id": item("p2"), "outcome": "passed",
                           "campaign_digest": "cafe1234cafe1234"}])
        nocov_tq = sidecar_for(nocov, sidecar(TQ_ITEMS), "nocov-tq.json")
        res_nocov = pinned_results(nocov, gold_path=gold, prod_index_path=index,
                            test_quality_path=nocov_tq, boundary=b)
        cell = {r["key"]: r for r in table_rows(res_nocov)}
        check("a run without coverage says so on the coverage and api rows, "
              "and scores no zero",
              NOT_SCORED_COVERAGE in cell["coverage_jaccard"]["value"]
              and NOT_SCORED_COVERAGE in cell["api_f1"]["value"]
              and cell["api_f1"]["number"] is None,
              cell["coverage_jaccard"]["value"])
        check("a run without coverage still has a full ladder and mutation "
              "rows",
              res_nocov["ladder"]["sums_to_denominator"]
              and res_nocov["mutation"]["scored"])

        off = _write(os.path.join(d, "off.jsonl"),
                     [dict(r, coverage=False) if r["outcome"] == "passed"
                      else r for r in run_rows])
        res_off = pinned_results(off, gold_path=gold, prod_index_path=index,
                          boundary=b)
        check("a PASSED row stamped coverage=false is refused, not scored 0",
              not res_off["coverage"]["scored"]
              and "--coverage" in res_off["coverage"]["reason"],
              str(res_off["coverage"]["reason"]))
        check("a loaded index survives both whole-run and all-item "
              "coverage exclusions without scoring API",
              all(not result["api"]["scored"]
                  and result["api"]["values"] is None
                  and result["prod_index"] == index
                  and all(result["api"].get(key) == value
                          for key, value in index_provenance.items())
                  for result in (res_nocov, res_off)))

        nopass = _write(os.path.join(d, "nopass.jsonl"),
                        [r for r in run_rows if r["outcome"] != "passed"])
        nopass_tq = sidecar_for(nopass, sidecar({}), "nopass-tq.json")
        res_np = pinned_results(nopass, gold_path=gold, prod_index_path=index,
                         test_quality_path=nopass_tq, boundary=b)
        cell = {r["key"]: r for r in table_rows(res_np)}
        check("0 passed: every quality row is n/a, never 0.0",
              all(cell[k]["value"] == NO_PASS and cell[k]["number"] is None
                  for k, _l, _b, _n in QUALITY_ROWS),
              str({k: cell[k]["value"] for k, _l, _b, _n in QUALITY_ROWS}))
        check("0 passed: the ladder still reports every instance",
              res_np["ladder"]["sums_to_denominator"] and res_np["n"] == 14
              and res_np["ladder"]["denominator"] == 9
              and res_np["ladder"]["rows"][-1]["count"] == 0)
        check("0 passed: no division by zero anywhere in the rendering",
              "n/a (0 passed)" in render_text(res_np)
              and "n/a (0 passed)" in render_markdown(res_np))

        # ------------------------- passes covering production code (S6)
        #
        # The whole point of the diagnostic is the THIRD state.  A pass that
        # covered no production line and a pass nobody measured are different
        # findings, and printing the second as the first would accuse the
        # evaluated system of writing a vacuous test on the strength of a run
        # launched without `--coverage`.
        pc = res["production_coverage"]
        check("both passes of the ordinary fixture touch production code, "
              "over the same denominator the pass rate uses",
              pc["scored"] and pc["n_covering"] == 2
              and pc["n_zero_production_lines"] == 0
              and pc["n_not_collected"] == 0
              and pc["denominator"] == res["ladder"]["denominator"] == 11
              and abs(pc["rate"] - 2 / 11) < 1e-12, str(pc))

        vacuous = _write(
            os.path.join(d, "vacuous.jsonl"),
            [dict(r, coverage_lines={"src/Test/GeneratedTest.php": [1, 2]})
             if r["item_id"] == item("p2") else r for r in run_rows])
        res_vac = pinned_results(vacuous, gold_path=gold,
                                 prod_index_path=index, boundary=b)
        pc_vac = res_vac["production_coverage"]
        vac_rows = {r["key"]: r for r in table_rows(res_vac)}
        check("a pass whose coverage is entirely inside the removable test "
              "tree covered ZERO production lines and is counted as such",
              pc_vac["scored"] and pc_vac["n_covering"] == 1
              and pc_vac["n_zero_production_lines"] == 1
              and pc_vac["n_not_collected"] == 0
              and pc_vac["zero_production_line_items"] == [item("p2")]
              and abs(pc_vac["rate"] - 1 / 11) < 1e-12, str(pc_vac))
        check("...and the pass rate does NOT move: the diagnostic reports a "
              "property of the passing tests, it does not reclassify them",
              vac_rows["pass_rate"]["value"]
              == {r["key"]: r for r in table_rows(res)}["pass_rate"]["value"]
              == "18.2% (2/11)", vac_rows["pass_rate"]["value"])
        check("the diagnostic is not a canonical row in any rendering",
              [r["key"] for r in vac_rows.values()]
              == [k for k, _l, _o in LADDER]
                 + [k for k, _l, _b, _n in QUALITY_ROWS]
              and "production_coverage" not in vac_rows
              and PRODUCTION_COVERAGE_LABEL not in
                  render_markdown_legacy(res_vac),
              str(list(vac_rows)))
        vac_renderings = {fmt: render(res_vac, fmt)
                          for fmt in ("text", "markdown", "json")}
        check("every labelled rendering carries the diagnostic and says it "
              "is one",
              all("9.1% (1/11)" in rendered and "DIAGNOSTIC" in rendered
                  for rendered in vac_renderings.values()),
              str({fmt: PRODUCTION_COVERAGE_LABEL.upper() in rendered
                   for fmt, rendered in vac_renderings.items()}))

        pc_nocov = res_nocov["production_coverage"]
        check("a run recorded without coverage withholds the rate and is "
              "NOT reported as covering zero production lines",
              not pc_nocov["scored"] and pc_nocov["rate"] is None
              and pc_nocov["n_not_collected"] == 2
              and pc_nocov["n_zero_production_lines"] == 0
              and pc_nocov["n_covering"] == 0
              and NOT_SCORED_COVERAGE in pc_nocov["reason"]
              and "not the same finding" in pc_nocov["reason"], str(pc_nocov))
        check("...and its rendering says which of the two it is",
              "not the same finding as covering no production line"
              in render_text(res_nocov), str(pc_nocov["reason"]))

        mixed = _write(
            os.path.join(d, "mixed-coverage.jsonl"),
            [dict(r, coverage_lines={}) if r["item_id"] == item("p1")
             else {k: v for k, v in r.items() if k != "coverage_lines"}
             if r["item_id"] == item("p2") else r for r in run_rows])
        pc_mixed = pinned_results(
            mixed, gold_path=gold, prod_index_path=index,
            boundary=b)["production_coverage"]
        check("one measured zero beside one unmeasured pass keeps both "
              "counts and still refuses to divide",
              not pc_mixed["scored"] and pc_mixed["rate"] is None
              and pc_mixed["n_zero_production_lines"] == 1
              and pc_mixed["zero_production_line_items"] == [item("p1")]
              and pc_mixed["n_not_collected"] == 1
              and pc_mixed["not_collected_items"] == [item("p2")],
              str(pc_mixed))

        pc_off = res_off["production_coverage"]
        check("a PASSED row stamped coverage=false is unmeasured here too, "
              "for the same reason the coverage rows refuse it",
              not pc_off["scored"] and pc_off["n_not_collected"] == 2
              and pc_off["n_zero_production_lines"] == 0, str(pc_off))
        pc_np = res_np["production_coverage"]
        check("0 passed: the diagnostic says so and never divides by the "
              "ladder to print 0.0%",
              not pc_np["scored"] and pc_np["rate"] is None
              and pc_np["reason"] == NO_PASS
              and NO_PASS in render_text(res_np), str(pc_np))

        nogold = pinned_results(run, gold_path=None, prod_index_path=index,
                         test_quality_path=tq_path, boundary=b,
                         artifacts=os.path.join(d, "absent"))
        check("no gold run: the coverage and api rows name the missing input",
              not nogold["coverage"]["scored"]
              and "--gold" in nogold["coverage"]["reason"],
              str(nogold["coverage"]["reason"]))
        check("no gold run: the ladder and the mutation rows are unaffected",
              nogold["ladder"]["sums_to_denominator"]
              and nogold["mutation"]["scored"])
        disabled_index = pinned_results(
            run, gold_path=gold, prod_index_path=index, boundary=b,
            api_scoring=API_SCORING_NONE)
        invalid_index_path = _write(os.path.join(d, "invalid-index.json"),
                                    [{"files": []}])
        invalid_index = pinned_results(
            run, gold_path=gold, prod_index_path=invalid_index_path, boundary=b)
        check("API-disabled, absent, invalid, and pre-load exclusions "
              "never claim an index was loaded",
              disabled_index["api"]["reason"] == NOT_MEASURED_API
              and "invalid production method index"
              in invalid_index["api"]["reason"]
              and all(result["prod_index"] is None
                      and not (set(index_provenance) & set(result["api"]))
                      for result in (docx, disabled_index, missing_index,
                                     invalid_index, res_np, nogold)))
        check("the gold TREE passed where the gold RUN belongs is refused",
              _raises(lambda: pinned_results(run, gold_path=d, boundary=b),
                      "not the gold tree"))
        check("a missing run file raises rather than printing an empty table",
              _raises(lambda: pinned_results(os.path.join(d, "nope.jsonl"),
                                      boundary=b), "no such run file"))
        duplicate = _write(os.path.join(d, "duplicate.jsonl"),
                           run_rows + [dict(run_rows[0], outcome="failed")])
        check("canonical results refuses duplicate item ids before the "
              "last-row-wins retry reader can hide one",
              _raises(lambda: pinned_results(duplicate, gold_path=gold,
                                      prod_index_path=index, boundary=b),
                      "duplicate item_id"))
        malformed_rows = [dict(r) for r in run_rows]
        malformed_rows[0].pop("item_id")
        malformed = _write(os.path.join(d, "malformed-id.jsonl"),
                           malformed_rows)
        check("canonical results shares the fail-closed item-id gate, so a "
              "missing id cannot become a blank project or denominator",
              _raises(lambda: pinned_results(malformed, gold_path=gold,
                                      prod_index_path=index, boundary=b),
                      "non-empty string"))
        duplicate_gold = _write(
            os.path.join(d, "duplicate-gold.jsonl"),
            gold_rows + [dict(gold_rows[0], outcome="failed")])
        check("the gold run is a publication input too, so its duplicate ids "
              "cannot be hidden by the same retry reader",
              _raises(lambda: pinned_results(run, gold_path=duplicate_gold,
                                      prod_index_path=index, boundary=b),
                      "duplicate item_id"))

        # A gold run that itself has no coverage for a passed item: the item
        # has no upper bound, so it must leave the aggregate AND be named.
        halfgold = _write(os.path.join(d, "halfgold.jsonl"),
                          [row("p1", "passed", dict(GOLD_COV)),
                           row("p2", "timeout", None)]
                          + [row(r["item_id"], "passed", dict(GOLD_COV))
                             for r in run_rows
                             if r["item_id"] not in (item("p1"), item("p2"))])
        res_hg = pinned_results(run, gold_path=halfgold, prod_index_path=index,
                         test_quality_path=tq_path, boundary=b)
        check("a passed item with no gold upper bound is excluded and named",
              res_hg["coverage"]["n_scored"] == 1
              and res_hg["coverage"]["excluded"]
              ["gold_without_coverage"] == {item("p2"): "timeout"}
              and res_hg["api"]["excluded"]
              ["gold_without_coverage"] == {item("p2"): "timeout"},
              str(res_hg["coverage"]["excluded"]))
        check("and the note says the row is over fewer than the passes",
              any("1 of the 2 passed" in n for n in notes(res_hg)),
              str(notes(res_hg)))

        # ------------------------------------------------- repeat draws
        #
        # The table must DISCLOSE a re-drawn instance -- not exclude it (that
        # would move a denominator fixed before execution) and not swallow it
        # (which is what A5 cell 4 shipped: a candidate-caused second draw
        # printed exactly like the other 31 first-draw passes).
        check("a table of first draws says nothing about draws",
              res["draws"]["n_repeat"] == 0
              and not any("REPEAT DRAW" in n for n in notes(res)),
              str(res["draws"]))
        redrawn = _write(os.path.join(d, "redrawn.jsonl"),
                         [dict(r, **({"draw": {
                             "n": 2, "reason": "candidate_caused",
                             "prior_outcomes": ["harness_error"],
                             "evidence": []}} if r["item_id"] == item("p1") else {}))
                          for r in run_rows])
        res_rd = pinned_results(redrawn, gold_path=gold, prod_index_path=index,
                         boundary=b)
        note = " ".join(notes(res_rd))
        check("a table containing one names it, with the count and the reason "
              "class, and says the row is still IN every number",
              res_rd["draws"]["by_reason"] == {"candidate_caused": 1}
              and "REPEAT DRAWS: 1 of" in note and "candidate_caused" in note
              and "INCLUDED in every number" in note, note)
        check("...and the thirteen-row payload is untouched by the disclosure, "
              "which is why it renders below the table and not in it",
              markdown_payload_lines(res_rd)
              == markdown_payload_lines(pinned_results(
                  _write(os.path.join(d, "plain.jsonl"), run_rows),
                  gold_path=gold, prod_index_path=index, boundary=b)))
        hand_edited = _write(os.path.join(d, "handedited.jsonl"),
                             [dict(r, **({"draw": {"n": 2, "reason": "rerun"}}
                                         if r["item_id"] == item("p1") else {}))
                              for r in run_rows])
        check("a MALFORMED stamp stops the table rather than reading as a "
              "first draw -- absence is the grandfathered case, a stamp "
              "nobody can parse is not",
              _raises(lambda: pinned_results(hand_edited, gold_path=gold,
                                      prod_index_path=index, boundary=b),
                      "not one of"))

        # ------------------------------ the campaign attestation, at read time
        # `write_merged` leaves a digest OF THE ROWS FILE beside a merge so a
        # reader can check the pair rather than assume it.  This table prints
        # that provenance; if the bytes moved, every line of it is about a
        # different file.  Silent when the pair holds.
        merged = _write(os.path.join(d, "merged.jsonl"), run_rows)
        with open(merged + draws.CAMPAIGN_SIDECAR_SUFFIX, "w",
                  encoding="utf-8") as fh:
            json.dump({"campaign_digest": "deadbeefdeadbeef",
                       "n": len(run_rows),
                       "rows_digest": draws._rows_digest(merged)}, fh)
        check("a merged run its sidecar still describes tabulates exactly as "
              "one without a sidecar does",
              markdown_payload_lines(
                  pinned_results(merged, gold_path=gold, prod_index_path=index,
                          boundary=b))
              == markdown_payload_lines(
                  pinned_results(run, gold_path=gold, prod_index_path=index,
                          boundary=b)))
        _write(merged, [dict(r, n_files=(r.get("n_files") or 0) + 1)
                        for r in run_rows])
        check("...and once the rows are not the rows the campaign attested "
              "to, there is no table at all -- the provenance block would "
              "otherwise cite a fingerprint for bytes that are gone",
              _raises(lambda: pinned_results(merged, gold_path=gold,
                                      prod_index_path=index, boundary=b),
                      "re-merge the shards"))

        # ------------------- the checked-interface secondary rows (6.2/6.3)
        # Region: p1's target is Cart 11 (gold covers it), p2's is Cart 10,
        # the failed item's is Cart 10-11, and one item's region is a Tax
        # line gold never ran -- the not_scorable case.
        regions_path = os.path.join(d, "regions.json")
        with open(regions_path, "w", encoding="utf-8") as fh:
            json.dump({"schema": M.TARGET_REGIONS_SCHEMA, "project": "t",
                       "items": {item("p1"): {"src/Prod/Cart.php": [11]},
                                 item("p2"): {"src/Prod/Cart.php": [10]},
                                 item("i_failed"):
                                     {"src/Prod/Cart.php": [10, 11]},
                                 item("i_timeout"):
                                     {"src/Prod/Tax.php": [9]}}}, fh)
        items_path = os.path.join(d, "items.jsonl")
        _write(items_path, [
            {"item_id": item("p1"), "checked_interfaces": {
                "checked": [{"key": ["App\\Cart", "total"],
                             "declaration": "public function total()"}],
                "empty_reason": None}},
            {"item_id": item("p2"), "checked_interfaces": {
                "checked": [{"key": ["App\\Cart", "total"],
                             "declaration": "public function total()"}],
                "empty_reason": None}},
            # Everything gold called is disclosed: nothing left to score.
            {"item_id": item("i_failed"), "checked_interfaces": {
                "checked": [{"key": ["App\\Cart", "total"],
                             "declaration": "public function total()"},
                            {"key": ["App\\Tax", "rate"],
                             "declaration": "public function rate()"}],
                "empty_reason": None}}])
        floors_path = os.path.join(d, "floors.json")
        with open(floors_path, "w", encoding="utf-8") as fh:
            json.dump({"schema": M.CONTROL_FLOORS_SCHEMA, "project": "t",
                       "n_gold_items": 16, "api_scored": True,
                       "target_regions_scored": True,
                       "floors": {"sibling_gold": {
                           "line_recall_typical": {"median": 0.999, "n": 14},
                           "target_region_recall_typical":
                               {"median": 0.0, "n": 12},
                           "n_items_without_sibling": 2},
                           "assertion_stripped_gold": None, "stub": None}}, fh)

        plain = pinned_results(run, gold_path=gold, prod_index_path=index,
                               boundary=b)
        sec_res = pinned_results(run, gold_path=gold, prod_index_path=index,
                                 boundary=b,
                                 target_regions_path=regions_path,
                                 items_path=items_path,
                                 control_floors_path=floors_path)
        check("without its own inputs the secondary block does not exist and "
              "the table is the one every pinned rendering already has",
              "secondary" not in plain and not secondary_rows(plain))
        canonical = {row["key"] for row in table_rows(plain)}
        check("...and adding the block moves NO canonical row: the thirteen "
              "render byte-for-byte as they did",
              [row for row in table_rows(sec_res) if row["key"] in canonical]
              == table_rows(plain))
        rows_by_key = {row["key"]: row for row in table_rows(sec_res)}
        region = sec_res["secondary"]["target_region"]
        check("target-region recall is the mean over the items whose gold "
              "covers a region line AND whose candidate ran",
              region["scored"] and region["n_scored"] == 2
              and region["values"]["recall"] == 1.0, str(region["values"]))
        check("the reaches-target denominator counts the item that never ran "
              "-- a crash does not reach the target",
              region["n_items"] == 3
              and region["values"]["reaches_rate"] == 2 / 3
              and region["per_item"]["reaches_target"][item("i_failed")]
              is False, str(region))
        check("an item whose gold covers no region line is not_scorable and "
              "named, never scored 0.0",
              region["excluded"][M.REGION_NO_GOLD_LINES] == [item("i_timeout")]
              and item("i_timeout") not in region["per_item"]["recall"],
              str(region["excluded"]))
        check("an item absent from the target map is counted separately from "
              "one the map covers and gold never entered",
              len(region["excluded"]["not_in_target_map"]) == 12,
              str(len(region["excluded"]["not_in_target_map"])))
        undisclosed = sec_res["secondary"]["undisclosed_api"]
        check("the undisclosed-api row scores D_G \\ I against D_C \\ I: p1 "
              "agrees on Tax::rate, p2 called Cart::clear instead",
              undisclosed["scored"] and undisclosed["n_scored"] == 2
              and undisclosed["per_item"][item("p1")]["f1"] == 1.0
              and undisclosed["per_item"][item("p2")]["f1"] == 0.0
              and undisclosed["values"]["f1"] == 0.5, str(undisclosed))
        check("a candidate that never ran leaves this row with the API "
              "axis's own reason, not with a score of 0.0",
              undisclosed["excluded"]["api_not_defined"] == [item("i_failed")],
              str(undisclosed["excluded"]))
        check("an item with no `checked_interfaces` field is excluded by "
              "name, not treated as disclosing nothing",
              len(undisclosed["excluded"]["no_checked_interfaces"]) == 13)
        # The fully-disclosed case needs a PASSED item whose whole gold set is
        # disclosed, which the sixteen-row fixture has no third pass for; the
        # block is a public function, so it is asked directly.
        fully = secondary(
            M.read_runs(run), {item("p1"), item("p2")}, gold, index, b,
            disclosed={item("p1"): {("App\\Cart", "total"),
                                    ("App\\Tax", "rate")},
                       item("p2"): {("App\\Cart", "total")}})["undisclosed_api"]
        check("an item whose whole gold call set is disclosed leaves the row "
              "with a reason, exactly as an empty D_G does",
              fully["excluded"][M.UNDISCLOSED_FULLY_DISCLOSED] == [item("p1")]
              and fully["n_scored"] == 1, str(fully))
        full = sec_res["secondary"]["full_denominator"]
        check("the full-denominator companion counts the failures: two "
              "passes of sixteen items scored, the rest substituted",
              full["scored"] and full["n_items"] == 16 and full["n_scored"] == 2
              and full["values"]["coverage.micro_jaccard"]
              == (1.0 + 0.5) / 16, str(full["values"]))
        check("...and the passed-only mean travels beside it, never instead "
              "of it",
              full["passed_only"]["coverage.micro_jaccard"] == 0.75
              and full["passed_only"]["coverage.micro_jaccard"]
              == res["coverage"]["values"]["jaccard"],
              str(full["passed_only"]))
        check("`excess` is substituted at 1.0 and everything else at 0.0 -- "
              "`summarise`'s polarity, not a second copy of it",
              full["undefined_score"] == M.UNDEFINED_SCORE
              and full["values"]["coverage.excess"]
              > full["passed_only"]["coverage.excess"], str(full["values"]))
        check("the rendered secondary rows carry the numbers, below the "
              "thirteen and labelled with their denominator",
              rows_by_key["target_region_recall"]["value"] == "1.000"
              and rows_by_key["reaches_target_rate"]["value"] == "0.667"
              and rows_by_key["undisclosed_api_f1"]["value"] == "0.500"
              and rows_by_key["coverage_jaccard_over_total"]["value"]
              == "0.094", str(rows_by_key["coverage_jaccard_over_total"]))
        check("no closure-cluster map means no interval, and the descriptive "
              "mean is still printed",
              rows_by_key["target_region_recall"]["interval"] is None
              and rows_by_key["target_region_recall"]["interval_reason"]
              == INTERVAL_NO_CLUSTERS)
        clustered = secondary(
            M.read_runs(run), {item("p1"), item("p2")}, gold, index, b,
            regions=M.load_target_regions(regions_path),
            cluster_map={row["item_id"]: "c" + row["item_id"]
                         for row in run_rows})["target_region"]
        check("a corpus below the preregistered 20-cluster floor withholds "
              "the INTERVAL and keeps the number, naming the floor",
              clustered["intervals"]["recall"] is None
              and f"at least {M.MIN_INFERENCE_CLUSTERS}"
              in clustered["interval_notes"]["recall"]
              and clustered["values"]["recall"] == 1.0, str(clustered))
        text = render_text(sec_res)
        check("the floors table renders as its own labelled block, with each "
              "median's item count",
              "MEASURED FLOORS" in text
              and "median 0.999  (n=14)" in text
              and "not supplied" in text, text)
        stripped_head = control_floors_lines(
            {"project": "t", "n_gold_items": 3,
             "floors": {"assertion_stripped_gold": {
                 "n_rows": 3, "n_construction_refused": 1, "n_scored": 2,
                 "n_passed": 1}}})[2]
        check("...and a stripped floor says how many of its rows were "
              "refused constructions, counted and not scored",
              stripped_head.endswith("(2 item(s) scored of 3 row(s), 1 "
                                     "passed, 1 refused construction and "
                                     "not scored)"), stripped_head)
        note = " ".join(notes(sec_res))
        check("the notes say what the full denominator is and that it is not "
              "comparable with the passed-only rows above",
              "full denominator` are over 16 item(s)" in note
              and "not comparable with the passed-only quality rows" in note,
              note)
        check("...and each secondary row's note states ITS OWN denominator: "
              "recall over the 2 that ran, reaches-target over all 3, with "
              "the item recorded without coverage disclosed, not folded in",
              "its denominator is 2 item(s) whose candidate ran" in note
              and "1 further scorable item(s) were recorded without coverage"
              in note
              and "over all 3 scorable item(s)" in note, note)

        one_input = pinned_results(run, gold_path=gold, prod_index_path=index,
                                   boundary=b, items_path=items_path)
        check("one input alone renders its own row and withholds the others "
              "by name, rather than withholding the block",
              {row["key"]: row["value"] for row in secondary_rows(one_input)}
              ["target_region_recall"] == NO_TARGET_REGIONS
              and one_input["secondary"]["undisclosed_api"]["scored"])

        stale_items = _write(os.path.join(d, "stale_items.jsonl"), [
            {"item_id": item("p1"), "checked_interfaces": {
                "checked": [{"key": ["App\\Cart"], "declaration": "class"}],
                "empty_reason": None}}])
        check("a disclosed key the pinned index does not know REFUSES the "
              "table rather than subtracting nothing and printing the "
              "ordinary api row under this row's label",
              _raises(lambda: pinned_results(
                  run, gold_path=gold, prod_index_path=index, boundary=b,
                  items_path=stale_items), "absent from the pinned"))

    TQ.load_bound_test_quality = _real_tq_loader

    # ------------------------------- THE COMPATIBILITY GATE, on REAL data
    #
    # The synthetic check above proves the two renderers agree with each
    # other.  Only this one proves that neither of them has changed what the
    # PUBLISHED table says -- a relabelled rung or a different rounding would
    # pass every check above and quietly restate every percentage in the
    # paper.  Guarded because the archived run is an artifact of the machine
    # that produced it and is not in the repository; the skip is printed, so
    # a green selftest on a machine without it is never mistaken for a pass.
    rel = os.path.relpath(LEGACY_FIXTURE, BENCHMARK)
    wrapper = os.environ.get(LEGACY_PIN_ENV) or ""
    if wrapper:
        verdict = legacy_pin_verdict(wrapper)
        check(f"PC8: the standard-setting run still renders as the frozen "
              f"payload in {rel} on its nine non-API rows, through the "
              f"wrapper supplied in ${LEGACY_PIN_ENV}",
              verdict is True, str(verdict))
    else:
        # NOT silent, and not a pass.  Named as UNARMED with the exact input
        # that arms it, because "could not be checked" and "was checked and
        # agreed" are the two states this line has to keep apart -- report
        # §6.1 called the disarmed state an "intended fail-closed result",
        # which is the reading this wording exists to prevent.
        print(f"  [UNARMED] PC8: the byte-for-byte pin on {rel} was NOT "
              f"executed: {legacy_pin_verdict(None)}")
    # Beside the verdict either way: the pin no longer compares these three,
    # so they are SHOWN as what they are rather than quietly dropped.
    _legacy_api = legacy_api_rows()
    print(f"  [INFO] PC8: the API rows of {rel} are {_legacy_api['label']} "
          f"evidence from harness version {_legacy_api['harness_version']} "
          f"and are not compared: "
          + ", ".join(f"{label} {value}"
                      for label, value in _legacy_api["rows"].items()))

    # PC8's failure modes, on synthetic inputs, so they are checked on every
    # machine including the ones with no archive.  Each is a NAMED failure
    # rather than an exception or a skip -- that distinction is the whole of
    # R4 item 9, and a test that only covered the happy path would leave it
    # exactly as unproven as the disarmed pin was.
    with tempfile.TemporaryDirectory() as d:
        pin_run = os.path.join(d, "pin.jsonl")
        _write(pin_run, [{
            "item_id": "coreshop/features/domain/p1.feature:1",
            "outcome": "passed", "campaign_digest": "cafe1234cafe1234",
            "coverage_lines": dict(GOLD_COV),
        }])
        pin_fixture = os.path.join(d, "frozen.md")
        with open(pin_fixture, "w", encoding="utf-8") as fh:
            fh.write("| metric | value |\n")
        missing_wrapper = os.path.join(d, "not-there.json")
        check("PC8: a MISSING wrapper fails by name, naming the path",
              legacy_pin_verdict(missing_wrapper, run_path=pin_run,
                                 fixture_path=pin_fixture)
              == f"the supplied test-quality wrapper is not a regular file: "
                 f"{missing_wrapper}")
        os.mkdir(os.path.join(d, "a-directory.json"))
        check("PC8: a wrapper path that is not a regular file fails by name, "
              "never with a traceback out of json.load",
              isinstance(legacy_pin_verdict(
                  os.path.join(d, "a-directory.json"), run_path=pin_run,
                  fixture_path=pin_fixture), str))
        stale = os.path.join(d, "stale.json")
        with open(stale, "w", encoding="utf-8") as fh:
            json.dump({"schema": TQ.TEST_QUALITY_SUMMARY_SCHEMA,
                       "per_item": {}}, fh)
        stale_verdict = legacy_pin_verdict(stale, run_path=pin_run,
                                           fixture_path=pin_fixture,
                                           artifacts=d)
        check("PC8: a STALE wrapper -- one with no current binding to these "
              "run bytes -- fails by name and says what did not validate",
              isinstance(stale_verdict, str)
              and stale_verdict.startswith("the wrapper did not validate:"),
              str(stale_verdict))
        tampered = os.path.join(d, "tampered.json")
        with open(tampered, "w", encoding="utf-8") as fh:
            json.dump({"schema": TQ.TEST_QUALITY_SUMMARY_SCHEMA,
                       "binding": {"schema": TQ.TEST_QUALITY_BINDING_SCHEMA,
                                   "run_sha256": "0" * 64,
                                   "generated_tests_sha256": "0" * 64},
                       "per_item": {}}, fh)
        tampered_verdict = legacy_pin_verdict(tampered, run_path=pin_run,
                                              fixture_path=pin_fixture,
                                              artifacts=d)
        check("PC8: a TAMPERED wrapper -- a binding that does not hash to "
              "these bytes -- fails by name, not by silently rendering",
              isinstance(tampered_verdict, str)
              and "stale or tampered" in tampered_verdict,
              str(tampered_verdict))
        check("PC8: an UNSUPPLIED wrapper is reported as inert with the exact "
              "input that would arm it, never as a pass",
              legacy_pin_verdict(None) is not True
              and LEGACY_PIN_ENV in legacy_pin_verdict(None)
              and "--coreshop-test-quality-wrapper"
              in legacy_pin_verdict(None))

        mismatch_wrapper = os.path.join(d, "mismatch.json")
        with open(mismatch_wrapper, "w", encoding="utf-8") as fh:
            fh.write("{}\n")
        with open(LEGACY_FIXTURE, encoding="utf-8") as fh:
            frozen_payload = fh.read()
        rendered_payload = frozen_payload.replace(
            "| pass rate | 5.0% (5/100) |",
            "| pass rate | 6.0% (6/100) |")
        real_results, real_render = results, render
        try:
            globals()["results"] = lambda *_args, **_kwargs: {}
            globals()["render"] = lambda *_args, **_kwargs: rendered_payload
            mismatch = legacy_pin_verdict(
                mismatch_wrapper, run_path=pin_run, artifacts=d)
        finally:
            globals()["results"] = real_results
            globals()["render"] = real_render
        frozen_label = os.path.relpath(LEGACY_FIXTURE,
                                       os.path.dirname(BENCHMARK))
        check("PC8: a byte mismatch returns a unified diff against the named "
              "frozen fixture",
              isinstance(mismatch, str)
              and f"--- {frozen_label}\n" in mismatch
              and "+++ rendered\n" in mismatch
              and "-| pass rate | 5.0% (5/100) |\n" in mismatch
              and "+| pass rate | 6.0% (6/100) |\n" in mismatch,
              str(mismatch))

        # §7.1, on a synthetic legacy-shaped rendering: what the current code
        # actually produces for that run now is nine reproduced rows and
        # three that cannot be computed from it at all.
        no_api_payload = frozen_payload
        for label, value in legacy_api_rows()["rows"].items():
            no_api_payload = no_api_payload.replace(
                f"| {label} | {value} |",
                f"| {label} | {NOT_SCORED_API_DIRECT} |")
        try:
            globals()["results"] = lambda *_args, **_kwargs: {}
            globals()["render"] = lambda *_args, **_kwargs: no_api_payload
            narrowed = legacy_pin_verdict(mismatch_wrapper,
                                          run_path=pin_run, artifacts=d)
            globals()["render"] = lambda *_args, **_kwargs: (
                no_api_payload.replace("| pass rate | 5.0% (5/100) |",
                                       "| pass rate | 6.0% (6/100) |"))
            narrowed_bad = legacy_pin_verdict(mismatch_wrapper,
                                              run_path=pin_run, artifacts=d)
        finally:
            globals()["results"] = real_results
            globals()["render"] = real_render
        check("PC8 §7.1: the three API rows are no longer compared, so a "
              "rendering that cannot reproduce them still passes on the nine "
              "it can",
              narrowed is True, str(narrowed))
        check("PC8 §7.1: a differing NON-API row still fails, and the diff "
              "carries only the rows that were compared",
              isinstance(narrowed_bad, str)
              and narrowed_bad.startswith(
                  "the rendering differs from the frozen payload on the "
                  "non-API rows:")
              and "-| pass rate | 5.0% (5/100) |\n" in narrowed_bad
              and "+| pass rate | 6.0% (6/100) |\n" in narrowed_bad
              and "api precision" not in narrowed_bad, str(narrowed_bad))
        check("PC8 §7.1: the published API rows are read from the FROZEN "
              "file, never re-rendered, and labelled as harness-5 "
              "legacy_consistency evidence",
              legacy_api_rows() == {
                  "label": LEGACY_CONSISTENCY,
                  "harness_version": LEGACY_TABLE_HARNESS_VERSION,
                  "rows": {"api precision": "0.973",
                           "api recall": "0.951",
                           "api f1": "0.960"}},
              str(legacy_api_rows()))

    # ------------------------------------------- what `report.py` refuses
    #
    # Here rather than in a selftest of its own: `report` has no fixtures and
    # these two refusals are about the same thing this module exists to
    # protect -- a table whose rows are not one population.
    from . import report as RP

    coreshop = [{"item_id": "coreshop/f.feature:1", "outcome": "passed"},
                {"item_id": "coreshop/g.feature:2", "outcome": "failed"}]
    two = coreshop + [{"item_id": "sylius/h.feature:3", "outcome": "passed"}]
    check("one project pools as it always has -- today's runs are untouched",
          RP.check_single_project(coreshop) == ["coreshop"])
    check("rows spanning two projects REFUSE a pooled total",
          _refuses(lambda: RP.check_single_project(two),
                   "REFUSED: these rows span 2 projects"))
    check("...unless --group-by project is asked for",
          RP.check_single_project(two, group_by="project")
          == ["coreshop", "sylius"])
    check("the grouping gate promises complete project reports, forbids the "
          "POOLED total, and names the equal-weight macro as the only "
          "cross-project headline",
          "no pooled total" in (RP.check_single_project.__doc__ or "")
          and "EQUAL-WEIGHT macro over projects"
          in (RP.check_single_project.__doc__ or ""))

    check("rows with no comparison_class are grandfathered, never defaulted "
          "into one",
          RP.check_comparison_class(coreshop) is None)
    check("a fixed-model scaffold and a product system are REFUSED one table",
          _refuses(lambda: RP.check_comparison_class(
              [dict(coreshop[0], comparison_class="fixed_model_scaffold"),
               dict(coreshop[1], comparison_class="product_system")]),
              "REFUSED: these rows declare 2 comparison classes"))
    check("one declared class is fine, and mixing a declared one with silent "
          "rows is grandfathered too",
          RP.check_comparison_class(
              [dict(coreshop[0], comparison_class="product_system"),
               coreshop[1]]) is None)
    check("a label this file has never heard of counts as its OWN class -- "
          "the conservative reading -- and the refusal says so",
          _refuses(lambda: RP.check_comparison_class(
              [dict(coreshop[0], comparison_class="product_system"),
               dict(coreshop[1], comparison_class="something_new")]),
              "something_new is not a class this file knows"))

    # -------------------------------------------- what the system DID
    behaved = RP.format_system_behaviour([
        {"item_id": "p/a:1", "outcome": "passed", "repeats": 3,
         "outcomes_all_runs": ["passed", "failed", "passed"],
         # Persisted answer evidence wins over the deliberately false driver
         # flag below.
         "produced_files": {"features/a.feature": "Feature: a"},
         "metadata": {"agent_seconds": 100.0, "trials": {"used": 2},
                      "agent_stats": {"llm_calls": 10, "wrote_files": False,
                                      "forced_write_used": True}}},
        {"item_id": "p/b:2", "outcome": "failed", "repeats": 3,
         "outcomes_all_runs": ["failed", "failed", "failed"],
         # An explicit empty artifact list is evidence of no answer write,
         # even though the driver claims it saw one.
         "written_files": [],
         "metadata": {"agent_seconds": 300.0, "trials": {"used": 0},
                      "agent_stats": {"llm_calls": 30, "wrote_files": True,
                                      "forced_write_used": False,
                                      "run_errors": ["429 exhausted"]}}},
    ])
    printed = "\n".join(behaved)
    check("system behaviour derives answer writes from produced/written files "
          "despite contradictory agent flags, and reports fallback, calls, "
          "time, trials and errors",
          "answer writes       1/2" in printed
          and "produced_files/written_files" in printed
          and "(1 of them via the forced-write fallback)" in printed
          and "max       30" in printed and "max    300.0 s" in printed
          and "run errors          1/2" in printed, printed)
    check("outcome instability is reported as a rate, and labelled DIAGNOSTIC "
          "ONLY so it is never applied to the denominator",
          "outcome instability  1/2" in printed and "(50.0%)" in printed
          and "DIAGNOSTIC ONLY" in printed, printed)
    check("a run with no repeats prints no instability line at all -- there "
          "is nothing to be unstable about",
          not any("instability" in ln for ln in
                  RP.format_system_behaviour(coreshop)))
    check("missing answer-file fields are named as unrecorded, never counted "
          "as zero writes",
          any("answer writes    not recorded" in ln for ln in
              RP.format_system_behaviour(coreshop)))

    # The Jaccard identity itself, independent of any file.
    check("jaccard == recall when the candidate kills nothing extra",
          TQ.jaccard_for(3, 4, 0) == 0.75)
    check("one candidate-only kill separates them: recall 1.0, jaccard 2/3",
          TQ.jaccard_for(2, 2, 1) == 2 / 3)
    check("gold killing nothing leaves the jaccard UNDEFINED, not 0.0",
          TQ.jaccard_for(0, 0, 3) is None)

    print("\n" + ("ALL PASS (results)" if ok else "FAILURES (results)"))
    return 0 if ok else 1


def _raises(fn, needle: str) -> bool:
    try:
        fn()
    except (ResultsInputError, M.MetricsInputError,
            draws.DrawRefusal) as e:
        return needle in str(e)
    except Exception:                                          # noqa: BLE001
        return False
    return False


def _refuses(fn, needle: str) -> bool:
    """Like `_raises`, for `report`'s refusals -- and it checks the MESSAGE.

    A refusal whose text does not say what the harm was is a refusal a reader
    will work around, so the message is part of what is under test.
    """
    from .report import ReportRefusal
    try:
        fn()
    except ReportRefusal as e:
        return needle in str(e)
    except Exception:                                          # noqa: BLE001
        return False
    return False


if __name__ == "__main__":
    raise SystemExit(selftest())
