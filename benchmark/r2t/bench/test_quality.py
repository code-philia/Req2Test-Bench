"""Per-solution test quality: is a PASS also a TEST? (SPEC_C3_PARALLEL §3.10)

`pass@1` alone is a weak claim for a requirement-to-test benchmark.  A
submission that defines every step with an empty body is green on **422/422**
items, which is the entire reason §3.10 has an anti-vacuity gate.  But that
gate is a CORPUS-level, one-time check — gold 1.000 against stub 0.0196 over a
400-mutant seeded sample — and what it establishes is that *the benchmark* can
tell a test from a no-op.  It establishes nothing about the particular items a
particular candidate passed, and it cannot: the two eval100 passes both fall
OUTSIDE the sampled gate population (gold kills no sampled mutant on either
item), so the gate's 1.000-vs-0.0196 says exactly nothing about them.

This module is the per-SOLUTION version of the same question.  For each item a
candidate passed: over the FULL set of mutants covering that item, does the
candidate's test kill what the reference test kills?  Three answers matter and
they are not the same finding:

    equivalent_to_reference   recall == 1.0   it kills everything gold kills
    weaker                    0 < r < 1.0     it passes, and it detects less
    vacuous                   recall == 0.0   it passes and detects NOTHING

Each scored item also carries the recall's symmetric partner, `jaccard` =
|C n G| / |C u G|, whose denominator includes the kills the candidate makes and
gold does not.  Recall cannot see those — its denominator is gold's set — so a
candidate that kills gold's mutants *and fifty others* reads 1.000 exactly like
one that kills gold's mutants and nothing else, and those are not the same
test.  The verdict vocabulary is unchanged and remains the recall's: the
Jaccard is reported beside it, not folded into it.

plus `not_scorable`, for an item where gold itself kills nothing — the mutants
covering it are equivalent as far as this benchmark can observe, so the item
carries no information about the candidate and must not be averaged as if it
did.  A `not_scorable` pass is not a good result and not a bad one; it is an
unverified one, and it is reported as such rather than being quietly counted
as either.

**Why this is a command and not a script.**  It was done by hand once, for the
two eval100 passes: the full mutant population covering those items (109
mutants), candidate and gold executed on separate workers, kill parity 24/24
and 25/25.  That is the number that turns "passed" into "passed and is
non-vacuous" — and a number produced by hand once is a number nobody can
reproduce, resume, or run against the next sweep.  Every piece of machinery it
needs already exists (`mutation.recall`, `mutation_run.run_slice`, the worker
triples); this is the convenience path that makes the right thing cheap enough
that it gets done every time.

Four properties it exists to guarantee
--------------------------------------
* **No sampling.**  `mutation-run --sample` exists because the corpus-wide
  population is 2,741 covered mutants / 49,553 pairs.  The population HERE is
  the mutants covering the *passed* items only — 109 for the two eval100
  passes — so a sample would buy nothing and would cost the one thing this
  measurement has to have: a recall of 1.0 over a sample of a 24-mutant set is
  not evidence of equivalence, it is evidence about the sample.
* **Never regenerate.**  The candidate is scored on exactly the bytes its run
  file recorded in `produced_files`.  Re-running the model to get a solution to
  mutate would measure a *different* solution than the one that passed, and
  nothing in the output would say so.
* **The eligibility rule is not re-implemented.**  Scoring goes through
  `mutation.recall`, so "an item counts only where gold's baseline passed and
  gold's kill set is non-empty" is the SAME rule the corpus gate applied,
  byte-for-byte the same function.  A second implementation of an eligibility
  rule is a second chance to invert it, and inverting it is precisely the bug
  (`kill == did not pass`) that made the vacuous candidate outscore the real
  one before P1-1.
* **A short results file is refused, not averaged.**  Recall over 40 of 109
  pairs is not a smaller measurement of the same thing, it is a different
  denominator — and on this population the missing pairs are a large fraction
  of it.  Planned shards are always exact.  `--allow-incomplete` is retained
  only for deliberately reading a short, externally supplied `--gold-results`
  file; it cannot turn a failed planned worker into a complete campaign.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import subprocess
import threading
import time
from functools import wraps
from typing import Callable, Iterable, Optional

from ..core import reviewed_git as _RG
from ..data.mutation import (OPERATORS, classify_outcome,
                             nondeterministic_mutants, recall)
from ..core.paths import CONFIG_DIR

#: The verdict vocabulary.  Four values, and no default: an item that cannot
#: be scored is named `not_scorable` rather than being folded into `vacuous`,
#: because "the candidate detects nothing" and "nothing here is detectable"
#: are opposite findings that would otherwise print the same.
EQUIVALENT = "equivalent_to_reference"
WEAKER = "weaker"
VACUOUS = "vacuous"
NOT_SCORABLE = "not_scorable"
VERDICTS: tuple[str, ...] = (EQUIVALENT, WEAKER, VACUOUS, NOT_SCORABLE)

#: The two solutions executed against the same mutants.  `gold` is a side and
#: not a special case: it is run through the identical `run_slice` path from
#: its own `produced_files`, so "what gold kills" is measured on this
#: population rather than inherited from a campaign that sampled a different
#: one.
SIDES: tuple[str, ...] = ("candidate", "gold")

#: Written into `--out`.  The merged per-side rows are kept beside the summary
#: because the summary is a claim and these are the evidence for it; a
#: verdict of `equivalent_to_reference` with no rows behind it is exactly the
#: hand-computed number this module replaces.
CANDIDATE_ROWS = "candidate_mutation.jsonl"
GOLD_ROWS = "gold_mutation.jsonl"
SUMMARY = "summary.json"
SHARD_DIR = "shards"
CAMPAIGN_STATE = "campaign.json"
TEST_QUALITY_CAMPAIGN_SCHEMA = "r2t.test-quality-campaign/v1"
TEST_QUALITY_CAMPAIGN_SCHEMA_V2 = "r2t.test-quality-campaign/v2"
TEST_QUALITY_PLAN_SCHEMA_V1 = "r2t.test-quality-plan/v1"
TEST_QUALITY_PLAN_SCHEMA = "r2t.test-quality-plan/v2"
D4_CONFIRMATION_PLAN_SCHEMA = "r2t.d4-confirmation-plan/v2"
D4_CONFIRMATION_PENDING_SCHEMA = "r2t.d4-confirmation-pending/v1"
D4_CONFIRMATION_METHOD = "r2t.d4-selective-whole-hard-set/1"
D4_PAIR_SHARD_POLICY = "r2t.d4-balanced-pairs-lpt/1"
TEST_QUALITY_PLAN_SCHEMA_V3 = "r2t.test-quality-plan/v3"
TEST_QUALITY_COMPUTE_CAP_SCHEMA = "r2t.test-quality-compute-cap/v1"
TEST_QUALITY_INTERRUPTION_SCHEMA = "r2t.test-quality-interruption/v1"
INTERRUPTION_COMPUTE_CAP = "compute_cap_reached"
INTERRUPTION_OPERATOR = "operator_cancelled"
TEST_QUALITY_FINAL_ARTIFACT_TYPES = frozenset({
    "native_observation", "precomputed_gold", "composite_observation",
})
TEST_QUALITY_PLAN_V3_FIELDS = frozenset({
    "schema", "jobs", "worker_resources", "worker_resources_sha256",
    "expected_pairs", "expected_pairs_sha256", "require_complete",
    "gold_precomputed", "final_artifacts", "shard_policy",
    "compute_cap", "compute_cap_sha256", "projection_by_side",
    "observation_ids_by_side", "estimand_pairs_sha256",
    "delta_pairs_sha256_by_side", "final_artifact_types_by_side",
    "preflight_cache_authority",
})

#: Execution order is not a scoring rule, but it is campaign identity: a
#: resumed shard must contain the same mutants it was originally assigned.
#: Keep the historical policy available by name so an old v1 plan remains
#: resumable byte-for-byte.  New campaigns use deterministic longest-
#: processing-time assignment where the only cost proxy is the number of
#: planned (item, mutant) pairs.  That proxy is known before execution, is
#: corpus-independent, and cannot learn from candidate outcomes.
SHARD_POLICY_STRIDED_V1 = "r2t.strided-mutants/1"
SHARD_POLICY_BALANCED_PAIRS_V1 = "r2t.balanced-pairs-lpt/1"
SHARD_POLICIES: tuple[str, ...] = (
    SHARD_POLICY_STRIDED_V1,
    SHARD_POLICY_BALANCED_PAIRS_V1,
)
DEFAULT_SHARD_POLICY = SHARD_POLICY_BALANCED_PAIRS_V1

#: The sidecar `report` looks for beside a run.  Two spellings are accepted on
#: READ and the first is what gets written: `runs/x.jsonl` names its summary
#: `runs/x.test_quality.json`, which is the same stem `report` prints the run
#: under, but a caller who appends to the full filename (as `run_slice` does
#: for its provenance) must not silently get "no test-quality data" instead of
#: their file.
SIDECAR_SUFFIX = ".test_quality.json"
TEST_QUALITY_BINDING_SCHEMA = "r2t.test-quality-binding/v1"
TEST_QUALITY_SUMMARY_SCHEMA = "r2t.test-quality-summary/v1"
#: The single-observation summary.  A separate schema and not a superset of
#: v1: it is scored against three PRESERVED reference observations rather
#: than against a gold leg this campaign executed, so its per-item entries
#: carry different fields and its denominators are section 5.1's narrowed
#: universe.  Nothing may read one as the other.
TEST_QUALITY_SUMMARY_SCHEMA_V2 = "r2t.test-quality-summary/v2"
FULL_POPULATION_SINGLE_OBSERVATION_POLICY = \
    "r2t.full-population-single-observation/1"
SINGLE_OBSERVATION_METHOD = "single_observation"
LEGACY_REBINDING_SCHEMA = "r2t.test-quality-legacy-rebinding/v1"
MUTATION_VALIDATION_SCHEMA = "r2t.mutation-validation/1"
LEGACY_CONSISTENCY_SCHEMA = "r2t.mutation-legacy-consistency/1"

#: What a row written before mutation rows carried an `engine` column is
#: called in the summary's tally.  It is a real category and not a fill-in:
#: the archived `test_quality_std` rows have no engine key, and pretending
#: they said `r2t-mutate` would be this module inventing evidence.  They are
#: attributed to the MANIFEST instead, which is checkable, and counted here so
#: the summary says how much of it rests on that attribution.
UNLABELLED_ENGINE = "unlabelled"

#: Which (item, mutant) pairs the CANDIDATE slice observes
#: (specifications/GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md).  `all` is every
#: mapped pair of the passed items, as before.  `gold-killed` is only the
#: pairs the bound gold observation kills: per-item recall, the verdicts and
#: `non_vacuous_passes` read candidate outcomes on those pairs alone, so they
#: are unchanged, while every companion that reads a candidate outcome on a
#: pair gold did not kill is withheld (`GOLD_KILLED_WITHHELD`).
CANDIDATE_PAIRS_ALL = "all"
CANDIDATE_PAIRS_GOLD_KILLED = "gold-killed"
CANDIDATE_PAIR_SCOPES: tuple[str, ...] = (CANDIDATE_PAIRS_ALL,
                                          CANDIDATE_PAIRS_GOLD_KILLED)
#: An explicit pair set the in-campaign gold slice (and so the candidate
#: slice) is restricted to: the pairs a named earlier gold observation killed.
GOLD_PAIR_PLAN_SCHEMA = "r2t.gold-pair-plan/1"
#: The summary measures a gold-killed campaign does not measure, by the name
#: they carry in a full-scope summary.  Each is present and null, never 0.
GOLD_KILLED_WITHHELD: tuple[str, ...] = (
    "per_item.candidate_only_kills", "per_item.jaccard", "jaccard_macro",
    "excluded.equivalent", "excluded.candidate_only_kill",
    "excluded.infrastructure",
)
GOLD_KILLED_NOT_MEASURED = (
    "not measured (candidate pairs restricted to gold-killed pairs; "
    "GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md)")
#: What a gold-killed v2 summary withholds, by its own field names: each
#: reads a candidate outcome off `G_i`, so each is present and null.
SINGLE_OBSERVATION_GOLD_KILLED_WITHHELD: tuple[str, ...] = (
    "per_item.candidate_only_kills", "per_item.full_union",
    "per_item.full_only_generated", "per_item.full_jaccard",
    "full_only_generated_macro", "full_jaccard_macro",
)
#: The scope disclosure of a gold-killed v2 summary.  A full-gold-only
#: reference always writes it; a hard-subset reference writes it only under
#: the labelled stub-gate-waived basis with `--candidate-pairs gold-killed`
#: (SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md section 2), so every
#: all-pairs summary keeps its bytes.
GOLD_KILLED_SUMMARY_FIELDS: frozenset[str] = frozenset({
    "candidate_pair_scope", "withheld_measures"})
#: A v2 summary scored against controls derived under a LABELLED reference
#: basis (`reference_controls.SENSITIVITY_PROJECTS`) carries these fields and
#: only it does: the label, `inference_valid: false`, the reference's waived
#: stub gate (a disclosed diagnostic) and the scoring host's gold
#: disagreements.  Every measure beside them is computed as against eligible
#: controls (SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md section 5).
SENSITIVITY_SUMMARY_FIELDS: frozenset[str] = frozenset({
    "sensitivity", "inference_valid", "reference_stub_gate",
    "reference_gold_disagreements"})


class TestQualityRefused(ValueError):
    """Refused rather than scored — see the message."""


def _single_observation_summary_fields(full_gold=False) -> frozenset[str]:
    from .mutation_run import CAMPAIGN_IDENTITY_FIELDS_V2_ADDED
    return frozenset({
        "schema", "method", "policy", "candidate_observation_count",
        "reference_observation_count", "verdict_basis", "companion_basis",
        "n_passed", "n_scorable", "recall_macro", "hard_recall_macro",
        "full_recall_macro", "full_only_generated_macro",
        "full_jaccard_macro", "verdicts", "non_vacuous_passes", "per_item",
        "mutants_in_population", "pairs_expected",
        "pairs_executed_candidate", "pairs_executed_gold", "require_complete",
        "workers", "jobs", "slices", "candidate_results", "gold_results",
        "run", "gold_baseline", "manifest", "map", "release",
        "mutation_validation", "seed", "shard_policy", "asset_index_sha256",
        "asset_project", "mutation_validation_sha256",
        "mutation_validation_class", "population_id", "manifest_digest",
        "manifest_sha256", "map_sha256", "release_sha256",
        "candidate_run_sha256", "candidate_generated_tests_sha256",
        "gold_baseline_sha256", "gold_generated_tests_sha256",
        "applier_sha256", "substrate_baseline_sha256",
        "worker_resources_sha256", "worker_resources", "harness_version",
        "container_image_digest", "workspace_seed_digest",
        "database_dump_digest", "engine", "engine_version", "parser",
        "timeout_seconds",
        "row_engines", "expected_pairs_sha256", "binding",
        "candidate_observation_id", "reference_controls",
        # Section 5.1 requires BOTH excluded counts beside every number
        # derived from the artifact: the reference's, sealed once at mint
        # time, and this run's own, discovered from its candidate rows.
        "reference_pairs", "reference_pairs_sha256",
        "reference_excluded_count",
        # The declared-subset disclosure: how many mapped items the reference
        # does not cover, and why.  Zero and None when nothing was declared.
        "reference_omitted_items", "reference_declared_reason",
        "candidate_pairs", "candidate_pairs_sha256",
        "candidate_excluded_count", "candidate_excluded_pairs",
        "candidate_scored_pairs", "candidate_scored_pairs_sha256",
        "candidate_rows_sha256", "gold_rows_sha256",
        "root_campaign_plan_sha256", "mutation_campaign_digests",
    } | set(CAMPAIGN_IDENTITY_FIELDS_V2_ADDED) | ({"candidate_pair_scope", "withheld_measures"} if full_gold else set()))


#: The two v2 summary fields added AFTER a real score was already on disk
#: (the declared-subset change, 2026-09-02), and the only two whose ABSENCE a
#: reader admits.  Absence IS the honest reading: a summary written before the
#: disclosure existed made no declaration, and `score_single_observation`
#: writes exactly `0` / `None` for a reference that declares nothing.  Same
#: one-sided rule as `campaign.CAMPAIGN_OPTIONAL_FIELDS` -- the PRODUCER still
#: requires all of them, so a run executing today has the disclosure and must
#: write it, and nothing fills the keys in on the way back from disk.
#:
#: Not a licence for unknown keys, and not "absences are fine": every other
#: expected field is still required, an authored extension still refuses, and
#: the absence buys admission only where the rederivation below independently
#: says this reference declared nothing.  A summary hiding a REAL declared
#: subset still refuses by name.
SINGLE_OBSERVATION_OPTIONAL_SUMMARY_FIELDS: frozenset[str] = frozenset({
    "reference_omitted_items", "reference_declared_reason"})

#: What `score_single_observation` rederives for an undeclared reference, and
#: therefore what an absent optional field is checked against.
_UNDECLARED_REFERENCE_SUBSET: dict = {
    "reference_omitted_items": 0,
    "reference_declared_reason": None,
}


_SINGLE_OBSERVATION_AUTHORITY_SEAL = object()


class _SingleObservationScoringAuthority:
    """In-memory join between authenticated controls and their scoring view."""

    __slots__ = ("controls", "sets", "seal")

    def __init__(self, controls: object, sets: object, seal: object):
        self.controls = controls
        self.sets = sets
        self.seal = seal

    @property
    def expected_pairs(self) -> frozenset:
        """The reference's SCORED universe, section 5.1 already applied."""
        return self.sets.expected_pairs


def _seal_single_observation_scoring_authority(
        controls: object) -> _SingleObservationScoringAuthority:
    """Private bridge from preserved reference validation to scoring.

    The scoring view is DERIVED here rather than accepted beside the
    controls: `reference_sets` returns it only for unchanged authenticated
    `ReferenceControls`, so there is no pair of objects that could disagree
    with each other and nothing to re-check afterwards.
    """
    from . import reference_controls as RC

    try:
        sets = RC.reference_sets(controls)
    except RC.ReferenceControlsRefused as exc:
        raise TestQualityRefused(str(exc)) from exc
    return _SingleObservationScoringAuthority(
        controls, sets, _SINGLE_OBSERVATION_AUTHORITY_SEAL)


def _require_single_observation_authority(
        authority: object) -> _SingleObservationScoringAuthority:
    if not isinstance(authority, _SingleObservationScoringAuthority) \
            or authority.seal is not _SINGLE_OBSERVATION_AUTHORITY_SEAL:
        raise TestQualityRefused(
            "REFUSED: single-observation scoring requires the sealed "
            "authority this module mints from authenticated "
            "ReferenceControls.")
    return authority


_AUTHENTICATED_GOLD_SELECTION_SEAL = object()


class _AuthenticatedGoldSelection:
    """In-memory admission for a rederived imported-reference selection.

    A focused reader validates its original reference authority and method
    before minting this object: the generic live route requires its portable
    roles/intersection; Kapua requires its fixed three-control evidence.
    Neither route may infer authority from an authored row list alone.
    It has no JSON spelling: serialization loses the private
    seal, so an authored document cannot bypass the ordinary cached-gold
    validators.
    """

    __slots__ = ("rows", "binding", "seal")

    def __init__(self, rows: list[dict], binding: dict, seal: object):
        self.rows = copy.deepcopy(rows)
        self.binding = copy.deepcopy(binding)
        self.seal = seal


def _seal_authenticated_gold_selection(
        rows: list[dict], binding: dict) -> _AuthenticatedGoldSelection:
    """Private bridge from authenticated reference admission to arithmetic."""
    fields = {
        "validation_class", "manifest_digest", "pairs_sha256", "engine",
        "engine_version", "gold_results_sha256",
        "gold_results_attestation_sha256", "gold_results_source",
        "gold_results_attestation",
    }
    if not isinstance(rows, list) or not rows \
            or any(not isinstance(row, dict) for row in rows) \
            or not isinstance(binding, dict) or set(binding) != fields:
        raise TestQualityRefused(
            "REFUSED: authenticated installed-gold selection is malformed.")
    return _AuthenticatedGoldSelection(
        rows, binding, _AUTHENTICATED_GOLD_SELECTION_SEAL)


def _open_authenticated_gold_selection(value: object) -> tuple[list[dict], dict]:
    if not isinstance(value, _AuthenticatedGoldSelection) \
            or value.seal is not _AUTHENTICATED_GOLD_SELECTION_SEAL:
        raise TestQualityRefused(
            "REFUSED: installed gold was not admitted by the generic "
            "policy/role join.")
    return copy.deepcopy(value.rows), copy.deepcopy(value.binding)


def _read_authenticated_installed_gold(
        reader: object, *, summary: dict,
        expected: set[tuple[str, str]], identity_inputs: dict) -> list[dict]:
    """Re-open one adapter-validated installed-gold selection.

    The callable revalidates its focused raw-role inventory and attestation.
    Generic installed routes supply it in memory; the fixed Kapua development
    path reconstructs it from its saved evidence input on every reload.
    """
    if not callable(reader):
        raise TestQualityRefused(
            "REFUSED: installed native gold needs its focused saved-evidence "
            "reader.")
    try:
        sealed = reader(summary, set(expected))
    except TestQualityRefused:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize adapter refusal
        raise TestQualityRefused(
            f"REFUSED: installed-gold saved-evidence reader failed: {exc}") \
            from exc
    rows, binding = _open_authenticated_gold_selection(sealed)
    wanted = {
        "manifest_digest": summary.get("manifest_digest"),
        "pairs_sha256": identity_inputs.get(
            "gold_attestation_pairs_sha256"),
        "engine": summary.get("engine"),
        "engine_version": summary.get("engine_version"),
        "gold_results_sha256": identity_inputs.get("gold_results_sha256"),
        "gold_results_attestation_sha256": identity_inputs.get(
            "gold_results_attestation_sha256"),
        "gold_results_source": summary.get("gold_results_source"),
        "gold_results_attestation": summary.get(
            "gold_results_attestation"),
    }
    changed = sorted(
        key for key, value in wanted.items()
        if binding.get(key) != value)
    if binding.get("validation_class") != "native" or changed:
        raise TestQualityRefused(
            "REFUSED: installed-gold reader differs from the native summary "
            f"binding in field(s) {changed}.")
    pairs = [(row.get("item_id"), row.get("mutant_id")) for row in rows]
    if len(rows) != len(expected) or set(pairs) != expected \
            or len(pairs) != len(set(pairs)):
        raise TestQualityRefused(
            "REFUSED: installed-gold reader did not return the exact selected "
            "candidate pair set.")
    return rows


def _reference_kill_pairs(reader: object, summary: dict,
                          pairs: set[tuple[str, str]]) -> set:
    """The literal-failed pairs of an installed reference over *pairs*."""
    if not callable(reader):
        raise TestQualityRefused(
            "REFUSED: installed native gold needs its focused saved-evidence "
            "reader.")
    try:
        sealed = reader(summary, set(pairs))
    except TestQualityRefused:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize adapter refusal
        raise TestQualityRefused(
            f"REFUSED: installed-gold saved-evidence reader failed: {exc}") \
            from exc
    rows, _binding = _open_authenticated_gold_selection(sealed)
    return {(row.get("item_id"), row.get("mutant_id")) for row in rows
            if row.get("outcome") == "failed"}


class _AuthenticatedLegacySummary(dict):
    """In-memory authority granted only after legacy chain re-derivation.

    The type is deliberately not a persisted field. JSON serialization emits
    an ordinary object and loading it again loses this authority, so a wrapper
    cannot authenticate itself merely by spelling the right schema/key shape.
    """


def registered_population_id(project: str, manifest_digest: str,
                             engine: Optional[str],
                             engine_version: Optional[str]) -> Optional[str]:
    """Resolve a summary's population binding through `VERSIONS.yml`.

    Fixture projects remain unregistered.  A real registered project with a
    changed digest refuses rather than emitting a plausible summary whose
    `population_id` merely disappeared.
    """
    from ..data.versions import ManifestError, population_id_for
    try:
        return population_id_for(
            project, manifest_digest, engine=engine,
            engine_version=engine_version)
    except ManifestError as e:
        raise TestQualityRefused(f"REFUSED: {e}") from e


#: The generation half of a FIXTURE campaign identity, in one named place.
#:
#: Explicit and greppable rather than implied: `identity_inputs_for_test_quality`
#: and `plan_jobs`' independent fallback both spread this dict, so "what a
#: fixture identity claims" has exactly one definition, and it claims nothing
#: it does not have. `mutation_run` refuses a `fixture` identity that carries
#: an attempt id, a runtime digest or a network posture, and
#: `refuse_unpublishable_generation` refuses the class itself wherever a
#: number could be published.
FIXTURE_GENERATION_INPUTS: dict = {
    "generation_provenance_class": "fixture",
    "generation_attempt_id": None,
    "generation_campaign_digest": "f" * 16,
    "generation_agent_runtime_sha256": None,
    "generation_network_semantics": None,
    "generation_condition": None,
    "generation_protocol_version": None,
    "generation_protocol_digest": None,
    "generation_native_budget": None,
}


def refuse_unpublishable_generation(klass, where: str, *,
                                    allow_development: bool = False) -> None:
    """Refuse a generation provenance class a published number may not rest on.

    The publication surfaces are the two places a PRESERVED artifact becomes
    a number somebody reads: the saved native summary a `report`/`results`
    reader loads, and precomputed gold re-entering a live campaign. A
    `fixture` identity is valid everywhere else and refused here, so a
    default can never be inherited into a publication.

    *allow_development* is set at exactly one call site — the saved-summary
    READER inside `_validate_native_summary` — and it does not make anything
    publishable.  It only stops the reader from turning a development-route
    sidecar into an input error, which would delete the entire results table
    rather than the three mutation rows.

    WHAT HOLDS PAST THAT READER is `publication_ready`, which re-asks the same
    question the reader was told to skip: the class must be in
    `GENERATION_PROVENANCE_PUBLISHABLE` or the cell is withheld with the class
    named.  Until that conjunct existed the answer downstream was
    `verdict_basis`: a development campaign has no hard subset, so the basis
    was `full_gold`, so the cell was withheld — a property of an EMPTY
    `VERSIONS.yml` `hard_subset_artifacts.pins` registry rather than of the
    class, and one that a single pin would have ended (PR #288).  The relaxed
    reader is now safe because the predicate re-checks, not because pinning
    never happens.
    """
    from .mutation_run import (GENERATION_PROVENANCE_DEVELOPMENT,
                               GENERATION_PROVENANCE_PUBLISHABLE)
    if allow_development and klass == GENERATION_PROVENANCE_DEVELOPMENT:
        return
    if klass not in GENERATION_PROVENANCE_PUBLISHABLE:
        raise TestQualityRefused(
            f"REFUSED: {where} carries generation provenance class "
            f"{klass!r}, which is not publishable "
            f"({list(GENERATION_PROVENANCE_PUBLISHABLE)}). A candidate whose "
            f"generation facts were defaulted rather than derived may not "
            f"become a published number.")


class TestQualityCancelled(TestQualityRefused):
    """A cooperative coordinator cancellation, as a TYPE (review finding 9).

    The root record's `interrupted` vs `failed` decision used to be made by
    substring-matching `"cooperatively cancelled"` against whatever text
    escaped.  That test was structurally unreachable in the case it mattered:
    when a cancel lands while workers are inside `run_slice`, each slice
    raises `MutationCancelled`, `execute_jobs` aggregates them into
    `"REFUSED: N mutation slice(s) failed…"`, and the phrase never appears —
    so a clean SIGTERM at hour 15 wrote terminal `failed`, and `failed` has no
    outgoing transition, stranding every valid shard in the directory.

    A subclass rather than a flag on the exception, because the classifier
    that reads it (`_campaign_directory_locked`) sees only the exception, and
    because `except TestQualityRefused` at every existing call site must keep
    catching it — a cancellation IS a refusal to score, and no caller should
    have to learn a second type to stay correct.
    """


# ----------------------------------------------------------------- loading
def load_jsonl(path: str) -> list[dict]:
    if os.path.islink(path) or not os.path.isfile(path):
        raise TestQualityRefused(
            f"REFUSED: JSONL evidence is not a regular file: {path}.")
    out: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise TestQualityRefused(
                    f"REFUSED: {path} line {n} is not JSON ({e}). A results "
                    f"file that cannot be read in full cannot be scored in "
                    f"part.") from None
    return out


def sidecar_paths(run_path: str) -> tuple[str, str]:
    """`(canonical, also-accepted)` names for a run's test-quality summary."""
    base = run_path[:-len(".jsonl")] if run_path.endswith(".jsonl") else run_path
    return base + SIDECAR_SUFFIX, run_path + SIDECAR_SUFFIX


def find_sidecar(run_path: str) -> Optional[str]:
    candidates = list(dict.fromkeys(sidecar_paths(run_path)))
    found = [candidate for candidate in candidates
             if os.path.lexists(candidate)]
    if not found:
        return None
    invalid = [path for path in found
               if os.path.islink(path) or not os.path.isfile(path)]
    if invalid:
        raise TestQualityRefused(
            f"REFUSED: test-quality sidecar path is not a regular file: "
            f"{invalid}.")
    if len(found) == 2:
        raise TestQualityRefused(
            f"REFUSED: both accepted test-quality sidecars exist for "
            f"{run_path}: {found}. Even byte-identical duplicates are "
            "ambiguous publication inputs; delete neither and resolve the "
            "canonical artifact through review.")
    return found[0]


# -------------------------------------------------------------- the inputs
def passed_solutions(run_rows: Iterable[dict]) -> dict:
    """`{item_id: produced_files}` for the rows that PASSED, and only those.

    Only passes are scored because the question is only about passes: a failed
    item's test quality is not in doubt, and running the mutant population
    against it would multiply the campaign by the failures without producing a
    number anyone would report.

    A pass carrying no files is kept rather than refused.  It cannot happen
    through `runner._record` (no files is `no_files_returned`, not `passed`),
    but if it ever does, the honest handling is to score it — the empty
    solution kills nothing, so it comes out `vacuous`, which is the correct
    answer and a far more useful one than a crash.
    """
    out: dict = {}
    seen = set()
    for number, row in enumerate(run_rows, 1):
        iid = row.get("item_id")
        if not isinstance(iid, str) or not iid or iid in seen:
            # Any two rows for one item are unresolved retry history, even if
            # only one passed.  Selecting the pass first and filtering later
            # would make line order decide which attempt's generated bytes
            # are bound into the publication sidecar.
            raise TestQualityRefused(
                f"REFUSED: candidate run has missing or duplicate item_id "
                f"{iid!r} at row {number}. Resolve retry history before "
                "test-quality; which attempt gets scored must not depend on "
                "line order.")
        seen.add(iid)
        if row.get("outcome") != "passed":
            continue
        out[iid] = row.get("produced_files") or []
    return out


def run_sensitivity(run_rows: Iterable[dict]) -> Optional[str]:
    """The one post-hoc sensitivity label a candidate run carries, or None.

    `run --sensitivity` stamps every row it writes and never shares a run
    file with unlabelled rows; a file that mixes labels is not one replay.
    """
    labels = {row.get("sensitivity") for row in run_rows}
    if len(labels) > 1:
        raise TestQualityRefused(
            f"REFUSED: candidate run mixes sensitivity labels "
            f"{sorted(str(label) for label in labels)}; score each "
            "labelled replay from its own run file.")
    return next(iter(labels), None)


def require_run_sensitivity(run_rows: Iterable[dict],
                            sensitivity: Optional[str]) -> None:
    """Every candidate row carries exactly the label being scored.

    A labelled replay executed its candidates with a harness overlay; scoring
    it without that overlay (or an unlabelled run with it) would observe
    mutants under a harness the candidate never passed under.  The gold
    baseline is exempt: it is the unlabelled reference either way.
    """
    label = run_sensitivity(run_rows)
    if label != sensitivity:
        raise TestQualityRefused(
            f"REFUSED: the candidate run is labelled {label!r} but "
            f"test-quality was asked to score sensitivity {sensitivity!r}; "
            "pass --sensitivity exactly when every run row carries that "
            "label (E_PETITIONS_WEBMOCK_MUTATION_AMENDMENT.md).")


def run_binding(run_path: str, run_rows: Optional[list[dict]] = None) -> dict:
    """Bind a summary to exact run bytes and the generated tests it scores."""
    from .mutation_run import candidate_digest, sha256_file
    rows = load_jsonl(run_path) if run_rows is None else run_rows
    return {
        "schema": TEST_QUALITY_BINDING_SCHEMA,
        "run_sha256": sha256_file(run_path),
        "generated_tests_sha256": candidate_digest(passed_solutions(rows)),
    }


def bind_summary(summary: dict, run_path: str,
                 run_rows: Optional[list[dict]] = None) -> dict:
    """Return a summary bound to *run_path*, refusing a conflicting claim."""
    binding = run_binding(run_path, run_rows)
    existing = summary.get("binding")
    if existing is not None and existing != binding:
        raise TestQualityRefused(
            f"REFUSED: the test-quality summary is bound to run/generated "
            f"digests {existing}, but {run_path} has {binding}. Item-id "
            "equality cannot prove the generated tests are the same.")
    return {**summary, "binding": binding}


def _load_json_object(path: str, label: str) -> dict:
    if os.path.islink(path) or not os.path.isfile(path):
        raise TestQualityRefused(
            f"REFUSED: {label} is not a regular file: {path}.")
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        raise TestQualityRefused(
            f"REFUSED: cannot read {label} {path}: {e}") from e
    if not isinstance(doc, dict):
        raise TestQualityRefused(
            f"REFUSED: {label} {path} is not a JSON object.")
    return doc


def _is_sha256(value) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def canonical_campaign_directory(path: str) -> str:
    """Canonical absolute spelling bound before a campaign starts."""
    if not isinstance(path, str) or not path:
        raise TestQualityRefused(
            "REFUSED: compute-capped test-quality requires a concrete "
            "campaign output directory.")
    return os.path.realpath(os.path.abspath(path))


#: Built from the shared grammar rather than retyped beside it: the path half
#: and the commit half are `r2t.core.reviewed_git`'s, so the two callers of that
#: module cannot drift into two spellings of one authority.
_COMPUTE_CAP_REVIEW_AUTHORITY = re.compile(
    rf"(?P<path>{_RG.PATH_PATTERN})@(?P<commit>{_RG.COMMIT_PATTERN})\Z")
#: Which shared refusal code produces which already reviewed diagnostic here.
#: The wording below is unchanged; only the code that reaches it moved.
_CAP_REVIEW_DIAGNOSTIC = {
    "path": "REFUSED: compute-cap review_authority path must be a normalized "
            "repository-relative POSIX path.",
    # New code, not new wording for an old one: before the repository was
    # pinned, an ancestor repository answered this question and the read
    # simply succeeded, so nothing here could have said so.
    "repository": "REFUSED: compute-cap review_authority must resolve in the "
                  "source-derived repository this package runs from.",
    "commit": "REFUSED: compute-cap review_authority does not name a locally "
              "recoverable full Git commit.",
    "entry": "REFUSED: compute-cap review_authority path is missing from its "
             "immutable commit or is not locally recoverable.",
    "mode": "REFUSED: compute-cap review_authority must resolve to one "
            "regular file blob at its immutable commit.",
    "blob": "REFUSED: compute-cap review_authority must resolve to one "
            "regular file blob at its immutable commit.",
}


def validate_compute_cap_review_authority(review_authority: str) -> str:
    """Resolve one immutable, repository-local cap review authority.

    The serialized spelling is ``<repo-relative-path>@<full-commit>``.  A
    branch, tag, abbreviated object id, or merely well-formed missing object
    is not recoverable immutable review evidence.  Resolution is repeated by
    readers rather than treated as a producer-only syntax check.

    The grammar, the repository root and the `ls-tree` entry check live in
    `r2t.core.reviewed_git` -- this resolver is where they were reviewed, and the
    publication consumers now run the same code rather than a second copy of
    it.  Extraction also closed the environment the read runs under, so an
    exported ``GIT_DIR`` can no longer answer this question out of a
    repository the caller supplied.
    """
    if not isinstance(review_authority, str) \
            or not review_authority \
            or review_authority != review_authority.strip() \
            or len(review_authority) > 1024:
        raise TestQualityRefused(
            "REFUSED: compute-cap review_authority must use the exact "
            "<repo-relative-path>@<40-lowercase-hex-commit> grammar.")
    match = _COMPUTE_CAP_REVIEW_AUTHORITY.fullmatch(review_authority)
    if match is None:
        raise TestQualityRefused(
            "REFUSED: compute-cap review_authority must use the exact "
            "<repo-relative-path>@<40-lowercase-hex-commit> grammar; "
            "mutable refs and abbreviated commits are not authorities.")
    path = match.group("path")
    commit = match.group("commit")
    try:
        # `path@40hex` is at most 1024 above, so the shared 983-character
        # path bound admits exactly what this resolver already admitted.
        _RG.blob_object(
            _RG.validate_commit(commit), _RG.validate_path(path),
            repository=_RG.repository_root(), timeout=10)
    except _RG.ReviewedGitRefused as exc:
        if exc.code == "git_exec":
            raise TestQualityRefused(
                "REFUSED: cannot locally resolve compute-cap review_authority "
                f"{review_authority!r}: {exc.detail}.") from exc
        raise TestQualityRefused(_CAP_REVIEW_DIAGNOSTIC[exc.code]) from exc
    return review_authority


def build_compute_cap(*, wall_clock_seconds: int, workers: int,
                      expected: Iterable[tuple[str, str]],
                      campaign_dir: str, review_authority: str) -> dict:
    """Build the exact pre-execution cap declaration from frozen inputs."""
    from .mutation_run import pair_set_digest

    if not isinstance(wall_clock_seconds, int) \
            or isinstance(wall_clock_seconds, bool) \
            or wall_clock_seconds < 1:
        raise TestQualityRefused(
            "REFUSED: compute-cap wall_clock_seconds must be a positive "
            f"integer, got {wall_clock_seconds!r}.")
    if not isinstance(workers, int) or isinstance(workers, bool) \
            or workers < 1:
        raise TestQualityRefused(
            f"REFUSED: compute-cap workers must be a positive integer, got "
            f"{workers!r}.")
    review_authority = validate_compute_cap_review_authority(
        review_authority)
    pairs = set(expected)
    if not pairs:
        raise TestQualityRefused(
            "REFUSED: a compute cap cannot bind an empty mutation estimand.")
    return {
        "schema": TEST_QUALITY_COMPUTE_CAP_SCHEMA,
        "wall_clock_seconds": wall_clock_seconds,
        "workers": workers,
        "expected_pairs": len(pairs),
        "expected_pairs_sha256": pair_set_digest(pairs),
        "campaign_dir": canonical_campaign_directory(campaign_dir),
        "review_authority": review_authority,
    }


def validate_compute_cap(cap: dict, *, workers: int,
                         expected: Iterable[tuple[str, str]],
                         campaign_dir: str) -> dict:
    """Require byte-exact agreement between a cap and execution inputs."""
    if not isinstance(cap, dict):
        raise TestQualityRefused(
            "REFUSED: compute-cap declaration is not an object.")
    fields = {"schema", "wall_clock_seconds", "workers", "expected_pairs",
              "expected_pairs_sha256", "campaign_dir", "review_authority"}
    if set(cap) != fields:
        raise TestQualityRefused(
            "REFUSED: compute-cap declaration has missing or unknown fields.")
    rebuilt = build_compute_cap(
        wall_clock_seconds=cap.get("wall_clock_seconds"), workers=workers,
        expected=expected, campaign_dir=campaign_dir,
        review_authority=cap.get("review_authority"))
    if cap != rebuilt:
        changed = sorted(key for key in fields
                         if cap.get(key) != rebuilt.get(key))
        raise TestQualityRefused(
            "REFUSED: compute-cap declaration differs from the frozen "
            f"campaign input(s) {changed}.")
    return cap


def validate_test_quality_plan_v3(plan: dict) -> dict:
    """Validate the one closed v3 root shape shared by v4 policies.

    Projection and preflight-cache production are not implemented in this
    module yet, so their reviewed non-null authorities remain fail-closed.
    Keeping the reserved slots in the one shared shape prevents compute-cap
    roots from assigning plan v3 a conflicting meaning in the meantime.
    """
    from .mutation_run import (EXECUTION_POLICY_SCALAR_V1,
                               MUTATION_IDENTITY_SCHEMA_V4, MutationAborted,
                               campaign_identity_digest, content_digest,
                               validate_observation_id)

    if not isinstance(plan, dict) or set(plan) != TEST_QUALITY_PLAN_V3_FIELDS:
        raise TestQualityRefused(
            "REFUSED: test-quality plan v3 has missing or unknown fields.")
    if plan.get("schema") != TEST_QUALITY_PLAN_SCHEMA_V3:
        raise TestQualityRefused(
            f"REFUSED: expected {TEST_QUALITY_PLAN_SCHEMA_V3}, got "
            f"{plan.get('schema')!r}.")
    maps = {
        "projection_by_side": plan.get("projection_by_side"),
        "observation_ids_by_side": plan.get("observation_ids_by_side"),
        "delta_pairs_sha256_by_side": plan.get(
            "delta_pairs_sha256_by_side"),
        "final_artifact_types_by_side": plan.get(
            "final_artifact_types_by_side"),
    }
    for name, value in maps.items():
        if not isinstance(value, dict) or set(value) != set(SIDES):
            raise TestQualityRefused(
                f"REFUSED: plan v3 {name} must have exact candidate/gold "
                "keys.")
    projections = maps["projection_by_side"]
    if any(value is not None for value in projections.values()):
        raise TestQualityRefused(
            "REFUSED: a non-null reuse projection has no implemented, "
            "reviewed producer yet.")
    if plan.get("preflight_cache_authority") is not None:
        raise TestQualityRefused(
            "REFUSED: a non-null preflight-cache authority has no "
            "implemented, reviewed producer yet.")
    artifact_types = maps["final_artifact_types_by_side"]
    unknown_types = sorted(
        [value for value in artifact_types.values()
         if not isinstance(value, str)
         or value not in TEST_QUALITY_FINAL_ARTIFACT_TYPES], key=str)
    if unknown_types:
        raise TestQualityRefused(
            "REFUSED: plan v3 has unknown final-artifact type(s) "
            f"{unknown_types}.")
    if any(value == "composite_observation"
           for value in artifact_types.values()):
        raise TestQualityRefused(
            "REFUSED: a composite final artifact requires the reviewed "
            "projection producer, which is not implemented yet.")
    estimand = plan.get("estimand_pairs_sha256")
    if not _is_sha256(estimand):
        raise TestQualityRefused(
            "REFUSED: plan v3 has no valid complete-estimand digest.")
    if any(not _is_sha256(value)
           for value in maps["delta_pairs_sha256_by_side"].values()):
        raise TestQualityRefused(
            "REFUSED: plan v3 has a malformed per-side delta-set digest.")

    resources = plan.get("worker_resources")
    if not isinstance(resources, list) or not resources \
            or any(not isinstance(record, dict) for record in resources) \
            or [record.get("index") for record in resources] \
            != list(range(len(resources))):
        raise TestQualityRefused(
            "REFUSED: plan v3 worker resources must be a nonempty, "
            "zero-based ordered assignment.")
    try:
        resources_sha256 = content_digest(resources)
    except (TypeError, ValueError) as exc:
        raise TestQualityRefused(
            "REFUSED: plan v3 worker resources are not canonical JSON "
            "values.") from exc
    if not _is_sha256(plan.get("worker_resources_sha256")) \
            or plan.get("worker_resources_sha256") != resources_sha256:
        raise TestQualityRefused(
            "REFUSED: plan v3 worker-resource digest does not authenticate "
            "its exact ordered assignment.")

    expected_count = plan.get("expected_pairs")
    expected_sha256 = plan.get("expected_pairs_sha256")
    if not isinstance(expected_count, int) or isinstance(expected_count, bool) \
            or expected_count < 1 or not _is_sha256(expected_sha256):
        raise TestQualityRefused(
            "REFUSED: plan v3 has no positive exact expected-pair "
            "population.")
    if expected_sha256 != estimand:
        raise TestQualityRefused(
            "REFUSED: plan v3 expected population differs from its complete "
            "estimand digest.")
    if not isinstance(plan.get("require_complete"), bool):
        raise TestQualityRefused(
            "REFUSED: plan v3 require_complete is not Boolean.")
    gold_precomputed = plan.get("gold_precomputed")
    if not isinstance(gold_precomputed, bool):
        raise TestQualityRefused(
            "REFUSED: plan v3 gold_precomputed is not Boolean.")
    if plan.get("final_artifacts") \
            != [CANDIDATE_ROWS, GOLD_ROWS, SUMMARY]:
        raise TestQualityRefused(
            "REFUSED: plan v3 does not name the exact canonical final "
            "artifact set.")
    shard_policy = plan.get("shard_policy")
    if shard_policy != SHARD_POLICY_BALANCED_PAIRS_V1:
        raise TestQualityRefused(
            "REFUSED: plan v3 does not bind the balanced-pairs shard "
            "policy.")

    cap = plan.get("compute_cap")
    cap_sha256 = plan.get("compute_cap_sha256")
    cap_fields = {
        "schema", "wall_clock_seconds", "workers", "expected_pairs",
        "expected_pairs_sha256", "campaign_dir", "review_authority",
    }
    if not isinstance(cap, dict) or set(cap) != cap_fields:
        raise TestQualityRefused(
            "REFUSED: plan v3 has no closed compute-cap/v1 declaration; no "
            "other plan-v3 producer is implemented yet.")
    authority = cap.get("review_authority")
    campaign_dir = cap.get("campaign_dir")
    if cap.get("schema") != TEST_QUALITY_COMPUTE_CAP_SCHEMA \
            or not isinstance(cap.get("wall_clock_seconds"), int) \
            or isinstance(cap.get("wall_clock_seconds"), bool) \
            or cap.get("wall_clock_seconds") < 1 \
            or not isinstance(cap.get("workers"), int) \
            or isinstance(cap.get("workers"), bool) \
            or cap.get("workers") != len(resources) \
            or cap.get("expected_pairs") != expected_count \
            or cap.get("expected_pairs_sha256") != expected_sha256 \
            or not isinstance(campaign_dir, str) or not campaign_dir \
            or canonical_campaign_directory(campaign_dir) != campaign_dir \
            or not isinstance(authority, str):
        raise TestQualityRefused(
            "REFUSED: plan v3 compute-cap declaration differs from its root "
            "population, worker assignment, directory, or authority.")
    validate_compute_cap_review_authority(authority)
    try:
        rebuilt_cap_sha256 = content_digest(cap)
    except (TypeError, ValueError) as exc:
        raise TestQualityRefused(
            "REFUSED: plan v3 compute-cap declaration is not canonical "
            "JSON.") from exc
    if not _is_sha256(cap_sha256) or cap_sha256 != rebuilt_cap_sha256:
        raise TestQualityRefused(
            "REFUSED: plan v3 compute-cap digest does not authenticate its "
            "exact declaration.")

    jobs = plan.get("jobs")
    if not isinstance(jobs, list) or not jobs \
            or any(not isinstance(job, dict) for job in jobs):
        raise TestQualityRefused(
            "REFUSED: plan v3 jobs are not a nonempty object array.")
    jobs_by_side = {side: [] for side in SIDES}
    job_fields = {"side", "worker", "of", "out",
                  "mutation_campaign_digest", "campaign_identity",
                  "preflight_cache_authority_sha256"}
    seen_jobs = set()
    for job in jobs:
        side = job.get("side")
        worker = job.get("worker")
        worker_count = job.get("of")
        out = job.get("out")
        identity = job.get("campaign_identity")
        key = (side, worker)
        if set(job) != job_fields or not isinstance(side, str) \
                or side not in jobs_by_side \
                or not isinstance(worker, int) or isinstance(worker, bool) \
                or worker < 0 \
                or not isinstance(worker_count, int) \
                or isinstance(worker_count, bool) \
                or worker_count != len(resources) \
                or worker >= worker_count or key in seen_jobs \
                or out != os.path.join(
                    SHARD_DIR, f"{side}.w{worker}.jsonl") \
                or not isinstance(identity, dict) \
                or identity.get("schema") != MUTATION_IDENTITY_SCHEMA_V4 \
                or identity.get("kind") != "test-quality" \
                or identity.get("side") != side \
                or identity.get("shard") != worker \
                or identity.get("of") != worker_count:
            raise TestQualityRefused(
                "REFUSED: plan v3 has a duplicate or malformed exact job "
                "binding.")
        seen_jobs.add(key)
        try:
            digest = campaign_identity_digest(identity)
        except (MutationAborted, TypeError, ValueError) as exc:
            raise TestQualityRefused(str(exc)) from exc
        if job.get("mutation_campaign_digest") != digest:
            raise TestQualityRefused(
                "REFUSED: plan v3 job digest does not authenticate its exact "
                "v4 campaign identity.")
        if job.get("preflight_cache_authority_sha256") is not None:
            raise TestQualityRefused(
                f"REFUSED: plan v3 {side} job claims a preflight-cache "
                "authority while the current root authority is null.")
        jobs_by_side[side].append(job)
        observation_id = maps["observation_ids_by_side"][side]
        try:
            if artifact_types[side] != "precomputed_gold":
                validate_observation_id(observation_id)
            elif observation_id is not None:
                validate_observation_id(observation_id)
        except MutationAborted as exc:
            raise TestQualityRefused(str(exc)) from exc
        if identity.get("observation_id") != observation_id:
            raise TestQualityRefused(
                f"REFUSED: plan v3 {side} job observation id differs from "
                "its per-side root binding.")
        if identity.get("reuse_projection_sha256") is not None:
            raise TestQualityRefused(
                f"REFUSED: plan v3 {side} job claims a projection while its "
                "per-side root binding is null.")
        if identity.get("estimand_pairs_sha256") != estimand:
            raise TestQualityRefused(
                f"REFUSED: plan v3 {side} job differs from the root's "
                "complete estimand digest.")
        if identity.get("shard_policy") != shard_policy \
                or identity.get("execution_policy") \
                != EXECUTION_POLICY_SCALAR_V1 \
                or any(identity.get(key) is not None for key in (
                    "batch_plan_sha256", "max_batch_members",
                    "max_batch_instances", "stack_reset_sha256",
                    "batch_journal_schema", "reuse_projection_sha256",
                    "preflight_cache_policy")) \
                or identity.get("compute_cap_sha256") != cap_sha256 \
                or identity.get("worker_resources_sha256") \
                != resources_sha256:
            raise TestQualityRefused(
                f"REFUSED: plan v3 {side} job does not bind the exact scalar "
                "cap, null batch/projection/cache policy, scheduling policy, "
                "and worker assignment.")
        pair_count = identity.get("expected_pairs")
        if not isinstance(pair_count, int) or isinstance(pair_count, bool) \
                or pair_count < 1 \
                or not _is_sha256(identity.get("expected_pairs_sha256")):
            raise TestQualityRefused(
                f"REFUSED: plan v3 {side} job has no positive authenticated "
                "pair partition.")

    # The generic side contract remains explicit even though the only current
    # producer is compute-cap/v1.  A future producer cannot inherit a loose
    # relation between the historical gold flag and the typed side authority.
    if artifact_types.get("candidate") != "native_observation" \
            or gold_precomputed \
            != (artifact_types.get("gold") == "precomputed_gold"):
        raise TestQualityRefused(
            "REFUSED: plan v3 gold_precomputed and per-side final-artifact "
            "types disagree.")
    for side in SIDES:
        if artifact_types[side] == "precomputed_gold":
            if side != "gold" or jobs_by_side[side] \
                    or maps["observation_ids_by_side"][side] is not None \
                    or maps["delta_pairs_sha256_by_side"][side] != estimand:
                raise TestQualityRefused(
                    "REFUSED: only a jobless, observation-free complete gold "
                    "side may be typed as precomputed_gold.")
        elif not jobs_by_side[side] \
                or maps["delta_pairs_sha256_by_side"][side] != estimand:
            raise TestQualityRefused(
                f"REFUSED: plan v3 has no complete native job/delta binding "
                f"for {side}'s declared final artifact.")

    # Compute-cap/v1 has no precomputed-gold or partial-root spelling.  Both
    # native legs cover the same complete estimand through the same nonempty
    # worker partitions and share the root-minted observation id.  LPT omits
    # empty tail jobs when the declared resource pool is wider than the mutant
    # population; those unused resources remain authenticated by the root.
    if gold_precomputed or not plan.get("require_complete") \
            or artifact_types \
            != {side: "native_observation" for side in SIDES}:
        raise TestQualityRefused(
            "REFUSED: compute-cap/v1 requires complete native candidate and "
            "gold legs.")
    observations = maps["observation_ids_by_side"]
    if observations["candidate"] != observations["gold"]:
        raise TestQualityRefused(
            "REFUSED: compute-cap/v1 candidate and gold jobs do not share "
            "one root-minted observation id.")
    for side in SIDES:
        workers = sorted(job["worker"] for job in jobs_by_side[side])
        if not workers or workers != list(range(len(workers))) \
                or len(workers) > len(resources):
            raise TestQualityRefused(
                f"REFUSED: compute-cap/v1 {side} jobs do not cover the exact "
                "zero-based nonempty worker prefix.")
        if sum(job["campaign_identity"]["expected_pairs"]
               for job in jobs_by_side[side]) != expected_count:
            raise TestQualityRefused(
                f"REFUSED: compute-cap/v1 {side} job partitions do not sum "
                "to the complete estimand.")
        pair_digests = [
            job["campaign_identity"]["expected_pairs_sha256"]
            for job in sorted(jobs_by_side[side],
                              key=lambda value: value["worker"])
        ]
        if len(pair_digests) != len(set(pair_digests)):
            raise TestQualityRefused(
                f"REFUSED: compute-cap/v1 {side} repeats an exact pair "
                "partition across workers.")
    candidate_partitions = [
        (job["campaign_identity"]["expected_pairs"],
         job["campaign_identity"]["expected_pairs_sha256"])
        for job in sorted(jobs_by_side["candidate"],
                          key=lambda value: value["worker"])
    ]
    gold_partitions = [
        (job["campaign_identity"]["expected_pairs"],
         job["campaign_identity"]["expected_pairs_sha256"])
        for job in sorted(jobs_by_side["gold"],
                          key=lambda value: value["worker"])
    ]
    if candidate_partitions != gold_partitions:
        raise TestQualityRefused(
            "REFUSED: compute-cap/v1 candidate and gold jobs do not bind "
            "the same deterministic pair partitions.")
    _admitted_policy_identity_binding(jobs, shard_policy)
    return plan


def _validate_rebinding_chain(chain: dict, run_path: str,
                              wrapper: dict, wrapper_path: str) -> dict:
    """Re-derive a legacy wrapper; hashing its references is insufficient.

    Returns the resolved evidence paths, so a caller that has to compare one
    of them against a discovered sidecar resolves it exactly once and the same
    way this validator did.
    """
    from .mutation_run import sha256_file
    if not isinstance(chain, dict) \
            or chain.get("schema") != LEGACY_REBINDING_SCHEMA:
        raise TestQualityRefused(
            f"REFUSED: explicit legacy wrapper has no "
            f"{LEGACY_REBINDING_SCHEMA} chain.")
    base_dir = _wrapper_base(wrapper_path, wrapper.get("path_base"))
    resolved: dict[str, str] = {}
    for label, path_key, digest_key in (
            ("source legacy sidecar", "source_sidecar",
             "source_sidecar_sha256"),
            ("legacy consistency report", "validation_report",
             "validation_report_sha256")):
        wanted = chain.get(digest_key)
        path = _resolve_wrapper_reference(
            chain.get(path_key), base_dir, label)
        if not _is_sha256(wanted) \
                or os.path.islink(path) or not os.path.isfile(path):
            raise TestQualityRefused(
                f"REFUSED: legacy wrapper cannot verify its {label}: "
                f"path={path!r}, sha256={wanted!r}.")
        actual = sha256_file(path)
        if actual != wanted:
            raise TestQualityRefused(
                f"REFUSED: legacy wrapper's {label} changed: {actual}, "
                f"expected {wanted}.")
        resolved[path_key] = path
    if chain.get("validation_schema") != MUTATION_VALIDATION_SCHEMA \
            or chain.get("validation_class") != "legacy_consistency" \
            or chain.get("native_provenance") is not False:
        raise TestQualityRefused(
            "REFUSED: legacy wrapper mislabels its validation provenance.")
    # The recorded operator consent (ruling 2.6) is the ONE field re-derivation
    # cannot compute: it is a decision, not a fact about bytes.  It is taken
    # from the document and everything else — the count, the per-item
    # disclosure, the degradation class — is re-derived and compared, so a
    # wrapper that claims a tolerance it did not measure still refuses.
    expected = _build_legacy_wrapper(
        run_path, resolved["source_sidecar"], resolved["validation_report"],
        wrapper_path=wrapper_path,
        allow_degraded_gold=bool(wrapper.get("allow_degraded_gold")))
    if wrapper != expected:
        changed = sorted(key for key in set(wrapper) | set(expected)
                         if wrapper.get(key) != expected.get(key))
        raise TestQualityRefused(
            f"REFUSED: legacy wrapper differs from the summary re-derived "
            f"from PR-2-validated bytes in field(s) {changed[:10]}.")
    return resolved


def _read_single_observation_authority(reader: object, summary: dict) \
        -> _SingleObservationScoringAuthority:
    if not callable(reader):
        raise TestQualityRefused(
            "REFUSED: a v2 summary requires its authenticated installed "
            "ReferenceControls reader.")
    try:
        value = reader(summary, None)
    except TestQualityRefused:
        raise
    except Exception as exc:  # noqa: BLE001 - reader boundary is explicit
        raise TestQualityRefused(
            f"REFUSED: installed ReferenceControls reader refused: {exc}") \
            from exc
    return _require_single_observation_authority(value)


def _validate_single_observation_summary(
        summary: dict, summary_path: str, run_path: str, *,
        reference_reader: object, campaign_status: str,
        rescore: bool = False) -> Optional[dict]:
    """Reopen and rederive the prospective v2 summary from candidate rows.

    With `rescore`, return its score re-derived from the same verified rows
    with the reviewed nondeterministic mutants left out (`rescore_recorded`).
    """
    from ..data import versions
    from .mutation_run import (MutationAborted, campaign_identity_digest,
                               candidate_digest, completed_pairs,
                               content_digest, pair_set_digest, sha256_file)

    if campaign_status not in {"running", "complete"}:
        raise AssertionError(campaign_status)
    if summary.get("schema") != TEST_QUALITY_SUMMARY_SCHEMA_V2 \
            or summary.get("policy") \
            != FULL_POPULATION_SINGLE_OBSERVATION_POLICY \
            or summary.get("method") != SINGLE_OBSERVATION_METHOD \
            or summary.get("candidate_observation_count") != 1 \
            or summary.get("reference_observation_count") != 1:
        raise TestQualityRefused(
            "REFUSED: v2 summary does not identify the reviewed one-"
            "candidate/one-reference-observation method.")
    expected_fields = _single_observation_summary_fields(summary.get("verdict_basis") == "full_gold")
    # Missing and unknown are different questions.  A field added after
    # a score was already written may be absent and is read as
    # undeclared; an extra field is an authored extension and refuses.
    missing = sorted(expected_fields - set(summary)
                     - SINGLE_OBSERVATION_OPTIONAL_SUMMARY_FIELDS)
    unknown = sorted(set(summary) - expected_fields
                     - SENSITIVITY_SUMMARY_FIELDS - GOLD_KILLED_SUMMARY_FIELDS)
    if missing or unknown:
        raise TestQualityRefused(
            "REFUSED: v2 summary has missing or unknown fields: "
            f"missing={missing}, unknown={unknown}.")
    # The scope fields exist together and only under gold-killed; `all` is
    # their absence.  Everything the scope changes is re-derived below.
    scope_fields = set(summary) & GOLD_KILLED_SUMMARY_FIELDS
    if scope_fields and (scope_fields != GOLD_KILLED_SUMMARY_FIELDS
                         or summary["candidate_pair_scope"]
                         != CANDIDATE_PAIRS_GOLD_KILLED):
        raise TestQualityRefused(
            "REFUSED: v2 summary has a malformed candidate pair scope "
            "(candidate_pair_scope, withheld_measures).")
    pair_scope = (CANDIDATE_PAIRS_GOLD_KILLED if scope_fields
                  else CANDIDATE_PAIRS_ALL)
    authority = _read_single_observation_authority(reference_reader, summary)
    controls = authority.controls
    reference_record = {
        "schema": controls["schema"],
        "digest": controls["digest"],
        "population_id": controls["population"]["id"],
        "observation_ids": {
            role: record["observation_id"]
            for role, record in controls["observations"].items()
        },
    }
    # The artifact digest covers its pair block, its exclusion list and its
    # per-item sets, so this one comparison settles "scored against THIS
    # reference" before any row is read.
    if summary.get("reference_controls") != reference_record:
        raise TestQualityRefused(
            "REFUSED: v2 summary was scored against other reference "
            "controls than the ones its reader authenticated.")
    if os.path.abspath(summary.get("run", "")) != os.path.abspath(run_path):
        raise TestQualityRefused(
            "REFUSED: native test-quality summary names another candidate "
            "run path.")
    if summary.get("binding") != run_binding(run_path):
        raise TestQualityRefused(
            "REFUSED: v2 summary binding differs from the sealed candidate "
            "run/generated-test bytes.")
    candidate_path = os.path.abspath(summary.get("candidate_results", ""))
    gold_path = os.path.abspath(summary.get("gold_results", ""))
    out_dir = os.path.dirname(candidate_path)
    if os.path.basename(candidate_path) != CANDIDATE_ROWS \
            or gold_path != os.path.join(out_dir, GOLD_ROWS):
        raise TestQualityRefused(
            "REFUSED: v2 candidate/reference projections are not the closed "
            "campaign artifacts.")
    canonical_path = os.path.join(out_dir, SUMMARY)
    if _load_json_object(canonical_path, "canonical v2 summary") != summary:
        raise TestQualityRefused(
            "REFUSED: v2 sidecar differs from its canonical campaign summary.")
    candidate_rows = load_jsonl(candidate_path)
    gold_rows = load_jsonl(gold_path)
    if summary.get("candidate_rows_sha256") != sha256_file(candidate_path) \
            or summary.get("gold_rows_sha256") != sha256_file(gold_path):
        raise TestQualityRefused(
            "REFUSED: v2 summary row digests differ from preserved evidence.")
    validate_native_retry_evidence(
        candidate_rows, where="single-observation candidate")
    run_rows = load_jsonl(run_path)
    passed = passed_solutions(run_rows)
    if bool(set(summary) & SENSITIVITY_SUMMARY_FIELDS) \
            != (authority.sets.sensitivity is not None):
        raise TestQualityRefused(
            "REFUSED: v2 summary and its reference controls disagree about "
            "the labelled sensitivity basis.")
    expected = single_observation_candidate_pairs(authority, passed,
                                                  pair_scope)
    manifest = _load_json_object(
        summary["manifest"], "v2 scored mutation manifest")
    mapping = _load_json_object(summary["map"], "v2 mutation map")
    by_mutant = mapping.get("by_mutant")
    control_population = controls["population"]
    path_claims = {
        "manifest_sha256": sha256_file(summary["manifest"]),
        "map_sha256": sha256_file(summary["map"]),
        "release_sha256": sha256_file(summary["release"]),
        "mutation_validation_sha256": sha256_file(
            summary["mutation_validation"]),
    }
    expected_path_claims = {
        "manifest_sha256": control_population["manifest_sha256"],
        "map_sha256": control_population["map_sha256"],
        "release_sha256": (
            controls._evaluation_scope["scope"]["task_items_sha256"]
            if getattr(controls, "_evaluation_scope", None) is not None else
            control_population["release_sha256"]),
        "mutation_validation_sha256": controls["authority"][
            "mutation_validation_sha256"],
    }
    if path_claims != expected_path_claims \
            or manifest.get("digest") != control_population["manifest_digest"] \
            or manifest.get("engine") != control_population["engine"] \
            or manifest.get("engine_version") \
            != control_population["engine_version"] \
            or manifest.get("parser") != control_population["parser"] \
            or not isinstance(by_mutant, dict):
        raise TestQualityRefused(
            "REFUSED: v2 manifest/map/release/validation bytes differ from "
            "the installed reference population authority.")
    # The manifest and the map still describe the COMPLETE mapped population.
    # Section 5.1 narrowed the scored universe when the reference was minted,
    # so the comparison is against the narrowed set: rederiving the mapped
    # one and demanding equality would refuse every reference that carries a
    # single excluded pair.
    mutants, restricted, _covering = population(manifest, by_mutant, passed)
    mutants, restricted = _narrow_to_reference(
        mutants, restricted, _reference_excluded_pairs(controls),
        _reference_declared_items(controls))
    if pair_scope == CANDIDATE_PAIRS_GOLD_KILLED:
        mutants, restricted = restrict_to_pairs(mutants, restricted, expected)
    if expected_pairs(restricted) != expected:
        raise TestQualityRefused(
            "REFUSED: v2 candidate manifest/map scope differs from the "
            "sealed reference pair set restricted to passed items.")
    binding = run_binding(run_path)
    gold_baseline_rows = load_jsonl(summary["gold_baseline"])
    gold_files, _gold_baseline = gold_side(gold_baseline_rows, passed)
    if summary.get("candidate_run_sha256") != binding["run_sha256"] \
            or summary.get("candidate_generated_tests_sha256") \
            != binding["generated_tests_sha256"] \
            or summary.get("gold_baseline_sha256") \
            != sha256_file(summary["gold_baseline"]) \
            or summary.get("gold_generated_tests_sha256") \
            != candidate_digest(gold_files):
        raise TestQualityRefused(
            "REFUSED: v2 candidate or gold-baseline bytes changed after "
            "scoring.")
    # As scored: a summary of an earlier harness kept the listed mutants.
    recomputed = score_single_observation(
        passed, candidate_rows, authority=authority, expected=expected,
        unscored=unscored_mutants(summary.get("harness_version")),
        candidate_pair_scope=pair_scope)
    # An absent optional field leaves this comparison rather than being
    # compared against `None`: `summary.get` would read the absence as a
    # value and refuse `reference_omitted_items` at `0 != None` on every
    # pre-disclosure document.  It leaves ONLY where the rederivation
    # says this reference declared nothing, so the absence is checked
    # against what it claims to mean; a declared reference keeps the key
    # and refuses by name.
    for _optional in SINGLE_OBSERVATION_OPTIONAL_SUMMARY_FIELDS:
        if _optional not in summary and recomputed[_optional] \
                == _UNDECLARED_REFERENCE_SUBSET[_optional]:
            del recomputed[_optional]
    changed = sorted(key for key, value in recomputed.items()
                     if summary.get(key) != value)
    if changed:
        raise TestQualityRefused(
            "REFUSED: v2 summary arithmetic differs from its candidate rows "
            f"in field(s) {changed}.")
    if gold_rows != _single_observation_gold_rows(authority, expected):
        raise TestQualityRefused(
            "REFUSED: v2 full-gold projection differs from authenticated G.")
    expected_digest = pair_set_digest(expected)
    if summary.get("expected_pairs_sha256") != expected_digest:
        raise TestQualityRefused(
            "REFUSED: v2 summary changed its exact executed pair identity.")
    state = _load_json_object(
        _campaign_state_path(out_dir), "v2 root campaign record")
    plan = state.get("plan") if isinstance(state, dict) else None
    state = _validate_campaign_state(state, plan)
    planned_jobs = plan.get("jobs") if isinstance(plan, dict) else None
    if state["status"] != campaign_status \
            or not isinstance(planned_jobs, list) \
            or bool(planned_jobs) != bool(expected) \
            or any(not isinstance(job, dict)
                   or job.get("side") != "candidate"
                   for job in planned_jobs) \
            or plan.get("gold_precomputed") is not True \
            or plan.get("require_complete") is not True \
            or plan.get("expected_pairs") != len(expected) \
            or plan.get("expected_pairs_sha256") != expected_digest \
            or summary.get("root_campaign_plan_sha256") \
            != content_digest(plan):
        raise TestQualityRefused(
            "REFUSED: v2 root is not the complete candidate-only campaign "
            "for the sealed passed-item pair set.")
    plan_policy = shard_policy_from_plan(plan)
    resources = plan.get("worker_resources")
    if not isinstance(resources, list) or not resources \
            or resources != summary.get("worker_resources") \
            or [record.get("index") for record in resources
                if isinstance(record, dict)] != list(range(len(resources))) \
            or plan.get("worker_resources_sha256") \
            != content_digest(resources) \
            or summary.get("worker_resources_sha256") \
            != content_digest(resources):
        raise TestQualityRefused(
            "REFUSED: v2 summary/root disagree on the complete ordered "
            "worker-resource assignment.")
    first_identity = (planned_jobs[0].get("campaign_identity") or {}) if planned_jobs else {}
    identity_inputs = copy.deepcopy(first_identity)
    rebuilt_jobs = plan_jobs(
        mutants, {"candidate": passed, "gold": gold_files}, restricted,
        len(resources), out_dir, sides=("candidate",),
        identity_inputs=identity_inputs,
        timeout=summary.get("timeout_seconds"),
        shard_policy=plan_policy,
        bind_shard_policy=policy_identity_binding_from_plan(plan),
        **_v4_execution_kwargs(first_identity)) if expected else []
    rebuilt_plan = (build_test_quality_campaign_plan(
        rebuilt_jobs, expected=expected, require_complete=True,
        gold_precomputed=True,
        candidate_scope=_single_observation_scope_record(
            authority, expected, pair_scope),
        worker_resources=resources,
        campaign_dir=out_dir, compute_cap=None) if expected else
        _zero_pair_candidate_plan(
            authority=authority, passed=passed, inputs=summary,
            worker_resources=resources, shard_policy=plan_policy,
            observation_id=summary.get("candidate_observation_id")))
    if rebuilt_plan != plan:
        raise TestQualityRefused(
            "REFUSED: v2 candidate-only root plan cannot be rederived from "
            "the reference-bound manifest/map, candidate, and runtime.")

    reopened_jobs = []
    reopened_rows = []
    reopened_pairs = set()
    derived_jobs = []
    derived_slices = []
    campaign_digests = []
    for number, (planned, rebuilt) in enumerate(
            zip(planned_jobs, rebuilt_jobs)):
        relative = planned.get("out")
        identity = planned.get("campaign_identity")
        worker = planned.get("worker")
        if not isinstance(relative, str) or not relative \
                or os.path.dirname(relative) != SHARD_DIR \
                or not isinstance(identity, dict) \
                or worker != number \
                or planned.get("of") != len(resources) \
                or identity.get("of") != len(resources):
            raise TestQualityRefused(
                "REFUSED: v2 root has malformed candidate job ownership.")
        path = rebuilt["out"]
        if path != os.path.join(out_dir, relative) \
                or rebuilt["identity"] != identity:
            raise TestQualityRefused(
                f"REFUSED: v2 candidate job {number} differs from its "
                "deterministically rebuilt allocation or identity.")
        rows = load_jsonl(path)
        seen = set()
        for row in rows:
            pair = (row.get("item_id"), row.get("mutant_id"))
            if not all(isinstance(value, str) and value for value in pair) \
                    or pair in seen:
                raise TestQualityRefused(
                    f"REFUSED: v2 candidate shard {number} has a malformed "
                    "or duplicate pair.")
            seen.add(pair)
        try:
            completed_pairs(
                path, identity, expected_pairs=seen, require_complete=True,
                expected_shard_policy=plan_policy,
                allow_missing_shard_policy=False)
        except MutationAborted as exc:
            raise TestQualityRefused(str(exc)) from exc
        if reopened_pairs & seen:
            raise TestQualityRefused(
                "REFUSED: v2 candidate shards overlap on a pair.")
        reopened_pairs.update(seen)
        reopened_rows.extend(rows)
        reopened_jobs.append(rebuilt)
        derived_jobs.append({
            "side": "candidate", "worker": worker,
            "mutants": len(rebuilt["mutants"]),
            "out": path,
        })
        derived_slices.append({
            "out": path, "rows": len(rows), "side": "candidate",
        })
        campaign_digests.append(campaign_identity_digest(identity))
    if reopened_pairs != expected or reopened_rows != candidate_rows:
        raise TestQualityRefused(
            "REFUSED: v2 merged candidate rows differ from the exact "
            "complete root-owned shard evidence.")
    validate_output_contents(
        out_dir, reopened_jobs,
        final_names=(CANDIDATE_ROWS, GOLD_ROWS, SUMMARY),
        campaign_plan=plan, campaign_status=campaign_status)

    durable = {
        "mutants_in_population": len(mutants),
        "pairs_expected": len(expected),
        "pairs_executed_candidate": len(candidate_rows),
        "pairs_executed_gold": len(gold_rows),
        "workers": len(resources),
        "jobs": derived_jobs,
        "slices": derived_slices,
        "row_engines": engine_report(
            {"engine": summary.get("engine"),
             "engine_version": summary.get("engine_version")},
            candidate_rows, gold_rows)["row_engines"],
        "mutation_campaign_digests": sorted(campaign_digests),
        "shard_policy": plan_policy,
        "require_complete": True,
    }
    changed_durable = sorted(
        key for key, value in durable.items() if summary.get(key) != value)
    if changed_durable:
        raise TestQualityRefused(
            "REFUSED: v2 durable summary fields differ from the root/shard "
            f"evidence in field(s) {changed_durable}.")
    planned_observations = {
        (job.get("campaign_identity") or {}).get("observation_id")
        for job in planned_jobs
    }
    if not expected:
        planned_observations = {plan["zero_pair_candidate"]["observation_id"]}
    if len(planned_observations) != 1:
        raise TestQualityRefused(
            "REFUSED: v2 candidate jobs mix observation identities.")
    planned_observation = next(iter(planned_observations))
    if not isinstance(planned_observation, str) \
            or summary.get("candidate_observation_id") \
            != planned_observation:
        raise TestQualityRefused(
            "REFUSED: v2 summary has no exact candidate observation identity.")
    # The asset index is the one population field a ruled envelope
    # equivalence speaks to: the row says the registered index and the
    # renamed one name the same population, so a campaign stamped with
    # either is this population's evidence.  It is resolved ONCE, here, and
    # lifted out of the exact joins below.  `stable` would otherwise repeat
    # this identical registry-against-summary comparison for the same field,
    # and `identity_stable` binds the shards to the value admitted here
    # rather than to the registry -- exactly as it already binds them to the
    # summary's run and generated-test digests -- so one observation still
    # cannot mix the two admissible digests across its shards.  Every other
    # population field stays an exact match.
    try:
        equivalent_indexes = (
            versions.equivalent_asset_indexes(control_population["id"])
            if getattr(controls, "_evaluation_scope", None) is None else ())
    except versions.ManifestError as exc:
        raise TestQualityRefused(f"REFUSED: {exc}") from exc
    indexes = (control_population["asset_index_sha256"], *equivalent_indexes)
    asset_index = summary.get("asset_index_sha256")
    if asset_index not in indexes:
        raise TestQualityRefused(
            f"REFUSED: v2 candidate summary asset index {asset_index!r} is "
            f"neither {control_population['id']}'s registered {indexes[0]!r} "
            f"nor a ruled envelope-equivalent {list(indexes[1:])!r}.")
    population_claims = {
        "population_id": control_population["id"],
        "asset_project": control_population["asset_project"],
        "manifest_sha256": control_population["manifest_sha256"],
        "manifest_digest": control_population["manifest_digest"],
        "map_sha256": control_population["map_sha256"],
        "release_sha256": control_population["release_sha256"],
        "engine": control_population["engine"],
        "engine_version": control_population["engine_version"],
        "parser": control_population["parser"],
    }
    changed_population = sorted(
        key for key, value in population_claims.items()
        if summary.get(key) != value)
    if changed_population:
        raise TestQualityRefused(
            "REFUSED: v2 candidate summary differs from the installed "
            f"reference population in field(s) {changed_population}.")
    reference = controls["authority"]
    # The candidate's own harness version when VERSIONS.yml declares it
    # compatible with the reference's recorded one for this project, so the
    # shards below bind to the admitted value; otherwise the recorded one,
    # which refuses by name exactly as before.
    harness_version = reference["harness_version"]
    # Likewise the campaign's applier when VERSIONS.yml accepts it beside
    # the reference's recorded one for this project.
    applier_sha256 = reference["applier_sha256"]
    # And the campaign's seed, workspace and substrate as one pair.
    seed = {key: reference[key] for key in versions.SEED_FIELDS}
    try:
        if versions.reference_harness_compatible(
                control_population["asset_project"], harness_version,
                summary.get("harness_version")):
            harness_version = summary.get("harness_version")
        if versions.reference_applier_accepted(
                control_population["asset_project"], applier_sha256,
                summary.get("applier_sha256")):
            applier_sha256 = summary.get("applier_sha256")
        if versions.reference_seed_accepted(
                control_population["asset_project"], seed, summary):
            seed = {key: summary.get(key) for key in versions.SEED_FIELDS}
    except versions.ManifestError as exc:
        raise TestQualityRefused(f"REFUSED: {exc}") from exc
    stable = {
        **population_claims,
        "mutation_validation_sha256": reference[
            "mutation_validation_sha256"],
        "mutation_validation_class": reference[
            "mutation_validation_class"],
        "substrate_baseline_sha256": seed["substrate_baseline_sha256"],
        "applier_sha256": applier_sha256,
        "harness_version": harness_version,
        "container_image_digest": reference["container_image_digest"],
        "workspace_seed_digest": seed["workspace_seed_digest"],
        "database_dump_digest": reference["database_dump_digest"],
        "timeout_seconds": reference["timeout_seconds"],
    }
    changed_summary_stable = sorted(
        key for key, value in stable.items() if summary.get(key) != value)
    if changed_summary_stable:
        raise TestQualityRefused(
            "REFUSED: v2 summary differs from installed reference controls "
            f"in stable field(s) {changed_summary_stable}.")
    identity_stable = {
        key: value for key, value in stable.items()
        if key != "population_id"
    }
    identity_stable.update({
        "asset_index_sha256": asset_index,
        "candidate_run_sha256": summary["candidate_run_sha256"],
        "candidate_generated_tests_sha256": summary[
            "candidate_generated_tests_sha256"],
        "solution_generated_tests_sha256": summary[
            "candidate_generated_tests_sha256"],
    })
    for number, planned in enumerate(planned_jobs):
        identity = planned["campaign_identity"]
        changed_identity = sorted(
            key for key, value in identity_stable.items()
            if identity.get(key) != value)
        if identity.get("kind") != "test-quality" \
                or identity.get("side") != "candidate" \
                or identity.get("sample") is not None \
                or identity.get("sample_seed") is not None \
                or changed_identity:
            raise TestQualityRefused(
                f"REFUSED: v2 candidate shard {number} differs from its "
                "sealed candidate/reference identity in field(s) "
                f"{changed_identity}.")
    return (score_single_observation(passed, candidate_rows,
                                     authority=authority, expected=expected,
                                     candidate_pair_scope=pair_scope)
            if rescore else None)


def _validate_native_summary(summary: dict, summary_path: str,
                             run_path: str, *,
                             installed_gold_reader: object = None,
                             reference_controls_reader: object = None,
                             _campaign_status: str = "complete",
                             rescore: bool = False) -> Optional[dict]:
    """Re-derive a current summary from its immutable campaign evidence.

    A run binding proves only which generated tests were scored.  Publication
    also needs proof that the verdicts in the sidecar are the arithmetic over
    the completed mutation rows, root plan, worker runtime and frozen assets.
    This validator deliberately follows those references all the way back;
    a self-consistent JSON object beside the run is not an attestation.

    With `rescore`, return the score re-derived from the same verified rows
    with the reviewed nondeterministic mutants left out (`rescore_recorded`).
    """
    if summary.get("schema") == TEST_QUALITY_SUMMARY_SCHEMA_V2:
        return _validate_single_observation_summary(
            summary, summary_path, run_path,
            reference_reader=reference_controls_reader,
            campaign_status=_campaign_status, rescore=rescore)

    from ..data import mutation_attestation as A
    from . import worker as W
    from .mutation_run import (CAMPAIGN_IDENTITY_FIELDS_V2_ADDED,
                               CAMPAIGN_IDENTITY_FIELDS_V4_ADDED,
                               MutationAborted, campaign_identity_digest,
                               completed_pairs, content_digest,
                               pair_set_digest, sha256_file,
                               validate_native_shards)

    if _campaign_status not in {"running", "complete"}:
        raise AssertionError(
            f"unsupported native-summary campaign status "
            f"{_campaign_status!r}")
    if summary.get("schema") != TEST_QUALITY_SUMMARY_SCHEMA:
        raise TestQualityRefused(
            f"REFUSED: native test-quality sidecar is not a "
            f"{TEST_QUALITY_SUMMARY_SCHEMA} document.")
    from . import slice3_test_quality as S3Q
    if S3Q.JOIN_KEY in summary:
        # SLICE3_TEST_QUALITY_SPEC.md §2.5: the additive Slice-3 acceptance
        # path, reachable only when the sidecar carries the join
        # discriminator.  Every docx/CoreShop summary takes the unchanged
        # path below, because none of them carries it.
        S3Q.validate_summary(summary, summary_path, run_path)
        return
    required_paths = {
        "run", "gold_baseline", "manifest", "map", "release",
        "mutation_validation", "candidate_results", "gold_results", "seed",
    }
    missing_paths = sorted(
        key for key in required_paths
        if not isinstance(summary.get(key), str) or not summary.get(key))
    if missing_paths:
        raise TestQualityRefused(
            f"REFUSED: native test-quality summary omits evidence path(s) "
            f"{missing_paths}.")
    if os.path.lexists(str(run_path) + ".headroom.json") or os.path.basename(summary["release"]).startswith("headroom_"):
        from ..java import kapua_headroom as H
        try:
            H.validate_candidate_workset(run_path, summary["release"])
        except (ValueError, OSError) as exc:
            raise TestQualityRefused(str(exc)) from exc
    verdict_basis = summary.get("verdict_basis")
    hard_mode = verdict_basis == "hard_subset"
    if verdict_basis not in ("full_gold", "hard_subset"):
        raise TestQualityRefused(
            f"REFUSED: current native summary has missing or unsupported "
            f"verdict_basis {verdict_basis!r}; current native summaries must "
            "explicitly say full_gold (sensitivity only) or hard_subset. "
            "Preserved summaries without this field are readable only through "
            "an authenticated legacy-rebinding wrapper.")
    hard_doc = None
    candidate_hard_rows = None
    candidate_hard_campaign = None
    candidate_hard_run_1_observation_id = None
    candidate_hard_observation_id = None
    if hard_mode:
        hard_path = summary.get("hard_subset")
        rerun_paths = summary.get("candidate_hard_rerun_results")
        rerun_hashes = summary.get("candidate_hard_rerun_sha256")
        claimed_observation = summary.get(
            "candidate_hard_rerun_observation_id")
        claimed_run_1_observation = summary.get(
            "candidate_hard_run_1_observation_id")
        rerun_fields_present = (
            "candidate_hard_rerun_results" in summary,
            "candidate_hard_rerun_sha256" in summary,
            "candidate_hard_rerun_observation_id" in summary,
            "candidate_hard_run_1_observation_id" in summary,
        )
        if not isinstance(hard_path, str) or not hard_path:
            raise TestQualityRefused(
                "REFUSED: hard-basis native summary omits its pinned hard "
                "artifact.")
        if any(rerun_fields_present) != all(rerun_fields_present):
            raise TestQualityRefused(
                "REFUSED: hard-basis native summary partially records "
                "candidate run 2; paths, hashes and standalone observation "
                "identities must travel together.")
        has_rerun = all(rerun_fields_present)
        if has_rerun and (
                not isinstance(rerun_paths, list) or not rerun_paths
                or not all(isinstance(path, str) and path
                           for path in rerun_paths)
                or not isinstance(rerun_hashes, list)
                or len(rerun_hashes) != len(rerun_paths)):
            raise TestQualityRefused(
                "REFUSED: hard-basis native summary has malformed candidate "
                "run-2 paths/hashes.")
        from ..toolkit.hard_subset import HardSubsetRefused, load as load_hard_subset
        try:
            hard_doc = load_hard_subset(
                hard_path,
                expected_population_id=summary.get(
                    "hard_subset_population_id"), require_pin=True)
            if has_rerun:
                candidate_hard_campaign = validate_native_shards(
                    rerun_paths, required_side="candidate",
                    return_campaign=True)
                candidate_hard_observation_id = _hard_rerun_observation_id(
                    candidate_hard_campaign, claimed_observation)
        except (HardSubsetRefused, MutationAborted, OSError, ValueError) as exc:
            raise TestQualityRefused(str(exc)) from exc
        if (has_rerun
                and [sha256_file(path) for path in rerun_paths] != rerun_hashes) \
                or sha256_file(hard_path) != summary.get("hard_subset_sha256") \
                or hard_doc["digest"] != summary.get("hard_subset_digest"):
            raise TestQualityRefused(
                "REFUSED: hard artifact or candidate run-2 bytes changed.")
        if has_rerun:
            candidate_hard_rows = candidate_hard_campaign["rows"]
    if os.path.abspath(summary["run"]) != os.path.abspath(run_path):
        raise TestQualityRefused(
            "REFUSED: native test-quality summary names another candidate "
            "run path.")

    candidate_path = os.path.abspath(summary["candidate_results"])
    gold_path = os.path.abspath(summary["gold_results"])
    out_dir = os.path.dirname(candidate_path)
    if os.path.basename(candidate_path) != CANDIDATE_ROWS \
            or gold_path != os.path.join(out_dir, GOLD_ROWS):
        raise TestQualityRefused(
            "REFUSED: native test-quality rows are not the canonical paired "
            "artifacts in one campaign directory.")
    canonical_path = os.path.join(out_dir, SUMMARY)
    canonical = _load_json_object(canonical_path,
                                  "canonical test-quality summary")
    if canonical != summary:
        raise TestQualityRefused(
            f"REFUSED: sidecar {summary_path} differs from the canonical "
            f"campaign summary {canonical_path}.")
    candidate_rows = load_jsonl(candidate_path)
    gold_rows = load_jsonl(gold_path)
    if summary.get("candidate_rows_sha256") != sha256_file(candidate_path) \
            or summary.get("gold_rows_sha256") != sha256_file(gold_path):
        raise TestQualityRefused(
            "REFUSED: native summary mutation-row hashes do not match its "
            "preserved candidate/gold evidence.")

    state_path = _campaign_state_path(out_dir)
    state_doc = _load_json_object(state_path,
                                  "test-quality root campaign record")
    plan = state_doc.get("plan")
    state = _validate_campaign_state(state_doc, plan)
    plan_shard_policy = shard_policy_from_plan(plan)
    policy_identity_bound = policy_identity_binding_from_plan(plan)
    summary_shard_policy = summary.get("shard_policy")
    if plan.get("schema") == TEST_QUALITY_PLAN_SCHEMA_V1:
        # Historical native summaries predate this disclosure.  Absence is
        # therefore the one admissible legacy spelling; a present value must
        # tell the truth about the v1 plan rather than relabel it.
        if summary_shard_policy not in (None, plan_shard_policy):
            raise TestQualityRefused(
                "REFUSED: native summary scheduling policy differs from its "
                "historical v1 root plan.")
    elif summary_shard_policy != plan_shard_policy:
        raise TestQualityRefused(
            "REFUSED: native summary scheduling policy differs from its "
            "root campaign plan.")
    if state["status"] != _campaign_status \
            or summary.get("root_campaign_plan_sha256") \
            != content_digest(plan):
        raise TestQualityRefused(
            f"REFUSED: native test-quality summary is not bound to its "
            f"{_campaign_status} root campaign plan.")
    if candidate_hard_campaign is not None:
        # Both values are 128-bit mutation-observation identities.  Run 1 is
        # domain-separated from the producer-owned root plan; run 2 is the
        # independently minted standalone identity validated above.
        candidate_hard_run_1_observation_id = \
            _d4_run_1_observation_id(plan)
        if claimed_run_1_observation \
                != candidate_hard_run_1_observation_id:
            raise TestQualityRefused(
                "REFUSED: D4 run-1 observation identity differs from the "
                "authenticated root campaign plan.")
        if candidate_hard_run_1_observation_id \
                == candidate_hard_observation_id:
            raise TestQualityRefused(
                "REFUSED: D4 candidate run 2 copied run 1's observation_id; "
                "the two complete executions are not independently "
                "identified.")

    # A root whose per-side jobs carry minted observation identities is a
    # bound-observation campaign; under Slice-3 such a campaign scores a
    # PAID VIEW of the population its map was built over, and the report's
    # release pin keeps naming that population.  Historical v1 plans have no
    # observation binding, so this is False for them; a bound root that
    # hands the population itself (the docx cap-bound shape) is unaffected
    # because the subset path collapses to the strict default whenever the
    # handed release is byte-equal to the pinned population document.
    budgeted_sidecar = None
    if "kapua_reference_evidence" in summary:
        from ..java import kapua_reference as KRef
        budgeted_sidecar, installed_gold_reader = KRef.saved_context(summary)
    if "prestashop_reference_evidence" in summary:
        if "kapua_reference_evidence" in summary:
            raise TestQualityRefused("REFUSED: saved result names two project reference authorities")
        from . import prestashop_reference as PRef
        budgeted_sidecar, installed_gold_reader = PRef.saved_context(summary)
    observation_bound_root = isinstance(plan, dict) and any(
        value is not None
        for value in (plan.get("observation_ids_by_side") or {}).values())
    try:
        assets = A.validate_campaign_asset_inputs(
            summary["mutation_validation"],
            manifest_path=summary["manifest"], map_path=summary["map"],
            release_path=summary["release"], require_release_ready=True,
            paid_view_subset=observation_bound_root,
            **({"budgeted_sidecar": budgeted_sidecar} if budgeted_sidecar is not None else {}))
    except (A.MutationAssetRefused, OSError, ValueError) as e:
        raise TestQualityRefused(str(e)) from e
    manifest, by_mutant = assets["manifest"], assets["map"]["by_mutant"]
    asset_claims = {
        "asset_index_sha256": assets["asset_index_sha256"],
        "asset_project": assets["asset_project"],
        "mutation_validation_sha256": sha256_file(
            summary["mutation_validation"]),
        "mutation_validation_class": assets["validation_class"],
        "manifest_sha256": sha256_file(summary["manifest"]),
        "manifest_digest": manifest.get("digest"),
        "map_sha256": sha256_file(summary["map"]),
        "release_sha256": sha256_file(summary["release"]),
    }
    asset_claims.update({key: assets[key] for key in
                         ("population_basis", "budgeted_sample_sha256", "parent_map_sha256")
                         if key in assets})
    changed_assets = sorted(
        key for key, value in asset_claims.items()
        if summary.get(key) != value)
    if changed_assets:
        raise TestQualityRefused(
            f"REFUSED: native summary differs from its validated mutation "
            f"assets in field(s) {changed_assets}.")
    if candidate_hard_campaign is not None:
        hard_identity = candidate_hard_campaign["campaign_identity"]
        expected_hard_identity = {
            "asset_index_sha256": summary.get("asset_index_sha256"),
            "asset_project": summary.get("asset_project"),
            "mutation_validation_sha256": summary.get(
                "mutation_validation_sha256"),
            "mutation_validation_class": summary.get(
                "mutation_validation_class"),
            "manifest_sha256": summary.get("manifest_sha256"),
            "manifest_digest": summary.get("manifest_digest"),
            "map_sha256": summary.get("map_sha256"),
            "release_sha256": summary.get("release_sha256"),
            "candidate_run_sha256": summary.get("candidate_run_sha256"),
            "candidate_generated_tests_sha256": summary.get(
                "candidate_generated_tests_sha256"),
            "solution_generated_tests_sha256": summary.get(
                "candidate_generated_tests_sha256"),
            "substrate_baseline_sha256": summary.get(
                "substrate_baseline_sha256"),
            "applier_sha256": summary.get("applier_sha256"),
            "engine": summary.get("engine"),
            "engine_version": summary.get("engine_version"),
            "parser": summary.get("parser"),
            "harness_version": summary.get("harness_version"),
            "container_image_digest": summary.get(
                "container_image_digest"),
            "workspace_seed_digest": summary.get("workspace_seed_digest"),
            "database_dump_digest": summary.get("database_dump_digest"),
            **{key: summary.get(key)
               for key in sorted(CAMPAIGN_IDENTITY_FIELDS_V2_ADDED)},
        }
        changed_hard = sorted(
            key for key, value in expected_hard_identity.items()
            if hard_identity.get(key) != value)
        if hard_identity.get("kind") != "mutation-run" \
                or hard_identity.get("sample") is not None \
                or hard_identity.get("sample_seed") is not None \
                or changed_hard:
            raise TestQualityRefused(
                "REFUSED: candidate hard rerun is not an unsampled native "
                f"observation of this candidate/population; changed "
                f"field(s) {changed_hard}.")
        refuse_unpublishable_generation(
            hard_identity.get("generation_provenance_class"),
            "the candidate hard rerun")
    registered = registered_population_id(
        assets["asset_project"], manifest.get("digest"),
        summary.get("engine"), summary.get("engine_version"))
    # Native summaries are current, regenerable evidence.  Once a real
    # project's population is registered, absence is not a legacy state: it
    # is indistinguishable from deleting the field by hand and would let a v1
    # and v2 summary compare on their intentionally unchanged engine@version.
    # Preserved historical summaries take the explicit legacy-rebinding path
    # below instead; their source bytes are never rewritten.
    if registered is not None and summary.get("population_id") != registered:
        raise TestQualityRefused(
            f"REFUSED: native summary must claim population_id "
            f"{registered!r} resolved from its frozen assets; got "
            f"{summary.get('population_id')!r}.")
    if registered is None and "population_id" in summary:
        raise TestQualityRefused(
            f"REFUSED: native summary claims population_id "
            f"{summary.get('population_id')!r}, but its frozen assets do not "
            f"resolve to a registered population.")

    run_rows = load_jsonl(run_path)
    gold_baseline_rows = load_jsonl(summary["gold_baseline"])
    passed = passed_solutions(run_rows)
    # The label is re-derived from the run rows, never read back: a summary
    # may name a sensitivity only when every row it scored carries it.
    sensitivity = run_sensitivity(run_rows)
    if summary.get("sensitivity") != sensitivity \
            or ("sensitivity" in summary) != (sensitivity is not None):
        raise TestQualityRefused(
            "REFUSED: native summary's sensitivity label differs from the "
            "label its candidate run rows carry.")
    gold_files, gold_baseline = gold_side(gold_baseline_rows, passed)
    if set(passed) - set(gold_files):
        raise TestQualityRefused(
            "REFUSED: native summary's gold baseline no longer covers every "
            "passed candidate item.")
    mutants, restricted, covering = population(manifest, by_mutant, passed)
    expected = expected_pairs(restricted)
    # Which pairs each side executed (GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md),
    # re-derived from the gold rows and pair plan named here, never read back
    # from a count.  `all` reproduces the population above unchanged.
    population_pairs = expected
    gold_plan = None
    gold_plan_binding = summary.get("gold_pair_plan")
    if gold_plan_binding is not None:
        if not isinstance(gold_plan_binding, dict) \
                or set(gold_plan_binding) != {"path", "sha256"} \
                or not isinstance(gold_plan_binding.get("path"), str):
            raise TestQualityRefused(
                "REFUSED: native summary has a malformed gold pair plan "
                "binding.")
        gold_plan, reread_binding = load_gold_pair_plan(
            gold_plan_binding["path"], manifest_digest=manifest.get("digest"))
        if reread_binding != gold_plan_binding:
            raise TestQualityRefused(
                "REFUSED: the gold pair plan's bytes or path changed since "
                "the campaign ran.")
    scope = candidate_pair_scope(
        scope=summary.get("candidate_pair_scope", CANDIDATE_PAIRS_ALL),
        passed=passed, mutants=mutants, restricted=restricted,
        gold_rows=(gold_rows if summary.get("gold_rows_precomputed") is True
                   else None),
        gold_baseline=gold_baseline, gold_plan=gold_plan)
    expected, candidate_expected = scope["expected"], scope["candidate"]
    if summary.get("candidate_run_sha256") != sha256_file(run_path) \
            or summary.get("gold_baseline_sha256") \
            != sha256_file(summary["gold_baseline"]):
        raise TestQualityRefused(
            "REFUSED: native summary run/gold-baseline byte digests changed.")
    from .mutation_run import candidate_digest
    if summary.get("candidate_generated_tests_sha256") \
            != candidate_digest(passed) \
            or summary.get("gold_generated_tests_sha256") \
            != candidate_digest(gold_files):
        raise TestQualityRefused(
            "REFUSED: native summary generated-test digests do not match the "
            "candidate and gold rows it names.")

    resources = plan.get("worker_resources") if isinstance(plan, dict) else None
    if not isinstance(resources, list) or resources != summary.get(
            "worker_resources"):
        raise TestQualityRefused(
            "REFUSED: native summary/root plan disagree about the ordered "
            "worker assignment.")
    if not isinstance(summary.get("workers"), int) \
            or isinstance(summary.get("workers"), bool) \
            or len(resources) != summary["workers"] \
            or [record.get("index") for record in resources
                if isinstance(record, dict)] != list(range(len(resources))):
        raise TestQualityRefused(
            "REFUSED: native root plan does not carry the exact ordered "
            "zero-based worker pool named by the summary.")
    try:
        seed = W.verified_seed_identity(
            summary["seed"],
            summary.get("database_dump_digest") != "no_database")
    except W.WorkerRefused as e:
        raise TestQualityRefused(str(e)) from e
    for key in ("workspace_seed_digest", "database_dump_digest"):
        if seed[key] != summary.get(key):
            raise TestQualityRefused(
                f"REFUSED: verified seed {key} differs from native summary.")
    resource_fields = {
        "index", "worker_spec", "workspace", "container", "schema",
        "credential", "env_file", "workdir", "runtime_attestation",
        "runtime_attestation_sha256",
    }
    runtime_identities = set()
    runtime_versions = set()
    spec_paths = []
    for number, record in enumerate(resources):
        if not isinstance(record, dict) or set(record) != resource_fields:
            raise TestQualityRefused(
                f"REFUSED: root worker resource {number} has missing or "
                "unknown fields.")
        att_path = record["runtime_attestation"]
        spec_path = record["worker_spec"]
        if os.path.islink(att_path) or not os.path.isfile(att_path) \
                or os.path.islink(spec_path) or not os.path.isfile(spec_path) \
                or not _is_sha256(record.get("runtime_attestation_sha256")) \
                or sha256_file(att_path) \
                != record["runtime_attestation_sha256"]:
            raise TestQualityRefused(
                f"REFUSED: worker runtime attestation changed for worker "
                f"{record.get('index')}.")
        att = _load_json_object(att_path, "worker runtime attestation")
        worker_doc = att.get("worker") if isinstance(att, dict) else None
        expected_resource = {
            "index": record["index"],
            "workspace": record["workspace"],
            "container": record["container"],
            "schema": record["schema"],
            "credential": record["credential"],
            "env_file": record["env_file"],
            "workdir": record["workdir"],
        }
        runtime_version = W.worker_runtime_version(att)
        from ..core.docker_cli import valid_endpoint_selection
        if runtime_version not in {"v1", "v2", "v3", "v4"} \
                or not isinstance(worker_doc, dict) \
                or any(worker_doc.get(key) != value
                       for key, value in expected_resource.items()) \
                or sha256_file(spec_path) \
                != att.get("worker_spec_sha256") \
                or att.get("container_image_digest") \
                != summary.get("container_image_digest") \
                or att.get("harness_version") \
                != summary.get("harness_version") \
                or att.get("workspace_seed_digest") \
                != summary.get("workspace_seed_digest") \
                or att.get("database_dump_digest") \
                != summary.get("database_dump_digest") \
                or (runtime_version == "v2" and not valid_endpoint_selection(
                    att.get("docker_endpoint_selection"))) \
                or any(att.get(key) != seed.get(key) for key in (
                    "seed_dir", "seed_manifest_sha256", "seed_key",
                    "workspace_seed_digest", "database_dump_digest",
                    "needs_database")):
            raise TestQualityRefused(
                f"REFUSED: worker {record.get('index')} runtime evidence "
                "does not match the summary/root assignment.")
        if runtime_version in {"v3", "v4"}:
            try:
                checked_v3 = W.validate_worker_runtime_v3(spec_path)
            except W.WorkerRefused as e:
                raise TestQualityRefused(
                    f"REFUSED: worker {record.get('index')} runtime "
                    f"evidence is invalid: {e}") from e
            if os.path.realpath(att_path) != checked_v3["runtime_path"] \
                    or att != checked_v3["runtime"]:
                raise TestQualityRefused(
                    f"REFUSED: worker {record.get('index')} v3 runtime "
                    "does not occupy its authority-bound path.")
            runtime_identities.add((
                runtime_version,
                json.dumps(att["docker_execution_authority"],
                           sort_keys=True, separators=(",", ":")),
                checked_v3["binding"]["pool"]["digest"],
            ))
        else:
            runtime_identities.add((
                runtime_version, att.get("docker_endpoint_selection")))
        runtime_versions.add(runtime_version)
        spec_paths.append(spec_path)
    if len(runtime_identities) != 1:
        raise TestQualityRefused(
            "REFUSED: native workers carry mixed Docker authority/route "
            "identities.")
    if runtime_versions in ({"v3"}, {"v4"}):
        try:
            W.validate_offline_worker_runtime_pool(spec_paths)
        except W.WorkerRefused as e:
            raise TestQualityRefused(
                f"REFUSED: worker-pool runtime evidence is invalid: {e}") \
                from e
    if plan.get("worker_resources_sha256") != content_digest(resources) \
            or summary.get("worker_resources_sha256") \
            != content_digest(resources):
        raise TestQualityRefused(
            "REFUSED: ordered worker-resource digest does not match the root "
            "assignment.")

    planned_jobs = plan.get("jobs") if isinstance(plan, dict) else None
    if not isinstance(planned_jobs, list) or not planned_jobs:
        raise TestQualityRefused(
            "REFUSED: complete native campaign has no planned mutation jobs.")
    first_identity = planned_jobs[0].get("campaign_identity") or {}
    shared_keys = (
        "asset_index_sha256", "asset_project",
        "mutation_validation_sha256", "mutation_validation_class",
        "manifest_sha256", "manifest_digest", "map_sha256",
        "release_sha256", "candidate_run_sha256",
        "candidate_generated_tests_sha256", "gold_baseline_sha256",
        "gold_generated_tests_sha256", "gold_results_sha256",
        "gold_results_attestation_sha256", "gold_provenance_class",
        "gold_attestation_manifest_digest", "gold_attestation_pairs_sha256",
        "gold_attestation_engine", "gold_attestation_engine_version",
        "substrate_baseline_sha256", "applier_sha256",
        "worker_resources_sha256", "harness_version",
        "container_image_digest", "workspace_seed_digest",
        "database_dump_digest", "engine", "engine_version", "parser",
        # The v2 generation half is shared too: every shard of one campaign
        # scored a candidate produced by ONE attempt, so a saved report whose
        # jobs disagree here is a cross-attempt merge that reached disk.
        *sorted(CAMPAIGN_IDENTITY_FIELDS_V2_ADDED),
        # v4 execution/cap/projection/cache fields are shared by every shard;
        # the per-shard expected pair digest remains outside this tuple.
        *sorted(CAMPAIGN_IDENTITY_FIELDS_V4_ADDED),
    )
    shared_keys += tuple(key for key in
                         ("population_basis", "budgeted_sample_sha256", "parent_map_sha256")
                         if key in first_identity)
    identity_inputs = {key: first_identity.get(key) for key in shared_keys}
    from .mutation_run import runtime_applier_sha256
    try:
        applier_sha256 = runtime_applier_sha256(manifest.get("engine"),
                                                summary["seed"])
    except MutationAborted as e:
        raise TestQualityRefused(str(e)) from e
    independent_identity = {
        **asset_claims,
        "candidate_run_sha256": sha256_file(run_path),
        "candidate_generated_tests_sha256": candidate_digest(passed),
        "gold_baseline_sha256": sha256_file(summary["gold_baseline"]),
        "gold_generated_tests_sha256": candidate_digest(gold_files),
        "applier_sha256": applier_sha256,
        "worker_resources_sha256": content_digest(resources),
        "harness_version": summary.get("harness_version"),
        "container_image_digest": summary.get("container_image_digest"),
        "workspace_seed_digest": seed["workspace_seed_digest"],
        "database_dump_digest": seed["database_dump_digest"],
        "engine": manifest.get("engine"),
        "engine_version": manifest.get("engine_version"),
        "parser": manifest.get("parser"),
    }
    mixed_shared = sorted(
        key for key, value in independent_identity.items()
        if identity_inputs.get(key) != value or summary.get(key) != value)
    if mixed_shared:
        raise TestQualityRefused(
            f"REFUSED: native summary/shard identity differs from independently "
            f"re-derived input field(s) {mixed_shared}.")
    for key in ("substrate_baseline_sha256",
                *sorted(CAMPAIGN_IDENTITY_FIELDS_V2_ADDED)):
        if summary.get(key) != identity_inputs.get(key):
            raise TestQualityRefused(
                f"REFUSED: native summary {key} differs from its shard "
                "campaign identity.")
    # THE PUBLICATION SURFACE.  This is the reader `report`, `results` and the
    # compatibility gate reach a native number through, so it is where a
    # defaulted generation class must stop.
    refuse_unpublishable_generation(
        identity_inputs.get("generation_provenance_class"),
        f"the native saved report {summary_path}",
        # THE ONE ALLOWED SITE.  `results` turns any refusal from this reader
        # into a whole-table input error, so refusing here costs the thirteen
        # rows and not the three that rest on the class.  The class is asked
        # again at `publication_ready`, which withholds those three rows on
        # the class itself, so what this line relaxes is the blast radius of
        # the refusal and not the rule.
        allow_development=True)
    for job in planned_jobs[1:]:
        other = job.get("campaign_identity") or {}
        changed = sorted(key for key in shared_keys
                         if other.get(key) != identity_inputs.get(key))
        if changed:
            raise TestQualityRefused(
                f"REFUSED: native root plan mixes shared campaign identity "
                f"field(s) {changed}.")
    timeout_values = {
        job.get("campaign_identity", {}).get("timeout_seconds")
        for job in planned_jobs
    }
    if len(timeout_values) != 1:
        raise TestQualityRefused(
            "REFUSED: native root plan mixes mutation timeout semantics.")
    timeout = next(iter(timeout_values))
    if ("kapua_reference_evidence" in summary or "prestashop_reference_evidence" in summary) \
            and summary.get("timeout_seconds") != timeout:
        raise TestQualityRefused("REFUSED: Kapua reference summary timeout differs from its candidate jobs.")
    if candidate_hard_campaign is not None \
            and candidate_hard_campaign["campaign_identity"].get(
            "timeout_seconds") != timeout:
        raise TestQualityRefused(
            "REFUSED: candidate hard rerun changed the mutation timeout "
            "semantics from the candidate's first observation.")
    n_workers = summary.get("workers")
    if not isinstance(n_workers, int) or isinstance(n_workers, bool):
        raise TestQualityRefused(
            "REFUSED: native summary has no integer worker count.")
    gold_precomputed = summary.get("gold_rows_precomputed")
    if not isinstance(gold_precomputed, bool):
        raise TestQualityRefused(
            "REFUSED: native summary does not declare precomputed-gold use.")
    sides = ("candidate",) if gold_precomputed else SIDES
    cap_bound = plan.get("schema") == TEST_QUALITY_PLAN_SCHEMA_V3
    compute_cap = plan.get("compute_cap") if cap_bound else None
    if cap_bound:
        cap_summary = {
            "compute_cap": compute_cap,
            **{key: plan.get(key) for key in (
                "projection_by_side", "observation_ids_by_side",
                "estimand_pairs_sha256", "delta_pairs_sha256_by_side",
                "final_artifact_types_by_side")},
            **{key: identity_inputs.get(key)
               for key in sorted(CAMPAIGN_IDENTITY_FIELDS_V4_ADDED)},
        }
        changed = sorted(key for key, value in cap_summary.items()
                         if summary.get(key) != value)
        if changed:
            raise TestQualityRefused(
                "REFUSED: cap-bound native summary differs from its root "
                f"plan in field(s) {changed}.")
    rebuilt_jobs = plan_jobs(
        scope["mutants"], {"candidate": passed, "gold": gold_files},
        scope["restricted"],
        n_workers, out_dir, sides=sides, identity_inputs=identity_inputs,
        timeout=timeout, shard_policy=plan_shard_policy,
        bind_shard_policy=policy_identity_bound,
        **_v4_execution_kwargs(first_identity))
    rebuilt_plan = build_test_quality_campaign_plan(
        rebuilt_jobs, expected=expected, candidate_scope=scope["record"],
        require_complete=summary.get("require_complete"),
        gold_precomputed=gold_precomputed, worker_resources=resources,
        campaign_dir=out_dir, compute_cap=compute_cap, sensitivity=sensitivity)
    if rebuilt_plan != plan:
        raise TestQualityRefused(
            "REFUSED: native root plan cannot be re-derived from its frozen "
            "population, run, runtime and worker assignment.")
    validate_output_contents(
        out_dir, rebuilt_jobs,
        final_names=(CANDIDATE_ROWS, GOLD_ROWS, SUMMARY),
        campaign_plan=rebuilt_plan, campaign_status=_campaign_status)

    def validate_merged_side(side: str, merged: list[dict],
                             wanted: set) -> None:
        combined = []
        seen = set()
        for job in [job for job in rebuilt_jobs if job["side"] == side]:
            pairs = _job_pairs(job["mutants"], job["by_mutant"],
                               job["files_by_item"])
            try:
                completed_pairs(job["out"], job["identity"],
                                expected_pairs=pairs,
                                require_complete=True,
                                expected_shard_policy=plan_shard_policy,
                                allow_missing_shard_policy=(
                                    plan.get("schema")
                                    == TEST_QUALITY_PLAN_SCHEMA_V1))
            except MutationAborted as e:
                raise TestQualityRefused(str(e)) from e
            for row in load_jsonl(job["out"]):
                pair = (row.get("item_id"), row.get("mutant_id"))
                if pair in seen:
                    raise TestQualityRefused(
                        f"REFUSED: native {side} shards repeat pair {pair}.")
                seen.add(pair)
                combined.append(row)
        if combined != merged or seen != wanted:
            raise TestQualityRefused(
                f"REFUSED: native merged {side} rows differ from the exact "
                "complete planned shards.")

    validate_merged_side("candidate", candidate_rows, candidate_expected)
    if not gold_precomputed:
        validate_merged_side("gold", gold_rows, expected)
        if gold_plan is not None and installed_gold_reader is not None:
            # A project reference re-observed on this host: its plan must be
            # exactly that reference's kills on this population.
            if _reference_kill_pairs(installed_gold_reader, summary,
                                     population_pairs) \
                    != population_pairs & gold_plan:
                raise TestQualityRefused(
                    "REFUSED: the gold pair plan is not the reference "
                    "evidence's full-gold kills on this candidate's pairs.")
    elif installed_gold_reader is not None:
        selected_rows = _read_authenticated_installed_gold(
            installed_gold_reader, summary=summary, expected=expected,
            identity_inputs=identity_inputs)
        if selected_rows != gold_rows:
            raise TestQualityRefused(
                "REFUSED: copied installed gold differs from the exact "
                "selection re-derived from its unchanged raw authority.")
    else:
        source_path = summary.get("gold_results_source")
        attestation_path = summary.get("gold_results_attestation")
        if not isinstance(source_path, str) \
                or not isinstance(attestation_path, str):
            raise TestQualityRefused(
                "REFUSED: precomputed native gold omits its source rows or "
                "attestation path.")
        source_rows = load_jsonl(source_path)
        attestation = _load_json_object(
            attestation_path, "precomputed-gold attestation")
        if source_rows != gold_rows \
                or sha256_file(source_path) \
                != identity_inputs["gold_results_sha256"]:
            raise TestQualityRefused(
                "REFUSED: copied precomputed gold differs from its attested "
                "source rows.")
        gold_binding = validate_precomputed_gold_attestation(
            attestation, inputs=identity_inputs, passed=passed,
            gold_files=gold_files, expected=expected, gold_rows=source_rows,
            manifest_digest=manifest.get("digest"),
            require_complete=summary.get("require_complete"),
            attestation_path=attestation_path, timeout=timeout)
        if summary.get("gold_provenance_class") \
                != gold_binding["validation_class"] \
                or identity_inputs.get("gold_provenance_class") \
                != gold_binding["validation_class"] \
                or identity_inputs.get("gold_attestation_manifest_digest") \
                != gold_binding["manifest_digest"] \
                or identity_inputs.get("gold_attestation_pairs_sha256") \
                != gold_binding["pairs_sha256"] \
                or identity_inputs.get("gold_attestation_engine") \
                != gold_binding["engine"] \
                or identity_inputs.get("gold_attestation_engine_version") \
                != gold_binding["engine_version"] \
                or sha256_file(attestation_path) \
                != identity_inputs.get("gold_results_attestation_sha256"):
            raise TestQualityRefused(
                "REFUSED: precomputed-gold validation facts differ from the "
                "native shard identities or summary.")
    if not gold_precomputed:
        optional_gold = (
            "gold_results_sha256", "gold_results_attestation_sha256",
            "gold_provenance_class", "gold_attestation_manifest_digest",
            "gold_attestation_pairs_sha256", "gold_attestation_engine",
            "gold_attestation_engine_version",
        )
        if summary.get("gold_provenance_class") != "native" \
                or any(identity_inputs.get(key) is not None
                       for key in optional_gold):
            raise TestQualityRefused(
                "REFUSED: freshly executed gold carries cached-gold identity "
                "claims or is not reported as native.")

    gold_killed, ignored, gold_infrastructure = gold_kill_sets(
        scored_gold_rows(gold_rows, summary, gold_plan),
        gold_baseline, passed)
    hard_killed = (hard_kill_sets(
        hard_doc, population_id=summary.get("population_id"), items=passed,
        manifest_digest=manifest.get("digest")) if hard_mode else None)

    def derive(unscored: frozenset) -> dict:
        derived = score(
            passed, covering, gold_killed, gold_baseline, candidate_rows,
            expected=(candidate_expected if summary.get("require_complete")
                      else None),
            hard_killed=hard_killed, candidate_rows_run_2=candidate_hard_rows,
            unscored=unscored)
        if scope["record"] is not None:
            withhold_gold_killed_companions(derived)
        return derived

    # As scored: a summary of an earlier harness kept the listed mutants.
    recomputed = derive(unscored_mutants(summary.get("harness_version")))
    semantic = {
        **recomputed,
        **gold_killed_summary_fields(scope, gold_plan_binding),
        **engine_report(manifest, candidate_rows, gold_rows),
        "mutants_in_population": len(mutants),
        "pairs_expected": len(expected),
        "pairs_executed_candidate": len(candidate_rows),
        "pairs_executed_gold": len(gold_rows),
        "gold_kills_ignored_ineligible_baseline": ignored,
        "gold_infrastructure_outcomes": gold_infrastructure,
        # Re-derived, not read back: the per-item disclosure ruling 2.6 makes
        # travel with a published number is evidence, so an edited list must
        # refuse here exactly as an edited count does.
        "gold_infrastructure_pairs": gold_infrastructure_pairs(
            gold_rows, gold_baseline, passed),
        "gold_rows_missing": len(missing_pairs(expected, gold_rows)),
        "expected_pairs_sha256": pair_set_digest(expected),
        "mutation_campaign_digests": sorted(
            campaign_identity_digest(job["identity"])
            for job in rebuilt_jobs),
    }
    changed_semantic = sorted(
        key for key, value in semantic.items() if summary.get(key) != value)
    if changed_semantic:
        raise TestQualityRefused(
            f"REFUSED: native summary arithmetic/provenance differs from its "
            f"rows in field(s) {changed_semantic[:12]}.")
    return derive(nondeterministic_mutants()) if rescore else None


def _validate_native_summary_before_completion(
        summary: dict, summary_path: str, run_path: str, *,
        installed_gold_reader: object = None,
        reference_controls_reader: object = None) -> None:
    """Re-derive final artifacts before publishing root completion.

    The ordinary saved-evidence reader remains strict about ``complete``.
    This producer-only gate runs the same validation against the still-running
    root; only after it succeeds may the atomic state transition bind the
    artifact hashes and publish completion.
    """
    kwargs = {"installed_gold_reader": installed_gold_reader,
              "_campaign_status": "running"}
    if reference_controls_reader is not None:
        kwargs["reference_controls_reader"] = reference_controls_reader
    _validate_native_summary(summary, summary_path, run_path, **kwargs)


def load_bound_test_quality(run_path: str,
                            summary_path: Optional[str] = None, *,
                            installed_gold_reader: object = None,
                            reference_controls_reader: object = None
                            ) -> Optional[dict]:
    """Load and verify the only test-quality summary attributable to a run.

    ``None`` means no sidecar exists.  A sidecar that exists but is unbound,
    stale or ambiguous is a refusal, never the same thing as absence and never
    a score of zero.
    """
    loaded = _load_bound(run_path, summary_path,
                         installed_gold_reader=installed_gold_reader,
                         reference_controls_reader=reference_controls_reader)
    return None if loaded is None else loaded[0]


def rescore_recorded(run_path: str, summary_path: str, *,
                     reference_controls_reader: object = None) -> tuple:
    """`(summary, rescored)`: a recorded summary and its score under D.

    Correction D needs no execution (specifications/EVALUATOR_CORRECTIONS_
    20261015_AMENDMENT.md section 5, step 4).  The summary is bound and
    re-derived as `load_bound_test_quality` does, as it was scored, and
    `rescored` is the same arithmetic over the same verified rows with the
    reviewed nondeterministic mutants left out.  Nothing is written.
    """
    loaded = _load_bound(run_path, summary_path, rescore=True,
                         reference_controls_reader=reference_controls_reader)
    if loaded is None or loaded[1] is None:
        raise TestQualityRefused(
            f"REFUSED: {run_path} has no native test-quality summary to "
            "re-score.")
    return loaded


def _load_bound(run_path: str, summary_path: Optional[str], *,
                installed_gold_reader: object = None,
                reference_controls_reader: object = None,
                rescore: bool = False) -> Optional[tuple]:
    """`(summary, rescored)` for `load_bound_test_quality`, or None.

    `rescored` is None unless `rescore` asks for it of a native summary.
    """
    discovered = find_sidecar(run_path)  # also refuses duplicate names
    path = summary_path or discovered
    if not path:
        return None
    summary = _load_json_object(path, "test-quality sidecar")
    chain = summary.get("legacy_rebinding")
    chain_paths: dict = {}
    if chain is not None:
        chain_paths = _validate_rebinding_chain(chain, run_path, summary, path)
        # Grant the historical absent-basis exception only after the complete
        # chain has been re-derived. This private in-memory type is what
        # `publication_ready` checks; no persisted boolean/schema token can
        # impersonate it.
        summary = _AuthenticatedLegacySummary(summary)
    # Both comparisons ask the same question `_build_legacy_wrapper` asks —
    # is this the same FILE — so both resolve symlinks rather than merely
    # normalising.  A wrapper whose chain names the preserved sidecar at one
    # spelling still coexists with the sidecar discovered at another spelling
    # of the same bytes; two genuinely different files still refuse.
    if summary_path and discovered \
            and os.path.realpath(summary_path) != os.path.realpath(discovered):
        if chain is None \
                or os.path.realpath(chain_paths.get("source_sidecar", "")) \
                != os.path.realpath(discovered):
            raise TestQualityRefused(
                f"REFUSED: explicit test-quality sidecar {summary_path} "
                f"conflicts with discovered sidecar {discovered}. Only a "
                "validated legacy-rebinding wrapper chained to those exact "
                "preserved bytes may coexist.")
    binding = summary.get("binding")
    if not isinstance(binding, dict) \
            or binding.get("schema") != TEST_QUALITY_BINDING_SCHEMA:
        raise TestQualityRefused(
            f"REFUSED: {path} has no {TEST_QUALITY_BINDING_SCHEMA} binding. "
            "It may be legacy evidence, but it cannot publish a current "
            "run-relative test-quality result.")
    actual = run_binding(run_path)
    if binding != actual:
        changed = sorted(k for k in set(binding) | set(actual)
                         if binding.get(k) != actual.get(k))
        raise TestQualityRefused(
            f"REFUSED: {path} is stale or tampered for {run_path}; binding "
            f"field(s) {changed} disagree. The non-vacuity result is withheld.")
    rescored = None
    if chain is None:
        kwargs = {"installed_gold_reader": installed_gold_reader}
        if reference_controls_reader is not None:
            kwargs["reference_controls_reader"] = reference_controls_reader
        if rescore:
            kwargs["rescore"] = True
        rescored = _validate_native_summary(summary, path, run_path, **kwargs)
    return summary, rescored


def validate_legacy_consistency_report(
        report: dict, *, expected_inputs: dict[str, str],
        candidate_historical_digest: str,
        gold_historical_digest: str, expected_pairs_count: int,
        n_passed: int, manifest_digest: Optional[str] = None,
        require_inputs: Iterable[str] = ()) -> dict:
    """Validate the limited PR-2 evidence envelope without upgrading it.

    This verifies claims that can be reconstructed from preserved bytes.  It
    deliberately requires ``native_provenance is False`` and returns that
    classification unchanged; it cannot manufacture identity fields absent
    when the historical mutation rows were written.
    """
    if not isinstance(report, dict) \
            or report.get("schema") != MUTATION_VALIDATION_SCHEMA:
        raise TestQualityRefused(
            f"REFUSED: legacy attestation is not a "
            f"{MUTATION_VALIDATION_SCHEMA} report.")
    inputs = report.get("inputs")
    if not isinstance(inputs, dict):
        raise TestQualityRefused(
            "REFUSED: legacy attestation has no exact input-byte index.")
    for key in set(require_inputs) | set(expected_inputs):
        record = inputs.get(key)
        if not isinstance(record, dict) or not _is_sha256(record.get("sha256")):
            raise TestQualityRefused(
                f"REFUSED: legacy attestation has no full SHA-256 for input "
                f"{key!r}.")
    for key, wanted in expected_inputs.items():
        if inputs[key]["sha256"] != wanted:
            raise TestQualityRefused(
                f"REFUSED: legacy attestation binds different {key} bytes: "
                f"{inputs[key]['sha256']}, expected {wanted}.")

    evidence = report.get("evidence")
    if not isinstance(evidence, dict) \
            or evidence.get("schema") != LEGACY_CONSISTENCY_SCHEMA \
            or evidence.get("validation_class") != "legacy_consistency" \
            or evidence.get("native_provenance") is not False:
        raise TestQualityRefused(
            f"REFUSED: report evidence is not explicitly limited "
            f"{LEGACY_CONSISTENCY_SCHEMA} evidence.")
    if not isinstance(evidence.get("historical_manifest_digest_present"), bool):
        raise TestQualityRefused(
            "REFUSED: legacy evidence omits whether historical rows carried "
            "the manifest digest.")
    if manifest_digest is not None \
            and evidence.get("manifest_digest") != manifest_digest:
        raise TestQualityRefused(
            "REFUSED: legacy evidence names a different scored manifest.")
    if evidence.get("candidate_digest") != candidate_historical_digest \
            or evidence.get("gold_digest") != gold_historical_digest:
        raise TestQualityRefused(
            "REFUSED: legacy evidence's historical solution digests differ "
            "from the preserved candidate/gold generated-test bytes.")
    if evidence.get("n_passed") != n_passed \
            or evidence.get("n_expected_pairs") != expected_pairs_count:
        raise TestQualityRefused(
            "REFUSED: legacy evidence's passed-item or exact-pair count "
            "differs from the preserved inputs.")
    for side in ("candidate", "gold"):
        facts = evidence.get(side)
        if not isinstance(facts, dict) \
                or facts.get("rows") != expected_pairs_count \
                or facts.get("pairs") != expected_pairs_count \
                or not isinstance(facts.get("rows_with_manifest_digest"), int) \
                or not isinstance(facts.get("absent_descriptor_fields"), list):
            raise TestQualityRefused(
                f"REFUSED: legacy evidence has incomplete {side} row/pair "
                "facts.")
    limitations = evidence.get("limitations")
    if not isinstance(limitations, list) or not limitations \
            or not all(isinstance(value, str) and value for value in limitations):
        raise TestQualityRefused(
            "REFUSED: legacy evidence does not retain its limitations.")
    return evidence


def validate_precomputed_gold_attestation(
        attestation: dict, *, inputs: dict, passed: dict, gold_files: dict,
        expected: set[tuple[str, str]], gold_rows: list[dict],
        manifest_digest: Optional[str], require_complete: bool,
        attestation_path: Optional[str] = None,
        timeout: int = 600) -> dict:
    """Return the exact native/legacy population binding after validation."""
    from .mutation_run import candidate_digest, pair_set_digest, sha256_file
    pairs = [(row.get("item_id"), row.get("mutant_id")) for row in gold_rows]
    pair_set = set(pairs)
    if len(pairs) != len(pair_set) or not pair_set <= expected \
            or (require_complete and pair_set != expected):
        raise TestQualityRefused(
            "REFUSED: attested precomputed gold must contain unique pairs "
            "from the current population and, unless --allow-incomplete was "
            "explicitly selected, the exact current pair set. Supersets need "
            "a separately validated filtered artifact.")
    candidate_generated = candidate_digest(passed)
    gold_generated = candidate_digest(gold_files)
    pair_digest = pair_set_digest(expected)
    actual_pair_digest = pair_set_digest(pair_set)

    if attestation.get("schema") == "r2t.mutation-shard/v1":
        from .mutation_run import (CAMPAIGN_IDENTITY_FIELDS_V2_ADDED,
                                   MUTATION_IDENTITY_SCHEMA,
                                   MUTATION_IDENTITY_SCHEMA_V3,
                                   MUTATION_IDENTITY_SCHEMA_V4,
                                   MUTATION_IDENTITY_SCHEMA_V5,
                                   _row_identity_problems,
                                   campaign_identity_digest,
                                   completed_pairs,
                                   identity_version,
                                   validate_publishable_generation,
                                   validate_standalone_output_directory,
                                   validate_worker_resource_evidence)
        if not attestation_path or os.path.islink(attestation_path) \
                or not os.path.isfile(attestation_path):
            raise TestQualityRefused(
                "REFUSED: native cached gold requires its saved complete "
                "shard sidecar path; an in-memory provenance object cannot "
                "prove which source rows it accompanied.")
        saved_attestation = _load_json_object(
            attestation_path, "native cached-gold shard attestation")
        if saved_attestation != attestation:
            raise TestQualityRefused(
                "REFUSED: in-memory native attestation differs from its "
                "saved shard sidecar.")
        source_name = attestation.get("out")
        if not isinstance(source_name, str) or not source_name \
                or source_name != os.path.basename(source_name):
            raise TestQualityRefused(
                "REFUSED: native shard attestation has no safe source-row "
                "basename.")
        source_rows_path = os.path.join(
            os.path.dirname(os.path.abspath(attestation_path)), source_name)
        if os.path.abspath(attestation_path) \
                != os.path.abspath(source_rows_path + ".provenance.json") \
                or os.path.islink(source_rows_path) \
                or not os.path.isfile(source_rows_path) \
                or sha256_file(source_rows_path) \
                != inputs["gold_results_sha256"]:
            raise TestQualityRefused(
                "REFUSED: native cached-gold sidecar is not beside the exact "
                "row bytes being supplied.")
        identity = attestation.get("campaign_identity")
        if not isinstance(identity, dict) \
                or identity.get("schema") not in {
                    MUTATION_IDENTITY_SCHEMA, MUTATION_IDENTITY_SCHEMA_V3,
                    MUTATION_IDENTITY_SCHEMA_V5}:
            raise TestQualityRefused(
                "REFUSED: native gold shard has no current campaign identity.")
        try:
            validate_publishable_generation(
                identity, reference_roles={"full-gold"},
                where="this precomputed native gold shard")
            campaign_digest = campaign_identity_digest(identity)
        except Exception as e:                              # noqa: BLE001
            raise TestQualityRefused(str(e)) from e
        expected_identity = {
            "asset_index_sha256": inputs["asset_index_sha256"],
            "asset_project": inputs["asset_project"],
            "mutation_validation_sha256": inputs[
                "mutation_validation_sha256"],
            "mutation_validation_class": inputs[
                "mutation_validation_class"],
            "manifest_sha256": inputs["manifest_sha256"],
            "manifest_digest": manifest_digest,
            "map_sha256": inputs["map_sha256"],
            "release_sha256": inputs["release_sha256"],
            "applier_sha256": inputs["applier_sha256"],
            "substrate_baseline_sha256": inputs[
                "substrate_baseline_sha256"],
            "worker_resources_sha256": inputs[
                "worker_resources_sha256"],
            "harness_version": inputs["harness_version"],
            "container_image_digest": inputs["container_image_digest"],
            "workspace_seed_digest": inputs["workspace_seed_digest"],
            "database_dump_digest": inputs["database_dump_digest"],
            "engine": inputs["engine"],
            "engine_version": inputs["engine_version"],
            "parser": inputs["parser"],
            "side": "gold",
            "timeout_seconds": timeout,
            "sample": None,
            "sample_seed": None,
            "expected_pairs": len(pair_set),
            "expected_pairs_sha256": actual_pair_digest,
            # The generation half binds too: cached gold executed against a
            # candidate produced by one attempt may not be reused under
            # another, which is the cross-attempt rule at the one place a
            # PRESERVED artifact re-enters a live campaign.
            **({key: inputs.get(key)
                for key in sorted(CAMPAIGN_IDENTITY_FIELDS_V2_ADDED)}
               if identity_version(identity) != "v5" else {}),
        }
        if identity.get("kind") == "test-quality":
            if identity_version(identity) != "v3":
                raise TestQualityRefused(
                    "REFUSED: unbound v2 test-quality cached gold is "
                    "ineligible. Its mutable shard sidecar cannot authenticate "
                    "an LPT policy, and no immutable exact source-root-plan "
                    "authority admits this artifact; supply policy-bound v3 "
                    "gold or a standalone mutation-run shard.")
            expected_identity.update({
                "kind": "test-quality",
                "candidate_run_sha256": inputs["candidate_run_sha256"],
                "candidate_generated_tests_sha256": candidate_generated,
                "gold_baseline_sha256": inputs["gold_baseline_sha256"],
                "gold_generated_tests_sha256": gold_generated,
                "solution_generated_tests_sha256": gold_generated,
            })
        elif identity.get("kind") == "mutation-run":
            # A standalone gold sweep treats the reference run as the
            # candidate it executes.  It therefore binds those bytes through
            # the generic candidate fields and leaves the test-quality-only
            # cached-gold fields empty.  Requiring the TQ spelling here made
            # `mutation-run --side gold` impossible to reuse despite being
            # the public producer of native gold evidence.
            expected_identity.update({
                "kind": "mutation-run",
                "candidate_run_sha256": inputs["gold_baseline_sha256"],
                "candidate_generated_tests_sha256": gold_generated,
                "gold_baseline_sha256": None,
                "gold_generated_tests_sha256": None,
                "gold_results_sha256": None,
                "gold_results_attestation_sha256": None,
                "gold_provenance_class": None,
                "gold_attestation_manifest_digest": None,
                "gold_attestation_pairs_sha256": None,
                "gold_attestation_engine": None,
                "gold_attestation_engine_version": None,
                "solution_generated_tests_sha256": gold_generated,
                "shard": 0,
                "of": 1,
            })
            try:
                validate_standalone_output_directory(
                    [source_rows_path], identity)
                validate_worker_resource_evidence(attestation, identity)
            except Exception as e:                          # noqa: BLE001
                raise TestQualityRefused(str(e)) from e
        else:
            raise TestQualityRefused(
                f"REFUSED: native cached-gold shard has unsupported "
                f"campaign kind {identity.get('kind')!r}.")
        changed = sorted(key for key, wanted in expected_identity.items()
                         if identity.get(key) != wanted)
        if changed or attestation.get("status") != "complete" \
                or attestation.get("rows") != len(gold_rows) \
                or attestation.get("rows_sha256") \
                != inputs["gold_results_sha256"] \
                or attestation.get("expected_pairs") != len(pair_set) \
                or attestation.get("expected_pairs_sha256") \
                != actual_pair_digest \
                or attestation.get("mutation_campaign_digest") \
                != campaign_digest:
            raise TestQualityRefused(
                f"REFUSED: native gold shard does not bind current field(s) "
                f"{changed or ['status/rows/campaign']}.")
        try:
            completed_pairs(
                source_rows_path, identity, expected_pairs=pair_set,
                require_complete=True,
                expected_shard_policy=(
                    identity.get("shard_policy")
                    if identity.get("schema") in {
                        MUTATION_IDENTITY_SCHEMA_V3,
                        MUTATION_IDENTITY_SCHEMA_V4}
                    else None))
        except Exception as e:                              # noqa: BLE001
            raise TestQualityRefused(str(e)) from e
        for number, row in enumerate(gold_rows, 1):
            bad = _row_identity_problems(row, identity, campaign_digest)
            if bad:
                raise TestQualityRefused(
                    f"REFUSED: native gold row {number} has mismatched "
                    f"campaign stamp field(s) {bad}.")
        return {
            "validation_class": "native",
            "manifest_digest": manifest_digest,
            "pairs_sha256": actual_pair_digest,
            "engine": inputs["engine"],
            "engine_version": inputs["engine_version"],
        }

    if attestation.get("schema") == TEST_QUALITY_SUMMARY_SCHEMA:
        raise TestQualityRefused(
            "REFUSED: a test-quality summary is a report, not native gold "
            "row provenance. Supply a complete r2t.mutation-shard/v1 "
            "attestation whose row hash and per-row campaign stamps can be "
            "revalidated.")

    if not attestation_path:
        raise TestQualityRefused(
            "REFUSED: legacy_consistency must be supplied as a saved report "
            "path so PR-2 can re-hash and re-derive every named input.")
    from ..data import mutation_attestation as A
    try:
        _facts, validated_report, _paths = A.load_validated_saved_report(
            attestation_path,
            expected_validation_class="legacy_consistency",
            require_release_ready=True)
    except (A.MutationAssetRefused, OSError, ValueError) as e:
        raise TestQualityRefused(str(e)) from e
    if validated_report != attestation:
        raise TestQualityRefused(
            "REFUSED: in-memory legacy attestation differs from the saved "
            "report PR-2 revalidated.")
    expected_report_inputs = {
        "release": inputs["release_sha256"],
        "candidate_run": inputs["candidate_run_sha256"],
        "gold_baseline": inputs["gold_baseline_sha256"],
        "gold_results": inputs["gold_results_sha256"],
    }
    if pair_set != expected:
        raise TestQualityRefused(
            "REFUSED: legacy_consistency attests an exact historical pair "
            "set; it cannot support --allow-incomplete. Supply native shard "
            "provenance for an explicitly short sensitivity analysis.")
    validate_legacy_consistency_report(
        attestation, expected_inputs=expected_report_inputs,
        candidate_historical_digest=A.solution_digest(passed),
        gold_historical_digest=A.solution_digest(gold_files),
        expected_pairs_count=len(expected), n_passed=len(passed),
        manifest_digest=manifest_digest,
        require_inputs={*expected_report_inputs, "candidate_results",
                        "raw_manifest", "map", "asset_index", "boundary",
                        "coverage_run", "engine_source"})
    return {
        "validation_class": "legacy_consistency",
        "manifest_digest": manifest_digest,
        "pairs_sha256": pair_digest,
        "engine": inputs["engine"],
        "engine_version": inputs["engine_version"],
    }


def _resolved_evidence_path(value: str, base_file: str) -> str:
    return (os.path.abspath(value) if os.path.isabs(value)
            else os.path.abspath(os.path.join(os.path.dirname(base_file), value)))


LEGACY_SOURCE_SUMMARY_FIELDS = {
    "candidate_results", "completeness_checked", "engine",
    "engine_version", "excluded", "gold_baseline",
    "gold_kills_ignored_ineligible_baseline", "gold_results",
    "gold_rows_missing", "gold_rows_precomputed", "jaccard_macro", "jobs",
    "manifest_digest", "map", "mutants_in_population",
    "mutants_non_production_excluded", "n_passed", "n_scorable",
    "non_vacuous_passes", "pairs_executed_candidate", "pairs_executed_gold",
    "pairs_expected", "parser", "per_item", "recall_macro", "release",
    "require_complete", "row_engines", "run", "slices", "verdicts",
    "workers", "workers_used",
}

#: The gold-degradation qualifier, enrolled as KNOWN but not REQUIRED.
#:
#: **Recorded deviation from plan R4 item 4, disclosed rather than settled by
#: merging.** The item says to "enroll `gold_infrastructure_outcomes` in
#: `LEGACY_SOURCE_SUMMARY_FIELDS` … so legacy-derived summaries carry the
#: qualifier too".  `LEGACY_SOURCE_SUMMARY_FIELDS` is an EXACT-MATCH set on the
#: PRESERVED historical sidecar — `_build_legacy_wrapper` refuses on `missing`
#: as well as on `unknown` — so adding the field to it does not make the
#: qualifier travel; it refuses every sidecar written before the field existed,
#: which is all of them.  Verified from bytes on this host: the preserved Cell
#: 2, Cell 3 and Cell 4 sidecars each match the 33-field set exactly and none
#: carries `gold_infrastructure_outcomes`, so the literal reading closes §4
#: steps J2 and J3 rather than arming them, and the only way to reopen them
#: would be to retrofit fields into preserved evidence — plan §8's explicit
#: non-goal.
#:
#: **OWNER COUNTERSIGNED 2026-08-05**, choosing among three enumerated options
#: (countersign as landed / enforce the literal text and accept that plan §4
#: steps J2 and J3 close until every preserved sidecar is rewritten / required
#: set plus a pinned SHA-256 exemption for the three preserved sidecars). The
#: landed form is countersigned exactly as recorded here and in disposition row
#: C13; D1 carries the plan-text annotation, as it does for the C12 resume
#: deviation this follows.
#:
#: What the review actually asked for (finding 22, third bullet: "so an
#: infra-reduced gold set is distinguishable from a fully executed one") is
#: satisfied here instead: the qualifier is enrolled as a known OPTIONAL field
#: whose value, when a source sidecar carries one, must RECONCILE with the
#: value re-derived from the PR-2-validated rows — so it is checked, not merely
#: tolerated — and the wrapper `_build_legacy_wrapper` emits carries the count,
#: the per-item disclosure ruling 2.6 requires, and the degradation class
#: forward to every surface that reads it.
LEGACY_SOURCE_OPTIONAL_SUMMARY_FIELDS = {
    "gold_infrastructure_outcomes", "gold_infrastructure_pairs",
    "gold_infrastructure_class", "allow_degraded_gold",
}

#: The one preserved sidecar admitted to the relaxed field-set path,
#: identified by content digest (`EVAL100_STD_WRAPPER_COMPLETION_SPEC.md` §3,
#: owner ruling 2026-08-18).  The published CoreShop eval100-std table was
#: scored from a sidecar written before `jaccard_macro` and `row_engines`
#: existed, so the exact-match check above refuses it (blocker LB1).  The
#: ruling does not waive the two claims: `reconcile_source_claims` re-derives
#: both from the preserved mutation rows and requires the re-derived macro to
#: agree with the published byte-pinned table.  Identity is the digest, not
#: the path, and the pin admits no family — any other sidecar whose field set
#: differs still refuses by name.
EVAL100_STD_SIDECAR_SHA256 = (
    "e7799f81ba45630569679fb225ccc06c5376151efca512e59214c4b8e199225a")

#: The gold-kill rule the pinned sidecar was scored under, as the wrapper
#: discloses it (spec §9, owner ruling 2026-08-18): on 2026-08-01 a gold
#: kill was `outcome == "failed"` only.  See `gold_kill_basis`.
COLLECTION_GOLD_KILL_RULE = "collection_2026-08-01_failed_only"


#: How a wrapper names the bytes it is bound to (review finding 25's rule).
#:
#: `mutation_attestation._saved_report_paths` already resolves a saved report's
#: evidence through a declared `path_base`, and R4 item 9 makes that the rule
#: for every new committed sidecar class: "no new committed sidecar class may
#: bind absolute paths".  The base here is the WRAPPER's own directory rather
#: than the repository root, because a legacy wrapper's evidence lives outside
#: the repository — a base of `repository_root` would name /data2 paths through
#: a `..` chain that means nothing on another machine, which is the defect the
#: rule exists to prevent, spelled differently.
WRAPPER_PATH_BASE_KIND = "wrapper_directory"


def _wrapper_base(wrapper_path: str, base: Optional[dict] = None) -> str:
    """The directory a wrapper's relative evidence references resolve against."""
    directory = os.path.dirname(os.path.abspath(wrapper_path))
    if base is None:
        return directory
    _exact_wrapper_base_keys(base)
    return os.path.abspath(os.path.join(directory, base["relative_to_wrapper"]))


def _exact_wrapper_base_keys(base) -> None:
    if not isinstance(base, dict) or set(base) != {"kind",
                                                   "relative_to_wrapper"}:
        raise TestQualityRefused(
            f"REFUSED: legacy wrapper path_base is not a "
            f"{{kind, relative_to_wrapper}} object: {base!r}.")
    if base["kind"] != WRAPPER_PATH_BASE_KIND \
            or not isinstance(base["relative_to_wrapper"], str) \
            or not base["relative_to_wrapper"] \
            or os.path.isabs(base["relative_to_wrapper"]):
        raise TestQualityRefused(
            f"REFUSED: legacy wrapper path_base must be a RELATIVE "
            f"{WRAPPER_PATH_BASE_KIND} reference: {base!r}. A committed "
            f"sidecar that binds absolute paths is bound to one machine.")


def _wrapper_reference(target: str, base_dir: str) -> str:
    """A wrapper's spelling of one evidence path: relative to its base."""
    return os.path.relpath(os.path.abspath(target), base_dir)


def _resolve_wrapper_reference(value, base_dir: str, label: str) -> str:
    if not isinstance(value, str) or not value or os.path.isabs(value):
        raise TestQualityRefused(
            f"REFUSED: legacy wrapper's {label} is not a relative reference: "
            f"{value!r}. Absolute evidence paths bind a committed sidecar to "
            f"the machine that wrote it.")
    return os.path.abspath(os.path.join(base_dir, value))


def reconcile_optional_qualifier(summary: dict,
                                 derived_pairs: list) -> None:
    """The compensating control for the optional-qualifier enrolment.

    `LEGACY_SOURCE_OPTIONAL_SUMMARY_FIELDS` admits the gold-degradation
    qualifier onto a preserved sidecar without requiring it.  Admitting a field
    without checking it would be tolerance, and tolerance is what the enrolment
    note above promises this is NOT: where a source sidecar carries a count, it
    is a claim about the same rows the wrapper re-derives from, and the two may
    not disagree.

    A named function rather than four lines inside `_build_legacy_wrapper`
    because that builder needs a whole PR-2 evidence tree to reach, and a
    control nothing can drive is a control nobody can check.
    """
    if "gold_infrastructure_outcomes" not in summary:
        return
    # ABSENCE is the key not being there.  A key present with a `null` value is
    # a sidecar that recorded the field and recorded nothing in it, which is a
    # claim about these rows and is not the same fact as never having measured
    # them -- so it is refused rather than read as absence.  (Extracting these
    # lines from `_build_legacy_wrapper` briefly lost that distinction; the
    # reviewer caught it, and the check name promises it.)
    claimed = summary["gold_infrastructure_outcomes"]
    if isinstance(claimed, bool) or not isinstance(claimed, int):
        raise TestQualityRefused(
            f"REFUSED: preserved legacy summary carries "
            f"gold_infrastructure_outcomes {claimed!r}, which is not a count. "
            f"A field recorded with nothing in it is a claim about these rows, "
            f"not the absence of one.")
    if claimed != len(derived_pairs):
        raise TestQualityRefused(
            f"REFUSED: preserved legacy summary's "
            f"gold_infrastructure_outcomes claims {claimed}, but the "
            f"PR-2-validated gold rows carry {len(derived_pairs)}.")


def reconcile_pinned_jaccard_cell(jaccard_macro: float) -> None:
    """Spec §5's required agreement: the re-derived macro vs the publication.

    The pinned eval100-std sidecar cannot state `jaccard_macro`, so its
    vouching moves to independent re-derivation plus the published rendering
    the byte pin protects (`results.LEGACY_FIXTURE`).  The comparison renders
    the derived macro as the table renders it (`.3f`), because three decimals
    is exactly the claim the publication made; a stronger equality would
    assert a precision the published table never stated.  On disagreement the
    builder refuses, so `rebind_legacy_test_quality` never reaches its write
    and no wrapper exists.
    """
    from .results import LEGACY_FIXTURE
    cell = None
    with open(LEGACY_FIXTURE, encoding="utf-8") as fh:
        for line in fh:
            parts = [part.strip()
                     for part in line.strip().strip("|").split("|")]
            if parts[0] == "mutation jaccard similarity":
                cell = parts[-1]
    rendered = f"{jaccard_macro:.3f}"
    if rendered != cell:
        raise TestQualityRefused(
            f"REFUSED: the jaccard macro re-derived from the preserved "
            f"mutation rows renders as {rendered}, but the published "
            f"byte-pinned table's mutation jaccard similarity cell is "
            f"{cell!r}. A wrapper the publication disagrees with may not "
            f"exist.")


def gold_kill_basis(gold_rows: list, gold_baseline: dict,
                    items: Iterable[str],
                    sidecar_sha256: str) -> tuple[dict, int, int, list]:
    """The gold kills a preserved sidecar's claims are re-derived against.

    Every sidecar reconciles against today's `gold_kill_sets`.  The one
    SHA-256-pinned eval100-std sidecar (spec §3) was scored on 2026-08-01,
    when a gold kill was `outcome == "failed"` only; commit `3882666`
    (2026-08-04) rewrote `gold_kill_sets` to classify via `classify_outcome`,
    under which a gold-side `timeout` on a passed-baseline item is a KILL.
    Exactly one preserved pair changes classification — item
    `coreshop/features/domain/cli/install_demo_data_command.feature:7`,
    mutant `722254dfee2f404f`, where the gold and candidate rows both
    recorded `timeout` — and with it three claims the sidecar states
    (`excluded`, `per_item`, `recall_macro`), so reconciling the 2026-08-01
    arithmetic against the 2026-08-04 rule refuses evidence that was correct
    when it was written (the J3 scratch rehearsal's step-2 refusal,
    2026-08-18).

    Owner ruling 2026-08-18 (spec §9): the pinned sidecar reconciles under
    the rule in force at its collection, and every pair the two rules
    classify differently is computed from the preserved rows — never
    transcribed — and disclosed in the wrapper's `legacy_rebinding` block.
    The candidate side is untouched: its kills went through
    `classify_outcome` at collection time already.  The infrastructure count
    stays today's: the 2026-08-01 rule had no such bucket, the sidecar never
    stated one, and the count feeds only the wrapper's current-shape
    disclosure fields.

    Returns `(gold_killed, ignored, infrastructure, flipped_pairs)`;
    `flipped_pairs` is `[]` off the pinned path.
    """
    killed, ignored, infrastructure = gold_kill_sets(
        gold_rows, gold_baseline, items)
    if sidecar_sha256 != EVAL100_STD_SIDECAR_SHA256:
        return killed, ignored, infrastructure, []
    wanted = set(items)
    collection_killed: dict = {}
    collection_ignored = 0
    for row in gold_rows:
        if row["item_id"] not in wanted or row["outcome"] != "failed":
            continue
        if gold_baseline.get(row["item_id"]) != "passed":
            collection_ignored += 1
            continue
        collection_killed.setdefault(row["item_id"], set()).add(
            row["mutant_id"])
    flipped = sorted(
        (item_id, mutant_id)
        for item_id in set(killed) | set(collection_killed)
        for mutant_id in (killed.get(item_id, set())
                          ^ collection_killed.get(item_id, set())))
    return collection_killed, collection_ignored, infrastructure, flipped


def reconcile_source_claims(summary: dict, source_claims: dict,
                            sidecar_sha256: str) -> bool:
    """The exact-match field set and the source-claims reconcile, pin-aware.

    Every preserved sidecar must state exactly `LEGACY_SOURCE_SUMMARY_FIELDS`
    (the optional set aside) and every stated claim must equal the value
    re-derived from PR-2-validated rows.  Where the field-set check would
    refuse, the relaxed path is taken iff the sidecar's bytes hash to
    `EVAL100_STD_SIDECAR_SHA256` (spec §3); the pin fixes the bytes, so it
    entails exactly the two absent fields and the eight-key per-item shape —
    no second field-set check is needed.  On that path `jaccard_macro` and
    `row_engines` leave the reconcile (the sidecar states neither), the
    derived-only per-item `jaccard` key alone is set aside, and the
    re-derived macro must agree with the published byte-pinned table
    (`reconcile_pinned_jaccard_cell`).  On that path the caller's
    `source_claims` are derived under the collection-time gold-kill rule
    (`gold_kill_basis`, spec §9), so the preserved 2026-08-01 arithmetic is
    reconciled against itself rather than against a rule that post-dates it.
    Returns whether the pinned path was taken.

    A named function rather than lines inside `_build_legacy_wrapper`, for
    `reconcile_optional_qualifier`'s reason: the builder needs a whole PR-2
    evidence tree to reach, and a control nothing can drive is a control
    nobody can check.
    """
    unknown = sorted(set(summary) - LEGACY_SOURCE_SUMMARY_FIELDS
                     - LEGACY_SOURCE_OPTIONAL_SUMMARY_FIELDS)
    missing = sorted(LEGACY_SOURCE_SUMMARY_FIELDS - set(summary))
    pinned = bool(missing or unknown) \
        and sidecar_sha256 == EVAL100_STD_SIDECAR_SHA256
    if (missing or unknown) and not pinned:
        raise TestQualityRefused(
            f"REFUSED: preserved legacy summary fields differ; "
            f"missing={missing}, unknown={unknown}.")
    claims = dict(source_claims)
    if pinned:
        del claims["jaccard_macro"], claims["row_engines"]
        claims["per_item"] = {
            item_id: {key: value for key, value in entry.items()
                      if key != "jaccard"}
            for item_id, entry in claims["per_item"].items()}
    changed = sorted(key for key, wanted in claims.items()
                     if summary.get(key) != wanted)
    if changed:
        raise TestQualityRefused(
            f"REFUSED: preserved legacy summary does not reconcile to "
            f"PR-2-validated rows in field(s) {changed}.")
    if pinned:
        reconcile_pinned_jaccard_cell(source_claims["jaccard_macro"])
    return pinned


def evidence_claim_admissible(claimed: str, wanted: str,
                              sidecar_sha256: str) -> bool:
    """One preserved evidence-path claim, pin-aware (spec §11).

    The claims loop never chose the bound bytes; it vouches the sidecar's
    recorded spelling for them.  A spelling that resolves on the executing
    host must be a regular file whose bytes equal the PR-2-attested file --
    anti-substitution, unchanged.  On the §3-pinned sidecar only, a spelling
    that resolves to NOTHING is an unresolvable historical spelling -- a
    fact about the author host, checkable nowhere -- so the claim is skipped
    and the bytes actually bound remain the attested on-host files (owner
    ruling 2026-08-19, spec §11).  An unpinned sidecar with a missing
    spelling refuses exactly as before.  `os.path.lexists` is the `run`
    claim's existing rule for the same distinction, so a symlink -- broken
    or not -- is never read as absent.

    A named function rather than lines inside `_build_legacy_wrapper`, for
    `reconcile_source_claims`'s reason: the builder needs a whole PR-2
    evidence tree to reach, and a control nothing can drive is a control
    nobody can check.
    """
    from .mutation_run import sha256_file
    if sidecar_sha256 == EVAL100_STD_SIDECAR_SHA256 \
            and claimed and not os.path.lexists(claimed):
        return True
    return bool(claimed) and not os.path.islink(claimed) \
        and os.path.isfile(claimed) \
        and sha256_file(claimed) == sha256_file(wanted)


def _build_legacy_wrapper(run_path: str, legacy_summary_path: str,
                          validation_report_path: str, *,
                          wrapper_path: str,
                          allow_degraded_gold: bool = False) -> dict:
    """Purely re-derive a current wrapper from fully validated legacy bytes."""
    from ..data import mutation_attestation as A
    from ..core.boundary import load_boundary
    from .mutation_run import sha256_file

    base_dir = _wrapper_base(wrapper_path)

    discovered = find_sidecar(run_path)
    # FILE identity, not spelling identity.  One preserved sidecar is reachable
    # both at its real `/data2` path and through an `R2T_DATA_ROOT`
    # `projects/<project>` symlink, and the J3 ceremony's own two prescribed
    # steps reach it one way each: the wrapper is built from `/data2`
    # arguments, while the armed pin derives its run path from the data root.
    # `os.path.abspath` normalises `..` but keeps the symlink, so the file
    # compared unequal to itself.  `os.path.realpath` is exactly what the
    # candidate-run comparison twenty lines below already uses.
    if discovered is None \
            or os.path.realpath(discovered) != os.path.realpath(
                legacy_summary_path):
        raise TestQualityRefused(
            f"REFUSED: {legacy_summary_path} is not the unique preserved "
            f"sidecar discovered for {run_path}.")
    summary = _load_json_object(legacy_summary_path,
                                "preserved legacy test-quality sidecar")
    if "binding" in summary:
        raise TestQualityRefused(
            "REFUSED: source sidecar already carries a binding; validate it "
            "directly instead of relabelling it as legacy.")
    try:
        facts, report, paths = A.load_validated_saved_report(
            validation_report_path,
            expected_validation_class="legacy_consistency",
            require_release_ready=True)
    except (A.MutationAssetRefused, OSError, ValueError) as e:
        raise TestQualityRefused(str(e)) from e
    if os.path.realpath(paths["candidate_run"]) \
            != os.path.realpath(run_path):
        raise TestQualityRefused(
            "REFUSED: PR-2 legacy report attests a different candidate run.")

    index = _load_json_object(paths["asset_index"], "mutation asset index")
    entry = index["projects"][facts["project"]]
    raw_manifest = _load_json_object(paths["raw_manifest"],
                                     "raw mutant manifest")
    boundary = load_boundary(paths["boundary"])
    role = entry["scored_population"]["role"]
    if role == "boundary_scored":
        manifest = A.derive_boundary_scored_manifest(
            raw_manifest, boundary, paths["boundary"],
            A.sha256_file(paths["boundary"]))
    elif role == "raw_equals_scored":
        manifest = A.derive_raw_equals_scored_manifest(
            raw_manifest, boundary, paths["boundary"],
            A.sha256_file(paths["boundary"]))
    else:                                                   # PR-2 made unreachable
        raise TestQualityRefused(
            f"REFUSED: unsupported scored population role {role!r}.")
    mapping = _load_json_object(paths["map"], "legacy mutant map")

    run_rows = load_jsonl(paths["candidate_run"])
    passed = passed_solutions(run_rows)
    gold_baseline_rows = load_jsonl(paths["gold_baseline"])
    gold_files, gold_outcomes = gold_side(gold_baseline_rows, passed)
    by_mutant = mapping.get("by_mutant")
    if not isinstance(by_mutant, dict) or not isinstance(
            manifest.get("mutants"), list):
        raise TestQualityRefused(
            "REFUSED: preserved manifest/map cannot reconstruct the legacy "
            "pair population.")
    mutants, restricted, covering = population(manifest, by_mutant, passed)
    expected = expected_pairs(restricted)
    release_ids = {row.get("item_id") for row in load_jsonl(paths["release"])}
    if None in release_ids or not set(passed) <= release_ids:
        raise TestQualityRefused(
            "REFUSED: preserved release does not contain every passed item "
            "named by the legacy candidate run.")

    candidate_rows = load_jsonl(paths["candidate_results"])
    gold_rows = load_jsonl(paths["gold_results"])
    for label, rows in (("candidate", candidate_rows), ("gold", gold_rows)):
        pairs = [(row.get("item_id"), row.get("mutant_id")) for row in rows]
        if len(pairs) != len(set(pairs)) or set(pairs) != expected:
            raise TestQualityRefused(
                f"REFUSED: preserved {label} rows are not the exact scored "
                "pair set reconstructed from PR-2 evidence.")

    # Hashed once: the basis selection here, the §3 pin admission in the
    # reconcile below, the §11 claim-spelling admissions further down and
    # the `legacy_rebinding` chain at the end all name the same bytes.
    source_sidecar_sha256 = sha256_file(legacy_summary_path)
    gold_killed, ignored, _gold_infrastructure, flipped_pairs = \
        gold_kill_basis(gold_rows, gold_outcomes, passed,
                        source_sidecar_sha256)
    # A legacy sidecar predates harness 25, so it is re-derived as it was
    # scored, with every mutant in it.
    derived = score(passed, covering, gold_killed, gold_outcomes,
                    candidate_rows, expected=expected, unscored=frozenset())
    engines = engine_report(manifest, candidate_rows, gold_rows)

    source_claims = {
        **derived,
        "mutants_in_population": len(mutants),
        "pairs_expected": len(expected),
        "pairs_executed_candidate": len(candidate_rows),
        "pairs_executed_gold": len(gold_rows),
        "gold_kills_ignored_ineligible_baseline": ignored,
        "gold_rows_precomputed": False,
        "gold_rows_missing": 0,
        "require_complete": True,
        # The historical summary named the pre-boundary manifest even though
        # its execution filtered the 258 retained mutants in memory.  Keep
        # that historical claim only while checking the old sidecar; the new
        # wrapper below names the canonical scored population.
        "manifest_digest": report["raw_manifest"]["digest"],
        "mutants_non_production_excluded": entry[
            "scored_population"]["n_non_production_excluded"],
        "parser": manifest["parser"],
        **engines,
    }
    reconcile_source_claims(summary, source_claims, source_sidecar_sha256)
    reconcile_optional_qualifier(
        summary, gold_infrastructure_pairs(gold_rows, gold_outcomes, passed))
    source_paths = {
        "candidate_results": paths["candidate_results"],
        "gold_results": paths["gold_results"],
        "gold_baseline": paths["gold_baseline"],
        "map": paths["map"],
    }
    bad_paths = []
    for key, wanted in source_paths.items():
        value = summary.get(key)
        claimed = (_resolved_evidence_path(value, legacy_summary_path)
                   if isinstance(value, str) else "")
        # Historical sidecars may name the same immutable bytes in the old
        # checkout (and the quarantined Cell-3 sidecar names its original run
        # location).  Path spelling is not identity: require both names to be
        # ordinary files and compare their full bytes instead -- except that
        # on the §3-pinned sidecar a spelling resolving to nothing on this
        # host is an unresolvable historical spelling and the claim is
        # skipped (`evidence_claim_admissible`, spec §11).
        if not evidence_claim_admissible(claimed, wanted,
                                         source_sidecar_sha256):
            bad_paths.append(key)
    if bad_paths:
        raise TestQualityRefused(
            f"REFUSED: preserved legacy summary names different evidence "
            f"path(s) {bad_paths}.")

    # The superseded Cell-3 run was moved into quarantine after its sidecar
    # was written, so the old ``run`` spelling no longer exists.  The wrapper
    # is bound to the PR-2-attested quarantined bytes above; retain only the
    # checkable part of the stale display path here.
    source_run = summary.get("run")
    if not isinstance(source_run, str) or not source_run \
            or os.path.basename(source_run) != os.path.basename(run_path):
        raise TestQualityRefused(
            "REFUSED: preserved legacy summary names a different run.")
    resolved_source_run = _resolved_evidence_path(
        source_run, legacy_summary_path)
    if os.path.lexists(resolved_source_run) \
            and (os.path.islink(resolved_source_run)
                 or not os.path.isfile(resolved_source_run)
                 or sha256_file(resolved_source_run)
                 != sha256_file(paths["candidate_run"])):
        raise TestQualityRefused(
            "REFUSED: preserved legacy summary's run path now resolves to "
            "different bytes.")

    # Python-docx summaries intentionally name the 32-item evaluation slice,
    # whereas the PR-2 report binds the immutable 239-item release from which
    # it was selected.  Prove the slice is exactly the candidate-run item set
    # and that every selected release row equals its attested parent row.
    source_release_value = summary.get("release")
    source_release = (_resolved_evidence_path(
        source_release_value, legacy_summary_path)
        if isinstance(source_release_value, str) else "")
    if source_sidecar_sha256 == EVAL100_STD_SIDECAR_SHA256 \
            and source_release and not os.path.lexists(source_release):
        # Unresolvable historical spelling on the pinned sidecar (spec §11):
        # the PR-2-attested release supplies the source-release bytes, and
        # the slice-equality check below runs unchanged over them.
        source_release = paths["release"]
    if not source_release or os.path.islink(source_release) \
            or not os.path.isfile(source_release):
        raise TestQualityRefused(
            "REFUSED: preserved legacy summary's release is not a regular "
            "file.")
    source_release_rows = load_jsonl(source_release)
    parent_release_rows = load_jsonl(paths["release"])

    def _unique_items(rows: list[dict], label: str) -> dict[str, dict]:
        result = {}
        for row in rows:
            item_id = row.get("item_id")
            if not isinstance(item_id, str) or not item_id \
                    or item_id in result:
                raise TestQualityRefused(
                    f"REFUSED: {label} has missing or duplicate item ids.")
            result[item_id] = row
        return result

    source_release_by_item = _unique_items(
        source_release_rows, "preserved legacy release")
    parent_release_by_item = _unique_items(
        parent_release_rows, "PR-2-attested parent release")
    run_items = {row.get("item_id") for row in run_rows}
    if None in run_items or set(source_release_by_item) != run_items \
            or any(parent_release_by_item.get(item_id) != row
                   for item_id, row in source_release_by_item.items()):
        raise TestQualityRefused(
            "REFUSED: preserved legacy release is not the exact candidate "
            "run slice of the PR-2-attested parent release.")
    if not isinstance(summary["workers"], int) \
            or summary["workers"] < 1 \
            or not isinstance(summary["workers_used"], list) \
            or not all(isinstance(value, str) and value
                       for value in summary["workers_used"]) \
            or not isinstance(summary["jobs"], list) \
            or not isinstance(summary["slices"], list):
        raise TestQualityRefused(
            "REFUSED: preserved legacy summary has malformed operational "
            "metadata.")

    infrastructure_pairs = gold_infrastructure_pairs(
        gold_rows, gold_outcomes, passed)
    if len(infrastructure_pairs) != _gold_infrastructure:
        raise TestQualityRefused(                           # pragma: no cover
            "REFUSED: the legacy wrapper's per-item infrastructure disclosure "
            "is not the count it discloses.")
    if not infrastructure_pairs and allow_degraded_gold:
        raise TestQualityRefused(
            "REFUSED: --allow-degraded-gold was passed for gold that carries "
            "no infrastructure outcome. Consent to a degradation that does "
            "not exist would make the recorded tolerance unreadable — it "
            "would no longer say which numbers rest on one.")
    population_id = registered_population_id(
        facts["project"], manifest.get("digest"),
        engines.get("engine"), engines.get("engine_version"))
    if population_id is None:                              # pragma: no cover
        raise TestQualityRefused(
            "REFUSED: validated Slice 1 legacy assets do not resolve to a "
            "registered population. The current wrapper cannot bind their "
            "reference-equivalent verdicts without rewriting source bytes.")
    wrapper = {
        "schema": TEST_QUALITY_SUMMARY_SCHEMA,
        **derived,
        "mutants_in_population": len(mutants),
        "pairs_expected": len(expected),
        "pairs_executed_candidate": len(candidate_rows),
        "pairs_executed_gold": len(gold_rows),
        "gold_kills_ignored_ineligible_baseline": ignored,
        "gold_infrastructure_outcomes": _gold_infrastructure,
        # Ruling 2.6's per-item disclosure, and the class that says WHY the
        # count may travel with a published number: legacy rows carry no
        # `attempt` stamp, so they can never claim degraded NATIVE gold.
        "gold_infrastructure_pairs": infrastructure_pairs,
        "gold_infrastructure_class": ("recorded_tolerance"
                                      if infrastructure_pairs else "none"),
        "allow_degraded_gold": bool(allow_degraded_gold),
        "gold_rows_precomputed": True,
        "gold_rows_missing": 0,
        "require_complete": True,
        "path_base": {"kind": WRAPPER_PATH_BASE_KIND,
                      "relative_to_wrapper": "."},
        "candidate_results": _wrapper_reference(
            paths["candidate_results"], base_dir),
        "gold_results": _wrapper_reference(paths["gold_results"], base_dir),
        "manifest_digest": manifest["digest"],
        "population_id": population_id,
        "parser": manifest["parser"],
        **engines,
        "binding": run_binding(run_path, run_rows),
        "gold_provenance_class": "legacy_consistency",
        "legacy_limitations": list(report["evidence"]["limitations"]),
        "legacy_rebinding": {
            "schema": LEGACY_REBINDING_SCHEMA,
            "source_sidecar": _wrapper_reference(
                legacy_summary_path, base_dir),
            "source_sidecar_sha256": source_sidecar_sha256,
            "validation_report": _wrapper_reference(
                validation_report_path, base_dir),
            "validation_report_sha256": sha256_file(validation_report_path),
            "validation_schema": MUTATION_VALIDATION_SCHEMA,
            "validation_class": report["evidence"]["validation_class"],
            "native_provenance": report["evidence"]["native_provenance"],
            # Spec §9's disclosure: which gold-kill rule the reconcile basis
            # was derived under, and every pair today's rule classifies
            # differently -- computed by `gold_kill_basis`, never transcribed.
            **({"gold_kill_rule": COLLECTION_GOLD_KILL_RULE,
                "gold_kill_rule_flipped_pairs": [
                    {"item_id": item_id, "mutant_id": mutant_id}
                    for item_id, mutant_id in flipped_pairs]}
               if source_sidecar_sha256 == EVAL100_STD_SIDECAR_SHA256
               else {}),
        },
    }
    return wrapper


def rebind_legacy_test_quality(run_path: str, legacy_summary_path: str,
                               validation_report_path: str,
                               out_path: str, *,
                               allow_degraded_gold: bool = False) -> dict:
    """Write a separate current binding around preserved legacy evidence."""
    from .mutation_run import MutationAborted, atomic_write_json
    if os.path.abspath(out_path) in {
            os.path.abspath(path) for path in sidecar_paths(run_path)}:
        raise TestQualityRefused(
            "REFUSED: a legacy wrapper may not occupy either automatically "
            "discovered sidecar name. Preserve the old sidecar and pass the "
            "wrapper explicitly to reporting.")
    wrapper = _build_legacy_wrapper(
        run_path, legacy_summary_path, validation_report_path,
        wrapper_path=out_path, allow_degraded_gold=allow_degraded_gold)
    try:
        atomic_write_json(out_path, wrapper, refuse_existing=True)
    except MutationAborted as e:
        raise TestQualityRefused(str(e)) from e
    return wrapper


def gold_side(gold_rows: Iterable[dict], items: Iterable[str]) -> tuple[dict, dict]:
    """`({item: files}, {item: outcome})` from gold's UNMUTATED run.

    One file serves both purposes deliberately.  The outcomes are the
    eligibility input (§3.10: a gold kill counts only where gold's own
    baseline passed), and the `produced_files` on the very same rows are the
    solution gold's side is executed from — so the run that establishes gold
    was healthy on an item and the bytes that get mutated against it cannot
    come from two different campaigns.
    """
    wanted = set(items)
    files: dict = {}
    outcomes: dict = {}
    for row in gold_rows:
        iid = row["item_id"]
        if iid not in wanted:
            continue
        if iid in outcomes:
            raise TestQualityRefused(
                f"REFUSED: two gold baseline rows for item {iid}.")
        outcomes[iid] = row.get("outcome")
        files[iid] = row.get("produced_files") or []
    return files, outcomes


def population(manifest: dict, by_mutant: dict,
               items: Iterable[str]) -> tuple[list, dict, dict]:
    """The FULL set of mutants covering the passed items — no sampling.

    Returns `(mutants, by_mutant_restricted, covering_by_item)`:

    * `mutants` in manifest order, so a slice is reproducible and two runs
      over the same inputs plan the same shards;
    * `by_mutant_restricted` maps each of them to the passed items it covers,
      and to nothing else — the covering list in the map is over the whole
      corpus, and executing it would run hundreds of items nobody is scoring;
    * `covering_by_item` is the inverse, which is `mutants_covering` in the
      report and the only honest denominator for "this item was measured
      against N mutants".
    """
    wanted = set(items)
    mutants: list[dict] = []
    restricted: dict = {}
    covering: dict = {i: [] for i in sorted(wanted)}
    for mutant in manifest.get("mutants") or []:
        hits = sorted(set(by_mutant.get(mutant["id"], ())) & wanted)
        if not hits:
            continue
        mutants.append(mutant)
        restricted[mutant["id"]] = hits
        for iid in hits:
            covering[iid].append(mutant["id"])
    return mutants, restricted, covering


def expected_pairs(by_mutant_restricted: dict) -> set:
    """Every `(item, mutant)` execution this measurement is defined over."""
    return {(iid, mid) for mid, items in by_mutant_restricted.items()
            for iid in items}


def missing_pairs(expected: set, rows: Iterable[dict]) -> list:
    got = {(r["item_id"], r["mutant_id"]) for r in rows}
    return sorted(expected - got)


def restrict_to_pairs(mutants: list, restricted: dict,
                      pairs: Iterable[tuple[str, str]]) -> tuple[list, dict]:
    """The planned population narrowed to *pairs*, manifest order kept.

    A mutant left with no pair leaves the plan: `shard_mutants` refuses a
    member with nothing to execute.  Map order within a mutant is kept too,
    so a slice's row sequence is the unrestricted sequence minus its drops.
    """
    wanted = set(pairs)
    kept = {}
    for mutant_id, items in restricted.items():
        keep = [item_id for item_id in items if (item_id, mutant_id) in wanted]
        if keep:
            kept[mutant_id] = keep
    return [mutant for mutant in mutants if mutant["id"] in kept], kept


def gold_killed_pairs(gold_rows: Iterable[dict], gold_baseline: dict,
                      items: Iterable[str]) -> set[tuple[str, str]]:
    """Exactly the pairs `recall` scores: `gold_kill_sets`, flattened."""
    killed, _ignored, _infrastructure = gold_kill_sets(
        gold_rows, gold_baseline, items)
    return {(item_id, mutant_id) for item_id, mutants in killed.items()
            for mutant_id in mutants}


def scored_gold_rows(gold_rows: list, record: dict,
                     gold_plan: Optional[frozenset]) -> list:
    """The gold rows `gold_kill_sets` scores, given the summary or provenance.

    Kapua's `G_i` is a literal `failed` (KAPUA_CENSUS330_MUTATION_AMENDMENT.md
    sections 6 and 7.2): its evidence reader turns a sealed full-gold
    `timeout` into a non-kill.  Gold observed again on the evidence's kills
    reads its own timeout the same way, so a cell's `G_i` means one thing on
    every host.  The written rows keep the observed outcome.
    """
    if gold_plan is None or "kapua_reference_evidence" not in record:
        return gold_rows
    return [dict(row, outcome="passed") if row.get("outcome") == "timeout"
            else row for row in gold_rows]


def build_gold_pair_plan(rows: Iterable[dict], *, manifest_digest: str,
                         source: str) -> dict:
    """A gold pair plan: the pairs a preserved gold observation killed.

    A pair enters on a literal `failed` outcome only; a timeout or an
    infrastructure outcome does not.  Two rows for one pair must agree, or
    the preserved observation does not say which pairs it killed.
    """
    if not isinstance(source, str) or not source.strip():
        raise TestQualityRefused("REFUSED: a gold pair plan names its source.")
    outcomes: dict = {}
    for number, row in enumerate(rows, 1):
        pair = (row.get("item_id"), row.get("mutant_id"))
        if not all(isinstance(value, str) and value for value in pair) \
                or not isinstance(row.get("outcome"), str):
            raise TestQualityRefused(
                f"REFUSED: gold row {number} has no item, mutant or outcome.")
        if outcomes.setdefault(pair, row["outcome"]) != row["outcome"]:
            raise TestQualityRefused(
                f"REFUSED: gold rows disagree about pair {pair}.")
    pairs = sorted(pair for pair, outcome in outcomes.items()
                   if outcome == "failed")
    if not pairs:
        raise TestQualityRefused("REFUSED: the gold rows kill no pair.")
    return {"schema": GOLD_PAIR_PLAN_SCHEMA,
            "manifest_digest": manifest_digest, "source": source,
            "pairs": [list(pair) for pair in pairs]}


def load_gold_pair_plan(path: str, *, manifest_digest: Optional[str]) \
        -> tuple[frozenset, dict]:
    """Read a gold pair plan; return its pairs and the binding to record."""
    from .mutation_run import sha256_file
    doc = _load_json_object(path, "gold pair plan")
    pairs = doc.get("pairs")
    if set(doc) != {"schema", "manifest_digest", "source", "pairs"} \
            or doc.get("schema") != GOLD_PAIR_PLAN_SCHEMA \
            or not isinstance(doc.get("source"), str) \
            or not doc["source"].strip() \
            or not isinstance(pairs, list) or not pairs \
            or not all(isinstance(pair, list) and len(pair) == 2
                       and all(isinstance(value, str) and value
                               for value in pair) for pair in pairs):
        raise TestQualityRefused(
            f"REFUSED: {path} is not a {GOLD_PAIR_PLAN_SCHEMA} document with "
            "a named source and a nonempty [item, mutant] pair list.")
    if doc["manifest_digest"] != manifest_digest:
        raise TestQualityRefused(
            f"REFUSED: gold pair plan {path} names manifest digest "
            f"{doc['manifest_digest']!r}, not this campaign's "
            f"{manifest_digest!r}.")
    unique = frozenset(tuple(pair) for pair in pairs)
    if len(unique) != len(pairs):
        raise TestQualityRefused(
            f"REFUSED: gold pair plan {path} repeats a pair.")
    return unique, {"path": os.path.abspath(path),
                    "sha256": sha256_file(path)}


def candidate_pair_scope(*, scope: str, passed: dict, mutants: list,
                         restricted: dict, gold_rows: Optional[list],
                         gold_baseline: dict,
                         gold_plan: Optional[frozenset]) -> dict:
    """Settle which pairs each side executes, before either side runs.

    Returns the estimand (`expected`: gold's pairs, the completeness and
    `pairs_expected` basis), the candidate's pairs, the planning population
    (`mutants`, `restricted`) and the root-plan record (`None` for the
    unchanged `all`, so an `all` plan keeps its historical bytes).

    * `all`: both sides execute every mapped pair, as before.
    * `gold-killed` over PRECOMPUTED gold: gold's rows exist, so the candidate
      executes exactly the pairs `gold_kill_sets` would score.
    * `gold-killed` with a gold pair plan: gold is observed in this campaign,
      so its kills are not known yet; both sides execute the plan's pairs.
      Scoring reads the in-campaign gold, so a plan pair gold does not kill
      here leaves the denominator, as it would unrestricted.
    """
    all_pairs = expected_pairs(restricted)
    if scope not in CANDIDATE_PAIR_SCOPES:
        raise TestQualityRefused(
            f"REFUSED: unknown candidate pair scope {scope!r}; expected one "
            f"of {list(CANDIDATE_PAIR_SCOPES)}.")
    if gold_plan is not None and scope != CANDIDATE_PAIRS_GOLD_KILLED:
        raise TestQualityRefused(
            "REFUSED: a gold pair plan restricts gold to earlier kills, so "
            "it requires --candidate-pairs gold-killed; a full candidate "
            "slice would read outcomes on pairs gold never ran.")
    if gold_plan is not None and gold_rows is not None:
        raise TestQualityRefused(
            "REFUSED: a gold pair plan restricts gold observed in this "
            "campaign; precomputed gold is already a complete observation.")
    if scope == CANDIDATE_PAIRS_ALL:
        return {"expected": all_pairs, "candidate": all_pairs,
                "mutants": mutants, "restricted": restricted, "record": None}
    if gold_rows is None and gold_plan is None:
        raise TestQualityRefused(
            "REFUSED: --candidate-pairs gold-killed needs gold's kills "
            "before the candidate is planned: supply precomputed gold "
            "(--gold-results, --kapua-reference-evidence or "
            "--prestashop-reference-evidence) or a --gold-pair-plan.")
    if gold_plan is not None:
        outside = sorted(pair for pair in gold_plan
                         if pair[0] in passed and pair not in all_pairs)
        if outside:
            raise TestQualityRefused(
                f"REFUSED: the gold pair plan names {len(outside)} pair(s) "
                f"of passed items outside the mapped population, e.g. "
                f"{outside[:3]}.")
        estimand = all_pairs & set(gold_plan)
        candidate = estimand
    else:
        estimand = all_pairs
        candidate = gold_killed_pairs(gold_rows, gold_baseline, passed) \
            & all_pairs
    if not candidate:
        raise TestQualityRefused(
            "REFUSED: gold kills no pair of this candidate's passed items, "
            "so a gold-killed candidate slice has nothing to execute.")
    # One planning population serves every side that executes: precomputed
    # gold executes no side of its own, and with a gold pair plan gold and
    # candidate execute the same pairs.
    narrowed_mutants, narrowed = restrict_to_pairs(
        mutants, restricted, candidate)
    return {"expected": estimand, "candidate": candidate,
            "mutants": narrowed_mutants, "restricted": narrowed,
            "record": gold_killed_scope_record(
                candidate, gold_pair_plan=gold_plan is not None)}


def gold_killed_scope_record(candidate: Iterable[tuple[str, str]], *,
                             gold_pair_plan: bool) -> dict:
    """The root plan's `candidate_pair_scope` for a gold-killed slice.

    GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md section 6: the scope, the candidate
    pair count and digest, and whether a gold pair plan applies.  Resume
    compares whole plans, so a campaign cannot resume under the other scope.
    """
    from .mutation_run import pair_set_digest
    candidate = set(candidate)
    return {"scope": CANDIDATE_PAIRS_GOLD_KILLED,
            "candidate_pairs": len(candidate),
            "candidate_pairs_sha256": pair_set_digest(candidate),
            "gold_pair_plan": gold_pair_plan}


def gold_killed_summary_fields(scope: dict,
                               gold_pair_plan_binding: Optional[dict]) -> dict:
    """The scope disclosure a gold-killed summary carries; `{}` for `all`.

    Absent under `all`, so every full-scope summary keeps its bytes.
    """
    record = scope["record"]
    if record is None:
        return {}
    return {"candidate_pair_scope": record["scope"],
            "candidate_pairs_expected": record["candidate_pairs"],
            "candidate_pairs_sha256": record["candidate_pairs_sha256"],
            "gold_pair_plan": (dict(gold_pair_plan_binding)
                               if gold_pair_plan_binding is not None
                               else None),
            "withheld_measures": list(GOLD_KILLED_WITHHELD)}


def withhold_gold_killed_companions(summary: dict) -> None:
    """Null every measure `GOLD_KILLED_WITHHELD` names, in place.

    `score` computes them over whatever rows it is given; over a gold-killed
    candidate slice those counts are about the slice, not the candidate, so
    printing them would be printing a number that was not measured.
    """
    for entry in summary["per_item"].values():
        entry["candidate_only_kills"] = None
        entry["jaccard"] = None
    summary["jaccard_macro"] = None
    summary["excluded"] = {key: None for key in summary["excluded"]}


def engine_report(manifest: dict, *row_sets: Iterable[dict]) -> dict:
    """Which mutation engine this summary is about — or a refusal.

    A recall is only meaningful against ONE operator set.  `r2t-mutate`'s
    eight PHP operators and `r2t-mutate-py`'s eight Python ones are neither
    the same operators nor comparably hard to kill, so a macro average taken
    over rows from both is a number about no population at all: it would move
    when the mix moved, and nothing in the summary would say the mix had
    moved.  Every published recall is therefore labelled with its engine, and
    two engines in one summary is a refusal rather than a footnote.

    Two refusals, and both are about a mix nobody chose:

    * more than one NAMED engine among the rows — two campaigns concatenated,
      or a resumed out file pointed at the other stack's manifest;
    * a named engine that is not the MANIFEST's — the manifest defines the
      population these rows were supposed to execute, so rows from another
      engine are rows about other mutants, whatever their ids happen to be.

    Rows with no `engine` key are neither of those.  They are older than the
    column (the archived `test_quality_std` campaign is all of them) and there
    is exactly one honest thing to say about them: they are attributed to the
    manifest that this run was given, and the count of how many is published
    beside the number so a reader can see how much rests on that attribution.
    """
    counts: dict = {}
    for rows in row_sets:
        for row in rows:
            label = row.get("engine") or UNLABELLED_ENGINE
            counts[label] = counts.get(label, 0) + 1
    named = sorted(k for k in counts if k != UNLABELLED_ENGINE)
    if len(named) > 1:
        raise TestQualityRefused(
            f"REFUSED: these rows were produced by {len(named)} different "
            f"mutation engines ({', '.join(f'{k}={counts[k]}' for k in named)}"
            f"). Recall is defined over ONE operator set; a macro average "
            f"across two is a number about neither population. Score them "
            f"separately, one summary per engine.")
    declared = manifest.get("engine")
    if named and declared and named[0] != declared:
        raise TestQualityRefused(
            f"REFUSED: the rows say engine={named[0]!r} but the manifest that "
            f"defines this population says {declared!r}. Either the rows were "
            f"executed against another manifest or this is the wrong manifest "
            f"for them; both make every (item, mutant) join a coincidence.")
    return {"engine": declared, "engine_version": manifest.get("engine_version"),
            "row_engines": counts}


# ------------------------------------------------------------- the campaign
def identity_inputs_for_test_quality(*, run_rows: list,
                                     gold_baseline_rows: list,
                                     manifest: dict, by_mutant: dict,
                                     gold_results: Optional[list] = None,
                                     gold_results_attestation: Optional[dict] = None,
                                     exact: Optional[dict] = None) -> dict:
    """Content inputs shared by every side/shard in one TQ campaign.

    The CLI supplies exact file-byte digests in ``exact``.  Canonical in-memory
    fallbacks keep the pure unit API deterministic without inventing mutable
    paths; they are not used by the publishable command.
    """
    from .mutation_run import candidate_digest, content_digest
    passed = passed_solutions(run_rows)
    gold_files, _gold_outcomes = gold_side(gold_baseline_rows, passed)
    engine = manifest.get("engine") or "fixture-engine"
    version = manifest.get("engine_version") or "fixture-version"
    parser = manifest.get("parser") or "fixture-parser"
    out = {
        "asset_index_sha256": content_digest({"fixture_asset_index": 1}),
        "asset_project": "fixture",
        "mutation_validation_sha256": content_digest(
            {"fixture_mutation_validation": 1}),
        "mutation_validation_class": "native",
        "manifest_sha256": content_digest(manifest),
        "manifest_digest": manifest.get("digest"),
        "map_sha256": content_digest({"by_mutant": by_mutant}),
        "release_sha256": content_digest(sorted(
            {r.get("item_id") for r in run_rows if r.get("item_id")})),
        "candidate_run_sha256": content_digest(run_rows),
        "candidate_generated_tests_sha256": candidate_digest(passed),
        "gold_baseline_sha256": content_digest(gold_baseline_rows),
        "gold_generated_tests_sha256": candidate_digest(gold_files),
        "gold_results_sha256": (content_digest(gold_results)
                                if gold_results is not None else None),
        "gold_results_attestation_sha256": (
            content_digest(gold_results_attestation)
            if gold_results_attestation is not None else None),
        "gold_provenance_class": None,
        "gold_attestation_manifest_digest": None,
        "gold_attestation_pairs_sha256": None,
        "gold_attestation_engine": None,
        "gold_attestation_engine_version": None,
        "applier_sha256": content_digest(
            {"engine": engine, "engine_version": version}),
        "substrate_baseline_sha256": content_digest(
            {"fixture_substrate": "test-quality"}),
        "worker_resources_sha256": content_digest([]),
        "harness_version": "fixture-harness-v1",
        "container_image_digest": "sha256:" + "7" * 64,
        "workspace_seed_digest": "6" * 64,
        "database_dump_digest": "5" * 64,
        "engine": engine,
        "engine_version": version,
        "parser": parser,
        # THE FIXTURE GENERATION HALF, AND WHY IT IS NOT `native_v2`.
        # A fixture candidate was produced by no agent, under no runtime, over
        # no network.  This default used to claim `native_v2` with a
        # plausible attempt id, so a real caller that omitted one generation
        # key inherited a FABRICATED attempt identity and could publish under
        # it -- the unlabelled-admission failure ruling 2.2 closed, wearing a
        # default's clothes. The class now says what it is, carries no
        # attempt/runtime/network (the validator refuses a fixture that
        # claims any of them), and is refused by every publication surface.
        **FIXTURE_GENERATION_INPUTS,
    }
    out.update(exact or {})
    return out


def _job_pairs(mutants: Iterable[dict], by_mutant: dict,
               files_by_item: dict) -> set[tuple[str, str]]:
    from .mutation_run import expected_pairs_for_slice
    return expected_pairs_for_slice(mutants, by_mutant, files_by_item)


def _identity_for_job(inputs: dict, *, side: str, worker: int, of: int,
                      timeout: int, mutants: list, by_mutant: dict,
                      files_by_item: dict,
                      shard_policy: Optional[str] = None,
                      execution_policy: Optional[str] = None,
                      batch_plan_sha256: Optional[str] = None,
                      max_batch_members: Optional[int] = None,
                      max_batch_instances: Optional[int] = None,
                      stack_reset_sha256: Optional[str] = None,
                      batch_journal_schema: Optional[str] = None,
                      compute_cap_sha256: Optional[str] = None,
                      reuse_projection_sha256: Optional[str] = None,
                      estimand_pairs_sha256: Optional[str] = None,
                      preflight_cache_policy: Optional[str] = None,
                      observation_id: Optional[str] = None) -> dict:
    from .mutation_run import (CAMPAIGN_IDENTITY_FIELDS_V2_ADDED,
                               EXECUTION_POLICY_SCALAR_V1,
                               build_campaign_identity, candidate_digest)
    # The v2 generation half, passed through by NAME rather than restated:
    # every one of these keys is both an identity field and the constructor's
    # parameter, so a field added there cannot be silently dropped here.
    generation = {key: inputs.get(key)
                  for key in sorted(CAMPAIGN_IDENTITY_FIELDS_V2_ADDED)}
    return build_campaign_identity(
        **generation,
        asset_index_sha256=inputs["asset_index_sha256"],
        asset_project=inputs["asset_project"],
        mutation_validation_sha256=inputs["mutation_validation_sha256"],
        mutation_validation_class=inputs["mutation_validation_class"],
        manifest_sha256=inputs["manifest_sha256"],
        manifest_digest=inputs.get("manifest_digest"),
        map_sha256=inputs["map_sha256"],
        release_sha256=inputs["release_sha256"],
        candidate_run_sha256=inputs["candidate_run_sha256"],
        candidate_generated_tests_sha256=inputs.get(
            "candidate_generated_tests_sha256"),
        gold_baseline_sha256=inputs.get("gold_baseline_sha256"),
        gold_generated_tests_sha256=inputs.get(
            "gold_generated_tests_sha256"),
        gold_results_sha256=inputs.get("gold_results_sha256"),
        gold_results_attestation_sha256=inputs.get(
            "gold_results_attestation_sha256"),
        gold_provenance_class=inputs.get("gold_provenance_class"),
        gold_attestation_manifest_digest=inputs.get(
            "gold_attestation_manifest_digest"),
        gold_attestation_pairs_sha256=inputs.get(
            "gold_attestation_pairs_sha256"),
        gold_attestation_engine=inputs.get("gold_attestation_engine"),
        gold_attestation_engine_version=inputs.get(
            "gold_attestation_engine_version"),
        solution_generated_tests_sha256=candidate_digest(files_by_item),
        substrate_baseline_sha256=inputs["substrate_baseline_sha256"],
        worker_resources_sha256=inputs["worker_resources_sha256"],
        harness_version=inputs["harness_version"],
        container_image_digest=inputs["container_image_digest"],
        workspace_seed_digest=inputs["workspace_seed_digest"],
        database_dump_digest=inputs["database_dump_digest"],
        applier_sha256=inputs.get("applier_sha256"),
        expected_pairs=_job_pairs(mutants, by_mutant, files_by_item),
        engine=inputs["engine"], engine_version=inputs["engine_version"],
        parser=inputs["parser"], side=side, shard=worker, of=of,
        timeout=timeout, kind="test-quality", shard_policy=shard_policy,
        execution_policy=(execution_policy or EXECUTION_POLICY_SCALAR_V1
                          if compute_cap_sha256 is not None
                          or reuse_projection_sha256 is not None
                          else execution_policy),
        batch_plan_sha256=batch_plan_sha256,
        max_batch_members=max_batch_members,
        max_batch_instances=max_batch_instances,
        stack_reset_sha256=stack_reset_sha256,
        batch_journal_schema=batch_journal_schema,
        compute_cap_sha256=compute_cap_sha256,
        reuse_projection_sha256=reuse_projection_sha256,
        estimand_pairs_sha256=estimand_pairs_sha256,
        preflight_cache_policy=preflight_cache_policy,
        observation_id=observation_id,
        # Present only for a campaign whose assets declared a budgeted
        # basis; absent, the constructor emits no key for them.
        population_basis=inputs.get("population_basis"),
        budgeted_sample_sha256=inputs.get("budgeted_sample_sha256"),
        parent_map_sha256=inputs.get("parent_map_sha256"))


def _v4_execution_kwargs(identity: dict) -> dict:
    """Return the complete shared v4 union for exact reconstruction."""
    from .mutation_run import (CAMPAIGN_IDENTITY_FIELDS_V4_ADDED,
                               MUTATION_IDENTITY_SCHEMA_V4)
    if not isinstance(identity, dict) \
            or identity.get("schema") != MUTATION_IDENTITY_SCHEMA_V4:
        return {}
    return {key: identity.get(key)
            for key in sorted(CAMPAIGN_IDENTITY_FIELDS_V4_ADDED)}


def shard_mutants(mutants: list, by_mutant: dict, files_by_item: dict,
                  n_workers: int, *,
                  policy: str = DEFAULT_SHARD_POLICY) -> list[list]:
    """Partition mutants without changing the planned pair population.

    ``balanced-pairs-lpt/1`` assigns the widest remaining mutant to the
    currently lightest shard.  Width is the number of distinct scored items
    covering that mutant, not a duration observed from a candidate run.  The
    tie breaks (manifest-independent mutant id, then worker index) are fixed,
    and each worker executes its assigned members in manifest order.

    The historical strided policy remains explicit for identity-matching
    resume of a v1 campaign.  Both policies return every input mutant exactly
    once; a caller that supplies a mutant with no executable pair is refused
    rather than manufacturing an empty mutation job.
    """
    if (not isinstance(n_workers, int) or isinstance(n_workers, bool)
            or n_workers < 1):
        raise TestQualityRefused(
            f"REFUSED: n_workers={n_workers!r} must be a positive integer.")
    if policy not in SHARD_POLICIES:
        raise TestQualityRefused(
            f"REFUSED: unknown shard policy {policy!r}; expected one of "
            f"{list(SHARD_POLICIES)}.")

    ordered = list(mutants)
    positions: dict[str, int] = {}
    weights: dict[str, int] = {}
    for position, mutant in enumerate(ordered):
        mid = mutant.get("id") if isinstance(mutant, dict) else None
        if not isinstance(mid, str) or not mid:
            raise TestQualityRefused(
                f"REFUSED: mutant at position {position} has no string id.")
        if mid in positions:
            raise TestQualityRefused(
                f"REFUSED: mutant population repeats id {mid!r}.")
        positions[mid] = position
        covering = {
            iid for iid in (by_mutant.get(mid) or [])
            if iid in files_by_item
        }
        if not covering:
            raise TestQualityRefused(
                f"REFUSED: mutant {mid!r} has no executable (item, mutant) "
                "pair for this side; it cannot be assigned to a shard.")
        weights[mid] = len(covering)

    if policy == SHARD_POLICY_STRIDED_V1:
        return [ordered[worker::n_workers] for worker in range(n_workers)]

    memberships: list[set[str]] = [set() for _ in range(n_workers)]
    loads = [0] * n_workers
    # LPT: widest first.  Mutant id rather than input position breaks equal-
    # width ties so a semantically identical manifest ordering cannot make a
    # different schedule.  Local execution order is restored below.
    for mid in sorted(weights, key=lambda value: (-weights[value], value)):
        worker = min(range(n_workers), key=lambda value: (loads[value], value))
        memberships[worker].add(mid)
        loads[worker] += weights[mid]
    return [[mutant for mutant in ordered if mutant["id"] in member_ids]
            for member_ids in memberships]


def plan_jobs(mutants: list, files_by_side: dict, by_mutant_restricted: dict,
              n_workers: int, out_dir: str, *,
              sides: Iterable[str] = SIDES,
              provenance: Optional[dict] = None,
              identity_inputs: Optional[dict] = None,
              timeout: int = 600, resume: bool = False,
              shard_policy: str = DEFAULT_SHARD_POLICY,
              bind_shard_policy: bool = True,
              execution_policy: Optional[str] = None,
              batch_plan_sha256: Optional[str] = None,
              max_batch_members: Optional[int] = None,
              max_batch_instances: Optional[int] = None,
              stack_reset_sha256: Optional[str] = None,
              batch_journal_schema: Optional[str] = None,
              compute_cap_sha256: Optional[str] = None,
              reuse_projection_sha256: Optional[str] = None,
              estimand_pairs_sha256: Optional[str] = None,
              preflight_cache_policy: Optional[str] = None,
              observation_id: Optional[str] = None) -> list[dict]:
    """One job per (side, worker); a worker's jobs run one after another.

    **A worker's workspace is a mutex.**  A mutation job edits production code
    in place and puts it back, and the integrity guard is told about exactly
    one file at a time (`mutation_run.apply_mutant`).  Two jobs on one worker
    at once would mutate the same tree concurrently: the second `apply` would
    see the first's mutant as the original, the revert would restore the wrong
    bytes, and every later row on that worker would be scored against an
    undeclared mutation.  So the sides are SERIALISED within a worker and
    parallelised across workers — which is what the hand-run did with two
    workers, generalised to K.

    New campaigns use deterministic pair-count LPT rather than mutant-count
    striding: items-per-mutant is skewed (median 3, mean 18.1, max 100 over
    CoreShop), so equal mutant counts are not equal work.  The legacy strided
    policy remains selectable for byte-identical resume.  Scheduling changes
    only shard membership/order; each side still executes the exact same
    complete (item, mutant) set under the same timeout and retry rules.  New
    LPT jobs bind the policy into identity v3.  ``bind_shard_policy=False`` is
    reserved for byte-reconstructing the short-lived legacy LPT v2 shape that
    predates that binding; without an immutable exact-artifact authority that
    shape is not resumable or publishable.  Historical strided v1 plans are
    always unbound.
    """
    if (not isinstance(n_workers, int) or isinstance(n_workers, bool)
            or n_workers < 1):
        raise TestQualityRefused(
            f"REFUSED: n_workers={n_workers!r} must be a positive integer.")
    shared_inputs = dict(identity_inputs or {})
    if not shared_inputs:
        from .mutation_run import candidate_digest, content_digest
        candidate_files = (files_by_side.get("candidate")
                           or next(iter(files_by_side.values()), {}))
        gold_files = files_by_side.get("gold") or candidate_files
        shared_inputs = {
            "manifest_sha256": content_digest(mutants),
            "asset_index_sha256": content_digest(
                {"fixture_asset_index": 1}),
            "asset_project": "fixture",
            "mutation_validation_sha256": content_digest(
                {"fixture_mutation_validation": 1}),
            "mutation_validation_class": "native",
            "manifest_digest": content_digest(mutants),
            "map_sha256": content_digest(by_mutant_restricted),
            "release_sha256": content_digest(sorted(
                set(candidate_files) | set(gold_files))),
            "candidate_run_sha256": content_digest(candidate_files),
            "candidate_generated_tests_sha256": candidate_digest(
                candidate_files),
            "gold_baseline_sha256": content_digest(gold_files),
            "gold_generated_tests_sha256": candidate_digest(gold_files),
            "gold_results_sha256": None,
            "gold_results_attestation_sha256": None,
            "gold_provenance_class": None,
            "gold_attestation_manifest_digest": None,
            "gold_attestation_pairs_sha256": None,
            "gold_attestation_engine": None,
            "gold_attestation_engine_version": None,
            "applier_sha256": content_digest("fixture-applier"),
            "substrate_baseline_sha256": content_digest(
                {"fixture_substrate": "test-quality"}),
            "worker_resources_sha256": content_digest([]),
            "harness_version": "fixture-harness-v1",
            "container_image_digest": "sha256:" + "7" * 64,
            "workspace_seed_digest": "6" * 64,
            "database_dump_digest": "5" * 64,
            "engine": "fixture-engine",
            "engine_version": "fixture-version",
            "parser": "fixture-parser",
            **FIXTURE_GENERATION_INPUTS,
        }
    shard_dir = os.path.join(out_dir, SHARD_DIR)
    jobs: list[dict] = []
    for side in sides:
        if side not in files_by_side:
            raise TestQualityRefused(
                f"REFUSED: no solution files for side {side!r}.")
        slices = shard_mutants(
            mutants, by_mutant_restricted, files_by_side[side], n_workers,
            policy=shard_policy)
        for w, slice_ in enumerate(slices):
            if not slice_:
                # Fewer mutants than workers: an empty job would install the
                # applier, clean a workspace and write an empty out file that
                # the merge would then read as a complete shard.
                continue
            inputs = dict(shared_inputs)
            identity = _identity_for_job(
                inputs, side=side, worker=w, of=n_workers, timeout=timeout,
                mutants=slice_, by_mutant=by_mutant_restricted,
                files_by_item=files_by_side[side],
                shard_policy=(
                    shard_policy
                    if bind_shard_policy
                    and shard_policy == SHARD_POLICY_BALANCED_PAIRS_V1
                    else None),
                execution_policy=execution_policy,
                batch_plan_sha256=batch_plan_sha256,
                max_batch_members=max_batch_members,
                max_batch_instances=max_batch_instances,
                stack_reset_sha256=stack_reset_sha256,
                batch_journal_schema=batch_journal_schema,
                compute_cap_sha256=compute_cap_sha256,
                reuse_projection_sha256=reuse_projection_sha256,
                estimand_pairs_sha256=estimand_pairs_sha256,
                preflight_cache_policy=preflight_cache_policy,
                observation_id=observation_id)
            jobs.append({
                "side": side,
                "worker": w,
                "of": n_workers,
                "mutants": slice_,
                "files_by_item": files_by_side[side],
                "by_mutant": by_mutant_restricted,
                "out": os.path.join(shard_dir, f"{side}.w{w}.jsonl"),
                "provenance": {**(provenance or {}), "side": side,
                               "shard_policy": shard_policy,
                               "manifest_digest": identity.get(
                                   "manifest_digest"),
                               "mutant_shard": w, "mutant_of": n_workers},
                "identity": identity,
                "shard_policy": shard_policy,
                "resume": bool(resume),
            })
    return jobs


def _drain_in_processes(queues: dict, execute: Callable[[dict], dict],
                        cancel_event, results: dict, failures: list) -> None:
    """Drain each worker's queue in its own forked process.

    A slice spends most of its time in pure-Python substrate hashing and
    resource restores around every execution, so worker threads of one
    interpreter take turns on its lock and the containers idle; a PrestaShop
    pool of 24 ran at a fiftieth of its speed.  Forked children share nothing
    but the pipe that returns their infos and exceptions, and `cancel_event`,
    which must be a fork-context `multiprocessing.Event` so that a stop set
    by either side reaches every worker at its next safe point.
    """
    import multiprocessing
    import sys
    ctx = multiprocessing.get_context("fork")
    sys.stdout.flush()
    sys.stderr.flush()
    children = []
    for worker in sorted(queues):
        receive, send = ctx.Pipe(duplex=False)

        def child(worker=worker, send=send) -> None:
            done: list = []
            for job in queues[worker]:
                if cancel_event.is_set():
                    break
                try:
                    done.append((True, (job["side"], job["worker"]),
                                 execute(job)))
                except Exception as e:                      # noqa: BLE001
                    done.append((False, job["side"], e))
                    cancel_event.set()
                    break
            sys.stdout.flush()
            try:
                send.send(done)
            except Exception:                               # noqa: BLE001
                # An exception that cannot cross the pipe keeps its name.
                send.send([(ok, key, value if ok else RuntimeError(
                    f"{type(value).__name__}: {value}"))
                    for ok, key, value in done])

        process = ctx.Process(target=child,
                              name=f"r2t-test-quality-worker-{worker}")
        process.start()
        send.close()
        children.append((worker, process, receive))
    for worker, process, receive in children:
        try:
            done = receive.recv()
        except EOFError:
            cancel_event.set()
            done = None
        process.join()
        if done is None:
            failures.append((worker, "?", RuntimeError(
                f"worker process exited {process.exitcode} before reporting "
                "its slices")))
            continue
        for ok, key, value in done:
            if ok:
                results[key] = value
            else:
                failures.append((worker, key, value))


def execute_jobs(jobs: list, execute: Callable[[dict], dict], *,
                 cancel_event: Optional[threading.Event] = None,
                 processes: bool = False) -> list[dict]:
    """Run each worker's queue in its own thread; return every job's info.

    With `processes`, a pool of more than one worker drains each queue in its
    own forked process instead (`_drain_in_processes`); the caller then
    supplies a fork-context `multiprocessing.Event` as `cancel_event`.

    `execute(job) -> info` is injected rather than imported so that this
    module's selftest can exercise the planning, the merge and the scoring
    without a container — and so that the executor, which is the only part
    that needs docker, is the only part that cannot be tested here.

    A worker that raises does not abort the others: they are already mid-
    mutant, and killing them is how a mutant gets left applied
    (`run_slice`'s own signal handling exists for exactly that).  Every
    failure is collected and raised together at the end, so the campaign never
    proceeds to scoring on rows it knows are short — and the completeness
    check would catch it anyway, which is belt and braces on purpose.
    """
    from concurrent.futures import ThreadPoolExecutor

    queues: dict = {}
    for job in jobs:
        queues.setdefault(job["worker"], []).append(job)
    if not queues:
        return []

    cancel_event = cancel_event or threading.Event()
    results: dict = {}
    # The EXCEPTIONS, not their rendered text.  What the root record needs to
    # decide is whether every worker stopped because it was asked to, and
    # `type(e).__name__` in a joined string is a claim about that which
    # nothing downstream can check (review finding 9).
    failures: list[tuple[int, str, BaseException]] = []

    def _drain(worker: int) -> None:
        for job in queues[worker]:
            if cancel_event.is_set():
                return
            key = (job["side"], job["worker"])
            try:
                results[key] = execute(job)
            except Exception as e:                          # noqa: BLE001
                failures.append((worker, job["side"], e))
                cancel_event.set()
                return

    if processes and len(queues) > 1:
        _drain_in_processes(queues, execute, cancel_event, results, failures)
    else:
        with ThreadPoolExecutor(max_workers=len(queues)) as pool:
            list(pool.map(_drain, sorted(queues)))
    if failures:
        from .mutation_run import MutationCancelled
        rendered = [f"worker {worker} / {side}: {type(e).__name__}: {e}"
                    for worker, side, e in failures]
        # EVERY collected failure a cancellation, and the event set: that is
        # a campaign that stopped because it was told to, and it is
        # `interrupted` and resumable.  One real failure among them makes the
        # whole thing `failed` — a crash that also cancelled its siblings is
        # still a crash, and the fail-closed direction is the safe one.
        # `MutationCancelled` ALONE, and `KeyboardInterrupt` deliberately
        # absent: `_drain` catches `Exception`, which a KeyboardInterrupt is
        # not, so it can never reach this list — and listing it anyway would
        # say that a Ctrl-C inside a worker is classified as a cooperative
        # stop, which is the opposite of what would happen.
        cancelled = cancel_event.is_set() and all(
            isinstance(e, MutationCancelled)
            for _worker, _side, e in failures)
        raise (TestQualityCancelled if cancelled else TestQualityRefused)(
            "REFUSED: " + str(len(failures)) + " mutation slice(s) "
            + ("were cooperatively cancelled" if cancelled else "failed")
            + ", so the results are short and nothing may be scored from "
              "them:\n  " + "\n  ".join(rendered))
    if cancel_event.is_set():
        raise TestQualityCancelled(
            "REFUSED: mutation campaign was cooperatively cancelled; all "
            "active workers restored their current mutant and no score was "
            "produced.")
    return [results[k] for k in sorted(results)]


def merge_rows(jobs: Iterable[dict], out_path: Optional[str], *,
               expected: Iterable[tuple[str, str]], side: str) -> list[dict]:
    """Strictly merge the complete planned shards for one side.

    Shards are disjoint by mutant, so a repeated `(item, mutant)` means two
    shards ran the same pair — the accidental K=2 execution that produced 26
    outcome disagreements on byte-identical input (A.7).  `recall` refuses
    duplicates too; this refuses earlier, where the file that caused it can
    still be named.
    """
    from .mutation_run import (MutationAborted, atomic_write_bytes,
                               completed_pairs)
    planned = list(jobs)
    if not planned:
        raise TestQualityRefused(
            f"REFUSED: no planned {side} shard exists to merge.")
    policies = {job.get("shard_policy", SHARD_POLICY_STRIDED_V1)
                for job in planned}
    if len(policies) != 1 or not policies <= set(SHARD_POLICIES):
        raise TestQualityRefused(
            f"REFUSED: {side} merge jobs carry mixed or unknown shard "
            f"policies: {sorted(str(value) for value in policies)}.")
    shard_policy = next(iter(policies))
    # Authenticate scheduling before reading a shard or creating the merged
    # output.  A coordinated edit of an unbound v2 job and its mutable
    # sidecar can make every local LPT label agree while the rows remain
    # indistinguishable from historical striding.  Genuine LPT is identity
    # v3; only the explicit historical strided representation remains v1/v2.
    _admitted_policy_identity_binding(planned, shard_policy)
    expected_set = set(expected)
    rows: list[dict] = []
    seen: dict = {}
    cores = set()
    for job in planned:
        path = job["out"]
        identity = job.get("identity") or {}
        if job.get("side") != side or identity.get("side") != side:
            raise TestQualityRefused(
                f"REFUSED: planned {side} merge contains job/identity side "
                f"{job.get('side')!r}/{identity.get('side')!r}.")
        if identity.get("shard") != job.get("worker") \
                or identity.get("of") != job.get("of"):
            raise TestQualityRefused(
                f"REFUSED: {path} identity names shard "
                f"{identity.get('shard')} of {identity.get('of')}, not planned "
                f"worker {job.get('worker')} of {job.get('of')}.")
        core = {k: v for k, v in identity.items()
                if k not in ("shard", "expected_pairs",
                             "expected_pairs_sha256")}
        cores.add(json.dumps(core, sort_keys=True, separators=(",", ":")))
        try:
            completed_pairs(
                path, identity,
                expected_pairs=_job_pairs(job["mutants"], job["by_mutant"],
                                          job["files_by_item"]),
                require_complete=True,
                expected_shard_policy=shard_policy,
                allow_missing_shard_policy=(
                    shard_policy == SHARD_POLICY_STRIDED_V1))
        except MutationAborted as e:
            raise TestQualityRefused(str(e)) from e
        for row in load_jsonl(path):
            pair = (row["item_id"], row["mutant_id"])
            if pair in seen:
                where = (f"twice in {path}" if seen[pair] == path
                         else f"in both {seen[pair]} and {path}")
                raise TestQualityRefused(
                    f"REFUSED: {pair} appears {where}. The same pair was "
                    f"executed twice; which outcome wins must not depend on "
                    f"file order, and `recall` would count both.")
            seen[pair] = path
            rows.append(row)
    if len(cores) != 1:
        raise TestQualityRefused(
            f"REFUSED: {side} shards carry mixed campaign identities; only "
            "shard number and its exact pair-set digest may differ.")
    got = set(seen)
    if got != expected_set:
        missing = sorted(expected_set - got)
        unexpected = sorted(got - expected_set)
        raise TestQualityRefused(
            f"REFUSED: {side} merge is not the exact planned pair set: "
            f"{len(missing)} missing and {len(unexpected)} unexpected, e.g. "
            f"missing {missing[:3]}, unexpected {unexpected[:3]}.")
    if out_path is not None:
        payload = "".join(json.dumps(row, sort_keys=True) + "\n"
                          for row in rows).encode("utf-8")
        try:
            atomic_write_bytes(out_path, payload, refuse_existing=True)
        except MutationAborted as e:
            raise TestQualityRefused(str(e)) from e
    return rows


def _planned_policy_identity_binding(records: Iterable[dict],
                                     shard_policy: str) -> bool:
    """Whether every saved/planned job binds *shard_policy* in identity.

    v1/v2 mutation identities are the archived unbound representation.  They
    remain readable as one homogeneous campaign, but may never be mixed with
    policy-bound v3 shards.  A historical strided root is exclusively the
    unbound representation; allowing a v3 identity under that root would let
    an attacker relabel a newer plan as historical merely by changing the
    root schema and hash.
    """
    from .mutation_run import (MutationAborted, campaign_identity_digest,
                               identity_version)
    bindings: set[bool] = set()
    versions: set[str] = set()
    count = 0
    for record in records:
        count += 1
        identity = None
        if isinstance(record, dict):
            identity = (record.get("campaign_identity")
                        if "campaign_identity" in record
                        else record.get("identity"))
        try:
            digest = campaign_identity_digest(identity or {})
            version = identity_version(identity or {})
        except MutationAborted as e:
            raise TestQualityRefused(str(e)) from e
        if identity.get("kind") != "test-quality" \
                or identity.get("side") != record.get("side") \
                or identity.get("shard") != record.get("worker") \
                or identity.get("of") != record.get("of"):
            raise TestQualityRefused(
                "REFUSED: test-quality root job and mutation identity "
                "disagree about kind, side, worker, or worker count.")
        if "campaign_identity" in record \
                and record.get("mutation_campaign_digest") != digest:
            raise TestQualityRefused(
                "REFUSED: test-quality root job's mutation campaign digest "
                "does not hash its saved identity.")
        bound = version in {"v3", "v4"}
        if bound and identity.get("shard_policy") != shard_policy:
            raise TestQualityRefused(
                f"REFUSED: policy-bound shard identity names "
                f"{identity.get('shard_policy')!r}, not root campaign policy "
                f"{shard_policy!r}.")
        bindings.add(bound)
        versions.add(version)
    if not count:
        raise TestQualityRefused(
            "REFUSED: test-quality root plan has no mutation jobs.")
    if len(bindings) != 1:
        raise TestQualityRefused(
            "REFUSED: test-quality root plan mixes policy-bound v3/v4 and "
            "historical unbound v1/v2 shard identities.")
    if len(versions) != 1:
        raise TestQualityRefused(
            f"REFUSED: test-quality root plan mixes mutation campaign "
            f"identity versions {sorted(versions)}.")
    bound = next(iter(bindings))
    if shard_policy == SHARD_POLICY_STRIDED_V1 and bound:
        raise TestQualityRefused(
            "REFUSED: historical v1 striding cannot carry a newer "
            "policy-bound shard identity.")
    return bound


def _admitted_policy_identity_binding(records: Iterable[dict],
                                       shard_policy: str) -> bool:
    """Require the only policy/identity generations this harness can trust."""
    bound = _planned_policy_identity_binding(records, shard_policy)
    if shard_policy == SHARD_POLICY_BALANCED_PAIRS_V1 and not bound:
        raise TestQualityRefused(
            "REFUSED: an unbound v1/v2 LPT root and mutable shard sidecars "
            "cannot authenticate which scheduling policy produced unchanged "
            "rows. No immutable exact-artifact authority admits this campaign; "
            "preserve it as ambiguous evidence and rerun into a new policy-bound "
            "v3 campaign.")
    return bound


def _zero_pair_candidate_plan(*, authority, passed, inputs, worker_resources,
                              shard_policy, observation_id):
    """Certify an empty restriction of an authenticated full reference map."""
    from .mutation_run import (CAMPAIGN_IDENTITY_FIELDS_V2_ADDED,
                               content_digest, pair_set_digest,
                               validate_observation_id)
    authority = _require_single_observation_authority(authority)
    if single_observation_candidate_pairs(authority, passed):
        raise TestQualityRefused("REFUSED: zero-job candidate has mapped pairs")
    validate_observation_id(observation_id)
    if shard_policy != DEFAULT_SHARD_POLICY:
        raise TestQualityRefused("REFUSED: zero-job candidate needs the current shard policy")
    resources = list(worker_resources)
    scope_record = _single_observation_scope_record(authority, set())
    return {
        "schema": TEST_QUALITY_PLAN_SCHEMA,
        "jobs": [], "worker_resources": resources,
        "worker_resources_sha256": content_digest(resources),
        "expected_pairs": 0, "expected_pairs_sha256": pair_set_digest(set()),
        "require_complete": True, "gold_precomputed": True,
        "final_artifacts": [CANDIDATE_ROWS, GOLD_ROWS, SUMMARY],
        **({"candidate_pair_scope": scope_record}
           if scope_record is not None else {}),
        "shard_policy": shard_policy,
        "zero_pair_candidate": {
            "reference_controls_digest": authority.controls["digest"],
            "passed_items": sorted(passed),
            "candidate_run_sha256": inputs["candidate_run_sha256"],
            "candidate_generated_tests_sha256": inputs["candidate_generated_tests_sha256"],
            "observation_id": observation_id,
            **{key: inputs.get(key) for key in sorted(CAMPAIGN_IDENTITY_FIELDS_V2_ADDED)},
        },
    }


def build_test_quality_campaign_plan(
        jobs: Iterable[dict], *,
        expected: Iterable[tuple[str, str]] = (),
        require_complete: bool = True,
        gold_precomputed: bool = False,
        candidate_scope: Optional[dict] = None,
        worker_resources: Iterable[dict] = (),
        campaign_dir: Optional[str] = None,
        compute_cap: Optional[dict] = None,
        reuse_projection: Optional[dict] = None,
        sensitivity: Optional[str] = None) -> dict:
    """Canonical root identity for execution, merge, scoring and resume."""
    from .mutation_run import (campaign_identity_digest, content_digest,
                               pair_set_digest)
    jobs = list(jobs)
    policies = {job.get("shard_policy", SHARD_POLICY_STRIDED_V1)
                for job in jobs}
    if len(policies) != 1 or not policies <= set(SHARD_POLICIES):
        raise TestQualityRefused(
            f"REFUSED: test-quality jobs carry mixed or unknown shard "
            f"policies: {sorted(str(value) for value in policies)}.")
    shard_policy = next(iter(policies))
    planned = []
    seen = set()
    source_jobs = {}
    for job in jobs:
        identity = job.get("identity")
        digest = campaign_identity_digest(identity or {})
        key = (job.get("side"), job.get("worker"))
        if key in seen:
            raise TestQualityRefused(
                f"REFUSED: test-quality plan repeats job {key}.")
        seen.add(key)
        source_jobs[key] = job
        planned.append({
            "side": job.get("side"),
            "worker": job.get("worker"),
            "of": job.get("of"),
            "out": os.path.join(SHARD_DIR, os.path.basename(job["out"])),
            "mutation_campaign_digest": digest,
            "campaign_identity": identity,
        })
    planned.sort(key=lambda row: (row["side"], row["worker"]))
    _admitted_policy_identity_binding(planned, shard_policy)
    expected_set = set(expected)
    resources = sorted((dict(record) for record in worker_resources),
                       key=lambda record: record.get("index", -1))
    resources_sha256 = content_digest(resources)
    identity_resource_digests = {
        row["campaign_identity"].get("worker_resources_sha256")
        for row in planned
    }
    if identity_resource_digests != {resources_sha256}:
        raise TestQualityRefused(
            "REFUSED: root worker assignment differs from the worker-resource "
            "digest carried by its mutation jobs.")
    cap_sha256 = None
    estimand_pairs_sha256 = pair_set_digest(expected_set)
    observation_ids_by_side = None
    delta_pairs_sha256_by_side = None
    if reuse_projection is not None:
        raise TestQualityRefused(
            "REFUSED: exact reuse projection is reserved in plan v3 but no "
            "reviewed projection producer is implemented yet.")
    if compute_cap is not None:
        if campaign_dir is None:
            raise TestQualityRefused(
                "REFUSED: a compute-cap plan must bind its canonical campaign "
                "directory.")
        validate_compute_cap(compute_cap, workers=len(resources),
                             expected=expected_set,
                             campaign_dir=campaign_dir)
        if gold_precomputed:
            raise TestQualityRefused(
                "REFUSED: compute-cap/v1 requires native candidate and gold "
                "legs; precomputed gold cannot produce the authenticated "
                "partial-reference fallback.")
        cap_sha256 = content_digest(compute_cap)
        from .mutation_run import (EXECUTION_POLICY_SCALAR_V1,
                                   identity_version)
        observations = {side: set() for side in SIDES}
        delta_pairs = {side: set() for side in SIDES}
        for row in planned:
            identity = row["campaign_identity"]
            side = row.get("side")
            worker = row.get("worker")
            if side not in observations:
                raise TestQualityRefused(
                    f"REFUSED: cap-bound root plan has unknown side "
                    f"{side!r}.")
            source = source_jobs[(side, worker)]
            pair_set = _job_pairs(
                source.get("mutants") or [], source.get("by_mutant") or {},
                source.get("files_by_item") or {})
            if delta_pairs[side] & pair_set:
                raise TestQualityRefused(
                    f"REFUSED: cap-bound root plan repeats a {side} pair "
                    "across job partitions.")
            delta_pairs[side].update(pair_set)
            if identity_version(identity) != "v4" \
                    or identity.get("execution_policy") \
                    != EXECUTION_POLICY_SCALAR_V1 \
                    or any(identity.get(key) is not None for key in (
                        "batch_plan_sha256", "max_batch_members",
                        "max_batch_instances", "stack_reset_sha256",
                        "batch_journal_schema", "preflight_cache_policy")) \
                    or identity.get("compute_cap_sha256") != cap_sha256 \
                    or identity.get("reuse_projection_sha256") is not None \
                    or identity.get("estimand_pairs_sha256") \
                    != estimand_pairs_sha256 \
                    or identity.get("side") != side \
                    or identity.get("shard") != worker \
                    or identity.get("of") != row.get("of") \
                    or identity.get("expected_pairs") != len(pair_set) \
                    or identity.get("expected_pairs_sha256") \
                    != pair_set_digest(pair_set):
                raise TestQualityRefused(
                    "REFUSED: cap-bound root plan has a shard identity that "
                    "does not bind the scalar policy, exact cap, null reuse "
                    "projection, full estimand, and exact job partition.")
            observations[side].add(identity.get("observation_id"))
        if any(not observations[side] for side in SIDES):
            raise TestQualityRefused(
                "REFUSED: cap-bound root plan must contain native candidate "
                "and gold jobs.")
        if any(len(observations[side]) != 1 for side in SIDES):
            raise TestQualityRefused(
                "REFUSED: cap-bound root plan mixes mutation observation ids "
                "within one side.")
        observation_ids_by_side = {
            side: next(iter(observations[side])) for side in SIDES
        }
        if len(set(observation_ids_by_side.values())) != 1:
            raise TestQualityRefused(
                "REFUSED: compute-cap/v1 requires one root-minted observation "
                "id across its native candidate and gold legs.")
        if any(delta_pairs[side] != expected_set for side in SIDES):
            raise TestQualityRefused(
                "REFUSED: cap-bound root plan's per-side job union differs "
                "from the complete estimand.")
        delta_pairs_sha256_by_side = {
            side: pair_set_digest(delta_pairs[side]) for side in SIDES
        }
    plan = {
        "schema": (TEST_QUALITY_PLAN_SCHEMA_V1
                   if shard_policy == SHARD_POLICY_STRIDED_V1
                   else TEST_QUALITY_PLAN_SCHEMA_V3
                   if compute_cap is not None
                   else TEST_QUALITY_PLAN_SCHEMA),
        "jobs": planned,
        "worker_resources": resources,
        "worker_resources_sha256": resources_sha256,
        "expected_pairs": len(expected_set),
        "expected_pairs_sha256": pair_set_digest(expected_set),
        "require_complete": bool(require_complete),
        "gold_precomputed": bool(gold_precomputed),
        "final_artifacts": [CANDIDATE_ROWS, GOLD_ROWS, SUMMARY],
        # Present only for a narrowed candidate slice, so every `all` plan
        # keeps its bytes; resume compares whole plans, so a changed scope
        # cannot resume another scope's shards.
        **({"candidate_pair_scope": dict(candidate_scope)}
           if candidate_scope is not None else {}),
    }
    # Keep legacy strided plans byte-for-byte reconstructable.  New v2 plans
    # name their scheduling semantics explicitly so a resume under another
    # policy refuses before a worker starts.
    if shard_policy != SHARD_POLICY_STRIDED_V1:
        plan["shard_policy"] = shard_policy
    if sensitivity is not None:
        # A labelled post-hoc replay's harness overlay is campaign identity:
        # resume compares whole plans, so an unlabelled campaign's shards
        # cannot be resumed under the overlay, or the reverse.  Absent for
        # every unlabelled plan, which keeps its bytes.
        plan["sensitivity"] = sensitivity
    if compute_cap is not None:
        # Reserved by the shared plan-v3 cache union.  The only current
        # producer is compute-cap/v1, which is deliberately uncached.  Keep
        # historical plan-v1/v2 job bytes unchanged.
        for record in planned:
            record["preflight_cache_authority_sha256"] = None
        plan.update({
            "compute_cap": compute_cap,
            "compute_cap_sha256": cap_sha256,
            "projection_by_side": {side: None for side in SIDES},
            "observation_ids_by_side": observation_ids_by_side,
            "estimand_pairs_sha256": estimand_pairs_sha256,
            "delta_pairs_sha256_by_side": delta_pairs_sha256_by_side,
            "final_artifact_types_by_side": {
                side: "native_observation" for side in SIDES
            },
            "preflight_cache_authority": None,
        })
        validate_test_quality_plan_v3(plan)
    return plan


def _campaign_state_path(out_dir: str) -> str:
    return os.path.join(out_dir, CAMPAIGN_STATE)


def campaign_interruption(kind: str, plan: dict) -> dict:
    """Build one typed interruption reason for a current root record."""
    if not isinstance(kind, str) \
            or kind not in {INTERRUPTION_COMPUTE_CAP, INTERRUPTION_OPERATOR}:
        raise TestQualityRefused(
            f"REFUSED: unsupported campaign interruption kind {kind!r}.")
    cap_sha256 = (plan.get("compute_cap_sha256")
                  if kind == INTERRUPTION_COMPUTE_CAP else None)
    if kind == INTERRUPTION_COMPUTE_CAP and not _is_sha256(cap_sha256):
        raise TestQualityRefused(
            "REFUSED: compute-cap interruption has no cap digest in its root "
            "plan.")
    return {
        "schema": TEST_QUALITY_INTERRUPTION_SCHEMA,
        "kind": kind,
        "compute_cap_sha256": cap_sha256,
    }


def _validate_campaign_state(doc: dict, plan: dict) -> dict:
    """Validate a root state before resume or transition."""
    from .mutation_run import content_digest
    if not isinstance(plan, dict):
        raise TestQualityRefused(
            "REFUSED: test-quality root campaign plan is not an object.")
    old_fields = {"schema", "status", "plan", "plan_sha256", "history",
                  "artifacts", "error"}
    schema = doc.get("schema") if isinstance(doc, dict) else None
    fields = (old_fields | {"interruption"}
              if schema == TEST_QUALITY_CAMPAIGN_SCHEMA_V2 else old_fields)
    if not isinstance(doc, dict) or set(doc) != fields \
            or schema not in {TEST_QUALITY_CAMPAIGN_SCHEMA,
                              TEST_QUALITY_CAMPAIGN_SCHEMA_V2}:
        raise TestQualityRefused(
            "REFUSED: test-quality root campaign record has missing, "
            "unknown, or unsupported fields.")
    if schema == TEST_QUALITY_CAMPAIGN_SCHEMA_V2 \
            and plan.get("schema") != TEST_QUALITY_PLAN_SCHEMA_V3:
        raise TestQualityRefused(
            "REFUSED: typed root campaign v2 does not carry a cap/projection-"
            "bound test-quality plan v3.")
    if schema == TEST_QUALITY_CAMPAIGN_SCHEMA \
            and plan.get("schema") == TEST_QUALITY_PLAN_SCHEMA_V3:
        raise TestQualityRefused(
            "REFUSED: cap/projection-bound plan v3 is hidden beneath an "
            "untyped historical root campaign v1.")
    if plan.get("schema") == TEST_QUALITY_PLAN_SCHEMA_V3:
        validate_test_quality_plan_v3(plan)
    if doc.get("plan") != plan \
            or doc.get("plan_sha256") != content_digest(plan):
        raise TestQualityRefused(
            "REFUSED: test-quality output belongs to a different root "
            "campaign plan; candidate, population, workers, pair set, "
            "timeout, gold provenance, or completeness policy changed.")
    statuses = {"running", "complete", "interrupted", "failed"}
    status = doc.get("status")
    history = doc.get("history")
    if not isinstance(status, str) or status not in statuses \
            or not isinstance(history, list) or not history \
            or any(not isinstance(value, str) or value not in statuses
                   for value in history) \
            or history[-1] != status:
        raise TestQualityRefused(
            "REFUSED: test-quality root campaign has malformed status "
            "history.")
    error = doc.get("error")
    artifacts = doc.get("artifacts")
    if status in {"running", "complete"} and error is not None:
        raise TestQualityRefused(
            "REFUSED: running/complete campaign record carries an error.")
    if status in {"interrupted", "failed"} \
            and (not isinstance(error, str) or not error):
        raise TestQualityRefused(
            "REFUSED: interrupted/failed campaign record omits its reason.")
    if schema == TEST_QUALITY_CAMPAIGN_SCHEMA_V2:
        interruption = doc.get("interruption")
        if status == "interrupted":
            if not isinstance(interruption, dict) \
                    or set(interruption) \
                    != {"schema", "kind", "compute_cap_sha256"} \
                    or interruption.get("schema") \
                    != TEST_QUALITY_INTERRUPTION_SCHEMA:
                raise TestQualityRefused(
                    "REFUSED: interrupted root campaign v2 has no valid "
                    "typed interruption reason.")
            expected_interruption = campaign_interruption(
                interruption.get("kind"), plan)
            if interruption != expected_interruption:
                raise TestQualityRefused(
                    "REFUSED: typed interruption differs from its root cap "
                    "identity.")
        elif interruption is not None:
            raise TestQualityRefused(
                "REFUSED: only an interrupted root may carry a typed "
                "interruption reason.")
    if not isinstance(artifacts, dict):
        raise TestQualityRefused(
            "REFUSED: campaign artifact binding is not an object.")
    if status != "complete" and artifacts:
        raise TestQualityRefused(
            "REFUSED: an incomplete campaign claims final artifacts.")
    if status == "complete":
        if set(artifacts) != {CANDIDATE_ROWS, GOLD_ROWS, SUMMARY} \
                or any(not _is_sha256(value)
                       for value in artifacts.values()):
            raise TestQualityRefused(
                "REFUSED: complete campaign has incomplete artifact hashes.")
    return doc


def _load_campaign_state(out_dir: str, plan: dict) -> dict:
    path = _campaign_state_path(out_dir)
    if os.path.islink(path) or not os.path.isfile(path):
        raise TestQualityRefused(
            f"REFUSED: test-quality root campaign record is not a regular "
            f"file: {path}.")
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        raise TestQualityRefused(
            f"REFUSED: cannot read root campaign record {path}: {e}") from e
    return _validate_campaign_state(doc, plan)


def shard_policy_from_plan(plan: dict) -> str:
    """Read scheduling semantics from a saved root plan, fail closed.

    The v1 schema predates an explicit field and has exactly one meaning:
    historical mutant striding.  The v2 schema was introduced together with
    pair-count LPT and must name it.  Inferring the current default here would
    rewrite history whenever a publication reader reconstructs an old plan.
    """
    if not isinstance(plan, dict):
        raise TestQualityRefused(
            "REFUSED: test-quality root campaign plan is not an object.")
    schema = plan.get("schema")
    if schema == TEST_QUALITY_PLAN_SCHEMA_V1:
        if "shard_policy" in plan:
            raise TestQualityRefused(
                "REFUSED: historical v1 root plan carries an invented "
                "shard_policy field.")
        return SHARD_POLICY_STRIDED_V1
    if schema in {TEST_QUALITY_PLAN_SCHEMA, TEST_QUALITY_PLAN_SCHEMA_V3}:
        policy = plan.get("shard_policy")
        if policy != SHARD_POLICY_BALANCED_PAIRS_V1:
            raise TestQualityRefused(
                f"REFUSED: {schema} root plan omits or misstates its balanced "
                f"scheduling policy: {policy!r}.")
        return policy
    raise TestQualityRefused(
        f"REFUSED: unsupported test-quality root plan schema {schema!r}.")


def policy_identity_binding_from_plan(plan: dict) -> bool:
    """Validate the root/identity policy relation and return its generation.

    ``False`` denotes the preserved historical v1-strided representation.
    ``True`` denotes a current v2/v3 LPT root whose shard identities are v3/v4
    and therefore stamp the policy onto every mutation row. An unbound v2 LPT
    root is reconstructable as bytes, but is not self-authenticating: a
    coordinated edit can turn a v1-strided root and all of its mutable
    sidecars into exactly that representation without changing a row.  No
    immutable exact-artifact authority for those short-lived files is shipped
    with this harness, so consumers must refuse them rather than guess which
    policy produced their rows.
    """
    policy = shard_policy_from_plan(plan)
    records = plan.get("jobs") if isinstance(plan, dict) else None
    if not isinstance(records, list):
        raise TestQualityRefused(
            "REFUSED: test-quality root plan jobs are not an array.")
    if records == [] and "zero_pair_candidate" in plan:
        return True
    return _admitted_policy_identity_binding(records, policy)


def _validate_existing_shard_policy_sidecars(out_dir: str, plan: dict,
                                             shard_policy: str) -> None:
    """Fail closed on every existing planned sidecar before worker preflight."""
    from .mutation_run import MUTATION_PROVENANCE_SCHEMA
    records = plan.get("jobs") if isinstance(plan, dict) else None
    if not isinstance(records, list):
        raise TestQualityRefused(
            "REFUSED: test-quality root plan jobs are not an array.")
    historical = plan.get("schema") == TEST_QUALITY_PLAN_SCHEMA_V1
    for number, record in enumerate(records):
        rel = record.get("out") if isinstance(record, dict) else None
        basename = os.path.basename(rel) if isinstance(rel, str) else None
        if not isinstance(rel, str) or not rel \
                or basename in {"", ".", ".."} \
                or rel != os.path.join(SHARD_DIR, basename):
            raise TestQualityRefused(
                f"REFUSED: root campaign job {number} has an unsafe shard "
                f"path {rel!r}.")
        rows_path = os.path.join(out_dir, rel)
        side_path = rows_path + ".provenance.json"
        if os.path.islink(rows_path) or os.path.islink(side_path):
            raise TestQualityRefused(
                f"REFUSED: planned resume shard evidence is a symlink: "
                f"{rows_path}.")
        if (os.path.lexists(rows_path) and not os.path.isfile(rows_path)) \
                or (os.path.lexists(side_path)
                    and not os.path.isfile(side_path)):
            raise TestQualityRefused(
                f"REFUSED: planned resume shard evidence is not a regular "
                f"file: {rows_path}, {side_path}.")
        rows_exist = os.path.isfile(rows_path)
        side_exists = os.path.isfile(side_path)
        if not rows_exist and not side_exists:
            continue
        if rows_exist != side_exists:
            raise TestQualityRefused(
                f"REFUSED: resume needs both {rows_path} and {side_path}; "
                "only one exists.")
        sidecar = _load_json_object(
            side_path, "test-quality shard provenance for --resume")
        recorded_policy = sidecar.get("shard_policy")
        policy_ok = (
            recorded_policy == shard_policy
            or (historical and recorded_policy is None))
        if not policy_ok:
            raise TestQualityRefused(
                f"REFUSED: {side_path} shard_policy "
                f"{recorded_policy!r} differs from its root campaign policy "
                f"{shard_policy!r}.")
        if sidecar.get("schema") != MUTATION_PROVENANCE_SCHEMA \
                or sidecar.get("campaign_identity") \
                != record.get("campaign_identity") \
                or sidecar.get("mutation_campaign_digest") \
                != record.get("mutation_campaign_digest"):
            raise TestQualityRefused(
                f"REFUSED: {side_path} does not carry the campaign identity "
                "and digest frozen into its root plan.")


def _resume_policy_identity_binding(out_dir: str,
                                    shard_policy: str) -> bool:
    """Read the saved plan generation before reconstructing resume jobs."""
    state_doc = _load_json_object(
        _campaign_state_path(out_dir),
        "test-quality root campaign record for --resume")
    plan = state_doc.get("plan")
    _validate_campaign_state(state_doc, plan)
    _refuse_cap_bound_resume(plan)
    saved_policy = shard_policy_from_plan(plan)
    if saved_policy != shard_policy:
        raise TestQualityRefused(
            f"REFUSED: --resume requested shard policy {shard_policy!r}, but "
            f"the saved root campaign uses {saved_policy!r}.")
    bound = policy_identity_binding_from_plan(plan)
    _validate_existing_shard_policy_sidecars(out_dir, plan, saved_policy)
    return bound


def _refuse_cap_bound_resume(plan: dict) -> None:
    """Keep compute-cap/v1 a hard, single-invocation wall-clock budget.

    Version 1 records no durable elapsed-time debit that a later process can
    subtract.  Starting a fresh timer would therefore turn every interruption
    (and every hard-killed ``running`` root) into a brand-new full allowance.
    The evidence remains readable, including by ``mutation-bound``; execution
    resume is deliberately unavailable until a cumulative cap schema exists.
    """
    if isinstance(plan, dict) \
            and plan.get("schema") == TEST_QUALITY_PLAN_SCHEMA_V3 \
            and plan.get("compute_cap") is not None:
        raise TestQualityRefused(
            "REFUSED: r2t.test-quality-compute-cap/v1 is a hard "
            "single-invocation budget and cannot be resumed; preserve this "
            "root as cap evidence and start a newly reviewed campaign in a "
            "new output directory.")


def resolve_cli_shard_policy(out_dir: str, requested: Optional[str], *,
                             resume: bool) -> str:
    """Resolve the public CLI policy before workers or outputs are touched.

    A new campaign always uses LPT.  Historical striding remains selectable
    only as an assertion while resuming an existing v1 root record; omitting
    the option on resume reads the saved schema, so a bare historical
    ``--resume`` cannot silently switch to today's default.
    """
    if requested is not None and requested not in SHARD_POLICIES:
        raise TestQualityRefused(
            f"REFUSED: unknown shard policy {requested!r}; expected one of "
            f"{list(SHARD_POLICIES)}.")
    if not resume:
        if requested == SHARD_POLICY_STRIDED_V1:
            raise TestQualityRefused(
                "REFUSED: r2t.strided-mutants/1 is historical resume-only; "
                "new campaigns use r2t.balanced-pairs-lpt/1.")
        return requested or DEFAULT_SHARD_POLICY

    state_path = _campaign_state_path(out_dir)
    state_doc = _load_json_object(
        state_path, "test-quality root campaign record for --resume")
    plan = state_doc.get("plan")
    _validate_campaign_state(state_doc, plan)
    _refuse_cap_bound_resume(plan)
    saved = shard_policy_from_plan(plan)
    if requested is not None and requested != saved:
        raise TestQualityRefused(
            f"REFUSED: --resume requested shard policy {requested!r}, but "
            f"the saved root campaign uses {saved!r}.")
    policy_identity_binding_from_plan(plan)
    _validate_existing_shard_policy_sidecars(out_dir, plan, saved)
    return saved


def _write_new_campaign_state(out_dir: str, plan: dict) -> dict:
    from .mutation_run import (MutationAborted, atomic_write_json,
                               content_digest)
    # Through the same validator as every other root write, so "one
    # transition table" is true of creation too and not only of movement.
    validate_root_transition(None, "running")
    doc = {
        "schema": (TEST_QUALITY_CAMPAIGN_SCHEMA_V2
                   if plan.get("schema") == TEST_QUALITY_PLAN_SCHEMA_V3
                   else TEST_QUALITY_CAMPAIGN_SCHEMA),
        "status": "running",
        "plan": plan,
        "plan_sha256": content_digest(plan),
        "history": ["running"],
        "artifacts": {},
        "error": None,
    }
    if doc["schema"] == TEST_QUALITY_CAMPAIGN_SCHEMA_V2:
        doc["interruption"] = None
    try:
        atomic_write_json(_campaign_state_path(out_dir), doc,
                          refuse_existing=True)
    except MutationAborted as e:
        raise TestQualityRefused(str(e)) from e
    return doc


#: The ROOT lifecycle, in the same shape as the shard one
#: (`mutation_run.SHARD_TRANSITIONS`).  `absent` is spelled `None`, and it is
#: reachable only through `_write_new_campaign_state`, which refuses an
#: existing file — so a root record is created once and moved thereafter.
ROOT_STATES: tuple[str, ...] = ("running", "complete", "interrupted",
                                "failed")
ROOT_TRANSITIONS: dict = {
    None: {"running"},
    "running": {"running", "complete", "interrupted", "failed"},
    "interrupted": {"running"},
    "complete": set(),
    "failed": set(),
}


def validate_root_transition(current: Optional[str], status: str) -> None:
    """The ONE validator every root campaign state write goes through."""
    if status not in ROOT_STATES:
        raise TestQualityRefused(
            f"REFUSED: unknown root campaign transition {status!r}.")
    if current is not None and current not in ROOT_STATES:
        raise TestQualityRefused(
            f"REFUSED: root campaign carries unknown recorded status "
            f"{current!r}.")
    if status not in ROOT_TRANSITIONS[current]:
        raise TestQualityRefused(
            f"REFUSED: root campaign cannot transition from "
            f"{current if current is not None else 'absent'!r} to "
            f"{status!r}.")


def planned_shard_states(out_dir: str, plan: dict) -> list:
    """`[(planned shard name, recorded status or None)]`. Reads only."""
    from .mutation_run import MUTATION_PROVENANCE_SCHEMA, provenance_path
    states = []
    for job in (plan.get("jobs") if isinstance(plan, dict) else None) or []:
        name = job.get("out")
        if not isinstance(name, str) or not name:
            continue
        side = provenance_path(os.path.join(out_dir, name))
        if os.path.islink(side) or not os.path.isfile(side):
            states.append((name, None))
            continue
        try:
            with open(side, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            raise TestQualityRefused(
                f"REFUSED: cannot read shard provenance {side}: {e}") from e
        if not isinstance(doc, dict) \
                or doc.get("schema") != MUTATION_PROVENANCE_SCHEMA:
            raise TestQualityRefused(
                f"REFUSED: {side} is not an {MUTATION_PROVENANCE_SCHEMA} "
                f"document, so the root state cannot be checked against it.")
        states.append((name, doc.get("status")))
    return states


def validate_root_shard_consistency(out_dir: str, plan: dict,
                                    status: str) -> None:
    """Refuse a TERMINAL root state its own shards do not support.

    The root record and the shard sidecars are written by different code at
    different times, and until this check nothing compared them.  Review
    finding 9's failure is exactly that gap: every in-flight slice wrote
    `interrupted`, the coordinator wrote `failed` over the top, and the
    directory then held a terminal root that contradicted every shard in it
    while `failed` has no outgoing transition.

    Only terminal writes are checked, and only in the two directions that are
    decidable from the sidecars: a `failed` root whose shards uniformly say
    `interrupted`, and a `complete` root over a shard that does not say
    `complete`.  A mixed set is left alone deliberately — one real failure
    beside an interruption IS a failed campaign, and that is the fail-closed
    direction.
    """
    if status not in {"complete", "failed"}:
        return
    states = planned_shard_states(out_dir, plan)
    recorded = [state for _name, state in states if state is not None]
    # UNIFORMLY interrupted, and that word is doing work in both directions:
    # every planned shard has an attestation, and every one of them says
    # `interrupted`.
    #
    # THE COMPLETENESS CONDITION NARROWS THIS REFUSAL — it fires in FEWER
    # states than "all the sidecars I can see say interrupted" would, and
    # that is deliberate rather than incidental strictness. A planned shard
    # with NO sidecar is not evidence of a cooperative stop: a worker that
    # died before writing one is exactly the case where `failed` is the true
    # state, and refusing there would deny the campaign its own terminal
    # record. A mix containing a `failed` shard is likewise a failed campaign
    # and passes through.
    if status == "failed" and recorded and len(recorded) == len(states) \
            and all(state == "interrupted" for state in recorded):
        raise TestQualityRefused(
            f"REFUSED: refusing to record root campaign {out_dir} as `failed` "
            f"when all {len(recorded)} planned shard(s) are attested "
            f"`interrupted`. Every worker stopped cooperatively, so this "
            f"campaign is `interrupted` and resumable; writing `failed` would "
            f"strand valid, identity-stamped rows behind a terminal state "
            f"(review finding 9).")
    if status == "complete":
        unfinished = sorted(name for name, state in states
                            if state != "complete")
        if unfinished:
            raise TestQualityRefused(
                f"REFUSED: root campaign cannot be recorded `complete` while "
                f"planned shard(s) {unfinished[:5]} are not attested "
                f"`complete`.")


def transition_campaign_state(out_dir: str, plan: dict, status: str, *,
                              error: Optional[str] = None,
                              artifacts: Optional[dict] = None,
                              interruption: Optional[dict] = None) -> dict:
    """Atomically move a validated root record to its next durable state."""
    from .mutation_run import MutationAborted, atomic_write_json
    if status not in ROOT_STATES:
        raise TestQualityRefused(
            f"REFUSED: unknown root campaign transition {status!r}.")
    current = _load_campaign_state(out_dir, plan)
    validate_root_transition(current["status"], status)
    validate_root_shard_consistency(out_dir, plan, status)
    if status in {"interrupted", "failed"}:
        if not isinstance(error, str) or not error:
            raise TestQualityRefused(
                f"REFUSED: {status} transition requires a reason.")
    elif error is not None:
        raise TestQualityRefused(
            f"REFUSED: {status} transition may not carry an error.")
    current_is_typed = (
        current.get("schema") == TEST_QUALITY_CAMPAIGN_SCHEMA_V2)
    if current_is_typed:
        if status == "interrupted":
            if not isinstance(interruption, dict):
                raise TestQualityRefused(
                    "REFUSED: interrupted campaign v2 transition requires a "
                    "typed interruption reason.")
        elif interruption is not None:
            raise TestQualityRefused(
                f"REFUSED: {status} transition may not carry an interruption.")
    elif interruption is not None:
        raise TestQualityRefused(
            "REFUSED: historical campaign v1 cannot carry an invented typed "
            "interruption.")
    final_artifacts = dict(artifacts or {})
    if status != "complete" and final_artifacts:
        raise TestQualityRefused(
            "REFUSED: only a complete campaign may bind final artifacts.")
    doc = {
        **current,
        "status": status,
        "history": [*current["history"], status],
        "artifacts": final_artifacts,
        "error": error,
    }
    if current_is_typed:
        doc["interruption"] = interruption
    _validate_campaign_state(doc, plan)
    try:
        atomic_write_json(_campaign_state_path(out_dir), doc)
    except MutationAborted as e:
        raise TestQualityRefused(str(e)) from e
    return doc


def prepare_output_directory(out_dir: str, jobs: Iterable[dict], *,
                             resume: bool,
                             campaign_plan: Optional[dict] = None) -> None:
    """Require a new/empty directory, or validate every existing resume shard."""
    from .mutation_run import MutationAborted, completed_pairs, provenance_path
    if os.path.lexists(out_dir) and os.path.islink(out_dir):
        raise TestQualityRefused(
            f"REFUSED: mutation output directory is a symlink: {out_dir}.")
    if os.path.lexists(out_dir) and not os.path.isdir(out_dir):
        raise TestQualityRefused(
            f"REFUSED: mutation output is not a directory: {out_dir}.")
    planned = list(jobs)
    campaign_plan = campaign_plan or build_test_quality_campaign_plan(planned)
    root_shard_policy = shard_policy_from_plan(campaign_plan)
    policy_identity_binding_from_plan(campaign_plan)
    if not resume:
        if os.path.isdir(out_dir) and os.listdir(out_dir):
            raise TestQualityRefused(
                f"REFUSED: mutation output directory is not empty: {out_dir}. "
                "Use a new/empty directory, or --resume only for the exact "
                "content-bound campaign already present.")
        os.makedirs(out_dir, exist_ok=True)
        _write_new_campaign_state(out_dir, campaign_plan)
        return
    if not os.path.isdir(out_dir):
        raise TestQualityRefused(
            f"REFUSED: --resume was requested but {out_dir} does not exist. "
            "Use the default new-output mode for a fresh campaign.")

    unexpected_root = sorted(set(os.listdir(out_dir))
                             - {SHARD_DIR, CAMPAIGN_STATE})
    if unexpected_root:
        raise TestQualityRefused(
            f"REFUSED: resume directory contains unplanned root artifact(s) "
            f"{unexpected_root[:5]}. Preserve it and use a new output; resume "
            "may contain only its root identity and planned partial shards.")

    state = _load_campaign_state(out_dir, campaign_plan)
    _refuse_cap_bound_resume(campaign_plan)
    if state["status"] in {"failed", "complete"}:
        raise TestQualityRefused(
            f"REFUSED: {out_dir} has terminal root campaign status "
            f"{state['status']!r}. Preserve it as evidence and use a new "
            "output directory.")

    final_names = {CANDIDATE_ROWS, GOLD_ROWS, SUMMARY}
    finished = sorted(name for name in final_names
                      if os.path.lexists(os.path.join(out_dir, name)))
    if finished:
        raise TestQualityRefused(
            f"REFUSED: {out_dir} already has final artifact(s) {finished}; it "
            "is not a partial campaign and will not be overwritten by resume.")
    shard_dir = os.path.join(out_dir, SHARD_DIR)
    allowed = {os.path.basename(job["out"]) for job in planned}
    allowed |= {name + ".provenance.json" for name in list(allowed)}
    if os.path.isdir(shard_dir):
        unexpected = sorted(set(os.listdir(shard_dir)) - allowed)
        if unexpected:
            raise TestQualityRefused(
                f"REFUSED: resume directory contains unplanned shard files "
                f"{unexpected[:5]}.")
    elif os.path.lexists(shard_dir):
        raise TestQualityRefused(
            f"REFUSED: {shard_dir} exists but is not a directory.")

    matched = 0
    for job in planned:
        path = job["out"]
        side = provenance_path(path)
        has_rows, has_side = os.path.isfile(path), os.path.isfile(side)
        if has_rows != has_side:
            raise TestQualityRefused(
                f"REFUSED: resume needs both {path} and {side}; only one "
                "exists.")
        if not has_rows:
            continue
        try:
            completed_pairs(
                path, job["identity"],
                expected_pairs=_job_pairs(job["mutants"], job["by_mutant"],
                                          job["files_by_item"]),
                expected_shard_policy=root_shard_policy,
                allow_missing_shard_policy=(
                    campaign_plan.get("schema")
                    == TEST_QUALITY_PLAN_SCHEMA_V1))
        except MutationAborted as e:
            raise TestQualityRefused(str(e)) from e
        matched += 1
    if not matched:
        raise TestQualityRefused(
            f"REFUSED: --resume found no identity-bearing shard in {out_dir}. "
            "Use the default mode for a new/empty campaign.")
    transition_campaign_state(out_dir, campaign_plan, "running")


def validate_output_contents(out_dir: str, jobs: Iterable[dict], *,
                             final_names: Iterable[str] = (),
                             require_all_shards: bool = True,
                             campaign_plan: Optional[dict] = None,
                             campaign_status: Optional[str] = None) -> None:
    """Require the exact planned artifact tree at a merge/finalization gate."""
    planned = list(jobs)
    if os.path.islink(out_dir) or not os.path.isdir(out_dir):
        raise TestQualityRefused(
            f"REFUSED: test-quality output is not a real directory: {out_dir}.")
    wanted_root = {SHARD_DIR, CAMPAIGN_STATE, *set(final_names)}
    got_root = set(os.listdir(out_dir))
    if got_root != wanted_root:
        raise TestQualityRefused(
            f"REFUSED: test-quality output root differs from the planned "
            f"artifact set: missing={sorted(wanted_root-got_root)[:5]}, "
            f"unexpected={sorted(got_root-wanted_root)[:5]}.")
    for name in wanted_root:
        path = os.path.join(out_dir, name)
        if os.path.islink(path):
            raise TestQualityRefused(
                f"REFUSED: planned test-quality artifact is a symlink: {path}.")
        if name == SHARD_DIR:
            if not os.path.isdir(path):
                raise TestQualityRefused(
                    f"REFUSED: planned shard path is not a directory: {path}.")
        elif not os.path.isfile(path):
            raise TestQualityRefused(
                f"REFUSED: planned final artifact is not a file: {path}.")
    if campaign_plan is not None:
        state = _load_campaign_state(out_dir, campaign_plan)
        if campaign_status is not None and state["status"] != campaign_status:
            raise TestQualityRefused(
                f"REFUSED: root campaign status is {state['status']!r}, not "
                f"{campaign_status!r}.")
        if state["status"] == "complete":
            from .mutation_run import sha256_file
            changed = sorted(
                name for name, digest in state["artifacts"].items()
                if not os.path.isfile(os.path.join(out_dir, name))
                or os.path.islink(os.path.join(out_dir, name))
                or sha256_file(os.path.join(out_dir, name)) != digest)
            if changed:
                raise TestQualityRefused(
                    f"REFUSED: complete root campaign artifact hash(es) "
                    f"changed: {changed}.")

    shard_dir = os.path.join(out_dir, SHARD_DIR)
    wanted_shards = {os.path.basename(job["out"]) for job in planned}
    wanted_shards |= {name + ".provenance.json"
                      for name in list(wanted_shards)}
    got_shards = set(os.listdir(shard_dir))
    unexpected = sorted(got_shards - wanted_shards)
    missing = sorted(wanted_shards - got_shards) if require_all_shards else []
    if unexpected or missing:
        raise TestQualityRefused(
            f"REFUSED: shard directory differs from the exact plan: "
            f"missing={missing[:5]}, unexpected={unexpected[:5]}.")
    for name in got_shards:
        path = os.path.join(shard_dir, name)
        if os.path.islink(path) or not os.path.isfile(path):
            raise TestQualityRefused(
                f"REFUSED: mutation shard evidence is not a regular file: "
                f"{path}.")


# ---------------------------------------------------------------- scoring
def gold_kill_sets(gold_rows: Iterable[dict], gold_baseline: dict,
                   items: Iterable[str]) -> tuple[dict, int, int]:
    """Return gold kills, ineligible kills and infrastructure outcomes.

    A gold KILL is not merely "gold's mutated run failed": §3.10 requires the
    killer's own baseline to have passed, or an item where gold was already
    broken would contribute mutants to the population that nothing could have
    killed for the right reason.  Gold passes everywhere today, which is
    exactly why deriving this naively would go unnoticed until the day it
    does not — so the ignored count is returned and reported.
    """
    wanted = set(items)
    killed: dict = {}
    ignored = 0
    infrastructure = 0
    for row in gold_rows:
        item_id = row.get("item_id")
        verdict = classify_outcome(
            gold_baseline.get(item_id), row.get("outcome"))
        if item_id not in wanted:
            continue
        if gold_baseline.get(item_id) != "passed":
            if verdict == "kill":
                ignored += 1
            elif verdict == "infrastructure":
                infrastructure += 1
            continue
        if verdict == "kill":
            killed.setdefault(item_id, set()).add(row["mutant_id"])
        elif verdict == "infrastructure":
            infrastructure += 1
    return killed, ignored, infrastructure


def gold_infrastructure_pairs(gold_rows: Iterable[dict],
                              gold_baseline: dict,
                              items: Iterable[str]) -> list[dict]:
    """The exact pairs behind `gold_kill_sets`' infrastructure COUNT.

    Ruling 2.6 admits a primary result over gold carrying a nonzero
    infrastructure count only while "the exact count and a per-item disclosure
    travel with the published number".  A tally cannot be disclosed per item,
    so the pairs themselves are recovered here, by the same classification the
    count is made of — one function's answer read two ways rather than two
    functions that can disagree about which rows they mean.
    """
    wanted = set(items)
    out = []
    for row in gold_rows:
        item_id = row.get("item_id")
        if item_id not in wanted:
            continue
        if classify_outcome(gold_baseline.get(item_id),
                            row.get("outcome")) != "infrastructure":
            continue
        out.append({"item_id": item_id, "mutant_id": row.get("mutant_id"),
                    "outcome": row.get("outcome"),
                    "gold_baseline_outcome": gold_baseline.get(item_id)})
    return sorted(out, key=lambda e: (e["item_id"] or "", e["mutant_id"] or ""))


def validate_native_retry_evidence(rows: Iterable[dict], *, where: str) -> None:
    """§3.10's retry, VERIFIED on the rows rather than assumed of them.

    The producer stamps every mutation row with the attempt it ended on and
    whether that attempt was a retry (`mutation_run.py:2437-2443`).  Nothing
    read those stamps back, so "infrastructure failures are retried once then
    excluded and counted" was a promise about code that could be edited away
    without a witness.

    **Which vocabulary "a final infrastructure outcome" means.**  There are two
    infrastructure sets in this repository and they are deliberately different:
    `mutation.INFRASTRUCTURE_OUTCOMES` is the SCORING vocabulary
    `classify_outcome` buckets by (it counts `undefined_steps`, `setup_error`
    and a dozen more), while `mutation_run.INFRASTRUCTURE_OUTCOMES` is the
    narrower set the retry loop actually fires on.  The rule pinned here is the
    producer's own: a row that ended on an outcome the loop RETRIES must show
    the second attempt.  Reading it against the scoring vocabulary instead
    would refuse honestly produced native evidence — the harness never retries
    an `undefined_steps` row, so no such row can ever carry `attempt == 2`.
    """
    from .mutation_run import INFRASTRUCTURE_OUTCOMES as RETRIABLE
    for number, row in enumerate(rows, 1):
        attempt = row.get("attempt")
        retried = row.get("retried_infrastructure")
        if isinstance(attempt, bool) or not isinstance(attempt, int) \
                or attempt not in (1, 2):
            raise TestQualityRefused(
                f"REFUSED: {where} row {number} has no native retry stamp "
                f"(attempt={attempt!r}); §3.10's retry cannot be verified, so "
                f"this gold may not be reported as degraded NATIVE gold. "
                f"Legacy rows predate the stamp and enter publication only "
                f"through ruling 2.6's recorded, disclosed tolerance.")
        if not isinstance(retried, bool) or retried != (attempt == 2):
            raise TestQualityRefused(
                f"REFUSED: {where} row {number} stamps attempt={attempt} but "
                f"retried_infrastructure={retried!r}; the two record one fact "
                f"and disagree, so neither is evidence.")
        if row.get("outcome") in RETRIABLE and attempt != 2:
            raise TestQualityRefused(
                f"REFUSED: {where} row {number} ended on retriable "
                f"infrastructure outcome {row.get('outcome')!r} at attempt "
                f"{attempt}. §3.10 retries such a failure once before counting "
                f"it; a first-and-only attempt is a retry that did not happen.")


def check_gold_degradation(gold_rows: Iterable[dict], gold_baseline: dict,
                           items: Iterable[str], *,
                           gold_provenance_class: Optional[str],
                           require_complete: bool,
                           allow_degraded_gold: bool) -> dict:
    """Refuse — or explicitly record — infrastructure-degraded imported gold.

    Called BEFORE the candidate slices run, for the same reason the short-gold
    check is: the candidate half is the expensive one, and whether its gold is
    usable is knowable from a file read.

    Short gold and degraded gold are DIFFERENT states and are kept apart here.
    A short file shrinks the set the candidate is measured against; a degraded
    one is the right size and carries outcomes that are the harness failing
    rather than the mutant surviving.  A file can be either, both or neither,
    and `gold_rows_missing` and `gold_infrastructure_outcomes` move
    independently because of it.

    Returns the disclosure block ruling 2.6 requires to travel with the number.
    """
    pairs = gold_infrastructure_pairs(gold_rows, gold_baseline, items)
    count = len(pairs)
    if count and gold_provenance_class == "native":
        # Native rows carry the stamps, so the retry §3.10 promises is checked
        # rather than assumed before any of them is tolerated.
        validate_native_retry_evidence(
            gold_rows, where="precomputed native gold")
        klass = "native_retry_verified"
    elif count:
        # Ruling 2.6, third bullet: legacy rows have no `attempt` stamp and
        # therefore cannot claim degraded NATIVE gold.  They are admitted as
        # the recorded tolerance instead — never as retry evidence, and never
        # silently.
        klass = "recorded_tolerance"
    else:
        klass = "none"
    if count and require_complete and not allow_degraded_gold:
        raise TestQualityRefused(
            f"REFUSED: the supplied gold rows carry {count} infrastructure "
            f"outcome(s) — the harness failing rather than a mutant surviving "
            f"— on pairs the candidate is scored against, e.g. "
            f"{[(e['item_id'], e['mutant_id']) for e in pairs[:3]]}. Under "
            f"complete scoring that degradation must be consented to "
            f"explicitly: pass --allow-degraded-gold, which is independent of "
            f"--allow-incomplete and records the count and the per-item "
            f"disclosure in the summary (owner ruling 2.6: nothing is "
            f"tolerated silently).")
    return {
        "gold_infrastructure_outcomes": count,
        "gold_infrastructure_pairs": pairs,
        "gold_infrastructure_class": klass,
        "allow_degraded_gold": bool(allow_degraded_gold),
    }


#: The qualifier a published mutation number must carry with it (R4 item 4).
#:
#: Seven fields, threaded through `report.non_vacuous`, `results.mutation` and
#: `compare` the way `engine` already is, because the number means a different
#: thing under each of them: how many pairs were expected, how many gold
#: actually executed, how many gold rows are missing, how many ended in the
#: harness failing, whether completeness was checked at all, whether it was
#: required, and which provenance class the gold came from.
PUBLICATION_QUALIFIER_FIELDS = (
    "require_complete", "completeness_checked", "pairs_expected",
    "pairs_executed_gold", "gold_rows_missing", "gold_infrastructure_outcomes",
    "gold_provenance_class",
)

#: The ruling-2.6 disclosure that travels beside the qualifier.
TOLERANCE_DISCLOSURE_FIELDS = (
    "gold_infrastructure_pairs", "gold_infrastructure_class",
    "allow_degraded_gold",
)


#: What a summary that IS publication-ready says about its own completeness.
#:
#: One definition, spread by the `report` and `results` fixtures exactly as
#: `FIXTURE_GENERATION_INPUTS` is spread, so a fixture cannot drift into being
#: publishable by acquiring a field nobody meant to grant it — and so a test
#: that wants the UNpublishable state has to name the field it drops.
COMPLETE_QUALIFIER_FIXTURE: dict = {
    # Publication-ready fixtures model the post-C4 primary explicitly.  Tests
    # for historical/full-gold sensitivity remove or override these fields.
    "verdict_basis": "hard_subset",
    "hard_subset_digest": "a" * 64,
    "require_complete": True,
    "completeness_checked": True,
    "pairs_expected": 80,
    "pairs_executed_gold": 80,
    "gold_rows_missing": 0,
    "gold_infrastructure_outcomes": 0,
    "gold_infrastructure_pairs": [],
    "gold_infrastructure_class": "none",
    "allow_degraded_gold": False,
    "gold_provenance_class": "native",
    # WHICH ATTEMPT PRODUCED THE CANDIDATE.  Publication-ready means the
    # candidate can name it, so the fixture states a publishable class here
    # rather than leaving the field absent: absence is a withholding reason
    # in `publication_ready`, and a fixture that omitted it would have been
    # asserting the ready path while modelling an unnameable candidate.
    "generation_provenance_class": "native_v2",
}


def publication_qualifier(summary: Optional[dict]) -> dict:
    """The qualifier fields, read off a summary, with absence left as absence.

    A summary written before a field existed says `None` for it, which is a
    different fact from `0` and is kept as one.
    """
    summary = summary or {}
    out = {key: summary.get(key)
           for key in PUBLICATION_QUALIFIER_FIELDS + TOLERANCE_DISCLOSURE_FIELDS}
    ready, reasons = publication_ready(summary)
    out["publication_ready"] = ready
    out["withheld_reasons"] = reasons
    return out


def publication_ready(summary: Optional[dict]) -> tuple[bool, list[str]]:
    """R4 item 5's predicate, and the reasons when it is False.

    > `require_complete && completeness_checked && gold_rows_missing == 0 &&
    >  gold_infrastructure_outcomes == 0`

    subject to owner ruling 2.6, which rewrites the last conjunct as
    *`gold_infrastructure_outcomes == 0` OR the recorded tolerance applies*,
    where "applies" means all three of: the consent flag was explicit, the
    count is disclosed beside the number, and the per-item disclosure is
    present.  A tolerance whose disclosure is missing is not a tolerance — it
    is the silence the ruling exists to forbid — so the disclosure is checked
    here rather than assumed of the operator who passed the flag.

    Returned as `(ready, reasons)` rather than a bare bool: a withheld number
    that does not say WHY is a number somebody re-runs the command for.
    """
    summary = summary or {}
    reasons = []
    if summary.get("schema") == TEST_QUALITY_SUMMARY_SCHEMA_V2:
        # The native v2 reader authenticates complete pairs, reference sets and
        # exclusions. Its closed schema does not carry v1 completeness fields.
        # That validation cannot supply missing historical generation evidence.
        from .mutation_run import GENERATION_PROVENANCE_PUBLISHABLE
        klass = summary.get("generation_provenance_class")
        if klass not in GENERATION_PROVENANCE_PUBLISHABLE:
            reasons.append(
                f"the candidate's generation provenance class is {klass!r}; "
                "development evidence cannot name a publishable generation attempt")
        if summary.get("require_complete") is not True:
            reasons.append("the candidate pair set requires complete validation")
        if summary.get("sensitivity") is not None:
            reasons.append(
                f"labelled sensitivity {summary['sensitivity']!r}: the "
                "reference's failed stub gate is waived, so the number is "
                "inference_valid false and never publishable")
        return not reasons, reasons
    # An absent basis is historical only when the summary is the authenticated
    # wrapper shape `load_bound_test_quality` validates before any publication
    # surface reaches this predicate.  A new/native object cannot obtain that
    # exception merely by omitting a field: `_validate_native_summary` rejects
    # it above, and direct/current fixture callers fail closed here too.
    authenticated_legacy_shape = isinstance(
        summary, _AuthenticatedLegacySummary)
    basis = summary.get("verdict_basis")
    if basis is None and not authenticated_legacy_shape:
        reasons.append(
            "verdict_basis is absent; only an authenticated legacy-rebinding "
            "wrapper may preserve pre-C4 full-gold semantics")
    elif basis is not None and basis != "hard_subset":
        reasons.append(
            f"verdict_basis is {basis!r}, not the "
            "population-pinned hard_subset; full-gold scoring is a "
            "sensitivity result after C4")
    if summary.get("verdict_basis") == "hard_subset" \
            and not _is_sha256(summary.get("hard_subset_digest")):
        reasons.append(
            "verdict_basis is hard_subset but hard_subset_digest is not a "
            "full lowercase SHA-256 binding for the denominator")
    # WHICH ATTEMPT PRODUCED THE CANDIDATE.
    # `refuse_unpublishable_generation` refuses an unpublishable class at each
    # READER, but a reader's refusal is a property of that reader's inputs;
    # the predicate that decides whether the number is PRINTED never asked.
    # A `development_unstamped` candidate that reached a hard subset would
    # therefore publish -- not because the class became nameable, but because
    # nothing on the printing path re-asked.  Ruling 2.2 closed that for the
    # `fixture` class; it is closed here for the class itself, at the
    # predicate, so the answer no longer depends on which reader ran.
    #
    # ABSENCE withholds by the same reading: a summary that names no class
    # cannot name its attempt either.  Two shapes are exempt, and they are the
    # exact two `load_bound_test_quality` already routes around
    # `_validate_native_summary`'s flat v2 identity comparison, because each
    # names the class elsewhere and re-derives it on every single load:
    #   * the authenticated legacy-rebinding wrapper.  `_build_legacy_wrapper`
    #     emits no `generation_provenance_class` at all (legacy rows carry no
    #     attempt stamp); its route is `legacy_exact_bytes`, which the owner
    #     ruled publishable.  Keyed on the private in-memory type the basis
    #     conjunct above already computed -- never on a persisted token, which
    #     a hand-written wrapper could spell for itself.
    #   * a Slice-3 join summary.  Its class lives in the preserved run-1
    #     mutation provenance, where `slice3_test_quality.build_summary` calls
    #     `refuse_unpublishable_generation` on it, and `validate_summary`
    #     re-runs that entire derivation on every read.  Stamping the class
    #     into the body instead is not available: `validate_summary` compares
    #     the whole re-derived body and would refuse the extra field.
    klass = summary.get("generation_provenance_class")
    if klass is None:
        from .slice3_test_quality import JOIN_KEY as _SLICE3_JOIN_KEY
        if not authenticated_legacy_shape and _SLICE3_JOIN_KEY not in summary:
            reasons.append(
                "the candidate's generation provenance class is absent, "
                "which cannot name the attempt that produced it")
    else:
        from .mutation_run import GENERATION_PROVENANCE_PUBLISHABLE
        if klass not in GENERATION_PROVENANCE_PUBLISHABLE:
            reasons.append(
                f"the candidate's generation provenance class is `{klass}`, "
                "which cannot name the attempt that produced it")
    if summary.get("require_complete") is not True:
        reasons.append(
            "the campaign was scored with --allow-incomplete, so this is an "
            "explicitly labelled sensitivity analysis, not a primary")
    if summary.get("completeness_checked") is not True:
        reasons.append(
            "completeness was never checked, so the pair set behind the "
            "number is unverified")
    missing = summary.get("gold_rows_missing")
    if missing is None or missing != 0:
        reasons.append(
            f"{missing} gold row(s) are missing, which shrinks the very set "
            f"the candidate is measured against")
    count = summary.get("gold_infrastructure_outcomes")
    if count is None:
        reasons.append(
            "the summary predates the gold-degradation counter, so whether "
            "the harness failed on any scored pair is unknown")
    elif count:
        pairs = summary.get("gold_infrastructure_pairs")
        if summary.get("allow_degraded_gold") is not True:
            reasons.append(
                f"gold carries {count} infrastructure outcome(s) and no "
                f"explicit --allow-degraded-gold consent is recorded (owner "
                f"ruling 2.6)")
        elif not isinstance(pairs, list) or len(pairs) != count:
            reasons.append(
                f"gold carries {count} infrastructure outcome(s) and the "
                f"per-item disclosure ruling 2.6 requires is absent or does "
                f"not match the count")
    return (not reasons), reasons


def _candidate_kills(rows: Iterable[dict]) -> dict:
    """`{item: set(mutant_ids the candidate killed)}`, gold's set aside.

    Needed for the mutants gold does NOT kill: `recall`'s denominator is
    gold's set, so a candidate kill outside it cannot raise the recall — but
    reporting it is the only way a reader can see that the gold kill set is
    incomplete rather than that the item is untestable.
    """
    out: dict = {}
    for row in rows:
        # Every item scored here passed its own baseline, so the timeout rule
        # in `classify_outcome` resolves the same way it does in `recall`.
        if classify_outcome("passed", row["outcome"]) == "kill":
            out.setdefault(row["item_id"], set()).add(row["mutant_id"])
    return out


def jaccard_for(killed: int, denominator: int,
                candidate_only: int) -> Optional[float]:
    """|C n G| / |C u G| from the three counts `score` already records.

    `killed` is |C n G| (gold's mutants the candidate also killed),
    `denominator` is |G| as actually scored, and `candidate_only` is |C \\ G|
    (kills outside gold's set), so |C u G| = denominator + candidate_only.

    **Why this exists beside the recall.**  Recall's denominator is gold's set
    alone, so a kill the candidate makes and gold does not cannot move it: a
    candidate that kills everything gold kills scores 1.000 whether it detects
    exactly gold's mutants or gold's mutants plus fifty others.  Those are not
    the same test.  The Jaccard puts the candidate-only kills in the
    denominator, so the pair separates "as strong as the reference" from
    "different from the reference"; the module already RECORDS
    `candidate_only_kills` for precisely this reason and, until now, nothing
    consumed it.  Neither number replaces the other and both are reported.

    UNDEFINED, not 0.0, when gold killed nothing that survived the
    eligibility rule.  Such an item is `not_scorable`: the mutants covering it
    are equivalent as far as this benchmark can observe, so the item carries
    no information about the candidate.  Returning 0/candidate_only there --
    which is what the arithmetic would do for a candidate that killed
    something on an item gold cannot score -- would punish a candidate for
    detecting MORE than the reference on exactly the items where the reference
    detects nothing.
    """
    if denominator <= 0:
        return None
    return killed / (denominator + candidate_only)


def verdict_for(n_gold_killed: int, item_recall: Optional[float]) -> str:
    """The four-way verdict, from gold's kill count and the item's recall."""
    if n_gold_killed == 0 or item_recall is None:
        return NOT_SCORABLE
    if item_recall >= 1.0:
        return EQUIVALENT
    if item_recall <= 0.0:
        return VACUOUS
    return WEAKER


def hard_kill_sets(doc: dict, *, population_id: Optional[str] = None,
                   items: Optional[Iterable[str]] = None,
                   manifest_digest: Optional[str] = None) \
        -> dict[str, set[str]]:
    """Validated artifact ``by_item`` as sets, optionally item-restricted."""
    from ..toolkit.hard_subset import HardSubsetRefused, validate
    try:
        validate(doc, expected_population_id=population_id)
    except HardSubsetRefused as exc:
        raise TestQualityRefused(str(exc)) from exc
    artifact_manifest = doc.get("population", {}).get("manifest_digest")
    if manifest_digest is not None and artifact_manifest != manifest_digest:
        raise TestQualityRefused(
            "REFUSED: hard subset and scored mutation campaign name different "
            f"manifest digests ({artifact_manifest!r} != "
            f"{manifest_digest!r}). A shared population_id cannot substitute "
            "catalogue evidence for the exact boundary-scored population.")
    wanted = None if items is None else set(items)
    return {
        item_id: set(mutants)
        for item_id, mutants in doc["hard_subset"]["by_item"].items()
        if wanted is None or item_id in wanted
    }


def _hard_rerun_observation_id(campaign: dict, claimed=None) -> str:
    """Return and, when supplied, match D4 run 2's producer-minted identity.

    ``validate_native_shards`` has already checked the standalone ownership
    plan, terminal shard bytes and each sidecar's observation metadata.  This
    final small binding prevents a saved test-quality summary from replacing
    that validated 32-hex identity with a copied or post-hoc value.
    """
    identity = campaign.get("campaign_identity") \
        if isinstance(campaign, dict) else None
    if not isinstance(identity, dict) or identity.get("kind") != "mutation-run":
        raise TestQualityRefused(
            "REFUSED: candidate hard run 2 is not a standalone native "
            "mutation observation.")
    from .mutation_run import MutationAborted, validate_observation_id
    try:
        actual = validate_observation_id(campaign.get("observation_id"))
    except MutationAborted as exc:
        raise TestQualityRefused(str(exc)) from exc
    if claimed is not None and claimed != actual:
        raise TestQualityRefused(
            "REFUSED: candidate hard run 2 observation metadata differs from "
            f"the standalone ownership record ({claimed!r} != {actual!r}).")
    return actual


def _candidate_n2_intersection(candidate_rows_1: list,
                               candidate_rows_2: list,
                               hard_pairs: set[tuple[str, str]]) \
        -> tuple[list[dict], list[str]]:
    """Exact two-run intersection retained for corpus anti-vacuity evidence.

    The corpus gold/stub control deliberately executes its complete declared
    pair population twice.  Per-candidate D4 headline scoring uses the separate
    selective helper below; keeping these contracts separate prevents the
    boundary-only optimization from rewriting the already versioned /3 corpus
    evidence schema.
    """
    if candidate_rows_2 is None:
        raise TestQualityRefused(
            "REFUSED: exact N=2 evidence requires candidate run 2.")

    def rows_by_pair(rows: Iterable[dict], label: str) -> dict:
        out = {}
        for number, row in enumerate(rows or [], 1):
            if not isinstance(row, dict):
                raise TestQualityRefused(
                    f"REFUSED: malformed {label} row {number}: {row!r}.")
            pair = (row.get("item_id"), row.get("mutant_id"))
            if pair in out:
                raise TestQualityRefused(
                    f"REFUSED: {label} repeats candidate pair {pair!r}.")
            if not all(isinstance(value, str) and value for value in pair) \
                    or not isinstance(row.get("outcome"), str):
                raise TestQualityRefused(
                    f"REFUSED: malformed {label} row {number}: {row!r}.")
            try:
                classify_outcome("passed", row["outcome"])
            except ValueError as exc:
                raise TestQualityRefused(str(exc)) from exc
            out[pair] = row["outcome"]
        return out

    observations = (
        rows_by_pair(candidate_rows_1, "candidate run 1"),
        rows_by_pair(candidate_rows_2, "candidate run 2"),
    )
    for number, values in enumerate(observations, 1):
        missing = sorted(hard_pairs - set(values))
        if missing:
            raise TestQualityRefused(
                f"REFUSED: exact N=2 candidate run {number} is missing "
                f"{len(missing)} required pair(s).")
    synthetic = []
    knife = set()
    for pair in sorted(hard_pairs):
        killed = [values[pair] == "failed" for values in observations]
        if killed[0] != killed[1]:
            knife.add(pair[0])
        synthetic.append({
            "item_id": pair[0], "mutant_id": pair[1],
            "outcome": "failed" if all(killed) else "passed",
        })
    return synthetic, sorted(knife)


def _candidate_outcomes_by_pair(rows: Iterable[dict], label: str) -> dict:
    """Validate one mutation observation without last-row-wins semantics."""
    out = {}
    for number, row in enumerate(rows or [], 1):
        if not isinstance(row, dict):
            raise TestQualityRefused(
                f"REFUSED: malformed {label} row {number}: {row!r}.")
        pair = (row.get("item_id"), row.get("mutant_id"))
        if pair in out:
            raise TestQualityRefused(
                f"REFUSED: {label} repeats candidate pair {pair!r}.")
        if not all(isinstance(value, str) and value for value in pair) \
                or not isinstance(row.get("outcome"), str):
            raise TestQualityRefused(
                f"REFUSED: malformed {label} row {number}: {row!r}.")
        try:
            classify_outcome("passed", row["outcome"])
        except ValueError as exc:
            raise TestQualityRefused(str(exc)) from exc
        out[pair] = row["outcome"]
    return out


def _candidate_hard_qualification(
        candidate_rows_1: list, hard_by_item: dict[str, set[str]]) \
        -> tuple[dict, set[tuple[str, str]], list[str],
                 set[tuple[str, str]]]:
    """Authenticate run 1 and derive D4's exact whole-item run-2 set."""
    hard_pairs = {
        (item_id, mutant_id)
        for item_id, mutants in hard_by_item.items()
        for mutant_id in mutants
    }
    run_1 = _candidate_outcomes_by_pair(
        candidate_rows_1, "candidate run 1")
    missing_run_1 = sorted(hard_pairs - set(run_1))
    if missing_run_1:
        raise TestQualityRefused(
            f"REFUSED: candidate run 1 is missing {len(missing_run_1)} hard "
            f"pair(s), e.g. {missing_run_1[:3]}; D4 qualification requires "
            "one complete first observation of every hard set.")

    qualifying_items = sorted(
        item_id for item_id, mutants in hard_by_item.items()
        if mutants and all(run_1[(item_id, mutant_id)] == "failed"
                           for mutant_id in mutants))
    qualifying_pairs = {
        (item_id, mutant_id)
        for item_id in qualifying_items
        for mutant_id in hard_by_item[item_id]
    }
    return run_1, hard_pairs, qualifying_items, qualifying_pairs


def _candidate_selective_hard_confirmation(
        candidate_rows_1: list, candidate_rows_2: Optional[list],
        hard_by_item: dict[str, set[str]]) -> tuple[list[dict], dict]:
    """Apply D4's whole-item, boundary-only confirmation rule.

    Run 1 must contain every hard pair.  An item qualifies for run 2 only when
    its hard set is nonempty and *every* run-1 outcome on that set is literally
    ``failed``.  Run 2 is then exactly the union of those qualifiers' complete
    hard sets -- not every hard pair and not a favorable/disputed subset.

    The final hard kill set uses literal-failed intersection for qualifiers.
    Nonqualifiers are deliberately not rerun and retain run 1's literal-failed
    kills.  Consequently timeouts and infrastructure labels are conservative
    non-kills at this headline boundary even where ordinary full-gold recall
    classifies a conditional timeout as a kill.
    """
    run_1, hard_pairs, qualifying_items, qualifying_pairs = \
        _candidate_hard_qualification(candidate_rows_1, hard_by_item)

    run_2 = None
    if candidate_rows_2 is None:
        if qualifying_pairs:
            raise TestQualityRefused(
                "REFUSED: candidate run 1 produced "
                f"{len(qualifying_items)} D4 qualifying item(s) / "
                f"{len(qualifying_pairs)} hard pair(s), but candidate run 2 "
                "is absent. Every initially hard-recall-1.0 item requires one "
                "complete independent confirmation.")
    else:
        run_2 = _candidate_outcomes_by_pair(
            candidate_rows_2, "candidate run 2")
        actual_run_2 = set(run_2)
        missing_run_2 = sorted(qualifying_pairs - actual_run_2)
        extra_run_2 = sorted(actual_run_2 - qualifying_pairs)
        if missing_run_2 or extra_run_2:
            raise TestQualityRefused(
                "REFUSED: candidate run 2 is not the exact union of complete "
                "hard sets for run-1 qualifiers: "
                f"{len(missing_run_2)} missing and {len(extra_run_2)} extra "
                f"pair(s); missing e.g. {missing_run_2[:3]}, extra e.g. "
                f"{extra_run_2[:3]}.")

    run_1_failed = {pair for pair in hard_pairs if run_1[pair] == "failed"}
    run_2_failed = ({pair for pair in qualifying_pairs
                     if run_2[pair] == "failed"}
                    if run_2 is not None else set())
    final_failed = (run_1_failed - qualifying_pairs) \
        | (run_1_failed & run_2_failed)
    union_failed = run_1_failed | run_2_failed
    flip_pairs = sorted(
        pair for pair in qualifying_pairs
        if (run_1[pair] == "failed") != (run_2[pair] == "failed"))

    synthetic = [
        {"item_id": item_id, "mutant_id": mutant_id,
         "outcome": ("failed" if (item_id, mutant_id) in final_failed
                     else "passed")}
        for item_id, mutant_id in sorted(hard_pairs)
    ]
    details = {
        "candidate_hard_runs": 2 if qualifying_pairs else 1,
        "hard_confirmation_run_2_required": bool(qualifying_pairs),
        "hard_confirmation_qualifying_items": qualifying_items,
        "hard_confirmation_pairs": len(qualifying_pairs),
        "hard_run_1_literal_failed_pairs": len(run_1_failed),
        "hard_run_2_literal_failed_pairs": (
            len(run_2_failed) if qualifying_pairs else None),
        "hard_union_literal_failed_pairs": len(union_failed),
        "hard_final_literal_failed_pairs": len(final_failed),
        "hard_flip_pairs": [
            {"item_id": item_id, "mutant_id": mutant_id}
            for item_id, mutant_id in flip_pairs
        ],
        "knife_edge_items": sorted({item_id for item_id, _ in flip_pairs}),
    }
    return synthetic, details


_D4_PLAN_FIELDS = frozenset({
    "schema", "method", "source", "candidate", "assets", "hard_subset",
    "qualification", "digest",
})
_D4_SOURCE_FIELDS = frozenset({
    "campaign_dir", "campaign_plan_sha256", "candidate_shards",
    "expected_pairs", "expected_pairs_sha256", "timeout_seconds",
    "observation_id",
})
_D4_SHARD_FIELDS = frozenset({
    "path", "rows_sha256", "sidecar_sha256",
    "campaign_identity_sha256",
})
_D4_CANDIDATE_FIELDS = frozenset({
    "run", "run_sha256", "generated_tests_sha256",
})
_D4_ASSET_FIELDS = frozenset({
    "mutation_validation", "mutation_validation_sha256",
    "mutation_validation_class", "asset_index_sha256", "asset_project",
    "manifest", "manifest_sha256", "manifest_digest", "map", "map_sha256",
    "release", "release_sha256", "population_id", "engine",
    "engine_version", "parser",
})
_D4_HARD_FIELDS = frozenset({
    "path", "sha256", "digest", "population_id", "pairs",
    "pairs_sha256",
})
_D4_QUALIFICATION_FIELDS = frozenset({
    "items", "pairs", "expected_pairs", "expected_pairs_sha256",
})
_D4_PAIR_FIELDS = frozenset({"item_id", "mutant_id"})


def _d4_exact(value, fields: frozenset[str], label: str) -> None:
    if type(value) is not dict or set(value) != fields:
        got = sorted(repr(key) for key in value) if type(value) is dict \
            else type(value).__name__
        raise TestQualityRefused(
            f"REFUSED: {label} must contain exactly {sorted(fields)}; got "
            f"{got}.")


def _d4_json_bytes(value, label: str) -> bytes:
    """Canonical JSON bytes whose spelling preserves scalar JSON types."""
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TestQualityRefused(
            f"REFUSED: {label} is not canonical JSON: {exc}.") from exc


def _d4_json_equal(left, right) -> bool:
    """Unlike Python equality, keep ``5``, ``5.0`` and ``true`` distinct."""
    return _d4_json_bytes(left, "D4 actual value") \
        == _d4_json_bytes(right, "D4 expected value")


def _d4_changed_fields(actual: dict, expected: dict) -> list[str]:
    return sorted(
        key for key in set(actual) | set(expected)
        if key not in actual or key not in expected
        or not _d4_json_equal(actual[key], expected[key]))


def _d4_require_string(value, label: str) -> str:
    if type(value) is not str or not value:
        raise TestQualityRefused(
            f"REFUSED: {label} must be a nonempty JSON string.")
    return value


def _d4_require_sha256(value, label: str) -> str:
    if type(value) is not str or not _is_sha256(value):
        raise TestQualityRefused(
            f"REFUSED: {label} must be exactly 64 lowercase hex characters.")
    return value


def _d4_require_path(value, label: str) -> str:
    path = _d4_require_string(value, label)
    if not os.path.isabs(path) or os.path.abspath(path) != path:
        raise TestQualityRefused(
            f"REFUSED: {label} must be a normalized absolute path.")
    return path


def _d4_require_int(value, label: str, *, minimum: int) -> int:
    # `bool` is an `int` subclass and `5.0 == 5` under Python equality.  A
    # saved execution plan admits neither representation: canonical JSON
    # types are part of the authenticated contract.
    if type(value) is not int or value < minimum:
        raise TestQualityRefused(
            f"REFUSED: {label} must be a JSON integer >= {minimum}; floats "
            "and booleans are not counts or timeouts.")
    return value


def _d4_pair_rows(pairs: Iterable[tuple[str, str]]) -> list[dict]:
    return [{"item_id": item_id, "mutant_id": mutant_id}
            for item_id, mutant_id in sorted(set(pairs))]


def _d4_pairs_from_rows(rows, label: str) -> set[tuple[str, str]]:
    if type(rows) is not list:
        raise TestQualityRefused(f"REFUSED: {label} is not a list.")
    out = set()
    for number, row in enumerate(rows, 1):
        _d4_exact(row, _D4_PAIR_FIELDS, f"{label} row {number}")
        pair = (row.get("item_id"), row.get("mutant_id"))
        if not all(type(value) is str and value and "\0" not in value
                   for value in pair):
            raise TestQualityRefused(
                f"REFUSED: {label} row {number} has an invalid "
                "item/mutant id.")
        if pair in out:
            raise TestQualityRefused(
                f"REFUSED: {label} repeats pair {pair!r}.")
        out.add(pair)
    if rows != _d4_pair_rows(out):
        raise TestQualityRefused(
            f"REFUSED: {label} is not in canonical pair order.")
    return out


def _d4_run_1_observation_id(campaign_plan: dict) -> str:
    """Domain-separate run 1's producer-owned root plan into a 128-bit id."""
    from .mutation_run import (MutationAborted, content_digest,
                               validate_observation_id)
    plan_sha256 = content_digest(campaign_plan)
    digest = hashlib.sha256()
    digest.update(b"r2t-d4-run-1-observation/1\0")
    digest.update(bytes.fromhex(plan_sha256))
    observation_id = digest.hexdigest()[:32]
    try:
        return validate_observation_id(observation_id)
    except MutationAborted as exc:                         # pragma: no cover
        raise TestQualityRefused(str(exc)) from exc


def build_d4_confirmation_plan(*, campaign_plan: dict, out_dir: str,
                               candidate_jobs: Iterable[dict],
                               candidate_rows: list,
                               expected: Iterable[tuple[str, str]],
                               hard_sets: dict[str, set[str]],
                               hard_subset_doc: dict,
                               hard_subset_path: str,
                               identity_inputs: dict,
                               run_path: str, timeout: int,
                               population_id: str) -> dict:
    """Build the authenticated pair plan that bridges D4 run 1 and run 2.

    Run 1 remains a subordinate, complete test-quality observation.  The plan
    pins that root campaign and every candidate shard byte, the exact hard
    artifact, the unchanged candidate/generated-test and mutation-asset
    identities, and the qualification-derived pair set.  It is an execution
    input, never a substitute for the source evidence it names.
    """
    from .mutation_run import (campaign_identity_digest, content_digest,
                               pair_set_digest, provenance_path, sha256_file)
    _d4_require_int(timeout, "D4 timeout_seconds", minimum=1)
    expected_set = set(expected)
    _run_1, hard_pairs, qualifying_items, qualifying_pairs = \
        _candidate_hard_qualification(candidate_rows, hard_sets)
    outside = sorted(hard_pairs - expected_set)
    if outside:
        raise TestQualityRefused(
            f"REFUSED: D4 hard pairs fall outside run 1, e.g. {outside[:3]}.")
    shards = []
    for job in sorted(candidate_jobs, key=lambda value: value["worker"]):
        path = os.path.abspath(job["out"])
        shards.append({
            "path": path,
            "rows_sha256": sha256_file(path),
            "sidecar_sha256": sha256_file(provenance_path(path)),
            "campaign_identity_sha256": campaign_identity_digest(
                job["identity"]),
        })
    if not shards:
        raise TestQualityRefused(
            "REFUSED: D4 run 1 has no candidate mutation shards.")
    assets = {
        "mutation_validation": os.path.abspath(
            identity_inputs["mutation_validation"]),
        "mutation_validation_sha256": identity_inputs[
            "mutation_validation_sha256"],
        "mutation_validation_class": identity_inputs[
            "mutation_validation_class"],
        "asset_index_sha256": identity_inputs["asset_index_sha256"],
        "asset_project": identity_inputs["asset_project"],
        "manifest": os.path.abspath(identity_inputs["manifest"]),
        "manifest_sha256": identity_inputs["manifest_sha256"],
        "manifest_digest": identity_inputs["manifest_digest"],
        "map": os.path.abspath(identity_inputs["map"]),
        "map_sha256": identity_inputs["map_sha256"],
        "release": os.path.abspath(identity_inputs["release"]),
        "release_sha256": identity_inputs["release_sha256"],
        "population_id": population_id,
        "engine": identity_inputs["engine"],
        "engine_version": identity_inputs["engine_version"],
        "parser": identity_inputs["parser"],
    }
    doc = {
        "schema": D4_CONFIRMATION_PLAN_SCHEMA,
        "method": D4_CONFIRMATION_METHOD,
        "source": {
            "campaign_dir": os.path.abspath(out_dir),
            "campaign_plan_sha256": content_digest(campaign_plan),
            "observation_id": _d4_run_1_observation_id(campaign_plan),
            "candidate_shards": shards,
            "expected_pairs": len(expected_set),
            "expected_pairs_sha256": pair_set_digest(expected_set),
            "timeout_seconds": timeout,
        },
        "candidate": {
            "run": os.path.abspath(run_path),
            "run_sha256": identity_inputs["candidate_run_sha256"],
            "generated_tests_sha256": identity_inputs[
                "candidate_generated_tests_sha256"],
        },
        "assets": assets,
        "hard_subset": {
            "path": os.path.abspath(hard_subset_path),
            "sha256": sha256_file(hard_subset_path),
            "digest": hard_subset_doc["digest"],
            "population_id": population_id,
            "pairs": len(hard_pairs),
            "pairs_sha256": pair_set_digest(hard_pairs),
        },
        "qualification": {
            "items": qualifying_items,
            "pairs": _d4_pair_rows(qualifying_pairs),
            "expected_pairs": len(qualifying_pairs),
            "expected_pairs_sha256": pair_set_digest(qualifying_pairs),
        },
    }
    doc["digest"] = content_digest(doc)
    return doc


def validate_d4_confirmation_plan_document(doc: dict) -> dict:
    """Validate the closed, self-digesting D4 plan representation."""
    from .mutation_run import content_digest, pair_set_digest
    _d4_exact(doc, _D4_PLAN_FIELDS, "D4 confirmation plan")
    _d4_require_string(doc["schema"], "D4 schema")
    _d4_require_string(doc["method"], "D4 method")
    _d4_require_sha256(doc["digest"], "D4 plan digest")
    if doc["schema"] != D4_CONFIRMATION_PLAN_SCHEMA \
            or doc["method"] != D4_CONFIRMATION_METHOD:
        raise TestQualityRefused(
            "REFUSED: unsupported D4 confirmation plan schema or method.")
    _d4_exact(doc["source"], _D4_SOURCE_FIELDS, "D4 source")
    _d4_exact(doc["candidate"], _D4_CANDIDATE_FIELDS, "D4 candidate")
    _d4_exact(doc["assets"], _D4_ASSET_FIELDS, "D4 assets")
    _d4_exact(doc["hard_subset"], _D4_HARD_FIELDS, "D4 hard subset")
    _d4_exact(doc["qualification"], _D4_QUALIFICATION_FIELDS,
              "D4 qualification")

    source = doc["source"]
    _d4_require_path(source["campaign_dir"], "D4 source campaign_dir")
    _d4_require_sha256(source["campaign_plan_sha256"],
                       "D4 source campaign_plan_sha256")
    from .mutation_run import MutationAborted, validate_observation_id
    try:
        validate_observation_id(source["observation_id"])
    except MutationAborted as exc:
        raise TestQualityRefused(str(exc)) from exc
    _d4_require_int(source["expected_pairs"],
                    "D4 source expected_pairs", minimum=1)
    _d4_require_sha256(source["expected_pairs_sha256"],
                       "D4 source expected_pairs_sha256")
    _d4_require_int(source["timeout_seconds"],
                    "D4 source timeout_seconds", minimum=1)
    shards = source["candidate_shards"]
    if type(shards) is not list or not shards:
        raise TestQualityRefused(
            "REFUSED: D4 plan has no run-1 candidate shards.")
    shard_paths = set()
    for number, shard in enumerate(shards, 1):
        _d4_exact(shard, _D4_SHARD_FIELDS,
                  f"D4 candidate shard {number}")
        path = _d4_require_path(
            shard["path"], f"D4 candidate shard {number} path")
        if path in shard_paths:
            raise TestQualityRefused(
                f"REFUSED: D4 candidate shard path {path!r} is repeated.")
        shard_paths.add(path)
        for field in ("rows_sha256", "sidecar_sha256",
                      "campaign_identity_sha256"):
            _d4_require_sha256(
                shard[field], f"D4 candidate shard {number} {field}")

    candidate = doc["candidate"]
    _d4_require_path(candidate["run"], "D4 candidate run")
    _d4_require_sha256(candidate["run_sha256"],
                       "D4 candidate run_sha256")
    _d4_require_sha256(candidate["generated_tests_sha256"],
                       "D4 candidate generated_tests_sha256")

    assets = doc["assets"]
    for field in ("mutation_validation", "manifest", "map", "release"):
        _d4_require_path(assets[field], f"D4 assets {field}")
    for field in ("mutation_validation_sha256", "asset_index_sha256",
                  "manifest_sha256", "manifest_digest", "map_sha256",
                  "release_sha256"):
        _d4_require_sha256(assets[field], f"D4 assets {field}")
    for field in ("mutation_validation_class", "asset_project",
                  "population_id", "engine", "engine_version", "parser"):
        _d4_require_string(assets[field], f"D4 assets {field}")

    hard = doc["hard_subset"]
    _d4_require_path(hard["path"], "D4 hard subset path")
    for field in ("sha256", "digest", "pairs_sha256"):
        _d4_require_sha256(hard[field], f"D4 hard subset {field}")
    _d4_require_string(hard["population_id"],
                       "D4 hard subset population_id")
    _d4_require_int(hard["pairs"], "D4 hard subset pairs", minimum=1)
    if hard["population_id"] != assets["population_id"]:
        raise TestQualityRefused(
            "REFUSED: D4 hard subset and assets name different populations.")

    qualification = doc["qualification"]
    _d4_require_int(qualification["expected_pairs"],
                    "D4 qualification expected_pairs", minimum=1)
    _d4_require_sha256(qualification["expected_pairs_sha256"],
                       "D4 qualification expected_pairs_sha256")
    pairs = _d4_pairs_from_rows(
        qualification["pairs"], "D4 qualification pairs")
    if qualification["expected_pairs"] != len(pairs) \
            or qualification["expected_pairs_sha256"] \
            != pair_set_digest(pairs):
        raise TestQualityRefused(
            "REFUSED: D4 plan pair count/digest differs from its exact list.")
    items = qualification["items"]
    malformed_items = type(items) is not list or (
        type(items) is list
        and any(type(item) is not str or not item or "\0" in item
                for item in items))
    if malformed_items or items != sorted(set(items)) \
            or {item_id for item_id, _mutant_id in pairs} != set(items):
        raise TestQualityRefused(
            "REFUSED: D4 qualifying items differ from its exact pair list.")
    if qualification["expected_pairs"] > hard["pairs"] \
            or hard["pairs"] > source["expected_pairs"]:
        raise TestQualityRefused(
            "REFUSED: D4 qualification/hard/source pair counts are not "
            "nested populations.")
    if doc["digest"] != content_digest(
            {key: value for key, value in doc.items() if key != "digest"}):
        raise TestQualityRefused(
            "REFUSED: D4 confirmation plan digest does not match its content.")
    return doc


def write_d4_confirmation_plan(path: str, doc: dict) -> str:
    """Write a new plan outside its source campaign directory."""
    from .mutation_run import MutationAborted, atomic_write_json
    validate_d4_confirmation_plan_document(doc)
    source_dir = os.path.realpath(doc["source"]["campaign_dir"])
    target = os.path.realpath(os.path.abspath(path))
    try:
        inside = os.path.commonpath((source_dir, target)) == source_dir
    except ValueError:
        inside = False
    if inside:
        raise TestQualityRefused(
            "REFUSED: D4 pair plan must be outside the resumable run-1 "
            "campaign directory.")
    try:
        atomic_write_json(path, doc, refuse_existing=True)
    except MutationAborted as exc:
        raise TestQualityRefused(str(exc)) from exc
    return os.path.abspath(path)


def _load_d4_confirmation_plan(path: str) -> dict:
    if os.path.islink(path) or not os.path.isfile(path):
        raise TestQualityRefused(
            f"REFUSED: D4 confirmation plan is not a regular file: {path}.")
    return validate_d4_confirmation_plan_document(
        _load_json_object(path, "D4 confirmation plan"))


def _pending_root_rows(campaign_dir: str, campaign_plan: dict,
                       expected: set[tuple[str, str]]) \
        -> tuple[list[dict], list[dict]]:
    """Authenticate the complete pending root and return candidate rows/jobs."""
    from .mutation_run import (MutationAborted, campaign_identity_digest,
                               completed_pairs, provenance_path)
    policy = shard_policy_from_plan(campaign_plan)
    _admitted_policy_identity_binding(campaign_plan.get("jobs") or [], policy)
    jobs = campaign_plan["jobs"]
    wanted_root = {SHARD_DIR, CAMPAIGN_STATE}
    actual_root = set(os.listdir(campaign_dir))
    if actual_root != wanted_root:
        raise TestQualityRefused(
            "REFUSED: pending D4 run-1 campaign has missing or unexpected "
            f"root artifacts: {sorted(actual_root ^ wanted_root)}.")
    shard_dir = os.path.join(campaign_dir, SHARD_DIR)
    allowed = set()
    rows_by_side: dict[str, list[dict]] = {}
    pairs_by_side: dict[str, set[tuple[str, str]]] = {}
    candidate_jobs = []
    for record in jobs:
        rel = record.get("out")
        if not isinstance(rel, str) \
                or rel != os.path.join(SHARD_DIR, os.path.basename(rel)):
            raise TestQualityRefused(
                "REFUSED: pending D4 root plan has a noncanonical shard path.")
        path = os.path.join(campaign_dir, rel)
        side_path = provenance_path(path)
        allowed.update((os.path.basename(path), os.path.basename(side_path)))
        identity = record.get("campaign_identity") or {}
        if record.get("mutation_campaign_digest") \
                != campaign_identity_digest(identity):
            raise TestQualityRefused(
                "REFUSED: pending D4 root job digest does not hash its "
                "campaign identity.")
        rows = load_jsonl(path)
        outcomes = _candidate_outcomes_by_pair(
            rows, f"pending {record.get('side')} run-1 shard")
        pairs = set(outcomes)
        try:
            completed_pairs(
                path, identity, expected_pairs=pairs, require_complete=True,
                expected_shard_policy=policy,
                allow_missing_shard_policy=(
                    policy == SHARD_POLICY_STRIDED_V1))
        except MutationAborted as exc:
            raise TestQualityRefused(str(exc)) from exc
        side = record.get("side")
        overlap = pairs_by_side.setdefault(side, set()) & pairs
        if overlap:
            raise TestQualityRefused(
                f"REFUSED: pending D4 {side} shards overlap on "
                f"{sorted(overlap)[:3]}.")
        pairs_by_side[side] |= pairs
        rows_by_side.setdefault(side, []).extend(rows)
        if side == "candidate":
            candidate_jobs.append({"worker": record["worker"], "out": path,
                                   "identity": identity})
    if not os.path.isdir(shard_dir) or set(os.listdir(shard_dir)) != allowed:
        raise TestQualityRefused(
            "REFUSED: pending D4 shard directory differs from its exact root "
            "plan.")
    if pairs_by_side.get("candidate") != expected:
        got = pairs_by_side.get("candidate", set())
        raise TestQualityRefused(
            "REFUSED: pending D4 candidate run 1 is not the complete mapped "
            f"population: {len(expected-got)} missing and "
            f"{len(got-expected)} unexpected pair(s).")
    return rows_by_side.get("candidate", []), candidate_jobs


def validate_d4_confirmation_plan(
        path: str, *, run1_campaign: str, hard_subset_path: str,
        candidate_run_path: str, assets: dict, validation_path: str,
        manifest_path: str, map_path: str, release_path: str) -> dict:
    """Re-derive a saved plan from its live run-1 and hard-subset evidence."""
    from ..toolkit.hard_subset import HardSubsetRefused, load as load_hard_subset
    from .mutation_run import (MutationAborted, candidate_digest,
                               campaign_identity_digest, content_digest,
                               pair_set_digest, provenance_path, sha256_file,
                               validate_campaign_asset_claims)
    doc = _load_d4_confirmation_plan(path)
    campaign_dir = os.path.abspath(run1_campaign)
    hard_path = os.path.abspath(hard_subset_path)
    run_path = os.path.abspath(candidate_run_path)
    if doc["source"]["campaign_dir"] != campaign_dir \
            or doc["hard_subset"]["path"] != hard_path \
            or doc["candidate"]["run"] != run_path:
        raise TestQualityRefused(
            "REFUSED: D4 plan names a different run-1 campaign, hard subset, "
            "or candidate run than the operator supplied.")
    supplied_paths = {
        "mutation_validation": os.path.abspath(validation_path),
        "manifest": os.path.abspath(manifest_path),
        "map": os.path.abspath(map_path),
        "release": os.path.abspath(release_path),
    }
    if any(doc["assets"].get(key) != value
           for key, value in supplied_paths.items()):
        raise TestQualityRefused(
            "REFUSED: D4 plan names different frozen mutation asset paths.")
    manifest = assets.get("manifest") if isinstance(assets, dict) else None
    by_mutant = (assets.get("map") or {}).get("by_mutant") \
        if isinstance(assets, dict) else None
    if not isinstance(manifest, dict) or not isinstance(by_mutant, dict):
        raise TestQualityRefused(
            "REFUSED: D4 plan validation has no release-ready manifest/map.")
    population_id = registered_population_id(
        assets.get("asset_project"), manifest.get("digest"),
        manifest.get("engine"), manifest.get("engine_version"))
    if population_id is None:
        raise TestQualityRefused(
            "REFUSED: D4 plan requires a registered mutation population.")
    current_assets = {
        **supplied_paths,
        "mutation_validation_sha256": sha256_file(validation_path),
        "mutation_validation_class": assets.get("validation_class"),
        "asset_index_sha256": assets.get("asset_index_sha256"),
        "asset_project": assets.get("asset_project"),
        "manifest_sha256": sha256_file(manifest_path),
        "manifest_digest": manifest.get("digest"),
        "map_sha256": sha256_file(map_path),
        "release_sha256": sha256_file(release_path),
        "population_id": population_id,
        "engine": manifest.get("engine"),
        "engine_version": manifest.get("engine_version"),
        "parser": manifest.get("parser"),
    }
    changed_assets = _d4_changed_fields(doc["assets"], current_assets)
    if changed_assets:
        raise TestQualityRefused(
            "REFUSED: D4 plan is stale for frozen mutation asset field(s) "
            f"{changed_assets}.")
    run_rows = load_jsonl(run_path)
    passed = passed_solutions(run_rows)
    current_candidate = {
        "run": run_path,
        "run_sha256": sha256_file(run_path),
        "generated_tests_sha256": candidate_digest(passed),
    }
    if not _d4_json_equal(doc["candidate"], current_candidate):
        raise TestQualityRefused(
            "REFUSED: D4 plan is stale for the candidate run or generated "
            "test bytes.")
    mutants, restricted, _covering = population(manifest, by_mutant, passed)
    expected = expected_pairs(restricted)
    state = _load_json_object(
        _campaign_state_path(campaign_dir), "pending D4 root campaign")
    campaign_plan = state.get("plan") if isinstance(state, dict) else None
    _validate_campaign_state(state, campaign_plan)
    if state.get("status") != "running" or state.get("artifacts"):
        raise TestQualityRefused(
            "REFUSED: D4 run-1 root is not the resumable pending campaign.")
    if doc["source"]["campaign_plan_sha256"] \
            != content_digest(campaign_plan):
        raise TestQualityRefused(
            "REFUSED: D4 plan is stale for the run-1 root campaign plan.")
    candidate_rows, candidate_jobs = _pending_root_rows(
        campaign_dir, campaign_plan, expected)
    source_shards = []
    candidate_identities = []
    for job in sorted(candidate_jobs, key=lambda value: value["worker"]):
        identity = job["identity"]
        try:
            validate_campaign_asset_claims(
                identity, assets, validation_path=validation_path,
                manifest_path=manifest_path, map_path=map_path,
                release_path=release_path)
        except MutationAborted as exc:
            raise TestQualityRefused(str(exc)) from exc
        changed_candidate = sorted(key for key, value in {
            "candidate_run_sha256": current_candidate["run_sha256"],
            "candidate_generated_tests_sha256": current_candidate[
                "generated_tests_sha256"],
            "solution_generated_tests_sha256": current_candidate[
                "generated_tests_sha256"],
        }.items() if identity.get(key) != value)
        if identity.get("kind") != "test-quality" \
                or identity.get("side") != "candidate" \
                or changed_candidate:
            raise TestQualityRefused(
                "REFUSED: D4 run-1 shard changed candidate identity field(s) "
                f"{changed_candidate}.")
        candidate_identities.append(identity)
        source_shards.append({
            "path": job["out"],
            "rows_sha256": sha256_file(job["out"]),
            "sidecar_sha256": sha256_file(provenance_path(job["out"])),
            "campaign_identity_sha256": campaign_identity_digest(identity),
        })
    timeouts = {identity.get("timeout_seconds")
                for identity in candidate_identities}
    if len(timeouts) != 1:
        raise TestQualityRefused(
            "REFUSED: D4 run-1 candidate shards mix timeout semantics.")
    run_1_timeout = next(iter(timeouts))
    _d4_require_int(run_1_timeout, "D4 run-1 timeout_seconds", minimum=1)
    source_expected = {
        "campaign_dir": campaign_dir,
        "campaign_plan_sha256": content_digest(campaign_plan),
        "observation_id": _d4_run_1_observation_id(campaign_plan),
        "candidate_shards": source_shards,
        "expected_pairs": len(expected),
        "expected_pairs_sha256": pair_set_digest(expected),
        "timeout_seconds": run_1_timeout,
    }
    if not _d4_json_equal(doc["source"], source_expected):
        raise TestQualityRefused(
            "REFUSED: D4 plan is stale or tampered for run-1 shard bytes, "
            "ownership, pair population, or timeout.")
    try:
        hard_doc = load_hard_subset(hard_path, require_pin=True)
    except (HardSubsetRefused, OSError, ValueError) as exc:
        raise TestQualityRefused(str(exc)) from exc
    hard_sets = hard_kill_sets(
        hard_doc, population_id=population_id, items=passed,
        manifest_digest=manifest.get("digest"))
    hard_pairs = {(item_id, mutant_id)
                  for item_id, values in hard_sets.items()
                  for mutant_id in values}
    outside = sorted(hard_pairs - expected)
    if outside:
        raise TestQualityRefused(
            f"REFUSED: D4 hard subset contains pair(s) outside run 1: "
            f"{outside[:3]}.")
    hard_expected = {
        "path": hard_path,
        "sha256": sha256_file(hard_path),
        "digest": hard_doc["digest"],
        "population_id": population_id,
        "pairs": len(hard_pairs),
        "pairs_sha256": pair_set_digest(hard_pairs),
    }
    if not _d4_json_equal(doc["hard_subset"], hard_expected):
        raise TestQualityRefused(
            "REFUSED: D4 plan is stale or tampered for the hard subset or "
            "registered population.")
    _run_1, _hard_pairs, items, pairs = _candidate_hard_qualification(
        candidate_rows, hard_sets)
    qualification = {
        "items": items,
        "pairs": _d4_pair_rows(pairs),
        "expected_pairs": len(pairs),
        "expected_pairs_sha256": pair_set_digest(pairs),
    }
    if not _d4_json_equal(doc["qualification"], qualification):
        raise TestQualityRefused(
            "REFUSED: D4 plan pair set is not the exact qualification "
            "derived from current run 1 and hard subset.")
    return {"plan": doc, "pairs": pairs, "candidate_files": passed,
            "mutants": mutants, "expected_run_1_pairs": expected,
            "timeout_seconds": run_1_timeout,
            "run_1_observation_id": source_expected["observation_id"],
            # In-memory only: generic prospective orchestration joins every
            # already-authenticated run-1 identity to its current reviewed
            # policy/runtime before spending a second observation.  This is
            # not part of the saved D4 document or another schema.
            "candidate_identities": candidate_identities}


def validate_d4_confirmation_run_2_binding(
        *, rerun_campaign: dict, shard_sidecars: Iterable[dict],
        plan_binding: dict, plan_path: str, run1_campaign: str,
        hard_subset_path: str) -> None:
    """Join a native run-2 observation back to its exact run-1 plan.

    Native shard validation authenticates each row, worker identity, exact
    shard pair set, and standalone observation.  This additional join proves
    that observation used the candidate bytes qualified by run 1, that every
    worker owns exactly the deterministic LPT allocation the canonical
    producer derives, and that every shard records the same complete D4
    source/provenance binding, including the plan's exact file bytes rather
    than only its semantic content digest.
    """
    from .mutation_run import sha256_file
    planned_pairs = plan_binding.get("pairs") \
        if isinstance(plan_binding, dict) else None
    plan = plan_binding.get("plan") \
        if isinstance(plan_binding, dict) else None
    if not isinstance(planned_pairs, set) or not isinstance(plan, dict):
        raise TestQualityRefused(
            "REFUSED: D4 run-2 finalization has no validated plan binding.")
    run_1_observation_id = (plan.get("source") or {}).get("observation_id")
    run_2_observation_id = _hard_rerun_observation_id(rerun_campaign)
    _d4_require_string(run_1_observation_id,
                       "D4 run-1 observation_id")
    from .mutation_run import MutationAborted, validate_observation_id
    try:
        validate_observation_id(run_1_observation_id)
    except MutationAborted as exc:
        raise TestQualityRefused(str(exc)) from exc
    if run_2_observation_id == run_1_observation_id:
        raise TestQualityRefused(
            "REFUSED: D4 run 2 copied run 1's observation_id; two complete "
            "executions require distinct producer-owned identities.")
    actual_pairs = rerun_campaign.get("pairs") \
        if isinstance(rerun_campaign, dict) else None
    if actual_pairs != planned_pairs:
        actual = actual_pairs if isinstance(actual_pairs, set) else set()
        missing = planned_pairs - actual
        extra = actual - planned_pairs
        raise TestQualityRefused(
            "REFUSED: D4 run 2 differs from its authenticated exact pair "
            f"plan: {len(missing)} missing and {len(extra)} extra pair(s).")
    identity = rerun_campaign.get("campaign_identity") or {}
    n_workers = identity.get("of")
    if type(n_workers) is not int or n_workers < 1:
        raise TestQualityRefused(
            "REFUSED: D4 run-2 campaign has no positive integer worker "
            "cardinality.")
    expected_allocations = shard_d4_confirmation_pairs(
        planned_pairs, n_workers)
    if any(not pairs for pairs in expected_allocations):
        raise TestQualityRefused(
            "REFUSED: D4 run 2 declares more workers than the exact plan has "
            "independently applicable mutant groups; use fewer workers.")
    authenticated_shards = rerun_campaign.get("shards")
    if type(authenticated_shards) is not list \
            or len(authenticated_shards) != n_workers:
        raise TestQualityRefused(
            "REFUSED: D4 run-2 native validation did not preserve the exact "
            "complete per-worker allocation.")
    shards_by_number = {}
    for record in authenticated_shards:
        fields = {"shard", "campaign_identity", "pairs"}
        if type(record) is not dict or set(record) != fields:
            raise TestQualityRefused(
                "REFUSED: D4 run-2 authenticated shard allocation is "
                "malformed.")
        number = record["shard"]
        shard_identity = record["campaign_identity"]
        shard_pairs = record["pairs"]
        if type(number) is not int or number in shards_by_number \
                or not 0 <= number < n_workers \
                or type(shard_identity) is not dict \
                or shard_identity.get("shard") != number \
                or shard_identity.get("of") != n_workers \
                or type(shard_pairs) is not set:
            raise TestQualityRefused(
                "REFUSED: D4 run-2 authenticated shard has invalid worker "
                "ownership.")
        expected_shard_pairs = expected_allocations[number]
        if shard_pairs != expected_shard_pairs:
            missing = expected_shard_pairs - shard_pairs
            extra = shard_pairs - expected_shard_pairs
            raise TestQualityRefused(
                f"REFUSED: D4 run-2 worker {number} does not own its exact "
                "deterministic pair allocation: "
                f"{len(missing)} missing and {len(extra)} extra pair(s).")
        shards_by_number[number] = record
    if set(shards_by_number) != set(range(n_workers)):
        raise TestQualityRefused(
            "REFUSED: D4 run-2 authenticated allocation is not the exact "
            "zero-based worker set.")
    planned_candidate = plan.get("candidate") or {}
    candidate_claims = {
        "candidate_run_sha256": planned_candidate.get("run_sha256"),
        "candidate_generated_tests_sha256": planned_candidate.get(
            "generated_tests_sha256"),
        "solution_generated_tests_sha256": planned_candidate.get(
            "generated_tests_sha256"),
    }
    changed_candidate = sorted(
        key for key, value in candidate_claims.items()
        if identity.get(key) != value)
    if changed_candidate:
        raise TestQualityRefused(
            "REFUSED: D4 run-2 campaign does not preserve the candidate/"
            "generated-test identity authenticated by run 1: "
            f"{changed_candidate}.")
    expected_provenance = {
        "d4_confirmation_plan": os.path.abspath(plan_path),
        "d4_confirmation_plan_sha256": sha256_file(plan_path),
        "d4_confirmation_plan_digest": plan.get("digest"),
        "d4_run_1_campaign": os.path.abspath(run1_campaign),
        "d4_run_1_observation_id": run_1_observation_id,
        "d4_hard_subset": os.path.abspath(hard_subset_path),
        "d4_pair_shard_policy": D4_PAIR_SHARD_POLICY,
    }
    sidecars = list(shard_sidecars)
    if len(sidecars) != n_workers:
        raise TestQualityRefused(
            "REFUSED: D4 run 2 does not have exactly one native provenance "
            "document per worker.")
    sidecar_workers = set()
    for number, sidecar in enumerate(sidecars, 1):
        if type(sidecar) is not dict:
            raise TestQualityRefused(
                f"REFUSED: D4 run-2 shard {number} provenance is malformed.")
        sidecar_identity = sidecar.get("campaign_identity")
        worker = sidecar_identity.get("shard") \
            if type(sidecar_identity) is dict else None
        if type(worker) is not int or worker in sidecar_workers \
                or worker not in shards_by_number \
                or not _d4_json_equal(
                    sidecar_identity,
                    shards_by_number[worker]["campaign_identity"]):
            raise TestQualityRefused(
                "REFUSED: D4 run-2 shard provenance does not match its "
                "authenticated worker identity.")
        sidecar_workers.add(worker)
        changed = sorted(
            key for key, value in expected_provenance.items()
            if not _d4_json_equal(sidecar.get(key), value))
        if changed:
            raise TestQualityRefused(
                "REFUSED: D4 run-2 shard provenance does not completely "
                "bind the authenticated plan/source supplied for "
                f"finalization; changed field(s) {changed}.")
    if sidecar_workers != set(range(n_workers)):
        raise TestQualityRefused(
            "REFUSED: D4 run-2 provenance is not the complete zero-based "
            "worker set.")


def shard_d4_confirmation_pairs(
        pairs: Iterable[tuple[str, str]], n_workers: int) \
        -> list[set[tuple[str, str]]]:
    """Deterministically pair-balance D4 while keeping each mutant together."""
    if not isinstance(n_workers, int) or isinstance(n_workers, bool) \
            or n_workers < 1:
        raise TestQualityRefused(
            "REFUSED: D4 pair sharding requires a positive worker count.")
    by_mutant: dict[str, set[tuple[str, str]]] = {}
    for pair in set(pairs):
        if not isinstance(pair, tuple) or len(pair) != 2 \
                or not all(isinstance(value, str) and value for value in pair):
            raise TestQualityRefused(
                f"REFUSED: malformed D4 execution pair {pair!r}.")
        by_mutant.setdefault(pair[1], set()).add(pair)
    bins = [set() for _ in range(n_workers)]
    loads = [0] * n_workers
    for mutant_id, mutant_pairs in sorted(
            by_mutant.items(), key=lambda value: (-len(value[1]), value[0])):
        del mutant_id
        worker = min(range(n_workers), key=lambda value: (loads[value], value))
        bins[worker].update(mutant_pairs)
        loads[worker] += len(mutant_pairs)
    return bins


def _reference_excluded_pairs(controls: dict) -> frozenset:
    """The pairs section 5.1 removed from the REFERENCE's scored universe.

    Read off the artifact's own disclosure list rather than differenced out
    of the population: `validate_reference_controls` rederived the whole
    attestation from its three sealed observations before it became
    `ReferenceControls`, so this list IS the narrowing that produced
    `expected_pairs`.
    """
    return frozenset((entry["item_id"], entry["mutant_id"])
                     for entry in controls["excluded_pairs"])


def _reference_declared_items(controls: dict) -> Optional[frozenset]:
    """The item set a DECLARED reference restricted its population to.

    `None` when the reference covers its whole mapped population, which is
    every project but a declared one and is the byte-unchanged path.

    The roster is read off `items` rather than off the disclosure list.  That
    key is one row per item of the pair set the attestation was derived over,
    written by `_derive_reference_controls` after the declaration narrowed the
    scope, so it IS the declared-and-mapped item set -- and it needs no
    release document to reconstruct, which the omitted-id list would.
    """
    if "declared_subset" not in controls:
        return None
    return frozenset(controls["items"])


def _narrow_to_reference(mutants: list, restricted: dict,
                         excluded: frozenset,
                         declared: Optional[frozenset] = None) \
        -> tuple[list, dict]:
    """Drop the reference's excluded pairs from a planned population.

    A mutant whose every pair was excluded leaves the campaign entirely:
    `shard_mutants` refuses a member with no executable pair, and planning
    one would execute a pair no reference observation covers.  Manifest
    order is preserved, so the shard allocation stays reproducible.

    `declared` applies the same narrowing at the item layer: the manifest and
    the map still describe the whole released population, and a declared
    reference observed only part of it.  The two narrowings compose in the
    order the specification states -- mapped pairs restricted to declared
    items, then minus section 5.1's excluded pairs.
    """
    narrowed = {}
    for mutant_id, items in restricted.items():
        keep = [item_id for item_id in items
                if (item_id, mutant_id) not in excluded
                and (declared is None or item_id in declared)]
        if keep:
            narrowed[mutant_id] = keep
    return ([mutant for mutant in mutants if mutant["id"] in narrowed],
            narrowed)


def _single_observation_candidate_outcomes(
        rows: Iterable[dict], expected: set) -> tuple[dict, dict]:
    """Close one candidate observation, naming its own section 5.1 drops.

    Returns `(outcomes, excluded)`.  Section 5.1 admits a candidate sweep's
    terminal timeout/infrastructure pairs exactly as it admits the
    reference's — at the measured rate, refusing them would make candidate
    scoring impossible for the same reason it makes reference collection
    impossible — but for THIS run only, and out of `G`, `H` and `C`
    together: dropping such a pair from the candidate's kill set while
    leaving it in gold's denominator would bias this run's recall downward.
    """
    outcomes: dict = {}
    excluded: dict = {}
    for number, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise TestQualityRefused(
                f"REFUSED: candidate observation row {number} is not an "
                "object.")
        pair = (row.get("item_id"), row.get("mutant_id"))
        if not all(isinstance(value, str) and value for value in pair):
            raise TestQualityRefused(
                f"REFUSED: candidate observation row {number} has a malformed "
                "pair identity.")
        if pair in outcomes or pair in excluded:
            raise TestQualityRefused(
                f"REFUSED: candidate observation repeats pair {pair!r}.")
        outcome = row.get("outcome")
        if not isinstance(outcome, str) or not outcome:
            raise TestQualityRefused(
                f"REFUSED: candidate observation has invalid terminal outcome "
                f"{outcome!r} for {pair!r}.")
        try:
            classification = classify_outcome("passed", outcome)
        except ValueError as exc:
            raise TestQualityRefused(
                f"REFUSED: candidate observation has unknown terminal outcome "
                f"{outcome!r} for {pair!r}.") from exc
        # `timeout` needs its own clause for the reason
        # `reference_controls._excluded_terminal_outcome` gives: under a
        # passed baseline `classify_outcome` buckets it as a KILL.
        if outcome == "timeout" or classification == "infrastructure":
            excluded[pair] = outcome
        else:
            outcomes[pair] = outcome
    actual = set(outcomes) | set(excluded)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        raise TestQualityRefused(
            "REFUSED: single-observation candidate rows differ from the exact "
            f"passed-item pair set: {len(missing)} missing and {len(extra)} "
            f"unexpected pair(s).")
    return outcomes, excluded


def _macro(values: Iterable[float]) -> Optional[float]:
    values = list(values)
    return sum(values) / len(values) if values else None


def single_observation_candidate_pairs(authority, passed,
                                       scope=CANDIDATE_PAIRS_ALL):
    """Exact candidate workload admitted by the sealed reference basis.

    A full-gold-only reference executes each pass's `G_i` only.  A
    hard-subset reference executes every pair of the passes, except under a
    labelled reference basis with scope `gold-killed`
    (SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md section 2): then only each
    pass's `G_i`, its full-gold kills after section 5.1 and any gold
    disagreements.  The hard subset must lie inside it, or the hard verdict
    would silently shrink; that premise is checked, not assumed.
    """
    authority = _require_single_observation_authority(authority)
    if scope not in CANDIDATE_PAIR_SCOPES:
        raise TestQualityRefused(
            f"REFUSED: unknown candidate pair scope {scope!r}; expected one "
            f"of {list(CANDIDATE_PAIR_SCOPES)}.")
    pairs = {pair for pair in authority.expected_pairs if pair[0] in passed}
    sets = authority.sets
    if getattr(sets, "reference_basis", "hard_subset") == "full_gold":
        return {pair for pair in pairs
                if pair[1] in sets.full_gold_kills.get(pair[0], ())}
    if scope == CANDIDATE_PAIRS_ALL:
        return pairs
    if getattr(sets, "sensitivity", None) is None:
        raise TestQualityRefused(
            "REFUSED: a gold-killed candidate slice of a hard-subset "
            "reference is adopted only for the labelled stub-gate-waived "
            "basis (SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md section 2); "
            "this reference's candidates are scored on every pair "
            "(GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md section 7).")
    kills = {(item_id, mutant_id) for item_id, mutant_id in pairs
             if mutant_id in sets.full_gold_kills.get(item_id, frozenset())}
    outside = sorted(
        (item_id, mutant_id) for item_id, mutant_id in pairs
        if mutant_id in sets.hard_subset.get(item_id, frozenset())
        and (item_id, mutant_id) not in kills)
    if outside:
        raise TestQualityRefused(
            f"REFUSED: {len(outside)} hard-subset pair(s) of the passed items "
            f"are not full-gold kills, e.g. {outside[:3]}; a gold-killed "
            "slice would drop them from the hard verdict.")
    if not kills:
        raise TestQualityRefused(
            "REFUSED: the reference's full gold kills no pair of this "
            "candidate's passed items, so a gold-killed candidate slice has "
            "nothing to execute; score it with --candidate-pairs all.")
    return kills


def _single_observation_scope_record(authority, pairs,
                                     scope=CANDIDATE_PAIRS_ALL) \
        -> Optional[dict]:
    """The v2 root plan's `candidate_pair_scope`, or None.

    A full-gold-only reference executes each pass's `G_i` only
    (FULL_GOLD_NV_LEAD_AMENDMENT.md section 5), and so does a labelled
    hard-subset basis scored with `gold-killed`; either plan binds the
    gold-killed scope exactly as the v1 routes' plans do.  A hard-subset
    reference scored on every pair keeps its plan's bytes.
    """
    authority = _require_single_observation_authority(authority)
    if getattr(authority.sets, "reference_basis", "hard_subset") != "full_gold" \
            and scope != CANDIDATE_PAIRS_GOLD_KILLED:
        return None
    return gold_killed_scope_record(pairs, gold_pair_plan=False)


#: The first harness whose scoring leaves out the reviewed nondeterministic
#: mutants (correction D, specifications/EVALUATOR_CORRECTIONS_20261015_
#: AMENDMENT.md section 3.4).
NONDETERMINISTIC_FROM_HARNESS = 25


def unscored_mutants(harness_version: object) -> frozenset:
    """The mutants a summary scored at `harness_version` leaves out.

    The reviewed nondeterministic list from harness 25 on, and none before
    it: a summary recorded by an earlier harness re-derives exactly as it was
    scored, and `rescore_recorded` applies the list to its verdicts without
    editing it.  A version that is not an integer (a fixture's) is current.
    """
    if isinstance(harness_version, int) \
            and harness_version < NONDETERMINISTIC_FROM_HARNESS:
        return frozenset()
    return nondeterministic_mutants()


def score_single_observation(
        passed: dict, candidate_rows: list, *,
        authority: object, expected: Optional[set] = None,
        unscored: Optional[frozenset] = None,
        candidate_pair_scope: str = CANDIDATE_PAIRS_ALL) -> dict:
    """Score one complete candidate against sealed reusable controls.

    `unscored` holds the mutants left out of every scored universe.  None
    means the reviewed nondeterministic list (harness 25, correction D); a
    summary re-derived as recorded passes `unscored_mutants` of its harness.

    Under `gold-killed` (`single_observation_candidate_pairs`) the candidate
    observed only `G_i`, so each item's universe is `G_i` minus its own
    drops.  `gold` and `hard` (inside `G_i`) are then the sets an all-pairs
    score intersects with its universe, and every recall, the verdict and
    `non_vacuous_passes` come out the same for the same outcomes on `G_i`;
    the companions that need an outcome off `G_i` are present and null.
    """
    from .mutation_run import pair_set_digest

    authority = _require_single_observation_authority(authority)
    passed_ids = set(passed)
    if not passed_ids:
        raise TestQualityRefused(
            "REFUSED: a zero-pass run has no single-observation mutation "
            "score.")
    reference_pairs = set(authority.expected_pairs)
    candidate_pairs = single_observation_candidate_pairs(
        authority, passed_ids, candidate_pair_scope)
    full_gold = getattr(authority.sets, "reference_basis", "hard_subset") == "full_gold"
    # A full-gold-only reference is always scored on its gold-killed slice.
    gold_killed = full_gold \
        or candidate_pair_scope == CANDIDATE_PAIRS_GOLD_KILLED
    sensitivity = getattr(authority.sets, "sensitivity", None)
    supplied = candidate_pairs if expected is None else set(expected)
    if supplied != candidate_pairs:
        missing = candidate_pairs - supplied
        extra = supplied - candidate_pairs
        raise TestQualityRefused(
            "REFUSED: candidate execution scope is not the complete reference "
            "map restricted to sealed passed items"
            + (" and their full-gold kills" if gold_killed else "") + ": "
            f"{len(missing)} missing and {len(extra)} unexpected pair(s).")
    outcomes, excluded = _single_observation_candidate_outcomes(
        candidate_rows, candidate_pairs)
    candidate_kills: dict = {}
    for (item_id, mutant_id), outcome in outcomes.items():
        if outcome == "failed":
            candidate_kills.setdefault(item_id, set()).add(mutant_id)

    sets = authority.sets
    # Harness 25 (correction D): a nondeterministic mutant is in no scored
    # universe, so it is in no item's G_i, hard subset or candidate kills.
    if unscored is None:
        unscored = nondeterministic_mutants()
    per_item = {}
    verdicts = {value: 0 for value in VERDICTS}
    hard_values = []
    full_values = []
    only_values = []
    jaccard_values = []
    for item_id in sorted(passed_ids):
        dropped = {mutant_id for iid, mutant_id in excluded if iid == item_id}
        # THE ONE UNIVERSE this item is scored over: the reference's pairs
        # for it, minus what this run's own harness failed on.  `gold` and
        # `hard` are intersected with it for the same reason `candidate` is
        # already restricted to it — three sets over three universes have
        # intersections that mean nothing.
        scored = {mutant_id for iid, mutant_id in candidate_pairs
                  if iid == item_id} - dropped - unscored
        gold = set(sets.full_gold_kills.get(item_id, frozenset())) & scored
        hard = (set() if full_gold else
                set(sets.hard_subset.get(item_id, frozenset())) & scored)
        candidate = candidate_kills.get(item_id, set()) & scored
        hard_killed = len(candidate & hard)
        hard_recall = hard_killed / len(hard) if hard else None
        full_killed = len(candidate & gold)
        full_recall = full_killed / len(gold) if gold else None
        union = candidate | gold
        only_generated = len(candidate - gold) / len(union) if union else None
        full_jaccard = len(candidate & gold) / len(union) if union else None
        verdict = verdict_for(len(gold), full_recall) if full_gold else verdict_for(len(hard), hard_recall)
        verdicts[verdict] += 1
        if hard_recall is not None:
            hard_values.append(hard_recall)
        # Companion macros use the existing full-gold-scorable item set.
        if full_recall is not None:
            full_values.append(full_recall)
            only_values.append(only_generated)
            jaccard_values.append(full_jaccard)
        per_item[item_id] = {
            "mutants_covering": len(scored),
            "candidate_excluded": len(dropped),
            "verdict_basis": "full_gold" if full_gold else "hard_subset",
            "verdict": verdict,
            "hard_gold_killed": None if full_gold else len(hard),
            "hard_candidate_killed": None if full_gold else hard_killed,
            "hard_denominator": None if full_gold else len(hard),
            "hard_recall": hard_recall,
            "full_gold_killed": len(gold),
            "full_candidate_killed": full_killed,
            "full_denominator": len(gold),
            "full_recall": full_recall,
            # Not measured on a gold-killed slice: each reads the
            # candidate's outcomes off `G_i`.
            "candidate_only_kills": None if gold_killed else len(candidate - gold),
            "full_union": None if gold_killed else len(union),
            "full_only_generated": None if gold_killed else only_generated,
            "full_jaccard": None if gold_killed else full_jaccard,
        }
        if sensitivity is not None:
            # Labelled basis only: the scored full-gold kills this pass did
            # not kill, by mutant.  A gold-agreement pilot (the full-gold
            # control run as the candidate) reads its flips here; the
            # candidate's own timeout or infrastructure pairs are
            # `candidate_excluded_pairs`, never listed here.
            per_item[item_id]["full_unkilled"] = sorted(gold - candidate)
    scored_pairs = {pair for pair in candidate_pairs - set(excluded)
                    if pair[1] not in unscored}
    return {
        **({"candidate_pair_scope": CANDIDATE_PAIRS_GOLD_KILLED,
            "withheld_measures": list(SINGLE_OBSERVATION_GOLD_KILLED_WITHHELD)}
           if gold_killed else {}),
        "method": SINGLE_OBSERVATION_METHOD,
        "policy": FULL_POPULATION_SINGLE_OBSERVATION_POLICY,
        "candidate_observation_count": 1,
        "reference_observation_count": 1,
        "verdict_basis": "full_gold" if full_gold else "hard_subset",
        "companion_basis": None if full_gold else "full_gold",
        "n_passed": len(passed_ids),
        "n_scorable": len(full_values if full_gold else hard_values),
        "recall_macro": _macro(full_values if full_gold else hard_values),
        "hard_recall_macro": _macro(hard_values),
        "full_recall_macro": _macro(full_values),
        "full_only_generated_macro": None if gold_killed else _macro(only_values),
        "full_jaccard_macro": None if gold_killed else _macro(jaccard_values),
        "verdicts": verdicts,
        "non_vacuous_passes": verdicts[EQUIVALENT],
        "per_item": per_item,
        "reference_pairs": len(reference_pairs),
        "reference_pairs_sha256": pair_set_digest(reference_pairs),
        "reference_excluded_count": sets.excluded_count,
        "reference_omitted_items": len(sets.omitted_items),
        "reference_declared_reason": sets.declared_reason,
        "candidate_pairs": len(candidate_pairs),
        "candidate_pairs_sha256": pair_set_digest(candidate_pairs),
        "candidate_excluded_count": len(excluded),
        "candidate_excluded_pairs": [
            {"item_id": item_id, "mutant_id": mutant_id,
             "outcome": excluded[(item_id, mutant_id)]}
            for item_id, mutant_id in sorted(excluded)],
        "candidate_scored_pairs": len(scored_pairs),
        "candidate_scored_pairs_sha256": pair_set_digest(scored_pairs),
        **({} if sensitivity is None else {
            # The labelled basis: every number above is the eligible
            # derivation's, and this names why none of it is primary.
            "sensitivity": sensitivity,
            "inference_valid": False,
            "reference_stub_gate": {
                "macro_recall": sets.stub_macro_recall,
                "threshold": sets.stub_threshold,
                "eligible": sets.eligible,
            },
            # Listed pair by pair with the source and SHA-256 of the pilot
            # document: the controls live only in memory, so the summary is
            # where the disclosure is preserved.
            "reference_gold_disagreements": copy.deepcopy(
                authority.controls["gold_disagreements"]),
        }),
    }


def _single_observation_gold_rows(authority: object, expected: set) -> list:
    """Project G over the EXECUTED pair set instead of running gold again.

    Every pair the campaign executes gets a row, including the ones this
    run's own harness later failed on: the projection is the preserved
    reference's answer for what was executed, and which of those pairs leave
    the scored universe is `score_single_observation`'s decision, recorded
    beside its numbers.
    """
    authority = _require_single_observation_authority(authority)
    gold = authority.sets.full_gold_kills
    return [{
        "item_id": item_id,
        "mutant_id": mutant_id,
        "outcome": ("failed" if mutant_id in gold.get(item_id, frozenset())
                    else "passed"),
    } for item_id, mutant_id in sorted(expected)]


def score(passed: dict, covering_by_item: dict, gold_killed: dict,
          gold_baseline: dict, candidate_rows: list, *,
          expected: Optional[set] = None,
          hard_killed: Optional[dict] = None,
          candidate_rows_run_2: Optional[list] = None,
          unscored: Optional[frozenset] = None) -> dict:
    """The per-item verdicts and the overall numbers, via `mutation.recall`.

    The macro average and the eligible count are `recall`'s own, not
    recomputed here: the whole point of routing through it is that this
    number and the gate's are produced by one function.  What this adds is the
    per-item vocabulary a reader needs — an item at 1.0 and an item at 0.0 are
    both "scored" to `recall`, and only one of them is a result worth
    publishing.

    `unscored` is as in `score_single_observation`: None means the reviewed
    nondeterministic list.
    """
    baseline = {iid: "passed" for iid in passed}

    # Harness 25 (correction D): a nondeterministic mutant's pairs leave the
    # scored population -- G_i, the hard subset, the candidate's rows and
    # the completeness expectation alike -- before anything is computed.
    if unscored is None:
        unscored = nondeterministic_mutants()
    gold_killed = {iid: set(mutants) - unscored
                   for iid, mutants in gold_killed.items()}
    if hard_killed is not None:
        hard_killed = {iid: set(mutants) - unscored
                       for iid, mutants in hard_killed.items()}
    candidate_rows = [row for row in candidate_rows
                      if row.get("mutant_id") not in unscored]
    if candidate_rows_run_2 is not None:
        candidate_rows_run_2 = [row for row in candidate_rows_run_2
                                if row.get("mutant_id") not in unscored]
    if expected is not None:
        expected = {pair for pair in expected if pair[1] not in unscored}

    # Legacy/full-gold summaries remain readable and rebuild byte-semantically.
    # The new branch is explicit: no artifact means no invented hard subset.
    hard_mode = hard_killed is not None
    hard_scored = None
    hard_confirmation: dict = {}
    if hard_mode:
        hard_killed = {iid: set(values)
                       for iid, values in (hard_killed or {}).items()
                       if iid in passed}
        hard_pairs = {(iid, mutant_id)
                      for iid, values in hard_killed.items()
                      for mutant_id in values}
        confirmed_rows, hard_confirmation = \
            _candidate_selective_hard_confirmation(
                candidate_rows, candidate_rows_run_2, hard_killed)
        hard_scored = recall(baseline, confirmed_rows, hard_killed,
                             expected_pairs=hard_pairs)

    scored = recall(baseline, candidate_rows, gold_killed,
                    expected_pairs=expected)
    candidate_kills = _candidate_kills(candidate_rows)

    per_item: dict = {}
    counts = {v: 0 for v in VERDICTS}
    for iid in sorted(passed):
        entry = scored["per_item"].get(iid) or {}
        gold_set = gold_killed.get(iid) or set()
        full_recall = entry.get("recall")
        hard_set = ((hard_killed or {}).get(iid) or set()) if hard_mode else None
        hard_entry = ((hard_scored or {}).get("per_item", {}).get(iid) or {})
        item_recall = hard_entry.get("recall") if hard_mode else full_recall
        basis_set = hard_set if hard_mode else gold_set
        verdict = verdict_for(len(basis_set or ()), item_recall)
        reason = None
        if verdict == NOT_SCORABLE:
            if not covering_by_item.get(iid):
                reason = "no mutant in the manifest covers this item"
            elif gold_baseline.get(iid) != "passed":
                reason = (f"gold's own baseline is "
                          f"{gold_baseline.get(iid)!r}, not 'passed', so none "
                          f"of its kills are eligible (§3.10)")
            elif hard_mode and not hard_set:
                reason = ("the population-pinned hard subset is empty for "
                          "this item — D3 requires not_scorable and forbids "
                          "falling back to the saturated full-gold set")
            elif not gold_set:
                reason = ("gold kills none of the mutants covering this item "
                          "— they are equivalent as far as this benchmark can "
                          "observe, so the item carries no information about "
                          "the candidate")
            else:
                reason = ("every one of gold's kills on this item was excluded "
                          "as infrastructure, so nothing was actually scored")
        counts[verdict] += 1
        # Kills outside gold's set: not in the recall, still evidence.
        candidate_only = len((candidate_kills.get(iid) or set()) - gold_set)
        full_candidate_killed = entry.get("killed", 0)
        full_denominator = entry.get("denominator", 0)
        full_jaccard = jaccard_for(full_candidate_killed, full_denominator,
                                   candidate_only)
        hard_candidate_killed = hard_entry.get("killed", 0)
        hard_denominator = hard_entry.get("denominator", 0)
        hard_jaccard = (jaccard_for(hard_candidate_killed, hard_denominator, 0)
                        if hard_mode else None)
        per_item[iid] = {
            "mutants_covering": len(covering_by_item.get(iid) or ()),
            "gold_killed": len(basis_set or ()),
            "candidate_killed": (hard_candidate_killed if hard_mode
                                  else full_candidate_killed),
            "denominator": (hard_denominator if hard_mode
                            else full_denominator),
            "recall": item_recall,
            # The symmetric partner of the recall, over the SAME counts, so a
            # reader can see the difference between "kills what gold kills"
            # and "kills what gold kills and nothing else" without going back
            # to the rows.  `verdict` is deliberately still the recall's:
            # widening the vocabulary would silently reclassify every result
            # scored before today.
            "jaccard": hard_jaccard if hard_mode else full_jaccard,
            "verdict": verdict,
            "not_scorable_reason": reason,
            "candidate_only_kills": candidate_only,
            **({
                "verdict_basis": "hard_subset",
                "full_gold_killed": len(gold_set),
                "full_candidate_killed": full_candidate_killed,
                "full_denominator": full_denominator,
                "full_recall": full_recall,
                "full_jaccard": full_jaccard,
                "hard_gold_killed": len(hard_set or ()),
                "hard_candidate_killed": hard_candidate_killed,
                "hard_denominator": hard_denominator,
                "hard_recall": item_recall,
                "hard_jaccard": hard_jaccard,
            } if hard_mode else {}),
        }

    jaccards = [v["jaccard"] for v in per_item.values()
                if v["jaccard"] is not None]
    result = {
        "n_passed": len(passed),
        "n_scorable": ((hard_scored or {})["n_eligible"] if hard_mode
                       else scored["n_eligible"]),
        "recall_macro": ((hard_scored or {})["recall"]
                         if hard_mode and (hard_scored or {})["n_eligible"]
                         else (scored["recall"] if not hard_mode
                               and scored["n_eligible"] else None)),
        # Macro over the SAME population as `recall_macro` -- an item is in
        # both or in neither, so the two are read against one denominator.
        "jaccard_macro": (round(sum(jaccards) / len(jaccards), 6)
                          if jaccards else None),
        "verdicts": counts,
        "non_vacuous_passes": counts[EQUIVALENT],
        "per_item": per_item,
        "excluded": ((hard_scored or {})["excluded"] if hard_mode
                     else scored["excluded"]),
        "completeness_checked": ((hard_scored or {})["completeness_checked"]
                                 if hard_mode
                                 else scored["completeness_checked"]),
    }
    if hard_mode:
        full_jaccards = [value["full_jaccard"] for value in per_item.values()
                         if value["full_jaccard"] is not None]
        result.update({
            "verdict_basis": "hard_subset",
            "hard_pairs": sum(len(value) for value in hard_killed.values()),
            "full_recall_macro": (scored["recall"]
                                  if scored["n_eligible"] else None),
            "hard_recall_macro": ((hard_scored or {})["recall"]
                                  if (hard_scored or {})["n_eligible"]
                                  else None),
            "full_jaccard_macro": (
                round(sum(full_jaccards) / len(full_jaccards), 6)
                if full_jaccards else None),
            "hard_jaccard_macro": result["jaccard_macro"],
            **hard_confirmation,
        })
    return result


# ------------------------------------------------------------ the command
class _CampaignFirstCause:
    """Linearize operator stop, cap expiry, and successful completion.

    The operator-facing event is deliberately distinct from the event workers
    observe.  Only this latch may set the worker event, after committing one
    immutable cause under ``_lock``.  That prevents a cap timer which fires
    during slow restoration from relabelling an earlier operator stop, and it
    prevents a late timer from cancelling a completion already committed.
    """

    OPERATOR = "operator"
    COMPUTE_CAP = "compute_cap"
    COMPLETE = "complete"

    def __init__(self, external_event: threading.Event,
                 worker_cancel_event: threading.Event, *,
                 deadline: Optional[float] = None):
        from .mutation_run import CoordinatorCancellationEvent
        self.external_event = external_event
        self.worker_cancel_event = worker_cancel_event
        self.deadline = deadline
        self._timestamped_external = isinstance(
            external_event, CoordinatorCancellationEvent)
        self._lock = threading.Lock()
        self._cause: Optional[str] = None
        self._closed = threading.Event()
        self._watcher: Optional[threading.Thread] = None
        self._timer: Optional[threading.Timer] = None

    def _commit_locked(self, cause: str) -> str:
        if self._cause is None:
            self._cause = cause
            if cause != self.COMPLETE:
                self.worker_cancel_event.set()
        return self._cause

    def _operator_snapshot(self) -> tuple[Optional[float], bool]:
        """Read one coherent operator-request state.

        The coordinator event serializes this pair with ``set()``.  A legacy
        Event has no source timestamp, but its visibility is still sampled at
        the same decision points and therefore remains fail-closed.
        """
        if self._timestamped_external:
            return self.external_event.operator_snapshot()
        return None, self.external_event.is_set()

    def _snapshot_cause(self, snapshot: tuple[Optional[float], bool],
                        now: float) -> Optional[str]:
        requested_at, external_visible = snapshot
        if requested_at is not None:
            if self.deadline is None or requested_at < self.deadline:
                return self.OPERATOR
            # A trusted timestamp at/after the deadline proves that cap expiry
            # linearized first even when the timer itself has not run yet.
            return self.COMPUTE_CAP
        if external_visible:
            # A plain Event cannot authenticate source ordering.  Treating a
            # visible request as operator evidence is the only direction that
            # cannot manufacture a publishable compute-cap result.
            return self.OPERATOR
        if self.deadline is not None and now >= self.deadline:
            return self.COMPUTE_CAP
        return None

    def _final_snapshot_cause(self) -> Optional[str]:
        """Take the source sample which linearizes cap or completion.

        A source-free snapshot is a safe decision point only when the whole
        operation lies on one side of the deadline.  If it straddles the
        boundary, a setter could have published immediately after the read but
        still before the deadline.  Retry after the boundary so that request is
        either observed or any later authenticated timestamp necessarily loses
        to cap.
        """
        while True:
            before = time.monotonic()
            snapshot = self._operator_snapshot()
            after = time.monotonic()
            requested_at, external_visible = snapshot
            if requested_at is not None or external_visible:
                return self._snapshot_cause(snapshot, after)
            if self.deadline is None or after < self.deadline:
                return None
            if before >= self.deadline:
                return self.COMPUTE_CAP
            # ``before < deadline <= after`` with no source: there was no
            # single side of the boundary on which this sample could safely
            # linearize.  The next sample begins after the deadline.

    def _refresh_locked(self, *, terminal_cause: Optional[str] = None
                        ) -> Optional[str]:
        if self._cause is not None:
            return self._cause
        if self._closed.is_set():
            return None

        # First establish the state from which this arbitration attempt began,
        # then sample the monotonic deadline.  ``operator_snapshot`` is atomic
        # with timestamp/flag publication, so it can never return a torn pair.
        initial_snapshot = self._operator_snapshot()
        now = time.monotonic()
        initial_cause = self._snapshot_cause(initial_snapshot, now)
        if initial_cause == self.OPERATOR:
            return self._commit_locked(self.OPERATOR)

        # Do not commit cap or completion from a one-shot observation.  The
        # final atomic sample is their decision linearization point: a request
        # published after the initial sample but before this point participates
        # in the same arbitration.  Sampling time again afterwards also closes
        # the case where the final snapshot waited across the deadline.
        if initial_cause == self.COMPUTE_CAP or terminal_cause is not None:
            final_cause = self._final_snapshot_cause()
            if final_cause is not None:
                return self._commit_locked(final_cause)
            if initial_cause == self.COMPUTE_CAP:
                return self._commit_locked(self.COMPUTE_CAP)
            if terminal_cause != self.COMPLETE:
                raise AssertionError(
                    f"unsupported terminal campaign cause: {terminal_cause}")
            return self._commit_locked(self.COMPLETE)
        return None

    def _watch_operator(self) -> None:
        while not self._closed.is_set():
            if self.external_event.wait(0.01):
                with self._lock:
                    if self._closed.is_set():
                        return
                    self._refresh_locked()
                return

    def _reach_compute_cap(self) -> None:
        with self._lock:
            if self._closed.is_set() or self._cause is not None:
                return
            self._refresh_locked()

    def start(self) -> None:
        # Claim an event supplied already-set before arming the cap timer.
        with self._lock:
            self._refresh_locked()
        self._watcher = threading.Thread(
            target=self._watch_operator, name="r2t-operator-cancel-watch",
            daemon=True)
        self._watcher.start()
        if self.deadline is not None:
            self._timer = threading.Timer(
                max(0.0, self.deadline - time.monotonic()),
                self._reach_compute_cap)
            self._timer.daemon = True
            self._timer.start()

    def cancellation_cause(self) -> Optional[str]:
        """Return a committed stop cause, refreshing deadline/signal state."""
        with self._lock:
            cause = self._refresh_locked()
        return cause if cause in {self.OPERATOR, self.COMPUTE_CAP} else None

    def commit_complete(self) -> str:
        """Commit completion iff neither cancellation cause linearizes first."""
        with self._lock:
            cause = self._refresh_locked(terminal_cause=self.COMPLETE)
            assert cause is not None
            return cause

    def close(self) -> None:
        # Linearize shutdown with every cause commit.  A watcher or timer which
        # won `_lock` first may finish its decision; one which arrives after
        # this point observes `_closed` under that same lock and cannot create
        # a post-close cancellation.
        with self._lock:
            self._closed.set()
        timer = self._timer
        if timer is not None:
            timer.cancel()
            if timer is not threading.current_thread() and timer.is_alive():
                timer.join(timeout=0.1)
        watcher = self._watcher
        if watcher is not None and watcher is not threading.current_thread():
            watcher.join(timeout=0.1)


def _campaign_directory_locked(func):
    """Apply the process lock without indenting the command implementation."""
    @wraps(func)
    def locked(*args, **kwargs):
        out_dir = kwargs.get("out_dir")
        if not isinstance(out_dir, str) or not out_dir:
            raise TestQualityRefused(
                "REFUSED: run_test_quality requires a concrete output "
                "directory for campaign locking.")
        from .mutation_run import (MutationAborted, mutation_resource_locks,
                                   output_lock)
        resources = kwargs.get("resource_identities") or ()
        lifecycle: dict = {}
        kwargs["_campaign_lifecycle"] = lifecycle
        try:
            with output_lock(out_dir):
                with mutation_resource_locks(resources):
                    try:
                        return func(*args, **kwargs)
                    except BaseException as exc:
                        # Mark only a root record this invocation created or
                        # successfully identity-checked for resume.  A failed
                        # attempt to resume some OTHER plan must never mutate
                        # that preserved campaign's state.
                        if lifecycle.get("owned"):
                            message = f"{type(exc).__name__}: {exc}"
                            # TYPED, not textual. `TestQualityCancelled` is
                            # raised only where every collected worker
                            # exception was itself a cancellation, or where
                            # the coordinator stopped between stages with the
                            # event set; nothing else can wear the type, and
                            # no message can accidentally match it.
                            latch = lifecycle.get("first_cause")
                            cause = (latch.cancellation_cause()
                                     if latch is not None else None)
                            cooperative = (
                                isinstance(exc, TestQualityCancelled)
                                and cause in {
                                    _CampaignFirstCause.OPERATOR,
                                    _CampaignFirstCause.COMPUTE_CAP})
                            status = ("interrupted" if cooperative
                                      else "failed")
                            interruption = None
                            if cooperative and lifecycle["plan"].get(
                                    "schema") == TEST_QUALITY_PLAN_SCHEMA_V3:
                                kind = (INTERRUPTION_COMPUTE_CAP
                                        if cause
                                        == _CampaignFirstCause.COMPUTE_CAP
                                        else INTERRUPTION_OPERATOR)
                                interruption = campaign_interruption(
                                    kind, lifecycle["plan"])
                            try:
                                transition_campaign_state(
                                    out_dir, lifecycle["plan"], status,
                                    error=message[:4000],
                                    interruption=interruption)
                            except Exception as state_error:   # noqa: BLE001
                                if hasattr(exc, "add_note"):
                                    exc.add_note(
                                        "also failed to persist root "
                                        f"campaign state: {state_error}")
                        raise
        except MutationAborted as e:
            raise TestQualityRefused(str(e)) from e
        finally:
            latch = lifecycle.get("first_cause")
            if latch is not None:
                latch.close()
    return locked


@_campaign_directory_locked
def run_test_quality(*, run_rows: list, gold_baseline_rows: list,
                     manifest: dict, by_mutant: dict, out_dir: str,
                     execute: Callable[[dict], dict], n_workers: int,
                     gold_results: Optional[list] = None,
                     gold_results_attestation: Optional[dict] = None,
                     gold_results_attestation_path: Optional[str] = None,
                     authenticated_gold: object = None,
                     single_observation_authority: object = None,
                     require_complete: bool = True,
                     allow_degraded_gold: bool = False,
                     candidate_pairs: str = CANDIDATE_PAIRS_ALL,
                     gold_pair_plan: Optional[frozenset] = None,
                     gold_pair_plan_binding: Optional[dict] = None,
                     provenance: Optional[dict] = None,
                     identity_inputs: Optional[dict] = None,
                     timeout: int = 600, resume: bool = False,
                     shard_policy: str = DEFAULT_SHARD_POLICY,
                     compute_cap_seconds: Optional[int] = None,
                     compute_cap_review_authority: Optional[str] = None,
                     execution_policy: Optional[str] = None,
                     batch_plan_sha256: Optional[str] = None,
                     max_batch_members: Optional[int] = None,
                     max_batch_instances: Optional[int] = None,
                     stack_reset_sha256: Optional[str] = None,
                     batch_journal_schema: Optional[str] = None,
                     reuse_projection_sha256: Optional[str] = None,
                     preflight_cache_policy: Optional[str] = None,
                     execution_observation_id: Optional[str] = None,
                     cancel_event: Optional[threading.Event] = None,
                     resource_identities: Iterable[tuple[str, str]] = (),
                     worker_resources: Iterable[dict] = (),
                     hard_subset_doc: Optional[dict] = None,
                     hard_subset_path: Optional[str] = None,
                     sensitivity: Optional[str] = None,
                     candidate_hard_rerun_rows: Optional[list] = None,
                     candidate_hard_rerun_paths: Iterable[str] = (),
                     candidate_hard_rerun_observation_id: Optional[str] = None,
                     d4_confirmation_plan_out: Optional[str] = None,
                     final_summary_validator: Optional[Callable[
                         [dict, str], None]] = None,
                     worker_processes: bool = False,
                     _campaign_lifecycle: Optional[dict] = None) -> dict:
    """Plan, execute, merge, score — the whole command, minus the CLI.

    `execute` is a `run_slice`-equivalent: it is handed a job and returns
    whatever it likes, having written that job's rows to `job["out"]`.  The
    injection is what lets the selftest cover the arithmetic without a
    container, and it is also what keeps the docker-shaped part of this
    command in `cli.py` where every other docker-shaped part lives.
    """
    if shard_policy not in SHARD_POLICIES:
        raise TestQualityRefused(
            f"REFUSED: unknown shard policy {shard_policy!r}; expected one "
            f"of {list(SHARD_POLICIES)}.")
    single_observation = single_observation_authority is not None
    if single_observation:
        _require_single_observation_authority(single_observation_authority)
        if authenticated_gold is not None or gold_results is not None \
                or gold_results_attestation is not None \
                or gold_results_attestation_path is not None:
            raise TestQualityRefused(
                "REFUSED: single-observation reference controls cannot be "
                "combined with v1 cached or authenticated gold inputs.")
        if execution_policy is None or execution_observation_id is None:
            raise TestQualityRefused(
                "REFUSED: single-observation execution requires one explicit "
                "candidate execution policy and observation identity.")
    authenticated_gold_binding = None
    if authenticated_gold is not None:
        if gold_results is not None or gold_results_attestation is not None \
                or gold_results_attestation_path is not None:
            raise TestQualityRefused(
                "REFUSED: authenticated installed gold cannot be combined "
                "with the ordinary cached-gold inputs.")
        gold_results, authenticated_gold_binding = \
            _open_authenticated_gold_selection(authenticated_gold)
    provenance = dict(provenance or {})
    claimed_policy = provenance.get("shard_policy")
    if claimed_policy is not None and claimed_policy != shard_policy:
        raise TestQualityRefused(
            f"REFUSED: caller provenance claims shard policy "
            f"{claimed_policy!r}, but execution requested {shard_policy!r}.")
    worker_resources = list(worker_resources)
    candidate_hard_rerun_paths = list(candidate_hard_rerun_paths)
    candidate_hard_run_1_observation_id = None
    passed = passed_solutions(run_rows)
    require_run_sensitivity(run_rows, sensitivity)
    if sensitivity is not None and single_observation:
        raise TestQualityRefused(
            "REFUSED: a labelled sensitivity replay is not scored against "
            "installed reference controls.")
    hard_inputs = (hard_subset_doc, hard_subset_path)
    if any(value is not None for value in hard_inputs) \
            != all(value is not None for value in hard_inputs):
        raise TestQualityRefused(
            "REFUSED: assertion-hard scoring requires the hard-subset "
            "document and its pinned path together; partial hard inputs "
            "cannot fall back to full-gold scoring.")
    rerun_supplied = candidate_hard_rerun_rows is not None
    if single_observation and (
            any(value is not None for value in hard_inputs)
            or rerun_supplied or d4_confirmation_plan_out is not None):
        raise TestQualityRefused(
            "REFUSED: the single-observation policy accepts no D4 or external "
            "hard-subset inputs.")
    if rerun_supplied != bool(candidate_hard_rerun_paths) \
            or rerun_supplied \
            != (candidate_hard_rerun_observation_id is not None):
        raise TestQualityRefused(
            "REFUSED: candidate hard run 2 rows, native shard paths and its "
            "standalone observation id must be supplied together.")
    if rerun_supplied and hard_subset_doc is None:
        raise TestQualityRefused(
            "REFUSED: candidate hard run 2 has no population-pinned hard "
            "subset denominator.")
    if d4_confirmation_plan_out is not None and hard_subset_doc is None:
        raise TestQualityRefused(
            "REFUSED: --candidate-hard-plan-out requires --hard-subset.")
    if d4_confirmation_plan_out is not None and rerun_supplied:
        raise TestQualityRefused(
            "REFUSED: D4 plan production and run-2 consumption are separate "
            "phases; omit --candidate-hard-plan-out when resuming with "
            "--candidate-hard-rerun.")
    if d4_confirmation_plan_out is not None:
        target = os.path.realpath(os.path.abspath(d4_confirmation_plan_out))
        root = os.path.realpath(os.path.abspath(out_dir))
        try:
            inside = os.path.commonpath((root, target)) == root
        except ValueError:
            inside = False
        if inside or os.path.lexists(d4_confirmation_plan_out):
            raise TestQualityRefused(
                "REFUSED: --candidate-hard-plan-out must be a new path "
                "outside the resumable --out campaign directory.")
    if rerun_supplied:
        from .mutation_run import (MutationAborted, validate_native_shards,
                                   validate_observation_id)
        try:
            validate_observation_id(candidate_hard_rerun_observation_id)
            rerun_campaign = validate_native_shards(
                candidate_hard_rerun_paths, required_side="candidate",
                return_campaign=True)
        except MutationAborted as exc:
            raise TestQualityRefused(str(exc)) from exc
        _hard_rerun_observation_id(
            rerun_campaign, candidate_hard_rerun_observation_id)
        if rerun_campaign["rows"] != candidate_hard_rerun_rows:
            raise TestQualityRefused(
                "REFUSED: candidate hard run-2 rows differ from the exact "
                "terminal native shards named by the summary inputs.")
    if (gold_pair_plan is None) != (gold_pair_plan_binding is None):
        raise TestQualityRefused(
            "REFUSED: a gold pair plan travels with its file binding.")
    if candidate_pairs not in CANDIDATE_PAIR_SCOPES:
        raise TestQualityRefused(
            f"REFUSED: unknown candidate pair scope {candidate_pairs!r}; "
            f"expected one of {list(CANDIDATE_PAIR_SCOPES)}.")
    # A single-observation slice is gold-killed for a full-gold-only
    # reference, or for a labelled stub-gate-waived basis that asks for it
    # (SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md section 2).
    if candidate_pairs == CANDIDATE_PAIRS_GOLD_KILLED and (
            (single_observation
             and getattr(single_observation_authority.sets, "reference_basis", "hard_subset") != "full_gold"
             and getattr(single_observation_authority.sets, "sensitivity", None) is None)
            or hard_subset_doc is not None
            or rerun_supplied or d4_confirmation_plan_out is not None
            or compute_cap_seconds is not None):
        raise TestQualityRefused(
            "REFUSED: --candidate-pairs gold-killed is defined for full-gold "
            "scoring only; the single-observation, hard-subset, D4 and "
            "compute-cap routes read candidate outcomes on pairs gold did "
            "not kill (GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md).")
    if not single_observation and authenticated_gold_binding is None \
            and (gold_results is None) != (gold_results_attestation is None):
        raise TestQualityRefused(
            "REFUSED: --gold-results and its native-or-legacy-consistency "
            "attestation must be supplied together.")
    gold_files, gold_baseline = gold_side(gold_baseline_rows, passed)
    missing_gold = sorted(set(passed) - set(gold_files))
    if missing_gold:
        # Without gold's row for an item there is no eligibility evidence and
        # no solution to execute; scoring it anyway would silently mean
        # "gold kills nothing here", i.e. an unverifiable pass would print as
        # `not_scorable` for an infrastructure reason.
        raise TestQualityRefused(
            f"REFUSED: gold's baseline run has no row for {len(missing_gold)} "
            f"passed item(s), e.g. {missing_gold[:3]}. The gold baseline must "
            f"cover every item being scored — it supplies both the "
            f"eligibility rule's input and the bytes gold's side is executed "
            f"from.")

    mutants, restricted, covering = population(manifest, by_mutant, passed)
    expected = expected_pairs(restricted)
    if single_observation:
        authority = _require_single_observation_authority(
            single_observation_authority)
        # Section 5.1's narrowing is applied to the PLANNED population, not
        # merely asserted against it: the manifest and map still describe the
        # complete mapped set, and executing a pair no control observed would
        # produce a candidate row with nothing to score it against.
        mutants, restricted = _narrow_to_reference(
            mutants, restricted, _reference_excluded_pairs(authority.controls),
            _reference_declared_items(authority.controls))
        expected = expected_pairs(restricted)
        reference_expected = {pair for pair in authority.expected_pairs
                              if pair[0] in set(passed)}
        if expected != reference_expected:
            raise TestQualityRefused(
                "REFUSED: candidate manifest/map scope differs from the exact "
                "sealed reference population restricted to passed items.")
        # Gold is PROJECTED, never executed: `gold_results` being non-None is
        # what collapses `sides` to candidate below, so no gold job object is
        # ever constructed for this campaign.
        if getattr(authority.sets, "reference_basis", "hard_subset") == "full_gold":
            if candidate_pairs != CANDIDATE_PAIRS_GOLD_KILLED or gold_pair_plan is not None:
                raise TestQualityRefused("REFUSED: full-gold-only controls require gold-killed candidate scope without a gold pair plan")
        if candidate_pairs == CANDIDATE_PAIRS_GOLD_KILLED:
            # Settled here, before planning, so the shards, the root plan,
            # the gold projection and every executed-pair identity below
            # are the slice's.
            if gold_pair_plan is not None:
                raise TestQualityRefused(
                    "REFUSED: a single-observation gold-killed slice comes "
                    "from the sealed reference, never a gold pair plan.")
            expected = single_observation_candidate_pairs(
                authority, passed, candidate_pairs)
            mutants, restricted = restrict_to_pairs(mutants, restricted, expected)
        gold_results = _single_observation_gold_rows(authority, expected)
    if (compute_cap_seconds is None) \
            != (compute_cap_review_authority is None):
        raise TestQualityRefused(
            "REFUSED: --compute-cap-seconds and "
            "--compute-cap-review-authority must be supplied together.")
    compute_cap = None
    compute_cap_sha256 = None
    estimand_pairs_sha256 = None
    observation_id = None
    if compute_cap_seconds is not None:
        from .mutation_run import content_digest, pair_set_digest
        compute_cap = build_compute_cap(
            wall_clock_seconds=compute_cap_seconds,
            workers=n_workers, expected=expected, campaign_dir=out_dir,
            review_authority=compute_cap_review_authority)
        compute_cap_sha256 = content_digest(compute_cap)
        estimand_pairs_sha256 = pair_set_digest(expected)
        # This identifies one physical observation, unlike the reproducible
        # campaign digest. A cap-bound v1 campaign cannot resume, so this id is
        # minted once and never has to be guessed or regenerated.
        observation_id = secrets.token_hex(16)
    hard_sets = None
    hard_population_id = None
    if hard_subset_doc is not None:
        hard_population_id = registered_population_id(
            (identity_inputs or {}).get("asset_project",
             hard_subset_doc.get("population", {}).get("project")),
            manifest.get("digest"), manifest.get("engine"),
            manifest.get("engine_version"))
        if hard_population_id is None:
            raise TestQualityRefused(
                "REFUSED: hard-subset scoring requires a registered mutation "
                "population; an unregistered fixture cannot publish this "
                "verdict basis.")
        hard_sets = hard_kill_sets(
            hard_subset_doc, population_id=hard_population_id, items=passed,
            manifest_digest=manifest.get("digest"))
        hard_pairs = {(item_id, mutant_id)
                      for item_id, values in hard_sets.items()
                      for mutant_id in values}
        outside = sorted(hard_pairs - expected)
        if outside:
            raise TestQualityRefused(
                "REFUSED: hard subset cites pair(s) outside the candidate's "
                f"frozen manifest/map population, e.g. {outside[:3]}.")
    from .mutation_run import (CAMPAIGN_IDENTITY_FIELDS_V2_ADDED,
                               CAMPAIGN_IDENTITY_FIELDS_V4_ADDED,
                               pair_set_digest)
    candidate_path = os.path.join(out_dir, CANDIDATE_ROWS)
    gold_path = os.path.join(out_dir, GOLD_ROWS)

    def _refuse_short_gold(short: list) -> None:
        raise TestQualityRefused(
            f"REFUSED: gold's rows cover {len(expected) - len(short)} of "
            f"{len(expected)} (item, mutant) executions, e.g. "
            f"{short[:3]} are absent. A short GOLD file shrinks the very set "
            f"the candidate is measured against, so the candidate would score "
            f"HIGHER for gold having run less. Drop --gold-results to execute "
            f"gold over this population, or pass --allow-incomplete and read "
            f"the number as being over the smaller population.")

    gold_rows: Optional[list] = None
    if gold_results is not None:
        # Attestation is for these exact bytes and this exact pair set.  A
        # larger gate file must first be filtered and validated into a new
        # preserved artifact; silently filtering here would make its original
        # attestation a claim about bytes it never named.
        gold_rows = list(gold_results)
        # Checked BEFORE the candidate slices run.  They are the expensive
        # half — hours, on borrowed workers — and a refusal afterwards has
        # already spent them to learn something knowable from a file read.
        short = missing_pairs(expected, gold_rows)
        if short and require_complete:
            _refuse_short_gold(short)
    # Which pairs each side executes, settled before either side runs.  Under
    # `all` this is the population above, unchanged; `expected` stays gold's
    # pair set (the estimand) and the candidate slice may be narrower.
    scope = candidate_pair_scope(
        scope=(CANDIDATE_PAIRS_ALL if single_observation else candidate_pairs), passed=passed, mutants=mutants,
        restricted=restricted, gold_rows=gold_rows,
        gold_baseline=gold_baseline, gold_plan=gold_pair_plan)
    expected, candidate_expected = scope["expected"], scope["candidate"]

    inputs = identity_inputs_for_test_quality(
        run_rows=run_rows, gold_baseline_rows=gold_baseline_rows,
        manifest=manifest, by_mutant=by_mutant, gold_results=gold_results,
        gold_results_attestation=gold_results_attestation,
        exact=identity_inputs)
    if single_observation:
        from .mutation_run import content_digest
        controls = _require_single_observation_authority(
            single_observation_authority).controls
        # `exact` overwrote the projection's own digest with the CLI's
        # (absent) --gold-results file digest; restore it, and bind the
        # attestation slot to the reference artifact these rows came from.
        inputs.update({
            "gold_results_sha256": content_digest(gold_results),
            "gold_results_attestation_sha256": controls["digest"],
            "gold_provenance_class": "native",
            "gold_attestation_manifest_digest": manifest.get("digest"),
            "gold_attestation_pairs_sha256": pair_set_digest(expected),
            "gold_attestation_engine": inputs["engine"],
            "gold_attestation_engine_version": inputs["engine_version"],
        })
    gold_provenance_class = "native"
    if authenticated_gold_binding is not None:
        gold_binding = authenticated_gold_binding
        from .mutation_run import pair_set_digest
        expected_binding = {
            "manifest_digest": manifest.get("digest"),
            "pairs_sha256": pair_set_digest(expected),
            "engine": inputs["engine"],
            "engine_version": inputs["engine_version"],
            "gold_results_sha256": inputs.get("gold_results_sha256"),
            "gold_results_attestation_sha256": inputs.get(
                "gold_results_attestation_sha256"),
            "gold_results_source": provenance.get("gold_results_source"),
            "gold_results_attestation": provenance.get(
                "gold_results_attestation"),
        }
        changed = sorted(
            key for key, value in expected_binding.items()
            if gold_binding.get(key) != value)
        if gold_binding.get("validation_class") != "native" or changed:
            raise TestQualityRefused(
                "REFUSED: authenticated installed gold differs from the "
                f"candidate population/engine in field(s) {changed}.")
        for key in ("gold_results_sha256",
                    "gold_results_attestation_sha256"):
            value = inputs.get(key)
            if not isinstance(value, str) or len(value) != 64 \
                    or any(ch not in "0123456789abcdef" for ch in value):
                raise TestQualityRefused(
                    "REFUSED: authenticated installed gold has no exact raw "
                    f"{key} authority.")
        gold_provenance_class = gold_binding["validation_class"]
        inputs.update({
            "gold_attestation_manifest_digest":
                gold_binding["manifest_digest"],
            "gold_attestation_pairs_sha256": gold_binding["pairs_sha256"],
            "gold_attestation_engine": gold_binding["engine"],
            "gold_attestation_engine_version":
                gold_binding["engine_version"],
        })
    elif gold_results is not None and not single_observation:
        gold_binding = validate_precomputed_gold_attestation(
            gold_results_attestation or {}, inputs=inputs, passed=passed,
            gold_files=gold_files, expected=expected,
            gold_rows=gold_results, manifest_digest=manifest.get("digest"),
            require_complete=require_complete,
            attestation_path=gold_results_attestation_path,
            timeout=timeout)
        gold_provenance_class = gold_binding["validation_class"]
        inputs.update({
            "gold_attestation_manifest_digest":
                gold_binding["manifest_digest"],
            "gold_attestation_pairs_sha256": gold_binding["pairs_sha256"],
            "gold_attestation_engine": gold_binding["engine"],
            "gold_attestation_engine_version":
                gold_binding["engine_version"],
        })
    inputs["gold_provenance_class"] = (
        gold_provenance_class if gold_results is not None else None)

    # Still BEFORE the candidate slices run, and after the attestation has
    # settled which class this gold is: whether it may be scored at all is a
    # question about bytes already on disk, and answering it after the
    # expensive half has run would spend hours to learn something a file read
    # decides.  Freshly executed gold cannot be degraded on arrival — its rows
    # do not exist yet — so the disclosure block is the empty one there.
    if gold_results is not None and not single_observation:
        degradation = check_gold_degradation(
            gold_rows or [], gold_baseline, passed,
            gold_provenance_class=gold_provenance_class,
            require_complete=require_complete,
            allow_degraded_gold=allow_degraded_gold)
    else:
        degradation = {"gold_infrastructure_pairs": [],
                       "gold_infrastructure_class": "none",
                       "allow_degraded_gold": bool(allow_degraded_gold)}
    sides = SIDES if gold_results is None else ("candidate",)
    bind_shard_policy = (
        _resume_policy_identity_binding(out_dir, shard_policy)
        if resume else True)
    from .mutation_run import (EXECUTION_POLICY_BATCH_BISECT_V1,
                               EXECUTION_POLICY_SCALAR_V1,
                               pair_set_digest, validate_observation_id)
    execution_values = (
        execution_policy, batch_plan_sha256, max_batch_members,
        max_batch_instances, stack_reset_sha256, batch_journal_schema,
        reuse_projection_sha256, preflight_cache_policy,
        execution_observation_id,
    )
    if any(value is not None for value in execution_values):
        if execution_policy not in {
                EXECUTION_POLICY_SCALAR_V1,
                EXECUTION_POLICY_BATCH_BISECT_V1}:
            raise TestQualityRefused(
                "REFUSED: live execution has no supported bound policy.")
        try:
            validate_observation_id(execution_observation_id)
        except Exception as exc:                          # noqa: BLE001
            raise TestQualityRefused(str(exc)) from exc
        estimand_pairs_sha256 = pair_set_digest(expected)
    jobs = plan_jobs(scope["mutants"],
                     {"candidate": passed, "gold": gold_files},
                     scope["restricted"], n_workers, out_dir, sides=sides,
                     provenance=provenance, identity_inputs=inputs,
                     timeout=timeout, resume=resume,
                     shard_policy=shard_policy,
                     bind_shard_policy=bind_shard_policy,
                     compute_cap_sha256=compute_cap_sha256,
                     execution_policy=execution_policy,
                     batch_plan_sha256=batch_plan_sha256,
                     max_batch_members=max_batch_members,
                     max_batch_instances=max_batch_instances,
                     stack_reset_sha256=stack_reset_sha256,
                     batch_journal_schema=batch_journal_schema,
                     reuse_projection_sha256=reuse_projection_sha256,
                     preflight_cache_policy=preflight_cache_policy,
                     estimand_pairs_sha256=estimand_pairs_sha256,
                     observation_id=(execution_observation_id
                                     if execution_policy is not None
                                     else observation_id))
    campaign_plan = (_zero_pair_candidate_plan(
        authority=single_observation_authority, passed=passed, inputs=inputs,
        worker_resources=worker_resources, shard_policy=shard_policy,
        observation_id=execution_observation_id)
        if single_observation and not expected else
        build_test_quality_campaign_plan(
            jobs, expected=expected, require_complete=require_complete,
            gold_precomputed=gold_results is not None,
            # The v2 slice was settled above from the sealed reference;
            # `scope["record"]` is v1's and stays None there, so v1's
            # withholding never touches a v2 summary.
            candidate_scope=(_single_observation_scope_record(
                single_observation_authority, expected, candidate_pairs)
                if single_observation else scope["record"]),
            worker_resources=worker_resources, campaign_dir=out_dir,
            compute_cap=compute_cap, sensitivity=sensitivity))
    if rerun_supplied:
        candidate_hard_run_1_observation_id = \
            _d4_run_1_observation_id(campaign_plan)
        if candidate_hard_run_1_observation_id \
                == candidate_hard_rerun_observation_id:
            raise TestQualityRefused(
                "REFUSED: D4 candidate run 2 copied run 1's observation_id; "
                "the two complete executions are not independently "
                "identified.")
    prepare_output_directory(
        out_dir, jobs, resume=resume, campaign_plan=campaign_plan)
    if single_observation and not expected:
        os.makedirs(os.path.join(out_dir, SHARD_DIR), exist_ok=True)
    lifecycle = _campaign_lifecycle if _campaign_lifecycle is not None else {}
    from .mutation_run import CoordinatorCancellationEvent
    external_cancel_event = (
        cancel_event if cancel_event is not None
        else CoordinatorCancellationEvent())
    # Forked workers (`worker_processes`) observe the parent's stop only
    # through an event that lives in shared memory.
    if worker_processes:
        import multiprocessing
        worker_cancel_event = multiprocessing.get_context("fork").Event()
    else:
        worker_cancel_event = threading.Event()
    cap_deadline = (time.monotonic() + compute_cap["wall_clock_seconds"]
                    if compute_cap is not None else None)
    first_cause = _CampaignFirstCause(
        external_cancel_event, worker_cancel_event, deadline=cap_deadline)
    lifecycle.update({"owned": True, "plan": campaign_plan,
                      "external_cancel_event": external_cancel_event,
                      "worker_cancel_event": worker_cancel_event,
                      "first_cause": first_cause})
    # The durable running root exists now. Arm both stop sources before any
    # worker is dispatched, with the monotonic deadline already fixed above.
    first_cause.start()

    def require_active(stage: str) -> None:
        if first_cause.cancellation_cause() is not None:
            raise TestQualityCancelled(
                "REFUSED: mutation campaign was cooperatively cancelled; "
                f"stopped before {stage} and no score was produced.")

    for job in jobs:
        job["cancel_event"] = worker_cancel_event
    require_active("worker execution")
    infos = execute_jobs(jobs, execute, cancel_event=worker_cancel_event,
                         processes=worker_processes)
    require_active("post-worker validation")
    validate_output_contents(
        out_dir, jobs, campaign_plan=campaign_plan,
        campaign_status="running")

    # D4 is deliberately two phase.  A qualifying pair set does not exist
    # until the complete first observation exists, while the second
    # observation must be a separately owned standalone mutation-run.  When
    # requested, stop at that exact boundary: authenticate run 1, write the
    # derived plan outside the resumable root, and leave every completed shard
    # plus the root state untouched for `--resume` after run 2 is produced.
    if d4_confirmation_plan_out is not None:
        if hard_sets is None or hard_subset_doc is None \
                or hard_subset_path is None:
            raise TestQualityRefused(
                "REFUSED: D4 plan production lost its hard-subset inputs.")
        candidate_preview = merge_rows(
            [job for job in jobs if job["side"] == "candidate"], None,
            expected=expected, side="candidate")
        _run_1, _hard_pairs, _qualifying_items, qualifying_pairs = \
            _candidate_hard_qualification(candidate_preview, hard_sets)
        if qualifying_pairs:
            required_paths = {
                key: provenance.get(key)
                for key in ("run", "mutation_validation", "manifest", "map",
                            "release")
            }
            missing_paths = sorted(
                key for key, value in required_paths.items()
                if not isinstance(value, str) or not value)
            if missing_paths:
                raise TestQualityRefused(
                    "REFUSED: D4 plan production requires canonical input "
                    f"path provenance for {missing_paths}.")
            plan_inputs = {**inputs, **required_paths}
            d4_plan = build_d4_confirmation_plan(
                campaign_plan=campaign_plan, out_dir=out_dir,
                candidate_jobs=[job for job in jobs
                                if job["side"] == "candidate"],
                candidate_rows=candidate_preview, expected=expected,
                hard_sets=hard_sets, hard_subset_doc=hard_subset_doc,
                hard_subset_path=hard_subset_path,
                identity_inputs=plan_inputs, run_path=required_paths["run"],
                timeout=timeout, population_id=hard_population_id)
            plan_path = write_d4_confirmation_plan(
                d4_confirmation_plan_out, d4_plan)
            return {
                "schema": D4_CONFIRMATION_PENDING_SCHEMA,
                "status": "awaiting_d4_confirmation",
                "plan": plan_path,
                "plan_digest": d4_plan["digest"],
                "root_campaign": os.path.abspath(out_dir),
                "root_campaign_plan_sha256": d4_plan["source"][
                    "campaign_plan_sha256"],
                "run_1_observation_id": d4_plan["source"][
                    "observation_id"],
                "qualifying_items": d4_plan["qualification"]["items"],
                "expected_pairs": d4_plan["qualification"][
                    "expected_pairs"],
                "expected_pairs_sha256": d4_plan["qualification"][
                    "expected_pairs_sha256"],
            }

    require_active("candidate merge")
    if single_observation and not expected:
        from .mutation_run import atomic_write_bytes
        atomic_write_bytes(candidate_path, b"", refuse_existing=True)
        candidate_rows = []
    else:
        candidate_rows = merge_rows(
            [j for j in jobs if j["side"] == "candidate"], candidate_path,
            expected=candidate_expected, side="candidate")
        require_active("gold merge")
    if gold_rows is None:
        gold_rows = merge_rows(
            [j for j in jobs if j["side"] == "gold"], gold_path,
            expected=expected, side="gold")
    else:
        # The attested rows are copied into --out even though they came from
        # elsewhere: the summary's evidence must be the rows this measurement
        # actually used, not a file that has since moved on.
        from .mutation_run import MutationAborted, atomic_write_bytes
        seen_gold = set()
        for row in gold_rows:
            pair = (row["item_id"], row["mutant_id"])
            if pair in seen_gold:
                raise TestQualityRefused(
                    f"REFUSED: precomputed gold has duplicate pair {pair}.")
            seen_gold.add(pair)
        payload = "".join(json.dumps(row, sort_keys=True) + "\n"
                          for row in gold_rows).encode("utf-8")
        try:
            atomic_write_bytes(gold_path, payload, refuse_existing=True)
        except MutationAborted as e:
            raise TestQualityRefused(str(e)) from e

    require_active("merged-row validation")
    validate_output_contents(
        out_dir, jobs, final_names=(CANDIDATE_ROWS, GOLD_ROWS),
        campaign_plan=campaign_plan, campaign_status="running")

    require_active("completeness checking")
    short_gold = missing_pairs(expected, gold_rows)
    if short_gold and require_complete:
        _refuse_short_gold(short_gold)

    # Before any arithmetic: are these rows one population?  A mixed-engine
    # merge is not a scoring problem to be handled downstream, it is a claim
    # this command must not make at all.
    engines = engine_report(manifest, candidate_rows, gold_rows)
    for key in ("engine", "engine_version"):
        theirs = provenance.get(key)
        if theirs is not None and engines[key] is not None \
                and theirs != engines[key]:
            raise TestQualityRefused(
                f"REFUSED: the caller's provenance says {key}={theirs!r} but "
                f"the manifest says {engines[key]!r}. The manifest is what "
                f"defines the population; a summary carrying the other label "
                f"would cite an engine that did not produce it.")

    require_active("scoring")
    gold_killed, ignored, gold_infrastructure = gold_kill_sets(
        scored_gold_rows(gold_rows, provenance, gold_pair_plan),
        gold_baseline, passed)
    # The disclosure ruling 2.6 requires, recomputed from the rows the score is
    # actually made of.  `require_complete=False` here is not a relaxation: the
    # refusal has already happened above, before the candidate ran, and freshly
    # executed gold cannot be refused at this point without destroying the
    # campaign's own evidence after paying for it.  What degraded FRESH gold
    # loses is the RENDERED primary (item 6's predicate), never the rows.
    # A projected reference leg cannot be degraded: every row is `failed` or
    # `passed` by construction, and the pairs the three observations DID
    # flake on left the scored universe before the artifact was minted.
    final_degradation = ({
        "gold_infrastructure_outcomes": 0,
        "gold_infrastructure_pairs": [],
        "gold_infrastructure_class": "none",
    } if single_observation else check_gold_degradation(
        gold_rows, gold_baseline, passed,
        gold_provenance_class=gold_provenance_class,
        require_complete=False, allow_degraded_gold=allow_degraded_gold))
    if final_degradation["gold_infrastructure_outcomes"] != gold_infrastructure:
        raise TestQualityRefused(                           # pragma: no cover
            f"REFUSED: the per-item infrastructure disclosure names "
            f"{final_degradation['gold_infrastructure_outcomes']} pair(s) but "
            f"the summary counts {gold_infrastructure}. A disclosure that is "
            f"not the number it discloses is worse than none.")
    population_id = (single_observation_authority.controls["population"]["id"]
                     if single_observation else registered_population_id(
                         inputs["asset_project"], manifest.get("digest"),
                         engines.get("engine"), engines.get("engine_version")))
    # The rule the summary's re-derivation applies to its harness version.
    unscored = unscored_mutants(inputs["harness_version"])
    summary = (score_single_observation(
        passed, candidate_rows, authority=single_observation_authority,
        expected=expected, unscored=unscored,
        candidate_pair_scope=candidate_pairs)
        if single_observation else score(
            passed, covering, gold_killed, gold_baseline, candidate_rows,
            expected=(candidate_expected if require_complete else None),
            hard_killed=hard_sets,
            candidate_rows_run_2=candidate_hard_rerun_rows,
            unscored=unscored))
    if scope["record"] is not None:
        withhold_gold_killed_companions(summary)
    require_active("summary construction")
    summary.update({
        "schema": (TEST_QUALITY_SUMMARY_SCHEMA_V2
                   if single_observation else TEST_QUALITY_SUMMARY_SCHEMA),
        "mutants_in_population": len(mutants),
        "pairs_expected": len(expected),
        "pairs_executed_candidate": len(candidate_rows),
        "pairs_executed_gold": len(gold_rows),
        "gold_kills_ignored_ineligible_baseline": ignored,
        "gold_infrastructure_outcomes": gold_infrastructure,
        "gold_infrastructure_pairs": final_degradation[
            "gold_infrastructure_pairs"],
        "gold_infrastructure_class": final_degradation[
            "gold_infrastructure_class"],
        "allow_degraded_gold": bool(allow_degraded_gold),
        "gold_rows_precomputed": gold_results is not None,
        **gold_killed_summary_fields(scope, gold_pair_plan_binding),
        "gold_provenance_class": gold_provenance_class,
        "gold_rows_missing": len(short_gold),
        "require_complete": require_complete,
        "workers": n_workers,
        **({
            "compute_cap": compute_cap,
            "compute_cap_sha256": compute_cap_sha256,
            **{key: campaign_plan[key] for key in (
                "projection_by_side", "observation_ids_by_side",
                "estimand_pairs_sha256", "delta_pairs_sha256_by_side",
                "final_artifact_types_by_side")},
            **{key: jobs[0]["identity"].get(key)
               for key in sorted(CAMPAIGN_IDENTITY_FIELDS_V4_ADDED)},
        } if compute_cap is not None else {}),
        "jobs": [{"side": j["side"], "worker": j["worker"],
                  "mutants": len(j["mutants"]), "out": j["out"]}
                 for j in jobs],
        "slices": infos,
        "candidate_results": os.path.abspath(candidate_path),
        "gold_results": os.path.abspath(gold_path),
        **provenance,
        # Method identity is authoritative here.  Caller provenance is
        # checked above, then expanded before this field so it cannot relabel
        # a balanced root campaign as historical striding.
        "shard_policy": shard_policy,
        "asset_index_sha256": inputs["asset_index_sha256"],
        "asset_project": inputs["asset_project"],
        "mutation_validation_sha256": inputs[
            "mutation_validation_sha256"],
        "mutation_validation_class": inputs[
            "mutation_validation_class"],
        **{key: inputs[key] for key in
           ("population_basis", "budgeted_sample_sha256", "parent_map_sha256")
           if key in inputs},
        "manifest_digest": manifest.get("digest"),
        **({"population_id": population_id} if population_id else {}),
        "manifest_sha256": inputs["manifest_sha256"],
        "map_sha256": inputs["map_sha256"],
        "release_sha256": inputs["release_sha256"],
        "candidate_run_sha256": inputs["candidate_run_sha256"],
        "candidate_generated_tests_sha256": inputs[
            "candidate_generated_tests_sha256"],
        "gold_baseline_sha256": inputs["gold_baseline_sha256"],
        "gold_generated_tests_sha256": inputs[
            "gold_generated_tests_sha256"],
        "gold_results_attestation_sha256": inputs.get(
            "gold_results_attestation_sha256"),
        "gold_results_sha256": inputs.get("gold_results_sha256"),
        "gold_attestation_manifest_digest": inputs.get(
            "gold_attestation_manifest_digest"),
        "gold_attestation_pairs_sha256": inputs.get(
            "gold_attestation_pairs_sha256"),
        "gold_attestation_engine": inputs.get("gold_attestation_engine"),
        "gold_attestation_engine_version": inputs.get(
            "gold_attestation_engine_version"),
        "applier_sha256": inputs["applier_sha256"],
        "substrate_baseline_sha256": inputs[
            "substrate_baseline_sha256"],
        "worker_resources_sha256": inputs["worker_resources_sha256"],
        "worker_resources": list(worker_resources),
        "harness_version": inputs["harness_version"],
        "container_image_digest": inputs["container_image_digest"],
        "workspace_seed_digest": inputs["workspace_seed_digest"],
        "database_dump_digest": inputs["database_dump_digest"],
        "parser": inputs["parser"],
        # WHICH ATTEMPT PRODUCED THE CANDIDATE (v2).  On the summary and not
        # only inside the shard identities, because the summary is what
        # `report`, `results` and a human read: a published recall number
        # that cannot say which generation attempt its candidate came from is
        # the state report §8.4 asked about and finding 20 found already real.
        **{key: inputs.get(key)
           for key in sorted(CAMPAIGN_IDENTITY_FIELDS_V2_ADDED)},
        "expected_pairs_sha256": pair_set_digest(expected),
        "binding": {
            "schema": TEST_QUALITY_BINDING_SCHEMA,
            "run_sha256": inputs["candidate_run_sha256"],
            "generated_tests_sha256": inputs[
                "candidate_generated_tests_sha256"],
        },
        # LAST, and deliberately after the caller's provenance: the engine a
        # recall is labelled with comes from the manifest that defined the
        # population, never from whatever the caller happened to pass.  A
        # caller that disagreed was refused above, so this overwrites nothing
        # but an identical value.
        **engines,
    })
    if single_observation:
        authority = _require_single_observation_authority(
            single_observation_authority)
        controls = authority.controls
        summary.update({
            "policy": FULL_POPULATION_SINGLE_OBSERVATION_POLICY,
            "method": SINGLE_OBSERVATION_METHOD,
            "candidate_observation_count": 1,
            "reference_observation_count": 1,
            "candidate_observation_id": execution_observation_id,
            "timeout_seconds": timeout,
            "reference_controls": {
                "schema": controls["schema"],
                "digest": controls["digest"],
                "population_id": controls["population"]["id"],
                "observation_ids": {
                    role: record["observation_id"]
                    for role, record in controls["observations"].items()
                },
            },
        })
    # Current summaries never use field absence as a compatibility signal.
    # LAST, after caller provenance, so a caller cannot relabel a full-gold
    # sensitivity as hard evidence (or vice versa).
    summary["verdict_basis"] = (
        (getattr(single_observation_authority.sets, "reference_basis", "hard_subset")
         if single_observation else "hard_subset" if hard_subset_doc is not None else "full_gold"))
    if sensitivity is not None:
        summary["sensitivity"] = sensitivity
    from .mutation_run import (MutationAborted, atomic_write_json,
                               campaign_identity_digest, content_digest,
                               sha256_file)
    if hard_subset_doc is not None:
        summary.update({
            "hard_subset": os.path.abspath(hard_subset_path),
            "hard_subset_digest": hard_subset_doc["digest"],
            "hard_subset_sha256": sha256_file(hard_subset_path),
            "hard_subset_population_id": hard_population_id,
        })
        if rerun_supplied:
            summary.update({
                "candidate_hard_rerun_results": [
                    os.path.abspath(path)
                    for path in candidate_hard_rerun_paths],
                "candidate_hard_rerun_sha256": [
                    sha256_file(path) for path in candidate_hard_rerun_paths],
                "candidate_hard_rerun_observation_id": (
                    candidate_hard_rerun_observation_id),
                "candidate_hard_run_1_observation_id": (
                    candidate_hard_run_1_observation_id),
            })
    summary["candidate_rows_sha256"] = sha256_file(candidate_path)
    summary["gold_rows_sha256"] = sha256_file(gold_path)
    summary["root_campaign_plan_sha256"] = content_digest(campaign_plan)
    summary["mutation_campaign_digests"] = sorted(
        campaign_identity_digest(j["identity"]) for j in jobs)
    if single_observation:
        # `infos` is whatever the injected executor returned; the v2 summary
        # states its slices from the jobs the root planned instead.
        summary["slices"] = [{
            "out": job["out"],
            "rows": len(load_jsonl(job["out"])),
            "side": job["side"],
        } for job in jobs]
        # The reader's optional set is deliberately NOT consulted here.
        # The grandfather is for READING a document written before the
        # declared-subset disclosure existed; a run executing today has
        # the disclosure to write and must write it.
        fields = _single_observation_summary_fields(summary.get("verdict_basis") == "full_gold")
        if getattr(single_observation_authority.sets, "sensitivity",
                   None) is not None:
            fields |= SENSITIVITY_SUMMARY_FIELDS
        if candidate_pairs == CANDIDATE_PAIRS_GOLD_KILLED:
            fields |= GOLD_KILLED_SUMMARY_FIELDS
        missing = sorted(fields - set(summary))
        if missing:
            raise TestQualityRefused(
                "REFUSED: v2 summary construction omitted required field(s) "
                f"{missing}.")
        # Exact-field, so the v1 gold-degradation and cached-gold disclosures
        # this route cannot mean do not travel beside numbers they describe.
        summary = {key: summary[key] for key in fields}
    require_active("summary write")
    summary_path = os.path.join(out_dir, SUMMARY)
    summary_written = False
    try:
        atomic_write_json(summary_path, summary,
                          refuse_existing=True)
        summary_written = True
    except MutationAborted as e:
        raise TestQualityRefused(str(e)) from e
    final_names = (CANDIDATE_ROWS, GOLD_ROWS, SUMMARY)
    try:
        require_active("final artifact validation")
        validate_output_contents(
            out_dir, jobs, final_names=final_names,
            campaign_plan=campaign_plan, campaign_status="running")
        if final_summary_validator is not None:
            if not callable(final_summary_validator):
                raise TestQualityRefused(
                    "REFUSED: final summary validator is not callable.")
            final_summary_validator(summary, summary_path)
        completion_cause = first_cause.commit_complete()
        if completion_cause != _CampaignFirstCause.COMPLETE:
            raise TestQualityCancelled(
                "REFUSED: mutation campaign cancellation linearized before "
                "root completion; no score was committed.")
        transition_campaign_state(
            out_dir, campaign_plan, "complete",
            artifacts={name: sha256_file(os.path.join(out_dir, name))
                       for name in final_names})
    except Exception:
        if summary_written:
            try:
                os.unlink(summary_path)
            except FileNotFoundError:                     # pragma: no cover
                pass
        raise
    validate_output_contents(
        out_dir, jobs, final_names=final_names,
        campaign_plan=campaign_plan, campaign_status="complete")
    return summary


def write_sidecar(summary: dict, run_path: str) -> str:
    """Put the summary where `report` will find it, beside the run."""
    from .mutation_run import MutationAborted, atomic_write_json
    summary = bind_summary(summary, run_path)
    path = sidecar_paths(run_path)[0]
    try:
        atomic_write_json(path, summary, refuse_existing=True,
                          allow_identical=True)
    except MutationAborted as e:
        raise TestQualityRefused(str(e)) from e
    return path


def _print_single_observation_summary(summary: dict) -> None:
    """The v2 console: one candidate observation against sealed controls.

    A separate printer rather than a widened one.  Every per-item field the
    v1 block reads — `recall`, `candidate_killed`, `gold_killed`,
    `not_scorable_reason` — is absent from a v2 entry, and the two numbers
    section 5.1 requires beside every derived number are absent from a v1
    one.  `publication_ready` is deliberately NOT consulted: its predicate is
    v1's (a hard-subset artifact digest, a gold-row shortfall, a gold
    infrastructure counter), and none of those exist here.
    """
    if summary["verdict_basis"] == "full_gold":
        print(f"test quality (single observation): full_gold recall {summary['full_recall_macro']}; "
              f"non-vacuous passes {summary['non_vacuous_passes']}/{summary['n_passed']}")
        print(f"  gold-killed candidate pairs: {summary['candidate_pairs']}; "
              f"reference exclusions {summary['reference_excluded_count']}; "
              f"candidate exclusions {summary['candidate_excluded_count']}")
        print("  only-generated kills and Jaccard: not measured; hard subset and stub gate: not defined")
        return
    macro = summary["hard_recall_macro"]
    print(f"\ntest quality (single observation): {summary['n_passed']} "
          f"passed item(s), {summary['n_scorable']} scorable, macro hard "
          f"recall {'-' if macro is None else format(macro, '.3f')} over "
          f"{summary['candidate_scored_pairs']} scored pair(s) of "
          f"{summary['candidate_pairs']} executed")
    sensitivity = summary.get("sensitivity")
    if sensitivity:
        gate = summary["reference_stub_gate"]
        print(f"  LABELLED POST-HOC SENSITIVITY {sensitivity} "
              f"(inference_valid: false): reference stub gate WAIVED, "
              f"disclosed diagnostic {gate['macro_recall']:.4f} vs <= "
              f"{gate['threshold']} (eligible: {gate['eligible']}); "
              f"{len(summary['reference_gold_disagreements']['pairs'])} gold "
              f"disagreement pair(s) removed from G and the hard subset")
    gold_killed = (summary.get("candidate_pair_scope")
                   == CANDIDATE_PAIRS_GOLD_KILLED)
    if gold_killed:
        print(f"  candidate pairs: gold-killed only ({summary['candidate_pairs']} "
              f"full-gold kill pair(s) of the passes); "
              + GOLD_KILLED_NOT_MEASURED + ": "
              + ", ".join(summary["withheld_measures"]))
    print("  verdict basis: hard_subset (single_observation, reference "
          f"controls {summary['reference_controls']['digest'][:12]}, "
          f"population {summary['population_id']})")
    # Section 5.1: BOTH excluded counts, beside the numbers derived from
    # them, on the screen the operator is already looking at.
    print(f"  section 5.1 exclusions: "
          f"{summary['reference_excluded_count']} reference pair(s) of "
          f"{summary['reference_pairs'] + summary['reference_excluded_count']}"
          f" mapped; {summary['candidate_excluded_count']} candidate pair(s) "
          f"in this run")
    # `.get`, because a summary written before the disclosure existed
    # carries neither key and reads as undeclared, which is no line at all.
    if summary.get("reference_omitted_items"):
        print(f"  declared reference subset: "
              f"{summary['reference_omitted_items']} released item(s) omitted "
              f"-- {summary.get('reference_declared_reason')}")
    excluded = summary["candidate_excluded_pairs"]
    for entry in excluded[:10]:
        print(f"    {entry['outcome']:<20} {entry['mutant_id']}  "
              f"{str(entry['item_id']).split('features/domain/')[-1]}")
    if len(excluded) > 10:
        print(f"    ... {len(excluded) - 10} more (full list in the "
              "summary's candidate_excluded_pairs)")
    for label, key in (("full recall", "full_recall_macro"),
                       ("full jaccard", "full_jaccard_macro"),
                       ("candidate-only", "full_only_generated_macro")):
        value = summary[key]
        print(f"  companion ({label}, full_gold basis): "
              + ("not measured" if gold_killed and key != "full_recall_macro"
                 else '-' if value is None else format(value, '.3f')))
    print("  generation provenance: "
          f"{summary.get('generation_provenance_class')}")
    if summary.get("engine"):
        print(f"  engine: {summary['engine']} "
              f"{summary.get('engine_version') or '?'}")
    for verdict in VERDICTS:
        note = ("  <- non_vacuous_pass_at_1 counts these"
                if verdict == EQUIVALENT else "")
        print(f"  {verdict:<24} {summary['verdicts'][verdict]:>4}{note}")
    for iid, item in sorted(summary["per_item"].items()):
        r = item["hard_recall"]
        short = iid.split("features/domain/")[-1]
        print(f"  {item['verdict']:<24} "
              f"{item['hard_candidate_killed']:>3}/"
              f"{item['hard_gold_killed']:<3} "
              f"hard recall {'-' if r is None else format(r, '.3f'):>5} "
              f"of {item['mutants_covering']:>3} scored"
              + (f" ({item['candidate_excluded']} excluded)"
                 if item["candidate_excluded"] else "")
              + f"  {short}")


def print_summary(summary: dict) -> None:
    """The short human version.  The publishable line is named as such."""
    if summary.get("schema") == TEST_QUALITY_SUMMARY_SCHEMA_V2:
        _print_single_observation_summary(summary)
        return
    macro = summary["recall_macro"]
    jac = summary.get("jaccard_macro")
    gold_killed = (summary.get("candidate_pair_scope")
                   == CANDIDATE_PAIRS_GOLD_KILLED)
    print(f"\ntest quality: {summary['n_passed']} passed item(s), "
          f"{summary['n_scorable']} scorable, macro recall "
          f"{'-' if macro is None else format(macro, '.3f')} / macro jaccard "
          f"{'not measured' if gold_killed else '-' if jac is None else format(jac, '.3f')} over "
          f"{summary['mutants_in_population']} mutant(s) / "
          f"{summary['pairs_expected']} expected execution(s)")
    if gold_killed:
        print(f"  candidate pairs: gold-killed only, "
              f"{summary.get('candidate_pairs_expected')} of "
              f"{summary['pairs_expected']}"
              + (f" (gold pair plan {summary['gold_pair_plan']['path']})"
                 if summary.get("gold_pair_plan") else "")
              + "; " + GOLD_KILLED_NOT_MEASURED + ": "
              + ", ".join(summary.get("withheld_measures") or ()))
    if summary.get("verdict_basis") == "hard_subset":
        print("  verdict basis: hard_subset (literal-failed D4 selective "
              "confirmation)"
              f"; hard macro {summary.get('hard_recall_macro')}"
              f"; full macro {summary.get('full_recall_macro')}"
              f"; {summary.get('hard_pairs')} hard pair(s)"
              f"; {len(summary.get('hard_confirmation_qualifying_items') or [])} "
              "qualifying item(s) / "
              f"{summary.get('hard_confirmation_pairs')} run-2 pair(s)")
    elif summary.get("verdict_basis") == "full_gold":
        label = ("declared B100 development basis" if "prestashop_reference_evidence" in summary
                 else "sensitivity only after C4")
        print(f"  verdict basis: full_gold ({label})")
    if "prestashop_reference_evidence" in summary:
        print("  method: single_observation; reference observations: 1; "
              "candidate observations: 1; no repeat-stability claim")
    # Which provenance the candidate resolved to, beside the number rather
    # than only inside the sidecar: `development_unstamped` is the reason the
    # NOT PUBLICATION-READY line below says what it says.
    print("  generation provenance: "
          f"{summary.get('generation_provenance_class')}")
    if summary.get("sensitivity"):
        print(f"  sensitivity: {summary['sensitivity']} (post-hoc sensitivity; "
              "never a primary result)")
    # `pairs_expected` is what the campaign PLANNED; describing it as
    # "executions" made the scoring-time console read as though that many gold
    # pairs had run, which is exactly wrong on the run where fewer did.  Both
    # numbers, always, so the gap is visible on the screen the operator is
    # already looking at.
    gold_label = ("reference gold rows reused" if "prestashop_reference_evidence" in summary
                  else "gold executions")
    print(f"  {gold_label}: {summary.get('pairs_executed_gold')} of "
          f"{summary['pairs_expected']} expected"
          + (f", {summary['gold_rows_missing']} row(s) missing"
             if summary.get("gold_rows_missing") else ""))
    degraded = summary.get("gold_infrastructure_outcomes")
    if degraded:
        # Ruling 2.6: the count and the per-item list travel with the number.
        print(f"  gold infrastructure outcomes: {degraded} "
              f"({summary.get('gold_infrastructure_class')}"
              + (", CONSENTED --allow-degraded-gold"
                 if summary.get("allow_degraded_gold") else
                 ", NO consent recorded")
              + ")")
        for entry in (summary.get("gold_infrastructure_pairs") or [])[:10]:
            print(f"    {entry.get('outcome'):<20} {entry.get('mutant_id')}  "
                  f"{str(entry.get('item_id')).split('features/domain/')[-1]}")
        if len(summary.get("gold_infrastructure_pairs") or []) > 10:
            print(f"    ... {degraded - 10} more (full list in the summary's "
                  f"gold_infrastructure_pairs)")
    ready, reasons = publication_ready(summary)
    if not ready:
        print("  NOT PUBLICATION-READY: " + "; ".join(reasons))
    # The engine, on the same screen as the number it qualifies: a recall of
    # 0.87 means one thing under `r2t-mutate` and another under
    # `r2t-mutate-py`, and an operator reading two summaries in one terminal
    # has no other way to tell which is which.
    if summary.get("engine"):
        rows = summary.get("row_engines") or {}
        unlabelled = rows.get(UNLABELLED_ENGINE)
        print(f"  engine: {summary['engine']} "
              f"{summary.get('engine_version') or '?'}"
              + (f" ({unlabelled} row(s) predate the engine column and are "
                 f"attributed to this manifest)" if unlabelled else ""))
    for verdict in VERDICTS:
        note = ("  <- non_vacuous_pass_at_1 counts these"
                if verdict == EQUIVALENT else "")
        print(f"  {verdict:<24} {summary['verdicts'][verdict]:>4}{note}")
    for iid, item in sorted(summary["per_item"].items()):
        r, j = item["recall"], item.get("jaccard")
        short = iid.split("features/domain/")[-1]
        print(f"  {item['verdict']:<24} "
              f"{item['candidate_killed']:>3}/{item['gold_killed']:<3} "
              f"recall {'-' if r is None else format(r, '.3f'):>5} "
              f"jaccard {'-' if j is None else format(j, '.3f'):>5}  "
              f"of {item['mutants_covering']:>3} covering  {short}")
        if item.get("verdict_basis") == "hard_subset":
            print(f"      hard {item['hard_candidate_killed']}/"
                  f"{item['hard_gold_killed']} recall "
                  f"{item.get('hard_recall')}; full "
                  f"{item['full_candidate_killed']}/"
                  f"{item['full_gold_killed']} recall "
                  f"{item.get('full_recall')}")
        if item["not_scorable_reason"]:
            print(f"      not scorable: {item['not_scorable_reason']}")


# --------------------------------------------------------------- selftest
def _single_observation_argv_refusals() -> dict:
    """Every option the v2 policy cannot mean, refused at argv BY NAME.

    Driven through `cli.main` and the real `cmd_test_quality`, because the
    parser is built inside `main` and the refusal has to happen before the
    verb touches a file.  Each of these is also refused inside
    `run_test_quality` -- but only after the worker preflight, so there the
    operator loses a provisioned pool instead of a command line.
    """
    from .. import cli
    base = ["test-quality", "--run", "r", "--gold-baseline", "g",
            "--manifest", "m", "--map", "p", "--mutation-validation", "v",
            "--seed", "s", "--workers", "w", "--out", "o"]
    reference = ["--reference-controls", "ref",
                 "--reference-attestation", "a.json"]
    incompatible = {
        "--gold-results": ["--gold-results", "x.jsonl"],
        "--gold-results-attestation": ["--gold-results-attestation", "x.json"],
        "--hard-subset": ["--hard-subset", "h.json"],
        "--candidate-hard-rerun": ["--candidate-hard-rerun", "s.jsonl"],
        "--candidate-hard-plan": ["--candidate-hard-plan", "p.json"],
        "--candidate-hard-plan-out": ["--candidate-hard-plan-out", "q.json"],
        "--allow-incomplete": ["--allow-incomplete"],
        "--allow-degraded-gold": ["--allow-degraded-gold"],
        "--compute-cap-seconds": ["--compute-cap-seconds", "60"],
        "--compute-cap-review-authority": [
            "--compute-cap-review-authority", "docs/x.md@" + "a" * 40],
    }
    results = {}
    for name, argv in incompatible.items():
        try:
            cli.main(base + reference + argv)
            results[name] = "not refused"
        except SystemExit as exc:
            results[name] = ("refused" if name in str(exc) else str(exc))
    for half in (reference[:2], reference[2:]):
        try:
            cli.main(base + half)
            results[half[0] + " alone"] = "not refused"
        except SystemExit as exc:
            results[half[0] + " alone"] = (
                "refused" if "neither establishes a reference" in str(exc)
                else str(exc))
    return results


def _two_independent_consent_flags() -> bool:
    """`--allow-incomplete` and `--allow-degraded-gold` are separate dests.

    Read off the REAL parser rather than asserted in prose: R4 item 1 says the
    new flag is "independent of `--allow-incomplete`", and the cheapest way for
    that to stop being true is one `dest=` shared between the two.  Driven
    through `cli.main`, because the parser is built inside it and a second
    parser assembled here would be a different object from the one users hit.
    """
    from .. import cli
    from . import cli as bench_cli
    seen = {}

    def capture(args):
        seen.update(vars(args))
        return 0

    real = bench_cli.cmd_test_quality
    bench_cli.cmd_test_quality = capture
    try:
        base = ["test-quality", "--run", "r", "--gold-baseline", "g",
                "--manifest", "m", "--map", "p", "--mutation-validation", "v",
                "--seed", "s", "--workers", "w", "--out", "o"]
        cli.main(base + ["--allow-incomplete"])
        incomplete_only = (seen.get("allow_incomplete"),
                           seen.get("allow_degraded_gold"))
        seen.clear()
        cli.main(base + ["--allow-degraded-gold"])
        degraded_only = (seen.get("allow_incomplete"),
                         seen.get("allow_degraded_gold"))
    finally:
        bench_cli.cmd_test_quality = real
    return incomplete_only == (True, False) and degraded_only == (False, True)


def selftest() -> int:
    """The arithmetic and the plan, with the execution faked.

    No container: `execute` is injected, exactly as `mutation_run`'s own
    selftest fakes a harness.  What is checked is everything that decides a
    published number — which items are scored, which mutants they are scored
    over, and the four verdicts — plus `report`'s `non_vacuous_pass_at_1`
    arithmetic, which is the number this whole module exists to produce.
    """
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def raises(fn, needle=""):
        try:
            fn()
        except ValueError as e:
            return needle in str(e)
        except Exception:                                   # noqa: BLE001
            return False
        return False

    # --------------------------------------------- single observation (v2)
    #
    # The scoring unit consumes only the private, authenticated bridge.  This
    # fixture is deliberately minted with `reference_controls`' own seals
    # here; production callers obtain these objects only by reopening the
    # preserved three-role evidence through that module's readers.
    from . import reference_controls as _RC

    def _single_fixture_controls(items, expected, *, excluded=(), full_gold=False,
                                 declared=None,
                                 population_overrides=None,
                                 authority_overrides=None,
                                 sensitivity=None, disagreements=()):
        observations = {
            role: _RC.SealedObservation(
                {"role": role}, _RC._OBSERVATION_SEAL,
                root=f"/fixture/{role}", portable=True)
            for role in _RC.ROLES
        }
        fixture_population = {
            "id": "fixture-v1", "asset_project": "fixture",
            "asset_index_sha256": "a" * 64,
            "manifest_sha256": "b" * 64,
            "manifest_digest": "d" * 64,
            "map_sha256": "e" * 64,
            "release_sha256": "f" * 64,
            "engine": "fixture-engine", "engine_version": "1.0",
            "parser": "fixture-parser/1",
        }
        fixture_population.update(population_overrides or {})
        fixture_authority = {
            "mutation_validation_sha256": "1" * 64,
            "mutation_validation_class": "native",
            "substrate_baseline_sha256": "2" * 64,
            "applier_sha256": "3" * 64,
            "harness_version": "fixture-harness-v1",
            "container_image_digest": "sha256:" + "7" * 64,
            "workspace_seed_digest": "6" * 64,
            "database_dump_digest": "5" * 64,
            "timeout_seconds": 600,
        }
        fixture_authority.update(authority_overrides or {})
        document = {
            "schema": _RC.SCHEMA,
            "digest": "c" * 64,
            "population": fixture_population,
            "pairs": {"excluded_count": len(excluded)},
            "excluded_pairs": [
                {"item_id": item_id, "mutant_id": mutant_id, "causes": []}
                for item_id, mutant_id in sorted(excluded)],
            "observations": {
                role: {"observation_id": str(number) * 32}
                for number, role in enumerate(_RC.ROLES, 1)
            },
            "authority": fixture_authority,
            "items": items,
            "stub_gate": {"macro_recall": 0.0, "threshold": 0.02,
                          "eligible": True},
        }
        if full_gold:
            document["reference_basis"] = "full_gold"
            document["stub_gate"] = None
            document["observations"] = {"full_gold": document["observations"]["full_gold"]}
            observations = {"full_gold": observations["full_gold"]}
            document["items"] = {iid: {**entry, "hard_subset": None, "stub_recall": None}
                                 for iid, entry in items.items()}
        if declared is not None:
            document["declared_subset"] = declared
        if sensitivity is not None:
            document["sensitivity"] = sensitivity
            document["stub_gate"] = {"macro_recall": 0.364, "threshold": 0.02,
                                     "eligible": False}
            document["gold_disagreements"] = {
                "source": "fixture pilot" if disagreements else None,
                "sha256": "d" * 64 if disagreements else None,
                "pairs": [{"item_id": item_id, "mutant_id": mutant_id}
                          for item_id, mutant_id in sorted(disagreements)]}
        controls = _RC.ReferenceControls(
            document, expected_pairs=frozenset(expected),
            observations=observations, seal=_RC._CONTROLS_SEAL)
        return controls, _seal_single_observation_scoring_authority(controls)

    def _so_row(mutant_id, outcome, item_id="i1"):
        return {"item_id": item_id, "mutant_id": mutant_id,
                "outcome": outcome}

    _so_pairs = {("i1", "m1"), ("i1", "m2"), ("i1", "m3")}
    _so_controls, _so_authority = _single_fixture_controls(
        {"i1": {"full_gold_kills": ["m1", "m2"], "hard_subset": ["m1"],
                "stub_recall": 0.0}},
        _so_pairs)
    _so_rows = [_so_row("m1", "failed"), _so_row("m2", "passed"),
                _so_row("m3", "failed")]
    _so_score = score_single_observation(
        {"i1": []}, _so_rows, authority=_so_authority,
        expected=set(_so_pairs))
    check("single-observation arithmetic keeps hard primary and explicit "
          "same-basis full companions",
          _so_score["hard_recall_macro"] == 1.0
          and _so_score["full_recall_macro"] == 0.5
          and _so_score["full_only_generated_macro"] == 1 / 3
          and _so_score["full_jaccard_macro"] == 1 / 3
          and _so_score["per_item"]["i1"]["verdict"] == EQUIVALENT
          and _so_score["reference_excluded_count"] == 0
          and _so_score["candidate_excluded_count"] == 0
          and _so_score["candidate_scored_pairs"] == 3)
    check("authored mappings cannot impersonate sealed reference controls",
          raises(lambda: _seal_single_observation_scoring_authority(
              dict(_so_controls)), "authenticated reference controls"))
    check("scoring refuses an authority this module did not mint",
          raises(lambda: score_single_observation(
              {"i1": []}, _so_rows,
              authority=_SingleObservationScoringAuthority(
                  _so_controls, _so_authority.sets, object())),
                 "sealed authority"))
    check("candidate scope refuses a missing or added pair",
          raises(lambda: score_single_observation(
              {"i1": []}, _so_rows[:-1], authority=_so_authority),
                 "passed-item pair set"))

    # Section 5.1, the candidate half.  A terminal timeout/infrastructure pair
    # is dropped from G, H and C TOGETHER: m2 is gold's second kill, so a run
    # that dropped it from the candidate alone would print full recall 0.5
    # for a candidate that killed everything still observable.
    for _terminal in ("timeout", "setup_error"):
        _ex_rows = [_so_row("m1", "failed"), _so_row("m2", _terminal),
                    _so_row("m3", "failed")]
        _ex_score = score_single_observation(
            {"i1": []}, _ex_rows, authority=_so_authority)
        check(f"a candidate pair ending on {_terminal} leaves the scored "
              "universe of G, H and C alike rather than refusing the run",
              _ex_score["candidate_excluded_count"] == 1
              and _ex_score["candidate_excluded_pairs"] == [
                  {"item_id": "i1", "mutant_id": "m2",
                   "outcome": _terminal}]
              and _ex_score["candidate_scored_pairs"] == 2
              and _ex_score["per_item"]["i1"]["candidate_excluded"] == 1
              and _ex_score["per_item"]["i1"]["mutants_covering"] == 2
              and _ex_score["per_item"]["i1"]["full_denominator"] == 1
              and _ex_score["full_recall_macro"] == 1.0
              and _ex_score["hard_recall_macro"] == 1.0,
              str(_ex_score["per_item"]["i1"]))

    # Harness 25, correction D: the reviewed nondeterministic mutants leave
    # G_i (and the hard subset and the candidate's kills) at scoring.  A
    # candidate that kills all of G_i except the random-draw mutant is
    # kill-complete, and killing it adds nothing.
    _nd = "96e02276fdb04ae5"
    check("[H25-D] the fixture mutant is on the reviewed list",
          _nd in nondeterministic_mutants())
    _nd_pairs = {("i1", "m1"), ("i1", _nd)}
    _nd_controls, _nd_authority = _single_fixture_controls(
        {"i1": {"full_gold_kills": ["m1", _nd], "hard_subset": ["m1", _nd],
                "stub_recall": 0.0}},
        _nd_pairs)
    for _nd_outcome in ("passed", "failed"):
        _nd_so = score_single_observation(
            {"i1": []}, [_so_row("m1", "failed"), _so_row(_nd, _nd_outcome)],
            authority=_nd_authority, expected=set(_nd_pairs))
        check(f"[H25-D] single observation: a kill set holding a listed "
              f"mutant is scored without it (candidate {_nd_outcome} it)",
              _nd_so["per_item"]["i1"]["full_gold_killed"] == 1
              and _nd_so["per_item"]["i1"]["hard_gold_killed"] == 1
              and _nd_so["full_recall_macro"] == 1.0
              and _nd_so["hard_recall_macro"] == 1.0
              and _nd_so["per_item"]["i1"]["verdict"] == EQUIVALENT
              and _nd_so["per_item"]["i1"]["candidate_only_kills"] == 0
              and _nd_so["candidate_scored_pairs"] == 1,
              str(_nd_so["per_item"]["i1"]))
        _nd_v1 = score(
            {"i1": []}, {"i1": ["m1", _nd]}, {"i1": {"m1", _nd}},
            {"i1": "passed"},
            [{"item_id": "i1", "mutant_id": "m1", "outcome": "failed"},
             {"item_id": "i1", "mutant_id": _nd, "outcome": _nd_outcome}],
            expected={("i1", "m1"), ("i1", _nd)})
        check(f"[H25-D] v1 recall: the same kill set is scored without the "
              f"listed mutant (candidate {_nd_outcome} it)",
              _nd_v1["per_item"]["i1"]["gold_killed"] == 1
              and _nd_v1["per_item"]["i1"]["recall"] == 1.0
              and _nd_v1["per_item"]["i1"]["verdict"] == EQUIVALENT
              and _nd_v1["per_item"]["i1"]["candidate_only_kills"] == 0,
              str(_nd_v1["per_item"]["i1"]))
    # A summary scored before harness 25 is re-derived as it was scored.
    _nd_as_recorded = (
        score_single_observation(
            {"i1": []}, [_so_row("m1", "failed"), _so_row(_nd, "passed")],
            authority=_nd_authority, expected=set(_nd_pairs),
            unscored=unscored_mutants(24)),
        score({"i1": []}, {"i1": ["m1", _nd]}, {"i1": {"m1", _nd}},
              {"i1": "passed"},
              [{"item_id": "i1", "mutant_id": "m1", "outcome": "failed"},
               {"item_id": "i1", "mutant_id": _nd, "outcome": "passed"}],
              expected={("i1", "m1"), ("i1", _nd)},
              unscored=unscored_mutants(24)))
    check("[H25-D] the list applies from harness 25 on (and to a fixture's "
          "non-integer version); both scorers re-derive an earlier summary "
          "with the listed mutant in G_i",
          unscored_mutants(24) == frozenset()
          and unscored_mutants(25) == nondeterministic_mutants()
          and unscored_mutants("fixture-harness-v1")
          == nondeterministic_mutants()
          and _nd_as_recorded[0]["per_item"]["i1"]["hard_gold_killed"] == 2
          and _nd_as_recorded[0]["per_item"]["i1"]["verdict"] == WEAKER
          and _nd_as_recorded[1]["per_item"]["i1"]["gold_killed"] == 2
          and _nd_as_recorded[1]["per_item"]["i1"]["verdict"] == WEAKER,
          str([entry["per_item"]["i1"] for entry in _nd_as_recorded]))

    # A candidate that passed a strict subset of the reference's items and
    # killed a strict subset of that item's hard set.
    _sub_pairs = {("i1", "m1"), ("i1", "m2"), ("i1", "m3"), ("i2", "m4")}
    _sub_controls, _sub_authority = _single_fixture_controls(
        {"i1": {"full_gold_kills": ["m1", "m2"],
                "hard_subset": ["m1", "m2"], "stub_recall": 0.0},
         "i2": {"full_gold_kills": ["m4"], "hard_subset": ["m4"],
                "stub_recall": 0.0}},
        _sub_pairs)
    _sub_score = score_single_observation(
        {"i1": []},
        [_so_row("m1", "failed"), _so_row("m2", "passed"),
         _so_row("m3", "passed")],
        authority=_sub_authority)
    check("a candidate scored over a strict subset of the reference keeps "
          "the reference's own totals beside its own",
          _sub_score["reference_pairs"] == 4
          and _sub_score["candidate_pairs"] == 3
          and _sub_score["n_passed"] == 1
          and _sub_score["hard_recall_macro"] == 0.5
          and _sub_score["per_item"]["i1"]["verdict"] == WEAKER
          and set(_sub_score["per_item"]) == {"i1"})

    # The reference's OWN exclusions narrow the universe before the candidate
    # is planned: m3's pair is not the candidate's to execute.
    _nar_controls, _nar_authority = _single_fixture_controls(
        {"i1": {"full_gold_kills": ["m1"], "hard_subset": ["m1"],
                "stub_recall": 0.0}},
        {("i1", "m1"), ("i1", "m2")}, excluded={("i1", "m3")})
    _nar_mutants = [{"id": mid} for mid in ("m1", "m2", "m3")]
    _nar_narrowed_mutants, _nar_restricted = _narrow_to_reference(
        _nar_mutants, {"m1": ["i1"], "m2": ["i1"], "m3": ["i1"]},
        _reference_excluded_pairs(_nar_authority.controls))
    check("a reference-excluded pair leaves the planned population, and a "
          "mutant with no surviving pair leaves it entirely",
          [m["id"] for m in _nar_narrowed_mutants] == ["m1", "m2"]
          and _nar_restricted == {"m1": ["i1"], "m2": ["i1"]}
          and score_single_observation(
              {"i1": []},
              [_so_row("m1", "failed"), _so_row("m2", "passed")],
              authority=_nar_authority)["reference_excluded_count"] == 1)

    # A DECLARED reference narrows the same planned population at the ITEM
    # layer: the manifest and map still cover `i2`, which the control run has
    # no gold row for, so the candidate must not plan a pair on it.
    _dec_controls, _dec_authority = _single_fixture_controls(
        {"i1": {"full_gold_kills": ["m1"], "hard_subset": ["m1"],
                "stub_recall": 0.0}},
        {("i1", "m1"), ("i1", "m2")},
        declared={"declared_items": 1, "release_items": 2,
                  "omitted_items": ["i2"], "omitted_pairs": 2,
                  "reason": "the gold baseline has no row for i2"})
    _dec_narrowed_mutants, _dec_restricted = _narrow_to_reference(
        [{"id": mid} for mid in ("m1", "m2", "m3")],
        {"m1": ["i1", "i2"], "m2": ["i1"], "m3": ["i2"]},
        _reference_excluded_pairs(_dec_authority.controls),
        _reference_declared_items(_dec_authority.controls))
    check("a declared reference narrows the planned population to its "
          "declared items, and a mutant that only covered an omitted item "
          "leaves the campaign entirely",
          [m["id"] for m in _dec_narrowed_mutants] == ["m1", "m2"]
          and _dec_restricted == {"m1": ["i1"], "m2": ["i1"]}
          and _reference_declared_items(_nar_authority.controls) is None)
    _dec_score = score_single_observation(
        {"i1": []}, [_so_row("m1", "failed"), _so_row("m2", "passed")],
        authority=_dec_authority)
    check("the declared-subset disclosure reaches the summary every rendered "
          "number is read from, and is inert when nothing was declared",
          _dec_score["reference_omitted_items"] == 1
          and _dec_score["reference_declared_reason"]
              == "the gold baseline has no row for i2"
          and _so_score["reference_omitted_items"] == 0
          and _so_score["reference_declared_reason"] is None)

    check("a scored manifest resolves to the stable population id carried by "
          "new summaries",
          registered_population_id(
              "python-docx",
              "0fb0ae453e006b5302be6b338707a00ff6712cb273438d873a6de22467a8f18c",
              "r2t-mutate-py", "1.0") == "python-docx-v1")
    check("an explicitly synthetic project does not fabricate a population id",
          registered_population_id("fixture", "d" * 64,
                                   "r2t-mutate", "1.0") is None)
    check("a registered project with a changed digest refuses before scoring",
          raises(lambda: registered_population_id(
              "python-docx", "d" * 64, "r2t-mutate-py", "1.0"),
                 "population_id"))

    # ------------------------------------------------------------ fixture
    #
    # Five passing items and one failing one, over six mutants.  Hand-computed
    # so the macro is not whatever the code happens to produce:
    #
    #   i_full  gold kills {m1,m2}  candidate kills {m1,m2}   recall 1.0
    #   i_weak  gold kills {m1,m3}  candidate kills {m1}      recall 0.5
    #   i_vac   gold kills {m4}     candidate kills {}        recall 0.0
    #   i_eqm   gold kills {}       (m5 survives both)        not scorable
    #   i_nocov no mutant covers it                           not scorable
    #   i_fail  did not pass                                  not scored at all
    #
    #   macro = (1.0 + 0.5 + 0.0) / 3 = 0.5 over 3 scorable of 5 passes.
    def mut(mid, line):
        return {"id": mid, "file": "src/CoreShop/Component/Order/Model/Order.php",
                "operator": "NegateConditional", "start_line": line,
                "start_col": 1, "original": "$a < $b", "mutated": "$a >= $b"}

    manifest = {"digest": "d" * 64, "n": 6,
                "mutants": [mut(f"m{i}", i) for i in range(1, 7)]}
    by_mutant = {"m1": ["i_full", "i_weak", "i_other"],
                 "m2": ["i_full"],
                 "m3": ["i_weak"],
                 "m4": ["i_vac"],
                 "m5": ["i_eqm"],
                 "m6": ["i_fail"]}
    run_rows = [{"item_id": i, "outcome": "passed",
                 "produced_files": [{"file_path": f"{i}.php", "code": "<?php"}]}
                for i in ("i_full", "i_weak", "i_vac", "i_eqm", "i_nocov")]
    run_rows += [{"item_id": "i_fail", "outcome": "failed",
                  "produced_files": [{"file_path": "x.php", "code": "<?php"}]}]
    run_rows += [{"item_id": f"i_pad{k}", "outcome": "container_error",
                  "produced_files": []} for k in range(4)]
    gold_rows = [{"item_id": i, "outcome": "passed",
                  "produced_files": [{"file_path": f"gold_{i}.php",
                                      "code": "<?php"}]}
                 for i in ("i_full", "i_weak", "i_vac", "i_eqm", "i_nocov",
                           "i_fail")]

    GOLD_KILLS = {("i_full", "m1"), ("i_full", "m2"),
                  ("i_weak", "m1"), ("i_weak", "m3"), ("i_vac", "m4")}
    CAND_KILLS = {("i_full", "m1"), ("i_full", "m2"), ("i_weak", "m1")}

    # A PUBLISHABLE generation half, supplied EXPLICITLY by the fixtures that
    # stand in for preserved native evidence re-entering a campaign.  The
    # module default is the `fixture` class and every publication surface
    # refuses it, so a fixture that wants to model a publishable artifact has
    # to say so here, by name, and say what it claims.
    NATIVE_GENERATION_INPUTS = {
        "generation_provenance_class": "native_v2",
        "generation_attempt_id": "fixture-native-attempt",
        "generation_campaign_digest": "0123456789abcdef",
        "generation_agent_runtime_sha256": "e" * 64,
        "generation_network_semantics": "fixture_closed_channel",
        "generation_condition": "c3",
        "generation_protocol_version": 4,
        "generation_protocol_digest": "bda1d9bcb1852e92",
        "generation_native_budget": {"max_iterations": 100},
    }

    def _stamped(job, row):
        from .mutation_run import row_identity_stamp
        return {**row, **row_identity_stamp(job["identity"])}

    def _finish_fake_job(job, status="complete"):
        """Attest a faked slice the way the real one does: running, then done.

        Through the real writer and therefore through the real transition
        table (`mutation_run.SHARD_TRANSITIONS`), because a fake that could
        write a terminal state out of nowhere would be a fake of a writer this
        harness does not have — and the resume defect this PR closes lives
        exactly in that difference.
        """
        from .mutation_run import recorded_shard_status, write_shard_provenance
        if recorded_shard_status(job["out"], job["identity"]) != "running":
            write_shard_provenance(job["out"], job["identity"], "running",
                                   provenance=job.get("provenance"))
        write_shard_provenance(job["out"], job["identity"], status,
                               provenance=job.get("provenance"),
                               error=(None if status in ("running", "complete")
                                      else f"faked {status} slice"))

    def fake_execute(kills_by_side):
        """A `run_slice`-equivalent: writes the rows a real slice would.

        It honours the same contract the real one does — one row per
        (mutant, item) pair the job covers, in the harness's outcome
        vocabulary — and records the jobs it was handed so the PLAN can be
        asserted as well as the arithmetic.
        """
        seen: list = []

        def execute(job):
            seen.append(job)
            kills = kills_by_side[job["side"]]
            os.makedirs(os.path.dirname(job["out"]), exist_ok=True)
            n = 0
            with open(job["out"], "a", encoding="utf-8") as fh:
                for mutant in job["mutants"]:
                    for iid in job["by_mutant"][mutant["id"]]:
                        if iid not in job["files_by_item"]:
                            continue
                        fh.write(json.dumps(_stamped(job, {
                            "item_id": iid, "mutant_id": mutant["id"],
                            "file": mutant["file"],
                            "operator": mutant["operator"],
                            "outcome": ("failed" if (iid, mutant["id"]) in kills
                                        else "passed")}), sort_keys=True) + "\n")
                        n += 1
            _finish_fake_job(job)
            return {"out": job["out"], "rows": n, "side": job["side"]}

        return execute, seen

    # ------------------------------- the whole v2 command, end to end
    #
    # Driven through the real `run_test_quality` with only the container
    # executor injected, and reopened through the real saved-evidence reader.
    # The property this exists for is the one the whole workstream buys: a
    # scored candidate with NO gold execution.
    def _single_observation_campaign(root, *, outcomes, excluded=(), full_gold=False,
                                     passed_item="i1",
                                     reference_items=None,
                                     reference_pairs=None,
                                     population_overrides=None,
                                     authority_overrides=None,
                                     input_overrides=None,
                                     asset_index_sha256="a" * 64,
                                     mutants=("m1", "m2", "m3"),
                                     sensitivity=None,
                                     candidate_pairs=None):
        """One complete candidate-only campaign over a fixture reference."""
        from . import mutation_run as _SO_MR
        run_path = os.path.join(root, "candidate.jsonl")
        baseline_path = os.path.join(root, "gold.jsonl")
        so_run_rows = [{
            "item_id": passed_item, "outcome": "passed",
            "produced_files": [{"file_path": "test_i1.py",
                                "code": "assert True\n"}],
        }]
        so_baseline_rows = [{
            "item_id": passed_item, "outcome": "passed",
            "produced_files": [{"file_path": "gold_i1.py",
                                "code": "assert True\n"}],
        }]
        for path, rows in ((run_path, so_run_rows),
                           (baseline_path, so_baseline_rows)):
            with open(path, "w", encoding="utf-8") as handle:
                for row in rows:
                    handle.write(json.dumps(row, sort_keys=True) + "\n")
        so_manifest = {
            "digest": "d" * 64, "engine": "fixture-engine",
            "engine_version": "1.0", "parser": "fixture-parser/1",
            "mutants": [{"id": mid, "file": f"src/{mid}.py",
                         "operator": "fixture-op", "start_line": number,
                         "start_col": 1, "original": "a", "mutated": "b"}
                        for number, mid in enumerate(mutants, 1)],
        }
        so_map = {mid: ["i1"] for mid in mutants}
        manifest_path = os.path.join(root, "manifest.json")
        map_path = os.path.join(root, "map.json")
        release_path = os.path.join(root, "release.json")
        validation_path = os.path.join(root, "validation.json")
        for path, document in ((manifest_path, so_manifest),
                               (map_path, {"by_mutant": so_map}),
                               (release_path, {"items": ["i1"]}),
                               (validation_path, {"status": "fixture"})):
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(document, handle, sort_keys=True)
                handle.write("\n")
        controls, authority = _single_fixture_controls(
            reference_items or {"i1": {
                "full_gold_kills": ["m1", "m2"], "hard_subset": ["m1"],
                "stub_recall": 0.0}},
            reference_pairs or {("i1", mid) for mid in mutants},
            excluded=excluded, full_gold=full_gold,
            population_overrides={
                "manifest_sha256": _SO_MR.sha256_file(manifest_path),
                "map_sha256": _SO_MR.sha256_file(map_path),
                "release_sha256": _SO_MR.sha256_file(release_path),
                **(population_overrides or {}),
            },
            authority_overrides={
                "mutation_validation_sha256": _SO_MR.sha256_file(
                    validation_path),
                **(authority_overrides or {}),
            }, sensitivity=sensitivity)
        resources = [{"index": 0}]
        inputs = identity_inputs_for_test_quality(
            run_rows=so_run_rows, gold_baseline_rows=so_baseline_rows,
            manifest=so_manifest, by_mutant=so_map, exact={
                **NATIVE_GENERATION_INPUTS,
                "asset_project": "fixture",
                "asset_index_sha256": asset_index_sha256,
                "mutation_validation_sha256": _SO_MR.sha256_file(
                    validation_path),
                "mutation_validation_class": "native",
                "manifest_sha256": _SO_MR.sha256_file(manifest_path),
                "manifest_digest": "d" * 64,
                "map_sha256": _SO_MR.sha256_file(map_path),
                "release_sha256": _SO_MR.sha256_file(release_path),
                "candidate_run_sha256": _SO_MR.sha256_file(run_path),
                "candidate_generated_tests_sha256": _SO_MR.candidate_digest(
                    passed_solutions(so_run_rows)),
                "gold_baseline_sha256": _SO_MR.sha256_file(baseline_path),
                "gold_generated_tests_sha256": _SO_MR.candidate_digest(
                    passed_solutions(so_baseline_rows)),
                "worker_resources_sha256": _SO_MR.content_digest(resources),
                "substrate_baseline_sha256": "2" * 64,
                "applier_sha256": "3" * 64,
                "engine": "fixture-engine", "engine_version": "1.0",
                "parser": "fixture-parser/1",
                **(input_overrides or {}),
            })
        calls = []

        def execute(job):
            calls.append(job)
            os.makedirs(os.path.dirname(job["out"]), exist_ok=True)
            with open(job["out"], "w", encoding="utf-8") as handle:
                for mutant in job["mutants"]:
                    for item_id in job["by_mutant"][mutant["id"]]:
                        outcome = outcomes[(item_id, mutant["id"])]
                        retried = outcome in _SO_MR.INFRASTRUCTURE_OUTCOMES
                        handle.write(json.dumps(_stamped(job, {
                            "item_id": item_id, "mutant_id": mutant["id"],
                            "file": mutant["file"],
                            "operator": mutant["operator"],
                            "outcome": outcome,
                            "attempt": 2 if retried else 1,
                            "retried_infrastructure": retried,
                        }), sort_keys=True) + "\n")
            _finish_fake_job(job)
            return {"out": job["out"], "rows": len(job["mutants"]),
                    "side": job["side"]}

        out_dir = os.path.join(root, "campaign")

        def reader(_summary, _expected):
            return authority

        def final(summary, path):
            _validate_native_summary_before_completion(
                summary, path, run_path, reference_controls_reader=reader)

        campaign = dict(
            run_rows=so_run_rows, gold_baseline_rows=so_baseline_rows,
            manifest=so_manifest, by_mutant=so_map,
            out_dir=out_dir, execute=execute, n_workers=1,
            single_observation_authority=authority,
            candidate_pairs=(candidate_pairs if candidate_pairs is not None
                             else CANDIDATE_PAIRS_GOLD_KILLED if full_gold
                             else CANDIDATE_PAIRS_ALL),
            provenance={
                "run": run_path, "gold_baseline": baseline_path,
                "manifest": manifest_path, "map": map_path,
                "release": release_path,
                "mutation_validation": validation_path,
                "seed": root,
            },
            identity_inputs=inputs, require_complete=True,
            worker_resources=resources,
            execution_policy=_SO_MR.EXECUTION_POLICY_SCALAR_V1,
            execution_observation_id="9" * 32,
            final_summary_validator=final)
        summary = run_test_quality(**campaign)
        return {"summary": summary, "calls": calls, "run": run_path,
                "out": out_dir, "reader": reader, "authority": authority,
                # The same campaign with some arguments replaced: a resume,
                # or the other candidate pair scope.
                "rerun": lambda **changed: run_test_quality(
                    **{**campaign, **changed})}

    def _so_case(root, name):
        path = os.path.join(root, name)
        os.makedirs(path)
        return path

    for _fg_outcomes, _fg_expected_nv in (({"m1": "failed", "m2": "failed"}, 1),
                                           ({"m1": "failed", "m2": "passed"}, 0),
                                           ({"m1": "failed", "m2": "timeout"}, 1)):
        with tempfile.TemporaryDirectory() as root:
            full = _single_observation_campaign(
                root, full_gold=True,
                outcomes={("i1", mid): outcome for mid, outcome in _fg_outcomes.items()})
            result = full["summary"]
            import io
            from contextlib import redirect_stdout
            printed = io.StringIO()
            with redirect_stdout(printed):
                _print_single_observation_summary(result)
            check("fullgold console prints NV and unmeasured companions without hard claims",
                  "non-vacuous passes" in printed.getvalue()
                  and "not measured" in printed.getvalue())
            check("full-gold native single-observation executes only sealed kills and reopens",
                  result["candidate_pairs"] == 2
                  and result["non_vacuous_passes"] == _fg_expected_nv
                  and result["verdict_basis"] == "full_gold"
                  and result["hard_recall_macro"] is None
                  and result["full_jaccard_macro"] is None
                  and result["candidate_pair_scope"] == "gold-killed")

    with tempfile.TemporaryDirectory() as root:
        full_zero = _single_observation_campaign(
            root, full_gold=True, outcomes={},
            reference_items={"i1": {"full_gold_kills": [], "hard_subset": None,
                                     "stub_recall": None}})
        check("full-gold empty kill set authenticates zero jobs without fabricating NV",
              full_zero["summary"]["candidate_pairs"] == 0
              and full_zero["summary"]["non_vacuous_passes"] == 0
              and full_zero["calls"] == [])
        from .mutation_run import pair_set_digest as _fz_digest
        check("the zero-job full-gold root plan binds the empty gold-killed "
              "slice, and every pass is not_scorable as all pairs would be",
              _load_json_object(_campaign_state_path(full_zero["out"]),
                                "zero-job root")["plan"]["candidate_pair_scope"]
              == {"scope": CANDIDATE_PAIRS_GOLD_KILLED, "candidate_pairs": 0,
                  "candidate_pairs_sha256": _fz_digest(set()),
                  "gold_pair_plan": False}
              and full_zero["summary"]["verdicts"][NOT_SCORABLE] == 1)

    # ----- gold-killed candidate scope on a full-gold-only reference
    #
    # GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md sections 1 and 3 as they apply to
    # the reference-controls route (coddy-agent, FULL_GOLD_NV_LEAD_AMENDMENT.md
    # section 5).  G_i1 = {m1, m2}; the candidate also kills m3, outside G,
    # so the all-pairs companions are real numbers the slice cannot see.
    # A full-gold-only reference admits no all-pairs campaign, so the
    # all-pairs scoring is the SAME fixture sealed with its three roles: the
    # same pairs, the same section 5.1 exclusions and the same full-gold
    # kills, scored over every pair.  Its full-gold measures are the
    # all-pairs full-gold scoring; its full-gold verdict is
    # `verdict_for(full_gold_killed, full_recall)` and its full-gold NV the
    # passes at full recall 1.0 (FULL_GOLD_NV_LEAD_AMENDMENT.md section 2).
    from pathlib import Path as _gk2_Path
    from collections import Counter as _gk2_Counter
    from .mutation_run import content_digest as _gk2_content
    from . import report as _gk2_report
    from . import results as _gk2_results
    _gk2_g = {("i1", "m1"), ("i1", "m2")}
    _gk2_item_same = ("full_gold_killed", "full_candidate_killed",
                      "full_denominator", "full_recall")
    _gk2_reference_same = ("n_passed", "full_recall_macro", "reference_pairs",
                           "reference_pairs_sha256",
                           "reference_excluded_count",
                           "reference_omitted_items",
                           "reference_declared_reason")
    _gk2_nulls = ("candidate_only_kills", "full_union",
                  "full_only_generated", "full_jaccard")
    _gk2_withheld = ["per_item.candidate_only_kills", "per_item.full_union",
                     "per_item.full_only_generated", "per_item.full_jaccard",
                     "full_only_generated_macro", "full_jaccard_macro"]
    with tempfile.TemporaryDirectory() as _gk2_root:
        _gk2_cases = {}
        for _gk2_name, _gk2_outcomes, _gk2_nv, _gk2_excluded, _gk2_only in (
                ("kills", {"m1": "failed", "m2": "failed", "m3": "failed"},
                 1, (0, 0), 1),
                ("misses", {"m1": "failed", "m2": "passed", "m3": "failed"},
                 0, (0, 0), 1),
                ("vacuous", {"m1": "passed", "m2": "passed", "m3": "failed"},
                 0, (0, 0), 1),
                # A timeout inside G and one outside: each scope leaves only
                # its own executed pairs, so the 5.1 counts are the slice's.
                ("excluded", {"m1": "failed", "m2": "timeout",
                              "m3": "timeout"}, 1, (1, 2), 0)):
            _gk2_rows = {("i1", mid): outcome
                         for mid, outcome in _gk2_outcomes.items()}
            _gk2_all = _single_observation_campaign(
                _so_case(_gk2_root, "all-" + _gk2_name), outcomes=_gk2_rows)
            _gk2 = _single_observation_campaign(
                _so_case(_gk2_root, "gk-" + _gk2_name), outcomes=_gk2_rows,
                full_gold=True)
            _gk2_cases[_gk2_name] = (_gk2_all, _gk2)
            _a, _s = _gk2_all["summary"], _gk2["summary"]
            _a_item, _s_item = _a["per_item"]["i1"], _s["per_item"]["i1"]
            _gk2_executed = {(item_id, mutant["id"])
                             for job in _gk2["calls"]
                             for mutant in job["mutants"]
                             for item_id in job["by_mutant"][mutant["id"]]}
            check(f"full-gold gold-killed ({_gk2_name}): the candidate "
                  "executes exactly G_i of its passes and gold is projected",
                  _gk2_executed == _gk2_g
                  and {job["side"] for job in _gk2["calls"]} == {"candidate"}
                  and _s["candidate_pairs"] == 2
                  and _a["candidate_pairs"] == 3,
                  str(sorted(_gk2_executed)))
            _derived = verdict_for(_a_item["full_gold_killed"],
                                   _a_item["full_recall"])
            _derived_nv = sum(1 for entry in _a["per_item"].values()
                              if entry["full_recall"] == 1.0)
            check(f"full-gold gold-killed ({_gk2_name}): recall, verdict and "
                  "non-vacuous count equal the all-pairs full-gold scoring "
                  "of the same outcomes",
                  all(_s_item[key] == _a_item[key] for key in _gk2_item_same)
                  and all(_s[key] == _a[key] for key in _gk2_reference_same)
                  and _s_item["verdict"] == _derived
                  and _s["recall_macro"] == _a["full_recall_macro"]
                  and _s["n_scorable"] == sum(
                      1 for entry in _a["per_item"].values()
                      if entry["full_recall"] is not None)
                  and _s["verdicts"] == {**{value: 0 for value in VERDICTS},
                                         **_gk2_Counter([_derived])}
                  and _s["non_vacuous_passes"] == _derived_nv == _gk2_nv
                  and _s["verdict_basis"] == "full_gold"
                  and _s["companion_basis"] is None,
                  json.dumps({"gold-killed": _s_item, "all": _a_item},
                             default=str)[:800])
            check(f"full-gold gold-killed ({_gk2_name}): only-generated, "
                  "Jaccard and candidate-only kills are present, null and "
                  "named where all pairs measured them",
                  _s["candidate_pair_scope"] == CANDIDATE_PAIRS_GOLD_KILLED
                  and _s["withheld_measures"] == _gk2_withheld
                  and _s["full_only_generated_macro"] is None
                  and _s["full_jaccard_macro"] is None
                  and all(key in _s_item and _s_item[key] is None
                          for key in _gk2_nulls)
                  and _a_item["candidate_only_kills"] == _gk2_only
                  and _a["full_jaccard_macro"] is not None
                  and "candidate_pair_scope" not in _a
                  and "withheld_measures" not in _a,
                  str(_s_item))
            check(f"full-gold gold-killed ({_gk2_name}): the executed-pair "
                  "and section 5.1 candidate counts describe the slice",
                  (_s["candidate_excluded_count"],
                   _a["candidate_excluded_count"]) == _gk2_excluded
                  and _s_item["mutants_covering"]
                  == 2 - _gk2_excluded[0]
                  and _a_item["mutants_covering"] == 3 - _gk2_excluded[1]
                  and _s["pairs_executed_candidate"] == 2
                  and _s["pairs_expected"] == 2,
                  str((_s["candidate_excluded_count"],
                       _a["candidate_excluded_count"])))
            _gk2_views = []
            for _campaign in (_gk2_all, _gk2):
                _reopened = load_bound_test_quality(
                    _campaign["run"], write_sidecar(_campaign["summary"],
                                                    _campaign["run"]),
                    reference_controls_reader=_campaign["reader"])
                _gk2_views.append((_reopened, _gk2_report.non_vacuous(
                    load_jsonl(_campaign["run"]), _reopened)))
            (_a_open, _a_nv), (_s_open, _s_nv) = _gk2_views
            check(f"full-gold gold-killed ({_gk2_name}): both summaries "
                  "reopen by rederivation and report.non_vacuous reads the "
                  "all-pairs full-gold numbers",
                  _s_open == _s and _a_open == _a
                  and _s_nv["non_vacuous_passes"]
                  == _s_nv["equivalent_to_reference"] == _derived_nv
                  and _s_nv["non_vacuous_pass_at_1"] == _derived_nv / 1
                  and all(_s_nv[key] == int(_derived == key)
                          for key in ("weaker", "vacuous", "not_scorable"))
                  and _s_nv["recall_macro"] == _s_nv["full_recall_macro"]
                  == _a_nv["full_recall_macro"]
                  and _s_nv["scored_items"] == _a_nv["scored_items"]
                  and _s_nv["stale"] is _a_nv["stale"] is False
                  and _s_nv["full_jaccard_macro"] is None
                  and _a_nv["full_jaccard_macro"] is not None,
                  json.dumps({"gold-killed": _s_nv, "all": _a_nv},
                             default=str)[:800])
            _gk2_mutation = _gk2_results.mutation(_s, {"i1"})
            _gk2_rendered = {row["key"]: row for row in _gk2_results.table_rows({
                "ladder": {"denominator": 1, "rows": []},
                "mutation": dict(_gk2_mutation, publication_ready=True),
                "coverage": {"scored": False, "values": None,
                             "reason": "fixture"},
                "api": {"scored": False, "values": None,
                        "reason": "fixture"}})}
            check(f"full-gold gold-killed ({_gk2_name}): results renders "
                  "recall and names only-generated and Jaccard not measured, "
                  "never 0",
                  _gk2_rendered["mutation_recall"]["number"]
                  == _s["full_recall_macro"]
                  and all(_gk2_rendered[key]["value"]
                          == _gk2_results.GOLD_KILLED_NOT_MEASURED
                          and _gk2_rendered[key]["number"] is None
                          for key in ("mutation_only_gen",
                                      "mutation_jaccard")),
                  str({key: _gk2_rendered[key]["value"]
                       for key in _gk2_rendered}))

        _gk2_all, _gk2 = _gk2_cases["kills"]
        _gk2_state = _load_json_object(
            _campaign_state_path(_gk2["out"]), "gold-killed root")
        _gk2_all_plan = _load_json_object(
            _campaign_state_path(_gk2_all["out"]), "all-pairs root")["plan"]
        check("full-gold gold-killed: the root plan binds the scope, the "
              "slice's count and digest; a hard-subset plan keeps its shape",
              _gk2_state["plan"]["candidate_pair_scope"]
              == {"scope": CANDIDATE_PAIRS_GOLD_KILLED, "candidate_pairs": 2,
                  "candidate_pairs_sha256": _fz_digest(_gk2_g),
                  "gold_pair_plan": False}
              and _gk2_state["plan"]["expected_pairs_sha256"]
              == _fz_digest(_gk2_g)
              and "candidate_pair_scope" not in _gk2_all_plan,
              str(_gk2_state["plan"].get("candidate_pair_scope")))
        _gk2_unbound = {key: value for key, value in _gk2_state["plan"].items()
                        if key != "candidate_pair_scope"}
        check("full-gold gold-killed: a root plan without the scope binding "
              "is another campaign",
              raises(lambda: _validate_campaign_state(_gk2_state,
                                                      _gk2_unbound),
                     "different root campaign plan"))

        # Resume across scopes, through the producer: the root record is
        # copied alone into a fresh directory and resumed.  The other scope
        # refuses on the basis before planning; the same scope matches the
        # plan and the terminal status refuses.  No worker runs in any.
        _gk2_resumes = []
        for _campaign, _scope, _needle in (
                (_gk2, CANDIDATE_PAIRS_ALL,
                 "require gold-killed candidate scope"),
                (_gk2, CANDIDATE_PAIRS_GOLD_KILLED,
                 "terminal root campaign status"),
                (_gk2_all, CANDIDATE_PAIRS_GOLD_KILLED,
                 "defined for full-gold scoring only")):
            _dir = _so_case(_gk2_root, f"resume-{len(_gk2_resumes)}")
            _gk2_Path(_dir, CAMPAIGN_STATE).write_bytes(_gk2_Path(
                _campaign_state_path(_campaign["out"])).read_bytes())
            _calls = len(_campaign["calls"])
            _gk2_resumes.append(
                raises(lambda: _campaign["rerun"](
                    out_dir=_dir, resume=True, candidate_pairs=_scope),
                    _needle)
                and len(_campaign["calls"]) == _calls)
        _gk2_fresh = os.path.join(_gk2_root, "fresh-other-scope")
        check("full-gold gold-killed: resume under the other scope refuses "
              "before any worker, and a hard-subset reference still refuses "
              "the gold-killed scope",
              all(_gk2_resumes) and len(_gk2_resumes) == 3
              and raises(lambda: _gk2["rerun"](
                  out_dir=_gk2_fresh, candidate_pairs=CANDIDATE_PAIRS_ALL),
                  "require gold-killed candidate scope")
              and raises(lambda: _gk2_all["rerun"](
                  out_dir=_gk2_fresh,
                  candidate_pairs=CANDIDATE_PAIRS_GOLD_KILLED),
                  "defined for full-gold scoring only")
              and not os.path.exists(_gk2_fresh),
              str(_gk2_resumes))

        # The saved-summary validator recomputes every withheld field from
        # the rows and rebuilds the scope-bound plan: a number put back, a
        # dropped disclosure, a respelled scope or an unbound plan refuses.
        _gk2_sidecar = sidecar_paths(_gk2["run"])[0]
        _gk2_canonical = os.path.join(_gk2["out"], SUMMARY)
        _gk2_state_path = _campaign_state_path(_gk2["out"])

        def _gk2_doctored(change, needle, plan_change=None):
            doc = copy.deepcopy(_gk2["summary"])
            change(doc)
            originals = {path: _gk2_Path(path).read_bytes()
                         for path in (_gk2_canonical, _gk2_state_path)}
            try:
                if plan_change is not None:
                    state = copy.deepcopy(_gk2_state)
                    plan_change(state["plan"])
                    state["plan_sha256"] = _gk2_content(state["plan"])
                    doc["root_campaign_plan_sha256"] = state["plan_sha256"]
                    _gk2_Path(_gk2_state_path).write_text(json.dumps(state))
                _gk2_Path(_gk2_canonical).write_text(json.dumps(doc))
                return raises(lambda: _validate_single_observation_summary(
                    doc, _gk2_sidecar, _gk2["run"],
                    reference_reader=_gk2["reader"],
                    campaign_status="complete"), needle)
            finally:
                for path, data in originals.items():
                    _gk2_Path(path).write_bytes(data)
        check("full-gold gold-killed: the validator refuses a re-inserted "
              "Jaccard, only-generated or candidate-only number",
              _gk2_doctored(lambda doc: doc.update(full_jaccard_macro=0.5),
                            "full_jaccard_macro")
              and _gk2_doctored(lambda doc: doc["per_item"]["i1"].update(
                  full_jaccard=2 / 3), "per_item")
              and _gk2_doctored(lambda doc: doc["per_item"]["i1"].update(
                  candidate_only_kills=0), "per_item")
              and _gk2_doctored(
                  lambda doc: doc.update(full_only_generated_macro=0.0),
                  "full_only_generated_macro"))
        check("full-gold gold-killed: the validator refuses a dropped "
              "disclosure, a respelled scope and a plan without the binding",
              _gk2_doctored(lambda doc: doc.pop("withheld_measures"),
                            "missing or unknown fields")
              and _gk2_doctored(lambda doc: doc.update(
                  candidate_pair_scope=CANDIDATE_PAIRS_ALL),
                  "candidate_pair_scope")
              and _gk2_doctored(
                  lambda doc: None, "cannot be rederived",
                  plan_change=lambda plan: plan.pop("candidate_pair_scope")))
        try:
            _validate_single_observation_summary(
                _gk2["summary"], _gk2_sidecar, _gk2["run"],
                reference_reader=_gk2["reader"], campaign_status="complete")
            _gk2_untouched = True
        except Exception as exc:                          # noqa: BLE001
            _gk2_untouched = repr(exc)
        check("full-gold gold-killed: the untouched summary still validates",
              _gk2_untouched is True, str(_gk2_untouched))

    with tempfile.TemporaryDirectory() as zero_root:
        zero = _single_observation_campaign(
            zero_root, outcomes={}, passed_item="i0",
            reference_items={
                "i0": {"full_gold_kills": [], "hard_subset": [], "stub_recall": None},
                "i1": {"full_gold_kills": ["m1"], "hard_subset": ["m1"], "stub_recall": 0.0}})
        zero_summary = zero["summary"]
        write_sidecar(zero_summary, zero["run"])
        reopened_zero = load_bound_test_quality(
            zero["run"], reference_controls_reader=zero["reader"])
        check("authenticated empty candidate restriction completes and reopens with zero executor calls",
              zero["calls"] == [] and reopened_zero["jobs"] == []
              and reopened_zero["candidate_pairs"] == 0
              and reopened_zero["hard_recall_macro"] is None
              and reopened_zero["per_item"]["i0"]["verdict"] == "not_scorable")
        from pathlib import Path
        candidate_bytes = Path(zero["run"]).read_bytes()
        Path(zero["run"]).write_bytes(candidate_bytes.replace(b"assert True", b"assert False"))
        check("zero-job reopening refuses changed candidate bytes",
              raises(lambda: load_bound_test_quality(
                  zero["run"], reference_controls_reader=zero["reader"]),
                  "binding"))
        Path(zero["run"]).write_bytes(candidate_bytes)
        state_path = _campaign_state_path(zero["out"])
        state_bytes = Path(state_path).read_bytes()
        state = json.loads(state_bytes)
        state["plan"]["zero_pair_candidate"]["passed_items"] = ["i1"]
        from .mutation_run import content_digest as _zero_digest
        state["plan_sha256"] = _zero_digest(state["plan"])
        Path(state_path).write_text(json.dumps(state))
        check("zero-job reopening refuses a changed certified passed-item set",
              raises(lambda: load_bound_test_quality(
                  zero["run"], reference_controls_reader=zero["reader"])))
        Path(state_path).write_bytes(state_bytes)


    with tempfile.TemporaryDirectory() as _so_root:
        _so_clean = _single_observation_campaign(
            _so_case(_so_root, "clean"),
            outcomes={("i1", "m1"): "failed", ("i1", "m2"): "passed",
                      ("i1", "m3"): "failed"})
        _so_sidecar = write_sidecar(_so_clean["summary"], _so_clean["run"])
        _so_reopened = load_bound_test_quality(
            _so_clean["run"], _so_sidecar,
            reference_controls_reader=_so_clean["reader"])
        _so_plan = _load_json_object(
            _campaign_state_path(_so_clean["out"]), "v2 root")["plan"]
        check("v2 execution plans candidate jobs ONLY -- no gold job object "
              "is constructed and no gold slice is executed",
              {job["side"] for job in _so_clean["calls"]} == {"candidate"}
              and {job["side"] for job in _so_plan["jobs"]} == {"candidate"}
              and _so_plan["gold_precomputed"] is True
              and _so_reopened["pairs_executed_gold"] == 3
              and _so_reopened["slices"] == [
                  {"out": _so_clean["calls"][0]["out"], "rows": 3,
                   "side": "candidate"}])
        check("v2 reopens by rederiving the exact reference/candidate pair "
              "identities",
              _so_reopened["schema"] == TEST_QUALITY_SUMMARY_SCHEMA_V2
              and _so_reopened["reference_pairs"] == 3
              and _so_reopened["candidate_pairs"] == 3
              and _so_reopened["candidate_scored_pairs"] == 3
              and _so_reopened["candidate_observation_id"] == "9" * 32
              and _so_reopened["verdict_basis"] == "hard_subset")
        _unknown_summary = copy.deepcopy(_so_clean["summary"])
        _unknown_summary["invented_compatibility_field"] = True
        check("v2 validation is exact-field and rejects an authored extension",
              raises(lambda: _validate_single_observation_summary(
                  _unknown_summary, _so_sidecar, _so_clean["run"],
                  reference_reader=_so_clean["reader"],
                  campaign_status="complete"),
                     "unknown fields"))

        # GRANDFATHERED ABSENCE, on the reading side only.  A v2 summary
        # written before the declared-subset disclosure existed carries
        # neither key, and a document that made no declaration is not a
        # document with an unknown field in it.  Both gates are exercised:
        # the closed field list, and the arithmetic rederivation from the
        # candidate rows, which reads an absent key as `None` and would
        # otherwise refuse `reference_omitted_items` at `0 != None`.
        #
        # Written over BOTH copies because the sidecar is validated against
        # its canonical campaign twin, and restored afterwards so the later
        # checks in this block still see the campaign they built.
        #
        # The positive is tautological against the field gate alone -- it is
        # built as the live list minus the optional set -- so the anchors are
        # the two negatives below and the assertion that a FRESH score of the
        # same campaign writes exactly the `0`/`None` that absence stands
        # for.  Without that the tolerance would be grounded in nothing.
        _pre_canonical = os.path.join(_so_clean["out"], SUMMARY)
        _pre_original = copy.deepcopy(_so_clean["summary"])

        def _pre_write(doc):
            from .mutation_run import sha256_file as _pre_sha
            for _path in (_pre_canonical, _so_sidecar):
                with open(_path, "w", encoding="utf-8") as _fh:
                    json.dump(doc, _fh, indent=1, sort_keys=True)
                    _fh.write("\n")
            # The root record pins the summary's hash, and a real campaign
            # wrote both together -- so restate it rather than leaving the
            # fixture describing a file that no longer exists.  This is what
            # makes the fixture a pre-disclosure CAMPAIGN and not just a
            # doctored file.
            _state_path = _campaign_state_path(_so_clean["out"])
            _state = _load_json_object(_state_path, "grandfather root")
            _state["artifacts"][SUMMARY] = _pre_sha(_pre_canonical)
            with open(_state_path, "w", encoding="utf-8") as _fh:
                json.dump(_state, _fh, indent=1, sort_keys=True)
                _fh.write("\n")

        def _pre_validate():
            _validate_single_observation_summary(
                _load_json_object(_so_sidecar, "grandfather sidecar"),
                _so_sidecar, _so_clean["run"],
                reference_reader=_so_clean["reader"],
                campaign_status="complete")

        # Named LITERALLY, not derived from the constant: a fixture built as
        # "the live list minus the optional set" is vacuous, because emptying
        # the constant empties the fixture too and the check keeps passing
        # over a document that was never pruned.  These are the two names the
        # declared-subset change added, and the equality below is what stops
        # the constant widening past them unnoticed.
        _pre_absent = ("reference_omitted_items", "reference_declared_reason")
        _pre_summary = {key: value for key, value in _pre_original.items()
                        if key not in _pre_absent}
        _pre_write(_pre_summary)
        _pre_admitted, _pre_detail = True, ""
        try:
            _pre_validate()
        except TestQualityRefused as _pre_exc:
            _pre_admitted, _pre_detail = False, str(_pre_exc)
        _pre_reopened = None
        if _pre_admitted:
            _pre_reopened = load_bound_test_quality(
                _so_clean["run"], _so_sidecar,
                reference_controls_reader=_so_clean["reader"])
        check("a v2 summary written before the declared-subset disclosure "
              "existed is READ as undeclared rather than refused, nothing is "
              "filled in on the way back, and its arithmetic still rederives "
              "from the candidate rows",
              _pre_admitted
              and _pre_reopened is not None
              and set(_pre_reopened) == _single_observation_summary_fields()
              - set(_pre_absent)
              # the tolerance is exactly these two names, and no wider
              and SINGLE_OBSERVATION_OPTIONAL_SUMMARY_FIELDS
              == frozenset(_pre_absent)
              and SINGLE_OBSERVATION_OPTIONAL_SUMMARY_FIELDS
              <= _single_observation_summary_fields()
              # absence means undeclared, stated as what the producer writes
              and _pre_original["reference_omitted_items"] == 0
              and _pre_original["reference_declared_reason"] is None,
              _pre_detail)
        _pre_write({key: value for key, value in _pre_summary.items()
                    if key != "reference_pairs_sha256"})
        check("the grandfather is exactly two names wide: any other absent "
              "field still refuses, by name and with an empty unknown list",
              raises(_pre_validate,
                     "missing=['reference_pairs_sha256'], unknown=[]"))
        _pre_write(dict(_pre_original, reference_omitted_items=6))
        check("only ABSENCE is read as undeclared: a declaration this "
              "reference never made still refuses at the rederivation",
              raises(_pre_validate,
                     "field(s) ['reference_omitted_items']"))
        _pre_write(_pre_original)

        # The 2026-09-01 envelope-equivalence ruling, at the third consumer:
        # `seal_reference_scope` reads the REGISTERED index out of the
        # registry, while every campaign under the renamed boundary config
        # stamps the ruled-equivalent one, so the summary/shard population
        # join has to resolve the ledger or no input can satisfy it.
        from ..data import versions as _SO_V
        _registered_index = _SO_V.population(
            "python-docx-v1")["asset_index_sha256"]
        _ruled_index = _SO_V.equivalent_asset_indexes("python-docx-v1")[0]
        _renamed_population = {"id": "python-docx-v1",
                               "asset_index_sha256": _registered_index}
        _so_renamed = _single_observation_campaign(
            _so_case(_so_root, "renamed-envelope"),
            outcomes={("i1", "m1"): "failed", ("i1", "m2"): "passed",
                      ("i1", "m3"): "failed"},
            population_overrides=_renamed_population,
            asset_index_sha256=_ruled_index)
        _so_renamed_reopened = load_bound_test_quality(
            _so_renamed["run"],
            write_sidecar(_so_renamed["summary"], _so_renamed["run"]),
            reference_controls_reader=_so_renamed["reader"])
        check("a v2 campaign stamping the CURRENT asset index scores against "
              "a population registered under the LEGACY one, and its shards "
              "stay pinned to the admitted digest",
              _so_renamed_reopened["asset_index_sha256"] == _ruled_index
              and _so_renamed_reopened["population_id"] == "python-docx-v1"
              and _ruled_index != _registered_index,
              str(_so_renamed_reopened.get("asset_index_sha256")))
        try:
            _single_observation_campaign(
                _so_case(_so_root, "unruled-envelope"),
                outcomes={("i1", "m1"): "failed", ("i1", "m2"): "passed",
                          ("i1", "m3"): "failed"},
                population_overrides=_renamed_population,
                asset_index_sha256="f" * 64)
            _unruled = "accepted"
        except TestQualityRefused as exc:
            _unruled = str(exc)
        check("an asset index no ruling equates still refuses, naming both "
              "digests it compared",
              "f" * 64 in _unruled and _registered_index in _unruled
              and _ruled_index in _unruled, _unruled)

        # Owner ruling 2026-09-15 at the final gate every producer passes:
        # VERSIONS.yml does not list harness 12 for coreshop, so a coreshop
        # reference recorded there still refuses a current-harness candidate.
        # The listed projects' acceptance runs through the CLI checks below.
        from .validate import HARNESS_VERSION as _SO_HARNESS
        try:
            _single_observation_campaign(
                _so_case(_so_root, "coreshop-h12-reference"),
                outcomes={("i1", "m1"): "failed", ("i1", "m2"): "passed",
                          ("i1", "m3"): "failed"},
                population_overrides={"asset_project": "coreshop"},
                authority_overrides={"harness_version": 12},
                input_overrides={"asset_project": "coreshop",
                                 "harness_version": _SO_HARNESS})
            _coreshop_h12 = "accepted"
        except TestQualityRefused as exc:
            _coreshop_h12 = str(exc)
        check("the summary validator refuses a coreshop reference recorded "
              "at harness 12 for a current-harness candidate, by name",
              "stable field(s) ['harness_version']" in _coreshop_h12,
              _coreshop_h12)

        # A candidate whose kill set is a strict subset of the reference's.
        _so_weak = _single_observation_campaign(
            _so_case(_so_root, "weaker"),
            outcomes={("i1", "m1"): "failed", ("i1", "m2"): "passed",
                      ("i1", "m3"): "passed"},
            reference_items={"i1": {
                "full_gold_kills": ["m1", "m2"],
                "hard_subset": ["m1", "m2"], "stub_recall": 0.0}})
        check("a candidate that kills a strict subset of the reference "
              "scores weaker rather than equivalent",
              _so_weak["summary"]["hard_recall_macro"] == 0.5
              and _so_weak["summary"]["verdicts"][WEAKER] == 1
              and _so_weak["summary"]["non_vacuous_passes"] == 0)

        # Harness 25, correction D, on recorded summaries.  Gold kills the
        # listed mutant `_nd`; the candidate kills the rest of G_i but not it.
        _d_outcomes = {("i1", "m1"): "failed", ("i1", _nd): "passed",
                       ("i1", "m3"): "failed"}
        _d_items = {"i1": {"full_gold_kills": ["m1", _nd],
                           "hard_subset": ["m1", _nd], "stub_recall": 0.0}}
        _d_recorded = _single_observation_campaign(
            _so_case(_so_root, "h25-d-recorded"), outcomes=_d_outcomes,
            reference_items=_d_items, mutants=("m1", _nd, "m3"),
            authority_overrides={"harness_version": 24},
            input_overrides={"harness_version": 24})
        _d_sidecar = write_sidecar(_d_recorded["summary"], _d_recorded["run"])
        _d_reopened = load_bound_test_quality(
            _d_recorded["run"], _d_sidecar,
            reference_controls_reader=_d_recorded["reader"])
        check("[H25-D] a summary scored at harness 24 re-derives as it was "
              "scored, the listed mutant still in its G_i",
              _d_reopened["harness_version"] == 24
              and _d_reopened["per_item"]["i1"]["hard_gold_killed"] == 2
              and _d_reopened["verdicts"][WEAKER] == 1,
              json.dumps(_d_reopened["per_item"])[:300])
        _d_current = _single_observation_campaign(
            _so_case(_so_root, "h25-d-current"), outcomes=_d_outcomes,
            reference_items=_d_items, mutants=("m1", _nd, "m3"))
        _d_current_reopened = load_bound_test_quality(
            _d_current["run"],
            write_sidecar(_d_current["summary"], _d_current["run"]),
            reference_controls_reader=_d_current["reader"])
        check("[H25-D] ...while a summary scored now leaves it out, when "
              "written and when re-derived",
              _d_current_reopened["per_item"]["i1"]["hard_gold_killed"] == 1
              and _d_current_reopened["verdicts"][EQUIVALENT] == 1,
              json.dumps(_d_current_reopened["per_item"])[:300])

        # The no-execution route of amendment section 5, step 4, through the
        # operator's command, with this fixture's reference standing in for
        # the installed one its flags name.
        import importlib.util as _d_importlib
        import io as _d_io
        from contextlib import redirect_stdout as _d_redirect
        from unittest.mock import patch as _d_patch
        from ..core.paths import BENCHMARK_ROOT
        from . import cli as _d_cli
        from .mutation_run import sha256_file as _d_sha256
        _d_spec = _d_importlib.spec_from_file_location(
            "select_h25_affected",
            os.path.join(BENCHMARK_ROOT, "scripts", "select_h25_affected.py"))
        _d_script = _d_importlib.module_from_spec(_d_spec)
        _d_spec.loader.exec_module(_d_script)
        _d_before = _d_sha256(_d_sidecar)
        _d_out = os.path.join(_so_root, "h25-d-rescore.json")
        with _d_patch.object(_d_cli, "_reference_controls_reader",
                             lambda _args: _d_recorded["reader"]), \
                _d_redirect(_d_io.StringIO()):
            _d_status = _d_script.main([
                "rescore", "--run", _d_recorded["run"],
                "--test-quality", _d_sidecar, "--out", _d_out])
        with open(_d_out, encoding="utf-8") as handle:
            _d_record = json.load(handle)
        check("[H25-D] the rescore command re-derives a recorded summary's "
              "verdicts without the listed pairs into a new record, and "
              "leaves the summary's bytes as they were",
              _d_status == 0
              and _d_record["schema"] == "r2t.h25-rescore/1"
              and _d_record["test_quality"]["harness_version"] == 24
              and _d_record["test_quality"]["sha256"] == _d_before
              and _d_record["changed_verdicts"] == {"i1": [WEAKER, EQUIVALENT]}
              and _d_record["score"]["per_item"]["i1"]["hard_gold_killed"] == 1
              and _d_record["score"]["candidate_scored_pairs"] == 2
              and _d_sha256(_d_sidecar) == _d_before,
              json.dumps(_d_record)[:400])

        # A candidate carrying its own section 5.1 pair, through the whole
        # producer: the summary discloses it, and the saved-evidence reader
        # rederives the same narrowed arithmetic from the rows.
        _so_excluded = _single_observation_campaign(
            _so_case(_so_root, "excluded"),
            outcomes={("i1", "m1"): "failed",
                      ("i1", "m2"): "container_error",
                      ("i1", "m3"): "failed"})
        _so_excluded_sidecar = write_sidecar(
            _so_excluded["summary"], _so_excluded["run"])
        _so_excluded_reopened = load_bound_test_quality(
            _so_excluded["run"], _so_excluded_sidecar,
            reference_controls_reader=_so_excluded["reader"])
        check("a candidate pair ending on infrastructure is disclosed by the "
              "run and rederived by the reader, with G narrowed to match",
              _so_excluded_reopened["candidate_excluded_count"] == 1
              and _so_excluded_reopened["candidate_excluded_pairs"] == [
                  {"item_id": "i1", "mutant_id": "m2",
                   "outcome": "container_error"}]
              and _so_excluded_reopened["candidate_pairs"] == 3
              and _so_excluded_reopened["candidate_scored_pairs"] == 2
              and _so_excluded_reopened["pairs_executed_candidate"] == 3
              and _so_excluded_reopened["full_recall_macro"] == 1.0
              and _so_excluded_reopened["reference_excluded_count"] == 0)

        # And the reference's own exclusion, which narrows what is EXECUTED.
        _so_narrow = _single_observation_campaign(
            _so_case(_so_root, "narrowed"),
            outcomes={("i1", "m1"): "failed", ("i1", "m2"): "passed"},
            excluded={("i1", "m3")},
            reference_pairs={("i1", "m1"), ("i1", "m2")})
        check("a reference that excluded a pair narrows the candidate "
              "campaign instead of refusing every v2 summary",
              _so_narrow["summary"]["pairs_expected"] == 2
              and _so_narrow["summary"]["mutants_in_population"] == 2
              and _so_narrow["summary"]["reference_excluded_count"] == 1
              and _so_narrow["summary"]["reference_pairs"] == 2
              and len(_so_narrow["calls"][0]["mutants"]) == 2)

        # ---------------- labelled reference sensitivity (stub gate waived)
        #
        # specifications/SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md: the same
        # fixture reference, G_i1 = {m1, m2} and H_i1 = {m1}, scored under
        # the labelled basis with the same candidate rows as the eligible
        # campaign.  Waiving the gate changes no number: every measure is the
        # eligible derivation's, and the label fields travel beside them.
        from . import report as _sens_report
        _sens_label = "sylius_stub_gate_waived_v1"
        _sens_outcomes = {("i1", "m1"): "failed", ("i1", "m2"): "passed",
                          ("i1", "m3"): "failed"}
        _sens = _single_observation_campaign(
            _so_case(_so_root, "sensitivity"), outcomes=_sens_outcomes,
            sensitivity=_sens_label)
        _sens_summary = _sens["summary"]
        _sens_executed = {(item_id, mutant["id"])
                          for job in _sens["calls"]
                          for mutant in job["mutants"]
                          for item_id in job["by_mutant"][mutant["id"]]}
        check("sensitivity: the candidate executes every pair of its passes, "
              "as against eligible controls, and gold is projected, never "
              "executed",
              _sens_executed == _so_pairs
              and {job["side"] for job in _sens["calls"]} == {"candidate"}
              and _sens_summary["candidate_pairs"]
              == _so_clean["summary"]["candidate_pairs"] == 3,
              str(sorted(_sens_executed)))
        _sens_same = (
            "verdict_basis", "companion_basis", "n_passed", "n_scorable",
            "recall_macro", "hard_recall_macro", "full_recall_macro",
            "full_only_generated_macro", "full_jaccard_macro", "verdicts",
            "non_vacuous_passes", "reference_pairs", "reference_pairs_sha256",
            "reference_excluded_count", "candidate_pairs",
            "candidate_pairs_sha256", "candidate_excluded_count",
            "candidate_scored_pairs", "candidate_scored_pairs_sha256")
        _sens_item = _sens_summary["per_item"]["i1"]
        _full_item = _so_clean["summary"]["per_item"]["i1"]
        check("sensitivity: the hard-subset verdict, hard recall, every "
              "full-gold companion and the non-vacuous count equal the "
              "eligible campaign's on the same rows",
              all(_sens_summary[key] == _so_clean["summary"][key]
                  for key in _sens_same)
              and {key: value for key, value in _sens_item.items()
                   if key != "full_unkilled"} == _full_item
              and _sens_summary["verdict_basis"] == "hard_subset"
              and _sens_summary["companion_basis"] == "full_gold"
              and _sens_item["verdict"] == EQUIVALENT
              and _sens_summary["hard_recall_macro"] == 1.0
              and _sens_summary["full_recall_macro"] == 0.5
              and _sens_summary["full_jaccard_macro"] is not None
              and _sens_summary["non_vacuous_passes"] == 1,
              json.dumps({key: [_sens_summary.get(key),
                                _so_clean["summary"].get(key)]
                          for key in _sens_same}, default=str)[:600])
        check("sensitivity: the label, inference_valid false, the waived "
              "stub gate and the gold disagreements travel in the summary",
              _sens_summary["sensitivity"] == _sens_label
              and _sens_summary["inference_valid"] is False
              and _sens_summary["reference_stub_gate"]
              == {"macro_recall": 0.364, "threshold": 0.02,
                  "eligible": False}
              and _sens_summary["reference_gold_disagreements"]
              == {"source": None, "sha256": None, "pairs": []}
              and not SENSITIVITY_SUMMARY_FIELDS
              & set(_so_clean["summary"]))
        check("sensitivity: each item lists the full-gold kills its pass "
              "did not kill, and an eligible summary has no such field",
              _sens_item["full_unkilled"] == ["m2"]
              and "full_unkilled" not in _full_item)
        _sens_sidecar = write_sidecar(_sens_summary, _sens["run"])
        _sens_reopened = load_bound_test_quality(
            _sens["run"], _sens_sidecar,
            reference_controls_reader=_sens["reader"])
        _sens_nv = _sens_report.non_vacuous(
            load_jsonl(_sens["run"]), _sens_reopened)
        check("sensitivity: the saved summary reopens by rederivation and "
              "the code-of-record non-vacuous count reads it, labelled",
              _sens_reopened == _sens_summary
              and _sens_nv["non_vacuous_passes"] == 1
              and _sens_nv["sensitivity"] == _sens_label
              and _sens_nv["inference_valid"] is False
              and _sens_nv["publication_ready"] is False
              and any("sensitivity" in reason
                      for reason in _sens_nv["withheld_reasons"]))
        import contextlib as _sens_contextlib
        import io as _sens_io
        _sens_console = _sens_io.StringIO()
        with _sens_contextlib.redirect_stdout(_sens_console):
            print_summary(_sens_summary)
        check("sensitivity: the console names the label and the waived gate "
              "beside the unchanged hard recall",
              "LABELLED POST-HOC SENSITIVITY sylius_stub_gate_waived_v1"
              in _sens_console.getvalue()
              and "stub gate WAIVED" in _sens_console.getvalue()
              and "hard recall 1.000" in _sens_console.getvalue(),
              _sens_console.getvalue()[-400:])
        _sens_unlabelled = {key: value for key, value in _sens_summary.items()
                            if key not in SENSITIVITY_SUMMARY_FIELDS}
        check("sensitivity: a summary that drops its label does not reopen "
              "against the labelled controls, and a labelled summary does "
              "not reopen against eligible controls",
              raises(lambda: _validate_single_observation_summary(
                  _sens_unlabelled, _sens_sidecar, _sens["run"],
                  reference_reader=_sens["reader"],
                  campaign_status="complete"))
              and raises(lambda: _validate_single_observation_summary(
                  _sens_summary, _sens_sidecar, _sens["run"],
                  reference_reader=_so_clean["reader"],
                  campaign_status="complete")))
        # A host's gold disagreement on (i1, m2) has already left G and H
        # in the derived controls (reference_controls' own test); the scorer
        # scores what is left and copies the disclosure.
        _sens_controls, _sens_authority = _single_fixture_controls(
            {"i1": {"full_gold_kills": ["m1"], "hard_subset": ["m1"],
                    "stub_recall": 1.0}},
            _so_pairs, sensitivity=_sens_label,
            disagreements={("i1", "m2")})
        _sens_direct = score_single_observation(
            {"i1": []}, [_so_row("m1", "failed"), _so_row("m2", "passed"),
                         _so_row("m3", "passed")],
            authority=_sens_authority)
        check("sensitivity: a gold disagreement leaves G and H and is listed "
              "in the summary",
              _sens_direct["candidate_pairs"] == 3
              and _sens_direct["non_vacuous_passes"] == 1
              and _sens_direct["per_item"]["i1"]["hard_denominator"] == 1
              and _sens_direct["per_item"]["i1"]["full_denominator"] == 1
              and _sens_direct["reference_gold_disagreements"]
              == {"source": "fixture pilot", "sha256": "d" * 64,
                  "pairs": [{"item_id": "i1", "mutant_id": "m2"}]}
              and _sens_direct["per_item"]["i1"]["full_unkilled"] == [])

        # ---------------- accepted reference appliers (VERSIONS.yml)
        #
        # A campaign whose applier differs from the reference's recorded one
        # refuses at summary validation, unless `accepted_reference_appliers`
        # lists it beside the recorded one for the project; then every
        # number is the recorded applier's campaign's.
        from unittest.mock import patch as _ap_patch
        from ..data import versions as _ap_versions
        _ap_later = {"applier_sha256": "4" * 64}
        check("applier: a campaign applier other than the reference's "
              "recorded one refuses at summary validation",
              raises(lambda: _single_observation_campaign(
                  _so_case(_so_root, "applier-unlisted"),
                  outcomes=_sens_outcomes, input_overrides=_ap_later),
                  "applier_sha256"))
        with _ap_patch.dict(_ap_versions.component("harness"), {
                "accepted_reference_appliers": {
                    "fixture": {"3" * 64: ["4" * 64]}}}):
            _ap = _single_observation_campaign(
                _so_case(_so_root, "applier-accepted"),
                outcomes=_sens_outcomes, input_overrides=_ap_later)
        check("applier: an applier VERSIONS.yml accepts for the project "
              "validates and scores exactly as the recorded applier's",
              _ap["summary"]["applier_sha256"] == "4" * 64
              and all(_ap["summary"][key] == _so_clean["summary"][key]
                      for key in ("verdicts", "non_vacuous_passes",
                                  "hard_recall_macro", "full_recall_macro",
                                  "candidate_pairs")))

        # ---------------- accepted reference seeds (VERSIONS.yml)
        #
        # Likewise a campaign on another seed: the workspace and substrate a
        # project's `accepted_reference_seeds` entry lists, as one pair,
        # beside the reference's recorded pair (CoreShop's seed v1.1,
        # BENCHMARK_V2_SPEC.md section 8.5).  One field of the pair alone,
        # another project's entry or any other seed still refuses.
        _sd_later = {"workspace_seed_digest": "8" * 64,
                     "substrate_baseline_sha256": "9" * 64}
        _sd_entry = {"recorded": {"workspace_seed_digest": "6" * 64,
                                  "substrate_baseline_sha256": "2" * 64},
                     "accepted": [_sd_later]}
        check("seed: a campaign seed other than the reference's recorded one "
              "refuses at summary validation",
              raises(lambda: _single_observation_campaign(
                  _so_case(_so_root, "seed-unlisted"),
                  outcomes=_sens_outcomes, input_overrides=_sd_later),
                  "substrate_baseline_sha256', 'workspace_seed_digest"))
        with _ap_patch.dict(_ap_versions.component("harness"), {
                "accepted_reference_seeds": {"fixture": [_sd_entry]}}):
            _sd = _single_observation_campaign(
                _so_case(_so_root, "seed-accepted"),
                outcomes=_sens_outcomes, input_overrides=_sd_later)
            _sd_half = _sd_later["workspace_seed_digest"]
            check("seed: one field of the accepted pair alone still refuses",
                  raises(lambda: _single_observation_campaign(
                      _so_case(_so_root, "seed-half"),
                      outcomes=_sens_outcomes,
                      input_overrides={"workspace_seed_digest": _sd_half}),
                      "workspace_seed_digest"))
        with _ap_patch.dict(_ap_versions.component("harness"), {
                "accepted_reference_seeds": {"other-project": [_sd_entry]}}):
            check("seed: another project's entry does not admit it",
                  raises(lambda: _single_observation_campaign(
                      _so_case(_so_root, "seed-other-project"),
                      outcomes=_sens_outcomes, input_overrides=_sd_later),
                      "workspace_seed_digest"))
        check("seed: a seed VERSIONS.yml accepts for the project validates "
              "and scores exactly as the recorded seed's",
              _sd["summary"]["workspace_seed_digest"] == "8" * 64
              and _sd["summary"]["substrate_baseline_sha256"] == "9" * 64
              and all(_sd["summary"][key] == _so_clean["summary"][key]
                      for key in ("verdicts", "non_vacuous_passes",
                                  "hard_recall_macro", "full_recall_macro",
                                  "candidate_pairs")))

        # --------- gold-killed candidate scope on the labelled basis
        #
        # GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md as adopted for the Sylius
        # labelled basis (owner, 2026-09-28).  The same fixture reference,
        # G_i1 = {m1, m2} and H_i1 = {m1}, and a candidate that also kills
        # m2 (in G, not in H) and m3 (outside G), so the all-pairs
        # companions are real numbers the gold-killed slice cannot see.
        # Each outcome set is scored under both scopes with the same
        # outcomes on G.
        from pathlib import Path as _gk_Path
        from .mutation_run import pair_set_digest as _gk_digest
        _gk_g = {("i1", "m1"), ("i1", "m2")}
        _gk_same = (
            "verdict_basis", "companion_basis", "n_passed", "n_scorable",
            "recall_macro", "hard_recall_macro", "full_recall_macro",
            "verdicts", "non_vacuous_passes", "reference_pairs",
            "reference_pairs_sha256", "reference_excluded_count",
            "sensitivity", "inference_valid", "reference_stub_gate",
            "reference_gold_disagreements")
        _gk_same_item = (
            "verdict_basis", "verdict", "hard_gold_killed",
            "hard_candidate_killed", "hard_denominator", "hard_recall",
            "full_gold_killed", "full_candidate_killed", "full_denominator",
            "full_recall", "full_unkilled")
        _gk_same_nv = (
            "non_vacuous_passes", "non_vacuous_pass_at_1",
            "equivalent_to_reference", "weaker", "vacuous", "not_scorable",
            "recall_macro", "hard_recall_macro", "full_recall_macro",
            "hard_n_scored", "companion_n_scored", "sensitivity",
            "inference_valid", "publication_ready", "stale")
        _gk_nulls = ("candidate_only_kills", "full_union",
                     "full_only_generated", "full_jaccard")
        _gk_cases = {}
        for _gk_name, _gk_outcomes, _gk_nv_expected in (
                ("kills", {("i1", "m1"): "failed", ("i1", "m2"): "failed",
                           ("i1", "m3"): "failed"}, 1),
                ("misses-hard", {("i1", "m1"): "passed",
                                 ("i1", "m2"): "failed",
                                 ("i1", "m3"): "failed"}, 0)):
            _gk_all = _single_observation_campaign(
                _so_case(_so_root, f"gk-all-{_gk_name}"),
                outcomes=_gk_outcomes, sensitivity=_sens_label)
            _gk = _single_observation_campaign(
                _so_case(_so_root, f"gk-{_gk_name}"),
                outcomes=_gk_outcomes, sensitivity=_sens_label,
                candidate_pairs=CANDIDATE_PAIRS_GOLD_KILLED)
            _gk_cases[_gk_name] = (_gk_all, _gk)
            _gk_a, _gk_s = _gk_all["summary"], _gk["summary"]
            _gk_executed = {(item_id, mutant["id"])
                            for job in _gk["calls"]
                            for mutant in job["mutants"]
                            for item_id in job["by_mutant"][mutant["id"]]}
            check(f"gold-killed ({_gk_name}): the candidate executes only "
                  "G_i of its passes and gold is projected, never executed",
                  _gk_executed == _gk_g
                  and {job["side"] for job in _gk["calls"]} == {"candidate"}
                  and _gk_s["candidate_pairs"] == 2
                  and _gk_s["pairs_executed_candidate"] == 2
                  and _gk_a["candidate_pairs"] == 3,
                  str(sorted(_gk_executed)))
            check(f"gold-killed ({_gk_name}): recall on both bases, the "
                  "hard-subset verdict and the non-vacuous count equal the "
                  "all-pairs campaign's on the same outcomes",
                  all(_gk_s[key] == _gk_a[key] for key in _gk_same)
                  and all(_gk_s["per_item"]["i1"][key]
                          == _gk_a["per_item"]["i1"][key]
                          for key in _gk_same_item)
                  and _gk_s["non_vacuous_passes"] == _gk_nv_expected
                  and _gk_s["verdict_basis"] == "hard_subset"
                  and _gk_s["companion_basis"] == "full_gold",
                  json.dumps({key: [_gk_s.get(key), _gk_a.get(key)]
                              for key in _gk_same}, default=str)[:600])
            check(f"gold-killed ({_gk_name}): candidate-only kills, "
                  "only-generated and Jaccard are present and null and "
                  "named, where all pairs measured them",
                  _gk_s["candidate_pair_scope"] == CANDIDATE_PAIRS_GOLD_KILLED
                  and _gk_s["withheld_measures"]
                  == list(SINGLE_OBSERVATION_GOLD_KILLED_WITHHELD)
                  and _gk_s["full_only_generated_macro"] is None
                  and _gk_s["full_jaccard_macro"] is None
                  and all(key in _gk_s["per_item"]["i1"]
                          and _gk_s["per_item"]["i1"][key] is None
                          for key in _gk_nulls)
                  and _gk_a["per_item"]["i1"]["candidate_only_kills"] == 1
                  and _gk_a["full_jaccard_macro"] is not None
                  and not GOLD_KILLED_SUMMARY_FIELDS & set(_gk_a),
                  str(_gk_s["per_item"]["i1"]))
            _gk_views = []
            for _gk_campaign in (_gk_all, _gk):
                _gk_sidecar = write_sidecar(_gk_campaign["summary"],
                                            _gk_campaign["run"])
                _gk_reopened = load_bound_test_quality(
                    _gk_campaign["run"], _gk_sidecar,
                    reference_controls_reader=_gk_campaign["reader"])
                _gk_views.append((_gk_reopened, _sens_report.non_vacuous(
                    load_jsonl(_gk_campaign["run"]), _gk_reopened)))
            (_gk_all_open, _gk_all_nv), (_gk_open, _gk_nv) = _gk_views
            check(f"gold-killed ({_gk_name}): both summaries reopen by "
                  "rederivation and report.non_vacuous reads the same "
                  "numbers, the gold-killed one naming its scope",
                  _gk_open == _gk_s and _gk_all_open == _gk_a
                  and all(_gk_nv[key] == _gk_all_nv[key]
                          for key in _gk_same_nv)
                  and _gk_nv["candidate_pair_scope"]
                  == CANDIDATE_PAIRS_GOLD_KILLED
                  and _gk_nv["withheld_measures"]
                  == list(SINGLE_OBSERVATION_GOLD_KILLED_WITHHELD)
                  and "candidate_pair_scope" not in _gk_all_nv,
                  json.dumps({key: [_gk_nv.get(key), _gk_all_nv.get(key)]
                              for key in _gk_same_nv}, default=str)[:600])

        _gk_all, _gk = _gk_cases["kills"]
        _gk_plan = _load_json_object(
            _campaign_state_path(_gk["out"]), "gold-killed root")["plan"]
        _gk_all_plan = _load_json_object(
            _campaign_state_path(_gk_all["out"]), "all-pairs root")["plan"]
        check("gold-killed: the root plan binds the scope, the slice's pair "
              "count and digest, and an all-pairs plan keeps its shape",
              _gk_plan["candidate_pair_scope"]
              == {"scope": CANDIDATE_PAIRS_GOLD_KILLED, "candidate_pairs": 2,
                  "candidate_pairs_sha256": _gk_digest(_gk_g),
                  "gold_pair_plan": False}
              and _gk_plan["expected_pairs"] == 2
              and _gk_plan["expected_pairs_sha256"] == _gk_digest(_gk_g)
              and "candidate_pair_scope" not in _gk_all_plan,
              str(_gk_plan.get("candidate_pair_scope")))
        # Resume across scopes, through the producer: each root record is
        # copied alone into a fresh directory and resumed.  Under its own
        # scope the plan matches and the terminal status is what refuses;
        # under the other scope the plan itself does not match.
        _gk_resume_ok = True
        _gk_resumes = 0
        for _gk_campaign, _gk_own, _gk_other in (
                (_gk, CANDIDATE_PAIRS_GOLD_KILLED, CANDIDATE_PAIRS_ALL),
                (_gk_all, CANDIDATE_PAIRS_ALL, CANDIDATE_PAIRS_GOLD_KILLED)):
            for _gk_scope, _gk_needle in (
                    (_gk_other, "different root campaign plan"),
                    (_gk_own, "terminal root campaign status")):
                _gk_resumes += 1
                _gk_dir = _so_case(_so_root, f"gk-resume-{_gk_resumes}")
                _gk_Path(_gk_dir, CAMPAIGN_STATE).write_bytes(_gk_Path(
                    _campaign_state_path(_gk_campaign["out"])).read_bytes())
                _gk_calls = len(_gk_campaign["calls"])
                _gk_resume_ok &= raises(lambda: _gk_campaign["rerun"](
                    out_dir=_gk_dir, resume=True,
                    candidate_pairs=_gk_scope), _gk_needle) \
                    and len(_gk_campaign["calls"]) == _gk_calls
        check("gold-killed: resume refuses a root campaign planned under the "
              "other scope before any worker runs", _gk_resume_ok)

        # The saved-summary validator recomputes every withheld field: a
        # number put back, or the scope dropped or respelled, refuses.
        _gk_sidecar = sidecar_paths(_gk["run"])[0]
        _gk_canonical = os.path.join(_gk["out"], SUMMARY)

        def _gk_doctored(change, needle):
            doc = copy.deepcopy(_gk["summary"])
            change(doc)
            original = _gk_Path(_gk_canonical).read_bytes()
            try:
                _gk_Path(_gk_canonical).write_text(json.dumps(doc))
                return raises(lambda: _validate_single_observation_summary(
                    doc, _gk_sidecar, _gk["run"],
                    reference_reader=_gk["reader"],
                    campaign_status="complete"), needle)
            finally:
                _gk_Path(_gk_canonical).write_bytes(original)
        check("gold-killed: the validator refuses a re-inserted Jaccard, "
              "only-generated or candidate-only count",
              _gk_doctored(lambda doc: doc.update(full_jaccard_macro=0.5),
                           "full_jaccard_macro")
              and _gk_doctored(lambda doc: doc["per_item"]["i1"].update(
                  full_jaccard=0.5), "per_item")
              and _gk_doctored(lambda doc: doc["per_item"]["i1"].update(
                  candidate_only_kills=0), "per_item")
              and _gk_doctored(
                  lambda doc: doc.update(full_only_generated_macro=0.0),
                  "full_only_generated_macro"))
        check("gold-killed: a summary that drops or respells its scope "
              "refuses",
              _gk_doctored(lambda doc: [doc.pop(key) for key in
                                        GOLD_KILLED_SUMMARY_FIELDS],
                           "differ from the exact passed-item pair set")
              and _gk_doctored(lambda doc: doc.pop("withheld_measures"),
                               "malformed candidate pair scope")
              and _gk_doctored(lambda doc: doc.update(
                  candidate_pair_scope=CANDIDATE_PAIRS_ALL),
                  "malformed candidate pair scope"))
        _gk_console = _sens_io.StringIO()
        with _sens_contextlib.redirect_stdout(_gk_console):
            print_summary(_gk["summary"])
        check("gold-killed: the console keeps the label and names the scope "
              "and what it does not measure",
              "LABELLED POST-HOC SENSITIVITY sylius_stub_gate_waived_v1"
              in _gk_console.getvalue()
              and "candidate pairs: gold-killed only" in _gk_console.getvalue()
              and GOLD_KILLED_NOT_MEASURED in _gk_console.getvalue()
              and "companion (full jaccard, full_gold basis): not measured"
              in _gk_console.getvalue(),
              _gk_console.getvalue()[-600:])
        # Refusals: the premise H_i within G_i, an empty slice, and every
        # route this line has no gold-killed adoption for.
        _gk_bad_hard = _single_fixture_controls(
            {"i1": {"full_gold_kills": ["m1"], "hard_subset": ["m1", "m3"],
                    "stub_recall": 0.0}}, _so_pairs,
            sensitivity=_sens_label)[1]
        _gk_no_kill = _single_fixture_controls(
            {"i1": {"full_gold_kills": [], "hard_subset": [],
                    "stub_recall": None}}, _so_pairs,
            sensitivity=_sens_label)[1]
        check("gold-killed: a hard subset outside G_i and a pass set gold "
              "kills nothing on refuse instead of shrinking or emptying",
              raises(lambda: single_observation_candidate_pairs(
                  _gk_bad_hard, {"i1"}, CANDIDATE_PAIRS_GOLD_KILLED),
                  "not full-gold kills")
              and raises(lambda: score_single_observation(
                  {"i1": []}, [], authority=_gk_no_kill,
                  candidate_pair_scope=CANDIDATE_PAIRS_GOLD_KILLED),
                  "nothing to execute")
              and single_observation_candidate_pairs(
                  _gk_bad_hard, {"i1"}) == _so_pairs)
        check("gold-killed: an unknown scope refuses, and a gold-killed "
              "slice of an unlabelled hard-subset reference refuses",
              raises(lambda: run_test_quality(
                  run_rows=[], gold_baseline_rows=[], manifest={},
                  by_mutant={}, out_dir=os.path.join(_so_root, "gk-v1"),
                  execute=lambda job: None, n_workers=1,
                  candidate_pairs="some"), "unknown candidate pair scope")
              and raises(lambda: single_observation_candidate_pairs(
                  _so_authority, {"i1"}, CANDIDATE_PAIRS_GOLD_KILLED),
                  "adopted only for the labelled stub-gate-waived basis")
              and raises(lambda: _so_clean["rerun"](
                  out_dir=_so_case(_so_root, "gk-unlabelled"),
                  candidate_pairs=CANDIDATE_PAIRS_GOLD_KILLED),
                  "defined for full-gold scoring only")
              and not os.path.exists(os.path.join(_so_root, "gk-v1")))

    # ------------------------------------------------------------ the plan
    passed = passed_solutions(run_rows)
    check("only PASSED rows are scored",
          sorted(passed) == ["i_eqm", "i_full", "i_nocov", "i_vac", "i_weak"],
          str(sorted(passed)))
    check("a failed row contributes neither a solution nor an item",
          "i_fail" not in passed and "i_pad0" not in passed)
    check("two passed rows for one item are refused, not resolved by order",
          raises(lambda: passed_solutions(run_rows + run_rows[:1]),
                 "duplicate item_id"))
    mixed_retry = [run_rows[0], {**run_rows[0], "outcome": "failed"}]
    check("a passed/failed retry pair is refused rather than selecting the "
          "pass after outcome filtering",
          raises(lambda: passed_solutions(mixed_retry),
                 "duplicate item_id"))

    mutants, restricted, covering = population(manifest, by_mutant, passed)
    check("the population is the UNION of the mutants covering the passes",
          [m["id"] for m in mutants] == ["m1", "m2", "m3", "m4", "m5"],
          str([m["id"] for m in mutants]))
    check("a mutant covering only a FAILED item is not in the population",
          "m6" not in restricted)
    check("coverage is restricted to the passed items, not the corpus",
          restricted["m1"] == ["i_full", "i_weak"], str(restricted["m1"]))
    check("an item no mutant covers is still a pass, with zero covering",
          covering["i_nocov"] == [] and covering["i_full"] == ["m1", "m2"],
          str(covering))
    check("the whole population is planned — nothing is sampled",
          len(mutants) == len({m for m, i in by_mutant.items()
                               if set(i) & set(passed)}))
    check("the expected pairs are every (item, mutant) in the population",
          expected_pairs(restricted) ==
          {("i_full", "m1"), ("i_weak", "m1"), ("i_full", "m2"),
           ("i_weak", "m3"), ("i_vac", "m4"), ("i_eqm", "m5")},
          str(sorted(expected_pairs(restricted))))

    with tempfile.TemporaryDirectory() as d:
        jobs = plan_jobs(mutants, {"candidate": passed, "gold": passed},
                         restricted, 2, d)
        check("one job per (side, worker), and both sides are planned",
              len(jobs) == 4 and {j["side"] for j in jobs} == set(SIDES),
              str([(j["side"], j["worker"]) for j in jobs]))
        per_worker: dict = {}
        for j in jobs:
            per_worker.setdefault(j["worker"], []).append(j["side"])
        check("a worker's two sides are queued, never concurrent (its "
              "workspace is a mutex)",
              all(sorted(v) == ["candidate", "gold"]
                  for v in per_worker.values()), str(per_worker))
        for side in SIDES:
            ids = [m["id"] for j in jobs if j["side"] == side
                   for m in j["mutants"]]
            check(f"the {side} shards partition the population exactly",
                  sorted(ids) == sorted(m["id"] for m in mutants)
                  and len(ids) == len(set(ids)), str(sorted(ids)))
        check("new campaigns balance expected pair counts with deterministic "
              "LPT",
              [m["id"] for j in jobs
               if j["side"] == "candidate" and j["worker"] == 0
               for m in j["mutants"]] == ["m1", "m4"]
              and {j["shard_policy"] for j in jobs}
              == {SHARD_POLICY_BALANCED_PAIRS_V1})
        from .mutation_run import (EXECUTION_POLICY_BATCH_BISECT_V1,
                                   MUTATION_IDENTITY_SCHEMA,
                                   MUTATION_IDENTITY_SCHEMA_V3,
                                   MUTATION_IDENTITY_SCHEMA_V4,
                                   content_digest, pair_set_digest,
                                   row_identity_stamp)
        check("new LPT shards bind policy in identity v3 and every row stamp",
              all(j["identity"]["schema"]
                  == MUTATION_IDENTITY_SCHEMA_V3
                  and j["identity"]["shard_policy"]
                  == SHARD_POLICY_BALANCED_PAIRS_V1
                  and row_identity_stamp(j["identity"])["shard_policy"]
                  == SHARD_POLICY_BALANCED_PAIRS_V1
                  for j in jobs))
        v4_union = {
            "execution_policy": EXECUTION_POLICY_BATCH_BISECT_V1,
            "batch_plan_sha256": "1" * 64,
            "max_batch_members": 4,
            "max_batch_instances": 12,
            "stack_reset_sha256": "2" * 64,
            "batch_journal_schema": "r2t.batch-journal/1",
            "compute_cap_sha256": None,
            "reuse_projection_sha256": None,
            "estimand_pairs_sha256": pair_set_digest(
                expected_pairs(restricted)),
            "preflight_cache_policy": "r2t.preflight-cache/1",
            "observation_id": "3" * 32,
        }
        v4_dir = os.path.join(d, "v4-reconstruction")
        v4_jobs = plan_jobs(
            mutants, {"candidate": passed, "gold": passed}, restricted, 2,
            v4_dir, **v4_union)
        v4_plan = build_test_quality_campaign_plan(
            v4_jobs, expected=expected_pairs(restricted))
        rebuilt_v4_jobs = plan_jobs(
            mutants, {"candidate": passed, "gold": passed}, restricted, 2,
            v4_dir, **_v4_execution_kwargs(v4_jobs[0]["identity"]))
        rebuilt_v4_plan = build_test_quality_campaign_plan(
            rebuilt_v4_jobs, expected=expected_pairs(restricted))
        check("native reconstruction threads the authoritative complete v4 "
              "batch/cache/observation union without dropping a field",
              all(job["identity"]["schema"]
                  == MUTATION_IDENTITY_SCHEMA_V4 for job in v4_jobs)
              and _v4_execution_kwargs(v4_jobs[0]["identity"]) == v4_union
              and content_digest(rebuilt_v4_plan) == content_digest(v4_plan))
        forged_identity = dict(
            jobs[0]["identity"], shard_policy=SHARD_POLICY_STRIDED_V1)
        check("a policy edit cannot retain a valid v3 identity or campaign "
              "digest",
              raises(lambda: _planned_policy_identity_binding(
                  [{"identity": forged_identity}],
                  SHARD_POLICY_BALANCED_PAIRS_V1),
                  "identity v3 is reserved"))
        legacy_jobs = plan_jobs(
            mutants, {"candidate": passed}, restricted, 2, d,
            sides=("candidate",),
            shard_policy=SHARD_POLICY_STRIDED_V1)
        check("the named legacy policy reproduces historical striding",
              [m["id"] for j in legacy_jobs if j["worker"] == 0
               for m in j["mutants"]] == ["m1", "m3", "m5"])
        check("historical striding retains the unbound v2 identity spelling",
              all(j["identity"]["schema"] == MUTATION_IDENTITY_SCHEMA
                  and "shard_policy" not in j["identity"]
                  for j in legacy_jobs))
        early_lpt_jobs = plan_jobs(
            mutants, {"candidate": passed}, restricted, 2, d,
            sides=("candidate",), bind_shard_policy=False)
        check("early unbound LPT v2 jobs remain byte-reconstructable but are "
              "ineligible without an immutable exact-artifact authority",
              all(j["identity"]["schema"] == MUTATION_IDENTITY_SCHEMA
                  and "shard_policy" not in j["identity"]
                  for j in early_lpt_jobs)
              and raises(lambda: build_test_quality_campaign_plan(
                  early_lpt_jobs),
                  "immutable exact-artifact authority"))
        check("candidate and gold receive identical balanced membership",
              [[m["id"] for m in j["mutants"]]
               for j in jobs if j["side"] == "candidate"]
              == [[m["id"] for m in j["mutants"]]
                  for j in jobs if j["side"] == "gold"])
        check("balanced assignment is deterministic",
              [[m["id"] for m in shard] for shard in shard_mutants(
                  mutants, restricted, passed, 2)]
              == [[m["id"] for m in shard] for shard in shard_mutants(
                  mutants, restricted, passed, 2)])
        synthetic_files = {f"i{k}": [] for k in range(1, 9)}
        synthetic_mutants = [mut("wide", 20), mut("four", 21),
                             mut("three", 22), mut("two", 23),
                             mut("one", 24)]
        synthetic_map = {
            "wide": [f"i{k}" for k in range(1, 6)],
            "four": [f"i{k}" for k in range(1, 5)],
            "three": [f"i{k}" for k in range(1, 4)],
            "two": ["i1", "i2"], "one": ["i1"],
        }
        balanced = shard_mutants(
            synthetic_mutants, synthetic_map, synthetic_files, 2)
        balanced_loads = [sum(len(synthetic_map[m["id"]]) for m in shard)
                          for shard in balanced]
        strided = shard_mutants(
            synthetic_mutants, synthetic_map, synthetic_files, 2,
            policy=SHARD_POLICY_STRIDED_V1)
        strided_loads = [sum(len(synthetic_map[m["id"]]) for m in shard)
                         for shard in strided]
        check("pair-count LPT lowers the deterministic worst-shard load",
              max(balanced_loads) == 8 and max(strided_loads) == 9,
              f"balanced={balanced_loads}, strided={strided_loads}")
        check("more workers than mutants plans no empty job",
              all(j["mutants"] for j in plan_jobs(
                  mutants, {"candidate": passed}, restricted, 9, d,
                  sides=("candidate",))))
        check("a non-positive worker count is refused",
              raises(lambda: plan_jobs(mutants, {"candidate": passed},
                                       restricted, 0, d), "REFUSED"))
        check("an unknown scheduling policy is refused before output",
              raises(lambda: plan_jobs(
                  mutants, {"candidate": passed}, restricted, 2, d,
                  shard_policy="post-hoc-fastest"), "unknown shard policy"))

    with tempfile.TemporaryDirectory() as d:
        dirty = os.path.join(d, "dirty")
        os.makedirs(dirty)
        with open(os.path.join(dirty, "historical.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write("preserve me")
        clean_jobs = plan_jobs(
            mutants[:1], {"candidate": passed},
            {"m1": restricted["m1"]}, 1, dirty,
            sides=("candidate",))
        check("default test-quality output refuses a nonempty directory",
              raises(lambda: prepare_output_directory(
                  dirty, clean_jobs, resume=False), "not empty"))

        resume_dir = os.path.join(d, "resume")
        identity_inputs = identity_inputs_for_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant)
        old_inputs = dict(identity_inputs,
                          candidate_run_sha256=(
                              "c00bd483a5689019" + "0" * 64)[:64])
        resume_jobs = plan_jobs(
            mutants[:1], {"candidate": passed},
            {"m1": restricted["m1"]}, 1, resume_dir,
            sides=("candidate",), identity_inputs=old_inputs, resume=True)
        prepare_output_directory(resume_dir, resume_jobs, resume=False)
        os.makedirs(os.path.join(resume_dir, SHARD_DIR))
        job = resume_jobs[0]
        first_iid = job["by_mutant"]["m1"][0]
        with open(job["out"], "w", encoding="utf-8") as fh:
            fh.write(json.dumps(_stamped(job, {
                "item_id": first_iid, "mutant_id": "m1",
                "outcome": "passed", "file": mutants[0]["file"]
            }), sort_keys=True) + "\n")
        _finish_fake_job(job, status="interrupted")
        check("--resume accepts an exact identity-bearing partial shard",
              not raises(lambda: prepare_output_directory(
                  resume_dir, resume_jobs, resume=True)))
        check("resume reconstruction detects a current policy-bound v3 plan",
              _resume_policy_identity_binding(
                  resume_dir, SHARD_POLICY_BALANCED_PAIRS_V1) is True)
        policy_side = job["out"] + ".provenance.json"
        authentic_policy_side = open(policy_side, "rb").read()
        forged_policy_doc = json.load(open(policy_side, encoding="utf-8"))
        forged_policy_doc["shard_policy"] = SHARD_POLICY_STRIDED_V1
        with open(policy_side, "w", encoding="utf-8") as fh:
            json.dump(forged_policy_doc, fh, indent=1, sort_keys=True)
        forged_policy_bytes = open(policy_side, "rb").read()
        policy_rows_before = open(job["out"], "rb").read()
        check("P1 regression: an LPT root refuses a shard sidecar relabelled "
              "as strided even when its embedded identity and rows are "
              "untouched",
              raises(lambda: resolve_cli_shard_policy(
                  resume_dir, None, resume=True),
                  "root campaign policy")
              and raises(lambda: prepare_output_directory(
                  resume_dir, resume_jobs, resume=True),
                  "policy-bound campaign identity"))
        check("P1 regression: the direct sidecar-policy refusal is read-only",
              open(job["out"], "rb").read() == policy_rows_before
              and open(policy_side, "rb").read() == forged_policy_bytes)
        with open(policy_side, "wb") as fh:
            fh.write(authentic_policy_side)
        new_inputs = dict(identity_inputs,
                          candidate_run_sha256=(
                              "12c5ad81f6561c70" + "0" * 64)[:64])
        wrong_jobs = plan_jobs(
            mutants[:1], {"candidate": passed},
            {"m1": restricted["m1"]}, 1, resume_dir,
            sides=("candidate",), identity_inputs=new_inputs, resume=True)
        rows_before = open(job["out"], "rb").read()
        side_before = open(job["out"] + ".provenance.json", "rb").read()
        check("--resume refuses the same pairs under another candidate-run "
              "digest", raises(lambda: prepare_output_directory(
                  resume_dir, wrong_jobs, resume=True),
                  "different root campaign plan"))
        check("resume refusal preserves the old shard byte for byte",
              open(job["out"], "rb").read() == rows_before
              and open(job["out"] + ".provenance.json", "rb").read()
              == side_before)
        legacy_policy_jobs = plan_jobs(
            mutants[:1], {"candidate": passed},
            {"m1": restricted["m1"]}, 1, resume_dir,
            sides=("candidate",), identity_inputs=old_inputs, resume=True,
            shard_policy=SHARD_POLICY_STRIDED_V1)
        check("resume refuses a scheduling-policy change even when one "
              "worker makes the pair membership identical",
              raises(lambda: prepare_output_directory(
                  resume_dir, legacy_policy_jobs, resume=True),
                  "different root campaign plan"))
        check("the scheduling-policy refusal is read-only",
              open(job["out"], "rb").read() == rows_before
              and open(job["out"] + ".provenance.json", "rb").read()
              == side_before)
        from .mutation_run import content_digest, sha256_file

        historical_dir = os.path.join(d, "historical-policy-resume")
        historical_jobs = plan_jobs(
            mutants[:1], {"candidate": passed},
            {"m1": restricted["m1"]}, 1, historical_dir,
            sides=("candidate",), identity_inputs=old_inputs, resume=True,
            shard_policy=SHARD_POLICY_STRIDED_V1)
        historical_plan = build_test_quality_campaign_plan(historical_jobs)
        prepare_output_directory(
            historical_dir, historical_jobs, resume=False,
            campaign_plan=historical_plan)
        os.makedirs(os.path.join(historical_dir, SHARD_DIR))
        historical_job = historical_jobs[0]
        with open(historical_job["out"], "w", encoding="utf-8") as fh:
            fh.write(json.dumps(_stamped(historical_job, {
                "item_id": first_iid, "mutant_id": "m1",
                "outcome": "passed", "file": mutants[0]["file"],
            }), sort_keys=True) + "\n")
        _finish_fake_job(historical_job, status="interrupted")
        check("historical v1 resume accepts the explicit strided sidecar "
              "spelling",
              not raises(lambda: prepare_output_directory(
                  historical_dir, historical_jobs, resume=True,
                  campaign_plan=historical_plan)))
        historical_side = historical_job["out"] + ".provenance.json"
        explicit_historical_bytes = open(historical_side, "rb").read()
        historical_doc = json.load(open(historical_side, encoding="utf-8"))
        historical_doc.pop("shard_policy")
        with open(historical_side, "w", encoding="utf-8") as fh:
            json.dump(historical_doc, fh, indent=1, sort_keys=True)
        check("historical v1 resume also accepts the older absent-policy "
              "sidecar spelling",
              not raises(lambda: prepare_output_directory(
                  historical_dir, historical_jobs, resume=True,
                  campaign_plan=historical_plan)))
        invalid_historical_policies = []
        for invalid_policy in (SHARD_POLICY_BALANCED_PAIRS_V1,
                               "post-hoc-fastest"):
            invalid_doc = dict(historical_doc,
                               shard_policy=invalid_policy)
            with open(historical_side, "w", encoding="utf-8") as fh:
                json.dump(invalid_doc, fh, indent=1, sort_keys=True)
            invalid_historical_policies.append(
                raises(lambda: prepare_output_directory(
                    historical_dir, historical_jobs, resume=True,
                    campaign_plan=historical_plan),
                    "root campaign policy"))
        check("historical v1 resume refuses every present policy except "
              "strided", all(invalid_historical_policies))
        with open(historical_side, "wb") as fh:
            fh.write(explicit_historical_bytes)

        # Exact second forgery from the review: with one worker, striding and
        # LPT have the same pair membership.  Rewrite only the v1 root as v2
        # LPT and its plan hash, leaving the authentic strided shard sidecar
        # and unbound identity untouched.  Reconstructed legacy-LPT jobs make
        # the forged root self-consistent; the shard policy must still stop it.
        historical_root = os.path.join(historical_dir, CAMPAIGN_STATE)
        relabelled_state = json.load(open(historical_root, encoding="utf-8"))
        relabelled_plan = dict(relabelled_state["plan"])
        relabelled_plan["schema"] = TEST_QUALITY_PLAN_SCHEMA
        relabelled_plan["shard_policy"] = SHARD_POLICY_BALANCED_PAIRS_V1
        relabelled_state["plan"] = relabelled_plan
        relabelled_state["plan_sha256"] = content_digest(relabelled_plan)
        with open(historical_root, "w", encoding="utf-8") as fh:
            json.dump(relabelled_state, fh, indent=1, sort_keys=True)
        relabelled_jobs = plan_jobs(
            mutants[:1], {"candidate": passed},
            {"m1": restricted["m1"]}, 1, historical_dir,
            sides=("candidate",), identity_inputs=old_inputs, resume=True,
            shard_policy=SHARD_POLICY_BALANCED_PAIRS_V1,
            bind_shard_policy=False)
        relabelled_job = relabelled_jobs[0]
        relabelled_root_job = relabelled_plan["jobs"][0]
        root_relabel_bytes = open(historical_root, "rb").read()
        shard_relabel_bytes = open(historical_side, "rb").read()
        rows_relabel_bytes = open(historical_job["out"], "rb").read()
        check("the one-worker root relabel is otherwise exactly "
              "reconstructable as an early unbound LPT plan",
              relabelled_root_job["campaign_identity"]
              == relabelled_job["identity"]
              and relabelled_root_job["mutation_campaign_digest"]
              == content_digest(relabelled_job["identity"])
              and relabelled_root_job["side"] == relabelled_job["side"]
              and relabelled_root_job["worker"]
              == relabelled_job["worker"]
              and relabelled_root_job["of"] == relabelled_job["of"]
              and relabelled_root_job["out"] == os.path.join(
                  SHARD_DIR, os.path.basename(relabelled_job["out"]))
              and raises(lambda: build_test_quality_campaign_plan(
                  relabelled_jobs), "immutable exact-artifact authority"))
        check("P1 regression: rewriting only a v1 root as v2 LPT cannot "
              "admit its still-strided shard provenance",
              raises(lambda: resolve_cli_shard_policy(
                  historical_dir, None, resume=True),
                  "immutable exact-artifact authority")
              and raises(lambda: prepare_output_directory(
                  historical_dir, relabelled_jobs, resume=True,
                  campaign_plan=relabelled_plan),
                  "immutable exact-artifact authority"))
        check("P1 regression: the root-relabel refusal preserves root, "
              "sidecar and rows byte for byte",
              open(historical_root, "rb").read() == root_relabel_bytes
              and open(historical_side, "rb").read() == shard_relabel_bytes
              and open(historical_job["out"], "rb").read()
              == rows_relabel_bytes)

        # Fresh HIGH finding: the mutable root and sidecar can be rewritten
        # together.  That makes all local policy claims agree while the v2 row
        # stamps stay exactly the authentic STRIDED bytes.  Therefore agreement
        # among those files is not authentication; only a policy-bound v3 row
        # or an external immutable exact-artifact authority can admit LPT.
        coordinated_doc = json.load(open(historical_side, encoding="utf-8"))
        coordinated_doc["shard_policy"] = SHARD_POLICY_BALANCED_PAIRS_V1
        with open(historical_side, "w", encoding="utf-8") as fh:
            json.dump(coordinated_doc, fh, indent=1, sort_keys=True)
        coordinated_root_bytes = open(historical_root, "rb").read()
        coordinated_side_bytes = open(historical_side, "rb").read()
        coordinated_rows_bytes = open(historical_job["out"], "rb").read()
        coordinated_rows_sha256 = sha256_file(historical_job["out"])
        coordinated_execute, coordinated_seen = fake_execute({
            "candidate": set(), "gold": set()})
        coordinated_refusals = (
            raises(lambda: resolve_cli_shard_policy(
                historical_dir, None, resume=True),
                "immutable exact-artifact authority"),
            raises(lambda: _resume_policy_identity_binding(
                historical_dir, SHARD_POLICY_BALANCED_PAIRS_V1),
                "immutable exact-artifact authority"),
            raises(lambda: prepare_output_directory(
                historical_dir, relabelled_jobs, resume=True,
                campaign_plan=relabelled_plan),
                "immutable exact-artifact authority"),
            raises(lambda: run_test_quality(
                run_rows=run_rows, gold_baseline_rows=gold_rows,
                manifest=manifest, by_mutant=by_mutant,
                out_dir=historical_dir, execute=coordinated_execute,
                n_workers=1, identity_inputs=old_inputs, resume=True,
                shard_policy=SHARD_POLICY_BALANCED_PAIRS_V1),
                "immutable exact-artifact authority"),
        )
        check("HIGH regression: coordinated root+sidecar LPT relabelling of "
              "unchanged strided rows is refused by the resolver, saved-plan "
              "preflight, output preflight, and full resume",
              all(coordinated_refusals) and not coordinated_seen,
              f"refusals={coordinated_refusals}, ran={coordinated_seen}")
        check("HIGH regression: every coordinated-rewrite refusal preserves "
              "the forged root and sidecar plus the authentic row bytes/hash",
              open(historical_root, "rb").read() == coordinated_root_bytes
              and open(historical_side, "rb").read()
              == coordinated_side_bytes
              and open(historical_job["out"], "rb").read()
              == coordinated_rows_bytes
              and sha256_file(historical_job["out"])
              == coordinated_rows_sha256
              == coordinated_doc["rows_sha256"])

        early_lpt_dir = os.path.join(d, "early-unbound-lpt-resume")
        early_lpt_resume_jobs = plan_jobs(
            mutants[:1], {"candidate": passed},
            {"m1": restricted["m1"]}, 1, early_lpt_dir,
            sides=("candidate",), identity_inputs=old_inputs, resume=True,
            bind_shard_policy=False)
        check("the root-plan builder refuses unauthenticated early v2 LPT "
              "before even a fresh output directory can be created",
              raises(lambda: build_test_quality_campaign_plan(
                  early_lpt_resume_jobs),
                  "immutable exact-artifact authority")
              and not os.path.lexists(early_lpt_dir))

        # The merge gate is independently callable, so it must enforce the
        # same policy-generation admission as planning and resume.  Start
        # with genuine historical striding, then coordinate the exact attack:
        # relabel both the mutable job and mutable sidecar as LPT while leaving
        # the unbound v2 identity and every row byte unchanged.
        historical_merge_dir = os.path.join(d, "historical-merge-control")
        historical_merge_jobs = plan_jobs(
            mutants[:1], {"candidate": passed},
            {"m1": restricted["m1"]}, 1, historical_merge_dir,
            sides=("candidate",), identity_inputs=old_inputs,
            shard_policy=SHARD_POLICY_STRIDED_V1)
        historical_merge_execute, _historical_merge_seen = fake_execute({
            "candidate": set()})
        historical_merge_execute(historical_merge_jobs[0])
        historical_merge_expected = _job_pairs(
            historical_merge_jobs[0]["mutants"],
            historical_merge_jobs[0]["by_mutant"],
            historical_merge_jobs[0]["files_by_item"])
        historical_merge_out = os.path.join(
            historical_merge_dir, "historical-merged.jsonl")
        historical_merged = merge_rows(
            historical_merge_jobs, historical_merge_out,
            expected=historical_merge_expected, side="candidate")
        check("merge accepts the genuine historical strided v2 control",
              len(historical_merged) == len(historical_merge_expected)
              and os.path.isfile(historical_merge_out)
              and historical_merge_jobs[0]["identity"]["schema"]
              == MUTATION_IDENTITY_SCHEMA)

        # Plans written before shard_policy existed mean historical striding.
        # Preserve that compatibility, including their absent sidecar field,
        # while ensuring the normalized policy is still passed to the shard
        # validator: a present unknown value is a disagreement, not absence.
        missing_policy_merge_job = dict(historical_merge_jobs[0])
        missing_policy_merge_job.pop("shard_policy")
        missing_policy_merge_side = (
            missing_policy_merge_job["out"] + ".provenance.json")
        missing_policy_merge_doc = json.load(open(
            missing_policy_merge_side, encoding="utf-8"))
        missing_policy_merge_doc.pop("shard_policy")
        with open(missing_policy_merge_side, "w", encoding="utf-8") as fh:
            json.dump(missing_policy_merge_doc, fh, indent=1, sort_keys=True)
        missing_policy_merge_out = os.path.join(
            historical_merge_dir, "missing-policy-merged.jsonl")
        missing_policy_merged = merge_rows(
            [missing_policy_merge_job], missing_policy_merge_out,
            expected=historical_merge_expected, side="candidate")
        check("merge normalizes an omitted historical job policy to "
              "striding and accepts the old absent-sidecar spelling",
              len(missing_policy_merged) == len(historical_merge_expected)
              and os.path.isfile(missing_policy_merge_out))

        missing_policy_merge_doc["shard_policy"] = "invented-policy"
        with open(missing_policy_merge_side, "w", encoding="utf-8") as fh:
            json.dump(missing_policy_merge_doc, fh, indent=1, sort_keys=True)
        invented_policy_merge_out = os.path.join(
            historical_merge_dir, "invented-policy-merged.jsonl")
        check("P2 regression: an omitted historical job policy cannot "
              "disable validation of a present invented sidecar policy",
              raises(lambda: merge_rows(
                  [missing_policy_merge_job], invented_policy_merge_out,
                  expected=historical_merge_expected, side="candidate"),
                  "differs from its root campaign policy")
              and not os.path.lexists(invented_policy_merge_out))

        relabelled_merge_job = dict(
            historical_merge_jobs[0],
            shard_policy=SHARD_POLICY_BALANCED_PAIRS_V1,
            provenance={
                **historical_merge_jobs[0]["provenance"],
                "shard_policy": SHARD_POLICY_BALANCED_PAIRS_V1,
            })
        relabelled_merge_side = (
            relabelled_merge_job["out"] + ".provenance.json")
        relabelled_merge_doc = json.load(open(
            relabelled_merge_side, encoding="utf-8"))
        relabelled_merge_doc["shard_policy"] = (
            SHARD_POLICY_BALANCED_PAIRS_V1)
        with open(relabelled_merge_side, "w", encoding="utf-8") as fh:
            json.dump(relabelled_merge_doc, fh, indent=1, sort_keys=True)
        relabelled_merge_out = os.path.join(
            historical_merge_dir, "forged-lpt-merged.jsonl")
        check("P2 regression: merge refuses a coordinated job+sidecar LPT "
              "relabel of unchanged historical strided rows before "
              "publication",
              raises(lambda: merge_rows(
                  [relabelled_merge_job], relabelled_merge_out,
                  expected=historical_merge_expected, side="candidate"),
                  "immutable exact-artifact authority")
              and not os.path.lexists(relabelled_merge_out))

        genuine_lpt_dir = os.path.join(d, "genuine-lpt-merge-control")
        genuine_lpt_jobs = plan_jobs(
            mutants[:1], {"candidate": passed},
            {"m1": restricted["m1"]}, 1, genuine_lpt_dir,
            sides=("candidate",), identity_inputs=old_inputs,
            shard_policy=SHARD_POLICY_BALANCED_PAIRS_V1)
        genuine_lpt_execute, _genuine_lpt_seen = fake_execute({
            "candidate": set()})
        genuine_lpt_execute(genuine_lpt_jobs[0])
        genuine_lpt_expected = _job_pairs(
            genuine_lpt_jobs[0]["mutants"],
            genuine_lpt_jobs[0]["by_mutant"],
            genuine_lpt_jobs[0]["files_by_item"])
        genuine_lpt_out = os.path.join(
            genuine_lpt_dir, "genuine-lpt-merged.jsonl")
        genuine_lpt_merged = merge_rows(
            genuine_lpt_jobs, genuine_lpt_out,
            expected=genuine_lpt_expected, side="candidate")
        check("merge accepts the genuine policy-bound LPT v3 control",
              len(genuine_lpt_merged) == len(genuine_lpt_expected)
              and os.path.isfile(genuine_lpt_out)
              and genuine_lpt_jobs[0]["identity"]["schema"]
              == MUTATION_IDENTITY_SCHEMA_V3
              and genuine_lpt_jobs[0]["identity"]["shard_policy"]
              == SHARD_POLICY_BALANCED_PAIRS_V1)

        pool_a = [{"index": 0, "workspace": "/worker/a"}]
        pool_b = [{"index": 0, "workspace": "/worker/b"}]
        pool_dir = os.path.join(d, "worker-pool-resume")
        pool_a_inputs = dict(
            identity_inputs,
            worker_resources_sha256=content_digest(pool_a))
        pool_a_jobs = plan_jobs(
            mutants[:1], {"candidate": passed},
            {"m1": restricted["m1"]}, 1, pool_dir,
            sides=("candidate",), identity_inputs=pool_a_inputs,
            resume=True)
        pool_a_plan = build_test_quality_campaign_plan(
            pool_a_jobs, worker_resources=pool_a)
        prepare_output_directory(
            pool_dir, pool_a_jobs, resume=False,
            campaign_plan=pool_a_plan)
        pool_b_inputs = dict(
            identity_inputs,
            worker_resources_sha256=content_digest(pool_b))
        pool_b_jobs = plan_jobs(
            mutants[:1], {"candidate": passed},
            {"m1": restricted["m1"]}, 1, pool_dir,
            sides=("candidate",), identity_inputs=pool_b_inputs,
            resume=True)
        pool_b_plan = build_test_quality_campaign_plan(
            pool_b_jobs, worker_resources=pool_b)
        check("--resume refuses a different worker assignment/runtime even "
              "when population and source hashes are unchanged",
              raises(lambda: prepare_output_directory(
                  pool_dir, pool_b_jobs, resume=True,
                  campaign_plan=pool_b_plan),
                  "different root campaign plan"))
        with open(os.path.join(resume_dir, "late-root-artifact"), "w",
                  encoding="utf-8") as fh:
            fh.write("unexpected")
        check("resume refuses an unplanned root artifact even when every "
              "existing shard identity matches",
              raises(lambda: prepare_output_directory(
                  resume_dir, resume_jobs, resume=True),
                  "unplanned root artifact"))

    # ------------------------------------ labelled sensitivity replays
    #
    # E_PETITIONS_WEBMOCK_MUTATION_AMENDMENT.md: a labelled replay is scored
    # only as itself.  Its label must be every run row's, it is root-plan
    # identity (so no resume crosses it), and it travels in the summary.
    sens_label = "webmock_world_v1"
    sens_rows = [dict(row, sensitivity=sens_label) for row in run_rows]
    check("an unlabelled run carries no sensitivity label; a labelled one "
          "carries exactly its own",
          run_sensitivity(run_rows) is None
          and run_sensitivity(sens_rows) == sens_label)
    check("a run file mixing labelled and unlabelled rows is refused",
          raises(lambda: run_sensitivity(sens_rows[:1] + run_rows[1:]),
                 "mixes sensitivity labels"))
    with tempfile.TemporaryDirectory() as d:
        def _sens(name, rows, label):
            execute_, _seen = fake_execute({"candidate": CAND_KILLS,
                                            "gold": GOLD_KILLS})
            return run_test_quality(
                run_rows=rows, gold_baseline_rows=gold_rows,
                manifest=manifest, by_mutant=by_mutant,
                out_dir=os.path.join(d, name), execute=execute_,
                n_workers=2, sensitivity=label)
        sens_summary = _sens("labelled", sens_rows, sens_label)
        plain_summary = _sens("plain", run_rows, None)
        check("a labelled replay's summary names its label over the same "
              "numbers; an unlabelled summary has no such field",
              sens_summary["sensitivity"] == sens_label
              and "sensitivity" not in plain_summary
              and sens_summary["per_item"] == plain_summary["per_item"]
              and sens_summary["recall_macro"]
              == plain_summary["recall_macro"])
        sens_states = {name: _load_json_object(
            os.path.join(d, name, CAMPAIGN_STATE), "fixture root")
            for name in ("labelled", "plain")}
        check("the label is root-plan identity: an unlabelled plan keeps its "
              "shape and cannot resume the labelled campaign",
              sens_states["labelled"]["plan"]["sensitivity"] == sens_label
              and "sensitivity" not in sens_states["plain"]["plan"]
              and raises(lambda: _validate_campaign_state(
                  sens_states["labelled"], sens_states["plain"]["plan"]),
                  "different root campaign plan"))
        check("labelled rows scored without the label refuse before any "
              "worker, and unlabelled rows scored with it too",
              raises(lambda: _sens("x-unlabelled", sens_rows, None),
                     "labelled 'webmock_world_v1'")
              and raises(lambda: _sens("x-labelled", run_rows, sens_label),
                         "labelled None")
              and not os.path.exists(os.path.join(d, "x-unlabelled"))
              and not os.path.exists(os.path.join(d, "x-labelled")))
    from . import cli as _sens_cli
    import argparse as _sens_argparse
    for _sens_namespace, _sens_needle in (
            ({"run": "run.jsonl", "sensitivity": sens_label},
             "missing --development"),
            ({"run": "run.jsonl", "sensitivity": sens_label,
              "development": True, "kapua_reference_evidence": "e.json"},
             "--kapua-reference-evidence"),
            ({"run": "run.jsonl", "sensitivity": sens_label,
              "development": True, "gold_results": "gold.jsonl"},
             "--gold-results")):
        try:
            _sens_cli.cmd_test_quality(
                _sens_argparse.Namespace(**_sens_namespace))
            _sens_refusal = "not refused"
        except SystemExit as e:
            _sens_refusal = str(e)
        check("test-quality --sensitivity refuses off the plain development "
              f"route ({_sens_needle}) before reading anything",
              _sens_needle in _sens_refusal, _sens_refusal)

    # -------------------------------------------------------- the numbers
    with tempfile.TemporaryDirectory() as d:
        execute, seen = fake_execute({"candidate": CAND_KILLS,
                                      "gold": GOLD_KILLS})
        summary = run_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant, out_dir=d,
            execute=execute, n_workers=2,
            provenance={"run": "fixture.jsonl"})
        check("every planned job was executed",
              len(seen) == 4 and sum(i["rows"] for i in summary["slices"]) == 12,
              str([(j["side"], j["worker"]) for j in seen]))
        check("the merged rows are exactly the expected executions, per side",
              summary["pairs_executed_candidate"] == 6
              and summary["pairs_executed_gold"] == 6
              and summary["pairs_expected"] == 6)

        items = summary["per_item"]
        check("a candidate that kills everything gold kills is "
              "equivalent_to_reference at 1.0",
              items["i_full"]["verdict"] == EQUIVALENT
              and items["i_full"]["recall"] == 1.0
              and items["i_full"]["candidate_killed"] == 2
              and items["i_full"]["gold_killed"] == 2, str(items["i_full"]))
        check("a candidate that kills SOME of gold's mutants is weaker",
              items["i_weak"]["verdict"] == WEAKER
              and items["i_weak"]["recall"] == 0.5, str(items["i_weak"]))
        check("a candidate that kills NOTHING is vacuous at 0.0, not "
              "not_scorable",
              items["i_vac"]["verdict"] == VACUOUS
              and items["i_vac"]["recall"] == 0.0
              and items["i_vac"]["gold_killed"] == 1, str(items["i_vac"]))
        check("an item where GOLD kills nothing is not_scorable, with the "
              "reason named",
              items["i_eqm"]["verdict"] == NOT_SCORABLE
              and items["i_eqm"]["recall"] is None
              and "equivalent" in (items["i_eqm"]["not_scorable_reason"] or ""),
              str(items["i_eqm"]))
        check("an item no mutant covers is not_scorable for its own reason",
              items["i_nocov"]["verdict"] == NOT_SCORABLE
              and "no mutant" in (items["i_nocov"]["not_scorable_reason"] or ""),
              str(items["i_nocov"]))
        check("mutants_covering is the item's own denominator, not the "
              "population's",
              [items[i]["mutants_covering"] for i in
               ("i_full", "i_weak", "i_vac", "i_eqm", "i_nocov")]
              == [2, 2, 1, 1, 0])
        check("not_scorable items are EXCLUDED from the macro",
              summary["n_scorable"] == 3 and summary["n_passed"] == 5)
        check("the macro matches the hand-computed (1.0 + 0.5 + 0.0)/3",
              summary["recall_macro"] == 0.5, str(summary["recall_macro"]))
        # The Jaccard, over the same three items.  No candidate-only kill in
        # this fixture, so it must EQUAL the recall here -- the case where it
        # does not is checked directly below, on the arithmetic.
        check("every scored item carries a jaccard beside its recall",
              [items[i]["jaccard"] for i in ("i_full", "i_weak", "i_vac")]
              == [1.0, 0.5, 0.0]
              and items["i_eqm"]["jaccard"] is None,
              str({i: items[i]["jaccard"] for i in items}))
        check("the macro jaccard is over the same population as the recall",
              summary["jaccard_macro"] == 0.5, str(summary["jaccard_macro"]))
        check("a kill gold does not make cannot raise the recall but DOES "
              "lower the jaccard",
              jaccard_for(2, 2, 1) == 2 / 3 and jaccard_for(2, 2, 0) == 1.0,
              str(jaccard_for(2, 2, 1)))
        check("an item gold cannot score has NO jaccard, not 0.0",
              jaccard_for(0, 0, 5) is None)
        check("the verdict vocabulary is unchanged by the jaccard",
              set(summary["verdicts"]) == set(VERDICTS))
        check("the verdict counts add up to the passes",
              summary["verdicts"] == {EQUIVALENT: 1, WEAKER: 1, VACUOUS: 1,
                                      NOT_SCORABLE: 2}
              and sum(summary["verdicts"].values()) == summary["n_passed"],
              str(summary["verdicts"]))
        check("only equivalent_to_reference counts as a non-vacuous pass",
              summary["non_vacuous_passes"] == 1)
        check("completeness was checked, not assumed",
              summary["completeness_checked"] is True)
        check("the summary is written into --out beside its evidence",
              os.path.isfile(os.path.join(d, SUMMARY))
              and os.path.isfile(os.path.join(d, CANDIDATE_ROWS))
              and os.path.isfile(os.path.join(d, GOLD_ROWS)))
        root_state = json.load(open(
            os.path.join(d, CAMPAIGN_STATE), encoding="utf-8"))
        check("the root campaign becomes complete only with hashes for all "
              "three final artifacts",
              root_state["status"] == "complete"
              and root_state["history"][0] == "running"
              and root_state["history"][-1] == "complete"
              and set(root_state["artifacts"])
              == {CANDIDATE_ROWS, GOLD_ROWS, SUMMARY})
        check("provenance survives into the summary",
              summary["run"] == "fixture.jsonl"
              and summary["manifest_digest"] == "d" * 64)
        check("a current full-gold summary names its sensitivity basis and is "
              "not publication-ready after C4",
              summary["verdict_basis"] == "full_gold"
              and publication_ready(summary)[0] is False
              and any("sensitivity result" in reason
                      for reason in publication_ready(summary)[1]),
              str(publication_ready(summary)))
        malformed_hard_digest = dict(
            COMPLETE_QUALIFIER_FIXTURE,
            hard_subset_digest="truthy-but-not-sha256")
        uppercase_hard_digest = dict(
            COMPLETE_QUALIFIER_FIXTURE, hard_subset_digest="A" * 64)
        check("truthy short or uppercase hard-subset digests cannot publish",
              publication_ready(malformed_hard_digest)[0] is False
              and publication_ready(uppercase_hard_digest)[0] is False
              and any("full lowercase SHA-256" in reason for reason in
                      publication_ready(malformed_hard_digest)[1]),
              str({"short": publication_ready(malformed_hard_digest),
                   "uppercase": publication_ready(uppercase_hard_digest)}))
        from .mutation_run import (GENERATION_PROVENANCE_CLASSES,
                                   GENERATION_PROVENANCE_PUBLISHABLE)
        from .slice3_test_quality import JOIN_KEY as _SLICE3_JOIN_KEY
        by_class = {
            klass: publication_ready(
                dict(COMPLETE_QUALIFIER_FIXTURE,
                     generation_provenance_class=klass))
            for klass in GENERATION_PROVENANCE_CLASSES}
        check("an otherwise complete candidate publishes under exactly the "
              "generation provenance classes that name an attempt",
              all(by_class[klass] == (True, [])
                  for klass in GENERATION_PROVENANCE_PUBLISHABLE)
              and not any(by_class[klass][0] for klass in by_class
                          if klass not in GENERATION_PROVENANCE_PUBLISHABLE),
              str({klass: value[0] for klass, value in by_class.items()}))
        check("a development-route or fixture candidate is withheld BY THE "
              "PREDICATE, naming the class it cannot publish under",
              all(by_class[klass][1] == [
                      f"the candidate's generation provenance class is "
                      f"`{klass}`, which cannot name the attempt that "
                      f"produced it"]
                  for klass in ("development_unstamped", "fixture")),
              str({klass: by_class[klass][1]
                   for klass in ("development_unstamped", "fixture")}))
        absent_class = {key: value
                        for key, value in COMPLETE_QUALIFIER_FIXTURE.items()
                        if key != "generation_provenance_class"}
        null_class = dict(COMPLETE_QUALIFIER_FIXTURE,
                          generation_provenance_class=None)
        absent_reason = ("the candidate's generation provenance class is "
                         "absent, which cannot name the attempt that "
                         "produced it")
        check("a candidate that states NO generation provenance class at all "
              "-- or an explicitly null one -- is withheld for the same "
              "reason: neither names an attempt",
              publication_ready(absent_class) == (False, [absent_reason])
              and publication_ready(null_class) == (False, [absent_reason]),
              str({"absent": publication_ready(absent_class),
                   "null": publication_ready(null_class)}))
        check("the two shapes that carry the class in re-derived evidence "
              "instead of the summary body keep publishing: the "
              "authenticated legacy wrapper and the Slice-3 join",
              publication_ready(
                  _AuthenticatedLegacySummary(absent_class)) == (True, [])
              and publication_ready(
                  dict(absent_class, **{_SLICE3_JOIN_KEY: {}}))
              == (True, []),
              str({"legacy": publication_ready(
                       _AuthenticatedLegacySummary(absent_class)),
                   "slice3": publication_ready(
                       dict(absent_class,
                            **{_SLICE3_JOIN_KEY: {}}))}))
        native_without_basis = {
            "schema": TEST_QUALITY_SUMMARY_SCHEMA,
            **{key: "fixture-path" for key in (
                "run", "gold_baseline", "manifest", "map", "release",
                "mutation_validation", "candidate_results", "gold_results",
                "seed")},
        }
        check("a current native summary cannot use absent verdict basis as a "
              "legacy compatibility signal",
              raises(lambda: _validate_native_summary(
                  native_without_basis, "fixture-sidecar", "fixture-path"),
                  "missing or unsupported verdict_basis"))
        partial_hard_rerun = {
            **native_without_basis,
            "verdict_basis": "hard_subset",
            "hard_subset": "fixture-hard-subset",
            "candidate_hard_rerun_results": ["fixture-run-2"],
        }
        check("a native hard summary cannot detach run-2 paths from hashes "
              "and its standalone observation identity",
              raises(lambda: _validate_native_summary(
                  partial_hard_rerun, "fixture-sidecar", "fixture-path"),
                  "partially records candidate run 2"))
        check("new summaries disclose the balanced scheduling policy",
              summary["shard_policy"] == SHARD_POLICY_BALANCED_PAIRS_V1
              and root_state["plan"]["schema"] == TEST_QUALITY_PLAN_SCHEMA
              and root_state["plan"]["shard_policy"]
              == SHARD_POLICY_BALANCED_PAIRS_V1)
        check("the public resolver gives every fresh campaign balanced LPT",
              resolve_cli_shard_policy(
                  os.path.join(d, "not-created"), None, resume=False)
              == SHARD_POLICY_BALANCED_PAIRS_V1)
        check("the public resolver refuses creation of a fresh historical "
              "strided campaign",
              raises(lambda: resolve_cli_shard_policy(
                  os.path.join(d, "not-created"),
                  SHARD_POLICY_STRIDED_V1, resume=False),
                  "historical resume-only"))
        forged_policy_out = os.path.join(d, "forged-policy")
        check("caller provenance cannot relabel balanced execution as "
              "historical striding",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=manifest, by_mutant=by_mutant,
                  out_dir=forged_policy_out,
                  execute=fake_execute({"candidate": CAND_KILLS,
                                        "gold": GOLD_KILLS})[0],
                  n_workers=2,
                  provenance={"shard_policy": SHARD_POLICY_STRIDED_V1}),
                  "caller provenance claims shard policy")
              and not os.path.exists(forged_policy_out))

        legacy_out = os.path.join(d, "legacy-strided")
        legacy_execute, _legacy_seen = fake_execute(
            {"candidate": CAND_KILLS, "gold": GOLD_KILLS})
        legacy_summary = run_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant, out_dir=legacy_out,
            execute=legacy_execute, n_workers=2,
            provenance={"run": "fixture.jsonl"},
            shard_policy=SHARD_POLICY_STRIDED_V1)
        metric_keys = {
            "per_item", "verdicts", "n_passed", "n_scorable",
            "non_vacuous_passes", "recall_macro", "jaccard_macro",
            "pairs_expected", "pairs_executed_candidate",
            "pairs_executed_gold",
        }
        check("balanced and legacy schedules produce identical scores",
              {key: summary[key] for key in metric_keys}
              == {key: legacy_summary[key] for key in metric_keys})
        def outcome_projection(path):
            return sorted((row["item_id"], row["mutant_id"], row["outcome"])
                          for row in load_jsonl(path))
        check("balanced and legacy schedules execute the same outcome-bearing "
              "pair set",
              outcome_projection(summary["candidate_results"])
              == outcome_projection(legacy_summary["candidate_results"])
              and outcome_projection(summary["gold_results"])
              == outcome_projection(legacy_summary["gold_results"]))
        legacy_state = json.load(open(
            os.path.join(legacy_out, CAMPAIGN_STATE), encoding="utf-8"))
        check("legacy striding reconstructs a v1 plan without invented "
              "fields",
              legacy_summary["shard_policy"] == SHARD_POLICY_STRIDED_V1
              and legacy_state["plan"]["schema"]
              == TEST_QUALITY_PLAN_SCHEMA_V1
              and "shard_policy" not in legacy_state["plan"])
        check("a bare --resume recovers historical striding from the saved "
              "v1 schema instead of applying today's default",
              resolve_cli_shard_policy(legacy_out, None, resume=True)
              == SHARD_POLICY_STRIDED_V1)
        check("an explicit policy change on --resume refuses before work",
              raises(lambda: resolve_cli_shard_policy(
                  legacy_out, SHARD_POLICY_BALANCED_PAIRS_V1, resume=True),
                  "saved root campaign uses"))

        # The sidecar `report` reads.
        run_path = os.path.join(d, "sweep.jsonl")
        with open(run_path, "w", encoding="utf-8") as fh:
            for row in run_rows:
                fh.write(json.dumps(row) + "\n")
        side = write_sidecar({k: v for k, v in summary.items()
                              if k != "binding"}, run_path)
        check("the sidecar is named for the run's stem, where report looks",
              side == os.path.join(d, "sweep" + SIDECAR_SUFFIX)
              and find_sidecar(run_path) == side, side)
        check("a run binding alone cannot upgrade a synthetic native "
              "sidecar into publishable evidence",
              raises(lambda: load_bound_test_quality(run_path),
                     "evidence path"))
        valid_side_bytes = open(side, "rb").read()
        forged = json.load(open(side, encoding="utf-8"))
        forged["schema"] = "not-a-test-quality-schema"
        with open(side, "w", encoding="utf-8") as fh:
            json.dump(forged, fh, indent=1, sort_keys=True)
        check("a forged native schema with the right run binding is refused",
              raises(lambda: load_bound_test_quality(run_path),
                     TEST_QUALITY_SUMMARY_SCHEMA))
        with open(side, "wb") as fh:
            fh.write(valid_side_bytes)
        original_run = open(run_path, "rb").read()
        changed_rows = list(run_rows)
        changed_rows[0] = {**changed_rows[0], "produced_files": [{
            "file_path": "i_full.php", "code": "<?php // changed"}]}
        with open(run_path, "w", encoding="utf-8") as fh:
            for row in changed_rows:
                fh.write(json.dumps(row) + "\n")
        check("same passed item IDs with changed generated tests are refused",
              raises(lambda: load_bound_test_quality(run_path), "binding"))
        with open(run_path, "wb") as fh:
            fh.write(original_run)
        with open(run_path, "ab") as fh:
            fh.write(b"\n")
        check("even metadata-neutral run-byte drift invalidates the exact run "
              "binding", raises(lambda: load_bound_test_quality(run_path),
                                 "binding"))
        with open(run_path, "wb") as fh:
            fh.write(original_run)
        alt = run_path + SIDECAR_SUFFIX
        with open(alt, "w", encoding="utf-8") as fh:
            json.dump({"binding": run_binding(run_path), "per_item": {}}, fh)
        check("two accepted sidecar spellings that disagree are refused",
              raises(lambda: find_sidecar(run_path), "both accepted"))
        with open(side, "rb") as source, open(alt, "wb") as duplicate:
            duplicate.write(source.read())
        check("even byte-identical duplicate sidecar spellings are refused",
              raises(lambda: find_sidecar(run_path), "byte-identical"))
        os.remove(alt)
        alt = run_path + SIDECAR_SUFFIX
        os.rename(side, alt)
        check("the run.jsonl.test_quality.json spelling is also found",
              find_sidecar(run_path) == alt, str(find_sidecar(run_path)))
        os.remove(alt)
        check("no sidecar means no claim, not a crash",
              find_sidecar(run_path) is None)

    # ------------------------------------ gold-killed candidate scope
    #
    # GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md section 3's equivalence argument,
    # on the six-mutant fixture with gold no longer killing (i_full, m2): the
    # candidate kills it anyway, and (i_eqm, m5) too, so the full-scope
    # companions are real, different numbers and not a coincidence of the
    # fixture.
    from .mutation_run import pair_set_digest as _gk_digest
    from . import report as _gk_report
    from . import results as _gk_results
    gk_gold = GOLD_KILLS - {("i_full", "m2")}
    gk_cand = CAND_KILLS | {("i_eqm", "m5")}
    gk_all_pairs = expected_pairs(population(
        manifest, by_mutant, passed_solutions(run_rows))[1])
    gk_invariant = ("verdict", "recall", "candidate_killed", "denominator",
                    "gold_killed", "mutants_covering", "not_scorable_reason")

    def _gk_same_non_vacuous(full, restricted_summary):
        """Every input `report.non_vacuous` reads, compared field by field."""
        items_equal = all(
            full["per_item"][iid][key] == restricted_summary["per_item"][iid][key]
            for iid in full["per_item"] for key in gk_invariant)
        headline = all(full[key] == restricted_summary[key] for key in (
            "recall_macro", "n_scorable", "n_passed", "verdicts",
            "non_vacuous_passes", "completeness_checked"))
        full_nv = _gk_report.non_vacuous(run_rows, full)
        restricted_nv = _gk_report.non_vacuous(run_rows, restricted_summary)
        reported = all(full_nv[key] == restricted_nv[key] for key in (
            "non_vacuous_passes", "non_vacuous_pass_at_1", "weaker",
            "vacuous", "not_scorable", "recall_macro", "scored_items"))
        return (items_equal and set(full["per_item"])
                == set(restricted_summary["per_item"])
                and headline and reported)

    def _gk_withheld(summary_):
        return (summary_["candidate_pair_scope"] == CANDIDATE_PAIRS_GOLD_KILLED
                and summary_["withheld_measures"] == list(GOLD_KILLED_WITHHELD)
                and summary_["jaccard_macro"] is None
                and set(summary_["excluded"].values()) == {None}
                and all(entry["jaccard"] is None
                        and entry["candidate_only_kills"] is None
                        for entry in summary_["per_item"].values()))

    def _gk_executed(seen_jobs, side):
        return {pair for job in seen_jobs if job["side"] == side
                for pair in _job_pairs(job["mutants"], job["by_mutant"],
                                       job["files_by_item"])}

    with tempfile.TemporaryDirectory() as d:
        full_execute, _full_seen = fake_execute(
            {"candidate": gk_cand, "gold": gk_gold})
        gk_full = run_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant,
            out_dir=os.path.join(d, "full"), execute=full_execute,
            n_workers=2)
        check("full scope: the extra candidate kill is a measured "
              "candidate-only kill",
              gk_full["excluded"]["candidate_only_kill"] == 1
              and gk_full["per_item"]["i_full"]["candidate_only_kills"] == 1
              and gk_full["jaccard_macro"] == 0.333333
              and "candidate_pair_scope" not in gk_full, str(gk_full["excluded"]))

        # Route (ii): gold observed in this campaign on an explicit plan of
        # an earlier observation's kills.  The plan's source rows include a
        # timeout, which does not enter it.
        preserved = [{"item_id": iid, "mutant_id": mid,
                      "outcome": ("failed" if (iid, mid) in gk_gold
                                  else "timeout")}
                     for iid, mid in sorted(gk_all_pairs)]
        plan_doc = build_gold_pair_plan(
            preserved, manifest_digest=manifest["digest"],
            source="fixture preserved gold")
        plan_path = os.path.join(d, "gold-pairs.json")
        with open(plan_path, "w", encoding="utf-8") as fh:
            json.dump(plan_doc, fh)
        gk_plan, gk_binding = load_gold_pair_plan(
            plan_path, manifest_digest=manifest["digest"])
        check("a gold pair plan holds exactly the literal-failed pairs of its "
              "source rows", gk_plan == frozenset(gk_gold), str(gk_plan))
        plan_execute, plan_seen = fake_execute(
            {"candidate": gk_cand, "gold": gk_gold})
        gk_plan_summary = run_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant,
            out_dir=os.path.join(d, "plan"), execute=plan_execute,
            n_workers=2, candidate_pairs=CANDIDATE_PAIRS_GOLD_KILLED,
            gold_pair_plan=gk_plan, gold_pair_plan_binding=gk_binding)
        check("gold pair plan: both slices execute exactly the plan's pairs",
              _gk_executed(plan_seen, "candidate") == set(gk_gold)
              and _gk_executed(plan_seen, "gold") == set(gk_gold)
              and gk_plan_summary["pairs_expected"] == len(gk_gold)
              and gk_plan_summary["gold_rows_missing"] == 0)
        check("gold pair plan: every non-vacuous input equals the full-scope "
              "summary's", _gk_same_non_vacuous(gk_full, gk_plan_summary))
        check("gold pair plan: the companions are withheld as null and the "
              "plan file is bound", _gk_withheld(gk_plan_summary)
              and gk_plan_summary["gold_pair_plan"] == gk_binding)

        # Route (i): precomputed (authenticated) gold; the candidate slice is
        # exactly gold's kills and gold is not executed at all.
        gk_gold_rows = [{"item_id": iid, "mutant_id": mid,
                         "outcome": ("failed" if (iid, mid) in gk_gold
                                     else "passed"),
                         "attempt": 1, "retried_infrastructure": False}
                        for iid, mid in sorted(gk_all_pairs)]
        gk_fixture_inputs = identity_inputs_for_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant)
        gk_gold_binding = {
            "validation_class": "native",
            "manifest_digest": manifest["digest"],
            "pairs_sha256": _gk_digest(gk_all_pairs),
            "engine": gk_fixture_inputs["engine"],
            "engine_version": gk_fixture_inputs["engine_version"],
            "gold_results_sha256": "a" * 64,
            "gold_results_attestation_sha256": "b" * 64,
            "gold_results_source": "/fixture/gold.jsonl",
            "gold_results_attestation": "/fixture/gold.jsonl",
        }

        def _gk_precomputed(name, scope_):
            execute_, seen_ = fake_execute({"candidate": gk_cand})
            return run_test_quality(
                run_rows=run_rows, gold_baseline_rows=gold_rows,
                manifest=manifest, by_mutant=by_mutant,
                out_dir=os.path.join(d, name), execute=execute_, n_workers=2,
                authenticated_gold=_seal_authenticated_gold_selection(
                    gk_gold_rows, gk_gold_binding),
                identity_inputs={"gold_results_sha256": "a" * 64,
                                 "gold_results_attestation_sha256": "b" * 64},
                provenance={"gold_results_source": "/fixture/gold.jsonl",
                            "gold_results_attestation": "/fixture/gold.jsonl"},
                candidate_pairs=scope_), seen_

        gk_pre_full, _pre_full_seen = _gk_precomputed("pre-full", "all")
        gk_pre, gk_pre_seen = _gk_precomputed(
            "pre-gold-killed", CANDIDATE_PAIRS_GOLD_KILLED)
        check("precomputed gold: the candidate executes exactly gold's kills "
              "and no gold job exists",
              _gk_executed(gk_pre_seen, "candidate") == set(gk_gold)
              and not _gk_executed(gk_pre_seen, "gold")
              and gk_pre["pairs_executed_candidate"] == len(gk_gold)
              and gk_pre["candidate_pairs_expected"] == len(gk_gold)
              and gk_pre["pairs_expected"] == len(gk_all_pairs)
              and gk_pre["gold_pair_plan"] is None)
        check("precomputed gold: every non-vacuous input equals the "
              "full-scope summary's, which equals the in-campaign one's",
              _gk_same_non_vacuous(gk_pre_full, gk_pre)
              and _gk_same_non_vacuous(gk_full, gk_pre_full))
        check("precomputed gold: the companions are withheld as null",
              _gk_withheld(gk_pre))
        gk_mutation = _gk_results.mutation(
            gk_pre, set(passed_solutions(run_rows)))
        gk_rows = {row["key"]: row for row in _gk_results.table_rows({
            "ladder": {"denominator": 1, "rows": []},
            "mutation": dict(gk_mutation, publication_ready=True),
            "coverage": {"scored": False, "values": None,
                         "reason": "fixture"},
            "api": {"scored": False, "values": None, "reason": "fixture"}})}
        check("results: a gold-killed summary renders recall and names the "
              "two dropped measures as not measured, never 0",
              gk_mutation["values"]["recall"] == 0.5
              and gk_mutation["values"]["only_gen"] is None
              and gk_mutation["values"]["jaccard"] is None
              and gk_rows["mutation_recall"]["number"] == 0.5
              and all(gk_rows[key]["value"]
                      == _gk_results.GOLD_KILLED_NOT_MEASURED
                      and gk_rows[key]["number"] is None
                      for key in ("mutation_only_gen", "mutation_jaccard")),
              str({key: gk_rows[key]["value"] for key in gk_rows}))

        # The scope is root-plan identity: a resume under the other scope is
        # a different campaign.
        def _gk_plan(name):
            return _load_json_object(
                os.path.join(d, name, CAMPAIGN_STATE), "fixture root")
        check("the root plan binds the narrowed scope and an all-scope plan "
              "keeps its historical shape",
              _gk_plan("pre-gold-killed")["plan"]["candidate_pair_scope"]
              == {"scope": CANDIDATE_PAIRS_GOLD_KILLED,
                  "candidate_pairs": len(gk_gold),
                  "candidate_pairs_sha256": _gk_digest(gk_gold),
                  "gold_pair_plan": False}
              and _gk_plan("plan")["plan"]["candidate_pair_scope"][
                  "gold_pair_plan"] is True
              and "candidate_pair_scope" not in _gk_plan("pre-full")["plan"])
        check("resume refuses a root campaign planned under the other scope",
              raises(lambda: _validate_campaign_state(
                  _gk_plan("pre-gold-killed"), _gk_plan("pre-full")["plan"]),
                  "different root campaign plan"))

        # Refusals, each before any worker is planned.
        def _gk_refused(needle, **kwargs):
            execute_, seen_ = fake_execute({"candidate": set(), "gold": set()})
            refused = raises(lambda: run_test_quality(
                run_rows=run_rows, gold_baseline_rows=gold_rows,
                manifest=manifest, by_mutant=by_mutant,
                out_dir=os.path.join(d, "refused"), execute=execute_,
                n_workers=1, **kwargs), needle)
            return refused and not seen_ \
                and not os.path.exists(os.path.join(d, "refused"))
        outside_path = os.path.join(d, "outside.json")
        with open(outside_path, "w", encoding="utf-8") as fh:
            json.dump(dict(plan_doc, pairs=[*plan_doc["pairs"],
                                            ["i_full", "m3"]]), fh)
        outside_plan, outside_binding = load_gold_pair_plan(
            outside_path, manifest_digest=manifest["digest"])
        check("gold-killed scope refuses without gold's kills in hand",
              _gk_refused("needs gold's kills",
                          candidate_pairs=CANDIDATE_PAIRS_GOLD_KILLED))
        check("a gold pair plan refuses under the full candidate scope",
              _gk_refused("requires --candidate-pairs gold-killed",
                          gold_pair_plan=gk_plan,
                          gold_pair_plan_binding=gk_binding))
        check("a gold pair plan refuses a pair of a passed item outside the "
              "mapped population",
              _gk_refused("outside the mapped population",
                          candidate_pairs=CANDIDATE_PAIRS_GOLD_KILLED,
                          gold_pair_plan=outside_plan,
                          gold_pair_plan_binding=outside_binding))
        check("gold-killed scope refuses the hard-subset route",
              _gk_refused("full-gold scoring only",
                          candidate_pairs=CANDIDATE_PAIRS_GOLD_KILLED,
                          hard_subset_doc={}, hard_subset_path="hard.json"))
        check("a gold pair plan for another manifest is refused",
              raises(lambda: load_gold_pair_plan(
                  plan_path, manifest_digest="e" * 64), "manifest digest"))
        check("gold rows that disagree about one pair make no plan",
              raises(lambda: build_gold_pair_plan(
                  preserved + [dict(preserved[0], outcome="passed")],
                  manifest_digest=manifest["digest"], source="fixture"),
                  "disagree"))

    # -------------------------------------- D4 selective hard confirmation
    d4_hard = {"a": {"m1", "m2"}, "b": {"m3", "m4"}}
    d4_pairs = {(item_id, mutant_id)
                for item_id, mutant_ids in d4_hard.items()
                for mutant_id in mutant_ids}

    def d4_rows(outcomes, pairs=d4_pairs):
        return [
            {"item_id": item_id, "mutant_id": mutant_id,
             "outcome": outcomes.get((item_id, mutant_id), "passed")}
            for item_id, mutant_id in sorted(pairs)
        ]

    d4_run_1 = d4_rows({
        ("a", "m1"): "failed", ("a", "m2"): "failed",
        ("b", "m3"): "failed",
    })
    d4_run_2 = d4_rows({("a", "m1"): "failed",
                         ("a", "m2"): "failed"},
                        {("a", "m1"), ("a", "m2")})
    d4_scored = score(
        {"a": {}, "b": {}}, d4_hard, d4_hard,
        {"a": "passed", "b": "passed"}, d4_run_1,
        expected=d4_pairs, hard_killed=d4_hard,
        candidate_rows_run_2=d4_run_2)
    check("D4 confirms exactly the initially hard-recall-1.0 item",
          d4_scored["hard_confirmation_qualifying_items"] == ["a"]
          and d4_scored["hard_confirmation_pairs"] == 2
          and d4_scored["candidate_hard_runs"] == 2,
          str(d4_scored))
    check("D4 does not rerun a below-boundary item and retains its run-1 "
          "literal-failed kill",
          d4_scored["per_item"]["b"]["hard_candidate_killed"] == 1
          and d4_scored["per_item"]["b"]["hard_recall"] == 0.5,
          str(d4_scored["per_item"]["b"]))
    check("D4 run 2 refuses missing, extra, and duplicate pairs",
          raises(lambda: score(
              {"a": {}, "b": {}}, d4_hard, d4_hard,
              {"a": "passed", "b": "passed"}, d4_run_1,
              expected=d4_pairs, hard_killed=d4_hard,
              candidate_rows_run_2=d4_run_2[:1]), "1 missing")
          and raises(lambda: score(
              {"a": {}, "b": {}}, d4_hard, d4_hard,
              {"a": "passed", "b": "passed"}, d4_run_1,
              expected=d4_pairs, hard_killed=d4_hard,
              candidate_rows_run_2=d4_run_2 + [{
                  "item_id": "b", "mutant_id": "m3",
                  "outcome": "failed"}]), "1 extra")
          and raises(lambda: score(
              {"a": {}, "b": {}}, d4_hard, d4_hard,
              {"a": "passed", "b": "passed"}, d4_run_1,
              expected=d4_pairs, hard_killed=d4_hard,
              candidate_rows_run_2=d4_run_2 + [dict(d4_run_2[0])]),
              "repeats candidate pair"))
    check("D4 run 1 must be complete on every hard pair",
          raises(lambda: score(
              {"a": {}, "b": {}}, d4_hard, d4_hard,
              {"a": "passed", "b": "passed"}, d4_run_1[:-1],
              hard_killed=d4_hard, candidate_rows_run_2=d4_run_2),
              "candidate run 1 is missing"))
    no_qualifier_rows = d4_rows({("a", "m1"): "failed"})
    no_qualifier = score(
        {"a": {}, "b": {}}, d4_hard, d4_hard,
        {"a": "passed", "b": "passed"}, no_qualifier_rows,
        expected=d4_pairs, hard_killed=d4_hard)
    check("zero D4 qualifiers require no run 2",
          no_qualifier["candidate_hard_runs"] == 1
          and no_qualifier["hard_confirmation_run_2_required"] is False
          and no_qualifier["hard_confirmation_pairs"] == 0)
    timeout_rows = d4_rows({("a", "m1"): "failed",
                            ("a", "m2"): "timeout"})
    timeout_hard = {"a": {"m1", "m2"}}
    timeout_scored = score(
        {"a": {}}, timeout_hard, timeout_hard, {"a": "passed"},
        [row for row in timeout_rows if row["item_id"] == "a"],
        expected={("a", "m1"), ("a", "m2")}, hard_killed=timeout_hard)
    check("D4 uses literal failed, so timeout neither qualifies nor becomes a "
          "hard headline kill",
          timeout_scored["hard_confirmation_qualifying_items"] == []
          and timeout_scored["per_item"]["a"]["hard_candidate_killed"] == 1)
    check("a qualifying D4 item cannot omit run 2",
          raises(lambda: score(
              {"a": {}, "b": {}}, d4_hard, d4_hard,
              {"a": "passed", "b": "passed"}, d4_run_1,
              expected=d4_pairs, hard_killed=d4_hard),
              "candidate run 2 is absent"))
    d4_campaign = {
        "campaign_identity": {"kind": "mutation-run"},
        "observation_id": "1" * 32,
    }
    check("D4 pins the producer-minted standalone run-2 observation id",
          _hard_rerun_observation_id(d4_campaign, "1" * 32) == "1" * 32)
    check("copied/forged run-2 observation metadata refuses",
          raises(lambda: _hard_rerun_observation_id(
              d4_campaign, "2" * 32), "ownership record"))

    # ------------------------------------------------- precomputed gold
    with tempfile.TemporaryDirectory() as d:
        gold_precomputed = [
            {"item_id": i, "mutant_id": m,
             "outcome": "failed" if (i, m) in GOLD_KILLS else "passed"}
            for (i, m) in sorted(expected_pairs(restricted))]

        # Reports are not row provenance.  Build the lower-level accepted
        # form: exact rows carrying one complete native shard identity.
        base_inputs = identity_inputs_for_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant,
            exact=NATIVE_GENERATION_INPUTS)
        native_job = plan_jobs(
            mutants, {"gold": gold_side(gold_rows, passed)[0]}, restricted,
            1, os.path.join(d, "native-source"), sides=("gold",),
            identity_inputs=base_inputs)[0]

        def native_gold_evidence(rows, name, gen_inputs=None, *,
                                 bind_shard_policy=True):
            from .mutation_run import (campaign_identity_digest,
                                       pair_set_digest, sha256_file)
            gen_inputs = (NATIVE_GENERATION_INPUTS if gen_inputs is None
                          else gen_inputs)
            pairs = {(row["item_id"], row["mutant_id"]) for row in rows}
            source_job = native_job
            if gen_inputs is not NATIVE_GENERATION_INPUTS \
                    or not bind_shard_policy:
                # Build the alternative at source -- either another generation
                # class or the pre-v3 unbound policy shape -- so the identity,
                # digest and every row stamp are internally consistent.  A
                # post-hoc identity edit would exercise only the digest check,
                # not the publication rule under test.
                source_job = plan_jobs(
                    mutants, {"gold": gold_side(gold_rows, passed)[0]},
                    restricted, 1, os.path.join(d, "gen-" + name),
                    sides=("gold",),
                    identity_inputs=identity_inputs_for_test_quality(
                        run_rows=run_rows, gold_baseline_rows=gold_rows,
                        manifest=manifest, by_mutant=by_mutant,
                        exact=gen_inputs),
                    bind_shard_policy=bind_shard_policy)[0]
            identity = {
                **source_job["identity"],
                "expected_pairs": len(pairs),
                "expected_pairs_sha256": pair_set_digest(pairs),
            }
            job = {"identity": identity}
            stamped = [_stamped(job, row) for row in rows]
            rows_path = os.path.join(d, name + ".jsonl")
            with open(rows_path, "w", encoding="utf-8") as fh:
                for row in stamped:
                    fh.write(json.dumps(row, sort_keys=True) + "\n")
            attestation = {
                **({"shard_policy": identity["shard_policy"]}
                   if "shard_policy" in identity else {}),
                "schema": "r2t.mutation-shard/v1",
                "status": "complete",
                "campaign_identity": identity,
                "mutation_campaign_digest": campaign_identity_digest(
                    identity),
                "out": os.path.basename(rows_path),
                "rows": len(stamped),
                "rows_sha256": sha256_file(rows_path),
                "expected_pairs": len(pairs),
                "expected_pairs_sha256": pair_set_digest(pairs),
            }
            attestation_path = rows_path + ".provenance.json"
            with open(attestation_path, "w", encoding="utf-8") as fh:
                json.dump(attestation, fh, indent=1, sort_keys=True)
            exact_inputs = identity_inputs_for_test_quality(
                run_rows=run_rows, gold_baseline_rows=gold_rows,
                manifest=manifest, by_mutant=by_mutant,
                gold_results=stamped,
                gold_results_attestation=attestation,
                exact={**gen_inputs,
                       "gold_results_sha256": sha256_file(rows_path)})
            return stamped, attestation, exact_inputs, attestation_path

        (native_rows, native_attestation, native_inputs,
         native_attestation_path) = \
            native_gold_evidence(gold_precomputed, "native-gold")

        execute, seen = fake_execute({"candidate": CAND_KILLS})
        summary = run_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant,
            out_dir=os.path.join(d, "campaign"),
            execute=execute, n_workers=2, gold_results=native_rows,
            gold_results_attestation=native_attestation,
            gold_results_attestation_path=native_attestation_path,
            identity_inputs=native_inputs)
        check("--gold-results executes the candidate side only",
              {j["side"] for j in seen} == {"candidate"},
              str([j["side"] for j in seen]))
        check("a precomputed gold file scores identically to executing gold",
              summary["recall_macro"] == 0.5
              and summary["verdicts"] == {EQUIVALENT: 1, WEAKER: 1,
                                          VACUOUS: 1, NOT_SCORABLE: 2},
              str(summary["verdicts"]))
        check("precomputed gold remains explicitly native and exact",
              summary["pairs_executed_gold"] == 6
              and summary["gold_rows_precomputed"] is True
              and summary["gold_provenance_class"] == "native")

        check("a complete current gold shard is accepted as native "
              "precomputed evidence only with every row stamp intact",
              validate_precomputed_gold_attestation(
                  native_attestation, inputs=native_inputs,
                  passed=passed, gold_files=gold_side(gold_rows, passed)[0],
                  expected=expected_pairs(restricted), gold_rows=native_rows,
                  manifest_digest=manifest.get("digest"),
                  require_complete=True,
                  attestation_path=native_attestation_path
                  )["validation_class"] == "native")

        # Fresh MEDIUM finding: a top-level sidecar field does not bind policy
        # for an unbound v2 test-quality identity.  Both a plausible historical
        # value and an arbitrary unknown value must therefore be ineligible;
        # accepting either would let mutable provenance invent scheduling facts
        # that are absent from the source root identity and every row stamp.
        (unbound_gold_rows, unbound_gold_attestation, unbound_gold_inputs,
         unbound_gold_attestation_path) = native_gold_evidence(
             gold_precomputed, "unbound-v2-gold", bind_shard_policy=False)
        unbound_rows_path = unbound_gold_attestation_path.removesuffix(
            ".provenance.json")
        unbound_rows_bytes = open(unbound_rows_path, "rb").read()
        unbound_rows_sha256 = sha256_file(unbound_rows_path)
        unbound_policy_results = {}
        for forged_policy in (SHARD_POLICY_STRIDED_V1, "post-hoc-fastest"):
            forged_unbound_attestation = dict(
                unbound_gold_attestation, shard_policy=forged_policy)
            with open(unbound_gold_attestation_path, "w",
                      encoding="utf-8") as fh:
                json.dump(forged_unbound_attestation, fh, indent=1,
                          sort_keys=True)
            forged_sidecar_bytes = open(
                unbound_gold_attestation_path, "rb").read()
            forged_inputs = dict(
                unbound_gold_inputs,
                gold_results_attestation_sha256=sha256_file(
                    unbound_gold_attestation_path))
            forged_execute, forged_seen = fake_execute({
                "candidate": CAND_KILLS})
            forged_out = os.path.join(
                d, "unbound-policy-" + forged_policy.replace("/", "_"))
            refused = raises(lambda: run_test_quality(
                run_rows=run_rows, gold_baseline_rows=gold_rows,
                manifest=manifest, by_mutant=by_mutant,
                out_dir=forged_out, execute=forged_execute, n_workers=1,
                gold_results=unbound_gold_rows,
                gold_results_attestation=forged_unbound_attestation,
                gold_results_attestation_path=(
                    unbound_gold_attestation_path),
                identity_inputs=forged_inputs),
                "unbound v2 test-quality cached gold is ineligible")
            unbound_policy_results[forged_policy] = (
                refused and not forged_seen and not os.path.lexists(forged_out)
                and open(unbound_rows_path, "rb").read()
                == unbound_rows_bytes
                and sha256_file(unbound_rows_path) == unbound_rows_sha256
                and open(unbound_gold_attestation_path, "rb").read()
                == forged_sidecar_bytes)
        check("MEDIUM regression: unbound v2 cached gold is ineligible when "
              "its mutable sidecar claims historical striding",
              unbound_policy_results[SHARD_POLICY_STRIDED_V1],
              str(unbound_policy_results))
        check("MEDIUM regression: unbound v2 cached gold is ineligible when "
              "its mutable sidecar claims an unknown policy",
              unbound_policy_results["post-hoc-fastest"],
              str(unbound_policy_results))

        # ------------------------------- PC1, PC3, PC4: degraded native gold
        #
        # One pair of the SAME complete gold file ends in the harness failing
        # instead of the mutant surviving.  Everything else -- the pair set,
        # the identities, the candidate side -- is held fixed, so what each
        # check below reads is the degradation and nothing else.
        _degraded_pair = sorted(expected_pairs(restricted))[0]

        def _degraded_gold(*, outcome="container_error", attempt=2,
                           retried=..., stamps=True):
            out = []
            for gold_row in gold_precomputed:
                pair = (gold_row["item_id"], gold_row["mutant_id"])
                fresh = dict(gold_row)
                if pair == _degraded_pair:
                    fresh["outcome"] = outcome
                    if stamps:
                        fresh["attempt"] = attempt
                        fresh["retried_infrastructure"] = (
                            attempt == 2 if retried is ... else retried)
                elif stamps:
                    fresh["attempt"] = 1
                    fresh["retried_infrastructure"] = False
                out.append(fresh)
            return out

        def _score_gold(rows, **kw):
            (r, attestation, inputs, attestation_path) = \
                native_gold_evidence(rows, "degraded-" + kw.pop("name"))
            execute_local, _seen = fake_execute({"candidate": CAND_KILLS})
            return run_test_quality(
                run_rows=run_rows, gold_baseline_rows=gold_rows,
                manifest=manifest, by_mutant=by_mutant,
                out_dir=os.path.join(d, "campaign-" + str(len(seen)) + kw.pop(
                    "out", "x")),
                execute=execute_local, n_workers=2, gold_results=r,
                gold_results_attestation=attestation,
                gold_results_attestation_path=attestation_path,
                identity_inputs=inputs, **kw)

        degraded_refused = ""
        try:
            _score_gold(_degraded_gold(), name="plain", out="a")
        except TestQualityRefused as e:
            degraded_refused = str(e)
        short_refused = ""
        try:
            _score_gold([r for r in _degraded_gold()
                         if (r["item_id"], r["mutant_id"])
                         != _degraded_pair], name="short", out="b")
        except TestQualityRefused as e:
            short_refused = str(e)
        check("PC1: SHORT gold and INFRASTRUCTURE-DEGRADED gold are distinct "
              "states -- each refusal names its own, and neither is the other",
              "infrastructure outcome(s)" in degraded_refused
              and "--allow-degraded-gold" in degraded_refused
              and "(item, mutant) executions" in short_refused
              and "--allow-incomplete" in short_refused
              and "infrastructure" not in short_refused,
              f"degraded={degraded_refused!r} short={short_refused!r}")
        consented = _score_gold(_degraded_gold(), name="consented", out="c",
                                allow_degraded_gold=True)
        check("PC1: ...and the consented degraded campaign scores, recording "
              "the flag, the count, the class and the per-item list",
              consented["allow_degraded_gold"] is True
              and consented["gold_infrastructure_outcomes"] == 1
              and consented["gold_rows_missing"] == 0
              and consented["gold_infrastructure_class"]
              == "native_retry_verified",
              str({k: consented.get(k) for k in
                   ("allow_degraded_gold", "gold_infrastructure_outcomes",
                    "gold_rows_missing", "gold_infrastructure_class")}))
        check("PC4: the per-item disclosure IS the aggregate count, pair for "
              "pair -- a disclosure that is not the number it discloses would "
              "be worse than none",
              len(consented["gold_infrastructure_pairs"])
              == consented["gold_infrastructure_outcomes"]
              and [(e["item_id"], e["mutant_id"])
                   for e in consented["gold_infrastructure_pairs"]]
              == [_degraded_pair]
              and consented["gold_infrastructure_pairs"][0]["outcome"]
              == "container_error",
              str(consented["gold_infrastructure_pairs"]))
        import io as _io
        from contextlib import redirect_stdout as _redirect
        _summary_out = _io.StringIO()
        with _redirect(_summary_out):
            print_summary(consented)
        _printed = _summary_out.getvalue()
        check("PC4: `print_summary` prints `pairs_executed_gold` and stops "
              "calling `pairs_expected` executions, and the degraded count "
              "and its per-item list are on the same screen",
              "gold executions: 6 of 6 expected" in _printed
              and "expected execution(s)" in _printed
              and "gold infrastructure outcomes: 1 (native_retry_verified, "
                  "CONSENTED --allow-degraded-gold)" in _printed
              and "container_error" in _printed, _printed)
        hard_consented = dict(
            consented, verdict_basis="hard_subset", hard_subset_digest="a" * 64)
        check("PC2: --allow-incomplete is NOT consent to degraded gold -- the "
              "short-gold escape hatch leaves the degraded campaign "
              "unpublishable, while a hard-basis fully disclosed tolerance "
              "remains eligible, and the two flags are separate parser dests",
              publication_ready(dict(hard_consented,
                                     allow_degraded_gold=False,
                                     require_complete=False))[0] is False
              and publication_ready(hard_consented)[0] is True
              # The second clause of this name, ASSERTED rather than claimed:
              # the real parser must carry two independent store_true dests,
              # so `--allow-incomplete` alone can never set the other.
              and _two_independent_consent_flags())
        # The optional-qualifier reconcile: the compensating control the
        # `LEGACY_SOURCE_OPTIONAL_SUMMARY_FIELDS` enrolment rests on.  Driven
        # directly, because `_build_legacy_wrapper` needs a whole PR-2
        # evidence tree to reach, and a control nothing can drive is a control
        # nobody can check.
        _reconcile_pairs = [{"item_id": "i", "mutant_id": "m",
                             "outcome": "container_error",
                             "gold_baseline_outcome": "passed"}]
        check("a preserved sidecar that carries a gold-degradation count it "
              "did not measure is REFUSED -- the optional qualifier is "
              "CHECKED where present, never merely tolerated",
              raises(lambda: reconcile_optional_qualifier(
                  {"gold_infrastructure_outcomes": 7}, _reconcile_pairs),
                  "claims 7, but the PR-2-validated gold rows carry 1"))
        check("...and the two admitted states pass: a sidecar that omits the "
              "field entirely (which is every preserved one) and a sidecar "
              "whose count agrees with the re-derived rows",
              reconcile_optional_qualifier({}, _reconcile_pairs) is None
              and reconcile_optional_qualifier(
                  {"gold_infrastructure_outcomes": 1},
                  _reconcile_pairs) is None)
        check("...and a field recorded with NOTHING in it is refused, not read "
              "as absence -- `null` is a claim about these rows and the key "
              "not being there is not",
              raises(lambda: reconcile_optional_qualifier(
                  {"gold_infrastructure_outcomes": None}, _reconcile_pairs),
                  "which is not a count")
              and raises(lambda: reconcile_optional_qualifier(
                  {"gold_infrastructure_outcomes": True}, _reconcile_pairs),
                  "which is not a count"))

        # The pinned eval100-std admission (EVAL100_STD_WRAPPER_COMPLETION
        # spec §§3+5+6), driven directly for the qualifier's reason above.
        # The claims mirror what `_build_legacy_wrapper` derives: the two
        # fields the preserved sidecar cannot state, a per-item entry whose
        # derived-only `jaccard` the eight preserved keys never carried, and
        # 0.908516 — the macro the preserved rows actually yield, which
        # renders as the committed fixture's published `0.909` cell.
        _pin_claims = {
            "n_passed": 5,
            "jaccard_macro": 0.908516,
            "row_engines": {"unlabelled": 1834},
            "per_item": {"i1": {
                "mutants_covering": 3, "gold_killed": 2,
                "candidate_killed": 2, "denominator": 2, "recall": 1.0,
                "jaccard": 0.908516, "verdict": EQUIVALENT,
                "not_scorable_reason": None, "candidate_only_kills": 0}},
        }
        _pin_summary = {field: "preserved" for field in
                        LEGACY_SOURCE_SUMMARY_FIELDS
                        - {"jaccard_macro", "row_engines"}}
        _pin_summary["n_passed"] = 5
        _pin_summary["per_item"] = {
            "i1": {key: value
                   for key, value in _pin_claims["per_item"]["i1"].items()
                   if key != "jaccard"}}
        check("an UNPINNED sidecar missing the two summary fields still "
              "refuses BY NAME",
              raises(lambda: reconcile_source_claims(
                  _pin_summary, _pin_claims, "0" * 64),
                  "missing=['jaccard_macro', 'row_engines'], unknown=[]"))
        check("the SHA-256-pinned eval100-std sidecar takes the relaxed "
              "path: the two underivable claims leave the reconcile, the "
              "derived-only per-item jaccard is set aside, and the "
              "re-derived macro agrees with the published byte-pinned table",
              reconcile_source_claims(_pin_summary, _pin_claims,
                                      EVAL100_STD_SIDECAR_SHA256) is True
              and reconcile_pinned_jaccard_cell(0.908516) is None)
        check("a pinned-path re-derived macro that disagrees with the "
              "published table refuses INSIDE the reconcile, not merely "
              "when `reconcile_pinned_jaccard_cell` is driven directly",
              raises(lambda: reconcile_source_claims(
                  _pin_summary, dict(_pin_claims, jaccard_macro=0.912),
                  EVAL100_STD_SIDECAR_SHA256),
                  "renders as 0.912"))
        check("the pinned path still reconciles every claim the sidecar "
              "DOES state",
              raises(lambda: reconcile_source_claims(
                  dict(_pin_summary, n_passed=2), _pin_claims,
                  EVAL100_STD_SIDECAR_SHA256),
                  "field(s) ['n_passed']"))
        _full_summary = dict(_pin_summary,
                             jaccard_macro=0.908516,
                             row_engines={"unlabelled": 1834},
                             per_item=_pin_claims["per_item"])
        check("a complete 33-field sidecar takes the strict path even under "
              "the pin digest — the pin admits nothing the field-set check "
              "would not have refused",
              reconcile_source_claims(_full_summary, _pin_claims,
                                      EVAL100_STD_SIDECAR_SHA256) is False
              and raises(lambda: reconcile_source_claims(
                  dict(_full_summary, jaccard_macro=0.5), _pin_claims,
                  EVAL100_STD_SIDECAR_SHA256),
                  "field(s) ['jaccard_macro']"))
        check("a re-derived macro that DISAGREES with the published table "
              "cell refuses by name",
              raises(lambda: reconcile_pinned_jaccard_cell(0.912),
                     "renders as 0.912")
              and raises(lambda: reconcile_pinned_jaccard_cell(0.912),
                         "cell is '0.909'"))

        # The collection-rule basis (spec §9, owner ruling 2026-08-18).  The
        # fixture mirrors the ONE preserved flipped pair in miniature: a
        # passed-baseline item where gold and the candidate both recorded
        # `timeout` on one mutant (`install_demo_data_command.feature:7`,
        # mutant `722254df…`), and counts chosen so the collection-basis
        # jaccard macro renders the committed fixture's published `0.909`
        # cell.  Driven directly, for LB5's recorded reason: the
        # `_build_legacy_wrapper` call site needs a whole PR-2 evidence tree
        # to reach, and the real bind at J3 is the end-to-end leg.
        _rule_passed = {"ia": ["f"], "ib": ["f"]}
        _rule_baseline = {"ia": "passed", "ib": "passed"}
        _rule_covering = {"ia": ["a1", "a2"],
                          "ib": [f"b{n}" for n in range(1, 12)]}
        _rule_gold_rows = (
            [{"item_id": "ia", "mutant_id": m, "outcome": "failed"}
             for m in ("a1", "a2")]
            + [{"item_id": "ib", "mutant_id": f"b{n}", "outcome": "failed"}
               for n in range(1, 11)]
            + [{"item_id": "ib", "mutant_id": "b11", "outcome": "timeout"}])
        _rule_cand_rows = (
            [{"item_id": "ia", "mutant_id": m, "outcome": "failed"}
             for m in ("a1", "a2")]
            + [{"item_id": "ib", "mutant_id": f"b{n}", "outcome": "failed"}
               for n in range(1, 10)]
            + [{"item_id": "ib", "mutant_id": "b10", "outcome": "passed"},
               {"item_id": "ib", "mutant_id": "b11", "outcome": "timeout"}])
        _rule_expected = {(row["item_id"], row["mutant_id"])
                          for row in _rule_gold_rows}
        _rule_current = gold_kill_sets(_rule_gold_rows, _rule_baseline,
                                       _rule_passed)
        _rule_basis = gold_kill_basis(_rule_gold_rows, _rule_baseline,
                                      _rule_passed,
                                      EVAL100_STD_SIDECAR_SHA256)
        check("the PINNED basis scores gold by the 2026-08-01 collection "
              "rule -- a gold-side timeout on a passed baseline is NOT a "
              "kill -- and the flipped pair is computed and named, never "
              "transcribed",
              _rule_basis[0]["ib"] == {f"b{n}" for n in range(1, 11)}
              and _rule_basis[3] == [("ib", "b11")], str(_rule_basis))
        check("an UNPINNED digest's basis is exactly today's "
              "`gold_kill_sets` -- the current rule, no flipped pairs",
              gold_kill_basis(_rule_gold_rows, _rule_baseline, _rule_passed,
                              "0" * 64) == (*_rule_current, [])
              and _rule_current[0]["ib"]
              == {f"b{n}" for n in range(1, 12)})

        def _rule_claims(gold_killed):
            return dict(score(_rule_passed, _rule_covering, gold_killed,
                              _rule_baseline, _rule_cand_rows,
                              expected=_rule_expected),
                        row_engines={"unlabelled": 26})

        _collection_claims = _rule_claims(_rule_basis[0])
        _rule_summary = {field: "preserved"
                         for field in LEGACY_SOURCE_SUMMARY_FIELDS
                         - {"jaccard_macro", "row_engines"}}
        _rule_summary.update(
            {key: value for key, value in _collection_claims.items()
             if key not in ("jaccard_macro", "row_engines", "per_item")},
            per_item={iid: {key: value for key, value in entry.items()
                            if key != "jaccard"}
                      for iid, entry in
                      _collection_claims["per_item"].items()})
        check("the pinned sidecar's 2026-08-01 arithmetic reconciles GREEN "
              "against the collection basis, cell agreement included",
              _collection_claims["recall_macro"] == 0.95
              and _collection_claims["jaccard_macro"] == 0.909091
              and _collection_claims["excluded"]["candidate_only_kill"] == 1
              and reconcile_source_claims(
                  _rule_summary, _collection_claims,
                  EVAL100_STD_SIDECAR_SHA256) is True)
        check("...and against TODAY's rule the same preserved arithmetic "
              "refuses in exactly the three fields the J3 rehearsal named",
              raises(lambda: reconcile_source_claims(
                  _rule_summary, _rule_claims(_rule_current[0]),
                  EVAL100_STD_SIDECAR_SHA256),
                  "field(s) ['excluded', 'per_item', 'recall_macro']"))
        check("a NON-pinned 33-field sidecar still reconciles under "
              "TODAY's rule, unchanged",
              reconcile_source_claims(
                  dict(_rule_summary, **_rule_claims(_rule_current[0])),
                  _rule_claims(_rule_current[0]), "0" * 64) is False)

        # Consumer-host rebinding (spec §11, owner-ruled 2026-08-19): the
        # claims loop's admissibility decision, extracted and driven
        # directly for LB5's recorded reason -- the `_build_legacy_wrapper`
        # call site needs a whole PR-2 evidence tree to reach, and the real
        # mint is the RUNBOOK_CORESHOP §4 consumer rehearsal.
        _spec11_wanted = os.path.join(d, "spec11_attested.jsonl")
        _spec11_same = os.path.join(d, "spec11_same_bytes.jsonl")
        _spec11_other = os.path.join(d, "spec11_other_bytes.jsonl")
        for _path, _payload in ((_spec11_wanted, "attested\n"),
                                (_spec11_same, "attested\n"),
                                (_spec11_other, "substituted\n")):
            with open(_path, "w", encoding="utf-8") as fh:
                fh.write(_payload)
        _spec11_missing = os.path.join(d, "no_such_author_host_path",
                                       "candidate_mutation.jsonl")
        check("spec §11: on the PINNED digest a claim spelling that "
              "resolves to nothing on this host is an unresolvable "
              "historical spelling -- skipped, so the mint proceeds on the "
              "PR-2-attested bytes",
              evidence_claim_admissible(
                  _spec11_missing, _spec11_wanted,
                  EVAL100_STD_SIDECAR_SHA256) is True)
        check("spec §11: anti-substitution is UNCHANGED on the pinned path "
              "-- a spelling that DOES resolve must still byte-match the "
              "attested file, and different bytes refuse",
              evidence_claim_admissible(
                  _spec11_other, _spec11_wanted,
                  EVAL100_STD_SIDECAR_SHA256) is False
              and evidence_claim_admissible(
                  _spec11_same, _spec11_wanted,
                  EVAL100_STD_SIDECAR_SHA256) is True)
        check("spec §11: an UNPINNED sidecar with a missing spelling still "
              "refuses exactly as today",
              evidence_claim_admissible(_spec11_missing, _spec11_wanted,
                                        "0" * 64) is False
              and evidence_claim_admissible(_spec11_same, _spec11_wanted,
                                            "0" * 64) is True)

        # PC3: the retry stamps, one broken way at a time.  Each fixture
        # differs from the CONSENTED one above in exactly one field, so a
        # refusal here is the stamp and not the degradation.
        for _label, _kw, _needle in (
                ("a first-and-only attempt on a retriable outcome",
                 {"attempt": 1}, "a retry that did not happen"),
                ("an out-of-range attempt", {"attempt": 3},
                 "no native retry stamp"),
                ("a retried flag that contradicts its attempt",
                 {"attempt": 2, "retried": False},
                 "record one fact and disagree"),
                ("no stamps at all -- the legacy shape",
                 {"stamps": False}, "no native retry stamp")):
            _refused = ""
            try:
                _score_gold(_degraded_gold(**_kw), name=_label[:12],
                            out=_label[:4], allow_degraded_gold=True)
            except TestQualityRefused as e:
                _refused = str(e)
            check(f"PC3: invalid native retry evidence refuses -- {_label}",
                  _needle in _refused, _refused or "did not refuse")
        check("PC3: ...and a legacy row missing the stamps may not claim "
              "degraded NATIVE gold, which is the sentence ruling 2.6 turns "
              "on",
              "may not be reported as degraded NATIVE gold" in (
                  _refused or ""), _refused)

        # ------------------------- LOOP-BACK (R3 review P2-1), surface TWO
        #
        # The R3 reviewer recorded that the fixture-class refusal at the two
        # publication surfaces had no red-on-delete tripwire: the LI7 check
        # that names it probes only the shared helper, so deleting either
        # CALL left the suite green.  This drives the second surface --
        # precomputed native gold re-entering a live campaign -- end to end,
        # over a shard whose identity, digest and row stamps are all
        # consistently `fixture`, which is exactly the state the guard is for.
        (_fx_rows, _fx_attestation, _fx_inputs, _fx_attestation_path) = \
            native_gold_evidence(gold_precomputed, "fixture-class-gold",
                                 gen_inputs=FIXTURE_GENERATION_INPUTS)
        _fx_execute, _fx_seen = fake_execute({"candidate": CAND_KILLS})
        _fx_refused = ""
        try:
            run_test_quality(
                run_rows=run_rows, gold_baseline_rows=gold_rows,
                manifest=manifest, by_mutant=by_mutant,
                out_dir=os.path.join(d, "campaign-fixture-class"),
                execute=_fx_execute, n_workers=2, gold_results=_fx_rows,
                gold_results_attestation=_fx_attestation,
                gold_results_attestation_path=_fx_attestation_path,
                identity_inputs=_fx_inputs)
        except TestQualityRefused as e:
            _fx_refused = str(e)
        check("LOOP-BACK: a consistently `fixture`-class native gold shard is "
              "REFUSED where a preserved artifact re-enters a live campaign, "
              "and the refusal names the surface",
              "this precomputed native gold shard" in _fx_refused
              and "not publishable" in _fx_refused, _fx_refused or "scored it")
        check("LOOP-BACK: ...and it is refused BEFORE the candidate side is "
              "executed, so the guard costs nothing to hold",
              not _fx_seen, str([j["side"] for j in _fx_seen]))

        # The public standalone producer uses generic mutation-run identity:
        # the gold baseline occupies its candidate fields, while TQ-only gold
        # fields are null.  Preserve a real worker/seed preimage so this is an
        # end-to-end compatibility test, not a hand-waved identity dict.
        from . import mutation_run as _MR
        from . import worker as _W
        standalone_seed = os.path.join(d, "standalone-seed")
        os.makedirs(standalone_seed)
        workspace_tar = os.path.join(standalone_seed, "workspace.tar")
        database_sql = os.path.join(standalone_seed, "database.sql")
        with open(workspace_tar, "wb") as fh:
            fh.write(b"standalone cached-gold workspace")
        with open(database_sql, "wb") as fh:
            fh.write(b"standalone cached-gold database")
        with open(os.path.join(standalone_seed, "seed.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({
                "format": 1, "seed_key": "standalone-gold-seed",
                "needs_database": True,
                "workspace": {"digest": _MR.sha256_file(workspace_tar)},
                "database": {"digest": _MR.sha256_file(database_sql)},
            }, fh, sort_keys=True)
        seed_identity = _W.verified_seed_identity(standalone_seed, True)
        standalone_worker = _W.WorkerSpec(
            index=0, workspace=os.path.join(d, "standalone-worker"),
            container="standalone-gold-worker", schema="standalone_gold_0",
            credential="standalone_gold_user_0",
            env_file=os.path.join(d, "standalone-worker.env"))
        standalone_spec = os.path.join(d, "standalone-worker.json")
        with open(standalone_spec, "w", encoding="utf-8") as fh:
            json.dump(standalone_worker.to_json(), fh, sort_keys=True)
        standalone_runtime = _W.runtime_attestation_path(standalone_spec)
        runtime_doc = {
            "schema": _W.WORKER_RUNTIME_SCHEMA_V2,
            "worker": standalone_worker.to_json(),
            "worker_spec_sha256": _MR.sha256_file(standalone_spec),
            **seed_identity,
            "container_image_digest": "sha256:" + "7" * 64,
            "docker_endpoint_selection": "legacy-default",
            "harness_version": "fixture-harness-v1",
        }
        with open(standalone_runtime, "w", encoding="utf-8") as fh:
            json.dump(runtime_doc, fh, sort_keys=True)
        standalone_resources = [{
            "index": 0,
            "worker_spec": os.path.realpath(standalone_spec),
            "workspace": os.path.realpath(standalone_worker.workspace),
            "container": standalone_worker.container,
            "schema": standalone_worker.schema,
            "credential": standalone_worker.credential,
            "env_file": os.path.realpath(standalone_worker.env_file),
            "workdir": standalone_worker.workdir,
            "runtime_attestation": os.path.realpath(standalone_runtime),
            "runtime_attestation_sha256": _MR.sha256_file(
                standalone_runtime),
        }]
        standalone_inputs = identity_inputs_for_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant,
            exact={
                **NATIVE_GENERATION_INPUTS,
                "worker_resources_sha256": _MR.content_digest(
                    standalone_resources),
                "workspace_seed_digest": seed_identity[
                    "workspace_seed_digest"],
                "database_dump_digest": seed_identity[
                    "database_dump_digest"],
            })
        gold_generated = _MR.candidate_digest(
            gold_side(gold_rows, passed)[0])
        standalone_identity = _MR.build_campaign_identity(
            **{key: standalone_inputs.get(key)
               for key in sorted(_MR.CAMPAIGN_IDENTITY_FIELDS_V2_ADDED)},
            asset_index_sha256=standalone_inputs[
                "asset_index_sha256"],
            asset_project=standalone_inputs["asset_project"],
            mutation_validation_sha256=standalone_inputs[
                "mutation_validation_sha256"],
            mutation_validation_class="native",
            manifest_sha256=standalone_inputs["manifest_sha256"],
            manifest_digest=manifest.get("digest"),
            map_sha256=standalone_inputs["map_sha256"],
            release_sha256=standalone_inputs["release_sha256"],
            candidate_run_sha256=standalone_inputs[
                "gold_baseline_sha256"],
            candidate_generated_tests_sha256=gold_generated,
            solution_generated_tests_sha256=gold_generated,
            substrate_baseline_sha256=standalone_inputs[
                "substrate_baseline_sha256"],
            applier_sha256=standalone_inputs["applier_sha256"],
            worker_resources_sha256=standalone_inputs[
                "worker_resources_sha256"],
            harness_version=standalone_inputs["harness_version"],
            container_image_digest=standalone_inputs[
                "container_image_digest"],
            workspace_seed_digest=standalone_inputs[
                "workspace_seed_digest"],
            database_dump_digest=standalone_inputs[
                "database_dump_digest"],
            expected_pairs=expected_pairs(restricted),
            engine=standalone_inputs["engine"],
            engine_version=standalone_inputs["engine_version"],
            parser=standalone_inputs["parser"], side="gold", shard=0,
            of=1, timeout=600)
        standalone_rows_path = os.path.join(
            d, "standalone-gold", "gold.w0.jsonl")
        _MR.prepare_standalone_output_directory(
            standalone_rows_path, standalone_identity)
        standalone_rows = [_stamped(
            {"identity": standalone_identity}, row)
            for row in gold_precomputed]
        with open(standalone_rows_path, "w", encoding="utf-8") as fh:
            for row in standalone_rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        _MR.write_shard_provenance(
            standalone_rows_path, standalone_identity, "running",
            provenance={"worker_resources": standalone_resources})
        standalone_attestation = _MR.write_shard_provenance(
            standalone_rows_path, standalone_identity, "complete",
            provenance={"worker_resources": standalone_resources})
        standalone_attestation_path = _MR.provenance_path(
            standalone_rows_path)
        standalone_inputs = identity_inputs_for_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant,
            gold_results=standalone_rows,
            gold_results_attestation=standalone_attestation,
            exact={
                **standalone_inputs,
                "gold_results_sha256": _MR.sha256_file(
                    standalone_rows_path),
                "gold_results_attestation_sha256": _MR.sha256_file(
                    standalone_attestation_path),
            })
        standalone_execute, _standalone_seen = fake_execute({
            "candidate": CAND_KILLS})
        standalone_summary = run_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant,
            out_dir=os.path.join(d, "standalone-gold-campaign"),
            execute=standalone_execute, n_workers=1,
            gold_results=standalone_rows,
            gold_results_attestation=standalone_attestation,
            gold_results_attestation_path=standalone_attestation_path,
            identity_inputs=standalone_inputs,
            worker_resources=standalone_resources)
        check("a real standalone mutation-run --side gold shard is reusable "
              "as native test-quality reference evidence",
              standalone_summary["gold_provenance_class"] == "native"
              and standalone_summary["recall_macro"] == 0.5)

        reference_identity = {
            key: standalone_identity[key]
            for key in _MR.CAMPAIGN_IDENTITY_FIELDS_V1
        }
        reference_identity.update({
            "schema": _MR.MUTATION_IDENTITY_SCHEMA_V5,
            "asset_project": "python-docx",
            "generation_provenance_class":
                _MR.GENERATION_PROVENANCE_REFERENCE_CONTROL,
            "reference_control_role": "full-gold",
            "reference_source_tag": "docx-reference-v1",
            "reference_workload_digest": "8" * 64,
        })
        reference_rows_path = os.path.join(
            d, "reference-gold", "gold.w0.jsonl")
        _MR.prepare_standalone_output_directory(
            reference_rows_path, reference_identity)
        reference_rows = [_stamped(
            {"identity": reference_identity}, row)
            for row in gold_precomputed]
        with open(reference_rows_path, "w", encoding="utf-8") as fh:
            for row in reference_rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        _MR.write_shard_provenance(
            reference_rows_path, reference_identity, "running",
            provenance={"worker_resources": standalone_resources})
        reference_attestation = _MR.write_shard_provenance(
            reference_rows_path, reference_identity, "complete",
            provenance={"worker_resources": standalone_resources})
        reference_attestation_path = _MR.provenance_path(reference_rows_path)
        reference_inputs = identity_inputs_for_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant,
            gold_results=reference_rows,
            gold_results_attestation=reference_attestation,
            exact={
                **standalone_inputs,
                "asset_project": "python-docx",
                "gold_results_sha256": _MR.sha256_file(
                    reference_rows_path),
                "gold_results_attestation_sha256": _MR.sha256_file(
                    reference_attestation_path),
            })
        reference_binding = validate_precomputed_gold_attestation(
            reference_attestation, inputs=reference_inputs,
            passed=passed, gold_files=gold_side(gold_rows, passed)[0],
            expected=expected_pairs(restricted), gold_rows=reference_rows,
            manifest_digest=manifest.get("digest"), require_complete=True,
            attestation_path=reference_attestation_path)
        check("test-quality admits complete full-gold exact-byte reference "
              "shards without inventing agent-generation fields",
              reference_binding["validation_class"] == "native"
              and not any(key in reference_identity
                          for key in _MR.CAMPAIGN_IDENTITY_FIELDS_V2_ADDED
                          - {"generation_provenance_class"}))

        # ---------------------- D4 exact-plan producer -> native validator
        # Exercise the operator workflow without a container: the real root
        # planner/lifecycle and shard attesters produce run 1; the real D4
        # builder derives its pair plan; the real standalone ownership writer
        # mints run 2; the native shard validator and resumed scorer consume
        # it.  Only execution outcomes are injected.
        import copy as _copy
        from ..toolkit import gold_killset as _GK
        from ..toolkit import hard_subset as _HS
        from ..data import versions as _V

        def additional_d4_worker_resource(index):
            worker = _W.WorkerSpec(
                index=index,
                workspace=os.path.join(d, f"d4-worker-{index}"),
                container=f"d4-worker-{index}",
                schema=f"d4_worker_{index}",
                credential=f"d4_worker_user_{index}",
                env_file=os.path.join(d, f"d4-worker-{index}.env"))
            spec_path = os.path.join(d, f"d4-worker-{index}.json")
            with open(spec_path, "w", encoding="utf-8") as fh:
                json.dump(worker.to_json(), fh, sort_keys=True)
            attestation_path = _W.runtime_attestation_path(spec_path)
            attestation = {
                "schema": _W.WORKER_RUNTIME_SCHEMA_V2,
                "worker": worker.to_json(),
                "worker_spec_sha256": _MR.sha256_file(spec_path),
                **seed_identity,
                "container_image_digest": runtime_doc[
                    "container_image_digest"],
                "docker_endpoint_selection": runtime_doc[
                    "docker_endpoint_selection"],
                "harness_version": runtime_doc["harness_version"],
            }
            with open(attestation_path, "w", encoding="utf-8") as fh:
                json.dump(attestation, fh, sort_keys=True)
            return {
                "index": index,
                "worker_spec": os.path.realpath(spec_path),
                "workspace": os.path.realpath(worker.workspace),
                "container": worker.container,
                "schema": worker.schema,
                "credential": worker.credential,
                "env_file": os.path.realpath(worker.env_file),
                "workdir": worker.workdir,
                "runtime_attestation": os.path.realpath(attestation_path),
                "runtime_attestation_sha256": _MR.sha256_file(
                    attestation_path),
            }

        # Run 1 deliberately has three workers.  Its qualifying set has only
        # two independently applicable mutant groups, so canonical run 2 uses
        # a smaller K=2 pool and final resume must still recover K=3 run 1.
        d4_run_1_resources = [
            standalone_resources[0],
            additional_d4_worker_resource(1),
            additional_d4_worker_resource(2),
        ]
        d4_run_2_resources = d4_run_1_resources[:2]

        d4_entry = _V.population("python-docx-v1")
        d4_manifest_digest = d4_entry["scored"]["manifest_digest"]
        d4_mutants = [
            {"id": mutant_id, "file": "src/d4.py",
             "operator": "NegateConditional", "start_line": line,
             "start_col": 1, "original": "a < b", "mutated": "a >= b"}
            for line, mutant_id in enumerate(("dm1", "dm2", "dm3"), 1)
        ]
        d4_manifest = {
            "digest": d4_manifest_digest, "n": len(d4_mutants),
            "engine": d4_entry["engine"],
            "engine_version": d4_entry["engine_version"],
            "parser": d4_entry["parser"], "mutants": d4_mutants,
        }
        d4_map = {
            "dm1": ["da", "dc"], "dm2": ["da"], "dm3": ["db"]}
        d4_run_rows = [
            {"item_id": item_id, "outcome": "passed",
             "produced_files": [{"file_path": f"{item_id}.py",
                                  "code": "def test_it(): pass\n"}]}
            for item_id in ("da", "db", "dc")
        ]
        d4_gold_rows = [
            {"item_id": item_id, "outcome": "passed",
             "produced_files": [{"file_path": f"gold_{item_id}.py",
                                  "code": "def test_gold(): pass\n"}]}
            for item_id in ("da", "db", "dc")
        ]
        d4_paths = {
            name: os.path.join(d, f"d4-{name}{suffix}")
            for name, suffix in (
                ("manifest", ".json"), ("map", ".json"),
                ("release", ".jsonl"), ("validation", ".json"),
                ("run", ".jsonl"), ("gold", ".jsonl"),
                ("hard", ".json"), ("plan", ".json"))
        }
        with open(d4_paths["manifest"], "w", encoding="utf-8") as fh:
            json.dump(d4_manifest, fh, sort_keys=True)
        with open(d4_paths["map"], "w", encoding="utf-8") as fh:
            json.dump({"by_mutant": d4_map}, fh, sort_keys=True)
        with open(d4_paths["release"], "w", encoding="utf-8") as fh:
            for item_id in ("da", "db", "dc"):
                fh.write(json.dumps({"item_id": item_id}) + "\n")
        with open(d4_paths["validation"], "w", encoding="utf-8") as fh:
            json.dump({"fixture": "release-ready"}, fh, sort_keys=True)
        for key, rows_ in (("run", d4_run_rows), ("gold", d4_gold_rows)):
            with open(d4_paths[key], "w", encoding="utf-8") as fh:
                for row in rows_:
                    fh.write(json.dumps(row, sort_keys=True) + "\n")

        d4_all_pairs = {
            ("da", "dm1"), ("da", "dm2"), ("db", "dm3"),
            ("dc", "dm1"),
        }
        d4_hard_identity = _GK._fixture_identity(
            manifest_digest=d4_manifest_digest,
            expected_pairs=d4_all_pairs)
        d4_hard_identity["harness_version"] = _V.component("harness")[
            "version"]

        def d4_hard_record(outcomes, observation, side="gold"):
            identity = _copy.deepcopy(d4_hard_identity)
            identity["side"] = side
            if side == "candidate":
                identity["candidate_run_sha256"] = "f" * 64
            return {
                "identity": identity, "outcomes": outcomes,
                "facts": {
                    "observation_id": observation,
                    "campaign_identity_sha256":
                        _MR.campaign_identity_digest(identity),
                    "rows_sha256": ["1" * 64],
                    "sidecars_sha256": ["2" * 64],
                    "n_shards": 1, "n_rows": len(outcomes),
                    "n_pairs": len(outcomes),
                    "pairs_sha256": _MR.pair_set_digest(outcomes),
                },
            }

        d4_failed = {pair: "failed" for pair in d4_all_pairs}
        d4_passed = {pair: "passed" for pair in d4_all_pairs}
        d4_hard_doc = _HS.build(
            "python-docx-v1",
            d4_hard_record(d4_failed, "a" * 32),
            d4_hard_record(d4_failed, "b" * 32),
            d4_hard_record(d4_passed, "c" * 32, "candidate"),
            d4_hard_record(d4_passed, "d" * 32, "candidate"),
            {"outcomes": {"da": "passed", "db": "passed",
                           "dc": "passed"},
             "reasons": {"da": None, "db": None, "dc": None},
             "sha256": "f" * 64,
             "generated_tests_sha256": "6" * 64})
        with open(d4_paths["hard"], "w", encoding="utf-8") as fh:
            json.dump(d4_hard_doc, fh, indent=1, sort_keys=True)
            fh.write("\n")

        d4_inputs = identity_inputs_for_test_quality(
            run_rows=d4_run_rows, gold_baseline_rows=d4_gold_rows,
            manifest=d4_manifest, by_mutant=d4_map, exact={
                **NATIVE_GENERATION_INPUTS,
                "asset_index_sha256": d4_entry["asset_index_sha256"],
                "asset_project": d4_entry["project"],
                "mutation_validation_sha256": _MR.sha256_file(
                    d4_paths["validation"]),
                "mutation_validation_class": "native",
                "manifest_sha256": _MR.sha256_file(d4_paths["manifest"]),
                "manifest_digest": d4_manifest_digest,
                "map_sha256": _MR.sha256_file(d4_paths["map"]),
                "release_sha256": _MR.sha256_file(d4_paths["release"]),
                "candidate_run_sha256": _MR.sha256_file(d4_paths["run"]),
                "candidate_generated_tests_sha256": _MR.candidate_digest(
                    passed_solutions(d4_run_rows)),
                "gold_baseline_sha256": _MR.sha256_file(d4_paths["gold"]),
                "gold_generated_tests_sha256": _MR.candidate_digest(
                    gold_side(d4_gold_rows,
                              passed_solutions(d4_run_rows))[0]),
                "applier_sha256": "9" * 64,
                "substrate_baseline_sha256": "8" * 64,
                "worker_resources_sha256": _MR.content_digest(
                    d4_run_1_resources),
                "harness_version": runtime_doc["harness_version"],
                "container_image_digest": runtime_doc[
                    "container_image_digest"],
                "workspace_seed_digest": seed_identity[
                    "workspace_seed_digest"],
                "database_dump_digest": seed_identity[
                    "database_dump_digest"],
                "engine": d4_entry["engine"],
                "engine_version": d4_entry["engine_version"],
                "parser": d4_entry["parser"],
            })
        d4_provenance = {
            "run": os.path.abspath(d4_paths["run"]),
            "gold_baseline": os.path.abspath(d4_paths["gold"]),
            "mutation_validation": os.path.abspath(d4_paths["validation"]),
            "manifest": os.path.abspath(d4_paths["manifest"]),
            "map": os.path.abspath(d4_paths["map"]),
            "release": os.path.abspath(d4_paths["release"]),
            "shard_policy": DEFAULT_SHARD_POLICY,
        }
        d4_execute, _d4_seen = fake_execute({
            "candidate": {
                ("da", "dm1"), ("da", "dm2"), ("dc", "dm1")},
            "gold": d4_all_pairs,
        })
        d4_root = os.path.join(d, "d4-run-1")
        d4_pending = run_test_quality(
            run_rows=d4_run_rows, gold_baseline_rows=d4_gold_rows,
            manifest=d4_manifest, by_mutant=d4_map, out_dir=d4_root,
            execute=d4_execute, n_workers=3, identity_inputs=d4_inputs,
            provenance=d4_provenance, timeout=5,
            worker_resources=d4_run_1_resources,
            hard_subset_doc=d4_hard_doc,
            hard_subset_path=d4_paths["hard"],
            d4_confirmation_plan_out=d4_paths["plan"])
        check("D4 producer stops after complete run 1 and emits the exact "
              "whole-item pair plan without finalizing the root",
              d4_pending["schema"] == D4_CONFIRMATION_PENDING_SCHEMA
              and d4_pending["qualifying_items"] == ["da", "dc"]
              and d4_pending["expected_pairs"] == 3
              and d4_pending["run_1_observation_id"]
              == _d4_run_1_observation_id(_load_json_object(
                  os.path.join(d4_root, CAMPAIGN_STATE),
                  "D4 pending root")["plan"])
              and _load_json_object(
                  os.path.join(d4_root, CAMPAIGN_STATE),
                  "D4 pending root")["status"] == "running")

        d4_assets = {
            "validation_class": "native",
            "asset_index_sha256": d4_entry["asset_index_sha256"],
            "asset_project": d4_entry["project"],
            "manifest": d4_manifest, "map": {"by_mutant": d4_map},
        }
        real_hard_load = _HS.load
        try:
            _HS.load = lambda path, **_kw: (
                _HS.validate(d4_hard_doc) and d4_hard_doc)
            d4_binding = validate_d4_confirmation_plan(
                d4_paths["plan"], run1_campaign=d4_root,
                hard_subset_path=d4_paths["hard"],
                candidate_run_path=d4_paths["run"], assets=d4_assets,
                validation_path=d4_paths["validation"],
                manifest_path=d4_paths["manifest"],
                map_path=d4_paths["map"], release_path=d4_paths["release"])

            def write_plan_variant(name, mutate):
                forged = _copy.deepcopy(d4_binding["plan"])
                mutate(forged)
                forged["digest"] = _MR.content_digest(
                    {key: value for key, value in forged.items()
                     if key != "digest"})
                forged_path = os.path.join(d, f"d4-{name}.json")
                with open(forged_path, "w", encoding="utf-8") as fh:
                    json.dump(forged, fh, indent=1, sort_keys=True)
                    fh.write("\n")
                return forged_path

            duplicate_plan = write_plan_variant(
                "duplicate-plan", lambda doc: doc["qualification"][
                    "pairs"].append(_copy.deepcopy(
                        doc["qualification"]["pairs"][0])))
            stale_plan = write_plan_variant(
                "stale-plan", lambda doc: doc["source"][
                    "candidate_shards"][0].update({"rows_sha256": "0" * 64}))

            def add_extra_pair(doc):
                pairs_ = doc["qualification"]["pairs"]
                pairs_.append({"item_id": "db", "mutant_id": "dm3"})
                pairs_.sort(key=lambda value: (
                    value["item_id"], value["mutant_id"]))
                pair_set_ = {(value["item_id"], value["mutant_id"])
                             for value in pairs_}
                doc["qualification"].update({
                    "items": sorted({item_id for item_id, _ in pair_set_}),
                    "expected_pairs": len(pair_set_),
                    "expected_pairs_sha256": _MR.pair_set_digest(pair_set_),
                })

            extra_plan = write_plan_variant("extra-plan", add_extra_pair)
            def remove_pair(doc):
                pairs_ = doc["qualification"]["pairs"][:-1]
                pair_set_ = {(value["item_id"], value["mutant_id"])
                             for value in pairs_}
                doc["qualification"].update({
                    "pairs": pairs_,
                    "items": sorted({item_id for item_id, _ in pair_set_}),
                    "expected_pairs": len(pair_set_),
                    "expected_pairs_sha256": _MR.pair_set_digest(pair_set_),
                })

            missing_plan = write_plan_variant("missing-plan", remove_pair)
            legacy_identity_plan = write_plan_variant(
                "legacy-identity-plan",
                lambda doc: doc.update({
                    "schema": "r2t.d4-confirmation-plan/v1"}))
            type_forged_plans = [
                write_plan_variant(
                    "float-source-count",
                    lambda doc: doc["source"].update({
                        "expected_pairs": float(
                            doc["source"]["expected_pairs"])})),
                write_plan_variant(
                    "boolean-source-count",
                    lambda doc: doc["source"].update({
                        "expected_pairs": True})),
                write_plan_variant(
                    "float-hard-count",
                    lambda doc: doc["hard_subset"].update({
                        "pairs": float(doc["hard_subset"]["pairs"])})),
                write_plan_variant(
                    "float-qualification-count",
                    lambda doc: doc["qualification"].update({
                        "expected_pairs": float(
                            doc["qualification"]["expected_pairs"])})),
                write_plan_variant(
                    "float-timeout", lambda doc: doc["source"].update({
                        "timeout_seconds": float(
                            doc["source"]["timeout_seconds"])})),
                write_plan_variant(
                    "boolean-timeout", lambda doc: doc["source"].update({
                        "timeout_seconds": True})),
            ]
            check("D4 plan representation is type-exact for every count and "
                  "the timeout: self-digesting floats/booleans cannot equal "
                  "JSON integers under Python's scalar equality",
                  all(raises(
                      lambda forged_path=forged_path:
                          validate_d4_confirmation_plan_document(
                              _load_json_object(
                                  forged_path, "type-forged D4 plan")),
                      "must be a JSON integer")
                      for forged_path in type_forged_plans))
            check("D4 plan consumption refuses duplicate, stale, and "
                  "self-consistently forged missing/extra pairs, plus the "
                  "old plan schema that lacked a run-1 identity",
                  raises(lambda: validate_d4_confirmation_plan_document(
                      _load_json_object(duplicate_plan, "duplicate D4 plan")),
                         "repeats pair")
                  and raises(lambda: validate_d4_confirmation_plan_document(
                      _load_json_object(
                          legacy_identity_plan, "legacy D4 plan")),
                      "unsupported D4")
                  and raises(lambda: validate_d4_confirmation_plan(
                      stale_plan, run1_campaign=d4_root,
                      hard_subset_path=d4_paths["hard"],
                      candidate_run_path=d4_paths["run"], assets=d4_assets,
                      validation_path=d4_paths["validation"],
                      manifest_path=d4_paths["manifest"],
                      map_path=d4_paths["map"],
                      release_path=d4_paths["release"]), "stale or tampered")
                  and raises(lambda: validate_d4_confirmation_plan(
                      extra_plan, run1_campaign=d4_root,
                      hard_subset_path=d4_paths["hard"],
                      candidate_run_path=d4_paths["run"], assets=d4_assets,
                      validation_path=d4_paths["validation"],
                      manifest_path=d4_paths["manifest"],
                      map_path=d4_paths["map"],
                      release_path=d4_paths["release"]),
                      "not the exact qualification")
                  and raises(lambda: validate_d4_confirmation_plan(
                      missing_plan, run1_campaign=d4_root,
                      hard_subset_path=d4_paths["hard"],
                      candidate_run_path=d4_paths["run"], assets=d4_assets,
                      validation_path=d4_paths["validation"],
                      manifest_path=d4_paths["manifest"],
                      map_path=d4_paths["map"],
                      release_path=d4_paths["release"]),
                      "not the exact qualification"))
            check("D4 plan consumption refuses the wrong run 1 or hard "
                  "subset before execution",
                  raises(lambda: validate_d4_confirmation_plan(
                      d4_paths["plan"], run1_campaign=os.path.join(d, "wrong"),
                      hard_subset_path=d4_paths["hard"],
                      candidate_run_path=d4_paths["run"], assets=d4_assets,
                      validation_path=d4_paths["validation"],
                      manifest_path=d4_paths["manifest"],
                      map_path=d4_paths["map"],
                      release_path=d4_paths["release"]), "different run-1")
                  and raises(lambda: validate_d4_confirmation_plan(
                      d4_paths["plan"], run1_campaign=d4_root,
                      hard_subset_path=os.path.join(d, "wrong-hard.json"),
                      candidate_run_path=d4_paths["run"], assets=d4_assets,
                      validation_path=d4_paths["validation"],
                      manifest_path=d4_paths["manifest"],
                      map_path=d4_paths["map"],
                      release_path=d4_paths["release"]), "different run-1"))
        finally:
            _HS.load = real_hard_load

        d4_partitions = shard_d4_confirmation_pairs(d4_binding["pairs"], 2)
        d4_root_state = _load_json_object(
            os.path.join(d4_root, CAMPAIGN_STATE), "D4 pending root")
        d4_root_candidate_identity = next(
            record["campaign_identity"]
            for record in d4_root_state["plan"]["jobs"]
            if record["side"] == "candidate")
        d4_run_2_provenance = {
            "worker_resources": d4_run_2_resources,
            "d4_confirmation_plan": os.path.abspath(d4_paths["plan"]),
            "d4_confirmation_plan_sha256": _MR.sha256_file(
                d4_paths["plan"]),
            "d4_confirmation_plan_digest": d4_binding["plan"]["digest"],
            "d4_run_1_campaign": os.path.abspath(d4_root),
            "d4_run_1_observation_id": d4_binding[
                "run_1_observation_id"],
            "d4_hard_subset": os.path.abspath(d4_paths["hard"]),
            "d4_pair_shard_policy": D4_PAIR_SHARD_POLICY,
        }

        def materialize_d4_run_2(
                label, allocations, forced_observation_id=None):
            paths = []
            for worker, allocation in enumerate(allocations):
                identity = _copy.deepcopy(d4_root_candidate_identity)
                identity.pop("shard_policy")
                identity.update({
                    "schema": _MR.MUTATION_IDENTITY_SCHEMA,
                    "kind": "mutation-run", "shard": worker,
                    "of": len(allocations),
                    "worker_resources_sha256": _MR.content_digest(
                        d4_run_2_resources),
                    "expected_pairs": len(allocation),
                    "expected_pairs_sha256": _MR.pair_set_digest(
                        allocation),
                })
                path = os.path.join(
                    d, label, f"candidate.w{worker}.jsonl")
                if forced_observation_id is not None and worker == 0:
                    os.makedirs(os.path.dirname(path))
                    _MR.atomic_write_json(
                        os.path.join(os.path.dirname(path),
                                     _MR.MUTATION_OUTPUT_PLAN),
                        _MR._standalone_output_plan(
                            identity, forced_observation_id),
                        refuse_existing=True)
                _MR.prepare_standalone_output_directory(path, identity)
                with open(path, "w", encoding="utf-8") as fh:
                    for item_id, mutant_id in sorted(allocation):
                        fh.write(json.dumps(_stamped(
                            {"identity": identity},
                            {"item_id": item_id, "mutant_id": mutant_id,
                             "outcome": "failed", "file": "src/d4.py",
                             "operator": "NegateConditional"}),
                            sort_keys=True) + "\n")
                _MR.write_shard_provenance(
                    path, identity, "running",
                    provenance=d4_run_2_provenance)
                _MR.write_shard_provenance(
                    path, identity, "complete",
                    provenance=d4_run_2_provenance)
                paths.append(path)
            campaign = _MR.validate_native_shards(
                paths, expected_pairs=d4_binding["pairs"],
                required_side="candidate", return_campaign=True)
            sidecars = [
                _load_json_object(
                    _MR.provenance_path(path), "D4 run-2 provenance")
                for path in paths
            ]
            return paths, sidecars, campaign

        (d4_run_2_paths, d4_run_2_sidecars,
         d4_native_run_2) = materialize_d4_run_2(
             "d4-run-2", d4_partitions)
        validate_d4_confirmation_run_2_binding(
            rerun_campaign=d4_native_run_2,
            shard_sidecars=d4_run_2_sidecars, plan_binding=d4_binding,
            plan_path=d4_paths["plan"], run1_campaign=d4_root,
            hard_subset_path=d4_paths["hard"])
        check("D4 K=2 exact-pair execution emits a current standalone native "
              "observation with deterministic ownership and complete "
              "provenance, using fewer workers than run 1",
              d4_native_run_2["pairs"] == d4_binding["pairs"]
              and isinstance(d4_native_run_2["observation_id"], str)
              and len(d4_native_run_2["observation_id"]) == 32
              and d4_native_run_2["campaign_identity"]["of"] == 2
              and {record["campaign_identity"]["of"]
                   for record in d4_root_state["plan"]["jobs"]} == {3})
        (_copied_paths, copied_sidecars,
         copied_campaign) = materialize_d4_run_2(
             "d4-run-2-copied-observation", d4_partitions,
             forced_observation_id=d4_binding["run_1_observation_id"])
        check("D4 finalization refuses a native-valid run 2 that copied the "
              "run-1 observation identity",
              raises(lambda: validate_d4_confirmation_run_2_binding(
                  rerun_campaign=copied_campaign,
                  shard_sidecars=copied_sidecars,
                  plan_binding=d4_binding, plan_path=d4_paths["plan"],
                  run1_campaign=d4_root,
                  hard_subset_path=d4_paths["hard"]),
                  "copied run 1's observation_id"))
        d4_wrong_candidate = _copy.deepcopy(d4_native_run_2)
        d4_wrong_candidate["campaign_identity"][
            "candidate_run_sha256"] = "0" * 64
        d4_short_provenance = _copy.deepcopy(d4_run_2_sidecars[0])
        d4_short_provenance.pop("d4_confirmation_plan_sha256")
        check("D4 finalization refuses a run-2 observation from other "
              "candidate bytes or incomplete plan/source provenance",
              raises(lambda: validate_d4_confirmation_run_2_binding(
                  rerun_campaign=d4_wrong_candidate,
                  shard_sidecars=d4_run_2_sidecars,
                  plan_binding=d4_binding, plan_path=d4_paths["plan"],
                  run1_campaign=d4_root,
                  hard_subset_path=d4_paths["hard"]),
                  "does not preserve")
              and raises(lambda: validate_d4_confirmation_run_2_binding(
                  rerun_campaign=d4_native_run_2,
                  shard_sidecars=[d4_short_provenance,
                                  d4_run_2_sidecars[1]],
                  plan_binding=d4_binding, plan_path=d4_paths["plan"],
                  run1_campaign=d4_root,
                  hard_subset_path=d4_paths["hard"]),
                  "does not completely bind"))

        # Both alternate campaigns are fully native-valid, have the same
        # exact disjoint union and use the same K=2 pool.  Only their worker
        # allocation violates the producer's deterministic LPT plan.
        (_swapped_paths, swapped_sidecars,
         swapped_campaign) = materialize_d4_run_2(
             "d4-run-2-swapped", list(reversed(d4_partitions)))
        m1_pairs = {pair for pair in d4_binding["pairs"] if pair[1] == "dm1"}
        m2_pairs = {pair for pair in d4_binding["pairs"] if pair[1] == "dm2"}
        split_allocations = [
            {sorted(m1_pairs)[0]} | m2_pairs,
            {sorted(m1_pairs)[1]},
        ]
        (_split_paths, split_sidecars,
         split_campaign) = materialize_d4_run_2(
             "d4-run-2-split-mutant", split_allocations)
        check("D4 finalization rejects native-valid swapped/arbitrary worker "
              "allocations and a mutant split across workers, not merely a "
              "correct union/policy label",
              raises(lambda: validate_d4_confirmation_run_2_binding(
                  rerun_campaign=swapped_campaign,
                  shard_sidecars=swapped_sidecars,
                  plan_binding=d4_binding, plan_path=d4_paths["plan"],
                  run1_campaign=d4_root,
                  hard_subset_path=d4_paths["hard"]),
                  "deterministic pair allocation")
              and raises(lambda: validate_d4_confirmation_run_2_binding(
                  rerun_campaign=split_campaign,
                  shard_sidecars=split_sidecars,
                  plan_binding=d4_binding, plan_path=d4_paths["plan"],
                  run1_campaign=d4_root,
                  hard_subset_path=d4_paths["hard"]),
                  "deterministic pair allocation"))

        check("resumed D4 scorer independently refuses a copied run-1 id "
              "before changing the pending root",
              raises(lambda: run_test_quality(
                  run_rows=d4_run_rows, gold_baseline_rows=d4_gold_rows,
                  manifest=d4_manifest, by_mutant=d4_map, out_dir=d4_root,
                  execute=lambda job: {"out": job["out"],
                                       "read_only": True},
                  n_workers=3, identity_inputs=d4_inputs,
                  provenance=d4_provenance, timeout=5, resume=True,
                  worker_resources=d4_run_1_resources,
                  hard_subset_doc=d4_hard_doc,
                  hard_subset_path=d4_paths["hard"],
                  candidate_hard_rerun_rows=copied_campaign["rows"],
                  candidate_hard_rerun_paths=_copied_paths,
                  candidate_hard_rerun_observation_id=copied_campaign[
                      "observation_id"]), "copied run 1's observation_id")
              and _load_json_object(
                  os.path.join(d4_root, CAMPAIGN_STATE),
                  "D4 pending root")["status"] == "running")

        d4_final = run_test_quality(
            run_rows=d4_run_rows, gold_baseline_rows=d4_gold_rows,
            manifest=d4_manifest, by_mutant=d4_map, out_dir=d4_root,
            execute=lambda job: {"out": job["out"], "read_only": True},
            n_workers=3, identity_inputs=d4_inputs,
            provenance=d4_provenance, timeout=5, resume=True,
            worker_resources=d4_run_1_resources,
            hard_subset_doc=d4_hard_doc,
            hard_subset_path=d4_paths["hard"],
            candidate_hard_rerun_rows=d4_native_run_2["rows"],
            candidate_hard_rerun_paths=d4_run_2_paths,
            candidate_hard_rerun_observation_id=d4_native_run_2[
                "observation_id"])
        check("D4 producer -> standalone run 2 -> resumed validator completes "
              "end to end on the exact selective pair set",
              d4_final["candidate_hard_runs"] == 2
              and d4_final["candidate_hard_run_1_observation_id"]
              == d4_binding["run_1_observation_id"]
              and d4_final["candidate_hard_run_1_observation_id"]
              != d4_final["candidate_hard_rerun_observation_id"]
              and d4_final["hard_confirmation_qualifying_items"]
              == ["da", "dc"]
              and d4_final["hard_confirmation_pairs"] == 3
              and d4_final["non_vacuous_passes"] == 2)
        check("a self-declared native object without its source shard "
              "sidecar path is refused",
              raises(lambda: validate_precomputed_gold_attestation(
                  native_attestation, inputs=native_inputs,
                  passed=passed, gold_files=gold_side(gold_rows, passed)[0],
                  expected=expected_pairs(restricted), gold_rows=native_rows,
                  manifest_digest=manifest.get("digest"),
                  require_complete=True), "saved complete shard sidecar"))

        superset = gold_precomputed + [
            {"item_id": "i_other", "mutant_id": "m1", "outcome": "failed"}]
        check("an attested precomputed-gold superset is refused rather than "
              "silently filtered into another population",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=manifest, by_mutant=by_mutant,
                  out_dir=os.path.join(d, "superset"), execute=execute,
                  n_workers=1, gold_results=superset,
                  gold_results_attestation=native_attestation),
                  "current population"))

        ran = []

        def _watch(job):
            ran.append(job["side"])
            return execute(job)

        short_gold = [r for r in gold_precomputed if r["mutant_id"] != "m3"]
        (short_native_rows, short_attestation, short_inputs,
         short_attestation_path) = \
            native_gold_evidence(short_gold, "native-gold-short")
        check("an INCOMPLETE precomputed gold file is refused",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=manifest, by_mutant=by_mutant,
                  out_dir=os.path.join(d, "short"), execute=_watch,
                  n_workers=1,
                  gold_results=short_native_rows,
                  gold_results_attestation=short_attestation,
                  gold_results_attestation_path=short_attestation_path,
                  identity_inputs=short_inputs),
                  "shrinks the very set"))
        check("...BEFORE the expensive candidate side is executed", ran == [],
              str(ran))

        sensitivity_execute, _sensitivity_seen = fake_execute(
            {"candidate": CAND_KILLS})
        sensitivity = run_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant,
            out_dir=os.path.join(d, "short-sensitivity"),
            execute=sensitivity_execute, n_workers=1,
            gold_results=short_native_rows,
            gold_results_attestation=short_attestation,
            gold_results_attestation_path=short_attestation_path,
            identity_inputs=short_inputs, require_complete=False)
        check("--allow-incomplete remains an explicitly native sensitivity "
              "analysis and discloses its smaller gold denominator",
              sensitivity["gold_provenance_class"] == "native"
              and sensitivity["require_complete"] is False
              and sensitivity["gold_rows_missing"] == 1)

    # ---------------------------------------------------- refusals & gaps
    with tempfile.TemporaryDirectory() as d:
        base_execute, _seen = fake_execute({"candidate": CAND_KILLS,
                                            "gold": GOLD_KILLS})
        injected = False

        def inject_extra_shard(job):
            nonlocal injected
            result = base_execute(job)
            if not injected:
                injected = True
                with open(os.path.join(d, SHARD_DIR, "unplanned.jsonl"), "w",
                          encoding="utf-8") as fh:
                    fh.write("{}\n")
            return result

        check("a shard file added after output preflight is refused at the "
              "merge gate",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=manifest, by_mutant=by_mutant, out_dir=d,
                  execute=inject_extra_shard, n_workers=1),
                  "differs from the exact plan"))

    with tempfile.TemporaryDirectory() as d:
        base_execute, _seen = fake_execute({"candidate": CAND_KILLS,
                                            "gold": GOLD_KILLS})
        injected = False

        def inject_extra_root(job):
            nonlocal injected
            result = base_execute(job)
            if not injected:
                injected = True
                with open(os.path.join(d, "unplanned-root.json"), "w",
                          encoding="utf-8") as fh:
                    fh.write("{}\n")
            return result

        check("a root artifact added after output preflight is refused at the "
              "merge gate",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=manifest, by_mutant=by_mutant, out_dir=d,
                  execute=inject_extra_root, n_workers=1),
                  "output root differs"))

    with tempfile.TemporaryDirectory() as d:
        short = {k for k in CAND_KILLS}

        def short_execute(job):
            """One pair never gets a row — a crashed worker, in effect."""
            os.makedirs(os.path.dirname(job["out"]), exist_ok=True)
            with open(job["out"], "a", encoding="utf-8") as fh:
                for mutant in job["mutants"]:
                    for iid in job["by_mutant"][mutant["id"]]:
                        if (iid, mutant["id"]) == ("i_weak", "m3"):
                            continue
                        pair = (iid, mutant["id"])
                        killed = (pair in GOLD_KILLS if job["side"] == "gold"
                                  else pair in short)
                        fh.write(json.dumps(_stamped(job, {
                            "item_id": iid, "mutant_id": mutant["id"],
                            "file": mutant["file"],
                            "outcome": "failed" if killed else "passed"}))
                            + "\n")
            _finish_fake_job(job)
            return {"out": job["out"], "rows": 0}

        check("a SHORT results file is refused, not averaged over",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=manifest, by_mutant=by_mutant, out_dir=d,
                  execute=short_execute, n_workers=1),
                  "missing"))
        check("--allow-incomplete cannot launder a missing PLANNED shard row",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=manifest, by_mutant=by_mutant,
                  out_dir=os.path.join(d, "loose"), execute=short_execute,
                  n_workers=1, require_complete=False), "missing"))

    with tempfile.TemporaryDirectory() as d:
        execute, _seen = fake_execute({"candidate": CAND_KILLS,
                                       "gold": GOLD_KILLS})
        check("a gold baseline missing a passed item is refused",
              raises(lambda: run_test_quality(
                  run_rows=run_rows,
                  gold_baseline_rows=[r for r in gold_rows
                                      if r["item_id"] != "i_vac"],
                  manifest=manifest, by_mutant=by_mutant, out_dir=d,
                  execute=execute, n_workers=1),
                  "no row for"))

        def boom(job):
            raise RuntimeError("container is gone")

        check("a worker that dies stops the scoring instead of shortening it",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=manifest, by_mutant=by_mutant,
                  out_dir=os.path.join(d, "boom"), execute=boom, n_workers=2),
                  "slice(s) failed"))
        failed_state = json.load(open(
            os.path.join(d, "boom", CAMPAIGN_STATE), encoding="utf-8"))
        check("a worker failure makes the root campaign terminally failed",
              failed_state["status"] == "failed"
              and failed_state["history"][-1] == "failed"
              and failed_state["artifacts"] == {})

        cancelled = threading.Event()
        cancelled.set()
        cancelled_out = os.path.join(d, "cancelled")
        check("coordinator cancellation is recorded before merge or score",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=manifest, by_mutant=by_mutant,
                  out_dir=cancelled_out, execute=execute, n_workers=1,
                  cancel_event=cancelled), "cooperatively cancelled"))
        interrupted_state = json.load(open(
            os.path.join(cancelled_out, CAMPAIGN_STATE), encoding="utf-8"))
        check("coordinator cancellation leaves an interrupted, never "
              "complete, root campaign",
              interrupted_state["status"] == "interrupted"
              and interrupted_state["artifacts"] == {})

        from . import mutation_run as _MR
        # Hold the coordinator/latch lock and the GIL across the cap boundary.
        # Both timer and watcher are therefore forced to observe the request
        # only after expiry, reproducing the review's scheduling boundary
        # deterministically.  The source timestamp, not that delayed poll,
        # must decide the immutable cause.
        import sys
        boundary_external = _MR.CoordinatorCancellationEvent()
        boundary_workers = threading.Event()
        boundary_deadline = time.monotonic() + 0.12
        boundary_latch = _CampaignFirstCause(
            boundary_external, boundary_workers,
            deadline=boundary_deadline)
        boundary_latch.start()
        old_switch_interval = sys.getswitchinterval()
        boundary_requested_at = None
        try:
            sys.setswitchinterval(1.0)
            with boundary_latch._lock:
                while time.monotonic() < boundary_deadline - 0.04:
                    pass
                boundary_external.set()
                boundary_requested_at = (
                    boundary_external.operator_requested_at())
                while time.monotonic() < boundary_deadline + 0.02:
                    pass
        finally:
            sys.setswitchinterval(old_switch_interval)
        boundary_cause = boundary_latch.cancellation_cause()
        boundary_kind = (
            INTERRUPTION_COMPUTE_CAP
            if boundary_cause == _CampaignFirstCause.COMPUTE_CAP
            else INTERRUPTION_OPERATOR)
        boundary_reason = campaign_interruption(
            boundary_kind, {"compute_cap_sha256": "a" * 64})
        boundary_latch.close()
        check("an operator request sourced before the deadline remains operator "
              "evidence when watcher and timer run only after the deadline",
              boundary_requested_at is not None
              and boundary_requested_at < boundary_deadline
              and boundary_cause == _CampaignFirstCause.OPERATOR
              and boundary_workers.is_set()
              and boundary_reason["kind"] == INTERRUPTION_OPERATOR
              and boundary_reason["compute_cap_sha256"] is None
              and (boundary_latch._watcher is None
                   or not boundary_latch._watcher.is_alive())
              and (boundary_latch._timer is None
                   or not boundary_latch._timer.is_alive()))

        early_complete_external = threading.Event()
        early_complete_workers = threading.Event()
        early_complete_latch = _CampaignFirstCause(
            early_complete_external, early_complete_workers,
            deadline=time.monotonic() + 0.05)
        early_complete_latch.start()
        early_complete_cause = early_complete_latch.commit_complete()
        time.sleep(0.08)
        check("completion linearizes before a later cap callback, which cannot "
              "cancel or relabel the committed result",
              early_complete_cause == _CampaignFirstCause.COMPLETE
              and early_complete_latch.commit_complete()
              == _CampaignFirstCause.COMPLETE
              and not early_complete_workers.is_set())
        early_complete_latch.close()
        expired_workers = threading.Event()
        expired_latch = _CampaignFirstCause(
            threading.Event(), expired_workers,
            deadline=time.monotonic() - 0.001)
        check("completion checks the monotonic deadline under the same lock and "
              "loses when cap expiry linearizes first",
              expired_latch.commit_complete()
              == _CampaignFirstCause.COMPUTE_CAP
              and expired_workers.is_set())
        expired_latch.close()
        late_operator = _MR.CoordinatorCancellationEvent()
        late_deadline = time.monotonic() - 0.001
        late_operator.set()
        late_workers = threading.Event()
        late_latch = _CampaignFirstCause(
            late_operator, late_workers, deadline=late_deadline)
        check("an authenticated operator request sourced after the deadline "
              "cannot hide cap expiry",
              late_latch.commit_complete()
              == _CampaignFirstCause.COMPUTE_CAP
              and late_workers.is_set())
        late_latch.close()

        class _ReentrantSignalSet(_MR.CoordinatorCancellationEvent):
            def __init__(self):
                super().__init__()
                self.injected = False

            def _published_is_set(self):
                visible = super()._published_is_set()
                if not self.injected:
                    self.injected = True
                    # Model a Python signal handler running between the flag
                    # and timestamp reads on the same main thread.  The RLock
                    # intentionally permits this re-entrant call.
                    self.set()
                return visible

        reentrant_external = _ReentrantSignalSet()
        reentrant_workers = threading.Event()
        reentrant_deadline = time.monotonic() - 0.001
        reentrant_latch = _CampaignFirstCause(
            reentrant_external, reentrant_workers,
            deadline=reentrant_deadline)
        reentrant_cause = reentrant_latch.commit_complete()
        reentrant_snapshot = reentrant_external.operator_snapshot()
        check("a same-thread signal between snapshot fields is re-read as one "
              "timestamped publication, so a post-deadline signal stays cap",
              reentrant_external.injected
              and reentrant_snapshot[0] is not None
              and reentrant_snapshot[0] >= reentrant_deadline
              and reentrant_snapshot[1] is True
              and reentrant_cause == _CampaignFirstCause.COMPUTE_CAP
              and reentrant_workers.is_set())
        reentrant_latch.close()

        # Pause a real setter after its source timestamp but before the Event
        # flag publication.  The campaign's atomic snapshot must wait for the
        # pair rather than observe timestamp and visibility on opposite sides
        # of the publication window.  Delaying that publication past the cap
        # does not change the pre-deadline source ordering.
        class _PausedPublication(_MR.CoordinatorCancellationEvent):
            def __init__(self):
                super().__init__()
                self.timestamp_written = threading.Event()
                self.allow_publication = threading.Event()
                self.publication_timed_out = False

            def set(self):
                with self._request_lock:
                    if self._requested_at is None:
                        self._requested_at = time.monotonic()
                    self.timestamp_written.set()
                    if not self.allow_publication.wait(1.0):
                        self.publication_timed_out = True
                    threading.Event.set(self)

        paused_external = _PausedPublication()
        paused_workers = threading.Event()
        paused_deadline = time.monotonic() + 10.0
        paused_latch = _CampaignFirstCause(
            paused_external, paused_workers, deadline=paused_deadline)
        paused_result = []
        paused_setter = threading.Thread(target=paused_external.set)
        paused_setter.start()
        paused_timestamp_ready = paused_external.timestamp_written.wait(0.5)
        paused_deadline = time.monotonic() + 0.12
        paused_latch.deadline = paused_deadline

        def paused_completion():
            paused_result.append(paused_latch.commit_complete())

        paused_completion_thread = threading.Thread(target=paused_completion)
        paused_completion_thread.start()
        while (time.monotonic() < paused_deadline + 0.005
               and paused_completion_thread.is_alive()):
            pass
        paused_was_blocked = paused_completion_thread.is_alive()
        paused_external.allow_publication.set()
        paused_setter.join(timeout=0.2)
        paused_completion_thread.join(timeout=0.2)
        paused_requested_at = paused_external.operator_requested_at()
        check("an atomic operator snapshot waits out a setter paused between "
              "timestamp and flag publication, preserving its pre-cap source",
              paused_timestamp_ready
              and paused_was_blocked
              and not paused_external.publication_timed_out
              and paused_requested_at is not None
              and paused_requested_at < paused_deadline
              and paused_result == [_CampaignFirstCause.OPERATOR]
              and paused_workers.is_set()
              and not paused_setter.is_alive()
              and not paused_completion_thread.is_alive())
        paused_latch.close()

        # Gate the first snapshot after it has read an unset event.  A request
        # can then be placed deterministically between the initial and final
        # samples taken by commit_complete().
        class _GateTimestampSnapshot(_MR.CoordinatorCancellationEvent):
            def __init__(self, gate_call=1):
                super().__init__()
                self.sample_gated = threading.Event()
                self.release_sample = threading.Event()
                self.gate_call = gate_call
                self._sample_calls = 0
                self._sample_calls_lock = threading.Lock()
                self.sample_timed_out = False

            def operator_snapshot(self):
                snapshot = super().operator_snapshot()
                with self._sample_calls_lock:
                    self._sample_calls += 1
                    gated = self._sample_calls == self.gate_call
                if gated:
                    self.sample_gated.set()
                    if not self.release_sample.wait(1.0):
                        self.sample_timed_out = True
                return snapshot

        between_external = _GateTimestampSnapshot()
        between_workers = threading.Event()
        between_deadline = time.monotonic() + 10.0
        between_latch = _CampaignFirstCause(
            between_external, between_workers, deadline=between_deadline)
        between_result = []
        between_thread = threading.Thread(
            target=lambda: between_result.append(
                between_latch.commit_complete()))
        between_thread.start()
        between_first_ready = between_external.sample_gated.wait(0.5)
        between_deadline = time.monotonic() + 0.2
        between_latch.deadline = between_deadline
        between_external.set()
        between_set_before_deadline = time.monotonic() < between_deadline
        between_external.release_sample.set()
        between_thread.join(timeout=0.2)
        check("a timestamped cancellation appearing after the initial sample "
              "but before the completion decision wins at the final sample",
              between_first_ready
              and between_set_before_deadline
              and not between_external.sample_timed_out
              and between_result == [_CampaignFirstCause.OPERATOR]
              and between_workers.is_set()
              and not between_thread.is_alive())
        between_latch.close()

        class _GatePlainSnapshot(threading.Event):
            def __init__(self, gate_call=1):
                super().__init__()
                self.sample_gated = threading.Event()
                self.release_sample = threading.Event()
                self.gate_call = gate_call
                self._sample_calls = 0
                self._sample_calls_lock = threading.Lock()
                self.sample_timed_out = False

            def is_set(self):
                visible = super().is_set()
                with self._sample_calls_lock:
                    self._sample_calls += 1
                    gated = self._sample_calls == self.gate_call
                if gated:
                    self.sample_gated.set()
                    if not self.release_sample.wait(1.0):
                        self.sample_timed_out = True
                return visible

        between_plain = _GatePlainSnapshot()
        between_plain_workers = threading.Event()
        between_plain_deadline = time.monotonic() + 10.0
        between_plain_latch = _CampaignFirstCause(
            between_plain, between_plain_workers,
            deadline=between_plain_deadline)
        between_plain_result = []
        between_plain_thread = threading.Thread(
            target=lambda: between_plain_result.append(
                between_plain_latch.commit_complete()))
        between_plain_thread.start()
        between_plain_ready = between_plain.sample_gated.wait(0.5)
        between_plain_deadline = time.monotonic() + 0.2
        between_plain_latch.deadline = between_plain_deadline
        between_plain.set()
        between_plain_before_deadline = (
            time.monotonic() < between_plain_deadline)
        between_plain.release_sample.set()
        between_plain_thread.join(timeout=0.2)
        check("a legacy Event becoming visible after the initial sample but "
              "before completion is conservatively caught by the final sample",
              between_plain_ready
              and between_plain_before_deadline
              and not between_plain.sample_timed_out
              and between_plain_result == [_CampaignFirstCause.OPERATOR]
              and between_plain_workers.is_set()
              and not between_plain_thread.is_alive())
        between_plain_latch.close()

        # Now pause the *final* sample after it has read an unset source.  The
        # request is published before the deadline, but the stale sample is not
        # returned until afterwards.  A single read followed by a time sample
        # would mislabel this schedule as cap; the bracketed protocol retries.
        straddle_external = _GateTimestampSnapshot(gate_call=2)
        straddle_workers = threading.Event()
        straddle_deadline = time.monotonic() + 10.0
        straddle_latch = _CampaignFirstCause(
            straddle_external, straddle_workers, deadline=straddle_deadline)
        straddle_result = []
        straddle_thread = threading.Thread(
            target=lambda: straddle_result.append(
                straddle_latch.commit_complete()))
        straddle_thread.start()
        straddle_final_ready = straddle_external.sample_gated.wait(0.5)
        straddle_deadline = time.monotonic() + 0.12
        straddle_latch.deadline = straddle_deadline
        straddle_external.set()
        straddle_set_before_deadline = time.monotonic() < straddle_deadline
        while time.monotonic() < straddle_deadline + 0.005:
            pass
        straddle_external.release_sample.set()
        straddle_thread.join(timeout=0.2)
        check("a timestamped pre-deadline request published after the final "
              "read is recovered when that stale read straddles the deadline",
              straddle_final_ready
              and straddle_set_before_deadline
              and not straddle_external.sample_timed_out
              and straddle_result == [_CampaignFirstCause.OPERATOR]
              and straddle_workers.is_set()
              and not straddle_thread.is_alive())
        straddle_latch.close()

        straddle_plain = _GatePlainSnapshot(gate_call=2)
        straddle_plain_workers = threading.Event()
        straddle_plain_deadline = time.monotonic() + 10.0
        straddle_plain_latch = _CampaignFirstCause(
            straddle_plain, straddle_plain_workers,
            deadline=straddle_plain_deadline)
        straddle_plain_result = []
        straddle_plain_thread = threading.Thread(
            target=lambda: straddle_plain_result.append(
                straddle_plain_latch.commit_complete()))
        straddle_plain_thread.start()
        straddle_plain_final_ready = straddle_plain.sample_gated.wait(0.5)
        straddle_plain_deadline = time.monotonic() + 0.12
        straddle_plain_latch.deadline = straddle_plain_deadline
        straddle_plain.set()
        straddle_plain_set_before_deadline = (
            time.monotonic() < straddle_plain_deadline)
        while time.monotonic() < straddle_plain_deadline + 0.005:
            pass
        straddle_plain.release_sample.set()
        straddle_plain_thread.join(timeout=0.2)
        check("a legacy Event published after the final read is recovered when "
              "that stale read straddles the deadline",
              straddle_plain_final_ready
              and straddle_plain_set_before_deadline
              and not straddle_plain.sample_timed_out
              and straddle_plain_result == [_CampaignFirstCause.OPERATOR]
              and straddle_plain_workers.is_set()
              and not straddle_plain_thread.is_alive())
        straddle_plain_latch.close()

        # The same inter-snapshot schedule on the other side of the deadline
        # must not let a late authenticated request conceal cap expiry.
        after_external = _GateTimestampSnapshot()
        after_workers = threading.Event()
        after_deadline = time.monotonic() + 10.0
        after_latch = _CampaignFirstCause(
            after_external, after_workers, deadline=after_deadline)
        after_result = []
        after_thread = threading.Thread(
            target=lambda: after_result.append(after_latch.commit_complete()))
        after_thread.start()
        after_first_ready = after_external.sample_gated.wait(0.5)
        after_deadline = time.monotonic() + 0.12
        after_latch.deadline = after_deadline
        while time.monotonic() < after_deadline + 0.005:
            pass
        after_external.set()
        after_external.release_sample.set()
        after_thread.join(timeout=0.2)
        after_requested_at = after_external.operator_requested_at()
        check("an authenticated request sourced after the deadline remains cap "
              "even when it appears between initial and final samples",
              after_first_ready
              and after_requested_at is not None
              and after_requested_at >= after_deadline
              and not after_external.sample_timed_out
              and after_result == [_CampaignFirstCause.COMPUTE_CAP]
              and after_workers.is_set()
              and not after_thread.is_alive())
        after_latch.close()

        plain_external = threading.Event()
        plain_external.set()
        plain_workers = threading.Event()
        plain_latch = _CampaignFirstCause(
            plain_external, plain_workers,
            deadline=time.monotonic() - 0.001)
        check("a legacy plain Event remains API-compatible but fail-closed: "
              "unknown source time can never be emitted as cap evidence",
              plain_latch.commit_complete() == _CampaignFirstCause.OPERATOR
              and plain_workers.is_set())
        plain_latch.close()

        class _PausedVisibleWait(threading.Event):
            def __init__(self):
                super().__init__()
                self.watcher_awake = threading.Event()
                self.release_watcher = threading.Event()
                self.wait_timed_out = False
                self._paused_once = False

            def wait(self, timeout=None):
                visible = super().wait(timeout)
                if visible and not self._paused_once:
                    self._paused_once = True
                    self.watcher_awake.set()
                    if not self.release_watcher.wait(1.0):
                        self.wait_timed_out = True
                return visible

        closing_external = _PausedVisibleWait()
        closing_workers = threading.Event()
        closing_latch = _CampaignFirstCause(
            closing_external, closing_workers)
        closing_latch.start()
        closing_external.set()
        closing_watcher_awake = closing_external.watcher_awake.wait(0.2)
        closing_thread = threading.Thread(target=closing_latch.close)
        closing_thread.start()
        closing_linearized = closing_latch._closed.wait(0.2)
        closing_external.release_watcher.set()
        closing_thread.join(timeout=0.3)
        check("close linearizes before an already-awake watcher can commit, "
              "then joins it without setting worker cancellation",
              closing_watcher_awake
              and closing_linearized
              and not closing_external.wait_timed_out
              and closing_latch._cause is None
              and not closing_workers.is_set()
              and not closing_thread.is_alive()
              and closing_latch._watcher is not None
              and not closing_latch._watcher.is_alive())

        class _PausedCapCallback(_CampaignFirstCause):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.timer_awake = threading.Event()
                self.release_timer = threading.Event()
                self.timer_wait_timed_out = False

            def _reach_compute_cap(self):
                self.timer_awake.set()
                if not self.release_timer.wait(1.0):
                    self.timer_wait_timed_out = True
                super()._reach_compute_cap()

        closing_timer_workers = threading.Event()
        closing_timer_latch = _PausedCapCallback(
            threading.Event(), closing_timer_workers,
            deadline=time.monotonic() + 0.03)
        closing_timer_latch.start()
        closing_timer_awake = closing_timer_latch.timer_awake.wait(0.2)
        closing_timer_thread = threading.Thread(
            target=closing_timer_latch.close)
        closing_timer_thread.start()
        closing_timer_linearized = closing_timer_latch._closed.wait(0.2)
        closing_timer_latch.release_timer.set()
        closing_timer_thread.join(timeout=0.3)
        check("close linearizes before an already-awake cap callback can "
              "commit, then joins timer and watcher without cancellation",
              closing_timer_awake
              and closing_timer_linearized
              and not closing_timer_latch.timer_wait_timed_out
              and closing_timer_latch._cause is None
              and not closing_timer_workers.is_set()
              and not closing_timer_thread.is_alive()
              and closing_timer_latch._timer is not None
              and not closing_timer_latch._timer.is_alive()
              and closing_timer_latch._watcher is not None
              and not closing_timer_latch._watcher.is_alive())

        cap_resources = [{"index": 0, "fixture": "cap-worker"}]
        cap_inputs = identity_inputs_for_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant,
            exact={**NATIVE_GENERATION_INPUTS,
                   "worker_resources_sha256":
                       _MR.content_digest(cap_resources)})

        def wait_for_cap(job):
            job["cancel_event"].wait(3)
            raise _MR.MutationCancelled("cap-aware fake worker stopped")

        cap_review_commit = subprocess.run(
            ["git", "-C", os.path.dirname(os.path.realpath(os.path.join(
                os.path.dirname(__file__), os.pardir, os.pardir))),
             "rev-parse", "--verify", "HEAD^{commit}"],
            check=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE).stdout.decode("ascii").strip()
        cap_review_authority = (
            "benchmark/MUTATION_BOUND_OPERATOR.md@" + cap_review_commit)
        validate_compute_cap_review_authority(cap_review_authority)
        authority_probe = lambda value: build_compute_cap(
            wall_clock_seconds=1, workers=1, expected={("i", "m")},
            campaign_dir=os.path.join(d, "authority-probe"),
            review_authority=value)
        check("compute-cap authority refuses latest and branch labels before "
              "campaign creation",
              raises(lambda: authority_probe("latest"), "mutable refs")
              and raises(lambda: authority_probe(
                  "benchmark/MUTATION_BOUND_OPERATOR.md@main"),
                  "mutable refs"))
        check("compute-cap authority refuses abbreviated commits",
              raises(lambda: authority_probe(
                  "benchmark/MUTATION_BOUND_OPERATOR.md@"
                  + cap_review_commit[:12]), "abbreviated"))
        check("compute-cap authority refuses a missing review record",
              raises(lambda: authority_probe(
                  "benchmark/DOES_NOT_EXIST.md@" + cap_review_commit),
                  "path is missing"))
        tampered_review_commit = (
            ("0" if cap_review_commit[0] != "0" else "1")
            + cap_review_commit[1:])
        check("compute-cap authority refuses a tampered immutable revision",
              raises(lambda: authority_probe(
                  "benchmark/MUTATION_BOUND_OPERATOR.md@"
                  + tampered_review_commit), "recoverable full Git commit"))
        check("rejected compute-cap authorities create no campaign bytes",
              not os.path.lexists(os.path.join(d, "authority-probe")))
        cap_out = os.path.join(d, "compute-cap")
        check("authenticated compute-cap timer stops through the cooperative "
              "worker path",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=manifest, by_mutant=by_mutant,
                  out_dir=cap_out, execute=wait_for_cap, n_workers=1,
                  identity_inputs=cap_inputs,
                  worker_resources=cap_resources,
                  compute_cap_seconds=1,
                  compute_cap_review_authority=cap_review_authority),
                  "cooperatively cancelled"))
        cap_state = json.load(open(
            os.path.join(cap_out, CAMPAIGN_STATE), encoding="utf-8"))
        cap_plan = cap_state["plan"]
        check("cap expiry is typed and bound through plan v3 and every v4 "
              "shard identity",
              cap_state["schema"] == TEST_QUALITY_CAMPAIGN_SCHEMA_V2
              and cap_plan["schema"] == TEST_QUALITY_PLAN_SCHEMA_V3
              and set(cap_plan) == TEST_QUALITY_PLAN_V3_FIELDS
              and cap_plan["projection_by_side"]
              == {side: None for side in SIDES}
              and cap_plan["observation_ids_by_side"]
              == {side: cap_plan["jobs"][0]["campaign_identity"][
                  "observation_id"] for side in SIDES}
              and cap_plan["delta_pairs_sha256_by_side"]
              == {side: cap_plan["estimand_pairs_sha256"] for side in SIDES}
              and cap_plan["final_artifact_types_by_side"]
              == {side: "native_observation" for side in SIDES}
              and cap_plan["preflight_cache_authority"] is None
              and cap_state["interruption"]
              == campaign_interruption(INTERRUPTION_COMPUTE_CAP, cap_plan)
              and all(job["campaign_identity"]["schema"]
                      == _MR.MUTATION_IDENTITY_SCHEMA_V4
                      and job["campaign_identity"]["compute_cap_sha256"]
                      == cap_plan["compute_cap_sha256"]
                      and job["preflight_cache_authority_sha256"] is None
                      for job in cap_plan["jobs"]))

        cap_gold_files = gold_side(gold_rows, passed)[0]
        cap_selected, cap_restricted, _cap_covering = population(
            manifest, by_mutant, passed)
        cap_rebuilt_jobs = plan_jobs(
            cap_selected, {"candidate": passed, "gold": cap_gold_files},
            cap_restricted, 1, cap_out, identity_inputs=cap_inputs,
            **_v4_execution_kwargs(
                cap_plan["jobs"][0]["campaign_identity"]))
        cap_rebuilt_plan = build_test_quality_campaign_plan(
            cap_rebuilt_jobs, expected=expected_pairs(cap_restricted),
            worker_resources=cap_resources, campaign_dir=cap_out,
            compute_cap=cap_plan["compute_cap"])
        check("plan v3 reconstructs the complete per-side projection, "
              "observation, delta, job, final-artifact, and cap bindings",
              cap_rebuilt_plan == cap_plan)

        wide_resources = [
            dict(cap_resources[0]),
            {"index": 1, "fixture": "authenticated-unused-tail-worker"},
        ]
        wide_inputs = {
            **cap_inputs,
            "worker_resources_sha256": _MR.content_digest(wide_resources),
        }
        wide_selected = cap_selected[:1]
        wide_restricted = {
            wide_selected[0]["id"]:
                cap_restricted[wide_selected[0]["id"]],
        }
        wide_expected = expected_pairs(wide_restricted)
        wide_estimand_sha256 = _MR.pair_set_digest(wide_expected)
        wide_cap = build_compute_cap(
            wall_clock_seconds=1, workers=2,
            expected=wide_expected, campaign_dir=cap_out,
            review_authority=cap_review_authority)
        wide_cap_sha256 = _MR.content_digest(wide_cap)
        wide_observation_id = cap_plan[
            "observation_ids_by_side"]["candidate"]
        wide_jobs = plan_jobs(
            wide_selected, {"candidate": passed, "gold": cap_gold_files},
            wide_restricted, 2, cap_out, identity_inputs=wide_inputs,
            compute_cap_sha256=wide_cap_sha256,
            estimand_pairs_sha256=wide_estimand_sha256,
            observation_id=wide_observation_id)
        wide_plan = build_test_quality_campaign_plan(
            wide_jobs, expected=wide_expected,
            worker_resources=wide_resources, campaign_dir=cap_out,
            compute_cap=wide_cap)
        check("plan v3 authenticates an unused tail resource when LPT omits "
              "empty jobs from a worker pool wider than the mutant set",
              {record["worker"] for record in wide_plan["jobs"]} == {0}
              and {record["of"] for record in wide_plan["jobs"]} == {2}
              and validate_test_quality_plan_v3(wide_plan) is wide_plan)

        import copy as _cap_copy
        malformed_v3 = _cap_copy.deepcopy(cap_plan)
        malformed_v3["projection_by_side"].pop("gold")
        old_singular_v3 = _cap_copy.deepcopy(cap_plan)
        old_singular_v3["reuse_projection"] = None
        bad_type_v3 = _cap_copy.deepcopy(cap_plan)
        bad_type_v3["final_artifact_types_by_side"]["candidate"] = "native"
        missing_cache_root_slot = _cap_copy.deepcopy(cap_plan)
        missing_cache_root_slot.pop("preflight_cache_authority")
        missing_cache_job_slot = _cap_copy.deepcopy(cap_plan)
        missing_cache_job_slot["jobs"][0].pop(
            "preflight_cache_authority_sha256")
        forged_cache_root = _cap_copy.deepcopy(cap_plan)
        forged_cache_root["preflight_cache_authority"] = {
            "schema": "unreviewed-cache-authority"
        }
        forged_cache_job = _cap_copy.deepcopy(cap_plan)
        forged_cache_job["jobs"][0][
            "preflight_cache_authority_sha256"] = "0" * 64
        check("plan v3 refuses malformed side maps, old singular reuse "
              "fields, open-ended final-artifact labels, and absent or "
              "non-null cache-authority slots",
              raises(lambda: validate_test_quality_plan_v3(malformed_v3),
                     "candidate/gold")
              and raises(lambda: validate_test_quality_plan_v3(
                  old_singular_v3), "missing or unknown")
              and raises(lambda: validate_test_quality_plan_v3(bad_type_v3),
                         "unknown final-artifact")
              and raises(lambda: validate_test_quality_plan_v3(
                  missing_cache_root_slot), "missing or unknown")
              and raises(lambda: validate_test_quality_plan_v3(
                  missing_cache_job_slot), "malformed exact job")
              and raises(lambda: validate_test_quality_plan_v3(
                  forged_cache_root), "no implemented, reviewed producer")
              and raises(lambda: validate_test_quality_plan_v3(
                  forged_cache_job), "current root authority is null"))
        mixed_v3 = _cap_copy.deepcopy(cap_plan)
        mixed_identity = mixed_v3["jobs"][-1]["campaign_identity"]
        mixed_identity["observation_id"] = "b" * 32
        mixed_v3["jobs"][-1]["mutation_campaign_digest"] = \
            _MR.campaign_identity_digest(mixed_identity)
        check("plan v3 refuses a validly rehashed job that mixes its side's "
              "root observation binding",
              raises(lambda: validate_test_quality_plan_v3(mixed_v3),
                     "differs from its per-side"))

        def rehash_v3_jobs(document):
            for record in document["jobs"]:
                record["mutation_campaign_digest"] = \
                    _MR.campaign_identity_digest(
                        record["campaign_identity"])
            return document

        unresolved_authority = _cap_copy.deepcopy(cap_plan)
        unresolved_authority["compute_cap"]["review_authority"] = (
            "benchmark/DOES_NOT_EXIST.md@" + cap_review_commit)
        unresolved_cap_sha256 = _MR.content_digest(
            unresolved_authority["compute_cap"])
        unresolved_authority["compute_cap_sha256"] = unresolved_cap_sha256
        for record in unresolved_authority["jobs"]:
            record["campaign_identity"]["compute_cap_sha256"] = \
                unresolved_cap_sha256
        rehash_v3_jobs(unresolved_authority)
        check("plan-v3 reader re-resolves a self-consistent immutable cap "
              "authority instead of trusting producer syntax checks",
              raises(lambda: validate_test_quality_plan_v3(
                  unresolved_authority), "path is missing"))

        def another_hex(value):
            return ("0" if value[0] != "0" else "1") + value[1:]

        malformed_label_list = _cap_copy.deepcopy(cap_plan)
        malformed_label_list["final_artifact_types_by_side"][
            "candidate"] = []
        malformed_label_object = _cap_copy.deepcopy(cap_plan)
        malformed_label_object["final_artifact_types_by_side"][
            "candidate"] = {}
        malformed_side = _cap_copy.deepcopy(cap_plan)
        malformed_side["jobs"][0]["side"] = []
        check("plan v3 turns JSON-valid unhashable labels and sides into "
              "controlled refusals",
              raises(lambda: validate_test_quality_plan_v3(
                  malformed_label_list), "unknown final-artifact")
              and raises(lambda: validate_test_quality_plan_v3(
                  malformed_label_object), "unknown final-artifact")
              and raises(lambda: validate_test_quality_plan_v3(
                  malformed_side), "malformed exact job"))

        forged_gold_flag = _cap_copy.deepcopy(cap_plan)
        forged_gold_flag["gold_precomputed"] = True
        forged_cap_digest = _cap_copy.deepcopy(cap_plan)
        forged_cap_digest["compute_cap_sha256"] = another_hex(
            forged_cap_digest["compute_cap_sha256"])
        for record in forged_cap_digest["jobs"]:
            record["campaign_identity"]["compute_cap_sha256"] = \
                forged_cap_digest["compute_cap_sha256"]
        rehash_v3_jobs(forged_cap_digest)
        forged_estimand = _cap_copy.deepcopy(cap_plan)
        forged_estimand["estimand_pairs_sha256"] = another_hex(
            forged_estimand["estimand_pairs_sha256"])
        for side in SIDES:
            forged_estimand["delta_pairs_sha256_by_side"][side] = \
                forged_estimand["estimand_pairs_sha256"]
        for record in forged_estimand["jobs"]:
            record["campaign_identity"]["estimand_pairs_sha256"] = \
                forged_estimand["estimand_pairs_sha256"]
        rehash_v3_jobs(forged_estimand)
        forged_delta = _cap_copy.deepcopy(cap_plan)
        forged_delta["delta_pairs_sha256_by_side"]["candidate"] = \
            another_hex(forged_delta["estimand_pairs_sha256"])
        check("plan v3 refuses coordinated gold, cap, estimand and native-"
              "delta semantic rewrites even when job identities are rehashed",
              raises(lambda: validate_test_quality_plan_v3(
                  forged_gold_flag), "gold_precomputed")
              and raises(lambda: validate_test_quality_plan_v3(
                  forged_cap_digest), "compute-cap digest")
              and raises(lambda: validate_test_quality_plan_v3(
                  forged_estimand), "expected population")
              and raises(lambda: validate_test_quality_plan_v3(
                  forged_delta), "native job/delta"))

        split_observations = _cap_copy.deepcopy(cap_plan)
        split_observations["observation_ids_by_side"]["gold"] = \
            another_hex(split_observations[
                "observation_ids_by_side"]["gold"])
        for record in split_observations["jobs"]:
            if record["side"] == "gold":
                record["campaign_identity"]["observation_id"] = \
                    split_observations["observation_ids_by_side"]["gold"]
        rehash_v3_jobs(split_observations)
        unsafe_job = _cap_copy.deepcopy(cap_plan)
        unsafe_job["jobs"][0]["out"] = "../../escape.jsonl"
        incomplete_workers = _cap_copy.deepcopy(cap_plan)
        for record in incomplete_workers["jobs"]:
            record["of"] = 2
            record["campaign_identity"]["of"] = 2
        rehash_v3_jobs(incomplete_workers)
        jobless_precomputed = _cap_copy.deepcopy(cap_plan)
        jobless_precomputed["jobs"] = [
            record for record in jobless_precomputed["jobs"]
            if record["side"] != "gold"
        ]
        jobless_precomputed["gold_precomputed"] = True
        jobless_precomputed["final_artifact_types_by_side"]["gold"] = \
            "precomputed_gold"
        check("plan v3 refuses split cap observations, unsafe paths, "
              "incomplete worker topology, and observed jobless gold",
              raises(lambda: validate_test_quality_plan_v3(
                  split_observations), "share one")
              and raises(lambda: validate_test_quality_plan_v3(
                  unsafe_job), "malformed exact job")
              and raises(lambda: validate_test_quality_plan_v3(
                  incomplete_workers), "malformed exact job")
              and raises(lambda: validate_test_quality_plan_v3(
                  jobless_precomputed), "observation-free"))

        batch_under_cap = _cap_copy.deepcopy(cap_plan)
        for record in batch_under_cap["jobs"]:
            identity = record["campaign_identity"]
            identity.update({
                "execution_policy": _MR.EXECUTION_POLICY_BATCH_BISECT_V1,
                "batch_plan_sha256": "1" * 64,
                "max_batch_members": 25,
                "max_batch_instances": 1,
                "stack_reset_sha256": "2" * 64,
                "batch_journal_schema": "r2t.batch-journal/1",
            })
        rehash_v3_jobs(batch_under_cap)
        check("plan v3 refuses structurally valid batch-bisect identities "
              "beneath the scalar compute cap",
              raises(lambda: validate_test_quality_plan_v3(batch_under_cap),
                     "exact scalar cap"))

        manual_cap_event = threading.Event()
        manual_cap_event.set()
        manual_cap_out = os.path.join(d, "manual-cap-stop")
        check("manual cancellation of a cap-bound campaign remains a "
              "different typed reason",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=manifest, by_mutant=by_mutant,
                  out_dir=manual_cap_out, execute=execute, n_workers=1,
                  identity_inputs=cap_inputs,
                  worker_resources=cap_resources,
                  compute_cap_seconds=30,
                  compute_cap_review_authority=cap_review_authority,
                  cancel_event=manual_cap_event),
                  "cooperatively cancelled"))
        manual_cap_state = json.load(open(
            os.path.join(manual_cap_out, CAMPAIGN_STATE), encoding="utf-8"))
        check("manual cap-bound stop cannot masquerade as cap expiry",
              manual_cap_state["interruption"]["kind"]
              == INTERRUPTION_OPERATOR
              and manual_cap_state["interruption"][
                  "compute_cap_sha256"] is None)

        slow_manual_event = threading.Event()
        slow_manual_out = os.path.join(d, "manual-before-cap-slow-cleanup")

        def slow_manual_cleanup(job):
            if not job["cancel_event"].wait(2):
                raise RuntimeError("operator cancellation was not forwarded")
            # Deliberately remain in restoration past the one-second cap. The
            # timer is allowed to fire, but the immutable first-cause latch may
            # not turn the earlier operator stop into compute-cap evidence.
            time.sleep(1.05)
            raise _MR.MutationCancelled("restored after slow cleanup")

        manual_trigger = threading.Timer(0.05, slow_manual_event.set)
        manual_trigger.daemon = True
        manual_trigger.start()
        try:
            slow_manual_refused = raises(lambda: run_test_quality(
                run_rows=run_rows, gold_baseline_rows=gold_rows,
                manifest=manifest, by_mutant=by_mutant,
                out_dir=slow_manual_out, execute=slow_manual_cleanup,
                n_workers=1, identity_inputs=cap_inputs,
                worker_resources=cap_resources,
                compute_cap_seconds=1,
                compute_cap_review_authority=cap_review_authority,
                cancel_event=slow_manual_event), "cooperatively cancelled")
        finally:
            manual_trigger.cancel()
        slow_manual_state = json.load(open(
            os.path.join(slow_manual_out, CAMPAIGN_STATE), encoding="utf-8"))
        check("manual cancellation before the timer remains operator_cancelled "
              "even when restoration crosses the cap deadline",
              slow_manual_refused
              and slow_manual_state["interruption"]["kind"]
              == INTERRUPTION_OPERATOR
              and slow_manual_state["interruption"][
                  "compute_cap_sha256"] is None)

        cap_state_before_resume = open(
            os.path.join(cap_out, CAMPAIGN_STATE), "rb").read()
        cap_resume_calls = []
        check("compute-cap/v1 interrupted roots cannot receive a brand-new full "
              "timer through --resume",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=manifest, by_mutant=by_mutant,
                  out_dir=cap_out,
                  execute=lambda job: cap_resume_calls.append(job),
                  n_workers=1, identity_inputs=cap_inputs,
                  worker_resources=cap_resources,
                  compute_cap_seconds=1,
                  compute_cap_review_authority=cap_review_authority,
                  resume=True), "single-invocation")
              and not cap_resume_calls
              and open(os.path.join(cap_out, CAMPAIGN_STATE), "rb").read()
              == cap_state_before_resume)

        # ------------------------------------------------ LI1 / LI3 / LI4 / LI5
        #
        # The ROOT lifecycle, the typed cooperative cancellation, and the
        # root/shard consistency gate.  Plan §5 "Lifecycle and identity";
        # review finding 9, whose failure was a clean SIGTERM at hour 15
        # writing terminal `failed` over shards that all said `interrupted`.
        _li_mutants, _li_restricted, _li_covering = population(
            manifest, by_mutant, passed)
        _li_gold_files = gold_side(gold_rows, passed)[0]

        # EXACTLY what `run_test_quality` computes for a native gold run, so
        # a resume fixture rebuilds the same root plan the campaign wrote —
        # a plan that differs anywhere is refused as another campaign, which
        # would make this a fixture bug wearing a lifecycle failure's name.
        _li_inputs = identity_inputs_for_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant)
        _li_inputs["gold_provenance_class"] = None

        def _plan_inputs():
            """The (mutants, files_by_side, restricted) triple `plan_jobs` takes."""
            return (_li_mutants,
                    {"candidate": passed, "gold": _li_gold_files},
                    _li_restricted)

        legal_root = {(None, "running"), ("running", "running"),
                      ("running", "complete"), ("running", "interrupted"),
                      ("running", "failed"), ("interrupted", "running")}
        root_states = (None, "running", "complete", "interrupted", "failed")
        root_accepted = set()
        for current in root_states:
            for target in ROOT_STATES:
                try:
                    validate_root_transition(current, target)
                    root_accepted.add((current, target))
                except TestQualityRefused:
                    pass
        check("LI1: every illegal ROOT campaign state transition refuses, "
              "and every legal one is admitted",
              root_accepted == legal_root,
              f"accepted {sorted(map(str, root_accepted - legal_root))}, "
              f"refused {sorted(map(str, legal_root - root_accepted))}")

        li1_out = os.path.join(d, "root-lifecycle")
        li1_jobs = plan_jobs(*_plan_inputs(), 1, li1_out,
                             identity_inputs=_li_inputs)
        li1_plan = build_test_quality_campaign_plan(
            li1_jobs, expected=expected_pairs(_li_restricted))
        prepare_output_directory(li1_out, li1_jobs, resume=False,
                                 campaign_plan=li1_plan)
        os.makedirs(os.path.join(li1_out, SHARD_DIR), exist_ok=True)
        for job in li1_jobs:
            with open(job["out"], "w", encoding="utf-8") as fh:
                fh.write("")
            _finish_fake_job(job, status="failed")
        transition_campaign_state(li1_out, li1_plan, "failed",
                                  error="a worker died")
        li1_state_bytes = open(_campaign_state_path(li1_out), "rb").read()
        check("LI1: the real root WRITER refuses to reopen a terminal "
              "campaign, so the table is not merely a table",
              raises(lambda: transition_campaign_state(
                  li1_out, li1_plan, "running"),
                  "cannot transition from 'failed' to 'running'"))
        check("LI1: ...and the refused root write leaves the record "
              "byte-identical",
              open(_campaign_state_path(li1_out), "rb").read()
              == li1_state_bytes)

        # LI7 -- A DEFAULT MAY NEVER BE INHERITED AS EVIDENCE.
        #
        # `identity_inputs_for_test_quality` has to answer for a candidate no
        # agent produced. It used to answer `native_v2` with a plausible
        # attempt id, so a real caller that omitted ONE generation key would
        # have inherited a fabricated attempt identity and published under
        # it. The default is now the self-disclosing `fixture` class, and the
        # two publication surfaces refuse it.
        defaulted = identity_inputs_for_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant)
        check("LI7: omitting the generation keys yields the self-disclosing "
              "`fixture` class, never a plausible `native_v2` identity",
              defaulted["generation_provenance_class"] == "fixture"
              and defaulted["generation_attempt_id"] is None
              and defaulted["generation_agent_runtime_sha256"] is None
              and defaulted["generation_network_semantics"] is None,
              str({k: defaulted[k] for k in sorted(
                  _MR.CAMPAIGN_IDENTITY_FIELDS_V2_ADDED)}))
        partial = identity_inputs_for_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=manifest, by_mutant=by_mutant,
            exact={key: value
                   for key, value in NATIVE_GENERATION_INPUTS.items()
                   if key != "generation_attempt_id"})
        partial_identity_refused = False
        try:
            _identity_for_job(partial, side="candidate", worker=0, of=1,
                              timeout=600, mutants=_li_mutants,
                              by_mutant=_li_restricted,
                              files_by_item=passed)
        except _MR.MutationAborted as e:
            partial_identity_refused = "must name the generation ATTEMPT" in \
                str(e)
        check("LI7: a caller that supplies eight of the nine generation keys "
              "cannot mint a valid native_v2 identity -- the missing one is "
              "refused, not defaulted",
              partial_identity_refused)
        fixture_identity = _identity_for_job(
            defaulted, side="candidate", worker=0, of=1, timeout=600,
            mutants=_li_mutants, by_mutant=_li_restricted,
            files_by_item=passed)
        check("LI7: a `fixture` identity is VALID (the unit tests build "
              "thousands) and carries nothing it does not have",
              fixture_identity["generation_provenance_class"] == "fixture"
              and fixture_identity["generation_attempt_id"] is None)
        dressed_refused = False
        try:
            _identity_for_job(
                dict(defaulted, generation_attempt_id="looks-real"),
                side="candidate", worker=0, of=1, timeout=600,
                mutants=_li_mutants, by_mutant=_li_restricted,
                files_by_item=passed)
        except _MR.MutationAborted as e:
            dressed_refused = "a fixture that claims any of the three" in str(e)
        check("LI7: ...and a fixture identity that claims an attempt id is "
              "refused, so it can never be mistaken for evidence",
              dressed_refused)
        check("LI7: the publication surfaces refuse the fixture class by "
              "name, so a defaulted identity can never become a number",
              raises(lambda: refuse_unpublishable_generation(
                  "fixture", "a fixture saved report"), "not publishable")
              and raises(lambda: refuse_unpublishable_generation(
                  None, "an unlabelled saved report"), "not publishable")
              and not raises(lambda: refuse_unpublishable_generation(
                  "native_v2", "a native report"))
              and not raises(lambda: refuse_unpublishable_generation(
                  "legacy_exact_bytes", "the Cell 3 candidate")))
        # THE DEVELOPMENT DOOR IS ONE DOOR.  `allow_development` is passed at
        # the saved-summary reader and nowhere else, so the default -- which
        # is what every other call site gets -- still refuses the class, and
        # the flag admits ONLY that class.
        check("the development class is refused by DEFAULT, so every call "
              "site that does not ask for it keeps refusing",
              raises(lambda: refuse_unpublishable_generation(
                  _MR.GENERATION_PROVENANCE_DEVELOPMENT,
                  "a development saved report"), "not publishable")
              and not raises(lambda: refuse_unpublishable_generation(
                  _MR.GENERATION_PROVENANCE_DEVELOPMENT,
                  "the reader", allow_development=True))
              and raises(lambda: refuse_unpublishable_generation(
                  "fixture", "a fixture saved report",
                  allow_development=True), "not publishable")
              and raises(lambda: refuse_unpublishable_generation(
                  None, "an unlabelled saved report",
                  allow_development=True), "not publishable"))

        # LI3 -- a cancel that lands INSIDE a worker, with a job still
        # pending.  This is the case the substring classifier could never
        # see: the slices raise `MutationCancelled`, `execute_jobs` wraps
        # them, and the phrase it matched on was never in the message.
        mid_worker_out = os.path.join(d, "mid-worker-cancel")
        mid_event = threading.Event()
        mid_seen: list = []

        def mid_worker_cancel(job):
            """Write a partial shard, then stop the way a signalled slice does."""
            mid_seen.append((job["side"], job["worker"]))
            os.makedirs(os.path.dirname(job["out"]), exist_ok=True)
            wrote = 0
            with open(job["out"], "a", encoding="utf-8") as fh:
                for mutant in job["mutants"][:1]:
                    for iid in job["by_mutant"][mutant["id"]]:
                        if iid not in job["files_by_item"]:
                            continue
                        fh.write(json.dumps(_stamped(job, {
                            "item_id": iid, "mutant_id": mutant["id"],
                            "file": mutant["file"],
                            "operator": mutant["operator"],
                            "outcome": "failed"}), sort_keys=True) + "\n")
                        wrote += 1
                        break
                    break
            _finish_fake_job(job, status="interrupted")
            mid_event.set()
            raise _MR.MutationCancelled(
                "mutation campaign cancelled between mutants")

        escaping: list = []
        try:
            run_test_quality(
                run_rows=run_rows, gold_baseline_rows=gold_rows,
                manifest=manifest, by_mutant=by_mutant,
                out_dir=mid_worker_out, execute=mid_worker_cancel,
                n_workers=1, cancel_event=mid_event)
        except TestQualityRefused as e:
            escaping.append(e)
        mid_state = json.load(open(
            os.path.join(mid_worker_out, CAMPAIGN_STATE), encoding="utf-8"))
        check("LI3: a cancel that lands INSIDE a worker escapes as the "
              "cooperative-cancellation TYPE, not as a message a classifier "
              "has to match",
              len(escaping) == 1
              and isinstance(escaping[0], TestQualityCancelled),
              str([type(e).__name__ for e in escaping]))
        check("LI3: ...and the root campaign records running -> interrupted, "
              "with no artifacts claimed",
              mid_state["status"] == "interrupted"
              and mid_state["history"] == ["running", "interrupted"]
              and mid_state["artifacts"] == {}
              and len(mid_seen) == 1, str(mid_state["history"]))
        mid_shard_states = sorted(
            (str(state) for _name, state in planned_shard_states(
                mid_worker_out, mid_state["plan"])))
        check("LI3: the shard that was mid-flight is attested `interrupted`, "
              "and the pending one was never started",
              mid_shard_states == ["None", "interrupted"],
              str(mid_shard_states))

        def _resume_root(out_dir_):
            """The exact (jobs, plan) pair `run_test_quality` would rebuild."""
            jobs_ = plan_jobs(*_plan_inputs(), 1, out_dir_,
                              identity_inputs=_li_inputs, resume=True)
            return jobs_, build_test_quality_campaign_plan(
                jobs_, expected=expected_pairs(_li_restricted),
                require_complete=True, gold_precomputed=False,
                worker_resources=[])

        resume_jobs, resume_plan = _resume_root(mid_worker_out)
        check("LI3: ...and the interrupted campaign REMAINS RESUMABLE -- the "
              "same output directory is accepted for --resume, which a "
              "`failed` root would have made impossible",
              not raises(lambda: prepare_output_directory(
                  mid_worker_out, resume_jobs, resume=True,
                  campaign_plan=resume_plan)))
        resumed_state = json.load(open(
            os.path.join(mid_worker_out, CAMPAIGN_STATE), encoding="utf-8"))
        check("LI3: resuming moves the root back to `running` along the one "
              "legal edge out of `interrupted`",
              resumed_state["status"] == "running"
              and resumed_state["history"] == ["running", "interrupted",
                                               "running"],
              str(resumed_state["history"]))

        # LI4 -- one real worker failure beside a sibling cancellation. The
        # fail-closed direction: a crash that also cancels its siblings is
        # still a crash.
        barrier = threading.Barrier(2, timeout=30)
        crash_event = threading.Event()

        def crash_beside_cancel(job):
            barrier.wait()
            if job["worker"] == 0:
                raise RuntimeError("container is gone")
            crash_event.wait(timeout=10)
            raise _MR.MutationCancelled(
                "mutation campaign cancelled between mutants")

        crash_jobs = plan_jobs(
            *_plan_inputs(), 2, os.path.join(d, "crash-plan"),
            identity_inputs=_li_inputs)
        crash_raised: list = []
        try:
            execute_jobs(crash_jobs, crash_beside_cancel,
                         cancel_event=crash_event)
        except TestQualityRefused as e:
            crash_raised.append(e)
        check("LI4: a real worker failure beside a sibling cancellation is "
              "NOT a cooperative cancellation -- it escapes as the plain "
              "refusal type",
              len(crash_raised) == 1
              and not isinstance(crash_raised[0], TestQualityCancelled)
              and "slice(s) failed" in str(crash_raised[0]),
              str([type(e).__name__ for e in crash_raised]))
        check("LI4: ...and both worker exceptions are named in the refusal, "
              "so the crash is not hidden by the cancellation",
              "RuntimeError: container is gone" in str(crash_raised[0])
              and "MutationCancelled" in str(crash_raised[0]))

        # Forked worker queues: every info returns through its pipe from a
        # process of its own, one per worker.
        import multiprocessing
        fork = multiprocessing.get_context("fork")
        proc_jobs = plan_jobs(
            *_plan_inputs(), 2, os.path.join(d, "proc-plan"),
            identity_inputs=_li_inputs)
        proc_infos = execute_jobs(
            proc_jobs, lambda job: {"pid": os.getpid(),
                                    "worker": job["worker"]},
            cancel_event=fork.Event(), processes=True)
        check("forked worker queues return every slice's info, each worker "
              "from its own process",
              len(proc_infos) == len(proc_jobs)
              and os.getpid() not in {i["pid"] for i in proc_infos}
              and len({i["pid"] for i in proc_infos})
              == len({j["worker"] for j in proc_jobs}),
              str(proc_infos))

        # `run_slice` raises `MutationCancelled` only once the shared stop is
        # set, so a sibling's cancellation always FOLLOWS the failure that
        # set it. This fake keeps that order, with both workers inside their
        # first job before anything fails: worker 1 cancels only when the
        # stop arrives, and worker 0 fails only once worker 1 is waiting for
        # it. A fake that cancels unprompted sets the stop itself, and
        # worker 0 may then rightly run nothing at all.
        proc_stop_on_crash = fork.Event()
        w1_inside = fork.Event()

        def proc_crash(job):
            if job["worker"] == 0:
                w1_inside.wait(timeout=60)
                raise RuntimeError("container is gone")
            w1_inside.set()
            proc_stop_on_crash.wait(timeout=60)
            raise _MR.MutationCancelled(
                "mutation campaign cancelled between mutants")

        def proc_crash_alone(job):
            if job["worker"] == 0:
                raise RuntimeError("container is gone")
            return {}

        for fake, beside, stop in (
                (proc_crash, True, proc_stop_on_crash),
                (proc_crash_alone, False, fork.Event())):
            proc_raised: list = []
            try:
                execute_jobs(proc_jobs, fake, cancel_event=stop,
                             processes=True)
            except TestQualityRefused as e:
                proc_raised.append(e)
            check("forked worker queues keep the fail-closed classification: "
                  "a real failure, "
                  + ("beside a sibling's cancellation" if beside else "alone")
                  + ", is a plain refusal that names it",
                  len(proc_raised) == 1
                  and not isinstance(proc_raised[0], TestQualityCancelled)
                  and "RuntimeError: container is gone" in str(proc_raised[0])
                  and ("MutationCancelled" in str(proc_raised[0])) == beside,
                  str(proc_raised))
        proc_stop = fork.Event()
        proc_stop.set()
        proc_cancelled: list = []
        try:
            execute_jobs(proc_jobs, lambda job: {}, cancel_event=proc_stop,
                         processes=True)
        except TestQualityCancelled as e:
            proc_cancelled.append(e)
        check("forked worker queues see a stop set in the parent and run "
              "nothing", len(proc_cancelled) == 1, str(proc_cancelled))
        proc_dead: list = []
        try:
            execute_jobs(proc_jobs, lambda job: os._exit(3),
                         cancel_event=fork.Event(), processes=True)
        except TestQualityRefused as e:
            proc_dead.append(e)
        check("a worker process that dies before reporting is a failure "
              "naming its exit status, never a silent short campaign",
              len(proc_dead) == 1 and "exited 3" in str(proc_dead[0]),
              str(proc_dead))
        crash_out = os.path.join(d, "crash-root")
        crash_event2 = threading.Event()
        barrier2 = threading.Barrier(2, timeout=30)

        def crash_beside_cancel2(job):
            barrier2.wait()
            if job["worker"] == 0:
                raise RuntimeError("container is gone")
            crash_event2.wait(timeout=10)
            _finish_fake_job(job, status="interrupted")
            raise _MR.MutationCancelled("cancelled between mutants")

        check("LI4: worker failure plus sibling cancellation makes the ROOT "
              "campaign terminally `failed`",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=manifest, by_mutant=by_mutant, out_dir=crash_out,
                  execute=crash_beside_cancel2, n_workers=2,
                  cancel_event=crash_event2), "slice(s) failed"))
        crash_state = json.load(open(
            os.path.join(crash_out, CAMPAIGN_STATE), encoding="utf-8"))
        check("LI4: ...and that terminal `failed` is written even though a "
              "sibling shard is attested `interrupted`, because the set is "
              "not uniformly interrupted",
              crash_state["status"] == "failed"
              and "interrupted" in [
                  state for _n, state in planned_shard_states(
                      crash_out, crash_state["plan"])],
              str(crash_state["status"]))

        # THE DISCRIMINATING CASE, and the reason the classifier reads a
        # TYPE: an exception whose TEXT contains the phrase the old
        # classifier matched on, raised by a worker that really failed. The
        # substring test calls this `interrupted` and offers the operator a
        # resume into a broken campaign; the type test calls it `failed`.
        impostor_out = os.path.join(d, "impostor-text")
        impostor_event = threading.Event()

        def impostor(job):
            impostor_event.set()
            raise RuntimeError(
                "the container was cooperatively cancelled by the host")

        check("LI4: a REAL failure whose message contains the words the old "
              "classifier matched on is still `failed`",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=manifest, by_mutant=by_mutant,
                  out_dir=impostor_out, execute=impostor, n_workers=1,
                  cancel_event=impostor_event), "slice(s) failed"))
        impostor_state = json.load(open(
            os.path.join(impostor_out, CAMPAIGN_STATE), encoding="utf-8"))
        check("LI4: ...and the root record says so -- the decision is the "
              "exception's TYPE, not a phrase anything can print",
              impostor_state["status"] == "failed"
              and impostor_state["history"] == ["running", "failed"],
              str(impostor_state["history"]))

        # LI5 -- the root/shard consistency gate itself, both ways.
        li5_out = os.path.join(d, "uniform-interrupted")
        li5_jobs = plan_jobs(*_plan_inputs(), 1, li5_out,
                             identity_inputs=_li_inputs)
        li5_plan = build_test_quality_campaign_plan(
            li5_jobs, expected=expected_pairs(_li_restricted))
        prepare_output_directory(li5_out, li5_jobs, resume=False,
                                 campaign_plan=li5_plan)
        os.makedirs(os.path.join(li5_out, SHARD_DIR), exist_ok=True)
        for job in li5_jobs:
            with open(job["out"], "w", encoding="utf-8") as fh:
                fh.write("")
            _finish_fake_job(job, status="interrupted")
        li5_state_before = open(
            _campaign_state_path(li5_out), "rb").read()
        check("LI5: a `failed` ROOT write over uniformly `interrupted` shard "
              "sidecars is refused, naming the resumable state it would have "
              "destroyed",
              raises(lambda: transition_campaign_state(
                  li5_out, li5_plan, "failed", error="a coordinator error"),
                  "planned shard(s) are attested `interrupted`"))
        check("LI5: ...and the refused write leaves the root record "
              "byte-identical",
              open(_campaign_state_path(li5_out), "rb").read()
              == li5_state_before)
        check("LI5: the CONSISTENT-state control passes: the same campaign "
              "records `interrupted` without complaint",
              not raises(lambda: transition_campaign_state(
                  li5_out, li5_plan, "interrupted",
                  error="cooperatively cancelled")))
        li5_failed_out = os.path.join(d, "one-failed-shard")
        li5_failed_jobs = plan_jobs(*_plan_inputs(), 2, li5_failed_out,
                                    identity_inputs=_li_inputs)
        li5_failed_plan = build_test_quality_campaign_plan(
            li5_failed_jobs, expected=expected_pairs(_li_restricted))
        prepare_output_directory(li5_failed_out, li5_failed_jobs,
                                 resume=False,
                                 campaign_plan=li5_failed_plan)
        os.makedirs(os.path.join(li5_failed_out, SHARD_DIR), exist_ok=True)
        for number, job in enumerate(li5_failed_jobs):
            with open(job["out"], "w", encoding="utf-8") as fh:
                fh.write("")
            _finish_fake_job(job, status=("failed" if number == 0
                                          else "interrupted"))
        check("LI5: the CONSISTENT-state control passes the other way too -- "
              "a `failed` root over a shard set that really holds a failure "
              "is written",
              not raises(lambda: transition_campaign_state(
                  li5_failed_out, li5_failed_plan, "failed",
                  error="a worker died")))
        li5_partial_out = os.path.join(d, "partial-complete")
        li5_partial_jobs = plan_jobs(*_plan_inputs(), 2, li5_partial_out,
                                     identity_inputs=_li_inputs)
        li5_partial_plan = build_test_quality_campaign_plan(
            li5_partial_jobs, expected=expected_pairs(_li_restricted))
        prepare_output_directory(li5_partial_out, li5_partial_jobs,
                                 resume=False,
                                 campaign_plan=li5_partial_plan)
        os.makedirs(os.path.join(li5_partial_out, SHARD_DIR), exist_ok=True)
        for number, job in enumerate(li5_partial_jobs):
            with open(job["out"], "w", encoding="utf-8") as fh:
                fh.write("")
            _finish_fake_job(job, status=("complete" if number else
                                          "interrupted"))
        check("LI5: a `complete` root over a shard that is not attested "
              "complete refuses, so the gate is not one-directional",
              raises(lambda: transition_campaign_state(
                  li5_partial_out, li5_partial_plan, "complete",
                  artifacts={name: "0" * 64 for name in
                             (CANDIDATE_ROWS, GOLD_ROWS, SUMMARY)}),
                  "not attested"))

    # ------------------------------------------------------- one engine only
    #
    # The refusal is on the ROWS, not on a flag, because that is where a mixed
    # population actually arrives: a `.jsonl` from the python stack appended to
    # a PHP one, or a resumed out file executed against the other manifest.
    php_man = dict(manifest, engine="r2t-mutate", engine_version="1.0")
    php_rows = [{"item_id": "i_full", "mutant_id": "m1", "outcome": "failed",
                 "engine": "r2t-mutate", "engine_version": "1.0"}]
    py_rows = [{"item_id": "i_full", "mutant_id": "m2", "outcome": "failed",
                "engine": "r2t-mutate-py", "engine_version": "1.0"}]
    old_rows = [{"item_id": "i_full", "mutant_id": "m1", "outcome": "failed"}]
    check("one engine's rows report that engine and count themselves",
          engine_report(php_man, php_rows) ==
          {"engine": "r2t-mutate", "engine_version": "1.0",
           "row_engines": {"r2t-mutate": 1}},
          str(engine_report(php_man, php_rows)))
    check("two engines in one summary are REFUSED, never macro-averaged",
          raises(lambda: engine_report(php_man, php_rows, py_rows),
                 "Recall is defined over ONE operator set"))
    check("rows from another engine than the manifest's are refused too -- "
          "the join would be a coincidence",
          raises(lambda: engine_report(php_man, py_rows), "wrong manifest"))
    check("rows written before the engine column are counted as unlabelled "
          "and attributed to the manifest, not invented",
          engine_report(php_man, old_rows)["row_engines"]
          == {UNLABELLED_ENGINE: 1}
          and engine_report(php_man, old_rows)["engine"] == "r2t-mutate")
    check("...and an archived gold file beside a freshly labelled candidate "
          "side still scores -- that is the --gold-results workflow",
          engine_report(php_man, php_rows, old_rows)["row_engines"]
          == {"r2t-mutate": 1, UNLABELLED_ENGINE: 1})
    with tempfile.TemporaryDirectory() as d:
        execute, _seen = fake_execute({"candidate": CAND_KILLS,
                                       "gold": GOLD_KILLS})
        summary = run_test_quality(
            run_rows=run_rows, gold_baseline_rows=gold_rows,
            manifest=php_man, by_mutant=by_mutant, out_dir=d,
            execute=execute, n_workers=2,
            provenance={"run": "fixture.jsonl"})
        check("the summary a published recall is read out of NAMES its engine",
              summary["engine"] == "r2t-mutate"
              and summary["engine_version"] == "1.0"
              and summary["row_engines"] == {"r2t-mutate": 12},
              str({k: summary.get(k) for k in
                   ("engine", "engine_version", "row_engines")}))
        check("a provenance claiming another engine is refused, not silently "
              "overwritten by the manifest's",
              raises(lambda: run_test_quality(
                  run_rows=run_rows, gold_baseline_rows=gold_rows,
                  manifest=php_man, by_mutant=by_mutant,
                  out_dir=os.path.join(d, "clash"), execute=execute,
                  n_workers=1, provenance={"engine": "r2t-mutate-py"}),
                  "would cite an engine that did not produce it"))

    # A gold baseline that did not pass makes its kills ineligible — the same
    # rule the corpus gate applies, reached through the same function.
    killed, ignored, infrastructure = gold_kill_sets(
        [{"item_id": "i_full", "mutant_id": "m1", "outcome": "failed"}],
        {"i_full": "container_error"}, ["i_full"])
    check("a gold kill on a gold item that did not pass is ignored (§3.10)",
          killed == {} and ignored == 1 and infrastructure == 0,
          f"{killed} {ignored} {infrastructure}")
    timeout_kills, _ignored, _infra = gold_kill_sets(
        [{"item_id": "i_full", "mutant_id": "m1", "outcome": "timeout"}],
        {"i_full": "passed"}, ["i_full"])
    check("gold's conditional timeout is a kill when its own baseline passed",
          timeout_kills == {"i_full": {"m1"}})
    check("an unknown gold outcome is refused instead of shrinking the "
          "reference denominator",
          raises(lambda: gold_kill_sets(
              [{"item_id": "i_full", "mutant_id": "m1",
                "outcome": "faild"}],
              {"i_full": "passed"}, ["i_full"]),
                 "unknown mutant-run outcome"))
    solo = score({"i_full": []}, {"i_full": ["m1"]}, {}, {"i_full": "failed"},
                 [{"item_id": "i_full", "mutant_id": "m1",
                   "outcome": "passed"}])
    check("an item gold was broken on is not_scorable for THAT reason",
          solo["per_item"]["i_full"]["verdict"] == NOT_SCORABLE
          and "baseline" in solo["per_item"]["i_full"]["not_scorable_reason"],
          str(solo["per_item"]["i_full"]))
    check("with nothing scorable the macro is None, never 0.0",
          solo["recall_macro"] is None and solo["n_scorable"] == 0)

    check("the verdict vocabulary is closed",
          {verdict_for(2, 1.0), verdict_for(2, 0.5), verdict_for(2, 0.0),
           verdict_for(0, None), verdict_for(2, None)} <= set(VERDICTS))

    # ------------------------------------------------- report.py arithmetic
    from . import report as R
    rows = [{"item_id": i, "outcome": "passed"} for i in
            ("i_full", "i_weak", "i_vac", "i_eqm", "i_nocov")]
    rows += [{"item_id": f"i_x{k}", "outcome": "failed"} for k in range(5)]
    tq = {"n_passed": 5, "n_scorable": 3, "recall_macro": 0.5,
          "verdicts": {EQUIVALENT: 1, WEAKER: 1, VACUOUS: 1, NOT_SCORABLE: 2},
          "per_item": {"i_full": {"verdict": EQUIVALENT},
                       "i_weak": {"verdict": WEAKER},
                       "i_vac": {"verdict": VACUOUS},
                       "i_eqm": {"verdict": NOT_SCORABLE},
                       "i_nocov": {"verdict": NOT_SCORABLE}}}
    nv = R.non_vacuous(rows, tq)
    check("pass_at_1 is passes over ITEMS, unchanged",
          nv["passed"] == 5 and nv["n"] == 10 and nv["pass_at_1"] == 0.5,
          str(nv))
    check("non_vacuous_pass_at_1 counts only equivalent_to_reference, over "
          "the SAME denominator",
          nv["non_vacuous_passes"] == 1 and nv["non_vacuous_pass_at_1"] == 0.1,
          str(nv))
    check("the unverified passes are counted, not folded into either number",
          nv["not_scorable"] == 2 and nv["weaker"] == 1 and nv["vacuous"] == 1)
    check("a run with no sidecar reports no non-vacuity claim",
          R.non_vacuous(rows, None) is None)
    stale = R.non_vacuous(rows[:-1] + [{"item_id": "i_new",
                                        "outcome": "passed"}], tq)
    check("a sidecar about DIFFERENT passes is marked stale, not published",
          stale["stale"] is True and stale["non_vacuous_pass_at_1"] is None,
          str(stale))
    check("a matching sidecar is not stale",
          nv["stale"] is False)

    # --------------------------------------------- the CLI's engine binding
    #
    # Everything above injects `execute` and so never crosses the seam where
    # the final review found the money-path blocker: `cmd_test_quality` built
    # the right harness under `--profile` but handed `run_slice` a hard-coded
    # PHP engine dir and no applier, so a docx cell staged `mutate.php` into a
    # container with no `php` and died at rc 127 — after the cell's spend.
    # These checks drive the REAL `cmd_test_quality` with only two things
    # faked, the harness construction and `run_slice` itself; the spy calls
    # the real `install_applier`, so what is asserted is the staged BYTES,
    # not a mock's opinion about them.
    import argparse as _argparse
    import types as _types

    from ..toolkit import algorand_bundle as _AB
    from . import cli as _cli
    from ..data import mutation_attestation as _MA
    from ..toolkit import mutation_py as _MP
    from . import mutation_run as _MR
    from . import worker as _W

    _CFG = CONFIG_DIR

    # ------------------------------------------- the SHARED asset resolver
    #
    # `test-quality` used to call `validate_campaign_asset_inputs` itself
    # while its two sibling verbs went through the shared resolver.  The
    # three are now one path, and the reason that is checkable rather than
    # merely readable is that the resolver's own peek must not change what
    # an unnamed report does: this verb's `--mutation-validation` is
    # optional, so the resolver is genuinely handed None, and the refusal
    # the operator sees has to stay the validator's own.
    _unnamed_direct = raises(
        lambda: _MA.validate_campaign_asset_inputs(
            None, manifest_path=None, map_path=None, release_path=None,
            require_release_ready=True),
        "a saved validation report path is required")
    _unnamed_wrapped = raises(
        lambda: _cli._validated_mutation_assets(
            _argparse.Namespace(mutation_validation=None, manifest=None,
                                map=None, release=None),
            paid_view_subset=False, compact_allowed=False),
        "a saved validation report path is required")
    check("an unnamed validation report refuses identically through the "
          "shared wrapper and through the validator it wraps",
          _unnamed_direct and _unnamed_wrapped)

    def _cli_fixture(d, engine, mutant_file):
        """One passed item, one mutant, one worker — as files, for the CLI."""
        man = {"digest": "d" * 64, "engine": engine, "engine_version": "1.0",
               "parser": "fixture", "operators": list(OPERATORS), "n": 1,
               "mutants": [{"id": "m1", "file": mutant_file,
                            "operator": "NegateConditional", "start_line": 3,
                            "start_col": 1, "original": "a < b",
                            "mutated": "a >= b"}]}
        paths = {"manifest": os.path.join(d, "mutants.json"),
                 "map": os.path.join(d, "map.json"),
                 "run": os.path.join(d, "run.jsonl"),
                 "gold_baseline": os.path.join(d, "gold.jsonl"),
                 "candidate_results": os.path.join(d, "mut_candidate.jsonl"),
                 "gold_results": os.path.join(d, "mut_gold.jsonl"),
                 "gold_results_attestation": os.path.join(
                     d, "legacy_consistency.json"),
                 "release": os.path.join(d, "items.jsonl"),
                 "worker": os.path.join(d, "w0.json"),
                 "workspace": os.path.join(d, "ws0"),
                 "out": os.path.join(d, "out")}
        os.makedirs(paths["workspace"], exist_ok=True)
        with open(paths["manifest"], "w", encoding="utf-8") as fh:
            json.dump(man, fh)
        with open(paths["map"], "w", encoding="utf-8") as fh:
            json.dump({"by_mutant": {"m1": ["i1"]}}, fh)
        # The candidate run and the GENERATION ATTEMPT that produced it.  The
        # real verb now refuses a candidate that cannot say which attempt it
        # came from (PR R3), so the fixture is what a v2-generated run looks
        # like: a `.campaign.json` sidecar holding the fingerprint, and rows
        # stamped with that fingerprint's digest.
        # FROZEN, not re-derived from `campaign.generation_fingerprint`:
        # this is the scorer's fixture, and what it needs is one agent
        # campaign document that stays byte-identical run to run.  Calling
        # the producer would make the fixture whatever the producer became,
        # so a change in the fingerprint schema would silently rewrite the
        # input this scorer is measured against instead of failing here.
        fingerprint = {
            "agent_runtime_sha256":
                "2747cc5640354d6b6299b797448bbce2237f9548ca3a673a"
                "7699df78fc8a982a",
            "agent_system": "openhands",
            "attempt_id": "fixture-cli-attempt-1",
            "campaign_id": "fixture-cli",
            "condition": "c3",
            "config_digest": "cfg0123456789ab",
            "container_image_digest": "sha256:" + "7" * 64,
            "coverage": False,
            "database_dump_digest": "5" * 64,
            "harness_commit": "a" * 40,
            "harness_source_sha256": "b" * 64,
            "harness_version": "fixture-harness-v1",
            "k_workers": 1,
            "model": "fixture-model",
            "network_semantics": "fixture_closed_channel",
            "protocol_digest": "bda1d9bcb1852e92",
            "protocol_version": 4,
            "schema": "r2t.generation-campaign/v2",
            "shard_rule": "sha1_item_id_mod_k",
            "trial_budget": 0,
            "workspace_seed_digest": "6" * 64,
        }
        fingerprint_digest = "f839d305179408ee"
        with open(paths["run"], "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i1", "outcome": "passed",
                                 "condition": "c3",
                                 "protocol_version": 4,
                                 "protocol_digest": "bda1d9bcb1852e92",
                                 "native_budget": {"max_iterations": 100},
                                 "campaign_digest": fingerprint_digest,
                                 "produced_files": [{"file_path": "t",
                                                     "code": "x"}]}) + "\n")
        with open(paths["run"] + ".campaign.json", "w",
                  encoding="utf-8") as fh:
            json.dump({"campaign": fingerprint,
                       "campaign_digest": fingerprint_digest,
                       "workers": [], "n": 1,
                       "rows_path": os.path.basename(paths["run"])},
                      fh, indent=1, sort_keys=True)
        with open(paths["gold_baseline"], "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i1", "outcome": "passed",
                                 "produced_files": [{"file_path": "g",
                                                     "code": "y"}]}) + "\n")
        with open(paths["gold_results"], "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i1", "mutant_id": "m1",
                                 "outcome": "failed", "file": mutant_file,
                                 "operator": "NegateConditional",
                                 "start_line": 3,
                                 "candidate_digest": _MR.candidate_digest({
                                     "i1": [{"file_path": "g",
                                              "code": "y"}]})[:16]}) + "\n")
        with open(paths["candidate_results"], "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i1", "mutant_id": "m1",
                                 "outcome": "failed", "file": mutant_file,
                                 "operator": "NegateConditional",
                                 "start_line": 3,
                                 "candidate_digest": _MR.candidate_digest({
                                     "i1": [{"file_path": "t",
                                              "code": "x"}]})[:16]}) + "\n")
        with open(paths["release"], "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i1"}) + "\n")
        needs_database = engine != "r2t-mutate-py"
        if needs_database:
            # The seed's generated classes, which a CoreShop (behat) route
            # reads as its derived-state baseline and refuses without.
            import io as _seed_io
            import tarfile as _tarfile
            with _tarfile.open(os.path.join(d, "workspace.tar"), "w") as tar:
                data = b"<?php // CoreShopProduct as seeded\n"
                info = _tarfile.TarInfo(
                    "var/classes/DataObject/CoreShopProduct.php")
                info.size = len(data)
                tar.addfile(info, _seed_io.BytesIO(data))
        with open(paths["worker"], "w", encoding="utf-8") as fh:
            worker_doc = {
                "index": 0, "workspace": paths["workspace"],
                "container": "c0",
                "schema": "s0" if needs_database else "",
                "credential": "u0" if needs_database else "",
                "env_file": os.path.join(d, "w0.env"),
                "workdir": "/work",
                "out_path": os.path.join(d, "unused.jsonl"),
                "artifacts_root": os.path.join(d, "unused-artifacts"),
            }
            json.dump(worker_doc, fh)
        # Mint a complete v3 authority -> pool -> binding -> runtime graph.
        # The CLI test mocks only the final live re-inspection leaf below, so
        # the real static and offline-publication validators consume these
        # exact files just as a new campaign does.
        from .. import docker_authority as _DA
        authority_doc = _DA._fixture_authority()
        authority_path = os.path.join(d, "docker-authority.json")
        _DA.write_evidence_no_clobber(authority_path, authority_doc)
        _loaded_authority, authority_ref = _DA.evidence_reference(
            authority_path, expected_schema=_DA.AUTHORITY_SCHEMA,
            validator=lambda value: _DA.validate_authority_document(
                value, current_source=False), label="fixture authority")
        worker = _W.WorkerSpec.from_json(worker_doc)
        network_name = "fixture-internal" if needs_database else None
        pool = _W.build_execution_pool(
            [worker], [paths["worker"]],
            database_container=("fixture-db" if needs_database else None),
            internal_network=network_name)
        network_id = "b" * 64
        attachment_name = network_name or "none"
        attachment = [{"name": attachment_name, "id": network_id}]
        container = {
            "name": worker.container, "id": "1" * 64,
            "image_id": "sha256:" + "7" * 64, "running": True,
            "host_network_mode": attachment_name,
            "network_attachments": attachment,
        }
        if needs_database:
            members = [{
                "role": "database", "worker_index": None,
                "name": "fixture-db", "id": "c" * 64,
                "image_id": "sha256:" + "d" * 64, "running": True,
                "host_network_mode": network_name,
                "network_attachments": attachment,
            }, {
                "role": "worker", "worker_index": 0, **container,
            }]
            members.sort(key=lambda row: (
                row["role"], -1 if row["worker_index"] is None
                else row["worker_index"], row["name"], row["id"]))
            network_policy = {
                "mode": "dedicated_internal", "name": network_name,
                "id": network_id, "driver": "bridge", "scope": "local",
                "internal": True, "ingress": False, "attachable": False,
                "expected_members": members,
                "observed_members": json.loads(json.dumps(members)),
            }
        else:
            network_policy = {
                "mode": "none", "name": "none", "id": network_id,
                "driver": "null", "scope": "local", "internal": False,
                "ingress": False, "attachable": False,
                "expected_members": [], "observed_members": [],
            }
        binding = {
            "schema": _DA.BINDING_SCHEMA,
            "captured_at_utc": "2026-08-06T00:00:00Z",
            "authority": authority_ref, "pool": pool, "worker_index": 0,
            "worker_spec_sha256": pool["workers"][0][
                "worker_spec_sha256"],
            "container": container, "network_policy": network_policy,
            "egress_probe": {"required": False, "status": "not_required",
                             "target": None, "evidence_sha256": None},
            "digest": "0" * 64,
        }
        binding["digest"] = _DA.semantic_digest(binding)
        _DA.validate_binding_document(binding)
        binding_path = _W.binding_attestation_path(paths["worker"])
        _DA.write_evidence_no_clobber(binding_path, binding)
        from .validate import HARNESS_VERSION as _FIXTURE_HARNESS_VERSION
        seed_identity = {
            "seed_dir": os.path.realpath(d),
            "seed_manifest_sha256": "3" * 64,
            "seed_key": "fixture-seed",
            "workspace_seed_digest": "6" * 64,
            "database_dump_digest": (
                "5" * 64 if needs_database else "no_database"),
            "needs_database": needs_database,
        }
        runtime_doc = _W.build_worker_runtime_attestation(
            worker, paths["worker"], seed_identity,
            _FIXTURE_HARNESS_VERSION, binding_path=binding_path)
        _DA.write_evidence_no_clobber(
            _W.runtime_attestation_path(paths["worker"]), runtime_doc)
        paths["_authority_doc"] = authority_doc
        paths["_authority_ref"] = authority_ref
        paths["_binding"] = binding
        candidate_files = {
            "i1": [{"file_path": "t", "code": "x"}]}
        gold_files = {"i1": [{"file_path": "g", "code": "y"}]}
        report = {
            "schema": MUTATION_VALIDATION_SCHEMA,
            "inputs": {
                key: {"path": os.path.abspath(paths[path_key]),
                      "sha256": _MR.sha256_file(paths[path_key])}
                for key, path_key in (
                    ("manifest", "manifest"), ("map", "map"),
                    ("release", "release"), ("candidate_run", "run"),
                    ("gold_baseline", "gold_baseline"),
                    ("candidate_results", "candidate_results"),
                    ("gold_results", "gold_results"))
            },
            "evidence": {
                "schema": LEGACY_CONSISTENCY_SCHEMA,
                "validation_class": "legacy_consistency",
                "native_provenance": False,
                "historical_manifest_digest_present": False,
                "manifest_digest": "d" * 64,
                "raw_manifest_digest": None,
                "candidate_digest": _MR.candidate_digest(
                    candidate_files)[:16],
                "gold_digest": _MR.candidate_digest(gold_files)[:16],
                "n_passed": 1,
                "n_expected_pairs": 1,
                "candidate": {"rows": 1, "pairs": 1,
                              "rows_with_manifest_digest": 0,
                              "absent_descriptor_fields": ["start_col"]},
                "gold": {"rows": 1, "pairs": 1,
                         "rows_with_manifest_digest": 0,
                         "absent_descriptor_fields": ["start_col"]},
                "limitations": ["fixture legacy evidence; no rows backfilled"],
            },
        }
        with open(paths["gold_results_attestation"], "w",
                  encoding="utf-8") as fh:
            json.dump(report, fh, indent=1, sort_keys=True)
        return paths

    def _cli_args(p, boundary, profile):
        return _argparse.Namespace(
            workers=[p["worker"]], manifest=p["manifest"], map=p["map"],
            mutation_validation=p["gold_results_attestation"],
            seed=os.path.dirname(p["worker"]),
            run=p["run"], gold_baseline=p["gold_baseline"],
            gold_results=None, release=p["release"],
            gold_results_attestation=None,
            out=p["out"], timeout=5, allow_incomplete=False,
            allow_degraded_gold=False, no_sidecar=False,
            boundary=os.path.join(_CFG, boundary),
            profile=(os.path.join(_CFG, profile) if profile else None),
            repo=p["workspace"], gold=os.path.dirname(p["worker"]),
            artifacts=os.path.dirname(p["worker"]), resume=False)

    # `--run` is the verb's only argparse-required option, but seven more are
    # structurally required by the live path and were declared `default=None`
    # for the Slice-3 join's sake.  Six of the seven used to reach `os.lstat`,
    # `os.path.join` or a `for` loop as `None` and end in a TypeError, and
    # `--mutation-validation` refused without naming itself; each must now
    # refuse naming the option it is missing.  `--development` is the live
    # path's other door, so this needs no capability, no fixture file and no
    # Docker -- the refusal fires before anything is read.
    def _omitting(*options):
        argv = {"run": "run.jsonl", "workers": ["worker.json"],
                "mutation_validation": "validation.json",
                "manifest": "manifest.json", "map": "map.json",
                "gold_baseline": "gold.jsonl", "seed": "seed",
                "out": "out", "development": True,
                "slice3_observations": None, "slice3_bundle": None}
        for option in options:
            argv[option[2:].replace("-", "_")] = None
        try:
            _cli.cmd_test_quality(_argparse.Namespace(**argv))
        except SystemExit as e:
            return (True if all(option in str(e) for option in options)
                    else f"refused as {e}")
        except BaseException as e:                          # noqa: BLE001
            return f"{type(e).__name__}: {e}"
        return "was not refused at all"

    structural = {option: _omitting(option) for option in (
        "--out", "--workers", "--mutation-validation", "--manifest", "--map",
        "--gold-baseline", "--seed")}
    check("every structurally required test-quality option refuses by name "
          "instead of reaching os.lstat/os.path.join as None",
          all(outcome is True for outcome in structural.values()),
          "; ".join(f"{option}: {outcome}"
                    for option, outcome in structural.items()
                    if outcome is not True))
    # And all of them in one refusal: the failure the runbook records is
    # having to relaunch once per omitted option.
    together = _omitting("--manifest", "--gold-baseline", "--out")
    check("test-quality names every missing structural option in a single "
          "refusal, not just the first one",
          together is True, str(together))

    # The same shape on the CONSUMER side, where it bites harder: `results`
    # and `report` have no asset options for `_reference_controls_reader` to
    # resolve the six sibling paths from, the way `cmd_test_quality` does, so
    # `--reference-controls X --reference-attestation Y` -- the exact form
    # that works for `test-quality` -- reached `os.lstat(None)` and came back
    # as a TypeError naming no option.
    def _omitting_reference(*options):
        argv = {"reference_controls": "tree",
                "reference_attestation": "attestation.json",
                "reference_validation": "validation.json",
                "reference_manifest": "manifest.json",
                "reference_map": "map.json",
                "reference_release": "release.jsonl",
                "reference_gold_baseline": "gold.jsonl"}
        for option in options:
            argv[option[2:].replace("-", "_")] = None
        # Only SystemExit is the subject here: with a complete set the reader
        # goes on to open the boundary, which a fixture namespace cannot
        # satisfy, and that is not a refusal.
        try:
            _cli._reference_controls_reader(_argparse.Namespace(**argv))
        except SystemExit as e:
            return (True if all(option in str(e) for option in options)
                    else f"refused as {e}")
        except BaseException:                               # noqa: BLE001
            return "not refused"
        return "not refused"

    reference_structural = {option: _omitting_reference(option) for option in (
        "--reference-attestation", "--reference-validation",
        "--reference-manifest", "--reference-map", "--reference-release",
        "--reference-gold-baseline")}
    check("every structurally required consumer reference option refuses by "
          "name instead of reaching os.lstat as None",
          all(outcome is True for outcome in reference_structural.values()),
          "; ".join(f"{option}: {outcome}"
                    for option, outcome in reference_structural.items()
                    if outcome is not True))
    reference_together = _omitting_reference(
        "--reference-map", "--reference-release", "--reference-gold-baseline")
    check("the consumer names every missing reference option in a single "
          "refusal, and a complete set is not refused at all",
          reference_together is True
          and _omitting_reference() == "not refused",
          str(reference_together) + " / complete set: "
          + str(_omitting_reference()))

    legacy_reader_checks: list[bool] = []
    # Every `paid_view_subset`/`compact_allowed` binding this verb asked the
    # shared resolver for, across every campaign driven below.
    resolver_bindings: list[dict] = []
    compact_probe: list[str] = []

    def _drive(p, boundary, profile):
        """Run the real verb; spy on `run_slice`, stage for real."""
        calls: list = []

        def validated_fixture_assets(_report_path, *, manifest_path,
                                     map_path, release_path,
                                     require_release_ready=True,
                                     paid_view_subset=False,
                                     budgeted_sidecar=None):
            del release_path, require_release_ready, paid_view_subset
            # This stand-in reads the map it is handed and nothing else, so
            # it cannot admit a derived one; a budgeted campaign driven
            # through it must fail loudly rather than run the parent.
            assert budgeted_sidecar is None, budgeted_sidecar
            with open(manifest_path, encoding="utf-8") as fh:
                fixture_manifest = json.load(fh)
            with open(map_path, encoding="utf-8") as fh:
                fixture_map = json.load(fh)
            return {
                "validation_class": "native",
                "validation_sha256": _MR.sha256_file(_report_path),
                "asset_index_sha256": "8" * 64,
                "asset_project": "fixture",
                "n_non_production_excluded": 0,
                "manifest": fixture_manifest,
                "map": fixture_map,
                "release_items": 1,
            }

        def spy(h, mutants_, items_by_id, files_by_item, by_mutant_,
                engine_dir, out_path, **kw):
            calls.append({"engine_dir": engine_dir,
                          "applier": kw.get("applier", _MR.PHP_APPLIER),
                          "engine": kw.get("engine"),
                          "derived_baseline": dict(
                              getattr(h, "derived_baseline", None) or {})})
            _MR.install_applier(h, engine_dir,
                                kw.get("applier", _MR.PHP_APPLIER))
            os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".",
                        exist_ok=True)
            n = 0
            with open(out_path, "a", encoding="utf-8") as fh:
                for m in mutants_:
                    for iid in by_mutant_.get(m["id"], []):
                        if iid not in files_by_item:
                            continue
                        fh.write(json.dumps(_stamped(
                            {"identity": kw["identity"]}, {
                            "item_id": iid, "mutant_id": m["id"],
                            "file": m["file"], "operator": m["operator"],
                            "outcome": "failed"})) + "\n")
                        n += 1
            from .mutation_run import write_shard_provenance
            write_shard_provenance(
                out_path, kw["identity"], "running",
                provenance=kw.get("provenance"))
            write_shard_provenance(
                out_path, kw["identity"], "complete",
                provenance=kw.get("provenance"))
            return {"out": out_path, "rows": n}

        real_harness, real_run_slice = _cli._harness, _MR.run_slice
        real_assets = _MA.validate_campaign_asset_inputs
        # Not a stub: it records the binding and then calls the real shared
        # resolver, so what is asserted is what the verb actually asked for.
        real_resolver = _cli._validated_mutation_assets

        def recording_resolver(namespace, **binding):
            resolver_bindings.append(dict(binding))
            return real_resolver(namespace, **binding)

        real_preflight = _W.preflight
        real_capture = _W.capture_execution_bindings
        real_seed_identity = _W.verified_seed_identity
        real_live_refusal = _cli._refuse_unbound_live_workload
        from ..core import docker_cli as _DC
        try:
            # The public command is intentionally closed until its complete
            # execution/result publication binding is specified.  Keep this
            # source-only assembly regression useful without adding a runtime
            # escape hatch: the test locally removes only that front-door
            # refusal, while every Docker leaf remains mocked below.
            _cli._refuse_unbound_live_workload = lambda *_a, **_kw: None
            _cli._harness = lambda a: (
                _types.SimpleNamespace(
                    root=a.repo, substrate_baseline_sha256="b" * 64),
                None, None)
            _MR.run_slice = spy
            _MA.validate_campaign_asset_inputs = validated_fixture_assets
            _cli._validated_mutation_assets = recording_resolver
            _W.preflight = lambda *a, **kw: {"workers": len(a[0])}
            _W.verified_seed_identity = (
                lambda _seed, needs_database: {
                    "seed_dir": os.path.realpath(_seed),
                    "seed_manifest_sha256": "3" * 64,
                    "seed_key": "fixture-seed",
                    "workspace_seed_digest": "6" * 64,
                    "database_dump_digest": (
                        "5" * 64 if needs_database else "no_database"),
                    "needs_database": needs_database})
            _DC._install_test_authority(
                p["_authority_doc"], p["_authority_ref"])
            _W.capture_execution_bindings = (
                lambda pool, authority_ref, docker_group=True: [
                    json.loads(json.dumps(p["_binding"]))])
            rc = _cli.cmd_test_quality(_cli_args(p, boundary, profile))
            # The compact Slice-3 authority is now REACHABLE from this verb,
            # and refused for the stated reason rather than dying inside the
            # native report loader.  No campaign is produced: the refusal
            # lands before a single worker is planned.
            if not compact_probe:
                compact_path = os.path.join(
                    os.path.dirname(p["run"]), "compact-authority.json")
                with open(compact_path, "w", encoding="utf-8") as fh:
                    json.dump({"schema": _AB.MUTATION_SCHEMA}, fh)
                compact_args = _cli_args(p, boundary, profile)
                compact_args.mutation_validation = compact_path
                compact_args.no_sidecar = True
                compact_args.out = p["out"] + "-compact"
                try:
                    _cli.cmd_test_quality(compact_args)
                    compact_probe.append("the compact authority was ADMITTED")
                except SystemExit as e:
                    compact_probe.append(str(e))
                check("a compact Algorand authority handed to test-quality "
                      "is refused by the shared Slice-3 rule, exactly as "
                      "mutation-run refuses it",
                      "compact Algorand mutation authority" in
                      compact_probe[0]
                      and not os.path.exists(
                          os.path.join(compact_args.out, CAMPAIGN_STATE)),
                      compact_probe[0])
            native_loaded = load_bound_test_quality(p["run"])
            # A current summary is rewritable evidence, so absence cannot be
            # grandfathered as if it were a preserved pre-registry artifact.
            # Rewrite the canonical twin too: this reaches the population
            # binding itself instead of passing only because the two copies
            # differ.
            canonical_summary_path = os.path.join(p["out"], SUMMARY)
            canonical_summary_bytes = open(
                canonical_summary_path, "rb").read()
            without_population = dict(native_loaded)
            without_population.pop("population_id", None)
            with open(canonical_summary_path, "w", encoding="utf-8") as fh:
                json.dump(without_population, fh, indent=1, sort_keys=True)
                fh.write("\n")
            real_registered_population_id = globals()[
                "registered_population_id"]
            globals()["registered_population_id"] = (
                lambda *_args, **_kwargs: "fixture-population-v1")
            try:
                _validate_native_summary(
                    without_population, find_sidecar(p["run"]), p["run"])
                missing_population_refused = False
            except TestQualityRefused as e:
                missing_population_refused = (
                    "must claim population_id" in str(e))
            finally:
                globals()["registered_population_id"] = (
                    real_registered_population_id)
                with open(canonical_summary_path, "wb") as fh:
                    fh.write(canonical_summary_bytes)
            check("a self-consistent rewrite cannot delete population_id "
                  "from a current registered native summary",
                  missing_population_refused)
            # Likewise a sensitivity label the run rows do not carry.
            with_label = dict(native_loaded, sensitivity="webmock_world_v1")
            with open(canonical_summary_path, "w", encoding="utf-8") as fh:
                json.dump(with_label, fh, indent=1, sort_keys=True)
                fh.write("\n")
            try:
                label_refused = raises(lambda: _validate_native_summary(
                    with_label, find_sidecar(p["run"]), p["run"]),
                    "sensitivity label")
            finally:
                with open(canonical_summary_path, "wb") as fh:
                    fh.write(canonical_summary_bytes)
            check("a native summary cannot claim a sensitivity label its run "
                  "rows do not carry", label_refused)
            staged_calls = list(calls)
            native_state = _load_json_object(
                os.path.join(p["out"], CAMPAIGN_STATE),
                "native fixture root campaign record")
            native_shard_side = os.path.join(
                p["out"], native_state["plan"]["jobs"][0]["out"])
            native_shard_side += ".provenance.json"
            native_shard_bytes = open(native_shard_side, "rb").read()
            native_shard_doc = _load_json_object(
                native_shard_side, "native fixture shard provenance")
            native_shard_doc["shard_policy"] = SHARD_POLICY_STRIDED_V1
            with open(native_shard_side, "w", encoding="utf-8") as fh:
                json.dump(native_shard_doc, fh, indent=1, sort_keys=True)
            forged_native_shard_bytes = open(native_shard_side, "rb").read()
            check("P1 publication regression: an LPT root cannot publish a "
                  "shard sidecar relabelled as strided",
                  raises(lambda: load_bound_test_quality(p["run"]),
                         "policy-bound campaign identity"))
            check("P1 publication regression: refusal leaves the forged "
                  "sidecar byte-identical",
                  open(native_shard_side, "rb").read()
                  == forged_native_shard_bytes)
            with open(native_shard_side, "wb") as fh:
                fh.write(native_shard_bytes)

            # Build a GENUINE historical representation rather than merely
            # relabelling this one-worker LPT root.  The public resolver is
            # patched only inside this selftest because fresh striding is
            # correctly unavailable to users; the rest is the real CLI
            # producer, so root plan, identities, rows and shard provenance
            # all say what a v1 artifact historically said.
            if not legacy_reader_checks:
                import shutil as _legacy_shutil
                legacy_run = os.path.join(
                    os.path.dirname(p["run"]), "historical-v1-run.jsonl")
                legacy_out = os.path.join(
                    os.path.dirname(p["out"]), "historical-v1-out")
                _legacy_shutil.copyfile(p["run"], legacy_run)
                native_generation = _MR.generation_evidence_for_run(
                    p["run"], load_jsonl(p["run"]))
                from . import test_quality as _TQ_module
                real_policy_resolver = _TQ_module.resolve_cli_shard_policy
                real_generation_for_run = _MR.generation_evidence_for_run
                legacy_reader_result: object = False
                try:
                    _TQ_module.resolve_cli_shard_policy = (
                        lambda *_a, **_kw: SHARD_POLICY_STRIDED_V1)
                    _MR.generation_evidence_for_run = (
                        lambda *_a, **_kw: dict(native_generation))
                    legacy_args = _cli_args(p, boundary, profile)
                    legacy_args.run = legacy_run
                    legacy_args.out = legacy_out
                    _cli.cmd_test_quality(legacy_args)
                    legacy_loaded = load_bound_test_quality(legacy_run)
                    state_doc = _load_json_object(
                        os.path.join(legacy_out, CAMPAIGN_STATE),
                        "historical fixture root campaign record")
                    shard_docs = [
                        _load_json_object(
                            os.path.join(legacy_out, record["out"])
                            + ".provenance.json",
                            "historical fixture shard provenance")
                        for record in state_doc["plan"]["jobs"]
                    ]
                    shard_paths = [
                        os.path.join(legacy_out, record["out"])
                        + ".provenance.json"
                        for record in state_doc["plan"]["jobs"]
                    ]
                    legacy_reader_result = {
                        "loaded_schema": legacy_loaded.get("schema"),
                        "loaded_policy": legacy_loaded.get("shard_policy"),
                        "plan_schema": state_doc["plan"]["schema"],
                        "plan_has_policy": (
                            "shard_policy" in state_doc["plan"]),
                        "shard_policies": [doc.get("shard_policy")
                                           for doc in shard_docs],
                        "identity_has_policy": [
                            "shard_policy" in doc["campaign_identity"]
                            for doc in shard_docs],
                    }
                    legacy_reader_result = (
                        legacy_reader_result
                        if not (
                            legacy_reader_result["loaded_schema"]
                            == TEST_QUALITY_SUMMARY_SCHEMA
                            and legacy_reader_result["loaded_policy"]
                            == SHARD_POLICY_STRIDED_V1
                            and legacy_reader_result["plan_schema"]
                            == TEST_QUALITY_PLAN_SCHEMA_V1
                            and not legacy_reader_result["plan_has_policy"]
                            and set(legacy_reader_result["shard_policies"])
                            == {SHARD_POLICY_STRIDED_V1}
                            and not any(legacy_reader_result[
                                "identity_has_policy"]))
                        else True)
                    saved_historical_sidecars = {
                        path: open(path, "rb").read()
                        for path in shard_paths
                    }
                    for path, doc in zip(shard_paths, shard_docs):
                        absent_doc = dict(doc)
                        absent_doc.pop("shard_policy")
                        with open(path, "w", encoding="utf-8") as fh:
                            json.dump(absent_doc, fh, indent=1,
                                      sort_keys=True)
                    check("historical v1 publication accepts sidecars whose "
                          "pre-disclosure policy field is absent",
                          load_bound_test_quality(legacy_run).get("schema")
                          == TEST_QUALITY_SUMMARY_SCHEMA)
                    invalid_publication_policies = []
                    first_path = shard_paths[0]
                    first_absent = _load_json_object(
                        first_path, "absent-policy historical shard")
                    for invalid_policy in (
                            SHARD_POLICY_BALANCED_PAIRS_V1,
                            "post-hoc-fastest"):
                        with open(first_path, "w", encoding="utf-8") as fh:
                            json.dump(dict(first_absent,
                                           shard_policy=invalid_policy),
                                      fh, indent=1, sort_keys=True)
                        invalid_publication_policies.append(
                            raises(lambda: load_bound_test_quality(legacy_run),
                                   "root campaign policy"))
                    check("historical v1 publication refuses every present "
                          "sidecar policy except strided",
                          all(invalid_publication_policies))
                    for path, payload in saved_historical_sidecars.items():
                        with open(path, "wb") as fh:
                            fh.write(payload)
                except BaseException as e:                  # the regression
                    legacy_reader_result = f"{type(e).__name__}: {e}"
                finally:
                    _TQ_module.resolve_cli_shard_policy = (
                        real_policy_resolver)
                    _MR.generation_evidence_for_run = real_generation_for_run
                check("a historical native v1 plan remains publishable: the "
                      "reader reconstructs striding rather than LPT",
                      legacy_reader_result is True,
                      str(legacy_reader_result))
                legacy_reader_checks.append(
                    legacy_reader_result is True)

            # ------------------- LOOP-BACK (R3 review P2-1), surface ONE
            #
            # The saved native summary a `report`/`results` reader loads.
            # Driven end to end through the real CLI verb and the real
            # reader, over a campaign whose generation half is consistently
            # `fixture` -- the candidate's own evidence resolver is replaced
            # at source, so the summary, its shards and every row stamp agree
            # with each other and only the publication surface can stop them.
            # `cmd_test_quality` refuses to overwrite an existing sidecar, so
            # this runs against a copy of the run and its campaign sidecar.
            import shutil as _shutil
            # Snapshotted BEFORE the second campaign, under its OWN name:
            # the fake harness closure resolves `calls` from this scope at
            # call time, so rebinding the same name would hand it the copy and
            # the second campaign's staged appliers would land in it anyway.
            alt_run = os.path.join(os.path.dirname(p["run"]),
                                   "fixture-class-run.jsonl")
            _shutil.copyfile(p["run"], alt_run)
            _shutil.copyfile(p["run"] + ".campaign.json",
                             alt_run + ".campaign.json")
            real_generation = _MR.generation_evidence_for_run
            _MR.generation_evidence_for_run = (
                lambda *_a, **_kw: dict(FIXTURE_GENERATION_INPUTS))
            try:
                alt_args = _cli_args(p, boundary, profile)
                alt_args.run = alt_run
                alt_args.out = p["out"] + "-fixture-class"
                _cli.cmd_test_quality(alt_args)
                try:
                    load_bound_test_quality(alt_run)
                    fixture_class_read_refused = "the reader accepted it"
                except TestQualityRefused as e:
                    fixture_class_read_refused = str(e)
            except (SystemExit, TestQualityRefused) as e:
                fixture_class_read_refused = f"campaign refused first: {e}"
            finally:
                _MR.generation_evidence_for_run = real_generation
            # A seed manifest is more than the workspace/database payloads:
            # its key and policy say which seed those bytes constitute.  A
            # manifest-only change must therefore invalidate the
            # provision-time attestations even when both artifact digests
            # remain byte-identical.
            _W.verified_seed_identity = (
                lambda _seed, needs_database: {
                    "seed_dir": os.path.realpath(_seed),
                    "seed_manifest_sha256": "4" * 64,
                    "seed_key": "fixture-seed",
                    "workspace_seed_digest": "6" * 64,
                    "database_dump_digest": (
                        "5" * 64 if needs_database else "no_database"),
                    "needs_database": needs_database})
            try:
                load_bound_test_quality(p["run"])
                seed_manifest_tamper_refused = False
            except TestQualityRefused as e:
                seed_manifest_tamper_refused = (
                    "runtime evidence" in str(e))
            # PC10, third leg: the REAL seed identity function against a
            # directory that holds no seed manifest -- the exact state an
            # operator who relocated `seed/` after a campaign leaves behind.
            # `seed.SeedRefused` is a bare RuntimeError, so before it was
            # normalised this call left the publication boundary as an
            # unhandled traceback (review finding 24).
            _W.verified_seed_identity = real_seed_identity
            try:
                load_bound_test_quality(p["run"])
                absent_seed_refused = "no refusal at all"
            except TestQualityRefused as e:
                absent_seed_refused = ("no seed at" in str(e)) or str(e)
            except BaseException as e:  # the defect, if it comes back
                absent_seed_refused = f"{type(e).__name__}: {e}"
        finally:
            _cli._harness, _MR.run_slice = real_harness, real_run_slice
            _cli._refuse_unbound_live_workload = real_live_refusal
            _cli._validated_mutation_assets = real_resolver
            _MA.validate_campaign_asset_inputs = real_assets
            _W.preflight = real_preflight
            _W.capture_execution_bindings = real_capture
            _W.verified_seed_identity = real_seed_identity
            _DC.configure()
        return (rc, staged_calls, native_loaded,
                seed_manifest_tamper_refused, absent_seed_refused,
                fixture_class_read_refused)

    with tempfile.TemporaryDirectory() as d:
        p = _cli_fixture(d, "r2t-mutate",
                         "src/CoreShop/Component/Order/Model/Order.php")
        legacy_path = sidecar_paths(p["run"])[0]
        legacy_summary = {"preserved": "legacy bytes", "n_passed": 1}
        with open(legacy_path, "w", encoding="utf-8") as fh:
            json.dump(legacy_summary, fh, indent=1, sort_keys=True)
        source_before = open(legacy_path, "rb").read()
        wrapper_dir = d
        chain = {
            "schema": LEGACY_REBINDING_SCHEMA,
            # Relative, under the wrapper's own `path_base` (R4 item 9's
            # design rule): a committed sidecar that binds absolute paths is
            # bound to the machine that wrote it.
            "source_sidecar": os.path.relpath(legacy_path, wrapper_dir),
            "source_sidecar_sha256": _MR.sha256_file(legacy_path),
            "validation_report": os.path.relpath(
                p["gold_results_attestation"], wrapper_dir),
            "validation_report_sha256": _MR.sha256_file(
                p["gold_results_attestation"]),
            "validation_schema": MUTATION_VALIDATION_SCHEMA,
            "validation_class": "legacy_consistency",
            "native_provenance": False,
        }
        rebuilt = {
            "schema": TEST_QUALITY_SUMMARY_SCHEMA,
            "binding": run_binding(p["run"]),
            "gold_provenance_class": "legacy_consistency",
            "path_base": {"kind": WRAPPER_PATH_BASE_KIND,
                          "relative_to_wrapper": "."},
            "per_item": {"i1": {"verdict": EQUIVALENT}},
            "legacy_rebinding": chain,
        }
        real_builder = globals()["_build_legacy_wrapper"]
        build_calls = []

        def checked_builder(run, source, report, *, wrapper_path,
                            allow_degraded_gold=False):
            build_calls.append((run, source, report, wrapper_path,
                                allow_degraded_gold))
            return rebuilt

        globals()["_build_legacy_wrapper"] = checked_builder
        wrapper_path = os.path.join(d, "legacy.bound.json")
        try:
            wrapper = rebind_legacy_test_quality(
                p["run"], legacy_path, p["gold_results_attestation"],
                wrapper_path)
            check("legacy consistency creates a separate current binding "
                  "without modifying the historical sidecar",
                  wrapper["gold_provenance_class"] == "legacy_consistency"
                  and open(legacy_path, "rb").read() == source_before
                  and os.path.isfile(wrapper_path) and build_calls)
            check("the central loader accepts an explicit wrapper only "
                  "through its exact preserved-sidecar chain",
                  load_bound_test_quality(p["run"], wrapper_path) == wrapper)
            # Two spellings of ONE file.  The J3 ceremony builds the wrapper
            # from `/data2` arguments and then arms a pin that derives its run
            # path from `R2T_DATA_ROOT`, whose `projects/<project>` is a
            # symlink onto the same tree; the chain's `source_sidecar` and the
            # discovered sidecar are then the same bytes under two names.
            linked_root = os.path.join(d, "via-data-root-symlink")
            os.symlink(os.path.dirname(p["run"]), linked_root)
            linked_run = os.path.join(linked_root,
                                      os.path.basename(p["run"]))
            try:
                linked_loaded: object = load_bound_test_quality(
                    linked_run, wrapper_path)
            except TestQualityRefused as e:                 # the defect
                linked_loaded = f"REFUSED: {e}"
            check("a wrapper validates when the run path reaches the SAME "
                  "preserved sidecar through a symlinked data root",
                  linked_loaded == wrapper, str(linked_loaded))
            authenticated_wrapper = load_bound_test_quality(
                p["run"], wrapper_path)
            check("only the in-memory re-derived legacy wrapper may retain an "
                  "absent verdict basis; persisted shape alone is withheld",
                  not any("verdict_basis is absent" in reason
                          for reason in publication_ready(
                              authenticated_wrapper)[1])
                  and any("verdict_basis is absent" in reason
                          for reason in publication_ready(wrapper)[1]))
            forged_path = os.path.join(d, "forged.bound.json")
            forged = {**wrapper,
                      "per_item": {"i1": {"verdict": VACUOUS}}}
            with open(forged_path, "w", encoding="utf-8") as fh:
                json.dump(forged, fh, indent=1, sort_keys=True)
            check("a wrapper cannot forge a score while merely retaining "
                  "valid reference hashes",
                  raises(lambda: load_bound_test_quality(
                      p["run"], forged_path), "differs from the summary"))
            unchained_path = os.path.join(d, "unchained.json")
            with open(unchained_path, "w", encoding="utf-8") as fh:
                json.dump({k: v for k, v in wrapper.items()
                           if k != "legacy_rebinding"}, fh)
            check("an explicit bound summary that conflicts with a "
                  "discovered legacy sidecar is refused without a rebind "
                  "chain", raises(lambda: load_bound_test_quality(
                      p["run"], unchained_path),
                      "conflicts with discovered"))
            with open(legacy_path, "ab") as fh:
                fh.write(b"\n")
            check("changing preserved legacy sidecar bytes invalidates the "
                  "wrapper", raises(lambda: load_bound_test_quality(
                      p["run"], wrapper_path),
                      "source legacy sidecar changed"))

            # The wrapper-completion spec's third scenario: a pinned-path
            # disagreement with the published table refuses INSIDE the
            # builder, so `rebind_legacy_test_quality` never reaches its
            # write.  The real §5 control raises through the swap harness.
            disagreeing_path = os.path.join(d, "disagreeing.bound.json")

            def disagreeing_builder(run, source, report, *, wrapper_path,
                                    allow_degraded_gold=False):
                reconcile_pinned_jaccard_cell(0.912)
                return rebuilt                          # pragma: no cover

            globals()["_build_legacy_wrapper"] = disagreeing_builder
            check("a pinned-path table disagreement refuses without writing "
                  "a wrapper",
                  raises(lambda: rebind_legacy_test_quality(
                      p["run"], legacy_path, p["gold_results_attestation"],
                      disagreeing_path), "renders as 0.912")
                  and not os.path.lexists(disagreeing_path))
        finally:
            globals()["_build_legacy_wrapper"] = real_builder

    with tempfile.TemporaryDirectory() as d:
        # `_build_legacy_wrapper`'s own sidecar-identity gate, driven
        # directly.  The builder needs a whole PR-2 evidence tree to get past
        # its SECOND step, so each check below asserts WHICH refusal it
        # reaches -- the identity gate, or the step immediately after it.
        real_runs = os.path.join(d, "real", "runs")
        os.makedirs(real_runs)
        real_run = os.path.join(real_runs, "eval.jsonl")
        with open(real_run, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "coreshop/f.feature:1",
                                 "outcome": "passed"}) + "\n")
        preserved = sidecar_paths(real_run)[0]
        with open(preserved, "w", encoding="utf-8") as fh:
            # Carries a `binding`, so the step AFTER the identity gate refuses
            # in its own distinct words and the two cannot be confused.
            json.dump({"preserved": "legacy bytes", "binding": {}}, fh)
        os.symlink(os.path.join(d, "real"), os.path.join(d, "data-root"))
        linked_run = os.path.join(d, "data-root", "runs", "eval.jsonl")
        missing_report = os.path.join(d, "no-such-validation-report.json")
        wrapper_out = os.path.join(d, "eval.tq_wrapper.json")
        check("the preserved sidecar is identified by FILE and not by "
              "spelling: a run reached through a symlinked data root matches "
              "the same sidecar named at its real path",
              raises(lambda: _build_legacy_wrapper(
                  linked_run, preserved, missing_report,
                  wrapper_path=wrapper_out), "already carries a binding"))
        decoy_runs = os.path.join(d, "decoy", "runs")
        os.makedirs(decoy_runs)
        with open(os.path.join(decoy_runs, os.path.basename(preserved)),
                  "w", encoding="utf-8") as fh:
            json.dump({"preserved": "different bytes"}, fh)
        os.symlink(os.path.join(d, "decoy"), os.path.join(d, "decoy-root"))
        check("...and a DIFFERENT real file at an equivalent-looking path is "
              "still refused as not the unique preserved sidecar",
              raises(lambda: _build_legacy_wrapper(
                  linked_run,
                  os.path.join(d, "decoy-root", "runs",
                               os.path.basename(preserved)),
                  missing_report, wrapper_path=wrapper_out),
                  "is not the unique preserved sidecar"))

    with tempfile.TemporaryDirectory() as d:
        # A docx-shaped invocation: python manifest, python profile.
        p = _cli_fixture(d, "r2t-mutate-py", "src/docx/api.py")
        (rc, calls, native_loaded, seed_manifest_tamper_refused,
         absent_seed_refused, fixture_class_read_refused) = _drive(
             p, "boundary_python_docx.yml", "profile_python_docx.yml")
        check("test-quality resolves its mutation assets through the SAME "
              "shared resolver mutation-run and recall use -- one code "
              "path, not two",
              rc == 0 and bool(resolver_bindings), str(resolver_bindings))
        check("a docx-shaped test-quality binds the PYTHON engine off the "
              "manifest, exactly as mutation-run does",
              rc == 0 and len(calls) == 2
              and all(call["engine_dir"] == _MP.PY_ENGINE_DIR
                      and call["applier"] == _MP.applier()
                      and call["engine"] == "r2t-mutate-py"
                      for call in calls),
              str(calls))
        staged = os.path.join(p["workspace"], "var/bench_mutate/mutate.py")
        with open(os.path.join(_MP.PY_ENGINE_DIR, "mutate.py"), "rb") as fh:
            want = fh.read()
        check("...and what it stages into the workspace IS the python "
              "applier, byte for byte, at the python rel path",
              os.path.isfile(staged) and open(staged, "rb").read() == want)
        check("...and the docx cell's sidecar is produced — the artifact the "
              "A5 per-cell gate rejects the cell without",
              find_sidecar(p["run"]) is not None
              and os.path.isfile(os.path.join(p["out"], SUMMARY)))
        check("a current native sidecar is re-derived through its complete "
              "root plan, shards, assets, runtime and arithmetic",
              native_loaded["schema"] == TEST_QUALITY_SUMMARY_SCHEMA
              and native_loaded["verdict_basis"] == "full_gold"
              and publication_ready(native_loaded)[0] is False)
        check("a seed-manifest-only identity change invalidates every "
              "provision-time worker attestation",
              seed_manifest_tamper_refused)
        check("PC10: an absent seed directory is a CONTROLLED refusal at the "
              "publication boundary, not a `SeedRefused` traceback",
              absent_seed_refused is True, str(absent_seed_refused))
        check("LOOP-BACK: the saved native summary READER refuses a "
              "consistently `fixture`-class campaign, and the refusal names "
              "that surface -- the tripwire the R3 review found missing",
              "the native saved report" in fixture_class_read_refused
              and "not publishable" in fixture_class_read_refused,
              fixture_class_read_refused)

        # ------------------------------------------------------------- PC9
        #
        # The in-place constraint, pinned DELIBERATELY (review finding 25;
        # plan §8 keeps portable native sidecars an explicit non-goal, so the
        # disposition is to state the constraint, not to remove it).  The run
        # and its sidecar are copied BYTE-IDENTICALLY to a second directory --
        # `run_binding` still matches, every hash still matches -- and the
        # only input that changed is the path.
        import shutil as _shutil
        _relocated_dir = os.path.join(d, "relocated")
        os.makedirs(_relocated_dir, exist_ok=True)
        _side_before = find_sidecar(p["run"])
        _moved_run = os.path.join(_relocated_dir,
                                  os.path.basename(p["run"]))
        _shutil.copyfile(p["run"], _moved_run)
        _shutil.copyfile(_side_before, os.path.join(
            _relocated_dir, os.path.basename(_side_before)))
        _pc9_refusal = ""
        try:
            load_bound_test_quality(_moved_run)
        except TestQualityRefused as e:
            _pc9_refusal = str(e)
        check("PC9: a byte-identical native sidecar copied to a second path "
              "draws EXACTLY the `names another candidate run path` refusal",
              _pc9_refusal == "REFUSED: native test-quality summary names "
                              "another candidate run path.",
              _pc9_refusal or "no refusal at all")
        # Asserted by EXACT EQUALITY, not by substring, which is what makes
        # it red when the comparison is DELETED rather than merely reworded.
        # Mutation-probed: with those four lines removed the relocated sidecar
        # still refuses, but much later and for an unrelated reason --
        # "REFUSED: saved validation report fields differ; missing=[...]" --
        # so a `raises(...)` check would have stayed green while the constraint
        # this row exists to pin had gone.  The two checks below say what was
        # held constant, in the suite rather than only in a comment.
        check("PC9: ...and the run bytes and the sidecar bytes really are "
              "identical, so PATH is the only input that changed",
              open(p["run"], "rb").read() == open(_moved_run, "rb").read()
              and open(_side_before, "rb").read() == open(os.path.join(
                  _relocated_dir, os.path.basename(_side_before)),
                  "rb").read())
        check("PC9: ...and the ORIGINAL path validated -- the refusal is the "
              "constraint, not a broken fixture",
              native_loaded["schema"] == TEST_QUALITY_SUMMARY_SCHEMA)

    with tempfile.TemporaryDirectory() as d:
        # A PHP-shaped invocation: CoreShop manifest, no profile at all.
        p = _cli_fixture(d, "r2t-mutate",
                         "src/CoreShop/Component/Order/Model/Order.php")
        (rc, calls, _native_loaded, _seed_tamper, _absent_seed,
         _fixture_class_read) = _drive(
            p, "boundary_coreshop.yml", None)
        check("a CoreShop test-quality (no profile) still binds the PHP "
              "engine and ITS applier — the archived path, unchanged",
              rc == 0 and len(calls) == 2
              and all(call["engine_dir"] == _MR.PHP_ENGINE_DIR
                      and call["applier"] is _MR.PHP_APPLIER
                      for call in calls),
              str(calls))
        check("v1.1: ...and every job's harness, candidate and gold, carries "
              "the seed's generated classes to restore before each pair",
              len(calls) == 2
              and all(call["derived_baseline"] == {
                  "var/classes/DataObject/CoreShopProduct.php":
                      b"<?php // CoreShopProduct as seeded\n"}
                  for call in calls),
              str([call["derived_baseline"] for call in calls]))
        staged = os.path.join(p["workspace"], "var/bench_mutate/mutate.php")
        with open(os.path.join(_MR.PHP_ENGINE_DIR, "mutate.php"), "rb") as fh:
            want = fh.read()
        check("...and the staged program is mutate.php, byte-identical to "
              "the engine's own",
              os.path.isfile(staged) and open(staged, "rb").read() == want)

    with tempfile.TemporaryDirectory() as d:
        # The mismatch: a PHP manifest under the docx profile.  Staging would
        # succeed and every apply would then fail inside the container; the
        # verb must refuse BEFORE any slice runs.
        p = _cli_fixture(d, "r2t-mutate",
                         "src/CoreShop/Component/Order/Model/Order.php")
        refused, calls = False, None
        try:
            (_rc, calls, _native_loaded, _seed_tamper,
             _absent_seed, _fixture_class) = _drive(
                 p, "boundary_python_docx.yml", "profile_python_docx.yml")
        except SystemExit as e:
            refused = "REFUSED" in str(e) and "r2t-mutate" in str(e)
        check("a manifest/profile engine mismatch is REFUSED before a single "
              "mutant is staged, naming both engines",
              refused and calls is None, str(calls))

    with tempfile.TemporaryDirectory() as d:
        # And the reverse: a python manifest with no profile (behat stack).
        p = _cli_fixture(d, "r2t-mutate-py", "src/docx/api.py")
        refused = False
        try:
            _drive(p, "boundary_coreshop.yml", None)
        except SystemExit as e:
            refused = "REFUSED" in str(e)
        check("...and the reverse mismatch (python manifest, no profile) is "
              "refused the same way", refused)

    # The native path's strictness, over every campaign driven above: the
    # release set stays the report's pinned population and the compact
    # authority stays closed.  A `True` here would be a silent methodology
    # change for the docx and CoreShop cells, not a refactor.
    check("every test-quality campaign asked the shared resolver for the "
          "unchanged native strictness -- no paid-view subset, no compact "
          "authority",
          bool(resolver_bindings)
          and all(binding == {"paid_view_subset": False,
                              "compact_allowed": False}
                  for binding in resolver_bindings),
          str(resolver_bindings))
    def _reference_cli_drive(p, boundary, profile, *, timeout_override=None,
                             calls=None, reference_harness=None,
                             project="fixture", full_gold=False,
                             candidate_pairs=None, gold_pair_plan=None,
                             second_mutant=False, preflights=None):
        """The REAL `test-quality` verb over an installed reference.

        The docx capability gate is NOT removed here, unlike `_drive`: the
        point of the check is that `--reference-controls` is itself the
        live-workload binding for a project with no reviewed wrapper.  Only
        the container leaves are faked, plus the from-disk reference read --
        `reference_loader` has its own from-disk selftest, and rebuilding a
        three-role tree here would test that module a second time instead of
        this verb's wiring.
        """
        from . import reference_loader as _RL
        from .validate import HARNESS_VERSION as _DRIVE_HARNESS_VERSION
        engine_dir, applier = _MR.binding_for("r2t-mutate-py")
        drive_pairs = {("i1", "m1")}
        if second_mutant:
            # A second mapped mutant gold does not kill: G_i1 = {m1} is then
            # a strict slice of the item's pairs {m1, m2}.
            with open(p["manifest"], encoding="utf-8") as fh:
                drive_manifest = json.load(fh)
            drive_manifest["mutants"].append(dict(
                drive_manifest["mutants"][0], id="m2", start_line=4))
            drive_manifest["n"] = 2
            with open(p["manifest"], "w", encoding="utf-8") as fh:
                json.dump(drive_manifest, fh)
            with open(p["map"], "w", encoding="utf-8") as fh:
                json.dump({"by_mutant": {"m1": ["i1"], "m2": ["i1"]}}, fh)
            drive_pairs.add(("i1", "m2"))
        controls, _authority = _single_fixture_controls(
            {"i1": {"full_gold_kills": ["m1"], "hard_subset": ["m1"],
                    "stub_recall": 0.0}},
            drive_pairs, full_gold=full_gold,
            population_overrides={
                "asset_index_sha256": "8" * 64,
                "asset_project": project,
                "manifest_sha256": _MR.sha256_file(p["manifest"]),
                "map_sha256": _MR.sha256_file(p["map"]),
                "release_sha256": _MR.sha256_file(p["release"]),
                "engine": "r2t-mutate-py", "parser": "fixture",
            },
            authority_overrides={
                "mutation_validation_sha256": _MR.sha256_file(
                    p["gold_results_attestation"]),
                "substrate_baseline_sha256": "b" * 64,
                "applier_sha256": _MR.sha256_file(
                    os.path.join(engine_dir, applier.source)),
                "harness_version": (_DRIVE_HARNESS_VERSION
                                    if reference_harness is None
                                    else reference_harness),
                "database_dump_digest": "no_database",
                "timeout_seconds": (5 if timeout_override is None
                                    else timeout_override),
            })
        # Caller-owned, so a refusal that raises out of this function still
        # tells the check whether any slice was dispatched first.
        calls = [] if calls is None else calls

        def fixture_assets(_report_path, *, manifest_path, map_path,
                           release_path, require_release_ready=True,
                           paid_view_subset=False, budgeted_sidecar=None):
            del release_path, require_release_ready, paid_view_subset
            # As above: this stand-in reads the map it is handed, so it can
            # admit no derived one.
            assert budgeted_sidecar is None, budgeted_sidecar
            with open(manifest_path, encoding="utf-8") as fh:
                fixture_manifest = json.load(fh)
            with open(map_path, encoding="utf-8") as fh:
                fixture_map = json.load(fh)
            return {
                "validation_class": "native",
                "validation_sha256": _MR.sha256_file(_report_path),
                "asset_index_sha256": "8" * 64,
                "asset_project": project,
                "n_non_production_excluded": 0,
                "manifest": fixture_manifest,
                "map": fixture_map,
                "release_items": 1,
            }

        def spy(h, mutants_, items_by_id, files_by_item, by_mutant_,
                engine_dir_, out_path, **kw):
            calls.append({"side": kw["identity"]["side"],
                          "mutants": len(mutants_),
                          "pairs": sorted(
                              (iid, m["id"]) for m in mutants_
                              for iid in by_mutant_.get(m["id"], [])
                              if iid in files_by_item)})
            _MR.install_applier(h, engine_dir_, kw["applier"])
            os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".",
                        exist_ok=True)
            n = 0
            with open(out_path, "a", encoding="utf-8") as fh:
                for m in mutants_:
                    for iid in by_mutant_.get(m["id"], []):
                        if iid not in files_by_item:
                            continue
                        fh.write(json.dumps(_stamped(
                            {"identity": kw["identity"]}, {
                                "item_id": iid, "mutant_id": m["id"],
                                "file": m["file"], "operator": m["operator"],
                                "outcome": "failed", "attempt": 1,
                                "retried_infrastructure": False})) + "\n")
                        n += 1
            _MR.write_shard_provenance(out_path, kw["identity"], "running",
                                       provenance=kw.get("provenance"))
            _MR.write_shard_provenance(out_path, kw["identity"], "complete",
                                       provenance=kw.get("provenance"))
            return {"out": out_path, "rows": n}

        real_harness, real_run_slice = _cli._harness, _MR.run_slice
        real_assets = _MA.validate_campaign_asset_inputs
        real_preflight = _W.preflight
        real_capture = _W.capture_execution_bindings
        real_seed_identity = _W.verified_seed_identity
        real_loader = _RL.load_native_reference_controls
        from ..core import docker_cli as _DC
        try:
            _cli._harness = lambda a: (
                _types.SimpleNamespace(
                    root=a.repo, substrate_baseline_sha256="b" * 64),
                None, None)
            _MR.run_slice = spy
            _MA.validate_campaign_asset_inputs = fixture_assets
            _W.preflight = lambda *a, **kw: (
                (preflights if preflights is not None else []).append(1)
                or {"workers": len(a[0])})
            _W.verified_seed_identity = (
                lambda _seed, needs_database: {
                    "seed_dir": os.path.realpath(_seed),
                    "seed_manifest_sha256": "3" * 64,
                    "seed_key": "fixture-seed",
                    "workspace_seed_digest": "6" * 64,
                    "database_dump_digest": (
                        "5" * 64 if needs_database else "no_database"),
                    "needs_database": needs_database})
            _RL.load_native_reference_controls = (
                lambda *_a, **_kw: {"controls": controls})
            _DC._install_test_authority(
                p["_authority_doc"], p["_authority_ref"])
            _W.capture_execution_bindings = (
                lambda pool, authority_ref, docker_group=True: [
                    json.loads(json.dumps(p["_binding"]))])
            args = _cli_args(p, boundary, profile)
            args.reference_controls = os.path.join(
                os.path.dirname(p["out"]), "reference")
            args.reference_attestation = os.path.join(
                os.path.dirname(p["out"]), "reference.json")
            if candidate_pairs is not None:
                args.candidate_pairs = candidate_pairs
            if gold_pair_plan is not None:
                args.gold_pair_plan = gold_pair_plan
            rc = _cli.cmd_test_quality(args)
        finally:
            _cli._harness, _MR.run_slice = real_harness, real_run_slice
            _MA.validate_campaign_asset_inputs = real_assets
            _W.preflight = real_preflight
            _W.capture_execution_bindings = real_capture
            _W.verified_seed_identity = real_seed_identity
            _RL.load_native_reference_controls = real_loader
            _DC.configure()
        return rc, calls, controls

    with tempfile.TemporaryDirectory() as d:
        p = _cli_fixture(d, "r2t-mutate-py", "src/docx/api.py")
        _ref_rc, _ref_calls, _ref_controls = _reference_cli_drive(
            p, "boundary_python_docx.yml", "profile_python_docx.yml")
        _ref_authority = _seal_single_observation_scoring_authority(
            _ref_controls)
        _ref_summary = load_bound_test_quality(
            p["run"], find_sidecar(p["run"]),
            reference_controls_reader=lambda _s, _e: _ref_authority)
        check("the installed reference IS the live-workload binding: the "
              "closed verb runs without the docx capability, plans candidate "
              "slices only, and publishes a validated v2 summary",
              _ref_rc == 0
              and [call["side"] for call in _ref_calls] == ["candidate"]
              and _ref_summary["schema"] == TEST_QUALITY_SUMMARY_SCHEMA_V2
              and _ref_summary["candidate_pairs"] == 1
              and _ref_summary["pairs_executed_gold"] == 1
              and _ref_summary["non_vacuous_passes"] == 1,
              f"rc={_ref_rc} calls={_ref_calls}")

    with tempfile.TemporaryDirectory() as d:
        p = _cli_fixture(d, "r2t-mutate-py", "src/docx/api.py")
        pool_refused, pool_calls = "no refusal at all", []
        try:
            _reference_cli_drive(
                p, "boundary_python_docx.yml", "profile_python_docx.yml",
                timeout_override=600, calls=pool_calls)
        except SystemExit as e:
            pool_refused = str(e)
        check("a pool that differs from the reference's sealed execution "
              "identity is refused BEFORE the first mutant is applied",
              "timeout_seconds" in pool_refused and not pool_calls,
              f"{pool_refused} / {pool_calls}")

    # GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md sections 1 and 7 through the real
    # verb: `--candidate-pairs gold-killed` with `--reference-controls` is
    # admitted for a full-gold-only reference and executes its sealed G_i
    # only; the other scope/basis pairings refuse once the reference is
    # read, before any worker preflight; a gold pair plan still refuses
    # before anything is read.
    with tempfile.TemporaryDirectory() as d:
        p = _cli_fixture(d, "r2t-mutate-py", "src/docx/api.py")
        _fg_rc, _fg_calls, _fg_controls = _reference_cli_drive(
            p, "boundary_python_docx.yml", "profile_python_docx.yml",
            full_gold=True, candidate_pairs=CANDIDATE_PAIRS_GOLD_KILLED,
            second_mutant=True)
        _fg_authority = _seal_single_observation_scoring_authority(
            _fg_controls)
        _fg_summary = load_bound_test_quality(
            p["run"], find_sidecar(p["run"]),
            reference_controls_reader=lambda _s, _e: _fg_authority)
        _fg_plan = _load_json_object(
            _campaign_state_path(p["out"]), "CLI full-gold root")["plan"]
        check("test-quality --reference-controls --candidate-pairs "
              "gold-killed scores a full-gold-only reference on its sealed "
              "G_i only and publishes a validated, scope-bound v2 summary",
              _fg_rc == 0
              and [(call["side"], call["pairs"]) for call in _fg_calls]
              == [("candidate", [("i1", "m1")])]
              and _fg_summary["verdict_basis"] == "full_gold"
              and _fg_summary["candidate_pair_scope"]
              == CANDIDATE_PAIRS_GOLD_KILLED
              and _fg_summary["candidate_pairs"] == 1
              and _fg_summary["reference_pairs"] == 2
              and _fg_summary["non_vacuous_passes"] == 1
              and _fg_summary["full_jaccard_macro"] is None
              and _fg_plan["candidate_pair_scope"]["candidate_pairs"] == 1,
              f"rc={_fg_rc} calls={_fg_calls}")
    for _fg_basis, _fg_scope, _fg_plan_path, _fg_needle in (
            (True, CANDIDATE_PAIRS_ALL, None, "full gold only"),
            (False, CANDIDATE_PAIRS_GOLD_KILLED, None,
             "served only for a full-gold-only reference"),
            (True, CANDIDATE_PAIRS_GOLD_KILLED, "absent-gold-pair-plan.json",
             "accepts no ['--gold-pair-plan']")):
        with tempfile.TemporaryDirectory() as d:
            p = _cli_fixture(d, "r2t-mutate-py", "src/docx/api.py")
            _fg_refused, _fg_calls, _fg_preflights = "no refusal", [], []
            try:
                _reference_cli_drive(
                    p, "boundary_python_docx.yml", "profile_python_docx.yml",
                    full_gold=_fg_basis, candidate_pairs=_fg_scope,
                    gold_pair_plan=_fg_plan_path, second_mutant=True,
                    calls=_fg_calls, preflights=_fg_preflights)
            except SystemExit as e:
                _fg_refused = str(e)
            check(f"test-quality --reference-controls refuses "
                  f"{'full-gold' if _fg_basis else 'hard-subset'} reference "
                  f"with --candidate-pairs {_fg_scope}"
                  + (" and a gold pair plan" if _fg_plan_path else "")
                  + " before any worker preflight or campaign output",
                  _fg_needle in _fg_refused and not _fg_calls
                  and not _fg_preflights and not os.path.exists(p["out"]),
                  f"{_fg_refused} / {_fg_calls} / {_fg_preflights}")

    # Owner ruling 2026-09-15 through the real verb: VERSIONS.yml lists
    # harness 12 for python-docx and algorand-sdk, so a current-harness pool
    # passes the pool check AND the summary validator against a reference
    # recorded there, and the candidate keeps its own version.  coreshop and
    # an unlisted project keep exact equality at the pool check.
    from .validate import HARNESS_VERSION as _COMPAT_HARNESS
    for _project in ("python-docx", "algorand-sdk"):
        with tempfile.TemporaryDirectory() as d:
            p = _cli_fixture(d, "r2t-mutate-py", "src/docx/api.py")
            _h_rc, _h_calls, _h_controls = _reference_cli_drive(
                p, "boundary_python_docx.yml", "profile_python_docx.yml",
                reference_harness=12, project=_project)
            _h_authority = _seal_single_observation_scoring_authority(
                _h_controls)
            _h_summary = load_bound_test_quality(
                p["run"], find_sidecar(p["run"]),
                reference_controls_reader=lambda _s, _e: _h_authority)
            check(f"{_project}: a reference recorded at harness 12 scores "
                  f"a candidate on a current-harness pool, which keeps its "
                  f"own harness version",
                  _h_rc == 0
                  and [call["side"] for call in _h_calls] == ["candidate"]
                  and _h_summary["harness_version"] == _COMPAT_HARNESS
                  and _h_controls["authority"]["harness_version"] == 12,
                  f"rc={_h_rc} calls={_h_calls}")
    for _project in ("coreshop", "fixture"):
        with tempfile.TemporaryDirectory() as d:
            p = _cli_fixture(d, "r2t-mutate-py", "src/docx/api.py")
            _h_refused, _h_calls = "no refusal at all", []
            try:
                _reference_cli_drive(
                    p, "boundary_python_docx.yml", "profile_python_docx.yml",
                    calls=_h_calls, reference_harness=12, project=_project)
            except SystemExit as e:
                _h_refused = str(e)
            check(f"{_project}: a reference recorded at harness 12 refuses "
                  f"a current-harness pool BEFORE the first mutant is applied",
                  "field(s) ['harness_version']" in _h_refused
                  and not _h_calls, f"{_h_refused} / {_h_calls}")

    _argv_refusals = _single_observation_argv_refusals()
    check("every option the single-observation policy cannot mean is refused "
          "at argv, by name, before any file is read",
          set(_argv_refusals.values()) == {"refused"},
          str({k: v for k, v in _argv_refusals.items() if v != "refused"}))

    print("\n" + ("ALL PASS (test_quality)" if ok
                  else "FAILURES (test_quality)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
