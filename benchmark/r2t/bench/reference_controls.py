"""Reusable full-population mutation reference controls.

Three complete observations -- full gold, assertion-stripped gold, stub --
are collected once per project and reduced here to the artifact every later
candidate is scored against without re-running any of them: per item, the
mutants gold kills (``G``) and the subset of those the assertion-stripped
gold does NOT kill (``H``).

The producer-side reader authenticates a current standalone mutation output
while its worker specifications and runtime attestations are still available.
The preserved reader checks the same closed plan, shards, row stamps and
sidecars after relocation, but deliberately treats producer-host paths inside
``worker_resources`` as recorded provenance rather than live inputs.

Section 5.1 of the specification governs the pairs that end on a terminal
timeout or infrastructure outcome after the reviewed retry policy.  They are
excluded from the scored universe rather than imputed, the exclusion is the
UNION over the three roles so that ``G``, ``S`` and the stub kill set share
one denominator, and the operator's consent to that narrowing is recorded in
the artifact beside the pairs it dropped.

`DECLARED_REFERENCE_SUBSET_SPEC.md` governs the items.  A reference may cover
a DECLARED strict subset of its mapped item population -- algorand's map pins
the 117-item release, but a gold oracle exists only for the 111-item execution
view -- provided the operator declares that item set here, the gold baseline
proves the omitted items are exactly the ones the control run has no row for,
and the omitted ids, counts and reason travel in the artifact.  Nothing
declares by default and the undeclared path is byte-unchanged.

`specifications/SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md` adds one
LABELLED basis, `sylius_stub_gate_waived_v1`, for a reference whose stub gate
failed.  `sensitivity_reference_controls` derives the same document from the
same three sealed observations -- the same `G_i`, the same hard subset
`H_i = G_i ∩ stripped-survived`, the same stub recalls -- records the failed
gate as a diagnostic instead of refusing, and names the label, so the result
can never be read as eligible controls: it is never written as an
attestation, and every summary scored against it carries the label.  Ported
from the harness-21 collector line for scoring at harness 25
(EVALUATOR_CORRECTIONS_20261015_AMENDMENT.md section 5).
"""
from __future__ import annotations

import copy
import json
import os
from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Optional

from ..toolkit import gold_killset
from ..data import mutation
from ..data import mutation_attestation
from . import mutation_run
from . import test_quality
from ..data import versions


SCHEMA = "r2t.single-observation-reference-controls/1"
METHOD = "single_observation"
REFERENCE_OBSERVATION_COUNT = 1
STUB_RECALL_THRESHOLD = 0.02
#: Labelled bases a failed-gate reference may be scored under, and the one
#: project each is defined for
#: (specifications/SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md).
SENSITIVITY_PROJECTS = {"sylius_stub_gate_waived_v1": "sylius"}
#: Pairs a scoring host's gold-agreement pilot saw survive although the
#: preserved full gold killed them.  They leave G and the hard subset for
#: every cell scored on that host, and are listed in the controls.
GOLD_DISAGREEMENTS_SCHEMA = "r2t.gold-disagreements/1"
ROLES = ("full_gold", "stripped_gold", "stub")
DECLARATION_FIELDS = frozenset({"items", "reason"})
ROLE_SIDE = {
    "full_gold": "gold",
    "stripped_gold": "candidate",
    "stub": "candidate",
}
IDENTITY_REFERENCE_ROLE = {
    "full_gold": "full-gold",
    "stripped_gold": "assertion-stripped-gold",
    "stub": "stub-control",
}
WORKLOAD_FIELDS = frozenset({
    "candidate_run_sha256", "generated_tests_sha256",
    "reference_source_tag", "reference_workload_digest",
})

# Generated-test bytes, role, worker allocation and observation identity may
# differ.  These are the population and execution semantics section 3 requires
# to remain identical across the three controls.
SHARED_IDENTITY_FIELDS = frozenset({
    "asset_index_sha256", "asset_project",
    "mutation_validation_sha256", "mutation_validation_class",
    "manifest_sha256", "manifest_digest", "map_sha256", "release_sha256",
    "substrate_baseline_sha256", "applier_sha256", "harness_version",
    "container_image_digest", "workspace_seed_digest",
    "database_dump_digest", "engine", "engine_version", "parser",
    "timeout_seconds", "sample", "sample_seed", "reference_source_tag",
})


class ReferenceControlsRefused(ValueError):
    """The supplied bytes do not establish reusable reference controls."""


_OBSERVATION_SEAL = object()
_SCOPE_SEAL = object()
_CONTROLS_SEAL = object()
_SETS_SEAL = object()


class ReferenceScope:
    """Adapter-authenticated population, baseline, and role workloads."""

    def __init__(self, *, population: dict, authority: dict,
                 expected_pairs: frozenset, workloads: dict, seal: object,
                 declaration: Optional[dict] = None):
        if seal is not _SCOPE_SEAL:
            raise ReferenceControlsRefused(
                "REFUSED: ReferenceScope is created only by "
                "`seal_reference_scope`.")
        self._seal = seal
        self.population = copy.deepcopy(population)
        self.authority = copy.deepcopy(authority)
        self.expected_pairs = frozenset(expected_pairs)
        self.workloads = copy.deepcopy(workloads)
        # The proved declaration, or None when the reference covers its whole
        # mapped item population.  `expected_pairs` is ALREADY restricted to
        # the declared items: this is the disclosure, not a second filter a
        # consumer has to remember to apply.
        self.declaration = copy.deepcopy(declaration)


class SealedObservation(dict):
    """An unchanged observation returned by one of this module's readers."""

    def __init__(self, value: dict, seal: object, *, root: str,
                 portable: bool):
        super().__init__(value)
        self._seal = seal
        self._root = root
        self._portable = portable


class ReferenceControls(dict):
    """A validated attestation joined to its three sealed observations."""

    def __init__(self, value: dict, *, expected_pairs: frozenset,
                 observations: Mapping[str, SealedObservation], seal: object):
        if seal is not _CONTROLS_SEAL or set(observations) != set(control_roles(value)):
            raise ReferenceControlsRefused(
                "REFUSED: ReferenceControls requires the exact internally "
                "validated three-role observation set.")
        super().__init__(value)
        self._seal = seal
        # The scored universe, which is the complete mapped set MINUS the
        # pairs section 5.1 excluded -- not `scope.expected_pairs`.  Candidate
        # scoring restricts this to its passed items, so handing it the
        # unnarrowed set would score a candidate on pairs no control observed.
        self._expected_pairs = frozenset(expected_pairs)
        self._observations = dict(observations)


class ReferenceSets:
    """Immutable authenticated scoring view; raw outcomes are not exposed."""

    def __init__(self, *, expected_pairs: frozenset, excluded_count: int,
                 full_gold_kills: Mapping[str, frozenset[str]],
                 hard_subset: Mapping[str, frozenset[str]],
                 stub_recall_by_item: Mapping[str, Optional[float]],
                 stub_macro_recall: float, stub_threshold: float,
                 eligible: bool, seal: object,
                 omitted_items: Iterable[str] = (),
                 declared_reason: Optional[str] = None,
                 reference_basis: str = "hard_subset",
                 sensitivity: Optional[str] = None):
        if seal is not _SETS_SEAL:
            raise ReferenceControlsRefused(
                "REFUSED: ReferenceSets is derived only from authenticated "
                "reference controls.")
        object.__setattr__(self, "_frozen", False)
        object.__setattr__(self, "_seal", seal)
        object.__setattr__(self, "expected_pairs", frozenset(expected_pairs))
        # Section 5.1 requires the excluded count to be printed beside every
        # number derived from the artifact.  It travels on the scoring view
        # for the same reason the stub gate's own numbers do: this is what a
        # consumer holds when it renders one.
        object.__setattr__(self, "excluded_count", excluded_count)
        # The declared subset's disclosure, on the same view and for the same
        # reason: a consumer holding this is what renders a number, and a
        # narrowed item denominator that does not say it is narrowed is
        # exactly what the ruling forbids.  Empty when nothing was declared.
        object.__setattr__(self, "omitted_items", tuple(omitted_items))
        object.__setattr__(self, "declared_reason", declared_reason)
        object.__setattr__(self, "full_gold_kills", MappingProxyType(
            dict(full_gold_kills)))
        object.__setattr__(self, "reference_basis", reference_basis)
        object.__setattr__(self, "hard_subset", None if hard_subset is None else MappingProxyType(
            dict(hard_subset)))
        object.__setattr__(self, "stub_recall_by_item", None if stub_recall_by_item is None else MappingProxyType(
            dict(stub_recall_by_item)))
        object.__setattr__(self, "stub_macro_recall", stub_macro_recall)
        object.__setattr__(self, "stub_threshold", stub_threshold)
        object.__setattr__(self, "eligible", eligible)
        # The labelled basis, or None for eligible controls.  Scoring records
        # it beside every number; the sets are derived exactly as for
        # eligible controls.
        object.__setattr__(self, "sensitivity", sensitivity)
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name, value):
        if getattr(self, "_frozen", False):
            raise AttributeError("ReferenceSets is immutable")
        object.__setattr__(self, name, value)


def control_roles(document):
    """The reviewed Coddy full-gold route; historical controls keep three roles."""
    return ("full_gold",) if document.get("reference_basis") == "full_gold" else ROLES


def authenticated_observation(value: object) -> bool:
    return isinstance(value, SealedObservation) \
        and value._seal is _OBSERVATION_SEAL


def authenticated_reference_scope(value: object) -> bool:
    return isinstance(value, ReferenceScope) \
        and value._seal is _SCOPE_SEAL


def authenticated_reference_controls(value: object) -> bool:
    return isinstance(value, ReferenceControls) \
        and value._seal is _CONTROLS_SEAL \
        and set(value._observations) == set(control_roles(value))


def authenticated_reference_sets(value: object) -> bool:
    return isinstance(value, ReferenceSets) and value._seal is _SETS_SEAL \
        and value._frozen is True


def artifact_digest(document: dict) -> str:
    if not isinstance(document, dict):
        raise ReferenceControlsRefused(
            "REFUSED: reference-controls attestation is not an object.")
    return mutation_run.content_digest(
        {key: value for key, value in document.items() if key != "digest"})


def _digest_checked(document: object) -> dict:
    """A document whose recorded digest is the digest of its own content."""
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise ReferenceControlsRefused(
            f"REFUSED: expected reference-controls schema {SCHEMA!r}.")
    if document.get("digest") != artifact_digest(document):
        raise ReferenceControlsRefused(
            "REFUSED: reference-controls digest does not match its canonical "
            "content.")
    return document


def _pairs(value: Iterable[tuple[str, str]]) -> frozenset[tuple[str, str]]:
    try:
        pairs = frozenset(value)
    except (TypeError, ValueError) as exc:
        raise ReferenceControlsRefused(
            "REFUSED: expected reference pairs are not an iterable set.") \
            from exc
    if not pairs or any(not isinstance(pair, tuple) or len(pair) != 2
                        or not all(isinstance(part, str) and part
                                   for part in pair)
                        for pair in pairs):
        raise ReferenceControlsRefused(
            "REFUSED: expected reference pairs must be nonempty string "
            "(item_id, mutant_id) tuples.")
    return pairs


def _declared_subset(declared_subset: object, release_ids: set[str],
                     baseline_ids: set[str], baseline_files: set[str]) \
        -> tuple[frozenset, Optional[dict]]:
    """The item set a reference covers, proved against its gold baseline.

    `declared_subset` is the operator's declaration -- `{"items", "reason"}`
    -- or None for the whole released population.  It is DECLARED, never
    discovered: an operator who has not said which items are out of scope
    gets the undeclared refusal below, unchanged, naming what is missing.

    The proof is one comparison, `baseline == declared`, and it is the whole
    of section 3.1:

    * `declared - baseline` means a declared item has no gold row.  A
      reference cannot cover an item its control run never observed.
    * `baseline - declared` means an item was omitted from the declaration
      whose gold row DOES exist.  A reference may only omit items the control
      run has no row for; narrowing the denominator past what the evidence
      forces is the silent narrowing the ruling forbids.

    Both refusals name the items, because the operator's next move is to
    declare exactly them or to stop.
    """
    if declared_subset is None:
        declared = frozenset(release_ids)
    else:
        if not isinstance(declared_subset, Mapping) \
                or set(declared_subset) != DECLARATION_FIELDS:
            raise ReferenceControlsRefused(
                "REFUSED: a declared reference subset binds exactly "
                f"{sorted(DECLARATION_FIELDS)}.")
        items = declared_subset["items"]
        reason = declared_subset["reason"]
        if not isinstance(items, (list, tuple)) or not items \
                or any(not isinstance(item, str) or not item
                       for item in items) \
                or list(items) != sorted(set(items)):
            raise ReferenceControlsRefused(
                "REFUSED: declared reference items must be a nonempty sorted "
                "unique list of item IDs.")
        if not isinstance(reason, str) or not reason.strip() \
                or "\n" in reason:
            raise ReferenceControlsRefused(
                "REFUSED: a declared reference subset needs the operator's "
                "one-line reason; a narrowing nobody explained is not a "
                "disclosure.")
        declared = frozenset(items)
        unknown = sorted(declared - release_ids)
        if unknown:
            raise ReferenceControlsRefused(
                f"REFUSED: declared reference item(s) {unknown[:3]} are not "
                "in the release document.")
        if declared == release_ids:
            raise ReferenceControlsRefused(
                "REFUSED: a declaration that omits nothing is not a "
                "declaration; omit the argument to cover the whole released "
                "population.")
    missing = sorted(declared - baseline_ids)
    if missing:
        raise ReferenceControlsRefused(
            f"REFUSED: the full gold baseline has no passed row for "
            f"{len(missing)} covered item(s), e.g. {missing[:3]}. A reference "
            f"covers only items its control run observed; declare the subset "
            f"it does cover if those items are out of scope.")
    undeclared = sorted(baseline_ids - declared)
    if undeclared:
        raise ReferenceControlsRefused(
            f"REFUSED: the full gold baseline covers {len(undeclared)} "
            f"item(s) outside the declared subset, e.g. {undeclared[:3]}. A "
            f"reference may only omit items its control run has no row for.")
    if baseline_files != set(declared):
        raise ReferenceControlsRefused(
            "REFUSED: full gold baseline solution bytes do not cover exactly "
            "the item set its rows do.")
    if declared_subset is None:
        return declared, None
    return declared, {
        "declared_items": len(declared),
        "release_items": len(release_ids),
        "omitted_items": sorted(release_ids - declared),
        "reason": declared_subset["reason"],
    }


def _load_json(path: str, label: str) -> dict:
    if os.path.islink(path) or not os.path.isfile(path):
        raise ReferenceControlsRefused(
            f"REFUSED: {label} is not a regular file: {path}.")
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReferenceControlsRefused(
            f"REFUSED: cannot read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReferenceControlsRefused(
            f"REFUSED: {label} is not a JSON object.")
    return value


def seal_reference_scope(
        population_id: str, *, manifest_path: str, map_path: str,
        release_path: str, gold_baseline_path: str,
        workloads: Mapping[str, Mapping[str, str]],
        declared_subset: Optional[Mapping[str, object]] = None) \
        -> ReferenceScope:
    return _seal_reference_scope(
        population_id, manifest_path=manifest_path, map_path=map_path,
        release_path=release_path, gold_baseline_path=gold_baseline_path,
        workloads=workloads, declared_subset=declared_subset)


def admit_reference_items(*, release_item_ids: Iterable[str],
                          gold_baseline_rows: Iterable[dict],
                          declared_subset=None):
    """Reuse the reference seal's declaration proof before a single leg runs."""
    rows = list(gold_baseline_rows)
    try:
        files = test_quality.passed_solutions(rows)
    except test_quality.TestQualityRefused as exc:
        raise ReferenceControlsRefused(str(exc)) from exc
    return _declared_subset(declared_subset, set(release_item_ids),
                            {row.get("item_id") for row in rows}, set(files))


def _seal_reference_scope(
        population_id: str, *, manifest_path: str, map_path: str,
        release_path: str, gold_baseline_path: str,
        workloads: Mapping[str, Mapping[str, str]], declared_subset=None,
        evaluation_scope=None) -> ReferenceScope:
    """The only way in: mint the sealed scope every entry point requires.

    Population, map, release, and full-gold baseline authority are rederived
    here.  The caller contributes only its three exact role workload
    bindings; it cannot replace the resulting scope with a pair list, because
    the expected pair set is read out of the validated map rather than
    accepted as an argument.

    `declared_subset` is the operator's declared item subset, proved here
    against the gold baseline by `_declared_subset` and then applied to the
    expected pair set.  It is supplied by the COLLECTION route, never by a
    scoring one -- the scoring route reads back the declaration the
    authenticated artifact recorded, exactly as it reads back section 5.1's
    recorded consent.  None means the whole released population, which is the
    byte-unchanged default.
    """
    manifest = _load_json(manifest_path, "scored mutation manifest")
    mapping = _load_json(map_path, "mutation map")
    try:
        release_ids = mutation_attestation.load_release_ids(release_path)
        mutation_attestation.validate_manifest(manifest)
        map_facts = mutation_attestation.validate_map(
            mapping, manifest, release_ids=release_ids)
        entry = versions.population(population_id)
        resolved = versions.population_id_for(
            entry["asset_project"], manifest["digest"],
            engine=manifest["engine"], engine_version=manifest["engine_version"])
    except (OSError, ValueError, versions.ManifestError) as exc:
        raise ReferenceControlsRefused(str(exc)) from exc
    if resolved != population_id \
            or manifest["engine"] != entry["engine"] \
            or manifest["engine_version"] != entry["engine_version"] \
            or manifest["parser"] != entry["parser"] \
            or mapping.get("release_sha256") \
            != mutation_run.sha256_file(release_path):
        raise ReferenceControlsRefused(
            "REFUSED: validated manifest/map/release do not resolve to the "
            "requested registered population.")
    baseline_rows = mutation_attestation.load_jsonl(gold_baseline_path)
    try:
        baseline_files = test_quality.passed_solutions(baseline_rows)
    except test_quality.TestQualityRefused as exc:
        raise ReferenceControlsRefused(str(exc)) from exc
    baseline_ids = {row.get("item_id") for row in baseline_rows}
    declared, declaration = _declared_subset(
        declared_subset, release_ids, baseline_ids, set(baseline_files))
    roles = (("full_gold",) if evaluation_scope is not None
             and entry["project"] == "coddy-agent"
             and set(workloads) == {"full_gold"} else ROLES)
    if not isinstance(workloads, Mapping) or set(workloads) != set(roles):
        raise ReferenceControlsRefused(
            "REFUSED: adapter workload authority must bind exactly the three "
            "reference roles.")
    checked_workloads = {}
    for role in roles:
        binding = workloads[role]
        if not isinstance(binding, Mapping) or set(binding) != WORKLOAD_FIELDS:
            raise ReferenceControlsRefused(
                f"REFUSED: adapter workload binding {role!r} has missing or "
                "unknown fields.")
        binding = dict(binding)
        for key in ("candidate_run_sha256", "generated_tests_sha256",
                    "reference_workload_digest"):
            value = binding[key]
            if not isinstance(value, str) or len(value) != 64 \
                    or any(ch not in "0123456789abcdef" for ch in value):
                raise ReferenceControlsRefused(
                    f"REFUSED: {role} workload {key} is not a SHA-256.")
        tag = binding["reference_source_tag"]
        if not isinstance(tag, str) or not tag or any(ch.isspace() for ch in tag):
            raise ReferenceControlsRefused(
                f"REFUSED: {role} workload has no reviewed source tag.")
        checked_workloads[role] = binding
    gold_binding = checked_workloads["full_gold"]
    if gold_binding["candidate_run_sha256"] \
            != mutation_run.sha256_file(gold_baseline_path) \
            or gold_binding["generated_tests_sha256"] \
            != mutation_run.candidate_digest(baseline_files):
        raise ReferenceControlsRefused(
            "REFUSED: full_gold workload differs from the complete gold "
            "baseline bytes and generated tests.")
    mapped = [(item_id, mutant_id)
              for mutant_id, item_ids in mapping["by_mutant"].items()
              for item_id in item_ids]
    # The declaration narrows the pair universe ONCE, here, so that every
    # later reader -- the three observations' coverage check, the derivation,
    # the candidate's restriction to passed items -- is already speaking about
    # the declared population.
    kept = [pair for pair in mapped if pair[0] in declared]
    if declaration is not None and not kept:
        raise ReferenceControlsRefused(
            "REFUSED: the declared reference subset carries no mapped pair; "
            "there is nothing to observe and no denominator to score.")
    expected = _pairs(kept)
    population = {
        "id": population_id,
        "project": entry["project"],
        "asset_project": entry["asset_project"],
        "generation": entry["generation"],
        "asset_index_sha256": (evaluation_scope["asset_index_sha256"]
                               if evaluation_scope is not None else
                               entry["asset_index_sha256"]),
        "manifest_sha256": mutation_run.sha256_file(manifest_path),
        "manifest_digest": manifest["digest"],
        "map_sha256": mutation_run.sha256_file(map_path),
        "release_sha256": mutation_run.sha256_file(release_path),
        "engine": entry["engine"],
        "engine_version": entry["engine_version"],
        "parser": entry["parser"],
    }
    authority = {
        "manifest_sha256": population["manifest_sha256"],
        "manifest_digest": population["manifest_digest"],
        "map_sha256": population["map_sha256"],
        "release_sha256": population["release_sha256"],
        "gold_baseline_sha256": mutation_run.sha256_file(gold_baseline_path),
        "gold_generated_tests_sha256":
            mutation_run.candidate_digest(baseline_files),
        "pairs_sha256": mutation_run.pair_set_digest(expected),
        # The MAP's own fact, not the declared one: this is the mutation
        # map's identity, and `declared_subset.omitted_pairs` below is what
        # the declaration removed from it.
        "n_pairs": map_facts["n_pairs"],
    }
    if declaration is not None:
        declaration["omitted_pairs"] = len(mapped) - len(kept)
    scope = ReferenceScope(
        population=population, authority=authority,
        expected_pairs=expected, workloads=checked_workloads,
        declaration=declaration, seal=_SCOPE_SEAL)
    # Only evaluation_reference calls this private seam, after its native
    # report and explicit collection scope have been joined. No new field is
    # added to historical attestations or their population schema.
    scope._evaluation_scope = copy.deepcopy(evaluation_scope)
    scope._manifest = copy.deepcopy(manifest)
    return scope


def _require_scope(scope: ReferenceScope) -> ReferenceScope:
    if not authenticated_reference_scope(scope):
        raise ReferenceControlsRefused(
            "REFUSED: reference work requires an unchanged authenticated "
            "ReferenceScope.")
    return scope


def _discover_paths(root: str) -> tuple[str, list[str], dict]:
    root = os.path.abspath(root)
    if os.path.islink(root) or not os.path.isdir(root):
        raise ReferenceControlsRefused(
            f"REFUSED: observation root is not a non-symlink directory: "
            f"{root}.")
    plan_path = os.path.join(root, mutation_run.MUTATION_OUTPUT_PLAN)
    if os.path.islink(plan_path) or not os.path.isfile(plan_path):
        raise ReferenceControlsRefused(
            f"REFUSED: observation has no regular output plan {plan_path}.")
    try:
        with open(plan_path, encoding="utf-8") as handle:
            plan = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReferenceControlsRefused(
            f"REFUSED: cannot read observation plan {plan_path}: {exc}") \
            from exc
    allowed = plan.get("allowed_artifacts") if isinstance(plan, dict) else None
    if not isinstance(plan, dict) \
            or plan.get("schema") != mutation_run.MUTATION_OUTPUT_PLAN_SCHEMA \
            or not isinstance(allowed, list) \
            or allowed != sorted(set(allowed)):
        raise ReferenceControlsRefused(
            "REFUSED: reusable reference observations require a current "
            "standalone v2 output plan with a closed artifact inventory.")
    expected = {mutation_run.MUTATION_OUTPUT_PLAN, *allowed}
    actual = set(os.listdir(root))
    for name in mutation_run.standalone_go_evidence_names(plan.get("campaign_core", {})):
        if name in actual:
            path = os.path.join(root, name)
            if os.path.islink(path) or not os.path.isdir(path):
                raise ReferenceControlsRefused("REFUSED: Go evidence must be a regular directory")
            actual.remove(name)
    if actual != expected:
        raise ReferenceControlsRefused(
            "REFUSED: observation directory differs from its closed "
            f"inventory: missing={sorted(expected-actual)}, "
            f"unexpected={sorted(actual-expected)}.")
    rows = [name for name in allowed
            if not name.endswith(".provenance.json")]
    if not rows or set(allowed) != {
            name for row in rows
            for name in (row, row + ".provenance.json")}:
        raise ReferenceControlsRefused(
            "REFUSED: observation plan does not pair every shard with one "
            "adjacent provenance sidecar.")
    return root, [os.path.join(root, name) for name in rows], plan


def _role_check(identity: dict, role: str, scope: ReferenceScope) -> None:
    scope = _require_scope(scope)
    if role not in ROLE_SIDE:
        raise ReferenceControlsRefused(
            f"REFUSED: unknown reference role {role!r}.")
    try:
        mutation_run._validate_campaign_identity(identity)
        mutation_run.validate_publishable_generation(
            identity, reference_roles={IDENTITY_REFERENCE_ROLE[role]},
            where=f"{role} reference observation")
    except mutation_run.MutationAborted as exc:
        raise ReferenceControlsRefused(str(exc)) from exc
    if identity.get("schema") != mutation_run.MUTATION_IDENTITY_SCHEMA_V5 \
            or identity.get("generation_provenance_class") \
            != mutation_run.GENERATION_PROVENANCE_REFERENCE_CONTROL \
            or identity.get("reference_control_role") \
            != IDENTITY_REFERENCE_ROLE[role]:
        raise ReferenceControlsRefused(
            f"REFUSED: {role} requires an authenticated v5 observation with "
            f"reference_control_role={IDENTITY_REFERENCE_ROLE[role]!r}.")
    if identity.get("kind") != "mutation-run" \
            or identity.get("side") != ROLE_SIDE[role] \
            or identity.get("sample") is not None \
            or identity.get("sample_seed") is not None:
        raise ReferenceControlsRefused(
            f"REFUSED: {role} must be an unsampled standalone "
            f"{ROLE_SIDE[role]} mutation observation.")
    population = scope.population
    # The asset index is the one identity field a ruled envelope equivalence
    # speaks to: the row says the registered index and the renamed one name
    # the same population, so an observation stamped with either is this
    # population's.  Everything else below stays an exact match.
    indexes = (population["asset_index_sha256"],)
    if getattr(scope, "_evaluation_scope", None) is None:
        indexes += versions.equivalent_asset_indexes(population["id"])
    index = identity.get("asset_index_sha256")
    if index not in indexes:
        raise ReferenceControlsRefused(
            f"REFUSED: {role} asset index {index!r} is neither "
            f"{population['id']}'s registered {indexes[0]!r} nor a ruled "
            f"envelope-equivalent {list(indexes[1:])!r}.")
    wanted = {
        "asset_project": population["asset_project"],
        "manifest_sha256": population["manifest_sha256"],
        "manifest_digest": population["manifest_digest"],
        "map_sha256": population["map_sha256"],
        "release_sha256": population["release_sha256"],
        "engine": population["engine"],
        "engine_version": population["engine_version"],
        "parser": population["parser"],
    }
    changed = sorted(key for key, value in wanted.items()
                     if identity.get(key) != value)
    workload = scope.workloads[role]
    workload_wanted = {
        "candidate_run_sha256": workload["candidate_run_sha256"],
        "candidate_generated_tests_sha256":
            workload["generated_tests_sha256"],
        "solution_generated_tests_sha256":
            workload["generated_tests_sha256"],
        "reference_source_tag": workload["reference_source_tag"],
        "reference_workload_digest": workload["reference_workload_digest"],
    }
    changed += sorted(key for key, value in workload_wanted.items()
                      if identity.get(key) != value)
    if changed:
        raise ReferenceControlsRefused(
            f"REFUSED: {role} differs from its authenticated population or "
            f"workload binding in field(s) {sorted(set(changed))}.")


def _excluded_terminal_outcome(outcome: object, role: str) -> bool:
    """Whether section 5.1 excludes this pair from the scored universe.

    A non-string outcome, or one no scoring vocabulary knows, stays a refusal:
    those are data errors, and a reader that cannot say what a row means may
    not decide what to do with it.  A terminal `timeout` or infrastructure
    result is a different fact -- the harness failing rather than a mutant
    surviving -- and section 5.1 drops its pair rather than imputing a kill or
    a survival.  `timeout` needs its own clause because `classify_outcome`
    buckets it as a KILL under a passed baseline.
    """
    if not isinstance(outcome, str) or not outcome:
        raise ReferenceControlsRefused(
            f"REFUSED: {role} has invalid terminal outcome {outcome!r}.")
    try:
        classification = mutation.classify_outcome("passed", outcome)
    except ValueError as exc:
        raise ReferenceControlsRefused(
            f"REFUSED: {role} has unknown terminal outcome {outcome!r}.") \
            from exc
    return outcome == "timeout" or classification == "infrastructure"


def _seal_observation(value: dict, *, root: str, portable: bool,
                      role: str, expected_pairs: frozenset,
                      plan_path: str, scope: ReferenceScope) \
        -> SealedObservation:
    identity = value["identity"]
    _role_check(identity, role, scope)
    outcomes = value["outcomes"]
    if set(outcomes) != expected_pairs:
        raise ReferenceControlsRefused(
            f"REFUSED: {role} does not cover the exact complete mapped pair "
            f"set: {len(expected_pairs-set(outcomes))} missing and "
            f"{len(set(outcomes)-expected_pairs)} unexpected pair(s).")
    excluded = {pair: outcome for pair, outcome in outcomes.items()
                if _excluded_terminal_outcome(outcome, role)}
    facts = copy.deepcopy(value["facts"])
    facts["output_plan_sha256"] = mutation_run.sha256_file(plan_path)
    sealed = {
        "role": role,
        "identity": copy.deepcopy(identity),
        "outcomes": copy.deepcopy(outcomes),
        # This role's own section 5.1 exclusions.  They are classified once,
        # here, where every outcome is already being read; the derivation
        # takes the union of the three roles' sets rather than reclassifying.
        "excluded": excluded,
        "facts": facts,
    }
    return SealedObservation(sealed, _OBSERVATION_SEAL,
                             root=root, portable=portable)


def _load_failed_host(root, *, role, scope, shard_pairs, portable):
    """A failed host's durable rows and its planned pairs (owner ruling 2026-09-30)."""
    root, paths, _plan = _discover_paths(root)
    try:
        loaded = mutation_run.read_failed_reference_shards(
            paths, shard_pairs=shard_pairs, strict=not portable)
        test_quality.validate_native_retry_evidence(
            loaded["rows"], where=f"failed {role} host observation")
    except (mutation_run.MutationAborted, test_quality.TestQualityRefused) as exc:
        raise ReferenceControlsRefused(str(exc)) from exc
    if portable:
        for sidecar in loaded["sidecars"]:
            _portable_worker_preimage(sidecar, sidecar["campaign_identity"])
    outcomes = {(row["item_id"], row["mutant_id"]): row.get("outcome") for row in loaded["rows"]}
    facts = {"observation_id": loaded["observation_id"],
             "campaign_identity_sha256": mutation_run.campaign_identity_digest(loaded["identity"]),
             "rows_sha256": [mutation_run.sha256_file(path) for path in loaded["paths"]],
             "sidecars_sha256": [mutation_run.sha256_file(mutation_run.provenance_path(path))
                                 for path in loaded["paths"]],
             "n_shards": len(loaded["paths"]), "n_rows": len(loaded["rows"]),
             "n_pairs": len(outcomes), "pairs_sha256": mutation_run.pair_set_digest(outcomes),
             "status": "failed", "planned_pairs": len(loaded["planned"])}
    host_scope = copy.copy(scope)
    host_scope.expected_pairs = frozenset(outcomes)
    observation = _seal_observation(
        {"identity": loaded["identity"], "outcomes": outcomes, "facts": facts},
        root=root, portable=portable, role=role, expected_pairs=host_scope.expected_pairs,
        plan_path=os.path.join(root, mutation_run.MUTATION_OUTPUT_PLAN), scope=host_scope)
    return observation, loaded["planned"]


def _load_host_observations(root, *, role, scope, portable):
    """Join disjoint native host campaigns without rewriting any producer identity.

    Owner ruling 2026-09-30 (full282 section 5): the hosts of one supplement
    allocation, bound to one frozen plan, observe exactly the pairs that the
    parent allocation's failed hosts left unrun, and those failed hosts
    contribute the rows they recorded.  A supplement host may fail in turn and
    be the parent of the next supplement; the last supplement has no failed
    host.  Every supplement's pairs are rederived here from its parent's
    failed shards, never read from a plan.
    """
    if role != "full_gold" or scope.population["project"] != "coddy-agent" \
            or set(scope.workloads) != {"full_gold"}:
        raise ReferenceControlsRefused("REFUSED: host partitions require Coddy full-gold scope")
    if os.path.islink(root) or not os.path.isdir(root):
        raise ReferenceControlsRefused("REFUSED: invalid full-gold host observation root")
    by_mutant = {}
    for item, mutant in scope.expected_pairs:
        by_mutant.setdefault(mutant, set()).add(item)
    hosts = {}
    for host in sorted(os.listdir(root)):
        host_root = os.path.join(root, host)
        _host_root, paths, _plan = _discover_paths(host_root)
        sidecars = [_load_json(mutation_run.provenance_path(path), "host reference provenance")
                    for path in paths]
        identity = sidecars[0]["campaign_identity"]
        try:
            mutation_run._validate_campaign_identity(identity)
            partition = identity.get("reference_partition")
            if not partition or partition["host"] != host:
                raise ReferenceControlsRefused("REFUSED: host directory differs from partition")
        except mutation_run.MutationAborted as exc:
            raise ReferenceControlsRefused(str(exc)) from exc
        hosts[host] = (host_root, identity,
                       any(sidecar.get("status") in ("failed", "interrupted") for sidecar in sidecars),
                       sidecars)
    # Hosts by the plan they name, in sorted host order; None is the parent allocation.
    groups = {}
    for host, value in hosts.items():
        groups.setdefault(value[1]["reference_partition"].get("supplement_plan_sha256"), []).append(host)
    parent = groups.pop(None, [])
    observations, outcomes = {}, {}

    def join(host, observation):
        if set(outcomes).intersection(observation["outcomes"]):
            raise ReferenceControlsRefused("REFUSED: overlapping full-gold host observations")
        outcomes.update(observation["outcomes"])
        observations[host] = observation

    def shard_pairs(host, pairs_by_mutant):
        identity = hosts[host][1]
        try:
            return mutation_run.reference_shard_pairs(
                scope._manifest, pairs_by_mutant, identity["reference_partition"], identity["of"])
        except mutation_run.MutationAborted as exc:
            raise ReferenceControlsRefused(str(exc)) from exc

    def continues(group, pairs_by_mutant):
        """Whether every shard identity of this group was planned for its slot of these pairs."""
        for host in group:
            planned = shard_pairs(host, pairs_by_mutant)
            for sidecar in hosts[host][3]:
                identity = sidecar.get("campaign_identity") or {}
                shard = identity.get("shard")
                if type(shard) is not int or not 0 <= shard < len(planned) \
                        or identity.get("expected_pairs") != len(planned[shard]) \
                        or identity.get("expected_pairs_sha256") \
                        != mutation_run.pair_set_digest(planned[shard]):
                    return False
        return True

    reader = load_preserved_observation if portable else load_native_observation
    # One level at a time: the parent allocation over every mapped pair, then
    # each supplement over what the failed hosts of the level before left unrun.
    levels, group, pairs_by_mutant, derived = [], parent, by_mutant, None
    while True:
        # A failed host is read as one only where a supplement follows it.
        failed = [host for host in group if groups and hosts[host][2]]
        planned, pending = set(), set()
        for host in group:
            host_root, identity, _failed, _sidecars = hosts[host]
            slots = shard_pairs(host, pairs_by_mutant)
            planned.update(*slots)
            host_scope = copy.copy(scope)
            if derived is not None:
                # A supplement names its own reviewed collection freeze.
                host_scope.workloads = copy.deepcopy(scope.workloads)
                host_scope.workloads[role]["reference_source_tag"] = identity.get("reference_source_tag")
            if host in failed:
                observation, host_planned = _load_failed_host(
                    host_root, role=role, scope=host_scope, shard_pairs=slots, portable=portable)
                pending |= host_planned - set(observation["outcomes"])
                join(host, observation)
                continue
            host_scope.expected_pairs = frozenset().union(*slots)
            join(host, reader(host_root, role=role, scope=host_scope))
        if derived is not None and planned != derived:
            raise ReferenceControlsRefused("REFUSED: full-gold supplement differs from the unrun pairs")
        levels.append((group, failed, derived))
        if not groups:
            break
        if not pending:
            raise ReferenceControlsRefused(
                "REFUSED: a full-gold supplement requires a failed parent host")
        derived, pairs_by_mutant = pending, {}
        for item, mutant in pending:
            pairs_by_mutant.setdefault(mutant, set()).add(item)
        # A lone remaining supplement is read as the next level and refused by
        # its own readers; several are told apart by their planned shard sets.
        following = list(groups) if len(groups) == 1 else [
            plan for plan, members in groups.items() if continues(members, pairs_by_mutant)]
        if len(following) != 1:
            raise ReferenceControlsRefused(
                "REFUSED: no unique full-gold supplement continues the failed hosts")
        group = groups.pop(following[0])
    identities = [observations[host]["identity"] for members, _failed, _derived in levels
                  for host in members]
    try:
        mutation_run.validate_reference_host_partition_identities(
            identities, expected_pairs=scope.expected_pairs, observed_pairs=set(outcomes))
    except mutation_run.MutationAborted as exc:
        raise ReferenceControlsRefused(str(exc)) from exc
    host_facts = {host: copy.deepcopy(observation["facts"])
                  for host, observation in observations.items()}
    facts = {"observation_id": mutation_run.content_digest(host_facts)[:32],
             "host_observations": host_facts,
             "n_shards": sum(value["n_shards"] for value in host_facts.values()),
             "n_rows": len(outcomes), "n_pairs": len(outcomes),
             "pairs_sha256": mutation_run.pair_set_digest(outcomes)}
    chain = []
    for (before, failed, _derived), (members, _failed, derived) in zip(levels, levels[1:]):
        first, added = observations[before[0]]["identity"], observations[members[0]]["identity"]
        chain.append({
            "plan_sha256": added["reference_partition"]["supplement_plan_sha256"],
            "parent": {"reference_source_tag": first["reference_source_tag"],
                       "allocation_sha256": first["reference_partition"]["allocation_sha256"],
                       "failed_hosts": failed,
                       "failed_hosts_rows": sum(len(observations[host]["outcomes"]) for host in failed)},
            "supplement": {"reference_source_tag": added["reference_source_tag"],
                           "allocation_sha256": added["reference_partition"]["allocation_sha256"],
                           "hosts": members},
            "pending_pairs": len(derived),
            "pending_pairs_sha256": mutation_run.pair_set_digest(derived)})
    if chain:
        # `supplement` is the last level; the chain records every tag and plan.
        facts["supplement"], facts["supplement_chain"] = chain[-1], chain
    return SealedObservation({"role": role, "identity": copy.deepcopy(identities[0]),
        "outcomes": outcomes, "excluded": {pair: value for pair, value in outcomes.items()
            if _excluded_terminal_outcome(value, role)}, "facts": facts},
        _OBSERVATION_SEAL, root=os.path.abspath(root), portable=portable)


def load_native_observation(root: str, *, role: str,
                            scope: ReferenceScope) \
        -> SealedObservation:
    """Strictly load producer-side standalone evidence and seal it."""
    scope = _require_scope(scope)
    from . import reference_pair_continuation as PC
    if os.path.isfile(os.path.join(root, PC.MARKER)):
        # Producer-side assembly of a continuation stays on the harness-21
        # collector line; this tree reads the delivered aggregate only.
        raise ReferenceControlsRefused(
            "REFUSED: a continued Sylius319 reference observation is reopened "
            "only by the preserved reader; it mints no attestation here.")
    expected = scope.expected_pairs
    if (role == "full_gold" and set(scope.workloads) == {"full_gold"}
            and not os.path.isfile(os.path.join(root, mutation_run.MUTATION_OUTPUT_PLAN))):
        return _load_host_observations(root, role=role, scope=scope, portable=False)
    root, paths, _plan = _discover_paths(root)
    try:
        loaded = gold_killset.load_native_run(
            paths, required_side=ROLE_SIDE.get(role, ""))
        test_quality.validate_native_retry_evidence(
            [row for path in paths for row in test_quality.load_jsonl(path)],
            where=f"{role} reference observation")
    except (gold_killset.GoldKillsetRefused,
            test_quality.TestQualityRefused) as exc:
        raise ReferenceControlsRefused(str(exc)) from exc
    return _seal_observation(
        loaded, root=root, portable=False, role=role,
        expected_pairs=expected,
        plan_path=os.path.join(root, mutation_run.MUTATION_OUTPUT_PLAN),
        scope=scope)


def _portable_worker_preimage(sidecar: dict, identity: dict) -> None:
    resources = sidecar.get("worker_resources")
    if not isinstance(resources, list) or not resources \
            or len(resources) != identity.get("of") \
            or mutation_run.content_digest(resources) \
            != identity.get("worker_resources_sha256"):
        raise ReferenceControlsRefused(
            "REFUSED: preserved shard has no unchanged worker-resource "
            "preimage for its campaign identity.")


def load_preserved_observation(root: str, *, role: str,
                               scope: ReferenceScope) \
        -> SealedObservation:
    """Read a relocated observation without opening producer-host paths."""
    scope = _require_scope(scope)
    from . import reference_pair_continuation as PC
    if os.path.isfile(os.path.join(root, PC.MARKER)):
        if role not in PC.ROLE_BINDINGS:
            raise ReferenceControlsRefused("REFUSED: continued reference role differs")
        try:
            return PC.aggregate(root, scope=scope, role=role)
        except (OSError, ValueError, mutation_run.MutationAborted) as exc:
            raise ReferenceControlsRefused(str(exc)) from exc
    expected = scope.expected_pairs
    if (role == "full_gold" and set(scope.workloads) == {"full_gold"}
            and not os.path.isfile(os.path.join(root, mutation_run.MUTATION_OUTPUT_PLAN))):
        return _load_host_observations(root, role=role, scope=scope, portable=True)
    root, paths, plan = _discover_paths(root)
    identities = []
    outcomes = {}
    shard_facts = []
    rows_for_retry = []
    observation_id = None
    for path in paths:
        sidecar_path = mutation_run.provenance_path(path)
        try:
            with open(sidecar_path, encoding="utf-8") as handle:
                sidecar = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ReferenceControlsRefused(
                f"REFUSED: cannot read preserved sidecar {sidecar_path}: "
                f"{exc}") from exc
        identity = sidecar.get("campaign_identity") \
            if isinstance(sidecar, dict) else None
        _role_check(identity or {}, role, scope)
        _portable_worker_preimage(sidecar, identity)
        try:
            with open(path, encoding="utf-8") as handle:
                rows = [json.loads(line) for line in handle if line.strip()]
            if any(not isinstance(row, dict)
                   or not isinstance(row.get("item_id"), str)
                   or not row.get("item_id")
                   or not isinstance(row.get("mutant_id"), str)
                   or not row.get("mutant_id") for row in rows):
                raise ReferenceControlsRefused(
                    f"REFUSED: preserved {role} shard has a malformed row.")
            shard_pairs = {(row.get("item_id"), row.get("mutant_id"))
                           for row in rows}
            mutation_run.completed_pairs(
                path, identity, expected_pairs=shard_pairs,
                require_complete=True)
        except (OSError, json.JSONDecodeError,
                mutation_run.MutationAborted) as exc:
            raise ReferenceControlsRefused(str(exc)) from exc
        if len(shard_pairs) != len(rows):
            raise ReferenceControlsRefused(
                f"REFUSED: preserved {role} shard repeats a pair.")
        for row in rows:
            pair = (row["item_id"], row["mutant_id"])
            if pair in outcomes:
                raise ReferenceControlsRefused(
                    f"REFUSED: preserved {role} shards overlap on {pair!r}.")
            outcomes[pair] = row.get("outcome")
        current_observation = sidecar.get("observation_id")
        try:
            mutation_run.validate_observation_id(current_observation)
        except mutation_run.MutationAborted as exc:
            raise ReferenceControlsRefused(str(exc)) from exc
        if observation_id is None:
            observation_id = current_observation
        elif observation_id != current_observation:
            raise ReferenceControlsRefused(
                f"REFUSED: preserved {role} shards have mixed observation "
                "identities.")
        identities.append(identity)
        rows_for_retry.extend(rows)
        shard_facts.append((identity["shard"], {
            "rows_sha256": mutation_run.sha256_file(path),
            "sidecar_sha256": mutation_run.sha256_file(sidecar_path),
        }))

    identities.sort(key=lambda value: value["shard"])
    if [identity["shard"] for identity in identities] \
            != list(range(len(identities))) \
            or any(identity["of"] != len(identities)
                   for identity in identities):
        raise ReferenceControlsRefused(
            f"REFUSED: preserved {role} is not its exact zero-based shard "
            "set.")
    cores = [{key: value for key, value in identity.items()
              if key not in {"shard", "expected_pairs",
                             "expected_pairs_sha256"}}
             for identity in identities]
    if any(core != cores[0] for core in cores[1:]):
        raise ReferenceControlsRefused(
            f"REFUSED: preserved {role} shards carry mixed campaign cores.")
    representative = identities[0]
    try:
        planned_observation = mutation_run._validate_standalone_output_plan(
            plan, representative)
        test_quality.validate_native_retry_evidence(
            rows_for_retry, where=f"preserved {role} reference observation")
    except (mutation_run.MutationAborted,
            test_quality.TestQualityRefused) as exc:
        raise ReferenceControlsRefused(str(exc)) from exc
    if planned_observation != observation_id:
        raise ReferenceControlsRefused(
            f"REFUSED: preserved {role} plan and sidecars name different "
            "observation identities.")
    shard_facts.sort(key=lambda value: value[0])
    facts = {
        "observation_id": observation_id,
        "campaign_identity_sha256":
            mutation_run.campaign_identity_digest(representative),
        "rows_sha256": [facts["rows_sha256"]
                        for _shard, facts in shard_facts],
        "sidecars_sha256": [facts["sidecar_sha256"]
                            for _shard, facts in shard_facts],
        "n_shards": len(identities),
        "n_rows": len(outcomes),
        "n_pairs": len(outcomes),
        "pairs_sha256": mutation_run.pair_set_digest(outcomes),
    }
    return _seal_observation(
        {"identity": representative, "outcomes": outcomes, "facts": facts},
        root=root, portable=True, role=role, expected_pairs=expected,
        plan_path=os.path.join(root, mutation_run.MUTATION_OUTPUT_PLAN),
        scope=scope)


def _control_facts(observation: SealedObservation) -> dict:
    facts = observation["facts"]
    return {"role": observation["role"], **copy.deepcopy(facts)}


def _derive_reference_controls(
        scope: ReferenceScope,
        observations: Mapping[str, SealedObservation], *,
        allow_excluded_pairs: object,
        sensitivity: Optional[str] = None,
        gold_disagreements: frozenset = frozenset(),
        gold_disagreements_binding: Optional[dict] = None) \
        -> tuple[dict, frozenset]:
    """The attestation and the scored pair set it was computed over.

    `sensitivity` names a labelled basis of `SENSITIVITY_PROJECTS`: the
    derivation is unchanged except that a failed stub gate is recorded
    (`eligible: false`) instead of refusing, the label is recorded, and
    `gold_disagreements` -- pairs the scoring host's gold did not kill --
    leave each item's `full_gold_kills` and `hard_subset` (a candidate is
    never asked to kill what this host's gold does not): the stub recalls
    and gate stay those of the stored observations, so the recorded
    diagnostic is the reference's own on every scoring host.  The disagreements
    document's `source` and `sha256` (`gold_disagreements_binding`) are
    recorded beside the pairs.  Without a label all three extra arguments
    must be empty, so every eligible attestation keeps its bytes.
    """
    if sensitivity is None and (gold_disagreements
                                or gold_disagreements_binding is not None):
        raise ReferenceControlsRefused(
            "REFUSED: gold disagreements narrow only a labelled sensitivity "
            "basis.")
    if gold_disagreements and gold_disagreements_binding is None:
        raise ReferenceControlsRefused(
            "REFUSED: gold disagreements need the source and SHA-256 of the "
            "document that lists them.")
    if sensitivity is not None and sensitivity not in SENSITIVITY_PROJECTS:
        raise ReferenceControlsRefused(
            f"REFUSED: unknown reference sensitivity {sensitivity!r}; known: "
            f"{sorted(SENSITIVITY_PROJECTS)}.")
    roles = tuple(scope.workloads)
    full_only = roles == ("full_gold",)
    if sensitivity is not None and full_only:
        raise ReferenceControlsRefused(
            "REFUSED: a labelled sensitivity basis waives the stub gate of a "
            "three-role reference; a full-gold-only reference has none.")
    if set(observations) != set(roles):
        raise ReferenceControlsRefused("REFUSED: observation roles differ from sealed scope")
    expected = scope.expected_pairs
    for role in roles:
        observation = observations[role]
        if not authenticated_observation(observation):
            raise ReferenceControlsRefused(
                "REFUSED: reference input is not an unchanged sealed "
                "observation.")
        if observation["role"] != role:
            raise ReferenceControlsRefused(
                "REFUSED: reference observations were supplied under another "
                "role.")
        # The scope an observation was READ under need not be the scope the
        # attestation is derived under.  Both checks therefore run against
        # THIS scope: without them a caller that mixed two scopes would get a
        # bare KeyError out of the per-item loop below instead of a refusal
        # naming the role and the directory it came from.
        _role_check(observation["identity"], role, scope)
        covered = set(observation["outcomes"])
        if covered != expected:
            raise ReferenceControlsRefused(
                f"REFUSED: {role} at {observation._root} does not cover the "
                f"exact complete mapped pair set: {len(expected - covered)} "
                f"missing and {len(covered - expected)} unexpected pair(s).")
    observation_ids = [observations[role]["facts"]["observation_id"]
                       for role in roles]
    if len(set(observation_ids)) != len(roles):
        raise ReferenceControlsRefused(
            "REFUSED: full gold, stripped gold, and stub require three "
            "distinct observation identities.")
    first_identity = observations["full_gold"]["identity"]
    for role in roles[1:]:
        identity = observations[role]["identity"]
        changed = sorted(field for field in SHARED_IDENTITY_FIELDS
                         if identity.get(field) != first_identity.get(field))
        if changed:
            raise ReferenceControlsRefused(
                f"REFUSED: {role} differs from full_gold in stable "
                f"population/execution field(s) {changed}.")

    # Section 5.1.  A terminal timeout or infrastructure outcome is the
    # harness failing rather than a mutant surviving, so its pair leaves the
    # scored universe instead of being imputed.  The exclusion is the UNION
    # over the three roles and applies to all three: G, S and the stub kill
    # set are only comparable while they are computed over ONE universe, and
    # a per-role exclusion would silently print three different denominators
    # as though they were the same one.
    causes: dict[tuple[str, str], list[dict]] = {}
    for role in roles:
        for pair, outcome in sorted(observations[role]["excluded"].items()):
            causes.setdefault(pair, []).append(
                {"role": role, "outcome": outcome})
    excluded = frozenset(causes)
    scored = expected - excluded
    if excluded and not allow_excluded_pairs:
        raise ReferenceControlsRefused(
            f"REFUSED: the reference observations end on "
            f"{len(excluded)} pair(s) whose terminal outcome is a timeout or "
            f"the harness failing rather than a mutant surviving, e.g. "
            f"{sorted(causes)[:3]}. Section 5.1 drops those pairs from the "
            f"scored universe of the selected roles rather than imputing an "
            f"outcome for them, and that narrowing must be consented to "
            f"explicitly: pass allow_excluded_pairs=True, which records the "
            f"count and the per-pair disclosure in the attestation (owner "
            f"ruling 2.6: nothing is tolerated silently).")

    # Every mapped item keeps a row even when the exclusion empties it: an
    # item scored over nothing is `not_scorable` exactly as an item with an
    # empty hard subset is, and dropping it would make the artifact's item
    # roster depend on which pairs happened to flake.
    by_item: dict[str, set[str]] = {item_id: set() for item_id, _m in expected}
    for item_id, mutant_id in scored:
        by_item[item_id].add(mutant_id)
    stored_kills = {pair for pair in scored
                    if observations["full_gold"]["outcomes"][pair] == "failed"}
    not_stored = sorted(set(gold_disagreements) - stored_kills)
    if not_stored:
        raise ReferenceControlsRefused(
            f"REFUSED: {len(not_stored)} gold disagreement pair(s) are not "
            f"scored full-gold kills of this reference, e.g. {not_stored[:3]}.")
    items = {}
    stub_recalls = []
    hard_count = 0
    for item_id in sorted(by_item):
        mapped = by_item[item_id]
        # The stored full-gold kills: the stub recall is the reference's
        # own, whatever a scoring host's pilot found.
        gold = {mutant_id for mutant_id in mapped
                if observations["full_gold"]["outcomes"][
                    (item_id, mutant_id)] == "failed"}
        if full_only:
            items[item_id] = {"full_gold_kills": sorted(gold),
                              "hard_subset": None, "scorable": bool(gold),
                              "stub_recall": None}
            continue
        stripped_passed = {mutant_id for mutant_id in mapped
                           if observations["stripped_gold"]["outcomes"][
                               (item_id, mutant_id)] == "passed"}
        hard = gold & stripped_passed
        stub_kills = {mutant_id for mutant_id in mapped
                      if observations["stub"]["outcomes"][
                          (item_id, mutant_id)] == "failed"}
        recall = None if not gold else len(stub_kills & gold) / len(gold)
        if recall is not None:
            stub_recalls.append(recall)
        # Only the candidate's bases lose a pilot's disagreements; an
        # eligible derivation has none, so its sets are unchanged.
        disagreed = {mutant_id for mutant_id in gold
                     if (item_id, mutant_id) in gold_disagreements}
        hard -= disagreed
        hard_count += len(hard)
        items[item_id] = {
            "full_gold_kills": sorted(gold - disagreed),
            "hard_subset": sorted(hard),
            "scorable": bool(hard),
            "stub_recall": recall,
        }
    if full_only and not any(item["full_gold_kills"] for item in items.values()):
        raise ReferenceControlsRefused(
            "REFUSED: every project item has an empty full-gold kill set over "
            f"the {len(scored)} scored pair(s).")
    if not full_only and hard_count == 0:
        raise ReferenceControlsRefused(
            f"REFUSED: every project item has an empty hard subset over the "
            f"{len(scored)} scored pair(s).")
    stub_macro = sum(stub_recalls) / len(stub_recalls) \
        if stub_recalls else 0.0
    if stub_macro > STUB_RECALL_THRESHOLD and sensitivity is None:
        raise ReferenceControlsRefused(
            f"REFUSED: stub macro recall {stub_macro} exceeds the reviewed "
            f"{STUB_RECALL_THRESHOLD} eligibility threshold.")

    document = {
        "schema": SCHEMA,
        "method": METHOD,
        "reference_observation_count": REFERENCE_OBSERVATION_COUNT,
        "population": copy.deepcopy(scope.population),
        # Both universes travel: `count`/`sha256` are the pair set the three
        # observations were required to cover -- the complete mapped set, or,
        # for a declared reference, its restriction to the declared items,
        # whose `declared_subset` block names what that removed -- and
        # `scored_*` is the narrowed set every number below was computed
        # over after section 5.1.
        "pairs": {
            "count": len(expected),
            "sha256": mutation_run.pair_set_digest(expected),
            "excluded_count": len(excluded),
            "scored_count": len(scored),
            "scored_sha256": mutation_run.pair_set_digest(scored),
        },
        # One entry per excluded pair, carrying every role that produced a
        # section 5.1 outcome on it and that role's exact outcome string, in
        # ROLES order.  A pair two roles both flaked on is one exclusion, not
        # two, so the list length is the excluded count.
        "excluded_pairs": [
            {"item_id": item_id, "mutant_id": mutant_id,
             "causes": causes[(item_id, mutant_id)]}
            for item_id, mutant_id in sorted(causes)],
        "allow_excluded_pairs": bool(allow_excluded_pairs),
        "authority": {
            **copy.deepcopy(scope.authority),
            **{field: first_identity.get(field)
               for field in sorted(SHARED_IDENTITY_FIELDS)},
        },
        "observations": {role: _control_facts(observations[role])
                         for role in roles},
        "items": items,
        "stub_gate": {
            "threshold": STUB_RECALL_THRESHOLD,
            "items": len(stub_recalls),
            "macro_recall": stub_macro,
            "eligible": stub_macro <= STUB_RECALL_THRESHOLD,
        },
        "hard_scorable_items": sum(item["scorable"]
                                   for item in items.values()),
    }
    if full_only:
        document.update(reference_basis="full_gold", stub_gate=None,
                        hard_scorable_items=None)
    if scope.declaration is not None:
        # Recorded only when a declaration was made, so an artifact minted
        # over a whole mapped population is byte-identical to one minted
        # before this rule existed -- the same discipline `paid_view_subset`
        # follows.  The omitted ids and the operator's reason live here; the
        # counts are what travel beside a rendered number.
        document["declared_subset"] = copy.deepcopy(scope.declaration)
    if sensitivity is not None:
        # Recorded only for the labelled basis, so an eligible attestation is
        # byte-identical to one minted before the basis existed.
        document["sensitivity"] = sensitivity
        binding = gold_disagreements_binding or {}
        document["gold_disagreements"] = {
            "source": binding.get("source"),
            "sha256": binding.get("sha256"),
            "pairs": [{"item_id": item_id, "mutant_id": mutant_id}
                      for item_id, mutant_id in sorted(gold_disagreements)],
        }
    document["digest"] = artifact_digest(document)
    return document, scored


def build_reference_controls(
        scope: ReferenceScope, *, full_gold: SealedObservation,
        stripped_gold: SealedObservation = None, stub: SealedObservation = None,
        allow_excluded_pairs: bool = False) -> dict:
    """Mint an attestation only from strict producer-authenticated controls.

    `allow_excluded_pairs` is the operator's recorded consent to section
    5.1's narrowing, and is exactly the fact `--allow-degraded-gold` records
    on the existing route: silence is not consent, so an observation set that
    produced any excluded pair refuses without it.
    """
    scope = _require_scope(scope)
    supplied = {role: observation for role, observation in
                (("full_gold", full_gold), ("stripped_gold", stripped_gold), ("stub", stub))
                if observation is not None}
    if any(not authenticated_observation(observation)
           or observation._portable for observation in supplied.values()):
        raise ReferenceControlsRefused(
            "REFUSED: reference-controls minting requires three strict "
            "producer-authenticated native observations; portable evidence "
            "may only validate an existing attestation.")
    document, _scored = _derive_reference_controls(
        scope, supplied, allow_excluded_pairs=allow_excluded_pairs)
    return document


def validate_reference_controls(
        document: dict, *, scope: ReferenceScope,
        full_gold: SealedObservation, stripped_gold: SealedObservation = None,
        stub: SealedObservation = None) -> ReferenceControls:
    """Rederive an attestation and return its authenticated joined form."""
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise ReferenceControlsRefused(
            f"REFUSED: expected reference-controls schema {SCHEMA!r}.")
    scope = _require_scope(scope)
    supplied = {role: observation for role, observation in
                (("full_gold", full_gold), ("stripped_gold", stripped_gold), ("stub", stub))
                if observation is not None}
    # The consent is a recorded fact OF the artifact here, not a decision
    # taken again: re-demanding it at read time would make a properly minted,
    # properly disclosed artifact unloadable by the consumer it was minted
    # for.  An artifact that carries exclusions WITHOUT the consent is still
    # refused, by this same derivation, because that is not a disclosure.
    rebuilt, scored = _derive_reference_controls(
        scope, supplied,
        allow_excluded_pairs=document.get("allow_excluded_pairs"))
    if document != rebuilt:
        raise ReferenceControlsRefused(
            "REFUSED: reference-controls attestation does not rederive from "
            "its preserved observations and complete pair set.")
    controls = ReferenceControls(
        copy.deepcopy(document), expected_pairs=scored,
        observations=supplied, seal=_CONTROLS_SEAL)
    controls._evaluation_scope = copy.deepcopy(
        getattr(scope, "_evaluation_scope", None))
    return controls


def sensitivity_reference_controls(
        scope: ReferenceScope, *, full_gold: SealedObservation,
        stripped_gold: SealedObservation, stub: SealedObservation,
        sensitivity: str, allow_excluded_pairs: bool,
        gold_disagreements: frozenset = frozenset(),
        gold_disagreements_binding: Optional[dict] = None) \
        -> ReferenceControls:
    """Join three sealed observations under a labelled sensitivity basis.

    The derivation -- `G_i`, the hard subset, the stub recalls -- the section
    5.1 union and its recorded consent are the attestation's own; only the
    stub gate is recorded as a diagnostic rather than enforced.
    Relocated (portable) observations are accepted because nothing is
    minted: the result lives in memory for one scoring command and is never
    written as an attestation, so it cannot be reopened as eligible controls.
    """
    scope = _require_scope(scope)
    if sensitivity not in SENSITIVITY_PROJECTS:
        raise ReferenceControlsRefused(
            f"REFUSED: unknown reference sensitivity {sensitivity!r}; known: "
            f"{sorted(SENSITIVITY_PROJECTS)}.")
    supplied = {"full_gold": full_gold, "stripped_gold": stripped_gold,
                "stub": stub}
    document, scored = _derive_reference_controls(
        scope, supplied, allow_excluded_pairs=allow_excluded_pairs,
        sensitivity=sensitivity,
        gold_disagreements=frozenset(gold_disagreements),
        gold_disagreements_binding=gold_disagreements_binding)
    controls = ReferenceControls(
        document, expected_pairs=scored, observations=supplied,
        seal=_CONTROLS_SEAL)
    controls._evaluation_scope = copy.deepcopy(
        getattr(scope, "_evaluation_scope", None))
    return controls


def load_gold_disagreements(path: str) -> tuple[frozenset, dict]:
    """Read a gold-agreement pilot's disagreement list and its binding.

    The binding is the document's own `source` and its SHA-256, which the
    controls and every summary scored under them record beside the pairs.
    """
    document = _load_json(path, "gold disagreements")
    pairs = document.get("pairs")
    if set(document) != {"schema", "source", "pairs"} \
            or document.get("schema") != GOLD_DISAGREEMENTS_SCHEMA \
            or not isinstance(document.get("source"), str) \
            or not document["source"].strip() \
            or not isinstance(pairs, list) \
            or not all(isinstance(pair, list) and len(pair) == 2
                       and all(isinstance(value, str) and value
                               for value in pair) for pair in pairs):
        raise ReferenceControlsRefused(
            f"REFUSED: {path} is not a {GOLD_DISAGREEMENTS_SCHEMA} document "
            "with a named source and an [item, mutant] pair list.")
    unique = frozenset(tuple(pair) for pair in pairs)
    if len(unique) != len(pairs):
        raise ReferenceControlsRefused(
            f"REFUSED: gold disagreements {path} repeat a pair.")
    return unique, {"source": document["source"],
                    "sha256": mutation_run.sha256_file(path)}


def load_preserved_reference_controls(
        root: str, document: dict, *, scope: ReferenceScope) \
        -> ReferenceControls:
    """Open ``full_gold/``, ``stripped_gold/`` and ``stub/`` after moving."""
    scope = _require_scope(scope)
    observations = {
        role: load_preserved_observation(
            os.path.join(root, role), role=role, scope=scope)
        for role in control_roles(document)
    }
    return validate_reference_controls(document, scope=scope, **observations)


def write(document: dict, path: str) -> str:
    """Install one minted attestation at an immutable path."""
    _digest_checked(document)
    try:
        return mutation_run.atomic_write_json(path, document,
                                              refuse_existing=True)
    except mutation_run.MutationAborted as exc:
        raise ReferenceControlsRefused(str(exc)) from exc


def load(path: str) -> dict:
    """Read an installed attestation, digest first.

    The artifact's identity IS this digest -- it pins no VERSIONS.yml entry,
    because the v2 scoring route joins it to the three preserved observations
    rather than to a registry.  Rederiving the digest here is what makes the
    bytes on disk the document the minting run signed; `artifact_digest` is
    already computed and read on every mint, so this adds no new hash.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReferenceControlsRefused(
            f"REFUSED: cannot read reference controls {path}: {exc}") from exc
    return _digest_checked(document)


def reference_sets(controls: ReferenceControls) -> ReferenceSets:
    """Return the only mutation sets candidate scoring needs.

    `expected_pairs` is the SCORED universe -- the complete mapped set minus
    section 5.1's exclusions -- because that is the set a candidate may be
    restricted to and scored over.
    """
    if not authenticated_reference_controls(controls):
        raise ReferenceControlsRefused(
            "REFUSED: scoring requires unchanged authenticated reference "
            "controls.")
    items = controls["items"]
    declaration = controls.get("declared_subset") or {}
    full_only = controls.get("reference_basis") == "full_gold"
    return ReferenceSets(
        reference_basis="full_gold" if full_only else "hard_subset",
        expected_pairs=controls._expected_pairs,
        excluded_count=controls["pairs"]["excluded_count"],
        omitted_items=tuple(declaration.get("omitted_items") or ()),
        declared_reason=declaration.get("reason"),
        full_gold_kills=MappingProxyType({
            item_id: frozenset(item["full_gold_kills"])
            for item_id, item in items.items()}),
        hard_subset=None if full_only else MappingProxyType({
            item_id: frozenset(item["hard_subset"])
            for item_id, item in items.items()}),
        stub_recall_by_item=None if full_only else MappingProxyType({
            item_id: item["stub_recall"]
            for item_id, item in items.items()}),
        stub_macro_recall=None if full_only else controls["stub_gate"]["macro_recall"],
        stub_threshold=None if full_only else controls["stub_gate"]["threshold"],
        eligible=True if full_only else controls["stub_gate"]["eligible"],
        sensitivity=controls.get("sensitivity"), seal=_SETS_SEAL)


def selftest() -> int:
    """Network-free preservation and derivation probes."""
    import shutil
    import tempfile

    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail else ""))
        ok = ok and bool(condition)

    def refuses(name, function, needle):
        try:
            function()
        except ReferenceControlsRefused as exc:
            check(name, needle in str(exc), str(exc))
            return
        check(name, False, "accepted")

    pairs = frozenset()
    scope = None
    worker_resources = [{
        "index": 0,
        "worker_spec": "/producer/workers/worker0.json",
        "workspace": "/producer/workspaces/worker0",
        "container": "reference-worker-0",
        "schema": "no_database",
        "credential": "none",
        "env_file": "/producer/workers/worker0.env",
        "workdir": "/workspace",
        "runtime_attestation": "/producer/workers/worker0.runtime.json",
        "runtime_attestation_sha256": "a" * 64,
    }]
    fixture_workspace_digest = "b" * 64
    fixture_database_digest = "no_database"

    def fixture_identity(role, observation_pairs):
        population = scope.population
        workload = scope.workloads[role]
        generated = workload["generated_tests_sha256"]
        base = mutation_run.build_campaign_identity(
            asset_index_sha256=population["asset_index_sha256"],
            asset_project=population["asset_project"],
            mutation_validation_sha256="1" * 64,
            mutation_validation_class="native",
            manifest_sha256=population["manifest_sha256"],
            manifest_digest=population["manifest_digest"],
            map_sha256=population["map_sha256"],
            release_sha256=population["release_sha256"],
            candidate_run_sha256=workload["candidate_run_sha256"],
            candidate_generated_tests_sha256=generated,
            solution_generated_tests_sha256=generated,
            substrate_baseline_sha256="8" * 64,
            applier_sha256="9" * 64,
            worker_resources_sha256=mutation_run.content_digest(
                worker_resources),
            harness_version=6,
            container_image_digest="sha256:" + "a" * 64,
            workspace_seed_digest=fixture_workspace_digest,
            database_dump_digest=fixture_database_digest,
            expected_pairs=observation_pairs,
            engine=population["engine"],
            engine_version=population["engine_version"],
            parser=population["parser"], side=ROLE_SIDE[role],
            shard=0, of=1, timeout=600,
            generation_provenance_class="native_v2",
            generation_attempt_id=f"fixture-{role}",
            generation_campaign_digest={
                "full_gold": "a", "stripped_gold": "b", "stub": "c",
            }[role] * 16,
            generation_agent_runtime_sha256="d" * 64,
            generation_network_semantics="network_none",
            generation_condition=role,
            generation_protocol_version=4,
            generation_protocol_digest="e" * 16,
            generation_native_budget={"fixture": True})
        reference = {
            key: base[key]
            for key in mutation_run.CAMPAIGN_IDENTITY_FIELDS_V1
        }
        reference.update({
            "schema": mutation_run.MUTATION_IDENTITY_SCHEMA_V5,
            "generation_provenance_class":
                mutation_run.GENERATION_PROVENANCE_REFERENCE_CONTROL,
            "reference_control_role": IDENTITY_REFERENCE_ROLE[role],
            "reference_source_tag": workload["reference_source_tag"],
            "reference_workload_digest":
                workload["reference_workload_digest"],
        })
        mutation_run._validate_campaign_identity(reference)
        return reference

    def write_observation(container, role, outcomes, observation_id):
        directory = os.path.join(container, role)
        path = os.path.join(directory,
                            f"{ROLE_SIDE[role]}.w0.jsonl")
        identity = fixture_identity(role, set(outcomes))
        mutation_run.prepare_standalone_output_directory(
            path, identity, observation_id)
        with open(path, "w", encoding="utf-8") as handle:
            for (item_id, mutant_id), outcome in sorted(outcomes.items()):
                # The producer retries exactly the outcomes ITS loop fires
                # on, and `validate_native_retry_evidence` reads that stamp
                # back, so a fixture carrying section 5.1 rows has to stamp
                # the retry it would really have made.
                attempt = 2 if outcome in \
                    mutation_run.INFRASTRUCTURE_OUTCOMES else 1
                handle.write(json.dumps({
                    "item_id": item_id, "mutant_id": mutant_id,
                    "outcome": outcome, "attempt": attempt,
                    "retried_infrastructure": attempt == 2,
                    **mutation_run.row_identity_stamp(identity),
                }, sort_keys=True) + "\n")
        provenance = {"worker_resources": worker_resources}
        mutation_run.write_shard_provenance(
            path, identity, "running", provenance=provenance)
        mutation_run.write_shard_provenance(
            path, identity, "complete", provenance=provenance)

    with tempfile.TemporaryDirectory() as temporary:
        release_path = os.path.join(temporary, "release.jsonl")
        with open(release_path, "w", encoding="utf-8") as handle:
            for item_id in ("item-a", "item-b"):
                handle.write(json.dumps({"item_id": item_id}) + "\n")
        raw_mutants = [{
            "file": (f"src/CoreShop/Component/Fixture/example{number}.php"),
            "operator": "Increment",
            "start_line": number, "start_col": 1,
            "original": str(number), "mutated": str(number + 1),
        } for number in range(1, 5)]
        manifest = mutation.build_manifest(
            raw_mutants, parser_version="fixture-parser")
        manifest_path = os.path.join(temporary, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, sort_keys=True)
        m1, m2, m3, m4 = [row["id"] for row in manifest["mutants"]]
        mapping = mutation_attestation.build_map_artifact(
            manifest,
            {m1: ["item-a"], m2: ["item-a"], m3: ["item-a"],
             m4: ["item-b"]}, [],
            coverage_sha256="c" * 64,
            release_sha256=mutation_run.sha256_file(release_path))
        map_path = os.path.join(temporary, "map.json")
        with open(map_path, "w", encoding="utf-8") as handle:
            json.dump(mapping, handle, sort_keys=True)
        baseline_path = os.path.join(temporary, "gold-baseline.jsonl")
        baseline_rows = [{
            "item_id": item_id, "outcome": "passed",
            "produced_files": [{
                "file_path": f"tests/{item_id}.py",
                "code": f"assert {item_id!r}",
            }],
        } for item_id in ("item-a", "item-b")]
        with open(baseline_path, "w", encoding="utf-8") as handle:
            for row in baseline_rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
        baseline_files = test_quality.passed_solutions(baseline_rows)
        workloads = {
            "full_gold": {
                "candidate_run_sha256":
                    mutation_run.sha256_file(baseline_path),
                "generated_tests_sha256":
                    mutation_run.candidate_digest(baseline_files),
                "reference_source_tag": "fixture-reference-v1",
                "reference_workload_digest": "1" * 64,
            },
            "stripped_gold": {
                "candidate_run_sha256": "2" * 64,
                "generated_tests_sha256": "3" * 64,
                "reference_source_tag": "fixture-reference-v1",
                "reference_workload_digest": "4" * 64,
            },
            "stub": {
                "candidate_run_sha256": "5" * 64,
                "generated_tests_sha256": "6" * 64,
                "reference_source_tag": "fixture-reference-v1",
                "reference_workload_digest": "7" * 64,
            },
        }
        # The fixture population borrows python-docx-v1's registered id and
        # asset index so `_role_check` resolves the REAL envelope-equivalence
        # ledger below; its catalogue is the synthetic manifest above, which
        # is why the rest of the entry stays a fixture.
        registered_index = versions.population(
            "python-docx-v1")["asset_index_sha256"]
        fixture_population = {
            "schema": "r2t.population/1", "project": "fixture-project",
            "asset_project": "fixture-project", "generation": 1,
            "asset_index_sha256": registered_index,
            "engine": manifest["engine"],
            "engine_version": manifest["engine_version"],
            "parser": manifest["parser"],
        }
        original_population = versions.population
        original_resolve = versions.population_id_for

        def seal_fixture_scope(bindings, *, release=None, mapping=None,
                               gold_baseline=None, declared_subset=None):
            versions.population = lambda value: (
                fixture_population if value == "python-docx-v1"
                else original_population(value))
            versions.population_id_for = lambda project, digest, **kw: (
                "python-docx-v1" if project == "fixture-project"
                and digest == manifest["digest"] else original_resolve(
                    project, digest, **kw))
            try:
                return seal_reference_scope(
                    "python-docx-v1", manifest_path=manifest_path,
                    map_path=mapping or map_path,
                    release_path=release or release_path,
                    gold_baseline_path=gold_baseline or baseline_path,
                    workloads=bindings, declared_subset=declared_subset)
            finally:
                versions.population = original_population
                versions.population_id_for = original_resolve

        scope = seal_fixture_scope(workloads)
        pairs = scope.expected_pairs
        check("the public scope bridge is the only way in and derives the "
              "expected pair set from the validated map",
              authenticated_reference_scope(scope)
              and pairs == frozenset({
                  ("item-a", m1), ("item-a", m2), ("item-a", m3),
                  ("item-b", m4)}))

        ruled_index = versions.equivalent_asset_indexes("python-docx-v1")[0]
        renamed_envelope = fixture_identity("full_gold", set(pairs))
        renamed_envelope["asset_index_sha256"] = ruled_index
        try:
            _role_check(renamed_envelope, "full_gold", scope)
            resolved = True
        except ReferenceControlsRefused as exc:
            resolved = str(exc)
        check("an observation stamped with the CURRENT asset index is this "
              "population's, though it is registered under the legacy one -- "
              "the 2026-09-01 envelope-equivalence ruling",
              resolved is True, str(resolved))
        unruled_envelope = fixture_identity("full_gold", set(pairs))
        unruled_envelope["asset_index_sha256"] = "f" * 64
        try:
            _role_check(unruled_envelope, "full_gold", scope)
            check("an asset index no ruling equates still refuses, naming "
                  "both digests it compared", False, "accepted")
        except ReferenceControlsRefused as exc:
            check("an asset index no ruling equates still refuses, naming "
                  "both digests it compared",
                  "f" * 64 in str(exc) and registered_index in str(exc)
                  and ruled_index in str(exc), str(exc))

        # Producer-side validation has live worker/seed preimages.  They are
        # moved away after strict loading to prove the installed reader does
        # not consult those recorded absolute paths.
        from . import worker
        producer = os.path.join(temporary, "producer")
        seed_dir = os.path.join(producer, "seed")
        os.makedirs(seed_dir)
        workspace_tar = os.path.join(seed_dir, "workspace.tar")
        database_sql = os.path.join(seed_dir, "database.sql")
        with open(workspace_tar, "wb") as handle:
            handle.write(b"reference controls workspace seed")
        with open(database_sql, "wb") as handle:
            handle.write(b"reference controls database seed")
        fixture_workspace_digest = mutation_run.sha256_file(workspace_tar)
        fixture_database_digest = mutation_run.sha256_file(database_sql)
        with open(os.path.join(seed_dir, "seed.json"), "w",
                  encoding="utf-8") as handle:
            json.dump({
                "format": 1, "seed_key": "reference-controls-fixture",
                "needs_database": True,
                "workspace": {"digest": fixture_workspace_digest},
                "database": {"digest": fixture_database_digest},
            }, handle, sort_keys=True)
        seed_identity = worker.verified_seed_identity(seed_dir, True)
        worker_spec = worker.WorkerSpec(
            index=0,
            workspace=os.path.join(producer, "workspace-0"),
            container="reference-worker-0", schema="reference_schema_0",
            credential="reference_user_0",
            env_file=os.path.join(producer, "worker0.env"))
        worker_spec_path = os.path.join(producer, "worker0.json")
        with open(worker_spec_path, "w", encoding="utf-8") as handle:
            json.dump(worker_spec.to_json(), handle, sort_keys=True)
        runtime_path = worker.runtime_attestation_path(worker_spec_path)
        runtime = {
            "schema": worker.WORKER_RUNTIME_SCHEMA_V2,
            "worker": worker_spec.to_json(),
            "worker_spec_sha256": mutation_run.sha256_file(worker_spec_path),
            **seed_identity,
            "container_image_digest": "sha256:" + "a" * 64,
            "docker_endpoint_selection": "legacy-default",
            "harness_version": 6,
        }
        with open(runtime_path, "w", encoding="utf-8") as handle:
            json.dump(runtime, handle, sort_keys=True)
        worker_resources = [{
            "index": 0,
            "worker_spec": os.path.realpath(worker_spec_path),
            "workspace": os.path.realpath(worker_spec.workspace),
            "container": worker_spec.container,
            "schema": worker_spec.schema,
            "credential": worker_spec.credential,
            "env_file": os.path.realpath(worker_spec.env_file),
            "workdir": worker_spec.workdir,
            "runtime_attestation": os.path.realpath(runtime_path),
            "runtime_attestation_sha256":
                mutation_run.sha256_file(runtime_path),
        }]

        source = os.path.join(temporary, "source")
        os.mkdir(source)
        # G_a = {m1, m2, m3}, S_a = {m1, m3}, so H_a = {m1, m3}.  item-b's
        # only pair survives full gold, so G_b and H_b are empty and item-b
        # is the not-scorable item throughout.
        clean = {
            "full_gold": {("item-a", m1): "failed", ("item-a", m2): "failed",
                          ("item-a", m3): "failed", ("item-b", m4): "passed"},
            "stripped_gold": {("item-a", m1): "passed",
                              ("item-a", m2): "failed",
                              ("item-a", m3): "passed",
                              ("item-b", m4): "passed"},
            "stub": {pair: "passed" for pair in pairs},
        }
        for role, observation_id in zip(ROLES, ("1" * 32, "2" * 32, "3" * 32)):
            write_observation(source, role, clean[role], observation_id)

        native = {
            role: load_native_observation(
                os.path.join(source, role), role=role,
                scope=scope)
            for role in ROLES
        }
        check("current standalone controls are strictly producer-authenticated",
              all(authenticated_observation(value)
                  for value in native.values()))
        document = build_reference_controls(
            scope, full_gold=native["full_gold"],
            stripped_gold=native["stripped_gold"], stub=native["stub"])

        # The section 5.1 tree.  The STUB flakes on (item-a, m1), which full
        # gold kills and stripped gold survives -- so m1 is in H until the
        # exclusion removes it from all three roles, and a per-role exclusion
        # would leave it there.  item-b's only pair is flaked by two roles at
        # once, which is what one disclosure entry with two causes looks like.
        excluded_outcomes = {
            "full_gold": clean["full_gold"],
            "stripped_gold": {**clean["stripped_gold"],
                              ("item-b", m4): "timeout"},
            "stub": {**clean["stub"],
                     ("item-a", m1): "container_error",
                     ("item-b", m4): "setup_error"},
        }
        excluded_source = os.path.join(temporary, "excluded")
        for role, observation_id in zip(ROLES, ("8" * 32, "9" * 32, "a" * 32)):
            write_observation(excluded_source, role,
                              excluded_outcomes[role], observation_id)
        excluded_native = {
            role: load_native_observation(
                os.path.join(excluded_source, role), role=role, scope=scope)
            for role in ROLES
        }
        refuses("section 5.1 pairs are excluded, never imputed, and never "
                "without the operator's recorded consent",
                lambda: build_reference_controls(
                    scope, full_gold=excluded_native["full_gold"],
                    stripped_gold=excluded_native["stripped_gold"],
                    stub=excluded_native["stub"]), "allow_excluded_pairs=True")
        excluded_document = build_reference_controls(
            scope, full_gold=excluded_native["full_gold"],
            stripped_gold=excluded_native["stripped_gold"],
            stub=excluded_native["stub"], allow_excluded_pairs=True)
        check("one disclosure entry per excluded pair names every causing "
              "role and its exact terminal outcome",
              excluded_document["excluded_pairs"] == [
                  {"item_id": "item-a", "mutant_id": m1,
                   "causes": [{"role": "stub",
                               "outcome": "container_error"}]},
                  {"item_id": "item-b", "mutant_id": m4,
                   "causes": [{"role": "stripped_gold", "outcome": "timeout"},
                              {"role": "stub", "outcome": "setup_error"}]}]
              and excluded_document["allow_excluded_pairs"] is True)
        check("the complete mapped set and the narrowed scored set both "
              "travel with the attestation",
              excluded_document["pairs"] == {
                  "count": 4,
                  "sha256": mutation_run.pair_set_digest(pairs),
                  "excluded_count": 2, "scored_count": 2,
                  "scored_sha256": mutation_run.pair_set_digest(
                      pairs - {("item-a", m1), ("item-b", m4)})})
        check("an item whose every pair is excluded keeps a not-scorable row "
              "instead of vanishing from the item roster",
              excluded_document["items"]["item-b"] == {
                  "full_gold_kills": [], "hard_subset": [],
                  "scorable": False, "stub_recall": None})

        # Owner ruling 2026-09-30: a pair whose mutant test only added files
        # is one first-attempt `unscorable_substrate` row.  The strict reader
        # admits it and section 5.1 takes it out of G for every role.
        unscorable_root = os.path.join(temporary, "unscorable")
        write_observation(unscorable_root, "full_gold", {
            **clean["full_gold"], ("item-a", m2): "unscorable_substrate"},
            "e" * 32)
        unscorable_gold = load_native_observation(
            os.path.join(unscorable_root, "full_gold"), role="full_gold",
            scope=scope)
        unscorable_roles = {"full_gold": unscorable_gold,
                            "stripped_gold": native["stripped_gold"],
                            "stub": native["stub"]}
        refuses("an unscorable-substrate pair is a section 5.1 exclusion "
                "that needs the recorded consent",
                lambda: _derive_reference_controls(
                    scope, unscorable_roles, allow_excluded_pairs=False),
                "allow_excluded_pairs=True")
        unscorable_document, unscorable_scored = _derive_reference_controls(
            scope, unscorable_roles, allow_excluded_pairs=True)
        check("an unscorable-substrate pair leaves G and every role's scored "
              "universe and is disclosed by its outcome",
              unscorable_scored == pairs - {("item-a", m2)}
              and unscorable_document["items"]["item-a"]["full_gold_kills"]
                  == sorted({m1, m3})
              and unscorable_document["excluded_pairs"] == [
                  {"item_id": "item-a", "mutant_id": m2,
                   "causes": [{"role": "full_gold",
                               "outcome": "unscorable_substrate"}]}])

        # ------------------------------------------- the declared subset
        #
        # A four-item release over the same manifest.  `item-c` is released
        # and mapped but the gold baseline has no row for it -- the algorand
        # 111-of-117 shape -- and `item-d` is released and gold-free and
        # mapped by nothing.  Declaring {item-a, item-b} therefore drops one
        # mapped pair and leaves the four the clean fixture already scores.
        declared_release = os.path.join(temporary, "release-declared.jsonl")
        with open(declared_release, "w", encoding="utf-8") as handle:
            for item_id in ("item-a", "item-b", "item-c", "item-d"):
                handle.write(json.dumps({"item_id": item_id}) + "\n")
        declared_mapping = mutation_attestation.build_map_artifact(
            manifest,
            {m1: ["item-a"], m2: ["item-a"], m3: ["item-a"],
             m4: ["item-b", "item-c"]}, [],
            coverage_sha256="c" * 64,
            release_sha256=mutation_run.sha256_file(declared_release))
        declared_map_path = os.path.join(temporary, "map-declared.json")
        with open(declared_map_path, "w", encoding="utf-8") as handle:
            json.dump(declared_mapping, handle, sort_keys=True)
        declaration = {
            "items": ["item-a", "item-b"],
            "reason": "the release gold oracle covers 2 of 4 released items",
        }

        def seal_declared(items=None, reason=None):
            subset = None if items is None else {
                "items": items, "reason": declaration["reason"]
                if reason is None else reason}
            return seal_fixture_scope(
                workloads, release=declared_release,
                mapping=declared_map_path, declared_subset=subset)

        refuses("an UNDECLARED item the gold baseline does not cover still "
                "refuses, and the refusal names what a declaration would "
                "have to cover",
                lambda: seal_declared(), "item-d")
        refuses("an omitted item whose gold row DOES exist refuses: a "
                "reference may only omit what its control run lacks",
                lambda: seal_declared(["item-a"]), "item-b")
        refuses("a declared item with no gold row refuses, naming it",
                lambda: seal_declared(["item-a", "item-b", "item-c"]),
                "item-c")
        refuses("a declaration that omits nothing is not a declaration",
                lambda: seal_declared(
                    ["item-a", "item-b", "item-c", "item-d"]),
                "omits nothing")
        refuses("a declaration nobody explained is not a disclosure",
                lambda: seal_declared(["item-a", "item-b"], reason="  "),
                "one-line reason")
        refuses("a declared item that is not released refuses",
                lambda: seal_declared(["item-a", "item-z"]),
                "not in the release document")

        # The release whose declared item carries no mapped pair at all.
        empty_release = os.path.join(temporary, "release-empty.jsonl")
        with open(empty_release, "w", encoding="utf-8") as handle:
            for item_id in ("item-a", "item-d"):
                handle.write(json.dumps({"item_id": item_id}) + "\n")
        empty_mapping = mutation_attestation.build_map_artifact(
            manifest,
            {m1: ["item-a"], m2: ["item-a"], m3: ["item-a"],
             m4: ["item-a"]}, [],
            coverage_sha256="c" * 64,
            release_sha256=mutation_run.sha256_file(empty_release))
        empty_map_path = os.path.join(temporary, "map-empty.json")
        with open(empty_map_path, "w", encoding="utf-8") as handle:
            json.dump(empty_mapping, handle, sort_keys=True)
        empty_baseline_path = os.path.join(temporary, "gold-empty.jsonl")
        empty_rows = [{
            "item_id": "item-d", "outcome": "passed",
            "produced_files": [{"file_path": "tests/item-d.py",
                                "code": "assert 'item-d'"}],
        }]
        with open(empty_baseline_path, "w", encoding="utf-8") as handle:
            for row in empty_rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
        empty_workloads = copy.deepcopy(workloads)
        empty_workloads["full_gold"].update({
            "candidate_run_sha256":
                mutation_run.sha256_file(empty_baseline_path),
            "generated_tests_sha256": mutation_run.candidate_digest(
                test_quality.passed_solutions(empty_rows)),
        })
        refuses("a declaration whose items carry no mapped pair refuses: "
                "there is nothing to observe and no denominator",
                lambda: seal_fixture_scope(
                    empty_workloads, release=empty_release,
                    mapping=empty_map_path,
                    gold_baseline=empty_baseline_path,
                    declared_subset={"items": ["item-d"],
                                     "reason": "only the unmapped item"}),
                "no mapped pair")

        declared_scope = seal_declared(["item-a", "item-b"])
        check("a declared subset seals over exactly the mapped pairs of its "
              "declared items, and the disclosure is derived rather than "
              "asserted",
              declared_scope.expected_pairs == pairs
              and declared_scope.declaration == {
                  "declared_items": 2, "release_items": 4,
                  "omitted_items": ["item-c", "item-d"], "omitted_pairs": 1,
                  "reason": declaration["reason"]}
              and declared_scope.authority["n_pairs"] == 5)

        declared_source = os.path.join(temporary, "declared")
        outer_scope = scope
        scope = declared_scope
        try:
            for role, observation_id in zip(
                    ROLES, ("e" * 32, "f" * 32, "0" * 32)):
                write_observation(declared_source, role, clean[role],
                                  observation_id)
            declared_native = {
                role: load_native_observation(
                    os.path.join(declared_source, role), role=role,
                    scope=declared_scope)
                for role in ROLES
            }
        finally:
            scope = outer_scope
        declared_document = build_reference_controls(
            declared_scope, full_gold=declared_native["full_gold"],
            stripped_gold=declared_native["stripped_gold"],
            stub=declared_native["stub"])
        check("the declared subset is disclosed in the artifact and the "
              "attestation is derived over the declared items only",
              declared_document["declared_subset"] == {
                  "declared_items": 2, "release_items": 4,
                  "omitted_items": ["item-c", "item-d"], "omitted_pairs": 1,
                  "reason": declaration["reason"]}
              and set(declared_document["items"]) == {"item-a", "item-b"}
              and declared_document["pairs"]["count"] == 4
              and declared_document["pairs"]["excluded_count"] == 0)
        check("an undeclared reference carries no declaration field at all, "
              "so nothing that declares nothing changes shape",
              "declared_subset" not in document
              and "declared_subset" not in excluded_document
              and scope.declaration is None)
        declared_controls = validate_reference_controls(
            copy.deepcopy(declared_document), scope=declared_scope,
            full_gold=declared_native["full_gold"],
            stripped_gold=declared_native["stripped_gold"],
            stub=declared_native["stub"])
        declared_sets = reference_sets(declared_controls)
        check("the omitted ids and the operator's reason reach the scoring "
              "view a consumer renders a number from",
              declared_sets.omitted_items == ("item-c", "item-d")
              and declared_sets.declared_reason == declaration["reason"]
              and declared_sets.expected_pairs == pairs)
        forged = copy.deepcopy(declared_document)
        forged["declared_subset"]["omitted_items"] = ["item-b", "item-c",
                                                      "item-d"]
        forged["declared_subset"]["declared_items"] = 1
        forged["digest"] = artifact_digest(forged)
        refuses("a self-consistent artifact cannot declare away an item its "
                "own observations covered",
                lambda: validate_reference_controls(
                    forged, scope=declared_scope,
                    full_gold=declared_native["full_gold"],
                    stripped_gold=declared_native["stripped_gold"],
                    stub=declared_native["stub"]), "does not rederive")

        installed_path = os.path.join(temporary, "reference-controls.json")
        write(excluded_document, installed_path)
        check("an installed attestation reloads as the document it was "
              "minted as", load(installed_path) == excluded_document)
        refuses("an installed attestation is immutable",
                lambda: write(excluded_document, installed_path),
                "already exists")
        tampered_path = os.path.join(temporary, "tampered.json")
        tampered = copy.deepcopy(excluded_document)
        tampered["pairs"]["scored_count"] = 4
        mutation_run.atomic_write_json(tampered_path, tampered)
        refuses("a document whose digest is not its own content is refused "
                "before any consumer reads a number from it",
                lambda: load(tampered_path), "digest does not match")

        relocated = os.path.join(temporary, "relocated")
        shutil.copytree(source, relocated)
        relocated_excluded = os.path.join(temporary, "relocated-excluded")
        shutil.copytree(excluded_source, relocated_excluded)
        os.rename(producer, producer + "-unavailable")
        preserved = {
            role: load_preserved_observation(
                os.path.join(relocated, role), role=role,
                scope=scope)
            for role in ROLES
        }
        check("relocated controls load without producer-host worker paths",
              all(authenticated_observation(value)
                  for value in preserved.values()))
        check("the sealed observation retains plan, row, and sidecar facts",
              all(value["facts"]["output_plan_sha256"]
                      and len(value["facts"]["rows_sha256"]) == 1
                      and len(value["facts"]["sidecars_sha256"]) == 1
                      for value in preserved.values()))
        refuses("portable observations cannot mint a new attestation",
                lambda: build_reference_controls(
                    scope, full_gold=preserved["full_gold"],
                    stripped_gold=preserved["stripped_gold"],
                    stub=preserved["stub"]), "strict producer-authenticated")

        swapped_workloads = copy.deepcopy(workloads)
        swapped_workloads["stripped_gold"], swapped_workloads["stub"] = (
            swapped_workloads["stub"],
            swapped_workloads["stripped_gold"])
        swapped_scope = seal_fixture_scope(swapped_workloads)
        refuses("role labels cannot swap adapter-authenticated workloads",
                lambda: load_preserved_observation(
                    os.path.join(relocated, "stripped_gold"),
                    role="stripped_gold", scope=swapped_scope),
                "workload binding")

        v2_identity = gold_killset._fixture_identity(
            manifest_digest=scope.population["manifest_digest"],
            expected_pairs=set(pairs))
        refuses("an unlabelled v2 observation cannot become a reference role",
                lambda: _role_check(v2_identity, "full_gold", scope),
                "authenticated v5")
        refuses("same-side stripped gold cannot be swapped with the stub role",
                lambda: load_preserved_observation(
                    os.path.join(relocated, "stripped_gold"), role="stub",
                    scope=scope), "not publishable")

        controls = validate_reference_controls(
            copy.deepcopy(document), scope=scope,
            full_gold=preserved["full_gold"],
            stripped_gold=preserved["stripped_gold"],
            stub=preserved["stub"])
        refuses("ReferenceScope cannot be directly authored",
                lambda: ReferenceScope(
                    population={}, authority={}, expected_pairs=pairs,
                    workloads={}, seal=object()), "seal_reference_scope")
        refuses("ReferenceControls cannot be directly authored",
                lambda: ReferenceControls(
                    {}, expected_pairs=pairs, observations={}, seal=object()),
                "internally validated")
        refuses("ReferenceControls requires all three roles even internally",
                lambda: ReferenceControls(
                    {}, expected_pairs=pairs, observations={},
                    seal=_CONTROLS_SEAL), "three-role")
        refuses("ReferenceSets cannot be directly authored",
                lambda: ReferenceSets(
                    expected_pairs=pairs, excluded_count=0,
                    full_gold_kills={}, hard_subset={},
                    stub_recall_by_item={}, stub_macro_recall=0.0,
                    stub_threshold=STUB_RECALL_THRESHOLD, eligible=True,
                    seal=object()), "derived only")
        saved_observations = controls._observations
        controls._observations = {}
        check("authenticated controls detect missing observation reassignment",
              not authenticated_reference_controls(controls))
        controls._observations = saved_observations
        # The companion "detect expected-pair reassignment" check is gone with
        # the field it exercised: `_expected_pairs_snapshot` was bound to the
        # SAME frozenset as `_expected_pairs`, so the comparison could only
        # ever be true and detected nothing. The role-set check above is a
        # real one -- `_observations` is rebuilt, not aliased.
        sets = reference_sets(controls)
        check("failed-only G and passed-stripped H rederive per item",
              authenticated_reference_sets(sets)
              and sets.expected_pairs == pairs
              and sets.full_gold_kills["item-a"] == frozenset({m1, m2, m3})
              and sets.hard_subset["item-a"] == frozenset({m1, m3})
              and not sets.hard_subset["item-b"])
        check("the zero-kill stub passes the exact project macro gate",
              sets.stub_macro_recall == 0.0
              and sets.stub_threshold == STUB_RECALL_THRESHOLD
              and sets.eligible)
        installed = load_preserved_reference_controls(
            relocated, copy.deepcopy(document), scope=scope)
        check("one portable reader rejoins the relocated three-role tree",
              authenticated_reference_controls(installed)
              and dict(installed) == document)

        excluded_controls = load_preserved_reference_controls(
            relocated_excluded, load(installed_path), scope=scope)
        excluded_sets = reference_sets(excluded_controls)
        check("the exclusion is uniform: the stub's own infrastructure pair "
              "leaves the gold and hard sets as well as the stub's",
              excluded_sets.expected_pairs
                  == pairs - {("item-a", m1), ("item-b", m4)}
              and excluded_sets.full_gold_kills["item-a"]
                  == frozenset({m2, m3})
              and excluded_sets.hard_subset["item-a"] == frozenset({m3})
              and not excluded_sets.hard_subset["item-b"]
              and excluded_sets.stub_recall_by_item["item-b"] is None)
        check("the excluded count travels on the scoring view, so a consumer "
              "cannot render a number without it",
              excluded_sets.excluded_count == 2 and sets.excluded_count == 0
              and sets.omitted_items == ()
              and sets.declared_reason is None)

        changed_document = copy.deepcopy(document)
        changed_document["items"]["item-a"]["hard_subset"] = [m2]
        changed_document["digest"] = artifact_digest(changed_document)
        refuses("a self-consistent authored hard subset cannot replace rows",
                lambda: validate_reference_controls(
                    changed_document, scope=scope,
                    full_gold=preserved["full_gold"],
                    stripped_gold=preserved["stripped_gold"],
                    stub=preserved["stub"]), "does not rederive")

        high_stub_root = os.path.join(temporary, "high-stub")
        write_observation(high_stub_root, "stub", {
            **clean["stub"], ("item-a", m1): "failed"}, "4" * 32)
        high_stub = load_preserved_observation(
            os.path.join(high_stub_root, "stub"), role="stub",
            scope=scope)
        refuses("stub recall above 0.02 withholds reusable controls",
                lambda: _derive_reference_controls(scope, {
                    "full_gold": preserved["full_gold"],
                    "stripped_gold": preserved["stripped_gold"],
                    "stub": high_stub}, allow_excluded_pairs=False),
                "exceeds")

        # The labelled sensitivity basis over the SAME failed-gate stub
        # (specifications/SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md): the
        # derivation is the attestation's, the gate is recorded rather than
        # enforced, and the result can never reopen as an attestation.
        label = "sylius_stub_gate_waived_v1"
        waived_passing = sensitivity_reference_controls(
            scope, full_gold=preserved["full_gold"],
            stripped_gold=preserved["stripped_gold"], stub=preserved["stub"],
            sensitivity=label, allow_excluded_pairs=False)
        label_fields = {"sensitivity", "gold_disagreements", "digest"}
        check("waiving the gate changes nothing when the gate passes: G, the "
              "hard subset, the stub recalls, the gate and every other field "
              "equal the eligible attestation's; only the label differs",
              {key: value for key, value in waived_passing.items()
               if key not in label_fields}
              == {key: value for key, value in document.items()
                  if key != "digest"}
              and waived_passing["stub_gate"]["eligible"] is True
              and reference_sets(waived_passing).hard_subset
              == sets.hard_subset
              and reference_sets(waived_passing).full_gold_kills
              == sets.full_gold_kills)
        sensitive = sensitivity_reference_controls(
            scope, full_gold=preserved["full_gold"],
            stripped_gold=preserved["stripped_gold"], stub=high_stub,
            sensitivity=label, allow_excluded_pairs=False)
        sensitive_sets = reference_sets(sensitive)
        check("a labelled sensitivity basis records the failed stub gate "
              "instead of refusing, and keeps the attestation's G and H",
              authenticated_reference_controls(sensitive)
              and sensitive["sensitivity"] == label
              and sensitive["stub_gate"]["eligible"] is False
              and sensitive["stub_gate"]["macro_recall"]
              > STUB_RECALL_THRESHOLD
              and sensitive["gold_disagreements"]
              == {"source": None, "sha256": None, "pairs": []}
              and all(sensitive["items"][item_id][key]
                      == document["items"][item_id][key]
                      for item_id in document["items"]
                      for key in ("full_gold_kills", "hard_subset",
                                  "scorable"))
              and sensitive_sets.hard_subset["item-a"] == frozenset({m1, m3})
              and sensitive_sets.sensitivity == label
              and sensitive_sets.eligible is False
              and reference_sets(controls).sensitivity is None)
        refuses("a sensitivity document never validates as an attestation",
                lambda: validate_reference_controls(
                    dict(sensitive), scope=scope,
                    full_gold=preserved["full_gold"],
                    stripped_gold=preserved["stripped_gold"],
                    stub=high_stub), "exceeds")
        refuses("an unknown sensitivity label refuses",
                lambda: sensitivity_reference_controls(
                    scope, full_gold=preserved["full_gold"],
                    stripped_gold=preserved["stripped_gold"], stub=high_stub,
                    sensitivity="post_hoc_anything",
                    allow_excluded_pairs=False), "unknown reference")
        refuses("the sensitivity basis keeps the section 5.1 consent rule",
                lambda: sensitivity_reference_controls(
                    scope, full_gold=excluded_native["full_gold"],
                    stripped_gold=excluded_native["stripped_gold"],
                    stub=excluded_native["stub"], sensitivity=label,
                    allow_excluded_pairs=False),
                "allow_excluded_pairs=True")
        disagreeing = sensitivity_reference_controls(
            scope, full_gold=preserved["full_gold"],
            stripped_gold=preserved["stripped_gold"], stub=high_stub,
            sensitivity=label, allow_excluded_pairs=False,
            gold_disagreements=frozenset({("item-a", m3)}),
            gold_disagreements_binding={"source": "fixture pilot",
                                        "sha256": "d" * 64})
        check("a gold disagreement leaves G and the hard subset and is "
              "listed in the controls with the source and digest of its "
              "document",
              disagreeing["items"]["item-a"]["full_gold_kills"]
              == sorted({m1, m2})
              and disagreeing["items"]["item-a"]["hard_subset"] == [m1]
              and disagreeing["gold_disagreements"]
              == {"source": "fixture pilot", "sha256": "d" * 64,
                  "pairs": [{"item_id": "item-a", "mutant_id": m3}]}
              and disagreeing["digest"] != sensitive["digest"])
        check("a gold disagreement leaves the stub recalls and the recorded "
              "stub gate those of the stored observations",
              disagreeing["stub_gate"] == sensitive["stub_gate"]
              and all(disagreeing["items"][item_id]["stub_recall"]
                      == sensitive["items"][item_id]["stub_recall"]
                      for item_id in sensitive["items"]),
              json.dumps([disagreeing["stub_gate"], sensitive["stub_gate"]]))
        refuses("gold disagreements without their document's binding refuse",
                lambda: sensitivity_reference_controls(
                    scope, full_gold=preserved["full_gold"],
                    stripped_gold=preserved["stripped_gold"], stub=high_stub,
                    sensitivity=label, allow_excluded_pairs=False,
                    gold_disagreements=frozenset({("item-a", m2)})),
                "source and SHA-256")
        refuses("a disagreement that is not a stored full-gold kill refuses",
                lambda: sensitivity_reference_controls(
                    scope, full_gold=preserved["full_gold"],
                    stripped_gold=preserved["stripped_gold"], stub=high_stub,
                    sensitivity=label, allow_excluded_pairs=False,
                    gold_disagreements=frozenset({("item-b", m4)}),
                    gold_disagreements_binding={"source": "x",
                                                "sha256": "d" * 64}),
                "not scored full-gold kills")
        refuses("gold disagreements never narrow eligible controls",
                lambda: _derive_reference_controls(
                    scope, preserved, allow_excluded_pairs=False,
                    gold_disagreements=frozenset({("item-a", m2)})),
                "labelled sensitivity")
        disagreements_path = os.path.join(temporary, "disagreements.json")
        with open(disagreements_path, "w", encoding="utf-8") as handle:
            json.dump({"schema": GOLD_DISAGREEMENTS_SCHEMA,
                       "source": "fixture pilot",
                       "pairs": [["item-a", m2]]}, handle)
        loaded_pairs, loaded_binding = load_gold_disagreements(
            disagreements_path)
        check("a gold disagreement file loads with its binding",
              loaded_pairs == frozenset({("item-a", m2)})
              and loaded_binding
              == {"source": "fixture pilot",
                  "sha256": mutation_run.sha256_file(disagreements_path)})
        with open(disagreements_path, "w", encoding="utf-8") as handle:
            json.dump({"schema": GOLD_DISAGREEMENTS_SCHEMA, "source": "x",
                       "pairs": [["item-a", m2], ["item-a", m2]]}, handle)
        refuses("a gold disagreement file that repeats a pair refuses",
                lambda: load_gold_disagreements(disagreements_path),
                "repeat a pair")

        # The same stub, measured over what is left after full gold flakes on
        # the one pair it kills.  The gate moves because its denominator is
        # the scored universe; computing it over the registered population
        # instead would refuse controls whose stub killed nothing scorable.
        narrowed_gate_root = os.path.join(temporary, "narrowed-gate")
        write_observation(narrowed_gate_root, "full_gold", {
            **clean["full_gold"], ("item-a", m1): "container_error"},
            "d" * 32)
        narrowed_gate_gold = load_preserved_observation(
            os.path.join(narrowed_gate_root, "full_gold"), role="full_gold",
            scope=scope)
        narrowed_gate, narrowed_gate_scored = _derive_reference_controls(
            scope, {"full_gold": narrowed_gate_gold,
                    "stripped_gold": preserved["stripped_gold"],
                    "stub": high_stub}, allow_excluded_pairs=True)
        check("the stub gate and G are measured over the scored universe "
              "rather than the registered one",
              narrowed_gate_scored == pairs - {("item-a", m1)}
              and narrowed_gate["stub_gate"]["macro_recall"] == 0.0
              and narrowed_gate["items"]["item-a"]["full_gold_kills"]
                  == sorted({m2, m3})
              and narrowed_gate["items"]["item-a"]["hard_subset"] == [m3])

        duplicate_root = os.path.join(temporary, "duplicate-observation")
        write_observation(duplicate_root, "stub", clean["stub"], "1" * 32)
        duplicate_stub = load_preserved_observation(
            os.path.join(duplicate_root, "stub"), role="stub",
            scope=scope)
        refuses("three roles cannot reuse one observation identity",
                lambda: _derive_reference_controls(scope, {
                    "full_gold": preserved["full_gold"],
                    "stripped_gold": preserved["stripped_gold"],
                    "stub": duplicate_stub},
                    allow_excluded_pairs=False), "distinct observation")

        # A timeout classifies as a KILL under a passed baseline, so section
        # 5.1 needs its own clause for it; an outcome no vocabulary knows is a
        # data error rather than a flake and still refuses.
        check("a terminal timeout is an exclusion and not a kill",
              _excluded_terminal_outcome("timeout", "stub")
              and mutation.classify_outcome("passed", "timeout") == "kill"
              and not _excluded_terminal_outcome("failed", "stub"))
        refuses("a non-string terminal outcome is a data error",
                lambda: _excluded_terminal_outcome(None, "stub"),
                "invalid terminal outcome")
        refuses("an outcome no scoring vocabulary knows is a data error",
                lambda: _excluded_terminal_outcome("mostly_fine", "stub"),
                "unknown terminal outcome")

        excluded_empty_root = os.path.join(temporary, "excluded-empty")
        write_observation(excluded_empty_root, "stub", {
            **clean["stub"], ("item-a", m1): "container_error",
            ("item-a", m3): "container_error"}, "c" * 32)
        excluded_empty_stub = load_preserved_observation(
            os.path.join(excluded_empty_root, "stub"), role="stub",
            scope=scope)
        refuses("the project-wide empty-hard refusal is re-derived over the "
                "narrowed universe",
                lambda: _derive_reference_controls(scope, {
                    "full_gold": preserved["full_gold"],
                    "stripped_gold": preserved["stripped_gold"],
                    "stub": excluded_empty_stub},
                    allow_excluded_pairs=True), "empty hard subset")

        empty_hard_root = os.path.join(temporary, "empty-hard")
        write_observation(empty_hard_root, "stripped_gold",
                          clean["full_gold"], "6" * 32)
        empty_hard = load_preserved_observation(
            os.path.join(empty_hard_root, "stripped_gold"),
            role="stripped_gold", scope=scope)
        refuses("an all-empty project hard set cannot finalize",
                lambda: _derive_reference_controls(scope, {
                    "full_gold": preserved["full_gold"],
                    "stripped_gold": empty_hard,
                    "stub": preserved["stub"]},
                    allow_excluded_pairs=False), "empty hard subset")

        missing = set(pairs) - {("item-b", m4)}
        narrowed_scope = copy.copy(scope)
        narrowed_scope.expected_pairs = frozenset(missing)
        refuses("a narrowed scope cannot make a complete observation partial",
                lambda: load_preserved_observation(
                    os.path.join(relocated, "full_gold"), role="full_gold",
                    scope=narrowed_scope), "does not cover the exact")
        # The scope an observation was READ under need not be the scope the
        # attestation is derived under, so both bindings are re-checked here.
        refuses("pair coverage is re-checked against the scope the "
                "derivation runs under",
                lambda: _derive_reference_controls(
                    narrowed_scope, preserved, allow_excluded_pairs=False),
                "does not cover the exact")
        refuses("the role workload binding is re-checked against the scope "
                "the derivation runs under",
                lambda: _derive_reference_controls(
                    swapped_scope, preserved, allow_excluded_pairs=False),
                "workload binding")
        refuses("a candidate-side control cannot be relabelled full gold",
                lambda: load_preserved_observation(
                    os.path.join(relocated, "stub"), role="full_gold",
                    scope=scope), "not publishable")

        stub_sidecar = mutation_run.provenance_path(os.path.join(
            relocated, "stub", "candidate.w0.jsonl"))
        with open(stub_sidecar, encoding="utf-8") as handle:
            changed = json.load(handle)
        changed["worker_resources"][0]["worker_spec"] = \
            "/another/producer/worker0.json"
        mutation_run.atomic_write_json(stub_sidecar, changed)
        refuses("changed preserved worker provenance is not portable evidence",
                lambda: load_preserved_observation(
                    os.path.join(relocated, "stub"), role="stub",
                    scope=scope), "worker-resource")

    print("\n" + ("ALL PASS (reference_controls)" if ok
                    else "FAILURES (reference_controls)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
