"""Execute a mutant manifest against a candidate — the gate's engine.

SPEC_C3_PARALLEL §3.10 (the anti-vacuity gate) and §3.11 (the manifest).
`r2t.data.mutation` defines the population and scores the results; this is the
part that actually applies a mutant, runs the scenarios that cover it, and
puts the file back.

Three properties it exists to guarantee, none of which is obvious from the
loop:

* **The mutation is declared before it happens.**  Production code is under
  the integrity baseline, and a run that finds it changed aborts as tampering
  — correctly, because that is how a solution rewriting `Order.php` would be
  caught.  A mutation campaign therefore tells the harness the one file it is
  about to change and its exact digest; everything else still aborts.  The
  alternative, switching the guard off for mutation runs, would remove it
  from the one campaign that edits production code on purpose.
* **The file goes back, and that is verified.**  A mutant left in place
  poisons every subsequent measurement silently, and it would look like the
  candidate getting worse.  The original bytes are held in memory, restored
  after each mutant, and the restored digest is compared with the original.
  A failed restore stops the campaign rather than continuing.
* **The applier and the enumerator are one program.**  `mutate.php --apply`
  re-enumerates the target file and refuses unless the requested mutant
  appears in that fresh enumeration, so "mutant M" cannot mean one thing at
  manifest time and another at execution time.

**Cost.**  Recomputed from the real manifest (§3.11, replacing the
provisional 205.4 h): 10,463 mutants over `src/CoreShop/{Component,Bundle}`,
of which **2,741 are covered** by at least one of the 100 eval items, giving
49,553 `(mutant, item)` pairs — 18.08 items per covered mutant.  At the
measured 4.89 s end-to-end without coverage that is **67.3 h** at K=1 for the
gold side, and 16.7 h with §3.13's batching.  Both are ~3.05x smaller than
the figures the spec marked provisional.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import shlex
import signal
import stat
import tempfile
import threading
import time
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from functools import wraps
from typing import Callable, Iterable, Optional, TYPE_CHECKING

from ..data.mutation import (ENGINE, ENGINE_VERSION, operator_profile_for)
from ..core.paths import BENCHMARK_ROOT

if TYPE_CHECKING:
    from .harness import Harness

#: Where the applier is staged inside the workspace.  `var/`, never `_bench/`:
#: `_bench` is a hashed substrate root and a stray file there aborts the next
#: item as tampering.
APPLIER_REL = "var/bench_mutate/mutate.php"

# Fixed destinations inside the short-lived, networkless Java analysis
# container.  Their host preimages are private trees outside the submitted
# workspace and are mounted read-only by DockerRunner.run_isolated_java.
JAVA_ANALYSIS_RUNTIME = "/opt/r2t-analysis"
JAVA_APPLIER_RUNTIME = "/opt/r2t-engine"

#: Where this repository keeps the enumerator/applier programs.  A `php`
#: directory today, a `py` directory when the second stack lands; the caller
#: passes the one its engine belongs to, which is why `run_slice`'s parameter
#: is `engine_dir` and not `php_dir` any more.
PHP_ENGINE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "php")

#: New mutation rows are attributable without consulting a mutable path.  The
#: identity deliberately uses full SHA-256 values even though some older
#: presentation-only digests in this repository are shortened to 16 hex
#: characters.  A campaign identity is a correctness boundary, not a label.
#: The identity every ordinary new mutation campaign is written under (PR R3).
#:
#: v1 -> v2 (2026-08-05, plan §3 PR R3, approved in `SLICE1_OWNER_RULINGS.md`
#: §2.2).  v1 bound the candidate's GENERATION only indirectly, through
#: `candidate_run_sha256`: the run file's bytes imply the condition, the
#: protocol, the network semantics and the native budget, in the sense that
#: someone holding the file could go and look them up.  Report §8.4 asked
#: whether that is sufficient identity; the owner ruled it is not (Q2), and
#: finding 20 supplied the realized precedent — two Cell 3 attempts under one
#: generation identity.  v2 carries those facts FIRST CLASS, plus which
#: generation attempt produced the bytes and under which provenance class.
#:
#: v3 is deliberately narrower: new test-quality plans bind their scheduling
#: policy into the shard identity, and therefore into every row stamp.  The
#: ordinary `mutation-run` constructor remains v2 unless its test-quality
#: caller supplies that policy.  This keeps archived v1/v2 documents readable
#: and re-hashable exactly as written while closing a relabelling gap in the
#: newer root-plan protocol.
#:
#: v1 and v2 documents remain readable and re-hashable exactly as written
#: (`_validate_campaign_identity` dispatches on the schema and fills nothing
#: in), and different identity versions may never be merged into one campaign.
MUTATION_IDENTITY_SCHEMA_V1 = "r2t.mutation-campaign/v1"
MUTATION_IDENTITY_SCHEMA_V2 = "r2t.mutation-campaign/v2"
MUTATION_IDENTITY_SCHEMA = MUTATION_IDENTITY_SCHEMA_V2
MUTATION_IDENTITY_SCHEMA_V3 = "r2t.mutation-campaign/v3"
MUTATION_IDENTITY_SCHEMA_V4 = "r2t.mutation-campaign/v4"
MUTATION_IDENTITY_SCHEMA_V5 = "r2t.mutation-campaign/v5"
MUTATION_PROVENANCE_SCHEMA = "r2t.mutation-shard/v1"
MUTATION_OUTPUT_PLAN_SCHEMA_V1 = "r2t.mutation-output-plan/v1"
MUTATION_OUTPUT_PLAN_SCHEMA = "r2t.mutation-output-plan/v2"
MUTATION_OUTPUT_PLAN = ".r2t-mutation-output.json"
MUTATION_VERIFICATION_SCHEMA = "r2t.mutation-shard-verification/v1"

#: The two admissible generation provenance classes (plan §3, PR R3).
#:
#: `native_v2` — the candidate was generated under an
#: `r2t.generation-campaign/v2` fingerprint, so an attempt identity, a
#: harness-source identity, a runtime-manifest digest and a network posture
#: all exist and are recorded here.
#:
#: `legacy_exact_bytes` — the candidate predates v2 and is admitted by the
#: owner's explicit ruling, bound to the exact run and generated-test SHA-256
#: values in `campaign.LEGACY_GENERATION_EVIDENCE`.  Its 16-hex generation
#: digest is recipe evidence whose schema cannot establish an attempt
#: identity.  A record marks that digest known-nonunique only when a collision
#: was actually observed (Cell 3); either way, no attempt identity is invented.
#: `fixture` is the THIRD class, and it exists so that a default can never
#: be mistaken for evidence.  `test_quality.identity_inputs_for_test_quality`
#: has to be able to build an identity for a candidate no agent produced;
#: before this it defaulted to `native_v2` with a plausible attempt id, so a
#: real caller that omitted one key would have inherited a fabricated
#: attempt identity and published under it -- the exact unlabelled-admission
#: failure ruling 2.2 closed. The default now says what it is, and every
#: publication surface refuses it.
GENERATION_PROVENANCE_FIXTURE = "fixture"

#: `development_unstamped` is the FOURTH class, and it exists for the route
#: the benchmark is actually developed on.  A candidate produced by the
#: ordinary `run --release` route carries no `<run>.campaign.json` sidecar and
#: no per-row campaign stamp, because the campaign route welds a run to a
#: SHA-256 over every `.py` file in the harness and so makes that run
#: unscorable after the next merge.  Such a candidate has no generation
#: campaign to name, and the honest record of that is the absence itself: no
#: attempt, no runtime manifest, no network posture, and no campaign digest.
#: What the ROWS say -- condition, protocol, native budget -- is carried
#: through unchanged, because those are facts about the rows and not about a
#: campaign identity nobody minted.
#:
#: It is deliberately absent from `GENERATION_PROVENANCE_PUBLISHABLE`: the
#: mutation metric over a development candidate is the same arithmetic over
#: the same pairs, but the candidate cannot cite the attempt that produced it,
#: and a published number that cannot is exactly what ruling 2.2 closed.
GENERATION_PROVENANCE_DEVELOPMENT = "development_unstamped"

#: The classes a PUBLISHED number may rest on.
GENERATION_PROVENANCE_PUBLISHABLE = ("native_v2", "legacy_exact_bytes")

#: Every class a valid identity may carry.  A `fixture` identity is valid --
#: the unit tests that never publish anything build thousands of them -- and
#: unpublishable, which is the distinction the two tuples draw.  A
#: `development_unstamped` identity is valid for the same reason and
#: unpublishable for a different one: the campaign it would cite was never
#: minted.
GENERATION_PROVENANCE_CLASSES = (*GENERATION_PROVENANCE_PUBLISHABLE,
                                 GENERATION_PROVENANCE_FIXTURE,
                                 GENERATION_PROVENANCE_DEVELOPMENT)

#: The v1 field set, kept verbatim so archived v1 documents keep validating
#: and re-hashing against themselves.
CAMPAIGN_IDENTITY_FIELDS_V1 = {
    "schema", "kind", "asset_index_sha256", "asset_project",
    "mutation_validation_sha256", "mutation_validation_class",
    "manifest_sha256", "manifest_digest", "map_sha256", "release_sha256",
    "candidate_run_sha256", "candidate_generated_tests_sha256",
    "gold_baseline_sha256", "gold_generated_tests_sha256",
    "gold_results_sha256", "gold_results_attestation_sha256",
    "gold_provenance_class", "gold_attestation_manifest_digest",
    "gold_attestation_pairs_sha256", "gold_attestation_engine",
    "gold_attestation_engine_version", "solution_generated_tests_sha256",
    "substrate_baseline_sha256", "applier_sha256",
    "worker_resources_sha256", "harness_version",
    "container_image_digest", "workspace_seed_digest",
    "database_dump_digest", "engine", "engine_version", "parser",
    "side", "shard", "of",
    "timeout_seconds", "sample", "sample_seed", "expected_pairs",
    "expected_pairs_sha256",
}

#: What v2 adds.  Every name is prefixed `generation_` on purpose: these are
#: facts about how the CANDIDATE WAS PRODUCED, not about how this mutation
#: campaign executes, and one unprefixed `condition` in a document that also
#: carries `side`, `engine` and `timeout_seconds` would read as the mutation
#: run's own.
CAMPAIGN_IDENTITY_FIELDS_V2_ADDED = {
    "generation_provenance_class",
    "generation_attempt_id",
    "generation_campaign_digest",
    "generation_agent_runtime_sha256",
    "generation_network_semantics",
    "generation_condition",
    "generation_protocol_version",
    "generation_protocol_digest",
    "generation_native_budget",
}

CAMPAIGN_IDENTITY_FIELDS = (CAMPAIGN_IDENTITY_FIELDS_V1
                            | CAMPAIGN_IDENTITY_FIELDS_V2_ADDED)

#: v3 is emitted only by new test-quality planning.  Keep the literals here
#: rather than importing `test_quality` and creating an identity-module cycle.
#: v3 began with the balanced policy.  Historical striding is deliberately
#: excluded: its only authentic representation is an unbound v1/v2 identity
#: beneath a test-quality plan v1 root.
TEST_QUALITY_SHARD_POLICIES = {"r2t.balanced-pairs-lpt/1"}
CAMPAIGN_IDENTITY_FIELDS_V3_ADDED = {"shard_policy"}
CAMPAIGN_IDENTITY_FIELDS_V3 = (
    CAMPAIGN_IDENTITY_FIELDS | CAMPAIGN_IDENTITY_FIELDS_V3_ADDED)

#: v4 is one shared extension point, not a cap-specific fork of the batching
#: identity.  ``MUTATION_BATCHING_EQUIVALENCE_SPEC.md`` owns the batching
#: fields; the cap-bound fallback and the reserved exact reuse projection add
#: the remaining cap/projection/cache fields. Writers always emit the entire
#: exact field set. The
#: current cap path is scalar, so all batch and projection fields are null.
EXECUTION_POLICY_SCALAR_V1 = "r2t.scalar/1"
EXECUTION_POLICY_BATCH_BISECT_V1 = "r2t.batch-bisect/1"
CAMPAIGN_IDENTITY_FIELDS_V4_ADDED = {
    "execution_policy", "batch_plan_sha256", "max_batch_members",
    "max_batch_instances", "stack_reset_sha256", "batch_journal_schema",
    "compute_cap_sha256", "reuse_projection_sha256",
    "estimand_pairs_sha256", "preflight_cache_policy", "observation_id",
}
CAMPAIGN_IDENTITY_FIELDS_V4 = (
    CAMPAIGN_IDENTITY_FIELDS_V3 | CAMPAIGN_IDENTITY_FIELDS_V4_ADDED)

# Reference controls have exact submitted bytes but no agent-generation
# campaign.  v5 is a sibling of v2, not an extension of it: carrying any v2
# attempt/runtime/network field would invent provenance the control has none
# of.  The two byte digests already live in v1 and complete the exact
# six-member generation tuple.
GENERATION_PROVENANCE_REFERENCE_CONTROL = "reference_control_exact_bytes"
#: Which adapter's rows each reviewed reference role IS.
#:
#: `runner._run_stamp` writes `"adapter": adapter.name` onto every row of
#: every run, and these three controls are built by exactly these three
#: adapters (`fixtures.SPECS`; the per-language variants in
#: `stub*.py`/`strip*.py` all construct `Adapter("stub", ...)` /
#: `Adapter("stripped-gold", ...)`).  So the leg an operator DECLARES can be
#: checked against the leg the harness itself RECORDED, which is the whole
#: reason the declaration is admissible as identity at all.  The role set is
#: derived from this table so the two cannot drift.
REFERENCE_CONTROL_ROLE_ADAPTERS = {
    "full-gold": "gold",
    "assertion-stripped-gold": "stripped-gold",
    "stub-control": "stub",
}
REFERENCE_CONTROL_ROLES = frozenset(REFERENCE_CONTROL_ROLE_ADAPTERS)


def is_gold_run_slice(identity: dict) -> bool:
    """Whether a slice's executions are gold runs (`Solution.gold_run`).

    Harness 25 runs a gold run under harness 24's suite and wiring rules
    and a candidate run under the corrected ones (specifications/
    EVALUATOR_CORRECTIONS_20261015_AMENDMENT.md section 3).  An unmutated
    run says which through the adapter that built it
    (`runner.is_gold_run_adapter`); a mutation slice receives bytes only, so
    its campaign identity says it: the gold side, and every reference
    leg's observation (full, assertion-stripped and stub), the latter two
    being candidate-side campaigns of gold-derived files.
    """
    return identity.get("side") == "gold" \
        or identity.get("reference_control_role") in REFERENCE_CONTROL_ROLES


CAMPAIGN_IDENTITY_FIELDS_V5_ADDED = {
    "generation_provenance_class", "reference_control_role",
    "reference_source_tag", "reference_workload_digest",
}
CAMPAIGN_IDENTITY_FIELDS_V5 = (
    CAMPAIGN_IDENTITY_FIELDS_V1 | CAMPAIGN_IDENTITY_FIELDS_V5_ADDED)

#: WHICH POPULATION THE MAP IS, and deliberately not a version of its own.
#: `population_basis` is a fact about the map a leg ran, not about how the
#: leg executed or how its candidate was produced, and a budgeted project
#: runs BOTH reference legs (v5) and candidate legs (v2/v3/v4) over the same
#: derived map -- so a sixth rung on the version ladder would have to be two
#: rungs, and neither would say the same thing as the other.  These three
#: names are therefore admitted beside any version's field set, all three or
#: none: an identity that carries none of them is byte-for-byte the document
#: it was before this existed, and an identity that carries one of them is
#: refused for the missing two.
CAMPAIGN_IDENTITY_BUDGETED_ADDED = {
    "population_basis", "budgeted_sample_sha256", "parent_map_sha256",
}
#: The only declared non-default basis (`data.subsets.BUDGETED_BASIS`),
#: restated here so identity validation does not import the sampler.
BUDGETED_POPULATION_BASIS = "budgeted_sample"


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def sha256_file(path: str) -> str:
    """Full SHA-256 of the exact bytes at *path*."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def content_digest(obj) -> str:
    """Full SHA-256 over canonical JSON."""
    return hashlib.sha256(_canonical(obj)).hexdigest()


def pair_set_digest(pairs: Iterable[tuple[str, str]]) -> str:
    """Identity of an exact set of ``(item_id, mutant_id)`` pairs."""
    unique = set(pairs)
    for item_id, mutant_id in unique:
        if "\0" in item_id or "\0" in mutant_id:
            raise MutationAborted(
                "REFUSED: an item or mutant id contains NUL, which is the "
                "campaign pair digest's field separator.")
    payload = b"".join(
        item_id.encode("utf-8", "surrogateescape") + b"\0"
        + mutant_id.encode("utf-8", "surrogateescape") + b"\n"
        for item_id, mutant_id in sorted(unique))
    return hashlib.sha256(payload).hexdigest()


def expected_pairs_for_slice(mutants: Iterable[dict], by_mutant: dict,
                             files_by_item: dict) -> set[tuple[str, str]]:
    """The exact pairs a slice is required to emit."""
    return set(ordered_pairs_for_slice(mutants, by_mutant, files_by_item))


def ordered_pairs_for_slice(mutants: Iterable[dict], by_mutant: dict,
                            files_by_item: dict) \
        -> list[tuple[str, str]]:
    """The deterministic row sequence executed by ``run_slice``.

    Mutants retain the shard's manifest order and covered items retain the
    frozen map order. Resume skips members of this sequence but never changes
    their relative order, so an interrupted shard's durable rows must be an
    exact prefix.
    """
    return [(iid, mutant["id"]) for mutant in mutants
            for iid in by_mutant.get(mutant["id"], [])
            if iid in files_by_item]


def build_campaign_identity(*, asset_index_sha256: str, asset_project: str,
                            mutation_validation_sha256: str,
                            mutation_validation_class: str,
                            manifest_sha256: str, map_sha256: str,
                            release_sha256: str, candidate_run_sha256: str,
                            solution_generated_tests_sha256: str,
                            substrate_baseline_sha256: str,
                            worker_resources_sha256: str,
                            harness_version: object,
                            container_image_digest: str,
                            workspace_seed_digest: str,
                            database_dump_digest: str,
                            expected_pairs: Iterable[tuple[str, str]],
                            engine: str, engine_version: str, parser: str,
                            side: str, shard: int, of: int, timeout: int,
                            generation_provenance_class: str,
                            generation_campaign_digest: Optional[str] = None,
                            generation_attempt_id: Optional[str] = None,
                            generation_agent_runtime_sha256: Optional[str] = None,
                            generation_network_semantics: Optional[str] = None,
                            generation_condition: Optional[str] = None,
                            generation_protocol_version: Optional[int] = None,
                            generation_protocol_digest: Optional[str] = None,
                            generation_native_budget: object = None,
                            manifest_digest: Optional[str] = None,
                            candidate_generated_tests_sha256: Optional[str] = None,
                            gold_baseline_sha256: Optional[str] = None,
                            gold_generated_tests_sha256: Optional[str] = None,
                            gold_results_sha256: Optional[str] = None,
                            gold_results_attestation_sha256: Optional[str] = None,
                            gold_provenance_class: Optional[str] = None,
                            gold_attestation_manifest_digest: Optional[str] = None,
                            gold_attestation_pairs_sha256: Optional[str] = None,
                            gold_attestation_engine: Optional[str] = None,
                            gold_attestation_engine_version: Optional[str] = None,
                            applier_sha256: Optional[str] = None,
                            sample: Optional[int] = None,
                            sample_seed: Optional[int] = None,
                            kind: str = "mutation-run",
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
                            observation_id: Optional[str] = None,
                            reference_control_role: Optional[str] = None,
                            reference_source_tag: Optional[str] = None,
                            reference_workload_digest: Optional[str] = None,
                            population_basis: Optional[str] = None,
                            budgeted_sample_sha256: Optional[str] = None,
                            parent_map_sha256: Optional[str] = None) \
        -> dict:
    """Return the immutable identity of one mutation shard.

    Paths are intentionally absent.  The caller may retain them as operator
    provenance, but resume and merge are decided only by content, the exact
    pair set, and execution semantics.
    """
    pairs = set(expected_pairs)
    v4_values = (execution_policy, batch_plan_sha256, max_batch_members,
                 max_batch_instances, stack_reset_sha256, batch_journal_schema,
                 compute_cap_sha256, reuse_projection_sha256,
                 estimand_pairs_sha256, preflight_cache_policy,
                 observation_id)
    emit_v4 = any(value is not None for value in v4_values)
    # Emitted only where it applies, exactly as `reference_source_tag` is:
    # a full-population leg's identity gains no key, so its digest is the
    # one it always was.
    budgeted_fields = {
        "population_basis": population_basis,
        "budgeted_sample_sha256": budgeted_sample_sha256,
        "parent_map_sha256": parent_map_sha256,
    }
    if all(value is None for value in budgeted_fields.values()):
        budgeted_fields = {}
    identity = {
        "schema": (MUTATION_IDENTITY_SCHEMA_V4 if emit_v4
                   else MUTATION_IDENTITY_SCHEMA_V3
                   if shard_policy is not None else MUTATION_IDENTITY_SCHEMA),
        "kind": kind,
        "asset_index_sha256": asset_index_sha256,
        "asset_project": asset_project,
        "mutation_validation_sha256": mutation_validation_sha256,
        "mutation_validation_class": mutation_validation_class,
        "manifest_sha256": manifest_sha256,
        "manifest_digest": manifest_digest,
        "map_sha256": map_sha256,
        "release_sha256": release_sha256,
        "candidate_run_sha256": candidate_run_sha256,
        "candidate_generated_tests_sha256": (
            candidate_generated_tests_sha256),
        "gold_baseline_sha256": gold_baseline_sha256,
        "gold_generated_tests_sha256": gold_generated_tests_sha256,
        "gold_results_sha256": gold_results_sha256,
        "gold_results_attestation_sha256": (
            gold_results_attestation_sha256),
        "gold_provenance_class": gold_provenance_class,
        "gold_attestation_manifest_digest": (
            gold_attestation_manifest_digest),
        "gold_attestation_pairs_sha256": gold_attestation_pairs_sha256,
        "gold_attestation_engine": gold_attestation_engine,
        "gold_attestation_engine_version": (
            gold_attestation_engine_version),
        "solution_generated_tests_sha256": (
            solution_generated_tests_sha256),
        "substrate_baseline_sha256": substrate_baseline_sha256,
        "applier_sha256": applier_sha256,
        "worker_resources_sha256": worker_resources_sha256,
        "harness_version": harness_version,
        "container_image_digest": container_image_digest,
        "workspace_seed_digest": workspace_seed_digest,
        "database_dump_digest": database_dump_digest,
        "engine": engine,
        "engine_version": engine_version,
        "parser": parser,
        "side": side,
        "shard": int(shard),
        "of": int(of),
        "timeout_seconds": int(timeout),
        "sample": sample,
        "sample_seed": sample_seed,
        "expected_pairs": len(pairs),
        "expected_pairs_sha256": pair_set_digest(pairs),
        # How the CANDIDATE was produced (v2).  Recorded here rather than
        # inferred from `candidate_run_sha256` because inference is not
        # identity: it requires the inferrer to hold the run file, and a
        # published number is read by people who never will.
        "generation_provenance_class": generation_provenance_class,
        "generation_attempt_id": generation_attempt_id,
        "generation_campaign_digest": generation_campaign_digest,
        "generation_agent_runtime_sha256": generation_agent_runtime_sha256,
        "generation_network_semantics": generation_network_semantics,
        "generation_condition": generation_condition,
        "generation_protocol_version": generation_protocol_version,
        "generation_protocol_digest": generation_protocol_digest,
        "generation_native_budget": generation_native_budget,
    }
    if generation_provenance_class == GENERATION_PROVENANCE_REFERENCE_CONTROL:
        old_generation = (
            generation_attempt_id, generation_campaign_digest,
            generation_agent_runtime_sha256, generation_network_semantics,
            generation_condition, generation_protocol_version,
            generation_protocol_digest, generation_native_budget,
        )
        if any(value is not None
               for value in (*old_generation, shard_policy, *v4_values)):
            raise MutationAborted(
                "REFUSED: reference_control_exact_bytes has no generation "
                "attempt/runtime/campaign fields or newer policy fields.")
        identity = {
            key: value for key, value in identity.items()
            if key in CAMPAIGN_IDENTITY_FIELDS_V1
        }
        identity.update({
            "schema": MUTATION_IDENTITY_SCHEMA_V5,
            "generation_provenance_class": generation_provenance_class,
            "reference_control_role": reference_control_role,
            "reference_source_tag": reference_source_tag,
            "reference_workload_digest": reference_workload_digest,
            **budgeted_fields,
        })
        _validate_campaign_identity(identity)
        # WHICH ROUTE MINTED THIS, keyed on the reviewed wrapper being
        # ACTIVE rather than on the project name.  A wrapper-driven mint runs
        # inside its capability, and that binding is kept byte-for-byte: the
        # tuple has to be the workload's exact six members.  A door-driven
        # mint has no capability -- `docx_v2_workload.bind_cli` compares the
        # whole argv against the approved one, so `--reference-role` cannot be
        # spliced into a wrapper phase -- and is bound instead by what the
        # operator declared and `reference_generation_evidence` verified
        # against the harness's own per-row stamp.  Keying this on
        # `asset_project == "python-docx"` would refuse every door-driven
        # python-docx leg, which is exactly the route the 2026-09-01 ruling
        # opened.
        from ..toolkit import docx_v2_workload
        if docx_v2_workload.has_active_capability():
            try:
                docx_v2_workload.require_reference_identity(identity)
            except (ValueError, SystemExit) as exc:
                raise MutationAborted(str(exc)) from exc
        return identity
    if any(value is not None for value in (
            reference_control_role, reference_source_tag,
            reference_workload_digest)):
        raise MutationAborted(
            "REFUSED: reference-control fields require provenance class "
            "reference_control_exact_bytes.")
    if shard_policy is not None:
        identity["shard_policy"] = shard_policy
    if emit_v4:
        identity.update({
            "execution_policy": execution_policy,
            "batch_plan_sha256": batch_plan_sha256,
            "max_batch_members": max_batch_members,
            "max_batch_instances": max_batch_instances,
            "stack_reset_sha256": stack_reset_sha256,
            "batch_journal_schema": batch_journal_schema,
            "compute_cap_sha256": compute_cap_sha256,
            "reuse_projection_sha256": reuse_projection_sha256,
            "estimand_pairs_sha256": estimand_pairs_sha256,
            "preflight_cache_policy": preflight_cache_policy,
            "observation_id": observation_id,
        })
    identity.update(budgeted_fields)
    _validate_campaign_identity(identity)
    return identity


def _full_sha256(value) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def identity_version(identity: dict) -> str:
    """Return the explicit version of the supplied identity document.

    Refused rather than guessed for anything else, and the refusal is the same
    one the single-schema check used to raise, so every caller that already
    handled an unsupported schema keeps handling it.
    """
    schema = identity.get("schema") if isinstance(identity, dict) else None
    if schema == MUTATION_IDENTITY_SCHEMA_V5:
        return "v5"
    if schema == MUTATION_IDENTITY_SCHEMA_V4:
        return "v4"
    if schema == MUTATION_IDENTITY_SCHEMA_V3:
        return "v3"
    if schema == MUTATION_IDENTITY_SCHEMA:
        return "v2"
    if schema == MUTATION_IDENTITY_SCHEMA_V1:
        return "v1"
    raise MutationAborted(
        f"REFUSED: unsupported mutation campaign identity schema "
        f"{schema!r}.")


def _validate_campaign_identity(identity: dict) -> None:
    """Reject unknown, missing, weakly typed, or internally mixed identity.

    All versions validate here, and none is rewritten on the way through:
    a v1 document read back from an archive must re-hash to the digest its
    sidecar recorded, which it can only do if nothing fills a v2 key in.  What
    the version decides is the FIELD SET and the generation rules; every other
    rule below is version-independent, so there is one place where "what a
    mutation campaign must be" is written.
    """
    version = identity_version(identity)
    fields = (CAMPAIGN_IDENTITY_FIELDS_V5 if version == "v5"
              else CAMPAIGN_IDENTITY_FIELDS_V4 if version == "v4"
              else CAMPAIGN_IDENTITY_FIELDS_V3 if version == "v3"
              else CAMPAIGN_IDENTITY_FIELDS if version == "v2"
              else CAMPAIGN_IDENTITY_FIELDS_V1)
    if set(identity) & CAMPAIGN_IDENTITY_BUDGETED_ADDED:
        fields = fields | CAMPAIGN_IDENTITY_BUDGETED_ADDED
    if "continuation_plan_sha256" in identity:
        if (version != "v5" or identity.get("reference_control_role") != "full-gold"
                or identity.get("side") != "gold"
                or identity.get("kind") != "mutation-run"
                or identity.get("sample") is not None
                or not _full_sha256(identity["continuation_plan_sha256"])):
            raise MutationAborted("REFUSED: invalid full-gold continuation identity")
        fields = fields | {"continuation_plan_sha256"}
    if "reference_pair_continuation_sha256" in identity:
        # A suffix segment of a delivered Sylius319 reference continuation
        # (reference_pair_continuation.py): read only through its aggregate.
        if (version != "v5" or identity.get("asset_project") != "sylius"
                or (identity.get("reference_control_role"), identity.get("side")) not in
                    {("assertion-stripped-gold", "candidate"), ("full-gold", "gold"),
                     ("stub-control", "candidate")}
                or (not 1 <= identity.get("of", 0) <= 16
                    if identity.get("reference_control_role") == "stub-control"
                    else identity.get("of") != 32)
                or identity.get("kind") != "mutation-run" or identity.get("sample") is not None
                or "continuation_plan_sha256" in identity
                or not _full_sha256(identity["reference_pair_continuation_sha256"])):
            raise MutationAborted("REFUSED: invalid Sylius reference continuation identity")
        fields = fields | {"reference_pair_continuation_sha256"}
    if "reference_partition" in identity:
        part = identity["reference_partition"]
        valid = (version == "v5" and identity.get("reference_control_role") == "full-gold"
                 and identity.get("side") == "gold" and identity.get("kind") == "mutation-run"
                 and identity.get("sample") is None and "continuation_plan_sha256" not in identity
                 and isinstance(part, dict)
                 and set(part) - {"speeds", "supplement_plan_sha256", "pair_slots"}
                 == {"allocation_sha256", "host", "offset", "total"}
                 and ("speeds" not in part or _valid_reference_speeds(part["speeds"], part["total"]))
                 and ("supplement_plan_sha256" not in part
                      or _full_sha256(part["supplement_plan_sha256"]))
                 and ("pair_slots" not in part
                      or (part["pair_slots"] is True and "supplement_plan_sha256" in part))
                 and _full_sha256(part["allocation_sha256"])
                 and isinstance(part["host"], str) and bool(part["host"])
                 and type(part["offset"]) is int and type(part["total"]) is int
                 and type(identity.get("of")) is int
                 and 0 <= part["offset"] < part["total"]
                 and part["offset"] + identity["of"] <= part["total"])
        if not valid:
            raise MutationAborted("REFUSED: invalid full-gold host partition identity")
        fields = fields | {"reference_partition"}
    missing = sorted(fields - set(identity))
    unknown = sorted(set(identity) - fields)
    if missing or unknown:
        raise MutationAborted(
            f"REFUSED: mutation campaign identity ({version}) fields differ; "
            f"missing={missing}, unknown={unknown}.")
    required_sha = {
        "asset_index_sha256", "mutation_validation_sha256",
        "manifest_sha256", "map_sha256", "release_sha256",
        "candidate_run_sha256", "candidate_generated_tests_sha256",
        "solution_generated_tests_sha256", "substrate_baseline_sha256",
        "applier_sha256", "worker_resources_sha256",
        "workspace_seed_digest", "expected_pairs_sha256"}
    optional_sha = {
        "gold_baseline_sha256", "gold_generated_tests_sha256",
        "gold_results_sha256", "gold_results_attestation_sha256",
        "gold_attestation_pairs_sha256"}
    for key in required_sha:
        if not _full_sha256(identity[key]):
            raise MutationAborted(
                f"REFUSED: mutation campaign identity has invalid {key}: "
                f"{identity[key]!r}.")
    for key in optional_sha:
        if identity[key] is not None and not _full_sha256(identity[key]):
            raise MutationAborted(
                f"REFUSED: mutation campaign identity has invalid {key}: "
                f"{identity[key]!r}.")
    if "population_basis" in identity:
        if identity["population_basis"] != BUDGETED_POPULATION_BASIS:
            raise MutationAborted(
                f"REFUSED: mutation campaign population_basis is "
                f"{identity['population_basis']!r}; the only declared "
                f"non-default basis is {BUDGETED_POPULATION_BASIS!r}, and a "
                f"leg that ran the whole population says so by carrying no "
                f"basis at all.")
        for key in ("budgeted_sample_sha256", "parent_map_sha256"):
            if not _full_sha256(identity[key]):
                raise MutationAborted(
                    f"REFUSED: mutation campaign identity has invalid {key}: "
                    f"{identity[key]!r}.")
    if not _full_sha256(identity["manifest_digest"]):
        raise MutationAborted(
            "REFUSED: mutation campaign manifest_digest is not a full "
            "SHA-256.")
    if identity["gold_attestation_manifest_digest"] is not None \
            and not _full_sha256(
                identity["gold_attestation_manifest_digest"]):
        raise MutationAborted(
            "REFUSED: gold attestation manifest digest is not full SHA-256.")
    for key in ("engine", "engine_version", "parser", "kind",
                "asset_project"):
        if not isinstance(identity[key], str) or not identity[key]:
            raise MutationAborted(
                f"REFUSED: mutation campaign identity has no {key}.")
    harness_version = identity["harness_version"]
    if not ((isinstance(harness_version, str) and harness_version)
            or (isinstance(harness_version, int)
                and not isinstance(harness_version, bool)
                and harness_version >= 1)):
        raise MutationAborted(
            "REFUSED: mutation campaign identity has no resolved positive "
            "harness_version.")
    image = identity["container_image_digest"]
    if not isinstance(image, str) or not image.startswith("sha256:") \
            or not _full_sha256(image[len("sha256:"):]):
        raise MutationAborted(
            "REFUSED: mutation campaign container_image_digest is not a "
            "resolved sha256 image identity.")
    database = identity["database_dump_digest"]
    if database != "no_database" and not _full_sha256(database):
        raise MutationAborted(
            "REFUSED: mutation campaign database_dump_digest is neither a "
            "full SHA-256 nor the explicit no_database sentinel.")
    if not isinstance(identity["kind"], str) \
            or identity["kind"] not in {"mutation-run", "test-quality"}:
        raise MutationAborted(
            f"REFUSED: unsupported mutation campaign kind "
            f"{identity['kind']!r}.")
    if version in {"v3", "v4"}:
        shard_policy = identity["shard_policy"]
        if identity["kind"] != "test-quality" \
                or not isinstance(shard_policy, str) \
                or shard_policy not in TEST_QUALITY_SHARD_POLICIES:
            raise MutationAborted(
                f"REFUSED: mutation campaign identity {version} is reserved for a "
                "test-quality shard carrying a supported shard_policy.")
    if version == "v4":
        policy = identity["execution_policy"]
        if not isinstance(policy, str) \
                or policy not in {EXECUTION_POLICY_SCALAR_V1,
                                  EXECUTION_POLICY_BATCH_BISECT_V1}:
            raise MutationAborted(
                f"REFUSED: mutation campaign identity v4 has unsupported "
                f"execution_policy {policy!r}.")
        for key in ("compute_cap_sha256", "reuse_projection_sha256"):
            value = identity[key]
            if value is not None and not _full_sha256(value):
                raise MutationAborted(
                    f"REFUSED: mutation campaign identity v4 has invalid "
                    f"{key}: {value!r}.")
        if not _full_sha256(identity["estimand_pairs_sha256"]):
            raise MutationAborted(
                "REFUSED: mutation campaign identity v4 has invalid "
                "estimand_pairs_sha256.")
        preflight_policy = identity["preflight_cache_policy"]
        if preflight_policy is not None \
                and (not isinstance(preflight_policy, str)
                     or preflight_policy != "r2t.preflight-cache/1"):
            raise MutationAborted(
                "REFUSED: mutation campaign identity v4 has unsupported "
                f"preflight_cache_policy "
                f"{identity['preflight_cache_policy']!r}.")
        batch_values = {
            "batch_plan_sha256": identity["batch_plan_sha256"],
            "max_batch_members": identity["max_batch_members"],
            "max_batch_instances": identity["max_batch_instances"],
            "stack_reset_sha256": identity["stack_reset_sha256"],
            "batch_journal_schema": identity["batch_journal_schema"],
        }
        if policy == EXECUTION_POLICY_SCALAR_V1:
            if any(value is not None for value in batch_values.values()):
                raise MutationAborted(
                    "REFUSED: scalar mutation identity v4 carries batching "
                    "fields; scalar fields must be null.")
        else:
            if not _full_sha256(batch_values["batch_plan_sha256"]) \
                    or not _full_sha256(batch_values["stack_reset_sha256"]) \
                    or not isinstance(batch_values["batch_journal_schema"], str) \
                    or not batch_values["batch_journal_schema"] \
                    or any(not isinstance(batch_values[key], int)
                           or isinstance(batch_values[key], bool)
                           or batch_values[key] < 1
                           for key in ("max_batch_members",
                                       "max_batch_instances")):
                raise MutationAborted(
                    "REFUSED: batch-bisect mutation identity v4 has missing "
                    "or invalid batching fields.")
        validate_observation_id(identity["observation_id"])
    if identity["kind"] == "test-quality":
        for key in ("gold_baseline_sha256", "gold_generated_tests_sha256"):
            if not _full_sha256(identity[key]):
                raise MutationAborted(
                    f"REFUSED: test-quality campaign identity has invalid "
                    f"{key}: {identity[key]!r}.")
    if version == "v5":
        if identity["kind"] != "mutation-run":
            raise MutationAborted(
                "REFUSED: reference-control identity v5 is reserved for a "
                "standalone mutation run.")
        if identity["generation_provenance_class"] \
                != GENERATION_PROVENANCE_REFERENCE_CONTROL:
            raise MutationAborted(
                "REFUSED: mutation identity v5 requires provenance class "
                "reference_control_exact_bytes.")
        if identity["reference_control_role"] not in REFERENCE_CONTROL_ROLES:
            raise MutationAborted(
                "REFUSED: reference_control_role must be exactly one of "
                f"{sorted(REFERENCE_CONTROL_ROLES)}.")
        expected_side = ("gold" if identity["reference_control_role"]
                         == "full-gold" else "candidate")
        if identity["side"] != expected_side \
                or identity["candidate_generated_tests_sha256"] \
                != identity["solution_generated_tests_sha256"]:
            raise MutationAborted(
                "REFUSED: reference-control role, mutation side, and exact "
                "submitted generated-test bytes disagree.")
        tag = identity["reference_source_tag"]
        if not isinstance(tag, str) or not tag or any(ch.isspace() for ch in tag):
            raise MutationAborted(
                "REFUSED: reference_source_tag must be one non-empty, "
                "space-free reviewed local tag.")
        if not _full_sha256(identity["reference_workload_digest"]):
            raise MutationAborted(
                "REFUSED: reference_workload_digest is not one lower-case "
                "SHA-256.")
    if identity["mutation_validation_class"] != "native":
        raise MutationAborted(
            "REFUSED: new mutation campaigns require a native, release-ready "
            "mutation-asset validation; legacy consistency is audit-only.")
    if identity["side"] not in ("candidate", "gold"):
        raise MutationAborted(
            f"REFUSED: mutation campaign side must be candidate or gold, got "
            f"{identity['side']!r}.")
    for key in ("shard", "of", "timeout_seconds", "expected_pairs"):
        if not isinstance(identity[key], int) or isinstance(identity[key], bool):
            raise MutationAborted(
                f"REFUSED: mutation campaign {key} must be an integer.")
    if identity["of"] < 1 or not 0 <= identity["shard"] < identity["of"]:
        raise MutationAborted(
            f"REFUSED: mutation shard {identity['shard']} of {identity['of']} "
            "is not a valid zero-based shard assignment.")
    if identity["timeout_seconds"] < 1 or identity["expected_pairs"] < 0:
        raise MutationAborted(
            "REFUSED: timeout must be positive and expected-pair count "
            "non-negative.")
    sample, seed = identity["sample"], identity["sample_seed"]
    if sample is None:
        if seed is not None:
            raise MutationAborted(
                "REFUSED: mutation campaign records a sample seed without "
                "a sample.")
    elif not isinstance(sample, int) or isinstance(sample, bool) \
            or sample < 1 or not isinstance(seed, int) \
            or isinstance(seed, bool):
        raise MutationAborted(
            "REFUSED: mutation campaign sample/seed is invalid.")
    has_gold = identity["gold_results_sha256"] is not None
    gold_bound = (
        "gold_results_attestation_sha256", "gold_provenance_class",
        "gold_attestation_manifest_digest", "gold_attestation_pairs_sha256",
        "gold_attestation_engine", "gold_attestation_engine_version")
    if any((identity[key] is not None) != has_gold for key in gold_bound):
        raise MutationAborted(
            "REFUSED: precomputed gold rows, attestation bytes, class, "
            "population, engine and pair-set identity must be bound together.")
    if has_gold and identity["gold_provenance_class"] not in (
            "native", "legacy_consistency"):
        raise MutationAborted(
            "REFUSED: precomputed gold must be classified as native or "
            "legacy_consistency evidence.")
    if has_gold and (identity["gold_attestation_manifest_digest"]
                     != identity["manifest_digest"]
                     or identity["gold_attestation_engine"]
                     != identity["engine"]
                     or identity["gold_attestation_engine_version"]
                     != identity["engine_version"]):
        raise MutationAborted(
            "REFUSED: precomputed gold attests another population or engine.")
    if version in {"v2", "v3", "v4"}:
        _validate_generation_provenance(identity)


def validate_publishable_generation(identity: dict, *, reference_roles=(),
                                    where="this evidence") -> None:
    """Admit ordinary publishable provenance or an explicitly allowed control."""
    if "reference_pair_continuation_sha256" in identity:
        raise MutationAborted("REFUSED: reference continuation suffix requires its aggregate")
    if "continuation_plan_sha256" in identity:
        raise MutationAborted("REFUSED: continued gold is development evidence only")
    klass = identity.get("generation_provenance_class")
    if klass in GENERATION_PROVENANCE_PUBLISHABLE:
        return
    roles = frozenset(reference_roles)
    if klass == GENERATION_PROVENANCE_REFERENCE_CONTROL \
            and identity.get("reference_control_role") in roles:
        return
    raise MutationAborted(
        f"REFUSED: {where} has unpublishable generation provenance "
        f"class/role {klass!r}/{identity.get('reference_control_role')!r}; "
        f"it is not publishable here. Allowed reference roles are "
        f"{sorted(roles)}.")


def _validate_generation_provenance(identity: dict) -> None:
    """The v2 half: which attempt produced the candidate, and under what.

    Two classes, and the difference between them is not cosmetic.
    `native_v2` asserts that a v2 generation fingerprint exists, so the four
    runtime terms are REQUIRED — an attempt that cannot say which runtime it
    ran under is not a v2 attempt.  `legacy_exact_bytes` asserts the
    opposite: no attempt identity exists, and pretending otherwise by
    inventing one is precisely the confusion the class is named for.  So it
    requires them ABSENT, and binds the candidate to the exact registered
    bytes instead.
    """
    from .campaign import legacy_generation_evidence

    klass = identity["generation_provenance_class"]
    if klass not in GENERATION_PROVENANCE_CLASSES:
        raise MutationAborted(
            f"REFUSED: generation_provenance_class must be one of "
            f"{list(GENERATION_PROVENANCE_CLASSES)}, got {klass!r}. A "
            f"candidate is generated under a v2 attempt identity, admitted "
            f"as explicitly labelled legacy evidence, or declared a fixture "
            f"that may never be published; there is no unlabelled state.")
    digest = identity["generation_campaign_digest"]
    if klass == GENERATION_PROVENANCE_DEVELOPMENT:
        # None, and not a placeholder such as `"d" * 16`.  A placeholder would
        # be a well-formed digest naming a campaign that was never minted --
        # readable as evidence by anything that only checks the shape.  None
        # is the fact, and the field is nullable everywhere it is consumed.
        if digest is not None:
            raise MutationAborted(
                f"REFUSED: a {GENERATION_PROVENANCE_DEVELOPMENT} candidate "
                f"names no generation campaign -- that absence is what the "
                f"class RECORDS -- so generation_campaign_digest is None, "
                f"got {digest!r}.")
    elif not isinstance(digest, str) or len(digest) != 16 \
            or any(c not in "0123456789abcdef" for c in digest):
        raise MutationAborted(
            f"REFUSED: generation_campaign_digest must be the 16 hex "
            f"characters `campaign.campaign_digest` returns, got {digest!r}.")
    runtime = identity["generation_agent_runtime_sha256"]
    attempt = identity["generation_attempt_id"]
    semantics = identity["generation_network_semantics"]
    legacy_record = None
    if klass == "native_v2":
        if not isinstance(attempt, str) or not attempt.strip():
            raise MutationAborted(
                "REFUSED: a native_v2 candidate must name the generation "
                "ATTEMPT that produced it; a recipe digest is not an attempt "
                "identity (review finding 20).")
        if not _full_sha256(runtime):
            raise MutationAborted(
                f"REFUSED: a native_v2 candidate must carry its generation "
                f"agent-runtime manifest digest, got {runtime!r}.")
        if not isinstance(semantics, str) or not semantics.strip():
            raise MutationAborted(
                "REFUSED: a native_v2 candidate must state the network "
                "semantics it was generated under.")
    elif klass in (GENERATION_PROVENANCE_FIXTURE,
                   GENERATION_PROVENANCE_DEVELOPMENT):
        # SELF-DISCLOSING, and for two different reasons that land in the same
        # place.  A fixture identity carries no attempt, no runtime digest and
        # no network posture because there was no agent, no runtime and no
        # network.  A development identity carries none of the three because
        # the run was never stamped with the campaign that had them.  Either
        # way, inventing one is what made the old default dangerous, and it
        # would be exactly as dangerous here.
        if attempt is not None or runtime is not None or semantics is not None:
            raise MutationAborted(
                f"REFUSED: a {klass} generation identity carries no attempt "
                f"identity, no runtime manifest digest and no network "
                f"semantics — a {klass} that claims any of the three is "
                f"indistinguishable from evidence. Got attempt={attempt!r}, "
                f"runtime={runtime!r}, network={semantics!r}.")
    else:
        if attempt is not None or runtime is not None or semantics is not None:
            raise MutationAborted(
                f"REFUSED: legacy_exact_bytes evidence has no attempt "
                f"identity, no runtime manifest and no recorded network "
                f"semantics — that absence is what the class NAMES. Got "
                f"attempt={attempt!r}, runtime={runtime!r}, "
                f"network={semantics!r}.")
        record = legacy_generation_evidence(
            run_sha256=identity["candidate_run_sha256"],
            generation_campaign_digest=digest)
        if record is None:
            raise MutationAborted(
                f"REFUSED: run {identity['candidate_run_sha256']} under "
                f"generation digest {digest} is not registered "
                f"legacy_exact_bytes evidence. The class admits exactly the "
                f"documents the owner ruled on "
                f"(`campaign.LEGACY_GENERATION_EVIDENCE`), bound to their "
                f"exact bytes; it is not a way to admit an unlabelled run.")
        if identity["candidate_generated_tests_sha256"] \
                != record["candidate_generated_tests_sha256"]:
            raise MutationAborted(
                f"REFUSED: legacy_exact_bytes evidence for "
                f"{record['label']} binds generated tests "
                f"{record['candidate_generated_tests_sha256']}, but this "
                f"campaign carries "
                f"{identity['candidate_generated_tests_sha256']}. The run "
                f"file and the tests it produced are bound TOGETHER; one "
                f"moved byte breaks both.")
        legacy_record = record
    condition = identity["generation_condition"]
    if condition is not None and (not isinstance(condition, str)
                                  or not condition.strip()):
        raise MutationAborted(
            f"REFUSED: generation_condition must name the arm the candidate "
            f"was generated under (e.g. 'c3') or be None for a control run, "
            f"got {condition!r}.")
    version_ = identity["generation_protocol_version"]
    pdigest = identity["generation_protocol_digest"]
    if version_ is not None and (isinstance(version_, bool)
                                 or not isinstance(version_, int)
                                 or version_ < 1):
        raise MutationAborted(
            f"REFUSED: generation_protocol_version must be a version number "
            f">= 1 or None, got {version_!r}.")
    if pdigest is not None and (not isinstance(pdigest, str)
                                or len(pdigest) != 16
                                or any(c not in "0123456789abcdef"
                                       for c in pdigest)):
        raise MutationAborted(
            f"REFUSED: generation_protocol_digest must be the 16 hex "
            f"characters `protocol.protocol_digest` returns or None, got "
            f"{pdigest!r}.")
    if (version_ is None) != (pdigest is None):
        raise MutationAborted(
            f"REFUSED: the generation protocol version and digest are "
            f"recorded together or not at all, got {version_!r} / "
            f"{pdigest!r}.")
    # THE NATIVE BUDGET IS A MAP, and it is stored as one rather than as a
    # digest of one: `protocol.native_budget` records the knobs IN FORCE
    # (`{"max_reflections": 10}`), a reader comparing two campaigns wants to
    # see which knob differed, and this document is hashed as canonical JSON
    # so a small map costs nothing that a scalar would not.  `{}` and None are
    # kept distinct: the empty map is "this system exposes no native budget",
    # None is "this candidate's rows do not say".
    budget = identity["generation_native_budget"]
    if budget is not None:
        if not isinstance(budget, dict) \
                or any(not isinstance(key, str) or not key
                       for key in budget) \
                or any(not isinstance(value, (str, int, float, bool,
                                              type(None)))
                       for value in budget.values()):
            raise MutationAborted(
                f"REFUSED: generation_native_budget must be the native-knob "
                f"map the candidate's rows record (scalar values only), or "
                f"None where they record none, got {budget!r}.")
    if legacy_record is not None:
        inherited = (
            "generation_condition", "generation_protocol_version",
            "generation_protocol_digest", "generation_native_budget",
        )
        changed = [key for key in inherited
                   if key in legacy_record
                   and _canonical(identity.get(key))
                   != _canonical(legacy_record[key])]
        if changed:
            raise MutationAborted(
                f"REFUSED: legacy_exact_bytes evidence for "
                f"{legacy_record['label']} binds inherited generation "
                f"fact(s) {changed}; this campaign carries different "
                "values. Exact run bytes may not be relabelled under another "
                "arm, protocol, or native budget.")


def campaign_identity_digest(identity: dict) -> str:
    """Full digest of a validated campaign identity, in its saved version.

    A v1 document hashes exactly as it was written, so archived evidence
    keeps verifying against its own sidecar; v2/v3/v4/v5 documents hash their own
    larger field sets.  Nothing here upgrades a document on the way through —
    an "upgrade" would silently restate history under an identity it never
    had, which is the one thing `legacy_exact_bytes` exists to make explicit.
    """
    _validate_campaign_identity(identity)
    return content_digest(identity)


def refuse_mixed_generation_evidence(identities: Iterable[dict],
                                     where: str) -> None:
    """One identity version and one generation attempt, or refuse by name.

    Both faults are already implied by the campaign-core comparison every
    merge does — two versions and two attempts produce different cores — but
    "mixed campaign cores" sends an operator hunting through forty fields.
    These two sentences name the fault and say whether it can be fixed:
    an identity-version mix never merges, and neither does a re-run.
    """
    docs = [identity for identity in identities if isinstance(identity, dict)]
    versions = sorted({identity_version(identity) for identity in docs})
    if len(versions) > 1:
        raise MutationAborted(
            f"REFUSED: {where} mixes mutation campaign identity versions "
            f"{versions}. v1 evidence records no generation attempt, runtime "
            f"or network semantics; merging a newer shard beside it would let "
            f"the v1 rows inherit identity they never carried.")
    if versions in (["v2"], ["v3"]):
        # ATTEMPT identity only — not the candidate bytes.  Two shards naming
        # different candidates are refused a line later as mixed campaign
        # cores, which is the accurate sentence for that fault; this one is
        # reserved for the mix a v1 fingerprint could not see at all: same
        # recipe, different ATTEMPT (review finding 20's chimeric shard set,
        # merged cleanly under one digest with `harness_commit` mixed).
        attempts = sorted(
            {(identity.get("generation_provenance_class"),
              identity.get("generation_attempt_id"),
              identity.get("generation_campaign_digest"))
             for identity in docs})
        if len(attempts) > 1:
            raise MutationAborted(
                f"REFUSED: {where} spans {len(attempts)} generation "
                f"attempts, e.g. {attempts[0]} and {attempts[1]}. A re-run is "
                f"a new campaign; its shards are merged among themselves or "
                f"not at all.")


def _homogeneous_row_fact(rows: Iterable[dict], key: str):
    """The one value the rows agree on for *key*, or None if none says.

    Disagreement is REFUSED rather than resolved by majority or by first-row
    order: a run file whose rows carry two conditions is two runs
    concatenated, and every generation fact this function returns is about to
    become part of an identity that asserts it of all of them.

    Absence is not disagreement.  Rows written before a stamp existed carry
    no key at all (`runner.STAMP_OPTIONAL_FIELDS`), and the same reading
    applies here: unverifiable, not wrong.
    """
    seen = [row[key] for row in rows if isinstance(row, dict) and key in row]
    unique = {json.dumps(value, sort_keys=True) for value in seen}
    if len(unique) > 1:
        raise MutationAborted(
            f"REFUSED: this candidate run's rows disagree about {key!r}: "
            f"{sorted(unique)[:3]}. A run file holding two configurations is "
            f"two runs, and a mutation campaign identity would assert one of "
            f"them about all of the rows.")
    return seen[0] if seen else None


def generation_evidence_for_run(run_path: str,
                                run_rows: Iterable[dict], *,
                                development: bool = False) -> dict:
    """The v2 generation facts for the candidate at *run_path*.

    Three admissible shapes, and nothing else (plan §3, PR R3 plus DOCX):

      1. REGISTERED LEGACY EVIDENCE — the run's exact bytes appear in
         `campaign.LEGACY_GENERATION_EVIDENCE`, so the owner has ruled on
         them by SHA-256.  The class is `legacy_exact_bytes`, the 16-hex
         generation digest remains recipe-scoped v1 evidence, and no attempt
         identity is invented.
      2. NATIVE v2 — the run has a `<run>.campaign.json` sidecar carrying an
         `r2t.generation-campaign/v2` fingerprint, and every stamped row
         carries that fingerprint's digest.  The rows are what bind the
         sidecar to the bytes: a sidecar copied in beside another run file
         would name a digest the rows do not.
      3. DOCX REFERENCE CONTROL — only while its closed evidence workload is
         active, the exact run resolves to its v5 role, reviewed source tag,
         and workload digest without invented attempt/runtime facts.

    Anything else is refused, by name, with all shapes spelled out.  The
    alternative — defaulting to "no generation facts recorded" — is exactly
    the indirect binding ruling 2.2 rejected.

    The resolver opens one non-symlink regular file, hashes those raw bytes,
    parses its JSONL from those same bytes, and verifies that *run_rows* is a
    type-preserving canonical view of those records.  A caller can therefore
    neither assert another digest nor substitute rows from another file.

    *development* adds a fourth OUTCOME rather than a fourth shape: where none
    of the three resolves, it records the absence as `development_unstamped`
    instead of refusing, so an ordinary-route candidate can be scored during
    development.  It is answered at the FINAL raise and nowhere earlier, and
    that placement is the whole of the design: a run that DOES carry a v2
    sidecar or a registry entry has already returned above with its real
    provenance, so the flag can only supply provenance where there is none.
    It can never downgrade provenance that exists.
    """
    from .campaign import (GENERATION_CAMPAIGN_SCHEMA, campaign_digest,
                           fingerprint_version, legacy_generation_evidence)

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(run_path, flags)
    except OSError as e:
        raise MutationAborted(
            f"REFUSED: candidate generation evidence is not a regular file "
            f"or cannot be read: {run_path}: {e}.") from e
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise MutationAborted(
                f"REFUSED: candidate generation evidence is not a regular "
                f"file: {run_path}.")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            run_bytes = fh.read()
    finally:
        os.close(fd)
    supplied_rows = list(run_rows)
    file_rows = []
    try:
        run_text = run_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise MutationAborted(
            f"REFUSED: candidate generation evidence {run_path} is not "
            f"UTF-8: {e}.") from e
    for number, line in enumerate(run_text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            file_rows.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise MutationAborted(
                f"REFUSED: candidate generation evidence {run_path} line "
                f"{number} is not JSON: {e}.") from None
    if len(supplied_rows) != len(file_rows) or any(
            _canonical(supplied) != _canonical(recorded)
            for supplied, recorded in zip(supplied_rows, file_rows)):
        raise MutationAborted(
            "REFUSED: candidate generation rows are not the exact "
            "type-preserving JSON records in the run file. Generation "
            "facts must be derived from the same bytes whose SHA-256 is "
            "registered, not from caller-supplied replacement rows.")
    rows = file_rows
    digest = hashlib.sha256(run_bytes).hexdigest()
    # Owner-registered exact bytes keep their legacy identity even while a
    # reference workload is active; the capability can classify only runs the
    # registry does not already own.
    record = legacy_generation_evidence(run_sha256=digest)
    if record is None:
        from ..toolkit import docx_v2_workload
        reference = docx_v2_workload.generation_evidence(digest)
        if reference is not None:
            return reference
    facts = {
        "generation_condition": _homogeneous_row_fact(rows, "condition"),
        "generation_protocol_version": _homogeneous_row_fact(
            rows, "protocol_version"),
        "generation_protocol_digest": _homogeneous_row_fact(
            rows, "protocol_digest"),
        "generation_native_budget": _homogeneous_row_fact(
            rows, "native_budget"),
    }
    if record is not None:
        inherited = (
            "generation_condition", "generation_protocol_version",
            "generation_protocol_digest", "generation_native_budget",
        )
        changed = [key for key in inherited
                   if key in record
                   and _canonical(facts.get(key))
                   != _canonical(record[key])]
        if changed:
            raise MutationAborted(
                f"REFUSED: registered legacy evidence {record['label']} "
                f"binds inherited generation fact(s) {changed}, but the run "
                "rows disagree. The registry binds exact run and generated-"
                "test bytes; it is not a relabelling flag.")
        return {
            **facts,
            "generation_provenance_class": "legacy_exact_bytes",
            "generation_attempt_id": None,
            "generation_campaign_digest":
                record["generation_campaign_digest"],
            "generation_agent_runtime_sha256": None,
            "generation_network_semantics": None,
            "legacy_generation_evidence": record,
        }
    sidecar = run_path + ".campaign.json"
    if not os.path.islink(sidecar) and os.path.isfile(sidecar):
        try:
            with open(sidecar, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            raise MutationAborted(
                f"REFUSED: cannot read candidate campaign sidecar "
                f"{sidecar}: {e}") from e
        fingerprint = doc.get("campaign") if isinstance(doc, dict) else None
        try:
            version = fingerprint_version(fingerprint or {})
        except SystemExit as e:
            raise MutationAborted(str(e)) from e
        if version != "v2":
            raise MutationAborted(
                f"REFUSED: {sidecar} carries a v1 generation fingerprint, "
                f"which records no attempt, no harness bytes and no runtime. "
                f"Re-generate under {GENERATION_CAMPAIGN_SCHEMA}, or register "
                f"these exact bytes as legacy_exact_bytes evidence the way "
                f"the owner ruled the corrected Cell 3 candidate in.")
        try:
            fingerprint_digest = campaign_digest(fingerprint)
        except SystemExit as e:
            raise MutationAborted(str(e)) from e
        # EVERY ROW, not merely a homogeneous one.  `_homogeneous_row_fact`
        # reads absence as unverifiable-not-wrong, which is right for a fact
        # a row may predate — and wrong here, because this is the binding
        # itself: a file with one stamped row and a thousand unstamped ones
        # would otherwise satisfy "the rows carry the sidecar's digest" while
        # 999 of them came from anywhere at all.
        unstamped = [number for number, row in enumerate(rows, 1)
                     if not isinstance(row, dict)
                     or "campaign_digest" not in row]
        if unstamped:
            raise MutationAborted(
                f"REFUSED: {len(unstamped)} of {len(rows)} row(s) in "
                f"{run_path} carry no campaign_digest at all (e.g. line "
                f"{unstamped[0]}), so this run is not one v2 generation "
                f"campaign's output. A partially stamped file is a merge of "
                f"stamped and unattributable rows; it may not be admitted "
                f"under the sidecar's attempt identity.")
        stamped = _homogeneous_row_fact(rows, "campaign_digest")
        if stamped is None or stamped != fingerprint_digest:
            raise MutationAborted(
                f"REFUSED: {sidecar} names generation campaign "
                f"{fingerprint_digest}, but the run's rows carry "
                f"{stamped!r}. A sidecar is bound to its rows by what they "
                f"were stamped with, never by sitting next to them.")
        # AND THE FACTS MUST AGREE WITH THE FINGERPRINT THEY ARE FILED UNDER.
        # The row half and the campaign half are written by different code at
        # different times (`runner._run_stamp` from the worker's own args,
        # the fingerprint once before any worker started), so rows uniformly
        # stamped `c2` under a `c3` fingerprint are internally consistent and
        # false — the same disagreement `campaign.STAMP_CROSSCHECKS` refuses
        # at merge, refused here before an identity is minted from it.
        #
        # One-sided in the same direction as that check: a fingerprint that
        # declares nothing about a field constrains nothing, while one that
        # DOES declare it demands the rows carry it and carry the same value.
        for fact_key, fingerprint_key in (
                ("generation_condition", "condition"),
                ("generation_protocol_version", "protocol_version"),
                ("generation_protocol_digest", "protocol_digest")):
            declared = fingerprint.get(fingerprint_key)
            if declared is None:
                continue
            if facts[fact_key] != declared:
                raise MutationAborted(
                    f"REFUSED: {sidecar} declares "
                    f"{fingerprint_key}={declared!r}, but the run's rows say "
                    f"{facts[fact_key]!r}. The generation facts a v2 mutation "
                    f"campaign records must be the ones its own fingerprint "
                    f"asserts; a candidate generated under another arm or "
                    f"recipe than the campaign it is filed under cannot be "
                    f"scored as either.")
        return {
            **facts,
            "generation_provenance_class": "native_v2",
            "generation_attempt_id": fingerprint["attempt_id"],
            "generation_campaign_digest": fingerprint_digest,
            "generation_agent_runtime_sha256":
                fingerprint["agent_runtime_sha256"],
            "generation_network_semantics": fingerprint["network_semantics"],
        }
    if development:
        # THE LAST WORD, deliberately.  Everything above returned real
        # provenance; only a run that has none at all reaches this line, and
        # for that run the four campaign-only fields are None because there
        # is no campaign to name.  The row-derived facts computed above stay
        # exactly as the rows recorded them.
        return {
            **facts,
            "generation_provenance_class": GENERATION_PROVENANCE_DEVELOPMENT,
            "generation_attempt_id": None,
            "generation_campaign_digest": None,
            "generation_agent_runtime_sha256": None,
            "generation_network_semantics": None,
        }
    raise MutationAborted(
        f"REFUSED: candidate run {run_path} (sha256 {digest}) carries no "
        f"generation provenance a current mutation campaign can record. It "
        f"needs "
        f"either an active reviewed DOCX reference workload, a {sidecar!r} "
        f"sidecar holding an "
        f"{GENERATION_CAMPAIGN_SCHEMA} fingerprint whose digest its rows are "
        f"stamped with, or an entry in "
        f"`campaign.LEGACY_GENERATION_EVIDENCE` binding these exact bytes. "
        f"For a development candidate that has none of the three, "
        f"`test-quality --development` records the absence as "
        f"{GENERATION_PROVENANCE_DEVELOPMENT}, which is scorable and never "
        f"publishable.")


def reference_generation_evidence(*, role: str, source_tag: str,
                                  candidate_rows: Iterable[dict],
                                  release_item_ids: Iterable[str],
                                  release_sha256: str,
                                  asset_index_sha256: str,
                                  control: Optional[dict] = None) -> dict:
    """The v5 generation members for an operator-declared reference leg.

    The DOCX reference legs get theirs from a reviewed workload document that
    pins the exact six-member tuple.  A project that has no such document
    declares its leg on the `mutation-run --reference-role` argv instead --
    and a declaration is only admissible as identity if something other than
    the operator's typing can contradict it, because a pair of these legs is
    directly admissible as the release gold kill set
    (`gold_killset.validate_observation_pair` allows the `full-gold` role) and
    as hard-subset population evidence (`hard_subset._validate_record`).

    Two things contradict it, and both are facts the harness itself wrote:

    THE ROLE IS THE ADAPTER STAMP.  `runner._run_stamp` puts
    `"adapter": adapter.name` on every row of every run, so a full-gold leg's
    rows say `gold`, a stripped leg's say `stripped-gold`, and a stub leg's
    say `stub` -- exactly the mapping in `REFERENCE_CONTROL_ROLE_ADAPTERS`.
    A candidate whose rows disagree with the declared role is refused by the
    row that disagrees.  An absent field is a disagreement: an unstamped file
    cannot say which control it is, which is the state the declaration exists
    to resolve rather than to assert past.

    THE OBSERVATION IS COMPLETE.  A reference observation is the whole mapped
    population -- `--sample`, `--sample-seed`, `--mutant-limit` and
    `--pair-plan` are refused by name on the argv for that reason, and a run
    file covering only part of the release reaches the same partial state by
    another route.  So the candidate's item set must EQUAL the release item
    set this campaign is bound to.
    """
    from .fixtures import FIXTURES

    adapter = REFERENCE_CONTROL_ROLE_ADAPTERS[role]
    rows = list(candidate_rows)
    for number, row in enumerate(rows, 1):
        stamped = row.get("adapter")
        if stamped != adapter:
            raise MutationAborted(
                f"REFUSED: --reference-role {role} declares these candidate "
                f"bytes are the {adapter!r} control, but row {number} "
                f"(item {row.get('item_id')!r}) carries adapter "
                f"{stamped!r}. The role is checked against the harness's own "
                f"per-row stamp (runner._run_stamp), not taken on the "
                f"operator's word.")
    released = set(release_item_ids)
    observed = {row["item_id"] for row in rows}
    missing = sorted(released - observed)
    extra = sorted(observed - released)
    if missing or extra:
        raise MutationAborted(
            f"REFUSED: a reference observation is the complete mapped "
            f"population, but these candidate bytes cover {len(observed)} "
            f"item(s) against a release of {len(released)}: {len(missing)} "
            f"released item(s) missing"
            + (f" (e.g. {', '.join(missing[:3])})" if missing else "")
            + f" and {len(extra)} item(s) that are not released"
            + (f" (e.g. {', '.join(extra[:3])})" if extra else "")
            + ". --sample and --mutant-limit are refused by name for this "
              "same invariant; a short run file reaches it another way.")
    if control is not None:
        from . import reference_workloads as RW
        from .test_quality import passed_solutions

        # The development reader has rederived ALL baseline rows, including
        # failed stubs and authentic stripped refusals. Its recorded producer
        # remains distinct from source_tag, the reviewed common freeze used
        # by this prospective reference observation.
        recipe_role = next(key for key, value in RW.ROLE_ADAPTERS.items()
                           if value == adapter)
        try:
            recipe = RW.validate_recipe(control["recipe"], role=recipe_role,
                                        execution_release_sha256=release_sha256)
            producer = RW._recorded_source_tag(rows, recipe, recipe_role)
            files = passed_solutions(rows)
            run_hash = control["candidate_run_sha256"]
            workload = {"recipe": recipe,
                        "baseline": {"sha256": run_hash, "source_tag": producer}}
            digest = content_digest(workload)
            if recipe["asset_index_sha256"] != asset_index_sha256 \
                    or producer != control["reference_source_tag"] \
                    or {row["item_id"]: row["outcome"] for row in rows} != control["baseline_outcomes"] \
                    or files != control["files_by_item"] \
                    or candidate_digest(files) != control["generated_tests_sha256"] \
                    or digest != control["reference_workload_digest"]:
                raise ValueError("authenticated control differs from the reference inputs")
            if not isinstance(run_hash, str) or len(run_hash) != 64 \
                    or any(ch not in "0123456789abcdef" for ch in run_hash):
                raise ValueError("authenticated control has no baseline SHA-256")
        except (KeyError, TypeError, ValueError) as exc:
            raise MutationAborted(f"REFUSED: source-bound reference input: {exc}") from exc
        return {"generation_provenance_class": GENERATION_PROVENANCE_REFERENCE_CONTROL,
                "reference_control_role": role, "reference_source_tag": source_tag,
                "reference_workload_digest": digest}
    if any("reference_derivation" in row for row in rows):
        raise MutationAborted("REFUSED: prospective control inputs require authenticated source replay")
    return {
        "generation_provenance_class":
            GENERATION_PROVENANCE_REFERENCE_CONTROL,
        "reference_control_role": role,
        "reference_source_tag": source_tag,
        # THE RECIPE, NOT THE BYTES.  The amendment's member 6 is "the
        # semantic digest of the workload that admits the control", and on
        # this route there is no workload document to digest -- so it is
        # built from what DECIDES what a leg executes.  Digesting the
        # generated-test map here would make member 6 a byte-for-byte copy of
        # member 4 (`candidate_generated_tests_sha256`), so comparing them
        # would prove nothing.
        #
        # BE EXACT ABOUT WHAT IT ADDS, because an earlier draft of this
        # comment overclaimed and a reviewer was right to say so: two of the
        # four inputs, `release_sha256` and `asset_index_sha256`, ARE already
        # members of this same tuple (CAMPAIGN_IDENTITY_FIELDS_V1).  They are
        # here to SCOPE the digest, not to add information -- so that one
        # role's digest cannot be carried to another population or another
        # released item set.  The information member 6 actually contributes
        # over the rest of the tuple is the adapter identity: nothing else in
        # a v5 identity says which of the three controls these bytes are.
        #
        #   adapter/adapter_version -- WHICH control this is, as the registry
        #     defines it: `gold` reads the release's gold tree, `stripped-gold`
        #     strips its assertions, `stub` emits closures. The version is what
        #     a change to any of those has to increment, so a leg collected
        #     before that change stays distinguishable from one collected
        #     after.
        #   release_sha256 -- over WHICH items, and it is also the document
        #     the completeness check above is taken against.
        #   asset_index_sha256 -- under WHICH registered population: the index
        #     pins this project's boundary config, scored manifest, mutation
        #     map and coverage oracle, and it is the identity every other
        #     member of this campaign is already bound to.
        #
        # What it does NOT cover: the gold tree's own bytes under `--gold`.
        # No campaign identity member digests that tree, and inventing one
        # here would be a new artifact rather than a binding of an existing
        # one.
        "reference_workload_digest": content_digest({
            "adapter": adapter,
            "adapter_version": FIXTURES[adapter].version,
            "release_sha256": release_sha256,
            "asset_index_sha256": asset_index_sha256,
        }),
    }


@dataclass(frozen=True)
class Applier:
    """How one engine's applier is staged and invoked.

    Facts and no behaviour, because there is exactly one applier protocol and
    every engine implements it: the program is copied into the
    workspace under `var/`, and it is invoked with the mutant's own
    coordinates (`--apply-file --start-line --start-col --operator --original
    --mutated --out`) so that it can RE-ENUMERATE the target and refuse a
    mutant it would not itself have produced.  Nothing about that contract is
    language-specific. Script engines need the file name, staging path, and
    interpreter; compiled-source engines additionally name their entry point.
    """
    #: The program's name inside the engine directory.
    source: str
    #: Where it is staged, repo-relative.  Must stay outside the hashed
    #: substrate roots — a file under `_bench/` aborts the next item as
    #: tampering, which is the reason `var/` is not a preference.
    rel: str
    #: What runs it inside the container.
    interpreter: str
    #: Optional compiled main class. Script engines leave this absent and are
    #: invoked as ``interpreter rel``. The Java engine stages source at
    #: ``rel``, compiles it once in ``install_applier``, then invokes this
    #: exact class; putting a wrapper in the measured repository would make
    #: the enumerator and applier different programs.
    entrypoint: Optional[str] = None
    #: Workspace-relative javac output directory. Present iff ``entrypoint``
    #: is present; keeping it structured (not embedded in a shell fragment)
    #: lets both campaign execution and the materialisation auditor construct
    #: and attest the same command.
    classes_rel: Optional[str] = None


#: The CoreShop applier, and the default everywhere below: every existing
#: caller keeps sending byte-identical commands.
PHP_APPLIER = Applier(source="mutate.php", rel=APPLIER_REL, interpreter="php")


@dataclass(frozen=True)
class Engine:
    """One mutation engine's identity, held as ONE object.

    `name` and `version` are hashed into every mutant id, `engine_dir` is
    where this repository keeps the enumerator/applier program, and `applier`
    is how that program is staged and invoked.  Those are one fact rather
    than four: a manifest minted by `name` can only be materialised by THIS
    applier out of THIS directory, and a release may only claim `name` at
    THIS version.  Held together so that the readers below cannot each end up
    with a different subset of the same engine.
    """
    name: str
    version: str
    engine_dir: str
    applier: Applier
    #: The keep-roots-and-drops policy its population is defined over, in
    #: `mutation.is_excluded`'s vocabulary.
    excluded_prefixes: tuple[str, ...]


def engines() -> dict[str, Engine]:
    """Every mutation engine this tree can execute, keyed by its own name.

    THE table.  `binding_for` below, `release._known_engines` and the three
    stack façades in `r2t/stacks/` all read this one, so a fourth language is
    one row here plus the module that owns its constants — not four tables
    that agree today and drift apart at the next engine.  `stacks.selftest`
    holds the façades to it.

    Deliberately a literal dict rather than a registry protocol: this
    benchmark has four engines and adding one changes what mutant
    ids mean, which is a reviewed act.  Discovery machinery would let a
    fourth arrive without that review.

    Built on call rather than at import because each engine module imports
    this one back for `Applier`.
    """
    from ..data import mutation as _php
    from ..toolkit import mutation_java as _java
    from ..toolkit import mutation_py as _py
    from ..toolkit import mutation_rb as _rb
    from ..toolkit import mutation_go as _go
    return {engine.name: engine for engine in (
        Engine(name=ENGINE, version=ENGINE_VERSION,
               engine_dir=PHP_ENGINE_DIR, applier=PHP_APPLIER,
               excluded_prefixes=_php.EXCLUDED_PREFIXES),
        Engine(name=_py.ENGINE, version=_py.ENGINE_VERSION,
               engine_dir=_py.PY_ENGINE_DIR, applier=_py.applier(),
               excluded_prefixes=_py.EXCLUDED_PREFIXES),
        Engine(name=_java.ENGINE, version=_java.ENGINE_VERSION,
               engine_dir=_java.JAVA_ENGINE_DIR, applier=_java.applier(),
               excluded_prefixes=_java.EXCLUDED_PREFIXES),
        Engine(name=_rb.ENGINE, version=_rb.ENGINE_VERSION,
               engine_dir=_rb.RB_ENGINE_DIR, applier=_rb.applier(),
               excluded_prefixes=_rb.EXCLUDED_PREFIXES),
        Engine(name=_go.ENGINE, version=_go.ENGINE_VERSION,
               engine_dir=_go.GO_ENGINE_DIR, applier=_go.applier(),
               excluded_prefixes=_go.EXCLUDED_PREFIXES),
    )}


def binding_for(engine: str) -> tuple[str, Applier]:
    """`(engine_dir, applier)` for the engine that MINTED a manifest's ids.

    Keyed on the ENGINE and on nothing else, because the engine is what the
    ids hash: a slice executed with the wrong applier would stage a program
    that cannot re-enumerate the file it is about to rewrite, and the
    "REFUSED: enumerating X now yields no mutant" that follows would be true
    of the applier rather than of the tree.  Reading it off the manifest also
    means a caller cannot pair a python population with the PHP applier by
    passing the wrong flag — there is no flag.

    An unknown engine is refused rather than defaulted.  `r2t-mutate` is not
    a safe fallback: it is `php`, and pointing it at a Python file produces a
    parse error that reads like a corrupt corpus.
    """
    bound = engines().get(engine)
    if bound is None:
        raise MutationAborted(
            f"REFUSED: no applier for mutation engine {engine!r}. Its mutant ids "
            f"hash that name, so nothing here can materialise them, and running "
            f"the campaign under another engine's applier would score a "
            f"different population under these ids.")
    return (bound.engine_dir, bound.applier)


def runtime_applier_sha256(engine: str, seed_dir: str) -> str:
    """SHA-256 of the applier bytes a campaign of `engine` executes.

    Go workers run the mutate.go installed in their verified `seed_dir`, so
    that seed member is the applier identity; this checkout's go/mutate.go is
    the catalogue builder, pinned separately. Every other engine stages this
    checkout's applier source and ignores `seed_dir`.
    """
    engine_dir, applier = binding_for(engine)
    if engine != "r2t-mutate-go":
        return sha256_file(os.path.join(engine_dir, applier.source))
    from ..go import mutation_runtime as go_runtime
    try:
        return hashlib.sha256(go_runtime.seed_applier(seed_dir)).hexdigest()
    except go_runtime.MutationRuntimeRefused as exc:
        raise MutationAborted(str(exc)) from exc


class MutationAborted(RuntimeError):
    pass


class MutationCancelled(MutationAborted):
    """Cooperative coordinator cancellation after restoration is safe."""


def _sha256(path: str) -> str:
    return sha256_file(path)


def _empty_sha256() -> str:
    return hashlib.sha256(b"").hexdigest()


def _open_parent_dir_fd(path: str) -> tuple[int, str]:
    """Open every parent component without following a symlink."""
    absolute = os.path.abspath(path)
    parent, name = os.path.split(absolute)
    if not name:
        raise OSError("path has no final component")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(os.path.sep, flags)
    try:
        for component in [part for part in parent.split(os.sep) if part]:
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, name
    except Exception:
        os.close(fd)
        raise


def _open_regular_nofollow(path: str, flags: int = os.O_RDONLY) -> int:
    parent_fd, name = _open_parent_dir_fd(path)
    try:
        fd = os.open(name, flags | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    current = os.fstat(fd)
    if not stat.S_ISREG(current.st_mode):
        os.close(fd)
        raise OSError("target is not a regular file")
    return fd


def _read_file_nofollow(path: str) -> bytes:
    try:
        fd = _open_regular_nofollow(path)
    except OSError as exc:
        raise MutationAborted(
            f"REFUSED: cannot open mutation target without following links "
            f"{path}: {exc}") from exc
    try:
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(fd)


def _file_lstat_identity(path: str) -> dict:
    """The source-file metadata a materialisation is allowed to preserve."""
    try:
        fd = _open_regular_nofollow(path)
        try:
            current = os.fstat(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise MutationAborted(
            f"REFUSED: mutation target is not a non-symlink regular file: "
            f"{path}: {exc}") from exc
    return {"mode": current.st_mode, "uid": current.st_uid,
            "gid": current.st_gid}


def _validate_lstat_identity(value: dict) -> dict:
    if not isinstance(value, dict) or set(value) != {"mode", "uid", "gid"} \
            or any(not isinstance(value[key], int)
                   or isinstance(value[key], bool)
                   for key in ("mode", "uid", "gid")) \
            or value["uid"] < 0 or value["gid"] < 0 \
            or not stat.S_ISREG(value["mode"]):
        raise MutationAborted(
            "REFUSED: applied mutation lacks an exact regular-file "
            "mode/uid/gid identity")
    return value


def _restore_bytes_and_lstat(path: str, data: bytes, identity: dict,
                             why: str) -> None:
    """Atomically restore bytes/lstat without following target or parents."""
    wanted = _validate_lstat_identity(identity)
    parent_fd = -1
    temporary = None
    fd = -1
    try:
        parent_fd, name = _open_parent_dir_fd(path)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL \
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        for _attempt in range(20):
            temporary = ".r2t-restore-" + secrets.token_hex(12)
            try:
                fd = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
                break
            except FileExistsError:
                continue
        if fd < 0:
            raise OSError("cannot reserve a private restoration file")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        current = os.fstat(fd)
        if (current.st_uid, current.st_gid) \
                != (wanted["uid"], wanted["gid"]):
            os.fchown(fd, wanted["uid"], wanted["gid"])
        # Ownership changes can clear set-ID bits, so the complete 07777 mode
        # is always restored last.  Read-only originals need no writable
        # intermediate pathname because all writes target the private file.
        os.fchmod(fd, stat.S_IMODE(wanted["mode"]))
        os.fsync(fd)
        staged = os.fstat(fd)
        if {"mode": staged.st_mode, "uid": staged.st_uid,
                "gid": staged.st_gid} != wanted:
            raise OSError("private restoration file has wrong mode/uid/gid")
        os.replace(temporary, name, src_dir_fd=parent_fd,
                   dst_dir_fd=parent_fd)
        temporary = None
        os.fsync(parent_fd)
        os.lseek(fd, 0, os.SEEK_SET)
        restored = bytearray()
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            restored.extend(chunk)
        if bytes(restored) != data:
            raise OSError("private restoration bytes did not read back")
    except OSError as exc:
        raise MutationAborted(
            f"REFUSED: cannot restore bytes/lstat for {path} after {why}: "
            f"{exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None and parent_fd >= 0:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except OSError:
                pass
        if parent_fd >= 0:
            os.close(parent_fd)
    if _read_file_nofollow(path) != data \
            or _file_lstat_identity(path) != wanted:
        raise MutationAborted(
            f"REFUSED: {path} did not restore exact bytes/mode/uid/gid after "
            f"{why}; this worker must be reprovisioned")


def substrate_baseline_digest(harness: Harness) -> str:
    """Identity of the exact immutable-source baseline a worker trusts.

    The digest binds both the path-to-content mapping and the policy that says
    which roots/volatile files that mapping covers.  Two pristine workers with
    different baselines therefore cannot contribute shards to one campaign.
    Unit fakes without a real ``StripManifest`` may expose an explicit full
    digest; real harnesses always derive it from ``man`` and cannot override
    their recorded baseline.
    """
    man = getattr(harness, "man", None)
    if man is not None:
        digests = getattr(man, "digests", None)
        if not isinstance(digests, dict) or not digests:
            raise MutationAborted(
                "REFUSED: this workspace has no nonempty substrate baseline "
                "to bind into the mutation campaign identity.")
        roots_fn = getattr(man, "roots", None)
        volatile_fn = getattr(man, "volatile", None)
        roots = list(roots_fn()) if callable(roots_fn) else list(
            getattr(man, "substrate_roots", None) or ())
        volatile = sorted(volatile_fn()) if callable(volatile_fn) else sorted(
            getattr(man, "substrate_volatile", None) or ())
        return content_digest({
            "digests": digests,
            "roots": roots,
            "volatile": volatile,
            "boundary_version": getattr(man, "boundary_version", None),
        })
    override = getattr(harness, "substrate_baseline_sha256", None)
    if (not isinstance(override, str) or len(override) != 64
            or any(c not in "0123456789abcdef" for c in override)):
        raise MutationAborted(
            "REFUSED: a harness without a StripManifest must expose a full "
            "substrate_baseline_sha256 for mutation execution.")
    return override


def _mutation_lock_root() -> str:
    root = os.path.join(
        tempfile.gettempdir(), f"r2t-mutation-locks-{os.getuid()}")
    if os.path.lexists(root) and (os.path.islink(root)
                                 or not os.path.isdir(root)):
        raise MutationAborted(
            f"REFUSED: mutation lock root is not a private directory: "
            f"{root}.")
    os.makedirs(root, mode=0o700, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError as e:
        raise MutationAborted(
            f"REFUSED: cannot secure mutation lock root {root}: {e}") from e
    return root


def _resource_identity(kind: str, value: str) -> tuple[str, str]:
    if not isinstance(kind, str) or not kind \
            or not isinstance(value, str) or not value:
        raise MutationAborted(
            f"REFUSED: mutation resource identity is invalid: "
            f"{kind!r}={value!r}.")
    if kind in {"workspace", "env_file", "output"}:
        value = os.path.realpath(os.path.abspath(value))
    return kind, value


#: Bound on how long a K-way shard waits for a sibling's output-directory
#: claim (`prepare_standalone_output_directory`).  Controllers may start
#: sibling shards in the same instant; the claim is a few filesystem
#: operations, so a holder past this bound is refused as before.
OUTPUT_CLAIM_WAIT_SECONDS = 60.0


@contextmanager
def mutation_resource_locks(resources: Iterable[tuple[str, str]], *,
                            wait_seconds: float = 0.0):
    """Hold every workspace/container/schema resource for a coordinator.

    Locks are acquired in canonical sorted order and held for the context's
    whole lifetime.  Different output directories therefore cannot run two
    mutation coordinators against one mutable workspace or container.

    A held lock is refused at once unless ``wait_seconds`` is positive; only
    the output-directory claim passes it, so a sibling shard waits out that
    brief section instead of losing its role to a startup race.
    """
    try:
        import fcntl
    except ImportError as e:                              # pragma: no cover
        raise MutationAborted(
            "REFUSED: mutation resource locking requires POSIX flock.") from e
    identities = sorted({_resource_identity(kind, value)
                         for kind, value in resources})
    lock_root = _mutation_lock_root()
    held: list[tuple[int, str, str]] = []
    try:
        for kind, value in identities:
            name = hashlib.sha256(_canonical(
                {"kind": kind, "value": value})).hexdigest() + ".lock"
            path = os.path.join(lock_root, name)
            flags = os.O_CREAT | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                fd = os.open(path, flags, 0o600)
            except OSError as e:
                raise MutationAborted(
                    f"REFUSED: cannot open mutation resource lock for "
                    f"{kind}={value!r}: {e}") from e
            deadline = time.monotonic() + wait_seconds
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as e:
                    if isinstance(e, BlockingIOError) \
                            and time.monotonic() < deadline:
                        time.sleep(0.05)
                        continue
                    os.close(fd)
                    raise MutationAborted(
                        f"REFUSED: another mutation coordinator already owns "
                        f"{kind}={value!r}; concurrent mutation is "
                        f"unsafe.") from e
            held.append((fd, kind, value))
        yield
    finally:
        for fd, _kind, _value in reversed(held):
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


@contextmanager
def output_lock(target: str):
    """Hold a non-blocking process lock for one campaign output target.

    The lock lives outside the evidence directory, so acquiring it neither
    makes a supposedly new output nonempty nor modifies historical bytes.
    Kernel release on process death is the recovery mechanism; the small lock
    file is intentionally persistent and content-free.
    """
    try:
        import fcntl
    except ImportError as e:                              # pragma: no cover
        raise MutationAborted(
            "REFUSED: mutation campaign locking requires POSIX flock.") from e
    lock_root = _mutation_lock_root()
    # Resolve existing parent-directory symlinks as well as ``..`` aliases;
    # otherwise two spellings of one output could acquire two different lock
    # files and concurrently append to the same inode.
    resolved = os.path.realpath(os.path.abspath(target))
    name = hashlib.sha256(resolved.encode(
        "utf-8", "surrogateescape")).hexdigest() + ".lock"
    lock_path = os.path.join(lock_root, name)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as e:
        raise MutationAborted(
            f"REFUSED: cannot open mutation campaign lock {lock_path}: {e}") \
            from e
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as e:
            raise MutationAborted(
                f"REFUSED: another coordinator already owns the mutation "
                f"campaign output {resolved}; concurrent resume is unsafe.") \
                from e
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def atomic_write_bytes(path: str, payload: bytes, *,
                       refuse_existing: bool = False,
                       allow_identical: bool = False) -> str:
    """Write in the destination directory and replace atomically.

    ``refuse_existing`` is the publication default.  ``allow_identical`` is
    useful for idempotent attestations, but never permits different bytes to
    overwrite evidence already present.
    """
    parent = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(parent, exist_ok=True)
    if os.path.lexists(path):
        if allow_identical and os.path.isfile(path):
            with open(path, "rb") as fh:
                if fh.read() == payload:
                    return path
        if refuse_existing:
            raise MutationAborted(
                f"REFUSED: output already exists: {path}. Use a new output, "
                "or an explicit identity-matching resume where supported.")
    fd, staged = tempfile.mkstemp(
        prefix=f".r2t-stage-{os.path.basename(path)}-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(staged, path)
    finally:
        if os.path.exists(staged):
            os.unlink(staged)
    return path


def atomic_write_json(path: str, doc: dict, *,
                      refuse_existing: bool = False,
                      allow_identical: bool = False) -> str:
    payload = (json.dumps(doc, indent=1, sort_keys=True, default=str)
               + "\n").encode("utf-8")
    return atomic_write_bytes(path, payload, refuse_existing=refuse_existing,
                              allow_identical=allow_identical)


def provenance_path(out_path: str) -> str:
    return out_path + ".provenance.json"


def validate_observation_id(value) -> str:
    """Return one independently minted mutation-observation identifier.

    Campaign identities intentionally describe reproducible inputs.  They
    therefore cannot prove that two byte-identical executions happened
    independently.  A fresh random identifier is minted when a standalone
    output directory is first claimed and is copied into every shard
    sidecar.  It is evidence of distinct execution records, not entropy used
    by execution itself.
    """
    if not isinstance(value, str) or len(value) != 32 \
            or any(ch not in "0123456789abcdef" for ch in value):
        raise MutationAborted(
            "REFUSED: mutation observation_id must be exactly 32 lowercase "
            "hex characters.")
    return value


def _standalone_output_plan(identity: dict, observation_id: str) -> dict:
    """One clean directory's immutable K-shard ownership record."""
    _validate_campaign_identity(identity)
    if identity.get("kind") != "mutation-run":
        raise MutationAborted(
            "REFUSED: standalone mutation output plans are only for "
            "mutation-run campaigns.")
    core = {key: value for key, value in identity.items()
            if key not in {"shard", "expected_pairs",
                           "expected_pairs_sha256"}}
    allowed = []
    for shard in range(identity["of"]):
        name = f"{identity['side']}.w{shard}.jsonl"
        allowed.extend((name, name + ".provenance.json"))
    return {
        "schema": MUTATION_OUTPUT_PLAN_SCHEMA,
        "observation_id": validate_observation_id(observation_id),
        "campaign_core": core,
        "campaign_core_sha256": content_digest(core),
        "allowed_artifacts": sorted(allowed),
    }


def _standalone_output_plan_v1(identity: dict) -> dict:
    """Reconstruct the historical plan exactly for read-only validation."""
    current = _standalone_output_plan(identity, "0" * 32)
    return {key: value for key, value in current.items()
            if key != "observation_id"} | {
                "schema": MUTATION_OUTPUT_PLAN_SCHEMA_V1,
            }


def _validate_standalone_output_plan(saved, identity: dict) -> Optional[str]:
    """Validate one saved ownership plan and return its observation id.

    v1 plans remain readable as historical evidence, but return ``None`` and
    are never resumed.  All newly created plans are v2.
    """
    if not isinstance(saved, dict):
        raise MutationAborted(
            "REFUSED: mutation output ownership record is not an object.")
    if saved.get("schema") == MUTATION_OUTPUT_PLAN_SCHEMA_V1:
        if saved != _standalone_output_plan_v1(identity):
            raise MutationAborted(
                "REFUSED: native v1 output ownership record differs from "
                "its shard campaign identity.")
        return None
    if saved.get("schema") != MUTATION_OUTPUT_PLAN_SCHEMA:
        raise MutationAborted(
            f"REFUSED: unsupported mutation output plan schema "
            f"{saved.get('schema')!r}.")
    observation_id = validate_observation_id(saved.get("observation_id"))
    if saved != _standalone_output_plan(identity, observation_id):
        raise MutationAborted(
            "REFUSED: native output ownership record differs from its shard "
            "campaign identity or observation identifier.")
    return observation_id


def _load_standalone_output_observation(out_path: str, identity: dict,
                                        *, require_current: bool) \
        -> Optional[str]:
    """Load the plan that owns ``out_path`` without requiring all shards."""
    out_abs = os.path.abspath(out_path)
    expected_name = f"{identity['side']}.w{identity['shard']}.jsonl"
    if os.path.basename(out_abs) != expected_name:
        raise MutationAborted(
            f"REFUSED: standalone shard {identity['shard']} must be named "
            f"{expected_name!r}.")
    plan_path = os.path.join(os.path.dirname(out_abs), MUTATION_OUTPUT_PLAN)
    if os.path.islink(plan_path) or not os.path.isfile(plan_path):
        raise MutationAborted(
            f"REFUSED: standalone mutation output has no regular ownership "
            f"record {plan_path}.")
    try:
        with open(plan_path, encoding="utf-8") as fh:
            saved = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        raise MutationAborted(
            f"REFUSED: cannot read mutation output plan {plan_path}: {e}") \
            from e
    observation_id = _validate_standalone_output_plan(saved, identity)
    if require_current and observation_id is None:
        raise MutationAborted(
            "REFUSED: v1 standalone output plans are read-only historical "
            "evidence; start a new output directory to create an independent "
            "v2 observation.")
    return observation_id


def standalone_go_evidence_names(identity):
    """Runtime Go captures accompany their planned shard, outside the row inventory.

    Keep historical ownership-plan bytes unchanged. Native Go capture directories
    were already produced by mutation-run; their presence is independent of the
    row/sidecar schema and does not authorize arbitrary campaign artifacts.
    """
    if identity.get("engine") != "r2t-mutate-go":
        return set()
    return {f"{identity['side']}.w{i}.jsonl.go-evidence" for i in range(identity['of'])}


def _present_go_evidence(out_dir, identity, entries):
    present = entries & standalone_go_evidence_names(identity)
    for name in present:
        path = os.path.join(out_dir, name)
        if os.path.islink(path) or not os.path.isdir(path):
            raise MutationAborted("REFUSED: Go mutation evidence must be a regular directory: " + path)
    return present


def prepare_standalone_output_directory(
        out_path: str, identity: dict,
        observation_id: Optional[str] = None) -> str:
    """Claim a new empty directory for one standalone K-way campaign.

    Later shards may join only the exact plan written by the first shard.
    A pre-existing unplanned directory -- in particular the historical
    partial Cell-3 directory -- is never inferred to belong to this run.
    The optional identity is used only by a separately frozen capability;
    ordinary callers retain the independently minted default.
    """
    out_abs = os.path.abspath(out_path)
    out_dir = os.path.dirname(out_abs)
    expected_name = f"{identity['side']}.w{identity['shard']}.jsonl"
    if os.path.basename(out_abs) != expected_name:
        raise MutationAborted(
            f"REFUSED: standalone shard {identity['shard']} must be written "
            f"as {expected_name!r} inside its dedicated output directory.")
    # Sibling shards of one campaign start together and share this directory;
    # the later one waits for the claim, then joins or refuses the plan below.
    with mutation_resource_locks([("output", out_dir)],
                                 wait_seconds=OUTPUT_CLAIM_WAIT_SECONDS):
        if os.path.lexists(out_dir):
            if os.path.islink(out_dir) or not os.path.isdir(out_dir):
                raise MutationAborted(
                    f"REFUSED: mutation output directory is not a non-symlink "
                    f"directory: {out_dir}")
        else:
            os.makedirs(out_dir, mode=0o700)
        plan_path = os.path.join(out_dir, MUTATION_OUTPUT_PLAN)
        entries = set(os.listdir(out_dir))
        if MUTATION_OUTPUT_PLAN not in entries:
            if entries:
                raise MutationAborted(
                    f"REFUSED: mutation output directory {out_dir} is not "
                    f"empty and has no {MUTATION_OUTPUT_PLAN} ownership "
                    "record. Use a new empty directory; preserved historical "
                    "rows are read-only evidence.")
            from ..toolkit import docx_v2_workload
            if observation_id is None:
                selected_observation = (
                    docx_v2_workload.active_observation_id(identity)
                    or secrets.token_hex(16))
            else:
                selected_observation = validate_observation_id(observation_id)
            plan = _standalone_output_plan(identity, selected_observation)
            atomic_write_json(plan_path, plan, refuse_existing=True)
            entries = {MUTATION_OUTPUT_PLAN}
        try:
            with open(plan_path, encoding="utf-8") as fh:
                saved = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            raise MutationAborted(
                f"REFUSED: cannot read mutation output plan {plan_path}: "
                f"{e}") from e
        try:
            recorded_observation = _validate_standalone_output_plan(
                saved, identity)
        except MutationAborted as e:
            raise MutationAborted(
                f"REFUSED: mutation output directory {out_dir} belongs to "
                "another candidate, role, population, runtime or shard "
                f"count: {e} Use a new empty directory.") from e
        if recorded_observation is None:
            raise MutationAborted(
                "REFUSED: v1 standalone output plans are read-only "
                "historical evidence; use a new empty directory.")
        if observation_id is not None \
                and recorded_observation != validate_observation_id(
                    observation_id):
            raise MutationAborted(
                "REFUSED: mutation output directory carries another "
                "observation identity; use a new empty directory.")
        plan = _standalone_output_plan(identity, recorded_observation)
        allowed = {MUTATION_OUTPUT_PLAN, *plan["allowed_artifacts"]}
        # Other shards write their rows and provenance after releasing the
        # directory claim. Their atomic-write stages are transient startup
        # entries, restricted to this plan's artifact names. Final assembly
        # still requires the exact completed payload, with no stages.
        stage_prefixes = tuple(f".r2t-stage-{name}-"
                               for name in plan["allowed_artifacts"])
        allowed |= _present_go_evidence(out_dir, identity, entries)
        unexpected = sorted(name for name in entries - allowed
                            if not name.startswith(stage_prefixes))
        if unexpected:
            raise MutationAborted(
                f"REFUSED: mutation output directory {out_dir} contains "
                f"unplanned artifact(s) {unexpected}; it is not a clean "
                "campaign directory.")
    return recorded_observation


def validate_standalone_output_directory(
        shard_paths: Iterable[str], identity: dict) -> Optional[str]:
    """Validate the complete directory containing native standalone shards."""
    paths = [os.path.abspath(path) for path in shard_paths]
    directories = {os.path.dirname(path) for path in paths}
    if len(directories) != 1:
        raise MutationAborted(
            "REFUSED: one native standalone campaign must be preserved in "
            "one dedicated output directory.")
    out_dir = next(iter(directories))
    plan_path = os.path.join(out_dir, MUTATION_OUTPUT_PLAN)
    if os.path.islink(plan_path) or not os.path.isfile(plan_path):
        raise MutationAborted(
            f"REFUSED: native standalone campaign has no regular output "
            f"ownership record {plan_path}.")
    try:
        with open(plan_path, encoding="utf-8") as fh:
            saved = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        raise MutationAborted(
            f"REFUSED: cannot read native output plan {plan_path}: {e}") \
            from e
    observation_id = _validate_standalone_output_plan(saved, identity)
    plan = (saved if observation_id is None
            else _standalone_output_plan(identity, observation_id))
    allowed = {MUTATION_OUTPUT_PLAN, *plan["allowed_artifacts"]}
    actual = set(os.listdir(out_dir))
    allowed |= _present_go_evidence(out_dir, identity, actual)
    if actual != allowed:
        raise MutationAborted(
            f"REFUSED: native output directory is not the exact completed "
            f"campaign: missing={sorted(allowed-actual)}, "
            f"unexpected={sorted(actual-allowed)}.")
    if observation_id is not None:
        for path in paths:
            try:
                with open(provenance_path(path), encoding="utf-8") as fh:
                    sidecar = json.load(fh)
            except (OSError, json.JSONDecodeError) as e:
                raise MutationAborted(
                    f"REFUSED: cannot read native shard observation "
                    f"evidence for {path}: {e}") from e
            if sidecar.get("observation_id") != observation_id:
                raise MutationAborted(
                    f"REFUSED: native shard {path} is not bound to output "
                    f"observation {observation_id}.")
    return observation_id


def _rows_state(out_path: str) -> tuple[int, str]:
    if not os.path.isfile(out_path):
        return 0, _empty_sha256()
    n = 0
    with open(out_path, "rb") as fh:
        for line in fh:
            if line.strip():
                n += 1
    return n, sha256_file(out_path)


#: The shard lifecycle (plan §3, PR R3), as ONE table.
#:
#: `absent` is a state and not a special case: "no sidecar yet" is where every
#: shard starts, and writing anything other than `running` into it would be a
#: shard claiming a history it does not have.
#:
#: `complete` and `failed` are TERMINAL, and that is the whole correction
#: (review finding 8).  At the reviewed head `write_shard_provenance`
#: validated only the status WORD, so a no-op resume rewrote a finished
#: shard's sidecar to `running` before doing zero work, and any cleanup
#: failure in that window relabelled a byte-identical attested shard `failed`.
#: `test_quality.transition_campaign_state` already had this table for the
#: ROOT record; the shard level did not, and the two now share one shape.
SHARD_STATES: tuple[str, ...] = ("running", "complete", "interrupted",
                                 "failed")
SHARD_TRANSITIONS: dict = {
    None: {"running"},
    "running": {"running", "complete", "interrupted", "failed"},
    "interrupted": {"running"},
    "complete": set(),
    "failed": set(),
}


def validate_shard_transition(current: Optional[str], status: str, *,
                              where: str = "mutation shard") -> None:
    """The ONE validator every shard sidecar write goes through.

    `current` is `None` for a shard with no sidecar yet.  Refusing rather
    than clamping is deliberate: a caller that wanted to move a terminal
    shard has a wrong model of what it is holding, and quietly leaving the
    sidecar alone would let it carry on believing it.
    """
    if status not in SHARD_STATES:
        raise MutationAborted(
            f"REFUSED: unknown mutation shard status {status!r}.")
    if current is not None and current not in SHARD_STATES:
        raise MutationAborted(
            f"REFUSED: {where} carries unknown recorded status {current!r}.")
    if status not in SHARD_TRANSITIONS[current]:
        raise MutationAborted(
            f"REFUSED: {where} cannot transition from "
            f"{current if current is not None else 'absent'!r} to {status!r}. "
            f"`complete` and `failed` are terminal: their bytes are the "
            f"evidence, and recovery is a rerun into a NEW campaign "
            f"directory, never a rewritten sidecar. Use `r2t verify-shard` to "
            f"re-attest a shard you believe was demoted wrongly.")


def recorded_shard_status(out_path: str, identity: dict) -> Optional[str]:
    """This shard's currently recorded state, or None when it has no sidecar.

    Reads the status ONLY.  The full resume validation (`completed_pairs`)
    re-hashes the rows and re-checks every stamp; this is the narrower
    question a WRITE has to answer first — "what am I about to move?" — and
    it refuses a sidecar belonging to another campaign, because a transition
    from someone else's state is not a transition at all.
    """
    side = provenance_path(out_path)
    if os.path.islink(side) or not os.path.isfile(side):
        return None
    try:
        with open(side, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        raise MutationAborted(
            f"REFUSED: cannot read mutation provenance {side}: {e}. A shard "
            f"whose recorded state cannot be read is not one this campaign "
            f"may overwrite.") from e
    if not isinstance(doc, dict) \
            or doc.get("schema") != MUTATION_PROVENANCE_SCHEMA:
        raise MutationAborted(
            f"REFUSED: {side} has unsupported or missing schema "
            f"{(doc or {}).get('schema') if isinstance(doc, dict) else None!r}"
            f"; legacy evidence needs the explicit legacy_consistency "
            f"validator, not a current write.")
    want = campaign_identity_digest(identity)
    if doc.get("mutation_campaign_digest") != want:
        raise MutationAborted(
            f"REFUSED: {side} belongs to mutation campaign "
            f"{doc.get('mutation_campaign_digest')!r}, not {want}; this "
            f"campaign may not transition another campaign's shard.")
    if identity_version(identity) in {"v3", "v4"} \
            and doc.get("shard_policy") != identity.get("shard_policy"):
        raise MutationAborted(
            f"REFUSED: {side} shard_policy {doc.get('shard_policy')!r} "
            f"differs from its policy-bound campaign identity "
            f"{identity.get('shard_policy')!r}; the writer may not erase "
            "that mismatch with a new transition.")
    return doc.get("status")


def write_shard_provenance(out_path: str, identity: dict, status: str, *,
                           provenance: Optional[dict] = None,
                           rows: Optional[int] = None,
                           rows_sha256: Optional[str] = None,
                           error: Optional[str] = None) -> dict:
    """Atomically attest the current state of one shard.

    A running document is refreshed after every durable row.  A hard kill can
    still land between the row append and the sidecar replace; that mismatch
    is detected on resume and refused rather than guessed away.  SIGKILL also
    cannot run Python restoration code, so mutation workers must remain
    disposable and are pristine-checked before a resume.

    EVERY write goes through `validate_shard_transition` first, so there is
    exactly one place where the shard lifecycle is decided and no caller can
    reach the atomic write around it.
    """
    provenance = dict(provenance or {})
    if identity_version(identity) in {"v3", "v4"} \
            and provenance.get("shard_policy") \
            != identity.get("shard_policy"):
        raise MutationAborted(
            "REFUSED: a policy-bound test-quality shard must write the same "
            "shard_policy in its provenance and campaign identity.")
    validate_shard_transition(recorded_shard_status(out_path, identity),
                              status, where=f"mutation shard {out_path}")
    digest = campaign_identity_digest(identity)
    provenance = dict(provenance or {})
    plan_path = os.path.join(os.path.dirname(os.path.abspath(out_path)),
                             MUTATION_OUTPUT_PLAN)
    if identity.get("kind") == "mutation-run" \
            and os.path.isfile(plan_path) and not os.path.islink(plan_path):
        try:
            with open(plan_path, encoding="utf-8") as fh:
                saved_plan = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            raise MutationAborted(
                f"REFUSED: cannot read mutation output plan {plan_path}: "
                f"{e}") from e
        if saved_plan.get("schema") == MUTATION_OUTPUT_PLAN_SCHEMA_V1:
            raise MutationAborted(
                "REFUSED: v1 standalone output plans are read-only "
                "historical evidence.")
        if saved_plan.get("schema") != MUTATION_OUTPUT_PLAN_SCHEMA:
            raise MutationAborted(
                f"REFUSED: unsupported mutation output plan schema "
                f"{saved_plan.get('schema')!r}.")
        observation_id = validate_observation_id(
            saved_plan.get("observation_id"))
        claimed = provenance.get("observation_id")
        if claimed is not None and claimed != observation_id:
            raise MutationAborted(
                f"REFUSED: shard provenance claims observation_id "
                f"{claimed!r}, but its output plan records "
                f"{observation_id!r}.")
        provenance["observation_id"] = observation_id
    if rows is None or rows_sha256 is None:
        rows, rows_sha256 = _rows_state(out_path)
    doc = {
        **provenance,
        "schema": MUTATION_PROVENANCE_SCHEMA,
        "status": status,
        "campaign_identity": identity,
        "mutation_campaign_digest": digest,
        "out": os.path.basename(out_path),
        "rows": int(rows),
        "rows_sha256": rows_sha256,
        "expected_pairs": identity["expected_pairs"],
        "expected_pairs_sha256": identity["expected_pairs_sha256"],
    }
    if error:
        doc["error"] = error
    atomic_write_json(provenance_path(out_path), doc)
    return doc


def _load_shard_provenance(out_path: str, identity: dict) -> dict:
    side = provenance_path(out_path)
    if not os.path.isfile(side):
        raise MutationAborted(
            f"REFUSED: {out_path} exists without {side}; its rows have no "
            "campaign identity and cannot be resumed or merged as current "
            "evidence.")
    try:
        with open(side, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        raise MutationAborted(
            f"REFUSED: cannot read mutation provenance {side}: {e}") from e
    if doc.get("schema") != MUTATION_PROVENANCE_SCHEMA:
        raise MutationAborted(
            f"REFUSED: {side} has unsupported or missing schema "
            f"{doc.get('schema')!r}; legacy evidence needs the explicit "
            "legacy_consistency validator, not current resume.")
    want = campaign_identity_digest(identity)
    embedded = doc.get("campaign_identity")
    got = doc.get("mutation_campaign_digest")
    try:
        embedded_digest = campaign_identity_digest(embedded or {})
    except MutationAborted as e:
        raise MutationAborted(
            f"REFUSED: {side} carries an invalid embedded campaign identity: "
            f"{e}") from e
    if embedded != identity or got != want or embedded_digest != want:
        raise MutationAborted(
            f"REFUSED: {out_path} belongs to mutation campaign {got!r}, not "
            f"{want}. Candidate, population, map, release, pair set, engine, "
            "side, shard, or timeout changed; use a new output directory.")
    if identity_version(identity) in {"v3", "v4"} \
            and doc.get("shard_policy") != identity.get("shard_policy"):
        raise MutationAborted(
            f"REFUSED: {side} shard_policy {doc.get('shard_policy')!r} "
            f"differs from its policy-bound campaign identity "
            f"{identity.get('shard_policy')!r}.")
    rows, rows_sha = _rows_state(out_path)
    if doc.get("rows") != rows or doc.get("rows_sha256") != rows_sha:
        raise MutationAborted(
            f"REFUSED: {side} attests {doc.get('rows')} row(s) / "
            f"{doc.get('rows_sha256')}, but {out_path} contains {rows} / "
            f"{rows_sha}. The previous write was torn or the rows were "
            "modified; do not resume into ambiguous evidence.")
    return doc


def row_identity_stamp(identity: dict,
                       campaign_digest: Optional[str] = None) -> dict:
    """Every campaign input copied onto a native row for local validation."""
    digest = campaign_digest or campaign_identity_digest(identity)
    _validate_campaign_identity(identity)
    expected = {
        key: value for key, value in identity.items()
        if key not in {"schema", "shard", "of"}
    }
    expected.update({
        "mutation_campaign_digest": digest,
        "mutant_shard": identity["shard"],
        "mutant_of": identity["of"],
    })
    return expected


def _row_identity_problems(row: dict, identity: dict,
                           campaign_digest: str) -> list[str]:
    expected = row_identity_stamp(identity, campaign_digest)
    return [key for key, value in expected.items() if row.get(key) != value]


def install_applier(harness: Harness, engine_dir: str,
                    applier: Applier = PHP_APPLIER) -> str:
    dst = os.path.join(harness.root, applier.rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(os.path.join(engine_dir, applier.source), encoding="utf-8") as src, \
            open(dst, "w", encoding="utf-8") as out:
        out.write(src.read())
    if (applier.entrypoint is None) != (applier.classes_rel is None):
        raise MutationAborted(
            "REFUSED: a compiled applier must declare both entrypoint and "
            "classes_rel")
    if applier.entrypoint is not None:
        from ..toolkit.mutation_java import (AMBIENT_JAVA_ENV_KEYS,
                                    java_sidecar_shell_prefix)
        classes_rel = applier.classes_rel
        classes_abs = os.path.abspath(os.path.join(harness.root, classes_rel))
        root = os.path.abspath(harness.root)
        try:
            contained = os.path.commonpath((root, classes_abs)) == root
        except ValueError:
            contained = False
        if not contained or os.path.lexists(classes_abs):
            raise MutationAborted(
                f"REFUSED: compiled applier classes path is not a fresh "
                f"contained directory: {classes_rel}")
        try:
            os.mkdir(classes_abs, 0o700)
        except OSError as exc:
            raise MutationAborted(
                f"REFUSED: cannot create compiled applier classes directory "
                f"{classes_rel}: {exc}") from exc
        if os.path.islink(classes_abs) or not os.path.isdir(classes_abs) \
                or os.path.realpath(classes_abs) != classes_abs:
            raise MutationAborted(
                f"REFUSED: compiled applier classes directory is not "
                f"canonical: {classes_rel}")
        cp = harness.runner.run(
            # JDK 8 keeps the public javac tree API in tools.jar; modular JDKs
            # expose it from jdk.compiler and harmlessly ignore a nonexistent
            # classpath entry at this location.
            java_sidecar_shell_prefix(harness.runner.workdir)
            + "\"$JAVA_HOME/bin/javac\" -proc:none "
            "-classpath \"$JAVA_HOME/lib/tools.jar\" "
            f"-d {shlex.quote(classes_rel)} "
            f"{shlex.quote(applier.rel)}", timeout=300,
            env={key: "" for key in AMBIENT_JAVA_ENV_KEYS})
        if cp.returncode != 0:
            raise MutationAborted(
                "REFUSED: compiling the staged Java mutation applier failed "
                f"(rc={cp.returncode}): "
                f"{(cp.stderr or cp.stdout or '')[-400:]}")
        main_class = os.path.join(
            classes_abs, *applier.entrypoint.split(".")) + ".class"
        if os.path.islink(main_class) or not os.path.isfile(main_class) \
                or os.path.realpath(main_class) != main_class:
            raise MutationAborted(
                f"REFUSED: javac did not produce compiled applier entrypoint "
                f"{applier.entrypoint!r} under {classes_rel}")
    return dst


def remove_applier(harness: Harness, applier: Applier = PHP_APPLIER) -> None:
    import shutil
    scratch = os.path.dirname(os.path.join(harness.root, applier.rel))
    shutil.rmtree(scratch, ignore_errors=True)
    if os.path.isdir(scratch):
        cp = harness.runner.run(f"rm -rf {os.path.dirname(applier.rel)}")
        if getattr(cp, "returncode", 0) != 0:
            raise MutationAborted(
                f"REFUSED: removing staged mutation applier failed with "
                f"rc={cp.returncode}; this worker is not pristine.")
    if os.path.lexists(scratch):
        raise MutationAborted(
            f"REFUSED: staged mutation applier remains at {scratch}; this "
            "worker is not pristine.")


@contextmanager
def _isolated_java_applier(harness: Harness, engine_dir: str,
                           applier: Applier, *,
                           expected_sha256: Optional[str] = None,
                           java_home: Optional[str] = None):
    """Compile the pinned Java engine outside the submitted RW workspace."""
    if applier.entrypoint is None or applier.classes_rel is None:
        raise MutationAborted(
            "REFUSED: isolated Java applier has no compiled entrypoint")
    prepare = getattr(harness.runner, "prepare_isolated_java_applier", None)
    if not callable(prepare):
        raise MutationAborted(
            "REFUSED: Java mutation campaigns require a runner with an "
            "isolated analysis container")
    from ..toolkit import mutation_java as JAVA
    workspace = os.path.realpath(os.path.abspath(harness.root))
    source = os.path.abspath(os.path.join(engine_dir, applier.source))
    if os.path.islink(source) or not os.path.isfile(source) \
            or os.path.realpath(source) != source:
        raise MutationAborted(
            "REFUSED: Java mutation engine source is not a canonical regular "
            f"file: {source}")
    try:
        source_in_workspace = os.path.commonpath((workspace, source)) \
            == workspace
    except ValueError:
        source_in_workspace = False
    if source_in_workspace:
        raise MutationAborted(
            "REFUSED: Java mutation engine source is inside the submitted "
            f"workspace: {source}")
    try:
        scratch = JAVA.private_java_scratch(
            "r2t_java_applier_", workspace)
    except RuntimeError as exc:
        raise MutationAborted(str(exc)) from exc
    authority_sha256 = expected_sha256 or sha256_file(source)
    staged_source = os.path.join(scratch, applier.source)
    classes = os.path.join(scratch, "classes")
    os.mkdir(classes, 0o700)
    try:
        try:
            from ..data.mutation_attestation import validate_preserved_file
            from ..toolkit.mutation_audit import stage_preserved_file
            stage_preserved_file(
                source, staged_source, authority_sha256,
                label="Java campaign engine")
            prepare_options = ({"java_home": java_home}
                               if java_home is not None else {})
            cp = prepare(staged_source, classes, timeout=300,
                         **prepare_options)
            validate_preserved_file(
                staged_source, authority_sha256,
                label="staged Java campaign engine")
        except Exception as exc:                            # noqa: BLE001
            raise MutationAborted(
                "REFUSED: isolated Java mutation engine compilation raised "
                f"{type(exc).__name__}: {exc}") from exc
        if cp.returncode != 0:
            raise MutationAborted(
                "REFUSED: compiling the isolated Java mutation engine failed "
                f"(rc={cp.returncode}): "
                f"{(cp.stderr or cp.stdout or '')[-400:]}")
        for directory, dirs, files in os.walk(classes, followlinks=False):
            for name in dirs + files:
                path = os.path.join(directory, name)
                if os.path.islink(path) or (name in files
                                            and not os.path.isfile(path)):
                    raise MutationAborted(
                        "REFUSED: isolated Java compiler produced a "
                        f"non-regular entry: {path}")
        main_class = os.path.join(
            classes, *applier.entrypoint.split(".")) + ".class"
        if not os.path.isfile(main_class) or os.path.islink(main_class) \
                or os.path.realpath(main_class) != main_class:
            raise MutationAborted(
                "REFUSED: isolated javac did not produce the mutation "
                f"entrypoint {applier.entrypoint!r}")
        yield classes
    finally:
        import shutil
        shutil.rmtree(scratch, ignore_errors=True)
        if os.path.lexists(scratch):
            raise MutationAborted(
                "REFUSED: isolated Java applier scratch could not be removed")


def _require_isolated_java_toolchain(
        harness: Harness, expected_parser: str, *, timeout: int = 120) -> str:
    """Bind one campaign shard to the javac/java that minted its manifest."""
    probe = getattr(harness.runner, "probe_isolated_java_toolchain", None)
    if not callable(probe):
        raise MutationAborted(
            "REFUSED: Java mutation campaigns require an isolated toolchain "
            "probe")
    try:
        cp = probe(timeout=timeout)
    except Exception as exc:                                # noqa: BLE001
        raise MutationAborted(
            "REFUSED: isolated Java toolchain probe raised "
            f"{type(exc).__name__}: {exc}") from exc
    if cp.returncode != 0:
        raise MutationAborted(
            "REFUSED: isolated Java toolchain probe failed "
            f"(rc={cp.returncode}): "
            f"{(cp.stderr or cp.stdout or '')[-500:]}")
    from ..toolkit import mutation_java as JAVA
    try:
        return JAVA.parse_toolchain_probe(
            (cp.stdout or "") + "\n" + (cp.stderr or ""),
            expected_parser=expected_parser)
    except RuntimeError as exc:
        raise MutationAborted(str(exc)) from exc


def apply_mutant(harness: Harness, mutant: dict,
                 applier: Applier = PHP_APPLIER,
                 operator_profile: str = "v2", *,
                 analysis_recipe: Optional[dict] = None,
                 analysis_bindings: Optional[dict[str, dict]] = None,
                 analysis_snapshot_root: Optional[str] = None,
                 java_classes_root: Optional[str] = None,
                 engine_dir: Optional[str] = None) -> dict:
    """Materialise one mutant, and declare it to the integrity guard."""
    if operator_profile not in {"v1", "v2"}:
        raise MutationAborted(
            f"REFUSED: unknown operator profile {operator_profile!r}")
    rel = mutant["file"]
    target = os.path.join(harness.root, rel)
    if not os.path.isfile(target):
        raise MutationAborted(f"REFUSED: {rel} does not exist in this workspace")
    original_lstat = _file_lstat_identity(target)
    original = _read_file_nofollow(target)
    analysis_context = nullcontext(None)
    classes_context = nullcontext(None)
    expected_java_bytes = None
    analysis_binding = None
    if applier.entrypoint is not None:
        if analysis_recipe is None:
            raise MutationAborted(
                "REFUSED: compiled Java apply has no authenticated analysis "
                "recipe")
        from ..toolkit import mutation_java as JAVA
        if not JAVA.analysis_path_covers(analysis_recipe, rel):
            raise MutationAborted(
                f"REFUSED: Java mutant file {rel!r} is outside its "
                "authenticated sourcepath")
        if analysis_bindings is None:
            analysis_binding = JAVA.analysis_binding_for_path(
                analysis_recipe, rel)
        else:
            analysis_binding = analysis_bindings.get(rel)
            if not isinstance(analysis_binding, dict):
                raise MutationAborted(
                    f"REFUSED: Java source {rel!r} has no cached module "
                    "analysis binding")
        if analysis_snapshot_root is None:
            analysis_context = JAVA.analysis_snapshot(
                harness.root, analysis_recipe, required_sources=[rel])
        else:
            snapshot = os.path.abspath(analysis_snapshot_root)
            try:
                contained = os.path.commonpath((harness.root, snapshot)) \
                    == os.path.abspath(harness.root)
            except ValueError:
                contained = False
            if contained or os.path.islink(snapshot) \
                    or not os.path.isdir(snapshot) \
                    or os.path.realpath(snapshot) != snapshot:
                raise MutationAborted(
                    "REFUSED: reusable Java analysis snapshot is not a "
                    "canonical workspace-inaccessible directory")
            analysis_context = nullcontext(snapshot)
        if java_classes_root is None:
            classes_context = _isolated_java_applier(
                harness, engine_dir or JAVA.JAVA_ENGINE_DIR, applier,
                java_home=(analysis_binding["compiler"]["java_home"]
                           if analysis_binding["compiler"] is not None
                           else None))
        else:
            classes = os.path.abspath(java_classes_root)
            try:
                classes_contained = os.path.commonpath(
                    (harness.root, classes)) == os.path.abspath(harness.root)
            except ValueError:
                classes_contained = False
            if classes_contained or os.path.islink(classes) \
                    or not os.path.isdir(classes) \
                    or os.path.realpath(classes) != classes:
                raise MutationAborted(
                    "REFUSED: reusable Java applier classes are not a "
                    "canonical workspace-inaccessible directory")
            classes_context = nullcontext(classes)

        def byte_offset(line: int, col: int) -> int:
            if line < 1 or col < 1:
                raise MutationAborted(
                    "REFUSED: Java mutant has invalid byte coordinates")
            starts = [0]
            starts.extend(index + 1 for index, value in enumerate(original)
                          if value == 10)
            if line > len(starts):
                raise MutationAborted(
                    "REFUSED: Java mutant coordinate is beyond source bytes")
            offset = starts[line - 1] + col - 1
            if offset > len(original):
                raise MutationAborted(
                    "REFUSED: Java mutant coordinate is beyond source bytes")
            return offset

        start = byte_offset(int(mutant["start_line"]),
                            int(mutant["start_col"]))
        end = byte_offset(int(mutant["end_line"]),
                          int(mutant["end_col"])) + 1
        original_span = mutant["original"].encode("utf-8")
        if end > len(original) or original[start:end] != original_span:
            raise MutationAborted(
                "REFUSED: Java mutant descriptor does not address the "
                "current exact source bytes")
        expected_java_bytes = (original[:start]
                               + mutant["mutated"].encode("utf-8")
                               + original[end:])
    elif analysis_recipe is not None:
        raise MutationAborted(
            "REFUSED: a script mutation applier was given Java analysis "
            "authority")
    def _restore(why: str) -> None:
        """Put the file back before propagating.

        Every failure path below has already, or may already have, written to
        the target: the applier can time out mid-write, exit non-zero after a
        partial `file_put_contents`, or produce a byte-identical no-op.  The
        restoration used to live only in `run_slice`'s `finally`, which is
        entered *after* `apply_mutant` returns — so a raising apply left the
        workspace mutated and every later pair on that worker ran against a
        production file nobody had declared. Restoring here means the raise is
        the only thing that escapes.
        """
        _restore_bytes_and_lstat(target, original, original_lstat, why)
        harness.expected_mutations = {}

    try:
        with analysis_context as analysis_root, \
                classes_context as isolated_classes:
            if analysis_root is not None:
                resolved_analysis = JAVA.snapshot_analysis_inputs(
                    analysis_root, analysis_binding["recipe"],
                    runtime_root=JAVA_ANALYSIS_RUNTIME,
                    allow_kapua_absent_manifest_classpath=analysis_binding[
                        "allow_kapua_absent_manifest_classpath"])
                compiler_args = analysis_binding["compiler_argv"]
                analysis_suffix = (
                    " --classpath "
                    f"{shlex.quote(resolved_analysis['classpath'])}"
                    " --sourcepath "
                    f"{shlex.quote(resolved_analysis['sourcepath'])}"
                    " --module-path "
                    f"{shlex.quote(resolved_analysis['module_path'])}"
                    + "".join(" " + shlex.quote(value)
                              for value in compiler_args))
                compiler = analysis_binding["compiler"]
                if compiler is None:
                    command = ("\"$JAVA_HOME/bin/java\" -cp "
                               f"\"{JAVA_APPLIER_RUNTIME}:"
                               f"$JAVA_HOME/lib/tools.jar\" "
                               f"{shlex.quote(applier.entrypoint)}")
                else:
                    java_home = compiler["java_home"]
                    command = (
                        f"{shlex.quote(java_home + '/bin/java')} -cp "
                        + shlex.quote(
                            JAVA_APPLIER_RUNTIME + ":"
                            + java_home + "/lib/tools.jar") + " "
                        + shlex.quote(applier.entrypoint))
                full_command = (
                    f"{command} --root {JAVA_ANALYSIS_RUNTIME} "
                    f"--write-root {shlex.quote(harness.runner.workdir)} ")
            else:
                analysis_suffix = ""
                full_command = (
                    f"{applier.interpreter} {applier.rel} "
                    f"--root {harness.runner.workdir} ")
            full_command += (
                f"--operator-profile {operator_profile} "
                f"--apply-file {shlex.quote(rel)} "
                f"--start-line {int(mutant['start_line'])} "
                f"--start-col {int(mutant['start_col'])} "
                f"--operator {shlex.quote(mutant['operator'])} "
                f"--original {shlex.quote(mutant['original'])} "
                f"--mutated {shlex.quote(mutant['mutated'])} "
                f"--out {shlex.quote(rel)}{analysis_suffix}")
            if analysis_root is None:
                cp = harness.runner.run(full_command, timeout=300)
            else:
                run_isolated = getattr(
                    harness.runner, "run_isolated_java", None)
                if not callable(run_isolated) or isolated_classes is None:
                    raise MutationAborted(
                        "REFUSED: Java mutation apply lost its isolated "
                        "runner/classes authority")
                cp = run_isolated(
                    full_command, workspace_host=harness.root,
                    analysis_host=analysis_root,
                    classes_host=isolated_classes,
                    analysis_runtime=JAVA_ANALYSIS_RUNTIME,
                    classes_runtime=JAVA_APPLIER_RUNTIME, timeout=300)
    except Exception as e:                                  # noqa: BLE001
        _restore(f"the applier raised {type(e).__name__}")
        raise MutationAborted(
            f"applying {mutant['id']} to {rel} raised {type(e).__name__}: {e}")
    if cp.returncode != 0:
        _restore(f"a non-zero applier exit ({cp.returncode})")
        raise MutationAborted(
            f"applying {mutant['id']} to {rel} failed (rc={cp.returncode}): "
            f"{(cp.stderr or cp.stdout or '')[-400:]}")
    try:
        applied_lstat = _file_lstat_identity(target)
    except MutationAborted:
        _restore("the applier replaced the target's file type")
        raise
    if applied_lstat != original_lstat:
        _restore("the applier changed target mode/uid/gid")
        raise MutationAborted(
            f"REFUSED: applying {mutant['id']} changed {rel} lstat metadata "
            f"from {original_lstat} to {applied_lstat}")
    applied_bytes = _read_file_nofollow(target)
    if expected_java_bytes is not None and applied_bytes != expected_java_bytes:
        _restore("the Java applier produced bytes other than the exact splice")
        raise MutationAborted(
            f"REFUSED: applying {mutant['id']} did not materialise its exact "
            "digest-bound Java byte splice")
    digest = hashlib.sha256(applied_bytes).hexdigest()
    if hashlib.sha256(original).hexdigest() == digest:
        _restore("a no-op mutation")
        raise MutationAborted(
            f"REFUSED: applying {mutant['id']} left {rel} byte-identical, so "
            f"the 'mutated' run would be the baseline wearing another name")
    harness.expected_mutations = {rel: digest}
    return {"file": rel, "digest": digest, "original": original,
            "lstat": original_lstat}


def revert_mutant(harness: Harness, applied: dict) -> None:
    target = os.path.join(harness.root, applied["file"])
    _restore_bytes_and_lstat(
        target, applied["original"], applied.get("lstat"),
        "normal mutant revert")
    harness.expected_mutations = {}


def completed_pairs(out_path: str, identity: dict, *,
                    expected_pairs: Iterable[tuple[str, str]],
                    require_complete: bool = False,
                    expected_shard_policy: Optional[str] = None,
                    allow_missing_shard_policy: bool = False) -> set:
    """Validated ``(item, mutant)`` executions already in a shard.

    Pair equality alone is not resume identity.  The sidecar, every row stamp,
    the exact rows bytes and membership in the planned pair set all have to
    agree before an existing row is allowed to suppress new work.
    """
    expected = set(expected_pairs)
    if pair_set_digest(expected) != identity.get("expected_pairs_sha256") \
            or len(expected) != identity.get("expected_pairs"):
        raise MutationAborted(
            "REFUSED: the caller's expected pair set does not match the "
            "mutation campaign identity.")
    doc = _load_shard_provenance(out_path, identity)
    if expected_shard_policy is not None:
        recorded_policy = doc.get("shard_policy")
        if not (allow_missing_shard_policy and recorded_policy is None) \
                and recorded_policy != expected_shard_policy:
            raise MutationAborted(
                f"REFUSED: {provenance_path(out_path)} shard_policy "
                f"{recorded_policy!r} differs from its root campaign policy "
                f"{expected_shard_policy!r}.")
    if doc.get("status") == "failed":
        raise MutationAborted(
            f"REFUSED: {out_path} is a failed shard. Its bytes remain "
            "failure evidence and are never resumable; reprovision the "
            "workspace and use a new output directory.")
    if require_complete and doc.get("status") != "complete":
        raise MutationAborted(
            f"REFUSED: {out_path} has status {doc.get('status')!r}, not "
            "'complete'; a planned shard that is still running, failed, or "
            "was interrupted cannot be merged.")
    done: set[tuple[str, str]] = set()
    digest = campaign_identity_digest(identity)
    with open(out_path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                # A row torn by a kill mid-write.  Refused rather than
                # skipped: silently ignoring it would re-run that pair and
                # leave the torn line in the file for `recall` to trip on.
                raise MutationAborted(
                    f"REFUSED: {out_path} line {n} is not JSON — the previous "
                    f"campaign was killed mid-write. Preserve these bytes as "
                    f"failure evidence and use a new output; do not truncate "
                    f"or repair an attested shard in place.")
            missing = _row_identity_problems(row, identity, digest)
            if missing:
                raise MutationAborted(
                    f"REFUSED: {out_path} line {n} has missing or mismatched "
                    f"campaign stamp field(s) {missing}; current rows may not "
                    "be mixed with legacy or another campaign.")
            pair = (row.get("item_id"), row.get("mutant_id"))
            if pair not in expected:
                raise MutationAborted(
                    f"REFUSED: {out_path} line {n} contains unexpected pair "
                    f"{pair}; it is outside this shard's planned pair set.")
            if pair in done:
                raise MutationAborted(
                    f"REFUSED: {out_path} contains duplicate pair {pair}; "
                    "which execution is the result is undefined.")
            done.add(pair)
    if require_complete and done != expected:
        absent = sorted(expected - done)
        unexpected = sorted(done - expected)
        raise MutationAborted(
            f"REFUSED: {out_path} is not the exact planned shard: "
            f"{len(absent)} missing and {len(unexpected)} unexpected pair(s), "
            f"e.g. missing {absent[:3]}, unexpected {unexpected[:3]}.")
    return done


def verify_shard(out_path: str) -> dict:
    """Re-attest one shard against its own bytes. READS ONLY.

    The remedy this exists to replace is a hand-edited sidecar.  A shard can
    be demoted to `failed` by a fault that has nothing to do with its rows —
    a cleanup or restoration error in the window after its last row was
    durable (review finding 8) — and once demoted, `completed_pairs` refuses
    it for both resume and merge while `complete` and `failed` are terminal.
    The honest recovery is a rerun into a NEW campaign directory; what an
    operator needs BEFORE spending that is evidence about which of the two
    happened, and that is what this reports.

    It answers exactly one question: is the state recorded in the sidecar
    consistent with the bytes beside it?  A `complete` shard whose rows are
    the exact planned pair set, correctly stamped, hashing to the recorded
    digest, is consistent.  A `failed` shard whose rows are ALSO all of that
    is not — its bytes say the work finished, and the sidecar says it did
    not.  Both answers are reported; neither is acted on, because a verb that
    could promote a shard would be the hand edit wearing a command name.

    Not a substitute for `completed_pairs`: this re-derives the expected pair
    set from the sidecar's own identity rather than from the caller's
    population, so it proves internal consistency and never that this shard
    is the one a given campaign planned.
    """
    side = provenance_path(out_path)
    problems: list[str] = []
    if os.path.islink(out_path) or not os.path.isfile(out_path) \
            or os.path.islink(side) or not os.path.isfile(side):
        raise MutationAborted(
            f"REFUSED: a shard and its sidecar must both be regular files to "
            f"be re-attested: {out_path}, {side}.")
    try:
        with open(side, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        raise MutationAborted(
            f"REFUSED: cannot read mutation provenance {side}: {e}") from e
    if not isinstance(doc, dict) \
            or doc.get("schema") != MUTATION_PROVENANCE_SCHEMA:
        raise MutationAborted(
            f"REFUSED: {side} is not an {MUTATION_PROVENANCE_SCHEMA} "
            f"document.")
    identity = doc.get("campaign_identity")
    recorded_digest = doc.get("mutation_campaign_digest")
    identity_consistent = False
    recomputed_digest = None
    try:
        recomputed_digest = campaign_identity_digest(identity or {})
        identity_consistent = recomputed_digest == recorded_digest
        if not identity_consistent:
            problems.append(
                f"the embedded identity hashes to {recomputed_digest}, but "
                f"the sidecar records {recorded_digest!r}")
    except MutationAborted as e:
        problems.append(f"the embedded campaign identity is invalid: {e}")
    rows_count, rows_sha = _rows_state(out_path)
    rows_consistent = (doc.get("rows") == rows_count
                       and doc.get("rows_sha256") == rows_sha)
    if not rows_consistent:
        problems.append(
            f"the sidecar attests {doc.get('rows')!r} row(s) / "
            f"{doc.get('rows_sha256')!r}, but the rows are {rows_count} / "
            f"{rows_sha}")
    pairs: set = set()
    rows_planned = False
    if identity_consistent:
        try:
            with open(out_path, encoding="utf-8") as fh:
                for number, line in enumerate(fh, 1):
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    stamp = _row_identity_problems(row, identity,
                                                   recomputed_digest)
                    if stamp:
                        problems.append(
                            f"line {number} has missing or mismatched "
                            f"campaign stamp field(s) {stamp}")
                        continue
                    pair = (row.get("item_id"), row.get("mutant_id"))
                    if pair in pairs:
                        problems.append(f"line {number} repeats pair {pair}")
                    pairs.add(pair)
        except (OSError, json.JSONDecodeError) as e:
            problems.append(f"the rows are not readable as JSON lines: {e}")
        rows_planned = (
            not problems
            and len(pairs) == identity.get("expected_pairs")
            and pair_set_digest(pairs)
            == identity.get("expected_pairs_sha256"))
        if not rows_planned and not problems:
            problems.append(
                f"the rows hold {len(pairs)} pair(s) digesting to "
                f"{pair_set_digest(pairs)}, not the "
                f"{identity.get('expected_pairs')} / "
                f"{identity.get('expected_pairs_sha256')} this identity "
                f"plans")
    status = doc.get("status")
    supports_complete = bool(identity_consistent and rows_consistent
                             and rows_planned and not problems)
    terminal = status in ("complete", "failed")
    consistent: Optional[bool] = None
    if status == "complete":
        consistent = supports_complete
    elif status == "failed":
        # A failed shard is consistent with its bytes exactly when its bytes
        # do NOT amount to a finished shard.  When they do, the sidecar is
        # the thing that is wrong, and saying so is this verb's whole job.
        consistent = not supports_complete
        if supports_complete:
            problems.append(
                "the recorded terminal state is `failed`, but these bytes "
                "are the exact complete planned pair set, correctly stamped "
                "and hashing to the recorded digest — the demotion is not "
                "supported by the evidence. Preserve this directory and "
                "rerun into a NEW campaign directory; do not edit the "
                "sidecar.")
    return {
        "schema": MUTATION_VERIFICATION_SCHEMA,
        "out": os.path.abspath(out_path),
        "sidecar": os.path.abspath(side),
        "recorded_status": status,
        "recorded_status_terminal": terminal,
        "recorded_rows": doc.get("rows"),
        "recorded_rows_sha256": doc.get("rows_sha256"),
        "rows": rows_count,
        "rows_sha256": rows_sha,
        "recorded_mutation_campaign_digest": recorded_digest,
        "recomputed_mutation_campaign_digest": recomputed_digest,
        "identity_consistent": identity_consistent,
        "rows_consistent": rows_consistent,
        "rows_are_the_planned_complete_set": rows_planned,
        "bytes_support_complete": supports_complete,
        "state_consistent_with_bytes": consistent,
        "problems": problems,
    }


def validate_native_shards(
        shard_paths: Iterable[str], *,
        expected_pairs: Optional[Iterable[tuple[str, str]]] = None,
        required_side: Optional[str] = None,
        return_campaign: bool = False,
        _continuation_plan_sha256: Optional[str] = None):
    """Validate and logically merge one complete native K-way campaign.

    Concatenation is not merge: it discards the sidecars that say which
    candidate, map, runtime and shard produced each row.  This reader checks
    those sidecars, every full row stamp, homogeneous campaign cores, the
    exact zero-based shard set and a disjoint pair union before returning
    rows in shard order.  Historical unstamped rows belong exclusively to the
    PR-2 ``legacy_consistency`` path and are never accepted here.
    """
    paths = list(shard_paths)
    if not paths:
        raise MutationAborted(
            "REFUSED: no native mutation shards were supplied.")
    resolved = [os.path.realpath(os.path.abspath(path)) for path in paths]
    if len(set(resolved)) != len(resolved):
        raise MutationAborted(
            "REFUSED: the same native mutation shard was supplied twice.")
    shards = []
    from .worker import _seed_verification_scope
    # Every shard authenticates the same complete worker pool. Keep the
    # existing file-change checks, but hash its unchanged seed only once
    # during this read-only assembly, including nested pool validations.
    with _seed_verification_scope():
        for path in paths:
            side_path = provenance_path(path)
            if os.path.islink(path) or not os.path.isfile(path) \
                    or os.path.islink(side_path) or not os.path.isfile(side_path):
                raise MutationAborted(
                    f"REFUSED: native shard and sidecar must be regular files: "
                    f"{path}, {side_path}.")
            try:
                with open(side_path, encoding="utf-8") as fh:
                    sidecar = json.load(fh)
            except (OSError, json.JSONDecodeError) as e:
                raise MutationAborted(
                    f"REFUSED: cannot read native shard sidecar {side_path}: "
                    f"{e}") from e
            identity = sidecar.get("campaign_identity") \
                if isinstance(sidecar, dict) else None
            _validate_campaign_identity(identity or {})
            if "reference_pair_continuation_sha256" in identity:
                raise MutationAborted("REFUSED: reference continuation suffix requires its aggregate")
            if identity.get("continuation_plan_sha256") != _continuation_plan_sha256:
                raise MutationAborted(
                    "REFUSED: a continuation suffix requires its aggregate validator")
            if identity.get("kind") != "mutation-run":
                raise MutationAborted(
                    "REFUSED: native standalone shard assembly accepts only "
                    "kind='mutation-run'. A test-quality shard is subordinate "
                    "to its authenticated root campaign and cannot be published "
                    "as independent recall evidence.")
            validate_worker_resource_evidence(sidecar, identity)
            rows = []
            pairs = set()
            with open(path, encoding="utf-8") as fh:
                for number, line in enumerate(fh, 1):
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError as e:
                        raise MutationAborted(
                            f"REFUSED: native shard {path} line {number} is not "
                            f"JSON: {e}") from e
                    pair = (row.get("item_id"), row.get("mutant_id"))
                    if not all(isinstance(value, str) and value for value in pair):
                        raise MutationAborted(
                            f"REFUSED: native shard {path} line {number} has no "
                            "non-empty string item_id/mutant_id pair.")
                    if pair in pairs:
                        raise MutationAborted(
                            f"REFUSED: native shard {path} repeats pair {pair}.")
                    pairs.add(pair)
                    rows.append(row)
            completed_pairs(path, identity, expected_pairs=pairs,
                            require_complete=True)
            shards.append((identity["shard"], identity, rows, pairs))
    shards.sort(key=lambda value: value[0])
    of_values = {identity["of"] for _n, identity, _rows, _pairs in shards}
    if len(of_values) != 1 or next(iter(of_values)) != len(shards) \
            or [number for number, _identity, _rows, _pairs in shards] \
            != list(range(len(shards))):
        raise MutationAborted(
            "REFUSED: native mutation inputs are not the exact zero-based "
            "complete shard set declared by their identities.")
    cores = {
        json.dumps({key: value for key, value in identity.items()
                    if key not in {"shard", "expected_pairs",
                                   "expected_pairs_sha256"}},
                   sort_keys=True, separators=(",", ":"))
        for _number, identity, _rows, _pairs in shards
    }
    refuse_mixed_generation_evidence(
        [identity for _number, identity, _rows, _pairs in shards],
        "this native mutation shard set")
    if len(cores) != 1:
        raise MutationAborted(
            "REFUSED: native mutation shards carry mixed campaign cores; "
            "candidate, assets, runtime, engine, timeout or sampling differ.")
    representative = shards[0][1]
    observation_id = None
    if representative.get("kind") == "mutation-run":
        observation_id = validate_standalone_output_directory(
            paths, representative)
    if required_side is not None and representative["side"] != required_side:
        raise MutationAborted(
            f"REFUSED: native mutation campaign role is "
            f"{representative['side']!r}, not required {required_side!r}.")
    merged = []
    union = set()
    for _number, _identity, rows, pairs in shards:
        overlap = union & pairs
        if overlap:
            raise MutationAborted(
                f"REFUSED: native mutation shards overlap on pair(s) "
                f"{sorted(overlap)[:3]}.")
        union |= pairs
        merged.extend(rows)
    if expected_pairs is not None:
        expected = set(expected_pairs)
        if union != expected:
            raise MutationAborted(
                f"REFUSED: native mutation shard union differs from the "
                f"population: {len(expected-union)} missing and "
                f"{len(union-expected)} unexpected pair(s).")
    if return_campaign:
        return {"rows": merged, "campaign_identity": representative,
                "pairs": union, "observation_id": observation_id,
                # Preserve the already-authenticated allocation.  Consumers
                # with a deterministic scheduler (D4 confirmation) must be
                # able to verify not only the disjoint union, but which exact
                # pairs worker N owned.  Returning these facts avoids a
                # second, racy read of rows after native validation.
                "shards": [
                    {"shard": number, "campaign_identity": identity,
                     "pairs": set(pairs)}
                    for number, identity, _rows, pairs in shards
                ]}
    return merged


def validate_candidate_gold_campaign_pair(candidate: dict,
                                          gold: dict) -> None:
    """Require two standalone native campaigns to be one comparison."""
    _validate_campaign_identity(candidate)
    _validate_campaign_identity(gold)
    if candidate.get("kind") != "mutation-run" \
            or gold.get("kind") != "mutation-run":
        raise MutationAborted(
            "REFUSED: native recall compares standalone kind='mutation-run' "
            "campaigns only; test-quality shards require their authenticated "
            "root campaign and are not independent publication inputs.")
    refuse_mixed_generation_evidence(
        [candidate, gold], "this native candidate/gold comparison")
    if candidate["side"] != "candidate" or gold["side"] != "gold":
        raise MutationAborted(
            "REFUSED: native recall requires explicit candidate and gold "
            "campaign roles.")
    permitted = {
        "side", "candidate_run_sha256",
        "candidate_generated_tests_sha256",
        "solution_generated_tests_sha256",
    }
    fields = (CAMPAIGN_IDENTITY_FIELDS_V3
              if identity_version(candidate) == "v3"
              else CAMPAIGN_IDENTITY_FIELDS)
    changed = sorted(
        key for key in fields - permitted
        if candidate.get(key) != gold.get(key))
    if changed:
        raise MutationAborted(
            f"REFUSED: candidate/gold native campaigns differ in shared "
            f"population or execution field(s) {changed}. They are not one "
            "reference-relative comparison.")


def validate_campaign_asset_claims(
        identity: dict, assets: dict, *, validation_path: str,
        manifest_path: str, map_path: str, release_path: str) -> None:
    """Join a native shard identity to freshly validated frozen assets.

    Rebuilding completeness from an arbitrary manifest/map is circular: a
    limited pilot can look complete if the caller supplies a correspondingly
    limited catalogue.  ``assets`` must be the result of PR-2's
    ``validate_campaign_asset_inputs``; this final join proves those exact
    bytes are the ones the shard stamped before they are used as its expected
    denominator.
    """
    _validate_campaign_identity(identity)
    manifest = assets.get("manifest") if isinstance(assets, dict) else None
    if not isinstance(manifest, dict):
        raise MutationAborted(
            "REFUSED: native recall has no validated scored manifest facts.")
    claims = {
        "asset_index_sha256": assets.get("asset_index_sha256"),
        "asset_project": assets.get("asset_project"),
        "mutation_validation_sha256": sha256_file(validation_path),
        "mutation_validation_class": assets.get("validation_class"),
        "manifest_sha256": sha256_file(manifest_path),
        "manifest_digest": manifest.get("digest"),
        "map_sha256": sha256_file(map_path),
        "release_sha256": sha256_file(release_path),
        "engine": manifest.get("engine"),
        "engine_version": manifest.get("engine_version"),
        "parser": manifest.get("parser"),
    }
    changed = sorted(key for key, value in claims.items()
                     if identity.get(key) != value)
    if changed:
        raise MutationAborted(
            f"REFUSED: native campaign identity differs from the fully "
            f"validated frozen assets in field(s) {changed}.")


def validate_worker_resource_evidence(sidecar: dict, identity: dict) -> list:
    """Validate the auditable preimage of a shard's worker-pool digest."""
    from . import worker as W

    resources = sidecar.get("worker_resources") \
        if isinstance(sidecar, dict) else None
    if not isinstance(resources, list) or not resources:
        raise MutationAborted(
            "REFUSED: native shard sidecar has no canonical nonempty "
            "worker_resources preimage.")
    if len(resources) != identity.get("of"):
        raise MutationAborted(
            f"REFUSED: native shard declares {identity.get('of')} workers "
            f"but preserves {len(resources)} worker resource record(s).")
    if content_digest(resources) != identity.get("worker_resources_sha256"):
        raise MutationAborted(
            "REFUSED: native shard worker_resources do not hash to the "
            "worker-pool digest in its campaign identity.")
    resource_fields = {
        "index", "worker_spec", "workspace", "container", "schema",
        "credential", "env_file", "workdir", "runtime_attestation",
        "runtime_attestation_sha256",
    }
    if [record.get("index") for record in resources
            if isinstance(record, dict)] != list(range(len(resources))):
        raise MutationAborted(
            "REFUSED: native shard worker_resources are not the exact "
            "ordered zero-based pool.")
    specs = []
    spec_paths = []
    runtime_identities = set()
    runtime_versions = set()
    needs_database = identity.get("database_dump_digest") != "no_database"
    for number, record in enumerate(resources):
        if not isinstance(record, dict) or set(record) != resource_fields:
            raise MutationAborted(
                f"REFUSED: native shard worker resource {number} has "
                "missing or unknown fields.")
        spec_path = record.get("worker_spec")
        att_path = record.get("runtime_attestation")
        if not isinstance(spec_path, str) or not isinstance(att_path, str) \
                or os.path.realpath(spec_path) != spec_path \
                or os.path.realpath(att_path) != att_path \
                or os.path.islink(spec_path) or not os.path.isfile(spec_path) \
                or os.path.islink(att_path) or not os.path.isfile(att_path) \
                or not _full_sha256(record.get(
                    "runtime_attestation_sha256")) \
                or sha256_file(att_path) \
                != record["runtime_attestation_sha256"]:
            raise MutationAborted(
                f"REFUSED: native shard worker {number} does not preserve "
                "its exact spec/runtime-attestation bytes.")
        try:
            with open(spec_path, encoding="utf-8") as fh:
                spec_doc = json.load(fh)
            spec = W.WorkerSpec.from_json(spec_doc)
            with open(att_path, encoding="utf-8") as fh:
                att = json.load(fh)
        except (OSError, json.JSONDecodeError, W.WorkerRefused) as e:
            raise MutationAborted(
                f"REFUSED: cannot validate native shard worker {number}: "
                f"{e}") from e
        expected_resource = {
            "index": spec.index,
            "workspace": os.path.realpath(spec.workspace),
            "container": spec.container,
            "schema": spec.schema,
            "credential": spec.credential,
            "env_file": os.path.realpath(spec.env_file),
            "workdir": spec.workdir,
        }
        runtime_version = W.worker_runtime_version(att)
        valid_attestation = runtime_version in {"v1", "v2", "v3", "v4"} \
            and att.get("worker") == spec.to_json() \
            and att.get("worker_spec_sha256") == sha256_file(spec_path) \
            and _full_sha256(att.get("seed_manifest_sha256")) \
            and isinstance(att.get("seed_key"), str) \
            and bool(att.get("seed_key")) \
            and isinstance(att.get("seed_dir"), str) \
            and os.path.realpath(att.get("seed_dir")) == att.get("seed_dir") \
            and att.get("container_image_digest") \
            == identity.get("container_image_digest") \
            and att.get("harness_version") \
            == identity.get("harness_version") \
            and att.get("workspace_seed_digest") \
            == identity.get("workspace_seed_digest") \
            and att.get("database_dump_digest") \
            == identity.get("database_dump_digest") \
            and isinstance(att.get("needs_database"), bool) \
            and att.get("needs_database") \
            == (identity.get("database_dump_digest") != "no_database")
        if valid_attestation and runtime_version == "v2":
            from ..core.docker_cli import valid_endpoint_selection
            valid_attestation = valid_endpoint_selection(
                att.get("docker_endpoint_selection"))
        if valid_attestation and runtime_version in {"v3", "v4"}:
            try:
                checked_v3 = W.validate_worker_runtime_v3(
                    spec_path, expected_worker=spec)
            except W.WorkerRefused as e:
                raise MutationAborted(
                    f"REFUSED: native shard worker {number} runtime "
                    f"evidence is invalid: {e}") from e
            valid_attestation = (
                os.path.realpath(att_path) == checked_v3["runtime_path"]
                and att == checked_v3["runtime"])
        if any(record.get(key) != value
               for key, value in expected_resource.items()) \
                or not valid_attestation:
            raise MutationAborted(
                f"REFUSED: native shard worker {number} spec, runtime "
                "attestation and campaign identity disagree.")
        runtime_versions.add(runtime_version)
        if runtime_version in {"v3", "v4"}:
            runtime_identities.add((
                runtime_version,
                json.dumps(att["docker_execution_authority"],
                           sort_keys=True, separators=(",", ":")),
                checked_v3["binding"]["pool"]["digest"],
            ))
        else:
            runtime_identities.add((
                runtime_version, att.get("docker_endpoint_selection")))
        try:
            seed = W.verified_seed_identity(att["seed_dir"], needs_database)
        except W.WorkerRefused as e:
            raise MutationAborted(str(e)) from e
        seed_fields = (
            "seed_dir", "seed_manifest_sha256", "seed_key",
            "workspace_seed_digest", "database_dump_digest",
            "needs_database",
        )
        changed_seed = sorted(
            key for key in seed_fields if att.get(key) != seed.get(key))
        if changed_seed:
            raise MutationAborted(
                f"REFUSED: native shard worker {number} runtime attestation "
                f"differs from its re-derived seed field(s) {changed_seed}.")
        specs.append(spec)
        spec_paths.append(spec_path)
    if len(runtime_identities) != 1:
        raise MutationAborted(
            "REFUSED: native shard worker runtime attestations name mixed "
            "Docker authority/route identities.")
    if runtime_versions in ({"v3"}, {"v4"}):
        try:
            W.validate_offline_worker_runtime_pool(spec_paths)
        except W.WorkerRefused as e:
            raise MutationAborted(
                f"REFUSED: native shard worker-pool runtime evidence is "
                f"invalid: {e}") from e
    try:
        W.preflight(specs, [], live=False,
                    needs_database=needs_database)
    except W.WorkerRefused as e:
        raise MutationAborted(str(e)) from e
    return resources


#: Outcomes that are the HARNESS failing rather than the candidate failing.
#: Shared with `r2t.data.mutation`, which excludes them from the denominator.
INFRASTRUCTURE_OUTCOMES = frozenset({
    "container_error", "scenario_not_found", "no_scenario_ran",
    "substrate_violation"})
#: Owner ruling 2026-09-30: a Go mutant whose test only added files to its
#: disposable copy.  Scored as infrastructure (`r2t.data.mutation`) but
#: deterministic, so deliberately outside the retry set above.
UNSCORABLE_SUBSTRATE = "unscorable_substrate"


def candidate_digest(files_by_item: dict) -> str:
    """Full identity of the generated tests a mutation run executes.

    A concatenated results file is otherwise unattributable: two shards could
    have been produced from different `produced_files` for the same item and
    nothing in the rows would say so.

    This is canonical structured JSON, not delimiter concatenation.  Source
    code is arbitrary text; making NUL or newline a field separator either
    rejects otherwise valid bytes or permits two different field sequences to
    hash as one campaign.
    """
    if not isinstance(files_by_item, dict):
        raise MutationAborted(
            "REFUSED: generated tests must be keyed by item id.")
    if not all(isinstance(iid, str) and iid for iid in files_by_item):
        raise MutationAborted(
            "REFUSED: generated-test item ids must be non-empty strings.")
    payload = []
    for iid in sorted(files_by_item):
        if not isinstance(iid, str) or not iid:
            raise MutationAborted(
                f"REFUSED: generated-test item id is invalid: {iid!r}.")
        files = files_by_item[iid]
        if not isinstance(files, list):
            raise MutationAborted(
                f"REFUSED: generated tests for {iid!r} are not a list.")
        canonical_files = []
        seen: set[str] = set()
        for number, file in enumerate(files, 1):
            if not isinstance(file, dict):
                raise MutationAborted(
                    f"REFUSED: generated test {number} for {iid!r} is not "
                    "an object.")
            path, code = file.get("file_path"), file.get("code")
            if not isinstance(path, str) or not path \
                    or not isinstance(code, str):
                raise MutationAborted(
                    f"REFUSED: generated test {number} for {iid!r} needs "
                    "non-empty file_path and string code.")
            if path in seen:
                raise MutationAborted(
                    f"REFUSED: generated tests for {iid!r} repeat path "
                    f"{path!r}.")
            seen.add(path)
            canonical_files.append({"file_path": path, "code": code})
        payload.append({"item_id": iid,
                        "files": sorted(canonical_files,
                                        key=lambda value: value["file_path"])})
    return content_digest(payload)


def _require_pristine_substrate(harness: Harness, where: str) -> dict:
    """Require a real, nonempty baseline and no undeclared source changes."""
    if getattr(harness, "expected_mutations", None):
        raise MutationAborted(
            f"REFUSED: {where}: the harness still declares a mutation from a "
            "previous operation: {harness.expected_mutations}.")
    report = harness.verify_substrate()
    if not report.get("baseline"):
        raise MutationAborted(
            f"REFUSED: {where}: this workspace has no source-hash baseline. "
            "A publishable mutation campaign cannot prove restoration without "
            "one; reprovision it from a baselined disposable worker.")
    if report.get("changed") or report.get("missing") or report.get("added"):
        raise MutationAborted(
            f"REFUSED: {where}: the workspace is not pristine: "
            f"changed={report.get('changed')[:3]}, "
            f"missing={report.get('missing')[:3]}, "
            f"added={report.get('added')[:3]}.")
    return report


class CoordinatorCancellationEvent(threading.Event):
    """One-shot cancellation event with a monotonic source timestamp.

    A consumer which observes an ordinary ``threading.Event`` can establish
    only that it is set *now*.  It cannot establish whether the request was
    made before or after a competing wall-clock deadline.  The coordinator's
    event records the first call to :meth:`set` before publishing the Event
    flag, so a delayed watcher can still authenticate source ordering.  The
    event is deliberately one-shot; cancellation requests are never cleared
    and reused within one mutation invocation.
    """

    def __init__(self):
        super().__init__()
        self._request_lock = threading.RLock()
        self._requested_at: Optional[float] = None

    def set(self) -> None:
        with self._request_lock:
            # Repeated and nested signal deliveries are idempotent.  The early
            # return is also essential for same-thread re-entry while the first
            # call is inside Event.set(): Event's condition lock is not
            # re-entrant even though this outer request lock deliberately is.
            if self._requested_at is not None:
                return
            requested_at = time.monotonic()
            # A Python signal may have completed a nested call while the time
            # sample above ran.  Preserve that call's already-published source.
            if self._requested_at is not None:
                return
            # This assignment publishes the request's source record.  A nested
            # signal from this point through flag publication sees it and
            # returns without trying to re-enter Event's condition lock.
            self._requested_at = requested_at
            # Publish the ordinary Event flag only after its timestamp.  A
            # waiter which wakes on the flag can therefore always read a
            # complete source record.
            self._publish_flag()

    def _publish_flag(self) -> None:
        """Publish Event visibility; split out for nested-signal regression."""
        super().set()

    def operator_requested_at(self) -> Optional[float]:
        """Return the first monotonic ``set`` source time, if any."""
        requested_at, _visible = self.operator_snapshot()
        return requested_at

    def operator_snapshot(self) -> tuple[Optional[float], bool]:
        """Atomically return the source timestamp and published Event flag.

        Keeping both reads under the same lock as :meth:`set` prevents a
        deadline arbiter from seeing the timestamp on one side of publication
        and the Event flag on the other.  In particular, a setter paused after
        recording its source time cannot be mistaken for an absent request.
        The flag is read first because Python may run a same-thread signal
        handler re-entrantly despite the ``RLock``; if that handler publishes
        between the two reads, the timestamp is then visible and the flag is
        re-read to return the completed pair.
        """
        with self._request_lock:
            visible = self._published_is_set()
            requested_at = self._requested_at
            if requested_at is not None and not visible:
                visible = self._published_is_set()
            return requested_at, visible

    def _published_is_set(self) -> bool:
        """Read Event visibility; split out for re-entrant race regression."""
        return super().is_set()


@contextmanager
def coordinator_cancellation(cancel_event: Optional[threading.Event] = None):
    """Own SIGINT/SIGTERM in the main thread and request a cooperative stop.

    The handler never raises asynchronously while a mutant is being restored.
    Workers observe the event only at safe points.  The default timestamped
    event also lets a deadline-aware coordinator authenticate when the request
    originated even if its watcher runs later. A supplied ordinary Event is
    retained for API compatibility and has the same one-shot contract: callers
    must not clear it before this context exits. SIGKILL remains outside any
    process's ability to recover, which is why mutation workspaces are
    disposable and every invocation begins with a pristine-source preflight.
    """
    event = (cancel_event if cancel_event is not None
             else CoordinatorCancellationEvent())
    if threading.current_thread() is not threading.main_thread():
        raise MutationAborted(
            "REFUSED: signal ownership belongs to the coordinator main thread.")

    def _request_stop(_signum, _frame):
        event.set()

    previous = {sig: signal.signal(sig, _request_stop)
                for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        yield event
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _campaign_output_locked(func):
    """Apply the process lock without burying ``run_slice`` in one indent."""
    @wraps(func)
    def locked(harness, mutants, items_by_id, files_by_item, by_mutant,
               engine_dir, out_path, *args, **kwargs):
        # The standalone CLI knows the complete WorkerSpec, including the DB
        # schema, credential and env-file identities.  Pure callers do not,
        # so they retain the conservative workspace/container fallback.  Pop
        # this coordinator-only argument before invoking ``run_slice``.
        explicit_resources = kwargs.pop("resource_identities", None)
        with output_lock(out_path):
            from .mutation_continuation import refuse_parent_resume
            refuse_parent_resume(out_path)
            if kwargs.get("resources_locked", False):
                return func(harness, mutants, items_by_id, files_by_item,
                            by_mutant, engine_dir, out_path, *args, **kwargs)
            if explicit_resources is not None:
                resources = list(explicit_resources)
            else:
                resources = [("workspace", harness.root)]
                container = getattr(getattr(harness, "runner", None),
                                    "container", None)
                if isinstance(container, str) and container:
                    resources.append(("container", container))
            with mutation_resource_locks(resources):
                return func(harness, mutants, items_by_id, files_by_item,
                            by_mutant, engine_dir, out_path, *args, **kwargs)
    return locked


@_campaign_output_locked
def run_slice(harness: Harness, mutants: list[dict], items_by_id: dict,
              files_by_item: dict, by_mutant: dict, engine_dir: str,
              out_path: str, *, timeout: int = 600,
              provenance: Optional[dict] = None,
              on_row: Optional[Callable[[dict], None]] = None,
              applier: Applier = PHP_APPLIER,
              operator_profile: str = "v2",
              engine: str = ENGINE,
              engine_version: str = ENGINE_VERSION,
              identity: Optional[dict] = None,
              manifest: Optional[dict] = None,
              java_analysis_root: Optional[str] = None,
              planned_pairs: Optional[Iterable[tuple[str, str]]] = None,
              resume: bool = False,
              cancel_event: Optional[threading.Event] = None,
              resources_locked: bool = False,
              continuation_plan_path: Optional[str] = None) -> dict:
    """Execute `mutants` against one candidate and append the rows.

    `files_by_item` is the candidate's solution per item — the SAME
    `produced_files` a run recorded, so a mutation campaign never regenerates
    and a candidate is scored on exactly the bytes its run file holds.

    `engine` names the enumerator these mutant ids came from and goes onto
    every row.  It is a parameter rather than a constant because there is now
    more than one engine, and it is on the ROW rather than only in the
    provenance sidecar because rows outlive the file they were written beside:
    two `.jsonl` files concatenated by an operator, or a resumed campaign
    pointed at the wrong manifest, produce a mixed population that `recall`
    would average as if it were one.  A row that says which engine minted its
    mutant is the only local evidence that it did not.

    The disagreement between this argument and a `provenance["engine"]` the
    caller supplies is REFUSED rather than resolved: they come from the same
    manifest in every real call, so a mismatch means the caller is confused
    about which population it is executing, and picking either one would
    stamp thousands of rows with a guess.
    """
    from ..core.gherkin import parse_feature_file
    from .runner import _record
    if operator_profile not in {"v1", "v2"}:
        raise MutationAborted(
            f"REFUSED: unknown operator profile {operator_profile!r}")
    if identity is None:
        raise MutationAborted(
            "REFUSED: mutation-run requires a versioned campaign identity. "
            "Legacy rows may be audited by legacy_consistency, but new or "
            "resumed publishable rows must be content-bound.")
    gold_run = is_gold_run_slice(identity)
    observation_id = None
    if identity.get("kind") == "mutation-run":
        expected_standalone_name = (
            f"{identity['side']}.w{identity['shard']}.jsonl")
        plan_path = os.path.join(
            os.path.dirname(os.path.abspath(out_path)),
            MUTATION_OUTPUT_PLAN)
        if os.path.isfile(plan_path) \
                or os.path.basename(os.path.abspath(out_path)) \
                == expected_standalone_name:
            observation_id = _load_standalone_output_observation(
                out_path, identity, require_current=True)
    campaign_digest = campaign_identity_digest(identity)
    analysis_recipe = None
    go_runtime = None
    go_authority = None
    if engine == "r2t-mutate-go":
        from ..go import mutation_runtime as go_runtime
        go_runtime.validate_campaign(manifest, identity)
    if engine == "r2t-mutate-java":
        if not isinstance(manifest, dict):
            raise MutationAborted(
                "REFUSED: Java mutation campaign requires the complete "
                "manifest that authenticates its analysis recipe")
        try:
            from ..data import mutation_attestation as A
            from ..toolkit import mutation_java as JAVA
            A.validate_manifest(manifest, expected_engine=engine)
            if manifest.get("digest") != identity.get("manifest_digest"):
                raise MutationAborted(
                    "REFUSED: Java campaign manifest digest differs from its "
                    "campaign identity")
            if manifest.get("engine_version") != engine_version \
                    or manifest.get("parser") != identity.get("parser"):
                raise MutationAborted(
                    "REFUSED: Java campaign manifest engine/parser differs "
                    "from its campaign identity")
            analysis_recipe = manifest["analysis_recipe"]
            # Structural validation is cheap here.  An active shard copies
            # and authenticates the complete recipe once below, before any
            # output; an already-complete read-only resume need not re-read a
            # dependency tree it will never execute.
            JAVA.validate_analysis_recipe(analysis_recipe)
        except MutationAborted:
            raise
        except (TypeError, ValueError) as exc:
            raise MutationAborted(str(exc)) from exc
    elif manifest is not None:
        if not isinstance(manifest, dict) \
                or manifest.get("engine") != engine:
            raise MutationAborted(
                "REFUSED: optional campaign manifest names another mutation "
                "engine")
    if java_analysis_root is not None:
        if analysis_recipe is None or analysis_recipe.get("schema") \
                != JAVA.MODULE_ANALYSIS_SCHEMA:
            raise MutationAborted(
                "REFUSED: separate Java analysis root requires Kapua module authority")
        java_analysis_root = os.path.abspath(java_analysis_root)
        provenance = {**(provenance or {}), "java_analysis_root": java_analysis_root}
    natural_expected = expected_pairs_for_slice(
        mutants, by_mutant, files_by_item)
    raw_planned = (None if planned_pairs is None else list(planned_pairs))
    malformed_planned = ([] if raw_planned is None else [
        pair for pair in raw_planned
        if not isinstance(pair, tuple) or len(pair) != 2
        or not all(isinstance(value, str) and value for value in pair)])
    if malformed_planned:
        raise MutationAborted(
            "REFUSED: pair-restricted mutation execution contains malformed "
            f"pairs: {malformed_planned[:3]}.")
    expected = (natural_expected if raw_planned is None
                else set(raw_planned))
    outside_planned = sorted(expected - natural_expected)
    if outside_planned:
        raise MutationAborted(
            "REFUSED: pair-restricted mutation execution contains "
            "candidate/map-external pairs: "
            f"{outside_planned[:3]}.")
    if (len(expected) != identity.get("expected_pairs")
            or pair_set_digest(expected) != identity.get(
                "expected_pairs_sha256")):
        raise MutationAborted(
            "REFUSED: the planned mutants/map/files pair selection differs "
            "from the campaign identity.")
    if continuation_plan_path is not None or "continuation_plan_sha256" in identity:
        from .mutation_continuation import (validate_plan, validate_identity,
                                            validate_child_resources)
        if continuation_plan_path is None or "continuation_plan_sha256" not in identity:
            raise MutationAborted("REFUSED: continuation needs both plan and bound identity")
        binding = validate_plan(continuation_plan_path)
        validate_identity(binding, identity)
        validate_child_resources(binding, (provenance or {}).get("worker_resources", []))
        if expected != binding["partitions"][identity["shard"]]:
            raise MutationAborted("REFUSED: continuation execution differs from pending partition")
    # Context comes from the witnessed closure snapshot, never the candidate
    # bytes. Check only items in this shard's authenticated pair selection,
    # before staging an applier, materializing answers, or writing evidence.
    from ..go.context import preflight
    preflight(harness, (items_by_id[iid]
                        for iid in sorted({iid for iid, _ in expected})))
    generated_digest = candidate_digest(files_by_item)
    if identity.get("solution_generated_tests_sha256") != generated_digest:
        raise MutationAborted(
            f"REFUSED: this slice's generated tests digest to "
            f"{generated_digest}, but its campaign identity says "
            f"{identity.get('solution_generated_tests_sha256')}. Candidate "
            "bytes changed; use a new output.")
    if go_runtime is not None:
        # Go workers run their seed-installed applier, not this checkout's
        # separately pinned catalogue builder.
        try:
            actual_applier_sha = go_runtime.installed_applier_sha256(harness)
        except go_runtime.MutationRuntimeRefused as exc:
            raise MutationAborted(str(exc)) from exc
    else:
        actual_applier_sha = sha256_file(os.path.join(engine_dir, applier.source))
    if identity.get("applier_sha256") != actual_applier_sha:
        raise MutationAborted(
            f"REFUSED: the applier bytes digest to {actual_applier_sha}, but "
            f"the campaign identity says {identity.get('applier_sha256')}.")
    for key, value in (("engine", engine),
                       ("engine_version", engine_version)):
        if identity.get(key) != value:
            raise MutationAborted(
                f"REFUSED: run_slice has {key}={value!r}, but the campaign "
                f"identity has {identity.get(key)!r}.")
    if identity.get("timeout_seconds") != int(timeout):
        raise MutationAborted(
            f"REFUSED: run_slice timeout {timeout} does not match campaign "
            f"timeout {identity.get('timeout_seconds')}.")
    provenance = dict(provenance or {})
    if observation_id is not None:
        claimed_observation = provenance.get("observation_id")
        if claimed_observation is not None \
                and claimed_observation != observation_id:
            raise MutationAborted(
                f"REFUSED: mutation provenance claims observation_id "
                f"{claimed_observation!r}, but output ownership records "
                f"{observation_id!r}.")
        provenance["observation_id"] = observation_id
    for key, ours in (("engine", engine), ("engine_version", engine_version)):
        theirs = provenance.get(key)
        if theirs is not None and theirs != ours:
            raise MutationAborted(
                f"REFUSED: this slice is being executed as {key}={ours!r} but "
                f"its provenance says {theirs!r}. The mutant ids hash the "
                f"engine, so the two disagree about which population is "
                f"running; reconcile them before spending the campaign.")
        provenance[key] = ours
    claimed_candidate = provenance.get("candidate_digest")
    if claimed_candidate is not None and claimed_candidate != generated_digest:
        raise MutationAborted(
            f"REFUSED: provenance claims candidate_digest "
            f"{claimed_candidate}, but the supplied generated tests digest to "
            f"{generated_digest}.")
    provenance["candidate_digest"] = generated_digest
    provenance["manifest_digest"] = identity.get("manifest_digest")

    # The Pimcore PHP harness restores generated class files before each pair only
    # when its route handed it the seed's bytes (`cli._derived_baseline`).
    # Without them a class re-saved under one mutant stays on disk for every
    # later pair -- the defect that voided the first CoreShop references --
    # so a route that forgot to attach them is refused here, before output.
    from .harness import Harness as _PhpHarness
    from .repo import derived_state_roots
    if (isinstance(harness, _PhpHarness)
            and derived_state_roots("behat", behat=harness.behat)
            and not harness.derived_baseline):
        raise MutationAborted(
            "REFUSED: this PHP harness carries no derived-state baseline, so "
            "var/classes regenerated under one mutant would persist into "
            "every later pair. Build it from the verified seed "
            "(`cli._derived_baseline`).")

    # Verify both states before touching an output: the current source tree is
    # pristine, and the baseline against which "pristine" was decided is the
    # exact one frozen into this campaign.  The second check is what prevents
    # two individually clean but differently baselined workers from merging.
    _require_pristine_substrate(harness, "before mutation campaign")
    actual_substrate = substrate_baseline_digest(harness)
    if identity.get("substrate_baseline_sha256") != actual_substrate:
        raise MutationAborted(
            f"REFUSED: this worker's substrate baseline digests to "
            f"{actual_substrate}, but the campaign identity says "
            f"{identity.get('substrate_baseline_sha256')}. Reprovision every "
            "worker from one immutable baseline and use a new output.")
    provenance["substrate_baseline_sha256"] = actual_substrate

    out_exists = os.path.lexists(out_path)
    side_exists = os.path.lexists(provenance_path(out_path))
    if os.path.islink(out_path) or os.path.islink(provenance_path(out_path)):
        raise MutationAborted(
            f"REFUSED: mutation rows/provenance may not be symlinks: "
            f"{out_path}.")
    if not resume and (out_exists or side_exists):
        raise MutationAborted(
            f"REFUSED: mutation output is not new: {out_path}. The default is "
            "a new output; pass --resume only for an exact identity-matching "
            "current campaign.")
    if resume and out_exists != side_exists:
        raise MutationAborted(
            f"REFUSED: resume needs both {out_path} and its provenance sidecar; "
            "only one exists.")
    done = (completed_pairs(out_path, identity, expected_pairs=expected)
            if resume and out_exists else set())

    # NOTHING LEFT TO DO — AND THEREFORE NOTHING TO WRITE (review finding 8).
    #
    # At the reviewed head this case fell through: the sidecar was rewritten
    # to `running` before any work, the applier was staged, a per-mutant
    # pristine check ran over empty `covering` sets, and any cleanup or
    # restoration failure in that window wrote terminal `failed` over a
    # byte-identical, previously attested shard. The K-way recovery recipe
    # (`README.md:336-349`) re-issues all K commands with `--resume`, so this
    # is the ordinary path for every shard that had already finished, not an
    # edge case.
    #
    # Two sub-cases, and only the first is strictly read-only:
    #
    #   * the shard is already attested `complete` — return its recorded
    #     state without touching a byte. Row and sidecar bytes are preserved
    #     even when a cleanup hook would fail, because no cleanup runs.
    #
    #   * the rows are complete but the shard was never attested (`running`
    #     or `interrupted`: a kill between the final row's durable write and
    #     the completion write leaves exactly this). It takes the ORDINARY
    #     completion path below — the same `completed_pairs` re-validation
    #     and the same single `complete` transition an in-process run takes
    #     after its last row — but stages no applier and executes no cleanup,
    #     because there is no mutant to apply and nothing to clean up.
    #
    # DEVIATION, RECORDED: plan §3 says resume "returns read-only" whenever
    # `done == expected`. Read literally that strands the second sub-case
    # forever: the rows are valid and complete, but merge requires
    # `complete`, no verb may write it (`verify-shard` is read-only by
    # mandate), and the recovery for a shard that is not failure evidence
    # would be a full rerun. That would defeat §5's own requirement that a
    # cooperatively cancelled campaign "remains resumable". The destructive
    # re-entry the plan is closing is the write over a TERMINAL attestation,
    # and that is refused here and, one level down, by the transition table.
    if resume and out_exists and done == expected:
        recorded = recorded_shard_status(out_path, identity)
        if recorded == "complete":
            side_doc = _load_shard_provenance(out_path, identity)
            return {"out": out_path, "rows": 0, "resumed_rows": len(done),
                    "total_rows": side_doc["rows"],
                    "mutants": len(mutants), "outcomes": {},
                    "provenance": provenance,
                    "campaign_identity": identity,
                    "mutation_campaign_digest": campaign_digest,
                    "status": "complete", "read_only": True,
                    "seconds": 0.0}
        write_shard_provenance(out_path, identity, "running",
                               provenance=provenance)
        final_done = completed_pairs(out_path, identity,
                                     expected_pairs=expected)
        if final_done != expected:
            raise MutationAborted(
                f"REFUSED: resumed shard has "
                f"{len(expected - final_done)} missing pair(s) on the second "
                "read; its rows changed underneath this process.")
        final_doc = write_shard_provenance(out_path, identity, "complete",
                                           provenance=provenance)
        return {"out": out_path, "rows": 0, "resumed_rows": len(done),
                "total_rows": final_doc["rows"],
                "mutants": len(mutants), "outcomes": {},
                "provenance": provenance,
                "campaign_identity": identity,
                "mutation_campaign_digest": campaign_digest,
                "status": "complete", "read_only": False,
                "seconds": 0.0}

    # Prune already-authenticated work before entering the per-mutant loop.
    #
    # ``completed_pairs`` above has authenticated every retained row against
    # the exact campaign identity, sidecar bytes and planned pair set.  A
    # mutant for which no pair remains cannot be applied and cannot emit a
    # row.  Keeping it in the live loop used to perform a complete substrate
    # tree verification anyway, once per already-completed mutant.  A late
    # interruption could consequently turn a one-pair resume into hundreds or
    # thousands of full-tree hashes before reaching that pair.
    #
    # This is intentionally narrower than a preflight cache: no parsed
    # feature, Solution, analyzer result, workspace state or framework process
    # is reused.  Every pending mutant retains the same pre-apply and
    # post-revert pristine checks, apply/revert cycle, scenario execution,
    # retry, row fsync and sidecar transition.  Input order is preserved and a
    # repeated mutant id keeps the first descriptor, which is the descriptor
    # the old loop would have executed before its newly written pair made any
    # later duplicate a no-op.
    pending_ids = {mutant_id for _item_id, mutant_id in expected - done}
    pending_mutants = []
    selected_ids: set[str] = set()
    for mutant in mutants:
        mutant_id = mutant["id"]
        if mutant_id in pending_ids and mutant_id not in selected_ids:
            pending_mutants.append(mutant)
            selected_ids.add(mutant_id)
    missing_pending_ids = sorted(pending_ids - selected_ids)
    if missing_pending_ids:                               # pragma: no cover
        # ``expected`` was already proved a subset of ``natural_expected``,
        # so reaching this branch means the in-memory plan changed while this
        # function was running.  Refuse before staging an applier or output.
        raise MutationAborted(
            "REFUSED: planned pending pair(s) name mutant ids absent from "
            f"the execution slice: {missing_pending_ids[:3]}.")

    cancel_event = cancel_event or threading.Event()
    started = time.time()
    n_rows = 0
    n_skipped = len(done)
    counts: dict = {}
    applier_attempted = False
    analysis_snapshot_context = None
    analysis_snapshot_root = None
    analysis_snapshot_entered = False
    java_applier_context = None
    java_classes_root = None
    java_applier_entered = False
    module_analysis_bindings = None
    output_started = False
    caught: Optional[BaseException] = None
    try:
        if cancel_event.is_set():
            raise MutationCancelled(
                "mutation campaign cancelled before the first mutant")
        if analysis_recipe is not None:
            # The exact image toolchain, complete authenticated source
            # membership, private snapshot, and compiled engine all preflight
            # before the first output byte. A parser mismatch or forged
            # missing member therefore leaves no resumable-looking shard.
            module_authority = analysis_recipe.get("schema") \
                == JAVA.MODULE_ANALYSIS_SCHEMA
            if module_authority:
                try:
                    module_analysis_bindings = JAVA.module_analysis_bindings(
                        analysis_recipe)
                    JAVA.validate_module_toolchains(
                        analysis_recipe, harness.runner,
                        timeout=min(timeout, 120))
                except (RuntimeError, ValueError) as exc:
                    raise MutationAborted(str(exc)) from exc
            else:
                _require_isolated_java_toolchain(
                    harness, manifest["parser"], timeout=min(timeout, 120))
            if java_analysis_root is not None:
                JAVA.validate_module_analysis_sources(
                    harness.root, analysis_recipe)
            analysis_snapshot_context = JAVA.analysis_snapshot(
                java_analysis_root or harness.root, analysis_recipe,
                required_sources=[row["file"]
                                  for row in manifest["mutants"]])
            analysis_snapshot_root = analysis_snapshot_context.__enter__()
            analysis_snapshot_entered = True
            java_applier_context = _isolated_java_applier(
                harness, engine_dir, applier,
                expected_sha256=identity["applier_sha256"],
                java_home=("/opt/java/openjdk8"
                           if module_authority else None))
            java_classes_root = java_applier_context.__enter__()
            java_applier_entered = True
        elif go_runtime is not None:
            # Go's engine is already sealed in the original seed. Reference
            # authority is authenticated before output; application belongs
            # to each selected item/attempt's finalized disposable copy.
            go_authority = go_runtime.prepare_campaign(
                harness, manifest, identity,
                artifacts=getattr(harness, "artifacts_dir", None))
        else:
            applier_attempted = True
            install_applier(harness, engine_dir, applier)

        # No output or applier is created until the source tree proves it has
        # a nonempty baseline and is pristine. For Java, the stronger parser,
        # source-membership, snapshot and engine preflights above also finish
        # before this boundary.
        os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".",
                    exist_ok=True)
        if not out_exists:
            atomic_write_bytes(out_path, b"", refuse_existing=True)
        output_started = True
        total_rows, rows_sha = _rows_state(out_path)
        write_shard_provenance(out_path, identity, "running",
                               provenance=provenance, rows=total_rows,
                               rows_sha256=rows_sha)
        rows_hash = hashlib.sha256()
        with open(out_path, "rb") as existing:
            for chunk in iter(lambda: existing.read(1 << 20), b""):
                rows_hash.update(chunk)
        with open(out_path, "ab") as fh:
            for mutant in pending_mutants:
                if cancel_event.is_set():
                    raise MutationCancelled(
                        "mutation campaign cancelled between mutants")
                covering = [i for i in by_mutant.get(mutant["id"], [])
                            if i in files_by_item
                            and (i, mutant["id"]) in expected
                            and (i, mutant["id"]) not in done]
                if not covering:
                    continue
                _require_pristine_substrate(
                    harness, f"before applying mutant {mutant['id']}")
                applied = None if go_runtime is not None else apply_mutant(
                    harness, mutant, applier,
                    operator_profile=operator_profile,
                    analysis_recipe=analysis_recipe,
                    analysis_bindings=module_analysis_bindings,
                    analysis_snapshot_root=analysis_snapshot_root,
                    java_classes_root=java_classes_root,
                    engine_dir=engine_dir)
                try:
                    for iid in covering:
                        if cancel_event.is_set():
                            raise MutationCancelled(
                                "mutation campaign cancelled between item "
                                "executions")
                        item = items_by_id[iid]
                        source_rel = item["provenance"]["file_path"]
                        from ..java.algorand import runtime_feature_path
                        runtime_rel = runtime_feature_path(
                            item.get("project") or "", source_rel)
                        feature = parse_feature_file(
                            os.path.join(harness.root, runtime_rel))
                        scenario = feature.scenario_at(item["provenance"]["line"])
                        if scenario is None:
                            raise MutationAborted(
                                f"REFUSED: item {iid} has no scenario at its "
                                "declared line, so planned pair "
                                f"{(iid, mutant['id'])} cannot be executed.")
                        from .harness import Solution
                        sol = Solution.from_json(
                            {"files": files_by_item[iid], "metadata": {}})
                        sol.gold_run = gold_run

                        # §3.10: "infrastructure failures are retried once then
                        # excluded and counted".  Without the retry a single
                        # container hiccup removes that mutant from the
                        # denominator permanently, and a denominator that
                        # shrinks for reasons unrelated to the candidate is how
                        # a recall number drifts upward without anybody
                        # choosing it.
                        attempt, rec, result = 0, None, None
                        while attempt < 2:
                            attempt += 1
                            if go_runtime is not None:
                                evidence_root = os.path.abspath(out_path) + ".go-evidence"
                                os.makedirs(evidence_root, exist_ok=True)
                                evidence_dir = tempfile.mkdtemp(
                                    prefix=f"{mutant['id']}.{attempt}.", dir=evidence_root)
                                result = go_runtime.run_solution(
                                    harness, feature, scenario, sol,
                                    mutant=mutant, manifest=manifest,
                                    identity=identity, authority=go_authority,
                                    timeout=timeout, evidence_dir=evidence_dir)
                            else:
                                # Harness 27: a non-debug Symfony kernel's
                                # pools hold metadata built under the
                                # previous pair's mutant; empty them so this
                                # pair builds its own.
                                if hasattr(harness, "clear_cache_pools"):
                                    harness.clear_cache_pools()
                                result = harness.run_solution(
                                    feature, scenario, sol, coverage=False,
                                    timeout=timeout,
                                    task=item.get("task") or "criterion_to_test")
                            if result.get("unscorable_substrate") is not None:
                                # Owner ruling 2026-09-30: the runtime has
                                # retired the copy and rechecked the original
                                # and the host. Recorded once, never retried.
                                rec = {"outcome": UNSCORABLE_SUBSTRATE,
                                       "execution_seconds": 0.0,
                                       "substrate_violation":
                                           result["unscorable_substrate"]}
                                break
                            if result.get("substrate_violation"):
                                raise MutationAborted(
                                    f"REFUSED: candidate execution for {iid} "
                                    "changed undeclared source substrate: "
                                    f"{result['substrate_violation']}. The "
                                    "worker is quarantined; do not continue.")
                            rec = _record(iid, item,
                                          {"files": files_by_item[iid]},
                                          0.0, result, coverage=False)
                            if rec["outcome"] not in INFRASTRUCTURE_OUTCOMES:
                                break
                        row = {"item_id": iid, "mutant_id": mutant["id"],
                               "operator": mutant["operator"],
                               "file": mutant["file"],
                               "start_line": mutant["start_line"],
                               "outcome": rec["outcome"],
                               "attempt": attempt,
                               "retried_infrastructure": attempt > 1,
                               **row_identity_stamp(identity,
                                                    campaign_digest),
                               "candidate_digest": generated_digest,
                               "seconds": rec["execution_seconds"]}
                        if "crash" in rec:
                            # Owner ruling 2026-09-28: a mutant that crashed
                            # the Go test process is killed (`failed`); the
                            # label discloses how many kills were crashes.
                            row["crash"] = rec["crash"]
                        if rec["outcome"] == UNSCORABLE_SUBSTRATE:
                            # Both scoped integrity reports, as evidence.
                            row["substrate_violation"] = \
                                rec["substrate_violation"]
                        encoded = (json.dumps(row, sort_keys=True) + "\n").encode(
                            "utf-8")
                        fh.write(encoded)
                        fh.flush()
                        os.fsync(fh.fileno())
                        rows_hash.update(encoded)
                        total_rows += 1
                        n_rows += 1
                        done.add((iid, mutant["id"]))
                        counts[row["outcome"]] = counts.get(row["outcome"], 0) + 1
                        write_shard_provenance(
                            out_path, identity, "running",
                            provenance=provenance, rows=total_rows,
                            rows_sha256=rows_hash.hexdigest())
                        if on_row is not None:
                            on_row(row)
                finally:
                    # In a `finally` because a mutant left applied is worse
                    # than a mutant not measured: it silently poisons every
                    # later item, on this worker, for the rest of the campaign.
                    try:
                        if applied is not None:
                            revert_mutant(harness, applied)
                    finally:
                        _require_pristine_substrate(
                            harness, f"after restoring mutant {mutant['id']}")
                if cancel_event.is_set():
                    raise MutationCancelled(
                        "mutation campaign cancelled after mutant restoration")
        if done != expected:
            missing = sorted(expected - done)
            unexpected = sorted(done - expected)
            raise MutationAborted(
                f"REFUSED: mutation slice ended with {len(missing)} missing and "
                f"{len(unexpected)} unexpected pair(s), e.g. missing "
                f"{missing[:3]}, unexpected {unexpected[:3]}.")
    except BaseException as e:                              # noqa: BLE001
        caught = e
    finally:
        cleanup_errors = []
        if applier_attempted:
            try:
                remove_applier(harness, applier)
            except BaseException as e:                       # noqa: BLE001
                cleanup_errors.append(e)
        if java_applier_entered:
            try:
                java_applier_context.__exit__(None, None, None)
            except BaseException as e:                       # noqa: BLE001
                cleanup_errors.append(e)
        if analysis_snapshot_entered:
            try:
                analysis_snapshot_context.__exit__(None, None, None)
            except BaseException as e:                       # noqa: BLE001
                cleanup_errors.append(e)
        if analysis_recipe is not None and analysis_snapshot_entered:
            try:
                # Recheck the compiler authority and the worker's original
                # sources at completion. Runtime classpath resources can differ
                # when Kapua names its separately captured compiler root.
                JAVA.revalidate_analysis_inputs(
                    java_analysis_root or harness.root, analysis_recipe)
                if java_analysis_root is not None:
                    JAVA.validate_module_analysis_sources(
                        harness.root, analysis_recipe)
            except BaseException as e:                       # noqa: BLE001
                cleanup_errors.append(e)
        try:
            from .repo import clean_workspace
            if hasattr(harness, "man") and hasattr(harness, "boundary"):
                clean_workspace(harness.man, harness.boundary)
            if hasattr(harness, "clear_registration"):
                harness.clear_registration()
        except BaseException as e:                           # noqa: BLE001
            cleanup_errors.append(e)
        try:
            # SPEC_C3_PARALLEL §3.1.1 rule 2: the per-pair restore runs BEFORE
            # a pair, so the shard's last pair can leave a class it
            # regenerated under a mutant.  Restore once more here, or the
            # worker goes on to `run`/`validate` (which never restore)
            # holding it.  Only the PHP harness has derived state.
            if hasattr(harness, "restore_derived_state"):
                harness.restore_derived_state(when="after the shard's last "
                                                   "pair")
            # The same for the pools the last pair filled under its mutant.
            if hasattr(harness, "clear_cache_pools"):
                harness.clear_cache_pools()
        except BaseException as e:                           # noqa: BLE001
            cleanup_errors.append(e)
        try:
            _require_pristine_substrate(harness,
                                        "after mutation campaign cleanup")
        except BaseException as e:                           # noqa: BLE001
            cleanup_errors.append(e)
        if cleanup_errors:
            details = "; ".join(f"{type(e).__name__}: {e}"
                                for e in cleanup_errors)
            original_error = (f" Original campaign error: "
                              f"{type(caught).__name__}: {caught}."
                              if caught is not None else "")
            cleanup_failure = MutationAborted(
                f"REFUSED: mutation campaign cleanup/restoration failed: "
                f"{details}. This worker must be reprovisioned."
                f"{original_error}")
            if caught is not None:
                cleanup_failure.__cause__ = caught
            caught = cleanup_failure

    if caught is not None:
        if not output_started:
            raise caught
        status = ("interrupted" if isinstance(
            caught, (MutationCancelled, KeyboardInterrupt)) else "failed")
        write_shard_provenance(
            out_path, identity, status, provenance=provenance,
            error=f"{type(caught).__name__}: {caught}")
        raise caught

    # Completeness is checked before and after cleanup; only then may the
    # sidecar transition atomically to `complete`.
    try:
        final_done = completed_pairs(out_path, identity,
                                     expected_pairs=expected)
        if final_done != expected:
            raise MutationAborted(
                f"REFUSED: final shard has {len(expected - final_done)} "
                "missing pair(s); complete provenance was not written.")
    except BaseException as e:                              # noqa: BLE001
        write_shard_provenance(
            out_path, identity, "failed", provenance=provenance,
            error=f"{type(e).__name__}: {e}")
        raise
    final_doc = write_shard_provenance(
        out_path, identity, "complete", provenance=provenance)
    return {"out": out_path, "rows": n_rows, "resumed_rows": n_skipped,
            "total_rows": final_doc["rows"],
            "mutants": len(mutants), "outcomes": counts,
            "provenance": provenance,
            "campaign_identity": identity,
            "mutation_campaign_digest": campaign_digest,
            "status": "complete",
            "seconds": round(time.time() - started, 1)}


def _valid_reference_speeds(speeds, total):
    """`[[slots, speed], ...]` in slot order: positive integers covering every slot."""
    return (isinstance(speeds, list) and bool(speeds)
            and all(isinstance(run, list) and len(run) == 2
                    and all(type(v) is int and v >= 1 for v in run) for run in speeds)
            and sum(run[0] for run in speeds) == total)


def load_reference_partition(path, host):
    """Bind local pools to disjoint slots in the immutable full-gold allocation.

    An optional integer `speed` on every host (relative per-worker throughput)
    selects speed-weighted balanced slots; without it slots are the stride.
    """
    import re
    with open(path, encoding='utf-8') as stream:
        allocation = json.load(stream)
    if not isinstance(allocation, dict) or not allocation or host not in allocation:
        raise MutationAborted('REFUSED: unknown full-gold allocation host')
    offset = 0
    selected = None
    hostnames = set()
    speeds = []
    for key, entry in sorted(allocation.items()):
        if (not re.fullmatch(r'[a-z][a-z0-9_]*', key)
                or not isinstance(entry, dict)
                or set(entry) - {'speed'} != {'host', 'root', 'authority', 'workers'}
                or type(entry['workers']) is not int or entry['workers'] < 2
                or ('speed' in entry and (type(entry['speed']) is not int or entry['speed'] < 1))
                or not isinstance(entry['host'], str) or not entry['host']
                or entry['host'] in hostnames):
            raise MutationAborted('REFUSED: invalid full-gold host allocation')
        hostnames.add(entry['host'])
        if key == host:
            selected = (offset, entry['workers'])
        offset += entry['workers']
        if 'speed' in entry:
            speeds.append([entry['workers'], entry['speed']])
    if speeds and len(speeds) != len(allocation):
        raise MutationAborted('REFUSED: full-gold host speeds must be given for every host or none')
    partition = {'allocation_sha256': sha256_file(path), 'host': host,
                 'offset': selected[0], 'total': offset}
    if speeds:
        partition['speeds'] = speeds
    return partition, selected[1]


def reference_slot_indices(sizes, partition):
    """Eligible-mutant indices (manifest order) of every global allocation slot.

    `sizes` are the eligible mutants' pair counts in manifest order.  Without
    `speeds` a slot is the manifest-order stride.  With `speeds`, whole mutants,
    largest first (manifest order on ties), go to the slot whose finish
    (load + pairs) / speed is least (lowest slot on ties), so slots on slower
    hosts receive proportionally fewer pairs.  Exact integer arithmetic; the
    union of pairs is the same under either scheme.
    """
    import heapq
    total = partition['total']
    if 'speeds' not in partition:
        return [list(range(slot, len(sizes), total)) for slot in range(total)]
    speed_of = [speed for count, speed in partition['speeds'] for _ in range(count)]
    heaps = {}
    for slot, speed in enumerate(speed_of):
        heaps.setdefault(speed, []).append((0, slot))      # ascending, so already a heap
    slots = [[] for _ in range(total)]
    for index in sorted(range(len(sizes)), key=lambda i: (-sizes[i], i)):
        pairs = sizes[index]
        best = None
        for speed, heap in heaps.items():
            load, slot = heap[0]
            if best is None:
                best = (speed, load, slot)
                continue
            mine, theirs = (load + pairs) * best[0], (best[1] + pairs) * speed
            if mine < theirs or (mine == theirs and slot < best[2]):
                best = (speed, load, slot)
        speed, load, slot = best
        heapq.heapreplace(heaps[speed], (load + pairs, slot))
        slots[slot].append(index)
    return [sorted(indices) for indices in slots]


def reference_pair_slots(count, partition):
    """Pair indices of every global slot when a supplement deals single pairs.

    Owner delegation 2026-09-30 (full282 section 5, fourth supplement): pairs
    in manifest-mutant then item order go one at a time to the slot whose
    finish (load + 1) / speed is least (lowest slot on ties), so one mutant's
    pairs spread over the slots instead of queueing on one worker.
    """
    import heapq
    total = partition['total']
    speed_of = ([speed for workers, speed in partition['speeds'] for _ in range(workers)]
                if 'speeds' in partition else [1] * total)
    heaps = {}
    for slot, speed in enumerate(speed_of):
        heaps.setdefault(speed, []).append((0, slot))
    slots = [[] for _ in range(total)]
    for index in range(count):
        best = None
        for speed, heap in heaps.items():
            load, slot = heap[0]
            if best is None:
                best = (speed, load, slot)
                continue
            mine, theirs = (load + 1) * best[0], (best[1] + 1) * speed
            if mine < theirs or (mine == theirs and slot < best[2]):
                best = (speed, load, slot)
        speed, load, slot = best
        heapq.heapreplace(heaps[speed], (load + 1, slot))
        slots[slot].append(index)
    return slots


def reference_shard_pairs(manifest, by_mutant, partition, workers):
    """Each local shard's exact pairs under the same slot assignment as mutation-run."""
    eligible = [m['id'] for m in manifest['mutants'] if by_mutant.get(m['id'])]
    if partition.get('pair_slots'):
        pairs = [(item, mutant) for mutant in eligible for item in sorted(set(by_mutant[mutant]))]
        slots = reference_pair_slots(len(pairs), partition)
        return [{pairs[index] for index in slots[partition['offset'] + i]} for i in range(workers)]
    slots = reference_slot_indices([len(set(by_mutant[m])) for m in eligible], partition)
    return [{(item, eligible[index]) for index in slots[partition['offset'] + i]
             for item in by_mutant[eligible[index]]} for i in range(workers)]


def reference_partition_pairs(manifest, by_mutant, partition, workers):
    """The host's exact union under the same slot assignment as mutation-run."""
    return set().union(*reference_shard_pairs(manifest, by_mutant, partition, workers))


# Owner ruling 2026-09-30 (full282 specification, section 5): a failed host
# partition of a full-gold reference keeps the rows it recorded, and a
# supplement campaign under its own allocation and tag observes exactly the
# pairs it did not.  The plan freezes that pending set before launch.  A
# supplement host may fail in turn: the next supplement's parent is then that
# supplement, and its plan names the parent plan.
REFERENCE_SUPPLEMENT_PLAN_SCHEMA = 'r2t.coddy-reference-supplement-plan/1'


def _pairs_by_mutant(pairs):
    by_mutant = {}
    for item, mutant in pairs:
        by_mutant.setdefault(mutant, set()).add(item)
    return by_mutant


def read_failed_reference_shards(paths, *, shard_pairs, strict=True):
    """The durable rows of one failed full-gold host campaign. READS ONLY.

    The shards stay failure evidence: nothing here resumes, promotes or
    rewrites them.  A shard is read only when its bytes are exactly what its
    sidecar attests (digest, row count, no torn last line), every row carries
    the campaign stamp, and its pairs are a duplicate-free subset of that
    shard's planned pairs -- all of them for a shard that completed before its
    host failed.  `shard_pairs[i]` is shard i's planned set; it must match the
    identity's pair digest.  The portable caller checks the worker-resource
    preimage itself; `strict` authenticates the producer-host evidence.
    """
    from .worker import _seed_verification_scope
    shards, statuses = [], set()
    with _seed_verification_scope():
        for path in paths:
            side = provenance_path(path)
            if os.path.islink(path) or not os.path.isfile(path) \
                    or os.path.islink(side) or not os.path.isfile(side):
                raise MutationAborted(f'REFUSED: failed shard and sidecar must be regular files: {path}')
            try:
                with open(side, encoding='utf-8') as stream:
                    doc = json.load(stream)
            except (OSError, json.JSONDecodeError) as exc:
                raise MutationAborted(f'REFUSED: cannot read failed shard sidecar {side}: {exc}') from exc
            identity = doc.get('campaign_identity') if isinstance(doc, dict) else None
            _validate_campaign_identity(identity or {})
            digest = campaign_identity_digest(identity)
            shard = identity['shard']
            if doc.get('schema') != MUTATION_PROVENANCE_SCHEMA \
                    or doc.get('mutation_campaign_digest') != digest \
                    or doc.get('status') not in ('failed', 'interrupted', 'complete') \
                    or not 0 <= shard < len(shard_pairs):
                raise MutationAborted(f'REFUSED: {side} is not a failed, interrupted or complete shard of this campaign')
            planned = shard_pairs[shard]
            if len(planned) != identity['expected_pairs'] \
                    or pair_set_digest(planned) != identity['expected_pairs_sha256']:
                raise MutationAborted(f'REFUSED: {path} was planned for other pairs')
            if strict:
                validate_worker_resource_evidence(doc, identity)
            with open(path, 'rb') as stream:
                data = stream.read()
            count, digest_bytes = _rows_state(path)
            if (data and not data.endswith(b'\n')) or doc.get('rows') != count \
                    or doc.get('rows_sha256') != digest_bytes:
                raise MutationAborted(f'REFUSED: {path} differs from the rows its sidecar attests')
            rows, pairs = [], set()
            for number, line in enumerate(data.split(b'\n'), 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise MutationAborted(f'REFUSED: {path} line {number} is not JSON') from exc
                pair = (row.get('item_id'), row.get('mutant_id')) if isinstance(row, dict) else None
                if pair is None or _row_identity_problems(row, identity, digest) \
                        or pair not in planned or pair in pairs:
                    raise MutationAborted(
                        f'REFUSED: {path} line {number} is unstamped, unplanned or repeated')
                pairs.add(pair)
                rows.append(row)
            if doc['status'] == 'complete' and pairs != planned:
                raise MutationAborted(f'REFUSED: complete shard {path} is not its planned set')
            statuses.add(doc['status'])
            shards.append((shard, identity, doc, rows, pairs, path))
    shards.sort(key=lambda value: value[0])
    ignored = {'shard', 'expected_pairs', 'expected_pairs_sha256'}
    cores = {json.dumps({k: v for k, v in shard[1].items() if k not in ignored}, sort_keys=True)
             for shard in shards}
    if [shard[0] for shard in shards] != list(range(len(shard_pairs))) \
            or len(shards) != shards[0][1]['of'] or len(cores) != 1 or statuses <= {'complete'}:
        raise MutationAborted('REFUSED: not the exact zero-based shard set of one failed host campaign')
    representative = shards[0][1]
    observation_id = validate_standalone_output_directory(
        [shard[5] for shard in shards], representative)
    return {'identity': representative, 'observation_id': observation_id,
            'rows': [row for shard in shards for row in shard[3]],
            'pairs': set().union(*(shard[4] for shard in shards)),
            'planned': set().union(*shard_pairs),
            'sidecars': [shard[2] for shard in shards],
            'paths': [shard[5] for shard in shards]}


def read_failed_reference_host(observations_root, host, *, manifest, by_mutant,
                               allocation_sha256, parent_plan=None):
    """`read_failed_reference_shards` over one host directory of the parent allocation.

    The shards' own identity names the partition; it must be this host's in
    the parent allocation.  A parent that is itself a supplement is named by
    its frozen plan file `parent_plan`: the identity must carry that plan, and
    the host's slots are of the plan's pending pairs rather than `by_mutant`.
    `facts` is what a supplement plan records of it.
    """
    plan_sha256 = None
    if parent_plan is not None:
        with open(parent_plan, encoding='utf-8') as stream:
            by_mutant = _pairs_by_mutant(reference_supplement_pending(json.load(stream)))
        plan_sha256 = sha256_file(parent_plan)
    first = os.path.join(observations_root, host, 'gold.w0.jsonl')
    try:
        with open(provenance_path(first), encoding='utf-8') as stream:
            identity = json.load(stream)['campaign_identity']
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise MutationAborted(f'REFUSED: cannot read failed host identity {first}: {exc}') from exc
    _validate_campaign_identity(identity)
    partition, workers = identity.get('reference_partition'), identity['of']
    if not partition or partition['host'] != host \
            or partition.get('supplement_plan_sha256') != plan_sha256 \
            or partition['allocation_sha256'] != allocation_sha256:
        raise MutationAborted('REFUSED: failed host identity differs from the parent allocation')
    paths = [os.path.join(observations_root, host, f'gold.w{i}.jsonl') for i in range(workers)]
    loaded = read_failed_reference_shards(
        paths, shard_pairs=reference_shard_pairs(manifest, by_mutant, partition, workers))
    loaded['facts'] = {
        'workers': workers, 'planned_pairs': len(loaded['planned']),
        'durable_pairs': len(loaded['pairs']),
        'shards': [{'path': os.path.abspath(path), 'status': doc['status'], 'rows': doc['rows'],
                    'rows_sha256': doc['rows_sha256'],
                    'provenance_sha256': sha256_file(provenance_path(path))}
                   for path, doc in zip(loaded['paths'], loaded['sidecars'])]}
    return loaded


def reference_supplement_pending(plan):
    """The frozen pending pair set of one supplement plan document."""
    pending = plan.get('pending') if isinstance(plan, dict) else None
    pairs = pending.get('pairs') if isinstance(pending, dict) else None
    if not isinstance(pairs, list) or plan.get('schema') != REFERENCE_SUPPLEMENT_PLAN_SCHEMA \
            or not all(isinstance(pair, list) and len(pair) == 2
                       and all(isinstance(value, str) and value for value in pair) for pair in pairs) \
            or pairs != sorted(pairs):
        raise MutationAborted('REFUSED: invalid full-gold supplement plan')
    result = {tuple(pair) for pair in pairs}
    if not result or len(result) != len(pairs) or pending.get('count') != len(result) \
            or pending.get('sha256') != pair_set_digest(result):
        raise MutationAborted('REFUSED: supplement plan pending pairs differ from their count or digest')
    return result


def load_reference_supplement(plan_path, allocation_path, host):
    """One supplement host's partition, bound to its frozen plan, and the pending pairs by mutant."""
    with open(plan_path, encoding='utf-8') as stream:
        plan = json.load(stream)
    pending = reference_supplement_pending(plan)
    if (plan.get('supplement') or {}).get('allocation', {}).get('sha256') \
            != sha256_file(allocation_path):
        raise MutationAborted('REFUSED: supplement allocation differs from its frozen plan')
    partition, workers = load_reference_partition(allocation_path, host)
    partition['supplement_plan_sha256'] = sha256_file(plan_path)
    slots = plan['supplement'].get('slots', 'mutants')
    if slots not in ('mutants', 'pairs'):
        raise MutationAborted('REFUSED: invalid full-gold supplement slot mode')
    if slots == 'pairs':
        partition['pair_slots'] = True
    return partition, workers, _pairs_by_mutant(pending)


def build_reference_supplement_plan(*, manifest, by_mutant, observations_root,
                                    parent_allocation, failed_hosts, parent_code,
                                    supplement_allocation, supplement_code, parent_plan=None,
                                    pair_slots=False):
    """Freeze the pairs the failed parent hosts did not record. READS ONLY.

    Run on the parent host from its preserved shards.  Every supplement slot
    must receive at least one pending mutant.  `parent_plan` is the frozen
    plan file of a parent that is itself a supplement; the new plan names it.
    """
    failed, pending = {}, set()
    parent_sha256 = sha256_file(parent_allocation)
    for host in sorted(failed_hosts):
        loaded = read_failed_reference_host(observations_root, host, manifest=manifest,
                                            by_mutant=by_mutant, allocation_sha256=parent_sha256,
                                            parent_plan=parent_plan)
        pending |= loaded['planned'] - loaded['pairs']
        failed[host] = loaded['facts']
    if not pending:
        raise MutationAborted('REFUSED: the failed hosts left no pending pair')
    pending_by_mutant = _pairs_by_mutant(pending)
    parent = {'allocation': {'path': os.path.abspath(parent_allocation), 'sha256': parent_sha256},
              'code': dict(parent_code), 'failed_hosts': failed}
    if parent_plan is not None:
        parent['plan'] = {'path': os.path.abspath(parent_plan), 'sha256': sha256_file(parent_plan)}
    with open(supplement_allocation, encoding='utf-8') as stream:
        supplement_hosts = sorted(json.load(stream))
    counts = {}
    for host in supplement_hosts:
        partition, workers = load_reference_partition(supplement_allocation, host)
        if pair_slots:
            partition['pair_slots'] = True
        slots = reference_shard_pairs(manifest, pending_by_mutant, partition, workers)
        if not all(slots):
            raise MutationAborted('REFUSED: a supplement worker would receive no pending mutant')
        counts[host] = sum(map(len, slots))
    return {'schema': REFERENCE_SUPPLEMENT_PLAN_SCHEMA, 'parent': parent,
            'pending': {'count': len(pending), 'sha256': pair_set_digest(pending),
                        'pairs': sorted(list(pair) for pair in pending)},
            'supplement': {'allocation': {'path': os.path.abspath(supplement_allocation),
                                          'sha256': sha256_file(supplement_allocation)},
                           'code': dict(supplement_code), 'host_pairs': counts,
                           **({'slots': 'pairs'} if pair_slots else {})}}


def validate_reference_host_shards(groups, *, manifest, by_mutant):
    """Authenticate every local campaign and the complete disjoint host allocation."""
    rows, identities, seen = [], [], set()
    for host, paths in sorted(groups.items()):
        with open(provenance_path(paths[0]), encoding='utf-8') as stream:
            identity = json.load(stream)['campaign_identity']
        _validate_campaign_identity(identity)
        part = identity.get('reference_partition')
        if not part or part['host'] != host:
            raise MutationAborted('REFUSED: full-gold host directory differs from identity')
        expected = reference_partition_pairs(manifest, by_mutant, part, identity['of'])
        local = validate_native_shards(paths, expected_pairs=expected, required_side='gold')
        if seen.intersection(expected):
            raise MutationAborted('REFUSED: overlapping full-gold host partitions')
        seen.update(expected); rows.extend(local); identities.append(identity)
    all_pairs = {(item, mutant) for mutant, items in by_mutant.items() for item in items}
    validate_reference_host_partition_identities(identities, expected_pairs=all_pairs, observed_pairs=seen)
    return rows


def validate_reference_host_partition_identities(identities, *, expected_pairs, observed_pairs):
    """Shared strict/portable proof of one complete multi-host reference campaign.

    One allocation, or (owner ruling 2026-09-30) the parent allocation and a
    chain of supplement allocations, each naming its own frozen plan in every
    identity.  Each tiles its own slots; the cores may differ only in
    `reference_source_tag`.  The caller orders the chain and proves each
    supplement's pairs are exactly what its parent's failed hosts left unrun.
    """
    if not identities:
        raise MutationAborted('REFUSED: no full-gold host partitions')
    for identity in identities:
        _validate_campaign_identity(identity)
    ignored = {'shard', 'of', 'expected_pairs', 'expected_pairs_sha256',
               'worker_resources_sha256', 'reference_partition'}
    groups = {}
    for x in identities:
        part = x['reference_partition']
        groups.setdefault((part['allocation_sha256'], part['total'], json.dumps(part.get('speeds')),
                           part.get('supplement_plan_sha256')), []).append(x)
    plans = [key[3] for key in groups]
    if plans.count(None) != 1 or len(set(plans)) != len(plans):
        raise MutationAborted('REFUSED: incomplete or mixed full-gold host campaign')
    cores = set()
    for (_allocation, total, _speeds, _plan), members in groups.items():
        slots = sorted((x['reference_partition']['offset'], x['of']) for x in members)
        end = 0
        for offset, count in slots:
            if offset != end:
                raise MutationAborted('REFUSED: missing or overlapping full-gold allocation slots')
            end += count
        group_cores = {json.dumps({k: v for k, v in identity.items() if k not in ignored}, sort_keys=True)
                       for identity in members}
        if len(group_cores) != 1 or end != total:
            raise MutationAborted('REFUSED: incomplete or mixed full-gold host campaign')
        cores.add(json.dumps({k: v for k, v in members[0].items()
                              if k not in ignored | {'reference_source_tag'}}, sort_keys=True))
    if len(cores) != 1 or set(observed_pairs) != set(expected_pairs):
        raise MutationAborted('REFUSED: incomplete or mixed full-gold host campaign')


def selftest() -> int:
    """The apply/revert contract, without a container.

    What is checked is the part that silently corrupts a campaign: that a
    no-op mutation is refused, that a failed restore aborts, and that the
    integrity guard is told about exactly one file and told again when the
    mutant is reverted.
    """
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def _raises_mutation(call):
        try:
            call()
        except MutationAborted:
            return True
        return False

    before_stop = time.monotonic()
    with coordinator_cancellation() as stamped_stop:
        stamped_stop.set()
        requested_at = stamped_stop.operator_requested_at()
        stop_snapshot = stamped_stop.operator_snapshot()
        after_stop = time.monotonic()
    check("the default coordinator cancellation event authenticates its "
          "monotonic source time before publishing the Event flag",
          isinstance(stamped_stop, CoordinatorCancellationEvent)
          and stamped_stop.is_set()
          and isinstance(requested_at, float)
          and stop_snapshot == (requested_at, True)
          and before_stop <= requested_at <= after_stop)

    class _NestedSetDuringPublication(CoordinatorCancellationEvent):
        def __init__(self):
            super().__init__()
            self.publish_calls = 0
            self.injected = False

        def _publish_flag(self):
            self.publish_calls += 1
            if not self.injected:
                self.injected = True
                self.set()
            super()._publish_flag()

    nested_stop = _NestedSetDuringPublication()
    nested_stop.set()
    nested_requested_at = nested_stop.operator_requested_at()
    nested_stop.set()
    check("nested and repeated signal deliveries are one-shot and never "
          "re-enter Event's non-reentrant publication lock",
          nested_stop.injected
          and nested_stop.publish_calls == 1
          and nested_stop.operator_snapshot()
          == (nested_requested_at, True))

    class _FakeRunner:
        def __init__(self, root, mutate=True):
            self.workdir = "/var/www/html"
            self.root = root
            self.mutate = mutate
            self.calls = []

        def run(self, inner, env=None, timeout=900):
            import subprocess
            self.calls.append(inner)
            if '"$JAVA_HOME/bin/javac" -proc:none ' in inner:
                words = shlex.split(inner)
                classes = words[words.index("-d") + 1]
                compiled = os.path.join(self.root, classes, "Mutate.class")
                os.makedirs(os.path.dirname(compiled), exist_ok=True)
                with open(compiled, "wb") as fh:
                    fh.write(b"fake-class-for-command-shape-only")
            if "--apply-file" in inner and self.mutate:
                words = shlex.split(inner)
                rel = words[words.index("--apply-file") + 1]
                p = os.path.join(self.root, rel)
                if inner.startswith("\"$JAVA_HOME/bin/java\" -cp "):
                    with open(p, "rb") as fh:
                        content = fh.read()
                    line = int(words[words.index("--start-line") + 1])
                    col = int(words[words.index("--start-col") + 1])
                    starts = [0]
                    starts.extend(i + 1 for i, byte in enumerate(content)
                                  if byte == 10)
                    at = starts[line - 1] + col - 1
                    old = words[words.index("--original") + 1].encode()
                    new = words[words.index("--mutated") + 1].encode()
                    with open(p, "wb") as fh:
                        fh.write(content[:at] + new
                                 + content[at + len(old):])
                else:
                    with open(p, "a", encoding="utf-8") as fh:
                        fh.write("// mutated\n")
            return subprocess.CompletedProcess([], 0, "", "")

        def prepare_isolated_java_applier(
                self, source_host, classes_host, timeout=300):
            import subprocess
            self.calls.append("isolated-javac " + source_host)
            with open(os.path.join(classes_host, "Mutate.class"), "wb") as fh:
                fh.write(b"fake-isolated-class-for-command-shape-only")
            return subprocess.CompletedProcess([], 0, "", "")

        def run_isolated_java(
                self, inner, *, workspace_host, analysis_host, classes_host,
                analysis_runtime, classes_runtime, timeout=900):
            mapped = inner.replace(analysis_runtime, analysis_host)
            mapped = mapped.replace(classes_runtime, classes_host)
            return self.run(mapped, timeout=timeout)

    class _FakeHarness:
        def __init__(self, root, mutate=True):
            self.root = root
            self.runner = _FakeRunner(root, mutate)
            self.expected_mutations = {}
            self.substrate_baseline_sha256 = "b" * 64
            self._baseline = {}
            src = os.path.join(root, "src")
            if os.path.isdir(src):
                for base, _dirs, names in os.walk(src):
                    for name in names:
                        path = os.path.join(base, name)
                        if os.path.isfile(path):
                            rel_ = os.path.relpath(path, root).replace(os.sep, "/")
                            self._baseline[rel_] = _sha256(path)

        def verify_substrate(self):
            now = {}
            src = os.path.join(self.root, "src")
            if os.path.isdir(src):
                for base, _dirs, names in os.walk(src):
                    for name in names:
                        path = os.path.join(base, name)
                        if os.path.isfile(path):
                            rel_ = os.path.relpath(path, self.root).replace(
                                os.sep, "/")
                            now[rel_] = _sha256(path)
            changed = sorted(rel_ for rel_, digest in now.items()
                             if rel_ in self._baseline
                             and self._baseline[rel_] != digest
                             and self.expected_mutations.get(rel_) != digest)
            return {"baseline": True, "checked": len(now),
                    "changed": changed,
                    "missing": sorted(set(self._baseline) - set(now)),
                    "added": sorted(set(now) - set(self._baseline)),
                    "mutated": sorted(self.expected_mutations)}

        def clear_registration(self):
            pass

    with tempfile.TemporaryDirectory() as root:
        # The old delimiter digest gave these two different field sequences
        # identical bytes.  Structured canonical JSON keeps arbitrary source
        # text and paths unambiguous.
        digest_a = candidate_digest({
            "i": [{"file_path": "a", "code": "b\0c"}]})
        digest_b = candidate_digest({
            "i": [{"file_path": "a\0b", "code": "c"}]})
        check("generated-test identity has no delimiter collision",
              digest_a != digest_b)

        locked_twice = False
        with mutation_resource_locks([("workspace", root)]):
            try:
                with mutation_resource_locks([
                        ("workspace", os.path.join(root, "."))]):
                    pass
            except MutationAborted:
                locked_twice = True
        check("one workspace is a mutex even through another lexical path",
              locked_twice)

        from . import worker as _W
        native_seed = os.path.join(root, "native-seed")
        os.makedirs(native_seed)
        native_workspace_tar = os.path.join(native_seed, "workspace.tar")
        native_database_sql = os.path.join(native_seed, "database.sql")
        with open(native_workspace_tar, "wb") as fh:
            fh.write(b"native mutation workspace seed")
        with open(native_database_sql, "wb") as fh:
            fh.write(b"native mutation database seed")
        workspace_seed_digest = sha256_file(native_workspace_tar)
        database_dump_digest = sha256_file(native_database_sql)
        with open(os.path.join(native_seed, "seed.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({
                "format": 1, "seed_key": "fixture-seed",
                "needs_database": True,
                "workspace": {"digest": workspace_seed_digest},
                "database": {"digest": database_dump_digest},
            }, fh, sort_keys=True)
        native_seed_identity = _W.verified_seed_identity(native_seed, True)
        native_resources = []
        for index in range(2):
            native_spec = _W.WorkerSpec(
                index=index,
                workspace=os.path.join(root, f"native-workspace-{index}"),
                container=f"fixture-worker-{index}",
                schema=f"fixture_schema_{index}",
                credential=f"fixture_user_{index}",
                env_file=os.path.join(root, f"worker{index}.env"))
            native_spec_path = os.path.join(root, f"worker{index}.json")
            with open(native_spec_path, "w", encoding="utf-8") as fh:
                json.dump(native_spec.to_json(), fh, sort_keys=True)
            native_attestation_path = _W.runtime_attestation_path(
                native_spec_path)
            native_attestation = {
                "schema": _W.WORKER_RUNTIME_SCHEMA_V2,
                "worker": native_spec.to_json(),
                "worker_spec_sha256": sha256_file(native_spec_path),
                **native_seed_identity,
                "container_image_digest": "sha256:" + "7" * 64,
                "docker_endpoint_selection": "legacy-default",
                "harness_version": "fixture-harness-v1",
            }
            with open(native_attestation_path, "w", encoding="utf-8") as fh:
                json.dump(native_attestation, fh, sort_keys=True)
            native_resources.append({
                "index": native_spec.index,
                "worker_spec": os.path.realpath(native_spec_path),
                "workspace": os.path.realpath(native_spec.workspace),
                "container": native_spec.container,
                "schema": native_spec.schema,
                "credential": native_spec.credential,
                "env_file": os.path.realpath(native_spec.env_file),
                "workdir": native_spec.workdir,
                "runtime_attestation": os.path.realpath(
                    native_attestation_path),
                "runtime_attestation_sha256": sha256_file(
                    native_attestation_path),
            })

        def native_provenance(of):
            return {"worker_resources": native_resources[:of]}

        rel = "src/CoreShop/Component/Order/Model/Order.php"
        os.makedirs(os.path.join(root, os.path.dirname(rel)))
        with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
            fh.write("<?php\nreturn $a + $b;\n")
        h = _FakeHarness(root)
        m = {"id": "abc0123456789def", "file": rel, "operator": "ArithmeticOperator",
             "start_line": 2, "start_col": 11,
             "end_line": 2, "end_col": 11,
             "original": "+", "mutated": "-"}

        def identity_for(files, pairs, *, engine=ENGINE,
                         engine_version=ENGINE_VERSION, side="candidate",
                         shard=0, of=1, candidate_run_sha256="c" * 64,
                         generation_provenance_class="native_v2",
                         generation_attempt_id="fixture-attempt-1",
                         generation_campaign_digest="0123456789abcdef",
                         generation_agent_runtime_sha256="e" * 64,
                         generation_network_semantics="fixture_closed",
                         generation_condition="c3",
                         generation_protocol_version=4,
                         generation_protocol_digest="bda1d9bcb1852e92",
                         generation_native_budget=None,
                         kind="mutation-run", shard_policy=None,
                         asset_project="fixture",
                         **execution_identity):
            generated = candidate_digest(files)
            return build_campaign_identity(
                generation_provenance_class=generation_provenance_class,
                generation_attempt_id=generation_attempt_id,
                generation_campaign_digest=generation_campaign_digest,
                generation_agent_runtime_sha256=(
                    generation_agent_runtime_sha256),
                generation_network_semantics=generation_network_semantics,
                generation_condition=generation_condition,
                generation_protocol_version=generation_protocol_version,
                generation_protocol_digest=generation_protocol_digest,
                generation_native_budget=generation_native_budget,
                asset_index_sha256="0" * 64, asset_project=asset_project,
                mutation_validation_sha256="9" * 64,
                mutation_validation_class="native",
                manifest_sha256="1" * 64, manifest_digest="a" * 64,
                map_sha256="2" * 64, release_sha256="3" * 64,
                candidate_run_sha256=candidate_run_sha256,
                candidate_generated_tests_sha256=generated,
                gold_baseline_sha256=("d" * 64
                                      if kind == "test-quality" else None),
                gold_generated_tests_sha256=(
                    generated if kind == "test-quality" else None),
                solution_generated_tests_sha256=generated,
                substrate_baseline_sha256="b" * 64,
                worker_resources_sha256=content_digest(native_resources[:of]),
                harness_version="fixture-harness-v1",
                container_image_digest="sha256:" + "7" * 64,
                workspace_seed_digest=workspace_seed_digest,
                database_dump_digest=database_dump_digest,
                applier_sha256=sha256_file(os.path.join(
                    PHP_ENGINE_DIR, PHP_APPLIER.source)),
                expected_pairs=pairs,
                engine=engine, engine_version=engine_version,
                parser="fixture-parser", side=side, shard=shard, of=of,
                timeout=600, kind=kind, shard_policy=shard_policy,
                **execution_identity)

        reference_base = identity_for(
            {"i1": [{"file_path": "a.py", "code": "assert True"}]},
            {("i1", "m1")}, side="gold")
        reference_identity = {
            key: reference_base[key] for key in CAMPAIGN_IDENTITY_FIELDS_V1
        }
        reference_identity.update({
            "schema": MUTATION_IDENTITY_SCHEMA_V5,
            "asset_project": "python-docx",
            "generation_provenance_class":
                GENERATION_PROVENANCE_REFERENCE_CONTROL,
            "reference_control_role": "full-gold",
            "reference_source_tag": "docx-reference-v1",
            "reference_workload_digest": "4" * 64,
        })
        reference_digest = campaign_identity_digest(reference_identity)
        check("DOCX v5 records exactly the six-member reference generation "
              "tuple without v2 attempt/runtime/campaign fields",
              set(reference_identity) == CAMPAIGN_IDENTITY_FIELDS_V5
              and all(key not in reference_identity
                      for key in CAMPAIGN_IDENTITY_FIELDS_V2_ADDED
                      - {"generation_provenance_class"}))
        variants = []
        for key, value in (
                ("reference_control_role", "stub-control"),
                ("candidate_run_sha256", "5" * 64),
                ("reference_source_tag", "docx-reference-v2"),
                ("reference_workload_digest", "6" * 64)):
            variant = dict(reference_identity, **{key: value})
            if key == "reference_control_role":
                variant["side"] = "candidate"
            variants.append(variant)
        generated_variant = dict(
            reference_identity,
            candidate_generated_tests_sha256="7" * 64,
            solution_generated_tests_sha256="7" * 64)
        variants.append(generated_variant)
        check("each mutable reference tuple member changes the campaign "
              "identity while all three reviewed roles validate",
              all(campaign_identity_digest(value) != reference_digest
                  for value in variants)
              and all(campaign_identity_digest(dict(
                  reference_identity,
                  reference_control_role=role,
                  side=("gold" if role == "full-gold" else "candidate")))
                  for role in REFERENCE_CONTROL_ROLES))
        # THE BUDGETED POPULATION BASIS (HEADROOM_SUBSET_AND_BUDGETED_
        # SAMPLE_SPEC.md section 2): a leg's identity binds the derived map
        # AND says it is a budget, drawn by which sidecar, from which parent.
        budgeted_kwargs = {
            "population_basis": BUDGETED_POPULATION_BASIS,
            "budgeted_sample_sha256": "a1" * 32,
            "parent_map_sha256": "b2" * 32,
        }
        budgeted_candidate = identity_for(
            {"i1": [{"file_path": "a.py", "code": "assert True"}]},
            {("i1", "m1")}, **budgeted_kwargs)
        full_candidate = identity_for(
            {"i1": [{"file_path": "a.py", "code": "assert True"}]},
            {("i1", "m1")})
        # Built through the REFERENCE branch, not by hand: S's five
        # reference legs mint their identity there, and the v1 projection
        # that branch takes would drop a basis it was not told to carry.
        budgeted_reference = identity_for(
            {"i1": [{"file_path": "a.py", "code": "assert True"}]},
            {("i1", "m1")}, side="gold",
            generation_provenance_class=(
                GENERATION_PROVENANCE_REFERENCE_CONTROL),
            generation_attempt_id=None, generation_campaign_digest=None,
            generation_agent_runtime_sha256=None,
            generation_network_semantics=None, generation_condition=None,
            generation_protocol_version=None,
            generation_protocol_digest=None,
            reference_control_role="full-gold",
            reference_source_tag="docx-reference-v1",
            reference_workload_digest="4" * 64, **budgeted_kwargs)
        check("a budgeted leg's identity carries the basis, the sidecar and "
              "the parent map beside the derived map's own sha256, on a "
              "candidate leg (v2) and a reference leg (v5) alike -- one "
              "population, two identity versions, the same declaration",
              set(budgeted_candidate)
              == CAMPAIGN_IDENTITY_FIELDS | CAMPAIGN_IDENTITY_BUDGETED_ADDED
              and set(budgeted_reference)
              == CAMPAIGN_IDENTITY_FIELDS_V5
              | CAMPAIGN_IDENTITY_BUDGETED_ADDED
              and _validate_campaign_identity(budgeted_reference) is None
              and campaign_identity_digest(budgeted_candidate)
              != campaign_identity_digest(full_candidate),
              str(sorted(set(budgeted_candidate) - set(full_candidate))))
        check("...and a full-population leg gains no key at all: its "
              "identity is the document it was before a budget existed",
              set(full_candidate) == CAMPAIGN_IDENTITY_FIELDS
              and not set(full_candidate) & CAMPAIGN_IDENTITY_BUDGETED_ADDED
              and campaign_identity_digest(build_campaign_identity(
                  asset_index_sha256="0" * 64, asset_project="fixture",
                  mutation_validation_sha256="9" * 64,
                  mutation_validation_class="native",
                  manifest_sha256="1" * 64, manifest_digest="a" * 64,
                  map_sha256="2" * 64, release_sha256="3" * 64,
                  candidate_run_sha256="c" * 64,
                  candidate_generated_tests_sha256="4" * 64,
                  solution_generated_tests_sha256="4" * 64,
                  substrate_baseline_sha256="b" * 64,
                  applier_sha256="5" * 64,
                  worker_resources_sha256="6" * 64,
                  harness_version="fixture-harness-v1",
                  container_image_digest="sha256:" + "7" * 64,
                  workspace_seed_digest="8" * 64,
                  database_dump_digest="d" * 64,
                  expected_pairs={("i1", "m1")}, engine="r2t-mutate",
                  engine_version="1.0.0", parser="fixture-parser",
                  side="candidate", shard=0, of=1, timeout=600,
                  generation_provenance_class="native_v2",
                  generation_attempt_id="fixture-attempt-1",
                  generation_campaign_digest="0123456789abcdef",
                  generation_agent_runtime_sha256="e" * 64,
                  generation_network_semantics="fixture_closed",
                  generation_condition="c3", generation_protocol_version=4,
                  generation_protocol_digest="bda1d9bcb1852e92"))
              # Computed on the pre-change tree at origin/master 164d673c and
              # pinned here: this is what "unchanged" means for every
              # archived full-population identity.
              == "8245fbdee6d1aac9961ce042c0ec0cd152ad9d3aaf95cc9c0caaee3"
                 "d3a0f26bd")
        def _identity_refusal(identity, contains):
            try:
                _validate_campaign_identity(identity)
            except MutationAborted as exc:
                return contains in str(exc)
            return False

        partial = {key: value for key, value in budgeted_candidate.items()
                   if key != "parent_map_sha256"}
        check("the three travel together: an identity that says it is a "
              "budget without saying from which parent is refused, by name",
              _identity_refusal(partial, "missing=['parent_map_sha256']"))
        check("...and an unknown basis word is refused rather than recorded: "
              "a leg that ran the whole population says so by carrying no "
              "basis at all",
              _identity_refusal(
                  dict(budgeted_candidate, population_basis="sampled"),
                  "population_basis is 'sampled'")
              and _identity_refusal(
                  dict(budgeted_candidate, parent_map_sha256="short"),
                  "invalid parent_map_sha256"))
        malformed = [
            {key: value for key, value in reference_identity.items()
             if key != "reference_control_role"},
            {**reference_identity, "generation_attempt_id": None},
            {**reference_identity, "reference_control_role": "unknown"},
            {**reference_identity, "reference_source_tag": ""},
            {**reference_identity, "reference_workload_digest": "A" * 64},
            {**reference_identity, "generation_provenance_class": "fixture"},
        ]
        check("missing, extra, empty, uppercase, unknown-role, and unknown-"
              "class reference identities all refuse",
              all(_raises_mutation(lambda value=value:
                  campaign_identity_digest(value)) for value in malformed))
        check("role-specific publication admits full gold here but rejects "
              "a stub role and fixture class",
              not _raises_mutation(lambda: validate_publishable_generation(
                  reference_identity, reference_roles={"full-gold"}))
              and _raises_mutation(lambda: validate_publishable_generation(
                  dict(reference_identity, reference_control_role="stub-control",
                       side="candidate"), reference_roles={"full-gold"})))

        generic_reference = dict(
            reference_identity, asset_project="CoreShop",
            reference_source_tag="coreshop-reference-v1")
        check("v5 authenticates the same exact reference roles for any "
              "registered project identity rather than a project allowlist",
              not _raises_mutation(
                  lambda: campaign_identity_digest(generic_reference)))

        # The MINT, not only the shape.  EVERY project's reference legs are
        # bound by what the operator declared on `mutation-run
        # --reference-role` (owner ruling, 2026-09-01), python-docx included:
        # one verified route for all three projects is the point of the door.
        # The reviewed DOCX wrapper is still a route for its own recorded
        # phases, and while its capability is ACTIVE it still pins the exact
        # six-member tuple -- which the second check below holds it to.
        def mint_reference(role, project, **members):
            return identity_for(
                {"i1": [{"file_path": "a.py", "code": "assert True"}]},
                {("i1", "m1")}, asset_project=project,
                side=("gold" if role == "full-gold" else "candidate"),
                generation_provenance_class=(
                    GENERATION_PROVENANCE_REFERENCE_CONTROL),
                generation_attempt_id=None, generation_campaign_digest=None,
                generation_agent_runtime_sha256=None,
                generation_network_semantics=None,
                generation_condition=None, generation_protocol_version=None,
                generation_protocol_digest=None,
                **{"reference_control_role": role,
                   "reference_source_tag": "fixture-reference-v1",
                   "reference_workload_digest": "4" * 64,
                   **members})

        roles = sorted(REFERENCE_CONTROL_ROLES)
        projects = ("fixture", "CoreShop", "python-docx")
        minted = {project: [mint_reference(role, project) for role in roles]
                  for project in projects}
        check("every project mints every reviewed reference role through the "
              "one operator door, and each leg is a distinct v5 identity",
              all([leg["reference_control_role"] for leg in legs] == roles
                  and all(set(leg) == CAMPAIGN_IDENTITY_FIELDS_V5
                          for leg in legs)
                  for legs in minted.values())
              and len({campaign_identity_digest(leg)
                       for legs in minted.values() for leg in legs})
              == len(roles) * len(projects))

        from ..toolkit import docx_v2_workload as _DW

        docx_generated = candidate_digest(
            {"i1": [{"file_path": "a.py", "code": "assert True"}]})

        def wrapper_phase(role):
            """Activate one reviewed DOCX reference phase for *role*."""
            capability = _DW._EvidenceCapability(
                "4" * 64, (), "sha256:" + "7" * 64, "full-gold-a", "9" * 32,
                {"class": GENERATION_PROVENANCE_REFERENCE_CONTROL,
                 "role": role, "generated_tests_sha256": docx_generated},
                {"sha256": "c" * 64}, "fixture-reference-v1")
            capability.current_action = "mutation-run"
            return _DW._activate(capability)

        with wrapper_phase("full-gold"):
            wrapper_exact = (
                mint_reference("full-gold", "python-docx")[
                    "reference_control_role"] == "full-gold"
                and all(_raises_mutation(
                    lambda role=role: mint_reference(role, "python-docx"))
                    for role in roles if role != "full-gold")
                and _raises_mutation(lambda: mint_reference(
                    "full-gold", "python-docx",
                    reference_source_tag="other-reference-v1")))
        check("the wrapper's recorded phases are unaffected: inside its "
              "active capability a mint is still held to that workload's "
              "exact six-member tuple, which is keyed on the capability "
              "rather than on the project name",
              wrapper_exact and not _DW.has_active_capability())

        # The operator door on the CLI verb.  Everything below refuses on the
        # argv alone -- before an asset is opened, let alone a worker
        # contacted -- because the alternative for CoreShop's 49,168-pair
        # reference sweep is the same refusal hours later.
        import types

        from . import cli as _cli

        def door_refuses(build, expected):
            # The expected fragment, not merely "REFUSED": every one of these
            # argv would also be refused by the capability gate above if the
            # door stopped opening, and that refusal would look identical.
            try:
                _cli.cmd_mutation_run(build())
            except SystemExit as exc:
                return expected in str(exc)
            return False

        def door_args(**overrides):
            values = {
                "reference_role": "full-gold", "reference_source_tag": "t1",
                "side": "gold", "sample": None,
                "sample_seed": _cli.MUTATION_SAMPLE_SEED_DEFAULT,
                "mutant_limit": None, "pair_plan": None,
            }
            values.update(overrides)
            return types.SimpleNamespace(**values)

        check("the reference door refuses a role/side disagreement and a "
              "source tag that is not one non-empty, space-free tag",
              door_refuses(lambda: door_args(side="candidate"),
                           "full-gold is collected with --side gold")
              and door_refuses(
                  lambda: door_args(reference_role="stub-control",
                                    side="gold"),
                  "stub-control is collected with --side candidate")
              and all(door_refuses(
                  lambda tag=tag: door_args(reference_source_tag=tag),
                  "requires --reference-source-tag")
                  for tag in (None, "", "coreshop reference v1",
                              "coreshop-reference-v1\n")))
        check("the reference door refuses every partial-population option, "
              "because a reference observation is the whole population",
              all(door_refuses(lambda override=override: door_args(**override),
                               option)
                  for option, override in (
                      ("--sample", {"sample": 10}),
                      ("--sample-seed", {"sample_seed": 7}),
                      ("--mutant-limit", {"mutant_limit": 5}),
                      ("--pair-plan", {"pair_plan": "plan.json"}))))
        check("`mutation-run` with no reference role and no reviewed "
              "workload capability stays closed",
              door_refuses(lambda: types.SimpleNamespace(),
                           "no reviewed complete-pre-execution"))

        # THE DECLARED ROLE AGAINST THE HARNESS'S OWN STAMP.  A declaration
        # nothing can contradict is two words the operator typed, and a pair
        # of full-gold legs is admissible as the release gold kill set --
        # so every row has to agree with the leg it is claimed to be.
        from .fixtures import FIXTURES as _fixtures

        released = ("i1", "i2", "i3")

        def reference_rows(adapter, item_ids=released, stamped=True):
            return [dict(
                {"item_id": item_id,
                 "produced_files": [{"file_path": f"{item_id}.py",
                                     "code": "assert True"}]},
                **({"adapter": adapter} if stamped else {}))
                for item_id in item_ids]

        def reference_evidence(role, adapter, item_ids=released, stamped=True):
            return reference_generation_evidence(
                role=role, source_tag="fixture-reference-v1",
                candidate_rows=reference_rows(adapter, item_ids, stamped),
                release_item_ids=released, release_sha256="a" * 64,
                asset_index_sha256="b" * 64)

        check("every reference role maps to an adapter the runner can "
              "actually stamp a row with",
              all(name in _fixtures
                  for name in REFERENCE_CONTROL_ROLE_ADAPTERS.values()))
        check("each reference role accepts exactly the adapter stamp its "
              "control writes, and refuses every other stamp",
              all(reference_evidence(role, adapter)["reference_control_role"]
                  == role
                  for role, adapter in REFERENCE_CONTROL_ROLE_ADAPTERS.items())
              and all(_raises_mutation(
                  lambda role=role, other=other:
                  reference_evidence(role, other))
                  for role, adapter
                  in REFERENCE_CONTROL_ROLE_ADAPTERS.items()
                  for other in REFERENCE_CONTROL_ROLE_ADAPTERS.values()
                  if other != adapter))
        check("a candidate whose rows carry no adapter stamp at all cannot "
              "declare which control it is",
              all(_raises_mutation(
                  lambda role=role, adapter=adapter: reference_evidence(
                      role, adapter, stamped=False))
                  for role, adapter
                  in REFERENCE_CONTROL_ROLE_ADAPTERS.items()))
        check("a reference observation that is short of, or wider than, the "
              "release item set refuses and says how many are missing",
              _raises_mutation(
                  lambda: reference_evidence("full-gold", "gold",
                                             item_ids=("i1", "i2")))
              and _raises_mutation(
                  lambda: reference_evidence("full-gold", "gold",
                                             item_ids=(*released, "i9"))))

        # THE DOOR END TO END FOR python-docx, the project this route used to
        # refuse by name.  Nothing verifies its legs differently: both facts
        # above are read off the candidate's own rows and the release, and
        # `reference_generation_evidence` has no project argument to branch
        # on -- so the members it returns mint that project's leg like any
        # other, and a leg that fails either fact never reaches a mint.
        def docx_door_leg(role, adapter, **rows):
            members = dict(reference_evidence(role, adapter, **rows))
            members.pop("generation_provenance_class")
            return mint_reference(role, "python-docx", **members)

        check("python-docx legs mint from the same verified members as every "
              "other project's, while a row stamped as another control, an "
              "unstamped candidate, and a population short of the release "
              "each refuse before any identity exists",
              [docx_door_leg(role, adapter)["reference_control_role"]
               for role, adapter
               in sorted(REFERENCE_CONTROL_ROLE_ADAPTERS.items())]
              == sorted(REFERENCE_CONTROL_ROLE_ADAPTERS)
              and all(_raises_mutation(
                  lambda role=role: docx_door_leg(role, "stub"))
                  for role in ("full-gold", "assertion-stripped-gold"))
              and _raises_mutation(
                  lambda: docx_door_leg("full-gold", "gold", stamped=False))
              and _raises_mutation(
                  lambda: docx_door_leg("full-gold", "gold",
                                        item_ids=("i1", "i2"))))

        # MEMBER 6 BINDS THE RECIPE, NOT THE BYTES.  Digesting the
        # generated-test map would make it a byte-for-byte copy of member 4,
        # and comparing a value with itself proves nothing.
        gold_evidence = reference_evidence("full-gold", "gold")
        check("reference_workload_digest is independent of the candidate "
              "bytes: it differs from the same rows' generated-test digest, "
              "is equal for two legs of one role over one population, and "
              "differs across the three roles",
              gold_evidence["reference_workload_digest"] != candidate_digest(
                  {row["item_id"]: row["produced_files"]
                   for row in reference_rows("gold")})
              and reference_evidence("full-gold", "gold")[
                  "reference_workload_digest"]
              == gold_evidence["reference_workload_digest"]
              and len({reference_evidence(role, adapter)[
                  "reference_workload_digest"]
                  for role, adapter
                  in REFERENCE_CONTROL_ROLE_ADAPTERS.items()})
              == len(REFERENCE_CONTROL_ROLE_ADAPTERS))
        check("reference_workload_digest changes with the population it "
              "names -- the release document and the registered asset index",
              len({reference_generation_evidence(
                  role="full-gold", source_tag="fixture-reference-v1",
                  candidate_rows=reference_rows("gold"),
                  release_item_ids=released,
                  release_sha256=release, asset_index_sha256=index)[
                      "reference_workload_digest"]
                  for release, index in (("a" * 64, "b" * 64),
                                         ("c" * 64, "b" * 64),
                                         ("a" * 64, "d" * 64))}) == 3)

        # Completed v1 worker evidence predates endpoint selection.  Its
        # resource record and attestation bytes are still hash-authenticated
        # post-hoc evidence, but adding the v2 field under the v1 schema must
        # never turn it into a rootless claim.
        legacy_resources = []
        legacy_documents = []
        for index, resource in enumerate(native_resources):
            with open(resource["runtime_attestation"], encoding="utf-8") as fh:
                legacy = json.load(fh)
            legacy["schema"] = _W.WORKER_RUNTIME_SCHEMA_V1
            legacy.pop("docker_endpoint_selection")
            legacy_path = os.path.join(root, f"legacy-worker{index}.runtime.json")
            with open(legacy_path, "w", encoding="utf-8") as fh:
                json.dump(legacy, fh, sort_keys=True)
            legacy_documents.append(legacy)
            legacy_resources.append({
                **resource,
                "runtime_attestation": os.path.realpath(legacy_path),
                "runtime_attestation_sha256": sha256_file(legacy_path),
            })
        legacy_identity = identity_for(
            {"i1": [{"file_path": "a", "code": "one"}]},
            {("i1", "m1")}, of=2)
        legacy_identity["worker_resources_sha256"] = content_digest(
            legacy_resources)
        try:
            legacy_read = validate_worker_resource_evidence(
                {"worker_resources": legacy_resources}, legacy_identity)
            legacy_accepted = len(legacy_read) == 2
        except MutationAborted:
            legacy_accepted = False
        forged_path = os.path.join(root, "legacy-worker0.relabelled.json")
        with open(forged_path, "w", encoding="utf-8") as fh:
            json.dump({**legacy_documents[0],
                       "docker_endpoint_selection": "legacy-default"},
                      fh, sort_keys=True)
        relabelled_resources = [dict(row) for row in legacy_resources]
        relabelled_resources[0].update({
            "runtime_attestation": os.path.realpath(forged_path),
            "runtime_attestation_sha256": sha256_file(forged_path),
        })
        relabelled_identity = dict(legacy_identity)
        relabelled_identity["worker_resources_sha256"] = content_digest(
            relabelled_resources)
        try:
            validate_worker_resource_evidence(
                {"worker_resources": relabelled_resources},
                relabelled_identity)
            relabelled_refused = False
        except MutationAborted:
            relabelled_refused = True
        check("authenticated completed worker-runtime/v1 evidence remains "
              "readable post-hoc but cannot be relabelled as rootless v2",
              legacy_accepted and relabelled_refused)

        def stamped_row(identity_, item_id, mutant_id, **extra):
            return {
                "item_id": item_id, "mutant_id": mutant_id,
                "outcome": "passed",
                **row_identity_stamp(identity_),
                **extra,
            }

        def attest(path, identity_, status, **kw):
            """Put a fixture shard into `status` along a LEGAL lifecycle path.

            Every state a fixture needs is reachable the way a real campaign
            reaches it — absent -> running -> terminal — so the fixtures go
            that way.  `write_shard_provenance` refuses anything else now
            (`SHARD_TRANSITIONS`), and a fixture that could bypass the table
            would be exercising a writer this module does not have.

            A fixture that needs to REPLACE an already-terminal shard removes
            its sidecar first and comes back through here, which is the
            on-disk equivalent of the new campaign directory the real
            recovery path requires.
            """
            if recorded_shard_status(path, identity_) != "running":
                write_shard_provenance(path, identity_, "running", **kw)
            return write_shard_provenance(path, identity_, status, **kw)

        v4_identity = identity_for(
            {"i1": [{"file_path": "a", "code": "one"}]},
            {("i1", "m1")}, kind="test-quality",
            shard_policy="r2t.balanced-pairs-lpt/1",
            execution_policy=EXECUTION_POLICY_SCALAR_V1,
            compute_cap_sha256="8" * 64,
            estimand_pairs_sha256="6" * 64,
            observation_id="7" * 32)

        def malformed_v4_refuses(field, value):
            malformed = {**v4_identity, field: value}
            try:
                _validate_campaign_identity(malformed)
            except MutationAborted:
                return True
            except (TypeError, AttributeError):
                return False
            return False

        check("v4 policy fields with unhashable values are controlled "
              "refusals, never TypeError escapes",
              malformed_v4_refuses("shard_policy", [])
              and malformed_v4_refuses("execution_policy", {})
              and malformed_v4_refuses("preflight_cache_policy", []))
        check("v4 requires the authoritative root-minted observation id",
              malformed_v4_refuses("observation_id", "not-an-observation"))

        v4_policy_dir = os.path.join(root, "v4-policy-sidecar")
        os.makedirs(v4_policy_dir)
        v4_policy_path = os.path.join(v4_policy_dir, "candidate.w0.jsonl")
        with open(v4_policy_path, "w", encoding="utf-8") as fh:
            fh.write("")
        write_shard_provenance(
            v4_policy_path, v4_identity, "running",
            provenance={"shard_policy": "r2t.balanced-pairs-lpt/1"})
        v4_policy_sidecar = provenance_path(v4_policy_path)
        with open(v4_policy_sidecar, encoding="utf-8") as fh:
            relabelled_v4 = json.load(fh)
        relabelled_v4["shard_policy"] = "r2t.strided-mutants/1"
        atomic_write_json(v4_policy_sidecar, relabelled_v4)
        try:
            recorded_shard_status(v4_policy_path, v4_identity)
            v4_policy_refused = False
        except MutationAborted as exc:
            v4_policy_refused = "shard_policy" in str(exc)
        check("v4 shard transitions enforce the identity-bound scheduling "
              "policy just as v3 transitions do", v4_policy_refused)

        merge_files = {
            "i1": [{"file_path": "a", "code": "one"}],
            "i2": [{"file_path": "b", "code": "two"}],
        }
        # Hold native sibling writes just before atomic replacement: this
        # is the supported K-way startup that exposed unplanned stages in
        # the real Python reference collection. No timing race is needed.
        from concurrent.futures import ThreadPoolExecutor
        from unittest.mock import patch

        concurrent_dir = os.path.join(root, "concurrent-startup")
        concurrent_paths = [os.path.join(
            concurrent_dir, f"candidate.w{shard}.jsonl") for shard in range(3)]
        concurrent_ids = [identity_for(merge_files, set(), shard=shard, of=3)
                          for shard in range(3)]
        observation = prepare_standalone_output_directory(
            concurrent_paths[0], concurrent_ids[0])
        prepare_standalone_output_directory(
            concurrent_paths[1], concurrent_ids[1])
        atomic_write_bytes(concurrent_paths[0], b"", refuse_existing=True)
        staged_ready = threading.Barrier(3, timeout=10)
        finish_writes = threading.Event()
        real_replace = os.replace
        held_destinations = {provenance_path(concurrent_paths[0]),
                             concurrent_paths[1]}

        def pause_sibling_replace(source, destination):
            if destination in held_destinations:
                staged_ready.wait()
                if not finish_writes.wait(10):
                    raise RuntimeError("sibling atomic write was not released")
            return real_replace(source, destination)

        with patch.object(os, "replace", side_effect=pause_sibling_replace), \
                ThreadPoolExecutor(max_workers=2) as writers:
            futures = [writers.submit(
                write_shard_provenance, concurrent_paths[0], concurrent_ids[0],
                "running", provenance=native_provenance(3)),
                writers.submit(atomic_write_bytes, concurrent_paths[1], b"",
                               refuse_existing=True)]
            try:
                staged_ready.wait()
                stages = [name for name in os.listdir(concurrent_dir)
                          if name.startswith(".r2t-stage-")]
                try:
                    joined = prepare_standalone_output_directory(
                        concurrent_paths[2], concurrent_ids[2])
                    join_error = ""
                except MutationAborted as exc:
                    joined, join_error = None, str(exc)
                check("a new shard joins the same observation while sibling "
                      "native row and provenance writes are staged",
                      len(stages) == 2 and joined == observation, join_error)
                for unexpected_name in (
                        "historical-partial.jsonl", ".r2t-stage-unplanned",
                        ".r2t-stage-candidate.w9.jsonl-unplanned"):
                    unexpected_path = os.path.join(concurrent_dir,
                                                   unexpected_name)
                    with open(unexpected_path, "w", encoding="utf-8") as fh:
                        fh.write("unplanned bytes\n")
                    try:
                        check("concurrent startup still refuses "
                              + unexpected_name,
                              _raises_mutation(lambda:
                                  prepare_standalone_output_directory(
                                      concurrent_paths[2], concurrent_ids[2])))
                    finally:
                        os.unlink(unexpected_path)
            finally:
                finish_writes.set()
            for future in futures:
                future.result(timeout=10)
        atomic_write_bytes(concurrent_paths[2], b"", refuse_existing=True)
        for path, identity in zip(concurrent_paths, concurrent_ids):
            attest(path, identity, "complete", provenance=native_provenance(3))
        check("concurrent atomic writers leave exactly the completed planned "
              "payload and one observation identity",
              validate_standalone_output_directory(
                  concurrent_paths, concurrent_ids[0]) == observation)
        # Sibling shards started in the same instant: the second waits out the
        # first one's claim instead of refusing, then joins its plan.
        race_dir = os.path.join(root, "claim-race")
        race_paths = [os.path.join(race_dir, f"candidate.w{shard}.jsonl")
                      for shard in range(2)]
        race_ids = [identity_for(merge_files, set(), shard=shard, of=2)
                    for shard in range(2)]
        with ThreadPoolExecutor(max_workers=2) as claimants:
            with mutation_resource_locks([("output", race_dir)]):
                claims = [claimants.submit(prepare_standalone_output_directory,
                                           path, identity)
                          for path, identity in zip(race_paths, race_ids)]
                time.sleep(0.3)
                both_waited = not any(claim.done() for claim in claims)
            race_observations = [claim.result(timeout=30) for claim in claims]
        check("sibling shards racing for one output directory both claim it: "
              "one writes the plan, the other waits and joins it",
              both_waited and race_observations[0] == race_observations[1]
              and sorted(os.listdir(race_dir)) == [MUTATION_OUTPUT_PLAN])
        race_plan = open(os.path.join(race_dir, MUTATION_OUTPUT_PLAN),
                         "rb").read()
        other_files = {"i1": [{"file_path": "a", "code": "another candidate"}]}
        other_id = identity_for(other_files, set(), shard=1, of=2)
        check("a different campaign still cannot take the claimed directory",
              _raises_mutation(lambda: prepare_standalone_output_directory(
                  race_paths[1], other_id))
              and sorted(os.listdir(race_dir)) == [MUTATION_OUTPUT_PLAN]
              and open(os.path.join(race_dir, MUTATION_OUTPUT_PLAN),
                       "rb").read() == race_plan)
        started_wait = time.monotonic()
        with mutation_resource_locks([("output", race_dir)]), \
                patch(__name__ + ".OUTPUT_CLAIM_WAIT_SECONDS", 0.2):
            held_claim = _raises_mutation(lambda: prepare_standalone_output_directory(
                race_paths[1], race_ids[1]))
        waited = time.monotonic() - started_wait
        started_other = time.monotonic()
        with mutation_resource_locks([("workspace", race_dir)]):
            other_lock = _raises_mutation(lambda: mutation_resource_locks(
                [("workspace", race_dir)]).__enter__())
        check("the claim wait is bounded; every other resource lock still "
              "refuses at once",
              held_claim and 0.2 <= waited < 5 and other_lock
              and time.monotonic() - started_other < 1)
        leftover_stage = os.path.join(concurrent_dir, stages[0])
        with open(leftover_stage, "w", encoding="utf-8") as fh:
            fh.write("interrupted native stage\n")
        check("completed campaign admission still refuses a leftover native "
              "stage for a planned artifact",
              _raises_mutation(lambda: validate_standalone_output_directory(
                  concurrent_paths, concurrent_ids[0])))
        os.unlink(leftover_stage)

        merge_dir = os.path.join(root, "native-candidate")
        merge_paths = []
        merge_identities = []
        for shard, pair in enumerate((("i1", "m1"), ("i2", "m2"))):
            path = os.path.join(merge_dir, f"candidate.w{shard}.jsonl")
            identity = identity_for(merge_files, {pair}, shard=shard, of=2)
            prepare_standalone_output_directory(path, identity)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(stamped_row(
                    identity, pair[0], pair[1])) + "\n")
            attest(path, identity, "complete",
                   provenance=native_provenance(identity["of"]))
            merge_paths.append(path)
            merge_identities.append(identity)
        check("native shard merge validates complete identities and an exact "
              "disjoint pair union",
              len(validate_native_shards(
                  merge_paths,
                  expected_pairs={("i1", "m1"), ("i2", "m2")})) == 2)
        from . import seed as _seed
        with patch.object(_seed, "verify_seed", wraps=_seed.verify_seed) as verify:
            candidate_campaign = validate_native_shards(
                merge_paths, required_side="candidate", return_campaign=True)
            first_reads = verify.call_count
            repeated_campaign = validate_native_shards(
                merge_paths, required_side="candidate", return_campaign=True)
            check("native shard assembly hashes a shared seed once per "
                  "invocation, with identical merged evidence",
                  first_reads == 1 and verify.call_count == 2
                  and candidate_campaign == repeated_campaign
                  and _W._seed_verifications.get() is None)

        # Reuse must not turn a file change between sibling shards into a
        # passing observation, nor retain a result after that failed read.
        original_resource_reader = validate_worker_resource_evidence
        with open(native_workspace_tar, "rb") as fh:
            saved_seed_bytes = fh.read()
        resource_reads = 0

        def change_seed_after_first_shard(sidecar, identity):
            nonlocal resource_reads
            result = original_resource_reader(sidecar, identity)
            resource_reads += 1
            if resource_reads == 1:
                with open(native_workspace_tar, "ab") as fh:
                    fh.write(b"changed between shard reads")
            return result

        try:
            with patch(__name__ + ".validate_worker_resource_evidence",
                       side_effect=change_seed_after_first_shard):
                check("native assembly refuses a seed changed between "
                      "shards and drops its reuse scope on failure",
                      _raises_mutation(lambda: validate_native_shards(merge_paths))
                      and _W._seed_verifications.get() is None)
        finally:
            with open(native_workspace_tar, "wb") as fh:
                fh.write(saved_seed_bytes)
        with patch.object(_seed, "verify_seed", wraps=_seed.verify_seed) as verify:
            check("a new assembly after failure authenticates the restored "
                  "seed again",
                  validate_native_shards(merge_paths, required_side="candidate",
                      return_campaign=True) == candidate_campaign
                  and verify.call_count == 1)
        first_sidecar_path = provenance_path(merge_paths[0])
        with open(first_sidecar_path, encoding="utf-8") as fh:
            first_sidecar = json.load(fh)
        missing_preimage = dict(first_sidecar)
        missing_preimage.pop("worker_resources")
        atomic_write_json(first_sidecar_path, missing_preimage)
        try:
            validate_native_shards(merge_paths)
            missing_worker_preimage_refused = False
        except MutationAborted as e:
            missing_worker_preimage_refused = (
                "worker_resources preimage" in str(e))
        # Restored as BYTES, not as a transition: this fixture edited a
        # complete sidecar behind the writer's back, and `complete` is
        # terminal, so putting the exact saved document back is the only
        # honest undo.
        atomic_write_json(first_sidecar_path, first_sidecar)
        check("native shard merge refuses a missing worker-resource digest "
              "preimage", missing_worker_preimage_refused)
        unexpected_path = os.path.join(merge_dir, "historical-partial.jsonl")
        with open(unexpected_path, "w", encoding="utf-8") as fh:
            fh.write("preserved historical bytes\n")
        try:
            validate_native_shards(merge_paths)
            unexpected_output_refused = False
        except MutationAborted as e:
            unexpected_output_refused = "unexpected" in str(e)
        os.remove(unexpected_path)
        check("native shard merge refuses unrelated historical artifacts in "
              "its campaign directory", unexpected_output_refused)
        dirty_dir = os.path.join(root, "historical-cell3")
        os.makedirs(dirty_dir)
        with open(os.path.join(dirty_dir, "old-19-of-32.jsonl"), "w",
                  encoding="utf-8") as fh:
            fh.write("historical\n")
        try:
            prepare_standalone_output_directory(
                os.path.join(dirty_dir, "candidate.w0.jsonl"),
                identity_for(merge_files, {("i1", "m1")}))
            dirty_output_refused = False
        except MutationAborted as e:
            dirty_output_refused = "new empty directory" in str(e)
        check("standalone mutation execution refuses a fresh shard beside "
              "historical partial output", dirty_output_refused)
        gold_dir = os.path.join(root, "native-gold")
        gold_paths = []
        for shard, pair in enumerate((("i1", "m1"), ("i2", "m2"))):
            path = os.path.join(gold_dir, f"gold.w{shard}.jsonl")
            identity = identity_for(
                {"i1": [{"file_path": "gold-a", "code": "one"}],
                 "i2": [{"file_path": "gold-b", "code": "two"}]},
                {pair}, side="gold", shard=shard, of=2,
                candidate_run_sha256="4" * 64)
            prepare_standalone_output_directory(path, identity)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(stamped_row(
                    identity, pair[0], pair[1])) + "\n")
            attest(path, identity, "complete",
                   provenance=native_provenance(identity["of"]))
            gold_paths.append(path)
        gold_campaign = validate_native_shards(
            gold_paths, required_side="gold", return_campaign=True)
        candidate_gold_ok = True
        try:
            validate_candidate_gold_campaign_pair(
                candidate_campaign["campaign_identity"],
                gold_campaign["campaign_identity"])
        except MutationAborted:
            candidate_gold_ok = False
        check("native comparison accepts an explicit candidate/gold pair "
              "with one population and runtime", candidate_gold_ok)
        try:
            validate_candidate_gold_campaign_pair(
                candidate_campaign["campaign_identity"],
                candidate_campaign["campaign_identity"])
            duplicate_role_refused = False
        except MutationAborted as e:
            duplicate_role_refused = "explicit candidate and gold" in str(e)
        check("native comparison refuses two campaigns both stamped as the "
              "candidate role", duplicate_role_refused)

        validation_path = os.path.join(root, "asset-validation.json")
        manifest_path = os.path.join(root, "asset-manifest.json")
        map_path = os.path.join(root, "asset-map.json")
        release_path = os.path.join(root, "asset-release.jsonl")
        for path, body in (
                (validation_path, "validated"),
                (manifest_path, '{"population":"full"}'),
                (map_path, '{"pairs":"full"}'),
                (release_path, '{"item_id":"i1"}\n')):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
        asset_manifest = {
            "digest": "d" * 64,
            "engine": candidate_campaign["campaign_identity"]["engine"],
            "engine_version": candidate_campaign[
                "campaign_identity"]["engine_version"],
            "parser": candidate_campaign["campaign_identity"]["parser"],
            "mutants": [{
                "id": "m1",
                "file": "src/CoreShop/Component/Foo.php",
                "operator": "fixture",
                "start_line": 1,
            }],
        }
        assets = {
            "asset_index_sha256": "e" * 64,
            "asset_project": "fixture",
            "validation_class": "native",
            "manifest": asset_manifest,
        }
        asset_identity = dict(candidate_campaign["campaign_identity"],
            asset_index_sha256=assets["asset_index_sha256"],
            asset_project=assets["asset_project"],
            mutation_validation_sha256=sha256_file(validation_path),
            mutation_validation_class="native",
            manifest_sha256=sha256_file(manifest_path),
            manifest_digest=asset_manifest["digest"],
            map_sha256=sha256_file(map_path),
            release_sha256=sha256_file(release_path))
        validate_campaign_asset_claims(
            asset_identity, assets, validation_path=validation_path,
            manifest_path=manifest_path, map_path=map_path,
            release_path=release_path)
        with open(manifest_path, "w", encoding="utf-8") as fh:
            fh.write('{"population":"pilot-subset"}')
        try:
            validate_campaign_asset_claims(
                asset_identity, assets, validation_path=validation_path,
                manifest_path=manifest_path, map_path=map_path,
                release_path=release_path)
            subset_assets_refused = False
        except MutationAborted as e:
            subset_assets_refused = "manifest_sha256" in str(e)
        check("native completeness cannot relabel a pilot with a subset "
              "manifest", subset_assets_refused)

        # Drive the public recall assembly over independently attested role
        # shards.  Mutation execution itself is exercised below; this check
        # owns the join between candidate/gold roles, frozen assets and the
        # reconstructed complete denominator.
        import io
        import types
        from contextlib import redirect_stdout
        from . import cli as _cli
        from ..data import mutation_attestation as _attestation

        candidate_baseline = os.path.join(root, "candidate-baseline.jsonl")
        gold_baseline = os.path.join(root, "gold-baseline.jsonl")
        with open(candidate_baseline, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "item_id": "i1", "outcome": "passed",
                "produced_files": [{
                    "file_path": "candidate.php", "code": "<?php"}],
            }) + "\n")
        with open(gold_baseline, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "item_id": "i1", "outcome": "passed",
                "produced_files": [{
                    "file_path": "gold.php", "code": "<?php"}],
            }) + "\n")
        # Restore the full-catalogue bytes after the deliberate subset
        # tamper above.  The validated object is what the PR-2 validator
        # would have parsed from these bytes in production.
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(asset_manifest, fh, sort_keys=True)
        with open(map_path, "w", encoding="utf-8") as fh:
            json.dump({"by_mutant": {"m1": ["i1"]}}, fh,
                      sort_keys=True)
        with open(release_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i1"}) + "\n")
        native_assets = {
            **assets,
            "manifest": asset_manifest,
            "map": {"by_mutant": {"m1": ["i1"]}},
        }
        common_claims = {
            "asset_index_sha256": native_assets["asset_index_sha256"],
            "asset_project": native_assets["asset_project"],
            "mutation_validation_sha256": sha256_file(validation_path),
            "mutation_validation_class": "native",
            "manifest_sha256": sha256_file(manifest_path),
            "manifest_digest": asset_manifest["digest"],
            "map_sha256": sha256_file(map_path),
            "release_sha256": sha256_file(release_path),
        }
        candidate_id = dict(identity_for(
            {"i1": [{"file_path": "candidate.php", "code": "<?php"}]},
            {("i1", "m1")}, candidate_run_sha256=sha256_file(
                candidate_baseline)), **common_claims)
        gold_id = dict(identity_for(
            {"i1": [{"file_path": "gold.php", "code": "<?php"}]},
            {("i1", "m1")}, side="gold",
            candidate_run_sha256=sha256_file(gold_baseline)),
            **common_claims)
        candidate_result = os.path.join(
            root, "recall-candidate", "candidate.w0.jsonl")
        gold_result = os.path.join(root, "recall-gold", "gold.w0.jsonl")
        for path, identity, outcome in (
                (candidate_result, candidate_id, "passed"),
                (gold_result, gold_id, "failed")):
            prepare_standalone_output_directory(path, identity)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(stamped_row(
                    identity, "i1", "m1",
                    file="src/CoreShop/Component/Foo.php",
                    outcome=outcome)) + "\n")
            attest(path, identity, "complete",
                   provenance=native_provenance(identity["of"]))
        recall_args = types.SimpleNamespace(
            baseline=candidate_baseline, results=[candidate_result],
            gold_results=[gold_result], legacy_consistency=None,
            require_complete=True, mutation_validation=validation_path,
            manifest=manifest_path, map=map_path, release=release_path,
            sample=None, sample_seed=20260731,
            gold_baseline=gold_baseline, boundary="unused", repo=root)
        real_assets_validator = _attestation.validate_campaign_asset_inputs
        real_boundary = _cli._boundary
        try:
            _attestation.validate_campaign_asset_inputs = (
                lambda *a, **kw: native_assets)
            _cli._boundary = lambda _args: types.SimpleNamespace(
                classify=lambda _path: "production")
            with redirect_stdout(io.StringIO()):
                native_recall_rc = _cli.cmd_recall(recall_args)
            # Harness 25 (D): the verb drops a listed mutant's pairs from
            # G_i, the candidate's rows and the completeness expectation.
            from unittest import mock as _mock
            listed_recall = {}
            for listed in (frozenset(), frozenset({"m1"})):
                printed = io.StringIO()
                with _mock.patch("r2t.data.mutation.nondeterministic_mutants",
                                 lambda listed=listed: listed), \
                        redirect_stdout(printed):
                    _cli.cmd_recall(recall_args)
                text = printed.getvalue()
                listed_recall[listed] = json.loads(text[text.index("{\n"):])
        finally:
            _attestation.validate_campaign_asset_inputs = (
                real_assets_validator)
            _cli._boundary = real_boundary
        check("native recall consumes genuine standalone kind=mutation-run "
              "candidate/gold roles through the validated complete "
              "denominator",
              native_recall_rc == 0
              and candidate_id["kind"] == gold_id["kind"]
              == "mutation-run")
        check("[H25-D] the recall verb scores gold's kill of a listed mutant "
              "as no kill at all: the item leaves the population",
              listed_recall[frozenset()]["n_population"] == 1
              and listed_recall[frozenset({"m1"})]["n_population"] == 0
              and listed_recall[frozenset({"m1"})]["excluded"]
              == {"equivalent": 0, "infrastructure": 0,
                  "candidate_only_kill": 0},
              str({sorted(k)[0] if k else "-": (v["n_population"],
                                                v["excluded"])
                   for k, v in listed_recall.items()}))

        # A test-quality shard is subordinate evidence: its mutable shard
        # files are authenticated only by the root test-quality campaign.
        # Before this regression, unbound v2 test-quality identities skipped
        # standalone directory ownership validation and public recall
        # accepted them as if they were independent mutation-run campaigns.
        tq_common = {
            "kind": "test-quality",
            "gold_baseline_sha256": sha256_file(gold_baseline),
            "gold_generated_tests_sha256": candidate_digest({
                "i1": [{"file_path": "gold.php", "code": "<?php"}]}),
        }
        tq_candidate_id = dict(candidate_id, **tq_common)
        tq_gold_id = dict(gold_id, **tq_common)
        tq_candidate_result = os.path.join(
            root, "tq-recall-candidate", "candidate.w0.jsonl")
        tq_gold_result = os.path.join(
            root, "tq-recall-gold", "gold.w0.jsonl")
        for path, identity, outcome in (
                (tq_candidate_result, tq_candidate_id, "passed"),
                (tq_gold_result, tq_gold_id, "failed")):
            os.makedirs(os.path.dirname(path))
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(stamped_row(
                    identity, "i1", "m1",
                    file="src/CoreShop/Component/Foo.php",
                    outcome=outcome)) + "\n")
            attest(path, identity, "complete",
                   provenance={
                       **native_provenance(identity["of"]),
                       "shard_policy": "historical-strided-v1",
                   })

        tq_shard_refusals = []
        for path, role in ((tq_candidate_result, "candidate"),
                           (tq_gold_result, "gold")):
            try:
                validate_native_shards(
                    [path], required_side=role, return_campaign=True)
                tq_shard_refusals.append(False)
            except MutationAborted as e:
                tq_shard_refusals.append(
                    "kind='mutation-run'" in str(e))
        try:
            validate_candidate_gold_campaign_pair(
                tq_candidate_id, tq_gold_id)
            tq_pair_refused = False
        except MutationAborted as e:
            tq_pair_refused = "standalone kind='mutation-run'" in str(e)
        check("native standalone assembly and direct candidate/gold pairing "
              "both refuse unbound v2 test-quality artifacts",
              all(tq_shard_refusals) and tq_pair_refused)

        tq_recall_args = types.SimpleNamespace(
            **{**vars(recall_args),
               "results": [tq_candidate_result],
               "gold_results": [tq_gold_result]})
        tq_asset_validation_calls = []
        tq_recall_stdout = io.StringIO()
        try:
            _attestation.validate_campaign_asset_inputs = (
                lambda *a, **kw: tq_asset_validation_calls.append(
                    (a, kw)) or native_assets)
            try:
                with redirect_stdout(tq_recall_stdout):
                    _cli.cmd_recall(tq_recall_args)
                tq_recall_refused = False
            except SystemExit as e:
                tq_recall_refused = "kind='mutation-run'" in str(e)
        finally:
            _attestation.validate_campaign_asset_inputs = (
                real_assets_validator)
        check("public native recall refuses test-quality shards before "
              "asset publication work or metric output",
              tq_recall_refused and not tq_asset_validation_calls
              and tq_recall_stdout.getvalue() == "")

        # Legacy rows have no native identity to consult.  Their PR-2 report
        # must therefore supply every scoring input, not merely bless the two
        # result files while caller-controlled baselines/map/boundary choose a
        # different denominator.
        legacy_loader_calls = []
        real_legacy_loader = (
            _attestation.load_validated_legacy_scoring_inputs)
        legacy_candidate_baseline = os.path.join(
            root, "legacy-candidate-baseline.jsonl")
        with open(legacy_candidate_baseline, "w", encoding="utf-8") as fh:
            for row in (
                    {"item_id": "i1", "outcome": "passed",
                     "produced_files": [{"file_path": "candidate.php",
                                         "code": "<?php"}]},
                    {"item_id": "i2", "outcome": "failed",
                     "produced_files": []}):
                fh.write(json.dumps(row) + "\n")
        legacy_candidate_rows = [json.loads(line) for line in open(
            candidate_result, encoding="utf-8") if line.strip()]
        legacy_gold_rows = [json.loads(line) for line in open(
            gold_result, encoding="utf-8") if line.strip()]
        legacy_report = {"inputs": {
            key: {"sha256": sha256_file(path)} for key, path in (
                ("candidate_run", legacy_candidate_baseline),
                ("gold_baseline", gold_baseline),
                ("candidate_results", candidate_result),
                ("gold_results", gold_result))}}
        legacy_bound = {
            "facts": {"release_ready": True},
            "report": legacy_report,
            "paths": {"gold_baseline": gold_baseline},
            "boundary": types.SimpleNamespace(
                classify=lambda _path: "production"),
            "manifest": asset_manifest,
            "map": {"by_mutant": {"m1": ["i1", "i2"]}},
            "candidate_run_rows": [json.loads(line) for line in open(
                legacy_candidate_baseline, encoding="utf-8")
                if line.strip()],
            "gold_baseline_rows": [json.loads(line) for line in open(
                gold_baseline, encoding="utf-8") if line.strip()],
            "candidate_result_rows": legacy_candidate_rows,
            "gold_result_rows": legacy_gold_rows,
            "passed_item_ids": {"i1"},
            "expected_pairs": {("i1", "m1")},
        }

        def fixture_legacy_loader(path, *, require_release_ready=True):
            legacy_loader_calls.append((path, require_release_ready))
            return legacy_bound

        legacy_args = types.SimpleNamespace(
            **{**vars(recall_args),
               "legacy_consistency": "fixture-legacy-report.json",
               "baseline": legacy_candidate_baseline,
               "require_complete": False,
               "manifest": "/caller/manifest-must-not-be-read.json",
               "map": "/caller/map-must-not-be-read.json",
               "boundary": "/caller/boundary-must-not-be-read.yml"})
        try:
            _attestation.load_validated_legacy_scoring_inputs = (
                fixture_legacy_loader)
            _cli._boundary = lambda _args: (_ for _ in ()).throw(
                AssertionError("caller boundary was consulted"))
            legacy_stdout = io.StringIO()
            with redirect_stdout(legacy_stdout):
                legacy_recall_rc = _cli.cmd_recall(legacy_args)
        finally:
            _attestation.load_validated_legacy_scoring_inputs = (
                real_legacy_loader)
            _cli._boundary = real_boundary
        check("legacy recall scores only report-resolved baselines, scored "
              "population, map and boundary, with mandatory completeness",
              legacy_recall_rc == 0
              and legacy_loader_calls == [
                  ("fixture-legacy-report.json", True)]
              and '"completeness_checked": true' in legacy_stdout.getvalue())

        wrong_legacy_baseline = os.path.join(root, "wrong-legacy-run.jsonl")
        with open(wrong_legacy_baseline, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"item_id": "i1", "outcome": "failed"})
                     + "\n")
        wrong_legacy_args = types.SimpleNamespace(
            **{**vars(legacy_args), "baseline": wrong_legacy_baseline})
        try:
            _attestation.load_validated_legacy_scoring_inputs = (
                fixture_legacy_loader)
            try:
                with redirect_stdout(io.StringIO()):
                    _cli.cmd_recall(wrong_legacy_args)
                wrong_legacy_baseline_refused = False
            except SystemExit as e:
                wrong_legacy_baseline_refused = "SHA-256" in str(e)
        finally:
            _attestation.load_validated_legacy_scoring_inputs = (
                real_legacy_loader)
        check("legacy recall refuses a caller baseline outside the saved "
              "consistency chain", wrong_legacy_baseline_refused)

        with open(candidate_baseline, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "item_id": "i1", "outcome": "passed",
                "produced_files": [{
                    "file_path": "candidate.php", "code": "<?php changed"}],
            }) + "\n")
        forged_generated_id = dict(
            candidate_id,
            candidate_run_sha256=sha256_file(candidate_baseline))
        with open(candidate_result, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(stamped_row(
                forged_generated_id, "i1", "m1",
                file="src/CoreShop/Component/Foo.php",
                outcome="passed")) + "\n")
        # A different campaign's shard cannot transition this one's, so the
        # fixture retires the old attestation before writing the forged
        # candidate's -- the same "new evidence, not an edited sidecar" rule
        # the real recovery path follows.
        os.remove(provenance_path(candidate_result))
        attest(candidate_result, forged_generated_id, "complete",
               provenance=native_provenance(forged_generated_id["of"]))
        forged_plan_path = os.path.join(
            os.path.dirname(candidate_result), MUTATION_OUTPUT_PLAN)
        with open(forged_plan_path, encoding="utf-8") as fh:
            forged_observation_id = json.load(fh)["observation_id"]
        atomic_write_json(
            forged_plan_path,
            _standalone_output_plan(
                forged_generated_id, forged_observation_id))
        try:
            _attestation.validate_campaign_asset_inputs = (
                lambda *a, **kw: native_assets)
            _cli._boundary = lambda _args: types.SimpleNamespace(
                classify=lambda _path: "production")
            try:
                with redirect_stdout(io.StringIO()):
                    _cli.cmd_recall(recall_args)
                generated_tamper_refused = False
            except SystemExit as e:
                generated_tamper_refused = (
                    "candidate_generated_tests_sha256" in str(e))
        finally:
            _attestation.validate_campaign_asset_inputs = (
                real_assets_validator)
            _cli._boundary = real_boundary
        check("native recall re-derives generated-test bytes instead of "
              "trusting a forged run-only binding",
              generated_tamper_refused)

        mixed = dict(merge_identities[1], candidate_run_sha256="e" * 64)
        with open(merge_paths[1], "w", encoding="utf-8") as fh:
            fh.write(json.dumps(stamped_row(mixed, "i2", "m2")) + "\n")
        os.remove(provenance_path(merge_paths[1]))
        attest(merge_paths[1], mixed, "complete",
               provenance=native_provenance(mixed["of"]))
        try:
            validate_native_shards(merge_paths)
            mixed_refused = False
        except MutationAborted as e:
            mixed_refused = "mixed campaign cores" in str(e)
        check("native shard merge refuses self-consistent shards from mixed "
              "candidates", mixed_refused)

        applied = apply_mutant(h, m)                     # type: ignore[arg-type]
        check("the applier is called with the mutant's own coordinates",
              "--start-line 2" in h.runner.calls[-1]
              and "--operator ArithmeticOperator" in h.runner.calls[-1])
        # The engine and staged path stay fixed; the manifest-selected
        # operator profile is now explicit so a v1 row is re-enumerated under
        # v1 rather than merely rediscovered inside the larger v2 traversal.
        check("the default applier invokes PHP at its staged path with an "
              "explicit profile",
              h.runner.calls[-1].startswith(
                  "php var/bench_mutate/mutate.php --root /var/www/html "
                  "--operator-profile v2 --apply-file "),
              h.runner.calls[-1][:120])
        check("the ONE mutated file is declared to the integrity guard",
              h.expected_mutations == {rel: applied["digest"]},
              str(h.expected_mutations))
        check("the declared digest is the file as it now stands",
              applied["digest"] == _sha256(os.path.join(root, rel)))

        revert_mutant(h, applied)                        # type: ignore[arg-type]
        check("reverting restores the original bytes",
              open(os.path.join(root, rel), encoding="utf-8").read()
              == "<?php\nreturn $a + $b;\n")
        check("reverting withdraws the declaration, so the guard is full again",
              h.expected_mutations == {})

        h_v1 = _FakeHarness(root)
        applied_v1 = apply_mutant(
            h_v1, m, operator_profile="v1")  # type: ignore[arg-type]
        check("an explicit v1 materialisation reaches the same program as "
              "an explicit v1 enumeration",
              "--operator-profile v1 --apply-file "
              in h_v1.runner.calls[-1], h_v1.runner.calls[-1])
        revert_mutant(h_v1, applied_v1)                 # type: ignore[arg-type]

        # A no-op "mutation" would make the mutated run the baseline again.
        h2 = _FakeHarness(root, mutate=False)
        try:
            apply_mutant(h2, m)                          # type: ignore[arg-type]
            check("a mutant that changes nothing is refused", False, "accepted")
        except MutationAborted as e:
            check("a mutant that changes nothing is refused",
                  "byte-identical" in str(e))
        check("a refused no-op leaves no declaration behind",
              h2.expected_mutations == {})

        # A failing applier must not leave the workspace mutated.
        class _BadRunner(_FakeRunner):
            def run(self, inner, env=None, timeout=900):
                import subprocess
                if "--apply-file" in inner:
                    rel_ = shlex.split(inner)[shlex.split(inner).index(
                        "--apply-file") + 1]
                    with open(os.path.join(self.root, rel_), "a",
                              encoding="utf-8") as fh:
                        fh.write("// half-written\n")
                    return subprocess.CompletedProcess([], 1, "", "boom")
                return subprocess.CompletedProcess([], 0, "", "")

        h4 = _FakeHarness(root)
        h4.runner = _BadRunner(root)
        before = open(os.path.join(root, rel), encoding="utf-8").read()
        try:
            apply_mutant(h4, m)                          # type: ignore[arg-type]
            check("a failed apply is refused", False, "accepted")
        except MutationAborted:
            check("a failed apply is refused", True)
        check("a failed apply RESTORES the file rather than leaving it mutated",
              open(os.path.join(root, rel), encoding="utf-8").read() == before)
        check("a failed apply leaves no declaration behind",
              h4.expected_mutations == {})

        # Restoration replaces a planted symlink itself through a verified
        # parent fd; it never follows the link and overwrites its referent.
        h3 = _FakeHarness(root)
        sink = os.path.join(root, "src", "sink.php")
        victim = os.path.join(root, "victim.txt")
        with open(victim, "wb") as fh:
            fh.write(b"VICTIM\n")
        os.symlink(victim, sink)
        sink_identity = _file_lstat_identity(os.path.join(root, rel))
        revert_mutant(h3, {"file": "src/sink.php",           # type: ignore[arg-type]
                           "original": b"<?php // original\n",
                           "lstat": sink_identity})
        check("restore replaces a planted symlink without touching its target",
              _read_file_nofollow(sink) == b"<?php // original\n"
              and open(victim, "rb").read() == b"VICTIM\n")
        os.remove(sink)

        readonly = os.path.join(root, "src", "readonly.php")
        with open(readonly, "wb") as fh:
            fh.write(b"ORIGINAL\n")
        os.chmod(readonly, 0o444)
        readonly_identity = _file_lstat_identity(readonly)
        replacement = os.path.join(root, "src", ".readonly-mutant")
        with open(replacement, "wb") as fh:
            fh.write(b"MUTATED\n")
        os.chmod(replacement, 0o444)
        os.replace(replacement, readonly)
        revert_mutant(h3, {"file": "src/readonly.php",       # type: ignore[arg-type]
                           "original": b"ORIGINAL\n",
                           "lstat": readonly_identity})
        check("revert restores exact bytes and a read-only 0444 mode",
              _read_file_nofollow(readonly) == b"ORIGINAL\n"
              and _file_lstat_identity(readonly) == readonly_identity)

        # Resume, which is what makes an overnight campaign restartable.
        rows = os.path.join(root, "rows.jsonl")
        resume_expected = {("i1", "m1"), ("i2", "m1"), ("i1", "m2")}
        resume_identity = identity_for({}, resume_expected)
        with open(rows, "w", encoding="utf-8") as fh:
            for pair in (("m1", "i1"), ("m1", "i2"), ("m2", "i1")):
                fh.write(json.dumps(stamped_row(
                    resume_identity, pair[1], pair[0])) + "\n")
        attest(rows, resume_identity, "interrupted")
        check("completed pairs are read back for resume",
              completed_pairs(rows, resume_identity,
                              expected_pairs=resume_expected)
              == resume_expected)
        try:
            completed_pairs(os.path.join(root, "nope.jsonl"), resume_identity,
                            expected_pairs=resume_expected)
            check("an absent current out file cannot masquerade as a resume",
                  False, "accepted")
        except MutationAborted:
            check("an absent current out file cannot masquerade as a resume",
                  True)
        with open(rows, "a", encoding="utf-8") as fh:
            fh.write('{"mutant_id": "m3", "item_')
        attest(rows, resume_identity, "interrupted")
        try:
            completed_pairs(rows, resume_identity,
                            expected_pairs=resume_expected)
            check("a row torn by a kill is refused, not skipped", False,
                  "accepted")
        except MutationAborted as e:
            check("a row torn by a kill is refused, not skipped",
                  "mid-write" in str(e))

        # The concrete Cell-3 failure shape: same pairs and generated files,
        # but a rerun candidate whose exact run bytes have another digest.
        # The historical c00... rows must remain historical rather than being
        # skipped and relabelled as the 12c... campaign.
        old_cell3_sha = ("c00bd483a5689019" + "0" * 64)[:64]
        new_cell3_sha = ("12c5ad81f6561c70" + "0" * 64)[:64]
        cell3_path = os.path.join(root, "cell3-old.jsonl")
        cell3_pairs = {("i1", "m1")}
        cell3_old = identity_for(
            {}, cell3_pairs, candidate_run_sha256=old_cell3_sha)
        cell3_new = identity_for(
            {}, cell3_pairs, candidate_run_sha256=new_cell3_sha)
        with open(cell3_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(stamped_row(
                cell3_old, "i1", "m1"), sort_keys=True) + "\n")
        attest(cell3_path, cell3_old, "complete")
        before_rows = open(cell3_path, "rb").read()
        before_side = open(provenance_path(cell3_path), "rb").read()
        refused_cell3 = False
        try:
            completed_pairs(cell3_path, cell3_new,
                            expected_pairs=cell3_pairs)
        except MutationAborted as e:
            refused_cell3 = "belongs to mutation campaign" in str(e)
        check("c00-style rows cannot resume as the 12c-style candidate even "
              "when every pair is the same", refused_cell3)
        check("an identity-mismatch refusal leaves historical rows and "
              "provenance byte-identical",
              open(cell3_path, "rb").read() == before_rows
              and open(provenance_path(cell3_path), "rb").read() == before_side)

        def _resume_refuses_rows(name, rows_, identity_, expected_, needle):
            path = os.path.join(root, name + ".jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                for row_ in rows_:
                    fh.write(json.dumps(row_, sort_keys=True) + "\n")
            attest(path, identity_, "interrupted")
            try:
                completed_pairs(path, identity_, expected_pairs=expected_)
            except MutationAborted as e:
                return needle in str(e)
            return False

        wrong_side_row = stamped_row(cell3_old, "i1", "m1", side="gold")
        check("resume refuses a row stamped for the wrong side",
              _resume_refuses_rows("wrong-side", [wrong_side_row], cell3_old,
                                   cell3_pairs, "stamp field"))
        wrong_shard_row = stamped_row(
            cell3_old, "i1", "m1", mutant_shard=1)
        check("resume refuses a row stamped for the wrong shard",
              _resume_refuses_rows("wrong-shard", [wrong_shard_row], cell3_old,
                                   cell3_pairs, "stamp field"))
        duplicate_row = stamped_row(cell3_old, "i1", "m1")
        check("resume refuses duplicate pairs rather than picking a row",
              _resume_refuses_rows(
                  "duplicate", [duplicate_row, duplicate_row], cell3_old,
                  cell3_pairs, "duplicate pair"))
        unexpected_row = stamped_row(cell3_old, "other", "m1")
        check("resume refuses a pair outside the planned set",
              _resume_refuses_rows("unexpected", [unexpected_row], cell3_old,
                                   cell3_pairs, "unexpected pair"))

        # ------------------------------------------------ LI1/LI6/LI8/LI9
        #
        # The shard lifecycle, the read-only re-attest verb, the identity
        # versions, and the candidate binding one moved byte has to break.
        # Plan §5 "Lifecycle and identity"; review findings 8 and 20.
        from .campaign import (LEGACY_GENERATION_EVIDENCE,
                               legacy_generation_evidence)
        # The owner's ruling, spelled out here as well as in the registry, so
        # a change to either is a failing check rather than a silent
        # re-binding of the one candidate admitted by name.
        CELL3_RUN_SHA256 = ("6c5527e4ca6511c3db44eeadfeae10cf"
                            "b162a578fad25076e79fcc55b6d2301c")
        CELL3_TESTS_SHA256 = ("ef4ebcc9d8fb66907f7672a45790490e"
                              "fb7a28b04ca9c9a8c9b4cd513e50517a")
        CELL4_RUN_SHA256 = ("03bab48c7cc4225eb45300cecaf16eb5"
                            "c80518174cb1e523a01afe1da8eff1e0")
        CELL4_TESTS_SHA256 = ("e7f175c742a3a11af1ba1822f9607e6"
                              "a4795be49d5700fc05f1917d45a8a66c2")
        cell3_record = LEGACY_GENERATION_EVIDENCE.get(CELL3_RUN_SHA256) or {}
        check("LI8: the corrected Cell 3 candidate is registered under the "
              "exact digests the owner ruled, with its 16-hex generation "
              "digest recorded as KNOWN NONUNIQUE",
              cell3_record.get("candidate_generated_tests_sha256")
              == CELL3_TESTS_SHA256
              and cell3_record.get("generation_campaign_digest")
              == "971f1c00943040d5"
              and cell3_record.get(
                  "generation_campaign_digest_known_nonunique") is True
              and cell3_record.get("historical_solution_digest")
              == "12c5ad81f6561c70",
              str(cell3_record))
        cell4_record = LEGACY_GENERATION_EVIDENCE.get(CELL4_RUN_SHA256) or {}
        check("C5: aider Cell 4 is registered only under the exact run/test "
              "digests and inherited facts the preregistration froze",
              cell4_record.get("candidate_run_sha256") == CELL4_RUN_SHA256
              and cell4_record.get("candidate_generated_tests_sha256")
              == CELL4_TESTS_SHA256
              and cell4_record.get("generation_campaign_digest")
              == "8c72ba3e579d4bad"
              and "generation_campaign_digest_known_nonunique"
              not in cell4_record
              and cell4_record.get("historical_solution_digest")
              == "b151752f3241ffab"
              and cell4_record.get("generation_condition") == "c3"
              and cell4_record.get("generation_protocol_version") == 4
              and cell4_record.get("generation_protocol_digest")
              == "bda1d9bcb1852e92"
              and cell4_record.get("generation_native_budget")
              == {"max_reflections": 10}, str(cell4_record))
        returned_cell4 = legacy_generation_evidence(
            run_sha256=CELL4_RUN_SHA256) or {}
        returned_cell4["generation_native_budget"]["max_reflections"] = 99
        check("C5: a caller cannot mutate the nested Cell 4 authority in "
              "place",
              LEGACY_GENERATION_EVIDENCE[CELL4_RUN_SHA256][
                  "generation_native_budget"] == {"max_reflections": 10})

        legal = {(None, "running"), ("running", "running"),
                 ("running", "complete"), ("running", "interrupted"),
                 ("running", "failed"), ("interrupted", "running")}
        states = (None, "running", "complete", "interrupted", "failed")
        accepted, refused_pairs = set(), set()
        for current in states:
            for target in SHARD_STATES:
                try:
                    validate_shard_transition(current, target)
                    accepted.add((current, target))
                except MutationAborted:
                    refused_pairs.add((current, target))
        check("LI1: every illegal SHARD state transition refuses, and every "
              "legal one is admitted",
              accepted == legal
              and refused_pairs == {(c, t) for c in states
                                    for t in SHARD_STATES} - legal,
              f"accepted {sorted(map(str, accepted - legal))}, refused "
              f"{sorted(map(str, legal - accepted))}")

        lifecycle_dir = os.path.join(root, "lifecycle")
        os.makedirs(lifecycle_dir)
        li_pairs = {("i1", "m1")}
        li_identity = identity_for({}, li_pairs)
        li_path = os.path.join(lifecycle_dir, "shard.jsonl")
        with open(li_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(stamped_row(li_identity, "i1", "m1"),
                                sort_keys=True) + "\n")
        write_shard_provenance(li_path, li_identity, "running")
        write_shard_provenance(li_path, li_identity, "complete")
        complete_side_bytes = open(provenance_path(li_path), "rb").read()
        demote_refused = False
        try:
            write_shard_provenance(li_path, li_identity, "running")
        except MutationAborted as e:
            demote_refused = ("cannot transition from 'complete'" in str(e)
                              and "verify-shard" in str(e))
        check("LI1: the real sidecar WRITER refuses to reopen a `complete` "
              "shard, and its refusal names the read-only re-attest verb",
              demote_refused)
        check("LI1: a refused transition leaves the attested sidecar "
              "byte-identical",
              open(provenance_path(li_path), "rb").read()
              == complete_side_bytes)
        failed_dir = os.path.join(root, "lifecycle-failed")
        os.makedirs(failed_dir)
        failed_path = os.path.join(failed_dir, "shard.jsonl")
        with open(failed_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(stamped_row(li_identity, "i1", "m1"),
                                sort_keys=True) + "\n")
        write_shard_provenance(failed_path, li_identity, "running")
        write_shard_provenance(failed_path, li_identity, "failed",
                               error="fixture failure evidence")
        failed_resume_refused = False
        try:
            write_shard_provenance(failed_path, li_identity, "running")
        except MutationAborted as e:
            failed_resume_refused = "terminal" in str(e)
        check("LI1: a `failed` shard is failure evidence, not a resume "
              "target -- the writer refuses to reopen it too",
              failed_resume_refused)
        foreign_refused = False
        try:
            write_shard_provenance(
                li_path, identity_for({}, li_pairs,
                                      candidate_run_sha256="f" * 64),
                "running")
        except MutationAborted as e:
            foreign_refused = "may not transition another campaign" in str(e)
        check("LI1: one campaign may not transition another campaign's "
              "shard, so the table cannot be walked around with a second "
              "identity", foreign_refused)

        # LI6 -- the read-only re-attest verb, on a pristine shard and on a
        # byte-identical demoted one.
        pristine_report = verify_shard(li_path)
        rows_before_verify = open(li_path, "rb").read()
        side_before_verify = open(provenance_path(li_path), "rb").read()
        rows_stat = os.stat(li_path).st_mtime_ns
        side_stat = os.stat(provenance_path(li_path)).st_mtime_ns
        verify_shard(li_path)
        check("LI6: `verify-shard` reports a pristine complete shard as "
              "consistent with its own bytes",
              pristine_report["state_consistent_with_bytes"] is True
              and pristine_report["recorded_status"] == "complete"
              and pristine_report["bytes_support_complete"] is True
              and pristine_report["problems"] == [],
              str(pristine_report["problems"]))
        demoted_dir = os.path.join(root, "lifecycle-demoted")
        os.makedirs(demoted_dir)
        demoted_path = os.path.join(demoted_dir, "shard.jsonl")
        with open(demoted_path, "wb") as fh:
            fh.write(open(li_path, "rb").read())
        write_shard_provenance(demoted_path, li_identity, "running")
        write_shard_provenance(
            demoted_path, li_identity, "failed",
            error="MutationAborted: cleanup/restoration failed")
        demoted_report = verify_shard(demoted_path)
        check("LI6: a shard demoted to `failed` over BYTE-IDENTICAL complete "
              "rows is reported INCONSISTENT with its own bytes",
              demoted_report["state_consistent_with_bytes"] is False
              and demoted_report["bytes_support_complete"] is True
              and open(demoted_path, "rb").read() == rows_before_verify
              and any("not supported by the evidence" in problem
                      for problem in demoted_report["problems"]),
              str(demoted_report))
        check("LI6: re-attesting writes NOTHING -- rows and sidecar keep "
              "their exact bytes and their mtimes",
              open(li_path, "rb").read() == rows_before_verify
              and open(provenance_path(li_path), "rb").read()
              == side_before_verify
              and os.stat(li_path).st_mtime_ns == rows_stat
              and os.stat(provenance_path(li_path)).st_mtime_ns == side_stat)
        truncated_dir = os.path.join(root, "lifecycle-truncated")
        os.makedirs(truncated_dir)
        truncated_path = os.path.join(truncated_dir, "shard.jsonl")
        with open(truncated_path, "w", encoding="utf-8") as fh:
            fh.write("")
        write_shard_provenance(truncated_path, li_identity, "running")
        write_shard_provenance(truncated_path, li_identity, "failed",
                               error="died before its first row")
        check("LI6: a genuinely short `failed` shard is reported CONSISTENT, "
              "so the verb distinguishes a wrong demotion from a real one",
              verify_shard(truncated_path)["state_consistent_with_bytes"]
              is True)

        # LI8 -- v1/v2 and cross-attempt shard combinations refuse.
        v1_identity = {key: value for key, value in li_identity.items()
                       if key not in CAMPAIGN_IDENTITY_FIELDS_V2_ADDED}
        v1_identity["schema"] = MUTATION_IDENTITY_SCHEMA_V1
        check("LI8: a v1 mutation identity still validates and re-hashes "
              "exactly as written, so archived evidence stays readable",
              campaign_identity_digest(v1_identity)
              == content_digest(v1_identity))
        mixed_version_refused = False
        try:
            refuse_mixed_generation_evidence([li_identity, v1_identity],
                                             "this fixture shard set")
        except MutationAborted as e:
            mixed_version_refused = "identity versions" in str(e)
        check("LI8: a v1 shard and a v2 shard may never be merged into one "
              "campaign", mixed_version_refused)
        second_attempt = identity_for(
            {}, li_pairs, generation_attempt_id="fixture-attempt-2")
        cross_attempt_refused = False
        try:
            refuse_mixed_generation_evidence([li_identity, second_attempt],
                                             "this fixture shard set")
        except MutationAborted as e:
            cross_attempt_refused = "generation attempts" in str(e)
        check("LI8: two shards of ONE recipe from two generation ATTEMPTS "
              "refuse to merge -- the realized Cell 3 collision, at the "
              "merge layer", cross_attempt_refused)
        check("LI8: ...and the same two attempts are two different mutation "
              "campaign identities, which v1 could not express",
              campaign_identity_digest(li_identity)
              != campaign_identity_digest(second_attempt))

        # LI9 -- one moved byte in the generated code changes BOTH recorded
        # candidate digests: the run file's bytes and the generated-test
        # identity computed from them.
        li9_dir = os.path.join(root, "moved-byte")
        os.makedirs(li9_dir)
        li9_files = {"i1": [{"file_path": "t.php", "code": "<?php $a = 1;"}]}
        li9_moved = {"i1": [{"file_path": "t.php", "code": "<?php $a = 2;"}]}
        li9_run = os.path.join(li9_dir, "run.jsonl")
        li9_moved_run = os.path.join(li9_dir, "run-moved.jsonl")
        for path_, files_ in ((li9_run, li9_files), (li9_moved_run,
                                                     li9_moved)):
            with open(path_, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"item_id": "i1", "outcome": "passed",
                                     "produced_files": files_["i1"]},
                                    sort_keys=True) + "\n")
        check("LI9: moving one byte of generated code changes BOTH recorded "
              "candidate digests -- the run file's SHA-256 and the "
              "generated-test identity",
              sha256_file(li9_run) != sha256_file(li9_moved_run)
              and candidate_digest(li9_files) != candidate_digest(li9_moved))
        legacy_bound_refused = False
        try:
            identity_for(li9_files, li_pairs,
                         generation_provenance_class="legacy_exact_bytes",
                         generation_attempt_id=None,
                         generation_agent_runtime_sha256=None,
                         generation_network_semantics=None,
                         generation_campaign_digest="971f1c00943040d5",
                         candidate_run_sha256=CELL3_RUN_SHA256)
        except MutationAborted as e:
            legacy_bound_refused = "binds generated tests" in str(e)
        check("LI9: legacy_exact_bytes evidence binds the run AND the tests, "
              "so a candidate whose generated bytes moved cannot inherit the "
              "Cell 3 ruling", legacy_bound_refused)
        cell3_identity = build_campaign_identity(
            **{**{key: li_identity[key] for key in CAMPAIGN_IDENTITY_FIELDS_V1
                  if key not in ("schema", "shard", "of", "expected_pairs",
                                 "expected_pairs_sha256", "timeout_seconds",
                                 "kind", "side")},
               "generation_provenance_class": "legacy_exact_bytes",
               "generation_attempt_id": None,
               "generation_agent_runtime_sha256": None,
               "generation_network_semantics": None,
               "generation_campaign_digest": "971f1c00943040d5",
               "generation_condition": "c3",
               "generation_protocol_version": 4,
               "generation_protocol_digest": "bda1d9bcb1852e92",
               "generation_native_budget": {"max_iterations": 100},
               "candidate_run_sha256": CELL3_RUN_SHA256,
               "candidate_generated_tests_sha256": CELL3_TESTS_SHA256},
            expected_pairs=li_pairs, side="candidate", shard=0, of=1,
            timeout=600, kind="mutation-run")
        check("LI8: the corrected Cell 3 candidate is admitted ONLY as "
              "labelled `legacy_exact_bytes` evidence bound to its exact run "
              "and generated-test SHA-256 values",
              cell3_identity["generation_provenance_class"]
              == "legacy_exact_bytes"
              and cell3_identity["generation_attempt_id"] is None
              and cell3_identity["candidate_run_sha256"] == CELL3_RUN_SHA256
              and cell3_identity["candidate_generated_tests_sha256"]
              == CELL3_TESTS_SHA256)
        cell4_identity = build_campaign_identity(
            **{**{key: li_identity[key] for key in CAMPAIGN_IDENTITY_FIELDS_V1
                  if key not in ("schema", "shard", "of", "expected_pairs",
                                 "expected_pairs_sha256", "timeout_seconds",
                                 "kind", "side")},
               "generation_provenance_class": "legacy_exact_bytes",
               "generation_attempt_id": None,
               "generation_agent_runtime_sha256": None,
               "generation_network_semantics": None,
               "generation_campaign_digest": "8c72ba3e579d4bad",
               "generation_condition": "c3",
               "generation_protocol_version": 4,
               "generation_protocol_digest": "bda1d9bcb1852e92",
               "generation_native_budget": {"max_reflections": 10},
               "candidate_run_sha256": CELL4_RUN_SHA256,
               "candidate_generated_tests_sha256": CELL4_TESTS_SHA256},
            expected_pairs=li_pairs, side="candidate", shard=0, of=1,
            timeout=600, kind="mutation-run")
        check("C5: aider Cell 4 resolves only as legacy_exact_bytes with no "
              "invented attempt/runtime/network identity",
              cell4_identity["generation_provenance_class"]
              == "legacy_exact_bytes"
              and cell4_identity["generation_attempt_id"] is None
              and cell4_identity["generation_agent_runtime_sha256"] is None
              and cell4_identity["generation_network_semantics"] is None)
        cell4_relabels = {
            "generation_condition": "c2",
            "generation_protocol_version": 3,
            "generation_protocol_digest": "0" * 16,
            "generation_native_budget": {"max_reflections": 9},
        }
        relabelled_cell4_refused = {}
        for field, forged in cell4_relabels.items():
            try:
                build_campaign_identity(
                    **{**{key: value for key, value in cell4_identity.items()
                          if key not in ("schema", "shard", "of",
                                         "expected_pairs",
                                         "expected_pairs_sha256",
                                         "timeout_seconds", "kind", "side")},
                       field: forged},
                    expected_pairs=li_pairs, side="candidate", shard=0, of=1,
                    timeout=600, kind="mutation-run")
                relabelled_cell4_refused[field] = "accepted"
            except MutationAborted as e:
                relabelled_cell4_refused[field] = str(e)
        check("C5: exact Cell 4 bytes cannot be relabelled under another "
              "arm, protocol, or native budget",
              all("binds inherited generation" in message
                  for message in relabelled_cell4_refused.values()),
              str(relabelled_cell4_refused))
        numeric_budget_alias_refused = False
        try:
            build_campaign_identity(
                **{**{key: value for key, value in cell4_identity.items()
                      if key not in ("schema", "shard", "of",
                                     "expected_pairs",
                                     "expected_pairs_sha256",
                                     "timeout_seconds", "kind", "side")},
                   "generation_native_budget": {"max_reflections": 10.0}},
                expected_pairs=li_pairs, side="candidate", shard=0, of=1,
                timeout=600, kind="mutation-run")
        except MutationAborted as e:
            numeric_budget_alias_refused = (
                "binds inherited generation" in str(e))
        check("C5: canonical JSON numeric type is part of the inherited "
              "Cell 4 budget (integer 10 cannot be relabelled as 10.0)",
              numeric_budget_alias_refused)
        unregistered_refused = False
        try:
            identity_for(li9_files, li_pairs,
                         generation_provenance_class="legacy_exact_bytes",
                         generation_attempt_id=None,
                         generation_agent_runtime_sha256=None,
                         generation_network_semantics=None,
                         generation_campaign_digest="971f1c00943040d5")
        except MutationAborted as e:
            unregistered_refused = "not registered" in str(e)
        check("LI8: `legacy_exact_bytes` is not a flag -- an unregistered "
              "run cannot claim the class", unregistered_refused)
        # The DERIVATION the real producers use: a candidate's generation
        # facts come from its own evidence, never from a flag.
        evidence_dir = os.path.join(root, "generation-evidence")
        os.makedirs(evidence_dir)

        def write_generation_rows(path, rows_):
            with open(path, "w", encoding="utf-8") as fh:
                for row_ in rows_:
                    fh.write(json.dumps(row_, sort_keys=True) + "\n")

        plain_run = os.path.join(evidence_dir, "plain.jsonl")
        plain_rows = [{"item_id": "i1", "outcome": "passed",
                       "produced_files": li9_files["i1"]}]
        write_generation_rows(plain_run, plain_rows)
        unlabelled_refused = False
        try:
            generation_evidence_for_run(plain_run, plain_rows)
        except MutationAborted as e:
            unlabelled_refused = ("carries no generation provenance" in str(e)
                                  and "LEGACY_GENERATION_EVIDENCE" in str(e))
        check("LI8: a candidate run with neither a v2 campaign sidecar nor a "
              "registry entry is REFUSED, not recorded as provenance-free",
              unlabelled_refused)
        from .campaign import (SHARD_RULE as _SHARD_RULE, campaign_digest as
                              _campaign_digest, generation_fingerprint)
        v2_fingerprint = generation_fingerprint(
            campaign_id="fixture-generation", k_workers=1,
            shard_rule=_SHARD_RULE, trial_budget=0, condition="c3",
            coverage=False, harness_version=6, config_digest="cfg0123456789ab",
            model="fixture-model", container_image_digest="sha256:" + "7" * 64,
            workspace_seed_digest="6" * 64, database_dump_digest="5" * 64,
            protocol_version=4, protocol_digest="bda1d9bcb1852e92",
            agent_system="openhands", attempt_id="fixture-generation-1",
            harness_commit="a" * 40, harness_source_sha256="b" * 64,
            agent_runtime_sha256="c" * 64,
            network_semantics="closed_gold_host_channel")
        v2_digest = _campaign_digest(v2_fingerprint)
        v2_run = os.path.join(evidence_dir, "v2.jsonl")
        v2_rows = [{"item_id": "i1", "outcome": "passed", "condition": "c3",
                    "protocol_version": 4,
                    "protocol_digest": "bda1d9bcb1852e92",
                    "native_budget": {"max_iterations": 100},
                    "campaign_digest": v2_digest,
                    "produced_files": li9_files["i1"]}]
        write_generation_rows(v2_run, v2_rows)
        with open(v2_run + ".campaign.json", "w", encoding="utf-8") as fh:
            json.dump({"campaign": v2_fingerprint,
                       "campaign_digest": v2_digest}, fh, sort_keys=True)
        v2_facts = generation_evidence_for_run(v2_run, v2_rows)
        check("LI8: a v2-generated candidate carries its attempt, runtime, "
              "network posture, condition, protocol and native budget "
              "through as FIRST-CLASS facts",
              v2_facts["generation_provenance_class"] == "native_v2"
              and v2_facts["generation_attempt_id"] == "fixture-generation-1"
              and v2_facts["generation_campaign_digest"] == v2_digest
              and v2_facts["generation_agent_runtime_sha256"] == "c" * 64
              and v2_facts["generation_network_semantics"]
              == "closed_gold_host_channel"
              and v2_facts["generation_condition"] == "c3"
              and v2_facts["generation_protocol_version"] == 4
              and v2_facts["generation_protocol_digest"]
              == "bda1d9bcb1852e92"
              and v2_facts["generation_native_budget"]
              == {"max_iterations": 100}, str(v2_facts))
        # THE DEVELOPMENT DOOR.  Same resolver, same rows, one keyword: where
        # the three shapes above find nothing, the absence is RECORDED rather
        # than refused.  `plain_run` is the shape an ordinary `run --release`
        # candidate has -- no sidecar, no per-row stamp -- and it is the run
        # the check above proves is otherwise refused.
        dev_facts = generation_evidence_for_run(plain_run, plain_rows,
                                                development=True)
        check("the development route RECORDS the absence of a generation "
              "campaign -- no attempt, no runtime, no network, and a None "
              "campaign digest rather than a placeholder that would name a "
              "campaign nobody minted",
              dev_facts["generation_provenance_class"]
              == GENERATION_PROVENANCE_DEVELOPMENT
              and dev_facts["generation_attempt_id"] is None
              and dev_facts["generation_campaign_digest"] is None
              and dev_facts["generation_agent_runtime_sha256"] is None
              and dev_facts["generation_network_semantics"] is None,
              str(dev_facts))
        dev_identity = identity_for(
            li9_files, li_pairs,
            generation_provenance_class=GENERATION_PROVENANCE_DEVELOPMENT,
            generation_attempt_id=None,
            generation_campaign_digest=None,
            generation_agent_runtime_sha256=None,
            generation_network_semantics=None)
        dev_publishable_refused = False
        try:
            validate_publishable_generation(dev_identity,
                                            where="a development candidate")
        except MutationAborted as e:
            dev_publishable_refused = "not publishable here" in str(e)
        check("a development identity is VALID and UNPUBLISHABLE -- it mints, "
              "so the metric can be computed, and "
              "`validate_publishable_generation` refuses the class",
              GENERATION_PROVENANCE_DEVELOPMENT
              not in GENERATION_PROVENANCE_PUBLISHABLE
              and dev_identity["generation_provenance_class"]
              == GENERATION_PROVENANCE_DEVELOPMENT
              and dev_publishable_refused)
        dev_dressed_refused = False
        try:
            identity_for(
                li9_files, li_pairs,
                generation_provenance_class=GENERATION_PROVENANCE_DEVELOPMENT,
                generation_attempt_id=None,
                generation_campaign_digest="0123456789abcdef",
                generation_agent_runtime_sha256=None,
                generation_network_semantics=None)
        except MutationAborted as e:
            dev_dressed_refused = "names no generation campaign" in str(e)
        check("...and it may not carry a campaign digest either: a 16-hex "
              "value there would name a campaign that was never minted",
              dev_dressed_refused)
        # THE PLACEMENT CHECK.  `development=True` is answered at the FINAL
        # raise, so a run that HAS provenance keeps it.  A flag that could
        # downgrade native_v2 to development_unstamped would let an operator
        # drop a stamped candidate's attempt identity by adding a word to the
        # command line.
        check("--development supplies provenance where there is none and "
              "never downgrades provenance that exists: a stamped run still "
              "resolves native_v2 under the flag",
              generation_evidence_for_run(v2_run, v2_rows, development=True)
              == v2_facts,
              str(generation_evidence_for_run(v2_run, v2_rows,
                                              development=True)))
        stolen_sidecar_refused = False
        try:
            stolen_rows = [dict(v2_rows[0], campaign_digest="0" * 16)]
            write_generation_rows(v2_run, stolen_rows)
            generation_evidence_for_run(
                v2_run, stolen_rows)
        except MutationAborted as e:
            stolen_sidecar_refused = "bound to its rows by what they" in str(e)
        check("LI8: a campaign sidecar is bound to its rows by their stamp, "
              "so one copied in beside another run's bytes is refused",
              stolen_sidecar_refused)
        chimeric_refused = False
        try:
            chimeric_rows = [
                v2_rows[0],
                {"item_id": "i2", "outcome": "passed",
                 "produced_files": []},
            ]
            write_generation_rows(v2_run, chimeric_rows)
            generation_evidence_for_run(v2_run, chimeric_rows)
        except MutationAborted as e:
            chimeric_refused = ("carry no campaign_digest at all" in str(e)
                                and "partially stamped" in str(e))
        check("LI8: a chimeric run -- one stamped row beside an unstamped "
              "one -- is refused, so the binding is over EVERY row and not "
              "over the one that happens to carry a digest", chimeric_refused)
        arm_disagreement_refused = False
        try:
            arm_rows = [dict(v2_rows[0], condition="c2")]
            write_generation_rows(v2_run, arm_rows)
            generation_evidence_for_run(v2_run, arm_rows)
        except MutationAborted as e:
            arm_disagreement_refused = ("declares condition='c3'" in str(e)
                                        and "the run's rows say 'c2'" in str(e))
        check("LI8: rows uniformly stamped with another ARM than their own "
              "fingerprint declares are refused, and the refusal names the "
              "field", arm_disagreement_refused)
        protocol_disagreement_refused = False
        try:
            protocol_rows = [dict(
                v2_rows[0], protocol_version=3,
                protocol_digest="e6ea6d2471996861")]
            write_generation_rows(v2_run, protocol_rows)
            generation_evidence_for_run(v2_run, protocol_rows)
        except MutationAborted as e:
            protocol_disagreement_refused = "protocol_version=4" in str(e)
        check("LI8: ...and so is a run whose rows followed another RECIPE "
              "than the fingerprint they are filed under",
              protocol_disagreement_refused)

        mixed_condition_refused = False
        try:
            mixed_rows = [v2_rows[0], dict(v2_rows[0], condition="c2")]
            write_generation_rows(v2_run, mixed_rows)
            generation_evidence_for_run(v2_run, mixed_rows)
        except MutationAborted as e:
            mixed_condition_refused = "disagree about 'condition'" in str(e)
        check("LI8: a run file whose rows disagree about the arm they were "
              "generated under is refused, not resolved by row order",
              mixed_condition_refused)
        write_generation_rows(v2_run, v2_rows)
        exact_cell3 = legacy_generation_evidence(
            run_sha256=CELL3_RUN_SHA256) or {}
        check("LI9: the registered Cell 3 bytes resolve by their full run "
              "SHA-256 and retain the known-nonunique recipe digest",
              exact_cell3.get("generation_campaign_digest")
              == "971f1c00943040d5"
              and exact_cell3.get("candidate_generated_tests_sha256")
              == CELL3_TESTS_SHA256,
              str(exact_cell3))
        check("C5: a registry-local unique recipe digest still cannot "
              "identify Cell 4 exact-byte evidence",
              legacy_generation_evidence(
                  generation_campaign_digest="8c72ba3e579d4bad") is None)

        cell4_rows = [{"condition": "c3", "protocol_version": 4,
                       "protocol_digest": "bda1d9bcb1852e92",
                       "native_budget": {"max_reflections": 10}}]
        # Exercise the public file resolver with bytes whose digest the test
        # can actually reproduce.  A temporary registry row is safer than the
        # old caller-asserted `run_sha256=` seam, which let a nonexistent file
        # impersonate Cell 4.
        legacy_run = os.path.join(evidence_dir, "legacy.jsonl")
        with open(legacy_run, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(cell4_rows[0], sort_keys=True) + "\n")
        synthetic_run_sha = sha256_file(legacy_run)
        synthetic_record = {
            **(legacy_generation_evidence(
                run_sha256=CELL4_RUN_SHA256) or {}),
            "label": "selftest_cell4_shape",
            "candidate_run_sha256": synthetic_run_sha,
        }
        LEGACY_GENERATION_EVIDENCE[synthetic_run_sha] = synthetic_record
        cell4_facts = generation_evidence_for_run(legacy_run, cell4_rows)
        check("C5: registered Cell 4 rows reproduce every inherited fact",
              cell4_facts["generation_provenance_class"]
              == "legacy_exact_bytes"
              and cell4_facts["generation_condition"] == "c3"
              and cell4_facts["generation_protocol_version"] == 4
              and cell4_facts["generation_protocol_digest"]
              == "bda1d9bcb1852e92"
              and cell4_facts["generation_native_budget"]
              == {"max_reflections": 10}, str(cell4_facts))
        check("...and registered legacy bytes keep that class under "
              "--development too -- the flag is answered after the registry, "
              "never before it",
              generation_evidence_for_run(legacy_run, cell4_rows,
                                          development=True) == cell4_facts)
        row_relabels = {
            "condition": "c2",
            "protocol_version": 3,
            "protocol_digest": "0" * 16,
            "native_budget": {"max_reflections": 9},
            "native_budget_numeric_alias": {"max_reflections": 10.0},
        }
        cell4_fact_mismatches = {}
        for label, forged in row_relabels.items():
            field = ("native_budget" if label
                     == "native_budget_numeric_alias" else label)
            forged_rows = [dict(cell4_rows[0], **{field: forged})]
            forged_path = os.path.join(
                evidence_dir, f"legacy-{label}.jsonl")
            with open(forged_path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(forged_rows[0], sort_keys=True) + "\n")
            forged_sha = sha256_file(forged_path)
            LEGACY_GENERATION_EVIDENCE[forged_sha] = {
                **(legacy_generation_evidence(
                    run_sha256=CELL4_RUN_SHA256) or {}),
                "label": f"selftest_cell4_{label}",
                "candidate_run_sha256": forged_sha,
            }
            try:
                generation_evidence_for_run(forged_path, forged_rows)
                cell4_fact_mismatches[label] = "accepted"
            except MutationAborted as e:
                cell4_fact_mismatches[label] = str(e)
            finally:
                LEGACY_GENERATION_EVIDENCE.pop(forged_sha, None)
        check("C5: every inherited-fact mismatch refuses before Cell 4 "
              "evidence is minted",
              all("binds inherited generation fact" in message
                  for message in cell4_fact_mismatches.values()),
              str(cell4_fact_mismatches))
        fabricated_rows_refused = False
        try:
            generation_evidence_for_run(
                legacy_run, [dict(cell4_rows[0], condition="c2")])
        except MutationAborted as e:
            fabricated_rows_refused = "same bytes" in str(e)
        check("C5: the file resolver refuses caller-supplied replacement "
              "rows before consulting the exact-byte registry",
              fabricated_rows_refused)
        missing_file_refused = False
        try:
            generation_evidence_for_run(
                os.path.join(evidence_dir, "does-not-exist.jsonl"),
                cell4_rows)
        except MutationAborted as e:
            missing_file_refused = "not a regular file" in str(e)
        check("C5: a nonexistent path cannot impersonate registered legacy "
              "bytes through a caller-asserted digest", missing_file_refused)
        LEGACY_GENERATION_EVIDENCE.pop(synthetic_run_sha, None)

        invented_attempt_refused = False
        try:
            identity_for(li9_files, li_pairs,
                         generation_provenance_class="legacy_exact_bytes",
                         generation_attempt_id="invented",
                         generation_campaign_digest="971f1c00943040d5",
                         candidate_run_sha256=CELL3_RUN_SHA256)
        except MutationAborted as e:
            invented_attempt_refused = "has no attempt identity" in str(e)
        check("LI8: legacy evidence may not be dressed up with an invented "
              "attempt identity", invented_attempt_refused)

        # §3.10's one-time infrastructure retry, and the provenance a
        # concatenated results file needs to be attributable.
        class _FlakyHarness(_FakeHarness):
            """Fails the first execution of every pair, then succeeds."""

            def __init__(self, root):
                super().__init__(root)
                self.seen = {}

            def run_solution(self, feature, scenario, sol, **kw):
                key = id(sol)
                self.seen[key] = self.seen.get(key, 0) + 1
                bad = self.seen[key] == 1
                return {"runs": [{"outcome": "container_error" if bad
                                  else "failed",
                                  "exit_code": 1, "wall_seconds": 0.1,
                                  "records": [] if bad else [
                                      {"scenario_line": 1,
                                       "steps": [{"text": "s",
                                                  "result": "failed",
                                                  "seconds": 0.1,
                                                  "exception": None}]}],
                                  "expected_line": 1,
                                  "stdout_tail": "Cannot autowire" if bad else ""}],
                        "written_files": [], "rejected_files": [],
                        "index_errors": {}, "registered_contexts": [],
                        "outcomes": [], "substrate_violation": None}

        feat = os.path.join(root, "f.feature")
        with open(feat, "w", encoding="utf-8") as fh:
            fh.write("Feature: f\n\n  Scenario: s\n    Given a\n")
        h6 = _FlakyHarness(root)
        h6.root = root
        out6 = os.path.join(root, "retry.jsonl")
        files6 = {"i1": [{"file_path": "a.php", "code": "<?php"}]}
        identity6 = identity_for(files6, {("i1", m["id"])})
        info = run_slice(h6, [m],
                         {"i1": {"item_id": "i1",
                                 "provenance": {"file_path": "f.feature",
                                                "line": 3}}},
                         files6,
                         {m["id"]: ["i1"]},
                         os.path.join(os.path.dirname(os.path.dirname(
                             os.path.abspath(__file__))), "php"),
                         out6, provenance={"manifest_digest": "a" * 64},
                         identity=identity6)
        rows6 = [json.loads(l) for l in open(out6, encoding="utf-8") if l.strip()]
        check("an infrastructure failure is retried once, not excluded",
              len(rows6) == 1 and rows6[0]["attempt"] == 2
              and rows6[0]["retried_infrastructure"] is True, str(rows6))
        check("the retry's result is what gets recorded",
              rows6 and rows6[0]["outcome"] == "failed", str(rows6[:1]))
        check("every row names the manifest and the candidate it faced",
              rows6[0]["manifest_digest"] == "a" * 64
              and len(rows6[0]["candidate_digest"]) == 64
              and rows6[0]["mutation_campaign_digest"]
              == campaign_identity_digest(identity6))
        side = json.load(open(out6 + ".provenance.json", encoding="utf-8"))
        check("a provenance sidecar sits beside the rows",
              side["manifest_digest"] == "a" * 64 and side["rows"] == 1
              and side["status"] == "complete"
              and side["rows_sha256"] == sha256_file(out6))

        # Harness 25: a slice tells the harness whether its executions are
        # gold runs, which keep harness 24's suite and wiring rules
        # (`Solution.gold_run`); nothing in the candidate bytes can say so.
        class _SeeingHarness(_FlakyHarness):
            def __init__(self, root):
                super().__init__(root)
                self.gold_runs = []

            def run_solution(self, feature, scenario, sol, **kw):
                self.gold_runs.append(sol.gold_run)
                self.seen[id(sol)] = 1      # no retry: one execution each
                return super().run_solution(feature, scenario, sol, **kw)

        marks = {}
        for side_name in ("gold", "candidate"):
            seeing = _SeeingHarness(root)
            seeing.root = root
            run_slice(seeing, [m],
                      {"i1": {"item_id": "i1",
                              "provenance": {"file_path": "f.feature",
                                             "line": 3}}},
                      files6, {m["id"]: ["i1"]},
                      os.path.join(os.path.dirname(os.path.dirname(
                          os.path.abspath(__file__))), "php"),
                      os.path.join(root, f"side-{side_name}.jsonl"),
                      identity=identity_for(files6, {("i1", m["id"])},
                                            side=side_name))
            marks[side_name] = seeing.gold_runs
        check("a gold-side slice's executions are gold runs and a candidate "
              "slice's are candidate runs",
              marks == {"gold": [True], "candidate": [False]}, str(marks))
        check("...and every reference leg's observation is a gold run, the "
              "candidate-side stripped and stub legs included",
              all(is_gold_run_slice({"side": "candidate",
                                     "reference_control_role": role})
                  for role in REFERENCE_CONTROL_ROLES)
              and not is_gold_run_slice({"side": "candidate"}))

        # A Go descriptor is selected outside the item loop, but each
        # permitted retry must enter the complete disposable-copy adapter.
        # This fixture replaces that adapter only; shared row/retry writing
        # runs unchanged, and no Go engine or manifest is qualified here.
        import sys
        from types import ModuleType
        from unittest.mock import patch
        go_dispatch = ModuleType("r2t.go.mutation_runtime")
        go_calls = []
        go_out = os.path.join(root, "go-copy-dispatch.jsonl")
        go_files = {"i1": [{"file_path":"a.go", "code":"first"}],
                    "i2": [{"file_path":"b.go", "code":"second"}]}
        go_identity = identity_for(go_files, {(i,m["id"]) for i in go_files},
                                   engine="r2t-mutate-go",engine_version="1.0")
        go_manifest = {"engine":"r2t-mutate-go"}
        authority = object()
        def go_validate(doc, ident):
            assert doc is go_manifest and ident is go_identity
            go_calls.append("validate")
        def go_prepare(harness, doc, ident, *, artifacts):
            assert not os.path.exists(go_out)
            go_calls.append("prepare")
            return authority
        go_seen = {}
        def go_execute(harness, feature, scenario, sol, **kwargs):
            assert kwargs["authority"] is authority and kwargs["mutant"] == m
            assert kwargs["manifest"] is go_manifest and kwargs["identity"] is go_identity
            assert kwargs["timeout"] == 600 and harness.expected_mutations == {}
            assert os.path.isdir(kwargs["evidence_dir"]) and not os.listdir(kwargs["evidence_dir"])
            assert os.path.dirname(kwargs["evidence_dir"]) == go_out + ".go-evidence"
            label = sol.files[0].code
            go_seen[label] = go_seen.get(label, 0) + 1
            go_calls.append((label,go_seen[label]))
            # Only the first item needs the existing single infra retry. The
            # second item's mutant crashed the Go test process: a kill, never
            # retried, whose runtime label reaches the row.
            bad = label == "first" and go_seen[label] == 1
            run = {"outcome":"container_error" if bad else "failed",
                "exit_code":1,"wall_seconds":0.1,"records":[],"expected_line":3,"stdout_tail":""}
            if label == "second":
                run["crash"] = "go_panic"
            return {"runs":[run],
                "written_files":[],"rejected_files":[],"index_errors":{},
                "registered_contexts":[],"outcomes":[],"substrate_violation":None}
        # The seed-installed applier, not this checkout's builder, is Go's
        # campaign applier identity.
        go_installed = [go_identity["applier_sha256"]]
        def go_installed_applier(harness):
            go_calls.append("applier")
            return go_installed[0]
        go_dispatch.validate_campaign=go_validate
        go_dispatch.installed_applier_sha256=go_installed_applier
        go_dispatch.MutationRuntimeRefused=RuntimeError
        go_dispatch.prepare_campaign=go_prepare
        go_dispatch.run_solution=go_execute
        forbidden = AssertionError("Go touched the host applier/mutant lifecycle")
        def go_run(out):
            with patch.dict(sys.modules,{"r2t.go.mutation_runtime":go_dispatch}), \
                    patch(__name__+".install_applier",side_effect=forbidden), \
                    patch(__name__+".apply_mutant",side_effect=forbidden), \
                    patch(__name__+".revert_mutant",side_effect=forbidden), \
                    patch(__name__+".remove_applier",side_effect=forbidden):
                run_slice(_FakeHarness(root),[m],
                    {i:{"item_id":i,"provenance":{"file_path":"f.feature","line":3}} for i in go_files},
                    go_files,{m["id"]:list(go_files)},PHP_ENGINE_DIR,out,
                    identity=go_identity,manifest=go_manifest,
                    engine="r2t-mutate-go",engine_version="1.0")
        go_run(go_out)
        go_rows=[json.loads(line) for line in open(go_out,encoding="utf-8")]
        check("Go applies inside each item/allowed retry and never mutates the host",
              go_calls == ["validate","applier","prepare",("first",1),("first",2),("second",1)]
              and [(r["item_id"],r["attempt"]) for r in go_rows] == [("i1",2),("i2",1)]
              and len(os.listdir(go_out + ".go-evidence")) == 3)
        check("a Go test-process crash row is a first-attempt `failed` kill "
              "carrying its crash label; other rows carry none",
              [(r["outcome"], r.get("crash")) for r in go_rows]
              == [("failed", None), ("failed", "go_panic")]
              and "crash" not in go_rows[0]
              and not go_rows[1]["retried_infrastructure"])
        # Later ramped shards join while the first shard's real Go attempt
        # directories are already present. Keep the historical output plan.
        import shutil
        go_pool = os.path.join(root, "go-ramp-output")
        go_paths = [os.path.join(go_pool, f"candidate.w{i}.jsonl") for i in range(2)]
        go_ids = [identity_for(go_files, set(), shard=i, of=2,
                  engine="r2t-mutate-go", engine_version="1.0") for i in range(2)]
        go_observation = prepare_standalone_output_directory(go_paths[0], go_ids[0])
        shutil.copytree(go_out + ".go-evidence", go_paths[0] + ".go-evidence")
        check("ramped Go shard joins after retained first-worker captures",
              prepare_standalone_output_directory(go_paths[1], go_ids[1]) == go_observation)
        for path in go_paths:
            atomic_write_bytes(path, b"", refuse_existing=True)
            atomic_write_json(provenance_path(path), {"observation_id": go_observation})
        check("closed Go output accepts its unchanged retained native captures",
              validate_standalone_output_directory(go_paths, go_ids[0]) == go_observation)
        stray = os.path.join(go_pool, "candidate.w9.jsonl.go-evidence")
        os.mkdir(stray)
        try:
            validate_standalone_output_directory(go_paths, go_ids[0])
            refused_go_capture = False
        except MutationAborted:
            refused_go_capture = True
        check("foreign Go evidence directory remains refused", refused_go_capture)
        os.rmdir(stray)
        # Owner ruling 2026-09-30: the runtime retired a copy its mutant test
        # only added files to and returns both scoped reports. The pair is one
        # `unscorable_substrate` row, never retried, and the slice goes on; a
        # violation the runtime did not recover still aborts it.
        added = {"changed": [], "missing": [], "added": ["external/x/c.yaml"]}
        scoped = {"copy": {**added, "mutated": [m["file"]]},
                  "original": {"changed": [], "missing": [], "added": [],
                               "mutated": []}}
        recovered = [True]
        def go_unscorable(harness, feature, scenario, sol, **kwargs):
            label = sol.files[0].code
            go_calls.append(label)
            result = {"runs": [], "written_files": [], "rejected_files": [],
                      "index_errors": {}, "registered_contexts": [],
                      "outcomes": [], "substrate_violation": added}
            if label == "second":
                result.update(substrate_violation=None, runs=[{
                    "outcome": "passed", "exit_code": 0, "wall_seconds": 0.1,
                    "records": [], "expected_line": 3, "stdout_tail": ""}])
            elif recovered[0]:
                result["unscorable_substrate"] = scoped
            return result
        go_dispatch.run_solution = go_unscorable
        go_dispatch.prepare_campaign = (
            lambda harness, doc, ident, *, artifacts:
            go_calls.append("prepare") or authority)
        go_calls.clear()
        go_unscorable_out = os.path.join(root, "go-unscorable.jsonl")
        go_run(go_unscorable_out)
        unscorable_rows = [json.loads(line) for line in
                           open(go_unscorable_out, encoding="utf-8")]
        check("a Go pair whose mutant test only added files is one "
              "first-attempt `unscorable_substrate` row carrying both scoped "
              "reports; it is not retried and the slice continues",
              go_calls == ["validate", "applier", "prepare", "first", "second"]
              and [(r["item_id"], r["outcome"], r["attempt"],
                    r["retried_infrastructure"], r["seconds"])
                   for r in unscorable_rows]
              == [("i1", "unscorable_substrate", 1, False, 0.0),
                  ("i2", "passed", 1, False, 0.1)]
              and unscorable_rows[0]["substrate_violation"] == scoped
              and "substrate_violation" not in unscorable_rows[1]
              and not _row_identity_problems(
                  unscorable_rows[0], go_identity,
                  campaign_identity_digest(go_identity))
              and json.load(open(provenance_path(go_unscorable_out),
                                 encoding="utf-8"))["status"] == "complete",
              str(unscorable_rows))
        go_calls.clear(); recovered[0] = False
        check("a Go substrate violation the runtime did not recover still "
              "aborts the slice at its first pair",
              _raises_mutation(lambda: go_run(
                  os.path.join(root, "go-unrecovered.jsonl")))
              and go_calls == ["validate", "applier", "prepare", "first"])
        go_dispatch.run_solution = go_execute
        go_dispatch.prepare_campaign = go_prepare
        go_calls.clear();go_installed[0] = "f" * 64
        go_other = os.path.join(root, "go-other-applier.jsonl")
        try:
            go_run(go_other)
            go_refusal = ""
        except MutationAborted as e:
            go_refusal = str(e)
        check("Go refuses a seed-installed applier other than the campaign "
              "applier before preparation or output",
              "applier bytes digest to " + "f" * 64 in go_refusal
              and go_calls == ["validate","applier"]
              and not os.path.lexists(go_other))
        check("non-Go campaigns keep the checkout applier identity and "
              "never read a seed",
              all(runtime_applier_sha256(name, os.path.join(root, "absent-seed"))
                  == sha256_file(os.path.join(bound.engine_dir, bound.applier.source))
                  for name, bound in engines().items() if name != "r2t-mutate-go"))

        # Go's immutable context join belongs before any mutation preparation.
        # These are metadata-only fixtures: no Go engine is registered or run.
        import copy
        from ..core.boundary import Boundary
        from ..go.context import ContextRefused, ContextTable, canonical_item

        go_item = canonical_item()
        go_item["files"].append("external/httpserver/bdd_other_test.go")
        go_ctx = go_item["go_suite"]
        go_id = go_item["item_id"]
        go_closure = {"item_id": go_id, "go_suite": go_ctx,
                      "files": go_item["files"],
                      "feature_file": go_ctx["feature_path"],
                      "scenario_line": go_ctx["scenario_line"]}
        go_table = ContextTable([go_closure], boundary=Boundary(
            1, "coddy-agent", root,
            removable=[(path, "answer") for path in go_item["files"]]),
            project="coddy-agent")
        go_files = {go_id: [{"file_path": path, "code": "package httpserver\n"}
                            for path in go_item["files"]]}
        go_pairs = {(go_id, m["id"])}
        go_identity = identity_for(go_files, go_pairs)
        go_cases = [
            ("missing context", lambda item: item.pop("go_suite")),
            ("changed context", lambda item:
                item["go_suite"].update(godog_tags="@other")),
            ("missing files", lambda item: item.pop("files")),
            ("missing sibling", lambda item: item["files"].pop()),
            ("missing harness context method", lambda item: None),
        ]
        for number, (label, alter) in enumerate(go_cases):
            broken = copy.deepcopy(go_item)
            alter(broken)
            context_harness = _FakeHarness(root)
            if label != "missing harness context method":
                context_harness.check_context = go_table.check_context
            go_out = os.path.join(root, f"go-context-refused-{number}.jsonl")
            preparation = RuntimeError("mutation preparation was reached")
            with patch.object(context_harness, "verify_substrate",
                              side_effect=preparation) as verify:
                refused = False
                try:
                    run_slice(context_harness, [m], {go_id: broken}, go_files,
                              {m["id"]: [go_id]}, PHP_ENGINE_DIR, go_out,
                              identity=go_identity)
                except ContextRefused:
                    refused = True
                except RuntimeError as exc:
                    if exc is not preparation:
                        raise
                check("mutation " + label + " refuses before preparation",
                      refused and not verify.called
                      and not context_harness.runner.calls
                      and not os.path.exists(go_out)
                      and not os.path.exists(provenance_path(go_out)))

        # The full candidate/map may contain items outside a worker's pair
        # plan. A malformed unselected Go item must not block the selected one.
        outside_id = "coddy-agent/features/unselected.feature:1"
        selection_items = {go_id: go_item, outside_id: {"item_id": outside_id}}
        selection_files = {**go_files, outside_id: []}
        selection_identity = identity_for(selection_files, go_pairs)
        selected_harness = _FakeHarness(root)
        selected_harness.check_context = go_table.check_context
        selected_out = os.path.join(root, "go-context-selected.jsonl")
        preparation = RuntimeError("selected context passed")
        with patch.object(selected_harness, "check_context",
                          wraps=go_table.check_context) as context_check, \
                patch.object(selected_harness, "verify_substrate",
                             side_effect=preparation):
            reached = False
            try:
                run_slice(selected_harness, [m], selection_items,
                          selection_files, {m["id"]: [go_id, outside_id]},
                          PHP_ENGINE_DIR, selected_out,
                          identity=selection_identity,
                          planned_pairs=(pair for pair in go_pairs))
            except RuntimeError as exc:
                if exc is not preparation:
                    raise
                reached = True
            check("mutation checks the exact multi-file item in an iterator "
                  "pair plan, leaving unselected items alone",
                  reached and context_check.call_count == 1
                  and context_check.call_args.args == (go_item,)
                  and not selected_harness.runner.calls
                  and not os.path.exists(selected_out))

        # D4 needs a whole mutant applied once but only the qualifying item's
        # pair executed.  The candidate/map stay complete and therefore keep
        # their original content identities; only the explicit pair plan
        # narrows execution.
        out6_pair = os.path.join(root, "pair-restricted.jsonl")
        files6_pair = {
            "i1": [{"file_path": "a.php", "code": "<?php"}],
            "i2": [{"file_path": "b.php", "code": "<?php"}],
        }
        planned6 = {("i1", m["id"])}
        identity6_pair = identity_for(files6_pair, planned6)
        run_slice(
            _FlakyHarness(root), [m],
            {iid: {"item_id": iid, "provenance": {
                "file_path": "f.feature", "line": 3}}
             for iid in files6_pair},
            files6_pair, {m["id"]: ["i1", "i2"]}, PHP_ENGINE_DIR,
            out6_pair, provenance={"manifest_digest": "a" * 64},
            identity=identity6_pair, planned_pairs=planned6)
        pair_rows = [json.loads(line) for line in open(
            out6_pair, encoding="utf-8") if line.strip()]
        check("pair-restricted mutation execution preserves the full "
              "candidate/map identity while emitting only planned pairs",
              {(row["item_id"], row["mutant_id"]) for row in pair_rows}
              == planned6
              and identity6_pair["solution_generated_tests_sha256"]
              == candidate_digest(files6_pair))
        try:
            run_slice(
                _FlakyHarness(root), [m],
                {iid: {"item_id": iid, "provenance": {
                    "file_path": "f.feature", "line": 3}}
                 for iid in files6_pair},
                files6_pair, {m["id"]: ["i1", "i2"]}, PHP_ENGINE_DIR,
                os.path.join(root, "pair-external.jsonl"),
                provenance={"manifest_digest": "a" * 64},
                identity=identity6_pair,
                planned_pairs={("outside", m["id"])})
            pair_external_refused = False
        except MutationAborted as exc:
            pair_external_refused = "candidate/map-external" in str(exc)
        check("pair restriction refuses a plan outside the unchanged "
              "candidate/map population before writing output",
              pair_external_refused)

        # ---------------------------------------------------------- LI2
        #
        # Resume into a shard that is already `complete` (review finding 8).
        # The documented K-way recovery re-issues all K commands with
        # --resume, so this is the ordinary path for every shard that had
        # already finished -- and at the reviewed head it rewrote the sidecar
        # to `running` before doing zero work, staged the applier, and let any
        # cleanup failure in that window write terminal `failed` over a
        # byte-identical attested shard.
        class _CleanupFails(_FlakyHarness):
            """A worker whose CLEANUP hook raises, and nothing else."""

            def __init__(self, root_):
                super().__init__(root_)
                self.cleanup_calls = 0

            def clear_registration(self):
                self.cleanup_calls += 1
                raise MutationAborted("simulated cleanup failure on resume")

        rows_before_resume = open(out6, "rb").read()
        side_before_resume = open(provenance_path(out6), "rb").read()
        rows_mtime = os.stat(out6).st_mtime_ns
        side_mtime = os.stat(provenance_path(out6)).st_mtime_ns
        cleanup_harness = _CleanupFails(root)
        staged_applier = os.path.join(cleanup_harness.root, PHP_APPLIER.rel)
        # Caught rather than propagated: a resume that RAISES over a complete
        # shard is this scenario's failure, and it must be reported as one
        # named check rather than as an aborted module.
        try:
            resumed_complete = run_slice(
                cleanup_harness, [m],
                {"i1": {"item_id": "i1", "provenance": {
                    "file_path": "f.feature", "line": 3}}},
                files6, {m["id"]: ["i1"]}, PHP_ENGINE_DIR, out6,
                provenance={"manifest_digest": "a" * 64}, identity=identity6,
                resume=True)
        except BaseException as e:                          # noqa: BLE001
            resumed_complete = {"status": f"raised {type(e).__name__}: {e}",
                                "read_only": None, "rows": None,
                                "resumed_rows": None}
        check("LI2: resuming a COMPLETE shard returns its recorded state "
              "read-only, executing no pair and no cleanup hook",
              resumed_complete["status"] == "complete"
              and resumed_complete["read_only"] is True
              and resumed_complete["rows"] == 0
              and resumed_complete["resumed_rows"] == 1
              and cleanup_harness.cleanup_calls == 0,
              str(resumed_complete))
        check("LI2: ...and the rows and sidecar keep their exact bytes and "
              "mtimes even though the cleanup hook WOULD have failed",
              open(out6, "rb").read() == rows_before_resume
              and open(provenance_path(out6), "rb").read()
              == side_before_resume
              and os.stat(out6).st_mtime_ns == rows_mtime
              and os.stat(provenance_path(out6)).st_mtime_ns == side_mtime)
        check("LI2: ...and no applier was staged into the workspace, so the "
              "no-op resume touched nothing at all",
              not os.path.lexists(staged_applier))

        # The other half of the same case: rows complete, sidecar never
        # attested (a kill between the final durable row and the completion
        # write). It must NOT be stranded -- §5 requires an interrupted
        # campaign to remain resumable -- so it takes the ordinary completion
        # path, still without staging an applier or running cleanup.
        unattested_dir = os.path.join(root, "unattested-complete")
        os.makedirs(unattested_dir)
        unattested = os.path.join(unattested_dir, "rows.jsonl")
        with open(unattested, "wb") as fh:
            fh.write(rows_before_resume)
        write_shard_provenance(unattested, identity6, "running")
        write_shard_provenance(unattested, identity6, "interrupted",
                               error="killed after its last row")
        unattested_rows = open(unattested, "rb").read()
        cleanup_harness2 = _CleanupFails(root)
        try:
            resumed_unattested = run_slice(
                cleanup_harness2, [m],
                {"i1": {"item_id": "i1", "provenance": {
                    "file_path": "f.feature", "line": 3}}},
                files6, {m["id"]: ["i1"]}, PHP_ENGINE_DIR, unattested,
                provenance={"manifest_digest": "a" * 64}, identity=identity6,
                resume=True)
        except BaseException as e:                          # noqa: BLE001
            resumed_unattested = {"status": f"raised {type(e).__name__}: {e}",
                                  "read_only": None, "rows": None}
        check("LI2: an INTERRUPTED shard whose rows are already the complete "
              "planned set is completed rather than stranded, without "
              "staging an applier or running cleanup",
              resumed_unattested["status"] == "complete"
              and resumed_unattested["read_only"] is False
              and resumed_unattested["rows"] == 0
              and cleanup_harness2.cleanup_calls == 0
              and open(unattested, "rb").read() == unattested_rows
              and json.load(open(provenance_path(unattested),
                                 encoding="utf-8"))["status"] == "complete",
              str(resumed_unattested))

        # A PARTIAL resume used to enter the live loop for every mutant whose
        # row was already authenticated, hashing the complete substrate once
        # for each before discovering that its covering list was empty.  Keep
        # enough completed groups here that the regression is structural, not
        # a timing-sensitive microbenchmark: 32 completed groups plus one
        # pending group must perform exactly the four campaign/pending checks
        # (campaign entry, pending pre-apply, pending post-revert, cleanup),
        # not 32 additional full-tree scans.
        class _CountingResume(_FlakyHarness):
            def __init__(self, root_):
                super().__init__(root_)
                self.substrate_checks = 0

            def verify_substrate(self):
                self.substrate_checks += 1
                return super().verify_substrate()

        completed_mutants = [
            {**m, "id": f"done{number:012d}"}
            for number in range(32)
        ]
        resume_mutants = completed_mutants + [m]
        resume_pairs = {("i1", mutant["id"])
                        for mutant in resume_mutants}
        resume_identity = identity_for(files6, resume_pairs)
        partial_resume = os.path.join(root, "partial-resume-pruned.jsonl")
        with open(partial_resume, "w", encoding="utf-8") as fh:
            for mutant in completed_mutants:
                fh.write(json.dumps(stamped_row(
                    resume_identity, "i1", mutant["id"],
                    operator=mutant["operator"], file=mutant["file"],
                    start_line=mutant["start_line"], attempt=1,
                    retried_infrastructure=False,
                    candidate_digest=candidate_digest(files6), seconds=0.1),
                    sort_keys=True) + "\n")
        write_shard_provenance(
            partial_resume, resume_identity, "running",
            provenance={"manifest_digest": "a" * 64})
        write_shard_provenance(
            partial_resume, resume_identity, "interrupted",
            provenance={"manifest_digest": "a" * 64},
            error="fixture interruption with one mutant group pending")
        counting_resume = _CountingResume(root)
        resumed_partial = run_slice(
            counting_resume, resume_mutants,
            {"i1": {"item_id": "i1", "provenance": {
                "file_path": "f.feature", "line": 3}}},
            files6, {mutant["id"]: ["i1"] for mutant in resume_mutants},
            PHP_ENGINE_DIR, partial_resume,
            provenance={"manifest_digest": "a" * 64},
            identity=resume_identity, resume=True)
        partial_rows = [json.loads(line) for line in open(
            partial_resume, encoding="utf-8") if line.strip()]
        check("T6: partial resume prunes 32 authenticated mutant groups "
              "before full-substrate scans and executes only the pending "
              "pair",
              counting_resume.substrate_checks == 4
              and resumed_partial["rows"] == 1
              and resumed_partial["resumed_rows"] == 32
              and len(partial_rows) == 33
              and partial_rows[-1]["mutant_id"] == m["id"],
              f"checks={counting_resume.substrate_checks}, "
              f"result={resumed_partial}")
        check("T6: the pending mutant retains both per-mutant integrity "
              "checks and the ordinary retry/terminal attestation",
              partial_rows[-1]["attempt"] == 2
              and partial_rows[-1]["retried_infrastructure"] is True
              and json.load(open(provenance_path(partial_resume),
                                 encoding="utf-8"))["status"] == "complete")

        wrong_claim = os.path.join(root, "wrong-claim.jsonl")
        try:
            run_slice(_FlakyHarness(root), [m],
                      {"i1": {"item_id": "i1", "provenance": {
                          "file_path": "f.feature", "line": 3}}},
                      files6, {m["id"]: ["i1"]}, PHP_ENGINE_DIR,
                      wrong_claim, identity=identity6,
                      provenance={"candidate_digest": "0" * 64})
            check("a caller cannot override the recomputed candidate digest",
                  False, "accepted")
        except MutationAborted as e:
            check("a caller cannot override the recomputed candidate digest",
                  "supplied generated tests" in str(e))
        check("candidate-digest refusal happens before any output is created",
              not os.path.lexists(wrong_claim)
              and not os.path.lexists(provenance_path(wrong_claim)))

        class _NoBaseline(_FlakyHarness):
            def verify_substrate(self):
                return {"baseline": False, "checked": 0, "changed": [],
                        "missing": [], "added": [], "mutated": []}

        no_baseline = os.path.join(root, "no-baseline.jsonl")
        try:
            run_slice(_NoBaseline(root), [m],
                      {"i1": {"item_id": "i1", "provenance": {
                          "file_path": "f.feature", "line": 3}}},
                      files6, {m["id"]: ["i1"]}, PHP_ENGINE_DIR,
                      no_baseline, identity=identity6)
            check("a mutation campaign without source hashes is refused",
                  False, "accepted")
        except MutationAborted as e:
            check("a mutation campaign without source hashes is refused",
                  "no source-hash baseline" in str(e))
        check("missing-baseline refusal precedes output and applier writes",
              not os.path.lexists(no_baseline)
              and not os.path.lexists(provenance_path(no_baseline)))

        class _DifferentBaseline(_FlakyHarness):
            def __init__(self, root):
                super().__init__(root)
                self.substrate_baseline_sha256 = "d" * 64

        different_baseline = os.path.join(root, "different-baseline.jsonl")
        try:
            run_slice(_DifferentBaseline(root), [m],
                      {"i1": {"item_id": "i1", "provenance": {
                          "file_path": "f.feature", "line": 3}}},
                      files6, {m["id"]: ["i1"]}, PHP_ENGINE_DIR,
                      different_baseline, identity=identity6)
            check("a pristine worker with another recorded baseline is "
                  "refused", False, "accepted")
        except MutationAborted as e:
            check("a pristine worker with another recorded baseline is "
                  "refused", "substrate baseline" in str(e))
        check("baseline-identity refusal precedes output and applier writes",
              not os.path.lexists(different_baseline)
              and not os.path.lexists(provenance_path(different_baseline)))

        other_applier = os.path.join(root, "other-applier.jsonl")
        try:
            run_slice(_FlakyHarness(root), [m],
                      {"i1": {"item_id": "i1", "provenance": {
                          "file_path": "f.feature", "line": 3}}},
                      files6, {m["id"]: ["i1"]}, PHP_ENGINE_DIR,
                      other_applier,
                      identity=dict(identity6, applier_sha256="f" * 64))
            other_refusal = ""
        except MutationAborted as e:
            other_refusal = str(e)
        check("a non-Go campaign still binds this checkout's applier source "
              "before output",
              "applier bytes digest to " + sha256_file(os.path.join(
                  PHP_ENGINE_DIR, PHP_APPLIER.source)) in other_refusal
              and not os.path.lexists(other_applier))

        locked_target = os.path.join(root, "concurrent-resume.jsonl")
        with output_lock(locked_target):
            try:
                with output_lock(locked_target):
                    pass
                nested_lock_refused = False
            except MutationAborted as e:
                nested_lock_refused = "another coordinator" in str(e)
        check("a second coordinator cannot concurrently resume one output",
              nested_lock_refused)

        restore_out = os.path.join(root, "restore-fails.jsonl")
        real_revert = globals()["revert_mutant"]

        def _restore_then_fail(harness_, applied_):
            real_revert(harness_, applied_)
            raise MutationAborted("simulated restoration verification failure")

        globals()["revert_mutant"] = _restore_then_fail
        try:
            try:
                run_slice(_FlakyHarness(root), [m],
                          {"i1": {"item_id": "i1", "provenance": {
                              "file_path": "f.feature", "line": 3}}},
                          files6, {m["id"]: ["i1"]}, PHP_ENGINE_DIR,
                          restore_out, identity=identity6)
                check("a restoration failure aborts the slice", False,
                      "accepted")
            except MutationAborted:
                check("a restoration failure aborts the slice", True)
        finally:
            globals()["revert_mutant"] = real_revert
        restore_side = json.load(open(provenance_path(restore_out),
                                      encoding="utf-8"))
        check("restoration failure can never leave complete provenance",
              restore_side["status"] == "failed"
              and restore_side["rows"] == 1,
              str({k: restore_side.get(k) for k in ("status", "rows", "error")}))

        other_rel = "src/CoreShop/Component/Order/Model/Other.php"
        other_path = os.path.join(root, other_rel)
        with open(other_path, "w", encoding="utf-8") as fh:
            fh.write("<?php // pristine\n")

        class _CorruptingHarness(_FlakyHarness):
            def run_solution(self, *args, **kwargs):
                result = super().run_solution(*args, **kwargs)
                with open(other_path, "a", encoding="utf-8") as fh:
                    fh.write("<?php // candidate corruption\n")
                return result

        corrupt_out = os.path.join(root, "corrupts-second-source.jsonl")
        try:
            run_slice(_CorruptingHarness(root), [m],
                      {"i1": {"item_id": "i1", "provenance": {
                          "file_path": "f.feature", "line": 3}}},
                      files6, {m["id"]: ["i1"]}, PHP_ENGINE_DIR,
                      corrupt_out, identity=identity6)
            check("changing a second retained source aborts the campaign",
                  False, "accepted")
        except MutationAborted as e:
            check("changing a second retained source aborts the campaign",
                  "not pristine" in str(e) or "cleanup/restoration" in str(e))
        corrupt_side = json.load(open(provenance_path(corrupt_out),
                                      encoding="utf-8"))
        check("a worker that changed any other source is quarantined as failed",
              corrupt_side["status"] == "failed")
        # A disposable worker would be reprovisioned.  The unit fixture restores
        # its byte so later independent checks start from a known baseline.
        with open(other_path, "w", encoding="utf-8") as fh:
            fh.write("<?php // pristine\n")

        # A signal must not bypass the restore.
        import signal as _sig
        h5 = _FlakyHarness(root)
        pristine = open(os.path.join(root, rel), encoding="utf-8").read()
        raised = {}

        def _boom_on_row(row):
            raise KeyboardInterrupt("simulated ^C mid-mutant")

        try:
            identity5 = identity_for({"i1": []}, {("i1", m["id"])})
            run_slice(h5, [m], {"i1": {"provenance": {"file_path": "f.feature",
                                                      "line": 3}}},
                      {"i1": []}, {m["id"]: ["i1"]},
                      os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/php",
                      os.path.join(root, "rows2.jsonl"), on_row=_boom_on_row,
                      identity=identity5)
        except BaseException as e:                          # noqa: BLE001
            raised["e"] = type(e).__name__
        check("an interrupt mid-mutant still restores the file",
              open(os.path.join(root, rel), encoding="utf-8").read() == pristine,
              raised.get("e", "no exception"))
        check("an interrupt leaves no mutation declared to the guard",
              h5.expected_mutations == {})

        if hasattr(os, "fork"):
            class _SlowHarness(_FlakyHarness):
                def run_solution(self, *args, **kwargs):
                    if not os.path.exists(signal_ready):
                        atomic_write_bytes(signal_ready, b"ready",
                                           refuse_existing=True)
                    time.sleep(0.25)
                    return super().run_solution(*args, **kwargs)

            signal_out = os.path.join(root, "signal.jsonl")
            signal_ready = os.path.join(root, "signal.ready")
            signal_identity = identity_for(files6, {("i1", m["id"])})
            pid = os.fork()
            if pid == 0:                                    # pragma: no cover
                try:
                    with coordinator_cancellation() as stop:
                        run_slice(
                            _SlowHarness(root), [m],
                            {"i1": {"item_id": "i1", "provenance": {
                                "file_path": "f.feature", "line": 3}}},
                            files6, {m["id"]: ["i1"]}, PHP_ENGINE_DIR,
                            signal_out, identity=signal_identity,
                            cancel_event=stop)
                except MutationCancelled:
                    os._exit(23)
                except BaseException:                        # noqa: BLE001
                    os._exit(24)
                os._exit(0)
            for _ in range(200):
                if os.path.isfile(signal_ready):
                    break
                time.sleep(0.005)
            os.kill(pid, _sig.SIGTERM)
            _waited, wait_status = os.waitpid(pid, 0)
            check("a real SIGTERM requests cooperative cancellation and exits "
                  "nonzero only after the current mutant is restored",
                  os.WIFEXITED(wait_status)
                  and os.WEXITSTATUS(wait_status) == 23,
                  str(wait_status))
            check("SIGTERM leaves the production source pristine",
                  open(os.path.join(root, rel), encoding="utf-8").read()
                  == pristine)
            signal_side = json.load(open(provenance_path(signal_out),
                                         encoding="utf-8"))
            check("a signalled shard is explicitly interrupted, never complete",
                  signal_side["status"] == "interrupted",
                  str(signal_side.get("status")))

        # -- and which applier a slice gets is the MANIFEST's engine, so a
        #    population cannot be executed by a program that could not have
        #    produced it.
        php_dir, php_ap = binding_for(ENGINE)
        check("a CoreShop manifest binds to php/mutate.php at the archived "
              "path -- every archived row came out of this pair",
              php_ap is PHP_APPLIER and php_dir == PHP_ENGINE_DIR
              and os.path.isfile(os.path.join(php_dir, php_ap.source)))
        py_dir, py_ap = binding_for("r2t-mutate-py")
        check("a python manifest binds to py/mutate.py, run by python3",
              py_ap.source == "mutate.py" and py_ap.interpreter == "python3"
              and os.path.isfile(os.path.join(py_dir, py_ap.source)),
              f"{py_dir} {py_ap}")
        check("...at its own staged path, still under var/",
              py_ap.rel.startswith("var/") and "_bench" not in py_ap.rel
              and py_ap.rel != php_ap.rel, py_ap.rel)
        java_dir, java_ap = binding_for("r2t-mutate-java")
        check("a Java manifest binds to the one javac-tree enumerate/apply "
              "source and its compiled entry point",
              java_ap.source == "Mutate.java"
              and java_ap.interpreter == "java"
              and java_ap.entrypoint is not None
              and java_ap.entrypoint == "Mutate"
              and java_ap.classes_rel == "var/bench_mutate/classes"
              and os.path.isfile(os.path.join(java_dir, java_ap.source)),
              f"{java_dir} {java_ap}")
        check("the Java applier has a distinct var/ staging path without "
              "claiming a cucumber harness",
              java_ap.rel.startswith("var/") and "_bench" not in java_ap.rel
              and java_ap.rel not in {php_ap.rel, py_ap.rel}, java_ap.rel)
        java_rel = "src/demo/Example.java"
        java_target = os.path.join(root, java_rel)
        os.makedirs(os.path.dirname(java_target), exist_ok=True)
        java_bytes = "class Example { int value = 1; }\n"
        with open(java_target, "w", encoding="utf-8") as fh:
            fh.write(java_bytes)
        java_m = dict(m, file=java_rel, start_line=1,
                      start_col=java_bytes.index("1") + 1,
                      end_line=1, end_col=java_bytes.index("1") + 1,
                      original="1", mutated="2")
        java_harness = _FakeHarness(root)
        staged_java = install_applier(java_harness, java_dir, java_ap)
        check("install_applier stages the exact Java producer source and "
              "compiles its entry point once before mutation execution",
              open(staged_java, encoding="utf-8").read()
              == open(os.path.join(java_dir, java_ap.source),
                      encoding="utf-8").read()
              and '"$JAVA_HOME/bin/javac" -proc:none -classpath '
              '"$JAVA_HOME/lib/tools.jar" '
              '-d var/bench_mutate/classes ' in
              java_harness.runner.calls[-1],
              java_harness.runner.calls[-1])
        from ..toolkit import mutation_java as _JAVA
        java_recipe = _JAVA.make_analysis_recipe(
            root, sourcepath=("src",))
        applied_java = apply_mutant(                       # type: ignore[arg-type]
            java_harness, java_m, java_ap,
            analysis_recipe=java_recipe)
        check("the Java campaign command runs the compiled class, not the "
              "source path as a second program, with its authenticated input "
              "outside the write root",
              java_harness.runner.calls[-1].startswith(
                  "\"$JAVA_HOME/bin/java\" -cp \"")
              and "$JAVA_HOME/lib/tools.jar\" Mutate --root "
              in java_harness.runner.calls[-1]
              and " --write-root /var/www/html "
              in java_harness.runner.calls[-1],
              java_harness.runner.calls[-1][:100])
        revert_mutant(java_harness, applied_java)          # type: ignore[arg-type]
        try:
            binding_for("infection")
            check("an unknown engine is REFUSED, never defaulted to php",
                  False, "accepted")
        except MutationAborted as e:
            check("an unknown engine is REFUSED, never defaulted to php",
                  "no applier for mutation engine" in str(e))

        check("the applier is staged under var/, never under _bench/",
              APPLIER_REL.startswith("var/") and "_bench" not in APPLIER_REL)
        check("...and so is any other stack's -- the rule is about the hashed "
              "substrate roots, not about PHP",
              PHP_APPLIER.rel.startswith("var/")
              and "_bench" not in PHP_APPLIER.rel)

        # -- a SECOND engine: the interpreter, the staged path and the source
        #    file all follow the Applier, and the flags do not change, because
        #    the applier contract is the same contract.
        py_applier = Applier(source="mutate.py", rel="var/bench_mutate/mutate.py",
                             interpreter="python3")
        h7 = _FakeHarness(root)
        apply_mutant(h7, m, py_applier)                  # type: ignore[arg-type]
        check("a second stack's applier is invoked by ITS interpreter at ITS "
              "path, with the same coordinates",
              h7.runner.calls[-1].startswith(
                  "python3 var/bench_mutate/mutate.py --root /var/www/html "
                  "--operator-profile v2 --apply-file ")
              and "--operator ArithmeticOperator" in h7.runner.calls[-1],
              h7.runner.calls[-1][:90])
        revert_mutant(h7, {"file": rel, "original":               # type: ignore
                           b"<?php\nreturn $a + $b;\n",
                           "lstat": _file_lstat_identity(
                               os.path.join(root, rel))})

        # -- the engine reaches the ROW, and a provenance that disagrees with
        #    it is refused rather than silently overwritten.
        out8 = os.path.join(root, "engine.jsonl")
        files8 = {"i1": [{"file_path": "a.php", "code": "<?php"}]}
        identity8 = identity_for(
            files8, {("i1", m["id"])}, engine="r2t-mutate-py",
            engine_version="1.0")
        info8 = run_slice(_FlakyHarness(root), [m],
                          {"i1": {"item_id": "i1",
                                  "provenance": {"file_path": "f.feature",
                                                 "line": 3}}},
                          files8,
                          {m["id"]: ["i1"]}, PHP_ENGINE_DIR, out8,
                          engine="r2t-mutate-py", engine_version="1.0",
                          provenance={"manifest_digest": "a" * 64},
                          identity=identity8)
        rows8 = [json.loads(l) for l in open(out8, encoding="utf-8") if l.strip()]
        check("every row says which engine minted its mutant",
              rows8 and rows8[0]["engine"] == "r2t-mutate-py"
              and rows8[0]["engine_version"] == "1.0", str(rows8[:1]))
        check("...and the provenance sidecar says the same thing",
              info8["provenance"]["engine"] == "r2t-mutate-py")
        check("the CoreShop default is still the PHP engine, so a row written "
              "the way every archived row was written names it",
              [json.loads(l) for l in open(out6, encoding="utf-8")
               if l.strip()][0]["engine"] == ENGINE)
        try:
            clash_identity = identity_for(
                {}, set(), engine="r2t-mutate-py",
                engine_version=ENGINE_VERSION)
            run_slice(_FlakyHarness(root), [], {}, {}, {}, PHP_ENGINE_DIR,
                      os.path.join(root, "clash.jsonl"),
                      engine="r2t-mutate-py",
                      provenance={"engine": ENGINE}, identity=clash_identity)
            check("a provenance that names another engine is refused",
                  False, "accepted")
        except MutationAborted as e:
            check("a provenance that names another engine is refused",
                  "which population is running" in str(e))

        # -- v1.1: generated class files across pairs AND mutants.  A pair run
        #    while a CoreExtension return-type mutant is applied re-saves the
        #    production class from mutated source -- the retained
        #    `Setup\ClassContext` save that voided the first CoreShop
        #    references.  The mutant revert restores only its source file, so
        #    the REAL `Harness.restore_derived_state`, at the point
        #    `Harness._run_solution` calls it, is what must hand every later
        #    pair and the next mutant the seed's bytes.
        from .harness import Harness as _PhpHarness
        from . import repo as _repo_module
        droot = os.path.join(root, "derived")
        os.makedirs(os.path.join(droot, os.path.dirname(rel)))
        with open(os.path.join(droot, "f.feature"), "w",
                  encoding="utf-8") as fh:
            fh.write("Feature: f\n\n  Scenario: s\n    Given a\n")
        product_rel = "var/classes/DataObject/CoreShopProduct.php"
        behat_rel = "var/classes/definition_BehatX.php"
        seed_class = b"<?php\npublic function getUnitDefinitions(): ?U {}\n"
        broken_class = b"<?php\npublic function getUnitDefinitions() {}\n"
        derived_baseline = {product_rel: seed_class}

        def reset_derived_fixture():
            with open(os.path.join(droot, rel), "w", encoding="utf-8") as fh:
                fh.write("<?php\nreturn $a + $b;\n")
            os.makedirs(os.path.join(droot, os.path.dirname(product_rel)),
                        exist_ok=True)
            with open(os.path.join(droot, product_rel), "wb") as fh:
                fh.write(seed_class)
            if os.path.exists(os.path.join(droot, behat_rel)):
                os.remove(os.path.join(droot, behat_rel))

        class _RegeneratingHarness(_FakeHarness):
            """psvi in miniature: a pair under a mutant regenerates the
            production class and generates a scenario-owned Behat% class."""

            restore_derived_state = _PhpHarness.restore_derived_state

            def __init__(self, root_, baseline):
                super().__init__(root_)
                self.derived_baseline = baseline
                self.entries = []

            def run_solution(self, feature, scenario, sol, **kw):
                # `Harness._run_solution`'s order: verify, restore, execute.
                self.verify_substrate()
                self.restore_derived_state()
                with open(os.path.join(self.root, product_rel), "rb") as fh:
                    self.entries.append(fh.read())
                if self.expected_mutations:
                    with open(os.path.join(self.root, product_rel),
                              "wb") as fh:
                        fh.write(broken_class)
                    with open(os.path.join(self.root, behat_rel), "wb") as fh:
                        fh.write(b"<?php // generated by the scenario\n")
                return {"runs": [{"outcome": "failed", "exit_code": 1,
                                  "wall_seconds": 0.1, "records": [
                                      {"scenario_line": 1,
                                       "steps": [{"text": "s",
                                                  "result": "failed",
                                                  "seconds": 0.1,
                                                  "exception": None}]}],
                                  "expected_line": 1, "stdout_tail": ""}],
                        "written_files": [], "rejected_files": [],
                        "index_errors": {}, "registered_contexts": [],
                        "outcomes": [], "substrate_violation": None}

        m_next = dict(m, id="0123456789abcd02")
        derived_files = {"i1": [{"file_path": "a.php", "code": "<?php"}],
                         "i2": [{"file_path": "b.php", "code": "<?php"}]}
        derived_items = {iid: {"item_id": iid, "provenance": {
            "file_path": "f.feature", "line": 3}} for iid in derived_files}
        derived_map = {m["id"]: ["i1", "i2"], m_next["id"]: ["i1"]}
        derived_identity = identity_for(
            derived_files, {("i1", m["id"]), ("i2", m["id"]),
                            ("i1", m_next["id"])})

        def derived_run(harness, name):
            return run_slice(harness, [m, m_next], derived_items,
                             derived_files, derived_map, PHP_ENGINE_DIR,
                             os.path.join(droot, name),
                             identity=derived_identity)

        def product_on_disk():
            with open(os.path.join(droot, product_rel), "rb") as fh:
                return fh.read()

        reset_derived_fixture()
        restoring = _RegeneratingHarness(droot, derived_baseline)
        restored_slice = derived_run(restoring, "derived-restored.jsonl")
        check("v1.1: after a pair regenerates the class under a mutant, the "
              "NEXT pair of that mutant and the NEXT mutant's first pair both "
              "start from the seed's bytes",
              restoring.entries == [seed_class, seed_class, seed_class],
              str(restoring.entries))
        check("v1.1: ...while the Behat% class the scenario generated beside "
              "it survives every restore, for the purge that owns it",
              os.path.isfile(os.path.join(droot, behat_rel)))
        check("v1.1: the shard's LAST pair also regenerated the class, and "
              "the completed shard hands its worker on holding the seed's "
              "bytes (run_slice's cleanup restores once more)",
              restored_slice["status"] == "complete"
              and product_on_disk() == seed_class, repr(product_on_disk()))

        reset_derived_fixture()
        unrestored = _RegeneratingHarness(droot, {})
        derived_run(unrestored, "derived-unrestored.jsonl")
        check("v1.1 COUNTER: without the restore the second pair already "
              "sees the class the first pair generated under the mutant, and "
              "so does the next mutant -- the H12 defect -- and the shard "
              "ends holding the broken class",
              unrestored.entries == [seed_class, broken_class, broken_class]
              and product_on_disk() == broken_class,
              str(unrestored.entries))

        # -- harness 27: a non-debug Symfony kernel's cache pools between
        #    pairs of the SAME item.  Sylius's `test_cached` keeps validator
        #    metadata (built constraint objects) in `<cache_dir>/pools`, and a
        #    hit never runs the constraint constructor.  The container is
        #    rebuilt only when the item changes, so a constraint-constructor
        #    mutant whose worker last ran the same item read metadata built
        #    without it and survived.  The fake reads the pool on a hit and
        #    fills it from the source on a miss; the pool starts filled from
        #    unmutated source, as an earlier pair elsewhere leaves it.
        import subprocess
        import types
        from .harness import COLD_POOL_PROJECTS
        proot = os.path.join(root, "pooled")
        os.makedirs(os.path.join(proot, os.path.dirname(rel)))
        with open(os.path.join(proot, "f.feature"), "w",
                  encoding="utf-8") as fh:
            fh.write("Feature: f\n\n  Scenario: s\n    Given a\n")
        pristine_source = "<?php\nreturn $a + $b;\n"
        pool_rel = "var/cache/test_cached/pools/system/validator.php"

        class _RmRunner(_FakeRunner):
            """`_FakeRunner`, but `rm -rf` really runs, in the tree."""

            def run(self, inner, env=None, timeout=900):
                if inner.startswith("rm -rf -- "):
                    return subprocess.run(["sh", "-c", inner], cwd=self.root,
                                          capture_output=True, text=True,
                                          timeout=timeout)
                return super().run(inner, env=env, timeout=timeout)

        class _PooledHarness(_FakeHarness):
            clear_cache_pools = _PhpHarness.clear_cache_pools

            def __init__(self, root_, project):
                super().__init__(root_)
                self.runner = _RmRunner(root_)
                self.boundary = types.SimpleNamespace(project=project)
                self.behat = types.SimpleNamespace(
                    cache_dir="var/cache/test_cached")
                self.entries = []

            def run_solution(self, feature, scenario, sol, **kw):
                pool = os.path.join(self.root, pool_rel)
                self.entries.append(os.path.exists(pool))
                if not os.path.exists(pool):
                    os.makedirs(os.path.dirname(pool), exist_ok=True)
                    with open(os.path.join(self.root, rel),
                              encoding="utf-8") as fh_src, \
                            open(pool, "w", encoding="utf-8") as fh_pool:
                        fh_pool.write(fh_src.read())
                with open(pool, encoding="utf-8") as fh:
                    built_mutated = fh.read() != pristine_source
                result = "failed" if built_mutated else "passed"
                return {"runs": [{"outcome": result,
                                  "exit_code": int(built_mutated),
                                  "wall_seconds": 0.1, "records": [
                                      {"scenario_line": 1,
                                       "steps": [{"text": "s",
                                                  "result": result,
                                                  "seconds": 0.1,
                                                  "exception": None}]}],
                                  "expected_line": 1, "stdout_tail": ""}],
                        "written_files": [], "rejected_files": [],
                        "index_errors": {}, "registered_contexts": [],
                        "outcomes": [], "substrate_violation": None}

        pooled_files = {"i1": [{"file_path": "a.php", "code": "<?php"}]}
        pooled_items = {"i1": {"item_id": "i1", "provenance": {
            "file_path": "f.feature", "line": 3}}}
        pooled_map = {m["id"]: ["i1"], m_next["id"]: ["i1"]}

        def pooled_run(project, name):
            with open(os.path.join(proot, rel), "w", encoding="utf-8") as fh:
                fh.write(pristine_source)
            pool = os.path.join(proot, pool_rel)
            os.makedirs(os.path.dirname(pool), exist_ok=True)
            with open(pool, "w", encoding="utf-8") as fh:
                fh.write(pristine_source)
            harness = _PooledHarness(proot, project)
            out = os.path.join(proot, name)
            run_slice(harness, [m, m_next], pooled_items, pooled_files,
                      pooled_map, PHP_ENGINE_DIR, out,
                      identity=identity_for(pooled_files,
                                            {("i1", m["id"]),
                                             ("i1", m_next["id"])}))
            with open(out, encoding="utf-8") as fh:
                outcomes = [json.loads(line)["outcome"] for line in fh]
            return harness, outcomes, os.path.exists(pool)

        cold, cold_outcomes, cold_left = pooled_run("sylius", "pooled.jsonl")
        check("h27: on Sylius the pools are emptied before every pair, so "
              "two mutants on the same item in a row are each built under "
              "their own mutant and both killed, and the shard hands its "
              "worker on with no pools",
              "sylius" in COLD_POOL_PROJECTS
              and cold.entries == [False, False]
              and cold_outcomes == ["failed", "failed"] and not cold_left,
              str((cold.entries, cold_outcomes, cold_left)))
        warm, warm_outcomes, warm_left = pooled_run("coreshop",
                                                    "pooled-debug.jsonl")
        check("h27 COUNTER: a debug-kernel project keeps its pools, and on "
              "this fake that is the harness-26 defect: both same-item pairs "
              "read the unmutated pool and survive",
              "coreshop" not in COLD_POOL_PROJECTS
              and warm.entries == [True, True]
              and warm_outcomes == ["passed", "passed"] and warm_left,
              str((warm.entries, warm_outcomes, warm_left)))

        reset_derived_fixture()
        host_writer = _repo_module._write_seed_bytes

        def host_refuses(*_args):
            raise PermissionError(13, "Permission denied")

        derived_out = os.path.join(droot, "derived-untaken.jsonl")
        _repo_module._write_seed_bytes = host_refuses
        try:
            # `_FakeRunner` accepts the in-container copy and does nothing.
            # The cleanup's restore fails the same way and becomes the
            # reported error, with the pair's refusal as its cause.
            derived_run(_RegeneratingHarness(droot, derived_baseline),
                        os.path.basename(derived_out))
            untaken = "accepted"
        except (MutationAborted, _repo_module.DerivedStateUnrestored) as exc:
            untaken = str(exc)
        finally:
            _repo_module._write_seed_bytes = host_writer
        untaken_side = json.load(open(provenance_path(derived_out),
                                      encoding="utf-8"))
        check("v1.1: a restore that cannot take aborts the shard: the sidecar "
              "is failed and says the worker must be reprovisioned, after "
              "the one row that was measured",
              "must be reprovisioned" in untaken
              and untaken_side["status"] == "failed"
              and "must be reprovisioned" in untaken_side.get("error", "")
              and untaken_side["rows"] == 1,
              str({k: untaken_side.get(k) for k in ("status", "rows",
                                                    "error")}))
        with open(os.path.join(droot, rel), encoding="utf-8") as fh:
            reverted = fh.read()
        check("v1.1: ...and the mutant is still reverted on the way out",
              reverted == "<?php\nreturn $a + $b;\n", reverted)

        reset_derived_fixture()
        from .repo import SubstrateTampered
        from .prestashop_resources import ResourceResetError

        class _OriginalAndCleanupFailure(_FakeHarness):
            def run_solution(self, *args, **kwargs):
                raise SubstrateTampered({"changed": ["shop.json"]})

            def restore_derived_state(self, **kwargs):
                raise ResourceResetError("fixture restoration refused")

        both_out = os.path.join(droot, "original-and-cleanup.jsonl")
        try:
            derived_run(_OriginalAndCleanupFailure(droot),
                        os.path.basename(both_out))
            both_failure = None
        except MutationAborted as exc:
            both_failure = exc
        both_side = json.load(open(provenance_path(both_out),
                                   encoding="utf-8"))
        check("cleanup failure preserves the distinct original exception in "
              "both the raised error and durable failed sidecar",
              isinstance(both_failure, MutationAborted)
              and isinstance(both_failure.__cause__, SubstrateTampered)
              and all(message in str(both_failure)
                      and message in both_side.get("error", "")
                      for message in (
                          "SubstrateTampered:", "changed: shop.json",
                          "ResourceResetError: fixture restoration refused"))
              and both_side["status"] == "failed"
              and both_side["rows"] == 0,
              str(both_side))

        # Every pair's own restore takes; only the one after the LAST pair
        # does not (the host is refused once all three pairs have run).
        reset_derived_fixture()
        last_refused = _RegeneratingHarness(droot, derived_baseline)

        def host_refuses_after_last_pair(*args):
            if len(last_refused.entries) == 3:
                raise PermissionError(13, "Permission denied")
            return host_writer(*args)

        last_out = os.path.join(droot, "derived-last-untaken.jsonl")
        _repo_module._write_seed_bytes = host_refuses_after_last_pair
        try:
            derived_run(last_refused, os.path.basename(last_out))
            last_untaken = "accepted"
        except MutationAborted as exc:
            last_untaken = str(exc)
        finally:
            _repo_module._write_seed_bytes = host_writer
        last_side = json.load(open(provenance_path(last_out),
                                   encoding="utf-8"))
        check("v1.1: when the restore after the last pair cannot take, the "
              "shard is failed (all three rows measured) and says the worker "
              "must be reprovisioned, instead of completing on a worker "
              "that holds the class the last pair regenerated",
              last_refused.entries == [seed_class] * 3
              and "DerivedStateUnrestored" in last_untaken
              and "must be reprovisioned" in last_untaken
              and "Original campaign error:" not in last_untaken
              and last_side["status"] == "failed"
              and "DerivedStateUnrestored" in last_side.get("error", "")
              and last_side["rows"] == 3,
              str({k: last_side.get(k) for k in ("status", "rows", "error")}))

        reset_derived_fixture()
        from ..core.boundary import load_boundary as _load_boundary
        php_boundary = _load_boundary(os.path.join(
            BENCHMARK_ROOT, "config", "boundary_coreshop.yml"),
            repo_root=droot)
        from .harness import DockerRunner as _DockerRunner
        from .repo import StripManifest as _StripManifest

        def php_harness(baseline, boundary=php_boundary):
            return _PhpHarness(
                _StripManifest(repo_root=droot, gold_root=droot),
                boundary, _DockerRunner("none", docker_group=False),
                derived_baseline=baseline)

        unattached_out = os.path.join(droot, "derived-unattached.jsonl")
        try:
            run_slice(php_harness(None), [m], derived_items, derived_files,
                      {m["id"]: ["i1", "i2"]}, PHP_ENGINE_DIR, unattached_out,
                      identity=identity_for(derived_files,
                                            {("i1", m["id"]),
                                             ("i2", m["id"])}))
            unattached = "accepted"
        except MutationAborted as exc:
            unattached = str(exc)
        try:
            run_slice(php_harness(derived_baseline), [m], derived_items,
                      derived_files, {m["id"]: ["i1", "i2"]}, PHP_ENGINE_DIR,
                      unattached_out,
                      identity=identity_for(derived_files,
                                            {("i1", m["id"]),
                                             ("i2", m["id"])}))
            attached = "accepted"
        except MutationAborted as exc:
            attached = str(exc)
        check("v1.1: a Pimcore harness whose route attached no derived baseline "
              "is refused before any output, and one that carries it passes "
              "that gate (and stops at the next one, the absent source "
              "baseline of this fixture)",
              "no derived-state baseline" in unattached
              and "no derived-state baseline" not in attached
              and "no source-hash baseline" in attached
              and not os.path.lexists(unattached_out),
              f"{unattached} / {attached}")
        from .prestashop_resources import ResourceResetError
        for project, next_gate in (
                ("prestashop", "fresh strip with native resource inputs"),
                ("sylius", "no source-hash baseline")):
            boundary = _load_boundary(os.path.join(
                BENCHMARK_ROOT, "config", f"boundary_{project}.yml"),
                repo_root=droot)
            try:
                run_slice(php_harness(None, boundary), [m], derived_items,
                          derived_files, {m["id"]: ["i1", "i2"]}, PHP_ENGINE_DIR,
                          unattached_out,
                          identity=identity_for(derived_files,
                                               {("i1", m["id"]), ("i2", m["id"])}))
                result = "accepted"
            except (MutationAborted, ResourceResetError) as exc:
                result = str(exc)
            check(f"{project}: an empty derived baseline reaches the independent "
                  "substrate gate without fabricating Pimcore classes",
                  "no derived-state baseline" not in result
                  and next_gate in result
                  and not os.path.lexists(unattached_out), result)

    # The guard itself: a declared mutation is allowed, an undeclared one is not.
    from ..core.boundary import load_boundary
    from .repo import StripManifest, verify_substrate
    here = BENCHMARK_ROOT
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, "src"))
        p = os.path.join(root, "src", "X.php")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("<?php // one\n")
        b = load_boundary(os.path.join(here, "config", "boundary_coreshop.yml"),
                          repo_root=root)
        man = StripManifest(repo_root=root, gold_root=root,
                            digests={"src/X.php": _sha256(p)})
        check("an unchanged tree is clean",
              not verify_substrate(man, b)["changed"])
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("<?php // two\n")
        check("an UNDECLARED production change is still reported",
              verify_substrate(man, b)["changed"] == ["src/X.php"])
        rep = verify_substrate(man, b, expected={"src/X.php": _sha256(p)})
        check("a DECLARED mutation is allowed and named",
              not rep["changed"] and rep["mutated"] == ["src/X.php"], str(rep))
        rep2 = verify_substrate(man, b, expected={"src/X.php": "0" * 64})
        check("declaring a DIFFERENT digest does not launder the change",
              rep2["changed"] == ["src/X.php"])

    print("\n" + ("ALL PASS (mutation_run)" if ok else "FAILURES (mutation_run)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
