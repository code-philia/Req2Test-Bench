"""Project-neutral live mutation/test-quality admission and orchestration.

This module is the section-11.1 authority boundary from
``LIVE_TEST_QUALITY_SPEC.md``.  It deliberately owns no project adapters and
no mutation arithmetic.  A focused adapter supplies a reviewed policy,
freshly validated role/material facts, the applicable execution-authority
fact, and one executor callback.  This module joins those facts to #203 and
then delegates durable execution and scoring to :mod:`r2t.bench.test_quality`.

The validated binding below is in-memory only.  It is not a declaration,
artifact schema, registry, or Boolean route flag.  In particular, historical
``campaign-results-descriptor/v1.mutation_capable`` values never enter this
module.
"""
from __future__ import annotations

import copy
import json
import os
import secrets
from dataclasses import dataclass
from typing import Mapping, Optional


UNSUPPORTED = "unsupported"
PRESERVED_EVIDENCE_ONLY = "preserved-evidence-only"
LIVE_CAPABLE = "live-capable"
READINESS_STATES = (UNSUPPORTED, PRESERVED_EVIDENCE_ONLY, LIVE_CAPABLE)

GOLD_ONBOARDING = "gold-onboarding"
LIVE_CANDIDATE = "live-candidate"
GOLD_ONBOARDING_REQUIRED_ROLES = (
    "mutation_validation", "scored_manifest", "mutation_map",
    "gold_baseline",
)


class LiveTestQualityRefused(RuntimeError):
    """A prospective live route whose reviewed authority does not join."""


def _refuse(message: str):
    raise LiveTestQualityRefused(f"REFUSED: {message}")


@dataclass(frozen=True)
class MutationCapability:
    """The validated #203 mutation declaration, without a route decision."""

    project: str
    supported: bool
    note: Optional[str]
    role_paths: tuple[tuple[str, str], ...]

    def roles(self) -> dict[str, str]:
        return dict(self.role_paths)


@dataclass(frozen=True)
class MutationReadiness:
    """One of the three derived issue-#205 results."""

    state: str
    capability: MutationCapability
    detail: str


_BINDING_SEAL = object()


@dataclass(frozen=True)
class _ValidatedLiveBinding:
    """Opaque, validated and non-persistable producer authority."""

    project: str
    bundle_version: str
    leg: str
    role_paths: tuple[tuple[str, str], ...]
    role_facts: tuple[tuple[str, str, str], ...]
    policy: Mapping[str, object]
    authority: Mapping[str, object]
    observation_workloads: tuple[tuple[object, ...], ...]
    adapter: object
    seal: object


@dataclass(frozen=True)
class _FixtureCandidateSeal:
    """Network-free selftest substitute for a verified result-v3 receipt."""

    path: str
    binding: tuple[tuple[str, str], ...]


_FIXTURE_AUTHORITY_SEAL = object()


@dataclass(frozen=True)
class _FixtureExecutionAuthority:
    """Private Docker-free substitute for a revalidated v3 worker pool."""

    project: str
    bundle_version: str
    leg: str
    policy_identity: str
    runtime: Mapping[str, object]
    seal: object


_ADMITTED_GOLD_SEAL = object()


@dataclass(frozen=True)
class _AdmittedInstalledGold:
    """In-memory installed-role/N=2 admission, never a persisted schema."""

    project: str
    bundle_version: str
    policy_identity: str
    policy_json: str
    identity_inputs_json: str
    role_facts: tuple[tuple[str, str, str], ...]
    records: tuple[Mapping[str, object], ...]
    hard_subset_sha256: Optional[str]
    seal: object


def resolve_mutation_capability(
        project: str, declaration: object) -> MutationCapability:
    """Validate and return the one #203 mutation capability declaration."""
    from ..data.release import ManifestRefused, _check_capabilities

    if not isinstance(project, str) or not project:
        _refuse("mutation capability needs a non-empty project identity")
    if not isinstance(declaration, dict):
        _refuse(f"{project} mutation capability is undeclared")
    try:
        capabilities = _check_capabilities(project, declaration)
    except ManifestRefused as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    supported = capabilities["mutation"]
    note = (declaration.get("capability_notes") or {}).get("mutation")
    artifacts = ((declaration.get("bundle") or {}).get("artifacts")
                 if isinstance(declaration.get("bundle"), dict) else None)
    role_paths = []
    if isinstance(artifacts, dict):
        from ..data.release import CAPABILITY_REQUIRED_ROLES
        for role in CAPABILITY_REQUIRED_ROLES["mutation"]:
            path = artifacts.get(role)
            if isinstance(path, str) and path:
                role_paths.append((role, path))
    return MutationCapability(
        project=project, supported=supported, note=note,
        role_paths=tuple(role_paths))


def _required_role_paths(
        capability: MutationCapability, required: tuple[str, ...]) \
        -> dict[str, str]:
    roles = capability.roles()
    missing = [role for role in required if role not in roles]
    if missing:
        _refuse(
            f"{capability.project} mutation declaration is missing required "
            f"installed role(s) {missing}")
    return {role: roles[role] for role in required}


def _validated_install(project: str, bundle_version: str,
                       installed_bundle: object) -> None:
    if not isinstance(installed_bundle, dict):
        _refuse(f"installed bundle validation refused: {installed_bundle}")
    if installed_bundle.get("project") != project:
        _refuse(
            "validated installed bundle fact names project "
            f"{installed_bundle.get('project')!r}, not {project!r}")
    if installed_bundle.get("version") != bundle_version:
        _refuse(
            "validated installed bundle fact names version "
            f"{installed_bundle.get('version')!r}, not {bundle_version!r}")


def _adapter_call(adapter: object, name: str, leg: str):
    callback = getattr(adapter, name, None)
    if not callable(callback):
        _refuse(f"live adapter does not implement {name}()")
    try:
        return callback(leg)
    except LiveTestQualityRefused:
        raise
    except Exception as exc:  # noqa: BLE001 - adapter refusals are named here
        _refuse(f"live adapter {name}() refused: {exc}")


def _role_facts(material: object, required: Mapping[str, str]) \
        -> tuple[tuple[str, str, str], ...]:
    facts = material.get("role_facts") if isinstance(material, dict) else None
    if not isinstance(facts, dict):
        _refuse("live adapter returned no validated role facts")
    extras = sorted(set(facts) - set(required))
    missing = sorted(set(required) - set(facts))
    if missing or extras:
        _refuse(
            "validated role facts differ from this leg's portable roles: "
            f"missing={missing}, unexpected={extras}")
    out = []
    for role, declared_path in required.items():
        fact = facts.get(role)
        if not isinstance(fact, dict) or set(fact) != {"path", "identity"}:
            _refuse(f"validated {role} fact must name path and identity")
        path = fact.get("path")
        identity = fact.get("identity")
        if path != declared_path:
            _refuse(
                f"validated {role} path {path!r} differs from declaration "
                f"{declared_path!r}")
        if not isinstance(identity, str) or not identity:
            _refuse(f"validated {role} fact has no non-empty identity")
        out.append((role, path, identity))
    return tuple(out)


_POLICY_FIELDS = frozenset({
    "population_id", "manifest_digest", "engine", "engine_version", "parser",
    "timeout_seconds", "workers", "shard_policy", "execution_policy",
    "batch_plan_sha256", "max_batch_members", "max_batch_instances",
    "stack_reset_sha256", "batch_journal_schema",
    "confirmation", "gold_observations", "needs_database", "network",
    "database_dump_digest", "compute_cap_seconds",
    "compute_cap_review_authority",
})


def _validated_policy(raw: object) -> dict:
    from . import mutation_run as MR
    from . import test_quality as TQ

    if not isinstance(raw, dict) or set(raw) != _POLICY_FIELDS:
        got = sorted(raw) if isinstance(raw, dict) else type(raw).__name__
        _refuse(
            f"live policy must contain exactly {sorted(_POLICY_FIELDS)}; "
            f"got {got}")
    policy = copy.deepcopy(raw)
    for key in ("manifest_digest", "engine", "engine_version", "parser"):
        if not isinstance(policy[key], str) or not policy[key]:
            _refuse(f"live policy {key} must be a non-empty string")
    for key in ("timeout_seconds", "workers"):
        if not isinstance(policy[key], int) or isinstance(policy[key], bool) \
                or policy[key] < 1:
            _refuse(f"live policy {key} must be a positive integer")
    if policy["shard_policy"] != TQ.SHARD_POLICY_BALANCED_PAIRS_V1:
        _refuse(
            "a new ordinary live campaign requires "
            f"{TQ.SHARD_POLICY_BALANCED_PAIRS_V1!r} shard policy")
    population_id = policy["population_id"]
    if population_id is not None \
            and (not isinstance(population_id, str) or not population_id):
        _refuse("live policy population_id must be non-empty or null")
    execution_policy = policy["execution_policy"]
    batch_fields = {
        "batch_plan_sha256": policy["batch_plan_sha256"],
        "max_batch_members": policy["max_batch_members"],
        "max_batch_instances": policy["max_batch_instances"],
        "stack_reset_sha256": policy["stack_reset_sha256"],
        "batch_journal_schema": policy["batch_journal_schema"],
    }
    if execution_policy == MR.EXECUTION_POLICY_SCALAR_V1:
        if any(value is not None for value in batch_fields.values()):
            _refuse("scalar live policy carries batch-only fields")
    elif execution_policy == MR.EXECUTION_POLICY_BATCH_BISECT_V1:
        for key in ("batch_plan_sha256", "stack_reset_sha256"):
            value = batch_fields[key]
            if not isinstance(value, str) or len(value) != 64 \
                    or any(ch not in "0123456789abcdef" for ch in value):
                _refuse(f"batch live policy has invalid {key}")
        for key in ("max_batch_members", "max_batch_instances"):
            value = batch_fields[key]
            if not isinstance(value, int) or isinstance(value, bool) \
                    or value < 1:
                _refuse(f"batch live policy has invalid {key}")
        if not isinstance(batch_fields["batch_journal_schema"], str) \
                or not batch_fields["batch_journal_schema"]:
            _refuse("batch live policy has no journal schema")
    else:
        _refuse(f"live policy has unknown execution policy {execution_policy!r}")
    if policy["confirmation"] not in {"none", "d4"}:
        _refuse("live policy confirmation must be 'none' or 'd4'")
    if policy["confirmation"] == "d4" \
            and execution_policy != MR.EXECUTION_POLICY_SCALAR_V1:
        _refuse(
            "D4 run 2 is an existing standalone scalar mutation observation; "
            "the current native identity cannot bind batch execution "
            "semantics, so batch-plus-D4 remains closed")
    observations = policy["gold_observations"]
    if not isinstance(observations, list) or not observations:
        _refuse("live policy must enumerate its gold/control observations")
    seen = set()
    full_gold = 0
    for number, observation in enumerate(observations, 1):
        if not isinstance(observation, dict) \
                or set(observation) != {"role", "kind", "expected_pairs"}:
            _refuse(
                f"gold observation policy {number} must name role, kind, "
                "and expected_pairs")
        role = observation["role"]
        kind = observation["kind"]
        pairs = observation["expected_pairs"]
        if not isinstance(role, str) or not role or role in seen:
            _refuse("gold observation roles must be distinct non-empty strings")
        seen.add(role)
        if kind not in {"full_gold", "control"}:
            _refuse(f"gold observation {role!r} has unknown kind {kind!r}")
        if kind == "full_gold":
            full_gold += 1
        if not isinstance(pairs, list) or any(
                not isinstance(pair, list) or len(pair) != 2
                or not all(isinstance(value, str) and value for value in pair)
                for pair in pairs):
            _refuse(f"gold observation {role!r} has malformed expected pairs")
        canonical = sorted({tuple(pair) for pair in pairs})
        if len(canonical) != len(pairs) \
                or [list(pair) for pair in canonical] != pairs:
            _refuse(
                f"gold observation {role!r} expected pairs must be unique "
                "and canonically sorted")
    if full_gold != 2:
        _refuse("gold policy requires exactly two full-gold observations")
    if policy["needs_database"] is not False \
            or policy["network"] != "none" \
            or policy["database_dump_digest"] != "no_database":
        _refuse(
            "database-backed live test quality remains closed; this binding "
            "requires needs_database=false, network='none', and the "
            "no_database sentinel")
    cap = policy["compute_cap_seconds"]
    cap_authority = policy["compute_cap_review_authority"]
    if (cap is None) != (cap_authority is None):
        _refuse("compute cap and its review authority must be supplied together")
    if cap is not None and (
            not isinstance(cap, int) or isinstance(cap, bool) or cap < 1
            or not isinstance(cap_authority, str) or not cap_authority):
        _refuse("reviewed compute cap values are malformed")
    if cap is not None:
        _refuse(
            "generic installed-gold execution has no existing compute-cap "
            "finalization path; capped bindings remain closed")
    return policy


_AUTHORITY_FIELDS = frozenset({
    "project", "bundle_version", "leg", "policy_identity",
    "worker_spec_paths", "seed_dir", "harness_version",
})


def _material_paths(material: object, extra: tuple[str, ...] = ()) -> list[str]:
    if not isinstance(material, dict):
        return list(extra)
    provenance = material.get("provenance")
    paths = []
    if isinstance(provenance, dict):
        paths.extend(value for value in provenance.values()
                     if isinstance(value, str) and value)
    for observation in material.get("observations") or []:
        if isinstance(observation, dict):
            workload_path = observation.get("workload_path")
            if isinstance(workload_path, str) and workload_path:
                paths.append(workload_path)
            paths.extend(job.get("out") for job in observation.get("jobs") or []
                         if isinstance(job, dict)
                         and isinstance(job.get("out"), str))
    paths.extend(material.get(key) for key in (
        "hard_subset_path", "d4_confirmation_plan_out",
        "candidate_hard_plan_path")
                 if isinstance(material.get(key), str)
                 and material.get(key))
    paths.extend(path for path in material.get(
        "candidate_hard_rerun_paths") or [] if isinstance(path, str))
    paths.extend(extra)
    return list(dict.fromkeys(os.path.abspath(path) for path in paths if path))


def _validated_assets(material: object, *, fixture: bool) -> Optional[dict]:
    if fixture:
        return None
    from ..data import mutation_attestation as A

    provenance = material.get("provenance") \
        if isinstance(material, dict) else None
    required = (
        "mutation_validation", "manifest", "map", "release",
        "gold_baseline", "seed",
    )
    missing = [key for key in required
               if not isinstance((provenance or {}).get(key), str)
               or not provenance[key]]
    if missing:
        _refuse(f"live material omits frozen asset path(s) {missing}")
    try:
        return A.validate_campaign_asset_inputs(
            provenance["mutation_validation"],
            manifest_path=provenance["manifest"],
            map_path=provenance["map"], release_path=provenance["release"],
            require_release_ready=True)
    except (A.MutationAssetRefused, OSError, ValueError) as exc:
        raise LiveTestQualityRefused(str(exc)) from exc


def _offline_runtime(worker_spec_paths: list[str], *, seed_dir: str,
                     harness_version: object, policy: dict,
                     answer_paths: list[str]) -> dict:
    from . import worker as W
    from .mutation_run import content_digest

    try:
        entries = [(os.path.abspath(path), W.load_worker_spec(path))
                   for path in worker_spec_paths]
        entries.sort(key=lambda item: item[1].index)
        paths = [item[0] for item in entries]
        workers = [item[1] for item in entries]
        if len(workers) != policy["workers"] \
                or [worker.index for worker in workers] \
                != list(range(policy["workers"])):
            _refuse(
                "execution authority does not name the exact zero-based "
                "reviewed worker count")
        loaded = W.validate_offline_worker_runtime_pool(paths)
        pool = loaded[0]["binding"]["pool"]
        if pool.get("database") is not None \
                or (pool.get("network") or {}).get("mode") != "none":
            _refuse(
                "no-database live quality requires an authenticated pool "
                "with no database and network mode 'none'")
        W.preflight(workers, answer_paths, live=False,
                    needs_database=False)
        first = loaded[0]["runtime"]
        if first.get("seed_dir") != os.path.abspath(seed_dir) \
                or first.get("harness_version") != harness_version \
                or first.get("needs_database") is not False:
            _refuse("worker runtime differs from the bound seed/harness mode")
        resources = [W._worker_resource_record(
            worker, path, item["runtime_path"], item["runtime_sha256"])
            for path, worker, item in zip(paths, workers, loaded)]
        return {
            "worker_resources": resources,
            "worker_resources_sha256": content_digest(resources),
            "harness_version": harness_version,
            "container_image_digest": first["container_image_digest"],
            "workspace_seed_digest": first["workspace_seed_digest"],
            "database_dump_digest": first["database_dump_digest"],
            "docker_execution_authority": first[
                "docker_execution_authority"],
            "docker_execution_pool_digest": pool["digest"],
            "protected_evidence_paths":
                W._runtime_protected_evidence_paths(loaded),
            "worker_spec_paths": paths,
            "seed_dir": os.path.abspath(seed_dir),
        }
    except LiveTestQualityRefused:
        raise
    except (W.WorkerRefused, OSError, ValueError) as exc:
        raise LiveTestQualityRefused(str(exc)) from exc


def _validated_authority(raw: object, *, project: str, bundle_version: str,
                         leg: str, policy: dict, material: object) -> dict:
    from .mutation_run import content_digest

    expected_identity = content_digest(policy)
    if isinstance(raw, _FixtureExecutionAuthority):
        if raw.seal is not _FIXTURE_AUTHORITY_SEAL:
            _refuse("synthetic execution authority has no private seal")
        changed = [key for key, actual, wanted in (
            ("project", raw.project, project),
            ("bundle_version", raw.bundle_version, bundle_version),
            ("leg", raw.leg, leg),
            ("policy_identity", raw.policy_identity, expected_identity),
        ) if actual != wanted]
        if changed:
            _refuse(f"synthetic execution authority differs on {changed}")
        runtime = copy.deepcopy(dict(raw.runtime))
        return {
            "project": project, "bundle_version": bundle_version,
            "leg": leg, "policy_identity": expected_identity,
            "fixture": True, "runtime": runtime, "assets": None,
        }
    if not isinstance(raw, dict) or set(raw) != _AUTHORITY_FIELDS:
        got = sorted(raw) if isinstance(raw, dict) else type(raw).__name__
        _refuse(
            f"execution authority must contain exactly "
            f"{sorted(_AUTHORITY_FIELDS)}; got {got}")
    authority = copy.deepcopy(raw)
    expected = {
        "project": project,
        "bundle_version": bundle_version,
        "leg": leg,
        "policy_identity": expected_identity,
    }
    changed = sorted(
        key for key, value in expected.items() if authority.get(key) != value)
    if changed:
        _refuse(
            f"execution authority differs from validated binding field(s) "
            f"{changed}")
    paths = authority.get("worker_spec_paths")
    seed_dir = authority.get("seed_dir")
    if not isinstance(paths, list) or not paths \
            or not all(isinstance(path, str) and path for path in paths) \
            or not isinstance(seed_dir, str) or not seed_dir:
        _refuse("execution authority has malformed worker/seed paths")
    assets = _validated_assets(material, fixture=False)
    runtime = _offline_runtime(
        paths, seed_dir=seed_dir,
        harness_version=authority.get("harness_version"), policy=policy,
        answer_paths=_material_paths(material, tuple(paths)))
    return {
        "project": project, "bundle_version": bundle_version, "leg": leg,
        "policy_identity": expected_identity, "fixture": False,
        "runtime": runtime, "assets": assets,
    }


def _fixture_execution_authority(
        project: str, bundle_version: str, leg: str, policy: dict,
        runtime: Mapping[str, object]) -> _FixtureExecutionAuthority:
    """Mint network-free authority only inside synthetic source tests."""
    from .mutation_run import content_digest

    return _FixtureExecutionAuthority(
        project, bundle_version, leg, content_digest(policy),
        copy.deepcopy(dict(runtime)), _FIXTURE_AUTHORITY_SEAL)


def _revalidate_live_authority(
        binding: _ValidatedLiveBinding, material: dict,
        extra_answer_paths: tuple[str, ...] = ()) -> dict:
    """Recheck the exact v3 pool live immediately before worker dispatch."""
    authority = dict(binding.authority)
    expected = copy.deepcopy(dict(authority["runtime"]))
    if authority.get("fixture") is True:
        return expected
    from . import worker as W

    paths = list(expected["worker_spec_paths"])
    try:
        entries = [(path, W.load_worker_spec(path)) for path in paths]
        entries.sort(key=lambda item: item[1].index)
        paths = [item[0] for item in entries]
        workers = [item[1] for item in entries]
        answer_paths = _material_paths(
            material, (*extra_answer_paths, *tuple(paths)))
        W.preflight(workers, answer_paths, live=False,
                    needs_database=False)
        current = W.validate_mutation_runtime(
            paths, workers, expected["seed_dir"],
            expected["harness_version"], False)
        comparable = {
            key: current[key] for key in (
                "worker_resources", "worker_resources_sha256",
                "harness_version", "container_image_digest",
                "workspace_seed_digest", "database_dump_digest",
                "docker_execution_authority",
                "docker_execution_pool_digest")
        }
        changed = sorted(
            key for key, value in comparable.items()
            if expected.get(key) != value)
        if changed:
            _refuse(
                "live worker authority changed after offline admission in "
                f"field(s) {changed}")
        W.preflight(
            workers, answer_paths,
            containment_paths=current["protected_evidence_paths"],
            live=True, needs_database=False)
    except LiveTestQualityRefused:
        raise
    except (W.WorkerRefused, OSError, ValueError) as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    return expected


def _bound_resource_identities(
        binding: _ValidatedLiveBinding) -> list[tuple[str, str]]:
    """Derive coordinator locks from the authenticated no-database pool."""
    from . import worker as W

    records = binding.authority.get("runtime", {}).get("worker_resources")
    if not isinstance(records, list) \
            or len(records) != binding.policy["workers"]:
        _refuse("live binding has no authenticated complete worker pool")
    identities = []
    for number, record in enumerate(records):
        if not isinstance(record, dict) or record.get("index") != number:
            _refuse("live binding worker resources are not exact zero-based")
        for field in W.resource_fields(False):
            value = record.get(field)
            if isinstance(value, str) and value:
                identities.append((field, value))
    if not identities:
        _refuse("live binding has no mutation resource identities")
    return identities


def _observation_workload_facts(
        material: object, policy: Mapping[str, object], leg: str
        ) -> tuple[tuple[object, ...], ...]:
    """Seal onboarding workload bytes and planned identities in memory."""
    if leg != GOLD_ONBOARDING:
        return ()
    from . import mutation_run as MR
    from . import test_quality as TQ

    planned = material.get("observations") \
        if isinstance(material, dict) else None
    roles = [record["role"] for record in policy["gold_observations"]]
    if not isinstance(planned, list) \
            or [record.get("role") for record in planned
                if isinstance(record, dict)] != roles:
        _refuse("gold-onboarding material differs from policy observation order")
    facts = []
    seen_observations = set()
    for observation in planned:
        role = observation["role"]
        path = observation.get("workload_path")
        rows = observation.get("workload_rows")
        jobs = observation.get("jobs")
        if not isinstance(path, str) or not path or not isinstance(rows, list) \
                or not isinstance(jobs, list) or not jobs:
            _refuse(f"gold observation {role!r} has malformed workload facts")
        try:
            if TQ.load_jsonl(path) != rows:
                _refuse(
                    f"gold observation {role!r} workload source changed")
            run = TQ.run_binding(path, rows)
            files = TQ.passed_solutions(rows)
            identities = []
            observation_ids = set()
            for job in jobs:
                if not isinstance(job, dict) \
                        or job.get("files_by_item") != files:
                    _refuse(
                        f"gold observation {role!r} job does not carry its "
                        "exact workload")
                MR.campaign_identity_digest(job.get("identity") or {})
                identities.append(json.dumps(
                    job["identity"], sort_keys=True, separators=(",", ":")))
                observation_ids.add(job.get("observation_id"))
            if len(observation_ids) != 1:
                _refuse(
                    f"gold observation {role!r} has no single output-plan "
                    "observation identity")
            observation_id = next(iter(observation_ids))
            MR.validate_observation_id(observation_id)
        except (MR.MutationAborted, TQ.TestQualityRefused) as exc:
            raise LiveTestQualityRefused(str(exc)) from exc
        if observation_id in seen_observations:
            _refuse("gold/control observations reuse an observation identity")
        seen_observations.add(observation_id)
        facts.append((
            role, os.path.realpath(os.path.abspath(path)),
            run["run_sha256"], run["generated_tests_sha256"],
            observation_id, tuple(identities)))
    return tuple(facts)


def validate_live_binding(
        project: str, bundle_version: str, declaration: object,
        installed_bundle: object, *, leg: str, adapter: object) \
        -> _ValidatedLiveBinding:
    """Validate one focused adapter/policy/authority binding in memory.

    ``adapter`` is intentionally an interface, not a registry.  A future
    focused adapter PR supplies an object implementing
    ``live_test_quality_policy(leg)``, ``live_test_quality_authority(leg)``,
    ``live_test_quality_material(leg)``, and ``execute_mutation(job)``.  This
    repository currently supplies no production object implementing it.  A
    candidate adapter also supplies ``read_installed_gold(expected_pairs)``;
    that focused callback reopens its existing closed inventory/attestation
    format without a registry or persisted adapter selector.
    """
    from ..data.release import CAPABILITY_REQUIRED_ROLES

    if leg not in {GOLD_ONBOARDING, LIVE_CANDIDATE}:
        _refuse(f"unknown live test-quality leg {leg!r}")
    capability = resolve_mutation_capability(project, declaration)
    if not capability.supported:
        _refuse(
            f"{project} declares mutation unsupported: {capability.note}")
    required_names = (GOLD_ONBOARDING_REQUIRED_ROLES
                      if leg == GOLD_ONBOARDING
                      else CAPABILITY_REQUIRED_ROLES["mutation"])
    required = _required_role_paths(capability, required_names)
    _validated_install(project, bundle_version, installed_bundle)
    policy = _validated_policy(_adapter_call(
        adapter, "live_test_quality_policy", leg))
    declared_engine = declaration.get("mutation_engine")
    if policy["engine"] != declared_engine:
        _refuse(
            "live adapter policy engine differs from the project's #203 "
            f"mutation engine ({policy['engine']!r} != "
            f"{declared_engine!r})")
    material = _adapter_call(adapter, "live_test_quality_material", leg)
    facts = _role_facts(material, required)
    authority = _validated_authority(
        _adapter_call(adapter, "live_test_quality_authority", leg),
        project=project, bundle_version=bundle_version, leg=leg,
        policy=policy, material=material)
    executor = getattr(adapter, "execute_mutation", None)
    if not callable(executor):
        _refuse("live adapter does not implement execute_mutation()")
    if leg == LIVE_CANDIDATE \
            and not callable(getattr(adapter, "read_installed_gold", None)):
        _refuse("live candidate adapter has no installed-gold reader")
    _validate_material(
        material, project=project, policy=policy, authority=authority,
        leg=leg)
    workloads = _observation_workload_facts(material, policy, leg)
    return _ValidatedLiveBinding(
        project=project, bundle_version=bundle_version, leg=leg,
        role_paths=tuple(required.items()), role_facts=facts,
        policy=policy, authority=authority,
        observation_workloads=workloads, adapter=adapter,
        seal=_BINDING_SEAL)


def _check_binding(binding: object, *, project: str, bundle_version: str,
                   leg: str) -> _ValidatedLiveBinding:
    if not isinstance(binding, _ValidatedLiveBinding) \
            or binding.seal is not _BINDING_SEAL:
        _refuse("live producer binding was not validated")
    changed = []
    for key, actual, expected in (
            ("project", binding.project, project),
            ("bundle_version", binding.bundle_version, bundle_version),
            ("leg", binding.leg, leg)):
        if actual != expected:
            changed.append(key)
    if changed:
        _refuse(f"live producer binding differs on {changed}")
    return binding


def _refresh_binding(binding: _ValidatedLiveBinding) -> dict:
    current_policy = _validated_policy(_adapter_call(
        binding.adapter, "live_test_quality_policy", binding.leg))
    if current_policy != dict(binding.policy):
        _refuse("live adapter policy changed after binding")
    material = _adapter_call(
        binding.adapter, "live_test_quality_material", binding.leg)
    current = _role_facts(material, dict(binding.role_paths))
    if current != binding.role_facts:
        changed = sorted(
            role for (role, _path, identity),
            (_role2, _path2, current_identity)
            in zip(binding.role_facts, current)
            if identity != current_identity)
        _refuse(
            f"installed live role evidence changed after binding: {changed}")
    current_authority = _validated_authority(
        _adapter_call(
            binding.adapter, "live_test_quality_authority", binding.leg),
        project=binding.project, bundle_version=binding.bundle_version,
        leg=binding.leg, policy=current_policy, material=material)
    if current_authority != dict(binding.authority):
        _refuse("live execution authority changed after binding")
    _validate_material(
        material, project=binding.project, policy=dict(binding.policy),
        authority=dict(binding.authority), leg=binding.leg)
    workloads = _observation_workload_facts(
        material, current_policy, binding.leg)
    if workloads != binding.observation_workloads:
        _refuse("gold-onboarding workload bytes or planned jobs changed")
    return material


def resolve_mutation_readiness(
        project: str, bundle_version: str, declaration: object,
        installed_bundle: object, live_binding: object = None) \
        -> MutationReadiness:
    """Derive exactly unsupported/preserved-evidence-only/live-capable."""
    from ..data.release import CAPABILITY_REQUIRED_ROLES

    capability = resolve_mutation_capability(project, declaration)
    if not capability.supported:
        return MutationReadiness(
            UNSUPPORTED, capability,
            f"{project} declares mutation unsupported: {capability.note}")
    required = _required_role_paths(
        capability, CAPABILITY_REQUIRED_ROLES["mutation"])
    _validated_install(project, bundle_version, installed_bundle)
    if live_binding is None:
        return MutationReadiness(
            PRESERVED_EVIDENCE_ONLY, capability,
            f"{project} bundle {bundle_version} validates all mutation roles, "
            "but no admitted live producer binding is available")
    binding = _check_binding(
        live_binding, project=project, bundle_version=bundle_version,
        leg=LIVE_CANDIDATE)
    if dict(binding.role_paths) != required:
        _refuse("live producer binding role paths differ from declaration")
    material = _refresh_binding(binding)
    _revalidate_readiness_gold(binding, material)
    return MutationReadiness(
        LIVE_CAPABLE, capability,
        f"{project} bundle {bundle_version} and its live producer binding "
        "validate")


def authorize_gold_onboarding(
        project: str, bundle_version: str, declaration: object,
        installed_bundle: object, binding: object) -> _ValidatedLiveBinding:
    """Apply the separate four-role onboarding gate (not readiness)."""
    capability = resolve_mutation_capability(project, declaration)
    if not capability.supported:
        _refuse(
            f"{project} declares mutation unsupported: {capability.note}")
    required = _required_role_paths(
        capability, GOLD_ONBOARDING_REQUIRED_ROLES)
    _validated_install(project, bundle_version, installed_bundle)
    admitted = _check_binding(
        binding, project=project, bundle_version=bundle_version,
        leg=GOLD_ONBOARDING)
    if dict(admitted.role_paths) != required:
        _refuse("gold-onboarding binding role paths differ from declaration")
    _refresh_binding(admitted)
    return admitted


def _validate_material(material: object, *, project: str, policy: dict,
                       authority: dict, leg: str) -> None:
    from . import test_quality as TQ
    from . import mutation_run as MR

    if not isinstance(material, dict):
        _refuse("live adapter material is not a mapping")
    for key in ("manifest", "by_mutant", "gold_baseline_rows",
                "identity_inputs", "worker_resources", "role_facts"):
        if key not in material:
            _refuse(f"live adapter material is missing {key!r}")
    manifest = material["manifest"]
    by_mutant = material["by_mutant"]
    baseline = material["gold_baseline_rows"]
    inputs = material["identity_inputs"]
    resources = material["worker_resources"]
    if not isinstance(manifest, dict) or not isinstance(by_mutant, dict) \
            or not isinstance(baseline, list) or not isinstance(inputs, dict) \
            or not isinstance(resources, list):
        _refuse("live adapter material has malformed core inputs")
    runtime = authority.get("runtime")
    if not isinstance(runtime, dict):
        _refuse("live execution authority has no authenticated runtime")
    expected = {
        "asset_project": project,
        "manifest_digest": policy["manifest_digest"],
        "engine": policy["engine"],
        "engine_version": policy["engine_version"],
        "parser": policy["parser"],
        "database_dump_digest": policy["database_dump_digest"],
        "worker_resources_sha256": runtime.get(
            "worker_resources_sha256"),
        "harness_version": runtime.get("harness_version"),
        "container_image_digest": runtime.get("container_image_digest"),
        "workspace_seed_digest": runtime.get("workspace_seed_digest"),
    }
    if resources != runtime.get("worker_resources") \
            or len(resources) != policy["workers"] \
            or [record.get("index") for record in resources] \
            != list(range(policy["workers"])):
        _refuse(
            "live material worker resources differ from the authenticated "
            "complete zero-based pool")
    provenance = material.get("provenance") or {}
    baseline_path = provenance.get("gold_baseline")
    if not isinstance(baseline_path, str) or not baseline_path:
        _refuse("live material has no exact installed gold-baseline path")
    try:
        saved_baseline = TQ.load_jsonl(baseline_path)
        baseline_binding = TQ.run_binding(baseline_path, baseline)
    except (TQ.TestQualityRefused, OSError, ValueError) as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    if saved_baseline != baseline \
            or baseline_binding["run_sha256"] \
            != inputs.get("gold_baseline_sha256") \
            or baseline_binding["generated_tests_sha256"] \
            != inputs.get("gold_generated_tests_sha256"):
        _refuse(
            "live gold-baseline rows or generated tests differ from their "
            "exact installed bytes and identity")
    if manifest.get("digest") != policy["manifest_digest"]:
        _refuse("live policy and scored manifest have different digests")
    for key in ("engine", "engine_version", "parser"):
        if manifest.get(key) != policy[key]:
            _refuse(f"live policy and scored manifest differ on {key}")
    try:
        resolved_population = TQ.registered_population_id(
            project, manifest.get("digest"), manifest.get("engine"),
            manifest.get("engine_version"))
    except TQ.TestQualityRefused as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    if policy["population_id"] != resolved_population:
        _refuse(
            "live policy population_id differs from the registered scored "
            "manifest population")
    assets = authority.get("assets")
    if authority.get("fixture") is not True:
        if not isinstance(assets, dict) \
                or material["manifest"] != assets.get("manifest") \
                or material["by_mutant"] \
                != (assets.get("map") or {}).get("by_mutant"):
            _refuse(
                "live manifest/map differ from the validated installed assets")
        exact_assets = {
            "asset_index_sha256": assets["asset_index_sha256"],
            "asset_project": assets["asset_project"],
            "mutation_validation_sha256": assets["validation_sha256"],
            "mutation_validation_class": assets["validation_class"],
            "manifest_sha256": MR.sha256_file(provenance["manifest"]),
            "map_sha256": MR.sha256_file(provenance["map"]),
            "release_sha256": MR.sha256_file(provenance["release"]),
            "gold_baseline_sha256": MR.sha256_file(
                provenance["gold_baseline"]),
        }
        expected.update(exact_assets)
        facts = {role: fact.get("identity")
                 for role, fact in material["role_facts"].items()
                 if isinstance(fact, dict)}
        role_expected = {
            "mutation_validation": exact_assets[
                "mutation_validation_sha256"],
            "scored_manifest": exact_assets["manifest_sha256"],
            "mutation_map": exact_assets["map_sha256"],
            "gold_baseline": exact_assets["gold_baseline_sha256"],
        }
        changed_roles = sorted(
            role for role, value in role_expected.items()
            if role in facts and facts[role] != value)
        if changed_roles:
            _refuse(
                "validated installed role identities differ from frozen "
                f"input bytes for {changed_roles}")
    changed = sorted(
        key for key, value in expected.items() if inputs.get(key) != value)
    if changed:
        _refuse(
            f"live material identity differs from policy/runtime field(s) "
            f"{changed}")
    if leg == LIVE_CANDIDATE:
        admitted_gold = material.get("admitted_gold")
        if admitted_gold is not None \
                and not isinstance(admitted_gold, _AdmittedInstalledGold):
            _refuse("live candidate material has malformed installed gold")
        fact_map = {role: fact.get("identity")
                    for role, fact in material["role_facts"].items()
                    if isinstance(fact, dict)}
        for role, input_key in (
                ("gold_results", "gold_results_sha256"),
                ("gold_results_attestation",
                 "gold_results_attestation_sha256")):
            if inputs.get(input_key) != fact_map.get(role):
                _refuse(
                    f"live material {input_key} differs from the installed "
                    f"{role} identity")
        hard = (material.get("hard_subset_doc"),
                material.get("hard_subset_path"))
        if any(value is not None for value in hard) \
                != all(value is not None for value in hard):
            _refuse("hard-subset document and path must be supplied together")
        if policy["confirmation"] == "none" and any(
                value is not None for value in (
                    *hard, material.get("candidate_hard_rerun_paths"),
                    material.get("candidate_hard_plan_path"),
                    material.get("d4_confirmation_plan_out"),
                    material.get("hard_subset_attested_sha256"))):
            _refuse("live material supplies D4 inputs under a no-confirmation policy")
        if policy["confirmation"] == "d4" and hard[0] is None:
            _refuse("D4 live policy has no population-pinned hard subset")
        if policy["confirmation"] == "d4":
            if authority.get("fixture") is not True \
                    and policy["population_id"] is None:
                _refuse(
                    "production D4 requires a registered population-pinned "
                    "hard subset")
            from ..toolkit.hard_subset import (
                HardSubsetRefused, load as load_hard_subset)
            try:
                if authority.get("fixture") is True:
                    with open(hard[1], encoding="utf-8") as fh:
                        saved_hard = json.load(fh)
                else:
                    saved_hard = load_hard_subset(
                        hard[1],
                        expected_population_id=policy["population_id"],
                        require_pin=True)
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                _refuse(f"cannot validate the installed hard subset: {exc}")
            except HardSubsetRefused as exc:
                raise LiveTestQualityRefused(str(exc)) from exc
            if saved_hard != hard[0]:
                _refuse(
                    "D4 hard-subset document differs from its exact "
                    "installed bytes")
        if policy["confirmation"] == "d4" \
                and material.get("hard_subset_attested_sha256") \
                != MR.sha256_file(hard[1]):
            _refuse(
                "D4 hard subset differs from the installed gold "
                "attestation binding")
        if policy["confirmation"] == "d4" \
                and isinstance(admitted_gold, _AdmittedInstalledGold) \
                and admitted_gold.hard_subset_sha256 \
                != material.get("hard_subset_attested_sha256"):
            _refuse("D4 installed-gold reader changed its hard-set binding")
        rerun_paths = material.get("candidate_hard_rerun_paths") or []
        plan_path = material.get("candidate_hard_plan_path")
        if bool(rerun_paths) != bool(plan_path):
            _refuse(
                "D4 finalization requires both native run-2 paths and its "
                "authenticated plan path")
        if rerun_paths and material.get("d4_confirmation_plan_out") is not None:
            _refuse("D4 plan production and finalization are separate phases")
    else:
        observations = material.get("observations")
        if not isinstance(observations, list):
            _refuse("gold-onboarding material has no observation plan")


def _load_candidate(candidate_path: str, receipt_path: object) \
        -> tuple[list[dict], dict, dict, bool]:
    from . import mutation_run as MR
    from . import result_ledger as RL
    from . import test_quality as TQ

    candidate_path = os.path.abspath(candidate_path)
    if isinstance(receipt_path, _FixtureCandidateSeal):
        if receipt_path.path != candidate_path:
            _refuse("fixture candidate seal names another result path")
        rows = TQ.load_jsonl(candidate_path)
        binding = TQ.run_binding(candidate_path, rows)
        if tuple(sorted(binding.items())) != receipt_path.binding:
            _refuse("sealed fixture candidate bytes or passed tests changed")
        generation = dict(TQ.FIXTURE_GENERATION_INPUTS)
        return rows, binding, generation, True
    if not isinstance(receipt_path, str) or not receipt_path:
        _refuse("live candidate requires its complete merged-run receipt path")
    try:
        receipt = RL.verify_receipt(receipt_path)
    except Exception as exc:  # noqa: BLE001 - normalize the evidence refusal
        _refuse(f"candidate result receipt did not verify: {exc}")
    if receipt.get("complete") is not True \
            or receipt.get("artifact_kind") != "merged_run" \
            or receipt.get("result_path") != candidate_path:
        _refuse(
            "candidate receipt is not the complete merged-run seal for the "
            "exact supplied result")
    rows = TQ.load_jsonl(candidate_path)
    binding = TQ.run_binding(candidate_path, rows)
    if binding["run_sha256"] != receipt.get("result_file_sha256"):
        _refuse("candidate receipt and run binding name different bytes")
    try:
        generation = MR.generation_evidence_for_run(candidate_path, rows)
    except MR.MutationAborted as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    generation.pop("legacy_generation_evidence", None)
    if generation.get("generation_provenance_class") != "native_v2" \
            or not isinstance(generation.get("generation_attempt_id"), str) \
            or not generation["generation_attempt_id"].strip():
        _refuse(
            "prospective live execution requires publishable native_v2 "
            "candidate provenance and one unambiguous generation attempt; "
            "historical exact-byte/reference evidence remains read-only")
    return rows, binding, generation, False


def _seal_fixture_candidate(candidate_path: str) -> _FixtureCandidateSeal:
    """Private synthetic-fixture seal; never accepted from JSON or a bool."""
    from . import test_quality as TQ

    path = os.path.abspath(candidate_path)
    binding = TQ.run_binding(path)
    return _FixtureCandidateSeal(path, tuple(sorted(binding.items())))


def admit_installed_gold(
        project: str, bundle_version: str, raw_policy: object,
        role_facts: Mapping[str, Mapping[str, str]], records: list[dict], *,
        identity_inputs: Mapping[str, object],
        hard_subset_sha256: Optional[str] = None) -> _AdmittedInstalledGold:
    """Join one closed installed gold role set to its reviewed N=2 policy.

    A focused adapter calls this only after its existing role/inventory and
    control-specific attestation validators have accepted the unchanged
    installed bytes.  This generic half enforces the portable role identities,
    exact policy observation order/pair sets, strict infrastructure rule, and
    the existing conservative full-gold intersection.
    """
    from ..toolkit import gold_killset as GK
    from ..data import mutation as M
    from . import mutation_run as MR
    from . import test_quality as TQ
    from ..data.release import CAPABILITY_REQUIRED_ROLES

    policy = _validated_policy(raw_policy)
    required = CAPABILITY_REQUIRED_ROLES["mutation"]
    if not isinstance(role_facts, Mapping) or set(role_facts) != set(required):
        _refuse("installed gold admission requires the exact six role facts")
    facts = []
    for role in required:
        fact = role_facts[role]
        if not isinstance(fact, Mapping) \
                or set(fact) != {"path", "identity"} \
                or not isinstance(fact["path"], str) or not fact["path"] \
                or not isinstance(fact["identity"], str) \
                or len(fact["identity"]) != 64 \
                or any(ch not in "0123456789abcdef"
                       for ch in fact["identity"]):
            _refuse(f"installed gold has malformed validated {role} fact")
        facts.append((role, fact["path"], fact["identity"]))
    if not isinstance(identity_inputs, Mapping):
        _refuse("installed gold admission has no exact identity inputs")
    inputs = copy.deepcopy(dict(identity_inputs))
    fact_map = {role: identity for role, _path, identity in facts}
    for role, input_key in (
            ("mutation_validation", "mutation_validation_sha256"),
            ("scored_manifest", "manifest_sha256"),
            ("mutation_map", "map_sha256"),
            ("gold_baseline", "gold_baseline_sha256"),
            ("gold_results", "gold_results_sha256"),
            ("gold_results_attestation",
             "gold_results_attestation_sha256")):
        if inputs.get(input_key) != fact_map[role]:
            _refuse(
                f"installed gold {input_key} differs from its validated "
                f"{role} role identity")
    if policy["confirmation"] == "d4":
        if not isinstance(hard_subset_sha256, str) \
                or len(hard_subset_sha256) != 64 \
                or any(ch not in "0123456789abcdef"
                       for ch in hard_subset_sha256):
            _refuse(
                "D4 installed-gold admission has no attestation-derived "
                "hard-subset identity")
    elif hard_subset_sha256 is not None:
        _refuse("a no-confirmation gold policy carries a hard-subset identity")
    observations = policy["gold_observations"]
    if not isinstance(records, list) or len(records) != len(observations):
        _refuse("installed gold records differ from the policy observation set")
    full = []
    checked_records = []
    observation_ids = []
    for policy_record, record in zip(observations, records):
        if not GK.authenticated_native_run(record) \
                or not isinstance(record, dict) \
                or not isinstance(record.get("outcomes"), dict) \
                or not isinstance(record.get("facts"), dict):
            _refuse(
                f"installed gold observation {policy_record['role']!r} "
                "is not a validated record")
        try:
            paths = GK.native_run_paths(record)
            saved_side = (record.get("identity") or {}).get("side")
            reopened = GK.load_native_run(
                paths, required_side=saved_side)
        except GK.GoldKillsetRefused as exc:
            raise LiveTestQualityRefused(str(exc)) from exc
        if dict(reopened) != dict(record):
            _refuse(
                f"installed gold observation {policy_record['role']!r} "
                "changed after raw-inventory validation")
        record = reopened
        try:
            TQ.validate_native_retry_evidence(
                [row for path in paths for row in TQ.load_jsonl(path)],
                where=(f"installed gold observation "
                       f"{policy_record['role']!r}"))
        except TQ.TestQualityRefused as exc:
            raise LiveTestQualityRefused(str(exc)) from exc
        expected = {tuple(pair) for pair in policy_record["expected_pairs"]}
        if set(record["outcomes"]) != expected \
                or record["facts"].get("pairs_sha256") \
                != MR.pair_set_digest(expected):
            _refuse(
                f"installed gold observation {policy_record['role']!r} "
                "covers another pair set")
        observation_id = record["facts"].get("observation_id")
        try:
            MR.validate_observation_id(observation_id)
        except MR.MutationAborted as exc:
            raise LiveTestQualityRefused(str(exc)) from exc
        observation_ids.append(observation_id)
        identity = record["identity"]
        wanted = {
            **{key: inputs.get(key) for key in (
                "asset_index_sha256", "mutation_validation_sha256",
                "mutation_validation_class", "manifest_sha256",
                "manifest_digest", "map_sha256", "release_sha256",
                "substrate_baseline_sha256", "applier_sha256",
                "worker_resources_sha256", "harness_version",
                "container_image_digest", "workspace_seed_digest",
                "database_dump_digest", "engine", "engine_version",
                "parser")},
            "asset_project": project,
            "timeout_seconds": policy["timeout_seconds"],
            "kind": "mutation-run",
            "sample": None,
            "sample_seed": None,
            "of": policy["workers"],
        }
        if policy_record["kind"] == "full_gold":
            wanted.update({
                "side": "gold",
                "candidate_run_sha256": inputs["gold_baseline_sha256"],
                "candidate_generated_tests_sha256": inputs[
                    "gold_generated_tests_sha256"],
                "solution_generated_tests_sha256": inputs[
                    "gold_generated_tests_sha256"],
            })
            if identity.get("schema") == MR.MUTATION_IDENTITY_SCHEMA_V5 \
                    and identity.get("reference_control_role") != "full-gold":
                _refuse("installed full-gold reference carries another role")
        elif identity.get("schema") == MR.MUTATION_IDENTITY_SCHEMA_V5:
            if identity.get("reference_control_role") != policy_record["role"]:
                _refuse(
                    f"installed control {policy_record['role']!r} is not "
                    "bound to its exact reference-control role")
        changed_identity = sorted(
            key for key, value in wanted.items()
            if identity.get(key) != value)
        if identity.get("schema") not in {
                MR.MUTATION_IDENTITY_SCHEMA_V2,
                MR.MUTATION_IDENTITY_SCHEMA_V5} \
                or changed_identity:
            _refuse(
                f"installed gold observation {policy_record['role']!r} "
                "differs from the project/policy identity in field(s) "
                f"{changed_identity}")
        try:
            infrastructure = sorted(
                pair for pair, outcome in record["outcomes"].items()
                if M.classify_outcome("passed", outcome)
                == "infrastructure")
        except ValueError as exc:
            raise LiveTestQualityRefused(str(exc)) from exc
        if infrastructure:
            _refuse(
                f"installed gold observation {policy_record['role']!r} "
                f"contains infrastructure for {infrastructure[:3]}")
        if policy_record["kind"] == "full_gold":
            full.append(record)
        checked_records.append(record)
    if len(observation_ids) != len(set(observation_ids)):
        _refuse("installed gold/control observation IDs are not independent")
    try:
        joined = GK.validate_observation_pair(full[0], full[1])
    except (GK.GoldKillsetRefused, IndexError) as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    try:
        policy_json = json.dumps(
            policy, sort_keys=True, separators=(",", ":"))
        inputs_json = json.dumps(
            inputs, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        _refuse(f"installed gold identity inputs are not canonical JSON: {exc}")
    return _AdmittedInstalledGold(
        project=project, bundle_version=bundle_version,
        policy_identity=MR.content_digest(policy), policy_json=policy_json,
        identity_inputs_json=inputs_json, role_facts=tuple(facts),
        records=tuple(copy.deepcopy(checked_records)),
        hard_subset_sha256=hard_subset_sha256, seal=_ADMITTED_GOLD_SEAL)


def _selected_installed_gold(
        value: object, binding: _ValidatedLiveBinding,
        expected: set[tuple[str, str]], material: Mapping[str, object]) -> object:
    from ..toolkit import gold_killset as GK
    from . import mutation_run as MR
    from . import test_quality as TQ

    if not isinstance(value, _AdmittedInstalledGold) \
            or value.seal is not _ADMITTED_GOLD_SEAL:
        _refuse("installed gold was not admitted through the policy/role join")
    changed = []
    if value.project != binding.project:
        changed.append("project")
    if value.bundle_version != binding.bundle_version:
        changed.append("bundle_version")
    if value.policy_identity != MR.content_digest(dict(binding.policy)):
        changed.append("policy")
    canonical_policy = json.dumps(
        dict(binding.policy), sort_keys=True, separators=(",", ":"))
    if value.policy_json != canonical_policy:
        changed.append("policy-bytes")
    if value.role_facts != binding.role_facts:
        changed.append("roles")
    if changed:
        _refuse(f"installed gold changed after admission on {changed}")
    role_facts = {
        role: {"path": path, "identity": identity}
        for role, path, identity in value.role_facts
    }
    current_inputs = material.get("identity_inputs")
    if not isinstance(current_inputs, Mapping):
        _refuse("installed-gold reader has no current identity inputs")
    installed_inputs = json.loads(value.identity_inputs_json)
    for key in (
            "asset_index_sha256", "asset_project",
            "mutation_validation_sha256", "mutation_validation_class",
            "manifest_sha256", "manifest_digest", "map_sha256",
            "release_sha256", "gold_baseline_sha256",
            "gold_generated_tests_sha256", "gold_results_sha256",
            "gold_results_attestation_sha256", "substrate_baseline_sha256",
            "applier_sha256", "worker_resources_sha256", "harness_version",
            "container_image_digest", "workspace_seed_digest",
            "database_dump_digest", "engine", "engine_version", "parser"):
        if current_inputs.get(key) != installed_inputs.get(key):
            _refuse(f"installed-gold reader identity changed on {key}")
    reopened = admit_installed_gold(
        value.project, value.bundle_version, json.loads(value.policy_json),
        role_facts, list(value.records), identity_inputs=installed_inputs,
        hard_subset_sha256=value.hard_subset_sha256)
    full_records = [record for policy_record, record in zip(
        json.loads(value.policy_json)["gold_observations"], reopened.records)
                    if policy_record["kind"] == "full_gold"]
    try:
        joined = GK.validate_observation_pair(
            full_records[0], full_records[1])
    except (GK.GoldKillsetRefused, IndexError) as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    rows = [{
        "item_id": item_id,
        "mutant_id": mutant_id,
        "outcome": ("failed" if (item_id, mutant_id)
                    in joined["intersection"] else "passed"),
    } for item_id, mutant_id in sorted(expected)]
    if not expected <= joined["pairs"]:
        _refuse(
            "installed gold does not cover the candidate's exact passed-item "
            "pair set")
    pairs = {(row.get("item_id"), row.get("mutant_id")) for row in rows}
    if pairs != expected or len(rows) != len(expected):
        _refuse(
            "installed gold does not cover the candidate's exact passed-item "
            "pair set")
    try:
        provenance = material.get("provenance") or {}
        source = provenance.get("gold_results_source")
        attestation = provenance.get("gold_results_attestation")
        if not isinstance(source, str) or not source \
                or not isinstance(attestation, str) or not attestation:
            _refuse(
                "installed-gold reader has no unchanged raw-role and "
                "attestation paths")
        return TQ._seal_authenticated_gold_selection(rows, {
            "validation_class": "native",
            "manifest_digest": binding.policy["manifest_digest"],
            "pairs_sha256": MR.pair_set_digest(expected),
            "engine": binding.policy["engine"],
            "engine_version": binding.policy["engine_version"],
            "gold_results_sha256": role_facts["gold_results"]["identity"],
            "gold_results_attestation_sha256": role_facts[
                "gold_results_attestation"]["identity"],
            "gold_results_source": source,
            "gold_results_attestation": attestation,
        })
    except TQ.TestQualityRefused as exc:
        raise LiveTestQualityRefused(str(exc)) from exc


def _installed_gold_reader(binding: _ValidatedLiveBinding):
    """Return the focused, adapter-aware saved-evidence reader for a binding."""
    _check_binding(
        binding, project=binding.project, bundle_version=binding.bundle_version,
        leg=LIVE_CANDIDATE)

    def read(_summary: dict, expected: set[tuple[str, str]]) -> object:
        material = _refresh_binding(binding)
        callback = getattr(binding.adapter, "read_installed_gold", None)
        if not callable(callback):                         # pragma: no cover
            _refuse("live candidate adapter lost its installed-gold reader")
        try:
            value = callback(set(expected))
        except LiveTestQualityRefused:
            raise
        except Exception as exc:  # noqa: BLE001 - adapter refusal boundary
            _refuse(f"installed-gold reader refused: {exc}")
        if isinstance(value, _AdmittedInstalledGold):
            return _selected_installed_gold(
                value, binding, expected, material)
        # A future focused adapter whose preserved inventory is not a native
        # standalone output (for example, an existing closed tree role) may
        # return the same private TQ selection seal after its own current
        # inventory/attestation validator has re-derived the facts.  TQ opens
        # and compares that seal; an ordinary dict or Boolean cannot pass.
        return value

    return read


def _revalidate_readiness_gold(
        binding: _ValidatedLiveBinding, material: Mapping[str, object]) -> None:
    """Reopen the complete installed draw before deriving live-capable."""
    from . import mutation_run as MR
    from . import test_quality as TQ

    full_draws = [
        {tuple(pair) for pair in observation["expected_pairs"]}
        for observation in binding.policy["gold_observations"]
        if observation["kind"] == "full_gold"
    ]
    if len(full_draws) != 2 or not full_draws[0] \
            or full_draws[0] != full_draws[1]:
        _refuse(
            "live readiness has no identical complete two-observation gold "
            "draw")
    expected = full_draws[0]
    try:
        baseline_passed = TQ.passed_solutions(
            material["gold_baseline_rows"])
        _mutants, restricted, _covering = TQ.population(
            material["manifest"], material["by_mutant"], baseline_passed)
        complete_draw = TQ.expected_pairs(restricted)
    except (TQ.TestQualityRefused, KeyError, TypeError, ValueError) as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    if expected != complete_draw:
        _refuse(
            "live readiness gold observations do not cover the complete "
            "installed population/map draw")
    provenance = material.get("provenance") or {}
    inputs = material.get("identity_inputs") or {}
    try:
        TQ._read_authenticated_installed_gold(
            _installed_gold_reader(binding),
            summary={
                "manifest_digest": binding.policy["manifest_digest"],
                "engine": binding.policy["engine"],
                "engine_version": binding.policy["engine_version"],
                "gold_results_source": provenance.get(
                    "gold_results_source"),
                "gold_results_attestation": provenance.get(
                    "gold_results_attestation"),
            },
            expected=expected,
            identity_inputs={
                **inputs,
                "gold_attestation_pairs_sha256":
                    MR.pair_set_digest(expected),
            })
    except TQ.TestQualityRefused as exc:
        raise LiveTestQualityRefused(str(exc)) from exc


def _candidate_execution_kwargs(
        policy: Mapping[str, object], expected: set[tuple[str, str]],
        out_dir: str, *, resume: bool) -> dict:
    """Bind one V4 observation; resume recovers its root-owned identity."""
    from . import mutation_run as MR
    from . import test_quality as TQ

    reviewed = {
        "execution_policy": policy["execution_policy"],
        "batch_plan_sha256": policy["batch_plan_sha256"],
        "max_batch_members": policy["max_batch_members"],
        "max_batch_instances": policy["max_batch_instances"],
        "stack_reset_sha256": policy["stack_reset_sha256"],
        "batch_journal_schema": policy["batch_journal_schema"],
        "reuse_projection_sha256": None,
        "preflight_cache_policy": None,
    }
    if not resume:
        return {**reviewed, "execution_observation_id": secrets.token_hex(16)}
    try:
        state = TQ._load_json_object(
            TQ._campaign_state_path(out_dir),
            "resumed generic live root campaign")
        plan = state.get("plan") if isinstance(state, dict) else None
        TQ._validate_campaign_state(state, plan)
        jobs = plan.get("jobs") if isinstance(plan, dict) else None
        first = (jobs[0].get("campaign_identity")
                 if isinstance(jobs, list) and jobs
                 and isinstance(jobs[0], dict) else None)
        saved = TQ._v4_execution_kwargs(first or {})
    except (TQ.TestQualityRefused, OSError, ValueError) as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    wanted = {
        **reviewed,
        "estimand_pairs_sha256": MR.pair_set_digest(expected),
    }
    changed = sorted(
        key for key, value in wanted.items() if saved.get(key) != value)
    if changed or not saved.get("observation_id"):
        _refuse(
            "resumed live campaign differs from its reviewed execution "
            f"binding in field(s) {changed or ['observation_id']}")
    try:
        root_shard_policy = TQ.shard_policy_from_plan(plan)
    except TQ.TestQualityRefused as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    candidate_jobs = [job for job in jobs if job.get("side") == "candidate"]
    actual_workers = sorted(job.get("worker") for job in candidate_jobs)
    if root_shard_policy != policy["shard_policy"] \
            or not actual_workers \
            or actual_workers != list(range(len(actual_workers))) \
            or len(actual_workers) > policy["workers"] \
            or any((job.get("campaign_identity") or {}).get("of")
                   != policy["workers"] for job in candidate_jobs):
        _refuse(
            "resumed live campaign differs from its reviewed shard policy "
            "or complete worker assignment")
    return {**reviewed,
            "execution_observation_id": saved["observation_id"]}


def run_live_confirmation(
        candidate_path: str, candidate_receipt_path: object,
        project: str, bundle_version: str, declaration: object,
        installed_bundle: object, binding: object, *,
        run_1_dir: str, plan_path: str, out_dir: str,
        resume: bool = False) -> list[str]:
    """Execute the exact D4 run-2 plan through the admitted generic route.

    Run 2 remains the existing standalone native ``mutation-run`` evidence.
    This function only supplies its generic authority: it revalidates the
    sealed candidate, six roles, installed gold, policy, assets, runtime, and
    D4 plan; constructs the deterministic native shard identities; dispatches
    them through the already-bound adapter; and validates their complete
    native/D4 join.  It writes no score, summary, sidecar, or new document
    format.  The returned shard paths are consumed on an exact-identity root
    resume by :func:`run_live_candidate`.
    """
    from . import mutation_run as MR
    from ..data.release import CAPABILITY_REQUIRED_ROLES
    from . import test_quality as TQ

    rows, candidate_binding, generation, fixture_candidate = _load_candidate(
        candidate_path, candidate_receipt_path)
    passed = TQ.passed_solutions(rows)
    if not passed:
        _refuse("zero-pass candidates have no D4 confirmation observation")
    if TQ.find_sidecar(candidate_path) is not None:
        _refuse("sealed candidate already has a test-quality sidecar")

    capability = resolve_mutation_capability(project, declaration)
    if not capability.supported:
        _refuse(f"{project} declares mutation unsupported: {capability.note}")
    required = _required_role_paths(
        capability, CAPABILITY_REQUIRED_ROLES["mutation"])
    _validated_install(project, bundle_version, installed_bundle)
    admitted = _check_binding(
        binding, project=project, bundle_version=bundle_version,
        leg=LIVE_CANDIDATE)
    if dict(admitted.role_paths) != required:
        _refuse("live confirmation binding role paths differ from declaration")
    material = _refresh_binding(admitted)
    _revalidate_readiness_gold(admitted, material)
    if fixture_candidate != bool(admitted.authority.get("fixture")):
        _refuse(
            "fixture-only candidate/authority cannot cross the prospective "
            "native execution boundary")
    if admitted.policy["confirmation"] != "d4" \
            or admitted.policy["execution_policy"] \
            != MR.EXECUTION_POLICY_SCALAR_V1:
        _refuse("live confirmation has no admitted scalar D4 policy")

    inputs = dict(material["identity_inputs"])
    candidate_claims = {
        "candidate_run_sha256": candidate_binding["run_sha256"],
        "candidate_generated_tests_sha256":
            candidate_binding["generated_tests_sha256"],
        **{key: generation.get(key)
           for key in sorted(MR.CAMPAIGN_IDENTITY_FIELDS_V2_ADDED)},
    }
    changed = sorted(
        key for key, value in candidate_claims.items()
        if inputs.get(key) != value)
    if changed:
        _refuse(
            "sealed candidate differs from live confirmation field(s) "
            f"{changed}")
    mutants, restricted, _covering = TQ.population(
        material["manifest"], material["by_mutant"], passed)
    expected = TQ.expected_pairs(restricted)
    if not expected:
        _refuse("candidate has no mutation pairs to confirm")

    provenance = dict(material.get("provenance") or {})
    gold_reader = _installed_gold_reader(admitted)
    try:
        TQ._read_authenticated_installed_gold(
            gold_reader,
            summary={
                "manifest_digest": admitted.policy["manifest_digest"],
                "engine": admitted.policy["engine"],
                "engine_version": admitted.policy["engine_version"],
                "gold_results_source": provenance.get(
                    "gold_results_source"),
                "gold_results_attestation": provenance.get(
                    "gold_results_attestation"),
            },
            expected=expected,
            identity_inputs={
                **inputs,
                "gold_attestation_pairs_sha256":
                    MR.pair_set_digest(expected),
            })
    except TQ.TestQualityRefused as exc:
        raise LiveTestQualityRefused(str(exc)) from exc

    run_1_dir = os.path.abspath(run_1_dir)
    plan_path = os.path.abspath(plan_path)
    out_dir = os.path.abspath(out_dir)
    declared_plan = (material.get("d4_confirmation_plan_out")
                     or material.get("candidate_hard_plan_path"))
    if not isinstance(declared_plan, str) \
            or os.path.abspath(declared_plan) != plan_path:
        _refuse(
            "D4 run-2 plan path differs from the reviewed live binding")
    hard_path = material["hard_subset_path"]
    assets = admitted.authority.get("assets")
    required_provenance = {
        "mutation_validation", "manifest", "map", "release",
    }
    missing = sorted(
        key for key in required_provenance
        if not isinstance(provenance.get(key), str) or not provenance[key])
    if missing:
        _refuse(f"D4 run 2 omits frozen evidence path(s) {missing}")
    try:
        plan = TQ.validate_d4_confirmation_plan(
            plan_path, run1_campaign=run_1_dir,
            hard_subset_path=hard_path, candidate_run_path=candidate_path,
            assets=assets,
            validation_path=provenance["mutation_validation"],
            manifest_path=provenance["manifest"],
            map_path=provenance["map"], release_path=provenance["release"])
    except (TQ.TestQualityRefused, MR.MutationAborted, OSError,
            KeyError, TypeError, ValueError) as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    if plan.get("timeout_seconds") != admitted.policy["timeout_seconds"]:
        _refuse("D4 run 2 changed the authenticated run-1 timeout")
    planned_pairs = plan.get("pairs")
    candidate_files = plan.get("candidate_files")
    plan_mutants = plan.get("mutants")
    if not isinstance(planned_pairs, set) or not planned_pairs \
            or not planned_pairs <= expected \
            or candidate_files != passed \
            or plan_mutants != mutants:
        _refuse(
            "validated D4 plan differs from the sealed candidate population")
    candidate_identities = plan.get("candidate_identities")
    if not isinstance(candidate_identities, list):
        _refuse("D4 run 1 has no complete authenticated identity set")
    root_execution = _candidate_execution_kwargs(
        admitted.policy, plan["expected_run_1_pairs"], run_1_dir,
        resume=True)
    root_wanted = {
        key: inputs.get(key) for key in (
            "asset_index_sha256", "asset_project",
            "mutation_validation_sha256", "mutation_validation_class",
            "manifest_sha256", "manifest_digest", "map_sha256",
            "release_sha256", "candidate_run_sha256",
            "candidate_generated_tests_sha256", "gold_baseline_sha256",
            "gold_generated_tests_sha256", "gold_results_sha256",
            "gold_results_attestation_sha256",
            "substrate_baseline_sha256", "applier_sha256",
            "worker_resources_sha256", "harness_version",
            "container_image_digest", "workspace_seed_digest",
            "database_dump_digest", "engine", "engine_version", "parser",
            *sorted(MR.CAMPAIGN_IDENTITY_FIELDS_V2_ADDED),
        )
    }
    root_wanted.update({
        "schema": MR.MUTATION_IDENTITY_SCHEMA_V4,
        "kind": "test-quality", "side": "candidate",
        "solution_generated_tests_sha256":
            candidate_binding["generated_tests_sha256"],
        "gold_provenance_class": "native",
        "gold_attestation_manifest_digest":
            admitted.policy["manifest_digest"],
        "gold_attestation_pairs_sha256": MR.pair_set_digest(expected),
        "gold_attestation_engine": admitted.policy["engine"],
        "gold_attestation_engine_version": admitted.policy["engine_version"],
        "timeout_seconds": admitted.policy["timeout_seconds"],
        "sample": None, "sample_seed": None,
        "of": admitted.policy["workers"],
        "shard_policy": admitted.policy["shard_policy"],
        "execution_policy": admitted.policy["execution_policy"],
        "batch_plan_sha256": admitted.policy["batch_plan_sha256"],
        "max_batch_members": admitted.policy["max_batch_members"],
        "max_batch_instances": admitted.policy["max_batch_instances"],
        "stack_reset_sha256": admitted.policy["stack_reset_sha256"],
        "batch_journal_schema": admitted.policy["batch_journal_schema"],
        "compute_cap_sha256": None,
        "reuse_projection_sha256": None,
        "estimand_pairs_sha256": MR.pair_set_digest(
            plan["expected_run_1_pairs"]),
        "preflight_cache_policy": None,
        "observation_id": root_execution["execution_observation_id"],
    })
    root_slices = TQ.shard_mutants(
        mutants, restricted, passed, admitted.policy["workers"],
        policy=admitted.policy["shard_policy"])
    planned_root_slices = [
        (number, shard_mutants)
        for number, shard_mutants in enumerate(root_slices) if shard_mutants
    ]
    if len(candidate_identities) != len(planned_root_slices):
        _refuse("D4 run 1 has no complete authenticated identity set")
    for identity, (number, shard_mutants) in zip(
            candidate_identities, planned_root_slices):
        shard_pairs = MR.expected_pairs_for_slice(
            shard_mutants, restricted, passed)
        changed_root = sorted(
            key for key, value in root_wanted.items()
            if not isinstance(identity, dict) or identity.get(key) != value)
        if identity.get("expected_pairs") != len(shard_pairs) \
                or identity.get("expected_pairs_sha256") \
                != MR.pair_set_digest(shard_pairs):
            changed_root.append("pair-allocation")
        if changed_root or identity.get("shard") != number:
            _refuse(
                "D4 run 1 differs from the current candidate/gold/runtime "
                f"binding in field(s) {changed_root or ['shard']}")
    allocations = TQ.shard_d4_confirmation_pairs(
        planned_pairs,
        min(admitted.policy["workers"], len({
            mutant_id for _item_id, mutant_id in planned_pairs})))
    try:
        if os.path.commonpath((run_1_dir, out_dir)) == run_1_dir:
            _refuse(
                "D4 run 2 must use a standalone output directory outside "
                "the resumable run-1 root")
    except ValueError:
        pass
    ownership_path = os.path.join(out_dir, MR.MUTATION_OUTPUT_PLAN)
    if resume != os.path.lexists(ownership_path):
        _refuse(
            "D4 run-2 resume requires its existing native output plan, and "
            "a new run requires an unclaimed output directory")

    d4_resources = copy.deepcopy(
        material["worker_resources"][:len(allocations)])
    if [record.get("index") for record in d4_resources] \
            != list(range(len(allocations))):
        _refuse("D4 run 2 has no exact zero-based worker-resource prefix")
    common_provenance = {
        **provenance,
        "candidate": os.path.abspath(candidate_path),
        "side": "candidate", "sample": None, "sample_seed": None,
        "d4_confirmation_plan": plan_path,
        "d4_confirmation_plan_sha256": MR.sha256_file(plan_path),
        "d4_confirmation_plan_digest": plan["plan"]["digest"],
        "d4_run_1_campaign": run_1_dir,
        "d4_run_1_observation_id": plan["run_1_observation_id"],
        "d4_hard_subset": os.path.abspath(hard_path),
        "d4_pair_shard_policy": TQ.D4_PAIR_SHARD_POLICY,
        "worker_resources": d4_resources,
        "harness_version": inputs["harness_version"],
        "container_image_digest": inputs["container_image_digest"],
        "workspace_seed_digest": inputs["workspace_seed_digest"],
        "database_dump_digest": inputs["database_dump_digest"],
    }
    by_id = {mutant["id"]: mutant for mutant in mutants}
    jobs = []
    for worker, pairs in enumerate(allocations):
        mutant_ids = {mutant_id for _item_id, mutant_id in pairs}
        shard_mutants = [by_id[mutant_id]
                         for mutant_id in by_id if mutant_id in mutant_ids]
        shard_files = copy.deepcopy(candidate_files)
        natural = MR.expected_pairs_for_slice(
            shard_mutants, material["by_mutant"], shard_files)
        if not pairs <= natural:
            _refuse(
                f"D4 worker {worker} pair allocation differs from the "
                "unchanged candidate/map population")
        identity = MR.build_campaign_identity(
            **{key: inputs.get(key)
               for key in sorted(MR.CAMPAIGN_IDENTITY_FIELDS_V2_ADDED)},
            asset_index_sha256=inputs["asset_index_sha256"],
            asset_project=inputs["asset_project"],
            mutation_validation_sha256=inputs[
                "mutation_validation_sha256"],
            mutation_validation_class=inputs[
                "mutation_validation_class"],
            manifest_sha256=inputs["manifest_sha256"],
            manifest_digest=inputs["manifest_digest"],
            map_sha256=inputs["map_sha256"],
            release_sha256=inputs["release_sha256"],
            candidate_run_sha256=inputs["candidate_run_sha256"],
            candidate_generated_tests_sha256=inputs[
                "candidate_generated_tests_sha256"],
            solution_generated_tests_sha256=MR.candidate_digest(
                candidate_files),
            substrate_baseline_sha256=inputs["substrate_baseline_sha256"],
            applier_sha256=inputs["applier_sha256"],
            worker_resources_sha256=MR.content_digest(d4_resources),
            harness_version=inputs["harness_version"],
            container_image_digest=inputs["container_image_digest"],
            workspace_seed_digest=inputs["workspace_seed_digest"],
            database_dump_digest=inputs["database_dump_digest"],
            expected_pairs=pairs, engine=inputs["engine"],
            engine_version=inputs["engine_version"], parser=inputs["parser"],
            side="candidate", shard=worker, of=len(allocations),
            timeout=admitted.policy["timeout_seconds"])
        jobs.append({
            "side": "candidate", "worker": worker,
            "of": len(allocations), "mutants": shard_mutants,
            "files_by_item": shard_files,
            "by_mutant": copy.deepcopy(material["by_mutant"]),
            "planned_pairs": set(pairs), "expected_pairs": set(pairs),
            "out": os.path.join(out_dir, f"candidate.w{worker}.jsonl"),
            "provenance": {
                **common_provenance, "mutant_shard": worker,
                "mutant_of": len(allocations)},
            "identity": identity, "resume": bool(resume),
            "execution_policy": admitted.policy["execution_policy"],
            "batch_plan_sha256": admitted.policy["batch_plan_sha256"],
            "max_batch_members": admitted.policy["max_batch_members"],
            "max_batch_instances": admitted.policy["max_batch_instances"],
            "stack_reset_sha256": admitted.policy["stack_reset_sha256"],
            "batch_journal_schema": admitted.policy[
                "batch_journal_schema"],
            "run_1_execution_observation_id": root_execution[
                "execution_observation_id"],
            "resources_locked": True,
        })

    resource_identities = _bound_resource_identities(admitted)

    def prepare_jobs() -> None:
        observation_id = MR.prepare_standalone_output_directory(
            jobs[0]["out"], jobs[0]["identity"])
        for job in jobs:
            MR.prepare_standalone_output_directory(
                job["out"], job["identity"], observation_id)
            job["observation_id"] = observation_id

    def execute_and_validate() -> list[str]:
        with MR.coordinator_cancellation() as cancel_event:
            for job in jobs:
                job["cancel_event"] = cancel_event
            TQ.execute_jobs(
                jobs, admitted.adapter.execute_mutation,
                cancel_event=cancel_event)
        paths = [job["out"] for job in jobs]
        campaign = MR.validate_native_shards(
            paths, expected_pairs=planned_pairs,
            required_side="candidate", return_campaign=True)
        TQ.validate_native_retry_evidence(
            campaign["rows"], where="D4 candidate confirmation")
        sidecars = []
        for path in paths:
            with open(MR.provenance_path(path), encoding="utf-8") as fh:
                sidecars.append(json.load(fh))
        TQ.validate_d4_confirmation_run_2_binding(
            rerun_campaign=campaign, shard_sidecars=sidecars,
            plan_binding=plan, plan_path=plan_path,
            run1_campaign=run_1_dir, hard_subset_path=hard_path)
        return paths

    try:
        with MR.output_lock(out_dir):
            with MR.mutation_resource_locks(resource_identities):
                # A resume authenticates its existing ownership before any
                # live worker inspection.  A new run delays its first durable
                # output-plan write until the live authority revalidates.
                if resume:
                    prepare_jobs()
                _revalidate_live_authority(
                    admitted, material,
                    (os.path.abspath(candidate_path), run_1_dir, plan_path,
                     os.path.abspath(hard_path), out_dir))
                if not resume:
                    prepare_jobs()
                paths = execute_and_validate()
    except (TQ.TestQualityRefused, MR.MutationAborted, OSError,
            json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    return paths


def _validated_d4_finalization(
        material: dict, binding: _ValidatedLiveBinding, *,
        candidate_path: str, out_dir: str, inputs: dict, resume: bool) \
        -> tuple[Optional[list], list[str], Optional[str]]:
    """Authenticate a supplied D4 run 2 against its exact run-1 plan."""
    from . import mutation_run as MR
    from . import test_quality as TQ

    paths = list(material.get("candidate_hard_rerun_paths") or [])
    if not paths:
        return None, [], None
    if not resume:
        _refuse("D4 finalization requires exact-identity root resume")
    hard_path = material["hard_subset_path"]
    plan_path = material["candidate_hard_plan_path"]
    provenance = material.get("provenance") or {}
    assets = binding.authority.get("assets")
    try:
        campaign = MR.validate_native_shards(
            paths, required_side="candidate", return_campaign=True)
        TQ.validate_native_retry_evidence(
            campaign["rows"], where="D4 candidate confirmation")
        observation_id = TQ._hard_rerun_observation_id(campaign)
        TQ.refuse_unpublishable_generation(
            campaign["campaign_identity"].get(
                "generation_provenance_class"),
            "the generic live candidate hard rerun")
        MR.validate_campaign_asset_claims(
            campaign["campaign_identity"], assets,
            validation_path=provenance["mutation_validation"],
            manifest_path=provenance["manifest"],
            map_path=provenance["map"], release_path=provenance["release"])
        identity = campaign["campaign_identity"]
        d4_workers = identity.get("of")
        if type(d4_workers) is not int or not 1 <= d4_workers \
                <= binding.policy["workers"]:
            _refuse("D4 run 2 has an invalid worker cardinality")
        d4_resources = material["worker_resources"][:d4_workers]
        if [record.get("index") for record in d4_resources] \
                != list(range(d4_workers)):
            _refuse("D4 run 2 changed its zero-based worker-resource prefix")
        wanted = {
            key: inputs.get(key) for key in (
                "asset_index_sha256", "asset_project",
                "mutation_validation_sha256", "mutation_validation_class",
                "manifest_sha256", "manifest_digest", "map_sha256",
                "release_sha256", "candidate_run_sha256",
                "candidate_generated_tests_sha256",
                "substrate_baseline_sha256", "applier_sha256",
                "harness_version", "container_image_digest",
                "workspace_seed_digest", "database_dump_digest", "engine",
                "engine_version", "parser",
                *sorted(MR.CAMPAIGN_IDENTITY_FIELDS_V2_ADDED),
            )
        }
        wanted.update({
            "schema": MR.MUTATION_IDENTITY_SCHEMA_V2,
            "solution_generated_tests_sha256": inputs[
                    "candidate_generated_tests_sha256"],
            "kind": "mutation-run", "side": "candidate",
            "timeout_seconds": binding.policy["timeout_seconds"],
            "sample": None, "sample_seed": None,
            "worker_resources_sha256": MR.content_digest(d4_resources),
        })
        changed = sorted(
            key for key, value in wanted.items() if identity.get(key) != value)
        if changed:
            _refuse(
                "D4 run 2 differs from the admitted candidate/assets/runtime "
                f"in field(s) {changed}")
        plan_binding = TQ.validate_d4_confirmation_plan(
            plan_path, run1_campaign=out_dir,
            hard_subset_path=hard_path, candidate_run_path=candidate_path,
            assets=assets,
            validation_path=provenance["mutation_validation"],
            manifest_path=provenance["manifest"],
            map_path=provenance["map"], release_path=provenance["release"])
        if plan_binding["timeout_seconds"] \
                != binding.policy["timeout_seconds"]:
            _refuse("D4 finalization changed the authenticated run-1 timeout")
        expected_d4_workers = min(
            binding.policy["workers"],
            len({mutant_id for _item_id, mutant_id
                 in plan_binding["pairs"]}))
        if d4_workers != expected_d4_workers:
            _refuse(
                "D4 run 2 changed the deterministic nonempty worker "
                "allocation derived from its authenticated plan")
        sidecars = []
        for path in paths:
            with open(MR.provenance_path(path), encoding="utf-8") as fh:
                sidecars.append(json.load(fh))
        TQ.validate_d4_confirmation_run_2_binding(
            rerun_campaign=campaign, shard_sidecars=sidecars,
            plan_binding=plan_binding, plan_path=plan_path,
            run1_campaign=out_dir, hard_subset_path=hard_path)
    except LiveTestQualityRefused:
        raise
    except (TQ.TestQualityRefused, MR.MutationAborted, OSError,
            json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    return campaign["rows"], paths, observation_id


def run_live_candidate(
        candidate_path: str, candidate_receipt_path: object,
        project: str, bundle_version: str, declaration: object,
        installed_bundle: object, binding: object, out_dir: str, *,
        resume: bool = False) -> Optional[dict]:
    """Run one sealed candidate through the admitted generic live route.

    Returns ``None`` for a zero-pass run.  That is intentionally the ordinary
    absence of a test-quality sidecar: the existing results renderer derives
    ``n/a (0 passed)`` from the bound candidate rows and starts no mutation
    campaign.
    """
    from . import mutation_run as MR
    from ..data.release import CAPABILITY_REQUIRED_ROLES
    from . import test_quality as TQ

    rows, candidate_binding, generation, fixture_candidate = _load_candidate(
        candidate_path, candidate_receipt_path)
    passed = TQ.passed_solutions(rows)
    if not passed:
        # Keep the existing renderer contract rather than minting a zero-pass
        # summary shape.  Results already derives ``n/a (0 passed)`` from
        # these rows when no sidecar exists.
        return None
    if TQ.find_sidecar(candidate_path) is not None:
        _refuse("sealed candidate already has a test-quality sidecar")

    capability = resolve_mutation_capability(project, declaration)
    if not capability.supported:
        _refuse(f"{project} declares mutation unsupported: {capability.note}")
    required = _required_role_paths(
        capability, CAPABILITY_REQUIRED_ROLES["mutation"])
    _validated_install(project, bundle_version, installed_bundle)
    admitted = _check_binding(
        binding, project=project, bundle_version=bundle_version,
        leg=LIVE_CANDIDATE)
    if dict(admitted.role_paths) != required:
        _refuse("live candidate binding role paths differ from declaration")
    material = _refresh_binding(admitted)
    _revalidate_readiness_gold(admitted, material)
    if fixture_candidate != bool(admitted.authority.get("fixture")):
        _refuse(
            "fixture-only candidate/authority cannot cross the prospective "
            "native execution boundary")
    inputs = dict(material["identity_inputs"])
    candidate_claims = {
        "candidate_run_sha256": candidate_binding["run_sha256"],
        "candidate_generated_tests_sha256":
            candidate_binding["generated_tests_sha256"],
        **{key: generation.get(key)
           for key in sorted(MR.CAMPAIGN_IDENTITY_FIELDS_V2_ADDED)},
    }
    changed = sorted(
        key for key, value in candidate_claims.items()
        if inputs.get(key) != value)
    if changed:
        _refuse(
            f"sealed candidate differs from live binding field(s) {changed}")

    _mutants, restricted, _covering = TQ.population(
        material["manifest"], material["by_mutant"], passed)
    expected = TQ.expected_pairs(restricted)
    if not expected:
        # Existing root plans require at least one execution job.  A passed
        # item outside the installed draw is not scorable; do not invent a
        # zero-pair campaign or contact a worker for it.
        return None
    gold_reader = _installed_gold_reader(admitted)
    authenticated_gold = gold_reader({}, expected)
    d4_rows, d4_paths, d4_observation = _validated_d4_finalization(
        material, admitted, candidate_path=candidate_path, out_dir=out_dir,
        inputs=inputs, resume=resume)
    execution = _candidate_execution_kwargs(
        admitted.policy, expected, out_dir, resume=resume)
    provenance = dict(material.get("provenance") or {})
    if admitted.authority.get("fixture") is not True:
        if os.path.abspath(provenance.get("run", "")) \
                != os.path.abspath(candidate_path):
            _refuse("live provenance run path differs from the sealed candidate")
        required_provenance = {
            "run", "gold_baseline", "manifest", "map", "release",
            "mutation_validation", "seed", "gold_results_source",
            "gold_results_attestation",
        }
        missing = sorted(
            key for key in required_provenance
            if not isinstance(provenance.get(key), str)
            or not provenance[key])
        if missing:
            _refuse(f"live candidate omits evidence path(s) {missing}")
    _revalidate_live_authority(
        admitted, material,
        (os.path.abspath(candidate_path), os.path.abspath(out_dir)))

    def final_validator(summary: dict, summary_path: str) -> None:
        TQ.validate_native_retry_evidence(
            TQ.load_jsonl(summary["candidate_results"]),
            where="live candidate observation")
        TQ._validate_native_summary_before_completion(
            summary, summary_path, candidate_path,
            installed_gold_reader=gold_reader)

    def execute_candidate(job: dict) -> dict:
        info = admitted.adapter.execute_mutation(job)
        TQ.validate_native_retry_evidence(
            TQ.load_jsonl(job["out"]), where="live candidate shard")
        return info

    kwargs = {
        "run_rows": rows,
        "gold_baseline_rows": material["gold_baseline_rows"],
        "manifest": material["manifest"],
        "by_mutant": material["by_mutant"],
        "out_dir": out_dir,
        "execute": execute_candidate,
        "n_workers": admitted.policy["workers"],
        "authenticated_gold": authenticated_gold,
        "require_complete": True,
        "allow_degraded_gold": False,
        "provenance": provenance,
        "identity_inputs": inputs,
        "timeout": admitted.policy["timeout_seconds"],
        "resume": resume,
        "shard_policy": admitted.policy["shard_policy"],
        "compute_cap_seconds": admitted.policy["compute_cap_seconds"],
        "compute_cap_review_authority":
            admitted.policy["compute_cap_review_authority"],
        **execution,
        "resource_identities": _bound_resource_identities(admitted),
        "worker_resources": material["worker_resources"],
        "hard_subset_doc": material.get("hard_subset_doc"),
        "hard_subset_path": material.get("hard_subset_path"),
        "candidate_hard_rerun_rows": d4_rows,
        "candidate_hard_rerun_paths": d4_paths,
        "candidate_hard_rerun_observation_id": d4_observation,
        "d4_confirmation_plan_out":
            material.get("d4_confirmation_plan_out"),
        "final_summary_validator": final_validator,
    }
    try:
        with MR.coordinator_cancellation() as cancel_event:
            summary = TQ.run_test_quality(
                **kwargs, cancel_event=cancel_event)
    except (TQ.TestQualityRefused, MR.MutationAborted) as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    if summary.get("schema") == TQ.D4_CONFIRMATION_PENDING_SCHEMA:
        return summary
    if summary.get("schema") != TQ.TEST_QUALITY_SUMMARY_SCHEMA:
        _refuse("native test-quality engine returned no final summary")
    try:
        TQ._validate_native_summary(
            summary, os.path.join(out_dir, TQ.SUMMARY), candidate_path,
            installed_gold_reader=gold_reader)
    except TQ.TestQualityRefused as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    sidecar = TQ.write_sidecar(summary, candidate_path)
    try:
        reopened = TQ.load_bound_test_quality(
            candidate_path, sidecar,
            installed_gold_reader=gold_reader)
    except TQ.TestQualityRefused as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    if reopened is None:                                  # pragma: no cover
        _refuse("native sidecar could not be reopened after finalization")
    return reopened


def run_gold_onboarding(
        project: str, bundle_version: str, declaration: object,
        installed_bundle: object, binding: object) -> list[dict]:
    """Execute and validate the policy-enumerated pre-live gold observations.

    The return value contains only the existing validated native-run records
    produced by :func:`r2t.toolkit.gold_killset.load_native_run`.  This leg writes no
    attestation, summary, readiness field, release role, or publication.
    """
    from ..toolkit import gold_killset as GK
    from . import mutation_run as MR
    from . import test_quality as TQ

    capability = resolve_mutation_capability(project, declaration)
    if not capability.supported:
        _refuse(f"{project} declares mutation unsupported: {capability.note}")
    required = _required_role_paths(
        capability, GOLD_ONBOARDING_REQUIRED_ROLES)
    _validated_install(project, bundle_version, installed_bundle)
    admitted = _check_binding(
        binding, project=project, bundle_version=bundle_version,
        leg=GOLD_ONBOARDING)
    if dict(admitted.role_paths) != required:
        _refuse("gold-onboarding binding role paths differ from declaration")
    material = _refresh_binding(admitted)
    if admitted.policy["execution_policy"] != MR.EXECUTION_POLICY_SCALAR_V1:
        _refuse(
            "gold onboarding has no existing live batch producer; the generic "
            "interface preserves the reviewed batch identity for a later "
            "focused adapter without activating it")
    baseline_passed = TQ.passed_solutions(material["gold_baseline_rows"])
    _mutants, restricted, _covering = TQ.population(
        material["manifest"], material["by_mutant"], baseline_passed)
    full_pairs = TQ.expected_pairs(restricted)
    policy_observations = {
        observation["role"]: observation
        for observation in admitted.policy["gold_observations"]
    }
    planned = material["observations"]
    if [observation.get("role") for observation in planned] \
            != list(policy_observations):
        _refuse("gold-onboarding jobs differ from reviewed observation order")
    prepared = []
    for observation in planned:
        role = observation.get("role")
        policy = policy_observations[role]
        workload_path = observation.get("workload_path")
        workload_rows = observation.get("workload_rows")
        if not isinstance(workload_path, str) or not workload_path \
                or not isinstance(workload_rows, list):
            _refuse(
                f"gold observation {role!r} has no exact workload bytes")
        try:
            if TQ.load_jsonl(workload_path) != workload_rows:
                _refuse(
                    f"gold observation {role!r} workload rows differ from "
                    "their exact source bytes")
            workload_files = TQ.passed_solutions(workload_rows)
            workload_binding = TQ.run_binding(workload_path, workload_rows)
        except TQ.TestQualityRefused as exc:
            raise LiveTestQualityRefused(str(exc)) from exc
        if policy["kind"] == "full_gold" and (
                workload_rows != material["gold_baseline_rows"]
                or workload_binding["run_sha256"]
                != material["identity_inputs"]["gold_baseline_sha256"]
                or workload_binding["generated_tests_sha256"]
                != material["identity_inputs"][
                    "gold_generated_tests_sha256"]):
            _refuse(
                f"full-gold observation {role!r} does not execute the exact "
                "installed gold baseline")
        expected = {tuple(pair) for pair in policy["expected_pairs"]}
        if policy["kind"] == "full_gold" and expected != full_pairs:
            _refuse(
                f"full-gold observation {role!r} is not the complete installed "
                "population/map pair set")
        if not expected <= full_pairs:
            _refuse(
                f"gold observation {role!r} contains pair(s) outside the "
                "installed population/map draw")
        jobs = observation.get("jobs")
        if not isinstance(jobs, list) or len(jobs) != admitted.policy["workers"]:
            _refuse(f"gold observation {role!r} has no execution jobs")
        job_pairs = set()
        paths = []
        for worker, job in enumerate(jobs):
            if not isinstance(job, dict) or not isinstance(job.get("out"), str) \
                    or not isinstance(job.get("identity"), dict) \
                    or not isinstance(job.get("expected_pairs"), (set, list)):
                _refuse(f"gold observation {role!r} has a malformed job")
            pairs = {tuple(pair) for pair in job["expected_pairs"]}
            if job_pairs & pairs:
                _refuse(f"gold observation {role!r} jobs overlap")
            job_pairs |= pairs
            identity = job["identity"]
            wanted = {
                **{key: material["identity_inputs"].get(key) for key in (
                    "asset_index_sha256", "asset_project",
                    "mutation_validation_sha256",
                    "mutation_validation_class", "manifest_sha256",
                    "manifest_digest", "map_sha256", "release_sha256",
                    "substrate_baseline_sha256", "applier_sha256",
                    "worker_resources_sha256", "harness_version",
                    "container_image_digest", "workspace_seed_digest",
                    "database_dump_digest", "engine", "engine_version",
                    "parser",
                )},
                "candidate_run_sha256": workload_binding["run_sha256"],
                "candidate_generated_tests_sha256":
                    workload_binding["generated_tests_sha256"],
                "solution_generated_tests_sha256":
                    workload_binding["generated_tests_sha256"],
                "timeout_seconds": admitted.policy["timeout_seconds"],
                "database_dump_digest": "no_database",
                "kind": "mutation-run",
                "sample": None,
                "sample_seed": None,
                "shard": worker,
                "of": admitted.policy["workers"],
                "expected_pairs": len(pairs),
                "expected_pairs_sha256": MR.pair_set_digest(pairs),
            }
            if policy["kind"] == "full_gold":
                wanted["side"] = "gold"
            changed = sorted(
                key for key, value in wanted.items()
                if identity.get(key) != value)
            if identity.get("schema") not in {
                    MR.MUTATION_IDENTITY_SCHEMA_V2,
                    MR.MUTATION_IDENTITY_SCHEMA_V5} \
                    or changed:
                _refuse(
                    f"gold observation {role!r} job identity differs on "
                    f"{changed}")
            try:
                MR.campaign_identity_digest(identity)
                if admitted.authority.get("fixture") is not True:
                    provenance = material["provenance"]
                    MR.validate_campaign_asset_claims(
                        identity, admitted.authority["assets"],
                        validation_path=provenance["mutation_validation"],
                        manifest_path=provenance["manifest"],
                        map_path=provenance["map"],
                        release_path=provenance["release"])
            except MR.MutationAborted as exc:
                raise LiveTestQualityRefused(str(exc)) from exc
            if job.get("side") != identity.get("side") \
                    or job.get("worker") != worker \
                    or job.get("of") != admitted.policy["workers"] \
                    or job.get("files_by_item") != workload_files:
                _refuse(
                    f"gold observation {role!r} job wrapper differs from "
                    f"worker {worker} identity or exact workload")
            paths.append(job["out"])
        if job_pairs != expected:
            _refuse(
                f"gold observation {role!r} job union differs from reviewed "
                "pair set")
        observation_ids = {job.get("observation_id") for job in jobs}
        if len(observation_ids) != 1:
            _refuse(
                f"gold observation {role!r} shards do not share one "
                "observation identity")
        try:
            MR.validate_observation_id(next(iter(observation_ids)))
        except MR.MutationAborted as exc:
            raise LiveTestQualityRefused(str(exc)) from exc
        if policy["kind"] == "control" and any(
                job["identity"].get("schema")
                == MR.MUTATION_IDENTITY_SCHEMA_V5
                and job["identity"].get("reference_control_role") != role
                for job in jobs):
            _refuse(f"gold control {role!r} carries another reference role")
        prepared.append((role, policy, jobs, paths, expected))

    _revalidate_live_authority(admitted, material)
    resource_identities = _bound_resource_identities(admitted)

    def execute_prepared() -> tuple[list[dict], list[dict]]:
        validated = []
        full_gold = []
        with MR.coordinator_cancellation() as cancel_event:
            for role, policy, jobs, paths, expected in prepared:
                for job in jobs:
                    job["resources_locked"] = True
                    job["cancel_event"] = cancel_event
                try:
                    with MR.output_lock(os.path.dirname(paths[0])):
                        TQ.execute_jobs(
                            jobs, admitted.adapter.execute_mutation,
                            cancel_event=cancel_event)
                except TQ.TestQualityRefused as exc:
                    raise LiveTestQualityRefused(str(exc)) from exc
                try:
                    record = GK.load_native_run(
                        paths, expected_jobs=jobs,
                        required_side=jobs[0]["identity"]["side"])
                    TQ.validate_native_retry_evidence(
                        [row for path in paths for row in TQ.load_jsonl(path)],
                        where=f"gold observation {role!r}")
                except (GK.GoldKillsetRefused, MR.MutationAborted,
                        TQ.TestQualityRefused) as exc:
                    raise LiveTestQualityRefused(str(exc)) from exc
                if set(record["outcomes"]) != expected:
                    _refuse(
                        f"gold observation {role!r} returned another pair "
                        "set")
                if record["facts"].get("observation_id") \
                        != jobs[0].get("observation_id"):
                    _refuse(
                        f"gold observation {role!r} output-plan identity "
                        "differs from its exact native shard identity")
                # Strict gold admission: every infrastructure outcome is
                # retained in native rows but cannot become reusable gold.
                try:
                    TQ.check_gold_degradation(
                        [row for path in paths
                         for row in TQ.load_jsonl(path)],
                        {item_id: "passed" for item_id in baseline_passed},
                        baseline_passed, gold_provenance_class="native",
                        require_complete=True, allow_degraded_gold=False)
                except TQ.TestQualityRefused as exc:
                    raise LiveTestQualityRefused(str(exc)) from exc
                validated.append(record)
                if policy["kind"] == "full_gold":
                    full_gold.append(record)
        return validated, full_gold

    try:
        with MR.mutation_resource_locks(resource_identities):
            validated, full_gold = execute_prepared()
    except MR.MutationAborted as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    observation_ids = [
        record["facts"]["observation_id"] for record in validated]
    if len(observation_ids) != len(set(observation_ids)):
        _refuse(
            "gold/control observations are not independently identified")
    if len(full_gold) != 2 \
            or full_gold[0]["facts"]["observation_id"] \
            == full_gold[1]["facts"]["observation_id"]:
        _refuse("full-gold observations are not two independent executions")
    try:
        GK.validate_observation_pair(full_gold[0], full_gold[1])
    except GK.GoldKillsetRefused as exc:
        raise LiveTestQualityRefused(str(exc)) from exc
    if admitted.policy["population_id"] is not None:
        try:
            GK.build(
                admitted.policy["population_id"], full_gold[0], full_gold[1])
        except GK.GoldKillsetRefused as exc:
            raise LiveTestQualityRefused(str(exc)) from exc
    return validated


def selftest() -> int:
    """Synthetic, network-free coverage of both generic live legs."""
    import json
    import tempfile
    from argparse import Namespace

    from . import campaign_table as CT
    from . import cli
    from ..toolkit import gold_killset as GK
    from . import mutation_run as MR
    from ..data import release
    from . import slice3_test_quality as S3Q
    try:
        from ..agents import slice3_eval
    except ImportError:
        print("  [SKIP] the live legs: both of them launch a Slice-3 "
              "mutation job through the agent coordinator, and this "
              "checkout has no agent component")
        return 0
    from . import test_quality as TQ
    from . import worker as W

    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    def refusal(fn, needle=""):
        try:
            fn()
        except (LiveTestQualityRefused, TQ.TestQualityRefused, SystemExit,
                slice3_eval.Slice3Refused) as exc:
            return not needle or needle in str(exc)
        except Exception:                                   # noqa: BLE001
            return False
        return False

    project = "synthetic-live-fixture"
    version = "fixture-v1"
    installed = {"project": project, "version": version}
    six_roles = release.CAPABILITY_REQUIRED_ROLES["mutation"]
    role_paths = {role: f"fixture/{role}.json" for role in six_roles}

    def declaration(*, supported=True, complete=True):
        artifacts = dict(role_paths)
        if not complete:
            artifacts.pop("gold_results")
            artifacts.pop("gold_results_attestation")
        return {
            "project": project,
            "capabilities": {
                "mutation": supported,
                "coverage": False,
                "api_similarity": False,
            },
            "capability_notes": {
                **({"mutation": "synthetic fixture has no mutant route"}
                   if not supported else {}),
                "coverage": "synthetic fixture does not measure coverage",
                "api_similarity":
                    "synthetic fixture does not measure API similarity",
            },
            **({"mutation_engine": "r2t-mutate"} if supported else {}),
            "bundle": {"artifacts": artifacts},
        }

    mutant = {
        "id": "m1", "file": "src/example.py", "operator": "fixture-op",
        "start_line": 1, "start_col": 1, "original": "a", "mutated": "b",
    }
    manifest = {
        "digest": "d" * 64,
        "engine": "r2t-mutate",
        "engine_version": "1.0",
        "parser": "fixture-parser/1",
        "mutants": [mutant],
    }
    by_mutant = {"m1": ["i1"]}
    candidate_rows = [{
        "item_id": "i1", "outcome": "passed",
        "produced_files": [{"file_path": "tests/test_i1.py",
                            "code": "def test_i1(): assert True\n"}],
    }]
    zero_rows = [{"item_id": "i1", "outcome": "failed",
                  "produced_files": []}]
    gold_baseline = [{
        "item_id": "i1", "outcome": "passed",
        "produced_files": [{"file_path": "tests/gold_i1.py",
                            "code": "def test_gold(): assert True\n"}],
    }]
    pair_list = [["i1", "m1"]]
    worker_resources: list[dict] = []
    runtime_exact: dict[str, object] = {}
    installed_gold: Optional[_AdmittedInstalledGold] = None

    class FixtureAdapter:
        def __init__(self, root: str, candidate_path: str,
                     rows: list[dict], *, leg: str):
            os.makedirs(root, exist_ok=True)
            self.root = root
            self.candidate_path = candidate_path
            self.rows = rows
            self.leg = leg
            self.calls = []
            self.execute_mode = "complete"
            self.candidate_outcome = "failed"
            self.gold_outcome = "failed"
            self.gold_outcomes = {}
            self.retry_evidence_override = None
            self.role_edits = {role: "" for role in six_roles}
            self.gold_results = [{"item_id": "i1", "mutant_id": "m1",
                                  "file": mutant["file"],
                                  "operator": mutant["operator"],
                                  "outcome": "failed"}]
            self.gold_attestation = {"fixture": "validated-in-selftest"}
            self.gold_attestation_path = os.path.join(
                root, f"{leg}-gold-attestation.json")
            with open(self.gold_attestation_path, "w", encoding="utf-8") as fh:
                json.dump(self.gold_attestation, fh, sort_keys=True)
                fh.write("\n")
            self.control_rows = [{
                "item_id": "i1", "outcome": "passed",
                "produced_files": [{
                    "file_path": "tests/control_i1.py",
                    "code": "def test_control(): assert 1 == 1\n",
                }],
            }]
            self.control_path = os.path.join(root, "control-workload.jsonl")
            with open(self.control_path, "w", encoding="utf-8") as fh:
                for row in self.control_rows:
                    fh.write(json.dumps(row, sort_keys=True) + "\n")
            self.policy = {
                "population_id": None,
                "manifest_digest": manifest["digest"],
                "engine": manifest["engine"],
                "engine_version": manifest["engine_version"],
                "parser": manifest["parser"],
                "timeout_seconds": 60,
                "workers": 1,
                "shard_policy": TQ.SHARD_POLICY_BALANCED_PAIRS_V1,
                "execution_policy": MR.EXECUTION_POLICY_SCALAR_V1,
                "batch_plan_sha256": None,
                "max_batch_members": None,
                "max_batch_instances": None,
                "stack_reset_sha256": None,
                "batch_journal_schema": None,
                "confirmation": "none",
                "gold_observations": [
                    {"role": "full_gold_a", "kind": "full_gold",
                     "expected_pairs": pair_list},
                    {"role": "full_gold_b", "kind": "full_gold",
                     "expected_pairs": pair_list},
                    {"role": "fixture_control", "kind": "control",
                     "expected_pairs": pair_list},
                ],
                "needs_database": False,
                "network": "none",
                "database_dump_digest": "no_database",
                "compute_cap_seconds": None,
                "compute_cap_review_authority": None,
            }
            self.identity_inputs = self._identity_inputs()
            self.observations = self._observation_jobs() \
                if leg == GOLD_ONBOARDING else None

        def _identity_inputs(self):
            generation = (TQ.FIXTURE_GENERATION_INPUTS
                          if self.leg == LIVE_CANDIDATE else {
                              "generation_provenance_class": "native_v2",
                              "generation_attempt_id":
                                  "synthetic-full-gold-attempt",
                              "generation_campaign_digest": "a" * 16,
                              "generation_agent_runtime_sha256": "b" * 64,
                              "generation_network_semantics": "none",
                              "generation_condition": None,
                              "generation_protocol_version": None,
                              "generation_protocol_digest": None,
                              "generation_native_budget": None,
                          })
            exact = {
                **generation,
                **runtime_exact,
                "asset_project": project,
                "database_dump_digest": "no_database",
                "worker_resources_sha256": MR.content_digest(
                    worker_resources),
                "gold_baseline_sha256": MR.sha256_file(
                    onboarding_candidate),
                "gold_generated_tests_sha256": MR.candidate_digest(
                    TQ.passed_solutions(gold_baseline)),
            }
            if os.path.isfile(self.candidate_path):
                binding = TQ.run_binding(self.candidate_path, self.rows)
                exact.update({
                    "candidate_run_sha256": binding["run_sha256"],
                    "candidate_generated_tests_sha256":
                        binding["generated_tests_sha256"],
                })
            return TQ.identity_inputs_for_test_quality(
                run_rows=self.rows, gold_baseline_rows=gold_baseline,
                manifest=manifest, by_mutant=by_mutant,
                gold_results=self.gold_results,
                gold_results_attestation=self.gold_attestation,
                exact=exact)

        def _facts(self, leg):
            wanted = (GOLD_ONBOARDING_REQUIRED_ROLES if leg == GOLD_ONBOARDING
                      else six_roles)
            identities = {
                "mutation_validation": self.identity_inputs[
                    "mutation_validation_sha256"],
                "scored_manifest": self.identity_inputs["manifest_sha256"],
                "mutation_map": self.identity_inputs["map_sha256"],
                "gold_baseline": self.identity_inputs[
                    "gold_baseline_sha256"],
                "gold_results": self.identity_inputs[
                    "gold_results_sha256"],
                "gold_results_attestation": self.identity_inputs[
                    "gold_results_attestation_sha256"],
            }
            answer = {}
            for role in wanted:
                answer[role] = {
                    "path": role_paths[role],
                    "identity": identities[role] + self.role_edits[role],
                }
            return answer

        def _standalone_identity(self, role, workload_path, workload_rows):
            inputs = self.identity_inputs
            files = TQ.passed_solutions(workload_rows)
            generated = MR.candidate_digest(files)
            return MR.build_campaign_identity(
                **{key: inputs.get(key)
                   for key in sorted(MR.CAMPAIGN_IDENTITY_FIELDS_V2_ADDED)},
                asset_index_sha256=inputs["asset_index_sha256"],
                asset_project=project,
                mutation_validation_sha256=inputs[
                    "mutation_validation_sha256"],
                mutation_validation_class="native",
                manifest_sha256=inputs["manifest_sha256"],
                manifest_digest=manifest["digest"],
                map_sha256=inputs["map_sha256"],
                release_sha256=inputs["release_sha256"],
                candidate_run_sha256=MR.sha256_file(workload_path),
                candidate_generated_tests_sha256=generated,
                solution_generated_tests_sha256=generated,
                substrate_baseline_sha256=inputs[
                    "substrate_baseline_sha256"],
                applier_sha256=inputs["applier_sha256"],
                worker_resources_sha256=inputs["worker_resources_sha256"],
                harness_version=inputs["harness_version"],
                container_image_digest=inputs["container_image_digest"],
                workspace_seed_digest=inputs["workspace_seed_digest"],
                database_dump_digest="no_database",
                expected_pairs={("i1", "m1")},
                engine=manifest["engine"],
                engine_version=manifest["engine_version"],
                parser=manifest["parser"],
                side=("gold" if role.startswith("full_gold")
                      else "candidate"),
                shard=0, of=1,
                timeout=self.policy["timeout_seconds"])

        def _observation_jobs(self):
            answer = []
            for number, role in enumerate(
                    ("full_gold_a", "full_gold_b", "fixture_control"), 1):
                workload_path = (self.candidate_path
                                 if role.startswith("full_gold")
                                 else self.control_path)
                workload_rows = (self.rows if role.startswith("full_gold")
                                 else self.control_rows)
                files = TQ.passed_solutions(workload_rows)
                side = ("gold" if role.startswith("full_gold")
                        else "candidate")
                answer.append(
                {"role": role,
                 "workload_path": workload_path,
                 "workload_rows": copy.deepcopy(workload_rows),
                 "jobs": [{
                    "out": os.path.join(
                        self.root, role, f"{side}.w0.jsonl"),
                    "identity": self._standalone_identity(
                        role, workload_path, workload_rows),
                    "observation_id": str(number) * 32,
                    "expected_pairs": {("i1", "m1")},
                    "files_by_item": copy.deepcopy(files),
                    "side": side, "worker": 0, "of": 1,
                    "observation_role": role,
                }]})
            return answer

        def live_test_quality_policy(self, leg):
            assert leg == self.leg
            return copy.deepcopy(self.policy)

        def live_test_quality_authority(self, leg):
            assert leg == self.leg
            return _fixture_execution_authority(
                project, version, leg, self.policy, {
                    "worker_resources": copy.deepcopy(worker_resources),
                    "worker_resources_sha256": MR.content_digest(
                        worker_resources),
                    **runtime_exact,
                    "docker_execution_authority": {
                        "fixture": "network-free"},
                    "docker_execution_pool_digest": "c" * 64,
                    "protected_evidence_paths": [],
                    "worker_spec_paths": [],
                    "seed_dir": "fixture",
                })

        def read_installed_gold(self, _expected):
            if self.leg != LIVE_CANDIDATE:
                _refuse("gold-onboarding adapter has no installed-gold role")
            try:
                with open(onboarding.gold_attestation_path,
                          encoding="utf-8") as fh:
                    installed_attestation = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                _refuse(f"fixture installed-gold attestation changed: {exc}")
            if installed_attestation != onboarding.gold_attestation \
                    or MR.content_digest(installed_attestation) \
                    != self._facts(LIVE_CANDIDATE)[
                        "gold_results_attestation"]["identity"]:
                _refuse("fixture installed-gold attestation changed")
            return self.live_test_quality_material(
                LIVE_CANDIDATE).get("admitted_gold")

        def live_test_quality_material(self, leg):
            assert leg == self.leg
            self.identity_inputs = self._identity_inputs()
            material = {
                "manifest": manifest,
                "by_mutant": by_mutant,
                "gold_baseline_rows": gold_baseline,
                "identity_inputs": self.identity_inputs,
                "worker_resources": worker_resources,
                "role_facts": self._facts(leg),
                "provenance": {
                    "run": self.candidate_path,
                    "gold_baseline": onboarding_candidate,
                    "manifest": onboarding_candidate,
                    "map": onboarding_candidate,
                    "release": onboarding_candidate,
                    "mutation_validation": onboarding_candidate,
                    "seed": seed_dir,
                    "gold_results_source": root,
                    "gold_results_attestation": (
                        onboarding.gold_attestation_path
                        if installed_gold is not None
                        else self.gold_attestation_path),
                },
            }
            if leg == GOLD_ONBOARDING:
                material["observations"] = self.observations
            else:
                material["admitted_gold"] = installed_gold
            return material

        def execute_mutation(self, job):
            self.calls.append(job)
            out = job["out"]
            identity = job["identity"]
            if identity.get("kind") == "mutation-run":
                MR.prepare_standalone_output_directory(
                    out, identity, job.get("observation_id"))
                outcome = self.gold_outcomes.get(
                    job.get("observation_role"), self.gold_outcome)
            else:
                os.makedirs(os.path.dirname(out), exist_ok=True)
                outcome = self.candidate_outcome
            if self.execute_mode != "missing":
                retry_evidence = (
                    self.retry_evidence_override
                    if self.retry_evidence_override is not None else
                    (2, True) if outcome in MR.INFRASTRUCTURE_OUTCOMES
                    else (1, False))
                row = {
                    "item_id": "i1", "mutant_id": "m1",
                    "file": mutant["file"], "operator": mutant["operator"],
                    "outcome": outcome,
                    "attempt": retry_evidence[0],
                    "retried_infrastructure": retry_evidence[1],
                    **MR.row_identity_stamp(identity),
                }
                with open(out, "w", encoding="utf-8") as fh:
                    fh.write(json.dumps(row, sort_keys=True) + "\n")
            provenance = (job.get("provenance") or {}) | {
                "worker_resources": worker_resources,
            }
            MR.write_shard_provenance(
                out, identity, "running", provenance=provenance)
            terminal = ("running" if self.execute_mode == "running" else
                        "failed" if self.execute_mode == "missing" else
                        "complete")
            if terminal != "running":
                MR.write_shard_provenance(
                    out, identity, terminal, provenance=provenance,
                    error=("fixture missing row" if terminal == "failed"
                           else None))
            return {"out": out, "status": terminal}

    check("the portable mutation role vocabulary remains exactly the #203 "
          "six-role tuple",
          six_roles == (
              "mutation_validation", "scored_manifest", "mutation_map",
              "gold_baseline", "gold_results",
              "gold_results_attestation"))
    unsupported = resolve_mutation_readiness(
        project, version, declaration(supported=False), installed)
    preserved = resolve_mutation_readiness(
        project, version, declaration(), installed)
    check("shared readiness derives unsupported and preserved-only without a "
          "caller route flag",
          unsupported.state == UNSUPPORTED
          and preserved.state == PRESERVED_EVIDENCE_ONLY)
    check("a Boolean cannot authorize prospective mutation work",
          refusal(lambda: resolve_mutation_readiness(
              project, version, declaration(), installed, True),
              "was not validated"))

    with tempfile.TemporaryDirectory() as root:
        seed_dir = os.path.join(root, "seed")
        os.makedirs(seed_dir)
        workspace_tar = os.path.join(seed_dir, "workspace.tar")
        with open(workspace_tar, "wb") as fh:
            fh.write(b"synthetic live fixture workspace")
        with open(os.path.join(seed_dir, "seed.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({
                "format": 1,
                "seed_key": "synthetic-live-fixture",
                "needs_database": False,
                "workspace": {"digest": MR.sha256_file(workspace_tar)},
                "database": {"declared": "no_database"},
            }, fh, sort_keys=True)
        seed_identity = W.verified_seed_identity(seed_dir, False)
        workspace = os.path.join(root, "worker-workspace")
        os.makedirs(workspace)
        env_file = os.path.join(root, "worker.env")
        with open(env_file, "w", encoding="utf-8") as fh:
            fh.write("R2T_WORKER_INDEX=0\n")
        os.chmod(env_file, 0o600)
        worker = W.WorkerSpec(
            index=0, workspace=workspace, container="synthetic-worker-0",
            schema="", credential="", env_file=env_file,
            workdir="/workspace")
        worker_spec = os.path.join(root, "worker0.json")
        with open(worker_spec, "w", encoding="utf-8") as fh:
            json.dump(worker.to_json(), fh, sort_keys=True)
        runtime_path = W.runtime_attestation_path(worker_spec)
        runtime_doc = {
            "schema": W.WORKER_RUNTIME_SCHEMA_V2,
            "worker": worker.to_json(),
            "worker_spec_sha256": MR.sha256_file(worker_spec),
            **seed_identity,
            "container_image_digest": "sha256:" + "7" * 64,
            "docker_endpoint_selection": "legacy-default",
            "harness_version": "fixture-harness-v1",
        }
        with open(runtime_path, "w", encoding="utf-8") as fh:
            json.dump(runtime_doc, fh, sort_keys=True)
        worker_resources.extend([{
            "index": 0,
            "worker_spec": os.path.realpath(worker_spec),
            "workspace": os.path.realpath(worker.workspace),
            "container": worker.container,
            "schema": worker.schema,
            "credential": worker.credential,
            "env_file": os.path.realpath(worker.env_file),
            "workdir": worker.workdir,
            "runtime_attestation": os.path.realpath(runtime_path),
            "runtime_attestation_sha256": MR.sha256_file(runtime_path),
        }])
        runtime_exact.update({
            "workspace_seed_digest": seed_identity[
                "workspace_seed_digest"],
            "database_dump_digest": "no_database",
            "container_image_digest": runtime_doc[
                "container_image_digest"],
            "harness_version": runtime_doc["harness_version"],
        })

        onboarding_candidate = os.path.join(root, "gold-baseline.jsonl")
        with open(onboarding_candidate, "w", encoding="utf-8") as fh:
            for row in gold_baseline:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        onboarding = FixtureAdapter(
            root, onboarding_candidate, gold_baseline, leg=GOLD_ONBOARDING)
        another_engine = declaration(complete=False)
        another_engine["mutation_engine"] = "r2t-mutate-py"
        check("the reviewed adapter policy must bind the declared mutation "
              "engine",
              refusal(lambda: validate_live_binding(
                  project, version, another_engine, installed,
                  leg=GOLD_ONBOARDING, adapter=onboarding),
                  "policy engine differs"))
        onboarding_binding = validate_live_binding(
            project, version, declaration(complete=False), installed,
            leg=GOLD_ONBOARDING, adapter=onboarding)
        observations = run_gold_onboarding(
            project, version, declaration(complete=False), installed,
            onboarding_binding)
        check("the separate four-role gate executes two complete independent "
              "full-gold observations plus the reviewed control without "
              "conferring readiness and supplies the native cancellation "
              "contract",
              len(observations) == 3
              and len({record["facts"]["observation_id"]
                       for record in observations}) == 3
              and observations[2]["identity"]["side"] == "candidate"
              and all(call.get("cancel_event") is not None
                      for call in onboarding.calls)
              and len({id(call["cancel_event"])
                       for call in onboarding.calls}) == 1
              and refusal(lambda: resolve_mutation_readiness(
                  project, version, declaration(complete=False), installed),
                  "missing required installed role"),
              str(observations))
        swapped = FixtureAdapter(
            os.path.join(root, "swapped-control"), onboarding_candidate,
            gold_baseline, leg=GOLD_ONBOARDING)
        swapped_binding = validate_live_binding(
            project, version, declaration(complete=False), installed,
            leg=GOLD_ONBOARDING, adapter=swapped)
        swapped.observations[2]["workload_path"] = onboarding_candidate
        swapped.observations[2]["workload_rows"] = copy.deepcopy(
            gold_baseline)
        check("a policy-enumerated control cannot swap its exact workload "
              "after the four-role binding",
              refusal(lambda: run_gold_onboarding(
                  project, version, declaration(complete=False), installed,
                  swapped_binding), "workload")
              and swapped.calls == [])
        installed_gold = admit_installed_gold(
            project, version, onboarding.policy,
            onboarding._facts(LIVE_CANDIDATE), observations,
            identity_inputs=onboarding.identity_inputs)
        check("candidate gold admission consumes the onboarding N=2 records "
              "through the same policy and six-role identities",
              isinstance(installed_gold, _AdmittedInstalledGold)
              and ("i1", "m1") in GK.validate_observation_pair(
                  installed_gold.records[0],
                  installed_gold.records[1])["intersection"])
        incomplete_draw_root = os.path.join(root, "incomplete-gold-draw")
        os.makedirs(incomplete_draw_root)
        incomplete_draw_path = os.path.join(
            incomplete_draw_root, "candidate.jsonl")
        with open(incomplete_draw_path, "w", encoding="utf-8") as fh:
            for row in candidate_rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        extra_mutant = {
            **mutant, "id": "m2", "start_line": 2,
            "original": "c", "mutated": "d",
        }
        manifest["mutants"].append(extra_mutant)
        by_mutant["m2"] = ["i1"]
        try:
            incomplete_draw = FixtureAdapter(
                incomplete_draw_root, incomplete_draw_path, candidate_rows,
                leg=LIVE_CANDIDATE)
            incomplete_draw_binding = validate_live_binding(
                project, version, declaration(), installed,
                leg=LIVE_CANDIDATE, adapter=incomplete_draw)
            incomplete_draw_refused = refusal(
                lambda: resolve_mutation_readiness(
                    project, version, declaration(), installed,
                    incomplete_draw_binding),
                "complete installed population/map draw")
        finally:
            manifest["mutants"].pop()
            by_mutant.pop("m2")
        check("live readiness refuses a policy whose N=2 gold draw is only "
              "a strict subset of the installed population/map draw before "
              "execution",
              incomplete_draw_refused and incomplete_draw.calls == [])
        changed_gold_records = copy.deepcopy(observations)
        changed_gold_records[0]["outcomes"][("i1", "m1")] = "passed"
        check("changed post-validation gold observation facts cannot be "
              "re-admitted through an intact role label",
              refusal(lambda: admit_installed_gold(
                  project, version, onboarding.policy,
                  onboarding._facts(LIVE_CANDIDATE), changed_gold_records,
                  identity_inputs=onboarding.identity_inputs),
                  "validated record"))

        flip_root = os.path.join(root, "gold-flip")
        os.makedirs(flip_root)
        flip = FixtureAdapter(
            flip_root, onboarding_candidate, gold_baseline,
            leg=GOLD_ONBOARDING)
        flip.gold_outcomes["full_gold_b"] = "passed"
        flip_binding = validate_live_binding(
            project, version, declaration(complete=False), installed,
            leg=GOLD_ONBOARDING, adapter=flip)
        flip_records = run_gold_onboarding(
            project, version, declaration(complete=False), installed,
            flip_binding)
        flip_gold = admit_installed_gold(
            project, version, flip.policy, flip._facts(LIVE_CANDIDATE),
            flip_records, identity_inputs=flip.identity_inputs)
        check("full-gold admission keeps the existing conservative N=2 "
              "intersection instead of choosing either observation",
              ("i1", "m1") not in GK.validate_observation_pair(
                  flip_gold.records[0], flip_gold.records[1])[
                      "intersection"])

        strict_root = os.path.join(root, "strict")
        os.makedirs(strict_root)
        strict_path = os.path.join(strict_root, "gold-baseline.jsonl")
        with open(strict_path, "w", encoding="utf-8") as fh:
            for row in gold_baseline:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        strict = FixtureAdapter(
            strict_root, strict_path, gold_baseline, leg=GOLD_ONBOARDING)
        strict.gold_outcome = "container_error"
        strict_binding = validate_live_binding(
            project, version, declaration(complete=False), installed,
            leg=GOLD_ONBOARDING, adapter=strict)
        try:
            run_gold_onboarding(
                project, version, declaration(complete=False), installed,
                strict_binding)
        except LiveTestQualityRefused as exc:
            strict_refusal = str(exc)
        else:
            strict_refusal = ""
        check("gold onboarding retains native infrastructure evidence but "
              "strictly refuses its admission",
              "infrastructure" in strict_refusal
              and any(os.path.isfile(job["out"])
                      for observation in strict.observations
                      for job in observation["jobs"])
              and len(strict.calls) == 1, strict_refusal)

        nonretry_root = os.path.join(root, "strict-nonretry")
        nonretry_path = os.path.join(nonretry_root, "gold-baseline.jsonl")
        os.makedirs(nonretry_root)
        with open(nonretry_path, "w", encoding="utf-8") as fh:
            for row in gold_baseline:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        nonretry = FixtureAdapter(
            nonretry_root, nonretry_path, gold_baseline,
            leg=GOLD_ONBOARDING)
        # Exercise installed admission itself: the ordinary onboarding gate
        # already rejects this scoring-infrastructure outcome, so temporarily
        # observe the authenticated native records that reach the later gate.
        nonretry.gold_outcomes["full_gold_a"] = "solution_error"
        nonretry_binding = validate_live_binding(
            project, version, declaration(complete=False), installed,
            leg=GOLD_ONBOARDING, adapter=nonretry)
        saved_gold_degradation = TQ.check_gold_degradation
        TQ.check_gold_degradation = lambda *_args, **_kwargs: {}
        try:
            nonretry_records = run_gold_onboarding(
                project, version, declaration(complete=False), installed,
                nonretry_binding)
        finally:
            TQ.check_gold_degradation = saved_gold_degradation
        check("installed gold admission rejects the full scoring "
              "infrastructure vocabulary, including non-retriable outcomes",
              refusal(lambda: admit_installed_gold(
                  project, version, nonretry.policy,
                  nonretry._facts(LIVE_CANDIDATE), nonretry_records,
                  identity_inputs=nonretry.identity_inputs),
                  "infrastructure"))

        retry_gold_root = os.path.join(root, "invalid-gold-retry")
        os.makedirs(retry_gold_root)
        retry_gold_path = os.path.join(
            retry_gold_root, "gold-baseline.jsonl")
        with open(retry_gold_path, "w", encoding="utf-8") as fh:
            for row in gold_baseline:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        retry_gold = FixtureAdapter(
            retry_gold_root, retry_gold_path, gold_baseline,
            leg=GOLD_ONBOARDING)
        retry_gold.retry_evidence_override = (2, False)
        retry_gold_binding = validate_live_binding(
            project, version, declaration(complete=False), installed,
            leg=GOLD_ONBOARDING, adapter=retry_gold)
        onboarding_retry_refused = refusal(
            lambda: run_gold_onboarding(
                project, version, declaration(complete=False), installed,
                retry_gold_binding),
            "record one fact and disagree")

        retry_validator = TQ.validate_native_retry_evidence

        def refuse_installed_retry(*_args, **_kwargs):
            raise TQ.TestQualityRefused(
                "REFUSED: synthetic installed retry evidence")

        TQ.validate_native_retry_evidence = refuse_installed_retry
        try:
            admission_retry_refused = refusal(
                lambda: admit_installed_gold(
                    project, version, onboarding.policy,
                    onboarding._facts(LIVE_CANDIDATE), observations,
                    identity_inputs=onboarding.identity_inputs),
                "synthetic installed retry evidence")
        finally:
            TQ.validate_native_retry_evidence = retry_validator
        check("new and installed native gold observations always validate "
              "attempt/retried-infrastructure agreement",
              onboarding_retry_refused and admission_retry_refused)

        real_native_validator = TQ._validate_native_summary
        native_validation_calls = []

        def fixture_native_validator(
                summary, summary_path, run_path, *,
                installed_gold_reader=None, _campaign_status="complete"):
            if summary.get("schema") != TQ.TEST_QUALITY_SUMMARY_SCHEMA \
                    or summary.get("binding") != TQ.run_binding(run_path):
                raise TQ.TestQualityRefused(
                    "REFUSED: synthetic native summary lost its run binding")
            with open(TQ._campaign_state_path(os.path.dirname(
                    summary["candidate_results"])), encoding="utf-8") as fh:
                state = json.load(fh)
            if state.get("status") != _campaign_status:
                raise TQ.TestQualityRefused(
                    "REFUSED: synthetic final validator saw the wrong root "
                    "state")
            expected = {("i1", "m1")}
            selected = TQ._read_authenticated_installed_gold(
                installed_gold_reader, summary=summary, expected=expected,
                identity_inputs={
                    "gold_attestation_pairs_sha256": summary[
                        "gold_attestation_pairs_sha256"],
                    "gold_results_sha256": summary["gold_results_sha256"],
                    "gold_results_attestation_sha256": summary[
                        "gold_results_attestation_sha256"],
                })
            if selected != TQ.load_jsonl(summary["gold_results"]):
                raise TQ.TestQualityRefused(
                    "REFUSED: synthetic saved reader changed selected gold")
            native_validation_calls.append(_campaign_status)

        # Fixture generation is intentionally unpublishable.  The production
        # path above always invokes the real native validator before root
        # completion; this narrow replacement lets the synthetic test observe
        # that gate without fabricating a release-ready asset/runtime tree.
        TQ._validate_native_summary = fixture_native_validator
        try:
            def candidate_case(name, rows=candidate_rows):
                case_root = os.path.join(root, name)
                os.makedirs(case_root)
                path = os.path.join(case_root, "candidate.jsonl")
                with open(path, "w", encoding="utf-8") as fh:
                    for row in rows:
                        fh.write(json.dumps(row, sort_keys=True) + "\n")
                adapter = FixtureAdapter(
                    case_root, path, rows, leg=LIVE_CANDIDATE)
                binding = validate_live_binding(
                    project, version, declaration(), installed,
                    leg=LIVE_CANDIDATE, adapter=adapter)
                return case_root, path, adapter, binding

            success_root, success_path, success, success_binding = \
                candidate_case("candidate-success")
            success_seal = _seal_fixture_candidate(success_path)
            live = resolve_mutation_readiness(
                project, version, declaration(), installed, success_binding)
            summary = run_live_candidate(
                success_path, success_seal, project, version, declaration(),
                installed, success_binding,
                os.path.join(success_root, "campaign"))
            with open(TQ._campaign_state_path(os.path.join(
                    success_root, "campaign")), encoding="utf-8") as fh:
                success_state = json.load(fh)
            success_identity = success_state["plan"]["jobs"][0][
                "campaign_identity"]
            recovered_execution = _candidate_execution_kwargs(
                success.policy, {("i1", "m1")},
                os.path.join(success_root, "campaign"), resume=True)
            check("the complete six-role binding derives live-capable and "
                  "runs through explicit V4 policy identity, native final "
                  "validation, and the reopenable binding writer",
                  live.state == LIVE_CAPABLE
                  and summary["schema"] == TQ.TEST_QUALITY_SUMMARY_SCHEMA
                  and summary["pairs_expected"] == 1
                  and TQ.find_sidecar(success_path) is not None
                  and success_identity["schema"]
                  == MR.MUTATION_IDENTITY_SCHEMA_V4
                  and success_identity["execution_policy"]
                  == MR.EXECUTION_POLICY_SCALAR_V1
                  and recovered_execution["execution_observation_id"]
                  == success_identity["observation_id"]
                  and all(call.get("cancel_event") is not None
                          for call in success.calls)
                  and "running" in native_validation_calls
                  and "complete" in native_validation_calls)

            raw_gold_path = GK.native_run_paths(
                installed_gold.records[0])[0]
            with open(raw_gold_path, "rb") as fh:
                raw_gold_bytes = fh.read()
            try:
                with open(raw_gold_path, "ab") as fh:
                    fh.write(b"\n")
                changed_raw_refused = refusal(
                    lambda: TQ.load_bound_test_quality(
                        success_path,
                        installed_gold_reader=_installed_gold_reader(
                            success_binding)))
                changed_raw_readiness_refused = refusal(
                    lambda: resolve_mutation_readiness(
                        project, version, declaration(), installed,
                        success_binding))
            finally:
                with open(raw_gold_path, "wb") as fh:
                    fh.write(raw_gold_bytes)
            check("the adapter-aware saved reader reopens unchanged raw N=2 "
                  "evidence for both readiness and summary use instead of "
                  "trusting the selected copy",
                  changed_raw_refused and changed_raw_readiness_refused)

            infra_root, infra_path, infra, infra_binding = \
                candidate_case("candidate-infrastructure")
            infra.candidate_outcome = "container_error"
            infra_summary = run_live_candidate(
                infra_path, _seal_fixture_candidate(infra_path), project,
                version, declaration(), installed, infra_binding,
                os.path.join(infra_root, "campaign"))
            candidate_evidence = TQ.load_jsonl(
                infra_summary["candidate_results"])
            check("a terminal candidate infrastructure outcome remains exact "
                  "evidence, imputes no kill, and does not veto completion",
                  infra_summary["pairs_executed_candidate"] == 1
                  and candidate_evidence[0]["outcome"] == "container_error"
                  and infra_summary["per_item"]["i1"][
                      "candidate_killed"] == 0)

            retry_root, retry_path, retry_candidate, retry_binding = \
                candidate_case("candidate-invalid-retry")
            retry_candidate.candidate_outcome = "container_error"
            retry_candidate.retry_evidence_override = (1, False)
            retry_out = os.path.join(retry_root, "campaign")
            check("a retriable candidate infrastructure outcome cannot "
                  "complete without its required second-attempt evidence",
                  refusal(lambda: run_live_candidate(
                      retry_path, _seal_fixture_candidate(retry_path),
                      project, version, declaration(), installed,
                      retry_binding, retry_out),
                      "retry that did not happen")
                  and not os.path.exists(os.path.join(
                      retry_out, TQ.SUMMARY))
                  and TQ.find_sidecar(retry_path) is None)

            missing_root, missing_path, missing, missing_binding = \
                candidate_case("candidate-missing")
            missing.execute_mode = "missing"
            missing_out = os.path.join(missing_root, "campaign")
            check("missing or nonterminal candidate execution retains root "
                  "evidence and emits no summary or run sidecar",
                  refusal(lambda: run_live_candidate(
                      missing_path, _seal_fixture_candidate(missing_path),
                      project, version, declaration(), installed,
                      missing_binding, missing_out))
                  and os.path.isfile(os.path.join(
                      missing_out, TQ.CAMPAIGN_STATE))
                  and not os.path.exists(os.path.join(missing_out, TQ.SUMMARY))
                  and TQ.find_sidecar(missing_path) is None)

            zero_root, zero_path, zero, zero_binding = \
                candidate_case("zero-pass", zero_rows)
            zero_out = os.path.join(zero_root, "campaign")
            check("zero-pass preserves n/a semantics without starting "
                  "mutation work",
                  run_live_candidate(
                      zero_path, _seal_fixture_candidate(zero_path), project,
                      version, declaration(), installed, zero_binding,
                      zero_out) is None
                  and zero.calls == [] and not os.path.exists(zero_out))

            changed_root, changed_path, changed, changed_binding = \
                candidate_case("changed-candidate")
            changed_seal = _seal_fixture_candidate(changed_path)
            with open(changed_path, "a", encoding="utf-8") as fh:
                fh.write("\n")
            check("changed sealed candidate bytes refuse before execution",
                  refusal(lambda: run_live_candidate(
                      changed_path, changed_seal, project, version,
                      declaration(), installed, changed_binding,
                      os.path.join(changed_root, "campaign")), "changed")
                  and changed.calls == [])

            class ChangedBaselineAdapter(FixtureAdapter):
                changed_baseline = False

                def live_test_quality_material(self, leg):
                    material = super().live_test_quality_material(leg)
                    if self.changed_baseline:
                        rows_ = copy.deepcopy(gold_baseline)
                        rows_[0]["produced_files"][0]["code"] = (
                            "def test_gold(): assert False\n")
                        material["gold_baseline_rows"] = rows_
                    return material

            baseline_root = os.path.join(root, "changed-gold-baseline")
            os.makedirs(baseline_root)
            baseline_path = os.path.join(baseline_root, "candidate.jsonl")
            with open(baseline_path, "w", encoding="utf-8") as fh:
                for row in candidate_rows:
                    fh.write(json.dumps(row, sort_keys=True) + "\n")
            changed_baseline = ChangedBaselineAdapter(
                baseline_root, baseline_path, candidate_rows,
                leg=LIVE_CANDIDATE)
            changed_baseline_binding = validate_live_binding(
                project, version, declaration(), installed,
                leg=LIVE_CANDIDATE, adapter=changed_baseline)
            changed_baseline.changed_baseline = True
            check("changed in-memory gold-baseline rows cannot reach mutation "
                  "work under the unchanged installed baseline identity",
                  refusal(lambda: run_live_candidate(
                      baseline_path, _seal_fixture_candidate(baseline_path),
                      project, version, declaration(), installed,
                      changed_baseline_binding,
                      os.path.join(baseline_root, "campaign")),
                      "gold-baseline rows")
                  and changed_baseline.calls == [])

            from . import result_ledger as RL
            real_receipt_validator = RL.verify_receipt
            real_generation_resolver = MR.generation_evidence_for_run
            RL.verify_receipt = lambda _path: {
                "complete": True, "artifact_kind": "merged_run",
                "result_path": os.path.abspath(success_path),
                "result_file_sha256": MR.sha256_file(success_path),
            }
            MR.generation_evidence_for_run = lambda _path, _rows: {
                **TQ.FIXTURE_GENERATION_INPUTS,
                "generation_provenance_class": "legacy_exact_bytes",
            }
            try:
                historical_candidate_refused = refusal(
                    lambda: _load_candidate(success_path, "receipt.json"),
                    "historical exact-byte")
            finally:
                RL.verify_receipt = real_receipt_validator
                MR.generation_evidence_for_run = real_generation_resolver
            check("historical exact-byte candidate provenance remains "
                  "read-only even behind a complete receipt",
                  historical_candidate_refused)

            for role in ("scored_manifest", "mutation_map", "gold_results",
                         "gold_results_attestation"):
                role_root, role_path, changed_role, role_binding = \
                    candidate_case("changed-" + role)
                changed_role.role_edits[role] = "-changed"
                check(f"changed {role} evidence refuses before execution",
                      refusal(lambda adapter=changed_role,
                                     binding_=role_binding,
                                     path_=role_path, root_=role_root:
                              run_live_candidate(
                                  path_, _seal_fixture_candidate(path_),
                                  project, version, declaration(), installed,
                                  binding_, os.path.join(root_, "campaign")),
                              "changed")
                      and changed_role.calls == [])

            confirmation_root = os.path.join(root, "conditional-confirmation")
            os.makedirs(confirmation_root)
            confirmation_path = os.path.join(
                confirmation_root, "candidate.jsonl")
            with open(confirmation_path, "w", encoding="utf-8") as fh:
                for row in candidate_rows:
                    fh.write(json.dumps(row, sort_keys=True) + "\n")
            hard_path = os.path.join(confirmation_root, "hard-subset.json")
            with open(hard_path, "w", encoding="utf-8") as fh:
                json.dump({"fixture": "population-pinned hard subset"}, fh)

            class ConfirmationAdapter(FixtureAdapter):
                def __init__(self):
                    super().__init__(
                        confirmation_root, confirmation_path, candidate_rows,
                        leg=LIVE_CANDIDATE)
                    self.policy["confirmation"] = "d4"
                    self.confirmation_gold = admit_installed_gold(
                        project, version, self.policy,
                        self._facts(LIVE_CANDIDATE), observations,
                        identity_inputs=self.identity_inputs,
                        hard_subset_sha256=MR.sha256_file(hard_path))
                    self.hard_doc = {
                        "fixture": "population-pinned hard subset"}
                    self.plan_path = os.path.join(
                        confirmation_root, "confirmation-plan.json")

                def live_test_quality_material(self, leg):
                    material = super().live_test_quality_material(leg)
                    material.update({
                        "admitted_gold": self.confirmation_gold,
                        "hard_subset_doc": self.hard_doc,
                        "hard_subset_path": hard_path,
                        "hard_subset_attested_sha256": MR.sha256_file(
                            hard_path),
                        "d4_confirmation_plan_out": self.plan_path,
                    })
                    return material

            confirmation = ConfirmationAdapter()
            confirmation_binding = validate_live_binding(
                project, version, declaration(), installed,
                leg=LIVE_CANDIDATE, adapter=confirmation)
            saved_hard_doc = confirmation.hard_doc
            confirmation.hard_doc = {"fixture": "changed hard subset"}
            changed_hard_refused = refusal(
                lambda: run_live_candidate(
                    confirmation_path,
                    _seal_fixture_candidate(confirmation_path),
                    project, version, declaration(), installed,
                    confirmation_binding,
                    os.path.join(confirmation_root, "changed-hard-campaign")),
                "hard-subset document")
            confirmation.hard_doc = saved_hard_doc
            check("changed in-memory D4 hard-subset content refuses against "
                  "the installed bytes before mutation work",
                  changed_hard_refused and confirmation.calls == [])
            real_runner = TQ.run_test_quality
            confirmation_kwargs = {}

            def pending_runner(**kwargs):
                confirmation_kwargs.update(kwargs)
                return {
                    "schema": TQ.D4_CONFIRMATION_PENDING_SCHEMA,
                    "status": "awaiting_d4_confirmation",
                }

            TQ.run_test_quality = pending_runner
            try:
                pending = run_live_candidate(
                    confirmation_path,
                    _seal_fixture_candidate(confirmation_path),
                    project, version, declaration(), installed,
                    confirmation_binding,
                    os.path.join(confirmation_root, "campaign"))
            finally:
                TQ.run_test_quality = real_runner
            check("conditional confirmation inputs come only from the "
                  "reviewed binding, and a pending first observation writes "
                  "no sidecar",
                  pending["schema"] == TQ.D4_CONFIRMATION_PENDING_SCHEMA
                  and confirmation_kwargs["require_complete"] is True
                  and confirmation_kwargs["allow_degraded_gold"] is False
                  and confirmation_kwargs["hard_subset_doc"]
                  is confirmation.hard_doc
                  and confirmation_kwargs["hard_subset_path"] == hard_path
                  and confirmation_kwargs["d4_confirmation_plan_out"]
                  == confirmation.plan_path
                  and TQ.find_sidecar(confirmation_path) is None)

            run_1_dir = os.path.join(confirmation_root, "campaign")
            run_1_observation_id = confirmation_kwargs[
                "execution_observation_id"]
            run_1_pairs = {("i1", "m1")}
            run_1_inputs = {
                **confirmation.identity_inputs,
                "gold_provenance_class": "native",
                "gold_attestation_manifest_digest": manifest["digest"],
                "gold_attestation_pairs_sha256": MR.pair_set_digest(
                    run_1_pairs),
                "gold_attestation_engine": manifest["engine"],
                "gold_attestation_engine_version": manifest[
                    "engine_version"],
            }
            run_1_jobs = TQ.plan_jobs(
                [mutant], {"candidate": TQ.passed_solutions(candidate_rows)},
                by_mutant, confirmation.policy["workers"], run_1_dir,
                sides=("candidate",),
                identity_inputs=run_1_inputs,
                timeout=confirmation.policy["timeout_seconds"],
                shard_policy=confirmation.policy["shard_policy"],
                execution_policy=confirmation.policy["execution_policy"],
                batch_plan_sha256=confirmation.policy["batch_plan_sha256"],
                max_batch_members=confirmation.policy["max_batch_members"],
                max_batch_instances=confirmation.policy[
                    "max_batch_instances"],
                stack_reset_sha256=confirmation.policy[
                    "stack_reset_sha256"],
                batch_journal_schema=confirmation.policy[
                    "batch_journal_schema"],
                estimand_pairs_sha256=MR.pair_set_digest(run_1_pairs),
                observation_id=run_1_observation_id)
            run_1_plan = TQ.build_test_quality_campaign_plan(
                run_1_jobs, expected=run_1_pairs, gold_precomputed=True,
                worker_resources=worker_resources)
            invalid_run_1_job = copy.deepcopy(run_1_jobs[0])
            invalid_run_1_job["out"] = os.path.join(
                confirmation_root, "invalid-run-1", "candidate.w0.jsonl")
            confirmation.candidate_outcome = "container_error"
            confirmation.retry_evidence_override = (1, False)
            invalid_run_1_refused = refusal(
                lambda: confirmation_kwargs["execute"](invalid_run_1_job),
                "retry that did not happen")
            confirmation.candidate_outcome = "failed"
            confirmation.retry_evidence_override = None
            check("D4 run 1 validates retry evidence before a confirmation "
                  "plan can be emitted",
                  invalid_run_1_refused
                  and not os.path.exists(confirmation.plan_path))
            TQ.prepare_output_directory(
                run_1_dir, run_1_jobs, resume=False,
                campaign_plan=run_1_plan)
            fixture_plan = {
                "digest": "e" * 64,
                "source": {"observation_id": run_1_observation_id},
                "candidate": {
                    "run_sha256": MR.sha256_file(confirmation_path),
                    "generated_tests_sha256": MR.candidate_digest(
                        TQ.passed_solutions(candidate_rows)),
                },
            }
            with open(confirmation.plan_path, "w", encoding="utf-8") as fh:
                json.dump(fixture_plan, fh, sort_keys=True)
                fh.write("\n")
            fixture_plan_binding = {
                "plan": fixture_plan,
                "pairs": {("i1", "m1")},
                "candidate_files": TQ.passed_solutions(candidate_rows),
                "mutants": [mutant],
                "expected_run_1_pairs": {("i1", "m1")},
                "timeout_seconds": confirmation.policy["timeout_seconds"],
                "run_1_observation_id": run_1_observation_id,
                "candidate_identities": [
                    job["identity"] for job in run_1_jobs],
            }
            real_plan_validator = TQ.validate_d4_confirmation_plan
            producer_plan_calls = []
            TQ.validate_d4_confirmation_plan = lambda *_args, **_kwargs: (
                producer_plan_calls.append((_args, _kwargs))
                or copy.deepcopy(fixture_plan_binding))
            run_2_dir = os.path.join(confirmation_root, "run-2")
            try:
                confirmation.gold_outcome = "container_error"
                confirmation.retry_evidence_override = (1, False)
                invalid_run_2_refused = refusal(
                    lambda: run_live_confirmation(
                        confirmation_path,
                        _seal_fixture_candidate(confirmation_path),
                        project, version, declaration(), installed,
                        confirmation_binding, run_1_dir=run_1_dir,
                        plan_path=confirmation.plan_path,
                        out_dir=os.path.join(
                            confirmation_root, "invalid-run-2")),
                    "retry that did not happen")
                retry_validator = TQ.validate_native_retry_evidence
                TQ.validate_native_retry_evidence = \
                    lambda *_args, **_kwargs: None
                try:
                    invalid_resume_paths = run_live_confirmation(
                        confirmation_path,
                        _seal_fixture_candidate(confirmation_path),
                        project, version, declaration(), installed,
                        confirmation_binding, run_1_dir=run_1_dir,
                        plan_path=confirmation.plan_path,
                        out_dir=os.path.join(
                            confirmation_root, "invalid-resume-run-2"))
                finally:
                    TQ.validate_native_retry_evidence = retry_validator
                invalid_resume_refused = refusal(
                    lambda: _validated_d4_finalization({
                        "candidate_hard_rerun_paths": invalid_resume_paths,
                        "hard_subset_path": hard_path,
                        "candidate_hard_plan_path": confirmation.plan_path,
                    }, confirmation_binding,
                        candidate_path=confirmation_path,
                        out_dir=run_1_dir,
                        inputs=confirmation.identity_inputs, resume=True),
                    "retry that did not happen")
                confirmation.gold_outcome = "failed"
                confirmation.retry_evidence_override = None
                producer_plan_calls.clear()
                rerun_paths = run_live_confirmation(
                    confirmation_path,
                    _seal_fixture_candidate(confirmation_path),
                    project, version, declaration(), installed,
                    confirmation_binding, run_1_dir=run_1_dir,
                    plan_path=confirmation.plan_path, out_dir=run_2_dir)
                rerun_campaign = MR.validate_native_shards(
                    rerun_paths, expected_pairs={("i1", "m1")},
                    required_side="candidate", return_campaign=True)

                confirmation.execute_mode = "running"
                missing_run_2_dir = os.path.join(
                    confirmation_root, "run-2-missing")
                missing_run_2_refused = refusal(
                    lambda: run_live_confirmation(
                        confirmation_path,
                        _seal_fixture_candidate(confirmation_path),
                        project, version, declaration(), installed,
                        confirmation_binding, run_1_dir=run_1_dir,
                        plan_path=confirmation.plan_path,
                        out_dir=missing_run_2_dir))
                with open(os.path.join(
                        missing_run_2_dir, MR.MUTATION_OUTPUT_PLAN),
                        encoding="utf-8") as fh:
                    interrupted_observation = json.load(fh)["observation_id"]
                nonterminal_retained = (
                    missing_run_2_refused
                    and os.path.isfile(MR.provenance_path(os.path.join(
                        missing_run_2_dir, "candidate.w0.jsonl")))
                    and not os.path.isfile(os.path.join(
                        missing_run_2_dir, TQ.SUMMARY))
                    and TQ.find_sidecar(confirmation_path) is None)
                confirmation.execute_mode = "complete"
                resumed_paths = run_live_confirmation(
                    confirmation_path,
                    _seal_fixture_candidate(confirmation_path),
                    project, version, declaration(), installed,
                    confirmation_binding, run_1_dir=run_1_dir,
                    plan_path=confirmation.plan_path,
                    out_dir=missing_run_2_dir, resume=True)
                resumed_campaign = MR.validate_native_shards(
                    resumed_paths, expected_pairs={("i1", "m1")},
                    required_side="candidate", return_campaign=True)
            finally:
                confirmation.execute_mode = "complete"
                TQ.validate_d4_confirmation_plan = real_plan_validator
            run_2_job = confirmation.calls[-3]
            check("the generic D4 phase executes only the exact qualifying "
                  "plan through the bound adapter and retains no score of "
                  "its own",
                  len(rerun_paths) == 1
                  and run_2_job["expected_pairs"] == {("i1", "m1")}
                  and run_2_job["identity"]["schema"]
                  == MR.MUTATION_IDENTITY_SCHEMA_V2
                  and run_2_job["identity"]["kind"] == "mutation-run"
                  and run_2_job["identity"]["side"] == "candidate"
                  and rerun_campaign["pairs"] == {("i1", "m1")}
                  and rerun_campaign["observation_id"]
                  != run_1_observation_id
                  and os.path.isfile(os.path.join(
                      run_2_dir, MR.MUTATION_OUTPUT_PLAN))
                  and not os.path.isfile(os.path.join(
                      run_2_dir, TQ.SUMMARY))
                  and TQ.find_sidecar(confirmation_path) is None
                  and len(producer_plan_calls) == 3)
            check("missing or nonterminal D4 run 2 retains native evidence, "
                  "emits no score or sidecar, and exact native resume "
                  "preserves its observation identity",
                  nonterminal_retained
                  and resumed_campaign["observation_id"]
                  == interrupted_observation
                  and resumed_campaign["observation_id"]
                  != run_1_observation_id)
            check("D4 run 2 validates retry evidence both when produced and "
                  "when reopened for root resume",
                  invalid_run_2_refused and invalid_resume_refused,
                  str((invalid_run_2_refused, invalid_resume_refused)))

            final_material = confirmation.live_test_quality_material(
                LIVE_CANDIDATE)
            final_material.pop("d4_confirmation_plan_out")
            final_material.update({
                "candidate_hard_rerun_paths": rerun_paths,
                "candidate_hard_plan_path": confirmation.plan_path,
            })
            final_inputs = dict(final_material["identity_inputs"])
            real_asset_claims = MR.validate_campaign_asset_claims
            real_publishable = TQ.refuse_unpublishable_generation
            real_plan_validator = TQ.validate_d4_confirmation_plan
            real_run2_validator = TQ.validate_d4_confirmation_run_2_binding
            d4_calls = []
            MR.validate_campaign_asset_claims = lambda *_args, **_kwargs: \
                d4_calls.append("assets")
            TQ.refuse_unpublishable_generation = lambda *_args, **_kwargs: None
            TQ.validate_d4_confirmation_plan = lambda *_args, **_kwargs: (
                d4_calls.append("plan")
                or copy.deepcopy(fixture_plan_binding))

            def tracked_run_2(**kwargs):
                real_run2_validator(**kwargs)
                d4_calls.append("run2")

            TQ.validate_d4_confirmation_run_2_binding = tracked_run_2
            try:
                d4_rows, d4_paths, d4_id = _validated_d4_finalization(
                    final_material, confirmation_binding,
                    candidate_path=confirmation_path,
                    out_dir=os.path.join(confirmation_root, "campaign"),
                    inputs=final_inputs, resume=True)
            finally:
                MR.validate_campaign_asset_claims = real_asset_claims
                TQ.refuse_unpublishable_generation = real_publishable
                TQ.validate_d4_confirmation_plan = real_plan_validator
                TQ.validate_d4_confirmation_run_2_binding = real_run2_validator
            check("D4 finalization authenticates assets, the exact run-1 "
                  "plan, and the complete run-2 binding before reuse",
                  d4_calls == ["assets", "plan", "run2"]
                  and d4_rows == rerun_campaign["rows"]
                  and d4_paths == rerun_paths
                  and d4_id == rerun_campaign["observation_id"])

            # Exercise the existing D4 K(run 2) rule through the generic
            # producer: a reviewed two-worker run 1 can have only one
            # qualifying mutant, in which case run 2 must bind the exact
            # zero-based one-worker resource prefix.
            prefix_root = os.path.join(confirmation_root, "worker-prefix")
            os.makedirs(prefix_root)
            prefix_workspace = os.path.join(prefix_root, "worker-workspace")
            os.makedirs(prefix_workspace)
            prefix_env = os.path.join(prefix_root, "worker.env")
            with open(prefix_env, "w", encoding="utf-8") as fh:
                fh.write("R2T_WORKER_INDEX=1\n")
            os.chmod(prefix_env, 0o600)
            prefix_worker = W.WorkerSpec(
                index=1, workspace=prefix_workspace,
                container="synthetic-worker-1", schema="", credential="",
                env_file=prefix_env, workdir="/workspace")
            prefix_worker_spec = os.path.join(prefix_root, "worker1.json")
            with open(prefix_worker_spec, "w", encoding="utf-8") as fh:
                json.dump(prefix_worker.to_json(), fh, sort_keys=True)
            prefix_runtime_path = W.runtime_attestation_path(
                prefix_worker_spec)
            prefix_runtime_doc = {
                **runtime_doc,
                "worker": prefix_worker.to_json(),
                "worker_spec_sha256": MR.sha256_file(prefix_worker_spec),
            }
            with open(prefix_runtime_path, "w", encoding="utf-8") as fh:
                json.dump(prefix_runtime_doc, fh, sort_keys=True)
            prefix_resources = [copy.deepcopy(worker_resources[0]), {
                "index": 1,
                "worker_spec": os.path.realpath(prefix_worker_spec),
                "workspace": os.path.realpath(prefix_worker.workspace),
                "container": prefix_worker.container,
                "schema": prefix_worker.schema,
                "credential": prefix_worker.credential,
                "env_file": os.path.realpath(prefix_worker.env_file),
                "workdir": prefix_worker.workdir,
                "runtime_attestation": os.path.realpath(
                    prefix_runtime_path),
                "runtime_attestation_sha256": MR.sha256_file(
                    prefix_runtime_path),
            }]

            class PrefixConfirmationAdapter(FixtureAdapter):
                def __init__(self):
                    super().__init__(
                        prefix_root, confirmation_path, candidate_rows,
                        leg=LIVE_CANDIDATE)
                    self.policy["workers"] = 2
                    self.policy["confirmation"] = "d4"
                    self.identity_inputs = self._identity_inputs()
                    self.hard_doc = {
                        "fixture": "population-pinned hard subset"}
                    self.plan_path = os.path.join(
                        prefix_root, "confirmation-plan.json")

                def _identity_inputs(self):
                    inputs_ = super()._identity_inputs()
                    inputs_["worker_resources_sha256"] = MR.content_digest(
                        prefix_resources)
                    return inputs_

                def live_test_quality_authority(self, leg):
                    assert leg == self.leg
                    return _fixture_execution_authority(
                        project, version, leg, self.policy, {
                            "worker_resources": copy.deepcopy(
                                prefix_resources),
                            "worker_resources_sha256": MR.content_digest(
                                prefix_resources),
                            **runtime_exact,
                            "docker_execution_authority": {
                                "fixture": "network-free"},
                            "docker_execution_pool_digest": "f" * 64,
                            "protected_evidence_paths": [],
                            "worker_spec_paths": [],
                            "seed_dir": "fixture",
                        })

                def live_test_quality_material(self, leg):
                    material = super().live_test_quality_material(leg)
                    material.update({
                        "admitted_gold": None,
                        "worker_resources": copy.deepcopy(prefix_resources),
                        "hard_subset_doc": self.hard_doc,
                        "hard_subset_path": hard_path,
                        "hard_subset_attested_sha256": MR.sha256_file(
                            hard_path),
                        "d4_confirmation_plan_out": self.plan_path,
                    })
                    return material

                def read_installed_gold(self, expected):
                    inputs_ = self._identity_inputs()
                    return TQ._seal_authenticated_gold_selection(
                        [{
                            "item_id": item_id, "mutant_id": mutant_id,
                            "outcome": "failed",
                        } for item_id, mutant_id in sorted(expected)], {
                            "validation_class": "native",
                            "manifest_digest": manifest["digest"],
                            "pairs_sha256": MR.pair_set_digest(expected),
                            "engine": manifest["engine"],
                            "engine_version": manifest["engine_version"],
                            "gold_results_sha256": inputs_[
                                "gold_results_sha256"],
                            "gold_results_attestation_sha256": inputs_[
                                "gold_results_attestation_sha256"],
                            "gold_results_source": root,
                            "gold_results_attestation":
                                onboarding.gold_attestation_path,
                        })

            prefix = PrefixConfirmationAdapter()
            prefix_binding = validate_live_binding(
                project, version, declaration(), installed,
                leg=LIVE_CANDIDATE, adapter=prefix)
            prefix_run_1_dir = os.path.join(prefix_root, "campaign")
            prefix_run_1_observation_id = "9" * 32
            prefix_inputs = {
                **prefix.identity_inputs,
                "gold_provenance_class": "native",
                "gold_attestation_manifest_digest": manifest["digest"],
                "gold_attestation_pairs_sha256": MR.pair_set_digest(
                    run_1_pairs),
                "gold_attestation_engine": manifest["engine"],
                "gold_attestation_engine_version": manifest[
                    "engine_version"],
            }
            prefix_run_1_jobs = TQ.plan_jobs(
                [mutant], {"candidate": TQ.passed_solutions(candidate_rows)},
                by_mutant, prefix.policy["workers"], prefix_run_1_dir,
                sides=("candidate",), identity_inputs=prefix_inputs,
                timeout=prefix.policy["timeout_seconds"],
                shard_policy=prefix.policy["shard_policy"],
                execution_policy=prefix.policy["execution_policy"],
                batch_plan_sha256=prefix.policy["batch_plan_sha256"],
                max_batch_members=prefix.policy["max_batch_members"],
                max_batch_instances=prefix.policy["max_batch_instances"],
                stack_reset_sha256=prefix.policy["stack_reset_sha256"],
                batch_journal_schema=prefix.policy[
                    "batch_journal_schema"],
                estimand_pairs_sha256=MR.pair_set_digest(run_1_pairs),
                observation_id=prefix_run_1_observation_id)
            prefix_run_1_plan = TQ.build_test_quality_campaign_plan(
                prefix_run_1_jobs, expected=run_1_pairs,
                gold_precomputed=True, worker_resources=prefix_resources)
            TQ.prepare_output_directory(
                prefix_run_1_dir, prefix_run_1_jobs, resume=False,
                campaign_plan=prefix_run_1_plan)
            prefix_plan = {
                "digest": "8" * 64,
                "source": {"observation_id": prefix_run_1_observation_id},
                "candidate": {
                    "run_sha256": MR.sha256_file(confirmation_path),
                    "generated_tests_sha256": MR.candidate_digest(
                        TQ.passed_solutions(candidate_rows)),
                },
            }
            with open(prefix.plan_path, "w", encoding="utf-8") as fh:
                json.dump(prefix_plan, fh, sort_keys=True)
                fh.write("\n")
            prefix_plan_binding = {
                "plan": prefix_plan,
                "pairs": {("i1", "m1")},
                "candidate_files": TQ.passed_solutions(candidate_rows),
                "mutants": [mutant],
                "expected_run_1_pairs": {("i1", "m1")},
                "timeout_seconds": prefix.policy["timeout_seconds"],
                "run_1_observation_id": prefix_run_1_observation_id,
                "candidate_identities": [
                    job["identity"] for job in prefix_run_1_jobs],
            }
            real_plan_validator = TQ.validate_d4_confirmation_plan
            TQ.validate_d4_confirmation_plan = (
                lambda *_args, **_kwargs: copy.deepcopy(prefix_plan_binding))
            prefix_run_2_dir = os.path.join(prefix_root, "run-2")
            try:
                prefix_paths = run_live_confirmation(
                    confirmation_path,
                    _seal_fixture_candidate(confirmation_path),
                    project, version, declaration(), installed,
                    prefix_binding, run_1_dir=prefix_run_1_dir,
                    plan_path=prefix.plan_path, out_dir=prefix_run_2_dir)
                prefix_campaign = MR.validate_native_shards(
                    prefix_paths, expected_pairs=run_1_pairs,
                    required_side="candidate", return_campaign=True)
                with open(MR.provenance_path(prefix_paths[0]),
                          encoding="utf-8") as fh:
                    prefix_sidecar = json.load(fh)
                prefix_material = prefix.live_test_quality_material(
                    LIVE_CANDIDATE)
                prefix_material.pop("d4_confirmation_plan_out")
                prefix_material.update({
                    "candidate_hard_rerun_paths": prefix_paths,
                    "candidate_hard_plan_path": prefix.plan_path,
                })
                real_asset_claims = MR.validate_campaign_asset_claims
                real_publishable = TQ.refuse_unpublishable_generation
                MR.validate_campaign_asset_claims = (
                    lambda *_args, **_kwargs: None)
                TQ.refuse_unpublishable_generation = (
                    lambda *_args, **_kwargs: None)
                try:
                    prefix_final = _validated_d4_finalization(
                        prefix_material, prefix_binding,
                        candidate_path=confirmation_path,
                        out_dir=prefix_run_1_dir,
                        inputs=dict(prefix_material["identity_inputs"]),
                        resume=True)
                finally:
                    MR.validate_campaign_asset_claims = real_asset_claims
                    TQ.refuse_unpublishable_generation = real_publishable
            finally:
                TQ.validate_d4_confirmation_plan = real_plan_validator
            check("generic D4 derives and re-authenticates the exact smaller "
                  "zero-based worker-resource prefix",
                  len(prefix_run_1_jobs) == 1
                  and prefix_run_1_jobs[0]["identity"]["of"] == 2
                  and prefix_campaign["campaign_identity"]["of"] == 1
                  and prefix_campaign["campaign_identity"][
                      "worker_resources_sha256"]
                  == MR.content_digest(prefix_resources[:1])
                  and prefix_sidecar["worker_resources"]
                  == prefix_resources[:1]
                  and prefix_final[1] == prefix_paths)
        finally:
            TQ._validate_native_summary = real_native_validator

        descriptor_path = os.path.join(root, "historical-descriptor.json")
        with open(descriptor_path, "w", encoding="utf-8") as fh:
            json.dump({
                "schema": CT.DESCRIPTOR_SCHEMA,
                "cells": [{"label": "historical", "mutation_capable": True,
                           "unavailable": CT.UNMERGEABLE}],
            }, fh)
        historical = CT.load_descriptor(descriptor_path)
        check("historical mutation_capable stays readable reporting evidence "
              "but cannot authorize prospective work",
              historical["cells"][0]["mutation_capable"] is True
              and refusal(lambda: resolve_mutation_readiness(
                  project, version, declaration(), installed,
                  historical["cells"][0]["mutation_capable"]),
                  "was not validated"))

        check("every direct Slice-3 forward seam now refuses independently",
              refusal(lambda: cli.run_slice3_mutation_job({}, []), "retired")
              and refusal(lambda: slice3_eval.launch_mutation_job(
                  {}, project="fixture", role="full_gold_a",
                  observation_id=None, observation_paths=[], run1_path=None,
                  runner_argv=[]), "retired")
              and refusal(lambda: slice3_eval.run_bound_mutation_job(
                  {}, project="fixture", role="full_gold_a",
                  observation_id="0" * 32, harness=None, mutants=[],
                  items_by_id={}, files_by_item={}, by_mutant={},
                  engine_dir="", out_path="", identity={}, manifest={}),
                  "retired"))

        saved_builder = S3Q.build_summary
        saved_printer = S3Q.print_summary
        reader_calls = []
        S3Q.build_summary = lambda run, **kwargs: (
            reader_calls.append((run, kwargs)) or {"fixture": "saved"})
        S3Q.print_summary = lambda summary: reader_calls.append(summary)
        try:
            reader_status = cli.cmd_test_quality(Namespace(
                run=os.path.join(root, "saved-run.jsonl"),
                slice3_observations=os.path.join(root, "saved-observations"),
                slice3_bundle=os.path.join(root, "saved-bundle.json"),
                no_sidecar=True))
        finally:
            S3Q.build_summary = saved_builder
            S3Q.print_summary = saved_printer
        check("the Docker-free Slice-3 saved-evidence reader still dispatches "
              "before every live gate",
              reader_status == 0 and len(reader_calls) == 2)

    print("  live_test_quality: OK" if ok else
          "  live_test_quality: FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":                                # pragma: no cover
    raise SystemExit(selftest())
