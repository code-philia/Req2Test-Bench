"""Open an installed three-role reference-controls tree from disk.

`reference_controls` can seal a scope and rejoin a relocated observation,
but only from workload bindings and paths a caller already holds.  Nothing
derived those bindings from what is on disk, so the sealed
`ReferenceControls` a consumer needs had no from-disk route.

This is that route.  Given the directory a reference collection installed --
`full_gold/`, `stripped_gold/`, `stub/`, each a standalone v2 mutation output
directory -- it reads each role's campaign identity out of the tree, turns the
three identities into the adapter workload authority the scope bridge
requires, binds that population to its reviewed native mutation-validation
report, and returns the sealed controls the preserved reader validated.

Two things it deliberately does not do.

It does not consent to anything, and it does not declare anything.  Section
5.1's narrowing is consented to once, at mint time, by
`build_reference_controls(allow_excluded_pairs=True)`, and the consent is then
a recorded field of the attestation.  A declared item subset is declared once,
at collection time, to `seal_reference_scope`, and is likewise a recorded
field.  A from-disk load is a read: it hands both recorded facts back to the
same derivation and the same scope bridge the mint ran, so an artifact that
carries exclusions WITHOUT the disclosure is still refused here, an artifact
whose declaration the gold baseline does not force is still refused by the
bridge, and a properly disclosed one loads without the operator being asked to
decide again what has already been decided.

It does not re-check what the preserved reader checks.  The per-role plan,
shard set, row stamps, sidecars, campaign cores and pair coverage are all
settled by `load_preserved_reference_controls`; this module only supplies the
bindings that reader cannot derive for itself.
"""
from __future__ import annotations

import json
import os
from typing import Optional

from ..data import mutation_attestation
from . import mutation_run
from . import reference_controls
from ..data import versions

from .reference_controls import ReferenceControlsRefused


def _refuse(message: str) -> None:
    raise ReferenceControlsRefused(f"REFUSED: {message}.")


def _read_json(path: str, label: str) -> dict:
    if os.path.islink(path) or not os.path.isfile(path):
        _refuse(f"{label} is not a regular file: {path}")
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        _refuse(f"cannot read {label} {path}: {exc}")
    if not isinstance(value, dict):
        _refuse(f"{label} is not a JSON object")
    return value


def _native_role_source(role: str, role_root: str) -> tuple[dict, dict]:
    """Read one role's workload binding and campaign identity off disk.

    Any shard of the role serves: the preserved reader refuses a role whose
    shards carry mixed campaign cores, and the workload binding lives in the
    core.  Shard 0 is read because a validated shard set is exactly
    ``0..of-1``, so it is the one shard every complete role has, and its name
    is derived from the role's OWN side rather than from the directory --
    a `full_gold/` holding candidate-side shards has no `gold.w0.jsonl` and
    fails here rather than being read under the wrong role.
    """
    from . import reference_pair_continuation as PC
    continued = os.path.isfile(os.path.join(role_root, PC.MARKER))
    if continued:
        # A delivered Sylius319 continuation aggregate: binding discovery
        # only; the reference reader validates both segments.
        plan = _read_json(os.path.join(role_root, "plan.json"),
                          "continued role plan")
        try:
            continued_role = PC.plan_role(plan)
        except (KeyError, TypeError, mutation_run.MutationAborted):
            continued_role = None
        if continued_role != role:
            _refuse("continued reference role differs")
        identity = plan.get("parent_identity")
    elif not os.path.isfile(os.path.join(role_root, mutation_run.MUTATION_OUTPUT_PLAN)):
        if role != "full_gold" or os.path.islink(role_root) or not os.path.isdir(role_root):
            _refuse("invalid host-partitioned reference root")
        hosts = sorted(os.listdir(role_root))
        if not hosts:
            _refuse("empty host-partitioned reference root")
        # This is only a representative workload binding. The observation
        # reader authenticates every host and proves the exact disjoint union.
        # A supplement host names its own freeze (owner ruling 2026-09-30),
        # so the binding is the first parent-allocation host's.
        def supplement(host):
            identity = _read_json(mutation_run.provenance_path(
                os.path.join(role_root, host, "gold.w0.jsonl")),
                "host reference shard provenance").get("campaign_identity")
            return "supplement_plan_sha256" in ((identity or {}).get("reference_partition") or {})
        role_root = os.path.join(role_root, next(
            (host for host in hosts if not supplement(host)), hosts[0]))
    if not continued:
        side = reference_controls.ROLE_SIDE[role]
        shard = os.path.join(role_root, f"{side}.w0.jsonl")
        identity = _read_json(
            mutation_run.provenance_path(shard),
            f"{role} reference shard provenance").get("campaign_identity")
    if not isinstance(identity, dict):
        _refuse(f"{role} reference shard provenance has no campaign identity")
    workload = {
        "candidate_run_sha256": identity.get("candidate_run_sha256"),
        "generated_tests_sha256":
            identity.get("candidate_generated_tests_sha256"),
        "reference_source_tag": identity.get("reference_source_tag"),
        "reference_workload_digest":
            identity.get("reference_workload_digest"),
    }
    return workload, identity


def _native_role_sources(root: str, roles=None) -> tuple[dict, dict]:
    """Derive all three bindings from an installed reference tree."""
    roles = reference_controls.ROLES if roles is None else roles
    if os.path.islink(root) or not os.path.isdir(root):
        _refuse(f"reference-controls tree is not a non-symlink directory: "
                f"{root}")
    if set(os.listdir(root)) != set(roles):
        _refuse(f"reference-controls tree must contain exactly "
                f"{', '.join(roles)}")
    workloads, identities = {}, {}
    for role in roles:
        workloads[role], identities[role] = _native_role_source(
            role, os.path.join(root, role))
    return workloads, identities


def _declared_subset_argument(attestation: dict,
                              release_path: str) -> Optional[dict]:
    """Rebuild the declaration argument the scope bridge re-proves.

    The artifact discloses what a declared reference OMITS -- the short list,
    and the fact a reader needs -- while the bridge is handed what it COVERS,
    because a declaration is a statement about the items a reference does
    cover.  Over one release document the two are exact complements, and the
    release is already an input here.

    Handing the recorded declaration back is not circular.  The bridge
    re-proves the reconstructed set against the release and the gold baseline
    on disk, so an artifact that declares away items the control run does have
    rows for fails there, and one whose declaration does not match the pair
    set its observations covered fails rederivation.
    """
    declaration = attestation.get("declared_subset")
    if declaration is None:
        return None
    if not isinstance(declaration, dict) \
            or not isinstance(declaration.get("omitted_items"), list) \
            or not isinstance(declaration.get("reason"), str):
        _refuse("installed attestation carries a malformed declared subset")
    try:
        release_ids = mutation_attestation.load_release_ids(release_path)
    except (mutation_attestation.MutationAssetRefused, OSError,
            ValueError) as exc:
        raise ReferenceControlsRefused(str(exc)) from exc
    return {
        "items": sorted(release_ids - set(declaration["omitted_items"])),
        "reason": declaration["reason"],
    }


def _reference_scope_from_bindings(
        *, project: str, validation_path: str, manifest_path: str,
        map_path: str, release_path: str, gold_baseline_path: str,
        workloads: dict, identities: dict,
        declared_subset: Optional[dict] = None,
        engine_source_path: Optional[str] = None,
        validation_input_paths: Optional[dict[str, str]] = None) \
        -> tuple[reference_controls.ReferenceScope, dict]:
    """Seal the scope those bindings name and bind it to reviewed assets.

    The scope bridge rederives the population, map, release and full-gold
    baseline, and it holds each role to its workload binding.  It does NOT
    look at `mutation_validation_sha256`: the three identities may agree with
    each other on a validation report nothing ever validated.  The campaign
    asset join closes that -- the manifest, map and release bytes handed here
    must be the ones a native saved report pinned, and every role identity
    must claim that exact report.
    """
    manifest = _read_json(manifest_path, "scored mutation manifest")
    try:
        population_id = versions.population_id_for(
            project, manifest.get("digest"), engine=manifest.get("engine"),
            engine_version=manifest.get("engine_version"))
        scope = reference_controls.seal_reference_scope(
            population_id, manifest_path=manifest_path, map_path=map_path,
            release_path=release_path,
            gold_baseline_path=gold_baseline_path, workloads=workloads,
            declared_subset=declared_subset)
        # `validate_campaign_asset_inputs` revalidates the saved report from
        # its own named bytes before it returns these facts, so the report is
        # not separately reopened here.
        #
        # `require_release_ready=True` because this is the NATIVE from-disk
        # entry for reference scoring, and every other native caller demands
        # it -- cli.py's two mutation verbs, mutation_bounds, test_quality,
        # live_test_quality, docx_v2_workload and algorand_bundle.  The only
        # other `False` in the tree is `bundle.py`'s legacy portable path,
        # where a completed materialisation audit cannot be demanded of
        # evidence collected before the audit existed.  A reference collection
        # is not legacy: it is being made now, and an incomplete audit means
        # the population it names was never proved to materialise.
        campaign = mutation_attestation.validate_campaign_asset_inputs(
            validation_path, manifest_path=manifest_path, map_path=map_path,
            release_path=release_path, require_release_ready=True,
            input_paths=validation_input_paths)
        for identity in identities.values():
            mutation_run.validate_campaign_asset_claims(
                identity, campaign, validation_path=validation_path,
                manifest_path=manifest_path, map_path=map_path,
                release_path=release_path)
        if engine_source_path is not None:
            # `applier_sha256` is the one execution field neither the scope
            # bridge nor the asset join reaches: the population fixes WHICH
            # mutants exist, not which producer wrote them.  When the engine
            # source is installed beside the reference, the three roles must
            # name its bytes.
            applier = mutation_run.sha256_file(engine_source_path)
            changed = sorted(role for role, identity in identities.items()
                             if identity.get("applier_sha256") != applier)
            if changed:
                _refuse(f"reference role(s) {changed} name a mutation "
                        f"applier other than the installed engine source "
                        f"{engine_source_path}")
    except (mutation_attestation.MutationAssetRefused,
            mutation_run.MutationAborted, versions.ManifestError,
            OSError) as exc:
        # Not `ValueError`: `ReferenceControlsRefused` is one, so both the
        # scope bridge's refusals and `_refuse` above leave here unchanged
        # rather than being rewrapped in themselves.
        raise ReferenceControlsRefused(str(exc)) from exc
    return scope, campaign


def load_native_reference_controls(
        project: str, root: str, *, validation_path: str,
        manifest_path: str, map_path: str, release_path: str,
        gold_baseline_path: str, attestation_path: str,
        engine_source_path: Optional[str] = None,
        validation_input_paths: Optional[dict[str, str]] = None) -> dict:
    """Load an installed reference collection as sealed controls.

    `root` is the directory holding the three role subdirectories; the
    remaining paths are the installed population, its reviewed native
    mutation-validation report, and the minted attestation.  Returns the
    sealed `ReferenceControls`, the `ReferenceScope` they were validated
    under -- which nothing else can mint, because only this module derives
    the workload bindings it needs -- and the identities of what was read.

    `validation_input_paths` names the native report's complete relocated
    input set. The existing native validator checks those locations against
    the unchanged report; omission retains its recorded-path resolution.
    """
    # Digest-first: the attestation is small and is read before the three
    # trees are walked, so a document that is not the one its minting run
    # signed refuses before any of that work.
    attestation = reference_controls.load(attestation_path)
    workloads, identities = _native_role_sources(root)
    scope, campaign = _reference_scope_from_bindings(
        project=project, validation_path=validation_path,
        manifest_path=manifest_path, map_path=map_path,
        release_path=release_path, gold_baseline_path=gold_baseline_path,
        workloads=workloads, identities=identities,
        declared_subset=_declared_subset_argument(attestation, release_path),
        engine_source_path=engine_source_path,
        validation_input_paths=validation_input_paths)
    controls = reference_controls.load_preserved_reference_controls(
        root, attestation, scope=scope)
    return {
        "controls": controls,
        "scope": scope,
        "roles": {
            "mutation_validation": {
                "path": validation_path,
                "sha256": campaign["validation_sha256"],
                "validation_class": campaign["validation_class"],
            },
            "scored_manifest": {
                "path": manifest_path,
                "sha256": scope.population["manifest_sha256"],
                "digest": scope.population["manifest_digest"],
            },
            "mutation_map": {
                "path": map_path,
                "sha256": scope.population["map_sha256"],
                "pairs_sha256": scope.authority["pairs_sha256"],
                "n_pairs": scope.authority["n_pairs"],
            },
            "gold_baseline": {
                "path": gold_baseline_path,
                "sha256": scope.authority["gold_baseline_sha256"],
                "generated_tests_sha256":
                    scope.authority["gold_generated_tests_sha256"],
            },
            # The identity is the one read off disk before anything was
            # sealed.  Reporting it is honest only because the load
            # succeeded: the preserved reader proved every shard of the role
            # carries this same campaign core.
            "gold_results": {
                role: {
                    "path": os.path.join(root, role),
                    "identity": identities[role],
                    "facts": controls["observations"][role],
                } for role in reference_controls.ROLES
            },
            "gold_results_attestation": {
                "path": attestation_path,
                "schema": controls["schema"],
                "digest": controls["digest"],
            },
        },
    }


def selftest() -> int:
    """Network-free from-disk load probes over a synthetic reference tree."""
    import shutil
    import tempfile
    from unittest.mock import patch

    from ..data import mutation
    from . import test_quality
    from . import worker

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

    scope = None
    worker_resources = []
    workspace_digest = "no_workspace"
    database_digest = "no_database"
    applier_sha256 = "9" * 64
    validation_sha256 = "1" * 64

    def fixture_identity(role, observation_pairs):
        population = scope.population
        workload = scope.workloads[role]
        generated = workload["generated_tests_sha256"]
        base = mutation_run.build_campaign_identity(
            asset_index_sha256=population["asset_index_sha256"],
            asset_project=population["asset_project"],
            mutation_validation_sha256=validation_sha256,
            mutation_validation_class="native",
            manifest_sha256=population["manifest_sha256"],
            manifest_digest=population["manifest_digest"],
            map_sha256=population["map_sha256"],
            release_sha256=population["release_sha256"],
            candidate_run_sha256=workload["candidate_run_sha256"],
            candidate_generated_tests_sha256=generated,
            solution_generated_tests_sha256=generated,
            substrate_baseline_sha256="8" * 64,
            applier_sha256=applier_sha256,
            worker_resources_sha256=mutation_run.content_digest(
                worker_resources),
            harness_version=6,
            container_image_digest="sha256:" + "a" * 64,
            workspace_seed_digest=workspace_digest,
            database_dump_digest=database_digest,
            expected_pairs=observation_pairs,
            engine=population["engine"],
            engine_version=population["engine_version"],
            parser=population["parser"],
            side=reference_controls.ROLE_SIDE[role],
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
        reference = {key: base[key]
                     for key in mutation_run.CAMPAIGN_IDENTITY_FIELDS_V1}
        reference.update({
            "schema": mutation_run.MUTATION_IDENTITY_SCHEMA_V5,
            "generation_provenance_class":
                mutation_run.GENERATION_PROVENANCE_REFERENCE_CONTROL,
            "reference_control_role":
                reference_controls.IDENTITY_REFERENCE_ROLE[role],
            "reference_source_tag": workload["reference_source_tag"],
            "reference_workload_digest":
                workload["reference_workload_digest"],
        })
        return reference

    def write_observation(container, role, outcomes, observation_id):
        path = os.path.join(
            container, role,
            f"{reference_controls.ROLE_SIDE[role]}.w0.jsonl")
        identity = fixture_identity(role, set(outcomes))
        mutation_run.prepare_standalone_output_directory(
            path, identity, observation_id)
        with open(path, "w", encoding="utf-8") as handle:
            for (item_id, mutant_id), outcome in sorted(outcomes.items()):
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
        def under(*parts):
            return os.path.join(temporary, *parts)

        release_path = under("release.jsonl")
        with open(release_path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"item_id": "item-a"}) + "\n")
        raw_mutants = [{
            "file": f"src/CoreShop/Component/Fixture/example{number}.php",
            "operator": "Increment", "start_line": number, "start_col": 1,
            "original": str(number), "mutated": str(number + 1),
        } for number in (1, 2)]
        manifest = mutation.build_manifest(raw_mutants,
                                           parser_version="fixture-parser")
        manifest_path = under("manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, sort_keys=True)
        m1, m2 = [row["id"] for row in manifest["mutants"]]
        mapping = mutation_attestation.build_map_artifact(
            manifest, {m1: ["item-a"], m2: ["item-a"]}, [],
            coverage_sha256="c" * 64,
            release_sha256=mutation_run.sha256_file(release_path))
        map_path = under("map.json")
        with open(map_path, "w", encoding="utf-8") as handle:
            json.dump(mapping, handle, sort_keys=True)
        baseline_path = under("gold-baseline.jsonl")
        baseline_rows = [{
            "item_id": "item-a", "outcome": "passed",
            "produced_files": [{"file_path": "tests/item_a.py",
                                "code": "assert True"}],
        }]
        with open(baseline_path, "w", encoding="utf-8") as handle:
            for row in baseline_rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
        baseline_files = test_quality.passed_solutions(baseline_rows)

        validation_path = under("mutation_validation.json")
        with open(validation_path, "w", encoding="utf-8") as handle:
            json.dump({"schema": "r2t.mutation-validation/1",
                       "status": "valid"}, handle, sort_keys=True)
        validation_sha256 = mutation_run.sha256_file(validation_path)
        engine_source = under("mutate.php")
        with open(engine_source, "w", encoding="utf-8") as handle:
            handle.write("<?php // fixture applier\n")
        applier_sha256 = mutation_run.sha256_file(engine_source)

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
        fixture_population = {
            "schema": "r2t.population/1", "project": "fixture-project",
            "asset_project": "fixture-project", "generation": 1,
            "asset_index_sha256": "0" * 64,
            "engine": manifest["engine"],
            "engine_version": manifest["engine_version"],
            "parser": manifest["parser"],
        }
        campaign_facts = {
            "validation_class": "native",
            "validation_sha256": validation_sha256,
            "asset_index_sha256": fixture_population["asset_index_sha256"],
            "asset_project": fixture_population["asset_project"],
            "n_non_production_excluded": 0,
            "manifest": manifest, "map": mapping, "release_items": 1,
        }
        original_population = versions.population
        original_resolve = versions.population_id_for
        original_assets = mutation_attestation.validate_campaign_asset_inputs
        versions.population = lambda value: (
            fixture_population if value == "fixture-v1"
            else original_population(value))
        versions.population_id_for = lambda project, digest, **kw: (
            "fixture-v1" if project == "fixture-project"
            and digest == manifest["digest"]
            else original_resolve(project, digest, **kw))
        # The saved native validation report is a whole PR-2 derivation with
        # its own frozen asset index; standing one up would test that
        # validator, not this loader.  The fixture double returns exactly
        # what it returns, so `validate_campaign_asset_claims` -- the join
        # this module owns -- still runs against real bytes on disk.
        asset_calls = []

        def fixture_assets(path, **kwargs):
            asset_calls.append((path, kwargs))
            return campaign_facts

        mutation_attestation.validate_campaign_asset_inputs = fixture_assets
        try:
            scope = reference_controls.seal_reference_scope(
                "fixture-v1", manifest_path=manifest_path, map_path=map_path,
                release_path=release_path, gold_baseline_path=baseline_path,
                workloads=workloads)
            pairs = scope.expected_pairs

            # A producer host: live worker specs, seed and runtime
            # attestations, all under one directory that is renamed away
            # before the tree is loaded from its installed location.
            producer = under("producer")
            seed_dir = os.path.join(producer, "seed")
            os.makedirs(seed_dir)
            workspace_tar = os.path.join(seed_dir, "workspace.tar")
            database_sql = os.path.join(seed_dir, "database.sql")
            with open(workspace_tar, "wb") as handle:
                handle.write(b"reference loader workspace seed")
            with open(database_sql, "wb") as handle:
                handle.write(b"reference loader database seed")
            workspace_digest = mutation_run.sha256_file(workspace_tar)
            database_digest = mutation_run.sha256_file(database_sql)
            with open(os.path.join(seed_dir, "seed.json"), "w",
                      encoding="utf-8") as handle:
                json.dump({"format": 1, "seed_key": "reference-loader",
                           "needs_database": True,
                           "workspace": {"digest": workspace_digest},
                           "database": {"digest": database_digest}},
                          handle, sort_keys=True)
            seed_identity = worker.verified_seed_identity(seed_dir, True)
            worker_spec = worker.WorkerSpec(
                index=0, workspace=os.path.join(producer, "workspace-0"),
                container="reference-loader-worker-0",
                schema="reference_schema_0", credential="reference_user_0",
                env_file=os.path.join(producer, "worker0.env"))
            worker_spec_path = os.path.join(producer, "worker0.json")
            with open(worker_spec_path, "w", encoding="utf-8") as handle:
                json.dump(worker_spec.to_json(), handle, sort_keys=True)
            runtime_path = worker.runtime_attestation_path(worker_spec_path)
            with open(runtime_path, "w", encoding="utf-8") as handle:
                json.dump({
                    "schema": worker.WORKER_RUNTIME_SCHEMA_V2,
                    "worker": worker_spec.to_json(),
                    "worker_spec_sha256":
                        mutation_run.sha256_file(worker_spec_path),
                    **seed_identity,
                    "container_image_digest": "sha256:" + "a" * 64,
                    "docker_endpoint_selection": "legacy-default",
                    "harness_version": 6,
                }, handle, sort_keys=True)
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

            # G = {m1, m2}, S kills only m2, so H = {m1}; the stub kills
            # nothing and clears the 0.02 macro-recall gate.
            collected = under("collected")
            outcomes = {
                "full_gold": {("item-a", m1): "failed",
                              ("item-a", m2): "failed"},
                "stripped_gold": {("item-a", m1): "passed",
                                  ("item-a", m2): "failed"},
                "stub": {pair: "passed" for pair in pairs},
            }
            for role, observation_id in zip(reference_controls.ROLES,
                                            ("1" * 32, "2" * 32, "3" * 32)):
                write_observation(collected, role, outcomes[role],
                                  observation_id)
            native = {
                role: reference_controls.load_native_observation(
                    os.path.join(collected, role), role=role, scope=scope)
                for role in reference_controls.ROLES
            }
            document = reference_controls.build_reference_controls(
                scope, full_gold=native["full_gold"],
                stripped_gold=native["stripped_gold"], stub=native["stub"])
            attestation_path = under("reference-controls.json")
            reference_controls.write(document, attestation_path)

            check("an attestation with no declaration hands the scope "
                  "bridge nothing, and a declared one is reconstructed as "
                  "the covered complement of what it discloses",
                  _declared_subset_argument(document, release_path) is None
                  and _declared_subset_argument(
                      {**document, "declared_subset": {
                          "declared_items": 1, "release_items": 2,
                          "omitted_items": ["item-z"], "omitted_pairs": 2,
                          "reason": "fixture"}},
                      release_path) == {"items": ["item-a"],
                                        "reason": "fixture"})
            refuses("a malformed declaration on an installed attestation "
                    "refuses rather than being ignored",
                    lambda: _declared_subset_argument(
                        {**document, "declared_subset": {
                            "omitted_items": "item-a", "reason": "fixture"}},
                        release_path), "malformed declared subset")

            derived_workloads, derived_identities = _native_role_sources(
                collected)
            check("the three adapter workload bindings the scope bridge "
                  "requires are derived from the installed tree, not "
                  "supplied",
                  derived_workloads == workloads
                  and set(derived_identities) == set(
                      reference_controls.ROLES)
                  and all(derived_identities[role]["reference_control_role"]
                          == reference_controls.IDENTITY_REFERENCE_ROLE[role]
                          for role in reference_controls.ROLES))

            # The relocation that matters: the tree is installed at a path
            # it was not collected at, and every producer-host path its
            # sidecars record is gone.
            installed = under("installed", "gold-results")
            os.makedirs(os.path.dirname(installed))
            shutil.copytree(collected, installed)
            os.rename(producer, producer + "-unavailable")

            def load(root=installed, engine=engine_source, input_paths=None):
                return load_native_reference_controls(
                    "fixture-project", root,
                    validation_path=validation_path,
                    manifest_path=manifest_path, map_path=map_path,
                    release_path=release_path,
                    gold_baseline_path=baseline_path,
                    attestation_path=attestation_path,
                    engine_source_path=engine,
                    validation_input_paths=input_paths)

            loaded = load()
            controls = loaded["controls"]
            sets = reference_controls.reference_sets(controls)
            check("an omitted input mapping retains native recorded-path "
                  "resolution and the release-ready gate",
                  asset_calls == [(validation_path, {
                      "manifest_path": manifest_path, "map_path": map_path,
                      "release_path": release_path,
                      "require_release_ready": True, "input_paths": None})])
            check("a reference collected on one host loads from its "
                  "installed path with every producer-host path gone",
                  reference_controls.authenticated_reference_controls(
                      controls)
                  and dict(controls) == document
                  and sets.hard_subset["item-a"] == frozenset({m1})
                  and sets.full_gold_kills["item-a"] == frozenset({m1, m2}))
            check("the load reports the six roles it read, joined to the "
                  "scope nothing else can mint",
                  reference_controls.authenticated_reference_scope(
                      loaded["scope"])
                  and set(loaded["roles"]) == {
                      "mutation_validation", "scored_manifest",
                      "mutation_map", "gold_baseline", "gold_results",
                      "gold_results_attestation"}
                  and set(loaded["roles"]["gold_results"]) == set(
                      reference_controls.ROLES)
                  and loaded["roles"]["gold_results_attestation"]["digest"]
                  == document["digest"])

            # Input closure validation belongs to the real native validator,
            # tested with its producer in mutation_audit. This loader passes
            # the complete mapping through without rewriting any location or
            # changing the reference identity it has already authenticated.
            relocated_inputs = {
                "raw_manifest": manifest_path, "manifest": manifest_path,
                "map": map_path, "coverage_run": baseline_path,
                "release": release_path, "engine_source": engine_source,
                "asset_index": under("installed", "assets.json"),
                "boundary": under("installed", "boundary_fixture.yml"),
                "audit_attestation": under("installed", "audit.json"),
            }
            relocated = load(input_paths=relocated_inputs)
            check("relocated native input locations reach the validator "
                  "unchanged and preserve the authenticated reference",
                  len(asset_calls) == 2
                  and asset_calls[-1] == (validation_path, {
                      "manifest_path": manifest_path, "map_path": map_path,
                      "release_path": release_path,
                      "require_release_ready": True,
                      "input_paths": relocated_inputs})
                  and asset_calls[-1][1]["input_paths"] is relocated_inputs
                  and reference_controls.authenticated_reference_controls(
                      relocated["controls"])
                  and reference_controls.authenticated_reference_scope(
                      relocated["scope"])
                  and relocated["controls"] == controls
                  and relocated["roles"] == loaded["roles"])
            native_refusal = mutation_attestation.MutationAssetRefused(
                "REFUSED: relocated native report inputs are incomplete")
            with patch.object(
                    mutation_attestation, "validate_campaign_asset_inputs",
                    side_effect=native_refusal), patch.object(
                    reference_controls, "load_preserved_reference_controls",
                    side_effect=AssertionError("preserved reader was reached")):
                refuses("native input refusal propagates before preserved "
                        "reference controls can be returned",
                        lambda: load(input_paths=relocated_inputs),
                        str(native_refusal))

            changed = under("changed")
            shutil.copytree(installed, changed)
            with open(os.path.join(changed, "stub",
                                   "candidate.w0.jsonl"), "a",
                      encoding="utf-8") as handle:
                handle.write(" ")
            refuses("a changed installed shard refuses at the public load "
                    "boundary", lambda: load(changed), "REFUSED:")

            removed = under("removed")
            shutil.copytree(installed, removed)
            os.unlink(os.path.join(removed, "stripped_gold",
                                   "candidate.w0.jsonl"))
            refuses("a missing installed shard refuses against the role's "
                    "own closed inventory", lambda: load(removed),
                    "differs from its closed inventory")

            partial = under("partial")
            shutil.copytree(installed, partial)
            shutil.rmtree(os.path.join(partial, "stub"))
            refuses("a tree that is not exactly the three roles refuses "
                    "before any binding is derived", lambda: load(partial),
                    "must contain exactly")

            other_engine = under("other-mutate.php")
            with open(other_engine, "w", encoding="utf-8") as handle:
                handle.write("<?php // a different applier\n")
            refuses("the installed engine source must be the producer the "
                    "three roles name",
                    lambda: load(engine=other_engine), "mutation applier")
        finally:
            versions.population = original_population
            versions.population_id_for = original_resolve
            mutation_attestation.validate_campaign_asset_inputs = \
                original_assets

    print("\n" + ("ALL PASS (reference_loader)" if ok
                  else "FAILURES (reference_loader)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
