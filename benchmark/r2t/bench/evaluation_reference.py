"""Plan, seal and reopen the approved evaluation-only reference scope.

The catalog retains its registered identity. The collection declaration binds
the particular native index/map/release and the execution task bytes. Existing
reference-controls readers still prove observation completeness and arithmetic.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path

from ..core.paths import BENCHMARK_ROOT
from ..data import mutation_attestation as MA, versions
from . import mutation_run as MR, reference_controls as RC
from . import reference_loader as RL, test_quality as TQ

ReferenceControlsRefused = RC.ReferenceControlsRefused
SCHEMA = "r2t.mutation-evaluation-scope/1"
SCOPE_FIELDS = {"id", "population_id", "task_items_sha256",
                "map_release_sha256", "mutation_map_sha256"}


def _refuse(message):
    raise ReferenceControlsRefused("REFUSED: " + message)


def _json(path):
    return RL._read_json(os.fspath(path), "evaluation reference input")


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        _refuse(f"{label} must contain exactly {sorted(fields)}")


def _project_declaration(project):
    # These reviewed source declarations select a collection policy; they
    # do not claim a reserved archive has been published or can be fetched.
    import yaml
    with open(os.path.join(BENCHMARK_ROOT, "config", "evaluation_bundles.yml"),
              encoding="utf-8") as handle:
        declarations = yaml.safe_load(handle)
    selected = declarations.get("projects", {}).get(project)
    if not isinstance(selected, dict):
        _refuse(f"no reviewed evaluation scope for {project!r}")
    return {**selected, "scope_template": _json(os.path.join(
        BENCHMARK_ROOT, "config", "evaluation_scopes", project + ".json"))}


def _require_full_gold_coverage(rows, release_ids, baseline_rows):
    RC.admit_reference_items(release_item_ids=release_ids, gold_baseline_rows=rows)
    for row in rows:
        lines = row.get("coverage_lines")
        counts = row.get("coverage_files")
        # The PHP recorder serializes an empty associative count map as [].
        # Match preparation's interpretation without changing preserved rows.
        if isinstance(counts, list) and not counts:
            counts = {}
        if (row.get("adapter") != "gold"
                or row.get("coverage_requested") is not True
                or row.get("coverage_collected") is not True
                or row.get("coverage_mismatch") != []
                or not isinstance(lines, dict) or not isinstance(counts, dict)
                or any(not isinstance(values, list) for values in lines.values())):
            _refuse("CoreShop full422 coverage is absent, incomplete or mismatched "
                    f"for {row.get('item_id')!r}")
        if counts != {path: len(values) for path, values in lines.items()}:
            _refuse("CoreShop full422 coverage file counts disagree with line coverage "
                    f"for {row.get('item_id')!r}")
    if TQ.passed_solutions(rows) != TQ.passed_solutions(baseline_rows):
        _refuse("CoreShop map coverage names different gold control solution bytes")



def _require_sylius_task_binding(execution_release_path, task_binding_path,
                                map_release_sha256):
    from ..data.sylius_selection import load_selection
    if task_binding_path is None:
        _refuse("Sylius319 requires its preserved implementation-census receipt")
    receipt = load_selection(execution_release_path)
    if _json(task_binding_path) != receipt or receipt["inputs"]["original_items"]["sha256"] \
            != map_release_sha256:
        _refuse("Sylius319 task binding differs from its replayed census or map release")


def _require_sylius_coverage(coverage_path, selected, mapping,
                             map_ids, execution_ids, baseline_rows):
    if MR.sha256_file(coverage_path) != selected["coverage_run_sha256"]:
        _refuse("Sylius319 map coverage is not the reviewed fresh gold authority")
    if mapping["n_mapped"] != selected["n_full_mapped_mutants"] or \
            mapping["n_pairs"] != selected["n_mapped_pairs_before_exclusion"]:
        _refuse("Sylius319 full map differs from its reviewed population counts")
    coverage_rows = MA.load_jsonl(coverage_path)
    _require_full_gold_coverage(coverage_rows, map_ids, coverage_rows)
    selected_coverage = [row for row in coverage_rows if row["item_id"] in execution_ids]
    if TQ.passed_solutions(selected_coverage) != TQ.passed_solutions(baseline_rows):
        _refuse("Sylius319 fresh map coverage differs from the gold control solution bytes")


def admit_evaluation_scope(*, scope_path, validation_path, manifest_path,
                           map_path, execution_release_path, map_release_path,
                           gold_baseline_path, validation_input_paths=None,
                           task_binding_path=None):
    """Authenticate one precollection scope without inventing sibling roles."""
    return _admit_evaluation_scope(_json(scope_path),
        validation_path=validation_path, manifest_path=manifest_path, map_path=map_path,
        execution_release_path=execution_release_path, map_release_path=map_release_path,
        gold_baseline_path=gold_baseline_path, validation_input_paths=validation_input_paths,
        task_binding_path=task_binding_path)


def _admit_evaluation_scope(document, *, validation_path, manifest_path, map_path,
                            execution_release_path, map_release_path,
                            gold_baseline_path, validation_input_paths=None,
                            task_binding_path=None, assets=None):
    _exact(document, {"schema", "scope", "asset_index_sha256",
                      "mutation_validation_sha256", "declared_subset"},
           "collection scope")
    if document["schema"] != SCHEMA:
        _refuse("unknown evaluation collection-scope schema")
    scope = document["scope"]
    _exact(scope, SCOPE_FIELDS, "collection scope binding")
    try:
        entry = versions.population(scope["population_id"])
        project = entry["project"]
        selected = _project_declaration(project)
        if project == "coddy-agent" and entry.get("generation") != 2:
            _refuse("Coddy full282 requires its generation-two Go population")
        known = selected["scope_template"]
        _exact(known, {"schema", "scope", "asset_index_sha256",
                       "mutation_validation_sha256", "declared_subset"},
               "reviewed scope template")
        _exact(known["scope"], SCOPE_FIELDS, "reviewed scope binding")
        for actual, source in ((document, known), (scope, known["scope"])):
            for key, value in source.items():
                if key not in {"scope", "declared_subset"} and value is not None \
                        and actual[key] != value:
                    _refuse(f"collection scope {key} differs from its reviewed source pin")
        if document["declared_subset"] != known["declared_subset"]:
            _refuse("collection scope declaration differs from its reviewed item set or reason")
        if assets is None:
            assets = MA.validate_campaign_asset_inputs(
                validation_path, manifest_path=manifest_path, map_path=map_path,
                release_path=map_release_path, require_release_ready=True,
                input_paths=validation_input_paths)
        manifest = assets["manifest"]
        resolved = versions.population_id_for(
            project, manifest["digest"], engine=manifest["engine"],
            engine_version=manifest["engine_version"])
        map_ids = MA.load_release_ids(map_release_path)
        execution_ids = MA.load_release_ids(execution_release_path)
        baseline_rows = MA.load_jsonl(gold_baseline_path)
        admitted, declaration = RC.admit_reference_items(
            release_item_ids=map_ids, gold_baseline_rows=baseline_rows,
            declared_subset=document["declared_subset"])
    except (MA.MutationAssetRefused, versions.ManifestError, OSError,
            ValueError) as exc:
        raise ReferenceControlsRefused(str(exc)) from exc
    expected = {
        "id": selected["scope_id"], "population_id": selected["population_id"],
        "task_items_sha256": MR.sha256_file(execution_release_path),
        "map_release_sha256": MR.sha256_file(map_release_path),
        "mutation_map_sha256": MR.sha256_file(map_path),
    }
    if scope != expected or resolved != scope["population_id"] \
            or assets["asset_project"] != project \
            or manifest["parser"] != entry["parser"] \
            or document["asset_index_sha256"] != assets["asset_index_sha256"] \
            or document["mutation_validation_sha256"] \
            != assets["validation_sha256"]:
        _refuse("collection scope differs from its native assets or catalog")
    for key in ("task_items_sha256", "map_release_sha256"):
        if scope[key] != selected[key]:
            _refuse(f"collection scope {key} differs from its reviewed tasks")
    if (selected.get("n_scored_mutants") is not None
            and manifest["n"] != selected["n_scored_mutants"]) \
            or manifest.get("raw_manifest_digest", manifest["digest"]) \
            != entry["catalogue"]["manifest_digest"]:
        _refuse("evaluation scope changes the registered mutant catalog")
    if execution_ids != set(admitted) \
            or len(execution_ids) != selected["n_items"]:
        _refuse("execution tasks differ from the proved reference item set")
    if (document["declared_subset"] is not None) != (project in {"algorand-sdk", "sylius"}):
        _refuse("only the reviewed Algorand and Sylius scopes carry declared subsets")
    if project in {"coreshop", "coddy-agent"} and scope["task_items_sha256"] \
            != scope["map_release_sha256"]:
        _refuse("full-population execution and map release must be identical")
    if project in {"coreshop", "coddy-agent"}:
        # Native validation already authenticated every input. Read this one
        # label to prove the new map's full passing gold census, a condition
        # historical native reports never imposed on their coverage rows.
        if validation_input_paths is not None:
            coverage_path = validation_input_paths["coverage_run"]
        else:
            report = _json(validation_path)
            coverage_path = report["inputs"]["coverage_run"]["path"]
            if not os.path.isabs(coverage_path):
                coverage_path = os.path.join(os.path.dirname(validation_path),
                    report["path_base"]["relative_to_report"], coverage_path)
        _require_full_gold_coverage(MA.load_jsonl(coverage_path), map_ids, baseline_rows)
    if project == "sylius":
        _require_sylius_task_binding(execution_release_path, task_binding_path,
                                    scope["map_release_sha256"])
        if validation_input_paths is not None:
            coverage_path = validation_input_paths["coverage_run"]
        else:
            report = _json(validation_path)
            coverage_path = report["inputs"]["coverage_run"]["path"]
            if not os.path.isabs(coverage_path):
                coverage_path = os.path.join(os.path.dirname(validation_path),
                    report["path_base"]["relative_to_report"], coverage_path)
        _require_sylius_coverage(coverage_path, selected, assets["map"],
                                map_ids, execution_ids, baseline_rows)
    if project == "python-docx":
        if task_binding_path is None:
            _refuse("python-docx evaluation needs its annotation task binding")
        binding = _json(task_binding_path)
        if binding != {
                "schema": "r2t.evaluation-task-binding/1",
                "task_items_sha256": scope["task_items_sha256"],
                "map_release_sha256": scope["map_release_sha256"]}:
            _refuse("annotation task binding differs from the scope")
        original = MA.load_jsonl(map_release_path)
        annotated = MA.load_jsonl(execution_release_path)
        without_annotation = lambda rows: [
            {key: value for key, value in row.items()
             if key != "target_interfaces"} for row in rows]
        if without_annotation(original) != without_annotation(annotated):
            _refuse("annotated tasks change historical task contents or order")
    mutants, restricted, _covering = TQ.population(
        manifest, assets["map"]["by_mutant"], admitted)
    pairs = TQ.expected_pairs(restricted)
    if project == "sylius" and (len(mutants) != selected["n_mapped_mutants"]
            or len(pairs) != selected["n_declared_pairs_before_exclusion"]):
        _refuse("Sylius319 map projection differs from its reviewed complete pair set")
    if not pairs:
        _refuse("declared evaluation reference contains no mapped pairs")
    return {"collection_scope": document, "project": project,
            "assets": assets, "admitted_items": admitted,
            "declaration": declaration, "mutants": mutants,
            "by_mutant": restricted, "expected_pairs": pairs}


def instantiate_evaluation_scope(*, template_path, validation_path, manifest_path,
                                 map_path, execution_release_path, map_release_path,
                                 gold_baseline_path, out, validation_input_paths=None,
                                 task_binding_path=None):
    """Fill only unknown measured pins, then admit and create one scope file."""
    document = _json(template_path)
    _exact(document, {"schema", "scope", "asset_index_sha256",
                      "mutation_validation_sha256", "declared_subset"}, "collection scope template")
    _exact(document["scope"], SCOPE_FIELDS, "collection scope template binding")
    try:
        assets = MA.validate_campaign_asset_inputs(
            validation_path, manifest_path=manifest_path, map_path=map_path,
            release_path=map_release_path, require_release_ready=True,
            input_paths=validation_input_paths)
    except (MA.MutationAssetRefused, OSError, ValueError) as exc:
        raise ReferenceControlsRefused(str(exc)) from exc
    for holder, key, value in (
            (document, "asset_index_sha256", assets["asset_index_sha256"]),
            (document, "mutation_validation_sha256", assets["validation_sha256"]),
            (document["scope"], "mutation_map_sha256", MR.sha256_file(map_path))):
        if holder[key] is None:
            holder[key] = value
    _admit_evaluation_scope(document, validation_path=validation_path,
        manifest_path=manifest_path, map_path=map_path,
        execution_release_path=execution_release_path, map_release_path=map_release_path,
        gold_baseline_path=gold_baseline_path, validation_input_paths=validation_input_paths,
        task_binding_path=task_binding_path, assets=assets)
    try:
        with open(out, "x", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError as exc:
        raise ReferenceControlsRefused(f"REFUSED: cannot create collection scope {out}: {exc}") from exc
    return document


def validate_evaluation_control_policy(*, project: str, role: str,
                                       control_policy: str | None) -> None:
    """Admit the one approved prospective policy for this project and role."""
    from ..toolkit.assertion_selection import POLICY
    if role not in RC.ROLES:
        _refuse(f"evaluation control policy has unknown reference role {role!r}")
    required = (POLICY if project in {"coreshop", "algorand-sdk", "coddy-agent", "sylius"}
                and role == "stripped_gold" else None)
    if control_policy != required:
        _refuse(f"evaluation control policy for {project}/{role} must be "
                f"{required!r}, got {control_policy!r}")


def _control(*, admitted, candidate_path, recipe_path, role, source_tag,
             execution_release_path, gold_root, release_gold_root,
             closures_path, feature_root=None, go_control_plans_root=None):
    from .reference_workloads import validate_control_input
    if role not in RC.ROLES:
        _refuse(f"unknown reference role {role!r}")
    if not isinstance(source_tag, str) or not source_tag \
            or any(char.isspace() for char in source_tag):
        _refuse("reference source tag must be one nonempty space-free tag")
    try:
        control = validate_control_input(
            project=admitted["project"], role=role, run_path=candidate_path,
            recipe_path=recipe_path, execution_release_path=execution_release_path,
            gold_root=gold_root, release_gold_root=release_gold_root,
            closures_path=closures_path, feature_root=feature_root,
            **({"go_control_plans_root": go_control_plans_root}
               if admitted["project"] == "coddy-agent" else {}))
    except (ValueError, OSError) as exc:
        raise ReferenceControlsRefused(str(exc)) from exc
    recipe = control["recipe"]
    _exact(recipe, {"adapter", "adapter_version", "release_sha256",
                    "asset_index_sha256", "control_policy"},
           "evaluation reference recipe")
    validate_evaluation_control_policy(project=admitted["project"], role=role,
                                      control_policy=recipe["control_policy"])
    scope = admitted["collection_scope"]
    if recipe["release_sha256"] != scope["scope"]["task_items_sha256"] \
            or recipe["asset_index_sha256"] != scope["asset_index_sha256"]:
        _refuse("reference recipe differs from execution tasks or scope index")
    if set(control["files_by_item"]) != set(admitted["admitted_items"]):
        _refuse("reference control solutions do not cover every admitted item")
    workload = {
        "candidate_run_sha256": control["candidate_run_sha256"],
        "generated_tests_sha256": control["generated_tests_sha256"],
        # The native observation names the common collection freeze, not the
        # baseline's own producer tag. The exact baseline run bytes stay bound
        # through candidate_run_sha256; the rederived workload digest covers
        # the recipe and must not be recomputed using this freeze.
        "reference_source_tag": source_tag,
        "reference_workload_digest": control["reference_workload_digest"],
    }
    return control, workload


def plan_reference_leg(*, scope_path, validation_path, manifest_path, map_path,
                       execution_release_path, map_release_path,
                       gold_baseline_path, candidate_path, role, source_tag,
                       recipe_path, gold_root, release_gold_root, closures_path,
                       validation_input_paths=None, task_binding_path=None,
                       feature_root=None, go_control_plans_root=None):
    """Plan every pair of one authenticated role without executing a test."""
    admitted = admit_evaluation_scope(
        scope_path=scope_path, validation_path=validation_path,
        validation_input_paths=validation_input_paths,
        manifest_path=manifest_path, map_path=map_path,
        execution_release_path=execution_release_path,
        map_release_path=map_release_path, gold_baseline_path=gold_baseline_path,
        task_binding_path=task_binding_path)
    control, workload = _control(
        admitted=admitted, candidate_path=candidate_path, recipe_path=recipe_path,
        role=role, source_tag=source_tag,
        execution_release_path=execution_release_path, gold_root=gold_root,
        release_gold_root=release_gold_root, closures_path=closures_path,
        feature_root=feature_root, go_control_plans_root=go_control_plans_root)
    if role == "full_gold" and workload["candidate_run_sha256"] \
            != MR.sha256_file(gold_baseline_path):
        _refuse("full-gold control run differs from the declared gold baseline")
    return {**admitted, "files_by_item": control["files_by_item"],
            "workload": workload, "generation": {
                "generation_provenance_class": MR.GENERATION_PROVENANCE_REFERENCE_CONTROL,
                "reference_control_role": RC.IDENTITY_REFERENCE_ROLE[role],
                "reference_source_tag": source_tag,
                "reference_workload_digest": workload["reference_workload_digest"]}}


def _check_tests_tree(role_root, files_by_item):
    root = Path(role_root)
    if {p.name for p in root.iterdir()} != {"run.jsonl", "tests"}:
        _refuse("reference-input role must contain exactly run.jsonl and tests")
    wanted = {}
    for item_id, files in files_by_item.items():
        for entry in files:
            relative = Path(item_id) / entry["file_path"]
            if relative.is_absolute() or ".." in relative.parts:
                _refuse("reference solution path escapes its tests tree")
            if relative.as_posix() in wanted:
                _refuse("reference solution map repeats an item/file path")
            wanted[relative.as_posix()] = entry["code"].encode("utf-8")
    tests = root / "tests"
    if not tests.is_dir():
        _refuse("reference inputs have no tests directory")
    actual = {p.relative_to(tests).as_posix(): p.read_bytes()
              for p in tests.rglob("*") if p.is_file()}
    if actual != wanted:
        _refuse("reference tests tree differs from the exact control solution map")


def _load_evaluation(*, scope_path, validation_path, manifest_path, map_path,
                     execution_release_path, map_release_path,
                     gold_baseline_path, reference_inputs_root,
                     reference_recipes_root, reference_controls_root,
                     gold_root, release_gold_root, closures_path,
                     validation_input_paths=None, task_binding_path=None,
                     feature_root=None, go_control_plans_root=None, engine_source_path=None,
                     attestation_path=None, allow_excluded_pairs=False,
                     reference_basis="hard_subset", sensitivity=None,
                     gold_disagreements=frozenset(),
                     gold_disagreements_binding=None):
    if sensitivity is not None and attestation_path is not None:
        _refuse("a labelled sensitivity basis is derived from the preserved "
                "observations, never read from an attestation")
    admitted = admit_evaluation_scope(
        scope_path=scope_path, validation_path=validation_path,
        validation_input_paths=validation_input_paths, manifest_path=manifest_path,
        map_path=map_path, execution_release_path=execution_release_path,
        map_release_path=map_release_path, gold_baseline_path=gold_baseline_path,
        task_binding_path=task_binding_path)
    if reference_basis not in {"hard_subset", "full_gold"}:
        _refuse("unknown evaluation reference basis")
    document = RC.load(attestation_path) if attestation_path is not None else None
    roles = (RC.control_roles(document) if document is not None else
             (("full_gold",) if reference_basis == "full_gold" else RC.ROLES))
    if roles == ("full_gold",) and admitted["project"] != "coddy-agent":
        _refuse("full-gold-only evaluation reference is approved for Coddy")
    _recorded, identities = RL._native_role_sources(reference_controls_root, roles)
    if set(os.listdir(reference_inputs_root)) != set(roles) \
            or set(os.listdir(reference_recipes_root)) \
            != {role + ".json" for role in roles}:
        _refuse("evaluation inputs/recipes must cover exactly the selected reference roles")
    workloads = {}
    for role in roles:
        root = os.path.join(reference_inputs_root, role)
        control, workloads[role] = _control(
            admitted=admitted, candidate_path=os.path.join(root, "run.jsonl"),
            recipe_path=os.path.join(reference_recipes_root, role + ".json"),
            role=role, source_tag=identities[role].get("reference_source_tag"),
            execution_release_path=execution_release_path, gold_root=gold_root,
            release_gold_root=release_gold_root, closures_path=closures_path,
            feature_root=feature_root, go_control_plans_root=go_control_plans_root)
        _check_tests_tree(root, control["files_by_item"])
        MR.validate_campaign_asset_claims(
            identities[role], admitted["assets"], validation_path=validation_path,
            manifest_path=manifest_path, map_path=map_path,
            release_path=map_release_path)
        # VERSIONS.yml `accepted_reference_appliers` may name the installed
        # source as an accepted later applier of the recorded one.
        if engine_source_path is not None \
                and not versions.reference_applier_accepted(
                    admitted["project"], identities[role]["applier_sha256"],
                    MR.sha256_file(engine_source_path)):
            _refuse(f"{role} runtime applier differs from its installed source")
    collection = admitted["collection_scope"]
    scope = RC._seal_reference_scope(
        collection["scope"]["population_id"], manifest_path=manifest_path,
        map_path=map_path, release_path=map_release_path,
        gold_baseline_path=gold_baseline_path, workloads=workloads,
        declared_subset=collection["declared_subset"], evaluation_scope=collection)
    if sensitivity is not None:
        project = RC.SENSITIVITY_PROJECTS.get(sensitivity)
        if project != scope.population["project"]:
            _refuse(f"sensitivity {sensitivity!r} is defined for project "
                    f"{project!r}, not {scope.population['project']!r}")
        # The scoring host is not the producer host: the relocated reader
        # never opens the producer's recorded paths.
        observations = {role: RC.load_preserved_observation(
            os.path.join(reference_controls_root, role), role=role, scope=scope)
            for role in roles}
        controls = RC.sensitivity_reference_controls(
            scope, **observations, sensitivity=sensitivity,
            allow_excluded_pairs=allow_excluded_pairs,
            gold_disagreements=gold_disagreements,
            gold_disagreements_binding=gold_disagreements_binding)
    elif attestation_path is None:
        observations = {role: RC.load_native_observation(
            os.path.join(reference_controls_root, role), role=role, scope=scope)
            for role in roles}
        document = RC.build_reference_controls(
            scope, **observations, allow_excluded_pairs=allow_excluded_pairs)
        controls = RC.validate_reference_controls(document, scope=scope,
                                                  **observations)
    else:
        document = RC.load(attestation_path)
        # Only the recorded declaration reaches reopening; changing the
        # collection document cannot silently narrow a previously sealed set.
        if RL._declared_subset_argument(document, map_release_path) \
                != collection["declared_subset"]:
            _refuse("installed declaration differs from its sealed reference")
        controls = RC.load_preserved_reference_controls(
            reference_controls_root, document, scope=scope)
    return {"controls": controls, "scope": scope,
            "collection_scope": copy.deepcopy(collection),
            "assets": admitted["assets"], "identities": identities,
            "execution_release_path": execution_release_path,
            "map_release_path": map_release_path,
            "roles": {"gold_results": {role: {
                "path": os.path.join(reference_controls_root, role),
                "identity": identities[role],
                "facts": controls["observations"][role]} for role in roles}}}


def seal_evaluation_reference(*, out, **inputs):
    """Mint only from three strict native observations and all source inputs."""
    if "attestation_path" in inputs:
        _refuse("reference sealing needs native observations, not an installed attestation")
    if os.path.lexists(out):
        _refuse("reference attestation output already exists")
    result = _load_evaluation(**inputs)
    RC.write(dict(result["controls"]), out)
    return result


def load_evaluation_reference(*, attestation_path, **inputs):
    """Reopen all sources and preserved observations without reference execution."""
    if "allow_excluded_pairs" in inputs:
        _refuse("installed reference loading uses recorded exclusion consent")
    return _load_evaluation(attestation_path=attestation_path, **inputs)


def load_evaluation_sensitivity_reference(*, sensitivity, allow_excluded_pairs,
                                          gold_disagreements=frozenset(),
                                          gold_disagreements_binding=None,
                                          **inputs):
    """Reopen all sources and join the observations under a labelled basis.

    specifications/SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md: no
    attestation is read or written, the section 5.1 consent is the operator's
    explicit `allow_excluded_pairs`, and the failed stub gate is recorded as
    a diagnostic rather than enforced.
    """
    if "attestation_path" in inputs:
        _refuse("a labelled sensitivity basis takes no attestation")
    return _load_evaluation(sensitivity=sensitivity,
                            allow_excluded_pairs=allow_excluded_pairs,
                            gold_disagreements=gold_disagreements,
                            gold_disagreements_binding=gold_disagreements_binding,
                            **inputs)


def validate_evaluation_reference_inputs(*, project, role_paths, scope,
                                         validation_input_paths,
                                         feature_root=None):
    """Common installed reference join for every evaluation bundle builder."""
    provenance = role_paths["provenance"]
    result = load_evaluation_reference(
        scope_path=os.path.join(provenance, "collection-scope.json"),
        validation_path=os.path.join(role_paths["mutation_validation"], "report.json"),
        validation_input_paths=validation_input_paths,
        manifest_path=role_paths["scored_manifest"], map_path=role_paths["mutation_map"],
        execution_release_path=role_paths["release_items"],
        map_release_path=role_paths["map_release"],
        gold_baseline_path=role_paths["gold_baseline"],
        reference_inputs_root=role_paths["reference_inputs"],
        reference_recipes_root=os.path.join(provenance, "reference-recipes"),
        reference_controls_root=role_paths["gold_results"],
        gold_root=role_paths["gold"], release_gold_root=role_paths["release_gold"],
        closures_path=os.path.join(provenance, "reference-closures.json"),
        task_binding_path=role_paths.get("task_binding"), feature_root=feature_root,
        go_control_plans_root=role_paths.get("go_control_plans"),
        engine_source_path=role_paths["engine_source"],
        attestation_path=role_paths["gold_results_attestation"])
    expected = {**result["collection_scope"]["scope"],
                "reference_attestation_sha256": MR.sha256_file(
                    role_paths["gold_results_attestation"])}
    if scope != expected or project != result["scope"].population["project"]:
        _refuse("bundle scope differs from its authenticated reference")
    return result
