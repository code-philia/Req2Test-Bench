"""Real native reference fixtures shared with evaluation-bundle round trips."""
from __future__ import annotations

import ast
from contextlib import ExitStack, contextmanager
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
from unittest.mock import patch

from ..data import mutation as M, mutation_attestation as MA, versions
from ..toolkit import mutation_audit as AUD
from . import evaluation_reference as ER, reference_controls as RC
from . import mutation_run as MR, test_quality as TQ, worker as W


def _write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def _rows(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
                    encoding="utf-8")
    return str(path)


def fixture_from_algorand_roles(root, roles, producer):
    """Compose real native reference fixtures around supplied Java roles.

    Supplied release, gold, seed and provenance bytes are never rewritten.
    Qualification remains S3's validator's responsibility; this helper adds
    no substitute qualification fact and patches no source/native reader.
    Returned patch_context binds only the synthetic catalog/scope registry.
    """
    from . import reference_workloads as RW
    from ..toolkit.assertion_selection import POLICY
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    W.verified_seed_identity(roles["seed"], False)
    workspace = root / "source"
    workspace.mkdir()
    with tarfile.open(Path(roles["seed"]) / "workspace.tar") as archive:
        archive.extractall(workspace, filter="data")
    if not (workspace / "src/main/java").is_dir():
        raise ValueError("Algorand fixture seed needs real src/main/java production sources")
    source = root / "control-source"
    release_root = source / "release"
    release_root.mkdir(parents=True)
    release = release_root / "items.jsonl"
    shutil.copyfile(roles["release_items"], release)
    shutil.copytree(roles["release_gold"], release_root / "gold")
    closures_path = roles["closures"]
    controls = {"execution_release_path": str(release), "gold_root": roles["gold"],
        "release_gold_root": str(release_root / "gold"), "closures_path": closures_path,
        "feature_root": str(workspace), "run_paths": {}, "recipe_paths": {}}
    tasks = MA.load_jsonl(release)
    for role in RC.ROLES:
        control_policy = POLICY if role == "stripped_gold" else None
        adapter = RW._adapter(project="algorand-sdk", role=role,
            gold_root=roles["gold"], release_gold_root=controls["release_gold_root"],
            closures_path=closures_path, feature_root=str(workspace), control_policy=control_policy)
        recipe = RW.reference_recipe(role=role, adapter_version=1,
            release_sha256=MR.sha256_file(release), asset_index_sha256="0" * 64,
            control_policy=control_policy)
        rows = []
        for task in tasks:
            payload = adapter(task)
            metadata = payload.get("metadata") or {}
            if not payload.get("files") or any(metadata.get(key) for key in (
                    "strip_refusal", "adapter_error", "error")):
                raise ValueError(f"Algorand {role} fixture source cannot derive {task['item_id']}: {metadata}")
            rows.append({"item_id": task["item_id"], "adapter": adapter.name,
                "outcome": "passed", "produced_files": payload["files"], "metadata": metadata,
                "reference_derivation": {key: value for key, value in recipe.items()
                                         if key != "asset_index_sha256"},
                "reference_source_tag": producer["tag"]})
        controls["run_paths"][role] = _rows(source / (role + ".jsonl"), rows)
        controls["recipe_paths"][role] = _write(source / (role + ".recipe.json"), recipe)
    oci = ER._json(roles["oci_image"])
    strip = ER._json(Path(roles["gold"]) / "strip_manifest.json")
    result = fixture_evaluation_inputs(root, project="algorand-sdk", _algorand_source={
        "roles": roles, "producer": producer, "controls": controls,
        "image_id": oci["config_image_id"], "substrate_digest": MR.content_digest(strip["digests"])})
    result["producer"] = dict(producer)
    return result


def _coddy_authority_fixture(workspace, controls, image_id, source_rel):
    """Small coherent original inventory and stripped seed for native joins."""
    from ..go.interfaces_attribution import SCHEMA, partitions
    from ..toolkit import mutation_go
    closures = json.loads(Path(controls["closures_path"]).read_text())
    gold = Path(controls["gold_root"])
    # Include every bounded audit root and a source outside the readable view.
    for name, raw in {
            "cmd/fixture.go": b"package cmd\n", "pkg/resource.txt": b"original resource\n",
            "external/cli/retained.go": b"package cli\n",
            "go.mod": (gold / "go.mod").read_bytes(), "go.sum": b""}.items():
        target = workspace / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    for path in Path(controls["feature_root"]).rglob("*.feature"):
        target = workspace / path.relative_to(controls["feature_root"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
    # A removed answer outside the selected closure is still original authority.
    extra = gold / "cmd/coddy/bdd_sessions_export_test.go"
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_text("package coddy\n")
    moved = sorted(path.relative_to(gold).as_posix() for path in gold.rglob("*.go"))
    _write(gold / "strip_manifest.json", {"schema": "fixture-strip/1", "moved": moved})
    originals = {path.relative_to(workspace).as_posix(): path.read_bytes()
                 for path in workspace.rglob("*") if path.is_file()}
    originals.update({path: (gold / path).read_bytes() for path in moved})
    index = {"schema": "r2t.go_prod_index/1", "root": str(workspace.resolve()),
        "image_id": image_id, "files": {source_rel: {"classes": []}},
        "contexts": [{"go_suite": row["go_suite"], "answer_files": row["files"],
                      "files": [source_rel]} for row in closures]}
    groups, contexts = partitions(closures, index)
    inventory = {path: {"sha256": hashlib.sha256(raw).hexdigest()}
                 for path, raw in originals.items()}
    attribution = {"schema": SCHEMA, "root": index["root"], "source_root": index["root"],
        "image_id": image_id, "source_inventory": inventory, "contexts": contexts,
        "partitions": [{"compiled_package_name": group["context"]["package_name"],
            "source_files": {path: inventory[path]["sha256"] for path in group["files"]}}
            for group in groups]}
    builds = mutation_go._context_union([{"package_dir": row["go_suite"]["package_dir"],
        "go_build_tags": row["go_suite"]["go_build_tags"], "production_files": row["files"]}
        for row in contexts])
    return index, attribution, builds


def fixture_evaluation_inputs(root, *, project="python-docx", seed_workspace_files=None,
                              coverage_changes=None, _algorand_source=None,
                              harness_version=12, _assets_only=False, baseline_producers=None,
                              collection_tag=None, collection_tags=None,
                              worker_resources_factory=None):
    """Create tiny real native assets/controls; patch only registry authority.

    Callers enter fixture['patch_context']() while loading/building. No native
    report, control-source or observation reader is replaced. All mutations
    here are synthetic source-fixture edits, not benchmark data collection.
    """
    from .reference_workloads import fixture_control_sources
    from ..toolkit.assertion_selection import POLICY
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    controls = (_algorand_source["controls"] if _algorand_source is not None else
                fixture_control_sources(str(root / "control-source"), project=project,
                    stripped_control_policy=POLICY if project in {"coreshop", "algorand-sdk", "coddy-agent"} else None))
    source_tag = (_algorand_source["producer"]["tag"] if _algorand_source is not None
                  else "fixture-reviewed-reference")
    image_id = (_algorand_source["image_id"] if _algorand_source is not None
                else "sha256:" + "a" * 64)
    substrate_digest = (_algorand_source["substrate_digest"] if _algorand_source is not None
                        else "8" * 64)
    stem, population_id, scope_id, engine, source_rel, source_code, mutation_lines = {
        "python-docx": ("python_docx", "python-docx-v1", "python-docx-full239-single-observation-v1",
            "r2t-mutate-py", "src/app.py", "a + b\nc + d\n", (1, 2)),
        "coreshop": ("coreshop", "coreshop-v1", "coreshop-full422-single-observation-v1",
            "r2t-mutate", "src/CoreShop/Component/Fixture.php",
            "<?php\nclass Fixture {\n public function addA($a, $b) { return $a + $b; }\n"
            " public function addB($a, $b) { return $a + $b; }\n}\n", (3, 4)),
        "prestashop": ("prestashop", "prestashop-fixture", "prestashop-fixture-only",
            "r2t-mutate", "src/Core/Fixture.php",
            "<?php\nclass Fixture {\n public function addA($a, $b) { return $a + $b; }\n"
            " public function addB($a, $b) { return $a + $b; }\n}\n", (3, 4)),
        "algorand-sdk": ("algorand", "algorand-sdk-v2", "algorand-sdk-declared111-single-observation-v1",
            "r2t-mutate-java", "src/main/java/Fixture.java",
            "public class Fixture {\n public void addA(int a, int b) { int value = a + b; }\n"
            " public void addB(int a, int b) { int value = a + b; }\n}\n", (2, 3)),
        "coddy-agent": ("coddy_agent", "coddy-agent-v1", "coddy-agent-full282-single-observation-v1",
            "r2t-mutate-go", "internal/fixture.go",
            "package fixture\nfunc AddA(a, b int) int { return a + b }\n"
            "func AddB(a, b int) int { return a + b }\n", (2, 3)),
    }[project]
    needs_database = project in {"coreshop", "prestashop"}
    task_path = controls["execution_release_path"]
    items = MA.load_jsonl(task_path)
    item_id = items[0]["item_id"]
    if _algorand_source is None:
        map_release = _rows(root / "map-release.jsonl", [
            {key: value for key, value in item.items() if key != "target_interfaces"}
            for item in items])
        _rows(task_path, [dict(item, target_interfaces={
            "behaviour": ["fixture.value"], "setup": []}) for item in items])
        if project in {"coreshop", "prestashop", "coddy-agent"}:
            shutil.copyfile(task_path, map_release)
    else:
        map_release = str(root / "map-release.jsonl")
        shutil.copyfile(_algorand_source["roles"]["map_release"], map_release)
    omitted_id = "algorand-sdk/features/unit/omitted.feature:1"
    if project == "algorand-sdk" and _algorand_source is None:
        _rows(map_release, [*items, {"item_id": omitted_id}])
    # The task bytes and actual adapter derivation exist before map/index
    # construction. These synthetic rows record that index-free producer
    # stamp; the later five-field recipe adds the measured index separately.
    for role, recipe_path in controls["recipe_paths"].items():
        recipe = ER._json(recipe_path)
        recipe["release_sha256"] = MR.sha256_file(task_path)
        _write(recipe_path, recipe)
        run_rows = MA.load_jsonl(controls["run_paths"][role])
        for row in run_rows:
            row["reference_derivation"] = {
                key: value for key, value in recipe.items() if key != "asset_index_sha256"}
            row["reference_source_tag"] = (baseline_producers or {}).get(role, source_tag)
        _rows(controls["run_paths"][role], run_rows)
    records = [{"file": source_rel, "operator": "ArithmeticOperator",
                "start_line": line, "start_col": source_code.splitlines()[line - 1].index("+") + 1,
                "original": "+", "mutated": "-"} for line in mutation_lines] \
        if _algorand_source is None else []
    workspace = root / "source"
    production = workspace / source_rel
    if _algorand_source is None:
        production.parent.mkdir(parents=True)
        production.write_text(source_code, encoding="utf-8")
    if project == "coreshop":
        excluded = "src/CoreShop/Behat/Context/Excluded.php"
        path = workspace / excluded
        path.parent.mkdir(parents=True)
        path.write_text(source_code.replace("class Fixture", "class Excluded"), encoding="utf-8")
        records.append(dict(records[0], file=excluded))
    if project == "algorand-sdk":
        from ..toolkit import mutation_java
        recipe = mutation_java.make_analysis_recipe(str(workspace), sourcepath=("src/main/java",))
        envelope = mutation_java.enumerate_local(str(workspace), ["src/main/java"],
            analysis_recipe=recipe, expected_enumerator_sha256=MR.sha256_file(mutation_java.JAVA_SOURCE),
            timeout=180)
        raw_manifest = mutation_java.population_for(envelope)
        assert raw_manifest["n"] > 0
        if _algorand_source is None:
            assert raw_manifest["n"] == 2
        else:
            source_rel = raw_manifest["mutants"][0]["file"]
            mutation_lines = (raw_manifest["mutants"][0]["start_line"],)
    elif project == "coddy-agent":
        from ..toolkit import mutation_go
        go_index, go_attribution, go_builds = _coddy_authority_fixture(
            workspace, controls, image_id, source_rel)
        raw_manifest = mutation_go.build_population(
            [dict(record, end_line=record["start_line"], end_col=record["start_col"])
             for record in records], parser_version="go version go1.25.0 linux/amd64",
            enumerator_rev=mutation_go.ENUMERATOR_REV, n_invalid=0,
            go_build_contexts=go_builds)
    else:
        raw_manifest = M.build_manifest(records, parser_version="fixture-" + stem,
            operators=M.OPERATORS_V1, exclusions=(), engine=engine, engine_version="1.0")
    raw_manifest_path = _write(root / "raw-manifest.json", raw_manifest)
    boundary = root / ("boundary_" + stem + ".yml")
    shutil.copyfile(_algorand_source["roles"]["boundary"] if _algorand_source is not None
                    else Path(ER.BENCHMARK_ROOT) / "config" / boundary.name, boundary)
    if project == "coreshop":
        from ..core.boundary import load_boundary
        manifest = MA.derive_boundary_scored_manifest(raw_manifest,
            load_boundary(str(boundary)), str(boundary), MR.sha256_file(boundary))
    else:
        manifest = raw_manifest
    manifest_path = _write(root / "manifest.json", manifest)
    facts = MA.validate_manifest(manifest)
    raw_facts = MA.validate_manifest(raw_manifest)
    coverage_rows = copy.deepcopy(MA.load_jsonl(controls["run_paths"]["full_gold"]))
    for row in coverage_rows:
        row.update(coverage_lines={source_rel: [mutation_lines[0]]},
                   coverage_requested=True, coverage_collected=True,
                   coverage_mismatch=[], coverage_files={source_rel: 1})
    coverage_rows[0].update(coverage_changes or {})
    if project == "algorand-sdk" and _algorand_source is None:
        coverage_rows.append(dict(coverage_rows[0], item_id=omitted_id))
    elif _algorand_source is not None:
        # The historical map oracle includes the omitted release items. Its
        # synthetic rows read their actual closure files; they never enter
        # the current reference baseline or its declared execution set.
        from ..toolkit.strip import load_closures
        closures = load_closures(controls["closures_path"])
        executed = {row["item_id"] for row in coverage_rows}
        for mapped in MA.load_jsonl(map_release):
            if mapped["item_id"] in executed:
                continue
            closure = closures[mapped["item_id"]]
            files = [{"file_path": path, "code": Path(controls["gold_root"], path).read_text(encoding="utf-8")}
                     for path in closure["files"]]
            coverage_rows.append({"item_id": mapped["item_id"], "adapter": "gold",
                "outcome": "passed", "produced_files": files, "metadata": {"source": "gold"},
                "coverage_lines": {source_rel: [mutation_lines[0]]},
                "coverage_requested": True, "coverage_collected": True,
                "coverage_mismatch": [], "coverage_files": {source_rel: 1}})
    coverage = _rows(root / "coverage.jsonl", coverage_rows)
    by_mutant, uncovered = M.map_mutants_to_items(
        manifest, MA.coverage_from_rows(coverage_rows))
    mapping = MA.build_map_artifact(
        manifest, by_mutant, uncovered, coverage_sha256=MR.sha256_file(coverage),
        release_sha256=MR.sha256_file(map_release))
    map_path = _write(root / "map.json", mapping)
    map_facts = MA.validate_map(mapping, manifest,
                               release_ids=MA.load_release_ids(map_release))
    extension = {"python-docx": "py", "coreshop": "php", "prestashop": "php", "algorand-sdk": "java", "coddy-agent": "go"}[project]
    engine_path = root / ("Mutate.java" if project == "algorand-sdk" else "mutate." + extension)
    if project == "algorand-sdk":
        shutil.copyfile(mutation_java.JAVA_SOURCE, engine_path)
    elif project == "coddy-agent":
        shutil.copyfile(mutation_go.GO_SOURCE, engine_path)
    else:
        engine_path.write_text(("#" if project == "python-docx" else "//")
                              + " synthetic enumerator/applier fixture\n", encoding="utf-8")

    def apply(mutant, path):
        value = Path(path).read_text(encoding="utf-8")
        lines = value.splitlines(keepends=True)
        index = mutant["start_line"] - 1
        lines[index] = lines[index].replace("+", "-", 1)
        Path(path).write_text("".join(lines), encoding="utf-8")

    def parse(_mutant, path):
        text = Path(path).read_text(encoding="utf-8")
        if project == "python-docx":
            ast.parse(text)
        elif project == "coddy-agent":
            import subprocess
            # gofmt parses with the same pinned Go toolchain, without writing
            # the source or loading/executing any subject package.
            subprocess.run([str(Path(shutil.which("go")).with_name("gofmt")), "-e", path],
                           capture_output=True, check=True)
        else:
            # The audit models its external language-parser leaf on tiny
            # valid arithmetic sources; native report/control readers remain
            # real. Exercise the project's actual source scanner here.
            if project in {"coreshop", "prestashop"}:
                from ..toolkit.strip import strip_php_source as scan
            else:
                from ..toolkit.strip_java import strip_java_source as scan
            scan(text, ["addA"])

    if project == "algorand-sdk":
        (workspace / AUD.DISPOSABLE_MARKER).write_text(AUD.DISPOSABLE_MARKER_CONTENT,
                                                       encoding="utf-8")
        audit = AUD.audit_with_engine(raw_manifest, str(workspace),
                                      engine_source_path=str(engine_path), timeout=180)
    else:
        audit = AUD.audit_population(raw_manifest, str(workspace), apply, parse)
        audit["operator_gate"] = {
            "mode": "real_engine", "disposable_marker": AUD.DISPOSABLE_MARKER,
            "engine_source_sha256": MR.sha256_file(engine_path),
            "runtime_parser_identity": manifest["parser"],
            "runtime_parser_reported": MA.expected_runtime_parser(manifest)}
    audit["digest"] = MA.audit_digest(audit)
    audit_path = _write(root / "audit.json", audit)
    population = {"n": facts["n"], "manifest_digest": facts["digest"],
                  "canonical_sha256": facts["canonical_sha256"]}
    raw_population = {"n": raw_facts["n"], "manifest_digest": raw_facts["digest"],
                      "canonical_sha256": raw_facts["canonical_sha256"]}
    index_entry = {
        "engine": manifest["engine"], "engine_version": manifest["engine_version"],
        "parser": manifest["parser"],
        "raw_population": dict(raw_population, role="pre_boundary_catalogue",
                               preserved_file_sha256=MR.sha256_file(raw_manifest_path)),
        "scored_population": dict(population,
                                  role="boundary_scored" if project == "coreshop" else "raw_equals_scored",
                                  raw_manifest_digest=raw_facts["digest"],
                                  n_non_production_excluded=raw_facts["n"] - facts["n"]),
        "boundary": {"config": boundary.name, "classification": "production",
                     "sha256": MR.sha256_file(boundary)},
        "mutation_map": {"manifest_role": "scored_population", **{
            key: map_facts[key] for key in ("n_mutants", "n_mapped", "n_uncovered",
                                          "n_pairs", "digest", "canonical_sha256")},
            "coverage_sha256": MR.sha256_file(coverage),
            "release_sha256": MR.sha256_file(map_release)},
        "coverage_oracle": {"rows": len(coverage_rows), "sha256": MR.sha256_file(coverage)},
        "release": {"items": len(coverage_rows), "sha256": MR.sha256_file(map_release)},
        "engine_source": {"sha256": MR.sha256_file(engine_path)},
        "materialisation_audit": {
            "expected_mutants": raw_facts["n"], "status": "complete",
            "attestation_digest": audit["digest"], "release_blocker": None,
            "bounded_roots": audit["bounded_roots"],
            "n_source_files": audit["n_source_files"],
            "source_set_sha256": audit["source_set_sha256_before"],
            "runtime_parser_identity": manifest["parser"],
            "engine_source_sha256": MR.sha256_file(engine_path)}}
    index_path = _write(root / "index.json", {
        "schema": MA.ASSET_INDEX_SCHEMA, "version": 1,
        "projects": {project: index_entry}})
    index_sha = MR.sha256_file(index_path)
    # The real pure helper generated these recipes; only their authority pin
    # is bound now, once the native index has been constructed.
    for recipe_path in controls["recipe_paths"].values():
        recipe = ER._json(recipe_path)
        recipe["asset_index_sha256"] = index_sha
        _write(recipe_path, recipe)
    inputs = {"raw_manifest": raw_manifest_path, "manifest": manifest_path,
              "map": map_path, "coverage_run": coverage, "release": map_release,
              "asset_index": index_path, "boundary": str(boundary),
              "engine_source": str(engine_path), "audit_attestation": audit_path}
    report = AUD.build_native_validation_report(
        project=project, paths=inputs,
        references={key: os.path.relpath(path, root) for key, path in inputs.items()},
        relative_to_report="..")
    report_path = _write(root / "validation/report.json", report)
    scope = {"schema": ER.SCHEMA, "scope": {
        "id": scope_id,
        "population_id": population_id,
        "task_items_sha256": MR.sha256_file(task_path),
        "map_release_sha256": MR.sha256_file(map_release),
        "mutation_map_sha256": MR.sha256_file(map_path)},
        "asset_index_sha256": index_sha,
        "mutation_validation_sha256": MR.sha256_file(report_path),
        "declared_subset": ({"items": sorted(item["item_id"] for item in items),
                             "reason": ("the fixture preserves its declared execution subset"
                                        if _algorand_source is not None else
                                        "the preserved gold oracle omits this item")}
                            if project == "algorand-sdk" else None)}
    provenance = root / "provenance"
    if _algorand_source is not None:
        shutil.copytree(_algorand_source["roles"]["provenance"], provenance)
    scope_path = _write(provenance / "collection-scope.json", scope)
    task_binding = _write(root / "task-binding.json", {
        "schema": "r2t.evaluation-task-binding/1",
        **{key: scope["scope"][key]
           for key in ("task_items_sha256", "map_release_sha256")}})
    shutil.copyfile(controls["closures_path"], provenance / "reference-closures.json")
    reference_inputs = root / "reference-inputs"
    for role in RC.ROLES:
        recipe = ER._json(controls["recipe_paths"][role])
        _write(provenance / "reference-recipes" / (role + ".json"), recipe)
        role_root = reference_inputs / role
        role_root.mkdir(parents=True)
        shutil.copyfile(controls["run_paths"][role], role_root / "run.jsonl")
        for iid, files in TQ.passed_solutions(MA.load_jsonl(role_root / "run.jsonl")).items():
            for entry in files:
                target = role_root / "tests" / iid / entry["file_path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(entry["code"], encoding="utf-8")
    baseline = str(reference_inputs / "full_gold/run.jsonl")
    registry_entry = {"project": project, "asset_project": project,
                      "generation": 2 if project in {"algorand-sdk", "coddy-agent"} else 1,
                      "engine": manifest["engine"],
                      "engine_version": manifest["engine_version"],
                      "parser": manifest["parser"], "asset_index_sha256": "0" * 64,
                      "catalogue": index_entry["raw_population"]}
    selected = {"scope_id": scope_id, "population_id": population_id,
                "n_items": len(items), "n_scored_mutants": manifest["n"],
                "scope_template": copy.deepcopy(scope),
                **{key: scope["scope"][key]
                   for key in ("task_items_sha256", "map_release_sha256")}}

    @contextmanager
    def patch_context():
        original = versions.population
        resolve = versions.population_id_for
        with ExitStack() as stack:
            stack.enter_context(patch.object(versions, "population", side_effect=lambda pid:
                registry_entry if pid == population_id else original(pid)))
            stack.enter_context(patch.object(versions, "population_id_for", side_effect=lambda
                candidate_project, digest, **kw: population_id if candidate_project == project
                and digest == manifest["digest"] else resolve(candidate_project, digest, **kw)))
            stack.enter_context(patch.object(ER, "_project_declaration", return_value=selected))
            yield

    common = dict(scope_path=scope_path, validation_path=report_path,
                  validation_input_paths=inputs, manifest_path=manifest_path,
                  map_path=map_path, execution_release_path=task_path,
                  map_release_path=map_release, gold_baseline_path=baseline,
                  gold_root=controls["gold_root"],
                  release_gold_root=controls["release_gold_root"],
                  closures_path=str(provenance / "reference-closures.json"),
                  task_binding_path=task_binding if project == "python-docx" else None,
                  feature_root=controls["feature_root"],
                  **({"go_control_plans_root": controls["go_control_plans_root"]}
                     if project == "coddy-agent" else {}))
    # Preserve valid worker/seed preimages for the strict producer reader.
    producer = root / "producer"
    seed = root / "seed"
    if _algorand_source is None:
        seed.mkdir()
        seed_files = {source_rel: production.read_bytes(), **(seed_workspace_files or {})}
        if project == "coddy-agent":
            from ..go.mutation_copy import ENGINE_PATH
            seed_files.update({path.relative_to(workspace).as_posix(): path.read_bytes()
                               for path in workspace.rglob("*") if path.is_file()})
            seed_files[ENGINE_PATH] = mutation_go.GO_SOURCE.read_bytes()
        if controls["feature_root"] is not None:
            feature_root = Path(controls["feature_root"])
            seed_files.update({path.relative_to(feature_root).as_posix(): path.read_bytes()
                               for path in feature_root.rglob("*.feature")})
        with tarfile.open(seed / "workspace.tar", "w") as archive:
            for name, value in sorted(seed_files.items()):
                member = tarfile.TarInfo(name)
                member.size = len(value)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(value))
    else:
        shutil.copytree(_algorand_source["roles"]["seed"], seed)
    workspace_sha = MR.sha256_file(seed / "workspace.tar")
    database = {"declared": "no_database", "digest": "no_database"}
    if needs_database:
        (seed / "database.sql").write_text("CREATE TABLE fixture (id INT);\n", encoding="utf-8")
        database = {"digest": MR.sha256_file(seed / "database.sql")}
    if _algorand_source is None:
        _write(seed / "seed.json", {"format": 1, "seed_key": "fixture-evaluation",
            "needs_database": needs_database, "workspace": {"digest": workspace_sha},
            "workspace_seed_digest": workspace_sha, "database_dump_digest": database["digest"],
            "database": database})
    seed_identity = W.verified_seed_identity(str(seed), needs_database)
    worker = W.WorkerSpec(index=0, workspace=str(producer / "workspace"),
                          container="evaluation-reference-fixture",
                          schema="fixture_schema" if needs_database else "",
                          credential="fixture_user" if needs_database else "",
                          env_file=str(producer / "worker0.env"),
                          workdir="/var/www/html" if needs_database else "/work")
    worker_path = _write(producer / "worker0.json", worker.to_json())
    runtime_path = _write(W.runtime_attestation_path(worker_path), {
        "schema": W.WORKER_RUNTIME_SCHEMA_V2, "worker": worker.to_json(),
        "worker_spec_sha256": MR.sha256_file(worker_path), **seed_identity,
        "container_image_digest": image_id,
        "docker_endpoint_selection": "legacy-default", "harness_version": harness_version})
    resources = [{"index": 0, "worker_spec": worker_path,
                  "workspace": worker.workspace, "container": worker.container,
                  "schema": worker.schema, "credential": worker.credential, "env_file": worker.env_file,
                  "workdir": worker.workdir, "runtime_attestation": runtime_path,
                  "runtime_attestation_sha256": MR.sha256_file(runtime_path)}]
    if _assets_only:
        return {"controls": controls, "common_args": common,
                "validation_input_paths": inputs, "manifest": manifest,
                "map": mapping, "worker_resources": resources,
                "seed": str(seed), "engine_path": str(engine_path),
                "source_tag": source_tag, "image_id": image_id,
                "substrate_digest": substrate_digest}
    observations = root / "observations"
    plans = {}
    role_resources = (worker_resources_factory(producer, seed_identity, image_id, harness_version)
                      if worker_resources_factory is not None else
                      {role: resources for role in RC.ROLES})
    with patch_context():
        for number, role in enumerate(RC.ROLES, 1):
            resources = role_resources[role]
            plans[role] = plan = ER.plan_reference_leg(
                **common, candidate_path=str(reference_inputs / role / "run.jsonl"),
                role=role, source_tag=(collection_tags or {}).get(role, collection_tag or source_tag),
                recipe_path=str(provenance / "reference-recipes" / (role + ".json")))
            identity = MR.build_campaign_identity(
                **plan["generation"], asset_index_sha256=index_sha,
                asset_project=project, mutation_validation_sha256=MR.sha256_file(report_path),
                mutation_validation_class="native", manifest_sha256=MR.sha256_file(manifest_path),
                manifest_digest=manifest["digest"], map_sha256=MR.sha256_file(map_path),
                release_sha256=MR.sha256_file(map_release),
                candidate_run_sha256=plan["workload"]["candidate_run_sha256"],
                candidate_generated_tests_sha256=plan["workload"]["generated_tests_sha256"],
                solution_generated_tests_sha256=plan["workload"]["generated_tests_sha256"],
                substrate_baseline_sha256=substrate_digest,
                worker_resources_sha256=MR.content_digest(resources), harness_version=harness_version,
                container_image_digest=image_id,
                workspace_seed_digest=workspace_sha, database_dump_digest=database["digest"],
                applier_sha256=MR.sha256_file(engine_path), expected_pairs=plan["expected_pairs"],
                engine=manifest["engine"], engine_version=manifest["engine_version"],
                parser=manifest["parser"], side=RC.ROLE_SIDE[role], shard=0, of=1, timeout=600)
            row_path = observations / role / (RC.ROLE_SIDE[role] + ".w0.jsonl")
            MR.prepare_standalone_output_directory(str(row_path), identity, str(number) * 32)
            _rows(row_path, [{"item_id": iid, "mutant_id": mid,
                "outcome": "failed" if role == "full_gold" else "passed",
                "attempt": 1, "retried_infrastructure": False,
                **MR.row_identity_stamp(identity)} for iid, mid in plan["expected_pairs"]])
            for state in ("running", "complete"):
                MR.write_shard_provenance(str(row_path), identity, state,
                                         provenance={"worker_resources": resources})
        reference_args = dict(common, reference_inputs_root=str(reference_inputs),
            reference_recipes_root=str(provenance / "reference-recipes"),
            reference_controls_root=str(observations), engine_source_path=str(engine_path))
        attestation = str(root / "reference-controls.json")
        loaded = ER.seal_evaluation_reference(out=attestation, **reference_args)
    final_scope = {**scope["scope"], "reference_attestation_sha256": MR.sha256_file(attestation)}
    role_sources = {"release_items": task_path, "map_release": map_release,
        "release_gold": controls["release_gold_root"], "gold": controls["gold_root"],
        "seed": str(seed), "boundary": str(boundary), "raw_manifest": raw_manifest_path,
        "scored_manifest": manifest_path, "mutation_map": map_path,
        "mutation_asset_index": index_path, "mutation_validation": str(root / "validation"),
        "engine_source": str(engine_path), "audit_attestation": audit_path,
        "coverage_run": coverage, "gold_baseline": baseline,
        "reference_inputs": str(reference_inputs), "gold_results": str(observations),
        "gold_results_attestation": attestation, "provenance": str(provenance),
        "task_binding": task_binding}
    if project != "python-docx":
        role_sources.pop("task_binding")
    if project == "coddy-agent":
        role_sources.update(go_control_plans=controls["go_control_plans_root"],
                            closures=controls["closures_path"],
                            production_index=_write(root / "production-index.json", go_index),
                            go_interface_attribution=_write(root / "go-interface-attribution.json", go_attribution))
    if _algorand_source is not None:
        role_sources = {**_algorand_source["roles"], **role_sources}
    return {"role_sources": role_sources, "scope": final_scope,
            "patch_context": patch_context, "reference_args": reference_args,
            "common_args": common, "loaded": loaded, "plans": plans,
            "validation_input_paths": inputs, "manifest": manifest,
            "map": mapping, "producer_root": str(producer), "item_id": item_id,
            "worker_resources": resources, "role_worker_resources": role_resources}


def score_fixture_candidate(root, *, role_paths, reference_reader):
    """Real candidate planner/summary revalidation with only execution faked.

    Bundle tests supply a reader that reopens their installed, relocated
    reference. Any attempt to dispatch a reference job fails in execute().
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    loaded = reference_reader()
    authority = TQ._seal_single_observation_scoring_authority(loaded["controls"])
    baseline = MA.load_jsonl(role_paths["gold_baseline"])
    item_id = baseline[0]["item_id"]
    run_rows = [{"item_id": item_id, "outcome": "passed",
                 "produced_files": [{"file_path": "candidate.py", "code": "assert True\n"}]}]
    run = _rows(root / "candidate.jsonl", run_rows)
    manifest = ER._json(role_paths["scored_manifest"])
    mapping = ER._json(role_paths["mutation_map"])
    resources = [{"index": 0}]
    inputs = TQ.identity_inputs_for_test_quality(
        run_rows=run_rows, gold_baseline_rows=baseline,
        manifest=manifest, by_mutant=mapping["by_mutant"])
    # This digest is scoped to the candidate's passed items. The reusable
    # reference authority below names the full baseline's solution map.
    candidate_gold_digest = inputs["gold_generated_tests_sha256"]
    reference = loaded["controls"]["authority"]
    inputs.update({key: reference[key] for key in inputs if key in reference})
    inputs.update({
        "generation_provenance_class": MR.GENERATION_PROVENANCE_DEVELOPMENT,
        "generation_campaign_digest": None, "generation_attempt_id": None,
        "generation_agent_runtime_sha256": None, "generation_network_semantics": None,
        "candidate_run_sha256": MR.sha256_file(run),
        "candidate_generated_tests_sha256": MR.candidate_digest(TQ.passed_solutions(run_rows)),
        "gold_baseline_sha256": MR.sha256_file(role_paths["gold_baseline"]),
        "gold_generated_tests_sha256": candidate_gold_digest,
        "worker_resources_sha256": MR.content_digest(resources)})
    calls = []

    def execute(job):
        assert job["side"] == "candidate", "reference execution was dispatched"
        calls.append(job)
        rows = [{"item_id": iid, "mutant_id": mutant["id"],
                 "file": mutant["file"], "operator": mutant["operator"],
                 "outcome": "failed", "attempt": 1, "retried_infrastructure": False,
                 **MR.row_identity_stamp(job["identity"])}
                for mutant in job["mutants"]
                for iid in job["by_mutant"][mutant["id"]]]
        _rows(job["out"], rows)
        for state in ("running", "complete"):
            MR.write_shard_provenance(job["out"], job["identity"], state,
                                     provenance=job.get("provenance"))
        return {"out": job["out"], "rows": len(rows), "side": "candidate"}

    def reader(_summary, _expected):
        return TQ._seal_single_observation_scoring_authority(
            reference_reader()["controls"])

    def final(summary, path):
        TQ._validate_native_summary_before_completion(
            summary, path, run, reference_controls_reader=reader)

    summary = TQ.run_test_quality(
        run_rows=run_rows, gold_baseline_rows=baseline, manifest=manifest,
        by_mutant=mapping["by_mutant"], out_dir=str(root / "campaign"),
        execute=execute, n_workers=1, single_observation_authority=authority,
        candidate_pairs="gold-killed" if authority.sets.reference_basis == "full_gold" else "all",
        provenance={"run": run, "gold_baseline": role_paths["gold_baseline"],
                    "manifest": role_paths["scored_manifest"], "map": role_paths["mutation_map"],
                    "release": role_paths["release_items"],
                    "mutation_validation": str(Path(role_paths["mutation_validation"]) / "report.json"),
                    "seed": role_paths["seed"]},
        identity_inputs=inputs, require_complete=True, worker_resources=resources,
        execution_policy=MR.EXECUTION_POLICY_SCALAR_V1,
        execution_observation_id="9" * 32, final_summary_validator=final)
    sidecar = TQ.write_sidecar(summary, run)
    reopened = TQ.load_bound_test_quality(run, sidecar, reference_controls_reader=reader)
    assert calls and {job["side"] for job in calls} == {"candidate"}
    assert {entry["side"] for entry in reopened["slices"]} == {"candidate"}
    assert reopened["release_sha256"] == MR.sha256_file(role_paths["map_release"])
    if reopened["asset_project"] in {"coreshop", "coddy-agent"}:
        assert reopened["release_sha256"] == MR.sha256_file(role_paths["release_items"])
    else:
        assert reopened["release_sha256"] != MR.sha256_file(role_paths["release_items"])
    assert reopened["generation_provenance_class"] == MR.GENERATION_PROVENANCE_DEVELOPMENT
    return reopened


def _test_control_policy(fixture, project):
    from ..toolkit.assertion_selection import POLICY
    from .reference_workloads import validate_control_input

    for role in RC.ROLES:
        expected = POLICY if project in {"coreshop", "algorand-sdk", "coddy-agent"} and role == "stripped_gold" else None
        ER.validate_evaluation_control_policy(project=project, role=role,
                                              control_policy=expected)
        try:
            ER.validate_evaluation_control_policy(project=project, role=role,
                control_policy=None if expected is not None else POLICY)
        except RC.ReferenceControlsRefused as exc:
            assert "evaluation control policy" in str(exc)
        else:
            raise AssertionError("wrong project/role policy was admitted")
    if project == "python-docx":
        return

    # These tiny gold closures use ordinary Then assertions. Consequently
    # their default/null derivation is internally valid and used to pass the
    # real public planner. Only the approved evaluation-policy join refuses it.
    roles = fixture["role_sources"]
    recipe_path = Path(roles["provenance"]) / "reference-recipes/stripped_gold.json"
    run_path = Path(roles["reference_inputs"]) / "stripped_gold/run.jsonl"
    recipe_bytes, run_bytes = recipe_path.read_bytes(), run_path.read_bytes()
    recipe = ER._json(recipe_path)
    rows = MA.load_jsonl(run_path)
    assert recipe["control_policy"] == POLICY
    source_args = {key: fixture["common_args"][key] for key in (
        "execution_release_path", "gold_root", "release_gold_root", "closures_path", "feature_root")}
    try:
        recipe["control_policy"] = None
        for row in rows:
            row["reference_derivation"]["control_policy"] = None
        _write(recipe_path, recipe)
        _rows(run_path, rows)
        default = validate_control_input(project=project, role="stripped_gold",
            run_path=str(run_path), recipe_path=str(recipe_path), **source_args)
        assert default["recipe"]["control_policy"] is None
        with fixture["patch_context"]():
            try:
                ER.plan_reference_leg(**fixture["common_args"], role="stripped_gold",
                    candidate_path=str(run_path), recipe_path=str(recipe_path),
                    source_tag="fixture-reviewed-reference")
            except RC.ReferenceControlsRefused as exc:
                assert "evaluation control policy" in str(exc), str(exc)
            else:
                raise AssertionError("public evaluation planner admitted a null stripped policy")
        # The historical helper still accepts the original four-field recipe
        # and source rows without the prospective derivation/tag fields.
        recipe.pop("control_policy")
        for row in rows:
            row.pop("reference_derivation")
            row.pop("reference_source_tag")
        _write(recipe_path, recipe)
        _rows(run_path, rows)
        historical = validate_control_input(project=project, role="stripped_gold",
            run_path=str(run_path), recipe_path=str(recipe_path), **source_args)
        assert "control_policy" not in historical["recipe"]
        assert "reference_source_tag" not in historical
    finally:
        recipe_path.write_bytes(recipe_bytes)
        run_path.write_bytes(run_bytes)


def _test_scope_instantiation(root, fixture):
    root = Path(root)
    original = ER._json(fixture["common_args"]["scope_path"])
    template = copy.deepcopy(original)
    template["asset_index_sha256"] = None
    template["mutation_validation_sha256"] = None
    template["scope"]["mutation_map_sha256"] = None
    template_path = _write(root / "template.json", template)
    template_bytes = Path(template_path).read_bytes()
    args = {key: fixture["common_args"][key] for key in (
        "validation_path", "validation_input_paths", "manifest_path", "map_path",
        "execution_release_path", "map_release_path", "gold_baseline_path", "task_binding_path")}
    out = root / "scope.json"

    def refuses(call):
        try:
            call()
        except RC.ReferenceControlsRefused:
            return
        raise AssertionError("invalid scope template was admitted")

    with fixture["patch_context"]():
        refuses(lambda: ER.admit_evaluation_scope(scope_path=template_path, **args))
        document = ER.instantiate_evaluation_scope(template_path=template_path, out=out, **args)
        assert document == original == ER._json(out)
        assert document["declared_subset"] == template["declared_subset"]
        assert Path(template_path).read_bytes() == template_bytes
        preserved = out.read_bytes()
        refuses(lambda: ER.instantiate_evaluation_scope(template_path=template_path, out=out, **args))
        assert out.read_bytes() == preserved
        for key in ("asset_index_sha256", "mutation_validation_sha256"):
            changed = copy.deepcopy(template)
            changed[key] = "0" * 64
            _write(template_path, changed)
            failed_out = root / (key + ".json")
            refuses(lambda: ER.instantiate_evaluation_scope(template_path=template_path,
                                                             out=failed_out, **args))
            assert not failed_out.exists()
        for key, value in (("mutation_map_sha256", "0" * 64),
                           ("task_items_sha256", None), ("map_release_sha256", "0" * 64)):
            changed = copy.deepcopy(template)
            changed["scope"][key] = value
            _write(template_path, changed)
            failed_out = root / (key + ".json")
            refuses(lambda: ER.instantiate_evaluation_scope(template_path=template_path,
                                                             out=failed_out, **args))
            assert not failed_out.exists()
        if template["declared_subset"] is not None:
            changed = copy.deepcopy(template)
            changed["declared_subset"]["reason"] += " changed"
            _write(template_path, changed)
            failed_out = root / "declaration.json"
            refuses(lambda: ER.instantiate_evaluation_scope(template_path=template_path,
                                                             out=failed_out, **args))
            assert not failed_out.exists()
        # A caller cannot clear an externally known map pin and then fill
        # the null from a different, internally valid native map.
        selected = copy.deepcopy(ER._project_declaration("fixture"))
        selected["scope_template"]["scope"]["mutation_map_sha256"] = "0" * 64
        _write(template_path, template)
        failed_out = root / "cleared-known-pin.json"
        with patch.object(ER, "_project_declaration", return_value=selected):
            refuses(lambda: ER.instantiate_evaluation_scope(template_path=template_path,
                                                             out=failed_out, **args))
        assert not failed_out.exists()


def _declared_scope_case(root, *, role_paths, validation_input_paths):
    """A tiny real native 1-of-2 map models Algorand's 111-of-117 proof."""
    root = Path(root)
    manifest = ER._json(role_paths["scored_manifest"])
    original = MA.load_jsonl(role_paths["map_release"])
    declared_id = original[0]["item_id"]
    omitted_id = "algorand-sdk/features/omitted.feature:1"
    release = _rows(root / "release.jsonl", original + [{"item_id": omitted_id}])
    rows = MA.load_jsonl(role_paths["coverage_run"])
    coverage = _rows(root / "coverage.jsonl", rows + [dict(rows[0], item_id=omitted_id)])
    by_mutant, uncovered = M.map_mutants_to_items(
        manifest, MA.coverage_from_rows(MA.load_jsonl(coverage)))
    mapping = MA.build_map_artifact(manifest, by_mutant, uncovered,
        coverage_sha256=MR.sha256_file(coverage), release_sha256=MR.sha256_file(release))
    map_path = _write(root / "map.json", mapping)
    map_facts = MA.validate_map(mapping, manifest, release_ids={declared_id, omitted_id})
    entry = ER._json(role_paths["mutation_asset_index"])["projects"]["python-docx"]
    entry["coverage_oracle"] = {"rows": 2, "sha256": MR.sha256_file(coverage)}
    entry["release"] = {"items": 2, "sha256": MR.sha256_file(release)}
    entry["mutation_map"].update({key: map_facts[key] for key in (
        "n_mutants", "n_mapped", "n_uncovered", "n_pairs", "digest", "canonical_sha256")})
    entry["mutation_map"].update(coverage_sha256=MR.sha256_file(coverage),
                                  release_sha256=MR.sha256_file(release))
    index = _write(root / "index.json", {"schema": MA.ASSET_INDEX_SCHEMA,
        "version": 1, "projects": {"algorand-sdk": entry}})
    inputs = dict(validation_input_paths, map=map_path, release=release,
                  coverage_run=coverage, asset_index=index)
    # All original inputs are copied under one root solely to construct the
    # producer's real native report with ordinary root-relative locators.
    for label, source in list(inputs.items()):
        if label in {"map", "release", "coverage_run", "asset_index"}:
            continue
        destination = root / label / Path(source).name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        inputs[label] = str(destination)
    report = AUD.build_native_validation_report(project="algorand-sdk", paths=inputs,
        references={key: os.path.relpath(value, root) for key, value in inputs.items()},
        relative_to_report=".")
    report_path = _write(root / "report.json", report)
    declaration = {"items": [declared_id], "reason": "the preserved gold oracle omits this item"}
    scope = {"schema": ER.SCHEMA, "scope": {
        "id": "algorand-sdk-declared111-single-observation-v1",
        "population_id": "algorand-sdk-v2",
        "task_items_sha256": MR.sha256_file(role_paths["release_items"]),
        "map_release_sha256": MR.sha256_file(release),
        "mutation_map_sha256": MR.sha256_file(map_path)},
        "asset_index_sha256": MR.sha256_file(index),
        "mutation_validation_sha256": MR.sha256_file(report_path),
        "declared_subset": declaration}
    scope_path = _write(root / "scope.json", scope)
    registry = {"project": "algorand-sdk", "asset_project": "algorand-sdk", "generation": 2,
        "engine": manifest["engine"], "engine_version": manifest["engine_version"],
        "parser": manifest["parser"], "catalogue": entry["raw_population"]}
    selected = {"scope_id": scope["scope"]["id"], "population_id": "algorand-sdk-v2",
                "n_items": 1, "n_scored_mutants": 2,
                "scope_template": copy.deepcopy(scope),
                **{key: scope["scope"][key] for key in ("task_items_sha256", "map_release_sha256")}}
    args = dict(scope_path=scope_path, validation_path=report_path,
        validation_input_paths=inputs, manifest_path=inputs["manifest"], map_path=map_path,
        execution_release_path=role_paths["release_items"], map_release_path=release,
        gold_baseline_path=role_paths["gold_baseline"])
    with patch.object(versions, "population", return_value=registry), \
            patch.object(versions, "population_id_for", return_value="algorand-sdk-v2"), \
            patch.object(ER, "_project_declaration", return_value=selected):
        admitted = ER.admit_evaluation_scope(**args)
        assert admitted["collection_scope"]["declared_subset"] == declaration
        assert len(admitted["expected_pairs"]) == 1
        assert map_facts["n_pairs"] == 2
        assert admitted["declaration"]["omitted_items"] == [omitted_id]
        for changed in (None, {"items": [declared_id, omitted_id], "reason": "claim everything"}):
            _write(scope_path, dict(scope, declared_subset=changed))
            try:
                ER.admit_evaluation_scope(**args)
            except RC.ReferenceControlsRefused:
                pass
            else:
                raise AssertionError("missing or enlarged declaration was admitted")


def _test_supplied_algorand_composition(root, fixture):
    """Native-reference component coverage, not a V8 qualification claim."""
    root = Path(root)
    supplied = dict(fixture["role_sources"])
    rows = MA.load_jsonl(supplied["map_release"])
    closures = json.loads(Path(fixture["common_args"]["closures_path"]).read_text())
    known = {row["item_id"] for row in closures}
    closures.extend(dict(closures[0], item_id=row["item_id"])
                    for row in rows if row["item_id"] not in known)
    supplied["closures"] = _write(root / "supplied-closures.json", closures)
    copied_gold = root / "supplied-gold"
    shutil.copytree(supplied["gold"], copied_gold)
    supplied["gold"] = str(copied_gold)
    copied_provenance = root / "supplied-provenance"
    shutil.copytree(supplied["provenance"], copied_provenance)
    supplied["provenance"] = str(copied_provenance)
    shutil.copyfile(supplied["closures"], copied_provenance / "reference-closures.json")
    # These are supplied runtime facts for this component fixture. The
    # missing source/release qualification evidence is intentionally not
    # invented; the full E -> S3 composition remains a separate acceptance.
    supplied["oci_image"] = _write(root / "supplied-oci.json", {
        "config_image_id": "sha256:" + "b" * 64})
    import hashlib
    with tarfile.open(Path(supplied["seed"]) / "workspace.tar") as archive:
        java_source = archive.extractfile("src/main/java/Fixture.java").read()
    digests = {"src/main/java/Fixture.java": hashlib.sha256(java_source).hexdigest()}
    _write(Path(supplied["gold"]) / "strip_manifest.json", {"digests": digests})
    paths = set()
    for role in ("gold", "release_gold", "seed", "provenance"):
        paths.update(path for path in Path(supplied[role]).rglob("*") if path.is_file())
    paths.update(Path(supplied[role]) for role in (
        "release_items", "map_release", "closures", "oci_image"))
    before = {path: path.read_bytes() for path in paths}
    producer = {"tag": "supplied-java-reference", "commit": "1" * 40}
    composed = fixture_from_algorand_roles(root / "composed", supplied, producer)
    assert all(path.read_bytes() == raw for path, raw in before.items())
    assert Path(composed["role_sources"]["seed"], "workspace.tar").read_bytes() \
        == Path(supplied["seed"], "workspace.tar").read_bytes()
    with composed["patch_context"]():
        def reader():
            return ER.load_evaluation_reference(**composed["reference_args"],
                attestation_path=composed["role_sources"]["gold_results_attestation"])
        result = reader()
        assert result["controls"]["authority"]["container_image_digest"] == "sha256:" + "b" * 64
        assert result["controls"]["authority"]["substrate_baseline_sha256"] \
            == MR.content_digest(digests)
        score_fixture_candidate(root / "candidate", role_paths=composed["role_sources"],
                                reference_reader=reader)
    assert composed["producer"] == producer


def _test_sylius_coverage(root):
    """Fresh full coverage cannot be replaced by the historical oracle.

    Small source fixtures exercise the full/selected join; the real census
    replay and its content refusals run in data.sylius_selection.
    """
    from ..toolkit.assertion_selection import POLICY
    rows = [{"item_id": iid, "adapter": "gold", "outcome": "passed",
             "produced_files": [{"file_path": "Check.php", "code": "<?php assert(true);"}],
             "coverage_requested": True, "coverage_collected": True,
             "coverage_mismatch": [], "coverage_lines": {"Source.php": [1]},
             "coverage_files": {"Source.php": 1}}
            for iid in ("sylius/a:1", "sylius/b:1")]
    path = _rows(root / "coverage.jsonl", rows)
    selected = {"coverage_run_sha256": MR.sha256_file(path),
        "n_full_mapped_mutants": 1, "n_mapped_pairs_before_exclusion": 2}
    mapping = {"n_mapped": 1, "n_pairs": 2}
    def run(baseline=None, declaration=None, mapped=None):
        return ER._require_sylius_coverage(path, declaration or selected,
            mapped or mapping, {row["item_id"] for row in rows}, {rows[0]["item_id"]},
            baseline if baseline is not None else rows[:1])
    run()
    altered = copy.deepcopy(rows[:1])
    altered[0]["produced_files"][0]["code"] = "<?php assert(false);"
    for call, message in (
            (lambda: run(declaration={**selected, "coverage_run_sha256": "0" * 64}), "fresh gold authority"),
            (lambda: run(mapped={**mapping, "n_pairs": 1}), "population counts"),
            (lambda: run(baseline=altered), "solution bytes"),
            (lambda: run(baseline=rows), "solution bytes")):
        try:
            call()
        except RC.ReferenceControlsRefused as exc:
            assert message in str(exc), str(exc)
        else:
            raise AssertionError("invalid Sylius coverage admitted")
    for role in RC.ROLES:
        expected = POLICY if role == "stripped_gold" else None
        ER.validate_evaluation_control_policy(project="sylius", role=role, control_policy=expected)
        try:
            ER.validate_evaluation_control_policy(project="sylius", role=role,
                control_policy=None if expected else POLICY)
        except RC.ReferenceControlsRefused:
            pass
        else:
            raise AssertionError("wrong Sylius role policy admitted")
    print("  [PASS] Sylius full/selected coverage joins reject old oracle, changed files/counts and wrong policy")


def _cross_host_worker_resources(producer, seed_identity, image_id, harness_version):
    """Recorded host snapshots; all copied files have the receiving UID's custody."""
    from .. import docker_authority as D
    result = {}
    for number, (role, uid) in enumerate(zip(RC.ROLES, (1002, 1000, 1000)), 1):
        root = producer / role
        root.mkdir(mode=0o700)
        worker = W.WorkerSpec(index=0, workspace=str(root / "workspace"),
            container=f"reference-{number}", schema="", credential="",
            env_file=str(root / "worker0.env"), workdir="/work",
            out_path=str(root / "output.jsonl"), artifacts_root=str(root / "artifacts"))
        worker_path = _write(root / "worker0.json", worker.to_json())
        authority = D._fixture_authority()
        socket = f"/run/user/{uid}/reference-{number}/docker.sock"
        address = "unix://" + socket
        authority["endpoint"].update(address=address, selection_identity="host:" + address,
            address_sha256=D.endpoint_address_digest(address))
        adapter = authority["adapter"]
        for key in ("invoking_uid", "invoking_gid", "socket_uid", "socket_gid",
                    "private_parent_uid", "private_parent_gid", "docker_root_uid", "docker_root_gid"):
            adapter[key] = uid
        adapter.update(selected_socket_path=socket, resolved_socket_path=socket,
                       private_parent_path=str(Path(socket).parent))
        authority["daemon"]["id"] = f"reference-host-{number}"
        authority["daemon"]["fingerprint_sha256"] = D.daemon_fingerprint(authority["daemon"])
        authority["digest"] = D.semantic_digest(authority)
        authority_path = str(root / "authority.json")
        D.write_evidence_no_clobber(authority_path, authority)
        _, authority_ref = D.evidence_reference(authority_path, expected_schema=D.AUTHORITY_SCHEMA,
            validator=lambda value: D.validate_authority_document(value, current_source=False),
            label="cross-host fixture authority")
        binding = D._fixture_binding()
        binding.update(authority=authority_ref, worker_spec_sha256=MR.sha256_file(worker_path),
            pool=W.build_execution_pool([worker], [worker_path],
                                        database_container=None, internal_network=None))
        binding["container"].update(name=worker.container, id=str(number) * 64, image_id=image_id)
        binding["digest"] = D.semantic_digest(binding)
        binding_path = W.binding_attestation_path(worker_path)
        D.write_evidence_no_clobber(binding_path, binding)
        runtime = W.build_worker_runtime_attestation(worker, worker_path, seed_identity,
            harness_version, binding_path=binding_path)
        runtime_path = _write(W.runtime_attestation_path(worker_path), runtime)
        record = {key: worker.to_json()[key] for key in (
            "index", "workspace", "container", "schema", "credential", "env_file", "workdir")}
        result[role] = [dict(record, worker_spec=worker_path, runtime_attestation=runtime_path,
                            runtime_attestation_sha256=MR.sha256_file(runtime_path))]
    return result


def _test_full_gold_only(root):
    fixture = fixture_evaluation_inputs(root / "source", project="coddy-agent",
        collection_tag="common-full-gold-freeze",
        worker_resources_factory=_cross_host_worker_resources)
    args = fixture["reference_args"]
    for role in ("stripped_gold", "stub"):
        shutil.rmtree(Path(args["reference_inputs_root"]) / role)
        shutil.rmtree(Path(args["reference_controls_root"]) / role)
        (Path(args["reference_recipes_root"]) / (role + ".json")).unlink()
    out = str(root / "full-gold.json")
    with fixture["patch_context"]():
        result = ER.seal_evaluation_reference(out=out, reference_basis="full_gold", **args)
        controls = result["controls"]
        sets = RC.reference_sets(controls)
        assert controls["reference_basis"] == sets.reference_basis == "full_gold"
        assert set(controls["observations"]) == {"full_gold"}
        assert controls["stub_gate"] is None and controls["hard_scorable_items"] is None
        assert sets.hard_subset is None and sets.stub_recall_by_item is None
        assert sets.stub_macro_recall is None and sets.stub_threshold is None
        assert sets.eligible and sets.full_gold_kills
        reopened = ER.load_evaluation_reference(attestation_path=out, **args)
        assert dict(reopened["controls"]) == dict(controls)
        altered = copy.deepcopy(dict(controls))
        altered["stub_gate"] = {"eligible": True}
        altered["digest"] = RC.artifact_digest(altered)
        _write(out, altered)
        try:
            ER.load_evaluation_reference(attestation_path=out, **args)
        except RC.ReferenceControlsRefused as exc:
            assert "does not rederive" in str(exc)
        else:
            raise AssertionError("invented stub eligibility accepted")
    with fixture["patch_context"]():
        full_root = Path(args["reference_controls_root"]) / "full_gold"
        row_path = full_root / "gold.w0.jsonl"
        rows = TQ.load_jsonl(str(row_path))
        sidecar = ER._json(MR.provenance_path(str(row_path)))
        survival_root = root / "all-surviving" / "full_gold"
        survival_path = str(survival_root / "gold.w0.jsonl")
        survival_identity = sidecar["campaign_identity"]
        MR.prepare_standalone_output_directory(survival_path, survival_identity, "9" * 32)
        _rows(survival_path, [{**row, "outcome": "passed"} for row in rows])
        for state in ("running", "complete"):
            MR.write_shard_provenance(survival_path, survival_identity, state,
                provenance={"worker_resources": sidecar["worker_resources"]})
        survival_args = dict(args, reference_controls_root=str(survival_root.parent))
        try:
            ER.seal_evaluation_reference(out=str(root / "empty-gold.json"),
                reference_basis="full_gold", **survival_args)
        except RC.ReferenceControlsRefused as exc:
            assert "empty full-gold kill set" in str(exc), str(exc)
        else:
            raise AssertionError("project-wide empty full-gold reference admitted")
        shutil.rmtree(full_root)
        by_mutant = {}
        for item, mutant in result["scope"].expected_pairs:
            by_mutant.setdefault(mutant, set()).add(item)

        def write_hosts(speeds=None):
            host_pairs = {}
            for number, host in enumerate(("host-a", "host-b")):
                identity = copy.deepcopy(sidecar["campaign_identity"])
                partition = {"allocation_sha256": "a" * 64, "host": host,
                             "offset": number, "total": 2}
                if speeds:
                    partition["speeds"] = speeds
                pairs = MR.reference_partition_pairs(fixture["manifest"], by_mutant, partition, 1)
                host_pairs[host] = pairs
                resources = fixture["role_worker_resources"][("full_gold", "stripped_gold")[number]]
                identity["worker_resources_sha256"] = MR.content_digest(resources)
                identity.update(reference_partition=partition, expected_pairs=len(pairs),
                                expected_pairs_sha256=MR.pair_set_digest(pairs))
                target = str(full_root / host / "gold.w0.jsonl")
                MR.prepare_standalone_output_directory(target, identity, str(number + 1) * 32)
                _rows(target, [{**row, **MR.row_identity_stamp(identity)} for row in rows
                              if (row["item_id"], row["mutant_id"]) in pairs])
                for state in ("running", "complete"):
                    MR.write_shard_provenance(target, identity, state,
                        provenance={"worker_resources": resources})
                evidence = Path(target + ".go-evidence")
                evidence.mkdir()
                (evidence / "retained-capture.json").write_text('{"retired": true}')
            return host_pairs
        write_hosts()
        multi_out = str(root / "multi-host.json")
        joined = ER.seal_evaluation_reference(out=multi_out, reference_basis="full_gold", **args)
        assert joined["controls"]["items"] == controls["items"]
        assert joined["controls"]["pairs"] == controls["pairs"]
        facts = joined["controls"]["observations"]["full_gold"]
        assert set(facts["host_observations"]) == {"host-a", "host-b"}
        identities = [ER._json(MR.provenance_path(str(full_root / host / "gold.w0.jsonl")))["campaign_identity"]
                      for host in ("host-a", "host-b")]
        for change in ("overlap", "gap", "allocation", "freeze", "speeds"):
            altered_ids = copy.deepcopy(identities)
            if change == "overlap":
                altered_ids[1]["reference_partition"]["offset"] = 0
            elif change == "speeds":
                altered_ids[1]["reference_partition"]["speeds"] = [[2, 1]]
            elif change == "gap":
                for identity in altered_ids:
                    identity["reference_partition"]["total"] = 3
            elif change == "allocation":
                altered_ids[1]["reference_partition"]["allocation_sha256"] = "b" * 64
            else:
                altered_ids[1]["reference_source_tag"] = "another-collection-freeze"
            try:
                MR.validate_reference_host_partition_identities(altered_ids,
                    expected_pairs=result["scope"].expected_pairs,
                    observed_pairs=result["scope"].expected_pairs)
            except MR.MutationAborted:
                pass
            else:
                raise AssertionError("full-gold host " + change + " accepted despite complete pair union")
        producer = Path(fixture["producer_root"])
        hidden = root / "producer-unavailable"
        producer.rename(hidden)
        try:
            reopened = ER.load_evaluation_reference(attestation_path=multi_out, **args)
            assert reopened["controls"] == joined["controls"]
        finally:
            hidden.rename(producer)
        (full_root / "host-b").rename(root / "missing-host")
        try:
            ER.load_evaluation_reference(attestation_path=multi_out, **args)
        except RC.ReferenceControlsRefused:
            pass
        else:
            raise AssertionError("incomplete full-gold host partition accepted")
        # Speed-weighted balanced slots seal to the same controls; the faster
        # host's slot holds more pairs.
        shutil.rmtree(full_root)
        balanced = write_hosts([[1, 3], [1, 1]])
        assert len(balanced["host-a"]) > len(balanced["host-b"]), balanced
        assert balanced["host-a"] | balanced["host-b"] == set(result["scope"].expected_pairs)
        weighted = ER.seal_evaluation_reference(out=str(root / "multi-host-balanced.json"),
                                                reference_basis="full_gold", **args)
        assert weighted["controls"]["items"] == controls["items"]
        assert weighted["controls"]["pairs"] == controls["pairs"]
    print("  [PASS] full-gold-only native reference seals and reopens without inventing hard or stub measures")


def _test_supplement_seal(root):
    """Owner ruling 2026-09-30: a failed parent host's rows plus a supplement over the rest.

    Three single-worker parent hosts, `pc` failed after part of its slot; two
    supplement hosts under their own allocation, plan and tag observe exactly
    what `pc` left.  `harness_error` stands in for any infrastructure-class
    outcome the section 5.1 rule excludes.  In the chain, supplement host `sa`
    fails in turn after one row and a second supplement (`ta`, `tb`) under its
    own allocation, plan and tag observes exactly what `sa` left.
    """
    fixture = fixture_evaluation_inputs(root / "source", project="coddy-agent",
        collection_tag="common-full-gold-freeze",
        worker_resources_factory=_cross_host_worker_resources)
    args = fixture["reference_args"]
    for role in ("stripped_gold", "stub"):
        shutil.rmtree(Path(args["reference_inputs_root"]) / role)
        shutil.rmtree(Path(args["reference_controls_root"]) / role)
        (Path(args["reference_recipes_root"]) / (role + ".json")).unlink()
    shard = str(Path(args["reference_controls_root"]) / "full_gold" / "gold.w0.jsonl")
    template_row = TQ.load_jsonl(shard)[0]
    template = ER._json(MR.provenance_path(shard))["campaign_identity"]
    pools = [fixture["role_worker_resources"][role] for role in RC.ROLES]
    mutants = [f"m{n:02d}" for n in range(15)]
    manifest = {"mutants": [{"id": mutant} for mutant in mutants]}
    by_mutant = {mutant: {f"i{k}" for k in range(n % 3 + 1)} for n, mutant in enumerate(mutants)}
    all_pairs = {(item, mutant) for mutant, items in by_mutant.items() for item in items}
    parent_allocation = _write(root / "parent-allocation.json", {"pa": {}, "pb": {}, "pc": {}})
    parent = {host: {"allocation_sha256": MR.sha256_file(parent_allocation), "host": host,
                     "offset": number, "total": 3} for number, host in enumerate(("pa", "pb", "pc"))}
    planned = {host: MR.reference_partition_pairs(manifest, by_mutant, part, 1)
               for host, part in parent.items()}
    durable = {pair for pair in planned["pc"] if pair[1] == "m02"} | {("i0", "m05")}
    pending = planned["pc"] - durable

    def outcome(pair):
        return "harness_error" if pair == ("i1", "m08") else (
            "passed" if pair[0] == "i2" else "failed")

    def write(obs, host, part, pairs, pool, number, *, rows=None, status="complete", **change):
        identity = copy.deepcopy(template)
        identity.update(change, worker_resources_sha256=MR.content_digest(pool),
                        reference_partition=part, expected_pairs=len(pairs),
                        expected_pairs_sha256=MR.pair_set_digest(pairs))
        target = str(obs / host / "gold.w0.jsonl")
        MR.prepare_standalone_output_directory(target, identity, str(number) * 32)
        _rows(target, [{**template_row, "item_id": item, "mutant_id": mutant,
                        "outcome": outcome((item, mutant)), **MR.row_identity_stamp(identity)}
                       for item, mutant in sorted(pairs if rows is None else rows)])
        for state in ("running", status):
            MR.write_shard_provenance(target, identity, state, provenance={"worker_resources": pool})
        return target

    def build(name, *, failed=("pc",), supplement_pairs=None, tag="supplement-freeze",
              plans=("e" * 64, "e" * 64), allocation="c" * 64, supplement_rows=None, **change):
        obs = root / name / "full_gold"
        for number, host in enumerate(("pa", "pb", "pc")):
            rows = None
            if host in failed:
                rows = durable if host == "pc" else set(sorted(planned[host])[:1])
            write(obs, host, parent[host], planned[host], pools[number], number + 1,
                  rows=rows, status="failed" if host in failed else "complete")
        pending_by_mutant = {}
        for item, mutant in pending:
            pending_by_mutant.setdefault(mutant, set()).add(item)
        for number, host in enumerate(("sa", "sb")):
            part = {"allocation_sha256": allocation, "host": host, "offset": number,
                    "total": 2, "supplement_plan_sha256": plans[number]}
            pairs = MR.reference_partition_pairs(manifest, pending_by_mutant, part, 1)
            pairs = (supplement_pairs or {}).get(host, pairs)
            rows = (supplement_rows or {}).get(host)
            write(obs, host, part, pairs, pools[number], number + 4, rows=rows,
                  status="complete" if rows is None else "failed",
                  reference_source_tag=tag, **change)
        return obs

    sa_durable = {("i1", "m05")}

    def build_chain(name, *, second_pairs=None, second_rows=None, second_pending=None,
                    second_plans=("f" * 64, "f" * 64), pair_slots=False, **options):
        obs = build(name, supplement_rows={"sa": sa_durable}, **options)
        unrun = second_pending or sa_planned - sa_durable
        unrun_by_mutant = {}
        for item, mutant in unrun:
            unrun_by_mutant.setdefault(mutant, set()).add(item)
        for number, host in enumerate(("ta", "tb")):
            part = {"allocation_sha256": "d" * 64, "host": host, "offset": number,
                    "total": 2, "supplement_plan_sha256": second_plans[number],
                    **({"pair_slots": True} if pair_slots else {})}
            pairs = MR.reference_partition_pairs(manifest, unrun_by_mutant, part, 1)
            pairs = (second_pairs or {}).get(host, pairs)
            rows = (second_rows or {}).get(host)
            write(obs, host, part, pairs, pools[number], number + 6, rows=rows,
                  status="complete" if rows is None else "failed",
                  reference_source_tag="second-supplement-freeze")
        return obs

    with fixture["patch_context"]():
        scope = ER.seal_evaluation_reference(out=str(root / "single.json"),
                                            reference_basis="full_gold", **args)["scope"]
        scope = copy.copy(scope)
        scope.expected_pairs = frozenset(all_pairs)
        scope._manifest = manifest
        obs = build("merged")
        strict = RC.load_native_observation(str(obs), role="full_gold", scope=scope)
        portable = RC.load_preserved_observation(str(obs), role="full_gold", scope=scope)
        assert strict["facts"] == portable["facts"] and strict["outcomes"] == portable["outcomes"]
        assert set(strict["outcomes"]) == all_pairs and strict["identity"]["reference_partition"] == parent["pa"]
        facts = strict["facts"]
        assert facts["host_observations"]["pc"]["status"] == "failed"
        assert facts["host_observations"]["pc"]["planned_pairs"] == len(planned["pc"])
        assert facts["supplement"] == {
            "plan_sha256": "e" * 64,
            "parent": {"reference_source_tag": "common-full-gold-freeze",
                       "allocation_sha256": parent["pa"]["allocation_sha256"],
                       "failed_hosts": ["pc"], "failed_hosts_rows": len(durable)},
            "supplement": {"reference_source_tag": "supplement-freeze",
                           "allocation_sha256": "c" * 64, "hosts": ["sa", "sb"]},
            "pending_pairs": len(pending), "pending_pairs_sha256": MR.pair_set_digest(pending)}, facts
        assert facts["supplement_chain"] == [facts["supplement"]], facts
        document = RC.build_reference_controls(scope, full_gold=strict, allow_excluded_pairs=True)
        assert [(row["item_id"], row["mutant_id"]) for row in document["excluded_pairs"]] == [("i1", "m08")]
        assert document["authority"]["reference_source_tag"] == "common-full-gold-freeze"
        RC.validate_reference_controls(document, scope=scope, full_gold=portable)

        # The plan the parent host would freeze names the same pending set,
        # and a supplement host's slot is the one the seal rederives.
        supplement_allocation = _write(root / "supplement-allocation.json", {
            host: {"host": "h-" + host, "root": "/srv/" + host, "authority": "/a/" + host, "workers": 2}
            for host in ("sa", "sb")})
        plan = MR.build_reference_supplement_plan(
            manifest=manifest, by_mutant=by_mutant, observations_root=str(obs),
            parent_allocation=parent_allocation, failed_hosts=["pc"],
            parent_code={"tag": "parent-tag", "commit": "1" * 40},
            supplement_allocation=supplement_allocation,
            supplement_code={"tag": "supplement-tag", "commit": "2" * 40})
        assert plan["pending"]["sha256"] == facts["supplement"]["pending_pairs_sha256"]
        assert plan["parent"]["failed_hosts"]["pc"]["durable_pairs"] == len(durable)
        assert plan["parent"]["failed_hosts"]["pc"]["shards"][0]["rows_sha256"] \
            == facts["host_observations"]["pc"]["rows_sha256"][0]
        plan_path = _write(root / "supplement-plan.json", plan)
        partition, workers, pending_by_mutant = MR.load_reference_supplement(
            plan_path, supplement_allocation, "sb")
        assert workers == 2 and partition["supplement_plan_sha256"] == MR.sha256_file(plan_path)
        assert set().union(*(MR.reference_partition_pairs(manifest, pending_by_mutant,
            MR.load_reference_supplement(plan_path, supplement_allocation, host)[0], 2)
            for host in ("sa", "sb"))) == pending
        for label, call in (
                ("allocation", lambda: MR.load_reference_supplement(plan_path, parent_allocation, "sa")),
                ("pending", lambda: MR.load_reference_supplement(_write(root / "bad-plan.json", dict(
                    plan, pending=dict(plan["pending"], count=1))), supplement_allocation, "sa")),
                ("empty slot", lambda: MR.build_reference_supplement_plan(
                    manifest=manifest, by_mutant=by_mutant, observations_root=str(obs),
                    parent_allocation=parent_allocation, failed_hosts=["pc"], parent_code={},
                    supplement_allocation=_write(root / "wide.json", {"sa": {"host": "h", "root": "/r",
                        "authority": "/a", "workers": 5}}), supplement_code={})),
                ("healthy host", lambda: MR.build_reference_supplement_plan(
                    manifest=manifest, by_mutant=by_mutant, observations_root=str(obs),
                    parent_allocation=parent_allocation, failed_hosts=["pa"], parent_code={},
                    supplement_allocation=supplement_allocation, supplement_code={}))):
            try:
                call()
            except MR.MutationAborted:
                pass
            else:
                raise AssertionError("supplement plan " + label + " accepted")

        # Tampered failed shards: bytes, attested row count, torn last line.
        for tamper in ("sha", "rows", "trailing"):
            obs = build("tamper-" + tamper)
            target = obs / "pc" / "gold.w0.jsonl"
            sidecar = ER._json(MR.provenance_path(str(target)))
            data = target.read_bytes()
            if tamper == "sha":
                target.write_bytes(data.replace(b'"failed"', b'"passed"', 1))
            elif tamper == "rows":
                _write(MR.provenance_path(str(target)), dict(sidecar, rows=sidecar["rows"] + 1))
            else:
                target.write_bytes(data[:-1])
                _write(MR.provenance_path(str(target)), dict(sidecar, rows_sha256=MR.sha256_file(target)))
            for reader in (RC.load_native_observation, RC.load_preserved_observation):
                try:
                    reader(str(obs), role="full_gold", scope=scope)
                except RC.ReferenceControlsRefused:
                    pass
                else:
                    raise AssertionError("tampered failed shard accepted: " + tamper)
        durable_pair, parent_pair = sorted(durable)[0], sorted(planned["pa"])[0]
        sa_pairs = MR.reference_partition_pairs(manifest, {m: {i for i, n in pending if n == m}
            for _i, m in pending}, {"host": "sa", "offset": 0, "total": 2}, 1)
        sb_pairs = pending - sa_pairs
        for name, options in (
                ("overlap", {"supplement_pairs": {"sa": sa_pairs | {durable_pair}}}),
                ("missing", {"supplement_pairs": {"sb": set(sorted(sb_pairs)[1:])}}),
                ("extra", {"supplement_pairs": {"sb": sb_pairs | {parent_pair}}}),
                ("core", {"timeout_seconds": template["timeout_seconds"] + 1}),
                ("unnamed failure", {"failed": ("pb", "pc")}),
                ("no failure", {"failed": ()}),
                ("third group", {"plans": ("e" * 64, "f" * 64)})):
            obs = build("refuse-" + name.replace(" ", "-"), **options)
            try:
                RC.load_native_observation(str(obs), role="full_gold", scope=scope)
            except RC.ReferenceControlsRefused:
                pass
            else:
                raise AssertionError("supplement " + name + " accepted")

        # The chain: `sa` failed after one row, and a second supplement under
        # its own plan covers what `sa` left.  The first supplement's hosts
        # name its real plan and allocation, as the second plan's reader needs.
        sa_planned = sa_pairs
        unrun = sa_planned - sa_durable
        first = {"plans": (MR.sha256_file(plan_path),) * 2,
                 "allocation": MR.sha256_file(supplement_allocation)}
        obs = build_chain("chain", **first)
        strict = RC.load_native_observation(str(obs), role="full_gold", scope=scope)
        portable = RC.load_preserved_observation(str(obs), role="full_gold", scope=scope)
        assert strict["facts"] == portable["facts"] and strict["outcomes"] == portable["outcomes"]
        assert set(strict["outcomes"]) == all_pairs
        chained = strict["facts"]
        assert chained["host_observations"]["sa"]["status"] == "failed"
        assert chained["host_observations"]["sa"]["planned_pairs"] == len(sa_planned)
        assert chained["supplement_chain"] == [
            dict(facts["supplement"], plan_sha256=first["plans"][0],
                 supplement=dict(facts["supplement"]["supplement"],
                                 allocation_sha256=first["allocation"])),
            {"plan_sha256": "f" * 64,
             "parent": {"reference_source_tag": "supplement-freeze",
                        "allocation_sha256": first["allocation"],
                        "failed_hosts": ["sa"], "failed_hosts_rows": len(sa_durable)},
             "supplement": {"reference_source_tag": "second-supplement-freeze",
                            "allocation_sha256": "d" * 64, "hosts": ["ta", "tb"]},
             "pending_pairs": len(unrun), "pending_pairs_sha256": MR.pair_set_digest(unrun)}], chained
        assert chained["supplement"] == chained["supplement_chain"][1]
        document = RC.build_reference_controls(scope, full_gold=strict, allow_excluded_pairs=True)
        assert document["authority"]["reference_source_tag"] == "common-full-gold-freeze"
        RC.validate_reference_controls(document, scope=scope, full_gold=portable)

        # The second plan is frozen from the failed supplement host: its slots
        # are of the first plan's pending pairs, and it names that plan.
        second_allocation = _write(root / "second-allocation.json", {"ta": {
            "host": "h-ta", "root": "/srv/ta", "authority": "/a/ta", "workers": 2}})
        second = dict(manifest=manifest, by_mutant=by_mutant, observations_root=str(obs),
                      parent_allocation=supplement_allocation, failed_hosts=["sa"],
                      parent_code={"tag": "supplement-tag", "commit": "2" * 40},
                      supplement_allocation=second_allocation,
                      supplement_code={"tag": "second-tag", "commit": "3" * 40})
        second_plan = MR.build_reference_supplement_plan(parent_plan=plan_path, **second)
        assert "plan" not in plan["parent"]
        assert second_plan["parent"]["plan"] == {
            "path": os.path.abspath(plan_path), "sha256": MR.sha256_file(plan_path)}
        assert second_plan["pending"]["sha256"] == chained["supplement"]["pending_pairs_sha256"]
        assert second_plan["parent"]["failed_hosts"]["sa"]["durable_pairs"] == len(sa_durable)
        assert second_plan["supplement"]["host_pairs"] == {"ta": len(unrun)}
        for label, call in (
                ("without its parent plan", lambda: MR.build_reference_supplement_plan(**second)),
                ("under another parent plan", lambda: MR.build_reference_supplement_plan(
                    parent_plan=_write(root / "other-plan.json", dict(plan, extra=1)), **second)),
                ("of a first-allocation host", lambda: MR.build_reference_supplement_plan(
                    parent_plan=plan_path, **dict(second, parent_allocation=parent_allocation,
                                                  failed_hosts=["pc"])))):
            try:
                call()
            except MR.MutationAborted:
                pass
            else:
                raise AssertionError("second supplement plan " + label + " accepted")

        ta_pairs = MR.reference_partition_pairs(manifest, {m: {i for i, n in unrun if n == m}
            for _i, m in unrun}, {"host": "ta", "offset": 0, "total": 2}, 1)
        tb_pairs = unrun - ta_pairs
        assert ta_pairs and tb_pairs
        for name, options, reason in (
                ("overlap", {"second_pairs": {"ta": ta_pairs | sa_durable}}, ""),
                ("missing", {"second_pairs": {"tb": set(sorted(tb_pairs)[1:])}}, ""),
                ("extra", {"second_pairs": {"tb": tb_pairs | {parent_pair}}}, ""),
                ("failed last host", {"second_rows": {"tb": set(sorted(tb_pairs)[:1])}}, ""),
                # Neither plan group was planned for what `pc` left ...
                ("no next level", {"supplement_pairs": {"sa": sa_pairs | {parent_pair}}},
                 "no unique full-gold supplement"),
                # ... or both were.
                ("two next levels", {"second_pending": pending}, "no unique full-gold supplement"),
                ("second plan split", {"second_plans": ("f" * 64, "9" * 64)},
                 "no unique full-gold supplement")):
            obs = build_chain("chain-refuse-" + name.replace(" ", "-"), **first, **options)
            for reader in (RC.load_native_observation, RC.load_preserved_observation):
                try:
                    reader(str(obs), role="full_gold", scope=scope)
                except RC.ReferenceControlsRefused as exc:
                    assert reason in str(exc), (name, str(exc))
                else:
                    raise AssertionError("supplement chain " + name + " accepted")
        # Delegated 2026-09-30 (full282 section 5, fourth supplement): the
        # second supplement deals single pairs.  Its slots tile the unrun
        # pairs once each, the reader rederives them from the recorded
        # partition, and a shard written under whole-mutant slots refuses.
        dealt = {"pair_slots": True, "offset": 0, "total": 2}
        dealt_by_mutant = {m: {i for i, n in unrun if n == m} for _i, m in unrun}
        ta_dealt, tb_dealt = MR.reference_shard_pairs(manifest, dealt_by_mutant, dealt, 2)
        assert ta_dealt | tb_dealt == unrun and not ta_dealt & tb_dealt
        # mutation-run deals from the manifest already filtered to the
        # mutants with pending pairs; the readers from the whole manifest.
        # The dealt mutants skip manifest entries, and both agree.
        dealt_at = [mutants.index(mutant) for mutant in sorted(dealt_by_mutant)]
        assert dealt_at[-1] - dealt_at[0] + 1 > len(dealt_at), dealt_at
        filtered = {"mutants": [m for m in manifest["mutants"] if dealt_by_mutant.get(m["id"])]}
        assert MR.reference_shard_pairs(filtered, dealt_by_mutant, dealt, 2) == [ta_dealt, tb_dealt]
        assert MR.reference_shard_pairs(filtered, dealt_by_mutant, dict(dealt, offset=1), 1) == [tb_dealt]
        assert abs(len(ta_dealt) - len(tb_dealt)) <= 1, (ta_dealt, tb_dealt)
        obs = build_chain("chain-pairs", pair_slots=True, **first)
        dealt_strict = RC.load_native_observation(str(obs), role="full_gold", scope=scope)
        dealt_portable = RC.load_preserved_observation(str(obs), role="full_gold", scope=scope)
        assert dealt_strict["facts"] == dealt_portable["facts"]
        assert dealt_strict["outcomes"] == strict["outcomes"]
        assert set(dealt_strict["outcomes"]) == all_pairs
        assert dealt_strict["facts"]["supplement_chain"] == chained["supplement_chain"]
        assert ta_dealt != ta_pairs, "fixture must tell the slot modes apart"
        obs = build_chain("chain-pairs-by-mutant", pair_slots=True,
                          second_pairs={"ta": ta_pairs, "tb": tb_pairs}, **first)
        for reader in (RC.load_native_observation, RC.load_preserved_observation):
            try:
                reader(str(obs), role="full_gold", scope=scope)
            except RC.ReferenceControlsRefused:
                pass
            else:
                raise AssertionError("pair-slot identity over whole-mutant shards accepted")
        dealt_plan = MR.build_reference_supplement_plan(parent_plan=plan_path, pair_slots=True, **second)
        assert dealt_plan["supplement"]["slots"] == "pairs" and "slots" not in second_plan["supplement"]
        assert dealt_plan["pending"] == second_plan["pending"]
        dealt_path = _write(root / "dealt-plan.json", dealt_plan)
        loaded, _workers, _pending = MR.load_reference_supplement(dealt_path, second_allocation, "ta")
        assert loaded["pair_slots"] is True
        assert "pair_slots" not in MR.load_reference_supplement(
            _write(root / "whole-plan.json", second_plan), second_allocation, "ta")[0]
        try:
            MR.load_reference_supplement(_write(root / "odd-plan.json", dict(dealt_plan, supplement=dict(
                dealt_plan["supplement"], slots="items"))), second_allocation, "ta")
        except MR.MutationAborted:
            pass
        else:
            raise AssertionError("unknown supplement slot mode accepted")

        obs = build_chain("chain-tamper", **first)
        target = obs / "sa" / "gold.w0.jsonl"
        target.write_bytes(target.read_bytes().replace(b'"failed"', b'"passed"', 1))
        for reader in (RC.load_native_observation, RC.load_preserved_observation):
            try:
                reader(str(obs), role="full_gold", scope=scope)
            except RC.ReferenceControlsRefused:
                pass
            else:
                raise AssertionError("tampered failed supplement shard accepted")
    parent_ids = [dict(template, reference_partition=part) for part in parent.values()]
    added = [dict(template, reference_source_tag="supplement-freeze", reference_partition={
        "allocation_sha256": "c" * 64, "host": host, "offset": n, "total": 2,
        "supplement_plan_sha256": "e" * 64}) for n, host in enumerate(("sa", "sb"))]
    MR.validate_reference_host_partition_identities(
        parent_ids + added, expected_pairs=all_pairs, observed_pairs=all_pairs)
    second = dict(template, reference_source_tag="second-supplement-freeze", reference_partition={
        "allocation_sha256": "d" * 64, "host": "ta", "offset": 0, "total": 1,
        "supplement_plan_sha256": "f" * 64})
    MR.validate_reference_host_partition_identities(
        parent_ids + added + [second], expected_pairs=all_pairs, observed_pairs=all_pairs)
    dealt_second = dict(second, reference_partition=dict(second["reference_partition"], pair_slots=True))
    MR.validate_reference_host_partition_identities(
        parent_ids + added + [dealt_second], expected_pairs=all_pairs, observed_pairs=all_pairs)
    for label, identity in (("pair slots outside a supplement", dict(parent_ids[0], reference_partition=dict(
                                parent["pa"], pair_slots=True))),
                            ("pair slots not true", dict(second, reference_partition=dict(
                                second["reference_partition"], pair_slots=1)))):
        try:
            MR._validate_campaign_identity(identity)
        except MR.MutationAborted:
            pass
        else:
            raise AssertionError(label + " accepted")
    for label, identities in (("lone supplement", added),
                              ("one plan under two allocations", parent_ids + added + [dict(
                                  second, reference_partition=dict(
                                      second["reference_partition"],
                                      supplement_plan_sha256="e" * 64))]),
                              ("chain core", parent_ids + added + [dict(
                                  second, timeout_seconds=template["timeout_seconds"] + 1)]),
                              ("tag within an allocation", parent_ids[:2] + [
                                  dict(parent_ids[2], reference_source_tag="supplement-freeze")])):
        try:
            MR.validate_reference_host_partition_identities(
                identities, expected_pairs=all_pairs, observed_pairs=all_pairs)
        except MR.MutationAborted:
            pass
        else:
            raise AssertionError(label + " accepted")
    print("  [PASS] a failed parent host's rows plus a planned supplement seal strictly and portably; "
          "overlap, gaps, extra pairs, tampered shards, core drift, unnamed failures and a third group refuse")
    print("  [PASS] a failed supplement host's rows plus a second planned supplement seal as one chain, "
          "also dealt as single pairs; overlap, gaps, extra pairs, a failed last host, unorderable plans, "
          "a mismatched slot mode and tampered shards refuse")


def _test_cross_host_seal(root):
    from .. import docker_authority as D
    source = root / "source"
    fixture = fixture_evaluation_inputs(source, project="coddy-agent",
        collection_tag="common-cross-host-freeze", worker_resources_factory=_cross_host_worker_resources)
    producer = Path(fixture["producer_root"])
    # Model a byte-preserving transfer into the same absolute paths. The
    # documents retain producer UIDs while the receiver owns the copied files.
    snapshot = root / "transfer"
    shutil.copytree(producer, snapshot)
    shutil.rmtree(producer)
    shutil.copytree(snapshot, producer)
    identities = set()
    runtime_shared = set()
    for role, uid in zip(RC.ROLES, (1002, 1000, 1000)):
        resource = fixture["role_worker_resources"][role][0]
        checked = W.validate_worker_runtime_v3(resource["worker_spec"])
        runtime = checked["runtime"]
        authority = D.load_reference(runtime["docker_execution_authority"],
            expected_schema=D.AUTHORITY_SCHEMA, validator=lambda value:
                D.validate_authority_document(value, current_source=False), label="copied fixture authority")
        assert authority["adapter"]["invoking_uid"] == uid
        assert Path(runtime["docker_execution_authority"]["path"]).stat().st_uid == os.geteuid()
        assert W.worker_runtime_version(runtime) == "v3"
        identities.add((authority["digest"], checked["binding"]["pool"]["digest"]))
        runtime_shared.add(tuple(runtime[key] for key in (
            "container_image_digest", "workspace_seed_digest", "database_dump_digest", "harness_version")))
    assert len(identities) == 3 and len(runtime_shared) == 1
    with fixture["patch_context"]():
        resealed = ER.seal_evaluation_reference(out=str(root / "mirrored-reference.json"),
                                               **fixture["reference_args"])
        assert dict(resealed["controls"]) == dict(fixture["loaded"]["controls"])
        for role in RC.ROLES:
            resource = fixture["role_worker_resources"][role][0]
            runtime = ER._json(resource["runtime_attestation"])
            paths = (resource["worker_spec"], resource["runtime_attestation"],
                     runtime["docker_execution_binding"]["path"],
                     runtime["docker_execution_authority"]["path"])
            for number, value in enumerate(paths):
                path = Path(value)
                original = path.read_bytes()
                for absent in (True, False):
                    out = root / f"refused-{role}-{number}-{absent}.json"
                    try:
                        if absent:
                            path.unlink()
                        else:
                            path.write_bytes(original + b"\n")
                        try:
                            ER.seal_evaluation_reference(out=str(out), **fixture["reference_args"])
                        except RC.ReferenceControlsRefused:
                            pass
                        else:
                            raise AssertionError(f"strict seal admitted changed {role} evidence: {path.name}")
                        assert not out.exists()
                    finally:
                        path.write_bytes(original)
    installed = root / "installed"
    shutil.copytree(source, installed)
    shutil.rmtree(installed / "producer")
    source.rename(root / "producer-unavailable")
    relocate = lambda value: json.loads(json.dumps(value).replace(str(source), str(installed)))
    with fixture["patch_context"]():
        portable = ER.validate_evaluation_reference_inputs(project="coddy-agent",
            role_paths=relocate(fixture["role_sources"]), scope=fixture["scope"],
            validation_input_paths=relocate(fixture["validation_input_paths"]))
        assert dict(portable["controls"]) == dict(fixture["loaded"]["controls"])
    print("  [PASS] three copied Go v3 host pools preserve producer UIDs, seal strictly, reject missing/altered evidence and reopen portably")


def _test_distinct_baseline_producers(root):
    producers = {"full_gold": "retained-gold-v4", "stripped_gold": "corrected-controls-v5",
                 "stub": "corrected-controls-v5"}
    fixture = fixture_evaluation_inputs(root, project="coddy-agent",
        baseline_producers=producers, collection_tag="common-mutation-freeze")
    inputs = Path(fixture["role_sources"]["reference_inputs"])
    with fixture["patch_context"]():
        loaded = ER.load_evaluation_reference(**fixture["reference_args"],
            attestation_path=fixture["role_sources"]["gold_results_attestation"])
        assert RC.authenticated_reference_controls(loaded["controls"])
        for role in RC.ROLES:
            path = inputs / role / "run.jsonl"
            original = path.read_bytes()
            rows = MA.load_jsonl(path)
            assert {row["reference_source_tag"] for row in rows} == {producers[role]}
            args = dict(fixture["common_args"], candidate_path=str(path), role=role,
                recipe_path=str(Path(fixture["role_sources"]["provenance"])
                                / "reference-recipes" / (role + ".json")))
            plan = ER.plan_reference_leg(**args, source_tag="common-mutation-freeze")
            different_freeze = ER.plan_reference_leg(**args, source_tag="different-freeze")
            assert plan["generation"]["reference_source_tag"] == "common-mutation-freeze"
            assert plan["workload"]["reference_workload_digest"] == \
                different_freeze["workload"]["reference_workload_digest"]
            for row in rows:
                row["reference_source_tag"] = "tampered-producer"
            try:
                _rows(path, rows)
                try:
                    ER.load_evaluation_reference(**fixture["reference_args"],
                        attestation_path=fixture["role_sources"]["gold_results_attestation"])
                except RC.ReferenceControlsRefused:
                    pass
                else:
                    raise AssertionError("changed baseline producer reopened native reference")
            finally:
                path.write_bytes(original)
    # Each observation is internally valid, but the complete seal requires
    # one common collection freeze across all three roles.
    try:
        fixture_evaluation_inputs(root / "different-freeze", project="coddy-agent",
            baseline_producers=producers, collection_tag="common-mutation-freeze",
            collection_tags={"stub": "different-freeze"})
    except RC.ReferenceControlsRefused as exc:
        assert "stable" in str(exc) and "reference_source_tag" in str(exc), str(exc)
    else:
        raise AssertionError("distinct observation freezes sealed together")
    print("  [PASS] native Go references retain distinct baseline producers, bind one freeze and reject tampering")


def selftest():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        _test_sylius_coverage(root / "sylius")
        fixture = fixture_evaluation_inputs(root / "source")
        _test_control_policy(fixture, "python-docx")
        _test_scope_instantiation(root / "python-template", fixture)
        with fixture["patch_context"]():
            loaded = ER.load_evaluation_reference(
                **fixture["reference_args"],
                attestation_path=fixture["role_sources"]["gold_results_attestation"])
            assert RC.authenticated_reference_controls(loaded["controls"])
            assert loaded["scope"].population["asset_index_sha256"] != "0" * 64
            assert len(loaded["scope"].expected_pairs) == 1
            assert len(fixture["manifest"]["mutants"]) == 2
        print("  [PASS] native report, distinct scope index, pure role sources and native observations seal and reopen")
        _test_distinct_baseline_producers(root / "distinct-producers")
        _test_full_gold_only(root / "full-gold-only")
        _test_supplement_seal(root / "supplement")
        _test_cross_host_seal(root / "cross-host")
        installed = root / "installed"
        shutil.copytree(root / "source", installed)
        (root / "source").rename(root / "producer-unavailable")
        relocate = lambda value: json.loads(json.dumps(value).replace(
            str(root / "source"), str(installed)))
        roles = relocate(fixture["role_sources"])
        inputs = relocate(fixture["validation_input_paths"])
        def reader():
            return ER.validate_evaluation_reference_inputs(
                project="python-docx", role_paths=roles, scope=fixture["scope"],
                validation_input_paths=inputs)
        with fixture["patch_context"]():
            moved = reader()
            assert dict(moved["controls"]) == dict(fixture["loaded"]["controls"])
            score_fixture_candidate(root / "private-candidate", role_paths=roles,
                                    reference_reader=reader)
            # specifications/SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md: the
            # labelled basis reopens the RELOCATED observations (the producer
            # tree is gone), takes no attestation, and is defined for one
            # project.
            sensitivity_args = relocate(fixture["reference_args"])
            try:
                ER.load_evaluation_sensitivity_reference(
                    **sensitivity_args, sensitivity="sylius_stub_gate_waived_v1",
                    allow_excluded_pairs=False)
            except RC.ReferenceControlsRefused as exc:
                assert "defined for project 'sylius'" in str(exc), str(exc)
            else:
                raise AssertionError("a sylius sensitivity loaded another project")
            try:
                ER.load_evaluation_sensitivity_reference(
                    **sensitivity_args, sensitivity="sylius_stub_gate_waived_v1",
                    allow_excluded_pairs=False,
                    attestation_path=roles["gold_results_attestation"])
            except RC.ReferenceControlsRefused as exc:
                assert "takes no attestation" in str(exc), str(exc)
            else:
                raise AssertionError("a sensitivity basis read an attestation")
            with patch.dict(RC.SENSITIVITY_PROJECTS,
                            {"sylius_stub_gate_waived_v1": "python-docx"}):
                sensitive = ER.load_evaluation_sensitivity_reference(
                    **sensitivity_args, sensitivity="sylius_stub_gate_waived_v1",
                    allow_excluded_pairs=False)["controls"]
            eligible = dict(moved["controls"])
            assert sensitive["sensitivity"] == "sylius_stub_gate_waived_v1"
            assert sensitive["items"] == eligible["items"]
            assert sensitive["observations"] == eligible["observations"]
            assert sensitive["digest"] != eligible["digest"]
            print("  [PASS] a labelled sensitivity basis reopens relocated observations without an attestation, for its own project only")
            # VERSIONS.yml accepted_reference_appliers: an installed engine
            # source other than the applier the roles recorded refuses,
            # unless the project's entry accepts it beside the recorded one.
            recorded_engine = Path(sensitivity_args["engine_source_path"])
            later_engine = root / "later-applier" / recorded_engine.name
            later_engine.parent.mkdir()
            later_engine.write_bytes(recorded_engine.read_bytes() + b"\n")
            later_args = dict(sensitivity_args,
                              engine_source_path=str(later_engine))
            def later_reader():
                return ER.load_evaluation_reference(
                    **later_args,
                    attestation_path=roles["gold_results_attestation"])
            try:
                later_reader()
            except RC.ReferenceControlsRefused as exc:
                assert "runtime applier differs from its installed source" \
                    in str(exc), str(exc)
            else:
                raise AssertionError("an unlisted installed applier was admitted")
            with patch.dict(versions.component("harness"), {
                    "accepted_reference_appliers": {"python-docx": {
                        MR.sha256_file(str(recorded_engine)):
                            [MR.sha256_file(str(later_engine))]}}}):
                accepted = later_reader()
            assert dict(accepted["controls"]) == dict(moved["controls"])
            print("  [PASS] an installed applier other than the recorded one refuses unless VERSIONS.yml accepts it for the project")
            def refuses(call, needle):
                try:
                    call()
                except (RC.ReferenceControlsRefused, MR.MutationAborted) as exc:
                    assert needle in str(exc), str(exc)
                else:
                    raise AssertionError("invalid evaluation reference was admitted")
            scope_path = Path(roles["provenance"]) / "collection-scope.json"
            original_scope = scope_path.read_bytes()
            scope_document = ER._json(scope_path)
            _write(scope_path, dict(scope_document, asset_index_sha256="0" * 64))
            refuses(reader, "differs from its reviewed source pin")
            scope_path.write_bytes(original_scope)
            role_root = Path(roles["reference_inputs"]) / "stripped_gold"
            run_path = role_root / "run.jsonl"
            original_run = run_path.read_bytes()
            shutil.copyfile(Path(roles["reference_inputs"]) / "stub/run.jsonl", run_path)
            refuses(reader, "supplied reference derivation")
            run_path.write_bytes(original_run)
            extra = role_root / "tests/unexpected.py"
            extra.write_text("pass\n", encoding="utf-8")
            refuses(reader, "tests tree differs")
            extra.unlink()
            recipe_path = Path(roles["provenance"]) / "reference-recipes/stub.json"
            original_recipe = recipe_path.read_bytes()
            recipe = ER._json(recipe_path)
            _write(recipe_path, dict(recipe, adapter_version=99))
            refuses(reader, "unsupported recorded")
            recipe_path.write_bytes(original_recipe)
            bad_release = dict(roles, map_release=roles["release_items"])
            refuses(lambda: ER.validate_evaluation_reference_inputs(
                project="python-docx", role_paths=bad_release, scope=fixture["scope"],
                validation_input_paths=inputs), "campaign release input")
        _declared_scope_case(root / "declared", role_paths=roles, validation_input_paths=inputs)
        coverage = MA.load_jsonl(roles["coverage_run"])
        released = {fixture["item_id"]}
        baseline_rows = MA.load_jsonl(roles["gold_baseline"])
        ER._require_full_gold_coverage(coverage, released, baseline_rows)
        for counts in ([], {}):
            empty = [dict(coverage[0], coverage_lines={}, coverage_files=counts)]
            before = copy.deepcopy(empty)
            ER._require_full_gold_coverage(empty, released, baseline_rows)
            assert empty == before
        for rows in ([dict(coverage[0], item_id="not-released")],
                     [dict(coverage[0], outcome="failed")],
                     [dict(coverage[0], adapter="replay")],
                     [dict(coverage[0], coverage_requested=False)],
                     [dict(coverage[0], coverage_collected=False)],
                     [dict(coverage[0], coverage_mismatch=["src/app.py"])],
                     [dict(coverage[0], coverage_files={"src/app.py": 2})],
                     [dict(coverage[0], coverage_files=[])],
                     [dict(coverage[0], produced_files=[{
                         "file_path": "different.py", "code": "assert False"}])],
                     [{key: value for key, value in coverage[0].items()
                       if key != "coverage_lines"}]):
            try:
                ER._require_full_gold_coverage(rows, released, baseline_rows)
            except RC.ReferenceControlsRefused:
                pass
            else:
                raise AssertionError("non-gold/incomplete CoreShop coverage was admitted")
        for field in ("coverage_requested", "coverage_collected", "coverage_mismatch", "coverage_files"):
            missing = [{key: value for key, value in coverage[0].items() if key != field}]
            try:
                ER._require_full_gold_coverage(missing, released, baseline_rows)
            except RC.ReferenceControlsRefused:
                pass
            else:
                raise AssertionError(f"CoreShop coverage lacking {field} was admitted")
        # Native report and map validators rederive their byte joins, but do
        # not inspect the recorder's status/count witness. Drive the public
        # planner through a fully native, self-consistent report carrying the
        # real producer mismatch shape S0 reported; it must refuse here.
        for name, changes, message in (
                ("mismatch", {"coverage_files": {"src/CoreShop/Component/Fixture.php": 2},
                              "coverage_mismatch": ["src/CoreShop/Component/Fixture.php"]},
                 "coverage is absent, incomplete or mismatched"),
                ("counts", {"coverage_files": {"src/CoreShop/Component/Fixture.php": 2}},
                 "coverage file counts disagree")):
            try:
                fixture_evaluation_inputs(root / ("core-recorder-" + name),
                                           project="coreshop", coverage_changes=changes)
            except RC.ReferenceControlsRefused as exc:
                assert message in str(exc), str(exc)
            else:
                raise AssertionError("public CoreShop scope admitted an invalid recorder witness")
        print("  [PASS] relocated original native report and all three controls score candidate-only with zero reference execution")
        print("  [PASS] mismatched scope, swapped controls, extra source files and unsupported recipes refuse")
        print("  [PASS] explicit Algorand-shaped declaration preserves the full native map and its original reason")
        print("  [PASS] CoreShop scope rejects missing/mismatched recorder coverage and preserves collected-empty rows")
        for project in ("coreshop", "algorand-sdk"):
            source = root / (project + "-source")
            fixture = fixture_evaluation_inputs(source, project=project)
            _test_control_policy(fixture, project)
            if project == "algorand-sdk":
                _test_supplied_algorand_composition(root / "supplied-java", fixture)
            _test_scope_instantiation(root / (project + "-template"), fixture)
            installed = root / (project + "-installed")
            shutil.copytree(source, installed)
            source.rename(root / (project + "-producer-unavailable"))
            relocate = lambda value: json.loads(json.dumps(value).replace(str(source), str(installed)))
            roles = relocate(fixture["role_sources"])
            inputs = relocate(fixture["validation_input_paths"])
            feature_root = relocate(fixture["common_args"]["feature_root"])

            def reader():
                return ER.validate_evaluation_reference_inputs(
                    project=project, role_paths=roles, scope=fixture["scope"],
                    validation_input_paths=inputs, feature_root=feature_root)

            with fixture["patch_context"]():
                reopened = reader()
                assert reopened["scope"].population["project"] == project
                summary = score_fixture_candidate(root / (project + "-candidate"),
                    role_paths=roles, reference_reader=reader)
                if project == "coreshop":
                    assert summary["database_dump_digest"] != "no_database"
                    assert fixture["manifest"]["n_non_production_excluded"] == 1
                else:
                    assert summary["reference_omitted_items"] == 1
                    assert summary["candidate_pairs"] == 1
            print(f"  [PASS] real {project} sources, native population/report and declared scope relocate and score candidate-only")
        print("  [PASS] scope instantiation fills only null measured pins, preserves declarations and refuses known-pin drift or overwrite")
        print("  [PASS] evaluation stripped policy is mandatory for CoreShop/Algorand while historical/default derivations remain readable")
    return 0
