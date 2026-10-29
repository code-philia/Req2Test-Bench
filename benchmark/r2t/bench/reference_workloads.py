"""Rederive reference inputs through the existing fixture producers.

This module executes no reference tests. It joins actual run bytes to the
files and selection metadata the recorded control recipe derives from its
authenticated source inputs. Population and source-tree admission belong to
the calling reference/bundle loader.
"""
from __future__ import annotations

import json
import os

from . import mutation_run
from .fixtures import Adapter, make_gold_adapter
from .test_quality import passed_solutions

ROLE_ADAPTERS = {"full_gold": "gold", "stripped_gold": "stripped-gold", "stub": "stub"}
RECIPE_FIELDS = frozenset({"adapter", "adapter_version", "release_sha256", "asset_index_sha256"})


class ReferenceWorkloadRefused(ValueError):
    """A run or recipe does not rederive from its reference inputs."""


def _refuse(message):
    raise ReferenceWorkloadRefused("REFUSED: " + message)


def validate_recipe(recipe: dict, *, role: str,
                    execution_release_sha256: str) -> dict:
    """Keep recorded four-field recipes, and admit the explicit fifth field.

    The recorded version is never replaced with today's fixture registry
    version. PHP stubs also have a version 2 producer; project routing below
    refuses that version for the other frameworks.
    """
    from ..toolkit.assertion_selection import POLICY

    if role not in ROLE_ADAPTERS:
        _refuse(f"unknown reference role {role!r}.")
    if not isinstance(recipe, dict) or set(recipe) not in (
            RECIPE_FIELDS, RECIPE_FIELDS | {"control_policy"}):
        _refuse("reference recipe must contain its exact four historical "
                "fields or five prospective fields.")
    if recipe["adapter"] != ROLE_ADAPTERS[role]:
        _refuse("reference recipe adapter differs from its role.")
    supported = (1, 2, 3) if role == "stub" else (1, 2) if role == "stripped_gold" else (1,)
    if type(recipe["adapter_version"]) is not int or recipe["adapter_version"] not in supported:
        _refuse(f"unsupported recorded reference adapter version "
                f"{recipe['adapter_version']!r}; it is not today's version.")
    for field in ("release_sha256", "asset_index_sha256"):
        value = recipe[field]
        if not isinstance(value, str) or len(value) != 64 or any(
                ch not in "0123456789abcdef" for ch in value):
            _refuse(f"reference recipe {field} is not a SHA-256.")
    if recipe["release_sha256"] != execution_release_sha256:
        _refuse("reference recipe release differs from the actual execution tasks.")
    policy = recipe.get("control_policy")
    if policy is not None and (policy != POLICY or role != "stripped_gold"):
        _refuse("control_policy is the reviewed stripped-gold selection only.")
    return dict(recipe)


def reference_recipe(*, role: str, adapter_version: int,
                     release_sha256: str, asset_index_sha256: str,
                     control_policy: str | None = None) -> dict:
    """Construct the prospective five-field recipe from actual producer facts."""
    recipe = {"adapter": ROLE_ADAPTERS.get(role),
              "adapter_version": adapter_version,
              "release_sha256": release_sha256,
              "asset_index_sha256": asset_index_sha256,
              "control_policy": control_policy}
    return validate_recipe(recipe, role=role,
                           execution_release_sha256=release_sha256)


def make_reviewed_strip_adapter(*, project: str, gold_root: str,
                               closures_path: str, control_policy: str,
                               adapter_version: int | None = None) -> Adapter:
    """Forward shared reviewed selections to the language's pure producer."""
    from ..toolkit.assertion_selection import POLICY, reviewed_assertion_selection
    from ..toolkit.strip import StripRefused, load_closures

    if control_policy != POLICY or project not in {"coreshop", "algorand-sdk", "sylius"}:
        _refuse("reviewed assertion targets apply only to CoreShop, Algorand and Sylius.")
    if project in {"coreshop", "sylius"}:
        from ..toolkit.strip import stripped_solution
    else:
        from ..toolkit.strip_java import stripped_solution
    if adapter_version is None:
        adapter_version = 2 if project == "sylius" else 1
    if type(adapter_version) is not int or adapter_version not in (
            (1, 2) if project == "sylius" else (1,)):
        _refuse("unsupported reviewed stripped producer version")
    extra = ({"preserve_sylius_cart_state": True}
             if project == "sylius" and adapter_version == 2 else {})
    closures = load_closures(closures_path)

    def run(task):
        closure = closures.get(task["item_id"])
        if closure is None:
            raise StripRefused(f"REFUSED: no closure for {task['item_id']!r}.")
        selection = reviewed_assertion_selection(closure, policy=control_policy)
        if selection is None:
            return stripped_solution(gold_root, closure, **extra)
        # The Java producer owns this same trailing pure-derivation seam;
        # no shared implementation duplicates its source transformer.
        return stripped_solution(gold_root, closure,
                                 assertion_selection=selection, **extra)

    return Adapter("stripped-gold", run, {
        "gold": gold_root, "closures": closures_path,
        "control_policy": control_policy, "adapter_version": adapter_version})


def _adapter(*, project, role, gold_root, release_gold_root, closures_path,
             feature_root, control_policy, adapter_version=1, go_control_plans_root=None):
    if type(adapter_version) is not int or adapter_version != 1 \
            and not (adapter_version == 2 and role == "stub"
                     and project in {"coreshop", "prestashop", "sylius"}) \
            and not (adapter_version == 3 and role == "stub" and project == "sylius") \
            and not (adapter_version == 2 and role == "stripped_gold"
                     and project == "sylius" and control_policy is not None):
        _refuse(f"unsupported reference adapter version {adapter_version!r} "
                f"for {project}/{role}.")
    if role == "full_gold":
        # The existing gold adapter owns sidecar interpretation. The release
        # layout places its manifest and sidecars in release/gold.
        if os.path.basename(os.path.normpath(release_gold_root)) != "gold":
            _refuse("released gold sidecars must occupy the release/gold tree.")
        return make_gold_adapter(os.path.dirname(release_gold_root), gold_root)
    if project == "coddy-agent":
        from ..go.control_adapter import make_replay_adapter
        return make_replay_adapter(role=role, gold_root=gold_root,
            closures_path=closures_path, go_control_plans_root=go_control_plans_root,
            control_policy=control_policy)
    if role == "stripped_gold" and control_policy is not None:
        return make_reviewed_strip_adapter(
            project=project, gold_root=gold_root, closures_path=closures_path,
            control_policy=control_policy, adapter_version=adapter_version)
    if project == "python-docx":
        from ..toolkit.strip_py import make_strip_adapter
        from ..toolkit.stub_py import make_stub_adapter
    elif project in {"coreshop", "prestashop", "sylius"}:
        from ..toolkit.strip import make_strip_adapter
        from ..toolkit.stub import make_stub_adapter
    elif project == "e-petitions":
        from ..toolkit.strip_rb import make_strip_adapter
        from ..toolkit.stub_rb import make_stub_adapter
    elif project in {"algorand-sdk", "kapua"}:
        from ..toolkit.strip_java import make_strip_adapter
        from ..toolkit.stub_java import make_stub_adapter
    else:
        _refuse(f"unsupported reference project {project!r}.")
    if role == "stripped_gold":
        return make_strip_adapter(gold_root, closures_path)
    if project == "coreshop":
        return make_stub_adapter(closures_path, adapter_version=adapter_version)
    if project in {"prestashop", "sylius"}:
        from ..core.boundary import load_boundary
        from ..core.paths import BENCHMARK_ROOT
        from .repo import behat_project
        project_config = behat_project(load_boundary(os.path.join(
            BENCHMARK_ROOT, "config", f"boundary_{project}.yml"), repo_root=gold_root))
        return make_stub_adapter(closures_path, namespace=project_config.stub_namespace,
            dir_=project_config.stub_dir, adapter_version=adapter_version)
    if project in {"algorand-sdk", "kapua"}:
        if feature_root is None:
            _refuse("Java stub rederivation requires the seed's pinned feature tree.")
        return make_stub_adapter(closures_path, feature_root)
    return make_stub_adapter(closures_path)


def _recorded_source_tag(rows, recipe, role):
    """Bind actual producer/version/tasks/policy before the map index exists.

    The baseline can produce the coverage oracle that determines its map and
    asset index. Therefore its recorded derivation excludes that later index;
    the complete five-field mutation recipe binds the index at collection.
    """
    if "control_policy" not in recipe:
        return None
    derivation = {key: value for key, value in recipe.items()
                  if key != "asset_index_sha256"}
    source_tag = None
    for row in rows:
        recorded = row.get("reference_derivation")
        if recorded != derivation:
            _refuse(f"{role} row {row.get('item_id')!r} does not record "
                    "the supplied reference derivation.")
        # Keep the recorded version's type as well as its value: JSON true
        # and 1 compare equal in Python, but are different producer records.
        validate_recipe({**recorded, "asset_index_sha256": recipe["asset_index_sha256"]}, role=role,
                        execution_release_sha256=recipe["release_sha256"])
        tag = row.get("reference_source_tag")
        if not isinstance(tag, str) or not tag or any(ch.isspace() for ch in tag):
            _refuse(f"{role} row {row.get('item_id')!r} has no single "
                    "nonempty reference source tag.")
        if source_tag is not None and tag != source_tag:
            _refuse(f"{role} rows record different reference source tags.")
        source_tag = tag
    return source_tag


def _validate_state_disposition(recorded, derived):
    if recorded.get("state_preserving_assertion") != derived.get("state_preserving_assertion"):
        _refuse("state-preserving assertion disposition differs from native derivation")
    if derived.get("state_preserving_assertion") is not None and any(
            recorded.get(key) != derived.get(key) for key in
            ("n_then_definitions", "then_definitions", "definition_identity_sha256")):
        _refuse("state-preserving assertion is mislabeled as whole-body removal")


def validate_control_input(*, project: str, role: str, run_path: str,
                           recipe_path: str, execution_release_path: str,
                           gold_root: str, release_gold_root: str,
                           closures_path: str, feature_root: str | None = None,
                           go_control_plans_root: str | None = None) -> dict:
    """Validate one actual role before collection or after relocation.

    Every released task must have an actual passing baseline and exactly the
    files its source recipe derives. The caller joins the recipe's asset
    index and returned hashes to the admitted population and observations.
    """
    from ..toolkit.strip import StripRefused

    with open(recipe_path, encoding="utf-8") as handle:
        recipe = validate_recipe(json.load(handle), role=role,
            execution_release_sha256=mutation_run.sha256_file(execution_release_path))
    with open(execution_release_path, encoding="utf-8") as handle:
        tasks = [json.loads(line) for line in handle if line.strip()]
    ids = [task.get("item_id") for task in tasks]
    if not ids or any(not isinstance(iid, str) or not iid for iid in ids) \
            or len(ids) != len(set(ids)) \
            or any(task.get("project") != project for task in tasks):
        _refuse("reference execution tasks have invalid item/project membership.")
    with open(run_path, encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    files_by_item = passed_solutions(rows)
    source_tag = _recorded_source_tag(rows, recipe, role)
    if set(files_by_item) != set(ids):
        _refuse(f"{role} baseline is not complete and passing: missing "
                f"{sorted(set(ids) - set(files_by_item))[:3]}, unexpected "
                f"{sorted(set(files_by_item) - set(ids))[:3]}.")
    if any(row.get("adapter") != ROLE_ADAPTERS[role] for row in rows):
        _refuse(f"{role} run carries a different or absent adapter stamp.")
    rows_by_id = {row["item_id"]: row for row in rows}
    if set(rows_by_id) != set(ids):
        _refuse(f"{role} run contains rows outside its complete execution tasks.")
    adapter = _adapter(
        project=project, role=role, gold_root=gold_root,
        release_gold_root=release_gold_root, closures_path=closures_path,
        feature_root=feature_root, control_policy=recipe.get("control_policy"),
        adapter_version=recipe["adapter_version"],
        go_control_plans_root=go_control_plans_root)
    derived = {}
    for task in tasks:
        iid = task["item_id"]
        try:
            payload = adapter(task)
        except StripRefused as exc:
            raise ReferenceWorkloadRefused(str(exc)) from exc
        metadata = payload.get("metadata") or {}
        if not payload.get("files") or metadata.get("adapter_error") \
                or metadata.get("error") or metadata.get("strip_refusal"):
            _refuse(f"{role} source derivation refused {iid!r}: {metadata}.")
        derived[iid] = payload["files"]
        recorded = rows_by_id[iid].get("metadata") or {}
        _validate_state_disposition(recorded, metadata)
        if recorded.get("assertion_selection") != metadata.get("assertion_selection"):
            _refuse(f"{role} assertion selection metadata differs for {iid!r}.")
        if project == "coddy-agent" and role == "stripped_gold" and any(
                recorded.get(key) != metadata.get(key) for key in
                ("n_then_definitions", "then_definitions", "definition_identity_sha256")):
            _refuse(f"{role} native selection metadata differs for {iid!r}.")
        if metadata.get("assertion_selection") is not None and any(
                key in recorded for key in ("n_then_definitions", "then_definitions")):
            _refuse(f"reviewed assertion targets are mislabeled as Then definitions for {iid!r}.")
    if derived != files_by_item:
        changed = [iid for iid in ids if derived[iid] != files_by_item[iid]]
        _refuse(f"{role} run files do not rederive from its control sources: {changed[:3]}.")
    result = {"files_by_item": files_by_item, "recipe": recipe,
              "reference_workload_digest": mutation_run.content_digest(recipe),
              "candidate_run_sha256": mutation_run.sha256_file(run_path),
              "generated_tests_sha256": mutation_run.candidate_digest(files_by_item)}
    if "control_policy" in recipe:
        result["reference_source_tag"] = source_tag
    return result


def validate_development_control_input(*, project: str = "prestashop", role: str,
        run_path: str, recipe_path: str, execution_release_path: str,
        gold_root: str, release_gold_root: str, closures_path: str,
        feature_root: str | None = None) -> dict:
    """Authenticate complete PrestaShop baselines, preserving their exclusions.

    PRESTASHOP_SINGLE_OBSERVATION_AMENDMENT keeps every released baseline
    row while executing only its passing solutions. This is source replay,
    not the all-passing admission of the evaluation-scope route above.
    """
    if project != "prestashop":
        _refuse("development control source replay is approved for PrestaShop only.")
    with open(recipe_path, encoding="utf-8") as handle:
        recipe = json.load(handle)
    return _development_control_input(project=project, role=role, run_path=run_path,
        recipe=recipe, execution_release_path=execution_release_path,
        gold_root=gold_root, release_gold_root=release_gold_root,
        closures_path=closures_path, feature_root=feature_root)


def _development_control_input(*, project: str, role: str, run_path: str,
        recipe: dict, execution_release_path: str, gold_root: str,
        release_gold_root: str, closures_path: str, feature_root: str | None = None) -> dict:
    """Pure source replay after the project's caller authenticates its inputs.

    PrestaShop supplies its explicit development recipe. Kapua's fixed-pilot
    reader supplies the recorded derivation and its already authenticated
    fresh-gold source trees; this helper does not admit a population itself.
    """
    from ..data.mutation import classify_outcome

    recipe = validate_recipe(recipe, role=role,
        execution_release_sha256=mutation_run.sha256_file(execution_release_path))
    if set(recipe) != RECIPE_FIELDS | {"control_policy"} or recipe["control_policy"] is not None:
        _refuse("development controls require the recorded default control policy.")
    with open(execution_release_path, encoding="utf-8") as handle:
        tasks = [json.loads(line) for line in handle if line.strip()]
    ids = [task.get("item_id") for task in tasks]
    if not ids or any(not isinstance(iid, str) or not iid for iid in ids) \
            or len(ids) != len(set(ids)) \
            or any(task.get("project") != project for task in tasks):
        _refuse("reference execution tasks have invalid item/project membership.")
    with open(run_path, encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    # The shared projection also refuses duplicate/missing row identities.
    files_by_item = passed_solutions(rows)
    rows_by_id = {row["item_id"]: row for row in rows}
    if set(rows_by_id) != set(ids):
        _refuse("development baseline must contain exactly every released item, including nonpasses.")
    if any(row.get("adapter") != ROLE_ADAPTERS[role] for row in rows):
        _refuse(f"{role} run carries a different or absent adapter stamp.")
    source_tag = _recorded_source_tag(rows, recipe, role)
    adapter = _adapter(project=project, role=role, gold_root=gold_root,
        release_gold_root=release_gold_root, closures_path=closures_path,
        feature_root=feature_root, control_policy=recipe["control_policy"],
        adapter_version=recipe["adapter_version"])
    outcomes = {}
    exclusions = []
    for task in tasks:
        iid = task["item_id"]
        row = rows_by_id[iid]
        outcome = row.get("outcome")
        try:
            classify_outcome("passed", outcome)
        except ValueError as exc:
            _refuse(f"invalid baseline outcome for {iid!r}: {exc}")
        payload = adapter(task)
        metadata = payload.get("metadata") or {}
        if payload.get("files") != row.get("produced_files") \
                or json.dumps(metadata, sort_keys=True) != json.dumps(row.get("metadata"), sort_keys=True):
            _refuse(f"{role} files or metadata do not rederive for {iid!r}.")
        if not payload.get("files") or metadata.get("adapter_error") \
                or metadata.get("error") or metadata.get("strip_refusal"):
            if not (role == "stripped_gold" and metadata.get("strip_refusal") is True
                    and not payload.get("files") and outcome == "no_files_returned"):
                _refuse(f"{role} source derivation is not an authentic stripped refusal for {iid!r}.")
        outcomes[iid] = outcome
        if outcome != "passed":
            if role == "full_gold":
                _refuse(f"full_gold baseline did not pass for {iid!r}.")
            exclusions.append({"item_id": iid, "outcome": outcome,
                "reason": metadata.get("adapter_error") or row.get("error") or None})
    run_sha256 = mutation_run.sha256_file(run_path)
    return {"files_by_item": files_by_item, "recipe": recipe,
        "reference_source_tag": source_tag,
        "candidate_run_sha256": run_sha256,
        "generated_tests_sha256": mutation_run.candidate_digest(files_by_item),
        "reference_workload_digest": mutation_run.content_digest({
            "recipe": recipe, "baseline": {"sha256": run_sha256, "source_tag": source_tag}}),
        "baseline_outcomes": outcomes, "exclusions": exclusions}


def fixture_control_sources(root: str, *, project: str = "python-docx",
                            asset_index_sha256: str = "b" * 64,
                            stripped_control_policy: str | None = None) -> dict:
    """Synthetic real-producer inputs shared by reference integration tests."""
    from pathlib import Path
    from ..data.release import _write_gold_fixture

    if project == "coddy-agent":
        from ..go.assertion_strip_selftest import control_sources_fixture
        return control_sources_fixture(root, asset_index_sha256=asset_index_sha256,
                                       stripped_control_policy=stripped_control_policy)
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    release = root / "release" / "items.jsonl"
    release.parent.mkdir()
    gold = root / "gold"
    feature_root = None
    if project == "python-docx":
        rel, cls = "features/steps/value.py", "value"
        code = ("from behave import given, then\n\n"
                "@given('a value')\ndef setup(context):\n    context.value = 7\n\n"
                "@then('the value matches')\ndef check(context):\n"
                "    assert context.value == 7\n")
        item = {"item_id": "python-docx/features/value.feature:1", "project": project}
    elif project in {"coreshop", "prestashop"}:
        namespace = ("CoreShop\\Behat\\Context\\Domain" if project == "coreshop"
                     else "Tests\\Integration\\Behaviour\\Features\\Context\\Domain")
        rel = ("src/CoreShop/Behat/Context/Domain/ValueContext.php" if project == "coreshop"
               else "tests/Integration/Behaviour/Features/Context/Domain/ValueFeatureContext.php")
        class_name = "ValueContext" if project == "coreshop" else "ValueFeatureContext"
        cls = namespace + "\\" + class_name
        code = ("<?php\nnamespace " + namespace + ";\n"
                "use Behat\\Behat\\Context\\Context;\n"
                "class " + class_name + " implements Context {\n"
                " private $value;\n"
                " /** @Given /^a value$/ */\n"
                " public function setup() { $this->value = 7; }\n"
                " /** @Then /^the value matches$/ */\n"
                " public function check() { assert($this->value === 7); }\n}\n")
        item = {"item_id": "coreshop/features/domain/value.feature:2", "project": project}
        if project == "prestashop":
            item.update(item_id="prestashop/tests/Integration/Behaviour/Features/Scenario/value.feature:2",
                        criterion={"gherkin": "Scenario: value\n Given a value\n Then the value matches\n"},
                        requirement={"background": ""})
    elif project == "algorand-sdk":
        rel = "src/test/java/com/algorand/algosdk/unit/ValueSteps.java"
        cls = "com.algorand.algosdk.unit.ValueSteps"
        code = ("package com.algorand.algosdk.unit;\n"
                "import cucumber.api.java.en.Given;\n"
                "import cucumber.api.java.en.Then;\n"
                "public class ValueSteps {\n private int value;\n"
                ' @Given("a value")\n public void setup() { value = 7; }\n'
                ' @Then("the value matches")\n public void check() { assert value == 7; }\n}\n')
        feature_root = str(root / "feature-source")
        feature = Path(feature_root) / "features/unit/value.feature"
        feature.parent.mkdir(parents=True)
        feature.write_text("Feature: value\n  Scenario: value\n"
                           "    Given a value\n    Then the value matches\n", encoding="utf-8")
        item = {"item_id": "algorand-sdk/features/unit/value.feature:2", "project": project,
                "provenance": {"file_path": "features/unit/value.feature"}}
    else:
        raise ValueError(f"unknown reference fixture project {project!r}")
    source = gold / rel
    source.parent.mkdir(parents=True)
    source.write_text(code, encoding="utf-8")
    items = [item]
    if project == "prestashop":
        items.append({**item, "item_id": item["item_id"].rsplit(":", 1)[0] + ":6",
                      "criterion": {"gherkin": "Scenario: another value\n Given a value\n Then the value matches\n"}})
    release.write_text("".join(json.dumps(task) + "\n" for task in items), encoding="utf-8")
    release_gold = release.parent / "gold"
    _write_gold_fixture(str(release_gold), {task["item_id"]: [rel] for task in items})
    closure = {"item_id": item["item_id"], "files": [rel], "di_fragment": {},
               "steps": [
                   {"keyword": keyword, "text": text, "side": "removable",
                    "definition": {"file": rel, "class": cls, "method": method}}
                   for keyword, text, method in (("Given", "a value", "setup"),
                                                  ("Then", "the value matches", "check"))]}
    if feature_root is not None:
        closure["feature_file"] = "features/unit/value.feature"
        for line, step in enumerate(closure["steps"], 3):
            step["source_line"] = line
    closures = root / "closures.json"
    closures.write_text(json.dumps([{**closure, "item_id": task["item_id"]}
                                    for task in items]), encoding="utf-8")
    result = {"execution_release_path": str(release), "gold_root": str(gold),
              "release_gold_root": str(release_gold), "closures_path": str(closures),
              "feature_root": feature_root, "run_paths": {}, "recipe_paths": {}}
    for role in ROLE_ADAPTERS:
        control_policy = stripped_control_policy if role == "stripped_gold" else None
        adapter = _adapter(project=project, role=role, gold_root=str(gold),
                           release_gold_root=str(release_gold), closures_path=str(closures),
                           feature_root=feature_root, control_policy=control_policy)
        recipe_document = reference_recipe(
            role=role, adapter_version=1, release_sha256=mutation_run.sha256_file(str(release)),
            asset_index_sha256=asset_index_sha256, control_policy=control_policy)
        rows = []
        for task in items:
            payload = adapter(task)
            assert payload["files"] and not (payload.get("metadata") or {}).get("adapter_error"), payload
            rows.append({"item_id": task["item_id"], "adapter": adapter.name, "outcome": "passed",
                   "produced_files": payload["files"], "metadata": payload["metadata"],
                   "reference_derivation": {key: value for key, value in recipe_document.items()
                                             if key != "asset_index_sha256"},
                   "reference_source_tag": "fixture-reviewed-reference"})
        run = root / f"{role}.jsonl"
        run.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        recipe = root / f"{role}.recipe.json"
        recipe.write_text(json.dumps(recipe_document), encoding="utf-8")
        result["run_paths"][role] = str(run)
        result["recipe_paths"][role] = str(recipe)
    return result


def selftest() -> int:
    import shutil
    import tempfile
    from pathlib import Path
    from ..toolkit.assertion_selection import POLICY

    old = {"adapter": "gold", "adapter_version": 1,
           "release_sha256": "a" * 64, "asset_index_sha256": "b" * 64}
    assert validate_recipe(old, role="full_gold", execution_release_sha256="a" * 64) == old
    from dataclasses import replace
    from .fixtures import FIXTURES
    current = FIXTURES["gold"]
    try:
        FIXTURES["gold"] = replace(current, version=99)
        assert validate_recipe(old, role="full_gold", execution_release_sha256="a" * 64) == old
    finally:
        FIXTURES["gold"] = current
    new = reference_recipe(role="full_gold", adapter_version=1,
                           release_sha256="a" * 64, asset_index_sha256="b" * 64)
    assert set(new) == RECIPE_FIELDS | {"control_policy"} and new["control_policy"] is None
    assert mutation_run.content_digest(old) != mutation_run.content_digest(new)
    for bad in (dict(new, adapter_version=2), dict(new, control_policy=POLICY),
                dict(new, release_sha256="c" * 64), dict(new, extra=True)):
        try:
            validate_recipe(bad, role="full_gold", execution_release_sha256="a" * 64)
        except ReferenceWorkloadRefused:
            pass
        else:
            raise AssertionError("invalid recipe admitted")
    disposition = {"state_preserving_assertion": {
        "policy": "r2t.sylius319-cart-state/1", "definition": {"method": "mixed"}},
        "n_then_definitions": 1, "then_definitions": [{"method": "check"}],
        "definition_identity_sha256": "a" * 64}
    _validate_state_disposition(disposition, disposition)
    _validate_state_disposition({}, {})
    for key in disposition:
        for wrong in ({k: v for k, v in disposition.items() if k != key},
                      {**disposition, key: None}):
            try:
                _validate_state_disposition(wrong, disposition)
            except ReferenceWorkloadRefused:
                pass
            else:
                raise AssertionError("missing or altered mixed-method claim admitted")
    try:
        _validate_state_disposition(disposition, {})
    except ReferenceWorkloadRefused:
        pass
    else:
        raise AssertionError("mixed-method claim added to historical producer")
    # Sylius uses the existing PHP v2 producer with its own removable path.
    from ..toolkit.stub import stub_solution
    from ..core.boundary import load_boundary
    from ..core.paths import BENCHMARK_ROOT
    from .repo import behat_project
    with tempfile.TemporaryDirectory() as tmp:
        item = {"item_id": "sylius/features/value.feature:3",
                "scenario": "Scenario: value\n  When I check a value"}
        closure = {"item_id": item["item_id"], "steps": []}
        path = Path(tmp) / "closures.json"
        path.write_text(json.dumps([closure]))
        config = behat_project(load_boundary(os.path.join(
            BENCHMARK_ROOT, "config", "boundary_sylius.yml"), repo_root=tmp))
        for version in (1, 2, 3):
            adapter = _adapter(project="sylius", role="stub", gold_root=tmp,
                release_gold_root=tmp, closures_path=str(path), feature_root=None,
                control_policy=None, adapter_version=version)
            assert adapter(item) == stub_solution(item, closure,
                namespace=config.stub_namespace, dir_=config.stub_dir,
                adapter_version=version)
            assert "namespace Sylius\\Behat\\Context\\Api;" in adapter(item)["files"][0]["code"]
        # The v2 exception stays scoped to PHP; other projects still refuse.
        try:
            _adapter(project="python-docx", role="stub", gold_root=tmp,
                release_gold_root=tmp, closures_path=str(path), feature_root=None,
                control_policy=None, adapter_version=2)
        except ReferenceWorkloadRefused:
            pass
        else:
            raise AssertionError("PHP stub v2 leaked into another framework")
    with tempfile.TemporaryDirectory() as directory:
        original = os.path.join(directory, "producer")
        fixture = fixture_control_sources(original)

        def validate(fixture, role):
            return validate_control_input(
                project="python-docx", role=role, run_path=fixture["run_paths"][role],
                recipe_path=fixture["recipe_paths"][role],
                **{key: fixture[key] for key in (
                    "execution_release_path", "gold_root", "release_gold_root",
                    "closures_path", "feature_root")})

        before = {role: validate(fixture, role) for role in ROLE_ADAPTERS}
        assert len({facts["generated_tests_sha256"] for facts in before.values()}) == 3
        assert {facts["reference_source_tag"] for facts in before.values()} == {"fixture-reviewed-reference"}
        run_path = Path(fixture["run_paths"]["full_gold"])
        recipe_path = Path(fixture["recipe_paths"]["full_gold"])
        run_bytes, recipe_bytes = run_path.read_bytes(), recipe_path.read_bytes()
        original_row = json.loads(run_bytes)
        for field, value in (
                ("reference_derivation", None),
                ("reference_derivation", {**original_row["reference_derivation"], "adapter_version": 2}),
                ("reference_derivation", {**original_row["reference_derivation"], "adapter_version": True}),
                ("reference_derivation", {**original_row["reference_derivation"], "release_sha256": "c" * 64}),
                ("reference_source_tag", None), ("reference_source_tag", "two tags")):
            row = {**original_row, field: value}
            if value is None:
                row.pop(field)
            run_path.write_text(json.dumps(row), encoding="utf-8")
            try:
                validate(fixture, "full_gold")
            except ReferenceWorkloadRefused:
                pass
            else:
                raise AssertionError(f"invalid recorded {field} admitted")
        try:
            _recorded_source_tag([original_row, {**original_row,
                "item_id": "python-docx/features/value.feature:2",
                "reference_source_tag": "different-reviewed-source"}],
                json.loads(recipe_bytes), "full_gold")
        except ReferenceWorkloadRefused as exc:
            assert "different reference source tags" in str(exc)
        else:
            raise AssertionError("mixed recorded source tags admitted")
        historical_row = {key: value for key, value in original_row.items()
                          if key not in {"reference_derivation", "reference_source_tag"}}
        historical_recipe = {key: value for key, value in json.loads(recipe_bytes).items()
                             if key != "control_policy"}
        run_path.write_text(json.dumps(historical_row), encoding="utf-8")
        recipe_path.write_text(json.dumps(historical_recipe), encoding="utf-8")
        historical = validate(fixture, "full_gold")
        assert historical["recipe"] == historical_recipe and "reference_source_tag" not in historical
        run_path.write_bytes(run_bytes)
        recipe_path.write_bytes(recipe_bytes)
        later_index = {**json.loads(recipe_bytes), "asset_index_sha256": "c" * 64}
        recipe_path.write_text(json.dumps(later_index), encoding="utf-8")
        bound = validate(fixture, "full_gold")
        assert bound["candidate_run_sha256"] == before["full_gold"]["candidate_run_sha256"]
        assert bound["reference_workload_digest"] != before["full_gold"]["reference_workload_digest"]
        recipe_path.write_bytes(recipe_bytes)
        moved = os.path.join(directory, "installed")
        shutil.move(original, moved)
        fixture = json.loads(json.dumps(fixture).replace(original, moved))
        assert {role: validate(fixture, role) for role in ROLE_ADAPTERS} == before

        path = Path(fixture["run_paths"]["stripped_gold"])
        original_bytes = path.read_bytes()
        row = json.loads(original_bytes)
        row["metadata"]["assertion_selection"] = {"policy": POLICY, "definitions": []}
        path.write_text(json.dumps(row), encoding="utf-8")
        try:
            validate(fixture, "stripped_gold")
        except ReferenceWorkloadRefused as exc:
            assert "selection metadata" in str(exc)
        else:
            raise AssertionError("invented policy metadata accepted")
        path.write_bytes(original_bytes)
        source = Path(fixture["gold_root"]) / "features/steps/value.py"
        source.write_text(source.read_text().replace("context.value = 7", "context.value = 8"))
        for role in ("full_gold", "stripped_gold"):
            try:
                validate(fixture, role)
            except ReferenceWorkloadRefused as exc:
                assert "do not rederive" in str(exc)
            else:
                raise AssertionError("changed reference source accepted")
    for project, suffix in (("coreshop", ".php"), ("algorand-sdk", ".java")):
        with tempfile.TemporaryDirectory() as directory:
            fixture = fixture_control_sources(directory, project=project)
            digests = set()
            for role in ROLE_ADAPTERS:
                args = {key: fixture[key] for key in (
                    "execution_release_path", "gold_root", "release_gold_root",
                    "closures_path", "feature_root")}
                result = validate_control_input(
                    project=project, role=role, run_path=fixture["run_paths"][role],
                    recipe_path=fixture["recipe_paths"][role], **args)
                assert all(iid.startswith(project + "/") for iid in result["files_by_item"])
                assert all(file["file_path"].endswith(suffix)
                           for files in result["files_by_item"].values() for file in files)
                digests.add(result["generated_tests_sha256"])
            assert len(digests) == 3
            if project == "coreshop":
                # Recorded v1 recipes must still select v1 output even after
                # the ordinary PHP stub factory starts producing version 2.
                run = Path(fixture["run_paths"]["stub"])
                recipe = Path(fixture["recipe_paths"]["stub"])
                row = json.loads(run.read_text())
                assert "?TableNode $table" in row["produced_files"][0]["code"]
                item = json.loads(Path(fixture["execution_release_path"]).read_text())
                payload = _adapter(project=project, role="stub",
                    gold_root=fixture["gold_root"], release_gold_root=fixture["release_gold_root"],
                    closures_path=fixture["closures_path"], feature_root=None,
                    control_policy=None, adapter_version=2)(item)
                row["produced_files"], row["metadata"] = payload["files"], payload["metadata"]
                row["reference_derivation"]["adapter_version"] = 2
                document = json.loads(recipe.read_text())
                document["adapter_version"] = 2
                run.write_text(json.dumps(row) + "\n")
                recipe.write_text(json.dumps(document))
                result = validate_control_input(project=project, role="stub",
                    run_path=str(run), recipe_path=str(recipe), **args)
                assert "TableNode|array|null $table" in next(iter(
                    result["files_by_item"].values()))[0]["code"]
                assert result["recipe"]["adapter_version"] == 2
            else:
                try:
                    _adapter(project=project, role="stub", gold_root=fixture["gold_root"],
                        release_gold_root=fixture["release_gold_root"],
                        closures_path=fixture["closures_path"], feature_root=fixture["feature_root"],
                        control_policy=None, adapter_version=2)
                except ReferenceWorkloadRefused as exc:
                    assert "unsupported reference adapter version" in str(exc)
                else:
                    raise AssertionError("PHP adapter version accepted for another framework")
            if project == "algorand-sdk":
                try:
                    validate_control_input(project=project, role="stub",
                        run_path=fixture["run_paths"]["stub"],
                        recipe_path=fixture["recipe_paths"]["stub"],
                        **{**args, "feature_root": None})
                except ReferenceWorkloadRefused as exc:
                    assert "pinned feature tree" in str(exc)
                else:
                    raise AssertionError("Java stub accepted absent feature bytes")
    with tempfile.TemporaryDirectory() as directory:
        from types import SimpleNamespace
        from .fixtures import _build_stripped_gold
        from ..toolkit.assertion_selection import TARGETS
        item = "coreshop/features/domain/product/product_store_values_inheritance.feature:17"
        file, cls, method = TARGETS[item][0]
        source = Path(directory) / "gold" / file
        source.parent.mkdir(parents=True)
        source.write_text("<?php\nclass ProductContext {\n public function " + method
                          + "() {\n  assert(true);\n }\n}\n", encoding="utf-8")
        closure = {"item_id": item, "files": [file], "steps": [
            {"keyword": "When", "side": "removable", "definition": {
                "file": file, "class": cls, "method": method}}]}
        (Path(directory) / "closures.json").write_text(json.dumps([closure]), encoding="utf-8")
        args = SimpleNamespace(artifacts=directory, gold=str(Path(directory) / "gold"),
                               profile=None, assertion_selection_policy=POLICY)
        adapter = _build_stripped_gold(args, None)
        payload = adapter({"item_id": item})
        assert adapter.name == "stripped-gold" and adapter.config["control_policy"] == POLICY
        assert payload["metadata"]["assertion_selection"]["policy"] == POLICY
        assert "assert(true)" not in payload["files"][0]["code"]
        args.assertion_selection_policy = None
        old = _build_stripped_gold(args, None)({"item_id": item})
        assert old["files"] == [] and old["metadata"]["strip_refusal"]
    _development_selftest()
    _development_cli_selftest()
    print("ALL PASS (reference_workloads)")
    return 0


def _development_selftest():
    import copy
    import tempfile
    from pathlib import Path
    from types import SimpleNamespace
    from . import cli

    def refuses(call, needle):
        try:
            call()
        except (ValueError, SystemExit, mutation_run.MutationAborted) as exc:
            assert needle in str(exc), str(exc)
        else:
            raise AssertionError("invalid development control accepted: " + needle)

    with tempfile.TemporaryDirectory() as directory:
        fixture = fixture_control_sources(directory, project="prestashop")
        args = {key: fixture[key] for key in (
            "execution_release_path", "gold_root", "release_gold_root", "closures_path", "feature_root")}
        def validate(role):
            return validate_development_control_input(role=role,
                run_path=fixture["run_paths"][role], recipe_path=fixture["recipe_paths"][role], **args)
        for role in ROLE_ADAPTERS:
            control = validate(role)
            assert len(control["files_by_item"]) == 2 and not control["exclusions"]

        path = Path(fixture["run_paths"]["stub"])
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[0]["outcome"] = "failed"
        def write(values):
            path.write_text("".join(json.dumps(row) + "\n" for row in values))
        write(rows)
        original = path.read_bytes()
        control = validate("stub")
        assert set(control["files_by_item"]) == {rows[1]["item_id"]}
        assert control["baseline_outcomes"][rows[0]["item_id"]] == "failed"
        assert control["exclusions"] == [{"item_id": rows[0]["item_id"], "outcome": "failed", "reason": None}]
        assert path.read_bytes() == original
        generation_args = dict(role="stub-control", source_tag="new-common-freeze",
            candidate_rows=rows, release_item_ids=control["baseline_outcomes"],
            release_sha256=control["recipe"]["release_sha256"], asset_index_sha256="b" * 64)
        generation = mutation_run.reference_generation_evidence(**generation_args, control=control)
        assert generation["reference_source_tag"] == "new-common-freeze"
        assert control["reference_source_tag"] == "fixture-reviewed-reference"
        assert generation["reference_workload_digest"] == control["reference_workload_digest"]
        refuses(lambda: mutation_run.reference_generation_evidence(**generation_args), "authenticated source replay")
        bad = copy.deepcopy(control)
        bad["recipe"]["adapter_version"] = 2
        refuses(lambda: mutation_run.reference_generation_evidence(**generation_args, control=bad), "reference derivation")
        bad = copy.deepcopy(control)
        bad["baseline_outcomes"][rows[0]["item_id"]] = "passed"
        refuses(lambda: mutation_run.reference_generation_evidence(**generation_args, control=bad), "differs")
        write(rows[1:])
        refuses(lambda: validate("stub"), "exactly every released item")
        write(rows + rows[:1])
        refuses(lambda: validate("stub"), "duplicate")
        bad_rows = copy.deepcopy(rows)
        bad_rows[0]["produced_files"][0]["code"] += "// changed\n"
        write(bad_rows)
        refuses(lambda: validate("stub"), "do not rederive")
        bad_rows = copy.deepcopy(rows)
        bad_rows[0]["metadata"]["n_steps"] = 999
        write(bad_rows)
        refuses(lambda: validate("stub"), "do not rederive")
        write(rows)

        cli_args = SimpleNamespace(reference_scope=None, reference_role="stub-control",
            budgeted_sidecar="authenticated-by-caller.json", candidate=str(path),
            release=fixture["execution_release_path"], reference_recipe=fixture["recipe_paths"]["stub"],
            reference_gold=fixture["gold_root"], reference_release_gold=fixture["release_gold_root"],
            reference_closures=fixture["closures_path"])
        assets = {"asset_project": "prestashop", "asset_index_sha256": "b" * 64}
        cli._refuse_unscoped_evaluation_sources(cli_args, development_reference=True)
        assert cli._development_reference_control(cli_args, assets=assets) == control
        refuses(lambda: cli._refuse_unscoped_evaluation_sources(cli_args), "require --reference-scope")
        refuses(lambda: cli._development_reference_control(cli_args,
            assets={**assets, "asset_index_sha256": "c" * 64}), "authenticated mutation assets")
        cli_args.budgeted_sidecar = None
        refuses(lambda: cli._development_reference_control(cli_args, assets=assets), "--budgeted-sidecar")
        cli_args.budgeted_sidecar = "b100.json"
        cli_args.reference_closures = None
        refuses(lambda: cli._development_reference_control(cli_args, assets=assets), "--reference-closures")
        cli_args.reference_closures = fixture["closures_path"]
        historical_rows = [{key: value for key, value in row.items()
                            if key not in {"reference_derivation", "reference_source_tag"}}
                           for row in rows]
        write(historical_rows)
        refuses(lambda: cli._development_reference_control(cli_args, assets=assets), "reference derivation")
        write(rows)

        # A source-authentic shared-definition refusal remains a baseline
        # exclusion. It is neither a fabricated passed solution nor a mutant.
        closures_path = Path(fixture["closures_path"])
        closures = json.loads(closures_path.read_text())
        closures[0]["steps"][1]["definition"] = closures[0]["steps"][0]["definition"]
        closures_path.write_text(json.dumps(closures))
        tasks = [json.loads(line) for line in Path(fixture["execution_release_path"]).read_text().splitlines()]
        path = Path(fixture["run_paths"]["stripped_gold"])
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        adapter = _adapter(project="prestashop", role="stripped_gold",
            gold_root=fixture["gold_root"], release_gold_root=fixture["release_gold_root"],
            closures_path=fixture["closures_path"], feature_root=None, control_policy=None)
        payload = adapter(tasks[0])
        assert payload["metadata"]["strip_refusal"] and not payload["files"]
        rows[0].update(produced_files=payload["files"], metadata=copy.deepcopy(payload["metadata"]), outcome="no_files_returned")
        write(rows)
        stripped = validate("stripped_gold")
        assert set(stripped["files_by_item"]) == {rows[1]["item_id"]}
        assert "shared with Given/When" in stripped["exclusions"][0]["reason"]
        rows[0]["metadata"]["adapter_error"] += " tampered"
        write(rows)
        refuses(lambda: validate("stripped_gold"), "do not rederive")
        rows[0]["metadata"] = payload["metadata"]
        rows[0]["outcome"] = "passed"
        write(rows)
        refuses(lambda: validate("stripped_gold"), "authentic stripped refusal")
        path = Path(fixture["run_paths"]["full_gold"])
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[0]["outcome"] = "failed"
        write(rows)
        refuses(lambda: validate("full_gold"), "baseline did not pass")
    print("  [PASS] development source replay preserves complete baselines, exclusions and original producer identity")


def _development_cli_selftest():
    import tempfile
    from pathlib import Path
    from types import SimpleNamespace
    from unittest.mock import patch
    from . import cli, worker
    from .evaluation_reference_selftest import fixture_evaluation_inputs
    from ..core.paths import BENCHMARK_ROOT
    from ..data.subsets import budgeted_sample
    from ..toolkit.subset_writer import write_budgeted_sample

    with tempfile.TemporaryDirectory() as directory:
        fixture = fixture_evaluation_inputs(Path(directory) / "native",
                                             project="prestashop", _assets_only=True)
        common = fixture["common_args"]
        controls = fixture["controls"]
        derived, sidecar = write_budgeted_sample(budgeted_sample(
            common["execution_release_path"], common["map_path"],
            common["manifest_path"], 100, 7), str(Path(directory) / "b100"))
        worker_path = fixture["worker_resources"][0]["worker_spec"]
        baseline = Path(controls["run_paths"]["full_gold"])
        original = baseline.read_bytes()
        rows = [json.loads(line) for line in original.splitlines()]
        historical = [{key: value for key, value in row.items()
                       if key not in {"reference_derivation", "reference_source_tag"}}
                      for row in rows]
        baseline.write_text("".join(json.dumps(row) + "\n" for row in historical))
        args = SimpleNamespace(reference_role="full-gold", reference_source_tag="fixture-freeze",
            side="gold", sample=None, sample_seed=cli.MUTATION_SAMPLE_SEED_DEFAULT,
            mutant_limit=None, pair_plan=None, run1_campaign=None, hard_subset=None,
            mutant_of=None, mutant_shard=0, worker=worker_path, worker_pool=[worker_path],
            mutation_validation=common["validation_path"], manifest=common["manifest_path"],
            map=derived, budgeted_sidecar=sidecar, release=common["execution_release_path"],
            candidate=str(baseline), profile=str(Path(BENCHMARK_ROOT) / "config/profile_prestashop.yml"),
            artifacts=directory, gold=controls["gold_root"], seed=fixture["seed"],
            out=str(Path(directory) / "never-executed.jsonl"))
        with patch.object(worker, "preflight", side_effect=AssertionError("runtime probe reached")) as probe, \
                patch.object(worker, "validate_mutation_runtime",
                             side_effect=AssertionError("runtime validation reached")) as runtime:
            def refuses(needle):
                try:
                    cli.cmd_mutation_run(args)
                except SystemExit as exc:
                    assert needle in str(exc), str(exc)
                else:
                    raise AssertionError("legacy PrestaShop control reached execution")
                assert not probe.called and not runtime.called
            # Real native asset readers run; only live runtime boundaries are
            # intercepted. Omitting the new fields cannot select the old door.
            refuses("development reference source replay requires")
            args.reference_recipe = controls["recipe_paths"]["full_gold"]
            args.reference_gold = controls["gold_root"]
            args.reference_release_gold = controls["release_gold_root"]
            args.reference_closures = controls["closures_path"]
            refuses("reference derivation")
            baseline.write_bytes(original)
            try:
                cli.cmd_mutation_run(args)
            except AssertionError as exc:
                assert str(exc) == "runtime probe reached", str(exc)
            else:
                raise AssertionError("authenticated source never reached the runtime boundary")
            assert probe.call_count == 1 and not runtime.called
        assert not Path(args.out).exists()
    print("  [PASS] actual PrestaShop B100 producer requires source replay before any runtime probe")


if __name__ == "__main__":
    raise SystemExit(selftest())
