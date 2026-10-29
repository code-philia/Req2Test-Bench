"""`req2test tasks`: each row's placement and environment belong to its
instance, and the reference prompt built from the row is the engine's.

The view profile is resolved per instance
(`r2t.data.profile.profile_for_item`): a Kapua instance answers in the
generated-glue package of the test module that runs its feature, and every
other project keeps the view profile.  Synthetic engine items and the
vendored view profiles and boundary: no kit, no Docker.
"""
import json
from types import SimpleNamespace

import pytest

from req2test import ENGINE_ROOT, dataset, tasks
from req2test.inference.prompt import build_prompt

CONFIG = ENGINE_ROOT / "config"

#: The Kapua view profiles' own (account unit runner) root.
ACCOUNT = ("service/account/test/src/test/java/org/eclipse/kapua/service/"
           "account/test/r2t/generated/")
#: Feature -> the generated package its suite builds and scans.
KAPUA = {
    "service/job/test/src/test/resources/features/JobService.feature":
        "service/job/test/src/test/java/org/eclipse/kapua/service/job/test/"
        "r2t/generated/",
    "translator/test/src/test/resources/features/TranslatorUnitTests.feature":
        "translator/test/src/test/java/org/eclipse/kapua/translator/test/"
        "r2t/generated/",
    "qa/integration/src/test/resources/features/authorization/"
    "RoleService.feature":
        "qa/integration/src/test/java/org/eclipse/kapua/integration/service/"
        "authorization/r2t/generated/",
    "service/account/test/src/test/resources/features/AccountService.feature":
        ACCOUNT,
}


def _item(project, language, framework, feature, line):
    return {"item_id": f"{project}/{feature}:{line}", "project": project,
            "language": language, "framework": framework,
            "task": "criterion_to_test",
            "provenance": {"file_path": feature, "line": line},
            "requirement": {"feature_title": "T", "narrative": None,
                            "background": None},
            "criterion": {"gherkin": "  Scenario: s\n    Then it holds"},
            "checked_interfaces": {"checked": [],
                                   "empty_reason": "no_action_or_check_call"},
            "expected_output": ["step_definitions"]}


def _instance(item):
    return {"instance_id": item["item_id"], "feature": {}, "scenario": {}}


def _rows(tmp_path, monkeypatch, project, profile, items, version="1.1",
          instance=_instance):
    """The rows of `items`, the release of a kit whose view profile is
    `profile`, and of their dataset rows `instance(item)`."""
    release = tmp_path / "items.jsonl"
    release.write_text("".join(json.dumps(i) + "\n" for i in items))
    kin = SimpleNamespace(release_items=release,
                          view_profile=lambda view: CONFIG / profile)
    monkeypatch.setattr(tasks, "check_split", lambda *a: None)
    monkeypatch.setattr(tasks, "load_kit",
                        lambda p: SimpleNamespace(version="t"))
    monkeypatch.setattr(tasks, "kit_inputs", lambda kit: kin)
    monkeypatch.setattr(dataset, "iter_instances",
                        lambda *a, **k: [instance(i) for i in items])
    return tasks.task_rows(project, "th", version=version)


def test_kapua_rows_name_the_package_of_the_instance_suite(
        tmp_path, monkeypatch):
    from r2t.bench.harness import Harness, Solution, SourceFile
    from r2t.core.boundary import load_boundary
    items = [_item("kapua", "java", "cucumber", feature, 10 + n)
             for n, feature in enumerate(KAPUA)]
    rows = _rows(tmp_path, monkeypatch, "kapua",
                 "profile_kapua_checked_interfaces_target_hidden.yml", items)
    assert [r["instance_id"] for r in rows] == [i["item_id"] for i in items]
    for row, root in zip(rows, KAPUA.values()):
        pl, prompt = row["placement"], build_prompt(row)
        assert pl["acceptance_mode"] == "directory"
        assert pl["acceptance_root"] == root
        assert pl["placement_hint"] == root + "..."
        assert pl["path"] == f"repo/{root}..."
        assert (f"Repository file to place code under: {root}... "
                f"(item {row['instance_id']})") in prompt
        # Both collection bullets: accepted under, discarded outside.
        assert prompt.count(f"`repo/{root}`") == 2
        assert (ACCOUNT in prompt) == (root == ACCOUNT)

    # `evaluate` writes what the rows ask for: the engine's acceptance rule
    # is the Kapua boundary, which admits every suite's generated package.
    repo = tmp_path / "repo"
    repo.mkdir()
    harness = SimpleNamespace(root=str(repo), boundary=load_boundary(
        str(CONFIG / "boundary_kapua.yml"), repo_root=str(repo)))
    harness._abs = lambda rel: Harness._abs(harness, rel)
    paths = [r["placement"]["acceptance_root"] + "GeneratedSteps.java"
             for r in rows]
    written, rejected = Harness.install_solution(harness, Solution(files=[
        SourceFile(file_path=p, code="class GeneratedSteps {}\n")
        for p in paths]))
    assert rejected == [] and written == paths


def test_other_projects_keep_the_view_profile(tmp_path, monkeypatch):
    items = [_item("python-docx", "python", "behave",
                   f"features/{name}.feature", 3)
             for name in ("api-open-document", "tbl-cell-access")]
    rows = _rows(tmp_path, monkeypatch, "python-docx",
                 "profile_python_docx_checked_interfaces_target_hidden.yml",
                 items)
    assert [r["placement"] for r in rows] == [rows[0]["placement"]] * 2
    assert rows[0]["placement"]["acceptance_root"] == "features/steps/"
    assert rows[0]["placement"]["path"] == "repo/features/steps/..."
    for row in rows:
        assert ("Repository file to place code under: features/steps/... "
                f"(item {row['instance_id']})") in build_prompt(row)


def test_rows_describe_the_runtime(tmp_path, monkeypatch):
    items = [_item("coreshop", "php", "behat", "features/cart.feature", 7)]
    profile = "profile_coreshop_checked_interfaces_target_hidden.yml"
    [red] = _rows(tmp_path, monkeypatch, "coreshop", profile, items)
    assert red["benchmark_version"] == "1.1" and red["view"] == "th"
    assert red["runtime_setup"] == (
        "req2test runtime setup --project coreshop --instance "
        "coreshop/features/cart.feature:7 --workspace WORKSPACE")
    assert "prompt" not in red
    env = red["environment"]
    assert env["run"] == ("`behat-scenario <feature file>:<line>` runs one "
                          "Scenario in this workspace.")
    assert any("It is a provisioned application runtime for the code in "
               "`./repo`" in fact for fact in env["facts"])
    prompt = build_prompt(red)
    assert "cannot be run" not in prompt
    # The run clause, CoreShop's entry-point sentence, and the runtime
    # visibility fact.
    assert ("The scenario can be run from this workspace. `behat-scenario "
            "<feature file>:<line>` runs one Scenario in this workspace."
            in prompt)
    assert ("It is a provisioned application runtime for the code in "
            "`./repo`" in prompt)
    assert red["placement"]["acceptance_root"]


def test_benchmark_1_1_offers_the_target_hidden_view_only(tmp_path,
                                                          monkeypatch):
    kin = SimpleNamespace(view_profile=lambda view: CONFIG / (
        "profile_python_docx_checked_interfaces_target_hidden.yml"))
    assert tasks.view_profile(kin, "th", "1.1") == CONFIG / (
        "profile_python_docx_checked_interfaces_target_hidden_exec.yml")
    with pytest.raises(ValueError, match="offers the th view only"):
        tasks.view_profile(kin, "ah", "1.1")
    with pytest.raises(ValueError, match="unknown benchmark version"):
        tasks.view_profile(kin, "th", "2.1")
