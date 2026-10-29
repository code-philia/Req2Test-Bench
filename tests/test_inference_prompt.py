"""`req2test.inference.prompt`: the prompt built from a task row alone is the
engine's `c2r` prompt, byte for byte.

Each profile pins the sha256 of its `c2r` prompt over a fixed canonical task
(`prompt_digest.c2r`); the row built from that task must reproduce it.  And
for synthetic items of every project, Kapua's resolved packages and the
coddy-agent Go answer included, the row's prompt equals the engine's
rendering of the same item.  No kit, no Docker.
"""
import hashlib

import pytest
from test_tasks import KAPUA, _rows

from req2test import ENGINE_ROOT, tasks
from req2test.execute import ensure_engine_path
from req2test.inference.prompt import build_prompt

ensure_engine_path()
from r2t.data.profile import load_profile, profile_for_item  # noqa: E402
from r2t.data.prompt import (agent_prompt_for, build_user_prompt,  # noqa: E402
                             canonical_task, environment_facts)
from r2t.data.release import task_view  # noqa: E402
from r2t.go.context import canonical_item  # noqa: E402

PROFILES = sorted((ENGINE_ROOT / "config").glob(
    "profile_*_checked_interfaces_target_hidden_exec.yml"))


def _instance(task: dict) -> dict:
    """The dataset row of an engine item: the same text, in dataset form."""
    req, field = task["requirement"], task["checked_interfaces"]
    return {"instance_id": task["item_id"],
            "feature": {"title": req["feature_title"],
                        "narrative": req.get("narrative"),
                        "background": req.get("background")},
            "scenario": {"gherkin": task["criterion"]["gherkin"]},
            "target_interfaces": field["checked"],
            "target_interfaces_empty_reason": field["empty_reason"]}


def _engine(task: dict, profile) -> str:
    return agent_prompt_for("c2r", profile=profile, trials=0).format(
        task=build_user_prompt(task, profile),
        instructions=environment_facts(profile))


def test_eight_profiles():
    assert len(PROFILES) == 8


@pytest.mark.parametrize("path", PROFILES, ids=lambda p: p.stem)
def test_row_prompt_has_the_frozen_digest(path):
    prof = load_profile(str(path))
    task = canonical_task(prof)
    row = tasks.task_row(prof.project, "th", "1.1", _instance(task), task,
                         prof)
    text = build_prompt(row)
    assert text == _engine(task, prof)
    assert (hashlib.sha256(text.encode()).hexdigest()
            == prof.prompt_digest["c2r"])


#: One feature per project; Kapua's four resolve to four packages.
FEATURES = {
    "algorand-sdk": ["features/unit/v2algodclient_paths.feature"],
    "coddy-agent": ["features/canonical.feature"],
    "coreshop": ["features/cart/adding_product.feature"],
    "e-petitions": ["features/admin/archive.feature"],
    "kapua": list(KAPUA),
    "prestashop": ["tests/Integration/Behaviour/Features/Scenario/Cart/"
                   "cart.feature"],
    "python-docx": ["features/api-open-document.feature"],
    "sylius": ["features/cart/shopping_cart/adding_product.feature"],
}


def _items(prof) -> list:
    items = []
    for n, feature in enumerate(FEATURES[prof.project]):
        line = 1 if prof.project == "coddy-agent" else 10 + n
        item = {"item_id": f"{prof.project}/{feature}:{line}",
                "project": prof.project, "language": prof.language,
                "framework": prof.framework, "task": "criterion_to_test",
                "provenance": {"file_path": feature, "line": line},
                "requirement": {
                    "feature_title": "Shopping",
                    "narrative": "  In order to buy\n  I want a cart",
                    "background": "  Background:\n    Given a store"},
                "criterion": {"gherkin": "  Scenario: s\n    When I add it\n"
                                         "    Then it holds"},
                "checked_interfaces": {"checked": [
                    {"key": ["A\\Cart", "add"],
                     "declaration": "public function add(): void;"},
                    {"key": ["A\\Cart", "total"],
                     "declaration": "public function total(): int;"},
                    {"key": ["b.Store", "open"],
                     "declaration": "def open(self)"}],
                    "empty_reason": None},
                "expected_output": ["step_definitions"]}
        if prof.project == "coddy-agent":
            item.update({k: v for k, v in canonical_item().items()
                         if k in ("files", "go_suite")})
        items.append(item)
    return items


@pytest.mark.parametrize("path", PROFILES, ids=lambda p: p.stem)
def test_row_prompt_equals_the_engine_prompt(path, tmp_path, monkeypatch):
    prof = load_profile(str(path))
    items = _items(prof)
    rows = _rows(tmp_path, monkeypatch, prof.project,
                 path.name.replace("_exec.yml", ".yml"), items,
                 instance=lambda i: _instance(task_view(i)))
    assert len(rows) == len(items)
    for row, item in zip(rows, items):
        task = task_view(item)
        assert "prompt" not in row
        assert build_prompt(row) == _engine(task,
                                            profile_for_item(prof, task))


def test_an_instance_without_target_interfaces():
    prof = load_profile(str(ENGINE_ROOT / "config" /
                            "profile_python_docx_checked_interfaces_"
                            "target_hidden_exec.yml"))
    task = dict(canonical_task(prof), checked_interfaces={
        "checked": [], "empty_reason": "no_action_or_check_call"})
    row = tasks.task_row(prof.project, "th", "1.1", _instance(task), task,
                         prof)
    text = build_prompt(row)
    assert text == _engine(task, prof)
    assert "none identified (no_action_or_check_call)" in text
