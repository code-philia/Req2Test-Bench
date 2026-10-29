"""Reviewed e-petitions scenario selection (Track B D15 / plan §5.1).

Extraction remains a complete inventory. Only this project's matcher and
closure generation select the non-JavaScript, non-WIP subset. This is not a
framework-wide default, nor source-visibility or release admission.
"""
from __future__ import annotations

PROJECT = "e-petitions"
PINNED_COMMIT = "8968fc9c24a205094132c884c18982fec8ccbb5f"
# Order defines the disjoint census: JS first, then non-JS WIP.
EXCLUDED_TAGS = ("@javascript", "@wip")
EXPECTED_SCENARIOS = {"eligible": 206, "javascript": 29, "wip": 72}


def matcher_tag_args(project: str | None) -> list[str]:
    if project != PROJECT:
        return []
    return ["--tags", " and ".join(f"not {tag}" for tag in EXCLUDED_TAGS)]


def exclusion_reason(project: str, feature, scenario) -> str | None:
    if project != PROJECT:
        return None
    tags = set(feature.tags) | set(scenario.tags)
    return next((tag[1:] for tag in EXCLUDED_TAGS if tag in tags), None)


def partition(walked, project: str):
    """Return eligible source tuples and explicit item-id exclusion reasons."""
    eligible, excluded = [], {}
    seen = set()
    for entry in walked:
        item_id, feature, scenario = entry
        if item_id in seen:
            raise ValueError(f"duplicate source criterion: {item_id}")
        seen.add(item_id)
        reason = exclusion_reason(project, feature, scenario)
        if reason:
            excluded[item_id] = reason
        else:
            eligible.append(entry)
    return eligible, excluded


def selftest() -> int:
    import importlib.util
    from pathlib import Path
    from ..core.gherkin import parse_feature_file
    feature = parse_feature_file("/fixture/f.feature", """@wip
Feature: F
  @javascript
  Scenario: Both
    Given a value
  Scenario: WIP only
    Given a value
""")
    walked = [(f"e-petitions/f.feature:{s.line}", feature, s) for s in feature.scenarios]
    eligible, excluded = partition(walked, PROJECT)
    assert not eligible and list(excluded.values()) == ["javascript", "wip"]
    assert partition(walked, "another-ruby-project") == (walked, {})
    assert matcher_tag_args(PROJECT) == ["--tags", "not @javascript and not @wip"]
    assert matcher_tag_args(None) == []
    try:
        partition(walked + walked, PROJECT)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate criteria accepted")
    scripts = Path(__file__).resolve().parents[2] / "scripts"
    for name in ("gate_s2_boundary_e_petitions", "gate_s3_closures_ruby"):
        spec = importlib.util.spec_from_file_location(name, scripts / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.selftest()
    print("[PASS] project-local inherited tag selection, exact boundary and closure gate refusals")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())
