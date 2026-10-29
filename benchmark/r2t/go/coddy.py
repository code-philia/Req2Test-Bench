"""Pinned coddy-agent candidate inventory, independent of registry witnesses.

GO_STACK_SPEC section 2 owns these pre-closure dispositions. This inventory
is not admission: stability, quality and anti-vacuity can exclude candidates
later. Requirements remain raw extraction evidence outside this criterion set.
"""
from __future__ import annotations

from pathlib import Path
import subprocess

from ..core.gherkin import parse_feature_file

PROJECT = "coddy-agent"
PINNED_COMMIT = "5fadd23573bafff8a39baa4c19b01af1878e0ac2"
FEATURE_EXCLUSIONS = {
    "features/spawn_agent_card.feature": "excluded_ui_build",
    "features/update_windows.feature": "excluded_windows_platform",
    "features/acp_session_integration.feature": "excluded_acp_child_session",
}
LINUX_FILTERED = ("features/prompt_attachment_encoding.feature", 82)


class CensusRefused(ValueError):
    pass


def _disposition(key):
    if key == LINUX_FILTERED:
        return "upstream_linux_tag_filtered"
    return FEATURE_EXCLUSIONS.get(key[0])


def candidate_census(source_root) -> dict:
    """Rediscover every original header at the clean full pin, never a copy."""
    root = Path(source_root).resolve()

    def git(*args):
        try:
            return subprocess.check_output(
                ["git", "--no-optional-locks", "-C", str(root), *args],
                stderr=subprocess.PIPE)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise CensusRefused("cannot read the pinned Go source Git identity") from exc

    if git("rev-parse", "HEAD").decode().strip() != PINNED_COMMIT:
        raise CensusRefused("Go candidate census requires the exact source pin")
    if git("rev-parse", "--is-shallow-repository").strip() != b"false":
        raise CensusRefused("Go candidate census requires a full clone")
    if (git("status", "--porcelain=v1", "--untracked-files=all")
            or git("ls-files", "--others", "--ignored", "--exclude-standard")):
        raise CensusRefused("Go candidate census requires unchanged pinned source bytes")
    paths = sorted(path.decode("utf-8") for path in
                   git("ls-tree", "-rz", "--name-only", PINNED_COMMIT,
                       "--", "features").split(b"\0")
                   if path.endswith(b".feature"))
    keys, outlines = [], 0
    for rel in paths:
        feature = parse_feature_file(str(root / rel))
        for scenario in feature.scenarios:
            keys.append((rel, scenario.line))
            outlines += scenario.kind in ("Scenario Outline", "Scenario Template")
    if (len(paths), len(keys), len(set(keys)), outlines) != (61, 293, 293, 4):
        raise CensusRefused("source headers disagree with the reviewed Go census")
    counts = {path: sum(key[0] == path for key in keys) for path in FEATURE_EXCLUSIONS}
    if counts != {"features/spawn_agent_card.feature": 1,
                  "features/update_windows.feature": 4,
                  "features/acp_session_integration.feature": 5} \
            or LINUX_FILTERED not in keys:
        raise CensusRefused("declared Go exclusion/header positions changed")
    selected = tuple(key for key in keys if _disposition(key) is None)
    if len(selected) != 282:
        raise CensusRefused("Go candidate set differs from the reviewed 282 headers")
    return {
        "source_commit": PINNED_COMMIT,
        "all_criteria": tuple(keys), "candidate_keys": selected,
        "excluded": {f"{PROJECT}/{path}:{line}": _disposition((path, line))
                     for path, line in keys if _disposition((path, line))},
        "feature_count": len(paths), "criterion_count": len(keys),
        "outline_count": outlines,
    }


def _item_keys(items):
    found = {}
    for item in items:
        if (item.get("project") != PROJECT or item.get("task") != "criterion_to_test"
                or item.get("language") != "go" or item.get("framework") != "godog"):
            raise CensusRefused("candidate set must contain only coddy-agent Go criteria")
        provenance = item.get("provenance") or {}
        path, line = provenance.get("file_path"), provenance.get("line")
        if not isinstance(path, str) or type(line) is not int or line <= 0:
            raise CensusRefused("candidate lacks original feature/header identity")
        key = path, line
        if item.get("item_id") != f"{PROJECT}/{path}:{line}" or key in found:
            raise CensusRefused("candidate identity is inconsistent or duplicated")
        found[key] = item
    return found


def select_candidates(raw_items, census):
    """Select reviewed keys only after proving complete raw criterion coverage."""
    criteria = [item for item in raw_items
                if item.get("project") == PROJECT
                and item.get("task") == "criterion_to_test"]
    found = _item_keys(criteria)
    if set(found) != set(census["all_criteria"]):
        raise CensusRefused("raw extraction does not cover every original Go criterion")
    return [found[key] for key in census["candidate_keys"]]


def assert_candidate_items(items, census):
    """Refuse missing, extra, duplicate or contextless pre-closure candidates."""
    from .context import validate_context
    found = _item_keys(items)
    wanted = set(census["candidate_keys"])
    if set(found) != wanted:
        raise CensusRefused(
            f"Go candidate set mismatch: missing={sorted(wanted - set(found))}, "
            f"unexpected={sorted(set(found) - wanted)}")
    for item in found.values():
        validate_context(item)


def selftest():
    from copy import deepcopy
    from .context import canonical_item
    item = canonical_item()
    key = (item["go_suite"]["feature_path"], item["go_suite"]["scenario_line"])
    census = {"candidate_keys": (key,), "all_criteria": (key,)}
    assert_candidate_items([item], census)
    assert select_candidates([item], census) == [item]
    bad = deepcopy(item)
    bad["item_id"] += "-wrong"
    missing_context = deepcopy(item)
    del missing_context["go_suite"]
    for label, action in (
            ("missing candidate", lambda: assert_candidate_items([], census)),
            ("duplicate candidate", lambda: assert_candidate_items([item, item], census)),
            ("wrong identity", lambda: assert_candidate_items([bad], census)),
            ("missing context", lambda: assert_candidate_items([missing_context], census)),
            ("partial raw inventory", lambda: select_candidates([], census))):
        try:
            action()
        except ValueError:
            print("  [PASS] " + label + " refuses")
        else:
            raise AssertionError(label + " was accepted")
    assert _disposition(LINUX_FILTERED) == "upstream_linux_tag_filtered"
    assert _disposition((LINUX_FILTERED[0], 2)) is None
    print("ALL PASS (Go candidate inventory)")
    return 0
