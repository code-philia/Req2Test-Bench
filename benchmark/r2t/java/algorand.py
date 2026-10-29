"""Algorand's source/runtime feature identity and pre-execution policy."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


PROJECT = "algorand-sdk"
OFFLINE_SOURCE = "features/unit/offline.feature"
UNIT_SOURCE = "features/unit/"
INTEGRATION_SOURCE = "features/integration/"
UNIT_WORKSPACE = "src/test/resources/com/algorand/algosdk/unit/"
INTEGRATION_WORKSPACE = \
    "src/test/resources/com/algorand/algosdk/integration/"
OFFLINE_WORKSPACE = INTEGRATION_WORKSPACE + "offline.feature"

BENCHMARK = Path(__file__).resolve().parents[2]
DEFAULT_ITEMS = BENCHMARK / "items.jsonl"
EXCLUSIONS = BENCHMARK / "config" / "exclusions_algorand.yml"

EXCLUSION_REASON = "needs_live_algod"
EXCLUSION_CAPTION = \
    "51 live-algod integration criteria are excluded before execution."
EXCLUDED_IDS_SHA256 = \
    "e1de142da6695f02a4634f1704632366d6d156aac999493598a12583d917bd00"


def source_to_workspace_feature(path: str) -> str:
    """Map the testing repository's feature identity into the composition."""
    if path == OFFLINE_SOURCE:
        return OFFLINE_WORKSPACE
    if path.startswith(UNIT_SOURCE):
        return UNIT_WORKSPACE + path[len(UNIT_SOURCE):]
    if path.startswith(INTEGRATION_SOURCE):
        return INTEGRATION_WORKSPACE + path[len(INTEGRATION_SOURCE):]
    raise ValueError(f"unexpected Algorand source feature path: {path}")


def runtime_feature_path(project: str, path: str) -> str:
    """Resolve a source identity to bytes in this project's workspace."""
    return source_to_workspace_feature(path) if project == PROJECT else path


def workspace_to_source_feature(path: str) -> str:
    """Recover the testing repository identity from a composed feature."""
    if path == OFFLINE_WORKSPACE:
        return OFFLINE_SOURCE
    if path.startswith(UNIT_WORKSPACE):
        return UNIT_SOURCE + path[len(UNIT_WORKSPACE):]
    if path.startswith(INTEGRATION_WORKSPACE):
        return INTEGRATION_SOURCE + path[len(INTEGRATION_WORKSPACE):]
    raise ValueError(f"unexpected Algorand workspace feature path: {path}")


def load_exclusion_policy(items_path: str | Path = DEFAULT_ITEMS) -> dict:
    """Load the exact 51-ID policy after authenticating its 210 source rows."""
    document = yaml.safe_load(EXCLUSIONS.read_text(encoding="utf-8"))
    rows: list[dict] = []
    source = bytearray()
    with open(items_path, "rb") as handle:
        for raw in handle:
            item = json.loads(raw)
            if item.get("project") == PROJECT:
                source.extend(raw)
                rows.append(item)

    source_identity = {
        "count": len(rows),
        "bytes": len(source),
        "sha256": hashlib.sha256(source).hexdigest(),
    }
    live_ids = sorted(
        item["item_id"] for item in rows
        if item.get("task") == "criterion_to_test"
        and item["provenance"]["file_path"].startswith(INTEGRATION_SOURCE)
    )
    ids_raw = ("\n".join(live_ids) + "\n").encode("utf-8")
    expected = {
        "version": 1,
        "project": PROJECT,
        "source_items": source_identity,
        "reason": EXCLUSION_REASON,
        "caption": EXCLUSION_CAPTION,
        "item_ids": live_ids,
        "sorted_item_ids_sha256": hashlib.sha256(ids_raw).hexdigest(),
    }
    if document != expected or len(live_ids) != 51 \
            or expected["sorted_item_ids_sha256"] != EXCLUDED_IDS_SHA256:
        raise ValueError(
            "Algorand exclusions do not match the exact source item set")
    return document


def admit_before_contact(values, *, item_id, items_path: str | Path = DEFAULT_ITEMS,
                         requested=()):
    """Remove the exact live-algod IDs before invoking a downstream actor.

    ``values`` is materialised only after the policy has authenticated the
    complete 210-row source.  Callers pass a projection rather than adapting
    their rows to one shared shape; closure tuples, release rows, and item IDs
    can therefore all use the same pre-contact boundary.
    """
    policy = load_exclusion_policy(items_path)
    blocked = set(policy["item_ids"])
    selected = sorted(blocked.intersection(requested))
    if selected:
        raise SystemExit(
            f"REFUSED: requested item {selected[0]} is excluded before "
            f"contact ({policy['reason']}): {policy['caption']}")
    admitted = [value for value in values if item_id(value) not in blocked]
    return admitted, policy
