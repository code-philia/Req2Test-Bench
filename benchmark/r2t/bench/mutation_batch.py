"""Closed, feasibility-only planning for mutation scenario batching.

This module implements the part of :file:`MUTATION_BATCHING_EQUIVALENCE_SPEC.md`
that is safe before any framework is batch-enabled: deterministic first-fit
partitioning, ordinary-source collision checks, concrete-instance caps, and an
exact proof that the proposed groups cover the scalar pair set once.

It deliberately does *not* execute a group.  ``ACTIVATION_STATUS`` is closed,
the enabled stack/task registry is empty, and every stack/task is projected to
``r2t.scalar/1`` with all batch campaign-identity fields null.  Consequently a
feasibility group is never authority to stamp ``r2t.batch-bisect/1``.  Stack
registry comparison, reset/isolation, execution, bisection, journals, pilots,
and canonical activation belong to later reviewed changes.

Membership reads only the frozen mutant order, item id, task, exact record
identities/weight, and ordinary-source content addresses.  Classifier inputs
are retained byte-for-byte as canonical JSON and authenticated by the plan,
but are intentionally opaque to the first-fit algorithm.  There is no side,
verdict, duration, retry, or kill field in the closed planner schema.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import re
from typing import Iterable, Optional

from .mutation_run import pair_set_digest


SCHEMA = "r2t.mutation-batch-feasibility-plan/1"
FEASIBILITY_REPORT_SCHEMA = "r2t.mutation-batch-feasibility-report/1"
METHOD = "r2t.batch-first-fit/1"
PURPOSE = "ordinary-path-feasibility-only"
REPORT_PURPOSE = "noncanonical-pilot-admission-only"
ACTIVATION_STATUS = "closed"
SCALAR_POLICY = "r2t.scalar/1"
BATCH_POLICY = "r2t.batch-bisect/1"
MAX_BATCH_MEMBERS = 25
PILOT_SPEEDUP_NUMERATOR = 3
PILOT_SPEEDUP_DENOMINATOR = 2

# There is intentionally no stack/task entry here.  Adding one would be a
# methodology and execution change, not a data edit to this planner.
ENABLED_STACK_TASKS: frozenset[tuple[str, str]] = frozenset()

CLASSIFIER_INPUT_KINDS = (
    "member_local_install",
    "written_rejected_files",
    "parse_compile",
    "index",
    "task",
    "registry",
    "preflight_cache",
)
_CLASSIFIER_ORDER = {name: index
                     for index, name in enumerate(CLASSIFIER_INPUT_KINDS)}
_CACHE_POLICY = "r2t.preflight-cache/1"
_CACHE_STATES = {"not_used", "hit", "miss"}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RAW_MEMBER_FIELDS = {
    "item_id", "task", "scenario_kind", "record_identities", "sources",
    "classifier_inputs",
}
_MEMBER_FIELDS = _RAW_MEMBER_FIELDS | {
    "weight", "sources_sha256", "classifier_inputs_sha256",
}
_RECORD_FIELDS = {"feature_file", "scenario_line"}
_SOURCE_FIELDS = {"declared_path", "installed_path", "bytes", "sha256"}
_RAW_CLASSIFIER_FIELDS = {"classifier", "input"}
_CLASSIFIER_FIELDS = _RAW_CLASSIFIER_FIELDS | {"input_sha256"}
_PAIR_FIELDS = {"item_id", "mutant_id"}
_GROUP_FIELDS = {
    "mutant_id", "ordinal", "planning_status", "scalar_reason", "task",
    "item_ids", "member_weights", "n_members", "n_instances",
    "solution_union_sha256", "group_sha256",
}
_WEIGHT_FIELDS = {"item_id", "instances"}
_PAIR_PROOF_FIELDS = {
    "expected_n", "expected_sha256", "planned_n", "planned_sha256",
    "duplicate_n", "missing_n", "extra_n",
}
_ACTIVATION_FIELDS = {
    "status", "reason", "enabled_stack_tasks", "fallbacks", "reuse_forks",
    "canonical_activation",
}
_FALLBACK_FIELDS = {
    "stack", "task", "execution_policy", "batch_plan_sha256",
    "max_batch_members", "max_batch_instances", "stack_reset_sha256",
    "batch_journal_schema",
}
_PLAN_FIELDS = {
    "schema", "method", "purpose", "stack", "max_batch_members",
    "max_batch_instances", "mutant_order", "expected_pairs",
    "expected_pairs_sha256", "members", "compatibility_groups",
    "pair_union", "activation", "plan_sha256",
}
_REPORT_FIELDS = {
    "schema", "purpose", "feasibility_plan_sha256", "stack",
    "expected_pairs", "expected_pairs_sha256",
    "scalar_framework_launches_min",
    "optimistic_all_pass_framework_launches",
    "full_bisection_framework_launches_max", "ordinary_candidate_groups",
    "scalar_groups", "multi_member_candidate_groups", "singleton_groups",
    "singleton_pair_share_numerator", "singleton_pair_share_denominator",
    "singleton_pair_share_floor_milli", "group_size_histogram",
    "optimistic_speedup_numerator",
    "optimistic_speedup_denominator", "optimistic_speedup_floor_milli",
    "pilot_threshold_numerator", "pilot_threshold_denominator",
    "pilot_decision", "decision_reason", "canonical_execution_policy",
    "batch_plan_sha256", "canonical_activation", "reuse_forks",
    "report_sha256",
}


class BatchPlanRefused(ValueError):
    """The feasibility plan is ambiguous, incomplete, or not closed."""


def _refuse(message: str) -> None:
    raise BatchPlanRefused("REFUSED: " + message)


def canonical_bytes(value) -> bytes:
    """Canonical UTF-8 JSON used by every content address in this module."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        _refuse(f"value is not canonical finite JSON: {exc}")
    raise AssertionError("unreachable")


def content_sha256(value) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _canonical_equal(left, right) -> bool:
    """Compare JSON values without Python's ``True == 1 == 1.0`` aliasing."""
    return canonical_bytes(left) == canonical_bytes(right)


def _exact(value, expected: set[str], where: str) -> None:
    if type(value) is not dict:
        _refuse(f"{where} is not an object")
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        _refuse(f"{where} keys differ; missing={missing}, extra={extra}")


def _text(value, where: str) -> str:
    if type(value) is not str or not value or "\0" in value:
        _refuse(f"{where} must be a non-empty NUL-free string")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        _refuse(f"{where} is not valid UTF-8 text: {exc}")
    return value


def _positive_int(value, where: str) -> int:
    if type(value) is not int or value < 1:
        _refuse(f"{where} must be a positive integer")
    return value


def _sha(value, where: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _refuse(f"{where} must be a full lowercase SHA-256")
    return value


def _path(value, where: str) -> str:
    path = _text(value, where)
    parts = path.split("/")
    if path.startswith("/") or "\\" in path or any(
            part in {"", ".", ".."} for part in parts):
        _refuse(f"{where} must be a canonical relative POSIX path")
    return path


def _walk_json(value, where: str) -> None:
    if value is None or type(value) in {bool, int, str}:
        if type(value) is str:
            try:
                value.encode("utf-8")
            except UnicodeError as exc:
                _refuse(f"{where} contains invalid UTF-8 text: {exc}")
        return
    if type(value) is float:
        if not math.isfinite(value):
            _refuse(f"{where} contains a non-finite float")
        return
    if type(value) is list:
        for index, member in enumerate(value):
            _walk_json(member, f"{where}[{index}]")
        return
    if type(value) is dict:
        for key, member in value.items():
            if type(key) is not str:
                _refuse(f"{where} has a non-string mapping key")
            _walk_json(member, f"{where}.{key}")
        return
    _refuse(f"{where} contains unsupported JSON value {type(value).__name__}")


def _json_copy(value, where: str):
    _walk_json(value, where)
    return json.loads(canonical_bytes(value).decode("utf-8"))


def source_fact(declared_path: str, installed_path: str, payload: bytes) -> dict:
    """Content-address one frozen ordinary source without retaining its bytes."""
    declared = _path(declared_path, "declared source path")
    installed = _path(installed_path, "installed source path")
    if type(payload) is not bytes:
        _refuse("source payload must be bytes")
    return {
        "declared_path": declared,
        "installed_path": installed,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _normalise_source(source: dict, where: str) -> dict:
    _exact(source, _SOURCE_FIELDS, where)
    declared = _path(source["declared_path"], f"{where}.declared_path")
    installed = _path(source["installed_path"], f"{where}.installed_path")
    byte_count = source["bytes"]
    if type(byte_count) is not int or byte_count < 0:
        _refuse(f"{where}.bytes must be a non-negative integer")
    return {
        "declared_path": declared,
        "installed_path": installed,
        "bytes": byte_count,
        "sha256": _sha(source["sha256"], f"{where}.sha256"),
    }


def _normalise_records(records, scenario_kind: str, where: str) -> list[dict]:
    if type(records) is not list or not records:
        _refuse(f"{where} must be a non-empty list")
    out = []
    for index, record in enumerate(records):
        label = f"{where}[{index}]"
        _exact(record, _RECORD_FIELDS, label)
        out.append({
            "feature_file": _path(record["feature_file"],
                                  f"{label}.feature_file"),
            "scenario_line": _positive_int(record["scenario_line"],
                                            f"{label}.scenario_line"),
        })
    out.sort(key=lambda row: (row["feature_file"], row["scenario_line"]))
    identities = [(row["feature_file"], row["scenario_line"]) for row in out]
    if len(set(identities)) != len(identities):
        _refuse(f"{where} repeats a feature-file-plus-line identity")
    if len({row["feature_file"] for row in out}) != 1:
        _refuse(f"{where} spans more than one harness-owned feature file")
    if scenario_kind == "plain" and len(out) != 1:
        _refuse("a plain scenario must have exactly one record identity")
    return out


def _normalise_classifier_inputs(inputs, where: str) -> list[dict]:
    if type(inputs) is not list:
        _refuse(f"{where} must be a list")
    out = []
    seen = set()
    for index, entry in enumerate(inputs):
        label = f"{where}[{index}]"
        _exact(entry, _RAW_CLASSIFIER_FIELDS, label)
        classifier = _text(entry["classifier"], f"{label}.classifier")
        if classifier not in _CLASSIFIER_ORDER:
            _refuse(f"{label}.classifier {classifier!r} is not in the closed "
                    f"classifier vocabulary")
        if classifier in seen:
            _refuse(f"{where} repeats classifier {classifier!r}")
        seen.add(classifier)
        payload = _json_copy(entry["input"], f"{label}.input")
        if type(payload) is not dict:
            _refuse(f"{label}.input must be an object")
        if classifier == "preflight_cache":
            _exact(payload, {"policy", "state"}, f"{label}.input")
            policy = payload["policy"]
            state = payload["state"]
            if policy not in {None, _CACHE_POLICY} or state not in _CACHE_STATES:
                _refuse(f"{label}.input has an unsupported cache policy/state")
            if (policy is None) != (state == "not_used"):
                _refuse(f"{label}.input cache policy/state are inconsistent")
        out.append({
            "classifier": classifier,
            "input": payload,
            "input_sha256": content_sha256(payload),
        })
    missing = [name for name in CLASSIFIER_INPUT_KINDS if name not in seen]
    if missing:
        _refuse(f"{where} is missing classifier inputs {missing}")
    out.sort(key=lambda row: _CLASSIFIER_ORDER[row["classifier"]])
    return out


def _normalise_member(raw: dict, where: str) -> dict:
    _exact(raw, _RAW_MEMBER_FIELDS, where)
    item_id = _text(raw["item_id"], f"{where}.item_id")
    task = _text(raw["task"], f"{where}.task")
    scenario_kind = raw["scenario_kind"]
    if scenario_kind not in {"plain", "outline"}:
        _refuse(f"{where}.scenario_kind must be plain or outline")
    records = _normalise_records(raw["record_identities"], scenario_kind,
                                 f"{where}.record_identities")

    if type(raw["sources"]) is not list:
        _refuse(f"{where}.sources must be a list")
    sources = [_normalise_source(source, f"{where}.sources[{index}]")
               for index, source in enumerate(raw["sources"])]
    sources.sort(key=lambda row: (row["declared_path"], row["installed_path"],
                                  row["sha256"], row["bytes"]))
    declared = [row["declared_path"] for row in sources]
    installed = [row["installed_path"] for row in sources]
    if len(set(declared)) != len(declared):
        _refuse(f"{where}.sources repeats a declared path")
    if len(set(installed)) != len(installed):
        _refuse(f"{where}.sources installs two files at one path")
    for index, left in enumerate(installed):
        for right in installed[index + 1:]:
            if _file_path_overlap(left, right):
                _refuse(f"{where}.sources has a file/ancestor collision: "
                        f"{left!r} and {right!r}")

    classifiers = _normalise_classifier_inputs(
        raw["classifier_inputs"], f"{where}.classifier_inputs")
    return {
        "item_id": item_id,
        "task": task,
        "scenario_kind": scenario_kind,
        "record_identities": records,
        "weight": len(records),
        "sources": sources,
        "sources_sha256": content_sha256(sources),
        "classifier_inputs": classifiers,
        "classifier_inputs_sha256": content_sha256(classifiers),
    }


def _validate_member(member: dict, where: str) -> dict:
    _exact(member, _MEMBER_FIELDS, where)
    raw_classifiers = []
    classifiers = member["classifier_inputs"]
    if type(classifiers) is not list:
        _refuse(f"{where}.classifier_inputs must be a list")
    for index, entry in enumerate(classifiers):
        label = f"{where}.classifier_inputs[{index}]"
        _exact(entry, _CLASSIFIER_FIELDS, label)
        _sha(entry["input_sha256"], f"{label}.input_sha256")
        if content_sha256(entry["input"]) != entry["input_sha256"]:
            _refuse(f"{label}.input_sha256 differs from its canonical input")
        raw_classifiers.append({"classifier": entry["classifier"],
                                "input": entry["input"]})
    normalised = _normalise_member({
        "item_id": member["item_id"],
        "task": member["task"],
        "scenario_kind": member["scenario_kind"],
        "record_identities": member["record_identities"],
        "sources": member["sources"],
        "classifier_inputs": raw_classifiers,
    }, where)
    if not _canonical_equal(normalised, member):
        _refuse(f"{where} derived weight/order/digests are not canonical")
    return normalised


def _normalise_pairs(pairs, where: str) -> list[dict]:
    if type(pairs) is not list or not pairs:
        _refuse(f"{where} must be a non-empty list")
    out = []
    for index, pair in enumerate(pairs):
        label = f"{where}[{index}]"
        _exact(pair, _PAIR_FIELDS, label)
        out.append({
            "item_id": _text(pair["item_id"], f"{label}.item_id"),
            "mutant_id": _text(pair["mutant_id"], f"{label}.mutant_id"),
        })
    identities = [(pair["item_id"], pair["mutant_id"]) for pair in out]
    duplicates = [pair for pair, count in Counter(identities).items()
                  if count > 1]
    if duplicates:
        _refuse(f"{where} contains duplicate pairs: {sorted(duplicates)!r}")
    return out


def _normalise_mutant_order(order, pair_mutants: set[str]) -> list[str]:
    if type(order) is not list or not order:
        _refuse("mutant_order must be a non-empty frozen list")
    out = [_text(value, f"mutant_order[{index}]")
           for index, value in enumerate(order)]
    if len(set(out)) != len(out):
        _refuse("mutant_order repeats a mutant id")
    missing = sorted(pair_mutants - set(out))
    extra = sorted(set(out) - pair_mutants)
    if missing or extra:
        _refuse(f"mutant_order differs from expected pairs; missing={missing}, "
                f"extra={extra}")
    return out


def _source_map(member: dict) -> dict[str, tuple[int, str]]:
    return {source["installed_path"]: (source["bytes"], source["sha256"])
            for source in member["sources"]}


def _file_path_overlap(left: str, right: str) -> bool:
    """Whether two distinct file paths make one filesystem union impossible."""
    return left != right and (left.startswith(right + "/")
                              or right.startswith(left + "/"))


def _path_collision(left: str, right: str) -> bool:
    return left == right or _file_path_overlap(left, right)


def _feature_path(member: dict) -> str:
    # Member validation proves every record identity uses one feature file.
    return member["record_identities"][0]["feature_file"]


def _ordinary_sources_compatible(group: dict, member: dict) -> bool:
    member_sources = _source_map(member)
    member_feature = _feature_path(member)
    if any(_path_collision(member_feature, feature_path)
           for feature_path in group["_feature_paths"]):
        return False
    for path, fact in member_sources.items():
        for prior_path, prior_fact in group["_source_map"].items():
            if path == prior_path:
                if fact != prior_fact:
                    return False
            elif _file_path_overlap(path, prior_path):
                return False
        if any(_path_collision(path, feature_path)
               for feature_path in group["_feature_paths"]):
            return False
    if any(_path_collision(path, member_feature)
           for path in group["_source_map"]):
        return False
    return True


def _validate_feature_paths(members: list[dict]) -> None:
    paths = [_feature_path(member) for member in members]
    if len(set(paths)) != len(paths):
        _refuse("members do not have unique harness-owned feature paths")
    for index, left in enumerate(paths):
        for right in paths[index + 1:]:
            if _file_path_overlap(left, right):
                _refuse("harness-owned feature paths have a file/ancestor "
                        f"collision: {left!r} and {right!r}")


def _group_union_sha256(item_ids: list[str], members_by_id: dict[str, dict]) \
        -> str:
    records = []
    for item_id in item_ids:
        for source in members_by_id[item_id]["sources"]:
            records.append({"item_id": item_id, **source})
    records.sort(key=lambda row: (
        row["item_id"], row["declared_path"], row["installed_path"],
        row["sha256"], row["bytes"]))
    return content_sha256(records)


def _freeze_group(group: dict, ordinal: int,
                  members_by_id: dict[str, dict]) -> dict:
    item_ids = list(group["item_ids"])
    weights = [{"item_id": item_id,
                "instances": members_by_id[item_id]["weight"]}
               for item_id in item_ids]
    out = {
        "mutant_id": group["mutant_id"],
        "ordinal": ordinal,
        "planning_status": group["planning_status"],
        "scalar_reason": group["scalar_reason"],
        "task": group["task"],
        "item_ids": item_ids,
        "member_weights": weights,
        "n_members": len(item_ids),
        "n_instances": sum(row["instances"] for row in weights),
        "solution_union_sha256": _group_union_sha256(item_ids, members_by_id),
    }
    out["group_sha256"] = content_sha256(out)
    return out


def _plan_groups(mutant_order: list[str], expected_pairs: list[dict],
                 members_by_id: dict[str, dict], max_batch_instances: int) \
        -> list[dict]:
    items_by_mutant: dict[str, list[str]] = {mutant: []
                                            for mutant in mutant_order}
    for pair in expected_pairs:
        items_by_mutant[pair["mutant_id"]].append(pair["item_id"])

    frozen = []
    for mutant_id in mutant_order:
        open_groups: list[dict] = []
        for item_id in sorted(items_by_mutant[mutant_id]):
            member = members_by_id[item_id]
            weight = member["weight"]
            feature_path = _feature_path(member)
            if weight > max_batch_instances:
                open_groups.append({
                    "mutant_id": mutant_id,
                    "planning_status": "scalar",
                    "scalar_reason": "member_exceeds_instance_cap",
                    "task": member["task"],
                    "item_ids": [item_id],
                    "n_instances": weight,
                    "_source_map": _source_map(member),
                    "_feature_paths": {feature_path},
                })
                continue
            if member["task"] == "requirement_to_test":
                open_groups.append({
                    "mutant_id": mutant_id,
                    "planning_status": "scalar",
                    "scalar_reason": "requirement_to_test_scalar_v1",
                    "task": member["task"],
                    "item_ids": [item_id],
                    "n_instances": weight,
                    "_source_map": _source_map(member),
                    "_feature_paths": {feature_path},
                })
                continue
            if any(_path_collision(path, feature_path)
                   for path in _source_map(member)):
                open_groups.append({
                    "mutant_id": mutant_id,
                    "planning_status": "scalar",
                    "scalar_reason": "synthetic_feature_path_conflict",
                    "task": member["task"],
                    "item_ids": [item_id],
                    "n_instances": weight,
                    "_source_map": _source_map(member),
                    "_feature_paths": {feature_path},
                })
                continue

            selected: Optional[dict] = None
            for group in open_groups:
                if group["planning_status"] != "ordinary_path_candidate" \
                        or group["task"] != member["task"] \
                        or len(group["item_ids"]) >= MAX_BATCH_MEMBERS \
                        or group["n_instances"] + weight \
                        > max_batch_instances \
                        or not _ordinary_sources_compatible(group, member):
                    continue
                selected = group
                break
            if selected is None:
                selected = {
                    "mutant_id": mutant_id,
                    "planning_status": "ordinary_path_candidate",
                    "scalar_reason": None,
                    "task": member["task"],
                    "item_ids": [],
                    "n_instances": 0,
                    "_source_map": {},
                    "_feature_paths": set(),
                }
                open_groups.append(selected)
            selected["item_ids"].append(item_id)
            selected["n_instances"] += weight
            selected["_source_map"].update(_source_map(member))
            selected["_feature_paths"].add(feature_path)

        for ordinal, group in enumerate(open_groups, 1):
            frozen.append(_freeze_group(group, ordinal, members_by_id))
    return frozen


def _pairs_from_groups(groups: list[dict]) -> list[tuple[str, str]]:
    return [(item_id, group["mutant_id"])
            for group in groups for item_id in group["item_ids"]]


def prove_pair_union(expected_pairs: Iterable[tuple[str, str]],
                     planned_pairs: Iterable[tuple[str, str]]) -> dict:
    """Prove exact set equality and refuse duplicate planned witnesses."""
    expected = list(expected_pairs)
    planned = list(planned_pairs)
    for label, pairs in (("expected", expected), ("planned", planned)):
        for index, pair in enumerate(pairs):
            if type(pair) is not tuple or len(pair) != 2:
                _refuse(f"{label} pair {index} is not an exact 2-tuple")
            _text(pair[0], f"{label} pair {index} item_id")
            _text(pair[1], f"{label} pair {index} mutant_id")
    expected_counts = Counter(expected)
    planned_counts = Counter(planned)
    expected_duplicates = sum(count - 1 for count in expected_counts.values())
    duplicates = sum(count - 1 for count in planned_counts.values())
    if expected_duplicates:
        _refuse(f"expected pair set itself contains {expected_duplicates} "
                "duplicate pair(s)")
    missing = set(expected_counts) - set(planned_counts)
    extra = set(planned_counts) - set(expected_counts)
    proof = {
        "expected_n": len(expected),
        "expected_sha256": pair_set_digest(expected),
        "planned_n": len(planned),
        "planned_sha256": pair_set_digest(planned),
        "duplicate_n": duplicates,
        "missing_n": len(missing),
        "extra_n": len(extra),
    }
    if duplicates or missing or extra or len(planned) != len(expected):
        _refuse("planned pair union is not the exact scalar set: "
                f"duplicates={duplicates}, missing={len(missing)}, "
                f"extra={len(extra)}")
    return proof


def _fallback_activation(stack: str, members: list[dict]) -> dict:
    fallbacks = []
    for task in sorted({member["task"] for member in members}):
        fallbacks.append({
            "stack": stack,
            "task": task,
            "execution_policy": SCALAR_POLICY,
            "batch_plan_sha256": None,
            "max_batch_members": None,
            "max_batch_instances": None,
            "stack_reset_sha256": None,
            "batch_journal_schema": None,
        })
    return {
        "status": ACTIVATION_STATUS,
        "reason": "stack_task_enablement_gate_closed",
        "enabled_stack_tasks": [],
        "fallbacks": fallbacks,
        "reuse_forks": False,
        "canonical_activation": False,
    }


def build_feasibility_plan(*, stack: str, members: list[dict],
                           expected_pairs: list[dict],
                           mutant_order: list[str],
                           max_batch_instances: int,
                           max_batch_members: int = MAX_BATCH_MEMBERS) -> dict:
    """Build the deterministic, non-executable ordinary-path plan.

    No ``side`` parameter exists.  Candidate and gold invoke this separately
    over their own frozen submitted bytes; membership cannot branch on their
    labels or on observations that do not exist in this schema.
    """
    stack = _text(stack, "stack")
    if max_batch_members != MAX_BATCH_MEMBERS or type(max_batch_members) is not int:
        _refuse(f"max_batch_members is pinned to {MAX_BATCH_MEMBERS}")
    max_batch_instances = _positive_int(max_batch_instances,
                                        "max_batch_instances")
    if type(members) is not list or not members:
        _refuse("members must be a non-empty list")
    normalised_members = [_normalise_member(member, f"members[{index}]")
                          for index, member in enumerate(members)]
    normalised_members.sort(key=lambda member: member["item_id"])
    item_ids = [member["item_id"] for member in normalised_members]
    if len(set(item_ids)) != len(item_ids):
        _refuse("members repeat an item_id")
    _validate_feature_paths(normalised_members)

    pairs = _normalise_pairs(expected_pairs, "expected_pairs")
    order = _normalise_mutant_order(
        mutant_order, {pair["mutant_id"] for pair in pairs})
    order_index = {mutant: index for index, mutant in enumerate(order)}
    pairs.sort(key=lambda pair: (order_index[pair["mutant_id"]],
                                 pair["item_id"]))
    pair_items = {pair["item_id"] for pair in pairs}
    missing_members = sorted(pair_items - set(item_ids))
    extra_members = sorted(set(item_ids) - pair_items)
    if missing_members or extra_members:
        _refuse("members differ from the exact expected-pair item set; "
                f"missing={missing_members}, extra={extra_members}")

    by_id = {member["item_id"]: member for member in normalised_members}
    groups = _plan_groups(order, pairs, by_id, max_batch_instances)
    expected_tuples = [(pair["item_id"], pair["mutant_id"]) for pair in pairs]
    pair_proof = prove_pair_union(expected_tuples, _pairs_from_groups(groups))
    expected_sha = pair_set_digest(expected_tuples)
    if pair_proof["expected_sha256"] != expected_sha:
        _refuse("internal expected-pair digest disagreement")

    plan = {
        "schema": SCHEMA,
        "method": METHOD,
        "purpose": PURPOSE,
        "stack": stack,
        "max_batch_members": MAX_BATCH_MEMBERS,
        "max_batch_instances": max_batch_instances,
        "mutant_order": order,
        "expected_pairs": pairs,
        "expected_pairs_sha256": expected_sha,
        "members": normalised_members,
        "compatibility_groups": groups,
        "pair_union": pair_proof,
        "activation": _fallback_activation(stack, normalised_members),
    }
    plan["plan_sha256"] = content_sha256(plan)
    return validate_plan(plan)


def _validate_groups(groups, members_by_id: dict[str, dict]) -> list[dict]:
    if type(groups) is not list or not groups:
        _refuse("compatibility_groups must be a non-empty list")
    out = []
    for index, group in enumerate(groups):
        label = f"compatibility_groups[{index}]"
        _exact(group, _GROUP_FIELDS, label)
        mutant_id = _text(group["mutant_id"], f"{label}.mutant_id")
        ordinal = _positive_int(group["ordinal"], f"{label}.ordinal")
        status = group["planning_status"]
        reason = group["scalar_reason"]
        if status not in {"ordinary_path_candidate", "scalar"}:
            _refuse(f"{label}.planning_status is unsupported")
        if status == "ordinary_path_candidate" and reason is not None:
            _refuse(f"{label} candidate has a scalar reason")
        if status == "scalar" and reason not in {
                "member_exceeds_instance_cap",
                "requirement_to_test_scalar_v1",
                "synthetic_feature_path_conflict"}:
            _refuse(f"{label} scalar reason is unsupported")
        task = _text(group["task"], f"{label}.task")
        item_ids = group["item_ids"]
        if type(item_ids) is not list or not item_ids:
            _refuse(f"{label}.item_ids must be a non-empty list")
        item_ids = [_text(item, f"{label}.item_ids") for item in item_ids]
        if item_ids != sorted(set(item_ids)):
            _refuse(f"{label}.item_ids are not unique lexicographic order")
        if any(item not in members_by_id for item in item_ids):
            _refuse(f"{label} names an unknown member")
        if any(members_by_id[item]["task"] != task for item in item_ids):
            _refuse(f"{label} mixes task semantics")
        if status == "scalar" and len(item_ids) != 1:
            _refuse(f"{label} scalar group is not a singleton")
        if len(item_ids) > MAX_BATCH_MEMBERS:
            _refuse(f"{label} exceeds the {MAX_BATCH_MEMBERS}-member cap")

        weights = group["member_weights"]
        if type(weights) is not list:
            _refuse(f"{label}.member_weights must be a list")
        for number, row in enumerate(weights):
            _exact(row, _WEIGHT_FIELDS, f"{label}.member_weights[{number}]")
        expected_weights = [{"item_id": item,
                             "instances": members_by_id[item]["weight"]}
                            for item in item_ids]
        if not _canonical_equal(weights, expected_weights):
            _refuse(f"{label}.member_weights do not retain member weights")
        if type(group["n_members"]) is not int \
                or group["n_members"] != len(item_ids) \
                or type(group["n_instances"]) is not int \
                or group["n_instances"] != sum(
                    row["instances"] for row in weights):
            _refuse(f"{label} count fields disagree with membership")
        _sha(group["solution_union_sha256"],
             f"{label}.solution_union_sha256")
        if group["solution_union_sha256"] \
                != _group_union_sha256(item_ids, members_by_id):
            _refuse(f"{label}.solution_union_sha256 differs from sources")
        _sha(group["group_sha256"], f"{label}.group_sha256")
        bare = {key: value for key, value in group.items()
                if key != "group_sha256"}
        if content_sha256(bare) != group["group_sha256"]:
            _refuse(f"{label}.group_sha256 differs from group content")
        out.append({
            "mutant_id": mutant_id,
            "ordinal": ordinal,
            "planning_status": status,
            "scalar_reason": reason,
            "task": task,
            "item_ids": item_ids,
            "member_weights": weights,
            "n_members": group["n_members"],
            "n_instances": group["n_instances"],
            "solution_union_sha256": group["solution_union_sha256"],
            "group_sha256": group["group_sha256"],
        })
    return out


def _validate_activation(activation: dict, stack: str,
                         members: list[dict]) -> None:
    _exact(activation, _ACTIVATION_FIELDS, "activation")
    if not _canonical_equal(activation, _fallback_activation(stack, members)):
        _refuse("activation is not the closed all-scalar fallback")
    if ENABLED_STACK_TASKS:
        _refuse("this schema cannot validate a non-empty enablement registry")
    for index, fallback in enumerate(activation["fallbacks"]):
        _exact(fallback, _FALLBACK_FIELDS, f"activation.fallbacks[{index}]")
        if fallback["execution_policy"] != SCALAR_POLICY \
                or any(fallback[key] is not None for key in (
                    "batch_plan_sha256", "max_batch_members",
                    "max_batch_instances", "stack_reset_sha256",
                    "batch_journal_schema")):
            _refuse("scalar fallback silently carries batch identity")


def validate_plan(plan: dict) -> dict:
    """Validate the closed schema, replay first-fit, and re-prove pair union."""
    _exact(plan, _PLAN_FIELDS, "batch feasibility plan")
    if plan["schema"] != SCHEMA or plan["method"] != METHOD \
            or plan["purpose"] != PURPOSE:
        _refuse("unsupported batch feasibility schema/method/purpose")
    stack = _text(plan["stack"], "stack")
    if type(plan["max_batch_members"]) is not int \
            or plan["max_batch_members"] != MAX_BATCH_MEMBERS:
        _refuse(f"max_batch_members is not pinned to {MAX_BATCH_MEMBERS}")
    max_instances = _positive_int(plan["max_batch_instances"],
                                  "max_batch_instances")

    pairs = _normalise_pairs(plan["expected_pairs"], "expected_pairs")
    order = _normalise_mutant_order(
        plan["mutant_order"], {pair["mutant_id"] for pair in pairs})
    order_index = {mutant: index for index, mutant in enumerate(order)}
    canonical_pairs = sorted(pairs, key=lambda pair: (
        order_index[pair["mutant_id"]], pair["item_id"]))
    if not _canonical_equal(plan["expected_pairs"], canonical_pairs):
        _refuse("expected_pairs do not follow frozen mutant/item order")
    pair_tuples = [(pair["item_id"], pair["mutant_id"])
                   for pair in canonical_pairs]
    _sha(plan["expected_pairs_sha256"], "expected_pairs_sha256")
    if plan["expected_pairs_sha256"] != pair_set_digest(pair_tuples):
        _refuse("expected_pairs_sha256 differs from the exact pair set")

    members = plan["members"]
    if type(members) is not list or not members:
        _refuse("members must be a non-empty list")
    normalised_members = [_validate_member(member, f"members[{index}]")
                          for index, member in enumerate(members)]
    if not _canonical_equal(
            members, sorted(normalised_members,
                            key=lambda member: member["item_id"])):
        _refuse("members are not in canonical item-id order")
    member_ids = [member["item_id"] for member in normalised_members]
    if len(set(member_ids)) != len(member_ids):
        _refuse("members repeat an item_id")
    pair_items = {pair["item_id"] for pair in canonical_pairs}
    if pair_items != set(member_ids):
        _refuse("member set differs from expected-pair item set")
    _validate_feature_paths(normalised_members)
    by_id = {member["item_id"]: member for member in normalised_members}

    groups = _validate_groups(plan["compatibility_groups"], by_id)
    expected_groups = _plan_groups(order, canonical_pairs, by_id, max_instances)
    if not _canonical_equal(groups, expected_groups):
        _refuse("compatibility groups are not the deterministic first-fit plan")

    _exact(plan["pair_union"], _PAIR_PROOF_FIELDS, "pair_union")
    proof = prove_pair_union(pair_tuples, _pairs_from_groups(groups))
    if not _canonical_equal(plan["pair_union"], proof):
        _refuse("pair_union proof differs from the exact planned union")
    _validate_activation(plan["activation"], stack, normalised_members)

    _sha(plan["plan_sha256"], "plan_sha256")
    bare = {key: value for key, value in plan.items()
            if key != "plan_sha256"}
    if content_sha256(bare) != plan["plan_sha256"]:
        _refuse("plan_sha256 differs from canonical plan content")
    return _json_copy(plan, "batch feasibility plan")


def _feasibility_report_body(plan: dict) -> dict:
    """Derive the launch-count screen required before a live batch pilot.

    The all-pass count is deliberately optimistic: every compatible group is
    assumed to resolve in its first shared framework process.  It is therefore
    an upper bound on launch-count speedup, not a prediction of wall time.  If
    even that bound is below the preregistered 1.5x threshold, spending a live
    scalar-versus-batched pilot cannot pass the timing gate and is skipped.

    The full-bisection count takes the opposite boundary.  Every multi-member
    candidate group visits its complete binary tree and every singleton uses
    its one allowed infrastructure retry: ``(n - 1) + 2n = 3n - 1`` launches.
    Scalar and already-singleton groups contribute two launches.  Neither
    count reads an outcome, duration, side label, worker, or corpus name.
    """
    closed = validate_plan(plan)
    groups = closed["compatibility_groups"]
    sizes = Counter(group["n_members"] for group in groups)
    ordinary = [group for group in groups
                if group["planning_status"] == "ordinary_path_candidate"]
    scalar = [group for group in groups
              if group["planning_status"] == "scalar"]
    multi = [group for group in ordinary if group["n_members"] > 1]
    singleton_count = sum(group["n_members"] == 1 for group in groups)

    scalar_launches = closed["pair_union"]["expected_n"]
    optimistic_launches = len(groups)
    if optimistic_launches < 1:                           # pragma: no cover
        _refuse("feasibility report has no framework launch group")
    full_bisection_launches = sum(
        3 * group["n_members"] - 1
        if group["planning_status"] == "ordinary_path_candidate"
        and group["n_members"] > 1
        else 2
        for group in groups)

    reaches_threshold = (
        scalar_launches * PILOT_SPEEDUP_DENOMINATOR
        >= optimistic_launches * PILOT_SPEEDUP_NUMERATOR)
    if not multi:
        decision = "skip_live_pilot"
        reason = "no_multi_member_candidate_group"
    elif not reaches_threshold:
        decision = "skip_live_pilot"
        reason = "optimistic_speedup_below_1_5x"
    else:
        decision = "eligible_for_noncanonical_equivalence_pilot"
        reason = "optimistic_speedup_meets_1_5x_screen"

    return {
        "schema": FEASIBILITY_REPORT_SCHEMA,
        "purpose": REPORT_PURPOSE,
        "feasibility_plan_sha256": closed["plan_sha256"],
        "stack": closed["stack"],
        "expected_pairs": scalar_launches,
        "expected_pairs_sha256": closed["pair_union"]["expected_sha256"],
        "scalar_framework_launches_min": scalar_launches,
        "optimistic_all_pass_framework_launches": optimistic_launches,
        "full_bisection_framework_launches_max":
            full_bisection_launches,
        "ordinary_candidate_groups": len(ordinary),
        "scalar_groups": len(scalar),
        "multi_member_candidate_groups": len(multi),
        "singleton_groups": singleton_count,
        "singleton_pair_share_numerator": singleton_count,
        "singleton_pair_share_denominator": scalar_launches,
        "singleton_pair_share_floor_milli":
            singleton_count * 1000 // scalar_launches,
        "group_size_histogram": {
            str(size): sizes[size] for size in sorted(sizes)
        },
        # Keep the exact rational as integers.  The milli field is display
        # only and is rounded down, so it can never make a sub-threshold plan
        # look eligible through floating-point rounding.
        "optimistic_speedup_numerator": scalar_launches,
        "optimistic_speedup_denominator": optimistic_launches,
        "optimistic_speedup_floor_milli":
            scalar_launches * 1000 // optimistic_launches,
        "pilot_threshold_numerator": PILOT_SPEEDUP_NUMERATOR,
        "pilot_threshold_denominator": PILOT_SPEEDUP_DENOMINATOR,
        "pilot_decision": decision,
        "decision_reason": reason,
        # A favourable screen authorises only the separately reviewed live
        # equivalence pilot.  It cannot stamp a batch identity, opt a stack
        # in, or turn reuseForks on.
        "canonical_execution_policy": SCALAR_POLICY,
        "batch_plan_sha256": None,
        "canonical_activation": False,
        "reuse_forks": False,
    }


def build_feasibility_report(plan: dict) -> dict:
    """Build a deterministic, closed go/skip screen for the live pilot."""
    report = _feasibility_report_body(plan)
    report["report_sha256"] = content_sha256(report)
    return validate_feasibility_report(plan, report)


def validate_feasibility_report(plan: dict, report: dict) -> dict:
    """Replay a report and prove that it cannot activate batch execution."""
    _exact(report, _REPORT_FIELDS, "batch feasibility report")
    expected = _feasibility_report_body(plan)
    digest = _sha(report["report_sha256"], "report_sha256")
    bare = {key: value for key, value in report.items()
            if key != "report_sha256"}
    if content_sha256(bare) != digest:
        _refuse("report_sha256 differs from canonical report content")
    if not _canonical_equal(bare, expected):
        _refuse("feasibility report differs from the deterministic replay")
    if report["canonical_execution_policy"] != SCALAR_POLICY \
            or report["batch_plan_sha256"] is not None \
            or report["canonical_activation"] is not False \
            or report["reuse_forks"] is not False:
        _refuse("feasibility report silently activates batch execution")
    return _json_copy(report, "batch feasibility report")


def _fixture_classifiers(tag: str, *, cached: bool = False) -> list[dict]:
    out = []
    for classifier in CLASSIFIER_INPUT_KINDS:
        if classifier == "preflight_cache":
            payload = ({"policy": _CACHE_POLICY, "state": "hit"}
                       if cached else {"policy": None, "state": "not_used"})
        else:
            payload = {"fixture": tag, "classifier": classifier}
        out.append({"classifier": classifier, "input": payload})
    return out


def _fixture_member(item_id: str, *, task: str = "criterion_to_test",
                    rows: tuple[int, ...] = (10,),
                    sources: Optional[list[dict]] = None,
                    classifier_tag: Optional[str] = None) -> dict:
    return {
        "item_id": item_id,
        "task": task,
        "scenario_kind": "plain" if len(rows) == 1 else "outline",
        "record_identities": [
            {"feature_file": f"features/_r2t_batch/{item_id}.feature",
             "scenario_line": line} for line in rows],
        "sources": list(sources or []),
        "classifier_inputs": _fixture_classifiers(classifier_tag or item_id),
    }


def selftest() -> int:
    failures = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        if condition:
            print(f"PASS {name}")
        else:
            print(f"FAIL {name}" + (f": {detail}" if detail else ""))
            failures.append(name)

    def refused(fn, contains: str = "REFUSED") -> bool:
        try:
            fn()
        except BatchPlanRefused as exc:
            return contains in str(exc)
        return False

    same_a = source_fact("answers/a.py", "tests/shared.py", b"same\n")
    same_c = source_fact("answers/c.py", "tests/shared.py", b"same\n")
    # Same length as ``same\n``: the conflict probe therefore needs the
    # content digest and cannot pass by comparing byte counts alone.
    conflict_b = source_fact("answers/b.py", "tests/shared.py", b"diff\n")
    unique_d = source_fact("answers/d.py", "tests/d.py", b"d\n")
    members = [
        _fixture_member("c", sources=[same_c]),
        _fixture_member("a", sources=[same_a]),
        _fixture_member("d", task="another_task", sources=[unique_d]),
        _fixture_member("b", sources=[conflict_b]),
    ]
    pairs = [{"item_id": item, "mutant_id": mutant}
             for mutant in ("m2", "m1") for item in ("d", "c", "b", "a")]
    plan = build_feasibility_plan(
        stack="behat", members=members, expected_pairs=pairs,
        mutant_order=["m2", "m1"], max_batch_instances=8)
    groups_m2 = [group for group in plan["compatibility_groups"]
                 if group["mutant_id"] == "m2"]
    check("first-fit uses frozen mutant order and lexicographic items",
          [group["item_ids"] for group in groups_m2]
          == [["a", "c"], ["b"], ["d"]], str(groups_m2))
    check("repeated installed paths require byte-identical content",
          groups_m2[0]["solution_union_sha256"] !=
          groups_m2[1]["solution_union_sha256"]
          and groups_m2[0]["item_ids"] == ["a", "c"]
          and groups_m2[1]["item_ids"] == ["b"])
    check("different tasks never share a feasibility group",
          groups_m2[2]["task"] == "another_task"
          and groups_m2[2]["item_ids"] == ["d"])

    prefix_members = [
        _fixture_member("parent", sources=[
            source_fact("answers/parent", "pkg", b"file\n")]),
        _fixture_member("child", sources=[
            source_fact("answers/child.py", "pkg/mod.py", b"child\n")]),
    ]
    prefix = build_feasibility_plan(
        stack="behat", members=prefix_members,
        expected_pairs=[{"item_id": item, "mutant_id": "m"}
                        for item in ("parent", "child")],
        mutant_order=["m"], max_batch_instances=25)
    check("file/ancestor installed-path collisions cannot share a group",
          sorted(group["item_ids"]
                 for group in prefix["compatibility_groups"])
          == [["child"], ["parent"]])

    feature_members = [
        _fixture_member("feature-a", sources=[source_fact(
            "answers/a.py", "features/_r2t_batch/feature-b.feature",
            b"overwrite\n")]),
        _fixture_member("feature-b"),
    ]
    feature_plan = build_feasibility_plan(
        stack="behat", members=feature_members,
        expected_pairs=[{"item_id": member["item_id"], "mutant_id": "m"}
                        for member in feature_members],
        mutant_order=["m"], max_batch_instances=25)
    check("a submitted source cannot overwrite another member's synthetic "
          "feature map",
          [group["item_ids"] for group in
           feature_plan["compatibility_groups"]]
          == [["feature-a"], ["feature-b"]])

    own_feature = _fixture_member("feature-own", sources=[source_fact(
        "answers/own.py", "features/_r2t_batch/feature-own.feature",
        b"overwrite\n")])
    own_feature_plan = build_feasibility_plan(
        stack="behat", members=[own_feature],
        expected_pairs=[{"item_id": "feature-own", "mutant_id": "m"}],
        mutant_order=["m"], max_batch_instances=25)
    check("a member that overwrites its own synthetic feature stays scalar",
          own_feature_plan["compatibility_groups"][0]["planning_status"]
          == "scalar"
          and own_feature_plan["compatibility_groups"][0]["scalar_reason"]
          == "synthetic_feature_path_conflict")
    feature_parent = _fixture_member("feature-parent")
    feature_parent["record_identities"][0]["feature_file"] = \
        "features/synthetic.feature"
    feature_child = _fixture_member("feature-child")
    feature_child["record_identities"][0]["feature_file"] = \
        "features/synthetic.feature/nested.feature"
    check("synthetic feature files cannot be ancestors of one another",
          refused(lambda: build_feasibility_plan(
              stack="behat", members=[feature_parent, feature_child],
              expected_pairs=[
                  {"item_id": "feature-parent", "mutant_id": "m"},
                  {"item_id": "feature-child", "mutant_id": "m"}],
              mutant_order=["m"], max_batch_instances=25),
              "feature paths have a file/ancestor collision"))
    ancestor_in_one = _fixture_member("ancestor-in-one", sources=[
        source_fact("answers/root", "pkg", b"file\n"),
        source_fact("answers/child", "pkg/mod.py", b"child\n"),
    ])
    check("one member cannot install a file beneath another installed file",
          refused(lambda: build_feasibility_plan(
              stack="behat", members=[ancestor_in_one],
              expected_pairs=[{"item_id": "ancestor-in-one",
                               "mutant_id": "m"}],
              mutant_order=["m"], max_batch_instances=25),
              "file/ancestor collision"))
    check("exact pair-union proof covers every scalar pair once",
          plan["pair_union"]["expected_n"] == 8
          and plan["pair_union"]["planned_n"] == 8
          and plan["pair_union"]["expected_sha256"]
          == plan["pair_union"]["planned_sha256"]
          and all(plan["pair_union"][key] == 0
                  for key in ("duplicate_n", "missing_n", "extra_n")))

    report = build_feasibility_report(plan)
    check("the pre-pilot screen counts the exact scalar and optimistic "
          "framework launches without reading outcomes",
          report["scalar_framework_launches_min"] == 8
          and report["expected_pairs_sha256"]
          == plan["pair_union"]["expected_sha256"]
          and report["optimistic_all_pass_framework_launches"] == 6
          and report["full_bisection_framework_launches_max"] == 18
          and report["group_size_histogram"] == {"1": 4, "2": 2}
          and report["singleton_pair_share_numerator"] == 4
          and report["singleton_pair_share_denominator"] == 8
          and report["singleton_pair_share_floor_milli"] == 500
          and report["optimistic_speedup_floor_milli"] == 1333)
    check("a plan whose optimistic speedup is below 1.5x automatically "
          "skips the live pilot and retains scalar fallback",
          report["pilot_decision"] == "skip_live_pilot"
          and report["decision_reason"]
          == "optimistic_speedup_below_1_5x"
          and report["canonical_execution_policy"] == SCALAR_POLICY
          and report["batch_plan_sha256"] is None
          and report["canonical_activation"] is False
          and report["reuse_forks"] is False)

    threshold_members = [
        _fixture_member("threshold-a", sources=[source_fact(
            "answers/a.py", "tests/shared.py", b"same\n")]),
        _fixture_member("threshold-b", sources=[source_fact(
            "answers/b.py", "tests/shared.py", b"same\n")]),
        _fixture_member("threshold-c", sources=[source_fact(
            "answers/c.py", "tests/shared.py", b"diff\n")]),
    ]
    threshold_plan = build_feasibility_plan(
        stack="behave", members=threshold_members,
        expected_pairs=[{"item_id": member["item_id"], "mutant_id": "m"}
                        for member in threshold_members],
        mutant_order=["m"], max_batch_instances=25)
    threshold_report = build_feasibility_report(threshold_plan)
    check("the exact 1.5x boundary is eligible only for the noncanonical "
          "equivalence pilot",
          threshold_report["scalar_framework_launches_min"] == 3
          and threshold_report[
              "optimistic_all_pass_framework_launches"] == 2
          and threshold_report["optimistic_speedup_floor_milli"] == 1500
          and threshold_report["pilot_decision"]
          == "eligible_for_noncanonical_equivalence_pilot"
          and threshold_report["canonical_execution_policy"]
          == SCALAR_POLICY
          and threshold_report["canonical_activation"] is False)
    same_membership_other_stack = build_feasibility_plan(
        stack="cucumber", members=threshold_members,
        expected_pairs=[{"item_id": member["item_id"], "mutant_id": "m"}
                        for member in threshold_members],
        mutant_order=["m"], max_batch_instances=25)
    check("the report binds the exact validated plan digest, not only the "
          "same group membership",
          same_membership_other_stack["compatibility_groups"]
          == threshold_plan["compatibility_groups"]
          and refused(lambda: validate_feasibility_report(
              same_membership_other_stack, threshold_report),
              "deterministic replay"))

    only_singletons = build_feasibility_plan(
        stack="behave", members=threshold_members[::2],
        expected_pairs=[{"item_id": member["item_id"], "mutant_id": "m"}
                        for member in threshold_members[::2]],
        mutant_order=["m"], max_batch_instances=25)
    singleton_report = build_feasibility_report(only_singletons)
    check("a plan with no multi-member group skips before a live pilot",
          singleton_report["pilot_decision"] == "skip_live_pilot"
          and singleton_report["decision_reason"]
          == "no_multi_member_candidate_group")

    forged_report = _json_copy(threshold_report, "fixture report")
    forged_report["pilot_decision"] = "skip_live_pilot"
    forged_report["decision_reason"] = "no_multi_member_candidate_group"
    bare_report = {key: value for key, value in forged_report.items()
                   if key != "report_sha256"}
    forged_report["report_sha256"] = content_sha256(bare_report)
    check("re-digesting cannot forge the deterministic pilot decision",
          refused(lambda: validate_feasibility_report(
              threshold_plan, forged_report), "deterministic replay"))

    shuffled = build_feasibility_plan(
        stack="behat", members=list(reversed(members)),
        expected_pairs=list(reversed(pairs)), mutant_order=["m2", "m1"],
        max_batch_instances=8)
    check("input ordering cannot alter the canonical plan",
          shuffled == plan and shuffled["plan_sha256"] == plan["plan_sha256"])

    outline_members = [
        _fixture_member("outline", rows=(21, 22, 23)),
        _fixture_member("plain"),
        _fixture_member("heavy", rows=(31, 32, 33, 34)),
    ]
    outline_pairs = [{"item_id": item, "mutant_id": "m"}
                     for item in ("plain", "outline", "heavy")]
    outline = build_feasibility_plan(
        stack="behave", members=outline_members,
        expected_pairs=outline_pairs, mutant_order=["m"],
        max_batch_instances=3)
    outline_by_id = {member["item_id"]: member for member in outline["members"]}
    heavy = next(group for group in outline["compatibility_groups"]
                 if group["item_ids"] == ["heavy"])
    check("outline weight is the exact number of Examples data rows",
          outline_by_id["outline"]["weight"] == 3
          and outline_by_id["plain"]["weight"] == 1)
    check("a member heavier than the pinned instance cap stays scalar",
          heavy["planning_status"] == "scalar"
          and heavy["scalar_reason"] == "member_exceeds_instance_cap"
          and heavy["n_instances"] == 4)

    many_members = [_fixture_member(f"i{index:02d}") for index in range(26)]
    many_pairs = [{"item_id": member["item_id"], "mutant_id": "m"}
                  for member in many_members]
    capped = build_feasibility_plan(
        stack="cucumber", members=many_members, expected_pairs=many_pairs,
        mutant_order=["m"], max_batch_instances=100)
    check("first-fit never exceeds the pinned 25-member cap",
          [group["n_members"] for group in capped["compatibility_groups"]]
          == [25, 1])

    req = build_feasibility_plan(
        stack="behat",
        members=[_fixture_member("req", task="requirement_to_test")],
        expected_pairs=[{"item_id": "req", "mutant_id": "m"}],
        mutant_order=["m"], max_batch_instances=25)
    check("requirement_to_test remains scalar in feasibility version 1",
          req["compatibility_groups"][0]["planning_status"] == "scalar"
          and req["compatibility_groups"][0]["scalar_reason"]
          == "requirement_to_test_scalar_v1")

    check("missing and duplicate planned pairs fail the exact union proof",
          refused(lambda: prove_pair_union(
              [("a", "m"), ("b", "m")], [("a", "m")]), "missing=1")
          and refused(lambda: prove_pair_union(
              [("a", "m")], [("a", "m"), ("a", "m")]),
              "duplicates=1"))
    duplicate_pairs = pairs + [dict(pairs[0])]
    check("duplicate expected pairs fail before planning",
          refused(lambda: build_feasibility_plan(
              stack="behat", members=members,
              expected_pairs=duplicate_pairs,
              mutant_order=["m2", "m1"], max_batch_instances=8),
              "duplicate pairs"))

    altered_members = list(members)
    altered_members[0] = _fixture_member(
        "c", sources=[source_fact("answers/c.py", "tests/shared.py",
                                  b"changed\n")])
    altered = build_feasibility_plan(
        stack="behat", members=altered_members, expected_pairs=pairs,
        mutant_order=["m2", "m1"], max_batch_instances=8)
    check("altered submitted bytes alter the plan digest",
          altered["plan_sha256"] != plan["plan_sha256"])

    classifier_changed_members = list(members)
    classifier_changed_members[0] = _fixture_member(
        "c", sources=[same_c], classifier_tag="different-static-input")
    classifier_changed = build_feasibility_plan(
        stack="behat", members=classifier_changed_members,
        expected_pairs=pairs, mutant_order=["m2", "m1"],
        max_batch_instances=8)
    memberships = [(group["mutant_id"], group["item_ids"])
                   for group in plan["compatibility_groups"]]
    memberships_changed = [(group["mutant_id"], group["item_ids"])
                           for group in classifier_changed["compatibility_groups"]]
    check("classifier inputs are retained but cannot affect membership",
          memberships_changed == memberships
          and classifier_changed["plan_sha256"] != plan["plan_sha256"]
          and classifier_changed["members"][2]["classifier_inputs_sha256"]
          != plan["members"][2]["classifier_inputs_sha256"])

    fallback = capped["activation"]
    check("every unsupported stack/task has an explicit scalar fallback",
          fallback["status"] == "closed"
          and fallback["enabled_stack_tasks"] == []
          and fallback["fallbacks"]
          and all(row["execution_policy"] == SCALAR_POLICY
                  for row in fallback["fallbacks"]))
    check("scalar fallback carries no silent batch identity or reuseForks",
          fallback["reuse_forks"] is False
          and fallback["canonical_activation"] is False
          and all(all(row[key] is None for key in (
              "batch_plan_sha256", "max_batch_members",
              "max_batch_instances", "stack_reset_sha256",
              "batch_journal_schema")) for row in fallback["fallbacks"]))

    tampered = _json_copy(plan, "fixture plan")
    tampered["activation"]["fallbacks"][0]["execution_policy"] = BATCH_POLICY
    bare = {key: value for key, value in tampered.items()
            if key != "plan_sha256"}
    tampered["plan_sha256"] = content_sha256(bare)
    check("even a re-digested plan cannot silently activate batching",
          refused(lambda: validate_plan(tampered), "all-scalar fallback"))

    typed_weight = _json_copy(plan, "fixture plan")
    typed_weight["members"][0]["weight"] = True
    bare = {key: value for key, value in typed_weight.items()
            if key != "plan_sha256"}
    typed_weight["plan_sha256"] = content_sha256(bare)
    typed_float_weight = _json_copy(plan, "fixture plan")
    typed_float_weight["members"][0]["weight"] = 1.0
    bare = {key: value for key, value in typed_float_weight.items()
            if key != "plan_sha256"}
    typed_float_weight["plan_sha256"] = content_sha256(bare)
    typed_proof = _json_copy(plan, "fixture plan")
    typed_proof["pair_union"]["duplicate_n"] = False
    bare = {key: value for key, value in typed_proof.items()
            if key != "plan_sha256"}
    typed_proof["plan_sha256"] = content_sha256(bare)
    typed_activation = _json_copy(plan, "fixture plan")
    typed_activation["activation"]["reuse_forks"] = 0
    typed_activation["activation"]["canonical_activation"] = 0
    bare = {key: value for key, value in typed_activation.items()
            if key != "plan_sha256"}
    typed_activation["plan_sha256"] = content_sha256(bare)
    check("re-digested bool/int/float scalar aliases fail the closed schema",
          refused(lambda: validate_plan(typed_weight), "not canonical")
          and refused(lambda: validate_plan(typed_float_weight),
                      "not canonical")
          and refused(lambda: validate_plan(typed_proof), "pair_union")
          and refused(lambda: validate_plan(typed_activation),
                      "all-scalar fallback"))
    unknown = _json_copy(plan, "fixture plan")
    unknown["side"] = "candidate"
    check("the closed plan has no side-label field",
          refused(lambda: validate_plan(unknown), "extra=['side']"))
    with_verdict = dict(members[0], verdict="passed")
    with_duration = dict(members[0], duration_seconds=1.5)
    check("member schema admits no observed verdict or duration field",
          refused(lambda: build_feasibility_plan(
              stack="behat", members=[with_verdict] + members[1:],
              expected_pairs=pairs, mutant_order=["m2", "m1"],
              max_batch_instances=8), "extra=['verdict']")
          and refused(lambda: build_feasibility_plan(
              stack="behat", members=[with_duration] + members[1:],
              expected_pairs=pairs, mutant_order=["m2", "m1"],
              max_batch_instances=8), "extra=['duration_seconds']"))

    bad_digest = _json_copy(plan, "fixture plan")
    bad_digest["max_batch_instances"] = 9
    check("altering a plan without re-digesting is refused",
          refused(lambda: validate_plan(bad_digest)))
    reordered = _json_copy(plan, "fixture plan")
    reordered["compatibility_groups"][0], reordered["compatibility_groups"][1] = (
        reordered["compatibility_groups"][1],
        reordered["compatibility_groups"][0])
    bare = {key: value for key, value in reordered.items()
            if key != "plan_sha256"}
    reordered["plan_sha256"] = content_sha256(bare)
    check("re-digesting cannot replace deterministic first-fit ordering",
          refused(lambda: validate_plan(reordered), "deterministic first-fit"))
    check("non-positive instance caps and unpinned member caps are refused",
          refused(lambda: build_feasibility_plan(
              stack="behat", members=members, expected_pairs=pairs,
              mutant_order=["m2", "m1"], max_batch_instances=0))
          and refused(lambda: build_feasibility_plan(
              stack="behat", members=members, expected_pairs=pairs,
              mutant_order=["m2", "m1"], max_batch_instances=8,
              max_batch_members=24), "pinned to 25"))

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(selftest())
