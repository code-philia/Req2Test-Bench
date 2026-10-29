"""The Slice-3 evidence readers: the frozen views, the six-observation gate,
the execution binding, the job derivation and the bound-observation reader.

Pure over documents and preserved bytes -- nothing here launches, pays or
talks to Docker.  It is the half of the Slice-3 coordinator
(`agents/slice3_eval.py`) that the algorand bundle's fetch-and-validate
route (`toolkit/algorand_bundle.py`, reached from `bundle fetch`) and the
test-quality join (`slice3_test_quality`) read, and it is benchmark-owned so
a checkout without the agent component can still fetch and validate the
bundle.  The coordinator imports every name back from here, so the digests
and refusals it issues are byte-for-byte the ones it always issued.
"""
from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict, deque
from typing import Iterable, Mapping, Optional


MUTANTS_PER_PROJECT = 20


OBSERVATION_ROLES = (
    "full_gold_a", "full_gold_b",
    "stripped_gold_a", "stripped_gold_b",
    "stub_a", "stub_b",
)


#: SLICE3_TEST_QUALITY_SPEC.md §2.2: the candidate terminal-outcome
#: vocabulary.  A kill is `failed` alone; `passed`, `undefined_steps` and
#: `parse_or_compile_error` are survivals a real candidate run records (the
#: preserved aider run 1 carries 18 and 8 of the latter two), and anything
#: else — a timeout, a harness error — stays refused as non-terminal.  The
#: six-gate CONTROLS keep the strict {passed, failed} set: a control whose
#: harness stumbled is corrupt evidence, not a survival.
CANDIDATE_TERMINAL_OUTCOMES = frozenset(
    {"passed", "failed", "undefined_steps", "parse_or_compile_error"})


_MUTANT_FILE_DOMAIN = "r2t.slice3.java20.file/1"


_MUTANT_DOMAIN = "r2t.slice3.java20.mutant/1"


class Slice3Refused(ValueError):
    """A proposed Slice-3 view or binding contradicts the preregistration."""


def _refuse(message: str) -> Slice3Refused:
    return Slice3Refused(message if message.startswith("REFUSED: ")
                         else "REFUSED: " + message)


def _utf8(value: str) -> bytes:
    return value.encode("utf-8")


def _hash(domain: str, *parts: str) -> str:
    payload = "\0".join((domain,) + parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _digest(document: object) -> str:
    raw = json.dumps(document, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _sha256(value: object, where: str) -> str:
    if not isinstance(value, str) or len(value) != 64 \
            or any(character not in "0123456789abcdef" for character in value):
        raise _refuse(f"{where} is not lowercase SHA-256")
    return value


def _item_manifest(*, project: str, kind: str, item_ids: list[str],
                   admitted_manifest_digest: str, closure_map_digest: str,
                   selector_version: str,
                   inference_valid: Optional[bool]) -> dict:
    document = {
        "schema": "r2t.slice3-item-view/1",
        "project": project,
        "kind": kind,
        "admitted_manifest_digest": admitted_manifest_digest,
        "closure_map_digest": closure_map_digest,
        "selector_version": selector_version,
        "ordered_item_ids": item_ids,
        "count": len(item_ids),
    }
    if inference_valid is not None:
        document["inference_valid"] = inference_valid
    document["digest"] = _digest(document)
    return document


def stepdef_key(closure: Mapping[str, object], item_id: str) -> str:
    """Key B: the SET of step definitions one item's steps resolve to.

    A definition is identified by `<file>::<class>#<method>`, taken over
    every step of the item regardless of keyword, deduplicated and sorted,
    then hashed.  What is deliberately NOT in the key: the step's text, its
    parameters, its Examples row, and the keyword itself.  Two scenarios
    that drive the same glue methods with different literals exercise the
    same code, and paying an agent to write a test against the second after
    the first tells us almost nothing new -- that is the whole point of
    grouping by this key rather than by the closure's FILE set, which is
    coarser and lumps unrelated methods of one big glue class together.

    A step whose `definition` is null contributed no resolvable target and
    is skipped; a released item with NO resolvable definition at all is
    refused rather than grouped, because it would otherwise form a silent
    "empty" set and buy a representative for nothing.  `file` may legitimately
    be null for a definition in a dependency the extractor cannot map to a
    path, which is spelled as the empty string here exactly as the Java
    closure extractor spells it.
    """
    steps = closure.get("steps")
    if not isinstance(steps, list):
        raise _refuse(f"{item_id}: released closure has no steps array")
    triples = set()
    for step in steps:
        if not isinstance(step, dict):
            raise _refuse(f"{item_id}: released closure step is not an object")
        definition = step.get("definition")
        if definition is None:
            continue
        if not isinstance(definition, dict):
            raise _refuse(f"{item_id}: step definition is not an object")
        klass = definition.get("class")
        method = definition.get("method")
        if klass is None:
            continue
        if not isinstance(klass, str) or not klass \
                or not isinstance(method, str) or not method:
            raise _refuse(f"{item_id}: step definition names no class/method")
        source = definition.get("file")
        if source is not None and (not isinstance(source, str) or not source):
            raise _refuse(f"{item_id}: step definition file is not a path")
        triples.add(f"{source or ''}::{klass}#{method}")
    if not triples:
        raise _refuse(
            f"{item_id}: released item resolves to no step definition, so it "
            "cannot join a step-definition census")
    return hashlib.sha1(
        "\n".join(sorted(triples)).encode("utf-8")).hexdigest()


def select_stepdef_view(project: str, items: Iterable[Mapping[str, object]],
                        admitted_manifest_digest: str,
                        closure_map_digest: str) -> dict:
    """One representative per distinct step-definition set, over a release.

    The owner's 2026-08-12 ruling, and it is the same construction for both
    projects: group the RELEASED population by key B, take the
    lexicographically smallest item id of each group as its representative,
    and pay for the representatives in raw-UTF-8 order.  Nothing is sampled
    and nothing is filled: the view is a function of the release, so a
    reader can recompute it from the release and get these exact ids.

    `inference_valid` is TRUE here, where the superseded epubcheck view
    stamped false.  The reason is precise and is worth stating as a claim
    that could be wrong: the earlier view could contain two items resolving
    to the same step definitions, so its per-item outcomes were not
    independent draws; this one cannot, by construction.  It remains
    possible for two representatives to share closure FILES -- key B is
    finer than the file-set cluster id -- so this is independence with
    respect to step-definition sets, which is the unit the ruling names,
    and not a claim about file-level disjointness.
    """
    rows = list(items)
    _sha256(admitted_manifest_digest, f"{project} admitted-manifest digest")
    _sha256(closure_map_digest, f"{project} closure-map digest")
    ids = [row.get("item_id") for row in rows]
    if any(not isinstance(item_id, str) or not item_id for item_id in ids):
        raise _refuse(f"every {project} released row must name an item_id")
    if len(ids) != len(set(ids)):
        raise _refuse(f"{project} released rows contain duplicate item ids")

    members: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        key = row.get("stepdef_key")
        if not isinstance(key, str) or len(key) != 40 \
                or any(character not in "0123456789abcdef" for character in key):
            raise _refuse(
                f"{project} released row {row.get('item_id')!r} carries no "
                "step-definition key")
        members[key].append(row["item_id"])

    sets = []
    for key in sorted(members):
        group = sorted(members[key], key=_utf8)
        sets.append({
            "set_id": key,
            "representative": group[0],
            "member_item_ids": group,
            "count": len(group),
        })
    selected = sorted((entry["representative"] for entry in sets), key=_utf8)
    selector = "r2t.slice3.stepdef-census/1"
    result = {
        "schema": "r2t.slice3-item-views/2",
        "project": project,
        "population_size": len(rows),
        "target": "stepdef_census",
        # The membership record is the anti-silence half of the ruling: a
        # reader can see WHICH items each paid representative stands for,
        # rather than being told a number of sets and taking it on trust.
        "stepdef_sets": sets,
        "execution_manifest": _item_manifest(
            project=project, kind="stepdef_census", item_ids=selected,
            admitted_manifest_digest=admitted_manifest_digest,
            closure_map_digest=closure_map_digest,
            selector_version=selector, inference_valid=True),
    }
    result["view_digest"] = _digest(result)
    return result


def _operator_stream(rows: list[dict], project: str) -> deque:
    """One operator's file-round-robin stream."""
    by_file: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_file[row["file"]].append(row)
    files = sorted(by_file, key=lambda path: (
        _hash(_MUTANT_FILE_DOMAIN, project, path), _utf8(path)))
    queues = {
        path: deque(sorted(by_file[path], key=lambda row: (
            _hash(_MUTANT_DOMAIN, project, row["mutant_id"]),
            _utf8(row["mutant_id"]))))
        for path in files
    }
    ordered = deque()
    while any(queues[path] for path in files):
        for path in files:
            if queues[path]:
                ordered.append(queues[path].popleft())
    return ordered


def select_mutants(mutants: Iterable[Mapping[str, object]],
                   execution_views: Mapping[str, Mapping[str, object]],
                   source_population_digests: Mapping[str, str],
                   coverage_map_digests: Mapping[str, str],
                   count: int = MUTANTS_PER_PROJECT) -> dict:
    """Select 20 valid, mapped mutants per project with two-level rotation."""
    execution = {
        project: list(view["ordered_item_ids"])
        for project, view in execution_views.items()
    }
    if set(source_population_digests) != set(execution) \
            or set(coverage_map_digests) != set(execution):
        raise _refuse("mutant source digests do not name the execution projects")
    for project, value in source_population_digests.items():
        _sha256(value, f"{project} mutant population digest")
    for project, value in coverage_map_digests.items():
        _sha256(value, f"{project} coverage-map digest")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise _refuse(f"mutant count must be an integer >= 1, got {count!r}")
    eligible: dict[str, list[dict]] = {project: [] for project in execution}
    seen = set()
    for raw in mutants:
        project = raw.get("project")
        if project not in execution or raw.get("valid") is not True \
                or raw.get("scored") is not True:
            continue
        required = (raw.get("mutant_id"), raw.get("operator"), raw.get("file"))
        if any(not isinstance(value, str) or not value for value in required):
            raise _refuse("eligible mutants need mutant_id, operator, and file")
        mapped = raw.get("mapped_item_ids")
        if not isinstance(mapped, list) or not all(
                isinstance(item_id, str) for item_id in mapped):
            raise _refuse(f"mutant {raw['mutant_id']} has no mapped_item_ids")
        mapped_set = set(mapped)
        mapped_admitted = [item_id for item_id in execution[project]
                           if item_id in mapped_set]
        if not mapped_admitted:
            continue
        identity = (project, raw["mutant_id"])
        if identity in seen:
            raise _refuse(f"duplicate mutant identity {identity!r}")
        seen.add(identity)
        eligible[project].append({
            "project": project,
            "mutant_id": raw["mutant_id"],
            "operator": raw["operator"],
            "file": raw["file"],
            "mapped_item_ids": mapped_admitted,
        })

    project_manifests = {}
    for project in sorted(execution, key=_utf8):
        rows = eligible[project]
        if len(rows) < count:
            raise _refuse(
                f"{project} has {len(rows)} valid mapped mutants, fewer than "
                f"the preregistered {count}")
        by_operator: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            by_operator[row["operator"]].append(row)
        operators = sorted(by_operator, key=_utf8)
        streams = {operator: _operator_stream(by_operator[operator], project)
                   for operator in operators}
        ordered = []
        while len(ordered) < count:
            moved = False
            for operator in operators:
                if streams[operator] and len(ordered) < count:
                    ordered.append(streams[operator].popleft())
                    moved = True
            if not moved:
                break
        pairs = []
        for row in ordered:
            for item_id in row["mapped_item_ids"]:
                pairs.append({"item_id": item_id,
                              "mutant_id": row["mutant_id"]})
        manifest = {
            "schema": "r2t.slice3-java20-mutant-view/1",
            "selector_version": "r2t.slice3.java20/1",
            "project": project,
            "source_population_digest": source_population_digests[project],
            "coverage_map_digest": coverage_map_digests[project],
            "execution_view_digest": execution_views[project]["digest"],
            "ordered_mutant_ids": [row["mutant_id"] for row in ordered],
            "ordered_pairs": pairs,
            "count": len(ordered),
        }
        manifest["digest"] = _digest(manifest)
        project_manifests[project] = manifest

    result = {
        "schema": "r2t.slice3-java20-mutant-views/1",
        "mutants_per_project": count,
        "projects": project_manifests,
    }
    result["view_digest"] = _digest(result)
    return result


def validate_six_observations(
        selected_pairs: Iterable[Mapping[str, str]],
        observations: Mapping[str, Iterable[Mapping[str, object]]],
        execution_by_project: Mapping[str, Iterable[str]]) -> dict:
    """Apply each project's independent six-observation gate.

    Every row carries its immutable ``observation_id``.  A role has one id per
    project and all six ids must differ; a role label alone is not evidence of
    a distinct observation.
    """
    pairs = [(row["project"], row["item_id"], row["mutant_id"])
             for row in selected_pairs]
    pair_set = set(pairs)
    global_reasons = []
    project_reasons: dict[str, list[str]] = defaultdict(list)
    if set(observations) != set(OBSERVATION_ROLES):
        global_reasons.append("observation roles are not the exact required six")
    if any(pair[0] not in execution_by_project for pair in pairs):
        global_reasons.append("selected pairs name a project outside the views")

    indexed: dict[str, dict[tuple[str, str, str], str]] = {}
    identities: dict[str, dict[str, set[str]]] = {}
    for role in OBSERVATION_ROLES:
        role_rows = list(observations.get(role, ()))
        table = {}
        role_ids: dict[str, set[str]] = defaultdict(set)
        for row in role_rows:
            key = (row.get("project"), row.get("item_id"), row.get("mutant_id"))
            if key in table:
                target = project_reasons[key[0]] \
                    if key[0] in execution_by_project else global_reasons
                target.append(f"{role} contains duplicate pair {key!r}")
            table[key] = row.get("outcome")
            observation_id = row.get("observation_id")
            if isinstance(key[0], str) and isinstance(observation_id, str) \
                    and observation_id:
                role_ids[key[0]].add(observation_id)
            else:
                target = project_reasons[key[0]] \
                    if key[0] in execution_by_project else global_reasons
                target.append(f"{role} has no observation identity")
            if row.get("outcome") not in {"passed", "failed"}:
                target = project_reasons[key[0]] \
                    if key[0] in execution_by_project else global_reasons
                target.append(f"{role} contains an infrastructure outcome")
        indexed[role] = table
        identities[role] = role_ids
    for role in OBSERVATION_ROLES:
        for key in set(indexed[role]) - pair_set:
            target = project_reasons[key[0]] \
                if key[0] in execution_by_project else global_reasons
            target.append("an observation contains a pair outside the frozen set")

    project_reports = {}
    eligible_projects = []
    for project in sorted(execution_by_project, key=_utf8):
        project_pairs = [pair for pair in pairs if pair[0] == project]
        project_set = set(project_pairs)
        reasons = list(global_reasons) + project_reasons[project]
        if len(project_pairs) != len(project_set):
            reasons.append("selected pair set contains duplicates")
        observation_ids = {}
        for role in OBSERVATION_ROLES:
            present = {pair for pair in indexed[role] if pair[0] == project}
            if present != project_set:
                reasons.append(
                    f"{role} does not cover the exact selected pair set")
            ids = identities[role].get(project, set())
            if len(ids) != 1:
                reasons.append(f"{role} does not have one observation identity")
            else:
                observation_ids[role] = next(iter(ids))
        if len(set(observation_ids.values())) != len(OBSERVATION_ROLES):
            reasons.append("the six observation identities are not distinct")

        item_records = {
            item_id: {
                "item_id": item_id, "status": "not_scorable",
                "hard_mutant_ids": [],
                "stub_twin_intersection_recall": None,
            }
            for item_id in execution_by_project[project]
        }
        if reasons:
            project_reports[project] = {
                "status": "functional_only",
                "reasons": sorted(set(reasons)),
                "observation_ids": observation_ids,
                "gold_flip_rate": None,
                "stub_twin_intersection_macro_recall": None,
                "hard_pairs": [],
                "items": item_records,
            }
            continue

        gold_a, gold_b = indexed["full_gold_a"], indexed["full_gold_b"]
        flips = sum(gold_a[pair] != gold_b[pair] for pair in project_pairs)
        flip_rate = flips / len(project_pairs) if project_pairs else 0.0
        if flip_rate > 0.02:
            reasons.append(
                f"full-gold twin flip rate {flip_rate:.6f} exceeds 0.02")
        hard = {pair for pair in project_pairs
                if gold_a[pair] == gold_b[pair] == "failed"
                and indexed["stripped_gold_a"][pair]
                == indexed["stripped_gold_b"][pair] == "passed"}
        gold_intersection = {pair for pair in project_pairs
                             if gold_a[pair] == gold_b[pair] == "failed"}
        stub_intersection = {pair for pair in project_pairs
                             if indexed["stub_a"][pair]
                             == indexed["stub_b"][pair] == "failed"}

        recalls = []
        for item_id, item in item_records.items():
            item_pairs = {pair for pair in project_set if pair[1] == item_id}
            item_hard = sorted((pair[2] for pair in hard & item_pairs),
                               key=_utf8)
            gold = gold_intersection & item_pairs
            recall = (len(stub_intersection & gold) / len(gold)
                      if gold else None)
            if recall is not None:
                recalls.append(recall)
            item.update({
                "status": "eligible" if item_hard else "not_scorable",
                "hard_mutant_ids": item_hard,
                "stub_twin_intersection_recall": recall,
            })
        macro = sum(recalls) / len(recalls) if recalls else None
        if macro is not None and macro > 0.02:
            reasons.append(
                f"stub twin-intersection macro recall {macro:.6f} exceeds 0.02")
        if not hard:
            reasons.append("no item has a non-empty hard-pair set")
        status = "functional_only" if reasons else "mutation_eligible"
        if status == "mutation_eligible":
            eligible_projects.append(project)
        project_reports[project] = {
            "status": status,
            "reasons": reasons,
            "observation_ids": observation_ids,
            "gold_flip_rate": flip_rate,
            "stub_twin_intersection_macro_recall": macro,
            "hard_pairs": [
                {"item_id": pair[1], "mutant_id": pair[2]}
                for pair in sorted(hard, key=lambda p: tuple(map(_utf8, p)))
            ],
            "items": item_records,
        }

    return {
        "schema": "r2t.slice3-six-observation-eligibility/1",
        "adaptive_expansion": False,
        "status": ("mutation_eligible" if eligible_projects
                   else "functional_only"),
        "eligible_projects": eligible_projects,
        "projects": project_reports,
    }


def build_mutation_execution_binding(
        mutant_views: Mapping[str, object],
        observation_ids: Mapping[str, Mapping[str, str]]) -> dict:
    """Bind ``mutation_run.run_slice(planned_pairs=...)`` to Slice-3 only.

    This is not ambient mutation capability: the only admitted projects are
    the Java projects this freeze carries a mutant view for, and each of the
    six control jobs references the one complete frozen mapped-pair set.  A
    project declared functional-only in the source-inputs document has no
    view here and no control observations (see `_derive_source_inputs`).  The
    ordinary CLI remains closed.
    """
    from . import mutation_run

    bound_projects = set(mutant_views.get("projects", {})) \
        if isinstance(mutant_views.get("projects"), Mapping) else set()
    if mutant_views.get("schema") != "r2t.slice3-java20-mutant-views/1" \
            or not bound_projects \
            or not bound_projects <= {"epubcheck", "algorand-sdk"}:
        raise _refuse(
            "mutation execution binding requires at least one Java20 view")
    unsigned_root = dict(mutant_views)
    claimed_root = unsigned_root.pop("view_digest", None)
    if claimed_root != _digest(unsigned_root):
        raise _refuse("Java20 view digest does not rederive")
    if set(observation_ids) != bound_projects:
        raise _refuse(
            "control observation ids do not name the mutation-scoped Java "
            "projects")

    projects = {}
    for project in (name for name in ("epubcheck", "algorand-sdk")
                    if name in bound_projects):
        manifest = mutant_views["projects"][project]
        unsigned = dict(manifest)
        claimed = unsigned.pop("digest", None)
        if claimed != _digest(unsigned) or manifest.get("project") != project:
            raise _refuse(f"{project} mutant manifest digest does not rederive")
        mutant_ids = manifest.get("ordered_mutant_ids")
        pairs = manifest.get("ordered_pairs")
        if manifest.get("count") != MUTANTS_PER_PROJECT \
                or not isinstance(mutant_ids, list) \
                or len(mutant_ids) != MUTANTS_PER_PROJECT \
                or len(set(mutant_ids)) != MUTANTS_PER_PROJECT \
                or not isinstance(pairs, list):
            raise _refuse(f"{project} is not the frozen 20-mutant scope")
        pair_tuples = []
        for pair in pairs:
            if not isinstance(pair, dict) \
                    or set(pair) != {"item_id", "mutant_id"} \
                    or pair["mutant_id"] not in mutant_ids:
                raise _refuse(f"{project} carries a malformed mapped pair")
            pair_tuples.append((pair["item_id"], pair["mutant_id"]))
        if len(pair_tuples) != len(set(pair_tuples)) or not pair_tuples:
            raise _refuse(f"{project} mapped pair set is empty or duplicated")
        ids = observation_ids[project]
        if set(ids) != set(OBSERVATION_ROLES) \
                or any(not isinstance(value, str) or len(value) != 32
                       or any(ch not in "0123456789abcdef" for ch in value)
                       for value in ids.values()) \
                or len(set(ids.values())) != len(OBSERVATION_ROLES):
            raise _refuse(
                f"{project} needs six distinct 32-hex observation identities")
        pair_digest = mutation_run.pair_set_digest(pair_tuples)
        projects[project] = {
            "mutant_manifest_digest": claimed,
            "pair_set_digest": pair_digest,
            "ordered_pairs": [list(pair) for pair in pair_tuples],
            "control_observations": [
                {"role": role, "observation_id": ids[role],
                 "pair_set_digest": pair_digest}
                for role in OBSERVATION_ROLES
            ],
        }
    document = {
        "schema": "r2t.slice3-java20-execution-binding/1",
        # A FROZEN document identity, not a module reference: this string
        # is the `producer` field of an already-issued
        # `r2t.slice3-java20-execution-binding/1` document, whose digest
        # `ALGORAND_BUNDLE_V4_SPEC.md` section 8 records.  It does not follow
        # the module to `r2t.bench.`.
        "producer": "r2t.mutation_run.run_slice",
        "producer_argument": "planned_pairs",
        "projects": projects,
        "candidate_policy": {
            "arms": ["aider", "openhands"],
            "run1_scope": "complete_frozen_mapped_pair_set",
            "d3_empty_hard_subset": "not_scorable",
            "d4_scope": "whole_hard_pair_union_for_initial_recall_1_items",
            "d4_observation": "new_native_complete_no_projection",
            "adaptive_expansion": False,
        },
    }
    document["digest"] = _digest(document)
    return document


def authorize_mutation_job(
        binding: Mapping[str, object], *, project: str, role: str,
        observation_id: str,
        eligibility: Optional[Mapping[str, object]] = None,
        run1_rows: Optional[Iterable[Mapping[str, object]]] = None) -> dict:
    """Return the exact existing-producer pair list for one admitted job."""
    from . import mutation_run

    if project not in {"epubcheck", "algorand-sdk"}:
        raise _refuse("Slice-3 mutation capability cannot authorize this project")
    unsigned = dict(binding)
    claimed = unsigned.pop("digest", None)
    if binding.get("schema") != "r2t.slice3-java20-execution-binding/1" \
            or claimed != _digest(unsigned):
        raise _refuse("mutation execution binding digest does not rederive")
    if project not in binding["projects"]:
        raise _refuse(
            f"{project} is declared functional-only in this freeze and has no "
            "mutation binding")
    project_binding = binding["projects"][project]
    full_pairs = [tuple(pair) for pair in project_binding["ordered_pairs"]]
    controls = {row["role"]: row["observation_id"]
                for row in project_binding["control_observations"]}
    if role in controls:
        if observation_id != controls[role]:
            raise _refuse("control job uses another observation identity")
        pairs = full_pairs
        required = True
    else:
        parts = role.split(":")
        if len(parts) != 2 or parts[0] not in {"candidate_run1",
                                              "candidate_run2"} \
                or parts[1] not in {"aider", "openhands"}:
            raise _refuse(f"unknown Slice-3 mutation role {role!r}")
        if not isinstance(eligibility, Mapping) \
                or eligibility.get("projects", {}).get(project, {}).get(
                    "status") != "mutation_eligible":
            raise _refuse(f"{project} has not opened candidate mutation scoring")
        if not isinstance(observation_id, str) or len(observation_id) != 32 \
                or any(ch not in "0123456789abcdef" for ch in observation_id) \
                or observation_id in set(controls.values()):
            raise _refuse(
                "candidate observation identity is not fresh 32-hex")
        if parts[0] == "candidate_run1":
            if run1_rows is not None:
                raise _refuse("candidate run 1 cannot consume prior outcomes")
            pairs = full_pairs
            required = True
        else:
            rows = list(run1_rows or ())
            by_pair = {}
            for row in rows:
                pair = (row.get("item_id"), row.get("mutant_id"))
                # Terminal survivals beyond passed/failed are admitted (spec
                # §2.2 seam fix); the kill rule below stays failed-only.
                if pair in by_pair or row.get("outcome") \
                        not in CANDIDATE_TERMINAL_OUTCOMES:
                    raise _refuse("candidate run 1 rows are duplicate or incomplete")
                by_pair[pair] = row["outcome"]
            if set(by_pair) != set(full_pairs):
                raise _refuse("candidate run 1 does not cover the frozen pair set")
            hard = {tuple((row["item_id"], row["mutant_id"]))
                    for row in eligibility["projects"][project]["hard_pairs"]}
            hard_by_item: dict[str, set[tuple[str, str]]] = defaultdict(set)
            for pair in hard:
                hard_by_item[pair[0]].add(pair)
            qualifying = {item_id for item_id, item_pairs in hard_by_item.items()
                          if item_pairs
                          and all(by_pair[pair] == "failed"
                                  for pair in item_pairs)}
            pairs = [pair for pair in full_pairs
                     if pair in hard and pair[0] in qualifying]
            required = bool(pairs)
    document = {
        "schema": "r2t.slice3-java20-mutation-job/1",
        "binding_digest": claimed,
        "project": project,
        "role": role,
        "observation_id": observation_id,
        "required": required,
        "planned_pairs": [list(pair) for pair in pairs],
        "pair_set_digest": (None if not pairs
                            else mutation_run.pair_set_digest(pairs)),
    }
    document["digest"] = _digest(document)
    return document


def _stable_bytes(path: str, label: str) -> bytes:
    if not isinstance(path, str) or not os.path.isabs(path) \
            or os.path.normpath(path) != path:
        raise _refuse(f"{label} path is not normalized and absolute")
    with open(path, "rb") as handle:
        first = handle.read()
        first_info = os.fstat(handle.fileno())
    with open(path, "rb") as handle:
        second = handle.read()
        second_info = os.fstat(handle.fileno())
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size,
                             info.st_mtime_ns)
    if first != second or identity(first_info) != identity(second_info):
        raise _refuse(f"{label} changed while read")
    return first


def _stable_json(path: str, label: str) -> tuple[dict, bytes]:
    from . import result_ledger as ledger

    first = _stable_bytes(path, label)
    document = ledger.loads_exact_json(first, label=label)
    if not isinstance(document, dict):
        raise _refuse(f"{label} is not an object")
    return document, first


def _read_rows(path: str, label: str) -> list[dict]:
    from . import result_ledger as ledger

    raw = _stable_bytes(path, label)
    rows = []
    for index, line in enumerate(raw.splitlines()):
        row = ledger.loads_exact_json(line, label=f"{label} row {index}")
        if not isinstance(row, dict):
            raise _refuse(f"{label} row {index} is not an object")
        rows.append(row)
    return rows


def _mutation_pairs(bundle: Mapping[str, object], project: str) \
        -> list[tuple[str, str]]:
    return [tuple(pair) for pair in bundle["mutation_execution_binding"]
            ["projects"][project]["ordered_pairs"]]


def _load_bound_mutation_observation(
        path: str, *, bundle: Mapping[str, object], project: str, role: str,
        observation_id: Optional[str] = None,
        eligibility: Optional[Mapping[str, object]] = None) -> list[dict]:
    """Read one complete producer output as a six-gate observation."""
    from . import mutation_run

    if not isinstance(path, str) or not os.path.isabs(path) \
            or os.path.normpath(path) != path:
        raise _refuse("Slice-3 mutation observation path is not absolute")
    sidecar, _raw = _stable_json(
        mutation_run.provenance_path(path), "Slice-3 mutation provenance")
    identity = sidecar.get("campaign_identity")
    try:
        mutation_run.campaign_identity_digest(identity)
    except mutation_run.MutationAborted as exc:
        raise _refuse(str(exc)) from exc
    if sidecar.get("status") != "complete" \
            or identity.get("asset_project") != project:
        raise _refuse("Slice-3 observation is not a complete project output")
    recorded_observation = sidecar.get("observation_id")
    if observation_id is not None and recorded_observation != observation_id:
        raise _refuse("Slice-3 observation identity differs from its role")
    expected_job = authorize_mutation_job(
        bundle["mutation_execution_binding"], project=project, role=role,
        observation_id=recorded_observation, eligibility=eligibility)
    if sidecar.get("slice3_execution_binding_digest") \
            != bundle["mutation_execution_binding"]["digest"] \
            or sidecar.get("slice3_mutation_job_digest") \
            != expected_job["digest"]:
        raise _refuse("mutation observation was not produced by its bound job")
    expected_pairs = set(_mutation_pairs(bundle, project))
    if set(tuple(pair) for pair in expected_job["planned_pairs"]) \
            != expected_pairs:
        raise _refuse("six-gate observation is not the complete frozen scope")
    try:
        mutation_run.completed_pairs(
            path, identity, expected_pairs=expected_pairs,
            require_complete=True)
    except mutation_run.MutationAborted as exc:
        raise _refuse(str(exc)) from exc
    rows = _read_rows(path, f"Slice-3 {role} observation")
    projected = []
    # The controls keep the strict vocabulary; a CANDIDATE run legitimately
    # records the other terminal survivals (spec §2.2 seam fix).
    admitted = ({"passed", "failed"} if role in OBSERVATION_ROLES
                else CANDIDATE_TERMINAL_OUTCOMES)
    for row in rows:
        if row.get("outcome") not in admitted:
            raise _refuse(
                "six-gate observation contains infrastructure"
                if role in OBSERVATION_ROLES
                else "candidate observation contains a non-terminal outcome")
        projected.append({
            "project": project,
            "item_id": row.get("item_id"),
            "mutant_id": row.get("mutant_id"),
            "outcome": row["outcome"],
            "observation_id": recorded_observation,
        })
    return projected
