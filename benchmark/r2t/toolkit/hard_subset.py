"""Population-pinned assertion-hard mutant subsets.

For each item, a mutant is hard exactly when:

* full gold's outcome is literal ``failed`` in both independent runs; and
* assertion-stripped gold's outcome is literal ``passed`` in both independent
  runs.

The first intersection removes kill flips.  The second witness removes
mutants killed by setup/action or execution alone.  Both observations must be
complete over the same population (restricted only by an explicitly recorded
unmutated stripped-baseline fidelity exclusion).
"""
from __future__ import annotations

import copy
import json
import os
from typing import Iterable, Optional

from . import gold_killset
from ..bench import mutation_run
from ..data import versions


SCHEMA = "r2t.hard-subset/1"
TOP_FIELDS = frozenset({
    "schema", "population_id", "population", "n_full_gold_runs",
    "n_stripped_runs", "runs", "pairs", "fidelity", "screen",
    "full_gold", "hard_subset", "knife_edge_items", "digest",
})
RUN_GROUP_FIELDS = frozenset({"full_gold", "stripped_gold"})
PAIRS_FIELDS = frozenset({
    "full_n", "full_sha256", "screened_n", "screened_sha256",
})
FIDELITY_FIELDS = frozenset({
    "baseline_sha256", "items_total", "items_passed", "items_excluded",
    "passed_item_ids_sha256", "generated_tests_sha256", "excluded",
})
EXCLUDED_ITEM_FIELDS = frozenset({"item_id", "outcome", "reason"})
SCREEN_FIELDS = frozenset({
    "passed_both_count", "outcome_disagreement_count",
    "gold_pairs_removed_by_screen", "removed_gold_pairs",
})
REMOVED_FIELDS = frozenset({
    "item_id", "mutant_id", "stripped_run_1_outcome",
    "stripped_run_2_outcome", "reason",
})
SET_FIELDS = frozenset({"count", "items", "by_item", "sha256", "ratio"})

# Full and stripped candidates intentionally differ in generated-test bytes,
# side, attempt and expected pair subset.  These fields are the immutable
# population/executor facts that must remain identical across all four runs.
POPULATION_EXECUTION_FIELDS = frozenset({
    "schema", "kind", "asset_index_sha256", "asset_project",
    "mutation_validation_sha256", "mutation_validation_class",
    "manifest_sha256", "manifest_digest", "map_sha256", "release_sha256",
    "substrate_baseline_sha256", "applier_sha256", "harness_version",
    "container_image_digest", "workspace_seed_digest",
    "database_dump_digest", "engine", "engine_version", "parser",
    "timeout_seconds", "sample", "sample_seed", "reference_source_tag",
    "generation_provenance_class",
})


class HardSubsetRefused(ValueError):
    """The evidence cannot establish the pre-registered hard subset."""


def _known_outcome(outcome, label: str) -> str:
    try:
        return gold_killset._known_outcome(outcome)
    except gold_killset.GoldKillsetRefused as exc:
        raise HardSubsetRefused(f"REFUSED: {label}: {exc}") from exc


def _exact(value, fields: frozenset[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        got = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise HardSubsetRefused(
            f"REFUSED: {label} must contain exactly {sorted(fields)}; got "
            f"{got}.")


def _sha(value) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(ch in "0123456789abcdef" for ch in value))


def artifact_digest(doc: dict) -> str:
    if not isinstance(doc, dict):
        raise HardSubsetRefused("REFUSED: hard subset is not an object.")
    return mutation_run.content_digest(
        {key: value for key, value in doc.items() if key != "digest"})


def pair_digest(pairs: Iterable[tuple[str, str]]) -> str:
    return mutation_run.pair_set_digest(set(pairs))


def item_digest(items: Iterable[str]) -> str:
    return mutation_run.content_digest(sorted(set(items)))


def _load_native(paths: Iterable[str], *, side: str, label: str) -> dict:
    paths = list(paths)
    try:
        campaign = mutation_run.validate_native_shards(
            paths, required_side=side, return_campaign=True)
    except (mutation_run.MutationAborted, OSError, ValueError) as exc:
        raise HardSubsetRefused(str(exc)) from exc
    identity = campaign["campaign_identity"]
    if identity.get("kind") != "mutation-run" \
            or identity.get("sample") is not None \
            or identity.get("sample_seed") is not None:
        raise HardSubsetRefused(
            f"REFUSED: {label} must be a standalone, unsampled mutation-run.")
    observation = campaign.get("observation_id")
    try:
        mutation_run.validate_observation_id(observation)
    except mutation_run.MutationAborted as exc:
        raise HardSubsetRefused(str(exc)) from exc
    outcomes = {}
    for row in campaign["rows"]:
        pair = (row.get("item_id"), row.get("mutant_id"))
        outcome = row.get("outcome")
        if pair in outcomes or not all(isinstance(x, str) and x for x in pair) \
                or not isinstance(outcome, str) or not outcome:
            raise HardSubsetRefused(
                f"REFUSED: {label} has duplicate/malformed pair {pair!r}.")
        _known_outcome(outcome, label)
        outcomes[pair] = outcome
    shard_facts = []
    for path in paths:
        sidecar_path = mutation_run.provenance_path(path)
        with open(sidecar_path, encoding="utf-8") as fh:
            sidecar = json.load(fh)
        shard_facts.append((sidecar["campaign_identity"]["shard"], {
            "rows_sha256": mutation_run.sha256_file(path),
            "sidecar_sha256": mutation_run.sha256_file(sidecar_path),
        }))
    shard_facts.sort(key=lambda value: value[0])
    facts = {
        "observation_id": observation,
        "campaign_identity_sha256":
            mutation_run.campaign_identity_digest(identity),
        "rows_sha256": [value["rows_sha256"] for _n, value in shard_facts],
        "sidecars_sha256": [value["sidecar_sha256"]
                            for _n, value in shard_facts],
        "n_shards": len(shard_facts), "n_rows": len(outcomes),
        "n_pairs": len(outcomes), "pairs_sha256": pair_digest(outcomes),
    }
    return {"identity": identity, "outcomes": outcomes, "facts": facts}


def load_full_gold(paths: Iterable[str]) -> dict:
    return _load_native(paths, side="gold", label="full gold")


def load_stripped(paths: Iterable[str]) -> dict:
    return _load_native(paths, side="candidate", label="stripped gold")


def load_candidate(paths: Iterable[str], *, label: str = "candidate") -> dict:
    """Load any standalone candidate observation with the same strict facts."""
    return _load_native(paths, side="candidate", label=label)


def load_fidelity(path: str) -> dict:
    """Load one complete unmutated stripped-baseline run."""
    outcomes = {}
    reasons = {}
    passed_files = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for number, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise HardSubsetRefused(
                        f"REFUSED: stripped fidelity row {number} is not an "
                        "object.")
                item_id = row.get("item_id")
                if not isinstance(item_id, str) or not item_id \
                        or item_id in outcomes:
                    raise HardSubsetRefused(
                        f"REFUSED: stripped fidelity row {number} has missing "
                        f"or duplicate item_id {item_id!r}.")
                metadata = row.get("metadata")
                if row.get("adapter") != "stripped-gold" \
                        or not isinstance(metadata, dict) \
                        or metadata.get("source") != "stripped_gold" \
                        or metadata.get("stripped_gold") is not True \
                        or metadata.get("item_id") != item_id:
                    raise HardSubsetRefused(
                        f"REFUSED: stripped fidelity row {number} is not a "
                        "producer-authenticated stripped-gold control for its "
                        f"own item_id {item_id!r}.")
                outcome = row.get("outcome")
                if not isinstance(outcome, str) or not outcome:
                    raise HardSubsetRefused(
                        f"REFUSED: stripped fidelity row {number} has invalid "
                        f"outcome {outcome!r}.")
                _known_outcome(outcome, "stripped fidelity")
                outcomes[item_id] = outcome
                if outcome == "passed":
                    files = row.get("produced_files") or []
                    if not isinstance(files, list):
                        raise HardSubsetRefused(
                            f"REFUSED: stripped fidelity row {number} has "
                            "non-list produced_files.")
                    passed_files[item_id] = files
                reasons[item_id] = (metadata.get("adapter_error")
                                    or row.get("error") or None)
    except (OSError, json.JSONDecodeError) as exc:
        raise HardSubsetRefused(
            f"REFUSED: cannot read stripped fidelity run {path}: {exc}") from exc
    return {"outcomes": outcomes, "reasons": reasons,
            "sha256": mutation_run.sha256_file(path),
            "generated_tests_sha256":
                mutation_run.candidate_digest(passed_files)}


def _validate_record(run: dict, *, side: str, label: str,
                     reference_role: str) -> None:
    if not isinstance(run, dict) or set(run) != {"identity", "outcomes", "facts"}:
        raise HardSubsetRefused(
            f"REFUSED: {label} is not a validated native-run record.")
    try:
        mutation_run._validate_campaign_identity(run["identity"])
        mutation_run.validate_publishable_generation(
            run["identity"], reference_roles={reference_role})
        mutation_run.validate_observation_id(
            run["facts"].get("observation_id"))
    except mutation_run.MutationAborted as exc:
        raise HardSubsetRefused(str(exc)) from exc
    if run["identity"].get("side") != side \
            or run["identity"].get("kind") != "mutation-run" \
            or run["identity"].get("sample") is not None \
            or run["identity"].get("sample_seed") is not None:
        raise HardSubsetRefused(
            f"REFUSED: {label} must be an unsampled standalone {side} run.")
    expected_harness = versions.component("harness")["version"]
    project = run["identity"].get("asset_project")
    if not versions.reference_harness_compatible(
            project, run["identity"].get("harness_version"),
            expected_harness):
        raise HardSubsetRefused(
            f"REFUSED: {label} uses harness version "
            f"{run['identity'].get('harness_version')!r}, neither current "
            f"version {expected_harness} nor one VERSIONS.yml declares "
            f"compatible for {project!r}; C5 must observe C4's verdict "
            "semantics rather than release stale evidence.")
    pairs = set(run["outcomes"])
    for outcome in run["outcomes"].values():
        _known_outcome(outcome, label)
    facts = run["facts"]
    if facts.get("n_rows") != len(pairs) or facts.get("n_pairs") != len(pairs) \
            or facts.get("pairs_sha256") != pair_digest(pairs) \
            or run["identity"].get("expected_pairs") != len(pairs) \
            or run["identity"].get("expected_pairs_sha256") \
            != pair_digest(pairs) \
            or facts.get("campaign_identity_sha256") \
            != mutation_run.campaign_identity_digest(run["identity"]):
        raise HardSubsetRefused(
            f"REFUSED: {label}'s pair/identity facts differ from its rows.")


def _run_facts(run: dict, index: int) -> dict:
    facts = copy.deepcopy(run["facts"])
    facts["index"] = index
    return facts


def _by_item(pairs: Iterable[tuple[str, str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for item_id, mutant_id in sorted(set(pairs)):
        out.setdefault(item_id, []).append(mutant_id)
    return out


def _set_block(pairs: set[tuple[str, str]], denominator: int) -> dict:
    by_item = _by_item(pairs)
    return {"count": len(pairs), "items": len(by_item), "by_item": by_item,
            "sha256": pair_digest(pairs),
            "ratio": (None if denominator == 0
                      else round(len(pairs) / denominator, 6))}


def build(population_id: str, full_1: dict, full_2: dict,
          stripped_1: dict, stripped_2: dict, fidelity: dict) -> dict:
    """Build the exact N=2 intersection plus N=2 passed witness."""
    for index, run in enumerate((full_1, full_2), 1):
        _validate_record(run, side="gold", label=f"full gold run {index}",
                         reference_role="full-gold")
    for index, run in enumerate((stripped_1, stripped_2), 1):
        _validate_record(run, side="candidate",
                         label=f"stripped gold run {index}",
                         reference_role="assertion-stripped-gold")
    observations = [run["facts"]["observation_id"]
                    for run in (full_1, full_2, stripped_1, stripped_2)]
    if len(set(observations)) != 4:
        raise HardSubsetRefused(
            "REFUSED: N=2 full + N=2 stripped requires four distinct "
            "observation_id values.")

    # Reuse the already-gated full-gold N=2 implementation.  This also binds
    # the requested population id to VERSIONS.yml and preserves kill flips.
    try:
        full_doc = gold_killset.build(population_id, full_1, full_2)
    except gold_killset.GoldKillsetRefused as exc:
        raise HardSubsetRefused(str(exc)) from exc

    first = full_1["identity"]
    for label, run in (("full gold run 2", full_2),
                       ("stripped gold run 1", stripped_1),
                       ("stripped gold run 2", stripped_2)):
        changed = sorted(key for key in POPULATION_EXECUTION_FIELDS
                         if run["identity"].get(key) != first.get(key))
        if changed:
            raise HardSubsetRefused(
                f"REFUSED: {label} differs in population/executor field(s) "
                f"{changed}.")
    changed_stripped = sorted(
        field for field in gold_killset.SHARED_CAMPAIGN_FIELDS
        if stripped_1["identity"].get(field)
        != stripped_2["identity"].get(field))
    if changed_stripped:
        raise HardSubsetRefused(
            "REFUSED: stripped-gold N=2 observations differ in generated "
            f"solution or execution field(s) {changed_stripped}.")

    full_pairs = set(full_1["outcomes"])
    expected_items = {item for item, _mutant in full_pairs}
    if not isinstance(fidelity, dict) \
            or set(fidelity) != {"outcomes", "reasons", "sha256",
                                 "generated_tests_sha256"} \
            or set(fidelity["outcomes"]) != expected_items:
        missing = sorted(expected_items - set((fidelity or {}).get(
            "outcomes", {}))) if isinstance(fidelity, dict) else []
        extra = sorted(set((fidelity or {}).get("outcomes", {}))
                       - expected_items) if isinstance(fidelity, dict) else []
        raise HardSubsetRefused(
            "REFUSED: stripped fidelity must contain exactly every item in "
            f"the full pair population (missing {missing[:3]}, extra "
            f"{extra[:3]}).")
    if not _sha(fidelity["generated_tests_sha256"]) \
            or any(run["identity"].get("candidate_generated_tests_sha256")
                   != fidelity["generated_tests_sha256"]
                   or run["identity"].get("solution_generated_tests_sha256")
                   != fidelity["generated_tests_sha256"]
                   or run["identity"].get("candidate_run_sha256")
                   != fidelity["sha256"]
                   for run in (stripped_1, stripped_2)):
        raise HardSubsetRefused(
            "REFUSED: stripped mutation observations do not execute the "
            "exact run/generated-test bytes bound by the fidelity baseline.")
    passed_items = {item for item, outcome in fidelity["outcomes"].items()
                    if outcome == "passed"}
    screened_pairs = {pair for pair in full_pairs if pair[0] in passed_items}
    stripped_sets = [set(stripped_1["outcomes"]),
                     set(stripped_2["outcomes"])]
    if stripped_sets[0] != screened_pairs or stripped_sets[1] != screened_pairs:
        details = [(len(screened_pairs - got), len(got - screened_pairs))
                   for got in stripped_sets]
        raise HardSubsetRefused(
            "REFUSED: each stripped run must be complete over exactly the "
            f"fidelity-passing pair population; missing/extra {details}.")

    full_intersection = {
        (item_id, mutant_id)
        for item_id, mids in full_doc["kills"]["by_item"].items()
        for mutant_id in mids
    }
    passed_both = {pair for pair in screened_pairs
                   if stripped_1["outcomes"][pair] == "passed"
                   and stripped_2["outcomes"][pair] == "passed"}
    hard = full_intersection & passed_both
    removed = full_intersection - hard
    removed_records = [{
        "item_id": pair[0], "mutant_id": pair[1],
        "stripped_run_1_outcome": stripped_1["outcomes"].get(pair),
        "stripped_run_2_outcome": stripped_2["outcomes"].get(pair),
        "reason": ("stripped_not_passed_both" if pair in screened_pairs
                   else "fidelity_excluded"),
    } for pair in sorted(removed)]
    excluded_items = [{
        "item_id": item, "outcome": fidelity["outcomes"][item],
        "reason": fidelity["reasons"].get(item),
    } for item in sorted(expected_items - passed_items)]
    hard_items = {item for item, _mutant in hard}
    full_items = {item for item, _mutant in full_intersection}

    doc = {
        "schema": SCHEMA, "population_id": population_id,
        "population": full_doc["population"],
        "n_full_gold_runs": 2, "n_stripped_runs": 2,
        "runs": {
            "full_gold": [_run_facts(full_1, 1), _run_facts(full_2, 2)],
            "stripped_gold": [_run_facts(stripped_1, 1),
                              _run_facts(stripped_2, 2)],
        },
        "pairs": {
            "full_n": len(full_pairs), "full_sha256": pair_digest(full_pairs),
            "screened_n": len(screened_pairs),
            "screened_sha256": pair_digest(screened_pairs),
        },
        "fidelity": {
            "baseline_sha256": fidelity["sha256"],
            "items_total": len(expected_items), "items_passed": len(passed_items),
            "items_excluded": len(excluded_items),
            "passed_item_ids_sha256": item_digest(passed_items),
            "generated_tests_sha256": fidelity["generated_tests_sha256"],
            "excluded": excluded_items,
        },
        "screen": {
            "passed_both_count": len(passed_both),
            "outcome_disagreement_count": sum(
                stripped_1["outcomes"][pair]
                != stripped_2["outcomes"][pair]
                for pair in screened_pairs),
            "gold_pairs_removed_by_screen": len(removed),
            "removed_gold_pairs": removed_records,
        },
        "full_gold": _set_block(full_intersection, len(full_intersection)),
        "hard_subset": _set_block(hard, len(full_intersection)),
        "knife_edge_items": sorted(full_items - hard_items),
    }
    doc["digest"] = artifact_digest(doc)
    validate(doc)
    return doc


def build_from_paths(population_id: str, full_1_paths: Iterable[str],
                     full_2_paths: Iterable[str],
                     stripped_1_paths: Iterable[str],
                     stripped_2_paths: Iterable[str],
                     fidelity_path: str) -> dict:
    groups = [list(value) for value in (
        full_1_paths, full_2_paths, stripped_1_paths, stripped_2_paths)]
    real_sets = [{os.path.realpath(os.path.abspath(path)) for path in paths}
                 for paths in groups]
    if any(real_sets[i] & real_sets[j] for i in range(4)
           for j in range(i + 1, 4)):
        raise HardSubsetRefused(
            "REFUSED: the four observations reuse at least one shard path.")
    return build(population_id, load_full_gold(groups[0]),
                 load_full_gold(groups[1]), load_stripped(groups[2]),
                 load_stripped(groups[3]), load_fidelity(fidelity_path))


def validate(doc: dict, *, expected_population_id: Optional[str] = None) -> dict:
    """Fail closed on schema, registry identity, counts and canonical digest."""
    _exact(doc, TOP_FIELDS, "hard subset")
    if doc["schema"] != SCHEMA:
        raise HardSubsetRefused(
            f"REFUSED: hard subset schema is {doc['schema']!r}, not {SCHEMA!r}.")
    if expected_population_id is not None \
            and doc["population_id"] != expected_population_id:
        raise HardSubsetRefused(
            f"REFUSED: expected population {expected_population_id!r}, got "
            f"{doc['population_id']!r}.")
    try:
        entry = versions.population(doc["population_id"])
    except versions.ManifestError as exc:
        raise HardSubsetRefused(f"REFUSED: {exc}") from exc
    expected_population = {
        "project": entry["project"], "generation": entry["generation"],
        "manifest_digest": doc["population"].get("manifest_digest"),
        "engine": entry["engine"], "engine_version": entry["engine_version"],
        "parser": entry["parser"],
        "asset_index_sha256": entry["asset_index_sha256"],
    }
    if doc["population"] != expected_population \
            or doc["population"]["manifest_digest"] not in {
                entry["catalogue"]["manifest_digest"],
                entry["scored"]["manifest_digest"]}:
        raise HardSubsetRefused(
            "REFUSED: hard subset population facts differ from VERSIONS.yml.")
    if doc["n_full_gold_runs"] != 2 or doc["n_stripped_runs"] != 2:
        raise HardSubsetRefused(
            "REFUSED: hard subset requires exact N=2 full and N=2 stripped.")
    _exact(doc["runs"], RUN_GROUP_FIELDS, "hard subset.runs")
    observations = []
    for group in ("full_gold", "stripped_gold"):
        runs = doc["runs"][group]
        if not isinstance(runs, list) or len(runs) != 2:
            raise HardSubsetRefused(f"REFUSED: runs.{group} is not N=2.")
        for index, run in enumerate(runs, 1):
            gold_killset._exact(run, gold_killset.RUN_FIELDS,
                                f"hard subset {group} run")
            counts_ok = (
                isinstance(run["n_shards"], int)
                and not isinstance(run["n_shards"], bool)
                and run["n_shards"] > 0
                and all(isinstance(run[key], int)
                        and not isinstance(run[key], bool)
                        and run[key] >= 0 for key in ("n_rows", "n_pairs")))
            hashes_ok = (
                _sha(run["campaign_identity_sha256"])
                and _sha(run["pairs_sha256"])
                and isinstance(run["rows_sha256"], list)
                and isinstance(run["sidecars_sha256"], list)
                and len(run["rows_sha256"]) == run["n_shards"]
                and len(run["sidecars_sha256"]) == run["n_shards"]
                and all(_sha(value) for value in
                        run["rows_sha256"] + run["sidecars_sha256"]))
            try:
                mutation_run.validate_observation_id(run["observation_id"])
                observation_ok = True
            except mutation_run.MutationAborted:
                observation_ok = False
            if run["index"] != index or not counts_ok or not hashes_ok \
                    or not observation_ok \
                    or run["n_rows"] != run["n_pairs"]:
                raise HardSubsetRefused(
                    f"REFUSED: malformed {group} run {index} facts.")
            observations.append(run["observation_id"])
    if len(set(observations)) != 4:
        raise HardSubsetRefused(
            "REFUSED: hard subset run records are not four observations.")

    _exact(doc["pairs"], PAIRS_FIELDS, "hard subset.pairs")
    for key in ("full_n", "screened_n"):
        if not isinstance(doc["pairs"][key], int) \
                or isinstance(doc["pairs"][key], bool) \
                or doc["pairs"][key] < 0:
            raise HardSubsetRefused(f"REFUSED: pairs.{key} is invalid.")
    if doc["pairs"]["screened_n"] > doc["pairs"]["full_n"] \
            or not _sha(doc["pairs"]["full_sha256"]) \
            or not _sha(doc["pairs"]["screened_sha256"]):
        raise HardSubsetRefused("REFUSED: hard-subset pair identities are invalid.")
    if any(run["n_pairs"] != doc["pairs"]["full_n"]
           or run["pairs_sha256"] != doc["pairs"]["full_sha256"]
           for run in doc["runs"]["full_gold"]) \
            or any(run["n_pairs"] != doc["pairs"]["screened_n"]
                   or run["pairs_sha256"] != doc["pairs"]["screened_sha256"]
                   for run in doc["runs"]["stripped_gold"]):
        raise HardSubsetRefused(
            "REFUSED: run pair facts disagree with full/screened populations.")

    _exact(doc["fidelity"], FIDELITY_FIELDS, "hard subset.fidelity")
    fidelity = doc["fidelity"]
    count_keys = ("items_total", "items_passed", "items_excluded")
    if not all(isinstance(fidelity[key], int)
               and not isinstance(fidelity[key], bool)
               and fidelity[key] >= 0 for key in count_keys) \
            or not isinstance(fidelity["excluded"], list) \
            or not _sha(fidelity["baseline_sha256"]) \
            or not _sha(fidelity["passed_item_ids_sha256"]) \
            or not _sha(fidelity["generated_tests_sha256"]) \
            or fidelity["items_passed"] + fidelity["items_excluded"] \
            != fidelity["items_total"] \
            or len(fidelity["excluded"]) != fidelity["items_excluded"]:
        raise HardSubsetRefused("REFUSED: fidelity accounting does not conserve items.")
    seen_excluded = set()
    for value in fidelity["excluded"]:
        _exact(value, EXCLUDED_ITEM_FIELDS, "fidelity exclusion")
        if not isinstance(value["item_id"], str) or not value["item_id"] \
                or value["item_id"] in seen_excluded \
                or value["outcome"] == "passed":
            raise HardSubsetRefused("REFUSED: malformed fidelity exclusion.")
        _known_outcome(value["outcome"], "fidelity exclusion")
        seen_excluded.add(value["item_id"])

    _exact(doc["screen"], SCREEN_FIELDS, "hard subset.screen")
    screen = doc["screen"]
    for key in ("passed_both_count", "outcome_disagreement_count",
                "gold_pairs_removed_by_screen"):
        if not isinstance(screen[key], int) or isinstance(screen[key], bool) \
                or screen[key] < 0:
            raise HardSubsetRefused(f"REFUSED: screen.{key} is invalid.")
    if screen["passed_both_count"] > doc["pairs"]["screened_n"] \
            or screen["outcome_disagreement_count"] \
            > doc["pairs"]["screened_n"] \
            or not isinstance(screen["removed_gold_pairs"], list):
        raise HardSubsetRefused(
            "REFUSED: hard-subset screen counts exceed their population.")
    removed_pairs = []
    for value in doc["screen"]["removed_gold_pairs"]:
        _exact(value, REMOVED_FIELDS, "screened-out gold pair")
        pair = (value["item_id"], value["mutant_id"])
        reason = value["reason"]
        outcomes = (value["stripped_run_1_outcome"],
                    value["stripped_run_2_outcome"])
        malformed_reason = (
            reason == "fidelity_excluded"
            and (pair[0] not in seen_excluded or outcomes != (None, None))) \
            or (reason == "stripped_not_passed_both"
                and (None in outcomes or outcomes == ("passed", "passed"))) \
            or reason not in {"fidelity_excluded",
                              "stripped_not_passed_both"}
        if not all(isinstance(part, str) and part for part in pair) \
                or pair in removed_pairs or malformed_reason:
            raise HardSubsetRefused(
                "REFUSED: malformed or contradictory screened-out gold pair.")
        if reason == "stripped_not_passed_both":
            _known_outcome(outcomes[0], "screened stripped run 1")
            _known_outcome(outcomes[1], "screened stripped run 2")
        removed_pairs.append(pair)
    if screen["removed_gold_pairs"] != sorted(
            screen["removed_gold_pairs"],
            key=lambda value: (value["item_id"], value["mutant_id"])):
        raise HardSubsetRefused(
            "REFUSED: screened-out gold pairs are not canonical-sorted.")
    if len(removed_pairs) != doc["screen"]["gold_pairs_removed_by_screen"]:
        raise HardSubsetRefused(
            "REFUSED: screened-out pair list does not reproduce its count.")

    sets = {}
    for name in ("full_gold", "hard_subset"):
        block = doc[name]
        _exact(block, SET_FIELDS, f"hard subset.{name}")
        pairs = []
        if not isinstance(block["by_item"], dict):
            raise HardSubsetRefused(f"REFUSED: {name}.by_item is not an object.")
        for item, mutants in sorted(block["by_item"].items()):
            if not isinstance(item, str) or not item \
                    or not isinstance(mutants, list) or not mutants \
                    or not all(isinstance(mutant, str) and mutant
                               for mutant in mutants) \
                    or mutants != sorted(set(mutants)):
                raise HardSubsetRefused(f"REFUSED: malformed {name} item set.")
            pairs.extend((item, mutant) for mutant in mutants)
        pair_set = set(pairs)
        if len(pair_set) != block["count"] \
                or len(block["by_item"]) != block["items"] \
                or pair_digest(pair_set) != block["sha256"]:
            raise HardSubsetRefused(f"REFUSED: {name} set identity is invalid.")
        sets[name] = pair_set
    if not sets["hard_subset"] <= sets["full_gold"] \
            or sets["full_gold"] - sets["hard_subset"] != set(removed_pairs):
        raise HardSubsetRefused(
            "REFUSED: hard subset plus screened-out pairs does not reproduce "
            "the N=2 full-gold intersection.")
    if len(sets["full_gold"]) > doc["pairs"]["full_n"] \
            or len(sets["hard_subset"]) > doc["pairs"]["screened_n"]:
        raise HardSubsetRefused(
            "REFUSED: full/hard kill sets exceed their screened populations.")
    denominator = len(sets["full_gold"])
    expected_ratio = (None if denominator == 0 else
                      round(len(sets["hard_subset"]) / denominator, 6))
    if doc["full_gold"]["ratio"] != (None if denominator == 0 else 1.0) \
            or doc["hard_subset"]["ratio"] != expected_ratio:
        raise HardSubsetRefused("REFUSED: hard-subset ratio arithmetic fails.")
    expected_knife = sorted({item for item, _mid in sets["full_gold"]}
                            - {item for item, _mid in sets["hard_subset"]})
    if not isinstance(doc["knife_edge_items"], list) \
            or doc["knife_edge_items"] != expected_knife:
        raise HardSubsetRefused(
            "REFUSED: knife_edge_items does not name the empty-hard items.")
    if doc["digest"] != artifact_digest(doc):
        raise HardSubsetRefused(
            "REFUSED: hard subset digest does not match canonical content.")
    return doc


def load(path: str, *, expected_population_id: Optional[str] = None,
         require_pin: bool = False, versions_path: Optional[str] = None) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise HardSubsetRefused(
            f"REFUSED: cannot read hard subset {path}: {exc}") from exc
    validate(doc, expected_population_id=expected_population_id)
    if require_pin:
        validate_pin(doc, path, versions_path=versions_path)
    return doc


def validate_pin(doc: dict, path: str, *,
                 versions_path: Optional[str] = None) -> dict:
    """Require both canonical artifact digest and serialized-byte pin."""
    validate(doc)
    try:
        pin = versions.hard_subset_pin(doc["population_id"], versions_path)
    except versions.ManifestError as exc:
        raise HardSubsetRefused(f"REFUSED: {exc}") from exc
    if pin["artifact_digest"] != doc["digest"] \
            or pin["sha256"] != versions.sha256_file(path):
        raise HardSubsetRefused(
            "REFUSED: hard subset bytes/content differ from their VERSIONS.yml "
            "pin.")
    expected_path = os.path.realpath(os.path.join(
        os.path.dirname(versions_path or versions.DEFAULT_MANIFEST_PATH),
        pin["path"]))
    if os.path.realpath(path) != expected_path:
        raise HardSubsetRefused(
            f"REFUSED: population {doc['population_id']!r} pins hard subset "
            f"at {expected_path}, not {os.path.realpath(path)}.")
    return pin


def write(doc: dict, path: str) -> str:
    validate(doc)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    try:
        with open(path, "x", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1, sort_keys=True)
            fh.write("\n")
    except FileExistsError as exc:
        raise HardSubsetRefused(
            f"REFUSED: output already exists: {path}; use --check or a new "
            "immutable path.") from exc
    return path


def selftest() -> int:
    import tempfile

    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))
        ok = ok and bool(condition)

    def refuses(name, fn, needle):
        try:
            fn()
        except HardSubsetRefused as exc:
            check(name, needle in str(exc), str(exc))
            return
        check(name, False, "accepted")

    pairs = {("a", "m1"), ("a", "m2"), ("b", "m3")}
    digest = versions.population("python-docx-v1")["scored"][
        "manifest_digest"]
    identity = gold_killset._fixture_identity(
        manifest_digest=digest, expected_pairs=pairs)
    identity["harness_version"] = versions.component("harness")["version"]

    with tempfile.TemporaryDirectory(prefix="r2t-hard-fidelity-") as temp:
        fidelity_path = os.path.join(temp, "stripped.jsonl")
        fidelity_rows = [
            {"item_id": "a", "outcome": "passed",
             "adapter": "stripped-gold",
             "produced_files": [{"file_path": "steps.py", "code": "pass\n"}],
             "metadata": {"source": "stripped_gold",
                          "stripped_gold": True, "item_id": "a"}},
            {"item_id": "b", "outcome": "adapter_error",
             "adapter": "stripped-gold", "produced_files": [],
             "metadata": {"source": "stripped_gold",
                          "stripped_gold": True, "item_id": "b",
                          "adapter_error": "fixture refusal"}},
        ]

        def write_fidelity(rows):
            with open(fidelity_path, "w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row, sort_keys=True) + "\n")

        write_fidelity(fidelity_rows)
        loaded_fidelity = load_fidelity(fidelity_path)
        check("stripped fidelity authenticates adapter/source/flag/item per row",
              loaded_fidelity["outcomes"]
              == {"a": "passed", "b": "adapter_error"}
              and loaded_fidelity["reasons"]["b"] == "fixture refusal")
        for field, mutate in (
                ("adapter", lambda row: row.update({"adapter": "gold"})),
                ("source", lambda row: row["metadata"].update(
                    {"source": "gold"})),
                ("stripped flag", lambda row: row["metadata"].update(
                    {"stripped_gold": False})),
                ("metadata item", lambda row: row["metadata"].update(
                    {"item_id": "another-item"}))):
            forged = copy.deepcopy(fidelity_rows)
            mutate(forged[1])
            write_fidelity(forged)
            refuses(f"ordinary/misbound fidelity cannot spoof {field}",
                    lambda path=fidelity_path: load_fidelity(path),
                    "producer-authenticated stripped-gold")

    def fixture(outcomes, observation, side="gold", pair_set=None):
        ids = set(pair_set if pair_set is not None else outcomes)
        ident = copy.deepcopy(identity)
        ident["side"] = side
        if side == "candidate":
            ident["candidate_run_sha256"] = "f" * 64
        ident["expected_pairs"] = len(ids)
        ident["expected_pairs_sha256"] = pair_digest(ids)
        return {"identity": ident, "outcomes": outcomes,
                "facts": {"observation_id": observation,
                          "campaign_identity_sha256":
                              mutation_run.campaign_identity_digest(ident),
                          "rows_sha256": ["1" * 64],
                          "sidecars_sha256": ["2" * 64], "n_shards": 1,
                          "n_rows": len(ids), "n_pairs": len(ids),
                          "pairs_sha256": pair_digest(ids)}}

    full1 = fixture({("a", "m1"): "failed", ("a", "m2"): "failed",
                     ("b", "m3"): "passed"}, "1" * 32)
    full2 = fixture({("a", "m1"): "failed", ("a", "m2"): "failed",
                     ("b", "m3"): "failed"}, "2" * 32)
    strip1 = fixture({("a", "m1"): "passed", ("a", "m2"): "failed",
                      ("b", "m3"): "passed"}, "3" * 32, "candidate")
    strip2 = fixture({("a", "m1"): "passed", ("a", "m2"): "passed",
                      ("b", "m3"): "passed"}, "4" * 32, "candidate")
    fidelity = {"outcomes": {"a": "passed", "b": "passed"},
                "reasons": {"a": None, "b": None}, "sha256": "f" * 64,
                "generated_tests_sha256": "6" * 64}

    def as_reference(run, role, workload_digest):
        result = copy.deepcopy(run)
        old = result["identity"]
        reference = {key: old[key]
                     for key in mutation_run.CAMPAIGN_IDENTITY_FIELDS_V1}
        reference.update({
            "schema": mutation_run.MUTATION_IDENTITY_SCHEMA_V5,
            "generation_provenance_class":
                mutation_run.GENERATION_PROVENANCE_REFERENCE_CONTROL,
            "reference_control_role": role,
            "reference_source_tag": "docx-reference-v1",
            "reference_workload_digest": workload_digest,
        })
        result["identity"] = reference
        result["facts"]["campaign_identity_sha256"] = \
            mutation_run.campaign_identity_digest(reference)
        return result

    reference_doc = build(
        "python-docx-v1",
        as_reference(full1, "full-gold", "a" * 64),
        as_reference(full2, "full-gold", "b" * 64),
        as_reference(strip1, "assertion-stripped-gold", "c" * 64),
        as_reference(strip2, "assertion-stripped-gold", "d" * 64),
        fidelity)
    check("hard-subset admits correctly role-bound full and stripped "
          "exact-byte reference controls",
          reference_doc["hard_subset"]["by_item"] == {"a": ["m1"]})

    def at_harness(run, version, project=None):
        moved = copy.deepcopy(run)
        moved["identity"]["harness_version"] = version
        if project is not None:
            moved["identity"]["asset_project"] = project
        moved["facts"]["campaign_identity_sha256"] = \
            mutation_run.campaign_identity_digest(moved["identity"])
        return moved

    # Owner ruling 2026-09-15: VERSIONS.yml lists harness 12 as compatible
    # for python-docx at the current harness, and not for coreshop.
    h12 = [at_harness(run, 12) for run in (full1, full2, strip1, strip2)]
    check("python-docx runs recorded at harness 12 build at the current "
          "harness, which VERSIONS.yml declares compatible for python-docx",
          build("python-docx-v1", *h12, fidelity)["hard_subset"]["by_item"]
          == {"a": ["m1"]})
    refuses("a coreshop run recorded at harness 12 still refuses",
            lambda: build("coreshop-v1", at_harness(full1, 12, "coreshop"),
                          full2, strip1, strip2, fidelity),
            "uses harness version 12")
    wrong_reference = as_reference(strip1, "stub-control", "e" * 64)
    refuses("hard-subset rejects a reference role swap",
            lambda: build("python-docx-v1", full1, full2, wrong_reference,
                          strip2, fidelity), "not publishable")
    doc = build("python-docx-v1", full1, full2, strip1, strip2, fidelity)
    check("hard means full failed in both AND stripped passed in both",
          doc["full_gold"]["count"] == 2
          and doc["hard_subset"]["by_item"] == {"a": ["m1"]}
          and doc["hard_subset"]["ratio"] == 0.5, str(doc["hard_subset"]))
    check("the stripped-killed gold mutant remains an auditable witness",
          doc["screen"]["removed_gold_pairs"] == [{
              "item_id": "a", "mutant_id": "m2",
              "stripped_run_1_outcome": "failed",
              "stripped_run_2_outcome": "passed",
              "reason": "stripped_not_passed_both"}])
    check("empty hard items are published as knife-edge items",
          doc["knife_edge_items"] == [], str(doc["knife_edge_items"]))
    check("artifact validates after canonical round trip", validate(doc) == doc)
    reused = copy.deepcopy(strip2)
    reused["facts"]["observation_id"] = "3" * 32
    refuses("four claimed runs cannot reuse an observation",
            lambda: build("python-docx-v1", full1, full2, strip1, reused,
                          fidelity), "four distinct")
    unpublishable = copy.deepcopy(full1)
    unpublishable["identity"]["generation_provenance_class"] = "fixture"
    unpublishable["identity"]["generation_attempt_id"] = None
    unpublishable["identity"]["generation_agent_runtime_sha256"] = None
    unpublishable["identity"]["generation_network_semantics"] = None
    unpublishable["facts"]["campaign_identity_sha256"] = \
        mutation_run.campaign_identity_digest(unpublishable["identity"])
    refuses("fixture-class observations cannot populate release evidence",
            lambda: build("python-docx-v1", unpublishable, full2, strip1,
                          strip2, fidelity), "unpublishable generation")
    stale_fidelity_1, stale_fidelity_2 = (copy.deepcopy(strip1),
                                          copy.deepcopy(strip2))
    for stale_fidelity in (stale_fidelity_1, stale_fidelity_2):
        stale_fidelity["identity"]["candidate_run_sha256"] = "e" * 64
        stale_fidelity["facts"]["campaign_identity_sha256"] = \
            mutation_run.campaign_identity_digest(stale_fidelity["identity"])
    refuses("stripped mutations bind the exact fidelity run bytes",
            lambda: build("python-docx-v1", full1, full2, stale_fidelity_1,
                          stale_fidelity_2, fidelity), "exact run/generated")
    def shortened(run):
        short = copy.deepcopy(run)
        short["outcomes"].pop(("b", "m3"))
        short["facts"]["n_rows"] = short["facts"]["n_pairs"] = 2
        short["facts"]["pairs_sha256"] = pair_digest(short["outcomes"])
        short["identity"]["expected_pairs"] = 2
        short["identity"]["expected_pairs_sha256"] = pair_digest(
            short["outcomes"])
        short["facts"]["campaign_identity_sha256"] = \
            mutation_run.campaign_identity_digest(short["identity"])
        return short
    short1, short2 = shortened(strip1), shortened(strip2)
    refuses("a short stripped witness refuses instead of shrinking the screen",
            lambda: build("python-docx-v1", full1, full2, short1, short2,
                          fidelity), "complete over exactly")
    full1_excluded = copy.deepcopy(full1)
    full1_excluded["outcomes"][("b", "m3")] = "failed"
    fidelity_excluded = {
        "outcomes": {"a": "passed", "b": "adapter_error"},
        "reasons": {"a": None, "b": "fixture adapter failure"},
        "sha256": "f" * 64, "generated_tests_sha256": "6" * 64,
    }
    excluded_doc = build("python-docx-v1", full1_excluded, full2,
                         short1, short2, fidelity_excluded)
    check("fidelity exclusions remain explicit instead of fabricating outcomes",
          excluded_doc["screen"]["removed_gold_pairs"][-1] == {
              "item_id": "b", "mutant_id": "m3",
              "stripped_run_1_outcome": None,
              "stripped_run_2_outcome": None,
              "reason": "fidelity_excluded",
          } and excluded_doc["knife_edge_items"] == ["b"],
          str(excluded_doc["screen"]["removed_gold_pairs"]))
    print("\n" + ("ALL PASS (hard_subset)" if ok
                    else "FAILURES (hard_subset)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
