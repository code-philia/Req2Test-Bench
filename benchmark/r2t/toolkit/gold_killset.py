"""Build and verify a two-run, population-pinned gold kill set.

One gold sweep is an observation, not a stable oracle.  This module consumes
exactly two complete native gold campaigns and records the conservative
intersection of their ``failed`` outcomes.  It also preserves every kill flip
and every other outcome disagreement, so nondeterminism can never disappear
inside a smaller headline set.

The artifact contains content identities only.  Operator paths belong in a
command log; mutable absolute paths do not belong in release evidence.
"""
from __future__ import annotations

import copy
import json
import os
from typing import Iterable, Optional

from ..data import mutation
from ..bench import mutation_run
from ..data import versions


SCHEMA = "r2t.gold-killset/1"
TOP_FIELDS = frozenset({
    "schema", "population_id", "population", "n_runs", "runs", "pairs",
    "kills", "outcome_disagreements", "digest",
})
#: Added beside `population` when the two observations ran a budgeted derived
#: map.  `population` stays the registry's own facts -- the registered
#: manifest is still the manifest these mutants come from -- so without these
#: two keys a budgeted killset would be indistinguishable from the full
#: population's, which is the one thing it must never be.
BUDGETED_TOP_FIELDS = frozenset({
    "population_basis", "budgeted_sample_sha256",
})
POPULATION_FIELDS = frozenset({
    "project", "generation", "manifest_digest", "engine",
    "engine_version", "parser", "asset_index_sha256",
})
RUN_FIELDS = frozenset({
    "index", "observation_id", "campaign_identity_sha256", "rows_sha256",
    "sidecars_sha256", "n_shards", "n_rows", "n_pairs", "pairs_sha256",
})
PAIR_FIELDS = frozenset({"n", "sha256"})
KILL_FIELDS = frozenset({
    "run_counts", "union_count", "intersection_count", "flip_count",
    "by_item", "flips",
})
FLIP_FIELDS = frozenset({
    "item_id", "mutant_id", "run_1_outcome", "run_2_outcome",
    "killed_in_run",
})
DISAGREEMENT_FIELDS = frozenset({
    "item_id", "mutant_id", "run_1_outcome", "run_2_outcome",
})

# These fields define what code/population was exercised.  Two observations
# may use different worker pools and therefore different full campaign
# identities, but they may not silently change any of these facts.
SHARED_CAMPAIGN_FIELDS = frozenset({
    "schema", "kind", "asset_index_sha256", "asset_project",
    "mutation_validation_sha256", "mutation_validation_class",
    "manifest_sha256", "manifest_digest", "map_sha256", "release_sha256",
    "candidate_run_sha256", "candidate_generated_tests_sha256",
    "solution_generated_tests_sha256", "substrate_baseline_sha256",
    "applier_sha256", "harness_version", "container_image_digest",
    "workspace_seed_digest", "database_dump_digest", "engine",
    "engine_version", "parser", "side", "timeout_seconds", "sample",
    "sample_seed", "expected_pairs", "expected_pairs_sha256",
    "generation_provenance_class", "generation_attempt_id",
    "generation_campaign_digest", "generation_agent_runtime_sha256",
    "generation_network_semantics", "generation_condition",
    "generation_protocol_version", "generation_protocol_digest",
    "generation_native_budget",
    "reference_control_role", "reference_source_tag",
    # WHICH POPULATION, not merely which map file.  `map_sha256` already
    # separates a derived map from its parent, but only these three say
    # whether the map that ran is a declared budget and which sidecar
    # declared it, so a full leg and a budgeted one -- or two budgeted legs
    # citing different sidecars -- cannot be joined as two observations of
    # one population.  Absent on both sides for a full population, which is
    # how every historical pair keeps joining.
    "population_basis", "budgeted_sample_sha256", "parent_map_sha256",
})


class GoldKillsetRefused(ValueError):
    """The proposed artifact is not two observations of one population."""


_NATIVE_RUN_SEAL = object()


class _ValidatedNativeRun(dict):
    """Mutable-dict-compatible record with a private byte-validation seal."""

    def __init__(self, value: dict, seal: object, *,
                 paths: Iterable[str] = (), snapshot: Optional[dict] = None):
        super().__init__(value)
        self._seal = seal
        self._paths = tuple(paths)
        self._snapshot = copy.deepcopy(value if snapshot is None else snapshot)

    def __deepcopy__(self, memo):
        return _ValidatedNativeRun(
            copy.deepcopy(dict(self), memo), self._seal,
            paths=copy.deepcopy(self._paths, memo),
            snapshot=copy.deepcopy(self._snapshot, memo))


def authenticated_native_run(value: object) -> bool:
    """Whether a record is the unchanged result of ``load_native_run``."""
    return isinstance(value, _ValidatedNativeRun) \
        and value._seal is _NATIVE_RUN_SEAL \
        and dict(value) == value._snapshot


def native_run_paths(value: object) -> tuple[str, ...]:
    """Return the exact raw inventory paths of an authenticated native run."""
    if not authenticated_native_run(value) or not value._paths:
        raise GoldKillsetRefused(
            "REFUSED: native gold record has no authenticated raw inventory.")
    return value._paths


def _exact(value, fields: frozenset[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        got = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise GoldKillsetRefused(
            f"REFUSED: {label} must contain exactly {sorted(fields)}; got "
            f"{got}.")


def _sha(value) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(ch in "0123456789abcdef" for ch in value))


def _observation_id(value) -> str:
    try:
        return mutation_run.validate_observation_id(value)
    except mutation_run.MutationAborted as exc:
        raise GoldKillsetRefused(str(exc)) from exc


def artifact_digest(doc: dict) -> str:
    """Digest the artifact without its self-referential ``digest`` field."""
    if not isinstance(doc, dict):
        raise GoldKillsetRefused("REFUSED: gold killset is not an object.")
    return mutation_run.content_digest(
        {key: value for key, value in doc.items() if key != "digest"})


def _population_claim(population_id: str, identity: dict) -> dict:
    try:
        resolved = versions.population_id_for(
            identity.get("asset_project"), identity.get("manifest_digest"),
            engine=identity.get("engine"),
            engine_version=identity.get("engine_version"))
        entry = versions.population(population_id)
        indexes = (entry["asset_index_sha256"],
                   *versions.equivalent_asset_indexes(population_id))
    except versions.ManifestError as exc:
        raise GoldKillsetRefused(f"REFUSED: {exc}") from exc
    if resolved != population_id:
        raise GoldKillsetRefused(
            f"REFUSED: native campaign resolves to population {resolved!r}, "
            f"not requested {population_id!r}.")
    # A ruled envelope equivalence says the registered index and the renamed
    # one name this same population, so a campaign stamped with either is
    # this population's evidence.  The claim below still records the
    # registered digest: that is the identity the population is registered
    # under, and `validate` reads it back from the registry.
    index = identity.get("asset_index_sha256")
    if index not in indexes:
        raise GoldKillsetRefused(
            f"REFUSED: native campaign's asset index {index!r} is neither "
            f"{population_id}'s registered {indexes[0]!r} nor a ruled "
            f"envelope-equivalent {list(indexes[1:])!r}.")
    if identity.get("parser") != entry["parser"]:
        raise GoldKillsetRefused(
            "REFUSED: native campaign's parser differs from the population "
            "registry.")
    return {
        "project": entry["project"],
        "generation": entry["generation"],
        "manifest_digest": identity["manifest_digest"],
        "engine": entry["engine"],
        "engine_version": entry["engine_version"],
        "parser": entry["parser"],
        "asset_index_sha256": entry["asset_index_sha256"],
    }


def _known_outcome(outcome) -> str:
    if not isinstance(outcome, str) or not outcome:
        raise GoldKillsetRefused(
            f"REFUSED: native gold row has invalid outcome {outcome!r}.")
    try:
        # A timeout is deliberately accepted but is not a kill here.  The
        # population-v2 owner ruling keeps the gold kill definition at the
        # literal outcome `failed`; timeout remains disclosed evidence.
        mutation.classify_outcome("timeout", outcome)
    except ValueError as exc:
        raise GoldKillsetRefused(str(exc)) from exc
    return outcome


def load_native_run(paths: Iterable[str], *,
                    expected_jobs: Optional[Iterable[dict]] = None,
                    required_side: str = "gold") -> dict:
    """Load one exact complete native gold campaign and its byte facts.

    When a producer supplies ``expected_jobs``, the retained shard identities,
    paths, and exact pair partitions must equal the pre-execution plan.  This
    is the join a self-consistent campaign alone cannot establish.
    """
    if required_side not in {"candidate", "gold"}:
        raise GoldKillsetRefused(
            f"REFUSED: unknown native observation side {required_side!r}.")
    paths = list(paths)
    try:
        campaign = mutation_run.validate_native_shards(
            paths, required_side=required_side, return_campaign=True)
    except (mutation_run.MutationAborted, OSError, ValueError) as exc:
        raise GoldKillsetRefused(str(exc)) from exc
    identity = campaign["campaign_identity"]
    if identity.get("kind") != "mutation-run":
        raise GoldKillsetRefused(
            "REFUSED: a reusable observation must be built from standalone "
            "mutation-run campaigns, not test-quality cache shards.")
    if identity.get("sample") is not None \
            or identity.get("sample_seed") is not None:
        raise GoldKillsetRefused(
            "REFUSED: a release gold killset requires the complete unsampled "
            "population (sample and sample_seed must both be null).")
    observation_id = campaign.get("observation_id")
    if observation_id is None:
        raise GoldKillsetRefused(
            "REFUSED: a release gold observation must use a current v2 "
            "standalone output plan with an observation_id; v1 evidence "
            "remains readable but cannot establish N=2 independence.")
    _observation_id(observation_id)

    outcomes = {}
    for row in campaign["rows"]:
        pair = (row.get("item_id"), row.get("mutant_id"))
        if pair in outcomes:
            raise GoldKillsetRefused(
                f"REFUSED: native campaign repeats pair {pair!r}.")
        outcomes[pair] = _known_outcome(row.get("outcome"))
    if set(outcomes) != campaign["pairs"]:
        raise GoldKillsetRefused(
            "REFUSED: native campaign rows and validated pair union differ.")

    planned = None
    if expected_jobs is not None:
        jobs = list(expected_jobs)
        try:
            planned = {job["identity"]["shard"]: job for job in jobs}
        except (KeyError, TypeError) as exc:
            raise GoldKillsetRefused(
                "REFUSED: planned gold jobs have malformed identities.") \
                from exc
        if len(planned) != len(jobs) or len(jobs) != len(paths):
            raise GoldKillsetRefused(
                "REFUSED: planned gold jobs do not name the exact retained "
                "shard count.")
    campaign_shards = {
        shard["shard"]: shard for shard in campaign["shards"]}
    shard_facts = []
    for path in paths:
        sidecar_path = mutation_run.provenance_path(path)
        with open(sidecar_path, encoding="utf-8") as fh:
            sidecar = json.load(fh)
        saved_identity = sidecar["campaign_identity"]
        shard = saved_identity["shard"]
        if planned is not None:
            job = planned.get(shard)
            expected = (set(job.get("expected_pairs") or [])
                        if isinstance(job, dict) else set())
            if job is None or saved_identity != job.get("identity") \
                    or os.path.realpath(os.path.abspath(path)) \
                    != os.path.realpath(os.path.abspath(job.get("out", ""))) \
                    or expected != campaign_shards[shard]["pairs"]:
                raise GoldKillsetRefused(
                    "REFUSED: retained gold shard differs from its exact "
                    f"authorized job for worker {shard}.")
        shard_facts.append((shard, {
            "rows_sha256": mutation_run.sha256_file(path),
            "sidecar_sha256": mutation_run.sha256_file(sidecar_path),
        }))
    shard_facts.sort(key=lambda value: value[0])
    facts = {
        "observation_id": observation_id,
        "campaign_identity_sha256":
            mutation_run.campaign_identity_digest(identity),
        "rows_sha256": [value["rows_sha256"] for _n, value in shard_facts],
        "sidecars_sha256": [value["sidecar_sha256"]
                            for _n, value in shard_facts],
        "n_shards": len(shard_facts),
        "n_rows": len(campaign["rows"]),
        "n_pairs": len(outcomes),
        "pairs_sha256": mutation_run.pair_set_digest(outcomes),
    }
    return _ValidatedNativeRun({
        "identity": identity, "outcomes": outcomes, "facts": facts,
    }, _NATIVE_RUN_SEAL,
        paths=tuple(os.path.realpath(os.path.abspath(path)) for path in paths))


def validate_observation_pair(run_1: dict, run_2: dict) -> dict:
    """Validate and derive the existing conservative two-run gold facts."""
    for number, run in enumerate((run_1, run_2), 1):
        if not isinstance(run, dict) \
                or not isinstance(run.get("identity"), dict) \
                or not isinstance(run.get("outcomes"), dict) \
                or not isinstance(run.get("facts"), dict):
            raise GoldKillsetRefused(
                f"REFUSED: run {number} is not a validated native-run record.")
        _observation_id(run["facts"].get("observation_id"))
    if run_1["facts"]["observation_id"] \
            == run_2["facts"]["observation_id"]:
        raise GoldKillsetRefused(
            "REFUSED: the two gold inputs carry the same observation_id; "
            "N=2 requires two independently claimed standalone outputs.")
    identities = [run_1["identity"], run_2["identity"]]
    for identity in identities:
        try:
            mutation_run._validate_campaign_identity(identity)
            mutation_run.validate_publishable_generation(
                identity, reference_roles={"full-gold"})
        except mutation_run.MutationAborted as exc:
            raise GoldKillsetRefused(str(exc)) from exc
        if identity.get("side") != "gold" or identity.get("kind") != "mutation-run":
            raise GoldKillsetRefused(
                "REFUSED: both inputs must be standalone gold mutation runs.")
        if identity.get("sample") is not None \
                or identity.get("sample_seed") is not None:
            raise GoldKillsetRefused(
                "REFUSED: both inputs must cover an unsampled population.")
    changed = sorted(key for key in SHARED_CAMPAIGN_FIELDS
                     if identities[0].get(key) != identities[1].get(key))
    if changed:
        raise GoldKillsetRefused(
            f"REFUSED: the two gold observations differ in population or "
            f"execution field(s) {changed}.")

    outcomes = [run_1["outcomes"], run_2["outcomes"]]
    for number, values in enumerate(outcomes, 1):
        for pair, outcome in values.items():
            if not isinstance(pair, tuple) or len(pair) != 2 \
                    or not all(isinstance(value, str) and value
                               for value in pair):
                raise GoldKillsetRefused(
                    f"REFUSED: run {number} has malformed pair {pair!r}.")
            _known_outcome(outcome)
    pair_sets = [set(values) for values in outcomes]
    if pair_sets[0] != pair_sets[1]:
        raise GoldKillsetRefused(
            f"REFUSED: gold observations have different pair populations: "
            f"{len(pair_sets[0] - pair_sets[1])} only in run 1 and "
            f"{len(pair_sets[1] - pair_sets[0])} only in run 2.")
    pair_digest = mutation_run.pair_set_digest(pair_sets[0])
    if any(run["facts"].get("n_pairs") != len(pair_sets[0])
           or run["facts"].get("pairs_sha256") != pair_digest
           for run in (run_1, run_2)):
        raise GoldKillsetRefused(
            "REFUSED: a run's preserved pair facts differ from its rows.")

    killed = [{pair for pair, outcome in values.items()
               if outcome == "failed"} for values in outcomes]
    intersection = killed[0] & killed[1]
    union = killed[0] | killed[1]
    flip_pairs = killed[0] ^ killed[1]
    by_item: dict[str, list[str]] = {}
    for item_id, mutant_id in sorted(intersection):
        by_item.setdefault(item_id, []).append(mutant_id)
    flips = [{
        "item_id": pair[0], "mutant_id": pair[1],
        "run_1_outcome": outcomes[0][pair],
        "run_2_outcome": outcomes[1][pair],
        "killed_in_run": 1 if pair in killed[0] else 2,
    } for pair in sorted(flip_pairs)]
    disagreements = [{
        "item_id": pair[0], "mutant_id": pair[1],
        "run_1_outcome": outcomes[0][pair],
        "run_2_outcome": outcomes[1][pair],
    } for pair in sorted(pair_sets[0])
        if outcomes[0][pair] != outcomes[1][pair]]

    return {
        "identities": identities,
        "outcomes": outcomes,
        "pairs": pair_sets[0],
        "pairs_sha256": pair_digest,
        "killed": killed,
        "intersection": intersection,
        "union": union,
        "flip_pairs": flip_pairs,
        "by_item": by_item,
        "flips": flips,
        "outcome_disagreements": disagreements,
    }


def build(population_id: str, run_1: dict, run_2: dict) -> dict:
    """Build an artifact from two already validated native-run records."""
    joined = validate_observation_pair(run_1, run_2)
    population = _population_claim(population_id, joined["identities"][0])

    runs = []
    for index, run in enumerate((run_1, run_2), 1):
        facts = dict(run["facts"])
        facts["index"] = index
        runs.append(facts)
    doc = {
        "schema": SCHEMA,
        "population_id": population_id,
        "population": population,
        "n_runs": 2,
        "runs": runs,
        "pairs": {"n": len(joined["pairs"]),
                  "sha256": joined["pairs_sha256"]},
        "kills": {
            "run_counts": [len(value) for value in joined["killed"]],
            "union_count": len(joined["union"]),
            "intersection_count": len(joined["intersection"]),
            "flip_count": len(joined["flip_pairs"]),
            "by_item": joined["by_item"],
            "flips": joined["flips"],
        },
        "outcome_disagreements": joined["outcome_disagreements"],
    }
    identity = joined["identities"][0]
    if identity.get("population_basis") is not None:
        # Agreed across both observations by SHARED_CAMPAIGN_FIELDS above,
        # so either one says it.
        doc["population_basis"] = identity["population_basis"]
        doc["budgeted_sample_sha256"] = identity["budgeted_sample_sha256"]
    doc["digest"] = artifact_digest(doc)
    validate(doc)
    return doc


def build_from_paths(population_id: str, run_1_paths: Iterable[str],
                     run_2_paths: Iterable[str]) -> dict:
    """Validate native bytes, then build their two-run killset artifact."""
    path_sets = [list(run_1_paths), list(run_2_paths)]
    resolved_sets = [{os.path.realpath(os.path.abspath(path))
                      for path in paths} for paths in path_sets]
    overlap = resolved_sets[0] & resolved_sets[1]
    if overlap:
        raise GoldKillsetRefused(
            f"REFUSED: the two gold observations reuse shard path(s) "
            f"{sorted(overlap)}.")
    inode_sets = []
    for number, paths in enumerate(path_sets, 1):
        identities = set()
        for path in paths:
            try:
                stat = os.stat(path, follow_symlinks=False)
            except OSError as exc:
                raise GoldKillsetRefused(
                    f"REFUSED: cannot stat gold run {number} shard {path}: "
                    f"{exc}") from exc
            identities.add((stat.st_dev, stat.st_ino))
        inode_sets.append(identities)
    if inode_sets[0] & inode_sets[1]:
        raise GoldKillsetRefused(
            "REFUSED: the two gold observations reuse the same shard inode "
            "through different paths.")
    return build(population_id, load_native_run(path_sets[0]),
                 load_native_run(path_sets[1]))


def validate(doc: dict, *, expected_population_id: Optional[str] = None) -> dict:
    """Fail closed on schema, registry binding, arithmetic and digest."""
    _exact(doc, (TOP_FIELDS | BUDGETED_TOP_FIELDS
                 if set(doc) & BUDGETED_TOP_FIELDS else TOP_FIELDS),
           "gold killset")
    if "population_basis" in doc:
        if doc["population_basis"] != mutation_run.BUDGETED_POPULATION_BASIS:
            raise GoldKillsetRefused(
                f"REFUSED: gold killset population_basis is "
                f"{doc['population_basis']!r}, not "
                f"{mutation_run.BUDGETED_POPULATION_BASIS!r}.")
        if not isinstance(doc["budgeted_sample_sha256"], str) \
                or len(doc["budgeted_sample_sha256"]) != 64:
            raise GoldKillsetRefused(
                "REFUSED: gold killset budgeted_sample_sha256 is not a full "
                "SHA-256.")
    if doc["schema"] != SCHEMA:
        raise GoldKillsetRefused(
            f"REFUSED: gold killset schema is {doc['schema']!r}, not {SCHEMA!r}.")
    if expected_population_id is not None \
            and doc["population_id"] != expected_population_id:
        raise GoldKillsetRefused(
            f"REFUSED: expected population {expected_population_id!r}, got "
            f"{doc['population_id']!r}.")
    _exact(doc["population"], POPULATION_FIELDS, "gold killset.population")
    try:
        entry = versions.population(doc["population_id"])
    except versions.ManifestError as exc:
        raise GoldKillsetRefused(f"REFUSED: {exc}") from exc
    expected_population = {
        "project": entry["project"],
        "generation": entry["generation"],
        "manifest_digest": doc["population"]["manifest_digest"],
        "engine": entry["engine"],
        "engine_version": entry["engine_version"],
        "parser": entry["parser"],
        "asset_index_sha256": entry["asset_index_sha256"],
    }
    if doc["population"] != expected_population \
            or doc["population"]["manifest_digest"] not in {
                entry["catalogue"]["manifest_digest"],
                entry["scored"]["manifest_digest"],
            }:
        raise GoldKillsetRefused(
            "REFUSED: gold killset population facts differ from VERSIONS.yml.")
    if doc["n_runs"] != 2 or not isinstance(doc["runs"], list) \
            or len(doc["runs"]) != 2:
        raise GoldKillsetRefused(
            "REFUSED: gold killset must contain exactly two run records.")
    for index, run in enumerate(doc["runs"], 1):
        _exact(run, RUN_FIELDS, f"gold killset.runs[{index - 1}]")
        if run["index"] != index or not all(
                isinstance(run[key], int) and not isinstance(run[key], bool)
                and run[key] > 0
                for key in ("n_shards", "n_rows", "n_pairs")):
            raise GoldKillsetRefused(
                f"REFUSED: run {index} has invalid index/count fields.")
        if run["n_rows"] != run["n_pairs"]:
            raise GoldKillsetRefused(
                f"REFUSED: run {index} does not contain one row per pair.")
        if not _sha(run["campaign_identity_sha256"]) \
                or not _sha(run["pairs_sha256"]) \
                or not isinstance(run["rows_sha256"], list) \
                or not isinstance(run["sidecars_sha256"], list) \
                or len(run["rows_sha256"]) != run["n_shards"] \
                or len(run["sidecars_sha256"]) != run["n_shards"] \
                or not all(_sha(value) for value in
                           run["rows_sha256"] + run["sidecars_sha256"]):
            raise GoldKillsetRefused(
                f"REFUSED: run {index} has malformed content identities.")
        _observation_id(run["observation_id"])
    if doc["runs"][0]["observation_id"] \
            == doc["runs"][1]["observation_id"]:
        raise GoldKillsetRefused(
            "REFUSED: gold run records do not represent two distinct "
            "observations.")
    _exact(doc["pairs"], PAIR_FIELDS, "gold killset.pairs")
    if not isinstance(doc["pairs"]["n"], int) \
            or isinstance(doc["pairs"]["n"], bool) \
            or doc["pairs"]["n"] < 1 or not _sha(doc["pairs"]["sha256"]):
        raise GoldKillsetRefused("REFUSED: gold killset pair facts are invalid.")
    if any(run["n_pairs"] != doc["pairs"]["n"]
           or run["pairs_sha256"] != doc["pairs"]["sha256"]
           for run in doc["runs"]):
        raise GoldKillsetRefused(
            "REFUSED: run pair facts disagree with the artifact population.")

    kills = doc["kills"]
    _exact(kills, KILL_FIELDS, "gold killset.kills")
    if not isinstance(kills["run_counts"], list) \
            or len(kills["run_counts"]) != 2 \
            or not all(isinstance(value, int) and not isinstance(value, bool)
                       and 0 <= value <= doc["pairs"]["n"]
                       for value in kills["run_counts"]):
        raise GoldKillsetRefused("REFUSED: kill run_counts are invalid.")
    for key in ("union_count", "intersection_count", "flip_count"):
        value = kills[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise GoldKillsetRefused(f"REFUSED: kills.{key} is invalid.")
    if kills["union_count"] - kills["intersection_count"] \
            != kills["flip_count"] \
            or sum(kills["run_counts"]) \
            != kills["union_count"] + kills["intersection_count"] \
            or kills["union_count"] > doc["pairs"]["n"]:
        raise GoldKillsetRefused("REFUSED: kill union/intersection arithmetic fails.")
    if not isinstance(kills["by_item"], dict):
        raise GoldKillsetRefused("REFUSED: kills.by_item is not an object.")
    intersection_pairs = []
    for item_id, mutant_ids in sorted(kills["by_item"].items()):
        if not isinstance(item_id, str) or not item_id \
                or not isinstance(mutant_ids, list) or not mutant_ids \
                or mutant_ids != sorted(set(mutant_ids)) \
                or not all(isinstance(value, str) and value
                           for value in mutant_ids):
            raise GoldKillsetRefused(
                f"REFUSED: malformed intersection list for item {item_id!r}.")
        intersection_pairs.extend((item_id, mutant_id)
                                  for mutant_id in mutant_ids)
    if len(intersection_pairs) != kills["intersection_count"]:
        raise GoldKillsetRefused(
            "REFUSED: kills.by_item does not reproduce intersection_count.")
    if not isinstance(kills["flips"], list) \
            or len(kills["flips"]) != kills["flip_count"]:
        raise GoldKillsetRefused("REFUSED: flips do not reproduce flip_count.")
    seen_flips = set()
    flip_records = {}
    for flip in kills["flips"]:
        _exact(flip, FLIP_FIELDS, "gold killset flip")
        pair = (flip["item_id"], flip["mutant_id"])
        if pair in seen_flips or not all(
                isinstance(value, str) and value for value in pair) \
                or flip["killed_in_run"] not in (1, 2) \
                or (flip["run_1_outcome"] == "failed") \
                == (flip["run_2_outcome"] == "failed") \
                or (flip["killed_in_run"] == 1) \
                != (flip["run_1_outcome"] == "failed"):
            raise GoldKillsetRefused(f"REFUSED: malformed kill flip {flip!r}.")
        _known_outcome(flip["run_1_outcome"])
        _known_outcome(flip["run_2_outcome"])
        seen_flips.add(pair)
        flip_records[pair] = (
            flip["run_1_outcome"], flip["run_2_outcome"],
            flip["killed_in_run"])
    if kills["flips"] != sorted(
            kills["flips"], key=lambda value: (value["item_id"],
                                                value["mutant_id"])):
        raise GoldKillsetRefused("REFUSED: kill flips are not canonical-sorted.")
    intersection_set = set(intersection_pairs)
    if intersection_set & seen_flips:
        raise GoldKillsetRefused(
            "REFUSED: an intersection kill is also recorded as a flip.")
    expected_run_counts = [
        len(intersection_set)
        + sum(record[2] == run for record in flip_records.values())
        for run in (1, 2)
    ]
    if kills["run_counts"] != expected_run_counts \
            or kills["intersection_count"] != len(intersection_set) \
            or kills["flip_count"] != len(seen_flips) \
            or kills["union_count"] != len(intersection_set | seen_flips):
        raise GoldKillsetRefused(
            "REFUSED: kill counts do not reproduce the intersection and "
            "oriented flips.")

    disagreements = doc["outcome_disagreements"]
    if not isinstance(disagreements, list):
        raise GoldKillsetRefused("REFUSED: outcome_disagreements is not a list.")
    seen_disagreements = set()
    disagreement_records = {}
    for disagreement in disagreements:
        _exact(disagreement, DISAGREEMENT_FIELDS,
               "gold killset outcome disagreement")
        pair = (disagreement["item_id"], disagreement["mutant_id"])
        if not all(isinstance(value, str) and value for value in pair) \
                or pair in seen_disagreements \
                or disagreement["run_1_outcome"] \
                == disagreement["run_2_outcome"]:
            raise GoldKillsetRefused(
                f"REFUSED: malformed outcome disagreement {disagreement!r}.")
        _known_outcome(disagreement["run_1_outcome"])
        _known_outcome(disagreement["run_2_outcome"])
        seen_disagreements.add(pair)
        disagreement_records[pair] = (
            disagreement["run_1_outcome"],
            disagreement["run_2_outcome"])
    if disagreements != sorted(
            disagreements, key=lambda value: (value["item_id"],
                                                value["mutant_id"])) \
            or len(seen_disagreements) > doc["pairs"]["n"]:
        raise GoldKillsetRefused(
            "REFUSED: outcome disagreements are unsorted or exceed the "
            "population.")
    if intersection_set & seen_disagreements:
        raise GoldKillsetRefused(
            "REFUSED: an intersection kill cannot also carry an outcome "
            "disagreement; intersection means failed in both runs.")
    disagreement_kill_flips = {
        pair: (outcomes[0], outcomes[1],
               1 if outcomes[0] == "failed" else 2)
        for pair, outcomes in disagreement_records.items()
        if (outcomes[0] == "failed") != (outcomes[1] == "failed")
    }
    if disagreement_kill_flips != flip_records:
        raise GoldKillsetRefused(
            "REFUSED: oriented kill flips and outcome disagreements do not "
            "describe the same evidence.")
    if doc["digest"] != artifact_digest(doc):
        raise GoldKillsetRefused(
            "REFUSED: gold killset digest does not match its canonical content.")
    return doc


def write(doc: dict, path: str) -> str:
    """Write one validated artifact without replacing existing evidence."""
    validate(doc)
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    try:
        with open(path, "x", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1, sort_keys=True)
            fh.write("\n")
    except FileExistsError as exc:
        raise GoldKillsetRefused(
            f"REFUSED: output already exists: {path}. Use --check or a new "
            "path; release evidence is immutable.") from exc
    return path


def _fixture_identity(*, manifest_digest: str, expected_pairs: set) -> dict:
    entry = versions.population("python-docx-v1")
    return mutation_run.build_campaign_identity(
        asset_index_sha256=entry["asset_index_sha256"],
        asset_project=entry["asset_project"],
        mutation_validation_sha256="1" * 64,
        mutation_validation_class="native",
        manifest_sha256="2" * 64,
        manifest_digest=manifest_digest,
        map_sha256="3" * 64, release_sha256="4" * 64,
        candidate_run_sha256="5" * 64,
        candidate_generated_tests_sha256="6" * 64,
        solution_generated_tests_sha256="6" * 64,
        substrate_baseline_sha256="7" * 64,
        applier_sha256="8" * 64,
        worker_resources_sha256="9" * 64,
        harness_version=6,
        container_image_digest="sha256:" + "a" * 64,
        workspace_seed_digest="b" * 64,
        database_dump_digest="c" * 64,
        expected_pairs=expected_pairs,
        engine=entry["engine"], engine_version=entry["engine_version"],
        parser=entry["parser"], side="gold", shard=0, of=1, timeout=600,
        generation_provenance_class="native_v2",
        generation_attempt_id="fixture-attempt",
        generation_campaign_digest="d" * 16,
        generation_agent_runtime_sha256="e" * 64,
        generation_network_semantics="internal-only",
        generation_condition="gold", generation_protocol_version=4,
        generation_protocol_digest="f" * 16,
        generation_native_budget={"fixture": True})


def selftest() -> int:
    """Pure contract probes; live native-byte validation belongs to M2."""
    import copy

    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail else ""))
        ok = ok and bool(condition)

    def refuses(name, fn, needle):
        try:
            fn()
        except GoldKillsetRefused as exc:
            check(name, needle in str(exc), str(exc))
            return
        check(name, False, "accepted")

    pairs = {("item-a", "m1"), ("item-a", "m2"), ("item-b", "m3")}
    digest = versions.population("python-docx-v1")["scored"][
        "manifest_digest"]
    identity = _fixture_identity(manifest_digest=digest,
                                 expected_pairs=pairs)

    def fixture_run(outcomes, observation_id):
        return {
            "identity": copy.deepcopy(identity),
            "outcomes": outcomes,
            "facts": {
                "observation_id": observation_id,
                "campaign_identity_sha256":
                    mutation_run.campaign_identity_digest(identity),
                "rows_sha256": ["1" * 64],
                "sidecars_sha256": ["2" * 64],
                "n_shards": 1, "n_rows": len(pairs),
                "n_pairs": len(pairs),
                "pairs_sha256": mutation_run.pair_set_digest(pairs),
            },
        }

    run_1 = fixture_run({
        ("item-a", "m1"): "failed", ("item-a", "m2"): "failed",
        ("item-b", "m3"): "passed",
    }, "1" * 32)
    run_2 = fixture_run({
        ("item-a", "m1"): "failed", ("item-a", "m2"): "passed",
        ("item-b", "m3"): "setup_error",
    }, "2" * 32)

    def as_reference(run, workload_digest, role="full-gold"):
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
        if role != "full-gold":
            reference["side"] = "candidate"
        result["identity"] = reference
        result["facts"]["campaign_identity_sha256"] = \
            mutation_run.campaign_identity_digest(reference)
        return result

    reference_1 = as_reference(run_1, "a" * 64)
    reference_2 = as_reference(run_2, "b" * 64)
    check("full-gold exact-byte controls are admitted as distinct N=2 "
          "workload observations",
          build("python-docx-v1", reference_1, reference_2)["kills"]
          ["intersection_count"] == 1)
    refuses("a role-mismatched reference control cannot populate full gold",
            lambda: build("python-docx-v1",
                          as_reference(run_1, "a" * 64,
                                       "assertion-stripped-gold"),
                          reference_2), "not publishable")
    doc = build("python-docx-v1", run_1, run_2)
    check("two runs produce the conservative failed-only intersection",
          doc["kills"]["by_item"] == {"item-a": ["m1"]}
          and doc["kills"]["run_counts"] == [2, 1]
          and doc["kills"]["flip_count"] == 1,
          str(doc["kills"]))
    check("all outcome disagreements remain visible",
          len(doc["outcome_disagreements"]) == 2,
          str(doc["outcome_disagreements"]))
    check("the artifact is digest-pinned and registry-bound",
          validate(copy.deepcopy(doc)) == doc)

    registered_index = versions.population(
        "python-docx-v1")["asset_index_sha256"]
    ruled_index = versions.equivalent_asset_indexes("python-docx-v1")[0]
    renamed_envelope = copy.deepcopy(identity)
    renamed_envelope["asset_index_sha256"] = ruled_index
    check("a campaign stamped with the CURRENT asset index is a "
          "python-docx-v1 observation, and the artifact still records the "
          "registered identity -- the 2026-09-01 envelope-equivalence ruling",
          _population_claim("python-docx-v1",
                            renamed_envelope)["asset_index_sha256"]
          == registered_index)
    unruled_envelope = copy.deepcopy(identity)
    unruled_envelope["asset_index_sha256"] = "f" * 64
    try:
        _population_claim("python-docx-v1", unruled_envelope)
        check("an asset index no ruling equates still refuses, naming both "
              "digests it compared", False, "accepted")
    except GoldKillsetRefused as exc:
        check("an asset index no ruling equates still refuses, naming both "
              "digests it compared",
              "f" * 64 in str(exc) and registered_index in str(exc)
              and ruled_index in str(exc), str(exc))

    tampered = copy.deepcopy(doc)
    tampered["kills"]["by_item"]["item-a"] = ["m1", "m9"]
    refuses("a changed kill set fails before its stale digest can be trusted",
            lambda: validate(tampered), "intersection_count")
    wrong_population = copy.deepcopy(run_2)
    wrong_population["identity"]["manifest_digest"] = "0" * 64
    refuses("two differently pinned populations cannot be intersected",
            lambda: build("python-docx-v1", run_1, wrong_population),
            "field(s)")
    wrong_id = copy.deepcopy(doc)
    wrong_id["population_id"] = "coreshop-v1"
    wrong_id["digest"] = artifact_digest(wrong_id)
    refuses("a plausible population label cannot override the manifest digest",
            lambda: validate(wrong_id), "population facts")
    def as_budgeted(run, sidecar_sha256="a1" * 32):
        result = copy.deepcopy(run)
        result["identity"].update({
            "population_basis": mutation_run.BUDGETED_POPULATION_BASIS,
            "budgeted_sample_sha256": sidecar_sha256,
            "parent_map_sha256": "b2" * 32,
        })
        result["facts"]["campaign_identity_sha256"] = \
            mutation_run.campaign_identity_digest(result["identity"])
        return result

    budgeted_doc = build("python-docx-v1", as_budgeted(run_1),
                         as_budgeted(run_2))
    check("two gold observations of the same budgeted population join, and "
          "the artifact says on its face which population that is -- a "
          "budgeted killset can never be read as the full one's",
          budgeted_doc["population_basis"] == "budgeted_sample"
          and budgeted_doc["budgeted_sample_sha256"] == "a1" * 32
          and budgeted_doc["population"] == doc["population"]
          and budgeted_doc["digest"] != doc["digest"]
          and validate(copy.deepcopy(budgeted_doc)) == budgeted_doc,
          str(budgeted_doc.get("population_basis")))
    refuses("a budgeted leg and a full-population leg are not two "
            "observations of one population, and the refusal names the "
            "fields that say so",
            lambda: build("python-docx-v1", as_budgeted(run_1), run_2),
            "population_basis")
    refuses("...nor are two budgeted legs that cite different sidecars",
            lambda: build("python-docx-v1", as_budgeted(run_1),
                          as_budgeted(run_2, "c3" * 32)),
            "budgeted_sample_sha256")
    unstamped = copy.deepcopy(budgeted_doc)
    del unstamped["population_basis"]
    unstamped["digest"] = artifact_digest(unstamped)
    refuses("and the artifact cannot drop half the declaration on the way "
            "out", lambda: validate(unstamped), "budgeted_sample_sha256")
    sampled = copy.deepcopy(run_2)
    sampled["identity"]["sample"] = 2
    sampled["identity"]["sample_seed"] = 1
    refuses("sampled gold cannot become a release killset",
            lambda: build("python-docx-v1", run_1, sampled), "unsampled")
    same_observation = copy.deepcopy(run_2)
    same_observation["facts"]["observation_id"] = \
        run_1["facts"]["observation_id"]
    refuses("one execution cannot be submitted twice as N=2 evidence",
            lambda: build("python-docx-v1", run_1, same_observation),
            "same observation_id")

    contradictory = copy.deepcopy(doc)
    contradictory_flip = contradictory["kills"]["flips"][0]
    contradictory_flip["run_1_outcome"] = "passed"
    contradictory_flip["run_2_outcome"] = "failed"
    contradictory_flip["killed_in_run"] = 2
    contradictory["digest"] = artifact_digest(contradictory)
    refuses("oriented flips must reproduce run counts and disagreements",
            lambda: validate(contradictory), "kill counts")
    contradictory_intersection = copy.deepcopy(doc)
    contradictory_intersection["outcome_disagreements"].append({
        "item_id": "item-a", "mutant_id": "m1",
        "run_1_outcome": "passed", "run_2_outcome": "setup_error",
    })
    contradictory_intersection["outcome_disagreements"].sort(
        key=lambda value: (value["item_id"], value["mutant_id"]))
    contradictory_intersection["digest"] = artifact_digest(
        contradictory_intersection)
    refuses("an intersection kill cannot claim non-failed disagreement "
            "outcomes", lambda: validate(contradictory_intersection),
            "intersection kill")

    print("\n" + ("ALL PASS (gold_killset)" if ok
                    else "FAILURES (gold_killset)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
