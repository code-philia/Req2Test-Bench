"""Portable source authority for the schema-/3 anti-vacuity measurement.

``anti_vacuity.json`` is a summary, not a measurement log.  This module
binds that summary to the released item pool, the two producer-authenticated
unmutated controls, and all four native mutation observations.  Producers
first validate the live native campaigns and archive their exact bytes under
the release directory.  Readers then re-attest the archived rows and
sidecars, recover their observation/campaign identities, and rederive every
candidate score and verdict printed by the summary.

The portable reader intentionally does not dereference the absolute worker
paths preserved inside a native sidecar.  Those paths are checked by
``validate_native_shards`` at capture time; the archived sidecar's SHA-256,
the row stamps, the complete-state attestation, and the release inventory pin
preserve that result without making a release readable only on its producer.
"""
from __future__ import annotations

import json
import os
from typing import Iterable


SOURCE_FIELDS = frozenset({"release_items", "baselines", "observations"})
FILE_FIELDS = frozenset({"path", "sha256"})
RELEASE_FIELDS = frozenset({
    "path", "sha256", "items", "item_ids_sha256",
})
BASELINE_FIELDS = frozenset({
    "path", "sha256", "items", "item_ids_sha256", "outcomes_sha256",
    "generated_tests_sha256",
})
OBSERVATION_FIELDS = frozenset({
    "observation_id", "campaign_identity_sha256", "pairs_sha256",
    "n_shards", "n_rows", "plan", "shards",
})
SHARD_FIELDS = frozenset({
    "index", "rows_path", "rows_sha256", "sidecar_path",
    "sidecar_sha256",
})


class EvidenceRefused(ValueError):
    """Archived anti-vacuity sources are absent, mutable, or contradictory."""


def _refuse(message: str) -> None:
    raise EvidenceRefused("REFUSED: " + message)


def _sha(value) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(ch in "0123456789abcdef" for ch in value))


def _exact(value, fields: frozenset[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        got = sorted(value) if isinstance(value, dict) else type(value).__name__
        _refuse(f"{label} must contain exactly {sorted(fields)}; got {got}")


def _count(value, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        _refuse(f"{label} is not an integer >= {minimum}")
    return value


def validate_shape(sources: dict) -> dict:
    """Validate the closed source-reference schema without reading a path."""
    _exact(sources, SOURCE_FIELDS, "anti-vacuity sources")
    release = sources["release_items"]
    _exact(release, RELEASE_FIELDS, "sources.release_items")
    if not isinstance(release["path"], str) or not release["path"] \
            or not _sha(release["sha256"]) \
            or not _sha(release["item_ids_sha256"]):
        _refuse("sources.release_items has an invalid path or SHA-256")
    _count(release["items"], "sources.release_items.items", minimum=1)

    baselines = sources["baselines"]
    if not isinstance(baselines, dict) or set(baselines) != {"gold", "stub"}:
        _refuse("sources.baselines must contain exactly gold and stub")
    for name, baseline in baselines.items():
        _exact(baseline, BASELINE_FIELDS, f"sources.baselines.{name}")
        if not isinstance(baseline["path"], str) or not baseline["path"] \
                or any(not _sha(baseline[field]) for field in (
                    "sha256", "item_ids_sha256", "outcomes_sha256",
                    "generated_tests_sha256")):
            _refuse(f"sources.baselines.{name} has an invalid path/digest")
        _count(baseline["items"], f"sources.baselines.{name}.items", minimum=1)

    observations = sources["observations"]
    if not isinstance(observations, dict) \
            or set(observations) != {"gold", "stub"}:
        _refuse("sources.observations must contain exactly gold and stub")
    for name, runs in observations.items():
        if not isinstance(runs, list) or len(runs) != 2:
            _refuse(f"sources.observations.{name} is not exact N=2")
        for run_index, observation in enumerate(runs):
            label = f"sources.observations.{name}[{run_index}]"
            _exact(observation, OBSERVATION_FIELDS, label)
            observation_id = observation["observation_id"]
            if not isinstance(observation_id, str) \
                    or len(observation_id) != 32 \
                    or any(ch not in "0123456789abcdef"
                           for ch in observation_id) \
                    or any(not _sha(observation[field]) for field in (
                        "campaign_identity_sha256", "pairs_sha256")):
                _refuse(f"{label} has an invalid observation/campaign digest")
            n_shards = _count(observation["n_shards"],
                              f"{label}.n_shards", minimum=1)
            _count(observation["n_rows"], f"{label}.n_rows", minimum=1)
            _exact(observation["plan"], FILE_FIELDS, f"{label}.plan")
            if not isinstance(observation["plan"]["path"], str) \
                    or not observation["plan"]["path"] \
                    or not _sha(observation["plan"]["sha256"]):
                _refuse(f"{label}.plan has an invalid path/digest")
            shards = observation["shards"]
            if not isinstance(shards, list) or len(shards) != n_shards:
                _refuse(f"{label}.shards does not match n_shards")
            for shard_index, shard in enumerate(shards):
                _exact(shard, SHARD_FIELDS,
                       f"{label}.shards[{shard_index}]")
                if shard["index"] != shard_index \
                        or any(not isinstance(shard[field], str)
                               or not shard[field]
                               for field in ("rows_path", "sidecar_path")) \
                        or any(not _sha(shard[field]) for field in (
                            "rows_sha256", "sidecar_sha256")):
                    _refuse(f"{label}.shards[{shard_index}] is not canonical")
    return sources


def _root(path: str) -> str:
    root = os.path.abspath(path)
    if os.path.islink(root) or not os.path.isdir(root) \
            or os.path.realpath(root) != root:
        _refuse(f"evidence root must be a canonical non-symlink directory: {path}")
    return root


def _resolve(root: str, relative: str, label: str) -> str:
    if not isinstance(relative, str) or not relative \
            or os.path.isabs(relative):
        _refuse(f"{label} must be a non-empty relative path")
    normal = os.path.normpath(relative)
    if normal in {"", ".", ".."} or normal.startswith(".." + os.sep) \
            or normal != relative:
        _refuse(f"{label} is not a canonical contained path: {relative!r}")
    path = os.path.abspath(os.path.join(root, normal))
    if os.path.commonpath((root, path)) != root \
            or os.path.realpath(path) != path \
            or os.path.islink(path) or not os.path.isfile(path):
        _refuse(f"{label} must name a contained non-symlink regular file: {relative}")
    return path


def _relative(root: str, path: str, label: str) -> str:
    absolute = os.path.abspath(path)
    if os.path.realpath(absolute) != absolute or os.path.islink(absolute) \
            or not os.path.isfile(absolute) \
            or os.path.commonpath((root, absolute)) != root:
        _refuse(f"{label} must already be archived beneath {root}: {path}")
    relative = os.path.relpath(absolute, root)
    # Exercise the reader's exact containment rules before publishing it.
    _resolve(root, relative, label)
    return relative


def _jsonl(path: str, label: str) -> list[dict]:
    rows = []
    try:
        with open(path, encoding="utf-8") as fh:
            for number, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    _refuse(f"{label} row {number} is not an object")
                rows.append(row)
    except (OSError, json.JSONDecodeError) as exc:
        _refuse(f"cannot read {label} {path}: {exc}")
    return rows


def _item_ids(rows: list[dict], label: str) -> set[str]:
    ids = set()
    for number, row in enumerate(rows, 1):
        item_id = row.get("item_id")
        if not isinstance(item_id, str) or not item_id or item_id in ids:
            _refuse(f"{label} row {number} has missing/duplicate item_id {item_id!r}")
        ids.add(item_id)
    if not ids:
        _refuse(f"{label} is empty")
    return ids


def _file_record(root: str, path: str, label: str) -> dict:
    from ..bench import mutation_run
    relative = _relative(root, path, label)
    return {"path": relative, "sha256": mutation_run.sha256_file(path)}


def _release_record(root: str, path: str) -> tuple[dict, set[str]]:
    from . import hard_subset as HS
    record = _file_record(root, path, "released item pool")
    ids = _item_ids(_jsonl(path, "released item pool"), "released item pool")
    return ({**record, "items": len(ids),
             "item_ids_sha256": HS.item_digest(ids)}, ids)


def _baseline_values(path: str, label: str) -> tuple[list[dict], dict[str, str], str]:
    from .anti_vacuity import control_baseline
    from ..bench import mutation_run
    from ..bench.test_quality import passed_solutions
    rows = _jsonl(path, f"{label} baseline")
    try:
        values = control_baseline(rows, label)
        generated = mutation_run.candidate_digest(passed_solutions(rows))
    except (ValueError, TypeError) as exc:
        _refuse(str(exc))
    return rows, values, generated


def _baseline_record(root: str, path: str, label: str) \
        -> tuple[dict, list[dict], dict[str, str]]:
    from . import hard_subset as HS
    from ..bench import mutation_run
    rows, values, generated = _baseline_values(path, label)
    record = _file_record(root, path, f"{label} baseline")
    record.update({
        "items": len(values),
        "item_ids_sha256": HS.item_digest(values),
        "outcomes_sha256": mutation_run.content_digest(values),
        "generated_tests_sha256": generated,
    })
    return record, rows, values


def _facts(paths: list[str], campaign: dict) -> dict:
    from . import hard_subset as HS
    from ..bench import mutation_run
    identities = []
    shards = []
    for path in paths:
        side_path = mutation_run.provenance_path(path)
        with open(side_path, encoding="utf-8") as fh:
            sidecar = json.load(fh)
        identities.append(sidecar["campaign_identity"])
        shards.append((sidecar["campaign_identity"]["shard"], {
            "rows_sha256": mutation_run.sha256_file(path),
            "sidecar_sha256": mutation_run.sha256_file(side_path),
        }))
    shards.sort(key=lambda value: value[0])
    return {
        "observation_id": campaign["observation_id"],
        "campaign_identity_sha256":
            mutation_run.campaign_identity_digest(campaign["campaign_identity"]),
        "rows_sha256": [value["rows_sha256"] for _n, value in shards],
        "sidecars_sha256": [value["sidecar_sha256"] for _n, value in shards],
        "n_shards": len(shards), "n_rows": len(campaign["rows"]),
        "n_pairs": len(campaign["pairs"]),
        "pairs_sha256": HS.pair_digest(campaign["pairs"]),
    }


def _admit_observation_generation(identity: dict, reference_role: str,
                                  label: str) -> None:
    from ..bench import mutation_run
    try:
        mutation_run.validate_publishable_generation(
            identity, reference_roles={reference_role}, where=label)
    except mutation_run.MutationAborted as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))


def _capture_observation(root: str, paths: Iterable[str], side: str,
                         label: str, reference_role: str) -> tuple[dict, dict]:
    """Strictly validate one live campaign and describe its archived bytes."""
    from . import hard_subset as HS
    from ..bench import mutation_run
    paths = [os.path.abspath(path) for path in paths]
    # Strict capture includes worker-resource preimages and the output plan.
    try:
        campaign = mutation_run.validate_native_shards(
            paths, required_side=side, return_campaign=True)
        _admit_observation_generation(
            campaign["campaign_identity"], reference_role, label)
        record = (HS.load_full_gold(paths) if side == "gold"
                  else HS.load_candidate(paths, label=label))
    except (mutation_run.MutationAborted, HS.HardSubsetRefused,
            OSError, ValueError) as exc:
        _refuse(str(exc))
    facts = _facts(paths, campaign)
    if record["facts"] != facts:
        _refuse(f"{label} strict native facts do not reproduce")

    shards = []
    for path in paths:
        side_path = mutation_run.provenance_path(path)
        with open(side_path, encoding="utf-8") as fh:
            identity = json.load(fh)["campaign_identity"]
        shards.append({
            "index": identity["shard"],
            "rows_path": _relative(root, path, f"{label} rows"),
            "rows_sha256": mutation_run.sha256_file(path),
            "sidecar_path": _relative(root, side_path, f"{label} sidecar"),
            "sidecar_sha256": mutation_run.sha256_file(side_path),
        })
    shards.sort(key=lambda value: value["index"])
    plan_path = os.path.join(os.path.dirname(paths[0]),
                             mutation_run.MUTATION_OUTPUT_PLAN)
    observation = {
        "observation_id": facts["observation_id"],
        "campaign_identity_sha256": facts["campaign_identity_sha256"],
        "pairs_sha256": facts["pairs_sha256"],
        "n_shards": facts["n_shards"], "n_rows": facts["n_rows"],
        "plan": _file_record(root, plan_path, f"{label} output plan"),
        "shards": shards,
    }
    return observation, record


def capture(*, root: str, release_items: str, gold_baseline: str,
            stub_baseline: str, gold_observations: Iterable[Iterable[str]],
            stub_observations: Iterable[Iterable[str]]) -> dict:
    """Capture exact source references after full native validation.

    Every input must already be archived under ``root``.  Refusing external
    paths prevents an apparently portable release from depending on mutable
    campaign files elsewhere on its producer.
    """
    root = _root(root)
    release_record, _ids = _release_record(root, os.path.abspath(release_items))
    baselines = {}
    for name, path in (("gold", gold_baseline), ("stub", stub_baseline)):
        baselines[name], _rows, _values = _baseline_record(
            root, os.path.abspath(path), name)
    groups = {"gold": list(gold_observations),
              "stub": list(stub_observations)}
    if any(len(groups[name]) != 2 for name in groups):
        _refuse("capture requires exact gold N=2 and stub N=2")
    observations = {"gold": [], "stub": []}
    for name, side in (("gold", "gold"), ("stub", "candidate")):
        for index, paths in enumerate(groups[name], 1):
            observation, _record = _capture_observation(
                root, paths, side, f"{name} observation {index}",
                "full-gold" if name == "gold" else "stub-control")
            observations[name].append(observation)
    sources = {"release_items": release_record,
               "baselines": baselines, "observations": observations}
    return validate_shape(sources)


def _validate_file_record(root: str, record: dict, label: str) -> str:
    from ..bench import mutation_run
    path = _resolve(root, record["path"], label)
    actual = mutation_run.sha256_file(path)
    if actual != record["sha256"]:
        _refuse(f"{label} SHA-256 is {actual}, expected {record['sha256']}")
    return path


def _load_release(root: str, record: dict) -> tuple[str, set[str]]:
    from . import hard_subset as HS
    path = _validate_file_record(root, record, "released item pool")
    ids = _item_ids(_jsonl(path, "released item pool"), "released item pool")
    expected = {"items": len(ids), "item_ids_sha256": HS.item_digest(ids)}
    if any(record[key] != value for key, value in expected.items()):
        _refuse("released item record does not rederive from its bytes")
    return path, ids


def _load_baseline(root: str, record: dict, label: str) \
        -> tuple[str, list[dict], dict[str, str]]:
    from . import hard_subset as HS
    from ..bench import mutation_run
    path = _validate_file_record(root, record, f"{label} baseline")
    rows, values, generated = _baseline_values(path, label)
    expected = {
        "items": len(values), "item_ids_sha256": HS.item_digest(values),
        "outcomes_sha256": mutation_run.content_digest(values),
        "generated_tests_sha256": generated,
    }
    if any(record[key] != value for key, value in expected.items()):
        _refuse(f"{label} baseline record does not rederive from its bytes")
    return path, rows, values


def _portable_observation(root: str, source: dict, side: str,
                          label: str, reference_role: str) -> dict:
    """Re-attest archived shard bytes without producer-local worker paths."""
    from . import hard_subset as HS
    from ..bench import mutation_run
    plan_path = _validate_file_record(root, source["plan"], f"{label} plan")
    identities = []
    rows = []
    pairs = set()
    row_hashes = []
    sidecar_hashes = []
    directories = set()
    for source_shard in source["shards"]:
        index = source_shard["index"]
        row_path = _resolve(root, source_shard["rows_path"],
                            f"{label} shard {index} rows")
        side_path = _resolve(root, source_shard["sidecar_path"],
                             f"{label} shard {index} sidecar")
        if side_path != mutation_run.provenance_path(row_path):
            _refuse(f"{label} shard {index} sidecar is not beside its rows")
        if mutation_run.sha256_file(row_path) != source_shard["rows_sha256"] \
                or mutation_run.sha256_file(side_path) \
                != source_shard["sidecar_sha256"]:
            _refuse(f"{label} shard {index} row/sidecar SHA-256 moved")
        try:
            verification = mutation_run.verify_shard(row_path)
            with open(side_path, encoding="utf-8") as fh:
                sidecar = json.load(fh)
        except (mutation_run.MutationAborted, OSError,
                json.JSONDecodeError) as exc:
            _refuse(str(exc))
        if verification["recorded_status"] != "complete" \
                or verification["state_consistent_with_bytes"] is not True \
                or verification["problems"]:
            _refuse(f"{label} shard {index} is not a re-attested complete shard")
        identity = sidecar.get("campaign_identity")
        if identity.get("side") != side or identity.get("shard") != index \
                or sidecar.get("observation_id") != source["observation_id"]:
            _refuse(f"{label} shard {index} has the wrong side/shard/observation")
        identities.append(identity)
        row_hashes.append(source_shard["rows_sha256"])
        sidecar_hashes.append(source_shard["sidecar_sha256"])
        shard_rows = _jsonl(row_path, f"{label} shard {index}")
        for row in shard_rows:
            pair = (row.get("item_id"), row.get("mutant_id"))
            if pair in pairs:
                _refuse(f"{label} repeats pair {pair!r} across shards")
            pairs.add(pair)
        rows.extend(shard_rows)
        directories.add(os.path.dirname(row_path))

    if len(directories) != 1 or os.path.dirname(plan_path) not in directories:
        _refuse(f"{label} plan and shards are not one archived campaign")
    if [identity["shard"] for identity in identities] \
            != list(range(len(identities))) \
            or any(identity["of"] != len(identities)
                   for identity in identities):
        _refuse(f"{label} is not the exact zero-based shard set")
    cores = {
        json.dumps({key: value for key, value in identity.items()
                    if key not in {"shard", "expected_pairs",
                                   "expected_pairs_sha256"}},
                   sort_keys=True, separators=(",", ":"))
        for identity in identities
    }
    if len(cores) != 1:
        _refuse(f"{label} carries mixed campaign cores")
    representative = identities[0]
    try:
        with open(plan_path, encoding="utf-8") as fh:
            plan = json.load(fh)
        observation_id = mutation_run._validate_standalone_output_plan(
            plan, representative)
    except (mutation_run.MutationAborted, OSError,
            json.JSONDecodeError) as exc:
        _refuse(str(exc))
    if observation_id != source["observation_id"]:
        _refuse(f"{label} output plan names another observation")
    facts = {
        "observation_id": observation_id,
        "campaign_identity_sha256":
            mutation_run.campaign_identity_digest(representative),
        "rows_sha256": row_hashes, "sidecars_sha256": sidecar_hashes,
        "n_shards": len(identities), "n_rows": len(rows),
        "n_pairs": len(pairs), "pairs_sha256": HS.pair_digest(pairs),
    }
    expected_source = {
        "observation_id": facts["observation_id"],
        "campaign_identity_sha256": facts["campaign_identity_sha256"],
        "pairs_sha256": facts["pairs_sha256"],
        "n_shards": facts["n_shards"], "n_rows": facts["n_rows"],
    }
    if any(source[key] != value for key, value in expected_source.items()):
        _refuse(f"{label} source record does not rederive from its bytes")
    _admit_observation_generation(representative, reference_role, label)
    return {"identity": representative, "rows": rows, "pairs": pairs,
            "facts": facts}


def _pair_accounting(rows: list[dict], expected: set[tuple[str, str]],
                     label: str) -> dict:
    seen = set()
    duplicates = 0
    for number, row in enumerate(rows, 1):
        pair = (row.get("item_id"), row.get("mutant_id"))
        if not all(isinstance(value, str) and value for value in pair):
            _refuse(f"malformed {label} row {number}")
        if pair in seen:
            duplicates += 1
        seen.add(pair)
    return {
        "rows": len(rows), "unique_pairs": len(seen),
        "duplicate_pairs": duplicates,
        "pairs_missing": len(expected - seen),
        "pairs_outside_population": len(seen - expected),
        "rows_dropped_non_production": 0,
    }


def _n2_recall(baseline: dict[str, str], rows_1: list[dict],
               rows_2: list[dict], killed: dict[str, set[str]], *,
               label: str) -> tuple[dict | None, list[str], str | None]:
    from ..data.mutation import recall
    from ..bench.test_quality import TestQualityRefused, _candidate_n2_intersection
    pairs = {(item_id, mutant_id)
             for item_id, mutants in killed.items()
             for mutant_id in mutants}
    try:
        synthetic, knife_edge = _candidate_n2_intersection(
            rows_1, rows_2, pairs)
        result = recall(baseline, synthetic, killed, expected_pairs=pairs)
    except (TestQualityRefused, ValueError) as exc:
        return None, [], f"{label}: {str(exc)[:600]}"
    return result, knife_edge, None


def rederive(sources: dict, *, root: str, hard_doc: dict) -> dict:
    """Load archived sources and rederive checks, scores, and the verdict."""
    from . import anti_vacuity as AV
    from . import gold_killset
    from . import hard_subset as HS
    from ..bench import mutation_run
    from ..data.mutation import classify_outcome

    validate_shape(sources)
    root = _root(root)
    release_path, release_ids = _load_release(root, sources["release_items"])
    baseline_rows = {}
    baselines = {}
    baseline_paths = {}
    for name in ("gold", "stub"):
        baseline_paths[name], baseline_rows[name], baselines[name] = \
            _load_baseline(root, sources["baselines"][name], name)
        for item_id, outcome in baselines[name].items():
            try:
                classify_outcome("passed", outcome)
            except ValueError as exc:
                _refuse(f"{name} baseline item {item_id!r}: {exc}")
    if set(baselines["gold"]) != release_ids \
            or set(baselines["stub"]) != release_ids:
        _refuse("released pool and gold/stub baselines do not name one exact item set")

    excluded = {row["item_id"] for row in hard_doc["fidelity"]["excluded"]}
    passed_ids = release_ids - excluded
    fidelity = hard_doc["fidelity"]
    if len(release_ids) != fidelity["items_total"] \
            or len(passed_ids) != fidelity["items_passed"] \
            or len(excluded) != fidelity["items_excluded"] \
            or HS.item_digest(passed_ids) != fidelity["passed_item_ids_sha256"]:
        _refuse("released item IDs do not reproduce hard-subset fidelity/exclusions")

    native = {"gold": [], "stub": []}
    for name, side in (("gold", "gold"), ("stub", "candidate")):
        for index, source in enumerate(sources["observations"][name], 1):
            native[name].append(_portable_observation(
                root, source, side, f"{name} observation {index}",
                "full-gold" if name == "gold" else "stub-control"))

    rebuilt_gold = [{**record["facts"], "index": index}
                    for index, record in enumerate(native["gold"], 1)]
    if rebuilt_gold != hard_doc["runs"]["full_gold"]:
        _refuse("gold observations are not the exact N=2 bytes pinned by hard_subset")
    observation_ids = [record["facts"]["observation_id"]
                       for record in native["gold"] + native["stub"]]
    observation_ids += [run["observation_id"]
                        for run in hard_doc["runs"]["stripped_gold"]]
    if len(set(observation_ids)) != 6:
        _refuse("full, stripped, and stub N=2 are not six distinct observations")

    gold_identity = native["gold"][0]["identity"]
    stub_identities = [record["identity"] for record in native["stub"]]
    changed_stub = sorted(
        field for field in gold_killset.SHARED_CAMPAIGN_FIELDS
        if stub_identities[0].get(field) != stub_identities[1].get(field))
    if changed_stub:
        _refuse(f"stub N=2 campaign identity differs in {changed_stub}")
    for index, identity in enumerate(stub_identities, 1):
        changed = sorted(field for field in HS.POPULATION_EXECUTION_FIELDS
                         if identity.get(field) != gold_identity.get(field))
        if changed:
            _refuse(f"stub observation {index} differs from gold in {changed}")

    baseline_identities = {"gold": gold_identity, "stub": stub_identities[0]}
    for name, identity in baseline_identities.items():
        generated = sources["baselines"][name]["generated_tests_sha256"]
        changed = []
        if mutation_run.sha256_file(baseline_paths[name]) \
                != identity.get("candidate_run_sha256"):
            changed.append("candidate_run_sha256")
        if generated != identity.get("candidate_generated_tests_sha256"):
            changed.append("candidate_generated_tests_sha256")
        if generated != identity.get("solution_generated_tests_sha256"):
            changed.append("solution_generated_tests_sha256")
        if changed:
            _refuse(f"{name} observations do not bind their baseline: {changed}")
    if mutation_run.sha256_file(release_path) != gold_identity.get(
            "release_sha256"):
        _refuse("gold campaign does not bind the exact released item bytes")

    expected_pairs = set(native["gold"][0]["pairs"])
    if len(expected_pairs) != hard_doc["pairs"]["full_n"] \
            or HS.pair_digest(expected_pairs) != hard_doc["pairs"]["full_sha256"]:
        _refuse("gold pair set does not reproduce the hard-subset population")
    for name in ("gold", "stub"):
        for index, record in enumerate(native[name], 1):
            if record["pairs"] != expected_pairs:
                _refuse(f"{name} observation {index} is not the exact pair population")

    checks = {"expected_item_mutant_pairs": len(expected_pairs)}
    sweep_complete = True
    duplicate_free = True
    population_consistent = True
    observations = {}
    for name in ("gold", "stub"):
        observations[name] = [record["rows"] for record in native[name]]
        run_checks = []
        for index, rows in enumerate(observations[name], 1):
            accounting = _pair_accounting(
                rows, expected_pairs, f"{name} observation {index}")
            run_checks.append(accounting)
            sweep_complete &= accounting["pairs_missing"] == 0
            duplicate_free &= accounting["duplicate_pairs"] == 0
            population_consistent &= accounting["pairs_outside_population"] == 0
        checks[name] = {"runs": run_checks}

    full_killed = {item_id: set(mutants) for item_id, mutants
                   in hard_doc["full_gold"]["by_item"].items()}
    hard_killed = {item_id: set(mutants) for item_id, mutants
                   in hard_doc["hard_subset"]["by_item"].items()}
    full_pairs = {(item_id, mutant_id)
                  for item_id, mutants in full_killed.items()
                  for mutant_id in mutants}
    hard_pairs = {(item_id, mutant_id)
                  for item_id, mutants in hard_killed.items()
                  for mutant_id in mutants}
    kills_outside = len(full_pairs - expected_pairs)
    checks["kill_set"] = {
        "full_pairs": len(full_pairs), "hard_pairs": len(hard_pairs),
        "pairs_outside_manifest_map_population": kills_outside,
    }

    candidates = {}
    for name in ("gold", "stub"):
        full_score, full_flips, full_refusal = _n2_recall(
            baselines[name], observations[name][0], observations[name][1],
            full_killed, label=f"{name} full N=2")
        if hard_pairs:
            hard_score, hard_flips, hard_refusal = _n2_recall(
                baselines[name], observations[name][0], observations[name][1],
                hard_killed, label=f"{name} hard N=2")
        else:
            hard_score, hard_flips, hard_refusal = None, [], None
        passed = sum(outcome == "passed" for outcome in baselines[name].values())
        candidates[name] = {
            "scenario_pass_rate": round(passed / len(baselines[name]), 4),
            "scenario_passed": passed,
            "scenario_instances": len(baselines[name]),
            "mutation_recall": None if hard_score is None else hard_score["recall"],
            "full_recall": None if full_score is None else full_score["recall"],
            "hard_recall": None if hard_score is None else hard_score["recall"],
            "full_n_eligible_items": (None if full_score is None
                                      else full_score["n_eligible"]),
            "hard_n_eligible_items": (None if hard_score is None
                                      else hard_score["n_eligible"]),
            "full_killed": (None if full_score is None else sum(
                value["killed"] for value in full_score["per_item"].values())),
            "full_denominator": (None if full_score is None else sum(
                value["denominator"]
                for value in full_score["per_item"].values())),
            "hard_killed": (None if hard_score is None else sum(
                value["killed"] for value in hard_score["per_item"].values())),
            "hard_denominator": (None if hard_score is None else sum(
                value["denominator"]
                for value in hard_score["per_item"].values())),
            "candidate_hard_runs": 2,
            "full_knife_edge_items": full_flips,
            "hard_knife_edge_items": hard_flips,
            "incomplete_refusal": hard_refusal or full_refusal,
            "complete": full_score is not None
                and (hard_score is not None or not hard_pairs),
            "executions": sum(len(rows) for rows in observations[name]),
        }

    gold, stub = candidates["gold"], candidates["stub"]
    ratio = hard_doc["hard_subset"]["ratio"]
    verdict = {
        "gold_full_recall": gold["full_recall"],
        "gold_hard_recall": gold["hard_recall"],
        "stub_full_recall": stub["full_recall"],
        "stub_hard_recall": stub["hard_recall"],
        "gold_hard_recall_one": gold["hard_recall"] == 1.0,
        "stub_hard_recall_zero": stub["hard_recall"]
            == AV.STUB_HARD_RECALL_EXACTLY,
        "hard_subset_ratio_in_band":
            AV.HARD_SUBSET_RATIO_AT_LEAST <= ratio
            <= AV.HARD_SUBSET_RATIO_AT_MOST,
        "stripped_baseline_fidelity":
            5 * fidelity["items_excluded"] <= fidelity["items_total"],
        "candidate_baselines_passed": all(
            candidate["scenario_passed"] == candidate["scenario_instances"]
            for candidate in candidates.values()),
        "sweep_complete": sweep_complete,
        "duplicate_free": duplicate_free,
        "kill_set_consistent": kills_outside == 0 and population_consistent,
        "both_scored": all(candidate["complete"]
                           for candidate in candidates.values()),
    }
    required_keys = [
        "stripped_baseline_fidelity", "candidate_baselines_passed",
        "sweep_complete", "duplicate_free", "kill_set_consistent",
        "both_scored",
    ]
    if hard_pairs:
        required_keys[:0] = [
            "gold_hard_recall_one", "stub_hard_recall_zero"]
    verdict["pass"] = all(verdict[key] for key in required_keys)
    return {"release_path": release_path, "release_ids": release_ids,
            "checks": checks, "candidates": candidates, "verdict": verdict}


def validate_release_inventory(sources: dict, *, root: str,
                               manifest_path: str,
                               manifest_sha256: str) -> None:
    """Bind every measured source byte to the pinned release inventory."""
    from ..bench import mutation_run
    validate_shape(sources)
    root = _root(root)
    manifest = os.path.abspath(manifest_path)
    if os.path.realpath(manifest) != manifest or os.path.islink(manifest) \
            or not os.path.isfile(manifest):
        _refuse(f"release manifest is not a canonical regular file: {manifest}")
    actual_manifest = mutation_run.sha256_file(manifest)
    if actual_manifest != manifest_sha256:
        _refuse(f"release manifest SHA-256 is {actual_manifest}, expected "
                f"its VERSIONS pin {manifest_sha256}")
    try:
        with open(manifest, encoding="utf-8") as fh:
            document = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        _refuse(f"cannot read release manifest {manifest}: {exc}")
    if not isinstance(document, dict) \
            or document.get("schema") != "r2t.dataset_manifest/2" \
            or not isinstance(document.get("release_inventory"), dict) \
            or not isinstance(document["release_inventory"].get("files"), dict):
        _refuse("anti-vacuity source authority requires dataset_manifest/2 inventory")
    release_root = os.path.dirname(manifest)
    if os.path.commonpath((release_root, root)) != release_root:
        _refuse("anti-vacuity source root is outside the inventoried release")
    inventory = document["release_inventory"]["files"]

    records = [sources["release_items"], *sources["baselines"].values()]
    for name in ("gold", "stub"):
        for observation in sources["observations"][name]:
            records.append(observation["plan"])
            for shard in observation["shards"]:
                records.extend((
                    {"path": shard["rows_path"],
                     "sha256": shard["rows_sha256"]},
                    {"path": shard["sidecar_path"],
                     "sha256": shard["sidecar_sha256"]},
                ))
    seen = set()
    for record in records:
        path = _resolve(root, record["path"], "inventoried anti-vacuity source")
        relative = os.path.relpath(path, release_root)
        if relative in seen:
            _refuse(f"anti-vacuity source is referenced twice: {relative}")
        seen.add(relative)
        if inventory.get(relative) != record["sha256"]:
            _refuse(f"release inventory does not pin anti-vacuity source "
                    f"{relative} to {record['sha256']}")
