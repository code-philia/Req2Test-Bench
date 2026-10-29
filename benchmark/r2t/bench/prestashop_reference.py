"""Reuse three source-authenticated PrestaShop B100 reference observations.

This is the fixed count amendment, not the N1 timeout/exclusion policy or an
N2 intersection. Raw native observations remain the authority. The saved gold
rows are explicitly derived oracle indicators, never another native execution.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import os

from ..data import mutation as M, mutation_attestation as A
from . import mutation_run as MR, test_quality as TQ, reference_workloads as RW
from ..toolkit import gold_killset as GK, hard_subset as HS

SCHEMA = "r2t.prestashop-reference-evidence/1"
CONTINUED_SCHEMA = "r2t.prestashop-reference-evidence/2"
CONTINUED_KIND = "prestashop_retained_prefix_v1"
SUMMARY_KEY = "prestashop_reference_evidence"
ROLES = ("full-gold", "assertion-stripped-gold", "stub-control")
ASSETS = ("mutation_validation", "manifest", "map", "release", "budgeted_sidecar")
SOURCES = ("gold_root", "release_gold_root", "closures_path")
BUDGET = ("population_basis", "budgeted_sample_sha256", "parent_map_sha256")
SHARED = HS.POPULATION_EXECUTION_FIELDS | frozenset(BUDGET)
# Worker placement may change between a reference and a candidate. These are
# the actual immutable executor/population facts, not the reference producer tag.
CANDIDATE_SHARED = SHARED - {
    "schema", "kind", "generation_provenance_class", "reference_source_tag",
    "sample", "sample_seed", "timeout_seconds",
}


def require(ok, reason):
    if not ok:
        raise TQ.TestQualityRefused("REFUSED: PrestaShop reference " + reason)


def _canonical(path):
    return os.path.realpath(os.path.abspath(os.fspath(path)))


def _reference(path):
    path = _canonical(path)
    require(os.path.isfile(path), "input is not a readable file: " + path)
    return {"path": path, "sha256": MR.sha256_file(path)}


def _checked(ref):
    with open(ref["path"], "rb") as handle:
        raw = handle.read()
    import hashlib
    require(hashlib.sha256(raw).hexdigest() == ref["sha256"],
            "preserved file changed: " + ref["path"])
    return raw


def _document(ref):
    return json.loads(_checked(ref))


def _pairs(mapping, items):
    return {(iid, mid) for mid, ids in mapping.items() for iid in ids if iid in items}


def _memory_policy(resources, identity):
    """Normalize the runtime preimage already authenticated by native readers."""
    from . import worker as W
    require(isinstance(resources, list) and resources
            and MR.content_digest(resources) == identity.get("worker_resources_sha256"),
            "memory policy has no bound worker-resource evidence")
    try:
        return W.normalized_worker_memory_policy(resources)
    except W.WorkerRefused as exc:
        raise TQ.TestQualityRefused(str(exc)) from exc


def _observation_memory_policy(record, shards):
    # load_native_run checked every shard against this same worker-pool
    # preimage. Reopen one of those exact sidecars, without treating a saved
    # policy claim as a substitute for its immutable runtime attestations.
    ref = _reference(MR.provenance_path(shards[0]["path"]))
    sidecar = _document(ref)
    shard = sidecar["campaign_identity"]["shard"]
    require(ref["sha256"] == record["facts"]["sidecars_sha256"][shard],
            "native worker-resource sidecar changed")
    return _memory_policy(sidecar["worker_resources"], record["identity"])


def derive(inputs, observations, sources):
    """Reopen one exact native shard group per role; perform no execution."""
    require(set(inputs) == set(ASSETS) and set(observations) == set(ROLES)
            and set(sources) == set(SOURCES),
            "needs five B100 assets, frozen control sources and exactly three roles")
    paths = {key: _canonical(path) for key, path in inputs.items()}
    sources = {key: _canonical(path) for key, path in sources.items()}
    assets = A.validate_campaign_asset_inputs(
        paths["mutation_validation"], manifest_path=paths["manifest"],
        map_path=paths["map"], release_path=paths["release"],
        budgeted_sidecar=paths["budgeted_sidecar"], require_release_ready=True)
    require(assets["asset_project"] == "prestashop" and assets.get("population_basis") == "budgeted_sample",
            "requires the native PrestaShop budgeted population")
    budget = _document(_reference(paths["budgeted_sidecar"]))
    require(budget.get("per_item") == 100, "this policy requires the approved B100 allocation")
    ids = A.load_release_ids(paths["release"])
    mapping = assets["map"]["by_mutant"]
    records, saved, baselines, memory_policies = {}, {}, {}, {}
    for role in ROLES:
        spec = observations[role]
        continued = isinstance(spec, dict) and set(spec) == {"baseline", "recipe", "continuation"}
        require(isinstance(spec, dict) and (set(spec) == {"baseline", "recipe", "shards"}
                or (continued and role == "full-gold")), "role input shape differs")
        baseline = _reference(spec["baseline"])
        rows = TQ.load_jsonl(baseline["path"])
        recipe = _reference(spec["recipe"])
        control = RW.validate_development_control_input(
            project="prestashop", role={"full-gold": "full_gold",
                "assertion-stripped-gold": "stripped_gold", "stub-control": "stub"}[role],
            run_path=baseline["path"], recipe_path=recipe["path"],
            execution_release_path=paths["release"], **sources)
        outcomes = control["baseline_outcomes"]
        require(set(outcomes) == ids, role + " baseline differs from the full release")
        passed = TQ.passed_solutions(rows)
        if continued:
            from . import prestashop_continuation as PC
            binding = spec["continuation"]
            require(isinstance(binding, dict) and set(binding) == {"plan", "child_shards"},
                    "continued gold input shape differs")
            record = PC.load_completed(binding["plan"], binding["child_shards"])
            require(record.get("kind") == CONTINUED_KIND, "continued gold kind differs")
            identity = record["parent_identity"]
            physical = record["row_sources"]
        else:
            shards = [_reference(path) for path in spec["shards"]]
            require(shards, role + " has no original native observation")
            record = GK.load_native_run([ref["path"] for ref in shards],
                                        required_side="gold" if role == "full-gold" else "candidate")
            identity = record["identity"]
            physical = shards
        # The original baseline remains the parent's authority. The typed loader
        # alone proves the explicitly approved child policy/source transition.
        if continued:
            memory_policies[role] = _memory_policy(record["child_worker_resources"], record["identity"])
            require(_memory_policy(record["parent_worker_resources"], identity) == memory_policies[role],
                    "continued gold changed memory policy")
        else:
            memory_policies[role] = _observation_memory_policy(record, shards)
        MR.validate_publishable_generation(identity, reference_roles={role})
        for checked_identity in ([identity, record["identity"]] if continued else [identity]):
            MR.validate_campaign_asset_claims(
                checked_identity, assets, validation_path=paths["mutation_validation"],
                manifest_path=paths["manifest"], map_path=paths["map"], release_path=paths["release"])
        generation = MR.reference_generation_evidence(
            role=role, source_tag=identity.get("reference_source_tag"), candidate_rows=rows,
            release_item_ids=ids, release_sha256=_reference(paths["release"])["sha256"],
            asset_index_sha256=assets["asset_index_sha256"], control=control)
        wanted = {**generation, **{key: assets[key] for key in BUDGET},
                  "candidate_run_sha256": baseline["sha256"],
                  "candidate_generated_tests_sha256": MR.candidate_digest(passed),
                  "solution_generated_tests_sha256": MR.candidate_digest(passed)}
        changed = sorted(key for key, value in wanted.items() if identity.get(key) != value)
        require(not changed, role + " differs from baseline/population identity: " + str(changed))
        require(set(record["outcomes"]) == _pairs(mapping, passed), role + " has a partial or extra baseline-eligible pair set")
        raw = (list(record["raw_rows"].values()) if continued else
               [row for ref in physical for row in TQ.load_jsonl(ref["path"])])
        TQ.validate_native_retry_evidence(raw, where=role)
        records[role], baselines[role] = record, outcomes
        saved[role] = {"baseline": baseline, "recipe": recipe, "facts": record["facts"]}
        if continued:
            saved[role].update(continuation=record["continuation"], row_sources=physical,
                               protected_paths=record["protected_paths"])
        else:
            saved[role]["shards"] = shards
    full = records["full-gold"]["identity"]
    require(full.get("timeout_seconds") == 600, "this policy preserves the 600-second timeout")
    for role, record in records.items():
        changed = sorted(key for key in SHARED if record["identity"].get(key) != full.get(key))
        require(not changed, role + " changed common population/executor fields: " + str(changed))
        require(memory_policies[role] == memory_policies["full-gold"],
                role + " changed the worker memory policy")
    observation_ids = [record["facts"]["observation_id"] for record in records.values()]
    if records["full-gold"].get("kind") == CONTINUED_KIND:
        observation_ids.append(records["full-gold"]["facts"]["child_observation_id"])
    shard_paths = [ref["path"] for record in saved.values()
                   for ref in record.get("row_sources", record.get("shards", []))]
    require(len(set(observation_ids)) == len(observation_ids)
            and len(shard_paths) == len(set(shard_paths)),
            "three controls must have distinct physical observations")
    diagnostics = summarize(records, baselines, ids)
    schema = CONTINUED_SCHEMA if "continuation" in saved["full-gold"] else SCHEMA
    doc = {"schema": schema, "project": "prestashop", "route": "development", "inference_valid": False,
           "method": "single_observation", "reference_observation_count": 1,
           "candidate_observation_count": 1,
           "inputs": {key: _reference(path) for key, path in paths.items()},
           "sources": sources, "observations": saved,
           "shared_identity": {key: full.get(key) for key in sorted(SHARED)},
           "diagnostics": diagnostics}
    if memory_policies["full-gold"] is not None:
        doc["worker_memory_policy"] = memory_policies["full-gold"]
    return doc, records


def summarize(records, baselines, ids):
    """One observed G and G∩S, preserving baseline failures and raw outcomes."""
    gold = records["full-gold"]["outcomes"]
    stripped = records["assertion-stripped-gold"]["outcomes"]
    stub = records["stub-control"]["outcomes"]
    gold_by_item, stripped_by_item, stub_by_item = (defaultdict(set) for _ in range(3))
    for (iid, mid), outcome in gold.items():
        if outcome == "failed":
            gold_by_item[iid].add(mid)
    for (iid, mid), outcome in stripped.items():
        if outcome == "passed":
            stripped_by_item[iid].add(mid)
    for (iid, mid), outcome in stub.items():
        if M.classify_outcome("passed", outcome) == "kill":
            stub_by_item[iid].add(mid)
    per_item = {}
    for iid in sorted(ids):
        kills = gold_by_item[iid]
        witness = stripped_by_item[iid] & kills
        stub_kills = stub_by_item[iid]
        stub_eligible = baselines["stub-control"][iid] == "passed"
        per_item[iid] = {
            "full_gold_failed": sorted(kills), "stripped_passed_witness": sorted(witness),
            "stripped_baseline": baselines["assertion-stripped-gold"][iid],
            "stub_baseline": baselines["stub-control"][iid],
            "stub_full_gold_recall": len(kills & stub_kills) / len(kills) if kills and stub_eligible else None,
            "stub_witness_recall": len(witness & stub_kills) / len(witness) if witness and stub_eligible else None,
        }
        per_item[iid]["hard_status"] = "scorable" if witness else "not_scorable"
    return {"per_item": per_item,
            "items_total": len(ids),
            "hard_not_scorable": sum(not value["stripped_passed_witness"] for value in per_item.values()),
            "baseline_outcomes": {role: dict(sorted(Counter(values.values()).items()))
                                  for role, values in baselines.items()},
            "raw_outcomes": {role: dict(sorted(Counter(record["outcomes"].values()).items()))
                             for role, record in records.items()}}


def load(path):
    doc = _document(_reference(path))
    require(doc.get("schema") in (SCHEMA, CONTINUED_SCHEMA), "evidence schema differs")
    try:
        inputs = {key: ref["path"] for key, ref in doc["inputs"].items()}
        observations = {}
        for role, record in doc["observations"].items():
            spec = {"baseline": record["baseline"]["path"], "recipe": record["recipe"]["path"]}
            if "continuation" in record:
                binding = record["continuation"]
                spec["continuation"] = {"plan": binding["plan"]["path"],
                    "child_shards": [ref["path"] for ref in binding["child_shards"]]}
            else:
                spec["shards"] = [ref["path"] for ref in record["shards"]]
            observations[role] = spec
        rebuilt, records = derive(inputs, observations, doc["sources"])
    except (KeyError, TypeError) as exc:
        raise TQ.TestQualityRefused("REFUSED: malformed PrestaShop reference evidence") from exc
    require(doc == rebuilt, "saved inputs, observation identity or diagnostics changed")
    return doc, records


def selection(path, expected, identity, *, worker_resources=None):
    """Mint the existing arithmetic seal only after reopening original evidence."""
    return _selection(path, *load(path), expected, identity,
                      worker_resources=worker_resources)


def _selection(path, doc, records, expected, identity, *, worker_resources=None):
    changed = sorted(key for key in CANDIDATE_SHARED if identity.get(key) != doc["shared_identity"].get(key))
    # A harness version VERSIONS.yml declares compatible with the reference's
    # for PrestaShop is not a difference, as at the worker-pool check and the
    # v2 summary validation (harness 25 reuses the harness-23 references).
    from ..data import versions
    try:
        if "harness_version" in changed and versions.reference_harness_compatible(
                doc["project"], doc["shared_identity"].get("harness_version"),
                identity.get("harness_version")):
            changed.remove("harness_version")
    except versions.ManifestError as exc:
        raise TQ.TestQualityRefused(f"REFUSED: {exc}") from exc
    require(not changed and identity.get("timeout_seconds") == doc["shared_identity"]["timeout_seconds"],
            "candidate differs from reference population/executor: " + str(changed))
    require(identity.get("gold_baseline_sha256") == doc["observations"]["full-gold"]["baseline"]["sha256"],
            "candidate names another gold baseline")
    memory_policy = (_memory_policy(worker_resources, identity)
                     if worker_resources is not None else None)
    require(memory_policy == doc.get("worker_memory_policy"),
            "candidate differs from reference worker memory policy or omits its runtime evidence")
    original = records["full-gold"]["outcomes"]
    require(expected and expected <= set(original), "selection is empty or contains unobserved pairs")
    gold = records["full-gold"]
    raw = (gold["raw_rows"] if gold.get("kind") == CONTINUED_KIND else
           {(row["item_id"], row["mutant_id"]): row
            for ref in doc["observations"]["full-gold"]["shards"]
            for row in TQ.load_jsonl(ref["path"])})
    # Preserve infrastructure outcomes/retry stamps for the existing degradation
    # checks. Only timeout changes representation: it is not literal failed G.
    rows = [{"item_id": iid, "mutant_id": mid,
             "outcome": "passed" if original[(iid, mid)] == "timeout" else original[(iid, mid)],
             "attempt": raw[(iid, mid)]["attempt"],
             "retried_infrastructure": raw[(iid, mid)]["retried_infrastructure"]}
            for iid, mid in sorted(expected)]
    ref = _reference(path)
    return TQ._seal_authenticated_gold_selection(rows, {
        "validation_class": "native", "manifest_digest": doc["shared_identity"]["manifest_digest"],
        "pairs_sha256": MR.pair_set_digest(expected), "engine": doc["shared_identity"]["engine"],
        "engine_version": doc["shared_identity"]["engine_version"],
        # One fixed inventory document fills the existing source/attestation
        # channels. It is not a raw JSONL file or an extra gold observation.
        "gold_results_sha256": ref["sha256"], "gold_results_attestation_sha256": ref["sha256"],
        "gold_results_source": ref["path"], "gold_results_attestation": ref["path"],
    })


def saved_reader(summary, expected):
    path = summary[SUMMARY_KEY]
    require(summary.get("verdict_basis") == "full_gold" and summary.get("inference_valid") is False,
            "saved result changed basis or inference boundary")
    require(summary.get("reference_method") == "single_observation"
            and summary.get("reference_observation_count") == 1
            and summary.get("candidate_observation_count") == 1,
            "saved result changed the single-observation policy")
    require(summary.get("gold_results_source") == path and summary.get("gold_results_attestation") == path,
            "saved result dropped its original reference authority")
    identity = {**summary, "timeout_seconds": summary.get("timeout_seconds")}
    doc, records = load(path)
    require(summary.get("reference_diagnostics") == doc["diagnostics"], "saved raw outcome diagnostics changed")
    # The native summary reader has authenticated these exact resources
    # against its root plan and candidate shards before invoking this reader.
    require(isinstance(summary.get("worker_resources"), list),
            "saved candidate has no worker-resource runtime evidence")
    return _selection(path, doc, records, expected, identity,
                      worker_resources=summary["worker_resources"])


def candidate_inputs(path, *, run_path, inputs, gold_baseline, task_items):
    """Read-only CLI preflight, including the real zero-job case."""
    doc, _ = load(path)
    for key in ASSETS:
        require(_reference(inputs[key]) == doc["inputs"][key], "candidate input differs: " + key)
    require(_reference(gold_baseline) == doc["observations"]["full-gold"]["baseline"],
            "candidate full-gold baseline differs")
    run_rows = TQ.load_jsonl(run_path)
    original = {row["item_id"]: row for row in TQ.load_jsonl(doc["inputs"]["release"]["path"])}
    tasks = TQ.load_jsonl(task_items)
    ids = [task["item_id"] for task in tasks]
    require(len(ids) == len(set(ids)) and set(ids) <= set(original),
            "candidate tasks are not a unique subset of the original release")
    from types import SimpleNamespace
    from ..data.prompt import checked_interfaces_block
    for task in tasks:
        checked_interfaces_block(task, SimpleNamespace(path=task_items))
        plain = {key: value for key, value in task.items() if key != "checked_interfaces"}
        require(plain == original[task["item_id"]],
                "candidate task changes original contents: " + task["item_id"])
    observed = [row["item_id"] for row in run_rows]
    require(len(observed) == len(set(observed)) and set(observed) == set(ids),
            "candidate rows differ from the declared complete sample")
    from ..core.ledger_primitives import domain_digest, ordered_item_ids_digest
    from ..core.source_view import verify_recorded_view
    from ..toolkit.source_views import MAP_SCHEMAS
    interfaces = domain_digest(MAP_SCHEMAS["r2t.target-body-map/v2"][1],
        [{"item_id": task["item_id"], "checked_interfaces": task["checked_interfaces"]}
         for task in tasks])
    population = ordered_item_ids_digest(ids)
    for row in run_rows:
        view = row.get("visibility")
        require(isinstance(view, dict)
                and view.get("interfaces_digest") == interfaces
                and view.get("population_digest") == population,
                "candidate visibility stamp differs from the exact annotated task sample")
        verify_recorded_view(row)
    mapping = json.loads(_checked(doc["inputs"]["map"]))["by_mutant"]
    expected = _pairs(mapping, TQ.passed_solutions(run_rows))
    return doc, expected


def saved_context(summary):
    """Recover B100 and the focused reader before native asset validation."""
    path = summary[SUMMARY_KEY]
    require(summary.get("gold_rows_precomputed") is True
            and summary.get("verdict_basis") == "full_gold"
            and summary.get("inference_valid") is False,
            "saved result must be candidate-only full-gold development evidence")
    require(summary.get("gold_results_source") == path
            and summary.get("gold_results_attestation") == path,
            "saved result dropped its original reference authority")
    doc, _ = load(path)
    for key in ASSETS:
        if key != "budgeted_sidecar":
            require(_reference(summary[key]) == doc["inputs"][key], "saved candidate asset differs: " + key)
    require(summary.get("reference_diagnostics") == doc["diagnostics"], "saved control diagnostics differ")
    # The old map release is immutable. A distinct annotated generation sample
    # owes both its bytes and its complete run membership, on every reload.
    task_ref = summary.get("prestashop_task_items")
    require(isinstance(task_ref, dict) and set(task_ref) == {"path", "sha256"},
            "saved result has no exact generation task sample")
    _checked(task_ref)
    candidate_inputs(path, run_path=summary["run"],
        inputs={key: doc["inputs"][key]["path"] for key in ASSETS},
        gold_baseline=doc["observations"]["full-gold"]["baseline"]["path"],
        task_items=task_ref["path"])
    return doc["inputs"]["budgeted_sidecar"]["path"], saved_reader


def protected_paths(path, doc):
    """Original control inputs must stay outside the candidate worker view."""
    return [path, *(ref["path"] for ref in doc["inputs"].values()),
            *doc["sources"].values(),
            *(record["baseline"]["path"] for record in doc["observations"].values()),
            *(record["recipe"]["path"] for record in doc["observations"].values()),
            *(os.path.dirname(ref["path"]) for record in doc["observations"].values() for ref in record.get("row_sources", record.get("shards", []))),
            *(record["continuation"]["plan"]["path"] for record in doc["observations"].values()
              if "continuation" in record),
            *(protected for record in doc["observations"].values()
              for protected in record.get("protected_paths", []))]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", help="JSON with assets, observations and source paths")
    parser.add_argument("--out", help="new single-observation reference evidence JSON")
    parser.add_argument("--check", help="reopen preserved evidence without writing")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        from .prestashop_reference_selftest import selftest
        return selftest()
    try:
        if args.check:
            require(not args.inputs and not args.out, "--check accepts no output/input manifest")
            doc, _records = load(args.check)
        else:
            require(bool(args.inputs) and bool(args.out), "--inputs and a new --out are required")
            inputs = _document(_reference(args.inputs))
            require(set(inputs) == {"assets", "observations", "sources"}, "input manifest shape differs")
            doc, _records = derive(inputs["assets"], inputs["observations"], inputs["sources"])
            with open(args.out, "x", encoding="utf-8") as handle:
                json.dump(doc, handle, indent=2, sort_keys=True)
                handle.write("\n")
        print(json.dumps({"schema": doc["schema"], "method": doc["method"],
                          "route": doc["route"], "items": doc["diagnostics"]["items_total"],
                          "observation_count": doc["reference_observation_count"]}, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    raise SystemExit(main())
