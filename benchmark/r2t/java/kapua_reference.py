"""Reuse three Kapua reference observations on authenticated development worksets.

This is the fixed count amendment, not the N1 timeout/exclusion policy or an
N2 intersection. Raw native observations remain the authority. The saved gold
rows are explicitly derived oracle indicators, never another native execution.

Census330 evidence may be sealed before its stub-control leg finishes
(KAPUA_CENSUS330_MUTATION_AMENDMENT.md section 12). Such stub-pending evidence
holds the full-gold and assertion-stripped observations only; every stub
measure is null and named as withheld, never read as 0, until a stub appendix
(`stub-appendix`) adds the stub-control observation to exactly that evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter
import copy
import json
import os
import sys

from . import kapua_census_mutation as CM
from . import kapua_gold_coverage as G
from . import kapua_headroom as H
from . import kapua_pilot as K
from ..data import mutation as M, mutation_attestation as A, subsets as S
from ..bench import mutation_run as MR, test_quality as TQ
from ..bench.reference_controls import STUB_RECALL_THRESHOLD
from ..toolkit import gold_killset as GK, hard_subset as HS, anti_vacuity as AV

SCHEMA = "r2t.kapua-reference-evidence/1"
SUMMARY_KEY = "kapua_reference_evidence"
ROLES = ("full-gold", "assertion-stripped-gold", "stub-control")
STUB = "stub-control"
STUB_FIELDS = ("stub_baseline", "stub_full_gold_recall", "stub_witness_recall")
APPENDIX_SCHEMA = "r2t.kapua-reference-stub-appendix/1"
# Stub-pending evidence carries this in its diagnostics, so every candidate
# summary that copies them names what is withheld and what completes it.
STUB_PENDING = {"status": "pending", "withheld": [*STUB_FIELDS, "stub_gate"],
                "completed_by": APPENDIX_SCHEMA}
ASSETS = ("mutation_validation", "manifest", "map", "release", "budgeted_sidecar")
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
        raise TQ.TestQualityRefused("REFUSED: Kapua reference " + reason)


def _pairs(mapping, items):
    return {(iid, mid) for mid, ids in mapping.items() for iid in ids if iid in items}


def _stub_kills(outcomes):
    """Per item, the stub's kills: the runner's kill classification, so a timeout counts."""
    kills = {}
    for (iid, mid), outcome in outcomes.items():
        if M.classify_outcome("passed", outcome) == "kill":
            kills.setdefault(iid, set()).add(mid)
    return kills


def derive(inputs, observations):
    """Reopen one exact native shard group per role; perform no execution.

    Census330 only (amendment section 12): without the stub-control role the
    evidence is stub-pending, the stub fields are null and
    `diagnostics.stub_control` lists them as withheld. Every full-gold and
    assertion-stripped field is what the three-role derivation writes
    (`_stub_pending`).
    """
    require(set(inputs) == set(ASSETS)
            and set(observations) in (set(ROLES), set(ROLES) - {STUB}),
            "needs the five L/B100 assets and the three control roles, "
            "or all but stub-control")
    paths = {key: G.canonical(path) for key, path in inputs.items()}
    assets = A.validate_campaign_asset_inputs(
        paths["mutation_validation"], manifest_path=paths["manifest"],
        map_path=paths["map"], release_path=paths["release"],
        budgeted_sidecar=paths["budgeted_sidecar"], require_release_ready=True)
    require(assets["asset_project"] == "kapua" and assets.get("population_basis") == "budgeted_sample",
            "requires the native Kapua budgeted L population")
    pilot = K.is_pilot(paths["release"])
    census = not pilot and CM.is_census(paths["release"])
    if pilot:
        _selection_doc, context = K.load_selection(paths["release"])
        ids = {row["item_id"] for row in context["items"]}
        replay = None
    elif census:
        # KAPUA_CENSUS330_MUTATION_AMENDMENT.md: the census330 B100 workset,
        # with every observation at the census runtime (its host rule).
        census_inputs = CM.load_inputs(paths["budgeted_sidecar"], paths)
        ids = set(CM.census_ids(paths["release"]))
        replay = None
    else:
        replay = S.replay_headroom(paths["release"])
        ids = set(replay["item_ids"])
    require(STUB in observations or census,
            "only census330 evidence may be sealed before its stub-control leg (amendment section 12)")
    mapping = assets["map"]["by_mutant"]
    records, saved, baselines = {}, {}, {}
    for role in (role for role in ROLES if role in observations):
        spec = observations[role]
        require(isinstance(spec, dict) and set(spec) == {"baseline", "shards"}, "role input shape differs")
        baseline = G.reference(spec["baseline"])
        rows = TQ.load_jsonl(baseline["path"])
        if role == "assertion-stripped-gold":
            outcomes = HS.load_fidelity(baseline["path"])["outcomes"]
        else:
            outcomes = AV.control_baseline(rows, "gold" if role == "full-gold" else "stub")
        require(set(outcomes) == ids, role + " baseline differs from exact L")
        if role == "full-gold":
            require(set(outcomes.values()) == {"passed"}, "full-gold baseline must pass on L")
            # Authenticates original R/K8/K7 -> C -> W4 L, retaining K8 stamps.
            if pilot:
                K.validate_full_gold(baseline["path"], paths["release"])
            elif census:
                CM.validate_full_gold(baseline["path"], paths["release"], census_inputs)
            else:
                gold_replay, _parent = H._gold_context(baseline["path"])
                require(gold_replay == replay, "full-gold projection names another L selection")
        if pilot:
            producer = context["fresh_plan"]["producer"]
            # A later control derivation retains its own coordinator commit;
            # executor identity, not a rewritten producer stamp, must match.
            require(all(row.get("harness_version") == producer["harness_version"] for row in rows),
                    role + " baseline differs from the fresh pilot harness")
        elif census:
            require(all(row.get("harness_version") == CM.RUNTIME["harness_version"] for row in rows),
                    role + " baseline differs from the census harness")
        passed = TQ.passed_solutions(rows)
        shards = [G.reference(path) for path in spec["shards"]]
        require(shards, role + " has no original native observation")
        record = GK.load_native_run([ref["path"] for ref in shards],
                                    required_side="gold" if role == "full-gold" else "candidate")
        identity = record["identity"]
        if pilot:
            fresh_plan = context["fresh_plan"]
            expected_runtime = {
                "harness_version": fresh_plan["producer"]["harness_version"],
                "container_image_digest": fresh_plan["pool"]["image_id"],
                "workspace_seed_digest": fresh_plan["pool"]["workspace_seed_digest"],
                "database_dump_digest": "no_database",
            }
            changed_runtime = sorted(key for key, value in expected_runtime.items()
                                     if identity.get(key) != value)
            require(not changed_runtime, role + " differs from fresh gold runtime: " + str(changed_runtime))
        elif census:
            changed_runtime = CM.runtime_differences(identity)
            require(not changed_runtime, role + " differs from the census runtime: " + str(changed_runtime))
        MR.validate_publishable_generation(identity, reference_roles={role})
        MR.validate_campaign_asset_claims(
            identity, assets, validation_path=paths["mutation_validation"],
            manifest_path=paths["manifest"], map_path=paths["map"], release_path=paths["release"])
        control = None
        if pilot and role != "full-gold":
            control = K._control(baseline["path"], paths["release"], assets["asset_index_sha256"],
                "stripped_gold" if role == "assertion-stripped-gold" else "stub", context)
        generation = MR.reference_generation_evidence(
            role=role, source_tag=identity.get("reference_source_tag"), candidate_rows=rows,
            release_item_ids=ids, release_sha256=G.reference(paths["release"])["sha256"],
            asset_index_sha256=assets["asset_index_sha256"], control=control)
        wanted = {**generation, **{key: assets[key] for key in BUDGET},
                  "candidate_run_sha256": baseline["sha256"],
                  "candidate_generated_tests_sha256": MR.candidate_digest(passed),
                  "solution_generated_tests_sha256": MR.candidate_digest(passed)}
        changed = sorted(key for key, value in wanted.items() if identity.get(key) != value)
        require(not changed, role + " differs from baseline/population identity: " + str(changed))
        require(set(record["outcomes"]) == _pairs(mapping, passed), role + " has a partial or extra baseline-eligible pair set")
        raw = [row for ref in shards for row in TQ.load_jsonl(ref["path"])]
        TQ.validate_native_retry_evidence(raw, where=role)
        records[role], baselines[role] = record, outcomes
        saved[role] = {"baseline": baseline, "shards": shards, "facts": record["facts"]}
    full = records["full-gold"]["identity"]
    for role, record in records.items():
        changed = sorted(key for key in SHARED if record["identity"].get(key) != full.get(key))
        require(not changed, role + " changed common population/executor fields: " + str(changed))
    observation_ids = [record["facts"]["observation_id"] for record in records.values()]
    shard_paths = [ref["path"] for record in saved.values() for ref in record["shards"]]
    require(len(set(observation_ids)) == len(records) and len(shard_paths) == len(set(shard_paths)),
            "controls must have distinct physical observations")
    gold = records["full-gold"]["outcomes"]
    stripped = records["assertion-stripped-gold"]["outcomes"]
    stub = records[STUB]["outcomes"] if STUB in records else None
    stub_kill_sets = _stub_kills(stub) if stub is not None else None
    per_item = {}
    for iid in sorted(ids):
        kills = {mid for (item, mid), outcome in gold.items() if item == iid and outcome == "failed"}
        witness = {mid for (item, mid), outcome in stripped.items() if item == iid and outcome == "passed"} & kills
        per_item[iid] = {
            "full_gold_failed": sorted(kills), "stripped_passed_witness": sorted(witness),
            "stripped_baseline": baselines["assertion-stripped-gold"][iid],
            **dict.fromkeys(STUB_FIELDS),
        }
        if stub is None:
            continue
        stub_kills = stub_kill_sets.get(iid, set())
        stub_eligible = baselines[STUB][iid] == "passed"
        per_item[iid].update({
            "stub_baseline": baselines[STUB][iid],
            "stub_full_gold_recall": len(kills & stub_kills) / len(kills) if kills and stub_eligible else None,
            "stub_witness_recall": len(witness & stub_kills) / len(witness) if witness and stub_eligible else None,
        })
    diagnostics = {"per_item": per_item, "raw_outcomes": {
        role: dict(sorted(Counter(record["outcomes"].values()).items())) for role, record in records.items()}}
    if stub is None:
        diagnostics["stub_control"] = copy.deepcopy(STUB_PENDING)
    doc = {"schema": SCHEMA, "project": "kapua", "route": "development", "inference_valid": False,
           "inputs": {key: G.reference(path) for key, path in paths.items()},
           "observations": saved,
           "shared_identity": {key: full.get(key) for key in sorted(SHARED)},
           "diagnostics": diagnostics}
    return doc, records


def _stub_pending(doc):
    """Three-role evidence as `derive` writes it without the stub-control role."""
    pending = copy.deepcopy(doc)
    del pending["observations"][STUB]
    del pending["diagnostics"]["raw_outcomes"][STUB]
    for entry in pending["diagnostics"]["per_item"].values():
        entry.update(dict.fromkeys(STUB_FIELDS))
    pending["diagnostics"]["stub_control"] = copy.deepcopy(STUB_PENDING)
    return pending


def _record_paths(record):
    return {"baseline": record["baseline"]["path"], "shards": [ref["path"] for ref in record["shards"]]}


def _observation_paths(doc):
    try:
        return ({key: ref["path"] for key, ref in doc["inputs"].items()},
                {role: _record_paths(record) for role, record in doc["observations"].items()})
    except (KeyError, TypeError, AttributeError) as exc:
        raise TQ.TestQualityRefused("REFUSED: malformed Kapua reference evidence") from exc


def stub_appendix(evidence, stub):
    """The stub-control appendix of census evidence (amendment section 12).

    For stub-pending evidence, the three-role derivation over the evidence's
    own inputs and observations plus `stub` ({"baseline", "shards"}) must equal
    the evidence once the stub fields are withheld again, so an appendix only
    adds the stub role to the evidence it names: a stub leg at another
    population or executor identity, or evidence that is not exactly this
    derivation, refuses. Three-role evidence is completed from its own stub
    leg only.

    `stub_gate` is measured, not applied (amendment section 6). It is not
    exactly the full-population statistic: the census stub leg covers only
    items whose stub baseline passes (`items_stub_baseline_not_passed` counts
    the items with a nonempty G_i it leaves out), `macro_recall` counts a stub
    timeout as a kill as the per-item diagnostics do (`macro_recall_literal_failed`
    counts only `failed`), and a stub infrastructure outcome on a G_i pair
    stays in the denominator as a non-kill where the full-population
    statistic drops the pair (`infrastructure_pairs_on_G` counts them).
    """
    ref = G.reference(evidence)
    doc = G.document(ref)
    require(doc.get("schema") == SCHEMA and isinstance(doc.get("diagnostics"), dict), "evidence schema differs")
    inputs, observations = _observation_paths(doc)
    if STUB in observations:
        require(isinstance(stub, dict) and set(stub) == {"baseline", "shards"}
                and {"baseline": G.canonical(stub["baseline"]), "shards": [G.canonical(path) for path in stub["shards"]]}
                == observations[STUB], "three-role evidence is completed from its own stub leg only")
        full, records = derive(inputs, observations)
        require(full == doc, "saved inputs, observation identity or diagnostics changed")
    else:
        require(doc["diagnostics"].get("stub_control") == STUB_PENDING, "evidence has no stub-pending record")
        full, records = derive(inputs, {**observations, STUB: stub})
        require(_stub_pending(full) == doc,
                "stub appendix does not complete this evidence: inputs, full-gold or stripped identity differ")
    outcomes = records[STUB]["outcomes"]
    kills = _stub_kills(outcomes)
    per_item, recalls, literal, infrastructure = {}, [], [], 0
    for iid, entry in full["diagnostics"]["per_item"].items():
        gold = set(entry["full_gold_failed"])
        eligible = entry["stub_baseline"] == "passed"
        per_item[iid] = {**{key: entry[key] for key in STUB_FIELDS},
                         # The stub's kills among G_i, so a reader can drop listed
                         # mutants; null where the stub was not observed.
                         "stub_killed_full_gold": sorted(kills.get(iid, set()) & gold) if eligible else None}
        if entry["stub_full_gold_recall"] is not None:
            recalls.append(entry["stub_full_gold_recall"])
            literal.append(sum(outcomes[(iid, mid)] == "failed" for mid in gold) / len(gold))
            infrastructure += sum(M.classify_outcome("passed", outcomes[(iid, mid)]) == "infrastructure" for mid in gold)
    return {"schema": APPENDIX_SCHEMA, "project": "kapua", "inference_valid": False,
            "evidence": ref, "observation": full["observations"][STUB],
            "diagnostics": {"per_item": per_item, "raw_outcomes": full["diagnostics"]["raw_outcomes"][STUB],
                            "stub_gate": {
                                "threshold": STUB_RECALL_THRESHOLD, "items": len(recalls),
                                "items_stub_baseline_not_passed": sum(
                                    bool(entry["full_gold_failed"]) and entry["stub_baseline"] != "passed"
                                    for entry in full["diagnostics"]["per_item"].values()),
                                "infrastructure_pairs_on_G": infrastructure,
                                "macro_recall": sum(recalls) / len(recalls) if recalls else None,
                                "macro_recall_literal_failed": sum(literal) / len(literal) if literal else None}}}


def load_stub_appendix(path):
    """Reopen a stub appendix against the evidence it names, as it is now."""
    doc = G.document(G.reference(path))
    require(doc.get("schema") == APPENDIX_SCHEMA, "stub appendix schema differs")
    try:
        evidence, stub = doc["evidence"]["path"], _record_paths(doc["observation"])
    except (KeyError, TypeError, AttributeError) as exc:
        raise TQ.TestQualityRefused("REFUSED: malformed Kapua stub appendix") from exc
    require(doc == stub_appendix(evidence, stub),
            "stub appendix names other evidence, another stub observation or changed measures")
    return doc


def load(path):
    doc = G.document(G.reference(path))
    require(doc.get("schema") == SCHEMA, "evidence schema differs")
    try:
        rebuilt, records = derive(*_observation_paths(doc))
    except (KeyError, TypeError) as exc:
        raise TQ.TestQualityRefused("REFUSED: malformed Kapua reference evidence") from exc
    require(doc == rebuilt, "saved inputs, observation identity or diagnostics changed")
    return doc, records


def selection(path, expected, identity):
    """Mint the existing arithmetic seal only after reopening original evidence."""
    return _selection(path, *load(path), expected, identity)


def _selection(path, doc, records, expected, identity):
    changed = sorted(key for key in CANDIDATE_SHARED if identity.get(key) != doc["shared_identity"].get(key))
    require(not changed and identity.get("timeout_seconds") == doc["shared_identity"]["timeout_seconds"],
            "candidate differs from reference population/executor: " + str(changed))
    require(identity.get("gold_baseline_sha256") == doc["observations"]["full-gold"]["baseline"]["sha256"],
            "candidate names another gold baseline")
    original = records["full-gold"]["outcomes"]
    require(expected and expected <= set(original), "selection is empty or contains unobserved pairs")
    raw = {(row["item_id"], row["mutant_id"]): row for ref in doc["observations"]["full-gold"]["shards"]
           for row in TQ.load_jsonl(ref["path"])}
    # Preserve infrastructure outcomes/retry stamps for the existing degradation
    # checks. Only timeout changes representation: it is not literal failed G.
    rows = [{"item_id": iid, "mutant_id": mid,
             "outcome": "passed" if original[(iid, mid)] == "timeout" else original[(iid, mid)],
             "attempt": raw[(iid, mid)]["attempt"],
             "retried_infrastructure": raw[(iid, mid)]["retried_infrastructure"]}
            for iid, mid in sorted(expected)]
    ref = G.reference(path)
    return TQ._seal_authenticated_gold_selection(rows, {
        "validation_class": "native", "manifest_digest": doc["shared_identity"]["manifest_digest"],
        "pairs_sha256": MR.pair_set_digest(expected), "engine": doc["shared_identity"]["engine"],
        "engine_version": doc["shared_identity"]["engine_version"],
        # One fixed inventory document fills the existing source/attestation
        # channels. It is not a raw JSONL file or an extra gold observation.
        "gold_results_sha256": ref["sha256"], "gold_results_attestation_sha256": ref["sha256"],
        "gold_results_source": ref["path"], "gold_results_attestation": ref["path"],
    })


def _saved_gold_authority(summary):
    """Where a saved result's gold rows came from, as the reader requires.

    Copied from the evidence (the default), or observed again in the
    campaign on the evidence's full-gold kills (a gold pair plan;
    GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md section 4), in which case no
    cached-gold channel is named.
    """
    path = summary[SUMMARY_KEY]
    on_host = summary.get("gold_pair_plan") is not None
    require(summary.get("gold_rows_precomputed") is (not on_host),
            "saved result must copy the evidence's gold rows, or re-observe gold on its pair plan")
    authority = (None, None) if on_host else (path, path)
    require((summary.get("gold_results_source"), summary.get("gold_results_attestation")) == authority,
            "saved result dropped its original reference authority")
    return path


def saved_reader(summary, expected):
    path = _saved_gold_authority(summary)
    require(summary.get("verdict_basis") == "full_gold" and summary.get("inference_valid") is False,
            "saved result changed basis or inference boundary")
    identity = {**summary, "timeout_seconds": summary.get("timeout_seconds")}
    doc, records = load(path)
    require(summary.get("reference_diagnostics") == doc["diagnostics"], "saved raw outcome diagnostics changed")
    return _selection(path, doc, records, expected, identity)


def candidate_inputs(path, *, run_path, inputs, gold_baseline):
    """Read-only CLI preflight, including the real zero-job case."""
    doc, _ = load(path)
    for key in ASSETS:
        require(G.reference(inputs[key]) == doc["inputs"][key], "candidate input differs: " + key)
    require(G.reference(gold_baseline) == doc["observations"]["full-gold"]["baseline"],
            "candidate full-gold baseline differs")
    if K.is_pilot(inputs["release"]):
        K.validate_candidates(run_path, inputs["release"])
    elif CM.is_census(inputs["release"]):
        CM.validate_candidates(run_path, inputs["release"])
    else:
        H.validate_candidate_workset(run_path, inputs["release"])
    run_rows = TQ.load_jsonl(run_path)
    mapping = json.loads(G.checked(doc["inputs"]["map"]))["by_mutant"]
    expected = _pairs(mapping, TQ.passed_solutions(run_rows))
    return doc, expected


def saved_context(summary):
    """Recover B100 and the focused reader before native asset validation."""
    path = _saved_gold_authority(summary)
    require(summary.get("verdict_basis") == "full_gold"
            and summary.get("inference_valid") is False,
            "saved result must be full-gold development evidence")
    doc, _ = load(path)
    for key in ASSETS:
        if key != "budgeted_sidecar":
            require(G.reference(summary[key]) == doc["inputs"][key], "saved candidate asset differs: " + key)
    require(summary.get("reference_diagnostics") == doc["diagnostics"], "saved control diagnostics differ")
    return doc["inputs"]["budgeted_sidecar"]["path"], saved_reader


def protected_paths(path, doc):
    """Original control inputs must stay outside the candidate worker view.

    Stub-pending evidence does not yet name its stub leg, which is placed
    beside it later; its whole directory is protected instead.
    """
    pending = (doc.get("diagnostics") or {}).get("stub_control") is not None
    return [path, *(ref["path"] for ref in doc["inputs"].values()),
            *(record["baseline"]["path"] for record in doc["observations"].values()),
            *(os.path.dirname(ref["path"]) for record in doc["observations"].values() for ref in record["shards"]),
            *([os.path.dirname(os.path.abspath(path))] if pending else [])]


def _selftest_saved(root):
    # Only the inherited fixture's native-capture leaves are synthetic. Seed,
    # Docker authority/runtime files, projections, raw shards and saved reads
    # are real evidence validators in this fresh interpreter.
    from pathlib import Path
    from ..core.boundary import load_boundary
    from ..bench import results as R, report as REPORT, population as P
    import contextlib
    import io
    root = Path(root)
    plan = json.loads((root / "collected/plan.json").read_text())
    manifest = json.loads((root / "population.json").read_text())
    def fixture_inputs(value):
        assert value == plan["inputs"]
        for key in ("boundary", "profile"):
            G.checked(value[key])
        G.checked({"path": str(root / "native.json"), "sha256": value["native_capture"]["receipt_sha256"]})
        G.checked({"path": str(root / "compiler.json"), "sha256": value["compiler_capture"]["receipt_sha256"]})
        files = {p for module in manifest["analysis_recipe"]["modules"] for p in module["source_files"]}
        return G.P.measured_release(value["release_root"]), load_boundary(value["boundary"]["path"]), {}, files
    def fixture_pool(*args):
        for worker in plan["pool"]["workers"]:
            for key in ("spec", "runtime", "binding"):
                G.checked(worker[key])
        return plan["pool"], []
    G.load_inputs, G.offline_pool = fixture_inputs, fixture_pool
    G.W.preflight = lambda *args, **kwargs: {}
    paths = json.loads((root / "reference-reuse/fixture-paths.json").read_text())
    view, gold, release = paths["view"], paths["gold"], paths["inputs"]["release"]
    summary = TQ.load_bound_test_quality(view)
    assert summary["recall_macro"] == 1.0 and summary["verdict_basis"] == "full_gold"
    assert summary["reference_diagnostics"]["raw_outcomes"]["full-gold"]["timeout"] == 1
    rendered = R.results(view, gold_path=gold, boundary=load_boundary(str(root / "boundary.yml")),
                         api_scoring="none", release_path=release)
    with contextlib.redirect_stdout(io.StringIO()) as output:
        reports = REPORT.report([view], release_paths=[release])
    assert rendered["population"]["planned_n"] == 2 and rendered["population"]["inference_valid"] is False
    assert next(iter(reports.values()))["population"]["planned_n"] == 2
    original = str(root / "openhands-sample1.jsonl")
    assert P.resolve(TQ.load_jsonl(original), original,
                     explicit_release=str(root / "census/eval-census.jsonl"))["planned_n"] == 6
    assert TQ.find_sidecar(original) is None
    print("PASS fresh-process three-control native-v1/B100 reload and descriptive L/C reports")


def _selftest_gold_killed_scope(*, work, root, view, candidate, gold, gold_rows, manifest,
                                mapping, admitted, identity, provenance, resources,
                                observations, gold_kill, gold_timeout, full, evidence,
                                inputs, seed, worker_path, shared, engine_dir, refuses):
    """GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md over the real native readers.

    Both routes of the spec's section 4: the evidence's sealed gold copied
    in, and gold observed again on the scoring host on its kills. Each
    keeps the full-scope verdicts and recall and withholds the companions;
    each saves as evidence the reader re-derives, and the Kapua pair plan must
    be exactly the evidence's literal-failed kills.
    """
    import contextlib
    import io
    from pathlib import Path
    from types import SimpleNamespace
    from unittest.mock import patch
    from ..bench import cli, worker as W
    seen = []
    reproduced = {"outcome": "failed"}

    def execute(job):
        seen.append(job)
        rows = [{"item_id": iid, "mutant_id": mid,
                 "outcome": ("timeout" if job["side"] == "candidate"
                             else reproduced["outcome"] if (iid, mid) == gold_kill else "passed"),
                 "attempt": 1, "retried_infrastructure": False, **MR.row_identity_stamp(job["identity"])}
                for iid, mid in sorted(TQ._job_pairs(job["mutants"], job["by_mutant"], job["files_by_item"]))]
        os.makedirs(os.path.dirname(job["out"]), exist_ok=True)
        Path(job["out"]).write_text("".join(json.dumps(row) + "\n" for row in rows))
        for status in ("running", "complete"):
            MR.write_shard_provenance(job["out"], job["identity"], status, provenance=job["provenance"])
        return {"out": job["out"], "rows": len(rows), "side": job["side"]}

    def executed(side):
        return {pair for job in seen if job["side"] == side
                for pair in TQ._job_pairs(job["mutants"], job["by_mutant"], job["files_by_item"])}

    def final(summary, summary_path):
        # A withheld measure re-inserted as a number is not what the rows say.
        path = Path(summary_path)
        original = path.read_bytes()
        forged = dict(summary, jaccard_macro=full["jaccard_macro"])
        path.write_text(json.dumps(forged))
        try:
            TQ._validate_native_summary_before_completion(forged, summary_path, view)
        except TQ.TestQualityRefused as exc:
            assert "jaccard_macro" in str(exc), str(exc)
        else:
            raise AssertionError("a gold-killed summary printed a Jaccard it never measured")
        finally:
            path.write_bytes(original)
        TQ._validate_native_summary_before_completion(summary, summary_path, view)

    def same_verdicts(summary):
        return (all(summary[key] == full[key] for key in ("recall_macro", "verdicts", "non_vacuous_passes", "n_scorable"))
                and {iid: (entry["verdict"], entry["recall"]) for iid, entry in summary["per_item"].items()}
                == {iid: (entry["verdict"], entry["recall"]) for iid, entry in full["per_item"].items()})

    def withheld(summary):
        return (summary["candidate_pair_scope"] == TQ.CANDIDATE_PAIRS_GOLD_KILLED
                and summary["jaccard_macro"] is None and set(summary["excluded"].values()) == {None}
                and all(entry["jaccard"] is None and entry["candidate_only_kills"] is None
                        for entry in summary["per_item"].values()))

    # Sealed gold copied in: the candidate executes exactly the one kill.
    copied = TQ.run_test_quality(run_rows=candidate, gold_baseline_rows=gold_rows, manifest=manifest,
        by_mutant=mapping, out_dir=str(work / "candidate-campaign-gold-killed"), execute=execute,
        n_workers=1, authenticated_gold=admitted, identity_inputs=identity, provenance=provenance,
        worker_resources=resources, final_summary_validator=final,
        candidate_pairs=TQ.CANDIDATE_PAIRS_GOLD_KILLED)
    assert executed("candidate") == {gold_kill} and not executed("gold")
    assert same_verdicts(copied) and withheld(copied) and copied["gold_rows_precomputed"] is True
    print("PASS: gold-killed candidate slice over sealed Kapua gold keeps verdicts and recall")

    # Gold observed again on the evidence's kills. The plan is built from the
    # full-gold evidence rows: its timeout pair is not a literal kill.
    plan_path = str(work / "gold-pairs.json")
    G.write(plan_path, TQ.build_gold_pair_plan(
        TQ.load_jsonl(observations["full-gold"]["shards"][0]),
        manifest_digest=manifest["digest"], source="fixture full-gold evidence"))
    plan, binding = TQ.load_gold_pair_plan(plan_path, manifest_digest=manifest["digest"])
    assert plan == {gold_kill} and gold_timeout not in plan
    on_host_identity = {**identity, "gold_results_sha256": None, "gold_results_attestation_sha256": None}
    on_host_provenance = {**provenance, "gold_results_source": None, "gold_results_attestation": None}

    def on_host(out, pairs, pairs_binding, validator):
        return TQ.run_test_quality(run_rows=candidate, gold_baseline_rows=gold_rows, manifest=manifest,
            by_mutant=mapping, out_dir=str(work / out), execute=execute, n_workers=1,
            identity_inputs=on_host_identity, provenance=on_host_provenance,
            worker_resources=resources, final_summary_validator=validator,
            candidate_pairs=TQ.CANDIDATE_PAIRS_GOLD_KILLED,
            gold_pair_plan=pairs, gold_pair_plan_binding=pairs_binding)

    seen.clear()
    reobserved = on_host("candidate-campaign-on-host-gold", plan, binding, final)
    assert executed("candidate") == executed("gold") == {gold_kill}
    assert same_verdicts(reobserved) and withheld(reobserved)
    assert reobserved["gold_rows_precomputed"] is False and reobserved["gold_pair_plan"] == binding
    wide_path = str(work / "gold-pairs-wide.json")
    G.write(wide_path, dict(G.document(G.reference(plan_path)), pairs=sorted([list(gold_kill), list(gold_timeout)])))
    wide, wide_binding = TQ.load_gold_pair_plan(wide_path, manifest_digest=manifest["digest"])
    refuses("on-host gold plan that is not the evidence's kills", lambda: on_host(
        "candidate-campaign-wide-plan", wide, wide_binding,
        lambda summary, path: TQ._validate_native_summary_before_completion(summary, path, view)),
        "not the reference evidence's full-gold kills")
    print("PASS: on-host Kapua gold over the evidence's kills keeps verdicts and recall")

    # A gold timeout on the scoring host is not a kill, exactly as the sealed
    # evidence reads its own (census amendment sections 6 and 7.2): the plan
    # pair leaves the denominator and stays listed by its observed outcome.
    seen.clear()
    reproduced["outcome"] = "timeout"
    try:
        timed = on_host("candidate-campaign-on-host-gold-timeout", plan, binding,
            lambda summary, path: TQ._validate_native_summary_before_completion(summary, path, view))
    finally:
        reproduced["outcome"] = "failed"
    written = TQ.load_jsonl(timed["gold_results"])
    assert executed("gold") == {gold_kill} and [row["outcome"] for row in written] == ["timeout"]
    assert TQ.gold_killed_pairs(written, {row["item_id"]: "passed" for row in gold_rows},
                                {gold_kill[0]}) == {gold_kill}, "the generic reading counts it"
    assert timed["n_scorable"] == 0 and all(entry["gold_killed"] == 0 for entry in timed["per_item"].values())
    print("PASS: an on-host Kapua gold timeout leaves G_i, as in the sealed evidence")

    # The same through the real CLI assembly, and its preflight refusal.
    def runtime_read(paths, workers, seed_path, version, needs_database, *, project):
        assert project == "kapua" and paths == [worker_path] and not needs_database
        return {**shared, "worker_resources": resources, "protected_evidence_paths": []}

    def run_slice(_harness, mutants, _items, files, by_mutant, _engine_dir, out_path, **kw):
        return execute({"identity": kw["identity"], "side": kw["identity"]["side"],
                        "mutants": mutants, "files_by_item": files, "by_mutant": by_mutant,
                        "out": out_path, "provenance": kw["provenance"]})

    def drive(out, pairs_path, evidence_path=evidence):
        args = argparse.Namespace(**inputs, run=view, gold_baseline=gold,
            kapua_reference_evidence=evidence_path, development=True, seed=str(seed), workers=[worker_path],
            out=str(work / out), gold_results=None, gold_results_attestation=None,
            timeout=600, allow_incomplete=False, allow_degraded_gold=False, no_sidecar=True,
            gold=str(root / "release/gold"), artifacts=str(work), repo=str(work / "workspace"),
            boundary=str(root / "boundary.yml"), resume=False,
            candidate_pairs=TQ.CANDIDATE_PAIRS_GOLD_KILLED, gold_pair_plan=pairs_path)
        with patch.object(W, "validate_mutation_runtime", runtime_read), \
             patch.object(cli, "_stack", lambda _args: SimpleNamespace(
                 engine_dir=engine_dir, FRAMEWORK="cucumber")), \
             patch.object(cli, "_stack_profile", lambda _args: SimpleNamespace(needs_database=False)), \
             patch.object(cli, "_behat_row", lambda _args: None), \
             patch.object(cli, "_harness", lambda _args: (SimpleNamespace(substrate_baseline_sha256="1" * 64), None, None)), \
             patch.object(MR, "run_slice", run_slice), contextlib.redirect_stdout(io.StringIO()):
            return cli.cmd_test_quality(args)

    seen.clear()
    assert drive("cli-on-host-gold", plan_path) == 0
    assert executed("candidate") == executed("gold") == {gold_kill}
    saved = TQ._load_json_object(str(work / "cli-on-host-gold" / TQ.SUMMARY), "fixture summary")
    assert same_verdicts(saved) and withheld(saved) and saved["gold_pair_plan"] == binding
    refuses("CLI gold pair plan that is not the evidence's kills", lambda: drive("cli-wide-plan", wide_path),
            "not the reference evidence's full-gold kills")
    assert not (work / "cli-wide-plan").exists()
    print("PASS: CLI on-host Kapua gold admits exactly the evidence's kills")
    return drive, plan_path


def _selftest_with_headroom(root, inputs, gold, source_run):
    """Real native readers; only the per-pair worker execution is synthetic."""
    import copy
    import contextlib
    import io
    from pathlib import Path
    from .. import docker_authority as D
    from ..bench import worker as W, seed as SEED, cli
    from ..bench.validate import HARNESS_VERSION
    from ..core.boundary import load_boundary

    def refuses(label, fn, fragment=""):
        try:
            fn()
        except (ValueError, OSError, RuntimeError, SystemExit) as exc:
            assert fragment in str(exc), label + ": " + str(exc)
            print("PASS refusal: " + label)
            return
        raise AssertionError(label + " accepted")

    work = root / "reference-reuse"
    work.mkdir()
    seed = work / "seed"
    boundary = load_boundary(str(root / "boundary.yml"))
    SEED.build_seed(boundary.repo_root, boundary, str(seed), "no_database", None, needs_database=False)
    seed_identity = W.verified_seed_identity(str(seed), False)
    worker_path = str(work / "worker.json")
    worker_doc = {"index": 0, "workspace": str(work / "workspace"), "container": "worker0",
                  "schema": "", "credential": "", "env_file": str(work / "worker.env"),
                  "workdir": "/workspace", "out_path": str(work / "unused.jsonl"),
                  "artifacts_root": str(work / "unused-artifacts")}
    G.write(worker_path, worker_doc)
    worker = W.WorkerSpec.from_json(worker_doc)
    authority_path = str(work / "authority.json")
    D.write_evidence_no_clobber(authority_path, D._fixture_authority())
    _, authority_ref = D.evidence_reference(authority_path, expected_schema=D.AUTHORITY_SCHEMA,
        validator=lambda value: D.validate_authority_document(value, current_source=False), label="fixture authority")
    binding = D._fixture_binding()
    binding["authority"] = authority_ref
    binding["pool"] = W.build_execution_pool([worker], [worker_path], database_container=None, internal_network=None)
    binding["worker_spec_sha256"] = MR.sha256_file(worker_path)
    binding["digest"] = D.semantic_digest(binding)
    D.write_evidence_no_clobber(W.binding_attestation_path(worker_path), binding)
    runtime = W.build_worker_runtime_attestation(worker, worker_path, seed_identity, HARNESS_VERSION,
        binding_path=W.binding_attestation_path(worker_path))
    D.write_evidence_no_clobber(W.runtime_attestation_path(worker_path), runtime)
    W.validate_offline_worker_runtime_pool([worker_path])
    resources = [{key: worker_doc[key] for key in
                  ("index", "workspace", "container", "schema", "credential", "env_file", "workdir")}]
    resources[0].update(worker_spec=worker_path, runtime_attestation=W.runtime_attestation_path(worker_path),
                        runtime_attestation_sha256=MR.sha256_file(W.runtime_attestation_path(worker_path)))
    assets = A.validate_campaign_asset_inputs(inputs["mutation_validation"],
        manifest_path=inputs["manifest"], map_path=inputs["map"], release_path=inputs["release"],
        budgeted_sidecar=inputs["budgeted_sidecar"])
    manifest, mapping = assets["manifest"], assets["map"]["by_mutant"]
    engine_dir, applier = MR.binding_for(manifest["engine"])
    shared = {"asset_index_sha256": assets["asset_index_sha256"], "asset_project": "kapua",
              "mutation_validation_sha256": MR.sha256_file(inputs["mutation_validation"]),
              "mutation_validation_class": "native", "manifest_sha256": MR.sha256_file(inputs["manifest"]),
              "manifest_digest": manifest["digest"], "map_sha256": MR.sha256_file(inputs["map"]),
              "release_sha256": MR.sha256_file(inputs["release"]), "substrate_baseline_sha256": "1" * 64,
              "applier_sha256": MR.sha256_file(os.path.join(engine_dir, applier.source)),
              "harness_version": HARNESS_VERSION, "container_image_digest": binding["container"]["image_id"],
              "workspace_seed_digest": seed_identity["workspace_seed_digest"], "database_dump_digest": "no_database",
              "engine": manifest["engine"], "engine_version": manifest["engine_version"], "parser": manifest["parser"],
              "worker_resources_sha256": MR.content_digest(resources), **{key: assets[key] for key in BUDGET}}
    gold_rows = TQ.load_jsonl(gold)
    ids = {row["item_id"] for row in gold_rows}
    all_pairs = sorted(_pairs(mapping, ids))
    assert len(all_pairs) >= 2
    gold_kill, gold_timeout = all_pairs[:2]
    observations = {}
    raw_bytes = {}
    for index, role in enumerate(ROLES):
        rows = copy.deepcopy(gold_rows)
        baseline = gold
        if role != "full-gold":
            for row in rows:
                row["adapter"] = MR.REFERENCE_CONTROL_ROLE_ADAPTERS[role]
                row["metadata"] = ({"source": "stripped_gold", "stripped_gold": True, "item_id": row["item_id"]}
                                   if role == "assertion-stripped-gold" else {"stub": True})
                row["harness_commit"] = "later-control-producer"
                if role == "assertion-stripped-gold" and row["item_id"] == gold_timeout[0]:
                    row["outcome"] = "failed"
                row["produced_files"] = [{"file_path": "tests/Control.java", "code": "class Control {}"}]
            baseline = str(work / (role + "-baseline.jsonl"))
            Path(baseline).write_text("".join(json.dumps(row) + "\n" for row in rows))
        generation = MR.reference_generation_evidence(role=role, source_tag="fixture-control-freeze",
            candidate_rows=rows, release_item_ids=ids, release_sha256=shared["release_sha256"],
            asset_index_sha256=shared["asset_index_sha256"])
        role_pairs = sorted(_pairs(mapping, TQ.passed_solutions(rows)))
        digest = MR.candidate_digest(TQ.passed_solutions(rows))
        identity = MR.build_campaign_identity(**shared, **generation,
            candidate_run_sha256=MR.sha256_file(baseline), candidate_generated_tests_sha256=digest,
            solution_generated_tests_sha256=digest, expected_pairs=role_pairs,
            side="gold" if role == "full-gold" else "candidate", shard=0, of=1, timeout=600)
        path = str(work / role / (identity["side"] + ".w0.jsonl"))
        MR.prepare_standalone_output_directory(path, identity, str(index + 1) * 32)
        raw = []
        for pair in role_pairs:
            outcome = ("failed" if pair == gold_kill else "timeout" if pair == gold_timeout else "passed") if role == "full-gold" else "passed"
            raw.append({"item_id": pair[0], "mutant_id": pair[1], "outcome": outcome,
                        "attempt": 1, "retried_infrastructure": False, **MR.row_identity_stamp(identity)})
        Path(path).write_text("".join(json.dumps(row) + "\n" for row in raw))
        for status in ("running", "complete"):
            MR.write_shard_provenance(path, identity, status, provenance={"worker_resources": resources})
        observations[role] = {"baseline": baseline, "shards": [path]}
        raw_bytes[path] = Path(path).read_bytes()
    doc, records = derive(inputs, observations)
    # Exercise the pilot branch with real native observations. Its selection
    # and fresh-gold proof are independently exercised by kapua_pilot.selftest;
    # substitute only that already-authenticated context at this boundary.
    from unittest.mock import patch
    pilot_context, _items, control_paths, control_source = K._fixture_controls(
        work / "pilot-controls", inputs["release"])
    pilot_context["fresh_plan"]["pool"] = {
        "image_id": shared["container_image_digest"],
        "workspace_seed_digest": shared["workspace_seed_digest"]}
    pilot_observations = {"full-gold": observations["full-gold"]}
    for index, role in enumerate(ROLES[1:], 2):
        canonical = "stripped_gold" if role == "assertion-stripped-gold" else "stub"
        baseline = control_paths[canonical]
        rows = TQ.load_jsonl(baseline)
        control = K._control(baseline, inputs["release"], shared["asset_index_sha256"], canonical, pilot_context)
        generation = MR.reference_generation_evidence(role=role, source_tag="fixture-control-freeze",
            candidate_rows=rows, release_item_ids=ids, release_sha256=shared["release_sha256"],
            asset_index_sha256=shared["asset_index_sha256"], control=control)
        files = TQ.passed_solutions(rows)
        pairs = _pairs(mapping, files)
        digest = MR.candidate_digest(files)
        identity = MR.build_campaign_identity(**shared, **generation,
            candidate_run_sha256=MR.sha256_file(baseline), candidate_generated_tests_sha256=digest,
            solution_generated_tests_sha256=digest, expected_pairs=pairs,
            side="candidate", shard=0, of=1, timeout=600)
        path = str(work / ("pilot-" + role) / "candidate.w0.jsonl")
        MR.prepare_standalone_output_directory(path, identity, str(index + 4) * 32)
        raw = [{"item_id": iid, "mutant_id": mid, "outcome": "passed", "attempt": 1,
                "retried_infrastructure": False, **MR.row_identity_stamp(identity)} for iid, mid in sorted(pairs)]
        Path(path).write_bytes(K.encoded(raw))
        for status in ("running", "complete"):
            MR.write_shard_provenance(path, identity, status, provenance={"worker_resources": resources})
        pilot_observations[role] = {"baseline": baseline, "shards": [path]}
    with patch.object(K, "is_pilot", return_value=True), \
            patch.object(K, "load_selection", return_value=({}, pilot_context)), \
            patch.object(K, "validate_full_gold") as full_proof:
        pilot_doc, _ = derive(inputs, pilot_observations)
        full_proof.assert_called_once_with(gold, inputs["release"])
        pilot_evidence = str(work / "pilot-references.json")
        G.write(pilot_evidence, pilot_doc)
        assert load(pilot_evidence)[0] == pilot_doc
        source_bytes = Path(control_source).read_bytes()
        Path(control_source).write_bytes(source_bytes.replace(b"int value = 7", b"int value = 8"))
        refuses("saved pilot control source drift", lambda: load(pilot_evidence))
        Path(control_source).write_bytes(source_bytes)
        for owner, key, bad in (("producer", "harness_version", HARNESS_VERSION + 1),
                                ("pool", "image_id", "sha256:" + "0" * 64),
                                ("pool", "workspace_seed_digest", "0" * 64)):
            original = pilot_context["fresh_plan"][owner][key]
            pilot_context["fresh_plan"][owner][key] = bad
            refuses("pilot references differ from fresh gold " + key, lambda: derive(inputs, pilot_observations))
            pilot_context["fresh_plan"][owner][key] = original
        # All three observations can agree with each other yet use an old
        # harness. Baselines stay at the fresh producer in this negative case.
        native_reader = GK.load_native_run
        def older_runtime(*args, **kwargs):
            record = copy.deepcopy(native_reader(*args, **kwargs))
            record["identity"]["harness_version"] = HARNESS_VERSION - 1
            return record
        with patch.object(GK, "load_native_run", side_effect=older_runtime):
            try:
                derive(inputs, pilot_observations)
            except TQ.TestQualityRefused as exc:
                assert "differs from fresh gold runtime" in str(exc) and "harness_version" in str(exc)
            else:
                raise AssertionError("matching references on another runtime were accepted")
    evidence = str(work / "references.json")
    G.write(evidence, doc)
    assert load(evidence)[0] == doc
    assert doc["diagnostics"]["raw_outcomes"]["full-gold"]["timeout"] == 1
    assert {r["facts"]["observation_id"] for r in records.values()} == {str(n) * 32 for n in (1, 2, 3)}
    assert doc["diagnostics"]["per_item"][gold_timeout[0]]["stripped_baseline"] == "failed"
    assert gold_timeout not in records["assertion-stripped-gold"]["outcomes"]
    view = H.project_sample1(gold, source_run, str(work / "candidate-view"))["run"]["path"]
    candidate = TQ.load_jsonl(view)
    _, expected = candidate_inputs(evidence, run_path=view, inputs=inputs, gold_baseline=gold)
    assert expected == set(all_pairs)
    _selftest_census_branch(work, inputs, observations, doc, gold, view, ids, shared, expected)
    identity = {**shared, **MR.generation_evidence_for_run(view, candidate, development=True),
                "candidate_run_sha256": MR.sha256_file(view),
                "candidate_generated_tests_sha256": MR.candidate_digest(TQ.passed_solutions(candidate)),
                "gold_baseline_sha256": MR.sha256_file(gold),
                "gold_generated_tests_sha256": MR.candidate_digest(TQ.passed_solutions(gold_rows)),
                "gold_results_sha256": MR.sha256_file(evidence), "gold_results_attestation_sha256": MR.sha256_file(evidence)}
    admitted = selection(evidence, expected, {**identity, "timeout_seconds": 600})
    oracle, _ = TQ._open_authenticated_gold_selection(admitted)
    killed, _, _ = TQ.gold_kill_sets(oracle, {iid: "passed" for iid in ids}, ids)
    assert sum(map(len, killed.values())) == 1 and gold_timeout[1] not in killed.get(gold_timeout[0], set())
    jobs = []
    def execute(job):
        jobs.append(job)
        assert job["side"] == "candidate"
        os.makedirs(os.path.dirname(job["out"]), exist_ok=True)
        rows = [{"item_id": iid, "mutant_id": mid, "outcome": "timeout",
                 "attempt": 1, "retried_infrastructure": False, **MR.row_identity_stamp(job["identity"])}
                for iid, mid in sorted(TQ._job_pairs(job["mutants"], job["by_mutant"], job["files_by_item"]))]
        Path(job["out"]).write_text("".join(json.dumps(row) + "\n" for row in rows))
        for status in ("running", "complete"):
            MR.write_shard_provenance(job["out"], job["identity"], status, provenance=job["provenance"])
        return {"out": job["out"], "rows": len(rows), "side": "candidate"}
    provenance = {**inputs, "run": view, "gold_baseline": gold, "seed": str(seed),
                  SUMMARY_KEY: evidence, "gold_results_source": evidence, "gold_results_attestation": evidence,
                  "reference_diagnostics": doc["diagnostics"], "inference_valid": False, "timeout_seconds": 600}
    def final(summary, summary_path):
        # Probe the actual saved native path with an equal canonical summary
        # while the real producer root is still running. A mismatched twin or
        # completed-artifact hash must not be what makes this test pass.
        path = Path(summary_path)
        original = path.read_bytes()
        without_authority = dict(summary)
        without_authority.pop(SUMMARY_KEY)
        path.write_text(json.dumps(without_authority))
        try:
            TQ._validate_native_summary_before_completion(without_authority, summary_path, view)
        except TQ.TestQualityRefused as exc:
            assert "campaign map" in str(exc), str(exc)
        else:
            raise AssertionError("omitted reference authority downgraded to ordinary native gold")
        finally:
            path.write_bytes(original)
        print("PASS refusal: missing typed reference authority reaches native map binding")
        TQ._validate_native_summary_before_completion(summary, summary_path, view)
    summary = TQ.run_test_quality(run_rows=candidate, gold_baseline_rows=gold_rows, manifest=manifest,
        by_mutant=mapping, out_dir=str(work / "candidate-campaign"), execute=execute, n_workers=1,
        authenticated_gold=admitted, identity_inputs=identity, provenance=provenance,
        worker_resources=resources, final_summary_validator=final)
    assert len(jobs) == 1 and summary["verdict_basis"] == "full_gold" and summary["recall_macro"] == 1.0
    assert summary["population_basis"] == "budgeted_sample" and summary["inference_valid"] is False
    TQ.write_sidecar(summary, view)
    assert TQ.load_bound_test_quality(view) == summary
    assert all(Path(path).read_bytes() == raw for path, raw in raw_bytes.items())
    assert TQ.publication_ready(summary)[0] is False
    drive, plan_path = _selftest_gold_killed_scope(
        work=work, root=root, view=view, candidate=candidate, gold=gold, gold_rows=gold_rows,
        manifest=manifest, mapping=mapping, admitted=admitted, identity=identity,
        provenance=provenance, resources=resources, observations=observations,
        gold_kill=gold_kill, gold_timeout=gold_timeout, full=summary, evidence=evidence,
        inputs=inputs, seed=seed, worker_path=worker_path, shared=shared,
        engine_dir=engine_dir, refuses=refuses)
    for key in ("reference_diagnostics", "gold_rows_precomputed", "inference_valid"):
        changed = dict(summary)
        changed.pop(key)
        refuses("saved evidence omission " + key, lambda: saved_context(changed))
    for path in (Path(evidence), Path(inputs["budgeted_sidecar"]), Path(observations["full-gold"]["shards"][0])):
        raw = path.read_bytes()
        path.write_bytes(raw + b" ")
        refuses("changed original authority " + str(path), lambda: TQ.load_bound_test_quality(view))
        path.write_bytes(raw)
    wrong = copy.deepcopy(observations)
    wrong["stub-control"] = wrong["assertion-stripped-gold"]
    refuses("wrong control role", lambda: derive(inputs, wrong))
    # A real complete L candidate with no passing rows reaches the CLI before
    # even trying to open the deliberately nonexistent worker manifest.
    failed = work / "failed.jsonl"
    lid = S.identify_for_inference(inputs["release"])
    failed.write_text("".join(json.dumps(dict(row, outcome="failed", subset_id=lid["subset_id"],
        subset_digest=lid["subset_digest"])) + "\n" for row in candidate))
    args = argparse.Namespace(**inputs, development=True, run=str(failed), gold_baseline=gold,
        kapua_reference_evidence=evidence, workers=[str(work / "nonexistent-worker.json")],
        seed=str(seed), out=str(work / "never-created"))
    with contextlib.redirect_stdout(io.StringIO()) as captured:
        assert cli.cmd_test_quality(args) == 0
    assert json.loads(captured.getvalue())["mutation_score"] is None
    assert not (work / "never-created").exists() and TQ.find_sidecar(str(failed)) is None
    # Real native variants exercise infrastructure disclosure and distinctness.
    def variation(role, target, observation_id, outcomes, **override):
        record = records[role]
        reference_identity = {**record["identity"], **override}
        path = str(work / target / (reference_identity["side"] + ".w0.jsonl"))
        MR.prepare_standalone_output_directory(path, reference_identity, observation_id)
        rows = []
        for (iid, mid), outcome in sorted(outcomes.items()):
            attempt = 2 if outcome in MR.INFRASTRUCTURE_OUTCOMES else 1
            rows.append({"item_id": iid, "mutant_id": mid, "outcome": outcome,
                         "attempt": attempt, "retried_infrastructure": attempt == 2,
                         **MR.row_identity_stamp(reference_identity)})
        Path(path).write_text("".join(json.dumps(row) + "\n" for row in rows))
        for status in ("running", "complete"):
            MR.write_shard_provenance(path, reference_identity, status, provenance={"worker_resources": resources})
        return {"baseline": observations[role]["baseline"], "shards": [path]}
    duplicate = copy.deepcopy(observations)
    duplicate["stub-control"] = variation("stub-control", "duplicate-id", "1" * 32, records["stub-control"]["outcomes"])
    refuses("duplicate physical observation identity", lambda: derive(inputs, duplicate))
    degraded = copy.deepcopy(observations)
    outcomes = dict(records["full-gold"]["outcomes"])
    outcomes[gold_timeout] = "container_error"
    degraded["full-gold"] = variation("full-gold", "degraded", "4" * 32, outcomes)
    degraded_doc, _ = derive(inputs, degraded)
    _selftest_stub_pending(work=work, inputs=inputs, observations=observations, doc=doc, records=records,
                           evidence=evidence, expected=expected, identity=identity, drive=drive,
                           plan_path=plan_path, variation=variation, other_gold=degraded["full-gold"],
                           refuses=refuses, ids=ids, shared=shared)
    degraded_path = str(work / "degraded.json")
    G.write(degraded_path, degraded_doc)
    degraded_rows, _ = TQ._open_authenticated_gold_selection(selection(
        degraded_path, expected, {**identity, "timeout_seconds": 600}))
    kwargs = {"gold_provenance_class": "native", "require_complete": True}
    refuses("infrastructure needs existing explicit degradation consent", lambda: TQ.check_gold_degradation(
        degraded_rows, {iid: "passed" for iid in ids}, ids, allow_degraded_gold=False, **kwargs))
    disclosure = TQ.check_gold_degradation(degraded_rows, {iid: "passed" for iid in ids}, ids,
        allow_degraded_gold=True, **kwargs)
    assert disclosure["gold_infrastructure_outcomes"] == 1 and disclosure["gold_infrastructure_class"] == "native_retry_verified"
    bad_baseline = work / "partial-gold.jsonl"
    bad_baseline.write_text(json.dumps(gold_rows[0]) + "\n")
    partial = copy.deepcopy(observations)
    partial["full-gold"]["baseline"] = str(bad_baseline)
    refuses("partial full-gold baseline", lambda: derive(inputs, partial))
    bad_baseline.write_text("".join(json.dumps(dict(row, outcome="failed")) + "\n" for row in gold_rows))
    refuses("failed full-gold baseline", lambda: derive(inputs, partial))
    wrong_budget = {**identity, "parent_map_sha256": "0" * 64, "timeout_seconds": 600}
    refuses("candidate mixed B100 parent", lambda: selection(evidence, expected, wrong_budget))
    refuses("candidate changed timeout", lambda: selection(evidence, expected, {**identity, "timeout_seconds": 601}))
    # Real CLI assembly on a second, narrower passed-item selection. Only live
    # worker inspection/stack construction and per-pair execution are replaced.
    from types import SimpleNamespace
    from unittest.mock import patch
    partial_view = str(root / "sample1-headroom-view/candidate.jsonl")
    cli_args = argparse.Namespace(**inputs, run=partial_view, gold_baseline=gold,
        kapua_reference_evidence=evidence, development=True, seed=str(seed), workers=[worker_path],
        out=str(work / "cli-candidate-campaign"), gold_results=None, gold_results_attestation=None,
        timeout=600, allow_incomplete=False, allow_degraded_gold=False, no_sidecar=False,
        gold=str(root / "release/gold"), artifacts=str(work), repo=str(work / "workspace"),
        boundary=str(root / "boundary.yml"), resume=False)
    def runtime_read(paths, workers, seed_path, version, needs_database, *, project):
        assert project == "kapua"
        assert paths == [worker_path] and not needs_database
        W.validate_offline_worker_runtime_pool(paths)
        assert W.verified_seed_identity(seed_path, False) == seed_identity
        return {**shared, "worker_resources": resources, "protected_evidence_paths": []}
    def run_slice(_harness, mutants, _items, files, by_mutant, _engine_dir, out_path, **kw):
        return execute({"identity": kw["identity"], "side": kw["identity"]["side"],
                        "mutants": mutants, "files_by_item": files, "by_mutant": by_mutant,
                        "out": out_path, "provenance": kw["provenance"]})
    with patch.object(W, "validate_mutation_runtime", runtime_read), \
         patch.object(cli, "_stack", lambda _args: SimpleNamespace(
             engine_dir=engine_dir, FRAMEWORK="cucumber")), \
         patch.object(cli, "_stack_profile", lambda _args: SimpleNamespace(needs_database=False)), \
         patch.object(cli, "_behat_row", lambda _args: None), \
         patch.object(cli, "_harness", lambda _args: (SimpleNamespace(substrate_baseline_sha256="1" * 64), None, None)), \
         patch.object(MR, "run_slice", run_slice), contextlib.redirect_stdout(io.StringIO()):
        assert cli.cmd_test_quality(cli_args) == 0
    partial_summary = TQ.load_bound_test_quality(partial_view)
    assert partial_summary["pairs_expected"] < summary["pairs_expected"]
    assert len(jobs) == 2 and all(job["side"] == "candidate" for job in jobs)
    assert all(Path(path).read_bytes() == raw for path, raw in raw_bytes.items())
    G.write(work / "fixture-paths.json", {"view": view, "evidence": evidence, "gold": gold, "inputs": inputs})
    import subprocess
    import sys
    process = subprocess.Popen([sys.executable, "-c",
        "from r2t.java.kapua_reference import _selftest_saved; import sys; _selftest_saved(sys.argv[1])", str(root)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2]), "PYTHONDONTWRITEBYTECODE": "1"})
    stdout, stderr = process.communicate(timeout=90)
    assert process.returncode == 0, stdout + stderr
    assert "PASS fresh-process" in stdout
    print(stdout.strip())
    print("PASS: three original observations, literal-failed oracle, candidate timeout kill, native saved B100, zero-job CLI")


def _selftest_stub_pending(*, ids, shared, refuses, inputs, observations, **kw):
    """KAPUA_CENSUS330_MUTATION_AMENDMENT.md section 12 over the real readers.

    Evidence sealed without the stub-control leg, census330 only: both
    candidate routes read it with the full-gold and hard-subset verdicts of
    the three-role evidence; every stub measure is null and listed, never 0;
    a stub appendix completes exactly that evidence and refuses any other
    identity. The census330 receipt, full-gold proof and candidate admission
    are substituted as in `_selftest_census_branch`; the three-role evidence
    `doc` rederives equally on that branch.
    """
    import contextlib
    two = {role: observations[role] for role in ROLES if role != STUB}
    refuses("stub-pending evidence outside census330", lambda: derive(inputs, two), "only census330")
    with contextlib.ExitStack() as stack:
        _census_patches(stack, ids, {key: shared[key] for key in CM.RUNTIME})
        _stub_pending_census(inputs=inputs, observations=observations, two=two, refuses=refuses, **kw)


def _stub_pending_census(*, work, inputs, observations, two, doc, records, evidence, expected, identity,
                         drive, plan_path, variation, other_gold, refuses):
    import contextlib
    import io
    from pathlib import Path
    assert derive(inputs, observations)[0] == doc
    pending_doc, _ = derive(inputs, two)
    assert pending_doc == _stub_pending(doc)
    assert pending_doc["diagnostics"]["stub_control"] == STUB_PENDING and STUB not in pending_doc["observations"]
    assert set(pending_doc["diagnostics"]["raw_outcomes"]) == {"full-gold", "assertion-stripped-gold"}
    per_item = pending_doc["diagnostics"]["per_item"]
    assert all(entry[key] is None for entry in per_item.values() for key in STUB_FIELDS)
    # The three-role fixture measures a stub recall of exactly 0.0; pending prints null.
    assert 0.0 in {entry["stub_full_gold_recall"] for entry in doc["diagnostics"]["per_item"].values()}
    for iid, entry in doc["diagnostics"]["per_item"].items():
        assert {k: v for k, v in entry.items() if k not in STUB_FIELDS} \
            == {k: v for k, v in per_item[iid].items() if k not in STUB_FIELDS}
    pending = str(work / "stub-pending-references.json")
    argv = [f"--{key.replace('_', '-')}={inputs[key]}" for key in ASSETS]
    for role, spec in two.items():
        argv += [f"--{role}-baseline={spec['baseline']}", *(f"--{role}-run={path}" for path in spec["shards"])]
    assert main([*argv, "--out", pending]) == 0
    assert load(pending)[0] == pending_doc
    for label, half in (("baseline without its runs", f"--stub-control-baseline={observations[STUB]['baseline']}"),
                        ("runs without their baseline", f"--stub-control-run={observations[STUB]['shards'][0]}")):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            refuses("stub-control " + label, lambda: main([*argv, half, "--out", str(work / "never.json")]))
        assert "or neither for stub-pending evidence" in err.getvalue(), err.getvalue()
    assert not (work / "never.json").exists()
    sealed = {path: TQ._open_authenticated_gold_selection(
        selection(path, expected, {**identity, "timeout_seconds": 600}))[0] for path in (evidence, pending)}
    assert sealed[evidence] == sealed[pending]

    def measured(out):
        summary = TQ._load_json_object(str(work / out / TQ.SUMMARY), "fixture summary")
        diagnostics = summary["reference_diagnostics"]["per_item"]
        kills = {iid: set() for iid in summary["per_item"]}
        for row in TQ.load_jsonl(summary["gold_results"]):
            if row["item_id"] in kills and row["outcome"] == "failed" \
                    and row["mutant_id"] in diagnostics[row["item_id"]]["stripped_passed_witness"]:
                kills[row["item_id"]].add(row["mutant_id"])
        assert any(kills.values()), f"{out}: H_i is empty, so the hard comparison below would be vacuous"
        hard = M.recall(dict.fromkeys(kills, "passed"), TQ.load_jsonl(summary["candidate_results"]), kills)
        return (summary,
                {iid: (entry["verdict"], entry["recall"]) for iid, entry in summary["per_item"].items()},
                {iid: (TQ.verdict_for(len(kills[iid]), entry["recall"]), entry["recall"])
                 for iid, entry in hard["per_item"].items()})

    for route, pairs in (("sealed-gold", None), ("on-host-gold", plan_path)):
        runs = {}
        for name, path in (("three-role", evidence), ("stub-pending", pending)):
            assert drive(f"cli-{route}-{name}", pairs, path) == 0
            runs[name] = measured(f"cli-{route}-{name}")
        (full, full_verdicts, full_hard), (withheld, verdicts, hard) = runs["three-role"], runs["stub-pending"]
        assert verdicts == full_verdicts and hard == full_hard, route
        assert all(withheld[key] == full[key] for key in (
            "recall_macro", "verdicts", "non_vacuous_passes", "n_scorable", "gold_rows_precomputed"))
        assert withheld["reference_diagnostics"] == pending_doc["diagnostics"]
        assert withheld[SUMMARY_KEY] == G.canonical(pending) and full[SUMMARY_KEY] == G.canonical(evidence)
    print("PASS: stub-pending Kapua evidence scores both routes with the three-role full-gold and hard verdicts")

    stub = observations[STUB]
    appendix_doc = stub_appendix(pending, stub)
    assert appendix_doc["evidence"] == G.reference(pending)
    assert appendix_doc["observation"] == doc["observations"][STUB]
    assert appendix_doc["diagnostics"]["raw_outcomes"] == doc["diagnostics"]["raw_outcomes"][STUB]
    assert {iid: {key: entry[key] for key in STUB_FIELDS} for iid, entry in appendix_doc["diagnostics"]["per_item"].items()} \
        == {iid: {key: entry[key] for key in STUB_FIELDS} for iid, entry in doc["diagnostics"]["per_item"].items()}
    gate = appendix_doc["diagnostics"]["stub_gate"]
    assert (gate["threshold"], gate["items"], gate["items_stub_baseline_not_passed"], gate["infrastructure_pairs_on_G"],
            gate["macro_recall"], gate["macro_recall_literal_failed"]) == (0.02, 1, 0, 0, 0.0, 0.0)
    killed_item = next(iid for iid, entry in doc["diagnostics"]["per_item"].items() if entry["full_gold_failed"])
    killed = (killed_item, doc["diagnostics"]["per_item"][killed_item]["full_gold_failed"][0])
    # A stub timeout on G is a kill for macro_recall only; an infrastructure
    # outcome is a non-kill in both and is counted.
    for observation_id, outcome, want in (("7" * 32, "timeout", (1.0, 0.0, 0)), ("8" * 32, "container_error", (0.0, 0.0, 1))):
        other = stub_appendix(pending, variation(STUB, "stub-" + outcome, observation_id,
                                                 {**records[STUB]["outcomes"], killed: outcome}))
        g = other["diagnostics"]["stub_gate"]
        assert (g["macro_recall"], g["macro_recall_literal_failed"], g["infrastructure_pairs_on_G"]) == want, (outcome, g)
        assert other["diagnostics"]["per_item"][killed_item]["stub_killed_full_gold"] == (
            [killed[1]] if outcome == "timeout" else [])
    appendix = str(work / "stub-appendix.json")
    assert main(["stub-appendix", "--evidence", pending, "--stub-control-baseline", stub["baseline"],
                 *(f"--stub-control-run={path}" for path in stub["shards"]), "--out", appendix]) == 0
    assert load_stub_appendix(appendix) == appendix_doc
    # Three-role evidence is completed from its own stub leg, with the same stub measures.
    own = stub_appendix(evidence, stub)
    assert own["diagnostics"] == appendix_doc["diagnostics"] and own["evidence"] == G.reference(evidence)
    refuses("three-role evidence completed from another stub leg", lambda: stub_appendix(evidence, variation(
        STUB, "stub-another-leg", "9" * 32, records[STUB]["outcomes"])), "its own stub leg only")
    assert os.path.dirname(os.path.abspath(pending)) in protected_paths(pending, pending_doc)
    assert os.path.dirname(os.path.abspath(evidence)) not in protected_paths(evidence, doc)
    refuses("stub appendix at another executor identity", lambda: stub_appendix(pending, variation(
        STUB, "stub-other-substrate", "6" * 32, records[STUB]["outcomes"], substrate_baseline_sha256="2" * 64)),
        "stub-control changed common population/executor fields: ['substrate_baseline_sha256']")
    refuses("stub appendix reusing the stripped observation", lambda: stub_appendix(pending, variation(
        STUB, "stub-stripped-id", records["assertion-stripped-gold"]["facts"]["observation_id"],
        records[STUB]["outcomes"])), "distinct physical observations")
    forged = str(work / "stub-appendix-forged.json")
    G.write(forged, dict(appendix_doc, diagnostics=dict(appendix_doc["diagnostics"], stub_gate=dict(
        appendix_doc["diagnostics"]["stub_gate"], macro_recall=0.01))))
    refuses("stub appendix with a changed stub gate", lambda: load_stub_appendix(forged), "changed measures")
    # Other valid stub-pending evidence at the same path (another full-gold
    # observation) is not the evidence this appendix completes.
    other = str(work / "stub-pending-other.json")
    G.write(other, derive(inputs, {**two, "full-gold": other_gold})[0])
    original = Path(pending).read_bytes()
    Path(pending).write_bytes(Path(other).read_bytes())
    try:
        assert stub_appendix(pending, stub)["evidence"] != appendix_doc["evidence"]
        refuses("stub appendix naming evidence whose identity changed", lambda: load_stub_appendix(appendix),
                "names other evidence")
    finally:
        Path(pending).write_bytes(original)
    assert load_stub_appendix(appendix) == appendix_doc
    print("PASS: the stub appendix completes exactly its stub-pending evidence")


def _census_patches(stack, ids, runtime):
    """Substitute only the census330 receipt, full-gold proof and candidate
    admission, which `kapua_census_mutation.selftest` exercises."""
    from unittest.mock import patch
    stack.enter_context(patch.object(CM, "is_census", return_value=True))
    stack.enter_context(patch.object(CM, "census_ids", return_value=sorted(ids)))
    stack.enter_context(patch.object(CM, "RUNTIME", runtime))
    return {"receipt": stack.enter_context(patch.object(CM, "load_inputs", return_value={"census": 1})),
            "full_gold": stack.enter_context(patch.object(CM, "validate_full_gold")),
            "candidates": stack.enter_context(patch.object(CM, "validate_candidates"))}


def _selftest_census_branch(work, inputs, observations, doc, gold, view, ids, shared, expected):
    """The census330 branch over the same real native observations. Its
    receipt, full-gold proof and candidate admission are exercised by
    `kapua_census_mutation.selftest`; only those are substituted here."""
    import contextlib

    runtime = {key: shared[key] for key in CM.RUNTIME}
    with contextlib.ExitStack() as stack:
        mocks = _census_patches(stack, ids, runtime)
        census_doc, _ = derive(inputs, observations)
        assert census_doc == doc
        mocks["receipt"].assert_called_once_with(inputs["budgeted_sidecar"], inputs)
        mocks["full_gold"].assert_called_once_with(gold, inputs["release"], {"census": 1})
        path = str(work / "census-references.json")
        G.write(path, census_doc)
        assert candidate_inputs(path, run_path=view, inputs=inputs, gold_baseline=gold)[1] == expected
        mocks["candidates"].assert_called_once_with(view, inputs["release"])
    # The host rule: a reference observed at another harness or image refuses.
    for key, value, fragment in (("harness_version", runtime["harness_version"] + 1, "census harness"),
                                 ("container_image_digest", "sha256:" + "0" * 64, "container_image_digest")):
        with contextlib.ExitStack() as stack:
            _census_patches(stack, ids, {**runtime, key: value})
            try:
                derive(inputs, observations)
            except TQ.TestQualityRefused as exc:
                assert "census" in str(exc) and fragment in str(exc), str(exc)
                print("PASS refusal: census reference at another " + key)
            else:
                raise AssertionError("census reference at another runtime accepted")
    print("PASS: census330 branch rederives the same evidence and keeps the census runtime")


def selftest():
    return G.selftest(headroom=True, reference_reuse=True)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["stub-appendix"]:
        parser = argparse.ArgumentParser(prog="kapua_reference stub-appendix", description=stub_appendix.__doc__)
        parser.add_argument("--evidence", required=True, help="the stub-pending evidence.json")
        parser.add_argument("--stub-control-baseline", required=True)
        parser.add_argument("--stub-control-run", action="append", required=True)
        parser.add_argument("--out", required=True)
        args = parser.parse_args(argv[1:])
        G.write(args.out, stub_appendix(args.evidence, {"baseline": args.stub_control_baseline,
                                                        "shards": args.stub_control_run}))
        load_stub_appendix(args.out)
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ASSETS:
        parser.add_argument("--" + key.replace("_", "-"), required=True)
    for role in ROLES:
        # Omitting both stub-control options writes stub-pending evidence.
        parser.add_argument("--" + role + "-baseline", required=role != STUB)
        parser.add_argument("--" + role + "-run", action="append", required=role != STUB)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    if (args.stub_control_baseline is None) != (args.stub_control_run is None):
        parser.error("name --stub-control-baseline with --stub-control-run, or neither for stub-pending evidence")
    doc, _ = derive({key: getattr(args, key) for key in ASSETS}, {
        role: {"baseline": getattr(args, role.replace("-", "_") + "_baseline"),
               "shards": getattr(args, role.replace("-", "_") + "_run")}
        for role in ROLES if getattr(args, role.replace("-", "_") + "_baseline") is not None})
    G.write(args.out, doc)
    load(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
