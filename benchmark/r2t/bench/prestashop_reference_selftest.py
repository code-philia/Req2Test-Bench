"""PrestaShop source-authenticated B100/N=1 reader and candidate-only checks.

Only execution outcomes are synthetic. Native audit reports, recipes,
baseline bytes, shard stamps, worker/seed attestations and saved readers use
the same validators as the command.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

from . import prestashop_reference as P, mutation_run as MR
from . import reference_workloads as RW, test_quality as TQ


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def rows(path, values):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(value, sort_keys=True) + "\n" for value in values), encoding="utf-8")
    return str(path)


def refuses(label, fn):
    try:
        fn()
    except (ValueError, OSError, RuntimeError, SystemExit):
        print("  [PASS] refuses " + label)
        return
    raise AssertionError(label + " accepted")


def arithmetic():
    records = {
        "full-gold": {"outcomes": {("a", "m1"): "failed", ("a", "m2"): "timeout",
                                   ("b", "m1"): "failed", ("c", "m1"): "passed"}},
        "assertion-stripped-gold": {"outcomes": {("a", "m1"): "passed", ("a", "m2"): "passed",
                                                  ("c", "m1"): "failed"}},
        "stub-control": {"outcomes": {("a", "m1"): "timeout", ("a", "m2"): "container_error",
                                       ("c", "m1"): "passed"}},
    }
    baselines = {"full-gold": dict.fromkeys("abc", "passed"),
                 "assertion-stripped-gold": {"a": "passed", "b": "no_files_returned", "c": "passed"},
                 "stub-control": {"a": "passed", "b": "failed", "c": "passed"}}
    result = P.summarize(records, baselines, set("abc"))
    assert result["per_item"]["a"]["full_gold_failed"] == ["m1"]
    assert result["per_item"]["a"]["stripped_passed_witness"] == ["m1"]
    assert result["per_item"]["a"]["stub_full_gold_recall"] == 1.0  # existing timeout policy
    assert result["per_item"]["b"]["hard_status"] == "not_scorable"
    assert result["per_item"]["b"]["stub_full_gold_recall"] is None
    assert result["items_total"] == 3 and result["hard_not_scorable"] == 2
    assert result["raw_outcomes"]["full-gold"]["timeout"] == 1
    print("  [PASS] one G∩S, exclusions, full denominator and existing timeout semantics")


def fixture_worker_resources(f, root, *, memory=False, count=1):
    from .. import docker_authority as D
    from . import worker as W
    from .validate import HARNESS_VERSION
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    original = json.loads(Path(f["worker_resources"][0]["worker_spec"]).read_text())
    workers, paths = [], []
    for index in range(count):
        worker_doc = dict(original, index=index, container=f"worker{index}",
            schema=f"test_fixture_{index}", credential=f"test_fixture_{index}",
            workspace=str(root / f"workspace{index}"),
            env_file=str(root / f"worker{index}.env"),
            out_path=str(root / f"worker{index}-output.jsonl"),
            artifacts_root=str(root / f"worker{index}-artifacts"))
        worker_path = write(root / f"worker{index}.json", worker_doc)
        os.chmod(worker_path, 0o600)
        paths.append(worker_path)
        workers.append(W.WorkerSpec.from_json(worker_doc))
    authority_path = str(root / "authority.json")
    D.write_evidence_no_clobber(authority_path, D._fixture_authority())
    _, authority_ref = D.evidence_reference(authority_path, expected_schema=D.AUTHORITY_SCHEMA,
        validator=lambda value: D.validate_authority_document(value, current_source=False), label="fixture authority")
    template = D._fixture_binding(database=True)
    template["authority"] = authority_ref
    template["pool"] = W.build_execution_pool(workers, paths,
        database_container="database", internal_network="r2t-internal")
    containers = [dict(template["container"], name=worker.container,
                      id=str(index + 1) * 64, image_id=f["image_id"])
                  for index, worker in enumerate(workers)]
    members = [member for member in template["network_policy"]["expected_members"]
               if member["role"] == "database"]
    members += [dict(container, role="worker", worker_index=index)
                for index, container in enumerate(containers)]
    for field in ("expected_members", "observed_members"):
        template["network_policy"][field] = copy.deepcopy(members)
    seed_identity = W.verified_seed_identity(f["seed"], True)
    resources = []
    for index, (worker, worker_path) in enumerate(zip(workers, paths)):
        binding = copy.deepcopy(template)
        binding.update(worker_index=index, worker_spec_sha256=MR.sha256_file(worker_path),
                       container=containers[index])
        binding["digest"] = D.semantic_digest(binding)
        D.write_evidence_no_clobber(W.binding_attestation_path(worker_path), binding)
        memory_args = {}
        if memory:
            memory_args["memory_evidence"] = {
                "policy": {"schema": "r2t.prestashop-memory-policy/1",
                           "memory_bytes": 4294967296, "swap_bytes": 0},
                "container_id": binding["container"]["id"],
                "configured_memory_bytes": 4294967296,
                "configured_memory_swap_bytes": 4294967296,
                "oom_kill_disabled": False,
                "effective_memory_bytes": 4294967296, "effective_swap_bytes": 0,
            }
        runtime = W.build_worker_runtime_attestation(worker, worker_path, seed_identity, HARNESS_VERSION,
            binding_path=W.binding_attestation_path(worker_path), **memory_args)
        write(W.runtime_attestation_path(worker_path), runtime)
        os.chmod(W.runtime_attestation_path(worker_path), 0o600)
        os.chmod(W.binding_attestation_path(worker_path), 0o600)
        record = {key: worker.to_json()[key] for key in (
            "index", "workspace", "container", "schema", "credential", "env_file", "workdir")}
        record.update(worker_spec=worker_path, runtime_attestation=W.runtime_attestation_path(worker_path),
            runtime_attestation_sha256=MR.sha256_file(W.runtime_attestation_path(worker_path)))
        resources.append(record)
    return resources


def fixture(root, *, memory=False, role_memory=None):
    from .evaluation_reference_selftest import fixture_evaluation_inputs
    from ..data import subsets as S
    from ..toolkit.subset_writer import write_budgeted_sample
    from .validate import HARNESS_VERSION
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    f = fixture_evaluation_inputs(root / "assets", project="prestashop", _assets_only=True,
        coverage_changes={"coverage_lines": {"src/Core/Fixture.php": [3, 4]},
                          "coverage_files": {"src/Core/Fixture.php": 2}})
    common = f["common_args"]
    draw = S.budgeted_sample(common["map_release_path"], common["map_path"],
                            common["manifest_path"], per_item=100, seed=20260912)
    derived, sidecar = write_budgeted_sample(draw, str(root / "budget100"))
    inputs = {"mutation_validation": common["validation_path"],
              "manifest": common["manifest_path"], "map": derived,
              "release": common["map_release_path"], "budgeted_sidecar": sidecar}
    sources = {key: common[key] for key in P.SOURCES}
    assets = P.A.validate_campaign_asset_inputs(inputs["mutation_validation"],
        manifest_path=inputs["manifest"], map_path=derived, release_path=inputs["release"],
        budgeted_sidecar=sidecar)
    ids = P.A.load_release_ids(inputs["release"])
    manifest = assets["manifest"]
    f["worker_resources"] = fixture_worker_resources(f, root / "candidate-worker", memory=memory)
    seed_info = json.loads((Path(f["seed"]) / "seed.json").read_text())
    engine_dir, applier = MR.binding_for(manifest["engine"])
    shared = {"asset_index_sha256": assets["asset_index_sha256"], "asset_project": "prestashop",
        "mutation_validation_sha256": assets["validation_sha256"], "mutation_validation_class": "native",
        "manifest_sha256": MR.sha256_file(inputs["manifest"]), "manifest_digest": manifest["digest"],
        "map_sha256": MR.sha256_file(derived), "release_sha256": MR.sha256_file(inputs["release"]),
        "substrate_baseline_sha256": f["substrate_digest"],
        "applier_sha256": MR.sha256_file(os.path.join(engine_dir, applier.source)),
        "harness_version": HARNESS_VERSION, "container_image_digest": f["image_id"],
        "workspace_seed_digest": seed_info["workspace_seed_digest"],
        "database_dump_digest": seed_info["database_dump_digest"],
        "engine": manifest["engine"], "engine_version": manifest["engine_version"], "parser": manifest["parser"],
        "worker_resources_sha256": MR.content_digest(f["worker_resources"]),
        **{key: assets[key] for key in P.BUDGET}}
    observations = {}
    baseline_by_role = {}
    raw_snapshot = {}
    for index, role in enumerate(P.ROLES):
        # Each role and the candidate use distinct physical worker evidence.
        # Equal caps must survive this placement change without a pool-hash join.
        resources = fixture_worker_resources(f, root / (role + "-worker"),
            memory=(role_memory or {}).get(role, memory))
        role_name = {"full-gold": "full_gold", "assertion-stripped-gold": "stripped_gold", "stub-control": "stub"}[role]
        baseline = f["controls"]["run_paths"][role_name]
        baseline_rows = TQ.load_jsonl(baseline)
        # A produced control can fail its unmutated baseline without changing
        # its valid, source-derived candidate bytes. Exercise that eligibility.
        if role != "full-gold" and len(baseline_rows) > 1:
            baseline_rows[-1]["outcome"] = "failed"
            rows(baseline, baseline_rows)
        recipe = f["controls"]["recipe_paths"][role_name]
        control = RW.validate_development_control_input(project="prestashop", role=role_name,
            run_path=baseline, recipe_path=recipe, execution_release_path=inputs["release"], **sources)
        passed = control["files_by_item"]
        pairs = sorted(P._pairs(assets["map"]["by_mutant"], passed))
        generation = MR.reference_generation_evidence(role=role, source_tag="reviewed-common-freeze",
            candidate_rows=baseline_rows, release_item_ids=ids, release_sha256=shared["release_sha256"],
            asset_index_sha256=shared["asset_index_sha256"], control=control)
        digest = MR.candidate_digest(passed)
        identity = MR.build_campaign_identity(
            **dict(shared, worker_resources_sha256=MR.content_digest(resources)), **generation,
            candidate_run_sha256=MR.sha256_file(baseline), candidate_generated_tests_sha256=digest,
            solution_generated_tests_sha256=digest, expected_pairs=pairs,
            side="gold" if role == "full-gold" else "candidate", shard=0, of=1, timeout=600)
        path = str(root / role / (identity["side"] + ".w0.jsonl"))
        MR.prepare_standalone_output_directory(path, identity, str(index + 1) * 32)
        result = []
        for n, (iid, mid) in enumerate(pairs):
            outcome = ("failed" if n == 0 else "timeout" if n == 1 else "passed") if role == "full-gold" else "passed"
            result.append({"item_id": iid, "mutant_id": mid, "outcome": outcome,
                           "attempt": 1, "retried_infrastructure": False, **MR.row_identity_stamp(identity)})
        rows(path, result)
        for status in ("running", "complete"):
            MR.write_shard_provenance(path, identity, status, provenance={"worker_resources": resources})
        observations[role] = {"baseline": baseline, "recipe": recipe, "shards": [path]}
        baseline_by_role[role] = baseline_rows
        raw_snapshot[path] = Path(path).read_bytes()
    return f, inputs, sources, observations, shared, baseline_by_role, raw_snapshot


def native_roundtrip(root, *, memory=False):
    f, inputs, sources, observations, shared, baselines, raw_snapshot = fixture(root, memory=memory)
    doc, records = P.derive(inputs, observations, sources)
    from ..data import subsets as S
    from ..toolkit.subset_writer import write_budgeted_sample
    changed_budget = S.budgeted_sample(inputs["release"], f["common_args"]["map_path"],
        inputs["manifest"], per_item=50, seed=20260912)
    other_map, other_sidecar = write_budgeted_sample(changed_budget, str(root / "budget50"))
    try:
        P.derive(dict(inputs, map=other_map, budgeted_sidecar=other_sidecar), observations, sources)
    except TQ.TestQualityRefused as exc:
        assert "approved B100" in str(exc), str(exc)
    else:
        raise AssertionError("another valid budget was labelled as the approved B100 policy")
    print("  [PASS] another valid budget cannot become B100 single-observation evidence")
    evidence = write(root / "reference-evidence.json", doc)
    assert P.load(evidence)[0] == doc
    if memory:
        pool = fixture_worker_resources(f, root / "mixed-pool", memory=True, count=2)
        native_identity = dict(records["full-gold"]["identity"], of=2,
                               worker_resources_sha256=MR.content_digest(pool))
        assert len(MR.validate_worker_resource_evidence({"worker_resources": pool}, native_identity)) == 2
        # Both workers retain one authority/pool identity and valid individual
        # bindings; only worker 1's runtime loses the prospective memory record.
        path = pool[1]["runtime_attestation"]
        downgraded = json.loads(Path(path).read_text())
        downgraded.pop("memory")
        downgraded["schema"] = "r2t.worker-runtime/v3"
        write(path, downgraded)
        pool[1]["runtime_attestation_sha256"] = MR.sha256_file(path)
        native_identity["worker_resources_sha256"] = MR.content_digest(pool)
        try:
            MR.validate_worker_resource_evidence({"worker_resources": pool}, native_identity)
        except MR.MutationAborted as exc:
            assert "mixed" in str(exc), str(exc)
        else:
            raise AssertionError("mixed v3/v4 pool passed the native shard reader")
        print("  [PASS] native shard reader refuses mixed v3/v4 within one authenticated pool")
    assert doc["method"] == "single_observation" and doc["reference_observation_count"] == 1
    assert doc["shared_identity"]["population_basis"] == "budgeted_sample"
    assert ("worker_memory_policy" in doc) == memory
    if memory:
        assert doc["worker_memory_policy"] == {
            "schema": "r2t.prestashop-memory-policy/1", "memory_bytes": 4294967296, "swap_bytes": 0}
    assert len({value["identity"]["worker_resources_sha256"] for value in records.values()}
               | {shared["worker_resources_sha256"]}) == 4
    assert len({value["facts"]["observation_id"] for value in records.values()}) == 3
    assert doc["diagnostics"]["raw_outcomes"]["full-gold"]["timeout"] == 1
    gold_baseline = observations["full-gold"]["baseline"]
    expected = set(records["full-gold"]["outcomes"])
    identity = {**shared, "timeout_seconds": 600, "gold_baseline_sha256": MR.sha256_file(gold_baseline)}
    admitted = P.selection(evidence, expected, identity, worker_resources=f["worker_resources"])
    if memory:
        refuses("capped candidate omits runtime evidence", lambda: P.selection(evidence, expected, identity))
    else:
        P.selection(evidence, expected, identity)  # unchanged historical API
    other_resources = fixture_worker_resources(f, root / "other-policy-worker", memory=not memory)
    other_identity = dict(identity, worker_resources_sha256=MR.content_digest(other_resources))
    refuses("candidate capped/uncapped memory mismatch", lambda: P.selection(
        evidence, expected, other_identity, worker_resources=other_resources))
    if memory:
        altered_resources = fixture_worker_resources(f, root / "changed-cap-worker", memory=True)
        runtime_path = altered_resources[0]["runtime_attestation"]
        altered = json.loads(Path(runtime_path).read_text())
        for key in ("configured_memory_bytes", "configured_memory_swap_bytes", "effective_memory_bytes"):
            altered["memory"][key] = 8589934592
        altered["memory"]["policy"]["memory_bytes"] = 8589934592
        write(runtime_path, altered)
        altered_resources[0]["runtime_attestation_sha256"] = MR.sha256_file(runtime_path)
        altered_identity = dict(identity, worker_resources_sha256=MR.content_digest(altered_resources))
        refuses("candidate changed cap in bound runtime", lambda: P.selection(
            evidence, expected, altered_identity, worker_resources=altered_resources))
    oracle, _ = TQ._open_authenticated_gold_selection(admitted)
    assert {row["mutant_id"] for row in oracle if row["outcome"] == "failed"}
    assert all(row["outcome"] != "timeout" for row in oracle)
    assert all(Path(path).read_bytes() == before for path, before in raw_snapshot.items())
    refuses("changed candidate timeout", lambda: P.selection(evidence, expected, {**identity, "timeout_seconds": 601}))
    refuses("changed B100 parent", lambda: P.selection(evidence, expected, {**identity, "parent_map_sha256": "0" * 64}))
    # VERSIONS.yml lists PrestaShop's mutation-compatible harness versions; a
    # candidate at another listed version is admitted, any other refuses.
    from ..data import versions as V
    listed = V.component("harness")["compatible_reference_versions"]["prestashop"]
    other = next(version for version in listed if version != shared["harness_version"])
    unlisted = min(listed) - 1
    compatible = P.selection(evidence, expected, {**identity, "harness_version": other},
                             worker_resources=f["worker_resources"])
    assert TQ._open_authenticated_gold_selection(compatible)[0] == oracle
    try:
        P.selection(evidence, expected, {**identity, "harness_version": unlisted},
                    worker_resources=f["worker_resources"])
    except TQ.TestQualityRefused as exc:
        assert "['harness_version']" in str(exc), str(exc)
    else:
        raise AssertionError("an unlisted candidate harness version was admitted")
    print("  [PASS] a candidate at a VERSIONS.yml-compatible harness selects the same oracle; an unlisted one refuses")
    wrong = copy.deepcopy(observations)
    wrong["stub-control"] = wrong["assertion-stripped-gold"]
    refuses("different control under stub role", lambda: P.derive(inputs, wrong, sources))
    for field in ("candidate_observation_count", "reference_observation_count"):
        changed = dict(doc, **{field: 2})
        write(evidence, changed)
        refuses("singleton relabeled as N=2 " + field, lambda: P.load(evidence))
    if memory:
        changed = dict(doc)
        changed.pop("worker_memory_policy")
        write(evidence, changed)
        refuses("saved capped reference drops memory policy", lambda: P.load(evidence))
    write(evidence, doc)
    path = observations["full-gold"]["shards"][0]
    original = Path(path).read_bytes()
    Path(path).write_bytes(original + original.splitlines(keepends=True)[0])
    refuses("duplicate native pair", lambda: P.load(evidence))
    Path(path).write_bytes(original.splitlines(keepends=True)[0])
    refuses("missing native pair", lambda: P.load(evidence))
    Path(path).write_bytes(original)
    recipe = observations["stub-control"]["recipe"]
    old = Path(recipe).read_bytes()
    data = json.loads(old)
    data["adapter_version"] = 999
    write(recipe, data)
    refuses("changed source recipe", lambda: P.load(evidence))
    Path(recipe).write_bytes(old)
    assert P.load(evidence)[0] == doc
    print("  [PASS] real native report/seed/shards/source replay and saved B100 reference round trip")
    candidate_roundtrip(root, f, inputs, observations, shared, baselines, evidence, doc, raw_snapshot)


def continued_consumer(root):
    """Exercise N1's typed boundary; planner admission has its own native tests."""
    import sys
    from types import SimpleNamespace
    _f, inputs, sources, observations, _shared, _baselines, snapshot = fixture(root, memory=True)
    ordinary_doc, ordinary = P.derive(inputs, observations, sources)
    parent = ordinary["full-gold"]
    parent_rows = TQ.load_jsonl(observations["full-gold"]["shards"][0])
    resources = json.loads(Path(MR.provenance_path(observations["full-gold"]["shards"][0])).read_text())["worker_resources"]
    plan = write(root / "plan.json", {"fixture": "typed reader boundary"})
    child = rows(root / "child.jsonl", [])
    record = {**parent, "kind": P.CONTINUED_KIND,
        "parent_identity": copy.deepcopy(parent["identity"]),
        "parent_worker_resources": resources,
        "child_worker_resources": resources,
        "protected_paths": [plan],
        "raw_rows": {(r["item_id"], r["mutant_id"]): r for r in parent_rows},
        "row_sources": [{**P._reference(path), "segment": "parent"} for path in snapshot
                        if path in observations["full-gold"]["shards"]]
                       + [{**P._reference(child), "segment": "child"}],
        "continuation": {"kind": P.CONTINUED_KIND, "plan": P._reference(plan),
                         "child_shards": [P._reference(child)]},
        "facts": {**parent["facts"], "child_observation_id": "child-observation",
                  "parent_identity": parent["identity"], "child_identity": parent["identity"],
                  "transition": {"fixture": True}, "stable_killset": False}}
    typed = copy.deepcopy(observations)
    typed["full-gold"].pop("shards")
    typed["full-gold"]["continuation"] = {"plan": plan, "child_shards": [child]}

    def load_completed(plan_path, child_paths):
        assert plan_path == plan and child_paths == [child]
        for ref in record["row_sources"]:
            P._checked(ref)
        return copy.deepcopy(record)

    # Only the continuation API is substituted. Source recipes, baselines,
    # asset validators and both ordinary reference readers remain native.
    with patch.dict(sys.modules, {"r2t.bench.prestashop_continuation":
                                  SimpleNamespace(load_completed=load_completed)}):
        doc, records = P.derive(inputs, typed, sources)
        assert doc["schema"] == P.CONTINUED_SCHEMA
        assert doc["diagnostics"] == ordinary_doc["diagnostics"]
        evidence = write(root / "continued-evidence.json", doc)
        assert P.load(evidence)[0] == doc
        identity = {**record["identity"], "gold_baseline_sha256":
                    MR.sha256_file(typed["full-gold"]["baseline"])}
        before = copy.deepcopy(record["raw_rows"])
        selected = P.selection(evidence, set(record["outcomes"]), identity, worker_resources=resources)
        selected_rows, _ = TQ._open_authenticated_gold_selection(selected)
        assert any(r["outcome"] == "failed" for r in selected_rows)
        assert all(r["outcome"] != "timeout" for r in selected_rows)
        assert record["raw_rows"] == before
        assert plan in P.protected_paths(evidence, doc)
        bad = copy.deepcopy(typed)
        bad["stub-control"] = typed["full-gold"]
        refuses("continuation used as stub", lambda: P.derive(inputs, bad, sources))
        old_id = record["facts"]["child_observation_id"]
        record["facts"]["child_observation_id"] = ordinary["stub-control"]["facts"]["observation_id"]
        refuses("child observation reused by a control", lambda: P.derive(inputs, typed, sources))
        record["facts"]["child_observation_id"] = old_id
        record["row_sources"].append({**P._reference(observations["stub-control"]["shards"][0]),
                                      "segment": "child"})
        refuses("physical continued source reused by a control", lambda: P.derive(inputs, typed, sources))
        record["row_sources"].pop()
        wrong = copy.deepcopy(doc)
        wrong["schema"] = P.SCHEMA
        write(evidence, wrong)
        refuses("continued inventory relabeled as homogeneous v1", lambda: P.load(evidence))
        write(evidence, doc)
        wrong = copy.deepcopy(doc)
        wrong["observations"]["full-gold"]["facts"].pop("transition")
        write(evidence, wrong)
        refuses("saved policy transition removed", lambda: P.load(evidence))
        write(evidence, doc)
        record["identity"] = {**record["identity"], "harness_version": -1}
        refuses("ordinary controls under another execution policy", lambda: P.derive(inputs, typed, sources))
    assert all(Path(path).read_bytes() == raw for path, raw in snapshot.items())
    print("  [PASS] typed continued N1, physical separation, disclosure and original-row selection")


def candidate_roundtrip(root, f, inputs, observations, shared, baselines, evidence, doc, raw_snapshot):
    from ..core.ledger_primitives import domain_digest, ordered_item_ids_digest
    from ..core import source_view as V
    from ..toolkit.source_views import MAP_SCHEMAS
    tasks = TQ.load_jsonl(inputs["release"])
    tasks = [dict(task, checked_interfaces={"checked": [], "empty_reason": "no_action_or_check_call"})
             for task in tasks]
    task_path = rows(root / "checked-tasks.jsonl", tasks)
    ids = [task["item_id"] for task in tasks]
    annotations = domain_digest(MAP_SCHEMAS["r2t.target-body-map/v2"][1],
        [{"item_id": task["item_id"], "checked_interfaces": task["checked_interfaces"]} for task in tasks])
    source = root / "assets/source"
    seed = V.qualify_source_seed(root=str(source), project="prestashop",
                                runtime_seed_digest=shared["workspace_seed_digest"])
    mapping = V.TargetMap("prestashop", seed.files_digest, ordered_item_ids_digest(ids), annotations,
        tuple(V.ItemSelection(iid, ("Fixture.addA",), V.Selection()) for iid in ids))
    policy = V.ViewPolicy("prestashop", "full", "b" * 64, "c" * 64, "d" * 64,
                          ("src/Core/Fixture.php",), "fixture/v1")
    candidate = copy.deepcopy(baselines["full-gold"])
    for n, row in enumerate(candidate):
        manifest = V.build_agent_view(V.plan_agent_view(source_seed=seed, item_id=row["item_id"],
            target_map=mapping, policy=policy), destination=str(root / f"view{n}"))
        manifest_path = write(root / f"view{n}.manifest.json", manifest)
        row["adapter"] = "fixture-agent"
        row.pop("reference_derivation")
        row.pop("reference_source_tag")
        row["visibility"] = {"schema": "r2t.visibility-run/v1", **{key: manifest[key] for key in (
            "source_files_digest", "runtime_seed_digest", "map_digest", "policy_digest",
            "population_digest", "interfaces_digest", "scope", "feedback")}}
        row["metadata"] = {"agent_view": {"path": manifest_path,
            "file_sha256": MR.sha256_file(manifest_path), "digest": manifest["digest"]}}
    run = rows(root / "candidate.jsonl", candidate)
    gold_baseline = observations["full-gold"]["baseline"]
    candidate_args = dict(run_path=run, inputs=inputs, gold_baseline=gold_baseline, task_items=task_path)
    _, expected = P.candidate_inputs(evidence, **candidate_args)
    plain = rows(root / "plain-tasks.jsonl", TQ.load_jsonl(inputs["release"]))
    refuses("unannotated candidate sample", lambda: P.candidate_inputs(evidence, **dict(candidate_args, task_items=plain)))
    malformed = copy.deepcopy(tasks)
    malformed[0]["checked_interfaces"]["empty_reason"] = None
    bad = rows(root / "bad-tasks.jsonl", malformed)
    refuses("malformed checked annotation", lambda: P.candidate_inputs(evidence, **dict(candidate_args, task_items=bad)))
    changed = copy.deepcopy(tasks)
    changed[0]["checked_interfaces"] = {"checked": [{"key": ["Fixture", "addA"],
        "declaration": "public function addA($a, $b)"}], "empty_reason": None}
    other = rows(root / "other-annotations.jsonl", changed)
    refuses("valid annotation not used by the generation view", lambda: P.candidate_inputs(evidence, **dict(candidate_args, task_items=other)))
    identity = {**shared, **MR.generation_evidence_for_run(run, candidate, development=True),
        "candidate_run_sha256": MR.sha256_file(run),
        "candidate_generated_tests_sha256": MR.candidate_digest(TQ.passed_solutions(candidate)),
        "gold_baseline_sha256": MR.sha256_file(gold_baseline),
        "gold_generated_tests_sha256": MR.candidate_digest(TQ.passed_solutions(baselines["full-gold"])),
        "gold_results_sha256": MR.sha256_file(evidence),
        "gold_results_attestation_sha256": MR.sha256_file(evidence)}
    admitted = P.selection(evidence, expected, {**identity, "timeout_seconds": 600},
                          worker_resources=f["worker_resources"])
    jobs = []

    def execute(job):
        jobs.append(job)
        assert job["side"] == "candidate", "a second gold execution was scheduled"
        terminal = [{"item_id": iid, "mutant_id": mid, "outcome": "timeout",
                     "attempt": 1, "retried_infrastructure": False, **MR.row_identity_stamp(job["identity"])}
                    for iid, mid in sorted(TQ._job_pairs(job["mutants"], job["by_mutant"], job["files_by_item"]))]
        rows(job["out"], terminal)
        for state in ("running", "complete"):
            MR.write_shard_provenance(job["out"], job["identity"], state, provenance=job["provenance"])
        return {"out": job["out"], "rows": len(terminal), "side": "candidate"}

    provenance = {**inputs, "run": run, "gold_baseline": gold_baseline, "seed": f["seed"],
        P.SUMMARY_KEY: evidence, "gold_results_source": evidence, "gold_results_attestation": evidence,
        "reference_diagnostics": doc["diagnostics"], "inference_valid": False, "timeout_seconds": 600,
        "reference_method": "single_observation", "reference_observation_count": 1,
        "candidate_observation_count": 1, "prestashop_task_items": P._reference(task_path)}

    def final(summary, summary_path):
        TQ._validate_native_summary_before_completion(summary, summary_path, run)

    summary = TQ.run_test_quality(run_rows=candidate, gold_baseline_rows=baselines["full-gold"],
        manifest=f["manifest"], by_mutant=json.loads(Path(inputs["map"]).read_text())["by_mutant"],
        out_dir=str(root / "candidate-campaign"), execute=execute, n_workers=1,
        authenticated_gold=admitted, identity_inputs=identity, provenance=provenance,
        worker_resources=f["worker_resources"], final_summary_validator=final)
    assert len(jobs) == 1 and jobs[0]["side"] == "candidate"
    assert summary["verdict_basis"] == "full_gold" and summary["recall_macro"] == 1.0
    assert summary["reference_observation_count"] == summary["candidate_observation_count"] == 1
    assert summary["population_basis"] == "budgeted_sample" and not summary["inference_valid"]
    TQ.write_sidecar(summary, run)
    assert TQ.load_bound_test_quality(run) == summary
    claimed_policy = dict(summary, worker_memory_policy=doc.get("worker_memory_policy"))
    claimed_policy.pop("worker_resources")
    refuses("saved candidate replaces bound runtime with policy claim", lambda: P.saved_reader(claimed_policy, expected))
    runtime_path = f["worker_resources"][0]["runtime_attestation"]
    runtime_before = Path(runtime_path).read_bytes()
    runtime_doc = json.loads(runtime_before)
    if "memory" in runtime_doc:
        runtime_doc["memory"]["policy"]["memory_bytes"] = 8589934592
        write(runtime_path, runtime_doc)
        refuses("saved candidate runtime cap changed", lambda: TQ.load_bound_test_quality(run))
        Path(runtime_path).write_bytes(runtime_before)
    assert not TQ.publication_ready(summary)[0]
    with redirect_stdout(io.StringIO()) as captured:
        TQ.print_summary(summary)
    assert "reference observations: 1" in captured.getvalue()
    assert "reference gold rows reused" in captured.getvalue()
    assert "declared B100 development basis" in captured.getvalue()
    assert "sensitivity only after C4" not in captured.getvalue()
    from . import results as R, report as REPORT
    rendered = R.mutation(summary, set(ids))
    assert rendered["reference_method"] == "single_observation"
    assert rendered["reference_observation_count"] == rendered["candidate_observation_count"] == 1
    note = " ".join(REPORT._v2_mutation_detail_lines(rendered))
    assert "full_gold B100 development" in note and "no repeat-stability claim" in note
    for key in ("reference_observation_count", "candidate_observation_count"):
        refuses("saved result omits " + key, lambda key=key: P.saved_reader(
            {k: v for k, v in summary.items() if k != key}, expected))
    before = Path(task_path).read_bytes()
    rows(task_path, changed)
    refuses("saved task bytes changed", lambda: TQ.load_bound_test_quality(run))
    Path(task_path).write_bytes(before)
    assert all(Path(path).read_bytes() == before for path, before in raw_snapshot.items())
    # A real zero-pass sample refuses no useful work and opens no worker.
    failed = rows(root / "failed.jsonl", [dict(row, outcome="failed") for row in candidate])
    from . import cli
    args = argparse.Namespace(**inputs, run=failed, gold_baseline=gold_baseline,
        development=True, prestashop_reference_evidence=evidence, prestashop_task_items=task_path,
        workers=[str(root / "absent-worker.json")], seed=f["seed"], out=str(root / "no-campaign"))
    with redirect_stdout(io.StringIO()) as captured:
        assert cli.cmd_test_quality(args) == 0
    assert json.loads(captured.getvalue())["campaign_created"] is False
    assert not (root / "no-campaign").exists()
    # Reach the actual positive CLI path with real inputs and evidence. Only
    # runtime contact and the executor are substituted; no asset/reference or
    # saved-summary validator is mocked.
    from types import SimpleNamespace
    from . import worker as W
    cli_run = rows(root / "cli-candidate.jsonl", candidate)
    worker_path = f["worker_resources"][0]["worker_spec"]
    args = argparse.Namespace(**inputs, run=cli_run, gold_baseline=gold_baseline,
        development=True, prestashop_reference_evidence=evidence, prestashop_task_items=task_path,
        workers=[worker_path], seed=f["seed"], out=str(root / "cli-campaign"),
        gold_results=None, gold_results_attestation=None, no_sidecar=False, resume=False,
        timeout=600, allow_incomplete=False, allow_degraded_gold=False,
        gold=f["controls"]["gold_root"], artifacts=str(root), repo=str(root / "workspace"),
        boundary=str(Path(f["common_args"]["validation_path"]).parents[1] / "boundary_prestashop.yml"))
    engine_dir, _ = MR.binding_for(f["manifest"]["engine"])

    def runtime(paths, specs, seed_path, version, needs_database, *, project):
        assert project == "prestashop"
        assert paths == [worker_path] and needs_database
        W.validate_offline_worker_runtime_pool(paths)
        assert W.verified_seed_identity(seed_path, True)["workspace_seed_digest"] == shared["workspace_seed_digest"]
        return {**shared, "worker_resources": f["worker_resources"], "protected_evidence_paths": []}

    def run_slice(_harness, mutants, _items, files, by_mutant, _engine_dir, out_path, **kw):
        return execute({"identity": kw["identity"], "side": kw["identity"]["side"],
            "mutants": mutants, "files_by_item": files, "by_mutant": by_mutant,
            "out": out_path, "provenance": kw["provenance"]})

    with patch.object(W, "validate_mutation_runtime", runtime), \
         patch.object(W, "preflight", return_value=None) as runtime_probe, \
         patch.object(cli, "_stack", return_value=SimpleNamespace(engine_dir=engine_dir, FRAMEWORK="behat")), \
         patch.object(cli, "_stack_profile", return_value=SimpleNamespace(needs_database=True)), \
         patch.object(cli, "_harness", return_value=(SimpleNamespace(substrate_baseline_sha256=shared["substrate_baseline_sha256"]), None, None)), \
         patch.object(MR, "run_slice", run_slice):
        missing = copy.copy(args)
        missing.prestashop_reference_evidence = None
        missing.prestashop_task_items = None
        refuses("old command would repeat gold", lambda: cli.cmd_test_quality(missing))
        assert not runtime_probe.called
        with redirect_stdout(io.StringIO()):
            assert cli.cmd_test_quality(args) == 0
    assert len(jobs) == 2 and all(job["side"] == "candidate" for job in jobs)
    assert TQ.load_bound_test_quality(cli_run)["candidate_observation_count"] == 1
    assert all(Path(path).read_bytes() == before for path, before in raw_snapshot.items())
    print("  [PASS] exact views, one candidate-only execution, unchanged timeout recall and saved report reload")


def cli_refusals():
    from . import cli
    for missing in ("release", "budgeted_sidecar", "prestashop_task_items"):
        values = dict(prestashop_reference_evidence="ref.json", prestashop_task_items="tasks.jsonl",
                      release="original.jsonl", budgeted_sidecar="budget.json")
        values.pop(missing)
        refuses("missing --" + missing.replace("_", "-"),
                lambda: cli.cmd_test_quality(argparse.Namespace(**values)))
    # No PrestaShop amendment adopts GOLD_KILLED_CANDIDATE_SCOPE_SPEC.md.
    complete = dict(prestashop_reference_evidence="ref.json", prestashop_task_items="tasks.jsonl",
                    release="original.jsonl", budgeted_sidecar="budget.json")
    for option in ({"candidate_pairs": "gold-killed"}, {"gold_pair_plan": "plan.json"}):
        try:
            cli.cmd_test_quality(argparse.Namespace(**complete, **option))
        except SystemExit as exc:
            assert "no PrestaShop amendment adopts" in str(exc), str(exc)
        else:
            raise AssertionError(f"PrestaShop evidence accepted {option}")
        print(f"  [PASS] refuses PrestaShop evidence with {sorted(option)[0]}")
    for option in ("prestashop_reference_evidence", "prestashop_task_items"):
        with patch.object(cli, "_cmd_test_quality_slice3", side_effect=AssertionError("unexpected Slice-3 dispatch")):
            refuses("Slice-3 combined with " + option,
                lambda: cli.cmd_test_quality(argparse.Namespace(slice3_observations="old", **{option: "new"})))


def selftest():
    arithmetic()
    cli_refusals()
    with tempfile.TemporaryDirectory(prefix="presta-reference-") as directory:
        root = Path(directory)
        # Docker authority evidence paths require a private directory chain;
        # tempfile honors the caller umask but a shared /dev/shm parent can
        # still make the newly-created root peer-replaceable. Keep this test
        # fixture private without weakening the production authority check.
        root.chmod(0o700)
        native_roundtrip(root / "historical")
        native_roundtrip(root / "capped", memory=True)
        _, inputs, sources, observations, _, _, _ = fixture(
            root / "mixed", memory=True, role_memory={"stub-control": False})
        refuses("reference roles mix capped and uncapped pools", lambda: P.derive(inputs, observations, sources))
        continued_consumer(root / "continued")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())
