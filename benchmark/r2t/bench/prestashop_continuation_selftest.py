"""Native retained rows, claims, child receipts and transition refusal checks.

The fixture substitutes population/source replay and host-worker I/O, not
native row identity, prefix order, sidecars, review binding or aggregation.
"""
from contextlib import contextmanager, ExitStack
import copy
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

from . import prestashop_continuation as P, mutation_continuation as M, mutation_run as R
from . import prestashop_memory as PM


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    return str(path)


def refuses(fn):
    try:
        fn()
    except (RuntimeError, ValueError, OSError):
        return
    raise AssertionError("invalid continuation admitted")


@contextmanager
def fixture(root):
    root = Path(root)
    files = {"i1": [{"file_path": "answer.php", "code": "<?php echo 1;"}]}
    mutants = [{"id": f"m{i:02d}"} for i in range(48)]
    mapping = {m["id"]: ["i1"] for m in mutants}
    paths = {key: write(root / (key + ".json"), {}) for key in P.ASSETS}
    Path(paths["release"]).write_text('{"item_id":"i1"}\n')
    Path(paths["candidate"]).write_text(json.dumps({"item_id": "i1", "adapter": "gold", "outcome": "passed", "produced_files": files["i1"]}) + '\n')
    refs = {key: M._reference(path) for key, path in paths.items()}
    assets = {"manifest": {"mutants": mutants}, "map": {"by_mutant": mapping}, "asset_index_sha256": "e" * 64}
    generation = {"generation_provenance_class": R.GENERATION_PROVENANCE_REFERENCE_CONTROL,
                  "reference_control_role": "full-gold", "reference_source_tag": P.PARENT_TAG,
                  "reference_workload_digest": "8" * 64}
    sources = {key: str(root / key) for key in P.SOURCES}
    def resources(name):
        return [{"index": i, "workspace": str(root / name / str(i)), "container": f"{name}{i}",
                 "schema": f"{name}{i}", "credential": f"{name}{i}", "env_file": str(root / name / f'{i}.env'),
                 "workdir": "/app", "worker_spec": str(root / name / f'{i}.json'),
                 "runtime_attestation": str(root / name / f'{i}.runtime.json'), "runtime_attestation_sha256": "a" * 64}
                for i in range(24)]
    parent_resources, child_resources = resources("parent"), resources("child")
    def identity(pairs, shard, child=False):
        return R.build_campaign_identity(asset_index_sha256="e" * 64, asset_project="prestashop",
            mutation_validation_sha256=refs["validation"]["sha256"], mutation_validation_class="native",
            manifest_sha256=refs["manifest"]["sha256"], manifest_digest="a" * 64,
            map_sha256=refs["map"]["sha256"], release_sha256=refs["release"]["sha256"],
            candidate_run_sha256=refs["candidate"]["sha256"], candidate_generated_tests_sha256=R.candidate_digest(files),
            solution_generated_tests_sha256=R.candidate_digest(files), substrate_baseline_sha256="c" * 64,
            worker_resources_sha256=R.content_digest(child_resources if child else parent_resources),
            harness_version=P.CHILD_HARNESS_VERSION if child else 19, container_image_digest="sha256:" + "d" * 64,
            workspace_seed_digest="f" * 64, database_dump_digest="e" * 64, applier_sha256="a" * 64,
            expected_pairs=pairs, engine="r2t-mutate", engine_version="1.0", parser="fixture-php",
            side="gold", shard=shard, of=24, timeout=600,
            population_basis="budgeted_sample", budgeted_sample_sha256="b" * 64, parent_map_sha256="9" * 64,
            **dict(generation, reference_source_tag="reviewed-child" if child else P.PARENT_TAG))
    def shard(path, ident, pairs, status, resources, observation):
        R.prepare_standalone_output_directory(str(path), ident, observation)
        Path(path).write_text(''.join(json.dumps({"item_id": i, "mutant_id": m,
            "outcome": "failed" if m == "m00" else "timeout" if m == "m01" else "passed",
            "attempt": 1, "retried_infrastructure": False, **R.row_identity_stamp(ident)}) + '\n' for i, m in pairs))
        R.write_shard_provenance(str(path), ident, "running", provenance={"worker_resources": resources})
        R.write_shard_provenance(str(path), ident, status, provenance={"worker_resources": resources})
    parents, planned, retained = [], [], []
    for i in range(24):
        pairs = R.ordered_pairs_for_slice(mutants[i::24], mapping, files)
        planned.extend(pairs); retained.extend(pairs[:1])
        path = str(root / "parents" / f"gold.w{i}.jsonl")
        shard(path, identity(pairs, i), pairs[:1], "failed" if i == 16 else "interrupted", parent_resources, P.PARENT_OBSERVATION)
        parents.append(path)
    full, done = set(planned), set(retained)
    source_refs = {name: M._reference(write(root / "source" / name, {"fixture": name})) for name in P.SOURCE_FILES}
    shop = root / "shop.json"; shop.write_text('{}')
    failure = {key: M._reference(write(root / (key + ".json"), {})) for key in P.FAILURE_FILES}
    failure["immutable_diff"] = M._reference(write(root / "immutable.json", {"baseline": True, "added": ["config/themes/hummingbird/shop.json"], "changed": [], "missing": [], "mutated": []}))
    failure["resource_diff"] = M._reference(write(root / "resources.json", [{"path": "tests/Resources/modules", "seed": {"mode": 0o755, "kind": "directory"}, "actual": {"mode": 0o777, "kind": "directory"}}]))
    failure["shop_bytes"] = M._reference(str(shop))
    failure["shop_metadata"] = M._reference(write(root / "metadata.json", {"path": "config/themes/hummingbird/shop.json", "size": 2, "sha256": R.sha256_file(str(shop))}))
    receipt = {"schema": P.ADMISSION_SCHEMA, "decision": "retain_verified_prefix_after_empty_shop_repair",
        "parent_source_commit": P.PARENT_COMMIT, "parent_source_tag": P.PARENT_TAG,
        "parent_observation_id": P.PARENT_OBSERVATION, "parent_source_files": source_refs,
        "child_source_commit": "f" * 40, "child_source_tag": "reviewed-child", "child_source_files": source_refs,
        "child_core": M._core(identity({("i1", "m24")}, 0, True)),
        "method_approval": M._reference(write(root / "approval.json", {"decision": "approved fixture"})),
        "failure_evidence": failure,
        "parent_evidence": {"parents": [{"rows": M._reference(p), "sidecar": M._reference(R.provenance_path(p))} for p in parents],
                            "output_plan": M._reference(str(root / "parents" / R.MUTATION_OUTPUT_PLAN))}}
    receipt["repair_qualification"] = M._reference(write(root / "qualification.json", {"schema": "r2t.prestashop-empty-shop-qualification/1", "source_commit": receipt["child_source_commit"], "source_files": source_refs, "status": "passed", "checks": {"empty_name_created": True, "exact_resource_restoration": True, "protected_siblings_rejected": True}, "evidence": [failure["shop_bytes"]]}))
    authority = {key: receipt[key] for key in ("parent_source_commit", "parent_source_files", "child_source_commit", "child_source_tag", "child_source_files", "child_core", "failure_evidence", "method_approval", "repair_qualification", "parent_evidence")}
    for field, schema in (("source_compatibility_review", "r2t.prestashop-source-compatibility-review/1"), ("prefix_validity_review", "r2t.prestashop-prefix-validity-review/1")):
        receipt[field] = M._reference(write(root / (field + '.json'), {"schema": schema, "decision": "admit", "reviewer": "fixture reviewer", "authority": authority, "rationale": "synthetic fixture only"}))
    admission = write(root / "admission.json", receipt)
    kwargs = {"inputs": paths, "sources": sources, "admission_path": admission, "plan_out": str(root / "plan.json")}
    with ExitStack() as stack:
        stack.enter_context(patch.object(P, "COUNTS", (48, 24, 24)))
        stack.enter_context(patch.object(P, "PAIR_DIGESTS", tuple(R.pair_set_digest(p) for p in (full, done, full-done))))
        stack.enter_context(patch.object(P, "_assets", return_value=(assets, files, {})))
        stack.enter_context(patch.object(P, "_source_files", return_value=None))
        stack.enter_context(patch.object(P, "_source_tag", return_value=None))
        stack.enter_context(patch.object(R, "validate_campaign_asset_claims", return_value=None))
        stack.enter_context(patch.object(R, "reference_generation_evidence", return_value=generation))
        stack.enter_context(patch.object(R, "validate_worker_resource_evidence", return_value=None))
        stack.enter_context(patch.object(PM, "normalized_worker_memory_policy", return_value=PM.PRESTASHOP_MEMORY_POLICY))
        stack.enter_context(patch.object(M, "_crash_quiescence", return_value=None))
        yield {"parents": parents, "kwargs": kwargs, "receipt": receipt, "identity": identity,
               "write_shard": shard, "child_resources": child_resources, "root": root}


def selftest():
    with tempfile.TemporaryDirectory() as directory, fixture(directory) as f:
        root, parents, kwargs = f["root"], f["parents"], f["kwargs"]
        original = {p: Path(p).read_bytes() for path in parents for p in (path, R.provenance_path(path))}
        invalid = copy.deepcopy(f["receipt"]); invalid["child_core"]["timeout_seconds"] = 601
        wrong = write(root / "wrong.json", invalid)
        refuses(lambda: P.create_plan(parents, **dict(kwargs, admission_path=wrong)))
        assert not Path(kwargs["plan_out"]).exists() and not Path(M.claim_path(str(root / 'parents'))).exists()
        # A coherent checksum cannot make a foreign campaign stamp valid.
        old_rows, old_side = Path(parents[0]).read_bytes(), Path(R.provenance_path(parents[0])).read_bytes()
        altered = json.loads(old_rows); altered["harness_version"] = 18
        Path(parents[0]).write_text(json.dumps(altered) + "\n")
        side_doc = json.loads(old_side); side_doc["rows_sha256"] = R.sha256_file(parents[0])
        write(R.provenance_path(parents[0]), side_doc)
        refuses(lambda: P.create_plan(parents, **kwargs))
        assert not Path(kwargs["plan_out"]).exists()
        Path(parents[0]).write_bytes(old_rows); Path(R.provenance_path(parents[0])).write_bytes(old_side)
        for changes in ({"outcome": "passed"}, {"outcome": "invented"}, {"attempt": 0}, {"mutant_id": "m24"}):
            altered = dict(json.loads(old_rows), **changes)
            Path(parents[0]).write_text(json.dumps(altered) + "\n")
            side_doc = json.loads(old_side); side_doc["rows_sha256"] = R.sha256_file(parents[0])
            write(R.provenance_path(parents[0]), side_doc)
            refuses(lambda: P.create_plan(parents, **kwargs))
            assert not Path(kwargs["plan_out"]).exists()
            Path(parents[0]).write_bytes(old_rows); Path(R.provenance_path(parents[0])).write_bytes(old_side)
        P.create_plan(parents, **kwargs)
        binding = M.validate_plan(kwargs["plan_out"])
        assert len(binding["completed"]) == 24 and len(binding["full"]) == 48
        # No-op planning reentry only accepts the exact already-claimed plan.
        P.create_plan(parents, **kwargs)
        children = []
        for i, pairs in enumerate(binding["partitions"]):
            identity = M.validate_identity(binding, f["identity"](pairs, i, True))
            path = str(root / "children" / f'gold.w{i}.jsonl')
            f["write_shard"](path, identity, pairs, "complete", f["child_resources"], "2" * 32)
            children.append(path)
        refuses(lambda: M.validate_continued_observation(kwargs["plan_out"], children))
        record = P.load_completed(kwargs["plan_out"], children)
        assert len(record["outcomes"]) == 48 and record["outcomes"][("i1", "m00")] == "failed"
        assert record["outcomes"][("i1", "m01")] == "timeout"
        assert record["identity"]["harness_version"] == P.CHILD_HARNESS_VERSION and record["parent_identity"]["harness_version"] == 19
        assert record["raw_rows"][("i1", "m00")]["harness_version"] == 19
        assert all(Path(path).read_bytes() == raw for path, raw in original.items())
        refuses(lambda: R.completed_pairs(parents[16], binding["parent_identity"], expected_pairs=binding["full"]))
        refuses(lambda: R.validate_native_shards(children, required_side="gold"))
        bad_identity = dict(f["identity"](binding["partitions"][0], 0, True), timeout_seconds=601)
        refuses(lambda: M.validate_identity(binding, bad_identity))
        Path(parents[0]).write_bytes(original[parents[0]] + b'{}\n')
        refuses(lambda: P.load_completed(kwargs["plan_out"], children))
        Path(parents[0]).write_bytes(original[parents[0]])
        review = Path(f["receipt"]["prefix_validity_review"]["path"])
        review.write_text('{}\n')
        refuses(lambda: P.load_completed(kwargs["plan_out"], children))
    print("  [PASS] failed prefix retained only by reviewed transition; exact complement and immutable parents")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())
