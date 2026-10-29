"""The approved PrestaShop failed-prefix transition, never ordinary resume.

Parents keep their failed/interrupted state. The independently reviewed
transition is consumed alongside native byte, identity and exact-prefix checks.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import subprocess

from . import mutation_run as R, mutation_continuation as M
from . import reference_workloads as RW
from ..data import mutation_attestation as A

SCHEMA = "r2t.prestashop-retained-prefix/1"
ADMISSION_SCHEMA = "r2t.prestashop-prefix-admission/1"
KIND = "prestashop_retained_prefix_v1"
PARENT_COMMIT = "17ff8fa1dafbdf9df5880245a83d7bb8511165a8"
PARENT_TAG = "onb-prestashop-memory4g-20260922"
#: The reviewed child harness (validate.HARNESS_VERSION at the child tag).
CHILD_HARNESS_VERSION = 23
PARENT_OBSERVATION = "544d26655aa8e5024a89e43a0ca79d27"
COUNTS = (132800, 69065, 63735)
PAIR_DIGESTS = (
    "e761f2cdbcc1a996fbd0d5ad405289f32ec92c04fcdc88107f81e93917539626",
    "3cb4cdde98dec56b088378e32a2e4cff0691747edbc443046a6dc0040b2401b9",
    "9e0752baabeaca859825914063c626354e5cc1c83c335e7b13b191c8be609777",
)
ASSETS = {"validation", "manifest", "map", "release", "candidate", "budgeted_sidecar", "recipe"}
SOURCES = {"gold_root", "release_gold_root", "closures_path"}
SOURCE_FILES = {"harness.py", "mutation_run.py", "prestashop_resources.py"}
FAILURE_FILES = {"report", "immutable_diff", "resource_diff", "shop_metadata", "shop_bytes",
                 "last_persisted_mutant", "last_unpersisted_recorder"}
CHANGED_CORE = {"harness_version", "reference_source_tag", "substrate_baseline_sha256"}


def require(ok, reason):
    M._require(ok, "PrestaShop " + reason)


def _doc(ref):
    return M._read(M._check_reference(ref))


def _source_files(commit, refs):
    require(set(refs) == SOURCE_FILES and isinstance(commit, str)
            and len(commit) == 40 and all(c in "0123456789abcdef" for c in commit),
            "source binding differs")
    root = str(Path(__file__).resolve().parents[3])
    for name, ref in refs.items():
        actual = Path(M._check_reference(ref)).read_bytes()
        result = subprocess.run(["git", "-C", root, "show", commit + ":benchmark/r2t/bench/" + name],
                                capture_output=True, check=False)
        require(result.returncode == 0 and actual == result.stdout,
                "review source is not the exact committed " + name)


def _source_tag(commit, tag):
    require(isinstance(tag, str) and bool(tag) and not any(c.isspace() for c in tag),
            "source tag is missing")
    root = str(Path(__file__).resolve().parents[3])
    result = subprocess.run(["git", "-C", root, "rev-parse", "--verify", "refs/tags/" + tag + "^{commit}"],
                            capture_output=True, check=False)
    require(result.returncode == 0 and result.stdout.decode().strip() == commit,
            "reviewed source tag resolves to another commit")


def _full_gold(identity):
    R._validate_campaign_identity(identity)
    require(identity["schema"] == R.MUTATION_IDENTITY_SCHEMA_V5
            and identity["asset_project"] == "prestashop"
            and identity["reference_control_role"] == "full-gold"
            and identity["kind"] == "mutation-run" and identity["side"] == "gold"
            and identity["sample"] is None and identity["timeout_seconds"] == 600
            and identity.get("population_basis") == "budgeted_sample"
            and "continuation_plan_sha256" not in identity,
            "requires the B100 full-gold identity")


def _assets(inputs, sources):
    require(set(inputs) == ASSETS and set(sources) == SOURCES, "input fields differ")
    paths = {key: M._check_reference(ref) for key, ref in inputs.items()}
    assets = A.validate_campaign_asset_inputs(paths["validation"],
        manifest_path=paths["manifest"], map_path=paths["map"], release_path=paths["release"],
        budgeted_sidecar=paths["budgeted_sidecar"], require_release_ready=True)
    require(assets["asset_project"] == "prestashop"
            and assets.get("population_basis") == "budgeted_sample"
            and _doc(inputs["budgeted_sidecar"]).get("per_item") == 100,
            "needs the approved PrestaShop B100 population")
    control = RW.validate_development_control_input(project="prestashop", role="full_gold",
        run_path=paths["candidate"], recipe_path=paths["recipe"],
        execution_release_path=paths["release"], **sources)
    files = control["files_by_item"]
    ids = A.load_release_ids(paths["release"])
    require(set(files) == ids and all(value == "passed" for value in control["baseline_outcomes"].values()),
            "gold baseline is not the complete passing release")
    return assets, files, control


def _failure(refs):
    require(set(refs) == FAILURE_FILES, "failure evidence fields differ")
    for ref in refs.values():
        M._check_reference(ref)
    immutable = _doc(refs["immutable_diff"])
    require(immutable.get("baseline") is True
            and immutable.get("added") == ["config/themes/hummingbird/shop.json"]
            and all(immutable.get(key) == [] for key in ("changed", "missing", "mutated")),
            "failure is not the single empty-shop immutable addition")
    changes = _doc(refs["resource_diff"])
    require(isinstance(changes, list) and bool(changes), "resource difference is absent")
    for change in changes:
        require(change["path"] == "tests/Resources/modules"
                or change["path"].startswith("tests/Resources/modules/"),
                "resource difference is outside native module modes")
        actual, seed = change["actual"], change["seed"]
        require({k: v for k, v in actual.items() if k != "mode"}
                == {k: v for k, v in seed.items() if k != "mode"},
                "resource difference changes content or kind")
        require((seed.get("mode"), actual.get("mode"), seed.get("kind"))
                in {(0o644, 0o666, "file"), (0o755, 0o777, "directory")},
                "resource mode transition differs")
    metadata = _doc(refs["shop_metadata"])
    raw = Path(M._check_reference(refs["shop_bytes"])).read_bytes()
    require(metadata.get("path") == "config/themes/hummingbird/shop.json"
            and metadata.get("size") == len(raw)
            and metadata.get("sha256") == hashlib.sha256(raw).hexdigest(),
            "empty-shop bytes differ from preserved metadata")


def _admission(ref, parent_core, parent_evidence):
    receipt = _doc(ref)
    expected = {"schema", "decision", "parent_source_commit", "parent_source_tag",
                "parent_observation_id", "parent_source_files", "child_source_commit",
                "child_source_tag", "child_source_files", "child_core", "method_approval",
                "source_compatibility_review", "prefix_validity_review", "repair_qualification",
                "failure_evidence", "parent_evidence"}
    require(set(receipt) == expected and receipt["schema"] == ADMISSION_SCHEMA
            and receipt["decision"] == "retain_verified_prefix_after_empty_shop_repair"
            and receipt["parent_source_commit"] == PARENT_COMMIT
            and receipt["parent_source_tag"] == PARENT_TAG
            and receipt["parent_observation_id"] == PARENT_OBSERVATION,
            "admission is not the approved historical transition")
    require(receipt["parent_evidence"] == parent_evidence, "reviewed parent bytes differ")
    _source_tag(PARENT_COMMIT, PARENT_TAG)
    _source_tag(receipt["child_source_commit"], receipt["child_source_tag"])
    _source_files(PARENT_COMMIT, receipt["parent_source_files"])
    _source_files(receipt["child_source_commit"], receipt["child_source_files"])
    _failure(receipt["failure_evidence"])
    child = receipt["child_core"]
    changed = {key for key in set(parent_core) | set(child) if parent_core.get(key) != child.get(key)}
    require(set(child) == set(parent_core) and changed <= CHANGED_CORE and parent_core["harness_version"] == 19
            and child.get("harness_version") == CHILD_HARNESS_VERSION
            and parent_core["reference_source_tag"] == PARENT_TAG
            and child.get("reference_source_tag") == receipt["child_source_tag"],
            "child changes more than the approved source/reset transition")
    # Review records are prospective trusted attestations, never synthesized
    # historical per-pair witnesses. Their exact reviewed inputs must match.
    authority = {key: receipt[key] for key in (
        "parent_source_commit", "parent_source_files", "child_source_commit", "child_source_tag",
        "child_source_files", "child_core", "failure_evidence", "method_approval", "repair_qualification", "parent_evidence")}
    M._check_reference(receipt["method_approval"])
    for field, schema in (("source_compatibility_review", "r2t.prestashop-source-compatibility-review/1"),
                          ("prefix_validity_review", "r2t.prestashop-prefix-validity-review/1")):
        review = _doc(receipt[field])
        require(set(review) == {"schema", "decision", "reviewer", "authority", "rationale"}
                and review["schema"] == schema and review["decision"] == "admit"
                and isinstance(review["reviewer"], str) and bool(review["reviewer"])
                and isinstance(review["rationale"], str) and bool(review["rationale"])
                and review["authority"] == authority, "independent review bindings differ")
    qualification = _doc(receipt["repair_qualification"])
    require(qualification.get("schema") == "r2t.prestashop-empty-shop-qualification/1"
            and set(qualification.get("source_files", {})) == SOURCE_FILES
            and all(qualification["source_files"][name]["sha256"] == receipt["child_source_files"][name]["sha256"] for name in SOURCE_FILES)
            and qualification.get("status") == "passed"
            and qualification.get("checks") == {"empty_name_created": True,
                "exact_resource_restoration": True, "protected_siblings_rejected": True},
            "repair qualification is absent or differs from reviewed child")
    _source_files(qualification["source_commit"], qualification["source_files"])
    for evidence in qualification.get("evidence", []):
        M._check_reference(evidence)
    require(bool(qualification.get("evidence")), "qualification omits raw evidence")
    return receipt


def _snapshot(parent_paths, inputs, sources, admission_ref):
    assets, files, control = _assets(inputs, sources)
    require(len(parent_paths) == 24 and len(set(parent_paths)) == 24,
            "requires the original 24 distinct parents")
    directory = os.path.dirname(parent_paths[0])
    require(all(os.path.dirname(p) == directory for p in parent_paths), "parents span directories")
    eligible = [m for m in assets["manifest"]["mutants"]
                if any(i in files for i in assets["map"]["by_mutant"].get(m["id"], []))]
    done, full, parents, partitions, raw_rows = set(), set(), [], [], {}
    representative = None
    from .worker import _seed_verification_scope
    with _seed_verification_scope():
        for shard, path in enumerate(parent_paths):
            side = M._read(R.provenance_path(path))
            identity = side["campaign_identity"]
            _full_gold(identity)
            require(identity["shard"] == shard and identity["of"] == 24
                    and side["status"] == ("failed" if shard == 16 else "interrupted")
                    and side["observation_id"] == PARENT_OBSERVATION,
                    "parent shard/status/observation differs")
            if representative is None:
                representative = identity
            require(M._core(identity) == M._core(representative)
                    and identity["worker_resources_sha256"] == representative["worker_resources_sha256"],
                    "parent identities differ")
            verification = R.verify_shard(path)
            require(verification["identity_consistent"] and verification["rows_consistent"],
                    "parent row integrity fails")
            R.validate_worker_resource_evidence(side, identity)
            if shard == 0:
                from .prestashop_memory import normalized_worker_memory_policy, PRESTASHOP_MEMORY_POLICY
                require(normalized_worker_memory_policy(side["worker_resources"]) == PRESTASHOP_MEMORY_POLICY,
                        "parent memory condition differs")
            expected = R.ordered_pairs_for_slice(eligible[shard::24], assets["map"]["by_mutant"], files)
            rows = A.load_jsonl(path)
            digest = R.campaign_identity_digest(identity)
            require(all(not R._row_identity_problems(row, identity, digest) for row in rows),
                    "parent row stamps differ from original campaign")
            observed = [(row["item_id"], row["mutant_id"]) for row in rows]
            require(observed == expected[:len(observed)] and len(expected) == identity["expected_pairs"]
                    and R.pair_set_digest(expected) == identity["expected_pairs_sha256"],
                    "parent rows are not the exact native ordered prefix")
            require(not done.intersection(observed), "parent pairs overlap")
            done.update(observed)
            full.update(expected)
            raw_rows.update(zip(observed, rows))
            partitions.append(expected[len(observed):])
            parents.append({"rows": M._reference(path), "sidecar": M._reference(R.provenance_path(path))})
    R.validate_standalone_output_directory(parent_paths, representative)
    R.validate_campaign_asset_claims(representative, assets, validation_path=inputs["validation"]["path"],
        manifest_path=inputs["manifest"]["path"], map_path=inputs["map"]["path"], release_path=inputs["release"]["path"])
    generation = R.reference_generation_evidence(role="full-gold", source_tag=PARENT_TAG,
        candidate_rows=A.load_jsonl(inputs["candidate"]["path"]), release_item_ids=A.load_release_ids(inputs["release"]["path"]),
        release_sha256=inputs["release"]["sha256"], asset_index_sha256=assets["asset_index_sha256"], control=control)
    wanted = {**generation, "candidate_run_sha256": inputs["candidate"]["sha256"],
              "candidate_generated_tests_sha256": R.candidate_digest(files),
              "solution_generated_tests_sha256": R.candidate_digest(files)}
    require(all(representative.get(k) == v for k, v in wanted.items()), "parent reference bytes differ")
    from . import test_quality as TQ
    from ..toolkit import gold_killset as GK
    TQ.validate_native_retry_evidence(raw_rows.values(), where="retained PrestaShop prefix")
    for row in raw_rows.values():
        GK._known_outcome(row.get("outcome"))
    remaining = full - done
    require(tuple(map(len, (full, done, remaining))) == COUNTS
            and tuple(R.pair_set_digest(p) for p in (full, done, remaining)) == PAIR_DIGESTS,
            "sets differ from the approved observation")
    require(all(partitions), "continuation has an empty original partition")
    output_plan = M._reference(os.path.join(directory, R.MUTATION_OUTPUT_PLAN))
    receipt = _admission(admission_ref, M._core(representative),
                         {"parents": parents, "output_plan": output_plan})
    plan = {"schema": SCHEMA, "parents": parents,
            "parent_output_plan": output_plan,
            "inputs": inputs, "sources": sources, "admission": admission_ref,
            "parent_identity": representative, "child_core": receipt["child_core"],
            "child_workers": 24, "full_pairs": len(full), "full_pairs_sha256": R.pair_set_digest(full),
            "completed_pairs": len(done), "completed_pairs_sha256": R.pair_set_digest(done),
            "partitions": [[list(pair) for pair in part] for part in partitions]}
    return plan, done, full, raw_rows, receipt


def _refs(value):
    if isinstance(value, dict):
        if set(value) == {"path", "sha256"}:
            yield value
        else:
            for child in value.values():
                yield from _refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _refs(child)


def create_plan(parent_paths, *, inputs, sources, admission_path, plan_out):
    """Validate before any claim/write; retain failed parent bytes unchanged."""
    parents = list(map(os.path.abspath, parent_paths))
    require(bool(parents), "parents missing")
    directory = os.path.dirname(parents[0])
    claim = M.claim_path(directory)
    input_refs = {key: M._reference(path) for key, path in inputs.items()}
    admission = M._reference(admission_path)
    plan_out = os.path.abspath(plan_out)
    require(os.path.commonpath([directory, plan_out]) != directory,
            "plan must be outside parent directory")
    from .worker import resource_fields
    with ExitStack() as stack:
        for path in sorted(parents):
            stack.enter_context(R.output_lock(path))
        resources = M._read(R.provenance_path(parents[0]))["worker_resources"]
        stack.enter_context(R.mutation_resource_locks([
            (key, resource[key]) for resource in resources
            for key in resource_fields(True) if resource.get(key)]))
        plan, _done, _full, _raw, _receipt = _snapshot(parents, input_refs, sources, admission)
        M._crash_quiescence(resources, directory, plan["parent_identity"]["container_image_digest"])
        # An interrupted write can leave a fully authenticated plan without its
        # claim. Re-entry may finish only that byte-identical plan, never replace.
        encoded = (json.dumps(plan, sort_keys=True, indent=2) + "\n").encode()
        if os.path.lexists(plan_out):
            require(Path(M._check_reference(M._reference(plan_out))).read_bytes() == encoded,
                    "existing plan differs")
        else:
            require(not os.path.lexists(claim), "another parent claim exists")
            R.atomic_write_bytes(plan_out, encoded, refuse_existing=True)
        marker = {"schema": M.CLAIM_SCHEMA, "plan": M._reference(plan_out)}
        if os.path.lexists(claim):
            require(M._read(claim) == marker, "parent claim differs")
        else:
            R.atomic_write_bytes(claim, (json.dumps(marker, sort_keys=True) + "\n").encode(),
                                 refuse_existing=True)
    return plan


def validate_plan(path):
    path = os.path.abspath(path)
    plan = M._read(path)
    require(plan.get("schema") == SCHEMA, "plan schema differs")
    parents = [M._check_reference(row["rows"]) for row in plan["parents"]]
    for row in plan["parents"]:
        M._check_reference(row["sidecar"])
    M._check_reference(plan["parent_output_plan"])
    claim = M.claim_path(os.path.dirname(parents[0]))
    require(M._read(claim) == {"schema": M.CLAIM_SCHEMA, "plan": M._reference(path)},
            "parent claim differs")
    derived, done, full, raw, receipt = _snapshot(parents, plan["inputs"], plan["sources"], plan["admission"])
    require(plan == derived, "plan does not rederive")
    resources = M._read(R.provenance_path(parents[0]))["worker_resources"]
    refs = list(_refs(plan)) + list(_refs(receipt))
    for field in ("source_compatibility_review", "prefix_validity_review", "repair_qualification"):
        refs.extend(_refs(_doc(receipt[field])))
    for ref in refs:
        M._check_reference(ref)
    return {"plan": plan, "plan_sha256": R.sha256_file(path),
            "partitions": [{tuple(pair) for pair in part} for part in plan["partitions"]],
            "parent_identity": plan["parent_identity"], "parent_resources": resources,
            "completed": done, "full": full, "uncertain": set(), "raw_rows": raw,
            "admission": receipt,
            "containment_paths": [r["workspace"] for r in resources],
            "protected_paths": [path, claim, *[ref["path"] for ref in refs],
                *[r[k] for r in resources for k in ("env_file", "worker_spec", "runtime_attestation") if r.get(k)]]}


def validate_identity(binding, identity):
    result = dict(identity)
    recorded = result.pop("continuation_plan_sha256", binding["plan_sha256"])
    _full_gold(result)
    require(recorded == binding["plan_sha256"] and M._core(result) == binding["plan"]["child_core"],
            "child source/runtime/reference differs from approved transition")
    require(result["of"] == 24 and 0 <= result["shard"] < 24, "child allocation differs")
    pairs = binding["partitions"][result["shard"]]
    require(result["expected_pairs"] == len(pairs)
            and result["expected_pairs_sha256"] == R.pair_set_digest(pairs), "child complement differs")
    require(result["worker_resources_sha256"] != binding["parent_identity"]["worker_resources_sha256"],
            "child reuses parent pool")
    result["continuation_plan_sha256"] = recorded
    R._validate_campaign_identity(result)
    return result


def load_completed(plan_path, child_paths):
    """Only this typed reader admits the reviewed parent/child policy change."""
    binding = validate_plan(plan_path)
    children = list(child_paths)
    require(len(children) == 24, "complete child pool required")
    pending = binding["full"] - binding["completed"]
    for shard, path in enumerate(children):
        side = M._read(R.provenance_path(path))
        require(side["campaign_identity"]["shard"] == shard, "children not in original order")
        M.validate_child_resources(binding, side["worker_resources"])
        validate_identity(binding, side["campaign_identity"])
        R.completed_pairs(path, side["campaign_identity"], expected_pairs=binding["partitions"][shard], require_complete=True)
    child = R.validate_native_shards(children, expected_pairs=pending, required_side="gold",
        return_campaign=True, _continuation_plan_sha256=binding["plan_sha256"])
    require(not binding["completed"].intersection(child["pairs"])
            and binding["completed"] | child["pairs"] == binding["full"], "incomplete or overlapping aggregate")
    raw = dict(binding["raw_rows"])
    for path in children:
        for row in A.load_jsonl(path):
            pair = (row["item_id"], row["mutant_id"])
            require(pair not in raw, "duplicate outcome")
            raw[pair] = row
    side = M._read(R.provenance_path(children[0]))
    child_identity = side["campaign_identity"]
    from .prestashop_memory import normalized_worker_memory_policy, PRESTASHOP_MEMORY_POLICY
    memory_policy = normalized_worker_memory_policy(side["worker_resources"])
    require(memory_policy == PRESTASHOP_MEMORY_POLICY, "child memory condition differs")
    child_observation = side["observation_id"]
    require(child_observation != PARENT_OBSERVATION, "child observation impersonates parent")
    sources = [{**parent["rows"], "segment": "parent"} for parent in binding["plan"]["parents"]]
    sources += [{**M._reference(path), "segment": "child"} for path in children]
    transition = {"admission": binding["plan"]["admission"],
                  "parent_identity": binding["parent_identity"], "child_identity": child_identity}
    return {"kind": KIND, "identity": child_identity, "parent_identity": binding["parent_identity"],
            "outcomes": {pair: row["outcome"] for pair, row in raw.items()}, "raw_rows": raw,
            "row_sources": sources, "protected_paths": binding["protected_paths"],
            "memory_policy": memory_policy,
            "parent_worker_resources": binding["parent_resources"],
            "child_worker_resources": side["worker_resources"],
            "facts": {"observation_id": PARENT_OBSERVATION, "child_observation_id": child_observation,
                "full_pairs": len(raw), "retained_pairs": len(binding["completed"]), "child_pairs": len(pending),
                "plan_sha256": binding["plan_sha256"], "parent_identity": binding["parent_identity"],
                "child_identity": child_identity, "transition": transition, "stable_killset": False},
            "continuation": {"kind": KIND, "plan": M._reference(plan_path),
                             "child_shards": [M._reference(path) for path in children]}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, help="JSON with inputs and sources mappings")
    parser.add_argument("--parent", action="append", required=True)
    parser.add_argument("--admission", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    inputs = M._read(args.inputs)
    create_plan(args.parent, inputs=inputs["inputs"], sources=inputs["sources"],
                admission_path=args.admission, plan_out=args.out)


if __name__ == "__main__":
    main()
