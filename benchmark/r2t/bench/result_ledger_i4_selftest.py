"""Source-only adversarial checks for I4's strict merged receipt.

All evidence is synthetic, owner-private, and temporary.  These checks never
contact Docker, a daemon, a model, a live pool, or the network and never write
a canonical benchmark artifact.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import tempfile
from types import SimpleNamespace

from . import campaign
from .. import cli
from . import cli as bench_cli
from .. import docker_authority as authority
from . import result_ledger as ledger
from ..core import ledger_primitives as primitives
from . import runner
from . import worker
from .validate import HARNESS_VERSION


def _write(path: str, value, *, raw: bool = False,
           indent: int | None = None) -> bytes:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    payload = value if raw else (
        json.dumps(
            value, sort_keys=True,
            separators=None if indent is not None else (",", ":"),
            indent=indent, ensure_ascii=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    with open(path, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)
    return payload


def _raw_ref(path: str, raw: bytes | None = None) -> dict:
    if raw is None:
        raw = ledger.read_trusted_bytes(path, label="fixture reference")
    return {"path": path, "file_sha256": ledger.raw_sha256(raw)}


def _input(role: str, logical: str, path: str) -> dict:
    raw = ledger.read_trusted_bytes(path, label=f"fixture {role}")
    return {
        "role": role, "logical_path": logical, "path": path,
        "byte_length": len(raw), "file_sha256": ledger.raw_sha256(raw),
    }


def _named(values: dict) -> list[dict]:
    return [{
        "name": name,
        "value_json": ledger.canonical_json_bytes(values[name]).decode(),
    } for name in sorted(values)]


def _fixture() -> dict:
    temporary = tempfile.TemporaryDirectory(prefix="r2t-ledger-i4-")
    root = os.path.realpath(temporary.name)
    base = ledger._build_selftest_fixture(root)
    for relative in (
            "workspace1/features", "artifacts1", "merged/a", "merged/b"):
        path = root + "/" + relative
        os.makedirs(path, mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)

    logical_feature = "features/shared.feature"
    feature_raw = (
        b"Feature: strict merge\n"
        b"  Scenario: shared bytes\n"
        b"    Given one stable fixture\n")
    workspaces = [root + "/workspace", root + "/workspace1"]
    artifacts = [root + "/artifacts", root + "/artifacts1"]
    for workspace_path in workspaces:
        _write(
            workspace_path + "/" + logical_feature,
            feature_raw, raw=True)

    bmp_id = "python-docx/\ue000-bmp"
    astral_id = "python-docx/\U00010000-astral"
    candidates = [bmp_id, astral_id]
    candidates.extend(
        f"python-docx/generated-{index:02d}" for index in range(32))
    by_shard: dict[int, list[str]] = {0: [], 1: []}
    selected_candidates = []
    for item_id in candidates:
        shard = campaign.shard_of(item_id, 2)
        if len(by_shard[shard]) < 2:
            by_shard[shard].append(item_id)
            selected_candidates.append(item_id)
        if all(len(values) == 2 for values in by_shard.values()):
            break
    if any(len(values) != 2 for values in by_shard.values()):
        raise AssertionError("fixture candidates do not span two items/K=2")
    # Release order is intentionally independent of Unicode merge order.
    release_ids = list(reversed(selected_candidates))
    generated_ids = [
        item_id for item_id in selected_candidates
        if "/generated-" in item_id]
    expected_codepoint_order = generated_ids + [bmp_id, astral_id]
    release_rows = [{
        "item_id": item_id, "task": "criterion_to_test",
        "project": "python-docx", "language": "python",
        "framework": "behave",
        "provenance": {"file_path": logical_feature, "line": number + 2},
    } for number, item_id in enumerate(release_ids)]
    release_raw = b"".join(
        (json.dumps(
            row, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True) + "\n").encode("utf-8")
        for row in release_rows)
    # The suffix is intentional: a test derives an output whose lock would
    # otherwise alias this exact trusted release file.
    release_path = root + "/release-source.result-v3.lock"
    _write(release_path, release_raw, raw=True)

    specs = []
    spec_raws = []
    spec_paths = []
    result_paths = []
    manifest_paths = []
    for index in range(2):
        result_path = root + f"/runs/shard{index}.jsonl"
        env_path = root + f"/secrets/worker{index}.env"
        spec_path = root + f"/workers/worker{index}.json"
        manifest_path = root + f"/runs/shard{index}.worker.json"
        spec = worker.WorkerSpec(
            index=index, workspace=workspaces[index],
            container=f"fixture_worker_{index}", schema="", credential="",
            env_file=env_path, workdir="/work", out_path=result_path,
            artifacts_root=artifacts[index])
        _write(env_path, f"R2T_WORKER_INDEX={index}\n".encode(), raw=True)
        spec_raw = _write(spec_path, spec.to_json(), indent=1)
        specs.append(spec)
        spec_raws.append(spec_raw)
        spec_paths.append(spec_path)
        result_paths.append(result_path)
        manifest_paths.append(manifest_path)

    authority_ref = _raw_ref(base["authority_path"], base["authority_raw"])
    authority_ref["digest"] = base["authority"]["digest"]
    pool = copy.deepcopy(base["binding"]["pool"])
    pool["workers"] = [{
        "index": index, "worker_spec_path": spec_paths[index],
        "worker_spec_sha256": ledger.raw_sha256(spec_raws[index]),
        "container_name": specs[index].container,
    } for index in range(2)]
    pool["digest"] = ledger.semantic_digest(pool)

    binding_refs = []
    bindings = []
    for index in range(2):
        binding = copy.deepcopy(base["binding"])
        binding["authority"] = authority_ref
        binding["pool"] = copy.deepcopy(pool)
        binding["worker_index"] = index
        binding["worker_spec_sha256"] = ledger.raw_sha256(spec_raws[index])
        binding["container"]["name"] = specs[index].container
        binding["container"]["id"] = str(5 + index) * 64
        binding["digest"] = ledger.semantic_digest(binding)
        authority.validate_binding_document(binding)
        binding_path = root + f"/binding{index}.json"
        binding_raw = _write(binding_path, binding, indent=1)
        binding_ref = _raw_ref(binding_path, binding_raw)
        binding_ref["digest"] = binding["digest"]
        bindings.append(binding)
        binding_refs.append(binding_ref)

    seed_document = ledger.loads_exact_json(base["seed_raw"], label="seed")
    harness = copy.deepcopy(
        base["receipt"]["execution"]["runtime"]["identity"]["harness"])
    image = bindings[0]["container"]["image_id"]
    runtime_references = []
    runtime_paths = []
    runtime_documents = []
    for index in range(2):
        runtime_document = {
            "schema": "r2t.worker-runtime/v3",
            "worker": specs[index].to_json(),
            "worker_spec_sha256": ledger.raw_sha256(spec_raws[index]),
            "seed_dir": os.path.dirname(base["seed_path"]),
            "seed_manifest_sha256": ledger.raw_sha256(base["seed_raw"]),
            "seed_key": seed_document["seed_key"],
            "workspace_seed_digest": seed_document[
                "workspace_seed_digest"],
            "database_dump_digest": "no_database",
            "container_image_digest": image,
            "harness_version": HARNESS_VERSION,
            "needs_database": False,
            "docker_execution_authority": authority_ref,
            "docker_execution_binding": binding_refs[index],
        }
        runtime_path = worker.runtime_attestation_path(spec_paths[index])
        runtime_raw = _write(runtime_path, runtime_document, indent=1)
        identity = {
            "schema": ledger.RUNTIME_IDENTITY_SCHEMA,
            "docker_execution_authority": authority_ref,
            "docker_execution_binding": binding_refs[index],
            "docker_daemon_fingerprint_sha256": base["authority"]["daemon"][
                "fingerprint_sha256"],
            "docker_execution_pool_digest": pool["digest"],
            "worker_index": index,
            "worker_spec_path": spec_paths[index],
            "worker_spec_sha256": ledger.raw_sha256(spec_raws[index]),
            "container_image_digest": image,
            "seed_dir": os.path.dirname(base["seed_path"]),
            "seed_manifest": _raw_ref(base["seed_path"], base["seed_raw"]),
            "seed_key": seed_document["seed_key"],
            "workspace_seed_digest": seed_document[
                "workspace_seed_digest"],
            "database_dump_digest": "no_database",
            "needs_database": False, "harness": harness,
            "digest": "0" * 64,
        }
        identity["digest"] = ledger.semantic_digest(identity)
        runtime_references.append({
            "path": runtime_path,
            "file_sha256": ledger.raw_sha256(runtime_raw),
            "identity": identity,
        })
        runtime_paths.append(runtime_path)
        runtime_documents.append(runtime_document)

    campaign_document = copy.deepcopy(
        ledger.loads_exact_json(base["campaign_raw"], label="campaign"))
    campaign_document["k_workers"] = 2
    campaign_document["campaign_id"] = "ledger-I4-é-\U00010000"
    campaign_raw = _write(base["campaign_path"], campaign_document, indent=1)
    campaign_ref = _raw_ref(base["campaign_path"], campaign_raw)
    campaign_ref.update({
        "campaign_digest": campaign.campaign_digest(campaign_document),
        "semantic_digest": ledger.semantic_digest(campaign_document),
    })
    agent_runtime_path = base["campaign_path"] + ".agent_runtime.json"
    agent_runtime_raw = ledger.read_trusted_bytes(
        agent_runtime_path, label="agent runtime")
    agent_runtime_document = ledger.loads_exact_json(
        agent_runtime_raw, label="agent runtime")
    agent_runtime_ref = _raw_ref(agent_runtime_path, agent_runtime_raw)
    agent_runtime_ref["agent_runtime_sha256"] = (
        campaign.agent_runtime_digest(agent_runtime_document))
    boundary_ref = copy.deepcopy(base["receipt"]["plan"]["boundary"])
    profile_ref = copy.deepcopy(base["receipt"]["plan"]["profile"])
    strip_entry = _input(
        "harness_strip_manifest", "strip_manifest.json", base["strip_path"])

    source_documents = []
    source_paths = []
    result_rows = {}
    for index in range(2):
        selected_ids = [
            item_id for item_id in release_ids
            if campaign.shard_of(item_id, 2) == index]
        if len(selected_ids) != 2:
            raise AssertionError("fixture must assign exactly two items/shard")
        stamp = {
            name: base["result_row"][name]
            for name in ledger.RUN_STAMP_NAMES
        }
        stamp.update({
            "campaign_digest": campaign_ref["campaign_digest"],
            "of": 2, "shard": index,
        })
        files = sorted([
            copy.deepcopy(strip_entry),
            _input(
                "harness_feature", logical_feature,
                workspaces[index] + "/" + logical_feature),
        ], key=lambda entry: (
            entry["role"], entry["logical_path"], entry["path"]))
        invocation = {
            "schema": ledger.RUN_INVOCATION_SCHEMA,
            "selection": {"limit": None, "requested_item_ids": None},
            "effective_run_stamp": _named(stamp),
            "adapter": {
                "kind": "empty", "name": "empty",
                "public_configuration": [], "secret_inputs": [],
                "files": files,
            },
            "resume": {
                "checkpoint_resume": True,
                "stale_running_suffix_adoption": True,
                "no_resume": False, "retry_failed": False,
            },
        }
        plan = {
            "schema": ledger.RUN_PLAN_SCHEMA,
            "campaign": campaign_ref,
            "campaign_agent_runtime": agent_runtime_ref,
            "release": _raw_ref(release_path, release_raw),
            "boundary": boundary_ref, "profile": profile_ref,
            "protocol": None,
            "worker_manifest_path": manifest_paths[index],
            "shard_index": index, "shard_count": 2,
            "shard_rule": campaign.SHARD_RULE,
            "workset": {
                "item_count": len(selected_ids),
                "ordered_item_ids_digest":
                    ledger.ordered_item_ids_digest(selected_ids),
            },
            "invocation": invocation,
            "invocation_digest": ledger.domain_digest(
                ledger.RUN_INVOCATION_SCHEMA, invocation),
            "digest": "0" * 64,
        }
        plan["digest"] = ledger.semantic_digest(plan)
        rows = []
        for ordinal, item_id in enumerate(selected_ids):
            row = {
                "item_id": item_id, "outcome": "passed",
                "scientific": {
                    "worker": index, "ordinal": ordinal,
                    "unicode": "é/Ω/中",
                    "values": [index, ordinal, True, None]},
                "wall_seconds": index + ordinal + 0.125,
                **stamp,
            }
            rows.append(row)
            result_rows[item_id] = row
        result_raw = b"".join(
            (json.dumps(
                row, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
            for row in rows)
        _write(result_paths[index], result_raw, raw=True)
        result = {
            "path": result_paths[index], "byte_length": len(result_raw),
            "row_count": len(rows),
            "file_sha256": ledger.raw_sha256(result_raw),
        }
        manifest_document = {
            "campaign": campaign_document,
            "campaign_digest": campaign_ref["campaign_digest"],
            "worker": campaign.WorkerManifest(
                shard=index, workspace=workspaces[index],
                container=specs[index].container, schema="", credential="",
                out_path=result_paths[index],
                artifacts_root=artifacts[index],
                started_at=f"2026-08-08T00:0{index}:00Z",
                finished_at=f"2026-08-08T00:0{index}:59Z",
                campaign_digest=campaign_ref["campaign_digest"]).to_json(),
        }
        manifest_raw = _write(
            manifest_paths[index], manifest_document, indent=1)
        receipt = {
            "schema": ledger.RECEIPT_SCHEMA,
            "artifact_kind": "run_shard",
            "execution": {
                "attempt_id": campaign_document["attempt_id"],
                "runtime": runtime_references[index],
            },
            "plan": plan, "result": result,
            "worker_manifest": _raw_ref(
                manifest_paths[index], manifest_raw),
            "digest": "0" * 64,
        }
        receipt["digest"] = ledger.semantic_digest(receipt)
        receipt_path = result_paths[index] + ledger.RECEIPT_SUFFIX
        _write(receipt_path, receipt, indent=1)
        source_documents.append(receipt)
        source_paths.append(receipt_path)

    return {
        "temporary": temporary, "root": root, "base": base,
        "source_paths": source_paths, "source_documents": source_documents,
        "result_paths": result_paths, "manifest_paths": manifest_paths,
        "runtime_paths": runtime_paths, "runtime_documents": runtime_documents,
        "bindings": bindings, "binding_refs": binding_refs,
        "specs": specs, "spec_paths": spec_paths,
        "campaign": campaign_document, "campaign_ref": campaign_ref,
        "release_path": release_path, "release_raw": release_raw,
        "release_ids": release_ids, "release_rows": release_rows,
        "expected_codepoint_order": expected_codepoint_order,
        "result_rows": result_rows, "logical_feature": logical_feature,
        "workspaces": workspaces,
    }


def _refused(callable_) -> bool:
    try:
        callable_()
    except (SystemExit, ledger.ResultLedgerRefused, ValueError, RuntimeError):
        return True
    return False


def _read(path: str) -> bytes:
    return ledger.read_trusted_bytes(path, label="I4 selftest evidence")


def _resign(document: dict) -> None:
    document["digest"] = ledger.semantic_digest(document)


def _capture_main(argv: list[str]) -> tuple[int, bytes, bytes]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = 0
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            code = cli.main(argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    return code, stdout.getvalue().encode(), stderr.getvalue().encode()


def _verified_sources(fixture: dict):
    reader = ledger._LiveReader()
    sources = ledger._load_source_paths(reader, fixture["source_paths"])
    reader.confirm()
    return sources


def _write_source_receipt(fixture: dict, index: int, document: dict) -> None:
    _resign(document)
    _write(fixture["source_paths"][index], document, indent=1)
    fixture["source_documents"][index] = document


def _replace_binding_snapshot(fixture: dict, index: int, mutate) -> None:
    """Rewrite and re-sign the complete binding -> runtime -> receipt chain."""
    binding = copy.deepcopy(fixture["bindings"][index])
    mutate(binding)
    _resign(binding)
    authority.validate_binding_document(binding)
    binding_path = fixture["binding_refs"][index]["path"]
    binding_raw = _write(binding_path, binding, indent=1)
    binding_ref = _raw_ref(binding_path, binding_raw)
    binding_ref["digest"] = binding["digest"]

    runtime_document = copy.deepcopy(fixture["runtime_documents"][index])
    runtime_document["docker_execution_binding"] = binding_ref
    runtime_raw = _write(
        fixture["runtime_paths"][index], runtime_document, indent=1)

    receipt = copy.deepcopy(fixture["source_documents"][index])
    runtime_reference = receipt["execution"]["runtime"]
    runtime_reference["file_sha256"] = ledger.raw_sha256(runtime_raw)
    identity = runtime_reference["identity"]
    identity["docker_execution_binding"] = binding_ref
    _resign(identity)
    _write_source_receipt(fixture, index, receipt)

    fixture["bindings"][index] = binding
    fixture["binding_refs"][index] = binding_ref
    fixture["runtime_documents"][index] = runtime_document


def _replace_source_result(
        fixture: dict, index: int, raw: bytes, row_count: int) -> None:
    _write(fixture["result_paths"][index], raw, raw=True)
    document = copy.deepcopy(fixture["source_documents"][index])
    document["result"].update({
        "byte_length": len(raw), "row_count": row_count,
        "file_sha256": ledger.raw_sha256(raw),
    })
    _write_source_receipt(fixture, index, document)


def _scope_sources(
        fixture: dict, *, requested: list[str] | None,
        limit: int | None) -> list[str]:
    release_ids = fixture["release_ids"]
    wanted = set(release_ids if requested is None else requested)
    scoped = []
    for index in range(2):
        document = copy.deepcopy(fixture["source_documents"][index])
        plan = document["plan"]
        plan["invocation"]["selection"] = {
            "limit": limit,
            "requested_item_ids": (
                None if requested is None else sorted(requested)),
        }
        selected = [
            item_id for item_id in release_ids
            if item_id in wanted and campaign.shard_of(item_id, 2) == index]
        if limit is not None:
            selected = selected[:limit]
        scoped.extend(selected)
        plan["invocation"]["adapter"]["files"] = [
            entry for entry in plan["invocation"]["adapter"]["files"]
            if entry["role"] != "harness_feature" or selected]
        plan["workset"] = {
            "item_count": len(selected),
            "ordered_item_ids_digest": ledger.ordered_item_ids_digest(
                selected),
        }
        plan["invocation_digest"] = ledger.domain_digest(
            ledger.RUN_INVOCATION_SCHEMA, plan["invocation"])
        plan["digest"] = ledger.semantic_digest(plan)
        rows = [fixture["result_rows"][item_id] for item_id in selected]
        raw = b"".join(
            (json.dumps(
                row, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False) + "\n").encode()
            for row in rows)
        _write(fixture["result_paths"][index], raw, raw=True)
        document["plan"] = plan
        document["result"].update({
            "byte_length": len(raw), "row_count": len(rows),
            "file_sha256": ledger.raw_sha256(raw),
        })
        _write_source_receipt(fixture, index, document)
    selected_set = set(scoped)
    return [item_id for item_id in release_ids if item_id in selected_set]


def _mutated_sources_refuse(fixture: dict, mutate) -> bool:
    sources = copy.deepcopy(_verified_sources(fixture))
    mutate(sources)
    return _refused(lambda: ledger._verify_merge_sources(sources))


def selftest() -> int:
    failures = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        if condition:
            print(f"  [PASS] {name}")
        else:
            failures.append(name + (f": {detail}" if detail else ""))
            print(f"  [FAIL] {name}" + (f" -- {detail}" if detail else ""))

    fixture = _fixture()
    root = fixture["root"]
    out_a = root + "/merged/a/strict.jsonl"
    out_b = root + "/merged/b/strict.jsonl"
    first = campaign.merge_publication_v3(
        list(reversed(fixture["source_paths"])),
        release_path=fixture["release_path"], out_path=out_a,
        expected_shards=2)
    second = campaign.merge_publication_v3(
        fixture["source_paths"], release_path=fixture["release_path"],
        out_path=out_b, expected_shards=2)
    receipt_a = ledger.loads_exact_json(
        _read(out_a + ledger.RECEIPT_SUFFIX), label="merged receipt")
    expected_rows = [
        fixture["result_rows"][item_id]
        for item_id in fixture["expected_codepoint_order"]]
    independent_expected_raw = b"".join(
        (json.dumps(
            row, sort_keys=True, ensure_ascii=True, allow_nan=False,
            separators=(", ", ": ")) + "\n").encode("utf-8")
        for row in expected_rows)
    check(
        "all-valid merge recursively verifies and canonicalizes source order",
        first["complete"] and second["complete"]
        and receipt_a["source_receipts"][0]["worker_index"] == 0
        and receipt_a["source_receipts"][1]["worker_index"] == 1
        and _read(out_a) == independent_expected_raw)
    check(
        "source CLI order cannot affect merged result or sidecar bytes",
        _read(out_a) == _read(out_b)
        and _read(out_a + ".campaign.json")
        == _read(out_b + ".campaign.json"))
    check(
        "Unicode item ordering and complete payload values are preserved",
        [row["item_id"] for row in ledger._json_lines(
            _read(out_a), "merged rows")]
        == fixture["expected_codepoint_order"]
        and fixture["expected_codepoint_order"].index("python-docx/\ue000-bmp")
        < fixture["expected_codepoint_order"].index(
            "python-docx/\U00010000-astral")
        and b"python-docx/\\ue000-bmp" in _read(out_a)
        and b"python-docx/\\ud800\\udc00-astral" in _read(out_a)
        and all(row["scientific"]["unicode"] == "é/Ω/中"
                for row in ledger._json_lines(_read(out_a), "merged rows")))

    before = {
        path: (os.lstat(path), _read(path))
        for path in (out_a, out_a + ".campaign.json",
                     out_a + ledger.RECEIPT_SUFFIX)
    }
    already = campaign.merge_publication_v3(
        fixture["source_paths"], release_path=fixture["release_path"],
        out_path=out_a, expected_shards=2)
    check(
        "valid existing merged receipt is idempotent and read-only",
        already["already_complete"] is True and all(
            ledger._stat_identity(os.lstat(path))
            == ledger._stat_identity(before[path][0])
            and _read(path) == before[path][1] for path in before))

    extra_fixture = _fixture()
    extra_complete = ledger.verify_receipt(
        extra_fixture["source_paths"][0])["complete"]
    check(
        "duplicate, missing, extra, and mixed source receipts refuse",
        _refused(lambda: campaign.merge_publication_v3(
            [fixture["source_paths"][0]] * 2,
            release_path=fixture["release_path"],
            out_path=root + "/merged/duplicate.jsonl", expected_shards=2))
        and _refused(lambda: campaign.merge_publication_v3(
            fixture["source_paths"][:1],
            release_path=fixture["release_path"],
            out_path=root + "/merged/missing.jsonl", expected_shards=2))
        and _refused(lambda: campaign.merge_publication_v3(
            fixture["source_paths"] + [extra_fixture["source_paths"][0]],
            release_path=fixture["release_path"],
            out_path=root + "/merged/extra.jsonl", expected_shards=2))
        and _refused(lambda: campaign.merge_publication_v3(
            [fixture["source_paths"][0],
             out_a + ledger.RECEIPT_SUFFIX],
            release_path=fixture["release_path"],
            out_path=root + "/merged/mixed.jsonl", expected_shards=2))
        and extra_complete)
    extra_fixture["temporary"].cleanup()

    copied_path = root + "/runs/copied.result-ledger.json"
    _write(copied_path, _read(fixture["source_paths"][0]), raw=True)
    check(
        "copying a receipt to another path cannot create another shard",
        _refused(lambda: campaign.merge_publication_v3(
            [copied_path, fixture["source_paths"][1]],
            release_path=fixture["release_path"],
            out_path=root + "/merged/copied.jsonl", expected_shards=2)))

    # Output-lock collision must be found while the release is still only a
    # stable-read input; opening it as a lock would change neither bytes nor
    # inode but would violate role separation and can deadlock readers.
    collision_out = fixture["release_path"][
        :-len(ledger.PUBLICATION_LOCK_SUFFIX)]
    release_before = (os.lstat(fixture["release_path"]),
                      _read(fixture["release_path"]))
    collision = _refused(lambda: campaign.merge_publication_v3(
        fixture["source_paths"], release_path=fixture["release_path"],
        out_path=collision_out, expected_shards=2))
    check(
        "derived result lock cannot alias trusted recursive evidence",
        collision
        and ledger._stat_identity(os.lstat(fixture["release_path"]))
        == ledger._stat_identity(release_before[0])
        and _read(fixture["release_path"]) == release_before[1]
        and not os.path.lexists(collision_out))

    # ------------------------------------------------ exact source JSONL
    source_fixture = _fixture()
    original_source_result = _read(source_fixture["result_paths"][0])
    original_source_receipt = copy.deepcopy(
        source_fixture["source_documents"][0])
    original_rows = ledger._json_lines(
        original_source_result, "original source rows")
    source_variants = [
        (b"{\"item_id\":\"x\"", 1),
        (b"{bad}\n", 1),
        (b"{\"item_id\":\"x\",\"item_id\":\"y\"}\n", 1),
        (b"{\"item_id\":\"x\",\"value\":NaN}\n", 1),
        (b"\n", 1),
        (original_source_result.replace(b"\n", b"\r\n"),
         len(original_rows)),
        (original_source_result[:-1], len(original_rows)),
        (b"".join(
            (json.dumps(row, sort_keys=True) + "\n").encode()
            for row in reversed(original_rows)), len(original_rows)),
        ((json.dumps(original_rows[0], sort_keys=True) + "\n"
          + json.dumps(original_rows[0], sort_keys=True) + "\n").encode(),
         2),
    ]
    grammar_refuses = True
    for number, (raw, row_count) in enumerate(source_variants):
        _replace_source_result(source_fixture, 0, raw, row_count)
        grammar_refuses = grammar_refuses and _refused(
            lambda number=number: ledger.prepare_publication_merge(
                source_fixture["source_paths"],
                release_path=source_fixture["release_path"],
                result_path=source_fixture["root"]
                + f"/merged/source-grammar-{number}.jsonl",
                expected_shards=2))
        _write(
            source_fixture["result_paths"][0], original_source_result,
            raw=True)
        source_fixture["source_documents"][0] = copy.deepcopy(
            original_source_receipt)
        _write(
            source_fixture["source_paths"][0], original_source_receipt,
            indent=1)
    wrong_shard_rows = copy.deepcopy(original_rows)
    wrong_shard_rows[0]["shard"] = 1
    wrong_shard_raw = b"".join(
        (json.dumps(row, sort_keys=True) + "\n").encode()
        for row in wrong_shard_rows)
    _replace_source_result(
        source_fixture, 0, wrong_shard_raw, len(wrong_shard_rows))
    wrong_shard = _refused(lambda: ledger.prepare_publication_merge(
        source_fixture["source_paths"],
        release_path=source_fixture["release_path"],
        result_path=source_fixture["root"] + "/merged/wrong-shard.jsonl",
        expected_shards=2))
    _write(source_fixture["result_paths"][0], original_source_result, raw=True)
    source_fixture["source_documents"][0] = copy.deepcopy(
        original_source_receipt)
    _write(source_fixture["source_paths"][0], original_source_receipt, indent=1)
    outside_rows = copy.deepcopy(original_rows)
    outside_rows[0]["item_id"] = "python-docx/out-of-workset"
    outside_raw = b"".join(
        (json.dumps(row, sort_keys=True) + "\n").encode()
        for row in outside_rows)
    _replace_source_result(
        source_fixture, 0, outside_raw, len(outside_rows))
    outside = _refused(lambda: ledger.prepare_publication_merge(
        source_fixture["source_paths"],
        release_path=source_fixture["release_path"],
        result_path=source_fixture["root"] + "/merged/outside.jsonl",
        expected_shards=2))
    check(
        "source JSONL refuses torn/blank/CRLF/duplicate-key/nonfinite/"
        "malformed/no-LF/wrong-order/duplicate/wrong-shard/out-of-workset",
        grammar_refuses and wrong_shard and outside)
    source_fixture["temporary"].cleanup()

    # ------------------------------------------- source-entry exact identities
    merged_receipt_path = out_a + ledger.RECEIPT_SUFFIX
    merged_receipt_raw = _read(merged_receipt_path)
    merged_receipt = ledger.loads_exact_json(
        merged_receipt_raw, label="merged receipt mutation base")
    entry_mutations = []
    entry_mutations.append(lambda doc: doc["source_receipts"].reverse())
    entry_mutations.extend([
        lambda doc, key=key: doc["source_receipts"][0].__setitem__(
            key, (1 if key == "worker_index" else "0" * 64))
        for key in ("worker_index", "receipt_file_sha256", "receipt_digest",
                    "source_result_file_sha256")
    ])
    entry_mutations.append(
        lambda doc: doc["source_receipts"][0].__setitem__(
            "receipt_path", doc["source_receipts"][1]["receipt_path"]))
    entry_refuses = True
    for mutate in entry_mutations:
        candidate = copy.deepcopy(merged_receipt)
        mutate(candidate)
        _resign(candidate)
        _write(merged_receipt_path, candidate, indent=1)
        entry_refuses = entry_refuses and _refused(
            lambda: ledger.verify_receipt(merged_receipt_path))
    _write(merged_receipt_path, merged_receipt_raw, raw=True)
    check(
        "reordered/wrong worker, receipt, result hash/path/digest identities refuse",
        entry_refuses and ledger.verify_receipt(
            merged_receipt_path)["complete"])

    copied_sources = copy.deepcopy(_verified_sources(fixture))
    synthetic_copy = copy.deepcopy(copied_sources[0])
    synthetic_copy.receipt_path += ".independent"
    synthetic_copy.document["digest"] = "f" * 64
    synthetic_copy.document["result"]["path"] += ".independent"
    synthetic_copy.document["result"]["file_sha256"] = "e" * 64
    copied_sources[1] = synthetic_copy
    check(
        "copied raw receipt hash uniqueness is enforced independently",
        _refused(lambda: ledger._verify_source_identity_uniqueness(
            copied_sources)))

    # -------------------------------------- merged row value and exact grammar
    merged_result_raw = _read(out_a)
    merged_rows = ledger._json_lines(merged_result_raw, "merged mutation base")
    result_variants = []
    changed_payload = copy.deepcopy(merged_rows)
    changed_payload[0]["scientific"]["values"][0] = 999
    result_variants.append(ledger._merged_rows_bytes(changed_payload))
    result_variants.append(ledger._merged_rows_bytes(list(reversed(merged_rows))))
    result_variants.append(merged_result_raw.replace(b'": ', b'":', 1))
    result_variants.append(b"".join(
        (json.dumps(
            row, sort_keys=True, ensure_ascii=False, allow_nan=False,
            separators=(", ", ": ")) + "\n").encode("utf-8")
        for row in merged_rows))
    result_variants.extend([
        merged_result_raw[:-1],
        merged_result_raw.replace(b"\n", b"\r\n"),
        b"\n" + merged_result_raw,
        b'{"item_id":"x","item_id":"y"}\n',
        b'{"item_id":"x","value":Infinity}\n',
        b'{"item_id":"x","value":1e}\n',
        b'{"item_id":"x","value":01}\n',
    ])
    result_refuses = True
    for raw in result_variants:
        candidate = copy.deepcopy(merged_receipt)
        _write(out_a, raw, raw=True)
        candidate["result"].update({
            "byte_length": len(raw),
            "row_count": len(merged_rows),
            "file_sha256": ledger.raw_sha256(raw),
        })
        reclosed_sidecar = copy.deepcopy(sidecar := ledger.loads_exact_json(
            _read(out_a + ".campaign.json"), label="reclosed sidecar"))
        reclosed_sidecar["rows_digest"] = ledger.raw_sha256(raw)[:16]
        reclosed_sidecar_raw = ledger._campaign_sidecar_bytes(reclosed_sidecar)
        _write(out_a + ".campaign.json", reclosed_sidecar_raw, raw=True)
        candidate["campaign_sidecar"]["file_sha256"] = (
            ledger.raw_sha256(reclosed_sidecar_raw))
        _resign(candidate)
        _write(merged_receipt_path, candidate, indent=1)
        result_refuses = result_refuses and _refused(
            lambda: ledger.verify_receipt(merged_receipt_path))
    _write(out_a, merged_result_raw, raw=True)
    # Restore from the independently published order-invariant peer, whose
    # sidecar has the same basename and therefore exact same bytes.
    _write(out_a + ".campaign.json", _read(out_b + ".campaign.json"), raw=True)
    _write(merged_receipt_path, merged_receipt_raw, raw=True)
    check(
        "merged rows refuse item-ID-only equality, payload drift, ordering, "
        "whitespace, torn, blank, CRLF, duplicate-key, and nonfinite bytes",
        result_refuses and ledger.verify_receipt(
            merged_receipt_path)["complete"])

    # -------------------------------------- exact closed campaign sidecar
    sidecar_path = out_a + ".campaign.json"
    sidecar_raw = _read(sidecar_path)
    sidecar = ledger.loads_exact_json(sidecar_raw, label="sidecar mutation base")
    sidecar_values = []
    for key, value in (
            ("campaign_digest", "0" * 16), ("n", 0),
            ("rows_path", "other.jsonl"), ("rows_digest", "0" * 16)):
        candidate = copy.deepcopy(sidecar)
        candidate[key] = value
        sidecar_values.append(ledger._campaign_sidecar_bytes(candidate))
    reordered_workers = copy.deepcopy(sidecar)
    reordered_workers["workers"].reverse()
    sidecar_values.append(ledger._campaign_sidecar_bytes(reordered_workers))
    changed_campaign = copy.deepcopy(sidecar)
    changed_campaign["campaign"]["campaign_id"] = "another campaign"
    sidecar_values.append(ledger._campaign_sidecar_bytes(changed_campaign))
    for field in campaign.WORKER_FIELDS:
        changed_worker = copy.deepcopy(sidecar)
        changed_worker["workers"][0][field] = (
            1 if field == "shard" else "changed")
        sidecar_values.append(ledger._campaign_sidecar_bytes(changed_worker))
    extra_sidecar = copy.deepcopy(sidecar)
    extra_sidecar["extra"] = True
    sidecar_values.append(ledger._campaign_sidecar_bytes(extra_sidecar))
    sidecar_values.extend([
        (json.dumps(sidecar, sort_keys=True, indent=1) + "\n").encode(),
        (json.dumps(
            sidecar, sort_keys=True, indent=2,
            ensure_ascii=False) + "\n").encode("utf-8"),
        sidecar_raw[:-1], sidecar_raw + b"\n",
        b'{"campaign":{},"n":1e}\n',
        b'{"campaign":{},"n":01}\n',
    ])
    sidecar_refuses = True
    for raw in sidecar_values:
        candidate_receipt = copy.deepcopy(merged_receipt)
        _write(sidecar_path, raw, raw=True)
        candidate_receipt["campaign_sidecar"]["file_sha256"] = (
            ledger.raw_sha256(raw))
        _resign(candidate_receipt)
        _write(merged_receipt_path, candidate_receipt, indent=1)
        sidecar_refuses = sidecar_refuses and _refused(
            lambda: ledger.verify_receipt(merged_receipt_path))
    wrong_sidecar_path = out_a + ".wrong-campaign.json"
    _write(wrong_sidecar_path, sidecar_raw, raw=True)
    candidate_receipt = copy.deepcopy(merged_receipt)
    candidate_receipt["campaign_sidecar"] = _raw_ref(
        wrong_sidecar_path, sidecar_raw)
    _resign(candidate_receipt)
    _write(merged_receipt_path, candidate_receipt, indent=1)
    sidecar_refuses = sidecar_refuses and _refused(
        lambda: ledger.verify_receipt(merged_receipt_path))
    _write(sidecar_path, sidecar_raw, raw=True)
    _write(merged_receipt_path, merged_receipt_raw, raw=True)
    check(
        "every sidecar field/order/path/digest/whitespace/newline mutation refuses",
        sidecar_refuses and ledger.verify_receipt(
            merged_receipt_path)["complete"])

    # -------------------------------- common plan/runtime/resource joins
    plan_mutations = [
        lambda sources: sources[1].document["plan"]["campaign"].__setitem__(
            "semantic_digest", "0" * 64),
        lambda sources: sources[1].document["plan"][
            "campaign_agent_runtime"].__setitem__("path", "/different"),
        lambda sources: sources[1].document["plan"]["release"].__setitem__(
            "path", "/different"),
        lambda sources: sources[1].document["plan"]["boundary"].__setitem__(
            "path", "/different"),
        lambda sources: sources[1].document["plan"]["profile"].__setitem__(
            "path", "/different"),
        lambda sources: sources[1].document["plan"].__setitem__(
            "protocol", {"path": "/different", "file_sha256": "0" * 64}),
        lambda sources: sources[1].document["plan"].__setitem__(
            "shard_count", 3),
        lambda sources: sources[1].document["plan"].__setitem__(
            "shard_rule", "different"),
        lambda sources: sources[1].document["plan"]["invocation"].__setitem__(
            "selection", {"limit": None,
                          "requested_item_ids": sorted(fixture["release_ids"])}),
        lambda sources: sources[1].document["plan"]["invocation"][
            "adapter"].__setitem__("kind", "stub"),
        lambda sources: sources[1].document["plan"]["invocation"][
            "adapter"].__setitem__("public_configuration", [{
                "name": "x", "value_json": "null"}]),
        lambda sources: sources[1].document["plan"]["invocation"][
            "adapter"].__setitem__("secret_inputs", ["x"]),
        lambda sources: sources[1].document["plan"]["invocation"][
            "resume"].__setitem__("no_resume", True),
        lambda sources: sources[1].document["plan"]["invocation"][
            "effective_run_stamp"][0].__setitem__("value_json", "false"),
    ]
    check(
        "common plan forbids every undocumented shard-local delta",
        all(_mutated_sources_refuse(fixture, mutate)
            for mutate in plan_mutations))

    runtime_mutations = [
        lambda sources: sources[1].document["execution"].__setitem__(
            "attempt_id", "different-attempt"),
        lambda sources: sources[1].runtime.authority["daemon"].__setitem__(
            "fingerprint_sha256", "0" * 64),
        lambda sources: sources[1].runtime.pool.__setitem__(
            "digest", "0" * 64),
        lambda sources: sources[1].runtime.identity.__setitem__(
            "container_image_digest", "sha256:" + "0" * 64),
        lambda sources: sources[1].runtime.identity.__setitem__(
            "workspace_seed_digest", "0" * 64),
        lambda sources: sources[1].runtime.identity["harness"].__setitem__(
            "version", HARNESS_VERSION + 1),
        lambda sources: sources[1].document["execution"]["runtime"][
            "identity"]["docker_execution_authority"].__setitem__(
                "path", "/different"),
    ]
    check(
        "attempt/authority/daemon/pool/image/seed/harness-version joins are "
        "direct",
        all(_mutated_sources_refuse(fixture, mutate)
            for mutate in runtime_mutations))

    # SECTION 16: shard 1 opened at another commit than shard 0 -- its
    # recorded harness pair, its plan stamp and its rows all name that
    # commit -- still merges, and the merged receipt lists both commits.
    moved_fixture = _fixture()
    moved_document = copy.deepcopy(moved_fixture["source_documents"][1])
    moved_identity = moved_document["execution"]["runtime"]["identity"]
    moved_identity["harness"]["git_commit"] = "f" * 40
    moved_identity["harness"]["source_sha256"] = "f" * 64
    _resign(moved_identity)
    moved_plan = moved_document["plan"]
    for entry in moved_plan["invocation"]["effective_run_stamp"]:
        if entry["name"] == "harness_commit":
            entry["value_json"] = json.dumps("fffffff")
    moved_plan["invocation_digest"] = ledger.domain_digest(
        ledger.RUN_INVOCATION_SCHEMA, moved_plan["invocation"])
    _resign(moved_plan)
    _write_source_receipt(moved_fixture, 1, moved_document)
    moved_rows = [
        dict(moved_fixture["result_rows"][item_id], harness_commit="fffffff")
        for item_id in moved_fixture["release_ids"]
        if campaign.shard_of(item_id, 2) == 1]
    _replace_source_result(
        moved_fixture, 1,
        b"".join((json.dumps(
            row, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False) + "\n").encode("utf-8") for row in moved_rows),
        len(moved_rows))
    moved_out = moved_fixture["root"] + "/merged/moved.jsonl"
    moved_stderr = io.StringIO()
    with contextlib.redirect_stderr(moved_stderr):
        moved_source_verified = ledger.verify_receipt(
            moved_fixture["source_paths"][1])
        campaign.merge_publication_v3(
            moved_fixture["source_paths"],
            release_path=moved_fixture["release_path"],
            out_path=moved_out, expected_shards=2)
        moved_verified = ledger.verify_receipt(
            moved_out + ledger.RECEIPT_SUFFIX)
    shard0_commit = moved_fixture["result_rows"][
        moved_fixture["release_ids"][0]]["harness_commit"]
    expected_commits = sorted({shard0_commit, "fffffff"} - {None})
    check("a shard opened at another commit verifies with a drift note, "
          "merges, and the merged receipt lists every row commit",
          moved_source_verified["verified"]
          and moved_source_verified["row_harness_commits"] == ["fffffff"]
          and moved_verified["verified"]
          and moved_verified["row_harness_commits"] == expected_commits
          and "note: harness recorded at" in moved_stderr.getvalue()
          and ("rows carry 2 harness commits" in moved_stderr.getvalue())
          == (len(expected_commits) == 2),
          moved_stderr.getvalue()[:300])
    moved_fixture["temporary"].cleanup()

    def container_overlap(sources):
        value = sources[1].runtime.worker.to_json()
        value["container"] = sources[0].runtime.worker.container
        sources[1].runtime.worker = worker.WorkerSpec.from_json(value)

    path_fields = ("workspace", "env_file", "out_path", "artifacts_root")

    def path_overlap(left_field, right_field):
        def mutate(sources):
            value = sources[1].runtime.worker.to_json()
            value[right_field] = (
                getattr(sources[0].runtime.worker, left_field) + "/nested")
            sources[1].runtime.worker = worker.WorkerSpec.from_json(value)
        return mutate

    resource_mutations = [container_overlap] + [
        path_overlap(left_field, right_field)
        for left_field in path_fields for right_field in path_fields
    ]

    check(
        "container equality and every pairwise worker path-field overlap refuse",
        all(_mutated_sources_refuse(fixture, mutate)
            for mutate in resource_mutations))

    def changed_network_snapshot(binding):
        network_id = "8" * 64
        binding["network_policy"]["id"] = network_id
        for attachment in binding["container"]["network_attachments"]:
            attachment["id"] = network_id

    binding_snapshot_cases = (
        ("capture time", lambda binding: binding.__setitem__(
            "captured_at_utc", "2026-08-06T00:00:01Z")),
        ("network policy", changed_network_snapshot),
    )
    binding_snapshot_results = []
    for _label, mutate in binding_snapshot_cases:
        binding_fixture = _fixture()
        _replace_binding_snapshot(binding_fixture, 1, mutate)
        individually_valid = all(
            ledger.verify_receipt(path)["complete"]
            for path in binding_fixture["source_paths"])
        merge_refused = _refused(lambda: ledger.prepare_publication_merge(
            binding_fixture["source_paths"],
            release_path=binding_fixture["release_path"],
            result_path=binding_fixture["root"]
                + "/merged/binding-snapshot.jsonl",
            expected_shards=2))
        binding_snapshot_results.append(individually_valid and merge_refused)
        binding_fixture["temporary"].cleanup()
    check(
        "fully re-signed binding capture-time and network snapshots cannot mix",
        all(binding_snapshot_results))

    def logical_content(sources):
        entry = sources[1].context.adapter_files[
            ("harness_feature", fixture["logical_feature"])]
        entry["file_sha256"] = "0" * 64

    def logical_global_path(sources):
        sources[1].context.adapter_files[
            ("harness_strip_manifest", "strip_manifest.json")]["path"] \
            = "/different"

    def logical_missing(sources):
        for source in sources:
            del source.context.adapter_files[
                ("harness_feature", fixture["logical_feature"])]

    def logical_extra(sources):
        sources[1].context.adapter_files[("extra", "extra.txt")] = {
            "role": "extra", "logical_path": "extra.txt", "path": "/x",
            "byte_length": 0, "file_sha256": ledger.raw_sha256(b""),
        }

    def logical_union(sources):
        sources[1].context.adapter_expected_paths[("ghost", "ghost.txt")] \
            = "/ghost"

    check(
        "logical projection refuses missing/extra/content/global-path/union drift",
        all(_mutated_sources_refuse(fixture, mutate) for mutate in (
            logical_content, logical_global_path, logical_missing,
            logical_extra, logical_union)))

    cross_plan_fixture = _fixture()
    cross_document = copy.deepcopy(
        cross_plan_fixture["source_documents"][1])
    cross_plan = cross_document["plan"]
    cross_plan["invocation"]["selection"]["requested_item_ids"] = sorted(
        cross_plan_fixture["release_ids"])
    cross_plan["invocation_digest"] = ledger.domain_digest(
        ledger.RUN_INVOCATION_SCHEMA, cross_plan["invocation"])
    cross_plan["digest"] = ledger.semantic_digest(cross_plan)
    cross_document["plan"] = cross_plan
    _write_source_receipt(cross_plan_fixture, 1, cross_document)
    cross_individually_valid = ledger.verify_receipt(
        cross_plan_fixture["source_paths"][1])["complete"]
    cross_plan_refused = _refused(lambda: ledger.prepare_publication_merge(
        cross_plan_fixture["source_paths"],
        release_path=cross_plan_fixture["release_path"],
        result_path=cross_plan_fixture["root"] + "/merged/cross-plan.jsonl",
        expected_shards=2))
    check(
        "individually valid equal-workset sources still require exact selection",
        cross_individually_valid and cross_plan_refused)
    cross_plan_fixture["temporary"].cleanup()

    content_fixture = _fixture()
    changed_feature = b"Feature: distinct worker bytes\n"
    changed_feature_path = content_fixture["workspaces"][1] \
        + "/" + content_fixture["logical_feature"]
    _write(changed_feature_path, changed_feature, raw=True)
    content_document = copy.deepcopy(content_fixture["source_documents"][1])
    content_plan = content_document["plan"]
    feature_entry = next(
        entry for entry in content_plan["invocation"]["adapter"]["files"]
        if entry["role"] == "harness_feature")
    feature_entry.update({
        "byte_length": len(changed_feature),
        "file_sha256": ledger.raw_sha256(changed_feature),
    })
    content_plan["invocation_digest"] = ledger.domain_digest(
        ledger.RUN_INVOCATION_SCHEMA, content_plan["invocation"])
    content_plan["digest"] = ledger.semantic_digest(content_plan)
    content_document["plan"] = content_plan
    _write_source_receipt(content_fixture, 1, content_document)
    content_individually_valid = ledger.verify_receipt(
        content_fixture["source_paths"][1])["complete"]
    content_refused = _refused(lambda: ledger.prepare_publication_merge(
        content_fixture["source_paths"],
        release_path=content_fixture["release_path"],
        result_path=content_fixture["root"] + "/merged/content.jsonl",
        expected_shards=2))
    check(
        "individually valid distinct worker paths require equal logical bytes",
        content_individually_valid and content_refused)
    content_fixture["temporary"].cleanup()

    incompatible_fixture = _fixture()
    incompatible_sources = [
        fixture["source_paths"][0], incompatible_fixture["source_paths"][1]]
    check(
        "complete sources from incompatible campaigns/runtimes never mix",
        all(ledger.verify_receipt(path)["complete"]
            for path in incompatible_sources)
        and _refused(lambda: ledger.prepare_publication_merge(
            incompatible_sources, release_path=fixture["release_path"],
            result_path=root + "/merged/incompatible.jsonl",
            expected_shards=2)))
    incompatible_fixture["temporary"].cleanup()

    def wrong_workset_order(sources):
        sources[0].context.item_ids.reverse()

    def wrong_workset_item(sources):
        sources[0].context.item_ids[0] = "python-docx/not-selected"

    def wrong_worker_partition(sources):
        sources[0].context.item_ids[0] = sources[1].context.item_ids[0]

    check(
        "workset replay refuses wrong order, out-of-scope, and wrong-shard IDs",
        all(_mutated_sources_refuse(fixture, mutate) for mutate in (
            wrong_workset_order, wrong_workset_item,
            wrong_worker_partition)))

    # -------------------------------- requested subset and per-shard limit
    subset_fixture = _fixture()
    requested_id = subset_fixture["release_ids"][0]
    scoped_ids = _scope_sources(
        subset_fixture, requested=[requested_id], limit=None)
    subset_out = subset_fixture["root"] + "/merged/subset.jsonl"
    subset_info = campaign.merge_publication_v3(
        subset_fixture["source_paths"],
        release_path=subset_fixture["release_path"], out_path=subset_out,
        expected_shards=2)
    subset_receipt_raw = _read(subset_out + ledger.RECEIPT_SUFFIX)
    subset_receipt = ledger.loads_exact_json(
        subset_receipt_raw, label="subset receipt")
    subset_sidecar = ledger.loads_exact_json(
        _read(subset_out + ".campaign.json"), label="subset sidecar")
    check(
        "requested subset publishes its exact scoped merge workset",
        subset_info["row_count"] == 1 and scoped_ids == [requested_id]
        and subset_receipt["merge"]["expected_item_count"] == 1
        and subset_receipt["merge"]["ordered_item_ids_digest"]
        == ledger.ordered_item_ids_digest(scoped_ids)
        and subset_sidecar["n"] == 1)
    full_claim = copy.deepcopy(subset_receipt)
    full_claim["merge"]["expected_item_count"] = len(
        subset_fixture["release_ids"])
    full_claim["merge"]["ordered_item_ids_digest"] = (
        ledger.ordered_item_ids_digest(subset_fixture["release_ids"]))
    _resign(full_claim)
    _write(subset_out + ledger.RECEIPT_SUFFIX, full_claim, indent=1)
    check(
        "incomplete scoped union cannot be presented as a broader full claim",
        _refused(lambda: ledger.verify_receipt(
            subset_out + ledger.RECEIPT_SUFFIX)))
    subset_fixture["temporary"].cleanup()

    limit_fixture = _fixture()
    limited_ids = _scope_sources(limit_fixture, requested=None, limit=1)
    limit_out = limit_fixture["root"] + "/merged/limit.jsonl"
    limit_info = campaign.merge_publication_v3(
        limit_fixture["source_paths"],
        release_path=limit_fixture["release_path"], out_path=limit_out,
        expected_shards=2)
    limit_receipt = ledger.loads_exact_json(
        _read(limit_out + ledger.RECEIPT_SUFFIX), label="limit receipt")
    check(
        "per-shard limit replays before union and preserves release-order digest",
        len(limited_ids) == 2 and limit_info["row_count"] == 2
        and limit_receipt["merge"]["ordered_item_ids_digest"]
        == ledger.ordered_item_ids_digest(limited_ids)
        and [row["item_id"] for row in ledger._json_lines(
            _read(limit_out), "limited merged rows")] == sorted(limited_ids))
    limit_fixture["temporary"].cleanup()

    # ------------------------------------------ offline and both CLI routes
    old_capture = authority.capture_authority
    old_runtime = worker.validate_worker_runtime_v3
    old_pool = worker.validate_offline_worker_runtime_pool
    def forbidden_contact(*_args, **_kwargs):
        raise AssertionError("live Docker/daemon/pool contact")
    authority.capture_authority = forbidden_contact
    worker.validate_worker_runtime_v3 = forbidden_contact
    worker.validate_offline_worker_runtime_pool = forbidden_contact
    try:
        offline = ledger.verify_receipt(merged_receipt_path)
    finally:
        authority.capture_authority = old_capture
        worker.validate_worker_runtime_v3 = old_runtime
        worker.validate_offline_worker_runtime_pool = old_pool
    check(
        "merged verification remains complete with Docker/daemon/pool fatal",
        offline["complete"] and offline["artifact_kind"] == "merged_run")

    cli_pub_out = root + "/merged/cli-publication.jsonl"
    publication_argv = ["merge", "--publication-v3"]
    for source_path in reversed(fixture["source_paths"]):
        publication_argv.extend(["--source-receipt", source_path])
    publication_argv.extend([
        "--of", "2", "--release", fixture["release_path"],
        "--out", cli_pub_out])
    pub_code, pub_stdout, pub_stderr = _capture_main(publication_argv)
    pub_payload = ledger.loads_exact_json(pub_stdout, label="publication CLI")
    check(
        "explicit merge --publication-v3 CLI publishes only from receipts",
        pub_code == 0 and not pub_stderr
        and pub_payload["artifact_kind"] == "merged_run"
        and ledger.verify_receipt(
            cli_pub_out + ledger.RECEIPT_SUFFIX)["complete"])
    mixed_cli_out = root + "/merged/cli-mixed.jsonl"
    mixed_cli = _capture_main([
        "merge", "--publication-v3", "--manifest",
        fixture["manifest_paths"][0], "--source-receipt",
        fixture["source_paths"][0], "--source-receipt",
        fixture["source_paths"][1], "--of", "2", "--release",
        fixture["release_path"], "--out", mixed_cli_out])
    # I5 is the reviewed stage that opens these three consumers, so a bare
    # `--publication-v3` is no longer an argparse error here.  What remains
    # I4's own invariant is that its merge-only receipt option never reaches
    # a consumer and that an I4-shaped consumer request still renders nothing.
    unopened = [
        _capture_main(["report", "--run", "/x", "--publication-v3"]),
        _capture_main([
            "compare", "--run", "/a", "--run", "/b",
            "--publication-v3"]),
        _capture_main(["results", "--run", "/x", "--publication-v3"]),
    ]
    leaked = [
        _capture_main(["report", "--run", "/x", "--source-receipt", "/r"]),
        _capture_main([
            "compare", "--run", "/a", "--run", "/b",
            "--source-receipt", "/r"]),
        _capture_main(["results", "--run", "/x", "--source-receipt", "/r"]),
    ]
    check(
        "publication refuses manifests and I4's merge-only receipt option "
        "never reaches a consumer",
        mixed_cli[0] == 1 and not os.path.lexists(mixed_cli_out)
        and all(code != 0 and not stdout
                for code, stdout, _stderr in unopened)
        and all(code == 2 and b"unrecognized arguments: --source-receipt"
                in stderr for code, _stdout, stderr in leaked))

    help_result = _capture_main(["merge", "--help"])
    missing_result = _capture_main([
        "merge", "--of", "2", "--out", "/tmp/i4-default-missing"])
    unknown_result = _capture_main([
        "merge", "--manifest", "/m", "--source-receipt", "/x",
        "--of", "2", "--out", "/tmp/i4-default-unknown"])
    # argparse lays these out at the width `shutil.get_terminal_size()`
    # reports, and that reads `sys.__stdout__`, which `redirect_stdout` never
    # rebinds -- so the operator's real terminal decides where the lines
    # break.  Line breaks are not part of the CLI surface, so flatten the
    # whitespace before hashing, exactly as I5's parser pins do.
    def parser_bytes(raw: bytes) -> str:
        return hashlib.sha256(b"".join(raw.split())).hexdigest()

    # The unknown-option diagnostic's usage line lists the commands the
    # composer registered, in registration order (bench's first), so its
    # bytes have one value with the agent component's verbs on the menu and
    # another in the benchmark-only mirror, which ships no `agents/cli.py`.
    unknown_pin = (
        # Re-pinned for `target-regions` and `control-floors`, the two
        # toolkit verbs TARGET_INTERFACES_V2_SPEC 6.2/6.3 adds after
        # `stub-accept`, and for `checked-interfaces` beside `interfaces`
        # (section 14 step 2). `merge`'s own options and every other
        # command name and its registration order are unchanged.
        "8dfacaa194d733ae21c26bcb7b71eb151b436748c7c3a5c0397dc5dd2f584a3f"
        if cli.agents is not None else
        "9f678481e481a0877f956a1bd9473f86e9ab560fed9e95ec20b85177751988eb")
    parser_exact = (
        help_result[0] == 0
        and parser_bytes(help_result[1])
        == "f6ddfe2e057b8181a493a1d69c7d749d07340dfc551271f3d10d88cfc2c634f6"
        and help_result[2] == b""
        and missing_result[0] == 2
        and parser_bytes(missing_result[2])
        == "54def204f4b60d39a79143e5b9af894739db896233265b9a458f163b644b09fa"
        and unknown_result[0] == 2
        and parser_bytes(unknown_result[2]) == unknown_pin)
    check(
        "default merge help/missing diagnostics equal I3's CLI surface and "
        "its unknown-option diagnostic pins the current command set",
        parser_exact)

    default_out = root + "/merged/default.jsonl"
    default_adjacent_receipt = default_out + ledger.RECEIPT_SUFFIX
    _write(default_adjacent_receipt, b"legacy-adjacent-diagnostic\n", raw=True)
    default_argv = ["merge"]
    for manifest_path in fixture["manifest_paths"]:
        default_argv.extend(["--manifest", manifest_path])
    default_argv.extend([
        "--of", "2", "--release", fixture["release_path"],
        "--out", default_out])
    default_code, default_stdout, default_stderr = _capture_main(default_argv)
    expected_default_stdout = (json.dumps({
        "out": default_out, "n": len(fixture["release_ids"]),
        "campaign_digest": fixture["campaign_ref"]["campaign_digest"],
        "workers": 2,
    }, indent=1) + "\n").encode()
    expected_default_sidecar = (json.dumps({
        "campaign": fixture["campaign"],
        "campaign_digest": fixture["campaign_ref"]["campaign_digest"],
        "workers": [
            ledger.loads_exact_json(
                _read(path), label="default WorkerManifest")["worker"]
            for path in fixture["manifest_paths"]],
        "n": len(fixture["release_ids"]),
        "rows_path": os.path.basename(default_out),
        "rows_digest": ledger.raw_sha256(independent_expected_raw)[:16],
    }, sort_keys=True, indent=2) + "\n").encode()
    check(
        "default merge keeps exact legacy bytes/diagnostics and no v3 artifacts",
        default_code == 0 and not default_stderr
        and default_stdout == expected_default_stdout
        and _read(default_out) == independent_expected_raw
        and _read(default_out + ".campaign.json")
        == expected_default_sidecar
        and _read(default_adjacent_receipt)
        == b"legacy-adjacent-diagnostic\n"
        and not any(os.path.lexists(default_out + suffix) for suffix in (
            ledger.CHECKPOINT_SUFFIX, ledger.PUBLICATION_LOCK_SUFFIX)))

    # -------------------------------- durability, crashes, and no-clobber
    crash_events = (
        "merge:before_result_create",
        "merged result:stage_fsync",
        "merged result:commit",
        "merged result:directory_fsync",
        "merge:after_result_create",
        "merged campaign sidecar:stage_fsync",
        "merged campaign sidecar:commit",
        "merged campaign sidecar:directory_fsync",
        "merge:after_sidecar_create",
        "merge:after_receipt_selfverify",
        "merge:before_receipt_create",
        "merged result receipt:stage_fsync",
        "merged result receipt:commit",
        "merged result receipt:directory_fsync",
        "merge:after_receipt_create",
    )
    crash_matrix = True
    persistent_reuse = True
    crash_root = root + "/crashes"
    os.makedirs(crash_root, mode=0o700, exist_ok=True)
    for number, target in enumerate(crash_events):
        parent = crash_root + f"/{number:02d}"
        os.makedirs(parent, mode=0o700, exist_ok=True)
        out = parent + "/strict.jsonl"
        def crash(event, target=target):
            if event == target:
                raise RuntimeError(target)
        crashed = False
        try:
            campaign.merge_publication_v3(
                fixture["source_paths"],
                release_path=fixture["release_path"], out_path=out,
                expected_shards=2, fault=crash)
        except runner._PublicationInjectedCrash:
            crashed = True
        result_present = os.path.lexists(out)
        sidecar_present = os.path.lexists(out + ".campaign.json")
        receipt_present = os.path.lexists(out + ledger.RECEIPT_SUFFIX)
        if target in crash_events[:2]:
            expected = (False, False, False)
        elif target in crash_events[2:6]:
            expected = (True, False, False)
        elif target in crash_events[6:12]:
            expected = (True, True, False)
        else:
            expected = (True, True, True)
        crash_matrix = crash_matrix and crashed \
            and (result_present, sidecar_present, receipt_present) == expected
        lock_path = runner.publication_lock_path(out)
        lock_before = os.lstat(lock_path)
        if receipt_present:
            recovered = campaign.merge_publication_v3(
                fixture["source_paths"],
                release_path=fixture["release_path"], out_path=out,
                expected_shards=2)
            crash_matrix = crash_matrix \
                and recovered["already_complete"] is True \
                and ledger.verify_receipt(
                    out + ledger.RECEIPT_SUFFIX)["complete"]
        elif result_present or sidecar_present:
            saved = {
                path: _read(path) for path in (out, out + ".campaign.json")
                if os.path.lexists(path)}
            crash_matrix = crash_matrix and _refused(
                lambda out=out: campaign.merge_publication_v3(
                    fixture["source_paths"],
                    release_path=fixture["release_path"], out_path=out,
                    expected_shards=2)) \
                and all(_read(path) == raw for path, raw in saved.items())
        else:
            recovered = campaign.merge_publication_v3(
                fixture["source_paths"],
                release_path=fixture["release_path"], out_path=out,
                expected_shards=2)
            crash_matrix = crash_matrix and recovered["complete"]
        persistent_reuse = persistent_reuse \
            and ledger._stat_identity(os.lstat(lock_path)) \
            == ledger._stat_identity(lock_before)
        crash_matrix = crash_matrix and not any(
            name.startswith(".r2t-ledger-stage-")
            for name in os.listdir(parent))
    check(
        "every result/sidecar/receipt stage-fsync/commit/dir-fsync crash "
        "window is durable, no-clobber, and recoverable only as specified",
        crash_matrix)
    check(
        "persistent canonical result lock identity is reused across recovery",
        persistent_reuse)

    partial_checks = True
    for role in ("result", "sidecar", "checkpoint"):
        parent = root + f"/partial-{role}"
        os.makedirs(parent, mode=0o700, exist_ok=True)
        out = parent + "/strict.jsonl"
        path = {
            "result": out,
            "sidecar": out + ".campaign.json",
            "checkpoint": out + ledger.CHECKPOINT_SUFFIX,
        }[role]
        sentinel = f"preexisting-{role}".encode()
        _write(path, sentinel, raw=True)
        partial_checks = partial_checks and _refused(
            lambda out=out: campaign.merge_publication_v3(
                fixture["source_paths"], release_path=fixture["release_path"],
                out_path=out, expected_shards=2)) \
            and _read(path) == sentinel
    stale_parent = root + "/stale-receipt"
    os.makedirs(stale_parent, mode=0o700, exist_ok=True)
    stale_out = stale_parent + "/strict.jsonl"
    stale_path = stale_out + ledger.RECEIPT_SUFFIX
    _write(stale_path, b"stale-invalid-receipt\n", raw=True)
    partial_checks = partial_checks and _refused(
        lambda: campaign.merge_publication_v3(
            fixture["source_paths"], release_path=fixture["release_path"],
            out_path=stale_out, expected_shards=2)) \
        and _read(stale_path) == b"stale-invalid-receipt\n" \
        and not os.path.lexists(runner.publication_lock_path(stale_out))
    receipt_winner = _read(merged_receipt_path)
    partial_checks = partial_checks and _refused(
        lambda: ledger.durable_create_bytes_no_clobber(
            merged_receipt_path, b"overwrite", label="receipt overwrite")) \
        and _read(merged_receipt_path) == receipt_winner
    check(
        "partial tuples and stale/overwrite receipts burn paths without repair",
        partial_checks)

    competing_parent = root + "/competing"
    os.makedirs(competing_parent, mode=0o700, exist_ok=True)
    competing_out = competing_parent + "/strict.jsonl"
    owner = runner._PublicationResultLock(competing_out)
    owner.__enter__()
    try:
        competing = _refused(lambda: campaign.merge_publication_v3(
            fixture["source_paths"], release_path=fixture["release_path"],
            out_path=competing_out, expected_shards=2))
    finally:
        owner.__exit__(None, None, None)
    check(
        "competing compliant writer cannot enter the result-scoped window",
        competing and not os.path.lexists(competing_out))

    race_parent = root + "/no-clobber-race"
    os.makedirs(race_parent, mode=0o700, exist_ok=True)
    race_out = race_parent + "/strict.jsonl"
    original_rename = primitives._rename_noreplace
    raced = {"done": False}
    def inject_winner(parent_fd, source, destination, label):
        if label == "merged result" and not raced["done"]:
            raced["done"] = True
            fd = os.open(
                destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600, dir_fd=parent_fd)
            try:
                os.write(fd, b"competing-winner")
                os.fsync(fd)
            finally:
                os.close(fd)
        return original_rename(parent_fd, source, destination, label)
    primitives._rename_noreplace = inject_winner
    try:
        no_clobber_race = _refused(lambda: campaign.merge_publication_v3(
            fixture["source_paths"], release_path=fixture["release_path"],
            out_path=race_out, expected_shards=2))
    finally:
        primitives._rename_noreplace = original_rename
    check(
        "noncompliant competing winner loses no bytes at no-clobber commit",
        no_clobber_race and raced["done"]
        and _read(race_out) == b"competing-winner"
        and not os.path.lexists(race_out + ledger.RECEIPT_SUFFIX))

    # ----------------------------- stable-source/output and lock TOCTOU seams
    source_races = True
    source_original = _read(fixture["result_paths"][0])
    source_seams = crash_events[:12]
    for number, target in enumerate(source_seams):
        parent = root + f"/source-race-{number}"
        os.makedirs(parent, mode=0o700, exist_ok=True)
        out = parent + "/strict.jsonl"
        mutated = {"done": False}
        def mutate_source(event, target=target):
            if event == target and not mutated["done"]:
                mutated["done"] = True
                _write(
                    fixture["result_paths"][0],
                    source_original + b" ", raw=True)
        refused = _refused(lambda: campaign.merge_publication_v3(
            fixture["source_paths"], release_path=fixture["release_path"],
            out_path=out, expected_shards=2, fault=mutate_source))
        _write(fixture["result_paths"][0], source_original, raw=True)
        source_races = source_races and refused and mutated["done"] \
            and not os.path.lexists(out + ledger.RECEIPT_SUFFIX)
    check(
        "source mutation at every stable-read/pre-receipt-commit seam refuses",
        source_races)

    staged_output_races = True
    for number, role in enumerate(("result", "sidecar")):
        parent = root + f"/staged-output-race-{number}"
        os.makedirs(parent, mode=0o700, exist_ok=True)
        out = parent + "/strict.jsonl"
        mutated = {"done": False}
        def mutate_output(event, role=role):
            if event == "merged result receipt:stage_fsync" \
                    and not mutated["done"]:
                mutated["done"] = True
                path = out if role == "result" else out + ".campaign.json"
                _write(path, _read(path) + b" ", raw=True)
        refused = _refused(lambda: campaign.merge_publication_v3(
            fixture["source_paths"], release_path=fixture["release_path"],
            out_path=out, expected_shards=2, fault=mutate_output))
        staged_output_races = staged_output_races and refused \
            and mutated["done"] \
            and not os.path.lexists(out + ledger.RECEIPT_SUFFIX)
    check(
        "staged receipt cannot seal result or sidecar mutation before rename",
        staged_output_races)

    lock_loss = True
    for number, attack in enumerate(("unlink", "replace", "symlink", "hardlink")):
        parent = root + f"/lock-loss-{number}"
        os.makedirs(parent, mode=0o700, exist_ok=True)
        out = parent + "/strict.jsonl"
        changed = {"done": False}
        def lose_lock(event, attack=attack):
            if event != "merge:before_result_create" or changed["done"]:
                return
            changed["done"] = True
            lock_path = runner.publication_lock_path(out)
            os.unlink(lock_path)
            if attack == "replace":
                _write(lock_path, b"replacement", raw=True)
            elif attack in {"symlink", "hardlink"}:
                sentinel = parent + "/sentinel"
                _write(sentinel, b"sentinel", raw=True)
                if attack == "symlink":
                    os.symlink(sentinel, lock_path)
                else:
                    os.link(sentinel, lock_path)
        refused = _refused(lambda: campaign.merge_publication_v3(
            fixture["source_paths"], release_path=fixture["release_path"],
            out_path=out, expected_shards=2, fault=lose_lock))
        lock_loss = lock_loss and refused and changed["done"] \
            and not os.path.lexists(out + ledger.RECEIPT_SUFFIX)
    check(
        "owned lock unlink/replacement/symlink/hardlink loss refuses in-flight",
        lock_loss)

    # ------------------------------------------------ filesystem path attacks
    storage = True
    for number, attack in enumerate(("symlink", "hardlink")):
        parent = root + f"/storage-{number}"
        os.makedirs(parent, mode=0o700, exist_ok=True)
        out = parent + "/strict.jsonl"
        lock_path = runner.publication_lock_path(out)
        sentinel = parent + "/sentinel"
        _write(sentinel, b"sentinel", raw=True)
        if attack == "symlink":
            os.symlink(sentinel, lock_path)
        else:
            os.link(sentinel, lock_path)
        storage = storage and _refused(lambda out=out: (
            campaign.merge_publication_v3(
                fixture["source_paths"], release_path=fixture["release_path"],
                out_path=out, expected_shards=2))) \
            and open(sentinel, "rb").read() == b"sentinel"
    unsafe = root + "/unsafe"
    os.makedirs(unsafe, mode=0o700, exist_ok=True)
    os.chmod(unsafe, 0o777)
    storage = storage and _refused(lambda: campaign.merge_publication_v3(
        fixture["source_paths"], release_path=fixture["release_path"],
        out_path=unsafe + "/strict.jsonl", expected_shards=2))
    os.chmod(unsafe, 0o700)
    original_acl = authority._acl_absent
    acl_out = root + "/acl/strict.jsonl"
    os.makedirs(os.path.dirname(acl_out), mode=0o700, exist_ok=True)
    acl_lock = runner.publication_lock_path(acl_out)
    authority._acl_absent = lambda path, directory=False: (
        False if path == acl_lock else original_acl(path, directory=directory))
    try:
        storage = storage and _refused(lambda: campaign.merge_publication_v3(
            fixture["source_paths"], release_path=fixture["release_path"],
            out_path=acl_out, expected_shards=2))
    finally:
        authority._acl_absent = original_acl
    storage = storage and _refused(lambda: campaign.merge_publication_v3(
        fixture["source_paths"], release_path=fixture["release_path"],
        out_path=root + "/merged/../traversal.jsonl", expected_shards=2))
    contained_out = fixture["workspaces"][0] + "/contained.jsonl"
    storage = storage and _refused(lambda: campaign.merge_publication_v3(
        fixture["source_paths"], release_path=fixture["release_path"],
        out_path=contained_out, expected_shards=2)) \
        and not os.path.lexists(contained_out)
    check(
        "symlink/hardlink/ACL/unsafe-dir/traversal/containment attacks refuse",
        storage)

    # ------------------------------------------------ named mutation probes
    # Each probe first refuses under production and then deliberately removes
    # only the named gate.  Acceptance by that mutant proves the negative
    # vector kills the check rather than merely failing somewhere unrelated.
    probe_root = root + "/mutation-probes"
    os.makedirs(probe_root, mode=0o700, exist_ok=True)

    mixed_out = probe_root + "/mixed-bound.jsonl"
    mixed_args = SimpleNamespace(
        publication_v3=True, manifest=[fixture["manifest_paths"][0]],
        source_receipt=list(fixture["source_paths"]), of=2,
        release=fixture["release_path"], out=mixed_out)
    mixed_baseline = _refused(lambda: bench_cli.cmd_merge(mixed_args))
    original_publication_sources = bench_cli._publication_merge_sources
    bench_cli._publication_merge_sources = lambda args: args.source_receipt
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            mixed_mutant_accepts = bench_cli.cmd_merge(mixed_args) == 0
    finally:
        bench_cli._publication_merge_sources = original_publication_sources

    duplicate_sources = copy.deepcopy(_verified_sources(fixture))
    duplicate_sources[1].receipt_raw = duplicate_sources[0].receipt_raw
    duplicate_baseline = _refused(
        lambda: ledger._verify_merge_sources(duplicate_sources))
    original_uniqueness = ledger._verify_source_identity_uniqueness
    ledger._verify_source_identity_uniqueness = lambda _sources: None
    try:
        duplicate_mutant_accepts = bool(
            ledger._verify_merge_sources(duplicate_sources).result_rows)
    finally:
        ledger._verify_source_identity_uniqueness = original_uniqueness

    probe_result = _read(out_a)
    probe_sidecar = _read(out_a + ".campaign.json")
    probe_receipt = _read(merged_receipt_path)
    probe_receipt_document = ledger.loads_exact_json(
        probe_receipt, label="row mutation probe receipt")
    probe_rows = ledger._json_lines(probe_result, "row mutation probe")
    probe_rows[0]["scientific"]["worker"] = 999
    changed_raw = b"".join(
        (json.dumps(
            row, sort_keys=True, ensure_ascii=True, allow_nan=False,
            separators=(", ", ": ")) + "\n").encode()
        for row in probe_rows)
    changed_sidecar = ledger.loads_exact_json(
        probe_sidecar, label="row mutation probe sidecar")
    changed_sidecar["rows_digest"] = ledger.raw_sha256(changed_raw)[:16]
    changed_sidecar_raw = ledger._campaign_sidecar_bytes(changed_sidecar)
    probe_receipt_document["result"].update({
        "byte_length": len(changed_raw), "row_count": len(probe_rows),
        "file_sha256": ledger.raw_sha256(changed_raw),
    })
    probe_receipt_document["campaign_sidecar"]["file_sha256"] = (
        ledger.raw_sha256(changed_sidecar_raw))
    _resign(probe_receipt_document)
    _write(out_a, changed_raw, raw=True)
    _write(out_a + ".campaign.json", changed_sidecar_raw, raw=True)
    _write(merged_receipt_path, probe_receipt_document, indent=1)
    item_only_baseline = _refused(
        lambda: ledger.verify_receipt(merged_receipt_path))
    original_row_exact = ledger._verify_merged_rows_exact
    def item_id_only(rows, _raw, projection):
        if [row.get("item_id") for row in rows] != [
                row.get("item_id") for row in projection.result_rows]:
            raise ledger._refuse("item IDs differ")
    ledger._verify_merged_rows_exact = item_id_only
    try:
        item_only_mutant_accepts = ledger.verify_receipt(
            merged_receipt_path)["complete"]
    finally:
        ledger._verify_merged_rows_exact = original_row_exact
        _write(out_a, probe_result, raw=True)
        _write(out_a + ".campaign.json", probe_sidecar, raw=True)
        _write(merged_receipt_path, probe_receipt, raw=True)

    source_path = fixture["result_paths"][0]
    source_raw = _read(source_path)
    semantic_source_raw = b"".join(
        (json.dumps(
            row, sort_keys=True, ensure_ascii=True, allow_nan=False,
            separators=(", ", ": ")) + "\n").encode()
        for row in ledger._json_lines(source_raw, "source SHA probe"))
    if semantic_source_raw == source_raw:
        raise AssertionError("source SHA probe requires distinct whitespace")
    _write(source_path, semantic_source_raw, raw=True)
    skipped_sha_baseline = _refused(
        lambda: ledger.verify_receipt(merged_receipt_path))
    original_result_bytes = ledger._verify_result_bytes
    def skipped_source_result_binding(
            reader, binding, label, *, prefix, allow_absent_empty=False):
        if label == "run-shard result":
            current = reader.read(binding["path"], label)
            changed = dict(binding)
            changed.update({
                "byte_length": len(current),
                "row_count": len(ledger._json_lines(current, label)),
                "file_sha256": ledger.raw_sha256(current),
            })
            return original_result_bytes(
                reader, changed, label, prefix=prefix,
                allow_absent_empty=allow_absent_empty)
        return original_result_bytes(
            reader, binding, label, prefix=prefix,
            allow_absent_empty=allow_absent_empty)
    ledger._verify_result_bytes = skipped_source_result_binding
    try:
        skipped_sha_mutant_accepts = ledger.verify_receipt(
            merged_receipt_path)["complete"]
    finally:
        ledger._verify_result_bytes = original_result_bytes
        _write(source_path, source_raw, raw=True)

    cached_sources = {
        source.receipt_path: source
        for source in copy.deepcopy(_verified_sources(fixture))}
    campaign_raw = _read(fixture["base"]["campaign_path"])
    _write(
        fixture["base"]["campaign_path"], campaign_raw + b" ", raw=True)
    recursive_baseline = _refused(
        lambda: ledger.verify_receipt(merged_receipt_path))
    original_load_source = ledger._load_run_source
    ledger._load_run_source = lambda _reader, path: copy.deepcopy(
        cached_sources[path])
    try:
        recursive_mutant_accepts = ledger.verify_receipt(
            merged_receipt_path)["complete"]
    finally:
        ledger._load_run_source = original_load_source
        _write(fixture["base"]["campaign_path"], campaign_raw, raw=True)

    receipt_before_probe = _read(merged_receipt_path)
    overwrite_baseline = _refused(
        lambda: ledger.durable_create_bytes_no_clobber(
            merged_receipt_path, b"mutant overwrite",
            label="mutation receipt overwrite"))
    original_durable_create = ledger.durable_create_bytes_no_clobber
    def unsafe_overwrite(path, payload, **_kwargs):
        _write(path, payload, raw=True)
    ledger.durable_create_bytes_no_clobber = unsafe_overwrite
    try:
        ledger.durable_create_bytes_no_clobber(
            merged_receipt_path, b"mutant overwrite",
            label="mutation receipt overwrite")
        overwrite_mutant_accepts = _read(
            merged_receipt_path) == b"mutant overwrite"
    finally:
        ledger.durable_create_bytes_no_clobber = original_durable_create
        _write(merged_receipt_path, receipt_before_probe, raw=True)

    incomplete_fixture = _fixture()
    incomplete_id = incomplete_fixture["release_ids"][0]
    _scope_sources(
        incomplete_fixture, requested=[incomplete_id], limit=None)
    incomplete_out = incomplete_fixture["root"] \
        + "/merged/incomplete-probe.jsonl"
    campaign.merge_publication_v3(
        incomplete_fixture["source_paths"],
        release_path=incomplete_fixture["release_path"],
        out_path=incomplete_out, expected_shards=2)
    incomplete_receipt_path = incomplete_out + ledger.RECEIPT_SUFFIX
    incomplete_receipt = ledger.loads_exact_json(
        _read(incomplete_receipt_path), label="incomplete probe receipt")
    incomplete_sidecar_path = incomplete_out + ".campaign.json"
    incomplete_sidecar = ledger.loads_exact_json(
        _read(incomplete_sidecar_path), label="incomplete probe sidecar")
    incomplete_sidecar["n"] = len(incomplete_fixture["release_ids"])
    incomplete_sidecar_raw = ledger._campaign_sidecar_bytes(
        incomplete_sidecar)
    _write(incomplete_sidecar_path, incomplete_sidecar_raw, raw=True)
    incomplete_receipt["campaign_sidecar"]["file_sha256"] = (
        ledger.raw_sha256(incomplete_sidecar_raw))
    incomplete_receipt["merge"].update({
        "expected_item_count": len(incomplete_fixture["release_ids"]),
        "ordered_item_ids_digest": ledger.ordered_item_ids_digest(
            incomplete_fixture["release_ids"]),
    })
    _resign(incomplete_receipt)
    _write(incomplete_receipt_path, incomplete_receipt, indent=1)
    incomplete_baseline = _refused(
        lambda: ledger.verify_receipt(incomplete_receipt_path))
    original_merge_sources = ledger._verify_merge_sources
    def skipped_complete_workset(sources, *, expected_shards=None):
        projection = original_merge_sources(
            sources, expected_shards=expected_shards)
        projection.merge_ids = list(projection.release_ids)
        return projection
    ledger._verify_merge_sources = skipped_complete_workset
    try:
        incomplete_mutant_accepts = ledger.verify_receipt(
            incomplete_receipt_path)["complete"]
    finally:
        ledger._verify_merge_sources = original_merge_sources
        incomplete_fixture["temporary"].cleanup()

    check(
        "named mutation probes kill mixed-bound, duplicate-receipt, "
        "item-ID-only, skipped-SHA/recursive-join, receipt-overwrite, and "
        "incomplete-workset mutants",
        mixed_baseline and mixed_mutant_accepts
        and duplicate_baseline and duplicate_mutant_accepts
        and item_only_baseline and item_only_mutant_accepts
        and skipped_sha_baseline and skipped_sha_mutant_accepts
        and recursive_baseline and recursive_mutant_accepts
        and overwrite_baseline and overwrite_mutant_accepts
        and incomplete_baseline and incomplete_mutant_accepts)

    fixture["temporary"].cleanup()
    if failures:
        print("\nFAILURES (result_ledger_i4):")
        for failure in failures:
            print(" - " + failure)
        return 1
    print("\nALL PASS (result_ledger_i4)")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())
