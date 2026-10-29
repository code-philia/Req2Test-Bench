"""Prospective ordinary-gold evidence for the Kapua development release.

The collector records what ran, never an approval or a campaign. A later
Kapua population approval binds the completed receipt before map/audit reads it.
Ordinary rows omit shard stamps: shard identity lives in the prospective argv,
retained v3 worker evidence, hash-selected membership and untouched file bytes.
"""
from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from . import kapua_population as P
from . import kapua_runtime as KR
from . import kapua_compiler as KC
from .. import docker_authority as D
from ..bench import campaign as C, result_ledger as L, worker as W
from ..bench.validate import HARNESS_VERSION
from ..core.boundary import load_boundary

PLAN_SCHEMA = "r2t.kapua-development-gold-plan/1"
RECEIPT_SCHEMA = "r2t.kapua-development-gold-receipt/1"
WORKERS = 16


def require(ok, reason):
    if not ok:
        raise ValueError("REFUSED: Kapua gold " + reason)


def canonical(path):
    return D.canonical_absolute_path(str(path), "Kapua gold input/output")


def raw_file(path):
    from ..toolkit.mutation_java import _regular_bytes
    return _regular_bytes(canonical(path), "Kapua gold evidence", maximum=1 << 30)


def reference(path):
    return {"path": canonical(path), "sha256": hashlib.sha256(raw_file(path)).hexdigest()}


def checked(ref):
    require(isinstance(ref, dict) and set(ref) == {"path", "sha256"}, "malformed file reference")
    raw = raw_file(ref["path"])
    require(hashlib.sha256(raw).hexdigest() == ref["sha256"], "evidence bytes changed: " + ref["path"])
    return raw


def document(ref):
    D.assert_trusted_file(canonical(ref["path"]), label="Kapua gold evidence")
    return D.loads_exact_json(checked(ref), label="Kapua gold evidence")


def write(path, value):
    with Path(path).open("xb") as handle:
        handle.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def now():
    return datetime.now(timezone.utc).isoformat()


def producer_identity():
    root = Path(__file__).resolve().parents[3]
    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
    require(not git("status", "--porcelain"), "producer checkout is dirty")
    detached = subprocess.run(["git", "-C", str(root), "symbolic-ref", "-q", "HEAD"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(detached.returncode == 1, "producer checkout is not detached")
    tag = git("describe", "--exact-match", "--tags", "HEAD")
    return {"source_tag": tag, "commit": git("rev-parse", "HEAD"),
            "tree": git("rev-parse", "HEAD^{tree}"), "harness_version": HARNESS_VERSION,
            "harness_source_sha256": C.harness_source_digest()}


def release_identity(release):
    return {key: release[key] for key in
            ("manifest_path", "manifest_sha256", "tree_sha256", "items_sha256")}


def execution_gold(inputs):
    """Original reference code may use a separately recorded current manifest."""
    original = Path(inputs["release_root"]) / "reference-gold"
    if "execution_gold" not in inputs:
        return str(original)
    selected = inputs["execution_gold"]
    require(isinstance(selected, dict) and set(selected) == {"root", "strip_manifest"},
            "execution gold fields differ")
    root = Path(canonical(selected["root"]))
    require(selected["strip_manifest"] == reference(root / "strip_manifest.json"),
            "execution strip manifest identity differs")
    # The manifest belongs to the new runtime, but every restored test byte
    # must still be the original release's gold. No writable alias or extra
    # candidate file may become another source of reference tests.
    expected = {str(path.relative_to(original)) for path in original.rglob("*") if path.is_file()}
    actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()}
    require(actual == expected, "execution gold file membership differs from release")
    for rel in sorted(expected - {"strip_manifest.json"}):
        require(raw_file(root / rel) == raw_file(original / rel),
                "execution gold changed original test bytes: " + rel)
    return str(root)


def load_inputs(inputs):
    required = {"release_root", "source_root", "boundary", "profile", "native_capture",
                "compiler_capture", "worker", "docker_authority", "active_workers"}
    require(isinstance(inputs, dict) and set(inputs) in (required, required | {"execution_gold"}),
            "input fields differ")
    require(type(inputs["active_workers"]) is int and 1 <= inputs["active_workers"] <= WORKERS,
            "active concurrency is outside the authenticated pool")
    for key in ("release_root", "source_root", "worker", "docker_authority"):
        canonical(inputs[key])
    for key in ("boundary", "profile"):
        checked(inputs[key])
    from .kapua_development_release import validate_profile, validate_gold
    validate_profile(inputs["profile"]["path"])
    boundary = load_boundary(inputs["boundary"]["path"], repo_root=inputs["source_root"])
    require(boundary.project == "kapua", "boundary names another project")
    release = P.measured_release(inputs["release_root"])
    for name in ("boundary", "profile"):
        recorded = Path(inputs["release_root"]) / "control-artifacts" / ("source-" + name + ".yml")
        require(reference(recorded)["sha256"] == inputs[name]["sha256"],
                "collection " + name + " differs from assembled release")
    closures = D.loads_exact_json(raw_file(Path(inputs["release_root"]) /
                                         "control-artifacts/closures.json"), label="Kapua closures")
    validate_gold(inputs["source_root"], boundary,
                  str(Path(inputs["release_root"]) / "reference-gold"), closures)
    selected_gold = execution_gold(inputs)
    if "execution_gold" in inputs:
        validate_gold(inputs["source_root"], boundary, selected_gold, closures)
    native_ref = inputs["native_capture"]
    require(isinstance(native_ref, dict) and set(native_ref) == {"root", "receipt_sha256"},
            "native reference differs")
    checked({"path": str(Path(native_ref["root"]) / "receipt.json"),
             "sha256": native_ref["receipt_sha256"]})
    native = KR.load_capture(native_ref["root"], source_root=inputs["source_root"], boundary=boundary)
    _, partition = KR.source_census(inputs["source_root"])
    require(release["released_item_ids"] <= set(partition["candidate_ids"]),
            "released item is not a native candidate")
    compiler_ref = inputs["compiler_capture"]
    require(isinstance(compiler_ref, dict) and set(compiler_ref) ==
            {"root", "binding_path", "receipt_sha256"}, "compiler reference differs")
    compiler = KC.load_module_authority(compiler_ref["root"],
        binding_path=compiler_ref["binding_path"],
        expected_receipt_sha256=compiler_ref["receipt_sha256"],
        source_root=inputs["source_root"], boundary=boundary, native_capture=native)
    source_files = {path for module in compiler["analysis_recipe"]["modules"]
                    for path in module["source_files"]}
    return release, boundary, native, source_files


def offline_pool(worker_path, native, producer):
    selected = W.validate_worker_runtime_v3(worker_path, harness_version=producer["harness_version"],
                                           needs_database=False)
    require(selected["worker"].index == 0, "discovery worker is not slot zero")
    paths = [row["worker_spec_path"] for row in selected["binding"]["pool"]["workers"]]
    require(len(paths) == WORKERS, "worker pool is not exactly 16 slots")
    loaded = W.validate_offline_worker_runtime_pool(paths)
    for row in loaded:
        require(row["worker"].workdir == "/work" and row["runtime"]["needs_database"] is False
                and row["runtime"]["harness_version"] == producer["harness_version"],
                "worker is not the recorded no-database /work harness")
        KR.validate_live_runtime(native, {"selected": row})
    return pool_identity(loaded), loaded


def pool_identity(loaded):
    first = loaded[0]
    runtime = first["runtime"]
    return {"digest": first["binding"]["pool"]["digest"],
            "image_id": runtime["container_image_digest"], "seed_dir": runtime["seed_dir"],
            "workspace_seed_digest": runtime["workspace_seed_digest"],
            "docker_execution_authority": runtime["docker_execution_authority"],
            "workers": [{"index": row["worker"].index,
                         "spec": reference(row["spec_path"]),
                         "runtime": reference(row["runtime_path"]),
                         "binding": reference(row["runtime"]["docker_execution_binding"]["path"])}
                        for row in loaded]}


def shard_plan(inputs, item_ids, pool, out, producer_root, interpreter):
    shards = []
    for index in range(WORKERS):
        root = Path(out) / f"shard-{index:02d}"
        output, log, kept = root / "rows.jsonl", root / "command.log", root / "artifacts"
        argv = [interpreter, "-m", "r2t.cli", "--worker", pool["workers"][index]["spec"]["path"],
                "--boundary", inputs["boundary"]["path"], "--artifacts", inputs["release_root"],
                "--gold", execution_gold(inputs),
                "--docker-authority", inputs["docker_authority"], "run", "--adapter", "gold",
                "--release", str(Path(inputs["release_root"]) / "items.jsonl"),
                "--profile", inputs["profile"]["path"], "--coverage", "--repeats", "1",
                "--timeout", "600", "--repro-check", "0", "--trials", "0",
                "--shard", str(index), "--of", str(WORKERS), "--out", str(output),
                "--keep-artifacts", str(kept)]
        shards.append({"index": index, "expected_item_ids":
                       [iid for iid in item_ids if C.shard_of(iid, WORKERS) == index],
                       "argv": argv, "cwd": producer_root, "output": str(output),
                       "log": str(log), "kept_artifacts": str(kept)})
    return shards


def validate_plan(plan, out, *, release, native):
    require(isinstance(plan, dict) and plan.get("schema") == PLAN_SCHEMA
            and plan.get("project") == "kapua" and plan.get("route") == "development"
            and plan.get("written_before") == "first ordinary gold subprocess dispatch",
            "prospective plan is missing or has another shape")
    require(document(plan["inputs_file"]) == plan["inputs"], "input file differs from plan")
    producer = plan["producer"]
    from ..toolkit.mutation_java import _is_sha256
    require(isinstance(producer.get("source_tag"), str) and producer["source_tag"]
            and isinstance(producer.get("commit"), str) and len(producer["commit"]) == 40
            and isinstance(producer.get("tree"), str) and len(producer["tree"]) == 40
            and _is_sha256(producer.get("harness_source_sha256")), "producer identity is incomplete")
    require(plan["release"] == release_identity(release)
            and plan["item_ids"] == [row["item_id"] for row in release["item_rows"]],
            "release identity/order differs from plan")
    pool, loaded = offline_pool(plan["inputs"]["worker"], native, producer)
    require(pool == plan["pool"], "preserved worker pool differs from plan")
    require(canonical(plan["inputs"]["docker_authority"]) == pool["docker_execution_authority"]["path"],
            "selected Docker authority differs from pool")
    shards = plan["shards"]
    require(isinstance(shards, list) and len(shards) == WORKERS, "shard plan is incomplete")
    protected_roots = [plan["inputs"][name] for name in ("source_root", "release_root")]
    protected_roots.append(execution_gold(plan["inputs"]))
    protected_roots += [plan["inputs"][name]["root"] for name in ("native_capture", "compiler_capture")]
    protected_roots += [pool["seed_dir"], shards[0]["cwd"]]
    require(not any(Path(out).resolve().is_relative_to(Path(path).resolve())
                    for path in protected_roots), "output lies inside source or authenticated inputs")
    require(shards == shard_plan(plan["inputs"], plan["item_ids"], pool, out,
                canonical(shards[0]["cwd"]), canonical(shards[0]["argv"][0])),
            "shard argv, paths or membership differ from ordinary gold recipe")
    W.preflight([row["worker"] for row in loaded],
        [plan["inputs"]["release_root"], str(out)],
        containment_paths=[plan["inputs_file"]["path"], plan["inputs"]["source_root"],
                           plan["inputs"]["native_capture"]["root"],
                           plan["inputs"]["compiler_capture"]["root"]],
        live=False, needs_database=False)
    return loaded


def validate_rows(raw, expected_ids, shard, producer, source_files, boundary):
    from ..bench import metrics
    from .direct_calls import canonical_events
    rows = L._json_lines(raw, "Kapua ordinary gold shard")
    by_id = {}
    for row in rows:
        iid = row.get("item_id")
        require(isinstance(iid, str) and iid not in by_id, "duplicate or missing row item")
        require(row.get("adapter") == "gold" and isinstance(row.get("metadata"), dict)
                and row["metadata"].get("source") == "gold" and row.get("outcome") == "passed"
                and type(row.get("repeats")) is int and row["repeats"] == 1
                and type(row.get("trials")) is int and row["trials"] == 0
                and all(row.get(key) is True for key in
                        ("coverage", "coverage_requested", "coverage_collected"))
                and row.get("coverage_mismatch") == [], "row is not one successful measured gold observation")
        require(not any(key in row for key in ("campaign_digest", "campaign", "publication_v3"))
                and all(row.get(key) is None for key in ("condition", "model", "agent_system"))
                and row.get("harness_version") == producer["harness_version"]
                and isinstance(row.get("harness_commit"), str)
                and len(row["harness_commit"]) >= 7
                and producer["commit"].startswith(row["harness_commit"]),
                "row has another ordinary recipe/producer or claims a campaign")
        require(("shard" not in row or type(row["shard"]) is int and row["shard"] == shard)
                and ("of" not in row or type(row["of"]) is int and row["of"] == WORKERS),
                "row carries another shard identity")
        lines, counts = row.get("coverage_lines"), row.get("coverage_files")
        require(isinstance(lines, dict) and isinstance(counts, dict) and set(lines) == set(counts),
                "coverage path/count sets differ")
        for path, values in lines.items():
            require(isinstance(path, str) and KC.relative(path) == path and path in source_files
                    and isinstance(values, list) and all(type(v) is int and v > 0 for v in values)
                    and values == sorted(set(values)) and type(counts[path]) is int
                    and counts[path] == len(values), "malformed or non-original production coverage")
        events = row.get("direct_calls")
        require(isinstance(events, list), "gold has no collected direct-call evidence")
        canonical_events(events)
        by_id[iid] = row
    require(set(by_id) == set(expected_ids) and len(by_id) == len(expected_ids),
            "shard is not the exact hash-selected released item set")
    metrics.check_scorable(by_id, "Kapua ordinary gold")
    _, dropped = metrics.scorable_gold(by_id, boundary)
    require(not dropped, "gold has unscorable released items")
    return rows


def artifacts_identity(root, rows):
    from ..bench.runner import item_key
    root = Path(root)
    require(root.is_dir() or not rows, "kept artifacts are missing")
    if not root.exists():
        return []
    refs = []
    for row in rows:
        item_root = root / "gold" / item_key(row["item_id"])
        record = D.loads_exact_json(raw_file(item_root / "record.json"), label="gold record")
        coverage = D.loads_exact_json(raw_file(item_root / "coverage.json"), label="gold coverage")
        meta = D.loads_exact_json(raw_file(item_root / "meta.json"), label="gold metadata")
        require(record == row and coverage == {"item_id": row["item_id"],
                "files": row["coverage_files"], "lines": row["coverage_lines"]},
                "kept record/coverage differs from row")
        require(meta.get("item_id") == row["item_id"] and meta.get("adapter") == "gold"
                and meta.get("outcome") == "passed" and type(meta.get("stdout_complete")) is bool,
                "kept metadata differs from row")
        raw_file(item_root / "stdout.log")
        for produced in row.get("produced_files") or []:
            rel = KC.relative(produced["file_path"])
            require(raw_file(item_root / "solution" / rel) == (produced.get("code") or "").encode(),
                    "kept solution differs from submitted gold bytes")
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "symlink in kept artifacts")
        if path.is_file():
            refs.append(reference(path))
    return refs


def validate_gold_solutions(rows, release_root):
    from ..bench.fixtures import make_gold_adapter
    adapter = make_gold_adapter(release_root, str(Path(release_root) / "reference-gold"))
    for row in rows:
        expected = adapter({"item_id": row["item_id"]})
        require(row.get("produced_files") == expected["files"],
                "row solution differs from the released original gold")


def live_shard(plan, shard, native):
    from ..core import docker_cli
    from ..bench import repo
    docker_cli.configure(authority_path=plan["inputs"]["docker_authority"])
    path = plan["pool"]["workers"][shard["index"]]["spec"]["path"]
    spec = W.load_worker_spec(path)
    boundary = load_boundary(plan["inputs"]["boundary"]["path"], repo_root=spec.workspace)
    runtime = W.validate_live_worker_runtime(path, spec, plan["producer"]["harness_version"], False,
        [plan["inputs"]["release_root"], plan["inputs"]["source_root"], shard["output"],
         shard["log"], shard["kept_artifacts"]], expected_pool_size=WORKERS,
        behat=repo.behat_project(boundary))
    KR.validate_live_runtime(native, runtime)
    require(runtime["docker_execution_pool_digest"] == plan["pool"]["digest"],
            "live worker changed its pool")


def run_shard(plan, shard, native, source_files, boundary):
    Path(shard["output"]).parent.mkdir()
    started = now()
    try:
        live_shard(plan, shard, native)
        env = dict(os.environ, PYTHONPATH=str(Path(shard["cwd"]) / "benchmark"))
        with Path(shard["log"]).open("xb") as handle:
            result = subprocess.run(shard["argv"], cwd=shard["cwd"], env=env,
                                    stdout=handle, stderr=subprocess.STDOUT)
        execution = {"index": shard["index"], "started_at": started, "finished_at": now(),
                     "returncode": result.returncode}
        write(Path(shard["output"]).parent / "execution.json", execution)
        require(result.returncode == 0, "ordinary shard subprocess failed")
        rows = validate_rows(raw_file(shard["output"]), shard["expected_item_ids"], shard["index"],
                             plan["producer"], source_files, boundary)
        validate_gold_solutions(rows, plan["inputs"]["release_root"])
        return {**execution, "rows": {**reference(shard["output"]), "n": len(rows)},
                "log": reference(shard["log"]), "kept_artifacts": shard["kept_artifacts"],
                "artifacts": artifacts_identity(shard["kept_artifacts"], rows)}
    except BaseException as error:
        write(Path(shard["output"]).parent / "failure.json",
              {"index": shard["index"], "started_at": started, "finished_at": now(),
               "error_type": type(error).__name__, "error": str(error)})
        raise


def execute_plan(plan, out, *, native, source_files, boundary):
    """Stop dispatch after failure; retain already running/completed shards."""
    completed, errors = [], []
    pending = iter(plan["shards"])
    with ThreadPoolExecutor(max_workers=plan["inputs"]["active_workers"]) as executor:
        futures = {}
        def submit():
            shard = next(pending, None)
            if shard is not None:
                futures[executor.submit(run_shard, plan, shard, native, source_files, boundary)] = shard
        for _ in range(plan["inputs"]["active_workers"]):
            submit()
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for future in done:
                futures.pop(future)
                try:
                    completed.append(future.result())
                except BaseException as error:
                    errors.append({"error_type": type(error).__name__, "error": str(error)})
            if not errors:
                for _ in done:
                    submit()
    if errors:
        write(Path(out) / "failure.json", {"status": "failed", "errors": errors,
              "completed_shards": sorted(completed, key=lambda row: row["index"]),
              "approval_created": False})
        raise ValueError("REFUSED: Kapua gold collection failed; raw partial evidence retained")
    completed.sort(key=lambda row: row["index"])
    output = Path(out) / "gold.jsonl"
    with output.open("xb") as handle:
        for shard in completed:
            ref = {key: shard["rows"][key] for key in ("path", "sha256")}
            handle.write(checked(ref))
    return {"schema": RECEIPT_SCHEMA, "status": "complete",
            "plan": reference(Path(out) / "plan.json"), "shards": completed,
            "rows": {**reference(output), "n": len(plan["item_ids"])},
            "assembly": "numeric_shard_order_original_file_bytes", "approval_created": False}


def check_receipt(receipt, plan, *, source_files, boundary):
    require(receipt.get("schema") == RECEIPT_SCHEMA and receipt.get("status") == "complete"
            and receipt.get("approval_created") is False
            and receipt.get("assembly") == "numeric_shard_order_original_file_bytes",
            "receipt is missing, partial or claims another collection route")
    require(len(receipt["shards"]) == WORKERS, "receipt omits a shard")
    all_rows, concatenated = [], []
    for index, (done, shard) in enumerate(zip(receipt["shards"], plan["shards"])):
        require(done["index"] == index and type(done["returncode"]) is int and done["returncode"] == 0
                and isinstance(done["started_at"], str) and isinstance(done["finished_at"], str)
                and datetime.fromisoformat(done["started_at"]) <= datetime.fromisoformat(done["finished_at"])
                and done["rows"]["path"] == shard["output"] and done["log"]["path"] == shard["log"]
                and done["kept_artifacts"] == shard["kept_artifacts"], "shard execution differs from plan")
        raw = checked({key: done["rows"][key] for key in ("path", "sha256")})
        checked(done["log"])
        rows = validate_rows(raw, shard["expected_item_ids"], index, plan["producer"], source_files, boundary)
        validate_gold_solutions(rows, plan["inputs"]["release_root"])
        require(type(done["rows"]["n"]) is int and done["rows"]["n"] == len(rows), "shard count differs")
        require(done["artifacts"] == artifacts_identity(shard["kept_artifacts"], rows),
                "kept artifact bytes changed")
        all_rows.extend(rows)
        concatenated.append(raw)
    ref = {key: receipt["rows"][key] for key in ("path", "sha256")}
    raw = checked(ref)
    require(raw == b"".join(concatenated) and receipt["rows"]["n"] == len(all_rows)
            and len(all_rows) == len(plan["item_ids"])
            and {row["item_id"] for row in all_rows} == set(plan["item_ids"]),
            "final rows differ from exact complete numeric-shard concatenation")
    return {row["item_id"]: row["coverage_lines"] for row in all_rows}, ref["sha256"]


def collect(inputs_path, out):
    out = Path(canonical(out))
    require(out.resolve() == out and not os.path.lexists(out), "collection output already exists or is noncanonical")
    inputs_ref = reference(inputs_path)
    inputs = document(inputs_ref)
    release, boundary, native, source_files = load_inputs(inputs)
    producer = producer_identity()
    pool, _ = offline_pool(inputs["worker"], native, producer)
    item_ids = [row["item_id"] for row in release["item_rows"]]
    plan = {"schema": PLAN_SCHEMA, "project": "kapua", "route": "development",
            "producer": producer, "inputs": inputs, "inputs_file": inputs_ref,
            "release": release_identity(release), "item_ids": item_ids, "pool": pool,
            "shards": shard_plan(inputs, item_ids, pool, out,
                                  str(Path(__file__).resolve().parents[3]), sys.executable),
            "written_before": "first ordinary gold subprocess dispatch"}
    validate_plan(plan, out, release=release, native=native)
    out.mkdir()
    write(out / "plan.json", plan)
    try:
        receipt = execute_plan(plan, out, native=native, source_files=source_files, boundary=boundary)
        check_receipt(receipt, plan, source_files=source_files, boundary=boundary)
        # Close input/source/worker joins again before declaring collection complete.
        final_release, _, final_native, _ = load_inputs(inputs)
        validate_plan(plan, out, release=final_release, native=final_native)
        require(producer_identity() == producer, "producer changed during collection")
        write(out / "receipt.json", receipt)
        return receipt
    except BaseException as error:
        if not (out / "failure.json").exists():
            write(out / "failure.json", {"status": "failed", "error_type": type(error).__name__,
                                         "error": str(error), "approval_created": False})
        raise


def _load_coverage(receipt_path, receipt_sha256, *, coverage_run, release, approved):
    receipt = document({"path": canonical(receipt_path), "sha256": receipt_sha256})
    require(receipt.get("status") == "complete", "receipt is partial")
    plan = document(receipt["plan"])
    require(plan["release"] == release_identity(release), "receipt release differs from approval")
    for name in ("source_root", "boundary", "native_capture", "compiler_capture"):
        require(plan["inputs"][name] == approved[name], "receipt differs from approval at " + name)
    actual_release, boundary, native, source_files = load_inputs(plan["inputs"])
    root = Path(canonical(receipt_path)).parent
    require(receipt["plan"]["path"] == str(root / "plan.json")
            and canonical(coverage_run) == receipt["rows"]["path"] == str(root / "gold.jsonl"),
            "selected rows/plan differ from completed receipt")
    validate_plan(plan, root, release=actual_release, native=native)
    return check_receipt(receipt, plan, source_files=source_files, boundary=boundary)


def load_coverage(receipt_path, receipt_sha256, *, coverage_run, release, approved):
    try:
        return _load_coverage(receipt_path, receipt_sha256, coverage_run=coverage_run,
                              release=release, approved=approved)
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError("REFUSED: Kapua gold receipt/plan has malformed fields") from error


PROJECTION_SCHEMA = "r2t.kapua-gold-census-projection/1"


def projection_path(coverage_run):
    return str(coverage_run) + ".projection.json"


def census_selection(items_path, release, annotation_verification):
    """Replay C and bind its annotated pool to actual recorded K7 outputs."""
    from ..data import subsets as S
    from ..toolkit.interfaces_java import annotated_rows

    items_path = canonical(items_path)
    identity = S.identify_for_inference(items_path)
    require(identity and identity["inference_valid"] is True
            and identity.get("sidecar"), "census has no current sampler provenance")
    sidecar = document(reference(identity["sidecar"]))
    require(sidecar.get("schema") == S.SCHEMA and sidecar.get("census") is True
            and sidecar.get("allow_cluster_siblings") is False,
            "selection is not the complete one-per-closure census")
    pool_path = str(Path(items_path).parent / sidecar["source_items"])
    require(S._closure_clusters(str(Path(items_path).parent))
            == S._closure_clusters(release["root"]),
            "census closure partition differs from the reviewed release")

    verification_ref = reference(annotation_verification)
    verification = document(verification_ref)
    require(verification.get("state") == "k7_attribution_output_verified"
            and verification.get("original_released_bytes_and_order_preserved") is True,
            "annotation verification is not completed K7 evidence")
    inputs = document(verification["input_receipt"])
    require(inputs.get("state") == "k7_inputs_prepared_attribution_not_run"
            and all(verification.get(k) == inputs.get(k) for k in ("tag", "commit", "tree", "image_id")),
            "annotation verification differs from its recorded producer inputs")
    hashes = inputs["input_sha256"]
    approved = release["approval"]
    native_path = str(Path(approved["native_capture"]["root"]) / "receipt.json")
    require(inputs.get("source_root") == approved["source_root"]
            and hashes.get(approved["boundary"]["path"]) == approved["boundary"]["sha256"]
            and hashes.get(native_path) == approved["native_capture"]["receipt_sha256"],
            "K7 original source/boundary/native capture differ from the reviewed release")
    require(hashes.get(release["items_path"]) == release["items_sha256"]
            and hashes.get(release["manifest_path"]) == release["manifest_sha256"],
            "K7 source items/manifest differ from the reviewed release")
    for path, digest in hashes.items():
        checked({"path": path, "sha256": digest})
    original_ids = [row["item_id"] for row in release["item_rows"]]
    require(inputs.get("released_item_ids") == original_ids
            and verification.get("items") == len(original_ids),
            "K7 source release membership/order differs")
    companion = checked(verification["annotated_companion"])
    evidence = document(verification["interfaces"])["items"]
    checked(verification["suite_partitions"])
    require([row["item_id"] for row in evidence] == original_ids,
            "K7 interface evidence membership/order differs")
    annotations = {row["item_id"]: row["target_interfaces"] for row in evidence}
    require(companion == annotated_rows(raw_file(release["items_path"]), annotations)
            and raw_file(pool_path) == companion,
            "census pool differs from the verified K7 annotation reconstruction")
    selected = [iid for iid, _line in S.read_items(items_path)]
    require(set(selected) <= release["released_item_ids"], "census contains a foreign release item")
    return selected, {"items": reference(items_path), "provenance": reference(identity["sidecar"]),
                      "annotation_verification": verification_ref}


def _projected_gold_bytes(full_run, selected):
    wanted = set(selected)
    return b"".join(line for line in raw_file(full_run).splitlines(keepends=True)
                    if line.strip() and json.loads(line)["item_id"] in wanted)


def project_census(release_root, approval_path, approved_digest, items_path,
                   annotation_verification, out):
    """Write original gold row bytes for the authenticated closure census."""
    release = P.validate_release(release_root, approval_path=approval_path,
                                 approved_digest=approved_digest)
    approved = release["approval"]
    full_receipt = document({"path": approved["gold_coverage"]["receipt_path"],
                             "sha256": approved["gold_coverage"]["receipt_sha256"]})
    full_run = full_receipt["rows"]["path"]
    P.load_gold_coverage(full_run, release, boundary_path=approved["boundary"]["path"])
    selected, selection = census_selection(items_path, release, annotation_verification)
    raw = _projected_gold_bytes(full_run, selected)
    out = Path(canonical(out))
    require(out.resolve() == out and not os.path.lexists(out),
            "projection output already exists or is noncanonical")
    # A derived output must not change the full release/source evidence it proves.
    for root in (release["root"], approved["source_root"],
                 approved["native_capture"]["root"], approved["compiler_capture"]["root"],
                 str(Path(full_run).parent), str(Path(items_path).parent)):
        require(not out.is_relative_to(Path(root)), "projection output is inside an input root")
    out.mkdir()
    coverage_run = out / "gold.jsonl"
    with coverage_run.open("xb") as handle:
        handle.write(raw)
    receipt = {"schema": PROJECTION_SCHEMA, "project": "kapua", "route": "development",
               "release_root": release["root"], "release": release_identity(release),
               "approval": reference(approval_path), "approved_digest": approved_digest,
               "full_gold": reference(full_run), "selection": selection,
               "coverage": reference(coverage_run), "items": len(selected),
               "derivation": "selected original full-gold row bytes in their original order",
               "approval_created": False}
    write(projection_path(coverage_run), receipt)
    load_census_projection(str(coverage_run), items_path, approved["boundary"]["path"])
    return receipt


def load_projection(coverage_run, items_path, boundary_path, *, release=None):
    """The two explicit projection schemas share the original native input gate."""
    doc = document(reference(projection_path(coverage_run)))
    if doc.get("schema") == PROJECTION_SCHEMA:
        return load_census_projection(coverage_run, items_path, boundary_path, release=release)
    from . import kapua_pilot as K
    if doc.get("schema") == K.GOLD_SCHEMA:
        return K.load_mapping(coverage_run, items_path, boundary_path, release=release)
    from . import kapua_headroom as H
    if doc.get("schema") == H.GOLD_SCHEMA:
        return H.load_gold(coverage_run, items_path, boundary_path, release=release)
    from . import kapua_census_mutation as CM
    if doc.get("schema") == CM.COVERAGE_SCHEMA:
        return CM.load_coverage(coverage_run, items_path, boundary_path, release=release)
    raise ValueError("REFUSED: unknown Kapua gold projection schema")


def load_census_projection(coverage_run, items_path, boundary_path, *, release=None):
    """Revalidate original collection, actual K7 selection and exact projection."""
    try:
        receipt = document(reference(projection_path(coverage_run)))
        require(isinstance(receipt, dict) and set(receipt) == {
            "schema", "project", "route", "release_root", "release", "approval",
            "approved_digest", "full_gold", "selection", "coverage", "items",
            "derivation", "approval_created"}
            and receipt["schema"] == PROJECTION_SCHEMA and receipt["project"] == "kapua"
            and receipt["route"] == "development" and receipt["approval_created"] is False
            and receipt["derivation"] == "selected original full-gold row bytes in their original order",
            "census projection receipt has another schema/route")
        checked(receipt["approval"])
        original = P.validate_release(receipt["release_root"],
            approval_path=receipt["approval"]["path"], approved_digest=receipt["approved_digest"])
        require(release is None or original == release, "projection names another full release/approval")
        require(receipt["release"] == release_identity(original), "projection full release identity differs")
        P.load_gold_coverage(receipt["full_gold"]["path"], original, boundary_path=boundary_path)
        checked(receipt["full_gold"])
        selection = receipt["selection"]
        require(set(selection) == {"items", "provenance", "annotation_verification"},
                "census projection selection references differ")
        for ref in selection.values():
            checked(ref)
        require(canonical(items_path) == selection["items"]["path"], "projection names another census")
        selected, expected_selection = census_selection(items_path, original,
            selection["annotation_verification"]["path"])
        require(selection == expected_selection and type(receipt["items"]) is int
                and receipt["items"] == len(selected), "projection census identity/count differs")
        require(receipt["coverage"]["path"] == canonical(coverage_run), "projection names other coverage")
        raw = checked(receipt["coverage"])
        require(raw == _projected_gold_bytes(receipt["full_gold"]["path"], selected),
                "projected rows differ from the original full-gold bytes")
        rows = L._json_lines(raw, "Kapua projected gold")
        require(len(rows) == len(selected) and {r["item_id"] for r in rows} == set(selected),
                "projected gold omits or duplicates census items")
        return {r["item_id"]: r["coverage_lines"] for r in rows}, receipt["coverage"]["sha256"]
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError("REFUSED: Kapua gold census projection has malformed fields") from error


def selftest(*, headroom=False, reference_reuse=False, pilot=False):
    """Ordinary producer/consumer joins, with no Docker or Kapua corpus needed."""
    import copy
    import tempfile
    from types import SimpleNamespace
    from unittest.mock import patch
    from ..bench.runner import _write_artifacts, item_key
    from ..core.boundary import Boundary
    from ..toolkit import mutation_java as MJ

    failures = []
    def refuses(label, fn):
        try:
            fn()
        except (ValueError, RuntimeError, OSError, D.DockerAuthorityRefused):
            return
        failures.append(label)

    with tempfile.TemporaryDirectory(prefix="kapua_gold_") as scratch:
        root = Path(scratch)
        source = root / "source"
        source.mkdir()
        files = {"commons/src/main/java/example/A.java", "service/src/main/java/example/B.java"}
        for rel in files:
            (source / rel).parent.mkdir(parents=True)
            (source / rel).write_text("class Example {}\n")
        source_hashes = {rel: reference(source / rel)["sha256"] for rel in files}
        boundary = Boundary(1, "kapua", str(source), [], [], [], [], {})
        release_root = root / "release"
        (release_root / "control-artifacts").mkdir(parents=True)
        # At least two populated hash shards, neither positional slicing nor release order.
        ids = [f"kapua/features/Example.feature:{n}" for n in range(3, 15)]
        glue = {iid: f"tests/Steps{index // 2}.java" for index, iid in enumerate(ids)}
        from .kapua import FEATURE_SUITES
        rows = [{"item_id": iid, "project": "kapua",
                 "provenance": {"file_path": next(iter(FEATURE_SUITES))}} for iid in ids]
        (release_root / "items.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
        write(release_root / "control-artifacts/closures.json",
              [{"item_id": iid, "admitted": True, "files": [glue[iid]],
                "steps": [{"side": "removable", "definition": {"file": glue[iid]},
                           "location": glue[iid] + ".check(java.lang.String)"}]} for iid in ids])
        (release_root / "gold").mkdir()
        (release_root / "reference-gold/tests").mkdir(parents=True)
        for rel in set(glue.values()):
            (release_root / "reference-gold" / rel).write_text("class Steps {}\n")
        # Use the real gold loader's per-item manifest shape.
        gold_manifest = {}
        for iid in ids:
            name = item_key(iid) + ".json"
            write(release_root / "gold" / name, {"item_id": iid, "files": [glue[iid]]})
            gold_manifest[iid] = name
        write(release_root / "gold/manifest.json", gold_manifest)
        manifest = P.release_file_manifest(release_root)
        manifest["released_item_ids"] = ids
        write(root / "release-manifest.json", manifest)
        release = P.measured_release(release_root)
        producer = {"source_tag": "fixture-reviewed", "commit": "a" * 40, "tree": "b" * 40,
                    "harness_version": HARNESS_VERSION, "harness_source_sha256": "c" * 64}
        for name in ("boundary.yml", "profile.yml", "native.json", "compiler.json", "authority.json"):
            write(root / name, {"fixture": name})
        (root / "boundary.yml").write_text(json.dumps({"version": 1, "project": "kapua",
            "repo_root": str(source), "removable": [], "retained": []}))
        (root / "native").mkdir()
        (root / "compiler").mkdir()
        workers = []
        for index in range(WORKERS):
            refs = {}
            for key in ("spec", "runtime", "binding"):
                path = root / f"worker{index}.{key}.json"
                write(path, {"index": index, "kind": key})
                refs[key] = reference(path)
            workers.append({"index": index, **refs})
        pool = {"digest": "d" * 64, "image_id": "sha256:" + "e" * 64,
                "seed_dir": str(root / "seed"), "workspace_seed_digest": "f" * 64,
                "docker_execution_authority": {"path": str(root / "authority.json"), "sha256": "1" * 64},
                "workers": workers}
        inputs = {"release_root": str(release_root), "source_root": str(source),
                  "boundary": reference(root / "boundary.yml"), "profile": reference(root / "profile.yml"),
                  "native_capture": {"root": str(root / "native"), "receipt_sha256": reference(root / "native.json")["sha256"]},
                  "compiler_capture": {"root": str(root / "compiler"), "binding_path": str(root / "compiler.json"),
                                       "receipt_sha256": reference(root / "compiler.json")["sha256"]},
                  "worker": workers[0]["spec"]["path"], "docker_authority": str(root / "authority.json"),
                  "active_workers": 1}
        # A new strip manifest does not require rewriting released gold.
        import shutil
        current_gold = root / "current-gold"
        shutil.copytree(release_root / "reference-gold", current_gold)
        write(current_gold / "strip_manifest.json", {"fixture": "current-runtime"})
        # This source-only fixture did not need a manifest in the legacy root.
        write(release_root / "reference-gold/strip_manifest.json", {"fixture": "historical-runtime"})
        # Rebind the fixture release manifest after adding that real gold member.
        fixture_manifest = P.release_file_manifest(release_root)
        fixture_manifest["released_item_ids"] = ids
        (root / "release-manifest.json").write_text(json.dumps(fixture_manifest))
        release = P.measured_release(release_root)
        current_inputs = {**inputs, "execution_gold": {"root": str(current_gold),
            "strip_manifest": reference(current_gold / "strip_manifest.json")}}
        assert execution_gold(inputs) == str(release_root / "reference-gold")
        assert execution_gold(current_inputs) == str(current_gold)
        refuses("null execution gold", lambda: execution_gold({**inputs, "execution_gold": None}))
        planned = shard_plan(current_inputs, ids, pool, root / "prospective", str(root), "/usr/bin/python3")
        assert all(shard["argv"][shard["argv"].index("--gold") + 1] == str(current_gold) for shard in planned)
        original_test = current_gold / next(iter(glue.values()))
        original_bytes = original_test.read_bytes()
        original_test.write_bytes(original_bytes + b"// changed\n")
        refuses("changed execution gold test", lambda: execution_gold(current_inputs))
        original_test.write_bytes(original_bytes)
        (current_gold / "extra.java").write_text("class Extra {}")
        refuses("extra execution gold test", lambda: execution_gold(current_inputs))
        (current_gold / "extra.java").unlink()
        manifest_bytes = (current_gold / "strip_manifest.json").read_bytes()
        (current_gold / "strip_manifest.json").write_bytes(manifest_bytes + b" ")
        refuses("changed execution manifest", lambda: execution_gold(current_inputs))
        (current_gold / "strip_manifest.json").write_bytes(manifest_bytes)
        assert execution_gold(current_inputs) == str(current_gold)
        inputs_path = root / "inputs.json"
        write(inputs_path, inputs)
        def fixture_inputs(value):
            assert value == inputs
            for name in ("boundary", "profile"):
                checked(value[name])
            checked({"path": str(root / "native.json"), "sha256": value["native_capture"]["receipt_sha256"]})
            checked({"path": str(root / "compiler.json"), "sha256": value["compiler_capture"]["receipt_sha256"]})
            for rel, digest in source_hashes.items():
                checked({"path": str(source / rel), "sha256": digest})
            return P.measured_release(value["release_root"]), boundary, {}, files
        def fixture_pool(*args):
            for worker in workers:
                for key in ("spec", "runtime", "binding"):
                    checked(worker[key])
            return pool, []
        def fixture_run(argv, *, cwd, env, stdout, stderr):
            output = Path(argv[argv.index("--out") + 1])
            plan = json.loads((output.parent.parent / "plan.json").read_bytes())
            slot = int(argv[argv.index("--shard") + 1])
            assert plan["shards"][slot]["argv"] == argv
            assert env["PYTHONPATH"] == str(Path(cwd) / "benchmark")
            selected = [iid for iid in ids if C.shard_of(iid, WORKERS) == slot]
            written = []
            for index, iid in enumerate(selected):
                coverage = {sorted(files)[index % 2]: [1, 3, 99999]}
                produced = {"files": [{"file_path": glue[iid], "code": "class Steps {}\n"}]}
                row = {"item_id": iid, "adapter": "gold", "metadata": {"source": "gold"},
                       "outcome": "passed", "repeats": 1, "trials": 0,
                       "condition": None, "model": None, "harness_version": HARNESS_VERSION,
                       "harness_commit": "a" * 7, "coverage": True, "coverage_requested": True,
                       "coverage_collected": True, "coverage_mismatch": [],
                       "coverage_lines": coverage, "coverage_files": {p: len(v) for p, v in coverage.items()},
                       "direct_calls": [], "produced_files": produced["files"]}
                _write_artifacts(argv[argv.index("--keep-artifacts") + 1], {"item_id": iid}, "gold",
                                 produced, {"runs": [{"stdout": "fixture native output\n"}]}, row, {})
                written.append(row)
            output.write_bytes(b"".join((json.dumps(row) + "\n").encode() for row in written))
            stdout.write(b"fixture ordinary command completed\n")
            return SimpleNamespace(returncode=0)
        out = root / "collected"
        with patch(__name__ + ".load_inputs", fixture_inputs), \
             patch(__name__ + ".producer_identity", lambda: producer), \
             patch(__name__ + ".offline_pool", fixture_pool), \
             patch(__name__ + ".live_shard", lambda *args: None), \
             patch.object(W, "preflight", lambda *args, **kwargs: {}), \
             patch.object(subprocess, "run", fixture_run):
            receipt = collect(str(inputs_path), str(out))
            assert receipt["approval_created"] is False
            assert len(receipt["shards"]) == WORKERS and receipt["rows"]["n"] == len(ids)
            assert raw_file(out / "gold.jsonl") == b"".join(raw_file(s["rows"]["path"]) for s in receipt["shards"])
            approved = {name: inputs[name] for name in ("source_root", "boundary", "native_capture", "compiler_capture")}
            digest = reference(out / "receipt.json")["sha256"]
            def load():
                return load_coverage(str(out / "receipt.json"), digest,
                    coverage_run=str(out / "gold.jsonl"), release=release, approved=approved)
            coverage, rows_digest = load()
            assert set(coverage) == set(ids) and rows_digest == reference(out / "gold.jsonl")["sha256"]
            assert any(path.startswith("commons/") for item in coverage.values() for path in item)
            compiler = {"java_home": "/opt/java/openjdk", "parser": "javac 17.0.17",
                "runtime_executable_sha256": "a" * 64, "compiler_executable_sha256": "b" * 64,
                "tools_jar_sha256": None, "encoding": "UTF-8", "source": "1.8",
                "target": "1.8", "release": None}
            modules, mutants = [], []
            for rel in sorted(files):
                name = rel.split("/src/main/java/")[0]
                classes = name + "/target/classes"
                (source / classes).mkdir(parents=True)
                (source / classes / "Example.class").write_bytes(b"fixture compiled class bytes")
                child = MJ.make_module_analysis_child_recipe(str(source), name, classpath=[classes])
                modules.append({"module": name, "source_root": name + "/src/main/java",
                                "source_files": [rel], "compiler": compiler, "recipe": child})
                mutants.append({"file": rel, "start_line": 3, "start_col": 1,
                    "end_line": 3, "end_col": 7, "operator": "ReturnValue", "original": "return 1;",
                    "mutated": "return 0;", "class": "Example", "method": "fixture"})
            recipe = MJ.make_module_analysis_recipe(str(source), modules)
            population = MJ.build_population(mutants, parser_version=MJ.module_analysis_parser(recipe),
                enumerator_rev=MJ.ENUMERATOR_REV, analysis_recipe=recipe)
            bound_release = {**release, "approval": {**approved, "gold_coverage": {
                "receipt_path": str(out / "receipt.json"), "receipt_sha256": digest}}}
            def mapped():
                return MJ._build_population_map(population, str(out / "gold.jsonl"),
                    release_ids=set(ids), release_sha256=release["items_sha256"],
                    kapua_release=bound_release, boundary_path=inputs["boundary"]["path"])
            mapping, mapped_coverage = mapped()
            assert mapped() == (mapping, mapped_coverage) and mapped_coverage == coverage
            assert mapping["coverage_sha256"] == rows_digest and mapping["n_mapped"] > 0
            # C is an actual /2 draw over the verified annotated full pool.
            from ..data import subsets as SUB, mutation_attestation as A
            from ..toolkit import mutation_asset_index as ASSETS
            from ..toolkit.interfaces_java import annotated_rows
            from ..toolkit.subset_writer import write_subset, write_budgeted_sample
            from ..bench.mutation_run import binding_for
            census_root = root / "census"
            census_root.mkdir()
            annotations = {iid: {"behaviour": ["example.Service"], "setup": []} for iid in ids}
            companion = annotated_rows(raw_file(release["items_path"]), annotations)
            (census_root / "items.jsonl").write_bytes(companion)
            write(census_root / "closure_clusters.json", SUB._closure_clusters(release["root"]))
            # Six real closure-file pairs produce C strictly smaller than R.
            subset, _ = write_subset(SUB.sample(str(census_root / "items.jsonl"),
                str(census_root), n=6, seed=1), str(census_root / "eval-census"))
            k7 = root / "k7"
            k7.mkdir()
            (k7 / "items.annotated.jsonl").write_bytes(companion)
            write(k7 / "interfaces.json", {"items": [{"item_id": iid, "target_interfaces": annotations[iid]} for iid in ids]})
            write(k7 / "suite-partitions.json", {"partitions": []})
            (root / "native/receipt.json").write_bytes((root / "native.json").read_bytes())
            k7_inputs = {"state": "k7_inputs_prepared_attribution_not_run",
                "tag": "fixture-original-k7", "commit": "b" * 40, "tree": "c" * 40, "image_id": "sha256:" + "d" * 64,
                "released_item_ids": ids, "source_root": str(source),
                "input_sha256": {release["items_path"]: release["items_sha256"],
                    release["manifest_path"]: release["manifest_sha256"],
                    inputs["boundary"]["path"]: inputs["boundary"]["sha256"],
                    str(root / "native/receipt.json"): inputs["native_capture"]["receipt_sha256"]}}
            write(k7 / "input-receipt.json", k7_inputs)
            k7_verification = {"state": "k7_attribution_output_verified",
                **{k: k7_inputs[k] for k in ("tag", "commit", "tree", "image_id")},
                "items": len(ids), "original_released_bytes_and_order_preserved": True,
                "input_receipt": reference(k7 / "input-receipt.json"),
                "annotated_companion": reference(k7 / "items.annotated.jsonl"),
                "interfaces": reference(k7 / "interfaces.json"),
                "suite_partitions": reference(k7 / "suite-partitions.json")}
            write(k7 / "verification.json", k7_verification)
            approval = {"schema": P.APPROVAL_SCHEMA, "project": "kapua", "route": "development",
                "release_manifest_sha256": release["manifest_sha256"], "release_tree_sha256": release["tree_sha256"],
                **approved, "gold_coverage": {"receipt_path": str(out / "receipt.json"), "receipt_sha256": digest}}
            approval["digest"] = D.semantic_digest(approval, domain=P.APPROVAL_SCHEMA)
            write(root / "approval.json", approval)
            projected = root / "projected"
            projection = project_census(str(release_root), str(root / "approval.json"), approval["digest"],
                subset, str(k7 / "verification.json"), str(projected))
            census_ids = {iid for iid, _ in SUB.read_items(subset)}
            projected_path = str(projected / "gold.jsonl")
            projected_cov, projected_sha = load_census_projection(projected_path, subset, inputs["boundary"]["path"])
            assert set(projected_cov) == census_ids and len(census_ids) < len(ids)
            assert raw_file(projected_path) == b"".join(line for line in raw_file(out / "gold.jsonl").splitlines(keepends=True)
                if json.loads(line)["item_id"] in census_ids)
            assert projection["approval_created"] is False and projection["full_gold"] == reference(out / "gold.jsonl")
            full_release = P.validate_release(str(release_root), approval_path=str(root / "approval.json"), approved_digest=approval["digest"])
            map_ids, map_sha = MJ._map_release_inputs(full_release, subset, projected_path, kapua=True)
            projected_map, _ = MJ._build_population_map(population, projected_path,
                release_ids=map_ids, release_sha256=map_sha, kapua_release=full_release,
                boundary_path=inputs["boundary"]["path"], items_path=subset)
            assert {iid for values in projected_map["by_mutant"].values() for iid in values} == census_ids
            assert projected_map["coverage_sha256"] == projected_sha and projected_map["release_sha256"] == reference(subset)["sha256"]
            # Same default full-R producer bytes; projection cannot change its interpretation.
            assert mapped() == (mapping, mapped_coverage)
            def projected_load():
                return load_census_projection(projected_path, subset, inputs["boundary"]["path"])
            for path in (Path(projected_path), k7 / "interfaces.json",
                         k7 / "verification.json", k7 / "input-receipt.json", root / "approval.json",
                         out / "gold.jsonl", census_root / "eval-census.provenance.json",
                         census_root / "items.jsonl"):
                before = path.read_bytes()
                path.write_bytes(before + b" ")
                refuses("census changed bytes " + str(path), projected_load)
                path.write_bytes(before)
            # A rehashed, replayable census over invented annotations still cannot
            # claim the actual recorded K7 interfaces output.
            invented = {iid: {"behaviour": ["invented.Service"], "setup": []} for iid in ids}
            original_pool = (census_root / "items.jsonl").read_bytes()
            original_census = Path(subset).read_bytes()
            original_provenance = (census_root / "eval-census.provenance.json").read_bytes()
            (census_root / "items.jsonl").write_bytes(annotated_rows(raw_file(release["items_path"]), invented))
            write_subset(SUB.sample(str(census_root / "items.jsonl"), str(census_root), n=6, seed=1), subset)
            refuses("replayed foreign annotation pool", lambda: census_selection(subset, full_release, str(k7 / "verification.json")))
            (census_root / "items.jsonl").write_bytes(original_pool)
            Path(subset).write_bytes(original_census)
            (census_root / "eval-census.provenance.json").write_bytes(original_provenance)
            refuses("census output reused", lambda: project_census(str(release_root), str(root / "approval.json"), approval["digest"],
                subset, str(k7 / "verification.json"), str(projected)))

            # Structurally complete fixture audit: exercise the REAL native report
            # and W16 asset consumers without invoking an engine or worker.
            engine_dir, applier = binding_for(population["engine"])
            engine_source = str(Path(engine_dir) / applier.source)
            engine_sha = A.sha256_file(engine_source)
            compiled = {"schema": "r2t.compiled-applier/2", "source_sha256": engine_sha,
                "interpreter": applier.interpreter, "entrypoint": applier.entrypoint,
                "classes_rel": applier.classes_rel.replace(os.sep, "/"), "classes_sha256": "a" * 64,
                "compiler_identity": compiler["parser"].split(" [", 1)[0],
                "compiler_executable_sha256": compiler["compiler_executable_sha256"],
                "runtime_identity": compiler["parser"],
                "runtime_executable_sha256": compiler["runtime_executable_sha256"], "tools_jar_sha256": None,
                "analysis_recipe_digest": population["analysis_recipe"]["digest"]}
            audit = {"schema": A.AUDIT_SCHEMA, "status": "complete", "manifest_digest": population["digest"],
                "engine": population["engine"], "engine_version": population["engine_version"], "parser": population["parser"],
                **{key: population["n"] for key in ("n_mutants", "n_attempted", "n_applied", "n_parse_valid", "n_restored")},
                "n_source_files": len(files), "bounded_roots": A._audit_roots(population),
                "source_set_sha256_before": "d" * 64, "source_set_sha256_after": "d" * 64,
                "source_lstat_sha256_before": "e" * 64, "source_lstat_sha256_after": "e" * 64,
                "failing_mutant_id": None, "failure_stage": None, "failure": None,
                "collateral": {"added": [], "changed": [], "deleted": []},
                "operator_gate": {"mode": "real_engine", "disposable_marker": A.DISPOSABLE_MARKER,
                    "engine_source_sha256": engine_sha, "runtime_parser_identity": population["parser"],
                    "runtime_parser_reported": A.expected_runtime_parser(population), "compiled_applier": compiled}}
            audit["digest"] = A.audit_digest(audit)
            write(root / "audit.json", audit)
            write(root / "population.json", population)
            write(root / "map-census.json", projected_map)
            native = root / "native-census"
            native.mkdir()
            minted = ASSETS.mint("kapua", raw_manifest_path=str(root / "population.json"),
                scored_manifest_path=str(root / "population.json"), map_path=str(root / "map-census.json"),
                coverage_path=projected_path, release_path=subset, boundary_path=inputs["boundary"]["path"],
                audit_path=str(root / "audit.json"), asset_index_out=str(native / "index.json"),
                validation_out=str(native / "validation.json"), engine_source_path=engine_source, expected_engine=MJ.ENGINE)
            native_report = minted["mutation_validation"]
            A.validate_saved_validation_report(native_report, expected_validation_class="native", require_release_ready=True)
            draw = SUB.budgeted_sample(subset, str(root / "map-census.json"), str(root / "population.json"), 100, 1)
            budget_map, budget_sidecar = write_budgeted_sample(draw, str(root / "budgeted"))
            consumer_args = {"manifest_path": str(root / "population.json"), "map_path": budget_map,
                             "release_path": subset, "budgeted_sidecar": budget_sidecar, "require_release_ready": True}
            assets = A.validate_campaign_asset_inputs(native_report, **consumer_args)
            assert assets["map"] == draw["derived_map"] and assets["population_basis"] == "budgeted_sample"
            index_path = native / "index.json"
            index_bytes = index_path.read_bytes()
            report_path = Path(native_report)
            report_bytes = report_path.read_bytes()
            index = json.loads(index_bytes)
            assert index["projects"]["kapua"]["coverage_oracle"]["projection_sha256"] == reference(projection_path(projected_path))["sha256"]
            # Update the outer report's index hash too: failure must come from
            # the consumed projection binding, not merely a stale outer digest.
            del index["projects"]["kapua"]["coverage_oracle"]["projection_sha256"]
            index_path.write_text(json.dumps(index))
            report = json.loads(report_bytes)
            report["inputs"]["asset_index"]["sha256"] = A.sha256_file(str(index_path))
            report_path.write_text(json.dumps(report))
            refuses("projected native report downgraded", lambda: A.validate_saved_validation_report(native_report, expected_validation_class="native", require_release_ready=True))
            refuses("projected W16 consumer downgraded", lambda: A.validate_campaign_asset_inputs(native_report, **consumer_args))
            index_path.write_bytes(index_bytes)
            report_path.write_bytes(report_bytes)
            projection_file = Path(projection_path(projected_path))
            projection_bytes = projection_file.read_bytes()
            projection_file.write_bytes(projection_bytes + b" ")
            refuses("changed projection receipt in W16 consumer", lambda: A.validate_campaign_asset_inputs(native_report, **consumer_args))
            projection_file.unlink()
            refuses("projection receipt omitted from native consumer", lambda: A.validate_campaign_asset_inputs(native_report, **consumer_args))
            projection_file.write_bytes(projection_bytes)
            assert A.validate_campaign_asset_inputs(native_report, **consumer_args)["map"] == draw["derived_map"]
            if pilot:
                from . import kapua_pilot as K
                K._selftest_with_gold(root, projected_path, str(out / "receipt.json"),
                                      inputs["boundary"]["path"], population, full_release)
            if headroom:
                from . import kapua_headroom as H
                H._selftest_with_gold(root, projected_path, subset, population, full_release,
                                      inputs["boundary"]["path"], engine_source, reference=reference_reuse)
            print("PASS: Kapua census/K7 projection and native/W16 provenance refusal joins")
            # The unchanged legacy campaign reader refuses these ordinary bytes.
            refuses("legacy reader accepted unstamped Kapua rows", lambda: MJ.strict_gold_coverage(str(out / "gold.jsonl"), set(ids)))
            plan = json.loads((out / "plan.json").read_bytes())
            one = next(s for s in plan["shards"] if s["expected_item_ids"])
            good = L._json_lines(raw_file(one["output"]), "fixture")
            def checked_rows(value):
                return validate_rows(b"".join((json.dumps(row) + "\n").encode() for row in value),
                    one["expected_item_ids"], one["index"], producer, files, boundary)
            for label, alter in (
                ("foreign item", lambda r: r.update(item_id="kapua/foreign:1")),
                ("not gold", lambda r: r.update(adapter="empty")),
                ("failed", lambda r: r.update(outcome="failed")),
                ("repeat2", lambda r: r.update(repeats=2)),
                ("bool repeat", lambda r: r.update(repeats=True)),
                ("no coverage", lambda r: r.update(coverage_collected=False)),
                ("mismatch", lambda r: r.update(coverage_mismatch=["lost"])),
                ("foreign source", lambda r: r.update(coverage_lines={"foreign/src/main/java/Z.java": [1]}, coverage_files={"foreign/src/main/java/Z.java": 1})),
                ("bad counts", lambda r: r.update(coverage_files={})),
                ("campaign", lambda r: r.update(campaign_digest="x")),
                ("shard", lambda r: r.update(shard=(one["index"] + 1) % WORKERS)),
                ("producer", lambda r: r.update(harness_commit="b" * 7)),
                ("direct calls", lambda r: r.update(direct_calls=None)),
            ):
                changed = copy.deepcopy(good)
                alter(changed[0])
                refuses(label, lambda: checked_rows(changed))
            refuses("duplicate", lambda: checked_rows(good + good[:1]))
            refuses("missing", lambda: checked_rows(good[1:]))
            empty = copy.deepcopy(good)
            for row in empty:
                row.update(coverage_lines={}, coverage_files={})
            checked_rows(empty)  # Collected empty coverage and high line numbers remain legal.
            for path in (out / "gold.jsonl", Path(one["output"]), out / "plan.json",
                         root / "worker0.runtime.json", root / "compiler.json", root / "native.json",
                         source / sorted(files)[0], release_root / "items.jsonl",
                         Path(one["kept_artifacts"]) / "gold" / item_key(good[0]["item_id"]) / "stdout.log"):
                before = path.read_bytes()
                path.write_bytes(before + b" ")
                refuses("changed bytes " + str(path), load)
                path.write_bytes(before)
            for protected in (source, release_root, root / "native", root / "compiler"):
                invalid_out = protected / "new-gold"
                invalid_plan = copy.deepcopy(plan)
                invalid_plan["shards"] = shard_plan(inputs, ids, pool, invalid_out,
                    plan["shards"][0]["cwd"], plan["shards"][0]["argv"][0])
                refuses("output inside input", lambda: validate_plan(invalid_plan, invalid_out,
                        release=release, native={}))
                assert not invalid_out.exists()
            altered = copy.deepcopy(plan)
            altered["shards"][0]["argv"].extend(["--campaign", "invented"])
            refuses("changed command", lambda: validate_plan(altered, out, release=release, native={}))
            altered = copy.deepcopy(plan)
            altered["shards"][one["index"]]["expected_item_ids"] = []
            refuses("changed shard membership", lambda: validate_plan(altered, out, release=release, native={}))
            partial = dict(receipt, status="failed")
            refuses("partial receipt", lambda: check_receipt(partial, plan, source_files=files, boundary=boundary))
            changed_approval = copy.deepcopy(approved)
            changed_approval["compiler_capture"]["receipt_sha256"] = "0" * 64
            refuses("capture approval mismatch", lambda: load_coverage(str(out / "receipt.json"), digest,
                    coverage_run=str(out / "gold.jsonl"), release=release, approved=changed_approval))
            refuses("output reused", lambda: collect(str(inputs_path), str(out)))
            calls = []
            def failed_run(argv, **kwargs):
                calls.append(argv)
                if len(calls) == 1:
                    return fixture_run(argv, **kwargs)
                kwargs["stdout"].write(b"actual partial failure\n")
                return SimpleNamespace(returncode=7)
            with patch.object(subprocess, "run", failed_run):
                failed_out = root / "failed"
                refuses("failed producer accepted", lambda: collect(str(inputs_path), str(failed_out)))
                assert len(calls) == 2 and (failed_out / "plan.json").is_file()
                assert (failed_out / "failure.json").is_file() and not (failed_out / "receipt.json").exists()
                failure = json.loads((failed_out / "failure.json").read_bytes())
                assert [row["index"] for row in failure["completed_shards"]] == [0]
                assert (failed_out / "shard-00/rows.jsonl").exists()
                execution = json.loads((failed_out / "shard-01/execution.json").read_bytes())
                assert execution["returncode"] == 7
    if failures:
        print("FAIL: " + "; ".join(failures))
        return 1
    print("PASS: Kapua ordinary gold producer, exact release/source/worker/row joins and partial failure")
    return 0



def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect_parser = commands.add_parser("collect")
    collect_parser.add_argument("--inputs", required=True)
    collect_parser.add_argument("--out", required=True)
    project = commands.add_parser("project-census")
    for name in ("release-root", "approval", "approved-digest", "items", "annotation-verification", "out"):
        project.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    if args.command == "collect":
        collect(args.inputs, args.out)
    else:
        project_census(args.release_root, args.approval, args.approved_digest,
                       args.items, args.annotation_verification, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
