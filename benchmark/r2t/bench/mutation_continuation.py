"""One authenticated full-gold prefix plus a disjoint, balanced suffix.

This is development evidence, never a homogeneous standalone observation or
a stable kill set. Planning and validation do not execute application tests.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os

from . import mutation_run as R
from .worker import _seed_verification_scope
from ..data import mutation_attestation as A

SCHEMA = "r2t.gold-mutation-continuation/1"
CLAIM_SCHEMA = "r2t.gold-mutation-continuation-claim/1"
SEGMENT_FIELDS = {"worker_resources_sha256", "shard", "of",
                  "expected_pairs", "expected_pairs_sha256"}


def _require(condition, message):
    if not condition:
        raise R.MutationAborted("REFUSED: continuation " + message)


def claim_path(parent_directory):
    return os.path.abspath(parent_directory) + ".continuation.json"


def refuse_parent_resume(out_path):
    _require(not os.path.lexists(claim_path(os.path.dirname(os.path.abspath(out_path)))),
             "parent has been sealed; ordinary resume is retired")


def _read(path):
    _require(not os.path.islink(path) and os.path.isfile(path),
             f"input must be a regular file: {path}")
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _reference(path):
    return {"path": os.path.abspath(path), "sha256": R.sha256_file(path)}


def _check_reference(reference):
    path = reference["path"]
    _require(os.path.abspath(path) == path and not os.path.islink(path),
             "reference must name an absolute regular file")
    _require(R.sha256_file(path) == reference["sha256"],
             f"frozen bytes changed: {path}")
    return path


def _core(identity):
    return {k: v for k, v in identity.items() if k not in SEGMENT_FIELDS}


def _full_gold(identity):
    R._validate_campaign_identity(identity)
    _require(identity["schema"] == R.MUTATION_IDENTITY_SCHEMA_V5
             and identity["kind"] == "mutation-run"
             and identity["side"] == "gold"
             and identity.get("reference_control_role") == "full-gold"
             and identity["sample"] is None
             and "continuation_plan_sha256" not in identity
             and "population_basis" not in identity,
             "requires an ordinary unsampled full-gold parent")


def _partitions(pairs, workers):
    """Existing deterministic LPT policy, applied to remaining mutant groups."""
    from .test_quality import shard_d4_confirmation_pairs
    return shard_d4_confirmation_pairs(pairs, workers)


def _assets(inputs):
    paths = {key: _check_reference(ref) for key, ref in inputs.items()}
    assets = A.validate_campaign_asset_inputs(
        paths["validation"], manifest_path=paths["manifest"],
        map_path=paths["map"], release_path=paths["release"],
        require_release_ready=True)
    rows = A.load_jsonl(paths["candidate"])
    release = A.load_release_ids(paths["release"])
    _require(len(rows) == len(release)
             and {row["item_id"] for row in rows} == release
             and all(row.get("adapter") == "gold" and row.get("outcome") == "passed"
                     for row in rows), "candidate must be the entire passing gold reference")
    from .test_quality import passed_solutions
    files = passed_solutions(rows)
    full = {(iid, mid) for mid, items in assets["map"]["by_mutant"].items()
            for iid in items}
    _require(all(iid in files for iid, _mid in full), "gold bytes do not cover full map")
    return assets, files, full


def _crash_receipt(path, parent_paths, inputs, assets, files, *, live=False):
    """Re-derive the six executed-but-uncertain pairs; never infer outcomes."""
    from pathlib import Path
    from types import SimpleNamespace
    from . import repo
    from ..core.gherkin import parse_feature_file, standalone_feature
    from ..stacks.cucumber_ruby import _complete_record
    receipt = _read(path)
    _require(receipt.get("schema") == "r2t.crash-evidence-preservation/1"
             and receipt.get("restored") is False and receipt.get("tests_executed") is False,
             "invalid crash preservation receipt")
    root = Path(path).parent
    refs = {}
    for ref in receipt["references"]:
        relative = ref["copy"]
        _require(not os.path.isabs(relative) and ".." not in Path(relative).parts
                 and relative not in refs, "ambiguous preserved reference")
        source = _check_reference({"path": ref["source"], "sha256": ref["sha256"]})
        copy = _check_reference({"path": str(root / relative), "sha256": ref["sha256"]})
        _require(os.path.getsize(copy) == ref["bytes"], "preserved length differs")
        refs[relative] = (source, Path(copy))

    def preserved(name, source=None):
        _require(name in refs, f"missing preserved evidence: {name}")
        actual, copy = refs[name]
        _require(source is None or actual == str(source), f"wrong evidence source: {name}")
        return copy

    for key, name in (("manifest", "assets/population.json"), ("map", "assets/mutant_map.json"),
                      ("validation", "assets/mutation_validation.json"),
                      ("candidate", "inputs/gold.jsonl"), ("release", "inputs/items.jsonl")):
        preserved(name, inputs[key]["path"])
    directory = Path(parent_paths[0]).parent
    preserved("parent/" + R.MUTATION_OUTPUT_PLAN, directory / R.MUTATION_OUTPUT_PLAN)
    man = repo.load_manifest(str(preserved("inputs/strip_manifest.json")))
    eligible = [m for m in assets["manifest"]["mutants"] if assets["map"]["by_mutant"].get(m["id"])]
    items = A.load_jsonl(inputs["release"]["path"])
    findings = receipt["executed_without_native_outcome"]
    _require(len(findings) == 6, "crash recovery requires exactly six uncertain pairs")
    uncertain, total, resources = set(), 0, []
    evidence = [_reference(str(p)) for source, copy in refs.values() for p in (source, copy)]
    for shard, (finding, parent) in enumerate(zip(findings, parent_paths)):
        _require(finding["worker"] == shard and finding.get("native_outcome") is None
                 and finding.get("missing") == ["process_exit", "coordinator_timeout_observation",
                    "coordinator_wall_seconds", "coordinator_attempt_count", "post_execution_cleanup"],
                 "crash finding changes missing native facts")
        preserved("parent/" + Path(parent).name, parent)
        preserved("parent/" + Path(R.provenance_path(parent)).name, R.provenance_path(parent))
        side = _read(R.provenance_path(parent))
        identity = side["campaign_identity"]
        _require(side["status"] == "running", "crash parent must retain original running status")
        _require(R.substrate_baseline_digest(SimpleNamespace(man=man)) == identity["substrate_baseline_sha256"],
                 "crash substrate baseline differs from parent")
        resource = side["worker_resources"][shard]
        spec = _read(str(preserved(f"worker{shard}/worker.json", resource["worker_spec"])))
        _require(all(spec.get(k) == resource.get(k) for k in ("workspace", "container", "env_file", "workdir")),
                 "crash worker identity differs")
        resources.append(resource)
        rows = A.load_jsonl(parent)
        sequence = [(iid, m["id"]) for m in eligible[shard::6]
                    for iid in assets["map"]["by_mutant"][m["id"]]]
        observed = [(r["item_id"], r["mutant_id"]) for r in rows]
        _require(observed == sequence[:len(rows)] and len(rows) < len(sequence)
                 and finding["durable_rows"] == len(rows), "crash rows are not exact native prefix")
        pair = sequence[len(rows)]
        _require(tuple(finding["pair"]) == pair and pair not in uncertain,
                 "uncertain pair is not unique exact next pair")
        uncertain.add(pair)
        total += len(rows)
        iid, mid = pair
        mutant = next(m for m in eligible if m["id"] == mid)
        _require(finding["mutant"] == mutant, "crash mutant differs from native manifest")
        workspace = Path(spec["workspace"])
        prefix = f"worker{shard}/"
        pristine = preserved(prefix + "pristine/" + mutant["file"])
        source = Path(refs[prefix + "pristine/" + mutant["file"]][0])
        source_root = source
        for _ in Path(mutant["file"]).parts:
            source_root = source_root.parent
        feature_bytes = preserved(prefix + "item.feature", workspace / "_bench/item.feature").read_bytes()
        matches = []
        for item in items:
            feature_path = source_root / item["provenance"]["file_path"]
            feature = parse_feature_file(str(feature_path))
            rendered = standalone_feature(feature, feature.scenario_at(item["provenance"]["line"]))
            evidence.append(_reference(str(feature_path)))
            if rendered.encode() == feature_bytes:
                matches.append(item["item_id"])
        _require(matches == [iid], "rendered feature does not uniquely identify next item")
        for produced in files[iid]:
            _require(preserved(prefix + "gold/" + produced["file_path"],
                               workspace / produced["file_path"]).read_bytes() == produced["code"].encode(),
                     "staged gold differs from native candidate")
        records = A.load_jsonl(str(preserved(prefix + "run_record.jsonl", workspace / "_bench/run_record.jsonl")))
        _require(len(records) == 1 and _complete_record(records[0], False)
                 and finding["recorded_scenario_result"] == records[0]["scenario_result"],
                 "missing or contradictory terminal scenario record")
        rendered_feature = parse_feature_file(str(preserved(prefix + "item.feature")))
        _require(len(rendered_feature.scenarios) == 1
                 and records[0]["feature_file"] == "_bench/item.feature"
                 and records[0]["feature_title"] == rendered_feature.title
                 and records[0]["scenario_title"] == rendered_feature.scenarios[0].title
                 and records[0]["scenario_line"] == rendered_feature.scenarios[0].line,
                 "terminal recorder does not identify the rendered scenario")
        original = pristine.read_bytes()
        actual = preserved(prefix + "applied/" + mutant["file"], workspace / mutant["file"]).read_bytes()
        offset = sum(map(len, original.splitlines(keepends=True)[:mutant["start_line"] - 1])) + mutant["start_col"] - 1
        before = mutant["original"].encode()
        _require(original[offset:offset + len(before)] == before
                 and actual == original[:offset] + mutant["mutated"].encode() + original[offset + len(before):],
                 "applied bytes are not exactly the declared mutant")
        inventory_path = str(root / prefix / "substrate-inventory.json")
        inventory = _read(inventory_path)
        evidence.append(_reference(inventory_path))
        _require(man.digests[mutant["file"]] == R.sha256_file(str(pristine)), "pristine mutant bytes differ from baseline")
        expected = {**man.digests, mutant["file"]: R.sha256_file(str(preserved(prefix + "applied/" + mutant["file"])))}
        _require(inventory == expected, "preserved inventory has collateral substrate changes")
        if live:
            from ..core.boundary import load_boundary
            boundary_path = Path(__file__).resolve().parents[2] / "config/boundary_e_petitions.yml"
            boundary = load_boundary(str(boundary_path), repo_root=str(workspace))
            _require(repo.substrate_digests(str(workspace), boundary, man.roots(), man.volatile()) == inventory,
                     "quarantined workspace differs from preserved inventory")
        for stage in ("before", "after"):
            inspect_path = str(root / f"{stage}-inspect-{shard}.json")
            inspected_record = _read(inspect_path)
            evidence.append(_reference(inspect_path))
            _require(inspected_record["exit"] == 0, "preserved container inspection failed")
            inspected = json.loads(inspected_record["stdout"])[0]
            _require(inspected["Image"] == identity["container_image_digest"]
                     and inspected["Name"].lstrip("/") == resource["container"]
                     and not inspected.get("ExecIDs") and not inspected["State"].get("Restarting")
                     and not inspected["State"].get("Paused"), "preserved container was not quiescent")
            if inspected["State"]["Running"]:
                top_path = str(root / f"{stage}-top-{shard}.json")
                top = _read(top_path)
                evidence.append(_reference(top_path))
                processes = [line.split(None, 2) for line in top["stdout"].splitlines()[1:] if line.strip()]
                _require(top["exit"] == 0 and processes
                         and all(len(row) == 3 and row[1] in {"postgres", "tail"} for row in processes),
                         "preserved worker had test processes")
            host_path = str(root / f"{stage}-host-processes.json")
            _require(_read(host_path) == {"active_coordinators": []}, "preserved coordinator was live")
            evidence.append(_reference(host_path))
    _require(total == receipt["durable_rows"] == 2401
             and len({(iid, mid) for mid, ids in assets["map"]["by_mutant"].items() for iid in ids}) == 127449,
             "receipt is outside the reviewed 2401-row/127449-pair recovery")
    if live:
        _crash_quiescence(resources, directory, identity["container_image_digest"])
    # Bind evidence not included in the original preservation reference array.
    return uncertain, sorted({(r["path"], r["sha256"]) for r in evidence})


def _host_pid_present(state):
    """Use /proc absence only in the configured local daemon's PID namespace."""
    from pathlib import Path
    from ..core import docker_cli
    pid = state.get("Pid")
    _require(isinstance(pid, int) and pid >= 0, "container has no host PID identity")
    if not state["Running"]:
        return False
    if Path("/proc", str(pid)).exists():
        return True
    document, _reference_value = docker_cli.authority_reference(live=False)
    endpoint = document["endpoint"]["address"]
    data_root = document["daemon"]["docker_root_dir"]
    observer = os.readlink("/proc/self/ns/pid")
    matched = []
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            argv = (process / "cmdline").read_bytes().decode().split("\0")
            if (argv and Path(argv[0]).name == "dockerd"
                    and "--host=" + endpoint in argv
                    and "--data-root=" + data_root in argv):
                matched.append(os.readlink(process / "ns/pid"))
        except (OSError, UnicodeError):
            continue
    _require(matched == [observer], "cannot prove observer shares selected daemon PID namespace")
    return False


def _crash_quiescence(resources, directory, image):
    """Read-only admission under resource/output locks; never docker exec."""
    import subprocess
    from pathlib import Path
    from ..core import docker_cli
    for resource in resources:
        def docker(args):
            result = subprocess.run(docker_cli.docker_argv(args), capture_output=True, text=True, timeout=120)
            _require(result.returncode == 0, "cannot inspect crashed container")
            return result.stdout
        inspected = json.loads(docker(["inspect", resource["container"]]))[0]
        state = inspected["State"]
        host_pid_present = _host_pid_present(state)
        _require(inspected["Image"] == image and not state.get("Restarting")
                 and not state.get("Paused")
                 and (not state["Running"] or not host_pid_present or not inspected.get("ExecIDs")), "crashed container is not quiescent")
        if state["Running"] and host_pid_present:
            processes = [line.split(None, 2) for line in docker(["top", resource["container"], "-eo", "pid,comm,args"]).splitlines()[1:] if line.strip()]
            _require(processes and all(len(row) == 3 and row[1] in {"postgres", "tail"} for row in processes),
                     "crashed container still has test processes")
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            args = (proc / "cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        _require(not ((b"mutation-run" in args and any(str(directory).encode() in a for a in args))
                      or (b"/tmp/epmut-operate-r9.py" in args and b"run" in args)),
                 "parent coordinator is still live")


@_seed_verification_scope()
def _snapshot(parent_paths, inputs, child_workers, crash_recovery=None, *, live=False):
    assets, files, full = _assets(inputs)
    eligible = [m for m in assets["manifest"]["mutants"]
                if assets["map"]["by_mutant"].get(m["id"])]
    uncertain, crash_evidence = (set(), [])
    if crash_recovery is not None:
        uncertain, crash_evidence = _crash_receipt(
            _check_reference(crash_recovery), parent_paths, inputs, assets, files, live=live)
    parents = []
    done = set()
    representative = None
    directory = os.path.dirname(os.path.abspath(parent_paths[0]))
    _require(len(parent_paths) == 6 and child_workers == 24,
             "this reviewed route is six parents to 24 children")
    _require(len(set(map(os.path.abspath, parent_paths))) == 6
             and all(os.path.dirname(os.path.abspath(p)) == directory for p in parent_paths),
             "parents must be six distinct shards in one directory")
    for shard, path in enumerate(parent_paths):
        side = _read(R.provenance_path(path))
        identity = side["campaign_identity"]
        _full_gold(identity)
        _require(identity["of"] == 6 and identity["shard"] == shard,
                 "parent shards must be in zero-based order")
        _require((side["status"] in {"interrupted", "complete"}
                  or (crash_recovery is not None and side["status"] == "running")),
                 "parent is live, failed, or not cooperatively stopped")
        if representative is None:
            representative = identity
        _require(_core(identity) == _core(representative)
                 and identity["worker_resources_sha256"] == representative["worker_resources_sha256"],
                 "parent campaign/runtime identities differ")
        R.validate_worker_resource_evidence(side, identity)
        expected = R.expected_pairs_for_slice(
            eligible[shard::6], assets["map"]["by_mutant"], files)
        observed = R.completed_pairs(path, identity, expected_pairs=expected,
                                     require_complete=side["status"] == "complete")
        _require(not done.intersection(observed), "parent pairs overlap")
        done.update(observed)
        parents.append({"rows": _reference(path),
                        "sidecar": _reference(R.provenance_path(path))})
    R.validate_standalone_output_directory(parent_paths, representative)
    wanted = {
        "asset_index_sha256": assets["asset_index_sha256"],
        "mutation_validation_sha256": inputs["validation"]["sha256"],
        "manifest_sha256": inputs["manifest"]["sha256"],
        "manifest_digest": assets["manifest"]["digest"],
        "map_sha256": inputs["map"]["sha256"],
        "release_sha256": inputs["release"]["sha256"],
        "candidate_run_sha256": inputs["candidate"]["sha256"],
        "candidate_generated_tests_sha256": R.candidate_digest(files),
        "solution_generated_tests_sha256": R.candidate_digest(files),
    }
    _require(all(representative[k] == v for k, v in wanted.items()),
             "parent population or reference differs from native inputs")
    _require(done <= full, "parent has foreign pairs")
    _require(uncertain <= full and not uncertain.intersection(done), "uncertain pairs overlap or are foreign")
    pending = full - done - uncertain
    partitions = _partitions(pending, child_workers)
    _require(all(partitions), "pending population leaves an empty child partition")
    plan = {
        "schema": SCHEMA, "parents": parents,
        "parent_output_plan": _reference(os.path.join(directory, R.MUTATION_OUTPUT_PLAN)),
        "inputs": inputs, "parent_identity": representative,
        "child_workers": child_workers,
        "full_pairs": len(full), "full_pairs_sha256": R.pair_set_digest(full),
        "completed_pairs": len(done), "completed_pairs_sha256": R.pair_set_digest(done),
        "partitions": [sorted(map(list, part)) for part in partitions],
    }
    if crash_recovery is not None:
        plan.update(crash_recovery=crash_recovery, uncertain_pairs=sorted(map(list, uncertain)),
                    crash_evidence=[{"path": p, "sha256": sha} for p, sha in crash_evidence])
    return plan, done, full


def prepare_continuation(parent_paths, *, mutation_validation_path, manifest_path,
                         map_path, release_path, candidate_run_path,
                         child_workers=24, plan_out, crash_recovery_path=None):
    """Seal quiescent native parents without changing their evidence bytes."""
    parent_paths = list(map(os.path.abspath, parent_paths))
    _require(bool(parent_paths), "parent paths are required")
    directory = os.path.dirname(parent_paths[0])
    claim = claim_path(directory)
    _require(not os.path.lexists(claim), "parent already has a continuation claim")
    inputs = {key: _reference(path) for key, path in {
        "validation": mutation_validation_path, "manifest": manifest_path,
        "map": map_path, "release": release_path, "candidate": candidate_run_path}.items()}
    with ExitStack() as stack:
        for path in sorted(parent_paths):
            stack.enter_context(R.output_lock(path))
        resources = []
        from .worker import resource_fields
        for path in parent_paths:
            side = _read(R.provenance_path(path))
            fields = resource_fields(side["campaign_identity"]["database_dump_digest"] != "no_database")
            for resource in side["worker_resources"]:
                resources.extend((key, resource[key]) for key in fields if resource.get(key))
        stack.enter_context(R.mutation_resource_locks(resources))
        plan, _done, _full = _snapshot(parent_paths, inputs, child_workers,
            _reference(crash_recovery_path) if crash_recovery_path is not None else None, live=True)
        _require(not os.path.lexists(claim), "parent claim appeared while acquiring locks")
        # Keep the marker outside the strictly closed native output directory.
        encoded = (json.dumps(plan, sort_keys=True, indent=2) + "\n").encode()
        plan_out = os.path.abspath(plan_out)
        _require(os.path.commonpath([directory, plan_out]) != directory,
                 "plan must be outside the parent output directory")
        R.atomic_write_bytes(plan_out, encoded, refuse_existing=True)
        marker = {"schema": CLAIM_SCHEMA, "plan": _reference(plan_out)}
        R.atomic_write_bytes(claim, (json.dumps(marker, sort_keys=True) + "\n").encode(),
                             refuse_existing=True)
    return plan


SUFFIX_SCHEMA = "r2t.gold-mutation-suffix-recovery/1"
INCIDENT_SCHEMA = "r2t.gold-mutation-suffix-incident/1"
APPLIED_WORKERS = {13, 17, 23}
RESET_WORKERS = {2, 3, 4, 7, 10, 14, 18, 21}
RESERVED_WORKERS = set(range(24))
PID_CLEANUP_WORKERS = RESERVED_WORKERS - APPLIED_WORKERS - RESET_WORKERS


def _suffix_failure(shard, side, stderr):
    """This incident's missing causes remain missing; no outcome inference."""
    error = side.get("error", "")
    if shard in {13, 17}:
        _require(side["status"] == "failed" and error.startswith(
            "MutationAborted: REFUSED: mutation campaign cleanup/restoration failed:")
            and "still declares a mutation" in error and "cleanup/restoration failed" in stderr,
            "masked suffix cleanup failure differs")
    elif shard == 23:
        _require(side["status"] == "running" and not error
                 and "write_shard_provenance" in stderr and "No space left on device" in stderr
                 and ".r2t-stage-gold.w23.jsonl.provenance.json-" in stderr,
                 "masked suffix sidecar failure differs")
    elif shard in RESET_WORKERS:
        _require(side["status"] == "failed"
                 and error.startswith("RuntimeError: Ruby bootstrap failed during reset:")
                 and "No space left on device" in error
                 and error.removeprefix("RuntimeError: ").strip() in stderr,
                 "suffix reset failure differs")
    elif shard in PID_CLEANUP_WORKERS and side["status"] == "failed":
        timed_out = (error.startswith("TimeoutExpired: Command")
                     and "subprocess.TimeoutExpired" in stderr
                     and (("rm -f /tmp/r2t-ruby-" in error and "timed out after 60 seconds" in error)
                          or ("_bench/compile_check.rb" in error and "timed out after 300 seconds" in error)))
        reset = (error.startswith("RuntimeError: Ruby bootstrap failed during reset:")
                 and "procReady not received" in error and error.strip() in stderr)
        _require(timed_out or reset, "suffix PID-exhaustion failure differs")
    else:
        _require(side["status"] == "interrupted" and error in {
            "MutationCancelled: mutation campaign cancelled between item executions",
            "MutationCancelled: mutation campaign cancelled between mutants",
            "MutationCancelled: mutation campaign cancelled after mutant restoration"},
            "suffix lacks native cooperative cleanup evidence")


def _suffix_prefix(path, identity, sequence):
    check = R.verify_shard(path)
    _require(check["identity_consistent"] and check["rows_consistent"],
             "suffix native identity or row hash differs")
    rows = A.load_jsonl(path)
    digest = R.campaign_identity_digest(identity)
    _require(all(not R._row_identity_problems(row, identity, digest) for row in rows),
             "suffix row stamp differs")
    observed = [(row["item_id"], row["mutant_id"]) for row in rows]
    _require(len(observed) < len(sequence) and observed == sequence[:len(observed)]
             and len(set(observed)) == len(observed), "suffix is not an exact incomplete assigned prefix")
    return set(observed), sequence[len(observed)]


def _suffix_inspection(resources, directory, image):
    """Read-only container/host proof, frozen into the incident receipt."""
    import subprocess
    from ..core import docker_cli
    _crash_quiescence(resources, directory, image)
    result = []
    for resource in resources:
        row = {}
        for kind, args in (("inspect", ["inspect", resource["container"]]),
                           ("top", ["top", resource["container"], "-eo", "pid,comm,args"])):
            if kind == "top":
                state = json.loads(row["inspect"])[0]["State"]
                row["host_pid_present"] = _host_pid_present(state)
                if state["Running"] and not row["host_pid_present"]:
                    row["host_pid_namespace"] = os.readlink("/proc/self/ns/pid")
                if not state["Running"] or not row["host_pid_present"]:
                    row[kind] = ""
                    continue
            cp = subprocess.run(docker_cli.docker_argv(args), capture_output=True, text=True, timeout=120)
            _require(cp.returncode == 0, "suffix container inspection failed")
            row[kind] = cp.stdout
        result.append(row)
    _validate_suffix_inspection(result, resources, image)
    return result


def _validate_suffix_inspection(proof, resources, image):
    _require(len(proof) == 24, "suffix inspection pool incomplete")
    for row, resource in zip(proof, resources):
        inspected = json.loads(row["inspect"])[0]
        state = inspected["State"]
        _require(inspected["Image"] == image and inspected["Name"].lstrip("/") == resource["container"]
                 and (not state["Running"] or row.get("host_pid_present") is False or not inspected.get("ExecIDs"))
                 and not state.get("Paused") and not state.get("Restarting"),
                 "suffix inspection is not quiescent")
        if state["Running"] and row.get("host_pid_present") is False:
            _require(isinstance(row.get("host_pid_namespace"), str) and row["host_pid_namespace"].startswith("pid:["),
                     "missing shared daemon PID-namespace witness")
        if state["Running"] and row.get("host_pid_present", True):
            processes = [line.split(None, 2) for line in row["top"].splitlines()[1:] if line.strip()]
            _require(processes and all(len(p) == 3 and p[1] in {"postgres", "tail"} for p in processes),
                     "suffix inspection contains test processes")


def _suffix_incident(prior, parent_paths, command_directories):
    from pathlib import Path
    from types import SimpleNamespace
    from . import repo
    from ..core.boundary import load_boundary
    side = _read(R.provenance_path(parent_paths[0]))
    resources = side["worker_resources"]
    image = prior["parent_identity"]["container_image_digest"]
    directory = Path(parent_paths[0]).parent
    before = _suffix_inspection(resources, directory, image)
    # Original recovery already authenticates this exact strip manifest.
    original = _read(prior["plan"]["crash_recovery"]["path"])
    strip = next(ref["source"] for ref in original["references"]
                 if ref["copy"] == "inputs/strip_manifest.json")
    man = repo.load_manifest(strip)
    _require(R.substrate_baseline_digest(SimpleNamespace(man=man)) == prior["parent_identity"]["substrate_baseline_sha256"],
             "suffix strip baseline differs")
    workers = []
    for i, (resource, command) in enumerate(zip(resources, command_directories)):
        workspace = resource["workspace"]
        boundary = load_boundary(str(Path(__file__).resolve().parents[2] / "config/boundary_e_petitions.yml"),
                                 repo_root=workspace)
        inventory = repo.substrate_digests(workspace, boundary, man.roots(), man.volatile())
        workers.append({"inventory": inventory, "command": {
            name: _reference(os.path.join(command, name)) for name in ("started.json", "finished.json", "stderr")}})
    after = _suffix_inspection(resources, directory, image)
    return {"schema": INCIDENT_SCHEMA, "strip_manifest": _reference(strip),
            "before": before, "after": after, "workers": workers}


@_seed_verification_scope()
def _suffix_snapshot(prior_path, parent_paths, incident):
    from pathlib import Path
    from types import SimpleNamespace
    from . import repo
    prior = validate_plan(prior_path)
    _require(prior["plan"]["schema"] == SCHEMA and len(prior["uncertain"]) == 6
             and "crash_recovery" in prior["plan"],
             "suffix recovery requires the reviewed six-uncertain original plan")
    _require(len(parent_paths) == 24 and len(set(parent_paths)) == 24
             and len({os.path.dirname(p) for p in parent_paths}) == 1,
             "suffix recovery requires all 24 distinct native shards")
    _require(incident["schema"] == INCIDENT_SCHEMA and len(incident["workers"]) == 24,
             "invalid suffix incident receipt")
    man = repo.load_manifest(_check_reference(incident["strip_manifest"]))
    _require(R.substrate_baseline_digest(SimpleNamespace(man=man)) == prior["parent_identity"]["substrate_baseline_sha256"],
             "suffix baseline differs from native identity")
    assets, files, _full = _assets(prior["plan"]["inputs"])
    done, unresolved, parents, protected = set(), set(), [], []
    resources = None
    for i, path in enumerate(parent_paths):
        side = _read(R.provenance_path(path))
        identity = side["campaign_identity"]
        _require(identity["shard"] == i and identity.get("continuation_plan_sha256") == prior["plan_sha256"],
                 "suffix parent does not bind its prior partition")
        validate_identity(prior, identity)
        validate_child_resources(prior, side["worker_resources"])
        R.validate_worker_resource_evidence(side, identity)
        if resources is None:
            resources = side["worker_resources"]
        _require(resources == side["worker_resources"], "suffix resource pools differ")
        sequence = [(iid, m["id"]) for m in assets["manifest"]["mutants"]
                    for iid in assets["map"]["by_mutant"].get(m["id"], [])
                    if (iid, m["id"]) in prior["partitions"][i]]
        observed, next_pair = _suffix_prefix(path, identity, sequence)
        _require(not done.intersection(observed), "suffix native prefixes overlap")
        done.update(observed)
        proof = incident["workers"][i]
        command = {name: _check_reference(ref) for name, ref in proof["command"].items()}
        _require(set(command) == {"started.json", "finished.json", "stderr"}, "suffix command evidence incomplete")
        protected.extend(command.values())
        started, finished = _read(command["started.json"]), _read(command["finished.json"])
        argv = started["argv"]
        _require(started["worker"] == finished["worker"] == i
                 and type(finished["exit"]) is int and finished["exit"] != 0
                 and argv[argv.index("--out") + 1] == path
                 and argv[argv.index("--worker") + 1] == resources[i]["worker_spec"]
                 and argv[argv.index("--continuation-plan") + 1] == os.path.abspath(prior_path),
                 "suffix command receipt names another invocation")
        stderr = Path(command["stderr"]).read_text()
        _suffix_failure(i, side, stderr)
        inventory = proof["inventory"]
        if i in RESERVED_WORKERS:
            unresolved.add(next_pair)
        if i in APPLIED_WORKERS:
            mutant = next(m for m in assets["manifest"]["mutants"] if m["id"] == next_pair[1])
            # These three retain the current mutant. The incident does not
            # assert whether the next item ran, regardless of recorder absence.
            source = Path(resources[i]["workspace"]) / mutant["file"]
            raw = source.read_bytes()
            original_ref = next(ref for ref in _read(prior["plan"]["crash_recovery"]["path"])["references"]
                                if ref["copy"] == "inputs/strip_manifest.json")
            source_root = Path(original_ref["source"]).parent.parent / "source"
            original = (source_root / mutant["file"]).read_bytes()
            _require(R.sha256_file(str(source_root / mutant["file"])) == man.digests[mutant["file"]],
                     "suffix pristine bytes differ")
            offset = sum(map(len, original.splitlines(keepends=True)[:mutant["start_line"] - 1])) + mutant["start_col"] - 1
            before = mutant["original"].encode()
            _require(original[offset:offset + len(before)] == before
                     and raw == original[:offset] + mutant["mutated"].encode() + original[offset + len(before):],
                     "suffix held worker does not contain its declared mutant")
            expected = {**man.digests, mutant["file"]: R.sha256_file(str(source))}
            protected.extend([str(source), str(source_root / mutant["file"])])
        else:
            expected = man.digests
        _require(inventory == expected, "suffix inventory has unaccounted source changes")
        parents.append({"rows": _reference(path), "sidecar": _reference(R.provenance_path(path))})
    for stage in ("before", "after"):
        _validate_suffix_inspection(incident[stage], resources, prior["parent_identity"]["container_image_digest"])
    R.validate_standalone_output_directory(parent_paths, _read(R.provenance_path(parent_paths[0]))["campaign_identity"])
    # A reset error may have occurred on the infrastructure retry. Preserve
    # its next pair as pending too; the absent first attempt is not inferred.
    _require(len(unresolved) == 24 and not unresolved.intersection(done | prior["completed"] | prior["uncertain"]),
             "held suffix pairs overlap retained observations")
    completed = prior["completed"] | done
    pending = prior["full"] - completed - prior["uncertain"] - unresolved
    partitions = _partitions(pending, 24)
    _require(all(partitions), "suffix recovery leaves empty child partition")
    plan = {"schema": SUFFIX_SCHEMA, "prior_plan": _reference(prior_path), "parents": parents,
            "parent_output_plan": _reference(os.path.join(os.path.dirname(parent_paths[0]), R.MUTATION_OUTPUT_PLAN)),
            "parent_identity": prior["parent_identity"], "inputs": prior["plan"]["inputs"],
            "child_workers": 24, "full_pairs": len(prior["full"]),
            "completed_pairs": len(completed), "completed_pairs_sha256": R.pair_set_digest(completed),
            "suffix_pairs": len(done), "unresolved_pairs": sorted(map(list, unresolved)),
            "uncertain_pairs": sorted(map(list, prior["uncertain"])),
            "partitions": [sorted(map(list, part)) for part in partitions]}
    return plan, prior, completed, unresolved, resources, protected


def prepare_suffix_recovery(prior_plan_path, parent_paths, *, command_directories, plan_out):
    """Seal this storage-failed suffix; hold twenty-four unresolved pairs unfinished."""
    parent_paths = list(map(os.path.abspath, parent_paths))
    _require(len(parent_paths) == len(command_directories) == 24, "suffix recovery needs 24 parents and command directories")
    directory = os.path.dirname(parent_paths[0])
    plan_out = os.path.abspath(plan_out)
    _require(os.path.commonpath([directory, plan_out]) != directory, "suffix plan must be outside parent outputs")
    claim = claim_path(directory)
    with ExitStack() as stack:
        for path in sorted(parent_paths):
            stack.enter_context(R.output_lock(path))
        _require(not os.path.lexists(claim), "suffix already sealed")
        from .worker import resource_fields
        side = _read(R.provenance_path(parent_paths[0]))
        fields = resource_fields(side["campaign_identity"]["database_dump_digest"] != "no_database")
        stack.enter_context(R.mutation_resource_locks([(k, r[k]) for r in side["worker_resources"] for k in fields if r.get(k)]))
        prior = validate_plan(prior_plan_path)
        incident = _suffix_incident(prior, parent_paths, command_directories)
        plan, *_ = _suffix_snapshot(prior_plan_path, parent_paths, incident)
        incident_path = plan_out + ".incident.json"
        R.atomic_write_json(incident_path, incident, refuse_existing=True)
        plan["incident"] = _reference(incident_path)
        R.atomic_write_json(plan_out, plan, refuse_existing=True)
        R.atomic_write_json(claim, {"schema": CLAIM_SCHEMA, "plan": _reference(plan_out)}, refuse_existing=True)
    return plan


def _validate_suffix_plan(path, plan):
    prior_path = _check_reference(plan["prior_plan"])
    parents = [_check_reference(p["rows"]) for p in plan["parents"]]
    for row in plan["parents"]:
        _check_reference(row["sidecar"])
    _check_reference(plan["parent_output_plan"])
    incident_path = _check_reference(plan["incident"])
    marker = claim_path(os.path.dirname(parents[0]))
    _require(_read(marker) == {"schema": CLAIM_SCHEMA, "plan": _reference(path)}, "suffix claim names another plan")
    derived, prior, done, unresolved, resources, protected = _suffix_snapshot(prior_path, parents, _read(incident_path))
    derived["incident"] = plan["incident"]
    _require(derived == plan, "suffix plan does not rederive from frozen evidence")
    return {**prior, "plan": plan, "plan_sha256": R.sha256_file(path),
            "partitions": [{tuple(pair) for pair in part} for part in plan["partitions"]],
            "completed": done, "unresolved": unresolved,
            "parent_resources": prior["parent_resources"] + resources,
            "containment_paths": prior["containment_paths"] + [r["workspace"] for r in resources],
            "protected_paths": prior["protected_paths"] + [path, marker, incident_path,
                plan["parent_output_plan"]["path"], *protected, *parents,
                *[R.provenance_path(p) for p in parents],
                *[r[k] for r in resources for k in ("env_file", "worker_spec", "runtime_attestation") if r.get(k)]]}


def validate_plan(path):
    path = os.path.abspath(path)
    plan = _read(path)
    if plan.get("schema") == "r2t.prestashop-retained-prefix/1":
        from . import prestashop_continuation as P
        return P.validate_plan(path)
    if plan.get("schema") == "r2t.gold-mutation-host-assignment/1":
        from .mutation_distribution import validate_assignment
        return validate_assignment(path)
    if plan.get("schema") == SUFFIX_SCHEMA:
        return _validate_suffix_plan(path, plan)
    _require(plan.get("schema") == SCHEMA, "unsupported plan schema")
    parent_paths = [_check_reference(row["rows"]) for row in plan["parents"]]
    for row in plan["parents"]:
        _check_reference(row["sidecar"])
    _check_reference(plan["parent_output_plan"])
    marker_path = claim_path(os.path.dirname(parent_paths[0]))
    _require(_read(marker_path) == {"schema": CLAIM_SCHEMA, "plan": _reference(path)},
             "parent claim names a different plan")
    for ref in plan.get("crash_evidence", []):
        _check_reference(ref)
    derived, done, full = _snapshot(parent_paths, plan["inputs"], plan["child_workers"],
                                    plan.get("crash_recovery"))
    _require(plan == derived, "plan does not rederive from frozen parent and full assets")
    for row in plan["parents"]:
        _check_reference(row["rows"])
        _check_reference(row["sidecar"])
    resources = _read(R.provenance_path(parent_paths[0]))["worker_resources"]
    return {"plan": plan, "plan_sha256": R.sha256_file(path),
            "partitions": [{tuple(pair) for pair in part} for part in plan["partitions"]],
            "parent_identity": plan["parent_identity"],
            "parent_resources": resources,
            "completed": done, "full": full,
            "uncertain": {tuple(pair) for pair in plan.get("uncertain_pairs", [])},
            "containment_paths": [r["workspace"] for r in resources],
            "protected_paths": [path, marker_path, *parent_paths,
                                *([plan["crash_recovery"]["path"]] if "crash_recovery" in plan else []),
                                *[ref["path"] for ref in plan.get("crash_evidence", [])],
                                *[R.provenance_path(p) for p in parent_paths],
                                plan["parent_output_plan"]["path"],
                                *[ref["path"] for ref in plan["inputs"].values()],
                                *[r[k] for r in resources for k in
                                  ("env_file", "worker_spec", "runtime_attestation")
                                  if r.get(k)]]}


def validate_child_resources(binding, resources):
    """All suffix workers must be new, including their mutable container state."""
    from .worker import resource_fields
    fields = resource_fields(binding["parent_identity"]["database_dump_digest"] != "no_database")
    _require(len(resources) == len(binding["partitions"]), "child resource pool is incomplete")
    for field in fields:
        parent_values = {r[field] for r in binding["parent_resources"] if r.get(field)}
        child_values = {r[field] for r in resources if r.get(field)}
        _require(not parent_values.intersection(child_values),
                 f"child reuses parent {field}")


def validate_identity(binding, identity):
    """Bind an otherwise ordinary child identity to its exact pending slice."""
    if binding.get("plan", {}).get("schema") == "r2t.prestashop-retained-prefix/1":
        from . import prestashop_continuation as P
        return P.validate_identity(binding, identity)
    result = dict(identity)
    recorded = result.pop("continuation_plan_sha256", binding["plan_sha256"])
    _require(recorded == binding["plan_sha256"], "child names another plan")
    _full_gold(result)
    _require(_core(result) == _core(binding["parent_identity"]),
             "child changes population/reference/source/runtime/timeout identity")
    _require(result["of"] == len(binding["partitions"])
             and 0 <= result["shard"] < result["of"], "child allocation differs")
    pairs = binding["partitions"][result["shard"]]
    _require(result["expected_pairs"] == len(pairs)
             and result["expected_pairs_sha256"] == R.pair_set_digest(pairs),
             "child pair set differs from its pending partition")
    _require(result["worker_resources_sha256"] != binding["parent_identity"]["worker_resources_sha256"],
             "child must use a fresh worker pool")
    result["continuation_plan_sha256"] = recorded
    R._validate_campaign_identity(result)
    return result


def validate_continued_observation(plan_path, child_paths):
    binding = validate_plan(plan_path)
    _require(binding["plan"].get("schema") != "r2t.prestashop-retained-prefix/1",
             "PrestaShop transitions require the typed reader")
    child_paths = list(child_paths)
    _require(len(child_paths) == len(binding["partitions"]), "child shard set incomplete")
    pending = set().union(*binding["partitions"])
    for shard, path in enumerate(child_paths):
        sidecar = _read(R.provenance_path(path))
        identity = sidecar["campaign_identity"]
        validate_child_resources(binding, sidecar["worker_resources"])
        _require(identity["shard"] == shard, "children must be in zero-based order")
        _require("continuation_plan_sha256" in identity, "child is not plan-bound")
        validate_identity(binding, identity)
        R.completed_pairs(path, identity, expected_pairs=binding["partitions"][shard],
                          require_complete=True)
    child = R.validate_native_shards(child_paths, expected_pairs=pending,
                                    required_side="gold", return_campaign=True,
                                    _continuation_plan_sha256=binding["plan_sha256"])
    unresolved = binding.get("unresolved", set())
    _require(not unresolved.intersection(child["pairs"])
             and not binding["completed"].intersection(child["pairs"])
             and not binding["uncertain"].intersection(child["pairs"])
             and binding["completed"] | binding["uncertain"] | unresolved | child["pairs"] == binding["full"],
             "aggregate has overlap or missing pairs")
    return {"schema": "r2t.continued-gold-observation/1",
            "label": "single continued development gold observation",
            "plan_sha256": binding["plan_sha256"],
            "parent_pairs": len(binding["completed"]), "child_pairs": len(child["pairs"]),
            "pairs": len(binding["full"]), "worker_transition": [6, 24, 24] if unresolved else [6, 24],
            "preserved_suffix_pairs": binding["plan"].get("suffix_pairs", 0),
            "native_pairs": len(binding["completed"]) + len(child["pairs"]),
            "uncertain_pairs": sorted(map(list, binding["uncertain"])),
            "unresolved_pairs": sorted(map(list, unresolved)), "complete": not unresolved,
            "accounted_pairs": len(binding["full"]) - len(unresolved),
            "parent_identity": binding["parent_identity"],
            "child_identity": child["campaign_identity"],
            "child_observation_id": child["observation_id"], "stable_killset": False}


def selftest():
    """Real native rows/plans/locks; only external asset/runtime fixtures are stubbed."""
    import tempfile
    from pathlib import Path
    from unittest.mock import patch

    def refused(fn):
        try:
            fn()
        except (R.MutationAborted, A.MutationAssetRefused, OSError, ValueError):
            return
        raise AssertionError("operation unexpectedly accepted")

    with tempfile.TemporaryDirectory(prefix="r2t-gold-continuation-") as temp:
        root = Path(temp)
        parents = root / "parents"
        parents.mkdir()
        files = {"i1": [{"file_path": "steps/x.rb", "code": "pass"}],
                 "i2": [{"file_path": "steps/x.rb", "code": "pass"}]}
        mutants = [{"id": f"m{i:03d}"} for i in range(72)]
        mapping = {m["id"]: ["i1", "i2"] for m in mutants}
        manifest = {"mutants": mutants, "digest": "a" * 64}
        paths = {}
        for key, value in (("manifest", manifest), ("map", {"by_mutant": mapping}),
                           ("validation", {})):
            paths[key] = str(root / (key + ".json"))
            Path(paths[key]).write_text(json.dumps(value))
        paths["release"] = str(root / "release.jsonl")
        Path(paths["release"]).write_text(''.join(json.dumps({"item_id": i}) + '\n' for i in files))
        paths["candidate"] = str(root / "gold.jsonl")
        Path(paths["candidate"]).write_text(''.join(json.dumps({
            "item_id": i, "adapter": "gold", "outcome": "passed", "produced_files": f}) + '\n'
            for i, f in files.items()))
        assets = {"manifest": manifest, "map": {"by_mutant": mapping},
                  "asset_index_sha256": "e" * 64}
        references = {k: _reference(p) for k, p in paths.items()}
        generated = R.candidate_digest(files)

        def identity(pairs, shard, workers, resource_hash="b" * 64):
            return R.build_campaign_identity(
                asset_index_sha256="e" * 64, asset_project="fixture",
                mutation_validation_sha256=references["validation"]["sha256"],
                mutation_validation_class="native",
                manifest_sha256=references["manifest"]["sha256"], manifest_digest="a" * 64,
                map_sha256=references["map"]["sha256"], release_sha256=references["release"]["sha256"],
                candidate_run_sha256=references["candidate"]["sha256"],
                candidate_generated_tests_sha256=generated, solution_generated_tests_sha256=generated,
                substrate_baseline_sha256="c" * 64, worker_resources_sha256=resource_hash,
                harness_version="fixture-harness", container_image_digest="sha256:" + "d" * 64,
                workspace_seed_digest="f" * 64, database_dump_digest="no_database",
                applier_sha256="a" * 64, expected_pairs=pairs, engine="r2t-mutate-rb",
                engine_version="1.0", parser="fixture-ruby", side="gold", shard=shard,
                of=workers, timeout=600,
                generation_provenance_class=R.GENERATION_PROVENANCE_REFERENCE_CONTROL,
                reference_control_role="full-gold", reference_source_tag="fixture-gold",
                reference_workload_digest="8" * 64)

        def save_shard(path, ident, pairs, status):
            R.prepare_standalone_output_directory(str(path), ident)
            path.write_text(''.join(json.dumps({"item_id": i, "mutant_id": m,
                "outcome": "passed", **R.row_identity_stamp(ident)}) + '\n'
                for i, m in sorted(pairs)))
            resources = [{"workspace": str(root / f'pool{ident["of"]}' / str(i)),
                          "container": f'pool{ident["of"]}-{i}',
                          "env_file": str(root / f'pool{ident["of"]}' / f'{i}.env')}
                         for i in range(ident["of"])]
            R.write_shard_provenance(str(path), ident, "running",
                                     provenance={"worker_resources": resources})
            if status != "running":
                R.write_shard_provenance(str(path), ident, status,
                                         provenance={"worker_resources": resources})

        parent_paths = []
        for i in range(6):
            path = parents / f"gold.w{i}.jsonl"
            expected = R.expected_pairs_for_slice(mutants[i::6], mapping, files)
            observed = expected if i == 0 else set(sorted(expected)[:2])
            save_shard(path, identity(expected, i, 6), observed,
                       "complete" if i == 0 else "interrupted")
            parent_paths.append(str(path))
        original = {p: Path(p).read_bytes() for path in parent_paths
                    for p in (path, R.provenance_path(path))}
        plan_path = str(root / "continuation.json")
        kwargs = dict(mutation_validation_path=paths["validation"], manifest_path=paths["manifest"],
                      map_path=paths["map"], release_path=paths["release"],
                      candidate_run_path=paths["candidate"], plan_out=plan_path)
        with patch.object(A, "validate_campaign_asset_inputs", return_value=assets), \
                patch.object(R, "validate_worker_resource_evidence", return_value=[]):
            # Native output lock refuses a live coordinator, without waiting.
            with R.output_lock(parent_paths[0]):
                refused(lambda: prepare_continuation(parent_paths, **kwargs))
            side_path = R.provenance_path(parent_paths[1])
            side = _read(side_path)
            for status in ("running", "failed"):
                Path(side_path).write_text(json.dumps({**side, "status": status}))
                refused(lambda: prepare_continuation(parent_paths, **kwargs))
            Path(side_path).write_bytes(original[side_path])
            prepare_continuation(parent_paths, **kwargs)
            binding = validate_plan(plan_path)
            assert all(Path(p).read_bytes() == b for p, b in original.items())
            assert set().union(*binding["partitions"]) == binding["full"] - binding["completed"]
            assert _partitions(binding["full"] - binding["completed"], 24) == binding["partitions"]
            refused(lambda: prepare_continuation(parent_paths, **kwargs))
            refused(lambda: refuse_parent_resume(parent_paths[0]))
            frozen = Path(parent_paths[0]).read_bytes()
            Path(parent_paths[0]).write_bytes(frozen + b'\n')
            refused(lambda: validate_plan(plan_path))
            Path(parent_paths[0]).write_bytes(frozen)
            child_paths = []
            children = root / "children"
            children.mkdir()
            for i, pairs in enumerate(binding["partitions"]):
                plain = identity(pairs, i, 24, "9" * 64)
                for field, wrong in (("timeout_seconds", 601), ("candidate_run_sha256", "1" * 64),
                                     ("workspace_seed_digest", "2" * 64)):
                    refused(lambda f=field, v=wrong: validate_identity(binding, {**plain, f: v}))
                bound = validate_identity(binding, plain)
                path = children / f"gold.w{i}.jsonl"
                save_shard(path, bound, pairs, "complete")
                assert R.completed_pairs(str(path), bound, expected_pairs=pairs) == pairs
                child_paths.append(str(path))
            refused(lambda: R.validate_native_shards(child_paths))
            refused(lambda: R.validate_publishable_generation(bound, reference_roles={"full-gold"}))
            result = validate_continued_observation(plan_path, child_paths)
            assert result["pairs"] == 144 and result["stable_killset"] is False
            refused(lambda: validate_continued_observation(plan_path, child_paths[:-1]))
            refused(lambda: validate_continued_observation(plan_path, [child_paths[0]] * 24))
            # Only a validated crash receipt can admit original running parents.
            Path(claim_path(str(parents))).unlink()
            Path(plan_path).unlink()
            receipt_path = root / "crash-receipt.json"
            receipt_path.write_text("{}")
            unknown = set(sorted(binding["full"] - binding["completed"])[:6])
            for parent in parent_paths:
                side_path = R.provenance_path(parent)
                side = _read(side_path)
                Path(side_path).write_text(json.dumps({**side, "status": "running"}))
            refused(lambda: prepare_continuation(parent_paths, **kwargs))
            with patch(__name__ + "._crash_receipt", return_value=(unknown, [])) as proof:
                prepare_continuation(parent_paths, **kwargs, crash_recovery_path=str(receipt_path))
                assert proof.call_args.kwargs["live"] is True
                crashed = validate_plan(plan_path)
                assert crashed["uncertain"] == unknown
                assert set().union(*crashed["partitions"]) == crashed["full"] - crashed["completed"] - unknown
                # Native suffix fixtures are rebuilt only in the private test root.
                import shutil
                shutil.rmtree(children)
                children.mkdir()
                for i, pairs in enumerate(crashed["partitions"]):
                    bound = validate_identity(crashed, identity(pairs, i, 24, "9" * 64))
                    save_shard(children / f"gold.w{i}.jsonl", bound, pairs, "complete")
                result = validate_continued_observation(plan_path, child_paths)
                assert result["native_pairs"] == 138 and result["uncertain_pairs"] == sorted(map(list, unknown))
                assert result["pairs"] == 144 and not result["stable_killset"]
                receipt_path.write_text('{"changed":true}')
                refused(lambda: validate_plan(plan_path))
            # The storage-failed second suffix retains native rows, reserves
            # all twenty-four failed-shard next pairs, and cannot report completion.
            from types import SimpleNamespace
            from . import repo
            baseline = {}
            for m in mutants:
                m.update(file=f"app/{m['id']}.rb", original="true", mutated="false",
                         start_line=1, start_col=1)
                pristine = root / "source" / m["file"]
                pristine.parent.mkdir(parents=True, exist_ok=True)
                pristine.write_text("true")
                baseline[m["file"]] = R.sha256_file(str(pristine))
            strip = root / "gold/strip_manifest.json"
            strip.parent.mkdir()
            strip.write_text("{}")
            receipt_path.write_text(json.dumps({"references": [{"copy": "inputs/strip_manifest.json", "source": str(strip)}]}))
            commands, incident_workers = [], []
            for i, path in enumerate(child_paths):
                side = _read(R.provenance_path(path))
                sequence = [(iid, m["id"]) for m in mutants for iid in mapping[m["id"]]
                            if (iid, m["id"]) in crashed["partitions"][i]]
                ident = side["campaign_identity"]
                Path(path).write_text(json.dumps({"item_id": sequence[0][0], "mutant_id": sequence[0][1],
                    "outcome": "passed", **R.row_identity_stamp(ident)}) + "\n")
                n, sha = R._rows_state(path)
                error = "MutationCancelled: mutation campaign cancelled between item executions"
                status = "interrupted"
                if i in RESET_WORKERS:
                    status, error = "failed", "RuntimeError: Ruby bootstrap failed during reset: No space left on device"
                if i in {13, 17}:
                    status, error = "failed", "MutationAborted: REFUSED: mutation campaign cleanup/restoration failed: still declares a mutation"
                if i == 23:
                    status, error = "running", ""
                side.update(status=status, error=error, rows=n, rows_sha256=sha)
                Path(R.provenance_path(path)).write_text(json.dumps(side))
                resource = side["worker_resources"][i]
                # Fixtures used by the earlier test omit the external spec ref.
                for r in side["worker_resources"]:
                    r["worker_spec"] = str(root / f"worker{r['container']}.json")
                Path(R.provenance_path(path)).write_text(json.dumps(side))
                directory = root / "commands" / str(i)
                directory.mkdir(parents=True)
                (directory / "started.json").write_text(json.dumps({"worker": i,
                    "argv": ["--out", path, "--worker", resource["worker_spec"], "--continuation-plan", plan_path]}))
                (directory / "finished.json").write_text(json.dumps({"worker": i, "exit": 1}))
                stderr = error.removeprefix("RuntimeError: ")
                if i == 23:
                    stderr = "write_shard_provenance No space left on device .r2t-stage-gold.w23.jsonl.provenance.json-x"
                (directory / "stderr").write_text(stderr)
                commands.append(str(directory))
                inventory = dict(baseline)
                if i in APPLIED_WORKERS:
                    mutant = next(m for m in mutants if m["id"] == sequence[1][1])
                    applied = Path(resource["workspace"]) / mutant["file"]
                    applied.parent.mkdir(parents=True, exist_ok=True)
                    applied.write_text("false")
                    inventory[mutant["file"]] = R.sha256_file(str(applied))
                incident_workers.append({"inventory": inventory, "command": {
                    name: _reference(str(directory / name)) for name in ("started.json", "finished.json", "stderr")}})
            resources = _read(R.provenance_path(child_paths[0]))["worker_resources"]
            inspection = [{"inspect": json.dumps([{"Image": "sha256:" + "d" * 64,
                "Name": "/" + r["container"], "ExecIDs": [],
                "State": {"Running": True, "Paused": False, "Restarting": False}}]),
                "top": "PID COMMAND ARGS\n1 postgres postgres\n"} for r in resources]
            incident = {"schema": INCIDENT_SCHEMA, "strip_manifest": _reference(str(strip)),
                        "before": inspection, "after": inspection, "workers": incident_workers}
            suffix_plan_path = str(root / "suffix.json")
            real_validate = validate_plan
            def validate_prior(path):
                return crashed if str(path) == plan_path else real_validate(path)
            with patch(__name__ + ".validate_plan", side_effect=validate_prior), \
                    patch(__name__ + "._suffix_incident", return_value=incident), \
                    patch.object(repo, "load_manifest", return_value=SimpleNamespace(digests=baseline)), \
                    patch.object(R, "substrate_baseline_digest", return_value="c" * 64):
                with R.output_lock(child_paths[0]):
                    refused(lambda: prepare_suffix_recovery(plan_path, child_paths,
                        command_directories=commands, plan_out=suffix_plan_path))
                prepare_suffix_recovery(plan_path, child_paths, command_directories=commands, plan_out=suffix_plan_path)
                suffix = validate_plan(suffix_plan_path)
                assert len(suffix["unresolved"]) == 24
                assert len(suffix["completed"]) == len(crashed["completed"]) + 24
                assert not set().union(*suffix["partitions"]).intersection(suffix["unresolved"])
                assert suffix["completed"] | suffix["uncertain"] | suffix["unresolved"] | set().union(*suffix["partitions"]) == suffix["full"]
                refused(lambda: validate_child_resources(suffix, resources))
                suffix_children = root / "suffix-children"
                suffix_children.mkdir()
                suffix_paths = []
                for i, pairs in enumerate(suffix["partitions"]):
                    ident = validate_identity(suffix, identity(pairs, i, 24, "7" * 64))
                    path = suffix_children / f"gold.w{i}.jsonl"
                    save_shard(path, ident, pairs, "complete")
                    # Use a genuinely separate synthetic pool for this tranche.
                    side = _read(R.provenance_path(str(path)))
                    for r in side["worker_resources"]:
                        r.update(workspace=r["workspace"] + "-fresh", container=r["container"] + "-fresh",
                                 env_file=r["env_file"] + "-fresh")
                    Path(R.provenance_path(str(path))).write_text(json.dumps(side))
                    suffix_paths.append(str(path))
                result = validate_continued_observation(suffix_plan_path, suffix_paths)
                assert result["complete"] is False and len(result["unresolved_pairs"]) == 24
                assert result["accounted_pairs"] == 120 and result["native_pairs"] == 114
                pid_error = "TimeoutExpired: Command ['docker', 'rm -f /tmp/r2t-ruby-1.pid'] timed out after 60 seconds"
                _suffix_failure(0, {"status": "failed", "error": pid_error},
                                "subprocess.TimeoutExpired " + pid_error)
                refused(lambda: _suffix_failure(0, {"status": "failed", "error": "TimeoutExpired: other"}, "other"))
                stopped_proof = json.loads(json.dumps(incident["before"]))
                for proof in stopped_proof:
                    inspected = json.loads(proof["inspect"])
                    inspected[0]["State"]["Running"] = False
                    inspected[0]["ExecIDs"] = ["stale-stopped-handle"]
                    proof["inspect"] = json.dumps(inspected)
                    proof["top"] = ""
                _validate_suffix_inspection(stopped_proof, resources, binding["parent_identity"]["container_image_digest"])
                for proof in stopped_proof:
                    inspected = json.loads(proof["inspect"])
                    inspected[0]["State"]["Running"] = True
                    proof["inspect"] = json.dumps(inspected)
                    proof["host_pid_present"] = False
                    proof["host_pid_namespace"] = "pid:[fixture-shared]"
                _validate_suffix_inspection(stopped_proof, resources, binding["parent_identity"]["container_image_digest"])
                stopped_proof[0]["host_pid_present"] = True
                refused(lambda: _validate_suffix_inspection(stopped_proof, resources, binding["parent_identity"]["container_image_digest"]))
                # Unknown failure claims cannot be promoted to reset failures.
                refused(lambda: _suffix_failure(2, {"status": "failed", "error": "unknown"}, "unknown"))
                frozen = Path(child_paths[0]).read_bytes()
                Path(child_paths[0]).write_bytes(frozen + frozen)
                refused(lambda: validate_plan(suffix_plan_path))
                Path(child_paths[0]).write_bytes(frozen)
                original_side = Path(R.provenance_path(child_paths[0])).read_bytes()
                row = json.loads(frozen)
                row["side"] = "solution"
                Path(child_paths[0]).write_text(json.dumps(row) + "\n")
                side = json.loads(original_side)
                side["rows"], side["rows_sha256"] = R._rows_state(child_paths[0])
                Path(R.provenance_path(child_paths[0])).write_text(json.dumps(side))
                refused(lambda: _suffix_snapshot(plan_path, child_paths, incident))
                Path(child_paths[0]).write_bytes(frozen)
                Path(R.provenance_path(child_paths[0])).write_bytes(original_side)
                bad = json.loads(json.dumps(incident))
                bad["workers"][2]["inventory"]["foreign.rb"] = "0" * 64
                refused(lambda: _suffix_snapshot(plan_path, child_paths, bad))
                changed = Path(commands[2]) / "stderr"
                changed.write_text("tampered error")
                refused(lambda: validate_plan(suffix_plan_path))
            # Internally re-stamped parent bytes are still outside the frozen plan.
            Path(parent_paths[1]).write_bytes(original[parent_paths[1]] + original[parent_paths[1]])
            refused(lambda: validate_plan(plan_path))
    # Crash continuation keeps the ordinary route strict and accounts for the
    # uncertain set without creating native result rows. External receipt proof
    # is stubbed here; native rows, identities, partitions and claims are real.
    with tempfile.TemporaryDirectory(prefix="r2t-crash-quiescence-") as temp:
        from types import SimpleNamespace
        receipt = Path(temp) / "receipt.json"
        receipt.write_text(json.dumps({"schema": "wrong"}))
        refused(lambda: _crash_receipt(str(receipt), [], {}, {}, {}))
        resource = {"container": "fixture"}
        inspect = {"Image": "image", "ExecIDs": [],
                   "State": {"Running": True, "Paused": False, "Restarting": False, "Pid": os.getpid()}}
        import subprocess
        from ..core import docker_cli
        with patch.object(docker_cli, "docker_argv", side_effect=lambda args: args), \
                patch.object(subprocess, "run") as run, \
                patch.object(Path, "iterdir", return_value=[]):
            def command(args, **kwargs):
                return SimpleNamespace(returncode=0, stdout=json.dumps([inspect])
                    if args[0] == "inspect" else "PID COMMAND COMMAND\n1 postgres postgres\n2 tail tail -f /dev/null\n")
            run.side_effect = command
            _crash_quiescence([resource], Path(temp), "image")
            inspect["ExecIDs"] = ["live-test"]
            refused(lambda: _crash_quiescence([resource], Path(temp), "image"))
            inspect["ExecIDs"] = []
            inspect["State"]["Paused"] = True
            refused(lambda: _crash_quiescence([resource], Path(temp), "image"))
            inspect["State"]["Paused"] = False
            run.side_effect = lambda args, **kwargs: SimpleNamespace(returncode=0,
                stdout=json.dumps([inspect]) if args[0] == "inspect" else "PID COMMAND COMMAND\n1 ruby cucumber\n")
            refused(lambda: _crash_quiescence([resource], Path(temp), "image"))
    print("  [PASS] native continuation prefix, locks, claims, tamper, allocation, child identity/resume and aggregate")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    verbs = parser.add_subparsers(dest="action", required=True)
    prep = verbs.add_parser("prepare")
    prep.add_argument("--parents", nargs="+", required=True)
    for flag in ("mutation-validation", "manifest", "map", "release", "candidate", "out"):
        prep.add_argument("--" + flag, required=True)
    prep.add_argument("--crash-recovery")
    prep.add_argument("--docker-authority")
    suffix = verbs.add_parser("prepare-suffix-recovery")
    suffix.add_argument("--prior-plan", required=True)
    suffix.add_argument("--parents", nargs="+", required=True)
    suffix.add_argument("--command-directories", nargs="+", required=True)
    suffix.add_argument("--out", required=True)
    suffix.add_argument("--docker-authority")
    aggregate = verbs.add_parser("aggregate")
    aggregate.add_argument("--plan", required=True)
    aggregate.add_argument("--children", nargs="+", required=True)
    args = parser.parse_args()
    if args.action in {"prepare", "prepare-suffix-recovery"} and args.docker_authority:
        from ..core import docker_cli
        docker_cli.configure(authority_path=args.docker_authority)
    if args.action == "prepare-suffix-recovery":
        result = prepare_suffix_recovery(args.prior_plan, args.parents,
            command_directories=args.command_directories, plan_out=args.out)
    elif args.action == "prepare":
        result = prepare_continuation(args.parents,
            mutation_validation_path=args.mutation_validation, manifest_path=args.manifest,
            map_path=args.map, release_path=args.release, candidate_run_path=args.candidate,
            plan_out=args.out, crash_recovery_path=args.crash_recovery)
    else:
        result = validate_continued_observation(args.plan, args.children)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
