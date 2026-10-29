"""Two host-local native campaigns continuing one frozen gold observation.

Portable execution assignments authenticate local inputs and master arithmetic.
Only the central producer and final reader reopen the historical native chain.
"""
from __future__ import annotations

from contextlib import ExitStack
import os
from pathlib import Path
from types import SimpleNamespace

from . import mutation_continuation as C
from . import mutation_run as R
from .worker import _seed_verification_scope
from ..data import mutation_attestation as A

MASTER_SCHEMA = "r2t.gold-mutation-distribution/1"
ASSIGNMENT_SCHEMA = "r2t.gold-mutation-host-assignment/1"
_require = C._require


def _pairs(value):
    _require(isinstance(value, list) and all(isinstance(p, list) and len(p) == 2
             and all(isinstance(s, str) and s for s in p) for p in value),
             "invalid distributed pair list")
    result = {tuple(p) for p in value}
    _require(len(result) == len(value) and value == sorted(map(list, result)),
             "distributed pair list is duplicate or unordered")
    return result


def _listed(pairs):
    return sorted(map(list, pairs))


def _hosts(hosts):
    _require(isinstance(hosts, list) and len(hosts) == 2, "requires exactly two hosts")
    _require(len({h["id"] for h in hosts}) == 2, "host IDs overlap")
    destinations = []
    for h in hosts:
        _require(set(h) == {"id", "master_path", "assignment_path", "inputs", "validation_inputs"}
                 and isinstance(h["id"], str) and h["id"], "invalid host descriptor")
        _require(set(h["inputs"]) == {"validation", "manifest", "map", "release", "candidate"}
                 and isinstance(h["validation_inputs"], dict) and h["validation_inputs"],
                 "host needs complete campaign and native report input locations")
        paths = [h["master_path"], h["assignment_path"], *h["inputs"].values(),
                 *h["validation_inputs"].values()]
        _require(all(isinstance(p, str) and p == os.path.abspath(p) for p in paths),
                 "host locations must be absolute")
        _require(h["master_path"] != h["assignment_path"], "master and assignment paths overlap")
        destinations.extend([h["master_path"], h["assignment_path"]])
    _require(len(set(destinations)) == len(destinations), "host plan destinations overlap")
    return hosts


def _arithmetic(master, full):
    _require(master.get("schema") == MASTER_SCHEMA, "unsupported distributed master")
    _hosts(master["hosts"])
    completed = _pairs(master["completed"])
    uncertain, held = _pairs(master["uncertain"]), _pairs(master["unresolved"])
    pending = _pairs(master["pending"])
    sets = [completed, uncertain, held, pending]
    union = set().union(*sets)
    _require(len(uncertain) == 6 and len(held) == 24,
             "distributed route requires six uncertain and 24 held pairs")
    _require(sum(map(len, sets)) == len(union) and union == full
             and master["full_pairs"] == len(full)
             and master["full_pairs_sha256"] == R.pair_set_digest(full),
             "distributed master has overlapping, foreign or missing pairs")
    parts = C._partitions(pending, 48)
    _require(all(parts) and master["partitions"] == [_listed(p) for p in parts],
             "distributed allocation differs from deterministic 48-slot LPT")
    return completed, uncertain, held, pending, parts


def _baseline(prior):
    """The reviewed incident already binds the pristine strip manifest."""
    incident = C._read(C._check_reference(prior["plan"]["incident"]))
    return incident["strip_manifest"]


def _quiescence(resources, directory, image):
    """Admit the reviewed init-enabled pool, including its idle PID 1 reaper."""
    import subprocess
    from ..core import docker_cli

    def docker(args):
        cp = subprocess.run(docker_cli.docker_argv(args), capture_output=True, text=True, timeout=120)
        _require(cp.returncode == 0, "cannot inspect distributed parent pool")
        return cp.stdout

    import json
    for resource in resources:
        inspected = json.loads(docker(["inspect", resource["container"]]))[0]
        state = inspected["State"]
        _require(inspected["Image"] == image and inspected["Name"].lstrip("/") == resource["container"]
                 and inspected.get("HostConfig", {}).get("Init") is True
                 and not state.get("Paused") and not state.get("Restarting")
                 and not inspected.get("ExecIDs"), "distributed parent is not quiescent and init-enabled")
        if state["Running"]:
            _require(C._host_pid_present(state), "running distributed parent has no live init PID")
            processes = [line.split(None, 2) for line in docker(
                ["top", resource["container"], "-eo", "pid,comm,args"]).splitlines()[1:] if line.strip()]
            _require(processes and all(len(p) == 3 and p[1] in {"postgres", "tail", "docker-init", "tini"}
                                       for p in processes), "distributed parent still has test processes")
            init = [p for p in processes if p[1] in {"docker-init", "tini"}]
            _require(len(init) == 1 and init[0][0] == str(state["Pid"])
                     and Path(init[0][2].split()[0]).name in {"docker-init", "tini"},
                     "distributed parent init process does not match container PID 1")
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            argv = (proc / "cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        _require(not (b"mutation-run" in argv and any(os.fsencode(directory) in a for a in argv)),
                 "distributed parent coordinator is still live")


@_seed_verification_scope()
def _snapshot(prior_path, parent_paths, hosts, *, live=False):
    from . import repo
    from ..core.boundary import load_boundary
    prior = C.validate_plan(prior_path)
    _require(prior["plan"]["schema"] == C.SUFFIX_SCHEMA,
             "distributed route requires the reviewed suffix recovery")
    _require(len(parent_paths) == len(set(parent_paths)) == 24
             and len({os.path.dirname(p) for p in parent_paths}) == 1,
             "requires 24 ordered distinct current parents in one directory")
    directory = os.path.dirname(parent_paths[0])
    baseline = _baseline(prior)
    man = repo.load_manifest(C._check_reference(baseline))
    _require(R.substrate_baseline_digest(SimpleNamespace(man=man)) ==
             prior["parent_identity"]["substrate_baseline_sha256"], "distributed source baseline differs")
    assets, files, full = C._assets(prior["plan"]["inputs"])
    parents, done, resources = [], set(), None
    for shard, path in enumerate(parent_paths):
        side = C._read(R.provenance_path(path))
        ident = side["campaign_identity"]
        _require(side["status"] in {"interrupted", "complete"},
                 "distributed parent is live, failed, or ambiguous")
        _require(ident["shard"] == shard and ident.get("continuation_plan_sha256") == prior["plan_sha256"],
                 "distributed parent names another prior assignment")
        C.validate_identity(prior, ident)
        C.validate_child_resources(prior, side["worker_resources"])
        R.validate_worker_resource_evidence(side, ident)
        if resources is None:
            resources = side["worker_resources"]
        _require(resources == side["worker_resources"], "distributed parent resources differ")
        observed = R.completed_pairs(path, ident, expected_pairs=prior["partitions"][shard],
                                     require_complete=side["status"] == "complete")
        sequence = [(iid, m["id"]) for m in assets["manifest"]["mutants"]
                    for iid in assets["map"]["by_mutant"].get(m["id"], [])
                    if (iid, m["id"]) in prior["partitions"][shard]]
        rows = A.load_jsonl(path)
        _require([(r["item_id"], r["mutant_id"]) for r in rows] == sequence[:len(rows)],
                 "distributed parent is not an exact native prefix")
        _require(not done.intersection(observed), "distributed parent rows overlap")
        done.update(observed)
        workspace = resources[shard]["workspace"]
        boundary = load_boundary(str(Path(__file__).resolve().parents[2] /
                                     "config/boundary_e_petitions.yml"), repo_root=workspace)
        _require(repo.substrate_digests(workspace, boundary, man.roots(), man.volatile()) == man.digests,
                 "distributed parent source is not restored")
        parents.append({"rows": C._reference(path), "sidecar": C._reference(R.provenance_path(path))})
    R.validate_standalone_output_directory(parent_paths, ident)
    if live:
        _quiescence(resources, directory, ident["container_image_digest"])
    _require(not done.intersection(prior["completed"] | prior["uncertain"] | prior["unresolved"]),
             "current prefix overlaps predecessors or held pairs")
    completed = prior["completed"] | done
    pending = full - completed - prior["uncertain"] - prior["unresolved"]
    plan = {"schema": MASTER_SCHEMA, "prior_plan": C._reference(prior_path), "parents": parents,
            "parent_output_plan": C._reference(os.path.join(directory, R.MUTATION_OUTPUT_PLAN)),
            "baseline": baseline, "inputs": prior["plan"]["inputs"],
            "parent_identity": prior["parent_identity"],
            "parent_resources": prior["parent_resources"] + resources,
            "hosts": _hosts(hosts), "full_pairs": len(full), "full_pairs_sha256": R.pair_set_digest(full),
            "completed": _listed(completed), "uncertain": _listed(prior["uncertain"]),
            "unresolved": _listed(prior["unresolved"]), "pending": _listed(pending),
            "partitions": [_listed(p) for p in C._partitions(pending, 48)]}
    _arithmetic(plan, full)
    return plan, prior


def prepare_distributed_continuation(prior_plan_path, parent_paths, *, hosts, plan_out):
    """Authenticate and seal stopped native parents; never execute tests."""
    from .worker import resource_fields
    parent_paths = list(map(os.path.abspath, parent_paths))
    _require(len(parent_paths) == 24, "requires 24 current parents")
    plan_out = os.path.abspath(plan_out)
    directory = os.path.dirname(parent_paths[0])
    claim = C.claim_path(directory)
    _hosts(hosts)
    _require(plan_out == hosts[0]["master_path"], "central master location differs from host descriptor")
    _require(os.path.commonpath([directory, plan_out]) != directory, "master must be outside parent outputs")
    with ExitStack() as stack:
        for path in sorted(parent_paths):
            stack.enter_context(R.output_lock(path))
        _require(not os.path.lexists(claim), "current parents are already sealed")
        side = C._read(R.provenance_path(parent_paths[0]))
        fields = resource_fields(side["campaign_identity"]["database_dump_digest"] != "no_database")
        stack.enter_context(R.mutation_resource_locks([(k, r[k]) for r in side["worker_resources"]
                                                      for k in fields if r.get(k)]))
        plan, _prior = _snapshot(prior_plan_path, parent_paths, hosts, live=True)
        R.atomic_write_json(plan_out, plan, refuse_existing=True)
        R.atomic_write_json(claim, {"schema": C.CLAIM_SCHEMA, "plan": C._reference(plan_out)}, refuse_existing=True)
    return plan


def validate_master(path):
    """Central-only validation reopens the entire unchanged historical chain."""
    path = os.path.abspath(path)
    master = C._read(path)
    _require(master.get("schema") == MASTER_SCHEMA, "unsupported distributed master")
    prior_path = C._check_reference(master["prior_plan"])
    parents = [C._check_reference(p["rows"]) for p in master["parents"]]
    for row in master["parents"]:
        C._check_reference(row["sidecar"])
    C._check_reference(master["parent_output_plan"])
    marker = C.claim_path(os.path.dirname(parents[0]))
    _require(C._read(marker) == {"schema": C.CLAIM_SCHEMA, "plan": C._reference(path)},
             "distributed parent claim names another master")
    derived, prior = _snapshot(prior_path, parents, master["hosts"])
    _require(derived == master, "distributed master does not rederive from frozen native chain")
    return master, prior


def _assignment(master, master_sha, host_id):
    matches = [(i, h) for i, h in enumerate(master["hosts"]) if h["id"] == host_id]
    _require(len(matches) == 1, "unknown distributed host")
    index, host = matches[0]
    return {"schema": ASSIGNMENT_SCHEMA, "master": {"path": host["master_path"], "sha256": master_sha},
            "host_id": host_id, "inputs": {k: {"path": p, "sha256": master["inputs"][k]["sha256"]}
                                           for k, p in host["inputs"].items()},
            "validation_inputs": host["validation_inputs"],
            "partitions": master["partitions"][index::2]}


def write_assignment(master_path, host_id, out_path):
    """Stage deterministic bytes; the remote destination remains master-bound."""
    master, _prior = validate_master(master_path)
    assignment = _assignment(master, R.sha256_file(master_path), host_id)
    R.atomic_write_json(out_path, assignment, refuse_existing=True)
    return assignment


def _local_assets(assignment):
    paths = {k: C._check_reference(ref) for k, ref in assignment["inputs"].items()}
    assets = A.validate_campaign_asset_inputs(paths["validation"], manifest_path=paths["manifest"],
        map_path=paths["map"], release_path=paths["release"], require_release_ready=True,
        input_paths=assignment["validation_inputs"])
    rows = A.load_jsonl(paths["candidate"])
    release = A.load_release_ids(paths["release"])
    _require(len(rows) == len(release) and {r["item_id"] for r in rows} == release
             and all(r.get("adapter") == "gold" and r.get("outcome") == "passed" for r in rows),
             "distributed candidate is not complete passing gold")
    from .test_quality import passed_solutions
    files = passed_solutions(rows)
    full = {(i, m) for m, ids in assets["map"]["by_mutant"].items() for i in ids}
    _require(all(i in files for i, _m in full), "distributed gold bytes do not cover full map")
    return full


def validate_assignment(path):
    """Portable admission: no claim to reopen central historical references."""
    path = os.path.abspath(path)
    assignment = C._read(path)
    _require(assignment.get("schema") == ASSIGNMENT_SCHEMA, "unsupported host assignment")
    master_path = C._check_reference(assignment["master"])
    master = C._read(master_path)
    _require(master.get("schema") == MASTER_SCHEMA, "unsupported assignment master")
    _hosts(master["hosts"])
    expected = _assignment(master, R.sha256_file(master_path), assignment["host_id"])
    _require(assignment == expected, "host assignment differs from frozen master projection")
    host = next(h for h in master["hosts"] if h["id"] == assignment["host_id"])
    _require(path == host["assignment_path"], "host assignment is at another host's location")
    full = _local_assets(assignment)
    completed, uncertain, unresolved, _pending, _parts = _arithmetic(master, full)
    C._full_gold(master["parent_identity"])
    protected = [path, master_path, *[ref["path"] for ref in assignment["inputs"].values()],
                 *assignment["validation_inputs"].values()]
    # Historical absolute paths are names used for separation, not files opened
    # on this host. Native preflight still checks this host's whole worker pool.
    return {"plan": assignment, "plan_sha256": R.sha256_file(path),
            "partitions": [_pairs(p) for p in assignment["partitions"]],
            "parent_identity": master["parent_identity"], "parent_resources": master["parent_resources"],
            "completed": completed, "uncertain": uncertain, "unresolved": unresolved, "full": full,
            "protected_paths": protected,
            "containment_paths": [r["workspace"] for r in master["parent_resources"]]}


#: Owner ruling OD10 (a), 2026-09-23: the 24 held pairs close as "held, never
#: observed" (MUTATION_GOLD_RESHARD_CONTINUATION_SPEC.md, "Owner ruling: the 24
#: held pairs close as held, never observed").
HELD_NEVER_OBSERVED = "held_never_observed"


@_seed_verification_scope()
def validate_distributed_observation(master_path, host_children, *, held_disposition=None):
    """Reopen the central chain and each host campaign; prove the exact union.

    Without `held_disposition` the 24 held pairs stay unresolved and the
    observation is incomplete.  With HELD_NEVER_OBSERVED they close unexecuted,
    outside outcomes and denominators, and the observation is complete.
    """
    _require(held_disposition in (None, HELD_NEVER_OBSERVED), "unknown held-pair disposition")
    master, prior = validate_master(master_path)
    _require(set(host_children) == {h["id"] for h in master["hosts"]}, "host shard sets incomplete")
    pending = _pairs(master["pending"])
    union, children, resources_by_host = set(), {}, []
    for host in master["hosts"]:
        path = host["assignment_path"]
        binding = validate_assignment(path)
        _require(C._read(path) == _assignment(master, R.sha256_file(master_path), host["id"]),
                 "final host uses another master")
        paths = list(host_children[host["id"]])
        _require(len(paths) == 24, "host native shard set incomplete")
        pool = None
        for shard, child_path in enumerate(paths):
            side = C._read(R.provenance_path(child_path))
            identity = side["campaign_identity"]
            _require(identity["shard"] == shard and "continuation_plan_sha256" in identity,
                     "host shards are unordered or not assignment bound")
            C.validate_identity(binding, identity)
            C.validate_child_resources(binding, side["worker_resources"])
            if pool is None:
                pool = side["worker_resources"]
            _require(pool == side["worker_resources"], "host resources differ")
            R.completed_pairs(child_path, identity, expected_pairs=binding["partitions"][shard], require_complete=True)
        expected = set().union(*binding["partitions"])
        child = R.validate_native_shards(paths, expected_pairs=expected, required_side="gold", return_campaign=True,
                                        _continuation_plan_sha256=binding["plan_sha256"])
        _require(not union.intersection(child["pairs"]), "host result pairs overlap")
        union.update(child["pairs"])
        resources_by_host.append(pool)
        children[host["id"]] = {"pairs": len(child["pairs"]), "campaign_identity": child["campaign_identity"],
                                "observation_id": child["observation_id"], "assignment_sha256": binding["plan_sha256"]}
    # Distinct names keep central offline evidence unambiguous even though
    # separate Docker authorities already isolate the actual mutable resources.
    from .worker import resource_fields
    fields = resource_fields(master["parent_identity"]["database_dump_digest"] != "no_database")
    for field in fields:
        _require(not {r[field] for r in resources_by_host[0] if r.get(field)}.intersection(
                     {r[field] for r in resources_by_host[1] if r.get(field)}),
                 "host resource identifiers overlap: " + field)
    _require(union == pending, "distributed result union differs from frozen pending set")
    completed, uncertain, held, _pending, _parts = _arithmetic(master, prior["full"])
    report = {"schema": "r2t.distributed-gold-observation/1", "label": "single continued development gold observation",
              "master_sha256": R.sha256_file(master_path), "parent_identity": master["parent_identity"],
              "parent_pairs": len(completed), "child_pairs": len(union), "native_pairs": len(completed | union),
              "pairs": len(prior["full"]), "uncertain_pairs": _listed(uncertain), "unresolved_pairs": _listed(held),
              "complete": False, "stable_killset": False, "worker_transition": [6, 24, 24, [24, 24]],
              "hosts": children}
    if held_disposition == HELD_NEVER_OBSERVED:
        # `_arithmetic` proved completed, uncertain, held and pending disjoint
        # with union == full, and the host union equals pending, so the native
        # outcomes plus the six uncertain and 24 held pairs are the population.
        report.update({"unresolved_pairs": [], "held_never_observed_pairs": _listed(held),
                       "held_disposition": HELD_NEVER_OBSERVED, "complete": True})
    return report


def selftest():
    """Native rows/identities/locks; only external assets and source are stubbed."""
    import copy
    import json
    import tempfile
    from unittest.mock import patch
    from . import repo

    def refused(fn):
        try:
            fn()
        except (R.MutationAborted, A.MutationAssetRefused, OSError, ValueError):
            return
        raise AssertionError("distributed operation unexpectedly accepted")

    with tempfile.TemporaryDirectory(prefix="r2t-distribution-") as temp:
        root = Path(temp)
        files = {"i": [{"file_path": "steps/x.rb", "code": "pass"}]}
        mutants = [{"id": f"m{i:03d}"} for i in range(400)]
        mapping = {m["id"]: ["i"] for m in mutants}
        manifest = {"mutants": mutants, "digest": "a" * 64}
        inputs = {}
        for label, value in (("manifest", manifest), ("map", {"by_mutant": mapping}), ("validation", {})):
            path = root / (label + ".json")
            path.write_text(json.dumps(value))
            inputs[label] = C._reference(str(path))
        for label, row in (("release", {"item_id": "i"}), ("candidate", {
                "item_id": "i", "adapter": "gold", "outcome": "passed", "produced_files": files["i"]})):
            path = root / (label + ".jsonl")
            path.write_text(json.dumps(row) + "\n")
            inputs[label] = C._reference(str(path))
        assets = {"manifest": manifest, "map": {"by_mutant": mapping}, "asset_index_sha256": "e" * 64}
        full = {("i", m["id"]) for m in mutants}
        ordered = sorted(full)
        done, uncertain, held = set(ordered[:6]), set(ordered[6:12]), set(ordered[12:36])
        initial_parts = C._partitions(full - done - uncertain - held, 24)
        generated = R.candidate_digest(files)

        def identity(pairs, shard, resource_sha):
            return R.build_campaign_identity(asset_index_sha256="e" * 64, asset_project="fixture",
                mutation_validation_sha256=inputs["validation"]["sha256"], mutation_validation_class="native",
                manifest_sha256=inputs["manifest"]["sha256"], manifest_digest="a" * 64,
                map_sha256=inputs["map"]["sha256"], release_sha256=inputs["release"]["sha256"],
                candidate_run_sha256=inputs["candidate"]["sha256"], candidate_generated_tests_sha256=generated,
                solution_generated_tests_sha256=generated, substrate_baseline_sha256="c" * 64,
                worker_resources_sha256=resource_sha, harness_version="fixture-harness",
                container_image_digest="sha256:" + "d" * 64, workspace_seed_digest="f" * 64,
                database_dump_digest="no_database", applier_sha256="a" * 64, expected_pairs=pairs,
                engine="r2t-mutate-rb", engine_version="1.0", parser="fixture-ruby", side="gold", shard=shard,
                of=24, timeout=600, generation_provenance_class=R.GENERATION_PROVENANCE_REFERENCE_CONTROL,
                reference_control_role="full-gold", reference_source_tag="fixture-gold", reference_workload_digest="8" * 64)

        def resources(name):
            return [{"workspace": str(root / name / str(i)), "container": f"{name}-{i}",
                     "env_file": str(root / name / f"{i}.env")} for i in range(24)]

        def save(path, ident, pairs, status, pool):
            R.prepare_standalone_output_directory(str(path), ident)
            path.write_text(''.join(json.dumps({"item_id": i, "mutant_id": m, "outcome": "passed",
                **R.row_identity_stamp(ident)}) + '\n' for i, m in sorted(pairs)))
            R.write_shard_provenance(str(path), ident, "running", provenance={"worker_resources": pool})
            R.write_shard_provenance(str(path), ident, status, provenance={"worker_resources": pool})

        baseline_path, incident_path, prior_path = [root / n for n in ("strip.json", "incident.json", "prior.json")]
        baseline_path.write_text("{}")
        incident_path.write_text(json.dumps({"strip_manifest": C._reference(str(baseline_path))}))
        prior_path.write_text("{}")
        prior = {"plan": {"schema": C.SUFFIX_SCHEMA, "incident": C._reference(str(incident_path)), "inputs": inputs},
                 "plan_sha256": R.sha256_file(str(prior_path)), "parent_identity": identity(full, 0, "a" * 64),
                 "partitions": initial_parts, "parent_resources": resources("historical"),
                 "completed": done, "uncertain": uncertain, "unresolved": held, "full": full}
        parents = root / "parents"
        parents.mkdir()
        parent_paths = []
        for i, pairs in enumerate(initial_parts):
            ident = C.validate_identity(prior, identity(pairs, i, "b" * 64))
            path = parents / f"gold.w{i}.jsonl"
            save(path, ident, {min(pairs)}, "interrupted", resources("parent"))
            parent_paths.append(str(path))
        hosts = []
        for name in ("host1", "host2"):
            directory = root / name
            directory.mkdir()
            relocated = {}
            for label, ref in inputs.items():
                local = directory / Path(ref["path"]).name
                local.write_bytes(Path(ref["path"]).read_bytes())
                relocated[label] = str(local)
            hosts.append({"id": name, "master_path": str(directory / "master.json"),
                          "assignment_path": str(directory / "assignment.json"), "inputs": relocated,
                          "validation_inputs": {"fixture": relocated["manifest"]}})
        master_path = hosts[0]["master_path"]
        old_validate = C.validate_plan

        def validate_prior(path):
            return prior if str(path) == str(prior_path) else old_validate(path)

        def native_assets(report, **kwargs):
            # Local reader actually consumes the explicit relocated bytes;
            # historical paths can disappear without a fallback lookup.
            assert kwargs["input_paths"] in [h["validation_inputs"] for h in hosts]
            assert Path(kwargs["input_paths"]["fixture"]).read_bytes() == Path(kwargs["manifest_path"]).read_bytes()
            return assets

        man = SimpleNamespace(digests={"app/a.rb": "c" * 64}, roots=lambda: (), volatile=lambda: ())
        with patch.object(C, "validate_plan", side_effect=validate_prior), \
                patch.object(C, "_assets", return_value=(assets, files, full)), \
                patch.object(repo, "load_manifest", return_value=man), \
                patch.object(repo, "substrate_digests", return_value=man.digests), \
                patch.object(R, "substrate_baseline_digest", return_value="c" * 64), \
                patch.object(R, "validate_worker_resource_evidence", return_value=[]), \
                patch(__name__ + "._quiescence"), \
                patch.object(A, "validate_campaign_asset_inputs", side_effect=native_assets):
            kwargs = {"hosts": hosts, "plan_out": master_path}
            with R.output_lock(parent_paths[0]):
                refused(lambda: prepare_distributed_continuation(str(prior_path), parent_paths, **kwargs))
            side_path = Path(R.provenance_path(parent_paths[0]))
            original_side = side_path.read_bytes()
            for status in ("running", "failed"):
                side = json.loads(original_side)
                side["status"] = status
                side_path.write_text(json.dumps(side))
                refused(lambda: prepare_distributed_continuation(str(prior_path), parent_paths, **kwargs))
            side_path.write_bytes(original_side)
            changed_side = json.loads(original_side)
            changed_side["campaign_identity"]["timeout_seconds"] = 601
            side_path.write_text(json.dumps(changed_side))
            refused(lambda: prepare_distributed_continuation(str(prior_path), parent_paths, **kwargs))
            side_path.write_bytes(original_side)
            with patch.object(repo, "substrate_digests", return_value={"changed.rb": "0" * 64}):
                refused(lambda: prepare_distributed_continuation(str(prior_path), parent_paths, **kwargs))
            master = prepare_distributed_continuation(str(prior_path), parent_paths, **kwargs)
            refused(lambda: prepare_distributed_continuation(str(prior_path), parent_paths, **kwargs))
            refused(lambda: C.refuse_parent_resume(parent_paths[0]))
            assert len(master["completed"]) == 30
            assert len(master["pending"]) == 340
            for host in hosts:
                write_assignment(master_path, host["id"], host["assignment_path"])
            Path(hosts[1]["master_path"]).write_bytes(Path(master_path).read_bytes())
            bindings = [C.validate_plan(h["assignment_path"]) for h in hosts]
            first = set().union(*bindings[0]["partitions"])
            second = set().union(*bindings[1]["partitions"])
            assert not first.intersection(second) and first | second == _pairs(master["pending"])
            hidden = root / "hidden-parents"
            parents.rename(hidden)
            C.validate_plan(hosts[1]["assignment_path"])
            refused(lambda: validate_master(master_path))
            hidden.rename(parents)
            host = hosts[1]
            assignment_path = Path(host["assignment_path"])
            saved = assignment_path.read_bytes()
            assignment = json.loads(saved)
            for field, value in (("host_id", "unknown"), ("partitions", bindings[0]["plan"]["partitions"]),
                                 ("validation_inputs", {})):
                changed = {**assignment, field: value}
                assignment_path.write_text(json.dumps(changed))
                refused(lambda: C.validate_plan(str(assignment_path)))
            assignment_path.write_bytes(saved)
            remote_master_path = Path(host["master_path"])
            saved_master = remote_master_path.read_bytes()
            for field in ("completed", "pending"):
                altered = copy.deepcopy(master)
                altered[field].append(altered[field][0])
                remote_master_path.write_text(json.dumps(altered))
                changed = _assignment(altered, R.sha256_file(str(remote_master_path)), host["id"])
                assignment_path.write_text(json.dumps(changed))
                refused(lambda: C.validate_plan(str(assignment_path)))
            altered = copy.deepcopy(master)
            altered["pending"] = altered["pending"][1:]
            refused(lambda: _arithmetic(altered, full))
            altered = copy.deepcopy(master)
            altered["partitions"][0], altered["partitions"][1] = altered["partitions"][1], altered["partitions"][0]
            refused(lambda: _arithmetic(altered, full))
            remote_master_path.write_bytes(saved_master)
            assignment_path.write_bytes(saved)
            candidate = Path(host["inputs"]["candidate"])
            saved_candidate = candidate.read_bytes()
            candidate.write_bytes(saved_candidate + b'\n')
            refused(lambda: C.validate_plan(str(assignment_path)))
            candidate.write_bytes(saved_candidate)
            child_paths = {}
            for host_index, (host, binding) in enumerate(zip(hosts, bindings)):
                output = root / (host["id"] + "-outputs")
                output.mkdir()
                child_paths[host["id"]] = []
                for i, pairs in enumerate(binding["partitions"]):
                    ident = C.validate_identity(binding, identity(pairs, i, str(host_index + 7) * 64))
                    path = output / f"gold.w{i}.jsonl"
                    save(path, ident, pairs, "complete", resources(host["id"] + "-fresh"))
                    child_paths[host["id"]].append(str(path))
            refused(lambda: R.validate_native_shards(child_paths["host1"]))
            refused(lambda: validate_distributed_observation(master_path, {"host1": child_paths["host1"]}))
            refused(lambda: validate_distributed_observation(master_path, {
                "host1": child_paths["host1"], "host2": child_paths["host1"]}))
            refused(lambda: validate_distributed_observation(master_path, {
                "host1": child_paths["host1"][:-1], "host2": child_paths["host2"]}))
            # Even internally re-hashed native rows cannot claim a foreign pair.
            bad_child = Path(child_paths["host1"][0])
            bad_side = Path(R.provenance_path(str(bad_child)))
            original_rows, original_provenance = bad_child.read_bytes(), bad_side.read_bytes()
            child_rows = [json.loads(line) for line in original_rows.splitlines()]
            child_rows[0]["mutant_id"] = "foreign-mutant"
            bad_child.write_text(''.join(json.dumps(row) + '\n' for row in child_rows))
            side = json.loads(original_provenance)
            side["rows"], side["rows_sha256"] = R._rows_state(str(bad_child))
            bad_side.write_text(json.dumps(side))
            refused(lambda: validate_distributed_observation(master_path, child_paths))
            bad_child.write_bytes(original_rows)
            bad_side.write_bytes(original_provenance)
            result = validate_distributed_observation(master_path, child_paths)
            assert result["pairs"] == 400 and result["native_pairs"] == 370
            assert len(result["uncertain_pairs"]) == 6 and len(result["unresolved_pairs"]) == 24
            assert not result["complete"] and not result["stable_killset"]
            closed = validate_distributed_observation(master_path, child_paths, held_disposition=HELD_NEVER_OBSERVED)
            assert closed["complete"] and not closed["stable_killset"] and closed["unresolved_pairs"] == []
            assert closed["held_never_observed_pairs"] == result["unresolved_pairs"]
            assert closed["uncertain_pairs"] == result["uncertain_pairs"] and closed["native_pairs"] == 370
            refused(lambda: validate_distributed_observation(master_path, child_paths, held_disposition="executed"))
            parent = Path(parent_paths[0])
            original_parent = parent.read_bytes()
            parent.write_bytes(original_parent + b'\n')
            refused(lambda: validate_distributed_observation(master_path, child_paths))
            refused(lambda: validate_distributed_observation(master_path, child_paths,
                                                             held_disposition=HELD_NEVER_OBSERVED))
    # Production parents use --init. Exercise their actual docker-top shape,
    # while retaining refusal of an active Ruby child or a foreign init PID.
    import subprocess
    from ..core import docker_cli
    inspection = {"Image": "image", "Name": "/parent", "HostConfig": {"Init": True},
                  "ExecIDs": [], "State": {"Running": True, "Paused": False,
                    "Restarting": False, "Pid": os.getpid()}}
    top = [f"PID COMMAND COMMAND\n{os.getpid()} docker-init /sbin/docker-init -- tail -f /dev/null\n"
           "101 tail tail -f /dev/null\n102 postgres postgres\n"]
    def command(args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=json.dumps([inspection]) if args[0] == "inspect" else top[0])
    with patch.object(docker_cli, "docker_argv", side_effect=lambda args: args), \
            patch.object(subprocess, "run", side_effect=command), \
            patch.object(Path, "iterdir", return_value=[]):
        _quiescence([{"container": "parent"}], "/fixture", "image")
        top[0] += "103 ruby cucumber\n"
        refused(lambda: _quiescence([{"container": "parent"}], "/fixture", "image"))
        top[0] = top[0].replace("103 ruby cucumber\n", "")
        inspection["HostConfig"]["Init"] = False
        refused(lambda: _quiescence([{"container": "parent"}], "/fixture", "image"))
        inspection["HostConfig"]["Init"] = True
        inspection["ExecIDs"] = ["live-exec"]
        refused(lambda: _quiescence([{"container": "parent"}], "/fixture", "image"))
        inspection["ExecIDs"] = []
        top[0] = top[0].replace(f"{os.getpid()} docker-init", "999999 docker-init")
        refused(lambda: _quiescence([{"container": "parent"}], "/fixture", "image"))
    print("  [PASS] two-host native freeze, portable assignments, relocation, tamper, union and strict native refusal")
    return 0
