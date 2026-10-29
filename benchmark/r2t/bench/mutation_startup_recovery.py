"""Explicit no-repeat development-pilot recovery; NEXT_SLICE_EXECUTION_SPEC §3.1.

This coordinator does not execute a mutation engine. It authenticates a narrow
historical startup boundary and runs the original reviewed CLI unchanged.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from . import mutation_run as MR
from . import test_quality as TQ

# The reviewed run_slice at this commit compiles the Java engine before
# creating the shard or observing a pair. Other source versions need review,
# not a diagnostic-string heuristic that guesses their execution boundary.
EXECUTION_COMMIT = "7c914a50b42d41fdb779866156a441bd461ce6f0"
SCHEMA = "r2t.pilot-startup-recovery/1"


def require(value, message):
    if not value:
        raise TQ.TestQualityRefused("REFUSED: startup recovery: " + message)


def read(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(),
            f"not a regular evidence file: {path}")
    return path.read_bytes()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def option(argv, name):
    require(argv.count(name) == 1, f"expected exactly one {name}")
    index = argv.index(name) + 1
    require(index < len(argv) and not argv[index].startswith("--"),
            f"missing value for {name}")
    return argv[index]


def git(source, *args):
    return subprocess.check_output(
        ["git", "-C", str(source), *args], text=True).strip()


def authenticate_source(source):
    require(git(source, "rev-parse", "HEAD") == EXECUTION_COMMIT,
            "execution checkout is not the reviewed startup-boundary commit")
    require(not git(source, "status", "--porcelain", "--untracked-files=normal"),
            "execution checkout is not clean")
    require(git(source, "rev-parse", "--abbrev-ref", "HEAD") == "HEAD",
            "execution checkout must be detached")


def invocation(started_path, campaign):
    raw = read(started_path)
    started = json.loads(raw)
    require(started.get("source_commit") == EXECUTION_COMMIT,
            "launch record has a different execution source")
    jobs = ([started["job"]] if "job" in started else started.get("jobs", []))
    require(len(jobs) == 1, "expected one candidate CLI launch")
    argv = jobs[0].get("argv", [])
    require(isinstance(argv, list) and all(isinstance(x, str) for x in argv),
            "launch argv is malformed")
    require(argv[1:3] == ["-m", "r2t.cli"] and "test-quality" in argv
            and "--development" in argv and "--resume" not in argv,
            "only original development test-quality launches are supported")
    require(Path(option(argv, "--out")).resolve() == campaign,
            "launch record belongs to another output")
    if "--allow-degraded-gold" in argv:
        approval = started.get("owner_approval", {})
        require(approval and digest(read(approval["path"])) == approval["sha256"],
                "degraded command lacks its retained owner approval")
    return argv, jobs[0]["log"], digest(raw)


def execution_environment(plan_path, source, argv):
    plan = json.loads(read(plan_path))
    require(plan["execution_source_commit"] == EXECUTION_COMMIT
            and Path(plan["cwd"]).resolve() == source
            and git(source, "rev-parse", plan["execution_source_tag"] + "^{}")
            == EXECUTION_COMMIT
            and git(source, "rev-parse", "HEAD^{tree}") == plan["execution_source_tree"],
            "original execution plan/source binding differs")
    original = [x for x in argv if x != "--allow-degraded-gold"]
    require(any(job["argv"] == original for job in plan["candidate_observations"]),
            "actual launch differs from the original frozen command")
    environment = plan["environment"]
    require(environment["PYTHONPATH"] == str(source / "benchmark"),
            "original Python import path differs")
    return dict(os.environ, JAVA_HOME=environment["JAVA_HOME"],
                PYTHONPATH=environment["PYTHONPATH"], PYTHONDONTWRITEBYTECODE="1")


def pristine_workers(source, command, environment, state):
    # No CLI dispatch or Docker operation: construct each original native
    # harness and read its substrate against its original immutable baseline.
    probe = '''
import argparse, json, sys
from r2t.stacks.cucumber import make_harness
from r2t.bench import mutation_run as M
d=json.load(sys.stdin)
a=d['argv']
def option(k): return a[a.index(k)+1]
for r in d['plan']['worker_resources']:
    args=argparse.Namespace(boundary=option('--boundary'),gold=option('--gold'),
        repo=r['workspace'],container=r['container'],workdir=r['workdir'])
    harness,_,_=make_harness(args)
    wanted=d['plan']['jobs'][r['index']]['campaign_identity']['substrate_baseline_sha256']
    if M.substrate_baseline_digest(harness)!=wanted:
        raise RuntimeError('worker baseline identity differs')
    M._require_pristine_substrate(harness,'startup continuation admission')
'''
    subprocess.run([command[0], "-c", probe], cwd=source, env=environment,
                   input=json.dumps({"argv": command, "plan": state["plan"]}),
                   text=True, check=True)


def sync_parent(path):
    # atomic_write_bytes may create the receipt's parent hierarchy. Persist
    # each directory entry too, before reopening a root in another directory.
    parent = Path(path).parent.resolve()
    for directory in (parent, *parent.parents):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def planned_pairs(state, argv):
    """Reconstruct actual membership, not just attestations of row stamps."""
    plan = state["plan"]
    TQ._validate_campaign_state(state, plan)
    require(plan.get("schema") == TQ.TEST_QUALITY_PLAN_SCHEMA
            and plan.get("gold_precomputed") is True
            and plan.get("require_complete") is True,
            "only complete-policy candidate plans v2 are supported")
    jobs = plan["jobs"]
    require(jobs and all(j["side"] == "candidate" for j in jobs),
            "only candidate jobs are supported")
    first = jobs[0]["campaign_identity"]
    for flag, field in (("--run", "candidate_run_sha256"),
                        ("--manifest", "manifest_sha256"),
                        ("--map", "map_sha256"),
                        ("--release", "release_sha256"),
                        ("--gold-baseline", "gold_baseline_sha256")):
        require(digest(read(option(argv, flag))) == first[field],
                f"changed input {flag}")
    candidates = [json.loads(line) for line in
                  read(option(argv, "--run")).splitlines() if line.strip()]
    files = TQ.passed_solutions(candidates)
    manifest = json.loads(read(option(argv, "--manifest")))
    mapping = json.loads(read(option(argv, "--map")))["by_mutant"]
    mutants, restricted, _ = TQ.population(manifest, mapping, files)
    expected = TQ.expected_pairs(restricted)
    require(len(expected) == plan["expected_pairs"]
            and MR.pair_set_digest(expected) == plan["expected_pairs_sha256"],
            "reconstructed population differs from root plan")
    n = len(jobs)
    require(sorted(j["worker"] for j in jobs) == list(range(n))
            and all(j["of"] == n for j in jobs), "incomplete worker plan")
    shards = TQ.shard_mutants(mutants, restricted, files, n,
                             policy=plan["shard_policy"])
    result = {}
    for job in jobs:
        identity = job["campaign_identity"]
        pairs = TQ._job_pairs(shards[job["worker"]], restricted, files)
        require(identity["side"] == "candidate"
                and identity["shard"] == job["worker"]
                and identity["of"] == n
                and MR.campaign_identity_digest(identity)
                == job["mutation_campaign_digest"]
                and len(pairs) == identity["expected_pairs"]
                and MR.pair_set_digest(pairs) == identity["expected_pairs_sha256"],
                "reconstructed shard differs from original identity")
        result[job["out"]] = pairs
    return result


def inspect(campaign, state, pairs, *, final=False):
    plan = state["plan"]
    TQ.validate_output_contents(
        str(campaign), plan["jobs"], campaign_plan=plan,
        final_names=plan["final_artifacts"] if final else (),
        require_all_shards=final,
        campaign_status="complete" if final else None)
    evidence, absent = {}, []
    for job in plan["jobs"]:
        relative = job["out"]
        path = campaign / relative
        side = Path(str(path) + ".provenance.json")
        require(path.exists() == side.exists(), "orphan rows or sidecar")
        if not path.exists():
            absent.append(job["worker"])
            continue
        raw, side_raw = read(path), read(side)
        doc = json.loads(side_raw)
        allowed = {"interrupted", "complete"}
        # An abrupt stop with a running sidecar is never guessed resumable.
        require(doc["status"] in allowed, "actual failed/running shard")
        MR.completed_pairs(str(path), job["campaign_identity"],
                           expected_pairs=pairs[relative],
                           expected_shard_policy=plan["shard_policy"],
                           require_complete=final)
        MR.validate_worker_resource_evidence(doc, job["campaign_identity"])
        evidence[relative] = {"bytes": len(raw), "sha256": digest(raw),
                              "sidecar_sha256": digest(side_raw),
                              "status": doc["status"]}
    require(evidence, "no authenticated shard evidence")
    return evidence, absent


def startup_evidence(state, absent, log_path):
    require(state["status"] == "failed" and absent,
            "not a failed root with absent startup shards")
    # The frozen source emits worker/stage/class in this aggregation. The
    # source boundary, exact launch record, absent files, and saved log are
    # all required; a matching diagnostic string alone does not admit it.
    text = state["error"]
    sections = re.findall(r"worker (\d+) / candidate: ([\s\S]*?)(?=\n  worker |\Z)", text)
    errors = {int(worker): message for worker, message in sections}
    require(len(errors) == len(sections), "duplicate worker error")
    fault = "unable to create session key: disk quota exceeded"
    for worker in absent:
        message = errors.get(worker, "")
        require(message.startswith("MutationAborted: REFUSED: compiling the isolated Java mutation engine failed (rc=125):")
                and fault in message, "absent shard lacks compiler startup proof")
    log = read(log_path)
    require(all(errors[w].strip().encode() in log for w in absent),
            "saved launch log does not corroborate missing-worker failures")
    return {"path": str(log_path), "sha256": digest(log),
            "absent_workers": sorted(absent),
            "boundary_source_commit": EXECUTION_COMMIT}


def verify_retained(campaign, receipt):
    for relative, old in receipt["shards"].items():
        raw = read(campaign / relative)
        require(len(raw) >= old["bytes"]
                and digest(raw[:old["bytes"]]) == old["sha256"],
                "recorded observation bytes changed")
        if old["status"] == "complete":
            require(len(raw) == old["bytes"]
                    and digest(read(campaign / (relative + ".provenance.json")))
                    == old["sidecar_sha256"], "completed shard changed")


@contextlib.contextmanager
def pool_lock(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd
    finally:
        os.close(fd)


def prepare(campaign, receipt_path, argv, launch_sha, log_path,
            recovery_commit, correction):
    """Called under pool and native output locks; one atomic receipt first."""
    root_path = campaign / "campaign.json"
    raw = read(root_path)
    state = json.loads(raw)
    pairs = planned_pairs(state, argv)
    if receipt_path.exists():
        receipt = json.loads(read(receipt_path))
        require(receipt.get("schema") == SCHEMA
                and receipt.get("campaign") == str(campaign)
                and receipt.get("argv") == argv
                and receipt.get("launch_sha256") == launch_sha
                and receipt.get("recovery_commit") == recovery_commit
                and receipt.get("execution_commit") == EXECUTION_COMMIT
                and receipt.get("operator_opt_in") is True,
                "receipt identity changed")
        saved = base64.b64decode(receipt["failed_root_b64"], validate=True)
        require(digest(saved) == receipt["failed_root_sha256"], "snapshot changed")
        original = json.loads(saved)
        require(original["status"] == "failed"
                and original["plan"] == state["plan"], "snapshot plan changed")
        historical_absent = [job["worker"] for job in original["plan"]["jobs"]
                             if job["out"] not in receipt["shards"]]
        require(startup_evidence(original, historical_absent,
                                 receipt["startup_evidence"]["path"])
                == receipt["startup_evidence"], "saved startup proof changed")
        verify_retained(campaign, receipt)
        if raw != saved:
            prefix = [*original["history"], "running"]
            require(state["history"][:len(prefix)] == prefix,
                    "root lost explicit failure/continuation history")
            require(state["status"] in {"running", "interrupted", "complete"},
                    "new terminal failure needs separate reviewed recovery")
            inspect(campaign, state, pairs, final=state["status"] == "complete")
            return receipt, state["status"] == "complete"
        inspect(campaign, state, pairs)
    else:
        shards, absent = inspect(campaign, state, pairs)
        proof = startup_evidence(state, absent, log_path)
        require(correction.strip(), "record the corrected external cause")
        receipt = {"schema": SCHEMA, "campaign": str(campaign),
                   "argv": argv, "launch_sha256": launch_sha,
                   "execution_commit": EXECUTION_COMMIT,
                   "recovery_commit": recovery_commit,
                   "correction": correction, "operator_opt_in": True,
                   "failed_root_b64": base64.b64encode(raw).decode(),
                   "failed_root_sha256": digest(raw), "shards": shards,
                   "startup_evidence": proof}
        MR.atomic_write_bytes(str(receipt_path),
                              (json.dumps(receipt, sort_keys=True, indent=2)
                               + "\n").encode(), refuse_existing=True)
    # File fsync alone does not make its renamed directory entry durable.
    sync_parent(receipt_path)
    reopened = {**state, "status": "running", "error": None,
                "history": [*state["history"], "running"]}
    TQ._validate_campaign_state(reopened, state["plan"])
    MR.atomic_write_json(str(root_path), reopened)
    sync_parent(root_path)
    return receipt, False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--continue-startup-failure", action="store_true", required=True)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--started", type=Path, required=True)
    parser.add_argument("--execution-plan", type=Path, required=True)
    parser.add_argument("--pool-lock", type=Path, required=True)
    parser.add_argument("--correction", required=True)
    args = parser.parse_args(argv)
    campaign = args.campaign.resolve()
    receipt_path = args.receipt.resolve()
    require(not receipt_path.is_relative_to(campaign), "receipt must be outside campaign")
    source = args.source.resolve()
    authenticate_source(source)
    own_source = Path(__file__).resolve().parents[3]
    require(not git(own_source, "status", "--porcelain", "--untracked-files=normal"),
            "recovery source must be clean")
    own_commit = git(own_source, "rev-parse", "HEAD")
    command, log_path, launch_sha = invocation(args.started, campaign)
    env = execution_environment(args.execution_plan, source, command)
    launch_sha = MR.content_digest({"started": launch_sha,
                                   "execution_plan": digest(read(args.execution_plan))})
    with pool_lock(args.pool_lock) as lock_fd:
        with MR.output_lock(str(campaign)):
            pristine_workers(source, command, env,
                             json.loads(read(campaign / "campaign.json")))
            receipt, complete = prepare(campaign, receipt_path, command,
                                        launch_sha, log_path, own_commit,
                                        args.correction)
        if not complete:
            # The child inherits the shared pool lock, including if its
            # coordinator dies; another recovery cannot overlap that child.
            result = subprocess.run([*command, "--resume"], cwd=source,
                                    env=env, pass_fds=(lock_fd,))
            require(result.returncode == 0,
                    f"original runner exited {result.returncode}; evidence preserved")
        with MR.output_lock(str(campaign)):
            state = json.loads(read(campaign / "campaign.json"))
            require(json.loads(read(receipt_path)) == receipt, "receipt changed during run")
            verify_retained(campaign, receipt)
            inspect(campaign, state, planned_pairs(state, command), final=True)
        print(json.dumps({"status": "complete", "continued_observation": True,
                          "receipt": str(receipt_path), "campaign": str(campaign)}))
    return 0


def selftest():
    """Native identities/sidecars with fake workers; no container or run access."""
    import tempfile
    import unittest
    from unittest.mock import patch

    class RecoveryTests(unittest.TestCase):
        def setUp(self):
            self.tmp = tempfile.TemporaryDirectory()
            self.addCleanup(self.tmp.cleanup)
            self.root = Path(self.tmp.name)
            # Worker provisioning has its own native tests. Recovery tests
            # retain real root/sidecar/row/membership validation below.
            self.resource_check = patch.object(MR, "validate_worker_resource_evidence",
                                               return_value=[])
            self.resource_check.start()
            self.addCleanup(self.resource_check.stop)

        def fixture(self, name="case", present=12):
            root = self.root / name
            root.mkdir()
            campaign = root / "campaign"
            records = [{"item_id": "i", "outcome": "passed", "produced_files": []}]
            mutants = [{"id": f"m{x:03}"} for x in range(64)]
            mapping = {m["id"]: ["i"] for m in mutants}
            docs = {"run": records, "manifest": {"mutants": mutants},
                    "map": {"by_mutant": mapping}, "release": records,
                    "gold-baseline": records}
            command = ["python", "-m", "r2t.cli", "test-quality", "--development"]
            for key, doc in docs.items():
                path = root / (key + ".json")
                path.write_text(json.dumps(doc) + "\n" if key in {"map", "manifest"}
                                else "".join(json.dumps(row) + "\n" for row in doc))
                command += ["--" + key, str(path)]
            command += ["--out", str(campaign)]
            jobs = TQ.plan_jobs(mutants, {"candidate": {"i": []}}, mapping,
                                16, str(campaign), sides=("candidate",))
            for job in jobs:
                identity = job["identity"]
                for flag, field in (("run", "candidate_run_sha256"),
                                    ("manifest", "manifest_sha256"),
                                    ("map", "map_sha256"),
                                    ("release", "release_sha256"),
                                    ("gold-baseline", "gold_baseline_sha256")):
                    identity[field] = digest(read(root / (flag + ".json")))
            plan = TQ.build_test_quality_campaign_plan(
                jobs, expected=TQ.expected_pairs(mapping), gold_precomputed=True,
                require_complete=True, campaign_dir=str(campaign))
            TQ.prepare_output_directory(str(campaign), jobs, resume=False,
                                        campaign_plan=plan)
            (campaign / "shards").mkdir()
            for index, job in enumerate(jobs[:present]):
                pairs = sorted(TQ._job_pairs(job["mutants"], mapping, {"i": []}))
                rows = [{**MR.row_identity_stamp(job["identity"]),
                         "item_id": item, "mutant_id": mutant,
                         "outcome": "container_error"} for item, mutant in
                        (pairs if index == 0 else pairs[:1])]
                Path(job["out"]).write_text("".join(json.dumps(r) + "\n" for r in rows))
                provenance = {"shard_policy": plan["shard_policy"]}
                MR.write_shard_provenance(job["out"], job["identity"], "running",
                                          provenance=provenance)
                MR.write_shard_provenance(job["out"], job["identity"],
                                          "complete" if index == 0 else "interrupted",
                                          provenance=provenance, error="cancelled" if index else None)
            errors = [f"worker {w} / candidate: MutationAborted: REFUSED: compiling the isolated Java mutation engine failed (rc=125): unable to create session key: disk quota exceeded"
                      for w in range(present, 16)]
            error = "REFUSED: startup failure\n  " + "\n  ".join(errors)
            TQ.transition_campaign_state(str(campaign), plan, "failed", error=error)
            log = root / "launch.log"
            log.write_text(error)
            return campaign, root / "recovery.json", command, log, jobs

        def prepare(self, fixture):
            campaign, receipt, command, log, _ = fixture
            return prepare(campaign, receipt, command, "launch", log,
                           "recovery-source", "host quota corrected")

        def test_real_mixed_shapes_and_native_remaining_membership(self):
            for present in (12, 10):
                fixture = self.fixture(str(present), present)
                campaign, receipt, command, _, jobs = fixture
                old = read(campaign / "campaign.json")
                complete = read(Path(jobs[0]["out"]))
                complete_side = read(Path(jobs[0]["out"] + ".provenance.json"))
                saved, finished = self.prepare(fixture)
                self.assertFalse(finished)
                self.assertEqual(base64.b64decode(saved["failed_root_b64"]), old)
                self.assertEqual(json.loads(read(campaign / "campaign.json"))["history"],
                                 ["running", "failed", "running"])
                TQ.prepare_output_directory(str(campaign), jobs, resume=True,
                                            campaign_plan=json.loads(old)["plan"])
                pairs = planned_pairs(json.loads(read(campaign / "campaign.json")), command)
                remaining = 0
                for job in jobs:
                    relative = "shards/" + Path(job["out"]).name
                    done = (MR.completed_pairs(job["out"], job["identity"],
                                               expected_pairs=pairs[relative])
                            if Path(job["out"]).exists() else set())
                    remaining += len(pairs[relative] - done)
                self.assertEqual(remaining, 64 - (present + 3))
                verify_retained(campaign, saved)
                self.assertEqual(read(Path(jobs[0]["out"])), complete)
                self.assertEqual(read(Path(jobs[0]["out"] + ".provenance.json")), complete_side)
                self.prepare(fixture)  # crash after reopen: no new history/reset

        def test_receipt_durable_before_reopen_and_crash_retry(self):
            fixture = self.fixture()
            campaign, receipt, _, _, _ = fixture
            original = read(campaign / "campaign.json")
            with patch.object(MR, "atomic_write_json", side_effect=RuntimeError("crash")):
                with self.assertRaisesRegex(RuntimeError, "crash"):
                    self.prepare(fixture)
            self.assertTrue(receipt.exists())
            self.assertEqual(read(campaign / "campaign.json"), original)
            saved = read(receipt)
            self.prepare(fixture)
            self.assertEqual(read(receipt), saved)

        def test_durability_includes_new_receipt_parent_hierarchy(self):
            path = self.root / "new" / "nested" / "receipt.json"
            expected = [path.parent, *path.parent.parents]
            with patch.object(os, "open", return_value=47) as opened, \
                    patch.object(os, "fsync") as synced, \
                    patch.object(os, "close") as closed:
                sync_parent(path)
            self.assertEqual([call.args[0] for call in opened.call_args_list], expected)
            self.assertEqual(synced.call_count, len(expected))
            self.assertEqual(closed.call_count, len(expected))

        def test_final_validation_keeps_original_rows_and_history(self):
            fixture = self.fixture()
            campaign, receipt_path, command, _, jobs = fixture
            receipt, _ = self.prepare(fixture)
            state = json.loads(read(campaign / "campaign.json"))
            pairs = planned_pairs(state, command)
            for job in jobs:
                path = Path(job["out"])
                relative = "shards/" + path.name
                if path.exists():
                    done = MR.completed_pairs(str(path), job["identity"],
                                               expected_pairs=pairs[relative])
                    side = json.loads(read(str(path) + ".provenance.json"))
                    if side["status"] == "complete":
                        continue
                else:
                    path.write_bytes(b"")
                    done = set()
                provenance = {"shard_policy": state["plan"]["shard_policy"]}
                MR.write_shard_provenance(str(path), job["identity"], "running",
                                          provenance=provenance)
                with path.open("a") as stream:
                    for item, mutant in sorted(pairs[relative] - done):
                        stream.write(json.dumps({**MR.row_identity_stamp(job["identity"]),
                                                 "item_id": item, "mutant_id": mutant,
                                                 "outcome": "passed"}) + "\n")
                MR.write_shard_provenance(str(path), job["identity"], "complete",
                                          provenance=provenance)
            artifacts = {}
            for name in state["plan"]["final_artifacts"]:
                (campaign / name).write_text("{}\n")
                artifacts[name] = digest(read(campaign / name))
            TQ.transition_campaign_state(str(campaign), state["plan"], "complete",
                                          artifacts=artifacts)
            old_root = read(campaign / "campaign.json")
            saved, complete = self.prepare(fixture)
            self.assertTrue(complete)
            self.assertEqual(saved, receipt)
            self.assertEqual(read(campaign / "campaign.json"), old_root)
            (campaign / "summary.json").write_text("changed")
            with self.assertRaisesRegex(TQ.TestQualityRefused, "hash"):
                self.prepare(fixture)

        def test_rejects_failed_shard_and_torn_rows(self):
            for fault in ("failed", "torn"):
                fixture = self.fixture(fault)
                campaign, receipt, _, _, jobs = fixture
                job = jobs[1]
                if fault == "failed":
                    path = Path(job["out"] + ".provenance.json")
                    doc = json.loads(read(path)); doc["status"] = "failed"
                    path.write_text(json.dumps(doc))
                else:
                    with open(job["out"], "ab") as stream:
                        stream.write(b'{"torn"')
                before = read(campaign / "campaign.json")
                with self.assertRaises((TQ.TestQualityRefused, MR.MutationAborted)):
                    self.prepare(fixture)
                self.assertFalse(receipt.exists())
                self.assertEqual(read(campaign / "campaign.json"), before)

        def test_rejects_missing_proof_changed_inputs_and_prefix(self):
            fixture = self.fixture()
            campaign, receipt, command, log, jobs = fixture
            original_log = read(log)
            log.write_text("unrelated startup error")
            with self.assertRaisesRegex(TQ.TestQualityRefused, "corroborate"):
                self.prepare(fixture)
            log.write_bytes(original_log)
            saved, _ = self.prepare(fixture)
            with open(jobs[1]["out"], "r+b") as stream:
                stream.write(b" ")
            with self.assertRaisesRegex(TQ.TestQualityRefused, "bytes changed"):
                verify_retained(campaign, saved)
            Path(option(command, "--map")).write_text("{}")
            with self.assertRaisesRegex(TQ.TestQualityRefused, "changed input"):
                self.prepare(fixture)

        def test_pool_excludes_second_coordinator(self):
            lock = self.root / "pool.lock"
            with pool_lock(lock):
                with self.assertRaises(BlockingIOError):
                    with pool_lock(lock):
                        self.fail("concurrent coordinator admitted")

    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(RecoveryTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
