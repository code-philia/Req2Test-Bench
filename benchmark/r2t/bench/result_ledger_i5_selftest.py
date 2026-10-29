"""Source-only adversarial checks for I5's publication-opening consumers.

All evidence is synthetic, owner-private, and temporary, including the
reviewed Git repository the blob authority is resolved against.  These checks
never contact Docker, a daemon, a model, a live pool, or the network, never
invoke a paid model, and never write a canonical benchmark artifact.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import subprocess
import tempfile

from . import campaign
from .. import cli
from . import cli as bench_cli
from .. import docker_authority as authority
from . import result_ledger as ledger
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


def _read(path: str) -> bytes:
    return ledger.read_trusted_bytes(path, label="I5 selftest evidence")


def _raw_ref(path: str, raw: bytes | None = None) -> dict:
    if raw is None:
        raw = _read(path)
    return {"path": path, "file_sha256": ledger.raw_sha256(raw)}


def _input(role: str, logical: str, path: str) -> dict:
    raw = _read(path)
    return {
        "role": role, "logical_path": logical, "path": path,
        "byte_length": len(raw), "file_sha256": ledger.raw_sha256(raw),
    }


def _named(values: dict) -> list[dict]:
    return [{
        "name": name,
        "value_json": ledger.canonical_json_bytes(values[name]).decode(),
    } for name in sorted(values)]


def _rows_bytes(rows: list[dict]) -> bytes:
    return b"".join(
        (json.dumps(row, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
        for row in rows)


def _refused(callable_) -> bool:
    try:
        callable_()
    except (SystemExit, ledger.ResultLedgerRefused, ValueError, RuntimeError):
        return True
    return False


def _capture_main(argv: list[str]) -> tuple[int, bytes, bytes]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = 0
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            code = cli.main(argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
            if not isinstance(exc.code, int):
                # The interpreter prints a non-integer SystemExit payload to
                # stderr; the capture keeps the same diagnostic channel.
                stderr.write(str(exc.code) + "\n")
    return code, stdout.getvalue().encode(), stderr.getvalue().encode()


# ------------------------------------------------------------------ fixture
def _shared(root: str) -> dict:
    """Everything three independent campaigns must agree about, built once."""
    base = ledger._build_selftest_fixture(root)
    logical_feature = "features/shared.feature"
    feature_raw = (
        b"Feature: publication consumers\n"
        b"  Scenario: shared bytes\n"
        b"    Given one stable fixture\n")
    workspaces = [root + "/ws0", root + "/ws1"]
    artifacts = [root + "/art0", root + "/art1"]
    for path in workspaces + artifacts:
        os.makedirs(path, mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
    for workspace_path in workspaces:
        _write(workspace_path + "/" + logical_feature, feature_raw, raw=True)

    # Compare's own inference gate needs at least twenty distinct closure
    # clusters, so the fixture carries twenty complete items per shard, each
    # with its own gold closure.
    per_shard = 20
    candidates = [f"python-docx/generated-{index:03d}" for index in range(256)]
    by_shard: dict[int, list[str]] = {0: [], 1: []}
    selected = []
    for item_id in candidates:
        shard = campaign.shard_of(item_id, 2)
        if len(by_shard[shard]) < per_shard:
            by_shard[shard].append(item_id)
            selected.append(item_id)
        if all(len(values) == per_shard for values in by_shard.values()):
            break
    if any(len(values) != per_shard for values in by_shard.values()):
        raise AssertionError("fixture candidates do not span two shards")
    release_ids = list(reversed(selected))
    release_rows = [{
        "item_id": item_id, "task": "criterion_to_test",
        "project": "python-docx", "language": "python",
        "framework": "behave",
        "provenance": {"file_path": logical_feature, "line": number + 2},
    } for number, item_id in enumerate(release_ids)]
    release_raw = _rows_bytes(release_rows)
    # Deliberately suffixed: an output whose derived lock would alias this
    # trusted release file must be refused rather than silently accepted.
    release_path = root + "/release-source.result-v3.lock"
    _write(release_path, release_raw, raw=True)

    # One gold closure per release item, under the release's own gold tree.
    gold_root = root + "/gold"
    gold_names = {}
    gold_sources = {}
    for number, item_id in enumerate(release_ids):
        relative = f"features/steps/fixture_source_{number:03d}.py"
        gold_sources[item_id] = relative
        _write(gold_root + "/" + relative,
               f"def fixture_step_{number:03d}():\n    pass\n".encode(),
               raw=True)
        name = item_id.replace("/", "_") + ".json"
        gold_names[item_id] = name
        _write(gold_root + "/" + name, {
            "item_id": item_id, "files": [relative],
            "di_fragment": {}, "context_classes": [],
            "feature_file": logical_feature, "scenario_line": 2,
        })
    _write(gold_root + "/manifest.json", gold_names)

    authority_ref = _raw_ref(base["authority_path"], base["authority_raw"])
    authority_ref["digest"] = base["authority"]["digest"]
    seed_document = ledger.loads_exact_json(base["seed_raw"], label="seed")
    harness = copy.deepcopy(
        base["receipt"]["execution"]["runtime"]["identity"]["harness"])
    return {
        "base": base, "root": root, "workspaces": workspaces,
        "artifacts": artifacts, "logical_feature": logical_feature,
        "release_path": release_path, "release_raw": release_raw,
        "release_ids": release_ids, "release_rows": release_rows,
        "gold_root": gold_root, "gold_names": gold_names,
        "gold_sources": gold_sources,
        "authority_ref": authority_ref, "seed": seed_document,
        "harness": harness,
        "strip_entry": _input("harness_strip_manifest", "strip_manifest.json",
                              base["strip_path"]),
    }


def _campaign(shared: dict, label: str, *, kind: str,
              limit: int | None = None) -> dict:
    """Build and durably merge one complete two-shard campaign."""
    root = shared["root"]
    base = shared["base"]
    release_ids = shared["release_ids"]
    specs, spec_raws, spec_paths = [], [], []
    result_paths, manifest_paths = [], []
    for index in range(2):
        result_path = root + f"/runs/{label}{index}.jsonl"
        env_path = root + f"/secrets/{label}{index}.env"
        spec_path = root + f"/workers/{label}{index}.json"
        spec = worker.WorkerSpec(
            index=index, workspace=shared["workspaces"][index],
            container=f"fixture_{label}_{index}", schema="", credential="",
            env_file=env_path, workdir="/work", out_path=result_path,
            artifacts_root=shared["artifacts"][index])
        _write(env_path, f"R2T_WORKER_INDEX={index}\n".encode(), raw=True)
        spec_raws.append(_write(spec_path, spec.to_json(), indent=1))
        specs.append(spec)
        spec_paths.append(spec_path)
        result_paths.append(result_path)
        manifest_paths.append(root + f"/runs/{label}{index}.worker.json")

    pool = copy.deepcopy(base["binding"]["pool"])
    pool["workers"] = [{
        "index": index, "worker_spec_path": spec_paths[index],
        "worker_spec_sha256": ledger.raw_sha256(spec_raws[index]),
        "container_name": specs[index].container,
    } for index in range(2)]
    pool["digest"] = ledger.semantic_digest(pool)

    binding_refs = []
    for index in range(2):
        binding = copy.deepcopy(base["binding"])
        binding["authority"] = shared["authority_ref"]
        binding["pool"] = copy.deepcopy(pool)
        binding["worker_index"] = index
        binding["worker_spec_sha256"] = ledger.raw_sha256(spec_raws[index])
        binding["container"]["name"] = specs[index].container
        binding["container"]["id"] = f"{ord(label[0]):02x}{index}".ljust(
            64, "0")
        binding["digest"] = ledger.semantic_digest(binding)
        authority.validate_binding_document(binding)
        binding_path = root + f"/binding-{label}{index}.json"
        binding_raw = _write(binding_path, binding, indent=1)
        binding_ref = _raw_ref(binding_path, binding_raw)
        binding_ref["digest"] = binding["digest"]
        binding_refs.append(binding_ref)

    image = base["binding"]["container"]["image_id"]
    runtime_references = []
    for index in range(2):
        runtime_document = {
            "schema": "r2t.worker-runtime/v3",
            "worker": specs[index].to_json(),
            "worker_spec_sha256": ledger.raw_sha256(spec_raws[index]),
            "seed_dir": os.path.dirname(base["seed_path"]),
            "seed_manifest_sha256": ledger.raw_sha256(base["seed_raw"]),
            "seed_key": shared["seed"]["seed_key"],
            "workspace_seed_digest": shared["seed"]["workspace_seed_digest"],
            "database_dump_digest": "no_database",
            "container_image_digest": image,
            "harness_version": HARNESS_VERSION,
            "needs_database": False,
            "docker_execution_authority": shared["authority_ref"],
            "docker_execution_binding": binding_refs[index],
        }
        runtime_path = worker.runtime_attestation_path(spec_paths[index])
        runtime_raw = _write(runtime_path, runtime_document, indent=1)
        identity = {
            "schema": ledger.RUNTIME_IDENTITY_SCHEMA,
            "docker_execution_authority": shared["authority_ref"],
            "docker_execution_binding": binding_refs[index],
            "docker_daemon_fingerprint_sha256":
                base["authority"]["daemon"]["fingerprint_sha256"],
            "docker_execution_pool_digest": pool["digest"],
            "worker_index": index,
            "worker_spec_path": spec_paths[index],
            "worker_spec_sha256": ledger.raw_sha256(spec_raws[index]),
            "container_image_digest": image,
            "seed_dir": os.path.dirname(base["seed_path"]),
            "seed_manifest": _raw_ref(base["seed_path"], base["seed_raw"]),
            "seed_key": shared["seed"]["seed_key"],
            "workspace_seed_digest": shared["seed"]["workspace_seed_digest"],
            "database_dump_digest": "no_database",
            "needs_database": False, "harness": shared["harness"],
            "digest": "0" * 64,
        }
        identity["digest"] = ledger.semantic_digest(identity)
        runtime_references.append({
            "path": runtime_path,
            "file_sha256": ledger.raw_sha256(runtime_raw),
            "identity": identity,
        })

    campaign_document = copy.deepcopy(
        ledger.loads_exact_json(base["campaign_raw"], label="campaign"))
    campaign_document["k_workers"] = 2
    campaign_document["campaign_id"] = f"ledger-I5-{label}"
    campaign_path = root + f"/campaign-{label}.json"
    campaign_raw = _write(campaign_path, campaign_document, indent=1)
    campaign_ref = _raw_ref(campaign_path, campaign_raw)
    campaign_ref.update({
        "campaign_digest": campaign.campaign_digest(campaign_document),
        "semantic_digest": ledger.semantic_digest(campaign_document),
    })
    agent_runtime_raw = _read(
        base["campaign_path"] + ".agent_runtime.json")
    agent_runtime_path = campaign_path + ".agent_runtime.json"
    _write(agent_runtime_path, agent_runtime_raw, raw=True)
    agent_runtime_ref = _raw_ref(agent_runtime_path, agent_runtime_raw)
    agent_runtime_ref["agent_runtime_sha256"] = campaign.agent_runtime_digest(
        ledger.loads_exact_json(agent_runtime_raw, label="agent runtime"))

    boundary_ref = copy.deepcopy(base["receipt"]["plan"]["boundary"])
    profile_ref = copy.deepcopy(base["receipt"]["plan"]["profile"])
    adapter_name = "gold" if kind == "gold" else "empty"
    source_paths = []
    for index in range(2):
        selected = [item_id for item_id in release_ids
                    if campaign.shard_of(item_id, 2) == index]
        if limit is not None:
            selected = selected[:limit]
        stamp = {name: base["result_row"][name]
                 for name in ledger.RUN_STAMP_NAMES}
        stamp.update({
            "campaign_digest": campaign_ref["campaign_digest"],
            "of": 2, "shard": index, "adapter": adapter_name,
        })
        files = [copy.deepcopy(shared["strip_entry"])]
        if selected:
            files.append(_input(
                "harness_feature", shared["logical_feature"],
                shared["workspaces"][index] + "/" + shared["logical_feature"]))
        public_configuration = []
        if kind == "gold":
            public_configuration = _named(
                {"gold_root": shared["gold_root"]})
            files.append(_input(
                "release_gold_manifest", "gold/manifest.json",
                shared["gold_root"] + "/manifest.json"))
            for item_id in selected:
                name = shared["gold_names"][item_id]
                files.append(_input(
                    "release_gold_record", "gold/" + name,
                    shared["gold_root"] + "/" + name))
                relative = shared["gold_sources"][item_id]
                files.append(_input(
                    "gold_source", relative,
                    shared["gold_root"] + "/" + relative))
        files.sort(key=lambda entry: (
            entry["role"], entry["logical_path"], entry["path"]))
        invocation = {
            "schema": ledger.RUN_INVOCATION_SCHEMA,
            "selection": {"limit": limit, "requested_item_ids": None},
            "effective_run_stamp": _named(stamp),
            "adapter": {
                "kind": kind, "name": adapter_name,
                "public_configuration": public_configuration,
                "secret_inputs": [], "files": files,
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
            "release": _raw_ref(shared["release_path"],
                                shared["release_raw"]),
            "boundary": boundary_ref, "profile": profile_ref,
            "protocol": None,
            "worker_manifest_path": manifest_paths[index],
            "shard_index": index, "shard_count": 2,
            "shard_rule": campaign.SHARD_RULE,
            "workset": {
                "item_count": len(selected),
                "ordered_item_ids_digest":
                    ledger.ordered_item_ids_digest(selected),
            },
            "invocation": invocation,
            "invocation_digest": ledger.domain_digest(
                ledger.RUN_INVOCATION_SCHEMA, invocation),
            "digest": "0" * 64,
        }
        plan["digest"] = ledger.semantic_digest(plan)
        rows = [{
            "item_id": item_id, "outcome": "passed",
            "wall_seconds": index + ordinal + 0.125, **stamp,
        } for ordinal, item_id in enumerate(selected)]
        result_raw = _rows_bytes(rows)
        _write(result_paths[index], result_raw, raw=True)
        manifest_raw = _write(manifest_paths[index], {
            "campaign": campaign_document,
            "campaign_digest": campaign_ref["campaign_digest"],
            "worker": campaign.WorkerManifest(
                shard=index, workspace=shared["workspaces"][index],
                container=specs[index].container, schema="", credential="",
                out_path=result_paths[index],
                artifacts_root=shared["artifacts"][index],
                started_at=f"2026-08-08T00:0{index}:00Z",
                finished_at=f"2026-08-08T00:0{index}:59Z",
                campaign_digest=campaign_ref["campaign_digest"]).to_json(),
        }, indent=1)
        receipt = {
            "schema": ledger.RECEIPT_SCHEMA,
            "artifact_kind": "run_shard",
            "execution": {
                "attempt_id": campaign_document["attempt_id"],
                "runtime": runtime_references[index],
            },
            "plan": plan,
            "result": {
                "path": result_paths[index], "byte_length": len(result_raw),
                "row_count": len(rows),
                "file_sha256": ledger.raw_sha256(result_raw),
            },
            "worker_manifest": _raw_ref(manifest_paths[index], manifest_raw),
            "digest": "0" * 64,
        }
        receipt["digest"] = ledger.semantic_digest(receipt)
        receipt_path = result_paths[index] + ledger.RECEIPT_SUFFIX
        _write(receipt_path, receipt, indent=1)
        source_paths.append(receipt_path)

    merged_result = root + f"/merged/{label}.jsonl"
    campaign.merge_publication_v3(
        source_paths, release_path=shared["release_path"],
        out_path=merged_result, expected_shards=2)
    return {
        "label": label, "source_paths": source_paths,
        "result": merged_result,
        "receipt": merged_result + ledger.RECEIPT_SUFFIX,
        "reviewed": f"reviewed/{label}.result-ledger.json",
    }


def _reviewed_repository(root: str, campaigns: list) -> tuple[str, str, str]:
    """A private Git repository holding the exact reviewed receipt blobs."""
    repository = root + "/reviewed-repo"
    os.makedirs(repository, mode=0o700)

    def git(*arguments: str) -> bytes:
        completed = subprocess.run(
            ["git", "-C", repository, *arguments], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        return completed.stdout

    git("init", "-q", "-b", "trunk")
    git("config", "user.email", "fixture@example.invalid")
    git("config", "user.name", "I5 fixture")
    git("commit", "-q", "--allow-empty", "-m", "empty parent")
    empty = git("rev-parse", "HEAD").decode("ascii").strip()
    for entry in campaigns:
        target = repository + "/" + entry["reviewed"]
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        _write(target, _read(entry["receipt"]), raw=True)
    os.symlink("a.result-ledger.json", repository + "/reviewed/link.json")
    git("add", "-A")
    git("commit", "-q", "-m", "reviewed receipts")
    commit = git("rev-parse", "HEAD").decode("ascii").strip()
    # A forged local replacement ref pointing the empty parent at the reviewed
    # commit.  With replacement honoured, `<empty>:reviewed/<label>` resolves
    # through the reviewed tree while the command line keeps naming the empty
    # commit; the authority read must keep answering for the object it was
    # given.  The probe below proves this ref is live by resolving it once
    # with replacement deliberately enabled.
    git("replace", empty, commit)
    return repository, commit, empty


def _promisor_repository(root: str) -> tuple[str, str, str]:
    """A partial clone whose reviewed blob is only available by fetching.

    A promisor clone answers `cat-file blob` for a missing object by going to
    its remote.  That is the one read in this file that could leave the
    machine, so it gets a real fixture rather than a mock: the source lives
    beside it on disk, the clone genuinely lacks the blob, and the guarded
    read must refuse rather than fetch it.
    """
    source = root + "/promisor-source"
    clone = root + "/promisor-clone"
    os.makedirs(source, mode=0o700)

    def git(where: str, *arguments: str) -> bytes:
        completed = subprocess.run(
            ["git", "-C", where, *arguments], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        return completed.stdout

    git(source, "init", "-q", "-b", "trunk")
    git(source, "config", "user.email", "fixture@example.invalid")
    git(source, "config", "user.name", "I5 fixture")
    git(source, "config", "uploadpack.allowFilter", "true")
    reviewed_path = "reviewed/promisor.result-ledger.json"
    _write(source + "/" + reviewed_path, b"{\"promisor\": true}\n", raw=True)
    git(source, "add", "-A")
    git(source, "-c", "commit.gpgSign=false", "commit", "-q", "-m", "promisor")
    commit = git(source, "rev-parse", "HEAD").decode("ascii").strip()
    subprocess.run(
        ["git", "clone", "-q", "--filter=blob:none", "--no-checkout",
         "file://" + source, clone],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    return clone, commit, reviewed_path


def _ancestor_repository(root: str, reviewed_path: str) -> tuple:
    """A repository whose SUBDIRECTORY is the derived root, holding the path.

    This is the shape nobody has to attack to reach: a `git archive` export,
    or a copy of the benchmark tree, sitting anywhere inside another
    checkout.  `git -C <derived root>` starts discovery there rather than
    pinning it, so with no ceiling the outer repository answers -- with a
    real commit, a real blob at the reviewed path, and bytes that are not
    this repository's.  The bytes below are deliberately NOT any receipt's,
    so a read that returns them is unmistakable.
    """
    outer = root + "/ancestor-repo"
    inner = outer + "/checkout"
    os.makedirs(inner, mode=0o700)

    def git(*arguments: str) -> bytes:
        completed = subprocess.run(
            ["git", "-C", outer, *arguments], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        return completed.stdout

    git("init", "-q", "-b", "trunk")
    git("config", "user.email", "fixture@example.invalid")
    git("config", "user.name", "I5 fixture")
    _write(outer + "/" + reviewed_path, b"ANCESTOR\n", raw=True)
    git("add", "-A")
    git("commit", "-q", "-m", "ancestor")
    return outer, inner, git("rev-parse", "HEAD").decode("ascii").strip()


def _fixture() -> dict:
    temporary = tempfile.TemporaryDirectory(prefix="r2t-ledger-i5-")
    root = os.path.realpath(temporary.name)
    for name in ("runs", "workers", "secrets", "merged", "out"):
        path = root + "/" + name
        os.makedirs(path, mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
    shared = _shared(root)
    campaigns = {
        "a": _campaign(shared, "a", kind="empty"),
        "b": _campaign(shared, "b", kind="empty"),
        "g": _campaign(shared, "g", kind="gold"),
        "s": _campaign(shared, "s", kind="empty", limit=1),
    }
    repository, commit, empty_commit = _reviewed_repository(
        root, list(campaigns.values()))
    promisor, promisor_commit, promisor_path = _promisor_repository(root)
    ancestor, ancestor_inner, ancestor_commit = _ancestor_repository(
        root, campaigns["a"]["reviewed"])
    return {
        "temporary": temporary, "root": root, "shared": shared,
        "campaigns": campaigns, "repository": repository, "commit": commit,
        "empty_commit": empty_commit, "promisor": promisor,
        "promisor_commit": promisor_commit, "promisor_path": promisor_path,
        "ancestor": ancestor, "ancestor_inner": ancestor_inner,
        "ancestor_commit": ancestor_commit,
    }


def _role(entry: dict, role: str) -> str:
    return json.dumps({
        "receipt_path": entry["receipt"],
        "reviewed_path": entry["reviewed"], "role": role,
    }, sort_keys=True)


# ------------------------- section 5.1's closed common-substrate membership
# RETYPED FROM THE SPEC, deliberately not imported from the production
# constants these probes exist to police.  A probe driven by
# `_SUBSTRATE_CAMPAIGN_FIELDS` cannot redden when a name leaves it: the loop
# would simply stop making that mutation.  Retyping is what makes a narrowed
# projection -- the regression that would admit two incompatible roles under
# a positive status -- a failing check rather than an invisible one.
_SUBSTRATE_TOP_LEVEL = (
    "boundary", "campaign", "campaign_agent_runtime_schema",
    "docker_authority", "docker_daemon_fingerprint_sha256",
    "effective_run_stamp", "harness_inputs", "pool", "profile", "release",
    "resume", "runtime_identity",
)
_SUBSTRATE_CAMPAIGN = (
    "schema", "k_workers", "shard_rule", "coverage", "harness_version",
    "config_digest", "container_image_digest", "workspace_seed_digest",
    "database_dump_digest",
)
# `harness_version` is projected from `identity["harness"]["version"]`; the
# recorded commit/source pair beside it is role-local (section 16).
_SUBSTRATE_IDENTITY = (
    "container_image_digest", "seed_dir", "seed_manifest", "seed_key",
    "workspace_seed_digest", "database_dump_digest", "needs_database",
    "harness_version",
)
_SUBSTRATE_STAMP = (
    "coverage", "dataset_version", "execution_timeout_seconds",
    "harness_version", "of", "repeats",
    "repro_check_count", "subset_digest", "subset_id",
)
_SUBSTRATE_POOL = ("schema", "database", "network", "worker_count", "workers")
_SUBSTRATE_WORKER = (
    "worker_spec", "binding_schema", "binding_worker_index",
    "container_image_id", "container_running", "container_host_network_mode",
    "container_network_attachments", "network_policy", "egress_probe",
)
_SUBSTRATE_INPUT_ROLES = (
    "harness_strip_manifest", "harness_feature", "harness_alias_table",
    "harness_autowirable_types",
)
#: The exact role-local names section 5.1 admits as differences.  They are
#: the other half of the same partition: a projection that compared them
#: would refuse evidence the spec admits, so they are probed for ADMISSION.
_WORKER_SPEC_ROLE_LOCAL = (
    "workspace", "container", "env_file", "out_path", "artifacts_root",
)
_CAMPAIGN_TREATMENT = ("trial_budget", "condition", "model", "agent_system")
_CAMPAIGN_ROLE_LOCAL = (
    "campaign_id", "attempt_id", "protocol_version", "protocol_digest",
    "agent_runtime_sha256",
)
_STAMP_TREATMENT = (
    "adapter", "adapter_version", "agent_system", "agent_version",
    "comparison_class", "condition", "keep_artifacts", "max_iterations",
    "max_tokens", "model", "native_budget", "prompt_digest", "temperature",
    "trials",
)
_STAMP_ROLE_LOCAL = (
    "campaign_digest", "protocol_digest", "protocol_version", "shard",
)


def _merge_projection(receipt_path: str):
    """The verified merged projection `_publication_substrate` derives FROM.

    Obtained through the production verifier rather than assembled, so the
    mutations below change real recursive evidence and are re-projected by
    the code under test.
    """
    reader = ledger._LiveReader()
    document, raw = ledger._load_ledger_document(
        reader, receipt_path, checkpoint=False)
    projections: list = []
    ledger._verify_receipt_document(
        reader, document, receipt_path, raw, projections)
    reader.confirm()
    return projections[0]


def _plan(projection) -> dict:
    return projection.sources[0].document["plan"]


def _binding(projection, index: int = 0) -> dict:
    return projection.sources[index].runtime.binding


def _worker_spec(projection, index: int = 0) -> dict:
    return projection.sources[index].runtime.runtime["worker"]


def _adapter_files(projection, index: int = 0) -> list:
    return projection.sources[index].document["plan"]["invocation"][
        "adapter"]["files"]


def _harness_entry(projection, index: int, role: str) -> dict:
    for entry in _adapter_files(projection, index):
        if entry["role"] == role:
            return entry
    raise KeyError(role)


def _assign(select, key, value):
    """A drift that assigns one named value inside the copied EVIDENCE."""
    def drift(projection) -> None:
        select(projection)[key] = value
    return drift


def _added_input(role: str):
    """A drift that adds one adapter input file under the given role."""
    def drift(projection) -> None:
        entry = dict(_harness_entry(projection, 0, "harness_feature"))
        entry["role"] = role
        entry["logical_path"] = "added/" + role
        _adapter_files(projection, 0).append(entry)
    return drift


def _substrate_drifts() -> dict:
    """One EVIDENCE mutation per section 5.1 common-substrate member.

    Every drift changes a verified document the projection is derived from,
    never the projection itself: overwriting a key of the built dictionary
    would prove only that `_require_same_json` compares dictionaries, and
    would keep passing if the member had been dropped from the projection
    entirely.
    """
    drifts = {
        "release": _assign(
            lambda p: _plan(p)["release"], "file_sha256", "9" * 64),
        "boundary": _assign(
            lambda p: _plan(p)["boundary"], "file_sha256", "9" * 64),
        "profile": _assign(
            lambda p: _plan(p)["profile"], "path", "/changed/profile.yml"),
        # The FULL authority document, including the two members that are
        # role-local identity everywhere else in this projection.
        "docker_authority.digest": _assign(
            lambda p: p.sources[0].runtime.authority, "digest", "9" * 64),
        "docker_authority.captured_at_utc": _assign(
            lambda p: p.sources[0].runtime.authority,
            "captured_at_utc", "2020-01-01T00:00:00Z"),
        "docker_daemon_fingerprint_sha256": _assign(
            lambda p: p.sources[0].runtime.identity,
            "docker_daemon_fingerprint_sha256", "9" * 64),
        "campaign_agent_runtime_schema": _assign(
            lambda p: p.sources[0].context.agent_runtime,
            "schema", "r2t.agent-runtime-manifest/changed"),
        "resume": _assign(
            lambda p: _plan(p)["invocation"]["resume"], "no_resume", True),
        "pool.schema": _assign(
            lambda p: p.sources[0].runtime.pool, "schema", "changed"),
        "pool.database": _assign(
            lambda p: p.sources[0].runtime.pool, "database", {"name": "db"}),
        "pool.network": _assign(
            lambda p: p.sources[0].runtime.pool["network"], "name", "changed"),
        "pool.worker_count": _extra_pool_worker,
        # Every worker index, both halves of each worker record: the runtime
        # WorkerSpec and the verified binding.
        "pool.workers[0].worker_spec": _assign(
            lambda p: _worker_spec(p, 0), "workdir", "/changed"),
        "pool.workers[1].worker_spec": _assign(
            lambda p: _worker_spec(p, 1), "credential", "changed"),
        "pool.workers[0].binding_schema": _assign(
            lambda p: _binding(p, 0), "schema", "changed"),
        "pool.workers[0].binding_worker_index": _assign(
            lambda p: _binding(p, 0), "worker_index", 7),
        "pool.workers[0].container_image_id": _assign(
            lambda p: _binding(p, 0)["container"],
            "image_id", "sha256:" + "9" * 64),
        "pool.workers[0].container_running": _assign(
            lambda p: _binding(p, 0)["container"], "running", False),
        "pool.workers[0].container_host_network_mode": _assign(
            lambda p: _binding(p, 0)["container"],
            "host_network_mode", "host"),
        "pool.workers[0].container_network_attachments": _assign(
            lambda p: _binding(p, 0)["container"]["network_attachments"][0],
            "name", "changed"),
        "pool.workers[0].network_policy": _assign(
            lambda p: _binding(p, 0)["network_policy"], "internal", True),
        "pool.workers[0].egress_probe": _assign(
            lambda p: _binding(p, 0)["egress_probe"], "status", "changed"),
        "pool.workers[1].egress_probe": _assign(
            lambda p: _binding(p, 1)["egress_probe"], "required", True),
        # The four-field harness-input identity, and the two closed roles
        # this fixture's campaigns do not otherwise carry.
        "harness_inputs.role": _assign(
            lambda p: _harness_entry(p, 0, "harness_feature"),
            "role", "harness_alias_table"),
        "harness_inputs.logical_path": _assign(
            lambda p: _harness_entry(p, 0, "harness_feature"),
            "logical_path", "features/changed.feature"),
        "harness_inputs.byte_length": _assign(
            lambda p: _harness_entry(p, 0, "harness_feature"),
            "byte_length", 1),
        "harness_inputs.file_sha256": _assign(
            lambda p: _harness_entry(p, 0, "harness_feature"),
            "file_sha256", "9" * 64),
        "harness_inputs[source 1]": _assign(
            lambda p: _harness_entry(p, 1, "harness_strip_manifest"),
            "file_sha256", "9" * 64),
        "harness_inputs.harness_alias_table": _added_input(
            "harness_alias_table"),
        "harness_inputs.harness_autowirable_types": _added_input(
            "harness_autowirable_types"),
        "runtime_identity.harness_version": _assign(
            lambda p: p.sources[0].runtime.identity["harness"],
            "version", "changed"),
    }
    for name in _SUBSTRATE_CAMPAIGN:
        drifts["campaign." + name] = _assign(
            lambda p: p.sources[0].context.campaign, name, "changed-" + name)
    for name in _SUBSTRATE_IDENTITY:
        if name == "harness_version":
            continue
        drifts["runtime_identity." + name] = _assign(
            lambda p: p.sources[0].runtime.identity, name, "changed-" + name)
    for name in _SUBSTRATE_STAMP:
        drifts["effective_run_stamp." + name] = _assign(
            lambda p: p.sources[0].context.stamp, name, "changed-" + name)
    return drifts


def _extra_pool_worker(projection) -> None:
    workers = projection.sources[0].runtime.pool["workers"]
    workers.append(copy.deepcopy(workers[0]))


def _role_local_drifts() -> dict:
    """One EVIDENCE mutation per role-local difference section 5.1 admits."""
    drifts = {
        "pool.digest": _assign(
            lambda p: p.sources[0].runtime.pool, "digest", "9" * 64),
        "binding.captured_at_utc": _assign(
            lambda p: _binding(p, 0), "captured_at_utc",
            "2020-01-01T00:00:00Z"),
        "binding.digest": _assign(
            lambda p: _binding(p, 0), "digest", "9" * 64),
        "binding.worker_spec_sha256": _assign(
            lambda p: _binding(p, 0), "worker_spec_sha256", "9" * 64),
        "container.id": _assign(
            lambda p: _binding(p, 0)["container"], "id", "9" * 64),
        "container.name": _assign(
            lambda p: _binding(p, 0)["container"], "name", "changed"),
        "network_attachment.id": _assign(
            lambda p: _binding(p, 0)["container"]["network_attachments"][0],
            "id", "9" * 64),
        "network_policy.id": _assign(
            lambda p: _binding(p, 0)["network_policy"], "id", "9" * 64),
        "harness input absolute path": _assign(
            lambda p: _harness_entry(p, 0, "harness_feature"),
            "path", "/another/workspace/features/shared.feature"),
        "a non-harness adapter input role": _added_input(
            "release_gold_record"),
        # Campaign `network_semantics` is agent-control, so it is admitted
        # HERE and refused between two agent arms by the checks below.
        "campaign.network_semantics": _assign(
            lambda p: p.sources[0].context.campaign,
            "network_semantics", "changed"),
        "campaign_agent_runtime.interpreter": _assign(
            lambda p: p.sources[0].context.agent_runtime,
            "interpreter", "changed"),
        # Section 16: the commit/source pair is recorded provenance; two
        # roles minted or opened at different commits still share a
        # substrate, and only the version above is compared.
        "campaign.harness_commit": _assign(
            lambda p: p.sources[0].context.campaign,
            "harness_commit", "f" * 40),
        "campaign.harness_source_sha256": _assign(
            lambda p: p.sources[0].context.campaign,
            "harness_source_sha256", "f" * 64),
        "effective_run_stamp.harness_commit": _assign(
            lambda p: p.sources[0].context.stamp, "harness_commit", "fffffff"),
        "runtime_identity.harness.git_commit": _assign(
            lambda p: p.sources[0].runtime.identity["harness"],
            "git_commit", "f" * 40),
        "runtime_identity.harness.source_sha256": _assign(
            lambda p: p.sources[0].runtime.identity["harness"],
            "source_sha256", "f" * 64),
    }
    for name in _WORKER_SPEC_ROLE_LOCAL:
        drifts["WorkerSpec." + name] = _assign(
            lambda p: _worker_spec(p, 0), name, "/changed/" + name)
    for name in ("worker_spec_path", "worker_spec_sha256", "container_name"):
        drifts["pool.workers[0]." + name] = _assign(
            lambda p: p.sources[0].runtime.pool["workers"][0],
            name, "changed-" + name)
    for name in _CAMPAIGN_TREATMENT + _CAMPAIGN_ROLE_LOCAL:
        drifts["campaign." + name] = _assign(
            lambda p: p.sources[0].context.campaign, name, "changed-" + name)
    for name in _STAMP_TREATMENT + _STAMP_ROLE_LOCAL:
        drifts["effective_run_stamp." + name] = _assign(
            lambda p: p.sources[0].context.stamp, name, "changed-" + name)
    return drifts


# ------------------------------------- section 9's v2 vectors, from the producer
def _v2_agent_evidence(template: ledger.PublicationRoleEvidence, *,
                       role: str, verified) \
        -> ledger.PublicationRoleEvidence:
    """v2 agent role evidence taken from a REAL verified v2 receipt.

    THE AGENT-PRODUCER STAGE DELETED THE LITERAL CONSTRUCTOR THAT USED TO
    LIVE HERE.  Everything section 9's rules actually read is now the agent
    producer's own output, read back by the production verifier rather than
    written by this file: the receipt schema and its source schemas are the
    v2 constants a verified receipt carried, and the four agent-control
    inputs are the protocol, campaign, campaign-agent-runtime and effective
    stamp `_verify_run_shard_receipt` retained from those exact bytes.  If
    the producer and this file ever disagree about a shape, the checks below
    go red here.

    What is still the v1 template is the merged-role WRAPPER -- result,
    workset, item IDs, substrate and gold closure -- because section 9's
    admission-vector and agent-control rules do not read any of it, and
    because a two-shard v2 merge is the merge stage's own fixture, not this
    one's.
    """
    return ledger.PublicationRoleEvidence(
        role=role, receipt_path=template.receipt_path,
        reviewed_path=template.reviewed_path,
        receipt_file_sha256=template.receipt_file_sha256,
        receipt_digest=template.receipt_digest,
        schema=verified.document["schema"],
        source_schemas=(verified.document["schema"],
                        verified.document["schema"]),
        result=dict(template.result), workset=dict(template.workset),
        item_ids=template.item_ids,
        adapter_kind=verified.context.adapter_files and
        verified.document["plan"]["invocation"]["adapter"]["kind"],
        comparison_class=verified.context.stamp["comparison_class"],
        release_reference=template.release_reference,
        substrate=template.substrate,
        agent_control_inputs={
            "protocol": copy.deepcopy(verified.context.protocol),
            "campaign": copy.deepcopy(verified.context.campaign),
            "agent_runtime": copy.deepcopy(verified.context.agent_runtime),
            "stamp": copy.deepcopy(verified.context.stamp),
        },
        gold_manifest=template.gold_manifest,
        gold_records=template.gold_records,
        input_bytes=template.input_bytes,
        present_paths=template.present_paths,
        absent_paths=template.absent_paths)


def _verified_agent_receipt(root: str, *, label: str, condition: str,
                            budget: int, version: int):
    """Build one real v2 agent shard and read it back through the verifier."""
    from ..agents import result_ledger_v2_selftest as producer
    built = producer.build_agent_receipt(
        root + "/agent-" + label, adapter_kind="openhands", label=label,
        condition=condition, openhands_budget=budget, aider_budget=10,
        version=version)
    reader = ledger._LiveReader()
    document, raw = ledger._load_ledger_document(
        reader, built["receipt_path"], checkpoint=False)
    source = ledger._verify_run_shard_receipt(
        reader, document, built["receipt_path"], raw)
    reader.confirm()
    return source


def _renamed(role: ledger.PublicationRoleEvidence, name: str) \
        -> ledger.PublicationRoleEvidence:
    clone = copy.copy(role)
    clone.role = name
    return clone


def selftest() -> int:
    failures = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        if condition:
            print(f"  [PASS] {name}")
        else:
            failures.append(name + (f": {detail}" if detail else ""))
            print(f"  [FAIL] {name}" + (f" -- {detail}" if detail else ""))

    def refuses(name: str, callable_, *, baseline=None) -> None:
        check(name, _refused(callable_) and (baseline is None or baseline))

    fixture = _fixture()
    original_root = ledger.reviewed_repository_root
    check(
        "the reviewed repository is the real source-derived root two "
        "directories above the running package",
        original_root() == os.path.realpath(os.path.join(
            os.path.dirname(os.path.abspath(ledger.__file__)),
            os.pardir, os.pardir, os.pardir)))
    ledger.reviewed_repository_root = lambda: fixture["repository"]
    try:
        _run_checks(fixture, check, refuses)
    finally:
        ledger.reviewed_repository_root = original_root
        fixture["temporary"].cleanup()

    if failures:
        print("\nFAILURES (result_ledger_i5):")
        for failure in failures:
            print(" - " + failure)
        return 1
    print("\nALL PASS (result_ledger_i5)")
    return 0


def _run_checks(fixture: dict, check, refuses) -> None:
    root = fixture["root"]
    campaigns = fixture["campaigns"]
    commit = fixture["commit"]
    a, b, g, s = (campaigns[key] for key in ("a", "b", "g", "s"))

    # ---------------------------------------------- 1. reviewed Git authority
    blob = ledger.reviewed_blob_bytes(
        commit, a["reviewed"], label="probe")
    check("a reviewed blob equals the live receipt bytes it pins",
          blob == _read(a["receipt"]))
    refuses("an abbreviated commit is not an authority",
            lambda: ledger.reviewed_blob_bytes(
                commit[:12], a["reviewed"], label="probe"))
    refuses("an uppercase commit is not an authority",
            lambda: ledger.reviewed_blob_bytes(
                commit.upper(), a["reviewed"], label="probe"))
    refuses("a branch name is not an authority",
            lambda: ledger.reviewed_blob_bytes(
                "trunk", a["reviewed"], label="probe"))
    refuses("a commit without the reviewed path refuses",
            lambda: ledger.reviewed_blob_bytes(
                fixture["empty_commit"], a["reviewed"], label="probe"))
    refuses("a symlink tree entry is not a regular-file blob",
            lambda: ledger.reviewed_blob_bytes(
                commit, "reviewed/link.json", label="probe"))
    refuses("an absolute reviewed path is refused by grammar",
            lambda: ledger.validate_reviewed_path("/etc/passwd", "probe"))
    refuses("a dot-dot reviewed component is refused by grammar",
            lambda: ledger.validate_reviewed_path("a/../b", "probe"))
    refuses("an over-long reviewed path is refused by grammar",
            lambda: ledger.validate_reviewed_path("a" * 984, "probe"))
    check("the 983-character reviewed path bound is admitted",
          ledger.validate_reviewed_path("a" * 983, "probe") == "a" * 983)

    # ---- 1a. the two invocation controls, against repositories that use them
    # A replacement ref is live in the fixture repository: with replacement
    # honoured the empty parent resolves through the reviewed tree, so the
    # refusal above is the control working rather than the fixture being
    # inert.
    replaced = subprocess.run(
        ["git", "-C", fixture["repository"], "-c", "core.useReplaceRefs=true",
         "ls-tree", "-z", "--full-tree", fixture["empty_commit"], "--",
         a["reviewed"]],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    check("the forged replacement ref really does redirect an unguarded read",
          replaced.returncode == 0 and b"blob" in replaced.stdout)
    refuses("a replacement ref never substitutes for the named commit's tree",
            lambda: ledger.reviewed_blob_bytes(
                fixture["empty_commit"], a["reviewed"], label="probe"))

    # A promisor clone answers a missing blob by fetching it.  The guarded
    # read must refuse; the same read with the control dropped must succeed,
    # or the refusal proves nothing.
    ledger.reviewed_repository_root = lambda: fixture["promisor"]
    try:
        lazy_refused = _refused(lambda: ledger.reviewed_blob_bytes(
            fixture["promisor_commit"], fixture["promisor_path"],
            label="probe"))
    finally:
        ledger.reviewed_repository_root = lambda: fixture["repository"]
    # The SAME read with the control dropped fetches the object and succeeds,
    # so the refusal above is the control rather than an empty fixture.
    lazily = subprocess.run(
        ["git", "-C", fixture["promisor"], "show",
         fixture["promisor_commit"] + ":" + fixture["promisor_path"]],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    check("a missing promisor blob refuses instead of being lazily fetched",
          lazy_refused and lazily.returncode == 0
          and lazily.stdout == b"{\"promisor\": true}\n")

    # The environment is BUILT, not inherited: every name that outranks
    # `-C <repository>` is absent from the child, so exporting one cannot
    # move the question to a repository the caller supplied.
    from ..core import reviewed_git
    check("no name that outranks -C survives into the reviewed read",
          not (set(reviewed_git.REDIRECTING_ENVIRONMENT_NAMES)
               & set(reviewed_git.closed_environment())))
    # ...and the ONE redirecting name a read does carry is derived from the
    # repository rather than inherited from anyone.  Omitting a ceiling is
    # the permissive setting for upward discovery, so it cannot live in the
    # repository-independent set.
    scoped_environment = reviewed_git.closed_environment(fixture["repository"])
    check("the only redirecting name a reviewed read carries is its own "
          "discovery ceiling",
          set(reviewed_git.REDIRECTING_ENVIRONMENT_NAMES)
          & set(scoped_environment) == {"GIT_CEILING_DIRECTORIES"}
          and scoped_environment == dict(
              reviewed_git.closed_environment(),
              GIT_CEILING_DIRECTORIES=os.path.dirname(fixture["repository"])))
    # The promisor clone is a real second repository that does NOT carry the
    # reviewed commit: if any of these names reached Git, the positive read
    # below would refuse instead of returning the pinned receipt bytes.
    other = fixture["promisor"]
    poisoned = {
        "GIT_DIR": other + "/.git", "GIT_WORK_TREE": other,
        "GIT_OBJECT_DIRECTORY": other + "/.git/objects",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": other + "/.git/objects",
        "GIT_CEILING_DIRECTORIES": "/",
        "GIT_COMMON_DIR": other + "/.git",
        "GIT_INDEX_FILE": other + "/.git/index",
        "GIT_NAMESPACE": "shadow",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.useReplaceRefs",
        "GIT_CONFIG_VALUE_0": "true",
    }
    restore = {name: os.environ.get(name) for name in poisoned}
    os.environ.update(poisoned)
    try:
        try:
            poisoned_blob = ledger.reviewed_blob_bytes(
                commit, a["reviewed"], label="probe")
        except ledger.ResultLedgerRefused:
            # A redirected read cannot see the reviewed commit at all; keep
            # it as a failed check rather than an aborted file.
            poisoned_blob = None
        poisoned_replacement = _refused(lambda: ledger.reviewed_blob_bytes(
            fixture["empty_commit"], a["reviewed"], label="probe"))
    finally:
        for name, value in restore.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    check("a caller-supplied repository/config environment cannot answer for "
          "the reviewed one",
          poisoned_blob == _read(a["receipt"]) and poisoned_replacement)

    # ---- 1a. the repository is PINNED, not merely where discovery STARTS.
    # Section 3's first sentence names the source-derived root; `-C <root>`
    # only starts Git's upward search there, so a root that is not itself a
    # repository is answered by its first ancestor that is.  No adversary is
    # needed -- a `git archive` export or a copied tree inside any other
    # checkout has this shape -- and it fails OPEN, with a real commit, a
    # real blob at the reviewed path, and bytes that are not this
    # repository's.
    ancestor = fixture["ancestor"]
    inner = fixture["ancestor_inner"]
    ancestor_commit = fixture["ancestor_commit"]
    try:
        ledger.reviewed_repository_root = lambda: inner
        ascended = _refused(lambda: ledger.reviewed_blob_bytes(
            ancestor_commit, a["reviewed"], label="probe"))
        # The control: that commit/path binding IS locally resolvable, and
        # the outer repository answers for ITSELF, so the refusal above is
        # the pin rather than a missing object or an empty fixture.
        ledger.reviewed_repository_root = lambda: ancestor
        ancestor_bytes = ledger.reviewed_blob_bytes(
            ancestor_commit, a["reviewed"], label="probe")
    finally:
        ledger.reviewed_repository_root = lambda: fixture["repository"]
    check("a repository ANCESTOR may not answer for the derived root",
          ascended and ancestor_bytes == b"ANCESTOR\n")
    check("the pin is Git's own answer about which tree replied, not an "
          "inference from an environment variable's semantics",
          _refused(lambda: reviewed_git.require_repository(inner))
          and reviewed_git.require_repository(ancestor) == ancestor)
    refuses("a repository that is not one normalized absolute directory "
            "refuses before any read",
            lambda: reviewed_git.repository_ceiling("reviewed-repo"))
    refuses("the filesystem root pins nothing and refuses",
            lambda: reviewed_git.repository_ceiling("/"))

    # ---- 1b. one authority model: both callers run the same code
    from . import test_quality
    real_run = reviewed_git.run
    seen = []

    def spy(repository, arguments, **kwargs):
        seen.append((repository, tuple(arguments)))
        return real_run(repository, arguments, **kwargs)

    reviewed_git.run = spy
    try:
        ledger.reviewed_blob_bytes(commit, a["reviewed"], label="probe")
        ledger_calls = len(seen)
        _refused(lambda: test_quality.validate_compute_cap_review_authority(
            a["reviewed"] + "@" + commit))
        cap_calls = len(seen) - ledger_calls
    finally:
        reviewed_git.run = real_run
    check("the ledger and the compute-cap resolver share ONE Git invocation",
          ledger_calls >= 2 and cap_calls >= 1)
    from ..data import mutation_attestation
    check("every reviewed-blob reader runs under the one closed environment",
          mutation_attestation._offline_git_env()
          == reviewed_git.closed_environment())
    check("both callers share one path grammar and one repository root",
          reviewed_git.PATH_PATTERN in
          test_quality._COMPUTE_CAP_REVIEW_AUTHORITY.pattern
          and reviewed_git.COMMIT_PATTERN in
          test_quality._COMPUTE_CAP_REVIEW_AUTHORITY.pattern
          and ledger.REVIEWED_PATH_MAX_LENGTH == reviewed_git.PATH_MAX_LENGTH
          and reviewed_git.repository_root() == os.path.realpath(os.path.join(
              os.path.dirname(os.path.abspath(ledger.__file__)),
              os.pardir, os.pardir, os.pardir)))

    # ------------------------------------------------------- 2. role tokens
    refuses("a role token with an unknown field refuses",
            lambda: ledger.parse_publication_role(json.dumps(
                {"receipt_path": a["receipt"], "reviewed_path": a["reviewed"],
                 "role": "report-run:0", "extra": 1})))
    refuses("a role token with a duplicate key refuses",
            lambda: ledger.parse_publication_role(
                '{"role": "report-run:0", "role": "report-run:0", '
                '"receipt_path": "/x", "reviewed_path": "y"}'))
    refuses("a role token with a non-string value refuses",
            lambda: ledger.parse_publication_role(json.dumps(
                {"receipt_path": a["receipt"],
                 "reviewed_path": a["reviewed"], "role": 0})))
    refuses("a relative role receipt path refuses",
            lambda: ledger.parse_publication_role(json.dumps(
                {"receipt_path": "runs/x.result-ledger.json",
                 "reviewed_path": a["reviewed"], "role": "report-run:0"})))

    def preflight(consumer, tokens, runs, gold=None):
        return ledger.publication_preflight(
            consumer, tokens, commit=commit, run_paths=runs, gold_path=gold)

    report_tokens = [_role(a, "report-run:0"), _role(b, "report-run:1")]
    report_runs = [a["result"], b["result"]]
    roles = preflight("report", report_tokens, report_runs)
    check("two report roles preflight in canonical index order",
          [role.role for role in roles] == ["report-run:0", "report-run:1"]
          and roles[0].result["path"] == a["result"])
    check("record argument order has no authority",
          [role.role for role in preflight(
              "report", list(reversed(report_tokens)), report_runs)]
          == ["report-run:0", "report-run:1"])
    refuses("a gapped report index refuses",
            lambda: preflight(
                "report", [_role(a, "report-run:0"), _role(b, "report-run:2")],
                report_runs))
    refuses("a non-canonical report index spelling refuses",
            lambda: preflight(
                "report", [_role(a, "report-run:0"), _role(b, "report-run:01")],
                report_runs))
    refuses("a duplicate role refuses",
            lambda: preflight(
                "report", [_role(a, "report-run:0"), _role(a, "report-run:1")],
                report_runs))
    refuses("a missing role refuses",
            lambda: preflight("report", [_role(a, "report-run:0")],
                              report_runs))
    refuses("a role whose result is not its input refuses",
            lambda: preflight(
                "report", [_role(b, "report-run:0"), _role(a, "report-run:1")],
                report_runs))
    refuses("a repeated input path refuses",
            lambda: preflight("report", report_tokens,
                              [a["result"], a["result"]]))

    # ------------------------------------------- 3. receipt-class refusals
    shard_receipt = a["source_paths"][0]
    shard_result = shard_receipt[:-len(ledger.RECEIPT_SUFFIX)]
    refuses("a loose run-shard source receipt is not a publication role",
            lambda: preflight(
                "report", [json.dumps({
                    "receipt_path": shard_receipt,
                    "reviewed_path": a["reviewed"],
                    "role": "report-run:0"})], [shard_result]))
    checkpoint_path = a["result"] + ledger.CHECKPOINT_SUFFIX
    _write(checkpoint_path, b"{}\n", raw=True)
    refuses("a checkpoint path is never a complete role",
            lambda: preflight(
                "report", [json.dumps({
                    "receipt_path": checkpoint_path,
                    "reviewed_path": a["reviewed"],
                    "role": "report-run:0"})], [a["result"]]))
    os.unlink(checkpoint_path)
    refuses("the merged result path is not a receipt path (no suffix "
            "inference)",
            lambda: preflight(
                "report", [json.dumps({
                    "receipt_path": a["result"],
                    "reviewed_path": a["reviewed"],
                    "role": "report-run:0"})], [a["result"]]))

    # ------------------------------------- 4. the durable output and status
    out_path = root + "/out/report.txt"
    status_path = out_path + ledger.PUBLICATION_STATUS_SUFFIX
    code, stdout, stderr = _capture_main([
        "report", "--publication-v3", "--publication-commit", commit,
        "--run", a["result"], "--run", b["result"],
        "--publication-role", report_tokens[0],
        "--publication-role", report_tokens[1],
        "--out", out_path])
    published = code == 0 and os.path.isfile(status_path)
    check("report --publication-v3 writes the output and its status",
          published, stderr.decode()[-400:])
    if not published:
        return
    status = ledger.verify_publication_status(status_path)
    check("stdout carries neither rendered bytes nor a second status",
          stdout == b"")
    check("the status binds the exact output bytes and canonical roles",
          status["output"]["file_sha256"] == ledger.raw_sha256(_read(out_path))
          and status["output"]["byte_length"] == len(_read(out_path))
          and [entry["role"] for entry in status["roles"]]
          == ["report-run:0", "report-run:1"]
          and status["consumer"] == "report"
          and status["claim"] == ledger.PUBLICATION_CLAIM
          and status["reviewed_commit"] == commit
          and status["parameters"] == {"per_item": False})
    check("every status role states row_count == item_count",
          all(entry["result"]["row_count"] == entry["workset"]["item_count"]
              for entry in status["roles"]))
    check("the status file bytes are the exact closed serialization",
          _read(status_path) == ledger.publication_status_bytes(status))

    again = _capture_main([
        "report", "--publication-v3", "--publication-commit", commit,
        "--run", a["result"], "--run", b["result"],
        "--publication-role", report_tokens[1],
        "--publication-role", report_tokens[0],
        "--out", out_path])
    check("a verified status/output pair is idempotent under a permuted "
          "record order", again[0] == 0 and again[1] == b"")

    # ------------------------- 4a. THE STATUS/REQUEST JOIN (§7.2)
    # "A present status is never ignored: a fully verified status/output pair
    # for the EXACT request is authoritative and idempotent; an invalid,
    # stale, MISMATCHED, or output-less status refuses."  The permuted
    # republish above is the positive side; without the rows below, the
    # resolver could hand request Y the positive status of request X -- a
    # caller told it published, pointed at a status that binds another
    # parameter set or another role set, and at output rendered for that
    # other request.  Each row asserts the NAMED refusal, so no row can pass
    # for an unrelated reason, and that the published pair is untouched.
    mismatch = ("REFUSED: the present publication status describes another "
                "request")
    published_pair = (_read(out_path), _read(status_path))

    def joined_request(*argv: str) -> bool:
        code, out, err = _capture_main([
            "report", "--publication-v3", "--publication-commit", commit,
            *argv, "--out", out_path])
        return (code != 0 and out == b""
                and err.decode().strip() == mismatch
                and (_read(out_path), _read(status_path)) == published_pair)

    check("a request whose parameters differ is refused, not answered by "
          "the present status",
          joined_request("--run", a["result"], "--run", b["result"],
                         "--publication-role", report_tokens[0],
                         "--publication-role", report_tokens[1], "--per-item"))
    check("a request whose role set differs is refused, not answered by the "
          "present status",
          joined_request("--run", a["result"],
                         "--publication-role", report_tokens[0]))

    # Every joined field, isolated at the predicate the two refusals above
    # reach only at their first disagreement.  No LIVE request can differ in
    # the consumer alone -- each consumer's parameter grammar is disjoint
    # (report has per_item, results has format) -- so the consumer row asks
    # the predicate directly with everything else held equal; without it the
    # consumer comparison would be shadowed by the parameters one.
    def joins(consumer: str, joined_roles, parameters: dict,
              joined_commit: str) -> bool:
        return ledger._publication_status_matches(
            status, consumer, joined_roles, parameters, joined_commit)

    drifted_role = copy.copy(roles[0])
    drifted_role.receipt_digest = "0" * 64
    check("the join answers YES to the exact request the status was built "
          "for", joins("report", roles, {"per_item": False}, commit))
    join_cases = (
        ("consumer", ("results", roles, {"per_item": False}, commit)),
        ("reviewed commit", ("report", roles, {"per_item": False}, "1" * 40)),
        ("parameters", ("report", roles, {"per_item": True}, commit)),
        ("role set", ("report", roles[:1], {"per_item": False}, commit)),
        ("role order", ("report", list(reversed(roles)),
                        {"per_item": False}, commit)),
        ("role evidence under an unchanged name",
         ("report", [drifted_role, roles[1]], {"per_item": False}, commit)),
    )
    for field, request in join_cases:
        check(f"the join answers NO to a request whose {field} differs",
              not joins(*request))

    tampered = copy.deepcopy(status)
    tampered["parameters"] = {"per_item": True}
    check("a status whose parameters changed no longer recomputes",
          ledger.semantic_digest(tampered) != status["digest"])
    check("changing one role digest changes the status digest",
          ledger.semantic_digest(
              {**status,
               "roles": [{**status["roles"][0], "receipt_digest": "0" * 64},
                         status["roles"][1]]}) != status["digest"])

    # §7.2 classifies the tuple in the READ-ONLY pass, BEFORE any lock leaf
    # is created: "With no status, a present output is a burned partial
    # tuple and refuses.  Only an absent status/output tuple can enter
    # creation."  Asserting only "refuses, no status leaf" would also hold
    # if the request entered creation -- took the lock, reclosed, rendered,
    # built a status -- and was stopped later by the no-clobber create's own
    # `already exists`.  So this row asserts the NAMED refusal, which tells
    # its operator the path is burned, AND that no lock leaf was ever
    # created for it.
    burned = root + "/out/burned.txt"
    _write(burned, b"complete but unclaimed\n", raw=True)
    code, burned_stdout, burned_stderr = _capture_main([
        "report", "--publication-v3", "--publication-commit", commit,
        "--run", a["result"], "--run", b["result"],
        "--publication-role", report_tokens[0],
        "--publication-role", report_tokens[1],
        "--out", burned])
    check("a complete but unclaimed output burns its path before the tuple "
          "can enter creation",
          code != 0 and burned_stdout == b""
          and burned_stderr.decode().strip() == (
              "REFUSED: a complete but unclaimed publication output burns "
              "this path; a retry uses a new output")
          and not os.path.lexists(burned + ledger.PUBLICATION_STATUS_SUFFIX)
          and not os.path.lexists(burned + ledger.PUBLICATION_LOCK_SUFFIX))

    collision = _capture_main([
        "report", "--publication-v3", "--publication-commit", commit,
        "--run", a["result"], "--run", b["result"],
        "--publication-role", report_tokens[0],
        "--publication-role", report_tokens[1],
        "--out", fixture["shared"]["release_path"][
            :-len(ledger.PUBLICATION_LOCK_SUFFIX)]])
    check("an output whose derived lock aliases a verified closure member "
          "refuses", collision[0] != 0)

    # ------------------------------------------------ 5. the refusal matrix
    def report_argv(*extra, out: str):
        return ["report", "--publication-v3", "--publication-commit", commit,
                "--run", a["result"], "--run", b["result"],
                "--publication-role", report_tokens[0],
                "--publication-role", report_tokens[1],
                "--out", out, *extra]

    for option in (("--only", "passed"), ("--group-by", "project"),
                   ("--test-quality", root + "/nope.json"),
                   ("--release", fixture["shared"]["release_path"])):
        result = _capture_main(report_argv(*option, out=root + "/out/x.txt"))
        check(f"report --publication-v3 refuses {option[0]}",
              result[0] != 0
              and not os.path.lexists(root + "/out/x.txt"))
    repeated = _capture_main(
        report_argv("--out", root + "/out/y.txt", out=root + "/out/y.txt"))
    check("a repeated singleton refuses instead of taking the last value",
          repeated[0] != 0 and b"repeated singleton" in repeated[2])
    missing_commit = _capture_main([
        "report", "--publication-v3", "--run", a["result"],
        "--publication-role", report_tokens[0], "--out", root + "/out/z.txt"])
    check("a missing mandatory publication occurrence refuses",
          missing_commit[0] != 0)

    # 5a. THE SAME REPEAT, SPELLED AS A PREFIX.  The occurrence scan can only
    # see the literal token, so an abbreviation argparse would resolve for
    # itself is the one way a singleton could still take a last value.  Each
    # of these decoy/real pairs would otherwise write the SECOND path.
    def abbreviated(argv: list, decoy: str, real: str) -> bool:
        result = _capture_main(argv)
        return (result[0] != 0
                and not os.path.lexists(decoy) and not os.path.lexists(real)
                and not os.path.lexists(
                    real + ledger.PUBLICATION_STATUS_SUFFIX)
                and not os.path.lexists(
                    decoy + ledger.PUBLICATION_STATUS_SUFFIX))

    decoy_out = root + "/out/abbrev-decoy.txt"
    real_out = root + "/out/abbrev-real.txt"

    def results_argv(*extra, out: str) -> list:
        return ["results", "--publication-v3", "--publication-commit", commit,
                "--run", a["result"], "--gold", g["result"],
                "--publication-role", _role(a, "results-candidate"),
                "--publication-role", _role(g, "results-gold"),
                "--out", out, *extra]

    def compare_argv(*extra, out: str) -> list:
        return ["compare", "--publication-v3", "--publication-commit", commit,
                "--run", a["result"], "--run", b["result"],
                "--gold-dir", fixture["shared"]["gold_root"],
                "--publication-role", _role(a, "compare-A"),
                "--publication-role", _role(b, "compare-B"),
                "--publication-role", _role(g, "compare-gold"),
                "--out", out, *extra]

    abbreviations = {
        "--ou": report_argv("--ou", real_out, out=decoy_out),
        "--publication-comm": report_argv(
            "--publication-comm", commit, out=decoy_out),
        "--ru": report_argv("--ru", a["result"], out=decoy_out),
        "--per-ite": report_argv("--per-ite", out=decoy_out),
        "--publication-rol": report_argv(
            "--publication-rol", report_tokens[0], out=decoy_out),
        "--gol": results_argv("--gol", g["result"], out=decoy_out),
        "--forma": results_argv("--forma", "json", out=decoy_out),
        "--gold-di": compare_argv(
            "--gold-di", root + "/merged", out=decoy_out),
        "--metri": compare_argv(
            "--metri", "non_vacuous_pass", out=decoy_out),
    }
    prefix_refused = {name: abbreviated(argv, decoy_out, real_out)
                      for name, argv in sorted(abbreviations.items())}
    check("no publication singleton can be repeated as an argparse prefix",
          all(prefix_refused.values()),
          str(sorted(name for name, ok in prefix_refused.items()
                     if not ok)))

    # ------------------------------------------------------- 6. per-item run
    per_item_out = root + "/out/report-per-item.txt"
    per_item = _capture_main(
        report_argv("--per-item", out=per_item_out))
    per_item_status = per_item_out + ledger.PUBLICATION_STATUS_SUFFIX
    check("report --per-item is allowed over all rows and is bound in status",
          per_item[0] == 0
          and ledger.verify_publication_status(
              per_item_status)["parameters"] == {"per_item": True}
          and _read(per_item_out) != _read(out_path))

    # ----------------------------------------------------------- 7. results
    results_tokens = [_role(a, "results-candidate"), _role(g, "results-gold")]
    results_out = root + "/out/results.md"
    results_run = _capture_main([
        "results", "--publication-v3", "--publication-commit", commit,
        "--run", a["result"], "--gold", g["result"],
        "--publication-role", results_tokens[1],
        "--publication-role", results_tokens[0],
        "--format", "markdown", "--out", results_out])
    results_status_path = results_out + ledger.PUBLICATION_STATUS_SUFFIX
    results_published = results_run[0] == 0 \
        and os.path.isfile(results_status_path)
    check("results --publication-v3 publishes over an explicit gold role",
          results_published, results_run[2].decode()[-400:])
    if results_published:
        results_status = ledger.verify_publication_status(results_status_path)
        check("the results status names the four existing formats' choice and "
              "the candidate/gold order",
              results_status["parameters"] == {"format": "markdown"}
              and [entry["role"] for entry in results_status["roles"]]
              == ["results-candidate", "results-gold"])
        check("results renders its unscored mutation and production cells",
              b"not scored" in _read(results_out))
    refuses("results refuses a non-gold gold role",
            lambda: preflight("results",
                              [_role(a, "results-candidate"),
                               _role(b, "results-gold")],
                              [a["result"]], b["result"]))
    refuses("results refuses an unequal candidate/gold workset",
            lambda: preflight("results",
                              [_role(s, "results-candidate"),
                               _role(g, "results-gold")],
                              [s["result"]], g["result"]))
    for option in (("--test-quality", root + "/nope.json"),
                   ("--prod-index", root + "/nope.json"),
                   ("--release", fixture["shared"]["release_path"])):
        result = _capture_main([
            "results", "--publication-v3", "--publication-commit", commit,
            "--run", a["result"], "--gold", g["result"],
            "--publication-role", results_tokens[0],
            "--publication-role", results_tokens[1],
            "--out", root + "/out/rq.md", *option])
        check(f"results --publication-v3 refuses {option[0]}",
              result[0] != 0 and not os.path.lexists(root + "/out/rq.md"))

    # ----------------------------------------------------------- 8. compare
    compare_tokens = [_role(a, "compare-A"), _role(b, "compare-B"),
                      _role(g, "compare-gold")]
    compare_out = root + "/out/compare.txt"
    compare_run = _capture_main([
        "compare", "--publication-v3", "--publication-commit", commit,
        "--run", a["result"], "--run", b["result"],
        "--gold-dir", fixture["shared"]["gold_root"],
        "--publication-role", compare_tokens[2],
        "--publication-role", compare_tokens[0],
        "--publication-role", compare_tokens[1],
        "--out", compare_out])
    compare_status_path = compare_out + ledger.PUBLICATION_STATUS_SUFFIX
    compare_published = compare_run[0] == 0 \
        and os.path.isfile(compare_status_path)
    check("compare --publication-v3 publishes over the receipt-bound gold "
          "closure", compare_published, compare_run[2].decode()[-400:])
    if compare_published:
        compare_status = ledger.verify_publication_status(compare_status_path)
        check("the compare status pins metric pass, the explicit gold "
              "directory, and the A/B/gold order",
              compare_status["parameters"] == {
                  "metric": "pass",
                  "gold_dir": fixture["shared"]["gold_root"]}
              and [entry["role"] for entry in compare_status["roles"]]
              == ["compare-A", "compare-B", "compare-gold"])
    for option in (("--items", fixture["shared"]["release_path"]),
                   ("--metric", "non_vacuous_pass"),
                   ("--test-quality", root + "/nope.json")):
        result = _capture_main([
            "compare", "--publication-v3", "--publication-commit", commit,
            "--run", a["result"], "--run", b["result"],
            "--gold-dir", fixture["shared"]["gold_root"],
            "--publication-role", compare_tokens[0],
            "--publication-role", compare_tokens[1],
            "--publication-role", compare_tokens[2],
            "--out", root + "/out/cq.txt", *option])
        check(f"compare --publication-v3 refuses {option[0]}",
              result[0] != 0 and not os.path.lexists(root + "/out/cq.txt"))
    compare_roles = preflight(
        "compare", compare_tokens, [a["result"], b["result"]])
    refuses("compare refuses a gold directory the receipts do not bind",
            lambda: ledger.publication_gold_clusters(
                compare_roles[2], root + "/merged", compare_roles[0].item_ids))
    clusters = ledger.publication_gold_clusters(
        compare_roles[2], fixture["shared"]["gold_root"],
        compare_roles[0].item_ids)
    check("the cluster map is derived from receipt-bound gold bytes only",
          set(clusters) == set(compare_roles[0].item_ids)
          and len(set(clusters.values())) == len(clusters))
    refuses("a non-gold compare-gold role refuses",
            lambda: preflight("compare",
                              [_role(a, "compare-A"), _role(g, "compare-B"),
                               _role(b, "compare-gold")],
                              [a["result"], g["result"]]))
    refuses("compare refuses an unequal A/B/gold workset",
            lambda: preflight("compare",
                              [_role(s, "compare-A"), _role(b, "compare-B"),
                               _role(g, "compare-gold")],
                              [s["result"], b["result"]]))
    refuses("compare-gold may not also be an outcome arm",
            lambda: preflight("compare",
                              [_role(a, "compare-A"), _role(g, "compare-B"),
                               _role(g, "compare-gold")],
                              [a["result"], g["result"]]))

    # ------------------------------- 9. common substrate and agent control
    # The substrate half runs the way the agent-control half does: over the
    # verified evidence the projection is DERIVED from, re-projected by the
    # production code.  Overwriting keys of the built projection instead
    # would prove only that `_require_same_json` compares dictionaries, and
    # would stay green while a member was deleted from the projection.
    substrate_projection = _merge_projection(a["receipt"])
    substrate = ledger._publication_substrate(substrate_projection)
    check("these probes re-derive exactly the substrate the publication path "
          "retained for both compared roles",
          ledger._same_json_value(substrate, compare_roles[0].substrate)
          and ledger._same_json_value(substrate, compare_roles[1].substrate))

    def substrate_role(drift) -> ledger.PublicationRoleEvidence:
        mutated = copy.deepcopy(substrate_projection)
        drift(mutated)
        drifted = copy.copy(compare_roles[0])
        drifted.substrate = ledger._publication_substrate(mutated)
        return drifted

    # Section 5.1 CLOSES this projection: "a field not assigned above is not
    # silently ignored".  A narrowed one is the regression that would admit
    # two incompatible roles under a positive status, so the membership is
    # asserted and not only exercised.
    # Each membership check GUARDS the one below it, so a projection that
    # narrowed the level above reports a failed check rather than raising a
    # KeyError out of the file and taking the remaining probes with it.
    source_workers = [source.runtime.runtime["worker"]
                      for source in substrate_projection.sources]
    closed_top = sorted(substrate) == sorted(_SUBSTRATE_TOP_LEVEL)
    check("the common substrate is exactly section 5.1's closed top level",
          closed_top)
    check("its campaign, runtime-identity and effective-stamp members are "
          "exactly the closed names",
          closed_top
          and sorted(substrate["campaign"]) == sorted(_SUBSTRATE_CAMPAIGN)
          and sorted(substrate["runtime_identity"])
          == sorted(_SUBSTRATE_IDENTITY)
          and sorted(substrate["effective_run_stamp"])
          == sorted(_SUBSTRATE_STAMP))
    closed_workers = closed_top \
        and sorted(substrate["pool"]) == sorted(_SUBSTRATE_POOL) \
        and len(substrate["pool"]["workers"]) == len(source_workers) \
        and all(sorted(worker) == sorted(_SUBSTRATE_WORKER)
                for worker in substrate["pool"]["workers"])
    check("the pool/runtime projection is ordered, closed, and covers every "
          "worker index",
          closed_workers
          and substrate["pool"]["worker_count"] == len(source_workers)
          and [worker["binding_worker_index"]
               for worker in substrate["pool"]["workers"]]
          == list(range(len(source_workers))))
    check("each retained WorkerSpec drops ONLY the five role-local names",
          closed_workers
          and all(sorted(worker["worker_spec"])
                  == sorted(set(source) - set(_WORKER_SPEC_ROLE_LOCAL))
                  for worker, source in zip(substrate["pool"]["workers"],
                                            source_workers)))
    check("attachments and the network policy lose only their object IDs, "
          "and the egress probe is the exact one",
          closed_workers and all(
              [sorted(attachment) for attachment
               in worker["container_network_attachments"]]
              == [sorted(set(attachment) - {"id"}) for attachment
                  in _binding(substrate_projection, index)["container"][
                      "network_attachments"]]
              and sorted(worker["network_policy"])
              == sorted(set(_binding(substrate_projection, index)[
                  "network_policy"]) - {"id"})
              and ledger._same_json_value(
                  worker["egress_probe"],
                  _binding(substrate_projection, index)["egress_probe"])
              for index, worker in enumerate(substrate["pool"]["workers"])))
    present_roles = {entry["role"] for source in substrate_projection.sources
                     for entry in source.document["plan"]["invocation"][
                         "adapter"]["files"]}
    check("the harness-input set is the four-field identity over exactly the "
          "four closed roles",
          closed_top
          and all(len(row) == 4 for row in substrate["harness_inputs"])
          and {row[0] for row in substrate["harness_inputs"]}
          == present_roles & set(_SUBSTRATE_INPUT_ROLES)
          and len(substrate["harness_inputs"]) == sum(
              1 for source in substrate_projection.sources
              for entry in source.document["plan"]["invocation"]["adapter"][
                  "files"]
              if entry["role"] in _SUBSTRATE_INPUT_ROLES))

    for name, drift in sorted(_substrate_drifts().items()):
        check(f"common-substrate member {name} refuses when its evidence "
              f"changes alone",
              _refused(lambda pair=(substrate_role(drift), compare_roles[1]):
                       ledger._require_common_substrate(list(pair))))
    # The other half of the partition.  A projection that compared these
    # would refuse evidence section 5.1 admits, so each is checked to pass
    # through the same gate the members above fail.
    for name, drift in sorted(_role_local_drifts().items()):
        check(f"role-local {name} is admitted as a difference",
              not _refused(
                  lambda pair=(substrate_role(drift), compare_roles[1]):
                  ledger._require_common_substrate(list(pair))))

    v1_a, v1_b, v1_g = compare_roles
    # Every leg below is built on a REAL v2 agent receipt, produced by
    # `agents.result_ledger_v2_selftest` and read back through the production
    # verifier.  There is no such producer without the agent component, and a
    # fixture-written v2 shape would prove only that this file can write one.
    try:
        from ..agents import result_ledger_v2_selftest      # noqa: F401
    except ImportError:
        print("  [SKIP] the v2 agent-control and schema-vector legs: their "
              "receipts come from the agent producer, and this checkout has "
              "no agent component")
    else:
        # The agent-control projection is DERIVED by the code under test, from
        # each arm's own retained evidence, so every check below runs through the
        # production `_require_agent_control_pair` rather than comparing two
        # answers a fixture wrote out.
        verified_a = _verified_agent_receipt(
            root, label="va", condition="c3", budget=100, version=3)
        verified_b = _verified_agent_receipt(
            root, label="vb", condition="c2", budget=30, version=4)
        v2_a = _v2_agent_evidence(compare_roles[0], role="compare-A",
                                  verified=verified_a)
        v2_b = _v2_agent_evidence(compare_roles[1], role="compare-B",
                                  verified=verified_b)
        check("the v2 evidence is a real producer receipt, not a fixture shape",
              v2_a.schema == ledger.AGENT_RECEIPT_SCHEMA
              and v2_a.adapter_kind == "openhands"
              and verified_a.agent_evidence is not None
              and verified_b.agent_evidence is not None)
        check("an admitted v2 agent pair differing only in protocol version, "
              "condition, arm prompt key, model loop budget and backend runtime "
              "keeps one agent-control projection",
              not _refused(lambda: ledger._require_agent_control_pair(
                  [v2_a, v2_b, compare_roles[2]])))
        check("a v1 pair is not asked for an agent-control projection at all",
              not _refused(lambda: ledger._require_agent_control_pair(
                  list(compare_roles))))

        # One mutation per DERIVED field, applied to the input it comes from:
        # changing the projection object directly would prove only that
        # `_require_same_json` compares dictionaries.
        projection = ledger.publication_agent_control(**v2_b.agent_control_inputs)

        def drift(**mutation) -> ledger.PublicationRoleEvidence:
            drifted = copy.copy(v2_b)
            drifted.agent_control_inputs = copy.deepcopy(v2_b.agent_control_inputs)
            for path, value in mutation.items():
                cursor = drifted.agent_control_inputs
                *parents, leaf = path.split("__")
                for name in parents:
                    cursor = cursor[name]
                cursor[leaf] = value
            return drifted

        control_drift = {
            "protocol": drift(protocol__setting="another-setting"),
            "campaign_network_semantics": drift(
                campaign__network_semantics="another-network"),
            "agent_runtime_environment_controls": drift(
                agent_runtime__environment_controls={"LEAKED": "1"}),
            "agent_runtime_network_semantics": drift(
                agent_runtime__network_semantics="another-network"),
            "sitecustomize_sha256": drift(
                agent_runtime__agent_versions={
                    "sitecustomize_sha256": "2" * 64, "openhands": "c2-build"}),
            # FALSE, not true: a real admitted agent arm already stamps
            # `sandboxed: true`, so drifting it to true would mutate nothing and
            # the probe would pass while proving nothing.
            "effective_run_stamp": drift(stamp__sandboxed=False),
        }
        check("the derived projection is exactly section 5.1's closed field set",
              sorted(projection) == sorted(control_drift))
        for field, drifted in sorted(control_drift.items()):
            check(f"agent-control field {field} refuses when it changes between "
                  f"A and B",
                  _refused(lambda pair=(v2_a, drifted, compare_roles[2]):
                           ledger._require_agent_control_pair(list(pair))))
        for name in ("agent_timeout_seconds", "protocol_deviations", "sandboxed",
                     "setting"):
            drifted = drift(**{"stamp__" + name: "changed-" + name})
            check(f"agent-control stamp field {name} refuses when it changes "
                  f"between A and B",
                  _refused(lambda pair=(v2_a, drifted, compare_roles[2]):
                           ledger._require_agent_control_pair(list(pair))))
        refuses("an admitted agent arm with no verified protocol refuses",
                lambda: ledger._require_agent_control_pair(
                    [v2_a, drift(protocol=None), compare_roles[2]]))
        refuses("an agent runtime without the sitecustomize control refuses",
                lambda: ledger._require_agent_control_pair(
                    [v2_a, drift(agent_runtime__agent_versions={"openhands": "x"}),
                     compare_roles[2]]))
        refuses("an agent role whose protocol omits a closed member refuses",
                lambda: ledger.publication_agent_control(
                    {"prompt_profile": {"arm_prompt_key": "c3"}},
                    {"network_semantics": "x"},
                    {"agent_versions": {"sitecustomize_sha256": None},
                     "environment_controls": {}, "network_semantics": "x"},
                    {name: None for name in
                     ("agent_timeout_seconds", "protocol_deviations",
                      "sandboxed", "setting")}))

        check("report admits each role independently as v1 or homogeneous "
              "agent v2",
              not _refused(lambda: ledger._require_admitted_schema_vector(
                  "report", [_renamed(v1_a, "report-run:0"),
                             _renamed(v2_b, "report-run:1")])))
        check("results admits exactly [v2 agent candidate, v1 gold]",
              not _refused(lambda: ledger._require_admitted_schema_vector(
                  "results", [_renamed(v2_a, "results-candidate"),
                              _renamed(v1_g, "results-gold")])))
        check("compare admits exactly [v2 A, v2 B, v1 gold]",
              not _refused(lambda: ledger._require_admitted_schema_vector(
                  "compare", [v2_a, v2_b, v1_g])))
        refuses("a v2 gold role refuses",
                lambda: ledger._require_admitted_schema_vector(
                    "results", [_renamed(v1_a, "results-candidate"),
                                _renamed(v2_b, "results-gold")]))
        refuses("a mixed v1/v2 compare pair refuses",
                lambda: ledger._require_admitted_schema_vector(
                    "compare", [v1_a, v2_b, v1_g]))
        heterogeneous = copy.copy(v2_a)
        heterogeneous.source_schemas = (ledger.AGENT_RECEIPT_SCHEMA,
                                        ledger.RECEIPT_SCHEMA)
        refuses("a v2 merged role with heterogeneous sources refuses",
                lambda: ledger._require_admitted_schema_vector(
                    "report", [_renamed(heterogeneous, "report-run:0")]))
    unknown = copy.copy(v1_a)
    unknown.schema = "r2t.result-ledger/v3"
    refuses("an unknown receipt schema refuses",
            lambda: ledger._require_admitted_schema_vector(
                "report", [_renamed(unknown, "report-run:0")]))

    # ------------------------------------------------ 10. mutation probes
    probe_out = root + "/out/probe.txt"

    def publish_probe(out: str, *, receipt=None, reviewed=None) -> int:
        token = json.dumps({
            "receipt_path": receipt or a["receipt"],
            "reviewed_path": reviewed or a["reviewed"],
            "role": "report-run:0"}, sort_keys=True)
        return _capture_main([
            "report", "--publication-v3", "--publication-commit", commit,
            "--run", a["result"], "--publication-role", token,
            "--out", out])[0]

    baseline = publish_probe(probe_out) == 0
    check("the single-role baseline publishes",
          baseline and os.path.isfile(
              probe_out + ledger.PUBLICATION_STATUS_SUFFIX))

    stale_result = _read(a["result"])
    ledger.durable_replace_bytes(
        a["result"], stale_result + b"\n", label="probe result drift")
    check("PROBE skipped result-SHA/runtime join: drifted merged result bytes "
          "refuse",
          baseline and publish_probe(root + "/out/p-sha.txt") != 0)
    ledger.durable_replace_bytes(
        a["result"], stale_result, label="probe result restore")

    live_receipt = _read(a["receipt"])
    drifted = ledger.loads_exact_json(live_receipt, label="probe receipt")
    drifted["merge"]["expected_item_count"] += 1
    ledger.durable_replace_bytes(
        a["receipt"],
        (json.dumps(drifted, indent=1, sort_keys=True, ensure_ascii=True)
         + "\n").encode(), label="probe receipt drift")
    check("PROBE incomplete-claim publication: a broadened workset claim "
          "refuses",
          baseline and publish_probe(root + "/out/p-claim.txt") != 0)
    ledger.durable_replace_bytes(
        a["receipt"], live_receipt, label="probe receipt restore")

    check("PROBE auto-wrapping legacy evidence: a receipt whose live bytes "
          "differ from the reviewed blob refuses",
          baseline and publish_probe(
              root + "/out/p-legacy.txt", reviewed=b["reviewed"]) != 0)
    check("PROBE suffix inference: the result path is not resolved to a "
          "receipt",
          baseline and publish_probe(
              root + "/out/p-suffix.txt", receipt=a["result"]) != 0)
    check("PROBE accepting a checkpoint as complete: a run-shard source "
          "receipt is not a complete role",
          baseline and publish_probe(
              root + "/out/p-shard.txt", receipt=a["source_paths"][0]) != 0)

    orphan_status = root + "/out/probe-orphan.txt"
    _write(orphan_status + ledger.PUBLICATION_STATUS_SUFFIX,
           _read(probe_out + ledger.PUBLICATION_STATUS_SUFFIX), raw=True)
    check("PROBE early positive status: a status whose output is absent or "
          "rebound never verifies",
          baseline
          and _refused(lambda: ledger.verify_publication_status(
              orphan_status + ledger.PUBLICATION_STATUS_SUFFIX)))

    # --------------------------------------------- 11. durable crash seams
    def publish_seam(out: str, at: str | None):
        def roles_now():
            return preflight("report", [_role(a, "report-run:0")],
                             [a["result"]])

        def crash(event: str) -> None:
            if event == at:
                raise RuntimeError("injected fault at " + event)

        return ledger.publish_consumer_output(
            consumer="report", roles=roles_now(),
            parameters={"per_item": False}, commit=commit, out_path=out,
            render=lambda: "seam rendering\n", reclose=roles_now,
            fault=None if at is None else crash)

    pre_output = root + "/out/seam-pre.txt"
    check("a fault before the output creates nothing and the retry publishes",
          _refused(lambda: publish_seam(
              pre_output, "publication:before_output_create"))
          and not os.path.lexists(pre_output)
          and publish_seam(pre_output, None)["consumer"] == "report")

    post_output = root + "/out/seam-output.txt"
    check("a fault after the output commit burns the path forever",
          _refused(lambda: publish_seam(
              post_output, "publication output:commit"))
          and os.path.lexists(post_output)
          and not os.path.lexists(
              post_output + ledger.PUBLICATION_STATUS_SUFFIX)
          and _refused(lambda: publish_seam(post_output, None)))

    post_status = root + "/out/seam-status.txt"
    check("a fault after the status commit recovers as idempotent completion",
          _refused(lambda: publish_seam(
              post_status, "publication status:directory_fsync"))
          and publish_seam(post_status, None)["output"]["file_sha256"]
          == ledger.raw_sha256(_read(post_status)))

    # §7.2's status create commit point is step 4's RENAME_NOREPLACE, which
    # runs BEFORE the directory `fsync` and the pair readback.  Every fault
    # from that instant onward leaves a status no later call may deny, so the
    # next status-first resolution has to DURABLY CONFIRM the committed status
    # leaf AND its parent directory before it promises completion -- otherwise
    # the dentry may still live only in cache, a power loss then loses the
    # status, and the surviving output is classified as a burned partial tuple
    # forever.  The sweep injects each post-commit seam in turn and watches
    # the recovery call's own `fsync()`s by file identity, which is the only
    # observation that distinguishes a durable confirmation from a re-read.
    real_fsync = os.fsync

    def recover_watching_fsync(out: str) -> tuple[dict, list]:
        synced: list = []

        def counting_fsync(fd: int):
            info = os.fstat(fd)
            synced.append((info.st_dev, info.st_ino))
            return real_fsync(fd)

        os.fsync = counting_fsync
        try:
            recovered = publish_seam(out, None)
        finally:
            os.fsync = real_fsync
        return recovered, synced

    post_commit_seams = (
        ("commit", "publication status:commit"),
        ("dirsync", "publication status:directory_fsync"),
        ("readback", "publication:after_status_create"),
    )
    for slug, seam in post_commit_seams:
        seam_out = root + "/out/seam-post-" + slug + ".txt"
        seam_status = seam_out + ledger.PUBLICATION_STATUS_SUFFIX
        crashed = _refused(lambda: publish_seam(seam_out, seam))
        committed = os.path.lexists(seam_out) and os.path.lexists(seam_status)
        leaf = os.stat(seam_status)
        parent = os.stat(os.path.dirname(seam_status))
        recovered, synced = recover_watching_fsync(seam_out)
        check("recovery after a fault at " + seam + " durably confirms the "
              "committed status leaf and its parent directory before "
              "answering idempotent completion",
              crashed and committed
              and recovered["output"]["file_sha256"]
              == ledger.raw_sha256(_read(seam_out))
              and (leaf.st_dev, leaf.st_ino) in synced
              and (parent.st_dev, parent.st_ino) in synced)

    # §7.2 re-verifies AFTER that durable confirmation and answers with what
    # survived it.  The confirmation is therefore the seam: a status that
    # drifts across it must refuse, not be returned from the pre-confirmation
    # read as this request's own positive completion.
    recover_drift = root + "/out/seam-recover-drift.txt"
    publish_seam(recover_drift, None)
    recover_drift_status = recover_drift + ledger.PUBLICATION_STATUS_SUFFIX
    original_confirm = ledger._publication_fsync_existing_status
    confirm_calls: list = []

    def confirm_then_drift(path: str) -> None:
        confirm_calls.append(path)
        original_confirm(path)
        document = ledger.loads_exact_json(
            _read(path), label="recovery drift status")
        document["reviewed_commit"] = "b" * 40
        document["digest"] = ledger.semantic_digest(document)
        ledger.durable_replace_bytes(
            path, ledger.publication_status_bytes(document),
            label="recovery drift status")

    ledger._publication_fsync_existing_status = confirm_then_drift
    try:
        drift_refused = _refused(lambda: publish_seam(recover_drift, None))
    finally:
        ledger._publication_fsync_existing_status = original_confirm
    check("a status that drifts across the durable confirmation is caught by "
          "the re-verification, not answered as this request's completion",
          confirm_calls == [recover_drift_status] and drift_refused)

    from .runner import _PublicationResultLock
    with _PublicationResultLock(post_status):
        check("a second writer refuses while the exact result lock is owned",
              _refused(lambda: publish_seam(post_status, None)))

    # ------------------------------- 11a. PRE-LOCK / RE-LOCK DRIFT (§7.2)
    # The read-only pass before the lock can police only what it saw.  §7.2
    # therefore re-closes the entire closure and rechecks all three path
    # roles WHILE OWNING the lock, and re-closes again after the output
    # create.  Each row below drifts exactly one thing between the two
    # passes, so the UNDER-LOCK work -- not the pre-lock pass -- is what has
    # to refuse; delete any one of those statements and its row goes red.
    # No row may leave a status leaf: before step 4's commit point a caught
    # failure guarantees absence.
    def _drifted(role, **changes):
        clone = copy.copy(role)
        for name, value in changes.items():
            setattr(clone, name, value)
        return clone

    def roles_now():
        return preflight("report", [_role(a, "report-run:0")], [a["result"]])

    def drift_publish(out: str, reclose, *, render=None, fault=None):
        paths = (out, out + ledger.PUBLICATION_STATUS_SUFFIX,
                 out + ledger.PUBLICATION_LOCK_SUFFIX)
        base = roles_now()
        return ledger.publish_consumer_output(
            consumer="report", roles=base, parameters={"per_item": False},
            commit=commit, out_path=out,
            render=render or (lambda: "drift rendering\n"),
            reclose=lambda: reclose(base, paths), fault=fault)

    intact_result = _read(a["result"])

    def drift_result_while_rendering() -> str:
        # The concurrent writer the lock exists for: the receipted merged
        # result is replaced after the under-lock re-close and before the
        # output create, so only step 2's re-close can still see it.
        ledger.durable_replace_bytes(
            a["result"], intact_result + b"\n", label="re-lock drift result")
        return "drift rendering\n"

    # slug -> (what drifted, reclose over (pre-lock roles, derived paths),
    #          render, whether the refusal is allowed to burn the output)
    drift_cases = (
        ("roles", "the reclosed role evidence no longer equals the pre-lock "
                  "roles",
         lambda base, paths: [_drifted(
             base[0], result={**base[0].result, "file_sha256": "0" * 64})],
         None, False),
        ("paths", "the reclosed closure grows a required-absent path that "
                  "aliases the status leaf",
         lambda base, paths: [_drifted(
             base[0], absent_paths=base[0].absent_paths + (paths[1],))],
         None, False),
        ("render", "the receipted merged result drifts while the consumer "
                   "renders",
         lambda base, paths: roles_now(), drift_result_while_rendering, True),
    )
    for slug, what, reclose, render, burns in drift_cases:
        out = root + "/out/drift-" + slug + ".txt"
        try:
            refused = _refused(
                lambda: drift_publish(out, reclose, render=render))
        finally:
            if _read(a["result"]) != intact_result:
                ledger.durable_replace_bytes(
                    a["result"], intact_result,
                    label="re-lock drift result restore")
        check("under-lock re-close: " + what + " refuses with no status",
              refused
              and not os.path.lexists(out + ledger.PUBLICATION_STATUS_SUFFIX)
              and os.path.lexists(out) == burns)

    # §7.2 step 1 exact-reads the durable output back before anything else
    # is written, so bytes substituted between the no-clobber create and the
    # status construction refuse WITHOUT a status leaf.  The fault seam is
    # the only way to be that writer.
    readback_out = root + "/out/drift-readback.txt"

    def substitute_after_create(event: str) -> None:
        if event == "publication:after_output_create":
            ledger.durable_replace_bytes(
                readback_out, b"substituted after the durable create\n",
                label="re-lock readback probe output")

    check("§7.2 step 1: the durable output's exact readback refuses bytes "
          "substituted after its no-clobber create, and commits no status",
          _refused(lambda: drift_publish(
              readback_out, lambda base, paths: base,
              fault=substitute_after_create))
          and os.path.lexists(readback_out)
          and not os.path.lexists(
              readback_out + ledger.PUBLICATION_STATUS_SUFFIX))

    # ------------------- 11b. the offline status verifier's own refusals
    # §7.1 makes digest recomputation and the exact serialization VERIFIER
    # duties, not builder properties.  Each negative is a scratch COPY of
    # the published pair under a new name, so the derived-path check passes
    # and the refusal under test is the one that fires; the control proves
    # the relocation itself verifies.
    def _redigested(document: dict, **changes) -> dict:
        rebound = {**document, **changes}
        rebound["digest"] = ledger.semantic_digest(rebound)
        return rebound

    verified_root = root + "/out/verified"
    published_output = _read(out_path)

    def verifier_pair(slug: str, mutate) -> str:
        copied_out = verified_root + "/" + slug + ".txt"
        _write(copied_out, published_output, raw=True)
        rebound = _redigested(
            copy.deepcopy(status),
            output={**status["output"], "path": copied_out})
        copied_status = copied_out + ledger.PUBLICATION_STATUS_SUFFIX
        _write(copied_status, mutate(rebound), raw=True)
        return copied_status

    control = verifier_pair("control", ledger.publication_status_bytes)
    check("the relocated status/output control pair verifies",
          ledger.verify_publication_status(control)["output"]["path"]
          == verified_root + "/control.txt")

    verifier_cases = (
        ("digest", "a status whose semantic digest does not recompute",
         lambda s: ledger.publication_status_bytes({**s, "digest": "a" * 64})),
        ("spelling", "a status re-serialized in any other exact JSON "
                     "spelling",
         lambda s: (json.dumps(s, indent=2, sort_keys=True, ensure_ascii=True,
                               allow_nan=False) + "\n").encode("utf-8")),
        ("rebound", "a re-digested status that rebinds the output bytes",
         lambda s: ledger.publication_status_bytes(_redigested(
             s, output={**s["output"], "file_sha256": "0" * 64}))),
    )
    for slug, what, mutate in verifier_cases:
        path = verifier_pair(slug, mutate)
        check("the offline verifier refuses " + what,
              _refused(lambda: ledger.verify_publication_status(path)))

    # ------------- 11c. THE UNDER-LOCK STATUS-FIRST RE-RESOLUTION (§7.2)
    # The pre-lock pass is read-only and can police only what it saw, so §7.2
    # "resolves the tuple status-first again" while owning the lock.  Only a
    # writer that loses that race can reach the second resolution, so the
    # schedule is forced the way the I2 selftest already forces its receipt
    # analogue (result_ledger_i2_selftest.py:1136-1153): the pre-lock pass is
    # made blind, and the main lock branch meets the tuple a preceding owner
    # committed in between.  Without the second resolution this request --
    # which IS complete -- meets the no-clobber create instead and refuses
    # with "publication output already exists".
    raced_out = root + "/out/race-underlock.txt"
    raced_status = raced_out + ledger.PUBLICATION_STATUS_SUFFIX
    first_writer = publish_seam(raced_out, None)
    raced_bytes = (_read(raced_out), _read(raced_status))
    original_resolve = ledger._publication_resolve
    resolve_calls: list = []

    def blind_pre_lock_pass(*args, **kwargs):
        resolve_calls.append(args[0])
        if len(resolve_calls) == 1:
            return None
        return original_resolve(*args, **kwargs)

    ledger._publication_resolve = blind_pre_lock_pass
    second_writer = None
    try:
        second_writer = publish_seam(raced_out, None)
    except (SystemExit, ledger.ResultLedgerRefused, ValueError, RuntimeError):
        second_writer = None
    finally:
        ledger._publication_resolve = original_resolve
    check("§7.2: the main lock branch resolves the tuple status-first AGAIN, "
          "so a pair committed after the pre-lock pass completes idempotently "
          "instead of refusing as a no-clobber collision",
          len(resolve_calls) == 2
          and second_writer is not None
          and ledger._same_json_value(second_writer, first_writer)
          and (_read(raced_out), _read(raced_status)) == raced_bytes)

    # ------- 11d. STRUCTURAL SELF-VERIFICATION IN MEMORY, BEFORE EVIDENCE
    # §7.2 completes status construction AND its structural self-verification
    # in memory BEFORE creating evidence, because §7.2 also rules that a
    # committed but invalid pair refuses: a builder regression caught only by
    # the trailing verifier has already created the output and committed an
    # invalid status, and that path can never be republished.  The stand-in
    # regression adds one non-closed member to the closed `parameters` object
    # and re-digests, so the closed-field violation is its only defect.
    selfverify_out = root + "/out/selfverify-inmemory.txt"
    original_build = ledger.build_publication_status

    def regressed_build(*args, **kwargs):
        status_document = original_build(*args, **kwargs)
        status_document["parameters"] = {
            **status_document["parameters"], "group_by": "project"}
        status_document["digest"] = ledger.semantic_digest(status_document)
        return status_document

    ledger.build_publication_status = regressed_build
    try:
        regression_refused = _refused(
            lambda: publish_seam(selfverify_out, None))
    finally:
        ledger.build_publication_status = original_build
    check("§7.2: a structurally invalid status is refused in memory, so a "
          "builder regression creates NO output leaf and commits NO status",
          regression_refused
          and not os.path.lexists(selfverify_out)
          and not os.path.lexists(
              selfverify_out + ledger.PUBLICATION_STATUS_SUFFIX))

    # ------------------------- 12. the renderer's own refusals stay refusals
    # The consumer renders INSIDE the durable seam, so a refusal it raises has
    # to leave as the same named `REFUSED:` exit the default route produces.
    # A traceback would be a second failure mode for the same input, and one
    # that says nothing about what was wrong.
    from . import draws as D
    from . import report as RP
    from . import results as R

    from .runner import _PublicationResultLock

    def renderer_refusal(argv: list, out: str, module, name: str,
                         exception) -> bool:
        real = getattr(module, name)

        def refuse(*_args, **_kwargs):
            raise exception

        setattr(module, name, refuse)
        try:
            code, stdout, stderr = _capture_main(argv)
        except BaseException as escaped:            # noqa: BLE001 - reported
            print(f"    ({name} escaped as {type(escaped).__name__})")
            return False
        finally:
            setattr(module, name, real)
        # The lock leaf is operational and is deliberately never removed; what
        # must be true is that it was RELEASED, so the next writer can own it.
        try:
            with _PublicationResultLock(out, create=False):
                released = True
        except (OSError, ledger.ResultLedgerRefused):
            released = False
        return (code != 0 and stdout == b"" and released
                and b"REFUSED: probe renderer" in stderr
                and not os.path.lexists(out)
                and not os.path.lexists(out + ledger.PUBLICATION_STATUS_SUFFIX))

    routed = {
        "report/ReportRefusal": renderer_refusal(
            report_argv(out=root + "/out/rr-report.txt"),
            root + "/out/rr-report.txt", RP, "publication_report",
            RP.ReportRefusal("REFUSED: probe renderer single-project gate")),
        "report/DrawRefusal": renderer_refusal(
            report_argv(out=root + "/out/rr-draw.txt"),
            root + "/out/rr-draw.txt", RP, "publication_report",
            D.DrawRefusal("REFUSED: probe renderer repeat-draw stamp")),
        "results/DrawRefusal": renderer_refusal(
            results_argv(out=root + "/out/rr-results.txt"),
            root + "/out/rr-results.txt", R, "publication_results",
            D.DrawRefusal("REFUSED: probe renderer repeat-draw stamp")),
        "results/ResultsInputError": renderer_refusal(
            results_argv(out=root + "/out/rr-input.txt"),
            root + "/out/rr-input.txt", R, "publication_results",
            R.ResultsInputError("probe renderer input")),
    }
    check("a renderer refusal inside the durable seam exits REFUSED and "
          "leaves no output, status or lock",
          all(routed.values()),
          str(sorted(name for name, ok in routed.items() if not ok)))

    # --------------------------------------- 13. ordinary default behaviour
    # Publication fixtures are campaign-stamped and must now arrive through
    # their validated role workset.  Keep the ordinary CLI contract controls
    # ordinary: explicit release bytes bind a small unstamped development run
    # without entering the publication-v3 route.
    ordinary_run = root + "/ordinary/default.jsonl"
    ordinary_rows = [{"item_id": row["item_id"], "outcome": "passed"}
                     for row in fixture["shared"]["release_rows"]]
    _write(ordinary_run, _rows_bytes(ordinary_rows), raw=True)
    population_args = ["--release", fixture["shared"]["release_path"]]
    default_report = _capture_main(
        ["report", "--run", ordinary_run, *population_args])
    check("the ordinary report route renders with an explicit planned "
          "population and takes no publication option",
          default_report[0] == 0 and default_report[1] != b""
          and _capture_main(
              ["report", "--run", ordinary_run, *population_args,
               "--publication-commit", commit])[0] != 0)
    stamped_default = _capture_main(["report", "--run", a["result"]])
    check("ordinary reporting consumes an adjacent complete receipt's "
          "validated selected/shard workset",
          stamped_default[0] == 0 and stamped_default[1] != b""
          and stamped_default[2] == b"")
    check("no other command accepts the publication consumer options",
          _capture_main(["merge", "--publication-v3", "--publication-role",
                         report_tokens[0], "--of", "2", "--out",
                         root + "/out/nope.jsonl"])[0] != 0)
    # The default parsers keep argparse's prefix matching.  Turning it off is
    # a property of the publication FORM, not of the verb.
    check("the default parsers still resolve an unambiguous option prefix",
          _capture_main(
              ["report", "--ru", ordinary_run, *population_args])[0] == 0)

    # The default route's own file behaviour and stdout, unchanged: the
    # rendering goes to the FILE or to stdout, never both.
    default_results_out = root + "/out/default-results.json"
    default_results = _capture_main([
        "--boundary", os.path.join(
            R.BENCHMARK, "config", "boundary_python_docx.yml"),
        "--artifacts", root + "/art0",
        "results", "--run", ordinary_run, "--gold", g["result"],
        *population_args,
        "--format", "json", "--out", default_results_out])
    check("the default results route still writes its file and names it on "
          "stdout",
          default_results[0] == 0
          and default_results[1] == f"wrote {default_results_out}\n".encode()
          and os.path.isfile(default_results_out)
          and not os.path.lexists(
              default_results_out + ledger.PUBLICATION_STATUS_SUFFIX))

    # BYTE PINS.  Machine-specific defaults (the release gold directory and
    # the artifacts root) are substituted out and the layout is flattened, so
    # the pin travels between checkouts while still covering every word and
    # every option spelling the three parsers print.
    # A DataPath default is machine-independent (never rendered as a host
    # path), so only string defaults still need substituting out.
    # Re-minted when `report` and `results` gained the `--reference-*` group
    # that names the installed reference collection a single-observation
    # (v2) sidecar is scored under.  `compare` names none and its three pins
    # are unchanged, which is the point of pinning the three separately.
    # `results` also describes language-specific index discovery and the
    # validated installed scoring_gold default. Its option spellings and
    # the `compare` help remain unchanged. Evaluation reference inputs add
    # the approved scope, portable locations, derivation sources and separate
    # execution release to report/results; their older options are unchanged.
    # Re-minted for the four `results` inputs of TARGET_INTERFACES_V2_SPEC
    # 6.2/6.3 (`--target-regions`, `--items`, `--control-floors`,
    # `--clusters`), each of which only ADDS a secondary row when it is
    # given. `report` and `compare` name none of them and their pins are
    # unchanged, which is the point of pinning the three separately.
    # Re-minted for `results --infrastructure-exclusions`
    # (REPORTING_POPULATION_COMPLETENESS_SPEC section 9): the `results` help
    # and its two usage diagnostics; `report` and `compare` are unchanged.
    # Re-minted when `report` and `results` gained the labelled reference
    # basis options (`--sensitivity`, `--allow-excluded-pairs`,
    # `--gold-disagreements`; SYLIUS_STUB_GATE_WAIVED_SENSITIVITY_SPEC.md)
    # and `report` gained `--non-vacuous-out`. `compare` names none of them.
    volatile = tuple(value for value in (bench_cli.DEFAULT_GOLD_DIR,
                                         R.DEFAULT_ARTIFACTS)
                     if isinstance(value, str))

    def parser_bytes(raw: bytes) -> str:
        import hashlib
        flat = b"".join(raw.split())
        for index, value in enumerate(volatile):
            flat = flat.replace(b"".join(value.encode().split()),
                                b"<VOLATILE%d>" % index)
        return hashlib.sha256(flat).hexdigest()

    parser_pins = {
        ("report", "--help"):
            "dd40b4460c6f504cc18aa79e4fff21b0903e37762983e55a13ee0cedad644d03",
        ("results", "--help"):
            "6e54538a14bce004bce277f61baa7854e1f726f87350559c558c26faaa22aaa4",
        ("compare", "--help"):
            "3211234f05a0bfcfb9b438b1afa3a83e6f21c70535572a1bf1325a5b2dee1372",
    }
    help_exact = []
    for (command, option), expected in sorted(parser_pins.items()):
        code, stdout, stderr = _capture_main([command, option])
        help_exact.append(code == 0 and stderr == b""
                          and parser_bytes(stdout) == expected)
    check("default report/results/compare help bytes pin the approved "
          "population-binding CLI surface",
          all(help_exact) and len(help_exact) == 3)

    diagnostic_pins = (
        (["report"], 2,
         "cc56f6a24dec090b5446e69a15b825cbb0e46cc067f8482cb43576705bee8912"),
        (["results"], 2,
         "48ef91278d60e56ae21846760360477cceaf4d505613e249ebd44e0dbcd907f0"),
        (["compare"], 2,
         "004982ab2181b8771ea427455b9b8794145c586d8a709d81f7baa70ff975c0dc"),
        (["report", "--run"], 2,
         "cdbc52c1226cd1624a7fa25c207ed3c91c751d3238c42294b58bfed280acd045"),
        (["results", "--run", "/x", "--format"], 2,
         "5503b03277f5d0de2dd47246c061876a7fe14fbfdd540434ded8ec0aac175b7e"),
        (["compare", "--run", "/a", "--run", "/b", "--gold-dir"], 2,
         "cce49d7e013ba1ac164af1a9406222ff7d8eae88763e98a07874d01f05dee057"),
        # The unknown-option usage line lists the commands the composer
        # registered, in registration order (bench's first): one value with
        # the agent component's verbs on the menu, another in the
        # benchmark-only mirror, which ships no `agents/cli.py`.
        # Re-pinned for `target-regions` and `control-floors`, the two
        # toolkit verbs registered after `stub-accept`.
        (["report", "--run", "/x", "--nope"], 2,
         "d9118845a76f770bf9a5ae5c3ae94b6149eba8afb9990b32ab0cc65975dcf194"
         if cli.agents is not None else
         "4c8f59c33c27e385ef9f45256e284cc576b815f4e5b70222c18e7e942b3d4bec"),
    )
    diagnostics_exact = []
    for argv, expected_code, expected in diagnostic_pins:
        code, stdout, stderr = _capture_main(argv)
        diagnostics_exact.append(code == expected_code and stdout == b""
                                 and parser_bytes(stderr) == expected)
    check("default missing/valueless diagnostics pin the approved "
          "population-binding surface and unknown-option diagnostics pin "
          "the current command set",
          all(diagnostics_exact)
          and len(diagnostics_exact) == len(diagnostic_pins))

    # THE PYTHON SURFACE.  Splitting `results.results` and `cli.cmd_compare`
    # into public wrapper plus private body must not change what an importer
    # sees.  The SIGNATURES are pinned; the docstrings are not -- a digest
    # over prose pins the sentence an author is allowed to improve, and
    # never once caught a contract change the parameter list did not.
    import inspect
    results_signature = inspect.signature(R.results)
    # `language` joined the list beside `api_scoring`: both come off the
    # profile, and it is what decides which of `index-prod`'s two output
    # names the default index lookup asks for (issue #282).  Keyword-only
    # with a default, so no existing caller's call site changed.
    check("the public Python entry points retain their contract plus the "
          "approved trailing population-binding and installed-reference "
          "inputs",
          list(results_signature.parameters)
          == ["run_path", "gold_path", "test_quality_path", "prod_index_path",
              "boundary", "artifacts", "api_scoring", "language",
              "release_path", "reference_controls_reader",
              # TARGET_INTERFACES_V2_SPEC 6.2/6.3: the secondary block's own
              # inputs, keyword-only with a default, appended after the
              # existing ten. No existing call site changed, and without
              # them the table is the one it already was.
              "target_regions_path", "items_path", "control_floors_path",
              "cluster_source",
              # REPORTING_POPULATION_COMPLETENESS_SPEC section 9: the
              # owner-ratified exclusions file, keyword-only with a default.
              "infrastructure_exclusions_path"]
          and [str(p.kind) for p in results_signature.parameters.values()]
          == ["POSITIONAL_OR_KEYWORD"] + ["KEYWORD_ONLY"] * 14
          and list(inspect.signature(bench_cli.cmd_compare).parameters)
          == ["args"])


if __name__ == "__main__":
    raise SystemExit(selftest())
