"""Reviewed DOCX population and exact-byte evidence workload bindings.

Population work retains its original two phases.  Evidence work adds only the
finite phases approved by ``DOCX_REFERENCE_CONTROL_EXACT_BYTES_AMENDMENT.md``;
their commands, reference roles, and candidate identities are derived here,
never supplied as an arbitrary argv or role.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import tempfile
from types import SimpleNamespace

from .. import docker_authority as A

# ``python -m`` executes this file as ``__main__``.  Producers import the
# package name lazily, so keep both names on the same one-shot capability
# state instead of loading a second, ambient module instance.
if __name__ == "__main__":
    sys.modules[f"{__package__}.docx_v2_workload"] = sys.modules[__name__]


SCHEMA = "r2t.docx-v2-population-workload/1"
EVIDENCE_SCHEMA = "r2t.docx-v2-evidence-workload/1"
CLAIM_SCHEMA = "r2t.docx-v2-workload-claim/1"
CLAIM_NAME = ".r2t-docx-workload-claimed.json"
OUTPUT_DIRECTORY = "outputs"
_TOP = {"schema", "source", "static_preflight", "docker_authority",
        "worker_runtime", "phase", "output_root", "digest"}
_EVIDENCE_TOP = {
    "schema", "source", "static_preflight", "docker_authority",
    "worker_runtime", "phase", "observation_id", "inputs",
    "output_root", "digest",
}
_SOURCE = {"repository", "commit", "tag"}
_FILE = {"path", "sha256"}
_WORKER = {"path", "sha256", "runtime_sha256"}
_INPUTS = {
    "mutation_validation", "manifest", "map", "release", "candidate",
    "gold_baseline", "gold_results", "gold_results_attestation",
    "hard_subset", "pair_plan", "run1_state",
}
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PHASES = {
    "population-v1-replay": ("v1", "mutants_v1.json",
                              "mutants_v1.raw.json"),
    "population-v2-build": ("v2", "mutants_v2.json",
                             "mutants_v2.raw.json"),
}
_REFERENCE_PHASES = {
    "stripped-fidelity": "assertion-stripped-gold",
    "full-gold-a": "full-gold",
    "full-gold-b": "full-gold",
    "stripped-gold-c": "assertion-stripped-gold",
    "stripped-gold-d": "assertion-stripped-gold",
    "stub-control-a": "stub-control",
    "stub-control-b": "stub-control",
}
_CANDIDATE_PHASES = {
    "candidate-openhands-c3-run1":
        "a5_cell3_python_docx_openhands_corrected",
    "candidate-aider-c4-run1": "a5_cell4_python_docx_aider",
    "candidate-openhands-c3-d4":
        "a5_cell3_python_docx_openhands_corrected",
    "candidate-aider-c4-d4": "a5_cell4_python_docx_aider",
}
_EVIDENCE_PHASES = frozenset((*_REFERENCE_PHASES, *_CANDIDATE_PHASES))
_OBSERVATION = re.compile(r"[0-9a-f]{32}\Z")
_SHARED_RUNTIME_FIELDS = (
    "seed_dir", "seed_manifest_sha256", "seed_key",
    "workspace_seed_digest", "database_dump_digest",
    "container_image_digest", "harness_version", "needs_database",
    "docker_execution_authority",
)


class WorkloadRefused(ValueError):
    """The DOCX population workload is stale, ambiguous, or unreviewed."""


def _refuse(message: str):
    raise WorkloadRefused("REFUSED: " + message)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        got = sorted(value) if isinstance(value, dict) else type(value).__name__
        _refuse(f"{label} fields differ; expected={sorted(fields)}, got={got}")
    return value


def _sha(value, label):
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        _refuse(f"{label} is not one lower-case SHA-256")
    return value


def semantic_digest(document: dict) -> str:
    try:
        return A.semantic_digest(document, domain=SCHEMA)
    except A.DockerAuthorityRefused as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))


def evidence_semantic_digest(document: dict) -> str:
    try:
        return A.semantic_digest(document, domain=EVIDENCE_SCHEMA)
    except A.DockerAuthorityRefused as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))


def _json(path: str, label: str):
    try:
        A.assert_trusted_file(path, label=label)
        with open(path, "rb") as handle:
            return A.loads_exact_json(handle.read(), label=label)
    except (A.DockerAuthorityRefused, OSError) as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))


def _record(value, label):
    record = _exact(value, _FILE, label)
    try:
        path = A.canonical_absolute_path(record["path"], label + ".path")
        A.assert_trusted_file(path, label=label)
        actual = A.sha256_file(path)
    except A.DockerAuthorityRefused as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))
    expected = _sha(record["sha256"], label + ".sha256")
    if actual != expected:
        _refuse(f"{label} SHA-256 is {actual}, expected {expected}")
    return {"path": path, "sha256": expected}


def _git(repository, args, label, *, allowed=(0,)):
    from ..core import reviewed_git as G
    try:
        result = G.run(repository, tuple(args))
    except G.ReviewedGitRefused as exc:
        _refuse(f"{label}: {exc.detail}")
    if result.returncode not in allowed:
        detail = os.fsdecode(result.stderr or result.stdout).strip()
        _refuse(f"{label}: {detail or 'Git read failed'}")
    return result


def _source(value):
    from ..core import reviewed_git as G
    source = _exact(value, _SOURCE, "source")
    try:
        repository = A.canonical_absolute_path(
            source["repository"], "source.repository")
    except A.DockerAuthorityRefused as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))
    if os.path.realpath(repository) != repository \
            or repository != G.repository_root():
        _refuse("source.repository is not this module's physical worktree")
    commit, tag = source["commit"], source["tag"]
    if not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None:
        _refuse("source.commit is not one full lower-case Git commit")
    if not isinstance(tag, str) or _TAG.fullmatch(tag) is None \
            or ".." in tag or "@{" in tag \
            or any(part in {"", ".", ".."} or part.endswith(".lock")
                   for part in tag.split("/")):
        _refuse("source.tag is not one literal local tag")
    if _git(repository, ("rev-parse", "HEAD"), "source HEAD").stdout \
            != (commit + "\n").encode():
        _refuse("source worktree is not at source.commit")
    detached = _git(repository, ("symbolic-ref", "--quiet", "HEAD"),
                    "detached source HEAD", allowed=(0, 1))
    if detached.returncode != 1:
        _refuse("source worktree is not detached")
    if _git(repository, ("status", "--porcelain=v1",
                         "--untracked-files=all"), "source status").stdout:
        _refuse("source worktree is not clean")
    resolved = _git(repository, ("rev-parse", "--verify",
                    f"refs/tags/{tag}^{{commit}}"), "source tag").stdout
    if resolved != (commit + "\n").encode():
        _refuse("source.tag does not resolve exactly to source.commit")
    return {"repository": repository, "commit": commit, "tag": tag}


def _preflight(value, source):
    record = _record(value, "static_preflight")
    saved = _json(record["path"], "static preflight")
    candidates = saved.get("candidates") if isinstance(saved, dict) else None
    by_label = {
        item.get("label"): item.get("path")
        for item in (candidates if isinstance(candidates, list) else [])
        if isinstance(item, dict)
    }
    labels = (
        "a5_cell3_python_docx_openhands_corrected",
        "a5_cell4_python_docx_aider",
    )
    if set(by_label) != set(labels) \
            or any(not isinstance(by_label[label], str) for label in labels):
        _refuse("static preflight does not name the two frozen candidate arms")
    from scripts import preflight_docx_c5 as C5
    try:
        rebuilt = C5.check_saved(
            Path(record["path"]), source["commit"],
            Path(by_label[labels[0]]), Path(by_label[labels[1]]))
    except (C5.PreflightRefused, OSError, ValueError) as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))
    if rebuilt != saved:
        _refuse("static preflight differs from its fresh rebuild")
    return rebuilt


def _runtime(authority_value, worker_values):
    from ..bench import worker as W
    authority = _record(authority_value, "docker_authority")
    if not isinstance(worker_values, list) or not worker_values:
        _refuse("worker_runtime is not a non-empty ordered list")
    records = []
    for index, value in enumerate(worker_values):
        item = _exact(value, _WORKER, f"worker_runtime[{index}]")
        record = _record(
            {"path": item["path"], "sha256": item["sha256"]},
            f"worker_runtime[{index}].worker")
        record["runtime_sha256"] = _sha(
            item["runtime_sha256"],
            f"worker_runtime[{index}].runtime_sha256")
        records.append(record)
    try:
        loaded = W.validate_offline_worker_runtime_pool(
            [item["path"] for item in records])
    except (W.WorkerRefused, OSError, ValueError) as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))
    expected = [{
        "path": item["spec_path"],
        "sha256": item["runtime"]["worker_spec_sha256"],
        "runtime_sha256": item["runtime_sha256"],
    } for item in loaded]
    if records != expected:
        _refuse("worker_runtime differs from its bound v3 evidence")
    authority_ref = loaded[0]["runtime"]["docker_execution_authority"]
    if (authority["path"], authority["sha256"]) != (
            authority_ref.get("path"), authority_ref.get("file_sha256")):
        _refuse("docker_authority differs from the complete worker pool")
    if any(item["runtime"]["needs_database"] is not False for item in loaded):
        _refuse("DOCX worker pool is not no-database")
    images = {item["runtime"]["container_image_digest"] for item in loaded}
    if len(images) != 1 or _IMAGE.fullmatch(next(iter(images))) is None:
        _refuse("worker pool has mixed or mutable container images")
    seed_dirs = {item["runtime"]["seed_dir"] for item in loaded}
    if len(seed_dirs) != 1:
        _refuse("worker pool has mixed workspace seeds")
    protected_paths = [authority["path"]]
    for item in loaded:
        protected_paths.extend((
            item["spec_path"], item["runtime_path"],
            item["runtime"]["seed_dir"],
            item["runtime"]["docker_execution_binding"]["path"],
        ))
    return {
        "authority": authority,
        "image": next(iter(images)),
        "workers": tuple(item["spec_path"] for item in loaded),
        "seed_dir": next(iter(seed_dirs)),
        "shared_runtime": {
            key: loaded[0]["runtime"][key]
            for key in _SHARED_RUNTIME_FIELDS
        },
        "protected_paths": tuple(dict.fromkeys(protected_paths)),
    }


def _d4_run1_runtime(campaign_plan, current_runtime):
    """Authenticate run 1's original pool and its shared runtime identity."""
    from ..bench import worker as W
    resources = (campaign_plan.get("worker_resources")
                 if isinstance(campaign_plan, dict) else None)
    if not isinstance(resources, list) or not resources:
        _refuse("D4 run1 state has no original worker resources")
    paths = [record.get("worker_spec")
             for record in resources if isinstance(record, dict)]
    if len(paths) != len(resources) or any(not isinstance(path, str)
                                           for path in paths):
        _refuse("D4 run1 worker resources have no exact spec paths")
    try:
        loaded = W.validate_offline_worker_runtime_pool(paths)
    except (W.WorkerRefused, OSError, ValueError) as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))
    expected = [{
        "index": item["worker"].index,
        "worker_spec": item["spec_path"],
        "workspace": os.path.realpath(item["worker"].workspace),
        "container": item["worker"].container,
        "schema": item["worker"].schema,
        "credential": item["worker"].credential,
        "env_file": os.path.realpath(item["worker"].env_file),
        "workdir": item["worker"].workdir,
        "runtime_attestation": item["runtime_path"],
        "runtime_attestation_sha256": item["runtime_sha256"],
    } for item in loaded]
    if resources != expected:
        _refuse("D4 run1 worker resources differ from their offline evidence")
    shared = {key: loaded[0]["runtime"][key]
              for key in _SHARED_RUNTIME_FIELDS}
    changed = sorted(key for key in _SHARED_RUNTIME_FIELDS
                     if shared[key] != current_runtime["shared_runtime"][key])
    if changed:
        _refuse("D4 run1 and run2 pools differ in shared runtime fact(s) "
                f"{changed}")
    protected = []
    for item in loaded:
        protected.extend((
            item["spec_path"], item["runtime_path"],
            item["runtime"]["seed_dir"],
            item["runtime"]["docker_execution_binding"]["path"],
            item["runtime"]["docker_execution_authority"]["path"],
        ))
    return tuple(paths), tuple(dict.fromkeys(protected))


def _output_root(value, *, require_empty=True):
    try:
        path = A.canonical_absolute_path(value, "output_root")
    except A.DockerAuthorityRefused as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))
    if path == "/" or os.path.realpath(path) != path or os.path.islink(path) \
            or not os.path.isdir(path):
        _refuse("output_root is not an existing canonical directory")
    try:
        info = os.stat(path, follow_symlinks=False)
        entries = os.listdir(path)
    except OSError as exc:
        _refuse(f"cannot inspect output_root: {exc}")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        _refuse("output_root must be current-user-owned and mode 0700")
    if require_empty and entries:
        _refuse("output_root must be empty before workload execution")
    return path


def _producer_root(output_root):
    return os.path.join(output_root, OUTPUT_DIRECTORY)


def _claim_document(facts):
    return {
        "schema": CLAIM_SCHEMA,
        "workload_schema": facts.get("schema", SCHEMA),
        "workload_digest": facts["digest"],
        "phase": facts["phase"],
    }


def _claim_output_root(facts):
    """Durably consume one fresh workload root before its first producer."""
    root = facts["output_root"]
    marker = os.path.join(root, CLAIM_NAME)
    payload = (json.dumps(_claim_document(facts), sort_keys=True,
                          separators=(",", ":")) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(marker, flags, 0o600)
    except OSError as exc:
        _refuse(f"output_root is already claimed: {exc}")
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written < 1:
                raise OSError("short claim write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    parent_fd = os.open(root, parent_flags)
    try:
        os.fsync(parent_fd)
        if set(os.listdir(root)) != {CLAIM_NAME}:
            _refuse("output_root changed while its one-shot claim was made")
        try:
            os.mkdir(_producer_root(root), mode=0o700)
        except OSError as exc:
            _refuse(f"cannot create deterministic producer directory: {exc}")
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return _producer_root(root)


def _validate_claim(facts):
    marker = os.path.join(facts["output_root"], CLAIM_NAME)
    if _json(marker, "workload claim") != _claim_document(facts):
        _refuse("completed workload claim differs from its workload")


def _argv(phase, source, preflight, runtime, output_root):
    if phase not in _PHASES:
        _refuse(f"phase is not one of {sorted(_PHASES)}")
    profile, scored_name, raw_name = _PHASES[phase]
    root = source["repository"]
    output_root = _producer_root(output_root)
    argv = [
        "--repo", preflight["corpus"]["root"],
        "--boundary", os.path.join(
            root, "benchmark/config/boundary_python_docx.yml"),
        "--docker-authority", runtime["authority"]["path"],
        "mutants", "build",
        "--profile", os.path.join(
            root, "benchmark/config/profile_python_docx.yml"),
        "--operator-profile", profile,
        "--out", os.path.join(output_root, scored_name),
        "--raw-out", os.path.join(output_root, raw_name),
    ]
    if profile == "v2":
        argv.append("--record-enumerator-rev")
    return tuple(argv)


def _evidence_inputs(value, phase):
    values = _exact(value, _INPUTS, "inputs")
    if phase == "stripped-fidelity":
        required = {"release", "candidate"}
    elif phase in _REFERENCE_PHASES:
        required = {"mutation_validation", "manifest", "map", "release",
                    "candidate"}
    else:
        required = {"mutation_validation", "manifest", "map", "release",
                    "candidate", "gold_baseline", "gold_results",
                    "gold_results_attestation", "hard_subset"}
        if phase.endswith("-d4"):
            required |= {"pair_plan", "run1_state"}
    present = {key for key, item in values.items() if item is not None}
    if present != required:
        _refuse(f"{phase} input set differs; expected={sorted(required)}, "
                f"got={sorted(present)}")
    return {key: (_record(item, f"inputs.{key}") if item is not None else None)
            for key, item in values.items()}


def _evidence_generation(phase, inputs, preflight):
    if phase in _REFERENCE_PHASES:
        from ..bench.campaign import legacy_generation_evidence
        from ..bench import mutation_run as MR
        from ..bench import test_quality as TQ
        legacy = legacy_generation_evidence(
            run_sha256=inputs["candidate"]["sha256"])
        if legacy is not None:
            _refuse(
                f"{legacy['label']} is registered only as legacy_exact_bytes; "
                "a reference workload cannot relabel those exact bytes")
        try:
            generated = MR.candidate_digest(TQ.passed_solutions(
                TQ.load_jsonl(inputs["candidate"]["path"])))
        except (TQ.TestQualityRefused, MR.MutationAborted,
                OSError, ValueError) as exc:
            _refuse(str(exc).removeprefix("REFUSED: "))
        return {"class": "reference_control_exact_bytes",
                "role": _REFERENCE_PHASES[phase],
                "generated_tests_sha256": generated}
    expected_label = _CANDIDATE_PHASES[phase]
    candidates = {item["label"]: item for item in preflight["candidates"]}
    candidate = candidates.get(expected_label)
    if candidate is None \
            or inputs["candidate"]["sha256"] != candidate["run_sha256"]:
        _refuse(f"{phase} candidate bytes differ from static preflight")
    return {"class": "legacy_exact_bytes", "role": None,
            "generated_tests_sha256": candidate["generated_tests_sha256"]}


def _require_fresh_d4_observation(observation_id, binding):
    if observation_id == binding.get("run_1_observation_id"):
        _refuse("D4 run2 observation_id copies run1 observation_id")


def _admit_d4_execution_shape(binding, runtime):
    """Reject a statically impossible run-2 command set before execution."""
    from ..bench import test_quality as TQ
    if binding["timeout_seconds"] != 600:
        _refuse("D4 run1 timeout differs from the fixed run2 timeout")
    partitions = TQ.shard_d4_confirmation_pairs(
        binding["pairs"], len(runtime["workers"]))
    empty = [number for number, pairs in enumerate(partitions) if not pairs]
    if empty:
        _refuse(
            "D4 current worker pool is wider than its independently "
            f"applicable mutant groups; empty shard(s) would be {empty}")


def _global_argv(source, preflight, runtime, worker=None):
    argv = []
    if worker is None:
        argv.extend(("--repo", preflight["corpus"]["root"]))
    argv.extend((
        "--boundary", os.path.join(
            source["repository"],
            "benchmark/config/boundary_python_docx.yml"),
    ))
    if worker is not None:
        argv.extend(("--worker", worker))
    argv.extend(("--docker-authority", runtime["authority"]["path"]))
    return argv


def _mutation_argv(*, source, preflight, runtime, inputs, output_root,
                   worker, shard, phase):
    full = phase.startswith("full-gold-")
    d4 = phase.endswith("-d4")
    side = "gold" if full else "candidate"
    argv = _global_argv(source, preflight, runtime, worker)
    argv.extend((
        "mutation-run",
        "--mutation-validation", inputs["mutation_validation"]["path"],
        "--manifest", inputs["manifest"]["path"],
        "--seed", runtime["seed_dir"],
        "--worker-pool", *runtime["workers"],
        "--side", side,
        "--map", inputs["map"]["path"],
        "--candidate", inputs["candidate"]["path"],
        "--release", inputs["release"]["path"],
    ))
    if d4:
        argv.extend((
            "--pair-plan", inputs["pair_plan"]["path"],
            "--run1-campaign", os.path.dirname(inputs["run1_state"]["path"]),
            "--hard-subset", inputs["hard_subset"]["path"],
        ))
    argv.extend((
        "--mutant-shard", str(shard),
        "--mutant-of", str(len(runtime["workers"])),
        "--timeout", "600",
        "--out", os.path.join(output_root, f"{side}.w{shard}.jsonl"),
        "--profile", os.path.join(
            source["repository"],
            "benchmark/config/profile_python_docx.yml"),
    ))
    return tuple(argv)


def _test_quality_argv(*, source, preflight, runtime, inputs, output_root,
                       phase):
    d4 = phase.endswith("-d4")
    run1_root = (os.path.dirname(inputs["run1_state"]["path"])
                 if d4 else os.path.join(output_root, "campaign"))
    workers = (runtime.get("resume_workers", runtime["workers"])
               if d4 else runtime["workers"])
    argv = _global_argv(source, preflight, runtime)
    argv.extend((
        "test-quality",
        "--run", inputs["candidate"]["path"],
        "--mutation-validation", inputs["mutation_validation"]["path"],
        "--manifest", inputs["manifest"]["path"],
        "--seed", runtime["seed_dir"],
        "--map", inputs["map"]["path"],
        "--gold-baseline", inputs["gold_baseline"]["path"],
        "--gold-results", inputs["gold_results"]["path"],
        "--gold-results-attestation",
        inputs["gold_results_attestation"]["path"],
        "--workers", *workers,
        "--shard-policy", "r2t.balanced-pairs-lpt/1",
        "--release", inputs["release"]["path"],
        "--timeout", "600",
        "--hard-subset", inputs["hard_subset"]["path"],
    ))
    if d4:
        argv.extend(("--candidate-hard-plan", inputs["pair_plan"]["path"]))
        for shard in range(len(runtime["workers"])):
            argv.extend(("--candidate-hard-rerun", os.path.join(
                output_root, f"candidate.w{shard}.jsonl")))
        argv.append("--resume")
    else:
        argv.extend(("--candidate-hard-plan-out",
                     os.path.join(output_root, "d4-plan.json")))
    argv.extend((
        "--no-sidecar", "--out", run1_root,
        "--profile", os.path.join(
            source["repository"],
            "benchmark/config/profile_python_docx.yml"),
    ))
    return tuple(argv)


def _evidence_commands(phase, source, preflight, runtime, inputs, output_root):
    output_root = _producer_root(output_root)
    if phase == "stripped-fidelity":
        if len(runtime["workers"]) != 1:
            _refuse("stripped-fidelity requires exactly one authenticated worker")
        argv = _global_argv(
            source, preflight, runtime, runtime["workers"][0])
        argv.extend((
            "run", "--adapter", "replay",
            "--replay", inputs["candidate"]["path"],
            "--release", inputs["release"]["path"],
            "--out", os.path.join(output_root, "stripped-fidelity.jsonl"),
            "--repro-check", "0", "--shard", "0", "--of", "1",
            "--profile", os.path.join(
                source["repository"],
                "benchmark/config/profile_python_docx.yml"),
        ))
        return (("run", tuple(argv)),)
    if phase in _REFERENCE_PHASES:
        return tuple(("mutation-run", _mutation_argv(
            source=source, preflight=preflight, runtime=runtime,
            inputs=inputs, output_root=output_root, worker=worker,
            shard=shard, phase=phase))
            for shard, worker in enumerate(runtime["workers"]))
    if phase.endswith("-run1"):
        return (("test-quality", _test_quality_argv(
            source=source, preflight=preflight, runtime=runtime,
            inputs=inputs, output_root=output_root, phase=phase)),)
    mutations = tuple(("mutation-run", _mutation_argv(
        source=source, preflight=preflight, runtime=runtime, inputs=inputs,
        output_root=output_root, worker=worker, shard=shard, phase=phase))
        for shard, worker in enumerate(runtime["workers"]))
    final = _test_quality_argv(
        source=source, preflight=preflight, runtime=runtime, inputs=inputs,
        output_root=output_root, phase=phase)
    return (*mutations, ("test-quality", final))


@dataclass
class _Capability:
    digest: str
    argv: tuple[str, ...]
    image_id: str
    protected_paths: tuple[str, ...] = ()
    used: bool = False


@dataclass
class _EvidenceCapability:
    digest: str
    commands: tuple[tuple[str, tuple[str, ...]], ...]
    image_id: str
    phase: str
    observation_id: str
    generation: dict
    candidate: dict
    source_tag: str
    protected_paths: tuple[str, ...] = ()
    position: int = 0
    current_action: str | None = None


_ACTIVE = None


def has_active_capability():
    return _ACTIVE is not None


def bind_cli(args, argv):
    if _ACTIVE is None:
        return
    action = ("mutants-build" if args.cmd == "mutants"
              and getattr(args, "action", None) == "build" else args.cmd)
    if isinstance(_ACTIVE, _Capability):
        if _ACTIVE.used or tuple(argv) != _ACTIVE.argv \
                or action != "mutants-build":
            raise SystemExit(
                "REFUSED: DOCX population capability does not match the "
                "exact unused CLI argv; no Docker command was run.")
        _ACTIVE.used = True
    else:
        if _ACTIVE.position >= len(_ACTIVE.commands) \
                or _ACTIVE.commands[_ACTIVE.position] != (action, tuple(argv)):
            raise SystemExit(
                "REFUSED: DOCX evidence capability does not match its next "
                "exact phase argv; no Docker command was run.")
        _ACTIVE.position += 1
        _ACTIVE.current_action = action
    args._docx_v2_workload = _ACTIVE
    args._publication_protected_paths = _ACTIVE.protected_paths


def capability_for(args, action):
    capability = getattr(args, "_docx_v2_workload", None)
    if capability is not _ACTIVE or capability is None:
        return None
    if isinstance(capability, _Capability):
        return capability if action == "mutants-build" else None
    return capability if action == capability.current_action else None


def generation_evidence(run_sha256):
    """Return the active exact-byte reference identity, or validate candidate."""
    capability = _ACTIVE
    if not isinstance(capability, _EvidenceCapability) \
            or capability.current_action not in {"mutation-run", "test-quality"}:
        return None
    if run_sha256 != capability.candidate["sha256"]:
        raise SystemExit(
            "REFUSED: DOCX evidence command opened candidate bytes other "
            "than the workload-bound input; no Docker command was run.")
    if capability.phase in _REFERENCE_PHASES:
        return {
            "generation_provenance_class":
                "reference_control_exact_bytes",
            "reference_control_role": capability.generation["role"],
            "reference_source_tag": capability.source_tag,
            "reference_workload_digest": capability.digest,
        }
    return None


def reference_candidate_files(run_path, run_rows):
    """Return the exact passed-only reference map for an active mutation."""
    capability = _ACTIVE
    if not isinstance(capability, _EvidenceCapability) \
            or capability.current_action != "mutation-run" \
            or capability.phase not in _REFERENCE_PHASES:
        return None
    from ..bench import mutation_run as MR
    from ..bench import test_quality as TQ
    try:
        evidence = MR.generation_evidence_for_run(run_path, run_rows)
        files = TQ.passed_solutions(run_rows)
        generated = MR.candidate_digest(files)
    except (MR.MutationAborted, TQ.TestQualityRefused,
            OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    if evidence.get("generation_provenance_class") \
            != "reference_control_exact_bytes" \
            or generated != capability.generation["generated_tests_sha256"]:
        raise SystemExit(
            "REFUSED: active DOCX reference mutation differs from its "
            "passed-solutions file map; no Docker command was run.")
    return files


def require_reference_identity(identity):
    capability = _ACTIVE
    expected = None
    if isinstance(capability, _EvidenceCapability) \
            and capability.phase in _REFERENCE_PHASES \
            and capability.current_action == "mutation-run":
        expected = {
            "generation_provenance_class":
                "reference_control_exact_bytes",
            "reference_control_role": capability.generation["role"],
            "candidate_run_sha256": capability.candidate["sha256"],
            "candidate_generated_tests_sha256":
                capability.generation["generated_tests_sha256"],
            "reference_source_tag": capability.source_tag,
            "reference_workload_digest": capability.digest,
        }
    changed = ([] if expected is None else [
        key for key, value in expected.items() if identity.get(key) != value])
    if expected is None or changed:
        _refuse("reference identity is not the active workload's exact "
                f"six-member tuple (changed={changed})")


def active_observation_id(identity):
    capability = _ACTIVE
    if not isinstance(capability, _EvidenceCapability) \
            or capability.current_action != "mutation-run":
        return None
    expected_class = ("reference_control_exact_bytes"
                      if capability.phase in _REFERENCE_PHASES
                      else "legacy_exact_bytes")
    if identity.get("generation_provenance_class") != expected_class \
            or identity.get("candidate_run_sha256") \
            != capability.candidate["sha256"] \
            or identity.get("candidate_generated_tests_sha256") \
            != capability.generation["generated_tests_sha256"]:
        _refuse("mutation identity differs from the active evidence workload")
    return capability.observation_id


@contextmanager
def _activate(capability):
    global _ACTIVE
    if _ACTIVE is not None:
        _refuse("a DOCX workload is already active")
    _ACTIVE = capability
    try:
        yield
    finally:
        _ACTIVE = None


def load(path, approved_digest, *, require_empty_output=True):
    try:
        path = A.canonical_absolute_path(path, "workload path")
    except A.DockerAuthorityRefused as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))
    document = _json(path, "workload")
    _exact(document, _TOP, "workload")
    if document["schema"] != SCHEMA:
        _refuse(f"workload schema is not {SCHEMA}")
    recorded = _sha(document["digest"], "workload.digest")
    if semantic_digest(document) != recorded \
            or _sha(approved_digest, "approved digest") != recorded:
        _refuse("workload digest is stale or not operator-approved")
    source = _source(document["source"])
    preflight = _preflight(document["static_preflight"], source)
    runtime = _runtime(
        document["docker_authority"], document["worker_runtime"])
    output_root = _output_root(
        document["output_root"], require_empty=require_empty_output)
    argv = _argv(
        document["phase"], source, preflight, runtime, output_root)
    protected_paths = tuple(dict.fromkeys((
        path, source["repository"], document["static_preflight"]["path"],
        preflight["corpus"]["root"], output_root,
        *runtime["protected_paths"],
    )))
    capability = _Capability(
        recorded, argv, runtime["image"], protected_paths)
    return {"path": path, "digest": recorded, "source": source,
            "preflight": preflight, "runtime": runtime,
            "phase": document["phase"], "output_root": output_root,
            "protected_paths": protected_paths,
            "argv": argv, "capability": capability}


def load_evidence(path, approved_digest, *, require_empty_output=True):
    try:
        path = A.canonical_absolute_path(path, "workload path")
    except A.DockerAuthorityRefused as exc:
        _refuse(str(exc).removeprefix("REFUSED: "))
    document = _json(path, "evidence workload")
    _exact(document, _EVIDENCE_TOP, "evidence workload")
    if document["schema"] != EVIDENCE_SCHEMA:
        _refuse(f"workload schema is not {EVIDENCE_SCHEMA}")
    recorded = _sha(document["digest"], "workload.digest")
    if evidence_semantic_digest(document) != recorded \
            or _sha(approved_digest, "approved digest") != recorded:
        _refuse("workload digest is stale or not operator-approved")
    phase = document["phase"]
    if phase not in _EVIDENCE_PHASES:
        _refuse(f"phase is not one of {sorted(_EVIDENCE_PHASES)}")
    observation_id = document["observation_id"]
    if not isinstance(observation_id, str) \
            or _OBSERVATION.fullmatch(observation_id) is None:
        _refuse("observation_id is not one lower-case 128-bit identifier")
    source = _source(document["source"])
    preflight = _preflight(document["static_preflight"], source)
    runtime = _runtime(
        document["docker_authority"], document["worker_runtime"])
    inputs = _evidence_inputs(document["inputs"], phase)
    generation = _evidence_generation(phase, inputs, preflight)
    output_root = _output_root(
        document["output_root"], require_empty=require_empty_output)
    if phase.endswith("-d4"):
        if os.path.basename(inputs["run1_state"]["path"]) != "campaign.json":
            _refuse("D4 run1_state is not the producer-owned campaign.json")
        from ..data import mutation_attestation as MA
        from ..bench import test_quality as TQ
        try:
            assets = MA.validate_campaign_asset_inputs(
                inputs["mutation_validation"]["path"],
                manifest_path=inputs["manifest"]["path"],
                map_path=inputs["map"]["path"],
                release_path=inputs["release"]["path"],
                require_release_ready=True)
            d4_binding = TQ.validate_d4_confirmation_plan(
                inputs["pair_plan"]["path"],
                run1_campaign=os.path.dirname(inputs["run1_state"]["path"]),
                hard_subset_path=inputs["hard_subset"]["path"],
                candidate_run_path=inputs["candidate"]["path"],
                assets=assets,
                validation_path=inputs["mutation_validation"]["path"],
                manifest_path=inputs["manifest"]["path"],
                map_path=inputs["map"]["path"],
                release_path=inputs["release"]["path"])
        except (MA.MutationAssetRefused, TQ.TestQualityRefused,
                OSError, ValueError) as exc:
            _refuse(str(exc).removeprefix("REFUSED: "))
        _require_fresh_d4_observation(observation_id, d4_binding)
        _admit_d4_execution_shape(d4_binding, runtime)
        run1_state = _json(inputs["run1_state"]["path"], "D4 run1 state")
        resume_workers, protected = _d4_run1_runtime(
            run1_state.get("plan") if isinstance(run1_state, dict) else None,
            runtime)
        runtime["resume_workers"] = resume_workers
        runtime["protected_paths"] = tuple(dict.fromkeys((
            *runtime["protected_paths"], *protected,
        )))
    commands = _evidence_commands(
        phase, source, preflight, runtime, inputs, output_root)
    protected_paths = tuple(dict.fromkeys((
        path, source["repository"], document["static_preflight"]["path"],
        preflight["corpus"]["root"], output_root,
        *(item["path"] for item in inputs.values() if item is not None),
        *runtime["protected_paths"],
    )))
    capability = _EvidenceCapability(
        recorded, commands, runtime["image"], phase, observation_id,
        generation, inputs["candidate"], source["tag"], protected_paths)
    return {
        "path": path, "digest": recorded, "schema": EVIDENCE_SCHEMA,
        "source": source, "preflight": preflight, "runtime": runtime,
        "phase": phase, "observation_id": observation_id, "inputs": inputs,
        "generation": generation, "output_root": output_root,
        "protected_paths": protected_paths, "commands": commands,
        "capability": capability,
    }


def load_for_audit(path, approved_digest):
    """Reauthenticate a completed v2 workload without reopening execution."""
    facts = load(path, approved_digest, require_empty_output=False)
    if facts["phase"] != "population-v2-build":
        _refuse("the materialisation audit requires population-v2-build")
    try:
        root_entries = sorted(os.listdir(facts["output_root"]))
    except OSError as exc:
        _refuse(f"cannot inspect completed v2 output root: {exc}")
    expected = ["mutants_v2.json", "mutants_v2.raw.json"]
    # Retain read-only admission of artifacts produced before durable claims.
    if root_entries == expected:
        return facts
    _validate_claim(facts)
    expected_root = [CLAIM_NAME, OUTPUT_DIRECTORY]
    if root_entries != expected_root:
        _refuse(f"completed v2 root entries differ; expected={expected_root}, "
                f"got={root_entries}")
    try:
        entries = sorted(os.listdir(_producer_root(facts["output_root"])))
    except OSError as exc:
        _refuse(f"cannot inspect completed v2 producer directory: {exc}")
    if entries != expected:
        _refuse(f"completed v2 output files differ; expected={expected}, "
                f"got={entries}")
    return facts


def _retained_command(facts):
    root = facts["source"]["repository"]
    return shlex.join([
        "env", "PYTHONDONTWRITEBYTECODE=1",
        f"PYTHONPATH={root}/benchmark", os.path.realpath(sys.executable),
        "-m", "r2t.toolkit.docx_v2_workload", "exec",
        "--workload", facts["path"],
        "--approved-digest", facts["digest"],
    ])


def execute(facts):
    from .. import cli
    _claim_output_root(facts)
    with _activate(facts["capability"]):
        if facts.get("schema") != EVIDENCE_SCHEMA:
            return cli.main(list(facts["argv"]))
        for _action, argv in facts["commands"]:
            result = cli.main(list(argv))
            if result:
                return result
        if facts["capability"].position != len(facts["commands"]):
            _refuse("evidence workload did not consume its exact command set")
        return 0


def selftest():
    ok = True

    def check(name, condition):
        nonlocal ok
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}")
        ok = ok and condition

    def refused(call, needle="REFUSED:"):
        try:
            call()
        except (WorkloadRefused, SystemExit, RuntimeError,
                A.DockerAuthorityRefused) as exc:
            return needle in str(exc)
        return False

    check("duplicate and non-finite JSON refuse",
          refused(lambda: A.loads_exact_json(
              b'{"x":1,"x":2}', label="workload"), "repeats key")
          and refused(lambda: A.loads_exact_json(
              b'{"x":NaN}', label="workload"), "non-finite"))
    base = {"schema": SCHEMA, "phase": "population-v1-replay",
            "digest": "0" * 64}
    check("semantic digest ignores only the digest field",
          semantic_digest(base) == semantic_digest(
              {**base, "digest": "f" * 64}))
    with tempfile.TemporaryDirectory(prefix="r2t-docx-population-") as root:
        os.chmod(root, 0o700)
        source = {"repository": "/reviewed/source"}
        preflight = {"corpus": {"root": "/reviewed/python-docx"}}
        runtime = {"authority": {"path": "/reviewed/authority.json"},
                   "image": "sha256:" + "a" * 64}
        v1 = _argv(
            "population-v1-replay", source, preflight, runtime, root)
        v2 = _argv(
            "population-v2-build", source, preflight, runtime, root)
        expected = (
            "--repo", "/reviewed/python-docx",
            "--boundary", "/reviewed/source/benchmark/config/"
            "boundary_python_docx.yml",
            "--docker-authority", "/reviewed/authority.json",
            "mutants", "build",
            "--profile", "/reviewed/source/benchmark/config/"
            "profile_python_docx.yml",
            "--operator-profile", "v1",
            "--out", os.path.join(
                root, OUTPUT_DIRECTORY, "mutants_v1.json"),
            "--raw-out", os.path.join(
                root, OUTPUT_DIRECTORY, "mutants_v1.raw.json"),
        )
        expected_v2 = (
            "--repo", "/reviewed/python-docx",
            "--boundary", "/reviewed/source/benchmark/config/"
            "boundary_python_docx.yml",
            "--docker-authority", "/reviewed/authority.json",
            "mutants", "build",
            "--profile", "/reviewed/source/benchmark/config/"
            "profile_python_docx.yml",
            "--operator-profile", "v2",
            "--out", os.path.join(
                root, OUTPUT_DIRECTORY, "mutants_v2.json"),
            "--raw-out", os.path.join(
                root, OUTPUT_DIRECTORY, "mutants_v2.raw.json"),
            "--record-enumerator-rev",
        )
        check("v1 replay is exact, unsampled, and preserves raw bytes",
              v1 == expected)
        check("v2 build is exact and records the pinned enumerator revision",
              v2 == expected_v2)
        check("unknown phases refuse",
              refused(lambda: _argv(
                  "oracle", source, preflight, runtime, root),
                  "phase is not"))
        occupied = os.path.join(root, "retained-output.json")
        Path(occupied).write_text("retained\n", encoding="utf-8")
        check("completed output is readable but cannot reopen execution",
              _output_root(root, require_empty=False) == root
              and refused(lambda: _output_root(root), "must be empty"))
        os.unlink(occupied)
        protected_workspace = os.path.join(root, "protected-worker")
        os.mkdir(protected_workspace)
        protected_input = os.path.join(
            protected_workspace, "reviewed-workload.json")
        capability = _Capability(
            "b" * 64, v1, runtime["image"], (protected_input,))
        args = SimpleNamespace(cmd="mutants", action="build")
        check("no ambient capability exists",
              capability_for(args, "mutants-build") is None)
        with _activate(capability):
            bind_cli(args, v1)
            exact = capability_for(args, "mutants-build") is capability
            changed = refused(lambda: bind_cli(args, v1 + ("changed",)),
                              "does not match")
        check("capability is exact-argv and erased after one operation",
              exact and changed and not has_active_capability())
        from ..bench import worker as W
        protected_worker = W.WorkerSpec(
            index=0, workspace=protected_workspace,
            container="protected-worker", schema="", credential="",
            env_file=os.path.join(root, "protected-worker.env"),
            workdir="/work")
        check("the capability propagates every workload-protected path and "
              "static worker preflight refuses nesting before Docker",
              args._publication_protected_paths == (protected_input,)
              and refused(lambda: W.preflight(
                  [protected_worker],
                  list(args._publication_protected_paths), live=False,
                  needs_database=False), "lies inside"))
        evidence_source = source
        evidence_preflight = {
            **preflight,
            "candidates": [
                {"label": "a5_cell3_python_docx_openhands_corrected",
                 "run_sha256": "3" * 64,
                 "generated_tests_sha256": "4" * 64},
                {"label": "a5_cell4_python_docx_aider",
                 "run_sha256": "5" * 64,
                 "generated_tests_sha256": "6" * 64},
            ],
        }
        evidence_runtime = {
            **runtime, "workers": ("/reviewed/worker0.json",),
            "seed_dir": "/reviewed/seed",
        }
        blank_inputs = {key: None for key in _INPUTS}
        reference_path = os.path.join(root, "reference.jsonl")
        reference_rows = [
            {
                "item_id": "item", "outcome": "passed",
                "produced_files": [{"file_path": "test_ref.py",
                                    "code": "def test_ref(): assert True"}],
            },
            {
                "item_id": "excluded", "outcome": "failed",
                "produced_files": [{"file_path": "test_excluded.py",
                                    "code": "def test_bad(): assert False"}],
            },
        ]
        Path(reference_path).write_text(
            "".join(json.dumps(row) + "\n" for row in reference_rows),
            encoding="utf-8")
        reference_inputs = {
            **blank_inputs,
            **{key: {"path": f"/reviewed/{key}", "sha256": "7" * 64}
               for key in ("mutation_validation", "manifest", "map",
                           "release")},
            "candidate": {"path": reference_path,
                          "sha256": A.sha256_file(reference_path)},
        }
        all_phases = {
            "stripped-fidelity", "full-gold-a", "full-gold-b",
            "stripped-gold-c", "stripped-gold-d", "stub-control-a",
            "stub-control-b", "candidate-openhands-c3-run1",
            "candidate-aider-c4-run1", "candidate-openhands-c3-d4",
            "candidate-aider-c4-d4",
        }
        check("evidence phase grammar is the exact finite amendment list",
              _EVIDENCE_PHASES == all_phases
              and _REFERENCE_PHASES == {
                  "stripped-fidelity": "assertion-stripped-gold",
                  "full-gold-a": "full-gold", "full-gold-b": "full-gold",
                  "stripped-gold-c": "assertion-stripped-gold",
                  "stripped-gold-d": "assertion-stripped-gold",
                  "stub-control-a": "stub-control",
                  "stub-control-b": "stub-control",
              })
        reference_generation = _evidence_generation(
            "full-gold-a", reference_inputs, evidence_preflight)
        reference_generated = reference_generation[
            "generated_tests_sha256"]
        check("reference phases derive class, role, and submitted-test digest",
              reference_generation["role"] == "full-gold"
              and reference_generation["class"]
              == "reference_control_exact_bytes"
              and _SHA.fullmatch(reference_generated) is not None)
        candidate_inputs = dict(
            reference_inputs,
            candidate={"path": "/reviewed/openhands.jsonl",
                       "sha256": "3" * 64})
        check("candidate phases retain the frozen legacy exact-byte tuple",
              _evidence_generation(
                  "candidate-openhands-c3-run1", candidate_inputs,
                  evidence_preflight)["class"] == "legacy_exact_bytes"
              and refused(lambda: _evidence_generation(
                  "candidate-aider-c4-run1", candidate_inputs,
                  evidence_preflight), "candidate bytes differ"))
        campaign_inputs = {
            key: ({"path": f"/reviewed/{key}", "sha256": "7" * 64}
                  if key not in {"pair_plan", "run1_state"} else None)
            for key in _INPUTS
        }
        d4_inputs = {
            **campaign_inputs,
            "pair_plan": {"path": "/reviewed/d4-plan.json",
                          "sha256": "a" * 64},
            "run1_state": {"path": "/reviewed/run1/campaign.json",
                           "sha256": "b" * 64},
        }
        run1_commands = _evidence_commands(
            "candidate-openhands-c3-run1", evidence_source,
            evidence_preflight, evidence_runtime, campaign_inputs, root)
        run1_workers = tuple(
            f"/reviewed/run1-worker{index}.json" for index in range(3))
        d4_runtime = {**evidence_runtime, "resume_workers": run1_workers}
        d4_commands = _evidence_commands(
            "candidate-openhands-c3-d4", evidence_source,
            evidence_preflight, d4_runtime, d4_inputs, root)
        fidelity_commands = _evidence_commands(
            "stripped-fidelity", evidence_source, evidence_preflight,
            evidence_runtime, reference_inputs, root)
        check("phase-derived commands are finite: fidelity once, run 1 once, "
              "and D4 exact rerun shards followed by one finalization",
              [action for action, _argv_ in fidelity_commands] == ["run"]
              and [action for action, _argv_ in run1_commands]
              == ["test-quality"]
              and [action for action, _argv_ in d4_commands]
              == ["mutation-run", "test-quality"]
              and "--resume" not in run1_commands[0][1]
              and "--resume" in d4_commands[-1][1]
              and "--pair-plan" in d4_commands[0][1])
        full_commands = _evidence_commands(
            "full-gold-a", evidence_source, evidence_preflight,
            evidence_runtime, campaign_inputs, root)
        check("worker-bound commands inherit the authenticated workspace "
              "while workerless candidate finalization retains the corpus",
              "--repo" not in full_commands[0][1]
              and "--worker" in full_commands[0][1]
              and "--repo" not in fidelity_commands[0][1]
              and "--worker" in fidelity_commands[0][1]
              and "--repo" in run1_commands[0][1]
              and "--worker" not in run1_commands[0][1])
        d4_mutation_argv = d4_commands[0][1]
        d4_final_argv = d4_commands[-1][1]
        mutation_pool = d4_mutation_argv[
            d4_mutation_argv.index("--worker-pool") + 1:
            d4_mutation_argv.index("--side")]
        resume_pool = d4_final_argv[
            d4_final_argv.index("--workers") + 1:
            d4_final_argv.index("--shard-policy")]
        check("D4 runs mutations on current K1 but resumes finalization on "
              "the authenticated run-1 K3 pool",
              mutation_pool == evidence_runtime["workers"]
              and resume_pool == run1_workers)
        check("D4 run2 observation must differ from authenticated run1",
              refused(lambda: _require_fresh_d4_observation(
                  "1" * 32, {"run_1_observation_id": "1" * 32}),
                  "copies run1")
              and _require_fresh_d4_observation(
                  "2" * 32, {"run_1_observation_id": "1" * 32}) is None)
        one_group = {("item", "mutant")}
        check("D4 rejects a timeout change or over-wide current pool during "
              "source-only workload admission",
              refused(lambda: _admit_d4_execution_shape(
                  {"timeout_seconds": 601, "pairs": one_group},
                  {"workers": ("worker0",)}), "fixed run2 timeout")
              and refused(lambda: _admit_d4_execution_shape(
                  {"timeout_seconds": 600, "pairs": one_group},
                  {"workers": ("worker0", "worker1")}),
                  "current worker pool is wider")
              and _admit_d4_execution_shape(
                  {"timeout_seconds": 600, "pairs": one_group},
                  {"workers": ("worker0",)}) is None)
        from ..bench import worker as W
        shared_runtime = {
            "seed_dir": "/reviewed/seed",
            "seed_manifest_sha256": "1" * 64,
            "seed_key": "docx-seed",
            "workspace_seed_digest": "2" * 64,
            "database_dump_digest": "no_database",
            "container_image_digest": "sha256:" + "3" * 64,
            "harness_version": 6,
            "needs_database": False,
            "docker_execution_authority": {
                "path": "/reviewed/authority.json",
                "file_sha256": "4" * 64,
            },
        }
        loaded_run1 = []
        run1_resources = []
        for index, spec_path in enumerate(run1_workers):
            worker = SimpleNamespace(
                index=index, workspace=f"/reviewed/workspace{index}",
                container=f"docx-worker-{index}", schema="r2t.worker/3",
                credential=f"/reviewed/credential{index}",
                env_file=f"/reviewed/env{index}", workdir="/workspace")
            runtime_path = f"{spec_path}.runtime.json"
            runtime_sha256 = str(index + 5) * 64
            loaded_run1.append({
                "worker": worker, "spec_path": spec_path,
                "runtime_path": runtime_path,
                "runtime_sha256": runtime_sha256,
                "runtime": {
                    **shared_runtime,
                    "worker_spec_sha256": str(index + 8) * 64,
                    "docker_execution_binding": {
                        "path": f"{spec_path}.binding.json",
                    },
                },
            })
            run1_resources.append({
                "index": index, "worker_spec": spec_path,
                "workspace": os.path.realpath(worker.workspace),
                "container": worker.container, "schema": worker.schema,
                "credential": worker.credential,
                "env_file": os.path.realpath(worker.env_file),
                "workdir": worker.workdir,
                "runtime_attestation": runtime_path,
                "runtime_attestation_sha256": runtime_sha256,
            })
        authenticated_paths = []
        real_validate_pool = W.validate_offline_worker_runtime_pool

        def fake_validate_pool(paths):
            authenticated_paths.append(tuple(paths))
            return loaded_run1

        W.validate_offline_worker_runtime_pool = fake_validate_pool
        try:
            resumed, protected = _d4_run1_runtime(
                {"worker_resources": run1_resources},
                {"shared_runtime": dict(shared_runtime)})
            changed_runtime = {
                "shared_runtime": {
                    **shared_runtime,
                    "container_image_digest": "sha256:" + "9" * 64,
                },
            }
            shared_change_refused = refused(
                lambda: _d4_run1_runtime(
                    {"worker_resources": run1_resources}, changed_runtime),
                "shared runtime fact")
        finally:
            W.validate_offline_worker_runtime_pool = real_validate_pool
        check("D4 offline-authenticates run1's exact K3 specs and shared "
              "runtime facts before reuse",
              authenticated_paths == [run1_workers, run1_workers]
              and resumed == run1_workers
              and all(path in protected for path in run1_workers)
              and shared_change_refused)
        reference_commands = _evidence_commands(
            "full-gold-a", evidence_source, evidence_preflight,
            evidence_runtime, reference_inputs, root)
        capability = _EvidenceCapability(
            "8" * 64, reference_commands, runtime["image"], "full-gold-a",
            "9" * 32, reference_generation, reference_inputs["candidate"],
            "docx-reference-v1")

        # Frozen candidate runs already carry historical sidecars.  The
        # wrapper's exact --no-sidecar command must not even open one, while a
        # command that would write a sidecar must refuse before live preflight.
        from .. import cli as cli_module
        from ..bench import cli as bench_cli
        from ..bench import test_quality as TQ
        sidecar_path = TQ.sidecar_paths(reference_path)[0]
        Path(sidecar_path).write_bytes(b'{"historical":true}\n')
        sidecar_before = Path(sidecar_path).read_bytes()
        sidecar_events = []
        real_find_sidecar = TQ.find_sidecar
        real_resolve_policy = TQ.resolve_cli_shard_policy
        real_worker_preflight = W.preflight

        def observed_find_sidecar(path):
            sidecar_events.append("sidecar")
            return real_find_sidecar(path)

        def stop_after_sidecar_admission(*_args, **_kwargs):
            sidecar_events.append("admitted")
            raise RuntimeError("after sidecar admission, before Docker")

        def unexpected_live_preflight(*_args, **_kwargs):
            sidecar_events.append("preflight")
            raise RuntimeError("unexpected worker preflight")

        sidecar_capability = _EvidenceCapability(
            "8" * 64, (), runtime["image"],
            "candidate-openhands-c3-run1", "a" * 32,
            {"class": "legacy_exact_bytes", "role": None,
             "generated_tests_sha256": reference_generated},
            reference_inputs["candidate"], "docx-reference-v1")
        sidecar_capability.current_action = "test-quality"
        try:
            TQ.find_sidecar = observed_find_sidecar
            TQ.resolve_cli_shard_policy = stop_after_sidecar_admission
            W.preflight = unexpected_live_preflight
            writing_args = SimpleNamespace(
                run=reference_path, no_sidecar=False,
                _docx_v2_workload=sidecar_capability)
            no_write_args = SimpleNamespace(
                run=reference_path, out=os.path.join(root, "sidecar-out"),
                resume=False, no_sidecar=True,
                _docx_v2_workload=sidecar_capability)
            with _activate(sidecar_capability):
                write_refused = refused(
                    lambda: bench_cli.cmd_test_quality(writing_args),
                    "already has test-quality sidecar")
                no_write_admitted = refused(
                    lambda: bench_cli.cmd_test_quality(no_write_args),
                    "after sidecar admission, before Docker")
        finally:
            TQ.find_sidecar = real_find_sidecar
            TQ.resolve_cli_shard_policy = real_resolve_policy
            W.preflight = real_worker_preflight
        check("sidecar overwrite refuses before Docker while --no-sidecar "
              "neither reads nor writes the historical binding",
              write_refused and no_write_admitted
              and sidecar_events == ["sidecar", "admitted"]
              and Path(sidecar_path).read_bytes() == sidecar_before)

        def reference_identity(**changed):
            from ..bench import mutation_run as MR
            values = {
                "asset_index_sha256": "0" * 64,
                "asset_project": "python-docx",
                "mutation_validation_sha256": "a" * 64,
                "mutation_validation_class": "native",
                "manifest_sha256": "b" * 64,
                "manifest_digest": "c" * 64,
                "map_sha256": "d" * 64, "release_sha256": "e" * 64,
                "candidate_run_sha256":
                    reference_inputs["candidate"]["sha256"],
                "candidate_generated_tests_sha256": reference_generated,
                "solution_generated_tests_sha256": reference_generated,
                "substrate_baseline_sha256": "f" * 64,
                "applier_sha256": "0" * 64,
                "worker_resources_sha256": "1" * 64,
                "harness_version": 6,
                "container_image_digest": "sha256:" + "2" * 64,
                "workspace_seed_digest": "3" * 64,
                "database_dump_digest": "no_database",
                "expected_pairs": {("item", "mutant")},
                "engine": "python-ast", "engine_version": "1",
                "parser": "ast", "side": "gold", "shard": 0, "of": 1,
                "timeout": 600,
                "generation_provenance_class":
                    "reference_control_exact_bytes",
                "reference_control_role": "full-gold",
                "reference_source_tag": "docx-reference-v1",
                "reference_workload_digest": "8" * 64,
            }
            values.update(changed)
            return MR.build_campaign_identity(**values)

        args = SimpleNamespace(cmd="mutation-run")

        def changed_argv_refuses(argv):
            fresh = _EvidenceCapability(
                "8" * 64, reference_commands, runtime["image"],
                "full-gold-a", "9" * 32, reference_generation,
                reference_inputs["candidate"], "docx-reference-v1")
            with _activate(fresh):
                return refused(lambda: bind_cli(
                    SimpleNamespace(cmd="mutation-run"), argv),
                    "next exact phase argv")

        exact_argv = reference_commands[0][1]
        candidate_at = exact_argv.index(reference_inputs["candidate"]["path"])
        check("a fresh capability rejects argv addition, omission, reorder, "
              "and path substitution independently of its reuse gate",
              all(changed_argv_refuses(argv) for argv in (
                  exact_argv + ("changed",), exact_argv[:-1],
                  (exact_argv[1], exact_argv[0], *exact_argv[2:]),
                  (*exact_argv[:candidate_at], "/changed/candidate.jsonl",
                   *exact_argv[candidate_at + 1:]),
              )))
        with _activate(capability):
            bind_cli(args, reference_commands[0][1])
            from ..bench import mutation_run as MR
            from ..bench import test_quality as TQ
            loaded_reference_rows = TQ.load_jsonl(reference_path)
            projected = reference_candidate_files(
                reference_path, loaded_reference_rows)
            projection_exact = (
                set(projected) == {"item"}
                and MR.candidate_digest(projected) == reference_generated
                and refused(lambda: reference_candidate_files(
                    reference_path, loaded_reference_rows[:-1]),
                    "not the exact type-preserving"))
            evidence = generation_evidence(
                reference_inputs["candidate"]["sha256"])
            identity = reference_identity()
            exact_identity = (evidence == {
                "generation_provenance_class":
                    "reference_control_exact_bytes",
                "reference_control_role": "full-gold",
                "reference_source_tag": "docx-reference-v1",
                "reference_workload_digest": "8" * 64,
            } and active_observation_id(identity) == "9" * 32)
            cross_refused = all(refused(call, "exact six-member tuple")
                                for call in (
                lambda: reference_identity(candidate_run_sha256="a" * 64),
                lambda: reference_identity(
                    candidate_generated_tests_sha256="a" * 64,
                    solution_generated_tests_sha256="a" * 64),
                lambda: reference_identity(
                    reference_source_tag="docx-reference-v2"),
                lambda: reference_identity(reference_workload_digest="a" * 64),
            ))
            old_field_refused = all(refused(
                lambda changed=changed: reference_identity(**changed),
                "has no generation") for changed in (
                    {"generation_attempt_id": "invented"},
                    {"generation_agent_runtime_sha256": "a" * 64},
                    {"generation_network_semantics": "invented"},
                    {"generation_campaign_digest": "a" * 16},
                ))
            reused = refused(lambda: bind_cli(
                SimpleNamespace(cmd="mutation-run"),
                reference_commands[0][1]), "next exact phase argv")
        check("the wrapper alone mints the exact six-member tuple and bound "
              "observation; cross-binding and old provenance fields refuse",
              projection_exact and exact_identity
              and cross_refused and old_field_refused)
        check("evidence capability is exact-argv, ordered, and single-use",
              reused and not has_active_capability())
        # After erasure the wrapper binds NOTHING.  The v5 mint itself is no
        # longer refused here -- since the 2026-09-01 ruling a python-docx
        # leg may also be collected through `mutation-run --reference-role`,
        # which runs with no capability at all -- so what this holds is that
        # none of the wrapper's own bindings leak out of its phase: no
        # projection, no exact-bytes generation tuple, no observation id.
        check("no wrapper binding survives capability erasure",
              reference_candidate_files(
                  reference_path, reference_rows) is None
              and generation_evidence(
                  reference_inputs["candidate"]["sha256"]) is None
              and active_observation_id(reference_identity()) is None)
        from ..bench import campaign as Campaign
        registered_sha = reference_inputs["candidate"]["sha256"]
        prior_registration = Campaign.LEGACY_GENERATION_EVIDENCE.get(
            registered_sha)
        Campaign.LEGACY_GENERATION_EVIDENCE[registered_sha] = {
            "schema": "r2t.legacy-generation-evidence/v1",
            "label": "synthetic-registered-legacy",
            "generation_campaign_digest": "a" * 16,
            "candidate_run_sha256": registered_sha,
            "candidate_generated_tests_sha256": reference_generated,
            "historical_solution_digest": "b" * 16,
            "authority": "docx_v2_workload selftest",
        }
        try:
            load_relabel_refused = refused(
                lambda: _evidence_generation(
                    "full-gold-a", reference_inputs, evidence_preflight),
                "registered only as legacy_exact_bytes")
            relabel_capability = _EvidenceCapability(
                "8" * 64, reference_commands, runtime["image"],
                "full-gold-a", "9" * 32, reference_generation,
                reference_inputs["candidate"], "docx-reference-v1")
            with _activate(relabel_capability):
                relabel_args = SimpleNamespace(cmd="mutation-run")
                bind_cli(relabel_args, reference_commands[0][1])
                resolved_class = MR.generation_evidence_for_run(
                    reference_path, loaded_reference_rows)[
                        "generation_provenance_class"]
                producer_relabel_refused = refused(
                    lambda: reference_candidate_files(
                        reference_path, loaded_reference_rows),
                    "passed-solutions file map")
        finally:
            if prior_registration is None:
                Campaign.LEGACY_GENERATION_EVIDENCE.pop(registered_sha, None)
            else:
                Campaign.LEGACY_GENERATION_EVIDENCE[
                    registered_sha] = prior_registration
        check("registered legacy bytes retain legacy_exact_bytes before and "
              "inside an active reference capability",
              load_relabel_refused
              and resolved_class == "legacy_exact_bytes"
              and producer_relabel_refused)
        failure_root = os.path.join(root, "first-command-failure")
        os.mkdir(failure_root, mode=0o700)
        failure_argv = _argv(
            "population-v1-replay", source, preflight, runtime,
            failure_root)
        failure_facts = {
            "digest": "a" * 64,
            "phase": "population-v1-replay",
            "output_root": failure_root,
            "argv": failure_argv,
            "capability": _Capability(
                "a" * 64, failure_argv, runtime["image"]),
        }
        real_cli_main = cli_module.main

        def fail_first_command(_argv_):
            raise RuntimeError("injected first command failure")

        cli_module.main = fail_first_command
        try:
            first_failed = refused(
                lambda: execute(failure_facts), "injected first command")
        finally:
            cli_module.main = real_cli_main
        producer_root = _producer_root(failure_root)
        marker = os.path.join(failure_root, CLAIM_NAME)
        claim_valid = (
            A.loads_exact_json(Path(marker).read_bytes(), label="workload claim")
            == _claim_document(failure_facts)
            and stat.S_IMODE(os.stat(marker).st_mode) == 0o600)
        check("a first-command failure durably consumes the parent root and "
              "reload refuses while deterministic child outputs remain valid",
              first_failed and claim_valid
              and sorted(os.listdir(failure_root))
              == [CLAIM_NAME, OUTPUT_DIRECTORY]
              and os.path.isdir(producer_root)
              and os.listdir(producer_root) == []
              and all(path.startswith(producer_root + os.sep)
                      for path in (
                          failure_argv[failure_argv.index("--out") + 1],
                          failure_argv[
                              failure_argv.index("--raw-out") + 1],
                      ))
              and refused(lambda: _output_root(failure_root), "must be empty")
              and refused(lambda: _claim_output_root(failure_facts),
                          "already claimed"))
    from ..bench import cli
    check("ordinary live producers remain closed",
          refused(lambda: cli.cmd_mutation_run(SimpleNamespace()),
                  "no reviewed")
          and refused(lambda: cli.cmd_test_quality(SimpleNamespace()),
                      "no reviewed")
          and cli._docx_v2_capability(
              SimpleNamespace(), "mutants-build") is None)
    print("\n" + ("ALL PASS (docx_v2_workload)" if ok
                    else "FAILURES (docx_v2_workload)"))
    return 0 if ok else 1


def main(argv=None):
    effective = list(sys.argv[1:] if argv is None else argv)
    if effective == ["--selftest"]:
        return selftest()
    parser = argparse.ArgumentParser(
        description="Validate or execute one reviewed DOCX workload")
    sub = parser.add_subparsers(dest="action", required=True)
    digest_parser = sub.add_parser(
        "digest", help="print the semantic digest of a draft workload")
    digest_parser.add_argument("--workload", required=True)
    for action in ("check", "command", "exec"):
        child = sub.add_parser(action)
        child.add_argument("--workload", required=True)
        child.add_argument("--approved-digest", required=True)
    args = parser.parse_args(effective)
    if args.action == "digest":
        try:
            document = _json(args.workload, "workload draft")
            if document.get("schema") == SCHEMA:
                _exact(document, _TOP, "workload")
                print(semantic_digest(document))
            elif document.get("schema") == EVIDENCE_SCHEMA:
                _exact(document, _EVIDENCE_TOP, "evidence workload")
                print(evidence_semantic_digest(document))
            else:
                _refuse("workload has no supported DOCX schema")
        except WorkloadRefused as exc:
            raise SystemExit(str(exc)) from exc
        return 0
    try:
        draft = _json(args.workload, "workload")
        facts = (load_evidence(args.workload, args.approved_digest)
                 if draft.get("schema") == EVIDENCE_SCHEMA
                 else load(args.workload, args.approved_digest))
    except WorkloadRefused as exc:
        raise SystemExit(str(exc)) from exc
    if args.action == "check":
        print(json.dumps({
            "schema": facts.get("schema", SCHEMA), "status": "ready",
            "workload": facts["path"], "digest": facts["digest"],
            "source_commit": facts["source"]["commit"],
            "source_tag": facts["source"]["tag"],
            "phase": facts["phase"], "output_root": facts["output_root"],
            "docker_invoked": False,
        }, indent=1, sort_keys=True))
        return 0
    if args.action == "command":
        print(_retained_command(facts))
        return 0
    return execute(facts)


if __name__ == "__main__":
    raise SystemExit(main())
