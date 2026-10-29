"""Strict source-only verification and durable result-ledger primitives.

I1's verifier remains the publication boundary.  I2 adds only the durable
create/replace and candidate-receipt helpers used by the explicit run
producer; it does not open consumers, contact Docker, or build relocation
bundles.  Live-file verification means that every recorded absolute path is
read exactly where recorded under the Docker-authority trusted-file policy.

I3 opens complete validation verification with its exact row identity.  I4
adds the independent strict-merge receipt and recursively verifies every
source run-shard receipt through one stable live snapshot.  CAS bundle
verification remains closed to I6.
"""
from __future__ import annotations

import copy
import json
import os
import posixpath
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Optional

from ..core import reviewed_git
# Re-exported: every name of the primitive layer, public and private, so
# `ledger.<name>` keeps resolving for this module's importers and
# `ResultLedgerRefused` stays ONE class object.
from ..core.ledger_primitives import (  # noqa: F401
    CHECKPOINT_SCHEMA, RECEIPT_SCHEMA, BUNDLE_INDEX_SCHEMA, ORDERED_IDS_DOMAIN,
    _SCHEMA_DIR, _SCHEMA_FILES, _SCHEMA_CACHE, _VALIDATOR_CACHE, _SHA256_RE,
    _HEX16_RE, ResultLedgerRefused, _refuse, _raise_from, loads_exact_json,
    canonical_json_bytes, _same_json_value, _require_same_json, domain_digest,
    semantic_digest, ordered_item_ids_digest, raw_sha256, _schema, _validator,
    _json_path, validate_json_schema, validate_checkpoint_schema,
    validate_receipt_schema, validate_bundle_index_schema,
    canonical_absolute_path, _require_workspace_separation, _path_components,
    _ACL_MODE_BIT_TAGS, _default_acl_gives_files_access_acl,
    _secure_directory_chain, _trusted_leaf, _stat_identity,
    _read_trusted_snapshot, read_trusted_bytes, _LiveReader, _RENAME_NOREPLACE,
    _fault, _open_directory_nofollow, _rename_noreplace, _write_all,
    durable_create_bytes_no_clobber, durable_replace_bytes, _exact_keys,
    _sha256, _hex16, _integer, _nonempty, _safe_relative, _contained_path,
    _verify_digest, _verify_raw_reference, _verify_semantic_reference,
    _json_lines, _parse_json_object, _parse_yaml, _named_canonical_values)
from ..core.paths import BENCHMARK_ROOT, PROTOCOL_DIR


RUNTIME_IDENTITY_SCHEMA = "r2t.worker-runtime-identity/v1"
RUNTIME_IDENTITY_V2_SCHEMA = "r2t.worker-runtime-identity/v2"
RUN_PLAN_SCHEMA = "r2t.run-plan/v1"
VALIDATION_PLAN_SCHEMA = "r2t.validation-plan/v1"
RUN_INVOCATION_SCHEMA = "r2t.run-invocation/v1"
VALIDATION_INVOCATION_SCHEMA = "r2t.validation-invocation/v1"
STRICT_MERGE_POLICY = "r2t.strict-merge/v1"

# Result rows predate the ledger schemas and deliberately remain ordinary
# JSON objects.  I3 therefore owns and pins the exact validation identity
# fields that make a row adoptable and sealable.
VALIDATION_ROW_IDENTITY_FIELDS = (
    "validation_attempt_id",
    "validation_plan_digest",
    "harness_version",
    "repeats",
    "timeout_seconds",
)

CHECKPOINT_SUFFIX = ".result-checkpoint.json"
RECEIPT_SUFFIX = ".result-ledger.json"
PUBLICATION_LOCK_SUFFIX = ".result-v3.lock"


_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHORT_COMMIT_RE = re.compile(r"[0-9a-f]{7,40}\Z")

RUN_STAMP_NAMES = frozenset({
    "adapter", "adapter_version", "agent_system", "agent_timeout_seconds",
    "agent_version", "campaign_digest", "comparison_class", "condition",
    "coverage", "dataset_version", "execution_timeout_seconds",
    "harness_commit", "harness_version", "keep_artifacts", "max_iterations",
    "max_tokens", "model", "native_budget", "of", "prompt_digest",
    "protocol_deviations", "protocol_digest", "protocol_version", "repeats",
    "repro_check_count", "sandboxed", "setting", "shard", "subset_digest",
    "subset_id", "temperature", "trials",
})

#: The kinds v1 reserves that are NOT agents.  `replay` serves another run's
#: cached bytes and `openai` is a live model call; neither may sign a v1
#: receipt, and neither is a growing set -- nothing registers a new transport
#: or a new prompt kind the way an arm is registered.  They stay a literal for
#: that reason.  The agents do not; see `_reserved_adapter_kinds`.
_RESERVED_NON_AGENT_KINDS = frozenset({"replay", "openai"})
_ADMITTED_ADAPTER_NAMES = {
    "empty": "empty",
    "gold": "gold",
    "stripped_gold": "stripped-gold",
    "stub": "stub",
}


def _reserved_adapter_kinds() -> frozenset:
    """Every adapter kind a v1 receipt may NAME but v1 never admits.

    The agents in it are the registry's agents, reached through the v2
    producer's `admitted_adapter_kinds` -- one seam, not a second census.
    It was a closed literal naming the two arms that existed, and the cost of
    that was not a missing refusal but a MISLABELLED one: a third arm's kind
    fell past the reserved branch into the admitted-name check and was
    refused as an UNSUPPORTED kind, i.e. as a system this harness has never
    heard of, at exactly the moment it ships an arm for it.

    WHY NOT `from .agents.registry import SPECS` HERE.  Section 5 installs
    the v2 producer inside the confined backend tree as one of the staged
    files in `result_ledger_v2.BACKEND_SOURCE_RUNTIME_SHARED`, where there
    is no `agents/` package and no `adapters.py`; a module-scope registry
    import would be a `ModuleNotFoundError` in every confined item.
    `admitted_adapter_kinds` already carries exactly that guard and the
    honest confined-runtime answer behind it (`BACKEND_PACKAGES`, the
    inventory the staged file itself carries), so this reads THAT rather than
    repeating the try/except and inventing a second fallback for the same
    question.  The import is function-local, as every other reference to the
    v2 producer in this module already is.

    Recomputed per call, so a spec registered after import -- how the
    selftest drives a third arm through this gate -- is seen.  Without the
    agent producer no agent kind is admitted, so none is reserved beyond
    the fixed set -- exact, because an agent document is already refused by
    name where it is loaded (`_load_ledger_document`, `agent_ledger_kind`).
    """
    try:
        from ..confined import result_ledger_v2 as agent
    except ImportError:
        return _RESERVED_NON_AGENT_KINDS
    return _RESERVED_NON_AGENT_KINDS | frozenset(
        agent.admitted_adapter_kinds())


@dataclass
class _RuntimeContext:
    runtime: dict
    runtime_raw: bytes
    identity: dict
    authority: dict
    binding: dict
    pool: dict
    worker_document: dict
    worker: object
    seed: dict
    harness: dict


def _stable_harness_identity(reader: _LiveReader) -> dict:
    """The live tree's recorded provenance pair: commit and source digest.

    Section 16: the evaluator identity a verifier enforces is
    `HARNESS_VERSION`; this pair is recorded on plans and disclosed on drift
    (`disclose_harness_drift`), never compared for equality.
    """
    from . import campaign
    del reader
    source = campaign.harness_source_digest()
    commit = campaign.harness_commit_identity()
    if commit is not None and _COMMIT_RE.fullmatch(commit) is None:
        raise _refuse("live harness commit is malformed")
    return {"version": None, "git_commit": commit, "source_sha256": source}


#: Drift pairs already reported, so a K-shard merge that verifies K runtimes
#: recorded under one commit says it once.  Output hygiene, not a check.
_DISCLOSED_HARNESS_DRIFT: set = set()


def _short_harness(identity: Mapping) -> str:
    commit = identity["git_commit"]
    return (("no-commit" if commit is None else commit[:12])
            + "/" + identity["source_sha256"][:12])


def disclose_harness_drift(recorded: Mapping, live: Mapping) -> None:
    """Say once that this tree is not the tree that recorded the document.

    Stderr only: `verify-receipt`, `worker provision` and `results` print
    their reports as the whole of stdout and callers parse that stream.
    """
    from .validate import HARNESS_VERSION
    key = (recorded["git_commit"], recorded["source_sha256"],
           live["git_commit"], live["source_sha256"])
    if key[:2] == key[2:] or key in _DISCLOSED_HARNESS_DRIFT:
        return
    _DISCLOSED_HARNESS_DRIFT.add(key)
    print(f"note: harness recorded at {_short_harness(recorded)}, executing "
          f"at {_short_harness(live)}; harness version {HARNESS_VERSION} "
          "still enforced", file=sys.stderr, flush=True)


def _validate_authority_paths(authority: dict) -> None:
    paths = (
        (authority["client"]["selected_executable"], "authority client path"),
        (authority["client"]["resolved_executable"], "authority resolved client"),
        (authority["daemon"]["docker_root_dir"], "authority Docker root"),
        (authority["adapter"]["selected_socket_path"], "authority socket"),
        (authority["adapter"]["resolved_socket_path"], "authority resolved socket"),
        (authority["adapter"]["private_parent_path"], "authority private parent"),
        (authority["adapter"]["docker_root_resolved_path"],
         "authority adapter Docker root"),
    )
    for path, label in paths:
        canonical_absolute_path(path, label, live=False)


def _seed_artifact_path(recorded: object, name: str, derived: str) -> object:
    """Remap a recorded seed path that still names `name` onto `derived`.

    `seed.build_seed` records the ABSOLUTE path the artifact had in the tree it
    was frozen from, and `bundle.build_bundle` relocates a seed with a plain
    `shutil.copytree` that does not rewrite it.  So every bundle-installed seed
    records a directory it no longer lives in, and held to the literal string
    no relocated seed could ever satisfy publication-v3 — including the
    CoreShop and python-docx seeds that have already shipped.

    Remapping is safe because the recorded string is INERT TO IDENTITY.  The
    archive and the dump are read from `derived` and never from what the
    manifest says, and the bytes are then pinned three ways by digest: the seed
    manifest's own `workspace`/`database` digest, its `workspace_seed_digest` /
    `database_dump_digest`, and the runtime and identity copies of the same.
    Dropping a directory the reader never reads through changes nothing that a
    digest does not already decide.

    The basename is still required to match, because a workspace record naming
    something that is not a `workspace.tar` is a mixed-up document rather than
    a moved one, and that is worth refusing.  A recorded path that is missing
    or is not a string is returned untouched, so it still fails the caller's
    equality check.
    """
    if isinstance(recorded, str) and posixpath.basename(recorded) == name:
        return derived
    return recorded


def _verify_seed(reader: _LiveReader, runtime: dict, identity: dict) -> dict:
    from . import seed
    seed_dir = canonical_absolute_path(identity["seed_dir"], "runtime seed_dir")
    if runtime["seed_dir"] != seed_dir:
        raise _refuse("runtime and identity seed directories differ")
    expected_manifest_path = seed_dir + "/" + seed.SEED_MANIFEST
    seed_ref = _exact_keys(
        identity["seed_manifest"], ("path", "file_sha256"),
        "runtime identity seed manifest reference")
    if seed_ref["path"] != expected_manifest_path:
        raise _refuse("seed manifest path is not exactly <seed_dir>/seed.json")
    raw = _verify_raw_reference(reader, seed_ref, "seed manifest")
    if raw_sha256(raw) != runtime["seed_manifest_sha256"]:
        raise _refuse("runtime seed manifest SHA differs from identity/reference")
    document = _parse_json_object(raw, "seed manifest")
    if _integer(document.get("format"), "seed manifest format", minimum=1) \
            != seed.SEED_FORMAT:
        raise _refuse("seed manifest format is unsupported")
    seed_needs_db = runtime["needs_database"]
    if seed_needs_db:
        if "needs_database" in document \
                and document["needs_database"] is not True:
            raise _refuse(
                "database seed needs_database is present but not true")
    elif document.get("needs_database") is not False:
        raise _refuse("seed manifest is not exact no-database evidence")
    if document.get("seed_key") != runtime["seed_key"] \
            or document.get("seed_key") != identity["seed_key"]:
        raise _refuse("seed key differs across seed, runtime, and identity")
    workspace = document.get("workspace")
    if not isinstance(workspace, dict):
        raise _refuse("seed workspace record is not an object")
    workspace_path = seed_dir + "/" + seed.WORKSPACE_TAR
    recorded_workspace = _seed_artifact_path(
        workspace.get("path"), seed.WORKSPACE_TAR, workspace_path)
    if recorded_workspace != workspace_path:
        raise _refuse("seed workspace path does not resolve to "
                      "<seed_dir>/workspace.tar")
    built_from = document.get("built_from")
    if built_from == ".":
        document["built_from"] = seed_dir
    else:
        canonical_absolute_path(
            built_from, "seed manifest built_from", live=False)
    workspace_bytes = reader.read(workspace_path, "seed workspace archive")
    archive_digest = raw_sha256(workspace_bytes)
    if _integer(workspace.get("bytes"), "seed workspace.bytes") \
            != len(workspace_bytes):
        raise _refuse("seed workspace byte length differs")
    if workspace.get("digest") != archive_digest:
        raise _refuse("seed workspace archive digest does not recompute")
    if document.get("workspace_seed_digest") != archive_digest \
            or runtime["workspace_seed_digest"] != archive_digest \
            or identity["workspace_seed_digest"] != archive_digest:
        raise _refuse(
            "workspace digest differs across archive, seed, runtime, and identity")
    database = document.get("database")
    if not isinstance(database, dict):
        raise _refuse("seed database record is not an object")
    database_path = seed_dir + "/" + seed.DATABASE_SQL
    if seed_needs_db:
        recorded_database = _seed_artifact_path(
            database.get("path"), seed.DATABASE_SQL, database_path)
        if database.get("declared") == "no_database" \
                or recorded_database != database_path \
                or database.get("digest") != runtime["database_dump_digest"] \
                or document.get("database_dump_digest") \
                != runtime["database_dump_digest"]:
            raise _refuse(
                "seed database declaration differs from the runtime dump "
                "digest")
        dump_bytes = reader.read(database_path, "seed database dump")
        if raw_sha256(dump_bytes) != database["digest"]:
            raise _refuse("seed database dump digest does not recompute")
        if _integer(database.get("bytes"), "seed database.bytes") \
                != len(dump_bytes):
            raise _refuse("seed database byte length differs")
    else:
        if database.get("declared") != "no_database" \
                or database.get("digest") != "no_database" \
                or database.get("path") is not None \
                or _integer(database.get("bytes"), "seed database.bytes") != 0 \
                or document.get("database_dump_digest") != "no_database":
            raise _refuse("seed database declaration is not exact no_database")
        reader.require_absent(database_path, "no-database database.sql")
    return document


def _verify_runtime(reader: _LiveReader, runtime_reference: object) \
        -> _RuntimeContext:
    from .. import docker_authority as authority
    from . import worker
    from .validate import HARNESS_VERSION

    ref = _exact_keys(
        runtime_reference, ("path", "file_sha256", "identity"),
        "execution.runtime")
    runtime_path = canonical_absolute_path(ref["path"], "execution.runtime.path")
    _sha256(ref["file_sha256"], "execution.runtime.file_sha256")
    runtime_raw = reader.read(runtime_path, "worker runtime v3")
    if raw_sha256(runtime_raw) != ref["file_sha256"]:
        raise _refuse("worker runtime raw SHA-256 differs")
    runtime = _parse_json_object(runtime_raw, "worker runtime v3")
    if worker.worker_runtime_version(runtime) not in {"v3", "v4"}:
        raise _refuse("worker runtime is not exact authority-bound v3/v4")
    validate_json_schema(runtime, runtime["schema"], label="worker runtime")
    try:
        # JSON Schema is necessary but not a replacement for the published
        # runtime-v3 scalar/path rules (notably the seed-key control-byte
        # refusal).  Replay that existing offline shape check against the
        # exact bytes already captured by the stable reader.
        embedded_worker = worker._validate_worker_runtime_v3_shape(
            runtime, authority)
    except worker.WorkerRefused as exc:
        _raise_from(exc, "worker runtime v3")

    runtime_needs_db = runtime["needs_database"]
    identity_schema = (RUNTIME_IDENTITY_V2_SCHEMA if runtime_needs_db
                       else RUNTIME_IDENTITY_SCHEMA)
    identity = ref["identity"]
    _verify_digest(identity, label="worker runtime identity")
    if identity["schema"] != identity_schema:
        raise _refuse("worker runtime identity schema is unsupported")

    runtime_authority_ref = runtime["docker_execution_authority"]
    runtime_binding_ref = runtime["docker_execution_binding"]
    if not _same_json_value(
            identity["docker_execution_authority"], runtime_authority_ref):
        raise _refuse("runtime and identity authority references differ")
    if not _same_json_value(
            identity["docker_execution_binding"], runtime_binding_ref):
        raise _refuse("runtime and identity binding references differ")

    binding, _binding_raw = _verify_semantic_reference(
        reader, runtime_binding_ref, "Docker execution binding",
        expected_schema=authority.BINDING_SCHEMA,
        validator=authority.validate_binding_document)
    if worker.worker_runtime_version(runtime) == "v4":
        try:
            worker._validate_worker_memory(runtime["memory"], container_id=binding["container"]["id"])
        except worker.WorkerRefused as exc:
            _raise_from(exc, "worker memory")
    auth_validator = lambda value: authority.validate_authority_document(
        value, current_source=False)
    authority_doc, _authority_raw = _verify_semantic_reference(
        reader, runtime_authority_ref, "Docker execution authority",
        expected_schema=authority.AUTHORITY_SCHEMA, validator=auth_validator)
    _validate_authority_paths(authority_doc)
    _require_same_json(
        binding["authority"], runtime_authority_ref,
        "binding authority differs from runtime authority")
    pool = binding["pool"]
    try:
        authority.validate_pool_document(pool, verify_files=False)
    except authority.DockerAuthorityRefused as exc:
        _raise_from(exc, "Docker execution pool")
    for entry in pool["workers"]:
        canonical_absolute_path(
            entry["worker_spec_path"], "pool WorkerSpec path")

    daemon_digest = authority_doc["daemon"]["fingerprint_sha256"]
    if identity["docker_daemon_fingerprint_sha256"] != daemon_digest:
        raise _refuse("identity daemon fingerprint differs from authority")
    if identity["docker_execution_pool_digest"] != pool["digest"]:
        raise _refuse("identity execution-pool digest differs from binding")
    index = _integer(identity["worker_index"], "runtime identity worker_index")
    if not _same_json_value(index, binding["worker_index"]) \
            or index >= len(pool["workers"]):
        raise _refuse("runtime identity selects another binding worker")
    entry = pool["workers"][index]
    if identity["worker_spec_path"] != entry["worker_spec_path"]:
        raise _refuse("runtime identity WorkerSpec path differs from pool entry")
    spec_path = canonical_absolute_path(
        identity["worker_spec_path"], "runtime identity WorkerSpec path")
    expected_runtime_path = canonical_absolute_path(
        worker.runtime_attestation_path(spec_path),
        "WorkerSpec-derived runtime attestation path")
    if runtime_path != expected_runtime_path:
        raise _refuse(
            "execution runtime path is not the WorkerSpec runtime attestation")
    spec_raw = reader.read(spec_path, "WorkerSpec")
    spec_hash = raw_sha256(spec_raw)
    if identity["worker_spec_sha256"] != spec_hash \
            or runtime["worker_spec_sha256"] != spec_hash \
            or binding["worker_spec_sha256"] != spec_hash \
            or entry["worker_spec_sha256"] != spec_hash:
        raise _refuse(
            "WorkerSpec SHA differs across file, identity, runtime, binding, or pool")
    spec_document = _parse_json_object(spec_raw, "WorkerSpec")
    try:
        spec = worker.WorkerSpec.from_json(spec_document)
    except worker.WorkerRefused as exc:
        _raise_from(exc, "WorkerSpec")
    if not _same_json_value(spec_document, runtime["worker"]):
        raise _refuse("runtime embeds another WorkerSpec than the bound file")
    if not _same_json_value(embedded_worker.to_json(), spec_document):
        raise _refuse("runtime-v3 shape check selected another WorkerSpec")
    for field in ("workspace", "env_file", "out_path", "artifacts_root"):
        canonical_absolute_path(
            getattr(spec, field), f"WorkerSpec.{field}")
    canonical_absolute_path(spec.workdir, "WorkerSpec.workdir", live=False)
    if spec.index != index or spec.container != entry["container_name"] \
            or spec.container != binding["container"]["name"]:
        raise _refuse("WorkerSpec index/container differs from binding/pool")
    image = binding["container"]["image_id"]
    if identity["container_image_digest"] != image \
            or runtime["container_image_digest"] != image:
        raise _refuse("container image differs across runtime identity and binding")

    if identity["needs_database"] is not runtime_needs_db \
            or identity["database_dump_digest"] \
            != runtime["database_dump_digest"]:
        raise _refuse("database declarations disagree in the runtime chain")
    if runtime_needs_db:
        if not spec.schema or not spec.credential \
                or pool["database"] is None \
                or not isinstance(pool["network"], dict) \
                or pool["network"].get("mode") != "dedicated_internal" \
                or not pool["network"].get("name"):
            raise _refuse(
                "database declarations disagree in the runtime chain")
    elif spec.schema != "" or spec.credential != "" \
            or pool["database"] is not None \
            or pool["network"] != {"mode": "none", "name": "none"}:
        raise _refuse("no-database declarations disagree in the runtime chain")

    seed_document = _verify_seed(reader, runtime, identity)
    # Keep the same protected-evidence inventory and two-way realpath
    # containment rule as runtime-v3 preflight, without pretending that this
    # single receipt carries every other worker runtime needed to call the
    # complete-pool preflight API.  This is wholly offline.
    loaded = [{
        "spec_path": spec_path,
        "runtime_path": runtime_path,
        "runtime": runtime,
        "binding": binding,
        "authority": authority_doc,
        "worker": spec,
    }]
    protected = (*worker._runtime_protected_evidence_paths(loaded),
                 spec.env_file, spec.out_path, spec.artifacts_root)
    _require_workspace_separation(
        spec.workspace, protected, "runtime protected evidence")
    recorded_harness = identity["harness"]
    if not _same_json_value(runtime["harness_version"], HARNESS_VERSION) \
            or not _same_json_value(recorded_harness["version"],
                                    HARNESS_VERSION):
        raise _refuse("runtime harness version differs from this harness")
    if recorded_harness["git_commit"] is not None \
            and _COMMIT_RE.fullmatch(recorded_harness["git_commit"]) is None:
        raise _refuse("recorded harness commit is malformed")
    _sha256(recorded_harness["source_sha256"],
            "worker runtime identity harness.source_sha256")
    disclose_harness_drift(recorded_harness, _stable_harness_identity(reader))

    derived_identity = {
        "schema": identity_schema,
        "docker_execution_authority": runtime_authority_ref,
        "docker_execution_binding": runtime_binding_ref,
        "docker_daemon_fingerprint_sha256": daemon_digest,
        "docker_execution_pool_digest": pool["digest"],
        "worker_index": index,
        "worker_spec_path": entry["worker_spec_path"],
        "worker_spec_sha256": spec_hash,
        "container_image_digest": image,
        "seed_dir": runtime["seed_dir"],
        "seed_manifest": {
            "path": runtime["seed_dir"] + "/seed.json",
            "file_sha256": runtime["seed_manifest_sha256"],
        },
        "seed_key": runtime["seed_key"],
        "workspace_seed_digest": runtime["workspace_seed_digest"],
        "database_dump_digest": runtime["database_dump_digest"],
        "needs_database": runtime_needs_db,
        "harness": recorded_harness,
        "digest": "0" * 64,
    }
    derived_identity["digest"] = semantic_digest(derived_identity)
    if not _same_json_value(identity, derived_identity):
        changed = sorted(
            key for key in derived_identity
            if not _same_json_value(identity.get(key), derived_identity[key]))
        raise _refuse(f"worker runtime identity projection differs; changed={changed}")
    return _RuntimeContext(
        runtime=runtime, runtime_raw=runtime_raw, identity=identity,
        authority=authority_doc, binding=binding, pool=pool,
        worker_document=spec_document, worker=spec, seed=seed_document,
        harness=recorded_harness)


# --------------------------------------------------------------- plan input
def _raw_reference_bytes(reader: _LiveReader, reference: object,
                         label: str) -> tuple[str, bytes]:
    ref = _exact_keys(reference, ("path", "file_sha256"), label + " reference")
    path = canonical_absolute_path(ref["path"], label + " reference.path")
    _sha256(ref["file_sha256"], label + " reference.file_sha256")
    raw = reader.read(path, label)
    if raw_sha256(raw) != ref["file_sha256"]:
        raise _refuse(f"{label} raw SHA-256 does not match its reference")
    return path, raw


def _verify_campaign_reference(reader: _LiveReader, reference: object) \
        -> tuple[dict, str]:
    from . import campaign
    ref = _exact_keys(
        reference,
        ("path", "file_sha256", "campaign_digest", "semantic_digest"),
        "campaign reference")
    path = canonical_absolute_path(ref["path"], "campaign reference.path")
    _sha256(ref["file_sha256"], "campaign reference.file_sha256")
    _hex16(ref["campaign_digest"], "campaign reference.campaign_digest")
    _sha256(ref["semantic_digest"], "campaign reference.semantic_digest")
    raw = reader.read(path, "generation campaign v2")
    if raw_sha256(raw) != ref["file_sha256"]:
        raise _refuse("campaign raw SHA-256 does not match its reference")
    document = _parse_json_object(raw, "generation campaign v2")
    if document.get("schema") != campaign.GENERATION_CAMPAIGN_SCHEMA:
        raise _refuse("campaign is not exact r2t.generation-campaign/v2")
    try:
        campaign._validate_fingerprint(document)
        old_digest = campaign.campaign_digest(document)
    except (Exception, SystemExit) as exc:
        _raise_from(exc, "generation campaign v2")
    if old_digest != ref["campaign_digest"]:
        raise _refuse("campaign compatibility digest does not recompute")
    if semantic_digest(document) != ref["semantic_digest"]:
        raise _refuse("campaign semantic digest does not recompute")
    return document, path


def _verify_agent_runtime_reference(reader: _LiveReader, reference: object) \
        -> tuple[dict, str]:
    from . import campaign
    ref = _exact_keys(
        reference, ("path", "file_sha256", "agent_runtime_sha256"),
        "campaign agent-runtime reference")
    path = canonical_absolute_path(
        ref["path"], "campaign agent-runtime reference.path")
    _sha256(ref["file_sha256"],
            "campaign agent-runtime reference.file_sha256")
    _sha256(ref["agent_runtime_sha256"],
            "campaign agent-runtime reference.agent_runtime_sha256")
    raw = reader.read(path, "campaign agent-runtime v2")
    if raw_sha256(raw) != ref["file_sha256"]:
        raise _refuse("campaign agent-runtime raw SHA-256 differs")
    document = _parse_json_object(raw, "campaign agent-runtime v2")
    try:
        digest = campaign.agent_runtime_digest(document)
    except (Exception, SystemExit) as exc:
        _raise_from(exc, "campaign agent-runtime v2")
    if digest != ref["agent_runtime_sha256"]:
        raise _refuse("campaign agent-runtime semantic hash differs")
    return document, path


def _verify_boundary_profile(
        reader: _LiveReader, boundary_reference: object,
        profile_reference: object):
    from ..core import boundary as boundary_module
    from ..data import profile as profile_module
    boundary_path, boundary_raw = _raw_reference_bytes(
        reader, boundary_reference, "boundary")
    profile_path, profile_raw = _raw_reference_bytes(
        reader, profile_reference, "resolved profile")
    boundary_value = _parse_yaml(boundary_raw, "boundary")
    profile_value = _parse_yaml(profile_raw, "resolved profile")
    if not isinstance(boundary_value, dict) or not isinstance(profile_value, dict):
        raise _refuse("boundary and resolved profile must be YAML mappings")
    try:
        boundary = boundary_module.load_boundary(boundary_path)
        profile = profile_module.load_profile(profile_path)
    except (Exception, SystemExit) as exc:
        _raise_from(exc, "boundary/profile validation")
    if boundary.raw != boundary_value or profile.raw != profile_value:
        raise _refuse("boundary/profile parsed snapshot differs from stable bytes")
    if canonical_absolute_path(
            profile.boundary_path, "resolved profile boundary path") \
            != boundary_path:
        raise _refuse("resolved profile names another boundary file")
    from ..core.paths import DataPath as _DataPath
    if not isinstance(boundary.repo_root, _DataPath):
        canonical_absolute_path(boundary.repo_root,
                                "boundary repository root", live=False)
    # A DataPath is the dataset-1.2 boundary's portable data-root-relative
    # default; its resolution belongs to the executing operator and is not
    # part of the validated bytes.
    if profile.project != boundary.project:
        raise _refuse("resolved profile and boundary name different projects")
    if profile.framework not in {"behat", "behave", "cucumber"}:
        raise _refuse("resolved profile framework is not an admitted stack")
    # The database posture is NOT asserted here.  This function resolves the
    # profile/boundary pair and has no runtime to join against; the posture is
    # cross-checked where both sides exist -- `_verify_runtime` (identity vs
    # runtime) and the campaign join (campaign + profile vs runtime).
    return boundary, profile, boundary_path, profile_path, boundary_raw


def _verify_protocol_reference(reader: _LiveReader, reference: object,
                               campaign_document: dict, profile):
    # The file half of the protocol -- validation and the digest -- which is
    # benchmark-owned; a fixture receipt's plan cites a recipe too.
    from . import protocol_file as protocol
    expected_version = campaign_document["protocol_version"]
    expected_digest = campaign_document["protocol_digest"]
    if reference is None:
        if expected_version is not None or expected_digest is not None:
            raise _refuse("campaign protocol identity has no plan reference")
        return None
    if expected_version is None or expected_digest is None:
        raise _refuse("plan protocol reference contradicts protocol-less campaign")
    path, raw = _raw_reference_bytes(reader, reference, "protocol")
    document = _parse_yaml(raw, "protocol")
    try:
        protocol.validate(document, path)
        digest = protocol.protocol_digest(document)
    except (Exception, SystemExit) as exc:
        _raise_from(exc, "protocol validation")
    if not _same_json_value(document["protocol_version"], expected_version) \
            or digest != expected_digest:
        raise _refuse("protocol version/digest differs from the campaign")
    if protocol.project_deviations(document, profile.project):
        raise _refuse("protocol prompt project differs from resolved profile")
    prompt_profile = document.get("prompt_profile")
    if not isinstance(prompt_profile, dict) \
            or not isinstance(prompt_profile.get("prompt_digest"), dict) \
            or any(prompt_profile["prompt_digest"].get(key) != value
                   for key, value in profile.prompt_digest.items()):
        raise _refuse("protocol prompt digests differ from resolved profile")
    copied = prompt_profile["prompt_digest"]
    bounded_keys = set(copied) & {"c3_bounded", "c3_bounded_superseded"}
    if bounded_keys:
        from .adapters import CANONICAL_TRIALS
        from ..data.prompt import prompt_digests
        bounded = prompt_digests(profile, CANONICAL_TRIALS)["c3"]
        if any(copied[key] != bounded for key in bounded_keys):
            raise _refuse(
                "protocol bounded prompt digest differs from resolved profile")
    return document


def _selection_ids(selection: object, source_ids: list[str], *,
                   validation_order: bool) -> list[str]:
    selected = _exact_keys(
        selection, ("limit", "requested_item_ids"), "plan selection")
    requested = selected["requested_item_ids"]
    if requested is not None:
        if not isinstance(requested, list) or any(
                not isinstance(item_id, str) or not item_id
                for item_id in requested):
            raise _refuse("requested item IDs are not nonempty strings")
        if requested != sorted(requested) or len(requested) != len(set(requested)):
            raise _refuse("requested item IDs are not sorted and unique")
        missing = sorted(set(requested) - set(source_ids))
        if missing:
            raise _refuse(f"requested item IDs are absent from inputs: {missing}")
    limit = selected["limit"]
    if limit is not None:
        limit = _integer(limit, "plan selection.limit", minimum=1)
    if validation_order:
        out = source_ids[:limit] if limit is not None else list(source_ids)
        if requested is not None:
            wanted = set(requested)
            out = [item_id for item_id in out if item_id in wanted]
    else:
        wanted = None if requested is None else set(requested)
        out = [item_id for item_id in source_ids
               if wanted is None or item_id in wanted]
    return out


def _verify_workset(workset: object, item_ids: list[str], label: str) -> None:
    value = _exact_keys(
        workset, ("item_count", "ordered_item_ids_digest"), label)
    count = _integer(value["item_count"], label + ".item_count")
    digest = _sha256(
        value["ordered_item_ids_digest"],
        label + ".ordered_item_ids_digest")
    if count != len(item_ids) or digest != ordered_item_ids_digest(item_ids):
        raise _refuse(f"{label} does not equal the reconstructed ordered IDs")


def _closure_records(raw: bytes, label: str) -> tuple[list[dict], dict[str, dict]]:
    value = loads_exact_json(raw, label=label)
    if not isinstance(value, list):
        raise _refuse(f"{label} is not a JSON array")
    by_id = {}
    for index, row in enumerate(value):
        if not isinstance(row, dict):
            raise _refuse(f"{label}[{index}] is not an object")
        item_id = _nonempty(row.get("item_id"), f"{label}[{index}].item_id")
        if item_id in by_id:
            raise _refuse(f"{label} repeats item ID {item_id!r}")
        files = row.get("files")
        if not isinstance(files, list) \
                or any(not isinstance(item, str) or not item for item in files):
            raise _refuse(f"{label}[{index}].files is not a string list")
        if len(files) != len(set(files)):
            raise _refuse(f"{label}[{index}].files contains duplicates")
        _nonempty(row.get("feature_file"),
                  f"{label}[{index}].feature_file")
        by_id[item_id] = row
    return value, by_id


def _closure_relative_path(value: str, boundary_root: str, label: str) -> str:
    # The v1 plan records canonical relative identities.  Historical
    # absolute closure spellings are readable elsewhere but are not silently
    # normalized into publication evidence.
    del boundary_root
    return _safe_relative(value, label)


def _input_file_map(reader: _LiveReader, value: object, label: str) \
        -> dict[tuple[str, str], dict]:
    if not isinstance(value, list):
        raise _refuse(f"{label} is not a list")
    keys = []
    out = {}
    for index, item in enumerate(value):
        entry = _exact_keys(
            item, ("role", "logical_path", "path", "byte_length",
                   "file_sha256"), f"{label}[{index}]")
        role = _nonempty(entry["role"], f"{label}[{index}].role")
        logical = _safe_relative(
            entry["logical_path"], f"{label}[{index}].logical_path")
        path = canonical_absolute_path(
            entry["path"], f"{label}[{index}].path")
        length = _integer(
            entry["byte_length"], f"{label}[{index}].byte_length")
        digest = _sha256(
            entry["file_sha256"], f"{label}[{index}].file_sha256")
        key = (role, logical)
        if key in out:
            raise _refuse(f"{label} repeats role/logical identity {key!r}")
        raw = reader.read(path, f"adapter input {role}:{logical}")
        if len(raw) != length or raw_sha256(raw) != digest:
            raise _refuse(f"adapter input bytes differ for {role}:{logical}")
        out[key] = entry
        keys.append((role, logical, path))
    if keys != sorted(keys):
        raise _refuse(f"{label} is not sorted by role/logical/path")
    return out


#: The string-list fields of the strip manifest, in `save` order.  Named
#: separately from the scalar/object ones because every one of them is
#: validated the same way and the list is walked twice below.
_STRIP_MANIFEST_LISTS = (
    "moved", "moved_config", "patched", "installed",
    "substrate_roots", "substrate_volatile", "bytecode_roots", "build_roots")


def _strip_manifest_fields() -> tuple:
    """Every key `repo.StripManifest.save` writes, and nothing else."""
    return ("repo_root", "gold_root", "boundary_version", "digests") \
        + _STRIP_MANIFEST_LISTS


def _supply_legacy_strip_fields(
        document: object, project: Optional[str]) -> object:
    """Supply the two shipped pre-current manifest shapes, and only those."""
    if not isinstance(document, dict):
        return document
    missing = set(_strip_manifest_fields()) - set(document)
    if project == "python-docx" and missing == {"build_roots"}:
        document["build_roots"] = []
    elif project == "coreshop" and missing == {
            "substrate_roots", "substrate_volatile",
            "bytecode_roots", "build_roots"}:
        document.update({name: [] for name in missing})
    return document


def _resolved_strip_gold_root(recorded: str, installed: str) -> str:
    """Resolve a relocated build-tree gold path onto its installed directory."""
    if posixpath.basename(recorded) == posixpath.basename(installed):
        return installed
    return recorded


def _verify_strip_substrate(document: dict, boundary) -> None:
    """Join a released gold's strip to THIS boundary by structure, not path.

    What this replaces.  The join used to be
    `strip_manifest.repo_root == boundary.repo_root`, an equality between two
    absolute path strings.  It was vacuous where it mattered and unsatisfiable
    by every real pair in this program.  A manifest's `repo_root` records the
    workspace the strip RAN in -- a preparation tree -- while a boundary's
    `repo_root` is a nominal identity (`/runtime/composed/algorand-sdk`) or a
    corpus checkout, and a publication run uses NEITHER: `runner`
    `_install_publication_harness_context` overwrites the boundary root with
    `bundle.runtime.worker.workspace` (runner.py:3040) and rebuilds the
    manifest through `_publication_manifest_object(..., workspace, gold)`
    (defined runner.py:1819, called at runner.py:3041), which carries every
    manifest field through verbatim EXCEPT `repo_root`.  So the equality
    constrained a root no run ever reads, and the gold bytes it was reached
    for are already digest-bound by the release and by this plan's own input
    projection.

    What is checked instead is the fact that equality was groping at: that
    this gold's strip was taken against THIS project's declared substrate.
    Every answer-code path in `moved` must classify `removable` under the
    boundary now in force.  A gold from another project fails at once,
    because its glue paths classify `production` here; that is the honest
    cross-project guard, and unlike the old one it survives the rebase.

    `moved_config` has a different job: it records lifecycle/configuration
    files removed or replaced while preparing the harness.  Its string-list
    and safe-relative-path shape is checked by `_strip_manifest`; it is not
    part of this structural boundary join.

    `moved` must be nonempty.  An empty list would satisfy the loop
    vacuously and let any boundary accept any gold -- the hole the
    empty-manifest probe in `result_ledger_i2_selftest` holds open.
    """
    from ..core.boundary import REMOVABLE

    if not document["moved"]:
        raise _refuse(
            "strip manifest moved no answer code; a gold whose strip removed "
            "nothing cannot be joined to a boundary")
    for relative in document["moved"]:
        if boundary.classify(relative) != REMOVABLE:
            raise _refuse(
                "strip manifest moved path is not removable under this "
                f"boundary: {relative}")


def _strip_manifest(reader: _LiveReader, entry: dict, boundary,
                    workspace: Optional[str] = None) -> dict:
    raw = reader.read(entry["path"], "harness strip manifest")
    document = _parse_json_object(raw, "harness strip manifest")
    # Exactly the keys `repo.StripManifest.save` writes, and no others: the
    # tuple is spelled out rather than derived so that a field appearing on
    # disk is a reviewed change to this contract.  `_strip_manifest_fields`
    # is what the selftest holds the two sides to, because a producer that
    # gains a key its reader refuses is a publication-time failure the rest
    # of the suite never reaches.
    document = _supply_legacy_strip_fields(
        document, getattr(boundary, "project", None))
    _exact_keys(document, _strip_manifest_fields(), "harness strip manifest")
    installed_gold_root = os.path.dirname(entry["path"])
    if document["gold_root"] == ".":
        gold_root = installed_gold_root
    else:
        recorded_gold_root = canonical_absolute_path(
            document["gold_root"], "strip manifest gold_root", live=False)
        gold_root = _resolved_strip_gold_root(
            recorded_gold_root, installed_gold_root)
    document["gold_root"] = gold_root
    # `repo_root` is PROVENANCE -- where the strip ran -- so it is held to
    # its shape and nothing more.  It is deliberately NOT equated with the
    # boundary's root; `_verify_strip_substrate` below carries the join, and
    # its docstring records why the old equality was vacuous.
    if document["repo_root"] == ".":
        if workspace is None:
            raise _refuse("portable strip manifest has no worker workspace")
        document["repo_root"] = canonical_absolute_path(
            workspace, "resolved strip manifest repo_root",
            live=False)
    else:
        canonical_absolute_path(
            document["repo_root"], "strip manifest repo_root", live=False)
    manifest_boundary_version = _integer(
        document["boundary_version"],
        "strip manifest boundary_version", minimum=1)
    boundary_version = _integer(
        boundary.version, "resolved boundary version", minimum=1)
    if not _same_json_value(manifest_boundary_version, boundary_version):
        raise _refuse("strip manifest boundary version differs")
    for key in _STRIP_MANIFEST_LISTS:
        values = document[key]
        if not isinstance(values, list) or any(
                not isinstance(item, str) for item in values):
            raise _refuse(f"strip manifest {key} is not a string list")
        for item in values:
            _safe_relative(item, f"strip manifest {key} path")
    _verify_strip_substrate(document, boundary)
    digests = document["digests"]
    if not isinstance(digests, dict):
        raise _refuse("strip manifest digests is not an object")
    for path, digest in digests.items():
        _safe_relative(path, "strip manifest digest path")
        _sha256(digest, "strip manifest substrate digest")
    expected_path = gold_root + "/strip_manifest.json"
    if entry["path"] != expected_path:
        raise _refuse("strip manifest is not exactly <gold_root>/strip_manifest.json")
    return document


def _expected_feature_paths(rows: list[dict], workspace: str,
                            project: str) -> dict:
    from ..java.algorand import runtime_feature_path
    expected = {}
    for row in rows:
        provenance = row.get("provenance")
        if not isinstance(provenance, dict):
            raise _refuse("release row has no provenance object")
        relative = _safe_relative(
            provenance.get("file_path"), "release provenance.feature path")
        expected[("harness_feature", relative)] = _contained_path(
            workspace, runtime_feature_path(project, relative),
            "harness feature")
    return expected


def _verify_adapter(
        reader: _LiveReader, invocation: dict, selected_rows: list[dict],
        all_release_ids: list[str], release_path: str, runtime: _RuntimeContext,
        boundary, profile, *,
        agent_kind: Optional[str] = None) -> tuple[dict, dict, dict, dict]:
    adapter = invocation["adapter"]
    kind = adapter["kind"]
    if agent_kind is None:
        if kind in _reserved_adapter_kinds():
            raise _refuse(f"adapter kind {kind!r} is reserved and not admitted")
        if kind not in _ADMITTED_ADAPTER_NAMES:
            raise _refuse(f"adapter kind {kind!r} is unsupported")
        if adapter["name"] != _ADMITTED_ADAPTER_NAMES[kind]:
            raise _refuse(
                "adapter public name does not match its admitted kind")
        if adapter["secret_inputs"] != []:
            raise _refuse("fixture adapter secret_inputs must be exactly empty")
    else:
        from ..confined import result_ledger_v2 as agent
        if kind != agent_kind:
            raise _refuse("adapter kind differs from the admitted agent kind")
        try:
            agent._refuse_non_agent_producer(adapter)
        except agent.ResultLedgerV2Refused as exc:
            raise _refuse(str(exc)) from exc
    files = _input_file_map(reader, adapter["files"], "adapter.files")

    common_config = ({"harness_autowirable_types_present"}
                     if profile.framework == "behat" else set())
    if agent_kind is not None:
        # Section 4's set: the eight agent names, plus the Behat-only ninth
        # under exactly the same profile authority v1 uses.  The agent module
        # remains the authority on what each value must EQUAL, and closes the
        # same set again; this call exists so a Behat agent plan that omits
        # the ninth name refuses here rather than reaching the common Behat
        # branch below with a missing key.
        from ..confined import result_ledger_v2 as agent
        config = _named_canonical_values(
            adapter["public_configuration"], "adapter.public_configuration",
            expected_names=set(agent.PUBLIC_CONFIGURATION_NAMES)
            | common_config)
    else:
        kind_config = ({"gold_root"} if kind in {"gold", "stripped_gold"}
                       else set())
        config = _named_canonical_values(
            adapter["public_configuration"], "adapter.public_configuration",
            expected_names=common_config | kind_config)
    if kind in {"gold", "stripped_gold"}:
        canonical_absolute_path(config["gold_root"], "adapter gold_root")

    strip_key = ("harness_strip_manifest", "strip_manifest.json")
    if strip_key not in files:
        raise _refuse("adapter omits the required harness strip manifest")
    strip = _strip_manifest(
        reader, files[strip_key], boundary, runtime.worker.workspace)
    gold_root = strip["gold_root"]
    if kind in {"gold", "stripped_gold"} \
            and config["gold_root"] != gold_root:
        raise _refuse("adapter gold_root differs from strip manifest")

    expected = {strip_key: gold_root + "/strip_manifest.json"}
    expected.update(_expected_feature_paths(
        selected_rows, runtime.worker.workspace, boundary.project))
    artifacts_root = canonical_absolute_path(
        runtime.worker.artifacts_root, "WorkerSpec artifacts_root")
    if profile.framework == "behat":
        present = config["harness_autowirable_types_present"]
        if not isinstance(present, bool):
            raise _refuse("harness_autowirable_types_present is not Boolean")
        expected[("harness_alias_table", "alias_table.json")] = (
            artifacts_root + "/alias_table.json")
        optional_path = artifacts_root + "/autowirable_types.json"
        if present:
            expected[("harness_autowirable_types",
                      "autowirable_types.json")] = optional_path
        else:
            reader.require_absent(optional_path, "optional autowirable types")

    selected_ids = [row["item_id"] for row in selected_rows]
    if kind == "gold":
        manifest_path = os.path.dirname(release_path) + "/gold/manifest.json"
        expected[("release_gold_manifest", "gold/manifest.json")] = manifest_path
        manifest_entry = files.get(("release_gold_manifest", "gold/manifest.json"))
        if manifest_entry is None:
            raise _refuse("gold adapter omits the release gold manifest")
        manifest = _parse_json_object(
            reader.read(manifest_path, "release gold manifest"),
            "release gold manifest")
        if set(manifest) != set(all_release_ids):
            raise _refuse("release gold manifest membership differs from release")
        source_paths = set()
        for item_id in selected_ids:
            name = _safe_relative(
                manifest[item_id], "release gold sidecar name")
            if "/" in name:
                raise _refuse("release gold sidecar name is not a basename")
            logical = "gold/" + name
            sidecar_path = os.path.dirname(release_path) + "/gold/" + name
            expected[("release_gold_record", logical)] = sidecar_path
            entry = files.get(("release_gold_record", logical))
            if entry is None:
                raise _refuse(f"gold adapter omits sidecar for {item_id}")
            sidecar = _parse_json_object(
                reader.read(sidecar_path, "release gold record"),
                "release gold record")
            _exact_keys(
                sidecar,
                ("item_id", "files", "di_fragment", "context_classes",
                 "feature_file", "scenario_line"),
                "release gold record")
            if sidecar["item_id"] != item_id \
                    or not isinstance(sidecar["files"], list):
                raise _refuse("release gold record identity/closure is invalid")
            for value in sidecar["files"]:
                relative = _closure_relative_path(
                    value, boundary.repo_root, "release gold source")
                source_paths.add(relative)
        for relative in sorted(source_paths):
            expected[("gold_source", relative)] = _contained_path(
                gold_root, relative, "gold source")

    if kind in {"stripped_gold", "stub"}:
        closure_path = artifacts_root + "/closures.json"
        expected[("fixture_closures", "closures.json")] = closure_path
        closure_entry = files.get(("fixture_closures", "closures.json"))
        if closure_entry is None:
            raise _refuse("adapter omits fixture closures")
        _all_closures, by_id = _closure_records(
            reader.read(closure_path, "fixture closures"), "fixture closures")
        missing = sorted(set(selected_ids) - set(by_id))
        if missing:
            raise _refuse(f"fixture closures omit selected IDs: {missing}")
        if kind == "stripped_gold":
            source_paths = {
                _closure_relative_path(value, boundary.repo_root,
                                       "stripped-gold source")
                for item_id in selected_ids
                for value in by_id[item_id]["files"]
            }
            for relative in sorted(source_paths):
                expected[("gold_source", relative)] = _contained_path(
                    gold_root, relative, "gold source")

    if agent_kind is not None:
        from ..confined import result_ledger_v2 as agent
        try:
            expected.update(agent.agent_expected_inputs(agent_kind, files))
        except agent.ResultLedgerV2Refused as exc:
            raise _refuse(str(exc)) from exc

    actual_projection = {key: entry["path"] for key, entry in files.items()}
    if actual_projection != expected:
        missing = sorted(set(expected) - set(actual_projection))
        extra = sorted(set(actual_projection) - set(expected))
        wrong = sorted(key for key in set(expected) & set(actual_projection)
                       if expected[key] != actual_projection[key])
        raise _refuse(
            "adapter file closure differs; "
            f"missing={missing}, extra={extra}, wrong_paths={wrong}")
    _require_workspace_separation(
        runtime.worker.workspace,
        [entry["path"] for (role, _logical), entry in files.items()
         if role != "harness_feature"],
        "coordinator adapter input")
    return config, strip, files, expected


@dataclass
class _RunPlanContext:
    item_ids: list[str]
    release_rows: list[dict]
    selected_rows: list[dict]
    campaign: dict
    campaign_path: str
    agent_runtime: dict
    boundary: object
    profile: object
    protocol: Optional[dict]
    stamp: dict
    adapter_config: dict
    adapter_files: dict
    adapter_expected_paths: dict
    strip_document: dict
    #: `None` for a fixture plan; section 4's verified agent projection for
    #: an agent plan, so a checkpoint and a receipt close the same document.
    agent_adapter: Optional[dict] = None


def _verify_run_plan(reader: _LiveReader, plan: dict,
                     runtime: _RuntimeContext, *,
                     agent_kind: Optional[str] = None) -> _RunPlanContext:
    from . import campaign as campaign_module
    if plan["schema"] != RUN_PLAN_SCHEMA:
        raise _refuse("run plan schema is unsupported")
    _verify_digest(plan, label="run plan")
    if plan["invocation"]["schema"] != RUN_INVOCATION_SCHEMA:
        raise _refuse("run invocation schema is unsupported")
    if plan["invocation_digest"] != domain_digest(
            RUN_INVOCATION_SCHEMA, plan["invocation"]):
        raise _refuse("run invocation digest does not recompute")
    canonical_absolute_path(
        plan["worker_manifest_path"], "run plan worker_manifest_path")

    campaign, campaign_path = _verify_campaign_reference(
        reader, plan["campaign"])
    agent_runtime, agent_runtime_path = _verify_agent_runtime_reference(
        reader, plan["campaign_agent_runtime"])
    if agent_runtime_path != campaign_path + ".agent_runtime.json":
        raise _refuse(
            "campaign agent-runtime path is not the campaign companion")
    if campaign["agent_runtime_sha256"] \
            != plan["campaign_agent_runtime"]["agent_runtime_sha256"]:
        raise _refuse("campaign names another agent-runtime digest")
    if campaign["network_semantics"] != agent_runtime["network_semantics"]:
        raise _refuse("campaign and agent-runtime network semantics differ")

    release_path, release_raw = _raw_reference_bytes(
        reader, plan["release"], "release")
    release_rows = _json_lines(release_raw, "release")
    release_ids = []
    for index, row in enumerate(release_rows):
        item_id = _nonempty(row.get("item_id"), f"release[{index}].item_id")
        if item_id in release_ids:
            raise _refuse(f"release repeats item ID {item_id!r}")
        release_ids.append(item_id)

    boundary, profile, boundary_path, profile_path, boundary_raw = (
        _verify_boundary_profile(
            reader, plan["boundary"], plan["profile"]))
    for row in release_rows:
        for field in ("project", "language", "framework"):
            if row.get(field) != getattr(profile, field):
                raise _refuse(
                    f"release row {row['item_id']} {field} differs from profile")
    if campaign["config_digest"] != raw_sha256(boundary_raw)[:16]:
        raise _refuse("campaign config digest differs from boundary bytes")
    protocol = _verify_protocol_reference(
        reader, plan["protocol"], campaign, profile)

    index = _integer(plan["shard_index"], "run plan shard_index")
    count = _integer(plan["shard_count"], "run plan shard_count", minimum=1)
    if index >= count or index != runtime.identity["worker_index"]:
        raise _refuse("run plan shard index differs from runtime worker")
    if not _same_json_value(count, campaign["k_workers"]) \
            or count != len(runtime.pool["workers"]):
        raise _refuse("run shard count differs from campaign or complete pool")
    if plan["shard_rule"] != campaign["shard_rule"]:
        raise _refuse("run plan and campaign shard rules differ")
    rule = plan["shard_rule"]
    selected_ids = _selection_ids(
        plan["invocation"]["selection"], release_ids,
        validation_order=False)
    if rule == campaign_module.SHARD_RULE:
        selected_ids = [item_id for item_id in selected_ids
                        if campaign_module.shard_of(item_id, count) == index]
        limit = plan["invocation"]["selection"]["limit"]
        if limit is not None:
            selected_ids = selected_ids[:limit]
    elif rule == campaign_module.POSITIONAL_SHARD_RULE:
        if agent_kind is None or protocol is None \
                or protocol["protocol_version"] not in {5, 6, 7, 8}:
            raise _refuse(
                "positional shards are admitted only for Slice-3 "
                "protocol (v5-v8) agent producers")
        if count != 4 \
                or plan["invocation"]["selection"] != {
                    "limit": None, "requested_item_ids": None} \
                or selected_ids != release_ids:
            raise _refuse(
                "Slice-3 positional shards require K=4 and the complete "
                "ordered release without another selector")
        selected_ids = campaign_module.assign_ordered_shards(
            release_ids, count)[index]
    else:
        raise _refuse("run shard rule is unsupported")
    _verify_workset(plan["workset"], selected_ids, "run plan workset")
    by_id = {row["item_id"]: row for row in release_rows}
    selected_rows = [by_id[item_id] for item_id in selected_ids]

    adapter_config, strip, adapter_files, adapter_expected_paths = _verify_adapter(
        reader, plan["invocation"], selected_rows, release_ids, release_path,
        runtime, boundary, profile, agent_kind=agent_kind)
    stamp = _named_canonical_values(
        plan["invocation"]["effective_run_stamp"],
        "run effective stamp", expected_names=set(RUN_STAMP_NAMES))
    if agent_kind is None:
        if campaign["agent_system"] is not None \
                or campaign["model"] is not None:
            raise _refuse(
                "admitted fixture campaign carries model/agent identity")
        agent_expected = {}
    else:
        from ..confined import result_ledger_v2 as agent
        if protocol is None:
            raise _refuse("an agent run plan carries no protocol reference")
        model = _nonempty(campaign["model"], "agent campaign model")
        if campaign["agent_system"] != agent_kind:
            raise _refuse("agent campaign agent_system differs from the plan")
        try:
            budget, stamped_iterations = agent.agent_budget(
                agent_kind, protocol)
        except agent.ResultLedgerV2Refused as exc:
            raise _refuse(str(exc)) from exc
        prompt_profile = protocol["prompt_profile"]
        arm = prompt_profile["arm_prompt_key"]
        if arm not in prompt_profile["prompt_digest"]:
            raise _refuse(
                "agent protocol prompt_digest omits its own arm prompt key")
        agent_expected = {
            "agent_system": agent_kind,
            "comparison_class": protocol["comparison_class"],
            "max_iterations": stamped_iterations,
            "model": model,
            "native_budget": {
                agent.NATIVE_BUDGET_KEY[agent_kind]: budget},
            "prompt_digest": prompt_profile["prompt_digest"][arm],
        }
    expected_equal = {
        "adapter": plan["invocation"]["adapter"]["name"],
        "agent_system": None,
        "campaign_digest": plan["campaign"]["campaign_digest"],
        "comparison_class": None,
        "condition": campaign["condition"],
        "coverage": campaign["coverage"],
        "harness_version": runtime.harness["version"],
        "keep_artifacts": None,
        "model": None,
        "native_budget": None,
        "of": count,
        "prompt_digest": None,
        "protocol_digest": campaign["protocol_digest"],
        "protocol_version": campaign["protocol_version"],
        "shard": index,
        "trials": campaign["trial_budget"],
    }
    expected_equal.update(agent_expected)
    for name, expected in expected_equal.items():
        if not _same_json_value(stamp[name], expected):
            raise _refuse(f"effective run stamp {name} differs from its owner")
    null_names = {"max_tokens", "protocol_deviations"}
    if agent_kind is None:
        null_names.update({"adapter_version", "agent_version"})
        if protocol is None:
            null_names.update({"agent_timeout_seconds", "max_iterations",
                               "temperature"})
    for name in sorted(null_names):
        if stamp[name] is not None:
            raise _refuse(
                f"effective run stamp {name} must be canonical null")
    if agent_kind is None:
        if stamp["sandboxed"] is not False:
            raise _refuse("fixture effective run stamp sandboxed must be false")
    else:
        if stamp["sandboxed"] is not True:
            raise _refuse("an admitted agent run stamps sandboxed true")
        # `openhands@1` from the SPEC, not from a literal `@1` here.  The
        # spec's docstring says a driver, preset or budget change must
        # increment `version`, and the first time one does, a hard-coded `@1`
        # would refuse the very rows the increment exists to label.  Reached
        # only host-side (`_verify_run_plan` already imports `campaign`, which
        # the confined backend tree does not carry), so the import is safe
        # here in the shape every other cross-module reference takes.
        from ..agents.registry import get_spec
        qualified = get_spec(agent_kind).qualified
        if stamp["adapter_version"] != qualified:
            raise _refuse(
                "agent effective stamp adapter_version is not the admitted "
                f"{qualified} identity")
        _nonempty(stamp["agent_version"], "agent effective stamp agent_version")
    if not _same_json_value(
            stamp["setting"],
            None if protocol is None else protocol["setting"]):
        raise _refuse("effective run stamp setting differs from protocol")
    if protocol is not None:
        protocol_stamp = {
            "agent_timeout_seconds": protocol["agent_timeout_seconds"],
            "condition": protocol["condition"],
            "coverage": protocol["coverage"],
            "max_iterations": protocol["max_iterations"],
            "repeats": protocol["repeats"],
            "temperature": protocol.get("temperature"),
            "trials": protocol["trials"],
        }
        if agent_kind is not None:
            # The adapter's own budget authority already fixed this member,
            # and aider stamps null against a protocol that carries an int.
            del protocol_stamp["max_iterations"]
        for name, expected in protocol_stamp.items():
            if not _same_json_value(stamp[name], expected):
                raise _refuse(
                    f"effective run stamp {name} differs from protocol")
        for campaign_name, protocol_name in (
                ("condition", "condition"), ("coverage", "coverage"),
                ("trial_budget", "trials")):
            if not _same_json_value(
                    campaign[campaign_name], protocol[protocol_name]):
                raise _refuse(
                    f"campaign {campaign_name} differs from protocol")
    for name in ("repeats", "execution_timeout_seconds"):
        _integer(stamp[name], f"effective run stamp {name}", minimum=1)
    _integer(stamp["repro_check_count"],
             "effective run stamp repro_check_count")
    # These are invocation claims preserved by the frozen plan and joined
    # exactly to every result row.  I1 does not reopen mutable VERSIONS/subset
    # sidecars that the plan does not reference; later publication preflight
    # compares the preserved claim with the requested release scope (§6.3).
    if stamp["dataset_version"] is not None:
        _nonempty(stamp["dataset_version"],
                  "effective run stamp dataset_version")
    subset_id = stamp["subset_id"]
    subset_digest = stamp["subset_digest"]
    if (subset_id is None) != (subset_digest is None):
        raise _refuse("effective run stamp carries only half a subset identity")
    if subset_id is not None:
        _nonempty(subset_id, "effective run stamp subset_id")
        _hex16(subset_digest, "effective run stamp subset_digest")
    commit = runtime.harness["git_commit"]
    short_commit = stamp["harness_commit"]
    if commit is None:
        if short_commit is not None:
            raise _refuse("effective run stamp invents a harness commit")
    elif not isinstance(short_commit, str) or not (7 <= len(short_commit) <= 40) \
            or not commit.startswith(short_commit):
        raise _refuse("effective run stamp harness commit differs")
    if not _same_json_value(
            stamp["harness_version"], campaign["harness_version"]):
        raise _refuse("campaign and runtime harness versions differ")
    if campaign["container_image_digest"] \
            != runtime.identity["container_image_digest"]:
        raise _refuse("campaign and runtime container images differ")
    if campaign["workspace_seed_digest"] \
            != runtime.identity["workspace_seed_digest"] \
            or campaign["database_dump_digest"] \
            != runtime.identity["database_dump_digest"]:
        raise _refuse("campaign and runtime seed/database identities differ")
    if profile.needs_database is not runtime.identity["needs_database"]:
        raise _refuse("run profile and runtime disagree on the database")
    protected_plan_paths = [
        campaign_path, agent_runtime_path, release_path,
        boundary_path, profile_path, plan["worker_manifest_path"],
        strip["gold_root"],
    ]
    if plan["protocol"] is not None:
        protected_plan_paths.append(plan["protocol"]["path"])
    _require_workspace_separation(
        runtime.worker.workspace, protected_plan_paths,
        "run coordinator evidence")
    agent_adapter = None
    if agent_kind is not None:
        # Section 4 is a property of the PLAN, so it closes here rather than
        # on the receipt's evidence path alone: a v2 checkpoint has no
        # validation variant and "admits only an OpenHands/aider plan
        # satisfying this document" (section 6), and a checkpoint reaches
        # exactly this function.
        from ..confined import result_ledger_v2 as agent
        try:
            agent_adapter = agent.verify_agent_adapter(
                reader, plan["invocation"]["adapter"],
                result_path=runtime.worker.out_path, protocol=protocol,
                campaign=campaign, stamp=stamp, profile=profile,
                boundary=boundary, profile_reference=plan["profile"],
                boundary_reference=plan["boundary"],
                agent_runtime=agent_runtime)
        except agent.ResultLedgerV2Refused as exc:
            raise _refuse(str(exc)) from exc
    return _RunPlanContext(
        item_ids=selected_ids, release_rows=release_rows,
        selected_rows=selected_rows, campaign=campaign,
        campaign_path=campaign_path, agent_runtime=agent_runtime,
        boundary=boundary, profile=profile, protocol=protocol, stamp=stamp,
        adapter_config=adapter_config, adapter_files=adapter_files,
        adapter_expected_paths=adapter_expected_paths,
        strip_document=strip,
        agent_adapter=agent_adapter)


@dataclass
class _ValidationPlanContext:
    item_ids: list[str]
    closures: list[dict]
    selected: list[dict]
    boundary: object
    profile: object
    gold_root: str
    strip_document: dict


def _raw_ref_list(reader: _LiveReader, value: object, label: str) \
        -> list[tuple[dict, bytes]]:
    if not isinstance(value, list):
        raise _refuse(f"{label} is not a list")
    out = []
    sort_keys = []
    seen = set()
    for index, reference in enumerate(value):
        path, raw = _raw_reference_bytes(
            reader, reference, f"{label}[{index}]")
        key = (path, reference["file_sha256"])
        if key in seen:
            raise _refuse(f"{label} repeats a reference")
        seen.add(key)
        sort_keys.append(key)
        out.append((reference, raw))
    if sort_keys != sorted(sort_keys):
        raise _refuse(f"{label} is not sorted")
    return out


def _verify_validation_plan(reader: _LiveReader, plan: dict,
                            runtime: _RuntimeContext) \
        -> _ValidationPlanContext:
    if plan["schema"] != VALIDATION_PLAN_SCHEMA:
        raise _refuse("validation plan schema is unsupported")
    _verify_digest(plan, label="validation plan")
    invocation = plan["invocation"]
    if invocation["schema"] != VALIDATION_INVOCATION_SCHEMA \
            or plan["invocation_digest"] != domain_digest(
                VALIDATION_INVOCATION_SCHEMA, invocation):
        raise _refuse("validation invocation identity does not recompute")
    closures_path, closures_raw = _raw_reference_bytes(
        reader, plan["closures"], "validation closures")
    closures, by_id = _closure_records(closures_raw, "validation closures")
    source_ids = [row["item_id"] for row in closures]
    item_ids = _selection_ids(
        invocation["selection"], source_ids, validation_order=True)
    _verify_workset(plan["workset"], item_ids, "validation plan workset")
    selected = [by_id[item_id] for item_id in item_ids]
    boundary, profile, boundary_path, profile_path, _boundary_raw = (
        _verify_boundary_profile(
            reader, plan["boundary"], plan["profile"]))
    if profile.needs_database is not False \
            or runtime.identity["needs_database"] is not False:
        raise _refuse("validation requires a no-database profile and runtime")
    if not _same_json_value(
            plan["harness_version"], runtime.harness["version"]):
        raise _refuse("validation plan harness version differs from runtime")
    _integer(plan["repeats"], "validation plan repeats", minimum=1)
    _integer(plan["timeout_seconds"],
             "validation plan timeout_seconds", minimum=1)

    inputs = invocation["harness_inputs"]
    gold_root = canonical_absolute_path(
        inputs["gold_root"], "validation gold_root")
    _secure_directory_chain(gold_root, include_leaf=True)
    if plan["strip_manifest"] is None:
        raise _refuse("current admitted validation stack requires strip manifest")
    strip_path, strip_raw = _raw_reference_bytes(
        reader, plan["strip_manifest"], "validation strip manifest")
    fake_entry = {"path": strip_path, "file_sha256": raw_sha256(strip_raw)}
    strip = _strip_manifest(
        reader, fake_entry, boundary, runtime.worker.workspace)
    if strip["gold_root"] != gold_root:
        raise _refuse("validation gold_root differs from strip manifest")

    expected_gold = sorted({
        _closure_relative_path(value, boundary.repo_root,
                               "validation gold relative path")
        for row in selected for value in row["files"]
    })
    actual_gold = []
    for index, entry in enumerate(plan["gold_inputs"]):
        item = _exact_keys(
            entry, ("relative_path", "path", "byte_length", "file_sha256"),
            f"validation gold_inputs[{index}]")
        relative = _safe_relative(
            item["relative_path"], f"validation gold_inputs[{index}].relative")
        expected_path = _contained_path(gold_root, relative,
                                        "validation gold input")
        if item["path"] != expected_path:
            raise _refuse("validation gold input path is not root-contained")
        raw = reader.read(expected_path, "validation gold input")
        if len(raw) != item["byte_length"] \
                or raw_sha256(raw) != item["file_sha256"]:
            raise _refuse("validation gold input bytes differ")
        actual_gold.append((relative, expected_path))
    if actual_gold != sorted(actual_gold) \
            or [relative for relative, _path in actual_gold] != expected_gold:
        raise _refuse("validation transitive gold-input closure differs")

    expected_features = sorted({
        _closure_relative_path(row["feature_file"], boundary.repo_root,
                               "validation feature path")
        for row in selected
    })
    feature_refs = _raw_ref_list(
        reader, inputs["feature_inputs"], "validation feature inputs")
    actual_features = []
    for reference, _raw in feature_refs:
        path = _contained_path(runtime.worker.workspace,
                               os.path.relpath(
                                   reference["path"], runtime.worker.workspace)
                               .replace(os.sep, "/"),
                               "validation feature")
        if path != reference["path"]:
            raise _refuse("validation feature reference is outside workspace")
        actual_features.append(
            os.path.relpath(path, runtime.worker.workspace).replace(os.sep, "/"))
    if actual_features != expected_features:
        raise _refuse("validation feature-input closure differs")

    alias = inputs["alias_table"]
    autowire = inputs["autowirable_types"]
    coordinator_paths = [
        closures_path, boundary_path, profile_path, strip_path, gold_root,
        *(entry["path"] for entry in plan["gold_inputs"]),
    ]
    artifacts = canonical_absolute_path(
        runtime.worker.artifacts_root, "validation artifacts root")
    if profile.framework == "behave":
        if alias is not None or autowire is not None:
            raise _refuse("Behave validation must not name coordinator inputs")
    else:
        if alias is None:
            raise _refuse("Behat validation omits alias table")
        alias_path, _ = _raw_reference_bytes(
            reader, alias, "validation alias table")
        coordinator_paths.append(alias_path)
        if alias_path != artifacts + "/alias_table.json":
            raise _refuse("validation alias table path differs")
        alias_value = loads_exact_json(
            reader.raw_by_path[alias_path], label="validation alias table")
        if not isinstance(alias_value, dict):
            raise _refuse("validation alias table is not a JSON object")
        optional = artifacts + "/autowirable_types.json"
        if autowire is None:
            reader.require_absent(optional, "validation autowirable types")
        else:
            optional_path, _ = _raw_reference_bytes(
                reader, autowire, "validation autowirable types")
            coordinator_paths.append(optional_path)
            if optional_path != optional:
                raise _refuse("validation autowirable-types path differs")
            optional_value = loads_exact_json(
                reader.raw_by_path[optional_path],
                label="validation autowirable types")
            if not isinstance(optional_value, list) or any(
                    not isinstance(value, str) for value in optional_value):
                raise _refuse(
                    "validation autowirable types is not a string list")
    if closures_path != plan["closures"]["path"]:
        raise _refuse("validation closures path drifted")
    _require_workspace_separation(
        runtime.worker.workspace, coordinator_paths,
        "validation coordinator evidence")
    return _ValidationPlanContext(
        item_ids=item_ids, closures=closures, selected=selected,
        boundary=boundary, profile=profile, gold_root=gold_root,
        strip_document=strip)


# ---------------------------------------------------------- result/receipt
def _verify_result_bytes(reader: _LiveReader, binding: object, label: str, *,
                         prefix: bool, allow_absent_empty: bool = False) \
        -> tuple[bytes, list[dict]]:
    value = _exact_keys(
        binding, ("path", "byte_length", "row_count", "file_sha256"), label)
    path = canonical_absolute_path(value["path"], label + ".path")
    length = _integer(value["byte_length"], label + ".byte_length")
    row_count = _integer(value["row_count"], label + ".row_count")
    digest = _sha256(value["file_sha256"], label + ".file_sha256")
    if allow_absent_empty and not os.path.lexists(path):
        _secure_directory_chain(path)
        if length != 0 or row_count != 0 or digest != raw_sha256(b""):
            raise _refuse(f"absent {label} is not an exact empty prefix")
        reader.absent_paths[path] = label
        return b"", []
    raw = reader.read(path, label)
    if prefix:
        if len(raw) < length:
            raise _refuse(f"{label} is shorter than its committed prefix")
        committed = raw[:length]
    else:
        if len(raw) != length:
            raise _refuse(f"{label} byte length differs")
        committed = raw
    if raw_sha256(committed) != digest:
        raise _refuse(f"{label} raw SHA-256 differs")
    rows = _json_lines(committed, label)
    if len(rows) != row_count:
        raise _refuse(f"{label} row count differs")
    return committed, rows


def _verify_row_sequence(rows: list[dict], expected_ids: list[str], *,
                         stamp: Optional[dict] = None,
                         allow_prefix: bool = False) -> None:
    if allow_prefix:
        expected_ids = expected_ids[:len(rows)]
    if len(rows) != len(expected_ids):
        raise _refuse("result row count does not cover its frozen workset")
    actual_ids = []
    for index, row in enumerate(rows):
        item_id = _nonempty(row.get("item_id"), f"result row {index}.item_id")
        actual_ids.append(item_id)
        if stamp is not None:
            missing = sorted(name for name in RUN_STAMP_NAMES if name not in row)
            if missing:
                raise _refuse(
                    f"result row {index} omits effective stamp fields {missing}")
            different = sorted(
                name for name in RUN_STAMP_NAMES
                if name != "harness_commit"
                and not _same_json_value(row[name], stamp[name]))
            if different:
                raise _refuse(
                    f"result row {index} effective stamp differs: {different}")
            # A row names the commit it was produced under, which may differ
            # from the plan's and from its neighbours' after a resume across
            # a merge (section 16.5); the shape is still closed.
            commit = row["harness_commit"]
            if commit is not None and (
                    not isinstance(commit, str)
                    or _SHORT_COMMIT_RE.fullmatch(commit) is None):
                raise _refuse(f"result row {index} harness_commit is malformed")
    if actual_ids != expected_ids or len(actual_ids) != len(set(actual_ids)):
        raise _refuse("result item IDs differ from frozen order or repeat")


def _verify_validation_row_sequence(
        rows: list[dict], expected_ids: list[str], *, execution: dict,
        plan: dict, allow_prefix: bool = False) -> None:
    """Verify I3's exact validation row order and publication identity."""
    _verify_row_sequence(rows, expected_ids, allow_prefix=allow_prefix)
    expected = {
        "validation_attempt_id": execution["attempt_id"],
        "validation_plan_digest": plan["digest"],
        "harness_version": plan["harness_version"],
        "repeats": plan["repeats"],
        "timeout_seconds": plan["timeout_seconds"],
    }
    for index, row in enumerate(rows):
        missing = [name for name in VALIDATION_ROW_IDENTITY_FIELDS
                   if name not in row]
        if missing:
            raise _refuse(
                f"validation result row {index} omits identity fields "
                f"{missing}")
        different = [
            name for name in VALIDATION_ROW_IDENTITY_FIELDS
            if not _same_json_value(row[name], expected[name])
        ]
        if different:
            raise _refuse(
                f"validation result row {index} identity differs: "
                f"{different}")


def _verify_worker_manifest(reader: _LiveReader, reference: object, plan: dict,
                            result: dict, runtime: _RuntimeContext,
                            context: _RunPlanContext) -> tuple[dict, dict]:
    from . import campaign
    path, raw = _raw_reference_bytes(reader, reference, "WorkerManifest")
    if path != plan["worker_manifest_path"]:
        raise _refuse("receipt WorkerManifest path differs from run plan")
    document = _parse_json_object(raw, "WorkerManifest")
    _exact_keys(document, ("campaign", "campaign_digest", "worker"),
                "WorkerManifest")
    if not _same_json_value(document["campaign"], context.campaign) \
            or document["campaign_digest"] \
            != plan["campaign"]["campaign_digest"]:
        raise _refuse("WorkerManifest campaign differs from run plan")
    try:
        worker_manifest = campaign.WorkerManifest.from_json(document["worker"])
    except (Exception, SystemExit) as exc:
        _raise_from(exc, "WorkerManifest.worker")
    worker_value = worker_manifest.to_json()
    if not _same_json_value(worker_value, document["worker"]):
        raise _refuse("WorkerManifest worker value is not exact canonical shape")
    if worker_manifest.finished_at is None:
        raise _refuse("complete receipt binds a partial WorkerManifest")
    expected = {
        "shard": runtime.worker.index,
        "workspace": runtime.worker.workspace,
        "container": runtime.worker.container,
        "schema": runtime.worker.schema,
        "credential": runtime.worker.credential,
        "out_path": result["path"],
        "artifacts_root": runtime.worker.artifacts_root,
        "campaign_digest": plan["campaign"]["campaign_digest"],
    }
    different = sorted(
        key for key, value in expected.items()
        if not _same_json_value(worker_value[key], value))
    if different:
        raise _refuse(f"WorkerManifest differs from runtime/result: {different}")
    return document, worker_value


def agent_ledger_kind(document: Mapping[str, object]) -> Optional[str]:
    """The admitted agent adapter kind of a v2 document, or None for v1.

    This is the ONE place a schema constant decides which contract closes a
    document.  A v1 receipt never reaches the agent chain and a v2 receipt
    never reaches the fixture adapter set, so neither version can be talked
    into the other's refusals.
    """
    schema = document.get("schema")
    if schema in (CHECKPOINT_SCHEMA, RECEIPT_SCHEMA):
        return None
    # Only a document that is not the fixture producer's needs the agent
    # evidence reader; without it the document cannot be admitted at all.
    try:
        from ..confined import result_ledger_v2 as agent
    except ImportError:
        raise _refuse(
            f"ledger schema {schema!r} is not the fixture producer's, and "
            f"the agent evidence reader (r2t.confined.result_ledger_v2) is not "
            f"shipped in this checkout")
    if schema not in (agent.CHECKPOINT_SCHEMA, agent.RECEIPT_SCHEMA):
        raise _refuse(f"ledger schema {schema!r} is unsupported")
    if document.get("artifact_kind") == "merged_run":
        return None
    plan = document.get("plan")
    adapter = plan.get("invocation", {}).get("adapter") \
        if isinstance(plan, dict) else None
    if not isinstance(adapter, dict):
        raise _refuse("v2 document carries no agent adapter invocation")
    try:
        return agent._refuse_non_agent_producer(adapter)
    except agent.ResultLedgerV2Refused as exc:
        raise _refuse(str(exc)) from exc


def _load_ledger_document(reader: _LiveReader, path: str, *,
                          checkpoint: bool) -> tuple[dict, bytes]:
    path = canonical_absolute_path(
        path, "checkpoint path" if checkpoint else "receipt path")
    label = "result checkpoint" if checkpoint else "result receipt"
    raw = reader.read(path, label)
    document = _parse_json_object(raw, label)
    schema = document.get("schema")
    # The agent producer's schemas are the agent component's to validate.
    # A fixture document never needs it; a document that is not a fixture
    # one is either the agent's or unsupported, and without the agent
    # evidence reader the two cannot be told apart, so it refuses by name.
    fixture_schema = CHECKPOINT_SCHEMA if checkpoint else RECEIPT_SCHEMA
    if schema == fixture_schema:
        agent = None
    else:
        try:
            from ..confined import result_ledger_v2 as agent
        except ImportError:
            raise _refuse(
                f"{label} schema {schema!r} is not the fixture producer's, "
                f"and the agent evidence reader (r2t.confined.result_ledger_v2) is "
                f"not shipped in this checkout")
    admitted = ((CHECKPOINT_SCHEMA, agent.CHECKPOINT_SCHEMA) if checkpoint
                else (RECEIPT_SCHEMA, agent.RECEIPT_SCHEMA)) \
        if agent is not None else (fixture_schema,)
    if schema not in admitted:
        raise _refuse(
            f"{label} schema {schema!r} is unsupported")
    if checkpoint:
        if schema == CHECKPOINT_SCHEMA:
            validate_checkpoint_schema(document)
        else:
            agent.validate_checkpoint_schema(document)
    else:
        if schema == RECEIPT_SCHEMA:
            validate_receipt_schema(document)
        else:
            agent.validate_receipt_schema(document)
    _verify_digest(document, label=label)
    return document, raw


def verify_checkpoint(path: str) -> dict:
    """Verify one mutable checkpoint as diagnostic, never complete evidence."""
    reader = _LiveReader()
    document, raw = _load_ledger_document(reader, path, checkpoint=True)
    result = document["result_prefix"]
    if path != result["path"] + CHECKPOINT_SUFFIX:
        raise _refuse("checkpoint path is not derived from its exact result path")
    runtime = _verify_runtime(reader, document["execution"]["runtime"])
    _require_workspace_separation(
        runtime.worker.workspace, [result["path"]],
        "checkpoint result")
    running = document["state"] == "running"
    population_identity = None
    release_path = None
    if document["artifact_kind"] == "run_shard":
        context = _verify_run_plan(reader, document["plan"], runtime,
                                   agent_kind=agent_ledger_kind(document))
        population_identity = {
            "campaign_digest": document["plan"]["campaign"][
                "campaign_digest"],
            "subset_id": context.stamp["subset_id"],
            "subset_digest": context.stamp["subset_digest"],
            "shard_rule": document["plan"]["shard_rule"],
            "shard_count": document["plan"]["shard_count"],
        }
        release_path = document["plan"]["release"]["path"]
        if document["execution"]["attempt_id"] \
                != context.campaign["attempt_id"]:
            raise _refuse("checkpoint attempt differs from campaign")
        _bytes, rows = _verify_result_bytes(
            reader, result, "checkpoint result prefix", prefix=running,
            allow_absent_empty=document["state"] == "draft")
        if running:
            full = reader.raw_by_path[result["path"]]
            suffix = full[result["byte_length"]:]
            if suffix:
                rows += _json_lines(suffix, "running checkpoint suffix")
        _verify_row_sequence(
            rows, context.item_ids, stamp=context.stamp, allow_prefix=True)
        if result["path"] != runtime.worker.out_path:
            raise _refuse(
                "checkpoint result path differs from selected WorkerSpec")
    else:
        context = _verify_validation_plan(reader, document["plan"], runtime)
        _bytes, rows = _verify_result_bytes(
            reader, result, "checkpoint validation prefix", prefix=running,
            allow_absent_empty=document["state"] == "draft")
        if running:
            full = reader.raw_by_path[result["path"]]
            suffix = full[result["byte_length"]:]
            if suffix:
                rows += _json_lines(
                    suffix, "running validation checkpoint suffix")
        _verify_validation_row_sequence(
            rows, context.item_ids, execution=document["execution"],
            plan=document["plan"], allow_prefix=True)
    reader.confirm()
    return {
        "artifact_kind": document["artifact_kind"],
        "checkpoint_digest": document["digest"],
        "checkpoint_file_sha256": raw_sha256(raw),
        "checkpoint_path": path,
        # The checkpoint verifier has already replayed the selection and the
        # selected shard rule and checked this workset against that replay.
        # Reporting consumes only the authoritative count/digest projection:
        # a mutable checkpoint is diagnostic evidence, not an enumerable
        # frozen-workset receipt.
        "workset": dict(document["plan"]["workset"]),
        "population_identity": population_identity,
        "release_path": release_path,
        "complete": False,
        "state": document["state"],
        "verified": True,
    }


def verify_reporting_workset(path: str) -> dict:
    """Reclose one result receipt and expose its already replayed workset.

    Reporting neither selects items nor assigns shards.  This projection is
    deliberately produced here, where the receipt verifier has already
    replayed those operations against the exact release, campaign, run plan,
    and retained result bytes.
    """
    reader = _LiveReader()
    document, raw = _load_ledger_document(reader, path, checkpoint=False)
    kind = document["artifact_kind"]
    if kind == "run_shard":
        source = _verify_run_shard_receipt(reader, document, path, raw)
        item_ids = tuple(source.context.item_ids)
        workset = dict(source.document["plan"]["workset"])
        campaign_digest = source.document["plan"]["campaign"][
            "campaign_digest"]
        stamp = source.context.stamp
        shard_rule = source.document["plan"]["shard_rule"]
        shard_count = source.document["plan"]["shard_count"]
        release_path = source.document["plan"]["release"]["path"]
    elif kind == "merged_run":
        projections: list = []
        _verify_receipt_document(
            reader, document, path, raw, projections=projections)
        projection = projections[0]
        first = projection.sources[0]
        item_ids = tuple(projection.merge_ids)
        workset = {
            "item_count": document["merge"]["expected_item_count"],
            "ordered_item_ids_digest":
                document["merge"]["ordered_item_ids_digest"],
        }
        campaign_digest = projection.campaign_digest
        stamp = first.context.stamp
        shard_rule = first.document["plan"]["shard_rule"]
        shard_count = first.document["plan"]["shard_count"]
        release_path = projection.release_reference["path"]
    else:
        raise _refuse(
            f"reporting receipt describes {kind!r}, not result rows")
    reader.confirm()
    return {
        "item_ids": item_ids,
        "workset": workset,
        "campaign_digest": campaign_digest,
        "subset_id": stamp["subset_id"],
        "subset_digest": stamp["subset_digest"],
        "shard_rule": shard_rule,
        "shard_count": shard_count,
        "release_path": release_path,
        "result_path": document["result"]["path"],
    }


@dataclass
class _VerifiedRunShard:
    document: dict
    receipt_path: str
    receipt_raw: Optional[bytes]
    result_raw: bytes
    rows: list[dict]
    runtime: _RuntimeContext
    context: _RunPlanContext
    worker_document: dict
    worker_value: dict
    #: `None` for a v1 fixture shard; the admitted adapter kind for a v2
    #: agent shard.  Carried on the source so a merge cannot mix the two
    #: without noticing.
    agent_kind: Optional[str] = None
    agent_evidence: Optional[dict] = None

    @property
    def worker_index(self) -> int:
        return self.runtime.worker.index


@dataclass
class _MergeProjection:
    sources: list[_VerifiedRunShard]
    release_reference: dict
    release_ids: list[str]
    merge_ids: list[str]
    result_rows: list[dict]
    result_raw: bytes
    campaign: dict
    campaign_digest: str
    campaign_semantic_digest: str
    pool_digest: str
    #: The one adapter kind every source shares: `None` for a v1 fixture
    #: merge, the admitted agent kind for a homogeneous v2 agent merge.
    agent_kind: Optional[str] = None


def _receipt_result_path(document: dict, path: str) -> dict:
    result = document["result"]
    if path != result["path"] + RECEIPT_SUFFIX:
        raise _refuse("receipt path is not derived from its exact result path")
    return result


def _verify_run_shard_receipt(
        reader: _LiveReader, document: dict, path: str,
        raw: Optional[bytes]) -> _VerifiedRunShard:
    """Verify a run receipt without closing the caller's shared snapshot."""
    result = _receipt_result_path(document, path)
    agent_kind = agent_ledger_kind(document)
    runtime = _verify_runtime(reader, document["execution"]["runtime"])
    _require_workspace_separation(
        runtime.worker.workspace, [result["path"]], "receipt result")
    context = _verify_run_plan(reader, document["plan"], runtime,
                               agent_kind=agent_kind)
    if document["execution"]["attempt_id"] \
            != context.campaign["attempt_id"]:
        raise _refuse("receipt attempt differs from generation campaign")
    result_raw, rows = _verify_result_bytes(
        reader, result, "run-shard result", prefix=False)
    _verify_row_sequence(rows, context.item_ids, stamp=context.stamp)
    if result["path"] != runtime.worker.out_path:
        raise _refuse("run result path differs from selected WorkerSpec")
    worker_document, worker_value = _verify_worker_manifest(
        reader, document["worker_manifest"], document["plan"], result,
        runtime, context)
    agent_evidence = None
    if agent_kind is not None:
        agent_evidence = _verify_agent_shard(
            reader, document, context, result_raw, rows, runtime)
    return _VerifiedRunShard(
        document=document, receipt_path=path, receipt_raw=raw,
        result_raw=result_raw, rows=rows, runtime=runtime, context=context,
        worker_document=worker_document, worker_value=worker_value,
        agent_kind=agent_kind, agent_evidence=agent_evidence)


def _verify_agent_shard(reader: _LiveReader, document: dict,
                        context: _RunPlanContext, result_raw: bytes,
                        rows: list[dict], runtime: _RuntimeContext) -> dict:
    """Close a v2 run shard through its companion, items and attestation.

    Section 4's plan projection is already closed by `_verify_run_plan`, on
    the checkpoint path as well as this one; what is added here is section
    5/6's evidence.  The release rows, the profile and the worker workspace
    travel with it because section 5.1 makes the verifier RECONSTRUCT the
    publication task and section 3.2's per-item argv rather than accept
    whatever the evidence happens to carry.
    """
    from ..confined import result_ledger_v2 as agent
    adapter_info = context.agent_adapter
    if adapter_info is None:
        raise _refuse("an agent run shard carries no verified agent adapter")
    try:
        return agent.verify_agent_producer_evidence(
            reader, receipt=document, adapter_info=adapter_info,
            item_ids=list(context.item_ids), result_raw=result_raw, rows=rows,
            selected_rows=context.selected_rows, profile=context.profile,
            workspace=runtime.worker.workspace)
    except agent.ResultLedgerV2Refused as exc:
        raise _refuse(str(exc)) from exc


def _verify_validation_receipt(
        reader: _LiveReader, document: dict, path: str) -> None:
    result = _receipt_result_path(document, path)
    runtime = _verify_runtime(reader, document["execution"]["runtime"])
    _require_workspace_separation(
        runtime.worker.workspace, [result["path"]], "receipt result")
    context = _verify_validation_plan(reader, document["plan"], runtime)
    _bytes, rows = _verify_result_bytes(
        reader, result, "validation result", prefix=False)
    _verify_validation_row_sequence(
        rows, context.item_ids, execution=document["execution"],
        plan=document["plan"])


def _common_run_plan_projection(plan: dict) -> dict:
    """Remove exactly S0's authenticated shard-local run-plan fields."""
    # Deferred like `_verify_worker_resource_disjointness`'s `campaign` import
    # below: `runner` imports this module, so naming it at module scope would
    # be circular.
    from .runner import AGENT_DEPLOYMENT_DIRECTORY

    common = copy.deepcopy(plan)
    del common["worker_manifest_path"]
    del common["shard_index"]
    del common["workset"]
    del common["invocation_digest"]
    del common["digest"]
    invocation = common["invocation"]
    del invocation["adapter"]["files"]
    stamps = invocation["effective_run_stamp"]
    invocation["effective_run_stamp"] = [
        stamp for stamp in stamps
        if stamp["name"] not in ("shard", "harness_commit")]
    # An agent plan's `storage_layout` is the amendment's section 4 value for
    # THIS shard's result path, and every one of its four members is derived
    # from it, so two shards of one campaign necessarily differ in it.  It is
    # authenticated shard-locally for exactly the same reason `adapter.files`
    # above is: `verify_agent_adapter` requires it to equal
    # `storage_layout(worker.out_path)` for the WorkerSpec this receipt was
    # already proved against.  Section 8's list of what a merge requires in
    # common -- adapter kind/name, campaign, model, endpoint projection,
    # backend runtime, seed, pricing selection, secret-channel name and
    # sanitized environment -- does not include it, and every one of those
    # nine is compared exactly by `require_homogeneous_agent_sources`.
    invocation["adapter"]["public_configuration"] = [
        entry for entry in invocation["adapter"]["public_configuration"]
        if entry.get("name") != "storage_layout"]
    # THE DEPLOYED AGENT INPUT IS UNDER THIS SHARD'S OWN ARTIFACTS ROOT.
    # `runner._agent_deployment_path` stages the harness-owned price table at
    # `<artifacts_root>/agent-inputs/pricing.yml`, and a pool gives every
    # worker its own `artifacts_root` -- `_verify_worker_resource_disjointness`
    # below REQUIRES them not to overlap.  So the `command_template` of two
    # shards of one campaign necessarily differs in that one argument, for the
    # same structural reason `storage_layout` does, and comparing it whole
    # refused every strict merge this campaign shape can produce.
    #
    # What a merge needs in common is WHICH input is deployed, not the
    # per-shard directory it was staged into.  The table's identity is not
    # weakened by this: `pricing_selection` carries the resolved rates and
    # their digest and is compared exactly, and `harness_owned_agent_digests`
    # records the staged bytes; drift is disclosed at verification (I2).
    for entry in invocation["adapter"]["public_configuration"]:
        if entry.get("name") != "command_template":
            continue
        try:
            argv = json.loads(entry["value_json"])
        except (KeyError, TypeError, ValueError):
            continue
        if not isinstance(argv, list):
            continue
        marker = "/" + AGENT_DEPLOYMENT_DIRECTORY + "/"
        entry["value_json"] = json.dumps([
            AGENT_DEPLOYMENT_DIRECTORY + "/" + token.rsplit(marker, 1)[1]
            if isinstance(token, str) and marker in token else token
            for token in argv
        ], sort_keys=True)
    return common


def _verify_worker_resource_disjointness(
        sources: list[_VerifiedRunShard]) -> None:
    from . import campaign
    path_fields = ("workspace", "env_file", "out_path", "artifacts_root")
    equal_fields = ("container", "schema", "credential")
    for left_index, left in enumerate(sources):
        for right in sources[left_index + 1:]:
            for left_field in path_fields:
                left_path = getattr(left.runtime.worker, left_field)
                for right_field in path_fields:
                    right_path = getattr(right.runtime.worker, right_field)
                    if campaign._path_conflict(left_path, right_path):
                        raise _refuse(
                            "worker filesystem resources overlap: "
                            f"{left.worker_index}.{left_field} and "
                            f"{right.worker_index}.{right_field}")
            for field in equal_fields:
                left_value = getattr(left.runtime.worker, field)
                right_value = getattr(right.runtime.worker, field)
                if left_value and left_value == right_value:
                    raise _refuse(
                        f"workers {left.worker_index} and "
                        f"{right.worker_index} share resource {field}")


def _common_binding_snapshot(binding: dict) -> dict:
    """Project the pool-wide capture facts shared by every worker binding."""
    return {
        "captured_at_utc": binding["captured_at_utc"],
        "network_policy": binding["network_policy"],
    }


def _verify_logical_projections(sources: list[_VerifiedRunShard]) -> None:
    # Pricing is staged under each shard's artifacts root.  Its content still
    # has to match because the byte-length/digest check runs before the path
    # comparison below.
    shard_local_roles = frozenset({
        "harness_feature", "harness_alias_table",
        "harness_autowirable_types", "fixture_closures",
        "pricing_table",
    })
    logical: dict[tuple[str, str], dict] = {}
    expected_keys = set()
    for source in sources:
        expected_keys.update(source.context.adapter_expected_paths)
        for key, entry in source.context.adapter_files.items():
            prior = logical.get(key)
            if prior is not None:
                if (entry["byte_length"], entry["file_sha256"]) != (
                        prior["byte_length"], prior["file_sha256"]):
                    raise _refuse(
                        "logical adapter input bytes differ across shards: "
                        f"{key!r}")
                if key[0] not in shard_local_roles \
                        and entry["path"] != prior["path"]:
                    raise _refuse(
                        "global adapter input path differs across shards: "
                        f"{key!r}")
            else:
                logical[key] = entry
    if set(logical) != expected_keys:
        raise _refuse(
            "deduplicated logical adapter closure differs from the full "
            "source-derived closure")


def _merged_rows_bytes(rows: list[dict]) -> bytes:
    try:
        return b"".join(
            (json.dumps(
                row, sort_keys=True, ensure_ascii=True, allow_nan=False,
                separators=(", ", ": ")) + "\n").encode("utf-8")
            for row in rows)
    except (TypeError, ValueError) as exc:
        raise _refuse(
            f"merged result row is not exact JSON encodable: {exc}") from exc


def _campaign_sidecar_bytes(sidecar: dict) -> bytes:
    try:
        return (json.dumps(
            sidecar, sort_keys=True, indent=2, ensure_ascii=True,
            allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _refuse(
            f"merged campaign sidecar is not exact JSON encodable: {exc}") \
            from exc


def _load_run_source(
        reader: _LiveReader, path: str) -> _VerifiedRunShard:
    document, raw = _load_ledger_document(reader, path, checkpoint=False)
    if document["artifact_kind"] != "run_shard":
        raise _refuse(
            "strict merge source is not a complete run_shard receipt")
    return _verify_run_shard_receipt(reader, document, path, raw)


def _load_source_paths(
        reader: _LiveReader, paths: Iterable[str]) \
        -> list[_VerifiedRunShard]:
    canonical = [
        canonical_absolute_path(path, "source receipt path") for path in paths]
    if not canonical:
        raise _refuse("strict merge requires at least one source receipt")
    if len(canonical) != len(set(canonical)):
        raise _refuse("strict merge repeats a source receipt path")
    return [_load_run_source(reader, path) for path in canonical]


def _load_source_entries(
        reader: _LiveReader, entries: list[dict]) \
        -> list[_VerifiedRunShard]:
    sources = []
    previous = -1
    unique: dict[str, set] = {
        "receipt path": set(), "receipt raw SHA-256": set(),
        "receipt digest": set(), "source result path": set(),
        "source result SHA-256": set(),
    }
    for number, entry in enumerate(entries):
        value = _exact_keys(
            entry,
            ("worker_index", "receipt_path", "receipt_file_sha256",
             "receipt_digest", "source_result_file_sha256"),
            f"source_receipts[{number}]")
        index = _integer(
            value["worker_index"],
            f"source_receipts[{number}].worker_index")
        if index <= previous:
            raise _refuse(
                "source receipts are not ordered by strictly increasing "
                "worker index")
        previous = index
        path = canonical_absolute_path(
            value["receipt_path"],
            f"source_receipts[{number}].receipt_path")
        source = _load_run_source(reader, path)
        if source.receipt_raw is None:
            raise _refuse("loaded source receipt has no exact raw bytes")
        actual = {
            "worker_index": source.worker_index,
            "receipt_file_sha256": raw_sha256(source.receipt_raw),
            "receipt_digest": source.document["digest"],
            "source_result_file_sha256":
                source.document["result"]["file_sha256"],
        }
        for key, expected in actual.items():
            if not _same_json_value(value[key], expected):
                raise _refuse(
                    f"source receipt entry {number} {key} differs from "
                    "the recursively verified receipt")
        identities = {
            "receipt path": path,
            "receipt raw SHA-256": actual["receipt_file_sha256"],
            "receipt digest": actual["receipt_digest"],
            "source result path": source.document["result"]["path"],
            "source result SHA-256": actual["source_result_file_sha256"],
        }
        for label, identity in identities.items():
            if identity in unique[label]:
                raise _refuse(f"strict merge repeats {label}")
            unique[label].add(identity)
        sources.append(source)
    return sources


def _source_entry(source: _VerifiedRunShard) -> dict:
    if source.receipt_raw is None:
        raise _refuse("source receipt has no exact raw bytes")
    return {
        "worker_index": source.worker_index,
        "receipt_path": source.receipt_path,
        "receipt_file_sha256": raw_sha256(source.receipt_raw),
        "receipt_digest": source.document["digest"],
        "source_result_file_sha256":
            source.document["result"]["file_sha256"],
    }


def _verify_source_identity_uniqueness(
        sources: list[_VerifiedRunShard]) -> None:
    identities: dict[str, list[object]] = {
        "worker index": [source.worker_index for source in sources],
        "receipt path": [source.receipt_path for source in sources],
        "receipt raw SHA-256": [
            raw_sha256(source.receipt_raw)
            if source.receipt_raw is not None else None
            for source in sources],
        "receipt digest": [
            source.document["digest"] for source in sources],
        "source result path": [
            source.document["result"]["path"] for source in sources],
        "source result SHA-256": [
            source.document["result"]["file_sha256"] for source in sources],
    }
    for label, values in identities.items():
        if None in values or len(values) != len(set(values)):
            raise _refuse(f"strict merge repeats or omits {label}")


def _verify_merge_homogeneity(
        sources: list[_VerifiedRunShard]) -> Optional[str]:
    """Section 8: one adapter kind, one schema version, one agent campaign.

    OpenHands/aider mixing and v1/v2 source mixing refuse here, before any
    row is copied.  `replay` and `openai` never reach this point: they are
    refused by the adapter admission every source already passed.
    """
    schemas = {source.document["schema"] for source in sources}
    if len(schemas) != 1:
        raise _refuse(
            f"strict merge mixes receipt schema versions {sorted(schemas)}")
    kinds = {source.agent_kind for source in sources}
    if len(kinds) != 1:
        raise _refuse(
            "strict merge mixes agent and fixture sources: "
            f"{sorted(str(kind) for kind in kinds)}")
    agent_kind = kinds.pop()
    if agent_kind is None:
        return None
    # Reached for agent sources only, which `agent_ledger_kind` admitted
    # with the reader present.
    from ..confined import result_ledger_v2 as agent
    try:
        agent.require_homogeneous_agent_sources([
            agent.merge_common_projection(source.document["plan"],
                                          source.context.stamp)
            for source in sources])
    except agent.ResultLedgerV2Refused as exc:
        raise _refuse(str(exc)) from exc
    return agent_kind


def _verify_merge_sources(
        sources: list[_VerifiedRunShard], *,
        expected_shards: Optional[int] = None) -> _MergeProjection:
    if not sources:
        raise _refuse("strict merge has no source receipts")
    sources = sorted(sources, key=lambda source: source.worker_index)
    _verify_source_identity_uniqueness(sources)
    agent_kind = _verify_merge_homogeneity(sources)
    first = sources[0]
    shard_count = first.document["plan"]["shard_count"]
    if expected_shards is not None and shard_count != expected_shards:
        raise _refuse("requested shard count differs from source run plans")
    if len(sources) != shard_count:
        raise _refuse(
            "strict merge does not contain exactly one source per worker")
    indices = [source.worker_index for source in sources]
    if indices != list(range(shard_count)):
        raise _refuse(
            "strict merge worker indices are missing, duplicate, or extra")

    common_plan = _common_run_plan_projection(first.document["plan"])
    common_authority_reference = first.document["execution"]["runtime"][
        "identity"]["docker_execution_authority"]
    common_binding_snapshot = _common_binding_snapshot(
        first.runtime.binding)
    common_runtime = {
        "authority": first.runtime.authority,
        "pool": first.runtime.pool,
        "daemon": first.runtime.identity[
            "docker_daemon_fingerprint_sha256"],
        "image": first.runtime.identity["container_image_digest"],
        "seed_dir": first.runtime.identity["seed_dir"],
        "seed_manifest": first.runtime.identity["seed_manifest"],
        "seed_key": first.runtime.identity["seed_key"],
        "workspace_seed": first.runtime.identity["workspace_seed_digest"],
        "database_dump": first.runtime.identity["database_dump_digest"],
        "needs_database": first.runtime.identity["needs_database"],
        "harness": first.runtime.identity["harness"]["version"],
    }
    attempt = first.document["execution"]["attempt_id"]
    release_reference = first.document["plan"]["release"]
    release_ids = [row["item_id"] for row in first.context.release_rows]
    campaign_reference = first.document["plan"]["campaign"]

    for source in sources:
        plan = source.document["plan"]
        _require_same_json(
            _common_run_plan_projection(plan), common_plan,
            "source run plans differ outside documented shard-local fields")
        if source.document["execution"]["attempt_id"] != attempt:
            raise _refuse("source receipt attempts differ")
        authority_reference = source.document["execution"]["runtime"][
            "identity"]["docker_execution_authority"]
        _require_same_json(
            authority_reference, common_authority_reference,
            "source authority references differ")
        runtime_projection = {
            "authority": source.runtime.authority,
            "pool": source.runtime.pool,
            "daemon": source.runtime.identity[
                "docker_daemon_fingerprint_sha256"],
            "image": source.runtime.identity["container_image_digest"],
            "seed_dir": source.runtime.identity["seed_dir"],
            "seed_manifest": source.runtime.identity["seed_manifest"],
            "seed_key": source.runtime.identity["seed_key"],
            "workspace_seed": source.runtime.identity[
                "workspace_seed_digest"],
            "database_dump": source.runtime.identity[
                "database_dump_digest"],
            "needs_database": source.runtime.identity["needs_database"],
            "harness": source.runtime.identity["harness"]["version"],
        }
        _require_same_json(
            runtime_projection, common_runtime,
            "source authority/pool/image/seed/harness facts differ")
        _require_same_json(
            source.runtime.binding["pool"], first.runtime.binding["pool"],
            "source binding-pool snapshots differ")
        _require_same_json(
            _common_binding_snapshot(source.runtime.binding),
            common_binding_snapshot,
            "source binding capture snapshots differ")
        _require_same_json(
            plan["release"], release_reference,
            "source release references differ")
        if [row["item_id"] for row in source.context.release_rows] \
                != release_ids:
            raise _refuse("source releases differ in exact ordered item IDs")
        if source.context.campaign["attempt_id"] != attempt:
            raise _refuse("source campaign attempt differs")
        if source.runtime.worker.index != plan["shard_index"]:
            raise _refuse("source plan selects another runtime worker")

    _verify_worker_resource_disjointness(sources)
    _verify_logical_projections(sources)

    from . import campaign as campaign_module
    selection = first.document["plan"]["invocation"]["selection"]
    selected_before_sharding = _selection_ids(
        selection, release_ids, validation_order=False)
    rule = first.document["plan"]["shard_rule"]
    if rule == campaign_module.SHARD_RULE:
        expected_by_worker = []
        limit = selection["limit"]
        for worker_index in range(shard_count):
            selected = [
                item_id for item_id in selected_before_sharding
                if campaign_module.shard_of(
                    item_id, shard_count) == worker_index]
            if limit is not None:
                selected = selected[:limit]
            expected_by_worker.append(selected)
    elif rule == campaign_module.POSITIONAL_SHARD_RULE:
        if shard_count != 4 \
                or selection != {
                    "limit": None, "requested_item_ids": None} \
                or selected_before_sharding != release_ids:
            raise _refuse(
                "Slice-3 positional merge requires the complete ordered "
                "release and K=4")
        assigned = campaign_module.assign_ordered_shards(
            release_ids, shard_count)
        expected_by_worker = [assigned[index]
                              for index in range(shard_count)]
    else:
        raise _refuse("strict merge shard rule is unsupported")
    expected_union = {
        item_id for selected in expected_by_worker for item_id in selected}
    merge_ids = [item_id for item_id in release_ids
                 if item_id in expected_union]

    rows_by_id = {}
    workset_ids = []
    for source in sources:
        if source.context.item_ids != expected_by_worker[source.worker_index]:
            raise _refuse(
                "source workset differs from common selection/shard replay")
        for item_id, row in zip(source.context.item_ids, source.rows):
            if item_id in rows_by_id:
                raise _refuse("strict merge repeats a source result item ID")
            rows_by_id[item_id] = row
            workset_ids.append(item_id)
    if len(workset_ids) != len(set(workset_ids)) \
            or set(workset_ids) != expected_union \
            or len(workset_ids) != len(merge_ids):
        raise _refuse(
            "source worksets do not partition the reconstructed scoped "
            "merge workset exactly")
    result_rows = [rows_by_id[item_id] for item_id in sorted(rows_by_id)]
    result_raw = _merged_rows_bytes(result_rows)
    return _MergeProjection(
        sources=sources, release_reference=copy.deepcopy(release_reference),
        release_ids=release_ids, merge_ids=merge_ids, result_rows=result_rows,
        result_raw=result_raw, campaign=copy.deepcopy(first.context.campaign),
        campaign_digest=campaign_reference["campaign_digest"],
        campaign_semantic_digest=campaign_reference["semantic_digest"],
        pool_digest=first.runtime.pool["digest"], agent_kind=agent_kind)


def _expected_campaign_sidecar(
        projection: _MergeProjection, result_path: str,
        result_sha256: str) -> dict:
    return {
        "campaign": projection.campaign,
        "campaign_digest": projection.campaign_digest,
        "workers": [source.worker_value for source in projection.sources],
        "n": len(projection.merge_ids),
        "rows_path": os.path.basename(result_path),
        "rows_digest": result_sha256[:16],
    }


def _verify_merged_rows_exact(
        rows: list[dict], result_raw: bytes,
        projection: _MergeProjection) -> None:
    """Require complete JSON-value equality and the one strict byte grammar."""
    if len(rows) != len(projection.result_rows):
        raise _refuse("merged row count differs from source workset")
    for index, (actual, expected) in enumerate(
            zip(rows, projection.result_rows)):
        if not _same_json_value(actual, expected):
            raise _refuse(
                f"merged row {index} is not the complete source JSON value")
    if result_raw != projection.result_raw:
        raise _refuse(
            "merged result bytes differ from strict ordering/serialization")


def _verify_merged_output_roles(
        reader: _LiveReader, sources: list[_VerifiedRunShard], *,
        result_path: str, sidecar_path: str, receipt_path: str,
        receipt_is_top_level: bool) -> str:
    """Keep every output/lock role distinct from recursively trusted input."""
    result_path = canonical_absolute_path(
        result_path, "merged result role", live=False)
    sidecar_path = canonical_absolute_path(
        sidecar_path, "merged campaign sidecar role", live=False)
    receipt_path = canonical_absolute_path(
        receipt_path, "merged receipt role", live=False)
    lock_path = canonical_absolute_path(
        result_path + PUBLICATION_LOCK_SUFFIX,
        "merged result lock path", live=False)
    roles = {
        "result": result_path,
        "campaign sidecar": sidecar_path,
        "receipt": receipt_path,
        "result lock": lock_path,
    }
    if len(set(roles.values())) != len(roles):
        raise _refuse("merged output/sidecar/receipt/lock roles collide")
    protected = set(reader.raw_by_path) | set(reader.absent_paths)
    if receipt_is_top_level:
        # The live verifier has already read this receipt, while candidate
        # self-verification has registered the same exact path as absent.
        # It is the sole output role intentionally present in the snapshot.
        protected.discard(receipt_path)
    collisions = sorted(set(roles.values()) & protected)
    if collisions:
        raise _refuse(
            "merged output/sidecar/receipt/lock collides with recursively "
            f"trusted source/reference evidence: {collisions}")
    for source in sources:
        _require_workspace_separation(
            source.runtime.worker.workspace, roles.values(),
            "merged coordinator output/lock")
    return lock_path


def merged_receipt_schema(agent_kind: Optional[str]) -> str:
    """A merge emits the version its homogeneous sources already are."""
    if agent_kind is None:
        return RECEIPT_SCHEMA
    from ..confined import result_ledger_v2 as agent
    return agent.RECEIPT_SCHEMA


def _require_merge_schema_agreement(document: dict,
                                    projection: _MergeProjection) -> None:
    expected = merged_receipt_schema(projection.agent_kind)
    if document["schema"] != expected:
        raise _refuse(
            f"merged receipt schema {document['schema']!r} does not match its "
            f"sources, which require {expected!r}")


def _verify_merged_receipt(
        reader: _LiveReader, document: dict, path: str,
        projections: Optional[list] = None) -> dict:
    result = _receipt_result_path(document, path)
    sources = _load_source_entries(reader, document["source_receipts"])
    sidecar_path = document["campaign_sidecar"]["path"]
    _verify_merged_output_roles(
        reader, sources, result_path=result["path"],
        sidecar_path=sidecar_path, receipt_path=path,
        receipt_is_top_level=True)
    projection = _verify_merge_sources(sources)
    _require_merge_schema_agreement(document, projection)
    if projections is not None:
        projections.append(projection)
    merge = document["merge"]
    expected_merge = {
        "policy": STRICT_MERGE_POLICY,
        "release": projection.release_reference,
        "expected_item_count": len(projection.merge_ids),
        "ordered_item_ids_digest":
            ordered_item_ids_digest(projection.merge_ids),
        "campaign_semantic_digest": projection.campaign_semantic_digest,
        "execution_pool_digest": projection.pool_digest,
    }
    _require_same_json(
        merge, expected_merge,
        "merged receipt merge projection does not reconstruct")
    source_result_paths = {
        source.document["result"]["path"] for source in projection.sources}
    if result["path"] in source_result_paths:
        raise _refuse("merged result path reuses a source result path")
    result_raw, rows = _verify_result_bytes(
        reader, result, "merged result", prefix=False)
    _verify_merged_rows_exact(rows, result_raw, projection)

    sidecar_ref = document["campaign_sidecar"]
    sidecar_path, sidecar_raw = _raw_reference_bytes(
        reader, sidecar_ref, "merged campaign sidecar")
    if sidecar_path != result["path"] + ".campaign.json":
        raise _refuse(
            "merged campaign sidecar path is not derived from result path")
    sidecar = _parse_json_object(sidecar_raw, "merged campaign sidecar")
    expected_sidecar = _expected_campaign_sidecar(
        projection, result["path"], raw_sha256(result_raw))
    _exact_keys(
        sidecar,
        ("campaign", "campaign_digest", "workers", "n", "rows_path",
         "rows_digest"), "merged campaign sidecar")
    _require_same_json(
        sidecar, expected_sidecar,
        "merged campaign sidecar fields do not reconstruct")
    if sidecar_raw != _campaign_sidecar_bytes(expected_sidecar):
        raise _refuse(
            "merged campaign sidecar bytes differ from exact serialization")
    return {
        "source_receipt_paths": [
            source.receipt_path for source in projection.sources],
        "release_path": projection.release_reference["path"],
        "worker_count": len(projection.sources),
        "row_harness_commits": _row_harness_commits(rows, path),
    }


#: `(receipt path, commits)` pairs already noted, so one `results` call that
#: verifies a receipt through several scopes says it once.
_DISCLOSED_ROW_COMMITS: set = set()


def _row_harness_commits(rows: list[dict], path: str) -> list[str]:
    """The distinct commits these rows were produced under, noted when >1."""
    commits = sorted({row.get("harness_commit") for row in rows} - {None})
    key = (path, tuple(commits))
    if len(commits) > 1 and key not in _DISCLOSED_ROW_COMMITS:
        _DISCLOSED_ROW_COMMITS.add(key)
        print(f"note: {os.path.basename(path)} rows carry {len(commits)} "
              f"harness commits: {'|'.join(commits)}",
              file=sys.stderr, flush=True)
    return commits


def _verify_receipt_document(reader: _LiveReader, document: dict, path: str,
                             raw: Optional[bytes],
                             projections: Optional[list] = None) -> dict:
    """Shared complete verifier for live and not-yet-published receipts."""
    artifact_kind = document["artifact_kind"]
    merged_details = None
    shard = None
    if artifact_kind == "merged_run":
        merged_details = _verify_merged_receipt(
            reader, document, path, projections)
    elif artifact_kind == "validation":
        _verify_validation_receipt(reader, document, path)
    else:
        shard = _verify_run_shard_receipt(reader, document, path, raw)
    result = document["result"]
    answer = {
        "artifact_kind": artifact_kind,
        "complete": True,
        "receipt_digest": document["digest"],
        "receipt_path": path,
        "result_file_sha256": result["file_sha256"],
        "result_path": result["path"],
        "row_count": result["row_count"],
        "verified": True,
    }
    if raw is not None:
        answer["receipt_file_sha256"] = raw_sha256(raw)
    if merged_details is not None:
        answer.update(merged_details)
    if shard is not None:
        answer["row_harness_commits"] = _row_harness_commits(shard.rows, path)
    return answer


@dataclass
class PublicationMergePlan:
    """Stable, source-complete byte plan for the I4 merge producer."""
    reader: _LiveReader
    sources: list[_VerifiedRunShard]
    result_path: str
    sidecar_path: str
    receipt_path: str
    lock_path: str
    result_raw: bytes
    sidecar_raw: bytes
    receipt: dict
    receipt_raw: bytes

    def confirm_sources(self) -> None:
        self.reader.confirm()

    @property
    def source_receipt_paths(self) -> list[str]:
        return [source.receipt_path for source in self.sources]


def prepare_publication_merge(
        source_receipt_paths: Iterable[str], *, release_path: str,
        result_path: str, expected_shards: int) -> PublicationMergePlan:
    """Precompute a strict merged tuple without creating an output leaf."""
    expected_shards = _integer(
        expected_shards, "strict merge expected shard count", minimum=1)
    result_path = canonical_absolute_path(
        result_path, "merged result path", live=False)
    release_path = canonical_absolute_path(
        release_path, "strict merge release path")
    reader = _LiveReader()
    sources = _load_source_paths(reader, source_receipt_paths)
    projection = _verify_merge_sources(
        sources, expected_shards=expected_shards)
    if release_path != projection.release_reference["path"]:
        raise _refuse(
            "requested release path differs from source run plans")
    sources = projection.sources
    source_paths = {source.receipt_path for source in sources}
    source_results = {
        source.document["result"]["path"] for source in sources}
    if result_path in source_paths or result_path in source_results:
        raise _refuse("merged result path reuses source evidence")
    sidecar_path = result_path + ".campaign.json"
    receipt_path = result_path + RECEIPT_SUFFIX
    lock_path = _verify_merged_output_roles(
        reader, sources, result_path=result_path, sidecar_path=sidecar_path,
        receipt_path=receipt_path, receipt_is_top_level=False)

    result_sha = raw_sha256(projection.result_raw)
    result = {
        "path": result_path,
        "byte_length": len(projection.result_raw),
        "row_count": len(projection.result_rows),
        "file_sha256": result_sha,
    }
    sidecar = _expected_campaign_sidecar(
        projection, result_path, result_sha)
    sidecar_raw = _campaign_sidecar_bytes(sidecar)
    receipt = {
        "schema": merged_receipt_schema(projection.agent_kind),
        "artifact_kind": "merged_run",
        "merge": {
            "policy": STRICT_MERGE_POLICY,
            "release": projection.release_reference,
            "expected_item_count": len(projection.merge_ids),
            "ordered_item_ids_digest":
                ordered_item_ids_digest(projection.merge_ids),
            "campaign_semantic_digest": projection.campaign_semantic_digest,
            "execution_pool_digest": projection.pool_digest,
        },
        "result": result,
        "campaign_sidecar": {
            "path": sidecar_path,
            "file_sha256": raw_sha256(sidecar_raw),
        },
        "source_receipts": [_source_entry(source) for source in sources],
        "digest": "0" * 64,
    }
    receipt["digest"] = semantic_digest(receipt)
    _validate_any_receipt_schema(receipt)
    receipt_raw = (json.dumps(
        receipt, indent=1, sort_keys=True, ensure_ascii=True,
        allow_nan=False) + "\n").encode("utf-8")
    reader.confirm()
    return PublicationMergePlan(
        reader=reader, sources=sources, result_path=result_path,
        sidecar_path=sidecar_path, receipt_path=receipt_path,
        lock_path=lock_path,
        result_raw=projection.result_raw, sidecar_raw=sidecar_raw,
        receipt=receipt, receipt_raw=receipt_raw)


def _validate_any_receipt_schema(document: object) -> str:
    """Validate an admitted receipt against exactly its own schema file."""
    if not isinstance(document, dict):
        raise _refuse("receipt is not an object")
    schema = document.get("schema")
    if schema == RECEIPT_SCHEMA:
        validate_receipt_schema(document)
        return schema
    # Not the fixture producer's: the agent evidence reader decides, and
    # without it the document cannot be admitted at all.
    try:
        from ..confined import result_ledger_v2 as agent
    except ImportError:
        raise _refuse(
            f"receipt schema {schema!r} is not the fixture producer's, and "
            f"the agent evidence reader (r2t.confined.result_ledger_v2) is not "
            f"shipped in this checkout")
    if schema == agent.RECEIPT_SCHEMA:
        agent.validate_receipt_schema(document)
    else:
        raise _refuse(f"receipt schema {schema!r} is unsupported")
    return schema


def verify_receipt_document(document: object, path: str) -> dict:
    """Self-verify a complete receipt while its no-clobber path is absent."""
    _validate_any_receipt_schema(document)
    _verify_digest(document, label="result receipt")
    path = canonical_absolute_path(path, "receipt path", live=False)
    reader = _LiveReader()
    reader.require_absent(path, "not-yet-published result receipt")
    answer = _verify_receipt_document(reader, document, path, None)
    reader.confirm()
    return answer


def verify_receipt(path: str) -> dict:
    """Completely verify one admitted live receipt without Docker contact."""
    reader = _LiveReader()
    document, raw = _load_ledger_document(reader, path, checkpoint=False)
    answer = _verify_receipt_document(reader, document, path, raw)
    reader.confirm()
    return answer


def validate_bundle_index_document(document: object) -> str:
    """Validate I1's bundle-index structure/digest without opening I6 CAS."""
    validate_bundle_index_schema(document)
    if not isinstance(document, dict) or document.get("schema") \
            != BUNDLE_INDEX_SCHEMA:
        raise _refuse("bundle-index schema is unsupported")
    _verify_digest(document, label="publication bundle index")
    roots = document["root_receipts"]
    keys = [(root["artifact_kind"], root["receipt_file_sha256"],
             root["receipt_digest"]) for root in roots]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise _refuse("bundle-index roots are not sorted and unique")
    return document["digest"]


# --------------------------------------------- I5 reviewed Git blob authority
#: I5 adds NO Git authority model.  `r2t.core.reviewed_git` is the one model in the
#: tree -- the compute-cap path/mode resolver and the C5/J0 hardened offline
#: invocation, extracted so that `test_quality` and this module run the same
#: code -- and everything below is the ledger's diagnostic wrapper over it.
REVIEWED_PATH_MAX_LENGTH = reviewed_git.PATH_MAX_LENGTH


def reviewed_repository_root() -> str:
    """The source-derived repository two directories above this package."""
    return reviewed_git.repository_root()


def validate_reviewed_path(value: object, label: str) -> str:
    """Replay the reviewed repository-relative POSIX authority grammar."""
    try:
        return reviewed_git.validate_path(value)
    except reviewed_git.ReviewedGitRefused as exc:
        raise _refuse(f"{label} {exc.detail}") from exc


def validate_reviewed_commit(value: object, label: str) -> str:
    if not isinstance(value, str) or _COMMIT_RE.fullmatch(value) is None:
        raise _refuse(f"{label} is not one full 40-lowercase-hex commit")
    return value


#: Which reviewed-authority refusal code produces which ledger diagnostic.
_REVIEWED_GIT_DIAGNOSTIC = {
    "git_exec": "cannot be locally resolved",
    "repository": "is not read from the source-derived reviewed repository",
    "commit": "does not name a locally recoverable commit",
    "entry": "does not select exactly one tree entry",
    "mode": "is not one regular-file blob at that exact commit",
    "blob": "names a blob object that is not locally readable",
}


def reviewed_blob_bytes(commit: str, reviewed_path: str, *,
                        label: str) -> bytes:
    """Read the one reviewed regular-file blob a commit/path pair names."""
    commit = validate_reviewed_commit(commit, f"{label} commit")
    reviewed_path = validate_reviewed_path(reviewed_path, f"{label} path")
    # Resolved HERE rather than inside the shared helper: the repository is
    # this module's answer to "which repository", and a source-only test that
    # supplies a private one substitutes exactly this function.
    repository = reviewed_repository_root()
    try:
        return reviewed_git.blob_bytes(
            commit, reviewed_path, repository=repository)
    except reviewed_git.ReviewedGitRefused as exc:
        raise _refuse(
            f"{label} {_REVIEWED_GIT_DIAGNOSTIC[exc.code]}: "
            f"{exc.detail}") from exc


# ------------------------------------------------ I5 publication consumers
PUBLICATION_STATUS_SCHEMA = "r2t.publication-consumer-status/v1"
PUBLICATION_STATUS_SUFFIX = ".publication-v3-status.json"
PUBLICATION_CLAIM = "r2t.full-receipt-worksets/v1"
#: The v2 agent receipt schema I5 admits under the producer proposal's
#: section 9.  I5 implements the admission vectors only; the v2 producer and
#: its recursive verifier remain closed to the later agent-producer stage.
AGENT_RECEIPT_SCHEMA = "r2t.result-ledger/v2"
PUBLICATION_CONSUMERS = ("report", "results", "compare")
PUBLICATION_ROLE_FIELDS = ("receipt_path", "reviewed_path", "role")
PUBLICATION_RESULT_FIELDS = ("path", "byte_length", "row_count", "file_sha256")
PUBLICATION_WORKSET_FIELDS = ("item_count", "ordered_item_ids_digest")
PUBLICATION_OUTPUT_FIELDS = ("path", "byte_length", "file_sha256")
PUBLICATION_STATUS_FIELDS = (
    "schema", "consumer", "claim", "reviewed_commit", "parameters", "roles",
    "output", "digest",
)
PUBLICATION_STATUS_ROLE_FIELDS = (
    "role", "receipt_path", "reviewed_path", "receipt_file_sha256",
    "receipt_digest", "result", "workset",
)
PUBLICATION_PARAMETER_FIELDS = {
    "report": ("per_item",),
    "results": ("format",),
    "compare": ("gold_dir", "metric"),
}
PUBLICATION_RESULTS_FORMATS = ("text", "json", "markdown", "markdown-legacy")
_CONSUMER_ROLE_NAMES = {
    "results": ("results-candidate", "results-gold"),
    "compare": ("compare-A", "compare-B", "compare-gold"),
}
_SUBSTRATE_CAMPAIGN_FIELDS = (
    "schema", "k_workers", "shard_rule", "coverage", "harness_version",
    "config_digest", "container_image_digest", "workspace_seed_digest",
    "database_dump_digest",
)
_SUBSTRATE_IDENTITY_FIELDS = (
    "container_image_digest", "seed_dir", "seed_manifest", "seed_key",
    "workspace_seed_digest", "database_dump_digest", "needs_database",
)
_SUBSTRATE_STAMP_NAMES = (
    "coverage", "dataset_version", "execution_timeout_seconds",
    "harness_version", "of", "repeats",
    "repro_check_count", "subset_digest", "subset_id",
)
_SUBSTRATE_INPUT_ROLES = frozenset({
    "harness_strip_manifest", "harness_feature", "harness_alias_table",
    "harness_autowirable_types",
})
_ROLE_LOCAL_WORKER_SPEC_FIELDS = (
    "workspace", "container", "env_file", "out_path", "artifacts_root",
)
_AGENT_PROTOCOL_REMOVED = (
    "protocol_version", "condition", "trials", "max_iterations",
    "temperature", "native_knobs", "comparison_class", "notes",
)
_AGENT_STAMP_NAMES = (
    "agent_timeout_seconds", "protocol_deviations", "sandboxed", "setting",
)
_GOLD_MANIFEST_LOGICAL = "gold/manifest.json"


def parse_publication_role(token: object) -> dict:
    """Parse one closed `--publication-role` token; order carries no meaning."""
    if not isinstance(token, str):
        raise _refuse("publication role token is not a string")
    record = _exact_keys(
        loads_exact_json(token, label="publication role"),
        PUBLICATION_ROLE_FIELDS, "publication role")
    for field in PUBLICATION_ROLE_FIELDS:
        if not isinstance(record[field], str):
            raise _refuse(f"publication role {field} is not a string")
    return {
        "role": record["role"],
        "receipt_path": canonical_absolute_path(
            record["receipt_path"], "publication role receipt_path"),
        "reviewed_path": validate_reviewed_path(
            record["reviewed_path"], "publication role reviewed_path"),
    }


def publication_role_names(consumer: str, run_count: int) -> tuple:
    """The exact role names section 2.2 requires for one request."""
    if consumer not in PUBLICATION_CONSUMERS:
        raise _refuse(f"publication consumer {consumer!r} is not opened")
    if consumer == "report":
        if run_count < 1:
            raise _refuse("publication report needs at least one --run")
        return tuple(f"report-run:{index}" for index in range(run_count))
    expected = 1 if consumer == "results" else 2
    if run_count != expected:
        raise _refuse(
            f"publication {consumer} needs exactly {expected} --run "
            f"occurrence(s)")
    return _CONSUMER_ROLE_NAMES[consumer]


@dataclass
class PublicationRoleEvidence:
    """One reclosed merged-run role plus the projections a consumer needs."""
    role: str
    receipt_path: str
    reviewed_path: str
    receipt_file_sha256: str
    receipt_digest: str
    schema: str
    source_schemas: tuple
    result: dict
    workset: dict
    item_ids: tuple
    adapter_kind: str
    comparison_class: object
    release_reference: dict
    substrate: dict
    #: The already verified documents section 5.1's agent-control projection
    #: is derived FROM, kept rather than the projection itself.  Deriving it
    #: for every role would impose the agent-only closed members -- campaign
    #: `network_semantics`' agent reading, `environment_controls`, and the
    #: `sitecustomize_sha256` contamination control -- on a gold or fixture
    #: role that has no agent to control.  Section 5.1 requires the
    #: projection only BETWEEN two admitted agent outcome roles, so it is
    #: derived exactly there.
    agent_control_inputs: dict
    gold_manifest: Optional[dict]
    gold_records: dict
    input_bytes: dict
    present_paths: tuple
    absent_paths: tuple


def _publication_substrate(projection: _MergeProjection) -> dict:
    """Section 5.1's closed common-substrate projection for one merged role."""
    first = projection.sources[0]
    plan = first.document["plan"]
    invocation = plan["invocation"]
    campaign = first.context.campaign
    identity = first.runtime.identity
    pool = first.runtime.pool
    workers = []
    for source in projection.sources:
        spec = copy.deepcopy(source.runtime.runtime["worker"])
        for field in _ROLE_LOCAL_WORKER_SPEC_FIELDS:
            del spec[field]
        binding = source.runtime.binding
        container = binding["container"]
        workers.append({
            "worker_spec": spec,
            "binding_schema": binding["schema"],
            "binding_worker_index": binding["worker_index"],
            "container_image_id": container["image_id"],
            "container_running": container["running"],
            "container_host_network_mode": container["host_network_mode"],
            "container_network_attachments": [
                {key: value for key, value in attachment.items()
                 if key != "id"}
                for attachment in container["network_attachments"]],
            "network_policy": {
                key: value for key, value in binding["network_policy"].items()
                if key != "id"},
            "egress_probe": binding["egress_probe"],
        })
    return {
        # Each reference carries the exact file SHA-256 the verifier already
        # proved, so reference equality is verified-document equality.
        "release": plan["release"],
        "boundary": plan["boundary"],
        "profile": plan["profile"],
        "campaign": {
            name: campaign[name] for name in _SUBSTRATE_CAMPAIGN_FIELDS},
        "campaign_agent_runtime_schema": first.context.agent_runtime["schema"],
        "docker_authority": first.runtime.authority,
        "docker_daemon_fingerprint_sha256":
            identity["docker_daemon_fingerprint_sha256"],
        "pool": {
            "schema": pool["schema"],
            "database": pool["database"],
            "network": pool["network"],
            "worker_count": len(pool["workers"]),
            "workers": workers,
        },
        "runtime_identity": {
            **{name: identity[name] for name in _SUBSTRATE_IDENTITY_FIELDS},
            "harness_version": identity["harness"]["version"],
        },
        "resume": invocation["resume"],
        "effective_run_stamp": {
            name: first.context.stamp[name]
            for name in _SUBSTRATE_STAMP_NAMES},
        "harness_inputs": sorted(
            [entry["role"], entry["logical_path"], entry["byte_length"],
             entry["file_sha256"]]
            for source in projection.sources
            for entry in source.document["plan"]["invocation"]["adapter"][
                "files"]
            if entry["role"] in _SUBSTRATE_INPUT_ROLES),
    }


def publication_agent_control(protocol: dict, campaign: dict,
                              agent_runtime: dict, stamp: dict) -> dict:
    """Section 5.1's agent-control projection between two agent roles."""
    if not isinstance(protocol, dict):
        raise _refuse("admitted agent role carries no verified protocol")
    document = copy.deepcopy(protocol)
    for name in _AGENT_PROTOCOL_REMOVED:
        if name not in document:
            raise _refuse(f"agent protocol omits closed member {name}")
        del document[name]
    prompt_profile = document["prompt_profile"]
    if "arm_prompt_key" not in prompt_profile:
        raise _refuse("agent protocol prompt_profile omits arm_prompt_key")
    del prompt_profile["arm_prompt_key"]
    versions = agent_runtime["agent_versions"]
    if "sitecustomize_sha256" not in versions:
        raise _refuse(
            "agent runtime omits the sitecustomize contamination control")
    sitecustomize = versions["sitecustomize_sha256"]
    if sitecustomize is not None:
        _sha256(sitecustomize, "agent_versions.sitecustomize_sha256")
    return {
        "protocol": document,
        "campaign_network_semantics": campaign["network_semantics"],
        "agent_runtime_environment_controls":
            agent_runtime["environment_controls"],
        "agent_runtime_network_semantics": agent_runtime["network_semantics"],
        "sitecustomize_sha256": sitecustomize,
        "effective_run_stamp": {
            name: stamp[name] for name in _AGENT_STAMP_NAMES},
    }


def _publication_gold_inputs(projection: _MergeProjection) -> tuple:
    """The already verified `release_gold_*` transitive input projection."""
    manifest = None
    records: dict = {}
    for source in projection.sources:
        files = source.document["plan"]["invocation"]["adapter"]["files"]
        for entry in files:
            identity = {
                "path": entry["path"], "byte_length": entry["byte_length"],
                "file_sha256": entry["file_sha256"]}
            if entry["role"] == "release_gold_manifest":
                if entry["logical_path"] != _GOLD_MANIFEST_LOGICAL:
                    raise _refuse(
                        "release gold manifest logical path is not exact")
                if manifest is not None \
                        and not _same_json_value(manifest, identity):
                    raise _refuse(
                        "release gold manifest input identities conflict")
                manifest = identity
            elif entry["role"] == "release_gold_record":
                logical = entry["logical_path"]
                if logical in records \
                        and not _same_json_value(records[logical], identity):
                    raise _refuse(
                        "release gold record input identities conflict")
                records[logical] = identity
    return manifest, records


def _publication_role_evidence(record: dict, commit: str) \
        -> PublicationRoleEvidence:
    """Run section 4's six preflight steps over one explicit role record."""
    receipt_path = record["receipt_path"]
    reader = _LiveReader()
    document, raw = _load_ledger_document(reader, receipt_path,
                                          checkpoint=False)
    blob = reviewed_blob_bytes(
        commit, record["reviewed_path"], label="publication reviewed receipt")
    if blob != raw:
        raise _refuse(
            "live publication receipt bytes differ from the reviewed blob")
    if document["artifact_kind"] != "merged_run":
        raise _refuse(
            "publication role receipt is not a complete merged_run receipt")
    projections: list = []
    _verify_receipt_document(reader, document, receipt_path, raw, projections)
    projection = projections[0]
    reader.confirm()

    result = _exact_keys(
        document["result"], PUBLICATION_RESULT_FIELDS,
        "publication role result")
    merge = document["merge"]
    workset = {
        "item_count": merge["expected_item_count"],
        "ordered_item_ids_digest": merge["ordered_item_ids_digest"],
    }
    if result["row_count"] != workset["item_count"]:
        raise _refuse(
            "publication role row count differs from its merged workset")
    first = projection.sources[0]
    adapter = first.document["plan"]["invocation"]["adapter"]
    gold_manifest, gold_records = _publication_gold_inputs(projection)
    return PublicationRoleEvidence(
        role=record["role"], receipt_path=receipt_path,
        reviewed_path=record["reviewed_path"],
        receipt_file_sha256=raw_sha256(raw),
        receipt_digest=document["digest"],
        schema=document["schema"],
        source_schemas=tuple(
            source.document["schema"] for source in projection.sources),
        result=dict(result), workset=workset,
        item_ids=tuple(projection.merge_ids),
        adapter_kind=adapter["kind"],
        comparison_class=first.context.stamp["comparison_class"],
        release_reference=projection.release_reference,
        substrate=_publication_substrate(projection),
        agent_control_inputs={
            "protocol": first.context.protocol,
            "campaign": first.context.campaign,
            "agent_runtime": first.context.agent_runtime,
            "stamp": first.context.stamp,
        },
        gold_manifest=gold_manifest, gold_records=gold_records,
        input_bytes=dict(reader.raw_by_path),
        present_paths=tuple(sorted(reader.raw_by_path)),
        absent_paths=tuple(sorted(reader.absent_paths)),
    )


def _require_admitted_schema_vector(consumer: str, roles: list) -> None:
    """Apply the producer proposal's section 9 v1/v2 admission vectors."""
    for role in roles:
        if role.schema == RECEIPT_SCHEMA:
            continue
        if role.schema != AGENT_RECEIPT_SCHEMA:
            raise _refuse(
                f"publication role receipt schema {role.schema!r} is not "
                f"admitted")
        if set(role.source_schemas) != {AGENT_RECEIPT_SCHEMA}:
            raise _refuse(
                "admitted v2 merged role does not have homogeneous agent-v2 "
                "sources")
    if consumer == "report":
        return
    vector = [role.schema for role in roles]
    if consumer == "results":
        admitted = ([RECEIPT_SCHEMA, RECEIPT_SCHEMA],
                    [AGENT_RECEIPT_SCHEMA, RECEIPT_SCHEMA])
    else:
        admitted = ([RECEIPT_SCHEMA, RECEIPT_SCHEMA, RECEIPT_SCHEMA],
                    [AGENT_RECEIPT_SCHEMA, AGENT_RECEIPT_SCHEMA,
                     RECEIPT_SCHEMA])
    if vector not in admitted:
        raise _refuse(
            f"publication {consumer} v1/v2 role vector {vector} is not one "
            f"of the admitted vectors")


def _require_common_substrate(roles: list) -> None:
    first = roles[0]
    for role in roles[1:]:
        _require_same_json(
            role.substrate, first.substrate,
            f"publication roles {first.role} and {role.role} differ in the "
            f"common substrate projection")


def _require_same_scope(roles: list) -> None:
    first = roles[0]
    for role in roles[1:]:
        _require_same_json(
            role.workset, first.workset,
            f"publication roles {first.role} and {role.role} have different "
            f"complete worksets")
        if set(role.item_ids) != set(first.item_ids):
            raise _refuse(
                f"publication roles {first.role} and {role.role} cover "
                f"different actual item IDs")
        _require_same_json(
            role.release_reference, first.release_reference,
            f"publication roles {first.role} and {role.role} cite different "
            f"merged releases")


def _require_agent_control_pair(roles: list) -> None:
    """Section 5.1's agent-control equality between compare's two arms.

    The producer proposal's section 9 gives this rule exactly one vector --
    `[v2 agent A, v2 agent B, v1 gold]` -- so the projection is DERIVED here,
    from each arm's own verified protocol, campaign, campaign-agent-runtime
    and effective stamp, rather than carried on the role.  A v1 pair has no
    agent to control and is left alone; gold is never asked to pretend it ran
    an agent protocol.
    """
    if roles[0].schema != AGENT_RECEIPT_SCHEMA \
            or roles[1].schema != AGENT_RECEIPT_SCHEMA:
        return
    first, second = (publication_agent_control(**role.agent_control_inputs)
                     for role in roles[:2])
    _require_same_json(
        first, second,
        "compare agent arms differ in the agent-control projection")


def _require_gold_role(role: PublicationRoleEvidence) -> None:
    if role.adapter_kind != "gold":
        raise _refuse(
            f"publication role {role.role} is adapter kind "
            f"{role.adapter_kind!r}, not the gold oracle")


def publication_preflight(consumer: str, role_tokens, *, commit: str,
                          run_paths, gold_path: Optional[str] = None) -> list:
    """The shared six-step preflight, in the canonical role order."""
    commit = validate_reviewed_commit(commit, "--publication-commit")
    runs = [canonical_absolute_path(path, "publication --run")
            for path in run_paths]
    inputs = list(runs)
    if consumer == "results":
        inputs.append(canonical_absolute_path(
            gold_path, "publication --gold"))
    elif gold_path is not None:
        raise _refuse("only publication results binds an explicit --gold run")
    if len(set(inputs)) != len(inputs):
        raise _refuse("publication inputs repeat one canonical result path")

    expected = publication_role_names(consumer, len(runs))
    records = [parse_publication_role(token) for token in role_tokens]
    for field in PUBLICATION_ROLE_FIELDS:
        values = [record[field] for record in records]
        if len(set(values)) != len(values):
            raise _refuse(f"publication role records repeat one {field}")
    if sorted(record["role"] for record in records) != sorted(expected):
        raise _refuse(
            f"publication {consumer} requires exactly the roles "
            f"{list(expected)}")

    evidence = {record["role"]: _publication_role_evidence(record, commit)
                for record in records}
    roles = [evidence[name] for name in expected]
    outcome_roles = roles[:-1] if consumer == "compare" else roles
    for role, path in zip(outcome_roles, inputs):
        if role.result["path"] != path:
            raise _refuse(
                f"publication role {role.role} verifies result "
                f"{role.result['path']} but its input names {path}")
    if consumer == "compare" and roles[-1].result["path"] in set(inputs):
        raise _refuse(
            "compare-gold is an authority role, never a third outcome arm")
    _require_admitted_schema_vector(consumer, roles)
    _require_common_substrate(roles)
    if consumer == "results":
        _require_same_scope(roles)
        _require_gold_role(roles[1])
    if consumer == "compare":
        _require_same_scope(roles)
        _require_gold_role(roles[2])
        if not _same_json_value(roles[0].comparison_class,
                                roles[1].comparison_class):
            raise _refuse("compare A and B record different comparison_class")
        _require_agent_control_pair(roles)
    return roles


def publication_gold_clusters(role: PublicationRoleEvidence, gold_dir: str,
                              item_ids) -> dict:
    """Derive section 5.4's cluster map from receipt-bound gold bytes only."""
    from ..data.release import cluster_id
    gold_dir = canonical_absolute_path(gold_dir, "publication --gold-dir")
    if role.gold_manifest is None:
        raise _refuse("compare-gold receipt carries no release gold manifest")
    manifest_path = gold_dir + "/manifest.json"
    if role.gold_manifest["path"] != manifest_path:
        raise _refuse(
            "compare-gold manifest input is not the explicit --gold-dir "
            "manifest")
    manifest = _parse_json_object(
        role.input_bytes[manifest_path], "release gold manifest")
    clusters = {}
    selected = set()
    for item_id in item_ids:
        if item_id not in manifest:
            raise _refuse(
                f"release gold manifest omits workset item {item_id!r}")
        name = _safe_relative(manifest[item_id], "release gold sidecar name")
        logical = "gold/" + name
        record = role.gold_records.get(logical)
        if record is None:
            raise _refuse(
                f"compare-gold closure omits the record for {item_id!r}")
        if record["path"] != gold_dir + "/" + name:
            raise _refuse(
                "compare-gold record input is outside the explicit --gold-dir")
        selected.add(logical)
        document = _parse_json_object(
            role.input_bytes[record["path"]], "release gold record")
        clusters[item_id] = cluster_id(document["files"])
    if selected != set(role.gold_records):
        raise _refuse(
            "compare-gold closure selects an extra receipted gold record")
    return clusters


# ------------------------------------------- I5 status document and channel
def publication_status_bytes(status: Mapping[str, object]) -> bytes:
    try:
        return (json.dumps(
            status, indent=1, sort_keys=True, ensure_ascii=True,
            allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _refuse(
            f"publication status is not exact JSON encodable: {exc}") from exc


def _publication_status_role(role: PublicationRoleEvidence) -> dict:
    return {
        "role": role.role,
        "receipt_path": role.receipt_path,
        "reviewed_path": role.reviewed_path,
        "receipt_file_sha256": role.receipt_file_sha256,
        "receipt_digest": role.receipt_digest,
        "result": dict(role.result),
        "workset": dict(role.workset),
    }


def _validate_publication_parameters(consumer: str, parameters: object) -> dict:
    fields = PUBLICATION_PARAMETER_FIELDS[consumer]
    values = _exact_keys(parameters, fields, f"{consumer} parameters")
    if consumer == "report":
        if not isinstance(values["per_item"], bool):
            raise _refuse("report parameter per_item is not Boolean")
    elif consumer == "results":
        if values["format"] not in PUBLICATION_RESULTS_FORMATS:
            raise _refuse("results parameter format is not an existing format")
    else:
        if values["metric"] != "pass":
            raise _refuse("compare parameter metric is not exactly 'pass'")
        canonical_absolute_path(values["gold_dir"], "compare parameter gold_dir")
    return values


def build_publication_status(consumer: str, roles: list, parameters: dict,
                             commit: str, output: dict) -> dict:
    status = {
        "schema": PUBLICATION_STATUS_SCHEMA,
        "consumer": consumer,
        "claim": PUBLICATION_CLAIM,
        "reviewed_commit": commit,
        "parameters": _validate_publication_parameters(consumer, parameters),
        "roles": [_publication_status_role(role) for role in roles],
        "output": _exact_keys(
            output, PUBLICATION_OUTPUT_FIELDS, "publication status output"),
        "digest": "0" * 64,
    }
    status["digest"] = semantic_digest(status)
    return status


def _validate_publication_status_document(document: object,
                                          status_path: str) -> dict:
    status = _exact_keys(
        document, PUBLICATION_STATUS_FIELDS, "publication status")
    if status["schema"] != PUBLICATION_STATUS_SCHEMA:
        raise _refuse("publication status schema is unsupported")
    if status["claim"] != PUBLICATION_CLAIM:
        raise _refuse("publication status claim is unsupported")
    consumer = status["consumer"]
    if consumer not in PUBLICATION_CONSUMERS:
        raise _refuse("publication status names an unopened consumer")
    validate_reviewed_commit(
        status["reviewed_commit"], "publication status reviewed_commit")
    _validate_publication_parameters(consumer, status["parameters"])
    roles = status["roles"]
    if not isinstance(roles, list) or not roles:
        raise _refuse("publication status has no roles")
    names = []
    for entry in roles:
        role = _exact_keys(
            entry, PUBLICATION_STATUS_ROLE_FIELDS, "publication status role")
        names.append(role["role"])
        canonical_absolute_path(
            role["receipt_path"], "status role receipt_path", live=False)
        validate_reviewed_path(
            role["reviewed_path"], "status role reviewed_path")
        _sha256(role["receipt_file_sha256"], "status role receipt_file_sha256")
        _sha256(role["receipt_digest"], "status role receipt_digest")
        result = _exact_keys(
            role["result"], PUBLICATION_RESULT_FIELDS, "status role result")
        canonical_absolute_path(result["path"], "status role result path",
                                live=False)
        _integer(result["byte_length"], "status role result byte_length")
        _sha256(result["file_sha256"], "status role result file_sha256")
        workset = _exact_keys(
            role["workset"], PUBLICATION_WORKSET_FIELDS,
            "status role workset")
        _sha256(workset["ordered_item_ids_digest"],
                "status role ordered_item_ids_digest")
        if _integer(result["row_count"], "status role result row_count") \
                != _integer(workset["item_count"], "status role item_count"):
            raise _refuse("status role row count differs from its workset")
        if role["receipt_path"] != result["path"] + RECEIPT_SUFFIX:
            raise _refuse("status role receipt path is not ledger-derived")
    run_count = len(names) - 1 if consumer == "compare" else (
        len(names) if consumer == "report" else 1)
    if names != list(publication_role_names(consumer, run_count)):
        raise _refuse("publication status roles are not the canonical order")
    output = _exact_keys(
        status["output"], PUBLICATION_OUTPUT_FIELDS, "publication status output")
    output_path = canonical_absolute_path(
        output["path"], "publication status output path", live=False)
    _integer(output["byte_length"], "publication status output byte_length")
    _sha256(output["file_sha256"], "publication status output file_sha256")
    if status_path != output_path + PUBLICATION_STATUS_SUFFIX:
        raise _refuse("publication status path is not derived from its output")
    _sha256(status["digest"], "publication status digest")
    _verify_digest(status, label="publication status")
    return status


def verify_publication_status(status_path: str) -> dict:
    """Offline verifier: one status, its exact bytes, and its bound output."""
    status_path = canonical_absolute_path(status_path, "publication status path")
    reader = _LiveReader()
    raw = reader.read(status_path, "publication status")
    status = _validate_publication_status_document(
        loads_exact_json(raw, label="publication status"), status_path)
    if raw != publication_status_bytes(status):
        raise _refuse(
            "publication status bytes differ from the exact serialization")
    output = status["output"]
    output_raw = reader.read(output["path"], "publication output")
    if len(output_raw) != output["byte_length"] \
            or raw_sha256(output_raw) != output["file_sha256"]:
        raise _refuse("publication status does not bind the live output bytes")
    reader.confirm()
    return status


def _publication_fsync_existing_status(status_path: str) -> None:
    """Finish a committed status leaf's file/directory durability.

    Section 7.2's status create commit point is the no-clobber rename, which
    precedes the directory `fsync`.  A fault, readback failure, or process
    death in that window leaves a committed status whose dentry may live only
    in cache, so the resolution that decides to answer with it must make it
    durable before promising completion.  This is the same duty runner's
    `_publication_fsync_existing_receipt` performs one layer down.
    """
    before = _trusted_leaf(status_path, "publication status")
    parent = os.path.dirname(status_path)
    parent_fd = _open_directory_nofollow(parent, "publication status parent")
    fd = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) \
            | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(os.path.basename(status_path), flags, dir_fd=parent_fd)
        opened = os.fstat(fd)
        if _stat_identity(before) != _stat_identity(opened):
            raise _refuse(
                "publication status changed before durability recovery")
        os.fsync(fd)
        synced = os.fstat(fd)
        current = os.stat(
            os.path.basename(status_path), dir_fd=parent_fd,
            follow_symlinks=False)
        if len({_stat_identity(value) for value in (
                before, opened, synced, current)}) != 1:
            raise _refuse(
                "publication status changed during durability recovery")
        os.fsync(parent_fd)
    except OSError as exc:
        raise _refuse(
            f"cannot complete publication status durability: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)
    after = _trusted_leaf(status_path, "publication status")
    if _stat_identity(after) != _stat_identity(before):
        raise _refuse(
            "publication status changed after durability recovery")


def _publication_output_paths(out_path: str, roles: list) -> tuple:
    """Derive the three path roles and prove they collide with no evidence."""
    out_path = canonical_absolute_path(
        out_path, "publication --out", live=False)
    status_path = out_path + PUBLICATION_STATUS_SUFFIX
    lock_path = out_path + PUBLICATION_LOCK_SUFFIX
    derived = (out_path, status_path, lock_path)
    if len(set(derived)) != 3:
        raise _refuse("publication output, status, and lock are not distinct")
    closure = set()
    for role in roles:
        closure.update(role.present_paths)
        closure.update(role.absent_paths)
        closure.add(role.receipt_path)
        closure.add(role.result["path"])
    for path in derived:
        if path in closure:
            raise _refuse(
                f"publication path {path} collides with a verified closure "
                f"member")
    return derived


def _publication_status_matches(status: dict, consumer: str, roles: list,
                                parameters: dict, commit: str) -> bool:
    return (status["consumer"] == consumer
            and status["reviewed_commit"] == commit
            and _same_json_value(status["parameters"], parameters)
            and _same_json_value(
                status["roles"],
                [_publication_status_role(role) for role in roles]))


def _publication_resolve(status_path: str, out_path: str, consumer: str,
                         roles: list, parameters: dict,
                         commit: str) -> Optional[dict]:
    """Status-first tuple resolution; a present output alone burns the path."""
    if os.path.lexists(status_path):
        status = verify_publication_status(status_path)
        if not _publication_status_matches(
                status, consumer, roles, parameters, commit):
            raise _refuse(
                "the present publication status describes another request")
        # Section 7.2: a verifier-valid exact pair is authoritative, so the
        # promise of completion is made durable here -- confirm the committed
        # status leaf and its parent directory, then verify the pair AGAIN
        # and answer with what survived the confirmation.
        _publication_fsync_existing_status(status_path)
        confirmed = verify_publication_status(status_path)
        if not _same_json_value(confirmed, status):
            raise _refuse(
                "publication status changed across durability recovery")
        return confirmed
    if os.path.lexists(out_path):
        raise _refuse(
            "a complete but unclaimed publication output burns this path; a "
            "retry uses a new output")
    return None


def publish_consumer_output(*, consumer: str, roles: list, parameters: dict,
                            commit: str, out_path: str,
                            render: Callable[[], str],
                            reclose: Callable[[], list],
                            fault: Optional[Callable[[str], None]] = None) \
        -> dict:
    """Render in memory, then create the output and, last, its status."""
    from . import runner
    parameters = _validate_publication_parameters(consumer, parameters)
    out_path, status_path, lock_path = _publication_output_paths(
        out_path, roles)
    expected_roles = [_publication_status_role(role) for role in roles]
    if os.path.lexists(lock_path):
        with runner._PublicationResultLock(out_path, create=False):
            existing = _publication_resolve(
                status_path, out_path, consumer, roles, parameters, commit)
    else:
        existing = _publication_resolve(
            status_path, out_path, consumer, roles, parameters, commit)
    if existing is not None:
        return existing

    with runner._PublicationResultLock(out_path) as lock:
        existing = _publication_resolve(
            status_path, out_path, consumer, roles, parameters, commit)
        if existing is not None:
            return existing
        lock.confirm()
        fresh = reclose()
        _require_same_json(
            [_publication_status_role(role) for role in fresh],
            expected_roles,
            "publication role evidence changed before the durable write")
        if _publication_output_paths(out_path, fresh) \
                != (out_path, status_path, lock_path):
            raise _refuse("publication path roles changed under the lock")
        payload = render().encode("utf-8")
        status = build_publication_status(
            consumer, fresh, parameters, commit,
            {"path": out_path, "byte_length": len(payload),
             "file_sha256": raw_sha256(payload)})
        status_raw = publication_status_bytes(status)
        _validate_publication_status_document(
            loads_exact_json(status_raw, label="publication status"),
            status_path)
        lock.confirm()
        _fault(fault, "publication:before_output_create")
        durable_create_bytes_no_clobber(
            out_path, payload, label="publication output", fault=fault)
        _fault(fault, "publication:after_output_create")
        reclose()
        if read_trusted_bytes(out_path, label="publication output") != payload:
            raise _refuse("durable publication output lost its exact bytes")
        lock.confirm()
        durable_create_bytes_no_clobber(
            status_path, status_raw, label="publication status", fault=fault)
        _fault(fault, "publication:after_status_create")
    return verify_publication_status(status_path)


# ----------------------------------------------------------- source selftest
def _selftest_write(path: str, value, *, raw: bool = False) -> bytes:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    if raw:
        data = value
    else:
        data = (json.dumps(value, indent=1, sort_keys=True,
                           ensure_ascii=True, allow_nan=False) + "\n").encode()
    with open(path, "wb") as fh:
        fh.write(data)
    os.chmod(path, 0o600)
    return data


def _selftest_raw_ref(path: str, raw: Optional[bytes] = None) -> dict:
    if raw is None:
        with open(path, "rb") as fh:
            raw = fh.read()
    return {"path": path, "file_sha256": raw_sha256(raw)}


def _selftest_input(role: str, logical: str, path: str) -> dict:
    with open(path, "rb") as fh:
        raw = fh.read()
    return {
        "role": role, "logical_path": logical, "path": path,
        "byte_length": len(raw), "file_sha256": raw_sha256(raw),
    }


def _build_selftest_fixture(root: str, *, database: bool = False) -> dict:
    """Create synthetic private evidence; never a canonical benchmark artifact."""
    from . import campaign
    from .. import docker_authority as authority
    from . import worker
    from ..data.profile import load_profile
    from .validate import HARNESS_VERSION

    root = canonical_absolute_path(os.path.realpath(root), "fixture root")
    for name in ("workspace/features", "artifacts", "gold", "seed", "runs",
                 "workers", "secrets"):
        path = root + "/" + name
        os.makedirs(path, mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
    result_path = root + "/runs/shard0.jsonl"
    worker_manifest_path = root + "/runs/shard0.worker.json"
    workspace = root + "/workspace"
    artifacts = root + "/artifacts"
    gold_root = root + "/gold"
    seed_dir = root + "/seed"
    feature_path = workspace + "/features/example.feature"
    feature_raw = _selftest_write(
        feature_path, b"Feature: fixture\n  Scenario: one\n    Given a fixture\n",
        raw=True)
    archive_members = {"features/example.feature": feature_raw}
    for number in range(5):
        relative = f"features/example{number}.feature"
        archive_members[relative] = feature_raw
    # The real Cucumber lifecycle fixture maps two selected examples beneath
    # its runtime source tree. Keep the worker seed's immutable originals at
    # those same paths so dirty-resume reconstruction exercises the production
    # archive authority rather than a test-only copy.
    for number in (0, 4):
        relative = f"src/test/resources/example{number}.feature"
        archive_members[relative] = feature_raw

    benchmark_root = BENCHMARK_ROOT
    source_boundary = benchmark_root + "/config/boundary_python_docx.yml"
    source_profile = benchmark_root + "/config/profile_python_docx.yml"
    with open(source_boundary, "rb") as fh:
        boundary_raw = fh.read()
    with open(source_profile, "rb") as fh:
        profile_raw = fh.read()
    if database:
        profile_raw = profile_raw.replace(
            b"  needs_database: false\n", b"  needs_database: true\n")
    config_root = root + "/config"
    os.makedirs(config_root, mode=0o700, exist_ok=True)
    boundary_path = config_root + "/boundary_python_docx.yml"
    profile_path = config_root + "/profile_python_docx.yml"
    _selftest_write(boundary_path, boundary_raw, raw=True)
    _selftest_write(profile_path, profile_raw, raw=True)
    profile = load_profile(profile_path)

    strip_document = {
        "repo_root": profile.raw.get("repo_root", "/unused")
        if isinstance(profile.raw, dict) else "/unused",
        "gold_root": gold_root,
        "moved": [], "moved_config": [], "patched": [], "installed": [],
        "boundary_version": 1, "digests": {}, "substrate_roots": [],
        "substrate_volatile": [], "bytecode_roots": [], "build_roots": [],
    }
    # The profile does not carry repo_root; its adjacent boundary does.
    from ..core.boundary import load_boundary, REMOVABLE
    fixture_boundary = load_boundary(boundary_path)
    fixture_repo_root = fixture_boundary.repo_root
    if not isinstance(fixture_repo_root, str):
        # The shipped boundary's default is data-root-relative (dataset 1.2);
        # the fixture materializes it below its own root instead of
        # consulting the operator's R2T_DATA_ROOT.
        fixture_repo_root = os.path.join(root, *fixture_repo_root.parts)
    strip_document["repo_root"] = fixture_repo_root
    # `_verify_strip_substrate` requires a nonempty `moved` whose paths
    # classify removable under the boundary IN USE, and this builder serves
    # every stack's fixtures, so the path is chosen by classification
    # rather than hard-coded: one candidate per stack family, first match
    # wins, and a boundary matching none is a fixture bug worth the loud
    # StopIteration.
    strip_document["moved"] = [next(
        candidate for candidate in (
            "features/steps/fixture_steps.py",
            "src/CoreShop/Behat/Fixture/FixtureContext.php",
            "src/test/java/com/algorand/algosdk/unit/Base.java",
            "src/test/java/org/w3c/epubcheck/test/AssertionSteps.java",
        ) if fixture_boundary.classify(candidate) == REMOVABLE)]
    strip_document["repo_root"] = "."
    strip_document["gold_root"] = "."
    strip_path = gold_root + "/strip_manifest.json"
    _selftest_write(strip_path, strip_document)

    import io
    import tarfile
    archive_buffer = io.BytesIO()
    with tarfile.open(
            fileobj=archive_buffer, mode="w",
            format=tarfile.GNU_FORMAT) as archive:
        for relative in sorted(archive_members):
            raw = archive_members[relative]
            info = tarfile.TarInfo(relative)
            info.size = len(raw)
            info.mode = 0o600
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(raw))
    workspace_archive = archive_buffer.getvalue()
    archive_path = seed_dir + "/workspace.tar"
    _selftest_write(archive_path, workspace_archive, raw=True)
    archive_digest = raw_sha256(workspace_archive)
    database_path = seed_dir + "/database.sql"
    database_raw = None
    if database:
        database_raw = b"CREATE TABLE fixture (id INT PRIMARY KEY);\n"
        _selftest_write(database_path, database_raw, raw=True)
        database_digest = raw_sha256(database_raw)
        database_record = {
            "path": database_path, "digest": database_digest,
            "bytes": len(database_raw),
        }
    else:
        database_digest = "no_database"
        database_record = {
            "declared": "no_database", "digest": "no_database",
            "path": None, "bytes": 0,
        }
    seed_document = {
        "format": 1, "seed_key": "fixture-seed-key",
        "built_at": "2026-08-07T00:00:00+0000",
        "built_from": ".", "build_seconds": 0.0,
        "workspace": {"path": "workspace.tar", "digest": archive_digest,
                      "bytes": len(workspace_archive)},
        "database": database_record,
        "cleanliness": {}, "workspace_seed_digest": archive_digest,
        "database_dump_digest": database_digest,
    }
    if not database:
        seed_document["needs_database"] = False
    seed_path = seed_dir + "/seed.json"
    seed_raw = _selftest_write(seed_path, seed_document)

    spec = worker.WorkerSpec(
        index=0, workspace=workspace,
        container="worker0" if database else "fixture_worker_0",
        schema="fixture_schema_0" if database else "",
        credential="fixture_user_0" if database else "",
        env_file=root + "/secrets/worker0.env",
        workdir="/work", out_path=result_path, artifacts_root=artifacts)
    if database:
        worker.write_env_file(spec, "fixture-password", {})
    else:
        _selftest_write(spec.env_file, b"R2T_WORKER_INDEX=0\n", raw=True)
    spec_path = root + "/workers/worker0.json"
    spec_raw = _selftest_write(spec_path, spec.to_json())
    spec_hash = raw_sha256(spec_raw)

    authority_document = authority._fixture_authority()
    authority_path = root + "/authority.json"
    authority_raw = _selftest_write(authority_path, authority_document)
    authority_ref = {
        "path": authority_path, "file_sha256": raw_sha256(authority_raw),
        "digest": authority_document["digest"],
    }
    binding_document = authority._fixture_binding(database=database)
    binding_document["authority"] = authority_ref
    binding_document["pool"]["workers"][0].update({
        "worker_spec_path": spec_path,
        "worker_spec_sha256": spec_hash,
        "container_name": spec.container,
    })
    binding_document["pool"]["digest"] = semantic_digest(
        binding_document["pool"])
    binding_document["worker_spec_sha256"] = spec_hash
    binding_document["container"]["name"] = spec.container
    image = binding_document["container"]["image_id"]
    binding_document["digest"] = semantic_digest(binding_document)
    authority.validate_binding_document(binding_document)
    binding_path = root + "/binding.json"
    binding_raw = _selftest_write(binding_path, binding_document)
    binding_ref = {
        "path": binding_path, "file_sha256": raw_sha256(binding_raw),
        "digest": binding_document["digest"],
    }

    runtime_document = {
        "schema": "r2t.worker-runtime/v3", "worker": spec.to_json(),
        "worker_spec_sha256": spec_hash, "seed_dir": seed_dir,
        "seed_manifest_sha256": raw_sha256(seed_raw),
        "seed_key": seed_document["seed_key"],
        "workspace_seed_digest": archive_digest,
        "database_dump_digest": database_digest,
        "container_image_digest": image, "harness_version": HARNESS_VERSION,
        "needs_database": database,
        "docker_execution_authority": authority_ref,
        "docker_execution_binding": binding_ref,
    }
    runtime_path = worker.runtime_attestation_path(spec_path)
    runtime_raw = _selftest_write(runtime_path, runtime_document)
    harness = {
        "version": HARNESS_VERSION,
        "git_commit": campaign.harness_commit_identity(),
        "source_sha256": campaign.harness_source_digest(),
    }
    identity = {
        "schema": (RUNTIME_IDENTITY_V2_SCHEMA if database
                   else RUNTIME_IDENTITY_SCHEMA),
        "docker_execution_authority": authority_ref,
        "docker_execution_binding": binding_ref,
        "docker_daemon_fingerprint_sha256": authority_document["daemon"][
            "fingerprint_sha256"],
        "docker_execution_pool_digest": binding_document["pool"]["digest"],
        "worker_index": 0, "worker_spec_path": spec_path,
        "worker_spec_sha256": spec_hash,
        "container_image_digest": image, "seed_dir": seed_dir,
        "seed_manifest": _selftest_raw_ref(seed_path, seed_raw),
        "seed_key": seed_document["seed_key"],
        "workspace_seed_digest": archive_digest,
        "database_dump_digest": database_digest,
        "needs_database": database,
        "harness": harness, "digest": "0" * 64,
    }
    identity["digest"] = semantic_digest(identity)
    runtime_reference = {
        "path": runtime_path, "file_sha256": raw_sha256(runtime_raw),
        "identity": identity,
    }

    agent_runtime = campaign.agent_runtime_manifest(
        interpreter="CPython fixture", agent_versions={},
        environment_controls={}, network_semantics="fixture_no_egress")
    agent_runtime_path = root + "/campaign.json.agent_runtime.json"
    agent_runtime_raw = _selftest_write(agent_runtime_path, agent_runtime)
    campaign_document = campaign.generation_fingerprint(
        campaign_id="ledger-selftest", k_workers=1,
        shard_rule=campaign.SHARD_RULE, trial_budget=0, condition=None,
        coverage=False, harness_version=HARNESS_VERSION,
        config_digest=raw_sha256(boundary_raw)[:16], model=None,
        container_image_digest=image, workspace_seed_digest=archive_digest,
        database_dump_digest=database_digest, protocol_version=None,
        protocol_digest=None, agent_system=None,
        attempt_id="ledger-selftest-attempt",
        harness_commit=harness["git_commit"],
        harness_source_sha256=harness["source_sha256"],
        agent_runtime_sha256=campaign.agent_runtime_digest(agent_runtime),
        network_semantics=agent_runtime["network_semantics"])
    campaign_path = root + "/campaign.json"
    campaign_raw = _selftest_write(campaign_path, campaign_document)
    campaign_ref = {
        "path": campaign_path, "file_sha256": raw_sha256(campaign_raw),
        "campaign_digest": campaign.campaign_digest(campaign_document),
        "semantic_digest": semantic_digest(campaign_document),
    }
    agent_runtime_ref = {
        "path": agent_runtime_path,
        "file_sha256": raw_sha256(agent_runtime_raw),
        "agent_runtime_sha256": campaign.agent_runtime_digest(agent_runtime),
    }

    item_id = "python-docx/features/example.feature:2"
    release_row = {
        "item_id": item_id, "task": "criterion_to_test",
        "project": profile.project, "language": profile.language,
        "framework": profile.framework,
        "provenance": {"file_path": "features/example.feature"},
    }
    release_path = root + "/release.jsonl"
    release_raw = _selftest_write(
        release_path,
        (json.dumps(release_row, sort_keys=True, separators=(",", ":"))
         + "\n").encode(), raw=True)

    stamp = {
        "adapter": "empty", "adapter_version": None, "agent_system": None,
        "agent_timeout_seconds": None, "agent_version": None,
        "campaign_digest": campaign_ref["campaign_digest"],
        "comparison_class": None, "condition": None, "coverage": False,
        "dataset_version": None, "execution_timeout_seconds": 60,
        "harness_commit": (None if harness["git_commit"] is None
                           else harness["git_commit"][:7]),
        "harness_version": HARNESS_VERSION, "keep_artifacts": None,
        "max_iterations": None, "max_tokens": None, "model": None,
        "native_budget": None, "of": 1, "prompt_digest": None,
        "protocol_deviations": None, "protocol_digest": None,
        "protocol_version": None, "repeats": 1, "repro_check_count": 0,
        "sandboxed": False, "setting": None, "shard": 0,
        "subset_digest": None, "subset_id": None, "temperature": None,
        "trials": 0,
    }
    if set(stamp) != set(RUN_STAMP_NAMES):
        raise AssertionError("selftest run stamp inventory drifted")
    named_stamp = [
        {"name": name,
         "value_json": canonical_json_bytes(stamp[name]).decode("utf-8")}
        for name in sorted(stamp)
    ]
    adapter_files = sorted([
        _selftest_input("harness_feature", "features/example.feature",
                        feature_path),
        _selftest_input("harness_strip_manifest", "strip_manifest.json",
                        strip_path),
    ], key=lambda item: (item["role"], item["logical_path"], item["path"]))
    invocation = {
        "schema": RUN_INVOCATION_SCHEMA,
        "selection": {"limit": None, "requested_item_ids": None},
        "effective_run_stamp": named_stamp,
        "adapter": {"kind": "empty", "name": "empty",
                    "public_configuration": [], "secret_inputs": [],
                    "files": adapter_files},
        "resume": {"checkpoint_resume": True,
                   "stale_running_suffix_adoption": True,
                   "no_resume": False, "retry_failed": False},
    }
    plan = {
        "schema": RUN_PLAN_SCHEMA, "campaign": campaign_ref,
        "campaign_agent_runtime": agent_runtime_ref,
        "release": _selftest_raw_ref(release_path, release_raw),
        "boundary": _selftest_raw_ref(boundary_path, boundary_raw),
        "profile": _selftest_raw_ref(profile_path, profile_raw),
        "protocol": None, "worker_manifest_path": worker_manifest_path,
        "shard_index": 0, "shard_count": 1,
        "shard_rule": "sha1_item_id_mod_k",
        "workset": {"item_count": 1,
                    "ordered_item_ids_digest": ordered_item_ids_digest(
                        [item_id])},
        "invocation": invocation,
        "invocation_digest": domain_digest(RUN_INVOCATION_SCHEMA, invocation),
        "digest": "0" * 64,
    }
    plan["digest"] = semantic_digest(plan)

    result_row = {"item_id": item_id, "outcome": "passed", **stamp}
    result_raw = (json.dumps(
        result_row, sort_keys=True, separators=(",", ":")) + "\n").encode()
    _selftest_write(result_path, result_raw, raw=True)
    worker_record = campaign.WorkerManifest(
        shard=0, workspace=workspace, container=spec.container,
        schema=spec.schema, credential=spec.credential, out_path=result_path,
        artifacts_root=artifacts,
        started_at="2026-08-07T00:00:00Z",
        finished_at="2026-08-07T00:01:00Z",
        campaign_digest=campaign_ref["campaign_digest"])
    worker_manifest_document = {
        "campaign": campaign_document,
        "campaign_digest": campaign_ref["campaign_digest"],
        "worker": worker_record.to_json(),
    }
    worker_manifest_raw = _selftest_write(
        worker_manifest_path, worker_manifest_document)
    result_binding = {
        "path": result_path, "byte_length": len(result_raw), "row_count": 1,
        "file_sha256": raw_sha256(result_raw),
    }
    receipt = {
        "schema": RECEIPT_SCHEMA, "artifact_kind": "run_shard",
        "execution": {"attempt_id": campaign_document["attempt_id"],
                      "runtime": runtime_reference},
        "plan": plan, "result": result_binding,
        "worker_manifest": _selftest_raw_ref(
            worker_manifest_path, worker_manifest_raw),
        "digest": "0" * 64,
    }
    receipt["digest"] = semantic_digest(receipt)
    receipt_path = result_path + RECEIPT_SUFFIX
    receipt_raw = _selftest_write(receipt_path, receipt)
    checkpoint = {
        "schema": CHECKPOINT_SCHEMA, "artifact_kind": "run_shard",
        "state": "running", "execution": receipt["execution"],
        "plan": plan, "result_prefix": result_binding,
        "reason": None, "digest": "0" * 64,
    }
    checkpoint["digest"] = semantic_digest(checkpoint)
    checkpoint_path = result_path + CHECKPOINT_SUFFIX
    checkpoint_raw = _selftest_write(checkpoint_path, checkpoint)
    return {
        "root": root, "receipt": receipt, "receipt_path": receipt_path,
        "receipt_raw": receipt_raw, "checkpoint": checkpoint,
        "checkpoint_path": checkpoint_path, "checkpoint_raw": checkpoint_raw,
        "result_path": result_path, "result_raw": result_raw,
        "result_row": result_row, "runtime_path": runtime_path,
        "runtime": runtime_document, "runtime_raw": runtime_raw,
        "authority_path": authority_path, "authority": authority_document,
        "authority_raw": authority_raw, "binding_path": binding_path,
        "binding": binding_document, "binding_raw": binding_raw,
        "spec_path": spec_path, "spec_raw": spec_raw,
        "seed_path": seed_path, "seed_raw": seed_raw,
        "archive_path": archive_path, "archive_raw": workspace_archive,
        "database_path": database_path, "database_raw": database_raw,
        "campaign_path": campaign_path, "campaign_raw": campaign_raw,
        "profile_path": profile_path, "profile_raw": profile_raw,
        "feature_path": feature_path, "feature_raw": feature_raw,
        "worker_manifest_path": worker_manifest_path,
        "worker_manifest_raw": worker_manifest_raw,
        "strip_path": strip_path, "repo_root": fixture_repo_root,
    }


def _selftest_schema_documents(fixture: dict) -> list[tuple[str, dict, object]]:
    import copy
    run_receipt = copy.deepcopy(fixture["receipt"])
    run_checkpoint = copy.deepcopy(fixture["checkpoint"])
    raw_ref = copy.deepcopy(run_receipt["plan"]["boundary"])
    runtime = copy.deepcopy(run_receipt["execution"]["runtime"])
    resume = {"checkpoint_resume": True,
              "stale_running_suffix_adoption": True,
              "no_resume": False, "retry_failed": False}
    validation_invocation = {
        "schema": VALIDATION_INVOCATION_SCHEMA,
        "selection": {"limit": None, "requested_item_ids": None},
        "harness_inputs": {"gold_root": fixture["root"] + "/gold",
                           "feature_inputs": [raw_ref],
                           "alias_table": raw_ref,
                           "autowirable_types": raw_ref},
        "resume": resume,
    }
    validation_plan = {
        "schema": VALIDATION_PLAN_SCHEMA, "closures": raw_ref,
        "boundary": raw_ref, "profile": raw_ref, "strip_manifest": raw_ref,
        "gold_inputs": [{"relative_path": "gold/source.py",
                         "path": fixture["root"] + "/gold/source.py",
                         "byte_length": 0, "file_sha256": "0" * 64}],
        "repeats": 1, "timeout_seconds": 1,
        "harness_version": 7,
        "workset": {"item_count": 0,
                    "ordered_item_ids_digest": "0" * 64},
        "invocation": validation_invocation,
        "invocation_digest": "0" * 64, "digest": "0" * 64,
    }
    validation_execution = {
        "attempt_id": "01234567-89ab-4cde-8fab-0123456789ab",
        "runtime": runtime,
    }
    validation_checkpoint = {
        "schema": CHECKPOINT_SCHEMA, "artifact_kind": "validation",
        "state": "running", "execution": validation_execution,
        "plan": validation_plan,
        "result_prefix": copy.deepcopy(run_receipt["result"]),
        "reason": None, "digest": "0" * 64,
    }
    validation_receipt = {
        "schema": RECEIPT_SCHEMA, "artifact_kind": "validation",
        "execution": validation_execution, "plan": validation_plan,
        "result": copy.deepcopy(run_receipt["result"]), "digest": "0" * 64,
    }
    merged_receipt = {
        "schema": RECEIPT_SCHEMA, "artifact_kind": "merged_run",
        "merge": {"policy": "r2t.strict-merge/v1", "release": raw_ref,
                  "expected_item_count": 1,
                  "ordered_item_ids_digest": "0" * 64,
                  "campaign_semantic_digest": "0" * 64,
                  "execution_pool_digest": "0" * 64},
        "result": copy.deepcopy(run_receipt["result"]),
        "campaign_sidecar": raw_ref,
        "source_receipts": [{
            "worker_index": 0, "receipt_path": fixture["receipt_path"],
            "receipt_file_sha256": "0" * 64,
            "receipt_digest": "0" * 64,
            "source_result_file_sha256": "0" * 64}],
        "digest": "0" * 64,
    }
    bundle = {
        "schema": BUNDLE_INDEX_SCHEMA,
        "root_receipts": [{"artifact_kind": "run_shard",
                           "receipt_file_sha256": "0" * 64,
                           "receipt_digest": "1" * 64}],
        "digest": "0" * 64,
    }
    return [
        ("run checkpoint", run_checkpoint, validate_checkpoint_schema),
        ("validation checkpoint", validation_checkpoint,
         validate_checkpoint_schema),
        ("run receipt", run_receipt, validate_receipt_schema),
        ("validation receipt", validation_receipt, validate_receipt_schema),
        ("merged receipt", merged_receipt, validate_receipt_schema),
        ("bundle index", bundle, validate_bundle_index_schema),
    ]


def selftest() -> int:
    import contextlib
    import copy
    import errno
    import io
    import tempfile
    import types
    from .validate import HARNESS_VERSION

    failures = []

    def check(name, condition, detail=""):
        passed = bool(condition)
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not passed else ""))
        if not passed:
            failures.append(name)

    def refused(fn) -> bool:
        try:
            fn()
        except ResultLedgerRefused:
            return True
        return False

    def rewrite(path: str, raw: bytes) -> None:
        _selftest_write(path, raw, raw=True)

    # THE SHARD-LOCAL DEPLOYED AGENT INPUT.  Two shards of one campaign stage
    # the harness-owned price table under their OWN artifacts roots, which the
    # pool requires not to overlap, so their `command_template` differs in that
    # one argument and nothing else.  Before this was projected away, the
    # strict merge refused every K>1 agent campaign with "source run plans
    # differ outside documented shard-local fields", which is why no such
    # campaign had ever produced a merged run or a rendered table.
    def _plan_with(pricing_path: str, reflections: str = "10",
                   commit: str = "abc1234") -> dict:
        return {
            "worker_manifest_path": "/w/m.json", "shard_index": 0,
            "workset": [], "invocation_digest": "d" * 64, "digest": "e" * 64,
            "invocation": {
                "effective_run_stamp": [
                    {"name": "shard", "value": "0"},
                    {"name": "harness_commit", "value_json": json.dumps(commit)},
                ],
                "adapter": {
                    "kind": "aider", "name": "aider", "files": {},
                    "public_configuration": [
                        {"name": "command_template", "value_json": json.dumps(
                            ["/env/bin/python3.12", "--max-reflections",
                             reflections, "--pricing-table", pricing_path])},
                        {"name": "storage_layout",
                         "value_json": '{"evidence_root": "/runs/w0"}'},
                    ],
                },
            },
        }

    shard0 = _plan_with("/pool/artifacts/shard0/agent-inputs/pricing.yml")
    shard1 = _plan_with("/pool/artifacts/shard1/agent-inputs/pricing.yml",
                        commit="def5678")
    check("two shards that differ only in the deployed input's own artifacts "
          "root and the commit they were launched at project to the same "
          "common plan",
          _common_run_plan_projection(shard0)
          == _common_run_plan_projection(shard1))
    check("the deployed input's NAME is still compared",
          _common_run_plan_projection(shard0)
          != _common_run_plan_projection(
              _plan_with("/pool/artifacts/shard1/agent-inputs/other.yml")))
    check("a real command-template difference still refuses to project equal",
          _common_run_plan_projection(shard0)
          != _common_run_plan_projection(_plan_with(
              "/pool/artifacts/shard1/agent-inputs/pricing.yml",
              reflections="25")))

    def _logical_source(role: str, path: str, digest: str):
        logical_path = ("config/pricing.yml" if role == "pricing_table"
                        else "r2t/aider_driver.py")
        key = (role, logical_path)
        files = {key: {
            "path": path, "byte_length": 10, "file_sha256": digest,
        }}
        return types.SimpleNamespace(context=types.SimpleNamespace(
            adapter_files=files, adapter_expected_paths={key}))

    check("byte-identical pricing copies may use shard-local paths",
          _verify_logical_projections([
              _logical_source("pricing_table", "/shard0/pricing.yml", "a" * 64),
              _logical_source("pricing_table", "/shard1/pricing.yml", "a" * 64),
          ]) is None)
    check("shard-local pricing still requires byte identity",
          refused(lambda: _verify_logical_projections([
              _logical_source("pricing_table", "/shard0/pricing.yml", "a" * 64),
              _logical_source("pricing_table", "/shard1/pricing.yml", "b" * 64),
          ])))
    check("global adapter input paths remain strict",
          refused(lambda: _verify_logical_projections([
              _logical_source("agent_driver", "/env0/driver.py", "a" * 64),
              _logical_source("agent_driver", "/env1/driver.py", "a" * 64),
          ])))

    check("strict JSON rejects duplicates at depth",
          refused(lambda: loads_exact_json(
              b'{"a":{"x":1,"x":2}}', label="duplicate vector")))
    nonfinite = (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
                 b'{"x":1e999}', b'{"x":01}', b'{"x":1.}',
                 b'{"x":+.1}')
    check("strict JSON rejects nonfinite, overflow, and malformed numbers",
          all(refused(lambda raw=raw: loads_exact_json(raw, label="number"))
              for raw in nonfinite))
    vector = {"schema": "r2t.example/v1", "value": "\N{SNOWMAN}",
              "digest": "ignored"}
    check("authority canonical semantic-digest vector",
          semantic_digest(vector)
          == "ea793c5038e281646274162f7dd5dbcd7961d7e58b9a44dd6076b6500a111ef6")
    check("ordered workset domain vector is order-sensitive",
          ordered_item_ids_digest(["a", "b"])
          != ordered_item_ids_digest(["b", "a"])
          and refused(lambda: ordered_item_ids_digest(["a", "a"])))
    check("canonical absolute paths refuse alternate spellings",
          canonical_absolute_path("/", "root") == "/"
          and all(refused(lambda path=path: canonical_absolute_path(path, "bad"))
                  for path in ("relative", "//tmp/x", "/tmp//x",
                               "/tmp/./x", "/tmp/x/", "/tmp/../x")))
    check("workspace separation is two-way but permits disjoint siblings",
          refused(lambda: _require_workspace_separation(
              "/tmp/i1-worker", ["/tmp/i1-worker/result.jsonl"],
              "contained result"))
          and refused(lambda: _require_workspace_separation(
              "/tmp/i1-worker", ["/tmp"], "enclosing evidence"))
          and not refused(lambda: _require_workspace_separation(
              "/tmp/i1-worker", ["/tmp/i1-results/result.jsonl"],
              "disjoint result")))
    source_order = ["b", "a", "c"]
    selection_positive = (
        _selection_ids(
            {"limit": 1, "requested_item_ids": ["a", "c"]},
            source_order, validation_order=False) == ["a", "c"]
        and _selection_ids(
            {"limit": 2, "requested_item_ids": ["a", "b"]},
            source_order, validation_order=True) == ["b", "a"])
    bad_selections = (
        {"limit": 0, "requested_item_ids": None},
        {"limit": -1, "requested_item_ids": None},
        {"limit": True, "requested_item_ids": None},
        {"limit": None, "requested_item_ids": ["a", "a"]},
        {"limit": None, "requested_item_ids": ["c", "a"]},
        {"limit": None, "requested_item_ids": ["unknown"]},
        {"limit": None, "requested_item_ids": [""]},
    )
    check("run and validation selectors preserve their exact historical order",
          selection_positive and all(refused(
              lambda value=value: _selection_ids(
                  value, source_order, validation_order=False))
              for value in bad_selections))

    # A strip's answer-code identity is `moved`; `moved_config` records
    # lifecycle/configuration work and deliberately does not participate in
    # the boundary join.  Pin that distinction against the two real
    # non-Java boundaries without consulting a prepared or canonical tree.
    from ..core.boundary import load_boundary, REMOVABLE
    config_root = BENCHMARK_ROOT \
        + "/config"
    coreshop_boundary = load_boundary(
        config_root + "/boundary_coreshop.yml",
        repo_root="/selftest/coreshop")
    docx_boundary = load_boundary(
        config_root + "/boundary_python_docx.yml",
        repo_root="/selftest/python-docx")
    coreshop_answer = \
        "src/CoreShop/Behat/Context/Domain/CartContext.php"
    coreshop_config = "behat.yml.dist"
    docx_answer = "features/steps/document.py"
    docx_config = "features/environment.py"

    def strip_join(boundary, moved, moved_config) -> None:
        _verify_strip_substrate({
            "moved": moved, "moved_config": moved_config,
        }, boundary)

    check("CoreShop and python-docx strips accept their lifecycle/config "
          "moves outside the answer-code join",
          coreshop_boundary.classify(coreshop_config) != REMOVABLE
          and docx_boundary.classify(docx_config) != REMOVABLE
          and not refused(lambda: strip_join(
              coreshop_boundary, [coreshop_answer], [coreshop_config]))
          and not refused(lambda: strip_join(
              docx_boundary, [docx_answer], [docx_config])))
    check("the strip join refuses cross-project answer code",
          refused(lambda: strip_join(
              docx_boundary, [coreshop_answer], [coreshop_config]))
          and refused(lambda: strip_join(
              coreshop_boundary, [docx_answer], [docx_config])))
    check("retained lifecycle code cannot stand in for moved answer code",
          refused(lambda: strip_join(
              docx_boundary, [docx_config], [])))
    check("the strip join refuses empty and partly-production moved lists",
          all(refused(lambda boundary=boundary: strip_join(
              boundary, [], []))
              for boundary in (coreshop_boundary, docx_boundary))
          and refused(lambda: strip_join(
              coreshop_boundary,
              [coreshop_answer,
               "src/CoreShop/Component/Order/Model/Order.php"], []))
          and refused(lambda: strip_join(
              docx_boundary,
              [docx_answer, "src/docx/document.py"], [])))

    with tempfile.TemporaryDirectory(prefix="r2t-ledger-i1-") as temporary:
        os.chmod(temporary, 0o700)
        fixture = _build_selftest_fixture(temporary)
        check("complete run-shard receipt verifies offline",
              verify_receipt(fixture["receipt_path"])["complete"] is True)
        reporting_workset = verify_reporting_workset(
            fixture["receipt_path"])
        check("reporting receives the receipt verifier's replayed shard "
              "workset rather than deriving a population from result rows",
              reporting_workset == {
                  "item_ids": (fixture["result_row"]["item_id"],),
                  "workset": fixture["receipt"]["plan"]["workset"],
                  "campaign_digest": fixture["receipt"]["plan"][
                      "campaign"]["campaign_digest"],
                  "subset_id": None, "subset_digest": None,
                  "shard_rule": fixture["receipt"]["plan"]["shard_rule"],
                  "shard_count": fixture["receipt"]["plan"]["shard_count"],
                  "release_path": fixture["receipt"]["plan"]["release"][
                      "path"],
                  "result_path": fixture["result_path"],
              }, str(reporting_workset))
        checkpoint_report = verify_checkpoint(fixture["checkpoint_path"])
        check("checkpoint verifies only as incomplete diagnostic state",
              checkpoint_report["verified"] is True
              and checkpoint_report["complete"] is False
              and checkpoint_report["workset"]
              == fixture["checkpoint"]["plan"]["workset"]
              and checkpoint_report["population_identity"] == {
                  "campaign_digest": fixture["checkpoint"]["plan"]
                      ["campaign"]["campaign_digest"],
                  "subset_id": None, "subset_digest": None,
                  "shard_rule": fixture["checkpoint"]["plan"]
                      ["shard_rule"],
                  "shard_count": fixture["checkpoint"]["plan"]
                      ["shard_count"],
              }
              and checkpoint_report["release_path"]
              == fixture["checkpoint"]["plan"]["release"]["path"])

        draft = copy.deepcopy(fixture["checkpoint"])
        draft["state"] = "draft"
        draft["result_prefix"].update({
            "byte_length": 0, "row_count": 0,
            "file_sha256": raw_sha256(b""),
        })
        draft["digest"] = semantic_digest(draft)
        _selftest_write(fixture["checkpoint_path"], draft)
        draft_suffix_refused = refused(
            lambda: verify_checkpoint(fixture["checkpoint_path"]))

        interrupted = copy.deepcopy(fixture["checkpoint"])
        interrupted["state"] = "interrupted"
        interrupted["reason"] = "synthetic interruption"
        interrupted["digest"] = semantic_digest(interrupted)
        _selftest_write(fixture["checkpoint_path"], interrupted)
        rewrite(fixture["result_path"], fixture["result_raw"] + b"stale")
        stopped_suffix_refused = refused(
            lambda: verify_checkpoint(fixture["checkpoint_path"]))

        _selftest_write(fixture["checkpoint_path"], fixture["checkpoint"])
        rewrite(fixture["result_path"], fixture["result_raw"] + b"stale")
        running_suffix_refused = refused(
            lambda: verify_checkpoint(fixture["checkpoint_path"]))
        rewrite(fixture["checkpoint_path"], fixture["checkpoint_raw"])
        rewrite(fixture["result_path"], fixture["result_raw"])
        other_result_path = fixture["root"] + "/runs/other.jsonl"
        _selftest_write(other_result_path, fixture["result_raw"], raw=True)
        rebound_checkpoint = copy.deepcopy(fixture["checkpoint"])
        rebound_checkpoint["result_prefix"]["path"] = other_result_path
        rebound_checkpoint["digest"] = semantic_digest(rebound_checkpoint)
        rebound_checkpoint_path = other_result_path + CHECKPOINT_SUFFIX
        _selftest_write(rebound_checkpoint_path, rebound_checkpoint)
        checkpoint_out_path_refused = refused(
            lambda: verify_checkpoint(rebound_checkpoint_path))
        check("draft and stopped checkpoints reject suffixes; running rejects "
              "a malformed suffix and a rebound result path",
              draft_suffix_refused and stopped_suffix_refused
              and running_suffix_refused and checkpoint_out_path_refused)

        # Pin every fixture adapter closure the v1 contract admits.  The
        # files are synthetic private inputs, never benchmark artifacts.
        item_id = fixture["result_row"]["item_id"]
        source_relative = "features/steps/fixture_source.py"
        source_path = fixture["root"] + "/gold/" + source_relative
        _selftest_write(source_path, b"def fixture_step():\n    pass\n", raw=True)
        sidecar_name = "fixture-sidecar.json"
        sidecar_path = fixture["root"] + "/gold/" + sidecar_name
        sidecar = {
            "item_id": item_id, "files": [source_relative],
            "di_fragment": {}, "context_classes": [],
            "feature_file": "features/example.feature", "scenario_line": 2,
        }
        _selftest_write(sidecar_path, sidecar)
        gold_manifest_path = fixture["root"] + "/gold/manifest.json"
        _selftest_write(gold_manifest_path, {item_id: sidecar_name})
        closures_path = fixture["root"] + "/artifacts/closures.json"
        closures = [{"item_id": item_id, "files": [source_relative],
                     "feature_file": "features/example.feature"}]
        _selftest_write(closures_path, closures)
        common_files = copy.deepcopy(
            fixture["receipt"]["plan"]["invocation"]["adapter"]["files"])

        def signed_adapter_outcome(kind: str, name: str,
                                   public_configuration: list,
                                   extra_files: list, *,
                                   base_files: Optional[list] = None) -> bool:
            candidate = copy.deepcopy(fixture["receipt"])
            invocation = candidate["plan"]["invocation"]
            invocation["adapter"] = {
                "kind": kind, "name": name,
                "public_configuration": public_configuration,
                "secret_inputs": [],
                "files": sorted(
                    (common_files if base_files is None else base_files)
                    + extra_files,
                    key=lambda entry: (
                        entry["role"], entry["logical_path"], entry["path"])),
            }
            for named in invocation["effective_run_stamp"]:
                if named["name"] == "adapter":
                    named["value_json"] = canonical_json_bytes(name).decode()
                    break
            candidate["plan"]["invocation_digest"] = domain_digest(
                RUN_INVOCATION_SCHEMA, invocation)
            candidate["plan"]["digest"] = semantic_digest(candidate["plan"])
            row = copy.deepcopy(fixture["result_row"])
            row["adapter"] = name
            result_raw = (json.dumps(
                row, sort_keys=True, separators=(",", ":")) + "\n").encode()
            rewrite(fixture["result_path"], result_raw)
            candidate["result"].update({
                "byte_length": len(result_raw),
                "file_sha256": raw_sha256(result_raw),
            })
            candidate["digest"] = semantic_digest(candidate)
            _selftest_write(fixture["receipt_path"], candidate)
            try:
                return verify_receipt(fixture["receipt_path"])["complete"]
            finally:
                rewrite(fixture["result_path"], fixture["result_raw"])
                rewrite(fixture["receipt_path"], fixture["receipt_raw"])

        gold_root_value = [{
            "name": "gold_root",
            "value_json": canonical_json_bytes(
                fixture["root"] + "/gold").decode(),
        }]
        gold_extra = [
            _selftest_input("release_gold_manifest", "gold/manifest.json",
                            gold_manifest_path),
            _selftest_input("release_gold_record", "gold/" + sidecar_name,
                            sidecar_path),
            _selftest_input("gold_source", source_relative, source_path),
        ]
        closure_input = _selftest_input(
            "fixture_closures", "closures.json", closures_path)
        admitted_adapter_results = {
            "empty": True,  # The primary fixture above is the empty positive.
            "gold": signed_adapter_outcome(
                "gold", "gold", gold_root_value, gold_extra),
            "stripped_gold": signed_adapter_outcome(
                "stripped_gold", "stripped-gold", gold_root_value,
                [closure_input,
                 _selftest_input("gold_source", source_relative, source_path)]),
            "stub": signed_adapter_outcome(
                "stub", "stub", [], [closure_input]),
        }
        check("all four admitted fixture adapter closures verify",
              all(admitted_adapter_results.values()),
              str(admitted_adapter_results))

        from ..core.boundary import load_boundary as load_boundary_fixture
        # An explicit repo_root: the shipped boundary's own default is a
        # data-root-relative DataPath since dataset 1.2, and this suite's
        # joins want the fixture's materialized absolute spelling.
        fixture_boundary = load_boundary_fixture(
            fixture["root"] + "/config/boundary_python_docx.yml",
            repo_root=fixture["repo_root"])

        # Closure equality is over the complete role/logical/path projection,
        # not merely over readable files.  Exercise missing, extra and
        # coordinator/workspace-rebound path spellings with fully re-signed
        # receipts.
        wrong_gold_path = fixture["root"] + "/gold/wrong-source.py"
        _selftest_write(wrong_gold_path, b"wrong source\n", raw=True)
        extra_path = fixture["root"] + "/artifacts/unexpected.json"
        _selftest_write(extra_path, b"{}\n", raw=True)
        wrong_feature_path = fixture["root"] + "/workspace/features/wrong.feature"
        _selftest_write(wrong_feature_path, b"Feature: wrong\n", raw=True)
        rebound_common = [
            (_selftest_input(
                "harness_feature", "features/example.feature",
                wrong_feature_path)
             if entry["role"] == "harness_feature" else copy.deepcopy(entry))
            for entry in common_files
        ]
        wrong_gold_files = [
            (_selftest_input("gold_source", source_relative, wrong_gold_path)
             if entry["role"] == "gold_source" else copy.deepcopy(entry))
            for entry in gold_extra
        ]
        adapter_closure_refusals = (
            refused(lambda: signed_adapter_outcome(
                "gold", "gold", gold_root_value, gold_extra[:-1])),
            refused(lambda: signed_adapter_outcome(
                "gold", "gold", gold_root_value,
                gold_extra + [_selftest_input(
                    "unexpected", "unexpected.json", extra_path)])),
            refused(lambda: signed_adapter_outcome(
                "gold", "gold", gold_root_value, wrong_gold_files)),
            refused(lambda: signed_adapter_outcome(
                "empty", "empty", [], [], base_files=rebound_common)),
        )

        selected_row = {
            "item_id": item_id,
            "provenance": {"file_path": "features/example.feature"},
        }
        fake_profile = types.SimpleNamespace(framework="behat")

        def direct_behat(present: bool, *, wrong_alias: bool = False,
                         omit_alias: bool = False) -> bool:
            suffix = ("present" if present else "absent") \
                + ("-wrong" if wrong_alias else "") \
                + ("-missing" if omit_alias else "")
            artifacts = fixture["root"] + "/artifacts/behat-" + suffix
            os.makedirs(artifacts, mode=0o700, exist_ok=True)
            os.chmod(artifacts, 0o700)
            alias_path = artifacts + "/alias_table.json"
            actual_alias_path = (artifacts + "/other-alias.json"
                                 if wrong_alias else alias_path)
            _selftest_write(actual_alias_path, b"{}\n", raw=True)
            files = list(common_files)
            if not omit_alias:
                files.append(_selftest_input(
                    "harness_alias_table", "alias_table.json",
                    actual_alias_path))
            if present:
                autowire_path = artifacts + "/autowirable_types.json"
                _selftest_write(autowire_path, b"[]\n", raw=True)
                files.append(_selftest_input(
                    "harness_autowirable_types", "autowirable_types.json",
                    autowire_path))
            invocation = {
                "adapter": {
                    "kind": "empty", "name": "empty",
                    "public_configuration": [{
                        "name": "harness_autowirable_types_present",
                        "value_json": ("true" if present else "false"),
                    }],
                    "secret_inputs": [],
                    "files": sorted(files, key=lambda entry: (
                        entry["role"], entry["logical_path"], entry["path"])),
                },
            }
            runtime = types.SimpleNamespace(worker=types.SimpleNamespace(
                workspace=fixture["root"] + "/workspace",
                artifacts_root=artifacts))
            reader = _LiveReader()
            _verify_adapter(
                reader, invocation, [selected_row], [item_id],
                fixture["root"] + "/release.jsonl", runtime,
                fixture_boundary, fake_profile)
            reader.confirm()
            return True

        behat_results = (
            direct_behat(True), direct_behat(False),
            refused(lambda: direct_behat(True, wrong_alias=True)),
            refused(lambda: direct_behat(False, omit_alias=True)),
        )
        check("adapter closures refuse missing, extra, rebound, and coordinator "
              "paths while both Behat optional-input states verify",
              all(adapter_closure_refusals) and all(behat_results),
              str({"closure": adapter_closure_refusals,
                   "behat": behat_results}))

        with open(fixture["strip_path"], "rb") as fh:
            strip_raw = fh.read()
        # The old probe here set `repo_root = "/different/repository"` and
        # expected the path-equality refusal `_strip_manifest` no longer
        # performs (its docstring records why the equality was vacuous).
        # The negatives now exercise the surviving contract: repo_root is
        # still held to its SHAPE, and the structural join refuses a moved
        # path that classifies production under the boundary in force.
        wrong_strip = loads_exact_json(strip_raw, label="strip-root fixture")
        wrong_strip["repo_root"] = "relative/not/absolute"
        _selftest_write(fixture["strip_path"], wrong_strip)
        strip_root_refused = refused(lambda: _strip_manifest(
            _LiveReader(), {"path": fixture["strip_path"]}, fixture_boundary,
            fixture["repo_root"]))
        rewrite(fixture["strip_path"], strip_raw)
        production_strip = loads_exact_json(strip_raw, label="strip fixture")
        production_strip["moved"] = ["src/docx/api.py"]
        _selftest_write(fixture["strip_path"], production_strip)
        production_moved_refused = refused(lambda: _strip_manifest(
            _LiveReader(), {"path": fixture["strip_path"]}, fixture_boundary,
            fixture["repo_root"]))
        rewrite(fixture["strip_path"], strip_raw)
        boolean_boundary = types.SimpleNamespace(
            repo_root=fixture_boundary.repo_root, version=True,
            classify=fixture_boundary.classify)
        boolean_boundary_refused = refused(lambda: _strip_manifest(
            _LiveReader(), {"path": fixture["strip_path"]},
            boolean_boundary, fixture["repo_root"]))
        check("closure paths stay relative and strip shape/join/version hold "
              "the boundary contract",
              refused(lambda: _closure_relative_path(
                  "/absolute/source.py", fixture_boundary.repo_root,
                  "absolute closure fixture"))
              and strip_root_refused and production_moved_refused
              and boolean_boundary_refused)

        # The producer and this reader must agree about the manifest's key
        # set.  Asserted against what `repo.StripManifest.save` ACTUALLY
        # writes, not against the fixture document built by hand above: a
        # field added to `save` alone is refused nowhere in this suite and
        # first fails at the publication ceremony, on the corpora that
        # already have numbers.  That is how `build_roots` -- the Java
        # stack's target/ sweep -- reached the write side while this read
        # side still ended at `bytecode_roots`.
        from .repo import StripManifest as _StripManifest
        produced_path = fixture["root"] + "/produced_strip_manifest.json"
        _StripManifest(
            repo_root=fixture_boundary.repo_root,
            gold_root=os.path.dirname(fixture["strip_path"]),
            boundary_version=1).save(produced_path)
        with open(produced_path, "rb") as fh:
            produced = loads_exact_json(fh.read(), label="produced strip")
        os.unlink(produced_path)
        accepted = set(_strip_manifest_fields())
        check("the strip manifest the harness WRITES is the strip manifest "
              "this ledger ACCEPTS, field for field",
              set(produced) == accepted,
              f"written but not accepted {sorted(set(produced) - accepted)}; "
              f"accepted but not written {sorted(accepted - set(produced))}")

        # Exercise I3's complete validation receipt boundary using the same
        # recursively authenticated runtime fixture as the I1 run receipt.
        validation_invocation = {
            "schema": VALIDATION_INVOCATION_SCHEMA,
            "selection": {"limit": 1,
                          "requested_item_ids": [item_id]},
            "harness_inputs": {
                "gold_root": fixture["root"] + "/gold",
                "feature_inputs": [_selftest_raw_ref(
                    fixture["feature_path"], fixture["feature_raw"])],
                "alias_table": None,
                "autowirable_types": None,
            },
            "resume": {"checkpoint_resume": True,
                       "stale_running_suffix_adoption": True,
                       "no_resume": False, "retry_failed": False},
        }
        source_raw = read_trusted_bytes(
            source_path, label="validation source fixture")
        validation_plan = {
            "schema": VALIDATION_PLAN_SCHEMA,
            "closures": _selftest_raw_ref(closures_path),
            "boundary": copy.deepcopy(fixture["receipt"]["plan"]["boundary"]),
            "profile": copy.deepcopy(fixture["receipt"]["plan"]["profile"]),
            "strip_manifest": _selftest_raw_ref(fixture["strip_path"]),
            "gold_inputs": [{
                "relative_path": source_relative,
                "path": source_path,
                "byte_length": len(source_raw),
                "file_sha256": raw_sha256(source_raw),
            }],
            "repeats": 1,
            "timeout_seconds": 60,
            "harness_version": fixture["receipt"]["execution"]["runtime"][
                "identity"]["harness"]["version"],
            "workset": {"item_count": 1,
                        "ordered_item_ids_digest": ordered_item_ids_digest(
                            [item_id])},
            "invocation": validation_invocation,
            "invocation_digest": domain_digest(
                VALIDATION_INVOCATION_SCHEMA, validation_invocation),
            "digest": "0" * 64,
        }
        validation_plan["digest"] = semantic_digest(validation_plan)
        validation_reader = _LiveReader()
        validation_runtime = _verify_runtime(
            validation_reader,
            fixture["receipt"]["execution"]["runtime"])
        validation_context = _verify_validation_plan(
            validation_reader, validation_plan, validation_runtime)
        validation_reader.confirm()
        validation_execution = copy.deepcopy(
            fixture["receipt"]["execution"])
        validation_execution["attempt_id"] = (
            "01234567-89ab-4cde-8fab-0123456789ab")
        validation_row = copy.deepcopy(fixture["result_row"])
        validation_row.update({
            "validation_attempt_id": validation_execution["attempt_id"],
            "validation_plan_digest": validation_plan["digest"],
            "harness_version": validation_plan["harness_version"],
            "repeats": validation_plan["repeats"],
            "timeout_seconds": validation_plan["timeout_seconds"],
        })
        validation_result_raw = (json.dumps(
            validation_row, sort_keys=True, separators=(",", ":"))
            + "\n").encode()
        rewrite(fixture["result_path"], validation_result_raw)
        validation_result = {
            "path": fixture["result_path"],
            "byte_length": len(validation_result_raw),
            "row_count": 1,
            "file_sha256": raw_sha256(validation_result_raw),
        }

        validation_checkpoint = {
            "schema": CHECKPOINT_SCHEMA,
            "artifact_kind": "validation",
            "state": "running",
            "execution": validation_execution,
            "plan": validation_plan,
            "result_prefix": copy.deepcopy(validation_result),
            "reason": None,
            "digest": "0" * 64,
        }
        validation_checkpoint["digest"] = semantic_digest(
            validation_checkpoint)
        _selftest_write(fixture["checkpoint_path"], validation_checkpoint)
        validation_checkpoint_report = verify_checkpoint(
            fixture["checkpoint_path"])
        rewrite(fixture["checkpoint_path"], fixture["checkpoint_raw"])

        validation_receipt = {
            "schema": RECEIPT_SCHEMA,
            "artifact_kind": "validation",
            "execution": validation_execution,
            "plan": validation_plan,
            "result": copy.deepcopy(validation_result),
            "digest": "0" * 64,
        }
        validation_receipt["digest"] = semantic_digest(validation_receipt)
        _selftest_write(fixture["receipt_path"], validation_receipt)
        validation_receipt_report = verify_receipt(fixture["receipt_path"])
        rewrite(fixture["result_path"], fixture["result_raw"])
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])

        unbound_gold = copy.deepcopy(validation_plan)
        unbound_gold["gold_inputs"][0].update({
            "path": wrong_gold_path,
            "byte_length": os.path.getsize(wrong_gold_path),
            "file_sha256": raw_sha256(read_trusted_bytes(
                wrong_gold_path, label="wrong validation source")),
        })
        unbound_gold["digest"] = semantic_digest(unbound_gold)
        unbound_feature = copy.deepcopy(validation_plan)
        unbound_feature["invocation"]["harness_inputs"]["feature_inputs"] = [
            _selftest_raw_ref(wrong_feature_path)]
        unbound_feature["invocation_digest"] = domain_digest(
            VALIDATION_INVOCATION_SCHEMA, unbound_feature["invocation"])
        unbound_feature["digest"] = semantic_digest(unbound_feature)
        behave_coordinator = copy.deepcopy(validation_plan)
        behave_coordinator["invocation"]["harness_inputs"]["alias_table"] = (
            _selftest_raw_ref(extra_path))
        behave_coordinator["invocation_digest"] = domain_digest(
            VALIDATION_INVOCATION_SCHEMA, behave_coordinator["invocation"])
        behave_coordinator["digest"] = semantic_digest(behave_coordinator)

        def validation_plan_refused(candidate: dict) -> bool:
            reader = _LiveReader()
            runtime = _verify_runtime(
                reader, fixture["receipt"]["execution"]["runtime"])
            return refused(
                lambda: _verify_validation_plan(reader, candidate, runtime))

        check("validation checkpoint authenticates rows and its receipt "
              "verifies complete in I3",
              validation_context.item_ids == [item_id]
              and validation_checkpoint_report["verified"] is True
              and validation_checkpoint_report["complete"] is False
              and validation_receipt_report["artifact_kind"] == "validation"
              and validation_receipt_report["complete"] is True)
        check("validation refuses unbound gold, feature, and Behave coordinator "
              "inputs",
              validation_plan_refused(unbound_gold)
              and validation_plan_refused(unbound_feature)
              and validation_plan_refused(behave_coordinator))

        original_reserved = _reserved_adapter_kinds()
        original_resolver = globals()["_reserved_adapter_kinds"]
        original_names = globals()["_ADMITTED_ADAPTER_NAMES"]

        # THE PROBE SIGNS A v1 RECEIPT PER KIND, so it can only be driven
        # with kinds a v1 receipt may NAME.  `result-ledger-v1.schema.json`
        # closes `adapter.kind` with the enum of the eight kinds that existed
        # when it was published; those are frozen published bytes, so a third
        # arm's kind is refused by the schema before `_verify_adapter` is
        # reached.  The baseline half would then be a refusal for the wrong
        # reason and the mutant half -- which must NOT swallow refusals, or
        # it could not tell a killed mutant from a live one -- would take the
        # exception out of `selftest` and end the whole battery.
        #
        # `_RESERVED_NON_AGENT_KINDS` is a literal the published enum carries
        # by construction; only the DERIVED agent half can grow past it, so
        # that is the half intersected.  A third arm is still reserved here
        # (the excursion below drives exactly that, through `_verify_adapter`
        # where no receipt is signed), and what it owes the agent producer is
        # `result_ledger_v2_selftest._third_agent_checks`, which is built for
        # it.
        v1_kinds = frozenset(_schema(RECEIPT_SCHEMA)["$defs"]
                             ["adapterInvocation"]["properties"]["kind"]
                             ["enum"])

        def v1_signable_reserved() -> frozenset:
            reserved = _reserved_adapter_kinds()
            return _RESERVED_NON_AGENT_KINDS | (
                (reserved - _RESERVED_NON_AGENT_KINDS) & v1_kinds)

        def reserved_probe() -> tuple:
            """Baseline refusals and admission mutants, per signable kind."""
            baseline, mutants = {}, {}
            for kind in sorted(v1_signable_reserved()):
                baseline[kind] = refused(
                    lambda kind=kind: signed_adapter_outcome(
                        kind, kind, [], []))
                globals()["_reserved_adapter_kinds"] = lambda: frozenset()
                globals()["_ADMITTED_ADAPTER_NAMES"] = {
                    **original_names, kind: kind}
                try:
                    mutants[kind] = signed_adapter_outcome(
                        kind, kind, [], [])
                finally:
                    globals()["_reserved_adapter_kinds"] = original_resolver
                    globals()["_ADMITTED_ADAPTER_NAMES"] = original_names
            return baseline, mutants

        reserved_results, reserved_mutants = reserved_probe()
        # The floor was the literal {"aider", "openhands", "replay",
        # "openai"} -- the two arms this study ships plus the two non-agent
        # kinds -- and a benchmark-only checkout ships no arm at all, so the
        # floor is `_reserved_adapter_kinds`'s own composition instead: the
        # non-agent kinds, plus whatever the REGISTRY files as an agent.
        # Read from the registry rather than from the v2 producer the
        # resolver goes through, so the two seams still have to agree.
        try:
            from ..agents.registry import SPECS as _specs
        except ImportError:
            shipped_agents = frozenset()
        else:
            shipped_agents = frozenset(spec.name for spec in _specs
                                       if spec.kind == "agent")
        reserved_floor = _RESERVED_NON_AGENT_KINDS | (shipped_agents & v1_kinds)
        check("every reserved adapter a v1 receipt may NAME refuses, and its "
              "admission mutant is killed",
              # The bound is derived, so it has to be shown that it did not
              # silently shrink: the probe covers exactly the signable
              # reserved kinds, and never fewer than the systems this
              # checkout actually ships.
              sorted(reserved_results) == sorted(v1_signable_reserved())
              and reserved_floor <= frozenset(reserved_results)
              and all(reserved_results.values())
              and all(reserved_mutants.values()),
              str({"floor": sorted(reserved_floor),
                   "baseline": reserved_results,
                   "mutant": reserved_mutants}))

        # THE SET IS DERIVED, so the thing to show is that it MOVES.  The loop
        # above proves the gate is load-bearing for the arms that exist; it
        # would keep passing unchanged if the agent half were still a literal,
        # because those two arms ARE the literal.  What only the derivation
        # can do is reserve an arm this file has never heard of, so a third
        # spec is registered on the registry -- never by editing `SPECS` in
        # place, since everything else reads that table -- and the gate is
        # driven with its kind.
        #
        # Driven THROUGH `_verify_adapter` rather than through
        # `signed_adapter_outcome`, and that is a fact about this version
        # worth stating rather than working around: `result-ledger-v1.schema
        # .json` closes `adapter.kind` with its own enum of the eight kinds
        # that existed when it was published, so a whole signed v1 receipt
        # naming a third arm never reaches this function at all.  A published
        # schema is an identity, not a table to grow; this check therefore
        # asserts what this module decides, at the one place it decides it.
        #
        # Without the derivation `acme` falls past the reserved branch into
        # the admitted-name check and is refused as an UNSUPPORTED kind:
        # still a refusal, but one that tells an operator the harness has
        # never heard of a system it in fact ships an arm for.  The message
        # is therefore asserted, not just the refusal.
        try:
            from ..agents import registry as _reg
            from ..agents.base import AdapterSpec as _Spec
        except ImportError:
            print("      [SKIP] the third-arm reservation legs: registering the "
                  "spec is what reserves the kind, and this checkout has no agent "
                  "component to register one from")
        else:
            third = _Spec(name="acme", version=1, kind="agent",
                          build=lambda args, harness: None,
                          trajectory_format="openhands.events/1",
                          sandbox="bwrap",
                          comparison_class="fixed_model_scaffold")

            def adapter_gate(kind: str) -> str:
                # `reader` and the rest are never touched: the reserved branch is
                # the first statement of the function, which is the point.
                invocation = {"adapter": {
                    "kind": kind, "name": kind, "secret_inputs": [],
                    "public_configuration": [], "files": []}}
                try:
                    _verify_adapter(None, invocation, [], [], "", None, None, None)
                except ResultLedgerRefused as exc:
                    return str(exc)
                return ""

            _reg.REGISTRY[third.name] = third
            _reg.SPECS = _reg.SPECS + (third,)
            try:
                third_reserved = third.name in _reserved_adapter_kinds()
                third_refusal = adapter_gate(third.name)
                # THE PROBE ABOVE, RE-DRIVEN WITH THE THIRD ARM REGISTERED --
                # the state the whole battery runs in once an arm is added, and
                # the state the probe used to DIE in.  Its mutant half signed a
                # receipt naming `acme`, the published v1 enum refused it, and
                # the exception left `selftest` altogether: no `[FAIL]` line, no
                # `ALL PASS`, the sweep stopping at this module.
                third_signable = v1_signable_reserved()
                third_probe = reserved_probe()
                third_signed = refused(
                    lambda: signed_adapter_outcome(
                        third.name, third.name, [], []))
            finally:
                del _reg.REGISTRY[third.name]
                _reg.SPECS = tuple(s for s in _reg.SPECS if s is not third)
            check("a third agent is reserved by its SPEC -- registering it is "
                  "what reserves it here, de-registering it releases it, and no "
                  "edit to this module is involved either way",
                  third_reserved
                  and "kind 'acme' is reserved and not admitted" in third_refusal
                  and third.name not in _reserved_adapter_kinds()
                  and _reserved_adapter_kinds() == original_reserved
                  and "kind 'acme' is unsupported" in adapter_gate(third.name),
                  f"reserved={third_reserved} refusal={third_refusal!r} "
                  f"after={sorted(_reserved_adapter_kinds())}")
            check("...and registering it leaves the signed-receipt probe intact "
                  "instead of ending the battery: a v1 receipt NAMING it is "
                  "refused by the published enum, which is exactly why the "
                  "probe's bound excludes it, and the probe still runs over the "
                  "same reserved kinds with the same verdicts",
                  third_signed
                  and third.name not in third_signable
                  and third_signable == v1_signable_reserved()
                  and third_probe == (reserved_results, reserved_mutants),
                  f"signed_receipt_refused={third_signed} "
                  f"signable_with_third={sorted(third_signable)} "
                  f"probe_moved={third_probe != (reserved_results, reserved_mutants)}")

        diagnostic_start = loads_exact_json(
            fixture["worker_manifest_raw"],
            label="WorkerManifest diagnostic timestamp fixture")
        diagnostic_start["worker"]["started_at"] = None
        diagnostic_worker_raw = _selftest_write(
            fixture["worker_manifest_path"], diagnostic_start)
        diagnostic_receipt = copy.deepcopy(fixture["receipt"])
        diagnostic_receipt["worker_manifest"]["file_sha256"] = raw_sha256(
            diagnostic_worker_raw)
        diagnostic_receipt["digest"] = semantic_digest(diagnostic_receipt)
        _selftest_write(fixture["receipt_path"], diagnostic_receipt)
        null_start_ok = verify_receipt(
            fixture["receipt_path"])["complete"]
        rewrite(fixture["worker_manifest_path"],
                fixture["worker_manifest_raw"])
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])
        check("WorkerManifest started_at remains diagnostic and may be null",
              null_start_ok)

        # A protocol-bound fixture still carries the complete effective knob
        # projection even though it makes no model call.  Build one fully
        # signed positive and then make plan/campaign-independent stamp bytes
        # contradict the bound protocol.
        from . import campaign as campaign_module
        from . import protocol_file as protocol_module
        protocol_source = os.path.join(PROTOCOL_DIR, "protocol_v4.yml")
        with open(protocol_source, "rb") as fh:
            protocol_raw = fh.read()
        protocol_path = fixture["root"] + "/config/protocol_v4.yml"
        _selftest_write(protocol_path, protocol_raw, raw=True)
        protocol_document = _parse_yaml(protocol_raw, "protocol fixture")
        protocol_digest = protocol_module.protocol_digest(protocol_document)

        protocol_campaign = loads_exact_json(
            fixture["campaign_raw"], label="protocol campaign fixture")
        protocol_campaign.update({
            "condition": protocol_document["condition"],
            "trial_budget": protocol_document["trials"],
            "coverage": protocol_document["coverage"],
            "protocol_version": protocol_document["protocol_version"],
            "protocol_digest": protocol_digest,
        })
        protocol_campaign_raw = _selftest_write(
            fixture["campaign_path"], protocol_campaign)
        protocol_campaign_digest = campaign_module.campaign_digest(
            protocol_campaign)
        protocol_plan = copy.deepcopy(fixture["receipt"]["plan"])
        protocol_plan["campaign"] = {
            "path": fixture["campaign_path"],
            "file_sha256": raw_sha256(protocol_campaign_raw),
            "campaign_digest": protocol_campaign_digest,
            "semantic_digest": semantic_digest(protocol_campaign),
        }
        protocol_plan["protocol"] = _selftest_raw_ref(
            protocol_path, protocol_raw)
        protocol_stamp = {
            "agent_timeout_seconds": protocol_document[
                "agent_timeout_seconds"],
            "campaign_digest": protocol_campaign_digest,
            "condition": protocol_document["condition"],
            "coverage": protocol_document["coverage"],
            "max_iterations": protocol_document["max_iterations"],
            "protocol_digest": protocol_digest,
            "protocol_version": protocol_document["protocol_version"],
            "repeats": protocol_document["repeats"],
            "setting": protocol_document["setting"],
            "temperature": protocol_document["temperature"],
            "trials": protocol_document["trials"],
        }
        for named in protocol_plan["invocation"]["effective_run_stamp"]:
            if named["name"] in protocol_stamp:
                named["value_json"] = canonical_json_bytes(
                    protocol_stamp[named["name"]]).decode()
        protocol_plan["invocation_digest"] = domain_digest(
            RUN_INVOCATION_SCHEMA, protocol_plan["invocation"])
        protocol_plan["digest"] = semantic_digest(protocol_plan)

        protocol_row = copy.deepcopy(fixture["result_row"])
        protocol_row.update(protocol_stamp)
        protocol_result_raw = (json.dumps(
            protocol_row, sort_keys=True, separators=(",", ":")) + "\n").encode()
        rewrite(fixture["result_path"], protocol_result_raw)
        protocol_worker = loads_exact_json(
            fixture["worker_manifest_raw"], label="protocol WorkerManifest")
        protocol_worker["campaign"] = protocol_campaign
        protocol_worker["campaign_digest"] = protocol_campaign_digest
        protocol_worker["worker"]["campaign_digest"] = protocol_campaign_digest
        protocol_worker_raw = _selftest_write(
            fixture["worker_manifest_path"], protocol_worker)
        protocol_receipt = copy.deepcopy(fixture["receipt"])
        protocol_receipt["plan"] = protocol_plan
        protocol_receipt["result"].update({
            "byte_length": len(protocol_result_raw),
            "file_sha256": raw_sha256(protocol_result_raw),
        })
        protocol_receipt["worker_manifest"]["file_sha256"] = raw_sha256(
            protocol_worker_raw)
        protocol_receipt["digest"] = semantic_digest(protocol_receipt)
        _selftest_write(fixture["receipt_path"], protocol_receipt)
        protocol_positive = verify_receipt(
            fixture["receipt_path"])["complete"]

        protocol_mismatch = copy.deepcopy(protocol_receipt)
        mismatch_plan = protocol_mismatch["plan"]
        for named in mismatch_plan["invocation"]["effective_run_stamp"]:
            if named["name"] == "max_iterations":
                named["value_json"] = canonical_json_bytes(
                    protocol_document["max_iterations"] + 1).decode()
                break
        mismatch_plan["invocation_digest"] = domain_digest(
            RUN_INVOCATION_SCHEMA, mismatch_plan["invocation"])
        mismatch_plan["digest"] = semantic_digest(mismatch_plan)
        mismatch_row = copy.deepcopy(protocol_row)
        mismatch_row["max_iterations"] = \
            protocol_document["max_iterations"] + 1
        mismatch_result_raw = (json.dumps(
            mismatch_row, sort_keys=True, separators=(",", ":")) + "\n").encode()
        rewrite(fixture["result_path"], mismatch_result_raw)
        protocol_mismatch["result"].update({
            "byte_length": len(mismatch_result_raw),
            "file_sha256": raw_sha256(mismatch_result_raw),
        })
        protocol_mismatch["digest"] = semantic_digest(protocol_mismatch)
        _selftest_write(fixture["receipt_path"], protocol_mismatch)
        protocol_mismatch_refused = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["campaign_path"], fixture["campaign_raw"])
        rewrite(fixture["result_path"], fixture["result_raw"])
        rewrite(fixture["worker_manifest_path"],
                fixture["worker_manifest_raw"])
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])
        check("bound protocol knobs replay exactly and a signed mismatch refuses",
              protocol_positive and protocol_mismatch_refused)

        documents = _selftest_schema_documents(fixture)
        schema_exhaustive = True
        schema_cases = 0

        def dictionaries(value, path=()):
            if isinstance(value, dict):
                yield path, value
                for key, child in value.items():
                    yield from dictionaries(child, path + (key,))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    yield from dictionaries(child, path + (index,))

        def at(value, path):
            for part in path:
                value = value[part]
            return value

        for _label, document, validator in documents:
            validator(document)
            for path, mapping in list(dictionaries(document)):
                for key in list(mapping):
                    missing = copy.deepcopy(document)
                    del at(missing, path)[key]
                    unknown = copy.deepcopy(document)
                    at(unknown, path)["unknown_i1_field"] = None
                    wrong = copy.deepcopy(document)
                    # 0.5 is outside every v1 field's type vocabulary: the
                    # only numeric schema fields are exact integers. It also
                    # avoids choosing null for fields whose oneOf explicitly
                    # permits null (git_commit, protocol, strip_manifest).
                    at(wrong, path)[key] = 0.5
                    schema_cases += 3
                    schema_exhaustive = schema_exhaustive and all(
                        refused(lambda candidate=candidate, validate=validator:
                                validate(candidate))
                        for candidate in (missing, unknown, wrong))
        check("every present schema field refuses missing, unknown, and wrong type",
              schema_exhaustive, f"{schema_cases} generated schema cases")

        malformed_hashes = True
        hash_cases = 0
        for _label, document, validator in documents:
            for path, mapping in list(dictionaries(document)):
                for key, value in list(mapping.items()):
                    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
                        continue
                    uppercase = (value.upper() if any(
                        char in "abcdef" for char in value)
                                 else "A" + value[1:])
                    for replacement in (uppercase, value[:-1]):
                        candidate = copy.deepcopy(document)
                        at(candidate, path)[key] = replacement
                        malformed_hashes = malformed_hashes and refused(
                            lambda candidate=candidate, validate=validator:
                            validate(candidate))
                        hash_cases += 1
        check("every schema hash occurrence refuses uppercase and truncation",
              malformed_hashes, f"{hash_cases} generated hash cases")
        campaign_hex = fixture["receipt"]["plan"]["campaign"][
            "campaign_digest"]
        malformed_campaign_hex = []
        campaign_upper = (campaign_hex.upper() if any(
            char in "abcdef" for char in campaign_hex)
                          else "A" + campaign_hex[1:])
        for replacement in (campaign_upper, campaign_hex[:-1]):
            candidate = copy.deepcopy(fixture["receipt"])
            candidate["plan"]["campaign"]["campaign_digest"] = replacement
            malformed_campaign_hex.append(refused(
                lambda candidate=candidate: validate_receipt_schema(candidate)))
        check("uppercase and truncated compatibility hashes refuse",
              all(malformed_campaign_hex))

        checkpoint_complete = copy.deepcopy(fixture["checkpoint"])
        checkpoint_complete["state"] = "complete"
        check("checkpoint can never spell or imply complete",
              refused(lambda: validate_checkpoint_schema(checkpoint_complete)))
        bundle = copy.deepcopy(documents[-1][1])
        bundle["digest"] = semantic_digest(bundle)
        check("bundle index receives only I1 schema/digest validation",
              validate_bundle_index_document(bundle) == bundle["digest"])

        original_result = fixture["result_raw"]
        row = fixture["result_row"]
        raw_variants = (
            (json.dumps(row, sort_keys=True) + "\n").encode(),
            (json.dumps(dict(reversed(list(row.items()))),
                        separators=(",", ":")) + "\n").encode(),
            original_result[:-1] + b"\r\n",
            original_result[:-1],
        )
        raw_refusals = []
        for raw in raw_variants:
            rewrite(fixture["result_path"], raw)
            raw_refusals.append(refused(
                lambda: verify_receipt(fixture["receipt_path"])))
        rewrite(fixture["result_path"], original_result)
        check("result raw hash detects whitespace, ordering, and final-newline edits",
              all(raw_refusals))

        ordered_path = fixture["root"] + "/runs/two-records.jsonl"
        ordered_raw = b'{"item_id":"a"}\n{"item_id":"b"}\n'
        reversed_raw = b'{"item_id":"b"}\n{"item_id":"a"}\n'
        _selftest_write(ordered_path, ordered_raw, raw=True)
        ordered_binding = {
            "path": ordered_path, "byte_length": len(ordered_raw),
            "row_count": 2, "file_sha256": raw_sha256(ordered_raw),
        }
        _ordered_bytes, ordered_rows = _verify_result_bytes(
            _LiveReader(), ordered_binding, "ordered result fixture",
            prefix=False)
        ordered_positive = not refused(lambda: _verify_row_sequence(
            ordered_rows, ["a", "b"]))
        rewrite(ordered_path, reversed_raw)
        physical_hash_refused = refused(lambda: _verify_result_bytes(
            _LiveReader(), ordered_binding, "reordered result fixture",
            prefix=False))
        reversed_binding = {
            **ordered_binding, "file_sha256": raw_sha256(reversed_raw)}
        _reversed_bytes, reversed_rows = _verify_result_bytes(
            _LiveReader(), reversed_binding, "re-signed reordered result",
            prefix=False)
        physical_sequence_refused = refused(lambda: _verify_row_sequence(
            reversed_rows, ["a", "b"]))
        check("physical two-record JSONL order is bound by both raw hash and "
              "frozen workset",
              ordered_positive and physical_hash_refused
              and physical_sequence_refused)

        def refusal(fn) -> str:
            try:
                fn()
            except ResultLedgerRefused as exc:
                return str(exc)
            return ""

        plan_stamp = {name: None for name in RUN_STAMP_NAMES}
        plan_stamp["harness_commit"] = "abc1234"

        def stamped_row(**changes) -> list:
            return [{"item_id": "a", **plan_stamp, **changes}]

        check("a row produced under another commit than its plan is accepted "
              "(section 16.5), a malformed one and another harness version "
              "still refuse",
              not refused(lambda: _verify_row_sequence(
                  stamped_row(harness_commit="def5678"), ["a"],
                  stamp=plan_stamp))
              and "harness_commit is malformed" in refusal(
                  lambda: _verify_row_sequence(
                      stamped_row(harness_commit="xyz"), ["a"],
                      stamp=plan_stamp))
              and "effective stamp differs" in refusal(
                  lambda: _verify_row_sequence(
                      stamped_row(harness_version=HARNESS_VERSION + 1),
                      ["a"], stamp=plan_stamp)))

        rewrite(fixture["campaign_path"], fixture["campaign_raw"] + b"\n")
        stale_campaign = refused(lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["campaign_path"], fixture["campaign_raw"])
        rewrite(fixture["archive_path"], fixture["archive_raw"] + b"stale")
        stale_archive = refused(lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["archive_path"], fixture["archive_raw"])
        check("stale companion and seed archive bytes refuse",
              stale_campaign and stale_archive)

        receipt_duplicate = fixture["receipt_raw"].rstrip()[:-1] \
            + b',"schema":"r2t.result-ledger/v1"}\n'
        rewrite(fixture["receipt_path"], receipt_duplicate)
        duplicate_receipt = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])
        check("standalone receipt parser rejects duplicate top-level keys",
              duplicate_receipt)

        def signed_identity_change(field, value) -> bool:
            receipt = copy.deepcopy(fixture["receipt"])
            receipt["execution"]["runtime"]["identity"][field] = value
            identity = receipt["execution"]["runtime"]["identity"]
            identity["digest"] = semantic_digest(identity)
            receipt["digest"] = semantic_digest(receipt)
            _selftest_write(fixture["receipt_path"], receipt)
            outcome = refused(lambda: verify_receipt(fixture["receipt_path"]))
            rewrite(fixture["receipt_path"], fixture["receipt_raw"])
            return outcome

        identity = fixture["receipt"]["execution"]["runtime"]["identity"]
        join_mutations = {
            "authority": ("docker_execution_authority",
                          {**identity["docker_execution_authority"],
                           "file_sha256": "f" * 64}),
            "binding": ("docker_execution_binding",
                        {**identity["docker_execution_binding"],
                         "file_sha256": "f" * 64}),
            "daemon": ("docker_daemon_fingerprint_sha256", "f" * 64),
            "pool": ("docker_execution_pool_digest", "f" * 64),
            "worker-index": ("worker_index", 1),
            "worker-path": ("worker_spec_path", fixture["root"] + "/other.json"),
            "worker-hash": ("worker_spec_sha256", "f" * 64),
            "image": ("container_image_digest", "sha256:" + "f" * 64),
            "seed-dir": ("seed_dir", fixture["root"] + "/other-seed"),
            "seed-key": ("seed_key", "another-seed"),
            "seed-archive": ("workspace_seed_digest", "f" * 64),
            "harness-version": ("harness",
                                {**identity["harness"],
                                 "version": HARNESS_VERSION + 1}),
            "harness-commit-malformed": ("harness",
                                         {**identity["harness"],
                                          "git_commit": "f" * 39}),
        }
        join_results = {
            name: signed_identity_change(field, value)
            for name, (field, value) in join_mutations.items()
        }

        # SECTION 16: the recorded commit/source pair is provenance, not an
        # equality.  A receipt recorded by another tree verifies, and the
        # verifier says so once per process on stderr.
        def signed_identity_drift(value) -> tuple:
            receipt = copy.deepcopy(fixture["receipt"])
            receipt["execution"]["runtime"]["identity"]["harness"] = value
            identity = receipt["execution"]["runtime"]["identity"]
            identity["digest"] = semantic_digest(identity)
            receipt["digest"] = semantic_digest(receipt)
            _selftest_write(fixture["receipt_path"], receipt)
            notes = []
            verified = []
            try:
                for _ in range(2):
                    stderr = io.StringIO()
                    with contextlib.redirect_stderr(stderr):
                        verified.append(
                            verify_receipt(fixture["receipt_path"])["verified"])
                    notes.append(stderr.getvalue())
            finally:
                rewrite(fixture["receipt_path"], fixture["receipt_raw"])
            return verified, notes

        drift_source = signed_identity_drift(
            {**identity["harness"], "source_sha256": "f" * 64})
        # The plan's 7-hex stamp is a within-plan prefix join on the recorded
        # commit and stays, so the drifted commit keeps that prefix.
        recorded_commit = identity["harness"]["git_commit"]
        drift_commit = signed_identity_drift(
            {**identity["harness"],
             "git_commit": recorded_commit[:7] + "f" * 33})
        check("a receipt whose recorded harness source digest or commit "
              "differs from the live tree verifies with one drift note, "
              "printed once per process",
              all(drift_source[0]) and all(drift_commit[0])
              and drift_source[1][0].count("note: harness recorded at") == 1
              and drift_commit[1][0].count("note: harness recorded at") == 1
              and drift_source[1][1] == "" and drift_commit[1][1] == "",
              repr((drift_source, drift_commit))[:300])
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            same_tree = verify_receipt(fixture["receipt_path"])["verified"]
        check("the unmodified receipt, recorded by this tree, verifies "
              "without a note",
              same_tree and stderr.getvalue() == "", stderr.getvalue())

        runtime = copy.deepcopy(fixture["runtime"])
        runtime["worker"]["workdir"] = "/another-workdir"
        runtime_raw = _selftest_write(fixture["runtime_path"], runtime)
        receipt = copy.deepcopy(fixture["receipt"])
        receipt["execution"]["runtime"]["file_sha256"] = raw_sha256(runtime_raw)
        receipt["digest"] = semantic_digest(receipt)
        _selftest_write(fixture["receipt_path"], receipt)
        join_results["runtime-worker"] = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["runtime_path"], fixture["runtime_raw"])
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])

        runtime = copy.deepcopy(fixture["runtime"])
        runtime["docker_execution_authority"]["file_sha256"] = "f" * 64
        runtime_raw = _selftest_write(fixture["runtime_path"], runtime)
        receipt = copy.deepcopy(fixture["receipt"])
        receipt["execution"]["runtime"]["file_sha256"] = raw_sha256(runtime_raw)
        receipt["digest"] = semantic_digest(receipt)
        _selftest_write(fixture["receipt_path"], receipt)
        join_results["runtime-authority"] = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["runtime_path"], fixture["runtime_raw"])
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])

        binding = copy.deepcopy(fixture["binding"])
        binding["authority"]["file_sha256"] = "f" * 64
        binding["digest"] = semantic_digest(binding)
        binding_raw = _selftest_write(fixture["binding_path"], binding)
        binding_ref = {"path": fixture["binding_path"],
                       "file_sha256": raw_sha256(binding_raw),
                       "digest": binding["digest"]}
        runtime = copy.deepcopy(fixture["runtime"])
        runtime["docker_execution_binding"] = binding_ref
        runtime_raw = _selftest_write(fixture["runtime_path"], runtime)
        receipt = copy.deepcopy(fixture["receipt"])
        receipt["execution"]["runtime"]["file_sha256"] = raw_sha256(runtime_raw)
        receipt["execution"]["runtime"]["identity"][
            "docker_execution_binding"] = binding_ref
        receipt_identity = receipt["execution"]["runtime"]["identity"]
        receipt_identity["digest"] = semantic_digest(receipt_identity)
        receipt["digest"] = semantic_digest(receipt)
        _selftest_write(fixture["receipt_path"], receipt)
        join_results["binding-authority"] = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["binding_path"], fixture["binding_raw"])
        rewrite(fixture["runtime_path"], fixture["runtime_raw"])
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])
        check("every runtime/authority/binding/daemon/pool/worker/image/seed/"
              "harness-version join mutation refuses",
              all(join_results.values()),
              str(sorted(name for name, value in join_results.items()
                         if not value)))

        # A binding whose pool selects another container is rejected by the
        # binding's own complete pool/container join before ledger projection.
        binding = copy.deepcopy(fixture["binding"])
        binding["pool"]["workers"][0]["container_name"] = "other_worker"
        binding["pool"]["digest"] = semantic_digest(binding["pool"])
        binding["digest"] = semantic_digest(binding)
        binding_raw = _selftest_write(fixture["binding_path"], binding)
        runtime = copy.deepcopy(fixture["runtime"])
        changed_ref = {"path": fixture["binding_path"],
                       "file_sha256": raw_sha256(binding_raw),
                       "digest": binding["digest"]}
        runtime["docker_execution_binding"] = changed_ref
        runtime_raw = _selftest_write(fixture["runtime_path"], runtime)
        receipt = copy.deepcopy(fixture["receipt"])
        receipt["execution"]["runtime"]["file_sha256"] = raw_sha256(runtime_raw)
        receipt["execution"]["runtime"]["identity"][
            "docker_execution_binding"] = changed_ref
        receipt_identity = receipt["execution"]["runtime"]["identity"]
        receipt_identity["digest"] = semantic_digest(receipt_identity)
        receipt["digest"] = semantic_digest(receipt)
        _selftest_write(fixture["receipt_path"], receipt)
        pool_container_refused = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["binding_path"], fixture["binding_raw"])
        rewrite(fixture["runtime_path"], fixture["runtime_raw"])
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])
        check("binding pool/container mismatch refuses", pool_container_refused)

        alternate_runtime_path = fixture["root"] + "/alternate-runtime.json"
        _selftest_write(
            alternate_runtime_path, fixture["runtime_raw"], raw=True)
        alternate_runtime_receipt = copy.deepcopy(fixture["receipt"])
        alternate_runtime_receipt["execution"]["runtime"]["path"] = (
            alternate_runtime_path)
        alternate_runtime_receipt["digest"] = semantic_digest(
            alternate_runtime_receipt)
        _selftest_write(fixture["receipt_path"], alternate_runtime_receipt)
        alternate_runtime_refused = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])

        forged_seed_key = "fixture-seed-key\nforged"
        shaped_seed = loads_exact_json(
            fixture["seed_raw"], label="runtime shape seed fixture")
        shaped_seed["seed_key"] = forged_seed_key
        shaped_seed_raw = _selftest_write(fixture["seed_path"], shaped_seed)
        shaped_runtime = copy.deepcopy(fixture["runtime"])
        shaped_runtime["seed_manifest_sha256"] = raw_sha256(shaped_seed_raw)
        shaped_runtime["seed_key"] = forged_seed_key
        shaped_runtime_raw = _selftest_write(
            fixture["runtime_path"], shaped_runtime)
        shaped_receipt = copy.deepcopy(fixture["receipt"])
        shaped_receipt["execution"]["runtime"]["file_sha256"] = raw_sha256(
            shaped_runtime_raw)
        shaped_identity = shaped_receipt["execution"]["runtime"]["identity"]
        shaped_identity["seed_manifest"]["file_sha256"] = raw_sha256(
            shaped_seed_raw)
        shaped_identity["seed_key"] = forged_seed_key
        shaped_identity["digest"] = semantic_digest(shaped_identity)
        shaped_receipt["digest"] = semantic_digest(shaped_receipt)
        _selftest_write(fixture["receipt_path"], shaped_receipt)
        runtime_shape_refused = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["seed_path"], fixture["seed_raw"])
        rewrite(fixture["runtime_path"], fixture["runtime_raw"])
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])

        contained_authority_path = (
            fixture["root"] + "/workspace/authority-copy.json")
        _selftest_write(
            contained_authority_path, fixture["authority_raw"], raw=True)
        contained_authority_ref = {
            "path": contained_authority_path,
            "file_sha256": raw_sha256(fixture["authority_raw"]),
            "digest": fixture["authority"]["digest"],
        }
        contained_binding = copy.deepcopy(fixture["binding"])
        contained_binding["authority"] = contained_authority_ref
        contained_binding["digest"] = semantic_digest(contained_binding)
        contained_binding_raw = _selftest_write(
            fixture["binding_path"], contained_binding)
        contained_binding_ref = {
            "path": fixture["binding_path"],
            "file_sha256": raw_sha256(contained_binding_raw),
            "digest": contained_binding["digest"],
        }
        contained_runtime = copy.deepcopy(fixture["runtime"])
        contained_runtime["docker_execution_authority"] = (
            contained_authority_ref)
        contained_runtime["docker_execution_binding"] = contained_binding_ref
        contained_runtime_raw = _selftest_write(
            fixture["runtime_path"], contained_runtime)
        contained_receipt = copy.deepcopy(fixture["receipt"])
        contained_runtime_ref = contained_receipt["execution"]["runtime"]
        contained_runtime_ref["file_sha256"] = raw_sha256(
            contained_runtime_raw)
        contained_identity = contained_runtime_ref["identity"]
        contained_identity["docker_execution_authority"] = (
            contained_authority_ref)
        contained_identity["docker_execution_binding"] = contained_binding_ref
        contained_identity["digest"] = semantic_digest(contained_identity)
        contained_receipt["digest"] = semantic_digest(contained_receipt)
        _selftest_write(fixture["receipt_path"], contained_receipt)
        contained_authority_refused = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["binding_path"], fixture["binding_raw"])
        rewrite(fixture["runtime_path"], fixture["runtime_raw"])
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])

        contained_campaign_path = (
            fixture["root"] + "/workspace/campaign-copy.json")
        _selftest_write(
            contained_campaign_path, fixture["campaign_raw"], raw=True)
        contained_campaign_receipt = copy.deepcopy(fixture["receipt"])
        contained_campaign_receipt["plan"]["campaign"]["path"] = (
            contained_campaign_path)
        contained_campaign_receipt["plan"]["digest"] = semantic_digest(
            contained_campaign_receipt["plan"])
        contained_campaign_receipt["digest"] = semantic_digest(
            contained_campaign_receipt)
        _selftest_write(
            fixture["receipt_path"], contained_campaign_receipt)
        contained_campaign_refused = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])
        agent_runtime_path = fixture["campaign_path"] + ".agent_runtime.json"
        agent_runtime_raw = read_trusted_bytes(
            agent_runtime_path, label="campaign agent-runtime fixture")
        alternate_agent_runtime_path = (
            fixture["root"] + "/alternate-agent-runtime.json")
        _selftest_write(
            alternate_agent_runtime_path, agent_runtime_raw, raw=True)
        alternate_agent_receipt = copy.deepcopy(fixture["receipt"])
        alternate_agent_receipt["plan"]["campaign_agent_runtime"]["path"] = (
            alternate_agent_runtime_path)
        alternate_agent_receipt["plan"]["digest"] = semantic_digest(
            alternate_agent_receipt["plan"])
        alternate_agent_receipt["digest"] = semantic_digest(
            alternate_agent_receipt)
        _selftest_write(fixture["receipt_path"], alternate_agent_receipt)
        alternate_agent_runtime_refused = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])
        check("runtime-v3 shape, original attestation path, and workspace "
              "separation refuse fully re-signed evidence aliases",
              alternate_runtime_refused and runtime_shape_refused
              and contained_authority_refused
              and contained_campaign_refused
              and alternate_agent_runtime_refused)

        def signed_citation_outcome(values: dict[str, object]) -> bool:
            citation_receipt = copy.deepcopy(fixture["receipt"])
            citation_plan = citation_receipt["plan"]
            for named in citation_plan["invocation"]["effective_run_stamp"]:
                if named["name"] in values:
                    named["value_json"] = canonical_json_bytes(
                        values[named["name"]]).decode()
            citation_plan["invocation_digest"] = domain_digest(
                RUN_INVOCATION_SCHEMA, citation_plan["invocation"])
            citation_plan["digest"] = semantic_digest(citation_plan)
            citation_row = copy.deepcopy(fixture["result_row"])
            citation_row.update(values)
            citation_result_raw = (json.dumps(
                citation_row, sort_keys=True,
                separators=(",", ":")) + "\n").encode()
            rewrite(fixture["result_path"], citation_result_raw)
            citation_receipt["result"].update({
                "byte_length": len(citation_result_raw),
                "file_sha256": raw_sha256(citation_result_raw),
            })
            citation_receipt["digest"] = semantic_digest(citation_receipt)
            _selftest_write(fixture["receipt_path"], citation_receipt)
            try:
                return verify_receipt(fixture["receipt_path"])["complete"]
            finally:
                rewrite(fixture["result_path"], fixture["result_raw"])
                rewrite(fixture["receipt_path"], fixture["receipt_raw"])

        citable_projection = {
            "dataset_version": "1.0",
            "subset_id": "evaldocx32",
            "subset_digest": "a" * 16,
        }
        citable_positive = signed_citation_outcome(citable_projection)
        malformed_citations = (
            {"dataset_version": 1},
            {"subset_id": "evaldocx32"},
            {"subset_digest": "a" * 16},
            {"subset_id": "evaldocx32", "subset_digest": "A" * 16},
            {"subset_id": "evaldocx32", "subset_digest": "a" * 15},
        )
        check("applicable dataset/subset claims verify as frozen plan values "
              "and malformed identities refuse",
              citable_positive and all(refused(
                  lambda values=values: signed_citation_outcome(values))
                  for values in malformed_citations))

        # Python considers False == 0 and True == 1.  Ledger joins are exact
        # JSON-value joins, so signed, fully rehashed evidence must not use
        # that host-language equivalence to cross a type boundary.
        def signed_stamp_refusal(name: str, value: object) -> bool:
            typed_receipt = copy.deepcopy(fixture["receipt"])
            typed_plan = typed_receipt["plan"]
            for named in typed_plan["invocation"]["effective_run_stamp"]:
                if named["name"] == name:
                    named["value_json"] = canonical_json_bytes(value).decode()
                    break
            else:
                raise AssertionError(f"missing fixture stamp {name}")
            typed_plan["invocation_digest"] = domain_digest(
                RUN_INVOCATION_SCHEMA, typed_plan["invocation"])
            typed_plan["digest"] = semantic_digest(typed_plan)
            typed_row = copy.deepcopy(fixture["result_row"])
            typed_row[name] = value
            typed_result_raw = (json.dumps(
                typed_row, sort_keys=True,
                separators=(",", ":")) + "\n").encode()
            rewrite(fixture["result_path"], typed_result_raw)
            typed_receipt["result"].update({
                "byte_length": len(typed_result_raw),
                "file_sha256": raw_sha256(typed_result_raw),
            })
            typed_receipt["digest"] = semantic_digest(typed_receipt)
            _selftest_write(fixture["receipt_path"], typed_receipt)
            outcome = refused(lambda: verify_receipt(fixture["receipt_path"]))
            rewrite(fixture["result_path"], fixture["result_raw"])
            rewrite(fixture["receipt_path"], fixture["receipt_raw"])
            return outcome

        typed_stamp_refused = (
            signed_stamp_refusal("shard", False)
            and signed_stamp_refusal("agent_timeout_seconds", 1)
            and signed_stamp_refusal("dataset_version", 1)
            and signed_stamp_refusal("subset_digest", "0" * 16))

        seed_document = loads_exact_json(
            fixture["seed_raw"], label="seed type fixture")
        seed_document["format"] = True
        typed_seed_raw = _selftest_write(fixture["seed_path"], seed_document)
        typed_runtime = copy.deepcopy(fixture["runtime"])
        typed_runtime["seed_manifest_sha256"] = raw_sha256(typed_seed_raw)
        typed_runtime_raw = _selftest_write(
            fixture["runtime_path"], typed_runtime)
        typed_receipt = copy.deepcopy(fixture["receipt"])
        typed_receipt["execution"]["runtime"]["file_sha256"] = raw_sha256(
            typed_runtime_raw)
        typed_identity = typed_receipt["execution"]["runtime"]["identity"]
        typed_identity["seed_manifest"]["file_sha256"] = raw_sha256(
            typed_seed_raw)
        typed_identity["digest"] = semantic_digest(typed_identity)
        typed_receipt["digest"] = semantic_digest(typed_receipt)
        _selftest_write(fixture["receipt_path"], typed_receipt)
        typed_seed_refused = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["seed_path"], fixture["seed_raw"])
        rewrite(fixture["runtime_path"], fixture["runtime_raw"])
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])

        worker_manifest_document = loads_exact_json(
            fixture["worker_manifest_raw"], label="WorkerManifest type fixture")
        worker_manifest_document["campaign"]["k_workers"] = True
        typed_worker_raw = _selftest_write(
            fixture["worker_manifest_path"], worker_manifest_document)
        typed_receipt = copy.deepcopy(fixture["receipt"])
        typed_receipt["worker_manifest"]["file_sha256"] = raw_sha256(
            typed_worker_raw)
        typed_receipt["digest"] = semantic_digest(typed_receipt)
        _selftest_write(fixture["receipt_path"], typed_receipt)
        typed_worker_refused = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["worker_manifest_path"],
                fixture["worker_manifest_raw"])
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])

        from . import campaign as campaign_type_module
        float_campaign = loads_exact_json(
            fixture["campaign_raw"], label="float campaign fixture")
        float_campaign["harness_version"] = 7.0
        float_campaign_raw = _selftest_write(
            fixture["campaign_path"], float_campaign)
        float_campaign_digest = campaign_type_module.campaign_digest(
            float_campaign)
        float_receipt = copy.deepcopy(fixture["receipt"])
        float_plan = float_receipt["plan"]
        float_plan["campaign"].update({
            "file_sha256": raw_sha256(float_campaign_raw),
            "campaign_digest": float_campaign_digest,
            "semantic_digest": semantic_digest(float_campaign),
        })
        for named in float_plan["invocation"]["effective_run_stamp"]:
            if named["name"] == "campaign_digest":
                named["value_json"] = canonical_json_bytes(
                    float_campaign_digest).decode()
                break
        float_plan["invocation_digest"] = domain_digest(
            RUN_INVOCATION_SCHEMA, float_plan["invocation"])
        float_plan["digest"] = semantic_digest(float_plan)
        float_row = copy.deepcopy(fixture["result_row"])
        float_row["campaign_digest"] = float_campaign_digest
        float_result_raw = (json.dumps(
            float_row, sort_keys=True, separators=(",", ":")) + "\n").encode()
        rewrite(fixture["result_path"], float_result_raw)
        float_receipt["result"].update({
            "byte_length": len(float_result_raw),
            "file_sha256": raw_sha256(float_result_raw),
        })
        float_worker = loads_exact_json(
            fixture["worker_manifest_raw"], label="float campaign fixture")
        float_worker["campaign"] = float_campaign
        float_worker["campaign_digest"] = float_campaign_digest
        float_worker["worker"]["campaign_digest"] = float_campaign_digest
        float_worker_raw = _selftest_write(
            fixture["worker_manifest_path"], float_worker)
        float_receipt["worker_manifest"]["file_sha256"] = raw_sha256(
            float_worker_raw)
        float_receipt["digest"] = semantic_digest(float_receipt)
        _selftest_write(fixture["receipt_path"], float_receipt)
        float_campaign_refused = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        rewrite(fixture["campaign_path"], fixture["campaign_raw"])
        rewrite(fixture["result_path"], fixture["result_raw"])
        rewrite(fixture["worker_manifest_path"],
                fixture["worker_manifest_raw"])
        rewrite(fixture["receipt_path"], fixture["receipt_raw"])
        check("signed Boolean/integer chimeras refuse in stamps, seed, and "
              "WorkerManifest/campaign joins",
              typed_stamp_refused and typed_seed_refused
              and typed_worker_refused and float_campaign_refused)

        symlink_path = fixture["root"] + "/receipt-symlink.json"
        os.symlink(fixture["receipt_path"], symlink_path)
        symlink_refused = refused(lambda: read_trusted_bytes(
            symlink_path, label="symlink fixture"))
        os.unlink(symlink_path)
        hardlink_path = fixture["root"] + "/receipt-hardlink.json"
        os.link(fixture["receipt_path"], hardlink_path)
        hardlink_refused = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        os.unlink(hardlink_path)
        unsafe_dir = fixture["root"] + "/unsafe"
        os.mkdir(unsafe_dir, 0o777)
        os.chmod(unsafe_dir, 0o777)
        unsafe_file = unsafe_dir + "/evidence.json"
        _selftest_write(unsafe_file, b"{}", raw=True)
        unsafe_refused = refused(
            lambda: read_trusted_bytes(unsafe_file, label="unsafe fixture"))
        os.chmod(unsafe_dir, 0o700)
        from .. import docker_authority as authority_module
        acl_path = fixture["root"] + "/acl-evidence.json"
        _selftest_write(acl_path, b"{}\n", raw=True)
        original_acl = authority_module._acl_absent

        def synthetic_acl(path, *, directory=False):
            if path == acl_path and not directory:
                return False
            return original_acl(path, directory=directory)

        authority_module._acl_absent = synthetic_acl
        try:
            acl_refused = refused(
                lambda: read_trusted_bytes(acl_path, label="ACL fixture"))
        finally:
            authority_module._acl_absent = original_acl
        check("symlink, hardlink, ACL, and unsafe-directory evidence refuses",
              symlink_refused and hardlink_refused and acl_refused
              and unsafe_refused)

        # Directory ACLs, faked at the xattr calls so no setfacl or
        # ACL-enabled filesystem is needed.  A default ACL grants nothing on
        # the directory carrying it; only the directory a file sits in passes
        # one on to that file.
        acl_root = fixture["root"] + "/acl-chain"
        nested_acl_path = acl_root + "/inner/evidence.json"
        direct_acl_path = acl_root + "/evidence.json"
        created_acl_path = acl_root + "/created.json"
        _selftest_write(nested_acl_path, b"{}\n", raw=True)
        _selftest_write(direct_acl_path, b"{}\n", raw=True)

        def acl_xattr(*tags):
            return (2).to_bytes(4, "little") + b"".join(
                tag.to_bytes(2, "little") + (5).to_bytes(2, "little")
                + (4242).to_bytes(4, "little") for tag in tags)

        named_default = {"system.posix_acl_default": acl_xattr(
            0x01, 0x04, 0x08, 0x10, 0x20)}
        mode_bit_default = {"system.posix_acl_default": acl_xattr(
            0x01, 0x04, 0x20)}

        def under_acl(xattrs, action):
            real_list, real_get = os.listxattr, os.getxattr

            def listxattr(path, *args, **kwargs):
                if path == acl_root:
                    return list(xattrs)
                return real_list(path, *args, **kwargs)

            def getxattr(path, attribute, *args, **kwargs):
                if path != acl_root:
                    return real_get(path, attribute, *args, **kwargs)
                if attribute in xattrs:
                    return xattrs[attribute]
                raise OSError(errno.ENODATA, os.strerror(errno.ENODATA), path)

            os.listxattr, os.getxattr = listxattr, getxattr
            try:
                action()
            except ResultLedgerRefused as exc:
                return str(exc)
            finally:
                os.listxattr, os.getxattr = real_list, real_get
            return ""

        check("a default ACL above the file's own directory does not refuse",
              under_acl(named_default, lambda: read_trusted_bytes(
                  nested_acl_path, label="ACL fixture")) == "")
        default_read = under_acl(named_default, lambda: read_trusted_bytes(
            direct_acl_path, label="ACL fixture"))
        default_create = under_acl(
            named_default, lambda: durable_create_bytes_no_clobber(
                created_acl_path, b"{}\n", label="ACL fixture"))
        check("a default ACL that gives new files an access ACL refuses on "
              "the file's own directory, before anything is written",
              all("default ACL gives files created in it an access ACL"
                  in text for text in (default_read, default_create))
              and not os.path.lexists(created_acl_path))
        check("a default ACL that only restates the mode bits does not "
              "refuse reads or writes in its directory",
              under_acl(mode_bit_default, lambda: read_trusted_bytes(
                  direct_acl_path, label="ACL fixture")) == ""
              and under_acl(
                  mode_bit_default, lambda: durable_create_bytes_no_clobber(
                      created_acl_path, b"{}\n", label="ACL fixture")) == ""
              and read_trusted_bytes(
                  created_acl_path, label="ACL fixture") == b"{}\n")
        check("an access ACL on any directory component refuses",
              "carries an access ACL" in under_acl(
                  {"system.posix_acl_access": b""},
                  lambda: read_trusted_bytes(
                      nested_acl_path, label="ACL fixture")))

        toctou_path = fixture["root"] + "/toctou.bin"
        _selftest_write(toctou_path, b"before", raw=True)
        # The trusted reader lives in `core.ledger_primitives`; its leaf
        # check is patched there, where `read_trusted_bytes` resolves it.
        from ..core import ledger_primitives as primitives
        original_leaf = primitives._trusted_leaf
        calls = []

        def changing_leaf(path, label):
            info = original_leaf(path, label)
            calls.append(path)
            if len(calls) == 1:
                _selftest_write(path, b"after-change", raw=True)
            return info

        primitives._trusted_leaf = changing_leaf
        try:
            toctou_refused = refused(
                lambda: read_trusted_bytes(toctou_path, label="TOCTOU fixture"))
        finally:
            primitives._trusted_leaf = original_leaf
        confirm_path = fixture["root"] + "/confirm-race.bin"
        _selftest_write(confirm_path, b"before", raw=True)
        confirm_reader = _LiveReader()
        confirm_reader.read(confirm_path, "confirm-race fixture")
        rewrite(confirm_path, b"after-")
        confirm_refused = refused(confirm_reader.confirm)
        timestamp_path = fixture["root"] + "/timestamp-only.bin"
        _selftest_write(timestamp_path, b"unchanged", raw=True)
        timestamp_reader = _LiveReader()
        timestamp_reader.read(timestamp_path, "timestamp-only fixture")
        timestamp_before = os.stat(timestamp_path)
        os.utime(timestamp_path, ns=(timestamp_before.st_atime_ns,
                                    timestamp_before.st_mtime_ns + 1_000_000))
        timestamp_only_accepted = not refused(timestamp_reader.confirm)
        check("stable reads reject in-read and final-confirm TOCTOU changes",
              toctou_refused and confirm_refused and timestamp_only_accepted)

        from . import worker as worker_module
        old_adapter = authority_module._current_adapter
        old_live = worker_module.validate_live_worker_runtime
        docker_calls = []

        def docker_bomb(*_args, **_kwargs):
            docker_calls.append(True)
            raise AssertionError("offline verifier contacted Docker")

        authority_module._current_adapter = docker_bomb
        worker_module.validate_live_worker_runtime = docker_bomb
        try:
            offline_ok = verify_receipt(fixture["receipt_path"])["verified"]
        finally:
            authority_module._current_adapter = old_adapter
            worker_module.validate_live_worker_runtime = old_live
        check("receipt remains verifiable after mocked daemon/pool disappearance",
              offline_ok and docker_calls == [])

        from .. import cli as cli_module
        from . import cli as bench_cli
        legacy_result = fixture["root"] + "/legacy.jsonl"
        _selftest_write(legacy_result, fixture["result_raw"], raw=True)
        check("receipt-less evidence stays readable but is never auto-upgraded",
              bench_cli._jsonl_rows(legacy_result)
              and not os.path.exists(legacy_result + RECEIPT_SUFFIX)
              and refused(lambda: verify_receipt(
                  legacy_result + RECEIPT_SUFFIX)))

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli_rc = cli_module.main(
                ["verify-receipt", "--receipt", fixture["receipt_path"]])
        machine = loads_exact_json(output.getvalue(), label="CLI output")
        bad_output = io.StringIO()
        try:
            with contextlib.redirect_stdout(bad_output):
                cli_module.main([
                    "verify-receipt", "--receipt",
                    fixture["root"] + "/missing.result-ledger.json"])
        except SystemExit as exc:
            bad_status = bool(str(exc).startswith("REFUSED:"))
        else:
            bad_status = False
        check("CLI emits one machine result only after complete verification",
              cli_rc == 0 and machine["verified"] is True
              and machine["complete"] is True
              and bad_status and bad_output.getvalue() == "")

        # Integration kill for the end-of-verification gate: mutate a file
        # already consumed by the plan only after the last run-specific join.
        # The real CLI must stay silent; disabling the final reread must make
        # exactly this adversarial vector reach its positive output.
        original_manifest_verifier = globals()["_verify_worker_manifest"]
        original_confirm = _LiveReader.confirm

        def mutate_after_manifest(*args, **kwargs):
            value = original_manifest_verifier(*args, **kwargs)
            rewrite(fixture["campaign_path"], fixture["campaign_raw"] + b" ")
            return value

        globals()["_verify_worker_manifest"] = mutate_after_manifest
        race_output = io.StringIO()
        try:
            with contextlib.redirect_stdout(race_output):
                cli_module.main(
                    ["verify-receipt", "--receipt", fixture["receipt_path"]])
        except SystemExit as exc:
            integrated_race_refused = str(exc).startswith("REFUSED:")
        else:
            integrated_race_refused = False
        finally:
            globals()["_verify_worker_manifest"] = original_manifest_verifier
            rewrite(fixture["campaign_path"], fixture["campaign_raw"])

        globals()["_verify_worker_manifest"] = mutate_after_manifest
        _LiveReader.confirm = lambda self: None
        mutant_output = io.StringIO()
        try:
            with contextlib.redirect_stdout(mutant_output):
                mutant_rc = cli_module.main(
                    ["verify-receipt", "--receipt", fixture["receipt_path"]])
            mutant_machine = loads_exact_json(
                mutant_output.getvalue(), label="final-confirm mutant output")
            integrated_mutant_accepts = (
                mutant_rc == 0 and mutant_machine["complete"] is True)
        finally:
            _LiveReader.confirm = original_confirm
            globals()["_verify_worker_manifest"] = original_manifest_verifier
            rewrite(fixture["campaign_path"], fixture["campaign_raw"])
        check("CLI final-confirm gate refuses a late companion race before "
              "positive output",
              integrated_race_refused and race_output.getvalue() == ""
              and integrated_mutant_accepts)

        # Mutation probes: each negative vector must become accepted if the
        # corresponding mandatory check is deliberately bypassed. This proves
        # that the vector kills, rather than merely traverses, that mutant.
        incomplete_receipt = copy.deepcopy(fixture["receipt"])
        incomplete_receipt["result"].update({
            "byte_length": 0, "row_count": 0,
            "file_sha256": raw_sha256(b""),
        })
        incomplete_receipt["digest"] = semantic_digest(incomplete_receipt)
        rewrite(fixture["result_path"], b"")
        _selftest_write(fixture["receipt_path"], incomplete_receipt)
        incomplete_refused = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        original_sequence = globals()["_verify_row_sequence"]
        globals()["_verify_row_sequence"] = lambda *_args, **_kwargs: None
        try:
            skipped_coverage_accepts = verify_receipt(
                fixture["receipt_path"])["complete"]
        finally:
            globals()["_verify_row_sequence"] = original_sequence
            rewrite(fixture["result_path"], fixture["result_raw"])
            rewrite(fixture["receipt_path"], fixture["receipt_raw"])
        check("mutation probe kills skipped complete-workset coverage",
              incomplete_refused and skipped_coverage_accepts)

        sha_only_row = dict(row)
        sha_only_row["outcome"] = "failed"
        sha_only_result = (json.dumps(
            sha_only_row, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(sha_only_result) != len(fixture["result_raw"]):
            raise AssertionError("SHA mutation vector must preserve byte length")
        rewrite(fixture["result_path"], sha_only_result)
        baseline_sha_refused = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        original_result_verifier = globals()["_verify_result_bytes"]

        def skipped_result_sha(reader, binding, label, *, prefix,
                               allow_absent_empty=False):
            changed = dict(binding)
            changed["file_sha256"] = raw_sha256(
                reader.read(changed["path"], label))
            return original_result_verifier(
                reader, changed, label, prefix=prefix,
                allow_absent_empty=allow_absent_empty)

        globals()["_verify_result_bytes"] = skipped_result_sha
        try:
            skipped_sha_accepts = verify_receipt(
                fixture["receipt_path"])["complete"]
        finally:
            globals()["_verify_result_bytes"] = original_result_verifier
            rewrite(fixture["result_path"], fixture["result_raw"])

        mutated_binding = copy.deepcopy(fixture["binding"])
        mutated_binding["authority"]["file_sha256"] = "f" * 64
        mutated_binding["digest"] = semantic_digest(mutated_binding)
        mutated_binding_raw = _selftest_write(
            fixture["binding_path"], mutated_binding)
        mutated_binding_ref = {
            "path": fixture["binding_path"],
            "file_sha256": raw_sha256(mutated_binding_raw),
            "digest": mutated_binding["digest"],
        }
        mutated_runtime = copy.deepcopy(fixture["runtime"])
        mutated_runtime["docker_execution_binding"] = mutated_binding_ref
        mutated_runtime_raw = _selftest_write(
            fixture["runtime_path"], mutated_runtime)
        mutated_receipt = copy.deepcopy(fixture["receipt"])
        mutated_receipt["execution"]["runtime"]["file_sha256"] = raw_sha256(
            mutated_runtime_raw)
        mutated_identity = mutated_receipt["execution"]["runtime"]["identity"]
        mutated_identity["docker_execution_binding"] = mutated_binding_ref
        mutated_identity["digest"] = semantic_digest(mutated_identity)
        mutated_receipt["digest"] = semantic_digest(mutated_receipt)
        _selftest_write(fixture["receipt_path"], mutated_receipt)
        baseline_join_refused = refused(
            lambda: verify_receipt(fixture["receipt_path"]))
        original_join = globals()["_require_same_json"]

        def skipped_binding_authority_join(left, right, message):
            if message == "binding authority differs from runtime authority":
                return None
            return original_join(left, right, message)

        globals()["_require_same_json"] = skipped_binding_authority_join
        try:
            skipped_join_accepts = verify_receipt(
                fixture["receipt_path"])["complete"]
        finally:
            globals()["_require_same_json"] = original_join
            rewrite(fixture["binding_path"], fixture["binding_raw"])
            rewrite(fixture["runtime_path"], fixture["runtime_raw"])
            rewrite(fixture["receipt_path"], fixture["receipt_raw"])
        check("mutation probes kill skipped result SHA and one runtime-chain join",
              baseline_sha_refused and skipped_sha_accepts
              and baseline_join_refused and skipped_join_accepts)

    # ------------------------------------------------ the RELOCATED seed
    # `bundle.build_bundle` relocates a seed with a plain `shutil.copytree`
    # and `seed.build_seed` recorded the ABSOLUTE path of the tree it was
    # frozen from, so a bundle-installed seed's `workspace.path` names a
    # directory it no longer lives in.  Held to that literal string, no
    # relocated seed could satisfy publication-v3 — which is what the shipped
    # CoreShop and python-docx seeds do.  The remap is safe because the
    # recorded string is inert: everything below reads the DERIVED path and
    # the bytes are pinned by digest three ways over.
    with tempfile.TemporaryDirectory(prefix="r2t-ledger-seedpath-") as temporary:
        os.chmod(temporary, 0o700)
        from . import seed as seed_module

        def seed_fixture(directory: str, *, workspace_path, database_path,
                         needs_database: bool, archive: bytes = b"tar-bytes",
                         dump: bytes = b"-- dump\n",
                         workspace_digest=None):
            """Write one real seed tree and the runtime/identity that join it."""
            archive_path = directory + "/" + seed_module.WORKSPACE_TAR
            _selftest_write(archive_path, archive, raw=True)
            digest = raw_sha256(archive)
            recorded_digest = digest if workspace_digest is None \
                else workspace_digest
            if needs_database:
                sql_path = directory + "/" + seed_module.DATABASE_SQL
                _selftest_write(sql_path, dump, raw=True)
                database = {"path": database_path, "digest": raw_sha256(dump),
                            "bytes": len(dump)}
                dump_digest = raw_sha256(dump)
            else:
                database = {"path": database_path, "digest": "no_database",
                            "declared": "no_database", "bytes": 0}
                dump_digest = "no_database"
            document = {
                "format": seed_module.SEED_FORMAT,
                "seed_key": "seedkey0123456789",
                "needs_database": needs_database,
                "built_from": "/build/tree/app",
                "workspace": {"path": workspace_path,
                              "digest": recorded_digest,
                              "bytes": len(archive)},
                "database": database,
                "workspace_seed_digest": recorded_digest,
                "database_dump_digest": dump_digest,
            }
            manifest_path = directory + "/" + seed_module.SEED_MANIFEST
            raw = _selftest_write(manifest_path, document)
            runtime = {
                "seed_dir": directory,
                "seed_manifest_sha256": raw_sha256(raw),
                "seed_key": document["seed_key"],
                "workspace_seed_digest": digest,
                "database_dump_digest": dump_digest,
                "needs_database": needs_database,
            }
            identity = {
                "seed_dir": directory,
                "seed_manifest": _selftest_raw_ref(manifest_path, raw),
                "seed_key": document["seed_key"],
                "workspace_seed_digest": digest,
            }
            return runtime, identity

        def verify(directory: str, **kwargs) -> bool:
            runtime, identity = seed_fixture(directory, **kwargs)
            reader = _LiveReader()
            document = _verify_seed(reader, runtime, identity)
            reader.confirm()
            return document["seed_key"] == runtime["seed_key"]

        def verifies(directory: str, **kwargs) -> bool:
            """A refusal is a FAILED check here, not a crashed selftest."""
            try:
                return verify(directory, **kwargs)
            except ResultLedgerRefused:
                return False

        in_place = temporary + "/in-place"
        check("a seed verified where it was built is unchanged",
              verifies(in_place,
                       workspace_path=in_place + "/"
                       + seed_module.WORKSPACE_TAR,
                       database_path=None, needs_database=False))

        portable = temporary + "/portable"
        check("the algorand portable projection still verifies",
              verifies(portable, workspace_path=seed_module.WORKSPACE_TAR,
                       database_path=None, needs_database=False))

        moved = temporary + "/moved"
        check("a RELOCATED seed whose workspace path still names the build "
              "tree verifies where it now lives",
              verifies(moved,
                       workspace_path="/build/tree/seed/v1/"
                       + seed_module.WORKSPACE_TAR,
                       database_path=None, needs_database=False))

        wrong_digest = temporary + "/wrong-digest"
        check("the same relocated seed with a MISMATCHED workspace digest is "
              "still refused — the digests decide, not the string",
              refused(lambda: verify(
                  wrong_digest,
                  workspace_path="/build/tree/seed/v1/"
                  + seed_module.WORKSPACE_TAR,
                  database_path=None, needs_database=False,
                  workspace_digest="f" * 64)))

        wrong_name = temporary + "/wrong-name"
        check("a workspace record naming something that is not a "
              "workspace.tar is still refused",
              refused(lambda: verify(
                  wrong_name,
                  workspace_path="/build/tree/seed/v1/"
                  + seed_module.DATABASE_SQL,
                  database_path=None, needs_database=False)))

        db_in_place = temporary + "/db-in-place"
        check("the CoreShop database half is unchanged when the seed is "
              "verified where it was built",
              verifies(db_in_place,
                       workspace_path=db_in_place + "/"
                       + seed_module.WORKSPACE_TAR,
                       database_path=db_in_place + "/"
                       + seed_module.DATABASE_SQL,
                       needs_database=True))

        db_moved = temporary + "/db-moved"
        check("a RELOCATED CoreShop seed's database.sql path is remapped the "
              "same way as its workspace",
              verifies(db_moved,
                       workspace_path="/build/tree/seed/v1/"
                       + seed_module.WORKSPACE_TAR,
                       database_path="/build/tree/seed/v1/"
                       + seed_module.DATABASE_SQL,
                       needs_database=True))

        db_wrong_name = temporary + "/db-wrong-name"
        check("a database record naming something that is not a database.sql "
              "is still refused",
              refused(lambda: verify(
                  db_wrong_name,
                  workspace_path="/build/tree/seed/v1/"
                  + seed_module.WORKSPACE_TAR,
                  database_path="/build/tree/seed/v1/elsewhere.sql",
                  needs_database=True)))

    return 1 if failures else 0
