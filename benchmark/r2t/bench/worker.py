"""The unit of parallelism: `(workspace_k, schema_k, container_k)`.

SPEC_C3_PARALLEL §3.1, §3.2 and H3/H8.  Execution was serial *by
construction*, not by policy — the workspace, `_bench/run_record.jsonl`,
`_bench/item.feature`, `_bench/services_item.yml`,
`_bench/solution_index.json`, `var/cache/test`, `var/classes` and the schema
`coreshop_bench` are all fixed shared paths.  Two executors that accidentally
started 76 seconds apart produced, over 89 doubly-executed items with
byte-identical input, **26 different outcomes (29%)**.  The outcome label
itself stopped being reproducible, and nothing noticed.

So the three are provisioned and torn down **together**.  A workspace can
never be re-pointed at another schema: `var/classes` holds Pimcore DataObject
definitions materialised as PHP files, created and purged per scenario, and it
is database-coupled state rather than a cache.  Container-per-worker is
mandatory because the timeout kill was container-wide (defect 3) and cheap
because the 1.92 GB image is shared and the writable layer is 9.54 MB.

**Isolation is enforced here, not asserted.**  Each worker gets its own
MySQL principal granted on its own schema only; the wildcard admin is removed
so a worker cannot simply connect as it; the credential reaches the container
in a mode-0600 env file at `docker run`, never in an exec's argv; and the
acceptance is an adversarial probe executed *from inside* the worker
container, because a grant table read by the coordinator says nothing about
what the container can reach.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import time
from dataclasses import dataclass, asdict
from typing import Callable, Iterable, Mapping, Optional

from .campaign import NO_DATABASE
from .repo import CORESHOP_BEHAT, BehatProject
from .dbadmin import (REQUIRED_DENIED, MySQL, DatabaseRefused, db_probe_php,
                      new_password, probe_report, _DSN_ENV_SLOT, _ident)
from .harness import DockerRunner
from ..core.paths import data_path
from ..java.direct_calls import AGENT_JAR_RUNTIME
from .seed import unpack_workspace
from ..core.paths import CONFIG_DIR

#: Where a worker's secret lives: readable by the coordinator, by nothing
#: else, and never inside a workspace.  A `.env` file under the workspace
#: would be visible to the submitted code the credential exists to contain.
SECRETS_DIRNAME = ".secrets"

COMPOSER_CACHE_ENV = "R2T_COMPOSER_CACHE"

#: The portable default cache below the operator-owned data root.  Composer
#: never runs during a sweep, but the image's entrypoint expects the
#: directory.  `composer_mounts` still prefers an explicit --composer-cache
#: or the environment variable, and still validates whichever source won.
COMPOSER_CACHE = data_path("cache", "composer")


def composer_mounts(*, required: bool,
                    explicit: Optional[str] = None,
                    environ=None) -> tuple[tuple[str, str], ...]:
    """Resolve CoreShop's content-bearing cache before Docker is contacted.

    A cache is not a portable default and must never be guessed from Kilo's
    layout.  Non-PHP/no-database stacks declare it unnecessary and receive no
    mount.  The read-only destination prevents submitted code from poisoning
    a cache shared by later workers.
    """
    if not required:
        return ()
    env = os.environ if environ is None else environ
    path = explicit if explicit is not None else env.get(COMPOSER_CACHE_ENV)
    if not isinstance(path, str) or not path:
        raise WorkerRefused(
            "REFUSED: CoreShop provisioning requires an explicit Composer "
            f"cache via --composer-cache or {COMPOSER_CACHE_ENV}; no Docker "
            "command was run")
    if "\x00" in path or "\r" in path or "\n" in path \
            or not os.path.isabs(path) or os.path.normpath(path) != path:
        raise WorkerRefused(
            "REFUSED: Composer cache must be a normalized absolute path")
    if os.path.islink(path) or not os.path.isdir(path) \
            or os.path.realpath(path) != path:
        raise WorkerRefused(
            f"REFUSED: Composer cache is not a canonical non-symlink "
            f"directory: {path}")
    return ((path, "/composer-cache:ro"),)

# The committed, digest-pinned recipe's disclosed successor.  The historical
# `coreshop_bench_img:base` remains recorded in released v1 evidence; changing
# the default cannot retroactively make that unrecorded build reproducible.
DEFAULT_IMAGE = "coreshop_bench_img:repro-v1"
DEFAULT_DB_CONTAINER = "coreshop_db"
DEFAULT_NETWORK = "coreshop_net"

#: The identities that must be pairwise disjoint for K workers to be K
#: workers.  Named as a tuple so preflight cannot forget one when a field is
#: added: every attribute here is compared, and adding a shared resource
#: without adding it here is the mistake this list exists to make visible.
RESOURCE_FIELDS = ("workspace", "container", "schema", "credential",
                   "env_file")

#: The two of them that only exist when there is a database (D6).
_DATABASE_FIELDS = ("schema", "credential")

# Values in these variables include a live password.  Docker inspection may
# examine them in memory, but no report, exception or campaign sidecar may
# contain them.  `_safe_runtime_env` below emits only non-secret identities
# and boolean coherence facts.
#: Pimcore's installer reads these four beside the DSN; a project whose
#: row says `db_install_vars: false` reads the DSN alone.
_INSTALL_ENV_KEYS = (
    "PIMCORE_INSTALL_MYSQL_USERNAME",
    "PIMCORE_INSTALL_MYSQL_PASSWORD",
    "PIMCORE_INSTALL_MYSQL_DATABASE",
    "PIMCORE_INSTALL_MYSQL_HOST_SOCKET",
)


def db_env_keys(behat=None) -> tuple:
    """The secret-bearing database variables one project's worker carries.

    CoreShop names its DSN `PIMCORE_TEST_DB_DSN` and four install
    variables beside it; Sylius names `DATABASE_URL` and nothing else.
    `behat` is `repo.BehatProject`; None is CoreShop's, which is what
    every caller that does not name a project means.
    """
    bp = behat or CORESHOP_BEHAT
    return ((bp.db_dsn_env, *_INSTALL_ENV_KEYS) if bp.db_install_vars
            else (bp.db_dsn_env,))


_DB_ENV_KEYS = db_env_keys()
_RUNTIME_ENV_KEYS = ("R2T_WORKER_INDEX", *_DB_ENV_KEYS)


def resource_fields(needs_database: bool = True) -> tuple:
    """Which identities preflight requires to be pairwise disjoint.

    Dropping `schema` and `credential` for a stack that has no database is
    not a relaxation, it is a correction: there is no schema, so every
    worker's is the empty string, so a disjointness check over them would
    refuse K>1 for a configuration that is perfectly separated in every
    respect that exists.  Keeping them and filling them with plausible
    derived names would be worse -- a worker record naming a MySQL principal
    that was never created, which a reader would take for a live grant.

    The workspace, the container and the credential FILE are still compared,
    which is the whole of what separates two behave workers.
    """
    if needs_database:
        return RESOURCE_FIELDS
    return tuple(f for f in RESOURCE_FIELDS if f not in _DATABASE_FIELDS)


WORKER_RUNTIME_SCHEMA_V1 = "r2t.worker-runtime/v1"
WORKER_RUNTIME_SCHEMA_V2 = "r2t.worker-runtime/v2"
WORKER_RUNTIME_SCHEMA = "r2t.worker-runtime/v3"
WORKER_RUNTIME_SCHEMA_V4 = "r2t.worker-runtime/v4"
from .prestashop_memory import (PRESTASHOP_MEMORY_POLICY, _validate_worker_memory,
    capture_prestashop_memory, normalized_worker_memory_policy, require_prestashop_memory)
WORKER_RUNTIME_SUFFIX = ".runtime.json"
WORKER_BINDING_SUFFIX = ".binding.json"
WORKER_RUNTIME_FIELDS_V1 = {
    "schema", "worker", "worker_spec_sha256", "seed_dir",
    "seed_manifest_sha256", "seed_key", "workspace_seed_digest",
    "database_dump_digest", "container_image_digest", "harness_version",
    "needs_database",
}
WORKER_RUNTIME_FIELDS_V2 = WORKER_RUNTIME_FIELDS_V1 | {
    "docker_endpoint_selection",
}
WORKER_RUNTIME_FIELDS = WORKER_RUNTIME_FIELDS_V1 | {
    "docker_execution_authority", "docker_execution_binding",
}


WORKER_RUNTIME_FIELDS_V4 = WORKER_RUNTIME_FIELDS | {"memory"}


def worker_runtime_version(document: object) -> Optional[str]:
    """Recognise exact historical/current evidence without upgrading any bytes."""
    if not isinstance(document, dict):
        return None
    if document.get("schema") == WORKER_RUNTIME_SCHEMA_V4 \
            and set(document) == WORKER_RUNTIME_FIELDS_V4:
        return "v4"
    if document.get("schema") == WORKER_RUNTIME_SCHEMA \
            and set(document) == WORKER_RUNTIME_FIELDS:
        return "v3"
    if document.get("schema") == WORKER_RUNTIME_SCHEMA_V2 \
            and set(document) == WORKER_RUNTIME_FIELDS_V2:
        return "v2"
    if document.get("schema") == WORKER_RUNTIME_SCHEMA_V1 \
            and set(document) == WORKER_RUNTIME_FIELDS_V1:
        return "v1"
    return None


def _validate_worker_runtime_v3_shape(document: dict, authority_module) \
        -> "WorkerSpec":
    """Enforce the published v3 schema before any path is dereferenced.

    Historical worker specs intentionally keep their old permissive reader;
    these stricter path/type rules belong only to newly minted v3 evidence.
    """
    if worker_runtime_version(document) not in {"v3", "v4"}:
        raise WorkerRefused(
            f"REFUSED: worker runtime is not exact {WORKER_RUNTIME_SCHEMA}")
    if worker_runtime_version(document) == "v4":
        _validate_worker_memory(document["memory"])
    try:
        worker = WorkerSpec.from_json(document["worker"])
        authority_module.canonical_absolute_path(
            document["seed_dir"], "worker runtime seed_dir")
        for field in ("workspace", "env_file", "workdir", "out_path",
                      "artifacts_root"):
            authority_module.canonical_absolute_path(
                getattr(worker, field), f"worker runtime worker.{field}")
    except authority_module.DockerAuthorityRefused as exc:
        raise WorkerRefused(str(exc)) from exc
    for field in ("worker_spec_sha256", "seed_manifest_sha256",
                  "workspace_seed_digest"):
        value = document[field]
        if not isinstance(value, str) \
                or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise WorkerRefused(
                f"REFUSED: worker runtime {field} is not full SHA-256")
    seed_key = document["seed_key"]
    if not isinstance(seed_key, str) or not seed_key \
            or any(mark in seed_key for mark in ("\x00", "\r", "\n")):
        raise WorkerRefused(
            "REFUSED: worker runtime seed_key is not a nonempty string")
    image = document["container_image_digest"]
    if not isinstance(image, str) \
            or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None:
        raise WorkerRefused(
            "REFUSED: worker runtime container image is not immutable")
    harness = document["harness_version"]
    if not ((isinstance(harness, str) and bool(harness))
            or (isinstance(harness, int) and not isinstance(harness, bool)
                and harness >= 1)):
        raise WorkerRefused(
            "REFUSED: worker runtime harness_version is invalid")
    needs_database = document["needs_database"]
    if not isinstance(needs_database, bool):
        raise WorkerRefused(
            "REFUSED: worker runtime needs_database is not boolean")
    database = document["database_dump_digest"]
    if needs_database:
        if not isinstance(database, str) \
                or re.fullmatch(r"[0-9a-f]{64}", database) is None:
            raise WorkerRefused(
                "REFUSED: database runtime has no full dump digest")
    elif database != NO_DATABASE:
        raise WorkerRefused(
            "REFUSED: no-database runtime has a database digest")
    return worker


def _sha256_regular_file(path: str, label: str) -> str:
    if os.path.islink(path) or not os.path.isfile(path):
        raise WorkerRefused(
            f"REFUSED: {label} is not a non-symlink regular file: {path}")
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _content_digest(value) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def runtime_attestation_path(worker_spec_path: str) -> str:
    """The provision-time runtime evidence paired with one WorkerSpec."""
    base, ext = os.path.splitext(worker_spec_path)
    return (base if ext == ".json" else worker_spec_path) \
        + WORKER_RUNTIME_SUFFIX


def binding_attestation_path(worker_spec_path: str) -> str:
    """The live Docker binding paired with one WorkerSpec."""
    base, ext = os.path.splitext(worker_spec_path)
    return (base if ext == ".json" else worker_spec_path) \
        + WORKER_BINDING_SUFFIX


_seed_verifications = ContextVar("worker_seed_verifications", default=None)


@contextmanager
def _seed_verification_scope():
    """Reuse unchanged seed bytes only within one read-only validation."""
    if _seed_verifications.get() is not None:
        yield
        return
    token = _seed_verifications.set({})
    try:
        yield
    finally:
        _seed_verifications.reset(token)


def _seed_file_state(seed_dir: str) -> tuple:
    from . import seed as S
    state = []
    for name in (S.SEED_MANIFEST, S.WORKSPACE_TAR, S.DATABASE_SQL):
        try:
            info = os.lstat(os.path.join(seed_dir, name))
        except FileNotFoundError:
            state.append(None)
            continue
        except OSError as exc:
            raise WorkerRefused(f"REFUSED: cannot inspect seed artifact: {exc}") from exc
        state.append((info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                      info.st_size, info.st_mtime_ns, info.st_ctime_ns))
    return tuple(state)


def verified_seed_identity(seed_dir: str, needs_database: bool) -> dict:
    """Hash and return the exact seed semantics used to provision workers.

    EVERY seed failure leaves here as `WorkerRefused`, including the ones
    `seed` itself raises.  `SeedRefused` is a bare `RuntimeError`, so an
    absent or relocated `seed/` used to sail straight through the
    `except W.WorkerRefused` handlers at the publication boundary and crash
    `report`, `results` and `recall` with a raw traceback (review finding
    24).  This is the one place all three reach the seed, so it is the one
    place the conversion belongs -- widening the handlers instead would leave
    the next caller to remember.
    """
    from . import seed as S
    try:
        cached = _seed_verifications.get()
        if cached is None:
            return _verified_seed_identity(seed_dir, needs_database)
        root = os.path.realpath(seed_dir)
        key = (root, bool(needs_database))
        before = _seed_file_state(root)
        previous = cached.get(key)
        if previous is not None and previous[0] == before:
            return dict(previous[1])
        result = _verified_seed_identity(seed_dir, needs_database)
        if _seed_file_state(root) != before:
            raise WorkerRefused(
                "REFUSED: seed artifacts changed during verification")
        cached[key] = (before, dict(result))
        return result
    except S.SeedRefused as e:
        raise WorkerRefused(str(e)) from e


def _verified_seed_identity(seed_dir: str, needs_database: bool) -> dict:
    from . import seed as S
    report = S.verify_seed(seed_dir)
    if not report.get("artifacts_ok"):
        raise WorkerRefused(
            f"REFUSED: mutation seed at {seed_dir} does not match its "
            "recorded bytes: " + json.dumps(report, sort_keys=True)[:500])
    if report.get("needs_database") is not bool(needs_database):
        raise WorkerRefused(
            f"REFUSED: mutation seed database semantics disagree: seed says "
            f"needs_database={report.get('needs_database')!r}, runtime says "
            f"{bool(needs_database)!r}.")
    for filename in (S.SEED_MANIFEST, S.WORKSPACE_TAR, S.DATABASE_SQL):
        path = os.path.join(seed_dir, filename)
        if not os.path.lexists(path):
            continue
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise WorkerRefused(
                f"REFUSED: cannot inspect seed artifact {path}: {exc}") from exc
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) \
                or info.st_nlink != 1:
            raise WorkerRefused(
                f"REFUSED: seed artifact is not a single-link regular file: "
                f"{path}")
    doc = S.read_seed(seed_dir)
    workspace = (doc or {}).get("workspace") or {}
    database = (doc or {}).get("database") or {}
    workspace_digest = workspace.get("digest")
    database_digest = (NO_DATABASE if database.get("declared") == NO_DATABASE
                       else database.get("digest"))
    if not isinstance(workspace_digest, str) \
            or len(workspace_digest) != 64:
        raise WorkerRefused(
            "REFUSED: mutation seed has no full workspace artifact digest.")
    if database_digest != NO_DATABASE \
            and (not isinstance(database_digest, str)
                 or len(database_digest) != 64):
        raise WorkerRefused(
            "REFUSED: mutation seed has no full database artifact digest or "
            "explicit no_database declaration.")
    manifest_path = os.path.join(seed_dir, S.SEED_MANIFEST)
    return {
        "seed_dir": os.path.realpath(seed_dir),
        "seed_manifest_sha256": _sha256_regular_file(
            manifest_path, "seed manifest"),
        "seed_key": report["seed_key"],
        "workspace_seed_digest": workspace_digest,
        "database_dump_digest": database_digest,
        "needs_database": bool(needs_database),
    }


def live_container_image_digest(container: str,
                                docker_group: bool = True) -> str:
    """Resolve the image ID of the running container, never its mutable tag."""
    cp = _docker(["inspect", container, "--format", "{{.Image}}"],
                 docker_group=docker_group, timeout=120)
    value = (cp.stdout or "").strip() if cp.returncode == 0 else ""
    payload = value[len("sha256:"):] if value.startswith("sha256:") else ""
    if len(payload) != 64 \
            or any(c not in "0123456789abcdef" for c in payload):
        raise WorkerRefused(
            f"REFUSED: cannot resolve immutable image ID for {container}: "
            f"{value!r} {(cp.stderr or '')[-200:]}")
    return value


def build_worker_runtime_attestation(
        worker: "WorkerSpec", worker_spec_path: str, seed_identity: dict,
        harness_version: object, *, binding_path: str,
        memory_evidence: Optional[dict] = None) -> dict:
    """Build v3, or memory-bound v4, from the captured authority/binding snapshot.

    The saved worker manifest is the authority: the record is re-read from
    ``worker_spec_path`` and must equal the WorkerSpec the caller derived,
    so a regenerated default can never shape the attested identity.
    """
    if not ((isinstance(harness_version, str) and harness_version)
            or (isinstance(harness_version, int)
                and not isinstance(harness_version, bool)
                and harness_version >= 1)):
        raise WorkerRefused(
            "REFUSED: worker runtime attestation has no harness version.")
    saved_worker = load_worker_spec(worker_spec_path)
    if saved_worker != worker:
        raise WorkerRefused(
            "REFUSED: worker runtime attestation input differs from the "
            "saved worker manifest; the saved manifests are authoritative")
    from .. import docker_authority as A
    binding, binding_ref = A.evidence_reference(
        binding_path, expected_schema=A.BINDING_SCHEMA,
        validator=A.validate_binding_document, label="worker Docker binding")
    authority_ref = binding["authority"]
    index = binding.get("worker_index")
    entries = binding["pool"]["workers"]
    if not isinstance(index, int) or isinstance(index, bool) \
            or index != worker.index or not 0 <= index < len(entries):
        raise WorkerRefused(
            "REFUSED: worker binding index does not match the WorkerSpec")
    entry = entries[index]
    spec_path = os.path.abspath(worker_spec_path)
    if entry["worker_spec_path"] != spec_path \
            or entry["worker_spec_sha256"] != _sha256_regular_file(
                spec_path, "worker spec") \
            or entry["container_name"] != worker.container \
            or binding["worker_spec_sha256"] \
            != entry["worker_spec_sha256"] \
            or binding["container"]["name"] != entry["container_name"]:
        raise WorkerRefused(
            "REFUSED: worker binding does not match the exact WorkerSpec")
    document = {
        "schema": WORKER_RUNTIME_SCHEMA,
        "worker": worker.to_json(),
        "worker_spec_sha256": entry["worker_spec_sha256"],
        **seed_identity,
        "container_image_digest": binding["container"]["image_id"],
        "docker_execution_authority": authority_ref,
        "docker_execution_binding": binding_ref,
        "harness_version": harness_version,
    }
    if memory_evidence is not None:
        _validate_worker_memory(memory_evidence, container_id=binding["container"]["id"])
        document.update(schema=WORKER_RUNTIME_SCHEMA_V4, memory=memory_evidence)
    _validate_worker_runtime_v3_shape(document, A)
    return document


def build_execution_pool(workers: list["WorkerSpec"],
                         worker_spec_paths: list[str], *,
                         database_container: Optional[str],
                         internal_network: Optional[str]) -> dict:
    """Freeze the complete persistent pool before any container mutation."""
    from .. import docker_authority as A
    if len(workers) != len(worker_spec_paths) or not workers \
            or [worker.index for worker in workers] != list(range(len(workers))):
        raise WorkerRefused(
            "REFUSED: execution pool must be the complete zero-based worker set")
    if (database_container is None) != (internal_network is None):
        raise WorkerRefused(
            "REFUSED: persistent workers support only database+internal or "
            "no-database+network-none")
    entries = []
    for worker, path in zip(workers, worker_spec_paths):
        path = os.path.abspath(path)
        try:
            A.assert_trusted_file(path, label="worker spec")
            with open(path, "rb") as spec_fh:
                spec_doc = A.loads_exact_json(
                    spec_fh.read(), label="worker spec")
        except A.DockerAuthorityRefused as exc:
            raise WorkerRefused(str(exc)) from exc
        if WorkerSpec.from_json(spec_doc) != worker:
            raise WorkerRefused(
                f"REFUSED: saved WorkerSpec differs from planned worker {worker.index}")
        entries.append({
            "index": worker.index,
            "worker_spec_path": path,
            "worker_spec_sha256": _sha256_regular_file(path, "worker spec"),
            "container_name": worker.container,
        })
    pool = {
        "schema": A.POOL_SCHEMA,
        "workers": entries,
        "database": ({"role": "database",
                      "container_name": database_container}
                     if database_container is not None else None),
        "network": ({"mode": "dedicated_internal", "name": internal_network}
                    if internal_network is not None
                    else {"mode": "none", "name": "none"}),
        "digest": "0" * 64,
    }
    pool["digest"] = A.semantic_digest(pool)
    try:
        A.validate_pool_document(pool, verify_files=True)
    except A.DockerAuthorityRefused as exc:
        raise WorkerRefused(str(exc)) from exc
    return pool


def _docker_json(argv: list[str], label: str, *,
                 docker_group: bool = True) -> dict:
    from .. import docker_authority as A
    cp = _docker(argv, docker_group=docker_group, timeout=120)
    if cp.returncode != 0:
        raise WorkerRefused(
            f"REFUSED: cannot inspect {label}; Docker returned "
            f"{cp.returncode}")
    try:
        value = A.loads_exact_json(cp.stdout or "", label=label)
    except A.DockerAuthorityRefused as exc:
        raise WorkerRefused(str(exc)) from exc
    if not isinstance(value, dict):
        raise WorkerRefused(f"REFUSED: {label} inspection is not an object")
    return value


def _container_snapshot(name: str, *, role: str,
                        worker_index: Optional[int],
                        docker_group: bool = True) -> tuple[dict, dict]:
    value = _docker_json(
        ["inspect", name, "--format", "{{json .}}"],
        f"container {name}", docker_group=docker_group)
    actual_name = value.get("Name")
    if isinstance(actual_name, str) and actual_name.startswith("/"):
        actual_name = actual_name[1:]
    networks = (value.get("NetworkSettings") or {}).get("Networks")
    if not isinstance(networks, dict):
        raise WorkerRefused(
            f"REFUSED: container {name} has no complete network map")
    attachments = []
    for network_name in sorted(networks):
        settings = networks[network_name]
        if not isinstance(settings, dict):
            raise WorkerRefused(
                f"REFUSED: container {name} network {network_name} is malformed")
        attachments.append({"name": network_name, "id": settings.get("NetworkID")})
    state = value.get("State") or {}
    host = value.get("HostConfig") or {}
    container = {
        "name": actual_name,
        "id": value.get("Id"),
        "image_id": value.get("Image"),
        "running": state.get("Running"),
        "host_network_mode": host.get("NetworkMode"),
        "network_attachments": attachments,
    }
    member = {"role": role, "worker_index": worker_index, **container}
    return container, member


def capture_execution_bindings(pool: dict, authority_ref: dict, *,
                               docker_group: bool = True) -> list[dict]:
    """Snapshot the complete live pool after every planned member exists."""
    from .. import docker_authority as A
    try:
        A.validate_pool_document(pool, verify_files=True)
        from ..core import docker_cli as D
        D.require_authority_reference(authority_ref, live=True)
    except A.DockerAuthorityRefused as exc:
        raise WorkerRefused(str(exc)) from exc
    members = []
    worker_containers = []
    for entry in pool["workers"]:
        container, member = _container_snapshot(
            entry["container_name"], role="worker",
            worker_index=entry["index"], docker_group=docker_group)
        worker_containers.append(container)
        members.append(member)
    if pool["database"] is not None:
        _container, member = _container_snapshot(
            pool["database"]["container_name"], role="database",
            worker_index=None, docker_group=docker_group)
        members.append(member)

    mode = pool["network"]["mode"]
    network_name = pool["network"]["name"]
    network = _docker_json(
        ["network", "inspect", network_name, "--format", "{{json .}}"],
        f"network {network_name}", docker_group=docker_group)
    network_id = network.get("Id")
    if mode == "none":
        policy = {
            "mode": "none", "name": "none", "id": network_id,
            "driver": network.get("Driver"), "scope": network.get("Scope"),
            "internal": network.get("Internal"),
            "ingress": network.get("Ingress"),
            "attachable": network.get("Attachable"),
            "expected_members": [], "observed_members": [],
        }
    else:
        members.sort(key=lambda row: (
            row["role"], -1 if row["worker_index"] is None
            else row["worker_index"], row["name"], row["id"]))
        live_members = network.get("Containers")
        if not isinstance(live_members, dict):
            raise WorkerRefused(
                "REFUSED: dedicated internal network has no membership map")
        observed = sorted(
            (container_id, item.get("Name") if isinstance(item, dict) else None)
            for container_id, item in live_members.items())
        planned = sorted((member["id"], member["name"]) for member in members)
        if observed != planned:
            raise WorkerRefused(
                "REFUSED: dedicated internal network membership differs from "
                "the complete pool")
        policy = {
            "mode": "dedicated_internal", "name": network_name,
            "id": network_id, "driver": network.get("Driver"),
            "scope": network.get("Scope"),
            "internal": network.get("Internal"),
            "ingress": network.get("Ingress"),
            "attachable": network.get("Attachable"),
            "expected_members": members,
            "observed_members": json.loads(json.dumps(members)),
        }
    captured_at = A.utc_now()
    bindings = []
    for entry, container in zip(pool["workers"], worker_containers):
        binding = {
            "schema": A.BINDING_SCHEMA,
            "captured_at_utc": captured_at,
            "authority": authority_ref,
            "pool": pool,
            "worker_index": entry["index"],
            "worker_spec_sha256": entry["worker_spec_sha256"],
            "container": container,
            "network_policy": policy,
            "egress_probe": {"required": False, "status": "not_required",
                             "target": None, "evidence_sha256": None},
            "digest": "0" * 64,
        }
        binding["digest"] = A.semantic_digest(binding)
        try:
            A.validate_binding_document(binding)
        except A.DockerAuthorityRefused as exc:
            raise WorkerRefused(str(exc)) from exc
        bindings.append(binding)
    return bindings


def validate_dedicated_database_network(container_name: str,
                                        network_name: str, *,
                                        docker_group: bool = True) -> dict:
    """Require the pre-existing database to be the internal network's sole peer."""
    container, _member = _container_snapshot(
        container_name, role="database", worker_index=None,
        docker_group=docker_group)
    network = _docker_json(
        ["network", "inspect", network_name, "--format", "{{json .}}"],
        f"network {network_name}", docker_group=docker_group)
    network_id = network.get("Id")
    expected_attachment = [{"name": network_name, "id": network_id}]
    live_members = network.get("Containers")
    if not isinstance(live_members, dict):
        raise WorkerRefused(
            "REFUSED: dedicated database network has no membership map")
    observed = sorted(
        (container_id, item.get("Name") if isinstance(item, dict) else None)
        for container_id, item in live_members.items())
    if network.get("Driver") != "bridge" \
            or network.get("Scope") != "local" \
            or network.get("Internal") is not True \
            or network.get("Ingress") is not False \
            or network.get("Attachable") is not False \
            or container["host_network_mode"] != network_name \
            or container["network_attachments"] != expected_attachment \
            or observed != [(container["id"], container_name)]:
        raise WorkerRefused(
            "REFUSED: database must already be running as the sole member "
            "of the exact local internal bridge before worker provisioning; "
            "the coordinator will not disconnect or rewire a shared database")
    return {"container": container, "network_id": network_id,
            "exclusive": True}


def _worker_resource_record(worker: "WorkerSpec", worker_spec_path: str,
                            attestation_path: str,
                            attestation_sha256: str) -> dict:
    """Canonical non-secret assignment included in mutation identities."""
    return {
        "index": worker.index,
        "worker_spec": os.path.realpath(worker_spec_path),
        "workspace": os.path.realpath(worker.workspace),
        "container": worker.container,
        "schema": worker.schema,
        "credential": worker.credential,
        "env_file": os.path.realpath(worker.env_file),
        "workdir": worker.workdir,
        "runtime_attestation": os.path.realpath(attestation_path),
        "runtime_attestation_sha256": attestation_sha256,
    }


def _load_runtime_attestation(worker_spec_path: str) -> tuple[str, str, dict]:
    """Read exact provision-time evidence without contacting Docker."""
    att_path = runtime_attestation_path(worker_spec_path)
    att_sha = _sha256_regular_file(att_path, "worker runtime attestation")
    try:
        with open(att_path, encoding="utf-8") as fh:
            attestation = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        raise WorkerRefused(
            f"REFUSED: cannot read worker runtime attestation "
            f"{att_path}: {e}") from e
    return att_path, att_sha, attestation


def validate_worker_runtime_v3(
        worker_spec_path: str, *, expected_worker: Optional["WorkerSpec"] = None,
        seed_dir: Optional[str] = None, harness_version: object = None,
        needs_database: Optional[bool] = None) -> dict:
    """Authenticate authority-bound v3/v4 runtime without changing historical data."""
    from .. import docker_authority as A
    worker_spec_path = os.path.abspath(worker_spec_path)
    att_path = runtime_attestation_path(worker_spec_path)
    try:
        A.assert_trusted_file(att_path, label="worker runtime v3")
        with open(att_path, "rb") as attestation_fh:
            raw = attestation_fh.read()
        attestation = A.loads_exact_json(raw, label="worker runtime v3")
    except (A.DockerAuthorityRefused, OSError) as exc:
        raise WorkerRefused(str(exc)) from exc
    if worker_runtime_version(attestation) not in {"v3", "v4"}:
        raise WorkerRefused(
            "REFUSED: new live worker execution requires exact "
            f"{WORKER_RUNTIME_SCHEMA} evidence at {att_path}; no Docker "
            "command was run. Reprovision this disposable worker.")
    attested_worker = _validate_worker_runtime_v3_shape(attestation, A)
    att_sha = hashlib.sha256(raw).hexdigest()
    try:
        binding = A.load_reference(
            attestation["docker_execution_binding"],
            expected_schema=A.BINDING_SCHEMA,
            validator=A.validate_binding_document,
            label="worker Docker binding")
        authority = A.load_reference(
            attestation["docker_execution_authority"],
            expected_schema=A.AUTHORITY_SCHEMA,
            validator=lambda value: A.validate_authority_document(
                value, current_source=False),
            label="Docker authority")
        A.validate_pool_document(binding["pool"], verify_files=True)
    except A.DockerAuthorityRefused as exc:
        raise WorkerRefused(str(exc)) from exc
    if worker_runtime_version(attestation) == "v4":
        _validate_worker_memory(attestation["memory"], container_id=binding["container"]["id"])
    if attestation["docker_execution_authority"] != binding["authority"]:
        raise WorkerRefused(
            "REFUSED: runtime and binding name different Docker authorities")
    index = binding["worker_index"]
    entry = binding["pool"]["workers"][index]
    spec_path = os.path.abspath(worker_spec_path)
    if entry["worker_spec_path"] != spec_path:
        raise WorkerRefused(
            "REFUSED: runtime binding points at another WorkerSpec path")
    try:
        with open(spec_path, "rb") as spec_fh:
            spec_raw = spec_fh.read()
        spec_doc = A.loads_exact_json(spec_raw, label="worker spec")
    except (OSError, A.DockerAuthorityRefused) as exc:
        raise WorkerRefused(str(exc)) from exc
    worker = WorkerSpec.from_json(spec_doc)
    if worker != attested_worker:
        raise WorkerRefused(
            "REFUSED: runtime embeds another WorkerSpec than its bound file")
    if expected_worker is not None and worker != expected_worker:
        raise WorkerRefused("REFUSED: runtime WorkerSpec differs from caller")
    if attestation["worker"] != worker.to_json() \
            or attestation["worker_spec_sha256"] \
            != hashlib.sha256(spec_raw).hexdigest() \
            or attestation["worker_spec_sha256"] != entry["worker_spec_sha256"] \
            or worker.index != index \
            or worker.container != binding["container"]["name"] \
            or attestation["container_image_digest"] \
            != binding["container"]["image_id"]:
        raise WorkerRefused(
            "REFUSED: runtime worker/spec/container/image joins are stale")
    runtime_needs_db = attestation["needs_database"]
    if not isinstance(runtime_needs_db, bool) \
            or (binding["pool"]["database"] is not None) != runtime_needs_db \
            or (runtime_needs_db and (not worker.schema or not worker.credential)) \
            or (not runtime_needs_db and (worker.schema or worker.credential)):
        raise WorkerRefused("REFUSED: runtime database semantics are incoherent")
    database_digest = attestation["database_dump_digest"]
    if runtime_needs_db:
        if not isinstance(database_digest, str) \
                or re.fullmatch(r"[0-9a-f]{64}", database_digest) is None:
            raise WorkerRefused("REFUSED: database runtime has no full dump digest")
    elif database_digest != NO_DATABASE:
        raise WorkerRefused("REFUSED: no-database runtime has a database digest")
    actual_seed = verified_seed_identity(
        attestation["seed_dir"], runtime_needs_db)
    for key, value in actual_seed.items():
        if attestation.get(key) != value:
            raise WorkerRefused(
                f"REFUSED: runtime seed join changed at {key}")
    if seed_dir is not None and os.path.realpath(seed_dir) \
            != attestation["seed_dir"]:
        raise WorkerRefused("REFUSED: caller selected another runtime seed")
    if needs_database is not None and bool(needs_database) is not runtime_needs_db:
        raise WorkerRefused("REFUSED: caller/runtime database semantics differ")
    if harness_version is not None \
            and attestation["harness_version"] != harness_version:
        raise WorkerRefused("REFUSED: runtime harness version is stale")
    return {
        "spec_path": spec_path,
        "worker": worker,
        "runtime_path": att_path,
        "runtime_sha256": att_sha,
        "runtime": attestation,
        "binding": binding,
        "authority": authority,
    }


_RUNTIME_PRIVATE_PARENT_ROLE = "Docker private parent"


def _runtime_protected_evidence_roles(
        loaded: list[dict]) -> tuple[tuple[str, str], ...]:
    """Every authenticated host path and the authority role it carries."""
    from .. import docker_authority as A
    return tuple(dict.fromkeys(
        entry
        for item in loaded
        for entry in (
            (item["spec_path"], "worker specification"),
            (item["runtime_path"], "worker runtime"),
            (item["runtime"]["seed_dir"], "worker seed"),
            (item["runtime"]["docker_execution_binding"]["path"],
             "Docker execution binding"),
            (item["runtime"]["docker_execution_authority"]["path"],
             "Docker execution authority"),
            (item["authority"]["adapter"]["selected_socket_path"],
             "selected Docker socket"),
            (item["authority"]["adapter"]["resolved_socket_path"],
             "resolved Docker socket"),
            (item["authority"]["adapter"]["private_parent_path"],
             _RUNTIME_PRIVATE_PARENT_ROLE),
            (item["authority"]["daemon"]["docker_root_dir"],
             "Docker data root"),
            (item["authority"]["client"]["selected_executable"],
             "selected Docker client"),
            (item["authority"]["client"]["resolved_executable"],
             "resolved Docker client"),
            (os.path.realpath(A.__file__), "Docker authority implementation"),
        )))


def _runtime_protected_evidence_paths(loaded: list[dict]) -> tuple[str, ...]:
    """Every authenticated host file that a workload mount must exclude."""
    return tuple(dict.fromkeys(
        path for path, _role in _runtime_protected_evidence_roles(loaded)))


@_seed_verification_scope()
def _authority_bound_runtime_attestations(
        worker_spec_paths: list[str], *, live: bool) -> list[dict]:
    """Authenticate a complete v3 pool, then optionally re-inspect it live."""
    if not worker_spec_paths:
        raise WorkerRefused(
            "REFUSED: live execution needs authority-bound worker evidence; "
            "no Docker command was run.")
    loaded = [validate_worker_runtime_v3(path)
              for path in worker_spec_paths]
    versions = {worker_runtime_version(item["runtime"]) for item in loaded}
    if len(versions) != 1:
        raise WorkerRefused("REFUSED: worker pool mixes capped and historical runtime evidence")
    authority_refs = [item["runtime"]["docker_execution_authority"]
                      for item in loaded]
    pools = [item["binding"]["pool"] for item in loaded]
    if any(ref != authority_refs[0] for ref in authority_refs[1:]) \
            or any(pool != pools[0] for pool in pools[1:]):
        raise WorkerRefused(
            "REFUSED: live worker pool carries mixed authority/pool evidence")
    snapshots = [(item["binding"]["captured_at_utc"],
                  item["binding"]["network_policy"])
                 for item in loaded]
    if any(snapshot != snapshots[0] for snapshot in snapshots[1:]):
        raise WorkerRefused(
            "REFUSED: live worker pool carries mixed binding snapshots")
    if [item["binding"]["worker_index"] for item in loaded] \
            != list(range(len(loaded))) \
            or len(loaded) != len(pools[0]["workers"]):
        raise WorkerRefused(
            "REFUSED: runtime bindings do not cover the complete zero-based pool")
    common_fields = ("seed_dir", "seed_manifest_sha256", "seed_key",
                     "workspace_seed_digest", "database_dump_digest",
                     "container_image_digest", "harness_version",
                     "needs_database")
    first = loaded[0]["runtime"]
    if any(any(item["runtime"][key] != first[key] for key in common_fields)
           for item in loaded[1:]):
        raise WorkerRefused(
            "REFUSED: live worker runtimes disagree on seed/harness/image")
    # V3 has no historical compatibility exception: evidence located inside
    # (or enclosing) a mutable worker workspace proves that the workload
    # could reach the trust anchor.  Apply this in the shared offline reader,
    # before an optional authority/Docker probe, so publication cannot bless
    # a layout that live execution must refuse.
    preflight(
        [item["worker"] for item in loaded], [],
        containment_paths=_runtime_protected_evidence_paths(loaded),
        live=False, needs_database=pools[0]["database"] is not None)
    if live:
        try:
            from ..core import docker_cli as D
            D.require_authority_reference(authority_refs[0], live=True)
        except D.DockerEndpointRefused as exc:
            raise WorkerRefused(str(exc)) from exc
        current = capture_execution_bindings(
            pools[0], authority_refs[0])
        comparable = ("authority", "pool", "worker_index",
                      "worker_spec_sha256", "container", "network_policy",
                      "egress_probe")
        for saved, observed in zip(
                (item["binding"] for item in loaded), current):
            changed = [key for key in comparable
                       if saved[key] != observed[key]]
            if changed:
                raise WorkerRefused(
                    "REFUSED: live worker binding changed; changed="
                    f"{changed}. Reprovision this disposable pool.")
        for item in loaded:
            if worker_runtime_version(item["runtime"]) == "v4":
                observed = capture_prestashop_memory(item["worker"])
                if observed["memory"] != item["runtime"]["memory"]:
                    raise WorkerRefused("REFUSED: live worker memory limits changed")
                item["oom_counters"] = observed["oom_counters"]
    return loaded


def validate_offline_worker_runtime_pool(
        worker_spec_paths: list[str]) -> list[dict]:
    """Authenticate a complete v3 pool without contacting Docker.

    Publication readers use this shared boundary so their v3 policy cannot
    drift: full authority references (including path and file hash), the
    complete pool object and every zero-based binding must agree.  Historical
    v1/v2 readers remain separate because those bytes deliberately do not
    satisfy the current evidence-file trust policy and never authorize live
    work.
    """
    return _authority_bound_runtime_attestations(
        worker_spec_paths, live=False)


@_seed_verification_scope()
def validate_live_worker_runtime(
        worker_spec_path: str, expected_worker: "WorkerSpec",
        harness_version: object, needs_database: bool,
        answer_paths: Iterable[str] = (), *,
        docker_group: bool = True,
        expected_pool_size: Optional[int] = None,
        expected_runtime: Optional[Mapping[str, object]] = None,
        behat=None, project: Optional[str] = None) -> dict:
    """Authorize one selected persistent worker and its complete v3 pool.

    The selected runtime is the discovery root: its authenticated binding
    supplies the ordered pool paths, so a caller cannot authorize a different
    pool with an extra flag.  Every static seed/spec/harness/containment join
    completes before authority revalidation or container inspection.

    `behat` is the project's `repo.BehatProject` row, and the LIVE preflight
    below needs it for the same reason `provision` does: which environment
    variable carries the DSN is per-project, so without the row a Sylius
    worker is inspected for `PIMCORE_TEST_DB_DSN`, found not to have it, and
    the whole authenticated pool is refused for being correctly configured.
    None is CoreShop's.
    """
    if not worker_spec_path:
        raise WorkerRefused(
            "REFUSED: new live evaluation/validation requires --worker with "
            "exact r2t.worker-runtime/v3 evidence; no Docker command was run.")
    answers = tuple(path for path in answer_paths if path)
    selected = validate_worker_runtime_v3(
        worker_spec_path, expected_worker=expected_worker,
        harness_version=harness_version, needs_database=needs_database)
    runtime_identity = {
        "harness_version": selected["runtime"]["harness_version"],
        "container_image_digest": selected["runtime"][
            "container_image_digest"],
        "workspace_seed_digest": selected["runtime"][
            "workspace_seed_digest"],
        "database_dump_digest": selected["runtime"][
            "database_dump_digest"],
    }
    if expected_runtime is not None:
        unknown = set(expected_runtime) - set(runtime_identity)
        changed = sorted(
            key for key in runtime_identity
            if expected_runtime.get(key) != runtime_identity[key])
        if unknown or changed:
            raise WorkerRefused(
                "REFUSED: campaign/runtime identity differs; "
                f"changed={changed}, unknown={sorted(unknown)}; no Docker "
                "command was run.")
    pool_paths = [entry["worker_spec_path"]
                  for entry in selected["binding"]["pool"]["workers"]]
    if expected_pool_size is not None \
            and expected_pool_size != len(pool_paths):
        raise WorkerRefused(
            f"REFUSED: --of {expected_pool_size} differs from authenticated "
            f"worker pool size {len(pool_paths)}; no Docker command was run.")
    if expected_worker.index >= len(pool_paths) \
            or os.path.abspath(worker_spec_path) \
            != pool_paths[expected_worker.index]:
        raise WorkerRefused(
            "REFUSED: selected worker is not its indexed member of the "
            "authenticated execution pool")
    loaded = _authority_bound_runtime_attestations(pool_paths, live=False)
    if project == "prestashop" or getattr(behat, "worker_init", None) == "prestashop":
        require_prestashop_memory(loaded)
    pool_specs = [item["worker"] for item in loaded]
    seed_dir = selected["runtime"]["seed_dir"]
    for path, spec in zip(pool_paths, pool_specs):
        validate_worker_runtime_v3(
            path, expected_worker=spec, seed_dir=seed_dir,
            harness_version=harness_version, needs_database=needs_database)
    protected = _runtime_protected_evidence_paths(loaded)
    preflight(pool_specs, list(answers), containment_paths=protected,
              live=False, docker_group=docker_group,
              needs_database=needs_database)

    live_loaded = _authority_bound_runtime_attestations(pool_paths, live=True)
    protected = _runtime_protected_evidence_paths(live_loaded)
    preflight(pool_specs, list(answers), containment_paths=protected,
              live=True, docker_group=docker_group,
              needs_database=needs_database, behat=behat)
    selected_live = live_loaded[expected_worker.index]
    return {
        "selected": selected_live,
        "pool_paths": tuple(pool_paths),
        "pool_specs": tuple(pool_specs),
        "protected_evidence_paths": protected,
        "docker_execution_authority": selected_live["runtime"][
            "docker_execution_authority"],
        "docker_execution_pool_digest": selected_live["binding"]["pool"][
            "digest"],
    }


def publication_runtime_reference(validated: dict,
                                  harness_identity: Mapping[str, object]) \
        -> dict:
    """Project an already-authenticated v3 runtime into ledger identity.

    ``validated`` may be the selected record returned by
    :func:`validate_worker_runtime_v3` or the complete live result returned by
    :func:`validate_live_worker_runtime`.  This function performs no Docker,
    daemon, pool, filesystem or network operation; it only closes the public
    identity over facts the existing validators already authenticated.
    """
    selected = validated.get("selected", validated)
    required = {
        "spec_path", "worker", "runtime_path", "runtime_sha256", "runtime",
        "binding", "authority",
    }
    if not isinstance(selected, dict) or not required <= set(selected):
        raise WorkerRefused(
            "REFUSED: publication runtime projection lacks a validated v3 "
            "selection")
    if not isinstance(harness_identity, Mapping) \
            or set(harness_identity) != {
                "version", "git_commit", "source_sha256"}:
        raise WorkerRefused(
            "REFUSED: publication harness identity has the wrong shape")
    runtime = selected["runtime"]
    binding = selected["binding"]
    authority = selected["authority"]
    if harness_identity["version"] != runtime["harness_version"]:
        raise WorkerRefused(
            "REFUSED: publication harness identity differs from validated "
            "runtime")
    from . import result_ledger
    identity_schema = (
        result_ledger.RUNTIME_IDENTITY_V2_SCHEMA
        if runtime["needs_database"] else result_ledger.RUNTIME_IDENTITY_SCHEMA)
    identity = {
        "schema": identity_schema,
        "docker_execution_authority": runtime[
            "docker_execution_authority"],
        "docker_execution_binding": runtime["docker_execution_binding"],
        "docker_daemon_fingerprint_sha256": authority["daemon"][
            "fingerprint_sha256"],
        "docker_execution_pool_digest": binding["pool"]["digest"],
        "worker_index": binding["worker_index"],
        "worker_spec_path": selected["spec_path"],
        "worker_spec_sha256": runtime["worker_spec_sha256"],
        "container_image_digest": runtime["container_image_digest"],
        "seed_dir": runtime["seed_dir"],
        "seed_manifest": {
            "path": runtime["seed_dir"] + "/seed.json",
            "file_sha256": runtime["seed_manifest_sha256"],
        },
        "seed_key": runtime["seed_key"],
        "workspace_seed_digest": runtime["workspace_seed_digest"],
        "database_dump_digest": runtime["database_dump_digest"],
        "needs_database": runtime["needs_database"],
        "harness": dict(harness_identity),
        "digest": "0" * 64,
    }
    identity["digest"] = result_ledger.semantic_digest(identity)
    return {
        "path": selected["runtime_path"],
        "file_sha256": selected["runtime_sha256"],
        "identity": identity,
    }


def validate_mutation_runtime_authority(
        worker_spec_paths: list[str]) -> str:
    """Preflight guard: all static joins pass before the first Docker probe."""
    loaded = _authority_bound_runtime_attestations(
        worker_spec_paths, live=True)
    return loaded[0]["runtime"]["docker_execution_authority"]["digest"]


def validate_mutation_runtime_endpoint_selection(
        worker_spec_paths: list[str]) -> str:
    """Deprecated name retained for callers; v3 never accepts a route claim."""
    return validate_mutation_runtime_authority(worker_spec_paths)


@_seed_verification_scope()
def validate_mutation_runtime(
        worker_spec_paths: list[str], workers: list["WorkerSpec"],
        seed_dir: str, harness_version: object, needs_database: bool, *,
        docker_group: bool = True, project: Optional[str] = None) -> dict:
    """Validate provision-time evidence and the live runtime for a sweep."""
    if len(worker_spec_paths) != len(workers) or not workers:
        raise WorkerRefused(
            "REFUSED: mutation runtime needs one worker-spec path per worker.")
    # Caller/seed/harness mismatches are static.  Prove all of them before the
    # authority probe or any container/network inspection.
    for spec_path, worker in zip(worker_spec_paths, workers):
        validate_worker_runtime_v3(
            spec_path, expected_worker=worker, seed_dir=seed_dir,
            harness_version=harness_version, needs_database=needs_database)
    if project == "prestashop":
        require_prestashop_memory(_authority_bound_runtime_attestations(worker_spec_paths, live=False))
    attestations = _authority_bound_runtime_attestations(
        worker_spec_paths, live=True)
    seed = verified_seed_identity(seed_dir, needs_database)
    records = []
    images = set()
    del docker_group
    for spec_path, worker, item in zip(
            worker_spec_paths, workers, attestations):
        checked = validate_worker_runtime_v3(
            spec_path, expected_worker=worker, seed_dir=seed_dir,
            harness_version=harness_version, needs_database=needs_database)
        if any(checked["runtime"][key] != value
               for key, value in seed.items()):
            raise WorkerRefused("REFUSED: runtime seed identity differs")
        image = checked["runtime"]["container_image_digest"]
        images.add(image)
        records.append(_worker_resource_record(
            worker, spec_path, checked["runtime_path"],
            checked["runtime_sha256"]))
    records.sort(key=lambda row: row["index"])
    if [row["index"] for row in records] != list(range(len(records))):
        raise WorkerRefused(
            "REFUSED: mutation runtime worker indices are not the exact "
            "zero-based ordered pool.")
    if len(images) != 1:
        raise WorkerRefused(
            f"REFUSED: mutation workers use mixed container images: "
            f"{sorted(images)}")
    return {
        "worker_resources": records,
        "worker_resources_sha256": _content_digest(records),
        "harness_version": harness_version,
        "container_image_digest": next(iter(images)),
        "workspace_seed_digest": seed["workspace_seed_digest"],
        "database_dump_digest": seed["database_dump_digest"],
        "docker_execution_authority": attestations[0]["runtime"][
            "docker_execution_authority"],
        "docker_execution_pool_digest": attestations[0]["binding"][
            "pool"]["digest"],
        "protected_evidence_paths": _runtime_protected_evidence_paths(
            attestations),
    }


class WorkerRefused(RuntimeError):
    pass


@dataclass(frozen=True)
class WorkerSpec:
    """What a worker IS — no secret, by construction.

    The password is not a field.  It exists in exactly two places: the
    mode-0600 env file this names, and the container's own environment.  A run
    stamp records `credential` (the account NAME), which is what §3.6 calls a
    non-secret credential identity.
    """

    index: int
    workspace: str
    container: str
    schema: str
    credential: str
    env_file: str
    workdir: str = "/var/www/html"
    out_path: str = ""
    artifacts_root: str = ""

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, doc: dict) -> "WorkerSpec":
        fields = set(cls.__dataclass_fields__)
        if not isinstance(doc, dict):
            raise WorkerRefused("REFUSED: worker spec is not a JSON object")
        missing = sorted(fields - set(doc))
        unknown = sorted(set(doc) - fields)
        if missing or unknown:
            raise WorkerRefused(
                f"REFUSED: worker spec fields differ; missing={missing}, "
                f"unknown={unknown}")
        if not isinstance(doc["index"], int) \
                or isinstance(doc["index"], bool) or doc["index"] < 0:
            raise WorkerRefused(
                f"REFUSED: worker index is invalid: {doc['index']!r}")
        bad_strings = sorted(
            key for key in fields - {"index"}
            if not isinstance(doc[key], str))
        if bad_strings:
            raise WorkerRefused(
                f"REFUSED: worker spec field(s) must be strings: "
                f"{bad_strings}")
        for key in ("workspace", "container", "env_file", "workdir"):
            if not doc[key]:
                raise WorkerRefused(
                    f"REFUSED: worker spec has no {key}")
        return cls(**doc)

    def runner(self, docker_group: bool = True) -> DockerRunner:
        return DockerRunner(self.container, workdir=self.workdir,
                            docker_group=docker_group)


def load_worker_spec(path: str) -> WorkerSpec:
    """Load one authoritative worker record."""
    if os.path.islink(path) or not os.path.isfile(path):
        raise WorkerRefused(
            f"REFUSED: worker spec is not a non-symlink regular file: {path}")
    try:
        with open(path, encoding="utf-8") as fh:
            return WorkerSpec.from_json(json.load(fh))
    except (OSError, json.JSONDecodeError) as e:
        raise WorkerRefused(f"REFUSED: cannot read worker spec {path}: {e}") \
            from e


def load_worker_pool(root: str, k: int) -> list[WorkerSpec]:
    """Load exactly ``worker0.json`` through ``worker{k-1}.json``."""
    if k < 1:
        raise WorkerRefused("REFUSED: K must be at least 1")
    workers = []
    for index in range(k):
        path = os.path.join(root, f"worker{index}.json")
        worker = load_worker_spec(path)
        if worker.index != index:
            raise WorkerRefused(
                f"REFUSED: {path} declares worker index {worker.index}, "
                f"expected {index} from its filename.")
        workers.append(worker)
    return workers


def _deny_peer_write(path: str) -> None:
    os.chmod(path, stat.S_IMODE(os.stat(path).st_mode) & ~0o022)


def write_worker_pool(root: str, workers: Iterable[WorkerSpec]) -> list[str]:
    """Save the planned pool so the admission rules can still accept it.

    Provisioning admits a pool only from a directory chain and spec files that
    no peer can replace, so the pool must not inherit the caller's umask: on a
    host whose default is 002 this root would be 0775 and the specs 0664, and
    the pool a `worker plan` just wrote would be refused by the next command.
    Only the peer-write bits are cleared, so an operator who deliberately
    widened read access keeps it.
    """
    os.makedirs(root, exist_ok=True)
    _deny_peer_write(root)
    paths = []
    for worker in workers:
        path = os.path.join(root, f"worker{worker.index}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(worker.to_json(), handle, indent=1, sort_keys=True)
        _deny_peer_write(path)
        paths.append(path)
    return paths


def worker_pool_needs_database(workers: list[WorkerSpec]) -> bool:
    """Return the database semantics declared by one complete worker pool."""
    modes = {(bool(w.schema), bool(w.credential)) for w in workers}
    if len(modes) != 1 or not modes.issubset({(True, True), (False, False)}):
        raise WorkerRefused(
            "REFUSED: saved worker specs disagree about database identity; "
            "re-run `worker plan` for one project.")
    return next(iter(modes))[0]


def plan_workers(root: str, k: int, *, runs_dir: Optional[str] = None,
                 artifacts_dir: Optional[str] = None,
                 name: Optional[str] = None,
                 workdir: str = "/var/www/html",
                 prefix: Optional[str] = None, kind: str = "php",
                 needs_database: bool = True) -> list[WorkerSpec]:
    """K workers whose every identity is derived from k, so none can collide.

    Derived rather than configured: a hand-written worker table is one
    copy-paste away from two workers sharing a schema, and that is precisely
    the 29%-disagreement failure.  Preflight still checks — deriving them
    correctly here does not make checking unnecessary, it makes the check
    cheap to pass.

    `prefix`, `name` and `kind` are the project namespace, pool namespace and
    what the container runs.  Their defaults reproduce CoreShop's names
    character for character (`coreshop_bench_php_0`, `coreshop_bench_0`),
    which matters because those names are what the archived worker manifests
    and the live containers already carry.

    `needs_database=False` leaves `schema` and `credential` EMPTY rather than
    deriving names for a schema that is never created and a MySQL principal
    that is never granted.  A record naming a live grant that does not exist
    is worse than one naming none, and `resource_fields` drops both from the
    disjointness check so K empty strings are not K collisions.
    """
    if k < 1:
        raise WorkerRefused("REFUSED: K must be at least 1")
    if name is None:
        name = "bench"
    if prefix is None:
        prefix = "coreshop"
    credential_namespace = (name if (prefix, name) == ("coreshop", "bench")
                            else f"{prefix}_{name}")
    root = os.path.abspath(root)
    runs_dir = os.path.abspath(runs_dir or os.path.join(root, "runs"))
    artifacts_dir = os.path.abspath(artifacts_dir
                                    or os.path.join(root, "artifacts"))
    secrets_dir = os.path.join(root, SECRETS_DIRNAME)
    out = []
    for i in range(k):
        out.append(WorkerSpec(
            index=i,
            workspace=os.path.join(root, f"worker{i}", "app"),
            container=_ident(f"{prefix}_{name}_{kind}_{i}", "container"),
            schema=(_ident(f"{prefix}_{name}_{i}", "schema")
                    if needs_database else ""),
            credential=(_ident(f"{credential_namespace}_{i}", "principal")
                        if needs_database else ""),
            env_file=os.path.join(secrets_dir, f"worker{i}.env"),
            workdir=workdir,
            out_path=os.path.join(runs_dir, f"worker{i}.jsonl"),
            artifacts_root=os.path.join(artifacts_dir, f"shard{i}"),
        ))
    return out


def _contains(outer: str, inner: str) -> bool:
    outer = os.path.realpath(outer).rstrip("/")
    inner = os.path.realpath(inner).rstrip("/")
    return inner == outer or inner.startswith(outer + "/")


def default_answer_paths(gold_root: str, artifacts: str,
                         release_dir: str) -> list[str]:
    """Everything that holds the answer, or an index of it.

    `gold/` is the removed test code.  `<release_dir>/gold/` is the installed
    scoring-bundle index keyed by item.  `closures.json` names, for
    every item, its files, its context classes, its constructor arguments and
    every step-definition pattern — it is an answer key that happens not to
    be code.  The generation caches hold whole solutions.  None of these may
    be reachable from a worker or an agent (§3.2).
    """
    return [p for p in (
        gold_root,
        os.path.join(release_dir, "gold"),
        os.path.join(artifacts, "closures.json"),
        os.path.join(artifacts, "matches.json"),
        os.path.join(artifacts, "php_index.json"),
        os.path.join(artifacts, "steps.json"),
        os.path.join(artifacts, "runs"),
    ) if p]


def _linked_regular_inputs(path: str) -> list[str]:
    """Return protected regular files that have another hard-link name.

    Realpath containment cannot see a hard link placed inside a worker
    workspace.  Requiring one link for live answer-bearing inputs makes such
    an alias visible before Docker contact.  Missing future outputs are
    intentionally ignored; they are still covered by lexical containment.
    """
    try:
        info = os.lstat(path)
    except OSError:
        return []
    if stat.S_ISREG(info.st_mode):
        return [path] if info.st_nlink != 1 else []
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        return []
    linked = []
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        # Do not traverse a directory symlink under an answer tree.  Its
        # resolved target is covered by ordinary containment when explicitly
        # named, and following it here could escape into an unbounded tree.
        dirnames[:] = [
            name for name in dirnames
            if not os.path.islink(os.path.join(dirpath, name))]
        for name in filenames:
            candidate = os.path.join(dirpath, name)
            try:
                candidate_info = os.lstat(candidate)
            except OSError:
                continue
            if stat.S_ISREG(candidate_info.st_mode) \
                    and candidate_info.st_nlink != 1:
                linked.append(candidate)
                if len(linked) == 8:
                    return linked
    return linked


def preflight(workers: list[WorkerSpec], answer_paths: list[str],
              *, containment_paths: Iterable[str] = (),
              live: bool = True, docker_group: bool = True,
              needs_database: bool = True,
              expected_indices: Optional[list[int]] = None,
              behat=None) -> dict:
    """Refuse to start unless the workers really are separate.

    Two halves, because they fail differently.  The STATIC half is arithmetic
    on names and paths and catches the configuration mistake.  The LIVE half
    asks Docker what each container actually has mounted, and catches the case
    where the names are fine and the container was created by hand months ago
    with the coordinator's whole artifacts directory bind-mounted into it.
    Answer paths additionally receive the recursive single-link audit;
    containment-only authority paths may legitimately contain hard links.
    """
    problems: list[str] = []
    containment_only = list(containment_paths)
    if live:
        from ..core.docker_cli import authority_protected_paths
        containment_only.extend(authority_protected_paths())
    containment_only = list(dict.fromkeys(
        os.path.abspath(path) for path in containment_only if path))
    protected_paths = [*answer_paths, *containment_only,
                       *(worker.env_file for worker in workers)]
    protected_paths = list(dict.fromkeys(
        os.path.abspath(path) for path in protected_paths if path))
    fields = resource_fields(needs_database)
    seen: dict[str, dict] = {f: {} for f in fields}
    for answer in answer_paths:
        linked = _linked_regular_inputs(answer)
        if linked:
            problems.append(
                f"answer-bearing input {answer} contains regular file(s) "
                f"with hard-link aliases: {linked}")
    for w in workers:
        for field in fields:
            if not getattr(w, field):
                problems.append(
                    f"worker {w.index} has no {field} identity")
        if not needs_database and (w.schema or w.credential):
            problems.append(
                f"worker {w.index} names schema/credential for a profile "
                "that declares no database")
        for field in ("workspace", "env_file"):
            if not os.path.isabs(getattr(w, field)):
                problems.append(
                    f"worker {w.index} {field} is not absolute: "
                    f"{getattr(w, field)!r}")
        try:
            env_info = os.lstat(w.env_file)
        except OSError:
            if live:
                problems.append(
                    f"worker {w.index} credential file is unavailable")
        else:
            if not stat.S_ISREG(env_info.st_mode) \
                    or stat.S_ISLNK(env_info.st_mode) \
                    or env_info.st_nlink != 1 \
                    or env_info.st_uid != os.geteuid() \
                    or stat.S_IMODE(env_info.st_mode) != 0o600:
                problems.append(
                    f"worker {w.index} credential file is not a "
                    "single-link current-UID mode-0600 regular file")
        if not w.workdir.startswith("/"):
            problems.append(
                f"worker {w.index} container workdir is not absolute: "
                f"{w.workdir!r}")
        for field in fields:
            value = getattr(w, field)
            canonical = (os.path.realpath(value)
                         if os.sep in str(value) else value)
            if canonical in seen[field]:
                problems.append(
                    f"workers {seen[field][canonical]} and {w.index} share "
                    f"{field} {value!r}")
            seen[field][canonical] = w.index

    indices = [w.index for w in workers]
    expected = (list(range(len(workers))) if expected_indices is None
                else sorted(expected_indices))
    if sorted(indices) != expected:
        problems.append(f"worker indices are not {expected}: "
                        f"{sorted(indices)}")

    for w in workers:
        for answer in answer_paths:
            # A publishable campaign normally starts with a NEW output path.
            # Containment is lexical after resolving existing parent
            # symlinks, so it is both meaningful and necessary before that
            # path exists; otherwise an output planned inside a mutable
            # worker tree escapes the preflight simply by not existing yet.
            if _contains(w.workspace, answer):
                problems.append(f"answer-bearing path {answer} lies inside "
                                f"worker {w.index}'s workspace")
            if _contains(answer, w.workspace):
                problems.append(f"worker {w.index}'s workspace lies inside "
                                f"answer-bearing path {answer}")
            if _contains(answer, w.env_file):
                problems.append(f"worker {w.index}'s credential file is "
                                f"reachable from answer-bearing path {answer}")
        for protected in containment_only:
            if _contains(w.workspace, protected):
                problems.append(
                    f"containment-protected path {protected} lies inside "
                    f"worker {w.index}'s workspace")
            if _contains(protected, w.workspace):
                problems.append(
                    f"worker {w.index}'s workspace lies inside "
                    f"containment-protected path {protected}")
        for other in workers:
            if other.index != w.index and _contains(w.workspace, other.workspace):
                problems.append(f"worker {other.index}'s workspace lies inside "
                                f"worker {w.index}'s")
    # A credential is private from EVERY mutable worker, not merely from the
    # worker that uses it.  Otherwise worker A can read worker B's env file
    # from a path nested under A's workspace and connect as B.
    for credential_owner in workers:
        for workspace_owner in workers:
            if _contains(workspace_owner.workspace,
                         credential_owner.env_file):
                problems.append(
                    f"worker {credential_owner.index}'s credential file is "
                    f"reachable from worker {workspace_owner.index}'s "
                    "workspace")

    live_report = {}
    if live:
        for w in workers:
            live_report[w.container] = mounts_of(w.container,
                                                 docker_group=docker_group,
                                                 behat=behat)
            info = live_report[w.container]
            # Fail CLOSED on anything Docker could not tell us.
            #
            # `mounts_of` turns an inspect failure into `exists: False` with an
            # empty mount list, and the loop below then finds nothing to
            # object to — so a review running without Docker access got a PASS
            # for four containers that did not exist. An absent, stopped or
            # unreadable container is not a clean worker; it is no worker.
            if not info.get("exists"):
                problems.append(
                    f"{w.container} could not be inspected — it does not "
                    f"exist, or Docker is unreachable. A preflight that "
                    f"cannot see a container has not checked it.")
                continue
            if not info.get("running"):
                problems.append(f"{w.container} exists but is not running")
            for detail in _runtime_env_binding_problems(
                    w, info.get("runtime_env"), needs_database, behat):
                problems.append(f"{w.container}: {detail}")
            mounted = {os.path.realpath(src): dst
                       for src, dst in info.get("mounts", [])}
            want = os.path.realpath(w.workspace)
            if mounted.get(want) != w.workdir:
                problems.append(
                    f"{w.container} does not mount {w.workspace} at "
                    f"{w.workdir} (it has {sorted(mounted.items())}); it would "
                    f"execute a workspace that is not this worker's")
            mount_details = info.get("mount_details")
            if not isinstance(mount_details, list):
                problems.append(
                    f"{w.container} mount access/type facts are unavailable")
                mount_details = []
            workspace_mounts = [
                item for item in mount_details
                if os.path.realpath(item.get("source", "")) == want
                and item.get("destination") == w.workdir]
            if len(workspace_mounts) != 1 \
                    or workspace_mounts[0].get("type") != "bind" \
                    or workspace_mounts[0].get("rw") is not True:
                problems.append(
                    f"{w.container} workspace is not one writable bind mount")
            for item in mount_details:
                source = item.get("source", "")
                destination = item.get("destination", "")
                is_workspace = os.path.realpath(source) == want \
                    and destination == w.workdir
                if not is_workspace:
                    if destination == AGENT_JAR_RUNTIME:
                        # The Java direct-invocation agent jar
                        # (stacks.cucumber, spec 2.4): a read-only host bind
                        # of one file, recorded by source path in the report.
                        if item.get("type") != "bind" \
                                or item.get("rw") is not False:
                            problems.append(
                                f"{w.container} direct-invocation agent jar "
                                "is not a read-only host bind")
                    elif destination != "/composer-cache":
                        problems.append(
                            f"{w.container} has an unexpected extra mount "
                            f"{source} -> {destination}; only the worker "
                            "workspace, the optional Composer cache and the "
                            "direct-invocation agent jar are allowed")
                    elif not needs_database:
                        problems.append(
                            f"{w.container} mounts a Composer cache for a "
                            "profile that declares no database/cache input")
                    elif item.get("type") != "bind" \
                            or item.get("rw") is not False:
                        problems.append(
                            f"{w.container} Composer cache is not a read-only "
                            "host bind")
            for src, dst in info.get("mounts", []):
                for protected in protected_paths:
                    if _contains(src, protected) \
                            or _contains(protected, src):
                        problems.append(
                            f"{w.container} mounts {src} -> {dst}, which "
                            f"reaches protected authority/evidence path "
                            f"{protected}")
                for other in workers:
                    if other.index != w.index and _contains(src, other.workspace):
                        problems.append(
                            f"{w.container} mounts {src}, which reaches "
                            f"worker {other.index}'s workspace")
    if problems:
        raise WorkerRefused(
            "REFUSED to start a K-way run:\n  - " + "\n  - ".join(problems))
    return {"workers": len(workers), "checked_answer_paths":
            [os.fspath(p) for p in answer_paths if os.path.exists(p)],
            "live": live_report}


def _docker(argv: list[str], docker_group: bool = True,
            stdin: Optional[str] = None,
            timeout: int = 600) -> subprocess.CompletedProcess:
    from ..core.docker_cli import docker_command
    cmd = docker_command(argv, docker_group=docker_group)
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                          timeout=timeout)


#: Exits 0 once a process of the container runs `tail -f /dev/null`, the
#: command `provision` starts it with, or 1 when $1 seconds have passed.
_REACHES_COMMAND = r'''end=$(( $(date +%s) + $1 ))
while [ "$(date +%s)" -lt "$end" ]; do
  for p in /proc/[0-9]*; do
    [ "$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)" = "tail -f /dev/null " ] && exit 0
  done
  sleep 0.2
done
exit 1'''


def wait_for_command(container: str, *, docker_group: bool = True,
                     timeout: int = 300) -> None:
    """Return once `container` runs its command, `tail -f /dev/null`.

    An image's entrypoint may prepare the container before it execs that
    command: e-petitions' starts PostgreSQL with `pg_ctl -w start`.  `docker
    run -d` returns before it has, and a command run at once -- the gold
    control's database reset -- found PostgreSQL not yet listening, or still
    starting up, on a loaded host.  The command runs as PID 1 or under an
    init (`--init`, tini), so every process is searched.  An entrypoint that
    fails stops the container, which ends the wait.
    """
    try:
        cp = _docker(["exec", container, "sh", "-c", _REACHES_COMMAND, "sh",
                      str(timeout)],
                     docker_group=docker_group, timeout=timeout + 60)
    except subprocess.TimeoutExpired:
        cp = None
    if cp is None or cp.returncode != 0:
        raise WorkerRefused(
            f"REFUSED: {container} did not reach its command within "
            f"{timeout}s: {((cp.stderr if cp else '') or '')[-500:]}")


def _safe_runtime_env(entries: list[str], behat=None) -> dict:
    """Project Docker's secret-bearing environment onto safe identity data.

    The DSN and password are deliberately never returned.  Malformed values
    are represented by booleans/``None`` so a refusal cannot accidentally
    print attacker-controlled secret material while explaining the mismatch.

    `behat` is the project row that says WHICH variable carries the DSN and
    whether there are install variables beside it; None is CoreShop's.
    """
    bp = behat or CORESHOP_BEHAT
    wanted = ("R2T_WORKER_INDEX", *db_env_keys(bp))
    relevant: dict[str, str] = {}
    duplicates: set[str] = set()
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, str) or "=" not in entry:
            continue
        key, value = entry.split("=", 1)
        if key not in wanted:
            continue
        if key in relevant:
            duplicates.add(key)
        relevant[key] = value

    def safe_identifier(value: object) -> Optional[str]:
        if isinstance(value, str) and len(value) <= 128 \
                and re.fullmatch(r"[A-Za-z0-9_]+", value):
            return value
        return None

    raw_index = relevant.get("R2T_WORKER_INDEX")
    worker_index = (raw_index if isinstance(raw_index, str)
                    and len(raw_index) <= 12 and raw_index.isascii()
                    and raw_index.isdigit() else None)
    install_user = safe_identifier(
        relevant.get("PIMCORE_INSTALL_MYSQL_USERNAME"))
    install_schema = safe_identifier(
        relevant.get("PIMCORE_INSTALL_MYSQL_DATABASE"))

    dsn = relevant.get(bp.db_dsn_env)
    dsn_user = None
    dsn_schema = None
    dsn_valid = False
    dsn_password = None
    dsn_host = None
    if isinstance(dsn, str):
        try:
            from urllib.parse import urlsplit
            parsed = urlsplit(dsn)
            candidate_schema = parsed.path[1:] if parsed.path.startswith(
                "/") else ""
            dsn_user = safe_identifier(parsed.username)
            dsn_schema = safe_identifier(candidate_schema)
            dsn_password = parsed.password
            dsn_host = parsed.hostname
            dsn_valid = bool(
                parsed.scheme == "mysql" and dsn_user and dsn_schema
                and isinstance(dsn_password, str) and dsn_password
                and isinstance(dsn_host, str) and dsn_host)
        except (TypeError, ValueError):
            # The report stays intentionally content-free.  The preflight
            # will name only the failed property (`dsn_valid`).
            pass
    install_password = relevant.get("PIMCORE_INSTALL_MYSQL_PASSWORD")
    install_host = relevant.get("PIMCORE_INSTALL_MYSQL_HOST_SOCKET")
    return {
        "present_keys": sorted(relevant),
        "duplicate_keys": sorted(duplicates),
        "worker_index": worker_index,
        "dsn_valid": dsn_valid,
        "dsn_principal": dsn_user,
        "dsn_schema": dsn_schema,
        "install_principal": install_user,
        "install_schema": install_schema,
        "dsn_password_present": bool(dsn_password),
        "install_password_present": bool(install_password),
        "password_channels_match": bool(
            dsn_password and install_password
            and dsn_password == install_password),
        "host_channels_match": bool(
            dsn_host and install_host and dsn_host == install_host),
    }


def _runtime_env_binding_problems(
        worker: WorkerSpec, runtime_env: object,
        needs_database: bool, behat=None) -> list[str]:
    """Compare a safe live projection with one worker's public identity.

    The install-variable half is CoreShop's SECOND channel: Pimcore's
    installer reads the credential twice, so the two copies are compared
    against each other.  A project whose row says there is one channel is
    checked on the one it has -- dropping the comparison there is not a
    relaxation, it is the absence of a second thing to compare.
    """
    bp = behat or CORESHOP_BEHAT
    if not isinstance(runtime_env, dict):
        return ["live runtime environment identity is unavailable"]
    problems = []
    if runtime_env.get("duplicate_keys"):
        problems.append("live runtime environment repeats identity key(s) "
                        f"{runtime_env['duplicate_keys']}")
    if runtime_env.get("worker_index") != str(worker.index):
        problems.append("live R2T_WORKER_INDEX differs from the worker spec")
    present = set(runtime_env.get("present_keys") or [])
    keys = db_env_keys(bp)
    if not needs_database:
        leaked = sorted(present & set(keys))
        if leaked:
            problems.append("database-free worker carries database variable(s) "
                            f"{leaked}")
        return problems

    missing = sorted(set(keys) - present)
    if missing:
        problems.append(f"live database environment misses key(s) {missing}")
    expected = {
        "dsn_principal": worker.credential,
        "dsn_schema": worker.schema,
    }
    coherent = ["dsn_valid", "dsn_password_present"]
    if bp.db_install_vars:
        expected["install_principal"] = worker.credential
        expected["install_schema"] = worker.schema
        coherent += ["install_password_present", "password_channels_match",
                     "host_channels_match"]
    changed = sorted(key for key, value in expected.items()
                     if runtime_env.get(key) != value)
    if changed:
        problems.append("live database identity differs from the worker spec "
                        f"in field(s) {changed}")
    incoherent = sorted(key for key in coherent
                        if runtime_env.get(key) is not True)
    if incoherent:
        problems.append("live database secret/DSN channels are incomplete or "
                        f"inconsistent in field(s) {incoherent}")
    return problems


def mounts_of(container: str, docker_group: bool = True,
              behat=None) -> dict:
    cp = _docker(["inspect", container, "--format",
                  "{{json .Mounts}}|{{json .Config.Env}}|{{json .State.Running}}"],
                 docker_group=docker_group, timeout=120)
    if cp.returncode != 0:
        return {"exists": False, "mounts": [], "env_keys": []}
    raw = (cp.stdout or "").strip()
    mounts_json, _, rest = raw.partition("|")
    env_json, _, running = rest.partition("|")
    try:
        raw_mounts = json.loads(mounts_json) or []
        if not isinstance(raw_mounts, list) \
                or any(not isinstance(m, dict)
                       or not isinstance(m.get("Source"), str)
                       or not isinstance(m.get("Destination"), str)
                       or not isinstance(m.get("Type"), str)
                       or not isinstance(m.get("RW"), bool)
                       for m in raw_mounts):
            raise TypeError("Docker mount projection is incomplete")
        mount_details = [{
            "source": m["Source"],
            "destination": m["Destination"],
            "type": m["Type"],
            "rw": m["RW"],
        } for m in raw_mounts]
        mounts = [(m["source"], m["destination"])
                  for m in mount_details]
        env = json.loads(env_json) or []
        is_running = json.loads(running or "false")
    except (json.JSONDecodeError, TypeError, AttributeError):
        return {"exists": False, "mounts": [], "env_keys": []}
    return {
        "exists": True,
        "running": is_running,
        "mounts": mounts,
        "mount_details": mount_details,
        # Names only.  Printing an environment VALUE from a container that
        # holds a database password is the same mistake as putting it in argv.
        "env_keys": sorted(e.split("=", 1)[0] for e in env),
        "runtime_env": _safe_runtime_env(env, behat),
    }


def image_env(image: str, docker_group: bool = True) -> list[str]:
    cp = _docker(["image", "inspect", image, "--format", "{{json .Config.Env}}"],
                 docker_group=docker_group, timeout=120)
    if cp.returncode != 0:
        raise WorkerRefused(f"REFUSED: no such image: {image}")
    return json.loads(cp.stdout or "[]")


def env_overrides(template_container: str, image: str,
                  docker_group: bool = True) -> dict:
    """The application-level environment, separated from the image's own.

    A worker must differ from the reference container in exactly the
    database, so the reference is read back and the image's baked-in defaults
    subtracted.  Copying the whole environment instead would carry the
    reference's DSN into every worker and silently point all K at one schema —
    which is the failure this module exists to make impossible.
    """
    base = set(image_env(image, docker_group=docker_group))
    cp = _docker(["inspect", template_container, "--format", "{{json .Config.Env}}"],
                 docker_group=docker_group, timeout=120)
    if cp.returncode != 0:
        raise WorkerRefused(f"REFUSED: no such container: {template_container}")
    out = {}
    for entry in json.loads(cp.stdout or "[]"):
        if entry in base:
            continue
        k, _, v = entry.partition("=")
        out[k] = v
    return out


def write_env_file(worker: WorkerSpec, password: Optional[str],
                   overrides: dict,
                   db_host: str = DEFAULT_DB_CONTAINER, db_port: int = 3306,
                   needs_database: bool = True, behat=None) -> str:
    """The credential's only home on disk: mode 0600, outside every workspace.

    Written with `os.open(..., 0o600)` rather than `open()` + `chmod`: between
    those two calls the file exists at the process umask, and this file is the
    isolation boundary between one worker's submitted code and every other
    worker's data.

    A stack with no database still gets a file, and it is still mode 0600.
    The five Pimcore DSN variables are what goes away; `R2T_WORKER_INDEX`
    STAYS, because it is not a database fact — it is how a row learns which
    worker produced it (§3.6), and a shard that cannot stamp its own index is
    a shard whose rows cannot be placed.

    WHICH variables those are is the project's row (`repo.BehatProject`):
    CoreShop bakes `PIMCORE_TEST_DB_DSN` plus the four the Pimcore
    installer reads, Sylius bakes `DATABASE_URL` with Doctrine's charset
    query and nothing else.  `behat=None` is CoreShop's, so the file every
    existing caller writes is byte-for-byte the file it wrote before.

    The per-worker value REPLACES whatever DSN the template container
    carried: that one names the install-time schema, and K workers reading
    it would be K workers on one schema.
    """
    bp = behat or CORESHOP_BEHAT
    os.makedirs(os.path.dirname(worker.env_file), exist_ok=True)
    os.chmod(os.path.dirname(worker.env_file), 0o700)
    env = dict(overrides)
    if needs_database:
        env[bp.db_dsn_env] = (
            f"mysql://{worker.credential}:{password}@{db_host}:{db_port}/"
            f"{worker.schema}{bp.db_dsn_suffix}")
        if bp.db_install_vars:
            env["PIMCORE_INSTALL_MYSQL_USERNAME"] = worker.credential
            env["PIMCORE_INSTALL_MYSQL_PASSWORD"] = password
            env["PIMCORE_INSTALL_MYSQL_DATABASE"] = worker.schema
            env["PIMCORE_INSTALL_MYSQL_HOST_SOCKET"] = db_host
    elif password is not None:
        # A password for a principal that was never created is a secret with
        # nowhere to be used and one more place to leak from.
        raise WorkerRefused(
            "REFUSED: a worker with no database was given a password. There "
            "is no principal to authenticate and nothing for it to reach.")
    env["R2T_WORKER_INDEX"] = str(worker.index)
    bad = [k for k, v in env.items() if "\n" in v or "\r" in v]
    if bad:
        raise WorkerRefused(
            f"REFUSED: {bad} contain a newline, which `docker run --env-file` "
            f"cannot represent — it would silently truncate the value.")
    body = "".join(f"{k}={v}\n" for k, v in sorted(env.items()))
    tmp = worker.env_file + ".part"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.replace(tmp, worker.env_file)
    return worker.env_file


#: Every object `information_schema.tables` counts, as `mysqldump` spells it
#: in the seed's own `database.sql`: `CREATE TABLE `x``, and the two
#: spellings a VIEW gets -- the placeholder `/*!50001 CREATE VIEW `x` AS
#: SELECT` written where its table would be, and the final
#: `/*!50001 VIEW `x` AS select` that follows the algorithm/security
#: comments.  Matched by NAME so a view's two spellings are one view.
_DUMP_TABLE = re.compile(r"^CREATE TABLE `([^`]+)`", re.MULTILINE)
_DUMP_VIEW = re.compile(r"^(?:/\*!\d+ )?(?:CREATE )?VIEW `([^`]+)` AS",
                        re.MULTILINE)


def dump_table_count(dump_path: str) -> int:
    """How many tables and views a complete load of this dump creates.

    The number this replaced was CoreShop's 252, written into a floor of
    100: every other project's pool was then measured against CoreShop's
    schema, and a Sylius worker holding its own correct 83 tables was
    refused as a partial load.  The seed's dump is the only thing that
    knows how big its schema is, so it is what the loaded schema is
    compared with.

    Views are counted beside tables because `information_schema.tables` --
    which is what `MySQL.table_bytes` reads -- counts them: CoreShop's 252
    is 215 tables and 37 Pimcore `object_*` views.
    """
    with open(dump_path, encoding="utf-8", errors="surrogateescape") as fh:
        text = fh.read()
    return len(set(_DUMP_TABLE.findall(text))
               | set(_DUMP_VIEW.findall(text)))


def provision(worker: WorkerSpec, seed_dir: str, db: Optional[MySQL] = None, *,
              image: str = DEFAULT_IMAGE,
              network: Optional[str] = DEFAULT_NETWORK,
              template_container: Optional[str] = None,
              overrides: Optional[dict] = None,
              docker_group: bool = True, force: bool = False,
              extra_run_args: tuple = (),
              extra_mounts: tuple = (),
              db_host: str = DEFAULT_DB_CONTAINER,
              needs_database: bool = True, behat=None,
              seed_policy: Optional[str] = None) -> dict:
    """Workspace, schema and container — together, or not at all.

    Ordered so that a failure leaves nothing half-usable: the workspace and
    the schema exist before the credential that reaches them, and the
    container is created last, because a running container pointed at a schema
    that failed to load is a worker that scores every item
    `container_error` and looks like a model failure.

    `needs_database=False` (D6) makes it a PAIR — workspace and container.
    The schema, the principal, the DSN and the load check are not relaxed
    for it, they do not apply: a python library has no schema, and running
    the CoreShop path against it would create an empty database nobody
    connects to and then refuse the worker for holding no tables, which
    reads exactly like a corrupt seed.

    The claim is CHECKED against the seed rather than trusted.  A seed built
    with a dump and provisioned as if it had none would leave every scenario
    talking to a database that was never loaded.

    `seed_policy` is the caller's own `rules_for(framework, project).digest()`
    and is checked the same way, for the failure that is otherwise SILENT and
    GREEN.  `--boundary` defaults to CoreShop's, so a forgotten flag provisions
    another project's seed while `write_env_file` bakes `PIMCORE_TEST_DB_DSN`
    into its containers — a variable that project's application ignores,
    leaving all K workers on the one schema named by the committed `.env`.
    Every check afterwards then reads the same wrong row and passes, and the
    isolation certificate that comes out describes a boundary nobody tested.

    What the comparison proves is the POLICY, not the project: it is the
    seed's recorded `rules_digest` against the one this invocation computes.
    `rules_for` narrows to a project only where a project row exists, so two
    projects on one framework share a digest — every `behave` project is
    `48836f0a…` — and swapping one for the other passes this check. What it
    does catch is the mix-up that changes the provisioning: a seed pruned by
    another policy's rules, carrying another policy's DSN variable. That is
    the CoreShop/Sylius direction, and it costs one comparison and no new
    field.
    """
    if behat is not None and behat.worker_init == "prestashop":
        if not worker.schema.startswith("test_") or worker.workdir != "/var/www/html":
            raise WorkerRefused("REFUSED: PrestaShop needs --prefix test_prestashop "
                                "and --workdir /var/www/html")
        if needs_database and db_host == DEFAULT_DB_CONTAINER and db is not None:
            db_host = db.container
    started = time.time()
    report: dict = {"worker": worker.to_json(),
                    "needs_database": needs_database}

    # The seed's own digests, checked before anything is provisioned from it.
    #
    # `verify_seed` existed and nothing called it: provisioning untarred the
    # workspace and loaded `database.sql` on the strength of the manifest
    # alone, so a truncated tar or a dump cut short by a full disk would have
    # been installed under a previously recorded identity and every result
    # attributed to that seed.
    from .seed import verify_seed
    seed_report = verify_seed(seed_dir)
    if not seed_report["artifacts_ok"]:
        raise WorkerRefused(
            f"REFUSED: the seed at {seed_dir} does not match its own recorded "
            f"digests, so provisioning from it would attribute results to a "
            f"seed that is not this one: {json.dumps(seed_report)[:400]}")
    if seed_report.get("needs_database", True) != needs_database:
        raise WorkerRefused(
            f"REFUSED: the seed at {seed_dir} was built "
            f"{'with' if seed_report.get('needs_database', True) else 'without'}"
            f" a database and this worker is being provisioned "
            f"{'with' if needs_database else 'without'} one. One of the two is "
            f"describing another stack, and the scenarios would run against "
            f"whichever of them is wrong.")
    if seed_policy is not None:
        from .seed import read_seed
        built_under = (read_seed(seed_dir) or {}).get("rules_digest")
        if built_under != seed_policy:
            raise WorkerRefused(
                f"REFUSED: the seed at {seed_dir} was built under seed policy "
                f"{built_under}; the policy this invocation's "
                f"--boundary/--profile names is {seed_policy}. Two projects "
                f"on one framework share a policy, so this does not say which "
                f"project either side is -- it says the seed was pruned by "
                f"another set of rules than the ones being provisioned from "
                f"it, and would be given another policy's DSN variable in "
                f"every container: the application then stays on the schema "
                f"its committed environment names, shared by all K workers, "
                f"with every check afterwards reading the same wrong row and "
                f"passing.")
        report["seed_policy"] = seed_policy
    report["seed"] = {"seed_key": seed_report["seed_key"]}

    if force:
        # The container goes first: it holds the bind mount, and removing the
        # workspace under a running executor is how a sweep ends up reading
        # half a tree.
        remove_container(worker.container, docker_group=docker_group)
        report["previous_workspace"] = remove_workspace(
            worker.workspace, image=image, docker_group=docker_group)
    else:
        require_container_absent(worker.container,
                                 docker_group=docker_group)
    report["workspace"] = unpack_workspace(seed_dir, worker.workspace,
                                           force=force)

    password = None
    if needs_database:
        if db is None:
            raise WorkerRefused(
                "REFUSED: a worker that needs a database was given no "
                "connection to create its schema with.")
        if force:
            # Dropped rather than loaded over.  `mysqldump` emits
            # `DROP TABLE IF EXISTS` for the tables it carries, so those would
            # be replaced — but Pimcore materialises a table per DataObject
            # class at scenario setup, and any of those left by a previous
            # campaign is in no dump and would survive the load, leaving a
            # schema that is neither the seed nor the campaign before it.
            db.drop_schema(worker.schema)
        dump_path = os.path.join(seed_dir, "database.sql")
        db.create_schema(worker.schema)
        db.load(worker.schema, dump_path)
        expected_tables = dump_table_count(dump_path)
        tables = db.table_bytes(worker.schema)
        report["schema"] = {"name": worker.schema, "tables": len(tables),
                            "bytes": sum(tables.values())}
        if not expected_tables:
            raise WorkerRefused(
                f"REFUSED: {dump_path} creates no table at all, so a "
                f"complete load of it cannot be told from a schema that was "
                f"never loaded.")
        if len(tables) != expected_tables:
            raise WorkerRefused(
                f"REFUSED: {worker.schema} holds {len(tables)} tables and "
                f"views; {dump_path} creates {expected_tables}. A partial "
                f"load — or a schema that was already there — would score "
                f"every item as the system under test failing.")

        password = new_password()
        report["principal"] = db.create_worker_principal(
            worker.credential, password, worker.schema)
    else:
        # DECLARED, not skipped silently: a report with no `schema` key at all
        # would read the same as a provision that crashed before reaching it.
        report["schema"] = {"name": None, "declared": NO_DATABASE}
    if overrides is not None:
        report["app_env"] = {"template_container": None,
                             "names": sorted(overrides)}
    else:
        if not template_container:
            raise WorkerRefused(
                "REFUSED: a database-backed worker inherits its application "
                "environment from a template container, and no default is "
                "safe -- the container that happens to carry that name may "
                "not be the one the provisioning recipe produced. Name it "
                "with --template-container.")
        overrides = env_overrides(template_container, image,
                                  docker_group=docker_group)
        # NAMES ONLY.  The values carry PIMCORE_SECRET and the install
        # encryption secret, whose only copy is that container's environment.
        # Recording which container was read, and which variables came out of
        # it, is what makes a hand-recreated template visible instead of
        # silently becoming the system under test.
        report["app_env"] = {"template_container": template_container,
                             "names": sorted(overrides)}
    write_env_file(worker, password, overrides,
                   # The DSN's host is the PUBLISHED ALIAS the database
                   # answers to on the pool's internal network, NOT the
                   # database container's own name.  `environment_lifecycle`
                   # publishes `descriptor.database.alias` with
                   # `--network-alias`, and a hand-built pool attaches its
                   # database container to the internal network under that
                   # same alias, so the alias is what every worker resolves
                   # while the container name is a per-pool nonce.
                   # `db.container` is the ADMIN HANDLE only — the name the
                   # provisioner runs `mysql` against — and threading it here
                   # would write that nonce into K credential files.
                   # A caller that knows a different host says so with
                   # `db_host=`; none does today.
                   db_host=db_host,
                   needs_database=needs_database, behat=behat)
    del password

    argv = ["run", "-d", "--name", worker.container,
            *(("--network", network) if network else ()),
            "--env-file", worker.env_file,
            "--security-opt", "no-new-privileges",
            "--pids-limit", "1024",
            "-v", f"{worker.workspace}:{worker.workdir}",
            *[a for src, dst in extra_mounts for a in ("-v", f"{src}:{dst}")],
            *extra_run_args,
            *(("--memory", str(PRESTASHOP_MEMORY_POLICY["memory_bytes"]),
               "--memory-swap", str(PRESTASHOP_MEMORY_POLICY["memory_bytes"]))
              if behat is not None and behat.worker_init == "prestashop" else ()),
            image, "tail", "-f", "/dev/null"]
    cp = _docker(argv, docker_group=docker_group, timeout=300)
    if cp.returncode != 0:
        raise WorkerRefused(f"REFUSED: could not start {worker.container}: "
                            f"{(cp.stderr or '')[-500:]}")
    wait_for_command(worker.container, docker_group=docker_group)
    if behat is not None and behat.worker_init == "prestashop":
        report["memory_observation"] = capture_prestashop_memory(worker, docker_group=docker_group)
        report["initialization"] = initialize_prestashop_worker(
            worker, seed_dir, docker_group=docker_group)
    report["container"] = mounts_of(worker.container,
                                    docker_group=docker_group, behat=behat)
    report["seconds"] = round(time.time() - started, 1)
    return report


def initialize_prestashop_worker(worker: WorkerSpec, seed_dir: str, *,
                                 docker_group: bool = True) -> dict:
    """Complete private restore inputs before provision returns to attestation."""
    from .seed import read_seed
    source_schema = (read_seed(seed_dir) or {}).get("source_schema")
    if not isinstance(source_schema, str):
        raise WorkerRefused("REFUSED: PrestaShop seed has no source schema")
    cp = _docker([
        "exec", "--workdir", worker.workdir, "--env", "XDEBUG_MODE=off",
        worker.container, "php",
        "tests/Integration/Behaviour/Bench/prestashop_worker_init.php",
        source_schema, worker.schema, worker.credential,
    ], docker_group=docker_group, timeout=300)
    try:
        report = json.loads(cp.stdout or "")
    except (ValueError, TypeError):
        report = None
    if (cp.returncode or not isinstance(report, dict)
            or report.get("schema") != worker.schema
            or report.get("principal") != worker.credential
            or report.get("private_tmp") is not True
            or not isinstance(report.get("tables"), int)
            or report["tables"] < 1):
        raise WorkerRefused("REFUSED: PrestaShop worker initialization failed; "
                            "no worker attestation can be written")
    return {"schema": worker.schema, "principal": worker.credential,
            "private_tmp": True, "tables": report["tables"]}


def require_container_absent(name: str, docker_group: bool = True) -> None:
    """Refuse a fresh provision if its planned container name already exists.

    Normal provisioning used to run `docker rm -f NAME` unconditionally,
    making the supposedly fresh bootstrap a destructive cleanup operation.
    Querying the exact planned name is within the saved pool plan; removing an
    unidentified pre-existing object is not.  The daemon and invoking user are
    trusted against races after this check by the authority threat model.
    """
    cp = _docker([
        "container", "ls", "--all", "--no-trunc",
        "--filter", f"name=^/{name}$",
        "--format", "{{.ID}}|{{.Names}}",
    ], docker_group=docker_group, timeout=120)
    if cp.returncode != 0:
        raise WorkerRefused(
            "REFUSED: could not prove the planned worker container name is "
            "unused; fresh provisioning performed no cleanup")
    rows = [line for line in (cp.stdout or "").splitlines() if line]
    expected = re.compile(rf"[0-9a-f]{{64}}\|{re.escape(name)}")
    if any(expected.fullmatch(row) is None for row in rows):
        raise WorkerRefused(
            "REFUSED: Docker returned an ambiguous exact-name projection; "
            "fresh provisioning performed no cleanup")
    if rows:
        raise WorkerRefused(
            f"REFUSED: planned worker container {name!r} already exists. "
            "Use a fresh workers root/prefix; normal provision never removes "
            "a pre-existing container and --force is closed.")


def remove_container(name: str, docker_group: bool = True) -> bool:
    cp = _docker(["rm", "-f", name], docker_group=docker_group, timeout=300)
    return cp.returncode == 0


def remove_workspace(path: str, image: str = DEFAULT_IMAGE,
                     docker_group: bool = True) -> dict:
    """Delete a workspace the container has been writing into as root.

    Submitted PHP runs as root on the bind mount (`DockerRunner` passes no
    `--user`), so `var/cache`, `var/classes` and anything a scenario created
    end up owned by root:root.  A host-side `shutil.rmtree` then dies with
    `PermissionError: 'Attributes.php'` partway through — which is how a
    re-provision leaves a half-deleted workspace that the next unpack merges
    into.  The retry runs `rm -rf` in a throwaway container, as the same uid
    that created the files.

    `--entrypoint` is overridden because the bench image's own entrypoint is
    an xdebug wrapper that would swallow the command.
    """
    import shutil
    if not os.path.isdir(path):
        return {"removed": False, "why": "absent"}
    try:
        shutil.rmtree(path)
        return {"removed": True, "as_root": False}
    except PermissionError:
        pass
    parent, name = os.path.split(os.path.abspath(path).rstrip("/"))
    cp = _docker(["run", "--rm", "--entrypoint", "/bin/sh",
                  "-v", f"{parent}:/mnt", image,
                  "-c", f"rm -rf {shlex.quote('/mnt/' + name)}"],
                 docker_group=docker_group, timeout=600)
    if cp.returncode != 0 or os.path.isdir(path):
        raise WorkerRefused(
            f"REFUSED: could not remove {path}, even as root inside a "
            f"container: {(cp.stderr or '')[-300:]}. Leaving it would let the "
            f"next unpack merge two trees into a workspace that is neither.")
    return {"removed": True, "as_root": True}


def teardown(worker: WorkerSpec, db: Optional[MySQL] = None, *,
             keep_workspace: bool = False, docker_group: bool = True,
             image: str = DEFAULT_IMAGE) -> dict:
    """The whole triple, torn down together.

    Leaving a schema behind after removing its container is how a later
    campaign silently inherits another campaign's rows; leaving the credential
    behind is how a container nobody remembers keeps write access to it.
    """
    out = {"container": remove_container(worker.container,
                                         docker_group=docker_group)}
    if db is not None:
        db.drop_principal(worker.credential)
        db.drop_schema(worker.schema)
        out["schema_dropped"] = True
    if os.path.isfile(worker.env_file):
        os.remove(worker.env_file)
        out["credential_removed"] = True
    if not keep_workspace and os.path.isdir(worker.workspace):
        # The worker's OWN image, because the fallback path deletes root-owned
        # files by running `rm -rf` in a throwaway container -- and reaching
        # for CoreShop's 1.92 GB PHP image to clean up after a python worker
        # works only for as long as that image happens to be on the host.
        out["workspace_removed"] = remove_workspace(worker.workspace,
                                                    image=image,
                                                    docker_group=docker_group)
    return out


PROBE_REL = "var/bench_probe/db_probe.php"


def _bind_probe_identity(report: dict, worker: WorkerSpec) -> dict:
    """Require a safe probe verdict to describe the worker that requested it."""
    if report.get("principal") != worker.credential \
            or report.get("own_schema") != worker.schema:
        raise WorkerRefused(
            f"REFUSED: database probe executed with a principal/schema that "
            f"does not belong to worker {worker.index}; the live container "
            "is bound to another database identity.")
    return report


def _safe_probe_output(raw: str, worker: WorkerSpec,
                       victim_schema: str) -> dict:
    """Parse a worker probe without returning any worker-controlled text.

    Submitted code can read its own DSN, so stdout, stderr, SQL error strings,
    visible schema names and arbitrary JSON fields are all secret-bearing.
    Only fixed check names, booleans/counts and identities already present in
    ``WorkerSpec`` cross this trust boundary.
    """
    def failed(reason: str) -> dict:
        return {
            "pass": False,
            "failure_class": reason,
            "worker": worker.index,
            "principal": None,
            "own_schema": None,
            "victim_schema": victim_schema,
            "reachable_checks": [],
            "checks_not_run": list(REQUIRED_DENIED),
            "denials_without_permission_error": [],
            "non_system_schema_count": None,
        }

    start = raw.find("{") if isinstance(raw, str) else -1
    if start < 0:
        return failed("probe_output_missing_json")
    try:
        doc = json.loads(raw[start:])
    except (json.JSONDecodeError, TypeError, ValueError):
        return failed("probe_output_invalid_json")
    if not isinstance(doc, dict):
        return failed("probe_output_not_object")

    # Bind before deriving the verdict. `probe_report` intentionally omits
    # identity fields on an early control failure, while the raw document
    # still carries the safe principal/schema values needed for this join.
    _bind_probe_identity(doc, worker)
    try:
        report = probe_report(doc)
    except (AttributeError, TypeError, ValueError):
        return failed("probe_output_invalid_shape")

    allowed_names = set(REQUIRED_DENIED)

    def safe_names(values) -> list[str]:
        if not isinstance(values, list):
            return []
        return sorted({value for value in values
                       if isinstance(value, str)
                       and value in allowed_names})

    reachable = safe_names(report.get("reachable_from_worker"))
    missing = safe_names(report.get("checks_not_run"))
    unproven = safe_names([
        entry.get("check") for entry in
        (report.get("denials_without_a_permission_error") or [])
        if isinstance(entry, dict)])
    if report.get("pass") is True:
        failure_class = None
    elif report.get("why"):
        failure_class = "own_schema_control_failed"
    elif reachable:
        failure_class = "forbidden_access_succeeded"
    elif missing:
        failure_class = "checks_not_run"
    elif unproven:
        failure_class = "denial_not_permission_error"
    else:
        failure_class = "probe_failed"
    visible = report.get("non_system_schemas_visible")
    visible_count = (len(visible) if isinstance(visible, list) else None)
    return {
        "pass": report.get("pass") is True,
        "failure_class": failure_class,
        "worker": worker.index,
        "principal": worker.credential,
        "own_schema": worker.schema,
        "victim_schema": victim_schema,
        "reachable_checks": reachable,
        "checks_not_run": missing,
        "denials_without_permission_error": unproven,
        "non_system_schema_count": visible_count,
    }


def probe_victim_schema(workers: list[WorkerSpec], worker: WorkerSpec,
                        sentinel: Optional[str] = None) -> str:
    """The schema this worker must NOT be able to read.

    At K>1 that is the next worker's schema, positionally.  At K=1 the
    positional neighbour wraps around to the worker's OWN schema, and a probe
    against yourself cannot fail for the reason the acceptance is about: every
    check succeeds, the verdict reads `forbidden_access_succeeded`, and an
    operator cannot tell that from a genuine isolation breach.  So K=1 must
    name a sentinel explicitly rather than silently probing itself.
    """
    if sentinel is not None:
        if sentinel == worker.schema:
            raise WorkerRefused(
                f"REFUSED: sentinel schema {sentinel!r} is worker "
                f"{worker.index}'s own schema, so a denial would be "
                "impossible and a success would prove nothing.")
        return sentinel
    victim = workers[(worker.index + 1) % len(workers)].schema
    if victim == worker.schema:
        raise WorkerRefused(
            "REFUSED: a one-worker pool has no neighbour to probe, and "
            "probing this worker's own schema would report a failure that is "
            "indistinguishable from a real one. Name a populated schema this "
            "worker may not read with --sentinel-schema.")
    return victim


def probe_database(worker: WorkerSpec, victim_schema: str,
                   docker_group: bool = True, *, behat=None) -> dict:
    """Run the §3.2 acceptance from INSIDE the worker container.

    Not from the coordinator, and not by reading `SHOW GRANTS`.  What is being
    checked is whether submitted code can reach a neighbour's data, and only
    code executing where submitted code executes, with the credential
    submitted code is given, can answer that.

    The probe is written under `var/`, never `_bench/`: `_bench` is a hashed
    substrate root and a stray file there aborts the next item as tampering.

    Refused outright for a worker that has no database (D6).  A probe that
    finds no neighbour's data because there IS no data would print `pass` and
    mean nothing, and a green isolation acceptance nobody can falsify is
    worse than no acceptance at all.

    `behat` names which environment variable holds the DSN, because that is
    the project's row and not a constant; `None` is CoreShop's.
    """
    if not worker.schema or not worker.credential:
        raise WorkerRefused(
            f"REFUSED: worker {worker.index} has no schema and no principal, "
            f"so there is no isolation to probe. A pass here would assert "
            f"something the configuration cannot make false.")
    runner = worker.runner(docker_group=docker_group)
    host_path = os.path.join(worker.workspace, PROBE_REL)
    os.makedirs(os.path.dirname(host_path), exist_ok=True)
    with open(host_path, "w", encoding="utf-8") as fh:
        fh.write(db_probe_php(behat))
    try:
        cp = runner.run(f"php {PROBE_REL} {shlex.quote(victim_schema)}",
                        timeout=300)
        raw = (cp.stdout or "").strip()
        out = _safe_probe_output(raw, worker, victim_schema)
    finally:
        import shutil
        shutil.rmtree(os.path.dirname(host_path), ignore_errors=True)
    return out


# ------------------------------------------------- per-execution reset probe
#
# `worker probe` answers "can this container reach a neighbour's data".  This
# answers the other half a mutation or test-quality pair depends on: "is what
# one pair execution wrote still there for the next one".  They are different
# questions and nothing else asks the second one -- `Harness._run_solution`
# does filesystem hygiene and restores generated production classes to their
# seed bytes, the schema reset itself is performed by the retained Behat hooks
# between scenarios, and no other code path checks that either happened.

#: The probe's own workspace, under `var/` for the reason `PROBE_REL` is:
#: `_bench` is a hashed substrate root and a stray file there aborts the next
#: item as tampering.  `var/` is outside the substrate roots, so the markers
#: below do not trip `verify_substrate`.
RESET_PROBE_DIR = "var/bench_reset_probe"
RESET_ADMIN_REL = f"{RESET_PROBE_DIR}/reset_admin.php"
RESET_REPORT_REL = {"a": f"{RESET_PROBE_DIR}/leg_a.json",
                    "b": f"{RESET_PROBE_DIR}/leg_b.json"}

#: Where CoreShop's marker context is installed: removable territory, so it is
#: written by `install_solution` and swept by `clean_workspace` exactly as a
#: candidate's context is.  That is the point -- the legs must travel the path
#: a pair travels, not a shortcut around it.  Which path that is belongs to
#: the project (`BehatProject.reset_context_rel`): writing THIS one into
#: another project puts the file outside that project's removable territory,
#: where `install_solution` refuses it and leg A has no step definitions.
RESET_CONTEXT_REL = CORESHOP_BEHAT.reset_context_rel

#: The slots the project's tables, its stub namespace and the program's own
#: vocabulary are rendered into.  No name here is a prefix of another, so the
#: substitutions cannot eat each other.
_RESET_MARKER_TABLE_SLOT = "R2T_MARKER_TABLE"
_RESET_CONTROL_TABLE_SLOT = "R2T_CONTROL_TABLE"
_RESET_CONTROL_COLUMN_SLOT = "R2T_CONTROL_COLUMN"
_RESET_BASELINE_TABLE_SLOT = "R2T_BASELINE_TABLE"
_RESET_BASELINE_FIELD_SLOT = "R2T_BASELINE_FIELD"
_RESET_NAMESPACE_SLOT = "R2T_STUB_NAMESPACE"

#: The PRODUCTION class leg A rewrites, under the `pimcore` program.  Not a
#: `Behat%` class, so no purge touches it; generated at seed time and
#: regenerated in place by any retained class save, which is how a mutant's
#: return-type change once reached every later pair on a worker.  The
#: harness's derived-state restore (`repo.DERIVED_STATE_ROOTS`) is what must
#: undo leg A's edit.
RESET_PRODUCTION_CLASS_REL = "var/classes/DataObject/CoreShopProduct.php"

#: What leg B must observe, per marker, under the `pimcore` program.
#:
#: `unpurged_row` is REQUIRED PRESENT and is the detector's own control, the
#: direct analogue of `own_schema_select` in `db_probe_php`.  The per-scenario
#: purges do not touch `versions` and the pruned seed leaves it empty, so a
#: probe reporting every marker absent has not demonstrated a reset -- it has
#: demonstrated that it is not observing anything, and that must fail rather
#: than read as the cleanest possible run.
#:
#: `rewritten_production_class` is leg A's nonce line appended to
#: `RESET_PRODUCTION_CLASS_REL`; leg B requires it gone, i.e. the seed's bytes
#: back.  A harness without the derived-state restore -- every harness before
#: mutation-evaluation-collection-v1.1 -- fails this marker, which is what
#: makes the probe the falsifier for that restore.  It is `pimcore`-only:
#: `doctrine` materialises no class definitions, so there is no such file to
#: rewrite and a marker there would be a name with nothing behind it.
_PIMCORE_EXPECTED_IN_LEG_B = {"purged_object": False,
                              "purged_class": False,
                              "rewritten_production_class": False,
                              "unpurged_row": True}

#: What leg B must observe under the `doctrine` program.
#:
#: Two markers, not three: `purged_class` has no analogue at all, because
#: Doctrine materialises no class definitions.  A third marker here would be
#: a name with nothing behind it, and a check that cannot fail is worse than
#: an absent one -- it reads as evidence.
_DOCTRINE_EXPECTED_IN_LEG_B = {"purged_row": False,
                               "unpurged_row": True}


def _reset_required_checks(expected: dict, baselines: tuple) -> tuple:
    """Every check that must be IN the document and satisfied.

    Absent is never a pass: a check that did not run is not a check that
    succeeded.  Derived from the program's markers and baselines rather than
    written out beside them, because the two lists are one list -- a marker
    with no `leg_b_` entry would be observed and never required, which is
    exactly the shape this function exists to make impossible.
    """
    return (("leg_a_ran",)
            + tuple(f"leg_a_{suffix}" for suffix, _ in baselines)
            + tuple(f"leg_a_read_back_{name}" for name in expected)
            + ("leg_b_ran",)
            + tuple(f"leg_b_{suffix}" for suffix, _ in baselines)
            + tuple(f"leg_b_{name}" for name in expected)
            + ("cleanup_unpurged_row_removed",))


def _pimcore_marker_names(nonce: str) -> dict:
    return {"object_key": f"r2t-reset-probe-{nonce}",
            "class_name": f"BehatR2tResetProbe{nonce}",
            "production_class_line": f"// r2t-reset-probe-class {nonce}",
            "version_note": f"r2t-reset-probe {nonce}"}


def _doctrine_marker_names(nonce: str) -> dict:
    return {"marker_code": f"R2T_RESET_PROBE_{nonce}",
            "control_version": f"R2T_CONTROL_{nonce}"}


def reset_marker_names(nonce: str, behat=None) -> dict:
    """The marker identities, derived once and used on both sides.

    A nonce per invocation rather than fixed names: markers left behind by an
    EARLIER failed probe would otherwise be read as this run's, and an
    operator could not tell a worker that fails today from one that failed
    last week.  The PHP builds the same strings from the same nonce, and the
    selftest pins that it still does.

    WHICH identities there are is the program's.  `pimcore` names an object
    key, a class name, the line leg A appends to the production class and a
    `versions` note; `doctrine` names the marker row's code and the migration
    version its control row is written under.  `behat=None` is CoreShop's
    four, unchanged.
    """
    return reset_program_for(behat).marker_names(nonce)


def reset_feature_text(nonce: str) -> str:
    """The synthesised two-scenario feature: leg A writes, leg B observes."""
    return (
        "Feature: r2t per-execution reset probe\n"
        "  Two scenarios, executed as two consecutive pair executions on one\n"
        "  worker with nothing between them.\n"
        "\n"
        "  Scenario: the probe writes its markers\n"
        f'    Given the reset probe writes its markers "{nonce}"\n'
        "\n"
        "  Scenario: the probe observes what survived\n"
        f'    Given the reset probe observes its markers "{nonce}"\n')


#: The `pimcore` program's marker context, installed exactly as a candidate's
#: context is.  Rendered by `reset_context_php`, never written as it stands.
#:
#: It never emits an exception MESSAGE.  The container holds the worker's own
#: DSN and a PDO/DBAL message can carry it -- the same trust boundary
#: `_safe_probe_output` exists for.  Only the exception CLASS crosses back,
#: and the Python side sanitises even that.
RESET_PROBE_CONTEXT_PHP = r"""<?php

declare(strict_types=1);

/*
 * GENERATED by r2t.bench.worker -- the per-execution schema-reset falsifier.
 *
 * Leg A writes four markers in four different scopes and reads them back in
 * the same scenario; that read-back is the control.  Leg B runs as the next
 * pair execution on the same worker and reports what survived.  What is under
 * test are the retained @BeforeScenario purges (the container runs with
 * CORESHOP_SKIP_DB_SETUP=1, so nothing else rebuilds the schema) and the
 * harness's own restore of generated production classes before each pair.
 */

namespace CoreShop\Behat\Context;

use Behat\Behat\Context\Context;
use Pimcore\Model\DataObject;
use Pimcore\Model\DataObject\ClassDefinition;

final class R2tResetProbeContext implements Context
{
    /**
     * @Given /^the reset probe writes its markers "([^"]+)"$/
     */
    public function writeMarkers($nonce): void
    {
        $nonce = (string) $nonce;
        $report = $this->baseline('A', $nonce);

        // purged_object -- one DataObject through Pimcore's own model API,
        // into the `objects` table the per-scenario purge is responsible for
        // clearing.  Not raw SQL: the purge deletes what the application
        // wrote, so the marker has to be written the way the application
        // writes.
        $report['wrote']['purged_object'] = $this->attempt(function () use ($nonce) {
            $folder = new DataObject\Folder();
            $folder->setKey($this->objectKey($nonce));
            $folder->setParentId(1);
            $folder->save();
        });

        // purged_class -- one materialised DataObject class definition in
        // var/classes, under a name no released item uses.  The name MUST
        // begin with `Behat`: PimcoreDaoContext::purgeClasses() selects
        // `name LIKE 'Behat%'`, so a differently named class would be outside
        // the reset's scope and its survival would prove nothing.
        $report['wrote']['purged_class'] = $this->attempt(function () use ($nonce) {
            $definition = new ClassDefinition();
            $definition->setName($this->className($nonce));
            $definition->setLayoutDefinitions(null);
            $definition->save();
        });

        // rewritten_production_class -- one line appended to a PRODUCTION
        // generated class, the file a retained class save regenerates in
        // place and no purge touches.  A trailing comment changes no
        // behaviour; the harness must put the seed's bytes back before leg B.
        $report['wrote']['rewritten_production_class'] = $this->attempt(function () use ($nonce) {
            $file = $this->productionClassFile();
            if (!is_file($file)) {
                throw new \RuntimeException('production class file missing');
            }
            if (false === file_put_contents(
                $file, "\n" . $this->productionClassLine($nonce) . "\n", FILE_APPEND
            )) {
                throw new \RuntimeException('production class file not writable');
            }
        });

        // unpurged_row -- the detector's own control.  Written by SQL on
        // purpose: its job is to survive, and going through the model would
        // make its survival depend on Pimcore's delete cascade rather than on
        // the purge policy this probe is measuring.
        $report['wrote']['unpurged_row'] = $this->attempt(function () use ($nonce) {
            $this->connection()->executeStatement(
                'INSERT INTO `R2T_CONTROL_TABLE` (`cid`, `ctype`, `note`, `date`, `storageType`)'
                . ' VALUES (NULL, ?, ?, ?, ?)',
                ['object', $this->versionNote($nonce), time(), 'db']
            );
        });

        $report = $this->observe($report, $nonce);
        $this->write($report, 'a');
    }

    /**
     * @Given /^the reset probe observes its markers "([^"]+)"$/
     */
    public function observeMarkers($nonce): void
    {
        $nonce = (string) $nonce;
        $report = $this->baseline('B', $nonce);
        $report = $this->observe($report, $nonce);
        $this->write($report, 'b');
    }

    private function observe(array $report, string $nonce): array
    {
        // Each marker reports whether its check RAN as well as what it saw.
        // An exception is the check not having run, not the state being gone.
        $report['markers']['purged_object'] = $this->look(function () use ($nonce) {
            return null !== DataObject::getByPath('/' . $this->objectKey($nonce));
        });
        $report['markers']['purged_class'] = $this->look(function () use ($nonce) {
            return is_file($this->classFile($nonce));
        });
        $report['markers']['rewritten_production_class'] = $this->look(function () use ($nonce) {
            $content = file_get_contents($this->productionClassFile());
            if (false === $content) {
                throw new \RuntimeException('production class file unreadable');
            }

            return false !== strpos($content, $this->productionClassLine($nonce));
        });
        $report['markers']['unpurged_row'] = $this->look(function () use ($nonce) {
            return 0 < (int) $this->connection()->fetchOne(
                'SELECT COUNT(*) FROM `R2T_CONTROL_TABLE` WHERE `note` = ?',
                [$this->versionNote($nonce)]
            );
        });
        return $report;
    }

    private function baseline(string $leg, string $nonce): array
    {
        $report = [
            'leg' => $leg,
            'nonce' => $nonce,
            'schema' => null,
            'baseline' => ['object_rows' => null, 'class_files' => null],
            'wrote' => [],
            'markers' => [],
        ];
        try {
            $connection = $this->connection();
            $report['schema'] = $connection->getDatabase();
            $report['baseline']['object_rows'] =
                (int) $connection->fetchOne('SELECT COUNT(*) FROM `R2T_MARKER_TABLE`');
        } catch (\Throwable $e) {
            $report['baseline']['error_class'] = get_class($e);
        }
        $directory = $this->classDirectory();
        if (is_dir($directory)) {
            $marker = basename($this->classFile($nonce));
            $count = 0;
            foreach ((array) glob($directory . '/definition_*.php') as $path) {
                if (basename((string) $path) !== $marker) {
                    ++$count;
                }
            }
            $report['baseline']['class_files'] = $count;
        }

        return $report;
    }

    private function attempt(callable $write): array
    {
        try {
            $write();

            return ['ok' => true, 'error_class' => null];
        } catch (\Throwable $e) {
            return ['ok' => false, 'error_class' => get_class($e)];
        }
    }

    private function look(callable $read): array
    {
        try {
            return ['ok' => true, 'present' => (bool) $read(),
                    'error_class' => null];
        } catch (\Throwable $e) {
            return ['ok' => false, 'present' => null,
                    'error_class' => get_class($e)];
        }
    }

    private function connection()
    {
        return \Pimcore::getContainer()->get('database_connection');
    }

    private function classDirectory(): string
    {
        return defined('PIMCORE_CLASS_DEFINITION_DIRECTORY')
            ? (string) PIMCORE_CLASS_DEFINITION_DIRECTORY
            : getcwd() . '/var/classes';
    }

    private function classFile(string $nonce): string
    {
        return $this->classDirectory() . '/definition_'
            . $this->className($nonce) . '.php';
    }

    private function productionClassFile(): string
    {
        return $this->classDirectory() . '/DataObject/CoreShopProduct.php';
    }

    private function productionClassLine(string $nonce): string
    {
        return '// r2t-reset-probe-class ' . $nonce;
    }

    private function objectKey(string $nonce): string
    {
        return 'r2t-reset-probe-' . $nonce;
    }

    private function className(string $nonce): string
    {
        return 'BehatR2tResetProbe' . $nonce;
    }

    private function versionNote(string $nonce): string
    {
        return 'r2t-reset-probe ' . $nonce;
    }

    private function write(array $report, string $leg): void
    {
        file_put_contents(
            getcwd() . '/var/bench_reset_probe/leg_' . $leg . '.json',
            json_encode($report)
        );
    }
}
"""

#: The `doctrine` program's marker context.  Same shape, same trust boundary,
#: a different purge underneath: `ORMPurger::purge()` empties every MAPPED
#: table, so the marker goes into one of those and the control goes into the
#: Doctrine Migrations version table, which is not a mapped entity and which
#: the purger therefore cannot reach.
#:
#: Behat 4 attributes rather than docblock annotations: `@Given` resolves to
#: nothing there, and a context whose steps do not bind leaves leg A passing
#: with no step executed -- an outcome the probe would read as a clean run.
RESET_DOCTRINE_CONTEXT_PHP = r"""<?php

declare(strict_types=1);

/*
 * GENERATED by r2t.bench.worker -- the per-execution schema-reset falsifier,
 * doctrine program.
 *
 * Leg A writes two markers in two different scopes and reads them back in the
 * same scenario; that read-back is the control.  Leg B runs as the next pair
 * execution on the same worker and reports what survived.  What is under test
 * is the retained per-scenario purge, which runs `ORMPurger::purge()` in a
 * #[BeforeScenario] hook: it empties every MAPPED table, so the marker row
 * must be gone, and it cannot see the migration version table, so the control
 * row must still be there.
 */

namespace R2T_STUB_NAMESPACE;

use Behat\Behat\Context\Context;
use Behat\Step\Given;
use Doctrine\DBAL\Connection;

final class R2tResetProbeContext implements Context
{
    public function __construct(private Connection $connection)
    {
    }

    #[Given('/^the reset probe writes its markers "([^"]+)"$/')]
    public function writeMarkers($nonce): void
    {
        $nonce = (string) $nonce;
        $report = $this->baseline('A', $nonce);

        // purged_row -- one row in a MAPPED table, which is what the purge
        // empties.  Written through the DBAL connection rather than through
        // the entity manager: its job is to be deleted, and going through
        // the ORM would make its survival depend on entity validation and
        // cascade configuration rather than on the purge policy this probe
        // is measuring.
        $report['wrote']['purged_row'] = $this->attempt(function () use ($nonce) {
            $this->insertMarker($this->markerCode($nonce));
        });

        // unpurged_row -- the detector's own control.  The migration version
        // table is not a mapped entity, so the purger cannot reach it; a leg
        // B that cannot see this row has not observed a purge, it has
        // observed nothing.
        $report['wrote']['unpurged_row'] = $this->attempt(function () use ($nonce) {
            $this->connection->executeStatement(
                'INSERT INTO `R2T_CONTROL_TABLE`'
                . ' (`R2T_CONTROL_COLUMN`, `executed_at`, `execution_time`)'
                . ' VALUES (?, ?, ?)',
                [$this->controlVersion($nonce), date('Y-m-d H:i:s'), 0]
            );
        });

        $report = $this->observe($report, $nonce);
        $this->write($report, 'a');
    }

    #[Given('/^the reset probe observes its markers "([^"]+)"$/')]
    public function observeMarkers($nonce): void
    {
        $nonce = (string) $nonce;
        $report = $this->baseline('B', $nonce);
        $report = $this->observe($report, $nonce);
        $this->write($report, 'b');
    }

    private function observe(array $report, string $nonce): array
    {
        // Each marker reports whether its check RAN as well as what it saw.
        // An exception is the check not having run, not the state being gone.
        $report['markers']['purged_row'] = $this->look(function () use ($nonce) {
            return 0 < (int) $this->connection->fetchOne(
                'SELECT COUNT(*) FROM `R2T_MARKER_TABLE` WHERE `code` = ?',
                [$this->markerCode($nonce)]
            );
        });
        $report['markers']['unpurged_row'] = $this->look(function () use ($nonce) {
            return 0 < (int) $this->connection->fetchOne(
                'SELECT COUNT(*) FROM `R2T_CONTROL_TABLE`'
                . ' WHERE `R2T_CONTROL_COLUMN` = ?',
                [$this->controlVersion($nonce)]
            );
        });

        return $report;
    }

    private function baseline(string $leg, string $nonce): array
    {
        $report = [
            'leg' => $leg,
            'nonce' => $nonce,
            'schema' => null,
            'baseline' => ['control_rows' => null],
            'wrote' => [],
            'markers' => [],
        ];
        try {
            $report['schema'] = $this->connection->getDatabase();
            $report['baseline']['control_rows'] = (int) $this->connection
                ->fetchOne('SELECT COUNT(*) FROM `R2T_CONTROL_TABLE`');
        } catch (\Throwable $e) {
            $report['baseline']['error_class'] = get_class($e);
        }

        return $report;
    }

    /**
     * The marker row: this run's nonce in `code`, and a minimal value for
     * every other column the table REQUIRES.
     *
     * The columns are read from the table rather than written out here,
     * because which table this is belongs to the project's boundary row and
     * not to this program.  Foreign keys are switched off around the insert
     * exactly as the retained purge hook switches them off around its
     * deletes: the hook has just emptied every mapped table, so the rows this
     * one would point AT are gone, and a marker that could not be written
     * would be reported as a broken worker rather than as a purge.
     */
    private function insertMarker(string $code): void
    {
        $values = ['code' => $code];
        $columns = $this->connection->fetchAllAssociative(
            'SELECT `COLUMN_NAME`, `DATA_TYPE`, `IS_NULLABLE`, `COLUMN_DEFAULT`,'
            . ' `EXTRA` FROM `information_schema`.`COLUMNS`'
            . ' WHERE `TABLE_SCHEMA` = DATABASE() AND `TABLE_NAME` = ?',
            ['R2T_MARKER_TABLE']
        );
        foreach ($columns as $column) {
            $name = (string) $column['COLUMN_NAME'];
            if (array_key_exists($name, $values)
                || 'NO' !== strtoupper((string) $column['IS_NULLABLE'])
                || null !== $column['COLUMN_DEFAULT']
                || str_contains(strtolower((string) $column['EXTRA']),
                                'auto_increment')) {
                continue;
            }
            $values[$name] = $this->placeholder(
                strtolower((string) $column['DATA_TYPE']), $code);
        }
        $names = array_keys($values);
        $sql = 'INSERT INTO `R2T_MARKER_TABLE` (`' . implode('`, `', $names)
            . '`) VALUES (' . implode(', ', array_fill(0, count($names), '?'))
            . ')';
        $this->connection->executeStatement('SET foreign_key_checks = 0');
        try {
            $this->connection->executeStatement($sql, array_values($values));
        } finally {
            $this->connection->executeStatement('SET foreign_key_checks = 1');
        }
    }

    private function placeholder(string $type, string $code)
    {
        if (in_array($type, ['tinyint', 'smallint', 'mediumint', 'int',
                             'integer', 'bigint', 'decimal', 'numeric',
                             'float', 'double', 'bit'], true)) {
            return 0;
        }
        if (in_array($type, ['datetime', 'timestamp'], true)) {
            return date('Y-m-d H:i:s');
        }
        if ('date' === $type) {
            return date('Y-m-d');
        }
        if ('time' === $type) {
            return date('H:i:s');
        }
        if ('year' === $type) {
            return date('Y');
        }
        if ('json' === $type) {
            return '{}';
        }

        return $code;
    }

    private function attempt(callable $write): array
    {
        try {
            $write();

            return ['ok' => true, 'error_class' => null];
        } catch (\Throwable $e) {
            return ['ok' => false, 'error_class' => get_class($e)];
        }
    }

    private function look(callable $read): array
    {
        try {
            return ['ok' => true, 'present' => (bool) $read(),
                    'error_class' => null];
        } catch (\Throwable $e) {
            return ['ok' => false, 'present' => null,
                    'error_class' => get_class($e)];
        }
    }

    private function markerCode(string $nonce): string
    {
        return 'R2T_RESET_PROBE_' . $nonce;
    }

    private function controlVersion(string $nonce): string
    {
        return 'R2T_CONTROL_' . $nonce;
    }

    private function write(array $report, string $leg): void
    {
        file_put_contents(
            getcwd() . '/var/bench_reset_probe/leg_' . $leg . '.json',
            json_encode($report)
        );
    }
}
"""

#: The coordinator's half: the seeded-baseline precheck and the removal of the
#: one durable marker.  One script with two modes, because it is one question
#: asked of one connection -- the worker's own DSN, read the way
#: `db_probe_php` reads it, from inside the worker container.  Rendered by
#: `reset_admin_php`, never written as it stands.
RESET_ADMIN_PHP = r"""<?php
// GENERATED by r2t.bench.worker -- the reset probe's baseline precheck and the
// removal of its one durable marker.  Runs inside a WORKER container with
// that worker's own DSN.  Emits no exception message: the DSN is in this
// process's environment.
$dsn = getenv('R2T_PROBE_DSN_ENV');
$mode = $argv[1] ?? '';
$note = $argv[2] ?? '';
$out = ['mode' => $mode, 'schema' => null, 'R2T_BASELINE_FIELD' => null,
        'deleted' => null, 'remaining' => null, 'error_class' => null];
if (!$dsn) { echo json_encode($out); exit(2); }
$p = parse_url($dsn);
$out['schema'] = ltrim($p['path'] ?? '', '/');
try {
    $c = new PDO(sprintf('mysql:host=%s;port=%s;dbname=%s',
                         $p['host'] ?? '', $p['port'] ?? 3306, $out['schema']),
                 $p['user'] ?? '', $p['pass'] ?? '',
                 [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    if ($mode === 'baseline') {
        $out['R2T_BASELINE_FIELD'] =
            (int) $c->query('SELECT COUNT(*) FROM `R2T_BASELINE_TABLE`')->fetchColumn();
    } elseif ($mode === 'cleanup') {
        $delete = $c->prepare('DELETE FROM `R2T_CONTROL_TABLE` WHERE `R2T_CONTROL_COLUMN` = ?');
        $delete->execute([$note]);
        $out['deleted'] = (int) $delete->rowCount();
        $left = $c->prepare('SELECT COUNT(*) FROM `R2T_CONTROL_TABLE` WHERE `R2T_CONTROL_COLUMN` = ?');
        $left->execute([$note]);
        $out['remaining'] = (int) $left->fetchColumn();
    }
} catch (Throwable $e) {
    $out['error_class'] = get_class($e);
}
echo json_encode($out);
"""


# The native dump hook restores every seeded table, so the durable observer
# control is a file in this container's private /tmp, outside that restore.
RESET_PRESTASHOP_CONTEXT_PHP = r"""<?php
declare(strict_types=1);
namespace R2T_STUB_NAMESPACE;

final class R2tResetProbeContext implements \Behat\Behat\Context\Context
{
    /** @Given /^the reset probe writes its markers "([^"]+)"$/ */
    public function writeMarkers($nonce): void
    {
        $report = $this->baseline('A', $nonce);
        $report['wrote']['restored_row'] = $this->attempt(function () use ($nonce) {
            $query = $this->connection()->prepare(
                'INSERT INTO `R2T_MARKER_TABLE` (`name`, `value`, `date_add`, `date_upd`)'
                . ' VALUES (?, ?, NOW(), NOW())');
            $query->execute(['R2T_RESET_PROBE_' . $nonce, 'probe']);
        });
        $report['wrote']['unpurged_file'] = $this->attempt(function () use ($nonce) {
            if (file_put_contents($this->controlPath($nonce), $nonce) === false) {
                throw new \RuntimeException('Cannot write reset control');
            }
        });
        $this->write($this->observe($report, $nonce), 'a');
    }

    /** @Given /^the reset probe observes its markers "([^"]+)"$/ */
    public function observeMarkers($nonce): void
    {
        $this->write($this->observe($this->baseline('B', $nonce), $nonce), 'b');
    }

    private function connection(): \PDO
    {
        return new \PDO('mysql:host=' . str_replace(':', ';port=', _DB_SERVER_)
            . ';dbname=' . _DB_NAME_, _DB_USER_, _DB_PASSWD_,
            [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
    }

    private function baseline(string $leg, string $nonce): array
    {
        $report = ['leg' => $leg, 'nonce' => $nonce, 'schema' => _DB_NAME_,
            'baseline' => ['configuration_rows' => null], 'wrote' => [], 'markers' => []];
        try {
            $report['baseline']['configuration_rows'] = (int) $this->connection()
                ->query('SELECT COUNT(*) FROM `R2T_MARKER_TABLE`')->fetchColumn();
        } catch (\Throwable $error) {
            $report['baseline']['error_class'] = get_class($error);
        }
        return $report;
    }

    private function observe(array $report, string $nonce): array
    {
        $report['markers']['restored_row'] = $this->look(function () use ($nonce) {
            $query = $this->connection()->prepare('SELECT COUNT(*) FROM `R2T_MARKER_TABLE` WHERE name = ?');
            $query->execute(['R2T_RESET_PROBE_' . $nonce]);
            return (int) $query->fetchColumn() > 0;
        });
        $report['markers']['unpurged_file'] = $this->look(function () use ($nonce) {
            return is_file($this->controlPath($nonce))
                && file_get_contents($this->controlPath($nonce)) === $nonce;
        });
        return $report;
    }

    private function controlPath(string $nonce): string
    {
        return sys_get_temp_dir() . '/r2t-reset-control-' . $nonce;
    }

    private function attempt(callable $write): array
    {
        try { $write(); return ['ok' => true, 'error_class' => null]; }
        catch (\Throwable $error) { return ['ok' => false, 'error_class' => get_class($error)]; }
    }

    private function look(callable $read): array
    {
        try { return ['ok' => true, 'present' => (bool) $read(), 'error_class' => null]; }
        catch (\Throwable $error) { return ['ok' => false, 'present' => null, 'error_class' => get_class($error)]; }
    }

    private function write(array $report, string $leg): void
    {
        file_put_contents(getcwd() . '/var/bench_reset_probe/leg_' . $leg . '.json', json_encode($report));
    }
}
"""

RESET_PRESTASHOP_ADMIN_PHP = r"""<?php
$mode = $argv[1] ?? '';
$note = $argv[2] ?? '';
$out = ['schema' => null, 'configuration_rows' => null, 'deleted' => null,
        'remaining' => null, 'error_class' => null];
try {
    $p = parse_url((string) getenv('R2T_PROBE_DSN_ENV'));
    $out['schema'] = rawurldecode(ltrim($p['path'] ?? '', '/'));
    $c = new PDO(sprintf('mysql:host=%s;port=%d;dbname=%s', $p['host'], $p['port'] ?? 3306, $out['schema']),
        rawurldecode($p['user']), rawurldecode($p['pass']), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    if ($mode === 'baseline') {
        $out['configuration_rows'] = (int) $c->query('SELECT COUNT(*) FROM `R2T_MARKER_TABLE`')->fetchColumn();
    } elseif ($mode === 'cleanup') {
        if (!preg_match('/^r2t-reset-control-[a-zA-Z0-9]+$/D', $note)) {
            throw new RuntimeException('Invalid reset control');
        }
        $path = sys_get_temp_dir() . '/' . $note;
        $out['deleted'] = is_file($path) ? (int) unlink($path) : 0;
        $out['remaining'] = (int) is_file($path);
    }
} catch (Throwable $error) { $out['error_class'] = get_class($error); }
echo json_encode($out);
"""


@dataclass(frozen=True)
class ResetProgram:
    """One stack's answer to "what does a per-scenario purge do here?".

    A PROGRAM rather than a table of names, because the question differs in
    kind and not only in vocabulary.  Pimcore's purge deletes DataObjects
    through the model and unlinks materialised class definitions from
    `var/classes`; Doctrine's `ORMPurger` empties every mapped table and
    knows nothing about files.  A probe that renamed Pimcore's three markers
    into Doctrine's world would report `purged_class` over a directory that
    does not exist -- a check that can only ever be absent, which
    `reset_report` would then have to be taught to forgive, which is how a
    falsifier stops falsifying.

    So the marker context's body, the admin SQL, the marker identities, what
    leg B must observe and which baselines mean "this leg reached a populated
    worker" are all the program's.  Everything OUTSIDE the program -- the two
    legs, the nonce, the leg-A read-back control, the ordering of failure
    classes in `reset_report` -- is shared, and is what makes the two
    programs the same acceptance.
    """

    name: str
    #: The marker context, before the project's tables are rendered in.
    context_template: str
    #: marker name -> what leg B must observe.  A marker expected PRESENT is
    #: a control; a marker expected ABSENT is the reset itself.
    expected_in_leg_b: dict
    #: (check suffix, the field the marker context reports it under).  Each
    #: one becomes `leg_a_<suffix>`/`leg_b_<suffix>` and must be > 0: a leg
    #: measured against an empty table cannot tell an absence from data that
    #: was never there.
    baselines: tuple
    #: (nonce) -> the marker identities both sides derive.
    marker_names: Callable
    #: Which of those identities the admin cleanup removes -- the one marker
    #: that is durable by construction, because the purge cannot reach it.
    durable_marker: str
    #: The row field naming the table the admin baseline counts, and the JSON
    #: key it counts into.
    baseline_table_field: str
    admin_baseline_field: str
    #: The column the durable marker is identified by in the control table.
    control_column: str
    #: True when the leg-B reachability baseline reads the SAME table as the
    #: unpurged control, so the two are one fact and not two.  Under
    #: `pimcore` they are independent (`objects` is purged, `versions` is
    #: not); under `doctrine` every mapped table is empty after the purge, so
    #: the only table that can carry a baseline IS the control.  Reported, not
    #: hidden: it is a real weakening of the leg-B reachability evidence.
    baseline_is_the_control: bool
    #: Whether the program's markers include a materialised class definition
    #: on disk, and so whether `reset_probe` requires the seeded `var/classes`
    #: before it starts.  Outside Pimcore there is nothing there to observe,
    #: and the precondition is ABSENT rather than pointed at some other
    #: directory that happens to exist.
    seeded_class_definitions: bool
    admin_template: str = RESET_ADMIN_PHP
    control_marker: str = "unpurged_row"
    feature_path: Optional[str] = None
    feature_tags: tuple = ()

    @property
    def required_checks(self) -> tuple:
        return _reset_required_checks(self.expected_in_leg_b, self.baselines)

    def context_php(self, behat: BehatProject) -> str:
        return _render_reset_php(self.context_template, behat, self)

    def admin_php(self, behat: BehatProject) -> str:
        return _render_reset_php(self.admin_template, behat, self)


def _render_reset_php(template: str, behat: BehatProject,
                      program: "ResetProgram") -> str:
    """The one substitution table, so the two halves cannot disagree.

    The context and the admin script read and write the same rows of the same
    two tables; rendering them from one table is what keeps leg B looking
    where leg A wrote.
    """
    return (template
            .replace(_RESET_NAMESPACE_SLOT, behat.stub_namespace)
            .replace(_RESET_MARKER_TABLE_SLOT, behat.reset_marker_table)
            .replace(_RESET_BASELINE_TABLE_SLOT,
                     getattr(behat, program.baseline_table_field))
            .replace(_RESET_BASELINE_FIELD_SLOT, program.admin_baseline_field)
            .replace(_RESET_CONTROL_TABLE_SLOT, behat.reset_control_table)
            .replace(_RESET_CONTROL_COLUMN_SLOT, program.control_column)
            .replace(_DSN_ENV_SLOT, behat.db_dsn_env))


RESET_PROGRAMS = {
    "prestashop": ResetProgram(
        name="prestashop", context_template=RESET_PRESTASHOP_CONTEXT_PHP,
        expected_in_leg_b={"restored_row": False, "unpurged_file": True},
        baselines=(("configuration_baseline", "configuration_rows"),),
        marker_names=lambda nonce: {"marker_name": f"R2T_RESET_PROBE_{nonce}",
                                    "control_file": f"r2t-reset-control-{nonce}"},
        durable_marker="control_file", baseline_table_field="reset_marker_table",
        admin_baseline_field="configuration_rows", control_column="name",
        baseline_is_the_control=False, seeded_class_definitions=False,
        admin_template=RESET_PRESTASHOP_ADMIN_PHP, control_marker="unpurged_file",
        feature_path="tests/Integration/Behaviour/Features/Scenario/CmsPage/r2t_reset_probe.feature",
        feature_tags=("@restore-all-tables-before-feature",)),
    "pimcore": ResetProgram(
        name="pimcore",
        context_template=RESET_PROBE_CONTEXT_PHP,
        expected_in_leg_b=_PIMCORE_EXPECTED_IN_LEG_B,
        baselines=(("object_baseline", "object_rows"),
                   ("class_baseline", "class_files")),
        marker_names=_pimcore_marker_names,
        durable_marker="version_note",
        baseline_table_field="reset_marker_table",
        admin_baseline_field="object_rows",
        control_column="note",
        baseline_is_the_control=False,
        seeded_class_definitions=True),
    "doctrine": ResetProgram(
        name="doctrine",
        context_template=RESET_DOCTRINE_CONTEXT_PHP,
        expected_in_leg_b=_DOCTRINE_EXPECTED_IN_LEG_B,
        baselines=(("control_baseline", "control_rows"),),
        marker_names=_doctrine_marker_names,
        durable_marker="control_version",
        baseline_table_field="reset_control_table",
        admin_baseline_field="control_rows",
        control_column="version",
        baseline_is_the_control=True,
        seeded_class_definitions=False),
}

#: CoreShop's program, and therefore what these two module names have always
#: meant.  Kept as names because they say, at the top of the file, which
#: verdict a `worker reset-probe` with no project row returns.
RESET_EXPECTED_IN_LEG_B = RESET_PROGRAMS["pimcore"].expected_in_leg_b
RESET_REQUIRED_CHECKS = RESET_PROGRAMS["pimcore"].required_checks


def reset_program_for(behat=None) -> ResetProgram:
    """The reset program this project's boundary names.

    CLOSED, and refused rather than defaulted: a boundary that misspells the
    program would otherwise run Pimcore's markers against another stack,
    fail on every one of them, and report a broken reset where there is a
    typo.  `behat=None` is CoreShop's `pimcore`.
    """
    row = behat or CORESHOP_BEHAT
    program = RESET_PROGRAMS.get(row.reset_program)
    if program is None:
        raise WorkerRefused(
            f"REFUSED: `reset_program: {row.reset_program!r}` is not a reset "
            f"program. The known ones are {sorted(RESET_PROGRAMS)}; running "
            f"another project's program would write markers this stack has no "
            f"purge for and report their absence as a reset.")
    return program


def reset_context_php(behat=None) -> str:
    """The marker context to install, for THIS project's program."""
    behat = behat or CORESHOP_BEHAT
    return reset_program_for(behat).context_php(behat)


def reset_admin_php(behat=None) -> str:
    """The coordinator's baseline/cleanup script, for the same program."""
    behat = behat or CORESHOP_BEHAT
    return reset_program_for(behat).admin_php(behat)


#: An exception class name is fixed PHP vocabulary rather than a message, so it
#: is the one piece of container-side text allowed across.  Bounded anyway:
#: nothing from inside a worker becomes a key, a name, or unbounded output.
_RESET_CLASS_NAME = re.compile(r"[A-Za-z0-9_\\]{1,80}")


def _reset_error_class(value) -> Optional[str]:
    if not isinstance(value, str):
        return None
    match = _RESET_CLASS_NAME.match(value)
    return match.group(0) if match else None


def _reset_int(value) -> Optional[int]:
    return value if isinstance(value, int) \
        and not isinstance(value, bool) else None


def _reset_marker(entry, expected: bool) -> dict:
    """One marker's observation, reduced to booleans and a class name."""
    entry = entry if isinstance(entry, dict) else {}
    present = entry.get("present")
    return {"ran": entry.get("ok") is True,
            "present": present if isinstance(present, bool) else None,
            "expected_present": expected,
            "error_class": _reset_error_class(entry.get("error_class"))}


def reset_report(doc: dict, behat=None) -> dict:
    """Turn the two legs into a verdict, and refuse the vacuous pass.

    The order is `probe_report`'s order, for `probe_report`'s reason.  The
    leg-A control is read first: a worker that could not write a marker, or
    could not see the marker it had just written, is a broken worker, and
    every absence reported after that is an artefact of the breakage rather
    than evidence of a reset.

    Then the leg-B reachability controls, then the markers.  `unpurged_row`
    absent outranks `purged_object` present, because a probe that observes
    nothing has made no measurement at all, and reporting the more dramatic
    finding would describe a boundary nobody tested.

    Cleanup is a pass condition rather than an exception so that every
    worker's verdict still reaches the operator: a stray durable marker is a
    reason to reprovision one worker, and hiding the rest of the pool's
    results behind it helps nobody.

    WHICH markers and baselines there are is the program's (`behat=None` is
    CoreShop's three markers and two baselines).  The arithmetic above is
    not: every program's document is read by this one function, so a program
    cannot arrive with a verdict rule of its own.
    """
    program = reset_program_for(behat)
    leg_a = doc.get("leg_a") if isinstance(doc.get("leg_a"), dict) else {}
    leg_b = doc.get("leg_b") if isinstance(doc.get("leg_b"), dict) else {}
    cleanup = doc.get("cleanup") if isinstance(doc.get("cleanup"), dict) else {}
    report_a = leg_a.get("report") if isinstance(
        leg_a.get("report"), dict) else None
    report_b = leg_b.get("report") if isinstance(
        leg_b.get("report"), dict) else None

    def markers_of(report, expected_map):
        seen = (report or {}).get("markers")
        seen = seen if isinstance(seen, dict) else {}
        return {name: _reset_marker(seen.get(name), expected)
                for name, expected in expected_map.items()}

    def baseline_of(report):
        seen = (report or {}).get("baseline")
        seen = seen if isinstance(seen, dict) else {}
        return {field: _reset_int(seen.get(field))
                for _, field in program.baselines}

    # Leg A read back its OWN markers, so every one of them must be present.
    expected_in_leg_b = program.expected_in_leg_b
    read_back = markers_of(report_a,
                           {name: True for name in expected_in_leg_b})
    observed = markers_of(report_b, expected_in_leg_b)
    baseline_a, baseline_b = baseline_of(report_a), baseline_of(report_b)
    wrote = (report_a or {}).get("wrote")
    wrote = wrote if isinstance(wrote, dict) else {}

    present, satisfied = {}, {}

    def record(name, is_present, is_satisfied):
        present[name] = bool(is_present)
        satisfied[name] = bool(is_present) and bool(is_satisfied)

    record("leg_a_ran", report_a is not None,
           leg_a.get("outcome") == "passed")
    record("leg_b_ran", report_b is not None,
           leg_b.get("outcome") == "passed")
    for leg, base in (("leg_a", baseline_a), ("leg_b", baseline_b)):
        for suffix, field in program.baselines:
            record(f"{leg}_{suffix}", base[field] is not None,
                   (base[field] or 0) > 0)
    for name, entry in read_back.items():
        record(f"leg_a_read_back_{name}", entry["present"] is not None,
               entry["ran"] and entry["present"] is True)
    for name, entry in observed.items():
        record(f"leg_b_{name}", entry["present"] is not None,
               entry["ran"] and entry["present"] is entry["expected_present"])
    record("cleanup_unpurged_row_removed",
           _reset_int(cleanup.get("remaining")) is not None,
           _reset_int(cleanup.get("remaining")) == 0)

    missing = [name for name in program.required_checks if not present[name]]
    failed_writes = sorted(
        name for name in expected_in_leg_b
        if not (isinstance(wrote.get(name), dict)
                and wrote[name].get("ok") is True))
    control = [name for name in ("leg_a_ran", *(f"leg_a_read_back_{n}"
                                                for n in read_back))
               if not satisfied[name]]
    unreachable = [name for name in
                   ("leg_b_ran", *(f"leg_b_{suffix}"
                                   for suffix, _ in program.baselines))
                   if not satisfied[name]]
    blind = observed[program.control_marker]["present"] is not True
    crossed = sorted(name for name, entry in observed.items()
                     if entry["expected_present"] is False
                     and entry["present"] is True)

    if control or failed_writes:
        failure_class = "leg_a_control_failed"
        why = ("leg A could not write its markers, or could not see what it "
               "wrote, so nothing after it is evidence")
    elif missing:
        failure_class = "checks_not_run"
        why = ("required checks did not run, and a check that did not run is "
               "not a check that succeeded")
    elif unreachable:
        failure_class = "leg_b_unreachable_baseline"
        why = ("leg B did not reach a populated worker, so an absent marker "
               "is indistinguishable from state that was never there")
    elif blind:
        failure_class = "probe_observed_nothing"
        why = ("the control marker the purges do not touch is absent too, so "
               "the probe demonstrated only that it is not observing "
               "anything")
    elif crossed:
        failure_class = "state_crossed_the_pair_boundary"
        why = "state written by one pair execution was visible to the next"
    elif not satisfied["cleanup_unpurged_row_removed"]:
        failure_class = "cleanup_left_marker"
        why = ("the probe could not remove its own durable marker. This "
               "worker must be reprovisioned.")
    else:
        failure_class, why = None, None

    return {
        "pass": failure_class is None,
        "failure_class": failure_class,
        "why": why,
        "program": program.name,
        # Under `doctrine` the leg-B reachability baseline and the unpurged
        # control are the same table, because the purge empties every mapped
        # one: there is no table that both survives the purge and is
        # independent of the control.  That is weaker evidence than
        # `pimcore`'s two independent facts, so it is stated in the verdict
        # rather than left for a reader to work out from the check names.
        "baseline_is_the_control": program.baseline_is_the_control,
        "worker": _reset_int(doc.get("worker")),
        "own_schema": doc.get("own_schema"),
        "nonce": doc.get("nonce"),
        "markers": doc.get("markers"),
        "checks_not_run": missing,
        "failed_writes": failed_writes,
        "markers_visible_in_leg_b": crossed,
        "leg_a": {"outcome": leg_a.get("outcome"), "baseline": baseline_a,
                  "read_back": read_back},
        "leg_b": {"outcome": leg_b.get("outcome"), "baseline": baseline_b,
                  "observed": observed},
        "cleanup": {"deleted": _reset_int(cleanup.get("deleted")),
                    "remaining": _reset_int(cleanup.get("remaining"))},
    }


def _reset_admin(worker: WorkerSpec, runner, mode: str,
                 note: str = "", *, behat=None) -> Optional[dict]:
    """One `reset_admin.php` round trip.  `None` when it said nothing usable.

    It never raises.  The precheck caller turns `None` into its own refusal;
    the cleanup caller runs in a `finally`, where raising would replace a
    substrate-tampering abort with a parsing complaint and lose the reason the
    campaign has to stop.  An unusable cleanup result leaves `remaining`
    absent, which `reset_report` reports as a check that did not run.

    `baseline_rows` is the program's own count under one name, because what
    the coordinator needs from it is the same either way: whether there is
    anything here for a later absence to be measured against.
    """
    behat = behat or CORESHOP_BEHAT
    program = reset_program_for(behat)
    host_path = os.path.join(worker.workspace, RESET_ADMIN_REL)
    os.makedirs(os.path.dirname(host_path), exist_ok=True)
    with open(host_path, "w", encoding="utf-8") as fh:
        fh.write(program.admin_php(behat))
    cp = runner.run(f"php {RESET_ADMIN_REL} {shlex.quote(mode)} "
                    f"{shlex.quote(note)}", timeout=300)
    raw = (cp.stdout or "")
    start = raw.find("{")
    if start < 0:
        return None
    try:
        doc = json.loads(raw[start:])
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("schema") != worker.schema:
        return None
    return {"baseline_rows": _reset_int(doc.get(program.admin_baseline_field)),
            "deleted": _reset_int(doc.get("deleted")),
            "remaining": _reset_int(doc.get("remaining")),
            "error_class": _reset_error_class(doc.get("error_class"))}


def _reset_leg(harness, feature, scenario, solution, worker: WorkerSpec,
               leg: str, timeout: int) -> dict:
    """One pair execution, plus the report the marker context left behind."""
    host_report = os.path.join(worker.workspace, RESET_REPORT_REL[leg])
    if os.path.exists(host_report):
        os.remove(host_report)
    result = harness.run_solution(feature, scenario, solution,
                                  coverage=False, timeout=timeout)
    outcomes = result.get("outcomes") or []
    outcome = outcomes[0] if outcomes else "no_scenario_ran"
    # The same relabelling `mutation_run._record` performs: a leg that changed
    # retained source is not a leg that passed, whatever its steps reported.
    if result.get("substrate_violation"):
        outcome = "substrate_violation"
    out = {"outcome": outcome, "report": None}
    if os.path.isfile(host_report):
        try:
            with open(host_report, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError, ValueError):
            doc = None
        if isinstance(doc, dict):
            out["report"] = doc
    return out


def reset_probe(worker: WorkerSpec, harness, docker_group: bool = True,
                timeout: int = 600, nonce: Optional[str] = None,
                behat=None) -> dict:
    """Demonstrate, from inside the worker, that a pair execution is reset.

    Two consecutive `Harness.run_solution` calls on one worker with nothing
    between them -- no reprovision, no container restart, no manual purge, no
    `worker probe` -- because the reset is a property of the EXECUTION path:
    it is performed by the retained Behat hooks between scenarios, and only a
    real execution can observe whether it happened.  The command performs both
    legs itself so that an operator cannot insert a step between them by
    accident.

    Refused before anything executes for a worker with no database, and for a
    worker whose schema does not hold the seeded baseline: an unseeded or
    already-drained worker yields an absence that proves nothing.  That is the
    refusal `probe_database` makes for a worker with no database and the one
    `worker probe --sentinel-schema` makes for an empty schema.

    WHICH markers are written, where the context is installed and what the
    baseline is come from the project's row, which is read off the HARNESS
    rather than taken as a second argument: the harness is the object that
    resolved the boundary, and it is already required (below) to be this
    worker's.  A row from anywhere else could disagree with the boundary the
    legs are actually stripped and installed under.
    """
    from ..core.gherkin import parse_feature_file
    from .harness import Solution, SourceFile
    from .repo import clean_workspace

    behat = behat or getattr(harness, "behat", None) or CORESHOP_BEHAT
    program = reset_program_for(behat)
    if not worker.schema or not worker.credential:
        raise WorkerRefused(
            f"REFUSED: worker {worker.index} has no schema and no principal, "
            f"so there is no per-execution state to reset. A pass here would "
            f"assert something the configuration cannot make false.")
    # H1, at the one boundary that can still get it wrong: the caller builds
    # the harness from a worker record, and a harness pointed at another
    # worker's workspace would write leg A into one container and read leg B
    # out of another -- every path involved exists in both.
    if os.path.abspath(harness.root) != os.path.abspath(worker.workspace):
        raise WorkerRefused(
            f"REFUSED: the harness writes into {harness.root} while worker "
            f"{worker.index}'s workspace is {worker.workspace}; the two legs "
            f"would not run on one worker.")

    nonce = nonce or hashlib.sha256(
        f"{worker.index}\0{worker.schema}\0{time.time_ns()}".encode("utf-8")
    ).hexdigest()[:12]
    markers = program.marker_names(nonce)
    runner = worker.runner(docker_group=docker_group)

    baseline = _reset_admin(worker, runner, "baseline", behat=behat)
    if baseline is None:
        raise WorkerRefused(
            f"REFUSED: worker {worker.index} did not answer the reset "
            f"baseline query with its own schema {worker.schema}; the live "
            f"container is bound to another database identity or to none.")
    baseline_table = getattr(behat, program.baseline_table_field)
    if (baseline["baseline_rows"] or 0) < 1:
        raise WorkerRefused(
            f"REFUSED: worker {worker.index}'s schema holds no rows in "
            f"`{baseline_table}`, so a marker's absence after the next "
            f"scenario would be indistinguishable from data that was never "
            f"there. Provision and seed the pool before probing it.")
    if program.seeded_class_definitions:
        class_dir = os.path.join(worker.workspace, "var", "classes")
        if not os.path.isdir(class_dir) or not [
                name for name in os.listdir(class_dir)
                if name.startswith("definition_") and name.endswith(".php")] \
                or not os.path.isfile(os.path.join(worker.workspace,
                                                   RESET_PRODUCTION_CLASS_REL)):
            raise WorkerRefused(
                f"REFUSED: worker {worker.index} has no materialised "
                f"DataObject class definitions (or no "
                f"{RESET_PRODUCTION_CLASS_REL}), so the var/classes half of "
                f"the reset cannot be observed. Provision and seed the pool "
                f"before probing it.")

    feature_path = (os.path.join(harness.root, program.feature_path)
                    if program.feature_path else "<r2t reset probe>")
    feature_text = reset_feature_text(nonce)
    if program.feature_tags:
        feature_text = " ".join(program.feature_tags) + "\n" + feature_text
    feature = parse_feature_file(feature_path, text=feature_text)
    if len(feature.scenarios) != 2:
        raise WorkerRefused(
            "REFUSED: the synthesised reset feature did not parse into two "
            "scenarios, so the probe would measure one execution and not a "
            "pair.")
    solution = Solution(files=[
        SourceFile(file_path=behat.reset_context_rel,
                   code=program.context_php(behat))])
    os.makedirs(os.path.join(worker.workspace, RESET_PROBE_DIR), exist_ok=True)

    doc = {"worker": worker.index, "own_schema": worker.schema,
           "nonce": nonce, "markers": markers}
    try:
        doc["leg_a"] = _reset_leg(harness, feature, feature.scenarios[0],
                                  solution, worker, "a", timeout)
        doc["leg_b"] = _reset_leg(harness, feature, feature.scenarios[1],
                                  solution, worker, "b", timeout)
    finally:
        # The durable marker is durable by construction, so it is removed and
        # re-read whatever happened above -- including the paths where a leg
        # never ran, which are exactly the paths that would otherwise carry a
        # stray row into a later campaign.
        doc["cleanup"] = _reset_admin(
            worker, runner, "cleanup",
            markers[program.durable_marker], behat=behat) or {}
        import shutil
        shutil.rmtree(os.path.join(worker.workspace, RESET_PROBE_DIR),
                      ignore_errors=True)
        clean_workspace(harness.man, harness.boundary)
        harness.clear_registration()
    for leg in ("leg_a", "leg_b"):
        schema = ((doc.get(leg) or {}).get("report") or {}).get("schema")
        if schema is not None and schema != worker.schema:
            raise WorkerRefused(
                f"REFUSED: worker {worker.index}'s {leg} executed against a "
                f"schema that does not belong to it; the live container is "
                f"bound to another database identity.")
    return reset_report(doc, behat)


def harden_database(workers: list[WorkerSpec], db: MySQL) -> dict:
    """Remove `root@%` — but only once the workers can live without it.

    The order is the whole point.  Dropping the wildcard admin first would
    break every worker at once and leave no way to tell an isolation success
    from a broken container.  So each worker's own principal is verified to
    exist and to be scoped to its own schema, and only then is the account
    that made schema separation meaningless taken away.
    """
    # Same rule as the probe: a stack with no database has no `root@%` to take
    # away, and removing it "successfully" would record a hardening step that
    # narrowed nothing for the workers it names.
    dbless = [w.index for w in workers if not w.credential]
    if dbless:
        raise WorkerRefused(
            f"REFUSED: workers {dbless} have no database principal, so there "
            f"is nothing to harden. Dropping root@% on their behalf would "
            f"record an isolation step that did not apply to them.")
    have = {u for u, h in db.principals()}
    missing = [w.credential for w in workers if w.credential not in have]
    if missing:
        raise DatabaseRefused(
            f"REFUSED: {missing} do not exist yet. Removing root@% now would "
            f"leave those workers with no way to reach their own schema.")
    for w in workers:
        grants = [r[0] for r in db.query(f"SHOW GRANTS FOR '{w.credential}'@'%';")]
        wide = [g for g in grants if "ON *.*" in g and "USAGE" not in g]
        if wide:
            raise DatabaseRefused(
                f"REFUSED: {w.credential} holds a server-wide grant {wide}, so "
                f"removing root@% would not narrow anything.")
        if not any(f"`{w.schema}`" in g for g in grants):
            raise DatabaseRefused(
                f"REFUSED: {w.credential} has no grant on {w.schema}.")
        # The check that was missing, and that cost a whole K=4 sweep.
        #
        # Pimcore materialises one `object_<class>` VIEW per DataObject class,
        # and `mysqldump` writes them out as
        # ``DEFINER=`root`@`%` SQL SECURITY DEFINER``.  Dropping `root@%` then
        # breaks every query through them — all 100 items came back
        # `no_scenario_ran`, which reads exactly like the system under test
        # failing.  The error message names the *querying* account, so nothing
        # points at the definer.  `seed.build_seed` now rewrites the dump to
        # `SQL SECURITY INVOKER`; this refuses to harden a schema where that
        # did not happen, rather than discovering it a sweep later.
        # Scoped to the account actually being removed.  Stripping the dump's
        # DEFINER clauses makes MySQL record whoever LOADED the schema —
        # `root@localhost`, which survives — so a guard that refused any
        # root-ish definer would refuse the very state that fixes the problem.
        owned = db.definer_accounts(w.schema)
        stale = {acct: objs for acct, objs in owned.items()
                 if acct.replace("`", "") == "root@%"}
        if stale:
            examples = sorted(v for objs in stale.values() for v in objs)[:4]
            raise DatabaseRefused(
                f"REFUSED: {w.schema} holds {sum(len(v) for v in stale.values())} "
                f"object(s) whose DEFINER is {sorted(stale)}, e.g. {examples}. "
                f"Removing root@% would break every query through them and the "
                f"failure would be charged to the system under test. Rebuild "
                f"the seed — `seed build` rewrites the dump to SQL SECURITY "
                f"INVOKER — and re-provision.")
    return db.remove_wildcard_root()


#: Sentinel for the reset-verdict fixtures below: "remove this key", which is
#: a different document from "this key is false".
_DROP = object()


def selftest() -> int:
    """Everything that needs neither Docker nor MySQL: the derivation of
    worker identities, saved lifecycle dispatch, preflight arithmetic, and
    the credential file."""
    import contextlib
    import io
    import stat
    import tempfile
    from unittest.mock import patch

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    def refused(fn):
        try:
            fn()
            return False
        except (WorkerRefused, DatabaseRefused):
            return True

    def cli_refused(fn):
        try:
            fn()
            return False
        except SystemExit as exc:
            return str(exc).startswith("REFUSED:")

    #: A second Behat project's row, in the one respect every live check
    #: reads: which environment variable its workers' DSN is in, and that
    #: Pimcore's four install variables are not beside it.
    sylius_pool_row = BehatProject(
        db_dsn_env="DATABASE_URL", db_dsn_suffix="?charset=utf8mb4",
        db_install_vars=False)

    with tempfile.TemporaryDirectory() as root:
        cache = os.path.join(root, "composer-cache")
        os.makedirs(cache)
        check("portable workers never guess a Composer cache and no-database "
              "workers mount none",
              refused(lambda: composer_mounts(
                  required=True, environ={}))
              and composer_mounts(required=False, environ={}) == ())
        check("an explicit canonical Composer cache is mounted read-only",
              composer_mounts(required=True, explicit=cache, environ={})
              == ((cache, "/composer-cache:ro"),))
        cache_link = os.path.join(root, "composer-cache-link")
        os.symlink(cache, cache_link)
        check("a symlink Composer cache refuses before Docker",
              refused(lambda: composer_mounts(
                  required=True, explicit=cache_link, environ={})))
        # The caller ordering is part of that contract too: a pure resolver
        # is insufficient if the CLI probes the authority first.
        from types import SimpleNamespace
        from .. import cli as _cli
        from . import cli as bench_cli
        from ..toolkit import cli as toolkit_cli
        from ..core import docker_cli as _docker_cli
        from ..data import release as _release
        from . import worker as _worker_api
        import threading
        from concurrent.futures import wait as real_wait

        parallel_workers = [SimpleNamespace(index=i) for i in range(6)]
        provision_barrier = threading.Barrier(2)
        concurrency_lock = threading.Lock()
        active = peak = 0

        def concurrent_provision(worker):
            nonlocal active, peak
            with concurrency_lock:
                active += 1
                peak = max(peak, active)
            try:
                provision_barrier.wait(timeout=5)
                return worker.index
            finally:
                with concurrency_lock:
                    active -= 1

        completed = list(bench_cli._provision_workers(
            parallel_workers, concurrent_provision, jobs=2))
        check("parallel provision uses the requested bound and returns every worker",
              peak == 2 and active == 0
              and sorted((worker.index, value) for worker, value in completed)
              == [(i, i) for i in range(6)])
        check("nonpositive provisioning concurrency refuses before dispatch",
              cli_refused(lambda: list(bench_cli._provision_workers(
                  parallel_workers, concurrent_provision, jobs=0))))

        survivor_started = threading.Event()
        allow_survivor_to_finish = threading.Event()
        survivor_finished = threading.Event()
        started = []

        def failed_provision(worker):
            started.append(worker.index)
            if worker.index == 0:
                if not survivor_started.wait(timeout=5):
                    raise AssertionError("second concurrent worker never started")
                raise WorkerRefused("fixture provisioning failure")
            survivor_started.set()
            if not allow_survivor_to_finish.wait(timeout=5):
                raise AssertionError("controller did not observe the failed worker")
            survivor_finished.set()
            return worker.index

        def observe_failed_worker(futures, **kwargs):
            done, pending = real_wait(futures, **kwargs)
            if any(future.exception() is not None for future in done):
                allow_survivor_to_finish.set()
            return done, pending

        with patch("concurrent.futures.wait", side_effect=observe_failed_worker):
            provision_failed = refused(lambda: list(bench_cli._provision_workers(
                parallel_workers, failed_provision, jobs=2)))
        check("failed provisioning stops refill and waits for every started worker",
              provision_failed and sorted(started) == [0, 1]
              and survivor_finished.is_set())
        real_worker_docker = globals()["_docker"]
        absence_calls = []

        def absence_projection(rows: str, returncode: int = 0):
            def invoke(argv, **_kwargs):
                absence_calls.append(tuple(argv))
                return SimpleNamespace(
                    returncode=returncode, stdout=rows, stderr="")
            return invoke

        absent_passed = False
        occupied_refused = False
        try:
            globals()["_docker"] = absence_projection("")
            require_container_absent("fixture_worker")
            absent_passed = True
            globals()["_docker"] = absence_projection(
                "a" * 64 + "|fixture_worker\n")
            occupied_refused = refused(
                lambda: require_container_absent("fixture_worker"))
        finally:
            globals()["_docker"] = real_worker_docker
        check("fresh provision proves the planned name absent and never "
              "uses an implicit rm sidecar",
              absent_passed and occupied_refused
              and all(call[:2] == ("container", "ls")
                      for call in absence_calls))
        harness_calls = []
        admission_calls = []
        admission_dir = os.path.join(root, "cli-admission")
        os.makedirs(admission_dir)
        with open(os.path.join(admission_dir, "closures.json"),
                  "w", encoding="utf-8") as fh:
            json.dump([], fh)
        real_harness = bench_cli._harness
        real_boundary = bench_cli._boundary
        real_admit = _release.admit_pre_execution
        bench_cli._harness = lambda _args: harness_calls.append(True)
        bench_cli._boundary = lambda _args: SimpleNamespace(project="fixture")
        _release.admit_pre_execution = lambda closures, project, items: (
            admission_calls.append((closures, project, items)) or
            (closures, None))
        try:
            check("run and validate require a worker before harness/Docker, "
                  "with validate completing static admission first",
                  cli_refused(lambda: bench_cli.cmd_run(SimpleNamespace(
                      worker=None, cmd="run")))
                  and cli_refused(lambda: toolkit_cli.cmd_validate(
                      SimpleNamespace(
                          worker=None, cmd="validate", boundary="fixture",
                          repo=root, artifacts=admission_dir, item=())))
                  and admission_calls == [([], "fixture", ())]
                  and harness_calls == [])
        finally:
            bench_cli._harness = real_harness
            bench_cli._boundary = real_boundary
            _release.admit_pre_execution = real_admit
        image_probes = []
        real_image_digest = bench_cli._image_digest
        bench_cli._image_digest = lambda image: image_probes.append(image)
        try:
            # `cmd_campaign` binds the agent producer before it inspects
            # anything, so this leg needs the agent component.
            from ..confined import result_ledger_v2  # noqa: F401
        except ImportError:
            print("  [SKIP] executable campaign creation requires v3 before "
                  "an image inspection: `cmd_campaign` needs "
                  "r2t.confined.result_ledger_v2 (agent component), which this "
                  "checkout does not ship")
        else:
            campaign_out = os.path.join(root, "unbound-campaign.json")
            check("executable campaign creation requires v3 before an image "
                  "inspection",
                  cli_refused(lambda: bench_cli.cmd_campaign(SimpleNamespace(
                      out=campaign_out, seed=os.path.join(root, "no-seed"),
                      boundary=__file__, protocol=None,
                      network_semantics="fixture", agent_system=None,
                      attempt_id="fixture-attempt", campaign_id="fixture",
                      allow_unresolved=False, worker=None)))
                  and image_probes == []
                  and not os.path.lexists(campaign_out)
                  and not os.path.lexists(
                      campaign_out + ".agent_runtime.json"))
        finally:
            bench_cli._image_digest = real_image_digest
        real_stack_profile = bench_cli._stack_profile
        real_authority_reference = _docker_cli.authority_reference
        authority_probes = []
        #: Every `worker` verb that administers a LIVE pool, and therefore
        #: refuses without exact v3 evidence before it reaches Docker.
        _live_admin_actions = ("preflight", "probe", "reset-probe", "harden",
                               "unharden", "teardown")

        def unexpected_authority_probe(*args, **kwargs):
            authority_probes.append((args, kwargs))
            raise WorkerRefused("authority probe reached")

        bench_cli._stack_profile = lambda _args: SimpleNamespace(
            needs_database=True, framework="behat", project="coreshop")
        _docker_cli.authority_reference = unexpected_authority_probe
        try:
            check("closed live producers refuse without treating Docker "
                  "authority as workload binding",
                  cli_refused(lambda: toolkit_cli.cmd_sanitise(
                      SimpleNamespace(dump_autoload=True)))
                  and cli_refused(lambda: bench_cli.cmd_mutation_run(
                      SimpleNamespace()))
                  and cli_refused(lambda: bench_cli.cmd_test_quality(
                      SimpleNamespace())))
            # `index`, `index-prod` and `mutants build` are OPEN on the named
            # container's immutable image ID (DOCKER_EXECUTION_AUTHORITY.md,
            # 2026-09-09 amendment): resolving that ID is their first live
            # act, and a container whose image is not a `sha256:` ID is
            # refused before the verb stages, reserves or runs anything.
            import sys as _sys
            me = _sys.modules[__name__]
            real_live_image = me.live_container_image_digest
            image_bindings = []

            def unresolvable_image(container, docker_group=True, behat=None):
                image_bindings.append(container)
                raise WorkerRefused(
                    f"REFUSED: cannot resolve immutable image ID for "
                    f"{container}: fixture")

            me.live_container_image_digest = unresolvable_image
            build_repo = os.path.join(root, "build-repo")
            # An unstripped-looking tree, so the behat `index` body reaches
            # its binding rather than its "index before strip" refusal.
            os.makedirs(os.path.join(
                build_repo, "src", "CoreShop", "Behat", "Context", "Domain"))
            build_args = SimpleNamespace(
                action="build", container="fixture-container",
                workdir="/var/www/html", repo=build_repo,
                boundary=os.path.join(CONFIG_DIR, "boundary_coreshop.yml"),
                profile=None, out=os.path.join(root, "build-out.json"),
                raw_out=None, path=None, sample=None, seed=None,
                operator_profile="v2", record_enumerator_rev=False)
            index_prod_args = SimpleNamespace(
                container="fixture-container", workdir="/var/www/html",
                repo=build_repo, boundary=build_args.boundary, profile=None,
                artifacts=os.path.join(root, "build-artifacts"), path=None,
                gold=os.path.join(root, "build-gold"))
            index_args = SimpleNamespace(
                container="fixture-container", workdir="/var/www/html",
                repo=build_repo, boundary=build_args.boundary, profile=None,
                artifacts=os.path.join(root, "index-artifacts"),
                features="features")
            from ..toolkit import mutation_py, pystep_index
            docx_boundary = os.path.join(CONFIG_DIR, "boundary_python_docx.yml")
            behave_index_args = SimpleNamespace(
                container="fixture-container", repo=build_repo,
                boundary=docx_boundary, profile=None, features="features",
                artifacts=os.path.join(root, "behave-index-artifacts"))
            behave_build_args = SimpleNamespace(
                action="build", container="fixture-container",
                repo=build_repo, boundary=docx_boundary, profile=None,
                out=os.path.join(root, "behave-build-out.json"), raw_out=None,
                path=None, sample=None, seed=None, operator_profile="v2",
                record_enumerator_rev=False)
            try:
                behat_build_refused = cli_refused(
                    lambda: bench_cli.cmd_mutants(build_args))
                index_prod_refused = cli_refused(
                    lambda: toolkit_cli.cmd_index_prod(index_prod_args))
                behat_index_refused = cli_refused(
                    lambda: toolkit_cli.cmd_index(index_args))
                behave_index_refused = cli_refused(
                    lambda: pystep_index.cmd_index(behave_index_args))
                behave_build_refused = cli_refused(
                    lambda: mutation_py.cmd_mutants(behave_build_args))
            finally:
                me.live_container_image_digest = real_live_image
            check("the five opened live producers bind the named container's "
                  "image ID first and refuse an unresolvable one before "
                  "staging",
                  behat_build_refused and index_prod_refused
                  and behat_index_refused and behave_index_refused
                  and behave_build_refused
                  and image_bindings == ["fixture-container"] * 5
                  and not os.path.lexists(build_args.out)
                  and not os.path.lexists(behave_build_args.out)
                  and not os.path.isdir(os.path.join(build_repo, "var"))
                  and not os.path.isdir(os.path.join(build_repo, "_bench"))
                  and not os.path.isdir(index_prod_args.artifacts)
                  and not os.path.isdir(index_args.artifacts)
                  and not os.path.isdir(behave_index_args.artifacts))
            # The database-backed `seed build` OPENED on 2026-09-16 (owner
            # ruling, DOCKER_EXECUTION_AUTHORITY.md): the boundary/profile
            # pair, `--db-container`, `--schema`, `--seed` and `--gold` are
            # the binding, and `seed.build_seed` records them in the seed
            # manifest.  Docker-free here because the database handle itself
            # is replaced: reaching it, with the container the argv named, is
            # the whole fact -- the verb no longer stops at a gate above it.
            from . import dbadmin as _dbadmin
            real_mysql = _dbadmin.MySQL
            seed_handles = []

            def unreachable_database(container, **_kw):
                seed_handles.append(container)
                raise WorkerRefused(f"fixture database handle: {container}")

            _dbadmin.MySQL = unreachable_database
            seed_build_args = SimpleNamespace(
                action="build", boundary=build_args.boundary, profile=None,
                repo=build_repo, schema="r2t_fixture_seed",
                seed=os.path.join(root, "seed-build-out"),
                gold=os.path.join(root, "seed-build-gold"),
                db_container="fixture-db", force=False)
            try:
                bench_cli.cmd_seed(seed_build_args)
                reached_database = False
            except WorkerRefused:
                reached_database = True
            except SystemExit:
                reached_database = False
            finally:
                _dbadmin.MySQL = real_mysql
            check("database-backed `seed build` reaches the database handle "
                  "the invocation names instead of refusing above it",
                  reached_database and seed_handles == ["fixture-db"]
                  and not os.path.lexists(seed_build_args.seed))
            force_args = SimpleNamespace(
                image=None,
                workers_root=os.path.join(root, "force-workers"), k=1,
                runs_dir=None, worker_artifacts=None,
                workdir="/var/www/html", container_kind="php",
                gold=os.path.join(root, "force-gold"),
                artifacts=os.path.join(root, "force-artifacts"), only=None,
                action="provision", internal_network="fixture-internal",
                composer_cache=None, db_container="fixture-db",
                seed=os.path.join(root, "force-seed"), force=True,
                boundary=bench_cli.DEFAULT_BOUNDARY, repo=None)
            check("worker provision --force cleanup is closed before Docker",
                  cli_refused(lambda: bench_cli.cmd_worker(force_args))
                  and authority_probes == [])
            live_admin_args = SimpleNamespace(
                image=None,
                workers_root=os.path.join(root, "admin-workers"), k=1,
                runs_dir=None, worker_artifacts=None,
                workdir="/var/www/html", container_kind="php",
                gold=os.path.join(root, "admin-gold"),
                artifacts=os.path.join(root, "admin-artifacts"), only=None,
                action="preflight", live=True,
                internal_network=None, composer_cache=None,
                db_container="fixture-db", seed=os.path.join(root, "seed"),
                force=False, worker=None,
                boundary=bench_cli.DEFAULT_BOUNDARY, repo=None)
            admin_actions_refused = []
            for action in _live_admin_actions:
                live_admin_args.action = action
                admin_actions_refused.append(
                    cli_refused(lambda: bench_cli.cmd_worker(live_admin_args)))
            check("every live worker administration action requires v3 "
                  "before Docker",
                  all(admin_actions_refused) and authority_probes == [])
            db_provision_refused = cli_refused(
                lambda: bench_cli.cmd_worker(SimpleNamespace(
                    image=None, workers_root=os.path.join(root, "order-workers"),
                    k=1, runs_dir=None, worker_artifacts=None,
                    workdir="/var/www/html", container_kind="php",
                    gold=os.path.join(root, "order-gold"),
                    artifacts=os.path.join(root, "order-artifacts"),
                    only=None, action="provision",
                    internal_network="fixture-internal", composer_cache="",
                    db_container="fixture-db", seed=os.path.join(root, "seed"),
                    force=False,
                    boundary=bench_cli.DEFAULT_BOUNDARY, repo=None)))
        finally:
            bench_cli._stack_profile = real_stack_profile
            _docker_cli.authority_reference = real_authority_reference
        # The cause here is the missing Composer cache, not the database
        # gate: `composer_mounts` is resolved before the first live authority
        # probe precisely so a missing host input refuses with zero Docker
        # contact.  Naming the cause matters -- read as "the database gate
        # closed it", this check would misdescribe the posture.
        check("DB-backed provision with no Composer cache refuses before any "
              "authority/Docker probe",
              db_provision_refused and authority_probes == [])

        # The database gate itself, directly.  It is a pure function of
        # (needs_database, workload), so the whole of its behaviour is three
        # assertions rather than a fixture.
        _gate = bench_cli._refuse_unbound_database_runtime
        _still_closed = (
            "database-backed confinement certification",
        )
        _now_open = (
            "database-backed persistent validation/evaluation",
            "database-backed worker provision",
            "database-backed executable campaign creation",
            "slice-3 evaluation execution",
            "database-backed mutation execution",
            "database-backed test-quality execution",
        )
        check("the database gate still closes the workloads whose claims "
              "reach past what a per-pool harden and probe demonstrate",
              all(cli_refused(lambda w=w: _gate(True, w))
                  for w in _still_closed))
        check("...and opens the ones those two commands can falsify, so a "
              "SQL boundary is demonstrated rather than asserted",
              not any(cli_refused(lambda w=w: _gate(True, w))
                      for w in _now_open))
        check("a no-database stack is never touched by the database gate, "
              "whichever workload it names",
              not any(cli_refused(lambda w=w: _gate(False, w))
                      for w in _still_closed + _now_open))
        # The dependency, stated directly.  The two execution workloads left
        # the closed set because a per-pool falsifier now exists for the one
        # claim that had none; this is what stops a later diff from deleting
        # the closure without keeping the demonstration that replaced it.
        _dbless_worker = WorkerSpec(
            index=0, workspace=root, container="fixture-php-0", schema="",
            credential="", env_file=os.path.join(root, "fixture.env"))
        check("the reopened execution workloads are paired with a per-pool "
              "reset falsifier that refuses a worker with no schema",
              "database-backed mutation execution" in _now_open
              and "database-backed test-quality execution" in _now_open
              and callable(reset_probe)
              and refused(lambda: reset_probe(_dbless_worker, None))
              and "reset-probe" in _live_admin_actions)

        # The reset verdict, over hand-written documents -- the shape
        # `dbadmin.selftest` uses for `probe_report`, and for the same reason:
        # what has to be pinned is which documents are a PASS, and that is a
        # pure function of the document.
        def _seen(present, ok=True, error_class=None):
            return {"ok": ok, "present": present, "error_class": error_class}

        _reset_nonce = "0f1e2d3c4b5a"
        _reset_good = {
            "worker": 0, "own_schema": "coreshop_bench_0",
            "nonce": _reset_nonce, "markers": reset_marker_names(_reset_nonce),
            "leg_a": {"outcome": "passed", "report": {
                "leg": "A", "nonce": _reset_nonce,
                "schema": "coreshop_bench_0",
                "baseline": {"object_rows": 1, "class_files": 21},
                "wrote": {name: {"ok": True, "error_class": None}
                          for name in RESET_EXPECTED_IN_LEG_B},
                "markers": {name: _seen(True)
                            for name in RESET_EXPECTED_IN_LEG_B}}},
            "leg_b": {"outcome": "passed", "report": {
                "leg": "B", "nonce": _reset_nonce,
                "schema": "coreshop_bench_0",
                "baseline": {"object_rows": 1, "class_files": 21},
                "wrote": {},
                "markers": {name: _seen(expected) for name, expected
                            in RESET_EXPECTED_IN_LEG_B.items()}}},
            "cleanup": {"deleted": 1, "remaining": 0}}

        def _reset_variant(**edit):
            doc = json.loads(json.dumps(_reset_good))
            for path, value in edit.items():
                node = doc
                keys = path.split("__")
                for key in keys[:-1]:
                    node = node[key]
                if value is _DROP:
                    del node[keys[-1]]
                else:
                    node[keys[-1]] = value
            return doc

        check("a worker whose markers were purged and whose control survived "
              "passes", reset_report(_reset_good)["pass"],
              json.dumps(reset_report(_reset_good))[:300])
        _blind_control = _reset_variant(
            leg_a__report__markers__unpurged_row=_seen(False))
        check("a leg A that could not see the marker it just wrote is not a "
              "pass", not reset_report(_blind_control)["pass"]
              and reset_report(_blind_control)["failure_class"]
              == "leg_a_control_failed")
        _crossed = _reset_variant(
            leg_b__report__markers__purged_object=_seen(True))
        check("a marker still visible to the NEXT pair execution is not a "
              "pass, and is named",
              not reset_report(_crossed)["pass"]
              and reset_report(_crossed)["failure_class"]
              == "state_crossed_the_pair_boundary"
              and reset_report(_crossed)["markers_visible_in_leg_b"]
              == ["purged_object"])
        _blind = _reset_variant(
            leg_b__report__markers__unpurged_row=_seen(False))
        check("a probe where even the control marker is absent is not a "
              "pass: it observed nothing, which is not a clean reset",
              not reset_report(_blind)["pass"]
              and reset_report(_blind)["failure_class"]
              == "probe_observed_nothing")
        _drained = _reset_variant(leg_b__report__baseline__object_rows=0)
        check("an absence measured against an EMPTY object table is not a "
              "pass",
              not reset_report(_drained)["pass"]
              and reset_report(_drained)["failure_class"]
              == "leg_b_unreachable_baseline")
        _partial = _reset_variant(
            leg_b__report__markers__purged_class=_DROP)
        check("a probe that skipped a required check is not a pass",
              not reset_report(_partial)["pass"]
              and reset_report(_partial)["checks_not_run"]
              == ["leg_b_purged_class"])
        _threw = _reset_variant(
            leg_b__report__markers__purged_object=_seen(
                None, ok=False, error_class="Doctrine\\DBAL\\Exception"))
        check("a marker check that THREW is a check that did not run, never "
              "an absence",
              not reset_report(_threw)["pass"]
              and reset_report(_threw)["checks_not_run"]
              == ["leg_b_purged_object"])
        _dirty = _reset_variant(cleanup__remaining=1)
        check("a probe that could not remove its own durable marker is not a "
              "pass and says the worker must be reprovisioned",
              not reset_report(_dirty)["pass"]
              and "must be reprovisioned" in reset_report(_dirty)["why"])
        check("the control marker is the one leg B must still SEE, so a "
              "verdict of all-absent can never be a pass",
              RESET_EXPECTED_IN_LEG_B["unpurged_row"] is True
              and set(RESET_EXPECTED_IN_LEG_B) == {"purged_object",
                                                   "purged_class",
                                                   "rewritten_production_class",
                                                   "unpurged_row"})
        # The production-class marker (v1.1): leg A appends a nonce line to
        # a generated PRODUCTION class, which no purge touches; only the
        # harness's derived-state restore can take it away before leg B.  A
        # harness without that restore -- c51836e1, the tag before it -- leaves
        # the line in place, and that must fail by name, not pass.
        _unrestored = _reset_variant(
            leg_b__report__markers__rewritten_production_class=_seen(True))
        check("a production class still carrying leg A's line in leg B (no "
              "derived-state restore) fails as state crossing the pair "
              "boundary, and is named",
              not reset_report(_unrestored)["pass"]
              and reset_report(_unrestored)["failure_class"]
              == "state_crossed_the_pair_boundary"
              and reset_report(_unrestored)["markers_visible_in_leg_b"]
              == ["rewritten_production_class"])
        _unwritten = _reset_variant(
            leg_a__report__wrote__rewritten_production_class={
                "ok": False, "error_class": "RuntimeException"})
        check("a leg A that could not rewrite the production class is a "
              "broken control, never a clean reset",
              reset_report(_unwritten)["failure_class"]
              == "leg_a_control_failed"
              and reset_report(_unwritten)["failed_writes"]
              == ["rewritten_production_class"])
        _unread = _reset_variant(
            leg_b__report__markers__rewritten_production_class=_DROP)
        check("a leg B that never looked at the production class did not "
              "run a required check",
              not reset_report(_unread)["pass"]
              and reset_report(_unread)["checks_not_run"]
              == ["leg_b_rewritten_production_class"])
        _names = reset_marker_names(_reset_nonce)
        check("both sides derive the same four marker identities from the "
              "nonce, so leg B looks for what leg A wrote",
              _names["class_name"].startswith("Behat")
              and "'r2t-reset-probe-' . $nonce" in RESET_PROBE_CONTEXT_PHP
              and "'BehatR2tResetProbe' . $nonce" in RESET_PROBE_CONTEXT_PHP
              and "'r2t-reset-probe ' . $nonce" in RESET_PROBE_CONTEXT_PHP
              and _names["production_class_line"]
              == "// r2t-reset-probe-class " + _reset_nonce
              and "'// r2t-reset-probe-class ' . $nonce"
              in RESET_PROBE_CONTEXT_PHP)
        from .repo import derived_state_roots as _derived_roots
        check("the production class leg A rewrites is a derived-state seed "
              "member the harness restores, and not a Behat% class a purge "
              "would take away on its own",
              RESET_PRODUCTION_CLASS_REL.startswith(
                  _derived_roots("behat", behat=CORESHOP_BEHAT)[0] + "/")
              and "/Behat" not in RESET_PRODUCTION_CLASS_REL
              and "'/DataObject/CoreShopProduct.php'"
              in RESET_PROBE_CONTEXT_PHP
              and RESET_PRODUCTION_CLASS_REL.endswith(
                  "/DataObject/CoreShopProduct.php"))
        from ..core.gherkin import parse_feature_file as _parse_feature
        from ..core.gherkin import standalone_feature as _standalone
        _reset_feature = _parse_feature(
            "<fixture>", text=reset_feature_text(_reset_nonce))
        _leg_files = [_standalone(_reset_feature, block)
                      for block in _reset_feature.scenarios]
        check("the synthesised feature parses into exactly two scenarios, "
              "one per leg, each naming the same nonce",
              len(_reset_feature.scenarios) == 2
              and "writes its markers" in _leg_files[0]
              and "observes its markers" in _leg_files[1]
              and all(f'"{_reset_nonce}"' in text for text in _leg_files))
        from ..core.boundary import REMOVABLE as _REMOVABLE
        from ..core.boundary import load_boundary as _load_boundary
        _cs_boundary = _load_boundary(os.path.join(CONFIG_DIR, "boundary_coreshop.yml"))
        check("the marker context is installable test code, so "
              "install_solution writes it instead of rejecting it and "
              "leaving leg A with no step definitions",
              _cs_boundary.classify(RESET_CONTEXT_REL) == _REMOVABLE)

        # ---- the reset probe as a per-project PROGRAM
        #
        # CoreShop's two PHP programs went from constants to renderings in
        # this change, so what is pinned first is their BYTES.  Everything
        # else here is a second program beside them; none of it is allowed to
        # move the acceptance that is in production use.
        #
        # The context digest moved ONCE since, at the harness-19 merge, and
        # to the mutation-evaluation-collection-v1.1 line's own constant:
        # that line added the `rewritten_production_class` marker to this
        # program, and the rendering reproduces its PHP byte for byte.  The
        # ADMIN script is still master's pre-refactor bytes, unchanged by
        # either line, which is why only one of the two numbers below moved.
        check("CoreShop's marker context renders byte for byte to the v1.1 "
              "line's own PHP, and the admin script to what it was before "
              "the tables became rows",
              hashlib.sha256(
                  reset_context_php().encode("utf-8")).hexdigest()[:16]
              == "7b9690285da51072"
              and hashlib.sha256(
                  reset_admin_php().encode("utf-8")).hexdigest()[:16]
              == "1f27ed2ecb235b59",
              hashlib.sha256(reset_context_php().encode()).hexdigest()[:16])
        check("...and the row a boundary with no `behat:` block gets still "
              "names CoreShop's program, path, tables and markers",
              reset_program_for().name == "pimcore"
              and RESET_CONTEXT_REL
              == "src/CoreShop/Behat/Context/R2tResetProbeContext.php"
              and (CORESHOP_BEHAT.reset_marker_table,
                   CORESHOP_BEHAT.reset_control_table) == ("objects",
                                                           "versions")
              and RESET_EXPECTED_IN_LEG_B == {
                  "purged_object": False, "purged_class": False,
                  "rewritten_production_class": False, "unpurged_row": True}
              and RESET_REQUIRED_CHECKS == (
                  "leg_a_ran", "leg_a_object_baseline",
                  "leg_a_class_baseline", "leg_a_read_back_purged_object",
                  "leg_a_read_back_purged_class",
                  "leg_a_read_back_rewritten_production_class",
                  "leg_a_read_back_unpurged_row", "leg_b_ran",
                  "leg_b_object_baseline", "leg_b_class_baseline",
                  "leg_b_purged_object", "leg_b_purged_class",
                  "leg_b_rewritten_production_class",
                  "leg_b_unpurged_row", "cleanup_unpurged_row_removed"))

        _sy_boundary = _load_boundary(
            os.path.join(CONFIG_DIR, "boundary_sylius.yml"))
        from dataclasses import replace as _dc_replace
        from .repo import behat_project as _behat_project
        _sy = _behat_project(_sy_boundary)
        _sy_program = reset_program_for(_sy)
        check("a project whose boundary names the `doctrine` program gets "
              "TWO markers: `purged_class` has no analogue there, so it is "
              "dropped rather than renamed onto something that cannot fail",
              _sy_program.name == "doctrine"
              and _sy_program.expected_in_leg_b == {"purged_row": False,
                                                   "unpurged_row": True}
              and not [c for c in _sy_program.required_checks
                       if "class_baseline" in c]
              and _sy_program.required_checks == (
                  "leg_a_ran", "leg_a_control_baseline",
                  "leg_a_read_back_purged_row",
                  "leg_a_read_back_unpurged_row", "leg_b_ran",
                  "leg_b_control_baseline", "leg_b_purged_row",
                  "leg_b_unpurged_row", "cleanup_unpurged_row_removed"),
              str(_sy_program.required_checks))
        check("...and its leg-B reachability control counts the UNPURGED "
              "table, because the purge empties every mapped one -- which "
              "makes it the same fact as the unpurged marker, and the "
              "verdict says so rather than leaving it to be worked out",
              _sy_program.baseline_table_field == "reset_control_table"
              and _sy_program.baselines == (("control_baseline",
                                             "control_rows"),)
              and _sy_program.baseline_is_the_control is True
              and RESET_PROGRAMS["pimcore"].baseline_is_the_control is False)

        _sy_names = reset_marker_names(_reset_nonce, _sy)
        _sy_context = reset_context_php(_sy)
        _sy_admin = reset_admin_php(_sy)
        check("the doctrine context is installed inside the SYLIUS stub "
              "territory, so install_solution writes it there instead of "
              "refusing a path outside the removable tree",
              _sy.reset_context_rel.startswith(_sy.stub_dir + "/")
              and _sy_boundary.classify(_sy.reset_context_rel) == _REMOVABLE
              and f"namespace {_sy.stub_namespace};" in _sy_context)
        check("...and it names the project's own tables and nothing of "
              "Pimcore's: the marker goes into a mapped table, the control "
              "into the migration version table the purger cannot see",
              "`sylius_channel`" in _sy_context
              and "`sylius_migrations`" in _sy_context
              and "objects" not in _sy_context
              and "versions" not in _sy_context
              and "Pimcore" not in _sy_context)
        check("...through Behat 4 step ATTRIBUTES, because `@Given` binds "
              "nothing there and leg A would pass with no step executed",
              "use Behat\\Step\\Given;" in _sy_context
              and _sy_context.count("#[Given('/^the reset probe ") == 2
              and "@Given" not in _sy_context)
        check("both sides derive the doctrine markers from the same nonce",
              _sy_names == {"marker_code": f"R2T_RESET_PROBE_{_reset_nonce}",
                            "control_version": f"R2T_CONTROL_{_reset_nonce}"}
              and "'R2T_RESET_PROBE_' . $nonce" in _sy_context
              and "'R2T_CONTROL_' . $nonce" in _sy_context
              and _sy_program.durable_marker == "control_version")
        check("the admin script reads the project's DSN variable and counts "
              "and deletes in the project's control table, by its own column",
              "getenv('DATABASE_URL')" in _sy_admin
              and "'control_rows'" in _sy_admin
              and "FROM `sylius_migrations`" in _sy_admin
              and "DELETE FROM `sylius_migrations` WHERE `version` = ?"
              in _sy_admin
              and "PIMCORE" not in _sy_admin and "objects" not in _sy_admin)
        check("a boundary that misspells its program is refused, not run "
              "under CoreShop's markers against a stack with no purge for "
              "them",
              refused(lambda: reset_program_for(
                  _dc_replace(CORESHOP_BEHAT, reset_program="doctrne"))))

        # The doctrine verdict, over the same hand-written documents, because
        # the arithmetic is shared and only the program's names change.
        _dr_good = {
            "worker": 0, "own_schema": "sylius_s1_0",
            "nonce": _reset_nonce, "markers": _sy_names,
            "leg_a": {"outcome": "passed", "report": {
                "leg": "A", "nonce": _reset_nonce, "schema": "sylius_s1_0",
                "baseline": {"control_rows": 26},
                "wrote": {name: {"ok": True, "error_class": None}
                          for name in _sy_program.expected_in_leg_b},
                "markers": {name: _seen(True)
                            for name in _sy_program.expected_in_leg_b}}},
            "leg_b": {"outcome": "passed", "report": {
                "leg": "B", "nonce": _reset_nonce, "schema": "sylius_s1_0",
                "baseline": {"control_rows": 27}, "wrote": {},
                "markers": {name: _seen(expected) for name, expected
                            in _sy_program.expected_in_leg_b.items()}}},
            "cleanup": {"deleted": 1, "remaining": 0}}

        def _dr_variant(**edit):
            doc = json.loads(json.dumps(_dr_good))
            for path, value in edit.items():
                node = doc
                keys = path.split("__")
                for key in keys[:-1]:
                    node = node[key]
                if value is _DROP:
                    del node[keys[-1]]
                else:
                    node[keys[-1]] = value
            return doc

        check("a doctrine worker whose mapped-table marker was purged and "
              "whose migration row survived passes, and the verdict names "
              "the program it ran",
              reset_report(_dr_good, _sy)["pass"]
              and reset_report(_dr_good, _sy)["program"] == "doctrine"
              and reset_report(_dr_good, _sy)["baseline_is_the_control"]
              is True,
              json.dumps(reset_report(_dr_good, _sy))[:300])
        check("...and the same document read under CoreShop's program is NOT "
              "a pass, because its three markers are simply not in it",
              not reset_report(_dr_good)["pass"]
              and reset_report(_dr_good)["failure_class"]
              == "leg_a_control_failed")
        _dr_crossed = _dr_variant(
            leg_b__report__markers__purged_row=_seen(True))
        check("a marker row still visible to the NEXT pair execution is not "
              "a pass: the per-scenario purge did not happen",
              not reset_report(_dr_crossed, _sy)["pass"]
              and reset_report(_dr_crossed, _sy)["failure_class"]
              == "state_crossed_the_pair_boundary"
              and reset_report(_dr_crossed, _sy)["markers_visible_in_leg_b"]
              == ["purged_row"])
        _dr_blind = _dr_variant(
            leg_b__report__markers__unpurged_row=_seen(False))
        check("a doctrine probe whose control row is gone too observed "
              "nothing, which is not a clean reset",
              not reset_report(_dr_blind, _sy)["pass"]
              and reset_report(_dr_blind, _sy)["failure_class"]
              == "probe_observed_nothing")
        _dr_drained = _dr_variant(leg_b__report__baseline__control_rows=0)
        check("an absence measured against an EMPTY control table is not a "
              "pass either, and the check that names it is the program's",
              not reset_report(_dr_drained, _sy)["pass"]
              and reset_report(_dr_drained, _sy)["failure_class"]
              == "leg_b_unreachable_baseline")
        _dr_partial = _dr_variant(leg_b__report__markers__purged_row=_DROP)
        check("a doctrine probe that skipped a required check is not a pass",
              not reset_report(_dr_partial, _sy)["pass"]
              and reset_report(_dr_partial, _sy)["checks_not_run"]
              == ["leg_b_purged_row"])

        # A failed post-provision live acceptance must not leave immutable
        # evidence that looks usable and also blocks a corrected retry.
        from ..data.profile import config_stem as _config_stem
        lifecycle_root = os.path.join(root, "lifecycle-workers")
        lifecycle_args = SimpleNamespace(
            image=None, workers_root=lifecycle_root, k=1,
            runs_dir=None, worker_artifacts=None, workdir="/work",
            container_kind="python", gold=os.path.join(root, "life-gold"),
            artifacts=os.path.join(root, "life-artifacts"), only=None,
            action="provision", internal_network=None, composer_cache=None,
            db_container="unused-db", seed=os.path.join(root, "life-seed"),
            force=False, boundary=bench_cli.DEFAULT_BOUNDARY, repo=None)
        lifecycle_profile = SimpleNamespace(
            needs_database=False, framework="behave", project="fixture")
        lifecycle_workers = plan_workers(
            lifecycle_root, 1, workdir="/work",
            prefix=_config_stem(lifecycle_profile.project), kind="python",
            needs_database=False)
        os.makedirs(lifecycle_root)
        lifecycle_spec = os.path.join(lifecycle_root, "worker0.json")
        with open(lifecycle_spec, "w", encoding="utf-8") as fh:
            json.dump(lifecycle_workers[0].to_json(), fh, sort_keys=True)
        check("an explicit run shard cannot contradict its worker before "
              "runtime/Docker validation",
              cli_refused(lambda: bench_cli._require_bound_live_worker(
                  SimpleNamespace(worker=lifecycle_spec, cmd="run", shard=1))))
        check("--worker-manifest without a campaign refuses before "
              "runtime/Docker validation",
              cli_refused(lambda: bench_cli._require_bound_live_worker(
                  SimpleNamespace(
                      worker=lifecycle_spec, cmd="run", shard=0,
                      worker_manifest=os.path.join(root, "worker-manifest.json"),
                      campaign=None))))
        from .campaign import (
            SHARD_RULE, agent_runtime_digest, generation_fingerprint,
            harness_commit_identity, harness_source_digest,
            probe_agent_runtime)
        from .validate import HARNESS_VERSION
        config_root = CONFIG_DIR
        boundary_path = os.path.join(
            config_root, "boundary_python_docx.yml")
        profile_path = os.path.join(config_root, "profile_python_docx.yml")
        with open(boundary_path, "rb") as fh:
            config_digest = hashlib.sha256(fh.read()).hexdigest()[:16]
        import sys as _sys
        network_semantics = "fixture_no_egress"
        agent_runtime = probe_agent_runtime(
            interpreter=_sys.executable,
            network_semantics=network_semantics, agent_system=None)
        lifecycle_campaign = os.path.join(root, "lifecycle-campaign.json")
        with open(lifecycle_campaign + ".agent_runtime.json", "w",
                  encoding="utf-8") as fh:
            json.dump(agent_runtime, fh, sort_keys=True)
        with open(lifecycle_campaign, "w", encoding="utf-8") as fh:
            json.dump(generation_fingerprint(
                campaign_id="fixture", k_workers=1,
                shard_rule=SHARD_RULE, trial_budget=0,
                condition=None, coverage=False,
                harness_version=HARNESS_VERSION,
                config_digest=config_digest, model=None,
                container_image_digest="sha256:" + "a" * 64,
                workspace_seed_digest="b" * 64,
                database_dump_digest=NO_DATABASE,
                protocol_version=None, protocol_digest=None,
                agent_system=None, attempt_id="fixture-attempt",
                harness_commit=harness_commit_identity(),
                harness_source_sha256=harness_source_digest(),
                agent_runtime_sha256=agent_runtime_digest(agent_runtime),
                network_semantics=network_semantics), fh, sort_keys=True)

        def campaign_args(path, *, condition=None, protocol_version=None,
                          protocol_digest=None, of=1, coverage=False):
            return SimpleNamespace(
                worker=lifecycle_spec, cmd="run", shard=0,
                campaign=path, of=of, trials=0, coverage=coverage,
                condition=condition, model=None, adapter="gold",
                protocol_version=protocol_version,
                protocol_digest=protocol_digest,
                boundary=boundary_path, profile=profile_path,
                gold=os.path.join(root, "life-gold"),
                artifacts=os.path.join(root, "life-artifacts"))

        check("a campaign run cannot omit --of before runtime/Docker "
              "validation",
              cli_refused(lambda: bench_cli._require_bound_live_worker(
                  campaign_args(lifecycle_campaign, of=None))))
        check("campaign flag contradictions refuse before runtime/Docker "
              "validation",
              cli_refused(lambda: bench_cli._require_bound_live_worker(
                  campaign_args(lifecycle_campaign, coverage=True))))
        with open(lifecycle_campaign, encoding="utf-8") as fh:
            base_campaign = json.load(fh)
        condition_campaign = os.path.join(root, "condition-campaign.json")
        with open(condition_campaign, "w", encoding="utf-8") as fh:
            json.dump({**base_campaign, "condition": "c3"}, fh,
                      sort_keys=True)
        shard_campaign = os.path.join(root, "shard-campaign.json")
        with open(shard_campaign, "w", encoding="utf-8") as fh:
            json.dump({**base_campaign, "shard_rule": "unknown-rule"}, fh,
                      sort_keys=True)

        check("campaign condition and unsupported shard rule refuse before "
              "runtime/Docker validation",
              cli_refused(lambda: bench_cli._require_bound_live_worker(
                  campaign_args(condition_campaign, condition="c2")))
              and cli_refused(lambda: bench_cli._require_bound_live_worker(
                  campaign_args(shard_campaign)))
              and cli_refused(lambda: bench_cli._require_bound_live_worker(
                  campaign_args(lifecycle_campaign, condition="c2")))
              and cli_refused(lambda: bench_cli._require_bound_live_worker(
                  campaign_args(
                      lifecycle_campaign, protocol_version=4,
                      protocol_digest="f" * 16))))

        # SECTION 4.1 OF THE RESULT-V3 AGENT PRODUCER AMENDMENT, AND THE
        # SECTION 10 BOUND ON IT.  A companion that section 4.1 builds "from
        # this selected backend, never by probing the coordinator
        # interpreter" cannot be re-probed here; a probe-built one must be,
        # and that comparison is the only thing on this path that refuses a
        # coordinator whose agent stack or proxy environment drifted away from
        # the campaign, before Docker contact.  The discriminator is therefore
        # the companion's own bytes -- `agent_backend_runtime_digest`, which
        # `probe_agent_runtime` cannot emit -- and NOT `agent_system`: every
        # openhands and aider campaign already on disk is probe-built, and
        # section 10 leaves those unchanged outside explicit agent publication
        # mode.  Both companions below carry an interpreter no live probe of
        # this process can report; only the probe-built one may notice.
        def agent_campaign(name, runtime_document):
            path = os.path.join(root, name)
            with open(path + ".agent_runtime.json", "w",
                      encoding="utf-8") as fh:
                json.dump(runtime_document, fh, sort_keys=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({**base_campaign, "agent_system": "openhands",
                           "agent_runtime_sha256": agent_runtime_digest(
                               runtime_document)}, fh, sort_keys=True)
            return path

        def cli_refusal(fn):
            try:
                fn()
            except SystemExit as exc:
                return str(exc)
            return ""

        # The drift re-probe mirrors campaign creation: an openhands campaign
        # is probed against the SELECTED backend interpreter under its exact
        # requirements lock.  The fixture interpreter reports exactly the
        # locked inventory, so the lock passes and the one difference left is
        # the overridden interpreter identity below.
        try:
            from ..agents.backends import AGENT_BACKENDS
        except ImportError:
            print("  [SKIP] the agent-runtime drift legs: they probe the "
                  "selected arm's `agents.backends` record, and this "
                  "checkout has no agent component")
        else:
            from .campaign import (RUNTIME_ENVIRONMENT_CONTROLS,
                                   _AGENT_RUNTIME_PREFIX,
                                   exact_requirements_lock)
            openhands_backend = AGENT_BACKENDS["openhands"]
            locked_inventory = exact_requirements_lock(
                openhands_backend.requirements_lock)
            fixture_openhands = os.path.join(root, "fixture-openhands-python")
            with open(fixture_openhands, "w", encoding="utf-8") as fh:
                fh.write(
                    f"#!{_sys.executable}\n"
                    "import json, os\n"
                    f"controls = {{name: os.environ.get(name) for name in "
                    f"{RUNTIME_ENVIRONMENT_CONTROLS!r}}}\n"
                    f"payload = {{'interpreter': 'FixtureOpenHands 1.0 (final)', "
                    f"'distributions': {locked_inventory!r}, "
                    "'sitecustomize_sha256': None, "
                    "'environment_controls': controls}\n"
                    f"print({_AGENT_RUNTIME_PREFIX!r} + "
                    "json.dumps(payload, sort_keys=True))\n")
            os.chmod(fixture_openhands, 0o755)
            saved_openhands_python = os.environ.get("R2T_OPENHANDS_PYTHON")
            os.environ["R2T_OPENHANDS_PYTHON"] = fixture_openhands
            try:
                drifted_runtime = {
                    **probe_agent_runtime(
                        interpreter=fixture_openhands,
                        network_semantics=network_semantics,
                        agent_system="openhands",
                        requirements_lock=openhands_backend.requirements_lock),
                    "interpreter": "CPython 0.0.0 (fixture)"}
                probed_message = cli_refusal(
                    lambda: bench_cli._require_bound_live_worker(
                        campaign_args(agent_campaign(
                            "probed-agent-campaign.json", drifted_runtime))))
                check("a probe-built openhands campaign still meets the live "
                      "backend-runtime comparison before Docker contact",
                      "current_agent_runtime_sha256" in probed_message
                      and "saved_agent_runtime_sha256" not in probed_message,
                      probed_message[:200])
                built_message = cli_refusal(
                    lambda: bench_cli._require_bound_live_worker(
                        campaign_args(agent_campaign(
                            "backend-built-agent-campaign.json",
                            {**drifted_runtime,
                             "agent_versions": {
                                 **drifted_runtime["agent_versions"],
                                 "agent_backend_runtime_digest": "d" * 64}}))))
                check("...while the backend-built companion section 4.1 defines "
                      "is not re-probed, and reaches the campaign flag crosscheck",
                      "current_agent_runtime_sha256" not in built_message
                      and "agent_system='openhands'" in built_message,
                      built_message[:200])
            finally:
                if saved_openhands_python is None:
                    os.environ.pop("R2T_OPENHANDS_PYTHON", None)
                else:
                    os.environ["R2T_OPENHANDS_PYTHON"] = saved_openhands_python
        lifecycle_evidence = (
            binding_attestation_path(lifecycle_spec),
            runtime_attestation_path(lifecycle_spec))
        real_stack_profile = bench_cli._stack_profile
        real_authority_reference = _docker_cli.authority_reference
        real_reset_phase = _docker_cli.reset_phase
        real_verified_seed = _worker_api.verified_seed_identity
        real_provision = _worker_api.provision
        real_capture_bindings = _worker_api.capture_execution_bindings
        real_preflight = _worker_api.preflight
        live_acceptance_calls = []
        live_acceptance_paths = []

        def lifecycle_preflight(_workers, _paths, *, live=True, **_kwargs):
            live_acceptance_calls.append(live)
            live_acceptance_paths.append([os.fspath(path) for path in _paths])
            if live:
                raise WorkerRefused("REFUSED: forced bad live mount fixture")
            return {"workers": 1}

        bench_cli._stack_profile = lambda _args: lifecycle_profile
        _docker_cli.authority_reference = lambda **_kwargs: (
            {}, {"path": "/private/authority.json",
                 "file_sha256": "a" * 64, "digest": "b" * 64})
        _docker_cli.reset_phase = lambda: None
        _worker_api.verified_seed_identity = lambda *_args, **_kwargs: {
            "seed_dir": "/private/seed", "seed_manifest_sha256": "1" * 64,
            "seed_key": "fixture", "workspace_seed_digest": "2" * 64,
            "database_dump_digest": NO_DATABASE,
        }
        _worker_api.provision = lambda *_args, **_kwargs: {
            "schema": {"declared": "none"}, "seconds": 0,
        }
        _worker_api.capture_execution_bindings = \
            lambda *_args, **_kwargs: [{"unpublished": True}]
        _worker_api.preflight = lifecycle_preflight
        try:
            lifecycle_refused = refused(
                lambda: bench_cli.cmd_worker(lifecycle_args))
        finally:
            bench_cli._stack_profile = real_stack_profile
            _docker_cli.authority_reference = real_authority_reference
            _docker_cli.reset_phase = real_reset_phase
            _worker_api.verified_seed_identity = real_verified_seed
            _worker_api.provision = real_provision
            _worker_api.capture_execution_bindings = real_capture_bindings
            _worker_api.preflight = real_preflight
        check("bad post-provision live acceptance mints no binding/runtime "
              "evidence",
              # Two static passes now precede the live acceptance: the saved
              # pool is preflighted once for every action, and provision
              # preflights again over the protected evidence set.
              lifecycle_refused
              and live_acceptance_calls == [False, False, True]
              and all(os.path.join(lifecycle_args.artifacts, "release", "gold")
                      in paths for paths in live_acceptance_paths)
              and not any(os.path.lexists(path)
                          for path in lifecycle_evidence),
              json.dumps({
                  "calls": live_acceptance_calls,
                  "expected_release_gold": os.path.join(
                      lifecycle_args.artifacts, "release", "gold"),
                  "paths": live_acceptance_paths,
              }, sort_keys=True))
        # PC10 at its choke point.  `report`, `results` and `recall` all reach
        # the seed through this one function and all guard it with
        # `except WorkerRefused`; `seed.SeedRefused` is a bare RuntimeError,
        # so an absent seed used to escape all three (review finding 24).
        from . import seed as _S
        empty_seed = os.path.join(root, "no-seed-here")
        os.makedirs(empty_seed)
        check("PC10: an absent seed leaves `verified_seed_identity` as the "
              "refusal type the publication boundary catches",
              refused(lambda: verified_seed_identity(empty_seed, False))
              and not issubclass(_S.SeedRefused, WorkerRefused))
        ws = plan_workers(root, 4)
        check("K workers have K distinct workspaces, schemas, containers "
              "and credentials",
              all(len({getattr(w, f) for w in ws}) == 4 for f in RESOURCE_FIELDS))
        check("every identity is derived from the index",
              ws[2].schema.endswith("_2") and ws[2].credential.endswith("_2")
              and ws[2].container.endswith("_2"))
        check("the default naming is still CoreShop's, character for "
              "character",
              ws[0].container == "coreshop_bench_php_0"
              and ws[0].schema == "coreshop_bench_0"
              and ws[0].credential == "bench_0")

        namespace_roots = [os.path.join(root, "pool-default"),
                           os.path.join(root, "pool-prefix-only")]
        namespace_flags = [
            (),
            ("--prefix", "coreshop_alpha"),
        ]
        namespace_statuses = []
        for pool_root, flags in zip(namespace_roots, namespace_flags):
            with contextlib.redirect_stdout(io.StringIO()):
                namespace_statuses.append(_cli.main([
                    "worker", "plan", "--k", "2",
                    "--workers-root", pool_root, *flags]))
        namespace_pools = [load_worker_pool(path, 2)
                           for path in namespace_roots]
        check("a default worker plan and a prefix-only plan are disjoint on "
              "every resource field",
              namespace_statuses == [0, 0]
              and all(
                  {getattr(w, field) for w in namespace_pools[0]}.isdisjoint(
                      {getattr(w, field) for w in namespace_pools[1]})
                  for field in RESOURCE_FIELDS))

        check("a worker record carries no password field",
              "password" not in ws[0].to_json()
              and set(ws[0].to_json()) == set(WorkerSpec.__dataclass_fields__))
        check("a worker round-trips through JSON",
              WorkerSpec.from_json(ws[3].to_json()) == ws[3])
        check("worker JSON is fail-closed on missing or unknown fields",
              refused(lambda: WorkerSpec.from_json({
                  k: v for k, v in ws[0].to_json().items()
                  if k != "workspace"}))
              and refused(lambda: WorkerSpec.from_json({
                  **ws[0].to_json(), "workspace_alias": ws[0].workspace})))

        # The pool a `worker plan` writes must survive the admission rules the
        # very next command applies, on a host whose umask would otherwise
        # publish it group-writable.  A 002 default is common, and it is what
        # made a fresh consumer's provision refuse the pool it had just saved.
        saved_umask = os.umask(0o002)
        try:
            permissive_root = os.path.join(root, "permissive-pool")
            written = write_worker_pool(
                permissive_root, plan_workers(permissive_root, 2))
        finally:
            os.umask(saved_umask)
        pool_modes = [stat.S_IMODE(os.stat(p).st_mode)
                      for p in [permissive_root, *written]]
        check("a permissive umask cannot save a peer-writable worker pool",
              len(written) == 2
              and all(mode & 0o022 == 0 for mode in pool_modes)
              and load_worker_pool(permissive_root, 2)
              == plan_workers(permissive_root, 2))
        os.chmod(permissive_root, 0o775)
        check("a widened pool root is restored, and reading is unaffected",
              write_worker_pool(permissive_root, plan_workers(
                  permissive_root, 2)) == written
              and stat.S_IMODE(os.stat(permissive_root).st_mode) & 0o022 == 0)
        seed_dir = os.path.join(root, "seed")
        os.makedirs(seed_dir)
        workspace_tar = os.path.join(seed_dir, "workspace.tar")
        database_sql = os.path.join(seed_dir, "database.sql")
        with open(workspace_tar, "wb") as fh:
            fh.write(b"workspace seed fixture")
        with open(database_sql, "wb") as fh:
            fh.write(b"database seed fixture")
        workspace_digest = _sha256_regular_file(
            workspace_tar, "fixture workspace seed")
        database_digest = _sha256_regular_file(
            database_sql, "fixture database seed")
        with open(os.path.join(seed_dir, "seed.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({
                "format": 1, "seed_key": "fixture-seed-key",
                "needs_database": True,
                "workspace": {"digest": workspace_digest},
                "database": {"digest": database_digest},
            }, fh)
        from unittest.mock import patch
        from . import seed as _seed
        import shutil

        with patch.object(_seed, "verify_seed", wraps=_seed.verify_seed) as verify:
            with _seed_verification_scope():
                first_seed = verified_seed_identity(seed_dir, True)
                first_seed["seed_key"] = "caller changed its returned copy"
                with _seed_verification_scope():
                    second_seed = verified_seed_identity(seed_dir, True)
                check("nested read-only validation reuses exact seed bytes "
                      "without sharing a mutable returned identity",
                      verify.call_count == 1
                      and second_seed["seed_key"] == "fixture-seed-key")
                check("seed reuse does not erase database semantics",
                      refused(lambda: verified_seed_identity(seed_dir, False)))
                another_seed = os.path.join(root, "another-seed")
                shutil.copytree(seed_dir, another_seed)
                another_identity = verified_seed_identity(another_seed, True)
                check("byte-identical seeds at different paths retain their "
                      "own verified path identities",
                      another_identity["seed_dir"] == another_seed
                      and verify.call_count == 3)
            verified_seed_identity(seed_dir, True)
            check("seed verification is fresh after a validation operation",
                  verify.call_count == 4 and _seed_verifications.get() is None)

        with _seed_verification_scope():
            changed_inputs_refused = []
            for name in (_seed.WORKSPACE_TAR, _seed.DATABASE_SQL,
                         _seed.SEED_MANIFEST):
                path = os.path.join(seed_dir, name)
                with open(path, "rb") as fh:
                    original_seed_bytes = fh.read()
                verified_seed_identity(seed_dir, True)
                try:
                    with open(path, "wb") as fh:
                        if name == _seed.SEED_MANIFEST:
                            changed_manifest = json.loads(original_seed_bytes)
                            changed_manifest["workspace"]["digest"] = "f" * 64
                            fh.write(json.dumps(changed_manifest).encode("utf-8"))
                        else:
                            fh.write(b"changed seed artifact")
                    with patch.object(_seed, "verify_seed", wraps=_seed.verify_seed) as verify:
                        changed_inputs_refused.append(all(refused(
                            lambda: verified_seed_identity(seed_dir, True))
                            for _attempt in range(2)) and verify.call_count == 2)
                finally:
                    with open(path, "wb") as fh:
                        fh.write(original_seed_bytes)
            check("changing any cached seed artifact still refuses",
                  changed_inputs_refused == [True, True, True])

        original_verify_identity = _verified_seed_identity
        with open(workspace_tar, "rb") as fh:
            original_workspace_bytes = fh.read()

        def changed_during_verification(path, needs_db):
            result = original_verify_identity(path, needs_db)
            with open(workspace_tar, "ab") as fh:
                fh.write(b"changed during verification")
            return result

        try:
            with _seed_verification_scope():
                with patch(__name__ + "._verified_seed_identity",
                           side_effect=changed_during_verification):
                    check("seed mutation during verification cannot become "
                          "a reusable identity",
                          refused(lambda: verified_seed_identity(seed_dir, True)))
        finally:
            with open(workspace_tar, "wb") as fh:
                fh.write(original_workspace_bytes)
        try:
            with _seed_verification_scope():
                verified_seed_identity(seed_dir, True)
                raise RuntimeError("end this validation early")
        except RuntimeError:
            pass
        with patch.object(_seed, "verify_seed", wraps=_seed.verify_seed) as verify:
            verified_seed_identity(seed_dir, True)
            check("failed validation cannot leave reusable seed state behind",
                  verify.call_count == 1 and _seed_verifications.get() is None)
        spec_paths = []
        for worker in ws:
            # The parser accepts any regular filename; provenance must retain
            # that actual path rather than reverse-engineering a .json name
            # from the paired runtime-attestation suffix.
            suffix = ".worker-spec" if worker.index == 0 else ".json"
            path = os.path.join(root, f"worker{worker.index}{suffix}")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(worker.to_json(), fh, sort_keys=True)
            spec_paths.append(path)
        from .. import docker_authority as _A
        from ..core import docker_cli as _D
        authority_doc = _A._fixture_authority()
        authority_path = os.path.join(root, "authority.json")
        _A.write_evidence_no_clobber(authority_path, authority_doc)
        _loaded_authority, authority_ref = _A.evidence_reference(
            authority_path, expected_schema=_A.AUTHORITY_SCHEMA,
            validator=lambda value: _A.validate_authority_document(
                value, current_source=False), label="fixture authority")
        pool = build_execution_pool(
            ws, spec_paths, database_container="fixture-db",
            internal_network="fixture-internal")
        network_id = "b" * 64
        attachment = [{"name": "fixture-internal", "id": network_id}]
        members = [{
            "role": "database", "worker_index": None, "name": "fixture-db",
            "id": "c" * 64, "image_id": "sha256:" + "d" * 64,
            "running": True, "host_network_mode": "fixture-internal",
            "network_attachments": attachment,
        }]
        containers = []
        for worker in ws:
            container = {
                "name": worker.container,
                "id": f"{worker.index + 1:x}" * 64,
                "image_id": "sha256:" + "a" * 64,
                "running": True,
                "host_network_mode": "fixture-internal",
                "network_attachments": attachment,
            }
            containers.append(container)
            members.append({"role": "worker", "worker_index": worker.index,
                            **container})
        members.sort(key=lambda row: (
            row["role"], -1 if row["worker_index"] is None
            else row["worker_index"], row["name"], row["id"]))
        policy = {
            "mode": "dedicated_internal", "name": "fixture-internal",
            "id": network_id, "driver": "bridge", "scope": "local",
            "internal": True, "ingress": False, "attachable": False,
            "expected_members": members,
            "observed_members": json.loads(json.dumps(members)),
        }
        bindings = []
        seed_identity = verified_seed_identity(seed_dir, True)
        for path, worker, container in zip(spec_paths, ws, containers):
            binding = {
                "schema": _A.BINDING_SCHEMA,
                "captured_at_utc": "2026-08-06T00:00:00Z",
                "authority": authority_ref, "pool": pool,
                "worker_index": worker.index,
                "worker_spec_sha256": pool["workers"][worker.index][
                    "worker_spec_sha256"],
                "container": container, "network_policy": policy,
                "egress_probe": {"required": False,
                                 "status": "not_required", "target": None,
                                 "evidence_sha256": None},
                "digest": "0" * 64,
            }
            binding["digest"] = _A.semantic_digest(binding)
            _A.validate_binding_document(binding)
            binding_path = binding_attestation_path(path)
            _A.write_evidence_no_clobber(binding_path, binding)
            runtime_doc = build_worker_runtime_attestation(
                worker, path, seed_identity, "fixture-harness-v1",
                binding_path=binding_path)
            _A.write_evidence_no_clobber(
                runtime_attestation_path(path), runtime_doc)
            bindings.append(binding)
        with patch.object(_seed, "verify_seed", wraps=_seed.verify_seed) as verify:
            with _seed_verification_scope():
                validate_worker_runtime_v3(spec_paths[0])
                changed_evidence_refused = []
                for path, field, value in (
                        (runtime_attestation_path(spec_paths[0]),
                         "workspace_seed_digest", "f" * 64),
                        (binding_attestation_path(spec_paths[0]),
                         "captured_at_utc", "2026-08-07T00:00:00Z")):
                    with open(path, "rb") as fh:
                        original_evidence = fh.read()
                    changed = json.loads(original_evidence)
                    changed[field] = value
                    try:
                        with open(path, "w", encoding="utf-8") as fh:
                            json.dump(changed, fh)
                        changed_evidence_refused.append(refused(
                            lambda: validate_worker_runtime_v3(spec_paths[0])))
                    finally:
                        with open(path, "wb") as fh:
                            fh.write(original_evidence)
                check("seed reuse still authenticates changed runtime and "
                      "binding evidence on every worker read",
                      changed_evidence_refused == [True, True]
                      and verify.call_count == 1)
        check("runtime builder refuses a binding for another worker with a "
              "controlled error",
              refused(lambda: build_worker_runtime_attestation(
                  ws[0], spec_paths[0], seed_identity,
                  "fixture-harness-v1",
                  binding_path=binding_attestation_path(spec_paths[1]))))
        real_capture = globals()["capture_execution_bindings"]
        live_inspections = []

        def fixture_capture(bound_pool, bound_authority, docker_group=True):
            live_inspections.append((bound_pool, bound_authority))
            return json.loads(json.dumps(bindings))

        globals()["capture_execution_bindings"] = fixture_capture
        _D._install_test_authority(authority_doc, authority_ref)
        try:
            with patch.object(_seed, "verify_seed", wraps=_seed.verify_seed) as verify:
                runtime = validate_mutation_runtime(
                    spec_paths, ws, seed_dir, "fixture-harness-v1", True)
                check("complete mutation pool validation hashes its shared "
                      "seed once, retaining every worker join",
                      verify.call_count == 1 and _seed_verifications.get() is None)
            check("v3 runtime binds complete pool, authority, live binding, "
                  "harness and verified seed bytes",
                  runtime["worker_resources_sha256"]
                  == _content_digest(runtime["worker_resources"])
                  and runtime["workspace_seed_digest"] == workspace_digest
                  and runtime["database_dump_digest"] == database_digest
                  and runtime["docker_execution_authority"] == authority_ref
                  and runtime["docker_execution_pool_digest"] == pool["digest"]
                  and runtime["worker_resources"][0]["worker_spec"]
                  == os.path.realpath(spec_paths[0])
                  and len(runtime["worker_resources"]) == 4
                  and len(live_inspections) == 1)
            real_execution_preflight = globals()["preflight"]
            execution_preflights = []

            def fixture_execution_preflight(
                    workers, paths, *, live=True, **_kwargs):
                execution_preflights.append(
                    (live, tuple(paths),
                     tuple(_kwargs.get("containment_paths", ())),
                     tuple(worker.index for worker in workers),
                     _kwargs.get("behat")))
                return {"workers": len(workers)}

            result_path = os.path.join(root, "future-run.jsonl")
            globals()["preflight"] = fixture_execution_preflight
            inspections_before = len(live_inspections)
            try:
                bound_execution = validate_live_worker_runtime(
                    spec_paths[0], ws[0], "fixture-harness-v1", True,
                    (path for path in (result_path,)), expected_pool_size=4)
                inspections_after_success = len(live_inspections)
                wrong_size_refused = refused(
                    lambda: validate_live_worker_runtime(
                        spec_paths[0], ws[0], "fixture-harness-v1", True,
                        (), expected_pool_size=3))
                expected_runtime = {
                    key: runtime[key]
                    for key in ("harness_version", "container_image_digest",
                                "workspace_seed_digest",
                                "database_dump_digest")
                }
                expected_runtime["workspace_seed_digest"] = "f" * 64
                mismatched_campaign_refused = refused(
                    lambda: validate_live_worker_runtime(
                        spec_paths[0], ws[0], "fixture-harness-v1", True,
                        (), expected_pool_size=4,
                        expected_runtime=expected_runtime))
            finally:
                globals()["preflight"] = real_execution_preflight
            check("ordinary live execution derives and revalidates the full "
                  "v3 pool while retaining generator-supplied answer paths",
                  bound_execution["pool_paths"] == tuple(spec_paths)
                  and tuple(bound_execution["pool_specs"]) == tuple(ws)
                  and inspections_after_success == inspections_before + 1
                  and wrong_size_refused
                  and mismatched_campaign_refused
                  and len(live_inspections) == inspections_after_success
                  and any(live and result_path in paths
                          for live, paths, _protected, _indices, _row
                          in execution_preflights)
                  and any(not live and "/private/docker" in protected
                          and "/usr/bin/docker" in protected
                          for live, _paths, protected, _indices, _row
                          in execution_preflights))

            # The project's row travels with the pool: `validate_live_worker_
            # runtime` is what every live verb goes through, and the live
            # half of the preflight it runs is where the DSN variable name
            # is read.
            row_preflights = []
            globals()["preflight"] = fixture_execution_preflight
            try:
                execution_preflights.clear()
                validate_live_worker_runtime(
                    spec_paths[0], ws[0], "fixture-harness-v1", True, (),
                    expected_pool_size=4, behat=sylius_pool_row)
                row_preflights = list(execution_preflights)
            finally:
                globals()["preflight"] = real_execution_preflight
            check("[sylius] the caller's row reaches the LIVE preflight of "
                  "the authenticated pool",
                  [row for live, _p, _c, _i, row in row_preflights if live]
                  == [sylius_pool_row])

            def authority_containment_refusal(
                    _workers, _paths, *, live=True, **kwargs):
                protected = kwargs.get("containment_paths", ())
                if not live and "/private/docker" in protected:
                    raise WorkerRefused(
                        "REFUSED: forced authority/workspace containment")
                return {"workers": 4}

            globals()["preflight"] = authority_containment_refusal
            inspections_before = len(live_inspections)
            try:
                authority_containment_refused = refused(
                    lambda: validate_live_worker_runtime(
                        spec_paths[0], ws[0], "fixture-harness-v1", True,
                        (), expected_pool_size=4))
            finally:
                globals()["preflight"] = real_execution_preflight
            check("authority-derived client/socket/data-root paths reach the "
                  "static containment gate before Docker inspection",
                  authority_containment_refused
                  and len(live_inspections) == inspections_before)
            bad_answer = os.path.join(ws[0].workspace, "future-results.jsonl")
            inspections_before = len(live_inspections)
            check("ordinary live execution refuses static answer/workspace "
                  "containment before authority or Docker inspection",
                  refused(lambda: validate_live_worker_runtime(
                      spec_paths[0], ws[0], "fixture-harness-v1", True,
                      (bad_answer,), expected_pool_size=4))
                  and len(live_inspections) == inspections_before)
            first_att = runtime_attestation_path(spec_paths[0])
            with open(first_att, encoding="utf-8") as fh:
                current_attestation = json.load(fh)
            malformed = []
            bad = json.loads(json.dumps(current_attestation))
            bad["harness_version"] = True
            malformed.append(bad)
            bad = json.loads(json.dumps(current_attestation))
            bad["worker"]["workspace"] = "relative/workspace"
            malformed.append(bad)
            bad = json.loads(json.dumps(current_attestation))
            bad["seed_dir"] = ["not", "a", "path"]
            malformed.append(bad)
            malformed_refused = True
            for document in malformed:
                with open(first_att, "w", encoding="utf-8") as fh:
                    json.dump(document, fh, sort_keys=True)
                malformed_refused = malformed_refused and refused(
                    lambda: validate_worker_runtime_v3(spec_paths[0]))
            with open(first_att, "w", encoding="utf-8") as fh:
                json.dump(current_attestation, fh, sort_keys=True)
            check("v3 schema types and absolute worker paths refuse before "
                  "dereference", malformed_refused)

            os.makedirs(ws[0].workspace, exist_ok=True)
            inside_binding = os.path.join(ws[0].workspace, "binding.json")
            _A.write_evidence_no_clobber(inside_binding, bindings[0])
            _inside_doc, inside_ref = _A.evidence_reference(
                inside_binding, expected_schema=_A.BINDING_SCHEMA,
                validator=_A.validate_binding_document,
                label="workspace-contained binding fixture")
            moved_reference = json.loads(json.dumps(current_attestation))
            moved_reference["docker_execution_binding"] = inside_ref
            with open(first_att, "w", encoding="utf-8") as fh:
                json.dump(moved_reference, fh, sort_keys=True)
            check("shared offline v3 validation refuses authenticated "
                  "evidence inside a worker workspace",
                  refused(lambda: validate_offline_worker_runtime_pool(
                      spec_paths)))
            with open(first_att, "w", encoding="utf-8") as fh:
                json.dump(current_attestation, fh, sort_keys=True)
            v2_attestation = {
                key: value for key, value in current_attestation.items()
                if key in WORKER_RUNTIME_FIELDS_V1
            }
            v2_attestation["schema"] = WORKER_RUNTIME_SCHEMA_V2
            v2_attestation["docker_endpoint_selection"] = "legacy-default"
            v1_attestation = {
                key: value for key, value in v2_attestation.items()
                if key != "docker_endpoint_selection"
            }
            v1_attestation["schema"] = WORKER_RUNTIME_SCHEMA_V1
            relabelled_v1 = {**v1_attestation,
                             "docker_endpoint_selection": "legacy-default"}
            check("v1/v2 remain exact offline identities without relabelling",
                  worker_runtime_version(current_attestation) == "v3"
                  and worker_runtime_version(v2_attestation) == "v2"
                  and worker_runtime_version(v1_attestation) == "v1"
                  and worker_runtime_version(relabelled_v1) is None)
            with open(first_att, "w", encoding="utf-8") as fh:
                json.dump(v2_attestation, fh, sort_keys=True)
            inspections_before = len(live_inspections)
            check("live work refuses historical v2 before Docker inspection",
                  refused(lambda: validate_mutation_runtime(
                      spec_paths, ws, seed_dir, "fixture-harness-v1", True))
                  and len(live_inspections) == inspections_before)
            with open(first_att, "w", encoding="utf-8") as fh:
                json.dump(current_attestation, fh, sort_keys=True)
            changed = dict(current_attestation)
            changed["harness_version"] = "other-harness"
            with open(first_att, "w", encoding="utf-8") as fh:
                json.dump(changed, fh, sort_keys=True)
            inspections_before = len(live_inspections)
            check("stale v3 harness refuses before Docker inspection",
                  refused(lambda: validate_mutation_runtime(
                      spec_paths, ws, seed_dir, "fixture-harness-v1", True))
                  and len(live_inspections) == inspections_before)
            with open(first_att, "w", encoding="utf-8") as fh:
                json.dump(current_attestation, fh, sort_keys=True)
        finally:
            globals()["capture_execution_bindings"] = real_capture
            _D.configure()
        check("complete v3 pools validate offline with no configured "
              "authority",
              len(validate_offline_worker_runtime_pool(spec_paths)) == 4)
        import shutil as _shutil
        os.makedirs(ws[0].workspace, exist_ok=True)
        nested_seed = os.path.join(ws[0].workspace, "nested-seed")
        _shutil.copytree(seed_dir, nested_seed)
        saved_runtime_docs = []
        for path in spec_paths:
            att_path = runtime_attestation_path(path)
            with open(att_path, encoding="utf-8") as fh:
                document = json.load(fh)
            saved_runtime_docs.append((att_path, document))
            changed_document = json.loads(json.dumps(document))
            changed_document["seed_dir"] = os.path.realpath(nested_seed)
            with open(att_path, "w", encoding="utf-8") as fh:
                json.dump(changed_document, fh, sort_keys=True)
        inspections_before_nested_seed = len(live_inspections)
        nested_seed_refused = refused(
            lambda: validate_offline_worker_runtime_pool(spec_paths))
        for att_path, document in saved_runtime_docs:
            with open(att_path, "w", encoding="utf-8") as fh:
                json.dump(document, fh, sort_keys=True)
        check("v3 seed evidence inside a worker workspace refuses offline "
              "before Docker inspection",
              nested_seed_refused
              and len(live_inspections) == inspections_before_nested_seed)
        seed_alias = os.path.join(ws[0].workspace, "workspace-seed-alias")
        os.link(os.path.join(seed_dir, "workspace.tar"), seed_alias)
        inspections_before_seed_alias = len(live_inspections)
        try:
            seed_alias_refused = refused(
                lambda: validate_offline_worker_runtime_pool(spec_paths))
        finally:
            os.unlink(seed_alias)
        check("a seed artifact hard-linked into a workspace refuses offline "
              "before Docker inspection",
              seed_alias_refused
              and len(live_inspections) == inspections_before_seed_alias)
        second_att = runtime_attestation_path(spec_paths[1])
        with open(second_att, encoding="utf-8") as fh:
            second_runtime = json.load(fh)
        mixed_snapshots_refuse = True
        for variant_name in ("timestamp", "other-member"):
            variant = json.loads(json.dumps(bindings[1]))
            if variant_name == "timestamp":
                variant["captured_at_utc"] = "2026-08-06T00:00:01Z"
            else:
                for members_key in ("expected_members", "observed_members"):
                    for member in variant["network_policy"][members_key]:
                        if member["role"] == "worker" \
                                and member["worker_index"] == 0:
                            member["image_id"] = "sha256:" + "e" * 64
            variant["digest"] = _A.semantic_digest(variant)
            variant_path = os.path.join(
                root, f"worker1.{variant_name}.binding.json")
            _A.write_evidence_no_clobber(variant_path, variant)
            _variant_doc, variant_ref = _A.evidence_reference(
                variant_path, expected_schema=_A.BINDING_SCHEMA,
                validator=_A.validate_binding_document,
                label=f"{variant_name} binding fixture")
            runtime_variant = json.loads(json.dumps(second_runtime))
            runtime_variant["docker_execution_binding"] = variant_ref
            with open(second_att, "w", encoding="utf-8") as fh:
                json.dump(runtime_variant, fh, sort_keys=True)
            mixed_snapshots_refuse = mixed_snapshots_refuse \
                and validate_worker_runtime_v3(spec_paths[1])["binding"] \
                == variant \
                and refused(lambda: validate_offline_worker_runtime_pool(
                    spec_paths))
            with open(second_att, "w", encoding="utf-8") as fh:
                json.dump(second_runtime, fh, sort_keys=True)
        check("offline pool refuses mixed capture instants and contradictory "
              "complete network snapshots", mixed_snapshots_refuse)
        check("K < 1 is refused", refused(lambda: plan_workers(root, 0)))

        # Preflight: the static half, which is the one a configuration
        # mistake trips.
        answers = [os.path.join(root, "gold")]
        os.makedirs(answers[0])
        check("cleanly derived workers pass preflight",
              preflight(ws, answers, live=False)["workers"] == 4)

        from . import cli as _CLI
        with patch.dict(os.environ, {"R2T_DATA_ROOT": root}):
            default_gold = os.fspath(_CLI.DEFAULT_GOLD)
            default_release_gold = os.path.join(
                os.fspath(_CLI.DEFAULT_ARTIFACTS), "release", "gold")
            os.makedirs(default_gold)
            os.makedirs(default_release_gold)
            with open(os.path.join(default_release_gold, "manifest.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({}, fh)
            default_report = preflight(
                ws,
                default_answer_paths(
                    _CLI.DEFAULT_GOLD, _CLI.DEFAULT_ARTIFACTS,
                    os.path.join(_CLI.DEFAULT_ARTIFACTS, "release")),
                live=False)
            rendered_report = json.dumps(default_report)
        check("the real default DataPath yields a JSON preflight report with "
              "string paths and protects installed release gold",
              isinstance(rendered_report, str)
              and default_gold in default_report["checked_answer_paths"]
              and default_release_gold
              in default_report["checked_answer_paths"]
              and all(isinstance(path, str) for path in
                      default_report["checked_answer_paths"]))

        clash = list(ws[:3]) + [WorkerSpec(**{**ws[3].to_json(),
                                              "schema": ws[0].schema})]
        check("two workers sharing a schema are refused",
              refused(lambda: preflight(clash, answers, live=False)))
        clash2 = list(ws[:3]) + [WorkerSpec(**{**ws[3].to_json(),
                                               "workspace": ws[1].workspace})]
        check("two workers sharing a workspace are refused",
              refused(lambda: preflight(clash2, answers, live=False)))
        cross_env = list(ws)
        cross_env[0] = WorkerSpec(**{
            **ws[0].to_json(),
            "env_file": os.path.join(ws[1].workspace, "worker0.env"),
        })
        check("one worker's credential file cannot be exposed inside "
              "another worker's workspace",
              refused(lambda: preflight(cross_env, answers, live=False)))
        clash3 = list(ws[:3]) + [WorkerSpec(**{**ws[3].to_json(),
                                               "container": ws[2].container})]
        check("two workers sharing a container are refused",
              refused(lambda: preflight(clash3, answers, live=False)))
        clash4 = list(ws[:3]) + [WorkerSpec(**{**ws[3].to_json(),
                                              "credential": ws[0].credential})]
        check("two workers sharing a credential identity are refused",
              refused(lambda: preflight(clash4, answers, live=False)))
        check("a gap in the worker indices is refused",
              refused(lambda: preflight([ws[0], ws[2]], answers, live=False)))

        # Preflight: the answer-reachability half.
        inside = WorkerSpec(**{**ws[0].to_json(),
                               "workspace": os.path.join(root, "outer")})
        os.makedirs(os.path.join(root, "outer", "gold"), exist_ok=True)
        check("an answer-bearing path inside a workspace is refused",
              refused(lambda: preflight(
                  [inside], [os.path.join(root, "outer", "gold")], live=False)))
        check("a planned output inside a workspace is refused before the "
              "output exists",
              refused(lambda: preflight(
                  [inside], [os.path.join(root, "outer", "future-output")],
                  live=False)))
        protected_file = os.path.join(answers[0], "answer-key.json")
        with open(protected_file, "w", encoding="utf-8") as fh:
            fh.write("{}")
        os.makedirs(ws[0].workspace, exist_ok=True)
        protected_alias = os.path.join(ws[0].workspace, "answer-key-alias")
        os.link(protected_file, protected_alias)
        try:
            hardlink_refused = refused(
                lambda: preflight(ws, answers, live=False))
        finally:
            os.unlink(protected_alias)
        check("a hard-link alias can never place an answer-bearing regular "
              "file inside a worker tree",
              hardlink_refused)
        daemon_root = os.path.join(root, "daemon-data")
        os.makedirs(daemon_root)
        daemon_file = os.path.join(daemon_root, "runtime")
        with open(daemon_file, "w", encoding="utf-8") as fh:
            fh.write("runtime")
        os.link(daemon_file, os.path.join(daemon_root, "runtime-alias"))
        check("containment-only roots may contain legitimate hard links",
              preflight(ws, answers, containment_paths=[daemon_root],
                        live=False)["workers"] == 4)
        nested_protected = WorkerSpec(**{
            **ws[0].to_json(),
            "workspace": os.path.join(daemon_root, "worker"),
        })
        check("containment-only roots still exclude worker workspaces",
              refused(lambda: preflight(
                  [nested_protected], answers,
                  containment_paths=[daemon_root], live=False)))
        nested = WorkerSpec(**{**ws[1].to_json(),
                               "workspace": os.path.join(answers[0], "app")})
        check("a workspace inside the gold tree is refused",
              refused(lambda: preflight([nested], answers, live=False)))
        exposed = WorkerSpec(**{**ws[0].to_json(),
                                "env_file": os.path.join(ws[0].workspace,
                                                         "worker.env")})
        check("a credential file inside its own workspace is refused",
              refused(lambda: preflight([exposed], answers, live=False)))

        # Live preflight must refuse what it cannot see (P1-5).
        for worker in ws:
            os.makedirs(os.path.dirname(worker.env_file), exist_ok=True)
            os.chmod(os.path.dirname(worker.env_file), 0o700)
            fd = os.open(worker.env_file,
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.close(fd)
        real_mounts = globals()["mounts_of"]

        def fixture_runtime_env(worker, *, dsn_worker=None,
                                index=None, dsn="valid",
                                install_password="fixture-secret"):
            target = dsn_worker or worker
            dsn_value = (
                f"mysql://{target.credential}:fixture-secret@"
                f"{DEFAULT_DB_CONTAINER}:3306/{target.schema}"
                if dsn == "valid" else dsn)
            return _safe_runtime_env([
                f"R2T_WORKER_INDEX={worker.index if index is None else index}",
                f"PIMCORE_TEST_DB_DSN={dsn_value}",
                f"PIMCORE_INSTALL_MYSQL_USERNAME={worker.credential}",
                f"PIMCORE_INSTALL_MYSQL_PASSWORD={install_password}",
                f"PIMCORE_INSTALL_MYSQL_DATABASE={worker.schema}",
                f"PIMCORE_INSTALL_MYSQL_HOST_SOCKET={DEFAULT_DB_CONTAINER}",
            ])

        def absent(container, docker_group=True, behat=None):
            return {"exists": False, "mounts": [], "env_keys": []}

        def stopped(container, docker_group=True, behat=None):
            return {"exists": True, "running": False, "mounts": [],
                    "env_keys": [], "docker_socket": False}

        def wrong_mount(container, docker_group=True, behat=None):
            return {"exists": True, "running": True,
                    "mounts": [("/somewhere/else", "/var/www/html")],
                    "env_keys": [], "docker_socket": False}

        def right_mount(container, docker_group=True, behat=None):
            idx = int(container.rsplit("_", 1)[1])
            return {"exists": True, "running": True,
                    "mounts": [(ws[idx].workspace, ws[idx].workdir)],
                    "mount_details": [{
                        "source": ws[idx].workspace,
                        "destination": ws[idx].workdir,
                        "type": "bind", "rw": True,
                    }],
                    "env_keys": [], "docker_socket": False,
                    "runtime_env": fixture_runtime_env(ws[idx])}

        for name, stub, label in (
                ("absent", absent, "a container that cannot be inspected"),
                ("stopped", stopped, "a container that exists but is stopped"),
                ("wrong", wrong_mount, "a container mounting the wrong "
                                       "workspace")):
            globals()["mounts_of"] = stub
            try:
                check(f"live preflight refuses {label}",
                      refused(lambda: preflight(ws, answers, live=True)))
            finally:
                globals()["mounts_of"] = real_mounts

        globals()["mounts_of"] = right_mount
        try:
            check("live preflight passes when every container is running with "
                  "its own workspace and DB identity",
                  preflight(ws, answers, live=True)["workers"] == 4)
        finally:
            globals()["mounts_of"] = real_mounts

        # -- the same containers, provisioned from a project whose row names
        # its database otherwise.
        #
        # The live half reads the DSN out of the container BY VARIABLE NAME,
        # so a pool that is correctly configured for Sylius has no
        # `PIMCORE_TEST_DB_DSN` and was refused as a broken pool.  Both
        # directions are pinned: with the row there is nothing to object to,
        # and without it the identical containers are refused -- which is
        # what makes the row do work rather than nothing.
        def sylius_mount(container, docker_group=True, behat=None):
            idx = int(container.rsplit("_", 1)[1])
            info = right_mount(container, docker_group=docker_group)
            info["runtime_env"] = _safe_runtime_env([
                f"R2T_WORKER_INDEX={ws[idx].index}",
                f"DATABASE_URL=mysql://{ws[idx].credential}:fixture-secret@"
                f"{DEFAULT_DB_CONTAINER}:3306/{ws[idx].schema}"
                f"?charset=utf8mb4",
            ], behat)
            return info

        globals()["mounts_of"] = sylius_mount
        try:
            check("[sylius] live preflight passes a pool whose workers carry "
                  "the DSN variable THEIR project names",
                  preflight(ws, answers, live=True,
                            behat=sylius_pool_row)["workers"] == 4)
            check("[sylius] ...and the same pool read as CoreShop's is "
                  "refused, so the row is what accepted it",
                  refused(lambda: preflight(ws, answers, live=True)))
        finally:
            globals()["mounts_of"] = real_mounts

        credential_alias = os.path.join(ws[0].workspace, "credential-alias")
        os.makedirs(ws[0].workspace, exist_ok=True)
        os.link(ws[0].env_file, credential_alias)
        globals()["mounts_of"] = right_mount
        try:
            check("a credential hard-linked into a workspace refuses live",
                  refused(lambda: preflight(ws, answers, live=True)))
        finally:
            globals()["mounts_of"] = real_mounts
            os.unlink(credential_alias)

        def composer_mount(container, docker_group=True, behat=None, *, rw=False):
            report = right_mount(container, docker_group=docker_group)
            report["mounts"] = [
                *report["mounts"], (cache, "/composer-cache")]
            report["mount_details"] = [
                *report["mount_details"], {
                    "source": cache, "destination": "/composer-cache",
                    "type": "bind", "rw": rw,
                }]
            return report

        globals()["mounts_of"] = lambda container, docker_group=True, behat=None: \
            composer_mount(container, docker_group=docker_group, rw=False)
        try:
            check("live preflight accepts a read-only Composer host bind",
                  preflight(ws, answers, live=True)["workers"] == 4)
        finally:
            globals()["mounts_of"] = real_mounts

        def credential_cache_mount(container, docker_group=True, behat=None):
            report = right_mount(container, docker_group=docker_group)
            secrets = os.path.dirname(ws[0].env_file)
            report["mounts"] = [
                *report["mounts"], (secrets, "/composer-cache")]
            report["mount_details"] = [*report["mount_details"], {
                "source": secrets, "destination": "/composer-cache",
                "type": "bind", "rw": False,
            }]
            return report

        globals()["mounts_of"] = credential_cache_mount
        try:
            check("a read-only cache bind cannot expose worker credentials",
                  refused(lambda: preflight(ws, answers, live=True)))
        finally:
            globals()["mounts_of"] = real_mounts
        globals()["mounts_of"] = lambda container, docker_group=True, behat=None: \
            composer_mount(container, docker_group=docker_group, rw=True)
        try:
            check("live preflight refuses a writable Composer host bind",
                  refused(lambda: preflight(ws, answers, live=True)))
        finally:
            globals()["mounts_of"] = real_mounts

        no_db_worker = WorkerSpec(**{
            **ws[0].to_json(), "schema": "", "credential": "",
        })

        def no_db_mount(container, docker_group=True, behat=None, *, composer=False):
            mounts = [(no_db_worker.workspace, no_db_worker.workdir)]
            details = [{
                "source": no_db_worker.workspace,
                "destination": no_db_worker.workdir,
                "type": "bind", "rw": True,
            }]
            if composer:
                mounts.append((cache, "/composer-cache"))
                details.append({
                    "source": cache, "destination": "/composer-cache",
                    "type": "bind", "rw": False,
                })
            return {
                "exists": True, "running": True, "mounts": mounts,
                "mount_details": details, "env_keys": [],
                "runtime_env": _safe_runtime_env(["R2T_WORKER_INDEX=0"]),
            }

        globals()["mounts_of"] = lambda container, docker_group=True, behat=None: \
            no_db_mount(container, docker_group=docker_group, composer=False)
        try:
            no_db_without_cache_passes = preflight(
                [no_db_worker], answers, live=True,
                needs_database=False)["workers"] == 1
        finally:
            globals()["mounts_of"] = real_mounts
        globals()["mounts_of"] = lambda container, docker_group=True, behat=None: \
            no_db_mount(container, docker_group=docker_group, composer=True)
        try:
            check("no-database live preflight accepts no cache and refuses "
                  "even a read-only Composer cache",
                  no_db_without_cache_passes
                  and refused(lambda: preflight(
                      [no_db_worker], answers, live=True,
                      needs_database=False)))
        finally:
            globals()["mounts_of"] = real_mounts

        def agent_jar_mount(container, docker_group=True, behat=None, *, rw=False):
            report = right_mount(container, docker_group=docker_group)
            jar = os.path.join(root, "r2t-direct-calls-agent.jar")
            report["mounts"] = [*report["mounts"], (jar, AGENT_JAR_RUNTIME)]
            report["mount_details"] = [*report["mount_details"], {
                "source": jar, "destination": AGENT_JAR_RUNTIME,
                "type": "bind", "rw": rw,
            }]
            return report

        globals()["mounts_of"] = lambda container, docker_group=True, behat=None: \
            agent_jar_mount(container, docker_group=docker_group, rw=False)
        try:
            check("live preflight accepts the direct-invocation agent jar as "
                  "a read-only host bind at its runtime path",
                  preflight(ws, answers, live=True)["workers"] == 4)
        finally:
            globals()["mounts_of"] = real_mounts
        globals()["mounts_of"] = lambda container, docker_group=True, behat=None: \
            agent_jar_mount(container, docker_group=docker_group, rw=True)
        try:
            check("...and refuses it writable",
                  refused(lambda: preflight(ws, answers, live=True)))
        finally:
            globals()["mounts_of"] = real_mounts

        def unexpected_read_only_mount(container, docker_group=True, behat=None):
            report = right_mount(container, docker_group=docker_group)
            source = os.path.join(root, "unreviewed-host-input")
            report["mounts"] = [*report["mounts"], (source, "/host-input")]
            report["mount_details"] = [*report["mount_details"], {
                "source": source, "destination": "/host-input",
                "type": "bind", "rw": False,
            }]
            return report

        globals()["mounts_of"] = unexpected_read_only_mount
        try:
            check("live preflight refuses an unreviewed read-only host bind",
                  refused(lambda: preflight(ws, answers, live=True)))
        finally:
            globals()["mounts_of"] = real_mounts

        nonstandard_authority = json.loads(json.dumps(authority_doc))
        nonstandard_socket = "/run/user/1001/r2t/control.endpoint"
        nonstandard_address = _A.endpoint_address(nonstandard_socket)
        nonstandard_authority["endpoint"].update({
            "selection_identity": "host:" + nonstandard_address,
            "address": nonstandard_address,
            "address_sha256": _A.endpoint_address_digest(
                nonstandard_address),
        })
        nonstandard_authority["adapter"]["selected_socket_path"] = (
            nonstandard_socket)
        nonstandard_authority["adapter"]["resolved_socket_path"] = (
            nonstandard_socket)
        nonstandard_authority["digest"] = _A.semantic_digest(
            nonstandard_authority)
        nonstandard_ref = {
            **authority_ref, "digest": nonstandard_authority["digest"]}

        def authority_mount(container, docker_group=True, behat=None):
            report = right_mount(container, docker_group=docker_group)
            report["mounts"] = [
                *report["mounts"],
                (nonstandard_socket,
                 "/run/control.endpoint"),
                ("/usr", "/host-usr"),
            ]
            return report

        def data_root_mount(container, docker_group=True, behat=None):
            report = right_mount(container, docker_group=docker_group)
            report["mounts"] = [
                *report["mounts"],
                (os.path.dirname(
                    nonstandard_authority["daemon"]["docker_root_dir"]),
                 "/host-daemon-storage"),
            ]
            return report

        _D._install_test_authority(nonstandard_authority, nonstandard_ref)
        globals()["mounts_of"] = authority_mount
        try:
            check("live preflight refuses the exact authority socket and "
                  "selected client even when neither mount ends in "
                  "docker.sock",
                  refused(lambda: preflight(ws, answers, live=True)))
        finally:
            globals()["mounts_of"] = real_mounts
            _D.configure()

        _D._install_test_authority(nonstandard_authority, nonstandard_ref)
        globals()["mounts_of"] = data_root_mount
        try:
            check("live preflight refuses a mount containing the authority "
                  "Docker data root",
                  refused(lambda: preflight(ws, answers, live=True)))
        finally:
            globals()["mounts_of"] = real_mounts
            _D.configure()

        safe_projection = fixture_runtime_env(ws[0])
        check("the live environment projection contains no DSN or password",
              "fixture-secret" not in json.dumps(safe_projection)
              and "mysql://" not in json.dumps(safe_projection),
              json.dumps(safe_projection, sort_keys=True))
        wrong_db_projection = fixture_runtime_env(
            ws[0], dsn_worker=ws[1])
        check("a matching image/mount with another worker's DSN is refused",
              bool(_runtime_env_binding_problems(
                  ws[0], wrong_db_projection, True)))
        malformed_projection = fixture_runtime_env(
            ws[0], dsn="not-a-dsn")
        check("a missing or malformed live DSN is refused without echoing it",
              bool(_runtime_env_binding_problems(
                  ws[0], malformed_projection, True))
              and "not-a-dsn" not in json.dumps(malformed_projection))
        mismatched_secret_projection = fixture_runtime_env(
            ws[0], install_password="another-secret")
        check("different DSN/install password channels are refused without "
              "persisting either secret",
              bool(_runtime_env_binding_problems(
                  ws[0], mismatched_secret_projection, True))
              and "secret" not in json.dumps(mismatched_secret_projection))
        wrong_index_projection = fixture_runtime_env(ws[0], index=1)
        check("a live worker index that differs from its spec is refused",
              bool(_runtime_env_binding_problems(
                  ws[0], wrong_index_projection, True)))
        check("a successful-looking DB probe for another worker is refused",
              refused(lambda: _bind_probe_identity({
                  "pass": True, "principal": ws[1].credential,
                  "own_schema": ws[1].schema,
              }, ws[0])))
        probe_secret = "SENTINEL-PROBE-PASSWORD"
        malformed_probe = _safe_probe_output(
            f"worker printed {probe_secret} and no JSON", ws[0], ws[1].schema)
        check("malformed probe output is reduced to a content-free failure",
              malformed_probe["pass"] is False
              and probe_secret not in json.dumps(malformed_probe)
              and "stdout" not in malformed_probe
              and "stderr" not in malformed_probe)
        denied_check = {
            "denied": True,
            "error": f"Access denied using password {probe_secret}",
        }
        parsed_probe_doc = {
            "principal": ws[0].credential,
            "own_schema": ws[0].schema,
            "visible_schemas": [f"schema_{probe_secret}"],
            "checks": {
                "own_schema_select": {"denied": False, "error": None},
                **{name: dict(denied_check) for name in REQUIRED_DENIED},
            },
        }
        parsed_probe = _safe_probe_output(
            json.dumps(parsed_probe_doc), ws[0], ws[1].schema)
        check("parsed probe errors and schema names cannot carry a password "
              "into the operator report",
              parsed_probe["pass"] is True
              and probe_secret not in json.dumps(parsed_probe)
              and "checks" not in parsed_probe
              and parsed_probe["non_system_schema_count"] == 1)

        # The credential file itself.
        w = ws[0]
        write_env_file(w, "s3cret-pw", {"PIMCORE_INSTANCE_IDENTIFIER": "x"})
        mode = stat.S_IMODE(os.stat(w.env_file).st_mode)
        body = open(w.env_file, encoding="utf-8").read()
        check("the credential file is mode 0600", mode == 0o600, oct(mode))
        check("its directory is mode 0700",
              stat.S_IMODE(os.stat(os.path.dirname(w.env_file)).st_mode) == 0o700)
        check("the DSN names the worker's own principal and schema",
              f"mysql://{w.credential}:s3cret-pw@" in body
              and body.strip().endswith(w.schema) is False
              and f"/{w.schema}\n" in body, body)
        check("the worker index is exported for a run stamp to pick up",
              f"R2T_WORKER_INDEX={w.index}\n" in body)
        check("a value containing a newline is refused, not truncated",
              refused(lambda: write_env_file(w, "pw", {"X": "a\nb"})))
        check("the password is nowhere in the worker RECORD",
              "s3cret-pw" not in json.dumps(w.to_json()))

        # -- the same file for a project that names its database otherwise.
        #
        # CoreShop's five variables are pinned as a KEY SET rather than
        # described, because the row must not be able to add or drop one:
        # a worker whose env file lost `PIMCORE_INSTALL_MYSQL_DATABASE`
        # installs into whatever schema the template carried, which is one
        # schema for K workers.
        check("[coreshop] the row leaves the credential file's key set "
              "exactly as it was",
              sorted(line.split("=", 1)[0]
                     for line in body.strip().split("\n"))
              == ["PIMCORE_INSTALL_MYSQL_DATABASE",
                  "PIMCORE_INSTALL_MYSQL_HOST_SOCKET",
                  "PIMCORE_INSTALL_MYSQL_PASSWORD",
                  "PIMCORE_INSTALL_MYSQL_USERNAME",
                  "PIMCORE_INSTANCE_IDENTIFIER",
                  "PIMCORE_TEST_DB_DSN",
                  "R2T_WORKER_INDEX"], body)
        check("[coreshop] ...and its DSN carries no query suffix",
              f"PIMCORE_TEST_DB_DSN=mysql://{w.credential}:s3cret-pw@"
              f"{DEFAULT_DB_CONTAINER}:3306/{w.schema}\n" in body, body)

        sylius_row = BehatProject(
            db_dsn_env="DATABASE_URL", db_dsn_suffix="?charset=utf8mb4",
            db_install_vars=False)
        write_env_file(w, "s3cret-pw", {"APP_ENV": "test_cached"},
                       behat=sylius_row)
        sbody = open(w.env_file, encoding="utf-8").read()
        check("[sylius] the DSN is DATABASE_URL, with Doctrine's charset "
              "query, naming this worker's own principal and schema",
              f"DATABASE_URL=mysql://{w.credential}:s3cret-pw@"
              f"{DEFAULT_DB_CONTAINER}:3306/{w.schema}?charset=utf8mb4\n"
              in sbody, sbody)
        check("[sylius] and NO Pimcore install variable is emitted -- there "
              "is no second installer to read one",
              "PIMCORE" not in sbody
              and sorted(line.split("=", 1)[0]
                         for line in sbody.strip().split("\n"))
              == ["APP_ENV", "DATABASE_URL", "R2T_WORKER_INDEX"], sbody)
        check("[sylius] it is still mode 0600",
              stat.S_IMODE(os.stat(w.env_file).st_mode) == 0o600)

        # The read-back half: the live preflight has to look for the SAME
        # variable it baked, or a healthy Sylius worker reads as one with
        # no database at all.
        sylius_env = [f"R2T_WORKER_INDEX={w.index}",
                      f"DATABASE_URL=mysql://{w.credential}:s3cret-pw@"
                      f"{DEFAULT_DB_CONTAINER}:3306/{w.schema}"
                      f"?charset=utf8mb4"]
        sylius_projection = _safe_runtime_env(sylius_env, sylius_row)
        check("[sylius] the safe projection reads the row's DSN, and still "
              "never returns the password",
              sylius_projection["dsn_valid"] is True
              and sylius_projection["dsn_principal"] == w.credential
              and sylius_projection["dsn_schema"] == w.schema
              and "s3cret-pw" not in json.dumps(sylius_projection),
              str(sylius_projection))
        check("[sylius] a coherent worker passes the live binding check on "
              "the one channel it has",
              not _runtime_env_binding_problems(w, sylius_projection, True,
                                                sylius_row),
              str(_runtime_env_binding_problems(w, sylius_projection, True,
                                                sylius_row)))
        check("[sylius] ...and the same environment read under CoreShop's "
              "row is refused, so the row is doing work rather than nothing",
              bool(_runtime_env_binding_problems(
                  w, _safe_runtime_env(sylius_env), True)))
        wrong = _safe_runtime_env(
            [f"R2T_WORKER_INDEX={w.index}",
             f"DATABASE_URL=mysql://someone_else:s3cret-pw@"
             f"{DEFAULT_DB_CONTAINER}:3306/{w.schema}?charset=utf8mb4"],
            sylius_row)
        check("[sylius] a DSN naming another principal is still refused",
              bool(_runtime_env_binding_problems(w, wrong, True, sylius_row)))

        # -- and the host in that DSN is the PUBLISHED ALIAS, not the
        # database container's own name.
        #
        # Worth pinning because getting it wrong is invisible until a
        # scenario runs: the DSN parses, the worker starts, and every item
        # then fails to connect to a name that is not published on this
        # pool's network.  The lifecycle names the database container with a
        # per-pool nonce and publishes `descriptor.database.alias` for it, so
        # the fixture database below is deliberately NOT called
        # `coreshop_db`: a fixture that reuses the alias as its container
        # name cannot tell the two apart.  The seed, the daemon and the
        # workspace are fixtures here; the argument is what is under test.
        from types import SimpleNamespace as _NS
        from . import seed as _seed_module

        class _FixtureDB:
            def __init__(self, container):
                self.container = container

            def drop_schema(self, schema):
                pass

            def create_schema(self, schema):
                pass

            def load(self, schema, path):
                pass

            def table_bytes(self, schema):
                return {f"t{i}": 1 for i in range(252)}

            def create_worker_principal(self, credential, password, schema):
                return {"principal": credential}

        _patched = ("require_container_absent", "unpack_workspace",
                    "_docker", "mounts_of")
        _real = {name: globals()[name] for name in _patched}
        _real_verify = _seed_module.verify_seed
        try:
            globals()["require_container_absent"] = lambda *a, **k: None
            globals()["unpack_workspace"] = lambda *a, **k: {"files": 0}
            globals()["_docker"] = lambda argv, **k: _NS(
                returncode=0, stdout="", stderr="")
            globals()["mounts_of"] = lambda *a, **k: {"exists": True}
            _seed_module.verify_seed = lambda *a, **k: {
                "artifacts_ok": True, "needs_database": True,
                "seed_key": "fixture"}
            seed_dir = os.path.join(root, "fixture-seed")
            # The seed's own dump, which is what a complete load is measured
            # against.  Its 37 views are written in BOTH of `mysqldump`'s
            # spellings -- the placeholder standing where the view's table
            # would be, and the final definition after the algorithm and
            # security comments -- because counting STATEMENTS would make
            # this schema 289 and refuse the load that is exactly right.
            os.makedirs(seed_dir, exist_ok=True)
            with open(os.path.join(seed_dir, "database.sql"), "w",
                      encoding="utf-8") as _dump:
                for _i in range(215):
                    _dump.write(f"CREATE TABLE `t{_i}` (`id` int);\n")
                for _i in range(37):
                    _dump.write(f"/*!50001 CREATE VIEW `v{_i}` AS SELECT \n"
                                f" 1 AS `id`*/;\n")
                for _i in range(37):
                    _dump.write(
                        "/*!50001 CREATE ALGORITHM=UNDEFINED */\n"
                        "/*!50013 SQL SECURITY INVOKER */\n"
                        f"/*!50001 VIEW `v{_i}` AS select 1 AS `id` */;\n")
            empty_seed_dir = os.path.join(root, "fixture-seed-empty")
            os.makedirs(empty_seed_dir, exist_ok=True)
            with open(os.path.join(empty_seed_dir, "database.sql"), "w",
                      encoding="utf-8") as _dump:
                _dump.write("-- a dump that creates nothing\n")
            nonce_db = _FixtureDB("r2t_nonce_database")
            provision(w, seed_dir, nonce_db,
                      network=None, overrides={"APP_ENV": "test"},
                      docker_group=False)
            coreshop_body = open(w.env_file, encoding="utf-8").read()
            provision(w, seed_dir, nonce_db, network=None,
                      overrides={"APP_ENV": "test_cached"},
                      docker_group=False, behat=sylius_row)
            sylius_body = open(w.env_file, encoding="utf-8").read()
            provision(w, seed_dir, nonce_db, network=None,
                      overrides={"APP_ENV": "test"},
                      docker_group=False, db_host="other_host")
            explicit_body = open(w.env_file, encoding="utf-8").read()

            # A load whose views never arrived -- which is what a dump
            # carrying a `DEFINER` the workers do not have produces, and
            # which the 100-table floor accepted.
            class _ViewlessDB(_FixtureDB):
                def table_bytes(self, schema):
                    return {f"t{i}": 1 for i in range(215)}

            def _provision_refusal(db, seed=seed_dir, **kw):
                try:
                    provision(w, seed, db, network=None,
                              overrides={"APP_ENV": "test"},
                              docker_group=False, **kw)
                    return "accepted"
                except WorkerRefused as exc:
                    return str(exc)

            partial_message = _provision_refusal(
                _ViewlessDB("r2t_nonce_database"))
            empty_dump_message = _provision_refusal(
                nonce_db, seed=empty_seed_dir)

            # F11: the seed's own policy against the invocation's.  The
            # fixture seed declares CoreShop's, which is what a CoreShop
            # invocation computes, so the pin is in both directions on real
            # digests rather than on two made-up strings.
            _coreshop_policy = _seed_module.DEFAULT_RULES.digest()
            _sylius_policy = _seed_module.rules_for("behat", "sylius").digest()
            with open(os.path.join(seed_dir, "seed.json"), "w",
                      encoding="utf-8") as _manifest:
                json.dump({"rules_digest": _coreshop_policy}, _manifest)
            policy_match = _provision_refusal(
                nonce_db, seed_policy=_coreshop_policy)
            policy_mismatch = _provision_refusal(
                nonce_db, seed_policy=_sylius_policy)
            policy_unstated = _provision_refusal(nonce_db)
        finally:
            for name in _patched:
                globals()[name] = _real[name]
            _seed_module.verify_seed = _real_verify

        check("[provision] the DSN names the PUBLISHED ALIAS as its host, "
              "not the nonce-named database container -- `coreshop_db` for "
              "every CoreShop pool, so their credential files are the bytes "
              "they always were",
              f"@{DEFAULT_DB_CONTAINER}:3306/{w.schema}\n" in coreshop_body
              and f"PIMCORE_INSTALL_MYSQL_HOST_SOCKET="
                  f"{DEFAULT_DB_CONTAINER}\n" in coreshop_body
              and nonce_db.container not in coreshop_body,
              coreshop_body.replace("\n", " | "))
        check("[provision] ...and the Sylius row gets the same alias, with "
              "Doctrine's charset query, from the same nonce-named container",
              f"DATABASE_URL=mysql://{w.credential}:" in sylius_body
              and f"@{DEFAULT_DB_CONTAINER}:3306/{w.schema}?charset=utf8mb4\n"
                  in sylius_body
              and nonce_db.container not in sylius_body,
              sylius_body.replace("\n", " | "))
        check("[provision] ...and a caller that knows a different host says "
              "so with `db_host=`, which is the only way that host moves",
              f"@other_host:3306/{w.schema}\n" in explicit_body
              and "PIMCORE_INSTALL_MYSQL_HOST_SOCKET=other_host\n"
                  in explicit_body
              and DEFAULT_DB_CONTAINER not in explicit_body,
              explicit_body.replace("\n", " | "))

        # -- the load is measured against the SEED'S dump, not CoreShop's 252
        #
        # The floor this replaced said "fewer than 100 tables is a partial
        # load, the reference schema has 252", which is CoreShop's number:
        # Sylius's 83-table schema is a complete load of ITS dump and was
        # refused as a broken one.
        check("[provision] a dump's own table count is its CREATE TABLEs and "
              "its views, each counted once however mysqldump spelled it",
              dump_table_count(os.path.join(seed_dir, "database.sql")) == 252
              and dump_table_count(
                  os.path.join(empty_seed_dir, "database.sql")) == 0,
              str(dump_table_count(os.path.join(seed_dir, "database.sql"))))
        check("[provision] ...so a schema that loaded its tables but not its "
              "views is refused, naming both numbers",
              "215" in partial_message and "252" in partial_message
              and partial_message.startswith("REFUSED:"), partial_message)
        check("[provision] ...and a dump that creates nothing is refused "
              "rather than trivially satisfied by an empty schema",
              empty_dump_message.startswith("REFUSED:")
              and "creates no table" in empty_dump_message,
              empty_dump_message)

        # -- F11: the one wrong pool that would otherwise provision GREEN
        #
        # `--boundary` defaults to CoreShop's.  Forget it on another
        # project's seed and `write_env_file` bakes `PIMCORE_TEST_DB_DSN`
        # into containers that ignore it, leaving all K workers on the one
        # schema the committed environment names -- and every check after
        # that reads the same wrong row and passes.  The seed already
        # records which policy built it, so the mismatch costs one
        # comparison.
        check("[provision] the CoreShop seed's recorded policy IS the "
              "default one, so every existing CoreShop pool passes the "
              "new check unchanged",
              _seed_module.DEFAULT_RULES.digest() == "6f28900b8f71453c"
              and _seed_module.rules_for("behat", "sylius").digest()
              == "f412abfee8188cf5"
              and policy_match == "accepted",
              policy_match)
        check("[provision] ...and a seed built under ANOTHER project's "
              "policy is refused, naming both digests and the flag that "
              "would have been wrong",
              policy_mismatch.startswith("REFUSED:")
              and "6f28900b8f71453c" in policy_mismatch
              and "f412abfee8188cf5" in policy_mismatch
              and "--boundary" in policy_mismatch, policy_mismatch)
        check("[provision] ...and a caller that states no policy is not "
              "checked against one it never named",
              policy_unstated == "accepted", policy_unstated)

        write_env_file(w, "s3cret-pw", {"PIMCORE_INSTANCE_IDENTIFIER": "x"})

        # ---- the degenerate triple: workspace + container, no database (D6)
        #
        # Every check here is about NOT provisioning something, which is the
        # kind of change that passes review by doing nothing and then fails a
        # sweep by having done nothing to the wrong half.
        nodb = plan_workers(os.path.join(root, "nodb"), 2,
                            prefix="docx", kind="py", needs_database=False)
        check("a no-database worker names no schema and no principal, rather "
              "than naming ones that were never created",
              all(w.schema == "" and w.credential == "" for w in nodb))
        check("its container and workspace are still its own",
              len({w.container for w in nodb}) == 2
              and len({w.workspace for w in nodb}) == 2
              and nodb[0].container == "docx_bench_py_0", nodb[0].container)
        check("K empty schemas are not K collisions — the disjointness check "
              "drops the fields that do not exist",
              resource_fields(True) == RESOURCE_FIELDS
              and set(resource_fields(False))
              == set(RESOURCE_FIELDS) - {"schema", "credential"}
              and preflight(nodb, answers, live=False,
                            needs_database=False)["workers"] == 2)
        check("...and the CoreShop reading of the same workers still refuses "
              "them, so the exemption is doing work rather than nothing",
              refused(lambda: preflight(nodb, answers, live=False)))
        # The separation that DOES exist is still enforced.
        share = [nodb[0], WorkerSpec(**{**nodb[1].to_json(),
                                        "workspace": nodb[0].workspace})]
        check("two no-database workers sharing a workspace are still refused",
              refused(lambda: preflight(share, answers, live=False,
                                        needs_database=False)))
        share2 = [nodb[0], WorkerSpec(**{**nodb[1].to_json(),
                                         "container": nodb[0].container})]
        check("two no-database workers sharing a container are still refused",
              refused(lambda: preflight(share2, answers, live=False,
                                        needs_database=False)))

        nw = nodb[0]
        write_env_file(nw, None, {"LANG": "C.UTF-8"}, needs_database=False)
        nbody = open(nw.env_file, encoding="utf-8").read()
        check("its env file carries no DSN and no MySQL variable at all",
              "mysql://" not in nbody and "PIMCORE" not in nbody, nbody)
        check("but it still carries the worker index, which is how a row "
              "learns which shard produced it",
              f"R2T_WORKER_INDEX={nw.index}\n" in nbody)
        nodb_projection = _safe_runtime_env(
            [f"R2T_WORKER_INDEX={nw.index}", "LANG=C.UTF-8"])
        check("the live no-database projection accepts the worker index and "
              "no database variables",
              not _runtime_env_binding_problems(
                  nw, nodb_projection, False))
        leaked_nodb_projection = _safe_runtime_env([
            f"R2T_WORKER_INDEX={nw.index}",
            "PIMCORE_TEST_DB_DSN=mysql://u:secret@db/s",
        ])
        check("a database variable in a declared no-database worker is "
              "refused without exposing its secret",
              bool(_runtime_env_binding_problems(
                  nw, leaked_nodb_projection, False))
              and "secret" not in json.dumps(leaked_nodb_projection))
        check("it is still mode 0600 — the file is not less protected for "
              "holding less",
              stat.S_IMODE(os.stat(nw.env_file).st_mode) == 0o600)
        check("a password for a principal that was never created is refused",
              refused(lambda: write_env_file(nw, "pw", {},
                                             needs_database=False)))
        check("the isolation probe refuses a worker with nothing to isolate, "
              "rather than passing it",
              refused(lambda: probe_database(nw, "somewhere")))
        check("and so does the hardening step",
              refused(lambda: harden_database(nodb, None)))

        # ---- who the probe is aimed at (the K=1 wrap-around)
        #
        # `victim = ws[(index + 1) % len(ws)]` is right for every pool but
        # one.  At K=1 it wraps to the worker itself, every check "succeeds",
        # and the verdict reads `forbidden_access_succeeded` -- a failure an
        # operator cannot tell apart from a real isolation breach.
        pair = plan_workers(os.path.join(root, "victim-pair"), 2)
        check("at K>1 the probe is aimed at the positional neighbour",
              probe_victim_schema(pair, pair[0]) == pair[1].schema
              and probe_victim_schema(pair, pair[1]) == pair[0].schema)
        solo = plan_workers(os.path.join(root, "victim-solo"), 1)
        check("a one-worker pool refuses rather than probing itself, because "
              "a self-probe cannot fail for the reason the acceptance is "
              "about",
              refused(lambda: probe_victim_schema(solo, solo[0])))
        check("...and naming a sentinel is what makes K=1 probeable",
              probe_victim_schema(solo, solo[0], "coreshop_bench")
              == "coreshop_bench")
        check("a sentinel that is the worker's own schema is refused, so the "
              "escape hatch cannot reintroduce the self-probe",
              refused(lambda: probe_victim_schema(
                  solo, solo[0], solo[0].schema)))
        check("a named sentinel overrides the neighbour at K>1 too, rather "
              "than being silently ignored",
              probe_victim_schema(pair, pair[0], "coreshop_bench")
              == "coreshop_bench")

        # ---- where a database worker's application environment comes from
        #
        # It used to default to whatever container held one hard-coded name.
        # On the author host that container had been recreated by hand and
        # carried a variable the provisioning recipe never emits, so the pool
        # inherited settings nothing recorded.
        import inspect as _inspect
        check("a database-backed provision names no default template "
              "container, so a hand-recreated one cannot silently become the "
              "system under test",
              _inspect.signature(provision)
              .parameters["template_container"].default is None)

        # Saved manifests are the authority after planning.  Use a docx pool
        # because its `/work` mount and non-CoreShop names reproduce the
        # incident: regenerating defaults changes every identity while still
        # producing superficially valid WorkerSpec objects.
        saved_root = os.path.join(root, "saved-docx")
        saved = plan_workers(saved_root, 2, prefix="python_docx", kind="py",
                             workdir="/work", needs_database=False)
        os.makedirs(saved_root, exist_ok=True)
        for worker in saved:
            with open(os.path.join(
                    saved_root, f"worker{worker.index}.json"), "w",
                    encoding="utf-8") as fh:
                json.dump(worker.to_json(), fh, sort_keys=True)
        loaded = load_worker_pool(saved_root, 2)
        check("lifecycle loading preserves the docx /work identity instead "
              "of reconstructing CoreShop's /var/www/html default",
              loaded == saved and all(w.workdir == "/work" for w in loaded)
              and loaded[0].container == "python_docx_bench_py_0")
        check("database semantics come from the saved pool",
              worker_pool_needs_database(loaded) is False)
        check("the exact saved pool is required — a missing worker is "
              "refused",
              refused(lambda: load_worker_pool(saved_root, 3)))
        wrong_index_root = os.path.join(root, "wrong-index")
        os.makedirs(wrong_index_root)
        with open(os.path.join(wrong_index_root, "worker0.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(saved[1].to_json(), fh)
        check("a saved filename/index disagreement is refused",
              refused(lambda: load_worker_pool(wrong_index_root, 1)))

        import argparse
        from types import SimpleNamespace
        from . import confine as _C
        from . import mutation_run as _MR
        from . import worker as _W

        def lifecycle_args(action, **changes):
            values = {
                "action": action, "workers_root": saved_root, "k": 2,
                "only": [1], "_workdir_explicit": False,
                "composer_cache": None, "profile": None,
                "worker": None,
                # Every real invocation is parsed, and the parser always
                # supplies the two GLOBAL flags below; a fixture that omits
                # them is not the argv `cmd_worker` ever sees.
                "boundary": _CLI.DEFAULT_BOUNDARY, "repo": None,
                # The parser-wide CoreShop default must NOT shape lifecycle
                # identity when the operator did not type it.
                "workdir": "/var/www/html", "gold": answers[0],
                "artifacts": os.path.join(root, "artifacts"),
                "image": "fixture-image", "seed": "fixture-seed",
                "db_container": "fixture-db", "internal_network": None,
                "force": True, "keep_workspace": False,
            }
            values.update(changes)
            return argparse.Namespace(**values)

        provisioned = []
        attested = []

        def fake_preflight(workers, _answers, **_kwargs):
            return {"workers": len(workers),
                    "live": {"fixture": "x" * 700}}

        def fake_provision(worker, _seed, _db, **kwargs):
            provisioned.append((worker, kwargs))
            return {"schema": {"declared": NO_DATABASE}, "seconds": 0}

        def fake_attestation(worker, path, _seed_identity, _harness_version,
                             **_kwargs):
            attested.append((worker.index, path))
            return {"fixture": True}

        evidence_written = []
        docx_profile = os.path.join(CONFIG_DIR, "profile_python_docx.yml")
        from .. import docker_authority as _DA
        from ..core import docker_cli as _DCLI
        # The merged provision keeps this repository's v3 gates: the COMPLETE
        # saved pool, no --force, no --only, and network none for a
        # no-database pool.  The saved-manifest identity claim is tested
        # inside those gates, with the authority seam mocked exactly as the
        # v3 fixtures above mock it.
        #
        # Provision under a DRIFTED authority: the commit that recorded the
        # document differs from the commit executing, which is the case
        # `docker_authority._disclose_verifier_drift` exists to allow.  Its
        # note must not reach stdout, or provision's report stops parsing in
        # the one case the disclosure was added for.
        def drifted_authority_reference(*_args, **_kwargs):
            _DA._disclose_verifier_drift("c" * 40, "d" * 40)
            return ({}, {"path": "/private/a.json",
                         "file_sha256": "a" * 64, "digest": "b" * 64})

        provision_stdout = io.StringIO()
        provision_stderr = io.StringIO()
        with patch.object(_W, "default_answer_paths",
                          return_value=[]), \
                patch.object(_W, "preflight",
                             side_effect=fake_preflight), \
                patch.object(_W, "verified_seed_identity",
                             return_value={}), \
                patch.object(_W, "provision",
                             side_effect=fake_provision), \
                patch.object(_W,
                             "build_worker_runtime_attestation",
                             side_effect=fake_attestation), \
                patch.object(_W, "capture_execution_bindings",
                             return_value=[{"fixture_binding": index}
                                           for index in range(2)]), \
                patch.object(_DA, "write_evidence_no_clobber",
                             side_effect=lambda path, _doc:
                             evidence_written.append(path)), \
                patch.object(_DCLI, "authority_reference",
                             side_effect=drifted_authority_reference), \
                patch.object(_DCLI, "reset_phase", return_value=None), \
                contextlib.redirect_stdout(provision_stdout), \
                contextlib.redirect_stderr(provision_stderr):
            provision_status = _CLI.cmd_worker(lifecycle_args(
                "provision", only=None, force=False, profile=docx_profile))
        try:
            provision_report = json.loads(provision_stdout.getvalue())
        except json.JSONDecodeError:
            provision_report = None
        check("provision derives every identity from the saved manifests "
              "and attests their exact saved paths",
              len(provisioned) == 2
              and provisioned[1][0].to_json() == saved[1].to_json()
              and all(worker.workdir == "/work"
                      for worker, _kwargs in provisioned)
              and attested == [
                  (0, os.path.abspath(
                      os.path.join(saved_root, "worker0.json"))),
                  (1, os.path.abspath(
                      os.path.join(saved_root, "worker1.json")))])
        check("provision hands each worker the boundary's Behat row, so the "
              "baked database environment is the project's and not a "
              "hard-coded CoreShop one",
              all(kwargs.get("behat") is CORESHOP_BEHAT
                  for _worker, kwargs in provisioned),
              str([kwargs.get("behat") for _worker, kwargs in provisioned]))
        check("worker provision prints one complete JSON report on stdout, "
              "and a drifted authority discloses on stderr without breaking it",
              provision_status == 0
              and provision_report == fake_preflight(saved, [])
              and len(provision_stdout.getvalue()) > 600
              and "worker 1:" in provision_stderr.getvalue()
              and "note: Docker authority recorded at cccccccccccc"
              in provision_stderr.getvalue()
              and "note: Docker authority" not in provision_stdout.getvalue())

        database_pool_root = os.path.join(root, "parallel-database-pool")
        database_workers = plan_workers(database_pool_root, 2)
        write_worker_pool(database_pool_root, database_workers)

        def parallel_cli_case(operation, *, changed_seed=False):
            contexts = []
            writes = []

            class DatabaseContext:
                def __init__(self, **_kwargs):
                    self.closed = False
                    contexts.append(self)

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    self.closed = True

            stdout = io.StringIO()
            with contextlib.ExitStack() as seams:
                seams.enter_context(patch(
                    "r2t.bench.dbadmin.MySQL", DatabaseContext))
                seams.enter_context(patch.object(
                    _W, "default_answer_paths", return_value=[]))
                seams.enter_context(patch.object(
                    _W, "preflight", side_effect=fake_preflight))
                seams.enter_context(patch.object(
                    _W, "verified_seed_identity",
                    side_effect=[{"fixture": "seed"},
                                 {"fixture": "changed" if changed_seed else "seed"}]))
                seams.enter_context(patch.object(
                    _W, "provision", side_effect=operation))
                seams.enter_context(patch.object(
                    _W, "validate_dedicated_database_network", return_value={}))
                capture = seams.enter_context(patch.object(
                    _W, "capture_execution_bindings",
                    return_value=[{"fixture_binding": index} for index in range(2)]))
                seams.enter_context(patch.object(
                    _W, "build_worker_runtime_attestation", return_value={"fixture": True}))
                seams.enter_context(patch.object(
                    _DA, "write_evidence_no_clobber",
                    side_effect=lambda path, _doc: writes.append(path)))
                seams.enter_context(patch.object(
                    _DCLI, "authority_reference", side_effect=drifted_authority_reference))
                seams.enter_context(patch.object(_DCLI, "reset_phase", return_value=None))
                seams.enter_context(contextlib.redirect_stdout(stdout))
                seams.enter_context(contextlib.redirect_stderr(io.StringIO()))
                try:
                    status = _CLI.cmd_worker(lifecycle_args(
                        "provision", workers_root=database_pool_root, k=2,
                        only=None, force=False, jobs=2,
                        profile=os.path.join(CONFIG_DIR, "profile_coreshop.yml"),
                        composer_cache=cache, internal_network="fixture-internal"))
                    error = None
                except (WorkerRefused, DatabaseRefused, SystemExit) as exc:
                    status, error = None, exc
            return status, error, contexts, writes, capture.call_count, stdout.getvalue()

        database_barrier = threading.Barrier(2)
        database_clients = []

        def parallel_database_provision(worker, _seed, db, **_kwargs):
            database_clients.append(db)
            database_barrier.wait(timeout=5)
            return {"schema": {"tables": 252}, "seconds": 0}

        status, error, contexts, writes, captures, stdout = parallel_cli_case(
            parallel_database_provision)
        check("parallel CLI provisioning owns one database context per worker "
              "and publishes only after all workers finish",
              status == 0 and error is None and captures == 1
              and len(writes) == 4 and len(contexts) == 2
              and len({id(db) for db in database_clients}) == 2
              and all(db.closed for db in contexts)
              and json.loads(stdout) == fake_preflight(database_workers, []))

        def partially_failed_provision(worker, *_args, **_kwargs):
            if worker.index == 0:
                raise WorkerRefused("fixture failed worker")
            return {"schema": {"tables": 252}, "seconds": 0}

        _status, error, contexts, writes, captures, _stdout = parallel_cli_case(
            partially_failed_provision)
        check("a failed parallel worker cannot mint any complete-pool evidence",
              isinstance(error, WorkerRefused) and not writes and captures == 0
              and all(db.closed for db in contexts))
        _status, error, _contexts, writes, captures, _stdout = parallel_cli_case(
            parallel_database_provision, changed_seed=True)
        check("a seed change during provisioning stops before binding capture",
              isinstance(error, SystemExit) and "seed changed" in str(error)
              and not writes and captures == 0)

        changed_spec = os.path.join(database_pool_root, "worker0.json")
        with open(changed_spec, "rb") as handle:
            original_spec_bytes = handle.read()

        def changed_spec_provision(worker, *_args, **_kwargs):
            if worker.index == 0:
                with open(changed_spec, "ab") as handle:
                    handle.write(b"\n")
            return {"schema": {"tables": 252}, "seconds": 0}

        try:
            _status, error, _contexts, writes, captures, _stdout = parallel_cli_case(
                changed_spec_provision)
        finally:
            with open(changed_spec, "wb") as handle:
                handle.write(original_spec_bytes)
        check("a saved worker-spec change stops before binding capture",
              isinstance(error, SystemExit) and "worker specs changed" in str(error)
              and not writes and captures == 0)

        def provision_refusal(**changes):
            try:
                with patch.object(_W, "default_answer_paths",
                                  return_value=[]), \
                        patch.object(_W, "preflight",
                                     side_effect=fake_preflight):
                    _CLI.cmd_worker(lifecycle_args(
                        "provision", profile=docx_profile, **changes))
            except SystemExit as exc:
                return str(exc)
            return ""

        check("this repository's provision gates survive the saved-manifest "
              "dispatch: --force, --only and a no-database network refuse",
              "lifecycle/cleanup" in provision_refusal(only=None, force=True)
              and "complete pool" in provision_refusal(only=[1], force=False)
              and "unbound peer route" in provision_refusal(
                  only=None, force=False,
                  internal_network="fixture-internal"))
        check("the public provision command refuses nonpositive job limits",
              "--jobs" in provision_refusal(only=None, force=False, jobs=0))

        destructive = []
        mismatch = lifecycle_args(
            "provision", _workdir_explicit=True, workdir="/var/www/html")
        try:
            with patch.object(_W, "provision",
                              side_effect=lambda *a, **k: destructive.append(a)):
                _CLI.cmd_worker(mismatch)
            mismatch_refused = False
        except SystemExit as e:
            mismatch_refused = "contradicts saved worker" in str(e)
        check("an explicit /var/www/html disagreement is refused before "
              "the provision callback",
              mismatch_refused and not destructive)

        def worker_flag_refused(**changes):
            values = {
                "worker": os.path.join(saved_root, "worker1.json"),
                "repo": None, "container": saved[1].container,
                "workdir": saved[1].workdir, "_container_explicit": False,
                "_workdir_explicit": False,
            }
            values.update(changes)
            try:
                _CLI._apply_worker(argparse.Namespace(**values))
                return False
            except SystemExit:
                return True

        check("--worker refuses explicit container/workdir disagreements "
              "instead of overwriting them before dispatch",
              worker_flag_refused(
                  container="other-container", _container_explicit=True)
              and worker_flag_refused(
                  workdir="/var/www/html", _workdir_explicit=True))

        torn_down = []
        admin_paths = [os.path.abspath(os.path.join(
            saved_root, f"worker{index}.json")) for index in range(2)]
        fake_static = {"binding": {"pool": {
            "workers": [{"worker_spec_path": p} for p in admin_paths],
            "database": None, "network": {"name": "none"}}}}
        fake_live = {
            "pool_specs": list(saved),
            "selected": {"binding": {"pool": {"database": None,
                                              "network": {"name": "none"}}},
                         "runtime": {"container_image_digest":
                                     "sha256:" + "f" * 64}}}
        with patch.object(_W, "default_answer_paths",
                          return_value=[]), \
                patch.object(_W, "preflight",
                             side_effect=fake_preflight), \
                patch.object(_W, "validate_worker_runtime_v3",
                             return_value=fake_static), \
                patch.object(_W, "validate_offline_worker_runtime_pool",
                             return_value=[{"worker": w} for w in saved]), \
                patch.object(_W, "validate_live_worker_runtime",
                             return_value=fake_live), \
                patch.object(_W, "teardown",
                             side_effect=lambda worker, _db, **kwargs:
                             torn_down.append((worker, kwargs)) or {}):
            _CLI.cmd_worker(lifecycle_args(
                "teardown",
                worker=os.path.join(saved_root, "worker1.json"),
                internal_network=None))
        check("teardown touches only the selected loaded-manifest identity, "
              "through the authenticated v3 admin pool",
              len(torn_down) == 1
              and torn_down[0][0].to_json() == saved[1].to_json()
              and torn_down[0][0].workdir == "/work"
              and torn_down[0][1]["image"] == "sha256:" + "f" * 64)

    print("\n" + ("ALL PASS (worker)" if ok else "FAILURES (worker)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
