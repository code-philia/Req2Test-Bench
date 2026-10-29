"""[consumer] `environment up|status|down` over the #181 project descriptors.

The three verbs implement the project-environment contract of
`DOCKER_EXECUTION_AUTHORITY.md`: `up` binds one verified authority artifact,
builds the reviewed per-project Dockerfile, provisions one fresh
nonce-namespaced worker pool through the existing `worker plan`/`worker
provision` surfaces, and ACCEPTS only after the descriptor's gold-control row
passes.  The gold-control row is diagnostic only; these commands open no
publication, mutation, test-quality, confinement-certificate, or
reproduction-tier claim.

Composition, not reimplementation.  Every worker step is the exact reviewed
command surface an operator would type — `worker plan`, `worker provision`,
`worker harden`, `worker probe`, `run --adapter gold`, and `worker teardown` —
invoked in-process with an explicit argv, so the evidence
rules those bodies enforce (fresh-pool no-clobber, post-provision binding/v3
capture, database isolation, and live admin-pool authentication) apply here by
identity rather than by copy. `status` reuses the worker runtime validator
directly.

The anchor is one small environment record below the data root
(`projects/<project>/environments/<nonce>/environment.json`).  It exists
because the pool's nonce is recorded nowhere else: v3 binding/runtime
evidence is immutable, so every `up` must mint a fresh pool root, and
`status`/`down` need one saved identity to answer for and to retire.  The
record pins the image ID captured at up-time — BuildKit attestation makes a
freshly built image ID differ from any other host's recorded ID by
construction, so tags are never compared across hosts.

Database-backed descriptors (`descriptor.database` present) additionally
compose the descriptor's digest-pinned database image and installed seed, a
nonce-labelled dedicated internal network, database and template containers,
the K=1 sentinel schema when needed, and the existing hardening and isolation
probe surfaces.  No project name selects that branch.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from typing import Optional

from .environment import PROJECTS, artifact_paths, manifest_facts
from ..core.paths import data_root, project_path


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCHMARK = os.path.dirname(HERE)

RECORD_SCHEMA = "r2t.project-environment/v1"
RECORD_NAME = "environment.json"
ENVIRONMENTS_DIRNAME = "environments"
GOLD_CONTROL_NAME = "gold-control.jsonl"
ENVIRONMENT_LABEL = "org.req2test.environment"

#: Repository under which every pool reserves a name for its own image.
#: `up` builds `<project>:base` -- ONE mutable name shared by every pool of a
#: project, ever -- and then pins the immutable ID that tag resolved to, in
#: the record and in each worker's runtime attestation.  The next build of the
#: same Dockerfile moves `:base` to a new ID and leaves the running pool's ID
#: with no name at all.  Nothing notices: the containers keep running and
#: `environment status` keeps saying live.  It surfaces only at `r2t campaign`,
#: which resolves `--image` and refuses because the tag no longer names what
#: the pool runs -- by which point the pool is unusable and unrecoverable.
#: A second name, scoped to the pool's nonce, is the whole fix.
PRESERVED_IMAGE_REPOSITORY = "r2t_preserve_img"

_DIGEST_IMAGE = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}")
_DOCKER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")

#: The doctor rows that describe a SAVED worker pool.  `up`'s host preflight
#: is the doctor composition minus these rows: the pool `up` is about to
#: create does not exist yet (on a fresh host the canonical workers directory
#: itself does not), and a previous, already-retired pool would fail them for
#: reasons that say nothing about this bring-up.  The dropped checks are not
#: lost — `worker provision`'s live acceptance and the gold-control row
#: validate the pool this very command creates.
POOL_ROWS = frozenset({
    "saved worker manifests",
    "live worker preflight",
    "saved runtime and verified seed",
    "worker image agreement",
    "worker confinement certificate",
})

_RECORD_FIELDS = ("schema", "project", "nonce", "created_at", "state", "k",
                  "workers_root", "workdir", "container_kind", "image",
                  "docker_execution_authority", "database", "gold_control")


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _descriptor(project: str):
    descriptor = PROJECTS.get(project)
    if descriptor is None:
        raise SystemExit(
            f"REFUSED: unknown environment project {project!r}; descriptors "
            f"exist for {sorted(PROJECTS)}")
    database = descriptor.database
    if database is None:
        if descriptor.template_command is not None \
                or descriptor.template_env is not None \
                or descriptor.composer_cache:
            raise SystemExit(
                f"REFUSED: environment descriptor {project!r} declares "
                "database-only template/cache facts without a database")
        return descriptor
    if _DIGEST_IMAGE.fullmatch(database.image) is None:
        raise SystemExit(
            f"REFUSED: environment descriptor {project!r} database image is "
            "not digest-pinned")
    if _DOCKER_NAME.fullmatch(database.alias) is None:
        raise SystemExit(
            f"REFUSED: environment descriptor {project!r} database alias is "
            "not a Docker name")
    if not isinstance(database.root_password, str) \
            or not database.root_password \
            or any(mark in database.root_password for mark in "\x00\r\n"):
        raise SystemExit(
            f"REFUSED: environment descriptor {project!r} has an invalid "
            "database root-password channel")
    from ..bench import worker as W
    from ..bench.dbadmin import DEFAULT_ROOT_PASSWORD
    if database.alias != W.DEFAULT_DB_CONTAINER \
            or database.root_password != DEFAULT_ROOT_PASSWORD:
        raise SystemExit(
            f"REFUSED: environment descriptor {project!r} database "
            "alias/password differ from the existing worker administration "
            "surface")
    command = descriptor.template_command
    if not isinstance(command, tuple) or not command or not all(
            isinstance(part, str) and part
            and not any(mark in part for mark in "\x00\r\n")
            for part in command):
        raise SystemExit(
            f"REFUSED: environment descriptor {project!r} database branch "
            "has no valid template command")
    if not callable(descriptor.template_env):
        raise SystemExit(
            f"REFUSED: environment descriptor {project!r} database branch "
            "has no template environment producer")
    return descriptor


def _database_resources(descriptor, nonce: str, k: int) -> Optional[dict]:
    """Closed, non-secret resource identity saved for status and down."""
    if descriptor.database is None:
        return None
    return {
        "image": descriptor.database.image,
        "alias": descriptor.database.alias,
        "network": f"r2t_{nonce}_internal",
        "container": f"r2t_{nonce}_database",
        "template_container": f"r2t_{nonce}_template",
        "sentinel_schema": f"{nonce}_sentinel" if k == 1 else None,
        "label": {"key": ENVIRONMENT_LABEL, "value": nonce},
    }


def _config_paths(project: str) -> tuple[str, str]:
    """The repository profile/boundary pair the reviewed commands consume."""
    from ..data.profile import config_stem
    stem = config_stem(project)
    return (os.path.join(BENCHMARK, "config", f"profile_{stem}.yml"),
            os.path.join(BENCHMARK, "config", f"boundary_{stem}.yml"))


def environments_root(project: str) -> str:
    return os.fspath(project_path(project, ENVIRONMENTS_DIRNAME))


def record_path(project: str, nonce: str) -> str:
    return os.path.join(environments_root(project), nonce, RECORD_NAME)


def _mint_nonce() -> str:
    """A fresh pool namespace; `worker plan --name` derives every worker
    identity from it, so two environments can never collide."""
    return "e" + secrets.token_hex(4)


def _load_record(path: str) -> dict:
    if os.path.islink(path) or not os.path.isfile(path):
        raise SystemExit(
            f"REFUSED: environment record is not a non-symlink regular "
            f"file: {path}")
    try:
        with open(path, encoding="utf-8") as fh:
            record = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(
            f"REFUSED: cannot read environment record {path}: {exc}") from exc
    if not isinstance(record, dict) \
            or record.get("schema") != RECORD_SCHEMA \
            or sorted(record) != sorted(_RECORD_FIELDS + (
                ("torn_down_at",) if "torn_down_at" in record else ())):
        raise SystemExit(
            f"REFUSED: {path} is not an exact {RECORD_SCHEMA} record")
    if record.get("state") not in ("up", "down"):
        raise SystemExit(
            f"REFUSED: {path} has unknown state {record.get('state')!r}")
    project = record.get("project")
    nonce = record.get("nonce")
    k = record.get("k")
    if not isinstance(project, str) or not isinstance(nonce, str) \
            or _DOCKER_NAME.fullmatch(nonce) is None \
            or not isinstance(k, int) or isinstance(k, bool) or k < 1:
        raise SystemExit(
            f"REFUSED: {path} has invalid project/nonce/K identity")
    descriptor = _descriptor(project)
    expected_database = _database_resources(descriptor, nonce, k)
    if record.get("database") != expected_database:
        raise SystemExit(
            f"REFUSED: {path} database resources disagree with the saved "
            "descriptor/nonce identity")
    return record


def _write_record(path: str, record: dict) -> None:
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    temporary = os.path.join(parent, f".{RECORD_NAME}.tmp")
    with open(temporary, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=1, sort_keys=True)
        fh.write("\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _saved_records(project: str) -> list[tuple[str, str, dict]]:
    root = environments_root(project)
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return []
    out = []
    for name in names:
        path = os.path.join(root, name, RECORD_NAME)
        if os.path.isfile(path):
            record = _load_record(path)
            if record["project"] != project or record["nonce"] != name:
                raise SystemExit(
                    f"REFUSED: environment record path disagrees with its "
                    f"saved project/nonce identity: {path}")
            out.append((name, path, record))
    return out


def _select_record(project: str, nonce: Optional[str],
                   records: list[tuple[str, str, dict]]) \
        -> tuple[str, str, dict]:
    if nonce is not None:
        for entry in records:
            if entry[0] == nonce:
                return entry
        raise SystemExit(
            f"REFUSED: no saved environment {nonce!r} for {project}; "
            f"saved nonces: {[name for name, _p, _r in records]}")
    if not records:
        raise SystemExit(
            f"REFUSED: no saved environment record for {project}")
    if len(records) > 1:
        raise SystemExit(
            f"REFUSED: {len(records)} saved environments for {project}; "
            f"name one with --nonce: {[name for name, _p, _r in records]}")
    return records[0]


# ---------------------------------------------------------------- live seams
# Module-level so the source-only selftest can stand fakes in for them,
# exactly as the worker and doctor lanes fake their Docker leaves.

def _cli(argv: list[str]) -> int:
    """One reviewed CLI surface, invoked in-process with an explicit argv."""
    from .. import cli
    return cli.main(list(argv))


def _step(name: str, argv: list[str]) -> None:
    print(f"== environment {name}: r2t {' '.join(argv)}", file=sys.stderr)
    try:
        rc = _cli(argv)
    except SystemExit as exc:
        raise SystemExit(f"environment step {name!r} failed: {exc}") from exc
    if rc:
        raise SystemExit(f"environment step {name!r} failed: exit {rc}")


def _build_image(dockerfile_dir: str, tag: str) -> str:
    """Build the reviewed per-project Dockerfile; return the immutable ID."""
    from ..core import docker_cli as DC
    from ..core.docker_cli import docker_argv
    dockerfile = os.path.join(dockerfile_dir, "Dockerfile")
    if not os.path.isfile(dockerfile):
        raise SystemExit(
            f"REFUSED: descriptor names no shipped Dockerfile: {dockerfile}")
    build = subprocess.run(docker_argv(["build", "-t", tag, dockerfile_dir]))
    if build.returncode != 0:
        raise SystemExit(
            f"REFUSED: docker build of {dockerfile_dir} failed with exit "
            f"{build.returncode}")
    # The build is an image mutation AND BuildKit writes its state into the
    # isolated client configuration, which every later command requires
    # empty.  Same pattern as the provision body: end the phase, so the next
    # Docker boundary gets a fresh empty config and repeats the authority
    # proof after the mutation.
    DC.reset_phase()
    inspect = subprocess.run(
        docker_argv(["image", "inspect", tag, "--format", "{{.Id}}"]),
        capture_output=True, text=True)
    value = (inspect.stdout or "").strip()
    payload = value[len("sha256:"):] if value.startswith("sha256:") else ""
    if inspect.returncode != 0 or len(payload) != 64 \
            or any(c not in "0123456789abcdef" for c in payload):
        raise SystemExit(
            f"REFUSED: cannot resolve immutable image ID for {tag}: "
            f"{value!r} {(inspect.stderr or '')[-200:]}")
    return value


def _preserve_pool_image(project: str, nonce: str, image_id: str) -> str:
    """Reserve a name for this pool's image, and return it.

    The pool is then planned, provisioned and recorded against THIS name
    rather than `:base`, so the image it is bound to cannot be moved out from
    under it -- neither by a concurrent bring-up finishing its own build
    between this one's build and its provision, nor by any later rebuild.
    It is taken once the pool's own root exists, so a bring-up refused by the
    host preflight or a dirty root leaves no name behind; the ID it reserves
    was captured at build time, so waiting cannot bind it to another build.

    The reservation is verified rather than assumed: an image name that did
    not take, or that resolves to something other than the ID just built, is
    the exact condition this function exists to prevent, and provisioning a
    pool against it would reproduce the fault it is meant to remove.
    """
    name = f"{PRESERVED_IMAGE_REPOSITORY}:{project}-{nonce}"
    # `_build_image` ends its phase on the way out, so this reservation is
    # already the first Docker boundary after the build and re-proves the
    # authority by itself; tagging writes no BuildKit state of its own.
    _docker(["image", "tag", image_id, name], timeout=60)
    resolved = (_docker(
        ["image", "inspect", name, "--format", "{{.Id}}"],
        timeout=60).stdout or "").strip()
    if resolved != image_id:
        raise SystemExit(
            f"REFUSED: reserved image name {name} resolves to {resolved!r}, "
            f"not the image {image_id!r} this bring-up built. The pool is "
            "not provisioned; no worker was created.")
    return name


def _release_pool_image_name(record: dict) -> Optional[dict]:
    """Give back the name `up` reserved for this pool's image.

    The reservation exists to outlive `:base`, so it has to be given back
    explicitly or every bring-up pins one image's layers on the host forever.
    This removes a NAME: Docker deletes the image only when no other name and
    no container still refer to it, which after this pool's teardown is
    exactly the case where nothing is left to preserve. A refusal (a sibling
    pool still running the same image) is reported, not raised -- the pool's
    own resources are already gone and its record must still be retired.
    """
    name = (record.get("image") or {}).get("preserved_tag")
    if not name:
        return None
    completed = _docker(["image", "rm", name], timeout=120, check=False)
    if completed.returncode == 0:
        return {"name": name, "released": True}
    return {"name": name, "released": False,
            "detail": (completed.stderr or completed.stdout
                       or "").strip()[-300:]}


def _docker(argv: list[str], *, env: Optional[dict] = None,
            timeout: int = 600, check: bool = True
            ) -> subprocess.CompletedProcess:
    """Run one authority-derived Docker leaf without exposing env values."""
    from ..core.docker_cli import docker_argv
    try:
        completed = subprocess.run(
            docker_argv(argv, environ=env), env=env,
            capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"REFUSED: Docker command failed: {exc}") from exc
    if check and completed.returncode:
        detail = (completed.stderr or completed.stdout or "").strip()[-500:]
        raise SystemExit(
            f"REFUSED: Docker command {argv[:2]} failed with exit "
            f"{completed.returncode}" + (f": {detail}" if detail else ""))
    return completed


def _inspect(kind: str, name: str) -> Optional[dict]:
    """Inspect one exact direct resource; distinguish absence from errors."""
    completed = _docker(
        [kind, "inspect", name, "--format", "{{json .}}"],
        timeout=60, check=False)
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "").strip()
        lowered = detail.lower()
        target = name.lower()
        absent = (
            kind == "container" and f"no such container: {target}" in lowered
        ) or (
            kind == "network" and f"network {target} not found" in lowered
        ) or (
            kind == "image" and f"no such image: {target}" in lowered
        )
        if absent:
            return None
        raise SystemExit(
            f"REFUSED: could not inspect Docker {kind} {name!r}"
            + (f": {detail[-500:]}" if detail else ""))
    try:
        document = json.loads(completed.stdout or "")
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"REFUSED: Docker returned invalid {kind} inspection JSON for "
            f"{name!r}") from exc
    if not isinstance(document, dict):
        raise SystemExit(
            f"REFUSED: Docker returned non-object {kind} inspection for "
            f"{name!r}")
    return document


def _resource_labels(kind: str, document: dict) -> dict:
    return ((document.get("Labels") or {}) if kind == "network" else
            ((document.get("Config") or {}).get("Labels") or {}))


def _require_database_resources_absent(database: dict) -> None:
    for role, kind in (("network", "network"),
                       ("container", "container"),
                       ("template_container", "container")):
        name = database[role]
        if _inspect(kind, name) is not None:
            raise SystemExit(
                f"REFUSED: planned environment {role} {name!r} already "
                "exists; environment up never adopts or removes it")


def _load_planned_database_workers(record: dict):
    """Load the exact saved plans used by bounded pre-v3 recovery."""
    from ..bench import worker as W
    try:
        workers = W.load_worker_pool(record["workers_root"], record["k"])
        if not W.worker_pool_needs_database(workers):
            raise W.WorkerRefused(
                "REFUSED: database environment plans declare no database")
        W.preflight(workers, [], live=False, needs_database=True)
    except W.WorkerRefused as exc:
        raise SystemExit(str(exc)) from exc
    if any(worker.workdir != record["workdir"] for worker in workers):
        raise SystemExit(
            "REFUSED: planned worker workdir differs from the saved "
            "database environment record")
    return workers


def _require_planned_worker_containers_absent(workers) -> None:
    """Complete the read-only exact-name preflight before DB mutation."""
    from ..bench import worker as W
    try:
        for worker in workers:
            W.require_container_absent(worker.container)
    except W.WorkerRefused as exc:
        raise SystemExit(str(exc)) from exc


def _complete_pool_identity_exists(record: dict) -> bool:
    """Whether every v3 binding/runtime path exists for authenticated down.

    ``lexists`` deliberately routes malformed or symlinked complete evidence
    through the existing authenticated teardown, where it refuses.  Recovery
    is only the pre-binding path, never a weaker fallback after v3 rejection.
    """
    from ..bench import worker as W
    paths = []
    for index in range(record["k"]):
        spec = os.path.join(record["workers_root"], f"worker{index}.json")
        paths.extend((W.binding_attestation_path(spec),
                      W.runtime_attestation_path(spec)))
    return all(os.path.lexists(path) for path in paths)


def _inspect_planned_worker_containers(record: dict, workers) -> dict:
    """Prove every present pre-v3 worker before any recovery mutation."""
    present = {}
    failures = []
    expected_image = record["image"]["id"]
    for worker in workers:
        document = _inspect("container", worker.container)
        if document is None:
            continue
        present[worker.container] = document
        actual_name = document.get("Name")
        if isinstance(actual_name, str) and actual_name.startswith("/"):
            actual_name = actual_name[1:]
        if actual_name != worker.container:
            failures.append(
                f"{worker.container}: live name is {actual_name!r}")
        if document.get("Image") != expected_image:
            failures.append(
                f"{worker.container}: immutable image differs from "
                "the saved environment image")

        mounts = document.get("Mounts")
        if not isinstance(mounts, list) or any(
                not isinstance(mount, dict)
                or not isinstance(mount.get("Source"), str)
                or not isinstance(mount.get("Destination"), str)
                for mount in mounts):
            failures.append(
                f"{worker.container}: Docker mount inspection is incomplete")
            continue
        workspace = os.path.realpath(worker.workspace)
        related = [
            mount for mount in mounts
            if os.path.realpath(mount["Source"]) == workspace
            or mount["Destination"] == worker.workdir
        ]
        if len(related) != 1 \
                or related[0].get("Type") != "bind" \
                or related[0].get("RW") is not True \
                or os.path.realpath(related[0]["Source"]) != workspace \
                or related[0]["Destination"] != worker.workdir:
            failures.append(
                f"{worker.container}: unique writable workspace mount "
                "differs from the exact saved plan")
    if failures:
        raise SystemExit(
            "REFUSED: planned worker recovery identity mismatch: "
            + "; ".join(failures)
            + "; no worker or direct environment resource was removed")
    return present


def _recover_planned_database_workers(record: dict, descriptor) -> list[dict]:
    """Bounded cleanup for provisioning that stopped before complete v3."""
    from ..bench import worker as W
    from ..bench.dbadmin import DatabaseRefused, MySQL

    workers = _load_planned_database_workers(record)
    present = _inspect_planned_worker_containers(record, workers)
    database = record["database"]
    database_document = _inspect("container", database["container"])
    reports = []

    def teardown_all(db) -> None:
        for worker in workers:
            report = W.teardown(
                worker, db, image=record["image"]["id"])
            if worker.container in present and not report.get("container"):
                raise W.WorkerRefused(
                    f"REFUSED: could not remove validated planned worker "
                    f"{worker.container}")
            reports.append(report)

    try:
        if database_document is None:
            teardown_all(None)
        else:
            admin_ready = False
            try:
                with MySQL(
                        container=database["container"],
                        password=descriptor.database.root_password) as db:
                    # Resource creation can stop at the health wait with a
                    # labelled but crash-stopped/nonresponsive database. Prove
                    # the admin route before worker teardown mutates anything.
                    db.schemas()
                    admin_ready = True
                    teardown_all(db)
            except (DatabaseRefused, OSError, subprocess.SubprocessError):
                if admin_ready:
                    raise
                # No worker schema/principal can outlive removal of this
                # environment-exclusive database container. The exact plans
                # still remove only their own containers, env files and
                # workspaces; labelled direct cleanup removes the unusable DB.
                teardown_all(None)
    except (DatabaseRefused, W.WorkerRefused, OSError,
            subprocess.SubprocessError) as exc:
        raise SystemExit(str(exc)) from exc
    return reports


def _wait_database(name: str) -> None:
    deadline = time.monotonic() + 180
    while True:
        completed = _docker([
            "container", "inspect", "--format",
            "{{.State.Health.Status}}", name,
        ], timeout=60)
        status = (completed.stdout or "").strip()
        if status == "healthy":
            return
        if status == "unhealthy" or time.monotonic() >= deadline:
            raise SystemExit(
                f"REFUSED: database container {name!r} did not become "
                f"healthy (last status {status!r})")
        time.sleep(2)


def _template_environment(descriptor, *, database: dict, seed: str,
                          workdir: str, image: str,
                          environment_dir: str) -> dict[str, str]:
    """Generate the template's Defuse key inside the installed seed."""
    from ..bench import seed as S

    label = f"{database['label']['key']}={database['label']['value']}"
    with tempfile.TemporaryDirectory(
            prefix=".template-key.", dir=environment_dir) as temporary:
        workspace = os.path.join(temporary, "workspace")
        try:
            S.unpack_workspace(seed, workspace)
        except (OSError, S.SeedRefused) as exc:
            raise SystemExit(str(exc)) from exc
        completed = _docker([
            "run", "--rm", "--name", database["template_container"],
            "--label", label, "--network", "none",
            "--volume", f"{workspace}:{workdir}:ro",
            image, *descriptor.template_command,
        ], timeout=300)
    lines = [line.strip() for line in (completed.stdout or "").splitlines()
             if line.strip()]
    value = lines[-1] if lines else ""
    try:
        values = descriptor.template_env(value)
    except Exception as exc:
        raise SystemExit(
            f"REFUSED: database descriptor rejected its template command "
            f"output: {exc}") from exc
    valid = isinstance(values, dict) and bool(values) and all(
        isinstance(name, str) and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*", name)
        and isinstance(value, str)
        and not any(mark in value for mark in "\x00\r\n")
        for name, value in values.items())
    if not valid:
        raise SystemExit(
            "REFUSED: database descriptor returned an invalid template "
            "environment")
    return values


def _create_database_resources(descriptor, *, database: dict, seed: str,
                               workdir: str, image: str,
                               environment_dir: str) -> None:
    """Create only the direct resources authorized by the DB descriptor."""
    label = f"{database['label']['key']}={database['label']['value']}"
    _docker([
        "network", "create", "--driver", "bridge", "--internal",
        "--label", label, database["network"],
    ], timeout=60)

    database_env = dict(os.environ)
    database_env["MYSQL_ROOT_PASSWORD"] = descriptor.database.root_password
    _docker([
        "run", "--detach", "--name", database["container"],
        "--label", label, "--network", database["network"],
        "--network-alias", descriptor.database.alias,
        "--health-cmd", "mysqladmin ping -h 127.0.0.1 --silent",
        "--health-interval", "2s", "--health-timeout", "2s",
        "--health-retries", "90", "--env", "MYSQL_ROOT_PASSWORD",
        descriptor.database.image,
    ], env=database_env, timeout=300)
    _wait_database(database["container"])

    values = _template_environment(
        descriptor, database=database, seed=seed, workdir=workdir,
        image=image, environment_dir=environment_dir)
    template_env = dict(os.environ)
    template_env.update(values)
    env_args = [part for name in sorted(values) for part in ("--env", name)]
    _docker([
        "run", "--detach", "--name", database["template_container"],
        "--label", label, "--network", "none", *env_args,
        image, "tail", "-f", "/dev/null",
    ], env=template_env, timeout=300)

    sentinel = database["sentinel_schema"]
    if sentinel is not None:
        from ..bench.dbadmin import DatabaseRefused, MySQL
        try:
            with MySQL(
                    container=database["container"],
                    password=descriptor.database.root_password) as db:
                db.create_schema(sentinel)
                db.load(sentinel, os.path.join(seed, "database.sql"))
                if not db.table_bytes(sentinel):
                    raise SystemExit(
                        "REFUSED: the K=1 isolation sentinel contains no "
                        "tables")
        except DatabaseRefused as exc:
            raise SystemExit(str(exc)) from exc


def _database_resource_status(record: dict) -> tuple[Optional[str], dict]:
    """Validate saved direct DB resources omitted from worker v3 evidence."""
    database = record["database"]
    if database is None:
        return None, {}
    reports = {}
    failures = []

    def fail(role: str, detail: str, report: dict) -> None:
        report["ok"] = False
        report["error"] = detail
        failures.append(f"{role}: {detail}")

    for role, kind in (("network", "network"),
                       ("container", "container"),
                       ("template_container", "container")):
        name = database[role]
        report = {"name": name}
        reports[role] = report
        try:
            document = _inspect(kind, name)
        except (Exception, SystemExit) as exc:
            fail(role, str(exc), report)
            continue
        if document is None:
            fail(role, "saved resource is absent", report)
            continue
        label_ok = _resource_labels(kind, document).get(
            database["label"]["key"]) == database["label"]["value"]
        report["label_ok"] = label_ok
        if not label_ok:
            fail(role, "saved resource has another environment label", report)
            continue

        if role == "network":
            properties = {
                "internal": document.get("Internal") is True,
                "driver": document.get("Driver") == "bridge",
                "scope": document.get("Scope") == "local",
            }
            report.update(properties)
            bad = sorted(key for key, value in properties.items() if not value)
            if bad:
                fail(role, f"saved network differs in {bad}", report)
            else:
                report["ok"] = True
            continue

        running = bool((document.get("State") or {}).get("Running"))
        report["running"] = running
        if role == "container":
            health = ((document.get("State") or {}).get("Health") or {}).get(
                "Status")
            report["health"] = health
            configured_image = (document.get("Config") or {}).get("Image")
            networks = (document.get("NetworkSettings") or {}).get(
                "Networks") or {}
            attachment = networks.get(database["network"]) or {}
            aliases = attachment.get("Aliases") or []
            properties = {
                "image": configured_image == database["image"],
                "network_mode": (document.get("HostConfig") or {}).get(
                    "NetworkMode") == database["network"],
                "sole_network": set(networks) == {database["network"]},
                "alias": database["alias"] in aliases,
                "healthy": health == "healthy",
            }
        else:
            properties = {
                "image": document.get("Image") == record["image"]["id"],
                "network_mode": (document.get("HostConfig") or {}).get(
                    "NetworkMode") == "none",
            }
        report.update(properties)
        bad = sorted(key for key, value in properties.items() if not value)
        if not running:
            bad.append("running")
        if bad:
            fail(role, f"saved container differs in {bad}", report)
        else:
            report["ok"] = True
    return ("; ".join(failures) if failures else None), reports


def _require_owned_database_resources(record: dict) -> None:
    """Prove every present direct resource is still owned before teardown."""
    database = record["database"]
    if database is None:
        return
    for role, kind in (("template_container", "container"),
                       ("container", "container"),
                       ("network", "network")):
        name = database[role]
        document = _inspect(kind, name)
        if document is None:
            continue
        labels = _resource_labels(kind, document)
        key = database["label"]["key"]
        value = database["label"]["value"]
        if labels.get(key) != value:
            raise SystemExit(
                f"REFUSED: saved {role} {name!r} does not carry exact label "
                f"{key}={value}; no environment resource was removed")


def _remove_database_resources(record: dict) -> None:
    """Remove saved direct resources, rechecking the ownership label."""
    database = record["database"]
    if database is None:
        return
    for role, kind in (("template_container", "container"),
                       ("container", "container"),
                       ("network", "network")):
        name = database[role]
        document = _inspect(kind, name)
        if document is None:
            continue
        labels = _resource_labels(kind, document)
        key = database["label"]["key"]
        value = database["label"]["value"]
        if labels.get(key) != value:
            raise SystemExit(
                f"REFUSED: saved {role} {name!r} changed ownership label; "
                "it was not removed")
        argv = (["container", "rm", "--force", name]
                if kind == "container" else ["network", "rm", name])
        _docker(argv, timeout=300 if kind == "container" else 60)


def _doctor_report(project: str) -> dict:
    from . import doctor as D
    return D.doctor(project=project)


def _host_preflight(project: str, *, creates_database: bool = False) -> None:
    """The doctor rows minus the pool rows, refusing on any remaining FAIL."""
    from .doctor import GENERATION_READINESS_ROWS
    report = _doctor_report(project)
    failed = []
    for row in report["checks"]:
        if row["name"] in POOL_ROWS:
            print(f"skip  {row['name']}: pool row; this command provisions "
                  f"its own fresh pool", file=sys.stderr)
            continue
        if creates_database and row["name"] in {
                "project image", "project database"}:
            why = ("already built and pinned its descriptor image"
                   if row["name"] == "project image" else
                   "creates its own fresh nonce database")
            print(f"skip  {row['name']}: this descriptor branch {why}",
                  file=sys.stderr)
            continue
        if row["name"] in GENERATION_READINESS_ROWS:
            print(f"skip  {row['name']}: paid generation, not environment "
                  "bring-up, owns this gate", file=sys.stderr)
            continue
        print(f"{row['status'].upper():4}  {row['name']}: {row['detail']}",
              file=sys.stderr)
        if row["status"] == "fail":
            failed.append(f"{row['name']}: {row['detail']}")
    if failed:
        raise SystemExit(
            "REFUSED: environment up host preflight failed: "
            + "; ".join(failed))


def _live_runtime(record: dict) -> dict:
    """Live v3 revalidation of exactly the saved record's pool."""
    from ..bench import worker as W
    from ..bench.repo import behat_project
    from ..bench.validate import HARNESS_VERSION
    from ..core.boundary import load_boundary
    workers = W.load_worker_pool(record["workers_root"], record["k"])
    needs_database = W.worker_pool_needs_database(workers)
    gold = os.fspath(project_path(record["project"], "gold"))
    artifacts = os.fspath(project_path(record["project"], "artifacts"))
    answers = W.default_answer_paths(
        gold, artifacts, os.path.join(artifacts, "release"))
    # The row the pool's containers were provisioned against: the live half
    # of the preflight reads each container's DSN variable by name, and this
    # record's project is what says which name that is.
    _profile_path, boundary_path = _config_paths(record["project"])
    return W.validate_live_worker_runtime(
        os.path.join(record["workers_root"], "worker0.json"), workers[0],
        HARNESS_VERSION, needs_database, answers,
        expected_pool_size=record["k"],
        behat=behat_project(load_boundary(boundary_path)))


def _pool_live_error(record: dict) -> Optional[str]:
    """None when the record's pool is live and bound; else why it is not."""
    from ..bench import worker as W
    try:
        runtime = _live_runtime(record)
    except (W.WorkerRefused, OSError, subprocess.SubprocessError) as exc:
        return str(exc)
    image_id = runtime["selected"]["runtime"]["container_image_digest"]
    if image_id != record["image"]["id"]:
        return (f"live pool runs image {image_id}, but the record pinned "
                f"{record['image']['id']} at up-time")
    # A rebuild moves the tag and leaves the pinned digest untagged; a later
    # removal takes the digest away while the pool's containers keep running
    # it. Acceptance is bound to that digest, so the pool is finished for any
    # new work the moment it stops resolving. Reporting it here is the
    # difference between learning that now and learning it from `r2t
    # campaign` in the middle of preparing a run.
    if _inspect("image", image_id) is None:
        return (f"pool image {image_id} is no longer in the image store; "
                "its containers still run it, but nothing can be bound to "
                "that digest again, so this environment can only be torn "
                "down and rebuilt")
    database = record["database"]
    if database is not None:
        pool = runtime["selected"]["binding"]["pool"]
        pool_database = pool.get("database")
        container = (pool_database.get("container_name")
                     if isinstance(pool_database, dict) else None)
        network = (pool.get("network") or {}).get("name")
        if container != database["container"] \
                or network != database["network"]:
            return (
                "live pool database/network differs from the exact resources "
                "saved by environment up")
    return None


# ------------------------------------------------------------------- verbs

def _up_database(project: str, descriptor, *,
                 k: Optional[int] = None) -> int:
    """Compose the database branch without changing the no-database route."""
    facts = manifest_facts(project)
    plan = facts["worker_plan"]
    k = int(plan["k"]) if k is None else k
    if k < 1:
        raise SystemExit("REFUSED: environment up needs --k of at least 1")
    tag = facts["harness_image"]

    from ..core import docker_cli as DC
    authority_path = DC.configured_authority_path()
    if authority_path is None:
        raise SystemExit(
            "REFUSED: environment up is a live Docker workload; name the "
            "verified authority artifact with --docker-authority. No Docker "
            "command was run.")
    _document, authority_ref = DC.authority_reference(live=True)

    root = data_root()
    roles = artifact_paths(project, root)
    release_items = roles.get("release_items")
    seed = roles.get("seed")
    if not release_items or not os.path.isfile(release_items):
        raise SystemExit(
            f"REFUSED: installed bundle has no release items for {project} "
            f"({release_items!r}); install the project bundle first. No "
            "Docker command was run.")
    if not seed or not os.path.isdir(seed):
        raise SystemExit(
            f"REFUSED: installed bundle has no seed for {project} "
            f"({seed!r}); install the project bundle first. No Docker "
            "command was run.")
    nonce = _mint_nonce()
    image_id = _build_image(descriptor.dockerfile_dir, tag)
    _host_preflight(project, creates_database=True)

    environment_dir = os.path.join(environments_root(project), nonce)
    if os.path.lexists(environment_dir):
        raise SystemExit(
            f"REFUSED: environment root already exists: {environment_dir}. "
            "v3 pool evidence is immutable, so every up mints a fresh "
            "nonce-namespaced root; retire the existing environment with "
            "`environment down` instead of reusing its root.")
    os.makedirs(environment_dir)
    pool_image = _preserve_pool_image(project, nonce, image_id)
    workers_root = os.path.join(environment_dir, "workers")
    composer_cache = None
    if descriptor.composer_cache:
        composer_cache = os.path.join(environment_dir, "composer-cache")
        os.mkdir(composer_cache, 0o700)
    profile_path, boundary_path = _config_paths(project)
    base = ["--docker-authority", authority_path]
    database = _database_resources(descriptor, nonce, k)
    assert database is not None

    _step("worker plan", base + [
        "worker", "plan", "--k", str(k), "--workers-root", workers_root,
        "--profile", profile_path, "--workdir", plan["workdir"],
        "--container-kind", plan["container_kind"], "--name", nonce])
    planned_workers = _load_planned_database_workers({
        "workers_root": workers_root,
        "k": k,
        "workdir": plan["workdir"],
    })
    _require_planned_worker_containers_absent(planned_workers)
    _require_database_resources_absent(database)

    gold_out = os.path.join(environment_dir, GOLD_CONTROL_NAME)
    worker0 = os.path.join(workers_root, "worker0.json")
    record = {
        "schema": RECORD_SCHEMA,
        "project": project,
        "nonce": nonce,
        "created_at": _utc_now(),
        "state": "up",
        "k": k,
        "workers_root": workers_root,
        "workdir": plan["workdir"],
        "container_kind": plan["container_kind"],
        "image": {"tag": tag, "id": image_id,
                  "preserved_tag": pool_image},
        "docker_execution_authority": authority_ref,
        "database": database,
        "gold_control": {
            "item": descriptor.gold_control_item,
            "out": gold_out,
            "outcome": None,
            "passed": False,
            "error": "database resource creation, worker provisioning, "
                     "hardening, isolation probe, and gold control have not "
                     "completed",
        },
    }
    path = record_path(project, nonce)
    _write_record(path, record)

    _create_database_resources(
        descriptor, database=database, seed=seed,
        workdir=plan["workdir"], image=pool_image,
        environment_dir=environment_dir)
    DC.reset_phase()

    provision_argv = base + [
        "worker", "provision", "--k", str(k),
        "--workers-root", workers_root, "--profile", profile_path,
        "--image", pool_image, "--seed", seed,
        "--db-container", database["container"],
        "--internal-network", database["network"],
        "--template-container", database["template_container"],
    ]
    if composer_cache is not None:
        provision_argv += ["--composer-cache", composer_cache]
    _step("worker provision", provision_argv)

    admin = base + ["--worker", worker0, "--boundary", boundary_path]
    lifecycle = [
        "--k", str(k), "--workers-root", workers_root,
        "--db-container", database["container"],
        "--internal-network", database["network"],
    ]
    try:
        _step("worker harden", admin + ["worker", "harden", *lifecycle])
        probe_argv = admin + ["worker", "probe", *lifecycle]
        if database["sentinel_schema"] is not None:
            probe_argv += ["--sentinel-schema", database["sentinel_schema"]]
        _step("worker probe", probe_argv)
    except BaseException as exc:
        record["gold_control"]["error"] = (
            str(exc) or "database hardening/isolation was interrupted")
        _write_record(path, record)
        print(
            "REFUSED: database environment acceptance stopped before its "
            f"gold control. The complete pool remains anchored by {path}; "
            "retire it with `environment down`.", file=sys.stderr)
        raise

    gold_argv = admin + [
        "run", "--adapter", "gold", "--profile", profile_path,
        "--release", release_items, "--item", descriptor.gold_control_item,
        "--shard", "0", "--out", gold_out]
    print(f"== environment gold control: r2t {' '.join(gold_argv)}",
          file=sys.stderr)
    gold_error = None
    try:
        rc = _cli(gold_argv)
        if rc:
            gold_error = f"gold-control run exited {rc}"
    except SystemExit as exc:
        gold_error = str(exc) or "gold-control run refused"
    outcome = None
    if os.path.isfile(gold_out):
        with open(gold_out, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                row = json.loads(line)
                if row.get("item_id") == descriptor.gold_control_item:
                    outcome = row.get("outcome")
    passed = gold_error is None and outcome == "passed"
    record["gold_control"] = {
        "item": descriptor.gold_control_item,
        "out": gold_out,
        "outcome": outcome,
        "passed": passed,
        **({"error": gold_error} if gold_error else {}),
    }
    _write_record(path, record)
    print(json.dumps({
        "project": project, "nonce": nonce, "state": "up",
        "accepted": passed, "k": k, "workers_root": workers_root,
        "image": record["image"], "database": database,
        "gold_control": record["gold_control"], "record": path,
    }, indent=1))
    if not passed:
        print("REFUSED: environment up acceptance requires a passing "
              f"gold-control row; got outcome={outcome!r}"
              + (f" ({gold_error})" if gold_error else "")
              + ". The pool remains anchored by the record above; retire it "
                "with `environment down`.", file=sys.stderr)
        return 1
    return 0


def up(project: str, *, k: Optional[int] = None) -> int:
    descriptor = _descriptor(project)
    if descriptor.database is not None:
        return _up_database(project, descriptor, k=k)
    facts = manifest_facts(project)
    plan = facts["worker_plan"]
    k = int(plan["k"]) if k is None else k
    if k < 1:
        raise SystemExit("REFUSED: environment up needs --k of at least 1")
    tag = facts["harness_image"]

    from ..core import docker_cli as DC
    authority_path = DC.configured_authority_path()
    if authority_path is None:
        raise SystemExit(
            "REFUSED: environment up is a live Docker workload; name the "
            "verified authority artifact with --docker-authority. No Docker "
            "command was run.")
    _document, authority_ref = DC.authority_reference(live=True)

    roles = artifact_paths(project, data_root())
    release_items = roles.get("release_items")
    if not release_items or not os.path.isfile(release_items):
        raise SystemExit(
            f"REFUSED: installed bundle has no release items for {project} "
            f"({release_items!r}); install the project bundle first. No "
            "Docker command was run.")

    nonce = _mint_nonce()
    image_id = _build_image(descriptor.dockerfile_dir, tag)
    _host_preflight(project)

    environment_dir = os.path.join(environments_root(project), nonce)
    if os.path.lexists(environment_dir):
        raise SystemExit(
            f"REFUSED: environment root already exists: {environment_dir}. "
            "v3 pool evidence is immutable, so every up mints a fresh "
            "nonce-namespaced root; retire the existing environment with "
            "`environment down` instead of reusing its root.")
    os.makedirs(environment_dir)
    pool_image = _preserve_pool_image(project, nonce, image_id)
    workers_root = os.path.join(environment_dir, "workers")
    profile_path, boundary_path = _config_paths(project)
    base = ["--docker-authority", authority_path]

    _step("worker plan", base + [
        "worker", "plan", "--k", str(k), "--workers-root", workers_root,
        "--profile", profile_path, "--workdir", plan["workdir"],
        "--container-kind", plan["container_kind"], "--name", nonce])
    _step("worker provision", base + [
        "worker", "provision", "--k", str(k), "--workers-root", workers_root,
        "--profile", profile_path, "--image", pool_image])

    gold_out = os.path.join(environment_dir, GOLD_CONTROL_NAME)
    worker0 = os.path.join(workers_root, "worker0.json")
    gold_argv = base + [
        "--worker", worker0, "--boundary", boundary_path,
        "run", "--adapter", "gold", "--profile", profile_path,
        "--release", release_items, "--item", descriptor.gold_control_item,
        "--shard", "0", "--out", gold_out]
    if plan["container_kind"] == "go":
        # Go's workspace contract binds artifacts to the selected worker.
        from ..bench.worker import load_worker_spec
        gold_argv = ["--artifacts", load_worker_spec(worker0).artifacts_root] + gold_argv
    print(f"== environment gold control: r2t {' '.join(gold_argv)}",
          file=sys.stderr)
    gold_error = None
    try:
        rc = _cli(gold_argv)
        if rc:
            gold_error = f"gold-control run exited {rc}"
    except SystemExit as exc:
        gold_error = str(exc) or "gold-control run refused"
    outcome = None
    if os.path.isfile(gold_out):
        with open(gold_out, encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                row = json.loads(line)
                if row.get("item_id") == descriptor.gold_control_item:
                    outcome = row.get("outcome")
    passed = gold_error is None and outcome == "passed"

    record = {
        "schema": RECORD_SCHEMA,
        "project": project,
        "nonce": nonce,
        "created_at": _utc_now(),
        "state": "up",
        "k": k,
        "workers_root": workers_root,
        "workdir": plan["workdir"],
        "container_kind": plan["container_kind"],
        "image": {"tag": tag, "id": image_id,
                  "preserved_tag": pool_image},
        "docker_execution_authority": authority_ref,
        "database": None,
        "gold_control": {
            "item": descriptor.gold_control_item,
            "out": gold_out,
            "outcome": outcome,
            "passed": passed,
            **({"error": gold_error} if gold_error else {}),
        },
    }
    _write_record(record_path(project, nonce), record)
    print(json.dumps({
        "project": project, "nonce": nonce, "state": "up",
        "accepted": passed, "k": k, "workers_root": workers_root,
        "image": record["image"], "gold_control": record["gold_control"],
        "record": record_path(project, nonce),
    }, indent=1))
    if not passed:
        print("REFUSED: environment up acceptance requires a passing "
              f"gold-control row; got outcome={outcome!r}"
              + (f" ({gold_error})" if gold_error else "")
              + ". The pool remains anchored by the record above; retire it "
                "with `environment down`.", file=sys.stderr)
        return 1
    return 0


def status(project: str, *, nonce: Optional[str] = None) -> int:
    _descriptor(project)
    records = _saved_records(project)
    if not records and nonce is None:
        print(json.dumps({"project": project, "state": "absent"}, indent=1))
        return 0
    nonce, _path, record = _select_record(project, nonce, records)
    if record["state"] == "down":
        print(json.dumps({
            "project": project, "nonce": nonce, "state": "down",
            "torn_down_at": record.get("torn_down_at"),
        }, indent=1))
        return 0
    pool_error = _pool_live_error(record)
    database_error, database_status = _database_resource_status(record)
    errors = [error for error in (pool_error, database_error) if error]
    live_error = "; ".join(errors) if errors else None
    summary = {
        "project": project, "nonce": nonce, "state": "up",
        "live": live_error is None,
        "accepted": record["gold_control"]["passed"],
        "k": record["k"], "workers_root": record["workers_root"],
        "image": record["image"],
        **({"error": live_error} if live_error else {}),
    }
    if record["database"] is not None:
        summary["database"] = {
            "resources": record["database"],
            "status": database_status,
        }
    print(json.dumps(summary, indent=1))
    return 0 if live_error is None else 1


def down(project: str, *, nonce: Optional[str] = None) -> int:
    descriptor = _descriptor(project)
    records = _saved_records(project)
    if not records and nonce is None:
        raise SystemExit(
            f"REFUSED: no saved environment record for {project}; nothing "
            "to tear down, and this command never guesses at unrecorded "
            "resources. No Docker command was run.")
    nonce, path, record = _select_record(project, nonce, records)
    if record["state"] == "down":
        print(json.dumps({
            "project": project, "nonce": nonce, "state": "down",
            "torn_down_at": record.get("torn_down_at"),
            "note": "already torn down",
        }, indent=1))
        return 0
    from ..core import docker_cli as DC
    authority_path = DC.configured_authority_path()
    if authority_path is None:
        raise SystemExit(
            "REFUSED: environment down is a live Docker workload; name the "
            "verified authority artifact with --docker-authority. No Docker "
            "command was run.")
    _profile_path, boundary_path = _config_paths(project)
    workers_root = record["workers_root"]
    if record["database"] is not None:
        database = record["database"]
        if _complete_pool_identity_exists(record):
            _require_owned_database_resources(record)
            _step("worker teardown", [
                "--docker-authority", authority_path,
                "--worker", os.path.join(workers_root, "worker0.json"),
                "--boundary", boundary_path,
                "worker", "teardown", "--k", str(record["k"]),
                "--workers-root", workers_root,
                "--db-container", database["container"],
                "--internal-network", database["network"]])
        else:
            try:
                DC.require_authority_reference(
                    record["docker_execution_authority"], live=True)
            except DC.DockerEndpointRefused as exc:
                raise SystemExit(str(exc)) from exc
            # Both ownership and every present planned worker are proved
            # before the first recovery mutation. An absent partial resource
            # is harmless; an object at an exact saved name with another
            # identity refuses the whole cleanup without removing anything.
            _require_owned_database_resources(record)
            _recover_planned_database_workers(record, descriptor)
        # Worker teardown is one mutating command phase. Revalidate the saved
        # authority before the separately owned direct-resource phase.
        DC.reset_phase()
        _remove_database_resources(record)
        released = _release_pool_image_name(record)
        record["state"] = "down"
        record["torn_down_at"] = _utc_now()
        _write_record(path, record)
        print(json.dumps({
            "project": project, "nonce": nonce, "state": "down",
            "torn_down_at": record["torn_down_at"], "record": path,
            "database": database,
            **({"image_name": released} if released else {}),
        }, indent=1))
        return 0
    _step("worker teardown", [
        "--docker-authority", authority_path,
        "--worker", os.path.join(workers_root, "worker0.json"),
        "--boundary", boundary_path,
        "worker", "teardown", "--k", str(record["k"]),
        "--workers-root", workers_root])
    released = _release_pool_image_name(record)
    record["state"] = "down"
    record["torn_down_at"] = _utc_now()
    _write_record(path, record)
    print(json.dumps({
        "project": project, "nonce": nonce, "state": "down",
        "torn_down_at": record["torn_down_at"], "record": path,
        **({"image_name": released} if released else {}),
    }, indent=1))
    return 0


# ----------------------------------------------------------------- selftest

def selftest() -> int:
    import contextlib
    import io
    import tempfile
    from dataclasses import replace
    from unittest import mock
    from .. import docker_authority as A
    from ..core import docker_cli as DC
    from ..bench import worker as W

    failures = []

    def check(name, condition, detail=""):
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))
        if not condition:
            failures.append(name)

    def refused(fn) -> str:
        try:
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                fn()
        except SystemExit as exc:
            return str(exc)
        return ""

    def quiet(fn):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = fn()
        payload = out.getvalue().strip()
        return rc, (json.loads(payload) if payload.startswith("{") else None)

    events: list = []
    gold_outcome = {"value": "passed"}
    nonces = {"value": "efixture01"}

    def fake_cli(argv):
        events.append(("cli", list(argv)))
        if "worker" in argv \
                and argv[argv.index("worker") + 1] == "plan":
            from ..data.profile import config_stem
            profile = argv[argv.index("--profile") + 1]
            project = next(
                candidate for candidate in PROJECTS
                if _config_paths(candidate)[0] == profile)
            root = argv[argv.index("--workers-root") + 1]
            workers = W.plan_workers(
                root, int(argv[argv.index("--k") + 1]),
                name=argv[argv.index("--name") + 1],
                workdir=argv[argv.index("--workdir") + 1],
                prefix=config_stem(project),
                kind=argv[argv.index("--container-kind") + 1],
                needs_database=PROJECTS[project].database is not None)
            W.write_worker_pool(root, workers)
        if "run" in argv:
            out = argv[argv.index("--out") + 1]
            item = argv[argv.index("--item") + 1]
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"item_id": item,
                                     "outcome": gold_outcome["value"]}) + "\n")
        return 0

    #: The fixture image store: NAME -> immutable ID, the only Docker state
    #: this fix is about.  "somebody rebuilt `:base`" is then one assignment
    #: into this dict, and no image on the host running the selftest is
    #: touched to prove what happens when a tag moves.
    images: dict = {}

    def fake_build(dockerfile_dir, tag):
        events.append(("build", dockerfile_dir, tag))
        images[tag] = "sha256:" + "b" * 64
        return images[tag]

    def fake_doctor(project):
        events.append(("doctor", project))
        # A healthy fresh host has neither its saved pool nor generation-only
        # metric inputs. A database environment also has no legacy fixed-name
        # database: it is about to create its own nonce resource.
        return {"ok": False, "checks": [
            {"name": "data root", "status": "pass", "detail": "fixture"},
            {"name": "project image",
             "status": ("fail" if PROJECTS[project].database is not None
                        else "pass"),
             "detail": "fixture legacy image is not installed"},
            {"name": "project database",
             "status": ("fail" if PROJECTS[project].database is not None
                        else "pass"),
             "detail": "fixture database is not running"},
            {"name": "saved worker manifests", "status": "fail",
             "detail": "no saved worker manifests; run `r2t worker plan` "
                       "first"},
            {"name": "mutation readiness", "status": "fail",
             "detail": "not_scored_mutation: fixture route closed"},
            {"name": "coverage readiness", "status": "fail",
             "detail": "not_scored_coverage: missing gold_baseline"},
            {"name": "production method index", "status": "fail",
             "detail": "not_scored_api: installed bundle validation refused: "
                       "candidate results are absent from input staging"},
        ]}

    live_docker = _docker

    def store_docker(argv, **kwargs):
        """Serve the image verbs from the fixture store, delegate the rest.

        Only the image verbs are answered here; container/network traffic
        keeps whatever fake the surrounding case installed, so this is
        invisible to every check that predates the store.
        """
        argv = list(argv)

        def done(returncode, stdout="", stderr=""):
            return subprocess.CompletedProcess(argv, returncode,
                                               stdout, stderr)

        if argv[:2] == ["image", "tag"]:
            if argv[2] not in set(images.values()) | set(images):
                return done(1, "", f"No such image: {argv[2]}")
            images[argv[3]] = images.get(argv[2], argv[2])
            return done(0)
        if argv[:2] == ["image", "inspect"]:
            if argv[2] not in images:
                return done(1, "", f"No such image: {argv[2]}")
            return done(0, images[argv[2]] + "\n")
        if argv[:2] == ["image", "rm"]:
            if argv[2] not in images:
                return done(1, "", f"No such image: {argv[2]}")
            del images[argv[2]]
            return done(0)
        return live_docker(argv, **kwargs)

    module = sys.modules[__name__]
    module._docker = store_docker

    saved_root = os.environ.get("R2T_DATA_ROOT")
    real = {"_cli": _cli, "_build_image": _build_image,
            "_doctor_report": _doctor_report, "_mint_nonce": _mint_nonce,
            "_live_runtime": _live_runtime, "_docker": _docker,
            "_inspect": _inspect,
            "_wait_database": _wait_database,
            "_template_environment": _template_environment,
            "_create_database_resources": _create_database_resources,
            "_require_database_resources_absent":
                _require_database_resources_absent,
            "_require_planned_worker_containers_absent":
                _require_planned_worker_containers_absent,
            "_complete_pool_identity_exists":
                _complete_pool_identity_exists,
            "_recover_planned_database_workers":
                _recover_planned_database_workers,
            "_database_resource_status": _database_resource_status,
            "_require_owned_database_resources":
                _require_owned_database_resources,
            "_remove_database_resources": _remove_database_resources}
    with tempfile.TemporaryDirectory() as root:
        try:
            os.environ["R2T_DATA_ROOT"] = root
            document = A._fixture_authority()
            reference = {"path": "/private/authority.json",
                         "file_sha256": "a" * 64,
                         "digest": document["digest"]}

            release_dir = os.path.join(root, "projects", "python-docx",
                                       "artifacts", "release")
            os.makedirs(release_dir)
            with open(os.path.join(release_dir, "items.jsonl"), "w",
                      encoding="utf-8") as fh:
                fh.write(json.dumps({"item_id": PROJECTS[
                    "python-docx"].gold_control_item}) + "\n")

            module._build_image = fake_build
            module._doctor_report = fake_doctor
            module._cli = fake_cli
            module._mint_nonce = lambda: nonces["value"]

            DC.configure()
            message = refused(lambda: up("python-docx"))
            check("up without a configured authority refuses before any "
                  "Docker or lifecycle step",
                  "--docker-authority" in message and events == [], message)

            DC._install_test_authority(document, reference)

            def failed_host(project):
                report = fake_doctor(project)
                report["checks"].append({
                    "name": "Docker daemon access", "status": "fail",
                    "detail": "fixture daemon unavailable"})
                return report

            with mock.patch.object(module, "_doctor_report", failed_host):
                message = refused(lambda: up("python-docx", k=2))
            check("up still refuses a host failure before creating a pool "
                  "when generation-only metric inputs are absent",
                  "Docker daemon access: fixture daemon unavailable" in message
                  and [event[0] for event in events] == ["build", "doctor"]
                  and not os.path.exists(record_path(
                      "python-docx", "efixture01")), message)
            events.clear()

            rc, summary = quiet(lambda: up("python-docx", k=2))
            argvs = [e[1] for e in events if e[0] == "cli"]
            steps = [e[0] for e in events]
            environment_dir = os.path.join(root, "projects", "python-docx",
                                           ENVIRONMENTS_DIRNAME,
                                           "efixture01")
            workers_root = os.path.join(environment_dir, "workers")
            check("up composes authority, build, doctor, plan, provision "
                  "and gold control in order",
                  steps == ["build", "doctor", "cli", "cli", "cli"]
                  and argvs[0][argvs[0].index("worker") + 1] == "plan"
                  and argvs[1][argvs[1].index("worker") + 1] == "provision"
                  and "run" in argvs[2], str(steps))
            check("the pool is nonce-namespaced below a fresh environment "
                  "root",
                  argvs[0][argvs[0].index("--workers-root") + 1]
                  == workers_root
                  and argvs[0][argvs[0].index("--name") + 1] == "efixture01"
                  and argvs[0][argvs[0].index("--k") + 1] == "2"
                  and argvs[0][argvs[0].index("--container-kind") + 1]
                  == "py"
                  and argvs[0][argvs[0].index("--workdir") + 1] == "/work",
                  str(argvs[0]))
            check("provision reuses the same pool root and binds the pool "
                  "to the reserved name rather than the rebuildable tag",
                  argvs[1][argvs[1].index("--workers-root") + 1]
                  == workers_root
                  and argvs[1][argvs[1].index("--image") + 1]
                  == "r2t_preserve_img:python-docx-efixture01",
                  str(argvs[1]))
            check("the gold control runs the descriptor's item on worker 0 "
                  "of this pool",
                  argvs[2][argvs[2].index("--item") + 1]
                  == PROJECTS["python-docx"].gold_control_item
                  and argvs[2][argvs[2].index("--worker") + 1]
                  == os.path.join(workers_root, "worker0.json")
                  and argvs[2][argvs[2].index("--adapter") + 1] == "gold",
                  str(argvs[2]))
            record = _load_record(record_path("python-docx", "efixture01"))
            check("up accepts on a passing gold control and pins the "
                  "up-time image ID and authority reference",
                  rc == 0 and summary["accepted"] is True
                  and record["state"] == "up"
                  and record["gold_control"]["passed"] is True
                  and record["image"] == {
                      "tag": "r2t_docx_img:base",
                      "id": "sha256:" + "b" * 64,
                      "preserved_tag":
                          "r2t_preserve_img:python-docx-efixture01"}
                  and record["docker_execution_authority"] == reference
                  and record["k"] == 2 and record["database"] is None,
                  json.dumps(record))

            # The installed Go route has no extraction artifacts. Its
            # harness still requires the artifact root of its bound worker,
            # including when the saved plan chooses a non-default location.
            from .environment import Bringup
            go_item = "coddy-agent/features/hooks_subagents.feature:18"
            go_release = os.path.join(root, "projects", "coddy-agent",
                                      "artifacts", "release", "items.jsonl")
            os.makedirs(os.path.dirname(go_release))
            with open(go_release, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"item_id": go_item}) + "\n")
            go_artifacts = os.path.join(root, "planned-go-artifacts")
            go_runs = []

            def go_cli(argv):
                if "run" in argv:
                    go_runs.append(list(argv))
                    worker = W.load_worker_spec(
                        argv[argv.index("--worker") + 1])
                    if "--artifacts" not in argv or argv[
                            argv.index("--artifacts") + 1] != worker.artifacts_root:
                        raise SystemExit("Go artifacts must belong to the bound worker")
                rc = fake_cli(argv)
                if "worker" in argv and argv[argv.index("worker") + 1] == "plan":
                    planned = argv[argv.index("--workers-root") + 1]
                    worker = W.load_worker_spec(os.path.join(planned, "worker0.json"))
                    W.write_worker_pool(planned, [replace(worker, artifacts_root=go_artifacts)])
                return rc

            go_descriptor = Bringup(
                dockerfile_dir=os.path.join(BENCHMARK, "docker", "coddy_agent"),
                database=None, template_command=None, template_env=None,
                composer_cache=False, gold_control_item=go_item)
            with mock.patch.dict(PROJECTS, {"coddy-agent": go_descriptor}), \
                    mock.patch.object(module, "manifest_facts", return_value={
                        "harness_image": "coddy_agent_bench_img:fixture",
                        "worker_plan": {"k": 1, "workdir": "/work", "container_kind": "go"}}), \
                    mock.patch.object(module, "artifact_paths", return_value={"release_items": go_release}), \
                    mock.patch.object(module, "_mint_nonce", return_value="egoartifacts"), \
                    mock.patch.object(module, "_cli", go_cli):
                go_rc, go_summary = quiet(lambda: up("coddy-agent", k=1))
            check("Go environment gold control uses its actual bound worker artifact root",
                  go_rc == 0 and go_summary["accepted"] is True
                  and len(go_runs) == 1 and "--artifacts" in go_runs[0]
                  and go_runs[0][go_runs[0].index("--artifacts") + 1] == go_artifacts
                  and go_runs[0].index("--artifacts") < go_runs[0].index("run"),
                  str(go_runs))
            check("non-Go environment gold keeps its existing project artifact defaults",
                  "--artifacts" not in argvs[2], str(argvs[2]))

            # THE INVARIANT. `r2t campaign` resolves `--image` with
            # `docker image inspect <image> --format {{.Id}}` and refuses
            # unless it equals the digest the pool was accepted on, so
            # "can this pool still be minted?" is exactly "does a name still
            # resolve to its pinned ID?".  Ask that question of both names,
            # before and after somebody rebuilds `:base`.
            def resolves(name):
                completed = module._docker(
                    ["image", "inspect", name, "--format", "{{.Id}}"])
                return ((completed.stdout or "").strip()
                        if completed.returncode == 0 else None)

            pinned = record["image"]["id"]
            reserved = record["image"]["preserved_tag"]
            check("both names resolve to the pinned image while the pool is "
                  "the most recent build",
                  resolves(record["image"]["tag"]) == pinned
                  and resolves(reserved) == pinned,
                  str({"base": resolves(record["image"]["tag"]),
                       "reserved": resolves(reserved), "pinned": pinned}))

            # Somebody rebuilds the project image -- another bring-up, a
            # Dockerfile edit, a second agent on the same host. One tag move.
            images[record["image"]["tag"]] = "sha256:" + "9" * 64
            check("a rebuilt `:base` no longer names the running pool's "
                  "image, which is how pools were being lost",
                  resolves(record["image"]["tag"]) != pinned,
                  str(resolves(record["image"]["tag"])))
            check("the pool's reserved name still resolves to the exact "
                  "image it was accepted on, so the rebuild cannot orphan "
                  "it and `campaign` can still be minted against it",
                  resolves(reserved) == pinned,
                  str({"reserved": resolves(reserved), "pinned": pinned}))
            images[record["image"]["tag"]] = pinned

            events.clear()
            message = refused(lambda: up("python-docx", k=2))
            check("up refuses a dirty pool root before any pool step",
                  "already exists" in message
                  and [e for e in events if e[0] == "cli"] == [], message)

            events.clear()
            nonces["value"] = "efixture02"
            gold_outcome["value"] = "failed"
            rc, summary = quiet(lambda: up("python-docx", k=2))
            second = _load_record(record_path("python-docx", "efixture02"))
            check("up refuses acceptance when the gold-control row is not "
                  "passed, while still anchoring the pool",
                  rc == 1 and summary["accepted"] is False
                  and second["state"] == "up"
                  and second["gold_control"]["passed"] is False
                  and second["gold_control"]["outcome"] == "failed",
                  json.dumps(second))

            message = refused(lambda: status("python-docx"))
            check("two saved environments make an unqualified selection "
                  "ambiguous", "--nonce" in message, message)

            # The image store is the one live fact status reads directly,
            # so it is faked here for every pool case below.
            missing_images: set[str] = set()

            def fake_inspect(kind, name):
                if kind == "image":
                    return None if name in missing_images else {"Id": name}
                return real["_inspect"](kind, name)

            module._inspect = fake_inspect
            module._live_runtime = lambda record: {
                "selected": {"runtime": {
                    "container_image_digest": record["image"]["id"]}}}
            rc, summary = quiet(
                lambda: status("python-docx", nonce="efixture01"))
            check("status answers live-and-bound from the saved record",
                  rc == 0 and summary["state"] == "up"
                  and summary["live"] is True and summary["accepted"] is True,
                  json.dumps(summary))

            pinned_image = record["image"]["id"]
            missing_images.add(pinned_image)
            rc, summary = quiet(
                lambda: status("python-docx", nonce="efixture01"))
            check("status reports a pool whose pinned image left the image "
                  "store as unusable, and names the digest",
                  rc == 1 and summary["live"] is False
                  and pinned_image in summary["error"]
                  and "image store" in summary["error"], json.dumps(summary))
            missing_images.discard(pinned_image)

            absent_image = subprocess.CompletedProcess(
                [], 1, "", "Error response from daemon: No such image: "
                + pinned_image)
            module._docker = lambda argv, **_kwargs: absent_image
            try:
                resolved = real["_inspect"]("image", pinned_image)
            except SystemExit as exc:
                resolved = f"REFUSED: {exc}"
            module._docker = real["_docker"]
            check("an image the daemon does not have reads as absent, not "
                  "as an inspection failure", resolved is None, str(resolved))

            module._live_runtime = lambda record: {
                "selected": {"runtime": {
                    "container_image_digest": "sha256:" + "c" * 64}}}
            rc, summary = quiet(
                lambda: status("python-docx", nonce="efixture01"))
            check("status refuses a live pool that drifted from the pinned "
                  "up-time image",
                  rc == 1 and summary["live"] is False
                  and "pinned" in summary["error"], json.dumps(summary))

            def broken(record):
                raise W.WorkerRefused("REFUSED: fixture pool is broken")
            module._live_runtime = broken
            rc, summary = quiet(
                lambda: status("python-docx", nonce="efixture01"))
            check("status distinguishes a broken pool from an absent one",
                  rc == 1 and summary["state"] == "up"
                  and summary["live"] is False
                  and "broken" in summary["error"], json.dumps(summary))

            events.clear()
            module._recover_planned_database_workers = (
                lambda *_args: events.append(("unexpected-recovery",)))
            rc, _summary = quiet(
                lambda: down("python-docx", nonce="efixture01"))
            teardown_argv = events[0][1]
            first_workers = os.path.join(root, "projects", "python-docx",
                                         ENVIRONMENTS_DIRNAME, "efixture01",
                                         "workers")
            record = _load_record(record_path("python-docx", "efixture01"))
            check("no-database down keeps the existing authenticated "
                  "teardown path and never enters planned recovery",
                  rc == 0 and len(events) == 1
                  and "teardown" in teardown_argv
                  and teardown_argv[teardown_argv.index("--workers-root") + 1]
                  == first_workers
                  and teardown_argv[teardown_argv.index("--worker") + 1]
                  == os.path.join(first_workers, "worker0.json")
                  and teardown_argv[teardown_argv.index("--k") + 1] == "2"
                  and record["state"] == "down"
                  and record.get("torn_down_at"), str(teardown_argv))
            check("down gives the reserved name back, so a retired pool "
                  "stops pinning its image forever",
                  _summary.get("image_name")
                  == {"name": "r2t_preserve_img:python-docx-efixture01",
                      "released": True}
                  and "r2t_preserve_img:python-docx-efixture01" not in images,
                  json.dumps({"summary": _summary.get("image_name"),
                              "names": sorted(images)}))
            second = _load_record(record_path("python-docx", "efixture02"))
            check("the sibling environment's record is untouched",
                  second["state"] == "up"
                  and second["image"]["preserved_tag"] in images)

            rc, summary = quiet(
                lambda: status("python-docx", nonce="efixture01"))
            check("status answers torn-down from the retired record",
                  rc == 0 and summary["state"] == "down"
                  and summary.get("torn_down_at"), json.dumps(summary))

            events.clear()
            rc, summary = quiet(
                lambda: down("python-docx", nonce="efixture01"))
            check("down of a retired environment is a recorded no-op",
                  rc == 0 and events == []
                  and summary.get("note") == "already torn down",
                  json.dumps(summary))

            message = refused(lambda: down("coreshop"))
            check("down with no saved record refuses rather than guessing "
                  "at unrecorded resources",
                  "no saved environment record" in message
                  and events == [], message)

            rc, summary = quiet(lambda: status("coreshop"))
            check("status answers absent when no environment was ever "
                  "brought up",
                  rc == 0 and summary == {"project": "coreshop",
                                          "state": "absent"},
                  json.dumps(summary))
        finally:
            for name, value in real.items():
                setattr(module, name, value)
            DC.configure()
            if saved_root is None:
                os.environ.pop("R2T_DATA_ROOT", None)
            else:
                os.environ["R2T_DATA_ROOT"] = saved_root

    original_descriptor = PROJECTS["python-docx"]
    swapped_descriptor = replace(
        original_descriptor,
        database=PROJECTS["coreshop"].database,
        template_command=PROJECTS["coreshop"].template_command,
        template_env=PROJECTS["coreshop"].template_env,
        composer_cache=True)
    selected = []
    real_up_database = _up_database
    try:
        PROJECTS["python-docx"] = swapped_descriptor
        module._up_database = lambda project, descriptor, *, k=None: (
            selected.append((project, descriptor, k)) or 0)
        check("the database route is selected from descriptor fields, not "
              "the project name",
              up("python-docx", k=3) == 0
              and selected == [("python-docx", swapped_descriptor, 3)],
              str(selected))
    finally:
        PROJECTS["python-docx"] = original_descriptor
        module._up_database = real_up_database

    try:
        PROJECTS["python-docx"] = replace(
            swapped_descriptor,
            database=replace(swapped_descriptor.database,
                             alias="another-database"))
        alias_message = refused(lambda: _descriptor("python-docx"))
        PROJECTS["python-docx"] = replace(
            swapped_descriptor,
            database=replace(swapped_descriptor.database,
                             root_password="another-password"))
        password_message = refused(lambda: _descriptor("python-docx"))
        check("descriptor validation rejects database connection facts the "
              "existing worker surfaces cannot carry",
              "worker administration surface" in alias_message
              and "worker administration surface" in password_message,
              f"{alias_message}; {password_message}")
    finally:
        PROJECTS["python-docx"] = original_descriptor

    database_descriptor = PROJECTS["coreshop"]
    with tempfile.TemporaryDirectory() as root:
        try:
            os.environ["R2T_DATA_ROOT"] = root
            roles = artifact_paths("coreshop", root)
            os.makedirs(roles["seed"])
            os.makedirs(os.path.dirname(roles["release_items"]))
            with open(roles["release_items"], "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "item_id": database_descriptor.gold_control_item,
                }) + "\n")

            def fake_absent(database):
                events.append((
                    "direct-absent", database,
                    os.path.exists(record_path(
                        "coreshop", nonces["value"]))))

            def fake_worker_absent(workers):
                events.append((
                    "worker-absent",
                    tuple(worker.container for worker in workers),
                    os.path.exists(record_path(
                        "coreshop", nonces["value"]))))

            def fake_worker_name_absent(name):
                events.append((
                    "worker-absent", name,
                    os.path.exists(record_path(
                        "coreshop", nonces["value"]))))

            def fake_services(descriptor, **kwargs):
                early = _load_record(record_path(
                    "coreshop", nonces["value"]))
                events.append(("services", descriptor, kwargs, early))

            module._build_image = fake_build
            module._doctor_report = fake_doctor
            module._cli = fake_cli
            module._mint_nonce = lambda: nonces["value"]
            module._require_database_resources_absent = fake_absent
            module._require_planned_worker_containers_absent = real[
                "_require_planned_worker_containers_absent"]
            module._create_database_resources = fake_services
            nonces["value"] = "edatabase01"
            gold_outcome["value"] = "passed"
            events.clear()
            DC._install_test_authority(document, reference)

            with mock.patch.object(W, "require_container_absent",
                                   fake_worker_name_absent):
                rc, summary = quiet(lambda: up("coreshop", k=1))
            module._require_planned_worker_containers_absent = (
                fake_worker_absent)
            argvs = [event[1] for event in events if event[0] == "cli"]
            kinds = [event[0] for event in events]
            environment_dir = os.path.join(
                root, "projects", "coreshop", ENVIRONMENTS_DIRNAME,
                "edatabase01")
            workers_root = os.path.join(environment_dir, "workers")
            expected_database = _database_resources(
                database_descriptor, "edatabase01", 1)
            provision = argvs[1]
            harden = argvs[2]
            probe = argvs[3]
            gold = argvs[4]
            check("the shipped CoreShop descriptor composes its database "
                  "environment on a fresh host",
                  rc == 0 and summary["accepted"] is True
                  and kinds == ["build", "doctor", "cli", "worker-absent",
                                "direct-absent", "services", "cli", "cli",
                                "cli", "cli"]
                  and argvs[0][argvs[0].index("worker") + 1] == "plan"
                  and provision[provision.index("worker") + 1]
                  == "provision"
                  and harden[harden.index("worker") + 1] == "harden"
                  and probe[probe.index("worker") + 1] == "probe"
                  and "run" in gold, str(kinds))
            check("database provision receives the installed seed and exact "
                  "nonce resources",
                  provision[provision.index("--seed") + 1] == roles["seed"]
                  and provision[provision.index("--db-container") + 1]
                  == expected_database["container"]
                  and provision[provision.index("--internal-network") + 1]
                  == expected_database["network"]
                  and provision[provision.index("--template-container") + 1]
                  == expected_database["template_container"]
                  and provision[provision.index("--composer-cache") + 1]
                  == os.path.join(environment_dir, "composer-cache")
                  and os.path.isdir(os.path.join(
                      environment_dir, "composer-cache")), str(provision))
            check("K=1 hardening precedes a real named-sentinel probe",
                  probe[probe.index("--sentinel-schema") + 1]
                  == expected_database["sentinel_schema"]
                  and harden.index("harden") < len(harden)
                  and kinds.index("services") < kinds.index("cli", 5),
                  str(probe))
            service = next(event for event in events
                           if event[0] == "services")
            check("direct composition consumes only descriptor/resource "
                  "facts",
                  service[1] is database_descriptor
                  and service[2]["database"] == expected_database
                  and service[2]["seed"] == roles["seed"]
                  and service[2]["workdir"] == "/var/www/html"
                  and service[2]["image"]
                  == "r2t_preserve_img:coreshop-edatabase01"
                  and service[3]["state"] == "up"
                  and service[3]["gold_control"]["passed"] is False
                  and service[3]["gold_control"]["outcome"] is None
                  and next(event[1] for event in events
                           if event[0] == "worker-absent")
                  == W.load_worker_pool(workers_root, 1)[0].container
                  and all(event[2] is False for event in events
                          if event[0] in {
                              "worker-absent", "direct-absent"}),
                  str(service[2]))
            record = _load_record(record_path(
                "coreshop", "edatabase01"))
            check("accepted database record saves every exact non-secret "
                  "resource needed by status and down",
                  record["database"] == expected_database
                  and record["gold_control"]["passed"] is True
                  and "root_password" not in record["database"],
                  json.dumps(record))

            saved_label = {ENVIRONMENT_LABEL: "edatabase01"}
            resource_docs = {
                ("network", expected_database["network"]): {
                    "Labels": saved_label, "Internal": True,
                    "Driver": "bridge", "Scope": "local",
                },
                ("container", expected_database["container"]): {
                    "Config": {"Labels": saved_label,
                               "Image": expected_database["image"]},
                    "State": {"Running": True,
                              "Health": {"Status": "healthy"}},
                    "HostConfig": {
                        "NetworkMode": expected_database["network"]},
                    "NetworkSettings": {"Networks": {
                        expected_database["network"]: {
                            "Aliases": [expected_database["alias"]]},
                    }},
                },
                ("container", expected_database["template_container"]): {
                    "Config": {"Labels": saved_label},
                    "State": {"Running": True},
                    "Image": record["image"]["id"],
                    "HostConfig": {"NetworkMode": "none"},
                },
            }
            module._inspect = lambda kind, name: resource_docs[(kind, name)]
            direct_error, direct_status = real[
                "_database_resource_status"](record)
            check("direct status validates the saved label, topology, image, "
                  "and MySQL health",
                  direct_error is None
                  and all(item["ok"] for item in direct_status.values()),
                  json.dumps(direct_status))
            resource_docs[("container", expected_database["container"])][
                "State"]["Health"]["Status"] = "unhealthy"
            direct_error, direct_status = real[
                "_database_resource_status"](record)
            check("direct status rejects a running but unhealthy database",
                  direct_error is not None and "healthy" in direct_error
                  and not direct_status["container"]["ok"],
                  json.dumps(direct_status))
            resource_docs[("container", expected_database["container"])][
                "State"]["Health"]["Status"] = "healthy"

            resource_docs[("container",
                           expected_database["template_container"])][
                               "Config"]["Labels"] = {
                                   ENVIRONMENT_LABEL: "another-environment"}
            message = refused(
                lambda: real["_require_owned_database_resources"](record))
            check("direct removal ownership refuses an exact resource with "
                  "another environment label",
                  "does not carry exact label" in message, message)
            resource_docs[("container",
                           expected_database["template_container"])][
                               "Config"]["Labels"] = saved_label
            removal_calls = []

            def fake_removal_docker(argv, **_kwargs):
                removal_calls.append(list(argv))
                return subprocess.CompletedProcess(argv, 0, "", "")

            module._docker = fake_removal_docker
            real["_remove_database_resources"](record)
            check("direct removal rechecks and removes exactly the saved "
                  "template, database, then network",
                  removal_calls == [
                      ["container", "rm", "--force",
                       expected_database["template_container"]],
                      ["container", "rm", "--force",
                       expected_database["container"]],
                      ["network", "rm", expected_database["network"]],
                  ], str(removal_calls))
            module._inspect = fake_inspect
            module._docker = real["_docker"]

            module._live_runtime = lambda saved: {
                "selected": {
                    "runtime": {
                        "container_image_digest": saved["image"]["id"],
                    },
                    "binding": {"pool": {
                        "database": {"container_name":
                                     saved["database"]["container"]},
                        "network": {"name":
                                    saved["database"]["network"]},
                    }},
                },
            }
            healthy_direct = {
                role: {"name": expected_database[role], "ok": True}
                for role in ("network", "container", "template_container")
            }
            module._database_resource_status = (
                lambda _record: (None, healthy_direct))
            rc, status_summary = quiet(lambda: status(
                "coreshop", nonce="edatabase01"))
            check("database status combines exact direct resources with the "
                  "authenticated pool",
                  rc == 0 and status_summary["live"] is True
                  and status_summary["database"]["resources"]
                  == expected_database, json.dumps(status_summary))
            module._database_resource_status = lambda _record: (
                "template_container: saved resource is absent",
                {"template_container": {"ok": False}})
            rc, status_summary = quiet(lambda: status(
                "coreshop", nonce="edatabase01"))
            check("database status degrades when one saved direct resource "
                  "does not validate",
                  rc == 1 and status_summary["live"] is False
                  and "template_container" in status_summary["error"],
                  json.dumps(status_summary))

            completed_record = _load_record(record_path(
                "coreshop", "edatabase01"))
            for index in range(completed_record["k"]):
                spec = os.path.join(
                    completed_record["workers_root"], f"worker{index}.json")
                for evidence_path in (
                        W.binding_attestation_path(spec),
                        W.runtime_attestation_path(spec)):
                    with open(evidence_path, "w", encoding="utf-8") as fh:
                        fh.write("{}\n")
            events.clear()
            module._complete_pool_identity_exists = real[
                "_complete_pool_identity_exists"]
            module._recover_planned_database_workers = (
                lambda *_args: events.append(("unexpected-recovery",)))

            def wrong_owner(_record):
                events.append(("ownership", "wrong"))
                raise SystemExit("REFUSED: fixture wrong environment label")

            module._require_owned_database_resources = wrong_owner
            module._remove_database_resources = (
                lambda _record: events.append(("remove-direct",)))
            message = refused(lambda: down(
                "coreshop", nonce="edatabase01"))
            still_up = _load_record(record_path(
                "coreshop", "edatabase01"))
            check("down refuses a wrong direct-resource label before worker "
                  "or direct removal",
                  "wrong environment label" in message
                  and events == [("ownership", "wrong")]
                  and still_up["state"] == "up", message)

            events.clear()
            module._require_owned_database_resources = (
                lambda _record: events.append(("ownership", "ok")))
            module._remove_database_resources = (
                lambda _record: events.append(("remove-direct",)))
            module._cli = fake_cli
            rc, down_summary = quiet(lambda: down(
                "coreshop", nonce="edatabase01"))
            teardown = next(event[1] for event in events
                            if event[0] == "cli")
            retired = _load_record(record_path(
                "coreshop", "edatabase01"))
            check("database down authenticates the exact pool before direct "
                  "resource removal and only then retires its record",
                  rc == 0
                  and [event[0] for event in events]
                  == ["ownership", "cli", "remove-direct"]
                  and teardown[teardown.index("worker") + 1] == "teardown"
                  and teardown[teardown.index("--db-container") + 1]
                  == expected_database["container"]
                  and teardown[teardown.index("--internal-network") + 1]
                  == expected_database["network"]
                  and real["_complete_pool_identity_exists"](
                      completed_record)
                  and retired["state"] == "down"
                  and down_summary["database"] == expected_database,
                  str(events))

            # A post-provision hardening failure has a complete v3 pool, so
            # it keeps the ordinary unaccepted record for normal down rather
            # than minting a rollback/repair state.
            nonces["value"] = "edatabase02"

            def harden_failure(argv):
                if "worker" in argv \
                        and argv[argv.index("worker") + 1] == "harden":
                    events.append(("cli", list(argv)))
                    raise SystemExit("REFUSED: fixture hardening failed")
                return fake_cli(argv)

            module._cli = harden_failure
            events.clear()
            DC._install_test_authority(document, reference)
            message = refused(lambda: up("coreshop", k=1))
            failed_record = _load_record(record_path(
                "coreshop", "edatabase02"))
            check("post-provision isolation failure remains an ordinary "
                  "unaccepted, downable environment record",
                  "hardening failed" in message
                  and failed_record["state"] == "up"
                  and failed_record["gold_control"]["passed"] is False
                  and "hardening failed"
                  in failed_record["gold_control"]["error"],
                  json.dumps(failed_record))

            # The first direct-resource mutation is already anchored. A
            # failure after the labelled network exists leaves one ordinary
            # selectable record, and later down tolerates every other planned
            # resource being absent.
            nonces["value"] = "edatabase03"
            direct_failure_docs = {}
            direct_failure_record = {}

            def fail_during_direct_creation(descriptor, **kwargs):
                del descriptor
                early = _load_record(record_path(
                    "coreshop", "edatabase03"))
                direct_failure_record.update(early)
                database = kwargs["database"]
                label = {ENVIRONMENT_LABEL: "edatabase03"}
                direct_failure_docs[("network", database["network"])] = {
                    "Labels": label,
                }
                direct_failure_docs[("container", database["container"])] = {
                    "Config": {"Labels": label},
                }
                events.append(("direct-created-database",
                               database["container"]))
                raise SystemExit(
                    "REFUSED: fixture database never became healthy")

            module._cli = fake_cli
            module._complete_pool_identity_exists = real[
                "_complete_pool_identity_exists"]
            module._create_database_resources = fail_during_direct_creation
            events.clear()
            DC._install_test_authority(document, reference)
            message = refused(lambda: up("coreshop", k=1))
            partial = _load_record(record_path(
                "coreshop", "edatabase03"))
            direct_database = partial["database"]
            check("a database-health failure is anchored before its owned "
                  "direct resources survive",
                  "never became healthy" in message
                  and direct_failure_record["state"] == "up"
                  and direct_failure_record["nonce"] == "edatabase03"
                  and direct_failure_record["workers_root"]
                  == os.path.join(os.path.dirname(record_path(
                      "coreshop", "edatabase03")), "workers")
                  and direct_failure_record["image"] == {
                      "tag": "coreshop_bench_img:base",
                      "id": "sha256:" + "b" * 64,
                      "preserved_tag":
                          "r2t_preserve_img:coreshop-edatabase03",
                  }
                  and direct_failure_record[
                      "docker_execution_authority"] == reference
                  and direct_failure_record["database"]
                  == _database_resources(
                      database_descriptor, "edatabase03", 1)
                  and direct_failure_record["gold_control"]["passed"]
                  is False
                  and direct_failure_record["gold_control"]["outcome"]
                  is None
                  and ("network", direct_database["network"])
                  in direct_failure_docs
                  and ("container", direct_database["container"])
                  in direct_failure_docs,
                  json.dumps(direct_failure_record))

            direct_inspections = []

            def inspect_direct_partial(kind, name):
                direct_inspections.append((kind, name))
                return direct_failure_docs.get((kind, name))

            direct_removals = []

            def remove_direct_partial(argv, **_kwargs):
                direct_removals.append(list(argv))
                if argv[:3] == ["container", "rm", "--force"]:
                    direct_failure_docs[("container", argv[3])] = None
                elif argv[:2] == ["network", "rm"]:
                    direct_failure_docs[("network", argv[2])] = None
                return subprocess.CompletedProcess(argv, 0, "", "")

            module._inspect = inspect_direct_partial
            module._docker = remove_direct_partial
            module._require_owned_database_resources = real[
                "_require_owned_database_resources"]
            module._recover_planned_database_workers = real[
                "_recover_planned_database_workers"]
            module._remove_database_resources = real[
                "_remove_database_resources"]
            recovered_plans = []

            def teardown_absent_plan(worker, db, **kwargs):
                recovered_plans.append((worker, db, kwargs))
                return {"container": False}

            class UnreadyMySQL:
                def __init__(self, **_kwargs):
                    pass

                def __enter__(self):
                    return self

                def __exit__(self, *_exc):
                    return None

                def schemas(self):
                    raise subprocess.TimeoutExpired(
                        ["docker", "exec", "fixture-db"], 60)

            from ..bench import dbadmin as DB
            DC._install_test_authority(document, reference)
            with mock.patch.object(W, "teardown", teardown_absent_plan), \
                    mock.patch.object(DB, "MySQL", UnreadyMySQL):
                rc, _summary = quiet(lambda: down(
                    "coreshop", nonce="edatabase03"))
            retired = _load_record(record_path(
                "coreshop", "edatabase03"))
            check("down later selects the direct-failure record and removes "
                  "only its present labelled resources",
                  rc == 0 and retired["state"] == "down"
                  and len(recovered_plans) == 1
                  and recovered_plans[0][1] is None
                  and recovered_plans[0][2]["image"]
                  == partial["image"]["id"]
                  and direct_removals == [
                      ["container", "rm", "--force",
                       direct_database["container"]],
                      ["network", "rm", direct_database["network"]],
                      ["image", "rm",
                       "r2t_preserve_img:coreshop-edatabase03"],
                  ],
                  str({"plans": recovered_plans,
                       "direct": direct_removals,
                       "inspections": direct_inspections}))

            # Provisioning can stop after it has created worker-owned state
            # but before any complete binding/runtime set. Recovery validates
            # every present container first, then consumes only the saved
            # plans and the saved direct-resource identities.
            nonces["value"] = "edatabase04"
            provision_docs = {}
            provision_workers = []

            def create_partial_services(descriptor, **kwargs):
                del descriptor
                database = kwargs["database"]
                label = {ENVIRONMENT_LABEL: "edatabase04"}
                provision_docs.update({
                    ("network", database["network"]): {"Labels": label},
                    ("container", database["container"]): {
                        "Config": {"Labels": label},
                    },
                    ("container", database["template_container"]): {
                        "Config": {"Labels": label},
                    },
                })
                events.append(("services", database))

            def fail_during_provision(argv):
                if "worker" in argv \
                        and argv[argv.index("worker") + 1] == "provision":
                    events.append(("cli", list(argv)))
                    root_path = argv[argv.index("--workers-root") + 1]
                    workers = W.load_worker_pool(root_path, 2)
                    provision_workers[:] = workers
                    for worker in workers:
                        os.makedirs(worker.workspace)
                        os.makedirs(os.path.dirname(worker.env_file),
                                    exist_ok=True)
                        with open(worker.env_file, "w", encoding="utf-8") \
                                as fh:
                            fh.write("FIXTURE=1\n")
                        os.chmod(worker.env_file, 0o600)
                        provision_docs[("container", worker.container)] = {
                            "Name": "/" + worker.container,
                            "Image": "sha256:" + "b" * 64,
                            "Mounts": [{
                                "Source": worker.workspace,
                                "Destination": worker.workdir,
                                "Type": "bind",
                                "RW": True,
                            }],
                        }
                    raise SystemExit(
                        "REFUSED: fixture provision failed before v3 binding")
                return fake_cli(argv)

            module._cli = fail_during_provision
            module._create_database_resources = create_partial_services
            module._require_planned_worker_containers_absent = real[
                "_require_planned_worker_containers_absent"]
            module._inspect = real["_inspect"]
            module._docker = real["_docker"]
            events.clear()
            DC._install_test_authority(document, reference)
            with mock.patch.object(W, "require_container_absent",
                                   fake_worker_name_absent):
                message = refused(lambda: up("coreshop", k=2))
            module._require_planned_worker_containers_absent = (
                fake_worker_absent)
            provision_record = _load_record(record_path(
                "coreshop", "edatabase04"))
            check("a provisioning failure before v3 completion keeps the "
                  "ordinary exact-resource record selectable",
                  "before v3 binding" in message
                  and provision_record["state"] == "up"
                  and provision_record["gold_control"]["passed"] is False
                  and len(provision_workers) == 2
                  and [event[1] for event in events
                       if event[0] == "worker-absent"] == [
                           worker.container for worker in provision_workers]
                  and all(event[2] is False for event in events
                          if event[0] == "worker-absent")
                  and not _complete_pool_identity_exists(provision_record),
                  json.dumps(provision_record))

            worker_inspections = []

            def inspect_provision_partial(kind, name):
                worker_inspections.append((kind, name))
                return provision_docs.get((kind, name))

            direct_recovery_removals = []

            def remove_provision_direct(argv, **_kwargs):
                direct_recovery_removals.append(list(argv))
                if argv[:3] == ["container", "rm", "--force"]:
                    provision_docs[("container", argv[3])] = None
                elif argv[:2] == ["network", "rm"]:
                    provision_docs[("network", argv[2])] = None
                return subprocess.CompletedProcess(argv, 0, "", "")

            module._inspect = inspect_provision_partial
            module._docker = remove_provision_direct
            module._require_owned_database_resources = real[
                "_require_owned_database_resources"]
            module._recover_planned_database_workers = real[
                "_recover_planned_database_workers"]
            module._remove_database_resources = real[
                "_remove_database_resources"]
            module._complete_pool_identity_exists = real[
                "_complete_pool_identity_exists"]

            mutation_calls = []
            class ValidationMySQL:
                def __init__(self, **_kwargs):
                    pass

                def __enter__(self):
                    return self

                def __exit__(self, *_exc):
                    return None

                def schemas(self):
                    return []

            def unexpected_teardown(worker, _db, **_kwargs):
                mutation_calls.append(worker.container)
                return {"container": True}

            provision_docs[("container", provision_workers[1].container)][
                "Name"] = "/another-worker"
            DC._install_test_authority(document, reference)
            with mock.patch.object(W, "teardown", unexpected_teardown), \
                    mock.patch.object(DB, "MySQL", ValidationMySQL):
                message = refused(lambda: down(
                    "coreshop", nonce="edatabase04"))
            still_up = _load_record(record_path(
                "coreshop", "edatabase04"))
            inspected_workers = [name for kind, name in worker_inspections
                                 if kind == "container"
                                 and name in {worker.container
                                              for worker in provision_workers}]
            check("a wrong live worker name refuses after inspecting every "
                  "present worker and before any removal",
                  "live name is" in message
                  and inspected_workers == [
                      worker.container for worker in provision_workers]
                  and mutation_calls == []
                  and direct_recovery_removals == []
                  and still_up["state"] == "up", message)

            provision_docs[("container", provision_workers[1].container)][
                "Name"] = "/" + provision_workers[1].container
            worker_inspections.clear()
            mutation_calls.clear()
            provision_docs[("container", provision_workers[1].container)][
                "Image"] = "sha256:" + "c" * 64
            DC._install_test_authority(document, reference)
            with mock.patch.object(W, "teardown", unexpected_teardown), \
                    mock.patch.object(DB, "MySQL", ValidationMySQL):
                message = refused(lambda: down(
                    "coreshop", nonce="edatabase04"))
            still_up = _load_record(record_path(
                "coreshop", "edatabase04"))
            inspected_workers = [name for kind, name in worker_inspections
                                 if kind == "container"
                                 and name in {worker.container
                                              for worker in provision_workers}]
            check("a wrong planned-worker image refuses after inspecting "
                  "every present worker and before any removal",
                  "immutable image differs" in message
                  and inspected_workers == [
                      worker.container for worker in provision_workers]
                  and mutation_calls == []
                  and direct_recovery_removals == []
                  and still_up["state"] == "up", message)

            provision_docs[("container", provision_workers[1].container)][
                "Image"] = provision_record["image"]["id"]
            provision_docs[("container", provision_workers[1].container)][
                "Mounts"][0]["Source"] = os.path.join(root, "wrong-workspace")
            worker_inspections.clear()
            mutation_calls.clear()
            DC._install_test_authority(document, reference)
            with mock.patch.object(W, "teardown", unexpected_teardown), \
                    mock.patch.object(DB, "MySQL", ValidationMySQL):
                message = refused(lambda: down(
                    "coreshop", nonce="edatabase04"))
            still_up = _load_record(record_path(
                "coreshop", "edatabase04"))
            inspected_workers = [name for kind, name in worker_inspections
                                 if kind == "container"
                                 and name in {worker.container
                                              for worker in provision_workers}]
            check("a wrong planned-worker workspace mount refuses before "
                  "worker or direct cleanup and leaves the record up",
                  "workspace mount differs" in message
                  and inspected_workers == [
                      worker.container for worker in provision_workers]
                  and mutation_calls == []
                  and direct_recovery_removals == []
                  and still_up["state"] == "up", message)

            provision_docs[("container", provision_workers[1].container)][
                "Mounts"][0]["Source"] = provision_workers[1].workspace
            worker_container_removals = []
            workspace_removals = []
            sql_removals = []

            def remove_planned_container(name, **_kwargs):
                worker_container_removals.append(name)
                key = ("container", name)
                existed = provision_docs.get(key) is not None
                provision_docs[key] = None
                return existed

            def remove_planned_workspace(path, **kwargs):
                workspace_removals.append((path, kwargs.get("image")))
                os.rmdir(path)
                return {"removed": True, "as_root": False}

            class RecoveryMySQL:
                def __init__(self, **kwargs):
                    sql_removals.append(("connect", kwargs))

                def __enter__(self):
                    return self

                def __exit__(self, *_exc):
                    return None

                def schemas(self):
                    return []

                def drop_principal(self, name):
                    sql_removals.append(("principal", name))

                def drop_schema(self, name):
                    sql_removals.append(("schema", name))

            from ..bench import dbadmin as DB
            DC._install_test_authority(document, reference)
            with mock.patch.object(W, "remove_container",
                                   remove_planned_container), \
                    mock.patch.object(W, "remove_workspace",
                                      remove_planned_workspace), \
                    mock.patch.object(DB, "MySQL", RecoveryMySQL):
                rc, _summary = quiet(lambda: down(
                    "coreshop", nonce="edatabase04"))
            recovered = _load_record(record_path(
                "coreshop", "edatabase04"))
            check("a corrected later down removes only exact saved worker "
                  "and direct resources before retiring the same record",
                  rc == 0 and recovered["state"] == "down"
                  and worker_container_removals == [
                      *(worker.container for worker in provision_workers),
                  ]
                  and [entry for entry in sql_removals
                       if entry[0] == "principal"] == [
                           ("principal", worker.credential)
                           for worker in provision_workers]
                  and [entry for entry in sql_removals
                       if entry[0] == "schema"] == [
                           ("schema", worker.schema)
                           for worker in provision_workers]
                  and workspace_removals == [
                      (worker.workspace, provision_record["image"]["id"])
                      for worker in provision_workers]
                  and all(not os.path.exists(worker.env_file)
                          and not os.path.exists(worker.workspace)
                          for worker in provision_workers)
                  and direct_recovery_removals == [
                      ["container", "rm", "--force",
                       provision_record["database"]["template_container"]],
                      ["container", "rm", "--force",
                       provision_record["database"]["container"]],
                      ["network", "rm",
                       provision_record["database"]["network"]],
                      ["image", "rm",
                       provision_record["image"]["preserved_tag"]],
                  ],
                  str({"workers": worker_container_removals,
                       "sql": sql_removals,
                       "workspaces": workspace_removals,
                       "direct": direct_recovery_removals}))

            # Exercise the direct-resource argv seam without Docker. The
            # template-key helper itself is checked separately below.
            direct_calls = []
            sentinel_calls = []

            def fake_direct_docker(argv, **kwargs):
                direct_calls.append((list(argv), kwargs.get("env")))
                return subprocess.CompletedProcess(
                    argv, 0, stdout="d" * 64 + "\n", stderr="")

            class FakeMySQL:
                def __init__(self, **kwargs):
                    sentinel_calls.append(("connect", kwargs))

                def __enter__(self):
                    return self

                def __exit__(self, *_exc):
                    return None

                def create_schema(self, name):
                    sentinel_calls.append(("create", name))

                def load(self, name, path):
                    sentinel_calls.append(("load", name, path))

                def table_bytes(self, name):
                    sentinel_calls.append(("tables", name))
                    return {"fixture": 1}

            module._docker = fake_direct_docker
            module._wait_database = (
                lambda name: direct_calls.append((["wait", name], None)))
            module._template_environment = (
                lambda *_args, **_kwargs: {"FIXTURE_ENV": "fixture"})
            from ..bench import dbadmin as DB
            with mock.patch.object(DB, "MySQL", FakeMySQL):
                real["_create_database_resources"](
                    database_descriptor, database=expected_database,
                    seed=roles["seed"], workdir="/var/www/html",
                    image="coreshop_bench_img:base",
                    environment_dir=environment_dir)
            docker_argvs = [call[0] for call in direct_calls
                            if call[0][0] != "wait"]
            database_run, template_run = docker_argvs[1], docker_argvs[2]
            label = f"{ENVIRONMENT_LABEL}=edatabase01"
            check("direct DB resources are nonce-labelled and descriptor "
                  "driven",
                  docker_argvs[0][:6] == [
                      "network", "create", "--driver", "bridge",
                      "--internal", "--label"]
                  and label in docker_argvs[0]
                  and database_run[-1]
                  == database_descriptor.database.image
                  and database_run[database_run.index("--network-alias") + 1]
                  == database_descriptor.database.alias
                  and label in database_run
                  and database_run[database_run.index("--name") + 1]
                  == expected_database["container"]
                  and direct_calls[1][1]["MYSQL_ROOT_PASSWORD"]
                  == database_descriptor.database.root_password
                  and ("connect", {
                      "container": expected_database["container"],
                      "password": database_descriptor.database.root_password,
                  }) in sentinel_calls,
                  str(docker_argvs))
            check("template stays off the database network and K=1 loads a "
                  "populated seed sentinel",
                  template_run[template_run.index("--network") + 1] == "none"
                  and label in template_run
                  and template_run[template_run.index("--name") + 1]
                  == expected_database["template_container"]
                  and ("load", expected_database["sentinel_schema"],
                       os.path.join(roles["seed"], "database.sql"))
                  in sentinel_calls,
                  str({"docker": docker_argvs,
                       "sentinel": sentinel_calls}))

            helper_calls = []

            def fake_helper_docker(argv, **_kwargs):
                helper_calls.append(list(argv))
                return subprocess.CompletedProcess(
                    argv, 0, stdout="def" + "1" * 133 + "\n", stderr="")

            module._docker = fake_helper_docker
            from ..bench import seed as S
            with mock.patch.object(S, "unpack_workspace"):
                template_values = real["_template_environment"](
                    database_descriptor, database=expected_database,
                    seed=roles["seed"], workdir="/var/www/html",
                    image="coreshop_bench_img:base",
                    environment_dir=environment_dir)
            helper = helper_calls[0]
            check("the seed-backed Defuse helper is labelled, isolated, and "
                  "read-only",
                  template_values["PIMCORE_SECRET"]
                  == "def" + "1" * 133
                  and helper[helper.index("--name") + 1]
                  == expected_database["template_container"]
                  and helper[helper.index("--label") + 1] == label
                  and helper[helper.index("--network") + 1] == "none"
                  and helper[helper.index("--volume") + 1].endswith(
                      ":/var/www/html:ro")
                  and helper[-len(database_descriptor.template_command):]
                  == list(database_descriptor.template_command), str(helper))
        finally:
            for name, value in real.items():
                setattr(module, name, value)
            DC.configure()
            if saved_root is None:
                os.environ.pop("R2T_DATA_ROOT", None)
            else:
                os.environ["R2T_DATA_ROOT"] = saved_root

    module._docker = live_docker
    print("\n" + ("ALL PASS (environment lifecycle)" if not failures
                  else "FAILURES (environment lifecycle)"))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
