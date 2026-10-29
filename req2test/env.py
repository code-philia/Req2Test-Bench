"""Per-project execution environments: `req2test env
up|status|down|stop-daemon`.

`up(kit, workers, run_dir)` turns an installed evaluation kit into a qualified
pool of engine workers on a current-user rootless Docker daemon:

1. select the daemon (`--docker-host`) or create this home's own one, and
   capture or reuse its `r2t.docker-execution-authority/v1` artifact;
2. load the kit's images and verify each by its config digest;
3. stage the kit's execution inputs in the engine's layout (seed, gold tree,
   `artifacts/release/{items.jsonl,gold/}`), relocating the absolute paths
   the kit's manifests recorded on the build host;
4. for database-backed projects, start the MySQL container on a dedicated
   internal network and the template container that carries the
   application environment (CoreShop's `template.env` is generated here, at
   install time, and never leaves the environment directory);
5. plan and provision the workers with the engine's `worker plan` /
   `worker provision`, then qualify them: `harden`, `probe` and
   `reset-probe` where there is a database, and a gold control on every
   worker.

Every worker step is the engine's own command surface (`python -m r2t.cli`),
run as a subprocess with an explicit argv, so the engine's evidence rules
(fresh-pool no-clobber, v3/v4 runtime attestations, memory policy, database
isolation) apply unchanged.  The few direct Docker commands here (image
load, network, database and template containers) go through the engine's
authority-derived client argv.

Nothing is written inside the git clone: environments live under
`$REQ2TEST_HOME/envs/<project>/<nonce>/` and the engine's data root is
`$REQ2TEST_HOME/engine/`.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional

from . import ENGINE_ROOT
from . import kits

GIB = 1 << 30

#: Environment record schema (`envs/<project>/<nonce>/env.json`).
RECORD_SCHEMA = "req2test.env/1"
#: Staged-input record schema (`engine/inputs/<project>/<kit>/inputs.json`).
INPUTS_SCHEMA = "req2test.env-inputs/1"
LABEL = "org.req2test.environment"
DB_ROOT_PASSWORD = "root"          # the engine's DEFAULT_ROOT_PASSWORD
#: Variables the engine refuses to see in its environment (they would select
#: a Docker daemon behind the authority's back).
AMBIENT_DOCKER_KEYS = (
    "DOCKER_API_VERSION", "DOCKER_CERT_PATH", "DOCKER_CONFIG",
    "DOCKER_CONTEXT", "DOCKER_DEFAULT_PLATFORM", "DOCKER_HOST",
    "DOCKER_TLS", "DOCKER_TLS_VERIFY",
)
#: Concurrent engine subprocesses during provision and qualification.
MAX_PARALLEL = 8
#: What to do with user files when the clone is not clean (`.gitignore`
#: ignores `/work/`).
CLEAN_CLONE_HINT = ("keep tasks, views and predictions outside the clone "
                    "(e.g. ~/r2t-work) or under ./work/")
#: Dirty paths the refusal names.
DIRTY_LISTED = 10


class EnvError(RuntimeError):
    """`env up/down/status` cannot proceed; the message says why and what next."""


# --------------------------------------------------------------------------
# Per-project descriptors (data).
#
# Paths are relative to the kit root (`kit.json`'s directory).  The kits
# were assembled by different builders, so the descriptor -- not a naming
# convention -- says where each engine input sits:
#   profile, boundary  the worker profile and boundary (`profile_<stem>.yml`)
#   profiles           the checked-interfaces view profiles, for the runner
#   seed               seed directory (seed.json, workspace.tar[, database.sql])
#   release_items      the execution release whose rows the gold sidecars bind
#   sidecars           gold sidecars (`manifest.json` + one JSON per item)
#   gold               the gold tree (`--gold`, with strip_manifest.json)
#   artifacts          a directory copied as `--artifacts` (or None)
#   agent_jar          Java direct-call agent, bound read-only into workers
# A source is a directory path, or {"tar": path, "member": dir} for an
# archive (`.tar` or `.tar.zst`) whose `member` subtree is the input
# (member None = the archive root).
#
# kind/workdir/prefix are `worker plan`'s container kind, mount point and
# identity prefix (None = the engine default).  memory_bytes is the cap the
# engine's provision must report as effective with zero swap (None = the
# paper ran uncapped).  k_default is the plan's per-host pool size (B rows);
# kit.json's `max_k_hint` is the warning threshold.  global_args are extra
# engine global options the project's lanes passed.  gold_control is a
# quick, date-independent eval item that passes under the kit's GT.
# --------------------------------------------------------------------------

def _db(image_key: str = "db_image", *, alias: Optional[str],
        template_command: Optional[tuple], template_env: str) -> dict:
    return {"image_key": image_key, "alias": alias,
            "template_command": template_command,
            "template_env": template_env}


PROJECTS: dict[str, dict] = {
    "python-docx": {
        "kind": "py", "workdir": "/work", "prefix": None,
        "profile": "exec/profiles/profile_python_docx.yml",
        "boundary": "exec/profiles/boundary_python_docx.yml",
        "profiles": {
            "th": "exec/profiles/profile_python_docx_checked_interfaces_target_hidden.yml",
            "ah": "exec/profiles/profile_python_docx_checked_interfaces_all_hidden.yml"},
        "seed": "exec/seed/checked-v2",
        "release_items": "exec/release/items.jsonl",
        "sidecars": "exec/release/gold",
        "gold": {"tar": "exec/gold/checked-v2.tar", "member": None},
        "artifacts": None, "agent_jar": None, "database": None,
        "memory_bytes": None, "k_default": 16, "global_args": [],
        "gold_control": "python-docx/features/api-open-document.feature:13",
    },
    "algorand-sdk": {
        "kind": "java", "workdir": "/work", "prefix": None,
        "profile": "exec/profiles/profile_algorand.yml",
        "boundary": "exec/profiles/boundary_algorand.yml",
        "profiles": {
            "th": "exec/profiles/profile_algorand_checked_interfaces_target_hidden.yml",
            "ah": "exec/profiles/profile_algorand_checked_interfaces_all_hidden.yml"},
        "seed": "exec/seed/checked-v2-rev3",
        "release_items": "exec/release/items.jsonl",
        "sidecars": "exec/release/gold",
        "gold": {"tar": "exec/gold/checked-v2.tar", "member": None},
        "artifacts": None,
        "agent_jar": "exec/agent/r2t-direct-calls-agent.jar",
        "database": None,
        "memory_bytes": None, "k_default": 16, "global_args": [],
        # RUNBOOK_ALGORAND.md's installation smoke item.
        "gold_control": "algorand-sdk/features/unit/abijson.feature:101",
    },
    "kapua": {
        "kind": "java", "workdir": "/work", "prefix": None,
        "profile": "exec/profiles/profile_kapua.yml",
        "boundary": "exec/profiles/boundary_kapua.yml",
        "profiles": {
            "th": "exec/profiles/profile_kapua_checked_interfaces_target_hidden.yml",
            "ah": "exec/profiles/profile_kapua_checked_interfaces_all_hidden.yml"},
        "seed": "exec/seed",
        "release_items": "exec/release/items.jsonl",
        "sidecars": "exec/release/gold",
        "gold": "exec/gold-tests",
        "artifacts": None,
        "agent_jar": "exec/agent/r2t-direct-calls-agent.jar",
        "database": None,
        # Load is about 3.3 per worker: at most ~28 workers per 64-CPU host.
        "memory_bytes": None, "k_default": 28, "global_args": [],
        "gold_control": ("kapua/translator/test/src/test/resources/features/"
                         "TranslatorUnitTests.feature:229"),
    },
    "coddy-agent": {
        "kind": "go", "workdir": "/work", "prefix": None,
        "profile": "exec/profiles/profile_coddy_agent.yml",
        "boundary": "exec/profiles/boundary_coddy_agent.yml",
        "profiles": {
            "th": "exec/profiles/profile_coddy_agent_checked_interfaces_target_hidden.yml",
            "ah": "exec/profiles/profile_coddy_agent_checked_interfaces_all_hidden.yml"},
        "seed": "exec/seed/v1",
        # The Go gold adapter checks EVERY sidecar in the manifest against
        # the release, so the release is the 282-row one the sidecars bind
        # (the 274 eval items are a subset of it).
        "release_items": "exec/release/full/items.jsonl",
        "sidecars": "exec/release/gold/release_gold",
        "gold": "exec/release/gold/tree",
        "artifacts": None, "agent_jar": None, "database": None,
        # The engine's Go memory policy (#979): 16 GiB, no swap.
        "memory_bytes": 16 * GIB, "k_default": 40, "global_args": [],
        "gold_control": "coddy-agent/features/hooks_subagents.feature:18",
    },
    "coreshop": {
        "kind": "php", "workdir": "/var/www/html", "prefix": None,
        "profile": "exec/profiles/profile_coreshop.yml",
        "boundary": "exec/profiles/boundary_coreshop.yml",
        "profiles": {
            "th": "exec/profiles/profile_coreshop_checked_interfaces_target_hidden.yml",
            "ah": "exec/profiles/profile_coreshop_checked_interfaces_all_hidden.yml"},
        "seed": "exec/seed",
        "release_items": "exec/release/items.jsonl",
        "sidecars": "exec/release/gold",
        "gold": "exec/release/gold_tree",
        "artifacts": "exec/release/artifacts", "agent_jar": None,
        # Workers reach MySQL by the engine's baked alias (coreshop_db);
        # the Defuse key comes from the seed's own generator, per install.
        "database": _db(alias="coreshop_db",
                        template_command=("vendor/bin/generate-defuse-key",),
                        template_env="r2t.toolkit.provision_coreshop:runtime_env"),
        "memory_bytes": None, "k_default": 24, "global_args": [],
        "gold_control": "coreshop/features/domain/cart/cart_base_item_taxes.feature:56",
    },
    "sylius": {
        "kind": "php", "workdir": "/var/www/html", "prefix": None,
        "profile": "exec/profiles/profile_sylius.yml",
        "boundary": "exec/profiles/boundary_sylius.yml",
        "profiles": {
            "th": "exec/profiles/profile_sylius_checked_interfaces_target_hidden.yml",
            "ah": "exec/profiles/profile_sylius_checked_interfaces_all_hidden.yml"},
        "seed": "exec/seed",
        "release_items": "exec/release/items.jsonl",
        "sidecars": "exec/release/gold",
        "gold": "exec/release/gold_tree",
        "artifacts": "exec/release/artifacts", "agent_jar": None,
        # Same shared alias as CoreShop: the engine refuses any other.
        "database": _db(alias="coreshop_db",
                        template_command=("php", "-r", "echo 'sylius-v1';"),
                        template_env="r2t.toolkit.provision_sylius:runtime_env"),
        "memory_bytes": None, "k_default": 16, "global_args": [],
        "gold_control": ("sylius/features/shop/product/show/prices/"
                         "viewing_products_price.feature:11"),
    },
    "prestashop": {
        "kind": "php", "workdir": "/var/www/html",
        # Native PrestaShop adds test_ to its schema names.
        "prefix": "test_prestashop",
        "profile": "exec/profiles/profile_prestashop.yml",
        "boundary": "exec/profiles/boundary_prestashop.yml",
        "profiles": {
            "th": "exec/profiles/profile_prestashop_checked_interfaces_target_hidden.yml",
            "ah": "exec/profiles/profile_prestashop_checked_interfaces_all_hidden.yml"},
        "seed": "exec/seed/v5",
        "release_items": "exec/release/items.jsonl",
        "sidecars": {"tar": "exec/release/gold/release-gold.tar.zst",
                     "member": "gold"},
        "gold": {"tar": "exec/release/gold/gold-v6.tar.zst",
                 "member": "gold-v6"},
        "artifacts": None, "agent_jar": None,
        # Workers address MySQL by its container name; no template command
        # (the installer generates no key).
        "database": _db(alias=None, template_command=None,
                        template_env="r2t.toolkit.provision_prestashop:runtime_env"),
        # r2t.prestashop-memory-policy/1: 4 GiB, no swap.
        "memory_bytes": 4 * GIB, "k_default": 24, "global_args": [],
        "gold_control": ("prestashop/tests/Integration/Behaviour/Features/"
                         "Scenario/SearchEngine/search_engine_management.feature:25"),
    },
    "e-petitions": {
        "kind": "ruby", "workdir": "/app", "prefix": None,
        "profile": "exec/profiles/profile_e_petitions.yml",
        "boundary": "exec/profiles/boundary_e_petitions.yml",
        "profiles": {
            "th": "exec/profiles/profile_e_petitions_checked_interfaces_target_hidden.yml",
            "ah": "exec/profiles/profile_e_petitions_checked_interfaces_all_hidden.yml"},
        "seed": "exec/seed",
        # The annotated release of the r2 implementation census (98 rows);
        # its sidecars live in the kit's artifacts tree.
        "release_items": "exec/release/e-petitions-implementations.jsonl",
        "sidecars": "exec/artifacts/release/gold",
        "gold": "exec/gold-tests",
        "artifacts": "exec/artifacts", "agent_jar": None, "database": None,
        "memory_bytes": None, "k_default": 24,
        "global_args": ["--features", "features"],
        "gold_control": "e-petitions/features/admin/admin_access.feature:60",
    },
}

DESCRIPTOR_KEYS = frozenset({
    "kind", "workdir", "prefix", "profile", "boundary", "profiles", "seed",
    "release_items", "sidecars", "gold", "artifacts", "agent_jar",
    "database", "memory_bytes", "k_default", "global_args", "gold_control"})


def descriptor(project: str) -> dict:
    try:
        return PROJECTS[project]
    except KeyError:
        raise EnvError(f"no environment descriptor for project {project!r}; "
                       f"known: {sorted(PROJECTS)}") from None


# --------------------------------------------------------------------------
# Paths and small helpers
# --------------------------------------------------------------------------

def req2test_home() -> Path:
    return kits.req2test_home().resolve()


def _private_dir(path: Path, *, fix_leaf: bool = False) -> Path:
    """Create `path` (and missing parents) without peer-write bits.

    The engine admits worker specs, evidence and the authority only below a
    directory chain no peer can replace.  Directories created here drop the
    group/other write bits whatever the host umask (002 on some hosts); an
    existing ancestor that a peer could replace is refused, not changed.
    `fix_leaf` also tightens `path` itself when it exists and is this
    user's (REQ2TEST_HOME, which `fetch` may have created under umask 002).
    """
    path = Path(path)
    missing = [p for p in [path, *path.parents] if not p.exists()]
    path.mkdir(parents=True, exist_ok=True)
    if fix_leaf and path.stat().st_uid == os.geteuid():
        missing.append(path)
    for created in missing:
        os.chmod(created, created.stat().st_mode & 0o7755)
    for part in [path, *path.parents]:
        info = part.stat()
        sticky_root = info.st_uid == 0 and info.st_mode & 0o1000
        if info.st_uid not in (0, os.geteuid()) or (
                info.st_mode & 0o022 and not sticky_root):
            raise EnvError(
                f"{part} is writable or owned by another user; the engine "
                "refuses evidence below it. Use a REQ2TEST_HOME whose every "
                "ancestor only you (or root) can write.")
    return path


def _log(message: str) -> None:
    print(f"== env {message}", file=sys.stderr, flush=True)


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _write_json(path: Path, doc, mode: int = 0o644) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def _read_jsonl_ids(path: Path) -> list:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line)["item_id"] for line in fh if line.strip()]


def _drop_ambient_docker() -> None:
    """The engine refuses ambient Docker selectors; this process never uses
    them either (every Docker call goes through the authority)."""
    present = [key for key in AMBIENT_DOCKER_KEYS if key in os.environ]
    for key in present:
        os.environ.pop(key)
    if present:
        _log(f"ignoring ambient {', '.join(present)}; Docker is selected by "
             "--docker-host and reached through the captured authority")


def _engine_modules():
    """Import the vendored engine in-process (for its Docker client argv)."""
    root = str(ENGINE_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        from r2t import docker_authority as DA
        from r2t.core import docker_cli as DC
    return DA, DC


def _engine_env(data_root: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in AMBIENT_DOCKER_KEYS}
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(ENGINE_ROOT), os.environ.get("PYTHONPATH")) if p)
    env["R2T_DATA_ROOT"] = str(data_root)
    env["PYTHONWARNINGS"] = "ignore::SyntaxWarning"
    return env


def _engine(argv: list, *, data_root: Path, log: Path,
            stdout: Optional[Path] = None) -> int:
    """`python -m r2t.cli ARGV`; stderr (and stdout unless captured) to `log`."""
    command = [sys.executable, "-m", "r2t.cli", *map(str, argv)]
    with open(log, "a", encoding="utf-8") as err:
        err.write(f"$ {' '.join(command)}\n")
        err.flush()
        out = open(stdout, "w", encoding="utf-8") if stdout else err
        try:
            return subprocess.call(
                command, env=_engine_env(data_root), stdin=subprocess.DEVNULL,
                stdout=out, stderr=err, cwd=str(data_root))
        finally:
            if stdout:
                out.close()


def _tail(path: Path, lines: int = 12) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return "".join(fh.readlines()[-lines:]).rstrip()
    except OSError:
        return ""


# --------------------------------------------------------------------------
# Kits
# --------------------------------------------------------------------------

def kit_from_dir(path) -> "kits.Kit":
    """A kit directory named on the command line (the one holding kit.json)."""
    root = Path(path).resolve()
    try:
        with open(root / "kit.json", encoding="utf-8") as fh:
            meta = json.load(fh)
    except (OSError, ValueError) as exc:
        raise EnvError(f"cannot read {root}/kit.json: {exc}") from exc
    if meta.get("schema") != kits.KIT_SCHEMA:
        raise EnvError(f"{root}/kit.json is not a {kits.KIT_SCHEMA} kit")
    return kits.Kit(project=meta["project"], version=meta["kit_version"],
                    root=root, meta=meta)


def find_kit(project: str, kit_dir: Optional[str] = None):
    """`--kit DIR`, else the installed kit (`req2test fetch`)."""
    if kit_dir:
        kit = kit_from_dir(kit_dir)
    else:
        try:
            kit = kits.load_kit(project)
        except (FileNotFoundError, ValueError, kits.KitError) as exc:
            raise EnvError(str(exc)) from exc
    if kit.project != project:
        raise EnvError(f"kit at {kit.root} is for {kit.project!r}, not {project!r}")
    return kit


def kit_images(kit) -> tuple:
    """(worker image, database image or None), each {file, config_digest}."""
    exec_env = kit.meta.get("exec_env") or {}
    images = exec_env.get("images") or []
    if len(images) != 1:
        raise EnvError(f"{kit.project} kit lists {len(images)} worker images; "
                       "expected exactly one")
    db = exec_env.get("db_image")
    for image in [images[0]] + ([db] if db else []):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image.get("config_digest") or ""):
            raise EnvError(f"{kit.project} kit image {image.get('name')!r} has "
                           "no config_digest")
    return images[0], db


# --------------------------------------------------------------------------
# Docker daemon and authority
# --------------------------------------------------------------------------

def daemon_name(home: Path) -> str:
    """This home's daemon unit (one per REQ2TEST_HOME, so homes never share)."""
    digest = hashlib.sha256(str(home).encode()).hexdigest()[:8]
    return f"req2test-docker-{digest}"


def _runtime_dir() -> Path:
    value = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.geteuid()}"
    return Path(value)


def daemon_socket(home: Path) -> Path:
    return _runtime_dir() / daemon_name(home) / "docker.sock"


#: Classic overlay2 image store: `docker image inspect .Id` is then the
#: config digest for every image, so one daemon verifies every kit
#: (python-docx's reference image was identified under the containerd store
#: and Algorand's route needs classic overlay2; HARNESS_PLAN A/B.7).
DAEMON_CONFIG = {"storage-driver": "overlay2",
                 "features": {"containerd-snapshotter": False}}


def _systemctl_user(*args, check=False) -> subprocess.CompletedProcess:
    return subprocess.run(["systemctl", "--user", *args], capture_output=True,
                          text=True, check=check)


def _secure_socket(socket: Path, data_root: Optional[Path]) -> None:
    """dockerd creates its socket 0660 and its root 0710; the authority
    requires both private to the invoking user."""
    os.chmod(socket, 0o600)
    if data_root is not None and data_root.is_dir():
        os.chmod(data_root, 0o700)


def ensure_daemon(home: Path, docker_host: Optional[str] = None) -> Path:
    """Return the Unix socket of the selected or this home's own daemon."""
    if docker_host:
        socket = Path(docker_host[len("unix://"):] if docker_host.startswith(
            "unix://") else docker_host)
        if not socket.is_socket():
            raise EnvError(f"--docker-host {docker_host}: no Unix socket there")
        return socket
    name = daemon_name(home)
    socket = daemon_socket(home)
    root = _private_dir(home / "docker")
    data = _private_dir(root / "data")
    tmp = _private_dir(root / "tmp")
    if _systemctl_user("is-active", name).stdout.strip() == "active" \
            and socket.is_socket():
        _secure_socket(socket, data)
        return socket
    found = {tool: shutil.which(tool) for tool in (
        "dockerd-rootless.sh", "dockerd", "rootlesskit", "slirp4netns",
        "newuidmap", "systemd-run", "docker")}
    for tool, where in found.items():
        if where is None:
            raise EnvError(
                f"cannot create a rootless Docker daemon: {tool} is not on "
                "PATH. Install Docker's rootless extras, or start your own "
                "rootless daemon and pass --docker-host unix:///PATH")
    # The unit gets no login PATH: name the directories the tools were
    # found in first, then the system ones.
    unit_path = []
    for tool in ("dockerd-rootless.sh", "dockerd", "rootlesskit",
                 "slirp4netns", "newuidmap"):
        unit_path.append(os.path.dirname(found[tool]))
    unit_path += ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
    unit_path = ":".join(dict.fromkeys(unit_path))
    config = root / "daemon.json"
    _write_json(config, DAEMON_CONFIG, mode=0o600)
    runtime = _runtime_dir() / name
    _systemctl_user("reset-failed", name)
    argv = [
        "systemd-run", "--user", f"--unit={name}",
        f"--description=req2test rootless Docker ({home})",
        "-p", "Delegate=yes", "-p", "Type=notify", "-p", "NotifyAccess=all",
        "-p", "KillMode=mixed", "-p", "TimeoutStartSec=180",
        "-p", "LimitNOFILE=infinity", "-p", "LimitNPROC=infinity",
        "-p", "TasksMax=infinity", "-p", f"RuntimeDirectory={name}",
        "-p", "RuntimeDirectoryMode=0700", "-p", "UMask=0077",
        f"--setenv=PATH={unit_path}",
        f"--setenv=HOME={os.path.expanduser('~')}",
        f"--setenv=XDG_RUNTIME_DIR={_runtime_dir()}",
        f"--setenv=DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR={runtime}/rootlesskit",
        "--setenv=DOCKERD_ROOTLESS_ROOTLESSKIT_NET=slirp4netns",
        "--setenv=DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=builtin",
        "--setenv=DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=true",
        f"--setenv=DOCKER_TMPDIR={tmp}",
        found["dockerd-rootless.sh"], f"--config-file={config}",
        f"--host=unix://{socket}", f"--data-root={data}",
        f"--exec-root={runtime}/exec", f"--pidfile={runtime}/dockerd.pid",
    ]
    _log(f"starting rootless Docker daemon {name} (data root {data})")
    started = subprocess.run(argv, capture_output=True, text=True)
    if started.returncode != 0 and _systemctl_user(
            "is-active", name).stdout.strip() not in ("active", "activating"):
        # (A concurrent `env up` on this home may have started it first.)
        raise EnvError(
            f"could not start {name} with systemd-run --user: "
            f"{(started.stderr or started.stdout).strip()[-600:]}\nStart a "
            "rootless daemon yourself and pass --docker-host unix:///PATH")
    deadline = time.monotonic() + 120
    while not socket.is_socket():
        if time.monotonic() > deadline:
            journal = subprocess.run(
                ["journalctl", "--user", "-u", name, "-n", "20", "--no-pager"],
                capture_output=True, text=True).stdout
            raise EnvError(f"{name} did not create {socket}:\n{journal}")
        time.sleep(1)
    _secure_socket(socket, data)
    return socket


def _daemon_store_problem(socket: Path) -> Optional[str]:
    """Why this daemon cannot verify images by config digest, or None."""
    cp = subprocess.run(
        ["docker", "--host", f"unix://{socket}", "info", "--format",
         "{{json .}}"], capture_output=True, text=True,
        env={k: v for k, v in os.environ.items()
             if k not in AMBIENT_DOCKER_KEYS})
    if cp.returncode != 0:
        return f"docker info failed: {cp.stderr.strip()[-300:]}"
    info = json.loads(cp.stdout)
    status = json.dumps(info.get("DriverStatus") or [])
    if "io.containerd.snapshotter" in status:
        return ("it uses the containerd image store, where `docker image "
                "inspect .Id` is a manifest digest rather than the kit's "
                "config digest; use a daemon with "
                "\"features\": {\"containerd-snapshotter\": false}")
    if "name=rootless" not in (info.get("SecurityOptions") or []):
        return ("it is not rootless; the engine's authority v1 accepts only "
                "a current-user rootless daemon")
    return None


def _git(args: list, cwd) -> Optional[bytes]:
    try:
        cp = subprocess.run(["git", "-C", str(cwd), *args],
                            capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return cp.stdout if cp.returncode == 0 else None


def dirty_clone_paths(engine_root=None) -> tuple:
    """`(clone root, ["XY path", ...])`: what `git status` shows in the clone
    the engine runs from, untracked files included, as the engine's Docker
    authority verifier sees it.  `(None, [])` when the engine is not in a
    git clone (the verifier then refuses on its own)."""
    top = _git(["rev-parse", "--show-toplevel"], engine_root or ENGINE_ROOT)
    if top is None:
        return None, []
    root = top.decode("utf-8", "replace").strip()
    out = _git(["status", "--porcelain=v1", "-z", "--untracked-files=all"],
               root)
    if out is None:
        return root, []
    entries = out.decode("utf-8", "replace").split("\0")
    paths, i = [], 0
    while i < len(entries):
        entry = entries[i]
        i += 1
        if not entry:
            continue
        paths.append(entry)
        if entry[0] in "RC":          # a rename or copy: its source follows
            i += 1
    return root, paths


def check_clean_clone(engine_root=None) -> None:
    """Refuse a clone with changes or untracked files before Docker work.

    The engine's Docker authority pins the clone's commit and will neither
    capture nor reuse one while `git status` shows anything, untracked files
    included; a task file or prediction written into the clone would
    otherwise fail deep inside `env up`.
    """
    root, paths = dirty_clone_paths(engine_root)
    if not paths:
        return
    listed = [f"  {p}" for p in paths[:DIRTY_LISTED]]
    if len(paths) > DIRTY_LISTED:
        listed.append(f"  ... and {len(paths) - DIRTY_LISTED} more")
    raise EnvError(
        f"the clone {root} is not clean ({len(paths)} changed or untracked "
        f"path(s)), and the engine's Docker authority refuses to run from "
        f"it:\n" + "\n".join(listed) + f"\n{CLEAN_CLONE_HINT}")


def ensure_authority(home: Path, socket: Path) -> Path:
    """Reuse the newest authority that still validates live, else capture one.

    The authority's verifier records this clone's commit and requires the
    clone to be clean; a stale one (daemon restarted with other facts, a
    different client) is replaced, never edited.
    """
    DA, _DC = _engine_modules()
    directory = _private_dir(home / "docker" / "authority")
    stem = hashlib.sha256(str(socket).encode()).hexdigest()[:8]
    for path in sorted(directory.glob(f"{stem}-*.json"), reverse=True):
        try:
            DA.load_authority(str(path), live=True)
            return path
        except DA.DockerAuthorityRefused as exc:
            _log(f"authority {path.name} no longer validates ({exc}); "
                 "capturing a new one")
            break
    path = directory / (f"{stem}-{time.strftime('%Y%m%dT%H%M%S')}"
                        f"-{os.getpid()}.json")
    client = shutil.which("docker")
    if client is None:
        raise EnvError("no docker CLI on PATH")
    try:
        DA.capture_authority(docker_host=f"unix://{socket}",
                             docker_cli=os.path.realpath(client), out=str(path))
    except DA.DockerAuthorityRefused as exc:
        check_clean_clone()           # a dirty clone, named with its paths
        raise EnvError(f"cannot capture a Docker authority for {socket}: "
                       f"{exc}") from exc
    _log(f"captured Docker authority {path}")
    return path


class _Docker:
    """Docker commands through the engine's authority-derived client argv."""

    def __init__(self, authority: Path):
        _DA, self.DC = _engine_modules()
        self.DC.configure(authority_path=str(authority))

    def argv(self, args: list) -> list:
        # A fresh phase per command: each repeats the live authority proof
        # and gets an empty client configuration, as the engine's own
        # lifecycle does after every mutation.
        self.DC.reset_phase()
        try:
            return self.DC.docker_argv(list(map(str, args)))
        except self.DC.DockerEndpointRefused as exc:
            # The proof is repeated per command against the clone: a clone
            # made dirty since `env up` is the usual cause, so name it.
            check_clean_clone()
            raise EnvError(f"Docker authority refused: {exc}") from exc

    def __call__(self, args: list, *, check: bool = True, env=None,
                 timeout: int = 600) -> subprocess.CompletedProcess:
        cp = subprocess.run(self.argv(args), capture_output=True, text=True,
                            env=env, timeout=timeout)
        if check and cp.returncode != 0:
            raise EnvError(f"docker {' '.join(map(str, args[:3]))} failed: "
                           f"{(cp.stderr or cp.stdout).strip()[-500:]}")
        return cp

    def exists(self, kind: str, name: str) -> bool:
        return self([kind, "inspect", name], check=False).returncode == 0

    def image_id(self, ref: str) -> Optional[str]:
        cp = self(["image", "inspect", "--format", "{{.Id}}", ref], check=False)
        return cp.stdout.strip() if cp.returncode == 0 else None


def load_image(docker: _Docker, kit, image: dict, project: str) -> str:
    """Load one kit image unless present; verify its ID is the config digest."""
    want = image["config_digest"]
    if docker.image_id(want) == want:
        return want
    archive = kit.path(image["file"])
    if not archive.is_file():
        raise EnvError(f"{project}: image archive {archive} is missing")
    _log(f"{project}: loading {archive.name}")
    if archive.name.endswith(".zst"):
        if shutil.which("zstd") is None:
            raise EnvError("zstd is required to load .zst kit images")
        unzstd = subprocess.Popen(["zstd", "-dc", str(archive)],
                                  stdout=subprocess.PIPE)
        load = subprocess.run(docker.argv(["load"]), stdin=unzstd.stdout,
                              capture_output=True, text=True)
        unzstd.stdout.close()
        if unzstd.wait() != 0:
            raise EnvError(f"zstd could not decompress {archive}")
    else:
        load = subprocess.run(docker.argv(["load", "--input", str(archive)]),
                              capture_output=True, text=True)
    if load.returncode != 0:
        raise EnvError(f"docker load {archive} failed: {load.stderr[-400:]}")
    got = docker.image_id(want)
    if got != want:
        raise EnvError(
            f"{project}: {archive.name} did not load as config digest {want} "
            f"(docker load said: {load.stdout.strip()[-300:]})")
    return want


def _key_quota_problem(containers: int,
                       key_users: Optional[str] = None) -> Optional[str]:
    """Rootless containers each take kernel keys; the per-UID quota (often
    1000 keys / 100000 bytes) fails `docker run` with "disk quota exceeded"."""
    if key_users is None:
        try:
            with open("/proc/key-users", encoding="ascii") as fh:
                key_users = fh.read()
        except OSError:
            return None
    for row in key_users.splitlines():
        uid, _, rest = row.partition(":")
        if uid.strip() != str(os.geteuid()):
            continue
        fields = rest.split()
        try:
            keys_used, keys_max = map(int, fields[2].split("/"))
            bytes_used, bytes_max = map(int, fields[3].split("/"))
        except (IndexError, ValueError):
            return None
        need_keys, need_bytes = containers + 4, (containers + 4) * 100
        if keys_max - keys_used < need_keys or bytes_max - bytes_used < need_bytes:
            return (f"kernel key quota for uid {uid.strip()}: {keys_used}/"
                    f"{keys_max} keys, {bytes_used}/{bytes_max} bytes used; "
                    f"{containers} more containers need about {need_keys} "
                    "keys. Retire finished pools or use a larger quota.")
    return None


# --------------------------------------------------------------------------
# Staged engine inputs
# --------------------------------------------------------------------------

def _extract(source, kit, dest: Path) -> None:
    """Copy a directory source, or extract an archive member, to `dest`."""
    if isinstance(source, str):
        src = kit.path(source)
        if not src.is_dir():
            raise EnvError(f"{kit.project}: kit input {src} is missing")
        shutil.copytree(src, dest, symlinks=True)
        return
    archive = kit.path(source["tar"])
    if not archive.is_file():
        raise EnvError(f"{kit.project}: kit archive {archive} is missing")
    scratch = Path(tempfile.mkdtemp(prefix=".extract.", dir=dest.parent))
    try:
        if archive.name.endswith(".zst"):
            unzstd = subprocess.Popen(["zstd", "-dc", str(archive)],
                                      stdout=subprocess.PIPE)
            untar = subprocess.run(["tar", "-C", str(scratch), "-xf", "-"],
                                   stdin=unzstd.stdout, capture_output=True)
            unzstd.stdout.close()
            ok = unzstd.wait() == 0 and untar.returncode == 0
        else:
            untar = subprocess.run(["tar", "-C", str(scratch), "-xf",
                                    str(archive)], capture_output=True)
            ok = untar.returncode == 0
        if not ok:
            raise EnvError(f"could not extract {archive}: "
                           f"{untar.stderr.decode(errors='replace')[-300:]}")
        member = scratch / source["member"] if source.get("member") else scratch
        if not member.is_dir():
            raise EnvError(f"{archive} has no {source.get('member')}/ member")
        os.rename(member, dest)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _relocate_seed(staged: Path, final: Path) -> dict:
    """Point seed.json's recorded artifact paths at the staged copies.

    `staged` is where the file is written now, `final` the directory it will
    be read from.  Returns {field: originally recorded path}.
    """
    path = staged / "seed.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    moved = {}
    for key, name in (("workspace", "workspace.tar"), ("database", "database.sql")):
        half = doc.get(key)
        if isinstance(half, dict) and isinstance(half.get("path"), str) \
                and half["path"] != str(final / name):
            moved[f"seed.json:{key}.path"] = half["path"]
            half["path"] = str(final / name)
    if moved:
        _write_json(path, doc)
    return moved


def _relocate_strip_manifest(staged: Path, final: Path) -> dict:
    """Point the strip manifest's recorded gold root at the staged tree.

    The engine replaces `gold_root` and `repo_root` with the live --gold and
    workspace when it loads the manifest, so this keeps the file truthful
    rather than changing any reading; `repo_root` (where the strip ran) is
    left as recorded provenance.
    """
    path = staged / "strip_manifest.json"
    if not path.is_file():
        return {}
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc.get("gold_root"), str) or doc["gold_root"] == str(final):
        return {}
    moved = {"strip_manifest.json:gold_root": doc["gold_root"]}
    doc["gold_root"] = str(final)
    _write_json(path, doc)
    return moved


def stage_inputs(kit, data_root: Path) -> Path:
    """The kit's execution inputs in the engine's layout, once per kit version.

    Layout: seed/, gold/, artifacts/ (with release/items.jsonl and
    release/gold/), agent/ (Java).  Copies, not links: the engine refuses
    hard-linked answer files and multiply-linked seed artifacts.  The
    directory is named by the kit version and its kit.json digest, so a
    re-released kit is staged afresh instead of reusing another kit's bytes.
    """
    d = descriptor(kit.project)
    kit_json = hashlib.sha256((kit.root / "kit.json").read_bytes()).hexdigest()
    target = (data_root / "inputs" / kit.project
              / f"{kit.version}-{kit_json[:12]}")
    record = target / "inputs.json"
    if record.is_file():
        return target
    _private_dir(target.parent)
    _log(f"{kit.project}: staging kit {kit.version} inputs in {target}")
    work = Path(tempfile.mkdtemp(prefix=f".{kit.version}.", dir=target.parent))
    try:
        os.chmod(work, 0o755)
        moved = {}
        seed_src = kit.path(d["seed"])
        seed = _private_dir(work / "seed")
        for name in ("seed.json", "workspace.tar", "database.sql"):
            if (seed_src / name).is_file():
                shutil.copyfile(seed_src / name, seed / name)
        if not (seed / "seed.json").is_file():
            raise EnvError(f"{kit.project}: no seed.json in {seed_src}")
        _extract(d["gold"], kit, work / "gold")
        if d["artifacts"]:
            _extract(d["artifacts"], kit, work / "artifacts")
        release = _private_dir(work / "artifacts" / "release")
        if (release / "gold").exists():
            shutil.rmtree(release / "gold")
        _extract(d["sidecars"], kit, release / "gold")
        shutil.copyfile(kit.path(d["release_items"]), release / "items.jsonl")
        if d["agent_jar"]:
            _private_dir(work / "agent")
            shutil.copyfile(kit.path(d["agent_jar"]),
                            work / "agent" / Path(d["agent_jar"]).name)
        # Recorded build-host paths now name the final staged location.
        moved.update(_relocate_seed(work / "seed", target / "seed"))
        moved.update(_relocate_strip_manifest(work / "gold", target / "gold"))
        manifest = json.loads((release / "gold" / "manifest.json").read_text())
        items = _read_jsonl_ids(release / "items.jsonl")
        missing = [i for i in items if i not in manifest]
        if missing:
            raise EnvError(f"{kit.project}: {len(missing)} release items have "
                           f"no gold sidecar, e.g. {missing[0]}")
        _write_json(work / "inputs.json", {
            "schema": INPUTS_SCHEMA, "project": kit.project,
            "kit_version": kit.version, "kit_root": str(kit.root),
            "kit_json_sha256": kit_json,
            "staged_at": _utc_now(), "sources": {
                k: d[k] for k in ("seed", "gold", "sidecars", "release_items",
                                  "artifacts", "agent_jar")},
            "n_release_items": len(items), "n_sidecars": len(manifest),
            "relocated": moved})
        try:
            os.rename(work, target)
        except OSError:
            if not record.is_file():      # not a concurrent stager's result
                raise
        return target
    finally:
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)


# --------------------------------------------------------------------------
# The environment handle
# --------------------------------------------------------------------------

@dataclasses.dataclass
class EnvHandle:
    """A provisioned, qualified worker pool and the engine arguments to use it.

    `global_args(i)` is the engine's global option list for a run on worker
    i (`python -m r2t.cli <global_args(i)> run --profile ... --release
    <release_items> ...`); `engine_env()` the subprocess environment.
    """
    project: str
    nonce: str
    env_dir: str
    record_path: str
    kit_root: str
    kit_version: str
    k: int
    authority_path: str
    docker_socket: str
    data_root: str
    workers_root: str
    worker_specs: list
    worker_ids: list
    workdir: str
    container_kind: str
    prefix: Optional[str]
    image_id: str
    profile: str
    boundary: str
    profiles: dict
    seed_dir: str
    gold_root: str
    artifacts: str
    release_items: str
    agent_jar: Optional[str]
    extra_global_args: list
    database: Optional[dict]
    state: str = "up"

    @property
    def kit(self):
        return kit_from_dir(self.kit_root)

    def artifacts_for(self, index: int) -> str:
        """Go binds execution artifacts to each worker's own root."""
        if self.container_kind == "go":
            with open(self.worker_specs[index], encoding="utf-8") as fh:
                return json.load(fh)["artifacts_root"]
        return self.artifacts

    def global_args(self, index: int) -> list:
        return ["--docker-authority", self.authority_path,
                "--worker", self.worker_specs[index],
                "--boundary", self.boundary, "--gold", self.gold_root,
                "--artifacts", self.artifacts_for(index),
                *self.extra_global_args]

    def pool_args(self) -> list:
        """`worker` lifecycle options naming this pool (and its database)."""
        args = ["--k", str(self.k), "--workers-root", self.workers_root]
        if self.database:
            args += ["--db-container", self.database["container"],
                     "--internal-network", self.database["network"]]
        return args

    def engine_env(self) -> dict:
        return _engine_env(Path(self.data_root))

    def to_json(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def load(cls, path) -> "EnvHandle":
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        if doc.get("schema") != RECORD_SCHEMA:
            raise EnvError(f"{path} is not a {RECORD_SCHEMA} record")
        fields = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in doc["handle"].items() if k in fields})


def _save(handle: EnvHandle, **extra) -> bool:
    """Write the record; False (nothing written) once it is retired.

    Monotonic: a record already marked `down` is final.  A process holding
    an older handle (an `up` still running when another session ran `env
    down`) must not turn it back into `up` or `failed`.
    """
    path = Path(handle.record_path)
    previous = {}
    if path.is_file():
        previous = json.loads(path.read_text(encoding="utf-8"))
    if (previous.get("handle") or {}).get("state") == "down":
        handle.state = "down"
        return False
    doc = {**previous, **extra, "schema": RECORD_SCHEMA,
           "handle": handle.to_json(), "updated_at": _utc_now()}
    _write_json(path, doc, mode=0o600)
    return True


# --------------------------------------------------------------------------
# up
# --------------------------------------------------------------------------

def _mint_nonce() -> str:
    return "e" + secrets.token_hex(4)


def _resolve_callable(spec: str) -> Callable:
    module, _, name = spec.partition(":")
    _engine_modules()
    import importlib
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return getattr(importlib.import_module(module), name)


def _template_values(docker: _Docker, d: dict, *, seed: Path, image: str,
                     workdir: str, env_dir: Path, label: str,
                     name: str) -> dict:
    """The template container's application environment.

    A template command (CoreShop's Defuse key generator, Sylius's token)
    runs offline over the unpacked seed; its last stdout line is the input
    of the engine provisioner's own `runtime_env`.
    """
    db = d["database"]
    produce = _resolve_callable(db["template_env"])
    if db["template_command"] is None:
        return produce()
    _engine_modules()
    from r2t.bench import seed as S
    with tempfile.TemporaryDirectory(prefix=".template.", dir=env_dir) as tmp:
        workspace = Path(tmp) / "workspace"
        S.unpack_workspace(str(seed), str(workspace))
        cp = docker(["run", "--rm", "--name", name, "--label", label,
                     "--network", "none", "--volume",
                     f"{workspace}:{workdir}:ro", image,
                     *db["template_command"]], timeout=600)
        shutil.rmtree(workspace, ignore_errors=True)
    lines = [line.strip() for line in cp.stdout.splitlines() if line.strip()]
    return produce(lines[-1] if lines else "")


def _database_resources(d: dict, *, nonce: str, db_image: str,
                        env_dir: Path, k: int) -> dict:
    """The names a database environment owns, recorded before any exists."""
    return {"network": f"req2test_{nonce}_net",
            "container": f"req2test_{nonce}_db",
            "template_container": f"req2test_{nonce}_template",
            "alias": d["database"]["alias"], "image": db_image,
            "template_env_file": str(env_dir / "template.env"),
            "composer_cache": str(env_dir / "composer-cache"),
            "sentinel_schema": f"{nonce}_sentinel" if k == 1 else None,
            "label": f"{LABEL}={nonce}"}


#: MySQL's first start initializes its data directory before the server
#: answers; on a host under heavy I/O that took 2-7 minutes. Failed health
#: probes inside the start period do not count, and the first probe that
#: passes ends it, so a quick start is not slowed down.
DB_HEALTH_START_PERIOD = 900
DB_HEALTH_DEADLINE = 1200


def _wait_healthy(docker, container: str, *, deadline: float = DB_HEALTH_DEADLINE,
                  clock: Callable = time.monotonic,
                  sleep: Callable = time.sleep) -> None:
    """Wait for the MySQL container's health check; refuse a stopped one."""
    until = clock() + deadline
    while True:
        state, _, health = docker(
            ["container", "inspect", "--format",
             "{{.State.Status}} {{.State.Health.Status}}", container],
            timeout=60).stdout.strip().partition(" ")
        if health == "healthy":
            return
        if state != "running" or health == "unhealthy" or clock() > until:
            raise EnvError(f"MySQL container did not become healthy "
                           f"({health or 'no health status'}, {state})")
        sleep(2)


def _start_database(docker: _Docker, d: dict, resources: dict, *, image: str,
                    seed: Path, workdir: str, env_dir: Path) -> None:
    db = d["database"]
    label = resources["label"]
    db_image = resources["image"]
    for kind, name in (("network", resources["network"]),
                       ("container", resources["container"]),
                       ("container", resources["template_container"])):
        if docker.exists(kind, name):
            raise EnvError(f"{kind} {name} already exists; nothing was adopted")
    _log(f"{d['_project']}: database network, MySQL and template container")
    docker(["network", "create", "--driver", "bridge", "--internal",
            "--label", label, resources["network"]], timeout=60)
    db_env = dict(os.environ, MYSQL_ROOT_PASSWORD=DB_ROOT_PASSWORD)
    docker(["run", "--detach", "--name", resources["container"],
            "--label", label, "--network", resources["network"],
            *(["--network-alias", db["alias"]] if db["alias"] else []),
            "--health-cmd", "mysqladmin ping -h 127.0.0.1 --silent",
            "--health-interval", "2s", "--health-timeout", "2s",
            "--health-retries", "90",
            "--health-start-period", f"{DB_HEALTH_START_PERIOD}s",
            "--env", "MYSQL_ROOT_PASSWORD",
            db_image], env=db_env, timeout=300)
    _wait_healthy(docker, resources["container"])
    values = _template_values(
        docker, d, seed=seed, image=image, workdir=workdir, env_dir=env_dir,
        label=label, name=resources["template_container"])
    bad = [k for k, v in values.items()
           if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k)
           or any(c in v for c in "\x00\r\n")]
    if bad:
        raise EnvError(f"template environment has invalid entries: {bad}")
    # template.env: generated per install, mode 0600, never shipped.
    env_file = Path(resources["template_env_file"])
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("".join(f"{k}={v}\n" for k, v in sorted(values.items())))
    docker(["run", "--detach", "--name", resources["template_container"],
            "--label", label, "--network", "none", "--env-file", str(env_file),
            image, "tail", "-f", "/dev/null"], timeout=300)
    os.mkdir(resources["composer_cache"], 0o700)
    if resources["sentinel_schema"]:
        _engine_modules()
        from r2t.bench.dbadmin import MySQL
        with MySQL(container=resources["container"],
                   password=DB_ROOT_PASSWORD) as admin:
            admin.create_schema(resources["sentinel_schema"])
            admin.load(resources["sentinel_schema"], str(seed / "database.sql"))
            if not admin.table_bytes(resources["sentinel_schema"]):
                raise EnvError("the K=1 isolation sentinel holds no tables")


def _check_memory(report_path: Path, expected: Optional[int], k: int) -> Optional[str]:
    """The engine applies the memory caps; confirm they are effective."""
    if expected is None:
        return None
    report = json.loads(report_path.read_text(encoding="utf-8"))
    seen = {}
    for row in report.get("memory_observations") or []:
        memory = ((row.get("at_attestation") or {}).get("memory") or {})
        seen[row.get("worker")] = (memory.get("effective_memory_bytes"),
                                   memory.get("effective_swap_bytes"))
    bad = {w: v for w, v in seen.items() if v != (expected, 0)}
    if len(seen) != k or bad:
        return (f"memory cap not effective: expected {expected} bytes and no "
                f"swap on {k} workers, observed {seen}")
    return None


def _parallel(jobs: list, fn) -> list:
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, min(MAX_PARALLEL, len(jobs)))) as pool:
        return list(pool.map(fn, jobs))


def _gold_control_row(path: Path, item: str) -> Optional[dict]:
    if not path.is_file():
        return None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                row = json.loads(line)
                if row.get("item_id") == item:
                    return row
    return None


def up(kit, workers: Optional[int] = None, run_dir=None, *,
       docker_host: Optional[str] = None, qualify: bool = True) -> EnvHandle:
    """Bring up and qualify `workers` engine workers for `kit`'s project.

    Raises EnvError when a step fails; the environment record then stays
    behind (state `failed`) so `down` can retire whatever was created.
    A clone that is not clean is refused first (`check_clean_clone`).
    """
    check_clean_clone()
    # Engine evidence must not be peer-writable whatever the host umask.
    previous = os.umask(0o022)
    try:
        return _up(kit, workers, run_dir, docker_host=docker_host,
                   qualify=qualify)
    finally:
        os.umask(previous)


def _up(kit, workers, run_dir, *, docker_host, qualify) -> EnvHandle:
    _drop_ambient_docker()
    project = kit.project
    d = dict(descriptor(project), _project=project)
    k = workers or d["k_default"]
    if k < 1:
        raise EnvError("--workers must be at least 1")
    hint = ((kit.meta.get("exec_env") or {}).get("worker") or {}).get("max_k_hint")
    if hint and k > hint:
        _log(f"{project}: {k} workers exceed the kit's per-host hint {hint}")
    home = _private_dir(req2test_home(), fix_leaf=True)
    data_root = _private_dir(home / "engine")
    image, db_image = kit_images(kit)
    if d["database"] and not db_image:
        raise EnvError(f"{project} needs a database but its kit has no db_image")
    if project == "prestashop":
        expiry = (kit.meta.get("date_expiry") or {}).get("groups") or {}
        for date, group in sorted(expiry.items()):
            _log(f"prestashop: {group.get('n_items_eval')} eval items "
                 f"({group.get('n_items_full')} in full) contain dates that "
                 f"expire on {date} and run on the host's clock "
                 "(docs/environments.md, Notes)")
    problem = _key_quota_problem(k + (2 if d["database"] else 0))
    if problem:
        raise EnvError(problem)

    socket = ensure_daemon(home, docker_host)
    problem = _daemon_store_problem(socket)
    if problem:
        raise EnvError(f"Docker daemon at {socket} cannot serve kits: {problem}")
    authority = ensure_authority(home, socket)
    docker = _Docker(authority)
    image_id = load_image(docker, kit, image, project)
    db_image_id = load_image(docker, kit, db_image, project) if d["database"] else None
    # A name keeps the loaded images from being pruned while no pool runs them.
    docker(["image", "tag", image_id, f"req2test/{project}:{image_id[7:19]}"])
    if db_image_id:
        docker(["image", "tag", db_image_id, f"req2test/mysql:{db_image_id[7:19]}"])
    inputs = stage_inputs(kit, data_root)

    nonce = _mint_nonce()
    env_dir = home / "envs" / project / nonce
    if env_dir.exists():
        raise EnvError(f"{env_dir} already exists")
    _private_dir(env_dir)
    qualification = _private_dir(env_dir / "qualification")
    log = env_dir / "engine.log"
    workers_root = env_dir / "workers"
    jar = (str(inputs / "agent" / Path(d["agent_jar"]).name)
           if d["agent_jar"] else None)
    handle = EnvHandle(
        project=project, nonce=nonce, env_dir=str(env_dir),
        record_path=str(env_dir / "env.json"), kit_root=str(kit.root),
        kit_version=kit.version, k=k, authority_path=str(authority),
        docker_socket=str(socket), data_root=str(data_root),
        workers_root=str(workers_root),
        worker_specs=[str(workers_root / f"worker{i}.json") for i in range(k)],
        worker_ids=list(range(k)), workdir=d["workdir"],
        container_kind=d["kind"], prefix=d["prefix"], image_id=image_id,
        profile=str(kit.path(d["profile"])),
        boundary=str(kit.path(d["boundary"])),
        profiles={v: str(kit.path(p)) for v, p in d["profiles"].items()},
        seed_dir=str(inputs / "seed"), gold_root=str(inputs / "gold"),
        artifacts=str(inputs / "artifacts"),
        release_items=str(inputs / "artifacts" / "release" / "items.jsonl"),
        agent_jar=jar, extra_global_args=list(d["global_args"]),
        database=None, state="provisioning")
    _save(handle, created_at=_utc_now(), qualification=None, error=None)
    if run_dir is not None:
        Path(run_dir).mkdir(parents=True, exist_ok=True)
        _write_json(Path(run_dir) / "env.json",
                    {"schema": RECORD_SCHEMA, "record": handle.record_path,
                     "project": project, "nonce": nonce})
    _log(f"{project}: environment {nonce} in {env_dir} (K={k})")

    def fail(step: str, detail: str) -> EnvError:
        handle.state = "failed"
        if not _save(handle, error={"step": step, "detail": detail}):
            return EnvError(f"{project} env {nonce}: {step} failed after the "
                            f"environment was retired by `env down`: {detail}")
        return EnvError(
            f"{project} env {nonce}: {step} failed: {detail}\n"
            f"engine log: {log}\nretire it with: req2test env down "
            f"--project {project} --nonce {nonce}")

    def engine(step: str, argv: list, **kw) -> None:
        rc = _engine(argv, data_root=data_root, log=log, **kw)
        if rc != 0:
            raise fail(step, f"engine exit {rc}\n{_tail(log)}")

    def bring_up() -> dict:
        if d["database"]:
            # Recorded before creation, so `down` can retire a partial one.
            handle.database = _database_resources(
                d, nonce=nonce, db_image=db_image_id, env_dir=env_dir, k=k)
            _save(handle)
            _start_database(docker, d, handle.database, image=image_id,
                            seed=inputs / "seed", workdir=d["workdir"],
                            env_dir=env_dir)
        base = ["--docker-authority", authority, "--boundary", handle.boundary,
                "--gold", handle.gold_root, "--artifacts", handle.artifacts,
                *handle.extra_global_args]
        _log(f"{project}: worker plan + provision")
        engine("worker plan", base + [
            "worker", "plan", "--k", k, "--workers-root", workers_root,
            "--profile", handle.profile, "--workdir", d["workdir"],
            "--container-kind", d["kind"], "--name", nonce,
            *(["--prefix", d["prefix"]] if d["prefix"] else [])],
            stdout=qualification / "plan.json")
        provision = base + [
            "worker", "provision", "--k", k, "--workers-root", workers_root,
            "--profile", handle.profile, "--seed", handle.seed_dir,
            "--image", image_id, "--jobs", min(k, MAX_PARALLEL)]
        if jar:
            provision += ["--direct-call-agent-jar", jar]
        if handle.database:
            provision += ["--db-container", handle.database["container"],
                          "--internal-network", handle.database["network"],
                          "--template-container",
                          handle.database["template_container"],
                          "--composer-cache", handle.database["composer_cache"]]
        engine("worker provision", provision,
               stdout=qualification / "provision.json")
        handle.state = "provisioned"
        _save(handle)
        problem = _check_memory(qualification / "provision.json",
                                d["memory_bytes"], k)
        if problem:
            raise fail("memory policy", problem)
        result = {"memory_bytes": d["memory_bytes"], "checks": {}}
        if qualify:
            result.update(qualify_pool(handle, d, log=log, out=qualification,
                                       fail=fail))
        return result

    try:
        result = bring_up()
    except EnvError as exc:
        if handle.state == "failed":
            raise
        raise fail(handle.state, str(exc)) from exc
    except Exception as exc:      # leave a retirable record, whatever failed
        raise fail(handle.state, f"{type(exc).__name__}: {exc}") from exc
    handle.state = "up"
    if not _save(handle, qualification=result, error=None):
        raise EnvError(f"{project} env {nonce} was retired by `env down` "
                       "while it was being brought up")
    _log(f"{project}: environment {nonce} is up and qualified "
         f"({k} workers)" if qualify else f"{project}: {nonce} is up "
         "(not qualified)")
    return handle


def qualify_pool(handle: EnvHandle, d: dict, *, log: Path, out: Path,
                 fail) -> dict:
    """harden/probe/reset-probe (database pools) and a gold control per worker."""
    data_root = Path(handle.data_root)
    checks = {}
    if handle.database:
        admin = handle.global_args(0)
        pool = handle.pool_args()
        for action in ("harden", "probe"):
            argv = admin + ["worker", action, *pool]
            if action == "probe" and handle.database["sentinel_schema"]:
                argv += ["--sentinel-schema", handle.database["sentinel_schema"]]
            _log(f"{handle.project}: worker {action}")
            rc = _engine(argv, data_root=data_root, log=log,
                         stdout=out / f"{action}.json")
            if rc != 0:
                raise fail(f"worker {action}", f"engine exit {rc}\n{_tail(log)}")
            checks[action] = "pass"

        def reset_probe(i):
            report = out / f"reset-probe.w{i}.json"
            rc = _engine(handle.global_args(i) + [
                "worker", "reset-probe", *pool, "--only", i],
                data_root=data_root, log=out / f"reset-probe.w{i}.log",
                stdout=report)
            return i, rc
        _log(f"{handle.project}: worker reset-probe on {handle.k} workers")
        failed = [i for i, rc in _parallel(handle.worker_ids, reset_probe) if rc]
        if failed:
            raise fail("worker reset-probe", f"workers {failed}: see "
                       f"{out}/reset-probe.w{failed[0]}.log\n"
                       f"{_tail(out / f'reset-probe.w{failed[0]}.log')}")
        checks["reset-probe"] = "pass"

    item = d["gold_control"]

    def gold_control(i):
        rows = out / f"gold-control.w{i}.jsonl"
        wlog = out / f"gold-control.w{i}.log"
        rc = _engine(handle.global_args(i) + [
            "run", "--adapter", "gold", "--profile", handle.profile,
            "--release", handle.release_items, "--item", item,
            "--coverage", "--repro-check", "0", "--out", rows],
            data_root=data_root, log=wlog)
        row = _gold_control_row(rows, item) or {}
        return i, rc, row.get("outcome"), row.get("execution_seconds")

    _log(f"{handle.project}: gold control {item} on {handle.k} workers")
    started = time.monotonic()
    results = _parallel(handle.worker_ids, gold_control)
    gold = {str(i): {"exit": rc, "outcome": outcome, "execution_seconds": secs}
            for i, rc, outcome, secs in results}
    bad = [i for i, rc, outcome, _ in results if rc or outcome != "passed"]
    if bad:
        raise fail("gold control", f"workers {bad}: "
                   f"{json.dumps({str(i): gold[str(i)] for i in bad})}\n"
                   f"{_tail(out / f'gold-control.w{bad[0]}.log')}")
    checks["gold_control"] = {"item": item, "workers": gold,
                              "wall_seconds": round(time.monotonic() - started, 1)}
    return {"checks": checks, "qualified_at": _utc_now()}


# --------------------------------------------------------------------------
# status / down
# --------------------------------------------------------------------------

def _home_of(handle: EnvHandle) -> Path:
    """The REQ2TEST_HOME that holds this environment (envs/<p>/<nonce>)."""
    return Path(handle.env_dir).parents[2]


def _ensure_own_daemon(handle: EnvHandle) -> None:
    """Restart the home's own daemon if the pool ran on it and it is stopped.

    A daemon chosen with --docker-host is never started here.
    """
    home = _home_of(handle)
    if handle.docker_socket == str(daemon_socket(home)):
        ensure_daemon(home)


def _containers(handle: EnvHandle) -> list:
    names = []
    for path in handle.worker_specs:
        try:
            with open(path, encoding="utf-8") as fh:
                names.append(json.load(fh)["container"])
        except (OSError, ValueError, KeyError):
            continue
    return names


def status(handle: EnvHandle) -> dict:
    _drop_ambient_docker()
    report = {"project": handle.project, "nonce": handle.nonce,
              "state": handle.state, "k": handle.k, "env_dir": handle.env_dir}
    if handle.state == "down":
        return report
    running = {}
    names = _containers(handle)
    if handle.database:
        names += [handle.database["container"],
                  handle.database["template_container"]]
    try:
        _ensure_own_daemon(handle)
        docker = _Docker(Path(handle.authority_path))
        for name in names:
            cp = docker(["container", "inspect", "--format",
                         "{{.State.Running}}", name], check=False)
            running[name] = cp.stdout.strip() == "true"
    except EnvError as exc:           # e.g. the authority no longer validates
        report["live"] = False
        report["error"] = str(exc)
        return report
    report["containers"] = running
    report["live"] = bool(running) and all(running.values()) \
        and len(_containers(handle)) == handle.k
    return report


def down(handle: EnvHandle) -> dict:
    """Tear down the pool, the database resources and the workspaces.

    A complete pool goes through the engine's `worker teardown` (which
    re-authenticates the pool's v3 evidence first).  A pool that stopped
    before its evidence existed, or that the engine refuses to
    authenticate (a worker container died), is removed by its exact planned
    names, which embed this environment's nonce.  Loaded images and staged
    inputs stay for the next `up`.
    """
    _drop_ambient_docker()
    report = {"project": handle.project, "nonce": handle.nonce}
    if os.path.isfile(handle.record_path):
        # The record, not a possibly stale in-memory handle, is the truth.
        handle = EnvHandle.load(handle.record_path)
    if handle.state == "down":
        report["note"] = "already down"
        return report
    data_root = Path(handle.data_root)
    log = Path(handle.env_dir) / "engine.log"
    # A stopped home daemon would leave the pool (and template.env, with
    # its key) behind; restart it to retire them.
    _ensure_own_daemon(handle)
    docker = _Docker(Path(handle.authority_path))
    specs = [p for p in handle.worker_specs if os.path.isfile(p)]
    complete = len(specs) == handle.k and all(
        os.path.isfile(p[:-len(".json")] + ".runtime.json") for p in specs)
    engine_rc = None
    if complete:
        engine_rc = _engine(handle.global_args(0) + [
            "worker", "teardown", *handle.pool_args()],
            data_root=data_root, log=log)
        if engine_rc == 0:
            report["workers"] = "engine teardown"
        else:
            _log(f"{handle.project} {handle.nonce}: engine teardown exited "
                 f"{engine_rc} (see {log}); removing workers by name")
    if engine_rc != 0 and specs:
        _engine_modules()
        from r2t.bench import worker as W
        removed = []
        for path in specs:
            spec = W.load_worker_spec(path)
            docker(["rm", "--force", "--volumes", spec.container], check=False)
            removed.append(spec.container)
            if os.path.isdir(spec.workspace):
                W.remove_workspace(spec.workspace, image=handle.image_id)
            if os.path.exists(spec.env_file):
                os.remove(spec.env_file)
        report["workers"] = {"removed_by_name": removed,
                             **({"engine_teardown_exit": engine_rc}
                                if engine_rc else {})}
    if handle.database:
        db = handle.database
        for kind, name in (("container", db["template_container"]),
                           ("container", db["container"]),
                           ("network", db["network"])):
            cp = docker([kind, "inspect", "--format",
                         "{{json .Config.Labels}}" if kind == "container"
                         else "{{json .Labels}}", name], check=False)
            if cp.returncode != 0:
                continue
            labels = json.loads(cp.stdout or "{}") or {}
            if labels.get(LABEL) != handle.nonce:
                raise EnvError(f"{kind} {name} does not carry {LABEL}="
                               f"{handle.nonce}; not removed")
            # --volumes: the MySQL image declares VOLUME /var/lib/mysql,
            # whose anonymous volume would otherwise outlive the container.
            docker(["container", "rm", "--force", "--volumes", name]
                   if kind == "container" else ["network", "rm", name],
                   timeout=300)
        env_file = Path(db["template_env_file"])
        if env_file.exists():
            env_file.unlink()
        shutil.rmtree(db["composer_cache"], ignore_errors=True)
        report["database"] = "removed"
    handle.state = "down"
    _save(handle, torn_down_at=_utc_now())
    return report


def records(project: Optional[str] = None) -> list:
    base = req2test_home() / "envs"
    pattern = f"{project}/*/env.json" if project else "*/*/env.json"
    return sorted(base.glob(pattern))


def select(project: str, nonce: Optional[str], *, live_only: bool) -> list:
    found = []
    for path in records(project):
        handle = EnvHandle.load(path)
        if nonce and handle.nonce != nonce:
            continue
        if live_only and handle.state == "down":
            continue
        found.append(handle)
    if nonce and not found:
        raise EnvError(f"no {'live ' if live_only else ''}environment "
                       f"{nonce} for {project}")
    return found


def select_for_down(project: str, nonce: Optional[str],
                    all_live: bool) -> list:
    """What `env down` may retire: one named environment, every live one
    with --all, or the project's only live one.  Several live environments
    may belong to other sessions still using them, so without --nonce or
    --all they are listed and nothing is retired."""
    if nonce and all_live:
        raise EnvError("give --nonce or --all, not both")
    live = select(project, nonce, live_only=True)
    if nonce or all_live or len(live) <= 1:
        return live
    listing = "\n".join(
        f"  {h.nonce}  state={h.state}  k={h.k}  {h.env_dir}" for h in live)
    raise EnvError(
        f"{len(live)} live {project} environments; name one with --nonce "
        f"(or retire them all with --all):\n{listing}")


# --------------------------------------------------------------------------
# CLI: req2test env ...
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="req2test env",
        description="bring up, inspect and retire a project's execution "
                    "environment (rootless Docker, images, database, "
                    "qualified worker pool)")
    sub = parser.add_subparsers(dest="action", metavar="ACTION")
    sub.required = True
    p = sub.add_parser("up", help="provision and qualify a worker pool")
    p.add_argument("--project", required=True, choices=sorted(PROJECTS))
    p.add_argument("--workers", type=int, default=None,
                   help="pool size K (default: the project's plan value)")
    p.add_argument("--kit", default=None, metavar="DIR",
                   help="kit directory (default: the installed kit)")
    p.add_argument("--docker-host", default=None, metavar="unix:///PATH",
                   help="use this rootless daemon instead of creating "
                        "REQ2TEST_HOME's own")
    p.add_argument("--run-dir", default=None,
                   help="also record the environment in DIR/env.json")
    p.add_argument("--no-qualify", action="store_true",
                   help="skip the pool checks and gold controls")
    for action, text in (("status", "show environments and whether they "
                          "are live"),
                         ("down", "tear down environments")):
        p = sub.add_parser(action, help=text)
        p.add_argument("--project", required=True, choices=sorted(PROJECTS))
        if action == "status":
            p.add_argument("--nonce", default=None,
                           help="one environment (default: all of the "
                                "project's)")
        else:
            p.add_argument("--nonce", default=None,
                           help="the environment to retire (needed when the "
                                "project has more than one live environment)")
            p.add_argument("--all", action="store_true", dest="all_live",
                           help="retire every live environment of the project "
                                "in this home, including ones other sessions "
                                "may be using")
    sub.add_parser(
        "stop-daemon",
        help="stop this home's rootless Docker daemon (refused while an "
             "environment is not down); the next `env up` restarts it",
        description="stop this home's rootless Docker daemon, which `env "
                    "up`, `evaluate` and `validate` start and leave running "
                    "for the next run. Refused while any environment of this "
                    "home is not down (`req2test env down`). Its loaded "
                    "images stay on disk; the next `env up` restarts it.")
    return parser


def stop_daemon() -> dict:
    """Stop this home's own rootless daemon (`req2test env stop-daemon`).

    Refused while any environment of the home is not `down`: its pool,
    database and template containers live on that daemon and would be left
    for `env down` to find stopped.
    """
    home = req2test_home()
    name = daemon_name(home)
    live = [h for h in map(EnvHandle.load, records()) if h.state != "down"]
    if live:
        listing = "\n".join(
            f"  {h.project} {h.nonce} (state {h.state}): req2test env down "
            f"--project {h.project} --nonce {h.nonce}" for h in live)
        raise EnvError(
            f"{len(live)} environment(s) of this home are not down, so "
            f"{name} keeps running; retire them first:\n{listing}")
    state = _systemctl_user("is-active", name).stdout.strip()
    if state not in ("active", "activating", "reloading", "deactivating"):
        return {"daemon": name, "state": state or "unknown",
                "note": "not running"}
    stopped = _systemctl_user("stop", name)
    if stopped.returncode != 0:
        raise EnvError(f"systemctl --user stop {name} failed: "
                       f"{(stopped.stderr or stopped.stdout).strip()[-400:]}")
    return {"daemon": name, "stopped": True,
            "data_root": str(home / "docker" / "data"),
            "note": "loaded images stay; the next `env up` restarts it"}


def main(argv=None) -> int:
    """`req2test env ACTION`; errors propagate to `req2test.cli.main`."""
    args = build_parser().parse_args(argv)
    if args.action == "up":
        kit = find_kit(args.project, args.kit)
        handle = up(kit, args.workers, args.run_dir,
                    docker_host=args.docker_host,
                    qualify=not args.no_qualify)
        with open(handle.record_path, encoding="utf-8") as fh:
            record = json.load(fh)
        print(json.dumps({"project": handle.project,
                          "nonce": handle.nonce, "k": handle.k,
                          "record": handle.record_path,
                          "workers_root": handle.workers_root,
                          "qualification": record.get("qualification")},
                         indent=1))
        return 0
    if args.action == "status":
        handles = select(args.project, args.nonce, live_only=False)
        print(json.dumps([status(h) for h in handles], indent=1))
        return 0
    if args.action == "stop-daemon":
        print(json.dumps(stop_daemon(), indent=1))
        return 0
    handles = select_for_down(args.project, args.nonce, args.all_live)
    if not handles:
        print(f"no live environment for {args.project}")
        return 0
    print(json.dumps([down(h) for h in handles], indent=1))
    return 0


if __name__ == "__main__":
    from .cli import main as cli_main
    sys.exit(cli_main(["env", *sys.argv[1:]]))
